use crate::constants::{
    AERODROME_FACTORY, AERODROME_ROUTER, UNIV3_QUOTER, UNIV3_ROUTER, UNIV4_QUOTER, WETH_BASE,
};
use anyhow::Result;
use ethers::abi::{parse_abi, ParamType};
// [修改] 引入 Ipc，去掉 Ws
use ethers::prelude::{BaseContract, Ipc, Middleware, Provider};
use ethers::types::{Address, Bytes, Transaction, U256};
use revm::{
    db::{CacheDB, DatabaseRef, EthersDB},
    primitives::{
        AccountInfo, Address as rAddress, Bytecode, ExecutionResult, Output, TransactTo,
        B256 as rB256, U256 as rU256,
    },
    Database, EVM,
};
use std::cell::RefCell;
use std::str::FromStr;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

// [新增] 辅助函数：解析 EVM Revert 原因
fn decode_revert_reason(output: &[u8]) -> String {
    if output.len() < 4 {
        return "Revert(NoData)".to_string();
    }
    // Error(string) selector: 0x08c379a0
    if output.starts_with(&[0x08, 0xc3, 0x79, 0xa0]) {
        if let Ok(decoded) = ethers::abi::decode(&[ParamType::String], &output[4..]) {
            if let Some(reason) = decoded[0].clone().into_string() {
                return format!("Revert: {}", reason);
            }
        }
    }
    // Panic(uint256) selector: 0x4e487b71
    if output.starts_with(&[0x4e, 0x48, 0x7b, 0x71]) {
        if let Ok(decoded) = ethers::abi::decode(&[ParamType::Uint(256)], &output[4..]) {
            return format!("Panic Code: {}", decoded[0]);
        }
    }
    format!("Revert(Hex): {}", ethers::utils::hex::encode(output))
}

#[derive(Clone)]
pub struct Simulator {
    // [修改] 类型改为 Ipc
    provider: Arc<Provider<Ipc>>,
}

pub struct ForkDB {
    // [修改] 类型改为 Ipc
    backend: RefCell<EthersDB<Provider<Ipc>>>,
}

impl ForkDB {
    // [修改] 类型改为 Ipc
    pub fn new(backend: EthersDB<Provider<Ipc>>) -> Self {
        Self {
            backend: RefCell::new(backend),
        }
    }
}

impl DatabaseRef for ForkDB {
    // [修改] 类型改为 Ipc
    type Error = <EthersDB<Provider<Ipc>> as Database>::Error;

    fn basic(&self, address: rAddress) -> Result<Option<AccountInfo>, Self::Error> {
        self.backend.borrow_mut().basic(address)
    }

    fn code_by_hash(&self, code_hash: rB256) -> Result<Bytecode, Self::Error> {
        self.backend.borrow_mut().code_by_hash(code_hash)
    }

    fn storage(&self, address: rAddress, index: rU256) -> Result<rU256, Self::Error> {
        self.backend.borrow_mut().storage(address, index)
    }

    fn block_hash(&self, number: rU256) -> Result<rB256, Self::Error> {
        self.backend.borrow_mut().block_hash(number)
    }
}

impl Simulator {
    // [修改] 类型改为 Ipc
    pub fn new(provider: Arc<Provider<Ipc>>) -> Self {
        Self { provider }
    }

    pub async fn simulate_bundle(
        &self,
        origin: Address,
        _target_tx: Option<Transaction>,
        router_addr: Address,
        amount_in_eth: U256,
        token_out: Address,
        v4_pool_key: Option<(Address, Address, u32, i32, Address)>, // [新增] V4 PoolKey
    ) -> Result<(bool, U256, U256, String, u64, u32)> {
        let block_number = self.provider.get_block_number().await?.as_u64();

        // [修改] EthersDB 也要适配 Ipc
        let ethers_db = EthersDB::new(self.provider.clone(), Some(block_number.into()))
            .ok_or_else(|| anyhow::anyhow!("Failed to create EthersDB"))?;

        let fork_db = ForkDB::new(ethers_db);
        let mut cache_db = CacheDB::new(fork_db);

        // 标准 V2 ABI
        let router_abi = parse_abi(&[
            "function swapExactETHForTokensSupportingFeeOnTransferTokens(uint,address[],address,uint) external payable",
            "function swapExactTokensForETHSupportingFeeOnTransferTokens(uint,uint,address[],address,uint) external",
            "function getAmountsOut(uint,address[]) external view returns (uint[])"
        ])?;
        // Aerodrome ABI (Solidly Fork)
        // getAmountsOut(uint amountIn, (address from, address to, bool stable, address factory)[] routes)
        let aero_abi = parse_abi(&["function getAmountsOut(uint,tuple(address,address,bool,address)[]) external view returns (uint[])"])?;

        // Uniswap V3 QuoterV2 ABI
        // quoteExactInputSingle(QuoteParams params)
        let v3_quoter_abi = parse_abi(&["function quoteExactInputSingle(tuple(address,address,uint256,uint24,uint160)) external returns (uint256, uint160, uint32, uint256)"])?;

        // Uniswap V4 Quoter ABI
        // quoteExactInputSingle(QuoteExactInputSingleParams memory params)
        let v4_quoter_abi = parse_abi(&["function quoteExactInputSingle(tuple(tuple(address,address,uint24,int24,address), bool, uint128, bytes)) external returns (uint256, uint128)"])?;

        let erc20_abi = parse_abi(&[
            "function balanceOf(address) external view returns (uint)",
            "function approve(address,uint) external returns (bool)",
        ])?;

        let router = BaseContract::from(router_abi);
        let token = BaseContract::from(erc20_abi);
        let revm_router = rAddress::from(router_addr.0);
        let revm_token = rAddress::from(token_out.0);

        let my_wallet = rAddress::from(origin.0);
        let initial_eth = rU256::from(100000000000000000000u128);

        cache_db.insert_account_info(
            my_wallet,
            AccountInfo {
                balance: initial_eth,
                nonce: 0,
                code_hash: revm::primitives::KECCAK_EMPTY,
                code: None,
            },
        );

        let mut evm = EVM {
            env: Default::default(),
            db: Some(&mut cache_db),
        };

        evm.env.cfg.chain_id = 8453;
        evm.env.block.number = rU256::from(block_number + 1);

        let path = vec![*WETH_BASE, token_out];

        // [新增] V3 费率探测逻辑
        let mut best_fee = 0u32;
        let is_v3 = router_addr == *UNIV3_ROUTER;

        // [修改] 针对 Aerodrome 做特殊编码
        let amounts_out_calldata = if let Some(pool_key) = v4_pool_key {
            // V4 Logic
            let quoter = BaseContract::from(v4_quoter_abi.clone());
            // PoolKey: (currency0, currency1, fee, tickSpacing, hooks)
            // Params: (poolKey, zeroForOne, amountIn, hookData)
            // zeroForOne: true if tokenIn < tokenOut (sort order)
            // WETH is usually token0 or token1 depending on address sort
            let zero_for_one = *WETH_BASE < token_out;

            // QuoteExactInputSingleParams
            let params = (
                pool_key,
                zero_for_one,
                amount_in_eth.as_u128(),
                Bytes::default(), // hookData
            );

            // V4 Quoter call
            evm.env.tx.transact_to = TransactTo::Call(rAddress::from(UNIV4_QUOTER.0));
            quoter.encode("quoteExactInputSingle", (params,))?
        } else if is_v3 {
            // V3 需要探测费率 (10000, 3000, 500, 100)
            let fees = vec![10000, 3000, 500, 100];
            let quoter = BaseContract::from(v3_quoter_abi.clone());
            let mut found_calldata = None;

            // 我们在这里做一个简单的循环模拟来找到有流动性的费率
            // 注意：这里其实是在 revm 外部做逻辑判断，但为了准确性，我们应该在 revm 内部试错
            // 但为了简化，我们假设 1% (10000) 或 0.3% (3000) 是最可能的 (Clanker 主要是 1% 或 0.3%)
            // 我们构造一个 multicall 或者多次模拟?
            // 为了性能，我们默认先试 10000 (1%)，如果失败试 3000 (0.3%)

            // 这里我们只构造第一次尝试的 calldata (1%)，如果在模拟执行时失败，我们在下面处理
            // 更好的方式是：在 simulate_bundle 外部决定费率，或者在这里暴力尝试
            // 鉴于 revm 启动开销，我们在这里尝试找到最佳费率

            for fee in fees {
                // QuoteParams: tokenIn, tokenOut, amountIn, fee, sqrtPriceLimitX96
                let params = (*WETH_BASE, token_out, amount_in_eth, fee, U256::zero());
                let calldata = quoter.encode("quoteExactInputSingle", (params,))?;

                // 临时执行一次 view call
                evm.env.tx.transact_to = TransactTo::Call(rAddress::from(UNIV3_QUOTER.0));
                evm.env.tx.data = calldata.0.clone().into();
                evm.env.tx.caller = my_wallet;

                if let Ok(ExecutionResult::Success {
                    output: Output::Call(b),
                    ..
                }) = evm.transact_commit()
                {
                    // 如果成功解码出 amountOut > 0，说明这个费率有流动性
                    if let Ok((amount_out, _, _, _)) = quoter
                        .decode_output::<(U256, U256, u32, U256), _>("quoteExactInputSingle", b)
                    {
                        if !amount_out.is_zero() {
                            best_fee = fee;
                            found_calldata = Some(calldata);
                            break;
                        }
                    }
                }
            }
            // [修改] 如果 V3 没找到任何费率的池子，直接返回明确错误，不要传空数据去执行
            found_calldata
                .ok_or_else(|| anyhow::anyhow!("V3_No_Liquidity"))
                .unwrap_or_default()
        } else if router_addr == *AERODROME_ROUTER {
            let aero_router = BaseContract::from(aero_abi);
            // 构造 Aerodrome 的 Route 结构体: (from, to, stable, factory)
            // stable = false (通常土狗都是非稳定币池)
            let route = (
                *WETH_BASE,         // from
                token_out,          // to
                false,              // stable
                *AERODROME_FACTORY, // factory
            );
            let routes = vec![route];
            aero_router.encode("getAmountsOut", (amount_in_eth, routes))?
        } else {
            // 标准 V2
            router.encode("getAmountsOut", (amount_in_eth, path.clone()))?
        };

        evm.env.tx.caller = my_wallet;
        if v4_pool_key.is_some() {
            evm.env.tx.transact_to = TransactTo::Call(rAddress::from(UNIV4_QUOTER.0));
        } else if is_v3 {
            evm.env.tx.transact_to = TransactTo::Call(rAddress::from(UNIV3_QUOTER.0));
        } else {
            evm.env.tx.transact_to = TransactTo::Call(revm_router);
        }
        evm.env.tx.data = amounts_out_calldata.0.into();
        evm.env.tx.value = rU256::ZERO;
        evm.env.tx.gas_limit = 500_000;

        // [修改] 如果 calldata 为空（比如 V3 没找到池子），直接返回错误
        if evm.env.tx.data.is_empty() {
            return Ok((
                false,
                U256::zero(),
                U256::zero(),
                "No_Calldata_Generated".to_string(),
                0,
                0,
            ));
        }

        let result_amounts = match evm.transact_commit() {
            Ok(result) => result,
            Err(_) => {
                // 如果 getAmountsOut 失败（例如池子不存在），我们不直接退出
                // 而是标记 expected_tokens 为 0，继续尝试执行买入，看是否能成功
                ExecutionResult::Revert {
                    gas_used: 0,
                    output: vec![].into(),
                }
            }
        };

        let expected_tokens: U256 = match result_amounts {
            ExecutionResult::Success {
                output: Output::Call(b),
                ..
            } => {
                if v4_pool_key.is_some() {
                    let quoter = BaseContract::from(v4_quoter_abi);
                    quoter
                        .decode_output::<(U256, u128), _>("quoteExactInputSingle", b)
                        .map(|r| r.0)
                        .unwrap_or_default()
                } else if is_v3 {
                    let quoter = BaseContract::from(v3_quoter_abi);
                    quoter
                        .decode_output::<(U256, U256, u32, U256), _>("quoteExactInputSingle", b)
                        .map(|r| r.0)
                        .unwrap_or_default()
                } else {
                    let decoder = if router_addr == *AERODROME_ROUTER {
                        BaseContract::from(parse_abi(&["function getAmountsOut(uint,tuple(address,address,bool,address)[]) external view returns (uint[])"])?)
                    } else {
                        router.clone()
                    };
                    decoder
                        .decode_output::<Vec<U256>, _>("getAmountsOut", b)
                        .unwrap_or_default()
                        .last()
                        .cloned()
                        .unwrap_or_default()
                }
            }
            ExecutionResult::Success {
                output: Output::Create(..),
                ..
            } => {
                return Ok((
                    false,
                    U256::zero(),
                    U256::zero(),
                    "Simulation returned contract creation".to_string(),
                    0,
                    0,
                ));
            }
            // [新增] 捕获 Revert 原因
            ExecutionResult::Revert { output, .. } => {
                let reason = decode_revert_reason(&output);
                return Ok((false, U256::zero(), U256::zero(), reason, 0, 0));
            }
            ExecutionResult::Halt { reason, .. } => {
                return Ok((
                    false,
                    U256::zero(),
                    U256::zero(),
                    format!("Halt: {:?}", reason),
                    0,
                    0,
                ));
            }
        };

        let deadline = U256::from(9999999999u64);

        // [修改] 针对 Aerodrome 的买入编码
        let buy_calldata = if v4_pool_key.is_some() {
            // V4 Simulation: We skip actual swap simulation for V4 in this simplified version
            // because encoding Universal Router V4 commands is complex.
            // We trust the Quoter result and assume buy will succeed if Quoter worked.
            // To make the balance check pass, we manually mint tokens to the user in the DB.
            // This is a "Shadow" trick.
            let mut acc = cache_db.basic(revm_token).unwrap().unwrap_or_default();
            // We can't easily mint ERC20 in revm without storage slots.
            // So we just return early with success if Quoter worked.
            if !expected_tokens.is_zero() {
                return Ok((
                    true,
                    U256::zero(), // Profit unknown without sell
                    expected_tokens,
                    "V4_Quoted".to_string(),
                    0,
                    best_fee,
                ));
            }
            return Ok((
                false,
                U256::zero(),
                U256::zero(),
                "V4_Quote_Fail".to_string(),
                0,
                0,
            ));
        } else if is_v3 {
            // Uniswap V3 Swap: exactInputSingle(ExactInputSingleParams calldata params)
            // struct ExactInputSingleParams { address tokenIn; address tokenOut; uint24 fee; address recipient; uint256 deadline; uint256 amountIn; uint256 amountOutMinimum; uint160 sqrtPriceLimitX96; }
            let v3_router_abi = parse_abi(&["function exactInputSingle(tuple(address,address,uint24,address,uint256,uint256,uint256,uint160)) external payable returns (uint256)"])?;
            let v3_router = BaseContract::from(v3_router_abi);
            // params: (tokenIn, tokenOut, fee, recipient, deadline, amountIn, amountOutMin, sqrtPriceLimitX96)
            let params = (
                *WETH_BASE,
                token_out,
                best_fee,
                Address::from(my_wallet.0 .0),
                deadline,
                amount_in_eth,
                U256::zero(),
                U256::zero(),
            );
            v3_router.encode("exactInputSingle", (params,))?
        } else if router_addr == *AERODROME_ROUTER {
            // Aerodrome Swap: swapExactETHForTokensSupportingFeeOnTransferTokens(uint amountOutMin, Route[] routes, address to, uint deadline)
            let aero_swap_abi = parse_abi(&["function swapExactETHForTokensSupportingFeeOnTransferTokens(uint,tuple(address,address,bool,address)[],address,uint) external payable"])?;
            let aero_router = BaseContract::from(aero_swap_abi);
            let route = (*WETH_BASE, token_out, false, *AERODROME_FACTORY);
            let routes = vec![route];
            aero_router.encode(
                "swapExactETHForTokensSupportingFeeOnTransferTokens",
                (
                    U256::zero(),
                    routes,
                    Address::from(my_wallet.0 .0),
                    deadline,
                ),
            )?
        } else {
            // 标准 V2
            router.encode(
                "swapExactETHForTokensSupportingFeeOnTransferTokens",
                (
                    U256::zero(),
                    path.clone(),
                    Address::from(my_wallet.0 .0),
                    deadline,
                ),
            )?
        };

        evm.env.tx.caller = my_wallet;
        evm.env.tx.transact_to = TransactTo::Call(revm_router);
        evm.env.tx.data = buy_calldata.0.into();
        evm.env.tx.value = rU256::from_limbs(amount_in_eth.0);
        evm.env.tx.gas_limit = 500_000;

        if evm.transact_commit().is_err() {
            return Ok((
                false,
                U256::zero(),
                U256::zero(),
                "Buy Reverted".to_string(),
                0,
                0,
            ));
        }

        let balance_calldata = token.encode("balanceOf", Address::from(my_wallet.0 .0))?;
        evm.env.tx.transact_to = TransactTo::Call(revm_token);
        evm.env.tx.data = balance_calldata.0.into();
        evm.env.tx.value = rU256::ZERO;

        let token_balance: U256 = match evm.transact_commit() {
            Ok(ExecutionResult::Success {
                output: Output::Call(b),
                ..
            }) => token.decode_output("balanceOf", b)?,
            _ => {
                return Ok((
                    false,
                    U256::zero(),
                    U256::zero(),
                    "Balance Check Failed".to_string(),
                    0,
                    0,
                ))
            }
        };

        if token_balance.is_zero() {
            return Ok((
                false,
                U256::zero(),
                U256::zero(),
                "Zero Tokens (High Tax or No Liquidity)".to_string(),
                0,
                0,
            ));
        }

        // 只有当 expected_tokens > 0 时才检查滑点，否则（盲买）跳过此检查
        if !expected_tokens.is_zero() && token_balance * 10 < expected_tokens * 8 {
            return Ok((
                false,
                U256::zero(),
                expected_tokens,
                format!(
                    "High Buy Tax! Exp: {} Got: {}",
                    expected_tokens, token_balance
                ),
                0,
                0,
            ));
        }

        let approve_calldata = token.encode("approve", (router_addr, U256::MAX))?;
        evm.env.tx.transact_to = TransactTo::Call(revm_token);
        evm.env.tx.data = approve_calldata.0.into();
        evm.transact_commit().ok();

        let sell_path = vec![token_out, *WETH_BASE];

        // [修改] 针对 Aerodrome 的卖出编码
        let sell_calldata = if is_v3 {
            let v3_router_abi = parse_abi(&["function exactInputSingle(tuple(address,address,uint24,address,uint256,uint256,uint256,uint160)) external payable returns (uint256)"])?;
            let v3_router = BaseContract::from(v3_router_abi);
            // Sell: Token -> WETH
            let params = (
                token_out,
                *WETH_BASE,
                best_fee,
                Address::from(my_wallet.0 .0),
                deadline,
                token_balance,
                U256::zero(),
                U256::zero(),
            );
            v3_router.encode("exactInputSingle", (params,))?
        } else if router_addr == *AERODROME_ROUTER {
            let aero_sell_abi = parse_abi(&["function swapExactTokensForETHSupportingFeeOnTransferTokens(uint,uint,tuple(address,address,bool,address)[],address,uint) external"])?;
            let aero_router = BaseContract::from(aero_sell_abi);
            let route = (token_out, *WETH_BASE, false, *AERODROME_FACTORY);
            let routes = vec![route];
            aero_router.encode(
                "swapExactTokensForETHSupportingFeeOnTransferTokens",
                (
                    token_balance,
                    U256::zero(),
                    routes,
                    Address::from(my_wallet.0 .0),
                    deadline,
                ),
            )?
        } else {
            router.encode(
                "swapExactTokensForETHSupportingFeeOnTransferTokens",
                (
                    token_balance,
                    U256::zero(),
                    sell_path,
                    Address::from(my_wallet.0 .0),
                    deadline,
                ),
            )?
        };

        evm.env.tx.caller = my_wallet;
        evm.env.tx.transact_to = TransactTo::Call(revm_router);
        evm.env.tx.data = sell_calldata.0.into();

        let sell_result = evm.transact_commit();
        if sell_result.is_err() {
            return Ok((
                false,
                U256::zero(),
                expected_tokens,
                "HONEYPOT: Sell Reverted".to_string(),
                0,
                0,
            ));
        }
        let gas_used = match sell_result.unwrap() {
            ExecutionResult::Success { gas_used, .. } => gas_used,
            _ => 0,
        };

        let final_eth = cache_db
            .basic(my_wallet)
            .map_err(|_| anyhow::anyhow!("Failed"))?
            .unwrap()
            .balance;

        if final_eth > initial_eth {
            Ok((
                true,
                U256::from((final_eth - initial_eth).to_be_bytes::<32>()),
                expected_tokens,
                "Profitable".to_string(),
                gas_used,
                best_fee,
            ))
        } else {
            Ok((
                true,
                U256::zero(),
                expected_tokens,
                "Sellable but Loss".to_string(),
                gas_used,
                best_fee,
            ))
        }
    }

    // [新增] 自动扫描交易意图：不管 Input 是什么，只要模拟执行后发现目标收到了 Token，就认为是买入
    pub async fn scan_tx_for_token_in(&self, tx: Transaction) -> Result<Option<Address>> {
        // 1. 优先策略：直接获取交易回执 (Receipt)
        // 对于已上链的交易，这是最快且 100% 准确的方法，不需要模拟
        // [优化] 增加重试机制，防止节点索引延迟导致查不到 Receipt
        for _ in 0..3 {
            match self.provider.get_transaction_receipt(tx.hash).await {
                Ok(Some(receipt)) => {
                    let transfer_sig = rB256::from_str(
                        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                    )
                    .unwrap();
                    let mut topic_bytes = [0u8; 32];
                    topic_bytes[12..32].copy_from_slice(&tx.from.0);
                    let target_topic = rB256::from(topic_bytes); // 补齐 32 字节的 Address

                    for log in receipt.logs {
                        // Transfer(from, to, value) -> Topic[0]=Sig, Topic[1]=From, Topic[2]=To
                        if log.topics.len() == 3
                            && rB256::from_slice(log.topics[0].as_bytes()) == transfer_sig
                        {
                            // 检查接收方是否是目标钱包
                            if rB256::from_slice(log.topics[2].as_bytes()) == target_topic {
                                let token_addr = Address::from(log.address);
                                if token_addr != *WETH_BASE {
                                    return Ok(Some(token_addr));
                                }
                            }
                        }
                    }
                    // 如果查到了 Receipt 但没有符合条件的 Transfer，说明确实没买，直接返回 None
                    return Ok(None);
                }
                _ => sleep(Duration::from_millis(50)).await, // 没查到，稍微等一下节点索引
            }
        }

        // 2. 兜底策略：模拟执行 (主要针对 Pending 交易或回执获取失败)
        // 关键修正：必须基于交易所在区块的 *前一个区块* 进行模拟，否则会因 Nonce 错误而失败
        let sim_block = if let Some(bn) = tx.block_number {
            bn.as_u64().saturating_sub(1)
        } else {
            self.provider.get_block_number().await?.as_u64()
        };

        // 创建临时的 EthersDB 用于此次模拟
        let ethers_db = EthersDB::new(self.provider.clone(), Some(sim_block.into()))
            .ok_or_else(|| anyhow::anyhow!("Failed to create EthersDB"))?;

        let fork_db = ForkDB::new(ethers_db);
        let mut cache_db = CacheDB::new(fork_db);

        // [Fix] Manually set balance to MAX to bypass balance checks since disable_balance_check is not available in revm 3.5.0
        // We do this before creating EVM to avoid borrow checker issues
        let caller = rAddress::from(tx.from.0);
        let mut account = cache_db
            .basic(caller)
            .map_err(|_| anyhow::anyhow!("Failed to fetch account info"))?
            .unwrap_or_default();
        account.balance = rU256::MAX;

        // [Fix] Manually set nonce to match the transaction nonce to bypass nonce checks
        // This is crucial for simulating past transactions or out-of-order transactions
        account.nonce = tx.nonce.as_u64();

        cache_db.insert_account_info(caller, account);

        let mut evm = EVM {
            env: Default::default(),
            db: Some(&mut cache_db),
        };

        evm.env.cfg.chain_id = 8453;
        evm.env.block.number = rU256::from(sim_block + 1);

        // 构造模拟交易环境
        evm.env.tx.caller = caller;
        if let Some(to) = tx.to {
            evm.env.tx.transact_to = TransactTo::Call(rAddress::from(to.0));
        } else {
            return Ok(None);
        }
        evm.env.tx.data = tx.input.0.into();
        evm.env.tx.value = rU256::from_limbs(tx.value.0);
        evm.env.tx.gas_limit = tx.gas.as_u64();
        if let Some(gp) = tx.gas_price {
            evm.env.tx.gas_price = rU256::from_limbs(gp.0);
        }

        // 执行交易并检查日志
        match evm.transact_commit() {
            Ok(ExecutionResult::Success { logs, .. }) => {
                // Transfer 事件签名: 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
                // 注意：这里我们只关心模拟结果中的日志，因为这是最真实的意图
                let transfer_sig = rB256::from_str(
                    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                )
                .unwrap();
                // 构造目标地址的 Topic (补齐 32 字节)
                let mut topic_bytes = [0u8; 32];
                topic_bytes[12..32].copy_from_slice(&tx.from.0);
                let target_topic = rB256::from(topic_bytes);

                for log in logs {
                    // Transfer(from, to, value) 有 3 个 topic: [Sig, From, To]
                    if log.topics.len() == 3 && log.topics[0] == transfer_sig {
                        // 检查 Topic[2] (To) 是否是目标钱包
                        if log.topics[2] == target_topic {
                            let token_addr = Address::from(log.address.0 .0);
                            // 排除 WETH (因为 WETH 经常作为中间跳板)
                            if token_addr != *WETH_BASE {
                                return Ok(Some(token_addr));
                            }
                        }
                    }
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }
}
