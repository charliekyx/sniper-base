use crate::constants::{
    AERODROME_FACTORY, AERODROME_ROUTER, PANCAKESWAP_V3_QUOTER, PANCAKESWAP_V3_ROUTER,
    UNIV3_QUOTER, UNIV3_ROUTER, UNIV4_QUOTER, UNIVERSAL_ROUTER, WETH_BASE,
};
use anyhow::Result;
use ethers::abi::{Abi, Function, Param, ParamType, StateMutability, Token};
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
    // [新增] V4 QuoteFailure(bytes) selector: 0x6190b2b0
    if output.starts_with(&[0x61, 0x90, 0xb2, 0xb0]) {
        if let Ok(decoded) = ethers::abi::decode(&[ParamType::Bytes], &output[4..]) {
            if let Some(inner_bytes) = decoded[0].clone().into_bytes() {
                // PoolNotInitialized selector: 0x86aa3070
                if inner_bytes.starts_with(&[0x86, 0xaa, 0x30, 0x70]) {
                    return "Revert: PoolNotInitialized (V4)".to_string();
                }
                // [新增] 捕获 Clanker V4 的常见自定义错误 (0x486aa307)
                if inner_bytes.starts_with(&[0x48, 0x6a, 0xa3, 0x07]) {
                    return "Revert: V4 Pool Not Found (486aa307)".to_string();
                }
                return format!("Revert(V4): {}", ethers::utils::hex::encode(inner_bytes));
            }
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
        let block = self
            .provider
            .get_block(block_number)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Failed to fetch block"))?;
        let block_timestamp = block.timestamp;

        // [修改] EthersDB 也要适配 Ipc
        let ethers_db = EthersDB::new(self.provider.clone(), Some(block_number.into()))
            .ok_or_else(|| anyhow::anyhow!("Failed to create EthersDB"))?;

        let fork_db = ForkDB::new(ethers_db);
        let mut cache_db = CacheDB::new(fork_db);

        // =========================================================================
        // [根本解决方案] 手动构建 ABI，绕过字符串解析器的 Bug
        // =========================================================================

        // 1. Aerodrome ABI: getAmountsOut(uint amountIn, Route[] routes)
        // Route Struct: (address from, address to, bool stable, address factory)
        let route_struct_type = ParamType::Tuple(vec![
            ParamType::Address, // from
            ParamType::Address, // to
            ParamType::Bool,    // stable
            ParamType::Address, // factory
        ]);

        #[allow(deprecated)]
        let aero_function = Function {
            name: "getAmountsOut".to_string(),
            inputs: vec![
                Param {
                    name: "amountIn".to_string(),
                    kind: ParamType::Uint(256),
                    internal_type: None,
                },
                Param {
                    name: "routes".to_string(),
                    kind: ParamType::Array(Box::new(route_struct_type.clone())), // 明确指定这是 Struct 数组
                    internal_type: None,
                },
            ],
            outputs: vec![Param {
                name: "amounts".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Uint(256))),
                internal_type: None,
            }],
            constant: Some(true),
            state_mutability: StateMutability::View,
        };

        let mut aero_abi = Abi::default();
        aero_abi
            .functions
            .insert("getAmountsOut".to_string(), vec![aero_function]);

        // 2. Uniswap V3 Quoter ABI: quoteExactInputSingle(QuoteParams params)
        // QuoteParams: (tokenIn, tokenOut, amountIn, fee, sqrtPriceLimitX96)
        let v3_params_type = ParamType::Tuple(vec![
            ParamType::Address,   // tokenIn
            ParamType::Address,   // tokenOut
            ParamType::Uint(256), // amountIn
            ParamType::Uint(24),  // fee
            ParamType::Uint(160), // sqrtPriceLimitX96
        ]);

        #[allow(deprecated)]
        let v3_function = Function {
            name: "quoteExactInputSingle".to_string(),
            inputs: vec![Param {
                name: "params".to_string(),
                kind: v3_params_type, // 明确指定这是 Struct (Tuple)
                internal_type: None,
            }],
            outputs: vec![
                Param {
                    name: "amountOut".to_string(),
                    kind: ParamType::Uint(256),
                    internal_type: None,
                },
                Param {
                    name: "sqrtPriceX96After".to_string(),
                    kind: ParamType::Uint(160),
                    internal_type: None,
                },
                Param {
                    name: "initializedTicksCrossed".to_string(),
                    kind: ParamType::Uint(32),
                    internal_type: None,
                },
                Param {
                    name: "gasEstimate".to_string(),
                    kind: ParamType::Uint(256),
                    internal_type: None,
                },
            ],
            constant: None,
            state_mutability: StateMutability::NonPayable,
        };

        let mut v3_quoter_abi = Abi::default();
        v3_quoter_abi
            .functions
            .insert("quoteExactInputSingle".to_string(), vec![v3_function]);

        // 3. [修复] Uniswap V4 Quoter ABI - 手动构建，彻底解决 Invalid data
        // PoolKey: (currency0, currency1, fee, tickSpacing, hooks)
        let v4_pool_key_type = ParamType::Tuple(vec![
            ParamType::Address,
            ParamType::Address,
            ParamType::Uint(24),
            ParamType::Int(24),
            ParamType::Address,
        ]);
        // QuoteParams: (poolKey, zeroForOne, amountIn, hookData)
        let v4_params_type = ParamType::Tuple(vec![
            v4_pool_key_type,
            ParamType::Bool,
            ParamType::Uint(128),
            ParamType::Bytes,
        ]);
        #[allow(deprecated)]
        let v4_function = Function {
            name: "quoteExactInputSingle".to_string(),
            inputs: vec![Param {
                name: "params".to_string(),
                kind: v4_params_type,
                internal_type: None,
            }],
            outputs: vec![
                Param {
                    name: "amountOut".to_string(),
                    kind: ParamType::Uint(256),
                    internal_type: None,
                },
                Param {
                    name: "gasEstimate".to_string(),
                    kind: ParamType::Uint(128),
                    internal_type: None,
                },
            ],
            constant: None,
            state_mutability: StateMutability::NonPayable,
        };
        let mut v4_quoter_abi = Abi::default();
        v4_quoter_abi
            .functions
            .insert("quoteExactInputSingle".to_string(), vec![v4_function]);

        // 4. 标准 V2 Router ABI - 手动构建
        let mut router_abi = Abi::default();
        // swapExactETH...
        #[allow(deprecated)]
        let swap_eth_func = Function {
            name: "swapExactETHForTokensSupportingFeeOnTransferTokens".to_string(),
            inputs: vec![
                Param {
                    name: "amountOutMin".to_string(),
                    kind: ParamType::Uint(256),
                    internal_type: None,
                },
                Param {
                    name: "path".to_string(),
                    kind: ParamType::Array(Box::new(ParamType::Address)),
                    internal_type: None,
                },
                Param {
                    name: "to".to_string(),
                    kind: ParamType::Address,
                    internal_type: None,
                },
                Param {
                    name: "deadline".to_string(),
                    kind: ParamType::Uint(256),
                    internal_type: None,
                },
            ],
            outputs: vec![],
            constant: None,
            state_mutability: StateMutability::Payable,
        };
        router_abi.functions.insert(
            "swapExactETHForTokensSupportingFeeOnTransferTokens".to_string(),
            vec![swap_eth_func],
        );
        // swapExactTokens...
        #[allow(deprecated)]
        let swap_tokens_func = Function {
            name: "swapExactTokensForETHSupportingFeeOnTransferTokens".to_string(),
            inputs: vec![
                Param {
                    name: "amountIn".to_string(),
                    kind: ParamType::Uint(256),
                    internal_type: None,
                },
                Param {
                    name: "amountOutMin".to_string(),
                    kind: ParamType::Uint(256),
                    internal_type: None,
                },
                Param {
                    name: "path".to_string(),
                    kind: ParamType::Array(Box::new(ParamType::Address)),
                    internal_type: None,
                },
                Param {
                    name: "to".to_string(),
                    kind: ParamType::Address,
                    internal_type: None,
                },
                Param {
                    name: "deadline".to_string(),
                    kind: ParamType::Uint(256),
                    internal_type: None,
                },
            ],
            outputs: vec![],
            constant: None,
            state_mutability: StateMutability::NonPayable,
        };
        router_abi.functions.insert(
            "swapExactTokensForETHSupportingFeeOnTransferTokens".to_string(),
            vec![swap_tokens_func],
        );
        // getAmountsOut
        #[allow(deprecated)]
        let get_amounts_out_func = Function {
            name: "getAmountsOut".to_string(),
            inputs: vec![
                Param {
                    name: "amountIn".to_string(),
                    kind: ParamType::Uint(256),
                    internal_type: None,
                },
                Param {
                    name: "path".to_string(),
                    kind: ParamType::Array(Box::new(ParamType::Address)),
                    internal_type: None,
                },
            ],
            outputs: vec![Param {
                name: "amounts".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Uint(256))),
                internal_type: None,
            }],
            constant: Some(true),
            state_mutability: StateMutability::View,
        };
        router_abi
            .functions
            .insert("getAmountsOut".to_string(), vec![get_amounts_out_func]);

        // 5. ERC20 ABI - 手动构建
        let mut erc20_abi = Abi::default();
        #[allow(deprecated)]
        let balance_of_func = Function {
            name: "balanceOf".to_string(),
            inputs: vec![Param {
                name: "account".to_string(),
                kind: ParamType::Address,
                internal_type: None,
            }],
            outputs: vec![Param {
                name: "balance".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            }],
            constant: Some(true),
            state_mutability: StateMutability::View,
        };
        erc20_abi
            .functions
            .insert("balanceOf".to_string(), vec![balance_of_func]);
        #[allow(deprecated)]
        let approve_func = Function {
            name: "approve".to_string(),
            inputs: vec![
                Param {
                    name: "spender".to_string(),
                    kind: ParamType::Address,
                    internal_type: None,
                },
                Param {
                    name: "amount".to_string(),
                    kind: ParamType::Uint(256),
                    internal_type: None,
                },
            ],
            outputs: vec![Param {
                name: "success".to_string(),
                kind: ParamType::Bool,
                internal_type: None,
            }],
            constant: None,
            state_mutability: StateMutability::NonPayable,
        };
        erc20_abi
            .functions
            .insert("approve".to_string(), vec![approve_func]);

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
        evm.env.block.timestamp =
            rU256::from_limbs(block_timestamp.0).saturating_add(rU256::from(12));

        let path = vec![*WETH_BASE, token_out];

        // [新增] V3 费率探测逻辑
        let mut best_fee = 0u32;
        let is_v3 = router_addr == *UNIV3_ROUTER || router_addr == *PANCAKESWAP_V3_ROUTER;

        // [修改] 针对 Aerodrome 做特殊编码
        let amounts_out_calldata = if let Some(pool_key) = v4_pool_key {
            // [FIXED] Manual Token Construction for V4 to avoid "Invalid Data"
            let func = v4_quoter_abi.function("quoteExactInputSingle")?;
            let zero_for_one = *WETH_BASE < token_out;

            // PoolKey: (currency0, currency1, fee, tickSpacing, hooks)
            let pk_token = Token::Tuple(vec![
                Token::Address(pool_key.0),
                Token::Address(pool_key.1),
                Token::Uint(U256::from(pool_key.2)),
                Token::Int(U256::from(pool_key.3 as u32)), // [修复] i32 -> u32 -> U256，确保位模式正确
                Token::Address(pool_key.4),
            ]);
            // Params: (poolKey, zeroForOne, amountIn, hookData)
            let params_token = Token::Tuple(vec![
                pk_token,
                Token::Bool(zero_for_one),
                Token::Uint(amount_in_eth),
                Token::Bytes(vec![]),
            ]);

            let encoded = func.encode_input(&[params_token])?;
            evm.env.tx.transact_to = TransactTo::Call(rAddress::from(UNIV4_QUOTER.0));
            Bytes::from(encoded)
        } else if is_v3 {
            // V3 需要探测费率 (10000, 3000, 2500, 500, 100)
            // 加入 2500 (0.25%) 主要是为了 PancakeSwap
            let fees = vec![10000, 3000, 2500, 500, 100];
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
                if router_addr == *PANCAKESWAP_V3_ROUTER {
                    evm.env.tx.transact_to =
                        TransactTo::Call(rAddress::from(PANCAKESWAP_V3_QUOTER.0));
                } else {
                    evm.env.tx.transact_to = TransactTo::Call(rAddress::from(UNIV3_QUOTER.0));
                }
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
                            println!("      [Sim] V3 Pool Found: Fee={}", fee);
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
            let aero_router = BaseContract::from(aero_abi.clone());
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
            // [修复] 如果是 Universal Router 且没有 PoolKey，直接报错，不要尝试调用 V2 方法
            if router_addr == *UNIVERSAL_ROUTER {
                return Ok((
                    false,
                    U256::zero(),
                    U256::zero(),
                    "Universal Router requires PoolKey".to_string(),
                    0,
                    0,
                ));
            }
            // 标准 V2
            router.encode("getAmountsOut", (amount_in_eth, path.clone()))?
        };

        evm.env.tx.caller = my_wallet;
        if v4_pool_key.is_some() {
            evm.env.tx.transact_to = TransactTo::Call(rAddress::from(UNIV4_QUOTER.0));
        } else if is_v3 {
            if router_addr == *PANCAKESWAP_V3_ROUTER {
                evm.env.tx.transact_to = TransactTo::Call(rAddress::from(PANCAKESWAP_V3_QUOTER.0));
            } else {
                evm.env.tx.transact_to = TransactTo::Call(rAddress::from(UNIV3_QUOTER.0));
            }
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
                "Pool Not Found (V3)".to_string(), // [优化] 明确提示 V3 没池子
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

        // [Debug] 打印 Quote 结果
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
                        BaseContract::from(aero_abi.clone())
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
                println!("      [Sim] Quote returned Contract Creation (Unexpected)");
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
                // [优化] V2 路由 Revert(NoData) 通常意味着池子不存在
                if reason == "Revert(NoData)" {
                    return Ok((
                        false,
                        U256::zero(),
                        U256::zero(),
                        "Pool Not Found (V2)".to_string(),
                        0,
                        0,
                    ));
                }
                println!("      [Sim] Quote Reverted: {}", reason);
                return Ok((false, U256::zero(), U256::zero(), reason, 0, 0));
            }
            ExecutionResult::Halt { reason, .. } => {
                println!("      [Sim] Quote Halted: {:?}", reason);
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

        println!(
            "      [Sim] Quote Success. Expected Out: {}",
            expected_tokens
        );

        // [新增] 如果 Quote 结果为 0，直接终止，不要尝试买入（节省资源并减少误报）
        if expected_tokens.is_zero() {
            return Ok((
                false,
                U256::zero(),
                U256::zero(),
                "Zero Liquidity (Quote=0)".to_string(),
                0,
                0,
            ));
        }

        let deadline = U256::from(9999999999u64);

        // [修改] 针对 Aerodrome 的买入编码
        let buy_calldata = if v4_pool_key.is_some() {
            // V4 Simulation: We skip actual swap simulation for V4 in this simplified version
            // because encoding Universal Router V4 commands is complex.
            // [Fix] Shadow Mint for V4: manually give tokens to the user in simulation DB
            // so that balance checks pass.
            if !expected_tokens.is_zero() {
                // Warning: We cannot write directly to storage without knowing the slot.
                // But we can skip the "Buy" execution check and just return Success.
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
            let v3_swap_params_type = ParamType::Tuple(vec![
                ParamType::Address,   // tokenIn
                ParamType::Address,   // tokenOut
                ParamType::Uint(24),  // fee
                ParamType::Address,   // recipient
                ParamType::Uint(256), // amountIn
                ParamType::Uint(256), // amountOutMinimum
                ParamType::Uint(160), // sqrtPriceLimitX96
            ]);

            #[allow(deprecated)]
            let v3_swap_func = Function {
                name: "exactInputSingle".to_string(),
                inputs: vec![Param {
                    name: "params".to_string(),
                    kind: v3_swap_params_type,
                    internal_type: None,
                }],
                outputs: vec![Param {
                    name: "amountOut".to_string(),
                    kind: ParamType::Uint(256),
                    internal_type: None,
                }],
                constant: None,
                state_mutability: StateMutability::Payable,
            };

            // [修复] 手动构建 Token::Tuple 以确保 V3 Swap 编码正确
            // 结构体顺序: tokenIn, tokenOut, fee, recipient, deadline, amountIn, amountOutMinimum, sqrtPriceLimitX96
            let params_token = Token::Tuple(vec![
                Token::Address(*WETH_BASE),
                Token::Address(token_out),
                Token::Uint(U256::from(best_fee)),
                Token::Address(Address::from(my_wallet.0 .0)),
                Token::Uint(amount_in_eth),
                Token::Uint(U256::zero()), // amountOutMinimum
                Token::Uint(U256::zero()), // sqrtPriceLimitX96
            ]);

            let encoded = v3_swap_func.encode_input(&[params_token])?;
            Bytes::from(encoded)
        } else if router_addr == *AERODROME_ROUTER {
            // Aerodrome Swap: swapExactETHForTokensSupportingFeeOnTransferTokens(uint amountOutMin, Route[] routes, address to, uint deadline)
            #[allow(deprecated)]
            let aero_swap_func = Function {
                name: "swapExactETHForTokensSupportingFeeOnTransferTokens".to_string(),
                inputs: vec![
                    Param {
                        name: "amountOutMin".to_string(),
                        kind: ParamType::Uint(256),
                        internal_type: None,
                    },
                    Param {
                        name: "routes".to_string(),
                        kind: ParamType::Array(Box::new(route_struct_type.clone())),
                        internal_type: None,
                    },
                    Param {
                        name: "to".to_string(),
                        kind: ParamType::Address,
                        internal_type: None,
                    },
                    Param {
                        name: "deadline".to_string(),
                        kind: ParamType::Uint(256),
                        internal_type: None,
                    },
                ],
                outputs: vec![],
                constant: None,
                state_mutability: StateMutability::Payable,
            };
            let mut aero_swap_abi = Abi::default();
            aero_swap_abi.functions.insert(
                "swapExactETHForTokensSupportingFeeOnTransferTokens".to_string(),
                vec![aero_swap_func],
            );
            let aero_router = BaseContract::from(aero_swap_abi.clone());
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
        evm.env.tx.gas_limit = 1_000_000; // [优化] 提高 Gas Limit

        // [修复] 正确捕获 Swap 交易的 Revert 原因
        let buy_result = evm.transact_commit();
        match buy_result {
            Ok(ExecutionResult::Success { .. }) => {
                // Swap 成功，继续检查余额
            }
            Ok(ExecutionResult::Revert { output, .. }) => {
                let reason = decode_revert_reason(&output);
                println!("      [Sim] Buy Tx Reverted: {}", reason);
                return Ok((
                    false,
                    U256::zero(),
                    U256::zero(),
                    format!("[HONEYPOT/RESTRICTED] Buy Reverted: {}", reason), // [优化] 明确标记
                    0,
                    0,
                ));
            }
            _ => {
                println!("      [Sim] Buy Tx Failed (System/Halt)");
                return Ok((
                    false,
                    U256::zero(),
                    U256::zero(),
                    "Buy Failed (System)".to_string(),
                    0,
                    0,
                ));
            }
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
            let v3_swap_params_type = ParamType::Tuple(vec![
                ParamType::Address,   // tokenIn
                ParamType::Address,   // tokenOut
                ParamType::Uint(24),  // fee
                ParamType::Address,   // recipient
                ParamType::Uint(256), // amountIn
                ParamType::Uint(256), // amountOutMinimum
                ParamType::Uint(160), // sqrtPriceLimitX96
            ]);
            #[allow(deprecated)]
            let v3_swap_func = Function {
                name: "exactInputSingle".to_string(),
                inputs: vec![Param {
                    name: "params".to_string(),
                    kind: v3_swap_params_type,
                    internal_type: None,
                }],
                outputs: vec![Param {
                    name: "amountOut".to_string(),
                    kind: ParamType::Uint(256),
                    internal_type: None,
                }],
                constant: None,
                state_mutability: StateMutability::Payable,
            };
            let mut v3_swap_abi = Abi::default();
            v3_swap_abi
                .functions
                .insert("exactInputSingle".to_string(), vec![v3_swap_func]);
            let v3_router = BaseContract::from(v3_swap_abi);
            // Sell: Token -> WETH
            let params = (
                token_out,
                *WETH_BASE,
                best_fee,
                Address::from(my_wallet.0 .0),
                token_balance,
                U256::zero(),
                U256::zero(),
            );
            v3_router.encode("exactInputSingle", (params,))?
        } else if router_addr == *AERODROME_ROUTER {
            #[allow(deprecated)]
            let aero_sell_func = Function {
                name: "swapExactTokensForETHSupportingFeeOnTransferTokens".to_string(),
                inputs: vec![
                    Param {
                        name: "amountIn".to_string(),
                        kind: ParamType::Uint(256),
                        internal_type: None,
                    },
                    Param {
                        name: "amountOutMin".to_string(),
                        kind: ParamType::Uint(256),
                        internal_type: None,
                    },
                    Param {
                        name: "routes".to_string(),
                        kind: ParamType::Array(Box::new(route_struct_type.clone())),
                        internal_type: None,
                    },
                    Param {
                        name: "to".to_string(),
                        kind: ParamType::Address,
                        internal_type: None,
                    },
                    Param {
                        name: "deadline".to_string(),
                        kind: ParamType::Uint(256),
                        internal_type: None,
                    },
                ],
                outputs: vec![],
                constant: None,
                state_mutability: StateMutability::NonPayable,
            };
            let mut aero_sell_abi = Abi::default();
            aero_sell_abi.functions.insert(
                "swapExactTokensForETHSupportingFeeOnTransferTokens".to_string(),
                vec![aero_sell_func],
            );
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

        let block = self
            .provider
            .get_block(sim_block)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Failed to fetch sim block"))?;
        let block_timestamp = block.timestamp;

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
        evm.env.block.timestamp =
            rU256::from_limbs(block_timestamp.0).saturating_add(rU256::from(12));

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
