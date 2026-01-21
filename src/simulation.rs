use crate::constants::WETH_BASE;
use crate::decoder::decode_revert_reason;
use crate::strategies::{DexStrategy, SimulationBehavior};
use anyhow::Result;
use ethers::abi::{Abi, Function, Param, ParamType, StateMutability};
use ethers::prelude::{BaseContract, Ipc, Middleware, Provider};
use ethers::types::{Address, Transaction, U256};
use revm::{
    db::{CacheDB, DatabaseRef, EthersDB},
    primitives::{
        AccountInfo, Address as rAddress, Bytecode, ExecutionResult, Output, ResultAndState,
        TransactTo, B256 as rB256, U256 as rU256,
    },
    Database, EVM,
};
use std::cell::RefCell;
use std::str::FromStr;
use std::sync::Arc;
use tokio::{
    task,
    time::{sleep, Duration},
};
use tracing::{debug, warn};

/// ERC-20 Transfer(address,address,uint256) event signature hash
const TRANSFER_EVENT_SIG: rB256 = rB256::new([
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
]);

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
        strategy: Arc<dyn DexStrategy>,
        amount_in_eth: U256,
        token_out: Address,
    ) -> Result<(bool, U256, U256, String, u64, u32)> {
        let block_number = self.provider.get_block_number().await?.as_u64();
        let block = self
            .provider
            .get_block(block_number)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Failed to fetch block"))?;
        let block_timestamp = block.timestamp;

        // Clone data to move into blocking task
        let provider = self.provider.clone();
        let strategy_clone = strategy.clone();

        // Spawn blocking task to run EVM (EthersDB requires blocking context)
        let res = task::spawn_blocking(move || -> Result<(bool, U256, U256, String, u64, u32)> {
            let strategy = strategy_clone;
            // [修改] EthersDB 也要适配 Ipc
            let ethers_db = EthersDB::new(provider, Some(block_number.into()))
                .ok_or_else(|| anyhow::anyhow!("Failed to create EthersDB"))?;

            let fork_db = ForkDB::new(ethers_db);
            let mut cache_db = CacheDB::new(fork_db);

            // 使用辅助函数获取 ERC20 ABI (用于余额检查和授权)
            let token = BaseContract::from(get_erc20_abi());

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

            evm.env.tx.caller = my_wallet;
            evm.env.cfg.chain_id = 8453;
            evm.env.block.number = rU256::from(block_number + 1);
            evm.env.block.timestamp =
                rU256::from_limbs(block_timestamp.0).saturating_add(rU256::from(12));

            // [Optimized] Smart Routing Logic

            // [新增] V3 费率探测逻辑
            let (quote_target, quote_data, quote_value) =
                strategy.encode_quote(amount_in_eth, *WETH_BASE, token_out)?;

            evm.env.tx.transact_to = TransactTo::Call(rAddress::from(quote_target.0));
            evm.env.tx.data = quote_data.0.into();
            evm.env.tx.value = rU256::from_limbs(quote_value.0);
            evm.env.tx.gas_limit = 500_000;

            let result_amounts = if strategy.quote_requires_commit() {
                match evm.transact_commit() {
                    Ok(result) => result,
                    Err(_) => ExecutionResult::Revert {
                        gas_used: 0,
                        output: vec![].into(),
                    },
                }
            } else {
                match evm.transact() {
                    Ok(res) => res.result,
                    Err(_) => ExecutionResult::Revert {
                        gas_used: 0,
                        output: vec![].into(),
                    },
                }
            };

            // [Debug] 打印 Quote 结果
            let expected_tokens: U256 = match result_amounts {
                ExecutionResult::Success {
                    output: Output::Call(b),
                    ..
                } => strategy.decode_quote(b.to_vec().into()).unwrap_or_default(),
                ExecutionResult::Success {
                    output: Output::Create(..),
                    ..
                } => {
                    warn!("[Sim] Quote returned Contract Creation (Unexpected)");
                    return Ok((
                        false,
                        U256::zero(),
                        U256::zero(),
                        "Simulation returned contract creation".to_string(),
                        0,
                        0,
                    ));
                }
                ExecutionResult::Revert { output, gas_used } => {
                    let reason = decode_revert_reason(&output);
                    let reason = if reason == "Revert(NoData)" {
                        format!("[{}] Pool Not Found / No Liquidity", strategy.name())
                    } else {
                        format!("[{}] {}", strategy.name(), reason)
                    };
                    debug!("[Sim] Quote Reverted: {}", reason);
                    return Ok((false, U256::zero(), U256::zero(), reason, gas_used, 0));
                }
                ExecutionResult::Halt { reason, gas_used } => {
                    let msg = format!("[{}] Halted: {:?}", strategy.name(), reason);
                    debug!("[Sim] Quote Halted: {:?}", msg);
                    return Ok((false, U256::zero(), U256::zero(), msg, gas_used, 0));
                }
            };

            if !expected_tokens.is_zero() {
                debug!(
                    "[Sim] Quote Success. Expected Out: {}",
                    expected_tokens
                );
            }

            // [新增] 如果 Quote 结果为 0，直接终止，不要尝试买入（节省资源并减少误报）
            if expected_tokens.is_zero() && !strategy.quote_requires_commit() {
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

            // [Refactor] 使用策略定义的行为控制流程，解耦硬编码判断
            if strategy.simulation_behavior() == SimulationBehavior::QuoteOnly {
                if !expected_tokens.is_zero() {
                    return Ok((
                        true,
                        U256::zero(),
                        expected_tokens,
                        "Quote_Only_Success".to_string(),
                        0,
                        strategy.fee(),
                    ));
                }
                return Ok((
                    false,
                    U256::zero(),
                    U256::zero(),
                    "Quote_Only_Fail".to_string(),
                    0,
                    0,
                ));
            }

            // 使用 Strategy 接口获取买入调用数据
            let (buy_target, buy_calldata, buy_value) = strategy.encode_buy(
                amount_in_eth,
                token_out,
                origin,
                deadline,
                U256::zero(),
            )?;

            evm.env.tx.transact_to = TransactTo::Call(rAddress::from(buy_target.0));
            evm.env.tx.data = buy_calldata.0.into();
            evm.env.tx.value = rU256::from_limbs(buy_value.0);
            evm.env.tx.gas_limit = 1_000_000; // [优化] 提高 Gas Limit

            // 正确捕获 Swap 交易的 Revert 原因
            let buy_result = evm.transact_commit();
            match buy_result {
                Ok(ExecutionResult::Success { .. }) => {
                    // Swap 成功，继续检查余额
                }
                Ok(ExecutionResult::Revert { output, gas_used }) => {
                    let reason = decode_revert_reason(&output);
                    let msg = format!("[{}] Buy Reverted: {}", strategy.name(), reason);
                    debug!("[Sim] {}", msg);
                    return Ok((
                        false,
                        U256::zero(),
                        U256::zero(),
                        format!("[HONEYPOT/RESTRICTED] {}", msg),
                        gas_used,
                        0,
                    ));
                }
                Ok(ExecutionResult::Halt { reason, gas_used }) => {
                    let msg = format!("[{}] Buy Halted: {:?}", strategy.name(), reason);
                    warn!("[Sim] {}", msg);
                    return Ok((false, U256::zero(), U256::zero(), msg, gas_used, 0));
                }
                _ => {
                    warn!("[Sim] Buy Tx Failed (System/Halt)");
                    return Ok((
                        false,
                        U256::zero(),
                        U256::zero(),
                        format!("[{}] Buy Failed (System)", strategy.name()),
                        0,
                        0,
                    ));
                }
            }

            let balance_calldata = token.encode("balanceOf", origin)?;
            evm.env.tx.transact_to = TransactTo::Call(rAddress::from(token_out.0));
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

            // 合并余额与税率检查
            if !expected_tokens.is_zero() {
                if token_balance * 10 < expected_tokens * 8 {
                    let reason = if token_balance.is_zero() {
                        "Zero Tokens (No Liquidity/Honeypot)".to_string()
                    } else {
                        format!("High Buy Tax! Exp: {} Got: {}", expected_tokens, token_balance)
                    };
                    return Ok((false, U256::zero(), expected_tokens, reason, 0, 0));
                }
            } else if token_balance.is_zero() {
                // 盲买模式下的保底检查
                return Ok((false, U256::zero(), U256::zero(), "Zero Tokens (Blind Buy)".to_string(), 0, 0));
            }

            let approve_calldata = token.encode("approve", (buy_target, U256::MAX))?;
            evm.env.tx.transact_to = TransactTo::Call(rAddress::from(token_out.0));
            evm.env.tx.data = approve_calldata.0.into();

            // Check approve result explicitly
            match evm.transact_commit() {
                Ok(ExecutionResult::Success { .. }) => {}
                Ok(ExecutionResult::Revert { output, gas_used }) => {
                    let reason = decode_revert_reason(&output);
                    let msg = format!("[{}] Approve Reverted: {}", strategy.name(), reason);
                    return Ok((
                        false,
                        U256::zero(),
                        expected_tokens,
                        msg,
                        gas_used,
                        0,
                    ));
                }
                Ok(ExecutionResult::Halt { reason, gas_used }) => {
                    let msg = format!("[{}] Approve Halted: {:?}", strategy.name(), reason);
                    return Ok((false, U256::zero(), expected_tokens, msg, gas_used, 0));
                }
                _ => {
                    return Ok((
                        false,
                        U256::zero(),
                        expected_tokens,
                        format!("[{}] Approve Failed (System)", strategy.name()),
                        0,
                        0,
                    ))
                }
            }

            let (sell_target, sell_calldata, sell_value) = strategy.encode_sell(
                token_balance,
                token_out,
                origin,
                deadline,
                U256::zero(),
            )?;

            evm.env.tx.transact_to = TransactTo::Call(rAddress::from(sell_target.0));
            evm.env.tx.data = sell_calldata.0.into();
            evm.env.tx.value = rU256::from_limbs(sell_value.0);

            let sell_result = evm.transact_commit();

            // Check sell result explicitly and capture gas/revert reason
            let gas_used = match sell_result {
                Ok(ExecutionResult::Success { gas_used, .. }) => gas_used,
                Ok(ExecutionResult::Revert { output, gas_used }) => {
                    let reason = decode_revert_reason(&output);
                    let msg = format!("[{}] Sell Reverted: {}", strategy.name(), reason);
                    return Ok((
                        false,
                        U256::zero(),
                        expected_tokens,
                        msg,
                        gas_used,
                        0,
                    ));
                }
                Ok(ExecutionResult::Halt { reason, gas_used }) => {
                    let msg = format!("[{}] Sell Halted: {:?}", strategy.name(), reason);
                    return Ok((false, U256::zero(), expected_tokens, msg, gas_used, 0));
                }
                _ => {
                    return Ok((
                        false,
                        U256::zero(),
                        expected_tokens,
                        format!("[{}] Sell Failed (System)", strategy.name()),
                        0,
                        0,
                    ));
                }
            };

            let mut final_eth = evm
                .db
                .as_mut()
                .unwrap()
                .basic(my_wallet)
                .map_err(|_| anyhow::anyhow!("Failed"))?
                .unwrap()
                .balance;

            // V3 Swaps return WETH. Virtuals might also behave unexpectedly.
            // We check WETH balance for these strategies to ensure we capture all profit.
            if strategy.name().contains("V3") || strategy.name().contains("Virtuals") {
                let weth_balance_calldata =
                    token.encode("balanceOf", origin)?;
                let revm_weth = rAddress::from(WETH_BASE.0);
                evm.env.tx.transact_to = TransactTo::Call(revm_weth);
                evm.env.tx.data = weth_balance_calldata.0.into();

                if let Ok(ResultAndState {
                    result:
                        ExecutionResult::Success {
                            output: Output::Call(b),
                            ..
                        },
                    ..
                }) = evm.transact()
                {
                    if let Ok(weth_bal) = token.decode_output::<U256, _>("balanceOf", b) {
                        final_eth += rU256::from_limbs(weth_bal.0);
                    }
                }
            }

            if final_eth >= initial_eth {
                Ok((
                    true,
                    U256::from((final_eth - initial_eth).to_be_bytes::<32>()),
                    expected_tokens,
                    "Profitable".to_string(),
                    gas_used,
                    strategy.fee(),
                ))
            } else {
                // 增加亏损阈值检查
                // 计算亏损金额
                let loss = initial_eth - final_eth;
                let invest_amt = rU256::from_limbs(amount_in_eth.0);
                // 亏损阈值：20% (考虑到滑点和Gas，太低会误杀)
                let max_loss = invest_amt * rU256::from(20) / rU256::from(100);

                if loss > max_loss {
                    warn!(
                        "[Sim] High Loss: Initial={} Final={} Loss={} Max={}",
                        initial_eth, final_eth, loss, max_loss
                    );
                    Ok((
                        false,
                        U256::zero(),
                        expected_tokens,
                        "High Tax/Loss (>20%)".to_string(),
                        gas_used,
                        strategy.fee(),
                    ))
                } else {
                    Ok((
                        true,
                        U256::zero(),
                        expected_tokens,
                        "Sellable but Loss (SAFE TO TRADE)".to_string(),
                        gas_used,
                        strategy.fee(),
                    ))
                }
            }
        })
        .await??;

        Ok(res)
    }

    // 自动扫描交易意图：不管 Input 是什么，只要模拟执行后发现目标收到了 Token，就认为是买入
    pub async fn scan_tx_for_token_in(&self, tx: Transaction) -> Result<Option<Address>> {
        // 构造目标地址的 Topic (补齐 32 字节的 Address)
        let mut topic_bytes = [0u8; 32];
        topic_bytes[12..32].copy_from_slice(&tx.from.0);
        let target_topic = rB256::from(topic_bytes);

        // 1. 优先策略：直接获取交易回执 (Receipt)
        // 对于已上链的交易，这是最快且 100% 准确的方法，不需要模拟
        // [优化] 增加重试机制，防止节点索引延迟导致查不到 Receipt
        for _ in 0..3 {
            match self.provider.get_transaction_receipt(tx.hash).await {
                Ok(Some(receipt)) => {
                    for log in receipt.logs {
                        // Transfer(from, to, value) -> Topic[0]=Sig, Topic[1]=From, Topic[2]=To
                        if log.topics.len() == 3
                            && rB256::from_slice(log.topics[0].as_bytes()) == TRANSFER_EVENT_SIG
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

        // Manually set balance to MAX to bypass balance checks since disable_balance_check is not available in revm 3.5.0
        // We do this before creating EVM to avoid borrow checker issues
        let caller = rAddress::from(tx.from.0);
        let mut account = cache_db
            .basic(caller)
            .map_err(|_| anyhow::anyhow!("Failed to fetch account info"))?
            .unwrap_or_default();
        account.balance = rU256::MAX;

        // Manually set nonce to match the transaction nonce to bypass nonce checks
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
                for log in logs {
                    // Transfer(from, to, value) 有 3 个 topic: [Sig, From, To]
                    if log.topics.len() == 3 && log.topics[0] == TRANSFER_EVENT_SIG {
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

// [新增] 辅助函数：构建 ERC20 ABI
fn get_erc20_abi() -> Abi {
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
    erc20_abi
}
