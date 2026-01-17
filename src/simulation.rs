use crate::constants::WETH_BASE;
use anyhow::Result;
use ethers::abi::parse_abi;
// [修改] 引入 Ipc，去掉 Ws
use ethers::prelude::{BaseContract, Ipc, Middleware, Provider};
use ethers::types::{Address, Transaction, U256};
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
    ) -> Result<(bool, U256, U256, String, u64)> {
        let block_number = self.provider.get_block_number().await?.as_u64();

        // [修改] EthersDB 也要适配 Ipc
        let ethers_db = EthersDB::new(self.provider.clone(), Some(block_number.into()))
            .ok_or_else(|| anyhow::anyhow!("Failed to create EthersDB"))?;

        let fork_db = ForkDB::new(ethers_db);
        let mut cache_db = CacheDB::new(fork_db);

        let router_abi = parse_abi(&[
            "function swapExactETHForTokensSupportingFeeOnTransferTokens(uint,address[],address,uint) external payable",
            "function swapExactTokensForETHSupportingFeeOnTransferTokens(uint,uint,address[],address,uint) external",
            "function getAmountsOut(uint,address[]) external view returns (uint[])"
        ])?;
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
        let amounts_out_calldata = router.encode("getAmountsOut", (amount_in_eth, path.clone()))?;

        evm.env.tx.caller = my_wallet;
        evm.env.tx.transact_to = TransactTo::Call(revm_router);
        evm.env.tx.data = amounts_out_calldata.0.into();
        evm.env.tx.value = rU256::ZERO;
        evm.env.tx.gas_limit = 500_000;

        let result_amounts = match evm.transact_commit() {
            Ok(result) => result,
            Err(_) => {
                return Ok((
                    false,
                    U256::zero(),
                    U256::zero(),
                    "GetAmountsOut Failed".to_string(),
                    0,
                ))
            }
        };

        let expected_tokens: U256 = match result_amounts {
            ExecutionResult::Success {
                output: Output::Call(b),
                ..
            } => {
                let amounts: Vec<U256> = router.decode_output("getAmountsOut", b)?;
                *amounts
                    .last()
                    .ok_or_else(|| anyhow::anyhow!("Empty amounts"))?
            }
            _ => {
                return Ok((
                    false,
                    U256::zero(),
                    U256::zero(),
                    "GetAmountsOut Failed".to_string(),
                    0,
                ))
            }
        };

        let deadline = U256::from(9999999999u64);
        let buy_calldata = router.encode(
            "swapExactETHForTokensSupportingFeeOnTransferTokens",
            (
                U256::zero(),
                path.clone(),
                Address::from(my_wallet.0 .0),
                deadline,
            ),
        )?;

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
                ))
            }
        };

        if token_balance.is_zero() {
            return Ok((
                false,
                U256::zero(),
                U256::zero(),
                "Zero Tokens (High Tax?)".to_string(),
                0,
            ));
        }

        if token_balance * 10 < expected_tokens * 8 {
            return Ok((
                false,
                U256::zero(),
                expected_tokens,
                format!(
                    "High Buy Tax! Exp: {} Got: {}",
                    expected_tokens, token_balance
                ),
                0,
            ));
        }

        let approve_calldata = token.encode("approve", (router_addr, U256::MAX))?;
        evm.env.tx.transact_to = TransactTo::Call(revm_token);
        evm.env.tx.data = approve_calldata.0.into();
        evm.transact_commit().ok();

        let sell_path = vec![token_out, *WETH_BASE];
        let sell_calldata = router.encode(
            "swapExactTokensForETHSupportingFeeOnTransferTokens",
            (
                token_balance,
                U256::zero(),
                sell_path,
                Address::from(my_wallet.0 .0),
                deadline,
            ),
        )?;

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
            ))
        } else {
            Ok((
                true,
                U256::zero(),
                expected_tokens,
                "Sellable but Loss".to_string(),
                gas_used,
            ))
        }
    }

    // [新增] 自动扫描交易意图：不管 Input 是什么，只要模拟执行后发现目标收到了 Token，就认为是买入
    pub async fn scan_tx_for_token_in(&self, tx: Transaction) -> Result<Option<Address>> {
        let block_number = self.provider.get_block_number().await?.as_u64();

        // 创建临时的 EthersDB 用于此次模拟
        let ethers_db = EthersDB::new(self.provider.clone(), Some(block_number.into()))
            .ok_or_else(|| anyhow::anyhow!("Failed to create EthersDB"))?;

        let fork_db = ForkDB::new(ethers_db);
        let mut cache_db = CacheDB::new(fork_db);

        let mut evm = EVM {
            env: Default::default(),
            db: Some(&mut cache_db),
        };

        evm.env.cfg.chain_id = 8453;
        evm.env.block.number = rU256::from(block_number + 1);

        // 构造模拟交易环境
        evm.env.tx.caller = rAddress::from(tx.from.0);
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
