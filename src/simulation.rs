use crate::constants::WETH_BASE;
use anyhow::Result;
use ethers::abi::parse_abi;
use ethers::prelude::*;
use ethers::types::{Address, Transaction, U256};
use revm::{
    db::{CacheDB, Database, DatabaseRef, EthersDB},
    primitives::{
        AccountInfo, Address as rAddress, Bytecode, ExecutionResult, TransactTo, U256 as rU256, B256, Output,
    },
    EVM,
};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

// 解决 revm 数据库引用的包装器
struct MutexDB<DB>(Arc<Mutex<DB>>);
impl<DB: Database> DatabaseRef for MutexDB<DB> {
    type Error = DB::Error;
    fn basic(&self, address: rAddress) -> Result<Option<AccountInfo>, Self::Error> { self.0.lock().unwrap().basic(address) }
    fn code_by_hash(&self, code_hash: B256) -> Result<Bytecode, Self::Error> { self.0.lock().unwrap().code_by_hash(code_hash) }
    fn storage(&self, address: rAddress, index: rU256) -> Result<rU256, Self::Error> { self.0.lock().unwrap().storage(address, index) }
    fn block_hash(&self, number: rU256) -> Result<B256, Self::Error> { self.0.lock().unwrap().block_hash(number) }
}

pub struct Simulator {
    provider: Arc<Provider<Ws>>,
}

impl Simulator {
    pub fn new(provider: Arc<Provider<Ws>>) -> Self {
        Self { provider }
    }

    // 模拟完整流程：买入 -> 检查余额 -> 授权 -> 卖出
    pub async fn simulate_bundle(
        &self,
        _target_tx: Option<Transaction>, 
        router_addr: Address,
        amount_in_eth: U256,
        token_out: Address,
    ) -> Result<(bool, U256, String)> {
        let block_number = self.provider.get_block_number().await?.as_u64();
        let ethers_db = EthersDB::new(self.provider.clone(), Some(block_number.into())).unwrap();
        let cache_db = CacheDB::new(MutexDB(Arc::new(Mutex::new(ethers_db))));
        
        let mut evm = EVM::new();
        evm.database(cache_db);
        evm.env.cfg.chain_id = 8453;
        evm.env.block.number = rU256::from(block_number + 1);

        // 模拟钱包设置
        let my_wallet = rAddress::from_str("0x0000000000000000000000000000000000001234").unwrap();
        let initial_eth = rU256::from(10000000000000000000u128); // 10 ETH 初始资金
        evm.db().unwrap().insert_account_info(my_wallet, AccountInfo {
            balance: initial_eth,
            nonce: 0,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: None,
        });

        // 准备 ABI
        let router_abi = parse_abi(&[
            "function swapExactETHForTokensSupportingFeeOnTransferTokens(uint,address[],address,uint) external payable",
            "function swapExactTokensForETHSupportingFeeOnTransferTokens(uint,uint,address[],address,uint) external",
            "function getAmountsOut(uint,address[]) external view returns (uint[])"
        ])?;
        let erc20_abi = parse_abi(&["function balanceOf(address) external view returns (uint)", "function approve(address,uint) external returns (bool)"])?;

        let router = BaseContract::from(router_abi);
        let token = BaseContract::from(erc20_abi);
        let revm_router = rAddress::from(router_addr.0);
        let revm_token = rAddress::from(token_out.0);

        // 1. 模拟买入
        let path = vec![*WETH_BASE, token_out];
        let deadline = U256::from(9999999999u64);
        let buy_calldata = router.encode("swapExactETHForTokensSupportingFeeOnTransferTokens", (U256::zero(), path.clone(), Address::from(my_wallet.0.0), deadline))?;

        evm.env.tx.caller = my_wallet;
        evm.env.tx.transact_to = TransactTo::Call(revm_router);
        evm.env.tx.data = buy_calldata.0.into();
        evm.env.tx.value = rU256::from_limbs(amount_in_eth.0);
        evm.env.tx.gas_limit = 500_000;

        if evm.transact_commit().is_err() {
            return Ok((false, U256::zero(), "Buy Reverted".to_string()));
        }

        // 2. 检查买到了多少币
        let balance_calldata = token.encode("balanceOf", Address::from(my_wallet.0.0))?;
        evm.env.tx.transact_to = TransactTo::Call(revm_token);
        evm.env.tx.data = balance_calldata.0.into();
        evm.env.tx.value = rU256::ZERO;
        
        let token_balance: U256 = match evm.transact_commit() {
            Ok(ExecutionResult::Success { output: Output::Call(b), .. }) => token.decode_output("balanceOf", b)?,
            _ => return Ok((false, U256::zero(), "Balance Check Failed".to_string())),
        };

        if token_balance.is_zero() {
            return Ok((false, U256::zero(), "Zero Tokens Received (High Tax?)".to_string()));
        }

        // 3. 模拟授权 (Approve)
        let approve_calldata = token.encode("approve", (router_addr, U256::MAX))?;
        evm.env.tx.transact_to = TransactTo::Call(revm_token);
        evm.env.tx.data = approve_calldata.0.into();
        evm.transact_commit().ok();

        // 4. 模拟卖出
        let sell_path = vec![token_out, *WETH_BASE];
        let sell_calldata = router.encode("swapExactTokensForETHSupportingFeeOnTransferTokens", (token_balance, U256::zero(), sell_path, Address::from(my_wallet.0.0), deadline))?;
        
        evm.env.tx.caller = my_wallet;
        evm.env.tx.transact_to = TransactTo::Call(revm_router);
        evm.env.tx.data = sell_calldata.0.into();
        
        if evm.transact_commit().is_err() {
            // 关键：如果买入成功但卖出失败，这是典型的貔貅盘！
            return Ok((false, U256::zero(), "HONEYPOT DETECTED: Sell Reverted".to_string()));
        }

        // 5. 计算利润
        let final_eth = evm.db().unwrap().basic(my_wallet).unwrap().unwrap().balance;
        if final_eth > initial_eth {
            Ok((true, U256::from((final_eth - initial_eth).to_be_bytes::<32>()), "Profitable".to_string()))
        } else {
            Ok((true, U256::zero(), "Sellable but Loss".to_string()))
        }
    }
}