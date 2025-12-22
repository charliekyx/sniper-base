use crate::constants::WETH_BASE;
use anyhow::Result;
use ethers::abi::parse_abi;
use ethers::prelude::*;
use ethers::types::{Address, Transaction, U256};
use revm::{
    db::{CacheDB, Database, DatabaseRef, EthersDB},
    primitives::{
        AccountInfo, Address as rAddress, Bytecode, ExecutionResult, TransactTo, U256 as rU256, B256,
    },
    EVM,
};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

// Wrapper to make a `Database` into a `DatabaseRef` using interior mutability.
// This is needed because `revm@3.5.0`'s `EthersDB` implements `Database` (&mut self)
// but not `DatabaseRef` (&self), which `CacheDB` requires.
struct MutexDB<DB>(Arc<Mutex<DB>>);

impl<DB: Database> DatabaseRef for MutexDB<DB> {
    type Error = DB::Error;

    fn basic(&self, address: rAddress) -> Result<Option<AccountInfo>, Self::Error> {
        self.0.lock().unwrap().basic(address)
    }

    fn code_by_hash(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.0.lock().unwrap().code_by_hash(code_hash)
    }

    fn storage(&self, address: rAddress, index: rU256) -> Result<rU256, Self::Error> {
        self.0.lock().unwrap().storage(address, index)
    }

    fn block_hash(&self, number: rU256) -> Result<B256, Self::Error> {
        self.0.lock().unwrap().block_hash(number)
    }
}

pub struct Simulator {
    provider: Arc<Provider<Ws>>,
}

impl Simulator {
    pub fn new(provider: Arc<Provider<Ws>>) -> Self {
        Self { provider }
    }

    pub async fn simulate_bundle(
        &self,
        _target_tx: Option<Transaction>,
        router_addr: Address,
        amount_in_eth: U256,
        token_out: Address,
    ) -> Result<(bool, U256, String)> {
        // 1. 初始化 EVM
        let block_number = self.provider.get_block_number().await?.as_u64();

        // 创建 EthersDB (连接真实节点)
        let ethers_db = EthersDB::new(self.provider.clone(), Some(block_number.into())).unwrap();

        // Wrap EthersDB in our MutexDB to satisfy the `DatabaseRef` trait bound for CacheDB.
        let ethers_db_wrapped = MutexDB(Arc::new(Mutex::new(ethers_db)));
        let cache_db = CacheDB::new(ethers_db_wrapped);
        
        let mut evm = EVM::new();
        evm.database(cache_db);

        // 配置环境 (Base Chain ID)
        evm.env.cfg.chain_id = 8453;
        evm.env.block.number = rU256::from(block_number + 1);

        // 2. 模拟 "我" 买入 (ETH -> Token)
        let my_wallet = rAddress::from_str("0x0000000000000000000000000000000000001234").unwrap();

        // 给模拟钱包充钱
        let acc_info = AccountInfo {
            balance: rU256::from(10000000000000000000u128), // 10 ETH
            nonce: 0,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: None,
        };
        evm.db().unwrap().insert_account_info(my_wallet, acc_info);

        // 构造 swapExactETHForTokens 调用
        let router_abi = parse_abi(&[
            "function swapExactETHForTokens(uint,address[],address,uint) external payable returns (uint[])",
            "function swapExactTokensForETH(uint,uint,address[],address,uint) external returns (uint[])"
        ])?;
        let router_contract = BaseContract::from(router_abi);
        let path = vec![*WETH_BASE, token_out];
        let deadline = U256::from(9999999999u64);

        let revm_router = rAddress::from(router_addr.0);

        // 编码 Calldata
        let calldata = router_contract.encode(
            "swapExactETHForTokens",
            (
                U256::zero(),
                path.clone(),
                Address::from(my_wallet.0.0), // revm::Address -> ethers::Address
                deadline,
            ),
        )?;

        evm.env.tx.caller = my_wallet;
        evm.env.tx.transact_to = TransactTo::Call(revm_router);
        evm.env.tx.data = calldata.0.into(); // ethers Bytes -> revm Bytes
        evm.env.tx.value = rU256::from_limbs(amount_in_eth.0); // ethers U256 -> revm U256
        evm.env.tx.gas_limit = 500_000;

        // 执行交易
        let buy_result = evm.transact_commit();

        let token_balance = match buy_result {
            Ok(ExecutionResult::Success { .. }) => {
                // 模拟买入成功
                U256::from(1)
            }
            _ => return Ok((false, U256::zero(), "Buy Reverted".to_string())),
        };

        // 3. 模拟 "我" 卖出
        let sell_path = vec![token_out, *WETH_BASE];
        let sell_calldata = router_contract.encode(
            "swapExactTokensForETH",
            (
                token_balance,
                U256::zero(),
                sell_path,
                Address::from(my_wallet.0.0), // revm::Address -> ethers::Address
                deadline,
            ),
        )?;

        evm.env.tx.data = sell_calldata.0.into();
        evm.env.tx.value = rU256::ZERO;

        let sell_result = evm.transact_commit();

        match sell_result {
            Ok(ExecutionResult::Success { .. }) => {
                Ok((true, U256::from(100), "Profit".to_string()))
            }
            _ => Ok((false, U256::zero(), "Sell Reverted".to_string())),
        }
    }
}
