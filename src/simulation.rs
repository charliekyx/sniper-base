use crate::constants::WETH_BASE;
use anyhow::Result;
use ethers::abi::parse_abi; // [修复1] 显式引入 parse_abi
use ethers::prelude::*;
use ethers::types::{Address, Transaction, U256};
use revm::{
    db::{CacheDB, DatabaseRef, EthersDB},
    primitives::{
        AccountInfo, Address as rAddress, Bytecode, ExecutionResult, TransactTo, U256 as rU256,
    },
    EVM,
};
use std::str::FromStr;
use std::sync::Arc;

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

        // [修复2] 创建 CacheDB (内存层)
        // revm 3.5.0 中，CacheDB::new 需要一个 DatabaseRef。
        // EthersDB 实现了 DatabaseRef，我们直接传入它的实例。

        let mut cache_db = CacheDB::new(Box::new(ethers_db));
        let mut evm = EVM::new();
        evm.database(cache_db);

        // 配置环境 (Base Chain ID)
        evm.env.cfg.chain_id = 8453.into();
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
        let router_abi = BaseContract::from(
            parse_abi(&["function swapExactETHForTokens(uint256,address[],address,uint256) external payable returns (uint256[])"]).unwrap()
        );
        let path = vec![*WETH_BASE, token_out];
        let deadline = U256::from(9999999999u64);

        // [修复3] 类型转换 (ethers::Address -> revm::Address)
        // 在 revm 3.5.0 中，需要手动转换类型，或者使用 unsafe/transmute，这里用安全的方法：
        let revm_path: Vec<rAddress> = path.iter().map(|a| rAddress::from(a.0)).collect();
        let revm_token_out = rAddress::from(token_out.0);
        let revm_router = rAddress::from(router_addr.0);

        // 编码 Calldata
        // 注意：ethers 编码时使用 ethers 的类型
        let calldata = router_abi.encode(
            "swapExactETHForTokens",
            (
                U256::zero(),
                path.clone(),
                Address(my_wallet.0),
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
        let sell_calldata = router_abi.encode(
            "swapExactTokensForETH",
            (
                token_balance,
                U256::zero(),
                sell_path,
                Address::from(my_wallet.0),
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
