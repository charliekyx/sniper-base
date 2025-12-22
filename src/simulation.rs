use crate::constants::WETH_BASE;
use anyhow::Result;
use ethers::abi::parse_abi;
use ethers::prelude::{BaseContract, Provider, Ws};
use ethers::providers::Middleware;
use ethers::types::{Address, Transaction, U256};
use revm::{
    db::{CacheDB, EthersDB},
    primitives::{
        AccountInfo, Address as rAddress, ExecutionResult, Output, TransactTo, U256 as rU256,
    },
    Database, EVM,
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
        &mut self,
        _target_tx: Option<Transaction>,
        router_addr: Address,
        amount_in_eth: U256,
        token_out: Address,
    ) -> Result<(bool, U256, String)> {
        let block_number = self.provider.get_block_number().await?.as_u64();

        // 1. Initialize EthersDB to fetch state (code + storage) on demand
        // self.provider is already an Arc<Provider<Ws>>, so we pass it directly.
        let ethers_db = EthersDB::new(self.provider.clone(), Some(block_number.into()))
            .ok_or_else(|| anyhow::anyhow!("Failed to create EthersDB"))?;
        let mut cache_db = CacheDB::new(ethers_db);

        // Prepare ABIs
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

        // 2. Setup simulation wallet (Mocking our own state)
        let my_wallet = rAddress::from_str("0x0000000000000000000000000000000000001234").unwrap();
        let initial_eth = rU256::from(10000000000000000000u128); // 10 ETH

        cache_db.insert_account_info(
            my_wallet,
            AccountInfo {
                balance: initial_eth,
                nonce: 0,
                code_hash: revm::primitives::KECCAK_EMPTY,
                code: None,
            },
        );

        // Create EVM instance with the database after all initial setup is done
        let mut evm = EVM {
            env: Default::default(),
            db: Some(&mut cache_db),
        };

        // Configure EVM environment
        evm.env.cfg.chain_id = 8453;
        evm.env.block.number = rU256::from(block_number + 1);

        // Step 0: Get expected token amount (for buy tax calculation)
        let path = vec![*WETH_BASE, token_out];
        let amounts_out_calldata = router.encode("getAmountsOut", (amount_in_eth, path.clone()))?;

        evm.env.tx.caller = my_wallet;
        evm.env.tx.transact_to = TransactTo::Call(revm_router);
        evm.env.tx.data = amounts_out_calldata.0.into();
        evm.env.tx.value = rU256::ZERO;
        evm.env.tx.gas_limit = 500_000;

        let result_amounts = match evm.transact_commit() {
            Ok(result) => result,
            Err(_) => return Ok((false, U256::zero(), "GetAmountsOut Failed".to_string())),
        };

        let expected_tokens: U256 = match result_amounts {
            ExecutionResult::Success {
                output: Output::Call(b),
                ..
            } => {
                let amounts: Vec<U256> = router.decode_output("getAmountsOut", b)?;
                *amounts
                    .last()
                    .ok_or_else(|| anyhow::anyhow!("Empty amounts returned from router"))?
            }
            _ => return Ok((false, U256::zero(), "GetAmountsOut Failed".to_string())),
        };

        // Step 1: Simulate buy
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
            return Ok((false, U256::zero(), "Buy Reverted".to_string()));
        }

        // Step 2: Check token balance
        let balance_calldata = token.encode("balanceOf", Address::from(my_wallet.0 .0))?;
        evm.env.tx.transact_to = TransactTo::Call(revm_token);
        evm.env.tx.data = balance_calldata.0.into();
        evm.env.tx.value = rU256::ZERO;

        let token_balance: U256 = match evm.transact_commit() {
            Ok(ExecutionResult::Success {
                output: Output::Call(b),
                ..
            }) => token.decode_output("balanceOf", b)?,
            _ => return Ok((false, U256::zero(), "Balance Check Failed".to_string())),
        };

        if token_balance.is_zero() {
            return Ok((
                false,
                U256::zero(),
                "Zero Tokens Received (High Tax?)".to_string(),
            ));
        }

        // Tax check: if received < 80% of expected, it's high tax
        if token_balance * 10 < expected_tokens * 8 {
            return Ok((
                false,
                U256::zero(),
                format!(
                    "High Buy Tax Detected! Exp: {} Got: {}",
                    expected_tokens, token_balance
                ),
            ));
        }

        // Step 3: Approve tokens
        let approve_calldata = token.encode("approve", (router_addr, U256::MAX))?;
        evm.env.tx.transact_to = TransactTo::Call(revm_token);
        evm.env.tx.data = approve_calldata.0.into();
        evm.transact_commit().ok();

        // Step 4: Simulate sell
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

        if evm.transact_commit().is_err() {
            return Ok((
                false,
                U256::zero(),
                "HONEYPOT DETECTED: Sell Reverted".to_string(),
            ));
        }

        // Step 5: Calculate final result
        // 直接从 cache_db 获取，因为 evm.db 只是它的一个可变引用
        // 注意：在 transact_commit 之后，状态已经写入了 cache_db
        let final_eth = cache_db
            .basic(my_wallet)
            .map_err(|_| anyhow::anyhow!("Failed to get balance"))?
            .unwrap()
            .balance;

        if final_eth > initial_eth {
            Ok((
                true,
                U256::from((final_eth - initial_eth).to_be_bytes::<32>()),
                "Profitable".to_string(),
            ))
        } else {
            Ok((true, U256::zero(), "Sellable but Loss".to_string()))
        }
    }
}
