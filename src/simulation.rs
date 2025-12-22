use crate::constants::WETH_BASE;
use anyhow::Result;
use ethers::abi::parse_abi;
use ethers::prelude::{BaseContract, Provider, Ws};
use ethers::providers::Middleware;
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

pub struct Simulator {
    provider: Arc<Provider<Ws>>,
}

// Wrapper to make EthersDB (which is &mut) compatible with CacheDB (which needs DatabaseRef/&self)
pub struct ForkDB {
    backend: RefCell<EthersDB<Provider<Ws>>>,
}

impl ForkDB {
    pub fn new(backend: EthersDB<Provider<Ws>>) -> Self {
        Self {
            backend: RefCell::new(backend),
        }
    }
}

impl DatabaseRef for ForkDB {
    type Error = <EthersDB<Provider<Ws>> as Database>::Error;

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
        // Pass U256 directly as required by the Database trait in this version of revm
        self.backend.borrow_mut().block_hash(number)
    }
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

        // 1. Initialize EthersDB
        let ethers_db = EthersDB::new(self.provider.clone(), Some(block_number.into()))
            .ok_or_else(|| anyhow::anyhow!("Failed to create EthersDB"))?;

        // 2. Wrap in ForkDB and then CacheDB
        let fork_db = ForkDB::new(ethers_db);
        let mut cache_db = CacheDB::new(fork_db);

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

        // 3. Setup simulation wallet
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

        // Create EVM instance
        let mut evm = EVM {
            env: Default::default(),
            db: Some(&mut cache_db),
        };

        // Configure EVM environment
        evm.env.cfg.chain_id = 8453;
        evm.env.block.number = rU256::from(block_number + 1);

        // Step 0: Get expected token amount
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

        // Tax check
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
        // Directly get from cache_db because evm.db is just a mutable reference to it
        // Note: After transact_commit, the state is already written to cache_db
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
