use crate::config::AppConfig;
use crate::nonce::NonceManager;
use crate::strategies::DexStrategy;
use chrono::Local;
use ethers::abi::{Abi, Function, Param, ParamType, StateMutability};
use ethers::prelude::*;
use ethers::providers::{Ipc, Middleware, Provider};
use std::sync::Arc;
use tokio::time::{timeout, Duration};
use tracing::{error, info, warn};

pub async fn execute_buy_and_approve(
    client: Arc<SignerMiddleware<Provider<Ipc>, LocalWallet>>,
    nonce_manager: Arc<NonceManager>,
    strategy: &dyn DexStrategy,
    token_out: Address,
    amount_in: U256,
    amount_out_min: U256,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let deadline = U256::from(Local::now().timestamp() + 60);
    let (router_addr, calldata, value) = strategy.encode_buy(
        amount_in,
        token_out,
        client.address(),
        deadline,
        amount_out_min,
    )?;
    info!(
        "[BUNDLE] Preparing Buy + Approve sequence for {:?}...",
        token_out
    );

    let nonce_buy = nonce_manager.get_and_increment();
    let nonce_approve = nonce_manager.get_and_increment();

    let gas_price = client.provider().get_gas_price().await.unwrap_or_default();
    let max_base_fee = U256::from(config.max_base_fee_gwei) * U256::from(1_000_000_000);
    if gas_price > max_base_fee {
        warn!(
            "SKIPPING BUY: Current base fee ({:.2} Gwei) > max configured base fee ({} Gwei)",
            gas_price.as_u64() as f64 / 1_000_000_000.0,
            config.max_base_fee_gwei
        );
        return Err(anyhow::anyhow!("Base fee too high"));
    }
    let priority_fee = U256::from(config.max_priority_fee_gwei * 1_000_000_000);
    let buffer_base_fee = gas_price * 125 / 100;
    let total_gas_price = buffer_base_fee + priority_fee;

    let buy_tx = Eip1559TransactionRequest::new()
        .to(router_addr)
        .value(value)
        .data(calldata)
        .gas(config.gas_limit)
        .max_fee_per_gas(total_gas_price)
        .max_priority_fee_per_gas(priority_fee)
        .nonce(nonce_buy);

    let mut erc20_abi = Abi::default();
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
    let token_contract = BaseContract::from(erc20_abi);
    let approve_calldata = token_contract.encode("approve", (router_addr, U256::MAX))?;
    let approve_tx = Eip1559TransactionRequest::new()
        .to(token_out)
        .data(approve_calldata.0)
        .gas(80_000)
        .max_fee_per_gas(total_gas_price)
        .max_priority_fee_per_gas(priority_fee)
        .nonce(nonce_approve);

    info!(
        "[BUNDLE] Broadcasting Nonce {} & {}...",
        nonce_buy, nonce_approve
    );
    let pending_buy = match client.send_transaction(buy_tx.clone(), None).await {
        Ok(p) => p,
        Err(e) => {
            error!("[ERROR] Buy Tx Failed immediately: {:?}", e);
            warn!("[RECOVERY] Attempting to resync Nonce from chain...");
            if let Ok(real_nonce) = client
                .get_transaction_count(
                    client.address(),
                    Some(BlockId::Number(BlockNumber::Pending)),
                )
                .await
            {
                nonce_manager.reset(real_nonce.as_u64());
            }
            return Err(e.into());
        }
    };
    let _ = client.send_transaction(approve_tx, None).await;
    info!("[BUNDLE] Buy Sent: {:?}", pending_buy.tx_hash());
    match timeout(Duration::from_secs(60), pending_buy).await {
        Ok(receipt_res) => {
            let receipt = receipt_res?;
            if receipt.is_some() && receipt.unwrap().status == Some(U64::from(1)) {
                info!("[BUNDLE] Buy Confirmed.");
                Ok(())
            } else {
                Err(anyhow::anyhow!("Buy transaction reverted"))
            }
        }
        Err(_) => {
            error!("[ALERT] Transaction STUCK (Low Gas). Please check Explorer !!!");
            Err(anyhow::anyhow!("Buy transaction timeout (Stuck)"))
        }
    }
}
