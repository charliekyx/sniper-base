use crate::config::AppConfig;
use crate::decoder::PoolKey;
use crate::strategies::{get_strategy_for_position, DexStrategy, UniswapV4Strategy};
use chrono::Local;
use ethers::prelude::*;
use ethers::providers::{Ipc, Middleware, Provider};
use std::sync::Arc;
use tracing::{error, info, warn};

pub async fn execute_smart_sell(
    client: Arc<SignerMiddleware<Provider<Ipc>, LocalWallet>>,
    strategy_opt: Option<Arc<dyn DexStrategy>>, // [新增] 优先使用现成策略
    router_addr: Address,
    token_in: Address,
    amount_token: U256,
    config: &AppConfig,
    is_panic: bool,
    fee: u32,
    v4_pool_key: Option<PoolKey>,
) -> anyhow::Result<TxHash> {
    let deadline = U256::from(Local::now().timestamp() + 120);

    // 1. 获取对应的策略对象
    let strategy: Arc<dyn DexStrategy> = if let Some(s) = strategy_opt {
        s
    } else if let Some(pk) = v4_pool_key {
        Arc::new(UniswapV4Strategy {
            pool_key: pk,
            name: "V4 Sell".into(),
        })
    } else {
        Arc::from(get_strategy_for_position(router_addr, fee, token_in))
    };

    let send_sell = |amt: U256, gas_mult: u64| {
        let client = client.clone();
        let priority_fee = config.max_priority_fee_gwei;
        let strategy = &strategy;

        async move {
            // 2. 直接调用策略的编码方法
            let (target_router, calldata, _) =
                strategy.encode_sell(amt, token_in, client.address(), deadline, U256::zero())?;

            let base_fee = client.provider().get_gas_price().await?;
            let prio_fee_val = U256::from(priority_fee * 1_000_000_000 * gas_mult);
            let max_fee = base_fee + prio_fee_val;

            let tx = Eip1559TransactionRequest::new()
                .to(target_router)
                .data(calldata)
                .gas(500_000)
                .max_fee_per_gas(max_fee)
                .max_priority_fee_per_gas(prio_fee_val);
            let pending = client.send_transaction(tx, None).await?;
            Ok::<_, anyhow::Error>(pending.tx_hash())
        }
    };

    info!("[SELL] Attempting to sell: {}...", amount_token);
    match send_sell(amount_token, if is_panic { 2 } else { 1 }).await {
        Ok(tx_hash) => return Ok(tx_hash),
        Err(e) => error!("   [Sell Fail] 100% Sell failed: {:?}", e),
    }
    if is_panic {
        warn!("[EMERGENCY] 100% Sell failed. Trying 50% dump to save capital...");
        let half_amount = amount_token / 2;
        match send_sell(half_amount, 3).await {
            Ok(tx_hash) => return Ok(tx_hash),
            Err(e) => error!("[Sell Fail] 50% Sell failed: {:?}", e),
        }
    }
    Err(anyhow::anyhow!("All sell attempts failed"))
}
