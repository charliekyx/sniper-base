use crate::buy::execute_buy_and_approve;
use crate::config::AppConfig;
use crate::constants::{
    get_router_name, AERODROME_FACTORY, AERODROME_ROUTER, AERO_V3_QUOTER, AERO_V3_ROUTER,
    ALIENBASE_ROUTER, BASESWAP_ROUTER, PANCAKESWAP_V3_QUOTER, PANCAKESWAP_V3_ROUTER,
    ROCKETSWAP_ROUTER, SUSHI_ROUTER, SWAPBASED_ROUTER, UNIV3_QUOTER, UNIV3_ROUTER, WETH_BASE,
};
use crate::decoder::{decode_router_input, extract_pool_key_from_universal_router};
use crate::lock_manager::LockManager;
use crate::logger::{log_shadow_trade, log_to_file, ShadowRecord};
use crate::monitor::monitor_position;
use crate::nonce::NonceManager;
use crate::position_dao::{save_position, PositionData};
use crate::simulation::Simulator;
use crate::strategies::*;
use chrono::Local;
use ethers::prelude::*;
use ethers::providers::{Ipc, Middleware, Provider};
use std::sync::Arc;
use tokio::task;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};

pub async fn process_transaction(
    tx: Transaction,
    provider: Arc<Provider<Ipc>>,
    client: Arc<SignerMiddleware<Provider<Ipc>, LocalWallet>>,
    nonce_manager: Arc<NonceManager>,
    simulator: Simulator,
    config: AppConfig,
    targets: Vec<Address>,
    lock_manager: LockManager,
) {
    if let Some(to) = tx.to {
        let is_from_target = targets.contains(&tx.from);
        if is_from_target {
            let selector_bytes = if tx.input.len() >= 4 {
                &tx.input[0..4]
            } else {
                &[]
            };
            let selector = ethers::utils::hex::encode(selector_bytes);
            if selector == "095ea7b3" || selector == "a9059cbb" {
                return;
            }
            let msg = format!(
                "[ACTIVITY] Target: {:?} | To: {:?} | Selector: 0x{}",
                tx.from, to, selector
            );
            info!("{}", msg);
            log_to_file(msg);
        }

        let router_name = get_router_name(&to);
        let decoded = decode_router_input(&tx.input);
        let mut v4_pool_key = extract_pool_key_from_universal_router(&tx.input);

        if let Some(pk) = v4_pool_key {
            if is_from_target {
                debug!("   [DEBUG] Extracted V4 PoolKey: Token0={:?}, Token1={:?}, Fee={}, TickSpacing={}, Hooks={:?}", pk.0, pk.1, pk.2, pk.3, pk.4);
            }
        }

        let (mut action, mut token_addr) = if let Some((act, tok)) = decoded {
            (act, tok)
        } else if is_from_target {
            if let Ok(Some(token)) = simulator.scan_tx_for_token_in(tx.clone()).await {
                ("Auto_Buy".to_string(), token)
            } else {
                let selector = if tx.input.len() >= 4 {
                    ethers::utils::hex::encode(&tx.input[0..4])
                } else {
                    "0x".to_string()
                };
                log_to_file(format!("   [IGNORED] No token inflow (Sell/Fail/Wrap) | Target tx to {:?} | Selector: 0x{} | InputLen: {}", to, selector, tx.input.len()));
                return;
            }
        } else {
            return;
        };

        if token_addr == Address::zero() && action == "Universal_Interaction" {
            if let Ok(Some(token)) = simulator.scan_tx_for_token_in(tx.clone()).await {
                token_addr = token;
                action = "Auto_Buy_Universal".to_string();
                if v4_pool_key.is_none() {
                    v4_pool_key = extract_pool_key_from_universal_router(&tx.input);
                    if v4_pool_key.is_some() {
                        debug!("   [DEBUG] Late Extraction of V4 PoolKey Success");
                    }
                }
            } else {
                return;
            }
        }

        if true {
            if is_from_target && router_name == "Unknown" {
                debug!(
                    "   [DEBUG] Target interacted with unknown router/contract: {:?}",
                    to
                );
                log_to_file(format!(
                    "   [DEBUG] Target interacted with unknown router/contract: {:?}",
                    to
                ));
            }
            if is_from_target {
                log_to_file(format!(
                    "   [MATCH] Action: {} | Token: {:?}",
                    action, token_addr
                ));
            }
            if router_name == "Unknown" && action != "AddLiquidity" && !action.contains("Auto_Buy")
            {
                return;
            }

            if !lock_manager.try_lock(token_addr) {
                return;
            }
            let cleanup = |token| {
                lock_manager.unlock(token);
            };

            let is_target_buy = config.copy_trade_enabled
                && is_from_target
                && (action.contains("Buy") || action.contains("Swap") || action == "Auto_Buy");
            let is_new_liquidity = config.sniper_enabled && action == "AddLiquidity";

            if !is_target_buy && !is_new_liquidity {
                cleanup(token_addr);
                return;
            }
            if token_addr == *WETH_BASE {
                cleanup(token_addr);
                return;
            }

            let trigger_msg = format!("Trigger: {} | Token: {:?}", action, token_addr);
            info!("\n {}", trigger_msg);
            log_to_file(trigger_msg);
            let buy_amt = U256::from((config.buy_amount_eth * 1e18) as u64);

            if config.sniper_block_delay > 0 && !config.shadow_mode {
                let target_block = provider.get_block_number().await.unwrap_or_default()
                    + config.sniper_block_delay;
                loop {
                    if provider.get_block_number().await.unwrap_or_default() >= target_block {
                        break;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
            }

            let mut strategies: Vec<Arc<dyn DexStrategy>> = Vec::new();
            if let Some(pk) = v4_pool_key {
                strategies.push(Arc::new(UniswapV4Strategy {
                    pool_key: pk,
                    name: "Extracted V4 Key".into(),
                }));
            }

            strategies.push(Arc::new(UniswapV3Strategy {
                router: *UNIV3_ROUTER,
                quoter: *UNIV3_QUOTER,
                fee: 10000,
                name: "UniV3 1%".into(),
            }));
            strategies.push(Arc::new(UniswapV3Strategy {
                router: *UNIV3_ROUTER,
                quoter: *UNIV3_QUOTER,
                fee: 3000,
                name: "UniV3 0.3%".into(),
            }));
            strategies.push(Arc::new(UniswapV3Strategy {
                router: *UNIV3_ROUTER,
                quoter: *UNIV3_QUOTER,
                fee: 500,
                name: "UniV3 0.05%".into(),
            }));
            strategies.push(Arc::new(UniswapV3Strategy {
                router: *PANCAKESWAP_V3_ROUTER,
                quoter: *PANCAKESWAP_V3_QUOTER,
                fee: 2500,
                name: "Pancake V3".into(),
            }));
            strategies.push(Arc::new(UniswapV3Strategy {
                router: *AERO_V3_ROUTER,
                quoter: *AERO_V3_QUOTER,
                fee: 100,
                name: "Aero V3 (Slipstream)".into(),
            }));

            strategies.push(Arc::new(UniswapV2Strategy {
                router: *SUSHI_ROUTER,
                name: "Sushi V2".into(),
            }));
            strategies.push(Arc::new(UniswapV2Strategy {
                router: *BASESWAP_ROUTER,
                name: "BaseSwap V2".into(),
            }));
            strategies.push(Arc::new(UniswapV2Strategy {
                router: *ALIENBASE_ROUTER,
                name: "AlienBase V2".into(),
            }));
            strategies.push(Arc::new(UniswapV2Strategy {
                router: *SWAPBASED_ROUTER,
                name: "SwapBased V2".into(),
            }));
            strategies.push(Arc::new(UniswapV2Strategy {
                router: *ROCKETSWAP_ROUTER,
                name: "RocketSwap V2".into(),
            }));

            strategies.push(Arc::new(AerodromeV2Strategy {
                router: *AERODROME_ROUTER,
                factory: *AERODROME_FACTORY,
                path: vec![*WETH_BASE, token_addr],
                name: "Aero V2 Direct".into(),
            }));
            strategies.push(Arc::new(VirtualsStrategy {
                name: "Virtuals Factory".into(),
            }));

            info!("   [Strategy] Scanning markets for liquidity...");
            let mut debug_errors = Vec::new();
            let mut best_sim_res = (
                false,
                U256::zero(),
                U256::zero(),
                "Init".to_string(),
                0,
                0u32,
            );
            let mut best_strategy: Option<Arc<dyn DexStrategy>> = None;
            let mut found_any = false;

            for strategy in strategies {
                let strategy_name = strategy.name().to_string();
                debug!("   [Strategy] Attempting: {}", strategy_name);
                let sim_res = simulator
                    .simulate_bundle(client.address(), strategy.clone(), buy_amt, token_addr)
                    .await;
                match sim_res {
                    Ok(res) => {
                        let (success, _, amount_out, ref reason, _, _) = res;
                        debug!(
                            "      -> Sim Result: Success={}, Gas={}, Reason='{}', Out={}",
                            success, res.4, reason, amount_out
                        );
                        if success {
                            let is_better = if !found_any {
                                true
                            } else {
                                let prev_reason = &best_sim_res.3;
                                let prev_out = best_sim_res.2;
                                let curr_prof = reason == "Profitable";
                                let prev_prof = prev_reason == "Profitable";
                                if curr_prof && !prev_prof {
                                    true
                                } else if curr_prof == prev_prof {
                                    amount_out > prev_out
                                } else {
                                    false
                                }
                            };
                            if is_better {
                                found_any = true;
                                best_sim_res = res.clone();
                                best_strategy = Some(strategy);
                                if reason == "Profitable" {
                                    break;
                                }
                            }
                        } else {
                            debug_errors.push(format!("[{}: {}]", strategy_name, reason));
                        }
                    }
                    Err(e) => {
                        error!("      -> Sim Error: {:?}", e);
                        debug_errors.push(format!("[{}: Error {}]", strategy_name, e));
                    }
                }
            }

            let (sim_ok, _profit_wei, expected_tokens, reason, gas_used, best_fee) =
                best_sim_res.clone();
            if !sim_ok {
                warn!("   [ABORT] All strategies failed.");
                for err in &debug_errors {
                    debug!("      -> {}", err);
                }
                log_to_file(format!(
                    "[ABORT] All Failed: {:?} | Token: {:?}",
                    debug_errors, token_addr
                ));
                cleanup(token_addr);
                return;
            }

            let strategy = best_strategy.unwrap();
            info!(
                "   [Strategy] Selected Best Route: {} (Reason: {})",
                strategy.name(),
                reason
            );
            let deadline = U256::from(Local::now().timestamp() + 3600);
            let effective_router = strategy
                .encode_buy(
                    buy_amt,
                    token_addr,
                    client.address(),
                    deadline,
                    U256::zero(),
                )
                .unwrap()
                .0;

            if config.shadow_mode {
                info!("   [Shadow] Sim OK: {}", reason);
                log_shadow_trade(ShadowRecord {
                    timestamp: Local::now().to_rfc3339(),
                    event_type: action.to_string(),
                    router: get_router_name(&effective_router),
                    trigger_hash: format!("{:?}", tx.hash),
                    token_address: format!("{:?}", token_addr),
                    amount_in_eth: config.buy_amount_eth.to_string(),
                    simulation_result: reason.clone(),
                    profit_eth_after_sell: Some("0.0".to_string()),
                    gas_used,
                    copy_target: Some(format!("{:?}", tx.from)),
                });
                task::spawn(monitor_position(
                    client.clone(),
                    strategy.clone(),
                    token_addr,
                    buy_amt,
                    config.clone(),
                    lock_manager.clone(),
                    Some(expected_tokens),
                ));
                return;
            }

            match execute_buy_and_approve(
                client.clone(),
                nonce_manager,
                strategy.as_ref(),
                token_addr,
                buy_amt,
                expected_tokens * 80 / 100,
                &config,
            )
            .await
            {
                Ok(_) => {
                    info!(">>> [PERSIST] Saving position to file...");
                    log_to_file(format!(
                        ">>> [LIVE] Buy Confirmed & Position Saved: {:?}",
                        token_addr
                    ));
                    let pos_data = PositionData {
                        token_address: token_addr,
                        router_address: effective_router,
                        initial_cost_eth: buy_amt,
                        timestamp: Local::now().timestamp() as u64,
                        fee: Some(best_fee),
                    };
                    let _ = save_position(&pos_data);
                    task::spawn(monitor_position(
                        client,
                        strategy.clone(),
                        token_addr,
                        buy_amt,
                        config,
                        lock_manager.clone(),
                        None
                    ));
                }
                Err(e) => {
                    error!("   [Error] Buy Tx Failed: {:?}", e);
                    cleanup(token_addr);
                }
            }
        }
    }
}
