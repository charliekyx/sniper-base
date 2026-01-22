use crate::buy::execute_buy_and_approve;
use crate::config::AppConfig;
use crate::constants::{get_router_name, UNIV3_QUOTER, UNIV3_ROUTER, USDC_BASE, WETH_BASE};
use crate::decoder::{decode_router_input, extract_pool_key_from_universal_router};
use crate::lock_manager::LockManager;
use crate::logger::{log_shadow_trade, log_to_file, ShadowRecord};
use crate::monitor::monitor_position;
use crate::nonce::NonceManager;
use crate::position_dao::{get_position, save_position, PositionData};
use crate::sell::execute_smart_sell;
use crate::simulation::Simulator;
use crate::spend_limit::SpendLimitManager;
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
    spend_manager: Arc<SpendLimitManager>,
) {
    if let Some(to) = tx.to {
        let is_from_target = targets.contains(&tx.from);
        if is_from_target {
            // 直接比较原始字节，避免 hex::encode 的内存分配
            if tx.input.len() >= 4 {
                let sig = &tx.input[0..4];
                // 0x095ea7b3: approve(address,uint256)
                // 0xa9059cbb: transfer(address,uint256)
                // 0x23b872dd: transferFrom(address,address,uint256)
                // 0xd0e30db0: deposit() (WETH wrap)
                // 0x2e1a7d4d: withdraw(uint256) (WETH unwrap)
                if sig == [0x09, 0x5e, 0xa7, 0xb3]
                    || sig == [0xa9, 0x05, 0x9c, 0xbb]
                    || sig == [0x23, 0xb8, 0x72, 0xdd]
                    || sig == [0xd0, 0xe3, 0x0d, 0xb0]
                    || sig == [0x2e, 0x1a, 0x7d, 0x4d]
                {
                    return;
                }
            }

            // 只有未被过滤的交易才进行 hex 编码用于日志显示
            let selector = if tx.input.len() >= 4 {
                ethers::utils::hex::encode(&tx.input[0..4])
            } else {
                "0x".to_string()
            };

            let msg = format!(
                "[ACTIVITY] Target: {:?} | To: {:?} | Selector: 0x{}",
                tx.from, to, selector
            );
            info!("{}", msg);
            log_to_file(msg);
        }

        let router_name = get_router_name(&to);
        let decoded = decode_router_input(&tx.input);
        let v4_pool_key = extract_pool_key_from_universal_router(&tx.input);

        // if let Some(pk) = v4_pool_key {
        //     if is_from_target {
        //         debug!("   [DEBUG] Extracted V4 PoolKey: Token0={:?}, Token1={:?}, Fee={}, TickSpacing={}, Hooks={:?}", pk.0, pk.1, pk.2, pk.3, pk.4);
        //     }
        // }

        let (mut action, mut token_addr, mut amount_in) = if let Some((act, tok, amt)) = decoded {
            (act, tok, amt)
        } else if is_from_target {
            if let Ok(Some(token)) = simulator.scan_tx_for_token_in(tx.clone()).await {
                ("Auto_Buy".to_string(), token, U256::zero())
            } else {
                let selector = if tx.input.len() >= 4 {
                    ethers::utils::hex::encode(&tx.input[0..4])
                } else {
                    "0x".to_string()
                };
                log_to_file(format!("[IGNORED] No token inflow (Sell/Fail/Wrap) | Target tx to {:?} | Selector: 0x{} | InputLen: {}", to, selector, tx.input.len()));
                return;
            }
        } else {
            return;
        };

        if token_addr == Address::zero() && action == "Universal_Interaction" {
            if let Ok(Some(token)) = simulator.scan_tx_for_token_in(tx.clone()).await {
                token_addr = token;
                action = "Auto_Buy_Universal".to_string();
            } else {
                return;
            }
        }

        if true {
            if is_from_target && router_name == "Unknown" {
                debug!(
                    "[DEBUG] Target interacted with unknown router/contract: {:?}",
                    to
                );
                log_to_file(format!(
                    "[DEBUG] Target interacted with unknown router/contract: {:?}",
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

            let cleanup = |token| {
                lock_manager.unlock(token);
            };

            let is_target_buy = config.copy_trade_enabled
                && is_from_target
                && (action.contains("Buy") || action.contains("Swap") || action == "Auto_Buy");

            // 检测目标是否在卖出
            let is_target_sell = config.copy_sell_enabled
                && is_from_target
                && (action.contains("Sell") || action.contains("Burn"));

            let is_new_liquidity = config.sniper_enabled && action == "AddLiquidity";

            if !is_target_buy && !is_new_liquidity && !is_target_sell {
                return;
            }
            if token_addr == *WETH_BASE {
                cleanup(token_addr);
                return;
            }

            // 跟单卖出逻辑
            if is_target_sell {
                // 只有当该代币绑定的 Leader 是当前交易发起者时，才卖出
                if let Some(leader) = lock_manager.get_leader(token_addr) {
                    if leader != tx.from {
                        // 虽然我们持有这个币，但卖出的人不是我们跟的大哥，忽略
                        return;
                    }

                    info!(
                        "[COPY SELL] Leader {:?} is selling {:?}. Calculating ratio...",
                        tx.from, token_addr
                    );

                    // 简单的获取余额逻辑 (构建最小 ABI)
                    let mut erc20_abi = ethers::abi::Abi::default();
                    let balance_func = ethers::abi::Function {
                        name: "balanceOf".to_string(),
                        inputs: vec![ethers::abi::Param {
                            name: "account".to_string(),
                            kind: ethers::abi::ParamType::Address,
                            internal_type: None,
                        }],
                        outputs: vec![ethers::abi::Param {
                            name: "balance".to_string(),
                            kind: ethers::abi::ParamType::Uint(256),
                            internal_type: None,
                        }],
                        constant: Some(true),
                        state_mutability: ethers::abi::StateMutability::View,
                    };
                    erc20_abi
                        .functions
                        .insert("balanceOf".to_string(), vec![balance_func]);
                    let token_contract = Contract::new(token_addr, erc20_abi, client.clone());

                    // 1. 获取当前的余额 (卖出后的余额)
                    let leader_balance_after = token_contract
                        .method::<_, U256>("balanceOf", leader)
                        .unwrap()
                        .call()
                        .await
                        .unwrap_or(U256::zero());

                    // 2. 计算卖出比例
                    // 如果解析不到 amount_in (为0)，则默认全仓卖出 (ratio = 1.0)
                    let ratio = if amount_in.is_zero() {
                        1.0
                    } else {
                        let total_before = leader_balance_after + amount_in;
                        if total_before.is_zero() {
                            1.0
                        } else {
                            let sold_f = amount_in.as_u128() as f64;
                            let total_f = total_before.as_u128() as f64;
                            sold_f / total_f
                        }
                    };

                    // 3. 获取我的余额
                    if let Ok(my_balance) = token_contract
                        .method::<_, U256>("balanceOf", client.address())
                        .unwrap()
                        .call()
                        .await
                    {
                        if !my_balance.is_zero() {
                            // 4. 计算我的卖出数量
                            let my_sell_amount = if ratio >= 0.99 {
                                my_balance // 如果卖出超过 99%，直接清仓
                            } else {
                                let my_bal_f = my_balance.as_u128() as f64;
                                let sell_f = my_bal_f * ratio;
                                U256::from(sell_f as u128)
                            };

                            if my_sell_amount.is_zero() {
                                return;
                            }

                            info!(
                                "[COPY SELL] Ratio: {:.2}% | My Sell: {} / {}",
                                ratio * 100.0,
                                my_sell_amount,
                                my_balance
                            );

                            // 尝试加载持仓信息以获取正确的 Router/Strategy
                            let strategy_opt = if let Some(pos) = get_position(token_addr) {
                                Some(Arc::from(get_strategy_for_position(
                                    pos.router_address,
                                    pos.fee.unwrap_or(0),
                                    token_addr,
                                )))
                            } else {
                                None // 如果找不到持仓文件，execute_smart_sell 会失败，但这比盲目卖出好
                            };

                            // 执行卖出
                            let _ = execute_smart_sell(
                                client.clone(),
                                strategy_opt, // 传入恢复的策略
                                Address::zero(),
                                token_addr,
                                my_sell_amount,
                                &config,
                                true, // 视为 Panic Sell，优先成交
                                0,    // Fee 自动获取
                                None, // Pool Key 自动获取
                            )
                            .await;

                            let email_body = format!(
                                "Event: Copy Sell Executed\nTarget: {:?}\nToken: {:?}",
                                tx.from, token_addr
                            );
                            crate::email::send_email_alert("Sniper: COPY SELL", &email_body);
                        }
                    }
                    // 卖出后不需要解锁，monitor.rs 会检测到余额为 0 自动退出并解锁
                    return;
                } else {
                    // 我们根本没持有这个币，忽略
                    return;
                }
            }

            // 确定 Leader: 如果是跟单，Leader 就是 tx.from；如果是狙击，Leader 为 0 地址
            let leader = if is_target_buy {
                tx.from
            } else {
                Address::zero()
            };

            // 买入逻辑 (只有未锁定的才买)
            if !lock_manager.try_lock(token_addr, leader) {
                return;
            }

            let trigger_msg = format!("Trigger: {} | Token: {:?}", action, token_addr);
            info!("{}", trigger_msg);
            log_to_file(trigger_msg);
            let buy_amt = U256::from((config.buy_amount_eth * 1e18) as u64);

            // 周限额检查：获取当前 ETH 对应的 USDC 价值
            let usdc_strategy = Arc::new(UniswapV3Strategy {
                router: *UNIV3_ROUTER,
                quoter: *UNIV3_QUOTER,
                fee: 3000,
                name: "PriceCheck".into(),
            });
            let usdc_val = match simulator
                .simulate_bundle(client.address(), usdc_strategy, buy_amt, *USDC_BASE, 0)
                .await
            {
                Ok((success, _, out, _, _, _)) if success => out.as_u128() as f64 / 1_000_000.0,
                _ => 0.0,
            };

            if usdc_val > 0.0 {
                let current_weekly = spend_manager.get_weekly_total();
                if current_weekly + usdc_val > config.weekly_usdc_limit {
                    warn!("[LIMIT] Weekly limit exceeded! Current: ${:.2}, This trade: ${:.2}, Limit: ${:.2}", 
                        current_weekly, usdc_val, config.weekly_usdc_limit);
                    cleanup(token_addr);
                    return;
                }
            }

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

            // 使用封装好的函数获取所有策略
            let strategies = get_all_strategies(token_addr, v4_pool_key);

            info!("[Strategy] Scanning markets for liquidity...");
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
                debug!("[Strategy] Attempting: {}", strategy_name);
                let sim_res = simulator
                    .simulate_bundle(
                        client.address(),
                        strategy.clone(),
                        buy_amt,
                        token_addr,
                        config.slippage_pct,
                    )
                    .await;
                match sim_res {
                    Ok(res) => {
                        let (success, _, amount_out, ref reason, _, _) = res;
                        debug!(
                            "[Sim Result]: Success={}, Gas={}, Reason='{}', Out={}",
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
                        error!("[Sim Error]: {:?}", e);
                        debug_errors.push(format!("[{}: Error {}]", strategy_name, e));
                    }
                }
            }

            let (sim_ok, _profit_wei, expected_tokens, reason, gas_used, best_fee) =
                best_sim_res.clone();
            if !sim_ok {
                warn!("[ABORT] All strategies failed.");
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
                "[Strategy] Selected Best Route: {} (Reason: {})",
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
                spend_manager.add_spend(usdc_val);
                info!("[Shadow] Sim OK: {}", reason);

                // let email_body = format!(
                //     "Event: Shadow Buy Triggered\nToken: {:?}\nAmount: {} ETH\nReason: {}\nTarget Wallet: {:?}",
                //     token_addr, config.buy_amount_eth, reason, tx.from
                // );
                // crate::email::send_email_alert("Sniper Bot: Shadow Buy", &email_body);

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
                expected_tokens * (100 - config.slippage_pct) / 100,
                &config,
            )
            .await
            {
                Ok(_) => {
                    spend_manager.add_spend(usdc_val);
                    info!("[PERSIST] Saving position to file...");

                    let email_body = format!(
                        "Event: Live Buy Confirmed\nToken: {:?}\nAmount: {} ETH\nRouter: {:?}\nTarget Wallet: {:?}",
                        token_addr, config.buy_amount_eth, effective_router, tx.from
                    );
                    crate::email::send_email_alert("Sniper: LIVE BUY SUCCESS", &email_body);

                    log_to_file(format!(
                        "[LIVE] Buy Confirmed & Position Saved: {:?}",
                        token_addr
                    ));
                    let pos_data = PositionData {
                        token_address: token_addr,
                        router_address: effective_router,
                        initial_cost_eth: buy_amt,
                        timestamp: Local::now().timestamp() as u64,
                        fee: Some(best_fee),
                        leader_wallet: Some(leader),
                    };
                    let _ = save_position(&pos_data);
                    task::spawn(monitor_position(
                        client,
                        strategy.clone(),
                        token_addr,
                        buy_amt,
                        config,
                        lock_manager.clone(),
                        None,
                    ));
                }
                Err(e) => {
                    error!("[Error] Buy Tx Failed: {:?}", e);
                    cleanup(token_addr);
                }
            }
        }
    }
}
