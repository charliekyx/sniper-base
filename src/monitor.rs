use crate::config::AppConfig;
use crate::constants::WETH_BASE;
use crate::lock_manager::LockManager;
use crate::position_dao::remove_position;
use crate::sell::execute_smart_sell;
use crate::strategies::DexStrategy;
use ethers::abi::{Abi, Function, Param, ParamType, StateMutability};
use ethers::prelude::*;
use ethers::providers::{Ipc, Provider};
use ethers::types::transaction::eip2718::TypedTransaction;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{debug, info, warn};

pub async fn monitor_position(
    client: Arc<SignerMiddleware<Provider<Ipc>, LocalWallet>>,
    strategy: Arc<dyn DexStrategy>,
    token_addr: Address,
    initial_cost_eth_arg: U256,
    config: AppConfig,
    lock_manager: LockManager,
    initial_simulated_tokens: Option<U256>,
) {
    info!("[MONITOR] Watching: {:?}", token_addr);

    // 准备一个极简的 ERC20 ABI 用于查询余额
    let mut erc20_abi = Abi::default();
    #[allow(deprecated)]
    let balance_func = Function {
        name: "balanceOf".to_string(),
        inputs: vec![Param {
            name: "account".to_string(),
            kind: ParamType::Address,
            internal_type: None,
        }],
        outputs: vec![Param {
            name: "balance".to_string(),
            kind: ParamType::Uint(256),
            internal_type: None,
        }],
        constant: Some(true),
        state_mutability: StateMutability::View,
    };
    erc20_abi
        .functions
        .insert("balanceOf".to_string(), vec![balance_func]);
    let token_contract = Contract::new(token_addr, erc20_abi, client.clone());

    let mut tp1_triggered = false;
    let mut check_count = 0;
    let mut shadow_balance = initial_simulated_tokens.unwrap_or(U256::zero());
    let mut initial_cost_eth = initial_cost_eth_arg; // 创建可变副本
    let mut highest_val = initial_cost_eth;
    let mut last_balance = U256::zero(); // 用于追踪余额变化

    loop {
        check_count += 1;
        if check_count % 20 == 0 {
            debug!("... monitoring {} ...", token_addr);
        }

        let balance: U256 = if config.shadow_mode {
            shadow_balance
        } else {
            match token_contract.method::<_, U256>("balanceOf", client.address()) {
                Ok(m) => match m.call().await {
                    Ok(b) => b,
                    Err(e) => {
                        debug!("Error fetching balance: {:?}", e);
                        sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                },
                Err(e) => {
                    debug!("Error encoding balance call: {:?}", e);
                    sleep(Duration::from_secs(1)).await;
                    continue;
                }
            }
        };

        if balance.is_zero() {
            info!(
                "[MONITOR] Balance is 0 for {:?}. Removing persistence.",
                token_addr
            );
            lock_manager.unlock(token_addr);
            remove_position(token_addr);
            break;
        }

        // [新增] 动态成本调整逻辑：配合 Copy Sell 和 分批止盈
        // 如果检测到余额减少（说明发生了卖出），则按比例下调初始成本和最高价记录
        if !last_balance.is_zero() && balance < last_balance {
            let ratio_num = balance;
            let ratio_den = last_balance;

            // 计算调整后的成本: new_cost = old_cost * (new_balance / old_balance)
            // 使用 saturating_mul 防止溢出 (虽然理论上不会)
            initial_cost_eth = initial_cost_eth
                .saturating_mul(ratio_num)
                .checked_div(ratio_den)
                .unwrap_or(initial_cost_eth);

            // 同时也调整最高价值记录，防止因为减仓导致触发移动止损
            highest_val = highest_val
                .saturating_mul(ratio_num)
                .checked_div(ratio_den)
                .unwrap_or(highest_val);

            info!(
                "[MONITOR] Position reduced (Copy Sell/TP). Adjusted Cost Basis: {} ETH",
                format_ether(initial_cost_eth)
            );
        }
        // 更新 last_balance
        last_balance = balance;

        // 统一使用策略获取当前价值
        let current_val = match strategy.encode_quote(balance, token_addr, *WETH_BASE) {
            Ok((to, data, _)) => {
                let tx: TypedTransaction = TransactionRequest::new().to(to).data(data).into();
                match client.provider().call(&tx, None).await {
                    Ok(output) => strategy.decode_quote(output).unwrap_or(U256::zero()),
                    Err(_) => {
                        sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                }
            }
            Err(_) => {
                sleep(Duration::from_millis(500)).await;
                continue;
            }
        };

        // [优化] 更新最高价值记录 (用于移动止损)
        if current_val > highest_val {
            highest_val = current_val;
        }

        let mut trigger_sell = false;
        let mut is_panic = false;
        let mut sell_amount = balance;
        let mut sell_reason = String::new();

        // 计算目标价格阈值
        let tp1_threshold = initial_cost_eth + (initial_cost_eth * config.tp1_percent / 100);
        let tp2_threshold = initial_cost_eth + (initial_cost_eth * config.tp2_percent / 100);
        let stop_loss_limit = initial_cost_eth * (100 - config.anti_rug_dip_threshold) / 100;

        // 1. 优先级最高：硬止损 (Hard Stop Loss)
        if current_val < stop_loss_limit {
            warn!("[ALERT] Price crashed! Panic Selling!");
            trigger_sell = true;
            is_panic = true;
            sell_reason = "Stop_Loss".to_string();
        } else {
            // 2. 检查移动止损 (Trailing Stop) 或 TP2
            // 如果开启了移动止损，则优先使用移动止损逻辑，忽略 TP2 (让利润奔跑)
            // 如果未开启移动止损，则使用 TP2 作为硬止盈
            if config.trailing_stop_enabled {
                let activation_price =
                    initial_cost_eth + (initial_cost_eth * config.trailing_stop_trigger_pct / 100);

                // 只有当当前最高价超过激活阈值时，才检查回撤
                if highest_val >= activation_price {
                    let callback_price =
                        highest_val * (100 - config.trailing_stop_callback_pct) / 100;
                    if current_val < callback_price {
                        info!(
                            "[EXIT] Trailing Stop Hit! High: {}, Curr: {}",
                            format_ether(highest_val),
                            format_ether(current_val)
                        );
                        trigger_sell = true;
                        sell_reason = format!("Trailing_Stop_High_{}", format_ether(highest_val));
                    }
                }
            } else if config.tp2_percent > 0 && current_val >= tp2_threshold {
                info!(
                    "[EXIT] TP2 Hit ({}%)! Selling {}%.",
                    config.tp2_percent, config.tp2_sell_pct
                );
                trigger_sell = true;
                sell_amount = balance * config.tp2_sell_pct / 100;
                sell_reason = format!("TP2_{}%", config.tp2_percent);
            }

            // 3. 独立检查 TP1 (回本逻辑)
            // 只要没有触发清仓卖出 (trigger_sell 为 false)，且 TP1 未触发过，就检查 TP1
            if !trigger_sell
                && config.tp1_percent > 0
                && !tp1_triggered
                && current_val >= tp1_threshold
            {
                info!(
                    "[EXIT] TP1 Hit ({}%)! Selling {}%.",
                    config.tp1_percent, config.tp1_sell_pct
                );
                trigger_sell = true;
                sell_amount = balance * config.tp1_sell_pct / 100;
                tp1_triggered = true;
                sell_reason = format!("TP1_{}%", config.tp1_percent);
            }
        }

        if trigger_sell {
            if config.shadow_mode {
                crate::logger::log_shadow_sell(
                    format!("{:?}", token_addr),
                    format_ether(initial_cost_eth),
                    format_ether(current_val),
                    sell_reason.clone(),
                );
                if sell_amount < balance {
                    shadow_balance = shadow_balance - sell_amount;
                } else {
                    lock_manager.unlock(token_addr);
                    break;
                }
            } else {
                let _ = execute_smart_sell(
                    client.clone(),
                    Some(strategy.clone()), // 传入当前策略，不再传空 Router
                    Address::zero(),        // Router 地址在此处被忽略，使用 0 地址占位
                    token_addr,
                    sell_amount,
                    &config,
                    is_panic,
                    strategy.fee(),
                    strategy.pool_key(),
                )
                .await;

                // 只有在清仓或恐慌卖出时才释放锁，防止分批止盈时重复买入
                if sell_amount >= balance || is_panic {
                    lock_manager.unlock(token_addr);
                    break; // [修复] 全仓卖出后必须退出循环，防止重复卖出
                }

                let email_body = format!(
                    "Event: Live Sell Executed\nToken: {:?}\nAmount: {:?}\nReason: {}\nCurrent Value: {} ETH",
                    token_addr, sell_amount, sell_reason, format_ether(current_val)
                );
                crate::email::send_email_alert("Sniper: LIVE SELL", &email_body);
            }
            if sell_amount < balance {
                sleep(Duration::from_secs(5)).await;
            }
        }
        sleep(Duration::from_secs(1)).await;
    }
}

// 辅助函数：安全地格式化 Ether 单位
fn format_ether(amount: U256) -> String {
    ethers::utils::format_units(amount, "ether").unwrap_or_else(|_| "0.0".to_string())
}
