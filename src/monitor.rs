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
    initial_cost_eth: U256,
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

        let mut trigger_sell = false;
        let mut is_panic = false;
        let mut sell_amount = balance;
        let mut sell_reason = String::new();

        // 计算目标价格阈值
        let tp1_threshold = initial_cost_eth + (initial_cost_eth * config.tp1_percent / 100);
        let tp2_threshold = initial_cost_eth + (initial_cost_eth * config.tp2_percent / 100);
        let stop_loss_limit = initial_cost_eth * (100 - config.anti_rug_dip_threshold) / 100;

        // 优先级：止损 > TP2 (高利润) > TP1 (低利润)
        if current_val < stop_loss_limit {
            warn!("[ALERT] Price crashed! Panic Selling!");
            trigger_sell = true;
            is_panic = true;
            sell_reason = "Stop_Loss".to_string();
        } else if config.tp2_percent > 0 && current_val >= tp2_threshold {
            info!(
                "[EXIT] TP2 Hit ({}%)! Selling {}%.",
                config.tp2_percent, config.tp2_sell_pct
            );
            trigger_sell = true;
            sell_amount = balance * config.tp2_sell_pct / 100;
            sell_reason = format!("TP2_{}%", config.tp2_percent);
        } else if config.tp1_percent > 0 && !tp1_triggered && current_val >= tp1_threshold {
            info!(
                "[EXIT] TP1 Hit ({}%)! Selling {}%.",
                config.tp1_percent, config.tp1_sell_pct
            );
            trigger_sell = true;
            sell_amount = balance * config.tp1_sell_pct / 100;
            tp1_triggered = true;
            sell_reason = format!("TP1_{}%", config.tp1_percent);
        }

        if trigger_sell {
            if config.shadow_mode {
                crate::logger::log_shadow_sell(
                    format!("{:?}", token_addr),
                    ethers::utils::format_units(initial_cost_eth, "ether").unwrap(),
                    ethers::utils::format_units(current_val, "ether").unwrap(),
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
                    Address::zero(), // execute_smart_sell 内部会通过 strategy 重新获取 router
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
                }

                let email_body = format!(
                    "Event: Live Sell Executed\nToken: {:?}\nAmount: {:?}\nReason: {}\nCurrent Value: {} ETH",
                    token_addr, sell_amount, sell_reason, ethers::utils::format_units(current_val, "ether").unwrap()
                );
                crate::email::send_email_alert("Sniper: LIVE SELL", &email_body);
            }
            if sell_amount < balance {
                sleep(Duration::from_secs(5)).await;
            }
        }
        sleep(Duration::from_secs(2)).await;
    }
}
