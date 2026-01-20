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

    let mut sold_half = false;
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

        if config.sell_strategy_3x_exit_all && current_val >= initial_cost_eth * 3 {
            info!("[EXIT] 3x Profit! Dumping ALL.");
            trigger_sell = true;
            sell_reason = "3x_Profit".to_string();
        } else if config.sell_strategy_2x_exit_half
            && !sold_half
            && current_val >= initial_cost_eth * 2
        {
            info!("[EXIT] 2x Profit! Selling HALF.");
            trigger_sell = true;
            sell_amount = balance / 2;
            sold_half = true;
            sell_reason = "2x_Profit_Half".to_string();
        } else {
            let stop_loss_limit = initial_cost_eth * (100 - config.anti_rug_dip_threshold) / 100;
            if current_val < stop_loss_limit {
                warn!("[ALERT] Price crashed! Panic Selling!");
                trigger_sell = true;
                is_panic = true;
                sell_reason = "Stop_Loss".to_string();
            }
        }

        if trigger_sell {
            if config.shadow_mode {
                crate::logger::log_shadow_sell(
                    format!("{:?}", token_addr),
                    ethers::utils::format_units(initial_cost_eth, "ether").unwrap(),
                    ethers::utils::format_units(current_val, "ether").unwrap(),
                    sell_reason.clone(),
                );
                if sell_reason == "2x_Profit_Half" {
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
                    *WETH_BASE,
                    sell_amount,
                    &config,
                    is_panic,
                    strategy.fee(),
                    strategy.pool_key(),
                )
                .await;
                lock_manager.unlock(token_addr);
            }
            if !sold_half || is_panic {
                sleep(Duration::from_secs(5)).await;
            }
        }
        sleep(Duration::from_secs(2)).await;
    }
}
