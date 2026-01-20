use crate::config::AppConfig;
use crate::constants::{
    AERODROME_FACTORY, AERODROME_ROUTER, AERO_V3_QUOTER, AERO_V3_ROUTER, PANCAKESWAP_V3_QUOTER,
    PANCAKESWAP_V3_ROUTER, UNIV3_QUOTER, UNIV3_ROUTER, UNIV4_QUOTER, VIRTUALS_FACTORY_ROUTER,
    VIRTUALS_ROUTER, WETH_BASE,
};
use crate::decoder::PoolKey;
use crate::lock_manager::LockManager;
use crate::position_dao::remove_position;
use crate::sell::execute_smart_sell;
use ethers::abi::{Abi, Function, Param, ParamType, StateMutability};
use ethers::prelude::*;
use ethers::providers::{Ipc, Provider};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{debug, info, warn};

pub async fn monitor_position(
    client: Arc<SignerMiddleware<Provider<Ipc>, LocalWallet>>,
    router_addr: Address,
    token_addr: Address,
    initial_cost_eth: U256,
    config: AppConfig,
    lock_manager: LockManager,
    initial_simulated_tokens: Option<U256>,
    fee: u32,
    v4_pool_key: Option<PoolKey>,
) {
    info!("[MONITOR] Watching: {:?}", token_addr);
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

    let mut router_abi = Abi::default();
    #[allow(deprecated)]
    let get_amounts_out_func = Function {
        name: "getAmountsOut".to_string(),
        inputs: vec![
            Param {
                name: "amountIn".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
            Param {
                name: "path".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Address)),
                internal_type: None,
            },
        ],
        outputs: vec![Param {
            name: "amounts".to_string(),
            kind: ParamType::Array(Box::new(ParamType::Uint(256))),
            internal_type: None,
        }],
        constant: Some(true),
        state_mutability: StateMutability::View,
    };
    router_abi
        .functions
        .insert("getAmountsOut".to_string(), vec![get_amounts_out_func]);
    let router_contract = Contract::new(router_addr, router_abi, client.clone());

    let mut v4_quoter_abi = Abi::default();
    let v4_pool_key_type = ParamType::Tuple(vec![
        ParamType::Address,
        ParamType::Address,
        ParamType::Uint(24),
        ParamType::Int(24),
        ParamType::Address,
    ]);
    let v4_params_type = ParamType::Tuple(vec![
        v4_pool_key_type,
        ParamType::Bool,
        ParamType::Uint(128),
        ParamType::Bytes,
    ]);
    #[allow(deprecated)]
    let v4_quote_func = Function {
        name: "quoteExactInputSingle".to_string(),
        inputs: vec![Param {
            name: "params".to_string(),
            kind: v4_params_type,
            internal_type: None,
        }],
        outputs: vec![
            Param {
                name: "amountOut".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
            Param {
                name: "gasEstimate".to_string(),
                kind: ParamType::Uint(128),
                internal_type: None,
            },
        ],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    };
    v4_quoter_abi
        .functions
        .insert("quoteExactInputSingle".to_string(), vec![v4_quote_func]);
    let v4_quoter = Contract::new(*UNIV4_QUOTER, v4_quoter_abi, client.clone());

    let mut v3_quoter_abi = Abi::default();
    let v3_params_type = ParamType::Tuple(vec![
        ParamType::Address,
        ParamType::Address,
        ParamType::Uint(256),
        ParamType::Uint(24),
        ParamType::Uint(160),
    ]);
    #[allow(deprecated)]
    let v3_quote_func = Function {
        name: "quoteExactInputSingle".to_string(),
        inputs: vec![Param {
            name: "params".to_string(),
            kind: v3_params_type,
            internal_type: None,
        }],
        outputs: vec![
            Param {
                name: "amountOut".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
            Param {
                name: "sqrtPriceX96After".to_string(),
                kind: ParamType::Uint(160),
                internal_type: None,
            },
            Param {
                name: "initializedTicksCrossed".to_string(),
                kind: ParamType::Uint(32),
                internal_type: None,
            },
            Param {
                name: "gasEstimate".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
        ],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    };
    v3_quoter_abi
        .functions
        .insert("quoteExactInputSingle".to_string(), vec![v3_quote_func]);
    let target_quoter = if router_addr == *PANCAKESWAP_V3_ROUTER {
        *PANCAKESWAP_V3_QUOTER
    } else if router_addr == *AERO_V3_ROUTER {
        *AERO_V3_QUOTER
    } else {
        *UNIV3_QUOTER
    };
    let quoter_contract = Contract::new(target_quoter, v3_quoter_abi, client.clone());
    let path = vec![token_addr, *WETH_BASE];

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
            match token_contract.method("balanceOf", client.address()) {
                Ok(m) => match m.call().await {
                    Ok(b) => b,
                    Err(_) => {
                        sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                },
                Err(_) => {
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

        let current_val = if let Some(pk) = v4_pool_key {
            let zero_for_one = token_addr < *WETH_BASE;
            let params = (pk, zero_for_one, balance.as_u128(), Bytes::default());
            match v4_quoter.method::<_, (U256, u128)>("quoteExactInputSingle", (params,)) {
                Ok(m) => match m.call().await {
                    Ok((amount_out, _)) => amount_out,
                    Err(_) => {
                        sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                },
                Err(_) => {
                    sleep(Duration::from_millis(500)).await;
                    continue;
                }
            }
        } else if router_addr == *UNIV3_ROUTER
            || router_addr == *PANCAKESWAP_V3_ROUTER
            || router_addr == *AERO_V3_ROUTER
        {
            let params = (token_addr, *WETH_BASE, balance, fee, U256::zero());
            match quoter_contract
                .method::<((Address, Address, U256, u32, U256),), (U256, U256, u32, U256)>(
                    "quoteExactInputSingle",
                    (params,),
                ) {
                Ok(m) => match m.call().await {
                    Ok((amount_out, _, _, _)) => amount_out,
                    Err(_) => {
                        sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                },
                Err(_) => {
                    sleep(Duration::from_millis(500)).await;
                    continue;
                }
            }
        } else if router_addr == *VIRTUALS_ROUTER {
            #[allow(deprecated)]
            let get_amounts_out_func = Function {
                name: "getAmountsOut".to_string(),
                inputs: vec![
                    Param {
                        name: "amountIn".to_string(),
                        kind: ParamType::Uint(256),
                        internal_type: None,
                    },
                    Param {
                        name: "routes".to_string(),
                        kind: ParamType::Array(Box::new(ParamType::Tuple(vec![
                            ParamType::Address,
                            ParamType::Address,
                            ParamType::Bool,
                            ParamType::Address,
                        ]))),
                        internal_type: None,
                    },
                ],
                outputs: vec![Param {
                    name: "amounts".to_string(),
                    kind: ParamType::Array(Box::new(ParamType::Uint(256))),
                    internal_type: None,
                }],
                constant: Some(true),
                state_mutability: StateMutability::View,
            };
            let mut aero_abi = Abi::default();
            aero_abi
                .functions
                .insert("getAmountsOut".to_string(), vec![get_amounts_out_func]);
            let v_contract = Contract::new(*AERODROME_ROUTER, aero_abi, client.clone());
            let route1 = (token_addr, *VIRTUALS_ROUTER, false, *AERODROME_FACTORY);
            let route2 = (*VIRTUALS_ROUTER, *WETH_BASE, false, *AERODROME_FACTORY);
            let routes = vec![route1, route2];
            match v_contract.method::<_, Vec<U256>>("getAmountsOut", (balance, routes)) {
                Ok(m) => match m.call().await {
                    Ok(v) => *v.last().unwrap_or(&U256::zero()),
                    Err(_) => {
                        sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                },
                Err(_) => {
                    sleep(Duration::from_millis(500)).await;
                    continue;
                }
            }
        } else if router_addr == *VIRTUALS_FACTORY_ROUTER {
            #[allow(deprecated)]
            let get_sell_price_func = Function {
                name: "getSellPrice".to_string(),
                inputs: vec![
                    Param {
                        name: "token".to_string(),
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
                    name: "price".to_string(),
                    kind: ParamType::Uint(256),
                    internal_type: None,
                }],
                constant: Some(true),
                state_mutability: StateMutability::View,
            };
            let mut v_abi = Abi::default();
            v_abi
                .functions
                .insert("getSellPrice".to_string(), vec![get_sell_price_func]);
            let v_contract = Contract::new(router_addr, v_abi, client.clone());
            match v_contract.method::<_, U256>("getSellPrice", (token_addr, balance)) {
                Ok(m) => match m.call().await {
                    Ok(val) => val,
                    Err(_) => {
                        sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                },
                Err(_) => {
                    sleep(Duration::from_millis(500)).await;
                    continue;
                }
            }
        } else {
            match router_contract.method::<_, Vec<U256>>("getAmountsOut", (balance, path.clone())) {
                Ok(m) => match m.call().await {
                    Ok(v) => *v.last().unwrap_or(&U256::zero()),
                    Err(_) => {
                        sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                },
                Err(_) => {
                    sleep(Duration::from_millis(500)).await;
                    continue;
                }
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
                    router_addr,
                    token_addr,
                    *WETH_BASE,
                    sell_amount,
                    &config,
                    is_panic,
                    fee,
                    v4_pool_key,
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
