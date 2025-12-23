mod config;
mod constants;
mod logger;
mod simulation;

use crate::config::AppConfig;
use crate::constants::{get_router_name, WETH_BASE};
use crate::logger::{log_shadow_trade, ShadowRecord};
use crate::simulation::Simulator;
use chrono::Local;
use ethers::abi::parse_abi;
use ethers::prelude::*;
use std::env;
use std::io::{self, Write};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task;
use tokio::time::{sleep, Duration};

// --- Helper: Input Data Decoding ---
fn decode_router_input(input: &[u8]) -> Option<(String, Address)> {
    if input.len() < 4 { return None; }
    let sig = &input[0..4];

    // Helper: read 32 bytes as usize
    let read_usize = |offset: usize| -> Option<usize> {
        if offset + 32 > input.len() { return None; }
        let slice = &input[offset..offset + 32];
        let val = U256::from_big_endian(slice);
        if val > U256::from(usize::MAX) { return None; }
        Some(val.as_usize())
    };

    // Helper: read address
    let read_address = |offset: usize| -> Option<Address> {
        if offset + 32 > input.len() { return None; }
        Some(Address::from_slice(&input[offset + 12..offset + 32]))
    };

    // Helper: parse address[] path
    let get_path_token = |arg_index: usize, get_last: bool| -> Option<Address> {
        let offset_ptr = 4 + arg_index * 32;
        let array_offset = read_usize(offset_ptr)?;
        let len_ptr = 4 + array_offset;
        let array_len = read_usize(len_ptr)?;
        if array_len == 0 { return None; }
        let elem_index = if get_last { array_len - 1 } else { 0 };
        let item_ptr = len_ptr + 32 + elem_index * 32;
        read_address(item_ptr)
    };

    if sig == [0x7f, 0xf3, 0x6a, 0xb5] || sig == [0xb6, 0xf9, 0xde, 0x95] {
        let action = if sig[0] == 0x7f { "Buy_ETH->Token" } else { "Buy_Fee_ETH->Token" };
        return get_path_token(1, true).map(|t| (action.to_string(), t));
    } else if sig == [0x18, 0xcb, 0xaf, 0xe5] || sig == [0x79, 0x1a, 0xc9, 0x47] {
        let action = if sig[0] == 0x18 { "Sell_Token->ETH" } else { "Sell_Fee_Token->ETH" };
        return get_path_token(2, false).map(|t| (action.to_string(), t));
    } else if sig == [0x38, 0xed, 0x17, 0x39] {
        return get_path_token(2, true).map(|t| ("Swap_Token->Token".to_string(), t));
    } else if sig == [0xf3, 0x05, 0xd7, 0x19] {
        return read_address(4).map(|t| ("AddLiquidity".to_string(), t));
    }
    None
}

// --- Transaction Execution ---

async fn execute_buy_and_approve(
    client: Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    router_addr: Address,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    config: &AppConfig,
) -> anyhow::Result<()> {
    println!(">>> [BUNDLE] Preparing Buy + Approve sequence for {:?}...", token_out);

    let start_nonce = client
        .get_transaction_count(client.address(), Some(BlockNumber::Pending.into()))
        .await?;

    let router_abi = parse_abi(&[
        "function swapExactETHForTokensSupportingFeeOnTransferTokens(uint amountOutMin, address[] calldata path, address to, uint deadline) external payable"
    ])?;
    let router = BaseContract::from(router_abi);
    let path = vec![token_in, token_out];
    let deadline = U256::from(Local::now().timestamp() + 60);

    let calldata = router.encode(
        "swapExactETHForTokensSupportingFeeOnTransferTokens",
        (U256::zero(), path, client.address(), deadline),
    )?;

    // Gas Strategy for Small Capital
    // We use standard gas price + small priority fee.
    let gas_price = client.provider().get_gas_price().await?;
    let priority_fee = U256::from(config.max_priority_fee_gwei * 1_000_000_000);
    let total_gas_price = gas_price + priority_fee;

    let buy_tx = TransactionRequest::new()
        .to(router_addr)
        .value(amount_in)
        .data(calldata.0)
        .gas(config.gas_limit)
        .gas_price(total_gas_price)
        .nonce(start_nonce);

    let erc20_abi = parse_abi(&["function approve(address,uint) external returns (bool)"])?;
    let token_contract = BaseContract::from(erc20_abi);
    let approve_calldata = token_contract.encode("approve", (router_addr, U256::MAX))?;

    let approve_tx = TransactionRequest::new()
        .to(token_out)
        .data(approve_calldata.0)
        .gas(80_000) // Lower gas limit for approve to save money
        .gas_price(total_gas_price)
        .nonce(start_nonce + 1);

    println!(">>> [BUNDLE] Broadcasting Nonce {} & {}...", start_nonce, start_nonce + 1);

    let pending_buy = client.send_transaction(buy_tx, None).await?;
    let pending_approve = client.send_transaction(approve_tx, None).await?;

    println!(">>> [BUNDLE] Sent! Hashes: {:?} | {:?}", pending_buy.tx_hash(), pending_approve.tx_hash());

    let receipt = pending_buy.await?;
    if receipt.is_some() && receipt.unwrap().status == Some(U64::from(1)) {
        println!(">>> [BUNDLE] Buy Confirmed. Starting monitor...");
        Ok(())
    } else {
        Err(anyhow::anyhow!("Buy transaction reverted"))
    }
}

async fn execute_sell(
    client: Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    router_addr: Address,
    token_in: Address,
    token_out: Address,
    amount_token: U256,
    config: &AppConfig,
) -> anyhow::Result<TxHash> {
    println!("<<< [SELL] Selling Amount: {}...", amount_token);

    let router_abi = parse_abi(&[
        "function swapExactTokensForETHSupportingFeeOnTransferTokens(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline) external"
    ])?;
    let router = BaseContract::from(router_abi);
    let path = vec![token_in, token_out];
    let deadline = U256::from(Local::now().timestamp() + 120);

    let sell_calldata = router.encode(
        "swapExactTokensForETHSupportingFeeOnTransferTokens",
        (amount_token, U256::zero(), path, client.address(), deadline),
    )?;

    let gas_price = client.provider().get_gas_price().await?
        + U256::from(config.max_priority_fee_gwei * 1_000_000_000);

    let tx = TransactionRequest::new()
        .to(router_addr)
        .data(sell_calldata.0)
        .gas(config.gas_limit)
        .gas_price(gas_price);

    let pending_tx = client.send_transaction(tx, None).await?;
    println!("<<< [SELL] Hash: {:?}", pending_tx.tx_hash());
    Ok(pending_tx.tx_hash())
}

async fn monitor_position(
    client: Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    router_addr: Address,
    token_addr: Address,
    initial_cost_eth: U256,
    config: AppConfig,
) {
    println!("*** [MONITOR] Watching: {:?}", token_addr);
    let erc20_abi = parse_abi(&["function balanceOf(address) external view returns (uint)"])
        .expect("Failed to parse ERC20 ABI");
    let token_contract = Contract::new(token_addr, erc20_abi, client.clone());
    let router_abi =
        parse_abi(&["function getAmountsOut(uint,address[]) external view returns (uint[])"])
            .expect("Failed to parse Router ABI");
    let router_contract = Contract::new(router_addr, router_abi, client.clone());
    let path = vec![token_addr, *WETH_BASE];

    let mut sold_half = false;
    let mut check_count = 0;

    loop {
        check_count += 1;
        if check_count % 20 == 0 {
            println!("... monitoring ...");
        }

        let balance: U256 = match token_contract.method("balanceOf", client.address()).unwrap().call().await {
            Ok(b) => b,
            Err(_) => {
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        if balance.is_zero() {
            println!("*** [MONITOR] Balance is 0. Position closed.");
            break;
        }

        let amounts_out: Vec<U256> = match router_contract.method("getAmountsOut", (balance, path.clone())).unwrap().call().await {
            Ok(v) => v,
            Err(_) => {
                sleep(Duration::from_millis(500)).await;
                continue;
            }
        };

        let current_val = *amounts_out.last().unwrap_or(&U256::zero());

        // Strategy for Small Cap (500 SGD)
        // We prioritize securing initial capital (Half Exit) to survive.
        if config.sell_strategy_3x_exit_all && current_val >= initial_cost_eth * 3 {
            println!("[EXIT] 3x Profit! Dumping ALL.");
            let _ = execute_sell(client.clone(), router_addr, token_addr, *WETH_BASE, balance, &config).await;
            break;
        }

        if config.sell_strategy_2x_exit_half && !sold_half && current_val >= initial_cost_eth * 2 {
            println!("[EXIT] 2x Profit! Selling HALF to recover cost.");
            let half = balance / 2;
            let _ = execute_sell(client.clone(), router_addr, token_addr, *WETH_BASE, half, &config).await;
            sold_half = true;
        }

        // Stop Loss
        let stop_loss_limit = initial_cost_eth * (100 - config.anti_rug_dip_threshold) / 100;
        if current_val < stop_loss_limit {
            println!("[ALERT] Price crashed! Panic Selling!");
            let _ = execute_sell(client.clone(), router_addr, token_addr, *WETH_BASE, balance, &config).await;
            break;
        }

        sleep(Duration::from_secs(2)).await;
    }
}

// Transaction Processor Task
async fn process_transaction(
    tx: Transaction,
    provider: Arc<Provider<Ws>>,
    client: Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    simulator: Simulator,
    config: AppConfig,
    targets: Vec<Address>,
) {
    if let Some(to) = tx.to {
        let router_name = get_router_name(&to);
        if router_name == "Unknown" { return; }

        if let Some((action, token_addr)) = decode_router_input(&tx.input) {
            let is_target_buy = config.copy_trade_enabled && targets.contains(&tx.from) && action == "Swap";
            let is_new_liquidity = config.sniper_enabled && action == "AddLiquidity";

            if is_target_buy || is_new_liquidity {
                println!("\n Trigger: {} | Token: {:?}", action, token_addr);
                let buy_amt = U256::from((config.buy_amount_eth * 1e18) as u64);

                // Anti-Trap Logic
                if config.sniper_block_delay > 0 && !config.shadow_mode {
                    let target_block = provider.get_block_number().await.unwrap_or_default() + config.sniper_block_delay;
                    // Optimization: Use a spin loop with tiny sleep for self-built node
                    loop {
                        let now = provider.get_block_number().await.unwrap_or_default();
                        if now >= target_block { break; }
                        sleep(Duration::from_millis(100)).await;
                    }
                }

                // Parallel Simulation
                let sim_res = simulator.simulate_bundle(None, to, buy_amt, token_addr).await;
                let (sim_ok, _, reason) = sim_res.unwrap_or((false, U256::zero(), "Simulation Error".to_string()));

                if !sim_ok {
                    println!("   [ABORT] Simulation failed: {}. Likely Honeypot.", reason);
                    return;
                }

                if config.shadow_mode {
                    println!("   [Shadow] Would buy now. Sim Result: {}", reason);
                    log_shadow_trade(ShadowRecord {
                        timestamp: Local::now().to_rfc3339(),
                        event_type: action,
                        router: router_name,
                        trigger_hash: format!("{:?}", tx.hash),
                        token_address: format!("{:?}", token_addr),
                        amount_in_eth: config.buy_amount_eth.to_string(),
                        simulation_result: reason,
                        profit_eth_after_sell: None,
                        gas_used: 0,
                        copy_target: None,
                    });
                } else {
                    match execute_buy_and_approve(client.clone(), to, *WETH_BASE, token_addr, buy_amt, &config).await {
                        Ok(_) => {
                            task::spawn(monitor_position(client, to, token_addr, buy_amt, config));
                        }
                        Err(e) => println!("   [Error] Buy Tx Failed: {:?}", e),
                    }
                }
            }
        }
    }
}

async fn run_shadow_mode(config: AppConfig) -> anyhow::Result<()> {
    let provider = Provider::<Ws>::connect(&config.rpc_url).await?;
    let provider = Arc::new(provider);

    println!(">>> SHADOW MODE STARTED <<<");
    if config.use_private_node {
        println!(">>> [OPTIMIZED] SELF-BUILT NODE DETECTED: UNLEASHING FULL SPEED");
        println!(">>> No Rate Limits | No Sampling | Full Mempool Stream");
    } else {
        println!(">>> [WARNING] Public Node Mode: Sampling 1/50 logs");
    }

    let filter = Filter::new().address(vec![*WETH_BASE]);
    let mut stream = provider.subscribe_logs(&filter).await?;
    let mut counter = 0;

    println!(">>> Waiting for logs...");

    while let Some(log) = stream.next().await {
        counter += 1;
        
        // Visual heartbeat
        if counter % 100 == 0 {
            print!(".");
            io::stdout().flush().unwrap();
        }

        // [OPTIMIZATION]
        // If using private node, process EVERYTHING.
        // If public node, sample to avoid 429 Errors.
        if !config.use_private_node && counter % 50 != 0 {
            continue;
        }

        if let Some(tx_hash) = log.transaction_hash {
            // [OPTIMIZATION]
            // Remove sleep for private node
            if !config.use_private_node {
                sleep(Duration::from_millis(100)).await;
            }

            // Spawn task to process log to avoid blocking the stream reader
            let p = provider.clone();
            let c = config.clone();
            task::spawn(async move {
                if let Ok(Some(tx)) = p.get_transaction(tx_hash).await {
                    if let Some((action, token_addr)) = decode_router_input(&tx.input) {
                        let to = tx.to.unwrap_or_default();
                        let router_name = get_router_name(&to);
                        if router_name != "Unknown" {
                            println!("\n[Shadow Capture] {} on {} | Token: {:?}", action, router_name, token_addr);
                            // Log logic here...
                        }
                    }
                }
            });
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let config = AppConfig::load("config.json");

    if config.shadow_mode {
        return run_shadow_mode(config).await;
    }

    println!("=== Base Sniper Pro ===");
    println!("Mode: LIVE (REAL MONEY)");
    if config.use_private_node {
        println!("Network: SELF-BUILT NODE (High Performance)");
    } else {
        println!("Network: PUBLIC RPC (Standard Performance)");
    }

    let provider = Provider::<Ws>::connect(&config.rpc_url).await?;
    let chain_id = provider.get_chainid().await?.as_u64();

    // Wallet Setup
    let env_key = env::var("PRIVATE_KEY").ok();
    let config_key = if config.private_key == "null" || config.private_key.is_empty() { None } else { Some(config.private_key.clone()) };
    let wallet = if let Some(pk) = env_key.or(config_key) {
        pk.parse::<LocalWallet>()?.with_chain_id(chain_id)
    } else {
        panic!("[FATAL] Live mode requires a private key.");
    };

    let client = Arc::new(SignerMiddleware::new(provider.clone(), wallet.clone()));
    let provider_arc = Arc::new(provider);
    let simulator = Simulator::new(provider_arc.clone());
    let targets = config.get_targets();

    // MPSC Channel:
    // With a self-built node, you might receive massive bursts of transactions.
    // We increase buffer size to 10,000 to avoid dropping potential targets.
    let (tx_sender, mut rx_receiver) = mpsc::channel::<Transaction>(10000);

    println!("Listening for Mempool Events...");
    let mut stream = provider_arc.subscribe_pending_txs().await?;

    // 1. Worker Task
    let p_clone = provider_arc.clone();
    let c_clone = client.clone();
    let cfg_clone = config.clone();
    let t_clone = targets.clone();
    let s_clone = simulator.clone();

    task::spawn(async move {
        while let Some(tx) = rx_receiver.recv().await {
            let p = p_clone.clone();
            let c = c_clone.clone();
            let cfg = cfg_clone.clone();
            let t = t_clone.clone();
            let s = s_clone.clone();
            
            // Spawn individual processing tasks
            // Self-built node can handle higher concurrency
            task::spawn(async move {
                 process_transaction(tx, p, c, s, cfg, t).await;
            });
        }
    });

    // 2. Listener Loop
    while let Some(tx_hash) = stream.next().await {
        let provider = provider_arc.clone();
        let sender = tx_sender.clone();
        
        task::spawn(async move {
            // Self-built nodes respond extremely fast.
            if let Ok(Some(tx)) = provider.get_transaction(tx_hash).await {
                let _ = sender.send(tx).await;
            }
        });
    }

    Ok(())
}