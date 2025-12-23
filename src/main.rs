mod config;
mod constants;
mod logger;
mod simulation;
mod persistence; // 新增：引入持久化模块

use crate::config::AppConfig;
use crate::constants::{get_router_name, WETH_BASE};
use crate::logger::{log_shadow_trade, ShadowRecord};
use crate::simulation::Simulator;
use crate::persistence::{init_storage, load_all_positions, save_position, remove_position, PositionData}; // 新增
use chrono::Local;
use ethers::abi::parse_abi;
use ethers::prelude::*;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task;
use tokio::time::{sleep, timeout, Duration};
use dotenv::dotenv;

// --- Nonce Manager ---
struct NonceManager {
    nonce: AtomicU64,
}

impl NonceManager {
    fn new(start_nonce: u64) -> Self {
        Self {
            nonce: AtomicU64::new(start_nonce),
        }
    }

    fn get_and_increment(&self) -> U256 {
        let n = self.nonce.fetch_add(1, Ordering::SeqCst);
        U256::from(n)
    }
}

// --- Helper: Input Decoding ---
fn decode_router_input(input: &[u8]) -> Option<(String, Address)> {
    if input.len() < 4 { return None; }
    let sig = &input[0..4];
    let read_usize = |offset: usize| -> Option<usize> {
        if offset + 32 > input.len() { return None; }
        let slice = &input[offset..offset + 32];
        let val = U256::from_big_endian(slice);
        if val > U256::from(usize::MAX) { return None; }
        Some(val.as_usize())
    };
    let read_address = |offset: usize| -> Option<Address> {
        if offset + 32 > input.len() { return None; }
        Some(Address::from_slice(&input[offset + 12..offset + 32]))
    };
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

// --- Execution Core ---

async fn execute_buy_and_approve(
    client: Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    nonce_manager: Arc<NonceManager>,
    router_addr: Address,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    amount_out_min: U256, 
    config: &AppConfig,
) -> anyhow::Result<()> {
    println!(">>> [BUNDLE] Preparing Buy + Approve sequence for {:?}...", token_out);

    let nonce_buy = nonce_manager.get_and_increment();
    let nonce_approve = nonce_manager.get_and_increment();

    let router_abi = parse_abi(&[
        "function swapExactETHForTokensSupportingFeeOnTransferTokens(uint amountOutMin, address[] calldata path, address to, uint deadline) external payable"
    ])?;
    let router = BaseContract::from(router_abi);
    let path = vec![token_in, token_out];
    let deadline = U256::from(Local::now().timestamp() + 60);

    let calldata = router.encode(
        "swapExactETHForTokensSupportingFeeOnTransferTokens",
        (amount_out_min, path, client.address(), deadline),
    )?;

    let gas_price = client.provider().get_gas_price().await?;
    let priority_fee = U256::from(config.max_priority_fee_gwei * 1_000_000_000);
    let total_gas_price = gas_price + priority_fee;

    let buy_tx = TransactionRequest::new()
        .to(router_addr)
        .value(amount_in)
        .data(calldata.0)
        .gas(config.gas_limit)
        .gas_price(total_gas_price)
        .nonce(nonce_buy);

    let erc20_abi = parse_abi(&["function approve(address,uint) external returns (bool)"])?;
    let token_contract = BaseContract::from(erc20_abi);
    let approve_calldata = token_contract.encode("approve", (router_addr, U256::MAX))?;

    let approve_tx = TransactionRequest::new()
        .to(token_out)
        .data(approve_calldata.0)
        .gas(80_000)
        .gas_price(total_gas_price)
        .nonce(nonce_approve);

    println!(">>> [BUNDLE] Broadcasting Nonce {} & {}...", nonce_buy, nonce_approve);

    let pending_buy = client.send_transaction(buy_tx.clone(), None).await?;
    let pending_approve = client.send_transaction(approve_tx, None).await?;

    println!(">>> [BUNDLE] Sent! Hashes: {:?} | {:?}", pending_buy.tx_hash(), pending_approve.tx_hash());

    match timeout(Duration::from_secs(30), pending_buy).await {
        Ok(receipt_res) => {
            let receipt = receipt_res?;
            if receipt.is_some() && receipt.unwrap().status == Some(U64::from(1)) {
                println!(">>> [BUNDLE] Buy Confirmed.");
                Ok(())
            } else {
                Err(anyhow::anyhow!("Buy transaction reverted"))
            }
        },
        Err(_) => {
            println!("!!! [ALERT] Transaction STUCK (Low Gas). Please check Explorer !!!");
            Err(anyhow::anyhow!("Buy transaction timeout (Stuck)"))
        }
    }
}

// Smart Sell Logic
async fn execute_smart_sell(
    client: Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    router_addr: Address,
    token_in: Address,
    token_out: Address,
    amount_token: U256,
    config: &AppConfig,
    is_panic: bool,
) -> anyhow::Result<TxHash> {
    let router_abi = parse_abi(&[
        "function swapExactTokensForETHSupportingFeeOnTransferTokens(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline) external"
    ])?;
    let router = BaseContract::from(router_abi);
    let path = vec![token_in, token_out];
    let deadline = U256::from(Local::now().timestamp() + 120);

    let send_sell = |amt: U256, gas_mult: u64| {
        let router = router.clone();
        let client = client.clone();
        let path = path.clone();
        let priority_fee = config.max_priority_fee_gwei;
        let gas_limit = config.gas_limit;

        async move {
            let calldata = router.encode(
                "swapExactTokensForETHSupportingFeeOnTransferTokens",
                (amt, U256::zero(), path, client.address(), deadline),
            )?;
            
            let gas_price = client.provider().get_gas_price().await? 
                + U256::from(priority_fee * 1_000_000_000 * gas_mult);

            let tx = TransactionRequest::new()
                .to(router_addr)
                .data(calldata.0)
                .gas(gas_limit + 50000) 
                .gas_price(gas_price);
            
            let pending = client.send_transaction(tx, None).await?;
            Ok::<_, anyhow::Error>(pending.tx_hash())
        }
    };

    println!("<<< [SELL] Attempting to sell: {}...", amount_token);
    
    // Attempt 1: 100%
    match send_sell(amount_token, if is_panic { 2 } else { 1 }).await {
        Ok(tx_hash) => return Ok(tx_hash),
        Err(e) => println!("   [Sell Fail] 100% Sell failed: {:?}", e),
    }

    if is_panic {
        println!("!!! [EMERGENCY] 100% Sell failed. Trying 50% dump to save capital...");
        // Attempt 2: 50%
        let half_amount = amount_token / 2;
        match send_sell(half_amount, 3).await { 
            Ok(tx_hash) => return Ok(tx_hash),
            Err(e) => println!("   [Sell Fail] 50% Sell failed: {:?}", e),
        }
    }

    Err(anyhow::anyhow!("All sell attempts failed"))
}

async fn monitor_position(
    client: Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    router_addr: Address,
    token_addr: Address,
    initial_cost_eth: U256,
    config: AppConfig,
) {
    println!("*** [MONITOR] Watching: {:?}", token_addr);
    let erc20_abi = parse_abi(&["function balanceOf(address) external view returns (uint)"]).unwrap();
    let token_contract = Contract::new(token_addr, erc20_abi, client.clone());
    let router_abi = parse_abi(&["function getAmountsOut(uint,address[]) external view returns (uint[])"]).unwrap();
    let router_contract = Contract::new(router_addr, router_abi, client.clone());
    let path = vec![token_addr, *WETH_BASE];

    let mut sold_half = false;
    let mut check_count = 0;

    loop {
        check_count += 1;
        if check_count % 20 == 0 { println!("... monitoring {} ...", token_addr); }

        let balance: U256 = match token_contract.method("balanceOf", client.address()).unwrap().call().await {
            Ok(b) => b,
            Err(_) => { sleep(Duration::from_secs(1)).await; continue; }
        };

        if balance.is_zero() {
            println!("*** [MONITOR] Balance is 0 for {:?}. Removing persistence.", token_addr);
            // 新增：余额归零（已卖出或转走），删除文件
            remove_position(token_addr);
            break;
        }

        let amounts_out: Vec<U256> = match router_contract.method("getAmountsOut", (balance, path.clone())).unwrap().call().await {
            Ok(v) => v,
            Err(_) => { sleep(Duration::from_millis(500)).await; continue; }
        };

        let current_val = *amounts_out.last().unwrap_or(&U256::zero());

        let mut trigger_sell = false;
        let mut is_panic = false;
        let mut sell_amount = balance;

        if config.sell_strategy_3x_exit_all && current_val >= initial_cost_eth * 3 {
            println!("[EXIT] 3x Profit! Dumping ALL.");
            trigger_sell = true;
        } else if config.sell_strategy_2x_exit_half && !sold_half && current_val >= initial_cost_eth * 2 {
            println!("[EXIT] 2x Profit! Selling HALF.");
            trigger_sell = true;
            sell_amount = balance / 2;
            sold_half = true;
        } else {
            let stop_loss_limit = initial_cost_eth * (100 - config.anti_rug_dip_threshold) / 100;
            if current_val < stop_loss_limit {
                println!("[ALERT] Price crashed! Panic Selling!");
                trigger_sell = true;
                is_panic = true;
            }
        }

        if trigger_sell {
            let _ = execute_smart_sell(client.clone(), router_addr, token_addr, *WETH_BASE, sell_amount, &config, is_panic).await;
            // 注意：我们不在这里立即删除文件，而是等下一次循环检测到余额为0时删除，这样更安全
            if !sold_half || is_panic { 
                // 给一点时间让链上更新
                sleep(Duration::from_secs(5)).await; 
            } 
        }

        sleep(Duration::from_secs(2)).await;
    }
}

async fn process_transaction(
    tx: Transaction,
    provider: Arc<Provider<Ws>>,
    client: Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    nonce_manager: Arc<NonceManager>,
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

                if config.sniper_block_delay > 0 && !config.shadow_mode {
                    let target_block = provider.get_block_number().await.unwrap_or_default() + config.sniper_block_delay;
                    loop {
                        if provider.get_block_number().await.unwrap_or_default() >= target_block { break; }
                        sleep(Duration::from_millis(100)).await;
                    }
                }

                let sim_res = simulator.simulate_bundle(None, to, buy_amt, token_addr).await;
                let (sim_ok, _, expected_tokens, reason) = sim_res.unwrap_or((false, U256::zero(), U256::zero(), "Sim Error".to_string()));

                if !sim_ok {
                    println!("   [ABORT] Simulation failed: {}. Likely Honeypot.", reason);
                    return;
                }

                if config.shadow_mode {
                    println!("   [Shadow] Sim OK. Reason: {}", reason);
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
                    let min_out = expected_tokens * 80 / 100;
                    
                    match execute_buy_and_approve(client.clone(), nonce_manager, to, *WETH_BASE, token_addr, buy_amt, min_out, &config).await {
                        Ok(_) => {
                            // 新增：买入成功后，立即持久化保存
                            println!(">>> [PERSIST] Saving position to file...");
                            let pos_data = PositionData {
                                token_address: token_addr,
                                router_address: to,
                                initial_cost_eth: buy_amt,
                                timestamp: Local::now().timestamp() as u64,
                            };
                            if let Err(e) = save_position(&pos_data) {
                                println!("!!! [ERROR] Failed to save position: {:?}", e);
                            }
                            
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
    let filter = Filter::new().address(vec![*WETH_BASE]);
    let mut stream = provider.subscribe_logs(&filter).await?;
    println!(">>> SHADOW MODE STARTED <<<");
    while let Some(log) = stream.next().await {
        if let Some(tx_hash) = log.transaction_hash {
            if !config.use_private_node { sleep(Duration::from_millis(100)).await; }
            let p = provider.clone();
            task::spawn(async move {
                if let Ok(Some(tx)) = p.get_transaction(tx_hash).await {
                     if let Some((action, token_addr)) = decode_router_input(&tx.input) {
                         let to = tx.to.unwrap_or_default();
                         if get_router_name(&to) != "Unknown" {
                             println!("\n[Shadow] {} | {:?}", action, token_addr);
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
    dotenv().ok();
    tracing_subscriber::fmt::init();
    let config = AppConfig::from_env();

    if config.shadow_mode { return run_shadow_mode(config).await; }

    println!("=== Base Sniper Pro (Optimized + Persistence) ===");
    println!("Mode: LIVE | Node: {}", if config.use_private_node { "PRIVATE" } else { "PUBLIC" });

    // 初始化存储文件夹
    init_storage();

    let provider = Provider::<Ws>::connect(&config.rpc_url).await?;
    let chain_id = provider.get_chainid().await?.as_u64();

    let wallet = if !config.private_key.is_empty() {
        config.private_key.parse::<LocalWallet>()?.with_chain_id(chain_id)
    } else {
        panic!("[FATAL] Private key missing in .env");
    };

    let client = Arc::new(SignerMiddleware::new(provider.clone(), wallet.clone()));
    let provider_arc = Arc::new(provider);
    let simulator = Simulator::new(provider_arc.clone());
    let targets = config.get_targets();

    // 恢复之前的持仓
    let existing_positions = load_all_positions();
    if !existing_positions.is_empty() {
        println!(">>> [RESTORE] Found {} existing positions. Resuming monitors...", existing_positions.len());
        for pos in existing_positions {
            println!("   -> Resuming monitor for {:?}", pos.token_address);
            let c = client.clone();
            let cfg = config.clone();
            task::spawn(monitor_position(c, pos.router_address, pos.token_address, pos.initial_cost_eth, cfg));
        }
    }

    let start_nonce = provider_arc.get_transaction_count(wallet.address(), None).await?.as_u64();
    let nonce_manager = Arc::new(NonceManager::new(start_nonce));
    println!(">>> Initialized Nonce: {}", start_nonce);

    let (tx_sender, mut rx_receiver) = mpsc::channel::<Transaction>(10000);
    let mut stream = provider_arc.subscribe_pending_txs().await?;

    let p_clone = provider_arc.clone();
    let c_clone = client.clone();
    let cfg_clone = config.clone();
    let t_clone = targets.clone();
    let s_clone = simulator.clone();
    let n_clone = nonce_manager.clone();

    task::spawn(async move {
        while let Some(tx) = rx_receiver.recv().await {
            let p = p_clone.clone();
            let c = c_clone.clone();
            let cfg = cfg_clone.clone();
            let t = t_clone.clone();
            let s = s_clone.clone();
            let n = n_clone.clone();
            task::spawn(async move {
                 process_transaction(tx, p, c, n, s, cfg, t).await;
            });
        }
    });

    while let Some(tx_hash) = stream.next().await {
        let provider = provider_arc.clone();
        let sender = tx_sender.clone();
        task::spawn(async move {
            if let Ok(Some(tx)) = provider.get_transaction(tx_hash).await {
                let _ = sender.send(tx).await;
            }
        });
    }

    Ok(())
}