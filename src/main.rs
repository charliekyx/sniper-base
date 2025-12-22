mod config;
mod logger;
mod simulation;
mod constants;

use crate::config::AppConfig;
use crate::logger::{log_shadow_trade, ShadowRecord};
use crate::simulation::Simulator;
use crate::constants::{get_router_name, WETH_BASE};
use ethers::prelude::*;
use ethers::abi::{Abi, parse_abi};
use std::sync::Arc;
use tokio::task;
use tokio::time::{sleep, Duration};
use chrono::Local;

// --- 辅助函数：Input Data 解码 ---
fn decode_router_input(input: &[u8]) -> Option<(String, Address)> {
    if input.len() < 4 { return None; }
    let swap_sig = &input[0..4] == [0x7f, 0xf3, 0x6a, 0xb5];
    let add_liq_sig = &input[0..4] == [0xf3, 0x05, 0xd7, 0x19];

    if swap_sig {
        let abi_str = r#"[{"name":"swapExactETHForTokens","type":"function","inputs":[{"type":"uint256"},{"type":"address[]"},{"type":"address"},{"type":"uint256"}]}]"#;
        if let Ok(abi) = serde_json::from_str::<Abi>(abi_str) {
            if let Ok(func) = abi.function("swapExactETHForTokens") {
                if let Ok(decoded) = func.decode_input(&input[4..]) {
                    if let Some(path) = decoded[1].clone().into_array() {
                        if let Some(last) = path.last() {
                            return last.clone().into_address().map(|t| ("Swap".to_string(), t));
                        }
                    }
                }
            }
        }
    } else if add_liq_sig {
        let abi_str = r#"[{"name":"addLiquidityETH","type":"function","inputs":[{"type":"address"},{"type":"uint256"},{"type":"uint256"},{"type":"uint256"},{"type":"address"},{"type":"uint256"}]}]"#;
        if let Ok(abi) = serde_json::from_str::<Abi>(abi_str) {
            if let Ok(func) = abi.function("addLiquidityETH") {
                if let Ok(decoded) = func.decode_input(&input[4..]) {
                    return decoded[0].clone().into_address().map(|t| ("AddLiquidity".to_string(), t));
                }
            }
        }
    }
    None
}

// --- 交易执行模块 ---

// 1. 买入
async fn execute_buy(
    client: Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    router_addr: Address,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    config: &AppConfig,
) -> anyhow::Result<TxHash> {
    println!(">>> [BUY] Sending Tx for {:?}...", token_out);

    let router_abi = parse_abi(&[
        "function swapExactETHForTokensSupportingFeeOnTransferTokens(uint amountOutMin, address[] calldata path, address to, uint deadline) external payable"
    ])?;
    let router = BaseContract::from(router_abi);
    let path = vec![token_in, token_out];
    let deadline = U256::from(Local::now().timestamp() + 60); // 1分钟过期，防止长时间挂起

    let calldata = router.encode(
        "swapExactETHForTokensSupportingFeeOnTransferTokens",
        (U256::zero(), path, client.address(), deadline)
    )?;

    // 激进的 Gas 策略
    let gas_price = client.provider().get_gas_price().await?;
    let priority_fee = U256::from(config.max_priority_fee_gwei * 1_000_000_000);
    
    let tx = TransactionRequest::new()
        .to(router_addr)
        .value(amount_in)
        .data(calldata.0)
        .gas(config.gas_limit) // 硬上限，防止耗尽
        .gas_price(gas_price + priority_fee);

    let pending_tx = client.send_transaction(tx, None).await?;
    println!(">>> [BUY] Hash: {:?}", pending_tx.tx_hash());
    Ok(pending_tx.tx_hash())
}

// 2. 卖出
async fn execute_sell(
    client: Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    router_addr: Address,
    token_in: Address, // 目标代币
    token_out: Address, // WETH
    amount_token: U256,
    config: &AppConfig,
) -> anyhow::Result<TxHash> {
    println!("<<< [SELL] Selling Amount: {}...", amount_token);
    
    // 步骤 A: 授权 (Approve)
    // 注意：实战中，部分 Sniper 会在买入后立即单独发送一笔 Approve 交易以节省卖出时间
    let erc20_abi = parse_abi(&["function approve(address,uint) external returns (bool)"])?;
    let token_contract = BaseContract::from(erc20_abi);
    let approve_calldata = token_contract.encode("approve", (router_addr, U256::MAX))?;
    
    let tx_approve = TransactionRequest::new().to(token_in).data(approve_calldata.0).gas(100_000).gas_price(client.provider().get_gas_price().await?);
    let _ = client.send_transaction(tx_approve, None).await?; // 不等待确认，直接发卖单 (冒险但快)

    // 步骤 B: 卖出 (Swap)
    let router_abi = parse_abi(&[
        "function swapExactTokensForETHSupportingFeeOnTransferTokens(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline) external"
    ])?;
    let router = BaseContract::from(router_abi);
    let path = vec![token_in, token_out];
    let deadline = U256::from(Local::now().timestamp() + 120);

    let sell_calldata = router.encode(
        "swapExactTokensForETHSupportingFeeOnTransferTokens",
        (amount_token, U256::zero(), path, client.address(), deadline)
    )?;

    let gas_price = client.provider().get_gas_price().await? + U256::from(config.max_priority_fee_gwei * 1_000_000_000);
    
    let tx = TransactionRequest::new()
        .to(router_addr)
        .data(sell_calldata.0)
        .gas(config.gas_limit)
        .gas_price(gas_price);

    let pending_tx = client.send_transaction(tx, None).await?;
    println!("<<< [SELL] Hash: {:?}", pending_tx.tx_hash());
    Ok(pending_tx.tx_hash())
}

// 3. 持仓监控任务 (Strategy Monitor)
async fn monitor_position(
    client: Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    router_addr: Address,
    token_addr: Address,
    initial_cost_eth: U256,
    config: AppConfig,
) {
    println!("*** [MONITOR] Watching: {:?}", token_addr);
    let erc20_abi = parse_abi(&["function balanceOf(address) external view returns (uint)"]).expect("Failed to parse ERC20 ABI");
    let token_contract = Contract::new(token_addr, erc20_abi, client.clone());
    let router_abi = parse_abi(&["function getAmountsOut(uint,address[]) external view returns (uint[])"]).expect("Failed to parse Router ABI");
    let router_contract = Contract::new(router_addr, router_abi, client.clone());
    let path = vec![token_addr, *WETH_BASE];

    let mut sold_half = false;
    let mut check_count = 0;

    loop {
        check_count += 1;
        // 每 20 次检查打印一次心跳
        if check_count % 20 == 0 { println!("... monitoring ..."); }

        // 查询余额
        let balance: U256 = match token_contract.method("balanceOf", client.address()).unwrap().call().await {
            Ok(b) => b,
            Err(_) => { sleep(Duration::from_secs(1)).await; continue; }
        };

        if balance.is_zero() {
            println!("*** [MONITOR] Balance is 0. Position closed.");
            break;
        }

        // 查询价值
        let amounts_out: Vec<U256> = match router_contract.method("getAmountsOut", (balance, path.clone())).unwrap().call().await {
            Ok(v) => v,
            Err(_) => {
                // 如果连续获取价格失败，可能是 Rug Pull (撤池子)
                sleep(Duration::from_millis(500)).await;
                continue;
            }
        };

        let current_val = *amounts_out.last().unwrap_or(&U256::zero());
        
        // --- 策略判断 ---

        // 1. 3倍止盈 (All Out)
        if config.sell_strategy_3x_exit_all && current_val >= initial_cost_eth * 3 {
            println!("[EXIT] 3x Profit! Dumping ALL.");
            let _ = execute_sell(client.clone(), router_addr, token_addr, *WETH_BASE, balance, &config).await;
            break;
        }

        // 2. 翻倍出本 (Half Out)
        if config.sell_strategy_2x_exit_half && !sold_half && current_val >= initial_cost_eth * 2 {
            println!("[EXIT] 2x Profit! Selling HALF to recover cost.");
            let half = balance / 2;
            let _ = execute_sell(client.clone(), router_addr, token_addr, *WETH_BASE, half, &config).await;
            sold_half = true;
        }

        // 3. 止损/防 Rug (Panic Sell)
        // 逻辑：如果价值跌到成本的 10% 以下 (90% loss)，或者如果配置了特定阈值
        let stop_loss_limit = initial_cost_eth * (100 - config.anti_rug_dip_threshold) / 100;
        if current_val < stop_loss_limit {
             println!("[ALERT] Price crashed! Panic Selling!");
             let _ = execute_sell(client.clone(), router_addr, token_addr, *WETH_BASE, balance, &config).await;
             break;
        }

        sleep(Duration::from_secs(2)).await;
    }
}

// --- 主程序 ---
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let config = AppConfig::load("config.json");
    
    println!("=== Base Sniper Pro ===");
    println!("Mode: {}", if config.shadow_mode { "SHADOW" } else { "LIVE (REAL MONEY)" });
    if !config.shadow_mode { println!("WARNING: You are running with REAL FUNDS."); }

    let provider = Provider::<Ws>::connect(&config.rpc_url).await?;
    let chain_id = provider.get_chainid().await?.as_u64();
    
    // 初始化钱包
    let wallet = if !config.private_key.is_empty() {
        config.private_key.parse::<LocalWallet>()?.with_chain_id(chain_id) // 这是为了防止重放攻击（Replay Attack), 以太坊交易签名标准（EIP-155）要求签名中包含链 ID，这样在 Base 链上签名的交易就不能被恶意拿到以太坊主网或其他链上去广播执行
    } else {
        if !config.shadow_mode {
            // 实盘模式下必须提供私钥，否则直接崩溃以保护资金
            panic!("[FATAL] You are in LIVE mode but no 'private_key' is set! A random wallet would cause PERMANENT LOSS of funds. Please configure it.");
        }
        let w = LocalWallet::new(&mut rand::thread_rng()).with_chain_id(chain_id);
        println!("[Shadow] No private key found. Using temporary random wallet: {:?}", w.address());
        w
    };
    
    let client = Arc::new(SignerMiddleware::new(provider.clone(), wallet.clone()));
    let provider_arc = Arc::new(provider);
    let simulator = Arc::new(Simulator::new(provider_arc.clone()));
    let targets = config.get_targets();

    println!("Listening for Mempool Events...");
    let mut stream = provider_arc.subscribe_pending_txs().await?;

    while let Some(tx_hash) = stream.next().await {
        let provider = provider_arc.clone();
        let client = client.clone();
        let config = config.clone();
        let sim = simulator.clone();
        let targets = targets.clone();

        task::spawn(async move {
            if let Ok(Some(tx)) = provider.get_transaction(tx_hash).await {
                if let Some(to) = tx.to {
                    let router_name = get_router_name(&to);
                    if router_name == "Unknown" { return; }

                    if let Some((action, token_addr)) = decode_router_input(&tx.input) {
                        
                        // 触发条件
                        let is_target_buy = config.copy_trade_enabled && targets.contains(&tx.from) && action == "Swap";
                        let is_new_liquidity = config.sniper_enabled && action == "AddLiquidity";

                        if is_target_buy || is_new_liquidity {
                            println!("\n Trigger: {} | Token: {:?}", action, token_addr);
                            let buy_amt = U256::from((config.buy_amount_eth * 1e18) as u64);

                            // --- 核心防御 1: Block Delay (防 Trap) ---
                            // 许多土狗盘在开盘前几个块会设置黑名单。延迟 1-2 个块买入能避开 90% 的陷阱。
                            if config.sniper_block_delay > 0 && !config.shadow_mode {
                                let target_block = provider.get_block_number().await.unwrap_or_default() + config.sniper_block_delay;
                                println!("   [SafeGuard] Waiting for block {} to avoid traps...", target_block);
                                loop {
                                    let now = provider.get_block_number().await.unwrap_or_default();
                                    if now >= target_block { break; }
                                    sleep(Duration::from_millis(500)).await;
                                }
                            }

                            // --- 核心防御 2: Pre-Flight Simulation (防 Honeypot) ---
                            // 在真正发送交易前，利用最新状态再模拟一次“买入+卖出”
                            // 如果模拟结果是无法卖出，或者利润为负(虽然Sniper利润通常无法预测，但这里主要看Revert)，则终止
                            let (sim_ok, _, reason) = sim.simulate_bundle(None, to, buy_amt, token_addr).await.unwrap();
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
                                    gas_used: 0, copy_target: None,
                                });
                            } else {
                                // --- 实战开火 ---
                                match execute_buy(client.clone(), to, *WETH_BASE, token_addr, buy_amt, &config).await {
                                    Ok(_) => {
                                        // 启动监控线程
                                        task::spawn(monitor_position(client, to, token_addr, buy_amt, config));
                                    }
                                    Err(e) => println!("   [Error] Buy Tx Failed: {:?}", e),
                                }
                            }
                        }
                    }
                }
            }
        });
    }
    Ok(())
}