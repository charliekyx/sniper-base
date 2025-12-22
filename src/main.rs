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
use tokio::sync::Mutex;
use tokio::task;
use tokio::time::{sleep, Duration}; // 引入 IO 库用于刷新打印缓存

// --- 辅助函数：Input Data 解码 (增强版) ---
fn decode_router_input(input: &[u8]) -> Option<(String, Address)> {
    if input.len() < 4 {
        return None;
    }
    let sig = &input[0..4];

    // 辅助闭包：读取 32 字节并转为 usize (用于读取 offset 和 length)
    let read_usize = |offset: usize| -> Option<usize> {
        if offset + 32 > input.len() {
            return None;
        }
        let slice = &input[offset..offset + 32];
        let val = U256::from_big_endian(slice);
        if val > U256::from(usize::MAX) {
            return None;
        }
        Some(val.as_usize())
    };

    // 辅助闭包：读取地址 (跳过前 12 字节 padding)
    let read_address = |offset: usize| -> Option<Address> {
        if offset + 32 > input.len() {
            return None;
        }
        Some(Address::from_slice(&input[offset + 12..offset + 32]))
    };

    // 辅助闭包：解析 address[] 路径
    let get_path_token = |arg_index: usize, get_last: bool| -> Option<Address> {
        // 1. 读取数组的 offset (相对于参数区起始位置 4)
        let offset_ptr = 4 + arg_index * 32;
        let array_offset = read_usize(offset_ptr)?;

        // 2. 读取数组长度
        let len_ptr = 4 + array_offset;
        let array_len = read_usize(len_ptr)?;
        if array_len == 0 {
            return None;
        }

        // 3. 确定目标元素索引
        let elem_index = if get_last { array_len - 1 } else { 0 };

        // 4. 读取元素 (长度字段占 32 字节，之后是元素)
        let item_ptr = len_ptr + 32 + elem_index * 32;
        read_address(item_ptr)
    };

    // 1. [BUY] swapExactETHForTokens (标准买入)
    // Sig: 0x7ff36ab5
    // 2. [BUY] swapExactETHForTokensSupportingFeeOnTransferTokens (带税买入 - 土狗常用)
    // Sig: 0xb6f9de95
    if sig == [0x7f, 0xf3, 0x6a, 0xb5] || sig == [0xb6, 0xf9, 0xde, 0x95] {
        let action = if sig[0] == 0x7f {
            "Buy_ETH->Token"
        } else {
            "Buy_Fee_ETH->Token"
        };
        return get_path_token(1, true).map(|t| (action.to_string(), t));
    }
    // 3. [SELL] swapExactTokensForETH (标准卖出)
    // Sig: 0x18cbafe5
    // 4. [SELL] swapExactTokensForETHSupportingFeeOnTransferTokens (带税卖出)
    // Sig: 0x791ac947
    else if sig == [0x18, 0xcb, 0xaf, 0xe5] || sig == [0x79, 0x1a, 0xc9, 0x47] {
        let action = if sig[0] == 0x18 {
            "Sell_Token->ETH"
        } else {
            "Sell_Fee_Token->ETH"
        };
        return get_path_token(2, false).map(|t| (action.to_string(), t));
    }
    // 5. [SWAP] swapExactTokensForTokens (币币互换 / USDC买币)
    // Sig: 0x38ed1739
    else if sig == [0x38, 0xed, 0x17, 0x39] {
        return get_path_token(2, true).map(|t| ("Swap_Token->Token".to_string(), t));
    }
    // 6. [LIQ] addLiquidityETH (加池子)
    // Sig: 0xf305d719
    else if sig == [0xf3, 0x05, 0xd7, 0x19] {
        // token is arg 0 (static address)
        return read_address(4).map(|t| ("AddLiquidity".to_string(), t));
    }

    None
}
// --- 交易执行模块 ---

// 1. 买入并授权 (Bundle/Pipeline 模式)
// 优化：通过手动管理 Nonce，连续发送买入和授权交易，使其极大概率在同一个区块内执行
async fn execute_buy_and_approve(
    client: Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    router_addr: Address,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    config: &AppConfig,
) -> anyhow::Result<()> {
    println!(
        ">>> [BUNDLE] Preparing Buy + Approve sequence for {:?}...",
        token_out
    );

    // 1. 获取起始 Nonce (Pending 状态，防止覆盖未打包交易)
    let start_nonce = client
        .get_transaction_count(client.address(), Some(BlockNumber::Pending.into()))
        .await?;

    // 2. 构建 Buy 交易
    let router_abi = parse_abi(&[
        "function swapExactETHForTokensSupportingFeeOnTransferTokens(uint amountOutMin, address[] calldata path, address to, uint deadline) external payable"
    ])?;
    let router = BaseContract::from(router_abi);
    let path = vec![token_in, token_out];
    let deadline = U256::from(Local::now().timestamp() + 60); // 1分钟过期，防止长时间挂起

    let calldata = router.encode(
        "swapExactETHForTokensSupportingFeeOnTransferTokens",
        (U256::zero(), path, client.address(), deadline),
    )?;

    // 激进的 Gas 策略
    let gas_price = client.provider().get_gas_price().await?;
    let priority_fee = U256::from(config.max_priority_fee_gwei * 1_000_000_000);
    let total_gas_price = gas_price + priority_fee;

    let buy_tx = TransactionRequest::new()
        .to(router_addr)
        .value(amount_in)
        .data(calldata.0)
        .gas(config.gas_limit) // 硬上限，防止耗尽
        .gas_price(total_gas_price)
        .nonce(start_nonce);

    // 3. 构建 Approve 交易 (Nonce + 1)
    let erc20_abi = parse_abi(&["function approve(address,uint) external returns (bool)"])?;
    let token_contract = BaseContract::from(erc20_abi);
    let approve_calldata = token_contract.encode("approve", (router_addr, U256::MAX))?;

    let approve_tx = TransactionRequest::new()
        .to(token_out)
        .data(approve_calldata.0)
        .gas(100_000)
        .gas_price(total_gas_price) // 保持一致的 Gas Price
        .nonce(start_nonce + 1);

    println!(
        ">>> [BUNDLE] Broadcasting Nonce {} (Buy) and {} (Approve)...",
        start_nonce,
        start_nonce + 1
    );

    // 4. 连续发送 (不等待)
    let pending_buy = client.send_transaction(buy_tx, None).await?;
    let pending_approve = client.send_transaction(approve_tx, None).await?;

    println!(
        ">>> [BUNDLE] Sent! Buy: {:?} | Approve: {:?}",
        pending_buy.tx_hash(),
        pending_approve.tx_hash()
    );

    // 5. 等待买入确认
    // 只要买入确认了，Approve 大概率也在同一个块或下一个块
    let receipt = pending_buy.await?;
    if receipt.is_some() && receipt.unwrap().status == Some(U64::from(1)) {
        println!(">>> [BUNDLE] Buy Confirmed. Starting monitor...");
        Ok(())
    } else {
        Err(anyhow::anyhow!("Buy transaction reverted"))
    }
}

// 2. 卖出
async fn execute_sell(
    client: Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    router_addr: Address,
    token_in: Address,  // 目标代币
    token_out: Address, // WETH
    amount_token: U256,
    config: &AppConfig,
) -> anyhow::Result<TxHash> {
    println!("<<< [SELL] Selling Amount: {}...", amount_token);

    // 步骤: 卖出 (Swap) - 假设已在买入后完成了 Approve
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

// 3. 持仓监控任务 (Strategy Monitor)
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
        // 每 20 次检查打印一次心跳
        if check_count % 20 == 0 {
            println!("... monitoring ...");
        }

        // 查询余额
        let balance: U256 = match token_contract
            .method("balanceOf", client.address())
            .expect("Method construction failed") // 构建调用通常不会失败，除非ABI错
            .call()
            .await
        {
            Ok(b) => b,
            Err(e) => {
                println!("   [Warn] Failed to get balance: {:?}", e);
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        if balance.is_zero() {
            println!("*** [MONITOR] Balance is 0. Position closed.");
            break;
        }

        // 查询价值
        let amounts_out: Vec<U256> = match router_contract
            .method("getAmountsOut", (balance, path.clone()))
            .expect("Method construction failed")
            .call()
            .await
        {
            Ok(v) => v,
            Err(e) => {
                // 如果连续获取价格失败，可能是 Rug Pull (撤池子)
                println!(
                    "   [Warn] Failed to get price (Potential Rug/Network Error): {:?}",
                    e
                );
                sleep(Duration::from_millis(500)).await;
                continue;
            }
        };

        let current_val = *amounts_out.last().unwrap_or(&U256::zero());

        // --- 策略判断 ---

        // 1. 3倍止盈 (All Out)
        if config.sell_strategy_3x_exit_all && current_val >= initial_cost_eth * 3 {
            println!("[EXIT] 3x Profit! Dumping ALL.");
            let _ = execute_sell(
                client.clone(),
                router_addr,
                token_addr,
                *WETH_BASE,
                balance,
                &config,
            )
            .await;
            break;
        }

        // 2. 翻倍出本 (Half Out)
        if config.sell_strategy_2x_exit_half && !sold_half && current_val >= initial_cost_eth * 2 {
            println!("[EXIT] 2x Profit! Selling HALF to recover cost.");
            let half = balance / 2;
            let _ = execute_sell(
                client.clone(),
                router_addr,
                token_addr,
                *WETH_BASE,
                half,
                &config,
            )
            .await;
            sold_half = true;
        }

        // 3. 止损/防 Rug (Panic Sell)
        // 逻辑：如果价值跌到成本的 10% 以下 (90% loss)，或者如果配置了特定阈值
        let stop_loss_limit = initial_cost_eth * (100 - config.anti_rug_dip_threshold) / 100;
        if current_val < stop_loss_limit {
            println!("[ALERT] Price crashed! Panic Selling!");
            let _ = execute_sell(
                client.clone(),
                router_addr,
                token_addr,
                *WETH_BASE,
                balance,
                &config,
            )
            .await;
            break;
        }

        sleep(Duration::from_secs(2)).await;
    }
}

async fn run_shadow_mode(config: AppConfig) -> anyhow::Result<()> {
    let provider = Provider::<Ws>::connect(&config.rpc_url).await?;
    let provider = Arc::new(provider);

    println!(">>> SHADOW MODE STARTED (BALANCED) <<<");
    println!(">>> Source: Public Node (Log Subscription)");
    println!(">>> Filter: WETH Events (High Volume)");
    println!(">>> Rate Limit: Processing only 1 out of 50 logs to save API credits");

    // 1. 切回监听 WETH，这是 Base 链上最活跃的合约，保证有源源不断的数据
    let filter = Filter::new().address(vec![*WETH_BASE]);

    let mut stream = provider.subscribe_logs(&filter).await?;
    let mut counter = 0;

    println!(">>> Waiting for logs... (Dots indicate activity)");

    while let Some(log) = stream.next().await {
        counter += 1;

        // 2. 视觉心跳：每收到 10 条日志打印一个点，证明连接是活的
        if counter % 10 == 0 {
            print!(".");
            io::stdout().flush().unwrap(); // 强制刷新缓存，立刻显示
        }

        // 3. 强力采样：每 50 条日志只处理 1 条
        // WETH 的日志量极大，不采样会瞬间耗尽免费节点的 CU 额度 (429 Error)
        if counter % 10 != 0 {
            continue;
        }

        if let Some(tx_hash) = log.transaction_hash {
            // 4. 串行处理：处理时稍微停顿一下，温柔对待公共节点
            sleep(Duration::from_millis(100)).await;

            if let Ok(Some(tx)) = provider.get_transaction(tx_hash).await {
                // 复用解码逻辑测试
                if let Some((action, token_addr)) = decode_router_input(&tx.input) {
                    let to = tx.to.unwrap_or_default();
                    let router_name = get_router_name(&to);

                    // 只记录我们关心的 Router 交易
                    if router_name != "Unknown" {
                        println!(
                            "\n[Shadow Capture] {} on {} | Token: {:?}",
                            action, router_name, token_addr
                        );

                        let record = ShadowRecord {
                            timestamp: Local::now().to_rfc3339(),
                            event_type: action.clone(),
                            router: router_name,
                            trigger_hash: format!("{:?}", tx.hash),
                            token_address: format!("{:?}", token_addr),
                            amount_in_eth: config.buy_amount_eth.to_string(),
                            simulation_result: "Shadow_Captured".to_string(),
                            profit_eth_after_sell: None,
                            gas_used: 0,
                            copy_target: None,
                        };

                        log_shadow_trade(record);
                    }
                }
            }
        }
    }
    Ok(())
}

// --- 主程序 ---
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let config = AppConfig::load("config.json");

    if config.shadow_mode {
        println!(">>> [MODE] SHADOW / PUBLIC NODE DETECTED <<<");
        println!(">>> Switching to Log Subscription (Safe for Infura/Alchemy)");
        // 进入独立的 Shadow 循环，不污染下面的 Sniper 逻辑
        return run_shadow_mode(config).await;
    }

    println!("=== Base Sniper Pro ===");
    println!(
        "Mode: {}",
        if config.shadow_mode {
            "SHADOW"
        } else {
            "LIVE (REAL MONEY)"
        }
    );
    if !config.shadow_mode {
        println!("WARNING: You are running with REAL FUNDS.");
    }

    let provider = Provider::<Ws>::connect(&config.rpc_url).await?;
    let chain_id = provider.get_chainid().await?.as_u64();

    // 初始化钱包
    // 优先从环境变量读取私钥，其次是配置文件
    let env_key = env::var("PRIVATE_KEY").ok();
    let config_key = if config.private_key == "null" || config.private_key.is_empty() {
        None
    } else {
        Some(config.private_key.clone())
    };

    let wallet = if let Some(pk) = env_key.or(config_key) {
        pk.parse::<LocalWallet>()?.with_chain_id(chain_id) // 这是为了防止重放攻击（Replay Attack), 以太坊交易签名标准（EIP-155）要求签名中包含链 ID，这样在 Base 链上签名的交易就不能被恶意拿到以太坊主网或其他链上去广播执行
    } else {
        if !config.shadow_mode {
            // 实盘模式下必须提供私钥，否则直接崩溃以保护资金
            panic!("[FATAL] You are in LIVE mode but no 'private_key' is set! A random wallet would cause PERMANENT LOSS of funds. Please configure it.");
        }
        let w = LocalWallet::new(&mut rand::thread_rng()).with_chain_id(chain_id);
        println!(
            "[Shadow] No private key found. Using temporary random wallet: {:?}",
            w.address()
        );
        w
    };

    let client = Arc::new(SignerMiddleware::new(provider.clone(), wallet.clone()));
    let provider_arc = Arc::new(provider);
    let simulator = Arc::new(Mutex::new(Simulator::new(provider_arc.clone())));
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
                    if router_name == "Unknown" {
                        return;
                    }

                    if let Some((action, token_addr)) = decode_router_input(&tx.input) {
                        // 触发条件
                        let is_target_buy = config.copy_trade_enabled
                            && targets.contains(&tx.from)
                            && action == "Swap";
                        let is_new_liquidity = config.sniper_enabled && action == "AddLiquidity";

                        if is_target_buy || is_new_liquidity {
                            println!("\n Trigger: {} | Token: {:?}", action, token_addr);
                            let buy_amt = U256::from((config.buy_amount_eth * 1e18) as u64);

                            // --- 核心防御 1: Block Delay (防 Trap) ---
                            // 许多土狗盘在开盘前几个块会设置黑名单。延迟 1-2 个块买入能避开 90% 的陷阱。
                            if config.sniper_block_delay > 0 && !config.shadow_mode {
                                let target_block =
                                    provider.get_block_number().await.unwrap_or_default()
                                        + config.sniper_block_delay;
                                println!(
                                    "   [SafeGuard] Waiting for block {} to avoid traps...",
                                    target_block
                                );
                                loop {
                                    let now = provider.get_block_number().await.unwrap_or_default();
                                    if now >= target_block {
                                        break;
                                    }
                                    sleep(Duration::from_millis(500)).await;
                                }
                            }

                            // --- 核心防御 2: Pre-Flight Simulation (防 Honeypot) ---
                            // 在真正发送交易前，利用最新状态再模拟一次“买入+卖出”
                            // 如果模拟结果是无法卖出，或者利润为负(虽然Sniper利润通常无法预测，但这里主要看Revert)，则终止
                            let mut sim_guard = sim.lock().await;
                            let sim_res = sim_guard
                                .simulate_bundle(None, to, buy_amt, token_addr)
                                .await;

                            // 修复 unwrap 崩溃风险
                            let (sim_ok, _, reason) = sim_res.unwrap_or((
                                false,
                                U256::zero(),
                                "Simulation Error".to_string(),
                            ));

                            if !sim_ok {
                                println!(
                                    "   [ABORT] Simulation failed: {}. Likely Honeypot.",
                                    reason
                                );
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
                                // --- 实战开火 ---
                                match execute_buy_and_approve(
                                    client.clone(),
                                    to,
                                    *WETH_BASE,
                                    token_addr,
                                    buy_amt,
                                    &config,
                                )
                                .await
                                {
                                    Ok(_) => {
                                        // 启动监控线程
                                        task::spawn(monitor_position(
                                            client, to, token_addr, buy_amt, config,
                                        ));
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
