mod config;
mod logger;
mod simulation;
mod constants;

use crate::config::AppConfig;
use crate::logger::{log_shadow_trade, ShadowRecord};
use crate::simulation::Simulator;
use crate::constants::{BASESWAP_ROUTER, ALIENBASE_ROUTER, get_router_name};
use ethers::prelude::*;
use std::sync::Arc;
use tokio::task;
use chrono::Local;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志
    tracing_subscriber::fmt::init();

    // 1. 加载配置
    let config = AppConfig::load("config.json");
    println!("=== Base Sniper Bot Starting ===");
    println!("Mode: {}", if config.shadow_mode { "SHADOW (Simulation Only)" } else { "LIVE (Real Money)" });
    println!("Monitoring {} Copy Trade Targets", config.target_wallets.len());

    // 2. 连接节点
    let provider = Provider::<Ws>::connect(&config.rpc_url).await?;
    let provider = Arc::new(provider);

    // 检查链 ID (防止连错到 ETH 主网)
    let chain_id = provider.get_chainid().await?;
    if chain_id.as_u64() != 8453 {
        panic!("CRITICAL ERROR: RPC is connected to Chain ID {}, expected 8453 (Base).", chain_id);
    }
    println!("Connected to Base Mainnet (Chain ID 8453).");

    let simulator = Arc::new(Simulator::new(provider.clone()));
    let target_wallets = config.get_targets();

    // 3. 订阅 Mempool
    println!("Subscribing to Pending Transactions...");
    let mut stream = provider.subscribe_pending_txs().await?;

    while let Some(tx_hash) = stream.next().await {
        let provider = provider.clone();
        let config = config.clone();
        let sim = simulator.clone();
        let targets = target_wallets.clone();

        task::spawn(async move {
            // 获取完整交易详情
            if let Ok(Some(tx)) = provider.get_transaction(tx_hash).await {
                
                // --- 逻辑 A: Copy Trade (跟单模式) ---
                if config.copy_trade_enabled && targets.contains(&tx.from) {
                    println!("[CopyTrade] Detected Target {:?} Action!", tx.from);
                    
                    // 简单的过滤：必须是发往 Router 的交易，且带有 ETH (买入)
                    // 真实逻辑需要解析 Input Data 确认是 swapETHForTokens
                    if let Some(to) = tx.to {
                        let router_name = get_router_name(&to);
                        if router_name != "Unknown" && !tx.value.is_zero() {
                            println!("   -> Target is buying on {}", router_name);
                            
                            // 提取目标 Token (这里为了简化，需从 tx.input 解析)
                            // 假设我们解析出了 token 地址
                            let mock_token = Address::random(); 

                            // 执行模拟
                            let (success, profit, reason) = sim.simulate_bundle(
                                Some(tx.clone()), 
                                to,
                                U256::from(100000000000000000u64), // 模拟跟 0.1 ETH
                                mock_token
                            ).await.unwrap_or((false, U256::zero(), "Sim Error".to_string()));

                            if config.shadow_mode {
                                log_shadow_trade(ShadowRecord {
                                    timestamp: Local::now().to_rfc3339(),
                                    event_type: "CopyTrade".to_string(),
                                    router: router_name,
                                    trigger_hash: format!("{:?}", tx.hash),
                                    token_address: format!("{:?}", mock_token),
                                    amount_in_eth: "0.1".to_string(),
                                    simulation_result: if success { "Profit" } else { "Fail" }.to_string(),
                                    profit_eth_after_sell: Some(profit.to_string()),
                                    gas_used: 0, 
                                    copy_target: Some(format!("{:?}", tx.from)),
                                });
                            }
                        }
                    }
                }

                // --- 逻辑 B: Sniper (新币狙击) ---
                if config.sniper_enabled {
                    if let Some(to) = tx.to {
                        // 如果有人往 Router 发交易
                        // 且调用的是 addLiquidityETH (需解析 input)
                        if get_router_name(&to) != "Unknown" {
                            // 这里可以通过 input data 的 selector 判断是否是 addLiquidity
                            // let selector = &tx.input[0..4];
                            // if selector == 0xf305d719 ...
                            
                            // 模拟逻辑同上...
                        }
                    }
                }
            }
        });
    }

    Ok(())
}