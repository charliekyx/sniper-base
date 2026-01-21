mod buy;
mod config;
mod constants;
mod decoder;
mod diagnostics;
mod email;
mod lock_manager;
mod logger;
mod monitor;
mod nonce;
mod position_dao;
mod processor;
mod sell;
mod simulation;
mod strategies;
mod spend_limit;

use config::AppConfig;
use diagnostics::run_self_check;
use lock_manager::LockManager;
use monitor::monitor_position;
use nonce::NonceManager;
use position_dao::{init_storage, load_all_positions};
use processor::process_transaction;
use simulation::Simulator;
use spend_limit::SpendLimitManager;
use strategies::get_strategy_for_position;

use dotenv::dotenv;
use ethers::prelude::*;
use ethers::providers::{Ipc, Middleware};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task;
use tracing::{error, info};
use tracing_subscriber::fmt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化阶段
    dotenv().ok();
    fmt::init();
    let config = AppConfig::from_env();
    init_storage();
    // 使用配置中的 RPC_URL (IPC 路径)
    let provider = Provider::<Ipc>::connect_ipc(&config.rpc_url)
        .await
        .expect("[FATAL] Failed to connect to IPC");
    if let Err(e) = provider.get_block_number().await {
        panic!(
            "[FATAL] Node connection test failed. Is the node running? Error: {:?}",
            e
        );
    }

    let chain_id = provider.get_chainid().await?.as_u64();
    let wallet = if !config.private_key.is_empty() {
        config
            .private_key
            .parse::<LocalWallet>()?
            .with_chain_id(chain_id)
    } else {
        panic!("[FATAL] Private key missing in .env");
    };
    let client = Arc::new(SignerMiddleware::new(provider.clone(), wallet.clone()));
    let provider_arc = Arc::new(provider);
    let simulator = Simulator::new(provider_arc.clone());
    // 初始化重复购买锁（必须在恢复持仓和启动监控之前）
    let lock_manager = LockManager::new();

    let spend_manager = Arc::new(SpendLimitManager::new("spend_history.json"));

    info!("Base Sniper Started");
    info!(
        "Mode: {} | Node: {}",
        if config.shadow_mode {
            "SHADOW (Simulation Only)"
        } else {
            "LIVE (Real Trading)"
        },
        if config.use_private_node {
            "PRIVATE"
        } else {
            "PUBLIC"
        }
    );

    // 在主循环开始前运行自检
    run_self_check(provider_arc.clone(), simulator.clone(), client.address()).await;

    let targets = config.get_targets();

    // 恢复之前的持仓
    let existing_positions = load_all_positions();
    if !existing_positions.is_empty() {
        info!(
            "[RESTORE] Found {} existing positions. Resuming monitors...",
            existing_positions.len()
        );
        for pos in existing_positions {
            // 恢复时也将 Token 加入锁，防止重复买入
            lock_manager.lock(pos.token_address);
            info!("Resuming monitor for {:?}", pos.token_address);
            let c = client.clone();
            let cfg = config.clone();
            let strategy = Arc::from(get_strategy_for_position(
                pos.router_address,
                pos.fee.unwrap_or(0),
                pos.token_address,
            ));
            task::spawn(monitor_position(
                c,
                strategy,
                pos.token_address,
                pos.initial_cost_eth,
                cfg,
                lock_manager.clone(),
                None, // 恢复持仓时，如果是 Shadow Mode 且没有持久化虚拟余额，这里可能会直接退出，这是预期行为
            ));
        }
    }

    let start_nonce = provider_arc
        .get_transaction_count(wallet.address(), None)
        .await?
        .as_u64();
    let nonce_manager = Arc::new(NonceManager::new(start_nonce));
    info!("Initialized Nonce: {}", start_nonce);

    let (tx_sender, mut rx_receiver) = mpsc::channel::<Transaction>(10000);
    let mut stream = provider_arc.subscribe_blocks().await?;

    let p_clone = provider_arc.clone();
    let c_clone = client.clone();
    let cfg_clone = config.clone();
    let t_clone = targets.clone();
    let s_clone = simulator.clone();
    let n_clone = nonce_manager.clone();
    let l_clone = lock_manager.clone();
    let sm_clone = spend_manager.clone();

    task::spawn(async move {
        while let Some(tx) = rx_receiver.recv().await {
            let p = p_clone.clone();
            let c = c_clone.clone();
            let cfg = cfg_clone.clone();
            let t = t_clone.clone();
            let s = s_clone.clone();
            let n = n_clone.clone();
            let l = l_clone.clone();
            let sm = sm_clone.clone();
            task::spawn(async move {
                process_transaction(tx, p, c, n, s, cfg, t, l, sm).await;
            });
        }
    });

    let mut last_heartbeat = std::time::Instant::now();

    while let Some(block) = stream.next().await {
        if last_heartbeat.elapsed() >= std::time::Duration::from_secs(3600) {
            if let Some(h) = block.hash {
                info!("HEARTBEAT] Still scanning... Latest Block: {:?}", h);
            }
            last_heartbeat = std::time::Instant::now();
        }

        let provider = provider_arc.clone();
        let sender = tx_sender.clone();

        // 使用 spawn 立即释放主循环，去处理下一个可能的事件
        task::spawn(async move {
            if let Some(hash) = block.hash {
                // 性能优化：不要在这里 println，或者用 tracing::debug
                // println!(">>> [NEW BLOCK] Scanned Block: {:?}", hash);

                // 关键点：这里会有一次 RTT，但在没有 Pending 流的情况下是无法避免的
                // 确保你的 op-geth 和 bot 在同一台机器或同一个内网，以消除网络延迟
                match provider.get_block_with_txs(hash).await {
                    Ok(Some(full_block)) => {
                        // 收到区块后，立即并行处理所有交易
                        for tx in full_block.transactions {
                            // 直接发送到处理通道
                            // 注意：这里的 tx 已经是 "Mined" 状态
                            if let Err(e) = sender.send(tx).await {
                                error!("Channel error: {:?}", e);
                            }
                        }
                    }
                    Ok(None) => {
                        // 区块可能还没同步完（虽然很少见），忽略
                    }
                    Err(e) => {
                        error!("Failed to fetch full block {:?}: {:?}", hash, e);
                    }
                }
            }
        });
    }

    Ok(())
}
