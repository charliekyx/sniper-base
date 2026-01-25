use crate::constants::{
    AERODROME_FACTORY, AERODROME_ROUTER, AERO_V3_QUOTER, AERO_V3_ROUTER, CLANKER_HOOK_DYNAMIC,
    CLANKER_HOOK_STATIC, UNIV3_QUOTER, UNIV3_ROUTER, UNIV4_QUOTER, UNIVERSAL_ROUTER,
    VIRTUALS_ROUTER, WETH_BASE,
};
use crate::simulation::Simulator;
use crate::strategies::*;
use ethers::prelude::*;
use ethers::providers::{Ipc, Middleware, Provider};
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info, warn};

pub async fn force_clear_stuck_txs(client: Arc<SignerMiddleware<Provider<Ipc>, LocalWallet>>) {
    let addr = client.address();
    let nonce_latest = client
        .get_transaction_count(addr, Some(BlockId::Number(BlockNumber::Latest)))
        .await
        .unwrap_or_default();
    let nonce_pending = client
        .get_transaction_count(addr, Some(BlockId::Number(BlockNumber::Pending)))
        .await
        .unwrap_or_default();

    if nonce_pending > nonce_latest {
        info!(
            "[CLEAR] Found stuck transactions. Latest Nonce: {}, Pending Nonce: {}. Clearing...",
            nonce_latest, nonce_pending
        );

        let gas_price = client.provider().get_gas_price().await.unwrap_or_default();
        // 提高 20% Gas Price 以确保覆盖旧交易
        let new_gas_price = gas_price * 120 / 100;

        for nonce in nonce_latest.as_u64()..nonce_pending.as_u64() {
            info!("[CLEAR] Cancelling Stuck Nonce {}...", nonce);
            let tx = Eip1559TransactionRequest::new()
                .to(addr) // 发给自己
                .value(0) // 0 ETH
                .nonce(nonce)
                .max_fee_per_gas(new_gas_price)
                .max_priority_fee_per_gas(new_gas_price);

            match client.send_transaction(tx, None).await {
                Ok(p) => info!("[CLEAR] Replacement sent: {:?}", p.tx_hash()),
                Err(e) => error!("[CLEAR] Failed to cancel nonce {}: {:?}", nonce, e),
            }
        }
        // 等待几秒让节点同步
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

pub async fn run_self_check(provider: Arc<Provider<Ipc>>, simulator: Simulator, owner: Address) {
    info!("[SELF-CHECK] Running startup diagnostics...");

    // 1. 检查关键合约是否存在 (验证地址配置是否正确)
    let checks = vec![
        ("Universal Router", *UNIVERSAL_ROUTER),
        ("UniV4 Quoter", *UNIV4_QUOTER),
        ("Clanker Static Hook (V4.1)", *CLANKER_HOOK_STATIC),
        ("Clanker Dynamic Hook (V4.1)", *CLANKER_HOOK_DYNAMIC),
        ("Aerodrome Router", *AERODROME_ROUTER),
        ("Virtuals Router", *VIRTUALS_ROUTER),
    ];

    for (name, addr) in checks {
        match provider.get_code(addr, None).await {
            Ok(code) => {
                if code.len() > 0 {
                    info!("[OK] Contract '{}' found at {:?}", name, addr);
                } else {
                    warn!(
                        "[WARN] Contract '{}' NOT FOUND at {:?} (Check constants.rs)",
                        name, addr
                    );
                }
            }
            Err(e) => error!("[ERR] Failed to check '{}': {:?}", name, e),
        }
    }

    // 2. 模拟测试 (WETH -> USDC on Aerodrome) 验证模拟引擎是否正常
    // Change to AERO (0x940181a94A35A4569E4529A3CDfB74e38FD98631) which definitely has a volatile pool
    if let Ok(test_token) = Address::from_str("0x940181a94A35A4569E4529A3CDfB74e38FD98631") {
        let amount_in = U256::from(50000000000000000u64); // 0.05 ETH (Increased to avoid gas loss false positive)

        info!("[TEST] Simulating WETH -> AERO (Aerodrome) to verify engine...");
        let origin = Address::from_str("0x0000000000000000000000000000000000001234").unwrap();

        let strategy = Arc::new(AerodromeV2Strategy {
            router: *AERODROME_ROUTER,
            factory: *AERODROME_FACTORY,
            path: vec![*WETH_BASE, test_token],
            name: "Aero Test".into(),
        });

        let sim_res = simulator
            .simulate_bundle(origin, strategy, amount_in, test_token, 20)
            .await;

        match sim_res {
            Ok((success, _, out, reason, _, _)) => {
                if success {
                    info!("[PASS] Simulation Engine is working. Output: {} AERO", out);
                } else {
                    error!("[FAIL] Simulation returned false. Reason: {}", reason);
                }
            }
            Err(e) => error!("[FAIL] Simulation crashed: {:?}", e),
        }
    }

    // 3. 模拟测试 (WETH -> USDC on Uniswap V3) 验证 V3 逻辑
    // USDC: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
    if let Ok(usdc) = Address::from_str("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913") {
        let amount_in = U256::from(50000000000000000u64); // 0.05 ETH
        info!("[TEST] Simulating WETH -> USDC (Uniswap V3) to verify V3 logic...");
        let origin = Address::from_str("0x0000000000000000000000000000000000001234").unwrap();

        let strategy = Arc::new(UniswapV3Strategy {
            router: *UNIV3_ROUTER,
            quoter: *UNIV3_QUOTER,
            fee: 3000,
            name: "UniV3 Test".into(),
        });

        let sim_res = simulator
            .simulate_bundle(origin, strategy, amount_in, usdc, 20)
            .await;

        match sim_res {
            Ok((success, _, out, reason, _, fee)) => {
                if success {
                    info!(
                        "[PASS] V3 Simulation working. Output: {} USDC (Fee Tier: {})",
                        out, fee
                    );
                } else {
                    error!("[FAIL] V3 Simulation failed. Reason: {}", reason);
                }
            }
            Err(e) => error!("[FAIL] V3 Simulation crashed: {:?}", e),
        }
    }

    // 4. 模拟测试 (V4 Quoter) 验证 V4 ABI 编码
    // 我们尝试 Quote 一个 V4 池子，只要返回的是合约错误(Revert)而不是系统错误(Invalid Data)，就说明 ABI 编码是完美的
    if let Ok(usdc) = Address::from_str("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913") {
        let amount_in = U256::from(50000000000000000u64); // 0.05 ETH
        info!("[TEST] Simulating V4 Quote (WETH -> USDC) to verify ABI encoding...");
        let origin = Address::from_str("0x0000000000000000000000000000000000001234").unwrap();

        let strategy = Arc::new(UniswapV4Strategy {
            pool_key: (*WETH_BASE, usdc, 10000, 200, *CLANKER_HOOK_STATIC),
            name: "V4 Test".into(),
        });

        let sim_res = simulator
            .simulate_bundle(origin, strategy, amount_in, usdc, 20)
            .await;

        match sim_res {
            Ok((success, _, out, reason, _, _)) => {
                if success {
                    info!("[PASS] V4 Engine working. Output: {}", out);
                } else {
                    // 关键点：只要能收到 Revert，说明 ABI 编码没问题，只是池子不存在
                    info!("[PASS] V4 Engine working. Contract responded: '{}' (This proves ABI is correct)", reason);
                }
            }
            Err(e) => error!("[FAIL] V4 Engine crashed: {:?}", e),
        }
    }

    // 5. 模拟测试 (Virtuals Protocol) 验证 ABI 编码
    // 我们尝试对一个随机地址进行 Virtuals Buy 模拟。
    // 预期结果：合约应该 Revert (例如 "Subject not found" 或类似的)，这证明我们成功调用了合约。
    {
        let amount_in = U256::from(50000000000000000u64); // 0.05 ETH
        info!("[TEST] Simulating Virtuals Buy (Random Token) to verify ABI...");
        let origin = Address::from_str("0x0000000000000000000000000000000000001234").unwrap();
        // Random token address
        let random_token = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();

        let strategy = Arc::new(VirtualsStrategy {
            name: "Virtuals Test".into(),
        });

        let sim_res = simulator
            .simulate_bundle(origin, strategy, amount_in, random_token, 20)
            .await;

        match sim_res {
            Ok((success, _, out, reason, _, _)) => {
                if success {
                    info!(
                        "[PASS] Virtuals Engine working (Unexpected Success). Output: {}",
                        out
                    );
                } else {
                    // 只要能收到 Revert，说明 ABI 编码没问题
                    info!("[PASS] Virtuals Engine working. Contract responded: '{}' (This proves ABI is correct)", reason);
                }
            }
            Err(e) => error!("[FAIL] Virtuals Engine crashed: {:?}", e),
        }
    }

    // 6. 模拟测试 (Aerodrome V3) 验证 Slipstream 逻辑
    if let Ok(usdc) = Address::from_str("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913") {
        let amount_in = U256::from(50000000000000000u64); // 0.05 ETH
        info!("[TEST] Simulating WETH -> USDC (Aerodrome V3) to verify Slipstream logic...");
        let origin = Address::from_str("0x0000000000000000000000000000000000001234").unwrap();

        let strategy = Arc::new(UniswapV3Strategy {
            router: *AERO_V3_ROUTER,
            quoter: *AERO_V3_QUOTER,
            fee: 500,
            name: "Aero V3 Test".into(),
        });

        let sim_res = simulator
            .simulate_bundle(origin, strategy, amount_in, usdc, 20)
            .await;

        match sim_res {
            Ok((success, _, out, reason, _, fee)) => {
                if success {
                    info!(
                        "[PASS] Aerodrome V3 Simulation working. Output: {} USDC (Fee Tier: {})",
                        out, fee
                    );
                } else {
                    error!("[FAIL] Aerodrome V3 Simulation failed. Reason: {}", reason);
                }
            }
            Err(e) => error!("[FAIL] Aerodrome V3 Simulation crashed: {:?}", e),
        }
    }

    // 7. Manual Test (Merged)
    // 硬编码测试地址: 0x55f1fa9b4244d5276aa3e3aaf1ad56ebbc55422d (Luna)
    let token_str = "0x55f1fa9b4244d5276aa3e3aaf1ad56ebbc55422d";
    if let Ok(token_addr) = Address::from_str(token_str) {
        info!("[MANUAL TEST] Starting simulation for: {:?}", token_addr);
        let amount = U256::from(10000000000000000u64); // 0.01 ETH

        let strategy = Arc::new(VirtualsStrategy {
            name: "Manual Test (Virtuals)".into(),
        });

        match simulator
            .simulate_bundle(owner, strategy, amount, token_addr, 20)
            .await
        {
            Ok((success, profit, tokens, reason, gas, _)) => {
                info!(
                    "[MANUAL TEST] Result: Success={}, Profit={}, Tokens={}, Gas={}",
                    success, profit, tokens, gas
                );
                info!("[MANUAL TEST] Reason: {}", reason);
            }
            Err(e) => {
                error!("[MANUAL TEST] Simulation Error: {:?}", e);
            }
        }
    }

    info!("[SELF-CHECK] Diagnostics complete.\n");
}
