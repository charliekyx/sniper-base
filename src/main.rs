mod config;
mod constants;
mod logger;
mod persistence;
mod simulation;

use crate::config::AppConfig;
use crate::constants::{
    get_router_name, AERODROME_FACTORY, AERODROME_ROUTER, ALIENBASE_ROUTER, BASESWAP_ROUTER,
    CLANKER_FACTORY_V4, SUSHI_ROUTER, UNIV3_QUOTER, UNIV3_ROUTER, UNIV4_QUOTER, UNIVERSAL_ROUTER,
    WETH_BASE,
};
use crate::logger::{log_shadow_trade, log_to_file, ShadowRecord};
use crate::persistence::{
    init_storage, load_all_positions, remove_position, save_position, PositionData,
};
use crate::simulation::Simulator;
use chrono::Local;
use dotenv::dotenv;
use ethers::abi::{parse_abi, Token};
use ethers::prelude::*;
use ethers::providers::{Ipc, Middleware};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::mpsc;
use tokio::task;
use tokio::time::{sleep, timeout, Duration};

// --- Nonce Manager (Enhanced) ---
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

    // 修复：当交易发送失败时，允许重置本地 Nonce
    fn reset(&self, new_nonce: u64) {
        self.nonce.store(new_nonce, Ordering::SeqCst);
        println!(">>> [NONCE] Resynced to {}", new_nonce);
    }
}

// --- V4 Helpers ---

// PoolKey: (currency0, currency1, fee, tickSpacing, hooks)
type PoolKey = (Address, Address, u32, i32, Address);

fn extract_pool_key_from_universal_router(input: &[u8]) -> Option<PoolKey> {
    // Universal Router execute(bytes commands, bytes[] inputs)
    // Selector: 0x3593564c
    if input.len() < 4 || &input[0..4] != [0x35, 0x93, 0x56, 0x4c] {
        return None;
    }

    // Decode execute(bytes,bytes[])
    let abi = parse_abi(&["function execute(bytes,bytes[])"]).ok()?;
    let function = abi.function("execute").ok()?;
    let decoded = function.decode_input(&input[4..]).ok()?;

    let commands: Vec<u8> = decoded[0].clone().into_bytes()?;
    let inputs: Vec<Bytes> = decoded[1]
        .clone()
        .into_array()?
        .into_iter()
        .map(|t| Bytes::from(t.into_bytes().unwrap()))
        .collect();

    // Command 0x10 is V4_SWAP
    for (i, &cmd) in commands.iter().enumerate() {
        // Mask out the flag bits (0x1f is the command mask, usually)
        // Actually Universal Router commands are just bytes. 0x10 is V4_SWAP.
        if cmd == 0x10 && i < inputs.len() {
            let param_bytes = &inputs[i];
            // V4_SWAP input: (bytes actions, bytes[] params)
            // The input bytes are NOT prefixed with selector, they are just the tuple
            // But ethabi expects a selector for decode_input usually, or we use decode params.
            // Let's try to decode as a tuple directly.
            let v4_tokens = ethers::abi::decode(
                &[
                    ethers::abi::ParamType::Bytes,
                    ethers::abi::ParamType::Array(Box::new(ethers::abi::ParamType::Bytes)),
                ],
                param_bytes,
            )
            .ok()?;

            let actions: Vec<u8> = v4_tokens[0].clone().into_bytes()?;
            let action_params: Vec<Bytes> = v4_tokens[1]
                .clone()
                .into_array()?
                .into_iter()
                .map(|t| Bytes::from(t.into_bytes().unwrap()))
                .collect();

            // Action 0x06 is SWAP_EXACT_IN_SINGLE
            for (j, &action) in actions.iter().enumerate() {
                if action == 0x06 && j < action_params.len() {
                    let p = &action_params[j];
                    // ExactInputSingleParams: (PoolKey poolKey, bool zeroForOne, uint128 amountIn, uint128 amountOutMin, bytes hookData)
                    // PoolKey: (currency0, currency1, fee, tickSpacing, hooks)
                    // Total struct: ((addr, addr, u24, i24, addr), bool, u128, u128, bytes)
                    let pool_key_type = ethers::abi::ParamType::Tuple(vec![
                        ethers::abi::ParamType::Address,
                        ethers::abi::ParamType::Address,
                        ethers::abi::ParamType::Uint(24),
                        ethers::abi::ParamType::Int(24),
                        ethers::abi::ParamType::Address,
                    ]);
                    let params_type = vec![
                        pool_key_type,
                        ethers::abi::ParamType::Bool,
                        ethers::abi::ParamType::Uint(128),
                        ethers::abi::ParamType::Uint(128),
                        ethers::abi::ParamType::Bytes,
                    ];

                    let decoded_params = ethers::abi::decode(&params_type, p).ok()?;
                    let pk_tuple = decoded_params[0].clone().into_tuple()?;

                    let c0 = pk_tuple[0].clone().into_address()?;
                    let c1 = pk_tuple[1].clone().into_address()?;
                    let fee = pk_tuple[2].clone().into_uint()?.as_u32();
                    let ts = pk_tuple[3].clone().into_int()?.as_u32() as i32;
                    let hooks = pk_tuple[4].clone().into_address()?;

                    return Some((c0, c1, fee, ts, hooks));
                }
            }
        }
    }
    None
}

// --- Helper: Input Decoding ---
fn decode_router_input(input: &[u8]) -> Option<(String, Address)> {
    if input.len() < 4 {
        return None;
    }
    let sig = &input[0..4];
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
    let read_address = |offset: usize| -> Option<Address> {
        if offset + 32 > input.len() {
            return None;
        }
        Some(Address::from_slice(&input[offset + 12..offset + 32]))
    };
    let get_path_token = |arg_index: usize, get_last: bool| -> Option<Address> {
        let offset_ptr = 4 + arg_index * 32;
        let array_offset = read_usize(offset_ptr)?;
        let len_ptr = 4 + array_offset;
        let array_len = read_usize(len_ptr)?;
        if array_len == 0 {
            return None;
        }
        let elem_index = if get_last { array_len - 1 } else { 0 };
        let item_ptr = len_ptr + 32 + elem_index * 32;
        read_address(item_ptr)
    };

    if sig == [0x7f, 0xf3, 0x6a, 0xb5] || sig == [0xb6, 0xf9, 0xde, 0x95] {
        let action = if sig[0] == 0x7f {
            "Buy_ETH->Token"
        } else {
            "Buy_Fee_ETH->Token"
        };
        return get_path_token(1, true).map(|t| (action.to_string(), t));
    } else if sig == [0x18, 0xcb, 0xaf, 0xe5] || sig == [0x79, 0x1a, 0xc9, 0x47] {
        let action = if sig[0] == 0x18 {
            "Sell_Token->ETH"
        } else {
            "Sell_Fee_Token->ETH"
        };
        return get_path_token(2, false).map(|t| (action.to_string(), t));
    } else if sig == [0x38, 0xed, 0x17, 0x39] || sig == [0x5c, 0x11, 0xd7, 0x95] {
        return get_path_token(2, true).map(|t| ("Swap_Token->Token".to_string(), t));
    } else if sig == [0xf3, 0x05, 0xd7, 0x19] {
        return read_address(4).map(|t| ("AddLiquidity".to_string(), t));
    } else if sig == [0xd1, 0xee, 0x21, 0x1d] || sig == [0x0f, 0x27, 0xc5, 0xc1] {
        // Odos Router: swap / swapCompact
        // 参数结构: (bytes pathDefinition, ...)
        // pathDefinition 是紧凑字节: [TokenIn(20)] [Fee(3)] [TokenOut(20)]
        let offset_ptr = 4; // 第一个参数的 offset
        let path_offset = read_usize(offset_ptr)?;
        let len_ptr = 4 + path_offset;
        let path_len = read_usize(len_ptr)?;

        // 最短路径: In(20) + Fee(3) + Out(20) = 43 字节
        if path_len < 40 {
            return None;
        }

        let path_start = len_ptr + 32;
        if path_start + path_len > input.len() {
            return None;
        }

        let path_bytes = &input[path_start..path_start + path_len];
        let token_in = Address::from_slice(&path_bytes[0..20]);
        let token_out = Address::from_slice(&path_bytes[path_len - 20..path_len]);

        if token_in == *WETH_BASE || token_in == Address::zero() {
            return Some(("Buy_Odos".to_string(), token_out));
        } else {
            // 如果不是用 ETH 买，可能是 USDC->Token (视为 Swap) 或者 Token->ETH (视为 Sell)
            // 这里简化处理：只要输出不是 ETH，就认为是买入/兑换目标 Token
            if token_out != *WETH_BASE && token_out != Address::zero() {
                return Some(("Swap_Odos".to_string(), token_out));
            }
            // 如果输出是 ETH，那就是卖出，返回输入 Token
            return Some(("Sell_Odos".to_string(), token_in));
        }
    } else if sig == [0x41, 0x4b, 0xf3, 0x89] {
        // Uniswap V3: exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))
        // Struct in calldata: tokenIn(0), tokenOut(32), fee(64), ...
        // Offset 4 + 32 = 36.
        return read_address(36).map(|t| ("Buy_V3_Single".to_string(), t));
    } else if sig == [0xc0, 0x4b, 0x8d, 0x59] {
        // Uniswap V3: exactInput((bytes path, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum))
        // Path is encoded as: tokenIn (20) + fee (3) + tokenOut (20) ...
        let offset_ptr = 4;
        let path_offset = read_usize(offset_ptr)?;
        let len_ptr = 4 + path_offset;
        let path_len = read_usize(len_ptr)?;
        if path_len < 20 {
            return None;
        }
        let path_start = len_ptr + 32;
        let token_out_start = path_start + path_len - 20;
        return Some((
            "Buy_V3_Multi".to_string(),
            Address::from_slice(&input[token_out_start..token_out_start + 20]),
        ));
    } else if sig == [0xca, 0xe6, 0xa6, 0xb3] || sig == [0x35, 0x93, 0x56, 0x4c] {
        // Uniswap Universal Router: execute
        // 这是一个聚合路由，输入数据很复杂。
        // 我们返回一个标记，具体的 Token 地址交给后续的 Simulator (scan_tx_for_token_in) 去从日志中提取。
        return Some(("Universal_Interaction".to_string(), Address::zero()));
    }
    None
}

// --- Execution Core ---

async fn execute_buy_and_approve(
    client: Arc<SignerMiddleware<Provider<Ipc>, LocalWallet>>,
    nonce_manager: Arc<NonceManager>,
    router_addr: Address,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    amount_out_min: U256,
    config: &AppConfig,
    fee: u32,                     // Added fee for V3
    v4_pool_key: Option<PoolKey>, // [新增] V4 PoolKey
) -> anyhow::Result<()> {
    println!(
        ">>> [BUNDLE] Preparing Buy + Approve sequence for {:?}...",
        token_out
    );

    let nonce_buy = nonce_manager.get_and_increment();
    let nonce_approve = nonce_manager.get_and_increment();

    let deadline = U256::from(Local::now().timestamp() + 60);

    // [修改] 实盘交易适配 Aerodrome
    let calldata = if let Some(pk) = v4_pool_key {
        // Universal Router V4 Swap
        // execute(bytes commands, bytes[] inputs, uint256 deadline)
        // Command: 0x10 (V4_SWAP)
        // V4_SWAP Input: (bytes actions, bytes[] params)
        // Action: 0x06 (SWAP_EXACT_IN_SINGLE)
        // Params: ((c0, c1, fee, ts, hooks), zeroForOne, amountIn, amountOutMin, hookData)

        let zero_for_one = *WETH_BASE < token_out;

        // Encode PoolKey
        let pk_token = Token::Tuple(vec![
            Token::Address(pk.0),
            Token::Address(pk.1),
            Token::Uint(pk.2.into()),
            Token::Int(U256::from(pk.3)),
            Token::Address(pk.4),
        ]);

        // Encode ExactInputSingleParams
        let swap_params = ethers::abi::encode(&vec![
            pk_token,
            Token::Bool(zero_for_one),
            Token::Uint(amount_in),
            Token::Uint(amount_out_min),
            Token::Bytes(vec![]), // hookData
        ]);

        // Encode V4_SWAP inputs: actions + params
        let actions = vec![0x06u8]; // SWAP_EXACT_IN_SINGLE
        let action_params = vec![Token::Bytes(swap_params)];
        let v4_swap_input =
            ethers::abi::encode(&vec![Token::Bytes(actions), Token::Array(action_params)]);

        // Encode execute
        let commands = vec![0x10u8]; // V4_SWAP
        let inputs = vec![Token::Bytes(v4_swap_input)];

        let router = BaseContract::from(parse_abi(&[
            "function execute(bytes,bytes[],uint256) external payable",
        ])?);
        router.encode("execute", (Bytes::from(commands), inputs, deadline))?
    } else if router_addr == *UNIV3_ROUTER {
        // Uniswap V3
        let v3_abi = parse_abi(&["function exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160)) external payable returns (uint256)"])?;
        let router = BaseContract::from(v3_abi);
        // params: (tokenIn, tokenOut, fee, recipient, deadline, amountIn, amountOutMin, sqrtPriceLimitX96)
        let params = (
            *WETH_BASE,
            token_out,
            fee,
            client.address(),
            deadline,
            amount_in,
            amount_out_min,
            U256::zero(),
        );
        router.encode("exactInputSingle", (params,))?
    } else if router_addr == *AERODROME_ROUTER {
        let aero_abi = parse_abi(&["function swapExactETHForTokensSupportingFeeOnTransferTokens(uint,(address,address,bool,address)[],address,uint) external payable"])?;
        let router = BaseContract::from(aero_abi);
        let route = (
            token_in,
            token_out,
            false, // stable
            *AERODROME_FACTORY,
        );
        let routes = vec![route];
        router.encode(
            "swapExactETHForTokensSupportingFeeOnTransferTokens",
            (amount_out_min, routes, client.address(), deadline),
        )?
    } else {
        // 标准 V2
        let router_abi = parse_abi(&[
            "function swapExactETHForTokensSupportingFeeOnTransferTokens(uint amountOutMin, address[] calldata path, address to, uint deadline) external payable"
        ])?;
        let router = BaseContract::from(router_abi);
        let path = vec![token_in, token_out];
        router.encode(
            "swapExactETHForTokensSupportingFeeOnTransferTokens",
            (amount_out_min, path, client.address(), deadline),
        )?
    };

    let gas_price = client.provider().get_gas_price().await?;
    let priority_fee = U256::from(config.max_priority_fee_gwei * 1_000_000_000);
    let total_gas_price = gas_price + priority_fee;

    let buy_tx = Eip1559TransactionRequest::new()
        .to(router_addr)
        .value(amount_in)
        .data(calldata.0)
        .gas(config.gas_limit) // Base 链建议给足 Gas
        .max_fee_per_gas(total_gas_price)
        .max_priority_fee_per_gas(priority_fee)
        .nonce(nonce_buy);

    let erc20_abi = parse_abi(&["function approve(address,uint) external returns (bool)"])?;
    let token_contract = BaseContract::from(erc20_abi);
    let approve_calldata = token_contract.encode("approve", (router_addr, U256::MAX))?;

    let approve_tx = Eip1559TransactionRequest::new()
        .to(token_out)
        .data(approve_calldata.0)
        .gas(80_000)
        .max_fee_per_gas(total_gas_price)
        .max_priority_fee_per_gas(priority_fee)
        .nonce(nonce_approve);

    println!(
        ">>> [BUNDLE] Broadcasting Nonce {} & {}...",
        nonce_buy, nonce_approve
    );

    // 修复：Nonce 错位保护
    // 如果发送交易直接失败 (Err)，说明 Nonce 可能没上链，或者 RPC 拒绝了。
    // 这时候本地 Nonce 已经增加了，但链上没动，会导致后续交易 Gap。
    let pending_buy = match client.send_transaction(buy_tx.clone(), None).await {
        Ok(p) => p,
        Err(e) => {
            println!("!!! [ERROR] Buy Tx Failed immediately: {:?}", e);
            println!("!!! [RECOVERY] Attempting to resync Nonce from chain...");
            if let Ok(real_nonce) = client.get_transaction_count(client.address(), None).await {
                nonce_manager.reset(real_nonce.as_u64());
            }
            return Err(e.into());
        }
    };

    // 尝试发送 Approve，如果不重要失败也可以接受（可以在卖出时再 approve）
    let _ = client.send_transaction(approve_tx, None).await;

    println!(">>> [BUNDLE] Buy Sent: {:?}", pending_buy.tx_hash());

    match timeout(Duration::from_secs(30), pending_buy).await {
        Ok(receipt_res) => {
            let receipt = receipt_res?;
            if receipt.is_some() && receipt.unwrap().status == Some(U64::from(1)) {
                println!(">>> [BUNDLE] Buy Confirmed.");
                Ok(())
            } else {
                Err(anyhow::anyhow!("Buy transaction reverted"))
            }
        }
        Err(_) => {
            println!("!!! [ALERT] Transaction STUCK (Low Gas). Please check Explorer !!!");
            Err(anyhow::anyhow!("Buy transaction timeout (Stuck)"))
        }
    }
}

// Smart Sell Logic
async fn execute_smart_sell(
    client: Arc<SignerMiddleware<Provider<Ipc>, LocalWallet>>,
    router_addr: Address,
    token_in: Address,
    token_out: Address,
    amount_token: U256,
    config: &AppConfig,
    is_panic: bool,
    fee: u32, // Added fee for V3
    v4_pool_key: Option<PoolKey>,
) -> anyhow::Result<TxHash> {
    let deadline = U256::from(Local::now().timestamp() + 120);

    let send_sell = |amt: U256, gas_mult: u64| {
        let client = client.clone();
        let priority_fee = config.max_priority_fee_gwei;
        let router_addr = router_addr; // Capture
        let token_in = token_in;
        let token_out = token_out;

        async move {
            // [修复] 卖出逻辑适配 Aerodrome
            let calldata = if let Some(pk) = v4_pool_key {
                // Universal Router V4 Sell
                // Same logic as buy but token_in is Token, token_out is WETH
                let zero_for_one = token_in < token_out;

                let pk_token = Token::Tuple(vec![
                    Token::Address(pk.0),
                    Token::Address(pk.1),
                    Token::Uint(pk.2.into()),
                    Token::Int(U256::from(pk.3)),
                    Token::Address(pk.4),
                ]);

                // Swap Exact Input Single (Sell all tokens)
                let swap_params = ethers::abi::encode(&vec![
                    pk_token,
                    Token::Bool(zero_for_one),
                    Token::Uint(amt),
                    Token::Uint(U256::zero()), // Min out 0 for panic sell
                    Token::Bytes(vec![]),
                ]);

                // Actions: SWAP_EXACT_IN_SINGLE (0x06) -> SETTLE_ALL (0x0c) -> TAKE_ALL (0x0e) ?
                // Simplified: Just SWAP_EXACT_IN_SINGLE usually handles transfer if router has allowance.
                // Universal Router V4 usually requires: SWAP -> TAKE_ALL (if output is ETH, maybe UNWRAP)
                // For simplicity, we assume standard V4 swap action handles it or we just do swap.
                // NOTE: Proper V4 encoding often needs SETTLE/TAKE.
                // Let's stick to the basic SWAP action for now, assuming standard router behavior.

                let actions = vec![0x06u8];
                let action_params = vec![Token::Bytes(swap_params)];
                let v4_swap_input =
                    ethers::abi::encode(&vec![Token::Bytes(actions), Token::Array(action_params)]);

                let commands = vec![0x10u8];
                let inputs = vec![Token::Bytes(v4_swap_input)];
                let router = BaseContract::from(parse_abi(&[
                    "function execute(bytes,bytes[],uint256) external payable",
                ])?);
                router.encode("execute", (Bytes::from(commands), inputs, deadline))?
            } else if router_addr == *UNIV3_ROUTER {
                let v3_abi = parse_abi(&["function exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160)) external payable returns (uint256)"])?;
                let router = BaseContract::from(v3_abi);
                // Sell: Token -> WETH
                let params = (
                    token_in,
                    token_out,
                    fee,
                    client.address(),
                    deadline,
                    amt,
                    U256::zero(),
                    U256::zero(),
                );
                router.encode("exactInputSingle", (params,))?
            } else if router_addr == *AERODROME_ROUTER {
                let aero_abi = parse_abi(&["function swapExactTokensForETHSupportingFeeOnTransferTokens(uint amountIn, uint amountOutMin, (address,address,bool,address)[] routes, address to, uint deadline) external"])?;
                let router = BaseContract::from(aero_abi);
                let route = (
                    token_in,
                    token_out,
                    false, // stable
                    *AERODROME_FACTORY,
                );
                let routes = vec![route];
                router.encode(
                    "swapExactTokensForETHSupportingFeeOnTransferTokens",
                    (amt, U256::zero(), routes, client.address(), deadline),
                )?
            } else {
                // 标准 V2
                let router_abi = parse_abi(&[
                    "function swapExactTokensForETHSupportingFeeOnTransferTokens(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline) external"
                ])?;
                let router = BaseContract::from(router_abi);
                let path = vec![token_in, token_out];
                router.encode(
                    "swapExactTokensForETHSupportingFeeOnTransferTokens",
                    (amt, U256::zero(), path, client.address(), deadline),
                )?
            };

            let base_fee = client.provider().get_gas_price().await?;
            let prio_fee_val = U256::from(priority_fee * 1_000_000_000 * gas_mult);
            let max_fee = base_fee + prio_fee_val;

            // [升级] 使用 EIP-1559 交易
            let tx = Eip1559TransactionRequest::new()
                .to(router_addr)
                .data(calldata.0)
                // 修复：卖出给足 Gas，防止因为逻辑复杂 OutOfGas 导致卖不出去
                .gas(500_000)
                .max_fee_per_gas(max_fee)
                .max_priority_fee_per_gas(prio_fee_val);

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
    client: Arc<SignerMiddleware<Provider<Ipc>, LocalWallet>>,
    router_addr: Address,
    token_addr: Address,
    initial_cost_eth: U256,
    config: AppConfig,
    processing_locks: Arc<Mutex<HashSet<Address>>>,
    initial_simulated_tokens: Option<U256>, // [新增] 用于影子模式的虚拟持仓
    fee: u32,                               // Added fee for V3
    v4_pool_key: Option<PoolKey>,
) {
    println!("*** [MONITOR] Watching: {:?}", token_addr);
    // 修复：使用 expect/match 替代 unwrap，防止 panic
    let erc20_abi = parse_abi(&["function balanceOf(address) external view returns (uint)"])
        .expect("ABI Parse Error");
    let token_contract = Contract::new(token_addr, erc20_abi, client.clone());

    // V2 Router
    let router_abi =
        parse_abi(&["function getAmountsOut(uint,address[]) external view returns (uint[])"])
            .expect("ABI Parse Error");
    let router_contract = Contract::new(router_addr, router_abi, client.clone());

    // V4 Quoter
    let v4_quoter = Contract::new(*UNIV4_QUOTER, parse_abi(&["function quoteExactInputSingle(((address,address,uint24,int24,address), bool, uint128, bytes)) external returns (uint256, uint128)"]).unwrap(), client.clone());

    // V3 Quoter
    let quoter_contract = Contract::new(*UNIV3_QUOTER, parse_abi(&["function quoteExactInputSingle((address,address,uint256,uint24,uint160)) external returns (uint256, uint160, uint32, uint256)"]).unwrap(), client.clone());
    let path = vec![token_addr, *WETH_BASE];

    let mut sold_half = false;
    let mut check_count = 0;
    let mut shadow_balance = initial_simulated_tokens.unwrap_or(U256::zero());

    loop {
        check_count += 1;
        if check_count % 20 == 0 {
            println!("... monitoring {} ...", token_addr);
        }

        // 修复：如果网络错误，不崩溃，而是等待重试
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
            println!(
                "*** [MONITOR] Balance is 0 for {:?}. Removing persistence.",
                token_addr
            );
            // 释放锁，允许再次买入
            if let Ok(mut locks) = processing_locks.lock() {
                locks.remove(&token_addr);
            }
            remove_position(token_addr);
            break;
        }

        let current_val = if let Some(pk) = v4_pool_key {
            // V4 Price Check
            let zero_for_one = token_addr < *WETH_BASE;
            let params = (pk, zero_for_one, balance.as_u128(), Bytes::default());
            match v4_quoter.method::<_, (U256, u128)>("quoteExactInputSingle", (params,)) {
                Ok(m) => match m.call().await {
                    Ok((amount_out, _)) => amount_out,
                    Err(_) => U256::zero(),
                },
                Err(_) => U256::zero(),
            }
        } else if router_addr == *UNIV3_ROUTER {
            // V3 Price Check
            let params = (token_addr, *WETH_BASE, balance, fee, U256::zero());
            match quoter_contract
                .method::<(Address, Address, U256, u32, U256), (U256, U256, u32, U256)>(
                    "quoteExactInputSingle",
                    params,
                ) {
                Ok(m) => match m.call().await {
                    Ok((amount_out, _, _, _)) => amount_out,
                    Err(_) => U256::zero(),
                },
                Err(_) => U256::zero(),
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
            println!("[EXIT] 3x Profit! Dumping ALL.");
            trigger_sell = true;
            sell_reason = "3x_Profit".to_string();
        } else if config.sell_strategy_2x_exit_half
            && !sold_half
            && current_val >= initial_cost_eth * 2
        {
            println!("[EXIT] 2x Profit! Selling HALF.");
            trigger_sell = true;
            sell_amount = balance / 2;
            sold_half = true;
            sell_reason = "2x_Profit_Half".to_string();
        } else {
            let stop_loss_limit = initial_cost_eth * (100 - config.anti_rug_dip_threshold) / 100;
            if current_val < stop_loss_limit {
                println!("[ALERT] Price crashed! Panic Selling!");
                trigger_sell = true;
                is_panic = true;
                sell_reason = "Stop_Loss".to_string();
            }
        }

        if trigger_sell {
            if config.shadow_mode {
                // 影子模式：记录数据并退出监控
                // 注意：这里计算的是本次卖出的价值，如果是半仓卖出，initial_cost_eth 只是参考
                crate::logger::log_shadow_sell(
                    format!("{:?}", token_addr),
                    ethers::utils::format_units(initial_cost_eth, "ether").unwrap(),
                    ethers::utils::format_units(current_val, "ether").unwrap(),
                    sell_reason.clone(),
                );

                // 如果是半仓卖出，更新虚拟余额并继续监控
                if sell_reason == "2x_Profit_Half" {
                    shadow_balance = shadow_balance - sell_amount;
                } else {
                    // 全仓卖出或止损，退出
                    if let Ok(mut locks) = processing_locks.lock() {
                        locks.remove(&token_addr);
                    }
                    break;
                }
            } else {
                // 实盘模式：执行真实卖出
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
                // 实盘卖出后释放锁
                if let Ok(mut locks) = processing_locks.lock() {
                    locks.remove(&token_addr);
                }
            }

            if !sold_half || is_panic {
                sleep(Duration::from_secs(5)).await;
            }
        }

        sleep(Duration::from_secs(2)).await;
    }
}

async fn process_transaction(
    tx: Transaction,
    provider: Arc<Provider<Ipc>>,
    client: Arc<SignerMiddleware<Provider<Ipc>, LocalWallet>>,
    nonce_manager: Arc<NonceManager>,
    simulator: Simulator,
    config: AppConfig,
    targets: Vec<Address>,
    processing_locks: Arc<Mutex<HashSet<Address>>>, // 新增：重复锁
) {
    if let Some(to) = tx.to {
        // 1. 只要是目标钱包的交易，先打日志，防止“静默失效”
        let is_from_target = targets.contains(&tx.from);
        if is_from_target {
            let selector_bytes = if tx.input.len() >= 4 {
                &tx.input[0..4]
            } else {
                &[]
            };
            let selector = ethers::utils::hex::encode(selector_bytes);

            // [新增] 提前过滤高频非交易操作，减少日志噪音
            // 0x095ea7b3: approve(address,uint256)
            // 0xa9059cbb: transfer(address,uint256)
            if selector == "095ea7b3" || selector == "a9059cbb" {
                return;
            }

            let msg = format!(
                "[ACTIVITY] Target: {:?} | To: {:?} | Selector: 0x{}",
                tx.from, to, selector
            );
            println!("{}", msg);
            log_to_file(msg);
        }

        let router_name = get_router_name(&to);
        let decoded = decode_router_input(&tx.input);

        // [修改] 智能识别逻辑：解码 -> 失败则模拟 -> 最终判定
        // [新增] 提取 V4 PoolKey
        let mut v4_pool_key = extract_pool_key_from_universal_router(&tx.input);

        let (mut action, mut token_addr) = if let Some((act, tok)) = decoded {
            (act, tok)
        } else if is_from_target {
            if let Ok(Some(token)) = simulator.scan_tx_for_token_in(tx.clone()).await {
                ("Auto_Buy".to_string(), token)
            } else {
                // 确实无法识别，打印日志并跳过
                let selector = if tx.input.len() >= 4 {
                    ethers::utils::hex::encode(&tx.input[0..4])
                } else {
                    "0x".to_string()
                };
                let _input_preview = ethers::utils::hex::encode(&tx.input);
                log_to_file(format!(
                    "   [IGNORED] No token inflow (Sell/Fail/Wrap) | Target tx to {:?} | Selector: 0x{} | InputLen: {}",
                    to, selector, tx.input.len()
                ));
                return;
            }
        } else {
            return;
        };

        // [新增] 如果是 Universal Router (Address::zero())，强制进行模拟以获取真实的 Token 地址
        if token_addr == Address::zero() && action == "Universal_Interaction" {
            if let Ok(Some(token)) = simulator.scan_tx_for_token_in(tx.clone()).await {
                token_addr = token;
                action = "Auto_Buy_Universal".to_string();
                // 如果之前没提取到 PoolKey，这里再试一次（虽然 input 没变，但逻辑上确认是 Universal）
                if v4_pool_key.is_none() {
                    v4_pool_key = extract_pool_key_from_universal_router(&tx.input);
                }
            } else {
                return; // 模拟也没发现代币流入（可能是卖出或失败），跳过
            }
        }

        if true {
            // 保持原有缩进结构，实际逻辑已在上面处理
            if is_from_target && router_name == "Unknown" {
                println!(
                    "   [DEBUG] Target interacted with unknown router/contract: {:?}",
                    to
                );
                log_to_file(format!(
                    "   [DEBUG] Target interacted with unknown router/contract: {:?}",
                    to
                ));
            }

            if is_from_target {
                log_to_file(format!(
                    "   [MATCH] Action: {} | Token: {:?}",
                    action, token_addr
                ));
            }

            if router_name == "Unknown" && action != "AddLiquidity" {
                return;
            }

            // 修复：双重购买保护
            // 检查该 Token 是否正在被处理，如果是，直接跳过
            {
                let mut locks = processing_locks.lock().unwrap();
                if locks.contains(&token_addr) {
                    return;
                }
                locks.insert(token_addr);
            }

            // 使用 defer 模式（手动在所有退出点移除）比较繁琐
            // 这里我们采用一个简单的 cleanup 闭包逻辑，或者在函数结束处统一移除
            // 由于 Rust async 闭包复杂，我们手动在 exit points 移除

            let cleanup = |token| {
                if let Ok(mut locks) = processing_locks.lock() {
                    locks.remove(&token);
                }
            };

            // 修复：匹配 decode_router_input 返回的动作名称
            // 允许 Swap_Token->Token，因为很多高手用 USDC/WETH 买入
            let is_target_buy = config.copy_trade_enabled
                && is_from_target
                && (action.contains("Buy") || action.contains("Swap") || action == "Auto_Buy");
            let is_new_liquidity = config.sniper_enabled && action == "AddLiquidity";

            if !is_target_buy && !is_new_liquidity {
                cleanup(token_addr);
                return;
            }

            // 过滤掉卖出 WETH 的行为（比如 Token -> WETH 也会被识别为 Swap）
            if token_addr == *WETH_BASE {
                cleanup(token_addr);
                return;
            }

            let trigger_msg = format!("Trigger: {} | Token: {:?}", action, token_addr);
            println!("\n {}", trigger_msg);
            log_to_file(trigger_msg);
            let buy_amt = U256::from((config.buy_amount_eth * 1e18) as u64);

            if config.sniper_block_delay > 0 && !config.shadow_mode {
                let target_block = provider.get_block_number().await.unwrap_or_default()
                    + config.sniper_block_delay;
                loop {
                    if provider.get_block_number().await.unwrap_or_default() >= target_block {
                        break;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
            }

            // [策略升级] 多路由扫描：如果目标使用聚合器，轮询主流 V2 DEX 直到找到流动性
            let mut effective_router = to;
            let mut sim_result_tuple = (
                false,
                U256::zero(),
                U256::zero(),
                "Init".to_string(),
                0,
                0u32,
            );

            let r_name = get_router_name(&to);

            // [策略重构] 盲测模式：构建一个策略列表，依次尝试
            // 结构: (Router地址, V4_PoolKey选项, 描述)
            let mut strategies: Vec<(Address, Option<PoolKey>, String)> = Vec::new();

            // 1. 优先尝试提取到的 V4 Key (如果有)
            if let Some(pk) = v4_pool_key {
                strategies.push((*UNIVERSAL_ROUTER, Some(pk), "Extracted V4 Key".to_string()));
            }

            // 2. 如果目标是 Universal Router 或 Unknown，尝试“盲猜” Clanker V4 配置
            // Clanker V4 特征: Fee 1%, Tick 60, Hook = Factory
            if r_name == "UniversalRouter" || r_name == "Unknown" {
                let token0 = if token_addr < *WETH_BASE {
                    token_addr
                } else {
                    *WETH_BASE
                };
                let token1 = if token_addr < *WETH_BASE {
                    *WETH_BASE
                } else {
                    token_addr
                };

                let guess_key = (
                    token0,
                    token1,
                    10000,               // Fee 1%
                    60,                  // TickSpacing
                    *CLANKER_FACTORY_V4, // Hook Guess
                );
                strategies.push((
                    *UNIVERSAL_ROUTER,
                    Some(guess_key),
                    "Guess Clanker V4".to_string(),
                ));
            }

            // 3. 总是尝试 Uniswap V3 (Clanker 经常兼容 V3，或者有 V3 池子)
            strategies.push((*UNIV3_ROUTER, None, "Uniswap V3".to_string()));

            // 4. 尝试主流 V2 DEX (Aerodrome, BaseSwap, etc.)
            strategies.push((*AERODROME_ROUTER, None, "Aerodrome V2".to_string()));
            strategies.push((*BASESWAP_ROUTER, None, "BaseSwap V2".to_string()));
            strategies.push((*ALIENBASE_ROUTER, None, "AlienBase V2".to_string()));
            strategies.push((*SUSHI_ROUTER, None, "SushiSwap V2".to_string()));

            println!("   [Strategy] Scanning markets for liquidity...");

            for (router, key, desc) in strategies {
                effective_router = router;
                let r_name_debug = get_router_name(&router);
                let sim_res = simulator
                    .simulate_bundle(
                        client.address(),
                        None,
                        effective_router,
                        buy_amt,
                        token_addr,
                        key, // 使用当前策略的 Key (可能是提取的，可能是猜的，也可能是 None)
                    )
                    .await;

                match sim_res {
                    Ok(res) => {
                        sim_result_tuple = res;
                        // 如果模拟成功（sim_ok = true），说明在这个路由上买入成功且有余额
                        if sim_result_tuple.0 {
                            println!(
                                "   [Strategy] Liquidity found via [{}] on {}! (Est: {})",
                                desc, r_name_debug, sim_result_tuple.2
                            );
                            // 如果成功的是盲猜的 Key，我们需要更新 v4_pool_key 以便后续交易使用
                            if key.is_some() {
                                v4_pool_key = key;
                            }
                            break;
                        } else {
                            // [新增] 打印失败原因，方便调试
                            println!(
                                "   [Debug] Tried [{}] -> Failed: {}",
                                desc, sim_result_tuple.3
                            );
                        }
                    }
                    Err(e) => {
                        // 记录错误但继续尝试下一个
                        println!("   [Debug] Tried [{}] -> Error: {:?}", desc, e);
                        sim_result_tuple = (
                            false,
                            U256::zero(),
                            U256::zero(),
                            format!("Sim Error on {}: {}", r_name_debug, e),
                            0,
                            0,
                        );
                    }
                }
            }

            let (sim_ok, profit_wei, expected_tokens, reason, gas_used, best_fee) =
                sim_result_tuple;

            if config.shadow_mode {
                println!("   [Shadow] Sim Result: {} | Reason: {}", sim_ok, reason);
                log_to_file(format!(
                    "[Shadow] Sim Result: {} | Reason: {} | Token: {:?}",
                    sim_ok, reason, token_addr
                ));

                // Use 'profit_wei' directly (it is a U256 value, not a reference, so no '*' needed)
                let profit_eth = if sim_ok {
                    Some(ethers::utils::format_units(profit_wei, "ether").unwrap_or_default())
                } else {
                    None
                };

                log_shadow_trade(ShadowRecord {
                    timestamp: Local::now().to_rfc3339(),
                    event_type: action.to_string(),
                    router: get_router_name(&effective_router), // [修复] 记录实际使用的有效路由(如 BaseSwap)，而不是目标的路由(如 Odos)
                    trigger_hash: format!("{:?}", tx.hash),
                    token_address: format!("{:?}", token_addr),
                    amount_in_eth: config.buy_amount_eth.to_string(),
                    simulation_result: reason.clone(),
                    profit_eth_after_sell: profit_eth,
                    gas_used,
                    copy_target: if is_target_buy {
                        Some(format!("{:?}", tx.from))
                    } else {
                        None
                    },
                });

                // 改进：如果你想在 Shadow Mode 测试卖出逻辑，可以模拟启动监控
                if sim_ok {
                    println!("   [Shadow] Starting virtual monitor for {:?}", token_addr);
                    task::spawn(monitor_position(
                        client.clone(),
                        effective_router,
                        token_addr,
                        buy_amt,
                        config.clone(),
                        processing_locks.clone(),
                        Some(expected_tokens), // [新增] 传入模拟的代币数量
                        best_fee,
                        v4_pool_key,
                    ));
                } else {
                    // 修复：如果模拟失败，立即释放锁，以便下次机会
                    cleanup(token_addr);
                }

                // 影子模式下直接返回，不进入实盘逻辑
                return;
            }

            // Real Trading Logic (Only reached if shadow_mode is false)
            if !sim_ok {
                println!("   [ABORT] Simulation failed: {}. Likely Honeypot.", reason);
                log_to_file(format!(
                    "[ABORT] Sim failed: {} | Token: {:?}",
                    reason, token_addr
                ));
                cleanup(token_addr);
                return;
            }

            let min_out = expected_tokens * 80 / 100;

            match execute_buy_and_approve(
                client.clone(),
                nonce_manager,
                effective_router,
                *WETH_BASE,
                token_addr,
                buy_amt,
                min_out,
                &config,
                best_fee,
                v4_pool_key,
            )
            .await
            {
                Ok(_) => {
                    println!(">>> [PERSIST] Saving position to file...");
                    log_to_file(format!(
                        ">>> [LIVE] Buy Confirmed & Position Saved: {:?}",
                        token_addr
                    ));
                    let pos_data = PositionData {
                        token_address: token_addr,
                        router_address: effective_router,
                        initial_cost_eth: buy_amt,
                        timestamp: Local::now().timestamp() as u64,
                        fee: Some(best_fee),
                    };
                    let _ = save_position(&pos_data);
                    task::spawn(monitor_position(
                        client,
                        effective_router,
                        token_addr,
                        buy_amt,
                        config,
                        processing_locks.clone(),
                        None, // 实盘模式不需要传入虚拟余额
                        best_fee,
                        v4_pool_key,
                    ));
                }
                Err(e) => {
                    println!("   [Error] Buy Tx Failed: {:?}", e);
                    cleanup(token_addr);
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt::init();
    let config = AppConfig::from_env();

    println!("=== Base Sniper Pro (Optimized + Secure) ===");
    println!(
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

    init_storage();

    // 修复：初始化重复购买锁（必须在恢复持仓和启动监控之前）
    let processing_locks = Arc::new(Mutex::new(HashSet::new()));

    // 修复：使用配置中的 RPC_URL (IPC 路径)
    let provider = Provider::<Ipc>::connect_ipc(&config.rpc_url).await?;

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
    let targets = config.get_targets();

    // 恢复之前的持仓
    let existing_positions = load_all_positions();
    if !existing_positions.is_empty() {
        println!(
            ">>> [RESTORE] Found {} existing positions. Resuming monitors...",
            existing_positions.len()
        );
        for pos in existing_positions {
            // 恢复时也将 Token 加入锁，防止重复买入
            {
                let mut locks = processing_locks.lock().unwrap();
                locks.insert(pos.token_address);
            }
            println!("   -> Resuming monitor for {:?}", pos.token_address);
            let c = client.clone();
            let cfg = config.clone();
            task::spawn(monitor_position(
                c,
                pos.router_address,
                pos.token_address,
                pos.initial_cost_eth,
                cfg,
                processing_locks.clone(),
                None, // 恢复持仓时，如果是 Shadow Mode 且没有持久化虚拟余额，这里可能会直接退出，这是预期行为
                pos.fee.unwrap_or(0),
                None, // Persistence struct needs update to store PoolKey if we want to resume V4. For now None.
            ));
        }
    }

    let start_nonce = provider_arc
        .get_transaction_count(wallet.address(), None)
        .await?
        .as_u64();
    let nonce_manager = Arc::new(NonceManager::new(start_nonce));
    println!(">>> Initialized Nonce: {}", start_nonce);

    let (tx_sender, mut rx_receiver) = mpsc::channel::<Transaction>(10000);
    let mut stream = provider_arc.subscribe_blocks().await?;

    let p_clone = provider_arc.clone();
    let c_clone = client.clone();
    let cfg_clone = config.clone();
    let t_clone = targets.clone();
    let s_clone = simulator.clone();
    let n_clone = nonce_manager.clone();
    let l_clone = processing_locks.clone();

    task::spawn(async move {
        while let Some(tx) = rx_receiver.recv().await {
            let p = p_clone.clone();
            let c = c_clone.clone();
            let cfg = cfg_clone.clone();
            let t = t_clone.clone();
            let s = s_clone.clone();
            let n = n_clone.clone();
            let l = l_clone.clone();
            task::spawn(async move {
                process_transaction(tx, p, c, n, s, cfg, t, l).await;
            });
        }
    });

    let mut debug_heartbeat = 0; // [新增]

    while let Some(block) = stream.next().await {
        debug_heartbeat += 1;
        if debug_heartbeat % 10 == 0 {
            // 每 10 个块打印一次，让你知道它还活着
            if let Some(h) = block.hash {
                let hb_msg = format!("[HEARTBEAT] Still scanning... Latest Block: {:?}", h);
                println!(">>> {}", hb_msg);
            }
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
                                eprintln!("Channel error: {:?}", e);
                            }
                        }
                    }
                    Ok(None) => {
                        // 区块可能还没同步完（虽然很少见），忽略
                    }
                    Err(e) => {
                        eprintln!("Failed to fetch full block {:?}: {:?}", hash, e);
                    }
                }
            }
        });
    }

    Ok(())
}
