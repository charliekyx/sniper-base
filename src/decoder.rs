use crate::constants::WETH_BASE;
use ethers::abi::ParamType;
use ethers::types::{Address, Bytes, U256};

// PoolKey: (currency0, currency1, fee, tickSpacing, hooks)
pub type PoolKey = (Address, Address, u32, i32, Address);

pub fn extract_pool_key_from_universal_router(input: &[u8]) -> Option<PoolKey> {
    // Universal Router execute signatures:
    // 0x3593564c: execute(bytes commands, bytes[] inputs)
    // 0xcae6a6b3: execute(bytes commands, bytes[] inputs, uint256 deadline)
    if input.len() < 4 {
        return None;
    }
    let selector = &input[0..4];

    // Determine param types based on selector
    let param_types = if selector == [0x35, 0x93, 0x56, 0x4c] {
        vec![
            ParamType::Bytes,
            ParamType::Array(Box::new(ParamType::Bytes)),
        ]
    } else if selector == [0xca, 0xe6, 0xa6, 0xb3] {
        vec![
            ParamType::Bytes,
            ParamType::Array(Box::new(ParamType::Bytes)),
            ParamType::Uint(256), // deadline
        ]
    } else {
        return None;
    };

    let decoded = ethers::abi::decode(&param_types, &input[4..]).ok()?;

    let commands: Vec<u8> = decoded[0].clone().into_bytes()?;
    let inputs: Vec<Bytes> = decoded[1]
        .clone()
        .into_array()?
        .into_iter()
        .map(|t| Bytes::from(t.into_bytes().unwrap()))
        .collect();

    // Command 0x10 is V4_SWAP
    for (i, &cmd) in commands.iter().enumerate() {
        if cmd == 0x10 && i < inputs.len() {
            let param_bytes = &inputs[i];
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

                    let whole_struct = ethers::abi::ParamType::Tuple(params_type);
                    let decoded = ethers::abi::decode(&[whole_struct], p).ok()?;
                    let struct_tuple = decoded[0].clone().into_tuple()?;
                    let pk_tuple = struct_tuple[0].clone().into_tuple()?;

                    let c0 = pk_tuple[0].clone().into_address()?;
                    let c1 = pk_tuple[1].clone().into_address()?;
                    let fee = pk_tuple[2].clone().into_uint()?.low_u32();
                    let ts = pk_tuple[3].clone().into_int()?.low_u32() as i32;
                    let hooks = pk_tuple[4].clone().into_address()?;

                    return Some((c0, c1, fee, ts, hooks));
                }
            }
        }
    }
    None
}

pub fn decode_router_input(input: &[u8]) -> Option<(String, Address)> {
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
    }
    // [新增] Virtuals Protocol Support
    // buy(address token, uint256 amountIn, uint256 minAmountOut) -> 0xf69ac97a
    else if sig == [0xf6, 0x9a, 0xc9, 0x7a] {
        return read_address(4).map(|t| ("Buy_Virtuals".to_string(), t));
    }
    // sell(address token, uint256 amountIn, uint256 minAmountOut) -> 0x831e10eb
    else if sig == [0x83, 0x1e, 0x10, 0xeb] {
        return read_address(4).map(|t| ("Sell_Virtuals".to_string(), t));
    }
    // [新增] Aerodrome V2 Support (Solidly Fork)
    // swapExactETHForTokensSupportingFeeOnTransferTokens(uint256 amountOutMin, Route[] routes, address to, uint256 deadline)
    // Selector: 0x7bf17d05
    else if sig == [0x7b, 0xf1, 0x7d, 0x05] {
        // 参数布局:
        // 0: amountOutMin
        // 1: offset to routes (usually 0x80 / 128)
        // 2: to (recipient)
        // 3: deadline
        let routes_offset = read_usize(36)?;
        let len_ptr = 4 + routes_offset;
        let routes_len = read_usize(len_ptr)?;
        if routes_len == 0 {
            return None;
        }
        // Route Struct: (address from, address to, bool stable, address factory)
        // 每个 Struct 占用 4 * 32 = 128 bytes (ABI 静态编码)
        // 我们需要最后一个 Route 的 'to' 字段 (即最终买入的 Token)
        // 最后一个 Route 的起始位置
        let last_route_start = len_ptr + 32 + (routes_len - 1) * 128;
        // 'to' 是结构体的第 2 个字段 (offset 32)
        return read_address(last_route_start + 32).map(|t| ("Buy_Aerodrome".to_string(), t));
    }
    // swapExactTokensForETHSupportingFeeOnTransferTokens(uint256 amountIn, uint256 amountOutMin, Route[] routes, address to, uint256 deadline)
    // Selector: 0x45013492
    else if sig == [0x45, 0x01, 0x34, 0x92] {
        // 卖出操作，Token In 是第一个 Route 的 'from'
        let routes_offset = read_usize(68)?; // 第3个参数
        let len_ptr = 4 + routes_offset;
        // 第一个 Route 的起始位置 = len_ptr + 32
        // 'from' 是结构体的第 1 个字段 (offset 0)
        return read_address(len_ptr + 32).map(|t| ("Sell_Aerodrome".to_string(), t));
    }
    // ... (Simplified for brevity, full logic from main.rs should be here if needed, but sticking to provided context logic)
    // Note: The original code had more branches (Odos, V3, Universal). I will include them to be safe.
    else if sig == [0x38, 0xed, 0x17, 0x39] || sig == [0x5c, 0x11, 0xd7, 0x95] {
        return get_path_token(2, true).map(|t| ("Swap_Token->Token".to_string(), t));
    } else if sig == [0xf3, 0x05, 0xd7, 0x19] {
        return read_address(4).map(|t| ("AddLiquidity".to_string(), t));
    } else if sig == [0xd1, 0xee, 0x21, 0x1d] || sig == [0x0f, 0x27, 0xc5, 0xc1] {
        let offset_ptr = 4;
        let path_offset = read_usize(offset_ptr)?;
        let len_ptr = 4 + path_offset;
        let path_len = read_usize(len_ptr)?;
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
            if token_out != *WETH_BASE && token_out != Address::zero() {
                return Some(("Swap_Odos".to_string(), token_out));
            }
            return Some(("Sell_Odos".to_string(), token_in));
        }
    } else if sig == [0x41, 0x4b, 0xf3, 0x89] || sig == [0x04, 0xe4, 0x5a, 0xaf] {
        // 0x414bf389: exactInputSingle (Old Router)
        // 0x04e45aaf: exactInputSingle (New SwapRouter02)
        // 两个版本的 tokenOut 都在结构体的第二个位置 (offset 32)，可以直接复用
        return read_address(36).map(|t| ("Buy_V3_Single".to_string(), t));
    } else if sig == [0xc0, 0x4b, 0x8d, 0x59] || sig == [0xb8, 0x58, 0x18, 0x3f] {
        // 0xc04b8d59: exactInput (Old Router)
        // 0xb858183f: exactInput (New SwapRouter02)
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
    } else if sig == [0xac, 0x96, 0x50, 0xd8] {
        // Uniswap V3 Multicall(bytes[] data)
        // 这是一个包装器，通常包含 swap。为了简单起见，我们标记它，具体的代币解析可能需要递归解码
        return Some(("Multicall_V3".to_string(), Address::zero()));
    } else if sig == [0xca, 0xe6, 0xa6, 0xb3] || sig == [0x35, 0x93, 0x56, 0x4c] {
        return Some(("Universal_Interaction".to_string(), Address::zero()));
    }
    None
}

/// 解析 EVM Revert 原因，提供更友好的报错信息
pub fn decode_revert_reason(output: &[u8]) -> String {
    if output.len() < 4 {
        return "Revert(NoData)".to_string();
    }
    let selector = &output[0..4];

    // 1. Error(string) selector: 0x08c379a0
    if selector == [0x08, 0xc3, 0x79, 0xa0] {
        if let Ok(decoded) = ethers::abi::decode(&[ParamType::String], &output[4..]) {
            if let Some(reason) = decoded[0].clone().into_string() {
                return format!("Revert: {}", reason);
            }
        }
    }
    // 2. Panic(uint256) selector: 0x4e487b71
    // 优化：将 Panic 代码转换为可读的错误描述
    else if selector == [0x4e, 0x48, 0x7b, 0x71] {
        if let Ok(decoded) = ethers::abi::decode(&[ParamType::Uint(256)], &output[4..]) {
            let code = decoded[0].clone().into_uint().unwrap_or_default().as_u64();
            let reason = match code {
                0x01 => "Assertion failed",
                0x11 => "Arithmetic overflow/underflow",
                0x12 => "Division by zero",
                0x21 => "Enum index out of bounds",
                0x22 => "Storage byte array incorrectly encoded",
                0x31 => "Pop on empty array",
                0x32 => "Array index out of bounds",
                0x41 => "Memory allocation too large",
                0x51 => "Zero-initialized internal function",
                _ => "Unknown Panic",
            };
            return format!("Panic(0x{:02x}): {}", code, reason);
        }
    }
    // 3. V4 QuoteFailure(bytes) selector: 0x6190b2b0
    else if selector == [0x61, 0x90, 0xb2, 0xb0] {
        if let Ok(decoded) = ethers::abi::decode(&[ParamType::Bytes], &output[4..]) {
            if let Some(inner_bytes) = decoded[0].clone().into_bytes() {
                if inner_bytes.len() >= 4 {
                    let inner_sig = &inner_bytes[0..4];
                    // PoolNotInitialized selector: 0x86aa3070
                    if inner_sig == [0x86, 0xaa, 0x30, 0x70] {
                        return "Revert: PoolNotInitialized (V4)".to_string();
                    }
                    // Clanker V4 custom error (0x486aa307)
                    if inner_sig == [0x48, 0x6a, 0xa3, 0x07] {
                        return "Revert: V4 Pool Not Found (486aa307)".to_string();
                    }
                    // Another V4 error (0x90bfb865)
                    if inner_sig == [0x90, 0xbf, 0xb8, 0x65] {
                        return "Revert: V4 Pool Not Found (90bfb865)".to_string();
                    }
                }
                return format!("Revert(V4): {}", ethers::utils::hex::encode(inner_bytes));
            }
        }
    }

    format!("Revert(Hex): {}", ethers::utils::hex::encode(output))
}
