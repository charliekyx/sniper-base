#![allow(dead_code)]
#![allow(deprecated)]

use anyhow::Result;
use ethers::prelude::*;
use crate::constants::*;
use crate::decoder::PoolKey;
use ethers::abi::{Abi, Function, Param, ParamType, StateMutability, Token as AbiToken};

/// 定义所有 DEX 协议必须遵循的标准接口
pub trait DexStrategy: Send + Sync {
    fn name(&self) -> &str;
    
    /// 返回 (目标合约地址, 调用数据, 发送的 ETH 金额) 用于获取报价 (支持 token_in -> token_out)
    fn encode_quote(&self, amount_in: U256, token_in: Address, token_out: Address) -> Result<(Address, Bytes, U256)>;
    
    /// 解码报价返回的原始字节，得到预期的 Token 数量
    fn decode_quote(&self, output: Bytes) -> Result<U256>;

    /// 返回 (目标合约地址, 调用数据, 发送的 ETH 金额) 用于执行买入
    fn encode_buy(&self, amount_in: U256, token_out: Address, recipient: Address, deadline: U256, amount_out_min: U256) -> Result<(Address, Bytes, U256)>;

    /// 返回 (目标合约地址, 调用数据, 发送的 ETH 金额) 用于执行卖出
    fn encode_sell(&self, amount_in: U256, token_out: Address, recipient: Address, deadline: U256, amount_out_min: U256) -> Result<(Address, Bytes, U256)>;
    
    /// 报价是否需要 commit 状态（大多数是 View，但有些如 Virtuals 需要模拟执行）
    fn quote_requires_commit(&self) -> bool { false }

    // 用于持久化存储的元数据
    fn fee(&self) -> u32 { 0 }
    fn pool_key(&self) -> Option<PoolKey> { None }
}

// =========================================================================
// 示例实现：Uniswap V2 策略
// =========================================================================
pub struct UniswapV2Strategy {
    pub router: Address,
    pub name: String,
}

impl DexStrategy for UniswapV2Strategy {
    fn name(&self) -> &str { &self.name }

    fn encode_quote(&self, amount_in: U256, token_in: Address, token_out: Address) -> Result<(Address, Bytes, U256)> {
        let path = vec![token_in, token_out];
        let data = BaseContract::from(v2_abi()).encode("getAmountsOut", (amount_in, path))?;
        Ok((self.router, data.0.into(), U256::zero()))
    }

    fn decode_quote(&self, output: Bytes) -> Result<U256> {
        let amounts: Vec<U256> = BaseContract::from(v2_abi()).decode_output("getAmountsOut", output)?;
        Ok(*amounts.last().unwrap_or(&U256::zero()))
    }

    fn encode_buy(&self, amount_in: U256, token_out: Address, recipient: Address, deadline: U256, amount_out_min: U256) -> Result<(Address, Bytes, U256)> {
        let path = vec![*WETH_BASE, token_out];
        let data = BaseContract::from(v2_abi()).encode("swapExactETHForTokensSupportingFeeOnTransferTokens", (amount_out_min, path, recipient, deadline))?;
        Ok((self.router, data.0.into(), amount_in))
    }

    fn encode_sell(&self, amount_in: U256, token_out: Address, recipient: Address, deadline: U256, amount_out_min: U256) -> Result<(Address, Bytes, U256)> {
        let path = vec![token_out, *WETH_BASE];
        let data = BaseContract::from(v2_abi()).encode("swapExactTokensForETHSupportingFeeOnTransferTokens", (amount_in, amount_out_min, path, recipient, deadline))?;
        Ok((self.router, data.0.into(), U256::zero()))
    }
}

// =========================================================================
// 示例实现：Aerodrome V2 策略 (支持自定义路径)
// =========================================================================
pub struct AerodromeV2Strategy {
    pub router: Address,
    pub factory: Address,
    pub path: Vec<Address>,
    pub name: String,
}

impl DexStrategy for AerodromeV2Strategy {
    fn name(&self) -> &str { &self.name }

    fn encode_quote(&self, amount_in: U256, token_in: Address, _token_out: Address) -> Result<(Address, Bytes, U256)> {
        let path = if token_in == self.path[0] {
            self.path.clone()
        } else {
            let mut p = self.path.clone();
            p.reverse();
            p
        };
        let mut routes = Vec::new();
        for i in 0..path.len() - 1 {
            routes.push((path[i], path[i+1], false, self.factory));
        }
        let data = BaseContract::from(aero_abi()).encode("getAmountsOut", (amount_in, routes))?;
        Ok((self.router, data.0.into(), U256::zero()))
    }

    fn decode_quote(&self, output: Bytes) -> Result<U256> {
        let amounts: Vec<U256> = BaseContract::from(aero_abi()).decode_output("getAmountsOut", output)?;
        Ok(*amounts.last().unwrap_or(&U256::zero()))
    }

    fn encode_buy(&self, amount_in: U256, _token_out: Address, recipient: Address, deadline: U256, amount_out_min: U256) -> Result<(Address, Bytes, U256)> {
        let mut routes = Vec::new();
        for i in 0..self.path.len() - 1 {
            routes.push((self.path[i], self.path[i+1], false, self.factory));
        }
        let data = BaseContract::from(aero_abi()).encode("swapExactETHForTokensSupportingFeeOnTransferTokens", (amount_out_min, routes, recipient, deadline))?;
        Ok((self.router, data.0.into(), amount_in))
    }

    fn encode_sell(&self, amount_in: U256, _token_out: Address, recipient: Address, deadline: U256, amount_out_min: U256) -> Result<(Address, Bytes, U256)> {
        let mut reversed_path = self.path.clone();
        reversed_path.reverse();
        let mut routes = Vec::new();
        for i in 0..reversed_path.len() - 1 {
            routes.push((reversed_path[i], reversed_path[i+1], false, self.factory));
        }
        let data = BaseContract::from(aero_abi()).encode("swapExactTokensForETHSupportingFeeOnTransferTokens", (amount_in, amount_out_min, routes, recipient, deadline))?;
        Ok((self.router, data.0.into(), U256::zero()))
    }
}

// =========================================================================
// 示例实现：Uniswap V4 策略
// =========================================================================
pub struct UniswapV4Strategy {
    pub pool_key: PoolKey,
    pub name: String,
}

impl DexStrategy for UniswapV4Strategy {
    fn name(&self) -> &str { &self.name }
    fn pool_key(&self) -> Option<PoolKey> { Some(self.pool_key) }
    fn fee(&self) -> u32 { self.pool_key.2 }

    fn encode_quote(&self, amount_in: U256, token_in: Address, token_out: Address) -> Result<(Address, Bytes, U256)> {
        let zero_for_one = token_in < token_out;
        let pk_token = AbiToken::Tuple(vec![
            AbiToken::Address(self.pool_key.0),
            AbiToken::Address(self.pool_key.1),
            AbiToken::Uint(U256::from(self.pool_key.2)),
            AbiToken::Int(U256::from(self.pool_key.3 as u32)),
            AbiToken::Address(self.pool_key.4),
        ]);
        let params = AbiToken::Tuple(vec![pk_token, AbiToken::Bool(zero_for_one), AbiToken::Uint(amount_in), AbiToken::Bytes(vec![])]);
        let abi = v4_quoter_abi();
        let func = abi.function("quoteExactInputSingle")?;
        let data = func.encode_input(&[params])?;
        Ok((*UNIV4_QUOTER, data.into(), U256::zero()))
    }

    fn decode_quote(&self, output: Bytes) -> Result<U256> {
        let (amount_out, _): (U256, u128) = BaseContract::from(v4_quoter_abi()).decode_output("quoteExactInputSingle", output)?;
        Ok(amount_out)
    }

    fn encode_buy(&self, amount_in: U256, token_out: Address, _recipient: Address, deadline: U256, amount_out_min: U256) -> Result<(Address, Bytes, U256)> {
        let zero_for_one = *WETH_BASE < token_out;
        let pk_token = AbiToken::Tuple(vec![
            AbiToken::Address(self.pool_key.0),
            AbiToken::Address(self.pool_key.1),
            AbiToken::Uint(U256::from(self.pool_key.2)),
            AbiToken::Int(U256::from(self.pool_key.3 as u32)),
            AbiToken::Address(self.pool_key.4),
        ]);
        let swap_params = ethers::abi::encode(&vec![pk_token, AbiToken::Bool(zero_for_one), AbiToken::Uint(amount_in), AbiToken::Uint(amount_out_min), AbiToken::Bytes(vec![])]);
        let actions = vec![0x06u8];
        let action_params = vec![AbiToken::Bytes(swap_params)];
        let v4_swap_input = ethers::abi::encode(&vec![AbiToken::Bytes(actions), AbiToken::Array(action_params)]);
        let commands = vec![0x10u8];
        let inputs = vec![AbiToken::Bytes(v4_swap_input)];
        
        let data = BaseContract::from(universal_router_abi()).encode("execute", (Bytes::from(commands), inputs, deadline))?;
        Ok((*UNIVERSAL_ROUTER, data.0.into(), amount_in))
    }

    fn encode_sell(&self, amount_in: U256, token_out: Address, _recipient: Address, deadline: U256, amount_out_min: U256) -> Result<(Address, Bytes, U256)> {
        let zero_for_one = token_out < *WETH_BASE;
        let pk_token = AbiToken::Tuple(vec![
            AbiToken::Address(self.pool_key.0),
            AbiToken::Address(self.pool_key.1),
            AbiToken::Uint(U256::from(self.pool_key.2)),
            AbiToken::Int(U256::from(self.pool_key.3 as u32)),
            AbiToken::Address(self.pool_key.4),
        ]);
        let swap_params = ethers::abi::encode(&vec![pk_token, AbiToken::Bool(zero_for_one), AbiToken::Uint(amount_in), AbiToken::Uint(amount_out_min), AbiToken::Bytes(vec![])]);
        let actions = vec![0x06u8];
        let action_params = vec![AbiToken::Bytes(swap_params)];
        let v4_swap_input = ethers::abi::encode(&vec![AbiToken::Bytes(actions), AbiToken::Array(action_params)]);
        let commands = vec![0x10u8];
        let inputs = vec![AbiToken::Bytes(v4_swap_input)];
        
        let data = BaseContract::from(universal_router_abi()).encode("execute", (Bytes::from(commands), inputs, deadline))?;
        Ok((*UNIVERSAL_ROUTER, data.0.into(), U256::zero()))
    }
}

// =========================================================================
// 示例实现：Virtuals Protocol 策略
// =========================================================================
pub struct VirtualsStrategy {
    pub name: String,
}

impl DexStrategy for VirtualsStrategy {
    fn name(&self) -> &str { &self.name }
    fn quote_requires_commit(&self) -> bool { true }

    fn encode_quote(&self, amount_in: U256, token_in: Address, token_out: Address) -> Result<(Address, Bytes, U256)> {
        if token_in == *WETH_BASE {
            let data = BaseContract::from(virtuals_abi()).encode("buy", (token_out, amount_in, U256::zero()))?;
            Ok((*VIRTUALS_FACTORY_ROUTER, data.0.into(), amount_in))
        } else {
            let data = BaseContract::from(virtuals_abi()).encode("getSellPrice", (token_in, amount_in))?;
            Ok((*VIRTUALS_FACTORY_ROUTER, data.0.into(), U256::zero()))
        }
    }

    fn decode_quote(&self, output: Bytes) -> Result<U256> {
        let amount_out: U256 = BaseContract::from(virtuals_abi()).decode_output("buy", output)?;
        Ok(amount_out)
    }

    fn encode_buy(&self, amount_in: U256, token_out: Address, _recipient: Address, _deadline: U256, amount_out_min: U256) -> Result<(Address, Bytes, U256)> {
        let data = BaseContract::from(virtuals_abi()).encode("buy", (token_out, amount_in, amount_out_min))?;
        Ok((*VIRTUALS_FACTORY_ROUTER, data.0.into(), amount_in))
    }

    fn encode_sell(&self, amount_in: U256, token_out: Address, _recipient: Address, _deadline: U256, _amount_out_min: U256) -> Result<(Address, Bytes, U256)> {
        let data = BaseContract::from(virtuals_abi()).encode("sell", (token_out, amount_in, U256::zero()))?;
        Ok((*VIRTUALS_FACTORY_ROUTER, data.0.into(), U256::zero()))
    }
}

// =========================================================================
// 示例实现：Uniswap V3 策略 (固定费率)
// =========================================================================
pub struct UniswapV3Strategy {
    pub router: Address,
    pub quoter: Address,
    pub fee: u32,
    pub name: String,
}

impl DexStrategy for UniswapV3Strategy {
    fn name(&self) -> &str { &self.name }
    fn fee(&self) -> u32 { self.fee }

    fn encode_quote(&self, amount_in: U256, token_in: Address, token_out: Address) -> Result<(Address, Bytes, U256)> {
        let params = (token_in, token_out, amount_in, self.fee, U256::zero());
        let data = BaseContract::from(v3_quoter_abi()).encode("quoteExactInputSingle", (params,))?;
        Ok((self.quoter, data.0.into(), U256::zero()))
    }

    fn decode_quote(&self, output: Bytes) -> Result<U256> {
        let (amount_out, _, _, _): (U256, U256, u32, U256) = BaseContract::from(v3_quoter_abi()).decode_output("quoteExactInputSingle", output)?;
        Ok(amount_out)
    }

    fn encode_buy(&self, amount_in: U256, token_out: Address, recipient: Address, _deadline: U256, amount_out_min: U256) -> Result<(Address, Bytes, U256)> {
        let params = AbiToken::Tuple(vec![
            AbiToken::Address(*WETH_BASE),
            AbiToken::Address(token_out),
            AbiToken::Uint(U256::from(self.fee)),
            AbiToken::Address(recipient),
            AbiToken::Uint(_deadline),
            AbiToken::Uint(amount_in),
            AbiToken::Uint(amount_out_min),
            AbiToken::Uint(U256::zero()),
        ]);
        let abi = v3_router_abi();
        let func = abi.function("exactInputSingle")?;
        let data = func.encode_input(&[params])?;
        Ok((self.router, data.into(), amount_in))
    }

    fn encode_sell(&self, amount_in: U256, token_out: Address, recipient: Address, _deadline: U256, amount_out_min: U256) -> Result<(Address, Bytes, U256)> {
        let params = AbiToken::Tuple(vec![
            AbiToken::Address(token_out),
            AbiToken::Address(*WETH_BASE),
            AbiToken::Uint(U256::from(self.fee)),
            AbiToken::Address(recipient),
            AbiToken::Uint(_deadline),
            AbiToken::Uint(amount_in),
            AbiToken::Uint(amount_out_min),
            AbiToken::Uint(U256::zero()),
        ]);
        let abi = v3_router_abi();
        let func = abi.function("exactInputSingle")?;
        let data = func.encode_input(&[params])?;
        Ok((self.router, data.into(), U256::zero()))
    }
}

/// 根据持久化的 PositionData 恢复策略对象
pub fn get_strategy_for_position(router: Address, fee: u32, token: Address) -> Box<dyn DexStrategy> {
    if router == *UNIV3_ROUTER || router == *PANCAKESWAP_V3_ROUTER || router == *AERO_V3_ROUTER {
        let quoter = if router == *PANCAKESWAP_V3_ROUTER { *PANCAKESWAP_V3_QUOTER } 
                    else if router == *AERO_V3_ROUTER { *AERO_V3_QUOTER } 
                    else { *UNIV3_QUOTER };
        Box::new(UniswapV3Strategy { router, quoter, fee, name: format!("Restored V3 ({})", fee) })
    } else if router == *VIRTUALS_FACTORY_ROUTER {
        Box::new(VirtualsStrategy { name: "Restored Virtuals".into() })
    } else if router == *VIRTUALS_ROUTER {
        Box::new(AerodromeV2Strategy { router: *AERODROME_ROUTER, factory: *AERODROME_FACTORY, path: vec![*WETH_BASE, *VIRTUALS_ROUTER, token], name: "Restored Virtuals Hop".into() })
    } else if router == *AERODROME_ROUTER {
        Box::new(AerodromeV2Strategy { router, factory: *AERODROME_FACTORY, path: vec![token, *WETH_BASE], name: "Restored Aero V2".into() })
    } else {
        Box::new(UniswapV2Strategy { router, name: "Restored V2".into() })
    }
}

// =========================================================================
// 辅助 ABI 构建函数 (保持代码整洁)
// =========================================================================
fn v2_abi() -> Abi {
    let mut abi = Abi::default();
    let get_amounts_out = Function {
        name: "getAmountsOut".to_string(),
        inputs: vec![Param { name: "amountIn".to_string(), kind: ParamType::Uint(256), internal_type: None }, Param { name: "path".to_string(), kind: ParamType::Array(Box::new(ParamType::Address)), internal_type: None }],
        outputs: vec![Param { name: "amounts".to_string(), kind: ParamType::Array(Box::new(ParamType::Uint(256))), internal_type: None }],
        constant: Some(true),
        state_mutability: StateMutability::View,
    };
    let swap_eth = Function {
        name: "swapExactETHForTokensSupportingFeeOnTransferTokens".to_string(),
        inputs: vec![Param { name: "amountOutMin".to_string(), kind: ParamType::Uint(256), internal_type: None }, Param { name: "path".to_string(), kind: ParamType::Array(Box::new(ParamType::Address)), internal_type: None }, Param { name: "to".to_string(), kind: ParamType::Address, internal_type: None }, Param { name: "deadline".to_string(), kind: ParamType::Uint(256), internal_type: None }],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::Payable,
    };
    let swap_tokens = Function {
        name: "swapExactTokensForETHSupportingFeeOnTransferTokens".to_string(),
        inputs: vec![Param { name: "amountIn".to_string(), kind: ParamType::Uint(256), internal_type: None }, Param { name: "amountOutMin".to_string(), kind: ParamType::Uint(256), internal_type: None }, Param { name: "path".to_string(), kind: ParamType::Array(Box::new(ParamType::Address)), internal_type: None }, Param { name: "to".to_string(), kind: ParamType::Address, internal_type: None }, Param { name: "deadline".to_string(), kind: ParamType::Uint(256), internal_type: None }],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    };
    abi.functions.insert("getAmountsOut".to_string(), vec![get_amounts_out]);
    abi.functions.insert("swapExactETHForTokensSupportingFeeOnTransferTokens".to_string(), vec![swap_eth]);
    abi.functions.insert("swapExactTokensForETHSupportingFeeOnTransferTokens".to_string(), vec![swap_tokens]);
    abi
}

fn universal_router_abi() -> Abi {
    let mut abi = Abi::default();
    let execute = Function {
        name: "execute".to_string(),
        inputs: vec![Param { name: "commands".to_string(), kind: ParamType::Bytes, internal_type: None }, Param { name: "inputs".to_string(), kind: ParamType::Array(Box::new(ParamType::Bytes)), internal_type: None }, Param { name: "deadline".to_string(), kind: ParamType::Uint(256), internal_type: None }],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::Payable,
    };
    abi.functions.insert("execute".to_string(), vec![execute]);
    abi
}

fn v3_quoter_abi() -> Abi {
    let mut abi = Abi::default();
    let v3_params_type = ParamType::Tuple(vec![ParamType::Address, ParamType::Address, ParamType::Uint(256), ParamType::Uint(24), ParamType::Uint(160)]);
    let quote_func = Function {
        name: "quoteExactInputSingle".to_string(),
        inputs: vec![Param { name: "params".to_string(), kind: v3_params_type, internal_type: None }],
        outputs: vec![Param { name: "amountOut".to_string(), kind: ParamType::Uint(256), internal_type: None }, Param { name: "sqrtPriceX96After".to_string(), kind: ParamType::Uint(160), internal_type: None }, Param { name: "initializedTicksCrossed".to_string(), kind: ParamType::Uint(32), internal_type: None }, Param { name: "gasEstimate".to_string(), kind: ParamType::Uint(256), internal_type: None }],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    };
    abi.functions.insert("quoteExactInputSingle".to_string(), vec![quote_func]);
    abi
}

fn v3_router_abi() -> Abi {
    let mut abi = Abi::default();
    let v3_swap_params_type = ParamType::Tuple(vec![ParamType::Address, ParamType::Address, ParamType::Uint(24), ParamType::Address, ParamType::Uint(256), ParamType::Uint(256), ParamType::Uint(256), ParamType::Uint(160)]);
    let swap_func = Function {
        name: "exactInputSingle".to_string(),
        inputs: vec![Param { name: "params".to_string(), kind: v3_swap_params_type, internal_type: None }],
        outputs: vec![Param { name: "amountOut".to_string(), kind: ParamType::Uint(256), internal_type: None }],
        constant: None,
        state_mutability: StateMutability::Payable,
    };
    abi.functions.insert("exactInputSingle".to_string(), vec![swap_func]);
    abi
}

fn aero_abi() -> Abi {
    let mut abi = Abi::default();
    let route_type = ParamType::Tuple(vec![ParamType::Address, ParamType::Address, ParamType::Bool, ParamType::Address]);
    let get_out = Function {
        name: "getAmountsOut".to_string(),
        inputs: vec![Param { name: "amountIn".to_string(), kind: ParamType::Uint(256), internal_type: None }, Param { name: "routes".to_string(), kind: ParamType::Array(Box::new(route_type.clone())), internal_type: None }],
        outputs: vec![Param { name: "amounts".to_string(), kind: ParamType::Array(Box::new(ParamType::Uint(256))), internal_type: None }],
        constant: Some(true),
        state_mutability: StateMutability::View,
    };
    let swap_eth = Function {
        name: "swapExactETHForTokensSupportingFeeOnTransferTokens".to_string(),
        inputs: vec![Param { name: "amountOutMin".to_string(), kind: ParamType::Uint(256), internal_type: None }, Param { name: "routes".to_string(), kind: ParamType::Array(Box::new(route_type.clone())), internal_type: None }, Param { name: "to".to_string(), kind: ParamType::Address, internal_type: None }, Param { name: "deadline".to_string(), kind: ParamType::Uint(256), internal_type: None }],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::Payable,
    };
    let swap_tokens = Function {
        name: "swapExactTokensForETHSupportingFeeOnTransferTokens".to_string(),
        inputs: vec![Param { name: "amountIn".to_string(), kind: ParamType::Uint(256), internal_type: None }, Param { name: "amountOutMin".to_string(), kind: ParamType::Uint(256), internal_type: None }, Param { name: "routes".to_string(), kind: ParamType::Array(Box::new(route_type)), internal_type: None }, Param { name: "to".to_string(), kind: ParamType::Address, internal_type: None }, Param { name: "deadline".to_string(), kind: ParamType::Uint(256), internal_type: None }],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    };
    abi.functions.insert("getAmountsOut".to_string(), vec![get_out]);
    abi.functions.insert("swapExactETHForTokensSupportingFeeOnTransferTokens".to_string(), vec![swap_eth]);
    abi.functions.insert("swapExactTokensForETHSupportingFeeOnTransferTokens".to_string(), vec![swap_tokens]);
    abi
}

fn v4_quoter_abi() -> Abi {
    let mut abi = Abi::default();
    let pk = ParamType::Tuple(vec![ParamType::Address, ParamType::Address, ParamType::Uint(24), ParamType::Int(24), ParamType::Address]);
    let params = ParamType::Tuple(vec![pk, ParamType::Bool, ParamType::Uint(128), ParamType::Bytes]);
    let func = Function {
        name: "quoteExactInputSingle".to_string(),
        inputs: vec![Param { name: "params".to_string(), kind: params, internal_type: None }],
        outputs: vec![Param { name: "amountOut".to_string(), kind: ParamType::Uint(256), internal_type: None }, Param { name: "gasEstimate".to_string(), kind: ParamType::Uint(128), internal_type: None }],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    };
    abi.functions.insert("quoteExactInputSingle".to_string(), vec![func]);
    abi
}

fn virtuals_abi() -> Abi {
    let mut abi = Abi::default();
    let buy = Function {
        name: "buy".to_string(),
        inputs: vec![Param { name: "token".to_string(), kind: ParamType::Address, internal_type: None }, Param { name: "amountIn".to_string(), kind: ParamType::Uint(256), internal_type: None }, Param { name: "minAmountOut".to_string(), kind: ParamType::Uint(256), internal_type: None }],
        outputs: vec![Param { name: "amountOut".to_string(), kind: ParamType::Uint(256), internal_type: None }],
        constant: None,
        state_mutability: StateMutability::Payable,
    };
    abi.functions.insert("buy".to_string(), vec![buy]);
    let get_sell_price = Function {
        name: "getSellPrice".to_string(),
        inputs: vec![Param { name: "token".to_string(), kind: ParamType::Address, internal_type: None }, Param { name: "amount".to_string(), kind: ParamType::Uint(256), internal_type: None }],
        outputs: vec![Param { name: "price".to_string(), kind: ParamType::Uint(256), internal_type: None }],
        constant: Some(true),
        state_mutability: StateMutability::View,
    };
    abi.functions.insert("getSellPrice".to_string(), vec![get_sell_price]);
    abi
}