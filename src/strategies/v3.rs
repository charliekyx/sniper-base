use crate::constants::*;
use crate::strategies::DexStrategy;
use anyhow::Result;
use ethers::abi::{Abi, Function, Param, ParamType, StateMutability, Token as AbiToken};
use ethers::prelude::*;

pub struct UniswapV3Strategy {
    pub router: Address,
    pub quoter: Address,
    pub fee: u32,
    pub name: String,
}

impl DexStrategy for UniswapV3Strategy {
    fn name(&self) -> &str {
        &self.name
    }
    fn fee(&self) -> u32 {
        self.fee
    }
    fn router(&self) -> Option<Address> {
        Some(self.router)
    }

    fn encode_quote(
        &self,
        amount_in: U256,
        token_in: Address,
        token_out: Address,
    ) -> Result<(Address, Bytes, U256)> {
        let params = (token_in, token_out, amount_in, self.fee, U256::zero());
        let data =
            BaseContract::from(v3_quoter_abi()).encode("quoteExactInputSingle", (params,))?;
        Ok((self.quoter, data.0.into(), U256::zero()))
    }

    fn decode_quote(&self, output: Bytes) -> Result<U256> {
        let (amount_out, _, _, _): (U256, U256, u32, U256) =
            BaseContract::from(v3_quoter_abi()).decode_output("quoteExactInputSingle", output)?;
        Ok(amount_out)
    }

    fn encode_buy(
        &self,
        amount_in: U256,
        token_out: Address,
        recipient: Address,
        _deadline: U256,
        amount_out_min: U256,
    ) -> Result<(Address, Bytes, U256)> {
        let params = AbiToken::Tuple(vec![
            AbiToken::Address(*WETH_BASE),
            AbiToken::Address(token_out),
            AbiToken::Uint(U256::from(self.fee)),
            AbiToken::Address(recipient),
            AbiToken::Uint(amount_in),
            AbiToken::Uint(amount_out_min),
            AbiToken::Uint(U256::zero()),
        ]);
        let abi = v3_router_abi();
        let func = abi.function("exactInputSingle")?;
        let data = func.encode_input(&[params])?;
        Ok((self.router, data.into(), amount_in))
    }

    fn encode_sell(
        &self,
        amount_in: U256,
        token_out: Address,
        recipient: Address,
        _deadline: U256,
        amount_out_min: U256,
    ) -> Result<(Address, Bytes, U256)> {
        let params = AbiToken::Tuple(vec![
            AbiToken::Address(token_out),
            AbiToken::Address(*WETH_BASE),
            AbiToken::Uint(U256::from(self.fee)),
            AbiToken::Address(recipient),
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

fn v3_quoter_abi() -> Abi {
    let mut abi = Abi::default();
    let v3_params_type = ParamType::Tuple(vec![
        ParamType::Address,
        ParamType::Address,
        ParamType::Uint(256),
        ParamType::Uint(24),
        ParamType::Uint(160),
    ]);
    let quote_func = Function {
        name: "quoteExactInputSingle".to_string(),
        inputs: vec![Param {
            name: "params".to_string(),
            kind: v3_params_type,
            internal_type: None,
        }],
        outputs: vec![
            Param {
                name: "amountOut".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
            Param {
                name: "sqrtPriceX96After".to_string(),
                kind: ParamType::Uint(160),
                internal_type: None,
            },
            Param {
                name: "initializedTicksCrossed".to_string(),
                kind: ParamType::Uint(32),
                internal_type: None,
            },
            Param {
                name: "gasEstimate".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
        ],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    };
    abi.functions
        .insert("quoteExactInputSingle".to_string(), vec![quote_func]);
    abi
}

fn v3_router_abi() -> Abi {
    let mut abi = Abi::default();
    let v3_swap_params_type = ParamType::Tuple(vec![
        ParamType::Address,   // tokenIn
        ParamType::Address,   // tokenOut
        ParamType::Uint(24),  // fee
        ParamType::Address,   // recipient
        ParamType::Uint(256), // amountIn
        ParamType::Uint(256), // amountOutMinimum
        ParamType::Uint(160), // sqrtPriceLimitX96
    ]);
    let swap_func = Function {
        name: "exactInputSingle".to_string(),
        inputs: vec![Param {
            name: "params".to_string(),
            kind: v3_swap_params_type,
            internal_type: None,
        }],
        outputs: vec![Param {
            name: "amountOut".to_string(),
            kind: ParamType::Uint(256),
            internal_type: None,
        }],
        constant: None,
        state_mutability: StateMutability::Payable,
    };
    abi.functions
        .insert("exactInputSingle".to_string(), vec![swap_func]);
    abi
}
