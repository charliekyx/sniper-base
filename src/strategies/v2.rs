use crate::constants::*;
use crate::strategies::DexStrategy;
use anyhow::Result;
use ethers::abi::{Abi, Function, Param, ParamType, StateMutability};
use ethers::prelude::*;

pub struct UniswapV2Strategy {
    pub router: Address,
    pub name: String,
}

impl DexStrategy for UniswapV2Strategy {
    fn name(&self) -> &str {
        &self.name
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
        let path = vec![token_in, token_out];
        let data = BaseContract::from(v2_abi()).encode("getAmountsOut", (amount_in, path))?;
        Ok((self.router, data.0.into(), U256::zero()))
    }

    fn decode_quote(&self, output: Bytes) -> Result<U256> {
        let amounts: Vec<U256> =
            BaseContract::from(v2_abi()).decode_output("getAmountsOut", output)?;
        Ok(*amounts.last().unwrap_or(&U256::zero()))
    }

    fn encode_buy(
        &self,
        amount_in: U256,
        token_out: Address,
        recipient: Address,
        deadline: U256,
        amount_out_min: U256,
    ) -> Result<(Address, Bytes, U256)> {
        let path = vec![*WETH_BASE, token_out];
        let data = BaseContract::from(v2_abi()).encode(
            "swapExactETHForTokensSupportingFeeOnTransferTokens",
            (amount_out_min, path, recipient, deadline),
        )?;
        Ok((self.router, data.0.into(), amount_in))
    }

    fn encode_sell(
        &self,
        amount_in: U256,
        token_out: Address,
        recipient: Address,
        deadline: U256,
        amount_out_min: U256,
    ) -> Result<(Address, Bytes, U256)> {
        let path = vec![token_out, *WETH_BASE];
        let data = BaseContract::from(v2_abi()).encode(
            "swapExactTokensForETHSupportingFeeOnTransferTokens",
            (amount_in, amount_out_min, path, recipient, deadline),
        )?;
        Ok((self.router, data.0.into(), U256::zero()))
    }
}

fn v2_abi() -> Abi {
    let mut abi = Abi::default();
    let get_amounts_out = Function {
        name: "getAmountsOut".to_string(),
        inputs: vec![
            Param {
                name: "amountIn".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
            Param {
                name: "path".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Address)),
                internal_type: None,
            },
        ],
        outputs: vec![Param {
            name: "amounts".to_string(),
            kind: ParamType::Array(Box::new(ParamType::Uint(256))),
            internal_type: None,
        }],
        constant: Some(true),
        state_mutability: StateMutability::View,
    };
    let swap_eth = Function {
        name: "swapExactETHForTokensSupportingFeeOnTransferTokens".to_string(),
        inputs: vec![
            Param {
                name: "amountOutMin".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
            Param {
                name: "path".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Address)),
                internal_type: None,
            },
            Param {
                name: "to".to_string(),
                kind: ParamType::Address,
                internal_type: None,
            },
            Param {
                name: "deadline".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
        ],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::Payable,
    };
    let swap_tokens = Function {
        name: "swapExactTokensForETHSupportingFeeOnTransferTokens".to_string(),
        inputs: vec![
            Param {
                name: "amountIn".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
            Param {
                name: "amountOutMin".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
            Param {
                name: "path".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Address)),
                internal_type: None,
            },
            Param {
                name: "to".to_string(),
                kind: ParamType::Address,
                internal_type: None,
            },
            Param {
                name: "deadline".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
        ],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    };
    abi.functions
        .insert("getAmountsOut".to_string(), vec![get_amounts_out]);
    abi.functions.insert(
        "swapExactETHForTokensSupportingFeeOnTransferTokens".to_string(),
        vec![swap_eth],
    );
    abi.functions.insert(
        "swapExactTokensForETHSupportingFeeOnTransferTokens".to_string(),
        vec![swap_tokens],
    );
    abi
}
