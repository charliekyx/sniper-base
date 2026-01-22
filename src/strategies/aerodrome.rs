use crate::strategies::DexStrategy;
use anyhow::Result;
use ethers::abi::{Abi, Function, Param, ParamType, StateMutability};
use ethers::prelude::*;

pub struct AerodromeV2Strategy {
    pub router: Address,
    pub factory: Address,
    pub path: Vec<Address>,
    pub name: String,
}

impl DexStrategy for AerodromeV2Strategy {
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
        _token_out: Address,
    ) -> Result<(Address, Bytes, U256)> {
        let path = if token_in == self.path[0] {
            self.path.clone()
        } else {
            let mut p = self.path.clone();
            p.reverse();
            p
        };
        let mut routes = Vec::new();
        for i in 0..path.len() - 1 {
            routes.push((path[i], path[i + 1], false, self.factory));
        }
        let data = BaseContract::from(aero_abi()).encode("getAmountsOut", (amount_in, routes))?;
        Ok((self.router, data.0.into(), U256::zero()))
    }

    fn decode_quote(&self, output: Bytes) -> Result<U256> {
        let amounts: Vec<U256> =
            BaseContract::from(aero_abi()).decode_output("getAmountsOut", output)?;
        Ok(*amounts.last().unwrap_or(&U256::zero()))
    }

    fn encode_buy(
        &self,
        amount_in: U256,
        _token_out: Address,
        recipient: Address,
        deadline: U256,
        amount_out_min: U256,
    ) -> Result<(Address, Bytes, U256)> {
        let mut routes = Vec::new();
        for i in 0..self.path.len() - 1 {
            routes.push((self.path[i], self.path[i + 1], false, self.factory));
        }
        let data = BaseContract::from(aero_abi()).encode(
            "swapExactETHForTokensSupportingFeeOnTransferTokens",
            (amount_out_min, routes, recipient, deadline),
        )?;
        Ok((self.router, data.0.into(), amount_in))
    }

    fn encode_sell(
        &self,
        amount_in: U256,
        _token_out: Address,
        recipient: Address,
        deadline: U256,
        amount_out_min: U256,
    ) -> Result<(Address, Bytes, U256)> {
        let mut reversed_path = self.path.clone();
        reversed_path.reverse();
        let mut routes = Vec::new();
        for i in 0..reversed_path.len() - 1 {
            routes.push((reversed_path[i], reversed_path[i + 1], false, self.factory));
        }
        let data = BaseContract::from(aero_abi()).encode(
            "swapExactTokensForETHSupportingFeeOnTransferTokens",
            (amount_in, amount_out_min, routes, recipient, deadline),
        )?;
        Ok((self.router, data.0.into(), U256::zero()))
    }
}

fn aero_abi() -> Abi {
    let mut abi = Abi::default();
    let route_type = ParamType::Tuple(vec![
        ParamType::Address,
        ParamType::Address,
        ParamType::Bool,
        ParamType::Address,
    ]);
    let get_out = Function {
        name: "getAmountsOut".to_string(),
        inputs: vec![
            Param {
                name: "amountIn".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
            Param {
                name: "routes".to_string(),
                kind: ParamType::Array(Box::new(route_type.clone())),
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
                name: "routes".to_string(),
                kind: ParamType::Array(Box::new(route_type.clone())),
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
                name: "routes".to_string(),
                kind: ParamType::Array(Box::new(route_type)),
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
        .insert("getAmountsOut".to_string(), vec![get_out]);
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
