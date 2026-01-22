use crate::constants::*;
use crate::strategies::DexStrategy;
use anyhow::Result;
use ethers::abi::{Abi, Function, Param, ParamType, StateMutability};
use ethers::prelude::*;

pub struct VirtualsStrategy {
    pub name: String,
}

impl DexStrategy for VirtualsStrategy {
    fn name(&self) -> &str {
        &self.name
    }
    fn quote_requires_commit(&self) -> bool {
        true
    }
    fn router(&self) -> Option<Address> {
        Some(*VIRTUALS_FACTORY_ROUTER)
    }

    fn encode_quote(
        &self,
        amount_in: U256,
        token_in: Address,
        token_out: Address,
    ) -> Result<(Address, Bytes, U256)> {
        if token_in == *WETH_BASE {
            let data = BaseContract::from(virtuals_abi())
                .encode("buy", (token_out, amount_in, U256::zero()))?;
            Ok((*VIRTUALS_FACTORY_ROUTER, data.0.into(), amount_in))
        } else {
            let data =
                BaseContract::from(virtuals_abi()).encode("getSellPrice", (token_in, amount_in))?;
            Ok((*VIRTUALS_FACTORY_ROUTER, data.0.into(), U256::zero()))
        }
    }

    fn decode_quote(&self, output: Bytes) -> Result<U256> {
        let amount_out: U256 = BaseContract::from(virtuals_abi()).decode_output("buy", output)?;
        Ok(amount_out)
    }

    fn encode_buy(
        &self,
        amount_in: U256,
        token_out: Address,
        _recipient: Address,
        _deadline: U256,
        amount_out_min: U256,
    ) -> Result<(Address, Bytes, U256)> {
        let data = BaseContract::from(virtuals_abi())
            .encode("buy", (token_out, amount_in, amount_out_min))?;
        Ok((*VIRTUALS_FACTORY_ROUTER, data.0.into(), amount_in))
    }

    fn encode_sell(
        &self,
        amount_in: U256,
        token_out: Address,
        _recipient: Address,
        _deadline: U256,
        _amount_out_min: U256,
    ) -> Result<(Address, Bytes, U256)> {
        let data = BaseContract::from(virtuals_abi())
            .encode("sell", (token_out, amount_in, U256::zero()))?;
        Ok((*VIRTUALS_FACTORY_ROUTER, data.0.into(), U256::zero()))
    }
}

fn virtuals_abi() -> Abi {
    let mut abi = Abi::default();
    let buy = Function {
        name: "buy".to_string(),
        inputs: vec![
            Param {
                name: "token".to_string(),
                kind: ParamType::Address,
                internal_type: None,
            },
            Param {
                name: "amountIn".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
            Param {
                name: "minAmountOut".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
        ],
        outputs: vec![Param {
            name: "amountOut".to_string(),
            kind: ParamType::Uint(256),
            internal_type: None,
        }],
        constant: None,
        state_mutability: StateMutability::Payable,
    };
    let get_sell_price = Function {
        name: "getSellPrice".to_string(),
        inputs: vec![
            Param {
                name: "token".to_string(),
                kind: ParamType::Address,
                internal_type: None,
            },
            Param {
                name: "amount".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
        ],
        outputs: vec![Param {
            name: "price".to_string(),
            kind: ParamType::Uint(256),
            internal_type: None,
        }],
        constant: Some(true),
        state_mutability: StateMutability::View,
    };
    abi.functions.insert("buy".to_string(), vec![buy]);
    abi.functions
        .insert("getSellPrice".to_string(), vec![get_sell_price]);
    abi
}
