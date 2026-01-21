use crate::constants::*;
use crate::decoder::PoolKey;
use crate::strategies::{DexStrategy, SimulationBehavior};
use anyhow::Result;
use ethers::abi::{Abi, Function, Param, ParamType, StateMutability, Token as AbiToken};
use ethers::prelude::*;

pub struct UniswapV4Strategy {
    pub pool_key: PoolKey,
    pub name: String,
}

impl DexStrategy for UniswapV4Strategy {
    fn name(&self) -> &str {
        &self.name
    }
    fn pool_key(&self) -> Option<PoolKey> {
        Some(self.pool_key)
    }
    fn fee(&self) -> u32 {
        self.pool_key.2
    }
    fn simulation_behavior(&self) -> SimulationBehavior {
        SimulationBehavior::QuoteOnly
    }

    fn encode_quote(
        &self,
        amount_in: U256,
        token_in: Address,
        token_out: Address,
    ) -> Result<(Address, Bytes, U256)> {
        let zero_for_one = token_in < token_out;
        let pk_token = AbiToken::Tuple(vec![
            AbiToken::Address(self.pool_key.0),
            AbiToken::Address(self.pool_key.1),
            AbiToken::Uint(U256::from(self.pool_key.2)),
            AbiToken::Int(U256::from(self.pool_key.3 as u32)),
            AbiToken::Address(self.pool_key.4),
        ]);
        let params = AbiToken::Tuple(vec![
            pk_token,
            AbiToken::Bool(zero_for_one),
            AbiToken::Uint(amount_in),
            AbiToken::Bytes(vec![]),
        ]);
        let abi = v4_quoter_abi();
        let func = abi.function("quoteExactInputSingle")?;
        let data = func.encode_input(&[params])?;
        Ok((*UNIV4_QUOTER, data.into(), U256::zero()))
    }

    fn decode_quote(&self, output: Bytes) -> Result<U256> {
        let (amount_out, _): (U256, u128) =
            BaseContract::from(v4_quoter_abi()).decode_output("quoteExactInputSingle", output)?;
        Ok(amount_out)
    }

    fn encode_buy(
        &self,
        amount_in: U256,
        token_out: Address,
        _recipient: Address,
        deadline: U256,
        amount_out_min: U256,
    ) -> Result<(Address, Bytes, U256)> {
        let zero_for_one = *WETH_BASE < token_out;
        let pk_token = AbiToken::Tuple(vec![
            AbiToken::Address(self.pool_key.0),
            AbiToken::Address(self.pool_key.1),
            AbiToken::Uint(U256::from(self.pool_key.2)),
            AbiToken::Int(U256::from(self.pool_key.3 as u32)),
            AbiToken::Address(self.pool_key.4),
        ]);
        let swap_params = ethers::abi::encode(&vec![
            pk_token,
            AbiToken::Bool(zero_for_one),
            AbiToken::Uint(amount_in),
            AbiToken::Uint(amount_out_min),
            AbiToken::Bytes(vec![]),
        ]);
        let actions = vec![0x06u8];
        let action_params = vec![AbiToken::Bytes(swap_params)];
        let v4_swap_input = ethers::abi::encode(&vec![
            AbiToken::Bytes(actions),
            AbiToken::Array(action_params),
        ]);
        let commands = vec![0x10u8];
        let inputs = vec![AbiToken::Bytes(v4_swap_input)];

        let data = BaseContract::from(universal_router_abi())
            .encode("execute", (Bytes::from(commands), inputs, deadline))?;
        Ok((*UNIVERSAL_ROUTER, data.0.into(), amount_in))
    }

    fn encode_sell(
        &self,
        amount_in: U256,
        token_out: Address,
        _recipient: Address,
        deadline: U256,
        amount_out_min: U256,
    ) -> Result<(Address, Bytes, U256)> {
        let zero_for_one = token_out < *WETH_BASE;
        let pk_token = AbiToken::Tuple(vec![
            AbiToken::Address(self.pool_key.0),
            AbiToken::Address(self.pool_key.1),
            AbiToken::Uint(U256::from(self.pool_key.2)),
            AbiToken::Int(U256::from(self.pool_key.3 as u32)),
            AbiToken::Address(self.pool_key.4),
        ]);
        let swap_params = ethers::abi::encode(&vec![
            pk_token,
            AbiToken::Bool(zero_for_one),
            AbiToken::Uint(amount_in),
            AbiToken::Uint(amount_out_min),
            AbiToken::Bytes(vec![]),
        ]);
        let actions = vec![0x06u8];
        let action_params = vec![AbiToken::Bytes(swap_params)];
        let v4_swap_input = ethers::abi::encode(&vec![
            AbiToken::Bytes(actions),
            AbiToken::Array(action_params),
        ]);
        let commands = vec![0x10u8];
        let inputs = vec![AbiToken::Bytes(v4_swap_input)];

        let data = BaseContract::from(universal_router_abi())
            .encode("execute", (Bytes::from(commands), inputs, deadline))?;
        Ok((*UNIVERSAL_ROUTER, data.0.into(), U256::zero()))
    }
}

fn v4_quoter_abi() -> Abi {
    let mut abi = Abi::default();
    let pk = ParamType::Tuple(vec![ParamType::Address, ParamType::Address, ParamType::Uint(24), ParamType::Int(24), ParamType::Address]);
    let params = ParamType::Tuple(vec![pk, ParamType::Bool, ParamType::Uint(128), ParamType::Bytes]);
    let func = Function {
        name: "quoteExactInputSingle".to_string(),
        inputs: vec![Param { name: "params".to_string(), kind: params, internal_type: None }],
        outputs: vec![
            Param { name: "amountOut".to_string(), kind: ParamType::Uint(256), internal_type: None },
            Param { name: "gasEstimate".to_string(), kind: ParamType::Uint(128), internal_type: None },
        ],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    };
    abi.functions.insert("quoteExactInputSingle".to_string(), vec![func]);
    abi
}

fn universal_router_abi() -> Abi {
    let mut abi = Abi::default();
    let execute = Function {
        name: "execute".to_string(),
        inputs: vec![Param { name: "commands".to_string(), kind: ParamType::Bytes, internal_type: None }, Param { name: "inputs".to_string(), kind: ParamType::Array(Box::new(ParamType::Bytes)), internal_type: None }, Param { name: "deadline".to_string(), kind: ParamType::Uint(256), internal_type: None }],
        outputs: vec![], constant: None, state_mutability: StateMutability::Payable,
    };
    abi.functions.insert("execute".to_string(), vec![execute]);
    abi
}