use ethers::types::Address;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::str::FromStr;

lazy_static! {
    pub static ref WETH_BASE: Address = Address::from_str("0x4200000000000000000000000000000000000006").unwrap();

    // Router Addresses
    pub static ref BASESWAP_ROUTER: Address = Address::from_str("0x2948acbbc8795267e62a1220683a48e718b52585").unwrap();
    pub static ref ALIENBASE_ROUTER: Address = Address::from_str("0x8c1A3cF8f83074169FE5D7aD50B978e1cd6b37c7").unwrap();
    pub static ref UNIV3_ROUTER: Address = Address::from_str("0x2626664c2603336E57B271c5C0b26F421741e481").unwrap();
    pub static ref UNIV3_QUOTER: Address = Address::from_str("0x3d4e44Eb1374240CE5F1B871ab261CD16335B76a").unwrap();
    pub static ref AERODROME_ROUTER: Address = Address::from_str("0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43").unwrap();

    // Uniswap V4 (Base)
    pub static ref UNIV4_POOL_MANAGER: Address = Address::from_str("0x498581fF718922c3f8e6A244956aF099B2652b2b").unwrap();
    pub static ref UNIV4_QUOTER: Address = Address::from_str("0x0d5e0f971ed27fbff6c2837bf31316121532048d").unwrap();

    pub static ref AERODROME_FACTORY: Address = Address::from_str("0x420DD381b31aEf6683db6B902084cB0FFECe40Da").unwrap();
    pub static ref SUSHI_ROUTER: Address = Address::from_str("0x6BDED42c6DA8FBf0d2bA55B2fa120C5e0c8D7891").unwrap();
    pub static ref ONEINCH_ROUTER: Address = Address::from_str("0x1111111254fb6c44bac0bed2854e76f90643097d").unwrap();
    pub static ref ODOS_ROUTER: Address = Address::from_str("0x8d0d118070b728e104294471fbe93c2e3affd694").unwrap();
    // Base Chain Universal Router
    pub static ref UNIVERSAL_ROUTER: Address = Address::from_str("0x743f2f29cdd66242fb27d292ab2cc92f45674635").unwrap();
    // deBridge Gate
    pub static ref DEBRIDGE_ROUTER: Address = Address::from_str("0x663dc15d3c1ac63ff12e45ab68fea3f0a883c251").unwrap();

    // High performance lookup map
    pub static ref ROUTER_NAMES: HashMap<Address, String> = {
        let mut m = HashMap::new();
        m.insert(*BASESWAP_ROUTER, "BaseSwap".to_string());
        m.insert(*ALIENBASE_ROUTER, "AlienBase".to_string());
        m.insert(*UNIV3_ROUTER, "UniV3".to_string());
        m.insert(*AERODROME_ROUTER, "Aerodrome".to_string());
        m.insert(*SUSHI_ROUTER, "SushiSwap".to_string());
        m.insert(*ONEINCH_ROUTER, "1inch".to_string());
        m.insert(*ODOS_ROUTER, "Odos".to_string());
        m.insert(*UNIVERSAL_ROUTER, "UniversalRouter".to_string());
        m.insert(*DEBRIDGE_ROUTER, "deBridge".to_string());
        m
    };
}

pub fn get_router_name(addr: &Address) -> String {
    ROUTER_NAMES
        .get(addr)
        .cloned()
        .unwrap_or_else(|| "Unknown".to_string())
}
