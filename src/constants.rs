use ethers::types::Address;
use std::str::FromStr;
use lazy_static::lazy_static;

lazy_static! {
    // Base Chain WETH
    pub static ref WETH_BASE: Address = Address::from_str("0x4200000000000000000000000000000000000006").unwrap();
    
    // --- Major DEX Routers on Base ---
    
    // 1. BaseSwap V2 (你原本有的)
    pub static ref BASESWAP_ROUTER: Address = Address::from_str("0x2948acbbc8795267e62a1220683a48e718b52585").unwrap();
    
    // 2. AlienBase V2 (你原本有的)
    pub static ref ALIENBASE_ROUTER: Address = Address::from_str("0x8c1A3cF8f83074169FE5D7aD50B978e1cd6b37c7").unwrap();
    
    // 3. Uniswap V3 (你原本有的)
    pub static ref UNIV3_ROUTER: Address = Address::from_str("0x2626664c2603336E57B271c5C0b26F421741e481").unwrap();

    // 4. Aerodrome (必须加！Base 链的老大)
    // 这是 Aerodrome V1 Router，目前绝大多数土狗和普通 Swap 都在这里
    pub static ref AERODROME_ROUTER: Address = Address::from_str("0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43").unwrap();

    // 5. SushiSwap V2 (Base) - 偶尔有土狗
    pub static ref SUSHI_ROUTER: Address = Address::from_str("0x6BDED42c6DA8FBf0d2bA55B2fa120C5e0c8D7891").unwrap();

    // 6. 1inch Aggregator (很多聪明钱用这个，很难解析但值得标记)
    pub static ref ONEINCH_ROUTER: Address = Address::from_str("0x1111111254fb6c44bac0bed2854e76f90643097d").unwrap();
}

pub fn get_router_name(addr: &Address) -> String {
    if *addr == *BASESWAP_ROUTER {
        "BaseSwap".to_string()
    } else if *addr == *ALIENBASE_ROUTER {
        "AlienBase".to_string()
    } else if *addr == *UNIV3_ROUTER {
        "UniV3".to_string()
    } else if *addr == *AERODROME_ROUTER {
        "Aerodrome".to_string()
    } else if *addr == *SUSHI_ROUTER {
        "SushiSwap".to_string()
    } else if *addr == *ONEINCH_ROUTER {
        "1inch".to_string()
    } else {
        "Unknown".to_string()
    }
}