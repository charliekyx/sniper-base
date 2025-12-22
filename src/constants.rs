use ethers::types::Address;
use std::str::FromStr;
use lazy_static::lazy_static;

lazy_static! {
    // Base 链的 WETH (不同于 ETH 主网!)
    pub static ref WETH_BASE: Address = Address::from_str("0x4200000000000000000000000000000000000006").unwrap();
    
    // BaseSwap V2 Router
    pub static ref BASESWAP_ROUTER: Address = Address::from_str("0x2948acbbc8795267e62a1220683a48e718b52585").unwrap();
    
    // AlienBase V2 Router
    pub static ref ALIENBASE_ROUTER: Address = Address::from_str("0x8c1A3cF8f83074169FE5D7aD50B978e1cd6b37c7").unwrap();
    
    // Uniswap V3 Router (Base)
    pub static ref UNIV3_ROUTER: Address = Address::from_str("0x2626664c2603336E57B271c5C0b26F421741e481").unwrap();
}

pub fn get_router_name(addr: &Address) -> String {
    if *addr == *BASESWAP_ROUTER {
        "BaseSwap".to_string()
    } else if *addr == *ALIENBASE_ROUTER {
        "AlienBase".to_string()
    } else if *addr == *UNIV3_ROUTER {
        "UniV3".to_string()
    } else {
        "Unknown".to_string()
    }
}