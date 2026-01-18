use ethers::types::Address;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::str::FromStr;

// todo: Virtuals Protocol：Base 链上目前非常火的 Virtuals 协议，它们不使用 Uniswap/Aerodrome，而是有自己的内部池子。你的机器人目前不支持 Virtuals
lazy_static! {
    pub static ref WETH_BASE: Address = Address::from_str("0x4200000000000000000000000000000000000006").unwrap();

    // Router Addresses
    pub static ref BASESWAP_ROUTER: Address = Address::from_str("0x2948acbbc8795267e62a1220683a48e718b52585").unwrap();
    pub static ref ALIENBASE_ROUTER: Address = Address::from_str("0x8c1A3cF8f83074169FE5D7aD50B978e1cd6b37c7").unwrap();
    pub static ref UNIV3_ROUTER: Address = Address::from_str("0x2626664c2603336E57B271c5C0b26F421741e481").unwrap();
    pub static ref UNIV3_QUOTER: Address = Address::from_str("0x3d4e44Eb1374240CE5F1B871ab261CD16335B76a").unwrap();
    pub static ref AERODROME_ROUTER: Address = Address::from_str("0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43").unwrap();
    // PancakeSwap V3 (Base)
    pub static ref PANCAKESWAP_V3_ROUTER: Address = Address::from_str("0x1b81D678ffb9C0263b24A97847620C99d213eB14").unwrap();
    pub static ref PANCAKESWAP_V3_QUOTER: Address = Address::from_str("0xB048Bbc1Ee6b733FFfCFb9e9CeF7375518e25997").unwrap();

    // Uniswap V4 (Base)
    pub static ref UNIV4_POOL_MANAGER: Address = Address::from_str("0x498581fF718922c3f8e6A244956aF099B2652b2b").unwrap();
    pub static ref UNIV4_QUOTER: Address = Address::from_str("0x0d5e0f971ed27fbff6c2837bf31316121532048d").unwrap();
    // [Updated] Clanker V4.1 Hooks (Base)
    // Static Fee Hook (Most common, usually 1%)
    pub static ref CLANKER_HOOK_STATIC: Address = Address::from_str("0xb429d62f8f3bFFb98CdB9569533eA23bF0Ba28CC").unwrap();
    // Dynamic Fee Hook (Fee flag 0x800000)
    pub static ref CLANKER_HOOK_DYNAMIC: Address = Address::from_str("0xd60D6B218116cFd801E28F78d011a203D2b068Cc").unwrap();
    // [New] Clanker V4.0 Hooks (Legacy/Fallback)
    pub static ref CLANKER_HOOK_STATIC_V4_0: Address = Address::from_str("0xDd5EeaFf7BD481AD55Db083062b13a3cdf0A68CC").unwrap();
    pub static ref CLANKER_HOOK_DYNAMIC_V4_0: Address = Address::from_str("0x34a45c6B61876d739400Bd71228CbcbD4F53E8cC").unwrap();

    pub static ref AERODROME_FACTORY: Address = Address::from_str("0x420DD381b31aEf6683db6B902084cB0FFECe40Da").unwrap();
    pub static ref SUSHI_ROUTER: Address = Address::from_str("0x6BDED42c6DA8FBf0d2bA55B2fa120C5e0c8D7891").unwrap();
    pub static ref ONEINCH_ROUTER: Address = Address::from_str("0x1111111254fb6c44bac0bed2854e76f90643097d").unwrap();
    pub static ref ODOS_ROUTER: Address = Address::from_str("0x8d0d118070b728e104294471fbe93c2e3affd694").unwrap();
    // Base Chain Universal Router
    pub static ref UNIVERSAL_ROUTER: Address = Address::from_str("0x743f2f29cdd66242fb27d292ab2cc92f45674635").unwrap();
    // deBridge Gate
    pub static ref DEBRIDGE_ROUTER: Address = Address::from_str("0x663dc15d3c1ac63ff12e45ab68fea3f0a883c251").unwrap();
    // SwapBased Router (Base)
    pub static ref SWAPBASED_ROUTER: Address = Address::from_str("0xaaa3b1F1bd7BCc97fD1917c18ade665C5D31F066").unwrap();
    // RocketSwap Router (Base)
    pub static ref ROCKETSWAP_ROUTER: Address = Address::from_str("0x4cf76043B3f97ba06917cBd90F9e3A2AFcd1aCd0").unwrap();
    // Virtuals Protocol (Base) - Agent Factory / Router
    pub static ref VIRTUALS_ROUTER: Address = Address::from_str("0x15e7903697e4d6D4498002967974657C6377077B").unwrap();

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
        m.insert(*SWAPBASED_ROUTER, "SwapBased".to_string());
        m.insert(*ROCKETSWAP_ROUTER, "RocketSwap".to_string());
        m.insert(*PANCAKESWAP_V3_ROUTER, "PancakeSwapV3".to_string());
        m.insert(*VIRTUALS_ROUTER, "VirtualsProtocol".to_string());
        m
    };
}

pub fn get_router_name(addr: &Address) -> String {
    ROUTER_NAMES
        .get(addr)
        .cloned()
        .unwrap_or_else(|| "Unknown".to_string())
}
