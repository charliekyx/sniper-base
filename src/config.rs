use serde::Deserialize;
use std::fs;
use ethers::types::Address;
use std::str::FromStr;

#[derive(Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub rpc_url: String,        // 你的 Reth 节点 WS 地址
    pub sniper_enabled: bool,   // 开关：狙击新币
    pub copy_trade_enabled: bool, // 开关：跟单大佬
    pub shadow_mode: bool,      // 核心开关：True = 只记录不发送
    pub target_wallets: Vec<String>, // 大佬白名单
    pub max_gas_gwei: u64,
}

impl AppConfig {
    pub fn load(path: &str) -> Self {
        let content = fs::read_to_string(path).expect("Failed to read config.json");
        serde_json::from_str(&content).expect("Failed to parse config json")
    }

    pub fn get_targets(&self) -> Vec<Address> {
        self.target_wallets
            .iter()
            .map(|s| Address::from_str(s).expect("Invalid address in config"))
            .collect()
    }
}