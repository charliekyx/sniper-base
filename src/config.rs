use serde::Deserialize;
use std::fs;
use ethers::types::Address;
use std::str::FromStr;

#[derive(Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub rpc_url: String,
    pub private_key: String,
    pub sniper_enabled: bool,
    pub copy_trade_enabled: bool,
    pub shadow_mode: bool,
    pub target_wallets: Vec<String>,
    
    // Node Configuration
    // Set to true since you have a self-built node
    pub use_private_node: bool, 
    
    // Capital & Gas Strategy (Optimized for 500 SGD / ~0.11 ETH)
    // Recommended: buy_amount_eth = 0.02 or 0.03
    pub buy_amount_eth: f64,       
    // Recommended: 300000 - 400000
    pub gas_limit: u64,            
    // Recommended: 2 - 5 Gwei (Keep it low to preserve capital)
    pub max_priority_fee_gwei: u64,
    
    // Protection Strategy
    pub sniper_block_delay: u64,
    pub sell_strategy_2x_exit_half: bool,
    pub sell_strategy_3x_exit_all: bool,
    pub anti_rug_dip_threshold: u64,
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