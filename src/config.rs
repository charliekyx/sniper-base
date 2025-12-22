use serde::Deserialize;
use std::fs;
use ethers::types::Address;
use std::str::FromStr;

#[derive(Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub rpc_url: String,
    pub private_key: String,       // 必填：用于实战交易
    pub sniper_enabled: bool,
    pub copy_trade_enabled: bool,
    pub shadow_mode: bool,         // true = 模拟运行; false = 真钱交易
    pub target_wallets: Vec<String>,
    
    // --- 资金与 Gas ---
    pub buy_amount_eth: f64,       // 单次狙击金额 (ETH)
    pub gas_limit: u64,            // 交易 Gas 上限 (防死循环/高耗费)
    pub max_priority_fee_gwei: u64,// 贿赂矿工的小费
    
    // --- 防御与策略 ---
    pub sniper_block_delay: u64,   // 延迟 N 个区块买入 (防开盘黑名单陷阱)
    pub sell_strategy_2x_exit_half: bool, // 翻倍出本 (卖 50%)
    pub sell_strategy_3x_exit_all: bool,  // 3倍清仓 (卖 100%)
    pub anti_rug_dip_threshold: u64,      // 跌幅止损阈值 (例如 50 表示跌 50% 跑路)
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