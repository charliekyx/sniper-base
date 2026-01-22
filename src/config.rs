use ethers::types::Address;
use std::env;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub rpc_url: String,
    pub private_key: String,
    pub sniper_enabled: bool,
    pub copy_trade_enabled: bool,
    pub copy_sell_enabled: bool,
    pub shadow_mode: bool,
    pub target_wallets: Vec<String>,

    // Node Config
    pub use_private_node: bool,

    // Capital & Gas
    pub buy_amount_eth: f64,
    pub gas_limit: u64,
    pub max_priority_fee_gwei: u64,

    // Strategy
    pub sniper_block_delay: u64,
    pub tp1_percent: u64,
    pub tp1_sell_pct: u64,
    pub tp2_percent: u64,
    pub tp2_sell_pct: u64,
    pub anti_rug_dip_threshold: u64,
    pub weekly_usdc_limit: f64,
    pub slippage_pct: u64,
}

impl AppConfig {
    pub fn from_env() -> Self {
        // Helper: get bool from env, default false
        let get_bool = |key: &str| -> bool {
            env::var(key)
                .unwrap_or_else(|_| "false".to_string())
                .to_lowercase()
                == "true"
        };

        // Helper: get u64 from env
        let get_u64 = |key: &str, default: u64| -> u64 {
            env::var(key)
                .map(|v| v.parse().unwrap_or(default))
                .unwrap_or(default)
        };

        // Helper: get f64 from env
        let get_f64 = |key: &str, default: f64| -> f64 {
            env::var(key)
                .map(|v| v.parse().unwrap_or(default))
                .unwrap_or(default)
        };

        // Helper: parse comma-separated list
        let get_vec = |key: &str| -> Vec<String> {
            env::var(key)
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };

        AppConfig {
            rpc_url: env::var("RPC_URL").expect("FATAL: RPC_URL must be set in env"),
            // If private key is not set, we might be in shadow mode or using random wallet
            private_key: env::var("PRIVATE_KEY").unwrap_or_else(|_| "".to_string()),

            sniper_enabled: get_bool("SNIPER_ENABLED"),
            copy_trade_enabled: get_bool("COPY_TRADE_ENABLED"),
            copy_sell_enabled: get_bool("COPY_SELL_ENABLED"),
            shadow_mode: get_bool("SHADOW_MODE"),
            use_private_node: get_bool("USE_PRIVATE_NODE"),

            target_wallets: get_vec("TARGET_WALLETS"),

            buy_amount_eth: get_f64("BUY_AMOUNT_ETH", 0.02),
            gas_limit: get_u64("GAS_LIMIT", 400000),
            max_priority_fee_gwei: get_u64("MAX_PRIORITY_FEE_GWEI", 3),

            sniper_block_delay: get_u64("SNIPER_BLOCK_DELAY", 2),
            tp1_percent: get_u64("TP1_PERCENT", 30), // 默认 +30% 利润
            tp1_sell_pct: get_u64("TP1_SELL_PCT", 50), // 默认卖出一半
            tp2_percent: get_u64("TP2_PERCENT", 80), // 默认 +80% 利润
            tp2_sell_pct: get_u64("TP2_SELL_PCT", 100), // 默认清仓
            anti_rug_dip_threshold: get_u64("ANTI_RUG_DIP_THRESHOLD", 50),
            weekly_usdc_limit: get_f64("WEEKLY_USDC_LIMIT", 1000.0),
            slippage_pct: get_u64("SLIPPAGE_PCT", 15),
        }
    }

    pub fn get_targets(&self) -> Vec<Address> {
        self.target_wallets
            .iter()
            .map(|s| Address::from_str(s).expect("Invalid address in TARGET_WALLETS env"))
            .collect()
    }
}
