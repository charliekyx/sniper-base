use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use chrono::Local;

#[derive(Serialize, Debug)]
pub struct ShadowRecord {
    pub timestamp: String,
    pub event_type: String, // "Sniper" or "CopyTrade"
    pub router: String,
    pub trigger_hash: String,
    pub token_address: String,
    pub amount_in_eth: String,
    pub simulation_result: String, // "Success" or "Revert"
    pub profit_eth_after_sell: Option<String>,
    pub gas_used: u64,
    pub copy_target: Option<String>,
}

pub fn log_shadow_trade(record: ShadowRecord) {
    let file_path = "shadow_trades.jsonl";
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)
        .unwrap();

    if let Ok(json) = serde_json::to_string(&record) {
        let _ = writeln!(file, "{}", json);
        println!("   [Log Saved] {}", record.trigger_hash);
    }
}