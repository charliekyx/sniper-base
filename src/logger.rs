use serde::Serialize;
use std::fs::OpenOptions;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct ShadowRecord {
    pub timestamp: String,
    pub event_type: String,     // e.g., "Buy_ETH->Token"
    pub router: String,         // e.g., "BaseSwap"
    pub trigger_hash: String,   // Tx Hash that triggered the sniper
    pub token_address: String,
    pub amount_in_eth: String,
    pub simulation_result: String, // e.g., "Profitable", "Honeypot"
    pub profit_eth_after_sell: Option<String>, // Estimated profit if sold immediately
    pub gas_used: u64,
    pub copy_target: Option<String>,
}

pub fn log_shadow_trade(record: ShadowRecord) {
    // Print to console for real-time monitoring
    println!("[SHADOW] {} | {} | {} | Res: {}", 
        record.timestamp, 
        record.event_type, 
        record.token_address, 
        record.simulation_result
    );

    // Save to CSV for analysis
    let file_path = "shadow_trades.csv";
    let file_exists = Path::new(file_path).exists();

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path);

    match file {
        Ok(f) => {
            let mut wtr = csv::WriterBuilder::new()
                .has_headers(!file_exists)
                .from_writer(f);

            if let Err(e) = wtr.serialize(&record) {
                eprintln!("[LOGGER ERROR] Failed to serialize record: {:?}", e);
            }
            
            if let Err(e) = wtr.flush() {
                eprintln!("[LOGGER ERROR] Failed to flush CSV writer: {:?}", e);
            }
        }
        Err(e) => {
            eprintln!("[LOGGER ERROR] Failed to open shadow_trades.csv: {:?}", e);
        }
    }
}