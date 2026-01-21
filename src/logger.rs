use chrono;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use tracing::{error, info};

#[derive(Debug, Serialize)]
pub struct ShadowRecord {
    pub timestamp: String,
    pub event_type: String,   // e.g., "Buy_ETH->Token"
    pub router: String,       // e.g., "BaseSwap"
    pub trigger_hash: String, // Tx Hash that triggered the sniper
    pub token_address: String,
    pub amount_in_eth: String,
    pub simulation_result: String, // e.g., "Profitable", "Honeypot"
    pub profit_eth_after_sell: Option<String>, // Estimated profit if sold immediately
    pub gas_used: u64,
    pub copy_target: Option<String>,
}

pub fn log_to_file(msg: String) {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let log_line = format!("[{}] {}\n", timestamp, msg);

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("app.log") {
        let _ = file.write_all(log_line.as_bytes());
    }
}

pub fn log_shadow_trade(record: ShadowRecord) {
    // Print to console for real-time monitoring
    info!(
        "[SHADOW] {} | {} | {} | Res: {}",
        record.timestamp, record.event_type, record.token_address, record.simulation_result
    );

    log_to_file(format!(
        "[SHADOW] {} | {} | Res: {}",
        record.event_type, record.token_address, record.simulation_result
    ));

    // Save to CSV for analysis
    let file_path = "shadow_trades.csv";
    let file_exists = Path::new(file_path).exists();

    let file = OpenOptions::new().create(true).append(true).open(file_path);

    match file {
        Ok(f) => {
            let mut wtr = csv::WriterBuilder::new()
                .has_headers(!file_exists)
                .from_writer(f);

            if let Err(e) = wtr.serialize(&record) {
                error!("[LOGGER ERROR] Failed to serialize record: {:?}", e);
            }

            if let Err(e) = wtr.flush() {
                error!("[LOGGER ERROR] Failed to flush CSV writer: {:?}", e);
            }
        }
        Err(e) => {
            error!("[LOGGER ERROR] Failed to open shadow_trades.csv: {:?}", e);
        }
    }
}

pub fn log_shadow_sell(token: String, initial_eth: String, final_eth: String, strategy: String) {
    let initial: f64 = initial_eth.parse().unwrap_or(0.0);
    let final_val: f64 = final_eth.parse().unwrap_or(0.0);
    let profit = final_val - initial;
    let roi = if initial > 0.0 {
        (profit / initial) * 100.0
    } else {
        0.0
    };

    info!(
        "[SHADOW EXIT] Token: {} | Result: {} ETH ({:.2}%) | Strategy: {}",
        token, profit, roi, strategy
    );

    log_to_file(format!(
        "[SHADOW EXIT] Token: {} | Result: {} ETH ({:.2}%) | Strategy: {}",
        token, profit, roi, strategy
    ));

    // 简单追加到另一个文件方便统计
    let file_path = "shadow_results.csv";
    let file_exists = std::path::Path::new(file_path).exists();
    if let Ok(f) = OpenOptions::new().create(true).append(true).open(file_path) {
        let mut wtr = csv::WriterBuilder::new()
            .has_headers(!file_exists)
            .from_writer(f);
        let _ = wtr.write_record(&[
            chrono::Local::now().to_rfc3339(),
            token,
            initial_eth,
            final_eth,
            profit.to_string(),
            format!("{:.2}%", roi),
            strategy,
        ]);
        let _ = wtr.flush();
    }
}
