use anyhow::Result;
use chrono::Local;
use ethers::types::{Address, U256};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::BufReader;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PositionData {
    pub token_address: Address,
    pub router_address: Address,
    pub initial_cost_eth: U256,
    pub timestamp: u64,
    pub fee: Option<u32>, // Fee Tier, 费率层级，Added for V3 support
    #[serde(default)]
    pub leader_wallet: Option<Address>, // 记录带单的钱包地址
}

pub fn init_storage() {
    let _ = fs::create_dir_all("positions");
}

pub fn save_position(data: &PositionData) -> Result<()> {
    let filename = format!("positions/{:?}.json", data.token_address);
    let file = File::create(filename)?;
    serde_json::to_writer_pretty(file, data)?;
    Ok(())
}

pub fn remove_position(token_address: Address) {
    let filename = format!("positions/{:?}.json", token_address);
    let archive_dir = "positions/archive";
    let _ = fs::create_dir_all(archive_dir);

    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let archive_filename = format!("{}/{:?}_{}.json", archive_dir, token_address, timestamp);
    let _ = fs::rename(filename, archive_filename);
}

pub fn load_all_positions() -> Vec<PositionData> {
    let mut positions = Vec::new();
    if let Ok(entries) = fs::read_dir("positions") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(file) = File::open(&path) {
                    let reader = BufReader::new(file);
                    if let Ok(pos) = serde_json::from_reader(reader) {
                        positions.push(pos);
                    }
                }
            }
        }
    }
    positions
}
