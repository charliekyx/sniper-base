use anyhow::Result;
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
    pub fee: Option<u32>, // Added for V3 support
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
    let _ = fs::remove_file(filename);
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
