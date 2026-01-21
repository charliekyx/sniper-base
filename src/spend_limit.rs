use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc, Duration};

#[derive(Serialize, Deserialize, Clone)]
pub struct SpendEntry {
    pub timestamp: DateTime<Utc>,
    pub usdc_amount: f64,
}

pub struct SpendLimitManager {
    file_path: String,
    entries: Arc<Mutex<Vec<SpendEntry>>>,
}

impl SpendLimitManager {
    pub fn new(file_path: &str) -> Self {
        let entries = if let Ok(data) = fs::read_to_string(file_path) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            Vec::new()
        };
        Self {
            file_path: file_path.to_string(),
            entries: Arc::new(Mutex::new(entries)),
        }
    }

    pub fn get_weekly_total(&self) -> f64 {
        let entries = self.entries.lock().unwrap();
        let one_week_ago = Utc::now() - Duration::days(7);
        entries
            .iter()
            .filter(|e| e.timestamp > one_week_ago)
            .map(|e| e.usdc_amount)
            .sum()
    }

    pub fn add_spend(&self, amount: f64) {
        let mut entries = self.entries.lock().unwrap();
        entries.push(SpendEntry {
            timestamp: Utc::now(),
            usdc_amount: amount,
        });
        let _ = fs::write(&self.file_path, serde_json::to_string(&*entries).unwrap_or_default());
    }
}