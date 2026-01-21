use ethers::types::U256;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;

pub struct NonceManager {
    nonce: AtomicU64,
}

impl NonceManager {
    pub fn new(start_nonce: u64) -> Self {
        Self {
            nonce: AtomicU64::new(start_nonce),
        }
    }

    pub fn get_and_increment(&self) -> U256 {
        let n = self.nonce.fetch_add(1, Ordering::SeqCst);
        U256::from(n)
    }

    pub fn reset(&self, new_nonce: u64) {
        self.nonce.store(new_nonce, Ordering::SeqCst);
        info!("[NONCE] Resynced to {}", new_nonce);
    }
}