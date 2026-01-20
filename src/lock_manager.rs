use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use ethers::types::Address;

#[derive(Clone, Debug, Default)]
pub struct LockManager {
    locks: Arc<Mutex<HashSet<Address>>>,
}

impl LockManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// 尝试对代币加锁。如果代币已锁定，返回 false；否则加锁并返回 true。
    pub fn try_lock(&self, token: Address) -> bool {
        let mut locks = self.locks.lock().unwrap();
        if locks.contains(&token) {
            false
        } else {
            locks.insert(token);
            true
        }
    }

    /// 强制加锁，通常用于程序启动恢复持仓时。
    pub fn lock(&self, token: Address) {
        let mut locks = self.locks.lock().unwrap();
        locks.insert(token);
    }

    /// 释放代币锁。
    pub fn unlock(&self, token: Address) {
        if let Ok(mut locks) = self.locks.lock() {
            locks.remove(&token);
        }
    }
}