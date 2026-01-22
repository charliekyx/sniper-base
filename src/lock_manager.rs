use ethers::types::Address;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Default)]
pub struct LockManager {
    // Key: Token Address, Value: Leader Address (Address::zero() if sniper/manual)
    locks: Arc<Mutex<HashMap<Address, Address>>>,
}

impl LockManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// 尝试对代币加锁。如果代币已锁定，返回 false；否则记录 Leader 并返回 true。
    pub fn try_lock(&self, token: Address, leader: Address) -> bool {
        let mut locks = self.locks.lock().unwrap();
        if locks.contains_key(&token) {
            false
        } else {
            locks.insert(token, leader);
            true
        }
    }

    /// 获取该代币绑定的 Leader
    pub fn get_leader(&self, token: Address) -> Option<Address> {
        self.locks.lock().unwrap().get(&token).cloned()
    }

    /// 强制加锁，通常用于程序启动恢复持仓时。
    pub fn lock(&self, token: Address, leader: Address) {
        let mut locks = self.locks.lock().unwrap();
        locks.insert(token, leader);
    }

    /// 释放代币锁。
    pub fn unlock(&self, token: Address) {
        if let Ok(mut locks) = self.locks.lock() {
            locks.remove(&token);
        }
    }
}
