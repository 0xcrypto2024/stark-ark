use std::sync::{Mutex, OnceLock};
use starknet::signers::LocalWallet;

// Global Session Storage
static SESSION: OnceLock<SessionManager> = OnceLock::new();

pub struct SessionManager {
    signer: Mutex<Option<LocalWallet>>,
}

impl SessionManager {
    pub fn global() -> &'static Self {
        SESSION.get_or_init(|| SessionManager {
            signer: Mutex::new(None),
        })
    }

    pub fn start_session(&self, wallet: LocalWallet) {
        let mut lock = self.signer.lock().unwrap();
        *lock = Some(wallet);
    }

    pub fn get_signer(&self) -> Option<LocalWallet> {
        let lock = self.signer.lock().unwrap();
        lock.clone()
    }

    pub fn is_active(&self) -> bool {
        let lock = self.signer.lock().unwrap();
        lock.is_some()
    }

    pub fn clear_session(&self) {
        let mut lock = self.signer.lock().unwrap();
        *lock = None;
    }
}
