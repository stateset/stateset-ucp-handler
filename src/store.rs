use crate::models::CheckoutResponse;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct CheckoutStore {
    sessions: Arc<RwLock<HashMap<String, StoredSession>>>,
}

#[derive(Clone)]
struct StoredSession {
    checkout: CheckoutResponse,
    expires_at: Option<Instant>,
}

impl StoredSession {
    fn new(checkout: CheckoutResponse, ttl: Option<Duration>) -> Self {
        let expires_at = ttl.map(|duration| Instant::now() + duration);
        Self { checkout, expires_at }
    }

    fn is_expired(&self) -> bool {
        self.expires_at
            .map(|deadline| Instant::now() > deadline)
            .unwrap_or(false)
    }
}

impl CheckoutStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn insert(&self, checkout: CheckoutResponse, ttl: Option<Duration>) {
        let mut sessions = self.sessions.write().await;
        sessions.insert(
            checkout.id.clone(),
            StoredSession::new(checkout, ttl),
        );
    }

    pub async fn get(&self, checkout_id: &str) -> Option<CheckoutResponse> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get(checkout_id) {
            if session.is_expired() {
                sessions.remove(checkout_id);
                return None;
            }
            return Some(session.checkout.clone());
        }
        None
    }

    pub async fn remove(&self, checkout_id: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(checkout_id);
    }
}

impl Default for CheckoutStore {
    fn default() -> Self {
        Self::new()
    }
}
