use crate::errors::ServiceError;
use crate::models::{Binding, DetokenizeRequest, TokenizeRequest, TokenizeResponse};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone)]
pub struct TokenizationService {
    store: Arc<RwLock<HashMap<String, TokenRecord>>>,
    ttl: Duration,
    single_use: bool,
}

#[derive(Clone)]
struct TokenRecord {
    credential: serde_json::Value,
    binding: Binding,
    created_at: Instant,
}

impl TokenizationService {
    pub fn new(ttl: Duration, single_use: bool) -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
            ttl,
            single_use,
        }
    }

    pub async fn tokenize(&self, request: TokenizeRequest) -> Result<TokenizeResponse, ServiceError> {
        if request.binding.checkout_id.trim().is_empty() {
            return Err(ServiceError::InvalidInput(
                "binding.checkout_id is required".to_string(),
            ));
        }

        let token = format!("tok_{}", Uuid::new_v4());
        let record = TokenRecord {
            credential: request.credential,
            binding: request.binding,
            created_at: Instant::now(),
        };

        let mut store = self.store.write().await;
        store.insert(token.clone(), record);

        Ok(TokenizeResponse { token })
    }

    pub async fn detokenize(
        &self,
        request: DetokenizeRequest,
    ) -> Result<serde_json::Value, ServiceError> {
        let mut store = self.store.write().await;
        let record = store
            .get(&request.token)
            .cloned()
            .ok_or_else(|| ServiceError::NotFound("Token not found".to_string()))?;

        if record.created_at.elapsed() > self.ttl {
            store.remove(&request.token);
            return Err(ServiceError::NotFound("Token expired".to_string()));
        }

        self.validate_binding(&record.binding, &request.binding)?;
        if self.single_use {
            store.remove(&request.token);
        }
        Ok(record.credential)
    }

    fn validate_binding(&self, stored: &Binding, request: &Binding) -> Result<(), ServiceError> {
        if stored.checkout_id != request.checkout_id {
            return Err(ServiceError::InvalidInput(
                "binding.checkout_id does not match".to_string(),
            ));
        }

        match (&stored.identity, &request.identity) {
            (Some(stored_identity), Some(request_identity)) => {
                if stored_identity.access_token != request_identity.access_token {
                    return Err(ServiceError::InvalidInput(
                        "binding.identity does not match".to_string(),
                    ));
                }
            }
            (Some(_), None) => {
                return Err(ServiceError::InvalidInput(
                    "binding.identity is required".to_string(),
                ))
            }
            _ => {}
        }

        Ok(())
    }
}
