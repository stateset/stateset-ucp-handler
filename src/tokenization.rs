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
        self.purge_expired(&mut store);
        store.insert(token.clone(), record);

        Ok(TokenizeResponse { token })
    }

    pub async fn detokenize(
        &self,
        request: DetokenizeRequest,
    ) -> Result<serde_json::Value, ServiceError> {
        let mut store = self.store.write().await;
        self.purge_expired(&mut store);
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

    fn purge_expired(&self, store: &mut HashMap<String, TokenRecord>) {
        store.retain(|_, record| record.created_at.elapsed() <= self.ttl);
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn tokenize_requires_checkout_id() {
        let service = TokenizationService::new(Duration::from_secs(60), true);
        let request = TokenizeRequest {
            credential: json!({"card": "4111"}),
            binding: Binding {
                checkout_id: " ".to_string(),
                identity: None,
            },
        };

        let err = service.tokenize(request).await.unwrap_err();
        assert!(matches!(err, ServiceError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn detokenize_rejects_mismatched_binding() {
        let service = TokenizationService::new(Duration::from_secs(60), false);
        let request = TokenizeRequest {
            credential: json!({"card": "4111"}),
            binding: Binding {
                checkout_id: "chk_123".to_string(),
                identity: None,
            },
        };

        let token = service.tokenize(request).await.unwrap().token;
        let err = service
            .detokenize(DetokenizeRequest {
                token,
                binding: Binding {
                    checkout_id: "chk_456".to_string(),
                    identity: None,
                },
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ServiceError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn detokenize_consumes_single_use_token() {
        let service = TokenizationService::new(Duration::from_secs(60), true);
        let credential = json!({"card": "4111"});
        let request = TokenizeRequest {
            credential: credential.clone(),
            binding: Binding {
                checkout_id: "chk_single".to_string(),
                identity: None,
            },
        };

        let token = service.tokenize(request).await.unwrap().token;
        let response = service
            .detokenize(DetokenizeRequest {
                token: token.clone(),
                binding: Binding {
                    checkout_id: "chk_single".to_string(),
                    identity: None,
                },
            })
            .await
            .unwrap();
        assert_eq!(response, credential);

        let err = service
            .detokenize(DetokenizeRequest {
                token,
                binding: Binding {
                    checkout_id: "chk_single".to_string(),
                    identity: None,
                },
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ServiceError::NotFound(_)));
    }
}
