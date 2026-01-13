//! Order event webhook delivery with JWS signatures.
//!
//! Signs webhook payloads using RFC 7797 detached JWS signatures
//! per the UCP Order capability specification.

use crate::crypto::{canonicalize, sign_detached, SigningKey};
use crate::errors::ServiceError;
use crate::models::OrderEvent;
use reqwest::Client;
use std::sync::Arc;
use tracing::{debug, info, warn};

#[derive(Clone)]
pub struct OrderWebhook {
    client: Client,
    webhook_url: Option<String>,
    api_key: Option<String>,
    /// Legacy static signature (deprecated, use signing_key instead)
    legacy_signature: Option<String>,
    /// Signing key for JWS signature generation
    signing_key: Option<Arc<SigningKey>>,
}

impl OrderWebhook {
    /// Creates a new OrderWebhook with legacy static signature.
    pub fn new(
        webhook_url: Option<String>,
        api_key: Option<String>,
        signature: Option<String>,
    ) -> Self {
        Self {
            client: Client::new(),
            webhook_url,
            api_key,
            legacy_signature: signature,
            signing_key: None,
        }
    }

    /// Creates a new OrderWebhook with proper JWS signing key.
    #[allow(dead_code)]
    pub fn with_signing_key(
        webhook_url: Option<String>,
        api_key: Option<String>,
        signing_key: SigningKey,
    ) -> Self {
        Self {
            client: Client::new(),
            webhook_url,
            api_key,
            legacy_signature: None,
            signing_key: Some(Arc::new(signing_key)),
        }
    }

    /// Sets the signing key for JWS signature generation.
    #[allow(dead_code)]
    pub fn set_signing_key(&mut self, signing_key: SigningKey) {
        self.signing_key = Some(Arc::new(signing_key));
        self.legacy_signature = None;
    }

    /// Generates a JWS signature for the given payload.
    ///
    /// Returns the compact detached JWS format: header..signature
    #[allow(dead_code)]
    fn sign_payload(&self, payload: &[u8]) -> Result<String, ServiceError> {
        let Some(key) = &self.signing_key else {
            return Err(ServiceError::InvalidState(
                "No signing key configured for webhook signatures".to_string(),
            ));
        };

        let jws = sign_detached(payload, key).map_err(|e| {
            ServiceError::External(format!("Failed to sign webhook payload: {}", e))
        })?;

        Ok(jws.to_compact())
    }

    /// Sends an order event to the configured webhook URL.
    ///
    /// The payload is signed using either:
    /// 1. JWS detached signature (if signing_key is configured)
    /// 2. Legacy static signature (if legacy_signature is configured)
    pub async fn send_order_event(&self, event: &OrderEvent) -> Result<(), ServiceError> {
        let Some(url) = self.webhook_url.as_deref() else {
            debug!("No webhook URL configured, skipping order event delivery");
            return Ok(());
        };

        // Serialize the event to JSON
        let payload_json = serde_json::to_vec(event).map_err(|e| {
            ServiceError::External(format!("Failed to serialize order event: {}", e))
        })?;

        // Build the request
        let mut request = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header("Request-Id", &event.event_id);

        // Add API key if configured
        if let Some(api_key) = self.api_key.as_deref() {
            request = request.header("X-API-Key", api_key);
        }

        // Add signature
        if let Some(key) = &self.signing_key {
            // Use proper JWS signature
            // First canonicalize the JSON for consistent signing
            let event_value: serde_json::Value = serde_json::from_slice(&payload_json)
                .map_err(|e| ServiceError::External(format!("JSON parse error: {}", e)))?;

            let canonical_payload = canonicalize(&event_value).map_err(|e| {
                ServiceError::External(format!("Failed to canonicalize payload: {}", e))
            })?;

            let jws = sign_detached(&canonical_payload, key).map_err(|e| {
                ServiceError::External(format!("Failed to sign webhook payload: {}", e))
            })?;

            request = request.header("Request-Signature", jws.to_compact());
            debug!("Added JWS signature to webhook request");
        } else if let Some(signature) = self.legacy_signature.as_deref() {
            // Fallback to legacy static signature
            request = request.header("Request-Signature", signature);
            debug!("Added legacy static signature to webhook request");
        }

        // Send the request
        let response = request.body(payload_json).send().await.map_err(|err| {
            ServiceError::External(format!("Failed to send order event webhook: {}", err))
        })?;

        if !response.status().is_success() {
            let status = response.status();
            warn!("Order event webhook returned status {}", status);
            return Err(ServiceError::External(format!(
                "Order event webhook returned status {}",
                status
            )));
        }

        info!("Order event webhook delivered successfully to {}", url);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_key_pair, SigningAlgorithm};

    #[test]
    fn test_webhook_creation() {
        let webhook = OrderWebhook::new(
            Some("https://example.com/webhook".to_string()),
            Some("test-key".to_string()),
            Some("legacy-sig".to_string()),
        );

        assert!(webhook.webhook_url.is_some());
        assert!(webhook.api_key.is_some());
        assert!(webhook.legacy_signature.is_some());
        assert!(webhook.signing_key.is_none());
    }

    #[test]
    fn test_webhook_with_signing_key() {
        let (signing_key, _) = generate_key_pair(SigningAlgorithm::ES256, "test-key".to_string());

        let webhook = OrderWebhook::with_signing_key(
            Some("https://example.com/webhook".to_string()),
            Some("test-key".to_string()),
            signing_key,
        );

        assert!(webhook.signing_key.is_some());
        assert!(webhook.legacy_signature.is_none());
    }

    #[test]
    fn test_sign_payload() {
        let (signing_key, _) = generate_key_pair(SigningAlgorithm::ES256, "test-key".to_string());

        let webhook = OrderWebhook::with_signing_key(
            Some("https://example.com/webhook".to_string()),
            None,
            signing_key,
        );

        let payload = b"test payload";
        let signature = webhook.sign_payload(payload).unwrap();

        // Should be in compact detached format: header..signature
        let parts: Vec<&str> = signature.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(!parts[0].is_empty()); // Header
        assert!(parts[1].is_empty());   // Empty payload (detached)
        assert!(!parts[2].is_empty()); // Signature
    }
}
