//! Order event webhook delivery with JWS signatures.
//!
//! Signs webhook payloads using RFC 7797 detached JWS signatures
//! per the UCP Order capability specification.

use crate::crypto::{canonicalize, sign_detached, SigningKey};
use crate::errors::ServiceError;
use crate::models::OrderEvent;
use chrono::{DateTime, Utc};
use reqwest::header::{HeaderMap, RETRY_AFTER};
use reqwest::{Client, StatusCode};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info, warn};

#[derive(Clone, Debug)]
pub struct OrderWebhookOptions {
    pub timeout: Duration,
    pub max_retries: usize,
    pub retry_backoff: Duration,
    pub user_agent: String,
}

impl Default for OrderWebhookOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_retries: 2,
            retry_backoff: Duration::from_millis(250),
            user_agent: format!("stateset-ucp-handler/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

#[derive(Clone)]
pub struct OrderWebhook {
    client: Client,
    webhook_url: Option<String>,
    api_key: Option<String>,
    /// Legacy static signature (deprecated, use signing_key instead)
    legacy_signature: Option<String>,
    /// Signing key for JWS signature generation
    signing_key: Option<Arc<SigningKey>>,
    options: OrderWebhookOptions,
}

impl OrderWebhook {
    /// Creates a new OrderWebhook with legacy static signature.
    pub fn new(
        webhook_url: Option<String>,
        api_key: Option<String>,
        signature: Option<String>,
    ) -> Self {
        Self::new_with_options(webhook_url, api_key, signature, OrderWebhookOptions::default())
    }

    /// Creates a new OrderWebhook with explicit options.
    pub fn new_with_options(
        webhook_url: Option<String>,
        api_key: Option<String>,
        signature: Option<String>,
        options: OrderWebhookOptions,
    ) -> Self {
        let client = Client::builder()
            .timeout(options.timeout)
            .user_agent(options.user_agent.clone())
            .build()
            .expect("Failed to create webhook HTTP client");

        Self {
            client,
            webhook_url,
            api_key,
            legacy_signature: signature,
            signing_key: None,
            options,
        }
    }

    /// Creates a new OrderWebhook with proper JWS signing key.
    #[allow(dead_code)]
    pub fn with_signing_key(
        webhook_url: Option<String>,
        api_key: Option<String>,
        signing_key: SigningKey,
    ) -> Self {
        Self::with_signing_key_and_options(
            webhook_url,
            api_key,
            signing_key,
            OrderWebhookOptions::default(),
        )
    }

    /// Creates a new OrderWebhook with signing key and explicit options.
    #[allow(dead_code)]
    pub fn with_signing_key_and_options(
        webhook_url: Option<String>,
        api_key: Option<String>,
        signing_key: SigningKey,
        options: OrderWebhookOptions,
    ) -> Self {
        let client = Client::builder()
            .timeout(options.timeout)
            .user_agent(options.user_agent.clone())
            .build()
            .expect("Failed to create webhook HTTP client");

        Self {
            client,
            webhook_url,
            api_key,
            legacy_signature: None,
            signing_key: Some(Arc::new(signing_key)),
            options,
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

        let signature_header = if let Some(key) = &self.signing_key {
            // Use proper JWS signature
            let event_value: serde_json::Value = serde_json::from_slice(&payload_json)
                .map_err(|e| ServiceError::External(format!("JSON parse error: {}", e)))?;

            let canonical_payload = canonicalize(&event_value).map_err(|e| {
                ServiceError::External(format!("Failed to canonicalize payload: {}", e))
            })?;

            let jws = sign_detached(&canonical_payload, key).map_err(|e| {
                ServiceError::External(format!("Failed to sign webhook payload: {}", e))
            })?;

            debug!("Added JWS signature to webhook request");
            Some(jws.to_compact())
        } else if let Some(signature) = self.legacy_signature.as_deref() {
            debug!("Added legacy static signature to webhook request");
            Some(signature.to_string())
        } else {
            None
        };

        let max_attempts = self.options.max_retries.saturating_add(1);
        let mut retry_after_override: Option<Duration> = None;
        for attempt in 0..max_attempts {
            if attempt > 0 {
                let delay = retry_after_override
                    .take()
                    .unwrap_or_else(|| self.retry_delay(attempt));
                sleep(delay).await;
            }

            let mut request = self
                .client
                .post(url)
                .header("Content-Type", "application/json")
                .header("Request-Id", &event.event_id);

            if let Some(api_key) = self.api_key.as_deref() {
                request = request.header("X-API-Key", api_key);
            }

            if let Some(signature) = signature_header.as_ref() {
                request = request.header("Request-Signature", signature);
            }

            let response = request.body(payload_json.clone()).send().await;

            match response {
                Ok(response) if response.status().is_success() => {
                    info!("Order event webhook delivered successfully to {}", url);
                    return Ok(());
                }
                Ok(response) => {
                    let status = response.status();
                    if should_retry(status) && attempt + 1 < max_attempts {
                        retry_after_override = retry_after_delay(response.headers());
                        warn!(
                            "Webhook attempt {} failed with status {}, retrying",
                            attempt + 1,
                            status
                        );
                        continue;
                    }
                    warn!("Order event webhook returned status {}", status);
                    return Err(ServiceError::External(format!(
                        "Order event webhook returned status {}",
                        status
                    )));
                }
                Err(err) => {
                    if attempt + 1 < max_attempts {
                        warn!(
                            "Webhook attempt {} failed: {}, retrying",
                            attempt + 1,
                            err
                        );
                        continue;
                    }
                    return Err(ServiceError::External(format!(
                        "Failed to send order event webhook: {}",
                        err
                    )));
                }
            }
        }

        Err(ServiceError::External(
            "Failed to deliver order event webhook".to_string(),
        ))
    }

    fn retry_delay(&self, attempt: usize) -> Duration {
        let shift = attempt.saturating_sub(1).min(10) as u32;
        let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
        let base_ms = self.options.retry_backoff.as_millis() as u64;
        Duration::from_millis(base_ms.saturating_mul(multiplier))
    }
}

fn should_retry(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn retry_after_delay(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if value.is_empty() {
        return None;
    }

    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds.max(1)));
    }

    if let Ok(date) = DateTime::parse_from_rfc2822(value) {
        let deadline = date.with_timezone(&Utc);
        let now = Utc::now();
        return deadline
            .signed_duration_since(now)
            .to_std()
            .ok()
            .filter(|delay| !delay.is_zero());
    }

    if let Ok(date) = DateTime::parse_from_rfc3339(value) {
        let deadline = date.with_timezone(&Utc);
        let now = Utc::now();
        return deadline
            .signed_duration_since(now)
            .to_std()
            .ok()
            .filter(|delay| !delay.is_zero());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};
    use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};
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

    #[test]
    fn retry_after_parses_seconds() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("5"));
        let delay = retry_after_delay(&headers).expect("retry delay");
        assert_eq!(delay.as_secs(), 5);
    }

    #[test]
    fn retry_after_parses_http_date() {
        let mut headers = HeaderMap::new();
        let when = (Utc::now() + ChronoDuration::seconds(10)).to_rfc2822();
        headers.insert(RETRY_AFTER, HeaderValue::from_str(&when).unwrap());
        let delay = retry_after_delay(&headers).expect("retry delay");
        assert!(delay.as_secs() >= 1);
    }

    #[test]
    fn retry_after_ignores_invalid_values() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("not-a-date"));
        assert!(retry_after_delay(&headers).is_none());
    }
}
