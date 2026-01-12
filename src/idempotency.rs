use axum::{
    body::Body,
    extract::{Request, State},
    http::{header::CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::constants::MAX_REQUEST_BODY_BYTES;

#[derive(Debug, Clone)]
pub struct IdempotencyRecord {
    pub request_hash: String,
    pub status_code: u16,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
    pub created_at: Instant,
}

#[derive(Clone)]
pub struct IdempotencyStore {
    entries: Arc<RwLock<HashMap<String, IdempotencyRecord>>>,
    ttl: Duration,
}

impl IdempotencyStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    pub async fn get(&self, key: &str) -> Option<IdempotencyRecord> {
        let mut entries = self.entries.write().await;
        if let Some(record) = entries.get(key) {
            if record.created_at.elapsed() > self.ttl {
                entries.remove(key);
                return None;
            }
            return Some(record.clone());
        }
        None
    }

    pub async fn insert(&self, key: String, record: IdempotencyRecord) {
        let mut entries = self.entries.write().await;
        entries.insert(key, record);
    }

    pub fn compute_hash(body: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(body);
        hex::encode(hasher.finalize())
    }
}

pub async fn idempotency_middleware(
    State(store): State<Option<Arc<IdempotencyStore>>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let Some(store) = store else {
        return next.run(request).await;
    };

    let idempotency_key = match headers.get("Idempotency-Key") {
        Some(value) => value.to_str().unwrap_or_default().to_string(),
        None => return next.run(request).await,
    };

    let method = request.method().clone();
    if method != axum::http::Method::POST && method != axum::http::Method::PUT {
        return next.run(request).await;
    }

    let (parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, MAX_REQUEST_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!("Failed to read request body: {}", err);
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                axum::Json(serde_json::json!({
                    "type": "invalid_request",
                    "code": "payload_too_large",
                    "message": format!("Request body exceeds {} bytes", MAX_REQUEST_BODY_BYTES)
                })),
            )
                .into_response();
        }
    };

    let request_hash = IdempotencyStore::compute_hash(&body_bytes);

    if let Some(record) = store.get(&idempotency_key).await {
        if record.request_hash != request_hash {
            return (
                StatusCode::CONFLICT,
                axum::Json(serde_json::json!({
                    "type": "invalid_request",
                    "code": "idempotency_conflict",
                    "message": "Idempotency key reused with different request payload"
                })),
            )
                .into_response();
        }

        debug!("Replaying idempotent response for {}", idempotency_key);
        let mut builder = Response::builder()
            .status(StatusCode::from_u16(record.status_code).unwrap_or(StatusCode::OK));

        if let Some(headers_map) = builder.headers_mut() {
            headers_map.insert(
                HeaderName::from_static("x-idempotent-replay"),
                HeaderValue::from_static("true"),
            );

            if let Some(content_type) = record.content_type.as_deref() {
                if let Ok(value) = HeaderValue::from_str(content_type) {
                    headers_map.insert(CONTENT_TYPE, value);
                }
            }

            headers_map.insert(
                HeaderName::from_static("idempotency-key"),
                HeaderValue::from_str(&idempotency_key).unwrap_or(HeaderValue::from_static("")),
            );

            if let Some(request_id) = headers.get("Request-Id") {
                headers_map.insert(HeaderName::from_static("request-id"), request_id.clone());
            }
        }

        let response = builder.body(Body::from(record.body)).unwrap();
        return response.into_response();
    }

    let request = Request::from_parts(parts, Body::from(body_bytes.clone()));
    let response = next.run(request).await;

    let (response_parts, response_body) = response.into_parts();
    let response_bytes = match axum::body::to_bytes(response_body, MAX_REQUEST_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!("Failed to buffer response for idempotency: {}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({
                    "type": "processing_error",
                    "code": "idempotency_store_failed",
                    "message": "Failed to store idempotent response"
                })),
            )
                .into_response();
        }
    };

    if response_parts.status.as_u16() < 500 {
        let content_type = response_parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());

        let record = IdempotencyRecord {
            request_hash,
            status_code: response_parts.status.as_u16(),
            body: response_bytes.to_vec(),
            content_type,
            created_at: Instant::now(),
        };

        store.insert(idempotency_key, record).await;
    }

    Response::from_parts(response_parts, Body::from(response_bytes))
}
