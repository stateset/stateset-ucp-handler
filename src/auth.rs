use axum::{
    extract::{Request, State},
    http::HeaderMap,
    middleware::Next,
    response::{IntoResponse, Response},
};
use crate::oauth::OAuthService;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, warn};

#[derive(Clone)]
pub struct AuthConfig {
    require_auth: bool,
    api_keys: Arc<HashSet<String>>,
    oauth: Option<Arc<OAuthService>>,
}

impl AuthConfig {
    pub fn new(require_auth: bool, api_keys: Vec<String>, oauth: Option<Arc<OAuthService>>) -> Self {
        Self {
            require_auth,
            api_keys: Arc::new(api_keys.into_iter().collect()),
            oauth,
        }
    }

    pub fn requires_auth(&self) -> bool {
        self.require_auth
    }

    pub async fn validate_token(&self, token: &str) -> bool {
        if self.api_keys.contains(token) {
            return true;
        }

        if let Some(oauth) = &self.oauth {
            return oauth.validate_access_token(token).await;
        }

        false
    }
}

pub async fn auth_middleware(
    State(auth): State<Arc<AuthConfig>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    if !auth.require_auth {
        return next.run(request).await;
    }

    let api_key = extract_api_key(&headers);
    match api_key {
        Some(key) if auth.validate_token(&key).await => {
            debug!("Authenticated request");
            next.run(request).await
        }
        Some(_) => {
            warn!("Invalid API key provided");
            unauthorized_response()
        }
        None => {
            warn!("Missing API key");
            unauthorized_response()
        }
    }
}

fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers.get("Authorization") {
        if let Ok(header) = value.to_str() {
            if let Some(token) = header.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }

    if let Some(value) = headers.get("X-API-Key") {
        if let Ok(header) = value.to_str() {
            return Some(header.to_string());
        }
    }

    None
}

fn unauthorized_response() -> Response {
    (
        axum::http::StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({
            "type": "invalid_request",
            "code": "unauthorized",
            "message": "Missing or invalid authentication credentials"
        })),
    )
        .into_response()
}
