use axum::{
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone)]
pub struct OAuthConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub token_ttl: Duration,
    pub code_ttl: Duration,
    pub redirect_uris: Option<HashSet<String>>,
    pub service_documentation: Option<String>,
}

#[derive(Clone)]
pub struct OAuthService {
    config: OAuthConfig,
    codes: Arc<RwLock<HashMap<String, AuthCodeRecord>>>,
    tokens: Arc<RwLock<HashMap<String, TokenRecord>>>,
}

#[derive(Clone)]
struct AuthCodeRecord {
    client_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
    created_at: Instant,
}

#[derive(Clone)]
struct TokenRecord {
    client_id: String,
    scopes: Vec<String>,
    created_at: Instant,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RevocationRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

#[derive(Debug)]
pub struct AuthorizationOutcome {
    pub redirect_uri: String,
    pub code: String,
    pub state: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: String,
}

#[derive(Debug, Serialize)]
pub struct OAuthMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub revocation_endpoint: String,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_documentation: Option<String>,
}

#[derive(Debug)]
pub struct OAuthError {
    status: StatusCode,
    code: &'static str,
    description: String,
}

impl OAuthError {
    fn new(status: StatusCode, code: &'static str, description: impl Into<String>) -> Self {
        Self {
            status,
            code,
            description: description.into(),
        }
    }

    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", description)
    }

    pub fn invalid_client(description: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_client", description)
    }

    pub fn invalid_grant(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_grant", description)
    }

    pub fn invalid_scope(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_scope", description)
    }

    pub fn unsupported_grant_type(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "unsupported_grant_type", description)
    }

    pub fn unsupported_response_type(description: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            description,
        )
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({
                "error": self.code,
                "error_description": self.description,
            })),
        )
            .into_response()
    }
}

impl OAuthService {
    pub fn new(config: OAuthConfig) -> Self {
        Self {
            config,
            codes: Arc::new(RwLock::new(HashMap::new())),
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn metadata(&self) -> OAuthMetadata {
        let issuer = self.config.issuer.trim_end_matches('/').to_string();
        OAuthMetadata {
            issuer: issuer.clone(),
            authorization_endpoint: format!("{}/oauth2/authorize", issuer),
            token_endpoint: format!("{}/oauth2/token", issuer),
            revocation_endpoint: format!("{}/oauth2/revoke", issuer),
            scopes_supported: self.config.scopes.clone(),
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            token_endpoint_auth_methods_supported: vec!["client_secret_basic".to_string()],
            service_documentation: self.config.service_documentation.clone(),
        }
    }

    pub fn validate_client(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<(), OAuthError> {
        if client_id != self.config.client_id || client_secret != self.config.client_secret {
            return Err(OAuthError::invalid_client(
                "Client authentication failed",
            ));
        }
        Ok(())
    }

    pub async fn authorize(
        &self,
        request: AuthorizationRequest,
    ) -> Result<AuthorizationOutcome, OAuthError> {
        if request.response_type != "code" {
            return Err(OAuthError::unsupported_response_type(
                "response_type must be code",
            ));
        }

        if request.client_id != self.config.client_id {
            return Err(OAuthError::invalid_client("Unknown client_id"));
        }

        self.validate_redirect_uri(&request.redirect_uri)?;
        let scopes = self.normalize_scopes(request.scope.as_deref())?;

        let code = format!("code_{}", Uuid::new_v4());
        let record = AuthCodeRecord {
            client_id: request.client_id,
            redirect_uri: request.redirect_uri.clone(),
            scopes,
            created_at: Instant::now(),
        };

        let mut codes = self.codes.write().await;
        codes.insert(code.clone(), record);

        Ok(AuthorizationOutcome {
            redirect_uri: request.redirect_uri,
            code,
            state: request.state,
        })
    }

    pub async fn exchange_code(
        &self,
        client_id: &str,
        request: TokenRequest,
    ) -> Result<TokenResponse, OAuthError> {
        if request.grant_type != "authorization_code" {
            return Err(OAuthError::unsupported_grant_type(
                "grant_type must be authorization_code",
            ));
        }

        let code = request.code.ok_or_else(|| {
            OAuthError::invalid_request("authorization code must be provided")
        })?;

        let record = {
            let mut codes = self.codes.write().await;
            codes
                .remove(&code)
                .ok_or_else(|| OAuthError::invalid_grant("authorization code not found"))?
        };

        if record.created_at.elapsed() > self.config.code_ttl {
            return Err(OAuthError::invalid_grant("authorization code expired"));
        }

        if record.client_id != client_id {
            return Err(OAuthError::invalid_grant(
                "authorization code does not match client",
            ));
        }

        if let Some(redirect_uri) = request.redirect_uri.as_deref() {
            if redirect_uri != record.redirect_uri {
                return Err(OAuthError::invalid_grant(
                    "redirect_uri does not match authorization request",
                ));
            }
        }

        let access_token = format!("at_{}", Uuid::new_v4());
        let token_record = TokenRecord {
            client_id: client_id.to_string(),
            scopes: record.scopes.clone(),
            created_at: Instant::now(),
        };

        let mut tokens = self.tokens.write().await;
        tokens.insert(access_token.clone(), token_record);

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.token_ttl.as_secs(),
            scope: record.scopes.join(" "),
        })
    }

    pub async fn revoke(&self, token: &str) -> Result<(), OAuthError> {
        let mut tokens = self.tokens.write().await;
        tokens.remove(token);
        Ok(())
    }

    pub async fn validate_access_token(&self, token: &str) -> bool {
        let mut tokens = self.tokens.write().await;
        let Some(record) = tokens.get(token) else {
            return false;
        };

        if record.created_at.elapsed() > self.config.token_ttl {
            tokens.remove(token);
            return false;
        }

        true
    }

    fn normalize_scopes(&self, scope: Option<&str>) -> Result<Vec<String>, OAuthError> {
        let mut scopes = match scope {
            Some(raw) => parse_scopes(raw),
            None => self.config.scopes.clone(),
        };

        if scopes.is_empty() {
            scopes = self.config.scopes.clone();
        }

        let allowed: HashSet<&str> = self.config.scopes.iter().map(|s| s.as_str()).collect();
        if scopes.iter().any(|scope| !allowed.contains(scope.as_str())) {
            return Err(OAuthError::invalid_scope("unsupported scope requested"));
        }

        Ok(scopes)
    }

    fn validate_redirect_uri(&self, redirect_uri: &str) -> Result<(), OAuthError> {
        if let Some(allowed) = &self.config.redirect_uris {
            if !allowed.contains(redirect_uri) {
                return Err(OAuthError::invalid_request("redirect_uri is not allowed"));
            }
        }
        Ok(())
    }
}

pub fn parse_basic_auth(headers: &HeaderMap) -> Result<(String, String), OAuthError> {
    let header_value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| OAuthError::invalid_client("Missing Authorization header"))?;

    let encoded = header_value
        .strip_prefix("Basic ")
        .ok_or_else(|| OAuthError::invalid_client("Authorization header must use Basic auth"))?;

    let decoded = BASE64_STANDARD
        .decode(encoded)
        .map_err(|_| OAuthError::invalid_client("Invalid basic auth encoding"))?;

    let decoded = String::from_utf8(decoded)
        .map_err(|_| OAuthError::invalid_client("Invalid basic auth credentials"))?;

    let mut parts = decoded.splitn(2, ':');
    let client_id = parts.next().unwrap_or_default();
    let client_secret = parts.next().unwrap_or_default();

    if client_id.is_empty() || client_secret.is_empty() {
        return Err(OAuthError::invalid_client("Invalid basic auth credentials"));
    }

    Ok((client_id.to_string(), client_secret.to_string()))
}

pub fn build_redirect_uri(
    base: &str,
    code: &str,
    state: Option<&str>,
) -> Result<String, OAuthError> {
    if base.trim().is_empty() {
        return Err(OAuthError::invalid_request(
            "redirect_uri must be provided",
        ));
    }

    let (base_part, fragment) = match base.split_once('#') {
        Some((head, tail)) => (head, Some(tail)),
        None => (base, None),
    };

    let delimiter = if base_part.contains('?') { "&" } else { "?" };
    let mut url = String::with_capacity(base.len() + 64);
    url.push_str(base_part);
    url.push_str(delimiter);
    url.push_str("code=");
    url.push_str(&encode_component(code));

    if let Some(state) = state {
        url.push_str("&state=");
        url.push_str(&encode_component(state));
    }

    if let Some(fragment) = fragment {
        url.push('#');
        url.push_str(fragment);
    }

    Ok(url)
}

fn parse_scopes(raw: &str) -> Vec<String> {
    raw.split(|ch: char| ch.is_whitespace() || ch == ',')
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
        .collect()
}

fn encode_component(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~' => output.push(byte as char),
            _ => {
                output.push('%');
                output.push(hex_digit(byte >> 4));
                output.push(hex_digit(byte & 0x0F));
            }
        }
    }
    output
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}
