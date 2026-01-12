use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub grpc_host: String,
    pub grpc_port: u16,
    pub base_url: String,
    pub ucp_version: String,
    pub service_version: String,
    pub log_level: String,
    pub require_auth: bool,
    pub api_keys: Vec<String>,
    pub require_idempotency: bool,
    pub session_ttl_seconds: u64,
    pub tax_bps: i64,
    pub order_webhook_url: Option<String>,
    pub order_webhook_api_key: Option<String>,
    pub webhook_signature: Option<String>,
    pub signing_keys_json: Option<String>,
    pub require_request_id: bool,
    pub buyer_consent_enabled: bool,
    pub ap2_enabled: bool,
    pub ap2_merchant_authorization: Option<String>,
    pub ap2_signing_key_id: Option<String>,
    pub signing_private_key_json: Option<String>,
    pub oauth_enabled: bool,
    pub oauth_issuer: String,
    pub oauth_client_id: String,
    pub oauth_client_secret: String,
    pub oauth_scopes: Vec<String>,
    pub oauth_token_ttl_seconds: u64,
    pub oauth_code_ttl_seconds: u64,
    pub oauth_redirect_uris: Vec<String>,
    pub oauth_service_documentation: Option<String>,
    pub token_ttl_seconds: u64,
    pub token_single_use: bool,
}

impl Config {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port: u16 = std::env::var("PORT")
            .unwrap_or_else(|_| "8081".to_string())
            .parse()?;

        let grpc_host = std::env::var("GRPC_HOST").unwrap_or_else(|_| host.clone());
        let grpc_port: u16 = std::env::var("GRPC_PORT")
            .unwrap_or_else(|_| "50051".to_string())
            .parse()?;

        let base_url = std::env::var("UCP_PUBLIC_BASE_URL").unwrap_or_else(|_| {
            format!("http://127.0.0.1:{}", port)
        });

        let ucp_version = std::env::var("UCP_VERSION").unwrap_or_else(|_| "2026-01-11".to_string());
        let service_version = std::env::var("UCP_SERVICE_VERSION")
            .unwrap_or_else(|_| ucp_version.clone());

        let api_keys = std::env::var("UCP_API_KEYS")
            .unwrap_or_default()
            .split(',')
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();

        let require_auth = std::env::var("UCP_REQUIRE_AUTH")
            .ok()
            .map(|value| value == "true" || value == "1")
            .unwrap_or(!api_keys.is_empty());

        let require_idempotency = std::env::var("UCP_REQUIRE_IDEMPOTENCY")
            .ok()
            .map(|value| value == "true" || value == "1")
            .unwrap_or(false);

        let require_request_id = std::env::var("UCP_REQUIRE_REQUEST_ID")
            .ok()
            .map(|value| value == "true" || value == "1")
            .unwrap_or(false);

        let buyer_consent_enabled = std::env::var("UCP_BUYER_CONSENT_ENABLED")
            .ok()
            .map(|value| value == "true" || value == "1")
            .unwrap_or(false);

        let ap2_enabled = std::env::var("UCP_AP2_ENABLED")
            .ok()
            .map(|value| value == "true" || value == "1")
            .unwrap_or(false);

        let ap2_merchant_authorization = std::env::var("UCP_AP2_MERCHANT_AUTH")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        let ap2_signing_key_id = std::env::var("UCP_AP2_SIGNING_KEY_ID")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        let signing_private_key_json = std::env::var("UCP_SIGNING_PRIVATE_KEY_JSON")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        // AP2 requires either a static merchant_authorization OR a signing key for dynamic generation
        if ap2_enabled && ap2_merchant_authorization.is_none() && signing_private_key_json.is_none() {
            return Err("AP2 requires either UCP_AP2_MERCHANT_AUTH or UCP_SIGNING_PRIVATE_KEY_JSON".into());
        }

        let session_ttl_seconds: u64 = std::env::var("UCP_SESSION_TTL_SECONDS")
            .unwrap_or_else(|_| "21600".to_string())
            .parse::<u64>()?
            .max(60);

        let tax_bps: i64 = std::env::var("UCP_TAX_BPS")
            .unwrap_or_else(|_| "875".to_string())
            .parse()?;

        let oauth_enabled = std::env::var("UCP_OAUTH_ENABLED")
            .ok()
            .map(|value| value == "true" || value == "1")
            .unwrap_or(false);

        let oauth_issuer = std::env::var("UCP_OAUTH_ISSUER").unwrap_or_else(|_| base_url.clone());

        let oauth_client_id =
            std::env::var("UCP_OAUTH_CLIENT_ID").unwrap_or_else(|_| "ucp-demo-client".to_string());
        let oauth_client_secret = std::env::var("UCP_OAUTH_CLIENT_SECRET")
            .unwrap_or_else(|_| "ucp-demo-secret".to_string());

        let oauth_scopes_raw = std::env::var("UCP_OAUTH_SCOPES")
            .unwrap_or_else(|_| "ucp:scopes:checkout_session".to_string());
        let oauth_scopes = oauth_scopes_raw
            .split(|ch: char| ch.is_whitespace() || ch == ',')
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
            .collect::<Vec<_>>();

        let oauth_token_ttl_seconds: u64 = std::env::var("UCP_OAUTH_TOKEN_TTL_SECONDS")
            .unwrap_or_else(|_| "3600".to_string())
            .parse::<u64>()?
            .max(60);

        let oauth_code_ttl_seconds: u64 = std::env::var("UCP_OAUTH_CODE_TTL_SECONDS")
            .unwrap_or_else(|_| "300".to_string())
            .parse::<u64>()?
            .max(30);

        let oauth_redirect_uris = std::env::var("UCP_OAUTH_REDIRECT_URIS")
            .unwrap_or_default()
            .split(',')
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();

        let oauth_service_documentation = std::env::var("UCP_OAUTH_SERVICE_DOCUMENTATION").ok();

        let token_ttl_seconds: u64 = std::env::var("UCP_TOKEN_TTL_SECONDS")
            .unwrap_or_else(|_| "900".to_string())
            .parse::<u64>()?
            .max(60);

        let token_single_use = std::env::var("UCP_TOKEN_SINGLE_USE")
            .ok()
            .map(|value| value == "true" || value == "1")
            .unwrap_or(true);

        Ok(Self {
            host,
            port,
            grpc_host,
            grpc_port,
            base_url,
            ucp_version,
            service_version,
            log_level: std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
            require_auth,
            api_keys,
            require_idempotency,
            session_ttl_seconds,
            tax_bps,
            order_webhook_url: std::env::var("UCP_ORDER_WEBHOOK_URL").ok(),
            order_webhook_api_key: std::env::var("UCP_ORDER_WEBHOOK_API_KEY").ok(),
            webhook_signature: std::env::var("UCP_WEBHOOK_SIGNATURE").ok(),
            signing_keys_json: std::env::var("UCP_SIGNING_KEYS_JSON").ok(),
            require_request_id,
            buyer_consent_enabled,
            ap2_enabled,
            ap2_merchant_authorization,
            ap2_signing_key_id,
            signing_private_key_json,
            oauth_enabled,
            oauth_issuer,
            oauth_client_id,
            oauth_client_secret,
            oauth_scopes,
            oauth_token_ttl_seconds,
            oauth_code_ttl_seconds,
            oauth_redirect_uris,
            oauth_service_documentation,
            token_ttl_seconds,
            token_single_use,
        })
    }
}
