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
    pub webhook_timeout_seconds: u64,
    pub webhook_max_retries: usize,
    pub webhook_retry_base_ms: u64,
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
    pub require_ucp_agent: bool,
    pub require_request_signature: bool,
    pub allow_insecure_urls: bool,
    pub profile_cache_ttl_seconds: u64,
    pub profile_fetch_timeout_seconds: u64,

    // iCommerce engine configuration
    /// Enable iCommerce as the execution backend (default: true)
    pub commerce_enabled: bool,
    /// Path to SQLite database for commerce persistence (default: ./commerce.db)
    pub commerce_db_path: String,
    /// Use iCommerce for tax calculation instead of fixed rate (default: true when commerce enabled)
    pub use_icommerce_tax: bool,
    /// Use iCommerce for promotions instead of hardcoded codes (default: true when commerce enabled)
    pub use_icommerce_promotions: bool,
    /// Use iCommerce for shipping rates instead of hardcoded options (default: true when commerce enabled)
    pub use_icommerce_shipping: bool,
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
            .map(|value| parse_env_bool(&value))
            .unwrap_or(!api_keys.is_empty());

        let require_idempotency = std::env::var("UCP_REQUIRE_IDEMPOTENCY")
            .ok()
            .map(|value| parse_env_bool(&value))
            .unwrap_or(false);

        let require_request_id = std::env::var("UCP_REQUIRE_REQUEST_ID")
            .ok()
            .map(|value| parse_env_bool(&value))
            .unwrap_or(false);

        let buyer_consent_enabled = std::env::var("UCP_BUYER_CONSENT_ENABLED")
            .ok()
            .map(|value| parse_env_bool(&value))
            .unwrap_or(false);

        let ap2_enabled = std::env::var("UCP_AP2_ENABLED")
            .ok()
            .map(|value| parse_env_bool(&value))
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
            .map(|value| parse_env_bool(&value))
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

        if oauth_enabled && oauth_redirect_uris.is_empty() {
            return Err("OAuth requires UCP_OAUTH_REDIRECT_URIS to be configured".into());
        }

        let oauth_service_documentation = std::env::var("UCP_OAUTH_SERVICE_DOCUMENTATION").ok();

        let token_ttl_seconds: u64 = std::env::var("UCP_TOKEN_TTL_SECONDS")
            .unwrap_or_else(|_| "900".to_string())
            .parse::<u64>()?
            .max(60);

        let token_single_use = std::env::var("UCP_TOKEN_SINGLE_USE")
            .ok()
            .map(|value| parse_env_bool(&value))
            .unwrap_or(true);

        let require_ucp_agent = std::env::var("UCP_REQUIRE_UCP_AGENT")
            .ok()
            .map(|value| parse_env_bool(&value))
            .unwrap_or(true);

        let require_request_signature = std::env::var("UCP_REQUIRE_REQUEST_SIGNATURE")
            .ok()
            .map(|value| parse_env_bool(&value))
            .unwrap_or(true);

        let allow_insecure_urls = std::env::var("UCP_ALLOW_INSECURE_URLS")
            .ok()
            .map(|value| parse_env_bool(&value))
            .unwrap_or_else(|| {
                base_url.starts_with("http://localhost")
                    || base_url.starts_with("http://127.0.0.1")
            });

        if !allow_insecure_urls && base_url.starts_with("http://") {
            return Err("UCP_PUBLIC_BASE_URL must use https:// unless UCP_ALLOW_INSECURE_URLS=true"
                .into());
        }

        let profile_cache_ttl_seconds: u64 = std::env::var("UCP_PROFILE_CACHE_TTL_SECONDS")
            .unwrap_or_else(|_| "3600".to_string())
            .parse::<u64>()?
            .max(30);

        let profile_fetch_timeout_seconds: u64 =
            std::env::var("UCP_PROFILE_FETCH_TIMEOUT_SECONDS")
                .unwrap_or_else(|_| "10".to_string())
                .parse::<u64>()?
                .max(1);

        let webhook_timeout_seconds: u64 = std::env::var("UCP_WEBHOOK_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "10".to_string())
            .parse::<u64>()?
            .max(1);

        let webhook_max_retries: usize = std::env::var("UCP_WEBHOOK_MAX_RETRIES")
            .unwrap_or_else(|_| "2".to_string())
            .parse::<usize>()?;

        let webhook_retry_base_ms: u64 = std::env::var("UCP_WEBHOOK_RETRY_BASE_MS")
            .unwrap_or_else(|_| "250".to_string())
            .parse::<u64>()?
            .max(1);

        // iCommerce configuration
        let commerce_enabled = std::env::var("COMMERCE_ENABLED")
            .ok()
            .map(|value| parse_env_bool(&value))
            .unwrap_or(true); // Enabled by default

        let commerce_db_path = std::env::var("COMMERCE_DB_PATH")
            .unwrap_or_else(|_| "./commerce.db".to_string());

        let use_icommerce_tax = std::env::var("USE_ICOMMERCE_TAX")
            .ok()
            .map(|value| parse_env_bool(&value))
            .unwrap_or(commerce_enabled);

        let use_icommerce_promotions = std::env::var("USE_ICOMMERCE_PROMOTIONS")
            .ok()
            .map(|value| parse_env_bool(&value))
            .unwrap_or(commerce_enabled);

        let use_icommerce_shipping = std::env::var("USE_ICOMMERCE_SHIPPING")
            .ok()
            .map(|value| parse_env_bool(&value))
            .unwrap_or(commerce_enabled);

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
            webhook_timeout_seconds,
            webhook_max_retries,
            webhook_retry_base_ms,
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
            require_ucp_agent,
            require_request_signature,
            allow_insecure_urls,
            profile_cache_ttl_seconds,
            profile_fetch_timeout_seconds,
            commerce_enabled,
            commerce_db_path,
            use_icommerce_tax,
            use_icommerce_promotions,
            use_icommerce_shipping,
        })
    }
}

fn parse_env_bool(value: &str) -> bool {
    let value = value.trim();
    value == "1" || value.eq_ignore_ascii_case("true")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvSnapshot {
        saved: Vec<(String, Option<String>)>,
    }

    impl EnvSnapshot {
        fn new(keys: &[&str]) -> Self {
            let saved = keys
                .iter()
                .map(|key| (key.to_string(), env::var(key).ok()))
                .collect();
            Self { saved }
        }
    }

    impl Drop for EnvSnapshot {
        fn drop(&mut self) {
            for (key, value) in self.saved.drain(..) {
                match value {
                    Some(value) => env::set_var(&key, value),
                    None => env::remove_var(&key),
                }
            }
        }
    }

    fn clear_env(keys: &[&str]) {
        for key in keys {
            env::remove_var(key);
        }
    }

    #[test]
    fn load_defaults_when_env_missing() {
        let _lock = ENV_LOCK.lock().unwrap();
        let keys = [
            "HOST",
            "PORT",
            "UCP_VERSION",
            "UCP_SERVICE_VERSION",
            "UCP_API_KEYS",
            "UCP_REQUIRE_AUTH",
            "UCP_PUBLIC_BASE_URL",
            "UCP_REQUIRE_IDEMPOTENCY",
            "UCP_REQUIRE_REQUEST_ID",
            "UCP_BUYER_CONSENT_ENABLED",
            "UCP_AP2_ENABLED",
            "UCP_AP2_MERCHANT_AUTH",
            "UCP_AP2_SIGNING_KEY_ID",
            "UCP_SIGNING_PRIVATE_KEY_JSON",
            "UCP_SESSION_TTL_SECONDS",
            "UCP_TAX_BPS",
            "UCP_OAUTH_ENABLED",
            "UCP_OAUTH_REDIRECT_URIS",
            "UCP_OAUTH_SCOPES",
            "UCP_TOKEN_TTL_SECONDS",
            "UCP_TOKEN_SINGLE_USE",
            "UCP_REQUIRE_UCP_AGENT",
            "UCP_REQUIRE_REQUEST_SIGNATURE",
            "UCP_ALLOW_INSECURE_URLS",
            "UCP_PROFILE_CACHE_TTL_SECONDS",
            "UCP_PROFILE_FETCH_TIMEOUT_SECONDS",
            "UCP_WEBHOOK_TIMEOUT_SECONDS",
            "UCP_WEBHOOK_MAX_RETRIES",
            "UCP_WEBHOOK_RETRY_BASE_MS",
            "COMMERCE_ENABLED",
            "COMMERCE_DB_PATH",
            "USE_ICOMMERCE_TAX",
            "USE_ICOMMERCE_PROMOTIONS",
            "USE_ICOMMERCE_SHIPPING",
        ];
        let _snapshot = EnvSnapshot::new(&keys);
        clear_env(&keys);

        let config = Config::load().unwrap();
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 8081);
        assert_eq!(config.ucp_version, "2026-01-11");
        assert!(config.api_keys.is_empty());
        assert!(!config.require_auth);
        assert_eq!(config.profile_cache_ttl_seconds, 3600);
        assert_eq!(config.profile_fetch_timeout_seconds, 10);
        assert_eq!(config.webhook_timeout_seconds, 10);
        assert_eq!(config.webhook_max_retries, 2);
        assert_eq!(config.webhook_retry_base_ms, 250);
    }

    #[test]
    fn load_sets_require_auth_when_api_keys_present() {
        let _lock = ENV_LOCK.lock().unwrap();
        let keys = ["UCP_API_KEYS", "UCP_REQUIRE_AUTH"];
        let _snapshot = EnvSnapshot::new(&keys);
        clear_env(&keys);

        env::set_var("UCP_API_KEYS", "key-1, key-2");
        let config = Config::load().unwrap();
        assert!(config.require_auth);
        assert_eq!(config.api_keys, vec!["key-1".to_string(), "key-2".to_string()]);
    }

    #[test]
    fn load_errors_when_oauth_enabled_without_redirects() {
        let _lock = ENV_LOCK.lock().unwrap();
        let keys = ["UCP_OAUTH_ENABLED", "UCP_OAUTH_REDIRECT_URIS"];
        let _snapshot = EnvSnapshot::new(&keys);
        clear_env(&keys);

        env::set_var("UCP_OAUTH_ENABLED", "true");
        let result = Config::load();
        assert!(result.is_err());
    }

    #[test]
    fn load_errors_when_ap2_enabled_without_auth() {
        let _lock = ENV_LOCK.lock().unwrap();
        let keys = [
            "UCP_AP2_ENABLED",
            "UCP_AP2_MERCHANT_AUTH",
            "UCP_SIGNING_PRIVATE_KEY_JSON",
        ];
        let _snapshot = EnvSnapshot::new(&keys);
        clear_env(&keys);

        env::set_var("UCP_AP2_ENABLED", "true");
        let result = Config::load();
        assert!(result.is_err());
    }
}
