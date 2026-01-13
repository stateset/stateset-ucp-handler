//! Platform profile negotiation for UCP.
//!
//! Implements:
//! - UCP-Agent header parsing (RFC 8941 Structured Field Values)
//! - Platform profile fetching and caching
//! - Capability intersection algorithm
//! - Version negotiation

use crate::crypto::{load_verifying_key, VerifyingKey};
use crate::models::{Capability, CapabilityRef, DiscoveryDocument, JwkKey, PaymentHandler};
use reqwest::Client;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, warn};

#[derive(Debug, Error)]
pub enum NegotiationError {
    #[error("Missing UCP-Agent header")]
    #[allow(dead_code)]
    MissingUcpAgentHeader,
    #[error("Invalid UCP-Agent header format: {0}")]
    InvalidUcpAgentFormat(String),
    #[error("Missing profile URL in UCP-Agent header")]
    #[allow(dead_code)]
    MissingProfileUrl,
    #[error("Failed to fetch platform profile: {0}")]
    ProfileFetchError(String),
    #[error("Invalid platform profile: {0}")]
    InvalidProfile(String),
    #[error("Version not supported: platform {platform_version} > business {business_version}")]
    VersionNotSupported {
        platform_version: String,
        business_version: String,
    },
    #[error("HTTP error: {0}")]
    HttpError(String),
}

/// Parsed UCP-Agent header contents
#[derive(Debug, Clone)]
pub struct UcpAgent {
    /// Platform profile URL
    pub profile_url: Option<String>,
    /// Additional parameters from the header (reserved for future use)
    #[allow(dead_code)]
    pub params: HashMap<String, String>,
}

/// Cached platform profile with TTL
#[derive(Debug, Clone)]
struct CachedProfile {
    profile: PlatformProfile,
    fetched_at: Instant,
    ttl: Duration,
}

impl CachedProfile {
    fn is_expired(&self) -> bool {
        self.fetched_at.elapsed() > self.ttl
    }
}

/// Platform profile data
#[derive(Debug, Clone)]
pub struct PlatformProfile {
    /// UCP version declared by platform
    pub version: String,
    /// Capabilities supported by platform
    pub capabilities: Vec<Capability>,
    /// Payment handlers supported by platform (reserved for future use)
    #[allow(dead_code)]
    pub payment_handlers: Vec<PaymentHandler>,
    /// Platform's signing keys for verification
    pub signing_keys: Vec<JwkKey>,
    /// Platform's webhook URL for order events (from order capability config)
    pub order_webhook_url: Option<String>,
}

/// Result of capability negotiation
#[derive(Debug, Clone)]
pub struct NegotiatedCapabilities {
    /// Negotiated UCP version (minimum of platform and business)
    pub version: String,
    /// Active capabilities (intersection)
    pub capabilities: Vec<CapabilityRef>,
    /// Platform's signing keys (for verifying mandates)
    pub platform_signing_keys: Vec<VerifyingKey>,
    /// Platform's order webhook URL (reserved for future use)
    #[allow(dead_code)]
    pub platform_webhook_url: Option<String>,
}

impl Default for NegotiatedCapabilities {
    fn default() -> Self {
        Self {
            version: "2026-01-11".to_string(),
            capabilities: Vec::new(),
            platform_signing_keys: Vec::new(),
            platform_webhook_url: None,
        }
    }
}

/// Profile cache for fetched platform profiles
pub struct ProfileCache {
    cache: RwLock<HashMap<String, CachedProfile>>,
    http_client: Client,
    default_ttl: Duration,
}

impl ProfileCache {
    pub fn new(default_ttl: Duration) -> Self {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("stateset-ucp-handler/0.1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            cache: RwLock::new(HashMap::new()),
            http_client,
            default_ttl,
        }
    }

    /// Fetches a platform profile, using cache if available
    pub async fn fetch_profile(&self, profile_url: &str) -> Result<PlatformProfile, NegotiationError> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(profile_url) {
                if !cached.is_expired() {
                    debug!("Using cached profile for {}", profile_url);
                    return Ok(cached.profile.clone());
                }
            }
        }

        // Fetch from remote
        debug!("Fetching platform profile from {}", profile_url);
        let response = self
            .http_client
            .get(profile_url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| NegotiationError::HttpError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(NegotiationError::ProfileFetchError(format!(
                "HTTP {} from {}",
                response.status(),
                profile_url
            )));
        }

        // Parse cache-control for TTL
        let ttl = parse_cache_control(response.headers().get("cache-control"))
            .unwrap_or(self.default_ttl);

        let discovery: DiscoveryDocument = response
            .json()
            .await
            .map_err(|e| NegotiationError::InvalidProfile(e.to_string()))?;

        let profile = PlatformProfile {
            version: discovery.ucp.version.clone(),
            capabilities: discovery.ucp.capabilities.clone(),
            payment_handlers: discovery
                .payment
                .map(|p| p.handlers)
                .unwrap_or_default(),
            signing_keys: discovery.signing_keys.unwrap_or_default(),
            order_webhook_url: extract_order_webhook_url(&discovery.ucp.capabilities),
        };

        // Store in cache
        {
            let mut cache = self.cache.write().await;
            cache.insert(
                profile_url.to_string(),
                CachedProfile {
                    profile: profile.clone(),
                    fetched_at: Instant::now(),
                    ttl,
                },
            );
        }

        Ok(profile)
    }

    /// Clears expired entries from cache
    #[allow(dead_code)]
    pub async fn cleanup_expired(&self) {
        let mut cache = self.cache.write().await;
        cache.retain(|_, v| !v.is_expired());
    }
}

/// Parses Cache-Control header to extract max-age
fn parse_cache_control(header: Option<&reqwest::header::HeaderValue>) -> Option<Duration> {
    let value = header?.to_str().ok()?;
    for part in value.split(',') {
        let part = part.trim();
        if let Some(stripped) = part.strip_prefix("max-age=") {
            let seconds: u64 = stripped.parse().ok()?;
            return Some(Duration::from_secs(seconds));
        }
    }
    None
}

/// Extracts order webhook URL from capability config
fn extract_order_webhook_url(capabilities: &[Capability]) -> Option<String> {
    for cap in capabilities {
        if cap.name == "dev.ucp.shopping.order" {
            if let Some(config) = &cap.config {
                if let Some(url) = config.get("webhook_url") {
                    return url.as_str().map(|s| s.to_string());
                }
            }
        }
    }
    None
}

// ============================================================================
// UCP-Agent Header Parsing (RFC 8941)
// ============================================================================

/// Parses the UCP-Agent header value according to RFC 8941 Dictionary format.
///
/// Format: `profile="https://platform.example/profile.json", key=value, ...`
pub fn parse_ucp_agent(header_value: &str) -> Result<UcpAgent, NegotiationError> {
    let header_value = header_value.trim();
    if header_value.is_empty() {
        return Err(NegotiationError::InvalidUcpAgentFormat(
            "Empty header value".to_string(),
        ));
    }

    let mut profile_url = None;
    let mut params = HashMap::new();

    // Parse RFC 8941 Dictionary-like format
    // This is a simplified parser - for full compliance, use the sfv crate
    for item in split_dictionary_items(header_value) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }

        if let Some((key, value)) = parse_dictionary_item(item) {
            if key == "profile" {
                profile_url = Some(value);
            } else {
                params.insert(key, value);
            }
        }
    }

    Ok(UcpAgent { profile_url, params })
}

/// Splits dictionary items, handling quoted strings
fn split_dictionary_items(s: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;

    for (i, c) in s.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                items.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }

    if start < s.len() {
        items.push(&s[start..]);
    }

    items
}

/// Parses a single dictionary item (key=value or key="value")
fn parse_dictionary_item(item: &str) -> Option<(String, String)> {
    let eq_pos = item.find('=')?;
    let key = item[..eq_pos].trim().to_string();
    let mut value = item[eq_pos + 1..].trim();

    // Remove quotes if present
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        value = &value[1..value.len() - 1];
    }

    Some((key, value.to_string()))
}

// ============================================================================
// Capability Intersection Algorithm
// ============================================================================

/// Computes the intersection of business and platform capabilities.
///
/// Algorithm:
/// 1. For each business capability, include if platform has matching name
/// 2. Remove extensions whose parent capability isn't in intersection
/// 3. Repeat until no orphaned extensions remain
pub fn intersect_capabilities(
    business_capabilities: &[Capability],
    platform_capabilities: &[Capability],
) -> Vec<Capability> {
    // Step 1: Base intersection by name
    let platform_names: std::collections::HashSet<&str> = platform_capabilities
        .iter()
        .map(|c| c.name.as_str())
        .collect();

    let mut result: Vec<Capability> = business_capabilities
        .iter()
        .filter(|cap| platform_names.contains(cap.name.as_str()))
        .cloned()
        .collect();

    // Steps 2-3: Iteratively prune orphaned extensions
    loop {
        let before_len = result.len();

        // Collect names into an owned HashSet to avoid borrow issues with retain
        let names_in_result: std::collections::HashSet<String> =
            result.iter().map(|c| c.name.clone()).collect();

        result.retain(|cap| {
            if let Some(parent_name) = &cap.extends {
                // Extension: keep only if parent is in result
                names_in_result.contains(parent_name)
            } else {
                // Base capability: always keep
                true
            }
        });

        if result.len() == before_len {
            break; // No changes, converged
        }
    }

    result
}

/// Converts capabilities to capability refs for response metadata
pub fn capabilities_to_refs(capabilities: &[Capability]) -> Vec<CapabilityRef> {
    capabilities
        .iter()
        .map(|cap| CapabilityRef {
            name: cap.name.clone(),
            version: cap.version.clone(),
        })
        .collect()
}

// ============================================================================
// Version Negotiation
// ============================================================================

/// Validates version compatibility between platform and business.
///
/// Returns the negotiated version (platform's version) if compatible,
/// or an error if platform version is newer than business version.
pub fn validate_version(
    platform_version: &str,
    business_version: &str,
) -> Result<String, NegotiationError> {
    // Version format: YYYY-MM-DD (lexicographic comparison works)
    if platform_version <= business_version {
        Ok(platform_version.to_string())
    } else {
        Err(NegotiationError::VersionNotSupported {
            platform_version: platform_version.to_string(),
            business_version: business_version.to_string(),
        })
    }
}

// ============================================================================
// Full Negotiation Flow
// ============================================================================

/// Performs full capability negotiation given a UCP-Agent header and business capabilities.
pub async fn negotiate(
    ucp_agent_header: Option<&str>,
    business_capabilities: &[Capability],
    business_version: &str,
    profile_cache: &ProfileCache,
) -> Result<NegotiatedCapabilities, NegotiationError> {
    // If no UCP-Agent header, return all business capabilities
    let Some(header_value) = ucp_agent_header else {
        debug!("No UCP-Agent header, using all business capabilities");
        return Ok(NegotiatedCapabilities {
            version: business_version.to_string(),
            capabilities: capabilities_to_refs(business_capabilities),
            platform_signing_keys: Vec::new(),
            platform_webhook_url: None,
        });
    };

    // Parse UCP-Agent header
    let ucp_agent = parse_ucp_agent(header_value)?;

    // If no profile URL, return all business capabilities
    let Some(profile_url) = ucp_agent.profile_url else {
        debug!("No profile URL in UCP-Agent, using all business capabilities");
        return Ok(NegotiatedCapabilities {
            version: business_version.to_string(),
            capabilities: capabilities_to_refs(business_capabilities),
            platform_signing_keys: Vec::new(),
            platform_webhook_url: None,
        });
    };

    // Fetch platform profile
    let platform_profile = profile_cache.fetch_profile(&profile_url).await?;

    // Validate version compatibility
    let negotiated_version = validate_version(&platform_profile.version, business_version)?;

    // Compute capability intersection
    let active_capabilities = intersect_capabilities(
        business_capabilities,
        &platform_profile.capabilities,
    );

    // Load platform signing keys for verification
    let mut platform_signing_keys = Vec::new();
    for jwk in &platform_profile.signing_keys {
        match load_verifying_key(jwk) {
            Ok(key) => platform_signing_keys.push(key),
            Err(e) => {
                warn!("Failed to load platform signing key {}: {}", jwk.kid, e);
            }
        }
    }

    Ok(NegotiatedCapabilities {
        version: negotiated_version,
        capabilities: capabilities_to_refs(&active_capabilities),
        platform_signing_keys,
        platform_webhook_url: platform_profile.order_webhook_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ucp_agent_simple() {
        let header = r#"profile="https://example.com/profile.json""#;
        let result = parse_ucp_agent(header).unwrap();
        assert_eq!(
            result.profile_url,
            Some("https://example.com/profile.json".to_string())
        );
    }

    #[test]
    fn test_parse_ucp_agent_with_params() {
        let header = r#"profile="https://example.com/profile.json", version="2026-01-11""#;
        let result = parse_ucp_agent(header).unwrap();
        assert_eq!(
            result.profile_url,
            Some("https://example.com/profile.json".to_string())
        );
        assert_eq!(result.params.get("version"), Some(&"2026-01-11".to_string()));
    }

    #[test]
    fn test_intersect_capabilities_basic() {
        let business = vec![
            Capability {
                name: "dev.ucp.shopping.checkout".to_string(),
                version: "2026-01-11".to_string(),
                spec: "https://ucp.dev/spec".to_string(),
                schema: "https://ucp.dev/schema".to_string(),
                extends: None,
                config: None,
            },
            Capability {
                name: "dev.ucp.shopping.fulfillment".to_string(),
                version: "2026-01-11".to_string(),
                spec: "https://ucp.dev/spec".to_string(),
                schema: "https://ucp.dev/schema".to_string(),
                extends: Some("dev.ucp.shopping.checkout".to_string()),
                config: None,
            },
            Capability {
                name: "dev.ucp.shopping.order".to_string(),
                version: "2026-01-11".to_string(),
                spec: "https://ucp.dev/spec".to_string(),
                schema: "https://ucp.dev/schema".to_string(),
                extends: None,
                config: None,
            },
        ];

        let platform = vec![
            Capability {
                name: "dev.ucp.shopping.checkout".to_string(),
                version: "2026-01-11".to_string(),
                spec: "https://ucp.dev/spec".to_string(),
                schema: "https://ucp.dev/schema".to_string(),
                extends: None,
                config: None,
            },
            Capability {
                name: "dev.ucp.shopping.fulfillment".to_string(),
                version: "2026-01-11".to_string(),
                spec: "https://ucp.dev/spec".to_string(),
                schema: "https://ucp.dev/schema".to_string(),
                extends: Some("dev.ucp.shopping.checkout".to_string()),
                config: None,
            },
        ];

        let result = intersect_capabilities(&business, &platform);

        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|c| c.name == "dev.ucp.shopping.checkout"));
        assert!(result.iter().any(|c| c.name == "dev.ucp.shopping.fulfillment"));
        assert!(!result.iter().any(|c| c.name == "dev.ucp.shopping.order"));
    }

    #[test]
    fn test_intersect_capabilities_orphaned_extension() {
        // Platform has extension but not its parent
        let business = vec![
            Capability {
                name: "dev.ucp.shopping.checkout".to_string(),
                version: "2026-01-11".to_string(),
                spec: "".to_string(),
                schema: "".to_string(),
                extends: None,
                config: None,
            },
            Capability {
                name: "dev.ucp.shopping.fulfillment".to_string(),
                version: "2026-01-11".to_string(),
                spec: "".to_string(),
                schema: "".to_string(),
                extends: Some("dev.ucp.shopping.checkout".to_string()),
                config: None,
            },
        ];

        let platform = vec![Capability {
            name: "dev.ucp.shopping.fulfillment".to_string(),
            version: "2026-01-11".to_string(),
            spec: "".to_string(),
            schema: "".to_string(),
            extends: Some("dev.ucp.shopping.checkout".to_string()),
            config: None,
        }];

        let result = intersect_capabilities(&business, &platform);

        // Fulfillment should be pruned because checkout (its parent) is not in intersection
        assert!(result.is_empty());
    }

    #[test]
    fn test_version_validation() {
        // Platform version <= business version: OK
        assert!(validate_version("2026-01-11", "2026-01-11").is_ok());
        assert!(validate_version("2025-01-01", "2026-01-11").is_ok());

        // Platform version > business version: Error
        assert!(validate_version("2027-01-01", "2026-01-11").is_err());
    }
}
