//! Node.js bindings for CheckoutService

use crate::error::{json_error, to_napi_error};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use stateset_ucp_lib::catalog::ProductCatalog;
use stateset_ucp_lib::events::{Event, EventSender};
use stateset_ucp_lib::models::{CheckoutCompleteRequest, CheckoutCreateRequest, CheckoutUpdateRequest};
use stateset_ucp_lib::service::CheckoutService as RustCheckoutService;
use stateset_ucp_lib::store::CheckoutStore;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Configuration for CheckoutService
#[napi(object)]
pub struct CheckoutServiceConfig {
    /// UCP protocol version
    pub ucp_version: String,
    /// Service version
    pub service_version: String,
    /// Base URL for the service
    pub base_url: String,
    /// Session TTL in seconds
    pub session_ttl_seconds: i64,
    /// Tax rate in basis points (e.g., 825 = 8.25%)
    pub tax_bps: i64,
    /// Enable identity linking capability
    #[napi(js_name = "identityLinkingEnabled")]
    pub identity_linking_enabled: Option<bool>,
    /// Enable buyer consent capability
    #[napi(js_name = "buyerConsentEnabled")]
    pub buyer_consent_enabled: Option<bool>,
    /// Enable AP2 mandate capability
    #[napi(js_name = "ap2Enabled")]
    pub ap2_enabled: Option<bool>,
    /// Static AP2 merchant authorization (optional)
    #[napi(js_name = "ap2MerchantAuthorization")]
    pub ap2_merchant_authorization: Option<String>,
}

/// Node.js wrapper for the UCP CheckoutService
#[napi]
pub struct CheckoutService {
    inner: Arc<RwLock<RustCheckoutService>>,
}

#[napi]
impl CheckoutService {
    /// Creates a new CheckoutService instance
    #[napi(constructor)]
    pub fn new(config: CheckoutServiceConfig) -> Self {
        // Create internal dependencies
        let store = CheckoutStore::new();
        let catalog = ProductCatalog::new();

        // Create event channel (events are dropped but we need the sender)
        let (tx, mut rx) = mpsc::channel::<Event>(100);
        // Spawn a task to receive events (prevents channel from blocking)
        tokio::spawn(async move {
            while let Some(_event) = rx.recv().await {
                // Events could be forwarded to Node.js callbacks in the future
            }
        });
        let event_sender = EventSender::new(tx);

        let service = RustCheckoutService::new(
            store,
            catalog,
            None,
            event_sender,
            config.ucp_version,
            config.service_version,
            config.base_url,
            config.session_ttl_seconds as u64,
            config.tax_bps,
            None, // signing_keys
            config.identity_linking_enabled.unwrap_or(false),
            config.buyer_consent_enabled.unwrap_or(false),
            false,
            false,
            false,
            config.ap2_enabled.unwrap_or(false),
            config.ap2_merchant_authorization,
            None, // ap2_signing_key
            None, // ap2_mandate_verifier
        );

        Self {
            inner: Arc::new(RwLock::new(service)),
        }
    }

    /// Creates a new checkout session
    ///
    /// @param requestJson - JSON string of CheckoutCreateRequest
    /// @returns JSON string of CheckoutResponse
    #[napi]
    pub async fn create_checkout(&self, request_json: String) -> Result<String> {
        let request: CheckoutCreateRequest =
            serde_json::from_str(&request_json).map_err(json_error)?;

        let service = self.inner.read().await;
        let response = service.create_checkout(request).await.map_err(to_napi_error)?;

        serde_json::to_string(&response).map_err(json_error)
    }

    /// Gets an existing checkout session by ID
    ///
    /// @param checkoutId - The checkout session ID
    /// @returns JSON string of CheckoutResponse
    #[napi]
    pub async fn get_checkout(&self, checkout_id: String) -> Result<String> {
        let service = self.inner.read().await;
        let response = service.get_checkout(&checkout_id).await.map_err(to_napi_error)?;

        serde_json::to_string(&response).map_err(json_error)
    }

    /// Updates an existing checkout session
    ///
    /// @param checkoutId - The checkout session ID
    /// @param requestJson - JSON string of CheckoutUpdateRequest
    /// @returns JSON string of CheckoutResponse
    #[napi]
    pub async fn update_checkout(
        &self,
        checkout_id: String,
        request_json: String,
    ) -> Result<String> {
        let request: CheckoutUpdateRequest =
            serde_json::from_str(&request_json).map_err(json_error)?;

        let service = self.inner.read().await;
        let response = service
            .update_checkout(&checkout_id, request)
            .await
            .map_err(to_napi_error)?;

        serde_json::to_string(&response).map_err(json_error)
    }

    /// Completes a checkout session and creates an order
    ///
    /// @param checkoutId - The checkout session ID
    /// @param requestJson - JSON string of CheckoutCompleteRequest
    /// @returns JSON string of CheckoutResponse
    #[napi]
    pub async fn complete_checkout(
        &self,
        checkout_id: String,
        request_json: String,
    ) -> Result<String> {
        let request: CheckoutCompleteRequest =
            serde_json::from_str(&request_json).map_err(json_error)?;

        let service = self.inner.read().await;
        let response = service
            .complete_checkout(&checkout_id, request)
            .await
            .map_err(to_napi_error)?;

        serde_json::to_string(&response).map_err(json_error)
    }

    /// Cancels a checkout session
    ///
    /// @param checkoutId - The checkout session ID
    /// @returns JSON string of CheckoutResponse
    #[napi]
    pub async fn cancel_checkout(&self, checkout_id: String) -> Result<String> {
        let service = self.inner.read().await;
        let response = service.cancel_checkout(&checkout_id).await.map_err(to_napi_error)?;

        serde_json::to_string(&response).map_err(json_error)
    }

    /// Returns the UCP discovery document
    ///
    /// @returns JSON string of DiscoveryDocument
    #[napi]
    pub async fn discovery_document(&self) -> Result<String> {
        let service = self.inner.read().await;
        let document = service.discovery_document();

        serde_json::to_string(&document).map_err(json_error)
    }
}
