//! Node.js bindings for A2A (Agent-to-Agent) handler

use crate::error::json_error;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use stateset_ucp_lib::a2a::{A2AHandler as RustA2AHandler, A2AMessage};
use stateset_ucp_lib::catalog::ProductCatalog;
use stateset_ucp_lib::events::{Event, EventSender};
use stateset_ucp_lib::service::CheckoutService;
use stateset_ucp_lib::store::CheckoutStore;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Configuration for A2AHandler
#[napi(object)]
pub struct A2AHandlerConfig {
    /// UCP protocol version
    pub ucp_version: String,
    /// Service version
    pub service_version: String,
    /// Base URL for the service
    pub base_url: String,
    /// Session TTL in seconds
    pub session_ttl_seconds: i64,
    /// Tax rate in basis points
    pub tax_bps: i64,
}

/// A2A (Agent-to-Agent) handler for UCP checkout operations
///
/// Implements the Google A2A protocol for agent communication
#[napi]
pub struct A2AHandler {
    inner: Arc<RwLock<RustA2AHandler>>,
}

#[napi]
impl A2AHandler {
    /// Creates a new A2AHandler instance
    #[napi(constructor)]
    pub fn new(config: A2AHandlerConfig) -> Self {
        // Create internal dependencies
        let store = CheckoutStore::new();
        let catalog = ProductCatalog::new();

        // Create event channel
        let (tx, mut rx) = mpsc::channel::<Event>(100);
        tokio::spawn(async move {
            while let Some(_event) = rx.recv().await {}
        });
        let event_sender = EventSender::new(tx);

        let checkout_service = CheckoutService::new(
            store,
            catalog,
            event_sender,
            config.ucp_version.clone(),
            config.service_version,
            config.base_url.clone(),
            config.session_ttl_seconds as u64,
            config.tax_bps,
            None,
            false,
            false,
            false,
            None,
            None,
        );

        let handler = RustA2AHandler::new(checkout_service, config.base_url, config.ucp_version);

        Self {
            inner: Arc::new(RwLock::new(handler)),
        }
    }

    /// Returns the agent card describing this agent's capabilities
    ///
    /// @returns JSON string of the AgentCard
    #[napi]
    pub async fn agent_card(&self) -> Result<String> {
        let handler = self.inner.read().await;
        let card = handler.agent_card();
        serde_json::to_string(&card).map_err(json_error)
    }

    /// Handles an A2A message and returns a response
    ///
    /// @param messageJson - JSON string of A2A message
    /// @returns JSON string of A2A response
    #[napi]
    pub async fn handle(&self, message_json: String) -> Result<String> {
        let message: A2AMessage = serde_json::from_str(&message_json).map_err(json_error)?;

        let handler = self.inner.read().await;
        let response = handler.handle(message).await;

        serde_json::to_string(&response).map_err(json_error)
    }
}
