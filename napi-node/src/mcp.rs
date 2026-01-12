//! Node.js bindings for MCP (Model Context Protocol) handler

use crate::error::json_error;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use stateset_ucp_lib::catalog::ProductCatalog;
use stateset_ucp_lib::events::{Event, EventSender};
use stateset_ucp_lib::mcp::{JsonRpcRequest, McpHandler as RustMcpHandler, openrpc_schema};
use stateset_ucp_lib::service::CheckoutService;
use stateset_ucp_lib::store::CheckoutStore;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Configuration for McpHandler
#[napi(object)]
pub struct McpHandlerConfig {
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

/// MCP (Model Context Protocol) handler for UCP checkout operations
///
/// Implements JSON-RPC 2.0 transport for AI agent integration
#[napi]
pub struct McpHandler {
    inner: Arc<RwLock<RustMcpHandler>>,
}

#[napi]
impl McpHandler {
    /// Creates a new McpHandler instance
    #[napi(constructor)]
    pub fn new(config: McpHandlerConfig) -> Self {
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
            config.ucp_version,
            config.service_version,
            config.base_url,
            config.session_ttl_seconds as u64,
            config.tax_bps,
            None,
            false,
            false,
            false,
            None,
            None,
        );

        let handler = RustMcpHandler::new(checkout_service);

        Self {
            inner: Arc::new(RwLock::new(handler)),
        }
    }

    /// Handles a JSON-RPC request and returns a response
    ///
    /// @param requestJson - JSON string of JSON-RPC 2.0 request
    /// @returns JSON string of JSON-RPC 2.0 response
    #[napi]
    pub async fn handle(&self, request_json: String) -> Result<String> {
        let request: JsonRpcRequest = serde_json::from_str(&request_json).map_err(json_error)?;

        let handler = self.inner.read().await;
        let response = handler.handle(request).await;

        serde_json::to_string(&response).map_err(json_error)
    }
}

/// Returns the MCP OpenRPC schema document
///
/// @returns JSON string of the OpenRPC schema
#[napi]
pub fn mcp_openrpc_schema() -> Result<String> {
    let schema = openrpc_schema();
    serde_json::to_string(&schema).map_err(json_error)
}
