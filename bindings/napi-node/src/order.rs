//! Node.js bindings for OrderService

use crate::error::{json_error, to_napi_error};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use stateset_ucp_lib::order_api::{
    AdjustmentRequest, FulfillmentEventRequest, OrderService as RustOrderService, OrderStore,
};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Configuration for OrderService
#[napi(object)]
pub struct OrderServiceConfig {
    /// UCP protocol version
    pub ucp_version: String,
    /// Base URL used to construct order permalinks
    pub base_url: Option<String>,
}

/// Order service for post-checkout order lifecycle management
///
/// Handles order retrieval, fulfillment events, and adjustments
#[napi]
pub struct OrderService {
    inner: Arc<RwLock<RustOrderService>>,
}

#[napi]
impl OrderService {
    /// Creates a new OrderService instance
    #[napi(constructor)]
    pub fn new(config: OrderServiceConfig) -> Self {
        let store = OrderStore::new();
        let base_url = config
            .base_url
            .unwrap_or_else(|| "http://127.0.0.1:8081".to_string());
        let service = RustOrderService::new(store.clone(), config.ucp_version, base_url);

        Self {
            inner: Arc::new(RwLock::new(service)),
        }
    }

    /// Gets an order by ID
    ///
    /// @param orderId - The order ID
    /// @returns JSON string of Order
    #[napi]
    pub async fn get_order(&self, order_id: String) -> Result<String> {
        let service = self.inner.read().await;
        let order = service.get_order(&order_id).await.map_err(to_napi_error)?;

        serde_json::to_string(&order).map_err(json_error)
    }

    /// Adds a fulfillment event to an order
    ///
    /// @param orderId - The order ID
    /// @param requestJson - JSON string of FulfillmentEventRequest
    /// @returns JSON string of updated Order
    #[napi]
    pub async fn add_fulfillment_event(
        &self,
        order_id: String,
        request_json: String,
    ) -> Result<String> {
        let request: FulfillmentEventRequest =
            serde_json::from_str(&request_json).map_err(json_error)?;

        let service = self.inner.read().await;
        let order = service
            .add_fulfillment_event(&order_id, request)
            .await
            .map_err(to_napi_error)?;

        serde_json::to_string(&order).map_err(json_error)
    }

    /// Adds an adjustment to an order (refund, return, credit, etc.)
    ///
    /// @param orderId - The order ID
    /// @param requestJson - JSON string of AdjustmentRequest
    /// @returns JSON string of updated Order
    #[napi]
    pub async fn add_adjustment(&self, order_id: String, request_json: String) -> Result<String> {
        let request: AdjustmentRequest =
            serde_json::from_str(&request_json).map_err(json_error)?;

        let service = self.inner.read().await;
        let order = service
            .add_adjustment(&order_id, request)
            .await
            .map_err(to_napi_error)?;

        serde_json::to_string(&order).map_err(json_error)
    }

    /// Stores an order in the service's order store
    ///
    /// This is useful for testing or when orders are created externally
    ///
    /// @param orderJson - JSON string of Order
    #[napi]
    pub async fn store_order(&self, order_json: String) -> Result<()> {
        let order: stateset_ucp_lib::models::Order =
            serde_json::from_str(&order_json).map_err(json_error)?;

        let service = self.inner.read().await;
        service.insert_order(order).await;
        Ok(())
    }
}
