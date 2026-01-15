//! Order lifecycle management APIs.
//!
//! Implements the UCP Order capability for post-checkout order management:
//! - Order retrieval
//! - Fulfillment event tracking
//! - Order adjustments (refunds, returns, credits)
//!
//! Hybrid storage using iCommerce Orders for persistence and in-memory cache
//! for UCP-specific metadata that doesn't map directly to iCommerce Order fields.

// Public API for order lifecycle management - used by consumers of this crate
#![allow(dead_code)]

use crate::commerce::CommerceEngine;
use crate::commerce_adapter::{decimal_to_cents, parse_order_id};
use crate::errors::ServiceError;
use crate::models::{Order, UcpResponseMeta, CapabilityRef, OrderLineItem, OrderQuantity, Total, ItemResponse, OrderFulfillment};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Hybrid order storage with iCommerce persistence and in-memory cache
#[derive(Clone)]
pub struct OrderStore {
    /// iCommerce engine for order persistence
    commerce: Option<CommerceEngine>,
    /// In-memory cache for UCP Order objects
    orders: Arc<RwLock<HashMap<String, Order>>>,
}

impl OrderStore {
    /// Create a new OrderStore with iCommerce backend
    pub fn new_with_commerce(commerce: CommerceEngine) -> Self {
        Self {
            commerce: Some(commerce),
            orders: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create an in-memory only store (for testing or legacy mode)
    pub fn new() -> Self {
        Self {
            commerce: None,
            orders: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Insert an order into the store
    ///
    /// Stores in cache and syncs to iCommerce for persistence
    pub async fn insert(&self, order: Order) {
        let order_id = order.id.clone();

        // Store in cache
        {
            let mut orders = self.orders.write().await;
            orders.insert(order_id.clone(), order.clone());
        }

        // Sync to iCommerce if available
        if let Some(ref commerce) = self.commerce {
            if let Err(e) = self.sync_to_icommerce(commerce, &order) {
                tracing::warn!("Failed to sync order to iCommerce: {}", e);
            }
        }
    }

    /// Get an order by ID
    ///
    /// First checks cache, then falls back to iCommerce
    pub async fn get(&self, order_id: &str) -> Option<Order> {
        // Fast path: check cache
        {
            let orders = self.orders.read().await;
            if let Some(order) = orders.get(order_id) {
                return Some(order.clone());
            }
        }

        // Slow path: try iCommerce
        if let Some(ref commerce) = self.commerce {
            if let Some(order) = self.load_from_icommerce(commerce, order_id) {
                // Re-populate cache
                let mut orders = self.orders.write().await;
                orders.insert(order_id.to_string(), order.clone());
                return Some(order);
            }
        }

        None
    }

    /// Update an order in the store
    pub async fn update(&self, order: Order) {
        let order_id = order.id.clone();

        // Update cache
        {
            let mut orders = self.orders.write().await;
            orders.insert(order_id.clone(), order.clone());
        }

        // Sync to iCommerce if available
        if let Some(ref commerce) = self.commerce {
            if let Err(e) = self.update_icommerce_order(commerce, &order) {
                tracing::warn!("Failed to update order in iCommerce: {}", e);
            }
        }
    }

    /// Sync UCP order to iCommerce
    fn sync_to_icommerce(&self, commerce: &CommerceEngine, order: &Order) -> Result<(), String> {
        use stateset_embedded::{CreateOrder, CreateOrderItem};

        // Parse order ID to UUID
        let uuid = parse_order_id(&order.id)
            .ok_or_else(|| "Invalid order ID format".to_string())?;

        // Check if order already exists
        if commerce.orders().get(uuid).map_err(|e| e.to_string())?.is_some() {
            // Order exists, update it
            return self.update_icommerce_order(commerce, order);
        }

        // Build order items
        // Note: iCommerce requires product_id as Uuid, we use nil() as placeholder
        // since UCP line items may not have a product_id
        let items: Vec<CreateOrderItem> = order.line_items.iter().map(|li| {
            CreateOrderItem {
                product_id: Uuid::nil(), // UCP doesn't require product_id
                variant_id: None,
                sku: li.item.id.clone(),
                name: li.item.title.clone(),
                quantity: li.quantity.total,
                unit_price: crate::commerce_adapter::cents_to_decimal(li.item.price),
                discount: None,
                tax_amount: None,
            }
        }).collect();

        // Create order in iCommerce
        // Note: iCommerce requires a customer_id, we use nil() as placeholder
        let create_request = CreateOrder {
            customer_id: Uuid::nil(), // UCP orders may not have customer_id
            items,
            currency: Some("USD".to_string()),
            notes: None,
            shipping_address: None,
            billing_address: None,
            payment_method: None,
            shipping_method: None,
        };

        match commerce.orders().create(create_request) {
            Ok(_created) => Ok(()),
            Err(e) => {
                tracing::debug!("Could not create order in iCommerce: {}", e);
                Ok(()) // Not a fatal error - we have the cache
            }
        }
    }

    /// Update an existing order in iCommerce
    fn update_icommerce_order(&self, commerce: &CommerceEngine, order: &Order) -> Result<(), String> {
        use stateset_embedded::{UpdateOrder, FulfillmentStatus as IcFulfillmentStatus};

        let uuid = parse_order_id(&order.id)
            .ok_or_else(|| "Invalid order ID format".to_string())?;

        // Map UCP fulfillment status to iCommerce status
        let fulfillment_status = if order.line_items.iter().all(|li| li.status == "fulfilled") {
            Some(IcFulfillmentStatus::Fulfilled)
        } else if order.line_items.iter().any(|li| li.status == "partial") {
            Some(IcFulfillmentStatus::PartiallyFulfilled)
        } else {
            None
        };

        // Extract tracking number from fulfillment events
        let tracking_number = order.fulfillment.events.as_ref().and_then(|events| {
            events
                .iter()
                .filter_map(|e| {
                    e.get("tracking_number")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .next_back()
        });

        let update = UpdateOrder {
            fulfillment_status,
            tracking_number,
            ..Default::default()
        };

        commerce.orders().update(uuid, update)
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Load order from iCommerce and convert to UCP format
    fn load_from_icommerce(&self, commerce: &CommerceEngine, order_id: &str) -> Option<Order> {
        let uuid = parse_order_id(order_id)?;
        let ic_order = commerce.orders().get(uuid).ok()??;

        // Convert iCommerce order to UCP Order
        let line_items: Vec<OrderLineItem> = ic_order.items.iter().map(|item| {
            // Determine fulfilled quantity based on order fulfillment status
            let fulfilled_qty = match ic_order.fulfillment_status {
                stateset_embedded::FulfillmentStatus::Fulfilled => item.quantity,
                stateset_embedded::FulfillmentStatus::PartiallyFulfilled => item.quantity / 2, // Estimate
                _ => 0,
            };

            OrderLineItem {
                id: format!("li_{}", item.id),
                item: ItemResponse {
                    id: item.sku.clone(),
                    title: item.name.clone(),
                    price: decimal_to_cents(item.unit_price),
                    image_url: None, // iCommerce OrderItem doesn't have image_url
                    extra: HashMap::new(),
                },
                quantity: OrderQuantity {
                    total: item.quantity,
                    fulfilled: fulfilled_qty,
                },
                totals: vec![Total {
                    total_type: "total".to_string(),
                    display_text: Some("Total".to_string()),
                    amount: decimal_to_cents(item.total),
                }],
                status: match ic_order.fulfillment_status {
                    stateset_embedded::FulfillmentStatus::Fulfilled => "fulfilled".to_string(),
                    stateset_embedded::FulfillmentStatus::PartiallyFulfilled => "partial".to_string(),
                    _ => "processing".to_string(),
                },
                parent_id: None,
                extra: HashMap::new(),
            }
        }).collect();

        let totals = vec![Total {
            total_type: "total".to_string(),
            display_text: Some("Total".to_string()),
            amount: decimal_to_cents(ic_order.total_amount),
        }];

        Some(Order {
            ucp: UcpResponseMeta {
                version: "2026-01-11".to_string(),
                capabilities: vec![CapabilityRef {
                    name: "dev.ucp.shopping.order".to_string(),
                    version: "2026-01-11".to_string(),
                }],
            },
            id: order_id.to_string(),
            checkout_id: format!("chk_{}", ic_order.id), // Best guess
            permalink_url: format!("https://example.com/orders/{}", order_id),
            line_items,
            fulfillment: OrderFulfillment {
                expectations: None,
                events: None,
            },
            totals,
            adjustments: None,
            extra: HashMap::new(),
        })
    }
}

impl Default for OrderStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Request to add a fulfillment event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FulfillmentEventRequest {
    /// Event type (e.g., "processing", "shipped", "in_transit", "delivered")
    #[serde(rename = "type")]
    pub event_type: String,
    /// Line items affected by this event
    pub line_items: Vec<FulfillmentLineItem>,
    /// Optional tracking information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracking: Option<TrackingInfo>,
    /// Optional description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Line item reference with quantity for fulfillment events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FulfillmentLineItem {
    pub id: String,
    pub quantity: i32,
}

/// Tracking information for shipments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackingInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracking_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracking_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub carrier: Option<String>,
}

/// Request to add an adjustment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdjustmentRequest {
    /// Adjustment type (e.g., "refund", "return", "credit", "cancellation")
    #[serde(rename = "type")]
    pub adjustment_type: String,
    /// Affected line items (optional, for order-level adjustments)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_items: Option<Vec<FulfillmentLineItem>>,
    /// Amount in minor units (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<i64>,
    /// Reason/description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Status (e.g., "pending", "completed")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Fulfillment event stored in order
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FulfillmentEvent {
    pub id: String,
    pub occurred_at: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub line_items: Vec<FulfillmentLineItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracking_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracking_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub carrier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Adjustment stored in order
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Adjustment {
    pub id: String,
    #[serde(rename = "type")]
    pub adjustment_type: String,
    pub occurred_at: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_items: Option<Vec<FulfillmentLineItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Order service for lifecycle management
#[derive(Clone)]
pub struct OrderService {
    store: OrderStore,
    ucp_version: String,
    base_url: String,
}

impl OrderService {
    pub fn new(store: OrderStore, ucp_version: String, base_url: String) -> Self {
        Self {
            store,
            ucp_version,
            base_url,
        }
    }

    pub async fn insert_order(&self, order: Order) {
        let mut order = order;
        self.apply_ucp_meta(&mut order);
        self.store.insert(order).await;
    }

    /// Gets an order by ID
    pub async fn get_order(&self, order_id: &str) -> Result<Order, ServiceError> {
        let mut order = self.store
            .get(order_id)
            .await
            .ok_or_else(|| ServiceError::NotFound(format!("Order {} not found", order_id)))?;
        self.apply_ucp_meta(&mut order);
        Ok(order)
    }

    /// Adds a fulfillment event to an order
    pub async fn add_fulfillment_event(
        &self,
        order_id: &str,
        request: FulfillmentEventRequest,
    ) -> Result<Order, ServiceError> {
        let mut order = self.get_order(order_id).await?;
        self.validate_fulfillment_request(&order, &request)?;

        // Create the fulfillment event
        let event = FulfillmentEvent {
            id: format!("fev_{}", Uuid::new_v4()),
            occurred_at: Utc::now().to_rfc3339(),
            event_type: request.event_type.clone(),
            line_items: request.line_items.clone(),
            tracking_number: request.tracking.as_ref().and_then(|t| t.tracking_number.clone()),
            tracking_url: request.tracking.as_ref().and_then(|t| t.tracking_url.clone()),
            carrier: request.tracking.as_ref().and_then(|t| t.carrier.clone()),
            description: request.description,
        };

        // Add to fulfillment events (append-only)
        let event_json = serde_json::to_value(&event).unwrap_or_default();

        if order.fulfillment.events.is_none() {
            order.fulfillment.events = Some(Vec::new());
        }
        if let Some(events) = order.fulfillment.events.as_mut() {
            events.push(event_json);
        }

        // Update line item quantities based on event type
        if request.event_type == "delivered" || request.event_type == "shipped" {
            self.update_line_item_quantities(&mut order, &request.line_items);
        }

        // Update order in store
        self.store.update(order.clone()).await;

        Ok(order)
    }

    /// Adds an adjustment to an order
    pub async fn add_adjustment(
        &self,
        order_id: &str,
        request: AdjustmentRequest,
    ) -> Result<Order, ServiceError> {
        let mut order = self.get_order(order_id).await?;
        self.validate_adjustment_request(&order, &request)?;

        // Create the adjustment
        let adjustment = Adjustment {
            id: format!("adj_{}", Uuid::new_v4()),
            adjustment_type: request.adjustment_type,
            occurred_at: Utc::now().to_rfc3339(),
            status: request.status.unwrap_or_else(|| "completed".to_string()),
            line_items: request.line_items,
            amount: request.amount,
            description: request.description,
        };

        // Add to adjustments (append-only)
        let adjustment_json = serde_json::to_value(&adjustment).unwrap_or_default();

        if order.adjustments.is_none() {
            order.adjustments = Some(Vec::new());
        }
        if let Some(adjustments) = order.adjustments.as_mut() {
            adjustments.push(adjustment_json);
        }

        // Update order in store
        self.store.update(order.clone()).await;

        Ok(order)
    }

    /// Updates line item fulfilled quantities
    fn update_line_item_quantities(&self, order: &mut Order, fulfilled_items: &[FulfillmentLineItem]) {
        for fulfilled in fulfilled_items {
            if let Some(line_item) = order.line_items.iter_mut().find(|li| li.id == fulfilled.id) {
                // Update fulfilled quantity
                let new_fulfilled = line_item.quantity.fulfilled + fulfilled.quantity;
                line_item.quantity.fulfilled = new_fulfilled.min(line_item.quantity.total);

                // Update status based on quantities
                if line_item.quantity.fulfilled >= line_item.quantity.total {
                    line_item.status = "fulfilled".to_string();
                } else if line_item.quantity.fulfilled > 0 {
                    line_item.status = "partial".to_string();
                }
            }
        }
    }

    fn apply_ucp_meta(&self, order: &mut Order) {
        order.ucp.version = self.ucp_version.clone();
        for cap in order.ucp.capabilities.iter_mut() {
            cap.version = self.ucp_version.clone();
        }

        let base_url = self.base_url.trim_end_matches('/');
        let has_placeholder = order
            .permalink_url
            .starts_with("https://example.com/orders/");
        if !base_url.is_empty()
            && (order.permalink_url.trim().is_empty() || has_placeholder)
        {
            order.permalink_url = format!("{}/orders/{}", base_url, order.id);
        }
    }

    fn validate_fulfillment_request(
        &self,
        order: &Order,
        request: &FulfillmentEventRequest,
    ) -> Result<(), ServiceError> {
        if request.event_type.trim().is_empty() {
            return Err(ServiceError::InvalidInput(
                "fulfillment event type is required".to_string(),
            ));
        }

        self.validate_line_item_refs(order, &request.line_items)
    }

    fn validate_adjustment_request(
        &self,
        order: &Order,
        request: &AdjustmentRequest,
    ) -> Result<(), ServiceError> {
        if request.adjustment_type.trim().is_empty() {
            return Err(ServiceError::InvalidInput(
                "adjustment type is required".to_string(),
            ));
        }

        if request.amount.is_none()
            && request
                .line_items
                .as_ref()
                .map(|items| items.is_empty())
                .unwrap_or(true)
        {
            return Err(ServiceError::InvalidInput(
                "adjustment must include line_items or amount".to_string(),
            ));
        }

        if let Some(items) = request.line_items.as_ref() {
            self.validate_line_item_refs(order, items)?;
        }

        if let Some(amount) = request.amount {
            if amount < 0 {
                return Err(ServiceError::InvalidInput(
                    "adjustment amount must be positive".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn validate_line_item_refs(
        &self,
        order: &Order,
        items: &[FulfillmentLineItem],
    ) -> Result<(), ServiceError> {
        if items.is_empty() {
            return Err(ServiceError::InvalidInput(
                "line_items must contain at least one item".to_string(),
            ));
        }

        let mut seen = HashSet::new();
        for item in items {
            if item.id.trim().is_empty() {
                return Err(ServiceError::InvalidInput(
                    "line_items.id is required".to_string(),
                ));
            }
            if item.quantity <= 0 {
                return Err(ServiceError::InvalidInput(
                    "line_items.quantity must be greater than 0".to_string(),
                ));
            }
            if !seen.insert(item.id.as_str()) {
                return Err(ServiceError::InvalidInput(format!(
                    "duplicate line_item id {}",
                    item.id
                )));
            }
            if !order.line_items.iter().any(|li| li.id == item.id) {
                return Err(ServiceError::InvalidInput(format!(
                    "line_item {} not found on order",
                    item.id
                )));
            }
        }

        Ok(())
    }

    /// Response metadata for order capability
    pub fn order_meta(&self) -> UcpResponseMeta {
        UcpResponseMeta {
            version: self.ucp_version.clone(),
            capabilities: vec![CapabilityRef {
                name: "dev.ucp.shopping.order".to_string(),
                version: self.ucp_version.clone(),
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ItemResponse, OrderFulfillment, OrderLineItem, OrderQuantity, Total};

    fn create_test_order() -> Order {
        Order {
            ucp: UcpResponseMeta {
                version: "2026-01-11".to_string(),
                capabilities: vec![CapabilityRef {
                    name: "dev.ucp.shopping.order".to_string(),
                    version: "2026-01-11".to_string(),
                }],
            },
            id: "order_123".to_string(),
            checkout_id: "chk_123".to_string(),
            permalink_url: "https://example.com/orders/order_123".to_string(),
            line_items: vec![
                OrderLineItem {
                    id: "li_1".to_string(),
                    item: ItemResponse {
                        id: "prod_1".to_string(),
                        title: "Test Product".to_string(),
                        price: 1000,
                        image_url: None,
                        extra: HashMap::new(),
                    },
                    quantity: OrderQuantity {
                        total: 2,
                        fulfilled: 0,
                    },
                    totals: vec![Total {
                        total_type: "total".to_string(),
                        display_text: Some("Total".to_string()),
                        amount: 2000,
                    }],
                    status: "processing".to_string(),
                    parent_id: None,
                    extra: HashMap::new(),
                },
            ],
            fulfillment: OrderFulfillment {
                expectations: None,
                events: None,
            },
            totals: vec![Total {
                total_type: "total".to_string(),
                display_text: Some("Total".to_string()),
                amount: 2000,
            }],
            adjustments: None,
            extra: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_add_fulfillment_event() {
        let store = OrderStore::new();
        let order = create_test_order();
        store.insert(order).await;

        let service = OrderService::new(
            store,
            "2026-01-11".to_string(),
            "https://example.com".to_string(),
        );

        let request = FulfillmentEventRequest {
            event_type: "shipped".to_string(),
            line_items: vec![FulfillmentLineItem {
                id: "li_1".to_string(),
                quantity: 1,
            }],
            tracking: Some(TrackingInfo {
                tracking_number: Some("123456".to_string()),
                tracking_url: Some("https://track.example.com/123456".to_string()),
                carrier: Some("UPS".to_string()),
            }),
            description: Some("Shipped via UPS".to_string()),
        };

        let updated = service.add_fulfillment_event("order_123", request).await.unwrap();

        assert!(updated.fulfillment.events.is_some());
        let events = updated.fulfillment.events.unwrap();
        assert_eq!(events.len(), 1);

        // Line item should be partially fulfilled
        assert_eq!(updated.line_items[0].quantity.fulfilled, 1);
        assert_eq!(updated.line_items[0].status, "partial");
    }

    #[tokio::test]
    async fn test_add_adjustment() {
        let store = OrderStore::new();
        let order = create_test_order();
        store.insert(order).await;

        let service = OrderService::new(
            store,
            "2026-01-11".to_string(),
            "https://example.com".to_string(),
        );

        let request = AdjustmentRequest {
            adjustment_type: "refund".to_string(),
            line_items: Some(vec![FulfillmentLineItem {
                id: "li_1".to_string(),
                quantity: 1,
            }]),
            amount: Some(1000),
            description: Some("Customer requested refund".to_string()),
            status: Some("completed".to_string()),
        };

        let updated = service.add_adjustment("order_123", request).await.unwrap();

        assert!(updated.adjustments.is_some());
        let adjustments = updated.adjustments.unwrap();
        assert_eq!(adjustments.len(), 1);
    }

    #[tokio::test]
    async fn test_rejects_duplicate_line_items() {
        let store = OrderStore::new();
        let order = create_test_order();
        store.insert(order).await;

        let service = OrderService::new(
            store,
            "2026-01-11".to_string(),
            "https://example.com".to_string(),
        );

        let request = FulfillmentEventRequest {
            event_type: "shipped".to_string(),
            line_items: vec![
                FulfillmentLineItem {
                    id: "li_1".to_string(),
                    quantity: 1,
                },
                FulfillmentLineItem {
                    id: "li_1".to_string(),
                    quantity: 1,
                },
            ],
            tracking: None,
            description: None,
        };

        let result = service.add_fulfillment_event("order_123", request).await;
        assert!(matches!(result, Err(ServiceError::InvalidInput(_))));
    }

    #[tokio::test]
    async fn test_adjustment_requires_amount_or_line_items() {
        let store = OrderStore::new();
        let order = create_test_order();
        store.insert(order).await;

        let service = OrderService::new(
            store,
            "2026-01-11".to_string(),
            "https://example.com".to_string(),
        );

        let request = AdjustmentRequest {
            adjustment_type: "refund".to_string(),
            line_items: None,
            amount: None,
            description: Some("missing fields".to_string()),
            status: None,
        };

        let result = service.add_adjustment("order_123", request).await;
        assert!(matches!(result, Err(ServiceError::InvalidInput(_))));
    }

    #[tokio::test]
    async fn test_permalink_updated_from_placeholder() {
        let store = OrderStore::new();
        let mut order = create_test_order();
        order.permalink_url = "https://example.com/orders/order_123".to_string();
        store.insert(order).await;

        let service = OrderService::new(
            store,
            "2026-01-11".to_string(),
            "https://merchant.test".to_string(),
        );

        let fetched = service.get_order("order_123").await.unwrap();
        assert_eq!(
            fetched.permalink_url,
            "https://merchant.test/orders/order_123"
        );
    }
}
