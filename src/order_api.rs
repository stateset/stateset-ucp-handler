//! Order lifecycle management APIs.
//!
//! Implements the UCP Order capability for post-checkout order management:
//! - Order retrieval
//! - Fulfillment event tracking
//! - Order adjustments (refunds, returns, credits)

use crate::errors::ServiceError;
use crate::models::{Order, OrderFulfillment, OrderLineItem, OrderQuantity, Total, UcpResponseMeta, CapabilityRef};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Order storage with in-memory persistence
#[derive(Clone)]
pub struct OrderStore {
    orders: Arc<RwLock<HashMap<String, Order>>>,
}

impl OrderStore {
    pub fn new() -> Self {
        Self {
            orders: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn insert(&self, order: Order) {
        let mut orders = self.orders.write().await;
        orders.insert(order.id.clone(), order);
    }

    pub async fn get(&self, order_id: &str) -> Option<Order> {
        let orders = self.orders.read().await;
        orders.get(order_id).cloned()
    }

    pub async fn update(&self, order: Order) {
        let mut orders = self.orders.write().await;
        orders.insert(order.id.clone(), order);
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
}

impl OrderService {
    pub fn new(store: OrderStore, ucp_version: String) -> Self {
        Self { store, ucp_version }
    }

    /// Gets an order by ID
    pub async fn get_order(&self, order_id: &str) -> Result<Order, ServiceError> {
        self.store
            .get(order_id)
            .await
            .ok_or_else(|| ServiceError::NotFound(format!("Order {} not found", order_id)))
    }

    /// Adds a fulfillment event to an order
    pub async fn add_fulfillment_event(
        &self,
        order_id: &str,
        request: FulfillmentEventRequest,
    ) -> Result<Order, ServiceError> {
        let mut order = self.get_order(order_id).await?;

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
    use crate::models::{ItemResponse, OrderLineItem};

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

        let service = OrderService::new(store, "2026-01-11".to_string());

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

        let service = OrderService::new(store, "2026-01-11".to_string());

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
}
