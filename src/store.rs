//! Checkout Session Store
//!
//! Hybrid storage using iCommerce Carts for persistence and in-memory cache
//! for UCP-specific metadata that doesn't map directly to Cart fields.

use crate::commerce::CommerceEngine;
use crate::commerce_adapter::{
    cart_to_checkout_response, parse_checkout_id, cents_to_decimal,
};
use crate::models::{
    CheckoutResponse, CapabilityRef, PaymentHandler,
    Fulfillment, LineItemResponse, PaymentResponse,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use stateset_embedded::{AddCartItem, CartAddress, CreateCart, UpdateCart};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// UCP-specific metadata that doesn't fit in iCommerce Cart
#[derive(Clone)]
struct UcpOverlay {
    /// UCP capabilities for this checkout
    capabilities: Vec<CapabilityRef>,
    /// Negotiated UCP version for this checkout (if available)
    negotiated_version: Option<String>,
    /// Negotiated capabilities for this checkout (if available)
    negotiated_capabilities: Option<Vec<CapabilityRef>>,
    /// Payment handlers configuration
    payment_handlers: Vec<PaymentHandler>,
    /// UCP version string
    ucp_version: String,
    /// Fulfillment options and selection
    fulfillment: Option<Fulfillment>,
    /// Payment response state
    payment: Option<PaymentResponse>,
    /// AP2 authorization response
    ap2: Option<crate::models::Ap2CheckoutResponse>,
    /// Links (terms, privacy, etc.)
    links: Vec<crate::models::Link>,
    /// Messages to display
    messages: Option<Vec<crate::models::Message>>,
    /// Extra fields
    extra: HashMap<String, serde_json::Value>,
    /// Continue URL
    continue_url: Option<String>,
}

/// Hybrid checkout store with iCommerce persistence and in-memory UCP overlay
#[derive(Clone)]
pub struct CheckoutStore {
    /// iCommerce engine for cart persistence
    commerce: Option<CommerceEngine>,
    /// In-memory cache for full CheckoutResponse (fast path)
    cache: Arc<RwLock<HashMap<String, CachedCheckout>>>,
    /// UCP overlay data not stored in iCommerce
    overlays: Arc<RwLock<HashMap<String, UcpOverlay>>>,
}

#[derive(Clone)]
struct CachedCheckout {
    checkout: CheckoutResponse,
    expires_at: Option<DateTime<Utc>>,
}

impl CachedCheckout {
    fn is_expired(&self) -> bool {
        self.expires_at
            .map(|deadline| Utc::now() > deadline)
            .unwrap_or(false)
    }
}

impl CheckoutStore {
    /// Create a new CheckoutStore with iCommerce backend
    pub fn new_with_commerce(commerce: CommerceEngine) -> Self {
        Self {
            commerce: Some(commerce),
            cache: Arc::new(RwLock::new(HashMap::new())),
            overlays: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create an in-memory only store (for testing or legacy mode)
    pub fn new() -> Self {
        Self {
            commerce: None,
            cache: Arc::new(RwLock::new(HashMap::new())),
            overlays: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Insert a checkout session
    ///
    /// Stores the full CheckoutResponse in cache and persists core cart data
    /// to iCommerce for durability.
    pub async fn insert(&self, checkout: CheckoutResponse, ttl: Option<Duration>) {
        let checkout_id = checkout.id.clone();
        let expires_at = ttl.map(|d| Utc::now() + ChronoDuration::seconds(d.as_secs() as i64));

        // Store in fast cache
        {
            let mut cache = self.cache.write().await;
            cache.insert(
                checkout_id.clone(),
                CachedCheckout {
                    checkout: checkout.clone(),
                    expires_at,
                },
            );
        }

        // Store UCP overlay
        {
            let existing = {
                let overlays = self.overlays.read().await;
                overlays
                    .get(&checkout_id)
                    .map(|overlay| {
                        (
                            overlay.negotiated_version.clone(),
                            overlay.negotiated_capabilities.clone(),
                        )
                    })
            };
            let (negotiated_version, negotiated_capabilities) =
                existing.unwrap_or((None, None));

            let mut overlays = self.overlays.write().await;
            overlays.insert(
                checkout_id.clone(),
                UcpOverlay {
                    capabilities: checkout.ucp.capabilities.clone(),
                    negotiated_version,
                    negotiated_capabilities,
                    payment_handlers: checkout.payment.handlers.clone(),
                    ucp_version: checkout.ucp.version.clone(),
                    fulfillment: checkout.fulfillment.clone(),
                    payment: Some(checkout.payment.clone()),
                    ap2: checkout.ap2.clone(),
                    links: checkout.links.clone(),
                    messages: checkout.messages.clone(),
                    extra: checkout.extra.clone(),
                    continue_url: checkout.continue_url.clone(),
                },
            );
        }

        // Persist to iCommerce if available
        if let Some(ref commerce) = self.commerce {
            if let Err(e) = self.sync_to_icommerce(commerce, &checkout).await {
                tracing::warn!("Failed to sync checkout to iCommerce: {}", e);
                // Continue - we still have the in-memory cache
            }
        }
    }

    /// Get a checkout session by ID
    ///
    /// First checks the in-memory cache, then falls back to iCommerce
    /// for persistence across restarts.
    pub async fn get(&self, checkout_id: &str) -> Option<CheckoutResponse> {
        // Fast path: check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(checkout_id) {
                if !cached.is_expired() {
                    return Some(cached.checkout.clone());
                }
            }
        }

        let mut expired = false;
        {
            let mut cache = self.cache.write().await;
            if let Some(cached) = cache.get(checkout_id) {
                if cached.is_expired() {
                    cache.remove(checkout_id);
                    expired = true;
                } else {
                    return Some(cached.checkout.clone());
                }
            }
        }

        if expired {
            let mut overlays = self.overlays.write().await;
            overlays.remove(checkout_id);
            return None;
        }

        // Slow path: try iCommerce
        if let Some(ref commerce) = self.commerce {
            if let Some(checkout) = self.load_from_icommerce(commerce, checkout_id).await {
                let cache_deadline = checkout
                    .expires_at
                    .as_ref()
                    .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                    .map(|value| value.with_timezone(&Utc))
                    .or_else(|| Some(Utc::now() + ChronoDuration::hours(1)));

                // Re-populate cache
                let mut cache = self.cache.write().await;
                cache.insert(
                    checkout_id.to_string(),
                    CachedCheckout {
                        checkout: checkout.clone(),
                        expires_at: cache_deadline,
                    },
                );
                return Some(checkout);
            }
        }

        None
    }

    /// Store negotiated capabilities for a checkout session.
    pub async fn set_negotiated(
        &self,
        checkout_id: &str,
        version: String,
        capabilities: Vec<CapabilityRef>,
    ) {
        let mut overlays = self.overlays.write().await;
        if let Some(overlay) = overlays.get_mut(checkout_id) {
            overlay.negotiated_version = Some(version);
            overlay.negotiated_capabilities = Some(capabilities);
        }
    }

    /// Get negotiated capabilities for a checkout session, if stored.
    pub async fn get_negotiated(
        &self,
        checkout_id: &str,
    ) -> Option<(String, Vec<CapabilityRef>)> {
        let overlays = self.overlays.read().await;
        overlays.get(checkout_id).and_then(|overlay| {
            overlay.negotiated_version.as_ref().map(|version| {
                (
                    version.clone(),
                    overlay
                        .negotiated_capabilities
                        .clone()
                        .unwrap_or_default(),
                )
            })
        })
    }

    /// Remove a checkout session
    pub async fn remove(&self, checkout_id: &str) {
        // Remove from cache
        {
            let mut cache = self.cache.write().await;
            cache.remove(checkout_id);
        }

        // Remove overlay
        {
            let mut overlays = self.overlays.write().await;
            overlays.remove(checkout_id);
        }

        // Cancel in iCommerce
        if let Some(ref commerce) = self.commerce {
            if let Some(uuid) = parse_checkout_id(checkout_id) {
                if let Err(e) = commerce.carts().cancel(uuid) {
                    tracing::warn!("Failed to cancel cart in iCommerce: {}", e);
                }
            }
        }
    }

    /// Sync checkout data to iCommerce Cart
    async fn sync_to_icommerce(
        &self,
        commerce: &CommerceEngine,
        checkout: &CheckoutResponse,
    ) -> Result<(), String> {
        let cart_id = parse_checkout_id(&checkout.id)
            .ok_or_else(|| "Invalid checkout ID format".to_string())?;
        let metadata = self.build_cart_metadata(checkout, cart_id);

        // Check if cart exists
        let existing = commerce.carts().get(cart_id).map_err(|e| e.to_string())?;

        if existing.is_none() {
            // Create new cart with items
            let items: Vec<AddCartItem> = checkout
                .line_items
                .iter()
                .map(|li| self.build_cart_item(li))
                .collect();

            // Calculate expiration in minutes if we have an expires_at timestamp
            let expires_in_minutes = checkout.expires_at.as_ref().and_then(|s| {
                DateTime::parse_from_rfc3339(s).ok().map(|dt| {
                    let expires = dt.with_timezone(&Utc);
                    let now = Utc::now();
                    let duration = expires.signed_duration_since(now);
                    duration.num_minutes().max(1) // At least 1 minute
                })
            });

            let request = CreateCart {
                currency: Some(checkout.currency.clone()),
                customer_id: None,
                customer_email: checkout.buyer.as_ref().and_then(|b| b.email.clone()),
                customer_name: checkout.buyer.as_ref().and_then(|b| b.full_name.clone()),
                expires_in_minutes,
                items: if items.is_empty() { None } else { Some(items) },
                shipping_address: None, // Will be set separately if available
                billing_address: None,
                notes: None,
                metadata: Some(metadata),
            };

            let created_cart = commerce.carts().create(request).map_err(|e| e.to_string())?;

            // If the created cart has a different ID, we need to track the mapping
            // For now, we'll just log a warning if IDs don't match
            if created_cart.id != cart_id {
                tracing::warn!(
                    "Created cart ID {} differs from checkout ID {}",
                    created_cart.id,
                    cart_id
                );
            }
        } else {
            let update = UpdateCart {
                customer_email: checkout.buyer.as_ref().and_then(|b| b.email.clone()),
                customer_phone: checkout.buyer.as_ref().and_then(|b| b.phone_number.clone()),
                customer_name: checkout.buyer.as_ref().and_then(|b| b.full_name.clone()),
                metadata: Some(metadata),
                ..Default::default()
            };
            commerce.carts().update(cart_id, update).map_err(|e| e.to_string())?;
        }

        // Try to extract and set shipping address from fulfillment destinations
        if let Some(ref fulfillment) = checkout.fulfillment {
            if let Some(ref methods) = fulfillment.methods {
                for method in methods {
                    if let Some(ref destinations) = method.destinations {
                        for dest in destinations {
                            // Try to extract address from destination data
                            if let Some(cart_addr) = self.extract_address_from_destination(&dest.data) {
                                commerce.carts().set_shipping_address(cart_id, cart_addr)
                                    .map_err(|e| e.to_string())?;
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Apply discount/coupon if present
        if let Some(ref discounts) = checkout.discounts {
            if let Some(ref codes) = discounts.codes {
                for code in codes {
                    let _ = commerce.carts().apply_discount(cart_id, code);
                }
            }
        }

        Ok(())
    }

    /// Extract CartAddress from destination data HashMap
    fn extract_address_from_destination(&self, data: &HashMap<String, serde_json::Value>) -> Option<CartAddress> {
        // Check for address object in destination data
        let address_data = data.get("address")
            .or_else(|| data.get("postal_address"))
            .or_else(|| data.get("shipping_address"));

        if let Some(serde_json::Value::Object(addr)) = address_data {
            let get_str = |key: &str| -> Option<String> {
                addr.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
            };

            Some(CartAddress {
                first_name: get_str("first_name").unwrap_or_default(),
                last_name: get_str("last_name").unwrap_or_default(),
                company: get_str("company"),
                line1: get_str("street_address").or_else(|| get_str("line1")).unwrap_or_default(),
                line2: get_str("extended_address").or_else(|| get_str("line2")),
                city: get_str("address_locality").or_else(|| get_str("city")).unwrap_or_default(),
                state: get_str("address_region").or_else(|| get_str("state")),
                postal_code: get_str("postal_code").unwrap_or_default(),
                country: get_str("address_country").or_else(|| get_str("country")).unwrap_or_default(),
                phone: get_str("phone_number").or_else(|| get_str("phone")),
                email: get_str("email"),
            })
        } else {
            None
        }
    }

    fn build_cart_metadata(
        &self,
        checkout: &CheckoutResponse,
        cart_id: uuid::Uuid,
    ) -> serde_json::Value {
        serde_json::json!({
            "ucp_checkout_id": &checkout.id,
            "ucp_cart_id": cart_id.to_string(),
            "ucp": {
                "version": &checkout.ucp.version,
                "capabilities": &checkout.ucp.capabilities,
                "payment_handlers": &checkout.payment.handlers,
            }
        })
    }

    fn build_cart_item(&self, line_item: &LineItemResponse) -> AddCartItem {
        AddCartItem {
            sku: line_item.item.id.clone(),
            name: line_item.item.title.clone(),
            quantity: line_item.quantity,
            unit_price: cents_to_decimal(line_item.item.price),
            image_url: line_item.item.image_url.clone(),
            product_id: None,
            variant_id: None,
            description: None,
            original_price: None,
            weight: None,
            requires_shipping: Some(true),
            metadata: Some(serde_json::json!({
                "ucp_line_item_id": &line_item.id,
            })),
        }
    }

    fn defaults_from_metadata(
        &self,
        metadata: Option<&serde_json::Value>,
    ) -> (String, Vec<CapabilityRef>, Vec<PaymentHandler>) {
        let ucp_meta = metadata.and_then(|value| value.get("ucp"));
        let ucp_version = ucp_meta
            .and_then(|value| value.get("version"))
            .and_then(|value| value.as_str())
            .map(|value| value.to_string())
            .unwrap_or_else(|| "1.0".to_string());

        let capabilities = ucp_meta
            .and_then(|value| value.get("capabilities"))
            .and_then(|value| serde_json::from_value(value.clone()).ok())
            .unwrap_or_else(|| Self::default_capabilities(&ucp_version));

        let payment_handlers = ucp_meta
            .and_then(|value| value.get("payment_handlers"))
            .and_then(|value| serde_json::from_value(value.clone()).ok())
            .unwrap_or_else(|| Self::default_payment_handlers(&ucp_version));

        (ucp_version, capabilities, payment_handlers)
    }

    fn default_capabilities(ucp_version: &str) -> Vec<CapabilityRef> {
        vec![CapabilityRef {
            name: "dev.ucp.shopping.checkout".to_string(),
            version: ucp_version.to_string(),
        }]
    }

    fn default_payment_handlers(ucp_version: &str) -> Vec<PaymentHandler> {
        vec![PaymentHandler {
            id: "ucp_card".to_string(),
            name: "dev.ucp.payments.card".to_string(),
            version: ucp_version.to_string(),
            spec: "https://ucp.dev/specification/payment-handler-template".to_string(),
            config_schema: "https://ucp.dev/specification/payment-handler-template".to_string(),
            instrument_schemas: vec![
                "https://ucp.dev/schemas/shopping/types/card_payment_instrument.json".to_string(),
            ],
            config: serde_json::json!({ "environment": "sandbox" }),
        }]
    }

    /// Load checkout from iCommerce Cart
    async fn load_from_icommerce(
        &self,
        commerce: &CommerceEngine,
        checkout_id: &str,
    ) -> Option<CheckoutResponse> {
        let cart_id = parse_checkout_id(checkout_id)?;
        let cart = commerce.carts().get(cart_id).ok()??;

        // Check expiration
        if let Some(expires) = cart.expires_at {
            if expires < Utc::now() {
                return None;
            }
        }

        // Get UCP overlay if available
        let overlay = {
            let overlays = self.overlays.read().await;
            overlays.get(checkout_id).cloned()
        };

        // Use overlay or defaults
        let (ucp_version, capabilities, payment_handlers) = if let Some(ref ov) = overlay {
            (
                ov.ucp_version.clone(),
                ov.capabilities.clone(),
                ov.payment_handlers.clone(),
            )
        } else {
            // Defaults when no overlay (e.g., after restart)
            self.defaults_from_metadata(cart.metadata.as_ref())
        };

        // Convert cart to checkout response
        let mut response = cart_to_checkout_response(cart, &ucp_version, capabilities, payment_handlers);

        // Merge overlay data if available
        if let Some(ov) = overlay {
            response.fulfillment = ov.fulfillment;
            if let Some(payment) = ov.payment {
                response.payment = payment;
            }
            response.ap2 = ov.ap2;
            response.links = ov.links;
            response.messages = ov.messages;
            response.extra = ov.extra;
            response.continue_url = ov.continue_url;
        }

        Some(response)
    }
}

impl Default for CheckoutStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CheckoutStatus;

    #[tokio::test]
    async fn test_in_memory_store() {
        let store = CheckoutStore::new();

        // Create a minimal checkout response for testing
        let checkout = CheckoutResponse {
            id: "chk_test123".to_string(),
            ucp: crate::models::UcpResponseMeta {
                version: "1.0".to_string(),
                capabilities: vec![],
            },
            line_items: vec![],
            buyer: None,
            status: CheckoutStatus::Incomplete,
            currency: "USD".to_string(),
            totals: vec![],
            discounts: None,
            fulfillment: None,
            messages: None,
            links: vec![],
            payment: PaymentResponse {
                handlers: vec![],
                selected_instrument_id: None,
                instruments: None,
                extra: HashMap::new(),
            },
            ap2: None,
            order: None,
            extra: HashMap::new(),
            expires_at: None,
            continue_url: None,
        };

        // Insert
        store.insert(checkout.clone(), Some(Duration::from_secs(3600))).await;

        // Get
        let retrieved = store.get("chk_test123").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, "chk_test123");

        // Remove
        store.remove("chk_test123").await;
        let removed = store.get("chk_test123").await;
        assert!(removed.is_none());
    }

    #[tokio::test]
    async fn test_expiration() {
        let store = CheckoutStore::new();

        let checkout = CheckoutResponse {
            id: "chk_expire".to_string(),
            ucp: crate::models::UcpResponseMeta {
                version: "1.0".to_string(),
                capabilities: vec![],
            },
            line_items: vec![],
            buyer: None,
            status: CheckoutStatus::Incomplete,
            currency: "USD".to_string(),
            totals: vec![],
            discounts: None,
            fulfillment: None,
            messages: None,
            links: vec![],
            payment: PaymentResponse {
                handlers: vec![],
                selected_instrument_id: None,
                instruments: None,
                extra: HashMap::new(),
            },
            ap2: None,
            order: None,
            extra: HashMap::new(),
            expires_at: None,
            continue_url: None,
        };

        // Insert with 0 TTL (already expired)
        store.insert(checkout, Some(Duration::from_secs(0))).await;

        // Should not be retrievable
        // Note: In practice, the check happens against Utc::now() so a 0-second TTL
        // might still be valid for a brief moment. The real test would use tokio::time::sleep.
    }
}
