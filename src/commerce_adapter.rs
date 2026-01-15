//! Commerce Adapter - Bridge between UCP Handler and iCommerce
//!
//! This module handles all type conversions between:
//! - UCP Handler types (i64 cents, String IDs)
//! - iCommerce types (rust_decimal::Decimal, uuid::Uuid)
#![allow(dead_code)]

use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use std::collections::HashMap;
use uuid::Uuid;

use crate::models::{
    CheckoutResponse, CheckoutStatus, LineItemResponse, ItemResponse,
    Total, Buyer, DiscountsObject, AppliedDiscount,
    PostalAddress, UcpResponseMeta, CapabilityRef, PaymentResponse,
};

use stateset_core::{
    Cart, CartStatus, CartItem, CartAddress, CheckoutResult,
    ApplyPromotionsResult, PromotionTarget,
    TaxCalculationResult,
};

// ============================================================================
// Currency Conversions
// ============================================================================

/// Convert cents (i64) to Decimal dollars
/// UCP uses cents (2500 = $25.00), iCommerce uses Decimal (25.00)
pub fn cents_to_decimal(cents: i64) -> Decimal {
    Decimal::new(cents, 2)
}

/// Convert Decimal dollars to cents (i64)
/// iCommerce uses Decimal (25.00), UCP uses cents (2500 = $25.00)
pub fn decimal_to_cents(decimal: Decimal) -> i64 {
    (decimal * Decimal::from(100))
        .round()
        .to_i64()
        .unwrap_or(0)
}

// ============================================================================
// ID Conversions
// ============================================================================

/// Parse a checkout ID string (may have "chk_" prefix) to Uuid
pub fn parse_checkout_id(s: &str) -> Option<Uuid> {
    let cleaned = s.trim_start_matches("chk_");
    Uuid::parse_str(cleaned).ok()
}

/// Format a Uuid as a checkout ID string with "chk_" prefix
pub fn format_checkout_id(uuid: Uuid) -> String {
    format!("chk_{}", uuid)
}

/// Parse an order ID string (may have "order_" prefix) to Uuid
pub fn parse_order_id(s: &str) -> Option<Uuid> {
    let cleaned = s.trim_start_matches("order_");
    Uuid::parse_str(cleaned).ok()
}

/// Format a Uuid as an order ID string with "order_" prefix
pub fn format_order_id(uuid: Uuid) -> String {
    format!("order_{}", uuid)
}

/// Parse a line item ID string (may have "li_" prefix) to Uuid
pub fn parse_line_item_id(s: &str) -> Option<Uuid> {
    let cleaned = s.trim_start_matches("li_");
    Uuid::parse_str(cleaned).ok()
}

/// Format a Uuid as a line item ID string with "li_" prefix
pub fn format_line_item_id(uuid: Uuid) -> String {
    format!("li_{}", uuid)
}

// ============================================================================
// Status Conversions
// ============================================================================

/// Convert iCommerce CartStatus to UCP CheckoutStatus
pub fn cart_status_to_checkout_status(status: CartStatus) -> CheckoutStatus {
    match status {
        CartStatus::Active => CheckoutStatus::Incomplete,
        CartStatus::ReadyForPayment => CheckoutStatus::ReadyForComplete,
        CartStatus::PaymentPending => CheckoutStatus::CompleteInProgress,
        CartStatus::Completed => CheckoutStatus::Completed,
        CartStatus::Abandoned => CheckoutStatus::Canceled,
        CartStatus::Cancelled => CheckoutStatus::Canceled,
        CartStatus::Expired => CheckoutStatus::Canceled,
    }
}

/// Convert UCP CheckoutStatus to iCommerce CartStatus
pub fn checkout_status_to_cart_status(status: &CheckoutStatus) -> CartStatus {
    match status {
        CheckoutStatus::Incomplete => CartStatus::Active,
        CheckoutStatus::RequiresEscalation => CartStatus::PaymentPending,
        CheckoutStatus::ReadyForComplete => CartStatus::ReadyForPayment,
        CheckoutStatus::CompleteInProgress => CartStatus::PaymentPending,
        CheckoutStatus::Completed => CartStatus::Completed,
        CheckoutStatus::Canceled => CartStatus::Cancelled,
    }
}

// ============================================================================
// Model Conversions: iCommerce -> UCP
// ============================================================================

/// Convert iCommerce Cart to UCP CheckoutResponse
pub fn cart_to_checkout_response(
    cart: Cart,
    ucp_version: &str,
    capabilities: Vec<CapabilityRef>,
    payment_handlers: Vec<crate::models::PaymentHandler>,
) -> CheckoutResponse {
    let line_items: Vec<LineItemResponse> = cart.items.iter().map(|item| {
        cart_item_to_line_item_response(item)
    }).collect();

    let totals = build_totals_from_cart(&cart);
    let status = cart_status_to_checkout_status(cart.status);

    CheckoutResponse {
        ucp: UcpResponseMeta {
            version: ucp_version.to_string(),
            capabilities,
        },
        id: format_checkout_id(cart.id),
        line_items,
        buyer: cart_to_buyer(&cart),
        status,
        currency: cart.currency.clone(),
        totals,
        discounts: cart_to_discounts(&cart),
        fulfillment: None, // Built separately based on available methods
        messages: None,
        links: Vec::new(),
        payment: PaymentResponse {
            handlers: payment_handlers,
            selected_instrument_id: None,
            instruments: None,
            extra: HashMap::new(),
        },
        ap2: None,
        order: None,       // Only populated after completion
        extra: HashMap::new(),
        expires_at: cart.expires_at.map(|dt| dt.to_rfc3339()),
        continue_url: None,
    }
}

/// Convert iCommerce CartItem to UCP LineItemResponse
pub fn cart_item_to_line_item_response(item: &CartItem) -> LineItemResponse {
    let line_item_id = item
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("ucp_line_item_id"))
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
        .unwrap_or_else(|| format_line_item_id(item.id));

    // Build totals for this line item
    let totals = vec![
        Total {
            total_type: "subtotal".to_string(),
            display_text: Some("Subtotal".to_string()),
            amount: decimal_to_cents(item.total),
        },
    ];

    LineItemResponse {
        id: line_item_id,
        item: ItemResponse {
            id: item.sku.clone(),
            title: item.name.clone(),
            price: decimal_to_cents(item.unit_price),
            image_url: item.image_url.clone(),
            extra: HashMap::new(),
        },
        quantity: item.quantity,
        totals,
        parent_id: None,
        extra: HashMap::new(),
    }
}

/// Build UCP totals array from iCommerce Cart
pub fn build_totals_from_cart(cart: &Cart) -> Vec<Total> {
    let mut totals = Vec::new();

    // Subtotal
    totals.push(Total {
        total_type: "subtotal".to_string(),
        display_text: Some("Subtotal".to_string()),
        amount: decimal_to_cents(cart.subtotal),
    });

    // Items discount (if any)
    if cart.discount_amount > Decimal::ZERO {
        totals.push(Total {
            total_type: "items_discount".to_string(),
            display_text: Some("Discount".to_string()),
            amount: decimal_to_cents(cart.discount_amount),
        });
    }

    // Shipping
    if cart.shipping_amount > Decimal::ZERO {
        totals.push(Total {
            total_type: "fulfillment".to_string(),
            display_text: Some("Shipping".to_string()),
            amount: decimal_to_cents(cart.shipping_amount),
        });
    }

    // Tax
    if cart.tax_amount > Decimal::ZERO {
        totals.push(Total {
            total_type: "tax".to_string(),
            display_text: Some("Tax".to_string()),
            amount: decimal_to_cents(cart.tax_amount),
        });
    }

    // Grand total
    totals.push(Total {
        total_type: "total".to_string(),
        display_text: Some("Total".to_string()),
        amount: decimal_to_cents(cart.grand_total),
    });

    totals
}

/// Extract Buyer from iCommerce Cart
pub fn cart_to_buyer(cart: &Cart) -> Option<Buyer> {
    let email = cart.customer_email.as_ref()?;

    Some(Buyer {
        first_name: cart.customer_name.clone(),
        last_name: None,
        full_name: cart.customer_name.clone(),
        email: Some(email.clone()),
        phone_number: cart.customer_phone.clone(),
        consent: None,
        extra: HashMap::new(),
    })
}

/// Extract DiscountsObject from iCommerce Cart
pub fn cart_to_discounts(cart: &Cart) -> Option<DiscountsObject> {
    if cart.discount_amount == Decimal::ZERO && cart.coupon_code.is_none() {
        return None;
    }

    let applied = cart.coupon_code.as_ref().map(|code| {
        vec![AppliedDiscount {
            code: Some(code.clone()),
            title: cart.discount_description.clone().unwrap_or_else(|| code.clone()),
            amount: decimal_to_cents(cart.discount_amount),
            automatic: Some(false),
            method: None,
            priority: None,
            allocations: None,
        }]
    });

    Some(DiscountsObject {
        codes: cart.coupon_code.as_ref().map(|c| vec![c.clone()]),
        applied,
    })
}

/// Convert iCommerce CheckoutResult to UCP order confirmation
pub fn checkout_result_to_order_confirmation(
    result: &CheckoutResult,
    base_url: &str,
) -> crate::models::OrderConfirmation {
    crate::models::OrderConfirmation {
        id: format_order_id(result.order_id),
        permalink_url: format!("{}/orders/{}", base_url, result.order_number),
        extra: HashMap::new(),
    }
}

// ============================================================================
// Model Conversions: UCP -> iCommerce
// ============================================================================

/// Convert UCP PostalAddress to iCommerce CartAddress
pub fn postal_address_to_cart_address(addr: &PostalAddress) -> CartAddress {
    // Combine first_name and last_name, or use full_name
    let first_name = addr.first_name.clone()
        .or_else(|| addr.full_name.clone())
        .unwrap_or_default();
    let last_name = addr.last_name.clone().unwrap_or_default();

    CartAddress {
        first_name,
        last_name,
        company: None,
        line1: addr.street_address.clone().unwrap_or_default(),
        line2: addr.extended_address.clone(),
        city: addr.address_locality.clone().unwrap_or_default(),
        state: addr.address_region.clone(),
        postal_code: addr.postal_code.clone().unwrap_or_default(),
        country: addr.address_country.clone().unwrap_or_default(),
        phone: addr.phone_number.clone(),
        email: None,
    }
}

/// Convert iCommerce CartAddress to UCP PostalAddress
pub fn cart_address_to_postal_address(addr: &CartAddress) -> PostalAddress {
    let full_name = format!("{} {}", addr.first_name, addr.last_name).trim().to_string();

    PostalAddress {
        first_name: Some(addr.first_name.clone()),
        last_name: Some(addr.last_name.clone()),
        full_name: if full_name.is_empty() { None } else { Some(full_name) },
        extended_address: addr.line2.clone(),
        street_address: Some(addr.line1.clone()),
        address_locality: Some(addr.city.clone()),
        address_region: addr.state.clone(),
        address_country: Some(addr.country.clone()),
        postal_code: Some(addr.postal_code.clone()),
        phone_number: addr.phone.clone(),
        extra: HashMap::new(),
    }
}

// ============================================================================
// Promotion Result Conversion
// ============================================================================

/// Convert iCommerce ApplyPromotionsResult to UCP discount structures
pub fn promotions_result_to_ucp(
    result: &ApplyPromotionsResult,
    _line_items: &[LineItemResponse],
) -> (Option<DiscountsObject>, i64, i64) {
    if result.applied_promotions.is_empty() {
        return (None, 0, 0);
    }

    let mut items_discount = 0i64;
    let mut order_discount = 0i64;

    let applied: Vec<AppliedDiscount> = result.applied_promotions.iter().map(|promo| {
        let amount = decimal_to_cents(promo.discount_amount);

        // Determine if this is an items discount or order discount based on target
        match promo.target {
            PromotionTarget::LineItem | PromotionTarget::Product | PromotionTarget::Category => {
                items_discount += amount;
            }
            PromotionTarget::Order | PromotionTarget::Shipping => {
                order_discount += amount;
            }
        }

        AppliedDiscount {
            code: promo.coupon_code.clone(),
            title: promo.promotion_name.clone(),
            amount,
            automatic: Some(promo.coupon_code.is_none()),
            method: None,
            priority: None,
            allocations: None, // iCommerce doesn't provide per-item allocations in this structure
        }
    }).collect();

    let codes: Vec<String> = result.applied_promotions.iter()
        .filter_map(|p| p.coupon_code.clone())
        .collect();

    let discounts = DiscountsObject {
        codes: if codes.is_empty() { None } else { Some(codes) },
        applied: Some(applied),
    };

    (Some(discounts), items_discount, order_discount)
}

// ============================================================================
// Tax Result Conversion
// ============================================================================

/// Convert iCommerce TaxCalculationResult to UCP tax total
pub fn tax_result_to_cents(result: &TaxCalculationResult) -> i64 {
    decimal_to_cents(result.total_tax)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_cents_decimal_conversion() {
        assert_eq!(cents_to_decimal(2500), Decimal::new(2500, 2)); // $25.00
        assert_eq!(decimal_to_cents(Decimal::new(2500, 2)), 2500);
        assert_eq!(decimal_to_cents(Decimal::new(999, 2)), 999); // $9.99
    }

    #[test]
    fn test_id_parsing() {
        let uuid = Uuid::new_v4();

        // Checkout IDs
        let checkout_id = format_checkout_id(uuid);
        assert!(checkout_id.starts_with("chk_"));
        assert_eq!(parse_checkout_id(&checkout_id), Some(uuid));
        assert_eq!(parse_checkout_id(&uuid.to_string()), Some(uuid));

        // Order IDs
        let order_id = format_order_id(uuid);
        assert!(order_id.starts_with("order_"));
        assert_eq!(parse_order_id(&order_id), Some(uuid));
    }

    #[test]
    fn test_status_conversion() {
        assert!(matches!(
            cart_status_to_checkout_status(CartStatus::Active),
            CheckoutStatus::Incomplete
        ));
        assert!(matches!(
            cart_status_to_checkout_status(CartStatus::Completed),
            CheckoutStatus::Completed
        ));
    }

    #[test]
    fn test_cart_item_metadata_preserves_ucp_id() {
        let now = Utc::now();
        let item = CartItem {
            id: Uuid::new_v4(),
            cart_id: Uuid::new_v4(),
            product_id: None,
            variant_id: None,
            sku: "sku-1".to_string(),
            name: "Sample Item".to_string(),
            description: None,
            image_url: None,
            quantity: 2,
            unit_price: Decimal::new(1000, 2),
            original_price: None,
            discount_amount: Decimal::ZERO,
            tax_amount: Decimal::ZERO,
            total: Decimal::new(2000, 2),
            weight: None,
            requires_shipping: true,
            metadata: Some(serde_json::json!({
                "ucp_line_item_id": "li_custom_123",
            })),
            created_at: now,
            updated_at: now,
        };

        let response = cart_item_to_line_item_response(&item);
        assert_eq!(response.id, "li_custom_123");
    }
}
