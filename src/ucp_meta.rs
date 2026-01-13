use crate::models::CheckoutResponse;
use crate::negotiation::NegotiatedCapabilities;
use std::collections::HashSet;

pub const AP2_MANDATE_CAPABILITY: &str = "dev.ucp.shopping.ap2_mandate";

pub fn requires_ap2_mandate(
    negotiated: Option<&NegotiatedCapabilities>,
    fallback: bool,
) -> bool {
    negotiated
        .map(|caps| has_capability(caps, AP2_MANDATE_CAPABILITY))
        .unwrap_or(fallback)
}

pub fn apply_negotiated_checkout(
    checkout: &mut CheckoutResponse,
    negotiated: Option<&NegotiatedCapabilities>,
) {
    let Some(negotiated) = negotiated else {
        return;
    };

    checkout.ucp.version = negotiated.version.clone();

    let allowed = negotiated_capability_names(negotiated);
    checkout
        .ucp
        .capabilities
        .retain(|capability| allowed.contains(capability.name.as_str()));

    if !allowed.contains(AP2_MANDATE_CAPABILITY) {
        checkout.ap2 = None;
    }
}

pub fn has_capability(negotiated: &NegotiatedCapabilities, name: &str) -> bool {
    negotiated
        .capabilities
        .iter()
        .any(|capability| capability.name == name)
}

fn negotiated_capability_names(
    negotiated: &NegotiatedCapabilities,
) -> HashSet<&str> {
    negotiated
        .capabilities
        .iter()
        .map(|capability| capability.name.as_str())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        Ap2CheckoutResponse, CapabilityRef, CheckoutResponse, CheckoutStatus, ItemResponse,
        LineItemResponse, PaymentResponse, Total, UcpResponseMeta,
    };
    use std::collections::HashMap;

    #[test]
    fn apply_negotiated_checkout_filters_capabilities() {
        let negotiated = NegotiatedCapabilities {
            version: "2026-01-11".to_string(),
            capabilities: vec![CapabilityRef {
                name: "dev.ucp.shopping.checkout".to_string(),
                version: "2026-01-11".to_string(),
            }],
            platform_signing_keys: Vec::new(),
            platform_webhook_url: None,
        };

        let mut checkout = CheckoutResponse {
            ucp: UcpResponseMeta {
                version: "2026-01-11".to_string(),
                capabilities: vec![
                    CapabilityRef {
                        name: "dev.ucp.shopping.checkout".to_string(),
                        version: "2026-01-11".to_string(),
                    },
                    CapabilityRef {
                        name: AP2_MANDATE_CAPABILITY.to_string(),
                        version: "2026-01-11".to_string(),
                    },
                ],
            },
            id: "chk_123".to_string(),
            line_items: vec![LineItemResponse {
                id: "li_1".to_string(),
                item: ItemResponse {
                    id: "item_1".to_string(),
                    title: "Widget".to_string(),
                    price: 1000,
                    image_url: None,
                    extra: HashMap::new(),
                },
                quantity: 1,
                totals: vec![Total {
                    total_type: "total".to_string(),
                    display_text: None,
                    amount: 1000,
                }],
                parent_id: None,
                extra: HashMap::new(),
            }],
            buyer: None,
            status: CheckoutStatus::Incomplete,
            currency: "USD".to_string(),
            totals: vec![Total {
                total_type: "total".to_string(),
                display_text: None,
                amount: 1000,
            }],
            discounts: None,
            fulfillment: None,
            messages: None,
            links: Vec::new(),
            expires_at: None,
            continue_url: None,
            payment: PaymentResponse {
                handlers: Vec::new(),
                selected_instrument_id: None,
                instruments: None,
                extra: HashMap::new(),
            },
            ap2: Some(Ap2CheckoutResponse {
                merchant_authorization: "sig".to_string(),
            }),
            order: None,
            extra: HashMap::new(),
        };

        apply_negotiated_checkout(&mut checkout, Some(&negotiated));

        assert_eq!(checkout.ucp.version, "2026-01-11");
        assert_eq!(checkout.ucp.capabilities.len(), 1);
        assert_eq!(
            checkout.ucp.capabilities[0].name,
            "dev.ucp.shopping.checkout"
        );
        assert!(checkout.ap2.is_none());
    }
}
