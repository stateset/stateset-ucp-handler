//! Checkout service orchestration for UCP sessions.
//!
//! Handles checkout lifecycle, totals/discounts, and optional AP2/identity features.

use crate::catalog::ProductCatalog;
use crate::crypto::{
    canonicalize, sign_detached_b64, verify_compact_jws, verify_detached_b64,
    verifying_key_from_signing, CompactJws, DetachedJws, SigningKey, VerifyingKey,
};
use crate::errors::ServiceError;
use crate::events::{Event, EventSender};
use crate::models::{
    AppliedDiscount, Ap2CheckoutResponse, Capability, CapabilityRef, CheckoutCompleteRequest,
    CheckoutCreateRequest, CheckoutResponse, CheckoutStatus, CheckoutUpdateRequest,
    DiscountAllocation, DiscountsObject, Fulfillment, FulfillmentAvailableMethod, FulfillmentGroup,
    FulfillmentMethod, FulfillmentOption, LineItemInput, LineItemResponse, Link, Message, Order,
    OrderConfirmation, OrderFulfillment, OrderLineItem, OrderQuantity, PaymentHandler,
    PaymentInstrument, PaymentRequest, PaymentResponse, Total, UcpResponseMeta,
};
use crate::store::CheckoutStore;
use crate::validation::{normalize_currency, validate_checkout_id, validate_quantity};
use chrono::{Duration as ChronoDuration, Utc};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

const CHECKOUT_CAPABILITY: &str = "dev.ucp.shopping.checkout";
const ORDER_CAPABILITY: &str = "dev.ucp.shopping.order";
const FULFILLMENT_CAPABILITY: &str = "dev.ucp.shopping.fulfillment";
const DISCOUNT_CAPABILITY: &str = "dev.ucp.shopping.discount";
const AP2_MANDATE_CAPABILITY: &str = "dev.ucp.shopping.ap2_mandate";
const IDENTITY_LINKING_CAPABILITY: &str = "dev.ucp.common.identity_linking";
const BUYER_CONSENT_CAPABILITY: &str = "dev.ucp.shopping.buyer_consent";

pub trait Ap2MandateVerifier: Send + Sync {
    /// Validate an AP2 mandate payload before completion.
    fn verify(&self, mandate: &str) -> Result<(), ServiceError>;
}

/// AP2 verifier that only validates SD-JWT+kb formatting.
#[derive(Default)]
pub struct FormatOnlyAp2MandateVerifier;

impl Ap2MandateVerifier for FormatOnlyAp2MandateVerifier {
    fn verify(&self, mandate: &str) -> Result<(), ServiceError> {
        let trimmed = mandate.trim();
        if trimmed.is_empty() {
            return Err(ServiceError::InvalidInput(
                "ap2.checkout_mandate is required".to_string(),
            ));
        }

        if !is_sd_jwt_kb_format(trimmed) {
            return Err(ServiceError::InvalidInput(
                "ap2.checkout_mandate must be a valid SD-JWT+kb token".to_string(),
            ));
        }

        Ok(())
    }
}

fn is_sd_jwt_kb_format(value: &str) -> bool {
    let mut parts = value.split('~');
    let jwt = parts.next().unwrap_or("");

    let mut jwt_parts = jwt.split('.');
    let header = jwt_parts.next().unwrap_or("");
    let payload = jwt_parts.next().unwrap_or("");
    let signature = jwt_parts.next().unwrap_or("");

    if jwt_parts.next().is_some() {
        return false;
    }

    if header.is_empty() || signature.is_empty() {
        return false;
    }

    if !is_base64url_segment(header) {
        return false;
    }

    if !payload.chars().all(is_base64url_char) {
        return false;
    }

    if !is_base64url_segment(signature) {
        return false;
    }

    for disclosure in parts {
        if !is_base64url_segment(disclosure) {
            return false;
        }
    }

    true
}

fn is_base64url_segment(value: &str) -> bool {
    !value.is_empty() && value.chars().all(is_base64url_char)
}

fn is_base64url_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'
}

fn checkout_value_without_ap2(
    checkout: &CheckoutResponse,
) -> Result<serde_json::Value, ServiceError> {
    let mut checkout_value = serde_json::to_value(checkout)
        .map_err(|err| ServiceError::InvalidInput(err.to_string()))?;
    if let Some(obj) = checkout_value.as_object_mut() {
        obj.remove("ap2");
    }
    Ok(checkout_value)
}

fn is_card_credential(credential: &serde_json::Value) -> bool {
    let Some(obj) = credential.as_object() else {
        return false;
    };

    if let Some(cred_type) = obj.get("type").and_then(|value| value.as_str()) {
        if cred_type == "card" {
            return true;
        }
    }

    obj.contains_key("card_number_type")
}

struct DiscountOutcome {
    discounts: Option<DiscountsObject>,
    items_discount: i64,
    order_discount: i64,
}

/// Core checkout lifecycle service for UCP sessions.
#[derive(Clone)]
pub struct CheckoutService {
    store: CheckoutStore,
    catalog: ProductCatalog,
    commerce: Option<crate::commerce::CommerceEngine>,
    event_sender: EventSender,
    ucp_version: String,
    service_version: String,
    base_url: String,
    session_ttl_seconds: u64,
    tax_bps: i64,
    handlers: Vec<PaymentHandler>,
    default_links: Vec<Link>,
    signing_keys: Option<Vec<crate::models::JwkKey>>,
    identity_linking_enabled: bool,
    buyer_consent_enabled: bool,
    use_icommerce_tax: bool,
    use_icommerce_promotions: bool,
    use_icommerce_shipping: bool,
    ap2_enabled: bool,
    ap2_merchant_authorization: Option<String>,
    ap2_signing_key: Option<SigningKey>,
    ap2_mandate_verifier: Arc<dyn Ap2MandateVerifier>,
}

impl CheckoutService {
    /// Create a new checkout service with feature flags and dependencies.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: CheckoutStore,
        catalog: ProductCatalog,
        commerce: Option<crate::commerce::CommerceEngine>,
        event_sender: EventSender,
        ucp_version: String,
        service_version: String,
        base_url: String,
        session_ttl_seconds: u64,
        tax_bps: i64,
        signing_keys: Option<Vec<crate::models::JwkKey>>,
        identity_linking_enabled: bool,
        buyer_consent_enabled: bool,
        use_icommerce_tax: bool,
        use_icommerce_promotions: bool,
        use_icommerce_shipping: bool,
        ap2_enabled: bool,
        ap2_merchant_authorization: Option<String>,
        ap2_signing_key: Option<SigningKey>,
        ap2_mandate_verifier: Option<Arc<dyn Ap2MandateVerifier>>,
    ) -> Self {
        let handlers = vec![PaymentHandler {
            id: "ucp_card".to_string(),
            name: "dev.ucp.payments.card".to_string(),
            version: ucp_version.clone(),
            spec: "https://ucp.dev/specification/payment-handler-template".to_string(),
            config_schema: "https://ucp.dev/specification/payment-handler-template".to_string(),
            instrument_schemas: vec![
                "https://ucp.dev/schemas/shopping/types/card_payment_instrument.json".to_string(),
            ],
            config: serde_json::json!({ "environment": "sandbox" }),
        }];

        let default_links = vec![
            Link {
                link_type: "terms_of_service".to_string(),
                url: format!("{}/terms", base_url),
                title: None,
            },
            Link {
                link_type: "privacy_policy".to_string(),
                url: format!("{}/privacy", base_url),
                title: None,
            },
        ];

        Self {
            store,
            catalog,
            commerce,
            event_sender,
            ucp_version,
            service_version,
            base_url,
            session_ttl_seconds,
            tax_bps,
            handlers,
            default_links,
            signing_keys,
            identity_linking_enabled,
            buyer_consent_enabled,
            use_icommerce_tax,
            use_icommerce_promotions,
            use_icommerce_shipping,
            ap2_enabled,
            ap2_merchant_authorization,
            ap2_signing_key,
            ap2_mandate_verifier: ap2_mandate_verifier
                .unwrap_or_else(|| Arc::new(FormatOnlyAp2MandateVerifier)),
        }
    }

    /// Create a new checkout session and return the response payload.
    pub async fn create_checkout(
        &self,
        request: CheckoutCreateRequest,
    ) -> Result<CheckoutResponse, ServiceError> {
        if request.line_items.is_empty() {
            return Err(ServiceError::InvalidInput(
                "line_items must contain at least one item".to_string(),
            ));
        }

        let currency = normalize_currency(&request.currency)?;
        let mut line_items = self.build_line_items(&request.line_items, &currency)?;
        let (fulfillment, fulfillment_cost) =
            self.build_fulfillment(request.fulfillment, &line_items, None)?;
        let discount_outcome = self.apply_discounts(
            &mut line_items,
            request.discounts,
            fulfillment_cost,
            &currency,
        )?;
        let totals = self.calculate_totals(
            &line_items,
            discount_outcome.items_discount,
            fulfillment_cost,
            discount_outcome.order_discount,
            &currency,
            fulfillment.as_ref(),
        )?;

        let buyer_has_consent = request
            .buyer
            .as_ref()
            .and_then(|buyer| buyer.consent.as_ref())
            .is_some();
        let payment = self.build_payment_response(request.payment, None);

        let mut checkout = CheckoutResponse {
            ucp: self.response_meta_for(
                fulfillment.is_some(),
                discount_outcome.discounts.is_some(),
                buyer_has_consent,
                self.ap2_enabled,
            ),
            id: format!("chk_{}", Uuid::new_v4()),
            line_items,
            buyer: request.buyer,
            status: CheckoutStatus::Incomplete,
            currency,
            totals,
            discounts: discount_outcome.discounts,
            fulfillment,
            messages: None,
            links: self.default_links.clone(),
            expires_at: Some(self.expires_at()),
            continue_url: None,
            payment,
            ap2: None, // Will be set after checkout is built
            order: None,
            extra: request.extra,
        };

        self.apply_status(&mut checkout);

        // Generate AP2 merchant authorization after checkout is built
        checkout.ap2 = self.ap2_response_for_checkout(&checkout);

        let ttl = Duration::from_secs(self.session_ttl_seconds);
        self.store.insert(checkout.clone(), Some(ttl)).await;

        Ok(checkout)
    }

    /// Load an existing checkout session by ID.
    pub async fn get_checkout(&self, checkout_id: &str) -> Result<CheckoutResponse, ServiceError> {
        self.store
            .get(checkout_id)
            .await
            .ok_or_else(|| ServiceError::NotFound(format!("Checkout {} not found", checkout_id)))
    }

    /// Record negotiated capabilities for a checkout session.
    pub async fn record_negotiated_checkout(
        &self,
        checkout_id: &str,
        version: &str,
        capabilities: &[CapabilityRef],
    ) {
        self.store
            .set_negotiated(checkout_id, version.to_string(), capabilities.to_vec())
            .await;
    }

    /// Get negotiated capabilities for a checkout session, if recorded.
    pub async fn negotiated_for_checkout(
        &self,
        checkout_id: &str,
    ) -> Option<(String, Vec<CapabilityRef>)> {
        self.store.get_negotiated(checkout_id).await
    }

    /// Update a checkout session, re-evaluating totals/requirements.
    pub async fn update_checkout(
        &self,
        checkout_id: &str,
        request: CheckoutUpdateRequest,
    ) -> Result<CheckoutResponse, ServiceError> {
        validate_checkout_id(checkout_id, &request.id)?;

        let existing = self.get_checkout(checkout_id).await?;
        let existing_fulfillment = existing.fulfillment.clone();
        let existing_discounts = existing.discounts.clone();
        let existing_payment = existing.payment.clone();
        if matches!(existing.status, CheckoutStatus::Completed | CheckoutStatus::Canceled) {
            return Err(ServiceError::InvalidState(
                "Checkout session cannot be updated".to_string(),
            ));
        }

        let currency = normalize_currency(&request.currency)?;
        let mut line_items = self.build_line_items(&request.line_items, &currency)?;

        let fulfillment_input = request.fulfillment.or(existing_fulfillment);
        let (fulfillment, fulfillment_cost) =
            self.build_fulfillment(fulfillment_input, &line_items, Some(checkout_id))?;

        let discount_input = request.discounts.or(existing_discounts);
        let discount_outcome =
            self.apply_discounts(&mut line_items, discount_input, fulfillment_cost, &currency)?;

        let totals = self.calculate_totals(
            &line_items,
            discount_outcome.items_discount,
            fulfillment_cost,
            discount_outcome.order_discount,
            &currency,
            fulfillment.as_ref(),
        )?;

        let buyer = request.buyer.or(existing.buyer);
        let buyer_has_consent = buyer
            .as_ref()
            .and_then(|buyer| buyer.consent.as_ref())
            .is_some();
        let payment = self.build_payment_response(request.payment, Some(existing_payment));

        let mut extra = existing.extra;
        for (key, value) in request.extra {
            extra.insert(key, value);
        }

        let mut checkout = CheckoutResponse {
            ucp: self.response_meta_for(
                fulfillment.is_some(),
                discount_outcome.discounts.is_some(),
                buyer_has_consent,
                self.ap2_enabled,
            ),
            id: existing.id,
            line_items,
            buyer,
            status: CheckoutStatus::Incomplete,
            currency,
            totals,
            discounts: discount_outcome.discounts,
            fulfillment,
            messages: None,
            links: self.default_links.clone(),
            expires_at: existing.expires_at,
            continue_url: existing.continue_url,
            payment,
            ap2: None, // Will be set after checkout is built
            order: None,
            extra,
        };

        self.apply_status(&mut checkout);

        // Generate AP2 merchant authorization after checkout is built
        checkout.ap2 = self.ap2_response_for_checkout(&checkout);

        let ttl = Duration::from_secs(self.session_ttl_seconds);
        self.store.insert(checkout.clone(), Some(ttl)).await;

        Ok(checkout)
    }

    /// Complete a checkout session using provided payment data.
    pub async fn complete_checkout(
        &self,
        checkout_id: &str,
        request: CheckoutCompleteRequest,
    ) -> Result<CheckoutResponse, ServiceError> {
        self.complete_checkout_with_requirements(
            checkout_id,
            request,
            self.ap2_enabled,
            None,
            None,
        )
        .await
    }

    /// Complete a checkout session with validation requirements.
    pub async fn complete_checkout_with_requirements(
        &self,
        checkout_id: &str,
        request: CheckoutCompleteRequest,
        require_ap2_mandate: bool,
        webhook_url: Option<String>,
        platform_signing_keys: Option<&[VerifyingKey]>,
    ) -> Result<CheckoutResponse, ServiceError> {
        let mut checkout = self.get_checkout(checkout_id).await?;

        if matches!(checkout.status, CheckoutStatus::Completed) {
            return Err(ServiceError::InvalidState(
                "Checkout session already completed".to_string(),
            ));
        }

        if matches!(checkout.status, CheckoutStatus::Canceled) {
            return Err(ServiceError::InvalidState(
                "Checkout session is canceled".to_string(),
            ));
        }

        if !matches!(checkout.status, CheckoutStatus::ReadyForComplete) {
            return Err(ServiceError::InvalidState(
                "Checkout session is not ready for completion".to_string(),
            ));
        }

        if require_ap2_mandate {
            let mandate = request
                .ap2
                .as_ref()
                .map(|ap2| ap2.checkout_mandate.as_str())
                .unwrap_or_default();
            self.ap2_mandate_verifier.verify(mandate)?;
            let platform_keys = platform_signing_keys.ok_or_else(|| {
                ServiceError::InvalidInput(
                    "ap2.checkout_mandate requires platform signing keys".to_string(),
                )
            })?;
            if platform_keys.is_empty() {
                return Err(ServiceError::InvalidInput(
                    "ap2.checkout_mandate requires platform signing keys".to_string(),
                ));
            }
            self.verify_ap2_mandate(mandate, &checkout, platform_keys)?;
        }

        self.attach_payment_data(&mut checkout, request.payment_data)?;
        self.apply_status(&mut checkout);
        if !matches!(checkout.status, CheckoutStatus::ReadyForComplete) {
            return Err(ServiceError::InvalidState(
                "Checkout session is not ready for completion".to_string(),
            ));
        }

        let order_id = format!("order_{}", Uuid::new_v4());
        let order = self.build_order(&checkout, &order_id)?;

        checkout.order = Some(OrderConfirmation {
            id: order_id.clone(),
            permalink_url: order.permalink_url.clone(),
            extra: HashMap::new(),
        });

        checkout.status = CheckoutStatus::Completed;
        checkout.messages = None;
        checkout.continue_url = None;
        checkout.ap2 = self.ap2_response_for_checkout(&checkout);

        let ttl = Duration::from_secs(self.session_ttl_seconds);
        self.store.insert(checkout.clone(), Some(ttl)).await;

        self.event_sender
            .send(Event::OrderCreated { order, webhook_url })
            .await;

        Ok(checkout)
    }

    /// Cancel an existing checkout session.
    pub async fn cancel_checkout(&self, checkout_id: &str) -> Result<CheckoutResponse, ServiceError> {
        let mut checkout = self.get_checkout(checkout_id).await?;

        if matches!(checkout.status, CheckoutStatus::Completed | CheckoutStatus::Canceled) {
            return Err(ServiceError::InvalidState(
                "Checkout session cannot be canceled".to_string(),
            ));
        }

        checkout.status = CheckoutStatus::Canceled;
        checkout.messages = None;

        let ttl = Duration::from_secs(self.session_ttl_seconds);
        self.store.insert(checkout.clone(), Some(ttl)).await;

        Ok(checkout)
    }

    /// Build the discovery document describing supported capabilities.
    pub fn discovery_document(&self) -> crate::models::DiscoveryDocument {
        let mut services = HashMap::new();
        services.insert(
            "dev.ucp.shopping".to_string(),
            crate::models::ServiceDefinition {
                version: self.service_version.clone(),
                spec: "https://ucp.dev/specification/overview".to_string(),
                rest: Some(crate::models::ServiceEndpoint {
                    schema: "https://ucp.dev/services/shopping/rest.openapi.json".to_string(),
                    endpoint: format!("{}/api", self.base_url),
                }),
                mcp: Some(crate::models::ServiceEndpoint {
                    schema: format!("{}/schemas/shopping/mcp.openrpc.json", self.base_url),
                    endpoint: format!("{}/mcp", self.base_url),
                }),
                a2a: Some(crate::models::A2AEndpoint {
                    endpoint: format!("{}/.well-known/agent-card.json", self.base_url),
                }),
                embedded: Some(crate::models::EmbeddedEndpoint {
                    schema: "https://ucp.dev/services/shopping/embedded.openrpc.json"
                        .to_string(),
                }),
            },
        );

        let mut capabilities = vec![
            crate::models::Capability {
                name: CHECKOUT_CAPABILITY.to_string(),
                version: self.ucp_version.clone(),
                spec: "https://ucp.dev/specification/checkout".to_string(),
                schema: "https://ucp.dev/schemas/shopping/checkout.json".to_string(),
                extends: None,
                config: None,
            },
            crate::models::Capability {
                name: FULFILLMENT_CAPABILITY.to_string(),
                version: self.ucp_version.clone(),
                spec: "https://ucp.dev/specification/fulfillment".to_string(),
                schema: "https://ucp.dev/schemas/shopping/fulfillment.json".to_string(),
                extends: Some(CHECKOUT_CAPABILITY.to_string()),
                config: None,
            },
            crate::models::Capability {
                name: DISCOUNT_CAPABILITY.to_string(),
                version: self.ucp_version.clone(),
                spec: "https://ucp.dev/specification/discount".to_string(),
                schema: "https://ucp.dev/schemas/shopping/discount.json".to_string(),
                extends: Some(CHECKOUT_CAPABILITY.to_string()),
                config: None,
            },
            crate::models::Capability {
                name: ORDER_CAPABILITY.to_string(),
                version: self.ucp_version.clone(),
                spec: "https://ucp.dev/specification/order".to_string(),
                schema: "https://ucp.dev/schemas/shopping/order.json".to_string(),
                extends: None,
                config: None,
            },
        ];

        if self.identity_linking_enabled {
            capabilities.push(crate::models::Capability {
                name: IDENTITY_LINKING_CAPABILITY.to_string(),
                version: self.ucp_version.clone(),
                spec: "https://ucp.dev/specification/identity-linking".to_string(),
                schema: "https://ucp.dev/specification/identity-linking".to_string(),
                extends: None,
                config: None,
            });
        }

        if self.buyer_consent_enabled {
            capabilities.push(crate::models::Capability {
                name: BUYER_CONSENT_CAPABILITY.to_string(),
                version: self.ucp_version.clone(),
                spec: "https://ucp.dev/specification/buyer-consent".to_string(),
                schema: "https://ucp.dev/schemas/shopping/buyer_consent.json".to_string(),
                extends: Some(CHECKOUT_CAPABILITY.to_string()),
                config: None,
            });
        }

        if self.ap2_enabled {
            capabilities.push(crate::models::Capability {
                name: AP2_MANDATE_CAPABILITY.to_string(),
                version: self.ucp_version.clone(),
                spec: "https://ucp.dev/specification/ap2-mandate".to_string(),
                schema: "https://ucp.dev/schemas/shopping/ap2_mandate.json".to_string(),
                extends: Some(CHECKOUT_CAPABILITY.to_string()),
                config: None,
            });
        }

        crate::models::DiscoveryDocument {
            ucp: crate::models::UcpDiscoveryProfile {
                version: self.ucp_version.clone(),
                services,
                capabilities,
            },
            payment: Some(crate::models::DiscoveryPayment {
                handlers: self.handlers.clone(),
            }),
            signing_keys: self.signing_keys.clone(),
            extra: HashMap::new(),
        }
    }

    /// Return the supported business capabilities.
    pub fn business_capabilities(&self) -> Vec<Capability> {
        self.discovery_document().ucp.capabilities
    }

    /// Return the business version string.
    pub fn business_version(&self) -> &str {
        &self.ucp_version
    }

    /// Return whether AP2 mandate support is enabled.
    pub fn ap2_enabled(&self) -> bool {
        self.ap2_enabled
    }

    #[allow(dead_code)]
    fn response_meta(&self) -> UcpResponseMeta {
        self.response_meta_for(false, false, false, false)
    }

    fn response_meta_for(
        &self,
        include_fulfillment: bool,
        include_discount: bool,
        include_buyer_consent: bool,
        include_ap2: bool,
    ) -> UcpResponseMeta {
        let mut capabilities = vec![crate::models::CapabilityRef {
            name: CHECKOUT_CAPABILITY.to_string(),
            version: self.ucp_version.clone(),
        }];

        if include_fulfillment {
            capabilities.push(crate::models::CapabilityRef {
                name: FULFILLMENT_CAPABILITY.to_string(),
                version: self.ucp_version.clone(),
            });
        }

        if include_discount {
            capabilities.push(crate::models::CapabilityRef {
                name: DISCOUNT_CAPABILITY.to_string(),
                version: self.ucp_version.clone(),
            });
        }

        if include_buyer_consent && self.buyer_consent_enabled {
            capabilities.push(crate::models::CapabilityRef {
                name: BUYER_CONSENT_CAPABILITY.to_string(),
                version: self.ucp_version.clone(),
            });
        }

        if include_ap2 && self.ap2_enabled {
            capabilities.push(crate::models::CapabilityRef {
                name: AP2_MANDATE_CAPABILITY.to_string(),
                version: self.ucp_version.clone(),
            });
        }

        UcpResponseMeta {
            version: self.ucp_version.clone(),
            capabilities,
        }
    }

    fn order_meta(&self) -> UcpResponseMeta {
        UcpResponseMeta {
            version: self.ucp_version.clone(),
            capabilities: vec![crate::models::CapabilityRef {
                name: ORDER_CAPABILITY.to_string(),
                version: self.ucp_version.clone(),
            }],
        }
    }

    /// Generates AP2 merchant authorization for a specific checkout.
    /// This creates a detached JWS signature over the canonicalized checkout data.
    fn ap2_response_for_checkout(&self, checkout: &CheckoutResponse) -> Option<Ap2CheckoutResponse> {
        if !self.ap2_enabled {
            return None;
        }

        // If we have a static authorization, use it
        if let Some(authorization) = &self.ap2_merchant_authorization {
            return Some(Ap2CheckoutResponse {
                merchant_authorization: authorization.clone(),
            });
        }

        // Generate dynamic signature using signing key
        let signing_key = self.ap2_signing_key.as_ref()?;

        // Build the payload to sign (checkout without ap2 field)
        let mut checkout_value = serde_json::to_value(checkout).ok()?;
        if let Some(obj) = checkout_value.as_object_mut() {
            obj.remove("ap2"); // Exclude ap2 field from signing
        }

        // Canonicalize and sign
        let canonical = canonicalize(&checkout_value).ok()?;
        let jws = sign_detached_b64(&canonical, signing_key).ok()?;

        Some(Ap2CheckoutResponse {
            merchant_authorization: jws.to_compact(),
        })
    }

    fn verify_ap2_mandate(
        &self,
        mandate: &str,
        checkout: &CheckoutResponse,
        platform_keys: &[VerifyingKey],
    ) -> Result<(), ServiceError> {
        let payload = self.verify_sd_jwt_signature(mandate, platform_keys)?;
        self.verify_sd_jwt_claims(&payload, checkout)?;
        self.verify_merchant_authorization(checkout)?;
        Ok(())
    }

    fn verify_sd_jwt_signature(
        &self,
        mandate: &str,
        platform_keys: &[VerifyingKey],
    ) -> Result<serde_json::Value, ServiceError> {
        let sd_jwt = mandate.split('~').next().unwrap_or("").trim();
        if sd_jwt.is_empty() {
            return Err(ServiceError::InvalidInput(
                "ap2.checkout_mandate is missing SD-JWT header".to_string(),
            ));
        }

        let compact = CompactJws::from_compact(sd_jwt)
            .map_err(|err| ServiceError::InvalidInput(err.to_string()))?;
        let header = compact
            .header()
            .map_err(|err| ServiceError::InvalidInput(err.to_string()))?;
        let kid = header.kid.as_deref().ok_or_else(|| {
            ServiceError::InvalidInput(
                "ap2.checkout_mandate header must include kid".to_string(),
            )
        })?;

        let candidates: Vec<&VerifyingKey> = platform_keys
            .iter()
            .filter(|key| key.kid == kid)
            .collect();
        if candidates.is_empty() {
            return Err(ServiceError::InvalidInput(
                "ap2.checkout_mandate signing key not found".to_string(),
            ));
        }

        for key in candidates {
            if verify_compact_jws(&compact, key).is_ok() {
                return compact
                    .payload_json()
                    .map_err(|err| ServiceError::InvalidInput(err.to_string()));
            }
        }

        Err(ServiceError::InvalidInput(
            "ap2.checkout_mandate signature verification failed".to_string(),
        ))
    }

    fn verify_sd_jwt_claims(
        &self,
        payload: &serde_json::Value,
        checkout: &CheckoutResponse,
    ) -> Result<(), ServiceError> {
        let now = Utc::now().timestamp();
        if let Some(exp) = payload.get("exp").and_then(|value| value.as_i64()) {
            if exp <= now {
                return Err(ServiceError::InvalidInput(
                    "ap2.checkout_mandate is expired".to_string(),
                ));
            }
        }

        if let Some(checkout_id) = payload
            .get("checkout_id")
            .and_then(|value| value.as_str())
        {
            if checkout_id != checkout.id {
                return Err(ServiceError::InvalidInput(
                    "ap2.checkout_mandate checkout_id mismatch".to_string(),
                ));
            }
        }

        if let Some(checkout_value) = payload.get("checkout") {
            if let Some(id) = checkout_value.get("id").and_then(|value| value.as_str()) {
                if id != checkout.id {
                    return Err(ServiceError::InvalidInput(
                        "ap2.checkout_mandate checkout mismatch".to_string(),
                    ));
                }
            }
            if let Some(merchant_auth) = checkout_value
                .get("ap2")
                .and_then(|value| value.get("merchant_authorization"))
                .and_then(|value| value.as_str())
            {
                if let Some(current) = checkout
                    .ap2
                    .as_ref()
                    .map(|ap2| ap2.merchant_authorization.as_str())
                {
                    if merchant_auth != current {
                        return Err(ServiceError::InvalidInput(
                            "ap2.checkout_mandate merchant_authorization mismatch".to_string(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    fn verify_merchant_authorization(
        &self,
        checkout: &CheckoutResponse,
    ) -> Result<(), ServiceError> {
        let ap2 = checkout.ap2.as_ref().ok_or_else(|| {
            ServiceError::InvalidInput("ap2.merchant_authorization is required".to_string())
        })?;

        if let Some(expected) = self.ap2_merchant_authorization.as_ref() {
            if ap2.merchant_authorization != *expected {
                return Err(ServiceError::InvalidInput(
                    "ap2.merchant_authorization mismatch".to_string(),
                ));
            }
            return Ok(());
        }

        let signing_key = self.ap2_signing_key.as_ref().ok_or_else(|| {
            ServiceError::InvalidInput("ap2 signing key is not configured".to_string())
        })?;
        let verifying_key = verifying_key_from_signing(signing_key);
        let jws = DetachedJws::from_compact(&ap2.merchant_authorization)
            .map_err(|err| ServiceError::InvalidInput(err.to_string()))?;
        let checkout_value = checkout_value_without_ap2(checkout)?;
        let canonical =
            canonicalize(&checkout_value).map_err(|err| ServiceError::InvalidInput(err.to_string()))?;

        verify_detached_b64(&jws, &canonical, &verifying_key)
            .map_err(|err| ServiceError::InvalidInput(err.to_string()))
    }

    fn build_line_items(
        &self,
        items: &[LineItemInput],
        currency: &str,
    ) -> Result<Vec<LineItemResponse>, ServiceError> {
        let mut line_items = Vec::with_capacity(items.len());

        for item in items {
            validate_quantity(item.quantity)?;
            self.catalog.check_inventory(&item.item.id, item.quantity)?;

            let product = self.catalog.get(&item.item.id)?;
            if product.currency.to_uppercase() != currency {
                return Err(ServiceError::InvalidInput(format!(
                    "Item {} uses currency {}, expected {}",
                    product.id, product.currency, currency
                )));
            }

            let line_item_id = item
                .id
                .as_ref()
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string())
                .unwrap_or_else(|| format!("li_{}", Uuid::new_v4()));

            let mut line_item = LineItemResponse {
                id: line_item_id,
                item: crate::models::ItemResponse {
                    id: product.id,
                    title: product.title,
                    price: product.price,
                    image_url: product.image_url,
                    extra: item.item.extra.clone(),
                },
                quantity: item.quantity,
                totals: Vec::new(),
                parent_id: item.parent_id.clone(),
                extra: item.extra.clone(),
            };

            self.update_line_item_totals(&mut line_item, 0);
            line_items.push(line_item);
        }

        Ok(line_items)
    }

    fn update_line_item_totals(&self, line_item: &mut LineItemResponse, discount: i64) {
        let subtotal = line_item.item.price * line_item.quantity as i64;
        let mut totals = Vec::new();

        totals.push(Total {
            total_type: "subtotal".to_string(),
            display_text: Some("Subtotal".to_string()),
            amount: subtotal,
        });

        if discount > 0 {
            totals.push(Total {
                total_type: "items_discount".to_string(),
                display_text: Some("Items discount".to_string()),
                amount: discount,
            });
        }

        totals.push(Total {
            total_type: "total".to_string(),
            display_text: Some("Total".to_string()),
            amount: (subtotal - discount).max(0),
        });

        line_item.totals = totals;
    }

    fn apply_discounts(
        &self,
        line_items: &mut [LineItemResponse],
        discounts: Option<DiscountsObject>,
        fulfillment_cost: i64,
        currency: &str,
    ) -> Result<DiscountOutcome, ServiceError> {
        let Some(discounts) = discounts else {
            return Ok(DiscountOutcome {
                discounts: None,
                items_discount: 0,
                order_discount: 0,
            });
        };

        let had_codes = discounts.codes.is_some();
        let raw_codes = discounts.codes.unwrap_or_default();
        let normalized_codes = raw_codes
            .iter()
            .map(|code| code.trim().to_uppercase())
            .filter(|code| !code.is_empty())
            .collect::<Vec<_>>();

        // Try iCommerce Promotions first if available
        if self.use_icommerce_promotions {
            if let Some(ref commerce) = self.commerce {
                if let Some(result) = self.try_icommerce_promotions(
                    commerce,
                    line_items,
                    &normalized_codes,
                    fulfillment_cost,
                    currency,
                )? {
                    return Ok(result);
                }
                // Fall through to legacy codes if iCommerce didn't match
            }
        }

        // Legacy hardcoded discount codes
        self.apply_legacy_discounts(line_items, &normalized_codes, fulfillment_cost, had_codes)
    }

    /// Try to apply discounts via iCommerce Promotions API
    fn try_icommerce_promotions(
        &self,
        commerce: &crate::commerce::CommerceEngine,
        line_items: &mut [LineItemResponse],
        codes: &[String],
        fulfillment_cost: i64,
        currency: &str,
    ) -> Result<Option<DiscountOutcome>, ServiceError> {
        use crate::commerce_adapter::{cents_to_decimal, decimal_to_cents};
        use stateset_embedded::{ApplyPromotionsRequest, PromotionLineItem, PromotionTarget};

        if codes.is_empty() {
            return Ok(None);
        }

        // Build promotion request
        let subtotal: i64 = line_items
            .iter()
            .map(|li| li.item.price * li.quantity as i64)
            .sum();

        let promo_line_items: Vec<PromotionLineItem> = line_items
            .iter()
            .map(|li| PromotionLineItem {
                id: li.id.clone(),
                product_id: None,
                variant_id: None,
                sku: Some(li.item.id.clone()),
                category_ids: vec![],
                quantity: li.quantity,
                unit_price: cents_to_decimal(li.item.price),
                line_total: cents_to_decimal(li.item.price * li.quantity as i64),
            })
            .collect();

        let request = ApplyPromotionsRequest {
            cart_id: None,
            customer_id: None,
            coupon_codes: codes.to_vec(),
            line_items: promo_line_items,
            subtotal: cents_to_decimal(subtotal),
            shipping_amount: cents_to_decimal(fulfillment_cost),
            shipping_country: None,
            shipping_state: None,
            currency: currency.to_string(),
            is_first_order: false,
        };

        let result = commerce.promotions().apply(request);

        match result {
            Ok(promo_result) => {
                // Check if any promotions were applied
                if promo_result.applied_promotions.is_empty() {
                    return Ok(None); // Fall back to legacy codes
                }

                // Convert iCommerce result to UCP DiscountOutcome
                let mut items_discount = 0i64;
                let mut order_discount = 0i64;
                let mut per_item_discount = vec![0i64; line_items.len()];

                let applied: Vec<AppliedDiscount> = promo_result
                    .applied_promotions
                    .iter()
                    .map(|promo| {
                        let amount = decimal_to_cents(promo.discount_amount);

                        // Determine discount target
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
                            method: Some("across".to_string()),
                            priority: None,
                            allocations: None, // iCommerce doesn't provide per-item allocations in this structure
                        }
                    })
                    .collect();

                // Apply per-line-item discounts from iCommerce
                for lid in &promo_result.line_item_discounts {
                    if let Some(index) = line_items.iter().position(|li| li.id == lid.line_item_id) {
                        per_item_discount[index] += decimal_to_cents(lid.discount_amount);
                    }
                }

                // Update line item totals
                for (index, line_item) in line_items.iter_mut().enumerate() {
                    let discount = per_item_discount.get(index).copied().unwrap_or(0);
                    self.update_line_item_totals(line_item, discount);
                }

                let codes_vec = if codes.is_empty() {
                    None
                } else {
                    Some(codes.to_vec())
                };

                Ok(Some(DiscountOutcome {
                    discounts: Some(DiscountsObject {
                        codes: codes_vec,
                        applied: Some(applied),
                    }),
                    items_discount,
                    order_discount,
                }))
            }
            Err(e) => {
                tracing::warn!("iCommerce promotions error: {}, falling back to legacy codes", e);
                Ok(None) // Fall back to legacy codes
            }
        }
    }

    /// Apply legacy hardcoded discount codes (SAVE10, SAVE5, SHIPFREE)
    fn apply_legacy_discounts(
        &self,
        line_items: &mut [LineItemResponse],
        normalized_codes: &[String],
        fulfillment_cost: i64,
        had_codes: bool,
    ) -> Result<DiscountOutcome, ServiceError> {
        let line_subtotals = line_items
            .iter()
            .map(|line_item| line_item.item.price * line_item.quantity as i64)
            .collect::<Vec<_>>();

        let mut per_item_discount = vec![0i64; line_items.len()];
        let mut applied = Vec::new();
        let mut order_discount = 0i64;
        let mut seen_codes = HashSet::new();

        for code in normalized_codes {
            if !seen_codes.insert(code.clone()) {
                continue;
            }

            match code.as_str() {
                "SAVE10" => {
                    let mut allocations = Vec::new();
                    let mut amount = 0i64;
                    for (index, subtotal) in line_subtotals.iter().enumerate() {
                        let discount = (subtotal * 10) / 100;
                        if discount <= 0 {
                            continue;
                        }
                        per_item_discount[index] += discount;
                        amount += discount;
                        allocations.push(DiscountAllocation {
                            path: format!("$.line_items[{}]", index),
                            amount: discount,
                        });
                    }

                    if amount > 0 {
                        applied.push(AppliedDiscount {
                            code: Some(code.clone()),
                            title: "Save 10%".to_string(),
                            amount,
                            automatic: Some(false),
                            method: Some("across".to_string()),
                            priority: Some(1),
                            allocations: Some(allocations),
                        });
                    }
                }
                "SAVE5" => {
                    let mut allocations = vec![0i64; line_items.len()];
                    let available = line_subtotals
                        .iter()
                        .enumerate()
                        .map(|(index, subtotal)| (subtotal - per_item_discount[index]).max(0))
                        .collect::<Vec<_>>();
                    let available_total: i64 = available.iter().sum();
                    let mut discount_total = 500i64;
                    if available_total <= 0 {
                        continue;
                    }
                    if discount_total > available_total {
                        discount_total = available_total;
                    }

                    let mut allocated = 0i64;
                    for (index, value) in available.iter().enumerate() {
                        if *value == 0 {
                            continue;
                        }
                        let share = (discount_total * value) / available_total;
                        allocations[index] = share;
                        allocated += share;
                    }

                    let mut remainder = discount_total - allocated;
                    if remainder > 0 {
                        for (index, value) in available.iter().enumerate() {
                            if *value > allocations[index] {
                                let add = remainder.min(value - allocations[index]);
                                allocations[index] += add;
                                remainder -= add;
                            }
                            if remainder == 0 {
                                break;
                            }
                        }
                    }

                    let mut applied_allocations = Vec::new();
                    let mut amount = 0i64;
                    for (index, value) in allocations.iter().enumerate() {
                        if *value == 0 {
                            continue;
                        }
                        per_item_discount[index] += *value;
                        amount += *value;
                        applied_allocations.push(DiscountAllocation {
                            path: format!("$.line_items[{}]", index),
                            amount: *value,
                        });
                    }

                    if amount > 0 {
                        applied.push(AppliedDiscount {
                            code: Some(code.clone()),
                            title: "Save $5".to_string(),
                            amount,
                            automatic: Some(false),
                            method: Some("across".to_string()),
                            priority: Some(2),
                            allocations: Some(applied_allocations),
                        });
                    }
                }
                "SHIPFREE" => {
                    let discount = fulfillment_cost.max(0);
                    if discount > 0 {
                        order_discount += discount;
                        applied.push(AppliedDiscount {
                            code: Some(code.clone()),
                            title: "Free shipping".to_string(),
                            amount: discount,
                            automatic: Some(false),
                            method: Some("across".to_string()),
                            priority: Some(3),
                            allocations: Some(vec![DiscountAllocation {
                                path: "$.totals.fulfillment".to_string(),
                                amount: discount,
                            }]),
                        });
                    }
                }
                _ => {}
            }
        }

        for (index, line_item) in line_items.iter_mut().enumerate() {
            let discount = per_item_discount.get(index).copied().unwrap_or(0);
            self.update_line_item_totals(line_item, discount);
        }

        let items_discount = per_item_discount.iter().sum();
        let codes = if had_codes {
            Some(normalized_codes.to_vec())
        } else {
            None
        };
        let applied = if applied.is_empty() { None } else { Some(applied) };

        Ok(DiscountOutcome {
            discounts: if codes.is_some() || applied.is_some() {
                Some(DiscountsObject { codes, applied })
            } else {
                None
            },
            items_discount,
            order_discount,
        })
    }

    fn calculate_totals(
        &self,
        line_items: &[LineItemResponse],
        items_discount: i64,
        fulfillment_cost: i64,
        order_discount: i64,
        currency: &str,
        fulfillment: Option<&Fulfillment>,
    ) -> Result<Vec<Total>, ServiceError> {
        let subtotal: i64 = line_items
            .iter()
            .map(|line_item| line_item.item.price * line_item.quantity as i64)
            .sum();

        let mut totals = Vec::new();
        totals.push(Total {
            total_type: "subtotal".to_string(),
            display_text: Some("Subtotal".to_string()),
            amount: subtotal,
        });

        if items_discount > 0 {
            totals.push(Total {
                total_type: "items_discount".to_string(),
                display_text: Some("Items discount".to_string()),
                amount: items_discount,
            });
        }

        if fulfillment_cost > 0 {
            totals.push(Total {
                total_type: "fulfillment".to_string(),
                display_text: Some("Fulfillment".to_string()),
                amount: fulfillment_cost,
            });
        }

        if order_discount > 0 {
            totals.push(Total {
                total_type: "discount".to_string(),
                display_text: Some("Discount".to_string()),
                amount: order_discount,
            });
        }

        let taxable_amount =
            (subtotal - items_discount + fulfillment_cost - order_discount).max(0);

        // Try iCommerce Tax API first, fall back to fixed rate
        let tax = self.calculate_tax(
            line_items,
            taxable_amount,
            currency,
            fulfillment,
            fulfillment_cost,
        );
        if tax > 0 {
            totals.push(Total {
                total_type: "tax".to_string(),
                display_text: Some("Tax".to_string()),
                amount: tax,
            });
        }

        let total = (taxable_amount + tax).max(0);
        totals.push(Total {
            total_type: "total".to_string(),
            display_text: Some("Total".to_string()),
            amount: total,
        });

        Ok(totals)
    }

    /// Calculate tax using iCommerce Tax API or fallback to fixed rate
    fn calculate_tax(
        &self,
        line_items: &[LineItemResponse],
        taxable_amount: i64,
        currency: &str,
        fulfillment: Option<&Fulfillment>,
        fulfillment_cost: i64,
    ) -> i64 {
        let tax_address = fulfillment.and_then(|value| self.tax_address_from_fulfillment(value));

        // Try iCommerce Tax API if available
        if self.use_icommerce_tax {
            if let Some(ref commerce) = self.commerce {
                if let Some(tax) = self.try_icommerce_tax(
                    commerce,
                    line_items,
                    currency,
                    tax_address,
                    fulfillment_cost,
                )
                {
                    return tax;
                }
            }
        }

        // Fallback to fixed rate
        (taxable_amount * self.tax_bps) / 10_000
    }

    /// Try to calculate tax using iCommerce Tax API
    fn try_icommerce_tax(
        &self,
        commerce: &crate::commerce::CommerceEngine,
        line_items: &[LineItemResponse],
        currency: &str,
        tax_address: Option<stateset_embedded::TaxAddress>,
        fulfillment_cost: i64,
    ) -> Option<i64> {
        use crate::commerce_adapter::{cents_to_decimal, decimal_to_cents};
        use rust_decimal::Decimal;
        use stateset_embedded::{ProductTaxCategory, TaxAddress, TaxCalculationRequest, TaxLineItem};

        // Build tax calculation request
        let tax_line_items: Vec<TaxLineItem> = line_items
            .iter()
            .map(|li| TaxLineItem {
                id: li.id.clone(),
                quantity: Decimal::from(li.quantity),
                unit_price: cents_to_decimal(li.item.price),
                tax_category: ProductTaxCategory::Standard,
                sku: Some(li.item.id.clone()),
                product_id: None,
                tax_code: None,
                description: None,
                discount_amount: Decimal::ZERO,
            })
            .collect();

        let shipping_address = tax_address.unwrap_or_else(|| TaxAddress {
            country: "US".to_string(),
            state: None,
            city: None,
            postal_code: None,
            line1: None,
            line2: None,
        });

        let shipping_amount = if fulfillment_cost > 0 {
            Some(cents_to_decimal(fulfillment_cost))
        } else {
            None
        };

        // Use the fulfillment address when available; otherwise fall back to defaults.
        let request = TaxCalculationRequest {
            line_items: tax_line_items,
            shipping_address,
            billing_address: None,
            shipping_amount,
            customer_id: None,
            transaction_date: None,
            currency: currency.to_string(),
            prices_include_tax: false,
        };

        match commerce.tax().calculate(request) {
            Ok(result) => {
                let tax_cents = decimal_to_cents(result.total_tax);
                if tax_cents > 0 {
                    Some(tax_cents)
                } else {
                    None // Fall back to fixed rate
                }
            }
            Err(e) => {
                tracing::debug!("iCommerce tax calculation error: {}, using fallback rate", e);
                None // Fall back to fixed rate
            }
        }
    }

    fn build_fulfillment(
        &self,
        fulfillment: Option<Fulfillment>,
        line_items: &[LineItemResponse],
        checkout_id: Option<&str>,
    ) -> Result<(Option<Fulfillment>, i64), ServiceError> {
        let Some(mut fulfillment) = fulfillment else {
            return Ok((None, 0));
        };

        let line_item_ids = line_items
            .iter()
            .map(|item| item.id.clone())
            .collect::<Vec<_>>();

        let mut methods = fulfillment.methods.take().unwrap_or_else(|| {
            vec![FulfillmentMethod {
                id: Some(format!("fm_{}", Uuid::new_v4())),
                method_type: "shipping".to_string(),
                line_item_ids: line_item_ids.clone(),
                destinations: None,
                selected_destination_id: None,
                groups: None,
                extra: HashMap::new(),
            }]
        });

        for method in &mut methods {
            if method.id.as_deref().unwrap_or("").trim().is_empty() {
                method.id = Some(format!("fm_{}", Uuid::new_v4()));
            }
            if method.method_type.trim().is_empty() {
                method.method_type = "shipping".to_string();
            }
            if method.line_item_ids.is_empty()
                || method
                    .line_item_ids
                    .iter()
                    .any(|id| !line_item_ids.contains(id))
            {
                method.line_item_ids = line_item_ids.clone();
            }

            if let Some(destinations) = method.destinations.as_mut() {
                for destination in destinations.iter_mut() {
                    if destination.id.as_deref().unwrap_or("").trim().is_empty() {
                        destination.id = Some(format!("dest_{}", Uuid::new_v4()));
                    }
                }
            }

            if method.selected_destination_id.is_none() {
                if let Some(destinations) = method.destinations.as_ref() {
                    if destinations.len() == 1 {
                        method.selected_destination_id = destinations[0].id.clone();
                    }
                }
            }

            let mut groups = method.groups.take().unwrap_or_else(|| {
                vec![FulfillmentGroup {
                    id: Some(format!("grp_{}", Uuid::new_v4())),
                    line_item_ids: method.line_item_ids.clone(),
                    options: Some(self.get_fulfillment_options(checkout_id)),
                    selected_option_id: None,
                    extra: HashMap::new(),
                }]
            });

            for group in &mut groups {
                if group.id.as_deref().unwrap_or("").trim().is_empty() {
                    group.id = Some(format!("grp_{}", Uuid::new_v4()));
                }
                if group.line_item_ids.is_empty()
                    || group
                        .line_item_ids
                        .iter()
                        .any(|id| !method.line_item_ids.contains(id))
                {
                    group.line_item_ids = method.line_item_ids.clone();
                }
                if group.options.is_none() {
                    group.options = Some(self.get_fulfillment_options(checkout_id));
                }
                if let Some(options) = group.options.as_mut() {
                    for (index, option) in options.iter_mut().enumerate() {
                        if option.id.as_deref().unwrap_or("").trim().is_empty() {
                            option.id = Some(format!("opt_{}", Uuid::new_v4()));
                        }
                        if option.title.as_deref().unwrap_or("").trim().is_empty() {
                            option.title =
                                Some(format!("Fulfillment Option {}", index + 1));
                        }
                        if option.totals.is_empty() {
                            option.totals.push(Total {
                                total_type: "total".to_string(),
                                display_text: Some("Fulfillment".to_string()),
                                amount: 0,
                            });
                        }
                    }
                }
                if group.selected_option_id.is_none() {
                    group.selected_option_id = group
                        .options
                        .as_ref()
                        .and_then(|options| options.first().and_then(|option| option.id.clone()));
                }
            }

            method.groups = Some(groups);
        }

        let available_methods = methods
            .iter()
            .map(|method| FulfillmentAvailableMethod {
                id: method
                    .id
                    .clone()
                    .unwrap_or_else(|| format!("fm_{}", Uuid::new_v4())),
                method_type: method.method_type.clone(),
                line_item_ids: method.line_item_ids.clone(),
                extra: HashMap::new(),
            })
            .collect::<Vec<_>>();

        fulfillment.methods = Some(methods);
        fulfillment.available_methods = Some(available_methods);

        let fulfillment_total = self.selected_fulfillment_cost(&fulfillment);
        Ok((Some(fulfillment), fulfillment_total))
    }

    fn get_fulfillment_options(&self, checkout_id: Option<&str>) -> Vec<FulfillmentOption> {
        // Try iCommerce shipping rates first
        if self.use_icommerce_shipping {
            if let Some(ref commerce) = self.commerce {
                if let Some(id) = checkout_id {
                    if let Some(options) = self.try_icommerce_shipping_rates(commerce, id) {
                        if !options.is_empty() {
                            return options;
                        }
                    }
                }
            }
        }

        // Fallback to default hardcoded options
        self.default_fulfillment_options()
    }

    /// Try to get shipping rates from iCommerce
    fn try_icommerce_shipping_rates(
        &self,
        commerce: &crate::commerce::CommerceEngine,
        checkout_id: &str,
    ) -> Option<Vec<FulfillmentOption>> {
        use crate::commerce_adapter::{decimal_to_cents, parse_checkout_id};

        let cart_id = parse_checkout_id(checkout_id)?;

        let rates = commerce.carts().get_shipping_rates(cart_id).ok()?;

        if rates.is_empty() {
            return None;
        }

        let now = Utc::now();
        let options: Vec<FulfillmentOption> = rates
            .into_iter()
            .map(|rate| {
                let estimated_days = rate.estimated_days.unwrap_or(5);
                let earliest = rate
                    .estimated_delivery
                    .unwrap_or_else(|| now + ChronoDuration::days(estimated_days as i64));

                FulfillmentOption {
                    id: Some(rate.id),
                    title: Some(format!("{} {}", rate.carrier, rate.service)),
                    description: rate.description,
                    carrier: Some(rate.carrier),
                    earliest_fulfillment_time: Some(earliest.to_rfc3339()),
                    latest_fulfillment_time: Some(
                        (earliest + ChronoDuration::days(2)).to_rfc3339(),
                    ),
                    totals: vec![Total {
                        total_type: "total".to_string(),
                        display_text: Some("Shipping".to_string()),
                        amount: decimal_to_cents(rate.price),
                    }],
                    extra: HashMap::new(),
                }
            })
            .collect();

        Some(options)
    }

    /// Default hardcoded fulfillment options (fallback when iCommerce unavailable)
    fn default_fulfillment_options(&self) -> Vec<FulfillmentOption> {
        let now = Utc::now();
        let standard_total = 500;
        let express_total = 1500;

        vec![
            FulfillmentOption {
                id: Some("ship_standard".to_string()),
                title: Some("Standard Shipping".to_string()),
                description: Some("Arrives in 5-7 business days".to_string()),
                carrier: Some("UPS".to_string()),
                earliest_fulfillment_time: Some((now + ChronoDuration::days(5)).to_rfc3339()),
                latest_fulfillment_time: Some((now + ChronoDuration::days(7)).to_rfc3339()),
                totals: vec![Total {
                    total_type: "total".to_string(),
                    display_text: Some("Shipping".to_string()),
                    amount: standard_total,
                }],
                extra: HashMap::new(),
            },
            FulfillmentOption {
                id: Some("ship_express".to_string()),
                title: Some("Express Shipping".to_string()),
                description: Some("Arrives in 2-3 business days".to_string()),
                carrier: Some("FedEx".to_string()),
                earliest_fulfillment_time: Some((now + ChronoDuration::days(2)).to_rfc3339()),
                latest_fulfillment_time: Some((now + ChronoDuration::days(3)).to_rfc3339()),
                totals: vec![Total {
                    total_type: "total".to_string(),
                    display_text: Some("Shipping".to_string()),
                    amount: express_total,
                }],
                extra: HashMap::new(),
            },
        ]
    }

    fn tax_address_from_fulfillment(
        &self,
        fulfillment: &Fulfillment,
    ) -> Option<stateset_embedded::TaxAddress> {
        let methods = fulfillment.methods.as_ref()?;

        for method in methods {
            let destinations = method.destinations.as_ref()?;
            let selected = method
                .selected_destination_id
                .as_ref()
                .and_then(|id| destinations.iter().find(|dest| dest.id.as_ref() == Some(id)))
                .or_else(|| destinations.first());

            if let Some(destination) = selected {
                if let Some(address) = self.tax_address_from_destination(&destination.data) {
                    return Some(address);
                }
            }
        }

        None
    }

    fn tax_address_from_destination(
        &self,
        data: &HashMap<String, serde_json::Value>,
    ) -> Option<stateset_embedded::TaxAddress> {
        let nested = data
            .get("address")
            .or_else(|| data.get("postal_address"))
            .or_else(|| data.get("shipping_address"))
            .and_then(|value| value.as_object());

        let get_str = |key: &str| -> Option<String> {
            if let Some(map) = nested {
                if let Some(value) = map.get(key).and_then(|value| value.as_str()) {
                    return Some(value.to_string());
                }
            }
            data.get(key)
                .and_then(|value| value.as_str())
                .map(|value| value.to_string())
        };

        let country = get_str("address_country").or_else(|| get_str("country"));
        let state = get_str("address_region").or_else(|| get_str("state"));
        let city = get_str("address_locality").or_else(|| get_str("city"));
        let postal_code = get_str("postal_code");
        let line1 = get_str("street_address").or_else(|| get_str("line1"));
        let line2 = get_str("extended_address").or_else(|| get_str("line2"));

        let has_any = country.is_some()
            || state.is_some()
            || city.is_some()
            || postal_code.is_some()
            || line1.is_some()
            || line2.is_some();

        if !has_any {
            return None;
        }

        Some(stateset_embedded::TaxAddress {
            country: country.unwrap_or_else(|| "US".to_string()),
            state,
            city,
            postal_code,
            line1,
            line2,
        })
    }

    fn selected_fulfillment_cost(&self, fulfillment: &Fulfillment) -> i64 {
        let Some(methods) = fulfillment.methods.as_ref() else {
            return 0;
        };

        methods
            .iter()
            .flat_map(|method| method.groups.as_ref().into_iter().flatten())
            .filter_map(|group| {
                let options = group.options.as_ref()?;
                let selected = group
                    .selected_option_id
                    .as_ref()
                    .and_then(|id| options.iter().find(|option| option.id.as_ref() == Some(id)))
                    .or_else(|| options.first());
                selected.map(|option| self.fulfillment_option_total(option))
            })
            .sum()
    }

    fn fulfillment_option_total(&self, option: &FulfillmentOption) -> i64 {
        option
            .totals
            .iter()
            .find(|total| total.total_type == "total")
            .map(|total| total.amount)
            .unwrap_or_else(|| option.totals.iter().map(|total| total.amount).sum())
    }

    fn build_payment_response(
        &self,
        request: PaymentRequest,
        existing: Option<PaymentResponse>,
    ) -> PaymentResponse {
        let mut payment = PaymentResponse {
            handlers: self.handlers.clone(),
            selected_instrument_id: request.selected_instrument_id,
            instruments: request.instruments,
            extra: request.extra,
        };

        if payment.selected_instrument_id.is_none() {
            if let Some(existing_payment) = existing {
                payment.selected_instrument_id = existing_payment.selected_instrument_id;
                if payment.instruments.is_none() {
                    payment.instruments = existing_payment.instruments;
                }
            }
        }

        payment
    }

    fn apply_status(&self, checkout: &mut CheckoutResponse) {
        self.auto_select_instrument(&mut checkout.payment);
        let mut messages = Vec::new();

        if checkout
            .buyer
            .as_ref()
            .and_then(|buyer| buyer.email.as_ref())
            .is_none()
        {
            messages.push(Message {
                message_type: "error".to_string(),
                code: Some("missing".to_string()),
                path: Some("$.buyer.email".to_string()),
                content_type: Some("plain".to_string()),
                content: "Buyer email is required".to_string(),
                severity: Some("recoverable".to_string()),
            });
        }

        if !self.has_selected_instrument(&checkout.payment) {
            messages.push(Message {
                message_type: "error".to_string(),
                code: Some("missing_payment".to_string()),
                path: Some("$.payment.selected_instrument_id".to_string()),
                content_type: Some("plain".to_string()),
                content: "A selected payment instrument is required".to_string(),
                severity: Some("recoverable".to_string()),
            });
        }

        if let Some(selected_id) = checkout.payment.selected_instrument_id.as_deref() {
            if let Some(instruments) = checkout.payment.instruments.as_ref() {
                if let Some((index, instrument)) = instruments
                    .iter()
                    .enumerate()
                    .find(|(_, instrument)| instrument.id == selected_id)
                {
                    if instrument.instrument_type == "card" {
                        let missing_brand = instrument
                            .brand
                            .as_deref()
                            .map(|value| value.trim().is_empty())
                            .unwrap_or(true);
                        let missing_digits = instrument
                            .last_digits
                            .as_deref()
                            .map(|value| value.trim().is_empty())
                            .unwrap_or(true);
                        if missing_brand || missing_digits {
                            messages.push(Message {
                                message_type: "error".to_string(),
                                code: Some("missing".to_string()),
                                path: Some(format!("$.payment.instruments[{}]", index)),
                                content_type: Some("plain".to_string()),
                                content: "Card payment instruments require brand and last_digits"
                                    .to_string(),
                                severity: Some("recoverable".to_string()),
                            });
                        }
                    }
                }
            }
        }

        if let Some(fulfillment) = checkout.fulfillment.as_ref() {
            if let Some(methods) = fulfillment.methods.as_ref() {
                for (index, method) in methods.iter().enumerate() {
                    if method.method_type != "shipping" && method.method_type != "pickup" {
                        messages.push(Message {
                            message_type: "error".to_string(),
                            code: Some("invalid".to_string()),
                            path: Some(format!("$.fulfillment.methods[{}].type", index)),
                            content_type: Some("plain".to_string()),
                            content: "Fulfillment method type must be shipping or pickup"
                                .to_string(),
                            severity: Some("recoverable".to_string()),
                        });
                        continue;
                    }

                    if method.selected_destination_id.as_deref().unwrap_or("").is_empty() {
                        messages.push(Message {
                            message_type: "error".to_string(),
                            code: Some("missing_destination".to_string()),
                            path: Some(format!(
                                "$.fulfillment.methods[{}].selected_destination_id",
                                index
                            )),
                            content_type: Some("plain".to_string()),
                            content: "Fulfillment destination is required".to_string(),
                            severity: Some("requires_buyer_input".to_string()),
                        });
                        continue;
                    }

                    if method.method_type == "pickup" {
                        let destinations = method.destinations.as_ref();
                        let selected = destinations.and_then(|destinations| {
                            let selected_id = method.selected_destination_id.as_ref()?;
                            destinations
                                .iter()
                                .find(|dest| dest.id.as_ref() == Some(selected_id))
                                .or_else(|| destinations.first())
                        });
                        if let Some(destination) = selected {
                            let name = destination
                                .data
                                .get("name")
                                .and_then(|value| value.as_str())
                                .unwrap_or("")
                                .trim();
                            if name.is_empty() {
                                messages.push(Message {
                                    message_type: "error".to_string(),
                                    code: Some("missing".to_string()),
                                    path: Some(format!(
                                        "$.fulfillment.methods[{}].destinations",
                                        index
                                    )),
                                    content_type: Some("plain".to_string()),
                                    content: "Pickup destinations require a name".to_string(),
                                    severity: Some("recoverable".to_string()),
                                });
                            }
                        }
                    }
                }
            }
        }

        let requires_escalation = messages.iter().any(|message| {
            matches!(
                message.severity.as_deref(),
                Some("requires_buyer_input") | Some("requires_buyer_review")
            )
        });

        if messages.is_empty() {
            checkout.status = CheckoutStatus::ReadyForComplete;
            checkout.messages = None;
            checkout.continue_url = None;
        } else if requires_escalation {
            checkout.status = CheckoutStatus::RequiresEscalation;
            checkout.messages = Some(messages);
            checkout.continue_url =
                Some(format!("{}/checkout/{}", self.base_url, checkout.id));
        } else {
            checkout.status = CheckoutStatus::Incomplete;
            checkout.messages = Some(messages);
            checkout.continue_url = None;
        }
    }

    fn has_selected_instrument(&self, payment: &PaymentResponse) -> bool {
        let Some(selected_id) = payment.selected_instrument_id.as_deref() else {
            return false;
        };

        let Some(instruments) = payment.instruments.as_ref() else {
            return false;
        };

        instruments.iter().any(|instrument| instrument.id == selected_id)
    }

    fn auto_select_instrument(&self, payment: &mut PaymentResponse) {
        if payment.selected_instrument_id.is_some() {
            return;
        }

        if let Some(instruments) = payment.instruments.as_ref() {
            if instruments.len() == 1 {
                payment.selected_instrument_id = Some(instruments[0].id.clone());
            }
        }
    }

    fn attach_payment_data(
        &self,
        checkout: &mut CheckoutResponse,
        payment_data: PaymentInstrument,
    ) -> Result<(), ServiceError> {
        if payment_data.id.trim().is_empty() {
            return Err(ServiceError::InvalidInput(
                "payment_data.id is required".to_string(),
            ));
        }

        if let Some(credential) = payment_data.credential.as_ref() {
            if is_card_credential(credential) {
                return Err(ServiceError::InvalidInput(
                    "payment_data.credential must be tokenized; card credentials are not permitted"
                        .to_string(),
                ));
            }
        }

        let payment = &mut checkout.payment;
        let instruments = payment.instruments.get_or_insert_with(Vec::new);
        if let Some(existing) = instruments
            .iter_mut()
            .find(|instrument| instrument.id == payment_data.id)
        {
            *existing = payment_data.clone();
        } else {
            instruments.push(payment_data.clone());
        }

        payment.selected_instrument_id = Some(payment_data.id);
        Ok(())
    }

    fn expires_at(&self) -> String {
        (Utc::now() + ChronoDuration::seconds(self.session_ttl_seconds as i64)).to_rfc3339()
    }

    fn build_order(&self, checkout: &CheckoutResponse, order_id: &str) -> Result<Order, ServiceError> {
        let line_items = checkout
            .line_items
            .iter()
            .map(|line_item| OrderLineItem {
                id: line_item.id.clone(),
                item: line_item.item.clone(),
                quantity: OrderQuantity {
                    total: line_item.quantity,
                    fulfilled: 0,
                },
                totals: line_item.totals.clone(),
                status: "processing".to_string(),
                parent_id: line_item.parent_id.clone(),
                extra: line_item.extra.clone(),
            })
            .collect::<Vec<_>>();

        Ok(Order {
            ucp: self.order_meta(),
            id: order_id.to_string(),
            checkout_id: checkout.id.clone(),
            permalink_url: format!("{}/orders/{}", self.base_url, order_id),
            line_items,
            fulfillment: self.build_order_fulfillment(checkout),
            totals: checkout.totals.clone(),
            adjustments: None,
            extra: HashMap::new(),
        })
    }

    fn build_order_fulfillment(&self, checkout: &CheckoutResponse) -> OrderFulfillment {
        let Some(fulfillment) = checkout.fulfillment.as_ref() else {
            return OrderFulfillment {
                expectations: None,
                events: None,
            };
        };

        let Some(methods) = fulfillment.methods.as_ref() else {
            return OrderFulfillment {
                expectations: None,
                events: None,
            };
        };

        let mut expectations = Vec::new();
        let mut events = Vec::new();

        for method in methods {
            let destination = self.selected_destination(method);
            let Some(destination) = destination else {
                continue;
            };

            let line_items = method
                .line_item_ids
                .iter()
                .filter_map(|id| {
                    checkout
                        .line_items
                        .iter()
                        .find(|item| &item.id == id)
                        .map(|item| {
                            serde_json::json!({
                                "id": item.id,
                                "quantity": item.quantity,
                            })
                        })
                })
                .collect::<Vec<_>>();

            if line_items.is_empty() {
                continue;
            }

            let line_items_for_event = line_items.clone();

            let description = self
                .selected_option_for_method(method)
                .and_then(|option| option.description.clone().or_else(|| option.title.clone()));

            expectations.push(serde_json::json!({
                "id": format!("exp_{}", Uuid::new_v4()),
                "line_items": line_items,
                "method_type": method.method_type.clone(),
                "destination": destination,
                "description": description,
                "fulfillable_on": "now",
            }));

            events.push(serde_json::json!({
                "id": format!("fev_{}", Uuid::new_v4()),
                "occurred_at": Utc::now().to_rfc3339(),
                "type": "processing",
                "line_items": line_items_for_event,
            }));
        }

        OrderFulfillment {
            expectations: if expectations.is_empty() {
                None
            } else {
                Some(expectations)
            },
            events: if events.is_empty() { None } else { Some(events) },
        }
    }

    fn selected_destination(&self, method: &FulfillmentMethod) -> Option<serde_json::Value> {
        let destinations = method.destinations.as_ref()?;
        let selected = method
            .selected_destination_id
            .as_ref()
            .and_then(|id| destinations.iter().find(|dest| dest.id.as_ref() == Some(id)))
            .or_else(|| destinations.first())?;

        if selected.data.is_empty() {
            return None;
        }

        let mut map = serde_json::Map::new();
        for (key, value) in &selected.data {
            map.insert(key.clone(), value.clone());
        }
        Some(serde_json::Value::Object(map))
    }

    fn selected_option_for_method<'a>(
        &self,
        method: &'a FulfillmentMethod,
    ) -> Option<&'a FulfillmentOption> {
        let groups = method.groups.as_ref()?;
        let group = groups.first()?;
        let options = group.options.as_ref()?;

        if let Some(selected_id) = group.selected_option_id.as_ref() {
            if let Some(option) = options
                .iter()
                .find(|option| option.id.as_ref() == Some(selected_id))
            {
                return Some(option);
            }
        }

        options.first()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_only_ap2_verifier_checks_structure() {
        let verifier = FormatOnlyAp2MandateVerifier;

        assert!(verifier.verify("header.payload.signature").is_ok());
        assert!(verifier.verify("missingdots").is_err());
        assert!(verifier.verify("a.b").is_err());
    }
}
