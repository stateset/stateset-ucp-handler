use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRef {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub name: String,
    pub version: String,
    pub spec: String,
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UcpResponseMeta {
    pub version: String,
    pub capabilities: Vec<CapabilityRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDefinition {
    pub version: String,
    pub spec: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rest: Option<ServiceEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp: Option<ServiceEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a2a: Option<A2AEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedded: Option<EmbeddedEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub schema: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedEndpoint {
    pub schema: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2AEndpoint {
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UcpDiscoveryProfile {
    pub version: String,
    pub services: HashMap<String, ServiceDefinition>,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryPayment {
    pub handlers: Vec<PaymentHandler>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryDocument {
    pub ucp: UcpDiscoveryProfile,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment: Option<DiscoveryPayment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_keys: Option<Vec<JwkKey>>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkKey {
    pub kid: String,
    pub kty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckoutStatus {
    Incomplete,
    RequiresEscalation,
    ReadyForComplete,
    CompleteInProgress,
    Completed,
    Canceled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Buyer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consent: Option<BuyerConsent>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuyerConsent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analytics: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferences: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marketing: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sale_of_data: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemRef {
    pub id: String,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineItemInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub item: ItemRef,
    pub quantity: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutCreateRequest {
    pub line_items: Vec<LineItemInput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buyer: Option<Buyer>,
    pub currency: String,
    pub payment: PaymentRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discounts: Option<DiscountsObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfillment: Option<Fulfillment>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutUpdateRequest {
    pub id: String,
    pub line_items: Vec<LineItemInput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buyer: Option<Buyer>,
    pub currency: String,
    pub payment: PaymentRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discounts: Option<DiscountsObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfillment: Option<Fulfillment>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ap2CompleteRequest {
    pub checkout_mandate: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutCompleteRequest {
    pub payment_data: PaymentInstrument,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ap2: Option<Ap2CompleteRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_signals: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ap2CheckoutResponse {
    pub merchant_authorization: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemResponse {
    pub id: String,
    pub title: String,
    pub price: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineItemResponse {
    pub id: String,
    pub item: ItemResponse,
    pub quantity: i32,
    pub totals: Vec<Total>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Total {
    #[serde(rename = "type")]
    pub total_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_text: Option<String>,
    pub amount: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Link {
    #[serde(rename = "type")]
    pub link_type: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    #[serde(rename = "type")]
    pub message_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_instrument_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruments: Option<Vec<PaymentInstrument>>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentResponse {
    pub handlers: Vec<PaymentHandler>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_instrument_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruments: Option<Vec<PaymentInstrument>>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentHandler {
    pub id: String,
    pub name: String,
    pub version: String,
    pub spec: String,
    pub config_schema: String,
    pub instrument_schemas: Vec<String>,
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostalAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_locality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentInstrument {
    pub id: String,
    pub handler_id: String,
    #[serde(rename = "type")]
    pub instrument_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brand: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_digits: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry_month: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry_year: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rich_text_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rich_card_art: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_address: Option<PostalAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderConfirmation {
    pub id: String,
    pub permalink_url: String,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub ucp: UcpResponseMeta,
    pub id: String,
    pub checkout_id: String,
    pub permalink_url: String,
    pub line_items: Vec<OrderLineItem>,
    pub fulfillment: OrderFulfillment,
    pub totals: Vec<Total>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adjustments: Option<Vec<serde_json::Value>>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderLineItem {
    pub id: String,
    pub item: ItemResponse,
    pub quantity: OrderQuantity,
    pub totals: Vec<Total>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderQuantity {
    pub total: i32,
    pub fulfilled: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderFulfillment {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expectations: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderEvent {
    #[serde(flatten)]
    pub order: Order,
    pub event_id: String,
    pub created_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutResponse {
    pub ucp: UcpResponseMeta,
    pub id: String,
    pub line_items: Vec<LineItemResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buyer: Option<Buyer>,
    pub status: CheckoutStatus,
    pub currency: String,
    pub totals: Vec<Total>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discounts: Option<DiscountsObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfillment: Option<Fulfillment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages: Option<Vec<Message>>,
    pub links: Vec<Link>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continue_url: Option<String>,
    pub payment: PaymentResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ap2: Option<Ap2CheckoutResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<OrderConfirmation>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscountsObject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied: Option<Vec<AppliedDiscount>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedDiscount {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub title: String,
    pub amount: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub automatic: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allocations: Option<Vec<DiscountAllocation>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscountAllocation {
    pub path: String,
    pub amount: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fulfillment {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<FulfillmentMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_methods: Option<Vec<FulfillmentAvailableMethod>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FulfillmentMethod {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub method_type: String,
    #[serde(default)]
    pub line_item_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destinations: Option<Vec<FulfillmentDestination>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_destination_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<FulfillmentGroup>>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FulfillmentGroup {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default)]
    pub line_item_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<FulfillmentOption>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_option_id: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FulfillmentOption {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub carrier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub earliest_fulfillment_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_fulfillment_time: Option<String>,
    #[serde(default)]
    pub totals: Vec<Total>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FulfillmentDestination {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(flatten)]
    pub data: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FulfillmentAvailableMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub line_item_ids: Vec<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentIdentity {
    pub access_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Binding {
    pub checkout_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<PaymentIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenizeRequest {
    pub credential: serde_json::Value,
    pub binding: Binding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetokenizeRequest {
    pub token: String,
    pub binding: Binding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenizeResponse {
    pub token: String,
}
