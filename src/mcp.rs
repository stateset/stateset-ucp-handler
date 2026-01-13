//! MCP (Model Context Protocol) JSON-RPC 2.0 transport.
//!
//! Implements the UCP MCP transport specification for AI agent integration.
//! All checkout operations are exposed via JSON-RPC 2.0 methods.

use crate::crypto::canonicalize;
use crate::errors::ServiceError;
use crate::models::{CheckoutCompleteRequest, CheckoutCreateRequest, CheckoutUpdateRequest, PaymentInstrument};
use crate::negotiation::NegotiatedCapabilities;
use crate::service::CheckoutService;
use crate::ucp_meta::{apply_negotiated_checkout, requires_ap2_mandate};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// JSON-RPC 2.0 request structure
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    /// JSON-RPC version (must be "2.0")
    pub jsonrpc: String,
    /// Method name to invoke
    pub method: String,
    /// Method parameters
    #[serde(default)]
    pub params: Option<Value>,
    /// Request ID (can be string, number, or null)
    pub id: Value,
}

/// JSON-RPC 2.0 response structure
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    /// JSON-RPC version (always "2.0")
    pub jsonrpc: String,
    /// Result on success
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error on failure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    /// Request ID (echoed from request)
    pub id: Value,
}

/// JSON-RPC 2.0 error object
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    /// Error code
    pub code: i32,
    /// Error message
    pub message: String,
    /// Additional error data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Standard JSON-RPC error codes
#[allow(dead_code)]
pub mod error_codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
    // Application-specific errors (-32000 to -32099)
    pub const NOT_FOUND: i32 = -32000;
    pub const INVALID_STATE: i32 = -32001;
    pub const VALIDATION_ERROR: i32 = -32002;
}

/// UCP metadata extracted from MCP request
#[derive(Debug, Clone, Deserialize, Default)]
pub struct UcpMeta {
    /// Platform profile URL for negotiation (deserialized from JSON)
    #[serde(default)]
    #[allow(dead_code)]
    pub profile: Option<String>,
}

pub fn extract_profile_url(params: &Option<Value>) -> Option<String> {
    params
        .as_ref()
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get("ucp"))
        .and_then(|u| u.get("profile"))
        .and_then(|v| v.as_str())
        .map(|value| value.to_string())
}

/// MCP handler for UCP checkout operations
#[derive(Clone)]
pub struct McpHandler {
    service: CheckoutService,
    idempotency: Arc<RwLock<HashMap<String, McpIdempotencyRecord>>>,
    idempotency_ttl: Duration,
}

#[derive(Clone)]
struct McpIdempotencyRecord {
    request_hash: String,
    response: JsonRpcResponse,
    created_at: Instant,
}

impl McpHandler {
    pub fn new(service: CheckoutService) -> Self {
        Self {
            service,
            idempotency: Arc::new(RwLock::new(HashMap::new())),
            idempotency_ttl: Duration::from_secs(600),
        }
    }

    /// Handles a JSON-RPC request and returns a response
    #[allow(dead_code)]
    pub async fn handle(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        self.handle_with_context(request, None).await
    }

    pub async fn handle_with_context(
        &self,
        request: JsonRpcRequest,
        negotiated: Option<&NegotiatedCapabilities>,
    ) -> JsonRpcResponse {
        // Validate JSON-RPC version
        if request.jsonrpc != "2.0" {
            return self.error_response(
                request.id,
                error_codes::INVALID_REQUEST,
                "Invalid JSON-RPC version",
                Some(self.ucp_error_data(
                    "invalid_request",
                    "Invalid JSON-RPC version",
                    "recoverable",
                )),
            );
        }

        // Extract UCP metadata from params._meta.ucp if present
        let _ucp_meta = self.extract_ucp_meta(&request.params);

        // Route to appropriate handler
        match request.method.as_str() {
            "create_checkout" | "ucp/checkout/create" => {
                self.create_checkout(request, negotiated).await
            }
            "get_checkout" | "ucp/checkout/get" => self.get_checkout(request, negotiated).await,
            "update_checkout" | "ucp/checkout/update" => {
                self.update_checkout(request, negotiated).await
            }
            "complete_checkout" | "ucp/checkout/complete" => {
                self.complete_checkout(request, negotiated).await
            }
            "cancel_checkout" | "ucp/checkout/cancel" => {
                self.cancel_checkout(request, negotiated).await
            }
            // MCP standard methods
            "initialize" => self.initialize(request).await,
            "tools/list" => self.list_tools(request).await,
            "tools/call" => self.call_tool(request, negotiated).await,
            _ => self.error_response(
                request.id,
                error_codes::METHOD_NOT_FOUND,
                &format!("Method not found: {}", request.method),
                Some(self.ucp_error_data(
                    "method_not_found",
                    &format!("Method not found: {}", request.method),
                    "recoverable",
                )),
            ),
        }
    }

    /// Extracts UCP metadata from request params
    fn extract_ucp_meta(&self, params: &Option<Value>) -> UcpMeta {
        params
            .as_ref()
            .and_then(|p| p.get("_meta"))
            .and_then(|m| m.get("ucp"))
            .and_then(|u| serde_json::from_value(u.clone()).ok())
            .unwrap_or_default()
    }

    /// Strips _meta from params for passing to service methods
    fn strip_meta(&self, params: Option<Value>) -> Option<Value> {
        params.map(|mut p| {
            if let Some(obj) = p.as_object_mut() {
                obj.remove("_meta");
            }
            p
        })
    }

    fn extract_idempotency_key(
        &self,
        params: &mut serde_json::Map<String, Value>,
    ) -> Option<String> {
        params
            .remove("idempotency_key")
            .and_then(|value| value.as_str().map(|value| value.to_string()))
    }

    fn request_hash(&self, method: &str, params: &Value) -> String {
        let canonical = canonicalize(params).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(method.as_bytes());
        hasher.update(b"\n");
        hasher.update(&canonical);
        hex::encode(hasher.finalize())
    }

    async fn idempotency_replay(
        &self,
        idempotency_key: &str,
        request_hash: &str,
        id: &Value,
    ) -> Option<JsonRpcResponse> {
        let mut store = self.idempotency.write().await;
        if let Some(record) = store.get(idempotency_key) {
            if record.created_at.elapsed() > self.idempotency_ttl {
                store.remove(idempotency_key);
                return None;
            }

            if record.request_hash != request_hash {
                return Some(self.error_response(
                    id.clone(),
                    error_codes::INVALID_PARAMS,
                    "Idempotency key reused with different request payload",
                    Some(self.ucp_error_data(
                        "idempotency_conflict",
                        "Idempotency key reused with different request payload",
                        "recoverable",
                    )),
                ));
            }

            return Some(record.response.clone());
        }
        None
    }

    async fn store_idempotency(
        &self,
        idempotency_key: String,
        request_hash: String,
        response: JsonRpcResponse,
    ) {
        let mut store = self.idempotency.write().await;
        store.insert(
            idempotency_key,
            McpIdempotencyRecord {
                request_hash,
                response,
                created_at: Instant::now(),
            },
        );
    }

    async fn create_checkout(
        &self,
        request: JsonRpcRequest,
        negotiated: Option<&NegotiatedCapabilities>,
    ) -> JsonRpcResponse {
        let params = self.strip_meta(request.params);
        let Some(params) = params else {
            return self.error_response(
                request.id,
                error_codes::INVALID_PARAMS,
                "Missing params for checkout creation",
                Some(self.ucp_error_data(
                    "missing_params",
                    "Missing params for checkout creation",
                    "recoverable",
                )),
            );
        };

        let mut params_map = match params.as_object() {
            Some(obj) => obj.clone(),
            None => {
                return self.error_response(
                    request.id,
                    error_codes::INVALID_PARAMS,
                    "Checkout params must be an object",
                    Some(self.ucp_error_data(
                        "invalid_params",
                        "Checkout params must be an object",
                        "recoverable",
                    )),
                );
            }
        };

        let idempotency_key = self.extract_idempotency_key(&mut params_map);
        let hash_params = Value::Object(params_map.clone());
        let request_hash = idempotency_key
            .as_ref()
            .map(|_| self.request_hash(request.method.as_str(), &hash_params));

        if let (Some(key), Some(hash)) = (&idempotency_key, &request_hash) {
            if let Some(response) = self.idempotency_replay(key, hash, &request.id).await {
                return response;
            }
        }

        let checkout_payload = params_map
            .remove("checkout")
            .unwrap_or_else(|| Value::Object(params_map));

        let create_request: CheckoutCreateRequest = match serde_json::from_value(checkout_payload) {
            Ok(req) => req,
            Err(e) => {
                return self.error_response(
                    request.id,
                    error_codes::INVALID_PARAMS,
                    &format!("Invalid checkout create params: {}", e),
                    Some(self.ucp_error_data(
                        "invalid_params",
                        &format!("Invalid checkout create params: {}", e),
                        "recoverable",
                    )),
                );
            }
        };

        let response = match self.service.create_checkout(create_request).await {
            Ok(mut checkout) => {
                apply_negotiated_checkout(&mut checkout, negotiated);
                self.success_response(request.id, &checkout)
            }
            Err(e) => self.service_error_response(request.id, e),
        };

        if let (Some(key), Some(hash)) = (idempotency_key, request_hash) {
            self.store_idempotency(key, hash, response.clone()).await;
        }

        response
    }

    async fn get_checkout(
        &self,
        request: JsonRpcRequest,
        negotiated: Option<&NegotiatedCapabilities>,
    ) -> JsonRpcResponse {
        let checkout_id = self.extract_checkout_id(&request.params);
        let Some(checkout_id) = checkout_id else {
            return self.error_response(
                request.id,
                error_codes::INVALID_PARAMS,
                "Missing checkout_id parameter",
                Some(self.ucp_error_data(
                    "missing_checkout_id",
                    "Missing checkout_id parameter",
                    "recoverable",
                )),
            );
        };

        match self.service.get_checkout(&checkout_id).await {
            Ok(mut checkout) => {
                apply_negotiated_checkout(&mut checkout, negotiated);
                self.success_response(request.id, &checkout)
            }
            Err(e) => self.service_error_response(request.id, e),
        }
    }

    async fn update_checkout(
        &self,
        request: JsonRpcRequest,
        negotiated: Option<&NegotiatedCapabilities>,
    ) -> JsonRpcResponse {
        let params = self.strip_meta(request.params);
        let Some(params) = params else {
            return self.error_response(
                request.id,
                error_codes::INVALID_PARAMS,
                "Missing params for checkout update",
                Some(self.ucp_error_data(
                    "missing_params",
                    "Missing params for checkout update",
                    "recoverable",
                )),
            );
        };

        let mut params_map = match params.as_object() {
            Some(obj) => obj.clone(),
            None => {
                return self.error_response(
                    request.id,
                    error_codes::INVALID_PARAMS,
                    "Checkout params must be an object",
                    Some(self.ucp_error_data(
                        "invalid_params",
                        "Checkout params must be an object",
                        "recoverable",
                    )),
                );
            }
        };

        let idempotency_key = self.extract_idempotency_key(&mut params_map);
        let hash_params = Value::Object(params_map.clone());
        let request_hash = idempotency_key
            .as_ref()
            .map(|_| self.request_hash(request.method.as_str(), &hash_params));

        if let (Some(key), Some(hash)) = (&idempotency_key, &request_hash) {
            if let Some(response) = self.idempotency_replay(key, hash, &request.id).await {
                return response;
            }
        }

        let checkout_id = params_map
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let Some(checkout_id) = checkout_id else {
            return self.error_response(
                request.id,
                error_codes::INVALID_PARAMS,
                "Missing checkout id in params",
                Some(self.ucp_error_data(
                    "missing_checkout_id",
                    "Missing checkout id in params",
                    "recoverable",
                )),
            );
        };

        let mut checkout_payload = params_map
            .remove("checkout")
            .unwrap_or_else(|| Value::Object(params_map));

        if let Some(obj) = checkout_payload.as_object_mut() {
            obj.entry("id".to_string())
                .or_insert_with(|| Value::String(checkout_id.clone()));
        }

        let update_request: CheckoutUpdateRequest = match serde_json::from_value(checkout_payload) {
            Ok(req) => req,
            Err(e) => {
                return self.error_response(
                    request.id,
                    error_codes::INVALID_PARAMS,
                    &format!("Invalid checkout update params: {}", e),
                    Some(self.ucp_error_data(
                        "invalid_params",
                        &format!("Invalid checkout update params: {}", e),
                        "recoverable",
                    )),
                );
            }
        };

        let response = match self.service.update_checkout(&checkout_id, update_request).await {
            Ok(mut checkout) => {
                apply_negotiated_checkout(&mut checkout, negotiated);
                self.success_response(request.id, &checkout)
            }
            Err(e) => self.service_error_response(request.id, e),
        };

        if let (Some(key), Some(hash)) = (idempotency_key, request_hash) {
            self.store_idempotency(key, hash, response.clone()).await;
        }

        response
    }

    async fn complete_checkout(
        &self,
        request: JsonRpcRequest,
        negotiated: Option<&NegotiatedCapabilities>,
    ) -> JsonRpcResponse {
        let params = self.strip_meta(request.params);
        let Some(params) = params else {
            return self.error_response(
                request.id,
                error_codes::INVALID_PARAMS,
                "Missing params for checkout completion",
                Some(self.ucp_error_data(
                    "missing_params",
                    "Missing params for checkout completion",
                    "recoverable",
                )),
            );
        };

        let mut params_map = match params.as_object() {
            Some(obj) => obj.clone(),
            None => {
                return self.error_response(
                    request.id,
                    error_codes::INVALID_PARAMS,
                    "Checkout params must be an object",
                    Some(self.ucp_error_data(
                        "invalid_params",
                        "Checkout params must be an object",
                        "recoverable",
                    )),
                );
            }
        };

        let idempotency_key = self.extract_idempotency_key(&mut params_map);
        let Some(idempotency_key) = idempotency_key else {
            return self.error_response(
                request.id,
                error_codes::INVALID_PARAMS,
                "Missing idempotency_key in params",
                Some(self.ucp_error_data(
                    "missing_idempotency_key",
                    "Missing idempotency_key in params",
                    "recoverable",
                )),
            );
        };

        let hash_params = Value::Object(params_map.clone());
        let request_hash = self.request_hash(request.method.as_str(), &hash_params);

        if let Some(response) = self
            .idempotency_replay(&idempotency_key, &request_hash, &request.id)
            .await
        {
            return response;
        }

        let checkout_id = params_map
            .get("checkout_id")
            .or_else(|| params_map.get("id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let Some(checkout_id) = checkout_id else {
            return self.error_response(
                request.id,
                error_codes::INVALID_PARAMS,
                "Missing checkout_id in params",
                Some(self.ucp_error_data(
                    "missing_checkout_id",
                    "Missing checkout_id in params",
                    "recoverable",
                )),
            );
        };

        let payment_value = params_map
            .remove("payment_data")
            .or_else(|| params_map.remove("payment"));
        let Some(payment_value) = payment_value else {
            return self.error_response(
                request.id,
                error_codes::INVALID_PARAMS,
                "Missing payment data in params",
                Some(self.ucp_error_data(
                    "missing_payment_data",
                    "Missing payment data in params",
                    "recoverable",
                )),
            );
        };

        let payment_data: PaymentInstrument = match serde_json::from_value(payment_value) {
            Ok(value) => value,
            Err(err) => {
                return self.error_response(
                    request.id,
                    error_codes::INVALID_PARAMS,
                    &format!("Invalid payment data: {}", err),
                    Some(self.ucp_error_data(
                        "invalid_payment_data",
                        &format!("Invalid payment data: {}", err),
                        "recoverable",
                    )),
                );
            }
        };

        let mut complete_payload = serde_json::Map::new();
        complete_payload.insert(
            "payment_data".to_string(),
            serde_json::to_value(payment_data).unwrap_or(Value::Null),
        );
        if let Some(risk_signals) = params_map.remove("risk_signals") {
            complete_payload.insert("risk_signals".to_string(), risk_signals);
        }
        if let Some(ap2) = params_map.remove("ap2") {
            complete_payload.insert("ap2".to_string(), ap2);
        } else if let Some(mandate) = params_map.remove("ap2.checkout_mandate") {
            complete_payload.insert(
                "ap2".to_string(),
                serde_json::json!({ "checkout_mandate": mandate }),
            );
        }

        let complete_request: CheckoutCompleteRequest =
            match serde_json::from_value(Value::Object(complete_payload)) {
                Ok(req) => req,
                Err(e) => {
                    return self.error_response(
                        request.id,
                        error_codes::INVALID_PARAMS,
                        &format!("Invalid checkout complete params: {}", e),
                        Some(self.ucp_error_data(
                            "invalid_params",
                            &format!("Invalid checkout complete params: {}", e),
                            "recoverable",
                        )),
                    );
                }
            };

        let require_ap2 = requires_ap2_mandate(negotiated, self.service.ap2_enabled());
        let response = match self
            .service
            .complete_checkout_with_requirements(&checkout_id, complete_request, require_ap2)
            .await
        {
            Ok(mut checkout) => {
                apply_negotiated_checkout(&mut checkout, negotiated);
                self.success_response(request.id, &checkout)
            }
            Err(e) => self.service_error_response(request.id, e),
        };

        self.store_idempotency(idempotency_key, request_hash, response.clone())
            .await;

        response
    }

    async fn cancel_checkout(
        &self,
        request: JsonRpcRequest,
        negotiated: Option<&NegotiatedCapabilities>,
    ) -> JsonRpcResponse {
        let params = self.strip_meta(request.params);
        let Some(params) = params else {
            return self.error_response(
                request.id,
                error_codes::INVALID_PARAMS,
                "Missing params for checkout cancellation",
                Some(self.ucp_error_data(
                    "missing_params",
                    "Missing params for checkout cancellation",
                    "recoverable",
                )),
            );
        };

        let mut params_map = match params.as_object() {
            Some(obj) => obj.clone(),
            None => {
                return self.error_response(
                    request.id,
                    error_codes::INVALID_PARAMS,
                    "Checkout params must be an object",
                    Some(self.ucp_error_data(
                        "invalid_params",
                        "Checkout params must be an object",
                        "recoverable",
                    )),
                );
            }
        };

        let idempotency_key = self.extract_idempotency_key(&mut params_map);
        let Some(idempotency_key) = idempotency_key else {
            return self.error_response(
                request.id,
                error_codes::INVALID_PARAMS,
                "Missing idempotency_key in params",
                Some(self.ucp_error_data(
                    "missing_idempotency_key",
                    "Missing idempotency_key in params",
                    "recoverable",
                )),
            );
        };

        let hash_params = Value::Object(params_map.clone());
        let request_hash = self.request_hash(request.method.as_str(), &hash_params);

        if let Some(response) = self
            .idempotency_replay(&idempotency_key, &request_hash, &request.id)
            .await
        {
            return response;
        }

        let checkout_id = params_map
            .get("checkout_id")
            .or_else(|| params_map.get("id"))
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());
        let Some(checkout_id) = checkout_id else {
            return self.error_response(
                request.id,
                error_codes::INVALID_PARAMS,
                "Missing checkout_id parameter",
                Some(self.ucp_error_data(
                    "missing_checkout_id",
                    "Missing checkout_id parameter",
                    "recoverable",
                )),
            );
        };

        let response = match self.service.cancel_checkout(&checkout_id).await {
            Ok(mut checkout) => {
                apply_negotiated_checkout(&mut checkout, negotiated);
                self.success_response(request.id, &checkout)
            }
            Err(e) => self.service_error_response(request.id, e),
        };

        self.store_idempotency(idempotency_key, request_hash, response.clone())
            .await;

        response
    }

    /// MCP initialize method - returns server capabilities
    async fn initialize(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let result = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "ucp-checkout-server",
                "version": "1.0.0"
            }
        });

        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id: request.id,
        }
    }

    /// MCP tools/list method - returns available tools
    async fn list_tools(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let tools = serde_json::json!({
            "tools": [
                {
                    "name": "create_checkout",
                    "description": "Create a new checkout session for purchasing items",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "line_items": {
                                "type": "array",
                                "description": "Items to purchase",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "item": {
                                            "type": "object",
                                            "properties": {
                                                "id": { "type": "string" }
                                            },
                                            "required": ["id"]
                                        },
                                        "quantity": { "type": "integer", "minimum": 1 }
                                    },
                                    "required": ["item", "quantity"]
                                }
                            },
                            "currency": { "type": "string", "default": "USD" }
                        },
                        "required": ["line_items", "currency"]
                    }
                },
                {
                    "name": "get_checkout",
                    "description": "Get the current state of a checkout session",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "id": { "type": "string", "description": "The checkout session ID" }
                        },
                        "required": ["id"]
                    }
                },
                {
                    "name": "update_checkout",
                    "description": "Update a checkout session with buyer info, fulfillment, or payment details",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "id": { "type": "string", "description": "The checkout session ID" },
                            "line_items": { "type": "array" },
                            "currency": { "type": "string" },
                            "buyer": { "type": "object" },
                            "fulfillment": { "type": "object" },
                            "payment": { "type": "object" }
                        },
                        "required": ["id"]
                    }
                },
                {
                    "name": "complete_checkout",
                    "description": "Complete a checkout session and create an order",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "id": { "type": "string", "description": "The checkout session ID" },
                            "payment": { "type": "object", "description": "Payment instrument data" },
                            "idempotency_key": { "type": "string", "format": "uuid" }
                        },
                        "required": ["id", "idempotency_key"]
                    }
                },
                {
                    "name": "cancel_checkout",
                    "description": "Cancel a checkout session",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "id": { "type": "string", "description": "The checkout session ID" },
                            "idempotency_key": { "type": "string", "format": "uuid" }
                        },
                        "required": ["id", "idempotency_key"]
                    }
                }
            ]
        });

        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(tools),
            error: None,
            id: request.id,
        }
    }

    /// MCP tools/call method - execute a tool
    async fn call_tool(
        &self,
        request: JsonRpcRequest,
        negotiated: Option<&NegotiatedCapabilities>,
    ) -> JsonRpcResponse {
        let params = request.params.as_ref();
        let tool_name = params
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str());
        let arguments = params
            .and_then(|p| p.get("arguments"))
            .cloned();

        let Some(tool_name) = tool_name else {
            return self.error_response(
                request.id,
                error_codes::INVALID_PARAMS,
                "Missing tool name",
                Some(self.ucp_error_data(
                    "missing_tool_name",
                    "Missing tool name",
                    "recoverable",
                )),
            );
        };

        // Create a synthetic request with the tool arguments
        let synthetic_request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: tool_name.to_string(),
            params: arguments,
            id: request.id.clone(),
        };

        // Execute the method directly (not through handle to avoid recursion)
        let response = match tool_name {
            "create_checkout" => self.create_checkout(synthetic_request, negotiated).await,
            "get_checkout" => self.get_checkout(synthetic_request, negotiated).await,
            "update_checkout" => self.update_checkout(synthetic_request, negotiated).await,
            "complete_checkout" => self.complete_checkout(synthetic_request, negotiated).await,
            "cancel_checkout" => self.cancel_checkout(synthetic_request, negotiated).await,
            _ => {
                return self.error_response(
                    request.id,
                    error_codes::METHOD_NOT_FOUND,
                    &format!("Unknown tool: {}", tool_name),
                    Some(self.ucp_error_data(
                        "unknown_tool",
                        &format!("Unknown tool: {}", tool_name),
                        "recoverable",
                    )),
                );
            }
        };

        // Wrap result in MCP tool response format
        if let Some(result) = response.result {
            let tool_result = serde_json::json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string_pretty(&result).unwrap_or_default()
                }]
            });
            JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(tool_result),
                error: None,
                id: request.id,
            }
        } else {
            response
        }
    }

    fn extract_checkout_id(&self, params: &Option<Value>) -> Option<String> {
        params
            .as_ref()
            .and_then(|p| {
                p.get("checkout_id")
                    .or_else(|| p.get("id"))
                    .and_then(|v| v.as_str())
            })
            .map(|s| s.to_string())
    }

    fn success_response<T: Serialize>(&self, id: Value, result: &T) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: serde_json::to_value(result).ok(),
            error: None,
            id,
        }
    }

    fn error_response(
        &self,
        id: Value,
        code: i32,
        message: &str,
        data: Option<Value>,
    ) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_string(),
                data,
            }),
            id,
        }
    }

    fn service_error_response(&self, id: Value, error: ServiceError) -> JsonRpcResponse {
        let (code, message) = match &error {
            ServiceError::NotFound(msg) => (error_codes::NOT_FOUND, msg.clone()),
            ServiceError::InvalidInput(msg) => (error_codes::VALIDATION_ERROR, msg.clone()),
            ServiceError::InvalidState(msg) => (error_codes::INVALID_STATE, msg.clone()),
            ServiceError::Conflict(msg) => (error_codes::INVALID_STATE, msg.clone()),
            ServiceError::External(msg) => (error_codes::INTERNAL_ERROR, msg.clone()),
            ServiceError::Internal(msg) => (error_codes::INTERNAL_ERROR, msg.clone()),
        };

        let ucp_code = match &error {
            ServiceError::NotFound(_) => "not_found",
            ServiceError::InvalidInput(_) => "invalid_input",
            ServiceError::InvalidState(_) => "invalid_state",
            ServiceError::Conflict(_) => "conflict",
            ServiceError::External(_) => "external_error",
            ServiceError::Internal(_) => "internal_error",
        };

        self.error_response(
            id,
            code,
            &message,
            Some(self.ucp_error_data(ucp_code, &message, "recoverable")),
        )
    }

    fn ucp_error_data(&self, code: &str, message: &str, severity: &str) -> Value {
        serde_json::json!({
            "status": "error",
            "errors": [
                {
                    "code": code,
                    "message": message,
                    "severity": severity
                }
            ]
        })
    }
}

/// Creates an MCP OpenRPC schema document
pub fn openrpc_schema() -> Value {
    serde_json::json!({
        "openrpc": "1.3.2",
        "info": {
            "title": "UCP Shopping Service",
            "version": "2026-01-11",
            "description": "Canonical MCP/JSON-RPC interface for UCP Shopping service. Schema references are logical pointers - actual payload shape is determined by negotiated capabilities.\n\n**Endpoint Resolution:** This spec defines methods only. The endpoint URL MUST be obtained from the merchant's discovery profile at `/.well-known/ucp` under `services[\"dev.ucp.shopping\"].mcp.endpoint`. The server entry below is a placeholder for tooling compatibility."
        },
        "servers": [
            {
                "name": "merchant",
                "url": "{endpoint}",
                "description": "Merchant-provided endpoint from UCP discovery profile",
                "variables": {
                    "endpoint": {
                        "default": "https://merchant.example.com/ucp/mcp",
                        "description": "Obtain from /.well-known/ucp → services[\"dev.ucp.shopping\"].mcp.endpoint"
                    }
                }
            }
        ],
        "methods": [
            {
                "name": "create_checkout",
                "summary": "Create a checkout",
                "params": [
                    {
                        "name": "checkout",
                        "required": true,
                        "schema": { "$ref": "https://ucp.dev/schemas/shopping/checkout.json" }
                    }
                ],
                "result": {
                    "name": "checkout",
                    "schema": { "$ref": "https://ucp.dev/schemas/shopping/checkout.json" }
                }
            },
            {
                "name": "get_checkout",
                "summary": "Get checkout",
                "params": [
                    {
                        "name": "id",
                        "required": true,
                        "schema": { "type": "string" }
                    }
                ],
                "result": {
                    "name": "checkout",
                    "schema": { "$ref": "https://ucp.dev/schemas/shopping/checkout.json" }
                }
            },
            {
                "name": "update_checkout",
                "summary": "Update checkout",
                "params": [
                    {
                        "name": "id",
                        "required": true,
                        "schema": { "type": "string" }
                    },
                    {
                        "name": "checkout",
                        "required": true,
                        "schema": { "$ref": "https://ucp.dev/schemas/shopping/checkout.json" }
                    }
                ],
                "result": {
                    "name": "checkout",
                    "schema": { "$ref": "https://ucp.dev/schemas/shopping/checkout.json" }
                }
            },
            {
                "name": "complete_checkout",
                "summary": "Complete checkout and place order",
                "params": [
                    {
                        "name": "id",
                        "required": true,
                        "schema": { "type": "string" }
                    },
                    {
                        "name": "payment",
                        "required": false,
                        "schema": { "$ref": "https://ucp.dev/schemas/shopping/payment.json" }
                    },
                    {
                        "name": "idempotency_key",
                        "required": true,
                        "schema": { "type": "string", "format": "uuid" }
                    }
                ],
                "result": {
                    "name": "checkout",
                    "schema": { "$ref": "https://ucp.dev/schemas/shopping/checkout.json" }
                }
            },
            {
                "name": "cancel_checkout",
                "summary": "Cancel checkout",
                "params": [
                    {
                        "name": "id",
                        "required": true,
                        "schema": { "type": "string" }
                    },
                    {
                        "name": "idempotency_key",
                        "required": true,
                        "schema": { "type": "string", "format": "uuid" }
                    }
                ],
                "result": {
                    "name": "checkout",
                    "schema": { "$ref": "https://ucp.dev/schemas/shopping/checkout.json" }
                }
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_rpc_request_parsing() {
        let json = r#"{
            "jsonrpc": "2.0",
            "method": "ucp/checkout/get",
            "params": { "checkout_id": "chk_123" },
            "id": 1
        }"#;

        let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.jsonrpc, "2.0");
        assert_eq!(request.method, "ucp/checkout/get");
        assert_eq!(request.id, serde_json::json!(1));
    }

    #[test]
    fn test_json_rpc_response_serialization() {
        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(serde_json::json!({"status": "ok"})),
            error: None,
            id: serde_json::json!(1),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"result\""));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn test_error_response_serialization() {
        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code: error_codes::METHOD_NOT_FOUND,
                message: "Method not found".to_string(),
                data: None,
            }),
            id: serde_json::json!("req-1"),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"error\""));
        assert!(json.contains("-32601"));
    }

    #[test]
    fn test_openrpc_schema() {
        let schema = openrpc_schema();
        assert_eq!(schema["openrpc"], "1.3.2");
        assert!(schema["methods"].as_array().unwrap().len() > 0);
    }
}
