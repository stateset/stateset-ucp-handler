//! MCP (Model Context Protocol) JSON-RPC 2.0 transport.
//!
//! Implements the UCP MCP transport specification for AI agent integration.
//! All checkout operations are exposed via JSON-RPC 2.0 methods.

use crate::errors::ServiceError;
use crate::models::{CheckoutCompleteRequest, CheckoutCreateRequest, CheckoutUpdateRequest};
use crate::negotiation::NegotiatedCapabilities;
use crate::service::CheckoutService;
use crate::ucp_meta::{apply_negotiated_checkout, requires_ap2_mandate};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, warn};

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
    /// Platform profile URL for negotiation
    #[serde(default)]
    pub profile: Option<String>,
}

/// MCP handler for UCP checkout operations
#[derive(Clone)]
pub struct McpHandler {
    service: CheckoutService,
}

impl McpHandler {
    pub fn new(service: CheckoutService) -> Self {
        Self { service }
    }

    /// Handles a JSON-RPC request and returns a response
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
                None,
            );
        }

        // Extract UCP metadata from params._meta.ucp if present
        let _ucp_meta = self.extract_ucp_meta(&request.params);

        // Route to appropriate handler
        match request.method.as_str() {
            "ucp/checkout/create" => self.create_checkout(request, negotiated).await,
            "ucp/checkout/get" => self.get_checkout(request, negotiated).await,
            "ucp/checkout/update" => self.update_checkout(request, negotiated).await,
            "ucp/checkout/complete" => self.complete_checkout(request, negotiated).await,
            "ucp/checkout/cancel" => self.cancel_checkout(request, negotiated).await,
            // MCP standard methods
            "initialize" => self.initialize(request).await,
            "tools/list" => self.list_tools(request).await,
            "tools/call" => self.call_tool(request, negotiated).await,
            _ => self.error_response(
                request.id,
                error_codes::METHOD_NOT_FOUND,
                &format!("Method not found: {}", request.method),
                None,
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
                None,
            );
        };

        let create_request: CheckoutCreateRequest = match serde_json::from_value(params) {
            Ok(req) => req,
            Err(e) => {
                return self.error_response(
                    request.id,
                    error_codes::INVALID_PARAMS,
                    &format!("Invalid checkout create params: {}", e),
                    None,
                );
            }
        };

        match self.service.create_checkout(create_request).await {
            Ok(mut checkout) => {
                apply_negotiated_checkout(&mut checkout, negotiated);
                self.success_response(request.id, &checkout)
            }
            Err(e) => self.service_error_response(request.id, e),
        }
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
                None,
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
                None,
            );
        };

        let checkout_id = params
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let Some(checkout_id) = checkout_id else {
            return self.error_response(
                request.id,
                error_codes::INVALID_PARAMS,
                "Missing checkout id in params",
                None,
            );
        };

        let update_request: CheckoutUpdateRequest = match serde_json::from_value(params) {
            Ok(req) => req,
            Err(e) => {
                return self.error_response(
                    request.id,
                    error_codes::INVALID_PARAMS,
                    &format!("Invalid checkout update params: {}", e),
                    None,
                );
            }
        };

        match self.service.update_checkout(&checkout_id, update_request).await {
            Ok(mut checkout) => {
                apply_negotiated_checkout(&mut checkout, negotiated);
                self.success_response(request.id, &checkout)
            }
            Err(e) => self.service_error_response(request.id, e),
        }
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
                None,
            );
        };

        let checkout_id = params
            .get("checkout_id")
            .or_else(|| params.get("id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let Some(checkout_id) = checkout_id else {
            return self.error_response(
                request.id,
                error_codes::INVALID_PARAMS,
                "Missing checkout_id in params",
                None,
            );
        };

        let complete_request: CheckoutCompleteRequest = match serde_json::from_value(params) {
            Ok(req) => req,
            Err(e) => {
                return self.error_response(
                    request.id,
                    error_codes::INVALID_PARAMS,
                    &format!("Invalid checkout complete params: {}", e),
                    None,
                );
            }
        };

        let require_ap2 = requires_ap2_mandate(negotiated, self.service.ap2_enabled());
        match self
            .service
            .complete_checkout_with_requirements(&checkout_id, complete_request, require_ap2)
            .await
        {
            Ok(mut checkout) => {
                apply_negotiated_checkout(&mut checkout, negotiated);
                self.success_response(request.id, &checkout)
            }
            Err(e) => self.service_error_response(request.id, e),
        }
    }

    async fn cancel_checkout(
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
                None,
            );
        };

        match self.service.cancel_checkout(&checkout_id).await {
            Ok(mut checkout) => {
                apply_negotiated_checkout(&mut checkout, negotiated);
                self.success_response(request.id, &checkout)
            }
            Err(e) => self.service_error_response(request.id, e),
        }
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
                    "name": "ucp_checkout_create",
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
                    "name": "ucp_checkout_get",
                    "description": "Get the current state of a checkout session",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "checkout_id": { "type": "string", "description": "The checkout session ID" }
                        },
                        "required": ["checkout_id"]
                    }
                },
                {
                    "name": "ucp_checkout_update",
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
                        "required": ["id", "line_items", "currency"]
                    }
                },
                {
                    "name": "ucp_checkout_complete",
                    "description": "Complete a checkout session and create an order",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "checkout_id": { "type": "string", "description": "The checkout session ID" },
                            "payment_data": { "type": "object", "description": "Payment instrument data" }
                        },
                        "required": ["checkout_id", "payment_data"]
                    }
                },
                {
                    "name": "ucp_checkout_cancel",
                    "description": "Cancel a checkout session",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "checkout_id": { "type": "string", "description": "The checkout session ID" }
                        },
                        "required": ["checkout_id"]
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
                None,
            );
        };

        // Create a synthetic request with the tool arguments
        let synthetic_request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: format!("ucp/checkout/{}", tool_name.trim_start_matches("ucp_checkout_")),
            params: arguments,
            id: request.id.clone(),
        };

        // Execute the method directly (not through handle to avoid recursion)
        let response = match tool_name {
            "ucp_checkout_create" => self.create_checkout(synthetic_request, negotiated).await,
            "ucp_checkout_get" => self.get_checkout(synthetic_request, negotiated).await,
            "ucp_checkout_update" => self.update_checkout(synthetic_request, negotiated).await,
            "ucp_checkout_complete" => self.complete_checkout(synthetic_request, negotiated).await,
            "ucp_checkout_cancel" => self.cancel_checkout(synthetic_request, negotiated).await,
            _ => {
                return self.error_response(
                    request.id,
                    error_codes::METHOD_NOT_FOUND,
                    &format!("Unknown tool: {}", tool_name),
                    None,
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

        self.error_response(id, code, &message, None)
    }
}

/// Creates an MCP OpenRPC schema document
pub fn openrpc_schema() -> Value {
    serde_json::json!({
        "openrpc": "1.2.6",
        "info": {
            "title": "UCP Shopping MCP API",
            "description": "MCP transport for UCP Shopping capabilities",
            "version": "1.0.0"
        },
        "methods": [
            {
                "name": "ucp/checkout/create",
                "summary": "Create a new checkout session",
                "params": [
                    {
                        "name": "line_items",
                        "required": true,
                        "schema": { "type": "array" }
                    },
                    {
                        "name": "currency",
                        "required": true,
                        "schema": { "type": "string" }
                    }
                ],
                "result": {
                    "name": "checkout",
                    "schema": { "$ref": "#/components/schemas/CheckoutResponse" }
                }
            },
            {
                "name": "ucp/checkout/get",
                "summary": "Get a checkout session by ID",
                "params": [
                    {
                        "name": "checkout_id",
                        "required": true,
                        "schema": { "type": "string" }
                    }
                ],
                "result": {
                    "name": "checkout",
                    "schema": { "$ref": "#/components/schemas/CheckoutResponse" }
                }
            },
            {
                "name": "ucp/checkout/update",
                "summary": "Update a checkout session",
                "params": [
                    {
                        "name": "id",
                        "required": true,
                        "schema": { "type": "string" }
                    }
                ],
                "result": {
                    "name": "checkout",
                    "schema": { "$ref": "#/components/schemas/CheckoutResponse" }
                }
            },
            {
                "name": "ucp/checkout/complete",
                "summary": "Complete a checkout session",
                "params": [
                    {
                        "name": "checkout_id",
                        "required": true,
                        "schema": { "type": "string" }
                    },
                    {
                        "name": "payment_data",
                        "required": true,
                        "schema": { "type": "object" }
                    }
                ],
                "result": {
                    "name": "checkout",
                    "schema": { "$ref": "#/components/schemas/CheckoutResponse" }
                }
            },
            {
                "name": "ucp/checkout/cancel",
                "summary": "Cancel a checkout session",
                "params": [
                    {
                        "name": "checkout_id",
                        "required": true,
                        "schema": { "type": "string" }
                    }
                ],
                "result": {
                    "name": "checkout",
                    "schema": { "$ref": "#/components/schemas/CheckoutResponse" }
                }
            }
        ],
        "components": {
            "schemas": {
                "CheckoutResponse": {
                    "type": "object",
                    "description": "UCP Checkout session response"
                }
            }
        }
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
        assert_eq!(schema["openrpc"], "1.2.6");
        assert!(schema["methods"].as_array().unwrap().len() > 0);
    }
}
