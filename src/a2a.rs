//! A2A (Agent-to-Agent) transport implementation.
//!
//! Implements the Google A2A protocol for agent-to-agent communication,
//! supporting agent cards, task management, and message handling.

use crate::errors::ServiceError;
use crate::models::{CheckoutCompleteRequest, CheckoutCreateRequest, CheckoutUpdateRequest};
use crate::negotiation::NegotiatedCapabilities;
use crate::service::CheckoutService;
use crate::ucp_meta::{apply_negotiated_checkout, requires_ap2_mandate};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, info};
use uuid::Uuid;

/// Agent Card - describes agent capabilities per A2A spec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCard {
    /// Agent name
    pub name: String,
    /// Agent description
    pub description: Option<String>,
    /// Agent URL (A2A endpoint)
    pub url: String,
    /// Protocol version
    pub version: String,
    /// Agent capabilities
    pub capabilities: AgentCapabilities,
    /// Authentication requirements
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<AgentAuthentication>,
    /// Default input modes
    #[serde(rename = "defaultInputModes", skip_serializing_if = "Option::is_none")]
    pub default_input_modes: Option<Vec<String>>,
    /// Default output modes
    #[serde(rename = "defaultOutputModes", skip_serializing_if = "Option::is_none")]
    pub default_output_modes: Option<Vec<String>>,
    /// Skills the agent supports
    pub skills: Vec<AgentSkill>,
}

/// Agent capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCapabilities {
    /// Whether streaming is supported
    #[serde(default)]
    pub streaming: bool,
    /// Whether push notifications are supported
    #[serde(rename = "pushNotifications", default)]
    pub push_notifications: bool,
    /// Whether state/context is persisted
    #[serde(rename = "stateTransitionHistory", default)]
    pub state_transition_history: bool,
}

/// Agent authentication requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAuthentication {
    /// Authentication schemes supported
    pub schemes: Vec<String>,
}

/// Agent skill definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSkill {
    /// Skill ID
    pub id: String,
    /// Skill name
    pub name: String,
    /// Skill description
    pub description: String,
    /// Input schema (JSON Schema)
    #[serde(rename = "inputSchema", skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
    /// Output schema (JSON Schema)
    #[serde(rename = "outputSchema", skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    /// Example inputs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub examples: Option<Vec<SkillExample>>,
}

/// Example for a skill
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillExample {
    /// Example name
    pub name: String,
    /// Example input
    pub input: Value,
    /// Example output
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,
}

/// A2A message structure
#[derive(Debug, Clone, Deserialize)]
pub struct A2AMessage {
    /// JSON-RPC version
    pub jsonrpc: String,
    /// Method name
    pub method: String,
    /// Request ID
    pub id: Value,
    /// Method parameters
    #[serde(default)]
    pub params: Option<A2AParams>,
}

/// A2A message parameters
#[derive(Debug, Clone, Deserialize)]
pub struct A2AParams {
    /// Context ID for session continuity
    #[serde(rename = "contextId")]
    pub context_id: Option<String>,
    /// Task ID
    #[serde(rename = "taskId")]
    pub task_id: Option<String>,
    /// Message parts
    #[serde(default)]
    pub message: Option<A2AMessageContent>,
    /// Additional parameters
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// A2A message content
#[derive(Debug, Clone, Deserialize)]
pub struct A2AMessageContent {
    /// Role (user, assistant)
    pub role: String,
    /// Message parts
    pub parts: Vec<MessagePart>,
}

/// Message part (text, data, file)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum MessagePart {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "data")]
    Data { data: Value },
    #[serde(rename = "file")]
    File {
        #[serde(rename = "mimeType")]
        mime_type: String,
        uri: Option<String>,
        data: Option<String>,
    },
}

/// A2A response structure
#[derive(Debug, Clone, Serialize)]
pub struct A2AResponse {
    /// JSON-RPC version
    pub jsonrpc: String,
    /// Request ID
    pub id: Value,
    /// Result
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<A2AResult>,
    /// Error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<A2AError>,
}

/// A2A result
#[derive(Debug, Clone, Serialize)]
pub struct A2AResult {
    /// Context ID for session continuity
    #[serde(rename = "contextId", skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Task ID
    #[serde(rename = "taskId", skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    /// Task state
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Response message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<A2AResponseMessage>,
    /// Artifacts produced
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<Artifact>>,
}

/// A2A response message
#[derive(Debug, Clone, Serialize)]
pub struct A2AResponseMessage {
    /// Role
    pub role: String,
    /// Message parts
    pub parts: Vec<MessagePart>,
}

/// Artifact produced by task
#[derive(Debug, Clone, Serialize)]
pub struct Artifact {
    /// Artifact name
    pub name: String,
    /// MIME type
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    /// Artifact data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    /// Artifact URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

/// A2A error
#[derive(Debug, Clone, Serialize)]
pub struct A2AError {
    /// Error code
    pub code: i32,
    /// Error message
    pub message: String,
    /// Error data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// A2A handler for UCP operations
#[derive(Clone)]
pub struct A2AHandler {
    service: CheckoutService,
    base_url: String,
    ucp_version: String,
}

impl A2AHandler {
    pub fn new(service: CheckoutService, base_url: String, ucp_version: String) -> Self {
        Self {
            service,
            base_url,
            ucp_version,
        }
    }

    /// Returns the agent card for this service
    pub fn agent_card(&self) -> AgentCard {
        AgentCard {
            name: "UCP Checkout Agent".to_string(),
            description: Some("Universal Commerce Protocol checkout agent for e-commerce transactions".to_string()),
            url: format!("{}/a2a", self.base_url),
            version: "1.0.0".to_string(),
            capabilities: AgentCapabilities {
                streaming: false,
                push_notifications: false,
                state_transition_history: true,
            },
            authentication: Some(AgentAuthentication {
                schemes: vec!["bearer".to_string()],
            }),
            default_input_modes: Some(vec!["text".to_string(), "data".to_string()]),
            default_output_modes: Some(vec!["text".to_string(), "data".to_string()]),
            skills: vec![
                AgentSkill {
                    id: "create_checkout".to_string(),
                    name: "Create Checkout".to_string(),
                    description: "Create a new checkout session with items to purchase".to_string(),
                    input_schema: Some(serde_json::json!({
                        "type": "object",
                        "properties": {
                            "line_items": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "item": { "type": "object" },
                                        "quantity": { "type": "integer" }
                                    }
                                }
                            },
                            "currency": { "type": "string" }
                        },
                        "required": ["line_items", "currency"]
                    })),
                    output_schema: None,
                    examples: Some(vec![SkillExample {
                        name: "Create checkout with one item".to_string(),
                        input: serde_json::json!({
                            "line_items": [
                                { "item": { "id": "prod_123" }, "quantity": 2 }
                            ],
                            "currency": "USD"
                        }),
                        output: None,
                    }]),
                },
                AgentSkill {
                    id: "get_checkout".to_string(),
                    name: "Get Checkout".to_string(),
                    description: "Retrieve the current state of a checkout session".to_string(),
                    input_schema: Some(serde_json::json!({
                        "type": "object",
                        "properties": {
                            "checkout_id": { "type": "string" }
                        },
                        "required": ["checkout_id"]
                    })),
                    output_schema: None,
                    examples: None,
                },
                AgentSkill {
                    id: "update_checkout".to_string(),
                    name: "Update Checkout".to_string(),
                    description: "Update a checkout session with buyer info, shipping, or payment".to_string(),
                    input_schema: Some(serde_json::json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "buyer": { "type": "object" },
                            "fulfillment": { "type": "object" },
                            "payment": { "type": "object" }
                        },
                        "required": ["id"]
                    })),
                    output_schema: None,
                    examples: None,
                },
                AgentSkill {
                    id: "complete_checkout".to_string(),
                    name: "Complete Checkout".to_string(),
                    description: "Complete a checkout session and create an order".to_string(),
                    input_schema: Some(serde_json::json!({
                        "type": "object",
                        "properties": {
                            "checkout_id": { "type": "string" },
                            "payment_data": { "type": "object" }
                        },
                        "required": ["checkout_id", "payment_data"]
                    })),
                    output_schema: None,
                    examples: None,
                },
                AgentSkill {
                    id: "cancel_checkout".to_string(),
                    name: "Cancel Checkout".to_string(),
                    description: "Cancel a checkout session".to_string(),
                    input_schema: Some(serde_json::json!({
                        "type": "object",
                        "properties": {
                            "checkout_id": { "type": "string" }
                        },
                        "required": ["checkout_id"]
                    })),
                    output_schema: None,
                    examples: None,
                },
            ],
        }
    }

    /// Handle an A2A message
    pub async fn handle(&self, message: A2AMessage) -> A2AResponse {
        self.handle_with_context(message, None).await
    }

    pub async fn handle_with_context(
        &self,
        message: A2AMessage,
        negotiated: Option<&NegotiatedCapabilities>,
    ) -> A2AResponse {
        if message.jsonrpc != "2.0" {
            return self.error_response(message.id, -32600, "Invalid JSON-RPC version");
        }

        match message.method.as_str() {
            "tasks/send" => self.handle_send_task(message, negotiated).await,
            "tasks/get" => self.handle_get_task(message).await,
            "tasks/cancel" => self.handle_cancel_task(message).await,
            _ => self.error_response(message.id, -32601, &format!("Method not found: {}", message.method)),
        }
    }

    async fn handle_send_task(
        &self,
        message: A2AMessage,
        negotiated: Option<&NegotiatedCapabilities>,
    ) -> A2AResponse {
        let params = message.params.unwrap_or(A2AParams {
            context_id: None,
            task_id: None,
            message: None,
            extra: HashMap::new(),
        });

        let task_id = params.task_id.unwrap_or_else(|| format!("task_{}", Uuid::new_v4()));
        let context_id = params.context_id.unwrap_or_else(|| format!("ctx_{}", Uuid::new_v4()));

        // Extract the operation from the message
        let Some(msg_content) = params.message else {
            return self.error_response(message.id, -32602, "Missing message content");
        };

        // Look for a data part with operation details
        let mut operation: Option<String> = None;
        let mut data: Option<Value> = None;

        for part in &msg_content.parts {
            match part {
                MessagePart::Data { data: d } => {
                    if let Some(op) = d.get("operation").and_then(|v| v.as_str()) {
                        operation = Some(op.to_string());
                    }
                    data = Some(d.clone());
                }
                MessagePart::Text { text } => {
                    // Try to parse as JSON for operation
                    if let Ok(parsed) = serde_json::from_str::<Value>(text) {
                        if let Some(op) = parsed.get("operation").and_then(|v| v.as_str()) {
                            operation = Some(op.to_string());
                        }
                        data = Some(parsed);
                    }
                }
                _ => {}
            }
        }

        let Some(operation) = operation else {
            return self.error_response(message.id, -32602, "Missing operation in message");
        };

        let result = match operation.as_str() {
            "create_checkout" => self.create_checkout(data, negotiated).await,
            "get_checkout" => self.get_checkout(data, negotiated).await,
            "update_checkout" => self.update_checkout(data, negotiated).await,
            "complete_checkout" => self.complete_checkout(data, negotiated).await,
            "cancel_checkout" => self.cancel_checkout(data, negotiated).await,
            _ => Err(ServiceError::InvalidInput(format!("Unknown operation: {}", operation))),
        };

        match result {
            Ok(checkout_data) => A2AResponse {
                jsonrpc: "2.0".to_string(),
                id: message.id,
                result: Some(A2AResult {
                    context_id: Some(context_id),
                    task_id: Some(task_id),
                    state: Some("completed".to_string()),
                    message: Some(A2AResponseMessage {
                        role: "assistant".to_string(),
                        parts: vec![MessagePart::Data { data: checkout_data }],
                    }),
                    artifacts: None,
                }),
                error: None,
            },
            Err(e) => self.error_response(message.id, -32000, &e.to_string()),
        }
    }

    async fn handle_get_task(&self, message: A2AMessage) -> A2AResponse {
        // For now, we don't persist tasks - return not found
        self.error_response(message.id, -32000, "Task not found")
    }

    async fn handle_cancel_task(&self, message: A2AMessage) -> A2AResponse {
        let params = message.params.unwrap_or(A2AParams {
            context_id: None,
            task_id: None,
            message: None,
            extra: HashMap::new(),
        });

        let Some(task_id) = params.task_id else {
            return self.error_response(message.id, -32602, "Missing taskId");
        };

        // Return success (task cancellation is a no-op for completed tasks)
        A2AResponse {
            jsonrpc: "2.0".to_string(),
            id: message.id,
            result: Some(A2AResult {
                context_id: params.context_id,
                task_id: Some(task_id),
                state: Some("canceled".to_string()),
                message: None,
                artifacts: None,
            }),
            error: None,
        }
    }

    async fn create_checkout(
        &self,
        data: Option<Value>,
        negotiated: Option<&NegotiatedCapabilities>,
    ) -> Result<Value, ServiceError> {
        let data = data.ok_or_else(|| ServiceError::InvalidInput("Missing data".to_string()))?;
        let request: CheckoutCreateRequest = serde_json::from_value(data)
            .map_err(|e| ServiceError::InvalidInput(format!("Invalid request: {}", e)))?;
        let mut checkout = self.service.create_checkout(request).await?;
        apply_negotiated_checkout(&mut checkout, negotiated);
        serde_json::to_value(&checkout)
            .map_err(|e| ServiceError::External(format!("Serialization error: {}", e)))
    }

    async fn get_checkout(
        &self,
        data: Option<Value>,
        negotiated: Option<&NegotiatedCapabilities>,
    ) -> Result<Value, ServiceError> {
        let data = data.ok_or_else(|| ServiceError::InvalidInput("Missing data".to_string()))?;
        let checkout_id = data
            .get("checkout_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServiceError::InvalidInput("Missing checkout_id".to_string()))?;
        let mut checkout = self.service.get_checkout(checkout_id).await?;
        apply_negotiated_checkout(&mut checkout, negotiated);
        serde_json::to_value(&checkout)
            .map_err(|e| ServiceError::External(format!("Serialization error: {}", e)))
    }

    async fn update_checkout(
        &self,
        data: Option<Value>,
        negotiated: Option<&NegotiatedCapabilities>,
    ) -> Result<Value, ServiceError> {
        let data = data.ok_or_else(|| ServiceError::InvalidInput("Missing data".to_string()))?;
        let checkout_id = data
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServiceError::InvalidInput("Missing id".to_string()))?
            .to_string();
        let request: CheckoutUpdateRequest = serde_json::from_value(data)
            .map_err(|e| ServiceError::InvalidInput(format!("Invalid request: {}", e)))?;
        let mut checkout = self.service.update_checkout(&checkout_id, request).await?;
        apply_negotiated_checkout(&mut checkout, negotiated);
        serde_json::to_value(&checkout)
            .map_err(|e| ServiceError::External(format!("Serialization error: {}", e)))
    }

    async fn complete_checkout(
        &self,
        data: Option<Value>,
        negotiated: Option<&NegotiatedCapabilities>,
    ) -> Result<Value, ServiceError> {
        let data = data.ok_or_else(|| ServiceError::InvalidInput("Missing data".to_string()))?;
        let checkout_id = data
            .get("checkout_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServiceError::InvalidInput("Missing checkout_id".to_string()))?
            .to_string();
        let request: CheckoutCompleteRequest = serde_json::from_value(data)
            .map_err(|e| ServiceError::InvalidInput(format!("Invalid request: {}", e)))?;
        let require_ap2 = requires_ap2_mandate(negotiated, self.service.ap2_enabled());
        let mut checkout = self
            .service
            .complete_checkout_with_requirements(&checkout_id, request, require_ap2)
            .await?;
        apply_negotiated_checkout(&mut checkout, negotiated);
        serde_json::to_value(&checkout)
            .map_err(|e| ServiceError::External(format!("Serialization error: {}", e)))
    }

    async fn cancel_checkout(
        &self,
        data: Option<Value>,
        negotiated: Option<&NegotiatedCapabilities>,
    ) -> Result<Value, ServiceError> {
        let data = data.ok_or_else(|| ServiceError::InvalidInput("Missing data".to_string()))?;
        let checkout_id = data
            .get("checkout_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServiceError::InvalidInput("Missing checkout_id".to_string()))?
            .to_string();
        let mut checkout = self.service.cancel_checkout(&checkout_id).await?;
        apply_negotiated_checkout(&mut checkout, negotiated);
        serde_json::to_value(&checkout)
            .map_err(|e| ServiceError::External(format!("Serialization error: {}", e)))
    }

    fn error_response(&self, id: Value, code: i32, message: &str) -> A2AResponse {
        A2AResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(A2AError {
                code,
                message: message.to_string(),
                data: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_card_serialization() {
        let card = AgentCard {
            name: "Test Agent".to_string(),
            description: Some("Test description".to_string()),
            url: "https://example.com/a2a".to_string(),
            version: "1.0.0".to_string(),
            capabilities: AgentCapabilities {
                streaming: false,
                push_notifications: false,
                state_transition_history: true,
            },
            authentication: None,
            default_input_modes: None,
            default_output_modes: None,
            skills: vec![],
        };

        let json = serde_json::to_string(&card).unwrap();
        assert!(json.contains("\"name\":\"Test Agent\""));
        assert!(json.contains("\"version\":\"1.0.0\""));
    }

    #[test]
    fn test_a2a_message_parsing() {
        let json = r#"{
            "jsonrpc": "2.0",
            "method": "tasks/send",
            "id": "req-1",
            "params": {
                "taskId": "task_123",
                "message": {
                    "role": "user",
                    "parts": [
                        { "type": "text", "text": "Hello" }
                    ]
                }
            }
        }"#;

        let message: A2AMessage = serde_json::from_str(json).unwrap();
        assert_eq!(message.method, "tasks/send");
        assert!(message.params.is_some());
    }
}
