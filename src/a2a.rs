//! A2A (Agent-to-Agent) transport implementation.
//!
//! Implements the Google A2A protocol for agent-to-agent communication,
//! supporting agent cards, task management, and message handling.

use crate::crypto::canonicalize;
use crate::errors::ServiceError;
use crate::models::{CheckoutCompleteRequest, CheckoutCreateRequest, CheckoutUpdateRequest};
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
    /// A2A protocol version
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    /// Preferred transport
    #[serde(rename = "preferredTransport", skip_serializing_if = "Option::is_none")]
    pub preferred_transport: Option<String>,
    /// Provider metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<AgentProvider>,
    /// Agent capabilities
    pub capabilities: AgentCapabilities,
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
    /// Supported extensions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<AgentExtension>>,
}

/// Agent provider metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProvider {
    pub organization: String,
    pub url: String,
}

/// Agent extension definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentExtension {
    /// Extension URI
    pub uri: String,
    /// Extension description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the extension is required
    #[serde(default)]
    pub required: bool,
    /// Extension parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
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
    /// Skill tags
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Example prompts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub examples: Option<Vec<String>>,
    /// Input schema (JSON Schema)
    #[serde(rename = "inputSchema", skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
    /// Output schema (JSON Schema)
    #[serde(rename = "outputSchema", skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
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
    /// Optional message ID
    #[serde(rename = "messageId")]
    pub message_id: Option<String>,
    /// Message parts
    #[serde(default)]
    pub message: Option<A2AMessageContent>,
    /// Optional configuration (deserialized from JSON, reserved for future use)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[allow(dead_code)]
    pub configuration: Option<Value>,
    /// Additional parameters (deserialized from JSON, reserved for future use)
    #[serde(flatten)]
    #[allow(dead_code)]
    pub extra: HashMap<String, Value>,
}

/// A2A message content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2AMessageContent {
    /// Role (user, assistant)
    pub role: String,
    /// Message parts
    pub parts: Vec<MessagePart>,
    /// Message ID for idempotency
    #[serde(rename = "messageId", skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    /// Message kind
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Context ID (if provided inside message)
    #[serde(rename = "contextId", skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Task ID (if provided inside message)
    #[serde(rename = "taskId", skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
}

/// Message part (text, data, file)
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind")]
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

impl<'de> Deserialize<'de> for MessagePart {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let part_type = value
            .get("type")
            .or_else(|| value.get("kind"))
            .and_then(|value| value.as_str())
            .ok_or_else(|| serde::de::Error::custom("Missing message part type"))?;

        match part_type {
            "text" => {
                let text = value
                    .get("text")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| serde::de::Error::custom("Missing text content"))?;
                Ok(MessagePart::Text {
                    text: text.to_string(),
                })
            }
            "data" => {
                let data = value
                    .get("data")
                    .cloned()
                    .ok_or_else(|| serde::de::Error::custom("Missing data payload"))?;
                Ok(MessagePart::Data { data })
            }
            "file" => {
                let mime_type = value
                    .get("mimeType")
                    .or_else(|| value.get("mime_type"))
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| serde::de::Error::custom("Missing mimeType"))?;
                let uri = value
                    .get("uri")
                    .and_then(|value| value.as_str())
                    .map(|value| value.to_string());
                let data = value
                    .get("data")
                    .and_then(|value| value.as_str())
                    .map(|value| value.to_string());
                Ok(MessagePart::File {
                    mime_type: mime_type.to_string(),
                    uri,
                    data,
                })
            }
            _ => Err(serde::de::Error::custom("Unknown message part type")),
        }
    }
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
    /// Message ID
    #[serde(rename = "messageId", skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    /// Message kind
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Message role
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Message parts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parts: Option<Vec<MessagePart>>,
    /// Optional status payload (task responses)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<A2AStatus>,
    /// Artifacts produced
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<Artifact>>,
}

/// A2A task status payload
#[derive(Debug, Clone, Serialize)]
pub struct A2AStatus {
    /// Task state
    pub state: String,
    /// Optional message payload
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<A2AResponseMessage>,
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
    message_cache: Arc<RwLock<HashMap<String, A2AIdempotencyRecord>>>,
    context_checkouts: Arc<RwLock<HashMap<String, String>>>,
    message_ttl: Duration,
}

#[derive(Clone)]
struct A2AIdempotencyRecord {
    request_hash: String,
    response: A2AResponse,
    created_at: Instant,
}

impl A2AHandler {
    pub fn new(service: CheckoutService, base_url: String, ucp_version: String) -> Self {
        Self {
            service,
            base_url,
            ucp_version,
            message_cache: Arc::new(RwLock::new(HashMap::new())),
            context_checkouts: Arc::new(RwLock::new(HashMap::new())),
            message_ttl: Duration::from_secs(600),
        }
    }

    /// Returns the agent card for this service
    pub fn agent_card(&self) -> AgentCard {
        let extension_capabilities = self
            .service
            .business_capabilities()
            .into_iter()
            .map(|capability| {
                let mut map = serde_json::Map::new();
                map.insert("name".to_string(), Value::String(capability.name));
                map.insert("version".to_string(), Value::String(capability.version));
                map.insert("spec".to_string(), Value::String(capability.spec));
                map.insert("schema".to_string(), Value::String(capability.schema));
                if let Some(extends) = capability.extends {
                    map.insert("extends".to_string(), Value::String(extends));
                }
                Value::Object(map)
            })
            .collect::<Vec<_>>();

        AgentCard {
            name: "UCP Checkout Agent".to_string(),
            description: Some(
                "Universal Commerce Protocol checkout agent for e-commerce transactions"
                    .to_string(),
            ),
            url: format!("{}/a2a", self.base_url),
            version: "1.0.0".to_string(),
            protocol_version: "0.3.0".to_string(),
            preferred_transport: Some("JSONRPC".to_string()),
            provider: None,
            capabilities: AgentCapabilities {
                streaming: false,
                extensions: Some(vec![AgentExtension {
                    uri: format!(
                        "https://ucp.dev/specification/reference?v={}",
                        self.ucp_version
                    ),
                    description: Some("Business agent supporting UCP".to_string()),
                    required: true,
                    params: Some(serde_json::json!({
                        "capabilities": extension_capabilities
                    })),
                }]),
            },
            default_input_modes: Some(vec![
                "text".to_string(),
                "text/plain".to_string(),
                "application/json".to_string(),
            ]),
            default_output_modes: Some(vec![
                "text".to_string(),
                "text/plain".to_string(),
                "application/json".to_string(),
            ]),
            skills: vec![
                AgentSkill {
                    id: "create_checkout".to_string(),
                    name: "Create Checkout".to_string(),
                    description: "Create a new checkout session with items to purchase".to_string(),
                    tags: Some(vec!["checkout".to_string()]),
                    examples: Some(vec![
                        "Create a checkout with one item".to_string(),
                        "Start a checkout for two items".to_string(),
                    ]),
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
                },
                AgentSkill {
                    id: "get_checkout".to_string(),
                    name: "Get Checkout".to_string(),
                    description: "Retrieve the current state of a checkout session".to_string(),
                    tags: Some(vec!["checkout".to_string()]),
                    examples: Some(vec!["Fetch the current checkout".to_string()]),
                    input_schema: Some(serde_json::json!({
                        "type": "object",
                        "properties": {
                            "checkout_id": { "type": "string" }
                        },
                        "required": ["checkout_id"]
                    })),
                    output_schema: None,
                },
                AgentSkill {
                    id: "update_checkout".to_string(),
                    name: "Update Checkout".to_string(),
                    description: "Update a checkout session with buyer info, shipping, or payment".to_string(),
                    tags: Some(vec!["checkout".to_string()]),
                    examples: Some(vec!["Update buyer info".to_string()]),
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
                },
                AgentSkill {
                    id: "complete_checkout".to_string(),
                    name: "Complete Checkout".to_string(),
                    description: "Complete a checkout session and create an order".to_string(),
                    tags: Some(vec!["checkout".to_string()]),
                    examples: Some(vec!["Complete checkout".to_string()]),
                    input_schema: Some(serde_json::json!({
                        "type": "object",
                        "properties": {
                            "checkout_id": { "type": "string" },
                            "payment_data": { "type": "object" }
                        },
                        "required": ["checkout_id", "payment_data"]
                    })),
                    output_schema: None,
                },
                AgentSkill {
                    id: "cancel_checkout".to_string(),
                    name: "Cancel Checkout".to_string(),
                    description: "Cancel a checkout session".to_string(),
                    tags: Some(vec!["checkout".to_string()]),
                    examples: Some(vec!["Cancel checkout".to_string()]),
                    input_schema: Some(serde_json::json!({
                        "type": "object",
                        "properties": {
                            "checkout_id": { "type": "string" }
                        },
                        "required": ["checkout_id"]
                    })),
                    output_schema: None,
                },
            ],
        }
    }

    /// Handle an A2A message
    #[allow(dead_code)]
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
            "message/send" | "tasks/send" => self.handle_send_message(message, negotiated).await,
            "tasks/get" => self.handle_get_task(message).await,
            "tasks/cancel" => self.handle_cancel_task(message).await,
            _ => self.error_response(message.id, -32601, &format!("Method not found: {}", message.method)),
        }
    }

    async fn handle_send_message(
        &self,
        message: A2AMessage,
        negotiated: Option<&NegotiatedCapabilities>,
    ) -> A2AResponse {
        let params = message.params.unwrap_or(A2AParams {
            context_id: None,
            task_id: None,
            message_id: None,
            message: None,
            configuration: None,
            extra: HashMap::new(),
        });

        let Some(msg_content) = params.message else {
            return self.error_response(message.id, -32602, "Missing message content");
        };

        let message_id = msg_content
            .message_id
            .clone()
            .or_else(|| params.message_id.clone());
        let Some(message_id) = message_id else {
            return self.error_response(message.id, -32602, "Missing messageId");
        };

        let context_id = params
            .context_id
            .clone()
            .or_else(|| msg_content.context_id.clone())
            .unwrap_or_else(|| format!("ctx_{}", Uuid::new_v4()));
        let task_id = params.task_id.clone().or_else(|| msg_content.task_id.clone());

        let request_hash = self.message_hash(&msg_content);
        if let Some(response) = self
            .idempotency_replay(&message_id, &request_hash, &message.id)
            .await
        {
            return response;
        }

        let parsed = ParsedA2ARequest::from_parts(&msg_content.parts);
        let checkout_payload = parsed.checkout.clone();
        let payment_data = parsed.payment_data.clone();
        let risk_signals = parsed.risk_signals.clone();
        let ap2_mandate = parsed.ap2_mandate.clone();
        let action = parsed.resolve_action();
        let Some(action) = action else {
            let response = self.error_response(message.id, -32602, "Missing action in message");
            self.store_idempotency(message_id, request_hash, response.clone())
                .await;
            return response;
        };

        let checkout_id = parsed
            .checkout_id
            .clone()
            .or_else(|| parsed.checkout.as_ref().and_then(checkout_id_from_value));

        let checkout_id = match action.as_str() {
            "get_checkout" | "update_checkout" | "complete_checkout" | "cancel_checkout" => {
                if let Some(checkout_id) = checkout_id {
                    Some(checkout_id)
                } else {
                    self.context_checkout(&context_id).await
                }
            }
            _ => checkout_id,
        };

        let result = match action.as_str() {
            "create_checkout" => match checkout_payload {
                Some(payload) => self.create_checkout(Some(payload), negotiated).await,
                None => Err(ServiceError::InvalidInput(
                    "Missing a2a.ucp.checkout payload".to_string(),
                )),
            },
            "get_checkout" => match checkout_id {
                Some(checkout_id) => {
                    self.get_checkout(
                        Some(serde_json::json!({ "checkout_id": checkout_id })),
                        negotiated,
                    )
                    .await
                }
                None => Err(ServiceError::InvalidInput("Missing checkout_id".to_string())),
            },
            "update_checkout" => match (checkout_payload, checkout_id) {
                (Some(mut payload), Some(checkout_id)) => {
                    if let Some(obj) = payload.as_object_mut() {
                        obj.entry("id".to_string())
                            .or_insert_with(|| Value::String(checkout_id));
                    }
                    self.update_checkout(Some(payload), negotiated).await
                }
                (None, _) => Err(ServiceError::InvalidInput(
                    "Missing a2a.ucp.checkout payload".to_string(),
                )),
                (_, None) => Err(ServiceError::InvalidInput("Missing checkout_id".to_string())),
            },
            "complete_checkout" => match (checkout_id, payment_data) {
                (Some(checkout_id), Some(payment_data)) => {
                    let mut payload = serde_json::Map::new();
                    payload.insert("checkout_id".to_string(), Value::String(checkout_id));
                    payload.insert("payment_data".to_string(), payment_data);
                    if let Some(risk_signals) = risk_signals {
                        payload.insert("risk_signals".to_string(), risk_signals);
                    }
                    if let Some(mandate) = ap2_mandate {
                        payload.insert(
                            "ap2".to_string(),
                            serde_json::json!({ "checkout_mandate": mandate }),
                        );
                    }
                    self.complete_checkout(Some(Value::Object(payload)), negotiated)
                        .await
                }
                (None, _) => Err(ServiceError::InvalidInput("Missing checkout_id".to_string())),
                (_, None) => Err(ServiceError::InvalidInput("Missing payment_data".to_string())),
            },
            "cancel_checkout" => match checkout_id {
                Some(checkout_id) => {
                    self.cancel_checkout(
                        Some(serde_json::json!({ "checkout_id": checkout_id })),
                        negotiated,
                    )
                    .await
                }
                None => Err(ServiceError::InvalidInput("Missing checkout_id".to_string())),
            },
            _ => Err(ServiceError::InvalidInput(format!(
                "Unknown action: {}",
                action
            ))),
        };

        let response = match result {
            Ok(checkout_data) => {
                if let Some(checkout_id) = checkout_data
                    .get("id")
                    .and_then(|value| value.as_str())
                    .map(|value| value.to_string())
                {
                    self.store_context_checkout(context_id.clone(), checkout_id)
                        .await;
                }

                A2AResponse {
                    jsonrpc: "2.0".to_string(),
                    id: message.id,
                    result: Some(A2AResult {
                        context_id: Some(context_id),
                        task_id,
                        message_id: Some(format!("msg_{}", Uuid::new_v4())),
                        kind: Some("message".to_string()),
                        role: Some("agent".to_string()),
                        parts: Some(vec![MessagePart::Data {
                            data: serde_json::json!({
                                "a2a.ucp.checkout": checkout_data
                            }),
                        }]),
                        status: None,
                        artifacts: None,
                    }),
                    error: None,
                }
            }
            Err(e) => self.error_response(message.id, -32000, &e.to_string()),
        };

        self.store_idempotency(message_id, request_hash, response.clone())
            .await;

        response
    }

    async fn handle_get_task(&self, message: A2AMessage) -> A2AResponse {
        // For now, we don't persist tasks - return not found
        self.error_response(message.id, -32000, "Task not found")
    }

    async fn handle_cancel_task(&self, message: A2AMessage) -> A2AResponse {
        let params = message.params.unwrap_or(A2AParams {
            context_id: None,
            task_id: None,
            message_id: None,
            message: None,
            configuration: None,
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
                message_id: None,
                kind: None,
                role: None,
                parts: None,
                status: Some(A2AStatus {
                    state: "canceled".to_string(),
                    message: None,
                }),
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
        if let Some(negotiated) = negotiated {
            self.service
                .record_negotiated_checkout(
                    &checkout.id,
                    &negotiated.version,
                    &negotiated.capabilities,
                )
                .await;
        }
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
            .or_else(|| data.get("id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServiceError::InvalidInput("Missing checkout_id".to_string()))?;
        let mut checkout = self.service.get_checkout(checkout_id).await?;
        if let Some(negotiated) = negotiated {
            self.service
                .record_negotiated_checkout(
                    &checkout.id,
                    &negotiated.version,
                    &negotiated.capabilities,
                )
                .await;
        }
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
        if let Some(negotiated) = negotiated {
            self.service
                .record_negotiated_checkout(
                    &checkout.id,
                    &negotiated.version,
                    &negotiated.capabilities,
                )
                .await;
        }
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
            .or_else(|| data.get("id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServiceError::InvalidInput("Missing checkout_id".to_string()))?
            .to_string();
        let request: CheckoutCompleteRequest = serde_json::from_value(data)
            .map_err(|e| ServiceError::InvalidInput(format!("Invalid request: {}", e)))?;
        let require_ap2 = requires_ap2_mandate(negotiated, self.service.ap2_enabled());
        let webhook_url = negotiated.and_then(|caps| caps.platform_webhook_url.clone());
        let mut checkout = self
            .service
            .complete_checkout_with_requirements(
                &checkout_id,
                request,
                require_ap2,
                webhook_url,
                negotiated.map(|caps| caps.platform_signing_keys.as_slice()),
            )
            .await?;
        if let Some(negotiated) = negotiated {
            self.service
                .record_negotiated_checkout(
                    &checkout.id,
                    &negotiated.version,
                    &negotiated.capabilities,
                )
                .await;
        }
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
            .or_else(|| data.get("id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServiceError::InvalidInput("Missing checkout_id".to_string()))?
            .to_string();
        let mut checkout = self.service.cancel_checkout(&checkout_id).await?;
        if let Some(negotiated) = negotiated {
            self.service
                .record_negotiated_checkout(
                    &checkout.id,
                    &negotiated.version,
                    &negotiated.capabilities,
                )
                .await;
        }
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

    fn message_hash(&self, message: &A2AMessageContent) -> String {
        let value = serde_json::to_value(message).unwrap_or(Value::Null);
        let canonical = canonicalize(&value).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&canonical);
        hex::encode(hasher.finalize())
    }

    async fn idempotency_replay(
        &self,
        message_id: &str,
        request_hash: &str,
        id: &Value,
    ) -> Option<A2AResponse> {
        let mut store = self.message_cache.write().await;
        if let Some(record) = store.get(message_id) {
            if record.created_at.elapsed() > self.message_ttl {
                store.remove(message_id);
                return None;
            }

            if record.request_hash != request_hash {
                return Some(self.error_response(
                    id.clone(),
                    -32602,
                    "messageId reused with different payload",
                ));
            }

            return Some(record.response.clone());
        }
        None
    }

    async fn store_idempotency(
        &self,
        message_id: String,
        request_hash: String,
        response: A2AResponse,
    ) {
        let mut store = self.message_cache.write().await;
        store.insert(
            message_id,
            A2AIdempotencyRecord {
                request_hash,
                response,
                created_at: Instant::now(),
            },
        );
    }

    async fn context_checkout(&self, context_id: &str) -> Option<String> {
        let store = self.context_checkouts.read().await;
        store.get(context_id).cloned()
    }

    async fn store_context_checkout(&self, context_id: String, checkout_id: String) {
        let mut store = self.context_checkouts.write().await;
        store.insert(context_id, checkout_id);
    }
}

#[derive(Debug, Clone, Default)]
struct ParsedA2ARequest {
    action: Option<String>,
    checkout: Option<Value>,
    payment_data: Option<Value>,
    risk_signals: Option<Value>,
    ap2_mandate: Option<String>,
    checkout_id: Option<String>,
}

impl ParsedA2ARequest {
    fn from_parts(parts: &[MessagePart]) -> Self {
        let mut parsed = ParsedA2ARequest::default();

        for part in parts {
            match part {
                MessagePart::Data { data } => {
                    parsed.update_from_value(data);
                }
                MessagePart::Text { text } => {
                    if let Ok(value) = serde_json::from_str::<Value>(text) {
                        parsed.update_from_value(&value);
                    }
                }
                _ => {}
            }
        }

        parsed
    }

    fn update_from_value(&mut self, value: &Value) {
        if let Some(action) = value.get("action").and_then(|value| value.as_str()) {
            self.action = Some(action.to_string());
        }

        if self.checkout_id.is_none() {
            self.checkout_id = value
                .get("checkout_id")
                .or_else(|| value.get("id"))
                .and_then(|value| value.as_str())
                .map(|value| value.to_string());
        }

        if let Some(checkout) = value.get("a2a.ucp.checkout") {
            self.checkout = Some(checkout.clone());
        }

        if let Some(payment_data) = value.get("a2a.ucp.checkout.payment_data") {
            self.payment_data = Some(payment_data.clone());
        }

        if let Some(risk_signals) = value.get("a2a.ucp.checkout.risk_signals") {
            self.risk_signals = Some(risk_signals.clone());
        }

        if let Some(mandate) = value.get("ap2.checkout_mandate").and_then(|value| value.as_str()) {
            self.ap2_mandate = Some(mandate.to_string());
        }
    }

    fn resolve_action(&self) -> Option<String> {
        if let Some(action) = &self.action {
            return Some(action.clone());
        }

        if self.payment_data.is_some() {
            return Some("complete_checkout".to_string());
        }

        if let Some(checkout) = &self.checkout {
            if checkout_id_from_value(checkout).is_some() {
                return Some("update_checkout".to_string());
            }
            return Some("create_checkout".to_string());
        }

        None
    }
}

fn checkout_id_from_value(value: &Value) -> Option<String> {
    value
        .get("id")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
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
            protocol_version: "0.3.0".to_string(),
            preferred_transport: Some("JSONRPC".to_string()),
            provider: None,
            capabilities: AgentCapabilities {
                streaming: false,
                extensions: None,
            },
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
