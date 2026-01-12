//! Embedded Protocol (EP) implementation.
//!
//! Implements the UCP Embedded Protocol for browser-based checkout flows,
//! supporting delegation contracts and callback handling.

use crate::errors::ServiceError;
use crate::service::CheckoutService;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Embedded Protocol query parameters
#[derive(Debug, Clone, Deserialize)]
pub struct EmbeddedParams {
    /// Action to perform
    #[serde(rename = "ec_action")]
    pub action: Option<String>,
    /// Session ID for continuity
    #[serde(rename = "ec_session_id")]
    pub session_id: Option<String>,
    /// Encoded payload (base64url JSON)
    #[serde(rename = "ec_payload")]
    pub payload: Option<String>,
    /// Callback URL for results
    #[serde(rename = "ec_callback")]
    pub callback: Option<String>,
    /// Platform profile URL
    #[serde(rename = "ec_profile")]
    pub profile: Option<String>,
}

/// Embedded Protocol response
#[derive(Debug, Clone, Serialize)]
pub struct EmbeddedResponse {
    /// Whether the operation succeeded
    pub success: bool,
    /// Redirect URL (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
    /// Result data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    /// Error message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Delegation contract for external service integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationContract {
    /// Contract ID
    pub id: String,
    /// Delegation type (payment, fulfillment, identity)
    #[serde(rename = "type")]
    pub delegation_type: String,
    /// Delegate service URL
    pub delegate_url: String,
    /// Required fields to be provided by delegate
    pub required_fields: Vec<String>,
    /// Optional fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional_fields: Option<Vec<String>>,
    /// Callback URL for delegate response
    pub callback_url: String,
    /// Expiration time (RFC 3339)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Additional contract metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, Value>>,
}

/// Delegation result returned from delegate
#[derive(Debug, Clone, Deserialize)]
pub struct DelegationResult {
    /// Contract ID this result fulfills
    pub contract_id: String,
    /// Status (completed, failed, canceled)
    pub status: String,
    /// Result data
    #[serde(default)]
    pub data: HashMap<String, Value>,
    /// Error message if failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Embedded checkout state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedCheckoutState {
    /// Checkout ID
    pub checkout_id: String,
    /// Current step in the flow
    pub step: String,
    /// Pending delegations
    #[serde(default)]
    pub pending_delegations: Vec<String>,
    /// Completed delegations
    #[serde(default)]
    pub completed_delegations: Vec<String>,
    /// UI customization options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_options: Option<UiOptions>,
}

/// UI customization options for embedded checkout
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiOptions {
    /// Primary color (hex)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_color: Option<String>,
    /// Logo URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    /// Merchant name to display
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_name: Option<String>,
    /// Custom CSS URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_css_url: Option<String>,
}

/// Embedded Protocol handler
#[derive(Clone)]
pub struct EmbeddedHandler {
    service: CheckoutService,
    base_url: String,
}

impl EmbeddedHandler {
    pub fn new(service: CheckoutService, base_url: String) -> Self {
        Self { service, base_url }
    }

    /// Parse embedded protocol parameters from query string
    pub fn parse_params(query: &str) -> Result<EmbeddedParams, ServiceError> {
        serde_urlencoded::from_str(query)
            .map_err(|e| ServiceError::InvalidInput(format!("Invalid query parameters: {}", e)))
    }

    /// Handle an embedded protocol request
    pub async fn handle(&self, params: EmbeddedParams) -> EmbeddedResponse {
        let action = params.action.as_deref().unwrap_or("view");

        match action {
            "view" | "start" => self.handle_view(params).await,
            "update" => self.handle_update(params).await,
            "delegate" => self.handle_delegate(params).await,
            "callback" => self.handle_callback(params).await,
            _ => EmbeddedResponse {
                success: false,
                redirect_url: None,
                data: None,
                error: Some(format!("Unknown action: {}", action)),
            },
        }
    }

    /// Handle view/start action - display checkout
    async fn handle_view(&self, params: EmbeddedParams) -> EmbeddedResponse {
        let Some(session_id) = params.session_id else {
            return EmbeddedResponse {
                success: false,
                redirect_url: None,
                data: None,
                error: Some("Missing ec_session_id".to_string()),
            };
        };

        match self.service.get_checkout(&session_id).await {
            Ok(checkout) => {
                let state = EmbeddedCheckoutState {
                    checkout_id: checkout.id.clone(),
                    step: match checkout.status {
                        crate::models::CheckoutStatus::Incomplete => "buyer_info".to_string(),
                        crate::models::CheckoutStatus::RequiresEscalation => "review".to_string(),
                        crate::models::CheckoutStatus::ReadyForComplete => "payment".to_string(),
                        crate::models::CheckoutStatus::CompleteInProgress => "processing".to_string(),
                        crate::models::CheckoutStatus::Completed => "confirmation".to_string(),
                        crate::models::CheckoutStatus::Canceled => "canceled".to_string(),
                    },
                    pending_delegations: vec![],
                    completed_delegations: vec![],
                    ui_options: None,
                };

                EmbeddedResponse {
                    success: true,
                    redirect_url: Some(format!(
                        "{}/checkout/{}/embedded",
                        self.base_url, checkout.id
                    )),
                    data: Some(serde_json::json!({
                        "checkout": checkout,
                        "state": state
                    })),
                    error: None,
                }
            }
            Err(e) => EmbeddedResponse {
                success: false,
                redirect_url: None,
                data: None,
                error: Some(e.to_string()),
            },
        }
    }

    /// Handle update action - update checkout from embedded UI
    async fn handle_update(&self, params: EmbeddedParams) -> EmbeddedResponse {
        let Some(session_id) = params.session_id else {
            return EmbeddedResponse {
                success: false,
                redirect_url: None,
                data: None,
                error: Some("Missing ec_session_id".to_string()),
            };
        };

        let Some(payload) = params.payload else {
            return EmbeddedResponse {
                success: false,
                redirect_url: None,
                data: None,
                error: Some("Missing ec_payload".to_string()),
            };
        };

        // Decode base64url payload
        let decoded = match decode_payload(&payload) {
            Ok(d) => d,
            Err(e) => {
                return EmbeddedResponse {
                    success: false,
                    redirect_url: None,
                    data: None,
                    error: Some(format!("Invalid payload: {}", e)),
                };
            }
        };

        // Parse as update request
        let update_request: crate::models::CheckoutUpdateRequest = match serde_json::from_value(decoded) {
            Ok(req) => req,
            Err(e) => {
                return EmbeddedResponse {
                    success: false,
                    redirect_url: None,
                    data: None,
                    error: Some(format!("Invalid update request: {}", e)),
                };
            }
        };

        match self.service.update_checkout(&session_id, update_request).await {
            Ok(checkout) => EmbeddedResponse {
                success: true,
                redirect_url: None,
                data: Some(serde_json::to_value(&checkout).unwrap_or_default()),
                error: None,
            },
            Err(e) => EmbeddedResponse {
                success: false,
                redirect_url: None,
                data: None,
                error: Some(e.to_string()),
            },
        }
    }

    /// Handle delegate action - create a delegation contract
    async fn handle_delegate(&self, params: EmbeddedParams) -> EmbeddedResponse {
        let Some(session_id) = params.session_id else {
            return EmbeddedResponse {
                success: false,
                redirect_url: None,
                data: None,
                error: Some("Missing ec_session_id".to_string()),
            };
        };

        let Some(payload) = params.payload else {
            return EmbeddedResponse {
                success: false,
                redirect_url: None,
                data: None,
                error: Some("Missing ec_payload (delegation type)".to_string()),
            };
        };

        // Decode payload to get delegation type
        let decoded = match decode_payload(&payload) {
            Ok(d) => d,
            Err(e) => {
                return EmbeddedResponse {
                    success: false,
                    redirect_url: None,
                    data: None,
                    error: Some(format!("Invalid payload: {}", e)),
                };
            }
        };

        let delegation_type = decoded
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("payment");

        let contract = self.create_delegation_contract(&session_id, delegation_type);

        EmbeddedResponse {
            success: true,
            redirect_url: Some(contract.delegate_url.clone()),
            data: Some(serde_json::to_value(&contract).unwrap_or_default()),
            error: None,
        }
    }

    /// Handle callback action - process delegation result
    async fn handle_callback(&self, params: EmbeddedParams) -> EmbeddedResponse {
        let Some(payload) = params.payload else {
            return EmbeddedResponse {
                success: false,
                redirect_url: None,
                data: None,
                error: Some("Missing ec_payload (delegation result)".to_string()),
            };
        };

        let decoded = match decode_payload(&payload) {
            Ok(d) => d,
            Err(e) => {
                return EmbeddedResponse {
                    success: false,
                    redirect_url: None,
                    data: None,
                    error: Some(format!("Invalid payload: {}", e)),
                };
            }
        };

        let result: DelegationResult = match serde_json::from_value(decoded) {
            Ok(r) => r,
            Err(e) => {
                return EmbeddedResponse {
                    success: false,
                    redirect_url: None,
                    data: None,
                    error: Some(format!("Invalid delegation result: {}", e)),
                };
            }
        };

        if result.status == "completed" {
            EmbeddedResponse {
                success: true,
                redirect_url: params.callback,
                data: Some(serde_json::json!({
                    "contract_id": result.contract_id,
                    "status": "completed"
                })),
                error: None,
            }
        } else {
            EmbeddedResponse {
                success: false,
                redirect_url: params.callback,
                data: None,
                error: result.error,
            }
        }
    }

    /// Create a delegation contract for external service
    pub fn create_delegation_contract(&self, checkout_id: &str, delegation_type: &str) -> DelegationContract {
        let contract_id = format!("dlg_{}", uuid::Uuid::new_v4());

        let (required_fields, delegate_url) = match delegation_type {
            "payment" => (
                vec![
                    "payment_method".to_string(),
                    "card_last_four".to_string(),
                    "card_brand".to_string(),
                ],
                format!("{}/delegate/payment", self.base_url),
            ),
            "fulfillment" => (
                vec![
                    "address_line1".to_string(),
                    "city".to_string(),
                    "postal_code".to_string(),
                    "country".to_string(),
                ],
                format!("{}/delegate/fulfillment", self.base_url),
            ),
            "identity" => (
                vec!["email".to_string(), "name".to_string()],
                format!("{}/delegate/identity", self.base_url),
            ),
            _ => (vec![], format!("{}/delegate/generic", self.base_url)),
        };

        let expires_at = chrono::Utc::now() + chrono::Duration::minutes(30);

        DelegationContract {
            id: contract_id,
            delegation_type: delegation_type.to_string(),
            delegate_url,
            required_fields,
            optional_fields: None,
            callback_url: format!(
                "{}/checkout/{}/embedded?ec_action=callback",
                self.base_url, checkout_id
            ),
            expires_at: Some(expires_at.to_rfc3339()),
            metadata: Some({
                let mut meta = HashMap::new();
                meta.insert("checkout_id".to_string(), serde_json::json!(checkout_id));
                meta
            }),
        }
    }

    /// Get delegation contract by type
    pub fn delegation_contract(&self, checkout_id: &str, delegation_type: &str) -> DelegationContract {
        self.create_delegation_contract(checkout_id, delegation_type)
    }
}

/// Decode base64url encoded JSON payload
fn decode_payload(encoded: &str) -> Result<Value, ServiceError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let decoded_bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| ServiceError::InvalidInput(format!("Base64 decode error: {}", e)))?;

    let json_str = String::from_utf8(decoded_bytes)
        .map_err(|e| ServiceError::InvalidInput(format!("UTF-8 decode error: {}", e)))?;

    serde_json::from_str(&json_str)
        .map_err(|e| ServiceError::InvalidInput(format!("JSON parse error: {}", e)))
}

/// Encode JSON payload as base64url
pub fn encode_payload(value: &Value) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let json_str = serde_json::to_string(value).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(json_str.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_params() {
        let query = "ec_action=view&ec_session_id=chk_123&ec_callback=https://example.com/callback";
        let params = EmbeddedHandler::parse_params(query).unwrap();

        assert_eq!(params.action, Some("view".to_string()));
        assert_eq!(params.session_id, Some("chk_123".to_string()));
        assert_eq!(params.callback, Some("https://example.com/callback".to_string()));
    }

    #[test]
    fn test_encode_decode_payload() {
        let original = serde_json::json!({
            "type": "payment",
            "amount": 1000
        });

        let encoded = encode_payload(&original);
        let decoded = decode_payload(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_delegation_contract_serialization() {
        let contract = DelegationContract {
            id: "dlg_123".to_string(),
            delegation_type: "payment".to_string(),
            delegate_url: "https://pay.example.com".to_string(),
            required_fields: vec!["card_number".to_string()],
            optional_fields: None,
            callback_url: "https://example.com/callback".to_string(),
            expires_at: None,
            metadata: None,
        };

        let json = serde_json::to_string(&contract).unwrap();
        assert!(json.contains("\"type\":\"payment\""));
        assert!(json.contains("\"delegate_url\""));
    }
}
