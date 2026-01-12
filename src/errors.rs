use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Conflict: {0}")]
    Conflict(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("External error: {0}")]
    External(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub body: ErrorBody,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    #[serde(rename = "type")]
    pub error_type: String,
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &str, message: &str, path: Option<String>) -> Self {
        Self {
            status,
            body: ErrorBody {
                error_type: "invalid_request".to_string(),
                code: code.to_string(),
                message: message.to_string(),
                path,
            },
        }
    }

    pub fn from_service(err: ServiceError) -> Self {
        match err {
            ServiceError::InvalidInput(message) => {
                Self::new(StatusCode::BAD_REQUEST, "invalid_request", &message, None)
            }
            ServiceError::NotFound(message) => {
                Self::new(StatusCode::NOT_FOUND, "not_found", &message, None)
            }
            ServiceError::Conflict(message) => {
                Self::new(StatusCode::CONFLICT, "conflict", &message, None)
            }
            ServiceError::InvalidState(message) => {
                Self::new(StatusCode::METHOD_NOT_ALLOWED, "invalid_state", &message, None)
            }
            ServiceError::External(message) => {
                Self::new(StatusCode::BAD_GATEWAY, "external_error", &message, None)
            }
            ServiceError::Internal(message) => {
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", &message, None)
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, axum::Json(self.body)).into_response()
    }
}
