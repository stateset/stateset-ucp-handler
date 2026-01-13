//! Error conversion utilities for Node.js bindings

use napi::Error as NapiError;
use stateset_ucp_lib::errors::ServiceError;

/// Converts a ServiceError to a napi::Error
pub fn to_napi_error(error: ServiceError) -> NapiError {
    NapiError::from_reason(error.to_string())
}

/// Converts a string error message to a napi::Error
pub fn to_napi_error_str(msg: impl Into<String>) -> NapiError {
    NapiError::from_reason(msg.into())
}

/// Converts a serde_json error to a napi::Error
pub fn json_error(error: serde_json::Error) -> NapiError {
    NapiError::from_reason(format!("JSON error: {}", error))
}

/// Converts a crypto error to a napi::Error
pub fn crypto_error(error: stateset_ucp_lib::crypto::CryptoError) -> NapiError {
    NapiError::from_reason(format!("Crypto error: {}", error))
}
