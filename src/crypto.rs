//! Cryptographic operations for UCP JWS signatures.
//!
//! Implements:
//! - ECDSA signing/verification (ES256, ES384)
//! - JWS Detached Content signatures (RFC 7797)
//! - JSON Canonicalization (RFC 8785)
//! - JWK key loading

// Public API functions for cryptographic operations - used by consumers of this crate
#![allow(dead_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use p384::ecdsa::{Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::str::FromStr;
use thiserror::Error;

use crate::models::JwkKey;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    #[error("Invalid signature format: {0}")]
    InvalidSignatureFormat(String),
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("Missing key component: {0}")]
    MissingKeyComponent(String),
    #[error("Base64 decode error: {0}")]
    Base64Error(String),
    #[error("JSON error: {0}")]
    JsonError(String),
    #[error("Key ID mismatch: expected {expected}, got {actual}")]
    KeyIdMismatch { expected: String, actual: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    ES256, // P-256 + SHA-256
    ES384, // P-384 + SHA-384
}

impl SigningAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            SigningAlgorithm::ES256 => "ES256",
            SigningAlgorithm::ES384 => "ES384",
        }
    }

    pub fn from_curve(crv: &str) -> Result<Self, CryptoError> {
        match crv {
            "P-256" => Ok(SigningAlgorithm::ES256),
            "P-384" => Ok(SigningAlgorithm::ES384),
            _ => Err(CryptoError::UnsupportedAlgorithm(format!("curve {}", crv))),
        }
    }
}

impl FromStr for SigningAlgorithm {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ES256" => Ok(SigningAlgorithm::ES256),
            "ES384" => Ok(SigningAlgorithm::ES384),
            _ => Err(CryptoError::UnsupportedAlgorithm(s.to_string())),
        }
    }
}

#[derive(Debug, Clone)]
enum SigningKeyInner {
    P256(P256SigningKey),
    P384(P384SigningKey),
}

#[derive(Debug, Clone)]
pub struct SigningKey {
    pub kid: String,
    pub algorithm: SigningAlgorithm,
    inner: SigningKeyInner,
}

#[derive(Debug, Clone)]
enum VerifyingKeyInner {
    P256(P256VerifyingKey),
    P384(P384VerifyingKey),
}

#[derive(Debug, Clone)]
pub struct VerifyingKey {
    pub kid: String,
    pub algorithm: SigningAlgorithm,
    inner: VerifyingKeyInner,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwsHeader {
    pub alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub b64: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct DetachedJws {
    pub protected: String,  // Base64url encoded header
    pub signature: String,  // Base64url encoded signature
}

impl DetachedJws {
    /// Converts to compact detached format: header..signature (empty payload)
    pub fn to_compact(&self) -> String {
        format!("{}..{}", self.protected, self.signature)
    }

    /// Parses from compact detached format
    pub fn from_compact(compact: &str) -> Result<Self, CryptoError> {
        let parts: Vec<&str> = compact.split('.').collect();
        if parts.len() != 3 {
            return Err(CryptoError::InvalidSignatureFormat(
                "Expected 3 parts separated by '.'".to_string(),
            ));
        }
        if !parts[1].is_empty() {
            return Err(CryptoError::InvalidSignatureFormat(
                "Detached JWS must have empty payload".to_string(),
            ));
        }
        Ok(DetachedJws {
            protected: parts[0].to_string(),
            signature: parts[2].to_string(),
        })
    }

    /// Extracts and parses the JWS header
    pub fn header(&self) -> Result<JwsHeader, CryptoError> {
        let header_bytes = URL_SAFE_NO_PAD
            .decode(&self.protected)
            .map_err(|e| CryptoError::Base64Error(e.to_string()))?;
        serde_json::from_slice(&header_bytes)
            .map_err(|e| CryptoError::JsonError(e.to_string()))
    }
}

// ============================================================================
// JSON Canonicalization (RFC 8785)
// ============================================================================

/// Canonicalizes a JSON value according to RFC 8785 (JCS).
///
/// Rules:
/// 1. Object keys are sorted lexicographically by UTF-16 code units
/// 2. No whitespace between tokens
/// 3. Numbers use shortest representation
/// 4. Strings use minimal escaping
pub fn canonicalize(value: &serde_json::Value) -> Result<Vec<u8>, CryptoError> {
    let canonical = canonicalize_value(value);
    Ok(canonical.into_bytes())
}

fn canonicalize_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => if *b { "true" } else { "false" }.to_string(),
        serde_json::Value::Number(n) => canonicalize_number(n),
        serde_json::Value::String(s) => canonicalize_string(s),
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonicalize_value).collect();
            format!("[{}]", items.join(","))
        }
        serde_json::Value::Object(obj) => {
            let mut keys = obj.keys().collect::<Vec<_>>();
            keys.sort_by(|a, b| compare_utf16(a, b));
            let pairs: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", canonicalize_string(k), canonicalize_value(&obj[*k])))
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
    }
}

fn canonicalize_number(n: &serde_json::Number) -> String {
    // RFC 8785: Use ES6 number serialization
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    if let Some(f) = n.as_f64() {
        // Handle special cases
        if f == 0.0 {
            return "0".to_string();
        }
        if f.is_infinite() || f.is_nan() {
            return "null".to_string(); // Not valid in JSON, but handle gracefully
        }
        let abs = f.abs();
        let use_exponent = !(1e-6..1e21).contains(&abs);
        let raw = n.to_string();
        if use_exponent {
            if raw.contains('e') || raw.contains('E') {
                return normalize_exponent(&raw);
            }
            return to_exponent(&raw);
        }
        if raw.contains('e') || raw.contains('E') {
            return expand_exponent(&raw);
        }
        return raw;
    }
    n.to_string()
}

fn canonicalize_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 2);
    result.push('"');
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\x08' => result.push_str("\\b"),
            '\x0c' => result.push_str("\\f"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c < '\x20' => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result.push('"');
    result
}

fn compare_utf16(a: &str, b: &str) -> Ordering {
    let mut a_units = a.encode_utf16();
    let mut b_units = b.encode_utf16();
    loop {
        match (a_units.next(), b_units.next()) {
            (Some(left), Some(right)) => {
                if left != right {
                    return left.cmp(&right);
                }
            }
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (None, None) => return Ordering::Equal,
        }
    }
}

fn normalize_exponent(raw: &str) -> String {
    let Some(pos) = raw.find(['e', 'E']) else {
        return raw.to_string();
    };
    let (mantissa, exp_part) = raw.split_at(pos);
    let exp_part = &exp_part[1..];
    let (sign, digits) = if let Some(rest) = exp_part.strip_prefix('-') {
        ('-', rest)
    } else if let Some(rest) = exp_part.strip_prefix('+') {
        ('+', rest)
    } else {
        ('+', exp_part)
    };
    let digits = digits.trim_start_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    format!("{mantissa}e{sign}{digits}")
}

fn expand_exponent(raw: &str) -> String {
    let parsed = parse_number(raw);
    let Some((negative, digits, decimal_pos, exponent)) = parsed else {
        return raw.to_string();
    };
    let decimal_pos = decimal_pos + exponent;
    let sign = if negative { "-" } else { "" };
    let mut value = if decimal_pos <= 0 {
        let zeros = "0".repeat((-decimal_pos) as usize);
        format!("{sign}0.{zeros}{digits}")
    } else if decimal_pos as usize >= digits.len() {
        let zeros = "0".repeat(decimal_pos as usize - digits.len());
        format!("{sign}{digits}{zeros}")
    } else {
        let pos = decimal_pos as usize;
        let (left, right) = digits.split_at(pos);
        format!("{sign}{left}.{right}")
    };
    if let Some(dot_pos) = value.find('.') {
        while value.ends_with('0') {
            value.pop();
        }
        if value.ends_with('.') && dot_pos == value.len() - 1 {
            value.pop();
        }
    }
    value
}

fn to_exponent(raw: &str) -> String {
    let parsed = parse_number(raw);
    let Some((negative, mut digits, mut decimal_pos, exponent)) = parsed else {
        return raw.to_string();
    };
    decimal_pos += exponent;
    while digits.starts_with('0') && digits.len() > 1 {
        digits.remove(0);
        decimal_pos -= 1;
    }
    while digits.ends_with('0') && digits.len() > 1 {
        digits.pop();
    }
    if digits.is_empty() {
        return "0".to_string();
    }
    let exp_value = decimal_pos - 1;
    let sign = if negative { "-" } else { "" };
    let (exp_sign, exp_digits) = if exp_value < 0 {
        ('-', (-exp_value).to_string())
    } else {
        ('+', exp_value.to_string())
    };
    if digits.len() == 1 {
        format!("{sign}{digits}e{exp_sign}{exp_digits}")
    } else {
        let (first, rest) = digits.split_at(1);
        format!("{sign}{first}.{rest}e{exp_sign}{exp_digits}")
    }
}

fn parse_number(raw: &str) -> Option<(bool, String, i32, i32)> {
    let (base, exponent) = match raw.find(['e', 'E']) {
        Some(pos) => {
            let (left, right) = raw.split_at(pos);
            let exponent: i32 = right[1..].parse().ok()?;
            (left, exponent)
        }
        None => (raw, 0),
    };
    let mut base = base;
    let mut negative = false;
    if let Some(rest) = base.strip_prefix('-') {
        negative = true;
        base = rest;
    } else if let Some(rest) = base.strip_prefix('+') {
        base = rest;
    }
    let (digits, decimal_pos) = if let Some(dot_pos) = base.find('.') {
        let mut digits = String::with_capacity(base.len() - 1);
        digits.push_str(&base[..dot_pos]);
        digits.push_str(&base[dot_pos + 1..]);
        (digits, dot_pos as i32)
    } else {
        (base.to_string(), base.len() as i32)
    };
    if digits.is_empty() {
        return None;
    }
    Some((negative, digits, decimal_pos, exponent))
}

// ============================================================================
// Key Loading
// ============================================================================

/// Loads a signing key from a JWK (requires private key component 'd')
pub fn load_signing_key(jwk: &JwkKey) -> Result<SigningKey, CryptoError> {
    if jwk.kty != "EC" {
        return Err(CryptoError::InvalidKeyFormat(format!(
            "Expected EC key type, got {}",
            jwk.kty
        )));
    }

    let crv = jwk.crv.as_ref().ok_or_else(|| {
        CryptoError::MissingKeyComponent("crv (curve)".to_string())
    })?;

    let _algorithm = SigningAlgorithm::from_curve(crv)?;

    // For signing, we need the private key component 'd'
    // If not present in JwkKey, we need to extend the model or use a different approach
    // For now, we'll generate keys for testing or load from extended config

    // This is a placeholder - in production, you'd load the actual private key
    // The JwkKey struct needs to be extended to include 'd' for private keys
    Err(CryptoError::MissingKeyComponent(
        "Private key loading requires extended JWK with 'd' component".to_string(),
    ))
}

/// Loads a verifying (public) key from a JWK
pub fn load_verifying_key(jwk: &JwkKey) -> Result<VerifyingKey, CryptoError> {
    if jwk.kty != "EC" {
        return Err(CryptoError::InvalidKeyFormat(format!(
            "Expected EC key type, got {}",
            jwk.kty
        )));
    }

    let crv = jwk.crv.as_ref().ok_or_else(|| {
        CryptoError::MissingKeyComponent("crv (curve)".to_string())
    })?;

    let x = jwk.x.as_ref().ok_or_else(|| {
        CryptoError::MissingKeyComponent("x coordinate".to_string())
    })?;

    let y = jwk.y.as_ref().ok_or_else(|| {
        CryptoError::MissingKeyComponent("y coordinate".to_string())
    })?;

    let algorithm = SigningAlgorithm::from_curve(crv)?;

    let x_bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|e| CryptoError::Base64Error(format!("x: {}", e)))?;

    let y_bytes = URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|e| CryptoError::Base64Error(format!("y: {}", e)))?;

    match algorithm {
        SigningAlgorithm::ES256 => {
            let mut point = vec![0x04]; // Uncompressed point format
            point.extend_from_slice(&x_bytes);
            point.extend_from_slice(&y_bytes);

            let verifying_key = P256VerifyingKey::from_sec1_bytes(&point)
                .map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))?;

            Ok(VerifyingKey {
                kid: jwk.kid.clone(),
                algorithm,
                inner: VerifyingKeyInner::P256(verifying_key),
            })
        }
        SigningAlgorithm::ES384 => {
            let mut point = vec![0x04];
            point.extend_from_slice(&x_bytes);
            point.extend_from_slice(&y_bytes);

            let verifying_key = P384VerifyingKey::from_sec1_bytes(&point)
                .map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))?;

            Ok(VerifyingKey {
                kid: jwk.kid.clone(),
                algorithm,
                inner: VerifyingKeyInner::P384(verifying_key),
            })
        }
    }
}

/// Extended JWK structure that includes the private key component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkPrivateKey {
    pub kid: String,
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    pub d: String, // Private key component
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
}

/// Loads a signing key from an extended JWK with private key
pub fn load_signing_key_from_private(jwk: &JwkPrivateKey) -> Result<SigningKey, CryptoError> {
    if jwk.kty != "EC" {
        return Err(CryptoError::InvalidKeyFormat(format!(
            "Expected EC key type, got {}",
            jwk.kty
        )));
    }

    let algorithm = SigningAlgorithm::from_curve(&jwk.crv)?;

    let d_bytes = URL_SAFE_NO_PAD
        .decode(&jwk.d)
        .map_err(|e| CryptoError::Base64Error(format!("d: {}", e)))?;

    match algorithm {
        SigningAlgorithm::ES256 => {
            let signing_key = P256SigningKey::from_bytes(d_bytes.as_slice().into())
                .map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))?;

            Ok(SigningKey {
                kid: jwk.kid.clone(),
                algorithm,
                inner: SigningKeyInner::P256(signing_key),
            })
        }
        SigningAlgorithm::ES384 => {
            let signing_key = P384SigningKey::from_bytes(d_bytes.as_slice().into())
                .map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))?;

            Ok(SigningKey {
                kid: jwk.kid.clone(),
                algorithm,
                inner: SigningKeyInner::P384(signing_key),
            })
        }
    }
}

/// Generates a new key pair for testing
pub fn generate_key_pair(algorithm: SigningAlgorithm, kid: String) -> (SigningKey, VerifyingKey) {
    match algorithm {
        SigningAlgorithm::ES256 => {
            let signing_key = P256SigningKey::random(&mut rand_core::OsRng);
            let verifying_key = *signing_key.verifying_key();

            (
                SigningKey {
                    kid: kid.clone(),
                    algorithm,
                    inner: SigningKeyInner::P256(signing_key),
                },
                VerifyingKey {
                    kid,
                    algorithm,
                    inner: VerifyingKeyInner::P256(verifying_key),
                },
            )
        }
        SigningAlgorithm::ES384 => {
            let signing_key = P384SigningKey::random(&mut rand_core::OsRng);
            let verifying_key = *signing_key.verifying_key();

            (
                SigningKey {
                    kid: kid.clone(),
                    algorithm,
                    inner: SigningKeyInner::P384(signing_key),
                },
                VerifyingKey {
                    kid,
                    algorithm,
                    inner: VerifyingKeyInner::P384(verifying_key),
                },
            )
        }
    }
}

// ============================================================================
// JWS Signing and Verification
// ============================================================================

/// Creates a detached JWS signature over the given payload.
///
/// The signature is created using RFC 7797 (Unencoded Payload Option),
/// with the payload NOT included in the compact serialization.
pub fn sign_detached(payload: &[u8], key: &SigningKey) -> Result<DetachedJws, CryptoError> {
    // Create JWS protected header
    let header = JwsHeader {
        alg: key.algorithm.as_str().to_string(),
        kid: Some(key.kid.clone()),
        typ: Some("JWT".to_string()),
        b64: Some(false), // RFC 7797: unencoded payload
        crit: Some(vec!["b64".to_string()]),
    };

    let header_json = serde_json::to_vec(&header)
        .map_err(|e| CryptoError::JsonError(e.to_string()))?;

    let protected = URL_SAFE_NO_PAD.encode(&header_json);

    // RFC 7797: For b64=false, signing input is: BASE64URL(header) || '.' || payload
    let mut signing_input = Vec::new();
    signing_input.extend_from_slice(protected.as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(payload);

    // Sign based on algorithm
    let signature = match &key.inner {
        SigningKeyInner::P256(sk) => {
            // Hash with SHA-256 and sign
            let sig: P256Signature = sk.sign(&signing_input);
            sig.to_bytes().to_vec()
        }
        SigningKeyInner::P384(sk) => {
            let sig: P384Signature = sk.sign(&signing_input);
            sig.to_bytes().to_vec()
        }
    };

    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

    Ok(DetachedJws {
        protected,
        signature: signature_b64,
    })
}

/// Creates a detached JWS signature over the given payload using base64url encoding.
///
/// This follows RFC 7515 Appendix F for detached payloads.
pub fn sign_detached_b64(payload: &[u8], key: &SigningKey) -> Result<DetachedJws, CryptoError> {
    let header = JwsHeader {
        alg: key.algorithm.as_str().to_string(),
        kid: Some(key.kid.clone()),
        typ: Some("JWT".to_string()),
        b64: None,
        crit: None,
    };

    let header_json = serde_json::to_vec(&header)
        .map_err(|e| CryptoError::JsonError(e.to_string()))?;

    let protected = URL_SAFE_NO_PAD.encode(&header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);

    let mut signing_input = Vec::new();
    signing_input.extend_from_slice(protected.as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(payload_b64.as_bytes());

    let signature = match &key.inner {
        SigningKeyInner::P256(sk) => {
            let sig: P256Signature = sk.sign(&signing_input);
            sig.to_bytes().to_vec()
        }
        SigningKeyInner::P384(sk) => {
            let sig: P384Signature = sk.sign(&signing_input);
            sig.to_bytes().to_vec()
        }
    };

    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

    Ok(DetachedJws {
        protected,
        signature: signature_b64,
    })
}

/// Verifies a detached JWS signature against the given payload.
pub fn verify_detached(
    jws: &DetachedJws,
    payload: &[u8],
    key: &VerifyingKey,
) -> Result<(), CryptoError> {
    // Parse and validate header
    let header = jws.header()?;
    if header.b64 != Some(false)
        || !header
            .crit
            .as_ref()
            .map(|crit| crit.iter().any(|entry| entry == "b64"))
            .unwrap_or(false)
    {
        return Err(CryptoError::InvalidSignatureFormat(
            "Detached JWS must use b64=false with crit header".to_string(),
        ));
    }

    // Verify algorithm matches
    let alg = header.alg.parse::<SigningAlgorithm>()?;
    if alg != key.algorithm {
        return Err(CryptoError::UnsupportedAlgorithm(format!(
            "Key uses {:?} but JWS uses {}",
            key.algorithm, header.alg
        )));
    }

    // Optionally verify kid
    if let Some(ref kid) = header.kid {
        if kid != &key.kid {
            return Err(CryptoError::KeyIdMismatch {
                expected: key.kid.clone(),
                actual: kid.clone(),
            });
        }
    }

    // Reconstruct signing input
    let mut signing_input = Vec::new();
    signing_input.extend_from_slice(jws.protected.as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(payload);

    // Decode signature
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&jws.signature)
        .map_err(|e| CryptoError::Base64Error(e.to_string()))?;

    // Verify based on algorithm
    match &key.inner {
        VerifyingKeyInner::P256(vk) => {
            let sig = P256Signature::from_bytes(sig_bytes.as_slice().into())
                .map_err(|e| CryptoError::InvalidSignatureFormat(e.to_string()))?;

            vk.verify(&signing_input, &sig)
                .map_err(|_| CryptoError::VerificationFailed)?;
        }
        VerifyingKeyInner::P384(vk) => {
            let sig = P384Signature::from_bytes(sig_bytes.as_slice().into())
                .map_err(|e| CryptoError::InvalidSignatureFormat(e.to_string()))?;

            vk.verify(&signing_input, &sig)
                .map_err(|_| CryptoError::VerificationFailed)?;
        }
    }

    Ok(())
}

/// Verifies a detached JWS signature using base64url-encoded payload.
pub fn verify_detached_b64(
    jws: &DetachedJws,
    payload: &[u8],
    key: &VerifyingKey,
) -> Result<(), CryptoError> {
    let header = jws.header()?;
    if header.b64 == Some(false) {
        return Err(CryptoError::InvalidSignatureFormat(
            "Detached JWS uses unencoded payload".to_string(),
        ));
    }

    let alg = header.alg.parse::<SigningAlgorithm>()?;
    if alg != key.algorithm {
        return Err(CryptoError::UnsupportedAlgorithm(format!(
            "Key uses {:?} but JWS uses {}",
            key.algorithm, header.alg
        )));
    }

    if let Some(ref kid) = header.kid {
        if kid != &key.kid {
            return Err(CryptoError::KeyIdMismatch {
                expected: key.kid.clone(),
                actual: kid.clone(),
            });
        }
    }

    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
    let mut signing_input = Vec::new();
    signing_input.extend_from_slice(jws.protected.as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(payload_b64.as_bytes());

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&jws.signature)
        .map_err(|e| CryptoError::Base64Error(e.to_string()))?;

    match &key.inner {
        VerifyingKeyInner::P256(vk) => {
            let sig = P256Signature::from_bytes(sig_bytes.as_slice().into())
                .map_err(|e| CryptoError::InvalidSignatureFormat(e.to_string()))?;

            vk.verify(&signing_input, &sig)
                .map_err(|_| CryptoError::VerificationFailed)?;
        }
        VerifyingKeyInner::P384(vk) => {
            let sig = P384Signature::from_bytes(sig_bytes.as_slice().into())
                .map_err(|e| CryptoError::InvalidSignatureFormat(e.to_string()))?;

            vk.verify(&signing_input, &sig)
                .map_err(|_| CryptoError::VerificationFailed)?;
        }
    }

    Ok(())
}

/// Signs a JSON value with canonicalization.
///
/// This is the primary function for AP2 and webhook signatures:
/// 1. Canonicalize the JSON (RFC 8785)
/// 2. Create detached JWS signature
pub fn sign_json(value: &serde_json::Value, key: &SigningKey) -> Result<DetachedJws, CryptoError> {
    let canonical = canonicalize(value)?;
    sign_detached(&canonical, key)
}

/// Verifies a JWS signature against a JSON value.
pub fn verify_json(
    jws: &DetachedJws,
    value: &serde_json::Value,
    key: &VerifyingKey,
) -> Result<(), CryptoError> {
    let canonical = canonicalize(value)?;
    verify_detached(jws, &canonical, key)
}

/// Exports a signing key (including private component) to JWK format
pub fn export_signing_key_jwk(key: &SigningKey) -> JwkPrivateKey {
    match &key.inner {
        SigningKeyInner::P256(sk) => {
            let verifying_key = P256VerifyingKey::from(sk);
            let point = verifying_key.to_encoded_point(false);
            let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
            let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
            let d = URL_SAFE_NO_PAD.encode(sk.to_bytes());

            JwkPrivateKey {
                kid: key.kid.clone(),
                kty: "EC".to_string(),
                crv: "P-256".to_string(),
                x,
                y,
                d,
                use_: Some("sig".to_string()),
                alg: Some("ES256".to_string()),
            }
        }
        SigningKeyInner::P384(sk) => {
            let verifying_key = P384VerifyingKey::from(sk);
            let point = verifying_key.to_encoded_point(false);
            let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
            let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
            let d = URL_SAFE_NO_PAD.encode(sk.to_bytes());

            JwkPrivateKey {
                kid: key.kid.clone(),
                kty: "EC".to_string(),
                crv: "P-384".to_string(),
                x,
                y,
                d,
                use_: Some("sig".to_string()),
                alg: Some("ES384".to_string()),
            }
        }
    }
}

/// Exports a verifying key to JWK format
pub fn export_verifying_key_jwk(key: &VerifyingKey) -> JwkKey {
    match &key.inner {
        VerifyingKeyInner::P256(vk) => {
            let point = vk.to_encoded_point(false);
            let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
            let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

            JwkKey {
                kid: key.kid.clone(),
                kty: "EC".to_string(),
                crv: Some("P-256".to_string()),
                x: Some(x),
                y: Some(y),
                n: None,
                e: None,
                use_: Some("sig".to_string()),
                alg: Some("ES256".to_string()),
            }
        }
        VerifyingKeyInner::P384(vk) => {
            let point = vk.to_encoded_point(false);
            let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
            let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

            JwkKey {
                kid: key.kid.clone(),
                kty: "EC".to_string(),
                crv: Some("P-384".to_string()),
                x: Some(x),
                y: Some(y),
                n: None,
                e: None,
                use_: Some("sig".to_string()),
                alg: Some("ES384".to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_simple() {
        let value = serde_json::json!({
            "b": 2,
            "a": 1
        });
        let canonical = canonicalize(&value).unwrap();
        assert_eq!(String::from_utf8(canonical).unwrap(), r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn test_canonicalize_nested() {
        let value = serde_json::json!({
            "z": {"b": 2, "a": 1},
            "a": [3, 1, 2]
        });
        let canonical = canonicalize(&value).unwrap();
        assert_eq!(
            String::from_utf8(canonical).unwrap(),
            r#"{"a":[3,1,2],"z":{"a":1,"b":2}}"#
        );
    }

    #[test]
    fn test_canonicalize_number_formatting() {
        let value = serde_json::json!({
            "small": 1e-7,
            "edge": 1e-6,
            "big": 1e21
        });
        let canonical = canonicalize(&value).unwrap();
        assert_eq!(
            String::from_utf8(canonical).unwrap(),
            r#"{"big":1e+21,"edge":0.000001,"small":1e-7}"#
        );
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let (signing_key, verifying_key) = generate_key_pair(SigningAlgorithm::ES256, "test-key".to_string());

        let payload = b"hello world";
        let jws = sign_detached(payload, &signing_key).unwrap();

        // Verify should succeed
        verify_detached(&jws, payload, &verifying_key).unwrap();

        // Verify with wrong payload should fail
        let wrong_payload = b"wrong data";
        assert!(verify_detached(&jws, wrong_payload, &verifying_key).is_err());
    }

    #[test]
    fn test_sign_verify_json() {
        let (signing_key, verifying_key) = generate_key_pair(SigningAlgorithm::ES384, "test-key-384".to_string());

        let value = serde_json::json!({
            "checkout_id": "chk_123",
            "total": 1000,
            "currency": "USD"
        });

        let jws = sign_json(&value, &signing_key).unwrap();
        verify_json(&jws, &value, &verifying_key).unwrap();
    }

    #[test]
    fn test_sign_verify_b64_roundtrip() {
        let (signing_key, verifying_key) =
            generate_key_pair(SigningAlgorithm::ES256, "test-key-b64".to_string());

        let payload = br#"{"hello":"world"}"#;
        let jws = sign_detached_b64(payload, &signing_key).unwrap();
        verify_detached_b64(&jws, payload, &verifying_key).unwrap();
    }

    #[test]
    fn test_compact_format() {
        let (signing_key, _) = generate_key_pair(SigningAlgorithm::ES256, "test".to_string());

        let jws = sign_detached(b"test", &signing_key).unwrap();
        let compact = jws.to_compact();

        // Should have format: header..signature
        let parts: Vec<&str> = compact.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(!parts[0].is_empty());
        assert!(parts[1].is_empty()); // Empty payload for detached
        assert!(!parts[2].is_empty());

        // Should parse back
        let parsed = DetachedJws::from_compact(&compact).unwrap();
        assert_eq!(parsed.protected, jws.protected);
        assert_eq!(parsed.signature, jws.signature);
    }

    #[test]
    fn test_export_verifying_key() {
        let (_, verifying_key) = generate_key_pair(SigningAlgorithm::ES256, "export-test".to_string());
        let jwk = export_verifying_key_jwk(&verifying_key);

        assert_eq!(jwk.kid, "export-test");
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv.as_deref(), Some("P-256"));
        assert!(jwk.x.is_some());
        assert!(jwk.y.is_some());
    }
}
