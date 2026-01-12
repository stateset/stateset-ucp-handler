//! Node.js bindings for cryptographic operations

use crate::error::{crypto_error, json_error};
use napi::bindgen_prelude::*;
use napi::{Env, JsObject};
use napi_derive::napi;
use stateset_ucp_lib::crypto::{
    self, DetachedJws as RustDetachedJws, JwkPrivateKey,
    SigningAlgorithm as RustSigningAlgorithm, SigningKey as RustSigningKey,
    VerifyingKey as RustVerifyingKey,
};
use std::sync::Arc;

/// Signing algorithm enumeration
#[napi]
pub enum SigningAlgorithm {
    /// ECDSA with P-256 curve and SHA-256
    ES256,
    /// ECDSA with P-384 curve and SHA-384
    ES384,
}

impl From<SigningAlgorithm> for RustSigningAlgorithm {
    fn from(alg: SigningAlgorithm) -> Self {
        match alg {
            SigningAlgorithm::ES256 => RustSigningAlgorithm::ES256,
            SigningAlgorithm::ES384 => RustSigningAlgorithm::ES384,
        }
    }
}

impl From<RustSigningAlgorithm> for SigningAlgorithm {
    fn from(alg: RustSigningAlgorithm) -> Self {
        match alg {
            RustSigningAlgorithm::ES256 => SigningAlgorithm::ES256,
            RustSigningAlgorithm::ES384 => SigningAlgorithm::ES384,
        }
    }
}

/// Detached JWS signature result
#[napi(object)]
pub struct DetachedJws {
    /// Base64url encoded protected header
    pub protected: String,
    /// Base64url encoded signature
    pub signature: String,
}

impl From<RustDetachedJws> for DetachedJws {
    fn from(jws: RustDetachedJws) -> Self {
        DetachedJws {
            protected: jws.protected,
            signature: jws.signature,
        }
    }
}

impl From<DetachedJws> for RustDetachedJws {
    fn from(jws: DetachedJws) -> Self {
        RustDetachedJws {
            protected: jws.protected,
            signature: jws.signature,
        }
    }
}

/// Opaque handle to a signing key (private key)
#[napi]
pub struct SigningKey {
    inner: Arc<RustSigningKey>,
}

#[napi]
impl SigningKey {
    /// Returns the key ID
    #[napi(getter)]
    pub fn kid(&self) -> String {
        self.inner.kid.clone()
    }

    /// Returns the algorithm
    #[napi(getter)]
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.inner.algorithm.into()
    }
}

/// Opaque handle to a verifying key (public key)
#[napi]
pub struct VerifyingKey {
    inner: Arc<RustVerifyingKey>,
}

#[napi]
impl VerifyingKey {
    /// Returns the key ID
    #[napi(getter)]
    pub fn kid(&self) -> String {
        self.inner.kid.clone()
    }

    /// Returns the algorithm
    #[napi(getter)]
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.inner.algorithm.into()
    }
}

/// Generated key pair result
pub struct KeyPairResult {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

/// Crypto utilities for JWS signing and verification
#[napi]
pub struct Crypto;

#[napi]
impl Crypto {
    /// Canonicalizes a JSON value according to RFC 8785 (JCS)
    ///
    /// @param jsonValue - JSON string to canonicalize
    /// @returns Canonical byte representation
    #[napi]
    pub fn canonicalize(json_value: String) -> Result<Buffer> {
        let value: serde_json::Value = serde_json::from_str(&json_value).map_err(json_error)?;
        let canonical = crypto::canonicalize(&value).map_err(crypto_error)?;
        Ok(Buffer::from(canonical))
    }

    /// Creates a detached JWS signature over the given payload
    ///
    /// @param payload - The payload bytes to sign
    /// @param key - The signing key
    /// @returns Detached JWS object
    #[napi]
    pub fn sign_detached(payload: Buffer, key: &SigningKey) -> Result<DetachedJws> {
        let jws = crypto::sign_detached(&payload, &key.inner).map_err(crypto_error)?;
        Ok(jws.into())
    }

    /// Verifies a detached JWS signature
    ///
    /// @param jwsCompact - Compact JWS string (header..signature)
    /// @param payload - The payload bytes that were signed
    /// @param key - The verifying key
    /// @throws Error if verification fails
    #[napi]
    pub fn verify_detached(jws_compact: String, payload: Buffer, key: &VerifyingKey) -> Result<()> {
        let jws = RustDetachedJws::from_compact(&jws_compact).map_err(crypto_error)?;
        crypto::verify_detached(&jws, &payload, &key.inner).map_err(crypto_error)
    }

    /// Signs a JSON value with canonicalization
    ///
    /// @param jsonValue - JSON string to sign
    /// @param key - The signing key
    /// @returns Detached JWS object
    #[napi]
    pub fn sign_json(json_value: String, key: &SigningKey) -> Result<DetachedJws> {
        let value: serde_json::Value = serde_json::from_str(&json_value).map_err(json_error)?;
        let jws = crypto::sign_json(&value, &key.inner).map_err(crypto_error)?;
        Ok(jws.into())
    }

    /// Verifies a JWS signature against a JSON value
    ///
    /// @param jwsCompact - Compact JWS string (header..signature)
    /// @param jsonValue - JSON string that was signed
    /// @param key - The verifying key
    /// @throws Error if verification fails
    #[napi]
    pub fn verify_json(jws_compact: String, json_value: String, key: &VerifyingKey) -> Result<()> {
        let jws = RustDetachedJws::from_compact(&jws_compact).map_err(crypto_error)?;
        let value: serde_json::Value = serde_json::from_str(&json_value).map_err(json_error)?;
        crypto::verify_json(&jws, &value, &key.inner).map_err(crypto_error)
    }

    /// Loads a signing key from a JWK with private key component
    ///
    /// @param jwkJson - JSON string of JWK with 'd' (private key) component
    /// @returns SigningKey handle
    #[napi]
    pub fn load_signing_key_from_private(jwk_json: String) -> Result<SigningKey> {
        let jwk: JwkPrivateKey = serde_json::from_str(&jwk_json).map_err(json_error)?;
        let key = crypto::load_signing_key_from_private(&jwk).map_err(crypto_error)?;
        Ok(SigningKey {
            inner: Arc::new(key),
        })
    }

    /// Loads a verifying (public) key from a JWK
    ///
    /// @param jwkJson - JSON string of public JWK
    /// @returns VerifyingKey handle
    #[napi]
    pub fn load_verifying_key(jwk_json: String) -> Result<VerifyingKey> {
        let jwk: stateset_ucp_lib::models::JwkKey =
            serde_json::from_str(&jwk_json).map_err(json_error)?;
        let key = crypto::load_verifying_key(&jwk).map_err(crypto_error)?;
        Ok(VerifyingKey {
            inner: Arc::new(key),
        })
    }

    /// Generates a new signing key for the given algorithm
    ///
    /// @param algorithm - The signing algorithm (ES256 or ES384)
    /// @param kid - Key ID to assign to the generated key
    /// @returns SigningKey (the verifying key can be derived from it)
    #[napi]
    pub fn generate_signing_key(algorithm: SigningAlgorithm, kid: String) -> SigningKey {
        let (signing, _verifying) = crypto::generate_key_pair(algorithm.into(), kid);
        SigningKey {
            inner: Arc::new(signing),
        }
    }

    /// Generates a new key pair for signing and verification
    ///
    /// @param algorithm - The signing algorithm (ES256 or ES384)
    /// @param kid - Key ID to assign to the generated keys
    /// @returns Object with signingKey and verifyingKey properties
    #[napi(ts_return_type = "{ signingKey: SigningKey, verifyingKey: VerifyingKey }")]
    pub fn generate_key_pair(env: Env, algorithm: SigningAlgorithm, kid: String) -> Result<JsObject> {
        let (signing, verifying) = crypto::generate_key_pair(algorithm.into(), kid);

        let signing_key = SigningKey {
            inner: Arc::new(signing),
        };
        let verifying_key = VerifyingKey {
            inner: Arc::new(verifying),
        };

        let mut obj = env.create_object()?;
        obj.set("signingKey", signing_key)?;
        obj.set("verifyingKey", verifying_key)?;
        Ok(obj)
    }

    /// Exports a verifying key to JWK format
    ///
    /// @param key - The verifying key to export
    /// @returns JSON string of the public JWK
    #[napi]
    pub fn export_verifying_key_jwk(key: &VerifyingKey) -> Result<String> {
        let jwk = crypto::export_verifying_key_jwk(&key.inner);
        serde_json::to_string(&jwk).map_err(json_error)
    }

    /// Converts a DetachedJws to compact format (header..signature)
    ///
    /// @param jws - The DetachedJws object
    /// @returns Compact JWS string
    #[napi]
    pub fn jws_to_compact(jws: DetachedJws) -> String {
        let rust_jws: RustDetachedJws = jws.into();
        rust_jws.to_compact()
    }

    /// Parses a compact JWS string into a DetachedJws object
    ///
    /// @param compact - Compact JWS string (header..signature)
    /// @returns DetachedJws object
    #[napi]
    pub fn jws_from_compact(compact: String) -> Result<DetachedJws> {
        let jws = RustDetachedJws::from_compact(&compact).map_err(crypto_error)?;
        Ok(jws.into())
    }
}
