use magnus::{
    exception, function, method, prelude::*, typed_data::Obj, Error, RArray, RHash, Ruby, Value,
};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use stateset_ucp_lib::catalog::ProductCatalog;
use stateset_ucp_lib::crypto::{
    self, DetachedJws as RustDetachedJws, JwkPrivateKey, SigningAlgorithm,
    SigningKey as RustSigningKey, VerifyingKey as RustVerifyingKey,
};
use stateset_ucp_lib::events::{Event, EventSender};
use stateset_ucp_lib::models::{
    CheckoutCompleteRequest, CheckoutCreateRequest, CheckoutUpdateRequest, JwkKey,
};
use stateset_ucp_lib::service::CheckoutService as RustCheckoutService;
use stateset_ucp_lib::store::CheckoutStore;
use std::sync::Arc;
use tokio::sync::mpsc;

#[magnus::wrap(class = "StatesetUcp::CheckoutService")]
struct CheckoutService {
    runtime: tokio::runtime::Runtime,
    inner: RustCheckoutService,
}

#[magnus::wrap(class = "StatesetUcp::SigningKey")]
struct SigningKey {
    inner: Arc<RustSigningKey>,
}

#[magnus::wrap(class = "StatesetUcp::VerifyingKey")]
struct VerifyingKey {
    inner: Arc<RustVerifyingKey>,
}

#[derive(Deserialize)]
struct CheckoutServiceConfig {
    ucp_version: String,
    service_version: String,
    base_url: String,
    session_ttl_seconds: u64,
    tax_bps: i64,
    identity_linking_enabled: Option<bool>,
    buyer_consent_enabled: Option<bool>,
    ap2_enabled: Option<bool>,
    ap2_merchant_authorization: Option<String>,
}

fn arg_error(message: impl std::fmt::Display) -> Error {
    Error::new(exception::arg_error(), message.to_string())
}

fn runtime_error(message: impl std::fmt::Display) -> Error {
    Error::new(exception::runtime_error(), message.to_string())
}

fn parse_algorithm(algorithm: &str) -> Result<SigningAlgorithm, Error> {
    SigningAlgorithm::from_str(algorithm).map_err(arg_error)
}

fn hash_get_value(ruby: &Ruby, hash: RHash, key: &str) -> Option<Value> {
    let symbol = ruby.to_symbol(key);
    hash.get(symbol).or_else(|| hash.get(key))
}

fn require_string(ruby: &Ruby, hash: RHash, key: &str) -> Result<String, Error> {
    let value = hash_get_value(ruby, hash, key)
        .ok_or_else(|| arg_error(format!("missing {key}")))?;
    value
        .try_convert::<String>()
        .map_err(|_| arg_error(format!("{key} must be a string")))
}

fn require_i64(ruby: &Ruby, hash: RHash, key: &str) -> Result<i64, Error> {
    let value = hash_get_value(ruby, hash, key)
        .ok_or_else(|| arg_error(format!("missing {key}")))?;
    value
        .try_convert::<i64>()
        .map_err(|_| arg_error(format!("{key} must be an integer")))
}

fn optional_bool(ruby: &Ruby, hash: RHash, key: &str) -> Result<Option<bool>, Error> {
    match hash_get_value(ruby, hash, key) {
        Some(value) => value
            .try_convert::<bool>()
            .map(Some)
            .map_err(|_| arg_error(format!("{key} must be true or false"))),
        None => Ok(None),
    }
}

fn optional_string(ruby: &Ruby, hash: RHash, key: &str) -> Result<Option<String>, Error> {
    match hash_get_value(ruby, hash, key) {
        Some(value) => value
            .try_convert::<String>()
            .map(Some)
            .map_err(|_| arg_error(format!("{key} must be a string"))),
        None => Ok(None),
    }
}

fn parse_config(ruby: &Ruby, value: Value) -> Result<CheckoutServiceConfig, Error> {
    if let Ok(config_json) = value.try_convert::<String>() {
        return serde_json::from_str(&config_json).map_err(arg_error);
    }

    if let Ok(hash) = value.try_convert::<RHash>() {
        let session_ttl_seconds = require_i64(ruby, hash, "session_ttl_seconds")?;
        if session_ttl_seconds < 0 {
            return Err(arg_error("session_ttl_seconds must be >= 0"));
        }

        return Ok(CheckoutServiceConfig {
            ucp_version: require_string(ruby, hash, "ucp_version")?,
            service_version: require_string(ruby, hash, "service_version")?,
            base_url: require_string(ruby, hash, "base_url")?,
            session_ttl_seconds: session_ttl_seconds as u64,
            tax_bps: require_i64(ruby, hash, "tax_bps")?,
            identity_linking_enabled: optional_bool(ruby, hash, "identity_linking_enabled")?,
            buyer_consent_enabled: optional_bool(ruby, hash, "buyer_consent_enabled")?,
            ap2_enabled: optional_bool(ruby, hash, "ap2_enabled")?,
            ap2_merchant_authorization: optional_string(ruby, hash, "ap2_merchant_authorization")?,
        });
    }

    Err(arg_error("config must be a Hash or JSON string"))
}

fn checkout_service_new(ruby: &Ruby, config: Value) -> Result<Obj<CheckoutService>, Error> {
    let config = parse_config(ruby, config)?;
    let runtime = tokio::runtime::Runtime::new().map_err(runtime_error)?;
    let store = CheckoutStore::new();
    let catalog = ProductCatalog::new();

    let (tx, mut rx) = mpsc::channel::<Event>(100);
    runtime.spawn(async move {
        while let Some(_event) = rx.recv().await {}
    });
    let event_sender = EventSender::new(tx);

    let service = RustCheckoutService::new(
        store,
        catalog,
        None,
        event_sender,
        config.ucp_version,
        config.service_version,
        config.base_url,
        config.session_ttl_seconds,
        config.tax_bps,
        None,
        config.identity_linking_enabled.unwrap_or(false),
        config.buyer_consent_enabled.unwrap_or(false),
        false,
        false,
        false,
        config.ap2_enabled.unwrap_or(false),
        config.ap2_merchant_authorization,
        None,
        None,
    );

    Ok(ruby.obj_wrap(CheckoutService {
        runtime,
        inner: service,
    }))
}

impl CheckoutService {
    fn create_checkout(&self, request_json: String) -> Result<String, Error> {
        let request: CheckoutCreateRequest = serde_json::from_str(&request_json).map_err(arg_error)?;
        let response = self
            .runtime
            .block_on(self.inner.create_checkout(request))
            .map_err(runtime_error)?;
        serde_json::to_string(&response).map_err(arg_error)
    }

    fn get_checkout(&self, checkout_id: String) -> Result<String, Error> {
        let response = self
            .runtime
            .block_on(self.inner.get_checkout(&checkout_id))
            .map_err(runtime_error)?;
        serde_json::to_string(&response).map_err(arg_error)
    }

    fn update_checkout(&self, checkout_id: String, request_json: String) -> Result<String, Error> {
        let request: CheckoutUpdateRequest = serde_json::from_str(&request_json).map_err(arg_error)?;
        let response = self
            .runtime
            .block_on(self.inner.update_checkout(&checkout_id, request))
            .map_err(runtime_error)?;
        serde_json::to_string(&response).map_err(arg_error)
    }

    fn complete_checkout(
        &self,
        checkout_id: String,
        request_json: String,
    ) -> Result<String, Error> {
        let request: CheckoutCompleteRequest =
            serde_json::from_str(&request_json).map_err(arg_error)?;
        let response = self
            .runtime
            .block_on(self.inner.complete_checkout(&checkout_id, request))
            .map_err(runtime_error)?;
        serde_json::to_string(&response).map_err(arg_error)
    }

    fn cancel_checkout(&self, checkout_id: String) -> Result<String, Error> {
        let response = self
            .runtime
            .block_on(self.inner.cancel_checkout(&checkout_id))
            .map_err(runtime_error)?;
        serde_json::to_string(&response).map_err(arg_error)
    }

    fn discovery_document(&self) -> Result<String, Error> {
        let document = self.inner.discovery_document();
        serde_json::to_string(&document).map_err(arg_error)
    }
}

impl SigningKey {
    fn kid(&self) -> String {
        self.inner.kid.clone()
    }

    fn algorithm(&self) -> String {
        self.inner.algorithm.as_str().to_string()
    }
}

impl VerifyingKey {
    fn kid(&self) -> String {
        self.inner.kid.clone()
    }

    fn algorithm(&self) -> String {
        self.inner.algorithm.as_str().to_string()
    }
}

fn crypto_canonicalize(json_value: String) -> Result<String, Error> {
    let value: JsonValue = serde_json::from_str(&json_value).map_err(arg_error)?;
    let bytes = crypto::canonicalize(&value).map_err(runtime_error)?;
    String::from_utf8(bytes).map_err(runtime_error)
}

fn crypto_sign_detached(payload: String, key: Obj<SigningKey>) -> Result<String, Error> {
    let jws = crypto::sign_detached(payload.as_bytes(), &key.inner).map_err(runtime_error)?;
    Ok(jws.to_compact())
}

fn crypto_verify_detached(
    jws_compact: String,
    payload: String,
    key: Obj<VerifyingKey>,
) -> Result<(), Error> {
    let jws = RustDetachedJws::from_compact(&jws_compact).map_err(runtime_error)?;
    crypto::verify_detached(&jws, payload.as_bytes(), &key.inner).map_err(runtime_error)
}

fn crypto_sign_json(json_value: String, key: Obj<SigningKey>) -> Result<String, Error> {
    let value: JsonValue = serde_json::from_str(&json_value).map_err(arg_error)?;
    let jws = crypto::sign_json(&value, &key.inner).map_err(runtime_error)?;
    Ok(jws.to_compact())
}

fn crypto_verify_json(
    jws_compact: String,
    json_value: String,
    key: Obj<VerifyingKey>,
) -> Result<(), Error> {
    let jws = RustDetachedJws::from_compact(&jws_compact).map_err(runtime_error)?;
    let value: JsonValue = serde_json::from_str(&json_value).map_err(arg_error)?;
    crypto::verify_json(&jws, &value, &key.inner).map_err(runtime_error)
}

fn crypto_load_signing_key_from_private(
    ruby: &Ruby,
    jwk_json: String,
) -> Result<Obj<SigningKey>, Error> {
    let jwk: JwkPrivateKey = serde_json::from_str(&jwk_json).map_err(arg_error)?;
    let key = crypto::load_signing_key_from_private(&jwk).map_err(runtime_error)?;
    Ok(ruby.obj_wrap(SigningKey {
        inner: Arc::new(key),
    }))
}

fn crypto_load_verifying_key(ruby: &Ruby, jwk_json: String) -> Result<Obj<VerifyingKey>, Error> {
    let jwk: JwkKey = serde_json::from_str(&jwk_json).map_err(arg_error)?;
    let key = crypto::load_verifying_key(&jwk).map_err(runtime_error)?;
    Ok(ruby.obj_wrap(VerifyingKey {
        inner: Arc::new(key),
    }))
}

fn crypto_generate_key_pair(
    ruby: &Ruby,
    algorithm: String,
    kid: String,
) -> Result<RArray, Error> {
    let algorithm = parse_algorithm(&algorithm)?;
    let (signing, verifying) = crypto::generate_key_pair(algorithm, kid);

    let signing_key = ruby.obj_wrap(SigningKey {
        inner: Arc::new(signing),
    });
    let verifying_key = ruby.obj_wrap(VerifyingKey {
        inner: Arc::new(verifying),
    });

    let array = ruby.ary_new();
    array.push(signing_key)?;
    array.push(verifying_key)?;
    Ok(array)
}

fn crypto_export_verifying_key_jwk(key: Obj<VerifyingKey>) -> Result<String, Error> {
    let jwk = crypto::export_verifying_key_jwk(&key.inner);
    serde_json::to_string(&jwk).map_err(arg_error)
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.define_module("StatesetUcp")?;

    let checkout_class = module.define_class("CheckoutService", ruby.class_object())?;
    checkout_class.define_singleton_method("new", function!(checkout_service_new, 1))?;
    checkout_class.define_method("create_checkout", method!(CheckoutService::create_checkout, 1))?;
    checkout_class.define_method("get_checkout", method!(CheckoutService::get_checkout, 1))?;
    checkout_class.define_method("update_checkout", method!(CheckoutService::update_checkout, 2))?;
    checkout_class.define_method("complete_checkout", method!(CheckoutService::complete_checkout, 2))?;
    checkout_class.define_method("cancel_checkout", method!(CheckoutService::cancel_checkout, 1))?;
    checkout_class.define_method("discovery_document", method!(CheckoutService::discovery_document, 0))?;

    let signing_key_class = module.define_class("SigningKey", ruby.class_object())?;
    signing_key_class.define_method("kid", method!(SigningKey::kid, 0))?;
    signing_key_class.define_method("algorithm", method!(SigningKey::algorithm, 0))?;

    let verifying_key_class = module.define_class("VerifyingKey", ruby.class_object())?;
    verifying_key_class.define_method("kid", method!(VerifyingKey::kid, 0))?;
    verifying_key_class.define_method("algorithm", method!(VerifyingKey::algorithm, 0))?;

    let crypto_module = module.define_module("Crypto")?;
    crypto_module.define_singleton_method("canonicalize", function!(crypto_canonicalize, 1))?;
    crypto_module.define_singleton_method("sign_detached", function!(crypto_sign_detached, 2))?;
    crypto_module.define_singleton_method("verify_detached", function!(crypto_verify_detached, 3))?;
    crypto_module.define_singleton_method("sign_json", function!(crypto_sign_json, 2))?;
    crypto_module.define_singleton_method("verify_json", function!(crypto_verify_json, 3))?;
    crypto_module.define_singleton_method(
        "load_signing_key_from_private",
        function!(crypto_load_signing_key_from_private, 1),
    )?;
    crypto_module.define_singleton_method(
        "load_verifying_key",
        function!(crypto_load_verifying_key, 1),
    )?;
    crypto_module.define_singleton_method("generate_key_pair", function!(crypto_generate_key_pair, 2))?;
    crypto_module.define_singleton_method(
        "export_verifying_key_jwk",
        function!(crypto_export_verifying_key_jwk, 1),
    )?;

    Ok(())
}
