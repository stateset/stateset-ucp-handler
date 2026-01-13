use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
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

fn json_error<E: std::fmt::Display>(err: E) -> PyErr {
    PyValueError::new_err(err.to_string())
}

fn runtime_error<E: std::fmt::Display>(err: E) -> PyErr {
    PyRuntimeError::new_err(err.to_string())
}

fn parse_algorithm(algorithm: &str) -> Result<SigningAlgorithm, PyErr> {
    SigningAlgorithm::from_str(algorithm).map_err(json_error)
}

#[pyclass(unsendable)]
pub struct CheckoutService {
    runtime: tokio::runtime::Runtime,
    inner: RustCheckoutService,
}

#[pymethods]
impl CheckoutService {
    #[new]
    #[pyo3(signature = (ucp_version, service_version, base_url, session_ttl_seconds, tax_bps, identity_linking_enabled=None, buyer_consent_enabled=None, ap2_enabled=None, ap2_merchant_authorization=None))]
    fn new(
        ucp_version: String,
        service_version: String,
        base_url: String,
        session_ttl_seconds: u64,
        tax_bps: i64,
        identity_linking_enabled: Option<bool>,
        buyer_consent_enabled: Option<bool>,
        ap2_enabled: Option<bool>,
        ap2_merchant_authorization: Option<String>,
    ) -> PyResult<Self> {
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
            event_sender,
            ucp_version,
            service_version,
            base_url,
            session_ttl_seconds,
            tax_bps,
            None,
            identity_linking_enabled.unwrap_or(false),
            buyer_consent_enabled.unwrap_or(false),
            ap2_enabled.unwrap_or(false),
            ap2_merchant_authorization,
            None,
            None,
        );

        Ok(Self {
            runtime,
            inner: service,
        })
    }

    fn create_checkout(&self, request_json: &str) -> PyResult<String> {
        let request: CheckoutCreateRequest = serde_json::from_str(request_json).map_err(json_error)?;
        let response = self
            .runtime
            .block_on(self.inner.create_checkout(request))
            .map_err(runtime_error)?;
        serde_json::to_string(&response).map_err(json_error)
    }

    fn get_checkout(&self, checkout_id: &str) -> PyResult<String> {
        let response = self
            .runtime
            .block_on(self.inner.get_checkout(checkout_id))
            .map_err(runtime_error)?;
        serde_json::to_string(&response).map_err(json_error)
    }

    fn update_checkout(&self, checkout_id: &str, request_json: &str) -> PyResult<String> {
        let request: CheckoutUpdateRequest =
            serde_json::from_str(request_json).map_err(json_error)?;
        let response = self
            .runtime
            .block_on(self.inner.update_checkout(checkout_id, request))
            .map_err(runtime_error)?;
        serde_json::to_string(&response).map_err(json_error)
    }

    fn complete_checkout(&self, checkout_id: &str, request_json: &str) -> PyResult<String> {
        let request: CheckoutCompleteRequest =
            serde_json::from_str(request_json).map_err(json_error)?;
        let response = self
            .runtime
            .block_on(self.inner.complete_checkout(checkout_id, request))
            .map_err(runtime_error)?;
        serde_json::to_string(&response).map_err(json_error)
    }

    fn cancel_checkout(&self, checkout_id: &str) -> PyResult<String> {
        let response = self
            .runtime
            .block_on(self.inner.cancel_checkout(checkout_id))
            .map_err(runtime_error)?;
        serde_json::to_string(&response).map_err(json_error)
    }

    fn discovery_document(&self) -> PyResult<String> {
        let document = self.inner.discovery_document();
        serde_json::to_string(&document).map_err(json_error)
    }
}

#[pyclass(unsendable)]
pub struct SigningKey {
    inner: Arc<RustSigningKey>,
}

#[pymethods]
impl SigningKey {
    #[getter]
    fn kid(&self) -> String {
        self.inner.kid.clone()
    }

    #[getter]
    fn algorithm(&self) -> String {
        self.inner.algorithm.as_str().to_string()
    }
}

#[pyclass(unsendable)]
pub struct VerifyingKey {
    inner: Arc<RustVerifyingKey>,
}

#[pymethods]
impl VerifyingKey {
    #[getter]
    fn kid(&self) -> String {
        self.inner.kid.clone()
    }

    #[getter]
    fn algorithm(&self) -> String {
        self.inner.algorithm.as_str().to_string()
    }
}

#[pyclass]
pub struct Crypto;

#[pymethods]
impl Crypto {
    #[staticmethod]
    fn canonicalize(json_value: &str) -> PyResult<Vec<u8>> {
        let value: JsonValue = serde_json::from_str(json_value).map_err(json_error)?;
        crypto::canonicalize(&value).map_err(runtime_error)
    }

    #[staticmethod]
    fn sign_detached(payload: &[u8], key: &SigningKey) -> PyResult<String> {
        let jws = crypto::sign_detached(payload, &key.inner).map_err(runtime_error)?;
        Ok(jws.to_compact())
    }

    #[staticmethod]
    fn verify_detached(jws_compact: &str, payload: &[u8], key: &VerifyingKey) -> PyResult<()> {
        let jws = RustDetachedJws::from_compact(jws_compact).map_err(runtime_error)?;
        crypto::verify_detached(&jws, payload, &key.inner).map_err(runtime_error)
    }

    #[staticmethod]
    fn sign_json(json_value: &str, key: &SigningKey) -> PyResult<String> {
        let value: JsonValue = serde_json::from_str(json_value).map_err(json_error)?;
        let jws = crypto::sign_json(&value, &key.inner).map_err(runtime_error)?;
        Ok(jws.to_compact())
    }

    #[staticmethod]
    fn verify_json(jws_compact: &str, json_value: &str, key: &VerifyingKey) -> PyResult<()> {
        let jws = RustDetachedJws::from_compact(jws_compact).map_err(runtime_error)?;
        let value: JsonValue = serde_json::from_str(json_value).map_err(json_error)?;
        crypto::verify_json(&jws, &value, &key.inner).map_err(runtime_error)
    }

    #[staticmethod]
    fn load_signing_key_from_private(jwk_json: &str) -> PyResult<SigningKey> {
        let jwk: JwkPrivateKey = serde_json::from_str(jwk_json).map_err(json_error)?;
        let key = crypto::load_signing_key_from_private(&jwk).map_err(runtime_error)?;
        Ok(SigningKey {
            inner: Arc::new(key),
        })
    }

    #[staticmethod]
    fn load_verifying_key(jwk_json: &str) -> PyResult<VerifyingKey> {
        let jwk: JwkKey = serde_json::from_str(jwk_json).map_err(json_error)?;
        let key = crypto::load_verifying_key(&jwk).map_err(runtime_error)?;
        Ok(VerifyingKey {
            inner: Arc::new(key),
        })
    }

    #[staticmethod]
    fn generate_key_pair(algorithm: &str, kid: &str) -> PyResult<(SigningKey, VerifyingKey)> {
        let algorithm = parse_algorithm(algorithm)?;
        let (signing, verifying) = crypto::generate_key_pair(algorithm, kid.to_string());
        Ok((
            SigningKey {
                inner: Arc::new(signing),
            },
            VerifyingKey {
                inner: Arc::new(verifying),
            },
        ))
    }

    #[staticmethod]
    fn export_verifying_key_jwk(key: &VerifyingKey) -> PyResult<String> {
        let jwk = crypto::export_verifying_key_jwk(&key.inner);
        serde_json::to_string(&jwk).map_err(json_error)
    }
}

#[pymodule]
fn stateset_ucp(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<CheckoutService>()?;
    m.add_class::<SigningKey>()?;
    m.add_class::<VerifyingKey>()?;
    m.add_class::<Crypto>()?;
    Ok(())
}
