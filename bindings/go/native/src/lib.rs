use serde::{Deserialize, Serialize};
use stateset_ucp_lib::catalog::ProductCatalog;
use stateset_ucp_lib::crypto::{self, DetachedJws as RustDetachedJws, JwkPrivateKey, SigningAlgorithm};
use stateset_ucp_lib::events::{Event, EventSender};
use stateset_ucp_lib::models::{
    CheckoutCompleteRequest, CheckoutCreateRequest, CheckoutUpdateRequest, JwkKey,
};
use stateset_ucp_lib::service::CheckoutService as RustCheckoutService;
use stateset_ucp_lib::store::CheckoutStore;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use tokio::sync::mpsc;

pub struct UcpCheckoutService {
    runtime: tokio::runtime::Runtime,
    inner: RustCheckoutService,
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

#[derive(Serialize)]
struct KeyPairOutput {
    signing_key: JwkPrivateKey,
    verifying_key: JwkKey,
}

impl UcpCheckoutService {
    fn new(config: CheckoutServiceConfig) -> Result<Self, String> {
        let runtime = tokio::runtime::Runtime::new().map_err(|err| err.to_string())?;
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
            config.ucp_version,
            config.service_version,
            config.base_url,
            config.session_ttl_seconds,
            config.tax_bps,
            None,
            config.identity_linking_enabled.unwrap_or(false),
            config.buyer_consent_enabled.unwrap_or(false),
            config.ap2_enabled.unwrap_or(false),
            config.ap2_merchant_authorization,
            None,
            None,
        );

        Ok(Self {
            runtime,
            inner: service,
        })
    }
}

fn set_error(out_error: *mut *mut c_char, message: impl std::fmt::Display) {
    if out_error.is_null() {
        return;
    }

    let message = message.to_string();
    let c_message = CString::new(message).unwrap_or_else(|_| CString::new("error").unwrap());
    unsafe {
        *out_error = c_message.into_raw();
    }
}

unsafe fn c_str_to_string(ptr: *const c_char) -> Result<String, String> {
    if ptr.is_null() {
        return Err("null pointer".to_string());
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map(|value| value.to_string())
        .map_err(|err| err.to_string())
}

fn string_to_c(value: String, out_error: *mut *mut c_char) -> *mut c_char {
    match CString::new(value) {
        Ok(value) => value.into_raw(),
        Err(_) => {
            set_error(out_error, "string contains null byte");
            ptr::null_mut()
        }
    }
}

fn parse_algorithm(value: &str) -> Result<SigningAlgorithm, String> {
    SigningAlgorithm::from_str(value).map_err(|err| err.to_string())
}

unsafe fn get_service<'a>(
    service: *mut UcpCheckoutService,
    out_error: *mut *mut c_char,
) -> Option<&'a UcpCheckoutService> {
    service.as_ref().or_else(|| {
        set_error(out_error, "service is null");
        None
    })
}

#[no_mangle]
pub extern "C" fn ucp_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn ucp_checkout_service_new(
    config_json: *const c_char,
    out_error: *mut *mut c_char,
) -> *mut UcpCheckoutService {
    let config_json = unsafe {
        match c_str_to_string(config_json) {
            Ok(value) => value,
            Err(err) => {
                set_error(out_error, err);
                return ptr::null_mut();
            }
        }
    };

    let config: CheckoutServiceConfig = match serde_json::from_str(&config_json) {
        Ok(value) => value,
        Err(err) => {
            set_error(out_error, err);
            return ptr::null_mut();
        }
    };

    match UcpCheckoutService::new(config) {
        Ok(service) => Box::into_raw(Box::new(service)),
        Err(err) => {
            set_error(out_error, err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn ucp_checkout_service_free(service: *mut UcpCheckoutService) {
    if service.is_null() {
        return;
    }
    unsafe {
        let _ = Box::from_raw(service);
    }
}

#[no_mangle]
pub extern "C" fn ucp_checkout_create(
    service: *mut UcpCheckoutService,
    request_json: *const c_char,
    out_error: *mut *mut c_char,
) -> *mut c_char {
    let service = unsafe { match get_service(service, out_error) { Some(s) => s, None => return ptr::null_mut() } };
    let request_json = unsafe {
        match c_str_to_string(request_json) {
            Ok(value) => value,
            Err(err) => {
                set_error(out_error, err);
                return ptr::null_mut();
            }
        }
    };

    let request: CheckoutCreateRequest = match serde_json::from_str(&request_json) {
        Ok(value) => value,
        Err(err) => {
            set_error(out_error, err);
            return ptr::null_mut();
        }
    };

    let response = match service.runtime.block_on(service.inner.create_checkout(request)) {
        Ok(value) => value,
        Err(err) => {
            set_error(out_error, err);
            return ptr::null_mut();
        }
    };

    match serde_json::to_string(&response) {
        Ok(value) => string_to_c(value, out_error),
        Err(err) => {
            set_error(out_error, err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn ucp_checkout_get(
    service: *mut UcpCheckoutService,
    checkout_id: *const c_char,
    out_error: *mut *mut c_char,
) -> *mut c_char {
    let service = unsafe { match get_service(service, out_error) { Some(s) => s, None => return ptr::null_mut() } };
    let checkout_id = unsafe {
        match c_str_to_string(checkout_id) {
            Ok(value) => value,
            Err(err) => {
                set_error(out_error, err);
                return ptr::null_mut();
            }
        }
    };

    let response = match service.runtime.block_on(service.inner.get_checkout(&checkout_id)) {
        Ok(value) => value,
        Err(err) => {
            set_error(out_error, err);
            return ptr::null_mut();
        }
    };

    match serde_json::to_string(&response) {
        Ok(value) => string_to_c(value, out_error),
        Err(err) => {
            set_error(out_error, err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn ucp_checkout_update(
    service: *mut UcpCheckoutService,
    checkout_id: *const c_char,
    request_json: *const c_char,
    out_error: *mut *mut c_char,
) -> *mut c_char {
    let service = unsafe { match get_service(service, out_error) { Some(s) => s, None => return ptr::null_mut() } };
    let checkout_id = unsafe {
        match c_str_to_string(checkout_id) {
            Ok(value) => value,
            Err(err) => {
                set_error(out_error, err);
                return ptr::null_mut();
            }
        }
    };
    let request_json = unsafe {
        match c_str_to_string(request_json) {
            Ok(value) => value,
            Err(err) => {
                set_error(out_error, err);
                return ptr::null_mut();
            }
        }
    };

    let request: CheckoutUpdateRequest = match serde_json::from_str(&request_json) {
        Ok(value) => value,
        Err(err) => {
            set_error(out_error, err);
            return ptr::null_mut();
        }
    };

    let response = match service
        .runtime
        .block_on(service.inner.update_checkout(&checkout_id, request))
    {
        Ok(value) => value,
        Err(err) => {
            set_error(out_error, err);
            return ptr::null_mut();
        }
    };

    match serde_json::to_string(&response) {
        Ok(value) => string_to_c(value, out_error),
        Err(err) => {
            set_error(out_error, err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn ucp_checkout_complete(
    service: *mut UcpCheckoutService,
    checkout_id: *const c_char,
    request_json: *const c_char,
    out_error: *mut *mut c_char,
) -> *mut c_char {
    let service = unsafe { match get_service(service, out_error) { Some(s) => s, None => return ptr::null_mut() } };
    let checkout_id = unsafe {
        match c_str_to_string(checkout_id) {
            Ok(value) => value,
            Err(err) => {
                set_error(out_error, err);
                return ptr::null_mut();
            }
        }
    };
    let request_json = unsafe {
        match c_str_to_string(request_json) {
            Ok(value) => value,
            Err(err) => {
                set_error(out_error, err);
                return ptr::null_mut();
            }
        }
    };

    let request: CheckoutCompleteRequest = match serde_json::from_str(&request_json) {
        Ok(value) => value,
        Err(err) => {
            set_error(out_error, err);
            return ptr::null_mut();
        }
    };

    let response = match service
        .runtime
        .block_on(service.inner.complete_checkout(&checkout_id, request))
    {
        Ok(value) => value,
        Err(err) => {
            set_error(out_error, err);
            return ptr::null_mut();
        }
    };

    match serde_json::to_string(&response) {
        Ok(value) => string_to_c(value, out_error),
        Err(err) => {
            set_error(out_error, err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn ucp_checkout_cancel(
    service: *mut UcpCheckoutService,
    checkout_id: *const c_char,
    out_error: *mut *mut c_char,
) -> *mut c_char {
    let service = unsafe { match get_service(service, out_error) { Some(s) => s, None => return ptr::null_mut() } };
    let checkout_id = unsafe {
        match c_str_to_string(checkout_id) {
            Ok(value) => value,
            Err(err) => {
                set_error(out_error, err);
                return ptr::null_mut();
            }
        }
    };

    let response = match service
        .runtime
        .block_on(service.inner.cancel_checkout(&checkout_id))
    {
        Ok(value) => value,
        Err(err) => {
            set_error(out_error, err);
            return ptr::null_mut();
        }
    };

    match serde_json::to_string(&response) {
        Ok(value) => string_to_c(value, out_error),
        Err(err) => {
            set_error(out_error, err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn ucp_checkout_discovery_document(
    service: *mut UcpCheckoutService,
    out_error: *mut *mut c_char,
) -> *mut c_char {
    let service = unsafe { match get_service(service, out_error) { Some(s) => s, None => return ptr::null_mut() } };
    let document = service.inner.discovery_document();

    match serde_json::to_string(&document) {
        Ok(value) => string_to_c(value, out_error),
        Err(err) => {
            set_error(out_error, err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn ucp_crypto_generate_key_pair(
    algorithm: *const c_char,
    kid: *const c_char,
    out_error: *mut *mut c_char,
) -> *mut c_char {
    let algorithm = unsafe {
        match c_str_to_string(algorithm) {
            Ok(value) => value,
            Err(err) => {
                set_error(out_error, err);
                return ptr::null_mut();
            }
        }
    };
    let kid = unsafe {
        match c_str_to_string(kid) {
            Ok(value) => value,
            Err(err) => {
                set_error(out_error, err);
                return ptr::null_mut();
            }
        }
    };

    let algorithm = match parse_algorithm(&algorithm) {
        Ok(value) => value,
        Err(err) => {
            set_error(out_error, err);
            return ptr::null_mut();
        }
    };

    let (signing, verifying) = crypto::generate_key_pair(algorithm, kid);
    let output = KeyPairOutput {
        signing_key: crypto::export_signing_key_jwk(&signing),
        verifying_key: crypto::export_verifying_key_jwk(&verifying),
    };

    match serde_json::to_string(&output) {
        Ok(value) => string_to_c(value, out_error),
        Err(err) => {
            set_error(out_error, err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn ucp_crypto_sign_json(
    json_value: *const c_char,
    jwk_private_json: *const c_char,
    out_error: *mut *mut c_char,
) -> *mut c_char {
    let json_value = unsafe {
        match c_str_to_string(json_value) {
            Ok(value) => value,
            Err(err) => {
                set_error(out_error, err);
                return ptr::null_mut();
            }
        }
    };
    let jwk_private_json = unsafe {
        match c_str_to_string(jwk_private_json) {
            Ok(value) => value,
            Err(err) => {
                set_error(out_error, err);
                return ptr::null_mut();
            }
        }
    };

    let value: serde_json::Value = match serde_json::from_str(&json_value) {
        Ok(value) => value,
        Err(err) => {
            set_error(out_error, err);
            return ptr::null_mut();
        }
    };
    let jwk: JwkPrivateKey = match serde_json::from_str(&jwk_private_json) {
        Ok(value) => value,
        Err(err) => {
            set_error(out_error, err);
            return ptr::null_mut();
        }
    };

    let key = match crypto::load_signing_key_from_private(&jwk) {
        Ok(value) => value,
        Err(err) => {
            set_error(out_error, err);
            return ptr::null_mut();
        }
    };
    let jws = match crypto::sign_json(&value, &key) {
        Ok(value) => value,
        Err(err) => {
            set_error(out_error, err);
            return ptr::null_mut();
        }
    };

    string_to_c(jws.to_compact(), out_error)
}

#[no_mangle]
pub extern "C" fn ucp_crypto_verify_json(
    jws_compact: *const c_char,
    json_value: *const c_char,
    jwk_public_json: *const c_char,
    out_error: *mut *mut c_char,
) -> bool {
    let jws_compact = unsafe {
        match c_str_to_string(jws_compact) {
            Ok(value) => value,
            Err(err) => {
                set_error(out_error, err);
                return false;
            }
        }
    };
    let json_value = unsafe {
        match c_str_to_string(json_value) {
            Ok(value) => value,
            Err(err) => {
                set_error(out_error, err);
                return false;
            }
        }
    };
    let jwk_public_json = unsafe {
        match c_str_to_string(jwk_public_json) {
            Ok(value) => value,
            Err(err) => {
                set_error(out_error, err);
                return false;
            }
        }
    };

    let jws = match RustDetachedJws::from_compact(&jws_compact) {
        Ok(value) => value,
        Err(err) => {
            set_error(out_error, err);
            return false;
        }
    };
    let value: serde_json::Value = match serde_json::from_str(&json_value) {
        Ok(value) => value,
        Err(err) => {
            set_error(out_error, err);
            return false;
        }
    };
    let jwk: JwkKey = match serde_json::from_str(&jwk_public_json) {
        Ok(value) => value,
        Err(err) => {
            set_error(out_error, err);
            return false;
        }
    };
    let key = match crypto::load_verifying_key(&jwk) {
        Ok(value) => value,
        Err(err) => {
            set_error(out_error, err);
            return false;
        }
    };

    match crypto::verify_json(&jws, &value, &key) {
        Ok(()) => true,
        Err(err) => {
            set_error(out_error, err);
            false
        }
    }
}
