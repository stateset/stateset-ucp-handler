package ucp

/*
#cgo CFLAGS: -I${SRCDIR}
#cgo LDFLAGS: -L${SRCDIR}/native/target/release -lstateset_ucp_ffi
#include "ucp.h"
#include <stdlib.h>
*/
import "C"

import (
    "encoding/json"
    "errors"
    "unsafe"
)

// CheckoutConfig configures the checkout service.
type CheckoutConfig struct {
    UCPVersion            string  `json:"ucp_version"`
    ServiceVersion        string  `json:"service_version"`
    BaseURL               string  `json:"base_url"`
    SessionTTLSeconds     uint64  `json:"session_ttl_seconds"`
    TaxBps                int64   `json:"tax_bps"`
    IdentityLinkingEnabled *bool   `json:"identity_linking_enabled,omitempty"`
    BuyerConsentEnabled    *bool   `json:"buyer_consent_enabled,omitempty"`
    AP2Enabled             *bool   `json:"ap2_enabled,omitempty"`
    AP2MerchantAuthorization *string `json:"ap2_merchant_authorization,omitempty"`
}

// CheckoutService wraps a native checkout service instance.
type CheckoutService struct {
    ptr *C.UcpCheckoutService
}

// NewCheckoutService creates a new checkout service.
func NewCheckoutService(config CheckoutConfig) (*CheckoutService, error) {
    payload, err := json.Marshal(config)
    if err != nil {
        return nil, err
    }

    cPayload := C.CString(string(payload))
    defer C.free(unsafe.Pointer(cPayload))

    var errPtr *C.char
    service := C.ucp_checkout_service_new(cPayload, &errPtr)
    if err := consumeError(errPtr); err != nil {
        return nil, err
    }
    if service == nil {
        return nil, errors.New("ucp_checkout_service_new returned null")
    }

    return &CheckoutService{ptr: service}, nil
}

// Close releases the native service.
func (s *CheckoutService) Close() error {
    if s == nil || s.ptr == nil {
        return nil
    }
    C.ucp_checkout_service_free(s.ptr)
    s.ptr = nil
    return nil
}

// CreateCheckout creates a new checkout session.
func (s *CheckoutService) CreateCheckout(request any) (string, error) {
    requestJSON, err := marshalJSON(request)
    if err != nil {
        return "", err
    }

    cRequest := C.CString(requestJSON)
    defer C.free(unsafe.Pointer(cRequest))

    var errPtr *C.char
    result := C.ucp_checkout_create(s.ptr, cRequest, &errPtr)
    return stringResult(result, errPtr)
}

// GetCheckout fetches a checkout by ID.
func (s *CheckoutService) GetCheckout(checkoutID string) (string, error) {
    cID := C.CString(checkoutID)
    defer C.free(unsafe.Pointer(cID))

    var errPtr *C.char
    result := C.ucp_checkout_get(s.ptr, cID, &errPtr)
    return stringResult(result, errPtr)
}

// UpdateCheckout updates a checkout session.
func (s *CheckoutService) UpdateCheckout(checkoutID string, request any) (string, error) {
    requestJSON, err := marshalJSON(request)
    if err != nil {
        return "", err
    }

    cID := C.CString(checkoutID)
    cRequest := C.CString(requestJSON)
    defer C.free(unsafe.Pointer(cID))
    defer C.free(unsafe.Pointer(cRequest))

    var errPtr *C.char
    result := C.ucp_checkout_update(s.ptr, cID, cRequest, &errPtr)
    return stringResult(result, errPtr)
}

// CompleteCheckout completes a checkout session.
func (s *CheckoutService) CompleteCheckout(checkoutID string, request any) (string, error) {
    requestJSON, err := marshalJSON(request)
    if err != nil {
        return "", err
    }

    cID := C.CString(checkoutID)
    cRequest := C.CString(requestJSON)
    defer C.free(unsafe.Pointer(cID))
    defer C.free(unsafe.Pointer(cRequest))

    var errPtr *C.char
    result := C.ucp_checkout_complete(s.ptr, cID, cRequest, &errPtr)
    return stringResult(result, errPtr)
}

// CancelCheckout cancels a checkout session.
func (s *CheckoutService) CancelCheckout(checkoutID string) (string, error) {
    cID := C.CString(checkoutID)
    defer C.free(unsafe.Pointer(cID))

    var errPtr *C.char
    result := C.ucp_checkout_cancel(s.ptr, cID, &errPtr)
    return stringResult(result, errPtr)
}

// DiscoveryDocument returns the discovery document JSON.
func (s *CheckoutService) DiscoveryDocument() (string, error) {
    var errPtr *C.char
    result := C.ucp_checkout_discovery_document(s.ptr, &errPtr)
    return stringResult(result, errPtr)
}

// GenerateKeyPair returns a JSON payload containing signing and verifying JWKs.
func GenerateKeyPair(algorithm, kid string) (string, error) {
    cAlg := C.CString(algorithm)
    cKid := C.CString(kid)
    defer C.free(unsafe.Pointer(cAlg))
    defer C.free(unsafe.Pointer(cKid))

    var errPtr *C.char
    result := C.ucp_crypto_generate_key_pair(cAlg, cKid, &errPtr)
    return stringResult(result, errPtr)
}

// SignJSON signs a JSON payload with a JWK private key.
func SignJSON(payload any, jwkPrivateJSON string) (string, error) {
    payloadJSON, err := marshalJSON(payload)
    if err != nil {
        return "", err
    }

    cPayload := C.CString(payloadJSON)
    cKey := C.CString(jwkPrivateJSON)
    defer C.free(unsafe.Pointer(cPayload))
    defer C.free(unsafe.Pointer(cKey))

    var errPtr *C.char
    result := C.ucp_crypto_sign_json(cPayload, cKey, &errPtr)
    return stringResult(result, errPtr)
}

// VerifyJSON verifies a JWS compact signature against a JSON payload.
func VerifyJSON(jwsCompact string, payload any, jwkPublicJSON string) error {
    payloadJSON, err := marshalJSON(payload)
    if err != nil {
        return err
    }

    cJws := C.CString(jwsCompact)
    cPayload := C.CString(payloadJSON)
    cKey := C.CString(jwkPublicJSON)
    defer C.free(unsafe.Pointer(cJws))
    defer C.free(unsafe.Pointer(cPayload))
    defer C.free(unsafe.Pointer(cKey))

    var errPtr *C.char
    ok := C.ucp_crypto_verify_json(cJws, cPayload, cKey, &errPtr)
    if err := consumeError(errPtr); err != nil {
        return err
    }
    if !bool(ok) {
        return errors.New("verification failed")
    }
    return nil
}

func marshalJSON(input any) (string, error) {
    switch value := input.(type) {
    case string:
        return value, nil
    case []byte:
        return string(value), nil
    case json.RawMessage:
        return string(value), nil
    default:
        data, err := json.Marshal(input)
        if err != nil {
            return "", err
        }
        return string(data), nil
    }
}

func consumeError(errPtr *C.char) error {
    if errPtr == nil {
        return nil
    }
    defer C.ucp_string_free(errPtr)
    return errors.New(C.GoString(errPtr))
}

func stringResult(value *C.char, errPtr *C.char) (string, error) {
    if err := consumeError(errPtr); err != nil {
        if value != nil {
            C.ucp_string_free(value)
        }
        return "", err
    }
    if value == nil {
        return "", errors.New("native call returned null")
    }
    defer C.ucp_string_free(value)
    return C.GoString(value), nil
}
