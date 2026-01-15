use axum::{
    body::Body,
    extract::{Extension, Form, Path, Query, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

mod a2a;
mod auth;
mod catalog;
mod commerce;
mod commerce_adapter;
mod config;
mod constants;
mod crypto;
mod embedded;
mod errors;
mod events;
mod grpc;
mod idempotency;
mod mcp;
mod models;
mod negotiation;
mod oauth;
mod order_api;
mod service;
mod store;
mod tokenization;
mod ucp_meta;
mod validation;
mod webhook;

use a2a::{A2AHandler, A2AMessage};
use auth::{auth_middleware, AuthConfig};
use config::Config;
use constants::MAX_REQUEST_BODY_BYTES;
use crypto::{
    canonicalize, load_signing_key_from_private, sign_detached, verify_detached, DetachedJws,
    JwkPrivateKey, SigningKey,
};
use embedded::{accepted_delegations, render_embedded_page, EmbeddedParams};
use errors::ApiError;
use events::{Event, EventSender};
use idempotency::{idempotency_middleware, CachedBody, IdempotencyStore};
use mcp::{extract_profile_url, error_codes as mcp_error_codes, JsonRpcError, JsonRpcRequest, JsonRpcResponse, McpHandler};
use models::{
    Capability, CheckoutCompleteRequest, CheckoutCreateRequest, CheckoutUpdateRequest,
    DetokenizeRequest, OrderEvent, TokenizeRequest,
};
use negotiation::{negotiate, NegotiatedCapabilities, NegotiationError, ProfileCache};
use oauth::{
    build_redirect_uri, parse_basic_auth, AuthorizationRequest, OAuthConfig, OAuthService,
    RevocationRequest, TokenRequest,
};
use order_api::{AdjustmentRequest, FulfillmentEventRequest, OrderService, OrderStore};
use service::CheckoutService;
use store::CheckoutStore;
use tokenization::TokenizationService;
use ucp_meta::{apply_negotiated_checkout, apply_negotiated_order, requires_ap2_mandate};
use webhook::{OrderWebhook, OrderWebhookOptions};
use tower_http::{
    compression::CompressionLayer, cors::CorsLayer, limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};

#[derive(Clone)]
pub struct AppState {
    service: CheckoutService,
    auth: Arc<AuthConfig>,
    idempotency: Option<Arc<IdempotencyStore>>,
    require_idempotency: bool,
    require_request_id: bool,
    require_ucp_agent: bool,
    require_request_signature: bool,
    oauth: Option<Arc<OAuthService>>,
    tokenization: Arc<TokenizationService>,
    profile_cache: Arc<ProfileCache>,
    mcp_handler: Arc<McpHandler>,
    a2a_handler: Arc<A2AHandler>,
    response_signing_key: Option<Arc<SigningKey>>,
    business_capabilities: Arc<Vec<Capability>>,
    business_version: String,
    order_service: Arc<OrderService>,
}

impl AppState {
    pub fn grpc_parts(&self) -> (CheckoutService, Arc<AuthConfig>, Arc<TokenizationService>) {
        (
            self.service.clone(),
            self.auth.clone(),
            self.tokenization.clone(),
        )
    }
}

impl axum::extract::FromRef<AppState> for Arc<AuthConfig> {
    fn from_ref(state: &AppState) -> Arc<AuthConfig> {
        state.auth.clone()
    }
}

impl axum::extract::FromRef<AppState> for Option<Arc<IdempotencyStore>> {
    fn from_ref(state: &AppState) -> Option<Arc<IdempotencyStore>> {
        state.idempotency.clone()
    }
}

#[derive(Clone)]
struct UcpRequestContext {
    negotiated: NegotiatedCapabilities,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = dotenvy::dotenv();

    let config = Config::load()?;

    let env_filter = tracing_subscriber::EnvFilter::try_new(config.log_level.clone())
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_thread_ids(true)
        .with_level(true)
        .json()
        .init();

    // Initialize iCommerce engine if enabled
    let commerce_engine = if config.commerce_enabled {
        match commerce::CommerceEngine::new(&config.commerce_db_path) {
            Ok(engine) => {
                info!("iCommerce engine initialized at {}", config.commerce_db_path);
                Some(engine)
            }
            Err(e) => {
                warn!("Failed to initialize iCommerce engine: {}. Falling back to in-memory stores.", e);
                None
            }
        }
    } else {
        info!("iCommerce engine disabled, using in-memory stores");
        None
    };

    // Create stores with iCommerce backend when available
    let store = match &commerce_engine {
        Some(engine) => CheckoutStore::new_with_commerce(engine.clone()),
        None => CheckoutStore::new(),
    };
    let catalog = match &commerce_engine {
        Some(engine) => catalog::ProductCatalog::new_with_commerce(engine.clone()),
        None => catalog::ProductCatalog::new(),
    };

    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(128);
    let event_sender = EventSender::new(event_tx);

    let signing_keys = config
        .signing_keys_json
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok());

    // Load AP2 signing key if configured
    let ap2_signing_key = config
        .signing_private_key_json
        .as_deref()
        .and_then(|raw| {
            let mut jwk: JwkPrivateKey = serde_json::from_str(raw).ok()?;
            if let Some(override_kid) = config.ap2_signing_key_id.as_ref() {
                jwk.kid = override_kid.clone();
            }
            match load_signing_key_from_private(&jwk) {
                Ok(key) => {
                    info!("Loaded AP2 signing key: {}", jwk.kid);
                    Some(key)
                }
                Err(e) => {
                    warn!("Failed to load AP2 signing key: {}", e);
                    None
                }
            }
        });

    let oauth_redirects = if config.oauth_redirect_uris.is_empty() {
        None
    } else {
        Some(config.oauth_redirect_uris.iter().cloned().collect())
    };

    let response_signing_key = ap2_signing_key.clone().map(Arc::new);

    let oauth_service = if config.oauth_enabled {
        Some(Arc::new(OAuthService::new(OAuthConfig {
            issuer: config.oauth_issuer.clone(),
            client_id: config.oauth_client_id.clone(),
            client_secret: config.oauth_client_secret.clone(),
            scopes: config.oauth_scopes.clone(),
            token_ttl: Duration::from_secs(config.oauth_token_ttl_seconds),
            code_ttl: Duration::from_secs(config.oauth_code_ttl_seconds),
            redirect_uris: oauth_redirects,
            service_documentation: config.oauth_service_documentation.clone(),
        })))
    } else {
        None
    };

    let service = CheckoutService::new(
        store,
        catalog,
        commerce_engine.clone(),
        event_sender.clone(),
        config.ucp_version.clone(),
        config.service_version.clone(),
        config.base_url.clone(),
        config.session_ttl_seconds,
        config.tax_bps,
        signing_keys,
        config.oauth_enabled,
        config.buyer_consent_enabled,
        config.use_icommerce_tax,
        config.use_icommerce_promotions,
        config.use_icommerce_shipping,
        config.ap2_enabled,
        config.ap2_merchant_authorization.clone(),
        ap2_signing_key,
        None,
    );

    let auth = Arc::new(AuthConfig::new(
        config.require_auth,
        config.api_keys.clone(),
        oauth_service.clone(),
    ));

    let tokenization = Arc::new(TokenizationService::new(
        Duration::from_secs(config.token_ttl_seconds),
        config.token_single_use,
    ));
    let business_capabilities = Arc::new(service.business_capabilities());
    let business_version = service.business_version().to_string();

    let idempotency_store = if config.require_idempotency || !config.api_keys.is_empty() {
        Some(Arc::new(IdempotencyStore::new(std::time::Duration::from_secs(
            86400,
        ))))
    } else {
        None
    };

    let order_store = match &commerce_engine {
        Some(engine) => OrderStore::new_with_commerce(engine.clone()),
        None => OrderStore::new(),
    };
    let order_service = Arc::new(OrderService::new(
        order_store.clone(),
        config.ucp_version.clone(),
        config.base_url.clone(),
    ));

    // Profile cache for platform profile negotiation (1 hour TTL)
    let profile_cache = Arc::new(ProfileCache::new_with_timeout(
        Duration::from_secs(config.profile_cache_ttl_seconds),
        Duration::from_secs(config.profile_fetch_timeout_seconds),
    ));

    // MCP handler for JSON-RPC transport
    let mcp_handler = Arc::new(McpHandler::new(service.clone()));

    // A2A handler for agent-to-agent transport
    let a2a_handler = Arc::new(A2AHandler::new(
        service.clone(),
        config.base_url.clone(),
        config.ucp_version.clone(),
    ));

    let state = AppState {
        service,
        auth,
        idempotency: idempotency_store,
        require_idempotency: config.require_idempotency,
        require_request_id: config.require_request_id,
        require_ucp_agent: config.require_ucp_agent,
        require_request_signature: config.require_request_signature,
        oauth: oauth_service.clone(),
        tokenization,
        profile_cache,
        mcp_handler,
        a2a_handler,
        response_signing_key,
        business_capabilities,
        business_version,
        order_service: order_service.clone(),
    };

    let mut webhook_options = OrderWebhookOptions::default();
    webhook_options.timeout = Duration::from_secs(config.webhook_timeout_seconds);
    webhook_options.max_retries = config.webhook_max_retries;
    webhook_options.retry_backoff = Duration::from_millis(config.webhook_retry_base_ms);

    let webhook_sender = OrderWebhook::new_with_options(
        config.order_webhook_url.clone(),
        config.order_webhook_api_key.clone(),
        config.webhook_signature.clone(),
        webhook_options,
    );

    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            match event {
                Event::OrderCreated { order } => {
                    order_store.insert(order.clone()).await;
                    let order_event = OrderEvent {
                        order,
                        event_id: format!("evt_{}", uuid::Uuid::new_v4()),
                        created_time: chrono::Utc::now().to_rfc3339(),
                    };

                    if let Err(err) = webhook_sender.send_order_event(&order_event).await {
                        warn!("Failed to deliver order event webhook: {}", err);
                    }
                }
            }
        }
    });

    let api_router = Router::new()
        .route("/checkout-sessions", post(create_checkout))
        .route("/checkout-sessions/:id", get(get_checkout).put(update_checkout))
        .route("/checkout-sessions/:id/complete", post(complete_checkout))
        .route("/checkout-sessions/:id/cancel", post(cancel_checkout))
        .route("/orders/:id", get(get_order))
        .route(
            "/orders/:id/fulfillment-events",
            post(add_fulfillment_event),
        )
        .route("/orders/:id/adjustments", post(add_adjustment))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            idempotency_middleware,
        ))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_headers_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            request_signature_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            ucp_agent_middleware,
        ));

    let tokenization_router = Router::new()
        .route("/tokenize", post(tokenize))
        .route("/detokenize", post(detokenize))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_headers_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            request_signature_middleware,
        ))
        .layer(middleware::from_fn_with_state(state.clone(), ucp_agent_middleware));

    let oauth_enabled = state.oauth.is_some();
    let mut app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/.well-known/ucp", get(discovery))
        .nest("/api", api_router)
        .merge(tokenization_router);

    if oauth_enabled {
        let oauth_router = Router::new()
            .route(
                "/.well-known/oauth-authorization-server",
                get(oauth_metadata),
            )
            .route("/oauth2/authorize", get(oauth_authorize))
            .route("/oauth2/token", post(oauth_token))
            .route("/oauth2/revoke", post(oauth_revoke));
        app = app.merge(oauth_router);
    }

    // MCP JSON-RPC transport
    let mcp_router = Router::new()
        .route(
            "/mcp",
            post(mcp_handler_endpoint)
                .layer(middleware::from_fn_with_state(state.clone(), auth_middleware)),
        )
        .route("/schemas/shopping/mcp.openrpc.json", get(mcp_schema));
    app = app.merge(mcp_router);

    // A2A (Agent-to-Agent) transport
    let a2a_router = Router::new()
        .route("/.well-known/agent-card.json", get(agent_card))
        .route(
            "/a2a",
            post(a2a_handler_endpoint)
                .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    a2a_extensions_middleware,
                ))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    ucp_agent_middleware,
                )),
        );
    app = app.merge(a2a_router);

    // Embedded Protocol
    let embedded_router = Router::new()
        .route("/checkout/:id", get(embedded_checkout))
        .route("/checkout/:id/embedded", get(embedded_checkout));
    app = app.merge(embedded_router);

    let grpc_state = state.clone();
    let app = app
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES))
        .layer(CompressionLayer::new())
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(response_headers_middleware))
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    info!("UCP handler listening on {}", addr);

    let grpc_addr: SocketAddr = format!("{}:{}", config.grpc_host, config.grpc_port).parse()?;

    let listener = tokio::net::TcpListener::bind(addr).await?;

    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
    let mut http_shutdown_rx = shutdown_tx.subscribe();
    let mut grpc_shutdown_rx = shutdown_tx.subscribe();

    tokio::spawn({
        let shutdown_tx = shutdown_tx.clone();
        async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                let _ = shutdown_tx.send(());
            }
        }
    });

    let http_server = async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = http_shutdown_rx.recv().await;
            })
            .await
            .map_err(|err| -> Box<dyn std::error::Error> { Box::new(err) })?;
        Ok::<(), Box<dyn std::error::Error>>(())
    };

    let grpc_server = async move {
        grpc::serve(grpc_addr, grpc_state, async move {
            let _ = grpc_shutdown_rx.recv().await;
        })
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    };

    tokio::try_join!(http_server, grpc_server)?;

    Ok(())
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
}

async fn ready() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ready" })))
}

async fn discovery(State(state): State<AppState>) -> impl IntoResponse {
    let document = state.service.discovery_document();
    (StatusCode::OK, Json(document))
}

async fn create_checkout(
    State(state): State<AppState>,
    Extension(context): Extension<UcpRequestContext>,
    headers: HeaderMap,
    Json(payload): Json<CheckoutCreateRequest>,
) -> Result<Response, ApiError> {
    let mut checkout = state
        .service
        .create_checkout(payload)
        .await
        .map_err(ApiError::from_service)?;

    apply_negotiated_checkout(&mut checkout, Some(&context.negotiated));

    build_json_response(
        StatusCode::CREATED,
        &checkout,
        &headers,
        state.response_signing_key.as_deref(),
    )
}

async fn get_checkout(
    State(state): State<AppState>,
    Extension(context): Extension<UcpRequestContext>,
    headers: HeaderMap,
    Path(checkout_id): Path<String>,
) -> Result<Response, ApiError> {
    let mut checkout = state
        .service
        .get_checkout(&checkout_id)
        .await
        .map_err(ApiError::from_service)?;

    apply_negotiated_checkout(&mut checkout, Some(&context.negotiated));

    build_json_response(
        StatusCode::OK,
        &checkout,
        &headers,
        state.response_signing_key.as_deref(),
    )
}

async fn update_checkout(
    State(state): State<AppState>,
    Extension(context): Extension<UcpRequestContext>,
    headers: HeaderMap,
    Path(checkout_id): Path<String>,
    Json(payload): Json<CheckoutUpdateRequest>,
) -> Result<Response, ApiError> {
    let mut checkout = state
        .service
        .update_checkout(&checkout_id, payload)
        .await
        .map_err(ApiError::from_service)?;

    apply_negotiated_checkout(&mut checkout, Some(&context.negotiated));

    build_json_response(
        StatusCode::OK,
        &checkout,
        &headers,
        state.response_signing_key.as_deref(),
    )
}

async fn complete_checkout(
    State(state): State<AppState>,
    Extension(context): Extension<UcpRequestContext>,
    headers: HeaderMap,
    Path(checkout_id): Path<String>,
    Json(payload): Json<CheckoutCompleteRequest>,
) -> Result<Response, ApiError> {
    let require_ap2 = requires_ap2_mandate(
        Some(&context.negotiated),
        state.service.ap2_enabled(),
    );
    let mut checkout = state
        .service
        .complete_checkout_with_requirements(&checkout_id, payload, require_ap2)
        .await
        .map_err(ApiError::from_service)?;

    apply_negotiated_checkout(&mut checkout, Some(&context.negotiated));

    build_json_response(
        StatusCode::OK,
        &checkout,
        &headers,
        state.response_signing_key.as_deref(),
    )
}

async fn cancel_checkout(
    State(state): State<AppState>,
    Extension(context): Extension<UcpRequestContext>,
    headers: HeaderMap,
    Path(checkout_id): Path<String>,
) -> Result<Response, ApiError> {
    let mut checkout = state
        .service
        .cancel_checkout(&checkout_id)
        .await
        .map_err(ApiError::from_service)?;

    apply_negotiated_checkout(&mut checkout, Some(&context.negotiated));

    build_json_response(
        StatusCode::OK,
        &checkout,
        &headers,
        state.response_signing_key.as_deref(),
    )
}

async fn get_order(
    State(state): State<AppState>,
    Extension(context): Extension<UcpRequestContext>,
    headers: HeaderMap,
    Path(order_id): Path<String>,
) -> Result<Response, ApiError> {
    let mut order = state
        .order_service
        .get_order(&order_id)
        .await
        .map_err(ApiError::from_service)?;

    apply_negotiated_order(&mut order, Some(&context.negotiated));

    build_json_response(
        StatusCode::OK,
        &order,
        &headers,
        state.response_signing_key.as_deref(),
    )
}

async fn add_fulfillment_event(
    State(state): State<AppState>,
    Extension(context): Extension<UcpRequestContext>,
    headers: HeaderMap,
    Path(order_id): Path<String>,
    Json(payload): Json<FulfillmentEventRequest>,
) -> Result<Response, ApiError> {
    let mut order = state
        .order_service
        .add_fulfillment_event(&order_id, payload)
        .await
        .map_err(ApiError::from_service)?;

    apply_negotiated_order(&mut order, Some(&context.negotiated));

    build_json_response(
        StatusCode::OK,
        &order,
        &headers,
        state.response_signing_key.as_deref(),
    )
}

async fn add_adjustment(
    State(state): State<AppState>,
    Extension(context): Extension<UcpRequestContext>,
    headers: HeaderMap,
    Path(order_id): Path<String>,
    Json(payload): Json<AdjustmentRequest>,
) -> Result<Response, ApiError> {
    let mut order = state
        .order_service
        .add_adjustment(&order_id, payload)
        .await
        .map_err(ApiError::from_service)?;

    apply_negotiated_order(&mut order, Some(&context.negotiated));

    build_json_response(
        StatusCode::OK,
        &order,
        &headers,
        state.response_signing_key.as_deref(),
    )
}

async fn tokenize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<TokenizeRequest>,
) -> Result<Response, ApiError> {
    let response = state
        .tokenization
        .tokenize(payload)
        .await
        .map_err(ApiError::from_service)?;

    build_json_response(
        StatusCode::OK,
        &response,
        &headers,
        state.response_signing_key.as_deref(),
    )
}

async fn detokenize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<DetokenizeRequest>,
) -> Result<Response, ApiError> {
    let credential = state
        .tokenization
        .detokenize(payload)
        .await
        .map_err(ApiError::from_service)?;

    build_json_response(
        StatusCode::OK,
        &credential,
        &headers,
        state.response_signing_key.as_deref(),
    )
}

async fn oauth_metadata(State(state): State<AppState>) -> Response {
    let Some(oauth) = state.oauth.as_ref() else {
        return oauth_unavailable();
    };

    let metadata = oauth.metadata();
    (StatusCode::OK, Json(metadata)).into_response()
}

async fn oauth_authorize(
    State(state): State<AppState>,
    Query(params): Query<AuthorizationRequest>,
) -> Response {
    let Some(oauth) = state.oauth.as_ref() else {
        return oauth_unavailable();
    };

    match oauth.authorize(params).await {
        Ok(outcome) => match build_redirect_uri(
            &outcome.redirect_uri,
            &outcome.code,
            outcome.state.as_deref(),
        ) {
            Ok(uri) => Redirect::temporary(&uri).into_response(),
            Err(err) => err.into_response(),
        },
        Err(err) => err.into_response(),
    }
}

async fn oauth_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(payload): Form<TokenRequest>,
) -> Response {
    let Some(oauth) = state.oauth.as_ref() else {
        return oauth_unavailable();
    };

    let (client_id, client_secret) = match parse_basic_auth(&headers) {
        Ok(value) => value,
        Err(err) => return err.into_response(),
    };

    if let Err(err) = oauth.validate_client(&client_id, &client_secret) {
        return err.into_response();
    }

    match oauth.exchange_code(&client_id, payload).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => err.into_response(),
    }
}

async fn oauth_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(payload): Form<RevocationRequest>,
) -> Response {
    let Some(oauth) = state.oauth.as_ref() else {
        return oauth_unavailable();
    };

    let (client_id, client_secret) = match parse_basic_auth(&headers) {
        Ok(value) => value,
        Err(err) => return err.into_response(),
    };

    if let Err(err) = oauth.validate_client(&client_id, &client_secret) {
        return err.into_response();
    }

    if let Err(err) = oauth.revoke(&payload.token).await {
        return err.into_response();
    }

    StatusCode::OK.into_response()
}

async fn ucp_agent_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Response {
    if request.method() == Method::OPTIONS {
        return next.run(request).await;
    }
    let header_value = match headers.get("UCP-Agent") {
        Some(value) => match value.to_str() {
            Ok(raw) => Some(raw),
            Err(_) => {
                return json_error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_ucp_agent",
                    "UCP-Agent header must be valid ASCII",
                )
            }
        },
        None => {
            if state.require_ucp_agent {
                return json_error_response(
                    StatusCode::BAD_REQUEST,
                    "missing_ucp_agent",
                    "UCP-Agent header is required",
                );
            }
            None
        }
    };

    let negotiated = match negotiate(
        header_value,
        state.business_capabilities.as_ref(),
        &state.business_version,
        state.profile_cache.as_ref(),
    )
    .await
    {
        Ok(result) => result,
        Err(err) => return negotiation_error_response(err),
    };

    request
        .extensions_mut()
        .insert(UcpRequestContext { negotiated });

    next.run(request).await
}

async fn request_signature_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    if method != Method::POST && method != Method::PUT {
        return next.run(request).await;
    }

    let signature_header = headers.get("Request-Signature").and_then(|value| {
        value
            .to_str()
            .ok()
            .map(|raw| raw.trim())
            .filter(|raw| !raw.is_empty())
    });

    if signature_header.is_none() && !state.require_request_signature {
        return next.run(request).await;
    }

    let signature = match signature_header {
        Some(value) => value,
        None => {
            return json_error_response(
                StatusCode::BAD_REQUEST,
                "missing_request_signature",
                "Request-Signature header is required",
            )
        }
    };

    let cached_body = request
        .extensions()
        .get::<CachedBody>()
        .map(|cached| cached.0.clone());

    let (mut parts, body) = request.into_parts();
    let body_bytes = match cached_body {
        Some(bytes) => bytes,
        None => match axum::body::to_bytes(body, MAX_REQUEST_BODY_BYTES).await {
            Ok(bytes) => {
                parts.extensions.insert(CachedBody(bytes.clone()));
                bytes
            }
            Err(err) => {
                warn!("Failed to read request body: {}", err);
                return json_error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "payload_too_large",
                    &format!("Request body exceeds {} bytes", MAX_REQUEST_BODY_BYTES),
                );
            }
        },
    };

    let context = parts.extensions.get::<UcpRequestContext>().cloned();
    let Some(context) = context else {
        return json_error_response(
            StatusCode::BAD_REQUEST,
            "missing_ucp_agent",
            "UCP-Agent negotiation is required for request signatures",
        );
    };

    if context.negotiated.platform_signing_keys.is_empty() {
        return json_error_response(
            StatusCode::BAD_REQUEST,
            "signature_keys_unavailable",
            "Platform signing keys are required to verify Request-Signature",
        );
    }

    if let Err(message) = verify_request_signature(
        signature,
        &body_bytes,
        &context.negotiated.platform_signing_keys,
    ) {
        return json_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_signature",
            &message,
        );
    }

    let request = Request::from_parts(parts, Body::from(body_bytes));
    next.run(request).await
}

async fn require_headers_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();

    if state.require_request_id && headers.get("Request-Id").is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "type": "invalid_request",
                "code": "missing_request_id",
                "message": "Request-Id header is required"
            })),
        )
            .into_response();
    }

    if state.require_idempotency
        && (method == axum::http::Method::POST || method == axum::http::Method::PUT)
        && headers.get("Idempotency-Key").is_none()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "type": "invalid_request",
                "code": "missing_idempotency_key",
                "message": "Idempotency-Key header is required"
            })),
        )
            .into_response();
    }

    next.run(request).await
}

async fn response_headers_middleware(
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let request_id = headers.get("Request-Id").cloned();
    let idempotency_key = headers.get("Idempotency-Key").cloned();

    let mut response = next.run(request).await;
    let response_headers = response.headers_mut();

    if let Some(value) = request_id {
        if response_headers.get("request-id").is_none() {
            response_headers.insert(HeaderName::from_static("request-id"), value);
        }
    }

    if let Some(value) = idempotency_key {
        if response_headers.get("idempotency-key").is_none() {
            response_headers.insert(HeaderName::from_static("idempotency-key"), value);
        }
    }

    response
}

async fn a2a_extensions_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    if request.method() == Method::OPTIONS {
        return next.run(request).await;
    }

    let expected = format!(
        "https://ucp.dev/specification/reference?v={}",
        state.business_version
    );

    let header_value = headers.get("X-A2A-Extensions").and_then(|value| value.to_str().ok());
    let has_extension = header_value
        .map(|value| value.split(',').any(|entry| entry.trim() == expected))
        .unwrap_or(false);

    if !has_extension {
        return json_error_response(
            StatusCode::BAD_REQUEST,
            "missing_a2a_extensions",
            "X-A2A-Extensions header must include the UCP extension URI",
        );
    }

    next.run(request).await
}

fn verify_request_signature(
    signature: &str,
    payload: &[u8],
    keys: &[crypto::VerifyingKey],
) -> Result<(), String> {
    let jws = DetachedJws::from_compact(signature)
        .map_err(|err| format!("Invalid detached JWS: {}", err))?;
    let header = jws
        .header()
        .map_err(|err| format!("Invalid JWS header: {}", err))?;

    let candidates: Vec<&crypto::VerifyingKey> = match header.kid.as_deref() {
        Some(kid) => keys.iter().filter(|key| key.kid == kid).collect(),
        None => keys.iter().collect(),
    };

    if candidates.is_empty() {
        return Err("No matching signing key found for Request-Signature".to_string());
    }

    for key in candidates {
        if verify_detached(&jws, payload, key).is_ok() {
            return Ok(());
        }
    }

    Err("Request-Signature verification failed".to_string())
}

fn negotiation_error_response(err: NegotiationError) -> Response {
    match err {
        NegotiationError::MissingUcpAgentHeader => json_error_response(
            StatusCode::BAD_REQUEST,
            "missing_ucp_agent",
            "UCP-Agent header is required",
        ),
        NegotiationError::InvalidUcpAgentFormat(message) => json_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_ucp_agent",
            &format!("Invalid UCP-Agent header: {}", message),
        ),
        NegotiationError::MissingProfileUrl => json_error_response(
            StatusCode::BAD_REQUEST,
            "missing_profile",
            "UCP-Agent profile is required",
        ),
        NegotiationError::VersionNotSupported {
            platform_version,
            business_version,
        } => json_error_response(
            StatusCode::BAD_REQUEST,
            "version_not_supported",
            &format!(
                "Platform version {} is newer than business version {}",
                platform_version, business_version
            ),
        ),
        NegotiationError::ProfileFetchError(message)
        | NegotiationError::InvalidProfile(message)
        | NegotiationError::HttpError(message) => json_error_response(
            StatusCode::BAD_GATEWAY,
            "profile_unavailable",
            &message,
        ),
    }
}

fn json_error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "type": "invalid_request",
            "code": code,
            "message": message
        })),
    )
        .into_response()
}

fn oauth_unavailable() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "unsupported",
            "error_description": "OAuth is not enabled on this handler"
        })),
    )
        .into_response()
}

fn build_json_response<T: Serialize>(
    status: StatusCode,
    body: &T,
    request_headers: &HeaderMap,
    signing_key: Option<&SigningKey>,
) -> Result<Response, ApiError> {
    let json_value = serde_json::to_value(body).map_err(|err| {
        warn!("Failed to serialize response: {}", err);
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "serialization_error",
            "Failed to serialize response",
            None,
        )
    })?;

    let json_body = serde_json::to_vec(&json_value).map_err(|err| {
        warn!("Failed to serialize response: {}", err);
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "serialization_error",
            "Failed to serialize response",
            None,
        )
    })?;

    let mut response = Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(json_body))
        .map_err(|err| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "response_build_failed",
                &format!("Failed to build response: {}", err),
                None,
            )
        })?;

    let response_headers = response.headers_mut();
    for key in ["Idempotency-Key", "Request-Id"] {
        if let Some(value) = request_headers.get(key) {
            if let Ok(header_name) = HeaderName::from_bytes(key.as_bytes()) {
                response_headers.insert(header_name, value.clone());
            }
        }
    }

    if let Some(request_id) = request_headers.get("Request-Id") {
        response_headers.insert(
            HeaderName::from_static("request-id"),
            HeaderValue::from_bytes(request_id.as_bytes()).unwrap_or(HeaderValue::from_static("")),
        );
    }

    if let Some(signing_key) = signing_key {
        let canonical = canonicalize(&json_value).map_err(|err| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "response_signing_failed",
                &format!("Failed to canonicalize response: {}", err),
                None,
            )
        })?;

        let jws = sign_detached(&canonical, signing_key).map_err(|err| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "response_signing_failed",
                &format!("Failed to sign response: {}", err),
                None,
            )
        })?;

        response_headers.insert(
            HeaderName::from_static("x-detached-jwt"),
            HeaderValue::from_str(&jws.to_compact()).unwrap_or(HeaderValue::from_static("")),
        );
    }

    Ok(response)
}

/// MCP JSON-RPC 2.0 endpoint handler
async fn mcp_handler_endpoint(
    State(state): State<AppState>,
    Json(request): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let Some(profile_url) = extract_profile_url(&request.params) else {
        let response = mcp_error_response(
            request.id,
            mcp_error_codes::INVALID_PARAMS,
            "Missing _meta.ucp.profile",
            "missing_ucp_profile",
        );
        return (StatusCode::OK, Json(response));
    };

    let header_value = format!("profile=\"{}\"", profile_url);
    let negotiated = match negotiate(
        Some(header_value.as_str()),
        state.business_capabilities.as_ref(),
        &state.business_version,
        state.profile_cache.as_ref(),
    )
    .await
    {
        Ok(result) => result,
        Err(err) => {
            let response = mcp_error_response(
                request.id,
                mcp_error_codes::INVALID_PARAMS,
                &format!("Negotiation failed: {}", err),
                negotiation_error_code(&err),
            );
            return (StatusCode::OK, Json(response));
        }
    };

    let response = state
        .mcp_handler
        .handle_with_context(request, Some(&negotiated))
        .await;
    (StatusCode::OK, Json(response))
}

fn mcp_error_response(
    id: serde_json::Value,
    code: i32,
    message: &str,
    ucp_code: &str,
) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.to_string(),
            data: Some(serde_json::json!({
                "status": "error",
                "errors": [
                    {
                        "code": ucp_code,
                        "message": message,
                        "severity": "recoverable"
                    }
                ]
            })),
        }),
        id,
    }
}

fn negotiation_error_code(err: &NegotiationError) -> &'static str {
    match err {
        NegotiationError::MissingUcpAgentHeader => "missing_ucp_agent",
        NegotiationError::InvalidUcpAgentFormat(_) => "invalid_ucp_agent",
        NegotiationError::MissingProfileUrl => "missing_ucp_profile",
        NegotiationError::ProfileFetchError(_) => "profile_fetch_error",
        NegotiationError::InvalidProfile(_) => "invalid_profile",
        NegotiationError::VersionNotSupported { .. } => "version_unsupported",
        NegotiationError::HttpError(_) => "http_error",
    }
}

/// MCP OpenRPC schema endpoint
async fn mcp_schema() -> impl IntoResponse {
    let schema = mcp::openrpc_schema();
    (StatusCode::OK, Json(schema))
}

/// A2A Agent Card endpoint
async fn agent_card(State(state): State<AppState>) -> impl IntoResponse {
    let card = state.a2a_handler.agent_card();
    (StatusCode::OK, Json(card))
}

/// A2A message handler endpoint
async fn a2a_handler_endpoint(
    State(state): State<AppState>,
    Extension(context): Extension<UcpRequestContext>,
    Json(message): Json<A2AMessage>,
) -> impl IntoResponse {
    let response = state
        .a2a_handler
        .handle_with_context(message, Some(&context.negotiated))
        .await;
    (StatusCode::OK, Json(response))
}

/// Embedded Protocol checkout handler
async fn embedded_checkout(
    State(state): State<AppState>,
    Path(checkout_id): Path<String>,
    Query(params): Query<EmbeddedParams>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if state.auth.requires_auth() {
        let token = extract_auth_token(&headers).or_else(|| params.auth.clone());
        let Some(token) = token else {
            let page = embedded_error_page(
                "Unauthorized",
                "Missing authentication credentials for embedded checkout.",
            );
            return (StatusCode::UNAUTHORIZED, Html(page));
        };

        if !state.auth.validate_token(&token).await {
            let page = embedded_error_page(
                "Unauthorized",
                "Invalid authentication token for embedded checkout.",
            );
            return (StatusCode::UNAUTHORIZED, Html(page));
        }
    }

    if let Some(version) = params.version.as_deref() {
        if version != state.business_version {
            let page = embedded_error_page(
                "Unsupported Version",
                &format!(
                    "Embedded checkout version {} is not supported. Expected {}.",
                    version, state.business_version
                ),
            );
            return (StatusCode::BAD_REQUEST, Html(page));
        }
    }

    let checkout = match state.service.get_checkout(&checkout_id).await {
        Ok(checkout) => checkout,
        Err(err) => {
            let page = embedded_error_page("Checkout Not Found", &err.to_string());
            return (StatusCode::NOT_FOUND, Html(page));
        }
    };

    let requested_delegations = params.requested_delegations();
    let accepted = accepted_delegations(&requested_delegations);
    let checkout_json = serde_json::to_string(&checkout).unwrap_or_else(|_| "{}".to_string());
    let page = render_embedded_page(&checkout_json, params.version.as_deref(), &accepted);
    (StatusCode::OK, Html(page))
}

fn extract_auth_token(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers.get("Authorization") {
        if let Ok(header) = value.to_str() {
            if let Some(token) = header.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }

    if let Some(value) = headers.get("X-API-Key") {
        if let Ok(header) = value.to_str() {
            return Some(header.to_string());
        }
    }

    None
}

fn embedded_error_page(title: &str, message: &str) -> String {
    let title = escape_html(title);
    let message = escape_html(message);

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>
    body {{
      font-family: "SF Pro Text", "Segoe UI", Arial, sans-serif;
      margin: 0;
      padding: 24px;
      background: #fff4f0;
      color: #1f2933;
    }}
    main {{
      max-width: 680px;
      margin: 0 auto;
      background: #ffffff;
      border: 1px solid #fed7c7;
      border-radius: 12px;
      padding: 24px;
      box-shadow: 0 10px 28px rgba(31, 41, 51, 0.08);
    }}
    h1 {{
      margin: 0 0 8px 0;
      font-size: 20px;
    }}
    p {{
      margin: 0;
      color: #7f1d1d;
      font-size: 14px;
    }}
  </style>
</head>
<body>
  <main>
    <h1>{title}</h1>
    <p>{message}</p>
  </main>
</body>
</html>
"#,
        title = title,
        message = message,
    )
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
        .replace('\'', "&#39;")
}
