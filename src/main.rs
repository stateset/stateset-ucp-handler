use axum::{
    extract::{Form, Path, Query, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
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
mod validation;
mod webhook;

use a2a::{A2AHandler, A2AMessage};
use auth::{auth_middleware, AuthConfig};
use config::Config;
use constants::MAX_REQUEST_BODY_BYTES;
use crypto::{load_signing_key_from_private, JwkPrivateKey};
use embedded::{EmbeddedHandler, EmbeddedParams};
use errors::ApiError;
use events::{Event, EventSender};
use idempotency::{idempotency_middleware, IdempotencyStore};
use mcp::{JsonRpcRequest, McpHandler};
use models::{
    CheckoutCompleteRequest, CheckoutCreateRequest, CheckoutUpdateRequest, DetokenizeRequest,
    OrderEvent, TokenizeRequest,
};
use negotiation::ProfileCache;
use oauth::{
    build_redirect_uri, parse_basic_auth, AuthorizationRequest, OAuthConfig, OAuthService,
    RevocationRequest, TokenRequest,
};
use service::CheckoutService;
use store::CheckoutStore;
use tokenization::TokenizationService;
use webhook::OrderWebhook;
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
    oauth: Option<Arc<OAuthService>>,
    tokenization: Arc<TokenizationService>,
    profile_cache: Arc<ProfileCache>,
    mcp_handler: Arc<McpHandler>,
    a2a_handler: Arc<A2AHandler>,
    embedded_handler: Arc<EmbeddedHandler>,
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

    let store = CheckoutStore::new();
    let catalog = catalog::ProductCatalog::new();

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
            let jwk: JwkPrivateKey = serde_json::from_str(raw).ok()?;
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
        event_sender.clone(),
        config.ucp_version.clone(),
        config.service_version.clone(),
        config.base_url.clone(),
        config.session_ttl_seconds,
        config.tax_bps,
        signing_keys,
        config.oauth_enabled,
        config.buyer_consent_enabled,
        config.ap2_enabled,
        config.ap2_merchant_authorization.clone(),
        ap2_signing_key,
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

    let idempotency_store = if config.require_idempotency || !config.api_keys.is_empty() {
        Some(Arc::new(IdempotencyStore::new(std::time::Duration::from_secs(
            86400,
        ))))
    } else {
        None
    };

    // Profile cache for platform profile negotiation (1 hour TTL)
    let profile_cache = Arc::new(ProfileCache::new(Duration::from_secs(3600)));

    // MCP handler for JSON-RPC transport
    let mcp_handler = Arc::new(McpHandler::new(service.clone()));

    // A2A handler for agent-to-agent transport
    let a2a_handler = Arc::new(A2AHandler::new(
        service.clone(),
        config.base_url.clone(),
        config.ucp_version.clone(),
    ));

    // Embedded protocol handler
    let embedded_handler = Arc::new(EmbeddedHandler::new(
        service.clone(),
        config.base_url.clone(),
    ));

    let state = AppState {
        service,
        auth,
        idempotency: idempotency_store,
        require_idempotency: config.require_idempotency,
        require_request_id: config.require_request_id,
        oauth: oauth_service.clone(),
        tokenization,
        profile_cache,
        mcp_handler,
        a2a_handler,
        embedded_handler,
    };

    let webhook_sender = OrderWebhook::new(
        config.order_webhook_url.clone(),
        config.order_webhook_api_key.clone(),
        config.webhook_signature.clone(),
    );

    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            match event {
                Event::OrderCreated { order } => {
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
        .layer(middleware::from_fn_with_state(
            state.clone(),
            idempotency_middleware,
        ))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_headers_middleware,
        ));

    let tokenization_router = Router::new()
        .route("/tokenize", post(tokenize))
        .route("/detokenize", post(detokenize))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_headers_middleware,
        ));

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
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    idempotency_middleware,
                ))
                .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    require_headers_middleware,
                )),
        )
        .route("/schemas/shopping/mcp.openrpc.json", get(mcp_schema));
    app = app.merge(mcp_router);

    // A2A (Agent-to-Agent) transport
    let a2a_router = Router::new()
        .route("/.well-known/agent-card.json", get(agent_card))
        .route(
            "/a2a",
            post(a2a_handler_endpoint)
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    idempotency_middleware,
                ))
                .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    require_headers_middleware,
                )),
        );
    app = app.merge(a2a_router);

    // Embedded Protocol
    let embedded_router = Router::new().route(
        "/checkout/:id/embedded",
        get(embedded_checkout)
            .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                require_headers_middleware,
            )),
    );
    app = app.merge(embedded_router);

    let grpc_state = state.clone();
    let app = app
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES))
        .layer(CompressionLayer::new())
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
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
    headers: HeaderMap,
    Json(payload): Json<CheckoutCreateRequest>,
) -> Result<Response, ApiError> {
    let checkout = state
        .service
        .create_checkout(payload)
        .await
        .map_err(ApiError::from_service)?;

    build_json_response(StatusCode::CREATED, &checkout, &headers)
}

async fn get_checkout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(checkout_id): Path<String>,
) -> Result<Response, ApiError> {
    let checkout = state
        .service
        .get_checkout(&checkout_id)
        .await
        .map_err(ApiError::from_service)?;

    build_json_response(StatusCode::OK, &checkout, &headers)
}

async fn update_checkout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(checkout_id): Path<String>,
    Json(payload): Json<CheckoutUpdateRequest>,
) -> Result<Response, ApiError> {
    let checkout = state
        .service
        .update_checkout(&checkout_id, payload)
        .await
        .map_err(ApiError::from_service)?;

    build_json_response(StatusCode::OK, &checkout, &headers)
}

async fn complete_checkout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(checkout_id): Path<String>,
    Json(payload): Json<CheckoutCompleteRequest>,
) -> Result<Response, ApiError> {
    let checkout = state
        .service
        .complete_checkout(&checkout_id, payload)
        .await
        .map_err(ApiError::from_service)?;

    build_json_response(StatusCode::OK, &checkout, &headers)
}

async fn cancel_checkout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(checkout_id): Path<String>,
) -> Result<Response, ApiError> {
    let checkout = state
        .service
        .cancel_checkout(&checkout_id)
        .await
        .map_err(ApiError::from_service)?;

    build_json_response(StatusCode::OK, &checkout, &headers)
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

    build_json_response(StatusCode::OK, &response, &headers)
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

    build_json_response(StatusCode::OK, &credential, &headers)
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
) -> Result<Response, ApiError> {
    let json_body = serde_json::to_vec(body).map_err(|err| {
        warn!("Failed to serialize response: {}", err);
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "serialization_error", "Failed to serialize response", None)
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

    Ok(response)
}

/// MCP JSON-RPC 2.0 endpoint handler
async fn mcp_handler_endpoint(
    State(state): State<AppState>,
    Json(request): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let response = state.mcp_handler.handle(request).await;
    (StatusCode::OK, Json(response))
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
    Json(message): Json<A2AMessage>,
) -> impl IntoResponse {
    let response = state.a2a_handler.handle(message).await;
    (StatusCode::OK, Json(response))
}

/// Embedded Protocol checkout handler
async fn embedded_checkout(
    State(state): State<AppState>,
    Path(checkout_id): Path<String>,
    Query(params): Query<EmbeddedParams>,
) -> impl IntoResponse {
    // Override session_id with path parameter
    let params = EmbeddedParams {
        session_id: Some(checkout_id),
        ..params
    };
    let response = state.embedded_handler.handle(params).await;
    (StatusCode::OK, Json(response))
}
