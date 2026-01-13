#![allow(clippy::result_large_err)]

use crate::{
    auth::AuthConfig,
    errors::ServiceError,
    models::{
        CheckoutCompleteRequest, CheckoutCreateRequest, CheckoutUpdateRequest, DetokenizeRequest,
        TokenizeRequest,
    },
    service::CheckoutService,
    tokenization::TokenizationService,
    AppState,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::info;

pub mod proto {
    tonic::include_proto!("ucp_handler.v1");
    pub const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("ucp_handler_descriptor");
}

#[derive(Clone)]
struct GrpcUcpHandler {
    service: CheckoutService,
    tokenization: Arc<TokenizationService>,
    auth: Arc<AuthConfig>,
}

impl GrpcUcpHandler {
    fn new(state: AppState) -> Self {
        let (service, auth, tokenization) = state.grpc_parts();
        Self {
            service,
            tokenization,
            auth,
        }
    }

    async fn authenticate<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if !self.auth.requires_auth() {
            return Ok(());
        }

        let metadata = request.metadata();
        let token = if let Some(value) = metadata.get("authorization") {
            let header = value
                .to_str()
                .map_err(|_| Status::unauthenticated("invalid authorization metadata"))?;
            header
                .strip_prefix("Bearer ")
                .ok_or_else(|| Status::unauthenticated("authorization must be Bearer <token>"))?
                .to_string()
        } else if let Some(value) = metadata.get("x-api-key") {
            value
                .to_str()
                .map_err(|_| Status::unauthenticated("invalid api key metadata"))?
                .to_string()
        } else {
            return Err(Status::unauthenticated("missing authorization metadata"));
        };

        if self.auth.validate_token(&token).await {
            Ok(())
        } else {
            Err(Status::unauthenticated("invalid credentials"))
        }
    }
}

fn map_service_error(err: ServiceError) -> Status {
    match err {
        ServiceError::InvalidInput(message) => Status::invalid_argument(message),
        ServiceError::NotFound(message) => Status::not_found(message),
        ServiceError::Conflict(message) => Status::already_exists(message),
        ServiceError::InvalidState(message) => Status::failed_precondition(message),
        ServiceError::External(message) => Status::unavailable(message),
        ServiceError::Internal(message) => Status::internal(message),
    }
}

fn required_non_empty(value: &str, field: &'static str) -> Result<(), Status> {
    if value.trim().is_empty() {
        return Err(Status::invalid_argument(format!("{field} is required")));
    }
    Ok(())
}

fn parse_json_value(bytes: &[u8], field: &'static str) -> Result<serde_json::Value, Status> {
    if bytes.is_empty() {
        return Err(Status::invalid_argument(format!("{field} is required")));
    }

    serde_json::from_slice(bytes)
        .map_err(|err| Status::invalid_argument(format!("{field} must be valid JSON: {err}")))
}

fn parse_json<T: DeserializeOwned>(bytes: &[u8], field: &'static str) -> Result<T, Status> {
    if bytes.is_empty() {
        return Err(Status::invalid_argument(format!("{field} is required")));
    }

    serde_json::from_slice(bytes)
        .map_err(|err| Status::invalid_argument(format!("{field} must be valid JSON: {err}")))
}

fn encode_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Status> {
    serde_json::to_vec(value)
        .map_err(|err| Status::internal(format!("failed to serialize response: {err}")))
}

fn parse_update_payload(
    id: &str,
    bytes: &[u8],
) -> Result<CheckoutUpdateRequest, Status> {
    let value = parse_json_value(bytes, "payload_json")?;
    let mut map = match value {
        serde_json::Value::Object(map) => map,
        _ => {
            return Err(Status::invalid_argument(
                "payload_json must be a JSON object",
            ))
        }
    };

    if let Some(existing) = map.get("id") {
        match existing {
            serde_json::Value::String(existing_id) if existing_id == id => {}
            serde_json::Value::String(_) => {
                return Err(Status::invalid_argument(
                    "payload_json id does not match request id",
                ))
            }
            _ => {
                return Err(Status::invalid_argument(
                    "payload_json id must be a string",
                ))
            }
        }
    } else {
        map.insert("id".to_string(), serde_json::Value::String(id.to_string()));
    }

    serde_json::from_value(serde_json::Value::Object(map))
        .map_err(|err| Status::invalid_argument(format!("payload_json must be valid checkout update: {err}")))
}

#[tonic::async_trait]
impl proto::ucp_handler_server::UcpHandler for GrpcUcpHandler {
    async fn create_checkout_session(
        &self,
        request: Request<proto::CheckoutCreateRequest>,
    ) -> Result<Response<proto::CheckoutResponse>, Status> {
        self.authenticate(&request).await?;
        let payload = parse_json::<CheckoutCreateRequest>(
            &request.get_ref().payload_json,
            "payload_json",
        )?;
        let checkout = self
            .service
            .create_checkout(payload)
            .await
            .map_err(map_service_error)?;
        Ok(Response::new(proto::CheckoutResponse {
            payload_json: encode_json(&checkout)?,
        }))
    }

    async fn get_checkout_session(
        &self,
        request: Request<proto::CheckoutGetRequest>,
    ) -> Result<Response<proto::CheckoutResponse>, Status> {
        self.authenticate(&request).await?;
        let id = request.get_ref().id.trim();
        required_non_empty(id, "id")?;
        let checkout = self
            .service
            .get_checkout(id)
            .await
            .map_err(map_service_error)?;
        Ok(Response::new(proto::CheckoutResponse {
            payload_json: encode_json(&checkout)?,
        }))
    }

    async fn update_checkout_session(
        &self,
        request: Request<proto::CheckoutUpdateRequest>,
    ) -> Result<Response<proto::CheckoutResponse>, Status> {
        self.authenticate(&request).await?;
        let id = request.get_ref().id.trim();
        required_non_empty(id, "id")?;
        let payload = parse_update_payload(id, &request.get_ref().payload_json)?;
        let checkout = self
            .service
            .update_checkout(id, payload)
            .await
            .map_err(map_service_error)?;
        Ok(Response::new(proto::CheckoutResponse {
            payload_json: encode_json(&checkout)?,
        }))
    }

    async fn complete_checkout_session(
        &self,
        request: Request<proto::CheckoutCompleteRequest>,
    ) -> Result<Response<proto::CheckoutResponse>, Status> {
        self.authenticate(&request).await?;
        let id = request.get_ref().id.trim();
        required_non_empty(id, "id")?;
        let payload = parse_json::<CheckoutCompleteRequest>(
            &request.get_ref().payload_json,
            "payload_json",
        )?;
        let checkout = self
            .service
            .complete_checkout(id, payload)
            .await
            .map_err(map_service_error)?;
        Ok(Response::new(proto::CheckoutResponse {
            payload_json: encode_json(&checkout)?,
        }))
    }

    async fn cancel_checkout_session(
        &self,
        request: Request<proto::CheckoutCancelRequest>,
    ) -> Result<Response<proto::CheckoutResponse>, Status> {
        self.authenticate(&request).await?;
        let id = request.get_ref().id.trim();
        required_non_empty(id, "id")?;
        let checkout = self
            .service
            .cancel_checkout(id)
            .await
            .map_err(map_service_error)?;
        Ok(Response::new(proto::CheckoutResponse {
            payload_json: encode_json(&checkout)?,
        }))
    }

    async fn tokenize(
        &self,
        request: Request<proto::TokenizeRequest>,
    ) -> Result<Response<proto::TokenizeResponse>, Status> {
        self.authenticate(&request).await?;
        let payload =
            parse_json::<TokenizeRequest>(&request.get_ref().payload_json, "payload_json")?;
        let response = self
            .tokenization
            .tokenize(payload)
            .await
            .map_err(map_service_error)?;
        Ok(Response::new(proto::TokenizeResponse {
            payload_json: encode_json(&response)?,
        }))
    }

    async fn detokenize(
        &self,
        request: Request<proto::DetokenizeRequest>,
    ) -> Result<Response<proto::DetokenizeResponse>, Status> {
        self.authenticate(&request).await?;
        let payload =
            parse_json::<DetokenizeRequest>(&request.get_ref().payload_json, "payload_json")?;
        let credential = self
            .tokenization
            .detokenize(payload)
            .await
            .map_err(map_service_error)?;
        Ok(Response::new(proto::DetokenizeResponse {
            payload_json: encode_json(&credential)?,
        }))
    }
}

pub async fn serve(
    addr: SocketAddr,
    state: AppState,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), Box<dyn std::error::Error>> {
    let handler = GrpcUcpHandler::new(state);

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<proto::ucp_handler_server::UcpHandlerServer<GrpcUcpHandler>>()
        .await;

    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::FILE_DESCRIPTOR_SET)
        .build_v1()?;

    info!("gRPC server listening on {}", addr);

    tonic::transport::Server::builder()
        .add_service(health_service)
        .add_service(reflection_service)
        .add_service(proto::ucp_handler_server::UcpHandlerServer::new(handler))
        .serve_with_shutdown(addr, shutdown)
        .await?;

    Ok(())
}
