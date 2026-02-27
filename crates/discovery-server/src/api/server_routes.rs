//! Маршруты для серверов кластера: регистрация, heartbeat, список, удаление.

use crate::api::middleware::{create_server_token, AuthenticatedServer};
use crate::api::AppState;
use crate::error::AppError;
use crate::services::registry_service::{
    self, delete_server, get_cluster_servers, heartbeat, RegisterData,
};
use axum::extract::{Path, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub server_id: String,
    pub cluster_id: String,
    pub public_url: String,
    pub version: String,
    pub public_key: String,
    pub timestamp: String,
    pub cluster_secret_hmac: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResponse {
    pub token: String,
    pub server_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatRequest {
    pub server_id: String,
    pub peer_count: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub server_id: String,
    pub public_url: String,
    pub public_key: String,
    pub version: String,
    pub last_seen: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClusterResponse {
    pub servers: Vec<ServerInfo>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/servers/register", post(register))
        .route("/servers/heartbeat", post(do_heartbeat))
        .route("/cluster/{cluster_id}", get(get_cluster))
        .route("/servers/{server_id}", delete(deregister))
}

/// POST /api/v1/servers/register — регистрация сервера через HMAC.
async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
    // Защита от replay-атак: timestamp не старше 5 минут
    if !registry_service::verify_timestamp(&req.timestamp) {
        return Err(AppError::Unauthorized(
            "Timestamp устарел или недействителен (более 5 минут)".into(),
        ));
    }

    // Проверка HMAC — cluster_secret берём из env по cluster_id
    let cluster_secret = get_cluster_secret(&req.cluster_id)?;
    if !registry_service::verify_hmac(
        &cluster_secret,
        &req.server_id,
        &req.cluster_id,
        &req.public_url,
        &req.timestamp,
        &req.cluster_secret_hmac,
    ) {
        return Err(AppError::Unauthorized("Неверный HMAC".into()));
    }

    let server_id = registry_service::register_server(
        &state.db,
        RegisterData {
            server_id: req.server_id,
            cluster_id: req.cluster_id.clone(),
            public_url: req.public_url,
            version: req.version,
            public_key: req.public_key,
        },
    )
    .await?;

    let token = create_server_token(&server_id, &req.cluster_id, &state.jwt_secret)?;
    tracing::info!("Сервер зарегистрирован: {server_id}");

    Ok(Json(RegisterResponse { token, server_id }))
}

/// POST /api/v1/servers/heartbeat — обновление last_seen.
async fn do_heartbeat(
    State(state): State<AppState>,
    AuthenticatedServer(claims): AuthenticatedServer,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    // server_id из токена должен совпадать с запросом
    if claims.sub != req.server_id {
        return Err(AppError::Unauthorized(
            "server_id не совпадает с токеном".into(),
        ));
    }

    heartbeat(&state.db, &req.server_id).await?;
    tracing::debug!(
        "Heartbeat: сервер {} (peers: {})",
        req.server_id,
        req.peer_count
    );

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET /api/v1/cluster/{cluster_id} — список активных серверов кластера.
async fn get_cluster(
    State(state): State<AppState>,
    AuthenticatedServer(_claims): AuthenticatedServer,
    Path(cluster_id): Path<String>,
) -> Result<Json<ClusterResponse>, AppError> {
    let servers = get_cluster_servers(&state.db, &cluster_id).await?;

    let server_infos = servers
        .into_iter()
        .map(|s| ServerInfo {
            server_id: s.server_id,
            public_url: s.public_url,
            public_key: s.public_key,
            version: s.version,
            last_seen: s.last_seen,
        })
        .collect();

    Ok(Json(ClusterResponse {
        servers: server_infos,
    }))
}

/// DELETE /api/v1/servers/{server_id} — удаление сервера.
async fn deregister(
    State(state): State<AppState>,
    AuthenticatedServer(claims): AuthenticatedServer,
    Path(server_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Сервер может удалить только себя
    if claims.sub != server_id {
        return Err(AppError::Unauthorized("Нельзя удалить чужой сервер".into()));
    }

    delete_server(&state.db, &server_id).await?;
    tracing::info!("Сервер удалён: {server_id}");

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Получить cluster_secret по cluster_id (из env переменной CLUSTER_SECRET_{CLUSTER_ID}).
fn get_cluster_secret(cluster_id: &str) -> Result<String, AppError> {
    // Конвертируем cluster_id в имя env переменной: "acme-corp" → "CLUSTER_SECRET_ACME_CORP"
    let env_key = format!(
        "CLUSTER_SECRET_{}",
        cluster_id
            .to_uppercase()
            .replace(['-', '.'], "_")
    );

    std::env::var(&env_key).map_err(|_| {
        AppError::Unauthorized(format!(
            "Неизвестный кластер или не задан секрет: {cluster_id}"
        ))
    })
}
