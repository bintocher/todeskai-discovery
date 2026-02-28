//! Маршруты для серверов: регистрация (cluster HMAC и simple), heartbeat, список, удаление, resolve.

use crate::api::middleware::{create_server_token, AuthenticatedServer};
use crate::api::AppState;
use crate::error::AppError;
use crate::services::registry_service::{
    self, delete_server, get_cluster_servers, get_server_by_id, heartbeat, RegisterData,
};
use axum::extract::{Path, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

// ── Типы запросов/ответов ────────────────────────────────────────────────────

/// Запрос кластерной регистрации (legacy HMAC-based).
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

/// Запрос простой регистрации (без cluster, для standalone серверов).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimpleRegisterRequest {
    pub server_id: String,
    pub public_url: String,
    pub version: String,
    pub public_key: String,
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

/// Запрос resolve сервера по ID.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveRequest {
    pub server_id: String,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/servers/register", post(register_cluster))
        .route("/servers/register/simple", post(register_simple))
        .route("/servers/heartbeat", post(do_heartbeat))
        .route("/servers/resolve", post(resolve_server))
        .route("/cluster/{cluster_id}", get(get_cluster))
        .route("/servers/{server_id}", delete(deregister))
}

// ── Обработчики ──────────────────────────────────────────────────────────────

/// POST /api/v1/servers/register — кластерная регистрация через HMAC (legacy).
async fn register_cluster(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
    // Защита от replay-атак: timestamp не старше 5 минут
    if !registry_service::verify_timestamp(&req.timestamp) {
        return Err(AppError::Unauthorized(
            "Timestamp устарел или недействителен (более 5 минут)".into(),
        ));
    }

    // Проверка HMAC
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
    tracing::info!(
        "Кластерная регистрация: {server_id} (cluster: {})",
        req.cluster_id
    );

    Ok(Json(RegisterResponse { token, server_id }))
}

/// POST /api/v1/servers/register/simple — простая регистрация без cluster (для standalone серверов).
///
/// Любой сервер может зарегистрироваться, указав только свой server_id и public_key.
/// cluster_id устанавливается в "" (standalone).
async fn register_simple(
    State(state): State<AppState>,
    Json(req): Json<SimpleRegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
    if req.server_id.is_empty() || req.public_url.is_empty() {
        return Err(AppError::BadRequest(
            "server_id и public_url обязательны".into(),
        ));
    }

    // SSRF защита: схема + приватные IP
    validate_public_url(&req.public_url)?;

    let server_id = registry_service::register_server(
        &state.db,
        RegisterData {
            server_id: req.server_id.clone(),
            cluster_id: String::new(), // standalone
            public_url: req.public_url,
            version: req.version,
            public_key: req.public_key,
        },
    )
    .await?;

    let token = create_server_token(&server_id, "", &state.jwt_secret)?;
    tracing::info!("Простая регистрация: {server_id}");

    Ok(Json(RegisterResponse { token, server_id }))
}

/// POST /api/v1/servers/heartbeat — обновление last_seen.
async fn do_heartbeat(
    State(state): State<AppState>,
    AuthenticatedServer(claims): AuthenticatedServer,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if claims.sub != req.server_id {
        return Err(AppError::Unauthorized(
            "server_id не совпадает с токеном".into(),
        ));
    }

    heartbeat(&state.db, &req.server_id).await?;
    tracing::debug!("Heartbeat: {} (peers: {})", req.server_id, req.peer_count);

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// POST /api/v1/servers/resolve — резолвить Server ID → publicUrl + publicKey.
///
/// Требует Bearer JWT от зарегистрированного сервера.
/// Не логирует запросы в DB (privacy: нельзя отследить кто кого ищет).
async fn resolve_server(
    State(state): State<AppState>,
    AuthenticatedServer(_claims): AuthenticatedServer,
    Json(req): Json<ResolveRequest>,
) -> Result<Json<ServerInfo>, AppError> {
    if req.server_id.is_empty() {
        return Err(AppError::BadRequest("server_id обязателен".into()));
    }

    match get_server_by_id(&state.db, &req.server_id).await? {
        Some(server) => Ok(Json(ServerInfo {
            server_id: server.server_id,
            public_url: server.public_url,
            public_key: server.public_key,
            version: server.version,
            last_seen: server.last_seen,
        })),
        None => Err(AppError::NotFound(format!(
            "Сервер {} не найден",
            req.server_id
        ))),
    }
}

/// GET /api/v1/cluster/{cluster_id} — список активных серверов кластера (legacy).
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

/// DELETE /api/v1/servers/{server_id} — дерегистрация.
async fn deregister(
    State(state): State<AppState>,
    AuthenticatedServer(claims): AuthenticatedServer,
    Path(server_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    if claims.sub != server_id {
        return Err(AppError::Unauthorized("Нельзя удалить чужой сервер".into()));
    }

    delete_server(&state.db, &server_id).await?;
    tracing::info!("Сервер дерегистрирован: {server_id}");

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Валидация public_url: схема http(s) + блокировка приватных IP/localhost.
fn validate_public_url(url: &str) -> Result<(), AppError> {
    let parsed =
        url::Url::parse(url).map_err(|_| AppError::BadRequest("Некорректный URL".into()))?;

    match parsed.scheme() {
        "http" | "https" => {}
        _ => {
            return Err(AppError::BadRequest(
                "public_url должен начинаться с http:// или https://".into(),
            ))
        }
    }

    if let Some(host) = parsed.host_str() {
        let lower = host.to_lowercase();
        if lower == "localhost" || lower == "127.0.0.1" || lower == "::1" || lower == "0.0.0.0" {
            return Err(AppError::BadRequest(
                "public_url не может указывать на localhost".into(),
            ));
        }
        // Блокировка приватных IP-диапазонов
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            let is_private = match ip {
                std::net::IpAddr::V4(v4) => {
                    v4.is_private() || v4.is_loopback() || v4.is_link_local()
                }
                std::net::IpAddr::V6(v6) => v6.is_loopback(),
            };
            if is_private {
                return Err(AppError::BadRequest(
                    "public_url не может указывать на приватный IP".into(),
                ));
            }
        }
    } else {
        return Err(AppError::BadRequest("public_url не содержит хост".into()));
    }

    Ok(())
}

/// Получить cluster_secret из env.
fn get_cluster_secret(cluster_id: &str) -> Result<String, AppError> {
    let env_key = format!(
        "CLUSTER_SECRET_{}",
        cluster_id.to_uppercase().replace(['-', '.'], "_")
    );
    std::env::var(&env_key).map_err(|_| {
        AppError::Unauthorized(format!(
            "Неизвестный кластер или не задан секрет: {cluster_id}"
        ))
    })
}
