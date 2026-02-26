//! Административные маршруты: список серверов, статистика.

use crate::api::middleware::AdminUser;
use crate::api::AppState;
use crate::error::AppError;
use crate::services::admin_service;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerRow {
    pub id: String,
    pub server_id: String,
    pub cluster_id: String,
    pub public_url: String,
    pub version: String,
    pub last_seen: String,
    pub active: bool,
    pub registered_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsResponse {
    pub total: u64,
    pub active: u64,
    pub inactive: u64,
    pub clusters: usize,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/servers", get(list_servers))
        .route("/stats", get(get_stats))
}

/// GET /api/v1/admin/servers — список всех серверов (требует admin JWT).
async fn list_servers(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
) -> Result<Json<Vec<ServerRow>>, AppError> {
    let servers = admin_service::list_all_servers(&state.db).await?;

    let rows = servers
        .into_iter()
        .map(|s| ServerRow {
            id: s.id,
            server_id: s.server_id,
            cluster_id: s.cluster_id,
            public_url: s.public_url,
            version: s.version,
            last_seen: s.last_seen,
            active: s.active,
            registered_at: s.registered_at,
        })
        .collect();

    Ok(Json(rows))
}

/// GET /api/v1/admin/stats — статистика реестра (требует admin JWT).
async fn get_stats(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
) -> Result<Json<StatsResponse>, AppError> {
    let stats = admin_service::get_stats(&state.db).await?;

    Ok(Json(StatsResponse {
        total: stats.total,
        active: stats.active,
        inactive: stats.inactive,
        clusters: stats.clusters,
    }))
}
