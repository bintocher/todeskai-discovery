//! HTTP API: маршрутизация и состояние приложения.

pub mod admin_routes;
pub mod auth_routes;
pub mod middleware;
pub mod rate_limit;
pub mod server_routes;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use rate_limit::RateLimiter;
use sea_orm::{ConnectionTrait, DatabaseConnection};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

/// Общее состояние приложения.
#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub jwt_secret: String,
    pub admin_username: String,
    pub admin_password_hash: String,
    pub rate_limiter: RateLimiter,
}

/// Построить маршрутизатор Axum.
pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Rate limiter: 60 запросов в минуту на IP
    let limiter = state.rate_limiter.clone();

    let public_routes = Router::new()
        .merge(server_routes::routes())
        .layer(axum::middleware::from_fn(move |req, next| {
            let limiter = limiter.clone();
            rate_limit::rate_limit_middleware(limiter, req, next)
        }));

    let admin_routes = admin_routes::routes();
    let auth_routes = auth_routes::routes();

    Router::new()
        .route("/health", get(health_check))
        .merge(auth_routes)
        .nest("/api/v1", public_routes)
        .nest("/api/v1/admin", admin_routes)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// GET /health — проверка работоспособности сервера.
async fn health_check(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db_ok = state.db.execute_unprepared("SELECT 1").await.is_ok();
    Json(serde_json::json!({
        "status": if db_ok { "ok" } else { "error" },
        "database": db_ok,
        "service": "discovery-server"
    }))
}
