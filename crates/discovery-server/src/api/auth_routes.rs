//! Маршруты аутентификации: логин администратора.

use crate::api::{middleware, AppState};
use crate::config::verify_password;
use crate::error::AppError;
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub token: String,
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/auth/login", post(login))
}

/// POST /auth/login — авторизация администратора.
async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    // Проверяем имя пользователя
    if req.username != state.admin_username {
        return Err(AppError::Unauthorized("Неверные учётные данные".into()));
    }

    // Проверяем пароль по хэшу
    if !verify_password(&req.password, &state.admin_password_hash) {
        tracing::warn!("Неудачная попытка входа для пользователя: {}", req.username);
        return Err(AppError::Unauthorized("Неверные учётные данные".into()));
    }

    let token = middleware::create_admin_token(&req.username, &req.username, &state.jwt_secret)?;
    tracing::info!("Администратор {} вошёл в систему", req.username);

    Ok(Json(LoginResponse { token }))
}
