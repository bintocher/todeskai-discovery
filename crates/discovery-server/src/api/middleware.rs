//! JWT middleware для admin и server эндпоинтов.

use crate::api::AppState;
use crate::error::AppError;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde::{Deserialize, Serialize};

/// Claims JWT-токена администратора.
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminClaims {
    pub sub: String,
    pub username: String,
    pub exp: usize,
    pub iat: usize,
}

/// Claims JWT-токена сервера кластера.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerClaims {
    /// server_id
    pub sub: String,
    pub cluster_id: String,
    pub exp: usize,
    pub iat: usize,
}

/// Экстрактор аутентифицированного администратора.
pub struct AdminUser(pub AdminClaims);

/// Экстрактор аутентифицированного сервера кластера.
pub struct AuthenticatedServer(pub ServerClaims);

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_bearer_token(parts)?;
        let claims = decode_token::<AdminClaims>(token, &state.jwt_secret)?;
        Ok(AdminUser(claims))
    }
}

impl FromRequestParts<AppState> for AuthenticatedServer {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_bearer_token(parts)?;
        let claims = decode_token::<ServerClaims>(token, &state.jwt_secret)?;
        Ok(AuthenticatedServer(claims))
    }
}

/// Создать JWT-токен администратора (TTL 24 часа).
pub fn create_admin_token(
    user_id: &str,
    username: &str,
    jwt_secret: &str,
) -> Result<String, AppError> {
    let now = chrono::Utc::now().timestamp() as usize;
    let claims = AdminClaims {
        sub: user_id.to_string(),
        username: username.to_string(),
        exp: now + 24 * 3600,
        iat: now,
    };
    encode_token(&claims, jwt_secret)
}

/// Создать JWT-токен сервера кластера (TTL 24 часа).
pub fn create_server_token(
    server_id: &str,
    cluster_id: &str,
    jwt_secret: &str,
) -> Result<String, AppError> {
    let now = chrono::Utc::now().timestamp() as usize;
    let claims = ServerClaims {
        sub: server_id.to_string(),
        cluster_id: cluster_id.to_string(),
        exp: now + 24 * 3600,
        iat: now,
    };
    encode_token(&claims, jwt_secret)
}

// ── Вспомогательные функции ──────────────────────────────────────────────────

fn extract_bearer_token(parts: &Parts) -> Result<&str, AppError> {
    parts
        .headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Отсутствует заголовок Authorization".into()))?
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("Ожидается Bearer токен".into()))
}

fn decode_token<T: serde::de::DeserializeOwned>(
    token: &str,
    jwt_secret: &str,
) -> Result<T, AppError> {
    let key = jsonwebtoken::DecodingKey::from_secret(jwt_secret.as_bytes());
    let validation = jsonwebtoken::Validation::default();
    jsonwebtoken::decode::<T>(token, &key, &validation)
        .map(|d| d.claims)
        .map_err(|e| AppError::Unauthorized(format!("Невалидный токен: {e}")))
}

fn encode_token<T: serde::Serialize>(claims: &T, jwt_secret: &str) -> Result<String, AppError> {
    let key = jsonwebtoken::EncodingKey::from_secret(jwt_secret.as_bytes());
    jsonwebtoken::encode(&jsonwebtoken::Header::default(), claims, &key)
        .map_err(|e| AppError::Internal(format!("Ошибка создания токена: {e}")))
}
