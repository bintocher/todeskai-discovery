//! Типы ошибок сервера обнаружения.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Не авторизован: {0}")]
    Unauthorized(String),

    #[error("Не найдено: {0}")]
    NotFound(String),

    #[error("Конфликт: {0}")]
    Conflict(String),

    #[error("Слишком много запросов")]
    TooManyRequests,

    #[error("Внутренняя ошибка: {0}")]
    Internal(String),

    #[error("Неверный запрос: {0}")]
    BadRequest(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m.clone()),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, m.clone()),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m.clone()),
            AppError::TooManyRequests => (
                StatusCode::TOO_MANY_REQUESTS,
                "Слишком много запросов".to_string(),
            ),
            AppError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m.clone()),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
        };
        (status, axum::Json(json!({ "error": message }))).into_response()
    }
}

impl From<sea_orm::DbErr> for AppError {
    fn from(e: sea_orm::DbErr) -> Self {
        AppError::Internal(e.to_string())
    }
}
