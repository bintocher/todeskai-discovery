//! In-memory rate limiter: 60 запросов в минуту на IP.

use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

struct RateEntry {
    count: u32,
    window_start: Instant,
}

/// Rate limiter для ограничения запросов по IP.
#[derive(Clone)]
pub struct RateLimiter {
    entries: Arc<Mutex<HashMap<String, RateEntry>>>,
    max_requests: u32,
    window_secs: u64,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window_secs,
        }
    }

    pub async fn check(&self, key: &str) -> bool {
        let mut entries = self.entries.lock().await;
        let now = Instant::now();

        // Периодическая очистка при росте таблицы
        if entries.len() > 1000 {
            entries.retain(|_, v| {
                now.duration_since(v.window_start).as_secs() < self.window_secs
            });
        }

        let entry = entries.entry(key.to_string()).or_insert(RateEntry {
            count: 0,
            window_start: now,
        });

        // Сброс окна если время истекло
        if now.duration_since(entry.window_start).as_secs() >= self.window_secs {
            entry.count = 1;
            entry.window_start = now;
            return true;
        }

        entry.count += 1;
        entry.count <= self.max_requests
    }
}

/// Middleware rate limiting: отклоняет запросы при превышении лимита.
pub async fn rate_limit_middleware(
    rate_limiter: RateLimiter,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let ip = extract_ip(&req);

    if !rate_limiter.check(&ip).await {
        tracing::warn!("Rate limit превышен для IP: {ip}");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(req).await)
}

/// Извлечь IP клиента (учитывает X-Forwarded-For).
pub fn extract_ip<B>(req: &Request<B>) -> String {
    req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            req.extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ci| ci.0.ip().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}
