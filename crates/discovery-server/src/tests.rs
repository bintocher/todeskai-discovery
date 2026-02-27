//! Тесты: HMAC-верификация, защита от replay-атак, интеграционные тесты HTTP.

#[cfg(test)]
mod tests {
    use crate::services::registry_service::{verify_hmac, verify_timestamp};

    // ── HMAC тесты ────────────────────────────────────────────────────────────

    fn make_hmac(
        cluster_secret: &str,
        server_id: &str,
        cluster_id: &str,
        public_url: &str,
        timestamp: &str,
    ) -> String {
        use base64::Engine;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;
        let message = format!("{}{}{}{}", server_id, cluster_id, public_url, timestamp);
        let mut mac = HmacSha256::new_from_slice(cluster_secret.as_bytes()).unwrap();
        mac.update(message.as_bytes());
        let result = mac.finalize().into_bytes();
        base64::engine::general_purpose::STANDARD.encode(result)
    }

    #[test]
    fn test_hmac_verify_valid() {
        let secret = "my-cluster-secret";
        let server_id = "srv-001";
        let cluster_id = "acme-corp";
        let public_url = "https://server.example.com:9090";
        let timestamp = "2026-02-26T10:00:00Z";

        let hmac_b64 = make_hmac(secret, server_id, cluster_id, public_url, timestamp);

        assert!(
            verify_hmac(secret, server_id, cluster_id, public_url, timestamp, &hmac_b64),
            "Правильный HMAC должен быть принят"
        );
    }

    #[test]
    fn test_hmac_verify_invalid() {
        let secret = "my-cluster-secret";
        let server_id = "srv-001";
        let cluster_id = "acme-corp";
        let public_url = "https://server.example.com:9090";
        let timestamp = "2026-02-26T10:00:00Z";

        let wrong_hmac = "dGhpcyBpcyBub3QgYSB2YWxpZCBobWFj";

        assert!(
            !verify_hmac(secret, server_id, cluster_id, public_url, timestamp, wrong_hmac),
            "Неверный HMAC должен быть отклонён"
        );
    }

    #[test]
    fn test_hmac_wrong_secret() {
        let server_id = "srv-001";
        let cluster_id = "acme-corp";
        let public_url = "https://server.example.com:9090";
        let timestamp = "2026-02-26T10:00:00Z";

        let hmac_b64 = make_hmac(
            "correct-secret",
            server_id,
            cluster_id,
            public_url,
            timestamp,
        );

        assert!(
            !verify_hmac(
                "wrong-secret",
                server_id,
                cluster_id,
                public_url,
                timestamp,
                &hmac_b64
            ),
            "HMAC с неверным секретом должен быть отклонён"
        );
    }

    // ── Replay protection тест ────────────────────────────────────────────────

    #[test]
    fn test_hmac_replay_protection_old_timestamp() {
        // Timestamp 10 минут назад — должен быть отклонён
        let old_time = chrono::Utc::now() - chrono::Duration::minutes(10);
        let timestamp = old_time.to_rfc3339();

        assert!(
            !verify_timestamp(&timestamp),
            "Старый timestamp должен быть отклонён (защита от replay)"
        );
    }

    #[test]
    fn test_hmac_replay_protection_valid_timestamp() {
        // Timestamp 1 минуту назад — должен быть принят
        let recent_time = chrono::Utc::now() - chrono::Duration::seconds(30);
        let timestamp = recent_time.to_rfc3339();

        assert!(
            verify_timestamp(&timestamp),
            "Актуальный timestamp должен быть принят"
        );
    }

    #[test]
    fn test_hmac_replay_protection_future_timestamp() {
        // Timestamp 1 минуту в будущем — должен быть принят (небольшое расхождение часов)
        let future_time = chrono::Utc::now() + chrono::Duration::seconds(60);
        let timestamp = future_time.to_rfc3339();

        assert!(
            verify_timestamp(&timestamp),
            "Timestamp на 1 минуту в будущем должен быть принят (дрейф часов)"
        );
    }

    // ── Password hash тест ────────────────────────────────────────────────────

    #[test]
    fn test_password_hash_and_verify() {
        use crate::config::{hash_password, verify_password};

        let password = "SuperSecret123!";
        let hash = hash_password(password);

        assert!(
            verify_password(password, &hash),
            "Верный пароль должен проходить проверку"
        );
        assert!(
            !verify_password("WrongPassword", &hash),
            "Неверный пароль должен отклоняться"
        );
    }

    // ── HTTP интеграционные тесты ─────────────────────────────────────────────
    // Запускаются только при явном указании: cargo test integration

    mod integration {
        use super::*;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        async fn build_test_app() -> axum::Router {
            use crate::api::{build_router, rate_limit::RateLimiter, AppState};
            use crate::config::hash_password;
            use discovery_migration::{Migrator, MigratorTrait};
            use sea_orm::{Database, DatabaseConnection};

            let db: DatabaseConnection = Database::connect("sqlite::memory:").await.unwrap();
            Migrator::up(&db, None).await.unwrap();

            let state = AppState {
                db,
                jwt_secret: "test-secret".to_string(),
                admin_username: "admin".to_string(),
                admin_password_hash: hash_password("admin123"),
                rate_limiter: RateLimiter::new(100, 60),
            };

            build_router(state)
        }

        #[tokio::test]
        async fn test_health_check() {
            let app = build_test_app().await;

            let response = app
                .oneshot(
                    Request::builder()
                        .uri("/health")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn test_register_requires_valid_hmac() {
            let app = build_test_app().await;

            let body = serde_json::json!({
                "serverId": "srv-test",
                "clusterId": "test-cluster",
                "publicUrl": "https://test.example.com",
                "version": "0.1.0",
                "publicKey": "dGVzdC1rZXk=",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "clusterSecretHmac": "invalid-hmac"
            });

            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/servers/register")
                        .header("content-type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();

            // Ожидаем 401 (нет env переменной с секретом)
            assert!(
                response.status() == StatusCode::UNAUTHORIZED
                    || response.status() == StatusCode::BAD_REQUEST
            );
        }
    }
}
