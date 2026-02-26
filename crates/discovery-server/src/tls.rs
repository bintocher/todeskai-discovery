//! TLS: ACME (Let's Encrypt), самоподписанный сертификат, или без TLS.

use crate::config::{ServerConfig, TlsMode};
use axum::Router;
use std::net::SocketAddr;
use tracing::info;

/// Запустить сервер в нужном TLS-режиме.
pub async fn serve(
    config: &ServerConfig,
    app: Router,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    match &config.tls_mode {
        TlsMode::None => serve_plain(config, app, shutdown_rx).await,
        TlsMode::SelfSigned => serve_self_signed(config, app).await,
        TlsMode::Acme => serve_acme(config, app).await,
    }
}

/// Запуск без TLS (HTTP).
async fn serve_plain(
    config: &ServerConfig,
    app: Router,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let addr: SocketAddr = config.listen.parse()?;
    info!("Запуск HTTP сервера на {addr} (без TLS)");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            while !*shutdown_rx.borrow_and_update() {
                if shutdown_rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await?;
    Ok(())
}

/// Запуск с самоподписанным TLS-сертификатом.
async fn serve_self_signed(config: &ServerConfig, app: Router) -> anyhow::Result<()> {
    let addr: SocketAddr = config.listen.parse()?;
    info!("Запуск HTTPS сервера на {addr} (самоподписанный сертификат)");

    let subject_alt_names = vec![config.domain.clone(), "localhost".to_string()];
    let certified_key = rcgen::generate_simple_self_signed(subject_alt_names)
        .map_err(|e| anyhow::anyhow!("Ошибка генерации сертификата: {e}"))?;

    let cert_pem = certified_key.cert.pem();
    let key_pem = certified_key.signing_key.serialize_pem();

    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
        cert_pem.into_bytes(),
        key_pem.into_bytes(),
    )
    .await?;

    axum_server::bind_rustls(addr, rustls_config)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

/// Запуск с ACME (Let's Encrypt, HTTP-01 challenge).
async fn serve_acme(config: &ServerConfig, app: Router) -> anyhow::Result<()> {
    use futures_util::StreamExt;

    let addr: SocketAddr = config.listen.parse()?;
    info!(
        "Запуск HTTPS сервера на {addr} (ACME HTTP-01, домен: {})",
        config.domain
    );

    let domain = config.domain.clone();
    let contact = format!("mailto:{}", config.contact_email);
    let keys_dir = config.keys_dir.clone();
    let is_prod = !config.acme_staging;

    let mut acme_state = rustls_acme::AcmeConfig::new([domain])
        .contact([contact])
        .cache(rustls_acme::caches::DirCache::new(keys_dir))
        .directory_lets_encrypt(is_prod)
        .challenge_type(rustls_acme::UseChallenge::Http01)
        .state();

    let acceptor = acme_state.axum_acceptor(acme_state.default_rustls_config());
    let challenge_service = acme_state.http01_challenge_tower_service();

    tokio::spawn(async move {
        loop {
            match acme_state.next().await {
                Some(Ok(ok)) => tracing::info!("ACME событие: {:?}", ok),
                Some(Err(err)) => tracing::error!("ACME ошибка: {:?}", err),
                None => break,
            }
        }
    });

    // HTTP сервер для ACME challenge на порту 80
    let http_app = axum::Router::new().fallback_service(challenge_service);
    let http_addr: SocketAddr = "0.0.0.0:80".parse()?;
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(http_addr).await {
            Ok(listener) => {
                if let Err(e) = axum::serve(listener, http_app).await {
                    tracing::error!("Ошибка HTTP сервера для ACME challenge: {e}");
                }
            }
            Err(e) => {
                tracing::error!("Не удалось привязать порт 80 для ACME: {e}");
            }
        }
    });

    axum_server::bind(addr)
        .acceptor(acceptor)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}
