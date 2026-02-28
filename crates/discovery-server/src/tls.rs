//! TLS: PEM-сертификаты, самоподписанный сертификат, или без TLS.

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
        TlsMode::Cert => serve_cert(config, app, shutdown_rx).await,
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

/// HTTPS с PEM-сертификатами из файлов (для продакшена, сертификаты от acme.sh).
async fn serve_cert(
    config: &ServerConfig,
    app: Router,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let addr: SocketAddr = config.listen.parse()?;
    let cert_path = &config.tls_cert;
    let key_path = &config.tls_key;

    info!("Запуск HTTPS сервера на {addr} (сертификат: {cert_path}, ключ: {key_path})");

    let rustls_config =
        axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await?;

    // Фоновая задача: перезагрузка сертификатов каждые 12 часов
    let reload_config = rustls_config.clone();
    let reload_cert = cert_path.clone();
    let reload_key = key_path.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(12 * 3600));
        interval.tick().await; // пропустить первый тик
        loop {
            interval.tick().await;
            match reload_config
                .reload_from_pem_file(&reload_cert, &reload_key)
                .await
            {
                Ok(()) => tracing::info!("TLS сертификаты перезагружены"),
                Err(e) => tracing::error!("Ошибка перезагрузки TLS сертификатов: {e}"),
            }
        }
    });

    let handle = axum_server::Handle::new();
    let handle_shutdown = handle.clone();
    tokio::spawn(async move {
        while !*shutdown_rx.borrow_and_update() {
            if shutdown_rx.changed().await.is_err() {
                break;
            }
        }
        handle_shutdown.graceful_shutdown(Some(tokio::time::Duration::from_secs(10)));
    });

    axum_server::bind_rustls(addr, rustls_config)
        .handle(handle)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}
