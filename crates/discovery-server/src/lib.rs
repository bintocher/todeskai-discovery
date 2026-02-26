//! Ядро сервера обнаружения ToDeskAI.

pub mod api;
pub mod config;
pub mod error;
pub mod services;
pub mod tls;

#[cfg(test)]
mod tests;

use api::AppState;
use config::ServerConfig;
use discovery_migration::{Migrator, MigratorTrait};
use sea_orm::{Database, DatabaseConnection};
use tokio::sync::watch;
use tracing::info;

/// Запустить сервер обнаружения.
pub async fn run(config: ServerConfig) -> anyhow::Result<()> {
    // 1. Подключение к БД
    info!("Подключение к базе данных: {}", config.db_url);
    let db: DatabaseConnection = Database::connect(&config.db_url).await?;

    // 2. Автоматические миграции
    info!("Выполнение миграций...");
    Migrator::up(&db, None).await?;

    // 3. Состояние приложения
    let state = AppState {
        db: db.clone(),
        jwt_secret: config.jwt_secret.clone(),
        admin_username: config.admin_username.clone(),
        admin_password_hash: config.admin_password_hash.clone(),
        rate_limiter: api::rate_limit::RateLimiter::new(60, 60),
    };

    // 4. Маршрутизатор
    let app = api::build_router(state);

    // 5. Фоновая задача очистки устаревших серверов
    let db_bg = db.clone();
    tokio::spawn(async move {
        services::cleanup_service::run_cleanup_loop(db_bg).await;
    });

    // 6. Graceful shutdown
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Получен сигнал завершения, останавливаю сервер...");
        let _ = shutdown_tx_clone.send(true);
    });

    // 7. Запуск сервера
    info!("Сервер обнаружения запущен");
    tls::serve(&config, app, shutdown_rx).await?;

    info!("Сервер обнаружения остановлен");
    Ok(())
}
