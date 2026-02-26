//! Фоновая задача очистки: деактивация и удаление устаревших серверов.

use chrono::Utc;
use discovery_entities::servers::{ActiveModel, Column, Entity as ServerEntity};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait,
    QueryFilter,
};

/// Запустить бесконечный цикл очистки (каждую минуту).
/// - Через 5 минут без heartbeat → active = false
/// - Через 24 часа без heartbeat → удаление записи
pub async fn run_cleanup_loop(db: DatabaseConnection) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

        if let Err(e) = cleanup_once(&db).await {
            tracing::error!("Ошибка очистки реестра серверов: {e}");
        }
    }
}

async fn cleanup_once(db: &DatabaseConnection) -> Result<(), sea_orm::DbErr> {
    let now = Utc::now();
    let all_servers = ServerEntity::find().all(db).await?;

    for server in all_servers {
        let Ok(last_seen) = chrono::DateTime::parse_from_rfc3339(&server.last_seen) else {
            continue;
        };
        let elapsed = now.signed_duration_since(last_seen.with_timezone(&Utc));
        let elapsed_secs = elapsed.num_seconds();

        if elapsed_secs > 86400 {
            // Старше 24 часов — удаляем
            tracing::info!(
                "Удаляю сервер {} (нет heartbeat {} сек)",
                server.server_id,
                elapsed_secs
            );
            let model: ActiveModel = server.into();
            model.delete(db).await?;
        } else if elapsed_secs > 300 && server.active {
            // Старше 5 минут — деактивируем
            tracing::info!(
                "Деактивирую сервер {} (нет heartbeat {} сек)",
                server.server_id,
                elapsed_secs
            );
            let mut model: ActiveModel = server.into();
            model.active = Set(false);
            model.update(db).await?;
        }
    }

    // Дополнительно: очистка вышедших за 24 часа неактивных серверов по cluster_id
    cleanup_inactive_by_time(db, now).await?;

    Ok(())
}

/// Удалить записи у которых active=false и last_seen > 24h (дополнительная проверка).
async fn cleanup_inactive_by_time(
    db: &DatabaseConnection,
    now: chrono::DateTime<Utc>,
) -> Result<(), sea_orm::DbErr> {
    let stale = ServerEntity::find()
        .filter(Column::Active.eq(false))
        .all(db)
        .await?;

    for server in stale {
        let Ok(last_seen) = chrono::DateTime::parse_from_rfc3339(&server.last_seen) else {
            continue;
        };
        let elapsed_secs = now
            .signed_duration_since(last_seen.with_timezone(&Utc))
            .num_seconds();

        if elapsed_secs > 86400 {
            let model: ActiveModel = server.into();
            model.delete(db).await?;
        }
    }

    Ok(())
}
