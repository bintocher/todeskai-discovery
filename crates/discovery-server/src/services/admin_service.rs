//! Административный сервис: статистика, список серверов.

use crate::error::AppError;
use discovery_entities::servers::{Entity as ServerEntity, Model};
use sea_orm::{DatabaseConnection, EntityTrait, PaginatorTrait};

/// Получить список всех серверов (активных и неактивных).
pub async fn list_all_servers(db: &DatabaseConnection) -> Result<Vec<Model>, AppError> {
    let servers = ServerEntity::find().all(db).await?;
    Ok(servers)
}

/// Статистика реестра серверов.
pub struct Stats {
    pub total: u64,
    pub active: u64,
    pub inactive: u64,
    pub clusters: usize,
}

/// Получить статистику по серверам.
pub async fn get_stats(db: &DatabaseConnection) -> Result<Stats, AppError> {
    use discovery_entities::servers::Column;
    use sea_orm::ColumnTrait;
    use sea_orm::QueryFilter;

    let total = ServerEntity::find().count(db).await?;
    let active = ServerEntity::find()
        .filter(Column::Active.eq(true))
        .count(db)
        .await?;
    let inactive = total - active;

    let all = ServerEntity::find().all(db).await?;
    let mut cluster_ids: Vec<String> = all.iter().map(|s| s.cluster_id.clone()).collect();
    cluster_ids.sort();
    cluster_ids.dedup();
    let clusters = cluster_ids.len();

    Ok(Stats {
        total,
        active,
        inactive,
        clusters,
    })
}
