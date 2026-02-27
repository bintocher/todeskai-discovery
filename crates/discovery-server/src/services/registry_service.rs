//! Сервис реестра серверов: регистрация, heartbeat, список кластера.

use crate::error::AppError;
use chrono::Utc;
use discovery_entities::servers::{ActiveModel, Column, Entity as ServerEntity, Model};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter,
};
use uuid::Uuid;

/// Данные для регистрации сервера.
pub struct RegisterData {
    pub server_id: String,
    pub cluster_id: String,
    pub public_url: String,
    pub version: String,
    pub public_key: String,
}

/// Зарегистрировать или обновить сервер.
/// Возвращает server_id, который был сохранён.
pub async fn register_server(
    db: &DatabaseConnection,
    data: RegisterData,
) -> Result<String, AppError> {
    let now = Utc::now().to_rfc3339();

    // Проверяем, существует ли уже такой server_id
    let existing = ServerEntity::find()
        .filter(Column::ServerId.eq(&data.server_id))
        .one(db)
        .await?;

    if let Some(record) = existing {
        // Обновляем существующую запись
        let mut model: ActiveModel = record.into();
        model.public_url = Set(data.public_url);
        model.version = Set(data.version);
        model.public_key = Set(data.public_key);
        model.last_seen = Set(now);
        model.active = Set(true);
        model.update(db).await?;
    } else {
        // Создаём новую запись
        let model = ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            server_id: Set(data.server_id.clone()),
            cluster_id: Set(data.cluster_id),
            public_url: Set(data.public_url),
            version: Set(data.version),
            public_key: Set(data.public_key),
            last_seen: Set(now.clone()),
            active: Set(true),
            registered_at: Set(now),
        };
        model.insert(db).await?;
    }

    Ok(data.server_id)
}

/// Обновить время последнего heartbeat для сервера.
pub async fn heartbeat(db: &DatabaseConnection, server_id: &str) -> Result<(), AppError> {
    let now = Utc::now().to_rfc3339();

    let record = ServerEntity::find()
        .filter(Column::ServerId.eq(server_id))
        .one(db)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Сервер не найден: {server_id}")))?;

    let mut model: ActiveModel = record.into();
    model.last_seen = Set(now);
    model.active = Set(true);
    model.update(db).await?;

    Ok(())
}

/// Получить список активных серверов кластера.
pub async fn get_cluster_servers(
    db: &DatabaseConnection,
    cluster_id: &str,
) -> Result<Vec<Model>, AppError> {
    let servers = ServerEntity::find()
        .filter(Column::ClusterId.eq(cluster_id))
        .filter(Column::Active.eq(true))
        .all(db)
        .await?;
    Ok(servers)
}

/// Удалить сервер по server_id.
pub async fn delete_server(db: &DatabaseConnection, server_id: &str) -> Result<(), AppError> {
    let record = ServerEntity::find()
        .filter(Column::ServerId.eq(server_id))
        .one(db)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Сервер не найден: {server_id}")))?;

    let model: ActiveModel = record.into();
    model.delete(db).await?;
    Ok(())
}

/// Проверить HMAC подпись запроса регистрации.
/// Сообщение: server_id + cluster_id + public_url + timestamp
pub fn verify_hmac(
    cluster_secret: &str,
    server_id: &str,
    cluster_id: &str,
    public_url: &str,
    timestamp: &str,
    provided_hmac: &str,
) -> bool {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use subtle::ConstantTimeEq;

    type HmacSha256 = Hmac<Sha256>;

    let message = format!("{}{}{}{}", server_id, cluster_id, public_url, timestamp);
    let mut mac = match HmacSha256::new_from_slice(cluster_secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(message.as_bytes());
    let expected = mac.finalize().into_bytes();

    let provided_bytes = base64::engine::general_purpose::STANDARD
        .decode(provided_hmac)
        .unwrap_or_default();

    expected.as_slice().ct_eq(&provided_bytes).into()
}

/// Проверить, не устарел ли timestamp (защита от replay-атак).
/// Отклоняет timestamps старше 5 минут.
pub fn verify_timestamp(timestamp: &str) -> bool {
    let Ok(ts) = chrono::DateTime::parse_from_rfc3339(timestamp) else {
        return false;
    };
    let now = Utc::now();
    let diff = now.signed_duration_since(ts.with_timezone(&Utc));
    diff.num_seconds().abs() <= 300
}
