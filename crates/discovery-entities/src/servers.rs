//! Entity для таблицы servers.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "servers")]
pub struct Model {
    /// UUID первичного ключа
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,

    /// Уникальный идентификатор сервера
    #[sea_orm(unique)]
    pub server_id: String,

    /// Идентификатор кластера
    pub cluster_id: String,

    /// Публичный URL сервера
    pub public_url: String,

    /// Версия сервера
    pub version: String,

    /// Публичный ключ X25519 (base64)
    pub public_key: String,

    /// Время последнего heartbeat (ISO-8601)
    pub last_seen: String,

    /// Активен ли сервер
    pub active: bool,

    /// Время регистрации (ISO-8601)
    pub registered_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
