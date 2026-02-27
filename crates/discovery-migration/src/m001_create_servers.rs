//! Миграция: создание таблицы servers.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m001_create_servers"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Servers::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Servers::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Servers::ServerId)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Servers::ClusterId).string().not_null())
                    .col(ColumnDef::new(Servers::PublicUrl).string().not_null())
                    .col(ColumnDef::new(Servers::Version).string().not_null())
                    .col(ColumnDef::new(Servers::PublicKey).string().not_null())
                    .col(ColumnDef::new(Servers::LastSeen).string().not_null())
                    .col(
                        ColumnDef::new(Servers::Active)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(ColumnDef::new(Servers::RegisteredAt).string().not_null())
                    .to_owned(),
            )
            .await?;

        // Индекс по cluster_id для быстрой выборки серверов кластера
        manager
            .create_index(
                Index::create()
                    .table(Servers::Table)
                    .col(Servers::ClusterId)
                    .name("idx_servers_cluster_id")
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Servers::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum Servers {
    Table,
    Id,
    ServerId,
    ClusterId,
    PublicUrl,
    Version,
    PublicKey,
    LastSeen,
    Active,
    RegisteredAt,
}
