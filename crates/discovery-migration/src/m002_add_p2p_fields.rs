//! Миграция: добавление P2P полей (peer_id, multiaddrs) в таблицу servers.

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m002_add_p2p_fields"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // peer_id — libp2p PeerId (base58). Пустая строка для серверов без P2P.
        manager
            .alter_table(
                Table::alter()
                    .table(Servers::Table)
                    .add_column(
                        ColumnDef::new(Servers::PeerId)
                            .string()
                            .not_null()
                            .default(""),
                    )
                    .to_owned(),
            )
            .await?;

        // multiaddrs — JSON массив multiaddr строк. Default: "[]".
        manager
            .alter_table(
                Table::alter()
                    .table(Servers::Table)
                    .add_column(
                        ColumnDef::new(Servers::Multiaddrs)
                            .string()
                            .not_null()
                            .default("[]"),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Servers::Table)
                    .drop_column(Servers::PeerId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Servers::Table)
                    .drop_column(Servers::Multiaddrs)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
enum Servers {
    Table,
    PeerId,
    Multiaddrs,
}
