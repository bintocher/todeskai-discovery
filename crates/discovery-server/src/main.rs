//! Точка входа сервера обнаружения ToDeskAI.

use clap::Parser;
use discovery_server::config::{hash_password, ServerConfig, TlsMode};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "discovery-server",
    about = "ToDeskAI Discovery Server — реестр серверов кластера"
)]
struct Cli {
    /// Адрес для прослушивания (host:port)
    #[arg(long, default_value = "0.0.0.0:3000")]
    listen: String,

    /// URL базы данных
    #[arg(
        long,
        default_value = "sqlite:./discovery.db?mode=rwc",
        env = "DATABASE_URL"
    )]
    db_url: String,

    /// Режим TLS: none, self-signed, acme
    #[arg(long, default_value = "none")]
    tls_mode: String,

    /// Домен для ACME / SAN
    #[arg(long, default_value = "discovery.todeskai.ru")]
    domain: String,

    /// Секрет JWT (случайный если не задан)
    #[arg(long, env = "JWT_SECRET")]
    jwt_secret: Option<String>,

    /// Имя пользователя администратора
    #[arg(long, default_value = "admin")]
    admin_username: String,

    /// Пароль администратора
    #[arg(long, env = "ADMIN_PASSWORD")]
    admin_password: Option<String>,

    /// Email для ACME-контакта
    #[arg(long, default_value = "admin@todeskai.ru")]
    contact_email: String,

    /// Директория для ACME-ключей
    #[arg(long, default_value = "/etc/discovery/keys")]
    keys_dir: String,

    /// Использовать staging ACME-сервер
    #[arg(long)]
    acme_staging: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Инициализация логгера
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // Разбор режима TLS
    let tls_mode: TlsMode = cli
        .tls_mode
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    // JWT secret: из аргумента или генерируем случайный
    let jwt_secret = cli.jwt_secret.unwrap_or_else(|| {
        let mut buf = [0u8; 32];
        getrandom::fill(&mut buf).expect("Ошибка генерации JWT secret");
        hex::encode(buf)
    });

    // Хэш пароля администратора
    let admin_password = cli.admin_password.unwrap_or_else(|| {
        tracing::warn!("Пароль администратора не задан, используется 'admin' (небезопасно!)");
        "admin".to_string()
    });
    let admin_password_hash = hash_password(&admin_password);

    let config = ServerConfig {
        listen: cli.listen,
        db_url: cli.db_url,
        tls_mode,
        domain: cli.domain,
        jwt_secret,
        admin_username: cli.admin_username,
        admin_password_hash,
        contact_email: cli.contact_email,
        keys_dir: cli.keys_dir,
        acme_staging: cli.acme_staging,
    };

    discovery_server::run(config).await
}
