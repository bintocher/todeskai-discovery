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

    /// Режим TLS: none, self-signed, cert
    #[arg(long, default_value = "none")]
    tls_mode: String,

    /// Домен для self-signed сертификата
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

    /// Путь к PEM-файлу сертификата (для --tls-mode cert)
    #[arg(
        long,
        default_value = "/etc/letsencrypt/live/discovery.todeskai.ru/fullchain.pem"
    )]
    tls_cert: String,

    /// Путь к PEM-файлу приватного ключа (для --tls-mode cert)
    #[arg(
        long,
        default_value = "/etc/letsencrypt/live/discovery.todeskai.ru/privkey.pem"
    )]
    tls_key: String,

    /// UDP порт для libp2p relay QUIC (0 = отключён). По умолчанию 443 — совпадает
    /// с HTTPS (TCP), но UDP и TCP не конфликтуют. Порт 443/udp реже блокируется
    /// ISP/NAT, чем нестандартные порты (4001).
    #[arg(long, default_value = "443", env = "RELAY_PORT")]
    relay_port: u16,

    /// TCP порт для libp2p relay (fallback при блокировке UDP/QUIC).
    /// По умолчанию 4001. Если 0 — TCP relay отключён.
    #[arg(long, default_value = "4001", env = "RELAY_TCP_PORT")]
    relay_tcp_port: u16,

    /// Путь к файлу Ed25519 keypair для relay node
    #[arg(
        long,
        default_value = "/var/lib/discovery/relay_key",
        env = "RELAY_KEY_FILE"
    )]
    relay_key_file: String,

    /// Внешний IP адрес relay (обязателен для серверов за NAT или VPS).
    /// Без этого relay не может включить адреса в ответ на reservation.
    #[arg(long, env = "RELAY_EXTERNAL_IP")]
    relay_external_ip: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Явная установка CryptoProvider для rustls
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Не удалось установить CryptoProvider");

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
        tls_cert: cli.tls_cert,
        tls_key: cli.tls_key,
        relay_port: cli.relay_port,
        relay_tcp_port: cli.relay_tcp_port,
        relay_key_file: cli.relay_key_file,
        relay_external_ip: cli.relay_external_ip,
    };

    discovery_server::run(config).await
}
