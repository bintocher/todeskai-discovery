//! Конфигурация сервера обнаружения.

#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Адрес для прослушивания (например "0.0.0.0:443")
    pub listen: String,

    /// URL подключения к БД (sqlite или postgres)
    pub db_url: String,

    /// Режим TLS
    pub tls_mode: TlsMode,

    /// Домен для ACME / SAN сертификата
    pub domain: String,

    /// Секрет JWT (генерируется случайно если не задан)
    pub jwt_secret: String,

    /// Имя пользователя администратора
    pub admin_username: String,

    /// Хэш пароля администратора (SHA-256 hex)
    pub admin_password_hash: String,

    /// Email контакта для ACME
    pub contact_email: String,

    /// Директория для хранения ACME-ключей
    pub keys_dir: String,

    /// Использовать staging ACME-сервер
    pub acme_staging: bool,
}

#[derive(Debug, Clone)]
pub enum TlsMode {
    None,
    SelfSigned,
    Acme,
}

impl std::str::FromStr for TlsMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(TlsMode::None),
            "self-signed" | "selfsigned" => Ok(TlsMode::SelfSigned),
            "acme" => Ok(TlsMode::Acme),
            other => Err(format!(
                "Неизвестный режим TLS: {other}. Допустимые: none, self-signed, acme"
            )),
        }
    }
}

impl std::fmt::Display for TlsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsMode::None => write!(f, "none"),
            TlsMode::SelfSigned => write!(f, "self-signed"),
            TlsMode::Acme => write!(f, "acme"),
        }
    }
}

/// Хэшировать пароль (SHA-256 hex).
pub fn hash_password(password: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(password.as_bytes());
    hex::encode(hash)
}

/// Проверить пароль по хэшу.
pub fn verify_password(password: &str, hash: &str) -> bool {
    hash_password(password) == hash
}
