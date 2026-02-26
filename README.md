# ToDeskAI Discovery Server

Rendezvous-сервер для автоматического обнаружения серверов todeskai в WAN.

## Архитектура

```
[Сервер A] --register--> [discovery.todeskai.ru] <--register-- [Сервер B]
[Сервер A] --lookup_cluster--> получает URL и pubkey Сервера B
[Сервер A] --connect(E2EE)--> [Сервер B]
```

Discovery server — только сообщает серверам адреса друг друга. Весь трафик данных идёт напрямую.

## API

### POST /api/v1/servers/register
Регистрация сервера с HMAC-SHA256 аутентификацией.

```json
{
  "serverId": "uuid",
  "clusterId": "acme-corp",
  "publicUrl": "https://server.example.com:9090",
  "version": "0.1.0",
  "publicKey": "base64-x25519-pubkey",
  "timestamp": "<current-utc-timestamp>",
  "clusterSecretHmac": "base64(HMAC-SHA256(...))"
}
```

### POST /api/v1/servers/heartbeat
Подтверждение активности сервера (каждые 2 мин).

### GET /api/v1/cluster/{cluster_id}
Список активных серверов кластера (требует Bearer JWT).

### DELETE /api/v1/servers/{server_id}
Удаление регистрации при остановке сервера.

## Запуск

```bash
# Разработка (SQLite, без TLS)
make run-dev

# Продакшн (ACME TLS)
./discovery-server \
  --listen 0.0.0.0:443 \
  --tls-mode acme \
  --domain discovery.todeskai.ru \
  --db-url postgres://user:pass@localhost/discovery
```

## Переменные окружения

| Переменная | Описание |
|------------|----------|
| `CLUSTER_SECRET_<CLUSTER_ID>` | Shared secret кластера для HMAC верификации |
| `RUST_LOG` | Уровень логирования (info, debug) |

## Безопасность

- **HMAC-SHA256**: аутентификация при регистрации
- **Replay protection**: timestamp в HMAC, отклоняются запросы старше 5 мин
- **JWT 24h**: Bearer токен для heartbeat и lookup
- **Rate limit**: 60 req/min per IP
- **Cleanup**: active=false через 5 мин без heartbeat, DELETE через 24h

## Структура

```
crates/
├── discovery-entities/    # SeaORM entity: servers
├── discovery-migration/   # Миграция: CREATE TABLE servers
└── discovery-server/      # Axum REST API сервер
    ├── api/               # Routes: server, auth, admin
    ├── services/          # Registry, admin, cleanup logic
    ├── tls.rs             # none / self-signed / ACME
    └── tests.rs           # Unit + integration тесты
```
