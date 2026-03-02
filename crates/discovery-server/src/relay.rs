//! libp2p Relay node — помогает серверам за NAT установить прямое соединение.
//!
//! Relay работает в server-mode: принимает reservation от клиентов и
//! проксирует начальный трафик, пока DCUtR не переключит на прямой QUIC.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identify, ping, relay, Multiaddr, PeerId, SwarmBuilder};
use tokio::sync::RwLock;

/// Информация о запущенном relay (для `/api/v1/relay-info`).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayInfo {
    pub peer_id: String,
    pub multiaddrs: Vec<String>,
}

/// Хранилище актуальных адресов relay.
pub type RelayInfoStore = Arc<RwLock<RelayInfo>>;

/// Создать пустое хранилище relay-информации.
pub fn new_relay_info_store() -> RelayInfoStore {
    Arc::new(RwLock::new(RelayInfo {
        peer_id: String::new(),
        multiaddrs: vec![],
    }))
}

/// Composed behaviour для relay node.
#[derive(NetworkBehaviour)]
struct RelayBehaviour {
    relay: relay::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
}

const PROTOCOL_VERSION: &str = "/todeskai-relay/1.0.0";
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Загрузить keypair из файла, либо сгенерировать новый и сохранить.
/// Формат файла: raw Ed25519 seed (32 байта).
fn load_or_generate_keypair(path: &str) -> anyhow::Result<Keypair> {
    let file_path = std::path::Path::new(path);

    if file_path.exists() {
        let mut bytes = std::fs::read(file_path)
            .map_err(|e| anyhow::anyhow!("Ошибка чтения relay keypair из {path}: {e}"))?;
        match bytes.len() {
            64 => {
                // Legacy формат (seed + public), берём первые 32 байта (seed)
                bytes.truncate(32);
            }
            32 => { /* Текущий формат, всё в порядке */ }
            other => {
                return Err(anyhow::anyhow!(
                    "Неверный размер файла ключа relay {path}: ожидалось 32 или 64 байта, найдено {other}"
                ));
            }
        }
        let keypair = Keypair::ed25519_from_bytes(bytes)
            .map_err(|e| anyhow::anyhow!("Ошибка парсинга relay keypair из {path}: {e}"))?;
        tracing::info!(path, "Relay keypair загружен из файла");
        Ok(keypair)
    } else {
        let keypair = Keypair::generate_ed25519();
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("Ошибка создания директории для {path}: {e}"))?;
        }
        // Сохраняем только seed (32 байта) — ed25519_from_bytes ожидает именно его
        let kp_ref = keypair
            .clone()
            .try_into_ed25519()
            .map_err(|e| anyhow::anyhow!("Keypair не Ed25519: {e}"))?;
        let seed = &kp_ref.to_bytes()[..32];
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(file_path)
                .map_err(|e| {
                    anyhow::anyhow!("Ошибка открытия relay keypair для записи в {path}: {e}")
                })?;
            file.write_all(seed)
                .map_err(|e| anyhow::anyhow!("Ошибка сохранения relay keypair в {path}: {e}"))?;
        }
        #[cfg(not(unix))]
        std::fs::write(file_path, seed)
            .map_err(|e| anyhow::anyhow!("Ошибка сохранения relay keypair в {path}: {e}"))?;
        tracing::info!(path, "Relay keypair сгенерирован и сохранён");
        Ok(keypair)
    }
}

/// Запустить relay node в background task.
///
/// Загружает Ed25519 keypair из файла (или генерирует новый),
/// слушает на указанном UDP порту (QUIC).
/// Обновляет `info_store` при появлении новых listen-адресов.
pub async fn start_relay(
    listen_port: u16,
    info_store: RelayInfoStore,
    relay_key_file: &str,
) -> anyhow::Result<()> {
    let keypair = load_or_generate_keypair(relay_key_file)?;
    let local_peer_id = keypair.public().to_peer_id();

    tracing::info!(peer_id = %local_peer_id, port = listen_port, "Запуск relay node");

    let mut swarm = build_relay_swarm(keypair.clone())?;

    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/udp/{listen_port}/quic-v1")
        .parse()
        .map_err(|e| anyhow::anyhow!("Ошибка парсинга listen addr: {e}"))?;

    swarm.listen_on(listen_addr)?;

    // Сохраняем PeerId сразу
    {
        let mut info = info_store.write().await;
        info.peer_id = local_peer_id.to_base58();
    }

    // Event loop в background
    tokio::spawn(relay_event_loop(swarm, local_peer_id, info_store));

    Ok(())
}

/// Построить Swarm для relay (server mode).
fn build_relay_swarm(keypair: Keypair) -> anyhow::Result<libp2p::Swarm<RelayBehaviour>> {
    let swarm = SwarmBuilder::with_existing_identity(keypair.clone())
        .with_tokio()
        .with_quic()
        .with_behaviour(|key| {
            let peer_id = key.public().to_peer_id();

            let relay = relay::Behaviour::new(peer_id, relay::Config::default());
            let identify = identify::Behaviour::new(identify::Config::new(
                PROTOCOL_VERSION.to_string(),
                key.public(),
            ));
            let ping = ping::Behaviour::default();

            Ok(RelayBehaviour {
                relay,
                identify,
                ping,
            })
        })
        .map_err(|e| anyhow::anyhow!("Ошибка сборки relay behaviour: {e}"))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(IDLE_TIMEOUT))
        .build();

    Ok(swarm)
}

/// Event loop relay-ноды.
async fn relay_event_loop(
    mut swarm: libp2p::Swarm<RelayBehaviour>,
    local_peer_id: PeerId,
    info_store: RelayInfoStore,
) {
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                // Добавляем /p2p/<peer_id> к адресу для полного multiaddr
                let full_addr = address.with(libp2p::multiaddr::Protocol::P2p(local_peer_id));
                tracing::info!(addr = %full_addr, "Relay: слушаем на адресе");

                let mut info = info_store.write().await;
                let addr_str = full_addr.to_string();
                // O(n) поиск допустим: relay имеет 1-3 listen-адреса, HashSet — избыточен
                if !info.multiaddrs.contains(&addr_str) {
                    info.multiaddrs.push(addr_str);
                }
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(
                relay::Event::ReservationReqAccepted { src_peer_id, .. },
            )) => {
                tracing::info!(peer = %src_peer_id, "Relay: reservation принята");
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(
                relay::Event::CircuitReqAccepted {
                    src_peer_id,
                    dst_peer_id,
                    ..
                },
            )) => {
                tracing::info!(
                    src = %src_peer_id,
                    dst = %dst_peer_id,
                    "Relay: circuit установлен"
                );
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(relay::Event::CircuitClosed {
                src_peer_id,
                dst_peer_id,
                ..
            })) => {
                tracing::debug!(
                    src = %src_peer_id,
                    dst = %dst_peer_id,
                    "Relay: circuit закрыт"
                );
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                tracing::debug!(peer = %peer_id, "Relay: соединение установлено");
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                tracing::debug!(peer = %peer_id, "Relay: соединение закрыто");
            }
            _ => {}
        }
    }
}
