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

/// Запустить relay node в background task.
///
/// Генерирует Ed25519 keypair, слушает на указанном UDP порту (QUIC).
/// Обновляет `info_store` при появлении новых listen-адресов.
pub async fn start_relay(
    listen_port: u16,
    info_store: RelayInfoStore,
) -> anyhow::Result<()> {
    let keypair = Keypair::generate_ed25519();
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
fn build_relay_swarm(
    keypair: Keypair,
) -> anyhow::Result<libp2p::Swarm<RelayBehaviour>> {
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

            Ok(RelayBehaviour { relay, identify, ping })
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
                let full_addr = address
                    .with(libp2p::multiaddr::Protocol::P2p(local_peer_id));
                tracing::info!(addr = %full_addr, "Relay: слушаем на адресе");

                let mut info = info_store.write().await;
                let addr_str = full_addr.to_string();
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
                relay::Event::CircuitReqAccepted { src_peer_id, dst_peer_id, .. },
            )) => {
                tracing::info!(
                    src = %src_peer_id,
                    dst = %dst_peer_id,
                    "Relay: circuit установлен"
                );
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(
                relay::Event::CircuitClosed { src_peer_id, dst_peer_id, .. },
            )) => {
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
