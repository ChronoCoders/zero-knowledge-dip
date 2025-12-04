use crate::config::Config;
use crate::validator::DatValidator;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

const MAX_PACKET_SIZE: usize = 65536;
const HANDSHAKE_RATE_LIMIT: Duration = Duration::from_secs(1);
const SESSION_TIMEOUT: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Serialize, Deserialize)]
enum PacketType {
    HandshakeInit,
    HandshakeResponse,
    DatAuth,
    DatAuthResponse,
    Data,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Packet {
    packet_type: PacketType,
    payload: Vec<u8>,
}

struct PeerState {
    _shared_secret: [u8; 32],
    cipher: Aes256Gcm,
    last_activity: Instant,
    validated: bool,
    _client_public_key: PublicKey,
}

pub struct VpnServer {
    _config: Arc<Config>,
    validator: Arc<DatValidator>,
    peers: Arc<RwLock<HashMap<SocketAddr, PeerState>>>,
    socket: Arc<UdpSocket>,
    server_private_key: StaticSecret,
    server_public_key: PublicKey,
}

impl VpnServer {
    pub async fn new(config: Config) -> Result<Self> {
        let bind_addr = format!("0.0.0.0:{}", config.wireguard_port);
        let socket = UdpSocket::bind(&bind_addr)
            .await
            .context("Failed to bind UDP socket")?;

        tracing::info!(
            addr = %bind_addr,
            server_ip = %config.server_ip,
            "VPN server listening"
        );

        let validator = Arc::new(DatValidator::new(
            &config.jwt_secret,
            config.server_ip,
        ));

        let server_private_key = Self::decode_private_key(&config.wireguard_private_key)?;
        let server_public_key = PublicKey::from(&server_private_key);

        tracing::info!(
            public_key = %general_purpose::STANDARD.encode(server_public_key.as_bytes()),
            "Server public key"
        );

        Ok(Self {
            _config: Arc::new(config),
            validator,
            peers: Arc::new(RwLock::new(HashMap::new())),
            socket: Arc::new(socket),
            server_private_key,
            server_public_key,
        })
    }

    pub async fn run(&self) -> Result<()> {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        tokio::spawn({
            let peers = Arc::clone(&self.peers);
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    Self::cleanup_stale_peers(&peers).await;
                }
            }
        });

        loop {
            let (len, peer_addr) = self
                .socket
                .recv_from(&mut buf)
                .await
                .context("Failed to receive packet")?;

            let packet_data = &buf[..len];

            if let Err(e) = self.handle_packet(peer_addr, packet_data).await {
                tracing::debug!(
                    peer = %peer_addr,
                    error = %e,
                    "Failed to handle packet"
                );
            }
        }
    }

    async fn cleanup_stale_peers(peers: &Arc<RwLock<HashMap<SocketAddr, PeerState>>>) {
        let mut peers_lock = peers.write().await;
        let stale: Vec<SocketAddr> = peers_lock
            .iter()
            .filter(|(_, state)| state.last_activity.elapsed() > SESSION_TIMEOUT)
            .map(|(addr, _)| *addr)
            .collect();

        for addr in stale {
            peers_lock.remove(&addr);
            tracing::info!(peer = %addr, "Removed stale peer");
        }
    }

    async fn handle_packet(&self, peer_addr: SocketAddr, data: &[u8]) -> Result<()> {
        let packet: Packet = serde_json::from_slice(data)
            .context("Failed to deserialize packet")?;

        match packet.packet_type {
            PacketType::HandshakeInit => self.handle_handshake_init(peer_addr, &packet).await,
            PacketType::DatAuth => self.handle_dat_auth(peer_addr, &packet).await,
            PacketType::Data => self.handle_data_packet(peer_addr, &packet).await,
            _ => bail!("Unexpected packet type"),
        }
    }

    async fn handle_handshake_init(&self, peer_addr: SocketAddr, packet: &Packet) -> Result<()> {
        let peers = self.peers.read().await;
        if let Some(peer) = peers.get(&peer_addr) {
            if peer.last_activity.elapsed() < HANDSHAKE_RATE_LIMIT {
                tracing::debug!(peer = %peer_addr, "Handshake rate limited");
                return Ok(());
            }
        }
        drop(peers);

        if packet.payload.len() != 32 {
            bail!("Invalid client public key length");
        }

        let mut client_public_key_bytes = [0u8; 32];
        client_public_key_bytes.copy_from_slice(&packet.payload);
        let client_public_key = PublicKey::from(client_public_key_bytes);

        let shared_secret = self.server_private_key.diffie_hellman(&client_public_key);

        let cipher_key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
        let cipher = Aes256Gcm::new(cipher_key);

        let mut peers = self.peers.write().await;
        peers.insert(
            peer_addr,
            PeerState {
                _shared_secret: *shared_secret.as_bytes(),
                cipher,
                last_activity: Instant::now(),
                validated: false,
                _client_public_key: client_public_key,
            },
        );

        tracing::info!(
            peer = %peer_addr,
            "Handshake initiated, sending server public key"
        );

        let response = Packet {
            packet_type: PacketType::HandshakeResponse,
            payload: self.server_public_key.as_bytes().to_vec(),
        };

        let response_data = serde_json::to_vec(&response)?;
        self.socket.send_to(&response_data, peer_addr).await?;

        Ok(())
    }

    async fn handle_dat_auth(&self, peer_addr: SocketAddr, packet: &Packet) -> Result<()> {
        let mut peers = self.peers.write().await;

        let peer = peers
            .get_mut(&peer_addr)
            .context("No handshake found for peer")?;

        let nonce_bytes = &packet.payload[..12];
        let ciphertext = &packet.payload[12..];
        let nonce = Nonce::from_slice(nonce_bytes);

        let decrypted = peer
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;

        let dat_token = String::from_utf8(decrypted)
            .context("DAT token is not valid UTF-8")?;

        match self.validator.validate(&dat_token) {
            Ok(claims) => {
                tracing::info!(
                    peer = %peer_addr,
                    ip = %claims.dip_details.ip,
                    "DAT token validated, connection authorized"
                );

                peer.validated = true;
                peer.last_activity = Instant::now();

                let response_payload = b"AUTH_OK";
                let response_nonce = Self::generate_nonce();
                let nonce_ref = Nonce::from_slice(&response_nonce);
                let encrypted = peer
                    .cipher
                    .encrypt(nonce_ref, response_payload.as_ref())
                    .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

                let mut response_data = response_nonce.to_vec();
                response_data.extend_from_slice(&encrypted);

                let response = Packet {
                    packet_type: PacketType::DatAuthResponse,
                    payload: response_data,
                };

                let response_json = serde_json::to_vec(&response)?;
                self.socket.send_to(&response_json, peer_addr).await?;

                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    peer = %peer_addr,
                    error = %e,
                    "DAT validation failed, dropping connection"
                );
                peers.remove(&peer_addr);
                bail!("DAT validation failed: {}", e);
            }
        }
    }

    async fn handle_data_packet(&self, peer_addr: SocketAddr, packet: &Packet) -> Result<()> {
        let mut peers = self.peers.write().await;

        let peer = peers
            .get_mut(&peer_addr)
            .context("Unknown peer")?;

        if !peer.validated {
            bail!("Peer not validated");
        }

        if packet.payload.len() < 12 {
            bail!("Packet too short");
        }

        let nonce_bytes = &packet.payload[..12];
        let ciphertext = &packet.payload[12..];
        let nonce = Nonce::from_slice(nonce_bytes);

        let decrypted = peer
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;

        peer.last_activity = Instant::now();

        tracing::trace!(
            peer = %peer_addr,
            len = decrypted.len(),
            "Received encrypted data packet"
        );

        Ok(())
    }

    fn decode_private_key(key_str: &str) -> Result<StaticSecret> {
        let key_bytes = general_purpose::STANDARD
            .decode(key_str)
            .context("Failed to decode private key")?;

        if key_bytes.len() != 32 {
            bail!("Invalid private key length: expected 32 bytes");
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);

        Ok(StaticSecret::from(key_array))
    }

    fn generate_nonce() -> [u8; 12] {
        use rand::Rng;
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill(&mut nonce);
        nonce
    }

    pub async fn shutdown(&self) {
        tracing::info!("Shutting down VPN server");
        let mut peers = self.peers.write().await;
        peers.clear();
    }
}
