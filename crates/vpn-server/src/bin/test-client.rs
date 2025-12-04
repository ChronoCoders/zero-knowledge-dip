use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use x25519_dalek::{PublicKey, StaticSecret};
use zkdip_crypto::jwt::JwtSigner;

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

#[derive(Parser, Debug)]
#[command(name = "vpn-test-client")]
#[command(about = "Test client for VPN server DAT validation")]
struct Args {
    #[arg(long, help = "VPN server address", default_value = "127.0.0.1:51820")]
    server: String,

    #[arg(long, help = "Server IP (DIP) for DAT token", default_value = "192.168.1.100")]
    ip: String,

    #[arg(
        long,
        help = "JWT secret for DAT generation",
        default_value = "dev_secret_key_change_in_production"
    )]
    jwt_secret: String,

    #[arg(long, help = "Token validity in days", default_value = "7")]
    validity_days: i64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    tracing::info!("Starting VPN test client");
    tracing::info!("Server: {}", args.server);
    tracing::info!("Target IP: {}", args.ip);

    let signer = JwtSigner::new(args.jwt_secret.as_bytes());
    let dat_token = signer
        .generate_dat(args.ip.clone(), args.validity_days)
        .context("Failed to generate DAT token")?;

    tracing::info!("Generated DAT token: {}", dat_token);

    let client = VpnTestClient::new(&args.server).await?;
    client.test_connection(dat_token).await?;

    tracing::info!("Test completed successfully!");

    Ok(())
}

struct VpnTestClient {
    socket: UdpSocket,
    server_addr: String,
    client_private_key: StaticSecret,
    client_public_key: PublicKey,
}

impl VpnTestClient {
    async fn new(server_addr: &str) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind UDP socket")?;

        let client_private_key = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let client_public_key = PublicKey::from(&client_private_key);

        tracing::info!(
            "Client public key: {}",
            general_purpose::STANDARD.encode(client_public_key.as_bytes())
        );

        Ok(Self {
            socket,
            server_addr: server_addr.to_string(),
            client_private_key,
            client_public_key,
        })
    }

    async fn test_connection(&self, dat_token: String) -> Result<()> {
        tracing::info!("Step 1: Sending handshake init...");
        let server_public_key = self.handshake_init().await?;

        tracing::info!("Step 2: Computing shared secret...");
        let shared_secret = self.client_private_key.diffie_hellman(&server_public_key);
        let cipher_key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
        let cipher = Aes256Gcm::new(cipher_key);

        tracing::info!("Step 3: Sending encrypted DAT token...");
        self.send_dat_auth(&cipher, dat_token).await?;

        tracing::info!("Step 4: Waiting for auth response...");
        self.wait_for_auth_response(&cipher).await?;

        tracing::info!("Step 5: Sending test data packet...");
        self.send_test_data(&cipher).await?;

        Ok(())
    }

    async fn handshake_init(&self) -> Result<PublicKey> {
        let packet = Packet {
            packet_type: PacketType::HandshakeInit,
            payload: self.client_public_key.as_bytes().to_vec(),
        };

        let data = serde_json::to_vec(&packet)?;
        self.socket.send_to(&data, &self.server_addr).await?;

        let mut buf = vec![0u8; 65536];
        let (len, _) = self.socket.recv_from(&mut buf).await?;

        let response: Packet = serde_json::from_slice(&buf[..len])?;

        match response.packet_type {
            PacketType::HandshakeResponse => {
                if response.payload.len() != 32 {
                    anyhow::bail!("Invalid server public key length");
                }

                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&response.payload);
                let server_public_key = PublicKey::from(key_bytes);

                tracing::info!(
                    "Received server public key: {}",
                    general_purpose::STANDARD.encode(server_public_key.as_bytes())
                );

                Ok(server_public_key)
            }
            _ => anyhow::bail!("Unexpected packet type in handshake response"),
        }
    }

    async fn send_dat_auth(&self, cipher: &Aes256Gcm, dat_token: String) -> Result<()> {
        let nonce = Self::generate_nonce();
        let nonce_ref = Nonce::from_slice(&nonce);

        let encrypted = cipher
            .encrypt(nonce_ref, dat_token.as_bytes())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

        let mut payload = nonce.to_vec();
        payload.extend_from_slice(&encrypted);

        let packet = Packet {
            packet_type: PacketType::DatAuth,
            payload,
        };

        let data = serde_json::to_vec(&packet)?;
        self.socket.send_to(&data, &self.server_addr).await?;

        tracing::info!("DAT auth packet sent");

        Ok(())
    }

    async fn wait_for_auth_response(&self, cipher: &Aes256Gcm) -> Result<()> {
        let mut buf = vec![0u8; 65536];
        let (len, _) = self.socket.recv_from(&mut buf).await?;

        let response: Packet = serde_json::from_slice(&buf[..len])?;

        match response.packet_type {
            PacketType::DatAuthResponse => {
                if response.payload.len() < 12 {
                    anyhow::bail!("Invalid auth response payload");
                }

                let nonce_bytes = &response.payload[..12];
                let ciphertext = &response.payload[12..];
                let nonce = Nonce::from_slice(nonce_bytes);

                let decrypted = cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;

                let response_msg = String::from_utf8(decrypted)?;

                if response_msg == "AUTH_OK" {
                    tracing::info!("✅ DAT validation successful! Connection authorized!");
                    Ok(())
                } else {
                    anyhow::bail!("Unexpected auth response: {}", response_msg);
                }
            }
            _ => anyhow::bail!("Unexpected packet type in auth response"),
        }
    }

    async fn send_test_data(&self, cipher: &Aes256Gcm) -> Result<()> {
        let test_message = b"Hello from test client!";

        let nonce = Self::generate_nonce();
        let nonce_ref = Nonce::from_slice(&nonce);

        let encrypted = cipher
            .encrypt(nonce_ref, test_message.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

        let mut payload = nonce.to_vec();
        payload.extend_from_slice(&encrypted);

        let packet = Packet {
            packet_type: PacketType::Data,
            payload,
        };

        let data = serde_json::to_vec(&packet)?;
        self.socket.send_to(&data, &self.server_addr).await?;

        tracing::info!("Test data packet sent");

        Ok(())
    }

    fn generate_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill(&mut nonce);
        nonce
    }
}
