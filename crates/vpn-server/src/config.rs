use anyhow::{Context, Result};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct Config {
    pub server_ip: IpAddr,
    pub jwt_secret: String,
    pub wireguard_private_key: String,
    pub wireguard_port: u16,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        let server_ip = std::env::var("SERVER_IP")
            .context("SERVER_IP not set")?
            .parse()
            .context("Invalid SERVER_IP format")?;

        let jwt_secret = std::env::var("JWT_SECRET").context("JWT_SECRET not set")?;

        let wireguard_private_key =
            std::env::var("WIREGUARD_PRIVATE_KEY").unwrap_or_else(|_| {
                let key = generate_private_key();
                tracing::warn!("WIREGUARD_PRIVATE_KEY not set, generated: {}", key);
                key
            });

        let wireguard_port = std::env::var("WIREGUARD_PORT")
            .unwrap_or_else(|_| "51820".to_string())
            .parse()
            .context("Invalid WIREGUARD_PORT format")?;

        Ok(Self {
            server_ip,
            jwt_secret,
            wireguard_private_key,
            wireguard_port,
        })
    }

    pub fn from_args(server_ip: IpAddr, jwt_secret: Option<String>) -> Result<Self> {
        dotenvy::dotenv().ok();

        let jwt_secret = jwt_secret
            .or_else(|| std::env::var("JWT_SECRET").ok())
            .context("JWT_SECRET must be provided via --jwt-secret or environment")?;

        let wireguard_private_key =
            std::env::var("WIREGUARD_PRIVATE_KEY").unwrap_or_else(|_| {
                let key = generate_private_key();
                tracing::warn!("WIREGUARD_PRIVATE_KEY not set, generated: {}", key);
                key
            });

        let wireguard_port = std::env::var("WIREGUARD_PORT")
            .unwrap_or_else(|_| "51820".to_string())
            .parse()
            .context("Invalid WIREGUARD_PORT format")?;

        Ok(Self {
            server_ip,
            jwt_secret,
            wireguard_private_key,
            wireguard_port,
        })
    }
}

fn generate_private_key() -> String {
    use x25519_dalek::StaticSecret;
    use rand::rngs::OsRng;
    let secret = StaticSecret::random_from_rng(OsRng);
    base64::encode(secret.to_bytes())
}
