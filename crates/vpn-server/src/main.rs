mod config;
mod server;
mod validator;

use anyhow::Result;
use clap::Parser;
use config::Config;
use server::VpnServer;
use std::net::IpAddr;

#[derive(Parser, Debug)]
#[command(name = "vpn-server")]
#[command(about = "Zero-Knowledge Dedicated IP VPN Server", long_about = None)]
struct Args {
    #[arg(long, help = "Server IP address (DIP)")]
    ip: Option<IpAddr>,

    #[arg(long, help = "JWT secret for DAT validation")]
    jwt_secret: Option<String>,

    #[arg(long, help = "WireGuard port", default_value = "51820")]
    port: u16,
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

    let config = if let Some(ip) = args.ip {
        Config::from_args(ip, args.jwt_secret)?
    } else {
        Config::from_env()?
    };

    tracing::info!(
        server_ip = %config.server_ip,
        port = config.wireguard_port,
        "Starting Zero-Knowledge VPN Server"
    );

    let server = VpnServer::new(config).await?;

    let shutdown_signal = tokio::spawn(async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for ctrl-c");
        tracing::info!("Received shutdown signal");
    });

    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                tracing::error!(error = %e, "Server error");
                return Err(e);
            }
        }
        _ = shutdown_signal => {
            server.shutdown().await;
        }
    }

    Ok(())
}
