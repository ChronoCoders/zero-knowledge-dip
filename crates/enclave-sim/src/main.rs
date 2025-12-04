mod attestation;
mod config;
mod error;
mod handlers;
mod state;

use axum::{
    routing::{get, post},
    Router,
};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "enclave_sim=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    dotenvy::dotenv().ok();

    let config = config::Config::from_env()?;
    let state = state::AppState::new(config);

    let app = Router::new()
        .route("/health", get(handlers::health))
        .route("/attestation", post(handlers::get_attestation))
        .route("/api/v1/generate-tokens", post(handlers::generate_tokens))
        .route("/api/v1/refresh-tokens", post(handlers::refresh_tokens))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&format!("0.0.0.0:{}", 3002)).await?;

    tracing::info!("enclave-sim listening on port 3002");

    axum::serve(listener, app).await?;

    Ok(())
}