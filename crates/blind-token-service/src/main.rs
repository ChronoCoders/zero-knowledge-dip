mod config;
mod error;
mod handlers;
mod models;
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
                .unwrap_or_else(|_| "blind_token_service=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    dotenvy::dotenv().ok();

    let config = config::Config::from_env()?;
    let state = state::AppState::new(config).await?;

    sqlx::migrate!("./migrations").run(&state.db).await?;

    let app = Router::new()
        .route("/health", get(handlers::health))
        .route("/api/v1/public-key", get(handlers::get_public_key))
        .route("/api/v1/blind-sign", post(handlers::blind_sign))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&format!("0.0.0.0:{}", 3001)).await?;

    tracing::info!("blind-token-service listening on port 3001");

    axum::serve(listener, app).await?;

    Ok(())
}
