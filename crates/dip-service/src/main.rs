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
                .unwrap_or_else(|_| "dip_service=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    dotenvy::dotenv().ok();

    let config = config::Config::from_env()?;
    let state = state::AppState::new(config).await?;

    sqlx::migrate!("./migrations").run(&state.db).await?;

    let app = Router::new()
        .route("/health", get(handlers::health))
        .route("/api/v1/assign", post(handlers::assign_dip))
        .route("/api/v1/refresh", post(handlers::refresh_dip))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&format!("0.0.0.0:{}", 3003)).await?;

    tracing::info!("dip-service listening on port 3003");

    axum::serve(listener, app).await?;

    Ok(())
}
