use crate::config::Config;
use crate::error::AppError;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub enclave_url: String,
    pub http_client: Arc<reqwest::Client>,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self, AppError> {
        let db = PgPoolOptions::new()
            .max_connections(5)
            .connect(&config.database_url)
            .await
            .map_err(AppError::Database)?;

        let http_client = reqwest::Client::new();

        Ok(Self {
            db,
            enclave_url: config.enclave_url,
            http_client: Arc::new(http_client),
        })
    }
}
