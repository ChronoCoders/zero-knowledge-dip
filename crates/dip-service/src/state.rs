use crate::config::Config;
use crate::error::AppError;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::Arc;
use zkdip_crypto::jwt::JwtSigner;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub enclave_url: String,
    pub http_client: Arc<reqwest::Client>,
    pub jwt_signer: Arc<JwtSigner>,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self, AppError> {
        let db = PgPoolOptions::new()
            .max_connections(5)
            .connect(&config.database_url)
            .await
            .map_err(AppError::Database)?;

        let http_client = reqwest::Client::new();
        let jwt_signer = JwtSigner::new(config.jwt_secret.as_bytes());

        Ok(Self {
            db,
            enclave_url: config.enclave_url,
            http_client: Arc::new(http_client),
            jwt_signer: Arc::new(jwt_signer),
        })
    }
}