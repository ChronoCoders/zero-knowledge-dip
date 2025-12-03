use crate::config::Config;
use crate::error::AppError;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::Arc;
use zkdip_crypto::blind_signature::BlindSigner;
use zkdip_crypto::jwt::JwtSigner;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub blind_signer: Arc<BlindSigner>,
    pub jwt_signer: Arc<JwtSigner>,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self, AppError> {
        let db = PgPoolOptions::new()
            .max_connections(5)
            .connect(&config.database_url)
            .await
            .map_err(AppError::Database)?;

        let blind_signer = BlindSigner::new(config.rsa_bits)?;
        let jwt_signer = JwtSigner::new(config.jwt_secret.as_bytes());

        Ok(Self {
            db,
            blind_signer: Arc::new(blind_signer),
            jwt_signer: Arc::new(jwt_signer),
        })
    }
}
