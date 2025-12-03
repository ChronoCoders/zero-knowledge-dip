use crate::error::AppError;

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub rsa_bits: usize,
}

impl Config {
    pub fn from_env() -> Result<Self, AppError> {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost/zkdip".to_string());

        let jwt_secret = std::env::var("JWT_SECRET")
            .unwrap_or_else(|_| "dev_secret_key_change_in_production".to_string());

        let rsa_bits = std::env::var("RSA_BITS")
            .unwrap_or_else(|_| "2048".to_string())
            .parse()
            .map_err(|_| AppError::Config("Invalid RSA_BITS".to_string()))?;

        Ok(Self {
            database_url,
            jwt_secret,
            rsa_bits,
        })
    }
}
