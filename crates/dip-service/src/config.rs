use crate::error::AppError;

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub enclave_url: String,
}

impl Config {
    pub fn from_env() -> Result<Self, AppError> {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost/zkdip".to_string());

        let enclave_url =
            std::env::var("ENCLAVE_URL").unwrap_or_else(|_| "http://localhost:3002".to_string());

        Ok(Self {
            database_url,
            enclave_url,
        })
    }
}
