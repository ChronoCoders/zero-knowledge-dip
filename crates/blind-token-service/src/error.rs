use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Crypto error: {0}")]
    Crypto(#[from] zkdip_crypto::CryptoError),

    #[error("Subscription already redeemed")]
    AlreadyRedeemed,

    #[error("Invalid subscription")]
    InvalidSubscription,

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Internal server error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Database(ref e) => {
                tracing::error!("Database error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
            }
            AppError::Crypto(ref e) => {
                tracing::error!("Crypto error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Cryptographic error")
            }
            AppError::AlreadyRedeemed => (StatusCode::CONFLICT, "Subscription already redeemed"),
            AppError::InvalidSubscription => (StatusCode::BAD_REQUEST, "Invalid subscription"),
            AppError::Config(ref e) => {
                tracing::error!("Config error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Configuration error")
            }
            AppError::Internal(ref e) => {
                tracing::error!("Internal error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
        };

        let body = Json(json!({
            "error": error_message,
            "details": self.to_string(),
        }));

        (status, body).into_response()
    }
}
