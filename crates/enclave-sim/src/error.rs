use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] zkdip_crypto::CryptoError),

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Token mismatch")]
    TokenMismatch,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Crypto(ref e) => {
                tracing::error!("Crypto error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Cryptographic error")
            }
            AppError::Internal(ref e) => {
                tracing::error!("Internal error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            AppError::TokenMismatch => {
                tracing::warn!("Token mismatch");
                (StatusCode::BAD_REQUEST, "Token mismatch")
            }
        };

        let body = Json(json!({
            "error": error_message,
            "details": self.to_string(),
        }));

        (status, body).into_response()
    }
}
