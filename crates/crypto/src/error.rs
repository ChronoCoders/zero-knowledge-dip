use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("RSA error: {0}")]
    RsaError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),

    #[error("Invalid blinding factor")]
    InvalidBlindingFactor,

    #[error("Decoding error: {0}")]
    DecodingError(String),

    #[error("Invalid signature")]
    InvalidSignature,
}

pub type Result<T> = std::result::Result<T, CryptoError>;
