use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
#[allow(dead_code)]
pub struct Subscription {
    pub id: Uuid,
    pub subscription_id: String,
    pub redeemed: bool,
    pub version: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct BlindSignRequest {
    pub srt: String,
    pub blinded_token: String,
}

#[derive(Debug, Serialize)]
pub struct BlindSignResponse {
    pub blind_signature: String,
}

#[derive(Debug, Serialize)]
pub struct PublicKeyResponse {
    pub public_key_pem: String,
}
