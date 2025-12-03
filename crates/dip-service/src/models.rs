use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
#[allow(dead_code)]
pub struct IpPool {
    pub id: Uuid,
    pub ip: String,
    pub status: String,
    pub reserved_until: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, FromRow)]
#[allow(dead_code)]
pub struct Assignment {
    pub id: Uuid,
    pub blinded_token_hash: String,
    pub ip: String,
    pub assigned_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct AssignRequest {
    pub unblinded_signature: String,
}

#[derive(Debug, Serialize)]
pub struct AssignResponse {
    pub dat: String,
    pub encrypted_drt: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub encrypted_srt: String,
    pub client_public_key: String,
}

#[derive(Debug, Serialize)]
pub struct RefreshResponse {
    pub dat: String,
    pub encrypted_drt: String,
}
