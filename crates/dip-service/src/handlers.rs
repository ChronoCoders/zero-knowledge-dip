use crate::error::AppError;
use crate::models::{
    AssignRequest, AssignResponse, Assignment, IpPool, RefreshRequest, RefreshResponse,
};
use crate::state::AppState;
use axum::{extract::State, Json};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zkdip_crypto::ecdh::EcdhKeyPair;
use zkdip_crypto::encryption::AesGcmEncryption;

#[derive(Serialize)]
struct EnclaveGenerateRequest {
    encrypted_srt: String,
    client_public_key: String,
}

#[derive(Deserialize)]
struct EnclaveGenerateResponse {
    dat: String,
    encrypted_drt: String,
}

#[derive(Serialize)]
struct EnclaveRefreshRequest {
    encrypted_srt: String,
    encrypted_drt: String,
    client_public_key: String,
}

#[derive(Deserialize)]
struct EnclaveRefreshResponse {
    dat: String,
    encrypted_drt: String,
}

pub async fn health() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "dip-service"
    }))
}

pub async fn assign_dip(
    State(state): State<AppState>,
    Json(req): Json<AssignRequest>,
) -> Result<Json<AssignResponse>, AppError> {
    let signature_bytes = general_purpose::STANDARD
        .decode(&req.unblinded_signature)
        .map_err(|e| AppError::Internal(format!("Invalid base64: {}", e)))?;

    let mut hasher = Sha256::new();
    hasher.update(&signature_bytes);
    let token_hash = hex::encode(hasher.finalize());

    let mut tx = state.db.begin().await?;

    let existing: Option<Assignment> =
        sqlx::query_as("SELECT * FROM assignments WHERE blinded_token_hash = $1")
            .bind(&token_hash)
            .fetch_optional(&mut *tx)
            .await?;

    if existing.is_some() {
        return Err(AppError::InvalidToken);
    }

    let ip: Option<IpPool> = sqlx::query_as(
        "SELECT * FROM ip_pool WHERE status = 'available' ORDER BY created_at LIMIT 1 FOR UPDATE",
    )
    .fetch_optional(&mut *tx)
    .await?;

    let ip = ip.ok_or(AppError::NoAvailableIps)?;

    sqlx::query(
        "UPDATE ip_pool SET status = 'reserved', reserved_until = NOW() + INTERVAL '3 days', updated_at = NOW() WHERE id = $1"
    )
    .bind(ip.id)
    .execute(&mut *tx)
    .await?;

    sqlx::query("INSERT INTO assignments (id, blinded_token_hash, ip) VALUES ($1, $2, $3)")
        .bind(Uuid::new_v4())
        .bind(&token_hash)
        .bind(&ip.ip)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    let client_keypair = EcdhKeyPair::generate();
    let client_public_b64 = client_keypair.public_key_base64();

    let srt = state
        .jwt_signer
        .generate_srt(format!("anonymous_{}", token_hash), 0, 3)?;

    let enclave_public_response: serde_json::Value = state
        .http_client
        .post(format!("{}/attestation", state.enclave_url))
        .json(&json!({ "nonce": "request_nonce" }))
        .send()
        .await?
        .json()
        .await?;

    let enclave_public_key_b64 = enclave_public_response["attestation"]["public_key"]
        .as_str()
        .ok_or_else(|| AppError::Internal("Missing enclave public key".to_string()))?;

    let enclave_public = zkdip_crypto::ecdh::public_key_from_base64(enclave_public_key_b64)?;
    let shared_secret = client_keypair.diffie_hellman(&enclave_public);
    let encryptor = AesGcmEncryption::new(&shared_secret);

    let encrypted_srt = encryptor
        .encrypt_string(&srt)
        .map_err(|e| AppError::Internal(format!("Failed to encrypt SRT: {}", e)))?;

    let enclave_req = EnclaveGenerateRequest {
        encrypted_srt,
        client_public_key: client_public_b64,
    };

    let enclave_response: EnclaveGenerateResponse = state
        .http_client
        .post(format!("{}/api/v1/generate-tokens", state.enclave_url))
        .json(&enclave_req)
        .send()
        .await?
        .json()
        .await?;

    Ok(Json(AssignResponse {
        dat: enclave_response.dat,
        encrypted_drt: enclave_response.encrypted_drt,
    }))
}

pub async fn refresh_dip(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>, AppError> {
    let enclave_req = EnclaveRefreshRequest {
        encrypted_srt: req.encrypted_srt,
        encrypted_drt: "placeholder".to_string(),
        client_public_key: req.client_public_key,
    };

    let response = state
        .http_client
        .post(format!("{}/api/v1/refresh-tokens", state.enclave_url))
        .json(&enclave_req)
        .send()
        .await?;

    let enclave_response: EnclaveRefreshResponse = response.json().await?;

    Ok(Json(RefreshResponse {
        dat: enclave_response.dat,
        encrypted_drt: enclave_response.encrypted_drt,
    }))
}