use crate::attestation::AttestationDocument;
use crate::error::AppError;
use crate::state::AppState;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zkdip_crypto::encryption::AesGcmEncryption;

#[derive(Debug, Deserialize)]
pub struct AttestationRequest {
    pub nonce: String,
}

#[derive(Debug, Serialize)]
pub struct AttestationResponse {
    pub attestation: AttestationDocument,
}

#[derive(Debug, Deserialize)]
pub struct GenerateTokensRequest {
    pub encrypted_srt: String,
    pub client_public_key: String,
}

#[derive(Debug, Serialize)]
pub struct GenerateTokensResponse {
    pub dat: String,
    pub encrypted_drt: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokensRequest {
    pub encrypted_srt: String,
    pub encrypted_drt: String,
    pub client_public_key: String,
}

#[derive(Debug, Serialize)]
pub struct RefreshTokensResponse {
    pub dat: String,
    pub encrypted_drt: String,
}

pub async fn health() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "enclave-sim"
    }))
}

pub async fn get_attestation(
    State(state): State<AppState>,
    Json(req): Json<AttestationRequest>,
) -> Result<Json<AttestationResponse>, AppError> {
    let public_key_b64 = state.ecdh_keypair.public_key_base64();
    let attestation = AttestationDocument::new(public_key_b64, req.nonce);

    Ok(Json(AttestationResponse { attestation }))
}

pub async fn generate_tokens(
    State(state): State<AppState>,
    Json(req): Json<GenerateTokensRequest>,
) -> Result<Json<GenerateTokensResponse>, AppError> {
    let client_public_key = zkdip_crypto::ecdh::public_key_from_base64(&req.client_public_key)?;

    let shared_secret = state.ecdh_keypair.diffie_hellman(&client_public_key);
    let encryptor = AesGcmEncryption::new(&shared_secret);

    let srt = encryptor
        .decrypt_string(&req.encrypted_srt)
        .map_err(|e| AppError::Internal(format!("Failed to decrypt SRT: {}", e)))?;

    let srt_claims = state.jwt_signer.verify_srt(&srt)?;

    let ip = "192.168.1.100".to_string();

    let dat = state.jwt_signer.generate_dat(ip.clone(), 3)?;

    let drt = state.jwt_signer.generate_drt(
        srt_claims.sub.clone(),
        ip,
        srt_claims.entitlements.dip.did,
        60,
    )?;

    let encrypted_drt = encryptor
        .encrypt_string(&drt)
        .map_err(|e| AppError::Internal(format!("Failed to encrypt DRT: {}", e)))?;

    Ok(Json(GenerateTokensResponse { dat, encrypted_drt }))
}

pub async fn refresh_tokens(
    State(state): State<AppState>,
    Json(req): Json<RefreshTokensRequest>,
) -> Result<Json<RefreshTokensResponse>, AppError> {
    let client_public_key = zkdip_crypto::ecdh::public_key_from_base64(&req.client_public_key)?;

    let shared_secret = state.ecdh_keypair.diffie_hellman(&client_public_key);
    let encryptor = AesGcmEncryption::new(&shared_secret);

    let srt = encryptor
        .decrypt_string(&req.encrypted_srt)
        .map_err(|e| AppError::Internal(format!("Failed to decrypt SRT: {}", e)))?;

    let drt = encryptor
        .decrypt_string(&req.encrypted_drt)
        .map_err(|e| AppError::Internal(format!("Failed to decrypt DRT: {}", e)))?;

    let srt_claims = state.jwt_signer.verify_srt(&srt)?;
    let drt_claims = state.jwt_signer.verify_drt(&drt)?;

    if srt_claims.sub != drt_claims.sub {
        return Err(AppError::TokenMismatch);
    }

    if srt_claims.entitlements.dip.did != drt_claims.did {
        return Err(AppError::TokenMismatch);
    }

    let new_dat = state
        .jwt_signer
        .generate_dat(drt_claims.dip_details.ip.clone(), 3)?;

    let new_drt = state.jwt_signer.generate_drt(
        drt_claims.sub.clone(),
        drt_claims.dip_details.ip.clone(),
        drt_claims.did,
        60,
    )?;

    let encrypted_drt = encryptor
        .encrypt_string(&new_drt)
        .map_err(|e| AppError::Internal(format!("Failed to encrypt DRT: {}", e)))?;

    Ok(Json(RefreshTokensResponse {
        dat: new_dat,
        encrypted_drt,
    }))
}
