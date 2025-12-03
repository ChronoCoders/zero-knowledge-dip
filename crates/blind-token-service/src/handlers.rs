use crate::error::AppError;
use crate::models::{BlindSignRequest, BlindSignResponse, PublicKeyResponse, Subscription};
use crate::state::AppState;
use axum::{extract::State, Json};
use base64::{engine::general_purpose, Engine as _};
use serde_json::{json, Value};
use uuid::Uuid;

pub async fn health() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "blind-token-service"
    }))
}

pub async fn get_public_key(
    State(state): State<AppState>,
) -> Result<Json<PublicKeyResponse>, AppError> {
    let public_key_pem = state.blind_signer.public_key_pem()?;

    Ok(Json(PublicKeyResponse { public_key_pem }))
}

pub async fn blind_sign(
    State(state): State<AppState>,
    Json(req): Json<BlindSignRequest>,
) -> Result<Json<BlindSignResponse>, AppError> {
    let srt_claims = state.jwt_signer.verify_srt(&req.srt)?;

    let mut tx = state.db.begin().await?;

    let existing: Option<Subscription> =
        sqlx::query_as("SELECT * FROM subscriptions WHERE subscription_id = $1")
            .bind(&srt_claims.sub)
            .fetch_optional(&mut *tx)
            .await?;

    match existing {
        Some(sub) => {
            if sub.redeemed {
                return Err(AppError::AlreadyRedeemed);
            }

            if sub.version != srt_claims.entitlements.dip.did as i32 {
                return Err(AppError::InvalidSubscription);
            }

            sqlx::query(
                "UPDATE subscriptions SET redeemed = true, updated_at = NOW() WHERE id = $1",
            )
            .bind(sub.id)
            .execute(&mut *tx)
            .await?;
        }
        None => {
            sqlx::query(
                "INSERT INTO subscriptions (id, subscription_id, redeemed, version) VALUES ($1, $2, $3, $4)"
            )
            .bind(Uuid::new_v4())
            .bind(&srt_claims.sub)
            .bind(true)
            .bind(srt_claims.entitlements.dip.did as i32)
            .execute(&mut *tx)
            .await?;
        }
    }

    tx.commit().await?;

    let blinded_bytes = general_purpose::STANDARD
        .decode(&req.blinded_token)
        .map_err(|e| AppError::Internal(format!("Invalid base64: {}", e)))?;

    let signature = state.blind_signer.blind_sign(&blinded_bytes)?;

    let signature_b64 = general_purpose::STANDARD.encode(&signature);

    Ok(Json(BlindSignResponse {
        blind_signature: signature_b64,
    }))
}
