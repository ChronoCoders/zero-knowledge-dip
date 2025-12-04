use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use zkdip_crypto::blind_signature::BlindClient;
use zkdip_crypto::jwt::JwtSigner;
use rand::Rng;

const BLIND_TOKEN_SERVICE: &str = "http://localhost:3001";
const DIP_SERVICE: &str = "http://localhost:3003";

#[derive(Serialize)]
struct BlindSignRequest {
    srt: String,
    blinded_token: String,
}

#[derive(Deserialize)]
struct BlindSignResponse {
    blind_signature: String,
}

#[derive(Deserialize)]
struct PublicKeyResponse {
    public_key_pem: String,
}

#[derive(Serialize)]
struct AssignRequest {
    unblinded_signature: String,
}

#[derive(Deserialize)]
struct AssignResponse {
    dat: String,
    encrypted_drt: String,
}

pub async fn run(subscription_id: String) -> Result<()> {
    println!("{}", "🚀 Starting DIP Assignment Flow".bold().green());
    println!();

    println!(
        "{}",
        "Step 1: Generate SRT (Subscription Receipt Token)".bold()
    );
    let jwt_signer = JwtSigner::new(b"dev_secret_key_change_in_production");
    let srt = jwt_signer.generate_srt(subscription_id.clone(), 0, 3)?;
    println!("✅ SRT generated");
    println!();

    println!("{}", "Step 2: Fetch Blind Token Service public key".bold());
    let client = reqwest::Client::new();
    let response: PublicKeyResponse = client
        .get(format!("{}/api/v1/public-key", BLIND_TOKEN_SERVICE))
        .send()
        .await?
        .json()
        .await?;
    println!("✅ Public key received");
    println!();

    println!("{}", "Step 3: Create blinded token".bold());
    let blind_client = BlindClient::from_pem(&response.public_key_pem)?;
    
    let mut rng = rand::rng();
    let random_bytes: Vec<u8> = (0..32).map(|_| rng.random()).collect();
    let message = random_bytes.as_slice();
    
    let blinded = blind_client.blind(message)?;
    println!("✅ Token blinded");
    println!();

    println!("{}", "Step 4: Request blind signature from service".bold());
    let blind_request = BlindSignRequest {
        srt: srt.clone(),
        blinded_token: general_purpose::STANDARD.encode(&blinded.blinded_message),
    };
    let blind_response: BlindSignResponse = client
        .post(format!("{}/api/v1/blind-sign", BLIND_TOKEN_SERVICE))
        .json(&blind_request)
        .send()
        .await?
        .json()
        .await?;
    println!("✅ Blind signature received");
    println!();

    println!("{}", "Step 5: Unblind signature".bold());
    let blind_sig = general_purpose::STANDARD.decode(&blind_response.blind_signature)?;
    let unblinded = blind_client.unblind(&blind_sig, &blinded.blinding_factor)?;
    println!("✅ Signature unblinded");
    println!();

    println!("{}", "Step 6: Verify signature".bold());
    let verified = blind_client.verify(message, &unblinded.signature)?;
    if !verified {
        anyhow::bail!("Signature verification failed!");
    }
    println!("✅ Signature verified");
    println!();

    println!("{}", "Step 7: Request DIP assignment".bold());
    let assign_request = AssignRequest {
        unblinded_signature: general_purpose::STANDARD.encode(&unblinded.signature),
    };
    let assign_response: AssignResponse = client
        .post(format!("{}/api/v1/assign", DIP_SERVICE))
        .json(&assign_request)
        .send()
        .await?
        .json()
        .await?;
    println!("✅ DIP assigned");
    println!();

    println!("{}", "🎉 Success!".bold().green());
    println!("{}: {}", "DAT".bold(), assign_response.dat);
    println!(
        "{}: {}",
        "Encrypted DRT".bold(),
        assign_response.encrypted_drt
    );

    Ok(())
}