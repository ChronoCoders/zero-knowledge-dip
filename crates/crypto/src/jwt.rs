use crate::error::{CryptoError, Result};
use crate::types::*;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

pub struct JwtSigner {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtSigner {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
        }
    }

    pub fn generate_srt(
        &self,
        subscription_id: String,
        version: u32,
        validity_days: i64,
    ) -> Result<String> {
        let exp = (chrono::Utc::now() + chrono::Duration::days(validity_days)).timestamp() as usize;

        let claims = SrtClaims {
            sub: subscription_id,
            exp,
            entitlements: Entitlements {
                dip: DipEntitlement { did: version },
            },
        };

        encode(&Header::default(), &claims, &self.encoding_key).map_err(CryptoError::JwtError)
    }

    pub fn generate_dat(&self, ip: String, validity_days: i64) -> Result<String> {
        let exp = (chrono::Utc::now() + chrono::Duration::days(validity_days)).timestamp() as usize;

        let claims = DatClaims {
            exp,
            dip_details: DedicatedIpDetails { ip },
        };

        encode(&Header::default(), &claims, &self.encoding_key).map_err(CryptoError::JwtError)
    }

    pub fn generate_drt(
        &self,
        subscription_id: String,
        ip: String,
        version: u32,
        validity_days: i64,
    ) -> Result<String> {
        let exp = (chrono::Utc::now() + chrono::Duration::days(validity_days)).timestamp() as usize;

        let claims = DrtClaims {
            sub: subscription_id,
            exp,
            dip_details: DedicatedIpDetails { ip },
            did: version,
        };

        encode(&Header::default(), &claims, &self.encoding_key).map_err(CryptoError::JwtError)
    }

    pub fn verify_srt(&self, token: &str) -> Result<SrtClaims> {
        let validation = Validation::new(Algorithm::HS256);
        let token_data = decode::<SrtClaims>(token, &self.decoding_key, &validation)?;
        Ok(token_data.claims)
    }

    pub fn verify_dat(&self, token: &str) -> Result<DatClaims> {
        let validation = Validation::new(Algorithm::HS256);
        let token_data = decode::<DatClaims>(token, &self.decoding_key, &validation)?;
        Ok(token_data.claims)
    }

    pub fn verify_drt(&self, token: &str) -> Result<DrtClaims> {
        let validation = Validation::new(Algorithm::HS256);
        let token_data = decode::<DrtClaims>(token, &self.decoding_key, &validation)?;
        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srt_generation_and_verification() {
        let signer = JwtSigner::new(b"test_secret");
        let srt = signer.generate_srt("sub123".to_string(), 0, 3).unwrap();
        let claims = signer.verify_srt(&srt).unwrap();

        assert_eq!(claims.sub, "sub123");
        assert_eq!(claims.entitlements.dip.did, 0);
    }

    #[test]
    fn test_dat_generation_and_verification() {
        let signer = JwtSigner::new(b"test_secret");
        let dat = signer.generate_dat("192.168.1.1".to_string(), 3).unwrap();
        let claims = signer.verify_dat(&dat).unwrap();

        assert_eq!(claims.dip_details.ip, "192.168.1.1");
    }

    #[test]
    fn test_drt_generation_and_verification() {
        let signer = JwtSigner::new(b"test_secret");
        let drt = signer
            .generate_drt("sub123".to_string(), "192.168.1.1".to_string(), 0, 60)
            .unwrap();
        let claims = signer.verify_drt(&drt).unwrap();

        assert_eq!(claims.sub, "sub123");
        assert_eq!(claims.dip_details.ip, "192.168.1.1");
        assert_eq!(claims.did, 0);
    }
}
