use anyhow::{anyhow, bail, Context, Result};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use zkdip_crypto::{jwt::JwtSigner, types::DatClaims};

pub struct DatValidator {
    jwt_signer: JwtSigner,
    expected_ip: IpAddr,
}

impl DatValidator {
    pub fn new(jwt_secret: &str, expected_ip: IpAddr) -> Self {
        let jwt_signer = JwtSigner::new(jwt_secret.as_bytes());
        Self {
            jwt_signer,
            expected_ip,
        }
    }

    pub fn validate(&self, token: &str) -> Result<DatClaims> {
        let claims = self
            .jwt_signer
            .verify_dat(token)
            .context("Failed to verify DAT token signature")?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        if claims.exp < now {
            bail!("DAT token has expired");
        }

        let token_ip: IpAddr = claims
            .dip_details
            .ip
            .parse()
            .context("Invalid IP address in DAT token")?;

        if token_ip != self.expected_ip {
            bail!(
                "DAT token IP mismatch: expected {}, got {}",
                self.expected_ip,
                token_ip
            );
        }

        tracing::info!(
            ip = %token_ip,
            exp = claims.exp,
            "DAT token validated successfully"
        );

        Ok(claims)
    }

    pub fn validate_base64(&self, token_b64: &str) -> Result<DatClaims> {
        let token = String::from_utf8(
            base64::decode(token_b64).context("Failed to decode base64 DAT token")?,
        )
        .context("DAT token is not valid UTF-8")?;

        self.validate(&token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_dat_token() {
        let secret = "test_secret";
        let ip = "192.168.1.100".parse().unwrap();
        let signer = JwtSigner::new(secret.as_bytes());

        let token = signer.generate_dat("192.168.1.100".to_string(), 1).unwrap();

        let validator = DatValidator::new(secret, ip);
        let result = validator.validate(&token);

        assert!(result.is_ok());
        let claims = result.unwrap();
        assert_eq!(claims.dip_details.ip, "192.168.1.100");
    }

    #[test]
    fn test_invalid_ip_mismatch() {
        let secret = "test_secret";
        let ip = "192.168.1.100".parse().unwrap();
        let signer = JwtSigner::new(secret.as_bytes());

        let token = signer.generate_dat("192.168.1.200".to_string(), 1).unwrap();

        let validator = DatValidator::new(secret, ip);
        let result = validator.validate(&token);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("IP mismatch"));
    }

    #[test]
    fn test_expired_token() {
        let secret = "test_secret";
        let ip = "192.168.1.100".parse().unwrap();
        let signer = JwtSigner::new(secret.as_bytes());

        let token = signer.generate_dat("192.168.1.100".to_string(), -1).unwrap();

        let validator = DatValidator::new(secret, ip);
        let result = validator.validate(&token);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn test_invalid_signature() {
        let secret = "test_secret";
        let wrong_secret = "wrong_secret";
        let ip = "192.168.1.100".parse().unwrap();
        let signer = JwtSigner::new(secret.as_bytes());

        let token = signer.generate_dat("192.168.1.100".to_string(), 1).unwrap();

        let validator = DatValidator::new(wrong_secret, ip);
        let result = validator.validate(&token);

        assert!(result.is_err());
    }
}
