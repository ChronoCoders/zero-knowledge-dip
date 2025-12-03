use crate::error::{CryptoError, Result};
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::rngs::OsRng;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey};

pub struct BlindSigner {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl BlindSigner {
    pub fn new(bits: usize) -> Result<Self> {
        let mut rng = OsRng;
        let private_key =
            RsaPrivateKey::new(&mut rng, bits).map_err(|e| CryptoError::RsaError(e.to_string()))?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(Self {
            private_key,
            public_key,
        })
    }

    pub fn from_private_key(private_key: RsaPrivateKey) -> Self {
        let public_key = RsaPublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }

    pub fn blind_sign(&self, blinded_message: &[u8]) -> Result<Vec<u8>> {
        let blinded = BigUint::from_bytes_be(blinded_message);
        let n = BigUint::from_bytes_be(&self.private_key.n().to_bytes_be());

        if blinded >= n {
            return Err(CryptoError::RsaError(
                "Blinded message too large".to_string(),
            ));
        }

        let d = BigUint::from_bytes_be(&self.private_key.d().to_bytes_be());
        let signature = blinded.modpow(&d, &n);

        Ok(signature.to_bytes_be())
    }

    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }

    pub fn public_key_pem(&self) -> Result<String> {
        use rsa::pkcs8::EncodePublicKey;
        self.public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| CryptoError::RsaError(e.to_string()))
    }

    pub fn private_key_pem(&self) -> Result<String> {
        use rsa::pkcs8::EncodePrivateKey;
        self.private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map(|s| s.to_string())
            .map_err(|e| CryptoError::RsaError(e.to_string()))
    }
}

pub struct BlindClient {
    public_key: RsaPublicKey,
}

impl BlindClient {
    pub fn new(public_key: RsaPublicKey) -> Self {
        Self { public_key }
    }

    pub fn from_pem(pem: &str) -> Result<Self> {
        use rsa::pkcs8::DecodePublicKey;
        let public_key = RsaPublicKey::from_public_key_pem(pem)
            .map_err(|e| CryptoError::RsaError(e.to_string()))?;
        Ok(Self { public_key })
    }

    pub fn blind(&self, message: &[u8]) -> Result<crate::types::BlindedToken> {
        let mut rng = OsRng;
        let n = BigUint::from_bytes_be(&self.public_key.n().to_bytes_be());
        let e = BigUint::from_bytes_be(&self.public_key.e().to_bytes_be());

        let mut attempts = 0;

        let r = loop {
            if attempts > 100 {
                return Err(CryptoError::InvalidBlindingFactor);
            }

            let candidate = rng.gen_biguint_range(&BigUint::from(2u32), &n);

            if num_integer::Integer::gcd(&candidate, &n) == BigUint::one() {
                break candidate;
            }

            attempts += 1;
        };

        let message_int = BigUint::from_bytes_be(message);
        let r_e = r.modpow(&e, &n);
        let blinded = (message_int * r_e) % &n;

        Ok(crate::types::BlindedToken {
            blinded_message: blinded.to_bytes_be(),
            blinding_factor: r.to_bytes_be(),
        })
    }

    pub fn unblind(
        &self,
        blind_signature: &[u8],
        blinding_factor: &[u8],
    ) -> Result<crate::types::UnblindedSignature> {
        let n = BigUint::from_bytes_be(&self.public_key.n().to_bytes_be());
        let sig = BigUint::from_bytes_be(blind_signature);
        let r = BigUint::from_bytes_be(blinding_factor);

        let r_inv = r.modinv(&n).ok_or(CryptoError::InvalidBlindingFactor)?;

        let unblinded = (sig * r_inv) % &n;

        Ok(crate::types::UnblindedSignature {
            signature: unblinded.to_bytes_be(),
        })
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let n = BigUint::from_bytes_be(&self.public_key.n().to_bytes_be());
        let e = BigUint::from_bytes_be(&self.public_key.e().to_bytes_be());

        let sig = BigUint::from_bytes_be(signature);
        let msg = BigUint::from_bytes_be(message);

        let verified = sig.modpow(&e, &n);

        Ok(verified == msg % &n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blind_signature_flow() {
        let signer = BlindSigner::new(2048).unwrap();
        let client = BlindClient::new(signer.public_key().clone());

        let message = b"test message for blind signature";

        let blinded_token = client.blind(message).unwrap();
        let blind_sig = signer.blind_sign(&blinded_token.blinded_message).unwrap();
        let unblinded = client
            .unblind(&blind_sig, &blinded_token.blinding_factor)
            .unwrap();

        assert!(client.verify(message, &unblinded.signature).unwrap());
    }

    #[test]
    fn test_pem_serialization() {
        let signer = BlindSigner::new(2048).unwrap();
        let pem = signer.public_key_pem().unwrap();

        let client = BlindClient::from_pem(&pem).unwrap();

        let message = b"test";
        let blinded = client.blind(message).unwrap();
        let sig = signer.blind_sign(&blinded.blinded_message).unwrap();
        let unblinded = client.unblind(&sig, &blinded.blinding_factor).unwrap();

        assert!(client.verify(message, &unblinded.signature).unwrap());
    }
}
