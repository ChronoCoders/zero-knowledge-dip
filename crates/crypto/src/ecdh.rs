use crate::error::{CryptoError, Result};
use base64::{engine::general_purpose, Engine as _};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct EcdhKeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl EcdhKeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn from_secret(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn public_key_base64(&self) -> String {
        general_purpose::STANDARD.encode(self.public.as_bytes())
    }

    pub fn diffie_hellman(&self, their_public: &PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(their_public).to_bytes()
    }
}

pub fn public_key_from_base64(b64: &str) -> Result<PublicKey> {
    let bytes = general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| CryptoError::DecodingError(e.to_string()))?;

    if bytes.len() != 32 {
        return Err(CryptoError::DecodingError(
            "Invalid public key length".to_string(),
        ));
    }

    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(PublicKey::from(array))
}

pub fn public_key_from_bytes(bytes: &[u8]) -> Result<PublicKey> {
    if bytes.len() != 32 {
        return Err(CryptoError::DecodingError(
            "Invalid public key length".to_string(),
        ));
    }

    let mut array = [0u8; 32];
    array.copy_from_slice(bytes);
    Ok(PublicKey::from(array))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_key_exchange() {
        let alice = EcdhKeyPair::generate();
        let bob = EcdhKeyPair::generate();

        let alice_shared = alice.diffie_hellman(bob.public_key());
        let bob_shared = bob.diffie_hellman(alice.public_key());

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_public_key_serialization() {
        let keypair = EcdhKeyPair::generate();
        let b64 = keypair.public_key_base64();
        let restored = public_key_from_base64(&b64).unwrap();

        assert_eq!(keypair.public_key().as_bytes(), restored.as_bytes());
    }
}
