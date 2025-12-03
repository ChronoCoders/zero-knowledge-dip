use crate::error::{CryptoError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;

pub struct AesGcmEncryption {
    cipher: Aes256Gcm,
}

impl AesGcmEncryption {
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new(key.into());
        Self { cipher }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt(&self, ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>> {
        if ciphertext_with_nonce.len() < 12 {
            return Err(CryptoError::EncryptionError(
                "Ciphertext too short".to_string(),
            ));
        }

        let nonce = Nonce::from_slice(&ciphertext_with_nonce[..12]);
        let ciphertext = &ciphertext_with_nonce[12..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))
    }

    pub fn encrypt_string(&self, plaintext: &str) -> Result<String> {
        let encrypted = self.encrypt(plaintext.as_bytes())?;
        Ok(general_purpose::STANDARD.encode(encrypted))
    }

    pub fn decrypt_string(&self, ciphertext: &str) -> Result<String> {
        let decoded = general_purpose::STANDARD
            .decode(ciphertext)
            .map_err(|e| CryptoError::DecodingError(e.to_string()))?;
        let decrypted = self.decrypt(&decoded)?;
        String::from_utf8(decrypted).map_err(|e| CryptoError::DecodingError(e.to_string()))
    }
}

pub fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let key = [42u8; 32];
        let encryptor = AesGcmEncryption::new(&key);

        let plaintext = b"Hello, World!";
        let ciphertext = encryptor.encrypt(plaintext).unwrap();
        let decrypted = encryptor.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_string_encryption() {
        let key = [42u8; 32];
        let encryptor = AesGcmEncryption::new(&key);

        let plaintext = "Secret message";
        let ciphertext = encryptor.encrypt_string(plaintext).unwrap();
        let decrypted = encryptor.decrypt_string(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_key_derivation() {
        let key1 = derive_key_from_password("password123", b"salt");
        let key2 = derive_key_from_password("password123", b"salt");
        let key3 = derive_key_from_password("different", b"salt");

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }
}
