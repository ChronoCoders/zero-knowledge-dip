use crate::config::Config;
use std::sync::Arc;
use zkdip_crypto::ecdh::EcdhKeyPair;
use zkdip_crypto::jwt::JwtSigner;

#[derive(Clone)]
pub struct AppState {
    pub jwt_signer: Arc<JwtSigner>,
    pub ecdh_keypair: Arc<EcdhKeyPair>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let jwt_signer = JwtSigner::new(config.jwt_secret.as_bytes());
        let ecdh_keypair = EcdhKeyPair::generate();

        Self {
            jwt_signer: Arc::new(jwt_signer),
            ecdh_keypair: Arc::new(ecdh_keypair),
        }
    }
}
