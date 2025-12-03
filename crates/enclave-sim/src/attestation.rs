use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationDocument {
    pub pcrs: Vec<String>,
    pub public_key: String,
    pub nonce: String,
    pub signature: String,
}

impl AttestationDocument {
    pub fn new(public_key: String, nonce: String) -> Self {
        let pcrs = vec![
            compute_pcr("enclave-sim-v0.1.0"),
            compute_pcr("bootloader"),
            compute_pcr("kernel"),
        ];

        let mut hasher = Sha256::new();
        hasher.update(&public_key);
        hasher.update(&nonce);
        for pcr in &pcrs {
            hasher.update(pcr);
        }
        let signature = hex::encode(hasher.finalize());

        Self {
            pcrs,
            public_key,
            nonce,
            signature,
        }
    }
}

fn compute_pcr(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}
