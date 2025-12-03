use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedicatedIpDetails {
    pub ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrtClaims {
    pub sub: String,
    pub exp: usize,
    pub entitlements: Entitlements,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlements {
    #[serde(rename = "xv.vpn.dip")]
    pub dip: DipEntitlement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DipEntitlement {
    pub did: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatClaims {
    pub exp: usize,
    #[serde(rename = "xv.vpn.dip.details")]
    pub dip_details: DedicatedIpDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrtClaims {
    pub sub: String,
    pub exp: usize,
    #[serde(rename = "xv.vpn.dip.details")]
    pub dip_details: DedicatedIpDetails,
    pub did: u32,
}

#[derive(Debug, Clone)]
pub struct BlindedToken {
    pub blinded_message: Vec<u8>,
    pub blinding_factor: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct UnblindedSignature {
    pub signature: Vec<u8>,
}
