use serde::Deserialize;

pub enum Endpoint {
    Nonce, Verify
}

impl Endpoint {
    pub fn value(&self) -> &'static str {
        match self {
            Endpoint::Nonce => "/nonce",
            Endpoint::Verify => "/verify"
        }
    }
}

#[derive(Deserialize)]
pub struct Payload {
    pub message: String,
    pub nonce: String,
}

#[derive(Deserialize)]
pub struct VerifyPayload {
    pub payload: Payload,
    pub signature: String,
}