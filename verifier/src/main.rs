use axum::{
    extract::State,
    http::StatusCode,
    Json,
    routing::{get, post},
    Router
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Value, json};
use std::io::{Error, ErrorKind, Read};
use std::fs::File;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use uuid::Uuid;

mod state;
use state::AppState;

mod client;
use client::*;

#[tokio::main]
async fn main() {
    // set up nonce
    let state = Arc::new(AppState {
        nonce: Mutex::new(Uuid::new_v4()),
    });

    // set up routes
    let app = Router::new()
        .route(Endpoint::Nonce.value(), get(get_nonce))
        .route(Endpoint::Verify.value(), post(verify))
        .with_state(state);

    // run app & listen on port 3000
    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn get_nonce(
    State(state): State<Arc<AppState>>
) -> (StatusCode, Json<Value>) {
    match state.nonce.lock() {
        Ok(uuid) => (
            StatusCode::OK,
            Json(json!({ "nonce": uuid.to_string() }))
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "Couldn't retrieve nonce."
            }))
        )
    }
}
    

async fn verify(
    State(state): State<Arc<AppState>>,
    Json(verify_payload): Json<VerifyPayload>
) -> (StatusCode, Json<Value>) {
    // retrieve cur nonce
    let mut current_nonce = match state.nonce.lock() {
        Ok(uuid) => uuid,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Couldn't retrieve nonce."
                }))
            )
        }
    };

    // verify nonce in payload matches current
    if current_nonce.to_string() != verify_payload.payload.nonce {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Invalid nonce."
            }))
        )
    }

    // grab verifying key from file system
    let verifying_key = match get_public_key() {
        Ok(key) => key,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": error.to_string()
                }))
            )
        }
    };

    // convert message to expected &[u8] type
    let message_bytes: &[u8] = verify_payload.payload.message.as_bytes();

    // decode signature
    let decoded_signature = match STANDARD.decode(&verify_payload.signature) {
        Ok(decoded) => decoded,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Could not decode signature."
                }))
            )
        }
    };
    // convert decoded signature to expected type
    let signature_bytes: [u8; 64] = match decoded_signature.try_into() {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Decoded signature did not have 64 bytes."
                }))
            )
        }
    };
    let signature = Signature::from_bytes(&signature_bytes);

    // verify signature
    match verifying_key.verify(message_bytes, &signature) {
        Ok(_) => {
            // rotate nonce on successful verification
            *current_nonce = Uuid::new_v4();
            
            return (
                StatusCode::OK,
                Json(json!({
                    "status": "verified",
                    "message": "Signature is valid."
                }))
            )
        },
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Invalid signature."
                }))
            )
        }
    }

}

fn get_public_key() -> std::io::Result<VerifyingKey> {
    let mut file = File::open("public_key.txt")?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    let contents_as_bytes :[u8; 32] = contents.try_into()
        .map_err(|_| {
            Error::new(
                ErrorKind::InvalidData, 
                "Key is not 32 bytes.")
        })?;
    let key = VerifyingKey::from_bytes(&contents_as_bytes)
        .map_err(|err| {
            Error::new(
                ErrorKind::InvalidData, 
                format!("{}", err.to_string()
            ))
        })?;

    Ok(key)
}