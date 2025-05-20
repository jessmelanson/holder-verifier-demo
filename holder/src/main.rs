use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use reqwest::{Client, Error};
use serde_json::json;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

#[tokio::main]
async fn main() {
    // generate key
    let mut csprng = OsRng;
    let mut signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    let mut file = File::create("public_key.txt")
        .expect("Couldn't create file.");
    let _ = file.write_all(verifying_key.as_bytes())
        .expect("Couldn't write to file.");

    // set up api client
    let client = Client::new();

    // get nonce
    let nonce = request_nonce(&client)
        .await
        .expect("Couldn't retrieve nonce.");

    // verify request
    let verification_res = request_verification(&client, &mut signing_key, &nonce).await;
    let result = match verification_res {
        Ok(message) => message,
        Err(error) => error.to_string()
    };
    println!("RESULT: {result}");
        
}

async fn request_nonce(client: &Client) -> Result<String, Error> {
    let nonce_res = client.get("http://localhost:3000/nonce")
        .send()
        .await?
        .json::<HashMap<String, String>>()
        .await?;
    let nonce = nonce_res.get("nonce")
        .expect("Missing nonce in response.")
        .to_string();
    Ok(nonce)
}

async fn request_verification(
    client: &Client,
    signing_key: &mut SigningKey,
    nonce: &str
) -> Result<String, Error> {
    // get signature
    let message = "Hello world!";
    let signature = signing_key.sign(message.as_bytes()).to_bytes();
    let encoded_signature = STANDARD.encode(signature);
    
    // set up request body
    let request_body = json!({
        "payload": {
            "message": message,
            "nonce": nonce
        },
        "signature": encoded_signature
    });
    
    // get verification response
    let verify_res = client.post("http://localhost:3000/verify")
        .json(&request_body)
        .send()
        .await?
        .json::<HashMap<String, String>>()
        .await?;
    let verification = verify_res.get("message")
        .expect("Missing message in response.");

    Ok(verification.to_string())
}