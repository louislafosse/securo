use securo::client::crypto::{EncryptedResponse, SecuroClient};

#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ExchangeRequest {
    pub client_public_key: String,
    pub client_ephemeral_public: String,
    pub client_verifying_key: String,
    pub client_kyber_public: String,      // POST-QUANTUM: Kyber-1024 public key
}

/// Stage 1 response from server
#[derive(serde::Deserialize, Debug)]
pub struct ExchangeStage1Response {
    pub server_x25519_public: String,
    pub server_verifying_key: String,
    pub server_ephemeral_public: String,
    pub server_signature: String,
    pub stage_token: String,            // HMAC token binding Stage 1 to Stage 2
}

/// Stage 2 request - Client sends encrypted keys
#[derive(serde::Serialize)]
pub struct ExchangeStage2Request {
    pub stage_token: String,            // HMAC token from Stage 1 response - prevents session fixation
    pub client_public_key_b64: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// Stage 2 response - Server completes exchange
#[derive(serde::Deserialize, Debug)]
pub struct ExchangeStage2Response {
    pub nonce: String,
    pub ciphertext: String,
}

#[allow(dead_code)]
#[derive(serde::Deserialize, Debug)]
pub struct ExchangeResponse {
    pub server_public_key: String,
    pub server_ephemeral_public: String,
    pub server_signature: String,
    pub encrypted_verifying_key: String,
    pub verifying_key_hmac: String,       // HMAC-SHA256 of encrypted_verifying_key using Kyber shared secret
    pub kyber_ciphertext: String,         // POST-QUANTUM: Kyber-1024 encapsulated secret
    pub temp_jwt: String,              // 10-minute temporary JWT for auth phase
    pub token_type: String,
    pub expires_in: u64,
}

#[allow(dead_code)]
#[derive(serde::Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// Client requests server's ephemeral key
#[allow(dead_code)]
pub async fn exchange_keys_stage1(
    client: &reqwest::Client,
) -> Result<ExchangeStage1Response, Box<dyn std::error::Error>> {
    tracing::info!("Exchange Stage 1: Requesting server ephemeral key...");
    
    let resp = client
        .get("https://127.0.0.1:8443/api/exchange/stage1")
        .send()
        .await?;
    
    if !resp.status().is_success() {
        let error_msg = format!("Exchange Stage 1 failed: Status {}", resp.status());
        tracing::error!("{}", error_msg);
        return Err(error_msg.into());
    }
    
    let stage1_resp: ExchangeStage1Response = resp.json().await?;
    
    Ok(stage1_resp)
}

/// Client sends encrypted keys and completes key agreement
pub async fn exchange_keys_stage2(
    client: &reqwest::Client,
    crypto: &mut SecuroClient,
    stage1_response: ExchangeStage1Response,
) -> Result<ExchangeResponse, Box<dyn std::error::Error>> {
    tracing::info!("Exchange Stage 2: Sending encrypted client keys...");
    
    // Set server's X25519 public key (for regular encryption after exchange)
    crypto.set_server_public_key(&stage1_response.server_x25519_public)?;
    
    // CRYPTO: Verify server signature and extract ephemeral public key
    let server_ephemeral_pub = crypto.verify_server_signature_stage2(
        &stage1_response.server_verifying_key,
        &stage1_response.server_ephemeral_public,
        &stage1_response.server_signature,
    )?;
    tracing::info!("Server signature verified");

    // CRYPTO: Encrypt client keys using server's ephemeral public key
    let (nonce_b64, ciphertext_b64) = crypto.encrypt_client_keys_stage2(&server_ephemeral_pub)?;
    
    // For Stage 2, send client keys back to server
    // The server will decrypt using its stored ephemeral secret from Stage 1
    let stage2_req = ExchangeStage2Request {
        stage_token: stage1_response.stage_token,  // Include stage_token to bind Stage 1 to Stage 2
        client_public_key_b64: crypto.get_public_key_base64(),
        nonce: nonce_b64,
        ciphertext: ciphertext_b64,
    };
    
    let resp = client
        .post("https://127.0.0.1:8443/api/exchange/stage2")
        .json(&stage2_req)
        .send()
        .await?;
    
    if !resp.status().is_success() {
        let error_msg = format!("Exchange Stage 2 failed: Status {}", resp.status());
        let body = resp.text().await.unwrap_or_default();
        tracing::error!("{} - {}", error_msg, body);
        return Err(error_msg.into());
    }
    
    let stage2_resp: ExchangeStage2Response = resp.json().await?;
    
    // CRYPTO: Decrypt stage 2 response using the ephemeral shared secret
    let response_json = crypto.decrypt_stage2_response(
        &stage2_resp.nonce,
        &stage2_resp.ciphertext,
        &server_ephemeral_pub,
    )?;

    // CRYPTO: Extract temp JWT and process response (including Kyber decapsulation)
    let temp_jwt = crypto.process_stage2_response(&response_json)?;

    let encrypted_verifying_key = response_json.get("encrypted_verifying_key")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let verifying_key_hmac = response_json.get("verifying_key_hmac")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    
    // Extract Kyber ciphertext for response display/logging
    let kyber_ciphertext = response_json.get("kyber_ciphertext")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let expires_in = response_json.get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(600);

    let token_type = response_json.get("token_type")
        .and_then(|v| v.as_str())
        .unwrap_or("Bearer")
        .to_string();
    
    Ok(ExchangeResponse {
        server_public_key: stage1_response.server_x25519_public,
        server_ephemeral_public: stage1_response.server_ephemeral_public,
        server_signature: stage1_response.server_signature,
        encrypted_verifying_key,
        verifying_key_hmac,
        kyber_ciphertext,
        temp_jwt,
        token_type,
        expires_in,
    })
}

/// Step 2: Send encrypted authentication with license key
/// Returns permanent access & refresh tokens
pub async fn auth(
    client: &reqwest::Client,
    crypto: &mut SecuroClient,
    license_key: &str,
) -> Result<AuthResponse, Box<dyn std::error::Error>> {
    tracing::info!("Sending encrypted authentication with license key");
    
    let session_id = crypto.get_session_id()
        .ok_or("Session ID not set")?;
    
    let auth_payload = serde_json::json!({
        "license_key": license_key,
    });

    let encrypted_req = crypto.encrypt_request(session_id, auth_payload)?;

    let resp = client
        .post("https://127.0.0.1:8443/api/auth")
        .json(&encrypted_req)
        .send()
        .await?;
    
    if !resp.status().is_success() {
        let error_msg = format!("Authentication failed: Status {}", resp.status());
        tracing::error!("{}", error_msg);
        return Err(error_msg.into());
    }
    
    let encrypted_resp: EncryptedResponse = resp.json().await?;
    let decrypted_value = crypto.decrypt_response(&encrypted_resp)?;
    let auth_resp: AuthResponse = serde_json::from_value(decrypted_value)?;
    
    tracing::info!("Authentication successful!");
    tracing::info!("Access Token: {}...", &auth_resp.access_token[..std::cmp::min(30, auth_resp.access_token.len())]);
    tracing::info!("Refresh Token: {}...", &auth_resp.refresh_token[..std::cmp::min(30, auth_resp.refresh_token.len())]);
    
    Ok(auth_resp)
}

/// Unauth session when done - plain JSON format
pub async fn unauth(
    client: &reqwest::Client,
    crypto: &SecuroClient,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("Unauthenticaticlientng session...");

    let session_id = crypto.get_session_id()
        .ok_or("Session ID not set")?;

    let unauth_payload = serde_json::json!({});
    
    let encrypted_req = crypto.encrypt_request(session_id, unauth_payload)?;
    
    let resp = client
        .post("https://127.0.0.1:8443/api/unauth")
        .json(&encrypted_req)
        .send()
        .await?;
    
    if !resp.status().is_success() {
        tracing::error!("Failed to unauthenticate: Status {}", resp.status());
        return Err(format!("Unauthentication failed: Status {}", resp.status()).into());
    }
    
    let encrypted_resp: EncryptedResponse = resp.json().await?;
    let decrypted_value = crypto.decrypt_response(&encrypted_resp)?;
    
    tracing::info!("✅ Session unauthenticated successfully!");
    tracing::info!("Server response: {}", decrypted_value);
    
    Ok(())
}
