use securo::server::crypto::SecuroServ;
use securo::client::crypto::SecuroClient;

fn main() {
    println!("\nSecuro Authentication Example\n");

    let server = SecuroServ::new();
    let mut client = SecuroClient::new();

    println!("Stage 1: Server generates ephemeral keys");
    let stage1_response = server.perform_exchange_stage1()
        .expect("Stage 1 failed");
    println!("Stage 1 response : {:?}", stage1_response);

    client.set_server_public_key(&stage1_response.server_x25519_public)
        .expect("Failed to set server public key");

    println!("Stage 2: Client sends encrypted keys");
    
    let server_ephemeral_pub = client.verify_server_signature_stage2(
        &stage1_response.server_verifying_key,
        &stage1_response.server_ephemeral_public,
        &stage1_response.server_signature,
    ).expect("Signature verification failed");

    let (nonce, ciphertext) = client.encrypt_client_keys_stage2(&server_ephemeral_pub)
        .expect("Failed to encrypt client keys");

    let stage2_request = securo::server::crypto::ExchangeStage2Request {
        stage_token: stage1_response.stage_token,
        client_public_key_b64: client.get_public_key_base64(),
        nonce,
        ciphertext,
    };

    println!("Stage 2 request : {:?}", stage2_request);
    let stage2_response = server.perform_exchange_stage2(stage2_request)
        .expect("Stage 2 failed");

    let response_json = client.decrypt_stage2_response(
        &stage2_response.nonce,
        &stage2_response.ciphertext,
        &server_ephemeral_pub,
    ).expect("Failed to decrypt stage 2 response");

    let temp_jwt = client.process_stage2_response(&response_json)
        .expect("Failed to process stage 2 response");

    println!("Session ID: {}", temp_jwt);
    println!("Two-stage exchange complete\n");

    println!("Extracting session UUID from exchange token");
    let session_uuid = server.validate_exchange_token(&temp_jwt)
        .expect("Failed to validate exchange token");

    println!("Generating access tokens");
    let token_pair = server.generate_token_pair(&session_uuid)
        .expect("Failed to generate tokens");

    println!("Access token generated\n");

    println!("Encrypting message from client");
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    let plaintext = serde_json::json!({
        "message": "Hello, Securo",
        "timestamp": timestamp
    });

    let encrypted_req = client.encrypt_request(&token_pair.access_token, plaintext.clone())
        .expect("Encryption failed");

    let server_encrypted_req = securo::server::crypto::EncryptedRequest {
        session_id: encrypted_req.session_id,
        nonce: encrypted_req.nonce,
        ciphertext: encrypted_req.ciphertext,
        timestamp: encrypted_req.timestamp,
    };
    println!("Server decrypting request : {:?}", server_encrypted_req);

    let (session_id, decrypted) = server.decrypt_request(&server_encrypted_req)
        .expect("Decryption failed");

    assert_eq!(decrypted, plaintext, "Decryption mismatch");
    println!("Decryption verified\n");

    println!("Server sending encrypted response");
    let response_data = serde_json::json!({
        "status": "success",
        "user_id": "user123",
        "role": "admin"
    });

    let encrypted_resp = server.encrypt_response(&session_id, response_data.clone())
        .expect("Server encryption failed");

    let client_encrypted_resp = securo::client::crypto::EncryptedResponse {
        nonce: encrypted_resp.nonce,
        ciphertext: encrypted_resp.ciphertext,
        signature: encrypted_resp.signature,
        timestamp: encrypted_resp.timestamp,
    };

    println!("Client decrypting response : {:?}", client_encrypted_resp);
    let decrypted_resp = client.decrypt_response(&client_encrypted_resp)
        .expect("Response decryption failed");

    assert_eq!(decrypted_resp, response_data, "Response mismatch");
    println!("Response verified\n");
}
