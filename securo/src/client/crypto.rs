use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    PublicKey, SalsaBox, SecretKey,
};
use chacha20poly1305::{
    ChaCha20Poly1305,
    Nonce as ChaNonce,
    aead::{KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Verifier};
use pqc_kyber::{RngCore, decapsulate, keypair};
use std::time::{SystemTime, UNIX_EPOCH};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use sha2::Sha256;
use crate::logger::linfo;

const KYBER_1024_CIPHERTEXT_SIZE: usize = 1568;  // Kyber-1024 encapsulation produces exactly 1568 bytes

/// Message structure for encrypted communication
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub session_id: String,        // UUID - identifies the client session
    pub nonce: String,              // 12 random bytes (ChaCha20Poly1305)
    pub ciphertext: String,         // contains encrypted JSON payload
    pub signature: String,          // Ed25519 signature over (session_id || nonce || ciphertext)
    pub timestamp: i64,
}

/// Encrypted request: client includes session_id for O(1) server-side lookup
/// Used for all authenticated API calls after /api/auth
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedRequest {
    pub session_id: String,         // Client's session UUID - enables O(1) server lookup
    pub nonce: String,
    pub ciphertext: String,
    pub timestamp: i64,             // Unix timestamp (seconds) - for TTL validation
}

/// Encrypted response: all content is encrypted
/// Server responds with encrypted data that client must decrypt
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedResponse {
    pub nonce: String,
    pub ciphertext: String,
    pub signature: String,          // Ed25519 signature over (nonce || ciphertext)
    pub timestamp: i64,
}

/// Client crypto state (session-based - generates ephemeral keys and stores session ID)
#[derive(Clone)]
#[allow(unused)]
pub struct SecuroClient {
    // Static X25519 keypair (persists across sessions)
    static_secret_key: SecretKey,
    static_public_key: PublicKey,
    
    // Ephemeral X25519 keypair (fresh for each exchange)
    ephemeral_secret_key: SecretKey,
    ephemeral_public_key: PublicKey,
    
    // Ed25519 keypair for signatures
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    
    // POST-QUANTUM: Kyber-1024 keypair
    kyber_secret_key: Vec<u8>,
    kyber_public_key: Vec<u8>,
    kyber_shared_secret: Option<Vec<u8>>,  // Decapsulated shared secret from server
    session_key: Option<[u8; 32]>,         // Hybrid session key derived from X25519 + Kyber
    
    server_public_key: Option<PublicKey>,
    server_verifying_key: Option<VerifyingKey>,  // Server's Ed25519 key for response verification
    stage1_server_ephemeral_b64: Option<String>,
    stage1_server_signature_b64: Option<String>,
    session_id: Option<String>,
    logger: crate::logger::LoggerHandle,
}

impl SecuroClient {

    /// Create a client crypto instance with no logging
    pub fn new() -> Self {
        Self::new_with_logger(crate::logger::LoggerHandle::null())
    }

    // Create a client crypto instance with verbose logging enabled
    pub fn new_with_verbose() -> Self {
        Self::new_with_logger(crate::logger::LoggerHandle::tracing())
    }

    /// Create a client crypto instance with fresh X25519 (static + ephemeral), Ed25519, and Kyber-1024 keypairs
    pub fn new_with_logger(logger: crate::logger::LoggerHandle) -> Self {
        let static_secret_key = SecretKey::generate(&mut OsRng);
        let static_public_key = static_secret_key.public_key();
        
        let ephemeral_secret_key = SecretKey::generate(&mut OsRng);
        let ephemeral_public_key = ephemeral_secret_key.public_key();
        
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let mut rng = OsRng;
        let kyber_kp = keypair(&mut rng).expect("Failed to generate Kyber keypair");
        
        linfo!(logger, "Client ephemeral keypair generated");
        linfo!(logger, "Kyber-1024 keypair generated (post-quantum)");

        Self {
            static_secret_key,
            static_public_key,
            ephemeral_secret_key,
            ephemeral_public_key,
            signing_key,
            verifying_key,
            kyber_secret_key: kyber_kp.secret.to_vec(),
            kyber_public_key: kyber_kp.public.to_vec(),
            kyber_shared_secret: None,
            session_key: None,
            server_public_key: None,
            server_verifying_key: None,
            stage1_server_ephemeral_b64: None,
            stage1_server_signature_b64: None,
            session_id: None,
            logger
        }
    }

    /// Get the client's Ed25519 verifying key (public) as base64
    pub fn get_verifying_key_base64(&self) -> String {
        BASE64_URL_SAFE.encode(self.verifying_key.as_bytes())
    }

    /// Get the client's ephemeral X25519 public key as base64
    pub fn get_ephemeral_public_base64(&self) -> String {
        BASE64_URL_SAFE.encode(self.ephemeral_public_key.as_bytes())
    }

    /// Get the client's Kyber-1024 public key as base64 (POST-QUANTUM)
    pub fn get_kyber_public_base64(&self) -> String {
        BASE64_URL_SAFE.encode(&self.kyber_public_key)
    }

    /// Set the session ID received from registration
    pub fn set_session_id(&mut self, session_id: String) {
        self.session_id = Some(session_id);
    }

    /// Get the session ID
    pub fn get_session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Get the client's static X25519 public key as base64
    pub fn get_public_key_base64(&self) -> String {
        BASE64_URL_SAFE.encode(self.static_public_key.as_bytes())
    }

    /// Set the server's public key
    pub fn set_server_public_key(&mut self, server_public_key_b64: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Decode the server's public key
        let server_public_key_bytes = BASE64_URL_SAFE.decode(server_public_key_b64)?;
        
        if server_public_key_bytes.len() != 32 {
            return Err("Invalid public key length".into());
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&server_public_key_bytes);
        self.server_public_key = Some(PublicKey::from(key_array));

        Ok(())
    }

    /// Set the server's Ed25519 verifying key for response signature verification
    pub fn set_server_verifying_key(&mut self, server_verifying_key_b64: &str) -> Result<(), Box<dyn std::error::Error>> {
        let server_verifying_key_bytes = BASE64_URL_SAFE.decode(server_verifying_key_b64)?;
        
        if server_verifying_key_bytes.len() != 32 {
            return Err("Invalid verifying key length".into());
        }

        let verifying_key = VerifyingKey::from_bytes(
            server_verifying_key_bytes[..32].as_ref().try_into()?
        )?;
        
        self.server_verifying_key = Some(verifying_key);
        Ok(())
    }

    /// Decapsulate Kyber ciphertext to derive post-quantum shared secret
    pub fn decapsulate_kyber(&mut self, kyber_ciphertext_b64: &str) -> Result<(), Box<dyn std::error::Error>> {
        if kyber_ciphertext_b64.is_empty() {
            return Err("Kyber ciphertext is required".into());
        }
        
        let ciphertext = BASE64_URL_SAFE.decode(kyber_ciphertext_b64)?;
        
        // SECURITY: Validate ciphertext length - Kyber-1024 produces exactly 1568 bytes
        // An attacker modifying the ciphertext length could cause decapsulation to fail
        // in unexpected ways, or could exploit edge cases in the decapsulation algorithm.
        // By validating length upfront, we ensure the ciphertext hasn't been tampered with.
        if ciphertext.len() != KYBER_1024_CIPHERTEXT_SIZE {
            tracing::warn!(
                "SECURITY: Invalid Kyber ciphertext length: got {} bytes, expected {} bytes. Possible MITM!",
                ciphertext.len(),
                KYBER_1024_CIPHERTEXT_SIZE
            );
            return Err(format!(
                "Invalid Kyber ciphertext length: got {}, expected {}",
                ciphertext.len(),
                KYBER_1024_CIPHERTEXT_SIZE
            ).into());
        }
        
        let shared_secret = decapsulate(&ciphertext, &self.kyber_secret_key)
            .map_err(|_| "Failed to decapsulate Kyber ciphertext")?;
        
        self.kyber_shared_secret = Some(shared_secret.to_vec());

        self.derive_session_key()?;
        Ok(())
    }

    /// Verify the HMAC of the encrypted verifying key using the Kyber shared secret
    pub fn verify_verifying_key_hmac(
        &self,
        encrypted_verifying_key_b64: &str,
        expected_hmac_b64: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(kyber_ss) = &self.kyber_shared_secret {
            let encrypted_bytes = BASE64_URL_SAFE.decode(encrypted_verifying_key_b64)?;

            // Compute HMAC of encrypted verifying key using Kyber shared secret
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(kyber_ss)
                .map_err(|_| "Failed to create HMAC")?;
            mac.update(&encrypted_bytes);
            
            // Decode and verify expected HMAC against computed HMAC
            let expected_hmac_bytes = BASE64_URL_SAFE.decode(expected_hmac_b64)?;
            mac.verify_slice(&expected_hmac_bytes)
                .map_err(|_| "Verifying key HMAC verification failed")?;
            
            Ok(())
        } else {
            Err("Kyber shared secret not available for HMAC verification".into())
        }
    }

    /// Create a shared secret box with the server
    /// Uses X25519 static key for crypto_box (asymmetric encryption)
    /// NOTE: Kyber provides post-quantum security via HMAC authentication.
    fn create_box(&self) -> Result<SalsaBox, Box<dyn std::error::Error>> {
        let server_public_key = self.server_public_key.as_ref()
            .ok_or("Server public key not set")?;
        
        Ok(SalsaBox::new(server_public_key, &self.static_secret_key))
    }

    /// Derive hybrid session key from X25519 + Kyber shared secrets using HKDF-SHA256.
    fn derive_session_key(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let server_public = self.server_public_key.as_ref()
            .ok_or("Server public key not set")?;
        let stage1_ephemeral_b64 = self.stage1_server_ephemeral_b64.as_ref()
            .ok_or("Missing Stage 1 server ephemeral for hybrid derivation")?;
        let kyber_ss = self.kyber_shared_secret.as_ref()
            .ok_or("Kyber shared secret not available")?;

        let static_secret = x25519_dalek::StaticSecret::from(self.static_secret_key.to_bytes());
        let server_x25519_pub = x25519_dalek::PublicKey::from(*server_public.as_bytes());
        let static_shared = static_secret.diffie_hellman(&server_x25519_pub);

        let stage1_ephemeral_bytes = BASE64_URL_SAFE.decode(stage1_ephemeral_b64)?;
        if stage1_ephemeral_bytes.len() != 32 {
            return Err("Stage 1 server ephemeral invalid length".into());
        }
        let mut stage1_ephemeral_array = [0u8; 32];
        stage1_ephemeral_array.copy_from_slice(&stage1_ephemeral_bytes);
        let stage1_ephemeral_pub = x25519_dalek::PublicKey::from(stage1_ephemeral_array);
        let ephemeral_shared = static_secret.diffie_hellman(&stage1_ephemeral_pub);

        let mut combined_secret = Vec::with_capacity(
            static_shared.as_bytes().len() + ephemeral_shared.as_bytes().len() + kyber_ss.len()
        );
        combined_secret.extend_from_slice(static_shared.as_bytes());
        combined_secret.extend_from_slice(ephemeral_shared.as_bytes());
        combined_secret.extend_from_slice(kyber_ss);

        let hkdf = Hkdf::<Sha256>::new(Some(b"securo-v2-session"), &combined_secret);
        let mut session_key = [0u8; 32];
        hkdf.expand(b"chacha20-encryption", &mut session_key)
            .map_err(|_| "HKDF expand failed")?;

        self.session_key = Some(session_key);
        Ok(())
    }

    /// Get the client's static X25519 secret key
    pub fn get_static_secret_key(&self) -> &SecretKey {
        &self.static_secret_key
    }

    /// Decrypt the server's verifying key (encrypted with client's static public key)
    pub fn decrypt_verifying_key(&self, encrypted_vk_b64: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let salsa_box = self.create_box()?;

        let encrypted_bytes = BASE64_URL_SAFE.decode(encrypted_vk_b64)?;
        
        // The server sends: nonce (24 bytes) + ciphertext
        if encrypted_bytes.len() < 24 {
            return Err("Invalid encrypted verifying key length".into());
        }

        let nonce_bytes = &encrypted_bytes[..24];
        let ciphertext = &encrypted_bytes[24..];

        let mut nonce_array = [0u8; 24];
        nonce_array.copy_from_slice(nonce_bytes);
        let nonce = crypto_box::Nonce::from(nonce_array);

        // Decrypt
        let plaintext = salsa_box
            .decrypt(&nonce, ciphertext)
            .map_err(|e| format!("Failed to decrypt verifying key: {:?}", e))?;

        Ok(plaintext)
    }

    /// Encrypt a request with session_id sent in plaintext
    /// The session_id is not encrypted, allowing the server to route to correct session immediately
    /// The payload (including sensitive data) is encrypted
    pub fn encrypt_request(
        &self,
        session_id: &str,
        payload: serde_json::Value,
    ) -> Result<EncryptedRequest, Box<dyn std::error::Error>> {
        let session_key = self.session_key.as_ref()
            .ok_or("Session key not derived - call decapsulate_kyber first")?;
        let cipher = ChaCha20Poly1305::new_from_slice(session_key)
            .map_err(|_| "Invalid session key length")?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
            
        let inner_payload = serde_json::json!({
            "payload": payload
        });

        let plaintext = serde_json::to_vec(&inner_payload)?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = ChaNonce::from(nonce_bytes);

        let ts_aad = now.to_le_bytes();
        let ciphertext = cipher.encrypt(&nonce, Payload {
            msg: plaintext.as_ref(),
            aad: &ts_aad,
        })
            .map_err(|_| "Encryption failed")?;

        Ok(EncryptedRequest {
            session_id: session_id.to_string(),
            nonce: BASE64_URL_SAFE.encode(nonce_bytes),
            ciphertext: BASE64_URL_SAFE.encode(&ciphertext),
            timestamp: now,
        })
    }

    /// Stage 2 - Verify server signature and prepare client keys for encryption
    /// Verifies: sign(server_verifying_key || server_ephemeral)
    /// Returns the ephemeral public key for use in creating the shared secret
    pub fn verify_server_signature_stage2(
        &mut self,
        server_verifying_key_b64: &str,
        server_ephemeral_b64: &str,
        server_signature_b64: &str,
    ) -> Result<PublicKey, Box<dyn std::error::Error>> {
        // Decode server verifying key
        let server_verifying_bytes = BASE64_URL_SAFE.decode(server_verifying_key_b64)?;
        if server_verifying_bytes.len() != 32 {
            return Err("Server verifying key invalid length".into());
        }
        
        // Decode server ephemeral public key
        let server_ephemeral_bytes = BASE64_URL_SAFE.decode(server_ephemeral_b64)?;
        if server_ephemeral_bytes.len() != 32 {
            return Err("Server ephemeral key invalid length".into());
        }
        
        // Decode signature
        let signature_bytes = BASE64_URL_SAFE.decode(server_signature_b64)?;
        if signature_bytes.len() != 64 {
            return Err("Signature invalid length".into());
        }
        
        // Construct verifying key
        let verifying_key = VerifyingKey::from_bytes(
            (&server_verifying_bytes[..32]).try_into()?
        )?;
        
        // Construct signature
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&signature_bytes);
        let signature = Signature::from_bytes(&sig_array);
        
        // Verify: sign(server_verifying_key || server_ephemeral)
        let mut sig_message = Vec::new();
        sig_message.extend_from_slice(&server_verifying_bytes);
        sig_message.extend_from_slice(&server_ephemeral_bytes);
        
        verifying_key.verify(&sig_message, &signature)
            .map_err(|e| format!("Server signature verification failed: {:?}", e))?;
        
        // Store server verifying key for later response verification
        self.server_verifying_key = Some(verifying_key);
        // Keep Stage 1 values so process_stage2_response can re-verify with authenticated key.
        self.stage1_server_ephemeral_b64 = Some(server_ephemeral_b64.to_string());
        self.stage1_server_signature_b64 = Some(server_signature_b64.to_string());
        
        // Construct and return ephemeral public key
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&server_ephemeral_bytes);
        Ok(PublicKey::from(key_array))
    }

    /// Stage 2 - finalize server verifying key using Kyber-authenticated payload.
    /// Verifies HMAC, decrypts the verifying key, and stores it for all future response checks.
    pub fn finalize_server_verifying_key_stage2(
        &mut self,
        encrypted_verifying_key_b64: &str,
        verifying_key_hmac_b64: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if encrypted_verifying_key_b64.is_empty() {
            return Err("Missing encrypted_verifying_key in stage 2 response".into());
        }
        if verifying_key_hmac_b64.is_empty() {
            return Err("Missing verifying_key_hmac in stage 2 response".into());
        }

        self.verify_verifying_key_hmac(encrypted_verifying_key_b64, verifying_key_hmac_b64)?;
        let decrypted_vk = self.decrypt_verifying_key(encrypted_verifying_key_b64)?;
        if decrypted_vk.len() != 32 {
            return Err("Decrypted verifying key invalid length".into());
        }

        let verifying_key = VerifyingKey::from_bytes((&decrypted_vk[..32]).try_into()?)?;
        self.server_verifying_key = Some(verifying_key);
        Ok(())
    }

    /// Re-verify Stage 1 signature using the authenticated server verifying key.
    pub fn verify_stage1_signature_with_authenticated_key(
        &self,
        server_ephemeral_b64: &str,
        server_signature_b64: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let verifying_key = self.server_verifying_key.as_ref()
            .ok_or("Authenticated server verifying key not set")?;

        let server_ephemeral_bytes = BASE64_URL_SAFE.decode(server_ephemeral_b64)?;
        if server_ephemeral_bytes.len() != 32 {
            return Err("Server ephemeral key invalid length".into());
        }

        let signature_bytes = BASE64_URL_SAFE.decode(server_signature_b64)?;
        if signature_bytes.len() != 64 {
            return Err("Signature invalid length".into());
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&signature_bytes);
        let signature = Signature::from_bytes(&sig_array);

        let mut sig_message = Vec::with_capacity(64);
        sig_message.extend_from_slice(verifying_key.as_bytes());
        sig_message.extend_from_slice(&server_ephemeral_bytes);
        verifying_key.verify(&sig_message, &signature)?;

        Ok(())
    }

    /// Stage 2 - Create encrypted payload with client keys
    /// Encrypts client's verifying key and Kyber public key using server's ephemeral public key
    /// Returns (nonce_b64, ciphertext_b64) for transmission
    pub fn encrypt_client_keys_stage2(
        &self,
        server_ephemeral_pub: &PublicKey,
    ) -> Result<(String, String), Box<dyn std::error::Error>> {
        // Create payload with client keys
        let client_keys_payload = serde_json::json!({
            "client_verifying_key": self.get_verifying_key_base64(),
            "client_kyber_public": self.get_kyber_public_base64(),
        });
        
        // Create box using client's static secret + server's ephemeral public
        let salsa_box = SalsaBox::new(server_ephemeral_pub, &self.static_secret_key);
        
        // Generate nonce and encrypt
        let nonce = SalsaBox::generate_nonce(&mut OsRng);
        let plaintext = client_keys_payload.to_string();
        let ciphertext = salsa_box.encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| "Client keys encryption failed")?;
        
        Ok((
            BASE64_URL_SAFE.encode(&nonce[..]),
            BASE64_URL_SAFE.encode(&ciphertext),
        ))
    }

    /// Stage 2 - Decrypt server's stage 2 response
    /// Decrypts response using the ephemeral shared secret
    /// Returns the parsed response JSON
    pub fn decrypt_stage2_response(
        &self,
        stage2_resp_nonce_b64: &str,
        stage2_resp_ciphertext_b64: &str,
        server_ephemeral_pub: &PublicKey,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        // Decode nonce and ciphertext
        let nonce_bytes = BASE64_URL_SAFE.decode(stage2_resp_nonce_b64)?;
        let ciphertext_bytes = BASE64_URL_SAFE.decode(stage2_resp_ciphertext_b64)?;
        
        if nonce_bytes.len() != 24 {
            return Err("Invalid stage 2 response nonce length".into());
        }
        
        let mut nonce_array = [0u8; 24];
        nonce_array.copy_from_slice(&nonce_bytes);
        let response_nonce = crypto_box::Nonce::from(nonce_array);
        
        // Create the same ephemeral box used to decrypt
        let salsa_box = SalsaBox::new(server_ephemeral_pub, &self.static_secret_key);
        
        // Decrypt response
        let plaintext_response = salsa_box.decrypt(&response_nonce, ciphertext_bytes.as_ref())
            .map_err(|_| "Stage 2 response decryption failed")?;
        
        // Parse response JSON
        let response_json: serde_json::Value = serde_json::from_slice(&plaintext_response)?;
        
        Ok(response_json)
    }

    /// Stage 2 - Extract and process temp JWT from stage 2 response.
    /// Also decapsulates required Kyber ciphertext.
    pub fn process_stage2_response(
        &mut self,
        response_json: &serde_json::Value,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Extract temp JWT
        let temp_jwt = response_json.get("temp_jwt")
            .and_then(|v| v.as_str())
            .ok_or("Missing temp_jwt in stage 2 response")?
            .to_string();
        
        // Set as session ID
        self.set_session_id(temp_jwt.clone());
        
        let encrypted_verifying_key = response_json.get("encrypted_verifying_key")
            .and_then(|v| v.as_str())
            .ok_or("Missing encrypted_verifying_key in stage 2 response")?;
        let verifying_key_hmac = response_json.get("verifying_key_hmac")
            .and_then(|v| v.as_str())
            .ok_or("Missing verifying_key_hmac in stage 2 response")?;

        let kyber_ct = response_json.get("kyber_ciphertext")
            .and_then(|v| v.as_str())
            .ok_or("Missing kyber_ciphertext in stage 2 response")?;
        self.decapsulate_kyber(kyber_ct)?;

        self.finalize_server_verifying_key_stage2(encrypted_verifying_key, verifying_key_hmac)?;
        let stage1_ephemeral = self.stage1_server_ephemeral_b64.as_deref()
            .ok_or("Missing Stage 1 server ephemeral context")?;
        let stage1_signature = self.stage1_server_signature_b64.as_deref()
            .ok_or("Missing Stage 1 server signature context")?;
        self.verify_stage1_signature_with_authenticated_key(stage1_ephemeral, stage1_signature)?;
        
        Ok(temp_jwt)
    }

    /// Decrypt an encrypted response from the server
    pub fn decrypt_response(
        &self,
        response: &EncryptedResponse,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {        
        // Verify signature first if server key is set
        if let Some(verifying_key) = &self.server_verifying_key {
            // Reconstruct the message that was signed: nonce || timestamp || ciphertext
            let mut sig_message = Vec::new();
            sig_message.extend_from_slice(response.nonce.as_bytes());
            sig_message.extend_from_slice(b"||");
            sig_message.extend_from_slice(response.timestamp.to_string().as_bytes());
            sig_message.extend_from_slice(b"||");
            sig_message.extend_from_slice(response.ciphertext.as_bytes());
            
            // Decode and verify signature
            let signature_bytes = BASE64_URL_SAFE.decode(&response.signature)?;
            if signature_bytes.len() != 64 {
                return Err("Invalid signature length".into());
            }
            
            let mut sig_array = [0u8; 64];
            sig_array.copy_from_slice(&signature_bytes);
            let signature = Signature::from_bytes(&sig_array);
            
            verifying_key.verify(&sig_message, &signature)?;
        }
        
        // Validate response timestamp freshness (TTL validation)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        let time_diff = (now - response.timestamp).abs();
        const TTL_WINDOW: i64 = 60;  // 60 second window for response freshness
        if time_diff > TTL_WINDOW {
            return Err(format!(
                "Response timestamp validation failed: time difference {} seconds exceeds TTL window of {} seconds",
                time_diff, TTL_WINDOW
            ).into());
        }

        let session_key = self.session_key.as_ref()
            .ok_or("Session key not derived")?;
        let cipher = ChaCha20Poly1305::new_from_slice(session_key)
            .map_err(|_| "Invalid session key length")?;

        let nonce_bytes = BASE64_URL_SAFE.decode(&response.nonce)?;
        let ciphertext = BASE64_URL_SAFE.decode(&response.ciphertext)?;

        if nonce_bytes.len() != 12 {
            return Err("Invalid nonce length for ChaCha20Poly1305".into());
        }

        let mut nonce_array = [0u8; 12];
        nonce_array.copy_from_slice(&nonce_bytes);
        let nonce = ChaNonce::from(nonce_array);
        let ts_aad = response.timestamp.to_le_bytes();
        let plaintext = cipher.decrypt(&nonce, Payload {
            msg: ciphertext.as_ref(),
            aad: &ts_aad,
        })
            .map_err(|_| "Decryption failed")?;

        let plaintext_str = String::from_utf8(plaintext)?;
        let response_payload: serde_json::Value = serde_json::from_str(&plaintext_str)?;

        Ok(response_payload)
    }
}

impl Default for SecuroClient {
    fn default() -> Self {
        Self::new()
    }
}
