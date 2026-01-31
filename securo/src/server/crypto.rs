use crypto_box::{
    PublicKey, SalsaBox, SecretKey, aead::{Aead, AeadCore, OsRng}
};
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use pqc_kyber::{RngCore, encapsulate};
use hmac::Hmac;
use sha2::{
    Sha256,
    Digest,
};
use hmac::Mac;
use std::time::Instant;
use crate::logger::{
    linfo,
    ldebug
};

        

const KYBER_1024_CIPHERTEXT_SIZE: usize = 1568;  // Kyber-1024 encapsulation produces exactly 1568 bytes
const NONCE_MAX_AGE_SECS: u64 = 120; // 2 minutes
const NONCE_CACHE_MAX_SIZE: usize = 10000;

/// Time-windowed nonce cache with automatic cleanup
#[derive(Clone)]
pub struct NonceCache {
    nonces: std::collections::HashMap<String, Instant>,
}

impl NonceCache {
    fn new() -> Self {
        Self {
            nonces: std::collections::HashMap::new(),
        }
    }
    
    /// Check if nonce exists and is not expired, then add it
    /// Returns true if nonce is fresh (not replayed), false if replayed
    fn check_and_insert(&mut self, nonce: &str) -> bool {
        self.cleanup_expired();
        
        // Check if nonce already exists
        if self.nonces.contains_key(nonce) {
            return false; // REPLAY DETECTED
        }
        
        // Prevent unbounded growth
        if self.nonces.len() >= NONCE_CACHE_MAX_SIZE {
            tracing::warn!("Nonce cache size limit reached, forcing cleanup");
            self.cleanup_expired();
            
            // If still full after cleanup, remove oldest entries
            if self.nonces.len() >= NONCE_CACHE_MAX_SIZE {
                let to_remove: Vec<String> = self.nonces.iter()
                    .take(NONCE_CACHE_MAX_SIZE / 4)
                    .map(|(k, _)| k.clone())
                    .collect();
                for key in to_remove {
                    self.nonces.remove(&key);
                }
            }
        }
        
        self.nonces.insert(nonce.to_string(), Instant::now());
        true
    }
    
    /// Remove expired nonces
    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.nonces.retain(|_, timestamp| {
            now.duration_since(*timestamp).as_secs() < NONCE_MAX_AGE_SECS
        });
    }
}

/// JWT Claims for session authentication (OAuth2-style)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,        // Subject (user identifier / session UUID)
    pub exp: usize,         // Expiration time (Unix timestamp)
    pub iat: usize,         // Issued at (Unix timestamp)
    pub token_type: String, // "access" or "refresh"
}

/// Token pair response (OAuth2 pattern)
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,     // "Bearer"
    pub expires_in: u64,        // seconds until access_token expires
}

/// Message structure for encrypted communication
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub session_id: String,        // UUID - identifies the client session
    pub nonce: String,
    pub ciphertext: String,
    pub signature: String,          // Ed25519 signature over (session_id || nonce || ciphertext)
    pub timestamp: i64,
}

/// Used for all authenticated API calls after /api/auth
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedRequest {
    pub session_id: String,         // Client's session UUID - for O(1) lookup
    pub nonce: String,              // 24 random bytes
    pub ciphertext: String,         // contains encrypted JSON payload
    pub timestamp: i64,
}

/// Server responds with encrypted data that client must decrypt
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedResponse {
    pub nonce: String,              // 24 random bytes
    pub ciphertext: String,         // contains encrypted JSON response
    pub signature: String,          // Ed25519 signature over (nonce || ciphertext)
    pub timestamp: i64,
}

/// Exchange and authentication request (one-step)
/// Includes both classical (X25519) and post-quantum (Kyber) keys
#[derive(Debug, Serialize, Deserialize)]
pub struct ExchangeRequest {
    pub client_public_key: String,        // X25519 static (base64)
    pub client_ephemeral_public: String,  // X25519 ephemeral (base64)
    pub client_verifying_key: String,     // Ed25519 verifying key (base64)
    pub client_kyber_public: String,      // Kyber-1024 public key (base64) - POST-QUANTUM
}

/// Exchange and authentication response (includes tokens)
/// Provides both classical and post-quantum security
#[derive(Debug, Serialize, Deserialize)]
pub struct ExchangeResponse {
    pub server_public_key: String,        // X25519 static (base64)
    pub server_ephemeral_public: String,  // X25519 ephemeral (base64)
    pub server_signature: String,         // Ed25519 signature proving server identity (base64)
    pub encrypted_verifying_key: String,  // Encrypted Ed25519 verifying key (base64)
    pub verifying_key_hmac: String,       // HMAC-SHA256 of encrypted_verifying_key using Kyber shared secret (base64) - AUTHENTICATES SERVER KEY
    pub kyber_ciphertext: String,         // Kyber-1024 encapsulated shared secret (base64) - POST-QUANTUM
    pub temp_jwt: String,               // Temporary JWT (10 min) for auth phase
    pub token_type: String,
    pub expires_in: u64,                  // Seconds until temp_jwt expires
}

/// Auth Response - Permanent tokens after license validation
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// Stage 1 of two-stage key exchange - Server initiates with ephemeral key
/// This is sent in response to an empty request from the client
#[derive(Debug, Serialize, Deserialize)]
pub struct ExchangeStage1Response {
    pub server_x25519_public: String,      // X25519 static (base64) - for encryption after exchange
    pub server_verifying_key: String,      // Ed25519 verifying key (base64) - for signature verification
    pub server_ephemeral_public: String,   // X25519 ephemeral public (base64) - for this exchange
    pub server_signature: String,          // Ed25519 signature: sign(server_verifying_key || server_ephemeral_public)
    pub stage_token: String,               // HMAC token binding Stage 1 to Stage 2 - prevents MITM modifications
}

/// Stage 2 of two-stage key exchange - Client sends keys encrypted
/// All client keys sent encrypted under shared secret derived from ephemeral keys
#[derive(Debug, Serialize, Deserialize)]
pub struct ExchangeStage2Request {
    pub stage_token: String,              // HMAC token from Stage 1 response - binds stages together and provides ephemeral secret
    pub client_public_key_b64: String,    // base64 - client's static X25519 public key (plaintext for session)
    pub nonce: String,                    // base64 - 24 random bytes for SalsaBox
    pub ciphertext: String,               // base64 - encrypted client verifying/kyber keys
}

/// Stage 2 response - Server completes key agreement
#[derive(Debug, Serialize, Deserialize)]
pub struct ExchangeStage2Response {
    pub nonce: String,                    // 24 random bytes
    pub ciphertext: String,               // encrypted response
}

/// Pending exchange state - tracks Stage 1 data for validation in Stage 2
#[derive(Clone)]
pub struct PendingExchange {
    pub ephemeral_secret: Vec<u8>,       // Server's ephemeral private key (32 bytes) - for Stage 2 decryption
    pub ephemeral_public_b64: String,    // Server's ephemeral public key (binds Stage 1 to Stage 2)
    pub client_verifying_key: String,    // Client's Ed25519 key from Stage 1 (if provided)
    pub client_kyber_public: String,     // Client's Kyber public key from Stage 1 (if provided)
    pub created_at: u64,                 // Unix timestamp - for cleanup
}

/// Session data including public key and heartbeat tracking
#[derive(Clone)]
pub struct SessionData {
    pub public_key: PublicKey,
    pub last_heartbeat: u64,  // Unix timestamp in seconds
    pub used_nonces: NonceCache,  // Time-windowed nonce cache to prevent replay attacks
}


#[derive(Debug, Clone)]
pub enum ServerError {
    InvalidKey,
    InvalidNonce,
    InvalidCiphertext,
    EncryptionFailed,
    DecryptionFailed,
    InvalidSession,
    SessionNotFound,
    InvalidSignature,
    InvalidProof,
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::InvalidKey => write!(f, "Invalid key format"),
            ServerError::InvalidNonce => write!(f, "Invalid nonce format"),
            ServerError::InvalidCiphertext => write!(f, "Invalid ciphertext format"),
            ServerError::EncryptionFailed => write!(f, "Encryption operation failed"),
            ServerError::DecryptionFailed => write!(f, "Decryption operation failed"),
            ServerError::InvalidSession => write!(f, "Invalid session format"),
            ServerError::SessionNotFound => write!(f, "Session not found or expired"),
            ServerError::InvalidSignature => write!(f, "Invalid signature"),
            ServerError::InvalidProof => write!(f, "Invalid proof of possession"),
        }
    }
}

impl std::error::Error for ServerError {}

impl ServerError {
    pub fn status_code(&self) -> u16 {
        match self {
            ServerError::InvalidKey |
            ServerError::InvalidNonce |
            ServerError::InvalidCiphertext => 400, // Bad Request
            ServerError::EncryptionFailed |
            ServerError::DecryptionFailed => 500, // Internal Server Error
            ServerError::InvalidSession |
            ServerError::SessionNotFound => 401, // Unauthorized
            ServerError::InvalidSignature |
            ServerError::InvalidProof => 403, // Forbidden - authentication failed
        }
    }

    /// Log the error with appropriate security context
    pub fn log_security_event(&self) {
        match self {
            ServerError::DecryptionFailed => {
                tracing::warn!("Decryption failed - possible tampering attempt or wrong key pair");
            }
            ServerError::InvalidKey => {
                tracing::warn!("Invalid key format received");
            }
            ServerError::InvalidSession => {
                tracing::error!("Invalid session ID format");
            }
            ServerError::SessionNotFound => {
                tracing::error!("Session not found - unknown or expired UUID");
            }
            ServerError::InvalidSignature => {
                tracing::warn!("SECURITY: Invalid signature detected - possible MITM attack!");
            }
            ServerError::InvalidProof => {
                tracing::warn!("SECURITY: Invalid proof of possession - possible MITM attack!");
            }
            _ => {
                tracing::error!("Crypto error: {}", self);
            }
        }
    }
}

/// Server crypto state (session-based with JWT authentication + Ed25519 signing)
#[allow(unused)]
pub struct SecuroServ {
    // Server's long-term X25519 keypair for encryption
    secret_key: SecretKey,
    public_key: PublicKey,
    // Server's Ed25519 keypair for signing (proves server identity)
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    // Map of session ID (UUID) to session data
    sessions: RwLock<HashMap<Uuid, SessionData>>,
    // JWT secret for signing tokens
    jwt_secret: String,
    // Temporary storage for ephemeral secrets from stage 1 (used in stage 2)
    ephemeral_secrets: RwLock<HashMap<String, Vec<u8>>>,  // ephemeral_public_b64 -> ephemeral_secret_bytes
    // Pending exchanges - tracks Stage 1 data to validate in Stage 2 (prevents session fixation)
    pending_exchanges: RwLock<HashMap<String, PendingExchange>>,  // stage_token -> PendingExchange
    logger: crate::logger::LoggerHandle,
}

impl SecuroServ {
    /// Create a new SecuroServ with no logging
    pub fn new() -> Self {
        Self::new_with_logger(crate::logger::LoggerHandle::null())
    }

    /// Create a new SecuroServ with verbose logging
    pub fn new_with_verbose() -> Self {
        Self::new_with_logger(crate::logger::LoggerHandle::tracing())
    }

    /// Create a new SecuroServ with a custom logger
    pub fn new_with_logger(logger: crate::logger::LoggerHandle) -> Self {
        // Generate X25519 keypair for encryption
        let secret_key = SecretKey::generate(&mut OsRng);
        let public_key = secret_key.public_key();
        
        // Generate Ed25519 keypair for signing (authentication)
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        
        // let random_bytes: [u8; 16] = rand::random();
        let mut random_bytes: [u8; 16] = [0u8; 16];
        OsRng.fill_bytes(&mut random_bytes);

        let random_string = BASE64_URL_SAFE.encode(random_bytes);
        let jwt_secret = format!("{}{}", random_string, Uuid::new_v4().simple());

        linfo!(logger, "🔐 Server keypairs generated");
        linfo!(logger, "📦 X25519 Public Key (encryption): {}", BASE64_URL_SAFE.encode(public_key.as_bytes()));
        linfo!(logger, "✍️  Ed25519 Verifying Key (signing): {}", BASE64_URL_SAFE.encode(verifying_key.as_bytes()));

        Self {
            secret_key,
            public_key,
            signing_key,
            verifying_key,
            sessions: RwLock::new(HashMap::new()),
            jwt_secret,
            ephemeral_secrets: RwLock::new(HashMap::new()),
            pending_exchanges: RwLock::new(HashMap::new()),
            logger,
        }
    }

    /// Get the server's X25519 public key as base64 (for encryption)
    pub fn get_public_key_base64(&self) -> String {
        BASE64_URL_SAFE.encode(self.public_key.as_bytes())
    }

    /// Get the server's Ed25519 verifying key as base64 (for signature verification)
    pub fn get_verifying_key_base64(&self) -> String {
        BASE64_URL_SAFE.encode(self.verifying_key.as_bytes())
    }

    /// Sign data with server's Ed25519 private key
    fn sign_data(&self, data: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(data);
        signature.to_bytes().to_vec()
    }

    /// Stage 1 of secure exchange - Server sends ephemeral key first
    /// Client requests this first (no parameters), server returns public keys
    /// This allows client to establish a secure channel before sending its keys
    pub fn perform_exchange_stage1(&self) -> Result<ExchangeStage1Response, ServerError> {
        linfo!(self.logger, "Exchange Stage 1: Sending server ephemeral key");

        // Generate random 32 bytes for ephemeral secret (x25519 scalar)
        let mut ephemeral_secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut ephemeral_secret_bytes);

        // Convert to StaticSecret (ephemeral keys are just x25519 scalars)
        let server_ephemeral_secret = x25519_dalek::StaticSecret::from(ephemeral_secret_bytes);
        let server_ephemeral_public = X25519PublicKey::from(&server_ephemeral_secret);
        
        // Create signature proving server identity
        // Signature proves: sign(server_permanent_ed25519 || server_ephemeral_x25519) with server's Ed25519 key
        let mut sig_message = Vec::with_capacity(64);
        sig_message.extend_from_slice(self.verifying_key.as_bytes());  // Ed25519 verifying key (what client receives)
        sig_message.extend_from_slice(server_ephemeral_public.as_bytes()); // X25519 ephemeral public
        let server_signature = self.sign_data(&sig_message);
        
        let server_ephemeral_public_b64 = BASE64_URL_SAFE.encode(server_ephemeral_public.as_bytes());
        
        // Generate stage_token: HMAC(ephemeral_public || server_signature || timestamp)
        // This binds the Stage 1 response to a specific Stage 2 request
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut token_message = Vec::new();
        token_message.extend_from_slice(server_ephemeral_public_b64.as_bytes());
        token_message.extend_from_slice(b"||");
        token_message.extend_from_slice(&server_signature);
        token_message.extend_from_slice(b"||");
        token_message.extend_from_slice(now.to_le_bytes().as_ref());
        
        let mut hmac = Hmac::<Sha256>::new_from_slice(self.verifying_key.as_bytes())
            .map_err(|_| ServerError::EncryptionFailed)?;
        hmac.update(&token_message);
        let stage_token = BASE64_URL_SAFE.encode(hmac.finalize().into_bytes());
        
        // Store pending exchange with stage_token (for validation in Stage 2)
        let pending = PendingExchange {
            ephemeral_secret: ephemeral_secret_bytes.to_vec(),  // Stored securely - not sent to client!
            ephemeral_public_b64: server_ephemeral_public_b64.clone(),
            client_verifying_key: String::new(),  // Will be filled in Stage 2
            client_kyber_public: String::new(),   // Will be filled in Stage 2
            created_at: now,
        };
        
        self.pending_exchanges.write().unwrap().insert(stage_token.clone(), pending);
        
        ldebug!(self.logger, "Server ephemeral key generated and signed");
        ldebug!(self.logger, "Stage token generated for session fixation protection");
        
        Ok(ExchangeStage1Response {
            server_x25519_public: self.get_public_key_base64(),  // X25519 key for regular encryption
            server_verifying_key: self.get_verifying_key_base64(),  // Ed25519 key for signature verification
            server_ephemeral_public: server_ephemeral_public_b64,
            server_signature: BASE64_URL_SAFE.encode(&server_signature),
            stage_token,
        })
    }

    /// Stage 2 of secure exchange - Process client's encrypted keys and complete exchange
    pub fn perform_exchange_stage2(&self, req: ExchangeStage2Request) -> Result<ExchangeStage2Response, ServerError> {
        linfo!(self.logger, "Exchange Stage 2: Processing client's encrypted keys");
        
        // VALIDATION: Check that stage_token is valid (prevents session fixation)
        // This also retrieves the stored ephemeral secret from Stage 1
        let pending = {
            let mut exchanges = self.pending_exchanges.write().unwrap();
            exchanges.remove(&req.stage_token)
                .ok_or_else(|| {
                    tracing::warn!("SECURITY: Stage 2 request with invalid/missing stage_token - possible session fixation attack!");
                    ServerError::InvalidProof
                })?
        };

        ldebug!(self.logger, "Stage token validated - Stage 1 and Stage 2 are bound together");
        
        // Extract the ephemeral secret that was stored in Stage 1
        let ephemeral_secret_bytes = pending.ephemeral_secret;
        
        if ephemeral_secret_bytes.len() != 32 {
            return Err(ServerError::InvalidKey);
        }
        
        // Reconstruct ephemeral secret as crypto_box::SecretKey
        let mut ephemeral_array = [0u8; 32];
        ephemeral_array.copy_from_slice(&ephemeral_secret_bytes);
        let server_ephemeral_secret = SecretKey::from(ephemeral_array);
        
        // Decode client's static public key
        let client_public_bytes = BASE64_URL_SAFE.decode(&req.client_public_key_b64)
            .map_err(|_| ServerError::InvalidKey)?;
        
        if client_public_bytes.len() != 32 {
            return Err(ServerError::InvalidKey);
        }
        
        let mut client_key_array = [0u8; 32];
        client_key_array.copy_from_slice(&client_public_bytes);
        let client_public_key = PublicKey::from(client_key_array);
        
        // Decrypt client's encrypted keys using ephemeral shared secret
        let salsa_box = SalsaBox::new(&client_public_key, &server_ephemeral_secret);
        
        // Decode nonce and ciphertext
        let nonce_bytes = BASE64_URL_SAFE.decode(&req.nonce)
            .map_err(|_| ServerError::InvalidNonce)?;
        let ciphertext = BASE64_URL_SAFE.decode(&req.ciphertext)
            .map_err(|_| ServerError::InvalidCiphertext)?;
        
        if nonce_bytes.len() != 24 {
            return Err(ServerError::InvalidNonce);
        }
        
        let mut nonce_array = [0u8; 24];
        nonce_array.copy_from_slice(&nonce_bytes);
        let nonce = crypto_box::Nonce::from(nonce_array);
        
        // Decrypt the client keys
        let plaintext = salsa_box.decrypt(&nonce, ciphertext.as_ref())
            .map_err(|_| ServerError::DecryptionFailed)?;
        
        // Parse decrypted client keys
        let client_keys_json: serde_json::Value = serde_json::from_slice(&plaintext)
            .map_err(|_| ServerError::DecryptionFailed)?;
        
        let client_verifying_key = client_keys_json.get("client_verifying_key")
            .and_then(|v| v.as_str())
            .ok_or(ServerError::InvalidKey)?
            .to_string();
        
        let client_kyber_public = client_keys_json.get("client_kyber_public")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        
        ldebug!(self.logger, "Client keys decrypted successfully");
        
        // Now complete the exchange with the decrypted keys
        let exchange_req = ExchangeRequest {
            client_public_key: req.client_public_key_b64,
            client_ephemeral_public: String::new(),
            client_verifying_key,
            client_kyber_public,
        };
        
        let exchange_response = self.perform_exchange(exchange_req)?;
        
        // Encrypt the response using the same ephemeral shared secret
        let response_payload = serde_json::json!({
            "encrypted_verifying_key": exchange_response.encrypted_verifying_key,
            "kyber_ciphertext": exchange_response.kyber_ciphertext,
            "temp_jwt": exchange_response.temp_jwt,
            "expires_in": exchange_response.expires_in,
            "token_type": exchange_response.token_type,
        });
        
        // Create response nonce and encrypt
        let response_nonce = SalsaBox::generate_nonce(&mut OsRng);
        let response_plaintext = response_payload.to_string();
        let response_ciphertext = salsa_box.encrypt(&response_nonce, response_plaintext.as_bytes())
            .map_err(|_| ServerError::EncryptionFailed)?;

        ldebug!(self.logger, "Stage 2 response encrypted successfully");

        Ok(ExchangeStage2Response {
            nonce: BASE64_URL_SAFE.encode(&response_nonce[..]),
            ciphertext: BASE64_URL_SAFE.encode(&response_ciphertext),
        })
    }

    /// Complete exchange with authentication - returns tokens immediately
    pub fn perform_exchange(&self, req: ExchangeRequest) -> Result<ExchangeResponse, ServerError> {
        linfo!(self.logger, "Starting authenticated key exchange");

        // Parse and validate client keys
        let client_x25519_bytes = BASE64_URL_SAFE.decode(&req.client_public_key)
            .map_err(|_| ServerError::InvalidKey)?;
        let client_verifying_bytes = BASE64_URL_SAFE.decode(&req.client_verifying_key)
            .map_err(|_| ServerError::InvalidKey)?;
        
        if client_x25519_bytes.len() != 32 {
            return Err(ServerError::InvalidKey);
        }
        
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&client_x25519_bytes);
        let client_public_key = PublicKey::from(key_array);
        
        // Generate ephemeral keypair
        let rng = OsRng;
        let server_ephemeral_secret = EphemeralSecret::random_from_rng(rng);
        let server_ephemeral_public = X25519PublicKey::from(&server_ephemeral_secret);
        
        // Create signature proving server identity: sign(server_x25519 || server_ephemeral)
        let mut sig_message = Vec::with_capacity(64);
        sig_message.extend_from_slice(self.public_key.as_bytes());
        sig_message.extend_from_slice(server_ephemeral_public.as_bytes());
        let server_signature = self.sign_data(&sig_message);
        
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"securoserv-session");
        hasher.update(&client_x25519_bytes);
        hasher.update(&client_verifying_bytes);
        
        // Add random nonce for uniqueness
        let mut random_nonce = [0u8; 16];
        OsRng.fill_bytes(&mut random_nonce);
        hasher.update(random_nonce);
        
        // Add timestamp for additional entropy
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        hasher.update(now_nanos.to_le_bytes());
        
        let session_hash = hasher.finalize();
        let session_uuid = Uuid::from_slice(&session_hash[..16])
            .map_err(|_| ServerError::InvalidSession)?;
                
        // Store session
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let session_data = SessionData {
            public_key: client_public_key.clone(),
            last_heartbeat: now,
            used_nonces: NonceCache::new(),
        };
        
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(session_uuid, session_data);

        // Encrypt server's Ed25519 verifying key with client's public key
        // NOTE: Using X25519 directly here. Kyber provides additional authentication via HMAC.
        let salsa_box = self.create_box_with_client(&client_public_key);
        let nonce = SalsaBox::generate_nonce(&mut OsRng);
        let verifying_key_bytes = self.verifying_key.as_bytes();
        let encrypted_verifying_key = salsa_box
            .encrypt(&nonce, verifying_key_bytes.as_ref())
            .map_err(|_| ServerError::EncryptionFailed)?;
        
        // Combine nonce + ciphertext for transmission (client needs both to decrypt)
        let mut encrypted_with_nonce = Vec::with_capacity(24 + encrypted_verifying_key.len());
        encrypted_with_nonce.extend_from_slice(&nonce[..]);
        encrypted_with_nonce.extend_from_slice(&encrypted_verifying_key);
        
        // POST-QUANTUM KEY ENCAPSULATION: Kyber-1024
        // Parse client's Kyber public key if provided
        let (kyber_ciphertext, kyber_shared_secret) = if !req.client_kyber_public.is_empty() {
            let client_kyber_pub_bytes = BASE64_URL_SAFE.decode(&req.client_kyber_public)
                .map_err(|_| ServerError::InvalidKey)?;
            
            // Encapsulate with client's Kyber public key
            let mut rng = OsRng;
            let (ciphertext, shared_secret) = encapsulate(&client_kyber_pub_bytes, &mut rng)
                .map_err(|_| ServerError::EncryptionFailed)?;
            
            // Kyber-1024 encapsulation MUST produce exactly 1568 bytes
            // Any deviation indicates a bug in the library or potential tampering
            if ciphertext.len() != KYBER_1024_CIPHERTEXT_SIZE {
                tracing::error!(
                    "SECURITY: Kyber encapsulation produced invalid ciphertext length: {} (expected {})",
                    ciphertext.len(),
                    KYBER_1024_CIPHERTEXT_SIZE
                );
                return Err(ServerError::EncryptionFailed);
            }

            ldebug!(self.logger, "Kyber-1024 encapsulation produced valid {} byte ciphertext", KYBER_1024_CIPHERTEXT_SIZE);

            // Return the ciphertext for the client to decapsulate
            // shared_secret will be used for HMAC authentication of verifying_key
            (BASE64_URL_SAFE.encode(ciphertext), Some(shared_secret.to_vec()))
        } else {
            (String::new(), None)
        };
        
        // Compute HMAC of encrypted_verifying_key using Kyber shared secret (if available)
        let verifying_key_hmac = if let Some(ref kyber_ss) = kyber_shared_secret {
            let mut mac = Hmac::<Sha256>::new_from_slice(kyber_ss)
                .map_err(|_| ServerError::EncryptionFailed)?;
            mac.update(&encrypted_with_nonce);
            BASE64_URL_SAFE.encode(mac.finalize().into_bytes())
        } else {
            String::new()
        };
        
        // Generate temporary token for key exchange phase (10 min)
        let temp_jwt = self.generate_temp_jwt(&session_uuid)?;

        linfo!(self.logger, "Session created: {}", session_uuid);
        linfo!(self.logger, "Post-quantum Kyber-1024 KEM completed");
        linfo!(self.logger, "Ed25519 verifying key authenticated with HMAC-SHA256");

        Ok(ExchangeResponse {
            server_public_key: self.get_public_key_base64(),
            server_ephemeral_public: BASE64_URL_SAFE.encode(server_ephemeral_public.as_bytes()),
            server_signature: BASE64_URL_SAFE.encode(&server_signature),
            encrypted_verifying_key: BASE64_URL_SAFE.encode(&encrypted_with_nonce),
            verifying_key_hmac,
            kyber_ciphertext,
            temp_jwt,
            token_type: "Bearer".to_string(),
            expires_in: 600,  // 10 minutes
        })
    }

    /// Generate access token (short-lived, 15 minutes)
    fn generate_access_token(&self, session_id: &Uuid) -> Result<String, ServerError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        
        let claims = Claims {
            sub: session_id.to_string(),
            exp: now + 900, // 15 minutes
            iat: now,
            token_type: "access".to_string(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|_| ServerError::InvalidSession)
    }

    /// Generate refresh token (long-lived, 7 days)
    fn generate_refresh_token(&self, session_id: &Uuid) -> Result<String, ServerError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        
        let claims = Claims {
            sub: session_id.to_string(),
            exp: now + 604800, // 7 days
            iat: now,
            token_type: "refresh".to_string(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|_| ServerError::InvalidSession)
    }

    /// Generate token pair (OAuth2 pattern)
    pub fn generate_token_pair(&self, session_id: &Uuid) -> Result<TokenPair, ServerError> {
        let access_token = self.generate_access_token(session_id)?;
        let refresh_token = self.generate_refresh_token(session_id)?;
        linfo!(self.logger, "Generated token pair (access: {}, refresh: {})", access_token, refresh_token);

        Ok(TokenPair {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: 900, // 15 minutes
        })
    }

    /// Generate temporary token for key exchange phase (10 minutes)
    pub fn generate_temp_jwt(&self, session_id: &Uuid) -> Result<String, ServerError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let claims = Claims {
            sub: session_id.to_string(),
            exp: (now + 600) as usize,  // 10 minutes
            iat: now as usize,
            token_type: "exchange".to_string(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|_| ServerError::InvalidSession)
    }

    /// Generic token validator
    /// silent: if true, suppresses warnings (used when trying multiple token types)
    fn validate_token(&self, token: &str, expected_type: &str, silent: bool) -> Result<Uuid, ServerError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;  // Validate expiration time
        validation.leeway = 30;  // Allow 30 seconds leeway for clock skew
        
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|e| {
            if !silent {
                tracing::warn!("Token validation failed for type '{}': {:?}", expected_type, e);
            }
            ServerError::InvalidSession
        })?;

        // Verify token type matches expected
        if token_data.claims.token_type != expected_type {
            if !silent {
                tracing::warn!("Token type mismatch: expected '{}', got '{}'", expected_type, token_data.claims.token_type);
            }
            return Err(ServerError::InvalidSession);
        }

        Uuid::parse_str(&token_data.claims.sub)
            .map_err(|_| ServerError::InvalidSession)
    }

    /// Validate access token (15 min) and extract session ID
    pub fn validate_access_token(&self, token: &str) -> Result<Uuid, ServerError> {
        self.validate_token(token, "access", false)
    }

    /// Validate exchange token (10 min) and extract session ID
    pub fn validate_exchange_token(&self, token: &str) -> Result<Uuid, ServerError> {
        self.validate_token(token, "exchange", false)
    }

    /// Validate refresh token (7 days) and extract session ID
    pub fn validate_refresh_token(&self, token: &str) -> Result<Uuid, ServerError> {
        self.validate_token(token, "refresh", false)
    }

    /// Try multiple token types silently - only warn if all fail
    fn validate_any_token(&self, token: &str, types: &[&str]) -> Result<Uuid, ServerError> {
        for token_type in types {
            if let Ok(uuid) = self.validate_token(token, token_type, true) {
                return Ok(uuid);
            }
        }
        
        tracing::warn!("Token validation failed for all types {:?}", types);
        Err(ServerError::InvalidSession)
    }

    /// Get a client's public key by session ID
    fn get_client_key(&self, session_id: &str) -> Result<PublicKey, ServerError> {
        let uuid = Uuid::parse_str(session_id)
            .map_err(|_| ServerError::InvalidSession)?;
        
        let sessions = self.sessions.read().unwrap();
        sessions.get(&uuid)
            .map(|data| data.public_key.clone())
            .ok_or(ServerError::SessionNotFound)
    }

    /// Unauth a client session
    pub fn unauth(&self, session_id: &str) -> Result<(), ServerError> {
        let uuid = Uuid::parse_str(session_id)
            .map_err(|_| ServerError::InvalidSession)?;
        
        let mut sessions = self.sessions.write().unwrap();
        match sessions.remove(&uuid) {
            Some(_) => {
                linfo!(self.logger, "Client unauthenticated: {}", session_id);
                linfo!(self.logger, "Total active sessions: {}", sessions.len());
                Ok(())
            }
            None => Err(ServerError::SessionNotFound)
        }
    }

    /// Get total number of active sessions
    pub fn get_active_sessions_count(&self) -> usize {
        self.sessions.read().unwrap().len()
    }

    /// Create a shared secret box with a client
    fn create_box_with_client(&self, client_public_key: &PublicKey) -> SalsaBox {
        SalsaBox::new(client_public_key, &self.secret_key)
    }

    /// Decrypt an encrypted request
    /// Uses client-provided session_id (JWT token) for HashMap lookup
    pub fn decrypt_request(
        &self,
        req: &EncryptedRequest,
    ) -> Result<(String, serde_json::Value), ServerError> {
        // The session_id is a JWT token - ONLY accept access tokens for regular encrypted requests
        // This prevents bypass of license checks using exchange tokens
        let session_uuid = self.validate_access_token(&req.session_id)?;

        // Check timestamp freshness (TTL validation)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ttl_seconds: i64 = 60;  // 60 second TTL for requests
        
        if (now - req.timestamp).abs() > ttl_seconds {
            tracing::warn!("Request timestamp outside TTL window (timestamp: {}, now: {}, ttl: {})", 
                req.timestamp, now, ttl_seconds);
            return Err(ServerError::InvalidProof);
        }

        // Decode nonce and ciphertext
        let nonce_bytes = BASE64_URL_SAFE.decode(&req.nonce)
            .map_err(|_| ServerError::InvalidNonce)?;
        let ciphertext = BASE64_URL_SAFE.decode(&req.ciphertext)
            .map_err(|_| ServerError::InvalidCiphertext)?;

        if nonce_bytes.len() != 24 {
            return Err(ServerError::InvalidNonce);
        }

        let mut nonce_array = [0u8; 24];
        nonce_array.copy_from_slice(&nonce_bytes);
        let nonce = crypto_box::Nonce::from(nonce_array);

        let mut sessions = self.sessions.write()
            .map_err(|_| ServerError::InvalidSession)?;
        
        let session_data = sessions.get_mut(&session_uuid)
            .ok_or(ServerError::SessionNotFound)?;

        // Check for nonce reuse with time-windowed cache
        if !session_data.used_nonces.check_and_insert(&req.nonce) {
            tracing::warn!("SECURITY: Nonce reuse detected - possible replay attack!");
            return Err(ServerError::InvalidNonce);
        }
        
        // Decrypt with the session's client key
        let salsa_box = SalsaBox::new(&session_data.public_key, &self.secret_key);
        let plaintext = salsa_box.decrypt(&nonce, ciphertext.as_ref())
            .map_err(|_| ServerError::DecryptionFailed)?;

        let plaintext_str = String::from_utf8(plaintext)
            .map_err(|_| ServerError::DecryptionFailed)?;
        let payload: serde_json::Value = serde_json::from_str(&plaintext_str)
            .map_err(|_| ServerError::DecryptionFailed)?;

        // Extract the actual payload
        let inner_payload = payload.get("payload")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        Ok((req.session_id.clone(), inner_payload))
    }

    /// Decrypt a request for the AUTH endpoint ONLY
    /// This is the ONLY endpoint that should accept exchange tokens
    /// Regular endpoints must use access tokens (see decrypt_request)
    pub fn decrypt_auth_request(
        &self,
        req: &EncryptedRequest,
    ) -> Result<(String, serde_json::Value), ServerError> {
        // The session_id is a JWT token - accept BOTH exchange and access tokens for auth
        let session_uuid = self.validate_any_token(&req.session_id, &["access", "exchange"])?;

        // Check timestamp freshness (TTL validation)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ttl_seconds: i64 = 60;  // 60 second TTL for requests
        
        if (now - req.timestamp).abs() > ttl_seconds {
            tracing::warn!("Request timestamp outside TTL window (timestamp: {}, now: {}, ttl: {})", 
                req.timestamp, now, ttl_seconds);
            return Err(ServerError::InvalidProof);
        }

        // Decode nonce and ciphertext
        let nonce_bytes = BASE64_URL_SAFE.decode(&req.nonce)
            .map_err(|_| ServerError::InvalidNonce)?;
        let ciphertext = BASE64_URL_SAFE.decode(&req.ciphertext)
            .map_err(|_| ServerError::InvalidCiphertext)?;

        if nonce_bytes.len() != 24 {
            return Err(ServerError::InvalidNonce);
        }

        let mut nonce_array = [0u8; 24];
        nonce_array.copy_from_slice(&nonce_bytes);
        let nonce = crypto_box::Nonce::from(nonce_array);

        let mut sessions = self.sessions.write()
            .map_err(|_| ServerError::InvalidSession)?;
        
        let session_data = sessions.get_mut(&session_uuid)
            .ok_or(ServerError::SessionNotFound)?;

        // Check for nonce reuse with time-windowed cache
        if !session_data.used_nonces.check_and_insert(&req.nonce) {
            tracing::warn!("SECURITY: Nonce reuse detected - possible replay attack!");
            return Err(ServerError::InvalidNonce);
        }
        
        // Decrypt with the session's client key
        let salsa_box = SalsaBox::new(&session_data.public_key, &self.secret_key);
        let plaintext = salsa_box.decrypt(&nonce, ciphertext.as_ref())
            .map_err(|_| ServerError::DecryptionFailed)?;

        let plaintext_str = String::from_utf8(plaintext)
            .map_err(|_| ServerError::DecryptionFailed)?;
        let payload: serde_json::Value = serde_json::from_str(&plaintext_str)
            .map_err(|_| ServerError::DecryptionFailed)?;

        // Extract the actual payload
        let inner_payload = payload.get("payload")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        Ok((req.session_id.clone(), inner_payload))
    }

    /// Encrypt a response
    /// Takes a payload and encrypts it for the client
    pub fn encrypt_response(
        &self,
        session_id: &str,
        response_payload: serde_json::Value,
    ) -> Result<EncryptedResponse, ServerError> {
        let session_uuid = self.validate_any_token(session_id, &["access", "exchange"])?;
        let session_id_str = session_uuid.to_string();

        // Get client public key from session
        let client_public_key = self.get_client_key(&session_id_str)?;

        // Create box with client's public key
        let salsa_box = self.create_box_with_client(&client_public_key);

        // Generate a random nonce
        let nonce = SalsaBox::generate_nonce(&mut OsRng);

        // Encrypt response payload as JSON
        let plaintext = serde_json::to_vec(&response_payload)
            .map_err(|_| ServerError::EncryptionFailed)?;

        let ciphertext = salsa_box
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|_| ServerError::EncryptionFailed)?;

        // Sign the response: nonce || ciphertext (both base64)
        let nonce_b64 = BASE64_URL_SAFE.encode(&nonce[..]);
        let ciphertext_b64 = BASE64_URL_SAFE.encode(&ciphertext);
        let mut sig_message = Vec::new();
        sig_message.extend_from_slice(nonce_b64.as_bytes());
        sig_message.extend_from_slice(b"||");
        sig_message.extend_from_slice(ciphertext_b64.as_bytes());
        let sig_bytes = self.sign_data(&sig_message);
        let signature = BASE64_URL_SAFE.encode(&sig_bytes);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        ldebug!(self.logger, "Response encrypted and signed successfully with timestamp: {}", timestamp);

        Ok(EncryptedResponse {
            nonce: nonce_b64,
            ciphertext: ciphertext_b64,
            signature,
            timestamp,
        })
    }
    
    /// Clean up expired pending exchanges (older than 5 minutes)
    /// Should be called periodically by the server
    pub fn cleanup_expired_pending_exchanges(&self) {
        const PENDING_EXCHANGE_TTL_SECS: u64 = 300; // 5 minutes
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut exchanges = self.pending_exchanges.write().unwrap();
        let initial_count = exchanges.len();
        
        exchanges.retain(|_token, pending| {
            let age = now.saturating_sub(pending.created_at);
            age < PENDING_EXCHANGE_TTL_SECS
        });
        
        let removed = initial_count - exchanges.len();
        if removed > 0 {
            linfo!(self.logger, "Cleaned up {} expired pending exchanges", removed);
        }
    }
    
    /// Get count of pending exchanges (for monitoring)
    pub fn get_pending_exchanges_count(&self) -> usize {
        self.pending_exchanges.read().unwrap().len()
    }
    
    /// Clean up expired sessions (no heartbeat for > 1 hour)
    /// Should be called periodically by the server
    pub fn cleanup_expired_sessions(&self) {
        const SESSION_TIMEOUT_SECS: u64 = 3600; // 1 hour
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut sessions = self.sessions.write().unwrap();
        let initial_count = sessions.len();
        
        sessions.retain(|_uuid, session| {
            let age = now.saturating_sub(session.last_heartbeat);
            age < SESSION_TIMEOUT_SECS
        });
        
        let removed = initial_count - sessions.len();
        if removed > 0 {
            linfo!(self.logger, "Cleaned up {} expired sessions", removed);
        }
    }
}

impl Default for SecuroServ {
    fn default() -> Self {
        Self::new()
    }
}
