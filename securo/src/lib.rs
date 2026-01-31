//! # Securo — Hybrid Post-Quantum Cryptographic Library
//!
//! Securo provides cryptographic primitives for secure authentication and communication
//! using hybrid classical + post-quantum cryptography.
//!
//! ## Implementation Examples
//!
//! **For complete usage examples, refer to:**
//! - [securoserv](https://github.com/louislafosse/securo/tree/main/securoserv) — Server implementation
//! - [securoclient](https://github.com/louislafosse/securo/tree/main/securoclient) — Client implementation  
//! - `examples/authentication.rs` — Standalone two-stage exchange example
//!
//! ## Core Features
//!
//! 1. **Hybrid Key Exchange** — X25519 + Kyber-1024 (post-quantum KEM)
//! 2. **AEAD Encryption** — XSalsa20-Poly1305 for message payloads
//! 3. **Signatures** — Ed25519 for authentication, HMAC-SHA256 for integrity
//! 4. **Certificate Pinning** — TLS with hardcoded certificate validation
//! 5. **Session Management** — JWT tokens with access/refresh pattern
//!
//! ## Architecture
//!
//! - [`server::crypto`] — Server key exchange, session encryption, token generation
//! - [`client::crypto`] — Client key exchange, request encryption, response verification
//! - [`server::pin`] / [`client::pin`] — TLS configuration with certificate pinning
//! - [`tls::TlsMode`] — Certificate pinning modes (normal vs mutual-TLS)
//!
//! ## Two-Stage Key Exchange
//!
//! **Stage 1**: Server sends ephemeral X25519 + Ed25519 keys with HMAC stage token  
//! **Stage 2**: Client sends encrypted keys (X25519 + Kyber), server responds with Kyber ciphertext + temp JWT
//!
//! Security properties:
//! - Post-quantum security via Kyber-1024
//! - Forward secrecy via ephemeral keys
//! - MITM protection via Ed25519 signatures
//! - Stage binding via HMAC tokens
//!
//! ## Key Data Structures
//!
//! ### Server Types ([`server::crypto`])
//!
//! - `SecuroServ` — Server crypto state
//! - `ExchangeStage1Response` — Stage 1 response (ephemeral keys + signature + stage_token)
//! - `ExchangeStage2Request` — Stage 2 request (encrypted client keys)
//! - `ExchangeStage2Response` — Stage 2 response (Kyber ciphertext + temp JWT)
//! - `TokenPair` — Access + refresh JWT tokens
//! - `EncryptedRequest` — Client-to-server encrypted message
//! - `EncryptedResponse` — Server-to-client encrypted message
//!
//! ### Client Types ([`client::crypto`])
//!
//! - `SecuroClient` — Client crypto state
//! - `EncryptedRequest` — Request structure with session_id + nonce + ciphertext
//! - `EncryptedResponse` — Response structure with signature verification
//!
//! ## Quick Example
//!
//! ```ignore
//! // Server
//! let server = SecuroServ::new();
//! let stage1 = server.perform_exchange_stage1()?;
//! let stage2 = server.perform_exchange_stage2(request)?;
//! let tokens = server.generate_token_pair(&session_uuid)?;
//!
//! // Client
//! let mut client = SecuroClient::new();
//! let (nonce, ciphertext) = client.encrypt_client_keys_stage2(&ephemeral_pub)?;
//! client.process_stage2_response(&response)?;
//! let encrypted = client.encrypt_request(&token, payload)?;
//! ```
//!
//! ## Documentation
//!
//! - `/docs/SECURITY_ARCHITECTURE.md` — Cryptographic specifications
//! - `/docs/AUTHENTICATION_ARCHITECTURE.md` — Protocol flow
//! - `examples/authentication.rs` — Working implementation

pub mod logger;
pub mod tls;

pub mod client {
    pub mod crypto;
    pub mod pin;
}

pub mod server {
    pub mod crypto;
    pub mod pin;
}