
# Security Architecture

## Encryption Algorithm Details

### XSalsa20-Poly1305 (Symmetric AEAD)

```
Encryption:
  ciphertext = XSalsa20Poly1305_encrypt(plaintext, key, nonce)
  - Key: 32 bytes (256-bit)
  - Nonce: 24 bytes (192-bit) - MUST be random and unique per message
  - Plaintext: arbitrary length
  - Ciphertext: Same length + 16-byte authentication tag

Decryption:
  plaintext = XSalsa20Poly1305_decrypt(ciphertext, key, nonce)
  - Automatically verifies authentication tag
  - Returns error if authentication fails (tampering detected)
```

### Ed25519 Signatures

```
Signing:
  signature = Ed25519_sign(message, signing_key)
  - Signing key: 32 bytes (256-bit)
  - Message: arbitrary length
  - Signature: 64 bytes

Verification:
  Ed25519_verify(message, signature, verifying_key)
  - Verifying key: 32 bytes (256-bit)
  - Returns true/false (no exceptions)
  - Secure against forgery (EUF-CMA)
```

### HMAC-SHA256

```
Generation:
  hmac = HMAC-SHA256(message, key)
  - Key: 32 bytes (256-bit)
  - Message: arbitrary length
  - HMAC: 32 bytes

Verification:
  constant_time_compare(computed_hmac, received_hmac)
  - Uses constant-time comparison to prevent timing attacks
  - Returns true only if values are identical
```

### Kyber-1024

```
Encapsulation (Server):
  (ciphertext, shared_secret) = encaps(public_key)
  - Public key: 1568 bytes
  - Ciphertext: 1568 bytes (deterministic for given input)
  - Shared secret: 32 bytes

Decapsulation (Client):
  shared_secret = decaps(ciphertext, secret_key)
  - Secret key: 3168 bytes
  - Ciphertext: 1568 bytes
  - Shared secret: 32 bytes (same as encapsulation)
```

### X25519 Diffie-Hellman

```
Key Generation:
  (secret_key, public_key) = X25519_keygen()
  - Secret key: 32 bytes (256-bit)
  - Public key: 32 bytes (256-bit)

Shared Secret:
  shared_secret = X25519(other_public_key, own_secret_key)
  - Produces 32 bytes of key material
  - Result independent of operation order: X25519(A_sk, B_pk) == X25519(B_sk, A_pk)
```

---

## Cryptographic Stack & Operations

| Operation | Algorithm | Keys/Parameters | Purpose |
|-----------|-----------|-----------------|---------|
| **Initial KEM** | Kyber-1024 | client_kyber_pk | Post-quantum key establishment |
| **Ephemeral DH** | X25519 | client_eph_sk, server_eph_pk | Session-specific ECDH |
| **Static DH** | X25519 | client_static_sk, server_static_pk | Prevents key substitution |
| **Key Derivation** | HKDF | DH1 \|\| DH2 \|\| kyber_ss | Hybrid secret (classical + PQ) |
| **Server Auth** | Ed25519 | server_signing_key | Signs ephemeral key & Kyber ciphertext |
| **Key Transport** | XSalsa20Poly1305 | kyber_shared_secret | Encrypts server's Ed25519 verifying key |
| **Key Auth** | HMAC-SHA256 | kyber_shared_secret | Authenticates encrypted key |
| **Token Sign** | HMAC-SHA256 | HYBRID_SECRET | Signs JWTs (access/refresh/stage) |
| **Request Encryption** | XSalsa20Poly1305 | HYBRID_SECRET | Encrypts request payload |
| **Response Encryption** | XSalsa20Poly1305 | HYBRID_SECRET | Encrypts response payload |
| **Response Auth** | Ed25519 | server_signing_key | Signs response (nonce \|\| ciphertext) |


### Why This Stack?

- **X25519**: Fast, secure, well-audited classical DH
- **Kyber-1024**: NIST-standardized post-quantum KEM (harvest-now-decrypt-later resistant)
- **Ed25519**: Deterministic signatures, no RNG failures
- **XSalsa20-Poly1305**: AEAD from NaCl, battle-tested
- **Certificate Pinning**: Prevents CA compromises

---

## Authentication & Key Exchange Flow

### Routes Details

#### `GET /api/exchange/stage1`
**Server initiates key exchange — returns ephemeral keys**

**Request:**
- Empty body (no authentication required)

**Response:**
| Field | Type | Purpose |
|-------|------|---------|
| `server_x25519_public` | string | Server's static X25519 public key for session identification |
| `server_verifying_key` | string | Server's Ed25519 key for verifying all future signatures |
| `server_ephemeral_public` | string | Ephemeral X25519 key for shared secret derivation |
| `server_signature` | string | Ed25519 signature proving server identity |
| `stage_token` | string | HMAC token binding Stage 2 to this Stage 1 — prevents MITM between stages |

---

#### `POST /api/exchange/stage2`
**Client sends encrypted keys — completes key agreement**

**Request:**
| Field | Type | Purpose |
|-------|------|---------|
| `stage_token` | string | From Stage 1 response — retrieves ephemeral secret securely server-side |
| `client_public_key_b64` | string | Client's static X25519 public key — plaintext for session UUID |
| `nonce` | string | Base64 24 random bytes for XSalsa20-Poly1305 encryption |
| `ciphertext` | string | Base64 encrypted credentials: `client_verifying_key` + `client_kyber_public` |

**Response:** *(encrypted with shared secret from ephemeral ECDH)*
| Field | Type | Purpose |
|-------|------|---------|
| `encrypted_verifying_key` | string | Server's Ed25519 key encrypted with shared secret |
| `verifying_key_hmac` | string | HMAC-SHA256 authentication — detects tampering |
| `kyber_ciphertext` | string | Kyber-1024 encapsulated secret for post-quantum security |
| `temp_jwt` | string | Temporary JWT valid 10 minutes — use only for `/api/auth` |
| `token_type` | string | `Bearer` |
| `expires_in` | number | `600` seconds |

---

#### `POST /api/auth`
**Authenticate client with license — returns permanent tokens**

**Request:** *(encrypted with shared secret from Stage 2)*
| Field | Type | Purpose |
|-------|------|---------|
| `session_id` | string | `temp_jwt` from Exchange Stage 2 — proves key exchange completion |
| `license_key` | string | UUID license from admin — client must have valid license |
| `nonce` | string | Base64 24 random bytes for encryption |
| `ciphertext` | string | Base64 encrypted `license_key` |

**Response:** *(encrypted with shared secret)*
| Field | Type | Purpose |
|-------|------|---------|
| `access_token` | string | JWT valid 15 minutes — use as `session_id` for `/api/encrypted` |
| `refresh_token` | string | JWT valid 7 days — use to refresh `access_token` |
| `token_type` | string | `Bearer` |
| `expires_in` | number | `900` seconds |

---

## HTTP Routes Configuration

### Protocol Flow by HTTP Method

| Endpoint | Method | Auth | Encryption | Purpose |
|----------|--------|------|-----------|---------|
| `/api/exchange/stage1` | GET | No | Plain JSON | Server initiates key exchange |
| `/api/exchange/stage2` | POST | No | Encrypted | Client responds to stage 1 |
| `/api/auth` | POST | stage_token | Encrypted | Client authenticates with license |
| `/api/unauth` | POST | access_token | Encrypted | Client logs out (session deleted) |
| `/api/refresh` | POST | refresh_token | Encrypted | Client refreshes access token |
| `/api/encrypted` | POST | access_token | Encrypted | Receive messages |
| `/api/encrypted/get` | POST | access_token | Encrypted | Get pending messages |
| `/api/encrypted/send` | POST | access_token | Encrypted | Send encrypted message |
| `/api/check` | POST | access_token | Encrypted | Verify license validity |
| `/api/report` | POST | access_token | Encrypted | Report user for abuse |
| `/api/admin/create_license` | POST | access_token (admin) | Encrypted/Plain | Create new license |
| `/api/admin/remove_license` | POST | access_token (admin)| Plain JSON | Revoke license |

---

## Security Features

### Cryptographic Protections
- **Ed25519 Authentication**: HMAC-SHA256 of encrypted verifying key prevents ciphertext modification
- **MITM Protection**: Ed25519 signatures verify server identity during key exchange
- **TLS Signature Verification**: Certificate signatures validated using webpki (defense-in-depth)
- **Forward Secrecy**: Ephemeral X25519 keys per session (stored securely server-side, never transmitted)
- **Post-Quantum KEM**: Kyber-1024 for harvest-now-decrypt-later resilience
- **End-to-End Encryption**: XSalsa20-Poly1305 (AEAD) with validated nonces
- **Cryptographic Session Binding**: Random UUIDs with cryptographic key derivation

### Session Security
- **Certificate Pinning**: Hardcoded certificate validation with full signature verification
- **License-Based Access**: UUID tokens with expiration
- **Dual-Ban System**: Ban by session_id OR machine_id
- **Session Fixation Protection**: stage_token cryptographically binds Stage 1 & Stage 2 of key exchange
- **Time-Windowed Nonce Cache**: 2-minute expiration window prevents replay attacks with automatic cleanup
- **Random Session IDs**: Cryptographically random UUIDs (Uuid::new_v4) prevent collision attacks
- **JWT Validation**: Claims verification (expiration with 30s leeway, token_type checking)
- **TTL Validation**: 60-second window on incoming requests

---

## References & Resources

### Cryptographic Algorithms & Security Standards

| Algorithm | Reference | Use Case |
|-----------|-----------|----------|
| **X25519** | [RFC 7748](https://tools.ietf.org/html/rfc7748) | Elliptic Curve Diffie-Hellman key agreement |
| **Ed25519** | [RFC 8032](https://tools.ietf.org/html/rfc8032) | Digital signatures, server identity verification |
| **Kyber-1024** | [NIST FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) | Post-quantum key encapsulation mechanism |
| **XSalsa20-Poly1305** | [NaCl Documentation](https://nacl.cr.yp.to/secretbox.html) | AEAD symmetric encryption |
| **SHA-256** | [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/FIPS180-4.pdf) | Cryptographic hashing |
| **HMAC-SHA256** | [RFC 2104](https://tools.ietf.org/html/rfc2104) | Message authentication codes |
| **Certificate Pinning Guide** | [Certificate and Public Key Pinning](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning) | Security Analysis |


### Libraries & Implementations

| Library | Language | Purpose | Link |
|---------|----------|---------|------|
| **Rustls** | Rust | TLS 1.3 implementation | [github.com/rustls/rustls](https://github.com/rustls/rustls) |
| **curve25519-dalek** | Rust | X25519 & Ed25519 cryptography | [github.com/dalek-cryptography/curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) |
| **CryptoBox** | Rust | Cryptographic library (XSalsa20-Poly1305) | [github.com/RustCrypto/nacl-compat/tree/master/crypto_box](https://github.com/RustCrypto/nacl-compat/tree/master/crypto_box) |
| **jsonwebtoken** | Rust | JWT creation & validation | [github.com/Keats/jsonwebtoken](https://github.com/Keats/jsonwebtoken) |
| **actix-web** | Rust | Web framework | [actix.rs](https://actix.rs/) |

### Related Resources

- **Perfect Forward Secrecy**: [Understanding PFS](https://en.wikipedia.org/wiki/Forward_secrecy)
- **AEAD Encryption**: [Authenticated Encryption](https://en.wikipedia.org/wiki/Authenticated_encryption)
- **TLS 1.3 Specification**: [RFC 8446](https://tools.ietf.org/html/rfc8446)

