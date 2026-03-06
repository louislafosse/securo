<div align="center">

</div>

<div align="center">
  <img src="https://raw.githubusercontent.com/louislafosse/securo/refs/heads/main/docs/logo_def.png" alt="Securo Logo" width="500"/>
  
  <p><strong>A hybrid post-quantum end-to-end encryption implementation using Securo:
  </br>HKDF-SHA256 hybrid key derivation from X25519 + Kyber-1024, SalsaBox (XSalsa20-Poly1305) bootstrap encryption, ChaCha20-Poly1305 session AEAD, Ed25519 signatures, Certificate (TLS 1.3) pinning (SPKI based), replay protection.
  </br></br>Server and Client included using Actix & Diesel Frameworks</strong></p>

  [![Crates.io](https://img.shields.io/crates/v/securo.svg)](https://crates.io/crates/securo)
  [![Documentation](https://docs.rs/securo/badge.svg)](https://docs.rs/securo)
</div>

## Quick start
Build the examples server and client locally (Certificate pinning enabled in client):

```bash
# Fedora
sudo dnf install -y sqlite-devel openssl

# Build server
cd securoserv
cargo build --release
bash ./scripts/gen-pinned-cert.sh
USE_TLS=true ./target/release/securoserv

# Build client
cd securoclient
cargo build --release
./target/release/securoclient
```

## [Crate Documentation](https://crates.io/crates/securo)

</br>

## [Security Architecture](./docs/SECURITY_ARCHITECTURE.md)

</br>

## [Authentication Architecture](./docs/AUTHENTICATION_ARCHITECTURE.md)
