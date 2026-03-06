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

## Prelude

**Read [Securoserv](https://github.com/louislafosse/securo/tree/main/securoserv) and [Securoclient](https://github.com/louislafosse/securo/tree/main/securoclient) for exact implementation of Securo.**

**Read this [Example of Implementation](https://github.com/louislafosse/securo/blob/main/securo/examples/authentication.rs) for a short and easy way to implement Securo.**

This crate provides the **cryptographic impl** for an authentication and communication system.
It implements a hybrid classical-post-quantum key exchange protocol (X25519 + Kyber-1024) with HKDF-SHA256 key derivation, SalsaBox bootstrap channel encryption, ChaCha20-Poly1305 session encryption, and certificate pinning to establish secure, authenticated connections between client and server.

## [Crate Documentation](https://crates.io/crates/securo)

</br>

## [Security Architecture](https://github.com/louislafosse/securo/blob/main/docs/SECURITY_ARCHITECTURE.md)

</br>

## [Authentication Architecture](https://github.com/louislafosse/securo/blob/main/docs/AUTHENTICATION_ARCHITECTURE.md)

</br>

## [Build instructions for Server & Client](https://github.com/louislafosse/securo/blob/main/README.md)
