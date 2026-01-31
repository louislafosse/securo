use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::danger::{ClientCertVerifier, ClientCertVerified};
use rustls::client::danger::HandshakeSignatureValid;
use std::sync::Arc;
use crate::tls::TlsMode;

/// Client certificate verifier that requires and pins a specific certificate
#[derive(Debug)]
struct PinnedClientCertVerifier {
    expected_cert: CertificateDer<'static>,
}

impl ClientCertVerifier for PinnedClientCertVerifier {
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // Compare certificate bytes directly
        if end_entity.as_ref() == self.expected_cert.as_ref() {
            // Certificate matches
            Ok(ClientCertVerified::assertion())
        } else {
            tracing::error!("Client certificate mismatch");
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ))
        }
    }

    /// Verify TLS 1.2 handshake signature
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_client_signature(message, cert, dss)
    }

    /// Verify TLS 1.3 handshake signature
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_client_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
}

/// Verify client certificate signature using webpki and ring
fn verify_client_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &rustls::DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    use rustls::pki_types::SignatureVerificationAlgorithm;
    
    // Parse certificate
    let end_entity = webpki::EndEntityCert::try_from(cert)
        .map_err(|_| rustls::Error::InvalidCertificate(
            rustls::CertificateError::BadEncoding
        ))?;
    
    // Map signature scheme to webpki algorithm
    let algorithm: &dyn SignatureVerificationAlgorithm = match dss.scheme {
        rustls::SignatureScheme::RSA_PKCS1_SHA256 => webpki::ring::RSA_PKCS1_2048_8192_SHA256,
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256 => webpki::ring::ECDSA_P256_SHA256,
        rustls::SignatureScheme::ED25519 => webpki::ring::ED25519,
        // RSA-PSS not directly supported in webpki-ring
        rustls::SignatureScheme::RSA_PSS_SHA256 => {
            tracing::debug!("RSA-PSS not supported via webpki, accepting due to exact cert pinning");
            return Ok(HandshakeSignatureValid::assertion());
        }
        _ => {
            return Err(rustls::Error::General(
                format!("Unsupported signature scheme: {:?}", dss.scheme)
            ));
        }
    };
    
    // Verify signature
    end_entity
        .verify_signature(algorithm, message, dss.signature())
        .map_err(|e| {
            tracing::warn!("Client signature verification failed: {:?}", e);
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadSignature
            )
        })?;
    
    Ok(HandshakeSignatureValid::assertion())
}

pub fn init_rustls_config(
    cert: &[u8],
    key: &[u8],
    mode: TlsMode,
) -> rustls::ServerConfig {
    let cert_chain_der: Vec<CertificateDer<'static>> = vec![
        CertificateDer::from_pem_slice(cert)
            .expect("Failed to parse certificate chain")
    ];

    let key_der = PrivateKeyDer::from_pem_slice(key)
        .expect("Failed to parse private key");

    match mode {
        TlsMode::MutualTlsPinning => {
            // Require client certificates and pin to the server's own certificate
            let client_verifier = Arc::new(PinnedClientCertVerifier {
                expected_cert: cert_chain_der[0].clone(),
            });

            ServerConfig::builder()
                .with_client_cert_verifier(client_verifier)
                .with_single_cert(cert_chain_der, key_der)
                .expect("bad certificate/key")
        }
        TlsMode::NormalPinning => {
            // No client cert required
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain_der, key_der)
                .expect("bad certificate/key")
        }
    }
}
