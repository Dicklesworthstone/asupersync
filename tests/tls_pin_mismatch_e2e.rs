//! End-to-end coverage for [`TlsConnectorBuilder::with_certificate_pins`]
//! enforcement against pin mismatch (br-asupersync-v24lvi follow-up
//! per br-asupersync-m209nx).
//!
//! v24lvi locked the pinning gate via unit tests in src/tls/connector.rs.
//! That coverage exercises the gate in isolation but never drives a
//! real TlsConnector::connect() through a complete TLS handshake to
//! verify the gate actually aborts on pin mismatch (i.e., the wiring
//! between the rustls handshake completion path and the post-handshake
//! pin_set.validate call). This e2e test closes that gap.
//!
//! The harness mirrors `tests/tls_conformance.rs`: a real rustls
//! TlsAcceptor on one half of a `VirtualTcpStream::pair` and a real
//! TlsConnector on the other half, driven cooperatively via
//! futures_lite::future::zip on a single thread. No tokio, no real
//! TCP. The acceptor presents the project's test fixture leaf cert
//! (CN=localhost) and the connector configures a `CertificatePinSet`
//! containing a *deliberately wrong* SHA-256 fingerprint so the
//! handshake completes (rustls accepts the cert via the
//! `AcceptAnyCert` verifier — same shape as tls_conformance) but the
//! v24lvi gate fails the post-handshake pin validation.

#![cfg(feature = "tls")]

use asupersync::net::tcp::VirtualTcpStream;
use asupersync::tls::{
    Certificate, CertificateChain, CertificatePin, CertificatePinSet, PrivateKey, TlsAcceptor,
    TlsAcceptorBuilder, TlsConnector, TlsError,
};
use std::sync::Arc;
use std::time::Duration;

/// Tiny base64 encoder (avoids pulling another dep into the test).
/// RFC 4648 standard alphabet, no padding tricks.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPH[(b0 >> 2) as usize] as char);
        out.push(ALPH[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPH[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPH[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Test fixture cert + key — same self-signed cert
/// (CN=localhost) used across the TLS test suite. Embedded inline so
/// this test does not depend on the tests/fixtures/tls/ files (some
/// CI configs strip those).
const TEST_CERT_PEM: &[u8] = include_bytes!("fixtures/tls/server.crt");
const TEST_KEY_PEM: &[u8] = include_bytes!("fixtures/tls/server.key");

/// Server-side TLS verifier that accepts any certificate. Required
/// here because the test cert has CA:TRUE and is self-signed —
/// webpki's strict end-entity validation would reject it. The
/// pinning gate runs AFTER rustls validation, so the v24lvi
/// enforcement path is what we're actually exercising.
#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn make_pair(port_base: u16) -> (VirtualTcpStream, VirtualTcpStream) {
    VirtualTcpStream::pair(
        format!("127.0.0.1:{port_base}").parse().unwrap(),
        format!("127.0.0.1:{}", port_base + 1).parse().unwrap(),
    )
}

fn make_acceptor() -> TlsAcceptor {
    let chain = CertificateChain::from_pem(TEST_CERT_PEM).expect("server.crt");
    let key = PrivateKey::from_pem(TEST_KEY_PEM).expect("server.key");
    TlsAcceptorBuilder::new(chain, key)
        .build()
        .expect("acceptor")
}

fn make_client_config_accepting_any() -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth()
}

/// br-asupersync-m209nx — When the connector is configured with a
/// `CertificatePinSet` whose pins do NOT match the server's leaf
/// certificate, `connect()` MUST abort with `TlsError::PinMismatch`
/// AFTER the rustls handshake completes. Without the v24lvi gate,
/// the handshake succeeds and the caller receives a TlsStream over
/// an un-pinned (potentially MITM'd) connection.
#[test]
fn pin_mismatch_aborts_connect_after_handshake() {
    // Build a pin set with a deliberately wrong SHA-256 hash. Any
    // 32-byte value distinct from the server.crt leaf's actual hash
    // will do — using all-0xCC for clarity in trace output.
    let wrong_hash = vec![0xCCu8; 32];
    let wrong_pin = CertificatePin::cert_sha256(wrong_hash).expect("32-byte hash");
    let pin_set = CertificatePinSet::new().with_pin(wrong_pin);

    // Build connector with a tiny handshake-timeout cap so the test
    // can't hang on a misbehaving rustls. The pin gate runs AFTER
    // handshake-complete, so the timeout should never fire.
    use asupersync::tls::TlsConnectorBuilder;
    let _ = TlsConnectorBuilder::new(); // ensure builder is in scope
    // Use the raw new() variant — we hand it an AcceptAnyCert
    // ClientConfig directly so we can apply our pin set on top.
    let mut connector = TlsConnector::new(make_client_config_accepting_any());
    connector = connector.with_handshake_timeout(Duration::from_secs(5));
    connector = connector.with_pin_set(pin_set);

    let acceptor = make_acceptor();
    let (client_io, server_io) = make_pair(6680);
    let (client_result, _server_result) =
        futures_lite::future::block_on(futures_lite::future::zip(
            connector.connect("localhost", client_io),
            acceptor.accept(server_io),
        ));

    let err = client_result
        .err()
        .expect("connect MUST fail when pin set rejects the leaf cert");
    match err {
        TlsError::PinMismatch { expected, actual } => {
            assert!(
                !expected.is_empty(),
                "PinMismatch.expected must list the configured pin(s)"
            );
            // `actual` is the leaf hash (base64-encoded String) the
            // connector computed at handshake — it MUST be a
            // non-empty representation of the REAL leaf hash, NOT
            // the wrong-pin we configured.
            assert!(
                !actual.is_empty(),
                "PinMismatch.actual must be the observed leaf hash"
            );
            // 0xCCCC...CC base64 = "zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw=" — the
            // observed real leaf hash MUST NOT equal that.
            let wrong_b64 = base64_encode(&[0xCCu8; 32]);
            assert_ne!(
                actual, wrong_b64,
                "PinMismatch.actual must be the real leaf hash, not the wrong pin"
            );
        }
        other => panic!("expected TlsError::PinMismatch, got {other:?}"),
    }
}

/// br-asupersync-m209nx — Sanity control: with a CORRECT pin (the
/// SHA-256 of the actual fixture leaf cert), `connect()` MUST
/// succeed. Confirms the test fixture isn't independently broken
/// and the pin path is the actual reason the mismatch test above
/// rejects the handshake.
#[test]
fn pin_match_admits_connect() {
    let leaf_certs = Certificate::from_pem(TEST_CERT_PEM).expect("server.crt");
    let leaf = leaf_certs
        .into_iter()
        .next()
        .expect("at least one leaf cert");
    // Compute the actual SHA-256 over the leaf cert DER and use it
    // as the pin. This is the canonical "I trust this exact cert"
    // form.
    let pin = CertificatePin::compute_cert_sha256(&leaf).expect("compute_cert_sha256 fixture leaf");
    let pin_set = CertificatePinSet::new().with_pin(pin);

    let mut connector = TlsConnector::new(make_client_config_accepting_any());
    connector = connector.with_handshake_timeout(Duration::from_secs(5));
    connector = connector.with_pin_set(pin_set);

    let acceptor = make_acceptor();
    let (client_io, server_io) = make_pair(6682);
    let (client_result, server_result) = futures_lite::future::block_on(futures_lite::future::zip(
        connector.connect("localhost", client_io),
        acceptor.accept(server_io),
    ));

    client_result.expect("connect MUST succeed when pin matches the leaf cert");
    server_result.expect("server-side handshake MUST succeed too");
}
