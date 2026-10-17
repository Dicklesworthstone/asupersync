//! Real PSS-signed leaf certificates through the existing bounded rustls pair.
//! Fixtures reuse the repository's public test key and are valid 2026-2036.

use super::{
    KEY_PEM, MemoryIo, TlsStream, assert_disconnected, assert_incomplete, establish,
    handshake, streams,
};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::tls::{Certificate, CertificateChain, PrivateKey, TlsError};
use rustls::{CipherSuite, ClientConfig, ProtocolVersion, ServerConfig};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

const CA: &[u8] = include_bytes!("../../../tests/fixtures/tls/pss/ca.crt");
const CASES: &[(&[u8], &str)] = &[
    (
        include_bytes!("../../../tests/fixtures/tls/pss/sha256.crt"),
        "24fb06ed43aece7b95da29196b902805f995d86b4cfb76a5e5c9d92286ffb847",
    ),
    (
        include_bytes!("../../../tests/fixtures/tls/pss/sha384.crt"),
        "7c5a3e276b22b80a5d54783ca43c83ac64236133f2a00647aa2786010accfd29cead3844da688dc1b45c06c7102b9e72",
    ),
    (
        include_bytes!("../../../tests/fixtures/tls/pss/sha512.crt"),
        "5ed67c1a4c5b2d082bc2c33a9583bedcd2725794f79b6a1ba88b06ad24db2150dd258c704d7e95d350788b221494cf32139d6a56e70052316adabcbb27820b39",
    ),
];

fn pss_configs(
    version: &'static rustls::SupportedProtocolVersion,
    leaf: Certificate,
) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateChain::from_pem(CA).unwrap().into_inner() {
        roots.add(certificate).unwrap();
    }
    let mut provider = rustls::crypto::ring::default_provider();
    if version.version == ProtocolVersion::TLSv1_3 {
        // Deliberately force a SHA-256 cipher-suite hash even when the CA's
        // certificate signature hash is SHA-384 or SHA-512.
        provider.cipher_suites.retain(|suite| {
            suite.suite() == CipherSuite::TLS13_AES_128_GCM_SHA256
        });
    }
    let provider = Arc::new(provider);
    let client = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            CertificateChain::from_cert(leaf).into_inner(),
            PrivateKey::from_pem(KEY_PEM).unwrap().clone_inner(),
        )
        .unwrap();
    (Arc::new(client), Arc::new(server))
}

fn leaf(pem: &[u8]) -> Certificate {
    Certificate::from_pem(pem).unwrap().remove(0)
}

fn exchange(sender: &mut TlsStream<MemoryIo>, receiver: &mut TlsStream<MemoryIo>) {
    let mut task = Context::from_waker(Waker::noop());
    let message = b"PSS channel binding does not consume application data";
    assert!(matches!(
        Pin::new(&mut *sender).poll_write(&mut task, message),
        Poll::Ready(Ok(written)) if written == message.len(),
    ));
    assert!(matches!(Pin::new(sender).poll_flush(&mut task), Poll::Ready(Ok(()))));
    let mut bytes = [0; 128];
    let mut read = ReadBuf::new(&mut bytes);
    assert!(matches!(
        Pin::new(receiver).poll_read(&mut task, &mut read),
        Poll::Ready(Ok(())),
    ));
    assert_eq!(read.filled(), message);
}

fn run_bindings(version: &'static rustls::SupportedProtocolVersion) {
    for &(pem, expected) in CASES {
        let certificate = leaf(pem);
        let (cc, sc) = pss_configs(version, certificate.clone());
        let (mut client, mut server) = streams(&cc, &sc);
        assert_incomplete(&client);
        establish(&mut client, &mut server);
        assert_eq!(client.protocol_version(), Some(version.version));
        if version.version == ProtocolVersion::TLSv1_3 {
            assert_eq!(client.negotiated_cipher_suite(), Some(CipherSuite::TLS13_AES_128_GCM_SHA256));
        }
        let calls = client.io.io_calls;
        let binding = client.tls_server_end_point_channel_binding().unwrap();
        assert_eq!(binding, hex::decode(expected).unwrap());
        assert_eq!(binding, certificate.tls_server_end_point_channel_binding().unwrap());
        assert_eq!(binding, client.tls_server_end_point_channel_binding().unwrap());
        assert_eq!(client.io.io_calls, calls);
        assert!(matches!(server.tls_server_end_point_channel_binding(), Err(TlsError::Configuration(_))));
        exchange(&mut client, &mut server);
        exchange(&mut server, &mut client);
        assert_eq!(binding, client.tls_server_end_point_channel_binding().unwrap());
    }
}

#[test]
fn tls12_pss_signed_server_leaves_use_their_actual_signature_hash() {
    run_bindings(&rustls::version::TLS12);
}

#[test]
fn tls13_pss_binding_hash_is_independent_of_the_negotiated_cipher_suite_hash() {
    run_bindings(&rustls::version::TLS13);
}

#[test]
fn pss_binding_waits_for_final_handshake_flush() {
    let (cc, sc) = pss_configs(&rustls::version::TLS13, leaf(CASES[1].0));
    let (mut client, mut server) = streams(&cc, &sc);
    let mut task = Context::from_waker(Waker::noop());
    assert!(client.poll_handshake(&mut task).is_pending());
    assert!(server.poll_handshake(&mut task).is_pending());
    client.io.block_flush = true;
    assert!(client.poll_handshake(&mut task).is_pending());
    assert!(!client.conn.is_handshaking());
    assert!(!client.is_ready());
    assert_incomplete(&client);
    client.io.block_flush = false;
    establish(&mut client, &mut server);
    assert_eq!(client.tls_server_end_point_channel_binding().unwrap(), hex::decode(CASES[1].1).unwrap());
}

#[test]
fn computable_pss_binding_does_not_bypass_certificate_signature_verification() {
    let mut der = leaf(CASES[1].0).as_der().to_vec();
    *der.last_mut().unwrap() ^= 1;
    let corrupt = Certificate::from_der(der);
    // Certificate-only hashing is deliberately not a trust decision.
    assert!(corrupt.tls_server_end_point_channel_binding().is_ok());
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let (cc, sc) = pss_configs(version, corrupt.clone());
        let (mut client, mut server) = streams(&cc, &sc);
        let (result, _) = handshake(&mut client, &mut server);
        assert!(result.is_err(), "a corrupt PSS signature must fail authentication");
        assert_disconnected(&client);
    }
}

#[test]
fn pss_session_resumption_preserves_certificate_binding_not_exporter_identity() {
    let (mut cc, mut sc) = pss_configs(&rustls::version::TLS13, leaf(CASES[1].0));
    Arc::get_mut(&mut cc).unwrap().enable_early_data = true;
    Arc::get_mut(&mut sc).unwrap().max_early_data_size = 1024;
    let (mut first, mut first_peer) = streams(&cc, &sc);
    establish(&mut first, &mut first_peer);
    let binding = first.tls_server_end_point_channel_binding().unwrap();
    let exporter = first.tls_exporter_channel_binding().unwrap();
    let mut task = Context::from_waker(Waker::noop());
    let mut bytes = [0; 1];
    let mut read = ReadBuf::new(&mut bytes);
    assert!(Pin::new(&mut first).poll_read(&mut task, &mut read).is_pending());
    let (mut resumed, mut peer) = streams(&cc, &sc);
    let super::TlsConnection::Client(conn) = &mut resumed.conn else { unreachable!() };
    assert!(conn.early_data().is_some());
    assert_incomplete(&resumed);
    establish(&mut resumed, &mut peer);
    let super::TlsConnection::Client(conn) = &resumed.conn else { unreachable!() };
    assert_eq!(conn.handshake_kind(), Some(rustls::HandshakeKind::Resumed));
    assert_eq!(resumed.tls_server_end_point_channel_binding().unwrap(), binding);
    assert_ne!(resumed.tls_exporter_channel_binding().unwrap(), exporter);
}
