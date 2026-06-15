use std::time::Duration;

use asupersync::cx::Cx;
use asupersync::net::quic_native::tls::QuicServerIdentityVerifier;
use asupersync::net::quic_native::{
    NativeQuicConnection, NativeQuicConnectionConfig, NativeQuicConnectionError,
    QuicConnectionState, QuicTlsError,
};
use asupersync::tls::{Certificate, CertificateChain, RootCertStore};

const TEST_CERT_PEM: &[u8] = include_bytes!("fixtures/tls/server.crt");

fn valid_fixture_time() -> rustls_pki_types::UnixTime {
    rustls_pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1_780_000_000))
}

fn after_fixture_expiration_time() -> rustls_pki_types::UnixTime {
    rustls_pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1_820_000_000))
}

fn trusted_fixture_material() -> (QuicServerIdentityVerifier, CertificateChain) {
    let certs = Certificate::from_pem(TEST_CERT_PEM).expect("fixture cert parses");
    let mut roots = RootCertStore::empty();
    roots
        .add(&certs[0])
        .expect("self-signed fixture can be a test trust anchor");
    let verifier = QuicServerIdentityVerifier::from_root_store(roots).expect("verifier builds");
    (verifier, CertificateChain::from(certs))
}

fn client_after_1rtt_key_install(cx: &Cx) -> NativeQuicConnection {
    let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
    conn.begin_handshake(cx).expect("handshake begins");
    conn.on_handshake_keys_available(cx)
        .expect("handshake keys install");
    conn.on_1rtt_keys_available(cx).expect("1-RTT keys install");
    conn
}

#[test]
fn valid_test_ca_certificate_confirms_client_handshake() {
    let cx = Cx::for_testing();
    let (verifier, chain) = trusted_fixture_material();
    let mut conn = client_after_1rtt_key_install(&cx);

    let receipt = conn
        .verify_server_identity_and_confirm_handshake(
            &cx,
            &verifier,
            "localhost",
            chain,
            valid_fixture_time(),
        )
        .expect("valid test-CA certificate confirms the client handshake");

    assert_eq!(receipt.chain_len, 1);
    assert_eq!(receipt.root_count, 1);
    assert_eq!(conn.state(), QuicConnectionState::Established);
    assert!(conn.can_send_1rtt());
}

#[test]
fn wrong_hostname_fails_closed_and_preserves_identity_gate() {
    let cx = Cx::for_testing();
    let (verifier, chain) = trusted_fixture_material();
    let mut conn = client_after_1rtt_key_install(&cx);

    let err = conn
        .verify_server_identity_and_confirm_handshake(
            &cx,
            &verifier,
            "not-localhost.example",
            chain,
            valid_fixture_time(),
        )
        .expect_err("wrong hostname must fail closed");

    assert!(matches!(
        err,
        NativeQuicConnectionError::Tls(QuicTlsError::ServerCertificateRejected { .. })
    ));
    assert_eq!(conn.state(), QuicConnectionState::Handshaking);
    assert!(!conn.can_send_1rtt());
    let confirm_err = conn
        .on_handshake_confirmed(&cx)
        .expect_err("failed verification must not set the identity gate");
    assert!(matches!(
        confirm_err,
        NativeQuicConnectionError::Tls(QuicTlsError::ServerCertificateUnverified)
    ));
}

#[test]
fn expired_certificate_time_fails_closed() {
    let (verifier, chain) = trusted_fixture_material();

    let err = verifier
        .verify_server_chain("localhost", chain, after_fixture_expiration_time())
        .expect_err("certificate outside validity window must fail closed");

    assert!(matches!(
        err,
        QuicTlsError::ServerCertificateRejected { .. }
    ));
}

#[test]
fn empty_root_store_is_rejected_before_handshake_use() {
    let err = QuicServerIdentityVerifier::from_root_store(RootCertStore::empty())
        .expect_err("empty roots must fail closed");

    assert_eq!(err, QuicTlsError::ServerIdentityRootStoreEmpty);
}

#[test]
fn empty_presented_chain_fails_closed() {
    let (verifier, _) = trusted_fixture_material();

    let err = verifier
        .verify_server_chain("localhost", CertificateChain::new(), valid_fixture_time())
        .expect_err("empty peer certificate chain must fail closed");

    assert_eq!(err, QuicTlsError::ServerCertificateChainEmpty);
}
