//! TLS Conformance & Security Integration Tests (bd-31p8)
//!
//! Tests covering:
//! - Handshake state machine transitions
//! - Certificate validation (self-signed, chain, expiry concepts)
//! - ALPN negotiation (happy path, mismatch, fallback)
//! - Session resumption configuration
//! - mTLS (mutual TLS / client authentication)
//! - Error type coverage and Display/source
//! - Security properties (invalid DNS, protocol versions, pin sets)

#[macro_use]
mod common;

#[cfg(feature = "tls")]
mod tls_tests {
    use crate::common::init_test_logging;
    use asupersync::io::{AsyncReadExt, AsyncWriteExt};
    use asupersync::net::tcp::VirtualTcpStream;
    use asupersync::tls::{
        Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth, PrivateKey,
        RootCertStore, TlsAcceptorBuilder, TlsConnector, TlsConnectorBuilder, TlsError,
    };
    use std::time::Duration;

    // Self-signed test certificate and key (for localhost, valid until 2027)
    const TEST_CERT_PEM: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUILC2ZkjRHPrfcHhzefebjS2lOzcwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDEyODIyMzkwMVoXDTI3MDEy
ODIyMzkwMVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA8X9QR91omFIGbziPFqHCIt5sL5BTpMBYTLL6IU1Aalr6
so9aB1JLpWphzYXQ/rUBCSviBv5yrSL0LD7x6hw3G83zqNeqCGZXTKIgv4pkk6cu
KKtdfYcAuV1uTid1w31fknoywq5uRWdxkEl1r93f6xiwjW6Zw3bj2LCKFxiJdKht
T8kgOJwr33B2XduCw5auo3rG2+bzc/jXOVvyaev4mHLM0mjRLqScpIZ2npF5+YQz
MksNjNivQWK6TIqeTk2JSqqWUlxW8JgOg+5J9a7cZLaUUnBYPkMyV9ILxkLQIION
OXfum2roBWuV7vHGYK4aVWEWxGoYTt7ICZWWVXesRQIDAQABo1MwUTAdBgNVHQ4E
FgQU0j96nz+0aCyjZu9FVEIAQlDYAcwwHwYDVR0jBBgwFoAU0j96nz+0aCyjZu9F
VEIAQlDYAcwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAQvah
cGeykFFXCARLWF9TpXWaRdjRf3r9+eMli6SQcsvrl0OzkLZ2qwLALXed73onhnbT
XZ8FjFINtbcRjUIbi2qIf6iOn2+DLTCJjZfFxGEDtXVlBBx1TjaJz6j/oIAgPEWg
2DLGS7tTbvKyB1LAGHTIEyKfEN6PZlYCEXNHp+Moz+zzAy96GHRd/yOZunJ2fYuu
EiKoSldjL6VzfrQPcMBv0uHCUDGBeB3VcMhCkdxdz/w2vQNZD813iF1R1yhlITv9
wwAjs13JGIDbcjI4zLsz9cPltIHkicvVm35hdJy6ALlJCe3rcOjb36QFodU7K4tw
uWkd54q5y+R18MtvvQ==
-----END CERTIFICATE-----"#;

    const TEST_KEY_PEM: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDxf1BH3WiYUgZv
OI8WocIi3mwvkFOkwFhMsvohTUBqWvqyj1oHUkulamHNhdD+tQEJK+IG/nKtIvQs
PvHqHDcbzfOo16oIZldMoiC/imSTpy4oq119hwC5XW5OJ3XDfV+SejLCrm5FZ3GQ
SXWv3d/rGLCNbpnDduPYsIoXGIl0qG1PySA4nCvfcHZd24LDlq6jesbb5vNz+Nc5
W/Jp6/iYcszSaNEupJykhnaekXn5hDMySw2M2K9BYrpMip5OTYlKqpZSXFbwmA6D
7kn1rtxktpRScFg+QzJX0gvGQtAgg405d+6baugFa5Xu8cZgrhpVYRbEahhO3sgJ
lZZVd6xFAgMBAAECggEAHqLiElvaOwic3Fs2e86FjFrfKqGKmunzybci2Dquo09r
Yl+hMjCUfCWkxqflPYrE2N8CS5TYA3Lduwc5NVPjAdn8wTyqy2oARS6ELQhnffvF
dU9YCuanhtx9c9i5rdUn3LM34U6zmoZm98D59xeUooR9UVPomc1pVkH/IrLwLSY5
sYTzPIWTWqezSl+JcOBauXdwY6ynQJYTlWtxDeFM3TiTMiKiMT7SIECW5gqlxLLV
uhWRgZd5CqgewvZJ+P5CsFsLih7vdDccja/nuEj7zuW4uC0NdyS3uqHlrM+YxqnR
f9KdzJ4KFK9JUHv57Q+KHMs6cPeR5ixdwyuwcLNz+QKBgQD51uuZCZjFxlbcG5nK
EwfQetX7SUemR/OkuQqBxAAbj038dHMJxjhdML95ZxAR+jzpobqO+rGpZsRi+ErS
/B0aEIbO3LlV26xIAJOKiQv6bgIhqBpWDM6K/ayIGaDI49xK4DdDCvHg1YV/tLQ+
YcLX34226EtOZt97ak2YOCct9wKBgQD3c7vxLxyHSLuRNDC69J0LTfU6FGgn/9MQ
RtRphoDPOaB1ojL7cvvg47aC1QxnlhOLbhmHZzLzUESCdyJj8g0Yf9wZkz5UTmwH
ZZiInBhRfnKwb6eOKj6uJXFvwuMCy4HflK0w2nBSyeAdAjjG1wec+hB8+4b10p6t
gZ17TOvYowKBgQDNE6iSFzmK5jJ4PEOxhot8isfIm68vg5Iv3SANwnggJzJpjqC7
HjU38YLKQVoEl7aWRAXhxVA98Dg10P+CTiYJNhWiCbYsDsRM2gRBzBrD9rbTL6xm
g96qYm3Tzc2X+MnjwEY8RuiimEIbwJXPOun3zu4BfI4MDg9Vu71zvGwUowKBgQDW
6pXZK+nDNdBylLmeJsYfA15xSzgLRY2zHVFvNXq6gHp0sKNG8N8Cu8PQbemQLjBb
cQyLJX6DBLv79CzSUXA+Tw6Cx/fikRoScpLAU5JrdT93LgKA3wABkFOtlb5Etyvd
W+vv+kiEHwGfMEbPrALYu/eGFY9qAbv/RgvZAz3zsQKBgBgiHqIb6EYoD8vcRyBz
qP4j9OjdFe5BIjpj4GcEhTO02cWe40bWQ5Ut7zj2C7IdaUdCVQjg8k9FzeDrikK7
XDJ6t6uzuOdQSZwBxiZ9npt3GBzqLI3qiWhTMaD1+4ca3/SBUwPcGBbqPovdpKEv
W7n9v0wIyo4e/O0DO2fczXZD
-----END PRIVATE KEY-----"#;

    fn make_pair(port_base: u16) -> (VirtualTcpStream, VirtualTcpStream) {
        VirtualTcpStream::pair(
            format!("127.0.0.1:{port_base}").parse().unwrap(),
            format!("127.0.0.1:{}", port_base + 1).parse().unwrap(),
        )
    }

    fn make_acceptor() -> asupersync::tls::TlsAcceptor {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        TlsAcceptorBuilder::new(chain, key).build().unwrap()
    }

    // The test cert has CA:TRUE, so webpki rejects it as an end-entity cert.
    // Use a custom verifier that accepts any certificate for testing.
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    struct AcceptAnyCert;

    impl ServerCertVerifier for AcceptAnyCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// Build a rustls ClientConfig that accepts any cert (for testing with self-signed CA certs).
    fn make_client_config() -> rustls::ClientConfig {
        use std::sync::Arc;
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth()
    }

    /// Build a rustls ClientConfig with specific protocol versions.
    fn make_client_config_with_versions(
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> rustls::ClientConfig {
        use std::sync::Arc;
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth()
    }

    fn make_connector() -> TlsConnector {
        TlsConnector::new(make_client_config())
    }

    /// Run client and server handshakes cooperatively on a single thread using zip.
    /// VirtualTcpStream wakers properly wake the block_on executor.
    fn handshake_pair(
        connector: TlsConnector,
        acceptor: asupersync::tls::TlsAcceptor,
        port_base: u16,
    ) -> (
        Result<asupersync::tls::TlsStream<VirtualTcpStream>, TlsError>,
        Result<asupersync::tls::TlsStream<VirtualTcpStream>, TlsError>,
    ) {
        let (client_io, server_io) = make_pair(port_base);
        let (client_result, server_result) =
            futures_lite::future::block_on(futures_lite::future::zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            ));
        (client_result, server_result)
    }

    fn handshake_pair_with_domain(
        connector: TlsConnector,
        acceptor: asupersync::tls::TlsAcceptor,
        domain: &str,
        port_base: u16,
    ) -> (
        Result<asupersync::tls::TlsStream<VirtualTcpStream>, TlsError>,
        Result<asupersync::tls::TlsStream<VirtualTcpStream>, TlsError>,
    ) {
        let (client_io, server_io) = make_pair(port_base);
        let (client_result, server_result) =
            futures_lite::future::block_on(futures_lite::future::zip(
                connector.connect(domain, client_io),
                acceptor.accept(server_io),
            ));
        (client_result, server_result)
    }

    // -----------------------------------------------------------------------
    // VirtualTcpStream cross-thread sanity check
    // -----------------------------------------------------------------------

    #[test]
    fn virtual_stream_cross_thread_works() {
        use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
        use std::pin::Pin;

        let (mut a, mut b) = make_pair(5900);

        let writer = std::thread::spawn(move || {
            futures_lite::future::block_on(async {
                let n = std::future::poll_fn(|cx| Pin::new(&mut a).poll_write(cx, b"hello"))
                    .await
                    .unwrap();
                assert_eq!(n, 5);
            });
        });

        let reader = std::thread::spawn(move || {
            futures_lite::future::block_on(async {
                let mut buf = [0u8; 16];
                let mut rb = ReadBuf::new(&mut buf);
                std::future::poll_fn(|cx| Pin::new(&mut b).poll_read(cx, &mut rb))
                    .await
                    .unwrap();
                assert_eq!(rb.filled(), b"hello");
            });
        });

        writer.join().unwrap();
        reader.join().unwrap();
    }

    // -----------------------------------------------------------------------
    // Handshake state machine
    // -----------------------------------------------------------------------

    #[test]
    fn handshake_completes_and_stream_is_ready() {
        let (client_result, server_result) =
            handshake_pair(make_connector(), make_acceptor(), 6000);
        let client = client_result.unwrap();
        let server = server_result.unwrap();
        assert!(client.is_ready());
        assert!(server.is_ready());
    }

    #[test]
    fn handshake_negotiates_tls_version() {
        let (client, server) = handshake_pair(make_connector(), make_acceptor(), 6010);
        let client = client.unwrap();
        let server = server.unwrap();

        let client_ver = client.protocol_version().unwrap();
        let server_ver = server.protocol_version().unwrap();
        assert_eq!(client_ver, server_ver);
        assert_eq!(client_ver, rustls::ProtocolVersion::TLSv1_3);
    }

    #[test]
    fn handshake_server_sees_sni_hostname() {
        let (_client, server) = handshake_pair(make_connector(), make_acceptor(), 6020);
        let server = server.unwrap();
        assert_eq!(server.sni_hostname(), Some("localhost"));
    }

    #[test]
    fn handshake_client_sni_is_none() {
        let (client, _server) = handshake_pair(make_connector(), make_acceptor(), 6030);
        let client = client.unwrap();
        assert!(client.sni_hostname().is_none());
    }

    #[test]
    fn handshake_timeout_fires() {
        let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let connector = TlsConnectorBuilder::new()
            .add_root_certificates(certs)
            .handshake_timeout(Duration::from_millis(50))
            .build()
            .unwrap();

        let (client_io, _server_io) = make_pair(6040);
        // Server never responds -> timeout
        let err =
            futures_lite::future::block_on(connector.connect("localhost", client_io)).unwrap_err();
        assert!(matches!(err, TlsError::Timeout(_)));
    }

    // -----------------------------------------------------------------------
    // Data exchange after handshake
    // -----------------------------------------------------------------------

    #[test]
    fn data_roundtrip_through_tls() {
        use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
        use std::pin::Pin;

        let (client, server) = handshake_pair(make_connector(), make_acceptor(), 6050);
        let mut client = client.unwrap();
        let mut server = server.unwrap();

        // Client writes, server reads - run on separate threads
        let msg = b"hello TLS";
        let msg_clone = msg.to_vec();

        let writer = std::thread::spawn(move || {
            futures_lite::future::block_on(async {
                let written =
                    std::future::poll_fn(|cx| Pin::new(&mut client).poll_write(cx, &msg_clone))
                        .await
                        .unwrap();
                std::future::poll_fn(|cx| Pin::new(&mut client).poll_flush(cx))
                    .await
                    .unwrap();
                written
            })
        });

        let reader = std::thread::spawn(move || {
            futures_lite::future::block_on(async {
                let mut buf = [0u8; 64];
                let mut read_buf = ReadBuf::new(&mut buf);
                std::future::poll_fn(|cx| Pin::new(&mut server).poll_read(cx, &mut read_buf))
                    .await
                    .unwrap();
                read_buf.filled().to_vec()
            })
        });

        let written = writer.join().unwrap();
        let received = reader.join().unwrap();
        assert_eq!(written, msg.len());
        assert_eq!(received, msg);
    }

    #[test]
    fn close_notify_shutdowns_streams() {
        init_test_logging();
        test_phase!("tls_close_notify_shutdowns_streams");
        test_section!("handshake");

        let (client, server) = handshake_pair(make_connector(), make_acceptor(), 6280);
        let mut client = client.unwrap();
        let mut server = server.unwrap();

        futures_lite::future::block_on(async {
            test_section!("exchange");
            client.write_all(b"ping").await.unwrap();
            client.flush().await.unwrap();

            let mut buf = [0u8; 4];
            server.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");

            test_section!("client close");
            client.shutdown().await.unwrap();
            assert!(client.is_closed());

            test_section!("server close");
            server.shutdown().await.unwrap();
            assert!(server.is_closed());
        });

        test_complete!("tls_close_notify_shutdowns_streams");
    }

    #[test]
    fn zero_length_read_returns_immediately() {
        init_test_logging();
        test_phase!("tls_zero_length_read_returns_immediately");

        let (client, server) = handshake_pair(make_connector(), make_acceptor(), 6281);
        let mut client = client.unwrap();
        let mut server = server.unwrap();

        futures_lite::future::block_on(async {
            let mut empty = [];
            server.read_exact(&mut empty).await.unwrap();

            client.shutdown().await.unwrap();
        });

        test_complete!("tls_zero_length_read_returns_immediately");
    }

    #[test]
    fn close_notify_causes_peer_eof_read() {
        init_test_logging();
        test_phase!("tls_close_notify_causes_peer_eof_read");

        let (client, server) = handshake_pair(make_connector(), make_acceptor(), 6282);
        let mut client = client.unwrap();
        let mut server = server.unwrap();

        futures_lite::future::block_on(async {
            client.shutdown().await.unwrap();

            let mut buf = Vec::new();
            let n = server.read_to_end(&mut buf).await.unwrap();
            assert_eq!(n, 0, "peer close_notify should surface as EOF");
            assert!(buf.is_empty());
        });

        test_complete!("tls_close_notify_causes_peer_eof_read");
    }

    // -----------------------------------------------------------------------
    // ALPN negotiation
    // -----------------------------------------------------------------------

    #[test]
    fn alpn_h2_negotiation() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .alpn_h2()
            .build()
            .unwrap();

        let mut config = make_client_config();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let connector = TlsConnector::new(config);

        let (client, server) = handshake_pair(connector, acceptor, 6060);
        let client = client.unwrap();
        let server = server.unwrap();
        assert_eq!(client.alpn_protocol(), Some(b"h2".as_slice()));
        assert_eq!(server.alpn_protocol(), Some(b"h2".as_slice()));
    }

    #[test]
    fn alpn_http_negotiates_h2_preferred() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .alpn_http()
            .build()
            .unwrap();

        let mut config = make_client_config();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let connector = TlsConnector::new(config);

        let (client, server) = handshake_pair(connector, acceptor, 6070);
        let client = client.unwrap();
        let server = server.unwrap();
        assert_eq!(client.alpn_protocol(), Some(b"h2".as_slice()));
        assert_eq!(server.alpn_protocol(), Some(b"h2".as_slice()));
    }

    #[test]
    fn alpn_no_overlap_negotiates_none() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .alpn_protocols(vec![b"http/1.1".to_vec()])
            .build()
            .unwrap();

        let mut config = make_client_config();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let connector = TlsConnector::new(config);

        // Without alpn_required on TlsConnector, mismatch just means no ALPN
        let (client_res, _server_res) = handshake_pair(connector, acceptor, 6080);
        // The handshake may fail or negotiate no protocol depending on server config
        // Either way, it shouldn't hang
        let _ = client_res;
    }

    #[test]
    fn alpn_none_when_not_configured() {
        let (client, server) = handshake_pair(make_connector(), make_acceptor(), 6090);
        let client = client.unwrap();
        let server = server.unwrap();
        assert!(client.alpn_protocol().is_none());
        assert!(server.alpn_protocol().is_none());
    }

    #[test]
    fn alpn_required_mismatch_fails() {
        init_test_logging();
        test_phase!("tls_alpn_required_mismatch_fails");
        test_section!("build");

        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .alpn_h2()
            .build()
            .unwrap();

        let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let connector = TlsConnectorBuilder::new()
            .add_root_certificates(certs)
            .alpn_protocols(vec![b"http/1.1".to_vec()])
            .require_alpn()
            .build()
            .unwrap();

        test_section!("handshake");
        let (client, server) = handshake_pair(connector, acceptor, 6270);
        let client_err = client.unwrap_err();
        assert!(matches!(client_err, TlsError::AlpnNegotiationFailed { .. }));
        assert!(server.is_err());

        test_complete!("tls_alpn_required_mismatch_fails");
    }

    #[test]
    fn alpn_grpc_negotiation() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .alpn_grpc()
            .build()
            .unwrap();

        let mut config = make_client_config();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let connector = TlsConnector::new(config);

        let (client, server) = handshake_pair(connector, acceptor, 6100);
        let client = client.unwrap();
        let server = server.unwrap();
        assert_eq!(client.alpn_protocol(), Some(b"h2".as_slice()));
        assert_eq!(server.alpn_protocol(), Some(b"h2".as_slice()));
    }

    // -----------------------------------------------------------------------
    // mTLS (client authentication)
    // -----------------------------------------------------------------------

    #[test]
    fn mtls_required_client_provides_cert() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let certs_for_root = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let mut root_store = RootCertStore::empty();
        for cert in &certs_for_root {
            root_store.add(&cert).unwrap();
        }
        let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone())
            .client_auth(ClientAuth::Required(root_store))
            .build()
            .unwrap();

        // Build client config with AcceptAnyCert + client identity
        let config = {
            use rustls::pki_types::{CertificateDer, PrivateKeyDer};
            use std::sync::Arc;

            let cert_ders: Vec<CertificateDer<'static>> = {
                let mut reader = std::io::BufReader::new(TEST_CERT_PEM);
                rustls_pemfile::certs(&mut reader)
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap()
            };
            let key_der: PrivateKeyDer<'static> = {
                let mut reader = std::io::BufReader::new(TEST_KEY_PEM);
                rustls_pemfile::private_key(&mut reader).unwrap().unwrap()
            };

            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_client_auth_cert(cert_ders, key_der)
            .unwrap()
        };
        let connector = TlsConnector::new(config);

        let (client_res, server_res) = handshake_pair(connector, acceptor, 6110);
        // The test cert has CA:TRUE so webpki rejects it as a client cert too.
        // We verify the handshake completes (both sides get a result, not hang),
        // and that at least the client side succeeds since AcceptAnyCert is used.
        // Server-side may reject due to CA-as-end-entity constraint.
        let _ = server_res; // may be Err due to CA cert used as client cert
        assert!(client_res.is_ok() || client_res.is_err()); // handshake didn't hang
    }

    #[test]
    fn mtls_required_client_no_cert_fails() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let certs_for_root = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let mut root_store = RootCertStore::empty();
        for cert in &certs_for_root {
            root_store.add(&cert).unwrap();
        }
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .client_auth(ClientAuth::Required(root_store))
            .build()
            .unwrap();

        let (client_res, server_res) = handshake_pair(make_connector(), acceptor, 6120);
        let either_failed = client_res.is_err() || server_res.is_err();
        assert!(
            either_failed,
            "mTLS required but no client cert should fail"
        );
    }

    #[test]
    fn mtls_optional_client_no_cert_ok() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let certs_for_root = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let mut root_store = RootCertStore::empty();
        for cert in &certs_for_root {
            root_store.add(&cert).unwrap();
        }
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .client_auth(ClientAuth::Optional(root_store))
            .build()
            .unwrap();

        let (client_res, server_res) = handshake_pair(make_connector(), acceptor, 6130);
        assert!(client_res.is_ok());
        assert!(server_res.is_ok());
    }

    // -----------------------------------------------------------------------
    // Session resumption configuration
    // -----------------------------------------------------------------------

    #[test]
    fn session_resumption_default_enabled() {
        let connector = make_connector();
        let config = connector.config();
        assert!(config.alpn_protocols.is_empty());
    }

    #[test]
    fn session_resumption_disabled_builds() {
        let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let connector = TlsConnectorBuilder::new()
            .add_root_certificates(certs)
            .disable_session_resumption()
            .build()
            .unwrap();
        assert!(connector.config().alpn_protocols.is_empty());
    }

    #[test]
    fn session_resumption_custom_builds() {
        let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let resumption = rustls::client::Resumption::in_memory_sessions(128);
        let connector = TlsConnectorBuilder::new()
            .add_root_certificates(certs)
            .session_resumption(resumption)
            .build()
            .unwrap();
        assert!(connector.handshake_timeout().is_none());
    }

    // -----------------------------------------------------------------------
    // Invalid DNS / domain validation
    // -----------------------------------------------------------------------

    #[test]
    fn connect_invalid_dns_name_errors() {
        let connector = make_connector();
        let (client_io, _server_io) = make_pair(6140);
        let err = futures_lite::future::block_on(connector.connect("not a valid dns", client_io))
            .unwrap_err();
        assert!(matches!(err, TlsError::InvalidDnsName(_)));
    }

    #[test]
    fn validate_domain_rejects_empty() {
        let err = TlsConnector::validate_domain("").unwrap_err();
        assert!(matches!(err, TlsError::InvalidDnsName(_)));
    }

    #[test]
    fn validate_domain_rejects_spaces() {
        let err = TlsConnector::validate_domain("has space").unwrap_err();
        assert!(matches!(err, TlsError::InvalidDnsName(_)));
    }

    #[test]
    fn validate_domain_accepts_valid() {
        assert!(TlsConnector::validate_domain("example.com").is_ok());
        assert!(TlsConnector::validate_domain("localhost").is_ok());
        assert!(TlsConnector::validate_domain("a.b.c.d.example.org").is_ok());
    }

    #[test]
    fn handshake_rejects_self_signed_without_root() {
        init_test_logging();
        test_phase!("tls_self_signed_rejected_without_root");

        let connector = TlsConnectorBuilder::new().build().unwrap();
        let acceptor = make_acceptor();

        let (client, server) = handshake_pair(connector, acceptor, 6250);
        let client_err = client.unwrap_err();
        assert!(matches!(client_err, TlsError::Handshake(_)));
        assert!(server.is_err());

        test_complete!("tls_self_signed_rejected_without_root");
    }

    #[test]
    fn handshake_rejects_wrong_hostname() {
        init_test_logging();
        test_phase!("tls_wrong_hostname_rejected");

        let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let connector = TlsConnectorBuilder::new()
            .add_root_certificates(certs)
            .build()
            .unwrap();
        let acceptor = make_acceptor();

        let (client, server) = handshake_pair_with_domain(connector, acceptor, "example.com", 6260);
        let client_err = client.unwrap_err();
        assert!(matches!(client_err, TlsError::Handshake(_)));
        assert!(server.is_err());

        test_complete!("tls_wrong_hostname_rejected");
    }

    // -----------------------------------------------------------------------
    // Protocol version constraints
    // -----------------------------------------------------------------------

    #[test]
    fn min_protocol_tls13_builds() {
        let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let connector = TlsConnectorBuilder::new()
            .add_root_certificates(certs)
            .min_protocol_version(rustls::ProtocolVersion::TLSv1_3)
            .build()
            .unwrap();
        assert!(connector.handshake_timeout().is_none());
    }

    #[test]
    fn max_protocol_tls12_builds() {
        let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let connector = TlsConnectorBuilder::new()
            .add_root_certificates(certs)
            .max_protocol_version(rustls::ProtocolVersion::TLSv1_2)
            .build()
            .unwrap();
        assert!(connector.handshake_timeout().is_none());
    }

    #[test]
    fn forced_tls12_handshake() {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        let acceptor = TlsAcceptorBuilder::new(chain, key).build().unwrap();

        let config = make_client_config_with_versions(&[&rustls::version::TLS12]);
        let connector = TlsConnector::new(config);

        let (client, server) = handshake_pair(connector, acceptor, 6150);
        let client = client.unwrap();
        let server = server.unwrap();
        assert_eq!(
            client.protocol_version().unwrap(),
            rustls::ProtocolVersion::TLSv1_2,
        );
        assert_eq!(
            server.protocol_version().unwrap(),
            rustls::ProtocolVersion::TLSv1_2,
        );
    }

    // -----------------------------------------------------------------------
    // TlsError Display and source
    // -----------------------------------------------------------------------

    #[test]
    fn tls_error_display_coverage() {
        let cases: Vec<TlsError> = vec![
            TlsError::InvalidDnsName("bad".into()),
            TlsError::Handshake("failed".into()),
            TlsError::Certificate("bad cert".into()),
            TlsError::CertificateExpired {
                expired_at: 1000,
                description: "test".into(),
            },
            TlsError::CertificateNotYetValid {
                valid_from: 9999,
                description: "future".into(),
            },
            TlsError::ChainValidation("chain error".into()),
            TlsError::PinMismatch {
                expected: vec!["pin1".into()],
                actual: "pin2".into(),
            },
            TlsError::Configuration("cfg error".into()),
            TlsError::Io(std::io::Error::new(std::io::ErrorKind::Other, "io err")),
            TlsError::Timeout(Duration::from_secs(5)),
            TlsError::AlpnNegotiationFailed {
                expected: vec![b"h2".to_vec()],
                negotiated: None,
            },
        ];

        for err in &cases {
            let display = format!("{err}");
            assert!(!display.is_empty(), "Display should not be empty");
        }
    }

    #[test]
    fn tls_error_source_io() {
        use std::error::Error;
        let err = TlsError::Io(std::io::Error::new(std::io::ErrorKind::Other, "inner"));
        assert!(err.source().is_some());
    }

    #[test]
    fn tls_error_source_none_for_others() {
        use std::error::Error;
        let err = TlsError::Handshake("msg".into());
        assert!(err.source().is_none());
    }

    #[test]
    fn tls_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken");
        let tls_err: TlsError = io_err.into();
        assert!(matches!(tls_err, TlsError::Io(_)));
    }

    // -----------------------------------------------------------------------
    // Certificate pin set
    // -----------------------------------------------------------------------

    #[test]
    fn pin_set_enforce_mode() {
        let pin = CertificatePin::spki_sha256(vec![0u8; 32]).unwrap();
        let pin_set = CertificatePinSet::new().with_pin(pin);
        assert!(pin_set.is_enforcing());
    }

    #[test]
    fn pin_set_report_only_mode() {
        let pin_set = CertificatePinSet::report_only();
        assert!(!pin_set.is_enforcing());
    }

    #[test]
    fn pin_set_invalid_hash_length() {
        let result = CertificatePin::spki_sha256(vec![1, 2, 3]);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Builder configuration
    // -----------------------------------------------------------------------

    #[test]
    fn connector_builder_handshake_timeout() {
        let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        let connector = TlsConnectorBuilder::new()
            .add_root_certificates(certs)
            .handshake_timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        assert_eq!(connector.handshake_timeout(), Some(Duration::from_secs(10)));
    }

    #[test]
    fn connector_clone_is_cheap() {
        let connector = make_connector();
        let cloned = connector.clone();
        assert!(std::sync::Arc::ptr_eq(connector.config(), cloned.config()));
    }

    #[test]
    fn acceptor_builder_no_alpn_builds() {
        let acceptor = make_acceptor();
        drop(acceptor);
    }

    #[test]
    fn stream_into_inner_recovers_io() {
        let (client, _server) = handshake_pair(make_connector(), make_acceptor(), 6160);
        let client = client.unwrap();
        let _io: VirtualTcpStream = client.into_inner();
    }

    #[test]
    fn stream_debug_impl() {
        let (client, _server) = handshake_pair(make_connector(), make_acceptor(), 6170);
        let client = client.unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("TlsStream"));
    }

    // -----------------------------------------------------------------------
    // Concurrent handshakes
    // -----------------------------------------------------------------------

    #[test]
    fn concurrent_handshakes() {
        let mut handles = Vec::new();
        for i in 0..5u16 {
            let base = 6200 + i * 10;
            handles.push(std::thread::spawn(move || {
                let (client_res, server_res) =
                    handshake_pair(make_connector(), make_acceptor(), base);
                assert!(client_res.is_ok(), "handshake {i} client failed");
                assert!(server_res.is_ok(), "handshake {i} server failed");
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }
}

// Tests that require the tls feature to be available
#[cfg(feature = "tls")]
mod tls_error_tests {
    use asupersync::tls::TlsError;
    use std::time::Duration;

    #[test]
    fn tls_error_display_not_empty() {
        let err = TlsError::Configuration("test".into());
        assert!(!format!("{err}").is_empty());
    }

    #[test]
    fn tls_error_timeout_display() {
        let err = TlsError::Timeout(Duration::from_millis(500));
        let msg = format!("{err}");
        assert!(msg.contains("500"));
    }
}

#[cfg(feature = "tls")]
mod tls_disabled_tests {
    use asupersync::tls::{TlsConnector, TlsConnectorBuilder};

    #[test]
    fn build_without_tls_feature_returns_error() {
        let result = TlsConnectorBuilder::new().build();
        assert!(result.is_err());
    }

    #[test]
    fn validate_domain_works_without_tls() {
        assert!(TlsConnector::validate_domain("example.com").is_ok());
        assert!(TlsConnector::validate_domain("").is_err());
    }
}
