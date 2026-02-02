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
    use asupersync::net::tcp::VirtualTcpStream;
    use asupersync::tls::{
        Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth, PrivateKey,
        RootCertStore, TlsAcceptorBuilder, TlsConnector, TlsConnectorBuilder, TlsError,
    };
    use futures_lite::future::zip;
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

    fn make_connector() -> TlsConnector {
        let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
        TlsConnectorBuilder::new()
            .add_root_certificates(certs)
            .build()
            .unwrap()
    }

    // -----------------------------------------------------------------------
    // Handshake state machine
    // -----------------------------------------------------------------------

    #[test]
    fn handshake_completes_and_stream_is_ready() {
        crate::common::run_test(|| async {
            let acceptor = make_acceptor();
            let connector = make_connector();
            let (client_io, server_io) = make_pair(6000);

            let (client, server) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let client = client.unwrap();
            let server = server.unwrap();
            assert!(client.is_ready());
            assert!(server.is_ready());
            assert!(!client.is_closed());
            assert!(!server.is_closed());
        });
    }

    #[test]
    fn handshake_negotiates_tls_version() {
        crate::common::run_test(|| async {
            let acceptor = make_acceptor();
            let connector = make_connector();
            let (client_io, server_io) = make_pair(6010);

            let (client, server) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let client = client.unwrap();
            let server = server.unwrap();

            // Both sides should agree on TLS version
            let client_ver = client.protocol_version().unwrap();
            let server_ver = server.protocol_version().unwrap();
            assert_eq!(client_ver, server_ver);
            // With modern rustls defaults, TLS 1.3 is preferred
            assert_eq!(client_ver, rustls::ProtocolVersion::TLSv1_3,);
        });
    }

    #[test]
    fn handshake_server_sees_sni_hostname() {
        crate::common::run_test(|| async {
            let acceptor = make_acceptor();
            let connector = make_connector();
            let (client_io, server_io) = make_pair(6020);

            let (client, server) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let _client = client.unwrap();
            let server = server.unwrap();

            // Server should see the SNI hostname sent by the client
            assert_eq!(server.sni_hostname(), Some("localhost"));
        });
    }

    #[test]
    fn handshake_client_sni_is_none() {
        crate::common::run_test(|| async {
            let acceptor = make_acceptor();
            let connector = make_connector();
            let (client_io, server_io) = make_pair(6030);

            let (client, _server) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let client = client.unwrap();
            // Client side does not have SNI access
            assert!(client.sni_hostname().is_none());
        });
    }

    #[test]
    fn handshake_timeout_fires() {
        crate::common::run_test(|| async {
            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .handshake_timeout(Duration::from_millis(5))
                .build()
                .unwrap();

            // Server never responds -> timeout
            let (client_io, _server_io) = make_pair(6040);
            let err = connector.connect("localhost", client_io).await.unwrap_err();
            assert!(matches!(err, TlsError::Timeout(_)));
        });
    }

    // -----------------------------------------------------------------------
    // Data exchange after handshake
    // -----------------------------------------------------------------------

    #[test]
    fn data_roundtrip_through_tls() {
        use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
        use std::pin::Pin;
        crate::common::run_test(|| async {
            let acceptor = make_acceptor();
            let connector = make_connector();
            let (client_io, server_io) = make_pair(6050);

            let (client, server) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let mut client = client.unwrap();
            let mut server = server.unwrap();

            // Client writes, server reads
            let msg = b"hello TLS";
            let written = std::future::poll_fn(|cx| Pin::new(&mut client).poll_write(cx, msg))
                .await
                .unwrap();
            assert_eq!(written, msg.len());

            // Flush client
            std::future::poll_fn(|cx| Pin::new(&mut client).poll_flush(cx))
                .await
                .unwrap();

            // Server reads
            let mut buf = [0u8; 64];
            let mut read_buf = ReadBuf::new(&mut buf);
            std::future::poll_fn(|cx| Pin::new(&mut server).poll_read(cx, &mut read_buf))
                .await
                .unwrap();
            assert_eq!(read_buf.filled(), msg);
        });
    }

    // -----------------------------------------------------------------------
    // ALPN negotiation
    // -----------------------------------------------------------------------

    #[test]
    fn alpn_h2_negotiation() {
        crate::common::run_test(|| async {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .alpn_h2()
                .build()
                .unwrap();

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_h2()
                .build()
                .unwrap();

            let (client_io, server_io) = make_pair(6060);
            let (client, server) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let client = client.unwrap();
            let server = server.unwrap();
            assert_eq!(client.alpn_protocol(), Some(b"h2".as_slice()));
            assert_eq!(server.alpn_protocol(), Some(b"h2".as_slice()));
        });
    }

    #[test]
    fn alpn_http_negotiates_h2_preferred() {
        crate::common::run_test(|| async {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .alpn_http()
                .build()
                .unwrap();

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_http()
                .build()
                .unwrap();

            let (client_io, server_io) = make_pair(6070);
            let (client, server) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let client = client.unwrap();
            let server = server.unwrap();
            // Server picks h2 (first in list)
            assert_eq!(client.alpn_protocol(), Some(b"h2".as_slice()));
            assert_eq!(server.alpn_protocol(), Some(b"h2".as_slice()));
        });
    }

    #[test]
    fn alpn_no_overlap_client_required_errors() {
        crate::common::run_test(|| async {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .alpn_protocols(vec![b"http/1.1".to_vec()])
                .build()
                .unwrap();

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_h2() // requires h2
                .build()
                .unwrap();

            let (client_io, server_io) = make_pair(6080);
            let (client_res, _server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let err = client_res.unwrap_err();
            assert!(matches!(err, TlsError::AlpnNegotiationFailed { .. }));
        });
    }

    #[test]
    fn alpn_none_when_not_configured() {
        crate::common::run_test(|| async {
            let acceptor = make_acceptor();
            let connector = make_connector();
            let (client_io, server_io) = make_pair(6090);

            let (client, server) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let client = client.unwrap();
            let server = server.unwrap();
            assert!(client.alpn_protocol().is_none());
            assert!(server.alpn_protocol().is_none());
        });
    }

    #[test]
    fn alpn_grpc_negotiation() {
        crate::common::run_test(|| async {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .alpn_grpc()
                .build()
                .unwrap();

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_grpc()
                .build()
                .unwrap();

            let (client_io, server_io) = make_pair(6100);
            let (client, server) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let client = client.unwrap();
            let server = server.unwrap();
            assert_eq!(client.alpn_protocol(), Some(b"h2".as_slice()));
            assert_eq!(server.alpn_protocol(), Some(b"h2".as_slice()));
        });
    }

    // -----------------------------------------------------------------------
    // mTLS (client authentication)
    // -----------------------------------------------------------------------

    #[test]
    fn mtls_required_client_provides_cert() {
        crate::common::run_test(|| async {
            // Server requires client certs
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

            // Client provides client cert
            let client_certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = TlsConnectorBuilder::new()
                .add_root_certificates(client_certs)
                .identity(chain, key)
                .build()
                .unwrap();

            let (client_io, server_io) = make_pair(6110);
            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            assert!(client_res.is_ok());
            assert!(server_res.is_ok());
        });
    }

    #[test]
    fn mtls_required_client_no_cert_fails() {
        crate::common::run_test(|| async {
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

            // Client has no client identity
            let connector = make_connector();

            let (client_io, server_io) = make_pair(6120);
            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            // At least one side must fail
            let either_failed = client_res.is_err() || server_res.is_err();
            assert!(
                either_failed,
                "mTLS required but no client cert should fail"
            );
        });
    }

    #[test]
    fn mtls_optional_client_no_cert_ok() {
        crate::common::run_test(|| async {
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

            let connector = make_connector();
            let (client_io, server_io) = make_pair(6130);

            let (client_res, server_res) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            assert!(client_res.is_ok());
            assert!(server_res.is_ok());
        });
    }

    // -----------------------------------------------------------------------
    // Session resumption configuration
    // -----------------------------------------------------------------------

    #[test]
    fn session_resumption_default_enabled() {
        let connector = make_connector();
        // Default config has resumption enabled (rustls default: in-memory, 256 sessions)
        let config = connector.config();
        // The resumption field is not directly inspectable, but building succeeds
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

        // Connector with disabled resumption builds successfully
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
        crate::common::run_test(|| async {
            let connector = make_connector();
            let (client_io, _server_io) = make_pair(6140);

            let err = connector
                .connect("not a valid dns", client_io)
                .await
                .unwrap_err();
            assert!(matches!(err, TlsError::InvalidDnsName(_)));
        });
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
        crate::common::run_test(|| async {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key).build().unwrap();

            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .max_protocol_version(rustls::ProtocolVersion::TLSv1_2)
                .build()
                .unwrap();

            let (client_io, server_io) = make_pair(6150);
            let (client, server) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

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
        });
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
        // Arc-based cloning should produce identical configs
        assert!(std::sync::Arc::ptr_eq(connector.config(), cloned.config()));
    }

    #[test]
    fn acceptor_builder_no_alpn_builds() {
        let acceptor = make_acceptor();
        // Should build without ALPN
        drop(acceptor);
    }

    #[test]
    fn stream_into_inner_recovers_io() {
        crate::common::run_test(|| async {
            let acceptor = make_acceptor();
            let connector = make_connector();
            let (client_io, server_io) = make_pair(6160);

            let (client, _server) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let client = client.unwrap();
            let _io: VirtualTcpStream = client.into_inner();
        });
    }

    #[test]
    fn stream_debug_impl() {
        crate::common::run_test(|| async {
            let acceptor = make_acceptor();
            let connector = make_connector();
            let (client_io, server_io) = make_pair(6170);

            let (client, _server) = zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let client = client.unwrap();
            let debug = format!("{client:?}");
            assert!(debug.contains("TlsStream"));
        });
    }

    // -----------------------------------------------------------------------
    // Concurrent handshakes
    // -----------------------------------------------------------------------

    #[test]
    fn concurrent_handshakes() {
        crate::common::run_test(|| async {
            let acceptor = make_acceptor();
            let connector = make_connector();

            let mut handles = Vec::new();
            for i in 0..5u16 {
                let a = acceptor.clone();
                let c = connector.clone();
                let base = 6200 + i * 10;
                handles.push(async move {
                    let (client_io, server_io) = make_pair(base);
                    let (client_res, server_res) =
                        zip(c.connect("localhost", client_io), a.accept(server_io)).await;
                    assert!(client_res.is_ok(), "handshake {i} client failed");
                    assert!(server_res.is_ok(), "handshake {i} server failed");
                });
            }

            // Run all concurrently
            for h in handles {
                h.await;
            }
        });
    }
}

// Tests that work without the tls feature flag
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

#[cfg(not(feature = "tls"))]
mod tls_disabled_tests {
    use asupersync::tls::{TlsConnector, TlsConnectorBuilder, TlsError};

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
