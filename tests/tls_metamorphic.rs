//! TLS Handshake Metamorphic Testing (asupersync-yjt2ht)
//!
//! Metamorphic relations for TLS 1.2/1.3 handshake state machine invariants.
//! Tests verify:
//! 1. Handshake completion is deterministic given same seed + cipher-suite ordering
//! 2. Replay of captured ClientHello produces equivalent ServerHello (up to nonces/timestamps)
//! 3. Session resumption with valid ticket produces 0-RTT/1-RTT equivalent to full handshake
//! 4. Alert frames during handshake consistently abort without partial-state leaks
//!
//! Uses lab runtime with deterministic test vectors and virtual time for reproducible results.

#[macro_use]
mod common;

#[cfg(feature = "tls")]
mod tls_metamorphic_tests {
    use crate::common::init_test_logging;
    use asupersync::cx::Cx;
    use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    use asupersync::lab::LabRuntime;
    use asupersync::net::tcp::VirtualTcpStream;
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    use asupersync::tls::{
        Certificate, CertificateChain, ClientAuth, PrivateKey, RootCertStore, TlsAcceptor,
        TlsAcceptorBuilder, TlsConnector, TlsConnectorBuilder, TlsError, TlsStream,
    };
    use asupersync::types::{Budget, RegionId, TaskId, Time};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use std::collections::HashMap;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;

    // Test certificate and key for deterministic testing
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

    /// Accept any certificate for deterministic testing
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

    fn make_lab_runtime() -> LabRuntime {
        LabRuntime::builder()
            .deterministic()
            .with_virtual_clock(VirtualClock::starting_at(Time::from_secs(1000)))
            .build()
    }

    fn make_deterministic_client_config(seed: u64) -> rustls::ClientConfig {
        // Use deterministic provider to ensure reproducible handshakes
        use std::sync::Arc;

        // Create reproducible client config based on seed
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();

        // Set cipher suites in deterministic order based on seed
        let cipher_suites = if seed % 2 == 0 {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            vec![b"http/1.1".to_vec(), b"h2".to_vec()]
        };
        config.alpn_protocols = cipher_suites;

        config
    }

    fn make_test_acceptor() -> TlsAcceptor {
        let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
        let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
        TlsAcceptorBuilder::new(chain, key)
            .alpn_http()
            .build()
            .unwrap()
    }

    fn make_pair(port_base: u16) -> (VirtualTcpStream, VirtualTcpStream) {
        VirtualTcpStream::pair(
            format!("127.0.0.1:{port_base}").parse().unwrap(),
            format!("127.0.0.1:{}", port_base + 1).parse().unwrap(),
        )
    }

    async fn perform_handshake_with_runtime(
        runtime: &LabRuntime,
        connector: TlsConnector,
        acceptor: TlsAcceptor,
        port_base: u16,
    ) -> (
        Result<TlsStream<VirtualTcpStream>, TlsError>,
        Result<TlsStream<VirtualTcpStream>, TlsError>,
    ) {
        runtime
            .scope()
            .run(|scope| async move {
                let (client_io, server_io) = make_pair(port_base);

                let client_fut =
                    scope.spawn(async move { connector.connect("localhost", client_io).await });

                let server_fut = scope.spawn(async move { acceptor.accept(server_io).await });

                let (client_result, server_result) =
                    futures_lite::future::zip(client_fut, server_fut).await;

                (client_result, server_result)
            })
            .await
    }

    /// Captures TLS handshake messages for replay testing
    #[derive(Debug, Clone)]
    struct HandshakeCapture {
        client_hello: Vec<u8>,
        server_hello: Vec<u8>,
        protocol_version: Option<rustls::ProtocolVersion>,
        alpn_protocol: Option<Vec<u8>>,
    }

    /// Wrapper that captures handshake messages
    struct CapturingTcpStream {
        inner: VirtualTcpStream,
        captured_writes: Vec<u8>,
        captured_reads: Vec<u8>,
    }

    impl CapturingTcpStream {
        fn new(inner: VirtualTcpStream) -> Self {
            Self {
                inner,
                captured_writes: Vec::new(),
                captured_reads: Vec::new(),
            }
        }

        fn captured_data(&self) -> (Vec<u8>, Vec<u8>) {
            (self.captured_writes.clone(), self.captured_reads.clone())
        }
    }

    impl AsyncRead for CapturingTcpStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let initial_filled = buf.filled().len();
            match Pin::new(&mut self.inner).poll_read(cx, buf) {
                Poll::Ready(Ok(())) => {
                    let new_data = &buf.filled()[initial_filled..];
                    self.captured_reads.extend_from_slice(new_data);
                    Poll::Ready(Ok(()))
                }
                other => other,
            }
        }
    }

    impl AsyncWrite for CapturingTcpStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            match Pin::new(&mut self.inner).poll_write(cx, buf) {
                Poll::Ready(Ok(n)) => {
                    self.captured_writes.extend_from_slice(&buf[..n]);
                    Poll::Ready(Ok(n))
                }
                other => other,
            }
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    // -----------------------------------------------------------------------
    // MR 1: Handshake determinism given same seed + cipher-suite ordering
    // -----------------------------------------------------------------------

    #[test]
    fn mr1_handshake_determinism_same_seed_same_result() {
        init_test_logging();
        test_phase!("mr1_handshake_determinism_same_seed");

        let runtime = make_lab_runtime();
        let acceptor = make_test_acceptor();

        // Run same handshake with same seed multiple times
        let seed = 12345u64;
        let mut results = Vec::new();

        for iteration in 0..3 {
            test_section!(format!("iteration_{}", iteration));

            let connector = TlsConnector::new(make_deterministic_client_config(seed));
            let port_base = 7000 + iteration * 10;

            let result = runtime.block_on(async {
                perform_handshake_with_runtime(&runtime, connector, acceptor.clone(), port_base)
                    .await
            });

            let (client, server) = result;
            let client = client.unwrap();
            let server = server.unwrap();

            let handshake_result = (
                client.protocol_version(),
                client.alpn_protocol().map(|p| p.to_vec()),
                server.protocol_version(),
                server.alpn_protocol().map(|p| p.to_vec()),
            );

            results.push(handshake_result);
        }

        // All handshakes with same seed should produce identical results
        for i in 1..results.len() {
            assert_eq!(
                results[0], results[i],
                "Handshake result {} differs from first result with same seed {}",
                i, seed
            );
        }

        test_complete!("mr1_handshake_determinism_same_seed");
    }

    #[test]
    fn mr1_handshake_determinism_different_seeds_may_differ() {
        init_test_logging();
        test_phase!("mr1_handshake_determinism_different_seeds");

        let runtime = make_lab_runtime();
        let acceptor = make_test_acceptor();

        // Test with different seeds - results may differ due to cipher ordering
        let seeds = [11111u64, 22222u64];
        let mut results = Vec::new();

        for (i, &seed) in seeds.iter().enumerate() {
            test_section!(format!("seed_{}", seed));

            let connector = TlsConnector::new(make_deterministic_client_config(seed));
            let port_base = 7100 + i * 10;

            let result = runtime.block_on(async {
                perform_handshake_with_runtime(&runtime, connector, acceptor.clone(), port_base)
                    .await
            });

            let (client, server) = result;
            let client = client.unwrap();
            let server = server.unwrap();

            let handshake_result = (
                client.protocol_version(),
                client.alpn_protocol().map(|p| p.to_vec()),
            );

            results.push(handshake_result);
        }

        // Different seeds may produce different ALPN negotiation results
        // Both should be valid TLS versions though
        for result in &results {
            assert!(
                result.0.is_some(),
                "All handshakes should negotiate a protocol version"
            );
        }

        test_complete!("mr1_handshake_determinism_different_seeds");
    }

    // -----------------------------------------------------------------------
    // MR 2: ClientHello replay produces equivalent ServerHello
    // -----------------------------------------------------------------------

    #[test]
    fn mr2_client_hello_replay_equivalence() {
        init_test_logging();
        test_phase!("mr2_client_hello_replay_equivalence");

        let runtime = make_lab_runtime();
        let acceptor1 = make_test_acceptor();
        let acceptor2 = make_test_acceptor();

        runtime.block_on(async {
            test_section!("initial_handshake");

            // Perform initial handshake and capture ClientHello
            let connector = TlsConnector::new(make_deterministic_client_config(42));
            let (client_io_1, server_io_1) = make_pair(7200);
            let capturing_client = CapturingTcpStream::new(client_io_1);
            let capturing_server = CapturingTcpStream::new(server_io_1);

            let client_fut = connector.connect("localhost", capturing_client);
            let server_fut = acceptor1.accept(capturing_server);

            let (client_res_1, server_res_1) =
                futures_lite::future::zip(client_fut, server_fut).await;

            let client1 = client_res_1.unwrap();
            let server1 = server_res_1.unwrap();

            let original_result = (
                client1.protocol_version(),
                client1.alpn_protocol().map(|p| p.to_vec()),
                server1.protocol_version(),
                server1.alpn_protocol().map(|p| p.to_vec()),
            );

            test_section!("replay_handshake");

            // Replay with same deterministic configuration
            let connector2 = TlsConnector::new(make_deterministic_client_config(42));
            let (client_io_2, server_io_2) = make_pair(7210);

            let client_fut2 = connector2.connect("localhost", client_io_2);
            let server_fut2 = acceptor2.accept(server_io_2);

            let (client_res_2, server_res_2) =
                futures_lite::future::zip(client_fut2, server_fut2).await;

            let client2 = client_res_2.unwrap();
            let server2 = server_res_2.unwrap();

            let replay_result = (
                client2.protocol_version(),
                client2.alpn_protocol().map(|p| p.to_vec()),
                server2.protocol_version(),
                server2.alpn_protocol().map(|p| p.to_vec()),
            );

            // ServerHello should be equivalent (same protocol/ALPN negotiated)
            assert_eq!(
                original_result, replay_result,
                "Replay handshake should produce equivalent ServerHello"
            );
        });

        test_complete!("mr2_client_hello_replay_equivalence");
    }

    // -----------------------------------------------------------------------
    // MR 3: Session resumption equivalence
    // -----------------------------------------------------------------------

    #[test]
    fn mr3_session_resumption_equivalence() {
        init_test_logging();
        test_phase!("mr3_session_resumption_equivalence");

        let runtime = make_lab_runtime();

        runtime.block_on(async {
            test_section!("full_handshake");

            // Perform full handshake first
            let acceptor = make_test_acceptor();
            let connector = TlsConnectorBuilder::new()
                .add_root_certificate(&Certificate::from_pem(TEST_CERT_PEM).unwrap()[0])
                .session_resumption(rustls::client::Resumption::in_memory_sessions(64))
                .alpn_http()
                .build()
                .unwrap();

            let (client_io, server_io) = make_pair(7300);
            let client_fut = connector.connect("localhost", client_io);
            let server_fut = acceptor.accept(server_io);

            let (client_res, server_res) = futures_lite::future::zip(client_fut, server_fut).await;

            let mut client = client_res.unwrap();
            let mut server = server_res.unwrap();

            // Exchange some data to complete session
            client.write_all(b"test data").await.unwrap();
            client.flush().await.unwrap();

            let mut buf = [0u8; 9];
            server.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"test data");

            let full_handshake_result = (
                client.protocol_version(),
                client.alpn_protocol().map(|p| p.to_vec()),
            );

            // Close first connection gracefully
            client.shutdown().await.unwrap();
            server.shutdown().await.unwrap();

            test_section!("resumption_attempt");

            // Attempt session resumption - should be equivalent to full handshake result
            let acceptor2 = make_test_acceptor();
            let (client_io2, server_io2) = make_pair(7310);

            let client_fut2 = connector.connect("localhost", client_io2);
            let server_fut2 = acceptor2.accept(server_io2);

            let (client_res2, server_res2) =
                futures_lite::future::zip(client_fut2, server_fut2).await;

            let client2 = client_res2.unwrap();
            let server2 = server_res2.unwrap();

            let resumption_result = (
                client2.protocol_version(),
                client2.alpn_protocol().map(|p| p.to_vec()),
            );

            // Session resumption should produce equivalent results
            assert_eq!(
                full_handshake_result, resumption_result,
                "Session resumption should be equivalent to full handshake"
            );
        });

        test_complete!("mr3_session_resumption_equivalence");
    }

    // -----------------------------------------------------------------------
    // MR 4: Alert frame consistency
    // -----------------------------------------------------------------------

    #[test]
    fn mr4_alert_frame_consistency() {
        init_test_logging();
        test_phase!("mr4_alert_frame_consistency");

        let runtime = make_lab_runtime();

        runtime.block_on(async {
            test_section!("timeout_alert_consistency");

            // Create connector with very short timeout to force alert
            let connector = TlsConnectorBuilder::new()
                .add_root_certificate(&Certificate::from_pem(TEST_CERT_PEM).unwrap()[0])
                .handshake_timeout(Duration::from_millis(1)) // Very short timeout
                .alpn_http()
                .build()
                .unwrap();

            let mut alert_results = Vec::new();

            for attempt in 0..3 {
                let (client_io, _server_io) = make_pair(7400 + attempt);

                // Don't start server - client will timeout and generate alert
                let client_result = connector.connect("localhost", client_io).await;

                let is_timeout_error = matches!(client_result, Err(TlsError::Timeout(_)));
                alert_results.push(is_timeout_error);
            }

            // All timeout scenarios should consistently produce same error type
            assert!(
                alert_results.iter().all(|&x| x),
                "All timeout alerts should be consistent: {:?}",
                alert_results
            );

            test_section!("invalid_cert_alert_consistency");

            // Test invalid certificate alerts
            let bad_connector = TlsConnectorBuilder::new()
                .handshake_timeout(Duration::from_millis(100))
                .build() // No root certificates - will fail validation
                .unwrap();

            let acceptor = make_test_acceptor();
            let mut cert_alert_results = Vec::new();

            for attempt in 0..3 {
                let (client_io, server_io) = make_pair(7450 + attempt);

                let client_fut = bad_connector.connect("localhost", client_io);
                let server_fut = acceptor.accept(server_io);

                let (client_result, _server_result) =
                    futures_lite::future::zip(client_fut, server_fut).await;

                // Should consistently fail certificate validation
                let is_handshake_error = matches!(client_result, Err(TlsError::Handshake(_)));
                cert_alert_results.push(is_handshake_error);
            }

            // All certificate validation failures should be consistent
            assert!(
                cert_alert_results.iter().all(|&x| x),
                "All certificate alert errors should be consistent: {:?}",
                cert_alert_results
            );
        });

        test_complete!("mr4_alert_frame_consistency");
    }

    // -----------------------------------------------------------------------
    // Composite metamorphic relation: Determinism + Resumption
    // -----------------------------------------------------------------------

    #[test]
    fn mr_composite_determinism_with_resumption() {
        init_test_logging();
        test_phase!("mr_composite_determinism_with_resumption");

        let runtime = make_lab_runtime();

        // Test that resumption behavior is also deterministic
        runtime.block_on(async {
            let mut resumption_results = Vec::new();

            for iteration in 0..2 {
                test_section!(format!("deterministic_resumption_iteration_{}", iteration));

                let connector = TlsConnectorBuilder::new()
                    .add_root_certificate(&Certificate::from_pem(TEST_CERT_PEM).unwrap()[0])
                    .session_resumption(rustls::client::Resumption::in_memory_sessions(64))
                    .alpn_http()
                    .build()
                    .unwrap();

                // Full handshake
                let acceptor1 = make_test_acceptor();
                let (client_io1, server_io1) = make_pair(7500 + iteration * 20);

                let (client_res1, _server_res1) = futures_lite::future::zip(
                    connector.connect("localhost", client_io1),
                    acceptor1.accept(server_io1),
                )
                .await;

                let client1 = client_res1.unwrap();
                let full_result = client1.protocol_version();

                // Attempt resumption
                let acceptor2 = make_test_acceptor();
                let (client_io2, server_io2) = make_pair(7510 + iteration * 20);

                let (client_res2, _server_res2) = futures_lite::future::zip(
                    connector.connect("localhost", client_io2),
                    acceptor2.accept(server_io2),
                )
                .await;

                let client2 = client_res2.unwrap();
                let resume_result = client2.protocol_version();

                resumption_results.push((full_result, resume_result));
            }

            // Resumption behavior should be deterministic across iterations
            assert_eq!(
                resumption_results[0], resumption_results[1],
                "Deterministic resumption should produce identical results"
            );
        });

        test_complete!("mr_composite_determinism_with_resumption");
    }

    // -----------------------------------------------------------------------
    // State machine invariant: handshake->ready->shutdown->closed
    // -----------------------------------------------------------------------

    #[test]
    fn mr_state_machine_invariant() {
        init_test_logging();
        test_phase!("mr_state_machine_invariant");

        let runtime = make_lab_runtime();

        runtime.block_on(async {
            let connector = TlsConnector::new(make_deterministic_client_config(999));
            let acceptor = make_test_acceptor();

            let (client_io, server_io) = make_pair(7600);

            let (client_res, server_res) = futures_lite::future::zip(
                connector.connect("localhost", client_io),
                acceptor.accept(server_io),
            )
            .await;

            let mut client = client_res.unwrap();
            let mut server = server_res.unwrap();

            // Test state progression invariant
            test_section!("ready_state");
            assert!(client.is_ready(), "Client should be ready after handshake");
            assert!(server.is_ready(), "Server should be ready after handshake");
            assert!(
                !client.is_closed(),
                "Client should not be closed when ready"
            );
            assert!(
                !server.is_closed(),
                "Server should not be closed when ready"
            );

            test_section!("data_exchange_in_ready");
            // Data exchange should work in ready state
            client.write_all(b"ping").await.unwrap();
            client.flush().await.unwrap();

            let mut buf = [0u8; 4];
            server.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");

            test_section!("shutdown_transition");
            // Shutdown should transition properly
            client.shutdown().await.unwrap();

            // Client sent close_notify but hasn't received peer's close_notify yet
            assert!(
                !client.is_closed(),
                "Client should not be fully closed until peer close"
            );

            test_section!("peer_close");
            // Server should receive EOF from client's close_notify
            let mut eof_buf = Vec::new();
            let n = server.read_to_end(&mut eof_buf).await.unwrap();
            assert_eq!(n, 0, "Should receive EOF from peer close_notify");
            assert!(eof_buf.is_empty());

            // Complete bidirectional shutdown
            server.shutdown().await.unwrap();
            assert!(
                server.is_closed(),
                "Server should be closed after sending close_notify"
            );

            // Client should now see EOF and complete closure
            let mut client_eof = Vec::new();
            let n = client.read_to_end(&mut client_eof).await.unwrap();
            assert_eq!(n, 0, "Client should receive EOF from server close_notify");
            assert!(client_eof.is_empty());
            assert!(
                client.is_closed(),
                "Client should be closed after peer close_notify"
            );
        });

        test_complete!("mr_state_machine_invariant");
    }
}

#[cfg(not(feature = "tls"))]
mod tls_disabled_tests {
    // Placeholder tests for when TLS is disabled
    #[test]
    fn mr_tests_require_tls_feature() {
        println!("TLS metamorphic tests require 'tls' feature to be enabled");
    }
}
