    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    #[cfg(feature = "tls")]
    use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
    #[cfg(feature = "tls")]
    use crate::net::tcp::VirtualTcpStream;
    #[cfg(feature = "tls")]
    use crate::test_utils::init_test_logging;
    #[cfg(feature = "tls")]
    use crate::tls::{
        Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder, TlsConnectorBuilder,
    };
    #[cfg(feature = "tls")]
    use futures_lite::future::{poll_fn, zip};
    #[cfg(feature = "tls")]
    use rustls::ClientConnection;
    #[cfg(feature = "tls")]
    use rustls::ServerConnection;
    #[cfg(feature = "tls")]
    use rustls::pki_types::ServerName;
    #[cfg(feature = "tls")]
    use std::sync::Arc;

    #[cfg(feature = "tls")]
    const TEST_CERT_PEM: &[u8] = include_bytes!("../../tests/fixtures/tls/server.crt");
    #[cfg(feature = "tls")]
    const TEST_KEY_PEM: &[u8] = include_bytes!("../../tests/fixtures/tls/server.key");

    #[test]
    fn test_tls_state_transitions() {
        assert_ne!(TlsState::Handshaking, TlsState::Ready);
        assert_ne!(TlsState::Ready, TlsState::ShuttingDown);
        assert_ne!(TlsState::ShuttingDown, TlsState::Closed);
    }

    #[test]
    fn tls_state_lifecycle_classifiers_are_exclusive() {
        let cases = [
            (TlsState::Handshaking, true, false, false, false),
            (TlsState::Ready, false, true, false, false),
            (TlsState::ShuttingDown, false, false, true, false),
            (TlsState::Closed, false, false, false, true),
        ];

        for (state, requires_handshake, allows_io, shutdown_pending, terminal) in cases {
            assert_eq!(state.requires_handshake(), requires_handshake);
            assert_eq!(state.allows_application_io(), allows_io);
            assert_eq!(state.shutdown_pending(), shutdown_pending);
            assert_eq!(state.is_terminal(), terminal);
        }
    }

    #[test]
    fn tls_state_exhaustive_inequality() {
        let states = [
            TlsState::Handshaking,
            TlsState::Ready,
            TlsState::ShuttingDown,
            TlsState::Closed,
        ];
        for (i, a) in states.iter().enumerate() {
            for (j, b) in states.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn tls_state_debug() {
        assert_eq!(format!("{:?}", TlsState::Handshaking), "Handshaking");
        assert_eq!(format!("{:?}", TlsState::Ready), "Ready");
        assert_eq!(format!("{:?}", TlsState::ShuttingDown), "ShuttingDown");
        assert_eq!(format!("{:?}", TlsState::Closed), "Closed");
    }

    #[test]
    fn tls_state_clone_and_copy() {
        let state = TlsState::Ready;
        let copied = state; // Copy
        let cloned = state; // Clone
        assert_eq!(state, copied);
        assert_eq!(state, cloned);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_stream_handshake_completes_under_lab_runtime() {
        init_test_logging();
        let config = TestConfig::new()
            .with_seed(0x715A_CCE8)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let (
            client_state_ready,
            server_state_ready,
            client_protocol,
            server_protocol,
            client_alpn,
            server_alpn,
            checkpoints,
        ) = LabRuntimeTarget::block_on(&mut runtime, async move {
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

            let server_name = ServerName::try_from("localhost".to_string()).unwrap();
            let client_conn =
                ClientConnection::new(Arc::clone(connector.config()), server_name).unwrap();
            let server_conn = ServerConnection::new(Arc::clone(acceptor.config())).unwrap();

            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5200".parse().unwrap(),
                "127.0.0.1:5201".parse().unwrap(),
            );

            let mut client_stream = TlsStream::new_client(client_io, client_conn);
            let mut server_stream = TlsStream::new_server(server_io, server_conn);

            let checkpoints = vec![serde_json::json!({
                "phase": "tls_stream_handshake_started",
                "client_state": format!("{:?}", client_stream.state),
                "server_state": format!("{:?}", server_stream.state),
                "client_addr": "127.0.0.1:5200",
                "server_addr": "127.0.0.1:5201",
            })];
            for checkpoint in &checkpoints {
                tracing::info!(event = %checkpoint, "tls_stream_lab_checkpoint");
            }

            let (client_result, server_result) = zip(
                poll_fn(|cx| client_stream.poll_handshake(cx)),
                poll_fn(|cx| server_stream.poll_handshake(cx)),
            )
            .await;
            client_result.expect("client handshake should succeed");
            server_result.expect("server handshake should succeed");

            let client_state_ready =
                client_stream.state == TlsState::Ready && client_stream.is_ready();
            let server_state_ready =
                server_stream.state == TlsState::Ready && server_stream.is_ready();
            let client_protocol = client_stream.protocol_version().is_some();
            let server_protocol = server_stream.protocol_version().is_some();
            let client_alpn = client_stream
                .alpn_protocol()
                .map(|protocol| protocol.to_vec());
            let server_alpn = server_stream
                .alpn_protocol()
                .map(|protocol| protocol.to_vec());

            let mut checkpoints = checkpoints;
            checkpoints.push(serde_json::json!({
                "phase": "tls_stream_handshake_completed",
                "client_state": format!("{:?}", client_stream.state),
                "server_state": format!("{:?}", server_stream.state),
                "client_protocol_present": client_protocol,
                "server_protocol_present": server_protocol,
                "client_alpn": client_alpn.as_ref().map(|protocol| String::from_utf8_lossy(protocol).to_string()),
                "server_alpn": server_alpn.as_ref().map(|protocol| String::from_utf8_lossy(protocol).to_string()),
            }));
            tracing::info!(event = %checkpoints[1], "tls_stream_lab_checkpoint");

            (
                client_state_ready,
                server_state_ready,
                client_protocol,
                server_protocol,
                client_alpn,
                server_alpn,
                checkpoints,
            )
        });

        assert!(client_state_ready);
        assert!(server_state_ready);
        assert!(client_protocol);
        assert!(server_protocol);
        assert_eq!(client_alpn.as_deref(), Some(b"h2".as_slice()));
        assert_eq!(server_alpn.as_deref(), Some(b"h2".as_slice()));
        assert_eq!(checkpoints.len(), 2);
        assert!(runtime.is_quiescent());
    }

    /// br-asupersync-2dxusr item 4: after the peer's transport closed without
    /// close_notify, the first read failed with UnexpectedEof but the next
    /// one returned a clean end of file, so a caller that read again took a
    /// truncated stream for a complete one.
    #[cfg(feature = "tls")]
    #[test]
    fn a_truncated_stream_keeps_failing_instead_of_reporting_a_clean_eof() {
        let config = TestConfig::new()
            .with_seed(0x2D_C504)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);
        let (first, second) = LabRuntimeTarget::block_on(&mut runtime, async move {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key).build().unwrap();
            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .build()
                .unwrap();
            let server_name = ServerName::try_from("localhost".to_string()).unwrap();
            let client_conn =
                ClientConnection::new(Arc::clone(connector.config()), server_name).unwrap();
            let server_conn = ServerConnection::new(Arc::clone(acceptor.config())).unwrap();
            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5300".parse().unwrap(),
                "127.0.0.1:5301".parse().unwrap(),
            );
            let mut client = TlsStream::new_client(client_io, client_conn);
            let mut server = TlsStream::new_server(server_io, server_conn);
            let (client_result, server_result) = zip(
                poll_fn(|cx| client.poll_handshake(cx)),
                poll_fn(|cx| server.poll_handshake(cx)),
            )
            .await;
            client_result.expect("client handshake should succeed");
            server_result.expect("server handshake should succeed");

            // The server's transport closes without a close_notify.
            drop(server);
            let first = read_once(&mut client).await;
            let second = read_once(&mut client).await;
            (first, second)
        });

        async fn read_once(
            stream: &mut TlsStream<VirtualTcpStream>,
        ) -> Result<usize, io::ErrorKind> {
            let mut bytes = [0_u8; 64];
            poll_fn(|cx| {
                let mut buf = ReadBuf::new(&mut bytes);
                Pin::new(&mut *stream)
                    .poll_read(cx, &mut buf)
                    .map(|result| result.map(|()| buf.filled().len()))
            })
            .await
            .map_err(|err| err.kind())
        }

        assert_eq!(first, Err(io::ErrorKind::UnexpectedEof));
        assert_eq!(
            second,
            Err(io::ErrorKind::UnexpectedEof),
            "a second read reported a clean end of file"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn handshake_failure_sends_its_alert_instead_of_a_bare_close() {
        init_test_logging();
        let config = TestConfig::new()
            .with_seed(0xA1E7_0001)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let (client_error, server_error) = LabRuntimeTarget::block_on(&mut runtime, async move {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            // The server speaks only h2 and the client offers only an unknown
            // protocol, so rustls refuses the ClientHello with a
            // no_application_protocol alert while the server is handshaking.
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .alpn_protocols(vec![b"h2".to_vec()])
                .build()
                .unwrap();
            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_protocols(vec![b"x-unknown".to_vec()])
                .build()
                .unwrap();

            let server_name = ServerName::try_from("localhost".to_string()).unwrap();
            let client_conn =
                ClientConnection::new(Arc::clone(connector.config()), server_name).unwrap();
            let server_conn = ServerConnection::new(Arc::clone(acceptor.config())).unwrap();
            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5210".parse().unwrap(),
                "127.0.0.1:5211".parse().unwrap(),
            );
            let mut client_stream = TlsStream::new_client(client_io, client_conn);
            let mut server_stream = TlsStream::new_server(server_io, server_conn);
            let server = async move {
                let result = poll_fn(|cx| server_stream.poll_handshake(cx)).await;
                // An acceptor closes right after a failed handshake, so only
                // bytes already written can reach the client.
                drop(server_stream);
                result
            };
            let (client_result, server_result) =
                zip(poll_fn(|cx| client_stream.poll_handshake(cx)), server).await;
            (
                client_result.expect_err("the client handshake must fail"),
                server_result.expect_err("the server refuses the ALPN offer"),
            )
        });

        let client_error = client_error.to_string();
        tracing::info!(%client_error, server_error = %server_error, "tls_alert_delivery");
        assert!(
            client_error.contains("received fatal alert"),
            "the client must learn why the server refused, not see a bare close: {client_error}"
        );
        assert!(runtime.is_quiescent());
    }

    /// Public parser fixture from rustls-pemfile 2.2.0 tests/data/crl.pem
    /// (Apache-2.0 / ISC / MIT), issued by "ponytown RSA CA", which did not
    /// issue the test certificate.
    #[cfg(feature = "tls")]
    const OTHER_ISSUER_CRL_PEM: &[u8] = b"-----BEGIN X509 CRL-----\n\
MIICiTBzAgEBMA0GCSqGSIb3DQEBCwUAMBoxGDAWBgNVBAMMD3Bvbnl0b3duIFJT\n\
QSBDQRcNMjMwNjI3MDgyODEyWhcNMjMwNzI3MDgyODEyWjAVMBMCAgHIFw0yMzA2\n\
MjcwODI3NTlaoA4wDDAKBgNVHRQEAwIBAjANBgkqhkiG9w0BAQsFAAOCAgEAP6EX\n\
9+hxjx/AqdBpynZXjGkEqigBcLcJ2PADOXngdQI1jC0WuYnZymUimemeULtt8X+1\n\
ai2KxAuF1m4NEKZsrGKvO+/9s/X1xbGroyHSAMKtZafFopFpoB2aNbYlx7yIyLtD\n\
BBIZIF50g20U+3izqpHutTD10itdk9TLsSceJHpwTkNJtaWMkOfBV28nKzEzVutV\n\
f6WzRpURGzui6nQy7aIqImeanpoBoz323psMfC32U0uMBCZltyHNqsX58/2Uhucx\n\
0IPnitNuhv4scCPf/jeRfGIWDrTf1/25LDzRxyg1S4z9aa+3GM4O3dqy4igZEhgT\n\
q3pjlJ2hUL5E0oqbZDIQD1SN8UUUv5N2AjwZcxVBNnYeGyuO7YpTBYiu62o73iL2\n\
CjgElfaMq/9hEr9GR9kJozh7VTxtQPbnr4DiucQvhv8o/A1z+zkC0gj8iCLFtDbO\n\
8bvDowcdle9LKkrLaBe6sO+fSH/I9Wj8vrEJKsuwaEraIdEaq2VrIMUPEWN0/MH9\n\
vTwHyadGSMK4CWtrn9fCAgSLw6NX74D7Cx1IaS8vstMjpeUqOS0dk5ThiW47HceB\n\
DTko7rV5N+RGH2nW1ynLoZKCJQqqZcLilFMyKPui3jifJnQlMFi54jGVgg/D6UQn\n\
7dA7wb2ux/1hSiaarp+mi7ncVOyByz6/WQP8mfc=\n\
-----END X509 CRL-----\n";

    /// A CRL from the self-signed test certificate's own key that revokes
    /// that certificate (serial 319CCC27...6C4B), next update 2126. Made with
    /// `openssl ca -gencrl -keyfile server.key -cert server.crt` from an
    /// index.txt holding one revoked entry for that serial.
    #[cfg(feature = "tls")]
    const TEST_CERT_REVOKED_CRL_PEM: &[u8] = b"-----BEGIN X509 CRL-----\n\
MIIB3TCBxgIBATANBgkqhkiG9w0BAQsFADBZMQswCQYDVQQGEwJVUzENMAsGA1UE\n\
CAwEVGVzdDENMAsGA1UEBwwEVGVzdDEYMBYGA1UECgwPQXN1cGVyU3luYyBUZXN0\n\
MRIwEAYDVQQDDAlsb2NhbGhvc3QXDTI2MTAwMzA0MTUwM1oYDzIxMjYwOTA5MDQx\n\
NTAzWjAnMCUCFDGczCdzSv8IrxFdAMI2QzZLLGxLFw0yNjEwMDMwMDAwMDBaoA4w\n\
DDAKBgNVHRQEAwIBATANBgkqhkiG9w0BAQsFAAOCAQEAczvy8Gclb2L+egBA3XVH\n\
iEb9PUNXFIm0BdsaN0dEpaQ+x1TTzIqrjcIuPWJjum0v5mmgeWXJyVHtJUrWB5B1\n\
bXyCqElzV/hKSqJLhGKUwhWOIZLd5kWOPGmSoO291xbsOcaDEG4DsOhobduBjP/z\n\
mj+NAAVGjaJKuGdbrzT1NVH6qkW4G0n+ZOuZf5CH3E90H0Bu+6lcJpYPpNGSFY0f\n\
4ZR9OkSx0eA+5EF7ThORH1LUGGbGpz5mLM6PSLN0571E3/pO7djtbceRr0rASxGG\n\
A4sj3J3HjUEnUUo0RKuVI+krlZN2dhvYvdazj/6Bcp05YiMVCJpGuoNADgg6KxKY\n\
jg==\n\
-----END X509 CRL-----\n";

    /// Handshakes against the test certificate with `crl_pem` configured on
    /// the client, and returns the client's and the server's results.
    #[cfg(feature = "tls")]
    fn handshake_with_client_crl(
        seed: u64,
        crl_pem: &'static [u8],
    ) -> (Result<(), TlsError>, Result<(), TlsError>) {
        let config = TestConfig::new().with_seed(seed).with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);
        let results = LabRuntimeTarget::block_on(&mut runtime, async move {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key).build().unwrap();
            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .with_crl_pem(crl_pem)
                .build()
                .unwrap();

            let server_name = ServerName::try_from("localhost".to_string()).unwrap();
            let client_conn =
                ClientConnection::new(Arc::clone(connector.config()), server_name).unwrap();
            let server_conn = ServerConnection::new(Arc::clone(acceptor.config())).unwrap();
            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5220".parse().unwrap(),
                "127.0.0.1:5221".parse().unwrap(),
            );
            let mut client_stream = TlsStream::new_client(client_io, client_conn);
            let mut server_stream = TlsStream::new_server(server_io, server_conn);
            // Both streams stay open until both handshakes return: a TLS 1.3
            // server writes its session tickets after the client's Finished,
            // and a client that had already closed would fail that write.
            let client = async move {
                let result = poll_fn(|cx| client_stream.poll_handshake(cx)).await;
                (result, client_stream)
            };
            let server = async move {
                let result = poll_fn(|cx| server_stream.poll_handshake(cx)).await;
                (result, server_stream)
            };
            let ((client_result, client_stream), (server_result, server_stream)) =
                zip(client, server).await;
            drop((client_stream, server_stream));
            (client_result, server_result)
        });
        assert!(runtime.is_quiescent());
        results
    }

    #[cfg(feature = "tls")]
    #[test]
    fn a_crl_for_another_issuer_does_not_refuse_the_handshake() {
        init_test_logging();
        // A CRL covers only the certificates its issuer signed. Configuring
        // one CA's CRL must not refuse servers whose CA has none, or a CRL
        // for a private CA would break every public host.
        let (client, server) = handshake_with_client_crl(0xC41_0001, OTHER_ISSUER_CRL_PEM);
        tracing::info!(client = ?client, server = ?server, "tls_crl_other_issuer");
        client.expect("a certificate whose issuer has no CRL is accepted");
        server.expect("the server handshake completes");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn a_certificate_revoked_by_its_issuers_crl_is_refused() {
        init_test_logging();
        let (client, _server) = handshake_with_client_crl(0xC41_0002, TEST_CERT_REVOKED_CRL_PEM);
        let error = client
            .expect_err("a revoked certificate must be refused")
            .to_string();
        tracing::info!(%error, "tls_crl_revoked");
        assert!(
            error.contains("Revoked"),
            "the refusal must name the revocation: {error}"
        );
    }

    /// Reports `Pending` on its second write call, as a bounded transport
    /// does while its buffer is full, and wakes the task at once.
    #[cfg(feature = "tls")]
    struct StallsSecondWrite<IO> {
        inner: IO,
        writes: usize,
    }

    /// Holds written bytes until flushed, like a buffered writer.
    #[cfg(feature = "tls")]
    struct SendsOnFlush<IO> {
        inner: IO,
        held: Vec<u8>,
    }

    #[cfg(feature = "tls")]
    impl<IO: AsyncRead + Unpin> AsyncRead for StallsSecondWrite<IO> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    #[cfg(feature = "tls")]
    impl<IO: AsyncWrite + Unpin> AsyncWrite for StallsSecondWrite<IO> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes += 1;
            if self.writes == 2 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[cfg(feature = "tls")]
    impl<IO: AsyncRead + Unpin> AsyncRead for SendsOnFlush<IO> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    #[cfg(feature = "tls")]
    impl<IO: AsyncWrite + Unpin> AsyncWrite for SendsOnFlush<IO> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.held.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = &mut *self;
            while !this.held.is_empty() {
                match Pin::new(&mut this.inner).poll_write(cx, &this.held) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Poll::Ready(Ok(n)) => {
                        this.held.drain(..n);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            Pin::new(&mut this.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// Runs a client handshake over `wrap(client transport)` against a plain
    /// server, drops the client as soon as its handshake returns, and
    /// reports the client's result, whether TLS bytes were still unsent at
    /// that point, and the server's result.
    #[cfg(feature = "tls")]
    fn handshake_through<W>(
        seed: u64,
        wrap: impl FnOnce(VirtualTcpStream) -> W + Send + 'static,
    ) -> (Result<(), TlsError>, bool, Result<(), TlsError>)
    where
        W: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let config = TestConfig::new().with_seed(seed).with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);
        let (client, server) = LabRuntimeTarget::block_on(&mut runtime, async move {
            let chain = CertificateChain::from_pem(TEST_CERT_PEM).unwrap();
            let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain, key).build().unwrap();
            let certs = Certificate::from_pem(TEST_CERT_PEM).unwrap();
            let connector = TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .build()
                .unwrap();

            let server_name = ServerName::try_from("localhost".to_string()).unwrap();
            let client_conn =
                ClientConnection::new(Arc::clone(connector.config()), server_name).unwrap();
            let server_conn = ServerConnection::new(Arc::clone(acceptor.config())).unwrap();
            let (client_io, server_io) = VirtualTcpStream::pair(
                "127.0.0.1:5230".parse().unwrap(),
                "127.0.0.1:5231".parse().unwrap(),
            );
            let mut client_stream = TlsStream::new_client(wrap(client_io), client_conn);
            let mut server_stream = TlsStream::new_server(server_io, server_conn);
            let client = async move {
                let result = poll_fn(|cx| client_stream.poll_handshake(cx)).await;
                // A caller that only reads next would not send anything
                // more, so the server must get the whole flight on its own.
                let unsent = client_stream.conn.wants_write();
                (result, unsent, client_stream)
            };
            let server = async move {
                let result = poll_fn(|cx| server_stream.poll_handshake(cx)).await;
                (result, server_stream)
            };
            // The client stays open, writing nothing more, until the server
            // finishes: a flight left unsent leaves the server waiting, and
            // the lab then ends with "task did not complete".
            let ((client_result, unsent, client_stream), (server_result, server_stream)) =
                zip(client, server).await;
            drop((client_stream, server_stream));
            ((client_result, unsent), server_result)
        });
        assert!(runtime.is_quiescent());
        (client.0, client.1, server)
    }

    #[cfg(feature = "tls")]
    #[test]
    fn handshake_completes_only_after_its_final_flight_is_written() {
        init_test_logging();
        // The second write is the client's last flight (after the
        // ClientHello); the transport refuses it once.
        let (client, unsent, server) = handshake_through(0xF117_0001, |io| StallsSecondWrite {
            inner: io,
            writes: 0,
        });
        tracing::info!(client = ?client, unsent, server = ?server, "tls_final_flight");
        client.expect("the client handshake completes");
        assert!(
            !unsent,
            "the handshake reported done with its final flight unsent"
        );
        server.expect("the server receives the client's Finished");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn handshake_flushes_a_transport_that_holds_writes() {
        init_test_logging();
        let (client, unsent, server) = handshake_through(0xF117_0002, |io| SendsOnFlush {
            inner: io,
            held: Vec::new(),
        });
        tracing::info!(client = ?client, unsent, server = ?server, "tls_flush_transport");
        client.expect("the client handshake completes");
        assert!(!unsent);
        server.expect("the server handshake completes");
    }

    #[cfg(feature = "tls-ring")]
    #[test]
    fn backpressured_writes_drain_new_records_after_retry() {
        use rustls::{ClientConfig, ServerConfig};
        use std::task::Waker;

        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let config = TestConfig::new()
                .with_seed(0xBAC0_0001)
                .with_max_steps(20_000);
            let mut runtime = LabRuntimeTarget::create_runtime(config);
            LabRuntimeTarget::block_on(&mut runtime, async move {
                let chain = CertificateChain::from_pem(TEST_CERT_PEM)
                    .unwrap()
                    .into_inner();
                let key = PrivateKey::from_pem(TEST_KEY_PEM).unwrap();
                let mut roots = rustls::RootCertStore::empty();
                for cert in &chain {
                    roots.add(cert.clone()).unwrap();
                }
                let provider = Arc::new(rustls::crypto::ring::default_provider());
                let client_config = ClientConfig::builder_with_provider(Arc::clone(&provider))
                    .with_protocol_versions(&[version])
                    .unwrap()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let server_config = ServerConfig::builder_with_provider(provider)
                    .with_protocol_versions(&[version])
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(chain, key.clone_inner())
                    .unwrap();
                let client_conn = ClientConnection::new(
                    Arc::new(client_config),
                    ServerName::try_from("localhost").unwrap(),
                )
                .unwrap();
                let server_conn = ServerConnection::new(Arc::new(server_config)).unwrap();
                let (client_io, server_io) = VirtualTcpStream::pair(
                    "127.0.0.1:5240".parse().unwrap(),
                    "127.0.0.1:5241".parse().unwrap(),
                );
                let mut client = TlsStream::new_client(
                    StallsSecondWrite {
                        inner: client_io,
                        writes: 0,
                    },
                    client_conn,
                );
                let mut server = TlsStream::new_server(
                    StallsSecondWrite {
                        inner: server_io,
                        writes: 0,
                    },
                    server_conn,
                );
                let (client_result, server_result) = zip(
                    poll_fn(|cx| client.poll_handshake(cx)),
                    poll_fn(|cx| server.poll_handshake(cx)),
                )
                .await;
                client_result.expect("client handshake");
                server_result.expect("server handshake");
                assert_eq!(client.protocol_version(), Some(version.version));
                assert_eq!(server.protocol_version(), Some(version.version));

                for client_side in [true, false] {
                    let (sender, peer) = if client_side {
                        (&mut client, &mut server)
                    } else {
                        (&mut server, &mut client)
                    };
                    let binding = if version.version == rustls::ProtocolVersion::TLSv1_3 {
                        Some(sender.tls_exporter_channel_binding().unwrap())
                    } else {
                        None
                    };
                    match &mut sender.conn {
                        TlsConnection::Client(conn) => conn.set_buffer_limit(Some(64)),
                        TlsConnection::Server(conn) => conn.set_buffer_limit(Some(64)),
                    }
                    let prefix = [b'a'; 64];
                    let suffix = b"request completed after backpressure";
                    {
                        let mut cx = Context::from_waker(Waker::noop());
                        // Admit the prefix, but keep its encrypted record in
                        // rustls by stalling the next transport write.
                        sender.io.writes = 1;
                        assert!(matches!(
                            Pin::new(&mut *sender).poll_write(&mut cx, &prefix),
                            Poll::Ready(Ok(n)) if n == prefix.len()
                        ));
                        assert!(sender.conn.wants_write());
                        assert_eq!(sender.io.writes, 2);
                        // Witness the full buffer without consuming any probe
                        // bytes. The next public write must take the retry path.
                        assert_eq!(
                            io::Write::write(&mut sender.conn.writer(), b"capacity probe").unwrap(),
                            0
                        );
                        sender.io.writes = 1;
                        assert!(Pin::new(&mut *sender).poll_write(&mut cx, suffix).is_pending());
                        assert_eq!(sender.io.writes, 2);
                        assert!(sender.conn.wants_write());

                        // The transport now accepts writes. Do not issue a
                        // flush or another write after this successful retry.
                        assert!(matches!(
                            Pin::new(&mut *sender).poll_write(&mut cx, suffix),
                            Poll::Ready(Ok(n)) if n == suffix.len()
                        ));
                        assert!(
                            !sender.conn.wants_write(),
                            "retry left new encrypted records stranded on a writable transport"
                        );
                    }
                    let mut received = vec![0; prefix.len() + suffix.len()];
                    let mut offset = 0;
                    while offset < received.len() {
                        let n = poll_fn(|cx| {
                            let mut buf = ReadBuf::new(&mut received[offset..]);
                            Pin::new(&mut *peer)
                                .poll_read(cx, &mut buf)
                                .map(|result| result.map(|()| buf.filled().len()))
                        })
                        .await
                        .expect("peer receives both accepted chunks");
                        assert!(n > 0, "unexpected EOF before the accepted bytes arrived");
                        offset += n;
                    }
                    assert_eq!(&received[..prefix.len()], &prefix);
                    assert_eq!(&received[prefix.len()..], suffix);
                    {
                        let mut extra = [0; 1];
                        let mut buf = ReadBuf::new(&mut extra);
                        let mut cx = Context::from_waker(Waker::noop());
                        assert!(Pin::new(&mut *peer).poll_read(&mut cx, &mut buf).is_pending());
                        assert!(buf.filled().is_empty(), "a pending write duplicated plaintext");
                    }
                    if let Some(binding) = binding {
                        assert_eq!(sender.tls_exporter_channel_binding().unwrap(), binding);
                        assert_eq!(peer.tls_exporter_channel_binding().unwrap(), binding);
                    }
                }
            });
            assert!(runtime.is_quiescent());
        }
    }
