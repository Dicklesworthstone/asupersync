//! Channel binding closes at authenticated close_notify, not at buffer exhaustion.

#![allow(clippy::pedantic, clippy::nursery)]

use super::{TlsConnection, TlsError, TlsStream};
use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::net::tcp::VirtualTcpStream;
use crate::tls::{CertificateChain, PrivateKey};
use futures_lite::future::{poll_fn, zip};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

type Stream = TlsStream<VirtualTcpStream>;
const CERT: &[u8] = include_bytes!("../../tests/fixtures/tls/server.crt");
const KEY: &[u8] = include_bytes!("../../tests/fixtures/tls/server.key");

fn run_pair(
    version: &'static rustls::SupportedProtocolVersion,
    established: bool,
    test: impl FnOnce(Stream, Stream) + Send + 'static,
) {
    let mut runtime = LabRuntimeTarget::create_runtime(
        TestConfig::new().with_seed(0xC105_E001).with_max_steps(20_000),
    );
    LabRuntimeTarget::block_on(&mut runtime, async move {
        let chain = CertificateChain::from_pem(CERT).unwrap().into_inner();
        let key = PrivateKey::from_pem(KEY).unwrap().clone_inner();
        let mut roots = rustls::RootCertStore::empty();
        for cert in &chain {
            roots.add(cert.clone()).unwrap();
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cc = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let sc = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let (client_io, server_io) = VirtualTcpStream::pair(
            "127.0.0.1:5290".parse().unwrap(),
            "127.0.0.1:5291".parse().unwrap(),
        );
        let mut client = TlsStream::new_client(
            client_io,
            ClientConnection::new(Arc::new(cc), ServerName::try_from("localhost").unwrap())
                .unwrap(),
        );
        let mut server = TlsStream::new_server(
            server_io,
            ServerConnection::new(Arc::new(sc)).unwrap(),
        );
        if established {
            let (c, s) = zip(
                poll_fn(|cx| client.poll_handshake(cx)),
                poll_fn(|cx| server.poll_handshake(cx)),
            )
            .await;
            c.expect("client handshake");
            s.expect("server handshake");
            for stream in [&client, &server] {
                assert!(stream.is_ready());
                assert_eq!(stream.protocol_version(), Some(version.version));
            }
        }
        test(client, server);
    });
    assert!(runtime.is_quiescent());
}

fn live_bindings(stream: &Stream) -> (Option<[u8; 32]>, Option<Vec<u8>>) {
    let exporter = if stream.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3) {
        Some(stream.tls_exporter_channel_binding().unwrap())
    } else {
        assert!(matches!(
            stream.tls_exporter_channel_binding(),
            Err(TlsError::Configuration(_))
        ));
        None
    };
    let endpoint = if matches!(&stream.conn, TlsConnection::Client(_)) {
        Some(stream.tls_server_end_point_channel_binding().unwrap())
    } else {
        assert!(matches!(
            stream.tls_server_end_point_channel_binding(),
            Err(TlsError::Configuration(_))
        ));
        None
    };
    (exporter, endpoint)
}

fn assert_revoked(stream: &Stream) {
    for result in [
        stream.tls_exporter_channel_binding().map(|_| ()),
        stream.tls_server_end_point_channel_binding().map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(TlsError::Io(error)) if error.kind() == io::ErrorKind::NotConnected
        ));
    }
}

fn send(stream: &mut Stream, message: &[u8]) {
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut *stream).poll_write(&mut cx, message),
        Poll::Ready(Ok(n)) if n == message.len()
    ));
    assert!(matches!(
        Pin::new(stream).poll_flush(&mut cx),
        Poll::Ready(Ok(()))
    ));
}

fn close_write(stream: &mut Stream, transport: bool) {
    let mut cx = Context::from_waker(Waker::noop());
    if transport {
        assert!(matches!(
            Pin::new(stream).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
    } else {
        assert!(matches!(stream.poll_shutdown_tls(&mut cx), Poll::Ready(Ok(()))));
    }
}

fn read(stream: &mut Stream, bytes: &mut [u8]) -> usize {
    let mut cx = Context::from_waker(Waker::noop());
    let mut buf = ReadBuf::new(bytes);
    assert!(matches!(
        Pin::new(stream).poll_read(&mut cx, &mut buf),
        Poll::Ready(Ok(()))
    ));
    buf.filled().len()
}

fn drain_closed(stream: &mut Stream, expected: &[u8]) {
    let mut received = Vec::new();
    // Small reads must not discard authenticated bytes just because the close
    // record was parsed in the same transport batch. Bound the test as well.
    for _ in 0..expected.len() + 2 {
        assert_revoked(stream);
        let mut bytes = [0; 7];
        let n = read(stream, &mut bytes);
        if n == 0 {
            break;
        }
        received.extend_from_slice(&bytes[..n]);
    }
    assert_eq!(received, expected);
    assert!(stream.read_closed);
    assert_revoked(stream);
    assert_eq!(read(stream, &mut [0; 1]), 0);
}

#[test]
fn received_close_revokes_bindings_before_buffered_plaintext_is_drained() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_receives in [true, false] {
            for transport_shutdown in [true, false] {
                run_pair(version, true, move |mut client, mut server| {
                    let (receiver, sender) = if client_receives {
                        (&mut client, &mut server)
                    } else {
                        (&mut server, &mut client)
                    };
                    let bindings = live_bindings(receiver);
                    let message = [0x5A; 257];
                    send(sender, &message);
                    close_write(sender, false);
                    // The synchronous getter cannot discover unprocessed wire
                    // bytes. A zero-capacity read must not consume them either.
                    assert_eq!(read(receiver, &mut []), 0);
                    assert_eq!(live_bindings(receiver), bindings);
                    let mut first = [0; 1];
                    assert_eq!(read(receiver, &mut first), 1);
                    assert_eq!(first, [0x5A]);
                    let state = receiver.conn.process_new_packets().unwrap();
                    assert!(state.peer_has_closed(), "close_notify must actually be parsed");
                    assert_eq!(state.plaintext_bytes_to_read(), message.len() - 1);
                    assert!(!receiver.read_closed, "application has not reached EOF");
                    assert_revoked(receiver);

                    // Revocation is NOT a forced full close: the existing
                    // half-close still permits a final response and orderly
                    // local shutdown while received bytes await consumption.
                    send(receiver, b"response");
                    let mut reply = [0; 8];
                    assert_eq!(read(sender, &mut reply), reply.len());
                    assert_eq!(&reply, b"response");
                    close_write(receiver, transport_shutdown);
                    assert!(!receiver.is_closed(), "unread plaintext must survive shutdown");
                    drain_closed(receiver, &message[1..]);
                    assert!(receiver.is_closed());
                    drain_closed(sender, b"");
                    assert!(sender.is_closed());
                });
            }
        }
    }
}

#[test]
fn handshake_batch_with_finished_data_and_close_never_admits_binding() {
    // These are the endpoints that send the final handshake flight: TLS 1.3
    // client Finished, and TLS 1.2 server CCS/Finished. Let that endpoint close
    // before the other side reads the flight; no TLS state is fabricated.
    for (version, client_sends) in [
        (&rustls::version::TLS13, true),
        (&rustls::version::TLS12, false),
    ] {
        run_pair(version, false, move |mut client, mut server| {
            let (sender, receiver) = if client_sends {
                (&mut client, &mut server)
            } else {
                (&mut server, &mut client)
            };
            let mut cx = Context::from_waker(Waker::noop());
            for _ in 0..128 {
                if let Poll::Ready(result) = sender.poll_handshake(&mut cx) {
                    result.expect("final-flight sender handshake");
                    break;
                }
                assert!(receiver.poll_handshake(&mut cx).is_pending());
            }
            assert!(sender.is_ready());
            assert!(!receiver.is_ready());
            assert!(matches!(
                receiver.tls_exporter_channel_binding(),
                Err(TlsError::Rustls(rustls::Error::HandshakeNotComplete))
            ));
            let message = [0x37; 129];
            send(sender, &message);
            close_write(sender, false);
            assert!(matches!(receiver.poll_handshake(&mut cx), Poll::Ready(Ok(()))));
            let state = receiver.conn.process_new_packets().unwrap();
            assert!(state.peer_has_closed());
            assert_eq!(state.plaintext_bytes_to_read(), message.len());
            assert!(!receiver.read_closed);
            assert_revoked(receiver);
            drain_closed(receiver, &message);
            close_write(receiver, false);
            drain_closed(sender, b"");
        });
    }
}

#[test]
fn buffered_plaintext_without_processed_close_keeps_bindings_available() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_receives in [true, false] {
            run_pair(version, true, move |mut client, mut server| {
                let (receiver, sender) = if client_receives {
                    (&mut client, &mut server)
                } else {
                    (&mut server, &mut client)
                };
                let bindings = live_bindings(receiver);
                let message = [0xA5; 257];
                send(sender, &message);
                let mut first = [0; 1];
                assert_eq!(read(receiver, &mut first), 1);
                let state = receiver.conn.process_new_packets().unwrap();
                assert!(!state.peer_has_closed());
                assert_eq!(state.plaintext_bytes_to_read(), message.len() - 1);
                assert!(!receiver.conn.wants_read(), "rustls is applying plaintext backpressure");
                assert_eq!(live_bindings(receiver), bindings);
                let mut rest = [0; 256];
                assert_eq!(read(receiver, &mut rest), rest.len());
                assert_eq!(first, [0xA5]);
                assert_eq!(rest, [0xA5; 256]);
                assert_eq!(live_bindings(receiver), bindings);
                close_write(sender, false);
                assert_eq!(read(receiver, &mut [0; 1]), 0);
                assert_revoked(receiver);
            });
        }
    }
}
