//! Shutdown after TLS failure must not flush a rejected session's transport.

#![allow(clippy::pedantic, clippy::nursery)]

use super::{TlsError, TlsStream};
use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
use crate::io::{AsyncRead, AsyncWrite, BufWriter, ReadBuf};
use crate::net::tcp::VirtualTcpStream;
use crate::tls::{CertificateChain, PrivateKey};
use futures_lite::future::{poll_fn, zip};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

const CERT: &[u8] = include_bytes!("../../tests/fixtures/tls/server.crt");
const KEY: &[u8] = include_bytes!("../../tests/fixtures/tls/server.key");

type Stream = TlsStream<BufferedIo>;

// Use the production BufWriter for buffering and shutdown, not a mock that
// silently drops buffered bytes on shutdown. Reading bypasses only its write
// buffer. Faults are injected at the transport boundary, never into TLS state.
struct BufferedIo {
    writer: BufWriter<VirtualTcpStream>,
    read_error: Option<io::ErrorKind>,
    read_eof: bool,
    flush_error: Option<io::ErrorKind>,
    calls: usize,
    shutdown_calls: usize,
}

impl BufferedIo {
    fn new(inner: VirtualTcpStream) -> Self {
        Self {
            writer: BufWriter::with_capacity(32 * 1024, inner),
            read_error: None,
            read_eof: false,
            flush_error: None,
            calls: 0,
            shutdown_calls: 0,
        }
    }
}

impl AsyncRead for BufferedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.calls += 1;
        if let Some(kind) = self.read_error {
            return Poll::Ready(Err(io::Error::new(kind, "injected read failure")));
        }
        if self.read_eof {
            return Poll::Ready(Ok(()));
        }
        Pin::new(self.writer.get_mut()).poll_read(cx, buf)
    }
}

impl AsyncWrite for BufferedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.calls += 1;
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.calls += 1;
        // Permit the server's initial empty flush so its failure occurs only
        // after it has buffered a real handshake flight in response to a hello.
        if !self.writer.buffer().is_empty()
            && let Some(kind) = self.flush_error
        {
            return Poll::Ready(Err(io::Error::new(kind, "injected flush failure")));
        }
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.calls += 1;
        self.shutdown_calls += 1;
        // The real BufWriter flushes its buffer here before closing the writer.
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

fn pair(version: &'static rustls::SupportedProtocolVersion) -> (Stream, Stream) {
    let chain = CertificateChain::from_pem(CERT).unwrap().into_inner();
    let key = PrivateKey::from_pem(KEY).unwrap().clone_inner();
    let mut roots = rustls::RootCertStore::empty();
    for cert in &chain {
        roots.add(cert.clone()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let (client_io, server_io) = VirtualTcpStream::pair(
        "127.0.0.1:5270".parse().unwrap(),
        "127.0.0.1:5271".parse().unwrap(),
    );
    (
        TlsStream::new_client(
            BufferedIo::new(client_io),
            ClientConnection::new(Arc::new(client), ServerName::try_from("localhost").unwrap())
                .unwrap(),
        ),
        TlsStream::new_server(
            BufferedIo::new(server_io),
            ServerConnection::new(Arc::new(server)).unwrap(),
        ),
    )
}

fn run_pair(
    version: &'static rustls::SupportedProtocolVersion,
    established: bool,
    test: impl FnOnce(Stream, Stream) + Send + 'static,
) {
    let mut runtime = LabRuntimeTarget::create_runtime(
        TestConfig::new()
            .with_seed(0x5A17_0001)
            .with_max_steps(20_000),
    );
    LabRuntimeTarget::block_on(&mut runtime, async move {
        let (mut client, mut server) = pair(version);
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
                assert!(stream.io.writer.buffer().is_empty());
            }
        }
        test(client, server);
    });
    assert!(runtime.is_quiescent());
}

fn read_once(stream: &mut Stream, bytes: &mut [u8]) -> Poll<io::Result<usize>> {
    let mut cx = Context::from_waker(Waker::noop());
    let mut buf = ReadBuf::new(bytes);
    Pin::new(stream)
        .poll_read(&mut cx, &mut buf)
        .map(|result| result.map(|()| buf.filled().len()))
}

fn buffer_plaintext(stream: &mut Stream, message: &[u8]) {
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut *stream).poll_write(&mut cx, message),
        Poll::Ready(Ok(n)) if n == message.len()
    ));
    // Witness that the encrypted records left rustls but NOT the transport.
    assert!(!stream.conn.wants_write());
    assert!(stream.transport_needs_flush);
    assert!(!stream.io.writer.buffer().is_empty());
}

fn shutdown(stream: &mut Stream, transport: bool) -> Poll<io::Result<()>> {
    let mut cx = Context::from_waker(Waker::noop());
    if transport {
        Pin::new(stream).poll_shutdown(&mut cx)
    } else {
        stream.poll_shutdown_tls(&mut cx).map(|result| {
            result.map_err(|error| match error {
                TlsError::Io(error) => error,
                other => io::Error::other(other),
            })
        })
    }
}

fn assert_shutdown_retains_failure(stream: &mut Stream, kind: io::ErrorKind, message: &str) {
    assert!(stream.is_closed());
    assert!(!stream.shutdown_flushed);
    let calls = stream.io.calls;
    let buffered = stream.io.writer.buffer().to_vec();
    assert!(!buffered.is_empty(), "must witness buffered bytes at the failure");
    for _ in 0..3 {
        for transport in [false, true] {
            let Poll::Ready(Err(error)) = shutdown(stream, transport) else {
                panic!("shutdown hid a retained TLS failure");
            };
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), message);
            assert_eq!(stream.io.calls, calls, "shutdown touched the failed transport");
            assert_eq!(stream.io.shutdown_calls, 0);
            assert_eq!(stream.io.writer.buffer(), buffered.as_slice());
            assert!(stream.is_closed());
            assert!(!stream.shutdown_flushed);
            for binding in [
                stream.tls_exporter_channel_binding().map(|_| ()),
                stream.tls_server_end_point_channel_binding().map(|_| ()),
            ] {
                assert!(matches!(
                    binding,
                    Err(TlsError::Io(error)) if error.kind() == io::ErrorKind::NotConnected
                ));
            }
        }
    }
}

#[test]
fn shutdown_after_fatal_read_cannot_flush_buffered_application_records() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            for kind in [
                io::ErrorKind::ConnectionReset,
                io::ErrorKind::BrokenPipe,
                io::ErrorKind::UnexpectedEof,
            ] {
                run_pair(version, true, move |mut client, mut server| {
                    let (stream, peer) = if client_side {
                        (&mut client, &mut server)
                    } else {
                        (&mut server, &mut client)
                    };
                    buffer_plaintext(stream, b"must remain unsent after the read fails");
                    let mut bytes = [0; 64];
                    assert!(read_once(peer, &mut bytes).is_pending());
                    if kind == io::ErrorKind::UnexpectedEof {
                        stream.io.read_eof = true;
                    } else {
                        stream.io.read_error = Some(kind);
                    }
                    let Poll::Ready(Err(error)) = read_once(stream, &mut bytes) else {
                        panic!("the transport failure must end the read");
                    };
                    assert_eq!(error.kind(), kind);
                    stream.io.read_error = None;
                    stream.io.read_eof = false;
                    assert_shutdown_retains_failure(stream, kind, &error.to_string());
                    // BufWriter::poll_shutdown would have published the bytes
                    // (and closed TCP) even though explicit TLS flush refused.
                    assert!(read_once(peer, &mut bytes).is_pending());
                });
            }
        }
    }
}

#[test]
fn shutdown_after_handshake_failure_cannot_flush_an_abandoned_flight() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            run_pair(version, false, move |mut client, mut server| {
                let mut cx = Context::from_waker(Waker::noop());
                if !client_side {
                    assert!(client.poll_handshake(&mut cx).is_pending());
                }
                let stream = if client_side { &mut client } else { &mut server };
                stream.io.flush_error = Some(io::ErrorKind::BrokenPipe);
                let Poll::Ready(Err(error)) = stream.poll_handshake(&mut cx) else {
                    panic!("the buffered handshake flight must fail its flush");
                };
                assert!(matches!(
                    &error,
                    TlsError::Io(error) if error.kind() == io::ErrorKind::BrokenPipe
                ));
                stream.io.flush_error = None;
                assert_shutdown_retains_failure(stream, io::ErrorKind::Other, &error.to_string());
            });
        }
    }
}

#[test]
fn fatal_read_during_shutdown_cannot_turn_into_graceful_success() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            for transport in [false, true] {
                run_pair(version, true, move |mut client, mut server| {
                    let (stream, peer) = if client_side {
                        (&mut client, &mut server)
                    } else {
                        (&mut server, &mut client)
                    };
                    buffer_plaintext(stream, b"buffered before a retryable shutdown error");
                    stream.io.flush_error = Some(io::ErrorKind::WriteZero);
                    assert!(matches!(
                        shutdown(stream, transport),
                        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WriteZero
                    ));
                    assert!(stream.state.shutdown_pending());
                    assert!(!stream.shutdown_flushed);
                    assert_eq!(stream.io.shutdown_calls, 0);
                    stream.io.read_error = Some(io::ErrorKind::ConnectionReset);
                    let mut bytes = [0; 64];
                    let Poll::Ready(Err(error)) = read_once(stream, &mut bytes) else {
                        panic!("read must fail during the unfinished shutdown");
                    };
                    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
                    stream.io.flush_error = None;
                    stream.io.read_error = None;
                    assert_shutdown_retains_failure(stream, error.kind(), &error.to_string());
                    assert!(read_once(peer, &mut bytes).is_pending());
                });
            }
        }
    }
}

#[test]
fn clean_half_close_still_flushes_and_allows_transport_shutdown() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            run_pair(version, true, move |mut client, mut server| {
                let (stream, peer) = if client_side {
                    (&mut client, &mut server)
                } else {
                    (&mut server, &mut client)
                };
                let message = b"graceful buffered delivery";
                buffer_plaintext(stream, message);
                assert!(matches!(shutdown(stream, false), Poll::Ready(Ok(()))));
                assert!(stream.shutdown_flushed && stream.state.shutdown_pending());
                assert!(stream.io.writer.buffer().is_empty());
                assert_eq!(stream.io.shutdown_calls, 0);
                let mut bytes = [0; 64];
                let Poll::Ready(Ok(n)) = read_once(peer, &mut bytes) else {
                    panic!("graceful shutdown lost the buffered plaintext");
                };
                assert_eq!(&bytes[..n], message);
                assert!(matches!(read_once(peer, &mut bytes), Poll::Ready(Ok(0))));
                assert!(peer.read_closed);
                // Close the other TLS write side. Both halves are now clean;
                // a subsequent AsyncWrite shutdown must still reach TCP.
                assert!(matches!(shutdown(peer, false), Poll::Ready(Ok(()))));
                assert!(matches!(read_once(stream, &mut bytes), Poll::Ready(Ok(0))));
                assert!(stream.is_closed() && peer.is_closed());
                for endpoint in [stream, peer] {
                    assert!(endpoint.read_error.is_none());
                    assert!(endpoint.write_error.is_none());
                    assert!(matches!(shutdown(endpoint, false), Poll::Ready(Ok(()))));
                    assert!(matches!(shutdown(endpoint, true), Poll::Ready(Ok(()))));
                    assert_eq!(endpoint.io.shutdown_calls, 1);
                }
            });
        }
    }
}
