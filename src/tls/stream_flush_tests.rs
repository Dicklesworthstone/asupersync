//! Flush-state regressions using real rustls records over VirtualTcpStream.

#![allow(clippy::pedantic, clippy::nursery)]

use super::{TlsError, TlsState, TlsStream};
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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

const CERT: &[u8] = include_bytes!("../../tests/fixtures/tls/server.crt");
const KEY: &[u8] = include_bytes!("../../tests/fixtures/tls/server.key");

type Stream = TlsStream<FaultIo>;

struct FaultIo {
    inner: VirtualTcpStream,
    block_write: bool,
    block_flush: bool,
    read_error: Option<io::ErrorKind>,
    write_error: Option<io::ErrorKind>,
    flush_error: Option<io::ErrorKind>,
    interrupted_flushes: usize,
    calls: usize,
    shutdown_calls: usize,
}

impl FaultIo {
    fn new(inner: VirtualTcpStream) -> Self {
        Self {
            inner,
            block_write: false,
            block_flush: false,
            read_error: None,
            write_error: None,
            flush_error: None,
            interrupted_flushes: 0,
            calls: 0,
            shutdown_calls: 0,
        }
    }
}

impl AsyncRead for FaultIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.calls += 1;
        if let Some(kind) = self.read_error {
            return Poll::Ready(Err(kind.into()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FaultIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.calls += 1;
        if self.block_write {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if let Some(kind) = self.write_error {
            return Poll::Ready(Err(kind.into()));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.calls += 1;
        if self.block_flush {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if self.interrupted_flushes > 0 {
            self.interrupted_flushes -= 1;
            // Deliberately do not wake here: a synchronous EINTR has no
            // readiness registration. The TLS adapter must arrange a retry.
            return Poll::Ready(Err(io::ErrorKind::Interrupted.into()));
        }
        if let Some(kind) = self.flush_error {
            return Poll::Ready(Err(kind.into()));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.calls += 1;
        self.shutdown_calls += 1;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
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
        "127.0.0.1:5250".parse().unwrap(),
        "127.0.0.1:5251".parse().unwrap(),
    );
    (
        TlsStream::new_client(
            FaultIo::new(client_io),
            ClientConnection::new(Arc::new(client), ServerName::try_from("localhost").unwrap())
                .unwrap(),
        ),
        TlsStream::new_server(
            FaultIo::new(server_io),
            ServerConnection::new(Arc::new(server)).unwrap(),
        ),
    )
}

fn run_pair(
    version: &'static rustls::SupportedProtocolVersion,
    established: bool,
    test: impl FnOnce(Stream, Stream) + Send + 'static,
) {
    let config = TestConfig::new()
        .with_seed(0xF105_0001)
        .with_max_steps(20_000);
    let mut runtime = LabRuntimeTarget::create_runtime(config);
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
            assert_eq!(client.protocol_version(), Some(version.version));
            assert_eq!(server.protocol_version(), Some(version.version));
        }
        test(client, server);
    });
    assert!(runtime.is_quiescent());
}

fn assert_binding_revoked(stream: &Stream) {
    assert!(matches!(
        stream.tls_exporter_channel_binding(),
        Err(TlsError::Io(error)) if error.kind() == io::ErrorKind::NotConnected
    ));
    assert!(matches!(
        stream.tls_server_end_point_channel_binding(),
        Err(TlsError::Io(error)) if error.kind() == io::ErrorKind::NotConnected
    ));
}

fn queue_plaintext(stream: &mut Stream, message: &[u8]) {
    let mut cx = Context::from_waker(Waker::noop());
    stream.io.block_write = true;
    assert!(matches!(
        Pin::new(&mut *stream).poll_write(&mut cx, message),
        Poll::Ready(Ok(n)) if n == message.len()
    ));
    assert!(stream.conn.wants_write(), "must witness queued TLS records");
    stream.io.block_write = false;
}

#[test]
fn fatal_application_flush_errors_revoke_bindings_and_remain_sticky() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            for record_write in [true, false] {
                for kind in [io::ErrorKind::ConnectionReset, io::ErrorKind::BrokenPipe] {
                    run_pair(version, true, move |mut client, mut server| {
                        let stream = if client_side { &mut client } else { &mut server };
                        if version.version == rustls::ProtocolVersion::TLSv1_3 {
                            stream.tls_exporter_channel_binding().unwrap();
                        }
                        queue_plaintext(stream, b"accepted before flush failure");
                        if record_write {
                            stream.io.write_error = Some(kind);
                        } else {
                            stream.io.flush_error = Some(kind);
                        }
                        let mut cx = Context::from_waker(Waker::noop());
                        assert!(matches!(
                            Pin::new(&mut *stream).poll_flush(&mut cx),
                            Poll::Ready(Err(error)) if error.kind() == kind
                        ));
                        assert!(stream.is_closed());
                        assert_binding_revoked(stream);
                        // Remove the fault. Even a subsequently writable
                        // transport cannot resurrect the authenticated session.
                        stream.io.write_error = None;
                        stream.io.flush_error = None;
                        let calls = stream.io.calls;
                        for _ in 0..3 {
                            assert!(matches!(
                                Pin::new(&mut *stream).poll_flush(&mut cx),
                                Poll::Ready(Err(error)) if error.kind() == kind
                            ));
                            assert!(matches!(
                                Pin::new(&mut *stream).poll_write(&mut cx, b"must not retry"),
                                Poll::Ready(Err(error)) if error.kind() == kind
                            ));
                            let mut bytes = [0; 64];
                            let mut buf = ReadBuf::new(&mut bytes);
                            assert!(matches!(
                                Pin::new(&mut *stream).poll_read(&mut cx, &mut buf),
                                Poll::Ready(Err(error)) if error.kind() == kind
                            ));
                            assert!(buf.filled().is_empty());
                            assert!(matches!(
                                Pin::new(&mut *stream).poll_shutdown(&mut cx),
                                Poll::Ready(Err(error)) if error.kind() == kind
                            ));
                            assert!(matches!(
                                stream.poll_shutdown_tls(&mut cx),
                                Poll::Ready(Err(TlsError::Io(error))) if error.kind() == kind
                            ));
                            assert!(matches!(
                                stream.poll_handshake(&mut cx),
                                Poll::Ready(Err(TlsError::Io(error)))
                                    if error.kind() == io::ErrorKind::NotConnected
                            ));
                            assert_eq!(stream.io.calls, calls, "terminal operation touched IO");
                            assert_binding_revoked(stream);
                        }
                    });
                }
            }
        }
    }
}

#[test]
fn application_flush_cannot_send_queued_records_after_a_fatal_read() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            run_pair(version, true, move |mut client, mut server| {
                let (stream, peer) = if client_side {
                    (&mut client, &mut server)
                } else {
                    (&mut server, &mut client)
                };
                queue_plaintext(stream, b"must stay unsent after the read fails");
                stream.io.read_error = Some(io::ErrorKind::ConnectionReset);
                let mut cx = Context::from_waker(Waker::noop());
                let mut bytes = [0; 64];
                let mut buf = ReadBuf::new(&mut bytes);
                assert!(matches!(
                    Pin::new(&mut *stream).poll_read(&mut cx, &mut buf),
                    Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset
                ));
                assert!(buf.filled().is_empty());
                assert!(stream.is_closed() && stream.conn.wants_write());
                stream.io.read_error = None;
                let calls = stream.io.calls;
                for _ in 0..3 {
                    assert!(matches!(
                        Pin::new(&mut *stream).poll_flush(&mut cx),
                        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset
                    ));
                    assert_eq!(stream.io.calls, calls);
                    assert_binding_revoked(stream);
                }
                let mut buf = ReadBuf::new(&mut bytes);
                assert!(Pin::new(&mut *peer).poll_read(&mut cx, &mut buf).is_pending());
                assert!(buf.filled().is_empty(), "terminal flush published application bytes");
            });
        }
    }
}

#[derive(Clone, Copy)]
enum FlushOperation {
    Application,
    TlsShutdown,
    TransportShutdown,
}

fn poll_operation(
    stream: &mut Stream,
    cx: &mut Context<'_>,
    operation: FlushOperation,
) -> Poll<io::Result<()>> {
    match operation {
        FlushOperation::Application => Pin::new(stream).poll_flush(cx),
        FlushOperation::TlsShutdown => stream.poll_shutdown_tls(cx).map(|result| {
            result.map_err(|error| match error {
                TlsError::Io(error) => error,
                other => io::Error::other(other),
            })
        }),
        FlushOperation::TransportShutdown => Pin::new(stream).poll_shutdown(cx),
    }
}

#[test]
fn interrupted_application_and_shutdown_flushes_wake_and_preserve_progress() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            for operation in [
                FlushOperation::Application,
                FlushOperation::TlsShutdown,
                FlushOperation::TransportShutdown,
            ] {
                run_pair(version, true, move |mut client, mut server| {
                    let (stream, peer) = if client_side {
                        (&mut client, &mut server)
                    } else {
                        (&mut server, &mut client)
                    };
                    let binding = stream.tls_exporter_channel_binding().ok();
                    let message = b"delivered once despite interrupted flushes";
                    queue_plaintext(stream, message);
                    stream.io.interrupted_flushes = 2;
                    let counter = Arc::new(WakeCount::default());
                    let waker = Waker::from(Arc::clone(&counter));
                    let mut cx = Context::from_waker(&waker);
                    for _ in 0..2 {
                        let before = counter.0.load(Ordering::Relaxed);
                        assert!(poll_operation(stream, &mut cx, operation).is_pending());
                        assert_eq!(counter.0.load(Ordering::Relaxed), before + 1);
                        assert!(!stream.is_closed());
                        assert!(stream.write_error.is_none());
                        assert!(!stream.shutdown_flushed);
                        assert_eq!(stream.io.shutdown_calls, 0);
                        if matches!(operation, FlushOperation::Application) {
                            assert!(stream.is_ready());
                            assert_eq!(stream.tls_exporter_channel_binding().ok(), binding);
                        } else {
                            assert!(stream.state.shutdown_pending());
                            assert_binding_revoked(stream);
                        }
                    }
                    assert_eq!(stream.io.interrupted_flushes, 0);
                    assert!(matches!(
                        poll_operation(stream, &mut cx, operation),
                        Poll::Ready(Ok(()))
                    ));
                    assert!(!stream.conn.wants_write());
                    assert_eq!(
                        stream.io.shutdown_calls,
                        usize::from(matches!(operation, FlushOperation::TransportShutdown))
                    );
                    let mut bytes = [0; 64];
                    let mut buf = ReadBuf::new(&mut bytes);
                    assert!(matches!(
                        Pin::new(&mut *peer).poll_read(&mut cx, &mut buf),
                        Poll::Ready(Ok(()))
                    ));
                    assert_eq!(buf.filled(), message);
                    let mut buf = ReadBuf::new(&mut bytes);
                    let after = Pin::new(&mut *peer).poll_read(&mut cx, &mut buf);
                    if matches!(operation, FlushOperation::Application) {
                        assert!(after.is_pending());
                        assert_eq!(peer.tls_exporter_channel_binding().ok(), binding);
                    } else {
                        assert!(matches!(after, Poll::Ready(Ok(()))));
                        assert!(peer.read_closed);
                        assert!(stream.shutdown_flushed);
                    }
                    assert!(buf.filled().is_empty(), "accepted plaintext was duplicated");
                });
            }
        }
    }
}

#[test]
fn interrupted_final_handshake_flush_keeps_bindings_unavailable_until_success() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            run_pair(version, false, move |mut client, mut server| {
                if client_side {
                    client.io.block_flush = true;
                } else {
                    server.io.block_flush = true;
                }
                let mut cx = Context::from_waker(Waker::noop());
                // Witness rustls completion while the stream's final flush is
                // held; no guessed flight counts or assignment to TLS state.
                for _ in 0..128 {
                    for stream in [&mut client, &mut server] {
                        if !stream.is_ready()
                            && let Poll::Ready(result) = stream.poll_handshake(&mut cx)
                        {
                            result.expect("handshake before the interrupted final flush");
                        }
                    }
                    let stream = if client_side { &client } else { &server };
                    if !stream.conn.is_handshaking() {
                        break;
                    }
                }
                let stream = if client_side { &mut client } else { &mut server };
                assert!(!stream.conn.is_handshaking(), "did not reach final flush");
                assert_eq!(stream.state, TlsState::Handshaking);
                stream.io.block_flush = false;
                stream.io.interrupted_flushes = 2;
                let counter = Arc::new(WakeCount::default());
                let waker = Waker::from(Arc::clone(&counter));
                let mut cx = Context::from_waker(&waker);
                for _ in 0..2 {
                    let before = counter.0.load(Ordering::Relaxed);
                    assert!(stream.poll_handshake(&mut cx).is_pending());
                    assert_eq!(counter.0.load(Ordering::Relaxed), before + 1);
                    assert_eq!(stream.state, TlsState::Handshaking);
                    assert!(matches!(
                        stream.tls_exporter_channel_binding(),
                        Err(TlsError::Rustls(rustls::Error::HandshakeNotComplete))
                    ));
                }
                assert!(matches!(stream.poll_handshake(&mut cx), Poll::Ready(Ok(()))));
                assert!(stream.is_ready());
                for _ in 0..128 {
                    for stream in [&mut client, &mut server] {
                        if !stream.is_ready()
                            && let Poll::Ready(result) = stream.poll_handshake(&mut cx)
                        {
                            result.expect("peer handshake after the final flush");
                        }
                    }
                    if client.is_ready() && server.is_ready() {
                        break;
                    }
                }
                assert!(client.is_ready() && server.is_ready());
                if version.version == rustls::ProtocolVersion::TLSv1_3 {
                    assert_eq!(
                        client.tls_exporter_channel_binding().unwrap(),
                        server.tls_exporter_channel_binding().unwrap()
                    );
                }
            });
        }
    }
}
