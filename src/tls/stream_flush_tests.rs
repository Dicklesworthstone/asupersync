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
    buffer_capacity: Option<usize>,
    buffered: Vec<u8>,
    capacity_waiter: Option<Waker>,
    capacity_stalls: usize,
    max_buffered: usize,
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
            buffer_capacity: None,
            buffered: Vec::new(),
            capacity_waiter: None,
            capacity_stalls: 0,
            max_buffered: 0,
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
        if let Some(capacity) = self.buffer_capacity {
            let remaining = capacity - self.buffered.len();
            if remaining == 0 && !buf.is_empty() {
                self.capacity_stalls += 1;
                self.capacity_waiter = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let n = remaining.min(buf.len());
            self.buffered.extend_from_slice(&buf[..n]);
            self.max_buffered = self.max_buffered.max(self.buffered.len());
            return Poll::Ready(Ok(n));
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
        let this = &mut *self;
        while !this.buffered.is_empty() {
            let n = std::task::ready!(Pin::new(&mut this.inner).poll_write(cx, &this.buffered))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            this.buffered.drain(..n);
            if let Some(waiter) = this.capacity_waiter.take() {
                waiter.wake();
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
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

fn read_plaintext(stream: &mut Stream, expected: &[u8]) {
    let mut cx = Context::from_waker(Waker::noop());
    let mut received = vec![0; expected.len()];
    let mut offset = 0;
    while offset < received.len() {
        let mut buf = ReadBuf::new(&mut received[offset..]);
        assert!(matches!(
            Pin::new(&mut *stream).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert!(!buf.filled().is_empty(), "EOF before all accepted bytes arrived");
        offset += buf.filled().len();
    }
    assert_eq!(received, expected);
}

#[test]
fn bounded_transport_capacity_does_not_deadlock_handshakes() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        run_pair(version, false, move |mut client, mut server| {
            client.io.buffer_capacity = Some(7);
            server.io.buffer_capacity = Some(11);
            let mut cx = Context::from_waker(Waker::noop());
            // Only drive the public handshake operation. Neither the driver
            // nor a background task flushes the bounded transport for TLS.
            for _ in 0..128 {
                for stream in [&mut client, &mut server] {
                    if !stream.is_ready() {
                        assert!(matches!(
                            stream.tls_exporter_channel_binding(),
                            Err(TlsError::Rustls(rustls::Error::HandshakeNotComplete))
                        ));
                        if let Poll::Ready(result) = stream.poll_handshake(&mut cx) {
                            result.expect("bounded transport handshake");
                        }
                    }
                }
                if client.is_ready() && server.is_ready() {
                    break;
                }
            }
            assert!(client.is_ready() && server.is_ready(), "capacity deadlocked TLS");
            for stream in [&client, &server] {
                assert_eq!(stream.protocol_version(), Some(version.version));
                assert!(stream.io.capacity_stalls > 0, "must reach actual buffer exhaustion");
                assert_eq!(stream.io.max_buffered, stream.io.buffer_capacity.unwrap());
                assert!(stream.io.buffered.is_empty());
                assert!(!stream.conn.wants_write());
                assert!(!stream.transport_needs_flush);
            }
            if version.version == rustls::ProtocolVersion::TLSv1_3 {
                assert_eq!(
                    client.tls_exporter_channel_binding().unwrap(),
                    server.tls_exporter_channel_binding().unwrap()
                );
            }
        });
    }
}

#[test]
fn bounded_transport_flush_and_both_shutdown_apis_deliver_all_records() {
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
                    stream.io.buffer_capacity = Some(7);
                    let binding = stream.tls_exporter_channel_binding().ok();
                    let message = [0xA5; 257];
                    queue_plaintext(stream, &message);
                    let mut cx = Context::from_waker(Waker::noop());
                    assert!(matches!(
                        poll_operation(stream, &mut cx, operation),
                        Poll::Ready(Ok(()))
                    ));
                    assert!(stream.io.capacity_stalls > 0);
                    assert_eq!(stream.io.max_buffered, 7);
                    assert!(stream.io.buffered.is_empty());
                    assert!(!stream.conn.wants_write());
                    assert!(!stream.transport_needs_flush);
                    read_plaintext(peer, &message);
                    let mut extra = [0; 1];
                    let mut buf = ReadBuf::new(&mut extra);
                    let after = Pin::new(&mut *peer).poll_read(&mut cx, &mut buf);
                    if matches!(operation, FlushOperation::Application) {
                        assert!(after.is_pending());
                        assert_eq!(stream.tls_exporter_channel_binding().ok(), binding);
                        assert_eq!(peer.tls_exporter_channel_binding().ok(), binding);
                    } else {
                        assert!(matches!(after, Poll::Ready(Ok(()))));
                        assert!(peer.read_closed && stream.shutdown_flushed);
                        assert_binding_revoked(stream);
                        assert_binding_revoked(peer);
                    }
                    assert!(buf.filled().is_empty(), "plaintext was duplicated");
                    assert_eq!(
                        stream.io.shutdown_calls,
                        usize::from(matches!(operation, FlushOperation::TransportShutdown))
                    );
                });
            }
        }
    }
}

#[test]
fn bounded_transport_pending_and_interrupted_flushes_keep_partial_records() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            run_pair(version, true, move |mut client, mut server| {
                let (stream, peer) = if client_side {
                    (&mut client, &mut server)
                } else {
                    (&mut server, &mut client)
                };
                let binding = stream.tls_exporter_channel_binding().ok();
                stream.io.buffer_capacity = Some(7);
                stream.io.block_flush = true;
                let message = [0x5A; 257];
                queue_plaintext(stream, &message);
                let mut cx = Context::from_waker(Waker::noop());
                for _ in 0..2 {
                    assert!(Pin::new(&mut *stream).poll_flush(&mut cx).is_pending());
                    assert!(stream.conn.wants_write());
                    assert!(stream.transport_needs_flush);
                    assert_eq!(stream.io.buffered.len(), 7);
                    assert!(stream.is_ready());
                }
                let mut bytes = [0; 1];
                let mut buf = ReadBuf::new(&mut bytes);
                assert!(Pin::new(&mut *peer).poll_read(&mut cx, &mut buf).is_pending());
                assert!(buf.filled().is_empty());
                // The task that resumes a pending flush may have a new waker.
                stream.io.block_flush = false;
                stream.io.interrupted_flushes = 1;
                let counter = Arc::new(WakeCount::default());
                let waker = Waker::from(Arc::clone(&counter));
                let mut cx = Context::from_waker(&waker);
                assert!(Pin::new(&mut *stream).poll_flush(&mut cx).is_pending());
                assert_eq!(counter.0.load(Ordering::Relaxed), 1);
                assert!(stream.transport_needs_flush && stream.conn.wants_write());
                assert_eq!(stream.io.buffered.len(), 7);
                assert!(matches!(
                    Pin::new(&mut *stream).poll_flush(&mut cx),
                    Poll::Ready(Ok(()))
                ));
                assert!(!stream.transport_needs_flush);
                assert!(stream.io.buffered.is_empty());
                read_plaintext(peer, &message);
                let mut buf = ReadBuf::new(&mut bytes);
                assert!(Pin::new(&mut *peer).poll_read(&mut cx, &mut buf).is_pending());
                assert!(buf.filled().is_empty());
                assert_eq!(stream.tls_exporter_channel_binding().ok(), binding);
                assert_eq!(peer.tls_exporter_channel_binding().ok(), binding);
            });
        }
    }
}

#[test]
fn bounded_transport_flush_failure_after_acceptance_is_sticky() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            for kind in [io::ErrorKind::ConnectionReset, io::ErrorKind::BrokenPipe] {
                run_pair(version, true, move |mut client, mut server| {
                    let (stream, peer) = if client_side {
                        (&mut client, &mut server)
                    } else {
                        (&mut server, &mut client)
                    };
                    stream.io.buffer_capacity = Some(7);
                    stream.io.flush_error = Some(kind);
                    let message = [0xC3; 257];
                    let mut cx = Context::from_waker(Waker::noop());
                    assert!(matches!(
                        Pin::new(&mut *stream).poll_write(&mut cx, &message),
                        Poll::Ready(Ok(n)) if n == message.len()
                    ));
                    assert_eq!(stream.io.capacity_stalls, 1);
                    assert_eq!(stream.io.buffered.len(), 7);
                    assert!(stream.is_closed());
                    assert_binding_revoked(stream);
                    stream.io.flush_error = None;
                    let calls = stream.io.calls;
                    for _ in 0..3 {
                        assert!(matches!(
                            Pin::new(&mut *stream).poll_write(&mut cx, &message),
                            Poll::Ready(Err(error)) if error.kind() == kind
                        ));
                        for operation in [
                            FlushOperation::Application,
                            FlushOperation::TlsShutdown,
                            FlushOperation::TransportShutdown,
                        ] {
                            assert!(matches!(
                                poll_operation(stream, &mut cx, operation),
                                Poll::Ready(Err(error)) if error.kind() == kind
                            ));
                        }
                        assert_eq!(stream.io.calls, calls);
                    }
                    let mut bytes = [0; 1];
                    let mut buf = ReadBuf::new(&mut bytes);
                    assert!(Pin::new(&mut *peer).poll_read(&mut cx, &mut buf).is_pending());
                    assert!(buf.filled().is_empty());
                });
            }
        }
    }
}

#[test]
fn successful_flush_does_not_spin_on_a_still_blocked_transport() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            run_pair(version, true, move |mut client, mut server| {
                let (stream, peer) = if client_side {
                    (&mut client, &mut server)
                } else {
                    (&mut server, &mut client)
                };
                let mut cx = Context::from_waker(Waker::noop());
                let first = b"already accepted";
                let second = b"still blocked";
                assert!(matches!(
                    Pin::new(&mut *stream).poll_write(&mut cx, first),
                    Poll::Ready(Ok(n)) if n == first.len()
                ));
                assert!(stream.transport_needs_flush);
                stream.io.block_write = true;
                let calls = stream.io.calls;
                assert!(matches!(
                    Pin::new(&mut *stream).poll_write(&mut cx, second),
                    Poll::Ready(Ok(n)) if n == second.len()
                ));
                // One blocked write, one flush, one retry: no new bytes were
                // accepted by the transport, so another flush cannot help.
                assert_eq!(stream.io.calls - calls, 3);
                assert!(!stream.transport_needs_flush);
                assert!(stream.conn.wants_write());
                let calls = stream.io.calls;
                assert!(Pin::new(&mut *stream).poll_flush(&mut cx).is_pending());
                assert_eq!(stream.io.calls - calls, 1);
                stream.io.block_write = false;
                assert!(matches!(
                    Pin::new(&mut *stream).poll_flush(&mut cx),
                    Poll::Ready(Ok(()))
                ));
                let mut expected = first.to_vec();
                expected.extend_from_slice(second);
                read_plaintext(peer, &expected);
            });
        }
    }
}

fn assert_failed_handshake_reads_error(stream: &mut Stream, original: &TlsError) {
    assert!(stream.is_closed());
    assert_binding_revoked(stream);
    let message = original.to_string();
    let calls = stream.io.calls;
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..3 {
        let mut bytes = [0; 16];
        let mut buf = ReadBuf::new(&mut bytes);
        let Poll::Ready(Err(error)) = Pin::new(&mut *stream).poll_read(&mut cx, &mut buf) else {
            panic!("a failed handshake became a clean EOF or a pending read");
        };
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(error.to_string(), message);
        assert!(buf.filled().is_empty());
        assert!(matches!(
            Pin::new(&mut *stream).poll_flush(&mut cx),
            Poll::Ready(Err(error))
                if error.kind() == io::ErrorKind::Other && error.to_string() == message
        ));
        assert!(matches!(
            Pin::new(&mut *stream).poll_write(&mut cx, b"must not send"),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe
        ));
        assert!(matches!(
            stream.poll_handshake(&mut cx),
            Poll::Ready(Err(TlsError::Io(error)))
                if error.kind() == io::ErrorKind::NotConnected
        ));
        assert_eq!(stream.io.calls, calls, "failed session performed more IO");
    }
}

#[test]
fn direct_handshake_transport_failures_do_not_become_clean_read_eof() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            for stage in 0..3 {
                for kind in [io::ErrorKind::ConnectionReset, io::ErrorKind::BrokenPipe] {
                    run_pair(version, false, move |mut client, mut server| {
                        let mut cx = Context::from_waker(Waker::noop());
                        if !client_side {
                            // A server needs a real ClientHello before it can
                            // reach its first record-write failure boundary.
                            assert!(client.poll_handshake(&mut cx).is_pending());
                        }
                        let stream = if client_side { &mut client } else { &mut server };
                        match stage {
                            0 => stream.io.read_error = Some(kind),
                            1 => stream.io.write_error = Some(kind),
                            _ => stream.io.flush_error = Some(kind),
                        }
                        let Poll::Ready(Err(error)) = stream.poll_handshake(&mut cx) else {
                            panic!("the selected handshake operation did not fail");
                        };
                        assert!(matches!(&error, TlsError::Io(error) if error.kind() == kind));
                        // A repaired transport must not turn an authentication
                        // failure into a successful zero-byte application read.
                        stream.io.read_error = None;
                        stream.io.write_error = None;
                        stream.io.flush_error = None;
                        assert_failed_handshake_reads_error(stream, &error);
                    });
                }
            }
        }
    }
}

#[test]
fn failed_final_handshake_flush_does_not_become_clean_read_eof() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            run_pair(version, false, move |mut client, mut server| {
                if client_side {
                    client.io.block_flush = true;
                } else {
                    server.io.block_flush = true;
                }
                let mut cx = Context::from_waker(Waker::noop());
                for _ in 0..128 {
                    for stream in [&mut client, &mut server] {
                        if !stream.is_ready()
                            && let Poll::Ready(result) = stream.poll_handshake(&mut cx)
                        {
                            result.expect("handshake before final-flush failure");
                        }
                    }
                    let stream = if client_side { &client } else { &server };
                    if !stream.conn.is_handshaking() {
                        break;
                    }
                }
                let stream = if client_side { &mut client } else { &mut server };
                assert!(!stream.conn.is_handshaking(), "final flush was not reached");
                assert_eq!(stream.state, TlsState::Handshaking);
                stream.io.block_flush = false;
                stream.io.flush_error = Some(io::ErrorKind::BrokenPipe);
                let Poll::Ready(Err(error)) = stream.poll_handshake(&mut cx) else {
                    panic!("final transport flush must fail");
                };
                assert!(matches!(
                    &error,
                    TlsError::Io(error) if error.kind() == io::ErrorKind::BrokenPipe
                ));
                stream.io.flush_error = None;
                assert_failed_handshake_reads_error(stream, &error);
            });
        }
    }
}

#[test]
fn buffered_certificate_failure_delivers_its_alert_and_remains_a_read_error() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for capacity in [7, 64] {
            run_pair(version, false, move |client, mut server| {
                // Keep certificate verification enabled, but intentionally
                // trust no issuer. Replace only the not-yet-polled client.
                let config = ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_protocol_versions(&[version])
                .unwrap()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
                let conn = ClientConnection::new(
                    Arc::new(config),
                    ServerName::try_from("localhost").unwrap(),
                )
                .unwrap();
                let mut client = TlsStream::new_client(client.into_inner(), conn);
                client.io.buffer_capacity = Some(capacity);
                let mut cx = Context::from_waker(Waker::noop());
                let mut client_error = None;
                let mut server_error = None;
                for _ in 0..128 {
                    if client_error.is_none()
                        && let Poll::Ready(result) = client.poll_handshake(&mut cx)
                    {
                        client_error = Some(result.expect_err("untrusted server accepted"));
                    }
                    if server_error.is_none()
                        && let Poll::Ready(result) = server.poll_handshake(&mut cx)
                    {
                        server_error = Some(result.expect_err("rejected client completed TLS"));
                    }
                    if client_error.is_some() && server_error.is_some() {
                        break;
                    }
                }
                let client_error = client_error.expect("certificate verifier must refuse");
                let server_error = server_error.expect("peer did not receive the buffered alert");
                assert!(matches!(&client_error, TlsError::Handshake(_)));
                assert!(matches!(
                    &server_error,
                    TlsError::Handshake(message)
                        if *message == rustls::Error::AlertReceived(
                            rustls::AlertDescription::UnknownCA
                        ).to_string()
                ));
                assert!(client.io.buffered.is_empty(), "fatal alert remained buffered");
                assert!(!client.transport_needs_flush);
                assert_failed_handshake_reads_error(&mut client, &client_error);
                assert_failed_handshake_reads_error(&mut server, &server_error);
            });
        }
    }
}

fn send_corrupt_record(sender: &mut Stream) {
    queue_plaintext(sender, b"the authenticated payload must not escape");
    let mut wire = Vec::new();
    while sender.conn.wants_write() {
        assert!(sender.conn.write_tls(&mut wire).unwrap() > 0);
    }
    // Corrupt actual encrypted output, not rustls state or plaintext. The
    // small fixture record fits in one VirtualTcpStream write.
    assert!(wire.len() > 5);
    *wire.last_mut().unwrap() ^= 1;
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut sender.io).poll_write(&mut cx, &wire),
        Poll::Ready(Ok(n)) if n == wire.len()
    ));
    assert!(matches!(
        Pin::new(&mut sender.io).poll_flush(&mut cx),
        Poll::Ready(Ok(()))
    ));
}

#[test]
fn buffered_bad_record_alert_is_delivered_from_either_endpoint() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            for capacity in [7, 64] {
                run_pair(version, true, move |mut client, mut server| {
                    let (receiver, sender) = if client_side {
                        (&mut client, &mut server)
                    } else {
                        (&mut server, &mut client)
                    };
                    receiver.io.buffer_capacity = Some(capacity);
                    send_corrupt_record(sender);
                    let mut cx = Context::from_waker(Waker::noop());
                    let mut bytes = [0; 64];
                    let mut buf = ReadBuf::new(&mut bytes);
                    assert!(matches!(
                        Pin::new(&mut *receiver).poll_read(&mut cx, &mut buf),
                        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData
                    ));
                    assert!(buf.filled().is_empty());
                    assert!(receiver.is_closed());
                    assert_binding_revoked(receiver);
                    assert!(receiver.io.buffered.is_empty(), "fatal alert remained buffered");
                    assert!(!receiver.transport_needs_flush);
                    let mut buf = ReadBuf::new(&mut bytes);
                    let Poll::Ready(Err(error)) = Pin::new(&mut *sender).poll_read(&mut cx, &mut buf)
                    else {
                        panic!("peer did not receive the buffered bad_record_mac alert");
                    };
                    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                    assert_eq!(
                        error.to_string(),
                        rustls::Error::AlertReceived(rustls::AlertDescription::BadRecordMac)
                            .to_string()
                    );
                    assert!(buf.filled().is_empty());
                    assert!(sender.is_closed());
                    assert_binding_revoked(sender);
                });
            }
        }
    }
}

#[test]
fn pending_or_failed_alert_flush_does_not_replace_the_original_tls_error() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            for pending in [true, false] {
                run_pair(version, true, move |mut client, mut server| {
                    let (receiver, sender) = if client_side {
                        (&mut client, &mut server)
                    } else {
                        (&mut server, &mut client)
                    };
                    receiver.io.buffer_capacity = Some(64);
                    receiver.io.block_flush = pending;
                    if !pending {
                        receiver.io.flush_error = Some(io::ErrorKind::BrokenPipe);
                    }
                    send_corrupt_record(sender);
                    let mut cx = Context::from_waker(Waker::noop());
                    let mut bytes = [0; 64];
                    let mut buf = ReadBuf::new(&mut bytes);
                    // The read must report the fatal record error immediately,
                    // not wait for alert delivery or replace it with BrokenPipe.
                    let Poll::Ready(Err(error)) = Pin::new(&mut *receiver).poll_read(&mut cx, &mut buf)
                    else {
                        panic!("best-effort alert delayed the original failure");
                    };
                    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                    assert_eq!(error.to_string(), rustls::Error::DecryptError.to_string());
                    assert!(buf.filled().is_empty());
                    assert!(receiver.is_closed());
                    assert_binding_revoked(receiver);
                    assert!(!receiver.io.buffered.is_empty());
                    assert!(receiver.transport_needs_flush);
                    receiver.io.block_flush = false;
                    receiver.io.flush_error = None;
                    let calls = receiver.io.calls;
                    let mut buf = ReadBuf::new(&mut bytes);
                    assert!(matches!(
                        Pin::new(&mut *receiver).poll_read(&mut cx, &mut buf),
                        Poll::Ready(Err(repeated))
                            if repeated.kind() == error.kind() && repeated.to_string() == error.to_string()
                    ));
                    assert!(buf.filled().is_empty());
                    assert_eq!(receiver.io.calls, calls);
                });
            }
        }
    }
}


#[test]
fn peer_certificate_metadata_is_hidden_before_wrapper_handshake_completion() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        run_pair(version, false, move |client, server| {
            for stream in [&client, &server] {
                assert!(!stream.handshake_completed);
                assert!(stream.state.requires_handshake());
                assert!(stream.peer_leaf_certificate_der().is_none());
                assert!(stream.peer_certificate_chain_der().is_none());
            }
        });
    }
}

#[test]
fn client_certificate_metadata_waits_for_the_final_tls13_transport_flush() {
    run_pair(&rustls::version::TLS13, false, move |mut client, mut server| {
        let mut cx = Context::from_waker(Waker::noop());

        // Publish ClientHello, then let the server return its authenticated
        // certificate/Finished flight. The client will know the certificate
        // during its next poll, but its own final Finished still must flush.
        assert!(client.poll_handshake(&mut cx).is_pending());
        assert!(server.poll_handshake(&mut cx).is_pending());

        client.io.block_flush = true;
        assert!(client.poll_handshake(&mut cx).is_pending());
        assert!(
            !client.conn.is_handshaking(),
            "rustls must have authenticated the server before the blocked final flush"
        );
        assert!(client.conn.peer_leaf_certificate_der().is_some());
        assert!(client.state.requires_handshake());
        assert!(!client.handshake_completed);
        assert!(client.peer_leaf_certificate_der().is_none());
        assert!(client.peer_certificate_chain_der().is_none());

        client.io.block_flush = false;
        assert!(matches!(client.poll_handshake(&mut cx), Poll::Ready(Ok(()))));
        assert!(client.handshake_completed);
        assert!(client.is_ready());

        let expected = CertificateChain::from_pem(CERT).unwrap().into_inner();
        assert_eq!(
            client.peer_leaf_certificate_der().as_deref(),
            Some(expected[0].as_ref())
        );
        assert_eq!(
            client.peer_certificate_chain_der().unwrap(),
            expected
                .iter()
                .map(|certificate| certificate.as_ref().to_vec())
                .collect::<Vec<_>>()
        );
    });
}

#[test]
fn failed_final_tls13_flush_never_publishes_peer_certificate_metadata() {
    run_pair(&rustls::version::TLS13, false, move |mut client, mut server| {
        let mut cx = Context::from_waker(Waker::noop());
        assert!(client.poll_handshake(&mut cx).is_pending());
        assert!(server.poll_handshake(&mut cx).is_pending());

        client.io.flush_error = Some(io::ErrorKind::BrokenPipe);
        let Poll::Ready(Err(TlsError::Io(error))) = client.poll_handshake(&mut cx) else {
            panic!("the final wrapper flush must fail");
        };
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(
            !client.conn.is_handshaking(),
            "rustls had already authenticated the server before wrapper failure"
        );
        assert!(client.conn.peer_leaf_certificate_der().is_some());
        assert!(!client.handshake_completed);
        assert!(client.is_closed());
        assert!(client.peer_leaf_certificate_der().is_none());
        assert!(client.peer_certificate_chain_der().is_none());

        client.io.flush_error = None;
        assert!(matches!(
            client.poll_handshake(&mut cx),
            Poll::Ready(Err(TlsError::Io(error)))
                if error.kind() == io::ErrorKind::NotConnected
        ));
        assert!(client.peer_leaf_certificate_der().is_none());
        assert!(client.peer_certificate_chain_der().is_none());
    });
}

#[test]
fn established_peer_certificate_metadata_survives_later_connection_close() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        run_pair(version, true, move |mut client, mut server| {
            let leaf = client
                .peer_leaf_certificate_der()
                .expect("established client exposes authenticated server certificate");
            let chain = client
                .peer_certificate_chain_der()
                .expect("established client exposes authenticated server chain");
            assert!(client.handshake_completed);
            assert!(!leaf.is_empty());
            assert_eq!(chain.first().map(Vec::as_slice), Some(leaf.as_slice()));

            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(client.poll_shutdown_tls(&mut cx), Poll::Ready(Ok(()))));
            let mut bytes = [0; 1];
            let mut buf = ReadBuf::new(&mut bytes);
            // Process the client's close_notify at the server.
            assert!(matches!(
                Pin::new(&mut server).poll_read(&mut cx, &mut buf),
                Poll::Ready(Ok(()))
            ));
            assert!(buf.filled().is_empty());

            assert!(matches!(server.poll_shutdown_tls(&mut cx), Poll::Ready(Ok(()))));
            let mut buf = ReadBuf::new(&mut bytes);
            assert!(matches!(
                Pin::new(&mut client).poll_read(&mut cx, &mut buf),
                Poll::Ready(Ok(()))
            ));
            assert!(client.is_closed());
            assert_eq!(client.peer_leaf_certificate_der().as_deref(), Some(leaf.as_slice()));
            assert_eq!(client.peer_certificate_chain_der().as_deref(), Some(chain.as_slice()));
        });
    }
}
