//! Real TLS records over an eager one-byte transport must not monopolize a poll.

#![allow(clippy::pedantic, clippy::nursery)]

use super::{TLS_WRITE_STEPS_PER_POLL, TlsConnection, TlsError, TlsStream};
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
type Stream = TlsStream<ShortIo>;

// Explicit transport test double: real bytes go through VirtualTcpStream, but
// each successful write can be limited to one byte. No TLS state is fabricated.
struct ShortIo {
    inner: VirtualTcpStream,
    limit: usize,
    blocked: bool,
    writes: usize,
    shutdowns: usize,
    flush_interrupts: usize,
}

impl ShortIo {
    fn new(inner: VirtualTcpStream) -> Self {
        Self {
            inner,
            limit: usize::MAX,
            blocked: false,
            writes: 0,
            shutdowns: 0,
            flush_interrupts: 0,
        }
    }
}

impl AsyncRead for ShortIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ShortIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes += 1;
        if self.blocked {
            // Used only in manually driven steps, never with a parked task.
            return Poll::Pending;
        }
        let len = bytes.len().min(self.limit);
        Pin::new(&mut self.inner).poll_write(cx, &bytes[..len])
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.flush_interrupts > 0 {
            self.flush_interrupts -= 1;
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "interrupted flush",
            )));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdowns += 1;
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
        "127.0.0.1:5280".parse().unwrap(),
        "127.0.0.1:5281".parse().unwrap(),
    );
    (
        TlsStream::new_client(
            ShortIo::new(client_io),
            ClientConnection::new(Arc::new(client), ServerName::try_from("localhost").unwrap())
                .unwrap(),
        ),
        TlsStream::new_server(
            ShortIo::new(server_io),
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
            .with_seed(0xB0D6_0001)
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
        }
        test(client, server);
    });
    assert!(runtime.is_quiescent());
}

fn check_budget(stream: &Stream, before: usize) -> usize {
    let writes = stream.io.writes - before;
    assert!(
        writes <= TLS_WRITE_STEPS_PER_POLL,
        "one-byte writes escaped the poll budget: {writes}"
    );
    writes
}

fn flush_to_completion(stream: &mut Stream) {
    // Replacing the waker after an earlier pending poll must wake the new task.
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    let mut cx = Context::from_waker(&waker);
    for _ in 0..1024 {
        let before = stream.io.writes;
        let wakes = count.0.load(Ordering::Relaxed);
        let result = Pin::new(&mut *stream).poll_flush(&mut cx);
        let writes = check_budget(stream, before);
        match result {
            Poll::Ready(result) => {
                result.expect("flush succeeds after cooperative yields");
                assert!(!stream.conn.wants_write());
                assert!(!stream.transport_needs_flush);
                return;
            }
            Poll::Pending => {
                assert_eq!(writes, TLS_WRITE_STEPS_PER_POLL);
                assert!(count.0.load(Ordering::Relaxed) > wakes, "yield lost its wakeup");
                assert!(stream.conn.wants_write());
            }
        }
    }
    panic!("flush did not finish within the test's step bound");
}

fn read_payload(stream: &mut Stream, expected: &[u8]) {
    let mut bytes = vec![0; expected.len()];
    let mut offset = 0;
    let mut cx = Context::from_waker(Waker::noop());
    while offset < bytes.len() {
        let mut buf = ReadBuf::new(&mut bytes[offset..]);
        assert!(matches!(
            Pin::new(&mut *stream).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert!(!buf.filled().is_empty(), "premature EOF");
        offset += buf.filled().len();
    }
    assert_eq!(bytes, expected);
}

fn read_tail(stream: &mut Stream) -> Poll<io::Result<()>> {
    let mut byte = [0];
    let mut buf = ReadBuf::new(&mut byte);
    let mut cx = Context::from_waker(Waker::noop());
    let result = Pin::new(stream).poll_read(&mut cx, &mut buf);
    assert!(buf.filled().is_empty(), "duplicate or cancelled plaintext arrived");
    result
}

#[test]
fn eager_short_handshake_writes_yield_and_preserve_binding_admission() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        run_pair(version, false, move |mut client, mut server| {
            client.io.limit = 1;
            server.io.limit = 1;
            let count = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&count));
            let mut cx = Context::from_waker(&waker);
            let mut yielded = false;
            for _ in 0..1024 {
                for stream in [&mut client, &mut server] {
                    if stream.is_ready() {
                        continue;
                    }
                    let before = stream.io.writes;
                    let wakes = count.0.load(Ordering::Relaxed);
                    let result = stream.poll_handshake(&mut cx);
                    let writes = check_budget(stream, before);
                    if let Poll::Ready(result) = result {
                        result.expect("short-write handshake");
                    }
                    if !stream.is_ready() {
                        assert!(matches!(
                            stream.tls_exporter_channel_binding(),
                            Err(TlsError::Rustls(rustls::Error::HandshakeNotComplete))
                        ));
                        if writes == TLS_WRITE_STEPS_PER_POLL && stream.conn.wants_write() {
                            assert!(count.0.load(Ordering::Relaxed) > wakes);
                            yielded = true;
                        }
                    }
                }
                if client.is_ready() && server.is_ready() {
                    break;
                }
            }
            assert!(yielded, "test never exhausted a write budget");
            assert!(client.is_ready() && server.is_ready());
            assert_eq!(client.protocol_version(), Some(version.version));
            assert_eq!(server.protocol_version(), Some(version.version));
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
fn accepted_plaintext_is_counted_once_across_write_and_flush_yields() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            run_pair(version, true, move |mut client, mut server| {
                let (sender, peer) = if client_side {
                    (&mut client, &mut server)
                } else {
                    (&mut server, &mut client)
                };
                sender.io.limit = 1;
                let binding = sender.tls_exporter_channel_binding().ok();
                let payload = [0xA5; 4096];
                let count = Arc::new(WakeCount::default());
                let waker = Waker::from(Arc::clone(&count));
                let mut cx = Context::from_waker(&waker);
                let before = sender.io.writes;
                assert!(matches!(
                    Pin::new(&mut *sender).poll_write(&mut cx, &payload),
                    Poll::Ready(Ok(n)) if n == payload.len()
                ));
                assert_eq!(check_budget(sender, before), TLS_WRITE_STEPS_PER_POLL);
                assert!(count.0.load(Ordering::Relaxed) > 0);
                assert!(sender.conn.wants_write() && sender.is_ready());
                flush_to_completion(sender);
                read_payload(peer, &payload);
                assert!(read_tail(peer).is_pending());
                assert_eq!(sender.tls_exporter_channel_binding().ok(), binding);
                assert_eq!(peer.tls_exporter_channel_binding().ok(), binding);
            });
        }
    }
}

#[test]
fn yielding_before_plaintext_acceptance_does_not_commit_cancelled_bytes() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            run_pair(version, true, move |mut client, mut server| {
                let (sender, peer) = if client_side {
                    (&mut client, &mut server)
                } else {
                    (&mut server, &mut client)
                };
                match &mut sender.conn {
                    TlsConnection::Client(conn) => conn.set_buffer_limit(Some(512)),
                    TlsConnection::Server(conn) => conn.set_buffer_limit(Some(512)),
                }
                let prefix = [0x3C; 512];
                sender.io.blocked = true;
                let mut cx = Context::from_waker(Waker::noop());
                assert!(matches!(
                    Pin::new(&mut *sender).poll_write(&mut cx, &prefix),
                    Poll::Ready(Ok(n)) if n == prefix.len()
                ));
                assert_eq!(
                    io::Write::write(&mut sender.conn.writer(), b"capacity probe").unwrap(),
                    0
                );
                sender.io.blocked = false;
                sender.io.limit = 1;
                let before = sender.io.writes;
                assert!(
                    Pin::new(&mut *sender)
                        .poll_write(&mut cx, b"cancelled request")
                        .is_pending()
                );
                assert_eq!(check_budget(sender, before), TLS_WRITE_STEPS_PER_POLL);
                // Abandon that unaccepted write and drain the existing prefix.
                // No future retains a borrowed plaintext slice across polls.
                flush_to_completion(sender);
                read_payload(peer, &prefix);
                assert!(read_tail(peer).is_pending());
                let replacement = b"replacement request";
                assert!(matches!(
                    Pin::new(&mut *sender).poll_write(&mut cx, replacement),
                    Poll::Ready(Ok(n)) if n == replacement.len()
                ));
                flush_to_completion(sender);
                read_payload(peer, replacement);
                assert!(read_tail(peer).is_pending());
            });
        }
    }
}

#[test]
fn both_shutdown_apis_yield_without_claiming_early_completion() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            for transport in [true, false] {
                run_pair(version, true, move |mut client, mut server| {
                    let (sender, peer) = if client_side {
                        (&mut client, &mut server)
                    } else {
                        (&mut server, &mut client)
                    };
                    let payload = [0x5A; 4096];
                    sender.io.blocked = true;
                    let mut cx = Context::from_waker(Waker::noop());
                    assert!(matches!(
                        Pin::new(&mut *sender).poll_write(&mut cx, &payload),
                        Poll::Ready(Ok(n)) if n == payload.len()
                    ));
                    sender.io.blocked = false;
                    sender.io.limit = 1;
                    let count = Arc::new(WakeCount::default());
                    let waker = Waker::from(Arc::clone(&count));
                    let mut cx = Context::from_waker(&waker);
                    let mut pending = 0;
                    for _ in 0..1024 {
                        let before = sender.io.writes;
                        let wakes = count.0.load(Ordering::Relaxed);
                        let result = if transport {
                            Pin::new(&mut *sender)
                                .poll_shutdown(&mut cx)
                                .map(|r| r.map_err(TlsError::Io))
                        } else {
                            sender.poll_shutdown_tls(&mut cx)
                        };
                        check_budget(sender, before);
                        assert!(matches!(
                            sender.tls_exporter_channel_binding(),
                            Err(TlsError::Io(e)) if e.kind() == io::ErrorKind::NotConnected
                        ));
                        match result {
                            Poll::Ready(result) => {
                                result.expect("shutdown");
                                break;
                            }
                            Poll::Pending => {
                                pending += 1;
                                assert!(!sender.shutdown_flushed);
                                assert!(sender.conn.wants_write());
                                assert_eq!(sender.io.shutdowns, 0);
                                assert!(count.0.load(Ordering::Relaxed) > wakes);
                            }
                        }
                    }
                    assert!(pending > 0 && sender.shutdown_flushed);
                    assert_eq!(sender.io.shutdowns, usize::from(transport));
                    read_payload(peer, &payload);
                    assert!(matches!(
                        read_tail(peer),
                        Poll::Ready(Ok(()))
                    ));
                });
            }
        }
    }
}

#[test]
fn automatic_handshake_and_application_write_share_one_poll_budget() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            run_pair(version, false, move |mut client, mut server| {
                client.io.limit = 1;
                server.io.limit = 1;
                let payload = [0x6D; 4096];
                let mut accepted = false;
                let mut cx = Context::from_waker(Waker::noop());
                for _ in 0..1024 {
                    let (sender, peer) = if client_side {
                        (&mut client, &mut server)
                    } else {
                        (&mut server, &mut client)
                    };
                    if !accepted {
                        let before = sender.io.writes;
                        if let Poll::Ready(result) =
                            Pin::new(&mut *sender).poll_write(&mut cx, &payload)
                        {
                            assert_eq!(result.unwrap(), payload.len());
                            accepted = true;
                        }
                        check_budget(sender, before);
                    }
                    if !peer.is_ready() {
                        let before = peer.io.writes;
                        if let Poll::Ready(result) = peer.poll_handshake(&mut cx) {
                            result.unwrap();
                        }
                        check_budget(peer, before);
                    }
                    if accepted && peer.is_ready() {
                        break;
                    }
                }
                assert!(accepted && client.is_ready() && server.is_ready());
                let (sender, peer) = if client_side {
                    (&mut client, &mut server)
                } else {
                    (&mut server, &mut client)
                };
                flush_to_completion(sender);
                read_payload(peer, &payload);
                assert!(read_tail(peer).is_pending());
            });
        }
    }
}

#[test]
fn cancellation_interruptions_end_tls_operations_without_retry_wakes() {
    use crate::cx::Cx;
    use crate::types::CancelKind;

    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            for operation in 0..4 {
                run_pair(version, operation != 3, move |mut client, mut server| {
                    let stream = if client_side { &mut client } else { &mut server };
                    let owner = Cx::for_testing();
                    owner.cancel_fast(CancelKind::User);
                    let count = Arc::new(WakeCount::default());
                    let waker = Waker::from(Arc::clone(&count));
                    let mut task = Context::from_waker(&waker);
                    let result = futures_lite::future::block_on(owner.with_ambient(async {
                        match operation {
                            0 => {
                                // VirtualTcpStream itself returns Interrupted
                                // when its real Cx checkpoint sees cancellation.
                                let mut bytes = [0; 1];
                                let mut buf = ReadBuf::new(&mut bytes);
                                Pin::new(&mut *stream).poll_read(&mut task, &mut buf)
                            }
                            1 => {
                                let payload = b"accepted before cancellation is observed";
                                assert!(matches!(
                                    Pin::new(&mut *stream).poll_write(&mut task, payload),
                                    Poll::Ready(Ok(n)) if n == payload.len()
                                ));
                                // Acceptance is still reported exactly once.
                                Pin::new(&mut *stream)
                                    .poll_write(&mut task, payload)
                                    .map(|r| r.map(|_| ()))
                            }
                            2 => {
                                stream.io.flush_interrupts = 1;
                                Pin::new(&mut *stream).poll_flush(&mut task)
                            }
                            _ => stream.poll_handshake(&mut task).map(|r| {
                                r.map_err(|e| match e {
                                    TlsError::Io(error) => error,
                                    other => io::Error::other(other),
                                })
                            }),
                        }
                    }));
                    let Poll::Ready(Err(error)) = result else {
                        panic!("acknowledged cancellation was swallowed as retryable EINTR");
                    };
                    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
                    assert_eq!(
                        error.to_string(),
                        if operation == 2 { "interrupted flush" } else { "cancelled" }
                    );
                    assert_eq!(count.0.load(Ordering::Relaxed), 0);
                    assert!(stream.is_closed());
                    assert!(matches!(
                        stream.tls_exporter_channel_binding(),
                        Err(TlsError::Io(e)) if e.kind() == io::ErrorKind::NotConnected
                    ));
                });
            }
        }
    }
}

#[test]
fn masked_cancellation_keeps_signal_interruptions_retryable() {
    use crate::cx::Cx;
    use crate::types::CancelKind;

    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            run_pair(version, true, move |mut client, mut server| {
                let (sender, peer) = if client_side {
                    (&mut client, &mut server)
                } else {
                    (&mut server, &mut client)
                };
                let binding = sender.tls_exporter_channel_binding().ok();
                let owner = Cx::for_testing();
                owner.cancel_fast(CancelKind::User);
                let count = Arc::new(WakeCount::default());
                let waker = Waker::from(Arc::clone(&count));
                let mut task = Context::from_waker(&waker);
                owner.masked(|| futures_lite::future::block_on(owner.with_ambient(async {
                    sender.io.flush_interrupts = 1;
                    assert!(Pin::new(&mut *sender).poll_flush(&mut task).is_pending());
                    assert!(count.0.load(Ordering::Relaxed) > 0);
                    assert!(sender.is_ready() && sender.write_error.is_none());
                    assert!(matches!(
                        Pin::new(&mut *sender).poll_flush(&mut task),
                        Poll::Ready(Ok(()))
                    ));
                    let payload = b"masked protocol cleanup";
                    assert!(matches!(
                        Pin::new(&mut *sender).poll_write(&mut task, payload),
                        Poll::Ready(Ok(n)) if n == payload.len()
                    ));
                    flush_to_completion(sender);
                    read_payload(peer, payload);
                    assert_eq!(sender.tls_exporter_channel_binding().ok(), binding);
                    assert_eq!(peer.tls_exporter_channel_binding().ok(), binding);
                })));
                assert!(owner.checkpoint().is_err(), "mask escaped its scope");
            });
        }
    }
}
