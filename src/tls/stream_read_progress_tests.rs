//! A write followed by a read must not strand accepted TLS records.
//!
//! Real rustls records, VirtualTcpStream and the production BufWriter provide
//! the data path. Only short writes and transport fault controls are doubles.

#![allow(clippy::pedantic, clippy::nursery)]

use super::{TLS_WRITE_STEPS_PER_POLL, TlsError, TlsStream};
use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite, BufWriter, ReadBuf};
use crate::net::tcp::VirtualTcpStream;
use crate::tls::{CertificateChain, PrivateKey};
use crate::types::CancelKind;
use futures_lite::future::{poll_fn, zip};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

const CERT: &[u8] = include_bytes!("../../tests/fixtures/tls/server.crt");
const KEY: &[u8] = include_bytes!("../../tests/fixtures/tls/server.key");
const REQUEST: &[u8] = &[0x5A; 1024];
const RESPONSE: &[u8] = b"response after the complete request";
type Stream = TlsStream<ProgressIo>;

struct ProgressIo {
    writer: BufWriter<VirtualTcpStream>,
    buffered: bool,
    limit: usize,
    block_write: bool,
    block_flush: bool,
    read_error: Option<io::ErrorKind>,
    write_error: Option<io::ErrorKind>,
    flush_error: Option<io::ErrorKind>,
    reads: usize,
    writes: usize,
    flushes: usize,
    output_waker: Option<Waker>,
}

impl ProgressIo {
    fn new(inner: VirtualTcpStream) -> Self {
        Self {
            writer: BufWriter::with_capacity(32 * 1024, inner),
            buffered: false,
            limit: usize::MAX,
            block_write: false,
            block_flush: false,
            read_error: None,
            write_error: None,
            flush_error: None,
            reads: 0,
            writes: 0,
            flushes: 0,
            output_waker: None,
        }
    }

    fn calls(&self) -> usize {
        self.reads + self.writes + self.flushes
    }

    fn release(&mut self) {
        self.block_write = false;
        self.block_flush = false;
        if let Some(waker) = self.output_waker.take() {
            waker.wake();
        }
    }
}

impl AsyncRead for ProgressIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.reads += 1;
        if let Some(kind) = self.read_error {
            return Poll::Ready(Err(io::Error::new(kind, "read failure")));
        }
        Pin::new(self.writer.get_mut()).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProgressIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes += 1;
        if let Some(kind) = self.write_error {
            return Poll::Ready(Err(io::Error::new(kind, "write failure")));
        }
        if self.block_write {
            self.output_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let bytes = &bytes[..bytes.len().min(self.limit)];
        if self.buffered {
            Pin::new(&mut self.writer).poll_write(cx, bytes)
        } else {
            Pin::new(self.writer.get_mut()).poll_write(cx, bytes)
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flushes += 1;
        if let Some(kind) = self.flush_error {
            return Poll::Ready(Err(io::Error::new(kind, "flush failure")));
        }
        if self.block_flush {
            self.output_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

fn run_pair(
    version: &'static rustls::SupportedProtocolVersion,
    test: impl FnOnce(Stream, Stream) + Send + 'static,
) {
    let mut runtime = LabRuntimeTarget::create_runtime(
        TestConfig::new().with_seed(0xAEAD_0081).with_max_steps(20_000),
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
            .with_protocol_versions(&[version]).unwrap()
            .with_root_certificates(roots).with_no_client_auth();
        let sc = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version]).unwrap()
            .with_no_client_auth().with_single_cert(chain, key).unwrap();
        let (c, s) = VirtualTcpStream::pair(
            "127.0.0.1:5310".parse().unwrap(), "127.0.0.1:5311".parse().unwrap(),
        );
        let mut client = TlsStream::new_client(
            ProgressIo::new(c),
            ClientConnection::new(Arc::new(cc), ServerName::try_from("localhost").unwrap()).unwrap(),
        );
        let mut server = TlsStream::new_server(
            ProgressIo::new(s), ServerConnection::new(Arc::new(sc)).unwrap(),
        );
        let (c, s) = zip(
            poll_fn(|cx| client.poll_handshake(cx)),
            poll_fn(|cx| server.poll_handshake(cx)),
        ).await;
        c.unwrap();
        s.unwrap();
        assert!(client.is_ready() && server.is_ready());
        test(client, server);
    });
    assert!(runtime.is_quiescent());
}

fn read(stream: &mut Stream, bytes: &mut [u8], waker: &Waker) -> Poll<io::Result<usize>> {
    let mut buf = ReadBuf::new(bytes);
    Pin::new(stream).poll_read(&mut Context::from_waker(waker), &mut buf)
        .map(|result| result.map(|()| buf.filled().len()))
}

fn queue(stream: &mut Stream, bytes: &[u8]) {
    assert!(matches!(
        Pin::new(stream).poll_write(&mut Context::from_waker(Waker::noop()), bytes),
        Poll::Ready(Ok(n)) if n == bytes.len()
    ));
}

fn binding(stream: &Stream) -> Option<[u8; 32]> {
    match stream.tls_exporter_channel_binding() {
        Ok(bytes) => Some(bytes),
        Err(TlsError::Configuration(_)) => {
            assert_eq!(stream.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_2));
            None
        }
        other => panic!("unexpected binding result: {other:?}"),
    }
}

// Deliberately bounded driver: after initial acceptance the requester ONLY
// reads. Separate counted-waker tests below verify wake delivery, not just
// eventual progress under this driver's deterministic repolling.
fn finish_request_reply(requester: &mut Stream, responder: &mut Stream) {
    let mut received = Vec::new();
    let mut reply = Vec::new();
    let mut sent_reply = false;
    for _ in 0..2048 {
        let mut bytes = [0; 128];
        if let Poll::Ready(result) = read(requester, &mut bytes, Waker::noop()) {
            let n = result.unwrap();
            assert!(n > 0, "reply was truncated");
            reply.extend_from_slice(&bytes[..n]);
        }
        if received.len() < REQUEST.len()
            && let Poll::Ready(result) = read(responder, &mut bytes, Waker::noop())
        {
            let n = result.unwrap();
            assert!(n > 0, "request was truncated");
            received.extend_from_slice(&bytes[..n]);
        }
        if received.len() == REQUEST.len() && !sent_reply {
            assert_eq!(received, REQUEST);
            queue(responder, RESPONSE);
            assert!(matches!(Pin::new(&mut *responder)
                .poll_flush(&mut Context::from_waker(Waker::noop())), Poll::Ready(Ok(()))));
            sent_reply = true;
        }
        if reply.len() >= RESPONSE.len() {
            break;
        }
    }
    assert_eq!(received, REQUEST, "request never left TLS/transport buffering");
    assert_eq!(reply, RESPONSE);
    assert!(!requester.conn.wants_write());
    assert!(!requester.transport_needs_flush);
    assert!(requester.io.writer.buffer().is_empty());
    assert!(read(responder, &mut [0; 1], Waker::noop()).is_pending(), "duplicated request");
    assert_eq!(binding(requester), binding(responder));
    let output_calls = requester.io.writes + requester.io.flushes;
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    for _ in 0..3 {
        assert!(read(requester, &mut [0; 1], &waker).is_pending());
    }
    assert_eq!(requester.io.writes + requester.io.flushes, output_calls);
    assert_eq!(count.0.load(Ordering::SeqCst), 0, "idle reads must not spin");
}

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

#[test]
fn a_response_read_drives_prior_short_blocked_and_buffered_writes() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_requests in [true, false] {
            for mode in 0..4 {
                run_pair(version, move |mut client, mut server| {
                    let (requester, responder) = if client_requests {
                        (&mut client, &mut server)
                    } else { (&mut server, &mut client) };
                    let before = binding(requester);
                    requester.io.limit = if mode == 0 { 1 } else { usize::MAX };
                    requester.io.block_write = mode == 1;
                    requester.io.buffered = mode >= 2;
                    queue(requester, REQUEST);
                    if mode < 2 {
                        assert!(requester.conn.wants_write(), "must witness queued ciphertext");
                    } else {
                        assert!(!requester.conn.wants_write());
                        assert!(!requester.io.writer.buffer().is_empty());
                    }
                    if mode == 3 {
                        requester.io.block_flush = true;
                        let count = Arc::new(WakeCount::default());
                        let waker = Waker::from(Arc::clone(&count));
                        assert!(read(requester, &mut [0; 1], &waker).is_pending());
                        assert!(requester.io.output_waker.is_some(), "read must park on flush");
                        requester.io.release();
                        assert!(count.0.load(Ordering::SeqCst) > 0);
                    } else {
                        requester.io.release();
                    }
                    finish_request_reply(requester, responder);
                    assert_eq!(binding(requester), before);
                });
            }
        }
    }
}

#[test]
fn read_draining_keeps_its_budget_and_wakes_replacement_readers() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_requests in [true, false] {
            run_pair(version, move |mut client, mut server| {
                let (stream, _) = if client_requests { (&mut client, &mut server) }
                    else { (&mut server, &mut client) };
                stream.io.limit = 1;
                queue(stream, REQUEST);
                let old = Arc::new(WakeCount::default());
                let new = Arc::new(WakeCount::default());
                for count in [&old, &new] {
                    let waker = Waker::from(Arc::clone(count));
                    let writes = stream.io.writes;
                    assert!(read(stream, &mut [0; 1], &waker).is_pending());
                    assert_eq!(stream.io.writes - writes, TLS_WRITE_STEPS_PER_POLL);
                    assert!(stream.conn.wants_write());
                    assert_eq!(count.0.load(Ordering::SeqCst), 1);
                }
                assert_eq!(old.0.load(Ordering::SeqCst), 1);
                assert!(stream.is_ready());
            });
        }
    }
}

#[test]
fn readable_plaintext_does_not_wait_for_the_blocked_write_direction() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_reads in [true, false] {
            run_pair(version, move |mut client, mut server| {
                let (stream, peer) = if client_reads { (&mut client, &mut server) }
                    else { (&mut server, &mut client) };
                stream.io.block_write = true;
                queue(stream, REQUEST);
                queue(peer, RESPONSE);
                let writes = stream.io.writes;
                let mut bytes = [0; 128];
                let Poll::Ready(Ok(n)) = read(stream, &mut bytes, Waker::noop()) else {
                    panic!("incoming plaintext was blocked by unrelated outgoing work");
                };
                assert_eq!(&bytes[..n], RESPONSE);
                assert_eq!(stream.io.writes, writes);
                assert!(stream.conn.wants_write());
                assert_eq!(binding(stream), binding(peer));
            });
        }
    }
}

#[test]
fn output_failure_during_a_pending_read_is_sticky_and_revokes_bindings() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_reads in [true, false] {
            for mode in 0..3 {
                run_pair(version, move |mut client, mut server| {
                    let (stream, _) = if client_reads { (&mut client, &mut server) }
                        else { (&mut server, &mut client) };
                    stream.io.block_write = mode != 2;
                    stream.io.buffered = mode == 2;
                    queue(stream, REQUEST);
                    stream.io.release();
                    let kind = match mode {
                        0 => { stream.io.limit = 0; io::ErrorKind::WriteZero }
                        1 => { stream.io.write_error = Some(io::ErrorKind::ConnectionReset);
                            io::ErrorKind::ConnectionReset }
                        _ => { stream.io.flush_error = Some(io::ErrorKind::BrokenPipe);
                            io::ErrorKind::BrokenPipe }
                    };
                    assert!(matches!(read(stream, &mut [0; 1], Waker::noop()),
                        Poll::Ready(Err(error)) if error.kind() == kind));
                    assert!(stream.is_closed());
                    stream.io.limit = usize::MAX;
                    stream.io.write_error = None;
                    stream.io.flush_error = None;
                    let calls = stream.io.calls();
                    for _ in 0..3 {
                        assert!(matches!(read(stream, &mut [0; 1], Waker::noop()),
                            Poll::Ready(Err(error)) if error.kind() == kind));
                        assert!(matches!(stream.tls_exporter_channel_binding(),
                            Err(TlsError::Io(error)) if error.kind() == io::ErrorKind::NotConnected));
                        assert!(matches!(Pin::new(&mut *stream)
                            .poll_flush(&mut Context::from_waker(Waker::noop())),
                            Poll::Ready(Err(error)) if error.kind() == kind));
                        assert_eq!(stream.io.calls(), calls);
                    }
                });
            }
        }
    }
}

#[test]
fn read_failure_and_empty_reads_do_not_publish_buffered_output() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_reads in [true, false] {
            run_pair(version, move |mut client, mut server| {
                let (stream, peer) = if client_reads { (&mut client, &mut server) }
                    else { (&mut server, &mut client) };
                stream.io.buffered = true;
                queue(stream, REQUEST);
                let buffered = stream.io.writer.buffer().to_vec();
                assert!(!buffered.is_empty());
                let calls = stream.io.calls();
                assert!(matches!(read(stream, &mut [], Waker::noop()), Poll::Ready(Ok(0))));
                assert_eq!(stream.io.calls(), calls);
                stream.io.read_error = Some(io::ErrorKind::ConnectionReset);
                let output_calls = stream.io.writes + stream.io.flushes;
                assert!(matches!(read(stream, &mut [0; 1], Waker::noop()),
                    Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset));
                assert_eq!(stream.io.writes + stream.io.flushes, output_calls);
                assert_eq!(stream.io.writer.buffer(), buffered);
                assert!(read(peer, &mut [0; 1], Waker::noop()).is_pending());
            });
        }
    }
}

#[test]
fn cancelling_a_read_retains_the_outgoing_prefix_for_the_next_reader() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_reads in [true, false] {
            run_pair(version, move |mut client, mut server| {
                let (stream, peer) = if client_reads { (&mut client, &mut server) }
                    else { (&mut server, &mut client) };
                stream.io.limit = 1;
                queue(stream, REQUEST);
                let before = binding(stream);
                let owner = Cx::for_testing();
                let mut bytes = [0xA5; 64];
                let mut wait = Box::pin(stream.read_with_cx(&owner, &mut bytes));
                assert!(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
                owner.cancel_fast(CancelKind::User);
                assert!(matches!(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted));
                drop(wait);
                assert_eq!(bytes, [0xA5; 64]);
                assert!(stream.is_ready() && stream.conn.wants_write());
                assert_eq!(binding(stream), before);
                finish_request_reply(stream, peer);
                assert_eq!(binding(stream), before);
            });
        }
    }
}
