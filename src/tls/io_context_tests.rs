//! Borrowed context waits retain TLS progress, byte results, and half-close state.

#![allow(clippy::pedantic, clippy::nursery)]

use super::*;
use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
use crate::io::{BufWriter, ReadBuf};
use crate::net::tcp::VirtualTcpStream;
use crate::tls::{CertificateChain, PrivateKey, TlsAcceptor, TlsConnector};
use crate::types::CancelKind;
use futures_lite::future::zip;
use rustls::{ClientConfig, ServerConfig};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

type Stream = TlsStream<ProbeIo>;
const CERT: &[u8] = include_bytes!("../../tests/fixtures/tls/server.crt");
const KEY: &[u8] = include_bytes!("../../tests/fixtures/tls/server.key");
const MESSAGE: &[u8] = b"a completed TLS write must be counted exactly once";

#[derive(Default)]
struct Probe {
    calls: AtomicUsize,
    dropped: AtomicUsize,
    parked: AtomicBool,
    block_read: AtomicBool,
    block_write: AtomicBool,
    block_flush: AtomicBool,
    block_shutdown: AtomicBool,
    waker: std::sync::Mutex<Option<Waker>>,
    cancel_on_read: std::sync::Mutex<Option<Cx>>,
    cancel_on_write: std::sync::Mutex<Option<Cx>>,
    cancel_on_pending: std::sync::Mutex<Option<Cx>>,
    read_error: std::sync::Mutex<Option<io::ErrorKind>>,
}

impl Probe {
    fn park<T>(&self, task: &Context<'_>) -> Poll<io::Result<T>> {
        *self.waker.lock().unwrap() = Some(task.waker().clone());
        self.parked.store(true, Ordering::Release);
        let cancel = self.cancel_on_pending.lock().unwrap().take();
        if let Some(cx) = cancel {
            cx.cancel_fast(CancelKind::User);
        }
        Poll::Pending
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn rescue(&self) {
        *self.read_error.lock().unwrap() = Some(io::ErrorKind::ConnectionAborted);
        let waker = self.waker.lock().unwrap().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

// Fault injection is explicit. Buffering, partial flush progress, records and
// endpoint delivery use the production BufWriter, VirtualTcpStream and rustls.
struct ProbeIo {
    writer: BufWriter<VirtualTcpStream>,
    probe: Arc<Probe>,
}

impl ProbeIo {
    fn new(inner: VirtualTcpStream) -> Self {
        Self {
            writer: BufWriter::with_capacity(32 * 1024, inner),
            probe: Arc::new(Probe::default()),
        }
    }
}

impl AsyncRead for ProbeIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        task: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.probe.calls.fetch_add(1, Ordering::SeqCst);
        let failure = *self.probe.read_error.lock().unwrap();
        let result = if let Some(kind) = failure {
            Poll::Ready(Err(io::Error::new(kind, "injected transport failure")))
        } else if self.probe.block_read.load(Ordering::Acquire) {
            return self.probe.park(task);
        } else {
            Pin::new(self.writer.get_mut()).poll_read(task, buf)
        };
        if result.is_ready() {
            let cancel = self.probe.cancel_on_read.lock().unwrap().take();
            if let Some(cx) = cancel {
                cx.cancel_fast(CancelKind::User);
            }
        } else {
            return self.probe.park(task);
        }
        result
    }
}

impl AsyncWrite for ProbeIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        task: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.probe.calls.fetch_add(1, Ordering::SeqCst);
        if self.probe.block_write.load(Ordering::Acquire) {
            return self.probe.park(task);
        }
        let result = Pin::new(&mut self.writer).poll_write(task, bytes);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            let cancel = self.probe.cancel_on_write.lock().unwrap().take();
            if let Some(cx) = cancel {
                cx.cancel_fast(CancelKind::User);
            }
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.probe.calls.fetch_add(1, Ordering::SeqCst);
        if self.probe.block_flush.load(Ordering::Acquire) {
            return self.probe.park(task);
        }
        Pin::new(&mut self.writer).poll_flush(task)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.probe.calls.fetch_add(1, Ordering::SeqCst);
        if self.probe.block_shutdown.load(Ordering::Acquire) {
            return self.probe.park(task);
        }
        Pin::new(&mut self.writer).poll_shutdown(task)
    }
}

impl Drop for ProbeIo {
    fn drop(&mut self) {
        self.probe.dropped.fetch_add(1, Ordering::SeqCst);
        self.probe.waker.lock().unwrap().take();
    }
}

async fn establish(version: &'static rustls::SupportedProtocolVersion) -> (Stream, Stream) {
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
    let connector = TlsConnector::new(client);
    let acceptor = TlsAcceptor::new(server);
    let (c, s) = VirtualTcpStream::pair(
        "127.0.0.1:5310".parse().unwrap(),
        "127.0.0.1:5311".parse().unwrap(),
    );
    let (c, s) = zip(
        connector.connect("localhost", ProbeIo::new(c)),
        acceptor.accept(ProbeIo::new(s)),
    )
    .await;
    let c = c.unwrap();
    let s = s.unwrap();
    for stream in [&c, &s] {
        assert!(stream.is_ready());
        assert_eq!(stream.protocol_version(), Some(version.version));
        assert!(stream.get_ref().writer.buffer().is_empty());
    }
    (c, s)
}

// All virtual transport progress is in this process. Bound manual completion
// rather than blocking the test forever on a lost byte; wake behavior has
// separate counted-waker and native-scheduler regressions below.
fn finish<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut task = Context::from_waker(Waker::noop());
    for _ in 0..4096 {
        if let Poll::Ready(result) = future.as_mut().poll(&mut task) {
            return result;
        }
    }
    panic!("virtual TLS operation exceeded its bounded completion driver");
}

fn run_pair(
    version: &'static rustls::SupportedProtocolVersion,
    test: impl FnOnce(Stream, Stream) + Send + 'static,
) {
    let mut runtime = LabRuntimeTarget::create_runtime(
        TestConfig::new().with_seed(0xC710_0001).with_max_steps(20_000),
    );
    LabRuntimeTarget::block_on(&mut runtime, async move {
        let (client, server) = establish(version).await;
        test(client, server);
    });
    assert!(runtime.is_quiescent());
}

fn binding(stream: &Stream) -> Option<[u8; 32]> {
    if stream.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3) {
        Some(stream.tls_exporter_channel_binding().unwrap())
    } else {
        assert!(matches!(stream.tls_exporter_channel_binding(), Err(TlsError::Configuration(_))));
        None
    }
}

#[derive(Clone, Copy, Debug)]
enum Operation {
    Read,
    Write,
    Flush,
    TlsShutdown,
    Shutdown,
}

type Wait<'a> = Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>>;

fn begin<'a>(
    op: Operation,
    stream: &'a mut Stream,
    cx: &'a Cx,
    buf: &'a mut [u8],
) -> Wait<'a> {
    Box::pin(async move {
        match op {
            Operation::Read => stream.read_with_cx(cx, buf).await,
            Operation::Write => stream.write_with_cx(cx, MESSAGE).await,
            Operation::Flush => stream.flush_with_cx(cx).await.map(|()| 0),
            Operation::Shutdown => stream.shutdown_with_cx(cx).await.map(|()| 0),
            Operation::TlsShutdown => stream.shutdown_tls_with_cx(cx).await
                .map(|()| 0)
                .map_err(|error| match error {
                    TlsError::Io(error) => error,
                    other => io::Error::other(other),
                }),
        }
    })
}

fn assert_cancelled<T>(result: Poll<io::Result<T>>) {
    match result {
        Poll::Ready(Err(error)) => {
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert_eq!(error.to_string(), "TLS I/O wait cancelled");
        }
        _ => panic!("pending I/O must return its context cancellation"),
    }
}

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

async fn receive(stream: &mut Stream, cx: &Cx, length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    let mut filled = 0;
    while filled < length {
        let n = stream.read_with_cx(cx, &mut bytes[filled..]).await.unwrap();
        assert!(n > 0, "EOF before accepted plaintext arrived");
        filled += n;
    }
    bytes
}

fn send(stream: &mut Stream, bytes: &[u8]) {
    let cx = Cx::for_testing();
    finish(async {
        let n = stream.write_with_cx(&cx, bytes).await.unwrap();
        assert_eq!(n, bytes.len());
        stream.flush_with_cx(&cx).await.unwrap();
    });
}

#[test]
fn pre_cancelled_io_waits_do_not_touch_or_close_an_established_stream() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            run_pair(version, move |mut client, mut server| {
                let stream = if client_side { &mut client } else { &mut server };
                let before = binding(stream);
                let probe = Arc::clone(&stream.get_ref().probe);
                let calls = probe.calls();
                let cx = Cx::for_testing();
                cx.cancel_fast(CancelKind::User);
                for op in [Operation::Read, Operation::Write, Operation::Flush,
                    Operation::TlsShutdown, Operation::Shutdown] {
                    let mut bytes = [0xA5; 64];
                    let mut wait = begin(op, stream, &cx, &mut bytes);
                    assert_cancelled(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())));
                    drop(wait);
                    assert_eq!(bytes, [0xA5; 64]);
                    assert_eq!(probe.calls(), calls);
                    assert_eq!(probe.dropped.load(Ordering::SeqCst), 0);
                    assert!(stream.is_ready());
                    assert_eq!(binding(stream), before);
                }
            });
        }
    }
}

#[test]
fn parked_read_observes_cancellation_and_replacement_wakers_without_losing_data() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            run_pair(version, move |mut client, mut server| {
                let (stream, peer) = if client_side { (&mut client, &mut server) }
                    else { (&mut server, &mut client) };
                let before = binding(stream);
                let probe = Arc::clone(&stream.get_ref().probe);
                let cx = Cx::for_testing();
                let old = Arc::new(WakeCount::default());
                let new = Arc::new(WakeCount::default());
                let old_waker = Waker::from(Arc::clone(&old));
                let new_waker = Waker::from(Arc::clone(&new));
                let mut bytes = [0xA5; 64];
                let mut wait = Box::pin(stream.read_with_cx(&cx, &mut bytes));
                assert!(wait.as_mut().poll(&mut Context::from_waker(&old_waker)).is_pending());
                assert!(wait.as_mut().poll(&mut Context::from_waker(&new_waker)).is_pending());
                assert!(probe.parked.load(Ordering::Acquire));
                let calls = probe.calls();
                let old_count = old.0.load(Ordering::SeqCst);
                let new_count = new.0.load(Ordering::SeqCst);
                cx.cancel_fast(CancelKind::User);
                assert_eq!(old.0.load(Ordering::SeqCst), old_count);
                assert!(new.0.load(Ordering::SeqCst) > new_count, "cancel must wake before repoll");
                assert_cancelled(wait.as_mut().poll(&mut Context::from_waker(&new_waker)));
                drop(wait);
                assert_eq!(probe.calls(), calls);
                assert_eq!(bytes, [0xA5; 64]);
                assert_eq!(binding(stream), before);
                send(peer, MESSAGE);
                let fresh = Cx::for_testing();
                assert_eq!(finish(receive(stream, &fresh, MESSAGE.len())), MESSAGE);
                assert_eq!(binding(stream), before);
                assert_eq!(probe.dropped.load(Ordering::SeqCst), 0);
            });
        }
    }
}

#[test]
fn pending_flush_and_shutdown_cancellation_preserves_buffered_records() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            for (op, stop_in_flush) in [(Operation::Flush, true),
                (Operation::TlsShutdown, true), (Operation::Shutdown, true),
                (Operation::Shutdown, false)] {
                run_pair(version, move |mut client, mut server| {
                    let (stream, peer) = if client_side { (&mut client, &mut server) }
                        else { (&mut server, &mut client) };
                    let before = binding(stream);
                    let probe = Arc::clone(&stream.get_ref().probe);
                    let fresh = Cx::for_testing();
                    assert_eq!(finish(stream.write_with_cx(&fresh, MESSAGE)).unwrap(), MESSAGE.len());
                    assert!(!stream.get_ref().writer.buffer().is_empty());
                    probe.block_flush.store(stop_in_flush, Ordering::Release);
                    probe.block_shutdown.store(!stop_in_flush, Ordering::Release);
                    let owner = Cx::for_testing();
                    let mut bytes = [0; 1];
                    let mut wait = begin(op, stream, &owner, &mut bytes);
                    assert!(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
                    let calls = probe.calls();
                    owner.cancel_fast(CancelKind::User);
                    assert_cancelled(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())));
                    drop(wait);
                    assert_eq!(probe.calls(), calls);
                    assert_eq!(probe.dropped.load(Ordering::SeqCst), 0);
                    if stop_in_flush {
                        assert!(!stream.get_ref().writer.buffer().is_empty());
                    }
                    probe.block_flush.store(false, Ordering::Release);
                    probe.block_shutdown.store(false, Ordering::Release);
                    finish(begin(op, stream, &fresh, &mut bytes)).unwrap();
                    assert_eq!(finish(receive(peer, &fresh, MESSAGE.len())), MESSAGE);
                    let mut extra = [0; 1];
                    if matches!(op, Operation::Flush) {
                        let mut task = Context::from_waker(Waker::noop());
                        let mut buf = ReadBuf::new(&mut extra);
                        assert!(Pin::new(&mut *peer).poll_read(&mut task, &mut buf).is_pending());
                        assert!(buf.filled().is_empty(), "plaintext was duplicated");
                        assert_eq!(binding(stream), before);
                    } else {
                        assert_eq!(finish(peer.read_with_cx(&fresh, &mut extra)).unwrap(), 0);
                        assert!(matches!(stream.tls_exporter_channel_binding(),
                            Err(TlsError::Io(error)) if error.kind() == io::ErrorKind::NotConnected));
                        assert!(finish(stream.write_with_cx(&fresh, b"closed")).is_err());
                    }
                });
            }
        }
    }
}

#[test]
fn cancelling_an_unaccepted_write_does_not_resubmit_or_lose_earlier_bytes() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            run_pair(version, move |mut client, mut server| {
                let (stream, peer) = if client_side { (&mut client, &mut server) }
                    else { (&mut server, &mut client) };
                let probe = Arc::clone(&stream.get_ref().probe);
                probe.block_write.store(true, Ordering::Release);
                let mut accepted = Vec::<u8>::new();
                let mut full = false;
                let mut task = Context::from_waker(Waker::noop());
                for _ in 0..128 {
                    match Pin::new(&mut *stream).poll_write(&mut task, &[0x44; 4096]) {
                        Poll::Ready(Ok(n)) => {
                            assert!(n > 0);
                            accepted.extend(std::iter::repeat_n(0x44, n));
                        }
                        Poll::Pending => { full = true; break; }
                        Poll::Ready(Err(error)) => panic!("buffer admission: {error}"),
                    }
                }
                assert!(full && !accepted.is_empty(), "must witness real rustls backpressure");
                let owner = Cx::for_testing();
                let mut bytes = [0; 1];
                let mut wait = begin(Operation::Write, stream, &owner, &mut bytes);
                assert!(wait.as_mut().poll(&mut task).is_pending());
                owner.cancel_fast(CancelKind::User);
                assert_cancelled(wait.as_mut().poll(&mut task));
                drop(wait);
                probe.block_write.store(false, Ordering::Release);
                let send_cx = Cx::for_testing();
                let read_cx = Cx::for_testing();
                let (flushed, received) = finish(zip(
                    stream.flush_with_cx(&send_cx),
                    receive(peer, &read_cx, accepted.len()),
                ));
                flushed.unwrap();
                assert_eq!(received, accepted);
                let mut buf = ReadBuf::new(&mut bytes);
                assert!(Pin::new(&mut *peer).poll_read(&mut task, &mut buf).is_pending());
                assert!(buf.filled().is_empty(), "cancelled write was accepted or bytes duplicated");
                assert_eq!(binding(stream), binding(peer));
            });
        }
    }
}

#[test]
fn completed_reads_writes_and_errors_are_not_replaced_by_racing_cancellation() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for client_side in [true, false] {
            run_pair(version, move |mut client, mut server| {
                let (stream, peer) = if client_side { (&mut client, &mut server) }
                    else { (&mut server, &mut client) };
                let probe = Arc::clone(&stream.get_ref().probe);
                let writer_cx = Cx::for_testing();
                *probe.cancel_on_write.lock().unwrap() = Some(writer_cx.clone());
                assert_eq!(finish(stream.write_with_cx(&writer_cx, MESSAGE)).unwrap(), MESSAGE.len());
                assert!(writer_cx.is_cancel_requested());
                let fresh = Cx::for_testing();
                finish(stream.flush_with_cx(&fresh)).unwrap();
                assert_eq!(finish(receive(peer, &fresh, MESSAGE.len())), MESSAGE);
                send(peer, MESSAGE);
                let reader_cx = Cx::for_testing();
                *probe.cancel_on_read.lock().unwrap() = Some(reader_cx.clone());
                let mut bytes = [0; 128];
                let n = finish(stream.read_with_cx(&reader_cx, &mut bytes)).unwrap();
                assert_eq!(&bytes[..n], MESSAGE);
                assert!(reader_cx.is_cancel_requested());
                assert_eq!(binding(stream), binding(peer));
                let error_cx = Cx::for_testing();
                *probe.cancel_on_read.lock().unwrap() = Some(error_cx.clone());
                *probe.read_error.lock().unwrap() = Some(io::ErrorKind::ConnectionReset);
                let error = finish(stream.read_with_cx(&error_cx, &mut bytes)).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
                assert_eq!(error.to_string(), "injected transport failure");
                assert!(stream.is_closed());
            });
        }
    }
}

#[test]
fn dropping_a_parked_wait_retires_its_observer_but_not_the_tls_stream() {
    run_pair(&rustls::version::TLS13, |mut client, mut server| {
        let owner = Cx::for_testing();
        let probe = Arc::clone(&client.get_ref().probe);
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&count));
        let mut bytes = [0; 64];
        let mut wait = Box::pin(client.read_with_cx(&owner, &mut bytes));
        assert!(wait.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        drop(wait);
        let wakes = count.0.load(Ordering::SeqCst);
        owner.cancel_fast(CancelKind::User);
        assert_eq!(count.0.load(Ordering::SeqCst), wakes, "dropped wait leaked a cancellation observer");
        assert_eq!(probe.dropped.load(Ordering::SeqCst), 0);
        send(&mut server, MESSAGE);
        assert_eq!(finish(receive(&mut client, &Cx::for_testing(), MESSAGE.len())), MESSAGE);
    });
}

#[test]
fn masks_and_restricted_resumes_preserve_the_context_io_boundary() {
    run_pair(&rustls::version::TLS13, |mut client, mut server| {
        let owner = Cx::for_testing();
        owner.cancel_fast(CancelKind::User);
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&count));
        let mut bytes = [0; 64];
        let mut wait = Box::pin(client.read_with_cx(&owner, &mut bytes));
        owner.masked(|| {
            for _ in 0..3 {
                assert!(wait.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
            }
        });
        assert_eq!(count.0.load(Ordering::SeqCst), 0, "masked wait must not busy-wake");
        assert_cancelled(wait.as_mut().poll(&mut Context::from_waker(&waker)));
        drop(wait);
        send(&mut server, MESSAGE);
        let n = owner.masked(|| finish(client.read_with_cx(&owner, &mut bytes))).unwrap();
        assert_eq!(&bytes[..n], MESSAGE);

        let owner = Cx::for_testing();
        let probe = Arc::clone(&client.get_ref().probe);
        let mut wait = Box::pin(client.read_with_cx(&owner, &mut bytes));
        assert!(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        let calls = probe.calls();
        let restricted = Cx::detached_cancel_context();
        let result = finish(restricted.with_ambient(poll_fn(|task| wait.as_mut().poll(task))));
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::PermissionDenied));
        drop(wait);
        assert_eq!(probe.calls(), calls);
        assert!(client.is_ready());
        assert_eq!(binding(&client), binding(&server));
    });
}

#[test]
fn cancellation_inside_the_first_pending_poll_cannot_be_lost() {
    run_pair(&rustls::version::TLS13, |mut client, _server| {
        let owner = Cx::for_testing();
        let probe = Arc::clone(&client.get_ref().probe);
        probe.block_read.store(true, Ordering::Release);
        *probe.cancel_on_pending.lock().unwrap() = Some(owner.clone());
        let mut bytes = [0xA5; 64];
        let mut wait = Box::pin(client.read_with_cx(&owner, &mut bytes));
        assert_cancelled(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())));
        drop(wait);
        assert!(probe.parked.load(Ordering::Acquire));
        assert_eq!(bytes, [0xA5; 64]);
        assert!(client.is_ready());
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_abort_joins_an_established_parked_tls_read_without_an_io_event() {
    use crate::runtime::{RuntimeBuilder, reactor::create_reactor, yield_now};
    use std::time::Duration;

    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .build()
        .unwrap();
    runtime.block_on(runtime.handle().spawn(async {
        let parent = Cx::current().expect("native task context");
        for client_side in [true, false] {
            let (client, server) = establish(&rustls::version::TLS13).await;
            let (mut stream, _peer) = if client_side { (client, server) } else { (server, client) };
            let probe = Arc::clone(&stream.get_ref().probe);
            probe.parked.store(false, Ordering::Release);
            probe.block_read.store(true, Ordering::Release);
            let mut child = parent.spawn(move |child_cx| async move {
                let mut bytes = [0; 64];
                stream.read_with_cx(&child_cx, &mut bytes).await
            }).unwrap();
            for _ in 0..1024 {
                if probe.parked.load(Ordering::Acquire) { break; }
                yield_now().await;
            }
            assert!(probe.parked.load(Ordering::Acquire), "must witness the child's Pending read");
            let calls = probe.calls();
            child.abort();
            let result = crate::time::timeout(
                parent.now(), Duration::from_secs(2), child.join(&parent),
            ).await;
            if result.is_err() {
                probe.rescue();
                let _ = crate::time::timeout(
                    parent.now(), Duration::from_secs(2), child.join(&parent),
                ).await;
                panic!("cancelled TLS read waited for transport readiness");
            }
            assert!(matches!(result, Ok(Ok(Err(error)))
                if error.kind() == io::ErrorKind::Interrupted
                    && error.to_string() == "TLS I/O wait cancelled"));
            assert_eq!(probe.calls(), calls);
            assert_eq!(probe.dropped.load(Ordering::SeqCst), 1);
        }
    }));
}
