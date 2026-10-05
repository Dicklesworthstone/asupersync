//! Real native TCP journeys. The peer uses this crate's H2/message codecs,
//! so these are lifecycle/flow-control regressions, not independent conformance.

use super::*;
use crate::bytes::{Bytes, BytesMut};
use crate::codec::Decoder as _;
use crate::grpc::{Channel, FramedCodec, IdentityCodec, MetadataValue};
use crate::http::h2::connection::{CLIENT_PREFACE, ReceivedFrame};
use crate::http::h2::{Connection, FrameCodec, Header, Settings};
use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
use crate::types::{CancelKind, TaskId};
use std::collections::VecDeque;
use std::future::Future;
use std::io::{Read, Write};
use std::marker::PhantomPinned;
use std::net::{SocketAddr, TcpListener};
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::Waker;
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(8);
const MESSAGE_BYTES: usize = 128 * 1024;

#[derive(Default)]
struct Gate {
    open: AtomicBool,
    waiter: Mutex<Option<Waker>>,
}

impl Gate {
    fn release(&self) {
        self.open.store(true, Ordering::SeqCst);
        let waiter = self.waiter.lock().unwrap().take();
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }

    fn poll(&self, task: &mut Context<'_>) -> bool {
        if self.open.load(Ordering::SeqCst) {
            return true;
        }
        *self.waiter.lock().unwrap() = Some(task.waker().clone());
        self.open.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
struct SourceStats {
    produced: AtomicUsize,
    eof: AtomicUsize,
    dropped: AtomicUsize,
}

struct SourceState {
    items: VecDeque<Result<Bytes, Status>>,
    parked: Option<mpsc::Sender<()>>,
    address: Option<usize>,
}

struct Source<'a> {
    label: &'a str,
    owner: TaskId,
    gate: Arc<Gate>,
    state: Mutex<SourceState>,
    stats: Arc<SourceStats>,
    _pin: PhantomPinned,
}

impl Streaming for Source<'_> {
    type Message = Bytes;

    fn poll_next(self: Pin<&mut Self>, task: &mut Context<'_>)
        -> Poll<Option<Result<Bytes, Status>>>
    {
        let this = self.as_ref().get_ref();
        assert!(!this.label.is_empty());
        assert_eq!(Cx::current().unwrap().task_id(), this.owner);
        let mut state = this.state.lock().unwrap();
        let address = std::ptr::from_ref(this).addr();
        if let Some(previous) = state.address.replace(address) {
            assert_eq!(previous, address, "pinned producer moved");
        }
        if !this.gate.poll(task) {
            if let Some(parked) = state.parked.take() {
                parked.send(()).unwrap();
            }
            return Poll::Pending;
        }
        assert_eq!(this.stats.eof.load(Ordering::SeqCst), 0, "producer repolled after EOF");
        if let Some(item) = state.items.pop_front() {
            this.stats.produced.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Some(item))
        } else {
            this.stats.eof.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(None)
        }
    }
}

impl Drop for Source<'_> {
    fn drop(&mut self) {
        assert_eq!(Cx::current().unwrap().task_id(), self.owner);
        if let Some(address) = self.state.lock().unwrap().address {
            assert_eq!(address, std::ptr::from_ref(self).addr());
        }
        self.stats.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

fn source<'a>(label: &'a str, owner: &Cx, parked: mpsc::Sender<()>,
    items: VecDeque<Result<Bytes, Status>>) -> (Source<'a>, Arc<Gate>, Arc<SourceStats>)
{
    let gate = Arc::new(Gate::default());
    let stats = Arc::new(SourceStats::default());
    let source = Source {
        label, owner: owner.task_id(), gate: Arc::clone(&gate),
        state: Mutex::new(SourceState { items, parked: Some(parked), address: None }),
        stats: Arc::clone(&stats), _pin: PhantomPinned,
    };
    (source, gate, stats)
}

#[derive(Clone, Copy)]
struct Reply {
    messages: usize,
    status: Option<&'static str>,
    early: bool,
    hold_trailers: bool,
    trailers_only: bool,
}

impl Reply {
    fn normal(messages: usize, status: Option<&'static str>) -> Self {
        Self { messages, status, early: false, hold_trailers: false, trailers_only: false }
    }

    fn held() -> Self {
        Self { early: true, hold_trailers: true, ..Self::normal(1, Some("0")) }
    }
}

struct Peer {
    address: SocketAddr,
    finish: mpsc::Sender<bool>,
    worker: std::thread::JoinHandle<(usize, bool)>,
}

fn flush(socket: &mut std::net::TcpStream, connection: &mut Connection) {
    while let Some(frame) = connection.next_frame() {
        let mut bytes = BytesMut::new();
        frame.encode(&mut bytes).unwrap();
        socket.write_all(&bytes).unwrap();
    }
}

fn reply(socket: &mut std::net::TcpStream, connection: &mut Connection,
    plan: Reply, finish: &mpsc::Receiver<bool>)
{
    let mut headers = vec![Header::new(":status", "200"),
        Header::new("content-type", "application/grpc"), Header::new("x-place", "initial")];
    let mut trailers = vec![Header::new("x-place", "trailing")];
    if let Some(status) = plan.status {
        trailers.push(Header::new("grpc-status", status));
        if status != "0" {
            trailers.push(Header::new("grpc-message", "upload%20refused"));
        }
    }
    if plan.trailers_only {
        headers.extend(trailers);
        connection.send_headers(1, headers, true).unwrap();
        flush(socket, connection);
        return;
    }
    connection.send_headers(1, headers, false).unwrap();
    let mut codec = FramedCodec::new(IdentityCodec);
    for _ in 0..plan.messages {
        let mut bytes = BytesMut::new();
        codec.encode_message(&Bytes::from_static(b"receipt"), &mut bytes).unwrap();
        connection.send_data(1, bytes.freeze(), false).unwrap();
    }
    flush(socket, connection);
    // No timing guesses: the test can witness a decoded retained message before
    // allowing trailers, or cancel/drop and ask the peer to observe TCP EOF.
    if plan.hold_trailers && !finish.recv_timeout(LIMIT).unwrap() {
        return;
    }
    connection.send_headers(1, trailers, true).unwrap();
    flush(socket, connection);
}

fn peer(plan: Reply, parked: mpsc::Receiver<()>) -> Peer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let (finish, finishing) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let deadline = Instant::now() + LIMIT;
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "client-streaming accept watchdog");
                    std::thread::park_timeout(Duration::from_millis(1));
                }
                Err(error) => panic!("client-streaming accept: {error}"),
            }
        };
        socket.set_read_timeout(Some(LIMIT)).unwrap();
        socket.set_write_timeout(Some(LIMIT)).unwrap();
        let mut connection = Connection::server(Settings::server());
        connection.queue_initial_settings();
        flush(&mut socket, &mut connection);
        let mut preface = [0; 24];
        socket.read_exact(&mut preface).unwrap();
        assert_eq!(&preface, CLIENT_PREFACE);
        let mut frames = FrameCodec::new();
        let mut input = BytesMut::new();
        let mut body = BytesMut::new();
        let mut codec = FramedCodec::with_message_size_limits(IdentityCodec, MESSAGE_BYTES, MESSAGE_BYTES);
        let mut count = 0;
        let mut half_closed = false;
        let mut seen_headers = false;
        let mut buffer = [0; 16 * 1024];
        loop {
            let n = match socket.read(&mut buffer) {
                Ok(n) => n,
                Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe) => 0,
                Err(error) => panic!("client-streaming peer read: {error}"),
            };
            if n == 0 {
                return (count, half_closed);
            }
            input.extend_from_slice(&buffer[..n]);
            while let Some(frame) = frames.decode(&mut input).unwrap() {
                match connection.process_frame(frame).unwrap() {
                    Some(ReceivedFrame::Headers { stream_id, end_stream, .. }) => {
                        assert_eq!(stream_id, 1);
                        assert!(!seen_headers && !end_stream);
                        seen_headers = true;
                        if plan.early {
                            parked.recv_timeout(LIMIT).unwrap();
                            reply(&mut socket, &mut connection, plan, &finishing);
                        }
                    }
                    Some(ReceivedFrame::Data { stream_id, data, end_stream }) => {
                        assert_eq!(stream_id, 1);
                        assert!(seen_headers && !half_closed && !plan.early);
                        body.extend_from_slice(&data);
                        while let Some(value) = codec.decode_message(&mut body).unwrap() {
                            assert_eq!(value.len(), MESSAGE_BYTES);
                            assert!(value.iter().all(|byte| usize::from(*byte) == count));
                            count += 1;
                        }
                        if end_stream {
                            assert!(body.is_empty());
                            half_closed = true;
                            reply(&mut socket, &mut connection, plan, &finishing);
                        }
                    }
                    _ => {}
                }
                flush(&mut socket, &mut connection);
            }
        }
    });
    Peer { address, finish, worker }
}

fn bounded(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
        let _ = send.send(result);
    });
    let result = receive.recv_timeout(Duration::from_secs(30))
        .expect("native client-streaming scenario must finish");
    worker.join().unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

fn runtime(workers: usize) -> crate::runtime::Runtime {
    let builder = if workers == 1 { RuntimeBuilder::current_thread() }
        else { RuntimeBuilder::new().worker_threads(workers) };
    builder.build().unwrap()
}

fn drained(runtime: &crate::runtime::Runtime) {
    let report = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.pending_obligations, 0);
}

async fn retain_first<IO, C, S>(call: &mut NativeClientStreamingCall<IO, C, S>)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    C: Codec,
    S: Streaming<Message = C::Encode>,
{
    poll_fn(|task| {
        {
            let mut waiting = pin!(call.response());
            assert!(waiting.as_mut().poll(task).is_pending(), "message alone is not success");
        }
        // The actual borrowing wait was dropped. Only owner-held state can
        // preserve this already-decoded message for the resumed call.
        if call.first.is_some() { Poll::Ready(()) } else { Poll::Pending }
    }).await;
    assert!(call.status().is_none());
}

fn ascii(metadata: &Metadata, key: &str) -> String {
    match metadata.get(key).unwrap() {
        MetadataValue::Ascii(value) => value.clone(),
        MetadataValue::Binary(_) => panic!("expected ASCII metadata"),
    }
}

#[test]
fn native_uploads_empty_and_multiwindow_sources_before_collecting_one_response() {
    bounded(|| {
        for workers in [1, 2] {
            for count in [0, 3] {
                let (parked, witness) = mpsc::channel();
                let peer = peer(Reply::normal(1, Some("0")), witness);
                let runtime = runtime(workers);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let label = String::from("borrowed non-Unpin source");
                    let items = (0..count).map(|i| Ok(Bytes::from(vec![i; MESSAGE_BYTES]))).collect();
                    let (source, gate, stats) = source(&label, &cx, parked, items);
                    gate.release();
                    let channel = Channel::builder(format!("http://{}", peer.address))
                        .timeout(LIMIT).max_send_message_size(MESSAGE_BYTES).connect().await.unwrap();
                    let mut call = GrpcClient::new(channel).into_native_client_streaming(
                        &cx, "/test.Upload/Collect", Request::new(source),
                    ).await.unwrap();
                    assert_eq!(stats.produced.load(Ordering::SeqCst), 0, "setup must not poll source");
                    let response = call.response().await.unwrap();
                    assert_eq!(response.get_ref().as_ref(), b"receipt");
                    assert_eq!(ascii(response.metadata(), "x-place"), "initial");
                    assert_eq!(ascii(call.trailers().unwrap(), "x-place"), "trailing");
                    assert_eq!(call.status().unwrap().code(), Code::Ok);
                    assert_eq!(stats.produced.load(Ordering::SeqCst), usize::from(count));
                    assert_eq!(stats.eof.load(Ordering::SeqCst), 1);
                    assert_eq!(stats.dropped.load(Ordering::SeqCst), 1);
                    assert_eq!(call.response().await.unwrap_err().code(), Code::FailedPrecondition);
                    call.cancel();
                    assert_eq!(call.status().unwrap().code(), Code::Ok);
                });
                assert_eq!(peer.worker.join().unwrap(), (usize::from(count), true));
                drained(&runtime);
            }
        }
    });
}

#[test]
fn dropped_response_wait_retains_first_message_and_waits_for_trailers() {
    bounded(|| {
        for workers in [1, 2] {
            let (parked, witness) = mpsc::channel();
            let peer = peer(Reply::held(), witness);
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (source, _gate, stats) = source("early response", &cx, parked, VecDeque::new());
                let channel = Channel::builder(format!("http://{}", peer.address))
                    .timeout(LIMIT).connect().await.unwrap();
                let mut call = GrpcClient::new(channel).into_native_client_streaming(
                    &cx, "/test.Upload/Collect", Request::new(source),
                ).await.unwrap();
                retain_first(&mut call).await;
                assert_eq!(stats.dropped.load(Ordering::SeqCst), 0);
                peer.finish.send(true).unwrap();
                assert_eq!(call.response().await.unwrap().into_inner().as_ref(), b"receipt");
                assert_eq!(stats.produced.load(Ordering::SeqCst), 0);
                assert_eq!(stats.eof.load(Ordering::SeqCst), 0, "early success does not imply source EOF");
                assert_eq!(stats.dropped.load(Ordering::SeqCst), 1);
                assert_eq!(ascii(call.trailers().unwrap(), "x-place"), "trailing");
            });
            assert_eq!(peer.worker.join().unwrap(), (0, false));
            drained(&runtime);
        }
    });
}

#[test]
fn late_peer_error_discards_the_buffered_message_and_preserves_status_and_trailers() {
    bounded(|| {
        for workers in [1, 2] {
            let (parked, witness) = mpsc::channel();
            let peer = peer(Reply { status: Some("7"), ..Reply::held() }, witness);
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (source, _gate, stats) = source("late error", &cx, parked, VecDeque::new());
                let channel = Channel::builder(format!("http://{}", peer.address))
                    .timeout(LIMIT).connect().await.unwrap();
                let mut call = GrpcClient::new(channel).into_native_client_streaming(
                    &cx, "/test.Upload/Collect", Request::new(source),
                ).await.unwrap();
                retain_first(&mut call).await;
                peer.finish.send(true).unwrap();
                let error = call.response().await.unwrap_err();
                assert_eq!(error.code(), Code::PermissionDenied);
                assert_eq!(error.message(), "upload refused");
                assert_eq!(call.status().unwrap().code(), Code::PermissionDenied);
                assert!(call.first.is_none());
                assert_eq!(ascii(call.trailers().unwrap(), "x-place"), "trailing");
                assert_eq!(stats.dropped.load(Ordering::SeqCst), 1);
            });
            assert_eq!(peer.worker.join().unwrap(), (0, false));
            drained(&runtime);
        }
    });
}

#[test]
fn successful_status_requires_exactly_one_message() {
    bounded(|| {
        for workers in [1, 2] {
            for messages in [0, 2] {
                let (parked, witness) = mpsc::channel();
                let peer = peer(Reply { hold_trailers: messages > 1,
                    ..Reply::normal(messages, Some("0")) }, witness);
                let runtime = runtime(workers);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let (source, gate, stats) = source("bad cardinality", &cx, parked, VecDeque::new());
                    gate.release();
                    let channel = Channel::builder(format!("http://{}", peer.address))
                        .timeout(LIMIT).connect().await.unwrap();
                    let mut call = GrpcClient::new(channel).into_native_client_streaming(
                        &cx, "/test.Upload/Collect", Request::new(source),
                    ).await.unwrap();
                    let error = call.response().await.unwrap_err();
                    assert_eq!(error.code(), Code::Internal);
                    assert!(error.message().contains(if messages == 0 { "no response" } else { "more than one" }));
                    assert_eq!(call.status().unwrap().code(), Code::Internal);
                    assert!(call.first.is_none());
                    assert_eq!(stats.dropped.load(Ordering::SeqCst), 1);
                    if messages > 1 {
                        peer.finish.send(false).unwrap();
                    }
                });
                assert_eq!(peer.worker.join().unwrap(), (0, true));
                drained(&runtime);
            }
        }
    });
}

#[test]
fn trailers_only_error_is_not_replaced_by_missing_message_error() {
    bounded(|| {
        for workers in [1, 2] {
            let (parked, witness) = mpsc::channel();
            let peer = peer(Reply { early: true, trailers_only: true,
                ..Reply::normal(0, Some("7")) }, witness);
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (source, _gate, stats) = source("early refusal", &cx, parked, VecDeque::new());
                let channel = Channel::builder(format!("http://{}", peer.address))
                    .timeout(LIMIT).connect().await.unwrap();
                let mut call = GrpcClient::new(channel).into_native_client_streaming(
                    &cx, "/test.Upload/Collect", Request::new(source),
                ).await.unwrap();
                let error = call.response().await.unwrap_err();
                assert_eq!(error.code(), Code::PermissionDenied);
                assert_eq!(error.message(), "upload refused");
                assert_eq!(stats.produced.load(Ordering::SeqCst), 0);
                assert_eq!(stats.dropped.load(Ordering::SeqCst), 1);
            });
            assert_eq!(peer.worker.join().unwrap(), (0, false));
            drained(&runtime);
        }
    });
}

#[test]
fn producer_error_after_a_response_does_not_become_success() {
    bounded(|| {
        for workers in [1, 2] {
            let (parked, witness) = mpsc::channel();
            let peer = peer(Reply::held(), witness);
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (source, gate, stats) = source("producer failure", &cx, parked,
                    VecDeque::from([Err(Status::resource_exhausted("upload quota"))]));
                let channel = Channel::builder(format!("http://{}", peer.address))
                    .timeout(LIMIT).connect().await.unwrap();
                let mut call = GrpcClient::new(channel).into_native_client_streaming(
                    &cx, "/test.Upload/Collect", Request::new(source),
                ).await.unwrap();
                retain_first(&mut call).await;
                gate.release();
                let error = call.response().await.unwrap_err();
                assert_eq!(error.code(), Code::ResourceExhausted);
                assert_eq!(error.message(), "upload quota");
                assert_eq!(stats.eof.load(Ordering::SeqCst), 0);
                assert_eq!(stats.dropped.load(Ordering::SeqCst), 1);
                assert!(call.first.is_none());
                peer.finish.send(false).unwrap();
            });
            assert_eq!(peer.worker.join().unwrap(), (0, false));
            drained(&runtime);
        }
    });
}

#[test]
fn explicit_cancel_and_drop_retire_a_parked_source_and_buffered_response() {
    bounded(|| {
        for workers in [1, 2] {
            for cancel in [false, true] {
                let (parked, witness) = mpsc::channel();
                let peer = peer(Reply::held(), witness);
                let runtime = runtime(workers);
                runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let (source, _gate, stats) = source("retired caller", &cx, parked, VecDeque::new());
                    let channel = Channel::builder(format!("http://{}", peer.address))
                        .timeout(LIMIT).connect().await.unwrap();
                    let mut call = GrpcClient::new(channel).into_native_client_streaming(
                        &cx, "/test.Upload/Collect", Request::new(source),
                    ).await.unwrap();
                    retain_first(&mut call).await;
                    if cancel {
                        call.cancel();
                        call.cancel();
                        assert!(call.first.is_none());
                        assert_eq!(call.response().await.unwrap_err().code(), Code::Cancelled);
                        assert_eq!(call.response().await.unwrap_err().code(), Code::FailedPrecondition);
                    }
                    drop(call);
                    assert_eq!(stats.dropped.load(Ordering::SeqCst), 1);
                    assert!(!cx.is_cancel_requested());
                    peer.finish.send(false).unwrap();
                });
                assert_eq!(peer.worker.join().unwrap(), (0, false));
                drained(&runtime);
            }
        }
    });
}

#[test]
fn owner_cancel_after_first_message_discards_it_and_retires_the_call() {
    bounded(|| {
        for workers in [1, 2] {
            let (parked, witness) = mpsc::channel();
            let peer = peer(Reply::held(), witness);
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let region = cx.open_child_region(crate::cx::ChildRegionSpec::inherit()).await.unwrap();
                let owner = region.cx();
                let (source, _gate, stats) = source("cancelled owner", &owner, parked, VecDeque::new());
                let channel = Channel::builder(format!("http://{}", peer.address))
                    .timeout(LIMIT).connect().await.unwrap();
                let mut call = GrpcClient::new(channel).into_native_client_streaming(
                    &owner, "/test.Upload/Collect", Request::new(source),
                ).await.unwrap();
                retain_first(&mut call).await;
                owner.cancel_with(CancelKind::User, Some("stop upload"));
                assert_eq!(call.response().await.unwrap_err().code(), Code::Cancelled);
                assert!(call.first.is_none());
                assert_eq!(stats.dropped.load(Ordering::SeqCst), 1);
                assert!(!cx.is_cancel_requested());
                peer.finish.send(false).unwrap();
                region.close().await.unwrap();
            });
            assert_eq!(peer.worker.join().unwrap(), (0, false));
            drained(&runtime);
        }
    });
}

#[test]
fn deadline_after_first_message_is_not_success_and_does_not_wait_for_source() {
    bounded(|| {
        for workers in [1, 2] {
            let (parked, witness) = mpsc::channel();
            let peer = peer(Reply::held(), witness);
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (source, _gate, stats) = source("deadline", &cx, parked, VecDeque::new());
                let channel = Channel::builder(format!("http://{}", peer.address))
                    .timeout(Duration::from_secs(2)).connect().await.unwrap();
                let mut call = GrpcClient::new(channel).into_native_client_streaming(
                    &cx, "/test.Upload/Collect", Request::new(source),
                ).await.unwrap();
                retain_first(&mut call).await;
                assert_eq!(call.response().await.unwrap_err().code(), Code::DeadlineExceeded);
                assert_eq!(stats.dropped.load(Ordering::SeqCst), 1);
                assert!(call.first.is_none());
                peer.finish.send(false).unwrap();
            });
            assert_eq!(peer.worker.join().unwrap(), (0, false));
            drained(&runtime);
        }
    });
}

#[test]
fn setup_refusal_never_polls_source_and_retires_captures_under_the_owner() {
    bounded(|| {
        let runtime = runtime(1);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let region = cx.open_child_region(crate::cx::ChildRegionSpec::inherit()).await.unwrap();
            let owner = region.cx();
            let (parked, _witness) = mpsc::channel();
            let (source, _gate, stats) = source("setup refused", &owner, parked, VecDeque::new());
            let channel = Channel::connect("http://loopback:50051").await.unwrap();
            let error = GrpcClient::new(channel).into_native_client_streaming(
                &owner, "/test.Upload/Collect", Request::new(source),
            ).await.unwrap_err();
            assert_eq!(error.code(), Code::FailedPrecondition);
            assert_eq!(stats.produced.load(Ordering::SeqCst), 0);
            assert_eq!(stats.dropped.load(Ordering::SeqCst), 1);
            region.close().await.unwrap();
        });
        drained(&runtime);
    });
}
