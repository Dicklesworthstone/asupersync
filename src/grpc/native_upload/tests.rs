//! Real TCP and the production HTTP/2 codecs, not an independent peer stack.
use super::*;
use crate::bytes::{Bytes, BytesMut};
use crate::codec::Decoder as _;
use crate::grpc::{Channel, FramedCodec, IdentityCodec};
use crate::http::h2::connection::{CLIENT_PREFACE, ReceivedFrame};
use crate::http::h2::{Connection, FrameCodec, Header, Settings};
use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
use crate::types::{CancelKind, TaskId};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::marker::PhantomPinned;
use std::net::{SocketAddr, TcpListener};
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
    parked: AtomicBool,
}

struct SourceState {
    items: VecDeque<Result<Bytes, Status>>,
    witness: Option<mpsc::Sender<()>>,
    address: Option<usize>,
}

// A borrowing, !Unpin source proves the adapter does not need 'static or Unpin.
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
            assert_eq!(previous, address, "request source moved after pinning");
        }
        if !this.gate.poll(task) {
            this.stats.parked.store(true, Ordering::SeqCst);
            if let Some(witness) = state.witness.take() {
                witness.send(()).unwrap();
            }
            return Poll::Pending;
        }
        assert_eq!(this.stats.eof.load(Ordering::SeqCst), 0, "source repolled after EOF");
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
        if let Some(address) = self.state.lock().unwrap().address {
            assert_eq!(address, std::ptr::from_ref(self).addr());
            assert_eq!(Cx::current().unwrap().task_id(), self.owner);
        }
        self.stats.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Echo,
    ZeroWindow,
    Quiet,
}

struct Peer {
    address: SocketAddr,
    worker: std::thread::JoinHandle<(usize, bool)>,
    respond: mpsc::Sender<()>,
}

fn write_pending(socket: &mut std::net::TcpStream, connection: &mut Connection) {
    while let Some(frame) = connection.next_frame() {
        let mut bytes = BytesMut::new();
        frame.encode(&mut bytes).unwrap();
        match socket.write_all(&bytes) {
            Ok(()) => {}
            // A cancelled call closes its connection, possibly while the peer
            // is still answering. Stop writing; the next read sees the close
            // and ends the exchange (closed_read).
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                return;
            }
            Err(error) => panic!("native upload peer write: {error}"),
        }
    }
}

fn message(connection: &mut Connection, codec: &mut FramedCodec<IdentityCodec>, value: &[u8]) {
    let mut bytes = BytesMut::new();
    codec.encode_message(&Bytes::copy_from_slice(value), &mut bytes).unwrap();
    connection.send_data(1, bytes.freeze(), false).unwrap();
}

fn closed_read(socket: &mut std::net::TcpStream, buffer: &mut [u8]) -> usize {
    match socket.read(buffer) {
        Ok(n) => n,
        Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe) => 0,
        Err(error) => panic!("native upload peer read: {error}"),
    }
}

fn peer(mode: Mode, producer_parked: mpsc::Receiver<()>) -> Peer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let (respond, response_gate) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let deadline = Instant::now() + LIMIT;
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "native upload accept watchdog");
                    std::thread::park_timeout(Duration::from_millis(1));
                }
                Err(error) => panic!("native upload accept: {error}"),
            }
        };
        socket.set_read_timeout(Some(LIMIT)).unwrap();
        socket.set_write_timeout(Some(LIMIT)).unwrap();
        let mut connection = Connection::server(Settings {
            initial_window_size: if matches!(mode, Mode::ZeroWindow) { 0 } else { 65535 },
            ..Settings::server()
        });
        connection.queue_initial_settings();
        write_pending(&mut socket, &mut connection);
        let mut preface = [0; 24];
        socket.read_exact(&mut preface).unwrap();
        assert_eq!(&preface, CLIENT_PREFACE);
        let mut frames = FrameCodec::new();
        let mut input = BytesMut::new();
        let mut body = BytesMut::new();
        let mut codec = FramedCodec::with_message_size_limits(
            IdentityCodec, MESSAGE_BYTES, MESSAGE_BYTES,
        );
        let mut count = 0;
        let mut headers = false;
        let mut half_closed = false;
        let mut buffer = [0; 16 * 1024];
        loop {
            let n = closed_read(&mut socket, &mut buffer);
            if n == 0 {
                return (count, half_closed);
            }
            input.extend_from_slice(&buffer[..n]);
            while let Some(frame) = frames.decode(&mut input).unwrap() {
                match connection.process_frame(frame).unwrap() {
                    Some(ReceivedFrame::Headers { stream_id, end_stream, .. }) => {
                        assert_eq!(stream_id, 1);
                        assert!(!headers && !end_stream);
                        headers = true;
                        // This is a real producer-Pending witness, not a sleep.
                        producer_parked.recv_timeout(LIMIT).unwrap();
                        response_gate.recv_timeout(LIMIT).unwrap();
                        if !matches!(mode, Mode::Quiet) {
                            connection.send_headers(1, vec![
                                Header::new(":status", "200"),
                                Header::new("content-type", "application/grpc"),
                                Header::new("x-initial", "upload"),
                            ], false).unwrap();
                            message(&mut connection, &mut codec, b"ready");
                        }
                    }
                    Some(ReceivedFrame::Data { stream_id, data, end_stream }) => {
                        assert_eq!(stream_id, 1);
                        assert!(headers && !half_closed);
                        assert!(matches!(mode, Mode::Echo), "parked upload must send no DATA");
                        body.extend_from_slice(&data);
                        while let Some(value) = codec.decode_message(&mut body).unwrap() {
                            assert_eq!(value.len(), MESSAGE_BYTES);
                            assert!(value.iter().all(|byte| usize::from(*byte) == count));
                            count += 1;
                            message(&mut connection, &mut codec, &[count as u8]);
                        }
                        if end_stream {
                            assert!(body.is_empty());
                            assert_eq!(count, 3);
                            half_closed = true;
                            connection.send_headers(1, vec![
                                Header::new("grpc-status", "0"),
                                Header::new("x-terminal", "complete"),
                            ], true).unwrap();
                        }
                    }
                    _ => {}
                }
                write_pending(&mut socket, &mut connection);
            }
        }
    });
    Peer { address, worker, respond }
}

fn bounded(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
        let _ = send.send(result);
    });
    let result = receive.recv_timeout(Duration::from_secs(30))
        .expect("native upload scenario must terminate");
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

fn assert_drained(runtime: &crate::runtime::Runtime) {
    let report = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.pending_obligations, 0);
}

fn source<'a>(label: &'a str, owner: &Cx, witness: mpsc::Sender<()>,
    items: VecDeque<Result<Bytes, Status>>) -> (Source<'a>, Arc<Gate>, Arc<SourceStats>)
{
    let gate = Arc::new(Gate::default());
    let stats = Arc::new(SourceStats::default());
    let source = Source {
        label, owner: owner.task_id(), gate: Arc::clone(&gate),
        state: Mutex::new(SourceState { items, witness: Some(witness), address: None }),
        stats: Arc::clone(&stats), _pin: PhantomPinned,
    };
    (source, gate, stats)
}

fn echo_case(drop_first_wait: bool) {
    bounded(move || {
        for workers in [1, 2] {
            let (witness, witnessed) = mpsc::channel();
            let peer = peer(Mode::Echo, witnessed);
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let label = String::from("borrowed pinned upload source");
                let items = (0..3).map(|i| Ok(Bytes::from(vec![i; MESSAGE_BYTES]))).collect();
                let (source, gate, stats) = source(&label, &cx, witness, items);
                let channel = Channel::builder(format!("http://{}", peer.address))
                    .timeout(LIMIT).max_send_message_size(MESSAGE_BYTES)
                    .connect().await.unwrap();
                let mut responses = GrpcClient::new(channel)
                    .into_native_bidi_streaming(&cx, "/test.Upload/Exchange", Request::new(source))
                    .await.unwrap();
                assert_eq!(stats.produced.load(Ordering::SeqCst), 0);
                if drop_first_wait {
                    let mut wait = Box::pin(responses.message());
                    poll_fn(|task| {
                        assert!(wait.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    }).await;
                    drop(wait);
                    assert_eq!(stats.dropped.load(Ordering::SeqCst), 0);
                }
                peer.respond.send(()).unwrap();
                // Peer sends this only AFTER the producer parks. A missing read
                // registration after RequestFlushed makes this wait time out.
                assert_eq!(responses.message().await.unwrap().unwrap().as_ref(), b"ready");
                assert_eq!(stats.produced.load(Ordering::SeqCst), 0);
                gate.release();
                let mut values = Vec::new();
                while let Some(message) = responses.message().await.unwrap() {
                    values.push(message);
                }
                assert_eq!(values.len(), 3);
                for (index, value) in values.iter().enumerate() {
                    assert_eq!(value.as_ref(), &[(index + 1) as u8]);
                }
                assert_eq!(responses.status().unwrap().code(), Code::Ok);
                assert!(responses.initial_metadata().unwrap().get("x-initial").is_some());
                assert!(responses.trailers().unwrap().get("x-terminal").is_some());
                assert!(responses.message().await.unwrap().is_none());
                assert_eq!(stats.produced.load(Ordering::SeqCst), 3);
                assert_eq!(stats.eof.load(Ordering::SeqCst), 1);
                assert_eq!(stats.dropped.load(Ordering::SeqCst), 1);
                assert!(!cx.is_cancel_requested());
            });
            assert_eq!(peer.worker.join().unwrap(), (3, true));
            assert_drained(&runtime);
        }
    });
}

#[test]
fn native_bidi_streams_both_directions_with_a_parked_borrowing_nonunpin_source() {
    echo_case(false);
}

#[test]
fn dropping_a_pending_message_wait_preserves_source_and_wire_progress() {
    echo_case(true);
}

#[test]
fn zero_upload_credit_stops_source_read_ahead_and_cancel_retires_everything() {
    bounded(|| {
        for workers in [1, 2] {
            let (witness, witnessed) = mpsc::channel();
            let peer = peer(Mode::ZeroWindow, witnessed);
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let items = (0..3).map(|i| Ok(Bytes::from(vec![i; MESSAGE_BYTES]))).collect();
                let (source, gate, stats) = source("bounded read ahead", &cx, witness, items);
                let channel = Channel::builder(format!("http://{}", peer.address))
                    .timeout(LIMIT).connect().await.unwrap();
                let mut call = GrpcClient::new(channel)
                    .into_native_bidi_streaming(&cx, "/test.Upload/Exchange", Request::new(source))
                    .await.unwrap();
                peer.respond.send(()).unwrap();
                assert_eq!(call.message().await.unwrap().unwrap().as_ref(), b"ready");
                gate.release();
                {
                    let mut wait = Box::pin(call.message());
                    poll_fn(|task| {
                        assert!(wait.as_mut().poll(task).is_pending());
                        if stats.produced.load(Ordering::SeqCst) == 1 {
                            Poll::Ready(())
                        } else {
                            Poll::Pending
                        }
                    }).await;
                }
                assert_eq!(stats.produced.load(Ordering::SeqCst), 1);
                call.cancel();
                assert_eq!(call.status().unwrap().code(), Code::Cancelled);
                assert!(call.message().await.unwrap().is_none());
                assert_eq!(stats.dropped.load(Ordering::SeqCst), 1);
                assert_eq!(stats.eof.load(Ordering::SeqCst), 0);
                assert!(!cx.is_cancel_requested());
            });
            assert_eq!(peer.worker.join().unwrap(), (0, false));
            assert_drained(&runtime);
        }
    });
}

#[test]
fn producer_failure_is_not_half_close_and_keeps_its_exact_status() {
    bounded(|| {
        for workers in [1, 2] {
            let (witness, witnessed) = mpsc::channel();
            let peer = peer(Mode::ZeroWindow, witnessed);
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let error = Status::resource_exhausted("application upload quota");
                let (source, gate, stats) = source("failed producer", &cx, witness,
                    VecDeque::from([Err(error.clone())]));
                let channel = Channel::builder(format!("http://{}", peer.address))
                    .timeout(LIMIT).connect().await.unwrap();
                let mut call = GrpcClient::new(channel)
                    .into_native_bidi_streaming(&cx, "/test.Upload/Exchange", Request::new(source))
                    .await.unwrap();
                peer.respond.send(()).unwrap();
                assert_eq!(call.message().await.unwrap().unwrap().as_ref(), b"ready");
                gate.release();
                let received = call.message().await.unwrap_err();
                assert_eq!(received.code(), error.code());
                assert_eq!(received.message(), error.message());
                assert_eq!(call.status().unwrap().message(), error.message());
                assert!(call.message().await.unwrap().is_none());
                assert_eq!(stats.dropped.load(Ordering::SeqCst), 1);
                assert_eq!(stats.eof.load(Ordering::SeqCst), 0);
                assert!(!cx.is_cancel_requested());
            });
            assert_eq!(peer.worker.join().unwrap(), (0, false));
            assert_drained(&runtime);
        }
    });
}

/// br-asupersync-244ump L2: a source that fails with an OK-coded status ends
/// the call as a failure whose status is not OK, so an aborted upload never
/// reads as success.
#[test]
fn a_source_failure_with_an_ok_status_does_not_report_ok() {
    bounded(|| {
        for workers in [1, 2] {
            let (witness, witnessed) = mpsc::channel();
            let peer = peer(Mode::ZeroWindow, witnessed);
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (source, gate, stats) = source(
                    "ok-coded failure",
                    &cx,
                    witness,
                    VecDeque::from([Err(Status::new(Code::Ok, "not really ok"))]),
                );
                let channel = Channel::builder(format!("http://{}", peer.address))
                    .timeout(LIMIT)
                    .connect()
                    .await
                    .unwrap();
                let mut call = GrpcClient::new(channel)
                    .into_native_bidi_streaming(&cx, "/test.Upload/Exchange", Request::new(source))
                    .await
                    .unwrap();
                peer.respond.send(()).unwrap();
                assert_eq!(call.message().await.unwrap().unwrap().as_ref(), b"ready");
                gate.release();
                let received = call.message().await.unwrap_err();
                assert_eq!(received.code(), Code::Internal);
                assert_eq!(call.status().unwrap().code(), Code::Internal);
                assert_eq!(stats.eof.load(Ordering::SeqCst), 0);
            });
            assert_eq!(peer.worker.join().unwrap(), (0, false));
            assert_drained(&runtime);
        }
    });
}

#[test]
fn owner_cancellation_wakes_a_call_with_a_never_ready_source() {
    bounded(|| {
        for workers in [1, 2] {
            let (witness, witnessed) = mpsc::channel();
            let peer = peer(Mode::Quiet, witnessed);
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let region = cx.open_child_region(crate::cx::ChildRegionSpec::inherit()).await.unwrap();
                let owner = region.cx();
                let (source, _gate, stats) = source("cancel parked producer", owner, witness,
                    VecDeque::new());
                let channel = Channel::builder(format!("http://{}", peer.address))
                    .timeout(LIMIT).connect().await.unwrap();
                let mut call = GrpcClient::new(channel)
                    .into_native_bidi_streaming(owner, "/test.Upload/Exchange", Request::new(source))
                    .await.unwrap();
                peer.respond.send(()).unwrap();
                {
                    let mut wait = Box::pin(call.message());
                    poll_fn(|task| {
                        assert!(wait.as_mut().poll(task).is_pending());
                        if stats.parked.load(Ordering::SeqCst) {
                            Poll::Ready(())
                        } else {
                            Poll::Pending
                        }
                    }).await;
                }
                owner.cancel_with(CancelKind::User, Some("stop native source"));
                assert_eq!(call.message().await.unwrap_err().code(), Code::Cancelled);
                assert_eq!(stats.produced.load(Ordering::SeqCst), 0);
                assert_eq!(stats.dropped.load(Ordering::SeqCst), 1);
                assert!(!cx.is_cancel_requested());
                region.close().await.unwrap();
            });
            assert_eq!(peer.worker.join().unwrap(), (0, false));
            assert_drained(&runtime);
        }
    });
}

#[test]
fn source_is_not_polled_when_native_setup_refuses() {
    bounded(|| {
        let runtime = runtime(1);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (witness, _receiver) = mpsc::channel();
            let (source, _gate, stats) = source("setup refusal", &cx, witness, VecDeque::new());
            let channel = Channel::connect("http://loopback:50051").await.unwrap();
            let error = GrpcClient::new(channel)
                .into_native_bidi_streaming(&cx, "/test.Upload/Exchange", Request::new(source))
                .await.unwrap_err();
            assert_eq!(error.code(), Code::FailedPrecondition);
            assert_eq!(stats.produced.load(Ordering::SeqCst), 0);
            assert_eq!(stats.dropped.load(Ordering::SeqCst), 1);
        });
        assert_drained(&runtime);
    });
}
