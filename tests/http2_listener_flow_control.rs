//! Native peer-credit stalls must release response ownership without stopping
//! sibling traffic. The raw client deliberately never auto-updates its windows.

#![cfg(not(target_arch = "wasm32"))]

use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::channel::oneshot;
use asupersync::codec::Decoder as _;
use asupersync::http::h1::server::HostPolicy;
use asupersync::http::h1::types::{Request, Response};
use asupersync::http::h2::connection::CLIENT_PREFACE;
use asupersync::http::h2::frame::{
    Frame, HeadersFrame, PingFrame, RstStreamFrame, Setting, SettingsFrame, WindowUpdateFrame,
};
use asupersync::http::h2::listener::{Http2Listener, Http2ListenerConfig, Http2ProducedResponse};
use asupersync::http::h2::{ErrorCode, FrameCodec, Header, HpackEncoder};
use asupersync::runtime::RuntimeBuilder;
use asupersync::sync::Notify;

const CHUNK: usize = 16_384;
const CONNECTION_WINDOW: usize = 65_535;

struct Peer {
    socket: TcpStream,
    codec: FrameCodec,
    buffered: BytesMut,
    encoder: HpackEncoder,
}

impl Peer {
    fn connect(address: SocketAddr, stream_stall: bool, small_buffer: bool) -> Self {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        if small_buffer {
            socket.set_recv_buffer_size(4096).unwrap();
        }
        socket.connect(&address.into()).unwrap();
        let mut socket: TcpStream = socket.into();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket.write_all(CLIENT_PREFACE).unwrap();
        let mut peer = Self {
            socket,
            codec: FrameCodec::new(),
            buffered: BytesMut::new(),
            encoder: HpackEncoder::new(),
        };
        // A large stream window isolates exhaustion of connection credit.
        peer.send(Frame::Settings(SettingsFrame::new(vec![
            Setting::InitialWindowSize(if stream_stall { 0 } else { 1_048_576 }),
        ])));
        peer
    }

    fn send(&mut self, frame: Frame) {
        let mut bytes = BytesMut::new();
        frame.encode(&mut bytes).unwrap();
        self.socket.write_all(&bytes).unwrap();
    }

    fn request(&mut self, stream_id: u32, path: &str) {
        let mut headers = BytesMut::new();
        self.encoder.encode(
            &[
                Header::new(":method", "GET"),
                Header::new(":scheme", "http"),
                Header::new(":path", path),
                Header::new(":authority", "localhost"),
            ],
            &mut headers,
        );
        self.send(Frame::Headers(HeadersFrame::new(
            stream_id,
            headers.freeze(),
            true,
            true,
        )));
    }

    fn receive(&mut self) -> Frame {
        loop {
            if let Some(frame) = self.codec.decode(&mut self.buffered).unwrap() {
                if let Frame::Settings(settings) = &frame
                    && !settings.ack
                {
                    self.send(Frame::Settings(SettingsFrame::ack()));
                }
                return frame;
            }
            let mut bytes = [0u8; CHUNK];
            let read = self
                .socket
                .read(&mut bytes)
                .expect("native response watchdog");
            assert_ne!(read, 0, "flow timeout must leave the connection usable");
            self.buffered.extend_from_slice(&bytes[..read]);
        }
    }

    fn empty_response(&mut self, stream_id: u32) {
        loop {
            match self.receive() {
                Frame::Headers(headers) if headers.stream_id == stream_id => {
                    assert!(headers.end_stream, "empty sibling needs no DATA credit");
                    return;
                }
                Frame::RstStream(reset) => panic!("sibling reset: {reset:?}"),
                Frame::GoAway(goaway) => panic!("connection unexpectedly closed: {goaway:?}"),
                _ => {}
            }
        }
    }
}

struct ProducerState {
    parked: std::sync::mpsc::Sender<(Cx, usize)>,
    cleanup: std::sync::mpsc::Sender<Cx>,
    release: Notify,
    released: AtomicBool,
    dropped: AtomicUsize,
}

struct ProducerDrop(Arc<ProducerState>);
impl Drop for ProducerDrop {
    fn drop(&mut self) {
        self.0.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

fn response(request: Request, produced: bool, state: Arc<ProducerState>) -> Http2ProducedResponse {
    if request.uri == "/bulk" {
        return Http2ProducedResponse::buffered(Response::new(
            200,
            "OK",
            vec![b'b'; 32 * 1024 * 1024],
        ));
    }
    if request.uri != "/blocked" {
        return Http2ProducedResponse::buffered(Response::new(200, "OK", Vec::new()));
    }
    if !produced {
        return Http2ProducedResponse::buffered(Response::new(200, "OK", vec![b'x'; 8 * CHUNK]));
    }
    Http2ProducedResponse::streaming(
        Response::new(200, "OK", Vec::new()),
        NonZeroUsize::MIN,
        NonZeroUsize::new(CHUNK).unwrap(),
        move |cx, mut sender| async move {
            let _retirement = ProducerDrop(Arc::clone(&state));
            for committed in 0..32 {
                let mut send =
                    std::pin::pin!(sender.send_bytes(&cx, Bytes::from(vec![b'x'; CHUNK])));
                let mut witnessed = false;
                let sent = poll_fn(|task_cx| {
                    let result = send.as_mut().poll(task_cx);
                    if result.is_pending() && !witnessed {
                        state.parked.send((cx.clone(), committed * CHUNK)).unwrap();
                        witnessed = true;
                    }
                    result
                })
                .await;
                if sent.is_err() {
                    assert!(cx.is_cancel_requested());
                    let mut cleanup = std::pin::pin!(
                        state
                            .release
                            .wait_until(|| state.released.load(Ordering::Acquire))
                    );
                    let mut witnessed = false;
                    poll_fn(|task_cx| {
                        let result = cleanup.as_mut().poll(task_cx);
                        if result.is_pending() && !witnessed {
                            state.cleanup.send(cx.clone()).unwrap();
                            witnessed = true;
                        }
                        result
                    })
                    .await;
                    break;
                }
            }
            Ok(sender)
        },
    )
}

fn wait_for(label: &str, condition: impl Fn() -> bool) {
    let started = Instant::now();
    while !condition() {
        assert!(started.elapsed() < Duration::from_secs(5), "{label}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[allow(clippy::fn_params_excessive_bools)]
fn peer_credit_stall(workers: usize, produced: bool, stream_stall: bool, bulk_stall: bool) {
    let runtime = RuntimeBuilder::new()
        .worker_threads(workers)
        .with_sharded_state(workers == 2)
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    let (parked, pending) = std::sync::mpsc::channel();
    let (cleanup, cleaning) = std::sync::mpsc::channel();
    let state = Arc::new(ProducerState {
        parked,
        cleanup,
        release: Notify::new(),
        released: AtomicBool::new(false),
        dropped: AtomicUsize::new(0),
    });
    let handler_state = Arc::clone(&state);
    let config = Http2ListenerConfig::default()
        .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
        .request_drain_grace(Duration::from_secs(10))
        .drain_timeout(Duration::from_secs(2))
        .hard_drain_timeout(Duration::from_secs(5));
    let listener = runtime
        .block_on(Http2Listener::bind_produced_with_config(
            "127.0.0.1:0",
            move |request| {
                let result = response(request, produced, Arc::clone(&handler_state));
                async move { result }
            },
            config,
        ))
        .unwrap()
        .flow_control_progress_timeout(Duration::from_secs(1))
        .max_in_flight_requests(NonZeroUsize::new(2).unwrap());
    let address = listener.local_addr().unwrap();
    let manager = listener.connection_manager().clone();
    let in_flight = listener.in_flight_requests();
    let handle = runtime.handle();
    let serving: Pin<Box<dyn Future<Output = _> + Send>> =
        Box::pin(async move { listener.run_produced(&handle).await });
    let run = runtime.handle().spawn(serving);
    let mut peer = Peer::connect(address, stream_stall, bulk_stall);
    peer.request(1, "/blocked");
    let mut data_bytes = 0;
    loop {
        match peer.receive() {
            Frame::Headers(headers) if headers.stream_id == 1 => {
                assert!(!headers.end_stream);
                if stream_stall {
                    break;
                }
            }
            Frame::Data(data) if data.stream_id == 1 => {
                assert!(!data.end_stream);
                data_bytes += data.data.len();
                assert!(data_bytes <= CONNECTION_WINDOW);
                if data_bytes == CONNECTION_WINDOW {
                    break;
                }
            }
            Frame::RstStream(reset) => panic!("reset before credit exhaustion witness: {reset:?}"),
            _ => {}
        }
    }
    if produced {
        loop {
            let (_, committed) = pending.recv_timeout(Duration::from_secs(3)).unwrap();
            if stream_stall || committed >= 5 * CHUNK {
                break;
            }
        }
    }
    assert_eq!(in_flight.load(Ordering::SeqCst), 1);
    assert_eq!(state.dropped.load(Ordering::SeqCst), 0);
    if bulk_stall {
        peer.request(3, "/bulk");
        peer.send(Frame::WindowUpdate(WindowUpdateFrame::new(
            0,
            64 * 1024 * 1024,
        )));
        peer.send(Frame::WindowUpdate(WindowUpdateFrame::new(
            3,
            64 * 1024 * 1024,
        )));
        loop {
            match peer.receive() {
                Frame::Data(data) if data.stream_id == 3 => {
                    assert!(!data.end_stream);
                    break;
                }
                Frame::RstStream(reset) => {
                    panic!("credit deadline fired before sibling pump witness: {reset:?}")
                }
                _ => {}
            }
        }
        // Stop reading a 32-MiB response through a 4-KiB receive buffer. The
        // sibling has ample HTTP/2 credit, but its TCP write cannot complete.
        // Stream 1 must begin cancellation cleanup while that pump is parked,
        // well before its separate ten-second transport timeout could fire.
    } else {
        peer.request(3, "/sibling");
        peer.empty_response(3);
        // Every acknowledged PING supplies another driver wake and transport write.
        // Those unrelated writes must not renew stream 1's credit deadline.
        let mut acknowledgements = 0u64;
        peer.send(Frame::Ping(PingFrame::new(acknowledgements.to_be_bytes())));
        let watchdog = Instant::now();
        loop {
            assert!(
                watchdog.elapsed() < Duration::from_secs(5),
                "PING traffic postponed flow timeout"
            );
            match peer.receive() {
                Frame::Ping(ping) if ping.ack => {
                    acknowledgements += 1;
                    peer.send(Frame::Ping(PingFrame::new(acknowledgements.to_be_bytes())));
                }
                Frame::RstStream(reset) => {
                    assert_eq!(reset.stream_id, 1);
                    assert_eq!(reset.error_code, ErrorCode::Cancel);
                    break;
                }
                Frame::Data(data) if data.stream_id == 1 => {
                    panic!("DATA escaped exhausted windows: {data:?}")
                }
                Frame::GoAway(goaway) => panic!("flow timeout must be stream-local: {goaway:?}"),
                _ => {}
            }
        }
        assert!(
            acknowledgements > 0,
            "peer traffic must reach the driver during the stall"
        );
    }
    if produced {
        let cx = cleaning.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(cx.is_cancel_requested());
        assert_eq!(
            in_flight.load(Ordering::SeqCst),
            if bulk_stall { 2 } else { 1 },
            "RST cannot release a live producer's permit"
        );
        assert_eq!(
            state.dropped.load(Ordering::SeqCst),
            0,
            "actual cleanup remains parked"
        );
        state.released.store(true, Ordering::Release);
        state.release.notify_waiters();
    }
    wait_for(
        "response permit did not retire after actual cleanup",
        || in_flight.load(Ordering::SeqCst) == usize::from(bulk_stall),
    );
    assert_eq!(state.dropped.load(Ordering::SeqCst), usize::from(produced));
    if !bulk_stall {
        peer.request(5, "/recovered");
        peer.empty_response(5);
    }
    drop(peer);
    assert!(manager.begin_drain(Duration::from_secs(2)));
    let stats = runtime.block_on(run).unwrap();
    assert!(stats.drain_report.unwrap().reached_quiescence);
    wait_for("native HTTP/2 tasks must actually retire", || {
        runtime.is_quiescent()
    });
    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
    assert_eq!(manager.active_count(), 0);
    assert!(
        runtime
            .task_inspector(Default::default())
            .list_tasks()
            .is_empty()
    );
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert_eq!(runtime.draining_region_count(), 0);
}

#[test]
fn stalled_response_credit_cancels_only_its_stream_and_retires_ownership() {
    for workers in [1, 2] {
        for produced in [false, true] {
            for stream_stall in [false, true] {
                peer_credit_stall(workers, produced, stream_stall, false);
            }
        }
    }
}

#[test]
fn sibling_transport_stall_cannot_hide_an_armed_flow_control_deadline() {
    for workers in [1, 2] {
        peer_credit_stall(workers, true, true, true);
    }
}

struct OwnedProducerState {
    handler: std::sync::mpsc::Sender<Cx>,
    producer_parked: std::sync::mpsc::Sender<Cx>,
    cleanup: std::sync::mpsc::Sender<(&'static str, Cx)>,
    producer_started: Notify,
    producing: AtomicBool,
    release: Notify,
    released: AtomicBool,
    child_dropped: AtomicUsize,
    producer_dropped: AtomicUsize,
}

struct OwnedProducerDrop(Arc<OwnedProducerState>, bool);

impl Drop for OwnedProducerDrop {
    fn drop(&mut self) {
        let counter = if self.1 {
            &self.0.producer_dropped
        } else {
            &self.0.child_dropped
        };
        counter.fetch_add(1, Ordering::SeqCst);
    }
}

async fn owned_cleanup_gate(cx: &Cx, role: &'static str, state: &OwnedProducerState) {
    let mut cleanup = std::pin::pin!(state.release.wait_until(|| state.released.load(Ordering::Acquire)));
    let mut witnessed = false;
    poll_fn(|task| {
        let result = cleanup.as_mut().poll(task);
        if result.is_pending() && !witnessed {
            state.cleanup.send((role, cx.clone())).unwrap();
            witnessed = true;
        }
        result
    })
    .await;
}

// A handler-created child cannot finish its dependency until the deferred
// producer starts. Closing a handler-only region would deadlock this exchange.
// Once production finishes, the same child deliberately parks during cleanup.
#[allow(clippy::fn_params_excessive_bools)]
fn owned_producer_lifetime(workers: usize, cancel: bool, disconnect: bool) {
    let runtime = RuntimeBuilder::new()
        .worker_threads(workers)
        .with_sharded_state(workers == 2)
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    let (handler, handled) = std::sync::mpsc::channel();
    let (producer_parked, parked) = std::sync::mpsc::channel();
    let (cleanup, cleaning) = std::sync::mpsc::channel();
    let state = Arc::new(OwnedProducerState {
        handler,
        producer_parked,
        cleanup,
        producer_started: Notify::new(),
        producing: AtomicBool::new(false),
        release: Notify::new(),
        released: AtomicBool::new(false),
        child_dropped: AtomicUsize::new(0),
        producer_dropped: AtomicUsize::new(0),
    });
    let handler_state = Arc::clone(&state);
    let listener = runtime
        .block_on(Http2Listener::bind_produced_with_config(
            "127.0.0.1:0",
            move |request: Request| {
                let handler_cx = Cx::current().expect("handler factory runs in request task");
                let state = Arc::clone(&handler_state);
                async move {
                    if request.uri != "/owned" {
                        return Http2ProducedResponse::buffered(Response::new(200, "OK", Vec::new()));
                    }
                    state.handler.send(handler_cx.clone()).unwrap();
                    let (ready, mut admitted) = oneshot::channel();
                    let (payload, mut dependency) = oneshot::channel();
                    let child_state = Arc::clone(&state);
                    let _child = handler_cx.spawn(move |child_cx| async move {
                        let _drop = OwnedProducerDrop(Arc::clone(&child_state), false);
                        let mut ready = Some(ready);
                        let mut producer = std::pin::pin!(child_state.producer_started.wait_until(|| {
                            child_state.producing.load(Ordering::Acquire)
                        }));
                        poll_fn(|task| {
                            let result = producer.as_mut().poll(task);
                            if result.is_pending() && let Some(ready) = ready.take() {
                                ready.send_blocking(child_cx.clone()).unwrap();
                            }
                            result
                        })
                        .await;
                        assert!(!child_cx.is_cancel_requested(), "handler child closed before production");
                        payload.send_blocking(Bytes::from_static(b"handler child supplied this body")).unwrap();
                        child_cx.cancelled().await;
                        owned_cleanup_gate(&child_cx, "child", &child_state).await;
                    }).unwrap();
                    let child_cx = admitted.recv(&handler_cx).await.unwrap();
                    assert_eq!(child_cx.region_id(), handler_cx.region_id());
                    assert_ne!(child_cx.task_id(), handler_cx.task_id());
                    Http2ProducedResponse::streaming(
                        Response::new(200, "OK", Vec::new()),
                        NonZeroUsize::MIN,
                        NonZeroUsize::new(128).unwrap(),
                        move |producer_cx, mut sender| {
                            let ambient = Cx::current().expect("producer factory has a request task");
                            assert_eq!(producer_cx.task_id(), handler_cx.task_id());
                            assert_eq!(producer_cx.region_id(), handler_cx.region_id());
                            assert_eq!(ambient.task_id(), handler_cx.task_id());
                            async move {
                                let _drop = OwnedProducerDrop(Arc::clone(&state), true);
                                state.producing.store(true, Ordering::Release);
                                state.producer_started.notify_waiters();
                                let bytes = dependency.recv(&producer_cx).await.unwrap();
                                sender.send_bytes(&producer_cx, bytes).await?;
                                if cancel {
                                    let mut cancelled = std::pin::pin!(producer_cx.cancelled());
                                    let mut witnessed = false;
                                    poll_fn(|task| {
                                        let result = cancelled.as_mut().poll(task);
                                        if result.is_pending() && !witnessed {
                                            state.producer_parked.send(producer_cx.clone()).unwrap();
                                            witnessed = true;
                                        }
                                        result
                                    }).await;
                                    owned_cleanup_gate(&producer_cx, "producer", &state).await;
                                } else {
                                    sender.finish(&producer_cx)?;
                                }
                                Ok(sender)
                            }
                        },
                    )
                }
            },
            Http2ListenerConfig::default()
                .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
                .request_drain_grace(Duration::from_secs(10))
                .drain_timeout(Duration::from_secs(2))
                .hard_drain_timeout(Duration::from_secs(5)),
        ))
        .unwrap()
        .max_in_flight_requests(NonZeroUsize::new(2).unwrap());
    let address = listener.local_addr().unwrap();
    let manager = listener.connection_manager().clone();
    let in_flight = listener.in_flight_requests();
    let handle = runtime.handle();
    let serving: Pin<Box<dyn Future<Output = _> + Send>> =
        Box::pin(async move { listener.run_produced_owned(&handle).await });
    let run = runtime.handle().spawn(serving);
    let mut peer = Peer::connect(address, false, false);
    peer.request(1, "/owned");
    let handler_cx = handled.recv_timeout(Duration::from_secs(5)).unwrap();
    loop {
        match peer.receive() {
            Frame::Headers(headers) if headers.stream_id == 1 => assert!(!headers.end_stream),
            Frame::Data(data) if data.stream_id == 1 => {
                assert_eq!(data.data.as_ref(), b"handler child supplied this body");
                assert!(!data.end_stream, "body bytes must precede request retirement");
                break;
            }
            Frame::RstStream(reset) => panic!("owned dependency failed: {reset:?}"),
            _ => {}
        }
    }
    if cancel {
        let producer = parked.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(producer.task_id(), handler_cx.task_id());
        if disconnect {
            peer.socket.shutdown(std::net::Shutdown::Both).unwrap();
        } else {
            peer.send(Frame::RstStream(RstStreamFrame::new(1, ErrorCode::Cancel)));
        }
    }
    let mut cleanup_roles = Vec::new();
    for _ in 0..if cancel { 2 } else { 1 } {
        let (role, cx) = cleaning.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(cx.is_cancel_requested());
        assert_eq!(cx.region_id(), handler_cx.region_id());
        cleanup_roles.push(role);
    }
    assert!(cleanup_roles.contains(&"child"));
    assert_eq!(cleanup_roles.contains(&"producer"), cancel);
    assert_eq!(in_flight.load(Ordering::SeqCst), 1);
    assert_eq!(state.child_dropped.load(Ordering::SeqCst), 0);
    assert_eq!(state.producer_dropped.load(Ordering::SeqCst), usize::from(!cancel));

    if !disconnect {
        // A sibling response proves the connection driver advanced while
        // stream 1's actual descendant remained parked. No sleep is a witness.
        peer.request(3, "/sibling");
        loop {
            match peer.receive() {
                Frame::Headers(headers) if headers.stream_id == 3 => {
                    assert!(headers.end_stream);
                    break;
                }
                Frame::Headers(headers) if headers.stream_id == 1 => assert!(!headers.end_stream),
                Frame::Data(data) if data.stream_id == 1 => assert!(!data.end_stream),
                Frame::RstStream(reset) if reset.stream_id == 3 => panic!("sibling reset: {reset:?}"),
                _ => {}
            }
        }
        assert_eq!(state.child_dropped.load(Ordering::SeqCst), 0);
    }
    state.released.store(true, Ordering::Release);
    state.release.notify_waiters();
    if !cancel {
        loop {
            match peer.receive() {
                Frame::Data(data) if data.stream_id == 1 && data.end_stream => {
                    assert!(data.data.is_empty());
                    assert_eq!(state.child_dropped.load(Ordering::SeqCst), 1);
                    break;
                }
                Frame::RstStream(reset) => panic!("clean owned response reset: {reset:?}"),
                _ => {}
            }
        }
    }
    wait_for("owned request permit must await actual retirement", || {
        in_flight.load(Ordering::SeqCst) == 0
    });
    assert_eq!(state.child_dropped.load(Ordering::SeqCst), 1);
    assert_eq!(state.producer_dropped.load(Ordering::SeqCst), 1);
    drop(peer);
    assert!(manager.begin_drain(Duration::from_secs(2)));
    let stats = runtime.block_on(run).unwrap();
    assert!(stats.drain_report.unwrap().reached_quiescence);
    wait_for("owned H2 runtime must retire all tasks", || runtime.is_quiescent());
    assert_eq!(manager.active_count(), 0);
    assert!(runtime.task_inspector(Default::default()).list_tasks().is_empty());
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert_eq!(runtime.draining_region_count(), 0);
}

#[test]
fn owned_producer_uses_handler_descendants_and_defers_end_stream_until_retirement() {
    for workers in [1, 2] {
        owned_producer_lifetime(workers, false, false);
    }
}

#[test]
fn owned_producer_reset_and_disconnect_drain_the_whole_request_subtree() {
    for workers in [1, 2] {
        for disconnect in [false, true] {
            owned_producer_lifetime(workers, true, disconnect);
        }
    }
}

#[cfg(feature = "test-internals")]
#[test]
fn owned_producer_finalizer_failure_resets_instead_of_completing_the_response() {
    for workers in [1, 2] {
        let runtime = RuntimeBuilder::new()
            .worker_threads(workers)
            .with_sharded_state(workers == 2)
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap();
        let finalized = Arc::new(AtomicUsize::new(0));
        let handler_finalized = Arc::clone(&finalized);
        let listener = runtime.block_on(Http2Listener::bind_produced_with_config(
            "127.0.0.1:0",
            move |_request: Request| {
                let cx = Cx::current().unwrap();
                let finalized = Arc::clone(&handler_finalized);
                assert!(asupersync::runtime::Runtime::current_handle().unwrap()
                    .register_sync_finalizer_for_testing(cx.region_id(), move || {
                        finalized.fetch_add(1, Ordering::SeqCst);
                        panic!("intentional owned HTTP/2 finalizer failure");
                    }));
                async {
                    Http2ProducedResponse::streaming(
                        Response::new(200, "OK", Vec::new()),
                        NonZeroUsize::MIN,
                        NonZeroUsize::new(8).unwrap(),
                        |cx, mut sender| async move {
                            sender.send_bytes(&cx, Bytes::from_static(b"partial")).await?;
                            sender.finish(&cx)?;
                            Ok(sender)
                        },
                    )
                }
            },
            Http2ListenerConfig::default()
                .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()])),
        )).unwrap();
        let address = listener.local_addr().unwrap();
        let manager = listener.connection_manager().clone();
        let in_flight = listener.in_flight_requests();
        let handle = runtime.handle();
        let serving: Pin<Box<dyn Future<Output = _> + Send>> =
            Box::pin(async move { listener.run_produced_owned(&handle).await });
        let run = runtime.handle().spawn(serving);
        let mut peer = Peer::connect(address, false, false);
        peer.request(1, "/finalizer");
        loop {
            match peer.receive() {
                Frame::Headers(headers) if headers.stream_id == 1 => assert!(!headers.end_stream),
                Frame::Data(data) if data.stream_id == 1 => assert!(!data.end_stream),
                Frame::RstStream(reset) if reset.stream_id == 1 => {
                    assert_eq!(reset.error_code, ErrorCode::InternalError);
                    break;
                }
                Frame::GoAway(goaway) => panic!("finalizer failure must be stream-local: {goaway:?}"),
                _ => {}
            }
        }
        assert_eq!(finalized.load(Ordering::SeqCst), 1);
        wait_for("failed finalizer must retire its request guard", || in_flight.load(Ordering::SeqCst) == 0);
        drop(peer);
        assert!(manager.begin_drain(Duration::from_secs(2)));
        assert!(runtime.block_on(run).unwrap().drain_report.unwrap().reached_quiescence);
        wait_for("failed finalizer must retire its tasks", || runtime.is_quiescent());
        assert_eq!(manager.active_count(), 0);
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert_eq!(runtime.draining_region_count(), 0);
    }
}
