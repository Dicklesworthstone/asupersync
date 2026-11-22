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
    let mut cleanup = std::pin::pin!(
        state
            .release
            .wait_until(|| state.released.load(Ordering::Acquire))
    );
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
                        return Http2ProducedResponse::buffered(Response::new(
                            200,
                            "OK",
                            Vec::new(),
                        ));
                    }
                    state.handler.send(handler_cx.clone()).unwrap();
                    let (ready, mut admitted) = oneshot::channel();
                    let (payload, mut dependency) = oneshot::channel();
                    let child_state = Arc::clone(&state);
                    let _child = handler_cx
                        .spawn(move |child_cx| async move {
                            let _drop = OwnedProducerDrop(Arc::clone(&child_state), false);
                            let mut ready = Some(ready);
                            let mut producer =
                                std::pin::pin!(child_state.producer_started.wait_until(|| {
                                    child_state.producing.load(Ordering::Acquire)
                                }));
                            poll_fn(|task| {
                                let result = producer.as_mut().poll(task);
                                if result.is_pending()
                                    && let Some(ready) = ready.take()
                                {
                                    ready.send_blocking(child_cx.clone()).unwrap();
                                }
                                result
                            })
                            .await;
                            assert!(
                                !child_cx.is_cancel_requested(),
                                "handler child closed before production"
                            );
                            payload
                                .send_blocking(Bytes::from_static(
                                    b"handler child supplied this body",
                                ))
                                .unwrap();
                            child_cx.cancelled().await;
                            owned_cleanup_gate(&child_cx, "child", &child_state).await;
                        })
                        .unwrap();
                    let child_cx = admitted.recv(&handler_cx).await.unwrap();
                    assert_eq!(child_cx.region_id(), handler_cx.region_id());
                    assert_ne!(child_cx.task_id(), handler_cx.task_id());
                    Http2ProducedResponse::streaming(
                        Response::new(200, "OK", Vec::new()),
                        NonZeroUsize::MIN,
                        NonZeroUsize::new(128).unwrap(),
                        move |producer_cx, mut sender| {
                            let ambient =
                                Cx::current().expect("producer factory has a request task");
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
                                            state
                                                .producer_parked
                                                .send(producer_cx.clone())
                                                .unwrap();
                                            witnessed = true;
                                        }
                                        result
                                    })
                                    .await;
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
                assert!(
                    !data.end_stream,
                    "body bytes must precede request retirement"
                );
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
    assert_eq!(
        state.producer_dropped.load(Ordering::SeqCst),
        usize::from(!cancel)
    );

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
                Frame::RstStream(reset) if reset.stream_id == 3 => {
                    panic!("sibling reset: {reset:?}")
                }
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
    wait_for("owned H2 runtime must retire all tasks", || {
        runtime.is_quiescent()
    });
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
        let listener = runtime
            .block_on(Http2Listener::bind_produced_with_config(
                "127.0.0.1:0",
                move |_request: Request| {
                    let cx = Cx::current().unwrap();
                    let finalized = Arc::clone(&handler_finalized);
                    assert!(
                        asupersync::runtime::Runtime::current_handle()
                            .unwrap()
                            .register_sync_finalizer_for_testing(cx.region_id(), move || {
                                finalized.fetch_add(1, Ordering::SeqCst);
                                panic!("intentional owned HTTP/2 finalizer failure");
                            })
                    );
                    async {
                        Http2ProducedResponse::streaming(
                            Response::new(200, "OK", Vec::new()),
                            NonZeroUsize::MIN,
                            NonZeroUsize::new(8).unwrap(),
                            |cx, mut sender| async move {
                                sender
                                    .send_bytes(&cx, Bytes::from_static(b"partial"))
                                    .await?;
                                sender.finish(&cx)?;
                                Ok(sender)
                            },
                        )
                    }
                },
                Http2ListenerConfig::default()
                    .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()])),
            ))
            .unwrap();
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
                Frame::GoAway(goaway) => {
                    panic!("finalizer failure must be stream-local: {goaway:?}")
                }
                _ => {}
            }
        }
        assert_eq!(finalized.load(Ordering::SeqCst), 1);
        wait_for("failed finalizer must retire its request guard", || {
            in_flight.load(Ordering::SeqCst) == 0
        });
        drop(peer);
        assert!(manager.begin_drain(Duration::from_secs(2)));
        assert!(
            runtime
                .block_on(run)
                .unwrap()
                .drain_report
                .unwrap()
                .reached_quiescence
        );
        wait_for("failed finalizer must retire its tasks", || {
            runtime.is_quiescent()
        });
        assert_eq!(manager.active_count(), 0);
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert_eq!(runtime.draining_region_count(), 0);
    }
}

mod body_budget {
    use super::*;
    use asupersync::http::h2::HpackDecoder;
    use asupersync::http::h2::frame::DataFrame;
    use asupersync::http::h2::listener::Http2ListenerStats;
    use asupersync::server::connection::ConnectionManager;

    struct BudgetPeer {
        wire: Peer,
        decoder: HpackDecoder,
        ping_sequence: u64,
    }

    impl BudgetPeer {
        fn connect(address: SocketAddr) -> Self {
            Self {
                wire: Peer::connect(address, false, false),
                decoder: HpackDecoder::new(),
                ping_sequence: 0,
            }
        }

        fn upload(&mut self, stream_id: u32, path: &str) {
            let mut headers = BytesMut::new();
            self.wire.encoder.encode(
                &[
                    Header::new(":method", "POST"),
                    Header::new(":scheme", "http"),
                    Header::new(":path", path),
                    Header::new(":authority", "localhost"),
                ],
                &mut headers,
            );
            self.wire.send(Frame::Headers(HeadersFrame::new(
                stream_id,
                headers.freeze(),
                false,
                true,
            )));
        }

        fn data(&mut self, stream_id: u32, bytes: &[u8], end_stream: bool) {
            self.wire.send(Frame::Data(DataFrame::new(
                stream_id,
                Bytes::from(bytes.to_vec()),
                end_stream,
            )));
        }

        fn trailers(&mut self, stream_id: u32) {
            let mut headers = BytesMut::new();
            self.wire
                .encoder
                .encode(&[Header::new("x-budget", "complete")], &mut headers);
            self.wire.send(Frame::Headers(HeadersFrame::new(
                stream_id,
                headers.freeze(),
                true,
                true,
            )));
        }

        // A matching PING ACK proves that every preceding frame on this
        // connection reached the listener before its byte counter is read.
        fn barrier(&mut self) {
            self.ping_sequence += 1;
            let payload = self.ping_sequence.to_be_bytes();
            self.wire.send(Frame::Ping(PingFrame::new(payload)));
            loop {
                match self.wire.receive() {
                    Frame::Ping(ping) if ping.ack && ping.opaque_data == payload => return,
                    Frame::Settings(_) | Frame::WindowUpdate(_) => {}
                    frame => panic!("unexpected frame before budget barrier: {frame:?}"),
                }
            }
        }

        fn reset(&mut self, stream_id: u32) {
            self.wire.send(Frame::RstStream(RstStreamFrame::new(
                stream_id,
                ErrorCode::Cancel,
            )));
            self.barrier();
        }

        fn refused(&mut self, stream_id: u32) {
            loop {
                match self.wire.receive() {
                    Frame::RstStream(reset) => {
                        assert_eq!(reset.stream_id, stream_id);
                        assert_eq!(reset.error_code, ErrorCode::EnhanceYourCalm);
                        return;
                    }
                    Frame::Settings(_) | Frame::WindowUpdate(_) => {}
                    frame => panic!("budget refusal must reset only its stream: {frame:?}"),
                }
            }
        }

        fn response(&mut self, stream_id: u32, expected: &[u8]) {
            let mut status = None;
            let mut body = Vec::new();
            loop {
                match self.wire.receive() {
                    Frame::Headers(headers) => {
                        assert_eq!(headers.stream_id, stream_id);
                        assert!(headers.end_headers);
                        assert!(status.is_none(), "unexpected response trailers");
                        let mut block = headers.header_block;
                        let decoded = self.decoder.decode(&mut block).unwrap();
                        status = decoded
                            .into_iter()
                            .find(|header| header.name == ":status")
                            .map(|header| header.value);
                        if headers.end_stream {
                            break;
                        }
                    }
                    Frame::Data(data) => {
                        assert_eq!(data.stream_id, stream_id);
                        assert!(status.is_some(), "response DATA needs HEADERS");
                        body.extend_from_slice(&data.data);
                        if data.end_stream {
                            break;
                        }
                    }
                    Frame::Settings(_) | Frame::WindowUpdate(_) => {}
                    frame => panic!("admitted request must complete normally: {frame:?}"),
                }
            }
            assert_eq!(status.as_deref(), Some("200"));
            assert_eq!(body, expected);
        }

        fn sibling(&mut self, stream_id: u32) {
            self.wire.request(stream_id, "/sibling");
            self.response(stream_id, b"");
        }
    }

    struct HandlerState {
        parked: std::sync::mpsc::Sender<usize>,
        cleaning: std::sync::mpsc::Sender<Cx>,
        release: Notify,
        released: AtomicBool,
        calls: AtomicUsize,
        parked_drops: AtomicUsize,
    }

    struct ParkedHandlerDrop(Arc<HandlerState>);

    impl Drop for ParkedHandlerDrop {
        fn drop(&mut self) {
            self.0.parked_drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn answer(request: Request, state: Arc<HandlerState>) -> Response {
        state.calls.fetch_add(1, Ordering::SeqCst);
        if request.uri == "/park" || request.uri == "/cancel" {
            let _drop = ParkedHandlerDrop(Arc::clone(&state));
            let cx = Cx::current().expect("request context installed while polling handler");
            if request.uri == "/cancel" {
                let mut cancelled = std::pin::pin!(cx.cancelled());
                let mut witnessed = false;
                poll_fn(|task| {
                    let result = cancelled.as_mut().poll(task);
                    if result.is_pending() && !witnessed {
                        state.parked.send(request.body.len()).unwrap();
                        witnessed = true;
                    }
                    result
                })
                .await;
                assert!(cx.is_cancel_requested());
            }
            let mut release = std::pin::pin!(
                state
                    .release
                    .wait_until(|| state.released.load(Ordering::Acquire))
            );
            let mut witnessed = false;
            poll_fn(|task| {
                let result = release.as_mut().poll(task);
                if result.is_pending() && !witnessed {
                    if request.uri == "/cancel" {
                        state.cleaning.send(cx.clone()).unwrap();
                    } else {
                        state.parked.send(request.body.len()).unwrap();
                    }
                    witnessed = true;
                }
                result
            })
            .await;
        }
        if request.uri == "/trailers" {
            assert_eq!(
                request.trailers,
                vec![("x-budget".to_owned(), "complete".to_owned())],
            );
        }
        // Consuming the actual body after the gate keeps its Vec alive while
        // the parked witness is observed; END_STREAM alone cannot free credit.
        Response::new(200, "OK", request.body)
    }

    struct Fixture {
        address: SocketAddr,
        stats: Arc<Http2ListenerStats>,
        state: Arc<HandlerState>,
        parked: std::sync::mpsc::Receiver<usize>,
        cleaning: std::sync::mpsc::Receiver<Cx>,
        manager: ConnectionManager,
    }

    fn observe(label: &str, condition: impl Fn() -> bool) {
        let started = Instant::now();
        while !condition() {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "budget cleanup watchdog: {label}"
            );
            std::thread::yield_now();
        }
    }

    fn exercise(workers: usize, limit: Option<NonZeroUsize>, workflow: impl FnOnce(&Fixture)) {
        let runtime = RuntimeBuilder::new()
            .worker_threads(workers)
            .with_sharded_state(workers == 2)
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap();
        let (parked, pending) = std::sync::mpsc::channel();
        let (cleaning, cleanup) = std::sync::mpsc::channel();
        let state = Arc::new(HandlerState {
            parked,
            cleaning,
            release: Notify::new(),
            released: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            parked_drops: AtomicUsize::new(0),
        });
        let handler_state = Arc::clone(&state);
        let listener = runtime
            .block_on(Http2Listener::bind_with_config(
                "127.0.0.1:0",
                move |request| answer(request, Arc::clone(&handler_state)),
                Http2ListenerConfig::default()
                    .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
                    .max_body_size(16)
                    .request_drain_grace(Duration::from_secs(10))
                    .drain_timeout(Duration::from_secs(2))
                    .hard_drain_timeout(Duration::from_secs(5)),
            ))
            .unwrap();
        let listener = if let Some(limit) = limit {
            listener.max_buffered_request_bytes(limit)
        } else {
            listener
        };
        let fixture = Fixture {
            address: listener.local_addr().unwrap(),
            stats: listener.stats_handle(),
            state,
            parked: pending,
            cleaning: cleanup,
            manager: listener.connection_manager().clone(),
        };
        let in_flight = listener.in_flight_requests();
        let handle = runtime.handle();
        let serving: Pin<Box<dyn Future<Output = _> + Send>> =
            Box::pin(async move { listener.run(&handle).await });
        let run = runtime.handle().spawn(serving);

        workflow(&fixture);

        assert!(fixture.manager.begin_drain(Duration::from_secs(2)));
        assert!(
            runtime
                .block_on(run)
                .unwrap()
                .drain_report
                .unwrap()
                .reached_quiescence
        );
        observe("all native HTTP/2 tasks retired", || runtime.is_quiescent());
        assert_eq!(fixture.stats.buffered_request_body_bytes(), 0);
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.manager.active_count(), 0);
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
    fn aggregate_limit_is_shared_and_pending_credit_survives_only_live_bodies() {
        for workers in [1, 2] {
            exercise(workers, NonZeroUsize::new(8), |fixture| {
                let mut first = BudgetPeer::connect(fixture.address);
                let mut second = BudgetPeer::connect(fixture.address);
                first.upload(1, "/echo");
                first.data(1, b"aaaaaa", false);
                first.barrier();
                assert_eq!(fixture.stats.buffered_request_body_bytes(), 6);

                // Two individually valid bodies on different connections reach
                // the exact global boundary without invoking either handler.
                second.upload(1, "/rejected");
                second.data(1, b"bb", false);
                second.barrier();
                assert_eq!(fixture.stats.buffered_request_body_bytes(), 8);
                assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
                assert_eq!(fixture.stats.body_budget_refusals_total(), 0);

                second.data(1, b"x", false);
                second.refused(1);
                assert_eq!(fixture.stats.buffered_request_body_bytes(), 6);
                assert_eq!(fixture.stats.body_budget_refusals_total(), 1);
                second.sibling(3);
                assert_eq!(fixture.stats.buffered_request_body_bytes(), 6);

                second.upload(5, "/echo");
                second.data(5, b"cc", true);
                second.response(5, b"cc");
                observe("replacement body's handler retired", || {
                    fixture.stats.buffered_request_body_bytes() == 6
                });

                first.reset(1);
                assert_eq!(fixture.stats.buffered_request_body_bytes(), 0);
                second.upload(7, "/echo");
                second.data(7, b"12345678", true);
                second.response(7, b"12345678");
                observe("exact-limit completed body retired", || {
                    fixture.stats.buffered_request_body_bytes() == 0
                });

                // Trailing HEADERS use a separate buffered-dispatch path.
                first.upload(3, "/trailers");
                first.data(3, b"trail!", false);
                first.barrier();
                assert_eq!(fixture.stats.buffered_request_body_bytes(), 6);
                first.trailers(3);
                first.response(3, b"trail!");
                observe("trailer-completed body retired", || {
                    fixture.stats.buffered_request_body_bytes() == 0
                });

                first.upload(5, "/echo");
                first.data(5, b"closed", false);
                first.barrier();
                assert_eq!(fixture.stats.buffered_request_body_bytes(), 6);
                drop(first);
                observe("disconnected connection retired", || {
                    fixture.manager.active_count() == 1
                        && fixture.stats.buffered_request_body_bytes() == 0
                });

                second.upload(9, "/echo");
                second.data(9, b"reusable", true);
                second.response(9, b"reusable");
                assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 5);
                assert_eq!(fixture.stats.body_budget_refusals_total(), 1);
            });
        }
    }

    #[test]
    fn dispatched_body_stays_charged_until_parked_handler_retires() {
        for workers in [1, 2] {
            exercise(workers, NonZeroUsize::new(8), |fixture| {
                let mut first = BudgetPeer::connect(fixture.address);
                let mut second = BudgetPeer::connect(fixture.address);
                first.upload(1, "/park");
                first.data(1, b"retained", true);
                assert_eq!(
                    fixture.parked.recv_timeout(Duration::from_secs(5)).unwrap(),
                    8,
                );
                assert_eq!(fixture.stats.buffered_request_body_bytes(), 8);
                assert_eq!(fixture.state.parked_drops.load(Ordering::SeqCst), 0);

                second.upload(1, "/rejected");
                second.data(1, b"x", true);
                second.refused(1);
                assert_eq!(fixture.stats.body_budget_refusals_total(), 1);
                second.sibling(3);
                assert_eq!(fixture.stats.buffered_request_body_bytes(), 8);
                assert_eq!(fixture.state.parked_drops.load(Ordering::SeqCst), 0);

                fixture.state.released.store(true, Ordering::Release);
                fixture.state.release.notify_waiters();
                first.response(1, b"retained");
                observe("parked handler actually retired", || {
                    fixture.stats.buffered_request_body_bytes() == 0
                });
                assert_eq!(fixture.state.parked_drops.load(Ordering::SeqCst), 1);

                second.upload(5, "/echo");
                second.data(5, b"reusable", true);
                second.response(5, b"reusable");
                assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 3);
                assert_eq!(fixture.stats.body_budget_refusals_total(), 1);
            });
        }
    }

    #[test]
    fn reset_and_disconnect_keep_credit_until_handler_cleanup_retires() {
        for workers in [1, 2] {
            for disconnect in [false, true] {
                exercise(workers, NonZeroUsize::new(8), |fixture| {
                    let mut first = BudgetPeer::connect(fixture.address);
                    let mut second = BudgetPeer::connect(fixture.address);
                    first.upload(1, "/cancel");
                    first.data(1, b"retained", true);
                    assert_eq!(
                        fixture.parked.recv_timeout(Duration::from_secs(5)).unwrap(),
                        8,
                    );
                    if disconnect {
                        first
                            .wire
                            .socket
                            .shutdown(std::net::Shutdown::Both)
                            .unwrap();
                    } else {
                        first.reset(1);
                    }
                    let cx = fixture
                        .cleaning
                        .recv_timeout(Duration::from_secs(5))
                        .unwrap();
                    assert!(cx.is_cancel_requested());
                    assert_eq!(fixture.state.parked_drops.load(Ordering::SeqCst), 0);
                    assert_eq!(fixture.stats.buffered_request_body_bytes(), 8);

                    second.upload(1, "/rejected");
                    second.data(1, b"x", true);
                    second.refused(1);
                    second.sibling(3);
                    assert_eq!(fixture.stats.buffered_request_body_bytes(), 8);
                    assert_eq!(fixture.state.parked_drops.load(Ordering::SeqCst), 0);
                    assert_eq!(fixture.stats.body_budget_refusals_total(), 1);

                    fixture.state.released.store(true, Ordering::Release);
                    fixture.state.release.notify_waiters();
                    observe("cancelled handler body actually retired", || {
                        fixture.stats.buffered_request_body_bytes() == 0
                    });
                    assert_eq!(fixture.state.parked_drops.load(Ordering::SeqCst), 1);
                    second.upload(5, "/echo");
                    second.data(5, b"reusable", true);
                    second.response(5, b"reusable");
                    if !disconnect {
                        first.sibling(3);
                    }
                    assert_eq!(
                        fixture.state.calls.load(Ordering::SeqCst),
                        if disconnect { 3 } else { 4 },
                    );
                });
            }
        }
    }

    #[test]
    fn unlimited_default_preserves_stream_and_connection_body_limits() {
        for workers in [1, 2] {
            exercise(workers, None, |fixture| {
                let mut first = BudgetPeer::connect(fixture.address);
                let mut second = BudgetPeer::connect(fixture.address);
                for stream_id in [1, 3, 5, 7] {
                    first.upload(stream_id, "/echo");
                    first.data(stream_id, b"0123456789abcdef", false);
                    second.upload(stream_id, "/echo");
                    second.data(stream_id, b"0123456789abcdef", false);
                }
                first.barrier();
                second.barrier();
                assert_eq!(fixture.stats.buffered_request_body_bytes(), 128);

                // The existing four-body connection cap still refuses excess
                // buffering even though no listener-wide cap was configured.
                first.upload(9, "/connection-limit");
                first.data(9, b"x", false);
                first.refused(9);
                assert_eq!(fixture.stats.buffered_request_body_bytes(), 128);

                // Leave room under the connection cap before violating only
                // stream 1's individual body limit.
                second.reset(7);
                assert_eq!(fixture.stats.buffered_request_body_bytes(), 112);
                second.data(1, b"x", false);
                second.refused(1);
                assert_eq!(fixture.stats.buffered_request_body_bytes(), 96);
                assert_eq!(fixture.stats.body_budget_refusals_total(), 0);
                assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 0);
                first.sibling(11);

                for stream_id in [1, 3, 5, 7] {
                    first.reset(stream_id);
                }
                assert_eq!(fixture.stats.buffered_request_body_bytes(), 32);
                drop(second);
                observe("unlimited pending bodies reclaimed on disconnect", || {
                    fixture.manager.active_count() == 1
                        && fixture.stats.buffered_request_body_bytes() == 0
                });

                first.upload(13, "/echo");
                first.data(13, b"0123456789abcdef", true);
                first.response(13, b"0123456789abcdef");
                assert_eq!(fixture.stats.body_budget_refusals_total(), 0);
                assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 2);
            });
        }
    }
}
