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
use asupersync::codec::Decoder as _;
use asupersync::http::h1::server::HostPolicy;
use asupersync::http::h1::types::{Request, Response};
use asupersync::http::h2::connection::CLIENT_PREFACE;
use asupersync::http::h2::frame::{
    Frame, HeadersFrame, PingFrame, Setting, SettingsFrame, WindowUpdateFrame,
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
