//! Real native H2 sockets plus focused ownership/encoding regressions.
//!
//! br-asupersync-server-stack-hardening-eeexl1.10; fixtures use an independent
//! raw H2 peer with finite socket/readiness bounds, not loopback RPC simulation.

use super::*;
use crate::grpc::server::Interceptor;
use crate::grpc::service::{
    MethodDescriptor, NamedService, ServiceDescriptor, ServiceHandlerFuture,
    ServiceStreamingFuture,
};
use crate::grpc::streaming::Streaming;
use crate::http::h2::{Header, HpackDecoder};
use crate::runtime::RuntimeBuilder;
use crate::server::shutdown::ShutdownSignal;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc as sync_mpsc;
use std::task::{Context, Wake, Waker};

const METHODS: &[MethodDescriptor] = &[
    MethodDescriptor::server_streaming("Values", "/test.Watch/Values"),
    MethodDescriptor::unary("Echo", "/test.Watch/Echo"),
    MethodDescriptor::bidi_streaming("Bidi", "/test.Watch/Bidi"),
];
static DESCRIPTOR: ServiceDescriptor = ServiceDescriptor {
    name: "Watch",
    package: "test",
    methods: METHODS,
};

#[derive(Clone, Copy)]
enum Mode {
    Values,
    Empty,
    Error,
    Never,
    Infinite,
    Oversized,
    ForgedTrailer,
}

struct Probe {
    calls: AtomicUsize,
    polls: AtomicUsize,
    drops: AtomicUsize,
    started: sync_mpsc::Sender<Cx>,
    retired: sync_mpsc::Sender<()>,
}

struct FixtureService {
    probe: Arc<Probe>,
    mode: Mode,
}

impl NamedService for FixtureService {
    const NAME: &'static str = "test.Watch";
}

impl ServiceHandler for FixtureService {
    fn descriptor(&self) -> &ServiceDescriptor {
        &DESCRIPTOR
    }

    fn method_names(&self) -> Vec<&str> {
        vec!["Values", "Echo", "Bidi"]
    }

    fn call_unary<'a>(
        &'a self,
        _cx: &'a Cx,
        _path: &'a str,
        request: Request<Bytes>,
        _trailers: Metadata,
    ) -> ServiceHandlerFuture<'a> {
        Box::pin(async move { Ok(Response::new(request.into_inner())) })
    }

    fn call_server_streaming<'a>(
        &'a self,
        cx: &'a Cx,
        _path: &'a str,
        _request: Request<Bytes>,
        _trailers: Metadata,
    ) -> ServiceStreamingFuture<'a> {
        self.probe.calls.fetch_add(1, Ordering::SeqCst);
        let stream = FixtureStream {
            probe: Arc::clone(&self.probe),
            cx: cx.clone(),
            mode: self.mode,
            index: 0,
        };
        Box::pin(async move {
            let mut trailers = Metadata::new();
            assert!(trailers.insert("x-end", "finished"));
            assert!(trailers.insert_bin("x-proof-bin", Bytes::from(vec![0, 255])));
            if matches!(stream.mode, Mode::ForgedTrailer) {
                assert!(trailers.insert("grpc-status", "0"));
            }
            Ok(RegisteredServerStream::new(stream).with_trailers(trailers))
        })
    }
}

struct FixtureStream {
    probe: Arc<Probe>,
    cx: Cx,
    mode: Mode,
    index: usize,
}

impl Streaming for FixtureStream {
    type Message = Bytes;

    fn poll_next(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, Status>>> {
        self.probe.polls.fetch_add(1, Ordering::SeqCst);
        if self.index == 0 {
            let _ = self.probe.started.send(self.cx.clone());
        }
        let index = self.index;
        self.index += 1;
        match self.mode {
            Mode::Never => Poll::Pending,
            Mode::Empty => Poll::Ready(None),
            Mode::Infinite => Poll::Ready(Some(Ok(Bytes::from(vec![0x33; 4096])))),
            Mode::Oversized => Poll::Ready(Some(Ok(Bytes::from(vec![0x44; 4097])))),
            Mode::Error if index == 1 => {
                Poll::Ready(Some(Err(Status::invalid_argument("bad %\n"))))
            }
            Mode::Error if index > 1 => panic!("stream polled after its terminal error"),
            _ if index >= 2 => Poll::Ready(None),
            _ => Poll::Ready(Some(Ok(Bytes::from(vec![
                if index == 0 { 0x11 } else { 0x22 };
                3000
            ])))),
        }
    }
}

impl Drop for FixtureStream {
    fn drop(&mut self) {
        self.probe.drops.fetch_add(1, Ordering::SeqCst);
        let _ = self.probe.retired.send(());
    }
}

struct Deny;
impl Interceptor for Deny {
    fn intercept_request(&self, _request: &mut Request<Bytes>) -> Result<(), Status> {
        Err(Status::unauthenticated("denied"))
    }

    fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
        Ok(())
    }
}

struct StopOnDrop(ShutdownSignal);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.trigger_immediate();
    }
}

#[derive(Default)]
struct WireReply {
    initial: Vec<Header>,
    trailers: Vec<Header>,
    body: Vec<u8>,
    reset: Option<u32>,
}

impl WireReply {
    fn trailer(&self, name: &str) -> Option<&str> {
        self.trailers
            .iter()
            .find(|header| header.name == name)
            .map(|header| header.value.as_str())
    }

    fn messages(&self) -> Vec<Vec<u8>> {
        let mut bytes = self.body.as_slice();
        let mut messages = Vec::new();
        while !bytes.is_empty() {
            assert!(bytes.len() >= 5, "truncated gRPC message header");
            assert_eq!(bytes[0], 0, "identity compression expected");
            let length = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
            assert!(bytes.len() - 5 >= length, "truncated gRPC message payload");
            messages.push(bytes[5..5 + length].to_vec());
            bytes = &bytes[5 + length..];
        }
        messages
    }
}

struct Peer {
    socket: TcpStream,
    decoder: HpackDecoder,
    reply: WireReply,
}

impl Peer {
    fn new(addr: SocketAddr, window: u32, path: &str, timeout: Option<&str>) -> Self {
        let socket = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
            .expect("connect native listener");
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut peer = Self {
            socket,
            decoder: HpackDecoder::new(),
            reply: WireReply::default(),
        };
        peer.socket.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
        let mut settings = vec![0, 4]; // SETTINGS_INITIAL_WINDOW_SIZE
        settings.extend_from_slice(&window.to_be_bytes());
        peer.send(4, 0, 0, &settings);
        let mut headers = Vec::new();
        for (name, value) in [
            (":method", "POST"),
            (":scheme", "http"),
            (":authority", "localhost"),
            (":path", path),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
        ] {
            literal(&mut headers, name, value);
        }
        if let Some(timeout) = timeout {
            literal(&mut headers, "grpc-timeout", timeout);
        }
        peer.send(1, 4, 1, &headers); // HEADERS / END_HEADERS
        peer.send(0, 1, 1, &[0, 0, 0, 0, 0]); // one empty request; END_STREAM
        peer
    }

    fn send(&mut self, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
        let length = u32::try_from(payload.len()).unwrap();
        assert!(length <= 0x00ff_ffff);
        let mut header = [0u8; 9];
        header[..3].copy_from_slice(&length.to_be_bytes()[1..]);
        header[3] = kind;
        header[4] = flags;
        header[5..].copy_from_slice(&stream.to_be_bytes());
        self.socket.write_all(&header).unwrap();
        self.socket.write_all(payload).unwrap();
    }

    fn frame(&mut self) -> (u8, u8, u32, Vec<u8>) {
        let mut header = [0u8; 9];
        self.socket.read_exact(&mut header).expect("native H2 frame");
        let len = (usize::from(header[0]) << 16)
            | (usize::from(header[1]) << 8)
            | usize::from(header[2]);
        assert!(len <= 1024 * 1024, "test peer frame budget");
        let mut payload = vec![0u8; len];
        self.socket.read_exact(&mut payload).unwrap();
        (
            header[3],
            header[4],
            u32::from_be_bytes(header[5..].try_into().unwrap()) & 0x7fff_ffff,
            payload,
        )
    }

    // Return (terminal, ping_ack). HPACK state is shared across response blocks.
    fn step(&mut self) -> (bool, bool) {
        let (kind, flags, stream, mut payload) = self.frame();
        match kind {
            4 if flags & 1 == 0 => self.send(4, 1, 0, &[]),
            6 if flags & 1 == 0 => self.send(6, 1, 0, &payload),
            6 => return (false, payload == b"credit!!"),
            0 if stream == 1 => {
                assert_eq!(flags & 8, 0, "fixture server emits unpadded DATA");
                self.reply.body.extend_from_slice(&payload);
                return (flags & 1 != 0, false);
            }
            1 if stream == 1 => {
                assert_eq!(flags & (8 | 32), 0, "fixture emits plain HEADERS");
                let mut last_flags = flags;
                while last_flags & 4 == 0 {
                    let (kind, next_flags, next_stream, next) = self.frame();
                    assert_eq!((kind, next_stream), (9, 1));
                    payload.extend_from_slice(&next);
                    last_flags = next_flags;
                }
                let headers = self
                    .decoder
                    .decode(&mut Bytes::from(payload))
                    .expect("decode response HPACK");
                if self.reply.initial.is_empty() {
                    self.reply.initial = headers;
                } else {
                    self.reply.trailers = headers;
                }
                return (flags & 1 != 0, false);
            }
            3 if stream == 1 => {
                self.reply.reset = Some(u32::from_be_bytes(payload.try_into().unwrap()));
                return (true, false);
            }
            7 => panic!("unexpected GOAWAY before test completion: {payload:?}"),
            _ => {}
        }
        (false, false)
    }

    fn finish(&mut self) {
        for _ in 0..20_000 {
            if self.step().0 {
                return;
            }
        }
        panic!("response exceeded test frame budget");
    }

    fn reset(&mut self) {
        self.send(3, 0, 1, &8u32.to_be_bytes());
    }
}

// Deliberately simple independent HPACK fixture encoder (no Huffman/indexing).
fn literal(block: &mut Vec<u8>, name: &str, value: &str) {
    assert!(name.len() < 128 && value.len() < 128);
    block.push(0);
    block.push(u8::try_from(name.len()).unwrap());
    block.extend_from_slice(name.as_bytes());
    block.push(u8::try_from(value.len()).unwrap());
    block.extend_from_slice(value.as_bytes());
}

fn stream_config() -> ServerStreamingConfig {
    ServerStreamingConfig {
        frame_capacity: NonZeroUsize::new(2).unwrap(),
        max_frame_bytes: NonZeroUsize::new(1024).unwrap(),
        max_trailer_bytes: 1024,
        terminal_timeout: Duration::from_millis(200),
    }
}

fn wire_case<F>(
    mode: Mode,
    window: u32,
    path: &'static str,
    timeout: Option<&'static str>,
    deny: bool,
    client: F,
) -> Arc<Probe>
where
    F: FnOnce(&mut Peer, sync_mpsc::Receiver<Cx>, sync_mpsc::Receiver<()>, &Arc<Probe>)
        + Send
        + 'static,
{
    let (started, starts) = sync_mpsc::channel();
    let (retired, retirements) = sync_mpsc::channel();
    let probe = Arc::new(Probe {
        calls: AtomicUsize::new(0),
        polls: AtomicUsize::new(0),
        drops: AtomicUsize::new(0),
        started,
        retired,
    });
    let fixture = FixtureService {
        mode,
        probe: Arc::clone(&probe),
    };
    let mut server = Server::builder().add_service(fixture).build();
    if deny {
        server.interceptors.push(Arc::new(Deny));
    }
    server.config.max_send_message_size = 4096;
    let server = Arc::new(server);
    let runtime = RuntimeBuilder::current_thread().build().expect("native test runtime");
    let handle = runtime.handle().clone();
    let peer_probe = Arc::clone(&probe);
    runtime.block_on(runtime.handle().spawn(async move {
        let listener = server
            .bind_registered_streaming_http2(
                "127.0.0.1:0", HostPolicy::allow_all(), stream_config(),
            )
            .await
            .expect("bind native streaming listener");
        let addr = listener.local_addr().unwrap();
        let shutdown = listener.shutdown_signal();
        let peer = std::thread::spawn(move || {
            let _stop = StopOnDrop(shutdown); // Also stops the server on assertion failure.
            let mut peer = Peer::new(addr, window, path, timeout);
            client(&mut peer, starts, retirements, &peer_probe);
        });
        let served = listener.run_produced(&handle).await;
        peer.join().expect("native wire assertions");
        served.expect("native listener stopped");
    }));
    probe
}

#[test]
fn native_registered_stream_sends_multiple_framed_messages_and_binary_trailers() {
    let probe = wire_case(
        Mode::Values, 65_535, "/test.Watch/Values", None, false,
        |peer, _, retired, _| {
            peer.finish();
            assert_eq!(peer.reply.reset, None);
            assert_eq!(peer.reply.messages(), vec![vec![0x11; 3000], vec![0x22; 3000]]);
            assert_eq!(peer.reply.trailer("grpc-status"), Some("0"));
            assert_eq!(peer.reply.trailer("x-end"), Some("finished"));
            assert_eq!(peer.reply.trailer("x-proof-bin"), Some("AP8"));
            retired.recv_timeout(Duration::from_secs(2))
                .expect("stream destroyed before terminal receipt");
        },
    );
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn native_empty_stream_has_success_trailers_without_a_phantom_message() {
    wire_case(
        Mode::Empty, 65_535, "/test.Watch/Values", None, false,
        |peer, _, _, _| {
            peer.finish();
            assert!(peer.reply.body.is_empty());
            assert_eq!(peer.reply.trailer("grpc-status"), Some("0"));
        },
    );
}

#[test]
fn native_stream_error_preserves_prior_complete_message_and_non_ok_status() {
    let probe = wire_case(
        Mode::Error, 65_535, "/test.Watch/Values", None, false,
        |peer, _, _, _| {
            peer.finish();
            assert_eq!(peer.reply.messages(), vec![vec![0x11; 3000]]);
            assert_eq!(peer.reply.trailer("grpc-status"), Some("3"));
            assert_eq!(peer.reply.trailer("grpc-message"), Some("bad %25%0A"));
            assert_eq!(peer.reply.trailer("x-end"), None);
        },
    );
    assert_eq!(probe.polls.load(Ordering::SeqCst), 2);
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn native_zero_credit_bounds_prefetch_then_window_update_resumes_production() {
    wire_case(
        Mode::Infinite, 0, "/test.Watch/Values", None, false,
        |peer, started, retired, probe| {
            while peer.reply.initial.is_empty() {
                assert!(!peer.step().0);
            }
            started.recv_timeout(Duration::from_secs(2)).expect("first stream poll reached");
            peer.send(6, 0, 0, b"credit!!");
            loop {
                let (done, ack) = peer.step();
                assert!(!done);
                if ack {
                    break;
                }
            }
            assert!(peer.reply.body.is_empty(), "no DATA without peer credit");
            // A 4101-byte framed message cannot fit in the 2 * 1024-byte channel.
            assert_eq!(probe.polls.load(Ordering::SeqCst), 1,
                "source must stop behind the first message");
            peer.send(8, 0, 1, &65_535u32.to_be_bytes());
            while peer.reply.body.len() < 3 * 4101 {
                assert!(!peer.step().0);
            }
            assert!(probe.polls.load(Ordering::SeqCst) >= 3,
                "WINDOW_UPDATE resumes source polls");
            peer.reset();
            retired.recv_timeout(Duration::from_secs(2))
                .expect("credit-blocked stream retired on RST");
            assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
        },
    );
}

#[test]
fn native_rst_wakes_and_retires_a_parked_service_stream() {
    wire_case(
        Mode::Never, 65_535, "/test.Watch/Values", None, false,
        |peer, started, retired, probe| {
            let cx = started.recv_timeout(Duration::from_secs(2))
                .expect("stream reached Pending");
            assert!(!cx.is_cancel_requested());
            peer.reset();
            retired.recv_timeout(Duration::from_secs(2))
                .expect("parked stream retired after RST");
            assert!(cx.is_cancel_requested());
            assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
        },
    );
}

#[test]
fn native_deadline_covers_the_stream_after_factory_returns() {
    wire_case(
        Mode::Never, 65_535, "/test.Watch/Values", Some("300m"), false,
        |peer, started, retired, _| {
            let cx = started.recv_timeout(Duration::from_secs(2))
                .expect("stream reached Pending before deadline");
            peer.finish();
            assert!(peer.reply.body.is_empty());
            assert_eq!(peer.reply.trailer("grpc-status"), Some("4"));
            retired.recv_timeout(Duration::from_secs(2)).expect("deadline drops stream");
            assert!(cx.is_cancel_requested());
        },
    );
}

#[test]
fn native_deadline_mid_message_never_reports_clean_grpc_completion() {
    wire_case(
        Mode::Infinite, 0, "/test.Watch/Values", Some("300m"), false,
        |peer, started, retired, _| {
            started.recv_timeout(Duration::from_secs(2)).expect("message production started");
            peer.finish();
            assert!(peer.reply.reset.is_some(), "incomplete message requires H2 failure");
            assert!(peer.reply.body.is_empty());
            assert_eq!(peer.reply.trailer("grpc-status"), None);
            retired.recv_timeout(Duration::from_secs(2)).expect("timed-out source retired");
        },
    );
}

#[test]
fn native_message_limit_and_reserved_trailers_fail_closed() {
    for mode in [Mode::Oversized, Mode::ForgedTrailer] {
        wire_case(
            mode, 65_535, "/test.Watch/Values", None, false,
            move |peer, _, _, _| {
                peer.finish();
                let expected = if matches!(mode, Mode::Oversized) { "8" } else { "13" };
                assert_eq!(peer.reply.trailer("grpc-status"), Some(expected));
                if matches!(mode, Mode::Oversized) {
                    assert!(peer.reply.body.is_empty());
                }
            },
        );
    }
}

#[test]
fn native_auth_short_circuits_stream_factory() {
    let probe = wire_case(
        Mode::Values, 65_535, "/test.Watch/Values", None, true,
        |peer, _, _, _| {
            peer.finish();
            assert_eq!(peer.reply.trailer("grpc-status"), Some("16"));
            assert!(peer.reply.body.is_empty());
        },
    );
    assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn native_mixed_listener_preserves_unary_and_refuses_bidi() {
    for (path, status) in [
        ("/test.Watch/Echo", "0"),
        ("/test.Watch/Bidi", "12"),
        ("/test.Watch/Missing", "12"),
    ] {
        let probe = wire_case(
            Mode::Values, 65_535, path, None, false,
            move |peer, _, _, _| {
                peer.finish();
                assert_eq!(peer.reply.trailer("grpc-status"), Some(status));
                if status == "0" {
                    assert_eq!(peer.reply.messages(), vec![Vec::<u8>::new()]);
                } else {
                    assert!(peer.reply.body.is_empty());
                }
            },
        );
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn streaming_config_rejects_unbounded_terminal_or_overflowing_retention() {
    let mut config = stream_config();
    assert!(config.validate().is_ok());
    config.terminal_timeout = Duration::ZERO;
    assert!(config.validate().is_err());
    config = stream_config();
    config.max_trailer_bytes = 12;
    assert!(config.validate().is_err());
    config = stream_config();
    config.frame_capacity = NonZeroUsize::new(usize::MAX).unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn terminal_budget_counts_base64_expansion_and_rejects_payload_rewrites() {
    let mut metadata = Metadata::new();
    assert!(metadata.insert_bin("x-bin", Bytes::from(vec![0; 6])));
    let response = Response::with_metadata(Bytes::new(), metadata);
    let headers = bounded_terminal_trailers(Ok(response), 24); // 5 + 8 + 12 = 25, not 23.
    assert_eq!(headers.get(&HeaderName::from_static("grpc-status"))
        .unwrap().to_str().unwrap(), "8");
    let headers = bounded_terminal_trailers(
        Ok(Response::new(Bytes::from_static(b"injected"))), 1024,
    );
    assert_eq!(headers.get(&HeaderName::from_static("grpc-status"))
        .unwrap().to_str().unwrap(), "13");
    let headers = bounded_terminal_trailers(
        Err(Status::invalid_argument("%".repeat(100))), 13,
    );
    assert_eq!(headers.len(), 1);
    assert_eq!(headers.get(&HeaderName::from_static("grpc-status"))
        .unwrap().to_str().unwrap(), "8");
}

#[test]
fn registered_server_stream_accepts_pinned_non_unpin_sources() {
    struct Pinned(std::marker::PhantomPinned);
    impl Streaming for Pinned {
        type Message = Bytes;
        fn poll_next(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Bytes, Status>>> {
            Poll::Ready(None)
        }
    }
    let (mut stream, _) = RegisteredServerStream::new(
        Pinned(std::marker::PhantomPinned),
    ).into_parts();
    assert!(matches!(stream.as_mut().poll_next(
        &mut Context::from_waker(Waker::noop()),
    ), Poll::Ready(None)));
}

#[test]
fn owner_cancellation_wakes_pending_source_without_an_io_event() {
    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let owner = Cx::for_testing();
    let call = Cx::for_testing();
    let count = Arc::new(Count(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&count));
    let mut task = Context::from_waker(&waker);
    let mut future = Box::pin(poll_cancellable(&owner, &call, std::future::pending::<()>()));
    assert!(future.as_mut().poll(&mut task).is_pending());
    owner.cancel_with(CancelKind::User, Some("owner test cancellation"));
    assert!(count.0.load(Ordering::SeqCst) > 0);
    match future.as_mut().poll(&mut task) {
        Poll::Ready(Err(status)) => assert_eq!(status.code(), Code::Cancelled),
        other => panic!("expected attributed cancellation, got {other:?}"),
    }
}

#[test]
fn aliased_owner_cancellation_keeps_deadline_and_budget_attribution() {
    for (kind, code) in [
        (CancelKind::User, Code::Cancelled),
        (CancelKind::Deadline, Code::DeadlineExceeded),
        (CancelKind::CostBudget, Code::ResourceExhausted),
    ] {
        let cx = Cx::for_testing();
        cx.cancel_with(kind, Some("explicit source"));
        let mut task = Context::from_waker(Waker::noop());
        let mut future = Box::pin(poll_cancellable(
            &cx, &cx, std::future::pending::<()>(),
        ));
        match future.as_mut().poll(&mut task) {
            Poll::Ready(Err(status)) => assert_eq!(status.code(), code),
            other => panic!("expected attributed cancellation, got {other:?}"),
        }
        assert_eq!(cx.cancel_reason().unwrap().kind, kind);
    }
}

#[test]
fn legacy_metadata_only_service_keeps_compiling_and_refuses_stream_execution() {
    struct Legacy;
    impl ServiceHandler for Legacy {
        fn descriptor(&self) -> &ServiceDescriptor {
            &DESCRIPTOR
        }

        fn method_names(&self) -> Vec<&str> {
            vec!["Values"]
        }
    }

    let service: Arc<dyn ServiceHandler> = Arc::new(Legacy);
    let cx = Cx::for_testing();
    let mut future = service.call_server_streaming(
        &cx,
        "/test.Watch/Values",
        Request::new(Bytes::new()),
        Metadata::new(),
    );
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(Err(status)) => assert_eq!(status.code(), Code::Unimplemented),
        other => panic!("expected legacy UNIMPLEMENTED result, got {other:?}"),
    }
}
