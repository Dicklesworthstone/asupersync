//! br-asupersync-ymueix: peer-directed backoff for new channel connections.
//! Exact A8 GOAWAY classification, fixed active policies, and real native peers.

use super::*;
use crate::grpc::{Channel, GrpcClient};
use crate::http::h2::ErrorCode;
use crate::runtime::RuntimeBuilder;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::AtomicBool;

const INTERVAL: Duration = Duration::from_secs(2);
const ACK_TIMEOUT: Duration = Duration::from_secs(1);
const REASON: &[u8] = b"too_many_pings";

fn goaway(code: ErrorCode, reason: &[u8]) -> Vec<u8> {
    // Independently encode a connection-level GOAWAY refusing stream 1.
    let length = u32::try_from(8 + reason.len()).unwrap();
    let mut bytes = length.to_be_bytes()[1..].to_vec();
    bytes.extend_from_slice(&[7, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.extend_from_slice(&u32::from(code).to_be_bytes());
    bytes.extend_from_slice(reason);
    bytes
}

fn rejection() -> Option<ReceivedFrame> {
    Some(ReceivedFrame::GoAway {
        last_stream_id: 0,
        error_code: ErrorCode::EnhanceYourCalm,
        debug_data: Bytes::from_static(REASON),
    })
}

fn observed_owner(backoff: &Arc<KeepaliveBackoff>) -> NativeServerStream<FixtureIo, IdentityCodec> {
    let (io, _) = fixture(Vec::new(), FRAME_BYTES, false);
    call(io).with_keepalive_backoff(Some(Arc::clone(backoff)))
}

#[test]
fn only_the_exact_valid_goaway_changes_the_interval() {
    for (code, reason, expected) in [
        (ErrorCode::EnhanceYourCalm, REASON, INTERVAL * 2),
        (ErrorCode::NoError, REASON, INTERVAL),
        (ErrorCode::ProtocolError, REASON, INTERVAL),
        (ErrorCode::EnhanceYourCalm, b"TOO_MANY_PINGS".as_slice(), INTERVAL),
        (ErrorCode::EnhanceYourCalm, b"too_many_pings ".as_slice(), INTERVAL),
        (ErrorCode::EnhanceYourCalm, b"too_many_pings\n".as_slice(), INTERVAL),
        (ErrorCode::EnhanceYourCalm, b"other:too_many_pings".as_slice(), INTERVAL),
        (ErrorCode::EnhanceYourCalm, b"".as_slice(), INTERVAL),
    ] {
        let backoff = Arc::new(KeepaliveBackoff::new(INTERVAL));
        let mut bytes = frame(4, 0, &[]);
        bytes.extend(goaway(code, reason));
        let (io, probe) = fixture(bytes, 3, false);
        let mut stream = call(io).with_keepalive_backoff(Some(Arc::clone(&backoff)));
        let error = run(stream.message()).unwrap_err();
        assert_eq!(error.code(), Code::Unavailable);
        assert_eq!(error.message(), "HTTP/2 GOAWAY refused the active gRPC stream");
        assert_eq!(backoff.interval(), expected, "{code:?} {reason:?}");
        assert!(run(stream.message()).unwrap().is_none());
        assert_eq!(backoff.interval(), expected, "terminal polls cannot repeat the feedback");
        assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    }

    // The H2 preface contract still rejects GOAWAY before peer SETTINGS.
    let backoff = Arc::new(KeepaliveBackoff::new(INTERVAL));
    let (io, _) = fixture(goaway(ErrorCode::EnhanceYourCalm, REASON), FRAME_BYTES, false);
    let mut malformed = call(io).with_keepalive_backoff(Some(Arc::clone(&backoff)));
    assert!(run(malformed.message()).is_err());
    assert_eq!(backoff.interval(), INTERVAL);
}

#[test]
fn a_connection_not_each_notification_doubles_the_shared_interval() {
    let backoff = Arc::new(KeepaliveBackoff::new(INTERVAL));
    let mut first = observed_owner(&backoff);
    let mut second = observed_owner(&backoff);
    for _ in 0..3 {
        assert_eq!(first.observe(rejection()).unwrap_err().code(), Code::Unavailable);
        assert_eq!(backoff.interval(), INTERVAL * 2);
    }
    assert_eq!(second.observe(rejection()).unwrap_err().code(), Code::Unavailable);
    assert_eq!(backoff.interval(), INTERVAL * 4);

    let saturating = Arc::new(KeepaliveBackoff::new(Duration::from_secs(u64::MAX / 2 + 1)));
    assert!(observed_owner(&saturating).observe(rejection()).is_err());
    assert_eq!(saturating.interval(), Duration::MAX);
    assert!(observed_owner(&saturating).observe(rejection()).is_err());
    assert_eq!(saturating.interval(), Duration::MAX, "backoff must never wrap or panic");
}

fn timed_owner(
    cx: &Cx,
    backoff: &Arc<KeepaliveBackoff>,
) -> (NativeServerStream<FixtureIo, IdentityCodec>, Arc<Probe>) {
    let (io, probe) = fixture(start(), FRAME_BYTES, false);
    let stream = NativeServerStream::new(
        cx, io, "localhost", "/test.Service/Watch",
        Request::new(Bytes::from_static(b"once")), IdentityCodec,
        NativeStreamConfig { timeout: Some(Duration::from_secs(10)), ..NativeStreamConfig::default() },
    ).unwrap()
        .with_keepalive_backoff(Some(Arc::clone(backoff)))
        .with_keepalive(NativeStreamKeepalive::new(backoff.interval(), ACK_TIMEOUT).unwrap())
        .unwrap();
    (stream, probe)
}

fn probe_count(probe: &Probe) -> usize {
    let writes = probe.writes.lock().unwrap();
    assert!(writes.starts_with(CLIENT_PREFACE));
    let mut bytes = BytesMut::from(&writes[CLIENT_PREFACE.len()..]);
    let mut decoder = FrameCodec::new();
    let mut count = 0;
    while let Some(frame) = decoder.decode(&mut bytes).unwrap() {
        if matches!(frame, Frame::Ping(ping) if !ping.ack) { count += 1; }
    }
    assert!(bytes.is_empty());
    count
}

#[test]
fn backoff_freezes_active_probes_timeouts_and_cancellation() {
    let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(20)));
    let cx = timed_cx(&clock);
    let backoff = Arc::new(KeepaliveBackoff::new(INTERVAL));
    let (mut active, active_probe) = timed_owner(&cx, &backoff);
    run(active.headers()).unwrap();
    assert!(observed_owner(&backoff).observe(rejection()).is_err());
    let (mut future, future_probe) = timed_owner(&cx, &backoff);
    run(future.headers()).unwrap();
    assert_eq!(active.keepalive.as_ref().unwrap().config.interval(), INTERVAL);
    assert_eq!(future.keepalive.as_ref().unwrap().config.interval(), INTERVAL * 2);
    assert_eq!(active.deadline, Some(Time::from_secs(30)));
    assert_eq!(future.deadline, Some(Time::from_secs(30)));

    let mut task = Context::from_waker(Waker::noop());
    clock.advance_to(Time::from_secs(22));
    assert!(active.poll_message(&mut task).is_pending());
    assert!(future.poll_message(&mut task).is_pending());
    assert_eq!(probe_count(&active_probe), 1);
    assert_eq!(probe_count(&future_probe), 0, "future connection must not use the old interval");
    clock.advance_to(Time::from_secs(23));
    assert_eq!(run(active.message()).unwrap_err().code(), Code::Unavailable);
    assert!(future.poll_message(&mut task).is_pending());
    assert_eq!(probe_count(&future_probe), 0);
    clock.advance_to(Time::from_secs(24));
    assert!(future.poll_message(&mut task).is_pending());
    assert_eq!(probe_count(&future_probe), 1);
    clock.advance_to(Time::from_secs(25));
    assert_eq!(run(future.message()).unwrap_err().code(), Code::Unavailable);
    assert_eq!(active_probe.drops.load(Ordering::SeqCst), 1);
    assert_eq!(future_probe.drops.load(Ordering::SeqCst), 1);
    assert_eq!(backoff.interval(), INTERVAL * 2, "ordinary expiry does not trigger backoff");
    assert!(!cx.is_cancel_requested());

    let (mut cancelled, cancelled_probe) = timed_owner(&cx, &backoff);
    assert!(cancelled.poll_message(&mut task).is_pending());
    cx.cancel_with(CancelKind::User, Some("keepalive backoff cancellation regression"));
    assert_eq!(run(cancelled.message()).unwrap_err().code(), Code::Cancelled);
    assert_eq!(cancelled_probe.drops.load(Ordering::SeqCst), 1);
    assert_eq!(backoff.interval(), INTERVAL * 2);
}

#[test]
fn opt_in_without_a_keepalive_interval_keeps_keepalive_disabled() {
    let channel = run(Channel::builder("http://127.0.0.1:50051").keepalive_backoff().connect()).unwrap();
    assert_eq!(channel.effective_keepalive_interval(), None);
    assert_eq!(channel.clone().with_keepalive_backoff().effective_keepalive_interval(), None);
    assert_eq!(channel.config().keepalive_interval, None);
    assert_eq!(channel.config().keepalive_timeout, None);
}

fn accept(listener: &TcpListener) -> std::net::TcpStream {
    let until = std::time::Instant::now() + Duration::from_secs(5);
    let socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(std::time::Instant::now() < until, "native keepalive accept watchdog");
                std::thread::park_timeout(Duration::from_millis(1));
            }
            Err(error) => panic!("native keepalive accept: {error}"),
        }
    };
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    socket
}

fn peer_frame(socket: &mut std::net::TcpStream) -> (u8, u8, u32, Vec<u8>) {
    let mut header = [0_u8; 9];
    socket.read_exact(&mut header).expect("native keepalive frame header");
    let length = (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
    assert!(length <= FRAME_BYTES);
    let stream = u32::from_be_bytes(header[5..9].try_into().unwrap()) & 0x7fff_ffff;
    let mut payload = vec![0; length];
    socket.read_exact(&mut payload).expect("native keepalive frame payload");
    (header[3], header[4], stream, payload)
}

fn request_head(socket: &mut std::net::TcpStream) {
    let mut preface = [0_u8; 24];
    socket.read_exact(&mut preface).unwrap();
    assert_eq!(&preface, CLIENT_PREFACE);
    let mut window_updates = 0;
    for _ in 0..16 {
        let (kind, flags, stream, payload) = peer_frame(socket);
        if kind == 1 {
            assert_eq!(stream, 1);
            assert_ne!(flags & 4, 0);
            let fields = crate::http::h2::HpackDecoder::new()
                .decode(&mut Bytes::from(payload)).unwrap();
            assert!(fields.iter().any(|header| header.name == ":path" && header.value == "/test.Service/Watch"));
            return;
        }
        // A Channel opens its connection window above 65535 with one
        // stream-0 WINDOW_UPDATE after SETTINGS (initial_connection_window_size).
        if kind == 8 {
            window_updates += 1;
            assert_eq!((stream, payload.len(), window_updates), (0, 4, 1), "one connection WINDOW_UPDATE");
            continue;
        }
        assert_eq!(kind, 4, "only SETTINGS and the connection WINDOW_UPDATE precede request HEADERS");
    }
    panic!("missing native keepalive request HEADERS");
}

fn peer_eof(socket: &mut std::net::TcpStream) {
    let mut bytes = [0_u8; 1024];
    for _ in 0..32 {
        if socket.read(&mut bytes).unwrap() == 0 { return; }
    }
    panic!("rejected native connection was not retired");
}

fn native_client<F, Fut>(client: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    let complete = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&complete);
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("native keepalive client context");
        let now = cx.timer_driver().unwrap().now();
        crate::time::timeout(now, Duration::from_secs(8), client(cx))
            .await.expect("native keepalive client watchdog");
        complete.store(true, Ordering::Release);
    }));
    assert!(observed.load(Ordering::Acquire), "native keepalive assertions did not finish");
}

#[derive(Clone, Copy, Debug)]
enum Shape { Server, Duplex, LegacyServer, LegacyBidi }

fn native_rejections(shape: Shape, enabled: bool, code: ErrorCode, reason: &'static [u8]) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        for _ in 0..2 {
            let mut socket = accept(&listener);
            request_head(&mut socket);
            socket.write_all(&start()).unwrap();
            let mut body = Vec::new();
            let mut saw_ping = false;
            for _ in 0..32 {
                let (kind, flags, stream, payload) = peer_frame(&mut socket);
                assert_ne!(kind, 1, "the request HEADERS must not be repeated");
                if kind == 0 {
                    body.extend_from_slice(&payload);
                    assert!(body.len() <= message(b"once").len());
                }
                if kind == 6 {
                    assert_eq!(stream, 0);
                    assert_eq!(flags, 0, "client probe must be a non-ACK PING");
                    assert_eq!(payload.len(), 8);
                    saw_ping = true;
                    break;
                }
            }
            assert!(saw_ping, "peer must observe an actual keepalive probe");
            if matches!(shape, Shape::Server | Shape::LegacyServer) {
                assert_eq!(body, message(b"once"));
            } else {
                assert!(body.is_empty());
            }
            socket.write_all(&goaway(code, reason)).unwrap();
            peer_eof(&mut socket);
        }
    });
    native_client(move |cx| async move {
        let base = Duration::from_millis(25);
        let timeout = Duration::from_secs(2);
        let mut builder = Channel::builder(format!("http://{address}"))
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(4))
            .keepalive_interval(base)
            .keepalive_timeout(timeout);
        if enabled && !matches!(shape, Shape::Duplex) { builder = builder.keepalive_backoff(); }
        let mut channel = builder.connect().await.unwrap();
        if enabled && matches!(shape, Shape::Duplex) { channel = channel.with_keepalive_backoff(); }
        let before_rejection = channel.clone();
        let should_back_off = enabled && code == ErrorCode::EnhanceYourCalm && reason == REASON;
        let mut expected = base;
        for connection in 0..2 {
            let mut cloned = if connection == 0 { channel.clone() } else { before_rejection.clone() };
            if enabled { cloned = cloned.with_keepalive_backoff(); }
            assert_eq!(cloned.effective_keepalive_interval(), Some(expected));
            let mut client = GrpcClient::new(cloned);
            let error = match shape {
                Shape::Server => {
                    let mut stream = client.into_native_server_streaming(
                        &cx, "/test.Service/Watch", Request::new(Bytes::from_static(b"once")),
                    ).await.unwrap();
                    let policy = stream.keepalive.as_ref().unwrap().config;
                    assert_eq!(policy.interval(), expected);
                    assert_eq!(policy.timeout(), timeout);
                    let error = stream.message().await.unwrap_err();
                    assert!(stream.message().await.unwrap().is_none());
                    error
                }
                Shape::Duplex => {
                    let mut stream = client.into_native_duplex(
                        &cx, "/test.Service/Watch", Request::new(()),
                    ).await.unwrap();
                    let error = loop {
                        match stream.next_event().await {
                            Err(error) => break error,
                            Ok(Some(NativeDuplexEvent::RequestFlushed)) => {}
                            other => panic!("unexpected duplex response: {other:?}"),
                        }
                    };
                    assert!(stream.next_event().await.unwrap().is_none());
                    error
                }
                Shape::LegacyServer => {
                    let mut stream = client.server_streaming::<Bytes, Bytes>(
                        "/test.Service/Watch", Request::new(Bytes::from_static(b"once")),
                    ).await.unwrap().into_inner();
                    let error = poll_fn(|task| Pin::new(&mut stream).poll_next(task))
                        .await.unwrap().unwrap_err();
                    assert!(poll_fn(|task| Pin::new(&mut stream).poll_next(task)).await.is_none());
                    error
                }
                Shape::LegacyBidi => {
                    let (mut sink, mut stream) = client.bidi_streaming::<Bytes, Bytes>(
                        "/test.Service/Watch",
                    ).await.unwrap();
                    let error = poll_fn(|task| Pin::new(&mut stream).poll_next(task))
                        .await.unwrap().unwrap_err();
                    assert_eq!(sink.send(Bytes::from_static(b"after-rejection")).await.unwrap_err().code(), error.code());
                    assert!(poll_fn(|task| Pin::new(&mut stream).poll_next(task)).await.is_none());
                    error
                }
            };
            assert_eq!(error.code(), Code::Unavailable);
            if should_back_off { expected *= 2; }
            assert_eq!(channel.effective_keepalive_interval(), Some(expected));
            assert_eq!(before_rejection.effective_keepalive_interval(), Some(expected));
            assert_eq!(channel.config().keepalive_interval, Some(base));
            assert_eq!(channel.config().keepalive_timeout, Some(timeout));
            assert_eq!(channel.config().connect_timeout, Duration::from_secs(3));
            assert_eq!(channel.config().timeout, Some(Duration::from_secs(4)));
            assert!(!cx.is_cancel_requested());
        }
    });
    peer.join().expect("native keepalive peer assertions");
}

#[test]
fn native_channel_clones_back_off_across_owned_and_legacy_connections() {
    for shape in [Shape::Server, Shape::Duplex, Shape::LegacyServer, Shape::LegacyBidi] {
        native_rejections(shape, true, ErrorCode::EnhanceYourCalm, REASON);
    }
}

#[test]
fn native_peer_rejections_require_opt_in_and_the_exact_reason() {
    native_rejections(Shape::Server, false, ErrorCode::EnhanceYourCalm, REASON);
    native_rejections(Shape::Server, true, ErrorCode::ProtocolError, REASON);
    native_rejections(Shape::Duplex, true, ErrorCode::EnhanceYourCalm, b"too_many_pings ");
}

struct PendingFlush {
    inner: crate::net::TcpStream,
    polls: Arc<AtomicUsize>,
}

impl AsyncRead for PendingFlush {
    fn poll_read(self: Pin<&mut Self>, task: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(task, buf)
    }
}

impl AsyncWrite for PendingFlush {
    fn poll_write(self: Pin<&mut Self>, task: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(task, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(task)
    }
}

#[test]
fn native_setup_observes_rejection_before_the_initial_flush_completes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let mut socket = accept(&listener);
        request_head(&mut socket);
        let mut bytes = frame(4, 0, &[]);
        bytes.extend(goaway(ErrorCode::EnhanceYourCalm, REASON));
        socket.write_all(&bytes).unwrap();
        peer_eof(&mut socket);
    });
    native_client(move |cx| async move {
        let backoff = Arc::new(KeepaliveBackoff::new(INTERVAL));
        let flush_polls = Arc::new(AtomicUsize::new(0));
        let observed_flush = Arc::clone(&flush_polls);
        let endpoint = NativeStreamEndpoint::new(address, "localhost", Duration::from_secs(3))
            .unwrap().with_keepalive_backoff(Some(Arc::clone(&backoff)));
        let error = endpoint.connect_with_transport(
            &cx, "/test.Service/Watch", Request::new(Bytes::from_static(b"once")), IdentityCodec,
            NativeStreamConfig::default(), NativeStreamWindows::default(), None,
            move |dialed| async move {
                match dialed {
                    DialedStream::Tcp(inner) => Ok(PendingFlush { inner, polls: flush_polls }),
                    #[cfg(unix)]
                    DialedStream::Unix(_) => Err(Status::internal("TCP fixture received a Unix socket")),
                }
            },
        ).await.unwrap_err();
        assert_eq!(error.code(), Code::Unavailable);
        assert_eq!(backoff.interval(), INTERVAL * 2);
        assert!(observed_flush.load(Ordering::SeqCst) > 0, "setup really parked its flush");
        assert!(!cx.is_cancel_requested());
    });
    peer.join().expect("native setup rejection peer assertions");
}
