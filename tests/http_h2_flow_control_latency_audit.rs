//! Regression tests for HTTP/2 flow-control resume latency.

#[cfg(feature = "test-internals")]
use asupersync::Cx;
use asupersync::bytes::Bytes;
#[cfg(feature = "test-internals")]
use asupersync::bytes::BytesMut;
#[cfg(feature = "test-internals")]
use asupersync::codec::Decoder as _;
#[cfg(feature = "test-internals")]
use asupersync::http::h1::HttpError;
#[cfg(feature = "test-internals")]
use asupersync::http::h1::server::HostPolicy;
#[cfg(feature = "test-internals")]
use asupersync::http::h2::connection::CLIENT_PREFACE;
use asupersync::http::h2::connection::Connection;
use asupersync::http::h2::frame::{Frame, SettingsFrame, WindowUpdateFrame};
#[cfg(feature = "test-internals")]
use asupersync::http::h2::frame::{HeadersFrame, RstStreamFrame};
use asupersync::http::h2::hpack::Header;
#[cfg(feature = "test-internals")]
use asupersync::http::h2::listener::{Http2Listener, Http2ListenerConfig};
use asupersync::http::h2::settings::Settings;
#[cfg(feature = "test-internals")]
use asupersync::http::h2::{ErrorCode, FrameCodec, HpackEncoder};
#[cfg(feature = "test-internals")]
use asupersync::runtime::RuntimeBuilder;
#[cfg(feature = "test-internals")]
use asupersync::web::{
    AsyncCxFnHandler1, FnHandler, Http2StreamResponder, Router, StatusCode, get,
};

fn open_connection() -> Connection {
    let mut conn = Connection::client(Settings::default());
    conn.process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
        .expect("peer SETTINGS should open the connection");

    match conn.next_frame() {
        Some(Frame::Settings(frame)) if frame.ack => {}
        other => panic!("expected SETTINGS ack, got {other:?}"),
    }

    conn
}

fn open_post_stream(conn: &mut Connection, path: &str) -> u32 {
    let headers = vec![
        Header::new(":method", "POST"),
        Header::new(":path", path),
        Header::new(":scheme", "https"),
        Header::new(":authority", "example.com"),
    ];
    let stream_id = conn
        .open_stream(headers, false)
        .expect("POST stream should open");

    match conn.next_frame() {
        Some(Frame::Headers(frame)) if frame.stream_id == stream_id => {}
        other => panic!("expected request HEADERS for stream {stream_id}, got {other:?}"),
    }

    stream_id
}

fn drain_data_until_blocked(conn: &mut Connection) -> usize {
    let mut sent = 0;

    loop {
        match conn.next_frame() {
            Some(Frame::Data(frame)) => sent += frame.data.len(),
            None => return sent,
            Some(other) => panic!("expected DATA or flow-control block, got {other:?}"),
        }
    }
}

#[test]
fn connection_window_update_resumes_blocked_data_immediately() {
    let mut conn = open_connection();
    let stream_id = open_post_stream(&mut conn, "/data");

    conn.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(
        stream_id, 65_535,
    )))
    .expect("stream WINDOW_UPDATE should leave stream window available");
    conn.send_data(stream_id, Bytes::from(vec![0xAB; 70_000]), false)
        .expect("DATA should queue");

    assert_eq!(drain_data_until_blocked(&mut conn), 65_535);
    assert_eq!(
        conn.send_window(),
        0,
        "connection window should be exhausted"
    );

    conn.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(0, 1_024)))
        .expect("connection WINDOW_UPDATE should succeed");

    match conn.next_frame() {
        Some(Frame::Data(frame)) => {
            assert_eq!(frame.stream_id, stream_id);
            assert_eq!(frame.data.len(), 1_024);
            assert!(!frame.end_stream);
        }
        other => panic!("expected immediate DATA after connection WINDOW_UPDATE, got {other:?}"),
    }
}

#[test]
fn stream_window_update_resumes_blocked_data_immediately() {
    let mut conn = open_connection();
    let stream_id = open_post_stream(&mut conn, "/stream-data");

    conn.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(0, 65_535)))
        .expect("connection WINDOW_UPDATE should leave connection window available");
    conn.send_data(stream_id, Bytes::from(vec![0xCD; 70_000]), false)
        .expect("DATA should queue");

    assert_eq!(drain_data_until_blocked(&mut conn), 65_535);
    assert_eq!(
        conn.stream(stream_id)
            .expect("stream should remain available")
            .send_window(),
        0,
        "stream window should be exhausted"
    );

    conn.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(
        stream_id, 1_024,
    )))
    .expect("stream WINDOW_UPDATE should succeed");

    match conn.next_frame() {
        Some(Frame::Data(frame)) => {
            assert_eq!(frame.stream_id, stream_id);
            assert_eq!(frame.data.len(), 1_024);
            assert!(!frame.end_stream);
        }
        other => panic!("expected immediate DATA after stream WINDOW_UPDATE, got {other:?}"),
    }
}

#[cfg(feature = "test-internals")]
fn read_h2_frame(
    stream: &mut std::net::TcpStream,
    codec: &mut FrameCodec,
    read_buf: &mut BytesMut,
) -> std::io::Result<Frame> {
    use std::io::Read as _;

    let mut chunk = [0_u8; 4096];
    loop {
        if let Some(frame) = codec.decode(read_buf).map_err(std::io::Error::other)? {
            return Ok(frame);
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "HTTP/2 peer closed before the next frame",
            ));
        }
        read_buf.extend_from_slice(&chunk[..read]);
    }
}

#[cfg(feature = "test-internals")]
struct LiveH2Client {
    stream: std::net::TcpStream,
    codec: FrameCodec,
    read_buf: BytesMut,
    encoder: HpackEncoder,
}

#[cfg(feature = "test-internals")]
impl LiveH2Client {
    fn connect(addr: std::net::SocketAddr, initial_stream_window: u32) -> Self {
        use std::io::Write as _;
        use std::time::Duration;

        let mut stream = std::net::TcpStream::connect(addr).expect("connect H2 client");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("set read timeout");
        stream.write_all(CLIENT_PREFACE).expect("write preface");
        let mut settings = BytesMut::new();
        Frame::Settings(SettingsFrame::new(vec![
            asupersync::http::h2::Setting::InitialWindowSize(initial_stream_window),
        ]))
        .encode(&mut settings)
        .expect("encode client SETTINGS");
        stream.write_all(&settings).expect("write client SETTINGS");
        stream.flush().expect("flush client preface");

        Self {
            stream,
            codec: FrameCodec::new(),
            read_buf: BytesMut::new(),
            encoder: HpackEncoder::new(),
        }
    }

    fn send_get(&mut self, stream_id: u32, path: &str) {
        use std::io::Write as _;

        let mut header_block = BytesMut::new();
        self.encoder.encode(
            &[
                Header::new(":method", "GET"),
                Header::new(":scheme", "http"),
                Header::new(":path", path),
                Header::new(":authority", "localhost"),
            ],
            &mut header_block,
        );
        let mut encoded = BytesMut::new();
        Frame::Headers(HeadersFrame::new(
            stream_id,
            header_block.freeze(),
            true,
            true,
        ))
        .encode(&mut encoded)
        .expect("encode request HEADERS");
        self.stream
            .write_all(&encoded)
            .expect("write request HEADERS");
        self.stream.flush().expect("flush request HEADERS");
    }

    fn send_reset(&mut self, stream_id: u32) {
        use std::io::Write as _;

        let mut encoded = BytesMut::new();
        Frame::RstStream(RstStreamFrame::new(stream_id, ErrorCode::Cancel))
            .encode(&mut encoded)
            .expect("encode RST_STREAM");
        self.stream.write_all(&encoded).expect("write RST_STREAM");
        self.stream.flush().expect("flush RST_STREAM");
    }

    fn next_application_frame(&mut self) -> Frame {
        use std::io::Write as _;

        loop {
            let frame = read_h2_frame(&mut self.stream, &mut self.codec, &mut self.read_buf)
                .expect("read H2 frame");
            match frame {
                Frame::Settings(settings) if !settings.ack => {
                    let mut ack = BytesMut::new();
                    Frame::Settings(SettingsFrame::ack())
                        .encode(&mut ack)
                        .expect("encode SETTINGS ack");
                    self.stream.write_all(&ack).expect("write SETTINGS ack");
                    self.stream.flush().expect("flush SETTINGS ack");
                }
                Frame::Settings(_) | Frame::WindowUpdate(_) => {}
                Frame::GoAway(goaway) => {
                    panic!("connection became unusable before response completed: {goaway:?}");
                }
                other => return other,
            }
        }
    }

    fn read_data_start(&mut self, stream_id: u32, expected: &[u8]) {
        let mut saw_headers = false;
        loop {
            match self.next_application_frame() {
                Frame::Headers(headers) if headers.stream_id == stream_id => {
                    assert!(!headers.end_stream, "response body must follow HEADERS");
                    saw_headers = true;
                }
                Frame::Data(data) if data.stream_id == stream_id => {
                    assert!(saw_headers, "response HEADERS must precede DATA");
                    assert_eq!(data.data.as_ref(), expected);
                    assert!(!data.end_stream, "committed DATA is not terminal");
                    return;
                }
                Frame::RstStream(reset) if reset.stream_id == stream_id => {
                    panic!("stream {stream_id} reset before committed DATA: {reset:?}");
                }
                _ => {}
            }
        }
    }

    fn read_buffered_response(&mut self, stream_id: u32, expected: &[u8]) {
        let mut saw_headers = false;
        let mut body = Vec::new();
        loop {
            match self.next_application_frame() {
                Frame::Headers(headers) if headers.stream_id == stream_id => {
                    saw_headers = true;
                    if headers.end_stream {
                        assert_eq!(body, expected);
                        return;
                    }
                }
                Frame::Data(data) if data.stream_id == stream_id => {
                    assert!(saw_headers, "response HEADERS must precede DATA");
                    body.extend_from_slice(&data.data);
                    if data.end_stream {
                        assert_eq!(body, expected);
                        return;
                    }
                }
                Frame::RstStream(reset) if reset.stream_id == stream_id => {
                    panic!("independent stream {stream_id} was reset: {reset:?}");
                }
                _ => {}
            }
        }
    }
}

#[cfg(feature = "test-internals")]
fn wait_for_atomic_bool(flag: &std::sync::atomic::AtomicBool, context: &str) {
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(5);
    while !flag.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline, "timed out waiting for {context}");
        std::thread::yield_now();
    }
}

#[cfg(feature = "test-internals")]
fn wait_for_atomic_usize(value: &std::sync::atomic::AtomicUsize, expected: usize, context: &str) {
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(5);
    while value.load(Ordering::Acquire) != expected {
        assert!(Instant::now() < deadline, "timed out waiting for {context}");
        std::thread::yield_now();
    }
}

#[cfg(feature = "test-internals")]
struct ProducerExitProbe {
    cx: Cx,
    exited: std::sync::Arc<std::sync::atomic::AtomicBool>,
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(feature = "test-internals")]
impl Drop for ProducerExitProbe {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;

        self.cancelled
            .store(self.cx.is_cancel_requested(), Ordering::Release);
        self.exited.store(true, Ordering::Release);
    }
}

#[cfg(feature = "test-internals")]
fn run_live_h2_case<C>(app: Router, client_case: C)
where
    C: FnOnce(std::net::SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>)
        + Send
        + 'static,
{
    use std::time::Duration;

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let listener = Http2Listener::bind_produced_with_config(
            "127.0.0.1:0",
            app.into_http2_produced_handler(),
            Http2ListenerConfig::default()
                .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
                .drain_timeout(Duration::from_secs(5))
                .hard_drain_timeout(Duration::from_secs(10)),
        )
        .await
        .expect("bind produced H2 listener");
        let addr = listener.local_addr().expect("listener local address");
        let manager = listener.connection_manager().clone();
        let in_flight = listener.in_flight_requests();
        let client_in_flight = std::sync::Arc::clone(&in_flight);
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run_produced(&handle).await })
            .expect("spawn produced H2 listener");

        std::thread::spawn(move || client_case(addr, client_in_flight))
            .join()
            .expect("H2 client thread");
        wait_for_atomic_usize(&in_flight, 0, "listener in-flight request quiescence");

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let stats = run_handle.await.expect("listener run result");
        assert!(stats.drain_report.expect("drain report").reached_quiescence);
        assert_eq!(manager.active_count(), 0);
    });
}

/// A peer RST_STREAM must cancel and reap exactly the targeted produced body.
/// The same connection remains usable for an independent later stream.
#[cfg(feature = "test-internals")]
#[test]
fn peer_reset_cancels_one_produced_body_and_preserves_connection() {
    use std::num::NonZeroUsize;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let admitted = Arc::new(AtomicUsize::new(0));
    let exited = Arc::new(AtomicBool::new(false));
    let cancelled = Arc::new(AtomicBool::new(false));
    let admitted_for_route = Arc::clone(&admitted);
    let exited_for_route = Arc::clone(&exited);
    let cancelled_for_route = Arc::clone(&cancelled);
    let app = Router::new()
        .without_default_trace()
        .route(
            "/reset",
            get(AsyncCxFnHandler1::<_, Http2StreamResponder>::new(
                move |_handler_cx: Cx, responder: Http2StreamResponder| {
                    let admitted = Arc::clone(&admitted_for_route);
                    let exited = Arc::clone(&exited_for_route);
                    let cancelled = Arc::clone(&cancelled_for_route);
                    async move {
                        responder.streaming(
                            StatusCode::OK,
                            NonZeroUsize::MIN,
                            NonZeroUsize::new(3).expect("non-zero frame limit"),
                            |producer_cx, mut sender| async move {
                                let _exit = ProducerExitProbe {
                                    cx: producer_cx.clone(),
                                    exited,
                                    cancelled,
                                };
                                for chunk in [b"abc".as_slice(), b"def", b"ghi"] {
                                    sender.send_chunk(&producer_cx, chunk).await?;
                                    admitted.fetch_add(1, Ordering::Release);
                                }
                                sender.finish(&producer_cx)?;
                                Ok(sender)
                            },
                        )
                    }
                },
            )),
        )
        .route("/ok", get(FnHandler::new(|| "ok")));

    let admitted_for_client = Arc::clone(&admitted);
    let exited_for_client = Arc::clone(&exited);
    let cancelled_for_client = Arc::clone(&cancelled);
    run_live_h2_case(app, move |addr, in_flight| {
        let mut client = LiveH2Client::connect(addr, 3);
        client.send_get(1, "/reset");
        client.read_data_start(1, b"abc");
        wait_for_atomic_usize(
            &admitted_for_client,
            2,
            "one sent and one queued produced DATA frame",
        );

        client.send_reset(1);
        wait_for_atomic_bool(&exited_for_client, "reset producer exit");
        assert!(
            cancelled_for_client.load(Ordering::Acquire),
            "producer Cx must observe peer-reset cancellation before exit"
        );
        wait_for_atomic_usize(&in_flight, 0, "reset stream reaping");

        client.send_get(3, "/ok");
        client.read_buffered_response(3, b"ok");
    });
}

/// Transport EOF must cancel every active produced body and retain its request
/// accounting until the producer owner has actually exited.
#[cfg(feature = "test-internals")]
#[test]
fn peer_disconnect_cancels_produced_body_before_listener_quiescence() {
    use std::num::NonZeroUsize;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let admitted = Arc::new(AtomicUsize::new(0));
    let exited = Arc::new(AtomicBool::new(false));
    let cancelled = Arc::new(AtomicBool::new(false));
    let admitted_for_route = Arc::clone(&admitted);
    let exited_for_route = Arc::clone(&exited);
    let cancelled_for_route = Arc::clone(&cancelled);
    let app = Router::new().without_default_trace().route(
        "/disconnect",
        get(AsyncCxFnHandler1::<_, Http2StreamResponder>::new(
            move |_handler_cx: Cx, responder: Http2StreamResponder| {
                let admitted = Arc::clone(&admitted_for_route);
                let exited = Arc::clone(&exited_for_route);
                let cancelled = Arc::clone(&cancelled_for_route);
                async move {
                    responder.streaming(
                        StatusCode::OK,
                        NonZeroUsize::MIN,
                        NonZeroUsize::new(3).expect("non-zero frame limit"),
                        |producer_cx, mut sender| async move {
                            let _exit = ProducerExitProbe {
                                cx: producer_cx.clone(),
                                exited,
                                cancelled,
                            };
                            for chunk in [b"abc".as_slice(), b"def", b"ghi"] {
                                sender.send_chunk(&producer_cx, chunk).await?;
                                admitted.fetch_add(1, Ordering::Release);
                            }
                            sender.finish(&producer_cx)?;
                            Ok(sender)
                        },
                    )
                }
            },
        )),
    );

    let admitted_for_client = Arc::clone(&admitted);
    let exited_for_client = Arc::clone(&exited);
    let cancelled_for_client = Arc::clone(&cancelled);
    run_live_h2_case(app, move |addr, in_flight| {
        let mut client = LiveH2Client::connect(addr, 3);
        client.send_get(1, "/disconnect");
        client.read_data_start(1, b"abc");
        wait_for_atomic_usize(
            &admitted_for_client,
            2,
            "one sent and one queued produced DATA frame",
        );

        client
            .stream
            .shutdown(std::net::Shutdown::Both)
            .expect("close H2 transport");
        drop(client);
        wait_for_atomic_bool(&exited_for_client, "disconnected producer exit");
        assert!(
            cancelled_for_client.load(Ordering::Acquire),
            "producer Cx must observe transport-loss cancellation before exit"
        );
        wait_for_atomic_usize(&in_flight, 0, "disconnect request reaping");
    });
}

/// A producer failure after committing DATA drains the admitted frame, resets
/// only that stream without a false END_STREAM, and leaves the connection live.
#[cfg(feature = "test-internals")]
#[test]
fn producer_error_drains_committed_data_then_resets_only_failed_stream() {
    use std::num::NonZeroUsize;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let failed = Arc::new(AtomicBool::new(false));
    let failed_for_route = Arc::clone(&failed);
    let app = Router::new()
        .without_default_trace()
        .route(
            "/fail",
            get(AsyncCxFnHandler1::<_, Http2StreamResponder>::new(
                move |_handler_cx: Cx, responder: Http2StreamResponder| {
                    let failed = Arc::clone(&failed_for_route);
                    async move {
                        responder.streaming(
                            StatusCode::OK,
                            NonZeroUsize::MIN,
                            NonZeroUsize::new(3).expect("non-zero frame limit"),
                            |producer_cx, mut sender| async move {
                                sender.send_chunk(&producer_cx, b"abc").await?;
                                failed.store(true, Ordering::Release);
                                Err(HttpError::BadHeader)
                            },
                        )
                    }
                },
            )),
        )
        .route("/ok", get(FnHandler::new(|| "ok")));

    let failed_for_client = Arc::clone(&failed);
    run_live_h2_case(app, move |addr, in_flight| {
        let mut client = LiveH2Client::connect(addr, 65_535);
        client.send_get(1, "/fail");
        client.read_data_start(1, b"abc");
        wait_for_atomic_bool(&failed_for_client, "producer failure return");

        match client.next_application_frame() {
            Frame::RstStream(reset) => {
                assert_eq!(reset.stream_id, 1);
                assert_eq!(reset.error_code, ErrorCode::InternalError);
            }
            other => panic!("expected failed stream RST_STREAM, got {other:?}"),
        }
        wait_for_atomic_usize(&in_flight, 0, "failed stream reaping");

        client.send_get(3, "/ok");
        client.read_buffered_response(3, b"ok");
    });
}

/// A real TCP/H2 listener must not pull a second Router-authored DATA frame
/// while the peer's tiny stream window is exhausted. WINDOW_UPDATE resumes
/// each chunk without duplication, and clean EOF is emitted exactly once even
/// when the final DATA byte consumed all credit.
#[cfg(feature = "test-internals")]
#[test]
fn router_produced_body_waits_for_live_h2_window_updates() {
    use std::io::Write as _;
    use std::num::NonZeroUsize;
    use std::time::Duration;

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let completed_sends = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let completed_sends_for_route = std::sync::Arc::clone(&completed_sends);
        let app = Router::new()
            .without_default_trace()
            .route(
                "/produced",
                get(AsyncCxFnHandler1::<_, Http2StreamResponder>::new(
                    move |_handler_cx: Cx, responder: Http2StreamResponder| {
                        let completed_sends = std::sync::Arc::clone(&completed_sends_for_route);
                        async move {
                            responder
                                .streaming(
                                    StatusCode::OK,
                                    NonZeroUsize::MIN,
                                    NonZeroUsize::new(3).expect("non-zero frame limit"),
                                    |producer_cx, mut sender| async move {
                                        for chunk in [b"abc".as_slice(), b"def", b"ghi"] {
                                            sender.send_chunk(&producer_cx, chunk).await?;
                                            completed_sends.fetch_add(
                                                1,
                                                std::sync::atomic::Ordering::SeqCst,
                                            );
                                        }
                                        sender.finish(&producer_cx)?;
                                        Ok(sender)
                                    },
                                )
                                .header("x-produced", "h2")
                        }
                    },
                )),
            )
            .into_http2_produced_handler();
        let listener = Http2Listener::bind_produced_with_config(
            "127.0.0.1:0",
            app,
            Http2ListenerConfig::default()
                .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
                .drain_timeout(Duration::from_secs(5))
                .hard_drain_timeout(Duration::from_secs(10)),
        )
        .await
        .expect("bind produced H2 listener");
        let addr = listener.local_addr().expect("listener local address");
        let manager = listener.connection_manager().clone();
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run_produced(&handle).await })
            .expect("spawn produced H2 listener");

        let completed_sends_for_client = std::sync::Arc::clone(&completed_sends);
        let client = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(addr).expect("connect H2 client");
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("set read timeout");
            let mut outbound = BytesMut::new();
            stream.write_all(CLIENT_PREFACE).expect("write preface");
            Frame::Settings(SettingsFrame::new(vec![
                asupersync::http::h2::Setting::InitialWindowSize(3),
            ]))
            .encode(&mut outbound)
            .expect("encode SETTINGS");
            let mut encoder = HpackEncoder::new();
            let mut header_block = BytesMut::new();
            encoder.encode(
                &[
                    Header::new(":method", "GET"),
                    Header::new(":scheme", "http"),
                    Header::new(":path", "/produced"),
                    Header::new(":authority", "localhost"),
                ],
                &mut header_block,
            );
            Frame::Headers(HeadersFrame::new(1, header_block.freeze(), true, true))
                .encode(&mut outbound)
                .expect("encode request HEADERS");
            stream.write_all(&outbound).expect("write H2 request");
            stream.flush().expect("flush H2 request");

            let mut codec = FrameCodec::new();
            let mut read_buf = BytesMut::new();
            let mut saw_status = false;
            let first_data = loop {
                match read_h2_frame(&mut stream, &mut codec, &mut read_buf)
                    .expect("read response setup frame")
                {
                    Frame::Settings(settings) if !settings.ack => {
                        let mut ack = BytesMut::new();
                        Frame::Settings(SettingsFrame::ack())
                            .encode(&mut ack)
                            .expect("encode SETTINGS ack");
                        stream.write_all(&ack).expect("write SETTINGS ack");
                    }
                    Frame::Headers(headers) if headers.stream_id == 1 => {
                        saw_status = true;
                        assert!(!headers.end_stream);
                    }
                    Frame::Data(data) if data.stream_id == 1 => break data,
                    _ => {}
                }
            };
            assert!(saw_status, "response HEADERS precede produced DATA");
            assert_eq!(first_data.data.as_ref(), b"abc");
            assert!(!first_data.end_stream);

            stream
                .set_read_timeout(Some(Duration::from_millis(250)))
                .expect("set exhausted-window timeout");
            let blocked = read_h2_frame(&mut stream, &mut codec, &mut read_buf)
                .expect_err("no second DATA may arrive without stream credit");
            assert!(
                matches!(
                    blocked.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ),
                "unexpected blocked-read result: {blocked}"
            );
            assert_eq!(
                completed_sends_for_client.load(std::sync::atomic::Ordering::SeqCst),
                2,
                "capacity one permits one queued frame, but zero credit must prevent the listener from pulling it and admitting a third"
            );
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("restore read timeout");

            for expected in [b"def".as_slice(), b"ghi"] {
                let mut update = BytesMut::new();
                Frame::WindowUpdate(WindowUpdateFrame::new(1, 3))
                    .encode(&mut update)
                    .expect("encode stream WINDOW_UPDATE");
                stream
                    .write_all(&update)
                    .expect("write stream WINDOW_UPDATE");
                stream.flush().expect("flush stream WINDOW_UPDATE");
                let data = loop {
                    match read_h2_frame(&mut stream, &mut codec, &mut read_buf)
                        .expect("read resumed DATA")
                    {
                        Frame::Data(data) if data.stream_id == 1 => break data,
                        _ => {}
                    }
                };
                assert_eq!(data.data.as_ref(), expected);
                assert!(!data.end_stream);
            }

            match read_h2_frame(&mut stream, &mut codec, &mut read_buf)
                .expect("read zero-credit terminal frame")
            {
                Frame::Data(data) => {
                    assert_eq!(data.stream_id, 1);
                    assert!(data.data.is_empty());
                    assert!(data.end_stream);
                }
                other => panic!("expected one empty terminal DATA frame, got {other:?}"),
            }
            stream
                .set_read_timeout(Some(Duration::from_millis(250)))
                .expect("set post-terminal timeout");
            let duplicate = read_h2_frame(&mut stream, &mut codec, &mut read_buf)
                .expect_err("no duplicate terminal frame may follow END_STREAM");
            assert!(
                matches!(
                    duplicate.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ),
                "unexpected post-terminal read result: {duplicate}"
            );
        });
        client.join().expect("H2 client thread");

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let stats = run_handle.await.expect("listener run result");
        assert!(stats.drain_report.expect("drain report").reached_quiescence);
    });
}
