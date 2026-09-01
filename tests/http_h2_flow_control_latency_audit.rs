//! Regression tests for HTTP/2 flow-control resume latency.

#[cfg(feature = "test-internals")]
use asupersync::Cx;
use asupersync::bytes::Bytes;
#[cfg(feature = "test-internals")]
use asupersync::bytes::BytesMut;
#[cfg(feature = "test-internals")]
use asupersync::codec::Decoder as _;
#[cfg(feature = "test-internals")]
use asupersync::http::h1::server::HostPolicy;
#[cfg(feature = "test-internals")]
use asupersync::http::h2::connection::CLIENT_PREFACE;
use asupersync::http::h2::connection::Connection;
#[cfg(feature = "test-internals")]
use asupersync::http::h2::frame::HeadersFrame;
use asupersync::http::h2::frame::{Frame, SettingsFrame, WindowUpdateFrame};
use asupersync::http::h2::hpack::Header;
#[cfg(feature = "test-internals")]
use asupersync::http::h2::listener::{Http2Listener, Http2ListenerConfig};
use asupersync::http::h2::settings::Settings;
#[cfg(feature = "test-internals")]
use asupersync::http::h2::{FrameCodec, HpackEncoder};
#[cfg(feature = "test-internals")]
use asupersync::runtime::RuntimeBuilder;
#[cfg(feature = "test-internals")]
use asupersync::web::{AsyncCxFnHandler1, Http2StreamResponder, Router, StatusCode, get};

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
