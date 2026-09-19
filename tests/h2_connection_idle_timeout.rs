//! Per-connection idle timeout for the HTTP/2 listener (br-asupersync-mfqfst
//! L4; h1 parity with `Http1Config::idle_timeout`).
//!
//! These e2e tests drive a real `Http2Listener` on a multi-thread runtime
//! with a raw frame-speaking std-TCP client, exercising the idle backstop in
//! the production serve loop (`src/http/h2/listener.rs`):
//!
//!   - `h2_reclaims_idle_connection_after_timeout`: once the served request's
//!     stream closes and the connection is fully quiescent, the server closes
//!     it with a NO_ERROR GOAWAY after the (short) idle budget — proving the
//!     timeout fires independently of any further client frame.
//!   - `h2_active_connection_not_reclaimed_during_handler`: a handler that
//!     runs longer than the idle budget keeps its stream active, so the idle
//!     timer never arms and the request still completes with a 200 (the idle
//!     timeout is not a request timeout — it must not truncate in-flight work).
//!
//! Integration tests (`--test`): they compile against the public API only and
//! are unaffected by any in-lib `#[cfg(test)]` breakage.

#![cfg(feature = "test-internals")]
// The TLS-enabled listener nests runtime and request-region futures deeply
// enough to exceed the default auto-trait solver recursion budget.
#![recursion_limit = "256"]

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder as _;
use asupersync::http::h1::server::HostPolicy;
use asupersync::http::h1::types::Response;
use asupersync::http::h2::ErrorCode;
use asupersync::http::h2::connection::CLIENT_PREFACE;
use asupersync::http::h2::frame::{DataFrame, Frame, HeadersFrame, PingFrame, SettingsFrame};
use asupersync::http::h2::listener::{Http2Listener, Http2ListenerConfig};
use asupersync::http::h2::{FrameCodec, Header, HpackDecoder, HpackEncoder};
use asupersync::runtime::RuntimeBuilder;

/// Base config: allow the `localhost` authority the raw client sends, disable
/// the request-budget recycle so idle reclamation is isolated, and set a short
/// idle budget so the test is fast.
fn idle_config(idle: Duration) -> Http2ListenerConfig {
    Http2ListenerConfig::default()
        .drain_timeout(Duration::from_secs(10))
        .hard_drain_timeout(Duration::from_secs(20))
        .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
        .max_requests_per_connection(None)
        .idle_timeout(Some(idle))
}

#[derive(Clone, Copy, Debug)]
enum DecodeProbe {
    Priority,
    PendingPriority,
    BeforeSettings,
    DuringContinuation,
    StreamZero,
    OversizedPriority,
    MalformedHeaders,
    InvalidHpack,
}

/// Exercise the listener's actual Framed reader, not just frame parsing.
fn decode_probe_client(addr: SocketAddr, probe: DecodeProbe) -> Vec<Frame> {
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(CLIENT_PREFACE).unwrap();
    let mut request = BytesMut::new();
    // A complete PRIORITY frame with four payload bytes instead of five.
    let mut malformed_priority = [0, 0, 4, 2, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    if matches!(probe, DecodeProbe::BeforeSettings) {
        request.extend_from_slice(&malformed_priority);
    }
    Frame::Settings(SettingsFrame::new(Vec::new()))
        .encode(&mut request)
        .unwrap();
    let mut block = BytesMut::new();
    HpackEncoder::new().encode(
        &[
            Header::new(":method", "GET"),
            Header::new(":scheme", "http"),
            Header::new(":path", "/survivor"),
            Header::new(":authority", "localhost"),
        ],
        &mut block,
    );
    let block = block.freeze();
    match probe {
        DecodeProbe::BeforeSettings => {}
        DecodeProbe::Priority => request.extend_from_slice(&malformed_priority),
        DecodeProbe::PendingPriority => {
            Frame::Headers(HeadersFrame::new(1, block.clone(), false, true))
                .encode(&mut request)
                .unwrap();
            request.extend_from_slice(&malformed_priority);
        }
        DecodeProbe::DuringContinuation => {
            Frame::Headers(HeadersFrame::new(1, block.clone(), false, false))
                .encode(&mut request)
                .unwrap();
            request.extend_from_slice(&malformed_priority);
        }
        DecodeProbe::StreamZero => {
            malformed_priority[8] = 0;
            request.extend_from_slice(&malformed_priority);
        }
        DecodeProbe::OversizedPriority => {
            request.extend_from_slice(&[0, 0x40, 1, 2, 0, 0, 0, 0, 1]);
            request.extend_from_slice(&vec![0; 16_385]);
        }
        DecodeProbe::MalformedHeaders => {
            // HEADERS with a self-dependent priority: its parser emits a
            // stream-tagged error, but it must not enter PRIORITY recovery.
            request.extend_from_slice(&[0, 0, 5, 1, 0x24, 0, 0, 0, 1, 0, 0, 0, 1, 0]);
        }
        DecodeProbe::InvalidHpack => {
            Frame::Headers(HeadersFrame::new(1, vec![0x80].into(), true, true))
                .encode(&mut request)
                .unwrap();
        }
    }
    Frame::Headers(HeadersFrame::new(3, block, true, true))
        .encode(&mut request)
        .unwrap();
    stream.write_all(&request).unwrap();
    let mut codec = FrameCodec::new();
    let mut input = BytesMut::new();
    let mut frames = Vec::new();
    loop {
        while let Some(frame) = codec.decode(&mut input).unwrap() {
            if matches!(&frame, Frame::Settings(settings) if !settings.ack) {
                let mut ack = BytesMut::new();
                Frame::Settings(SettingsFrame::ack())
                    .encode(&mut ack)
                    .unwrap();
                let _ = stream.write_all(&ack);
            }
            let finished = matches!(&frame, Frame::GoAway(_))
                || matches!(&frame, Frame::Data(data) if data.stream_id == 3 && data.end_stream)
                || matches!(&frame, Frame::Headers(headers) if headers.stream_id == 3 && headers.end_stream);
            frames.push(frame);
            if finished {
                return frames;
            }
        }
        let mut chunk = [0; 4096];
        let n = stream
            .read(&mut chunk)
            .expect("response or GOAWAY before deadline");
        if n == 0 {
            return frames;
        }
        input.extend_from_slice(&chunk[..n]);
    }
}

#[test]
fn h2_priority_decode_recovery_preserves_connection_error_boundaries() {
    for probe in [
        DecodeProbe::Priority,
        DecodeProbe::PendingPriority,
        DecodeProbe::BeforeSettings,
        DecodeProbe::DuringContinuation,
        DecodeProbe::StreamZero,
        DecodeProbe::OversizedPriority,
        DecodeProbe::MalformedHeaders,
        DecodeProbe::InvalidHpack,
    ] {
        let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
        let handle = runtime.handle();
        runtime.block_on(async move {
            let listener = Http2Listener::bind_with_config(
                "127.0.0.1:0",
                |_| async { Response::new(200, "OK", b"survived".to_vec()) },
                idle_config(Duration::from_secs(5)),
            ).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let manager = listener.connection_manager().clone();
            let run = handle.clone().try_spawn(async move { listener.run(&handle).await }).unwrap();
            let result = std::thread::spawn(move || decode_probe_client(addr, probe)).join();
            assert!(manager.begin_drain(Duration::from_secs(5)));
            let _ = run.await.unwrap();
            let frames = result.expect("probe client");
            if matches!(probe, DecodeProbe::Priority | DecodeProbe::PendingPriority) {
                assert!(frames.iter().any(|f| matches!(f, Frame::RstStream(r) if r.stream_id == 1 && r.error_code == ErrorCode::FrameSizeError)), "{probe:?}: {frames:?}");
                assert!(!frames.iter().any(|f| matches!(f, Frame::GoAway(_))), "{probe:?}: {frames:?}");
                assert!(frames.iter().any(|f| matches!(f, Frame::Data(d) if d.stream_id == 3 && &d.data[..] == b"survived")), "sibling request must complete: {frames:?}");
            } else {
                let expected = match probe {
                    DecodeProbe::OversizedPriority => ErrorCode::FrameSizeError,
                    DecodeProbe::InvalidHpack => ErrorCode::CompressionError,
                    _ => ErrorCode::ProtocolError,
                };
                assert!(frames.iter().any(|f| matches!(f, Frame::GoAway(g) if g.error_code == expected)), "{probe:?}: {frames:?}");
                assert!(!frames.iter().any(|f| matches!(f, Frame::Data(_))), "fatal frame must stop sibling request: {probe:?}: {frames:?}");
            }
        });
    }
}

/// What one raw h2 client observed before the connection closed.
#[derive(Debug, Default)]
struct H2ClientOutcome {
    status: Option<String>,
    body: Vec<u8>,
    goaway_last_stream_ids: Vec<u32>,
}

/// Raw frame-speaking blocking client on a std thread: sends the preface, an
/// empty SETTINGS frame, and one GET on stream 1, then reads frames (acking
/// server SETTINGS) until EOF or read timeout. With `read_to_eof` true it
/// keeps reading past the response so the server-initiated close (GOAWAY +
/// EOF) is observed.
fn h2_blocking_client(
    addr: SocketAddr,
    path: &'static str,
    read_to_eof: bool,
) -> std::thread::JoinHandle<H2ClientOutcome> {
    h2_blocking_client_with_body_pause(addr, path, read_to_eof, None)
}

fn h2_blocking_client_with_body_pause(
    addr: SocketAddr,
    path: &'static str,
    read_to_eof: bool,
    mut body_pause: Option<Duration>,
) -> std::thread::JoinHandle<H2ClientOutcome> {
    std::thread::spawn(move || {
        let mut outcome = H2ClientOutcome::default();
        let mut stream = std::net::TcpStream::connect(addr).expect("client connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("set read timeout");

        let mut out = BytesMut::new();
        stream.write_all(CLIENT_PREFACE).expect("write preface");
        Frame::Settings(SettingsFrame::new(Vec::new()))
            .encode(&mut out)
            .expect("encode client SETTINGS");

        let mut encoder = HpackEncoder::new();
        let mut block = BytesMut::new();
        encoder.encode(
            &[
                Header::new(":method", "GET"),
                Header::new(":scheme", "http"),
                Header::new(":path", path),
                Header::new(":authority", "localhost"),
            ],
            &mut block,
        );
        Frame::Headers(HeadersFrame::new(
            1,
            block.freeze(),
            body_pause.is_none(),
            true,
        ))
        .encode(&mut out)
        .expect("encode request HEADERS");
        if body_pause.is_some() {
            Frame::Ping(PingFrame::new(*b"bodywait"))
                .encode(&mut out)
                .expect("encode body pause barrier");
        }
        stream.write_all(&out).expect("write request");
        stream.flush().expect("flush request");

        let mut codec = FrameCodec::new();
        let mut read_buf = BytesMut::new();
        let mut decoder = HpackDecoder::new();
        let mut chunk = [0u8; 4096];
        loop {
            loop {
                match codec.decode(&mut read_buf) {
                    Ok(Some(Frame::Ping(ping))) if ping.ack && ping.opaque_data == *b"bodywait" => {
                        if let Some(pause) = body_pause.take() {
                            // The server acknowledged a frame after HEADERS,
                            // so the request is pending before the pause starts.
                            std::thread::sleep(pause);
                            let mut data = BytesMut::new();
                            Frame::Data(DataFrame::new(1, b"body".as_slice().into(), true))
                                .encode(&mut data)
                                .expect("encode delayed request body");
                            if stream.write_all(&data).is_err() {
                                return outcome;
                            }
                        }
                    }
                    Ok(Some(Frame::Settings(settings))) if !settings.ack => {
                        let mut ack = BytesMut::new();
                        Frame::Settings(SettingsFrame::ack())
                            .encode(&mut ack)
                            .expect("encode SETTINGS ack");
                        // The server may already be closing; a failed ack
                        // write is not an outcome-changing event.
                        let _ = stream.write_all(&ack);
                    }
                    Ok(Some(Frame::Headers(headers))) => {
                        let mut block =
                            asupersync::bytes::Bytes::from(headers.header_block.to_vec());
                        if let Ok(decoded) = decoder.decode(&mut block) {
                            for header in decoded {
                                if header.name == ":status" {
                                    outcome.status = Some(header.value);
                                }
                            }
                        }
                        if headers.end_stream && !read_to_eof {
                            return outcome;
                        }
                    }
                    Ok(Some(Frame::Data(data))) => {
                        outcome.body.extend_from_slice(&data.data);
                        if data.end_stream && !read_to_eof {
                            return outcome;
                        }
                    }
                    Ok(Some(Frame::GoAway(goaway))) => {
                        outcome.goaway_last_stream_ids.push(goaway.last_stream_id);
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => return outcome,
                }
            }
            match stream.read(&mut chunk) {
                Ok(0) => return outcome,
                Ok(n) => read_buf.extend_from_slice(&chunk[..n]),
                Err(_) => return outcome,
            }
        }
    })
}

/// br-asupersync-mfqfst L4: a connection that has served its request and gone
/// quiescent is reclaimed after the idle budget — the server sends a GOAWAY
/// and closes without any further client frame driving it.
#[test]
fn h2_reclaims_idle_connection_after_timeout() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let listener = Http2Listener::bind_with_config(
            "127.0.0.1:0",
            move |req| async move {
                let body = format!("served {}", req.uri).into_bytes();
                Response::new(200, "OK", body)
            },
            idle_config(Duration::from_millis(300)),
        )
        .await
        .expect("bind listener");

        let addr = listener.local_addr().expect("local addr");
        let manager = listener.connection_manager().clone();

        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&handle).await })
            .expect("spawn listener run");

        // read_to_eof: the request completes, then the idle backstop closes
        // the connection — observe the GOAWAY and EOF that follow.
        let client = h2_blocking_client(addr, "/idle", true);
        let outcome = client.join().expect("client thread");

        assert_eq!(outcome.status.as_deref(), Some("200"), "{outcome:?}");
        assert_eq!(outcome.body, b"served /idle", "{outcome:?}");
        assert!(
            !outcome.goaway_last_stream_ids.is_empty(),
            "an idle connection must be reclaimed with a GOAWAY after the idle \
             budget: {outcome:?}"
        );

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let _ = run_handle.await.expect("listener run result");
    });
}

/// br-asupersync-mfqfst L4: while a handler is running its stream stays
/// active, so the idle timer never arms — a handler that runs longer than the
/// idle budget still completes with a 200. The idle timeout is a quiescence
/// backstop, not a request timeout, and must not truncate in-flight work.
#[test]
fn h2_active_connection_not_reclaimed_during_handler() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let listener = Http2Listener::bind_with_config(
            "127.0.0.1:0",
            move |req| async move {
                // Hold the stream open well past the idle budget (300ms): if
                // the idle timer wrongly counted an active stream as idle, the
                // connection would close and the client would never see a 200.
                asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(600))
                    .await;
                let body = format!("served {}", req.uri).into_bytes();
                Response::new(200, "OK", body)
            },
            idle_config(Duration::from_millis(300)),
        )
        .await
        .expect("bind listener");

        let addr = listener.local_addr().expect("local addr");
        let manager = listener.connection_manager().clone();

        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&handle).await })
            .expect("spawn listener run");

        let client = h2_blocking_client(addr, "/slow-handler", true);
        let outcome = client.join().expect("client thread");

        assert_eq!(
            outcome.status.as_deref(),
            Some("200"),
            "a long-running handler must still complete — the idle timer must \
             not reclaim a connection with an active stream: {outcome:?}"
        );
        assert_eq!(outcome.body, b"served /slow-handler", "{outcome:?}");

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let _ = run_handle.await.expect("listener run result");
    });
}

#[test]
fn h2_disabled_stream_timeout_preserves_paused_request_body() {
    let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
    let handle = runtime.handle();
    runtime.block_on(async move {
        let listener = Http2Listener::bind_with_config(
            "127.0.0.1:0",
            |req| async move { Response::new(200, "OK", req.body) },
            idle_config(Duration::from_millis(300)).stream_idle_timeout(None),
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();
        let manager = listener.connection_manager().clone();
        let run = handle
            .clone()
            .try_spawn(async move { listener.run(&handle).await })
            .unwrap();
        let client = h2_blocking_client_with_body_pause(
            addr,
            "/paused-body",
            true,
            Some(Duration::from_millis(900)),
        );
        let outcome = client.join().unwrap();
        assert!(manager.begin_drain(Duration::from_secs(5)));
        let _ = run.await.unwrap();
        assert_eq!(outcome.status.as_deref(), Some("200"), "{outcome:?}");
        assert_eq!(outcome.body, b"body", "{outcome:?}");
        assert!(
            !outcome.goaway_last_stream_ids.is_empty(),
            "connection idle timeout must still reclaim the completed stream: {outcome:?}"
        );
    });
}
