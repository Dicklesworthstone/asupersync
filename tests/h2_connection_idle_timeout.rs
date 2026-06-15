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

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder as _;
use asupersync::http::h1::server::HostPolicy;
use asupersync::http::h1::types::Response;
use asupersync::http::h2::connection::CLIENT_PREFACE;
use asupersync::http::h2::frame::{Frame, HeadersFrame, SettingsFrame};
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
        Frame::Headers(HeadersFrame::new(1, block.freeze(), true, true))
            .encode(&mut out)
            .expect("encode request HEADERS");
        stream.write_all(&out).expect("write request");
        stream.flush().expect("flush request");

        let mut codec = FrameCodec::new();
        let mut read_buf = BytesMut::new();
        let mut decoder = HpackDecoder::new();
        let mut chunk = [0u8; 4096];
        loop {
            loop {
                match codec.decode(&mut read_buf) {
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
