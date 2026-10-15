//! Per-connection request-budget recycling for the HTTP/2 listener
//! (br-asupersync-mfqfst L4; h1 parity with
//! `Http1Config::max_requests_per_connection`).
//!
//! These e2e tests drive a real `Http2Listener` on a multi-thread runtime
//! with a raw frame-speaking std-TCP client (preface + SETTINGS + HEADERS),
//! exercising the production serve loop in `src/http/h2/listener.rs`:
//!
//!   - `h2_recycles_connection_at_request_limit`: with
//!     `max_requests_per_connection(Some(1))`, the single request is still
//!     served with a 200 + body, and the server then recycles the connection
//!     by initiating a graceful GOAWAY and closing the transport (the client
//!     observes a server-initiated GOAWAY and EOF after its response).
//!   - `h2_unlimited_budget_keeps_connection_after_single_request`: with a
//!     budget of `Some(2)`, a single request does NOT trip the recycle, so the
//!     client gets its 200 with no server-initiated GOAWAY — the connection is
//!     kept alive for further requests.
//!
//! These are integration tests (`--test`), so they compile against the public
//! API only and are unaffected by any in-lib `#[cfg(test)]` breakage.

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

/// Base config: allow the `localhost` authority the raw client sends, and
/// keep the drain budgets generous so recycling (driven by the request
/// budget, not a drain signal) is the thing under test.
fn recycle_config(max_requests: Option<u64>) -> Http2ListenerConfig {
    Http2ListenerConfig::default()
        .drain_timeout(Duration::from_secs(10))
        .hard_drain_timeout(Duration::from_secs(20))
        .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
        .max_requests_per_connection(max_requests)
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
/// server SETTINGS) until EOF or read timeout. With `read_to_eof` false it
/// returns as soon as the response stream ends (so a kept-alive connection is
/// not waited on); the recycle scenario passes true to observe the
/// server-initiated GOAWAY and the close.
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

/// br-asupersync-mfqfst L4: with a one-request budget, the request is served
/// (200 + body) and the connection is then recycled — the server initiates a
/// graceful GOAWAY and closes, instead of keeping the connection alive.
#[test]
fn h2_recycles_connection_at_request_limit() {
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
            recycle_config(Some(1)),
        )
        .await
        .expect("bind listener");

        let addr = listener.local_addr().expect("local addr");
        let manager = listener.connection_manager().clone();

        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&handle).await })
            .expect("spawn listener run");

        // read_to_eof: observe the recycle GOAWAY and the server close that
        // follow the single served response.
        let client = h2_blocking_client(addr, "/recycle", true);
        let outcome = client.join().expect("client thread");

        assert_eq!(outcome.status.as_deref(), Some("200"), "{outcome:?}");
        assert_eq!(outcome.body, b"served /recycle", "{outcome:?}");
        assert!(
            !outcome.goaway_last_stream_ids.is_empty(),
            "server must recycle the connection with a GOAWAY after the \
             one-request budget is reached: {outcome:?}"
        );

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let stats = run_handle.await.expect("listener run result");
        let report = stats.drain_report.expect("drain report");
        assert!(report.reached_quiescence, "{report}");
    });
}

/// br-asupersync-mfqfst L4: a budget larger than the requests actually served
/// must NOT recycle the connection — the client gets its 200 with no
/// server-initiated GOAWAY, proving the budget is consumed per request rather
/// than tripped prematurely.
#[test]
fn h2_unlimited_budget_keeps_connection_after_single_request() {
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
            // Budget of 2: a single request stays well under it.
            recycle_config(Some(2)),
        )
        .await
        .expect("bind listener");

        let addr = listener.local_addr().expect("local addr");
        let manager = listener.connection_manager().clone();

        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&handle).await })
            .expect("spawn listener run");

        // read_to_eof false: return once the response stream ends. A recycled
        // connection would have queued a GOAWAY before/with the response; a
        // kept-alive one has not.
        let client = h2_blocking_client(addr, "/keep-alive", false);
        let outcome = client.join().expect("client thread");

        assert_eq!(outcome.status.as_deref(), Some("200"), "{outcome:?}");
        assert_eq!(outcome.body, b"served /keep-alive", "{outcome:?}");
        assert!(
            outcome.goaway_last_stream_ids.is_empty(),
            "a single request under the budget must not recycle the \
             connection: {outcome:?}"
        );

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let _ = run_handle.await.expect("listener run result");
    });
}
