//! Frame-arrival-independent CONTINUATION timeout for the HTTP/2 listener
//! (br-asupersync-mfqfst L4).
//!
//! `Connection::check_continuation_timeout` only runs when a frame arrives, so
//! a client that opens a header block (HEADERS without END_HEADERS) and then
//! goes silent could pin a half-read header block open forever (slowloris).
//! The serve loop now arms an absolute deadline from the connection's
//! remaining CONTINUATION budget that fires without any further frame.
//!
//! `h2_reclaims_stalled_continuation_connection`: a client sends a HEADERS
//! frame with END_HEADERS unset and then sends nothing more; after the
//! (short) CONTINUATION budget the server closes the connection with a
//! PROTOCOL_ERROR GOAWAY, no response, no further client frame required.
//!
//! Integration test (`--test`): public API only, unaffected by in-lib
//! `#[cfg(test)]` breakage.

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
use asupersync::http::h2::settings::Settings;
use asupersync::http::h2::{FrameCodec, Header, HpackEncoder};
use asupersync::runtime::RuntimeBuilder;

/// What the stalled client observed before the connection closed.
#[derive(Debug, Default)]
struct H2ClientOutcome {
    status: Option<String>,
    goaway_count: usize,
    closed: bool,
}

/// Raw frame-speaking blocking client: sends the preface, an empty SETTINGS
/// frame, and a single HEADERS frame on stream 1 with END_HEADERS *unset*
/// (claiming a CONTINUATION sequence) and then sends nothing more, reading
/// frames (acking server SETTINGS) until the server closes the connection.
fn h2_stalled_continuation_client(addr: SocketAddr) -> std::thread::JoinHandle<H2ClientOutcome> {
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
                Header::new(":path", "/stalled"),
                Header::new(":authority", "localhost"),
            ],
            &mut block,
        );
        // end_stream = false, end_headers = false: the server now expects a
        // CONTINUATION frame that this client deliberately never sends.
        Frame::Headers(HeadersFrame::new(1, block.freeze(), false, false))
            .encode(&mut out)
            .expect("encode incomplete HEADERS");
        stream.write_all(&out).expect("write request");
        stream.flush().expect("flush request");

        let mut codec = FrameCodec::new();
        let mut read_buf = BytesMut::new();
        let mut chunk = [0u8; 4096];
        loop {
            loop {
                match codec.decode(&mut read_buf) {
                    Ok(Some(Frame::Settings(settings))) if !settings.ack => {
                        let mut ack = BytesMut::new();
                        Frame::Settings(SettingsFrame::ack())
                            .encode(&mut ack)
                            .expect("encode SETTINGS ack");
                        let _ = stream.write_all(&ack);
                    }
                    Ok(Some(Frame::Headers(_))) => {
                        // A response would mean the request completed — it must
                        // not, since the header block is incomplete.
                        outcome.status = Some("unexpected-headers".to_owned());
                    }
                    Ok(Some(Frame::GoAway(_))) => outcome.goaway_count += 1,
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => {
                        outcome.closed = true;
                        return outcome;
                    }
                }
            }
            match stream.read(&mut chunk) {
                Ok(0) => {
                    outcome.closed = true;
                    return outcome;
                }
                Ok(n) => read_buf.extend_from_slice(&chunk[..n]),
                Err(_) => return outcome,
            }
        }
    })
}

/// br-asupersync-mfqfst L4: a connection left mid-CONTINUATION with no further
/// frame is reclaimed after the budget — the server emits a GOAWAY and closes
/// without waiting for a frame that never comes, and the handler never runs.
#[test]
fn h2_reclaims_stalled_continuation_connection() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let handler_ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handler_flag = std::sync::Arc::clone(&handler_ran);

        // Short CONTINUATION budget so the stall is reclaimed quickly.
        let mut settings = Settings::server();
        settings.continuation_timeout_ms = 200;
        let config = Http2ListenerConfig::default()
            .drain_timeout(Duration::from_secs(10))
            .hard_drain_timeout(Duration::from_secs(20))
            .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
            .settings(settings);

        let listener = Http2Listener::bind_with_config(
            "127.0.0.1:0",
            move |_req| {
                let handler_flag = std::sync::Arc::clone(&handler_flag);
                async move {
                    handler_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    Response::new(200, "OK", Vec::new())
                }
            },
            config,
        )
        .await
        .expect("bind listener");

        let addr = listener.local_addr().expect("local addr");
        let manager = listener.connection_manager().clone();

        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&handle).await })
            .expect("spawn listener run");

        let client = h2_stalled_continuation_client(addr);
        let outcome = client.join().expect("client thread");

        assert!(
            outcome.closed,
            "server must close the stalled CONTINUATION connection: {outcome:?}"
        );
        assert!(
            outcome.goaway_count >= 1,
            "server must signal the stall with a GOAWAY: {outcome:?}"
        );
        assert_eq!(
            outcome.status, None,
            "no response: the request never completed: {outcome:?}"
        );
        assert!(
            !handler_ran.load(std::sync::atomic::Ordering::SeqCst),
            "handler must not run for an incomplete request"
        );

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let _ = run_handle.await.expect("listener run result");
    });
}
