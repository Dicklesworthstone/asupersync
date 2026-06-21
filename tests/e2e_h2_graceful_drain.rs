//! Request-aware graceful drain e2e for the HTTP/2 listener
//! (br-asupersync-eprpk6, increments 2-4; h1 parity with
//! tests/e2e_h1_graceful_drain.rs).
//!
//! Scenarios against a real `Http2Listener` on a multi-thread runtime, with
//! a raw frame-speaking std-TCP client (preface + SETTINGS + HEADERS):
//!   - `h2_serves_request_response_round_trip`: sanity — one request, one
//!     200 response with the response body on a DATA frame.
//!   - `h2_rejects_disallowed_host_with_421`: a request whose host is not on
//!     the allow-list gets a per-stream 421 and the handler never runs
//!     (br-asupersync-mfqfst M8).
//!   - `h2_drain_completes_in_flight_requests`: requests parked in handlers
//!     when the drain begins complete under a generous soft budget; clients
//!     observe the two-stage GOAWAY (warning 2^31-1, then the ratcheted
//!     definitive boundary) and the drain report reaches quiescence.
//!   - `h2_drain_escalates_stragglers`: handlers that never finish are
//!     escalated at the soft deadline; clients never see a 200 and the
//!     listener still stops cleanly with a truthful report.
//!   - `h2_lb_compat_keeps_socket_until_drain_completes` (br-asupersync-1kcwfd
//!     item 3; h1 D2.4 AC5 parity): with `lb_compat_keep_socket`, the listening
//!     socket stays bound (TCP handshakes succeed, nothing is served) for the
//!     whole drain window and closes only once the drain is over.

#![cfg(feature = "test-internals")]

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
use asupersync::server::shutdown::ShutdownPhase;
use asupersync::sync::Notify;

fn drain_config(drain: Duration, hard: Duration) -> Http2ListenerConfig {
    Http2ListenerConfig::default()
        .drain_timeout(drain)
        .hard_drain_timeout(hard)
        // br-asupersync-mfqfst M8: the h2 listener is now secure-by-default
        // (RejectUnknown host policy). These e2e clients send `:authority
        // localhost`, so allow it explicitly.
        .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
}

/// What one raw h2 client observed before the connection closed.
#[derive(Debug, Default)]
struct H2ClientOutcome {
    status: Option<String>,
    body: Vec<u8>,
    goaway_last_stream_ids: Vec<u32>,
}

/// Raw frame-speaking blocking client on a std thread: sends the preface,
/// an empty SETTINGS frame, and one GET on stream 1, then reads frames
/// (acking server SETTINGS) until EOF or read timeout. With `read_to_eof`
/// false it returns as soon as the response stream ends (keep-alive
/// connections otherwise stay open); drain scenarios pass true so the
/// stage-2 GOAWAY and server close are observed.
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

/// Sanity: a single request gets a 200 with its body on a DATA frame.
#[test]
fn h2_serves_request_response_round_trip() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let listener = Http2Listener::bind_with_config(
            "127.0.0.1:0",
            move |req| async move {
                let body = format!("hello {}", req.uri).into_bytes();
                Response::new(200, "OK", body)
            },
            drain_config(Duration::from_secs(10), Duration::from_secs(20)),
        )
        .await
        .expect("bind listener");

        let addr = listener.local_addr().expect("local addr");
        let manager = listener.connection_manager().clone();

        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&handle).await })
            .expect("spawn listener run");

        let client = h2_blocking_client(addr, "/round-trip", false);
        let outcome = client.join().expect("client thread");
        assert_eq!(outcome.status.as_deref(), Some("200"), "{outcome:?}");
        assert_eq!(outcome.body, b"hello /round-trip", "{outcome:?}");

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let stats = run_handle.await.expect("listener run result");
        let report = stats.drain_report.expect("drain report");
        assert!(report.reached_quiescence, "{report}");
    });
}

/// br-asupersync-mfqfst M8: a request whose `:authority`/host is not on the
/// listener's allow-list is answered with a per-stream 421 Misdirected
/// Request, and the handler never runs.
#[test]
fn h2_rejects_disallowed_host_with_421() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let handler_ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handler_flag = std::sync::Arc::clone(&handler_ran);
        // The client sends `:authority localhost`, which is NOT on this
        // allow-list, so the request must be rejected before the handler.
        let config = Http2ListenerConfig::default()
            .drain_timeout(Duration::from_secs(10))
            .hard_drain_timeout(Duration::from_secs(20))
            .host_policy(HostPolicy::allow_list(vec!["other.example".to_owned()]));
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

        let client = h2_blocking_client(addr, "/blocked", false);
        let outcome = client.join().expect("client thread");
        assert_eq!(outcome.status.as_deref(), Some("421"), "{outcome:?}");
        assert!(
            !handler_ran.load(std::sync::atomic::Ordering::SeqCst),
            "handler must not run for a rejected host"
        );

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let _ = run_handle.await.expect("listener run result");
    });
}

/// In-flight requests at drain start complete within a generous soft
/// budget; clients observe the two-stage GOAWAY and their 200s.
#[test]
fn h2_drain_completes_in_flight_requests() {
    const IN_FLIGHT: usize = 5;

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let release = Arc::new(Notify::new());
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handler_release = Arc::clone(&release);
        let handler_released = Arc::clone(&released);

        let listener = Http2Listener::bind_with_config(
            "127.0.0.1:0",
            move |_req| {
                let release = Arc::clone(&handler_release);
                let released = Arc::clone(&handler_released);
                async move {
                    release
                        .wait_until(|| released.load(Ordering::Acquire))
                        .await;
                    Response::new(200, "OK", b"drained".to_vec())
                }
            },
            drain_config(Duration::from_secs(10), Duration::from_secs(20)),
        )
        .await
        .expect("bind listener");

        let addr = listener.local_addr().expect("local addr");
        let shutdown = listener.shutdown_signal();
        let manager = listener.connection_manager().clone();
        let in_flight = listener.in_flight_requests();

        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&handle).await })
            .expect("spawn listener run");

        let clients: Vec<_> = (0..IN_FLIGHT)
            .map(|_| h2_blocking_client(addr, "/parked", true))
            .collect();

        while in_flight.load(Ordering::Acquire) < IN_FLIGHT {
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }

        assert!(
            manager.begin_drain(Duration::from_secs(10)),
            "begin_drain transitions Running -> Draining"
        );
        released.store(true, Ordering::Release);
        release.notify_waiters();

        let stats = run_handle.await.expect("listener run result");
        assert_eq!(shutdown.phase(), ShutdownPhase::Stopped, "clean stop");
        assert_eq!(stats.force_closed, 0, "no connection was force-closed");

        let report = stats.drain_report.expect("drain report");
        assert_eq!(report.requests_at_drain_start, IN_FLIGHT);
        assert_eq!(report.requests_completed, IN_FLIGHT);
        assert!(report.reached_quiescence, "{report}");
        assert!(!report.hard_deadline_hit, "{report}");
        assert_eq!(report.requests_at_escalation, None, "{report}");

        for client in clients {
            let outcome = client.join().expect("client thread");
            assert_eq!(
                outcome.status.as_deref(),
                Some("200"),
                "in-flight request completed during drain: {outcome:?}"
            );
            assert_eq!(
                outcome.goaway_last_stream_ids.first().copied(),
                Some(0x7fff_ffff),
                "stage-1 GOAWAY warns with the max stream id: {outcome:?}"
            );
            assert_eq!(
                outcome.goaway_last_stream_ids.last().copied(),
                Some(1),
                "stage-2 GOAWAY ratchets to the served stream: {outcome:?}"
            );
        }
    });
}

/// Handlers that never finish are escalated at the soft deadline; clients
/// never see a 200 and the listener still reaches a clean stop.
#[test]
fn h2_drain_escalates_stragglers() {
    const STRAGGLERS: usize = 3;

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let handlers_parked = Arc::new(AtomicUsize::new(0));
        let handler_parked = Arc::clone(&handlers_parked);

        let listener = Http2Listener::bind_with_config(
            "127.0.0.1:0",
            move |_req| {
                let handlers_parked = Arc::clone(&handler_parked);
                async move {
                    handlers_parked.fetch_add(1, Ordering::AcqRel);
                    let mut iterations = 0usize;
                    loop {
                        asupersync::time::sleep(
                            asupersync::time::wall_now(),
                            Duration::from_millis(10),
                        )
                        .await;
                        iterations = iterations.wrapping_add(1);
                        if iterations == usize::MAX {
                            break;
                        }
                    }
                    Response::new(200, "OK", Vec::new())
                }
            },
            drain_config(Duration::from_millis(200), Duration::from_secs(5)),
        )
        .await
        .expect("bind listener");

        let addr = listener.local_addr().expect("local addr");
        let shutdown = listener.shutdown_signal();
        let manager = listener.connection_manager().clone();
        let in_flight = listener.in_flight_requests();

        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&handle).await })
            .expect("spawn listener run");

        let clients: Vec<_> = (0..STRAGGLERS)
            .map(|_| h2_blocking_client(addr, "/straggler", true))
            .collect();

        while in_flight.load(Ordering::Acquire) < STRAGGLERS
            || handlers_parked.load(Ordering::Acquire) < STRAGGLERS
        {
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }

        // The manager gets a LONG backstop deadline so the request-aware
        // supervisor (config drain_timeout = 200ms) is deterministically the
        // escalation driver; with equal deadlines the manager's own timeout
        // can force-close first and the report records no escalation.
        assert!(
            manager.begin_drain(Duration::from_secs(5)),
            "begin_drain transitions Running -> Draining"
        );

        let stats = run_handle.await.expect("listener run result");
        assert_eq!(shutdown.phase(), ShutdownPhase::Stopped, "clean stop");

        let report = stats.drain_report.expect("drain report");
        assert_eq!(report.requests_at_drain_start, STRAGGLERS);
        assert_eq!(report.requests_at_escalation, Some(STRAGGLERS), "{report}");
        assert!(!report.hard_deadline_hit, "{report}");
        assert!(
            report.reached_quiescence,
            "escalated handlers released their in-flight guards: {report}"
        );

        for client in clients {
            let outcome = client.join().expect("client thread");
            assert_ne!(
                outcome.status.as_deref(),
                Some("200"),
                "straggler must not complete: {outcome:?}"
            );
        }
    });
}

/// br-asupersync-1kcwfd item 3 (h1 D2.4 AC5 parity, mirrors
/// `tests/e2e_h1_graceful_drain.rs::lb_compat_keeps_socket_until_drain_completes`):
/// with `lb_compat_keep_socket`, the listening socket stays bound and keeps
/// completing TCP handshakes for the whole drain window (load balancers can
/// still probe it), serves nothing new, and closes only once the drain has
/// finished. The in-flight request that held the window open still completes.
#[test]
fn h2_lb_compat_keeps_socket_until_drain_completes() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let release = Arc::new(Notify::new());
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handler_release = Arc::clone(&release);
        let handler_released = Arc::clone(&released);

        let listener = Http2Listener::bind_with_config(
            "127.0.0.1:0",
            move |_req| {
                let release = Arc::clone(&handler_release);
                let released = Arc::clone(&handler_released);
                async move {
                    release
                        .wait_until(|| released.load(Ordering::Acquire))
                        .await;
                    Response::new(200, "OK", b"drained".to_vec())
                }
            },
            drain_config(Duration::from_secs(10), Duration::from_secs(20))
                .lb_compat_keep_socket(true),
        )
        .await
        .expect("bind listener");

        let addr = listener.local_addr().expect("local addr");
        let manager = listener.connection_manager().clone();
        let in_flight = listener.in_flight_requests();

        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&handle).await })
            .expect("spawn listener run");

        // One request parked in its handler keeps the drain window open.
        let client = h2_blocking_client(addr, "/parked", true);
        while in_flight.load(Ordering::Acquire) < 1 {
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }

        assert!(
            manager.begin_drain(Duration::from_secs(10)),
            "begin_drain transitions Running -> Draining"
        );

        // Give the accept loop time to observe the drain and park the socket,
        // then prove the socket still completes TCP handshakes mid-drain.
        asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(100)).await;
        let probe = std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500));
        assert!(
            probe.is_ok(),
            "lb_compat keeps the socket connectable during the drain: {probe:?}"
        );
        drop(probe);

        // Release the parked handler so the drain completes.
        released.store(true, Ordering::Release);
        release.notify_waiters();
        let stats = run_handle.await.expect("listener run result");
        let report = stats.drain_report.expect("request-aware drain report");
        assert!(
            report.reached_quiescence,
            "drain reached quiescence: {report}"
        );

        // The parked socket is closed once the drain is over: connection
        // attempts now fail (allow a short window for the OS to tear down).
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
                Err(_) => break,
                Ok(stream) => {
                    drop(stream);
                    assert!(
                        std::time::Instant::now() < deadline,
                        "socket must close after the drain completes"
                    );
                    asupersync::time::sleep(
                        asupersync::time::wall_now(),
                        Duration::from_millis(50),
                    )
                    .await;
                }
            }
        }

        let outcome = client.join().expect("client thread");
        assert_eq!(
            outcome.status.as_deref(),
            Some("200"),
            "the in-flight request completed during the lb_compat drain: {outcome:?}"
        );
        assert_eq!(outcome.body, b"drained", "{outcome:?}");
    });
}
