//! Request-aware graceful drain e2e for the HTTP/2 listener
//! (br-asupersync-eprpk6, increments 2-4; h1 parity with
//! tests/e2e_h1_graceful_drain.rs).
//!
//! Scenarios against a real `Http2Listener` on a multi-thread runtime, with
//! a raw frame-speaking std-TCP client (preface + SETTINGS + HEADERS):
//!   - `h2_serves_request_response_round_trip`: sanity — one request, one
//!     200 response with the response body on a DATA frame.
//!   - `h2_router_composes_over_live_listener_with_request_cx`: a Cx-aware
//!     Router handler and its 404 fallback both run through the same real
//!     frame-level listener adapter (br-asupersync-server-stack-hardening-eeexl1.17).
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

use asupersync::Cx;
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
use asupersync::web::handler::AsyncCxFnHandler;
use asupersync::web::router::{Router, get};

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

/// The production Router adapter composes with the native H2 listener over
/// real frames, inherits its bounded request-region Cx, and preserves 404
/// routing.
#[test]
fn h2_router_composes_over_live_listener_with_request_cx() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let request_timeout = Duration::from_secs(30);
        let handler_runs = Arc::new(AtomicUsize::new(0));
        let observed_runs = Arc::clone(&handler_runs);
        let app = Router::new()
            .without_default_trace()
            .route(
                "/router-h2",
                get(AsyncCxFnHandler::new(move |cx: Cx| {
                    let observed_runs = Arc::clone(&observed_runs);
                    async move {
                        let ambient = Cx::current()
                            .expect("listener request Cx should remain current in router handler");
                        assert_eq!(ambient.region_id(), cx.region_id());
                        assert_eq!(ambient.task_id(), cx.task_id());
                        let remaining = cx
                            .remaining_budget()
                            .deadline
                            .expect("H2 listener must install its finite request deadline");
                        assert!(
                            remaining <= request_timeout,
                            "request budget {remaining:?} exceeds configured {request_timeout:?}"
                        );
                        assert!(
                            remaining >= Duration::from_secs(20),
                            "request budget {remaining:?} did not originate from the fresh 30s listener timeout"
                        );
                        observed_runs.fetch_add(1, Ordering::SeqCst);
                        "router-h2-cx"
                    }
                })),
            )
            .into_http_handler();
        let listener = Http2Listener::bind_with_config(
            "127.0.0.1:0",
            app,
            drain_config(Duration::from_secs(10), Duration::from_secs(20))
                .request_timeout(Some(request_timeout)),
        )
        .await
        .expect("bind Router-backed H2 listener");

        let addr = listener.local_addr().expect("local addr");
        let manager = listener.connection_manager().clone();
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&handle).await })
            .expect("spawn Router-backed listener run");

        let matched = h2_blocking_client(addr, "/router-h2", false)
            .join()
            .expect("matched client thread");
        assert_eq!(matched.status.as_deref(), Some("200"), "{matched:?}");
        assert_eq!(matched.body, b"router-h2-cx", "{matched:?}");
        assert_eq!(handler_runs.load(Ordering::SeqCst), 1);

        let unmatched = h2_blocking_client(addr, "/missing", false)
            .join()
            .expect("unmatched client thread");
        assert_eq!(unmatched.status.as_deref(), Some("404"), "{unmatched:?}");
        assert_eq!(handler_runs.load(Ordering::SeqCst), 1);

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

// The external oracle is deliberately opt-in. A maintained proof command must
// select this exact ignored test; an ordinary ignored/zero-test run is no proof.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod external_h2spec {
    use super::*;
    use base64::Engine as _;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::fs::{self, File, OpenOptions};
    use std::future::{Future, poll_fn};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::Instant;

    const BINARY_SHA256: &str = "ac679b916bcd46c52314b17c8903d8dffebf0f2357586d272731f6d8bfd5e9f7";
    const VERSION: &str = "Version: 2.6.0 (70ac2294010887f48b18e2d64f5cccd48421fad1)";
    const BODY: &[u8] = b"asupersync native h2spec interoperability\n";

    fn digest(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn new_file(path: &Path) -> File {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap_or_else(|error| {
                panic!("preserve existing evidence {}: {error}", path.display())
            })
    }

    fn write_json(dir: &Path, name: &str, value: &Value) {
        serde_json::to_writer_pretty(new_file(&dir.join(name)), value).unwrap();
    }

    // Owned by the test thread, outside the native worker watchdog. Even a
    // failed assertion exports the original raw files for the remote runner.
    struct ExportArtifacts(PathBuf);

    impl Drop for ExportArtifacts {
        fn drop(&mut self) {
            let emit = || -> std::io::Result<()> {
                let mut paths = fs::read_dir(&self.0)?
                    .map(|entry| entry.map(|entry| entry.path()))
                    .collect::<std::io::Result<Vec<_>>>()?;
                paths.sort();
                for path in paths {
                    if !path.is_file() {
                        continue;
                    }
                    let size = fs::metadata(&path)?.len();
                    if size > 32 * 1024 * 1024 {
                        return Err(std::io::Error::other(format!(
                            "artifact exceeds export bound; retained at {} ({size} bytes)",
                            path.display()
                        )));
                    }
                    let bytes = fs::read(&path)?;
                    println!(
                        "ASUPERSYNC_H2SPEC_ARTIFACT {}",
                        json!({"name":path.file_name().unwrap().to_str().unwrap(),
                            "sha256":digest(&bytes),"bytes":bytes.len(),
                            "base64":base64::engine::general_purpose::STANDARD.encode(&bytes)})
                    );
                }
                Ok(())
            };
            if let Err(error) = emit() {
                eprintln!(
                    "H2SPEC_ARTIFACT_EXPORT_FAILED dir={} {error}",
                    self.0.display()
                );
                if !std::thread::panicking() {
                    panic!("raw external evidence export failed: {error}");
                }
            }
        }
    }

    struct OwnedProcess(Child);

    impl Drop for OwnedProcess {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                // This exact subprocess is ours. Killing on timeout is failure,
                // and its original partial stdout/stderr remain in the files.
                if let Err(error) = self.0.kill() {
                    eprintln!("h2spec owned process kill failed: {error}");
                }
                if let Err(error) = self.0.wait() {
                    eprintln!("h2spec owned process wait failed: {error}");
                }
            }
        }
    }

    fn run_process(
        binary: &Path,
        args: &[String],
        dir: &Path,
        stage: &str,
        timeout: Duration,
    ) -> Value {
        write_json(
            dir,
            &format!("{stage}.command.json"),
            &json!({"program":binary,"args":args,"timeout_seconds":timeout.as_secs()}),
        );
        let mut child = OwnedProcess(
            Command::new(binary)
                .args(args)
                .stdin(Stdio::null())
                .stdout(new_file(&dir.join(format!("{stage}.stdout"))))
                .stderr(new_file(&dir.join(format!("{stage}.stderr"))))
                .spawn()
                .unwrap_or_else(|error| panic!("{stage} spawn failed: {error}")),
        );
        let pid = child.0.id();
        let started = Instant::now();
        let (status, timed_out) = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break (status, false);
            }
            if started.elapsed() >= timeout {
                child.0.kill().expect("kill this timed-out external oracle");
                break (
                    child.0.wait().expect("reap timed-out external oracle"),
                    true,
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let receipt = json!({"stage":stage,"pid":pid,"exit_code":status.code(),
            "success":status.success(),"timed_out":timed_out,
            "elapsed_ms":started.elapsed().as_millis(),"artifact_dir":dir,
            "stdout":dir.join(format!("{stage}.stdout")),
            "stderr":dir.join(format!("{stage}.stderr"))});
        write_json(dir, &format!("{stage}.terminal.json"), &receipt);
        receipt
    }

    fn h2spec(binary: &Path, dir: &Path, stage: &str, addr: SocketAddr, cases: &[&str]) -> Value {
        let mut args = vec![
            "--strict".to_owned(),
            "--verbose".to_owned(),
            "--timeout".to_owned(),
            "3".to_owned(),
            "--host".to_owned(),
            addr.ip().to_string(),
            "--port".to_owned(),
            addr.port().to_string(),
            "--path".to_owned(),
            "/".to_owned(),
            "--junit-report".to_owned(),
            dir.join(format!("{stage}.xml"))
                .to_str()
                .unwrap()
                .to_owned(),
        ];
        args.extend(cases.iter().map(|case| (*case).to_owned()));
        run_process(
            binary,
            &args,
            dir,
            stage,
            Duration::from_secs(if stage == "full" { 900 } else { 30 }),
        )
    }

    // v2.6.0 emits the group package and description in JUnit, but no numeric
    // case ID. Join to discovery from that exact pinned binary, rather than
    // inventing IDs from the subset's XML position. Python's standard XML
    // parser handles escaping; no ad-hoc XML string matching decides success.
    const PARSE_REPORT: &str = r#"
import json, pathlib, re, sys, xml.etree.ElementTree as ET
directory, stage, selection = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3:]
titles = {'Generic tests for HTTP/2 server':'generic',
          'Hypertext Transfer Protocol Version 2 (HTTP/2)':'http2',
          'HPACK: Header Compression for HTTP/2':'hpack'}
known, root, section = {}, None, None
for line in (directory/'discovery.stdout').read_text().splitlines():
    text = line.strip()
    if text in titles:
        root, section = titles[text], None
    elif match := re.fullmatch(r'(\d[\d.]*)\. (.+)', text):
        section = match[1]
    elif match := re.fullmatch(r'(\d+): (.+)', text):
        assert root and section, line
        key, identity = (root+'/'+section, match[2]), root+'/'+section+'/'+match[1]
        assert key not in known, key
        known[key] = identity
assert {key.split('/')[0] for key, _ in known} == {'generic','http2','hpack'}
expected = {identity for identity in known.values()
            if any(identity == item or identity.startswith(item+'/') for item in selection)}
assert expected, selection
tree = ET.parse(directory/(stage+'.xml')).getroot()
assert tree.tag == 'testsuites'
rows, seen = [], set()
for suite in tree.findall('testsuite'):
    cases = suite.findall('testcase')
    assert int(suite.attrib['tests']) == len(cases)
    counted = {'failures':0,'errors':0,'skipped':0}
    for case in cases:
        key = (case.attrib['package'], case.attrib['classname'])
        identity = known[key]
        assert identity not in seen, identity
        seen.add(identity)
        results = [kind for kind in ('failure','error','skipped') if case.find(kind) is not None]
        assert len(results) <= 1, identity
        result = results[0] if results else 'passed'
        if results:
            counted[{'failure':'failures','error':'errors','skipped':'skipped'}[result]] += 1
        rows.append(dict(id=identity, package=key[0], description=key[1], result=result,
                         diagnostic=''.join(case.itertext()), time=case.attrib['time']))
    assert all(int(suite.attrib[name]) == value for name, value in counted.items()), suite.attrib
assert seen == expected, dict(missing=sorted(expected-seen), unexpected=sorted(seen-expected))
summary = dict(selected=len(rows), passed=sum(row['result']=='passed' for row in rows),
               failed=sum(row['result']=='failure' for row in rows),
               errors=sum(row['result']=='error' for row in rows),
               skipped=sum(row['result']=='skipped' for row in rows),
               cases=sorted(rows,key=lambda row:row['id']))
print(json.dumps(summary,sort_keys=True))
"#;

    fn report(dir: &Path, stage: &str, selection: &[&str]) -> Value {
        let mut args = vec![
            "-c".to_owned(),
            PARSE_REPORT.to_owned(),
            dir.to_str().unwrap().to_owned(),
            stage.to_owned(),
        ];
        args.extend(selection.iter().map(|item| (*item).to_owned()));
        let parse_stage = format!("{stage}.parse");
        let terminal = run_process(
            Path::new("python3"),
            &args,
            dir,
            &parse_stage,
            Duration::from_secs(15),
        );
        assert_eq!(terminal["success"], true, "{terminal}");
        assert_eq!(terminal["timed_out"], false, "{terminal}");
        serde_json::from_slice(&fs::read(dir.join(format!("{parse_stage}.stdout"))).unwrap())
            .unwrap()
    }

    fn write_frame(socket: &mut std::net::TcpStream, frame: Frame) {
        let mut bytes = BytesMut::new();
        frame.encode(&mut bytes).unwrap();
        socket.write_all(&bytes).unwrap();
    }

    fn request(addr: SocketAddr, method: &str, path: &str, until_eof: bool) -> Value {
        let mut socket =
            std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket.write_all(CLIENT_PREFACE).unwrap();
        write_frame(&mut socket, Frame::Settings(SettingsFrame::new(Vec::new())));
        let mut block = BytesMut::new();
        HpackEncoder::new().encode(
            &[
                Header::new(":method", method),
                Header::new(":scheme", "http"),
                Header::new(":path", path),
                Header::new(":authority", addr.to_string()),
            ],
            &mut block,
        );
        write_frame(
            &mut socket,
            Frame::Headers(HeadersFrame::new(1, block.freeze(), method != "POST", true)),
        );
        if method == "POST" {
            write_frame(
                &mut socket,
                Frame::Data(asupersync::http::h2::frame::DataFrame::new(
                    1,
                    asupersync::bytes::Bytes::from_static(b"post-body"),
                    true,
                )),
            );
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut codec = FrameCodec::new();
        let mut buffer = BytesMut::new();
        let mut decoder = HpackDecoder::new();
        let mut status = None;
        let mut body = Vec::new();
        let mut frames = Vec::new();
        let mut ended = false;
        let mut eof = false;
        while !ended || until_eof {
            while let Some(frame) = codec
                .decode(&mut buffer)
                .expect("valid native response frame")
            {
                assert!(frames.len() < 512, "bounded readiness/drain frame trace");
                frames.push(format!("{frame:?}"));
                match frame {
                    Frame::Settings(settings) if !settings.ack => {
                        write_frame(&mut socket, Frame::Settings(SettingsFrame::ack()));
                    }
                    Frame::Headers(headers) => {
                        let mut block = headers.header_block;
                        for header in decoder.decode(&mut block).unwrap() {
                            if header.name == ":status" {
                                status = Some(header.value);
                            }
                        }
                        ended |= headers.end_stream;
                    }
                    Frame::Data(data) => {
                        body.extend_from_slice(&data.data);
                        assert!(body.len() <= 64 * 1024);
                        ended |= data.end_stream;
                    }
                    _ => {}
                }
            }
            if ended && !until_eof {
                break;
            }
            socket
                .set_read_timeout(Some(
                    deadline
                        .checked_duration_since(Instant::now())
                        .expect("whole readiness/open-stream read deadline"),
                ))
                .unwrap();
            let mut chunk = [0; 8192];
            match socket.read(&mut chunk) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(count) => buffer.extend_from_slice(&chunk[..count]),
                Err(error) => {
                    panic!("native H2 response did not reach its terminal: {error}; {frames:?}")
                }
            }
        }
        json!({"method":method,"path":path,"status":status,"body":body,
            "end_stream":ended,"eof":eof,"frames":frames})
    }

    struct HeldRequest {
        cx: Cx,
        dropped: Arc<AtomicUsize>,
        cancelled: Arc<AtomicUsize>,
    }

    impl Drop for HeldRequest {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
            if self.cx.is_cancel_requested() {
                self.cancelled.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    struct NativeServer {
        runtime: Option<asupersync::runtime::Runtime>,
        run: Option<
            asupersync::runtime::JoinHandle<
                std::io::Result<asupersync::server::shutdown::ShutdownStats>,
            >,
        >,
        manager: asupersync::server::connection::ConnectionManager,
        in_flight: Arc<AtomicUsize>,
        stats: Arc<asupersync::http::h2::listener::Http2ListenerStats>,
        addr: SocketAddr,
        parked: std::sync::mpsc::Receiver<(asupersync::types::TaskId, asupersync::types::RegionId)>,
        dropped: Arc<AtomicUsize>,
        cancelled: Arc<AtomicUsize>,
    }

    impl NativeServer {
        fn start() -> Self {
            type HandlerFuture = std::pin::Pin<Box<dyn Future<Output = Response> + Send>>;
            type Handler =
                Box<dyn Fn(asupersync::http::h1::types::Request) -> HandlerFuture + Send + Sync>;
            let runtime = RuntimeBuilder::multi_thread()
                .worker_threads(2)
                .build()
                .unwrap();
            assert_eq!(runtime.config().worker_threads, 2);
            let dropped = Arc::new(AtomicUsize::new(0));
            let cancelled = Arc::new(AtomicUsize::new(0));
            let handler_dropped = Arc::clone(&dropped);
            let handler_cancelled = Arc::clone(&cancelled);
            let (sent, parked) = std::sync::mpsc::sync_channel(1);
            let listener = runtime
                .block_on(Http2Listener::bind_with_config(
                    "127.0.0.1:0",
                    Box::new(
                        move |req: asupersync::http::h1::types::Request| -> HandlerFuture {
                            let sent = sent.clone();
                            let dropped = Arc::clone(&handler_dropped);
                            let cancelled = Arc::clone(&handler_cancelled);
                            Box::pin(async move {
                                if req.uri == "/__h2spec_open_stream" {
                                    let cx = Cx::current().expect("real native request context");
                                    let _held = HeldRequest {
                                        cx: cx.clone(),
                                        dropped,
                                        cancelled,
                                    };
                                    let (_keep_open, mut receiver) =
                                        asupersync::channel::mpsc::channel::<()>(1);
                                    let mut receiving = Box::pin(receiver.recv(&cx));
                                    let mut announced = false;
                                    let result = poll_fn(|poll_cx| {
                                        let result = receiving.as_mut().poll(poll_cx);
                                        if result.is_pending() && !announced {
                                            sent.try_send((cx.task_id(), cx.region_id())).unwrap();
                                            announced = true;
                                        }
                                        result
                                    })
                                    .await;
                                    assert_eq!(
                                        result,
                                        Err(asupersync::channel::mpsc::RecvError::Cancelled)
                                    );
                                }
                                Response::new(200, "OK", BODY.to_vec())
                            })
                        },
                    ) as Handler,
                    Http2ListenerConfig::default()
                        // h2spec constructs authority from the ephemeral endpoint.
                        // This is explicit test-service policy, not a default flip.
                        .host_policy(HostPolicy::allow_all())
                        .request_timeout(None)
                        .idle_timeout(None)
                        .stream_idle_timeout(None)
                        .drain_timeout(Duration::from_millis(100))
                        .hard_drain_timeout(Duration::from_secs(5)),
                ))
                .unwrap();
            let addr = listener.local_addr().unwrap();
            let manager = listener.connection_manager().clone();
            let stats = listener.stats_handle();
            let in_flight = listener.in_flight_requests();
            let handle = runtime.handle();
            let spawner = handle.clone();
            let serving: std::pin::Pin<
                Box<
                    dyn Future<
                            Output = std::io::Result<asupersync::server::shutdown::ShutdownStats>,
                        > + Send,
                >,
            > = Box::pin(async move { listener.run(&handle).await });
            let run = spawner.try_spawn(serving).unwrap();
            Self {
                runtime: Some(runtime),
                run: Some(run),
                manager,
                stats,
                in_flight,
                addr,
                parked,
                dropped,
                cancelled,
            }
        }

        fn stop_with_open_stream(mut self, dir: &Path) -> Value {
            let quiet_deadline = Instant::now() + Duration::from_secs(10);
            while self.manager.active_count() != 0 || self.in_flight.load(Ordering::SeqCst) != 0 {
                assert!(
                    Instant::now() < quiet_deadline,
                    "external suite left a connection/handler live"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            let addr = self.addr;
            let (sent, received) = std::sync::mpsc::sync_channel(1);
            let client = std::thread::spawn(move || {
                let result = std::panic::catch_unwind(|| {
                    request(addr, "GET", "/__h2spec_open_stream", true)
                });
                let _ = sent.send(result);
            });
            let identity = self
                .parked
                .recv_timeout(Duration::from_secs(10))
                .expect("actual request receive crossed Pending");
            assert_eq!(self.in_flight.load(Ordering::SeqCst), 1);
            assert_eq!(self.manager.active_count(), 1);
            assert_eq!(self.dropped.load(Ordering::SeqCst), 0);
            let held_tasks = self
                .runtime
                .as_ref()
                .unwrap()
                .task_inspector(Default::default())
                .list_active_tasks();
            let registered_owner = held_tasks
                .iter()
                .any(|task| task.id == identity.0 && task.region_id == identity.1);
            write_json(
                dir,
                "open-stream.parked.json",
                &json!({"task":identity.0,"region":identity.1,
                "in_flight":1,"active_connections":1,"actual_recv_pending":true,
                "registered_owner":registered_owner,"actual_live_tasks":format!("{held_tasks:?}")}),
            );
            assert!(self.manager.begin_drain(Duration::from_secs(5)));
            let runtime = self.runtime.as_ref().unwrap();
            let stats = runtime
                .block_on(self.run.take().unwrap())
                .expect("native listener drain result");
            let response = received
                .recv_timeout(Duration::from_secs(25))
                .expect("open stream client terminated");
            client.join().expect("owned open stream reader joined");
            let response = response.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
            let report = stats
                .drain_report
                .as_ref()
                .expect("actual request-aware drain report");
            let deadline = Instant::now() + Duration::from_secs(10);
            while !runtime.is_quiescent() {
                assert!(
                    Instant::now() < deadline,
                    "native owned tasks did not reach quiescence"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            let tasks = runtime.task_inspector(Default::default()).list_tasks();
            let leaks = runtime.diagnostics().find_leaked_obligations();
            let trace = runtime
                .handle()
                .trace_snapshot()
                .expect("native terminal trace");
            let completes = trace
                .iter()
                .filter(|event| {
                    event.kind == asupersync::trace::TraceEventKind::Complete
                        && matches!(event.data, asupersync::trace::TraceData::Task { task, region }
                    if task == identity.0 && region == identity.1)
                })
                .count();
            let shutdown = self
                .runtime
                .take()
                .unwrap()
                .shutdown_timeout(Duration::from_secs(5));
            let receipt = json!({"scenario":"native_open_stream_shutdown","task":identity.0,"region":identity.1,
                "registered_owner_at_pending":registered_owner,
                "actual_recv_pending":true,"handler_dropped":self.dropped.load(Ordering::SeqCst),
                "handler_cancel_seen":self.cancelled.load(Ordering::SeqCst),"task_complete_events":completes,
                "active_connections":self.manager.active_count(),"in_flight":self.in_flight.load(Ordering::SeqCst),
                "live_tasks":tasks.len(),"leaks":leaks.len(),"runtime_shutdown":shutdown,
                "requests_at_drain_start":report.requests_at_drain_start,
                "requests_at_escalation":report.requests_at_escalation,
                "reached_quiescence":report.reached_quiescence,"hard_deadline_hit":report.hard_deadline_hit,
                "listener_stats":format!("{:?}",self.stats.snapshot()),"client":response});
            write_json(dir, "open-stream.shutdown.json", &receipt);
            assert!(
                registered_owner,
                "handler ambient Cx lacks an actual registered owner: {receipt}"
            );
            assert_eq!(receipt["handler_dropped"], 1, "{receipt}");
            assert_eq!(receipt["handler_cancel_seen"], 1, "{receipt}");
            assert_eq!(receipt["task_complete_events"], 1, "{receipt}");
            assert_eq!(receipt["active_connections"], 0, "{receipt}");
            assert_eq!(receipt["in_flight"], 0, "{receipt}");
            assert!(
                tasks.is_empty() && leaks.is_empty() && shutdown,
                "{receipt}"
            );
            assert_eq!(report.requests_at_drain_start, 1, "{receipt}");
            assert_eq!(report.requests_at_escalation, Some(1), "{receipt}");
            assert!(
                report.reached_quiescence && !report.hard_deadline_hit,
                "{receipt}"
            );
            assert_eq!(receipt["client"]["eof"], true, "{receipt}");
            assert_ne!(receipt["client"]["status"], "200", "{receipt}");
            receipt
        }
    }

    impl Drop for NativeServer {
        fn drop(&mut self) {
            // Failure cleanup requests actual connection shutdown, and cannot
            // fabricate the joined/zero-ownership receipt above.
            if self.runtime.is_some() {
                self.manager.force_close();
            }
        }
    }

    fn invalid_ping_peer() -> (
        SocketAddr,
        std::thread::JoinHandle<()>,
        std::sync::mpsc::Receiver<Value>,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let (sent, received) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let result = std::panic::catch_unwind(|| {
                let deadline = Instant::now() + Duration::from_secs(15);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "negative oracle never connected");
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("negative listener accept: {error}"),
                    }
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut preface = [0; 24];
                socket.read_exact(&mut preface).unwrap();
                assert_eq!(&preface, CLIENT_PREFACE);
                write_frame(&mut socket, Frame::Settings(SettingsFrame::new(Vec::new())));
                let mut codec = FrameCodec::new();
                let mut buffer = BytesMut::new();
                let mut settings = 0;
                let mut acknowledgements = 0;
                let mut ping = None;
                let mut wire = Vec::new();
                loop {
                    while let Some(frame) = codec.decode(&mut buffer).unwrap() {
                        wire.push(format!("{frame:?}"));
                        assert!(wire.len() <= 64);
                        match frame {
                            Frame::Settings(frame) if !frame.ack => {
                                settings += 1;
                                write_frame(&mut socket, Frame::Settings(SettingsFrame::ack()));
                            }
                            Frame::Settings(_) => acknowledgements += 1,
                            Frame::Ping(frame) if !frame.ack => {
                                assert!(
                                    settings > 0 && acknowledgements > 0,
                                    "PING must follow a successful two-way SETTINGS handshake"
                                );
                                assert!(ping.is_none());
                                assert_eq!(frame.opaque_data, *b"h2spec\0\0");
                                let mut wrong = frame.opaque_data;
                                wrong[0] ^= 1;
                                write_frame(
                                    &mut socket,
                                    Frame::Ping(asupersync::http::h2::frame::PingFrame::ack(wrong)),
                                );
                                ping = Some(json!({"received":frame.opaque_data,"sent":wrong}));
                            }
                            _ => {}
                        }
                    }
                    let mut chunk = [0; 4096];
                    match socket.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(count) => buffer.extend_from_slice(&chunk[..count]),
                        Err(error) => {
                            panic!("negative peer did not reach client close: {error}; {wire:?}")
                        }
                    }
                }
                assert!(ping.is_some(), "no planted protocol response was exercised");
                json!({"role":"deliberately_invalid_negative_only_peer","preface_valid":true,
                    "settings_received":settings,"settings_ack_received":acknowledgements,
                    "wrong_ping_responses":1,"ping":ping,"frames":wire,"client_closed":true})
            });
            let value = match result {
                Ok(value) => value,
                Err(panic) => {
                    let diagnostic = panic
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
                        .unwrap_or_else(|| "non-string panic".to_owned());
                    json!({"peer_error":diagnostic})
                }
            };
            let _ = sent.send(value);
        });
        (addr, worker, received)
    }

    fn exercise(binary: PathBuf, dir: PathBuf, source_base: String, source_fingerprint: String) {
        let bytes = fs::read(&binary).expect("explicit H2SPEC_BIN exists");
        assert_eq!(digest(&bytes), BINARY_SHA256, "unreviewed external binary");
        let version = run_process(
            &binary,
            &["--version".to_owned()],
            &dir,
            "version",
            Duration::from_secs(10),
        );
        assert_eq!(version["success"], true, "{version}");
        let version_text = fs::read_to_string(dir.join("version.stdout")).unwrap();
        assert_eq!(version_text.trim(), VERSION);
        let discovery = run_process(
            &binary,
            &[
                "--strict".to_owned(),
                "--dryrun".to_owned(),
                "generic".to_owned(),
                "http2".to_owned(),
                "hpack".to_owned(),
            ],
            &dir,
            "discovery",
            Duration::from_secs(10),
        );
        assert_eq!(discovery["success"], true, "{discovery}");
        write_json(
            &dir,
            "identity.json",
            &json!({"binary":binary,"binary_sha256":BINARY_SHA256,
            "version":VERSION,"archive_sha256":"157ee0de702e01ad40e752dbf074b366027e550c8e7504f9450da2809e279318",
            "release_url":"https://github.com/summerwind/h2spec/releases/download/v2.6.0/h2spec_linux_amd64.tar.gz",
            "archive_digest_verified_here":false,"package_version":env!("CARGO_PKG_VERSION"),
            "source_base":source_base,"source_fingerprint":source_fingerprint,
            "source_authority":"caller_reported_clean_overlay_identity_not_worker_hash",
            "features":"tls,test-internals","backend":"native_two_worker","transport":"cleartext_prior_knowledge_h2"}),
        );
        let server = NativeServer::start();
        let get = request(server.addr, "GET", "/", false);
        let post = request(server.addr, "POST", "/", false);
        let readiness = json!({"addr":server.addr.to_string(),"get":get,"post":post});
        write_json(&dir, "readiness.json", &readiness);
        for result in [&readiness["get"], &readiness["post"]] {
            assert_eq!(result["status"], "200", "{readiness}");
            assert_eq!(result["body"], json!(BODY), "{readiness}");
            assert_eq!(result["end_stream"], true, "{readiness}");
        }
        let full_terminal = h2spec(
            &binary,
            &dir,
            "full",
            server.addr,
            &["generic", "http2", "hpack"],
        );
        // Do not assert the external verdict yet: retain the negative control
        // and actual open-stream shutdown even when the real sweep found bugs.
        let (bad_addr, bad_worker, bad_received) = invalid_ping_peer();
        let negative_terminal = h2spec(&binary, &dir, "negative", bad_addr, &["generic/3.7/1"]);
        let peer = bad_received
            .recv_timeout(Duration::from_secs(20))
            .expect("bounded invalid peer termination");
        bad_worker.join().expect("owned invalid peer joined");
        write_json(&dir, "negative.peer.json", &peer);
        // Hash again after execution, so replacing the explicitly selected tool
        // while the suite ran cannot produce a successful identity receipt.
        assert_eq!(digest(&fs::read(&binary).unwrap()), BINARY_SHA256);
        let full_report = report(&dir, "full", &["generic", "http2", "hpack"]);
        write_json(
            &dir,
            "full.verdict.json",
            &json!({"terminal":full_terminal,"report":full_report}),
        );
        let negative_report = report(&dir, "negative", &["generic/3.7/1"]);
        let negative = json!({"terminal":negative_terminal,"report":negative_report,"peer":peer});
        write_json(&dir, "negative.verdict.json", &negative);
        let cleanup = server.stop_with_open_stream(&dir);
        assert_eq!(negative["terminal"]["timed_out"], false, "{negative}");
        assert_eq!(negative["terminal"]["exit_code"], 1, "{negative}");
        assert_eq!(negative["report"]["selected"], 1, "{negative}");
        assert_eq!(negative["report"]["passed"], 0, "{negative}");
        assert_eq!(negative["report"]["skipped"], 0, "{negative}");
        assert_eq!(
            negative["report"]["failed"].as_u64().unwrap()
                + negative["report"]["errors"].as_u64().unwrap(),
            1,
            "{negative}"
        );
        assert_eq!(negative["peer"]["wrong_ping_responses"], 1, "{negative}");
        let diagnostic = negative["report"]["cases"][0]["diagnostic"]
            .as_str()
            .unwrap();
        assert!(
            diagnostic.contains("PING Frame")
                && diagnostic.contains("h2spec")
                && diagnostic.contains("i2spec")
                && !diagnostic.contains("Timeout"),
            "{negative}"
        );
        let passed = full_terminal["success"] == true
            && full_terminal["timed_out"] == false
            && full_report["selected"].as_u64().unwrap() > 0
            && full_report["passed"] == full_report["selected"]
            && full_report["failed"] == 0
            && full_report["errors"] == 0
            && full_report["skipped"] == 0;
        let summary = json!({"schema_version":"asupersync.native_h2spec.v1","bead_id":"asupersync-bi2462.36",
            "binary_sha256":BINARY_SHA256,"version":VERSION,
            "source_base":source_base,"source_fingerprint":source_fingerprint,
            "source_authority":"caller_reported_clean_overlay_identity_not_worker_hash",
            "features":"tls,test-internals","package_version":env!("CARGO_PKG_VERSION"),"readiness":readiness,
            "full":{"terminal":full_terminal,"report":full_report},"negative":negative,
            "cleanup":cleanup,"passed":passed});
        write_json(&dir, "summary.json", &summary);
        println!("ASUPERSYNC_H2SPEC_SUMMARY {summary}");
        assert!(
            passed,
            "external strict h2spec failed; original cases/frames/stdout/stderr/XML are retained at {}",
            dir.display()
        );
    }

    #[test]
    #[ignore = "requires pinned external h2spec v2.6.0; run through the maintained --h2spec proof mode"]
    fn native_h2spec_strict_conformance() {
        assert!(
            cfg!(feature = "tls"),
            "maintained h2spec proof profile requires tls,test-internals"
        );
        let binary =
            fs::canonicalize(std::env::var_os("H2SPEC_BIN").expect("explicit H2SPEC_BIN required"))
                .unwrap();
        let dir = PathBuf::from(
            std::env::var_os("H2SPEC_ARTIFACT_DIR").expect("fresh H2SPEC_ARTIFACT_DIR required"),
        );
        assert!(
            dir.is_absolute(),
            "remote raw evidence path must be absolute"
        );
        fs::create_dir(&dir)
            .expect("artifact directory must be fresh; never overwrite previous evidence");
        let _export = ExportArtifacts(dir.clone());
        println!("ASUPERSYNC_H2SPEC_ARTIFACT_DIR {}", dir.display());
        let source_base = std::env::var("H2SPEC_SOURCE_BASE").expect("caller source base required");
        let source_fingerprint =
            std::env::var("H2SPEC_SOURCE_FINGERPRINT").expect("caller source fingerprint required");
        assert_eq!(source_base.len(), 40);
        assert_eq!(source_fingerprint.len(), 64);
        assert!(
            source_base
                .bytes()
                .chain(source_fingerprint.bytes())
                .all(|byte| byte.is_ascii_hexdigit())
        );
        let (sent, received) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let result =
                std::panic::catch_unwind(|| exercise(binary, dir, source_base, source_fingerprint));
            let _ = sent.send(result);
        });
        let result = received
            .recv_timeout(Duration::from_secs(1200))
            .expect("whole native interoperability watchdog; no success or cleanup is implied");
        worker
            .join()
            .expect("owned native interoperability worker terminated");
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }
}
