//! Request-aware graceful drain e2e for the HTTP/1.1 listener
//! (br-asupersync-server-stack-hardening-eeexl1.2, D2.2b).
//!
//! Six scenarios against a real `Http1Listener` on a multi-thread runtime:
//!   - `produced_listener_writes_chunks_and_terminal_trailers`: the production
//!     listener writes multiple bounded chunks and exactly one trailer-bearing
//!     terminator over a real TCP connection.
//!   - `produced_listener_finishes_in_flight_body_during_drain`: a parked
//!     produced body remains in the listener request count and finishes inside
//!     a graceful drain without force-close.
//!   - `sse_listener_force_close_cancels_source_without_terminator`: an
//!     infinite SSE source is force-closed during drain, cancelled exactly
//!     once, and never publishes a clean terminator.
//!   - `drain_completes_in_flight_requests`: many requests are in flight when
//!     the drain begins with a generous soft budget; every one completes with
//!     a `200` that advertises `Connection: close`, nothing is force-closed,
//!     and the drain report reaches quiescence without the hard deadline.
//!   - `drain_escalates_stragglers`: handlers that never finish are in flight
//!     when the drain begins with a tight soft budget; the supervisor
//!     escalates through force-close, the stragglers are interrupted (clients
//!     see the connection close without a response), and the listener still
//!     reaches a clean stop with a drain report.
//!   - `lb_compat_keeps_socket_until_drain_completes` (D2.4 AC5): with
//!     `lb_compat_keep_socket`, TCP handshakes still succeed against the
//!     bound-but-not-accepting socket for the whole drain window, and the
//!     socket only closes once the drain completes.

#![cfg(feature = "test-internals")]
// Match the runtime crate's limit for the nested produced-body/drain futures.
#![recursion_limit = "256"]

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
use asupersync::http::h1::server::{HostPolicy, Http1Config, Http1Server, Http1StreamingServer};
use asupersync::http::h1::stream::Http1ProducedResponse;
use asupersync::http::h1::types::Response;
use asupersync::http::{HeaderMap, HeaderName, HeaderValue};
use asupersync::io::{AsyncRead, AsyncWrite};
use asupersync::runtime::RuntimeBuilder;
use asupersync::server::shutdown::ShutdownPhase;
use asupersync::sync::Notify;
use asupersync::web::sse::{SseEvent, StreamingSse, StreamingSseError, StreamingSseSource};

/// Observes an actual reactor-backed write returning Pending. It never
/// manufactures Pending and never wakes the serving task itself.
struct ObservedResponseSocket {
    inner: asupersync::net::tcp::stream::TcpStream,
    pending: Arc<AtomicUsize>,
    parked: Arc<Notify>,
    first_write: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl AsyncRead for ObservedResponseSocket {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut asupersync::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ObservedResponseSocket {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        {
            let mut first = self.first_write.lock().expect("response witness lock");
            if first.is_empty() {
                first.extend_from_slice(&buf[..buf.len().min(64)]);
            }
        }
        let polled = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if polled.is_pending() {
            self.pending.fetch_add(1, Ordering::AcqRel);
            self.parked.notify_one();
        }
        polled
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The peer holds its receive window closed throughout the verdict. For a
/// short error response, fill the real TCP send queue first; otherwise a
/// 100-byte refusal can fit even though the application never reads it.
fn nonreading_response_peer(
    request: &[u8],
    prefill: bool,
) -> (std::net::TcpStream, std::net::TcpStream, usize) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind response socket");
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
        .expect("create nonreading peer");
    socket
        .set_recv_buffer_size(4096)
        .expect("small receive window");
    socket
        .connect(
            &listener
                .local_addr()
                .expect("response socket address")
                .into(),
        )
        .expect("connect nonreading peer");
    let mut client = std::net::TcpStream::from(socket);
    client
        .write_all(request)
        .expect("send request before parking");
    let (mut server, _) = listener.accept().expect("accept response socket");
    socket2::SockRef::from(&server)
        .set_send_buffer_size(4096)
        .expect("small server send queue");
    server
        .set_nonblocking(true)
        .expect("nonblocking response socket");
    let mut filled = 0;
    if prefill {
        let started = std::time::Instant::now();
        let mut blocked_since = None;
        let fill = [b'x'; 16 * 1024];
        loop {
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "TCP queue never filled"
            );
            match server.write(&fill) {
                Ok(0) => panic!("response socket closed during setup"),
                Ok(count) => {
                    filled += count;
                    blocked_since = None;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    let blocked = blocked_since.get_or_insert_with(std::time::Instant::now);
                    if blocked.elapsed() >= Duration::from_millis(50) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("fill response socket: {error}"),
            }
        }
    }
    (server, client, filled)
}

fn stalled_response_matrix(force_close: bool) {
    let cases = [
        ("streaming", b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(), 200),
        ("bad-head", b"BROKEN\r\n\r\n".to_vec(), 400),
        ("large-head", format!("GET / HTTP/1.1\r\nHost: localhost\r\nX-Large: {}\r\n\r\n", "x".repeat(1024)).into_bytes(), 431),
        ("host-refused", b"GET / HTTP/1.1\r\nHost: invalid.example\r\n\r\n".to_vec(), 421),
        ("expect-refused", b"GET / HTTP/1.1\r\nHost: localhost\r\nExpect: impossible\r\n\r\n".to_vec(), 417),
        ("continue", b"POST / HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\n".to_vec(), 100),
    ];
    for workers in [1, 2] {
        for (scenario, request, status) in &cases {
            let streaming = *scenario == "streaming";
            let (server, client, filled) = nonreading_response_peer(request, !streaming);
            let runtime = RuntimeBuilder::new()
                .worker_threads(workers)
                .build()
                .expect("native runtime");
            let handle = runtime.handle();
            runtime.block_on(async move {
                let pending = Arc::new(AtomicUsize::new(0));
                let parked = Arc::new(Notify::new());
                let first_write = Arc::new(std::sync::Mutex::new(Vec::new()));
                let in_flight = Arc::new(AtomicUsize::new(0));
                let shutdown = asupersync::server::shutdown::ShutdownSignal::new();
                let socket = ObservedResponseSocket {
                    inner: asupersync::net::tcp::stream::TcpStream::from_std(server).expect("reactor socket"),
                    pending: Arc::clone(&pending),
                    parked: Arc::clone(&parked),
                    first_write: Arc::clone(&first_write),
                };
                let config = Http1Config {
                    max_headers_size: if *scenario == "large-head" { 256 } else { 8192 },
                    allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
                    idle_timeout: (!force_close).then_some(Duration::from_millis(300)),
                    ..Http1Config::default()
                };
                let serving_signal = shutdown.clone();
                let serving_in_flight = Arc::clone(&in_flight);
                let serving = handle.try_spawn(async move {
                    if streaming {
                        let cx = asupersync::Cx::current().expect("serving context");
                        Http1StreamingServer::with_config(
                            |_cx, _request| async { Response::new(200, "OK", vec![b'x'; 8 * 1024 * 1024]) },
                            config,
                        )
                        .with_shutdown_signal(serving_signal)
                        .with_in_flight_requests(serving_in_flight)
                        .serve(&cx, socket)
                        .await
                    } else {
                        Http1Server::with_config(
                            |_request| async { panic!("rejected request reached handler") }, config,
                        )
                        .with_shutdown_signal(serving_signal)
                        .with_in_flight_requests(serving_in_flight)
                        .serve(socket)
                        .await
                    }
                }).expect("spawn connection");
                asupersync::time::timeout(asupersync::time::wall_now(), Duration::from_secs(2),
                    parked.wait_until(|| pending.load(Ordering::Acquire) > 0),
                ).await.expect("real response write must park before trigger");
                let prefix = first_write.lock().expect("response prefix").clone();
                assert!(prefix.starts_with(format!("HTTP/1.1 {status} ").as_bytes()), "wrong response path: {prefix:?}");
                let in_flight_at_park = in_flight.load(Ordering::Acquire);
                if streaming {
                    assert_eq!(in_flight_at_park, 1);
                }
                let triggered = std::time::Instant::now();
                if force_close {
                    assert!(shutdown.begin_drain(Duration::from_secs(10)));
                    assert!(shutdown.begin_force_close());
                }
                let result = asupersync::time::timeout(
                    asupersync::time::wall_now(), Duration::from_secs(2), serving,
                ).await;
                let elapsed = triggered.elapsed();
                // Failure cleanup happens after the verdict. The nonreader
                // cannot make a missing response deadline look successful.
                drop(client);
                let result = result.expect("parked response must release its connection");
                if *scenario != "continue" {
                    assert!(matches!(result, Err(asupersync::http::h1::codec::HttpError::Io(ref error))
                        if error.kind() == if force_close { std::io::ErrorKind::Interrupted } else { std::io::ErrorKind::TimedOut }),
                        "unexpected response result: {result:?}");
                }
                assert_eq!(in_flight.load(Ordering::Acquire), 0, "request slot leaked");
                eprintln!("{{\"bead\":\"asupersync-bi2462.103\",\"scenario\":\"{scenario}\",\"workers\":{workers},\"force_close\":{force_close},\"prefill_bytes\":{filled},\"pending_writes\":{},\"in_flight_at_park\":{in_flight_at_park},\"elapsed_ms\":{},\"retired\":true}}", pending.load(Ordering::Acquire), elapsed.as_millis());
            });
        }
    }
}

#[test]
fn nonreading_peer_releases_streaming_and_error_responses_at_idle_deadline() {
    stalled_response_matrix(false);
}

#[test]
fn force_close_releases_parked_streaming_and_error_responses_without_idle_timeout() {
    stalled_response_matrix(true);
}

struct PendingProducerDrop(Arc<AtomicUsize>);

impl Drop for PendingProducerDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
fn produced_listener_bounds_parked_frame_and_terminal_receipt_waits() {
    for workers in [1, 2] {
        for terminal_receipt in [false, true] {
            let runtime = RuntimeBuilder::new()
                .worker_threads(workers)
                .build()
                .expect("native producer runtime");
            let handle = runtime.handle();
            runtime.block_on(async move {
                let parked = Arc::new(Notify::new());
                let polls = Arc::new(AtomicUsize::new(0));
                let drops = Arc::new(AtomicUsize::new(0));
                let handler_parked = Arc::clone(&parked);
                let handler_polls = Arc::clone(&polls);
                let handler_drops = Arc::clone(&drops);
                let listener = Http1Listener::bind_produced_with_config(
                    "127.0.0.1:0",
                    move |_cx, _request| {
                        let parked = Arc::clone(&handler_parked);
                        let polls = Arc::clone(&handler_polls);
                        let drops = Arc::clone(&handler_drops);
                        async move {
                            Http1ProducedResponse::chunked(NonZeroUsize::MIN, 200, "OK", move |cx, mut sender| async move {
                                let _drop = PendingProducerDrop(drops);
                                sender.send_chunk(&cx, b"alpha").await?;
                                if terminal_receipt {
                                    sender.finish(&cx)?;
                                }
                                std::future::poll_fn(move |_task| {
                                    polls.fetch_add(1, Ordering::AcqRel);
                                    parked.notify_one();
                                    // No self-wake and no external release: only
                                    // the server's deadline can end this wait.
                                    std::task::Poll::<()>::Pending
                                }).await;
                                Ok(sender)
                            })
                        }
                    },
                    localhost_config(Duration::from_secs(5), Duration::from_secs(10))
                        .http_config(Http1Config {
                            allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
                            idle_timeout: Some(Duration::from_millis(300)),
                            request_drain_grace: Duration::from_millis(25),
                            ..Http1Config::default()
                        }),
                ).await.expect("bind stalled producer listener");
                let address = listener.local_addr().expect("producer address");
                let manager = listener.connection_manager().clone();
                let in_flight = listener.in_flight_requests();
                let shutdown = listener.shutdown_signal();
                let running = handle.clone().try_spawn(async move { listener.run_produced(&handle).await }).expect("spawn producer listener");
                let client = blocking_client(address);
                asupersync::time::timeout(asupersync::time::wall_now(), Duration::from_secs(2),
                    parked.wait_until(|| polls.load(Ordering::Acquire) > 0),
                ).await.expect("producer reached an actual pending poll");
                assert_eq!(in_flight.load(Ordering::Acquire), 1);
                let started = std::time::Instant::now();
                let retired = asupersync::time::timeout(asupersync::time::wall_now(), Duration::from_secs(2), async {
                    while !manager.is_empty() || in_flight.load(Ordering::Acquire) != 0 {
                        asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
                    }
                }).await;
                let elapsed = started.elapsed();
                // Begin drain only after recording the independent idle-bound
                // verdict. Shutdown cannot rescue a stuck producer into green.
                assert!(manager.begin_drain(Duration::from_secs(5)));
                if retired.is_err() {
                    let _ = shutdown.begin_force_close();
                }
                let stats = asupersync::time::timeout(asupersync::time::wall_now(), Duration::from_secs(2), running)
                    .await.expect("listener shutdown must finish").expect("listener result");
                let response = client.join().expect("producer client");
                retired.expect("idle deadline must retire a parked producer");
                assert_eq!(drops.load(Ordering::Acquire), 1, "producer dropped exactly once");
                assert_eq!(stats.force_closed, 0);
                assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
                assert!(response_body(&response).starts_with("5\r\nalpha\r\n"));
                assert!(!response_body(&response).contains("0\r\n\r\n"), "no clean terminator without producer receipt");
                eprintln!("{{\"bead\":\"asupersync-bi2462.103\",\"scenario\":\"parked-producer\",\"workers\":{workers},\"terminal_receipt\":{terminal_receipt},\"pending_polls\":{},\"elapsed_ms\":{},\"retired_before_shutdown\":true}}", polls.load(Ordering::Acquire), elapsed.as_millis());
            });
        }
    }
}

fn localhost_config(drain: Duration, hard: Duration) -> Http1ListenerConfig {
    Http1ListenerConfig::default()
        .http_config(Http1Config {
            allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
            ..Http1Config::default()
        })
        .drain_timeout(drain)
        .hard_drain_timeout(hard)
}

/// Blocking client on a std thread: sends one GET and reads to EOF (the
/// draining server closes the connection after the response).
fn blocking_client(addr: SocketAddr) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut stream = std::net::TcpStream::connect(addr).expect("client connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("set read timeout");
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("client write");
        let mut response = String::new();
        // EOF (server close) ends the read; a timeout fails loudly via the
        // empty-response asserts in the callers.
        let _ = stream.read_to_string(&mut response);
        response
    })
}

fn response_body(response: &str) -> &str {
    response.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

fn has_two_sse_event_chunks(response: &[u8]) -> bool {
    let Some(head_end) = response
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
    else {
        return false;
    };
    let head = std::str::from_utf8(&response[..head_end]).expect("SSE response head is UTF-8");
    assert!(
        head.split("\r\n").skip(1).any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("transfer-encoding")
                    && value.trim().eq_ignore_ascii_case("chunked")
            })
        }),
        "SSE response must advertise chunked transfer encoding: {head:?}"
    );

    let body = &response[head_end + b"\r\n\r\n".len()..];
    let expected = [
        b"data:event-1\n\n".as_slice(),
        b"data:event-2\n\n".as_slice(),
    ];
    let mut cursor = 0;
    for expected_payload in expected {
        let Some(size_line_end) = body[cursor..]
            .windows(b"\r\n".len())
            .position(|window| window == b"\r\n")
            .map(|offset| cursor + offset)
        else {
            return false;
        };
        let size_line =
            std::str::from_utf8(&body[cursor..size_line_end]).expect("SSE chunk size is ASCII");
        let chunk_size = usize::from_str_radix(size_line, 16).expect("valid SSE chunk size");
        assert_ne!(chunk_size, 0, "SSE stream terminated before two events");

        let payload_start = size_line_end + b"\r\n".len();
        let payload_end = payload_start + chunk_size;
        if body.len() < payload_end + b"\r\n".len() {
            return false;
        }
        assert_eq!(
            &body[payload_start..payload_end],
            expected_payload,
            "each live SSE event must occupy its own HTTP chunk"
        );
        assert_eq!(
            &body[payload_end..payload_end + b"\r\n".len()],
            b"\r\n",
            "SSE chunk must end with CRLF"
        );
        cursor = payload_end + b"\r\n".len();
    }
    true
}

struct InfiniteSseSource {
    source_calls: Arc<AtomicUsize>,
    cancel_calls: Arc<AtomicUsize>,
}

impl StreamingSseSource for InfiniteSseSource {
    fn next_event(&mut self, cx: &asupersync::Cx) -> Result<Option<SseEvent>, StreamingSseError> {
        cx.checkpoint().map_err(|_| StreamingSseError::Cancelled)?;
        let call = self.source_calls.fetch_add(1, Ordering::AcqRel) + 1;
        Ok(Some(SseEvent::default().data(format!("event-{call}"))))
    }

    fn cancel(&mut self) {
        self.cancel_calls.fetch_add(1, Ordering::AcqRel);
    }
}

/// BODY-7C: the production listener reaches the supervised produced-response
/// driver over a real TCP socket, including terminal trailers.
#[test]
fn produced_listener_writes_chunks_and_terminal_trailers() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let listener = Http1Listener::bind_produced_with_config(
            "127.0.0.1:0",
            |_cx, _request| async move {
                Http1ProducedResponse::chunked(
                    NonZeroUsize::MIN,
                    200,
                    "OK",
                    |producer_cx, mut sender| async move {
                        sender.send_chunk(&producer_cx, b"alpha").await?;
                        sender.send_chunk(&producer_cx, b"beta").await?;
                        let mut trailers = HeaderMap::new();
                        trailers.append(
                            HeaderName::from_static("x-checksum"),
                            HeaderValue::from_static("verified"),
                        );
                        sender.send_trailers(&producer_cx, trailers).await?;
                        Ok(sender)
                    },
                )
                .with_header("Trailer", "x-checksum")
            },
            localhost_config(Duration::from_secs(10), Duration::from_secs(20)),
        )
        .await
        .expect("bind produced listener");

        let addr = listener.local_addr().expect("local addr");
        let manager = listener.connection_manager().clone();
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run_produced(&handle).await })
            .expect("spawn produced listener");

        let client = blocking_client(addr);
        let response = client.join().expect("client thread");
        assert!(
            response.starts_with("HTTP/1.1 200 OK\r\n"),
            "produced listener returned a success head: {response:?}"
        );
        assert_eq!(
            response_body(&response),
            "5\r\nalpha\r\n4\r\nbeta\r\n0\r\nx-checksum: verified\r\n\r\n"
        );
        assert_eq!(
            response.matches("0\r\n").count(),
            1,
            "terminal chunk is serialized exactly once"
        );

        assert!(
            manager.begin_drain(Duration::from_secs(10)),
            "stop the listener after the connection closes"
        );
        let stats = run_handle.await.expect("produced listener result");
        assert_eq!(stats.force_closed, 0);
        assert!(manager.is_empty());
    });
}

/// BODY-7C: a produced response stays in the listener-wide request count for
/// its complete producer lifetime and can finish inside a graceful drain.
#[test]
fn produced_listener_finishes_in_flight_body_during_drain() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let producer_started = Arc::new(Notify::new());
        let producer_release = Arc::new(Notify::new());
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handler_started = Arc::clone(&producer_started);
        let handler_release = Arc::clone(&producer_release);
        let handler_released = Arc::clone(&released);

        let listener = Http1Listener::bind_produced_with_config(
            "127.0.0.1:0",
            move |_cx, _request| {
                let producer_started = Arc::clone(&handler_started);
                let producer_release = Arc::clone(&handler_release);
                let released = Arc::clone(&handler_released);
                async move {
                    Http1ProducedResponse::chunked(
                        NonZeroUsize::MIN,
                        200,
                        "OK",
                        move |producer_cx, mut sender| async move {
                            sender.send_chunk(&producer_cx, b"alpha").await?;
                            producer_started.notify_one();
                            producer_release
                                .wait_until(|| released.load(Ordering::Acquire))
                                .await;
                            sender.send_chunk(&producer_cx, b"beta").await?;
                            sender.finish(&producer_cx)?;
                            Ok(sender)
                        },
                    )
                }
            },
            localhost_config(Duration::from_secs(10), Duration::from_secs(20)),
        )
        .await
        .expect("bind produced listener");

        let addr = listener.local_addr().expect("local addr");
        let shutdown = listener.shutdown_signal();
        let manager = listener.connection_manager().clone();
        let in_flight = listener.in_flight_requests();
        let stats_handle = listener.stats_handle();
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run_produced(&handle).await })
            .expect("spawn produced listener");

        let client = blocking_client(addr);
        producer_started.notified().await;
        assert_eq!(
            in_flight.load(Ordering::Acquire),
            1,
            "produced body remains an in-flight request while its producer is parked"
        );
        assert!(
            manager.begin_drain(Duration::from_secs(10)),
            "begin drain with the produced body in flight"
        );

        for _ in 0..400 {
            if stats_handle.snapshot().drains_started_total == 1 {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        let during_drain = stats_handle.snapshot();
        assert_eq!(during_drain.drains_started_total, 1);
        assert_eq!(during_drain.last_drain_requests_at_start, 1);
        assert_eq!(in_flight.load(Ordering::Acquire), 1);

        released.store(true, Ordering::Release);
        producer_release.notify_waiters();

        let stats = run_handle.await.expect("produced listener result");
        let response = client.join().expect("client thread");
        assert_eq!(
            response_body(&response),
            "5\r\nalpha\r\n4\r\nbeta\r\n0\r\n\r\n"
        );
        assert!(
            response.to_lowercase().contains("connection: close"),
            "draining produced response advertises close: {response:?}"
        );
        assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
        assert_eq!(stats.force_closed, 0);
        let report = stats.drain_report.expect("produced drain report");
        assert_eq!(report.requests_at_drain_start, 1);
        assert_eq!(report.requests_completed, 1);
        assert_eq!(report.requests_stranded, 0);
        assert!(report.reached_quiescence);
        assert!(!report.hard_deadline_hit);
        assert_eq!(in_flight.load(Ordering::Acquire), 0);
        assert!(manager.is_empty());
    });
}

/// BODY-7D: force-closing the production listener cancels an infinite live
/// SSE source exactly once and closes without a successful chunk terminator.
#[test]
fn sse_listener_force_close_cancels_source_without_terminator() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let source_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let handler_source_calls = Arc::clone(&source_calls);
        let handler_cancel_calls = Arc::clone(&cancel_calls);
        let listener = Http1Listener::bind_sse_with_config(
            "127.0.0.1:0",
            move |_cx, _request| {
                let source_calls = Arc::clone(&handler_source_calls);
                let cancel_calls = Arc::clone(&handler_cancel_calls);
                async move {
                    StreamingSse::from_source(InfiniteSseSource {
                        source_calls,
                        cancel_calls,
                    })
                    .into_http1_response(NonZeroUsize::MIN)
                }
            },
            localhost_config(Duration::from_millis(200), Duration::from_secs(5)),
        )
        .await
        .expect("bind SSE listener");

        let addr = listener.local_addr().expect("local addr");
        let shutdown = listener.shutdown_signal();
        let manager = listener.connection_manager().clone();
        let in_flight = listener.in_flight_requests();
        let stats_handle = listener.stats_handle();
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run_sse(&handle).await })
            .expect("spawn SSE listener");

        let (observed_tx, observed_rx) = std::sync::mpsc::sync_channel(1);
        let client = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(addr).expect("client connect");
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("set read timeout");
            stream
                .write_all(b"GET /events HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .expect("write SSE request");

            let mut received = Vec::new();
            while !has_two_sse_event_chunks(&received) {
                let mut buffer = [0_u8; 4096];
                let count = stream.read(&mut buffer).expect("read SSE bytes");
                assert_ne!(count, 0, "SSE connection closed before two chunks");
                received.extend_from_slice(&buffer[..count]);
            }
            observed_tx
                .send(received.clone())
                .expect("publish two-event observation");

            let mut rolling_tail = received[received.len().saturating_sub(4)..].to_vec();
            let mut saw_terminator = received.windows(5).any(|window| window == b"0\r\n\r\n");
            loop {
                let mut buffer = [0_u8; 4096];
                let count = match stream.read(&mut buffer) {
                    Ok(count) => count,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::BrokenPipe
                        ) =>
                    {
                        break;
                    }
                    Err(error) => panic!("read until force-close termination: {error}"),
                };
                if count == 0 {
                    break;
                }
                rolling_tail.extend_from_slice(&buffer[..count]);
                saw_terminator |= rolling_tail.windows(5).any(|window| window == b"0\r\n\r\n");
                if rolling_tail.len() > 4 {
                    rolling_tail.drain(..rolling_tail.len() - 4);
                }
            }
            (received, saw_terminator)
        });

        let observed = observed_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("client observed two live SSE events");
        let observed = String::from_utf8(observed).expect("SSE response is UTF-8");
        assert!(response_body(&observed).contains("data:event-1\n\n"));
        assert!(response_body(&observed).contains("data:event-2\n\n"));
        assert!(!response_body(&observed).contains("0\r\n\r\n"));
        assert_eq!(in_flight.load(Ordering::Acquire), 1);

        assert!(
            manager.begin_drain(Duration::from_secs(5)),
            "begin drain with infinite SSE in flight"
        );
        for _ in 0..400 {
            if stats_handle.snapshot().drains_started_total == 1 {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }

        let stats = run_handle.await.expect("SSE listener result");
        let (_, saw_terminator) = client.join().expect("client thread");
        assert!(
            !saw_terminator,
            "force-close must not publish a clean terminator"
        );
        assert_eq!(cancel_calls.load(Ordering::Acquire), 1);
        assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
        assert!(stats.force_closed > 0);
        let report = stats.drain_report.expect("SSE drain report");
        assert_eq!(report.requests_at_drain_start, 1);
        assert_eq!(report.requests_at_escalation, Some(1));
        assert_eq!(report.requests_stranded, 0);
        assert!(report.reached_quiescence);
        assert!(!report.hard_deadline_hit);
        assert_eq!(in_flight.load(Ordering::Acquire), 0);
        assert!(manager.is_empty());
    });
}

/// AC1: in-flight requests at drain start complete within a generous soft
/// budget — zero cancelled, quiescence reached, `Connection: close` on every
/// in-flight response.
#[test]
fn drain_completes_in_flight_requests() {
    const IN_FLIGHT: usize = 50;

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

        let listener = Http1Listener::bind_with_config(
            "127.0.0.1:0",
            move |_req| {
                let release = Arc::clone(&handler_release);
                let released = Arc::clone(&handler_released);
                async move {
                    // Race-free park: re-checks the flag after every wake, so
                    // a handler that reaches this line after the test's
                    // notify_waiters still proceeds.
                    release
                        .wait_until(|| released.load(Ordering::Acquire))
                        .await;
                    Response::new(200, "OK", b"drained".to_vec())
                }
            },
            localhost_config(Duration::from_secs(10), Duration::from_secs(20)),
        )
        .await
        .expect("bind listener");

        let addr = listener.local_addr().expect("local addr");
        let shutdown = listener.shutdown_signal();
        let manager = listener.connection_manager().clone();
        let in_flight = listener.in_flight_requests();
        let stats_handle = listener.stats_handle();

        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&handle).await })
            .expect("spawn listener run");

        let clients: Vec<_> = (0..IN_FLIGHT).map(|_| blocking_client(addr)).collect();

        // Gate: every request has been read and is parked in its handler.
        while in_flight.load(Ordering::Acquire) < IN_FLIGHT {
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }

        assert!(
            manager.begin_drain(Duration::from_secs(10)),
            "begin_drain transitions Running -> Draining"
        );

        // `begin_drain` changes the manager state synchronously, while the
        // listener records its request snapshot when the drain supervisor
        // starts. Keep every handler parked until that snapshot is observable;
        // otherwise a fast handler can finish between those two events and
        // make this fixture race its own release signal.
        for _ in 0..400 {
            if stats_handle.snapshot().drains_started_total == 1 {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(
            stats_handle.snapshot().drains_started_total,
            1,
            "drain supervisor captured the in-flight snapshot before handler release"
        );

        // Release every parked handler; the drain window is generous, so all
        // of them complete gracefully.
        released.store(true, Ordering::Release);
        release.notify_waiters();

        let stats = run_handle.await.expect("listener run result");

        assert_eq!(shutdown.phase(), ShutdownPhase::Stopped, "clean stop");
        assert_eq!(stats.force_closed, 0, "no connection was force-closed");

        let report = stats.drain_report.expect("request-aware drain report");
        assert_eq!(
            report.requests_at_drain_start, IN_FLIGHT,
            "every request was in flight when the drain began"
        );
        assert_eq!(
            report.requests_completed, IN_FLIGHT,
            "all requests completed"
        );
        assert_eq!(report.requests_stranded, 0, "no request was stranded");
        assert_eq!(
            report.requests_at_escalation, None,
            "a clean drain never escalates (D2.4)"
        );
        assert!(report.reached_quiescence, "drain reached quiescence");
        assert!(!report.hard_deadline_hit, "hard deadline never fired");

        // D2.4 AC6: the drain is observable through the listener counters.
        let counters = stats_handle.snapshot();
        assert_eq!(counters.drains_started_total, 1);
        assert_eq!(counters.drains_quiescent_total, 1);
        assert_eq!(counters.drain_escalations_total, 0);
        assert_eq!(counters.drain_hard_deadline_hits_total, 0);
        assert_eq!(counters.last_drain_requests_at_start, IN_FLIGHT as u64);
        assert_eq!(counters.last_drain_requests_stranded, 0);

        for client in clients {
            let response = client.join().expect("client thread");
            assert!(
                response.starts_with("HTTP/1.1 200"),
                "in-flight request completed during drain: {response:?}"
            );
            let lower = response.to_lowercase();
            assert!(
                lower.contains("connection: close"),
                "draining response advertises Connection: close: {response:?}"
            );
        }
    });
}

/// AC2: handlers that never finish are escalated at the soft deadline and the
/// listener still reaches a clean stop with a truthful drain report.
#[test]
fn drain_escalates_stragglers() {
    const STRAGGLERS: usize = 5;

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let handlers_parked = Arc::new(AtomicUsize::new(0));
        let handler_parked = Arc::clone(&handlers_parked);

        let listener = Http1Listener::bind_with_config(
            "127.0.0.1:0",
            move |_req| {
                let handlers_parked = Arc::clone(&handler_parked);
                async move {
                    handlers_parked.fetch_add(1, Ordering::AcqRel);
                    loop {
                        asupersync::time::sleep(
                            asupersync::time::wall_now(),
                            Duration::from_millis(10),
                        )
                        .await;
                    }
                }
            },
            localhost_config(Duration::from_millis(200), Duration::from_secs(5)),
        )
        .await
        .expect("bind listener");

        let addr = listener.local_addr().expect("local addr");
        let shutdown = listener.shutdown_signal();
        let manager = listener.connection_manager().clone();
        let in_flight = listener.in_flight_requests();
        let stats_handle = listener.stats_handle();

        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&handle).await })
            .expect("spawn listener run");

        let clients: Vec<_> = (0..STRAGGLERS).map(|_| blocking_client(addr)).collect();

        while in_flight.load(Ordering::Acquire) < STRAGGLERS
            || handlers_parked.load(Ordering::Acquire) < STRAGGLERS
        {
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }

        // The manager gets a LONG backstop deadline so the request-aware
        // supervisor (config drain_timeout = 200ms) is deterministically the
        // escalation driver; with equal deadlines the manager's own timeout
        // can force-close first and the report records no escalation (the
        // race surfaced in the h2 twin of this test).
        assert!(
            manager.begin_drain(Duration::from_secs(5)),
            "begin_drain transitions Running -> Draining"
        );

        let stats = run_handle.await.expect("listener run result");

        assert_eq!(shutdown.phase(), ShutdownPhase::Stopped, "clean stop");
        assert!(
            stats.force_closed > 0,
            "stragglers were force-closed after escalation: {stats:?}"
        );

        let report = stats.drain_report.expect("request-aware drain report");
        assert_eq!(
            report.requests_at_drain_start, STRAGGLERS,
            "every straggler was in flight when the drain began"
        );
        assert!(
            !report.hard_deadline_hit,
            "escalation resolved the drain before the hard deadline: {report}"
        );
        assert!(
            report.reached_quiescence,
            "escalated handlers released their in-flight guards: {report}"
        );
        assert_eq!(
            report.requests_at_escalation,
            Some(STRAGGLERS),
            "all stragglers were still in flight at the escalation point (D2.4): {report}"
        );

        // D2.4 AC6: escalation shows up in the listener counters.
        let counters = stats_handle.snapshot();
        assert_eq!(counters.drains_started_total, 1);
        assert_eq!(counters.drain_escalations_total, 1);
        assert_eq!(counters.drain_hard_deadline_hits_total, 0);
        assert_eq!(counters.last_drain_requests_at_start, STRAGGLERS as u64);

        // Stragglers were interrupted: no complete 200 response was written.
        for client in clients {
            let response = client.join().expect("client thread");
            assert!(
                !response.starts_with("HTTP/1.1 200"),
                "straggler must not complete: {response:?}"
            );
        }
    });
}

/// D2.4 AC5: with `lb_compat_keep_socket`, the listening socket stays bound
/// (handshakes succeed, nothing is served) for the whole drain window and
/// closes only after the drain completes.
#[test]
fn lb_compat_keeps_socket_until_drain_completes() {
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

        let listener = Http1Listener::bind_with_config(
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
            localhost_config(Duration::from_secs(10), Duration::from_secs(20))
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

        // One request in flight keeps the drain window open.
        let client = blocking_client(addr);
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
        assert!(report.reached_quiescence, "drain reached quiescence");

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

        let response = client.join().expect("client thread");
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "the in-flight request completed during the lb_compat drain: {response:?}"
        );
    });
}
