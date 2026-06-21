//! Request-aware graceful drain e2e for the HTTP/1.1 listener
//! (br-asupersync-server-stack-hardening-eeexl1.2, D2.2b).
//!
//! Two scenarios against a real `Http1Listener` on a multi-thread runtime:
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

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
use asupersync::http::h1::server::{HostPolicy, Http1Config};
use asupersync::http::h1::types::Response;
use asupersync::runtime::RuntimeBuilder;
use asupersync::server::shutdown::ShutdownPhase;
use asupersync::sync::Notify;

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
