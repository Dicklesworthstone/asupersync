//! Budget-composition (meet) conformance for the `HttpClient` fluent request
//! builder — br-asupersync-server-stack-hardening-eeexl1.4, AC2:
//! "ambient 10s budget + `.timeout(30s)` -> effective 10s (meet semantics)".
//!
//! The in-module `budget_deadline` unit tests in `src/http/h1/http_client.rs`
//! drive the private `drive_with_budget_deadline` helper directly with
//! positional `(configured, per_call)` arguments, and the in-module
//! `forwarded_budget_trace_event_emitted` test only asserts that *some*
//! `client.budget_forwarded` event exists (it never checks the composed
//! value). These integration tests pin the previously-unproven half: that the
//! **public fluent surface** — `client.get(url).timeout(d).send(cx)` — composes
//! the per-call timeout, the client-configured `request_timeout`, and the
//! remaining ambient [`Cx`] budget by **meet** (the tightest bound wins), and
//! that the resulting effective deadline carries the *exact* expected value.
//!
//! The proof reads the `client.budget_forwarded proto=h1 remaining_ns=<R>
//! total_timeout_ns=<E>` user-trace event the client emits once per exchange
//! (`http_client.rs:224`) and asserts the relationship between `R` (the ambient
//! remaining) and `E` (the effective, meet-composed deadline). A loopback TCP
//! fixture answers `200 OK` so the happy path is exercised end-to-end; the
//! trace fires before the request future is awaited, so the composed value is
//! observed regardless of how fast the exchange completes.
//!
//! Clock alignment: the budget baseline is taken with [`wall_now`] *inside* the
//! runtime closure, so it resolves through the same `Cx::current()` timer-driver
//! path that `drive_with_budget_deadline` uses for its own `now`. The two
//! readings therefore share one monotonic timeline (the driver's, or the global
//! wall epoch when no driver is installed), and the driver reading always
//! follows the baseline, so the observed remaining is `<= 10s` by construction.
//!
//! Runs as a standalone integration crate (mirrors
//! `tests/http_client_fluent_request_wire_conformance.rs`) so the proof lane is
//! reliable. Requires `--features test-internals` for the test-only `Cx`
//! constructors and `set_trace_buffer`.

use asupersync::Cx;
use asupersync::http::h1::{ClientError, HttpClient};
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::wall_now;
use asupersync::trace::{TraceBufferHandle, TraceData, TraceEventKind};
use asupersync::types::Budget;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Drive an async body on a lightweight current-thread runtime (matches the
/// in-module `budget_deadline` tests' `runtime_block_on`).
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    RuntimeBuilder::current_thread()
        .build()
        .expect("build current-thread runtime")
        .block_on(fut)
}

/// Accept one connection from a non-blocking listener, polling until `timeout`.
fn accept_with_timeout(listener: &TcpListener, timeout: Duration) -> std::io::Result<TcpStream> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((conn, _peer)) => return Ok(conn),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() > deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "accept timed out",
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) => return Err(err),
        }
    }
}

/// Spawn a fixture that serves exactly one request with `200 OK`. It drains the
/// request head (up to `\r\n\r\n`) so the client's write completes cleanly,
/// then responds and closes.
fn spawn_ok_server() -> (SocketAddr, thread::JoinHandle<std::io::Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking listener");
    let addr = listener.local_addr().expect("listener local_addr");

    let handle = thread::spawn(move || -> std::io::Result<()> {
        let mut conn = accept_with_timeout(&listener, IO_TIMEOUT)?;
        conn.set_nonblocking(false)?;
        conn.set_read_timeout(Some(IO_TIMEOUT))?;
        conn.set_write_timeout(Some(IO_TIMEOUT))?;

        let mut scratch = [0u8; 1024];
        let mut acc = Vec::new();
        loop {
            match conn.read(&mut scratch) {
                Ok(0) => break,
                Ok(n) => {
                    acc.extend_from_slice(&scratch[..n]);
                    if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(err) => return Err(err),
            }
        }

        conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")?;
        conn.flush()?;
        Ok(())
    });

    (addr, handle)
}

/// Return the single `client.budget_forwarded proto=h1 ...` user-trace message
/// captured in `trace`, asserting there is exactly one.
fn single_budget_forwarded(trace: &TraceBufferHandle) -> String {
    let messages: Vec<String> = trace
        .snapshot()
        .into_iter()
        .filter(|event| event.kind == TraceEventKind::UserTrace)
        .filter_map(|event| match event.data {
            TraceData::Message(msg) if msg.starts_with("client.budget_forwarded proto=h1 ") => {
                Some(msg)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        messages.len(),
        1,
        "expected exactly one client.budget_forwarded event, got {messages:?}"
    );
    messages.into_iter().next().expect("length checked to be 1")
}

/// Parse `(remaining_ns, total_timeout_ns)` from a `client.budget_forwarded`
/// message. `remaining_ns` is `None` when the source printed the literal
/// `none` (an unbounded ambient budget).
fn parse_forwarded(msg: &str) -> (Option<u128>, u128) {
    let mut remaining: Option<u128> = None;
    let mut total: Option<u128> = None;
    for token in msg.split_whitespace() {
        if let Some(value) = token.strip_prefix("remaining_ns=") {
            remaining = if value == "none" {
                None
            } else {
                Some(value.parse().expect("remaining_ns must be a u128"))
            };
        } else if let Some(value) = token.strip_prefix("total_timeout_ns=") {
            total = Some(value.parse().expect("total_timeout_ns must be a u128"));
        }
    }
    (
        remaining,
        total.expect("total_timeout_ns must be present in the message"),
    )
}

/// HEADLINE (AC2): an ambient 10s budget meet-composed with a longer per-call
/// `.timeout(30s)` yields an effective deadline of the *ambient* 10s — the
/// tighter bound wins, and the per-call override cannot extend it.
#[test]
fn ambient_budget_meet_caps_longer_per_call_timeout() {
    let (addr, server) = spawn_ok_server();
    let trace = TraceBufferHandle::new(64);
    let trace_handle = trace.clone();

    block_on(async move {
        let now = wall_now();
        let budget = Budget::INFINITE.tightened_by_timeout(now, Duration::from_secs(10));
        let cx = Cx::for_testing_with_budget(budget);
        cx.set_trace_buffer(trace_handle);
        // Default client: no configured request_timeout, so the meet is
        // strictly ambient(10s) vs per-call(30s).
        let client = HttpClient::new();
        let resp = client
            .get(format!("http://{addr}/"))
            .timeout(Duration::from_secs(30))
            .send(&cx)
            .await
            .expect("loopback GET should succeed");
        assert_eq!(resp.status, 200);
    });
    server
        .join()
        .expect("server thread panicked")
        .expect("server io error");

    let msg = single_budget_forwarded(&trace);
    let (remaining, total) = parse_forwarded(&msg);
    let remaining = remaining.expect("a 10s ambient budget must print remaining_ns, not `none`");

    // Meet picked the ambient remaining, NOT the 30s per-call override.
    assert_eq!(
        total, remaining,
        "effective deadline must equal the (tighter) ambient remaining: `{msg}`"
    );
    assert!(
        total < Duration::from_secs(30).as_nanos(),
        "the 30s per-call override must NOT win the meet: `{msg}`"
    );
    // It is the ~10s ambient bound: never above 10s (the driver reading follows
    // the baseline on one monotonic timeline), and clearly closer to 10s than 0.
    assert!(
        total <= Duration::from_secs(10).as_nanos(),
        "effective must not exceed the 10s ambient budget: `{msg}`"
    );
    assert!(
        total > Duration::from_secs(5).as_nanos(),
        "effective must reflect the ~10s ambient budget, not a degenerate value: `{msg}`"
    );
}

/// When the ambient budget is unbounded, the per-call `.timeout()` is the only
/// bound, so it becomes the effective deadline verbatim (`remaining_ns=none`).
#[test]
fn per_call_timeout_wins_when_ambient_unbounded() {
    let (addr, server) = spawn_ok_server();
    let trace = TraceBufferHandle::new(64);
    let trace_handle = trace.clone();

    block_on(async move {
        // for_testing => Budget::INFINITE (no deadline).
        let cx = Cx::for_testing();
        cx.set_trace_buffer(trace_handle);
        let client = HttpClient::new();
        let resp = client
            .get(format!("http://{addr}/"))
            .timeout(Duration::from_secs(2))
            .send(&cx)
            .await
            .expect("loopback GET should succeed");
        assert_eq!(resp.status, 200);
    });
    server
        .join()
        .expect("server thread panicked")
        .expect("server io error");

    let msg = single_budget_forwarded(&trace);
    let (remaining, total) = parse_forwarded(&msg);
    assert!(
        remaining.is_none(),
        "an unbounded ambient budget must print remaining_ns=none: `{msg}`"
    );
    assert_eq!(
        total,
        Duration::from_secs(2).as_nanos(),
        "with no ambient/config bound, the 2s per-call timeout is the effective deadline: `{msg}`"
    );
}

/// The three-way meet includes the client-configured `request_timeout`: with
/// ambient 10s, configured 5s, and per-call 30s, the configured 5s — the
/// tightest — is the effective deadline.
#[test]
fn configured_request_timeout_meets_in_as_tightest() {
    let (addr, server) = spawn_ok_server();
    let trace = TraceBufferHandle::new(64);
    let trace_handle = trace.clone();

    block_on(async move {
        let now = wall_now();
        let budget = Budget::INFINITE.tightened_by_timeout(now, Duration::from_secs(10));
        let cx = Cx::for_testing_with_budget(budget);
        cx.set_trace_buffer(trace_handle);
        let client = HttpClient::builder()
            .request_timeout(Duration::from_secs(5))
            .build();
        let resp = client
            .get(format!("http://{addr}/"))
            .timeout(Duration::from_secs(30))
            .send(&cx)
            .await
            .expect("loopback GET should succeed");
        assert_eq!(resp.status, 200);
    });
    server
        .join()
        .expect("server thread panicked")
        .expect("server io error");

    let msg = single_budget_forwarded(&trace);
    let (remaining, total) = parse_forwarded(&msg);
    let remaining = remaining.expect("a 10s ambient budget must print remaining_ns, not `none`");

    assert_eq!(
        total,
        Duration::from_secs(5).as_nanos(),
        "the configured 5s request_timeout must win the three-way meet: `{msg}`"
    );
    assert!(
        total < remaining,
        "configured 5s must be tighter than the ~10s ambient remaining: `{msg}`"
    );
    assert!(
        total < Duration::from_secs(30).as_nanos(),
        "configured 5s must be tighter than the 30s per-call override: `{msg}`"
    );
}

/// Security/fail-closed: an already-expired ambient budget cannot be resurrected
/// by a long per-call `.timeout()`. The exchange fails fast through the public
/// fluent surface with a budget fail-closed outcome — either
/// [`ClientError::Cancelled`] (the budget checkpoint in `check_cx` trips first,
/// since `Cx::checkpoint()` rejects an exhausted budget) or
/// [`ClientError::DeadlineExceeded`] (the meet computes a zero effective
/// deadline). Both prove the 300s per-call override never wins; what it must
/// never do is succeed or run for ~300s.
#[test]
fn expired_ambient_budget_overrides_long_per_call_timeout() {
    let started = Instant::now();
    let result = block_on(async move {
        let now = wall_now();
        // Zero remaining: deadline == now, so by the time the budget is
        // checkpointed / the driver re-reads `now`, nothing is left.
        let budget = Budget::INFINITE.tightened_by_timeout(now, Duration::ZERO);
        let cx = Cx::for_testing_with_budget(budget);
        let client = HttpClient::new();
        client
            .get("http://127.0.0.1:1/")
            .timeout(Duration::from_secs(300))
            .send(&cx)
            .await
    });

    assert!(
        matches!(
            result,
            Err(ClientError::Cancelled | ClientError::DeadlineExceeded)
        ),
        "an expired ambient budget must fail closed (cancelled/deadline) regardless of a 300s per-call timeout; got {result:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "must fail fast, not attempt the 300s exchange"
    );
}
