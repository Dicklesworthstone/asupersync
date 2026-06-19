//! Regression guards for br-asupersync-rr849p: `timeout()`-wrapped socket
//! reads must complete when data arrives instead of stalling to the timeout
//! deadline.
//!
//! Two tests, both under the real asupersync runtime:
//!   - `rr849p_minimal_tcp_timeout_read_diag`: PG-free minimal guard — a raw
//!     `TcpStream` read with and without a bare `timeout()` wrapper, plus an
//!     io/timer monitor timeline for diagnosability.
//!   - `localize_request_cx_read_after_write`: the canonical PostgreSQL
//!     reproduction — a `timeout()`-wrapped `query_unchecked` (CONTROL) and a
//!     request-region-wrapped query with an INFINITE budget (REGION) against
//!     scripted PG backends.
//!
//! Historical root cause (fixed in src/runtime/scheduler/three_lane.rs):
//! before the br-asupersync-1ajbtl default-reactor flip, default-built
//! runtimes had no I/O reactor, so reads re-polled through ~1ms
//! `fallback_rewake` wheel timers. Workers only pump the timer wheel in
//! `next_task()`; a worker stuck in the inner backoff loop never fired due
//! wheel timers, and the block_on thread could park all the way to the far
//! `timeout()` Sleep deadline — stranding the due re-poll timer and stalling
//! the read for the full timeout.

#![cfg(all(feature = "postgres", feature = "test-internals"))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use asupersync::Outcome;
use asupersync::cx::Cx;
use asupersync::database::postgres::PgConnection;
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::wall_now;
use asupersync::types::Budget;
use asupersync::web::request_region::{
    ServerHopOutcome, ServerRequestRegion, derive_request_budget,
};

const SERVER_READ_TIMEOUT: Duration = Duration::from_secs(12);

fn backend_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + body.len());
    out.push(msg_type);
    let body_len = i32::try_from(body.len()).expect("backend message body fits i32");
    out.extend_from_slice(&(body_len + 4).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn read_startup_message(stream: &mut TcpStream) {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .expect("read startup length");
    let len = i32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len - 4];
    stream.read_exact(&mut body).expect("read startup body");
}

fn read_frontend_message(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut type_buf = [0u8; 1];
    stream
        .read_exact(&mut type_buf)
        .expect("read frontend message type");
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .expect("read frontend message length");
    let len = i32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len - 4];
    stream
        .read_exact(&mut body)
        .expect("read frontend message body");
    (type_buf[0], body)
}

fn write_handshake(conn: &mut TcpStream) {
    read_startup_message(conn);
    conn.write_all(&backend_message(b'R', &0i32.to_be_bytes()))
        .expect("write AuthenticationOk");
    let mut key_data = Vec::with_capacity(8);
    key_data.extend_from_slice(&7_777i32.to_be_bytes());
    key_data.extend_from_slice(&424_242i32.to_be_bytes());
    conn.write_all(&backend_message(b'K', &key_data))
        .expect("write BackendKeyData");
    conn.write_all(&backend_message(b'Z', b"I"))
        .expect("write connect ReadyForQuery");
    conn.flush().expect("flush handshake");
}

/// Answers a single-column `SELECT 1` text result: RowDescription + DataRow +
/// CommandComplete + ReadyForQuery.
fn answer_select_one(conn: &mut TcpStream) {
    let mut row_desc = Vec::new();
    row_desc.extend_from_slice(&1i16.to_be_bytes()); // field count
    row_desc.extend_from_slice(b"n\0"); // column name
    row_desc.extend_from_slice(&0u32.to_be_bytes()); // table_oid
    row_desc.extend_from_slice(&0i16.to_be_bytes()); // column attr
    row_desc.extend_from_slice(&23u32.to_be_bytes()); // type_oid INT4
    row_desc.extend_from_slice(&4i16.to_be_bytes()); // type_size
    row_desc.extend_from_slice(&(-1i32).to_be_bytes()); // type_modifier
    row_desc.extend_from_slice(&0i16.to_be_bytes()); // format_code text
    conn.write_all(&backend_message(b'T', &row_desc))
        .expect("write RowDescription");

    let mut data_row = Vec::new();
    data_row.extend_from_slice(&1i16.to_be_bytes()); // field count
    data_row.extend_from_slice(&1i32.to_be_bytes()); // value length
    data_row.push(b'1'); // value "1"
    conn.write_all(&backend_message(b'D', &data_row))
        .expect("write DataRow");

    conn.write_all(&backend_message(b'C', b"SELECT 1\0"))
        .expect("write CommandComplete");
    conn.write_all(&backend_message(b'Z', b"I"))
        .expect("write ReadyForQuery");
    conn.flush().expect("flush SELECT answer");
}

/// Control backend: handshake then answer exactly one query (the plain
/// SELECT), no SET expected (the task_cx budget is infinite).
fn control_server(listener: &TcpListener) {
    let (mut conn, _) = listener.accept().expect("accept control connection");
    conn.set_read_timeout(Some(SERVER_READ_TIMEOUT))
        .expect("set control read timeout");
    write_handshake(&mut conn);
    let (msg_type, body) = read_frontend_message(&mut conn);
    assert_eq!(msg_type, b'Q', "control expects a simple query");
    assert!(
        body.starts_with(b"SELECT"),
        "control expects SELECT, got {:?}",
        String::from_utf8_lossy(&body)
    );
    answer_select_one(&mut conn);
    let mut probe = [0u8; 64];
    let _ = conn.read(&mut probe);
}

/// Region backend: handshake, answer the budget-derived SET, then answer the
/// SELECT. Both responses are written promptly, so a correctly reading client
/// returns rows quickly.
fn region_server(listener: &TcpListener) {
    let (mut conn, _) = listener.accept().expect("accept region connection");
    conn.set_read_timeout(Some(SERVER_READ_TIMEOUT))
        .expect("set region read timeout");
    write_handshake(&mut conn);

    // Tolerate either ordering: with a finite request budget the first message
    // is the budget-derived SET (then the SELECT); with an INFINITE budget no
    // SET is sent and the SELECT arrives first. Answer whatever arrives so the
    // localization can observe whether the client reads each response.
    let (msg_type, body) = read_frontend_message(&mut conn);
    assert_eq!(msg_type, b'Q', "region expects a simple query");
    if body.starts_with(b"SET statement_timeout") {
        conn.write_all(&backend_message(b'C', b"SET\0"))
            .expect("write SET CommandComplete");
        conn.write_all(&backend_message(b'Z', b"I"))
            .expect("write SET ReadyForQuery");
        conn.flush().expect("flush SET answer");

        // If the client reads the SET response it sends the SELECT next; if it
        // parks on the SET response, this read times out (the localization
        // signal under a finite budget).
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            read_frontend_message(&mut conn)
        })) {
            Ok((t, b)) => {
                assert_eq!(t, b'Q', "region expects SELECT after SET");
                assert!(
                    b.starts_with(b"SELECT"),
                    "region expects SELECT, got {:?}",
                    String::from_utf8_lossy(&b)
                );
                answer_select_one(&mut conn);
            }
            Err(_) => {
                eprintln!("RR849P region server: client never sent SELECT after SET (parked)");
            }
        }
    } else {
        assert!(
            body.starts_with(b"SELECT"),
            "region expects SET or SELECT first, got {:?}",
            String::from_utf8_lossy(&body)
        );
        answer_select_one(&mut conn);
    }
    let mut probe = [0u8; 64];
    let _ = conn.read(&mut probe);
}

/// Minimal PG-free regression guard for br-asupersync-rr849p: a bare
/// `timeout()` wrapped around a `TcpStream` read must complete when data
/// arrives, not stall to the timeout deadline. Phase A (control) performs the
/// identical read WITHOUT the timeout wrapper; phase B wraps it in
/// `timeout(4s)`.
///
/// Root cause this guards against: before the br-asupersync-1ajbtl
/// default-reactor flip, default-built runtimes had no I/O reactor, so reads
/// re-polled through ~1ms `fallback_rewake` wheel timers. Workers only pump
/// the timer wheel in `next_task()`; before the rr849p fix, a worker in the
/// inner backoff loop never processed due wheel timers, and the block_on
/// thread could park all the way to the far `timeout()` Sleep deadline —
/// stranding the due 1ms re-poll timer (`timer_next_ms=Some(0)` frozen) and
/// stalling the read for the full timeout.
///
/// The `[RR849P-DIAG ...]` monitor timeline prints io stats (when a reactor
/// exists) and the timer wheel's next-deadline/pending view to keep the
/// failure mode diagnosable if it regresses.
#[test]
fn rr849p_minimal_tcp_timeout_read_diag() {
    use asupersync::io::{AsyncRead, ReadBuf};
    use asupersync::net::TcpStream as AsupTcpStream;
    use std::pin::Pin;
    use std::sync::mpsc;
    use std::task::Poll;

    const SERVER_WRITE_DELAY: Duration = Duration::from_millis(500);
    const READ_TIMEOUT: Duration = Duration::from_secs(4);

    fn spawn_server(listener: TcpListener, tag: &'static str) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            std::thread::sleep(SERVER_WRITE_DELAY);
            conn.write_all(b"RR849P!!").expect("write payload");
            conn.flush().expect("flush payload");
            eprintln!("[RR849P-DIAG server {tag}] payload written");
            // Hold the socket open so the client read window is bounded only
            // by the client, never by EOF. The healthy read completes within
            // milliseconds of the write; 2s comfortably outlives it without
            // dragging the test out.
            std::thread::sleep(Duration::from_secs(2));
        })
    }

    async fn read_some(stream: &mut AsupTcpStream, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut read_buf = ReadBuf::new(buf);
        std::future::poll_fn(|task_cx| {
            match Pin::new(&mut *stream).poll_read(task_cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }

    let control_listener = TcpListener::bind("127.0.0.1:0").expect("bind control");
    let control_addr = control_listener.local_addr().expect("control addr");
    let timeout_listener = TcpListener::bind("127.0.0.1:0").expect("bind timeout");
    let timeout_addr = timeout_listener.local_addr().expect("timeout addr");
    let control_thread = spawn_server(control_listener, "control");
    let timeout_thread = spawn_server(timeout_listener, "timeout");

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");

    // Monitor thread: samples io + timer driver state on a 50ms cadence for
    // the whole test, printing only on change so the timeline stays readable.
    // The io handle is optional because explicitly reactorless builds and
    // platforms without a native backend still use the timer fallback regime;
    // default-built non-wasm runtimes should normally expose it
    // (br-asupersync-1ajbtl).
    #[allow(clippy::type_complexity)]
    let (handle_tx, handle_rx) = mpsc::channel::<(
        Option<asupersync::runtime::IoDriverHandle>,
        Option<asupersync::time::TimerDriverHandle>,
    )>();
    let monitor_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let monitor_done_flag = std::sync::Arc::clone(&monitor_done);
    let monitor = std::thread::spawn(move || {
        let Ok((io, timer)) = handle_rx.recv() else {
            return;
        };
        let start = std::time::Instant::now();
        let mut last = String::new();
        while start.elapsed() < Duration::from_secs(12)
            && !monitor_done_flag.load(std::sync::atomic::Ordering::Acquire)
        {
            let io_part = io.as_ref().map_or_else(
                || "io=none".to_string(),
                |io| {
                    let s = io.stats();
                    format!(
                        "polls={} events={} wakers={} unknown={} regs={} deregs={} waker_count={}",
                        s.polls,
                        s.events_received,
                        s.wakers_dispatched,
                        s.unknown_tokens,
                        s.registrations,
                        s.deregistrations,
                        io.waker_count(),
                    )
                },
            );
            let timer_part = timer.as_ref().map_or_else(
                || "timer=none".to_string(),
                |t| {
                    let next_ms = t
                        .next_deadline()
                        .map(|d| d.as_nanos().saturating_sub(t.now().as_nanos()) / 1_000_000);
                    format!(
                        "timer_next_ms={next_ms:?} timer_pending={}",
                        t.pending_count()
                    )
                },
            );
            let line = format!("{io_part} {timer_part}");
            if line != last {
                eprintln!(
                    "[RR849P-DIAG monitor +{:>5}ms] {line}",
                    start.elapsed().as_millis()
                );
                last = line;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    let join_handle = runtime.handle().spawn(async move {
        let task_cx = Cx::current().expect("runtime task context");
        eprintln!(
            "[RR849P-DIAG task] task cx io_driver={} timer_driver={}",
            task_cx.io_driver_handle().is_some(),
            task_cx.timer_driver().is_some()
        );

        // Phase A: identical read, no timeout wrapper.
        let mut control_stream = AsupTcpStream::connect(control_addr)
            .await
            .expect("connect control");
        eprintln!("[RR849P-DIAG task] phase A (no timeout) read starting");
        let phase_a_start = std::time::Instant::now();
        let mut buf_a = [0u8; 8];
        let control_n = read_some(&mut control_stream, &mut buf_a)
            .await
            .expect("control read");
        let control_ms = phase_a_start.elapsed().as_millis();
        eprintln!("[RR849P-DIAG task] phase A read done n={control_n} in {control_ms}ms");

        // Phase B: same read wrapped in a bare timeout().
        let mut timeout_stream = AsupTcpStream::connect(timeout_addr)
            .await
            .expect("connect timeout");
        eprintln!("[RR849P-DIAG task] phase B (timeout-wrapped) read starting");
        let phase_b_start = std::time::Instant::now();
        let mut buf_b = [0u8; 8];
        let timeout_result = asupersync::time::timeout(
            task_cx.now(),
            READ_TIMEOUT,
            read_some(&mut timeout_stream, &mut buf_b),
        )
        .await;
        let timeout_ms = phase_b_start.elapsed().as_millis();
        eprintln!(
            "[RR849P-DIAG task] phase B read done result={timeout_result:?} in {timeout_ms}ms"
        );

        (control_n, control_ms, timeout_result, timeout_ms)
    });

    let (control_n, control_ms, timeout_result, timeout_ms) = runtime.block_on(async move {
        let ambient_cx = Cx::current().expect("block_on ambient cx");
        eprintln!(
            "[RR849P-DIAG main] ambient cx io_driver={} timer_driver={}",
            ambient_cx.io_driver_handle().is_some(),
            ambient_cx.timer_driver().is_some()
        );
        let _ = handle_tx.send((ambient_cx.io_driver_handle(), ambient_cx.timer_driver()));
        join_handle.await
    });

    control_thread.join().expect("control server thread");
    timeout_thread.join().expect("timeout server thread");
    monitor_done.store(true, std::sync::atomic::Ordering::Release);
    monitor.join().expect("monitor thread");

    assert_eq!(control_n, 8, "phase A control read returns the payload");
    assert!(
        control_ms < 2_000,
        "phase A control read should complete near the 500ms server delay, took {control_ms}ms"
    );
    match timeout_result {
        Ok(Ok(n)) => {
            assert_eq!(n, 8, "phase B timeout-wrapped read returns the payload");
            assert!(
                timeout_ms < 2_000,
                "phase B timeout-wrapped read should complete near the 500ms server delay, \
                 took {timeout_ms}ms (rr849p stall)"
            );
        }
        Ok(Err(err)) => panic!("phase B timeout-wrapped read io error: {err:?}"),
        Err(elapsed) => panic!(
            "RR849P DIAG: timeout-wrapped reactor read stalled to the deadline \
             ({timeout_ms}ms): {elapsed:?}"
        ),
    }
}

// Canonical reproduction for br-asupersync-rr849p, now serving as the
// regression guard: a `timeout()`-wrapped PostgreSQL read must complete when
// the server answers (CONTROL phase), and a request-region-wrapped query with
// an INFINITE budget must round-trip (REGION phase). Before the fix the
// CONTROL phase stalled to the full timeout deadline because workers in the
// inner backoff loop never pumped due wheel timers while the block_on thread
// parked to the far Sleep deadline (see the scheduler backoff break in
// src/runtime/scheduler/three_lane.rs and the diag companion test above).
#[test]
fn localize_request_cx_read_after_write() {
    let control_listener = TcpListener::bind("127.0.0.1:0").expect("bind control");
    let control_addr = control_listener.local_addr().expect("control addr");
    let region_listener = TcpListener::bind("127.0.0.1:0").expect("bind region");
    let region_addr = region_listener.local_addr().expect("region addr");

    let control_thread = std::thread::spawn(move || control_server(&control_listener));
    let region_thread = std::thread::spawn(move || region_server(&region_listener));

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");

    let (control_rows, region_outcome) = runtime.block_on(runtime.handle().spawn(async move {
        let task_cx = Cx::current().expect("runtime task context");

        // CONTROL: plain query under task_cx.
        let control_url = format!(
            "postgres://app@127.0.0.1:{}/db?sslmode=disable",
            control_addr.port()
        );
        let mut control_conn = match PgConnection::connect(&task_cx, &control_url).await {
            Outcome::Ok(conn) => conn,
            other => panic!("control connect failed: {other:?}"),
        };
        // CANONICAL MINIMAL REPRO (br-asupersync-rr849p): wrap the plain read
        // in a bare `timeout()` — no request region, no AmbientCxScope. The
        // server answers promptly, so a correct timeout-wrapped reactor read
        // returns Ok(rows) in ms; if the timeout wrapper stalls reactor wakes,
        // this resolves Err(Elapsed) at ~4s.
        let control_timeout = asupersync::time::timeout(
            task_cx.now(),
            Duration::from_secs(4),
            control_conn.query_unchecked(&task_cx, "SELECT 1"),
        )
        .await;
        let control_rows = match control_timeout {
            Ok(rows) => rows,
            Err(_elapsed) => panic!(
                "RR849P CANONICAL REPRO: a bare timeout()-wrapped reactor read \
                 stalled until the deadline even though the server answered \
                 promptly — the timeout wrapper, not the request region, breaks \
                 reactor-driven reads"
            ),
        };

        // REGION: same query inside run_with_protocol_drain with a finite
        // budget (server answers both the SET and the SELECT).
        let region_url = format!(
            "postgres://app@127.0.0.1:{}/db?sslmode=disable",
            region_addr.port()
        );
        let mut region_conn = match PgConnection::connect(&task_cx, &region_url).await {
            Outcome::Ok(conn) => conn,
            other => panic!("region connect failed: {other:?}"),
        };
        // ISOLATION (br-asupersync-rr849p): use an INFINITE budget so
        // run_with_protocol_drain takes the no-deadline `primary.await` path
        // (no timeout_at wrapper). A watchdog connection-cancel bounds the
        // test: if the region read works, the query returns rows in ms before
        // the watchdog fires; if it parks, the watchdog cancels at 5s. This
        // isolates whether the read stall is caused by the timeout_at
        // budget-deadline wrapper or by the AmbientCxScope / request-cx path.
        let now = wall_now();
        let (budget, source) = derive_request_budget(Budget::INFINITE, now, None, None, None);
        let region = ServerRequestRegion::mint("rr849p", budget, now).expect("mint request region");
        let region_cx = region.cx().clone();
        let watchdog = Cx::for_testing();
        let watchdog_fire = watchdog.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(5));
            watchdog_fire.cancel_with(
                asupersync::CancelKind::User,
                Some("rr849p watchdog: region read did not complete"),
            );
        });
        let region_outcome = region
            .run_with_protocol_drain(source, Some(watchdog), Duration::from_secs(2), async move {
                region_conn.query_unchecked(&region_cx, "SELECT 1").await
            })
            .await;

        (control_rows, region_outcome)
    }));

    control_thread.join().expect("control server thread");
    region_thread.join().expect("region server thread");

    // CONTROL must succeed: proves runtime + query method + reads work.
    let control_count = match control_rows {
        Outcome::Ok(rows) => rows.len(),
        other => panic!("CONTROL query under task_cx failed: {other:?}"),
    };
    assert_eq!(control_count, 1, "control SELECT 1 returns one row");

    // REGION result is the localization signal. We assert the control/region
    // split explicitly so the failure message records which path broke.
    match region_outcome {
        ServerHopOutcome::Ok(Outcome::Ok(rows)) => {
            assert_eq!(rows.len(), 1, "region SELECT 1 returns one row");
            // Region-wrapped reads work WITHOUT timeout_at: the stall is the
            // budget-deadline timeout_at wrapper, not the AmbientCxScope /
            // request-cx path.
            eprintln!(
                "RR849P ISOLATION: region read OK with INFINITE budget (no timeout_at) — stall is timeout_at-specific"
            );
        }
        ServerHopOutcome::Ok(Outcome::Cancelled(_))
        | ServerHopOutcome::ConnectionLost
        | ServerHopOutcome::Cancelled => {
            panic!(
                "RR849P ISOLATION: region read STILL parked with INFINITE budget \
                 (no timeout_at, watchdog-bounded) — stall is in the \
                 AmbientCxScope / request-cx read path, not timeout_at"
            );
        }
        other => panic!("unexpected region outcome: {other:?}"),
    }
}
