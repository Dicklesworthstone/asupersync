//! Localization repro for br-asupersync-rr849p: does a request-region-wrapped
//! PgConnection fail to read responses that are already available on the wire?
//!
//! Two phases against scripted PostgreSQL backends, both under the real
//! asupersync runtime:
//!   - CONTROL: `query_unchecked(&task_cx, "SELECT 1")` directly (no request
//!     region). The server answers immediately. Proves the runtime + the
//!     query method + reactor-driven reads work under `task_cx`.
//!   - REGION: the same query inside `ServerRequestRegion::run_with_protocol_drain`
//!     with a finite budget. The server answers BOTH the budget-derived
//!     `SET statement_timeout` and the `SELECT`. If region-wrapped reads work,
//!     the handler returns rows in milliseconds; if it parks on the
//!     SET-response read even though the response is already buffered, the
//!     budget deadline fires (~budget) and the handler resolves Cancelled.
//!
//! A CONTROL=Ok + REGION=Cancelled split localizes the defect to the request
//! cx / AmbientCxScope read path inside run_with_protocol_drain, rather than a
//! general runtime+PG read problem.

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

const REGION_BUDGET: Duration = Duration::from_secs(4);
const SERVER_READ_TIMEOUT: Duration = Duration::from_secs(12);

fn backend_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + body.len());
    out.push(msg_type);
    out.extend_from_slice(&((body.len() as i32) + 4).to_be_bytes());
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

// IGNORED: this is the runnable canonical reproduction for br-asupersync-rr849p
// (a `timeout()`-wrapped reactor-driven socket read stalls until the deadline
// instead of completing when data arrives). It is expected to FAIL on the
// canonical phase until rr849p is fixed; un-ignore it once the timer+reactor
// interaction is corrected so it becomes the regression guard. Run with
// `cargo test -p asupersync --test rr849p_request_cx_read_localization
//  --features postgres,test-internals -- --ignored --nocapture`.
#[ignore = "reproduces br-asupersync-rr849p (timeout-wrapped reactor read stalls); un-ignore when fixed"]
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
