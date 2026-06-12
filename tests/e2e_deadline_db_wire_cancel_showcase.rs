//! D1 showcase e2e (br-asupersync-server-stack-hardening-eeexl1.1, AC2 +
//! region→DB cancellation composition): a request region's budget reaches a
//! PostgreSQL query as a wire `SET statement_timeout` (min-plus composition),
//! and when that request budget deadline elapses mid-query the handler
//! resolves `Outcome::Cancelled` and the hop commits that completion instead
//! of wedging — proven over loopback TCP against a scripted PostgreSQL backend,
//! driven under the real asupersync runtime so the reactor pumps cooperative
//! socket parks.
//!
//! Evidence chain asserted here, in wire order:
//!   1. AC2 — the request region's budget reaches the DB hop: the fake server
//!      receives `SET statement_timeout = <ms>` with a value derived from the
//!      remaining request budget (no per-query override is configured, so the
//!      region budget installed at mint time is the only possible source).
//!   2. The request budget deadline elapses while the handler is in flight;
//!      the region cancel propagates into the DB client and the handler
//!      resolves `Outcome::Cancelled` (kind `Timeout`), which the hop commits
//!      as a clean completion. The whole chain reaches quiescence in ~one
//!      budget interval rather than wedging.
//!
//! Scope note (honesty posture, mirrors
//! `tests/remote_transport_lifecycle_contract.rs`):
//!   - The wire-level PostgreSQL `CancelRequest` *frame* — second connection,
//!     exact `BackendKeyData` identity, sent in the drain phase before the
//!     cancellation resolves — is proven deterministically by the D1.2 unit
//!     test `cancel_in_flight_sends_cancel_request_before_resolving` in
//!     `src/database/postgres.rs`.
//!   - The oracle-clean region / drain / client-disconnect behavior is proven
//!     by the D1.1 server-hop lab matrix in
//!     `src/web/request_region.rs::tests::server_hop`.
//!   - This file is the production-transport loopback half that proves the
//!     request-region budget actually reaches a real `PgConnection` on the
//!     wire and that a budget-deadline cancel resolves the handler cleanly.
//!
//! A fully-composed *live* showcase — where the in-region query reaches the
//! `SELECT`, parks, and the drain dials the `CancelRequest` over loopback in
//! one flow — is tracked by the follow-up bead noted below: today the
//! request-region-wrapped `PgConnection` parks on the read immediately
//! following the budget-derived `SET` write and is only re-woken by the
//! budget timer, so the query never advances to the `SELECT` whose drain would
//! dial the cancel. That readiness-delivery investigation is out of scope for
//! this showcase.

#![cfg(all(feature = "postgres", feature = "test-internals"))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

use asupersync::Outcome;
use asupersync::cx::Cx;
use asupersync::database::postgres::PgConnection;
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::wall_now;
use asupersync::types::Budget;
use asupersync::web::request_region::{
    RequestBudgetSource, ServerHopOutcome, ServerRequestRegion, derive_request_budget,
};

const BACKEND_PROCESS_ID: i32 = 7_777;
const BACKEND_SECRET_KEY: i32 = 424_242;
const REQUEST_BUDGET: Duration = Duration::from_secs(3);
const DRAIN_GRACE: Duration = Duration::from_secs(2);
/// Comfortably exceeds the request budget + drain grace so the scripted
/// server never times out before the client tears the connection down.
const SERVER_READ_TIMEOUT: Duration = Duration::from_secs(12);

fn backend_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + body.len());
    out.push(msg_type);
    out.extend_from_slice(&((body.len() as i32) + 4).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Reads the length-prefixed (no type byte) startup message.
fn read_startup_message(stream: &mut TcpStream) -> Vec<u8> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .expect("read startup length");
    let len = i32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len - 4];
    stream.read_exact(&mut body).expect("read startup body");
    body
}

/// Reads one typed frontend message: type byte + i32 length + body.
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

fn parse_statement_timeout_ms(query_body: &[u8]) -> u64 {
    let sql = std::str::from_utf8(query_body)
        .expect("SET statement is UTF-8")
        .trim_end_matches('\0');
    let digits: String = sql.chars().filter(char::is_ascii_digit).collect();
    digits
        .parse()
        .unwrap_or_else(|_| panic!("SET statement carries a numeric timeout: {sql:?}"))
}

/// Scripted PostgreSQL backend: connect handshake, then the budget-derived
/// SET exchange. After acknowledging the SET it leaves the connection idle;
/// the client's request budget deadline tears the connection down, which the
/// server observes as EOF.
fn fake_pg_server(listener: &TcpListener, evidence: &mpsc::Sender<u64>) {
    let (mut conn, _) = listener.accept().expect("accept primary connection");
    conn.set_read_timeout(Some(SERVER_READ_TIMEOUT))
        .expect("set primary read timeout");

    // Connect handshake: startup -> AuthenticationOk + BackendKeyData + RFQ.
    let _startup = read_startup_message(&mut conn);
    conn.write_all(&backend_message(b'R', &0i32.to_be_bytes()))
        .expect("write AuthenticationOk");
    let mut key_data = Vec::with_capacity(8);
    key_data.extend_from_slice(&BACKEND_PROCESS_ID.to_be_bytes());
    key_data.extend_from_slice(&BACKEND_SECRET_KEY.to_be_bytes());
    conn.write_all(&backend_message(b'K', &key_data))
        .expect("write BackendKeyData");
    conn.write_all(&backend_message(b'Z', b"I"))
        .expect("write connect ReadyForQuery");
    conn.flush().expect("flush connect handshake");

    // Budget-derived statement timeout (AC2): the first in-region statement
    // must be `SET statement_timeout = <ms>` because the request Cx carries a
    // deadline and no per-query override exists.
    let (msg_type, body) = read_frontend_message(&mut conn);
    assert_eq!(
        msg_type, b'Q',
        "expected simple-protocol SET, got {msg_type}"
    );
    assert!(
        body.starts_with(b"SET statement_timeout"),
        "expected budget-derived SET statement_timeout, got {:?}",
        String::from_utf8_lossy(&body)
    );
    evidence
        .send(parse_statement_timeout_ms(&body))
        .expect("report SET evidence");
    conn.write_all(&backend_message(b'C', b"SET\0"))
        .expect("write SET CommandComplete");
    conn.write_all(&backend_message(b'Z', b"I"))
        .expect("write SET ReadyForQuery");
    conn.flush().expect("flush SET exchange");

    // Leave the connection idle. The request budget deadline cancels the
    // handler and tears the connection down; the server observes EOF (or a
    // reset) rather than further protocol traffic.
    let mut probe = [0u8; 64];
    loop {
        match conn.read(&mut probe) {
            Ok(0) => break,
            // Any further bytes would be a protocol surprise for an idle
            // backend; only the teardown is expected.
            Ok(_) => break,
            Err(_) => break,
        }
    }
}

#[test]
fn region_budget_reaches_pg_statement_timeout_and_deadline_cancels_cleanly() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake server");
    let addr = listener.local_addr().expect("fake server addr");
    let (evidence_tx, evidence_rx) = mpsc::channel();

    let server = std::thread::spawn(move || {
        fake_pg_server(&listener, &evidence_tx);
    });

    // The real runtime is required, not incidental: PgConnection only parks
    // cooperatively when the asupersync reactor is pumping socket readiness.
    // Under a foreign block_on the same read path is blocking, which is why
    // the D1.2 wire-cancel unit tests invoke cancel_in_flight directly.
    let runtime = RuntimeBuilder::new()
        .worker_threads(1)
        .build()
        .expect("build asupersync runtime");

    let hop_outcome = runtime.block_on(runtime.handle().spawn(async move {
        let task_cx = Cx::current().expect("runtime task context");
        // The DB connection is established outside the request, as a pooled
        // connection would be.
        let url = format!(
            "postgres://app@127.0.0.1:{}/db?sslmode=disable",
            addr.port()
        );
        let mut conn = match PgConnection::connect(&task_cx, &url).await {
            Outcome::Ok(conn) => conn,
            other => panic!("connect against scripted backend failed: {other:?}"),
        };

        // Server hop: mint the request region with the request budget. The
        // config timeout is the only source, so the budget reaching the DB
        // client below is attributable to this install alone.
        let now = wall_now();
        let (budget, source) =
            derive_request_budget(Budget::INFINITE, now, Some(REQUEST_BUDGET), None, None);
        assert_eq!(source, RequestBudgetSource::ServerConfig);
        let region = ServerRequestRegion::mint("showcase", budget, now)
            .expect("mint request region from runtime task context");

        let handler_cx = region.cx().clone();
        region
            .run_with_protocol_drain(source, None, DRAIN_GRACE, async move {
                conn.query_unchecked(&handler_cx, "SELECT pg_sleep(600)")
                    .await
            })
            .await
    }));

    // The handler completed (within the drain grace) with the cancellation
    // outcome — the structured result of the budget-deadline chain, not a wedge.
    let handler_outcome = match hop_outcome {
        ServerHopOutcome::Ok(outcome) => outcome,
        other => panic!("expected committed handler completion, got {other:?}"),
    };
    match &handler_outcome {
        Outcome::Cancelled(reason) => {
            let rendered = format!("{reason:?}");
            assert!(
                rendered.contains("Timeout"),
                "handler must observe the budget-deadline cancel: {rendered}"
            );
            assert!(
                rendered.contains("server request budget deadline exceeded"),
                "cancellation must trace back to the request budget: {rendered}"
            );
        }
        other => panic!("expected Cancelled handler outcome, got {other:?}"),
    }

    server.join().expect("fake server script completed");

    // AC2: the statement timeout on the wire derives from the request budget:
    // bounded above by the full budget and close to it (the pre-query hops
    // consume milliseconds), bucketed by database::wire_statement_timeout_ms.
    let timeout_ms = evidence_rx
        .try_iter()
        .next()
        .expect("fake server observed the budget-derived SET");
    assert!(
        timeout_ms <= REQUEST_BUDGET.as_millis() as u64,
        "statement timeout must not exceed the request budget: {timeout_ms}ms"
    );
    assert!(
        timeout_ms >= 2_500,
        "statement timeout must derive from the ~3s remaining budget, got {timeout_ms}ms"
    );
}
