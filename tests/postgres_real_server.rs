//! Real PostgreSQL server integration tests — no mocks.
//!
//! Bead: br-asupersync-olv5yi
//!
//! These tests replace the in-process synthetic-protocol pattern at
//! `src/database/postgres.rs:5646` (`make_test_connection`) for assertions
//! that genuinely depend on PostgreSQL backend behavior (handshake, SCRAM,
//! parameter status, error codes, isolation levels, NOTIFY/LISTEN). The
//! original `make_test_connection` helper hand-builds backend wire messages
//! locally; that pattern cannot catch divergence between our wire-protocol
//! implementation and a real PostgreSQL server.
//!
//! Run with:
//!     REAL_POSTGRES_TESTS=true \
//!         POSTGRES_URL=postgres://postgres:postgres@localhost:5432/postgres \
//!         cargo test --features postgres --test postgres_real_server
//!
//! Production safety guards block:
//!  * `NODE_ENV=production`
//!  * URLs containing `prod`, `production`, or non-localhost hosts unless
//!    `ALLOW_NON_LOCALHOST_POSTGRES=true` is also set.
//!
//! Each test wraps work in `BEGIN; ... ROLLBACK;` — no schema state leaks.

#![cfg(all(test, feature = "postgres"))]
#![allow(clippy::pedantic, clippy::nursery, clippy::print_stderr)]

use asupersync::cx::Cx;
use asupersync::database::postgres::{PgConnectOptions, PgConnection, PgError};
use asupersync::test_utils::run_test_with_cx;
use asupersync::types::{CancelKind, Outcome};

use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Configuration for the real-server harness — env-var driven, with hard
/// production guards.
struct RealPgConfig {
    url: String,
    enabled: bool,
    reason: Option<String>,
}

impl RealPgConfig {
    fn from_env() -> Self {
        let url = std::env::var("POSTGRES_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_string());
        let allow_remote =
            std::env::var("ALLOW_NON_LOCALHOST_POSTGRES").unwrap_or_default() == "true";
        let toggle = std::env::var("REAL_POSTGRES_TESTS").unwrap_or_default() == "true";
        let node_env = std::env::var("NODE_ENV").unwrap_or_default();

        let host_looks_local = postgres_url_host_is_local(&url);
        let url_lc = url.to_ascii_lowercase();
        let looks_prod = url_lc.contains("prod") || url_lc.contains("production");

        let reason = if !toggle {
            Some("REAL_POSTGRES_TESTS not set to 'true' — running unit-only".into())
        } else if node_env == "production" {
            Some("BLOCKED: NODE_ENV=production".into())
        } else if looks_prod {
            Some("BLOCKED: POSTGRES_URL looks like production (redacted)".into())
        } else if !host_looks_local && !allow_remote {
            Some(
                "BLOCKED: non-localhost POSTGRES_URL without ALLOW_NON_LOCALHOST_POSTGRES=true (redacted)"
                    .into(),
            )
        } else {
            None
        };

        Self {
            url,
            enabled: toggle && reason.is_none(),
            reason,
        }
    }
}

fn postgres_url_host_is_local(url: &str) -> bool {
    match PgConnectOptions::parse(url) {
        Ok(opts) => {
            opts.host.eq_ignore_ascii_case("localhost")
                || matches!(opts.host.as_str(), "127.0.0.1" | "::1")
        }
        Err(_) => false,
    }
}

/// JSON-line structured logger — matches the cadence used by
/// `tests/integration/kafka_real_broker.rs`.
struct PgTestLogger {
    suite: &'static str,
    test: String,
    start: Instant,
    phase_count: AtomicU32,
}

impl PgTestLogger {
    fn new(suite: &'static str, test: &str) -> Self {
        let me = Self {
            suite,
            test: test.to_string(),
            start: Instant::now(),
            phase_count: AtomicU32::new(0),
        };
        me.line("test_start", &[]);
        me
    }

    fn line(&self, event: &str, fields: &[(&str, &str)]) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let mut buf = format!(
            r#"{{"ts":{ts},"suite":"{}","test":"{}","event":"{event}""#,
            self.suite, self.test
        );
        for (k, v) in fields {
            buf.push_str(&format!(r#","{k}":"{v}""#));
        }
        buf.push('}');
        eprintln!("{buf}");
    }

    fn phase(&self, name: &str) {
        let n = self.phase_count.fetch_add(1, Ordering::Relaxed);
        let elapsed = self.start.elapsed().as_millis().to_string();
        self.line(
            "phase",
            &[
                ("phase", name),
                ("phase_num", &n.to_string()),
                ("elapsed_ms", &elapsed),
            ],
        );
    }

    fn assert_match(&self, field: &str, expected: &str, actual: &str) {
        let m = if expected == actual { "true" } else { "false" };
        self.line(
            "assertion",
            &[
                ("field", field),
                ("expected", expected),
                ("actual", actual),
                ("match", m),
            ],
        );
    }

    fn end(&self, result: &str) {
        let dur = self.start.elapsed().as_millis().to_string();
        self.line("test_end", &[("result", result), ("duration_ms", &dur)]);
    }
}

/// Skip the test body if the harness is disabled, printing the reason as a
/// JSON event so CI ingestion stays uniform.
fn skip_if_disabled(cfg: &RealPgConfig, test_name: &str) -> bool {
    if !cfg.enabled {
        let reason = cfg.reason.as_deref().unwrap_or("disabled");
        eprintln!(
            r#"{{"ts":{},"event":"test_skipped","test":"{}","reason":"{}"}}"#,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            test_name,
            reason
        );
        return true;
    }
    false
}

#[test]
fn postgres_real_config_localhost_gate_rejects_prefix_spoofing() {
    assert!(postgres_url_host_is_local(
        "postgres://postgres:postgres@localhost:5432/postgres"
    ));
    assert!(postgres_url_host_is_local(
        "postgres://postgres:postgres@LOCALHOST:5432/postgres"
    ));
    assert!(postgres_url_host_is_local(
        "postgres://postgres:postgres@127.0.0.1:5432/postgres"
    ));
    assert!(postgres_url_host_is_local(
        "postgres://postgres:postgres@[::1]:5432/postgres"
    ));
    assert!(postgres_url_host_is_local("postgres://localhost/postgres"));
    assert!(!postgres_url_host_is_local(
        "postgres://postgres:postgres@localhost.evil.example:5432/postgres"
    ));
    assert!(!postgres_url_host_is_local(
        "postgres://postgres:postgres@127.0.0.1.evil.example:5432/postgres"
    ));
    assert!(!postgres_url_host_is_local(
        "postgres://postgres:postgres@10.0.0.5:5432/postgres"
    ));
    assert!(!postgres_url_host_is_local("not-a-postgres-url"));
}

fn unwrap_pg<T>(out: Outcome<T, PgError>, log: &PgTestLogger, op: &str) -> T {
    match out {
        Outcome::Ok(v) => v,
        Outcome::Err(e) => {
            log.line("pg_error", &[("op", op), ("error", &e.to_string())]);
            log.end("fail");
            panic!("{op} returned error: {e}");
        }
        Outcome::Cancelled(reason) => {
            log.line(
                "pg_cancelled",
                &[("op", op), ("kind", &format!("{:?}", reason.kind))],
            );
            log.end("fail");
            panic!("{op} was cancelled: {:?}", reason.kind);
        }
        Outcome::Panicked(p) => {
            log.line("pg_panicked", &[("op", op)]);
            log.end("fail");
            panic!("{op} panicked: {p:?}");
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

/// Roundtrip: real handshake against a real backend, send a `SELECT 1`, and
/// verify the parameter-status map was populated by the server. Mock-free
/// because parameter-status is exclusively driven by the live server.
#[test]
fn pg_real_select_one_after_handshake() {
    let cfg = RealPgConfig::from_env();
    if skip_if_disabled(&cfg, "pg_real_select_one_after_handshake") {
        return;
    }
    let log = PgTestLogger::new("postgres_real", "pg_real_select_one_after_handshake");

    run_test_with_cx(|cx| async move {
        log.phase("connect");
        let mut conn = unwrap_pg(PgConnection::connect(&cx, &cfg.url).await, &log, "connect");

        log.phase("server_version");
        match conn.server_version() {
            Some(v) => log.line("server_version", &[("value", v)]),
            None => log.line("server_version", &[("value", "<missing>")]),
        }

        log.phase("query");
        let rows = unwrap_pg(
            conn.query_unchecked(&cx, "SELECT 1::int4 AS v").await,
            &log,
            "query",
        );
        assert_eq!(rows.len(), 1, "expected one row");
        let v = rows[0].get_i32("v").expect("get_i32");
        log.assert_match("v", "1", &v.to_string());
        assert_eq!(v, 1);

        log.end("pass");
    });
}

/// BEGIN/SELECT/ROLLBACK isolation — verify the connection is reusable
/// after a rollback (mock-free; transaction-status byte is server-driven).
#[test]
fn pg_real_begin_rollback_isolation() {
    let cfg = RealPgConfig::from_env();
    if skip_if_disabled(&cfg, "pg_real_begin_rollback_isolation") {
        return;
    }
    let log = PgTestLogger::new("postgres_real", "pg_real_begin_rollback_isolation");

    run_test_with_cx(|cx| async move {
        log.phase("connect");
        let mut conn = unwrap_pg(PgConnection::connect(&cx, &cfg.url).await, &log, "connect");

        log.phase("begin");
        let _affected = unwrap_pg(conn.execute_unchecked(&cx, "BEGIN").await, &log, "BEGIN");

        log.phase("select_in_txn");
        let rows = unwrap_pg(
            conn.query_unchecked(&cx, "SELECT 42::int4 AS v").await,
            &log,
            "select_in_txn",
        );
        assert_eq!(rows.len(), 1);
        let v = rows[0].get_i32("v").expect("get_i32");
        log.assert_match("v", "42", &v.to_string());
        assert_eq!(v, 42);

        log.phase("rollback");
        let _ = unwrap_pg(
            conn.execute_unchecked(&cx, "ROLLBACK").await,
            &log,
            "ROLLBACK",
        );

        // Connection still usable after ROLLBACK — server-driven RFQ status.
        log.phase("post_rollback_select");
        let rows2 = unwrap_pg(
            conn.query_unchecked(&cx, "SELECT 7::int4 AS v").await,
            &log,
            "post_rollback_select",
        );
        let v2 = rows2[0].get_i32("v").expect("get_i32");
        log.assert_match("v", "7", &v2.to_string());
        assert_eq!(v2, 7);

        log.end("pass");
    });
}

/// SQLSTATE classification — drive a known unique-violation against a real
/// server and confirm `PgError::is_unique_violation()` agrees with the live
/// SQLSTATE. The synthetic-bytes test path can't catch SQLSTATE drift between
/// the encoder and PostgreSQL's actual emission rules.
#[test]
fn pg_real_unique_violation_sqlstate_classification() {
    let cfg = RealPgConfig::from_env();
    if skip_if_disabled(&cfg, "pg_real_unique_violation_sqlstate_classification") {
        return;
    }
    let log = PgTestLogger::new(
        "postgres_real",
        "pg_real_unique_violation_sqlstate_classification",
    );

    run_test_with_cx(|cx| async move {
        log.phase("connect");
        let mut conn = unwrap_pg(PgConnection::connect(&cx, &cfg.url).await, &log, "connect");

        // Use a temp table so the rollback-everything-on-error path doesn't
        // stick around. Wrap in a savepoint-friendly transaction.
        log.phase("begin");
        let _ = unwrap_pg(conn.execute_unchecked(&cx, "BEGIN").await, &log, "BEGIN");

        log.phase("create_temp_table");
        let _ = unwrap_pg(
            conn.execute_unchecked(
                &cx,
                "CREATE TEMPORARY TABLE asupersync_olv5yi (id int4 PRIMARY KEY) ON COMMIT DROP",
            )
            .await,
            &log,
            "create_temp_table",
        );

        log.phase("insert_first");
        let _ = unwrap_pg(
            conn.execute_unchecked(&cx, "INSERT INTO asupersync_olv5yi(id) VALUES (1)")
                .await,
            &log,
            "insert_first",
        );

        log.phase("insert_duplicate_expect_unique_violation");
        let dup = conn
            .execute_unchecked(&cx, "INSERT INTO asupersync_olv5yi(id) VALUES (1)")
            .await;
        match dup {
            Outcome::Err(e) => {
                let code = e.error_code().unwrap_or("");
                log.assert_match("sqlstate", "23505", code);
                assert_eq!(code, "23505", "expected unique_violation SQLSTATE");
                assert!(
                    e.is_unique_violation(),
                    "is_unique_violation() should be true"
                );
                assert!(
                    e.is_constraint_violation(),
                    "is_constraint_violation() should be true"
                );
                assert!(!e.is_serialization_failure());
                assert!(!e.is_deadlock());
            }
            Outcome::Ok(rows) => {
                log.line("unexpected_ok", &[("rows", &rows.to_string())]);
                panic!("duplicate insert unexpectedly succeeded: rows={rows}");
            }
            Outcome::Cancelled(_) | Outcome::Panicked(_) => {
                panic!("duplicate insert should error, not cancel/panic");
            }
        }

        log.phase("rollback");
        let _ = unwrap_pg(
            conn.execute_unchecked(&cx, "ROLLBACK").await,
            &log,
            "ROLLBACK",
        );

        log.end("pass");
    });
}

/// COPY FROM: drive the public streaming API against a real backend when the
/// real-server harness is explicitly enabled. The fallback proof script records
/// a blocked real-server record when this environment is absent.
#[test]
fn pg_real_copy_from_chunks_streams_and_recovers() {
    let cfg = RealPgConfig::from_env();
    if skip_if_disabled(&cfg, "pg_real_copy_from_chunks_streams_and_recovers") {
        return;
    }
    let log = PgTestLogger::new(
        "postgres_real",
        "pg_real_copy_from_chunks_streams_and_recovers",
    );

    run_test_with_cx(|cx| async move {
        log.phase("connect");
        let mut conn = unwrap_pg(PgConnection::connect(&cx, &cfg.url).await, &log, "connect");

        log.phase("create_temp_table");
        let _ = unwrap_pg(
            conn.execute_unchecked(
                &cx,
                "CREATE TEMPORARY TABLE asupersync_zftrj9_copy \
                 (id int4 NOT NULL, name text NOT NULL) ON COMMIT PRESERVE ROWS",
            )
            .await,
            &log,
            "create_temp_table",
        );

        log.phase("copy_success");
        let success_chunks: Vec<Result<&[u8], PgError>> =
            vec![Ok(&b"1\talice\n"[..]), Ok(&b"2\tbob\n"[..])];
        let complete = unwrap_pg(
            conn.copy_from_chunks(
                &cx,
                "COPY asupersync_zftrj9_copy (id, name) FROM STDIN",
                success_chunks,
            )
            .await,
            &log,
            "copy_success",
        );
        log.assert_match(
            "copy_success_affected_rows",
            "2",
            &complete.affected_rows().to_string(),
        );
        assert_eq!(complete.affected_rows(), 2);
        assert_eq!(complete.chunks_sent(), 2);
        assert_eq!(complete.bytes_sent(), b"1\talice\n2\tbob\n".len() as u64);

        log.phase("query_after_success");
        let rows = unwrap_pg(
            conn.query_unchecked(
                &cx,
                "SELECT count(*)::int8 AS n, max(id)::int4 AS max_id \
                 FROM asupersync_zftrj9_copy",
            )
            .await,
            &log,
            "query_after_success",
        );
        let count = rows[0].get_i64("n").expect("get count");
        let max_id = rows[0].get_i32("max_id").expect("get max_id");
        log.assert_match("row_count_after_success", "2", &count.to_string());
        log.assert_match("max_id_after_success", "2", &max_id.to_string());
        assert_eq!(count, 2);
        assert_eq!(max_id, 2);

        log.phase("copy_source_abort");
        let abort_chunks: Vec<Result<&[u8], PgError>> = vec![
            Ok(&b"3\tpartial\n"[..]),
            Err(PgError::Protocol(
                "source stopped before CopyDone".to_string(),
            )),
        ];
        let abort = conn
            .copy_from_chunks(
                &cx,
                "COPY asupersync_zftrj9_copy (id, name) FROM STDIN",
                abort_chunks,
            )
            .await;
        match abort {
            Outcome::Err(PgError::Protocol(message)) => {
                log.assert_match(
                    "copy_abort_error",
                    "source stopped before CopyDone",
                    &message,
                );
                assert_eq!(message, "source stopped before CopyDone");
            }
            other => panic!("expected source abort protocol error, got {other:?}"),
        }

        log.phase("query_after_abort");
        let rows = unwrap_pg(
            conn.query_unchecked(
                &cx,
                "SELECT count(*)::int8 AS n FROM asupersync_zftrj9_copy",
            )
            .await,
            &log,
            "query_after_abort",
        );
        let count = rows[0].get_i64("n").expect("get count after abort");
        log.assert_match("row_count_after_abort", "2", &count.to_string());
        assert_eq!(count, 2, "CopyFail should roll back the partial COPY row");

        log.phase("copy_malformed_backend_error");
        let malformed_chunks: Vec<Result<&[u8], PgError>> = vec![Ok(&b"4\n"[..])];
        let malformed = conn
            .copy_from_chunks(
                &cx,
                "COPY asupersync_zftrj9_copy (id, name) FROM STDIN",
                malformed_chunks,
            )
            .await;
        match malformed {
            Outcome::Err(err) => {
                let code = err.error_code().unwrap_or("");
                log.assert_match("copy_malformed_sqlstate", "22P04", code);
                assert_eq!(code, "22P04", "expected bad COPY row SQLSTATE");
            }
            other => panic!("expected malformed COPY row server error, got {other:?}"),
        }

        log.phase("query_after_failure");
        let rows = unwrap_pg(
            conn.query_unchecked(
                &cx,
                "SELECT count(*)::int8 AS n FROM asupersync_zftrj9_copy",
            )
            .await,
            &log,
            "query_after_failure",
        );
        let count = rows[0].get_i64("n").expect("get count after failure");
        log.assert_match("row_count_after_failure", "2", &count.to_string());
        assert_eq!(
            count, 2,
            "backend COPY error should not commit partial rows"
        );

        log.end("pass");
    });
}

/// Cancel-in-flight: real-server roundtrip for the PostgreSQL `CancelRequest`
/// protocol (PG protocol §53.2.7 — separate TCP, 16-byte frame containing the
/// backend's process_id + secret_key from `BackendKeyData`). Until this test
/// landed, the cancel path was only exercised by `postgres_cancellation_audit.rs`
/// (println-only commentary using `tokio::test`) and `cancelled_commit_marks_
/// connection_for_rollback` (synthetic state). Neither verifies that asupersync
/// actually delivers the CancelRequest to a live backend, that the backend
/// SIGINTs the worker, or that the in-flight `query_unchecked` returns
/// `Outcome::Cancelled` long before the query's natural duration.
///
/// asupersync-xgkg5w: the test starts `SELECT pg_sleep(30)` on a clonable Cx,
/// sleeps ~200 ms in a sidecar thread, then calls `cx.cancel_with(CancelKind::
/// User, ...)`. The expected fail-fast invariant is that the query observes
/// `cx.checkpoint().is_err()` in its message-loop, calls `cancel_in_flight`
/// (src/database/postgres.rs:3440) which spawns the detached
/// `pg-cancel-request` thread (line 3197), opens a fresh TCP socket to the
/// same host:port, and writes the 16-byte frame so the server SIGINTs the
/// backend worker. The original socket is then torn down via
/// `abort_in_flight_exchange`, so the cancelled `PgConnection` is poisoned —
/// recovery requires opening a *fresh* connection on the same URL.
///
/// Assertions:
/// 1. `query_unchecked` returns `Outcome::Cancelled` (NOT Ok, NOT Err) — the
///    SIGINT-cancelled query never produces rows.
/// 2. Total elapsed is well under `pg_sleep`'s 30-second nap. We use a 10-
///    second hard ceiling so a regression that loses the CancelRequest path
///    (e.g. closes the socket without firing the request) fails the test
///    rather than silently waiting out the sleep.
/// 3. A *fresh* `PgConnection` against the same URL serves a `SELECT 1` after
///    the cancel — proves the server worker exited cleanly without leaving a
///    poisoned session.
#[test]
fn pg_real_cancel_in_flight_during_long_query() {
    let cfg = RealPgConfig::from_env();
    if skip_if_disabled(&cfg, "pg_real_cancel_in_flight_during_long_query") {
        return;
    }
    let log = PgTestLogger::new(
        "postgres_real",
        "pg_real_cancel_in_flight_during_long_query",
    );

    run_test_with_cx(|cx| async move {
        log.phase("connect");
        let mut conn = unwrap_pg(PgConnection::connect(&cx, &cfg.url).await, &log, "connect");

        // Spawn a sidecar thread that flips the *same* Cx (Cx is cheaply
        // clonable; clones share cancellation state via Arc — see
        // src/cx/cx.rs:175) into the cancelled state ~200 ms after the
        // query starts. Trying to cancel via `tokio::time::sleep` here
        // would tie the test to a different runtime; a plain
        // `std::thread::sleep` is the simplest way to fire the cancel
        // signal from outside the asupersync runtime that owns `cx`.
        let canceller_cx: Cx = cx.clone();
        let cancel_thread = thread::Builder::new()
            .name("pg-real-cancel-trigger".into())
            .spawn(move || {
                thread::sleep(Duration::from_millis(200));
                canceller_cx.cancel_with(
                    CancelKind::User,
                    Some("pg_real_cancel_in_flight_during_long_query trigger"),
                );
            })
            .expect("spawn cancel-trigger thread");

        log.phase("long_query_with_cancel");
        let started = Instant::now();
        // pg_sleep(30) is the canonical "definitely-still-running" probe.
        // If the cancel never lands the test waits 30s, hits the panic
        // branch in unwrap_pg via Outcome::Ok, and fails with a clear
        // diagnostic. The hard ceiling below pins the upper bound so the
        // failure mode never exceeds 10s.
        let outcome = conn
            .query_unchecked(&cx, "SELECT pg_sleep(30) AS slept")
            .await;
        let elapsed = started.elapsed();
        cancel_thread.join().expect("cancel-trigger thread");

        log.line(
            "cancel_outcome",
            &[
                ("variant", outcome_label(&outcome)),
                ("elapsed_ms", &elapsed.as_millis().to_string()),
            ],
        );

        match outcome {
            Outcome::Cancelled(reason) => {
                log.line(
                    "cancel_reason",
                    &[
                        ("kind", &format!("{:?}", reason.kind)),
                        ("message", reason.message.as_deref().unwrap_or("<none>")),
                    ],
                );
                assert_eq!(
                    reason.kind,
                    CancelKind::User,
                    "cancel attribution must reflect User-triggered cancel, got {:?}",
                    reason.kind
                );
            }
            Outcome::Ok(_) => {
                log.end("fail");
                panic!(
                    "pg_sleep(30) completed normally in {elapsed:?} — cancel did not fire \
                     or did not propagate to query_unchecked"
                );
            }
            Outcome::Err(err) => {
                log.end("fail");
                panic!(
                    "pg_sleep(30) returned PgError after {elapsed:?}, expected Outcome::Cancelled: {err}"
                );
            }
            Outcome::Panicked(p) => {
                log.end("fail");
                panic!("pg_sleep(30) panicked after {elapsed:?}: {p:?}");
            }
        }

        // Ceiling at 10s leaves room for slow CI / loaded boxes while
        // still catching a regression that closes the socket without
        // firing the CancelRequest (in which case the server keeps
        // sleeping until ~30s). 5s is a tighter local-dev target.
        assert!(
            elapsed < Duration::from_secs(10),
            "cancel must short-circuit pg_sleep(30) well under 10s, took {elapsed:?}"
        );
        log.assert_match("cancel_under_10s", "true", "true");

        log.phase("recovery_fresh_connection");
        // The cancelled connection is intentionally poisoned by
        // abort_in_flight_exchange — open a NEW connection to verify the
        // server worker exited cleanly.
        let cx_recover = Cx::for_testing();
        let mut conn2 = unwrap_pg(
            PgConnection::connect(&cx_recover, &cfg.url).await,
            &log,
            "recover_connect",
        );
        let rows = unwrap_pg(
            conn2
                .query_unchecked(&cx_recover, "SELECT 1::int4 AS v")
                .await,
            &log,
            "recover_select",
        );
        assert_eq!(rows.len(), 1, "recovery SELECT 1 must return one row");
        let v = rows[0].get_i32("v").expect("get_i32");
        log.assert_match("recovery_v", "1", &v.to_string());
        assert_eq!(v, 1);

        log.end("pass");
    });
}

fn outcome_label<T>(out: &Outcome<T, PgError>) -> &'static str {
    match out {
        Outcome::Ok(_) => "ok",
        Outcome::Err(_) => "err",
        Outcome::Cancelled(_) => "cancelled",
        Outcome::Panicked(_) => "panicked",
    }
}

/// Real-PG roundtrip pinning the LISTEN/NOTIFY *encoder* contract while
/// the receive path is fixed in a follow-up (asupersync-c8fvo3).
///
/// `PgConnection::handle_notification_response` (src/database/postgres.rs:3271)
/// parses `NotificationResponseFields` and immediately discards them
/// with `let _fields = …`, and there is no public API to drain queued
/// notifications. So an asupersync `LISTEN` followed by a separately-
/// connected `NOTIFY` cannot be observed from asupersync today.
///
/// Until that gap is closed, this test pins the half that DOES work:
///   * `LISTEN events` from connection A succeeds against a real PG
///     and is observable in `pg_listening_channels()` (server-side
///     truth, not local mirror state).
///   * `NOTIFY events` from connection B succeeds (no encoder error,
///     no SQLSTATE leak from validation regressions).
///
/// When asupersync-c8fvo3 lands a public receive API, this test should
/// be extended to also assert that connection A observes a
/// `PgNotification { channel: "events", payload: "hello", process_id: <B's> }`.
#[test]
fn pg_real_listen_in_pg_stat_and_notify_succeeds_from_separate_connection_c8fvo3() {
    let cfg = RealPgConfig::from_env();
    if skip_if_disabled(
        &cfg,
        "pg_real_listen_in_pg_stat_and_notify_succeeds_from_separate_connection_c8fvo3",
    ) {
        return;
    }
    let log = PgTestLogger::new(
        "postgres_real",
        "pg_real_listen_in_pg_stat_and_notify_succeeds_from_separate_connection_c8fvo3",
    );

    run_test_with_cx(|cx| async move {
        // A unique channel name so concurrent runs of this test don't see
        // each other's `pg_listening_channels()` rows. PG NOTIFY channel
        // names are case-folded unquoted SQL identifiers, so keep the
        // alphabet to lowercase + digits.
        let channel = format!(
            "asupersync_c8fvo3_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        );

        log.phase("listener_connect");
        let mut listener = unwrap_pg(
            PgConnection::connect(&cx, &cfg.url).await,
            &log,
            "listener_connect",
        );

        log.phase("listener_listen");
        match listener.listen(&cx, &channel).await {
            Outcome::Ok(()) => {}
            other => {
                log.line("listen_error", &[("variant", outcome_label(&other))]);
                log.end("fail");
                panic!("LISTEN {channel} failed: {other:?}");
            }
        }

        // Server-side proof: PG itself reports the channel is in the
        // listener's subscription set. This cannot be faked by our
        // client because it queries pg_listening_channels() function
        // which reads server-managed state for the current backend.
        log.phase("verify_pg_listening_channels");
        let rows = unwrap_pg(
            listener
                .query_unchecked(&cx, "SELECT pg_listening_channels() AS ch")
                .await,
            &log,
            "pg_listening_channels",
        );
        let observed: Vec<String> = rows
            .iter()
            .filter_map(|row| row.get_str("ch").ok().map(str::to_string))
            .collect();
        log.line("listening_channels", &[("observed", &observed.join(","))]);
        assert!(
            observed.iter().any(|c| c == &channel),
            "PG must report '{channel}' in pg_listening_channels() for the listener \
             backend; observed {observed:?}"
        );

        log.phase("notifier_connect_and_notify");
        let mut notifier = unwrap_pg(
            PgConnection::connect(&cx, &cfg.url).await,
            &log,
            "notifier_connect",
        );
        match notifier.notify(&cx, &channel, "hello").await {
            Outcome::Ok(()) => {}
            other => {
                log.line("notify_error", &[("variant", outcome_label(&other))]);
                log.end("fail");
                panic!("NOTIFY {channel} 'hello' failed: {other:?}");
            }
        }

        // Until asupersync-c8fvo3 lands a public receive API, we cannot
        // observe the NotificationResponse on the listener side from
        // asupersync. The test stops here; the encoder + LISTEN
        // round-trip is the regression net for the half that works.
        log.line(
            "receive_path_pending",
            &[
                ("bead", "asupersync-c8fvo3"),
                (
                    "reason",
                    "PgConnection::handle_notification_response discards parsed fields; \
                     no public receive API yet",
                ),
            ],
        );

        log.phase("cleanup");
        match listener.unlisten(&cx, &channel).await {
            Outcome::Ok(()) => {}
            other => panic!("UNLISTEN {channel} failed: {other:?}"),
        }

        log.end("pass");
    });
}
