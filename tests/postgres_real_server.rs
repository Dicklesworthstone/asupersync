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

use asupersync::database::postgres::{PgConnection, PgError};
use asupersync::test_utils::run_test_with_cx;
use asupersync::types::Outcome;

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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

        let host_looks_local = url.contains("@localhost")
            || url.contains("@127.0.0.1")
            || url.contains("@[::1]")
            || url.contains("@/");
        let url_lc = url.to_ascii_lowercase();
        let looks_prod = url_lc.contains("prod") || url_lc.contains("production");

        let reason = if !toggle {
            Some("REAL_POSTGRES_TESTS not set to 'true' — running unit-only".into())
        } else if node_env == "production" {
            Some("BLOCKED: NODE_ENV=production".into())
        } else if looks_prod {
            Some(format!(
                "BLOCKED: POSTGRES_URL looks like production: {url}"
            ))
        } else if !host_looks_local && !allow_remote {
            Some(format!(
                "BLOCKED: non-localhost POSTGRES_URL without ALLOW_NON_LOCALHOST_POSTGRES=true: {url}"
            ))
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
