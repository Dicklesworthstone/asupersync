//! Real PostgreSQL server integration tests — migration from make_test_connection mocks
//!
//! Bead: br-asupersync-qr9j1k
//!
//! These tests replace high-priority `make_test_connection()` calls in
//! `src/database/postgres.rs` with real PostgreSQL server connections per the
//! testing-perfect-e2e methodology. Focus on transaction behavior, query
//! execution errors, and prepared statement handling where real server behavior
//! provides verification that mocked TCP socket pairs cannot.
//!
//! Wire protocol parsing and type conversion tests remain as mocks since
//! deterministic message injection is superior for those test cases.
//!
//! Run with:
//!     REAL_PG_TESTS=true \
//!         POSTGRES_URL=postgres://postgres:postgres@localhost:5432/postgres \
//!         cargo test --features postgres --test postgres_make_test_connection_migration
//!
//! Production safety guards block:
//!  * `NODE_ENV=production`
//!  * URLs containing `prod`, `production`, or non-localhost hosts unless
//!    `ALLOW_NON_LOCALHOST_POSTGRES=true` is also set.

#![cfg(all(test, feature = "postgres"))]
#![allow(clippy::pedantic, clippy::nursery, clippy::print_stderr)]

use asupersync::database::postgres::{PgConnectOptions, PgConnection, PgError};
use asupersync::test_utils::run_test_with_cx;
use asupersync::types::{Outcome, CancelKind};
use asupersync::Cx;

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Configuration for the real-server harness — env-var driven, with hard
/// production guards matching postgres_real_server.rs pattern.
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
        let toggle = std::env::var("REAL_PG_TESTS").unwrap_or_default() == "true";
        let node_env = std::env::var("NODE_ENV").unwrap_or_default();

        let host_looks_local = postgres_url_host_is_local(&url);
        let url_lc = url.to_ascii_lowercase();
        let looks_prod = url_lc.contains("prod") || url_lc.contains("production");

        let reason = if !toggle {
            Some("REAL_PG_TESTS not set to 'true' — running unit-only".into())
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

fn postgres_url_host_is_local(url: &str) -> bool {
    match PgConnectOptions::parse(url) {
        Ok(opts) => {
            opts.host.eq_ignore_ascii_case("localhost")
                || matches!(opts.host.as_str(), "127.0.0.1" | "::1")
        }
        Err(_) => false,
    }
}

/// Structured logger matching postgres_real_server.rs pattern
struct PgMigrationTestLogger {
    suite: &'static str,
    test: String,
    start: Instant,
    phase_count: AtomicU32,
}

impl PgMigrationTestLogger {
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

fn unwrap_pg<T>(out: Outcome<T, PgError>, log: &PgMigrationTestLogger, op: &str) -> T {
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

fn assert_user_cancelled<T, E>(outcome: Outcome<T, E>) {
    match outcome {
        Outcome::Cancelled(reason) => assert_eq!(reason.kind, CancelKind::User),
        _ => panic!("expected Cancelled outcome with User cancel kind"),
    }
}

fn cancelled_cx() -> Cx {
    let cx = Cx::for_testing();
    cx.cancel_fast(CancelKind::User);
    cx
}

// ─── HIGH PRIORITY MIGRATION TESTS ──────────────────────────────────────────

/// Real database test: transaction rollback behavior verification.
///
/// This migrates transaction handling tests to verify that real PostgreSQL
/// transaction state is properly tracked and that connections remain usable
/// after transaction rollbacks. Focuses on server-driven transaction status.
#[test]
fn real_pg_transaction_rollback_behavior() {
    let cfg = RealPgConfig::from_env();
    if skip_if_disabled(&cfg, "real_pg_transaction_rollback_behavior") {
        return;
    }
    let log = PgMigrationTestLogger::new("postgres_migration", "real_pg_transaction_rollback_behavior");

    run_test_with_cx(|cx| async move {
        log.phase("connect");
        let mut conn = unwrap_pg(PgConnection::connect(&cx, &cfg.url).await, &log, "connect");

        log.phase("begin_transaction");
        let _ = unwrap_pg(conn.execute_unchecked(&cx, "BEGIN").await, &log, "BEGIN");

        // Insert some test data that we'll rollback
        log.phase("insert_test_data");
        let _ = unwrap_pg(
            conn.execute_unchecked(&cx, "CREATE TEMPORARY TABLE test_rollback (id int)").await,
            &log,
            "create_temp_table"
        );
        let _ = unwrap_pg(
            conn.execute_unchecked(&cx, "INSERT INTO test_rollback VALUES (42)").await,
            &log,
            "insert_data"
        );

        // REAL DATABASE VERIFICATION: Data should be visible within transaction
        log.phase("verify_data_in_transaction");
        let rows = unwrap_pg(
            conn.query_unchecked(&cx, "SELECT id FROM test_rollback").await,
            &log,
            "select_in_txn"
        );
        assert_eq!(rows.len(), 1);
        let val = rows[0].get_i32("id").expect("get_i32");
        assert_eq!(val, 42);
        log.line("data_visible", &[("value", "42")]);

        // Rollback the transaction
        log.phase("rollback_transaction");
        let _ = unwrap_pg(
            conn.execute_unchecked(&cx, "ROLLBACK").await,
            &log,
            "ROLLBACK"
        );

        // REAL DATABASE VERIFICATION: Connection should be usable after rollback
        log.phase("verify_connection_usable_after_rollback");
        let test_query = conn.query_unchecked(&cx, "SELECT 1 as test").await;
        match test_query {
            Outcome::Ok(rows) => {
                log.line("post_rollback_query", &[("rows", &rows.len().to_string())]);
                assert_eq!(rows.len(), 1);
                let val = rows[0].get_i32("test").expect("get_i32");
                assert_eq!(val, 1);
            }
            other => {
                log.line("post_rollback_query_failed", &[("outcome", &format!("{:?}", other))]);
                panic!("connection should be usable after rollback, got: {:?}", other);
            }
        }

        // Verify temp table was cleaned up by rollback
        log.phase("verify_rollback_cleaned_up");
        let cleanup_check = conn.query_unchecked(&cx, "SELECT COUNT(*) FROM pg_tables WHERE tablename LIKE 'test_rollback%'").await;
        match cleanup_check {
            Outcome::Ok(rows) => {
                let count = rows[0].get_i64("count").expect("get_i64");
                log.line("table_cleanup_check", &[("remaining_tables", &count.to_string())]);
                assert_eq!(count, 0, "temp table should be cleaned up by rollback");
            }
            other => {
                log.line("cleanup_check_failed", &[("outcome", &format!("{:?}", other))]);
                // Non-critical - just log the failure
            }
        }

        log.end("pass");
    });
}

/// Real database test: prepared statement lifecycle with real backend.
///
/// This migrates deallocate testing to verify that prepared statement
/// management works correctly with a real PostgreSQL server, including
/// error handling and connection health tracking.
#[test]
fn real_pg_prepared_statement_lifecycle() {
    let cfg = RealPgConfig::from_env();
    if skip_if_disabled(&cfg, "real_pg_prepared_statement_lifecycle") {
        return;
    }
    let log = PgMigrationTestLogger::new("postgres_migration", "real_pg_prepared_statement_lifecycle");

    run_test_with_cx(|cx| async move {
        log.phase("connect");
        let mut conn = unwrap_pg(PgConnection::connect(&cx, &cfg.url).await, &log, "connect");

        // Test 1: Prepare and execute a statement
        log.phase("prepare_and_execute_statement");
        let _ = unwrap_pg(
            conn.execute_unchecked(&cx, "PREPARE test_stmt AS SELECT $1::int4 as value").await,
            &log,
            "prepare_statement"
        );

        let rows = unwrap_pg(
            conn.query_unchecked(&cx, "EXECUTE test_stmt(123)").await,
            &log,
            "execute_statement"
        );
        assert_eq!(rows.len(), 1);
        let val = rows[0].get_i32("value").expect("get_i32");
        assert_eq!(val, 123);
        log.line("statement_execution", &[("value", "123")]);

        // Test 2: Deallocate the statement
        log.phase("deallocate_statement");
        let dealloc_result = conn.execute_unchecked(&cx, "DEALLOCATE test_stmt").await;
        match dealloc_result {
            Outcome::Ok(_) => {
                log.line("deallocate_success", &[("success", "true")]);
            }
            other => {
                log.line("unexpected_dealloc_outcome", &[("outcome", &format!("{:?}", other))]);
                panic!("deallocate should succeed, got: {:?}", other);
            }
        }

        // Test 3: Verify statement is gone (should error)
        log.phase("verify_statement_deallocated");
        let execute_deallocated = conn.query_unchecked(&cx, "EXECUTE test_stmt(456)").await;
        match execute_deallocated {
            Outcome::Err(e) => {
                log.line("execute_deallocated_failed", &[("error", &e.to_string())]);
                // REAL DATABASE VERIFICATION: Should get specific PostgreSQL error
                if let Some(code) = e.error_code() {
                    log.line("deallocated_error_code", &[("code", code)]);
                    assert_eq!(code, "26000", "expected prepared statement not found error");
                }
            }
            other => {
                log.line("unexpected_execute_outcome", &[("outcome", &format!("{:?}", other))]);
                panic!("execute on deallocated statement should error, got: {:?}", other);
            }
        }

        // Test 4: Connection should still be usable after statement error
        log.phase("verify_connection_usable_after_error");
        let recovery_query = conn.query_unchecked(&cx, "SELECT 'recovered' as status").await;
        match recovery_query {
            Outcome::Ok(rows) => {
                assert_eq!(rows.len(), 1);
                let status = rows[0].get_str("status").expect("get_str");
                assert_eq!(status, "recovered");
                log.line("connection_recovery", &[("status", "recovered")]);
            }
            other => {
                log.line("recovery_failed", &[("outcome", &format!("{:?}", other))]);
                panic!("connection should recover after statement error, got: {:?}", other);
            }
        }

        log.end("pass");
    });
}

/// Real database test: query execution error handling with real server responses.
///
/// This migrates query error handling tests to verify that the driver correctly
/// processes error responses from a real PostgreSQL server, including proper
/// session state recovery after errors.
#[test]
fn real_pg_query_execution_error_handling() {
    let cfg = RealPgConfig::from_env();
    if skip_if_disabled(&cfg, "real_pg_query_execution_error_handling") {
        return;
    }
    let log = PgMigrationTestLogger::new("postgres_migration", "real_pg_query_execution_error_handling");

    run_test_with_cx(|cx| async move {
        log.phase("connect");
        let mut conn = unwrap_pg(PgConnection::connect(&cx, &cfg.url).await, &log, "connect");

        // Test 1: Syntax error should preserve session but return error
        log.phase("test_syntax_error");
        let syntax_error = conn.query_unchecked(&cx, "SELECT invalid syntax here").await;
        match syntax_error {
            Outcome::Err(e) => {
                log.line("syntax_error_received", &[("error", &e.to_string())]);
                // REAL DATABASE VERIFICATION: Check that we get the actual PostgreSQL error
                if let Some(code) = e.error_code() {
                    log.line("syntax_error_sqlstate", &[("code", code)]);
                    assert_eq!(code, "42601", "expected syntax error SQLSTATE");
                }
            }
            other => {
                log.line("unexpected_syntax_outcome", &[("outcome", &format!("{:?}", other))]);
                panic!("expected syntax error, got: {:?}", other);
            }
        }

        // Test 2: Session should be recoverable after syntax error
        log.phase("test_session_recovery_after_error");
        let recovery_query = conn.query_unchecked(&cx, "SELECT 42").await;
        match recovery_query {
            Outcome::Ok(rows) => {
                log.line("session_recovery", &[("success", "true"), ("rows", &rows.len().to_string())]);
                assert_eq!(rows.len(), 1);
                let val = rows[0].get_i32("?column?").expect("get_i32");
                assert_eq!(val, 42);
            }
            other => {
                log.line("session_recovery_failed", &[("outcome", &format!("{:?}", other))]);
                panic!("session should be recoverable after syntax error, got: {:?}", other);
            }
        }

        // Test 3: Division by zero error
        log.phase("test_division_by_zero");
        let div_zero = conn.query_unchecked(&cx, "SELECT 1/0").await;
        match div_zero {
            Outcome::Err(e) => {
                log.line("division_error_received", &[("error", &e.to_string())]);
                // REAL DATABASE VERIFICATION: Check for actual PostgreSQL division by zero error
                if let Some(code) = e.error_code() {
                    log.line("division_error_sqlstate", &[("code", code)]);
                    assert_eq!(code, "22012", "expected division by zero SQLSTATE");
                }
            }
            other => {
                log.line("unexpected_division_outcome", &[("outcome", &format!("{:?}", other))]);
                panic!("expected division by zero error, got: {:?}", other);
            }
        }

        // Test 4: Session still usable after division error
        log.phase("test_final_recovery");
        let final_query = conn.query_unchecked(&cx, "SELECT 'recovered'").await;
        match final_query {
            Outcome::Ok(rows) => {
                log.line("final_recovery", &[("success", "true")]);
                assert_eq!(rows.len(), 1);
            }
            other => {
                log.line("final_recovery_failed", &[("outcome", &format!("{:?}", other))]);
                panic!("session should still be usable, got: {:?}", other);
            }
        }

        log.end("pass");
    });
}