//! Real MySQL server integration tests — migration from make_test_connection mocks
//!
//! Bead: br-asupersync-qr9j1k
//!
//! These tests replace the `make_test_connection()` calls in
//! `src/database/mysql.rs` with real MySQL server connections per the
//! testing-perfect-e2e methodology. Focus on transaction cancellation handling
//! where real server behavior provides better verification than mocked connections.
//!
//! Run with:
//!     REAL_MYSQL_TESTS=true \
//!         MYSQL_URL=mysql://root:password@localhost:3306/mysql \
//!         cargo test --features mysql --test mysql_make_test_connection_migration
//!
//! Production safety guards block:
//!  * `NODE_ENV=production`
//!  * URLs containing `prod` or `production`
//!  * non-localhost hosts unless `ALLOW_NON_LOCALHOST_MYSQL=true`

#![cfg(all(test, feature = "mysql"))]
#![allow(clippy::pedantic, clippy::nursery, clippy::print_stderr)]

use asupersync::database::mysql::{MySqlConnectOptions, MySqlConnection, MySqlError};
use asupersync::test_utils::run_test_with_cx;
use asupersync::types::Outcome;

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Configuration for the real-server harness — env-var driven, with hard
/// production guards matching the postgres pattern.
struct RealMySqlConfig {
    url: String,
    enabled: bool,
    reason: Option<String>,
}

impl RealMySqlConfig {
    fn from_env() -> Self {
        let url = std::env::var("MYSQL_URL")
            .unwrap_or_else(|_| "mysql://root:password@localhost:3306/mysql".to_string());
        let toggle = std::env::var("REAL_MYSQL_TESTS").unwrap_or_default() == "true";
        let allow_remote = std::env::var("ALLOW_NON_LOCALHOST_MYSQL").unwrap_or_default() == "true";
        let node_env = std::env::var("NODE_ENV").unwrap_or_default();

        let host_looks_local = mysql_url_host_is_local(&url);
        let url_lc = url.to_ascii_lowercase();
        let looks_prod = url_lc.contains("prod") || url_lc.contains("production");

        let reason = if !toggle {
            Some("REAL_MYSQL_TESTS not set to 'true' — running unit-only".to_string())
        } else if node_env == "production" {
            Some("BLOCKED: NODE_ENV=production".to_string())
        } else if looks_prod {
            Some("BLOCKED: MYSQL_URL looks like production (redacted)".to_string())
        } else if !host_looks_local && !allow_remote {
            Some(
                "BLOCKED: non-localhost MYSQL_URL without ALLOW_NON_LOCALHOST_MYSQL=true (redacted)"
                    .to_string(),
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

fn mysql_url_host_is_local(url: &str) -> bool {
    match MySqlConnectOptions::parse(url) {
        Ok(opts) => {
            opts.host.eq_ignore_ascii_case("localhost")
                || matches!(opts.host.as_str(), "127.0.0.1" | "::1")
        }
        Err(_) => false,
    }
}

/// Structured logger matching the postgres pattern
struct MySqlMigrationTestLogger {
    suite: &'static str,
    test: String,
    start: Instant,
    phase_count: AtomicU32,
}

impl MySqlMigrationTestLogger {
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
fn skip_if_disabled(cfg: &RealMySqlConfig, test_name: &str) -> bool {
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

fn unwrap_mysql<T>(out: Outcome<T, MySqlError>, log: &MySqlMigrationTestLogger, op: &str) -> T {
    match out {
        Outcome::Ok(v) => v,
        Outcome::Err(e) => {
            log.line("mysql_error", &[("op", op), ("error", &e.to_string())]);
            log.end("fail");
            panic!("{op} returned error: {e}");
        }
        Outcome::Cancelled(reason) => {
            log.line(
                "mysql_cancelled",
                &[("op", op), ("kind", &format!("{:?}", reason.kind))],
            );
            log.end("fail");
            panic!("{op} was cancelled: {:?}", reason.kind);
        }
        Outcome::Panicked(p) => {
            log.line("mysql_panicked", &[("op", op)]);
            log.end("fail");
            panic!("{op} panicked: {p:?}");
        }
    }
}

// ─── MIGRATION TESTS FROM make_test_connection ─────────────────────────────

/// Real database test: MySQL transaction rollback behavior verification.
///
/// This migrates transaction handling tests to verify that real MySQL
/// transaction state is properly tracked and that connections remain usable
/// after transaction rollbacks.
#[test]
fn real_mysql_transaction_rollback_behavior() {
    let cfg = RealMySqlConfig::from_env();
    if skip_if_disabled(&cfg, "real_mysql_transaction_rollback_behavior") {
        return;
    }
    let log = MySqlMigrationTestLogger::new(
        "mysql_migration",
        "real_mysql_transaction_rollback_behavior",
    );

    run_test_with_cx(|cx| async move {
        log.phase("connect");
        let mut conn = unwrap_mysql(
            MySqlConnection::connect(&cx, &cfg.url).await,
            &log,
            "connect",
        );

        log.phase("begin_transaction");
        let _ = unwrap_mysql(conn.execute_unchecked(&cx, "BEGIN").await, &log, "BEGIN");

        // Insert some test data that we'll rollback
        log.phase("insert_test_data");
        let _ = unwrap_mysql(
            conn.execute_unchecked(&cx, "CREATE TEMPORARY TABLE test_rollback (id int)")
                .await,
            &log,
            "create_temp_table",
        );
        let _ = unwrap_mysql(
            conn.execute_unchecked(&cx, "INSERT INTO test_rollback VALUES (42)")
                .await,
            &log,
            "insert_data",
        );

        // REAL DATABASE VERIFICATION: Data should be visible within transaction
        log.phase("verify_data_in_transaction");
        let rows = unwrap_mysql(
            conn.query_unchecked(&cx, "SELECT id FROM test_rollback")
                .await,
            &log,
            "select_in_txn",
        );
        assert_eq!(rows.len(), 1);
        let val = rows[0].get_i32("id").expect("get_i32");
        assert_eq!(val, 42);
        log.line("data_visible", &[("value", "42")]);

        // Rollback the transaction
        log.phase("rollback_transaction");
        let _ = unwrap_mysql(
            conn.execute_unchecked(&cx, "ROLLBACK").await,
            &log,
            "ROLLBACK",
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
                log.line(
                    "post_rollback_query_failed",
                    &[("outcome", &format!("{:?}", other))],
                );
                panic!(
                    "connection should be usable after rollback, got: {:?}",
                    other
                );
            }
        }

        log.end("pass");
    });
}

/// Real database test: MySQL-specific query error handling.
///
/// This tests error handling with real MySQL error responses to verify
/// that session recovery works correctly after various error conditions.
#[test]
fn real_mysql_query_execution_error_handling() {
    let cfg = RealMySqlConfig::from_env();
    if skip_if_disabled(&cfg, "real_mysql_query_execution_error_handling") {
        return;
    }
    let log = MySqlMigrationTestLogger::new(
        "mysql_migration",
        "real_mysql_query_execution_error_handling",
    );

    run_test_with_cx(|cx| async move {
        log.phase("connect");
        let mut conn = unwrap_mysql(
            MySqlConnection::connect(&cx, &cfg.url).await,
            &log,
            "connect",
        );

        // Test 1: Syntax error should preserve session but return error
        log.phase("test_syntax_error");
        let syntax_error = conn
            .query_unchecked(&cx, "SELECT invalid syntax here")
            .await;
        match syntax_error {
            Outcome::Err(e) => {
                log.line("syntax_error_received", &[("error", &e.to_string())]);
                // REAL DATABASE VERIFICATION: Check that we get the actual MySQL error
                if let Some(code) = e.error_code() {
                    log.line("syntax_error_code", &[("code", &code)]);
                    // MySQL syntax errors are typically 1064
                    assert_eq!(code, "1064", "expected MySQL syntax error code");
                }
            }
            other => {
                log.line(
                    "unexpected_syntax_outcome",
                    &[("outcome", &format!("{:?}", other))],
                );
                panic!("expected syntax error, got: {:?}", other);
            }
        }

        // Test 2: Session should be recoverable after syntax error
        log.phase("test_session_recovery_after_error");
        let recovery_query = conn.query_unchecked(&cx, "SELECT 42").await;
        match recovery_query {
            Outcome::Ok(rows) => {
                log.line(
                    "session_recovery",
                    &[("success", "true"), ("rows", &rows.len().to_string())],
                );
                assert_eq!(rows.len(), 1);
                let val = rows[0].get_i32("42").expect("get_i32");
                assert_eq!(val, 42);
            }
            other => {
                log.line(
                    "session_recovery_failed",
                    &[("outcome", &format!("{:?}", other))],
                );
                panic!(
                    "session should be recoverable after syntax error, got: {:?}",
                    other
                );
            }
        }

        // Test 3: Division by zero error (MySQL behavior)
        log.phase("test_division_by_zero");
        let div_zero = conn.query_unchecked(&cx, "SELECT 1/0").await;
        match div_zero {
            Outcome::Ok(rows) => {
                // MySQL returns NULL for 1/0 instead of error by default
                log.line("division_result", &[("rows", &rows.len().to_string())]);
                assert_eq!(rows.len(), 1);
                // MySQL NULL handling differs from PostgreSQL
            }
            Outcome::Err(e) => {
                // Some MySQL configurations may error on division by zero
                log.line("division_error_received", &[("error", &e.to_string())]);
            }
            other => {
                log.line(
                    "unexpected_division_outcome",
                    &[("outcome", &format!("{:?}", other))],
                );
                panic!("unexpected division by zero result: {:?}", other);
            }
        }

        // Test 4: Session still usable
        log.phase("test_final_recovery");
        let final_query = conn.query_unchecked(&cx, "SELECT 'recovered'").await;
        match final_query {
            Outcome::Ok(rows) => {
                log.line("final_recovery", &[("success", "true")]);
                assert_eq!(rows.len(), 1);
            }
            other => {
                log.line(
                    "final_recovery_failed",
                    &[("outcome", &format!("{:?}", other))],
                );
                panic!("session should still be usable, got: {:?}", other);
            }
        }

        log.end("pass");
    });
}
