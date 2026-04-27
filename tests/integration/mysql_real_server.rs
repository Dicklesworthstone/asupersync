//! Real MySQL server integration tests — no synthetic packet server.
//!
//! Bead: br-asupersync-yyqs0n
//!
//! Run with:
//!     REAL_MYSQL_TESTS=true \
//!         MYSQL_URL=mysql://root:password@localhost:3306/mysql \
//!         cargo test --features mysql --test mysql_real_server -- --nocapture
//!
//! Production safety guards block:
//!  * `NODE_ENV=production`
//!  * URLs containing `prod` or `production`
//!  * non-localhost hosts unless `ALLOW_NON_LOCALHOST_MYSQL=true`

#![cfg(all(test, feature = "mysql"))]
#![allow(clippy::pedantic, clippy::nursery, clippy::print_stderr)]

use asupersync::database::mysql::{IsolationLevel, MySqlConnection, MySqlError};
use asupersync::test_utils::run_test_with_cx;
use asupersync::types::Outcome;

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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
        let allow_remote =
            std::env::var("ALLOW_NON_LOCALHOST_MYSQL").unwrap_or_default() == "true";
        let node_env = std::env::var("NODE_ENV").unwrap_or_default();

        let url_lc = url.to_ascii_lowercase();
        let host_looks_local = url_lc.contains("@localhost")
            || url_lc.contains("@127.0.0.1")
            || url_lc.contains("@[::1]");
        let looks_prod = url_lc.contains("prod") || url_lc.contains("production");

        let reason = if !toggle {
            Some("REAL_MYSQL_TESTS not set to 'true' — running unit-only".to_string())
        } else if node_env == "production" {
            Some("BLOCKED: NODE_ENV=production".to_string())
        } else if looks_prod {
            Some(format!("BLOCKED: MYSQL_URL looks like production: {url}"))
        } else if !host_looks_local && !allow_remote {
            Some(format!(
                "BLOCKED: non-localhost MYSQL_URL without ALLOW_NON_LOCALHOST_MYSQL=true: {url}"
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

struct MySqlTestLogger {
    suite: &'static str,
    test: &'static str,
    start: Instant,
    phase_count: AtomicU32,
}

impl MySqlTestLogger {
    fn new(suite: &'static str, test: &'static str) -> Self {
        let me = Self {
            suite,
            test,
            start: Instant::now(),
            phase_count: AtomicU32::new(0),
        };
        me.line("test_start", &[]);
        me
    }

    fn line(&self, event: &str, fields: &[(&str, String)]) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let mut buf = format!(
            r#"{{"ts":{ts},"suite":"{}","test":"{}","event":"{event}""#,
            self.suite, self.test
        );
        for (key, value) in fields {
            let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
            buf.push_str(&format!(r#","{key}":"{escaped}""#));
        }
        buf.push('}');
        eprintln!("{buf}");
    }

    fn phase(&self, name: &str) {
        let phase_num = self.phase_count.fetch_add(1, Ordering::Relaxed);
        self.line(
            "phase",
            &[
                ("phase", name.to_string()),
                ("phase_num", phase_num.to_string()),
                ("elapsed_ms", self.start.elapsed().as_millis().to_string()),
            ],
        );
    }

    fn end(&self, result: &str) {
        self.line(
            "test_end",
            &[
                ("result", result.to_string()),
                ("duration_ms", self.start.elapsed().as_millis().to_string()),
            ],
        );
    }
}

fn skip_if_disabled(cfg: &RealMySqlConfig, test_name: &str) -> bool {
    if !cfg.enabled {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let reason = cfg.reason.as_deref().unwrap_or("disabled");
        eprintln!(
            r#"{{"ts":{ts},"event":"test_skipped","test":"{test_name}","reason":"{reason}"}}"#
        );
        return true;
    }
    false
}

fn unwrap_mysql<T>(outcome: Outcome<T, MySqlError>, op: &str, log: &MySqlTestLogger) -> T {
    match outcome {
        Outcome::Ok(value) => value,
        Outcome::Err(err) => {
            log.line(
                "mysql_error",
                &[("op", op.to_string()), ("error", err.to_string())],
            );
            log.end("fail");
            panic!("{op} returned error: {err}");
        }
        Outcome::Cancelled(reason) => {
            log.line(
                "mysql_cancelled",
                &[
                    ("op", op.to_string()),
                    ("kind", format!("{:?}", reason.kind)),
                ],
            );
            log.end("fail");
            panic!("{op} cancelled: {:?}", reason.kind);
        }
        Outcome::Panicked(payload) => {
            log.line("mysql_panicked", &[("op", op.to_string())]);
            log.end("fail");
            panic!("{op} panicked: {payload:?}");
        }
    }
}

#[test]
fn mysql_real_ping_query_and_prepared_roundtrip() {
    let cfg = RealMySqlConfig::from_env();
    if skip_if_disabled(&cfg, "mysql_real_ping_query_and_prepared_roundtrip") {
        return;
    }

    let log = MySqlTestLogger::new("mysql_real", "mysql_real_ping_query_and_prepared_roundtrip");

    run_test_with_cx(|cx| async move {
        log.phase("connect");
        let mut conn = unwrap_mysql(MySqlConnection::connect(&cx, &cfg.url).await, "connect", &log);
        log.line(
            "connection",
            &[
                ("server_version", conn.server_version().to_string()),
                ("connection_id", conn.connection_id().to_string()),
            ],
        );

        log.phase("ping");
        unwrap_mysql(conn.ping(&cx).await, "ping", &log);

        log.phase("select_one");
        let rows = unwrap_mysql(
            conn.query_unchecked(&cx, "SELECT 1 AS v, 'ok' AS name").await,
            "query",
            &log,
        );
        assert_eq!(rows.len(), 1, "expected one row");
        assert_eq!(rows[0].get_i32("v").expect("v"), 1);
        assert_eq!(rows[0].get_str("name").expect("name"), "ok");

        log.phase("temp_table");
        unwrap_mysql(
            conn.execute_unchecked(
                &cx,
                "CREATE TEMPORARY TABLE IF NOT EXISTS asupersync_real_stmt (id INT PRIMARY KEY, name VARCHAR(64) NOT NULL)",
            )
            .await,
            "create_temp_table",
            &log,
        );

        log.phase("prepare_insert");
        let insert_stmt = unwrap_mysql(
            conn.prepare(
                &cx,
                "INSERT INTO asupersync_real_stmt (id, name) VALUES (?, ?)",
            )
            .await,
            "prepare_insert",
            &log,
        );
        assert_eq!(insert_stmt.param_count(), 2, "insert param_count");
        assert_eq!(insert_stmt.column_count(), 0, "insert column_count");
        unwrap_mysql(
            conn.execute_prepared(&cx, &insert_stmt, &[&1_i32, &"alpha"]).await,
            "execute_prepared",
            &log,
        );

        log.phase("prepare_select");
        let select_stmt = unwrap_mysql(
            conn.prepare(&cx, "SELECT id, name FROM asupersync_real_stmt WHERE id = ?")
                .await,
            "prepare_select",
            &log,
        );
        assert_eq!(select_stmt.param_count(), 1, "select param_count");
        let rows = unwrap_mysql(
            conn.query_prepared(&cx, &select_stmt, &[&1_i32]).await,
            "query_prepared",
            &log,
        );
        assert_eq!(rows.len(), 1, "expected one prepared row");
        assert_eq!(rows[0].get_i32("id").expect("id"), 1);
        assert_eq!(rows[0].get_str("name").expect("name"), "alpha");

        log.phase("close");
        conn.close().await.expect("close");
        log.end("pass");
    });
}

#[test]
fn mysql_real_transaction_isolation_and_rollback() {
    let cfg = RealMySqlConfig::from_env();
    if skip_if_disabled(&cfg, "mysql_real_transaction_isolation_and_rollback") {
        return;
    }

    let log =
        MySqlTestLogger::new("mysql_real", "mysql_real_transaction_isolation_and_rollback");

    run_test_with_cx(|cx| async move {
        log.phase("connect");
        let mut conn = unwrap_mysql(MySqlConnection::connect(&cx, &cfg.url).await, "connect", &log);

        log.phase("temp_table");
        unwrap_mysql(
            conn.execute_unchecked(
                &cx,
                "CREATE TEMPORARY TABLE IF NOT EXISTS asupersync_real_tx (id INT PRIMARY KEY, name VARCHAR(64) NOT NULL)",
            )
            .await,
            "create_temp_table",
            &log,
        );

        log.phase("begin_with_isolation");
        let mut tx = unwrap_mysql(
            conn.begin_with_isolation(&cx, IsolationLevel::ReadCommitted, false)
                .await,
            "begin_with_isolation",
            &log,
        );
        assert_eq!(
            tx.isolation_level(),
            Some(IsolationLevel::ReadCommitted),
            "transaction should retain requested isolation"
        );
        assert!(!tx.is_read_only(), "transaction should be read-write");

        log.phase("insert_inside_tx");
        unwrap_mysql(
            tx.execute_unchecked(
                &cx,
                "INSERT INTO asupersync_real_tx (id, name) VALUES (7, 'rolled-back')",
            )
            .await,
            "tx_insert",
            &log,
        );

        log.phase("rollback");
        unwrap_mysql(tx.rollback(&cx).await, "rollback", &log);

        log.phase("verify_rollback");
        let rows = unwrap_mysql(
            conn.query_unchecked(
                &cx,
                "SELECT COUNT(*) AS cnt FROM asupersync_real_tx WHERE id = 7",
            )
            .await,
            "verify_rollback",
            &log,
        );
        assert_eq!(rows.len(), 1, "expected count row");
        assert_eq!(rows[0].get_i64("cnt").expect("cnt"), 0);

        log.phase("close");
        conn.close().await.expect("close");
        log.end("pass");
    });
}
