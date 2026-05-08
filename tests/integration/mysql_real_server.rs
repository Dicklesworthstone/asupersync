//! Real MySQL server integration tests — no synthetic packet server.
//!
//! Bead: br-asupersync-yyqs0n
//!
//! Run with:
//!     rch exec -- env REAL_MYSQL_TESTS=true \
//!         MYSQL_URL=mysql://root:password@localhost:3306/mysql \
//!         cargo test --features mysql --test mysql_real_server -- --nocapture
//!
//! Production safety guards block:
//!  * `NODE_ENV=production`
//!  * URLs containing `prod` or `production`
//!  * non-localhost hosts unless `ALLOW_NON_LOCALHOST_MYSQL=true`

#![cfg(all(test, feature = "mysql"))]
#![allow(clippy::pedantic, clippy::nursery, clippy::print_stderr)]

use asupersync::database::mysql::{
    IsolationLevel, MySqlConnectOptions, MySqlConnection, MySqlError,
};
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

fn mysql_url_host_is_local(url: &str) -> bool {
    match MySqlConnectOptions::parse(url) {
        Ok(opts) => {
            opts.host.eq_ignore_ascii_case("localhost")
                || matches!(opts.host.as_str(), "127.0.0.1" | "::1")
        }
        Err(_) => false,
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

#[test]
fn mysql_real_config_localhost_gate_rejects_prefix_spoofing() {
    assert!(mysql_url_host_is_local(
        "mysql://root:password@localhost:3306/mysql"
    ));
    assert!(mysql_url_host_is_local(
        "mysql://root:password@LOCALHOST:3306/mysql"
    ));
    assert!(mysql_url_host_is_local(
        "mysql://root:password@127.0.0.1:3306/mysql"
    ));
    assert!(mysql_url_host_is_local(
        "mysql://root:password@[::1]:3306/mysql"
    ));
    assert!(mysql_url_host_is_local("mysql://localhost/mysql"));
    assert!(!mysql_url_host_is_local(
        "mysql://root:password@localhost.evil.example:3306/mysql"
    ));
    assert!(!mysql_url_host_is_local(
        "mysql://root:password@127.0.0.1.evil.example:3306/mysql"
    ));
    assert!(!mysql_url_host_is_local(
        "mysql://root:password@10.0.0.5:3306/mysql"
    ));
    assert!(!mysql_url_host_is_local("not-a-mysql-url"));
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
        let mut conn = unwrap_mysql(
            MySqlConnection::connect(&cx, &cfg.url).await,
            "connect",
            &log,
        );
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
            conn.query_unchecked(&cx, "SELECT 1 AS v, 'ok' AS name")
                .await,
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
            conn.execute_prepared(&cx, &insert_stmt, &[&1_i32, &"alpha"])
                .await,
            "execute_prepared",
            &log,
        );

        log.phase("prepare_select");
        let select_stmt = unwrap_mysql(
            conn.prepare(
                &cx,
                "SELECT id, name FROM asupersync_real_stmt WHERE id = ?",
            )
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

    let log = MySqlTestLogger::new(
        "mysql_real",
        "mysql_real_transaction_isolation_and_rollback",
    );

    run_test_with_cx(|cx| async move {
        log.phase("connect");
        let mut conn = unwrap_mysql(
            MySqlConnection::connect(&cx, &cfg.url).await,
            "connect",
            &log,
        );

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

#[test]
fn mysql_real_read_only_transaction_rejects_mutation() {
    let cfg = RealMySqlConfig::from_env();
    if skip_if_disabled(&cfg, "mysql_real_read_only_transaction_rejects_mutation") {
        return;
    }

    let log = MySqlTestLogger::new(
        "mysql_real",
        "mysql_real_read_only_transaction_rejects_mutation",
    );

    run_test_with_cx(|cx| async move {
        log.phase("connect");
        let mut conn = unwrap_mysql(
            MySqlConnection::connect(&cx, &cfg.url).await,
            "connect",
            &log,
        );

        let table_name = format!(
            "asupersync_real_tx_ro_{}_{}",
            conn.connection_id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        );
        let drop_sql = format!("DROP TABLE IF EXISTS {table_name}");
        let create_sql = format!(
            "CREATE TABLE {table_name} (id INT PRIMARY KEY, name VARCHAR(64) NOT NULL) ENGINE=InnoDB"
        );
        let insert_sql = format!("INSERT INTO {table_name} (id, name) VALUES (7, 'should-fail')");
        let verify_sql = format!("SELECT COUNT(*) AS cnt FROM {table_name} WHERE id = 7");

        log.phase("drop_before");
        unwrap_mysql(
            conn.execute_unchecked(&cx, &drop_sql).await,
            "drop_before",
            &log,
        );

        log.phase("create_table");
        unwrap_mysql(
            conn.execute_unchecked(&cx, &create_sql).await,
            "create_table",
            &log,
        );

        log.phase("begin_read_only");
        let mut tx = unwrap_mysql(
            conn.begin_with_isolation(&cx, IsolationLevel::ReadCommitted, true)
                .await,
            "begin_read_only",
            &log,
        );
        assert!(tx.is_read_only(), "transaction should be read-only");

        log.phase("insert_rejected");
        match tx.execute_unchecked(&cx, &insert_sql).await {
            Outcome::Err(MySqlError::Server {
                code,
                sql_state,
                message,
            }) => {
                let mentions_read_only = message.to_ascii_uppercase().contains("READ ONLY");
                assert!(
                    sql_state == "25006" || mentions_read_only,
                    "expected READ ONLY rejection, got code={code} state={sql_state} message={message}"
                );
            }
            other => {
                log.end("fail");
                panic!("expected READ ONLY mutation rejection, got {other:?}");
            }
        }

        log.phase("rollback");
        unwrap_mysql(tx.rollback(&cx).await, "rollback", &log);

        log.phase("verify_no_row");
        let rows = unwrap_mysql(
            conn.query_unchecked(&cx, &verify_sql).await,
            "verify_no_row",
            &log,
        );
        assert_eq!(rows.len(), 1, "expected count row");
        assert_eq!(rows[0].get_i64("cnt").expect("cnt"), 0);

        log.phase("drop_after");
        unwrap_mysql(
            conn.execute_unchecked(&cx, &drop_sql).await,
            "drop_after",
            &log,
        );

        log.phase("close");
        conn.close().await.expect("close");
        log.end("pass");
    });
}

/// Abandoned-transaction recovery: dropping a `MySqlTransaction` without
/// calling `commit` or `rollback` is the exact path a Rust panic unwind
/// follows through `with_mysql_transaction`'s body. The Drop impl
/// (src/database/mysql.rs:4839) calls `poison_for_rollback`, setting
/// `needs_rollback = true` on the underlying connection. The next async
/// operation must call `drain_abandoned_transaction` (line 3893), send
/// `COM_QUERY ROLLBACK`, parse OK, clear `needs_rollback`, and let the
/// caller's query proceed against a clean session.
///
/// asupersync-llwouh: today this drain path is verified only through
/// unit tests against synthetic packet state. There is no roundtrip
/// against a real MySQL server proving that:
///   * a real `BEGIN; INSERT; <drop tx>; SELECT` does NOT see the
///     inserted row (the implicit ROLLBACK runs against the live
///     server, not just our internal flag),
///   * the connection is genuinely reusable for further reads and
///     writes after the drain,
///   * MySQL itself agrees the transaction was aborted (a fresh
///     `SELECT @@in_transaction` returns 0).
///
/// This is the canonical safety net for panic-unwind correctness: if
/// the Drop poison logic regresses, partial writes from a panicked
/// transaction body would silently commit on the next query (because
/// `needs_rollback` would never get set, and the open server-side
/// transaction would auto-commit on connection close-with-implicit-
/// commit modes, or worse, leak into the next caller's query in pool
/// reuse). A real-server test is the only way to catch that.
#[test]
fn mysql_real_dropped_transaction_drains_rollback_on_next_op() {
    let cfg = RealMySqlConfig::from_env();
    if skip_if_disabled(
        &cfg,
        "mysql_real_dropped_transaction_drains_rollback_on_next_op",
    ) {
        return;
    }

    let log = MySqlTestLogger::new(
        "mysql_real",
        "mysql_real_dropped_transaction_drains_rollback_on_next_op",
    );

    run_test_with_cx(|cx| async move {
        log.phase("connect");
        let mut conn = unwrap_mysql(
            MySqlConnection::connect(&cx, &cfg.url).await,
            "connect",
            &log,
        );

        // TEMPORARY tables are session-local and auto-drop on connection
        // close, so this test leaves no schema state behind even if it
        // panics or is killed mid-flight.
        log.phase("create_temp_table");
        unwrap_mysql(
            conn.execute_unchecked(
                &cx,
                "CREATE TEMPORARY TABLE asupersync_llwouh_drop_rollback \
                 (id INT PRIMARY KEY, payload VARCHAR(64) NOT NULL) ENGINE=InnoDB",
            )
            .await,
            "create_temp_table",
            &log,
        );

        log.phase("baseline_in_transaction_off");
        let baseline = unwrap_mysql(
            conn.query_unchecked(&cx, "SELECT @@in_transaction AS in_txn")
                .await,
            "baseline_in_transaction",
            &log,
        );
        let baseline_in_txn = baseline[0].get_i64("in_txn").expect("baseline in_txn");
        log.line(
            "assertion",
            &[
                ("field", "baseline_in_txn".to_string()),
                ("expected", "0".to_string()),
                ("actual", baseline_in_txn.to_string()),
            ],
        );
        assert_eq!(
            baseline_in_txn, 0,
            "fresh connection must not be inside a transaction"
        );

        // Open a transaction, insert a row, then deliberately drop the
        // MySqlTransaction without commit/rollback. This is the exact
        // shape of the unwind path: between the begin().await and the
        // commit/rollback call, a panic would drop `tx` mid-stack — and
        // the test simulates that by letting the inner block end while
        // tx is still in scope, then dropping it manually.
        log.phase("begin_insert_drop");
        let drop_returned_at_ms;
        {
            let mut tx = unwrap_mysql(conn.begin(&cx).await, "begin", &log);
            unwrap_mysql(
                tx.execute_unchecked(
                    &cx,
                    "INSERT INTO asupersync_llwouh_drop_rollback \
                     (id, payload) VALUES (1, 'abandoned-via-drop')",
                )
                .await,
                "insert_inside_tx",
                &log,
            );
            // Drop without commit/rollback. The Drop impl on
            // MySqlTransaction calls poison_for_rollback() which sets
            // needs_rollback=true on the underlying connection.
            drop(tx);
            drop_returned_at_ms = log_elapsed_ms(&log);
        }
        log.line("tx_dropped", &[("at_ms", drop_returned_at_ms.to_string())]);

        // First op after the drop is the one that must drain. We use
        // the row count itself as the assertion: if the implicit
        // ROLLBACK fires, count is 0; if the drain regressed and the
        // connection silently committed (or leaked the open tx into
        // this query), count would be 1.
        log.phase("first_op_after_drop_drains_rollback");
        let drained = unwrap_mysql(
            conn.query_unchecked(
                &cx,
                "SELECT COUNT(*) AS cnt FROM asupersync_llwouh_drop_rollback",
            )
            .await,
            "post_drop_count",
            &log,
        );
        let count_after_drop = drained[0].get_i64("cnt").expect("post_drop_count");
        log.line(
            "assertion",
            &[
                ("field", "post_drop_count".to_string()),
                ("expected", "0".to_string()),
                ("actual", count_after_drop.to_string()),
            ],
        );
        assert_eq!(
            count_after_drop, 0,
            "implicit ROLLBACK must hide the INSERT performed inside the dropped \
             transaction; got {count_after_drop} (regression indicates the Drop \
             poison path is not draining)"
        );

        // Server-side proof: MySQL itself must agree the connection is
        // out of the transaction. @@in_transaction is server-side state,
        // not anything our wire codec can fake.
        log.phase("server_side_in_transaction_off");
        let post_drain = unwrap_mysql(
            conn.query_unchecked(&cx, "SELECT @@in_transaction AS in_txn")
                .await,
            "post_drain_in_transaction",
            &log,
        );
        let post_drain_in_txn = post_drain[0].get_i64("in_txn").expect("post_drain in_txn");
        log.line(
            "assertion",
            &[
                ("field", "post_drain_in_txn".to_string()),
                ("expected", "0".to_string()),
                ("actual", post_drain_in_txn.to_string()),
            ],
        );
        assert_eq!(
            post_drain_in_txn, 0,
            "after drain, MySQL must report the connection is no longer \
             inside a transaction; got @@in_transaction={post_drain_in_txn}"
        );

        // Connection must remain genuinely usable: write, then read.
        log.phase("write_after_drop");
        let affected = unwrap_mysql(
            conn.execute_unchecked(
                &cx,
                "INSERT INTO asupersync_llwouh_drop_rollback \
                 (id, payload) VALUES (2, 'after-drop')",
            )
            .await,
            "post_drop_insert",
            &log,
        );
        log.line(
            "assertion",
            &[
                ("field", "post_drop_insert_affected".to_string()),
                ("expected", "1".to_string()),
                ("actual", affected.to_string()),
            ],
        );
        assert_eq!(affected, 1, "post-drain INSERT must succeed");

        log.phase("read_after_drop");
        let final_rows = unwrap_mysql(
            conn.query_unchecked(
                &cx,
                "SELECT id, payload FROM asupersync_llwouh_drop_rollback ORDER BY id",
            )
            .await,
            "post_drop_select",
            &log,
        );
        assert_eq!(
            final_rows.len(),
            1,
            "only the post-drop INSERT must be visible; got {} rows",
            final_rows.len()
        );
        let id = final_rows[0].get_i64("id").expect("id");
        log.line(
            "assertion",
            &[
                ("field", "final_id".to_string()),
                ("expected", "2".to_string()),
                ("actual", id.to_string()),
            ],
        );
        assert_eq!(
            id, 2,
            "visible row must be the post-drop INSERT, not the abandoned one"
        );

        log.phase("close");
        conn.close().await.expect("close");
        log.end("pass");
    });
}

fn log_elapsed_ms(log: &MySqlTestLogger) -> u128 {
    log.start.elapsed().as_millis()
}
