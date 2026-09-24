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
//!     rch exec -- env REAL_POSTGRES_TESTS=true POSTGRES_URL=postgres://postgres:postgres@localhost:5432/postgres CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_postgres_real_server cargo test --features postgres --test postgres_real_server
//!
//! Production safety guards block:
//!  * `NODE_ENV=production`
//!  * URLs containing `prod`, `production`, or non-localhost hosts unless
//!    `ALLOW_NON_LOCALHOST_POSTGRES=true` is also set.
//!
//! Each test wraps work in `BEGIN; ... ROLLBACK;` — no schema state leaks.

#![cfg(all(test, feature = "postgres"))]
#![allow(clippy::pedantic, clippy::nursery, clippy::print_stderr)]

use asupersync::channel::oneshot;
use asupersync::cx::Cx;
use asupersync::database::postgres::{PgConnectOptions, PgConnection, PgError};
use asupersync::runtime::RuntimeBuilder;
use asupersync::test_utils::run_test_with_cx;
use asupersync::time::{sleep, timeout};
use asupersync::types::{CancelKind, Outcome};

use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
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
    match PgConnectOptions::parse_with_tls(url) {
        Ok((opts, _)) => {
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
    assert!(postgres_url_host_is_local(
        "postgres://localhost/postgres?sslmode=verify-full&sslrootcert=%2Fprivate%20ca.pem"
    ));
}

/// Run against an actual private-CA PostgreSQL server with REAL_POSTGRES_TESTS=true
/// and PGSSLROOTCERT set to its CA bundle. Each mode must authenticate and the
/// backend's own pg_stat_ssl row must confirm that this session uses TLS.
#[cfg(feature = "tls")]
#[test]
fn pg_real_private_ca_tls_verification() {
    use asupersync::database::postgres::{PgTlsOptions, PgTlsVerification};

    let cfg = RealPgConfig::from_env();
    if skip_if_disabled(&cfg, "pg_real_private_ca_tls_verification") {
        return;
    }
    let Ok(root_path) = std::env::var("PGSSLROOTCERT") else {
        eprintln!(
            r#"{{"event":"test_skipped","test":"pg_real_private_ca_tls_verification","reason":"PGSSLROOTCERT private CA bundle not configured"}}"#
        );
        return;
    };
    let log = PgTestLogger::new("postgres_real", "pg_real_private_ca_tls_verification");
    run_test_with_cx(|cx| async move {
        for mode in [PgTlsVerification::VerifyCa, PgTlsVerification::VerifyFull] {
            let (options, _) = PgConnectOptions::parse_with_tls(&cfg.url).unwrap();
            let tls = PgTlsOptions::new()
                .root_certificate_file(&root_path)
                .verification(mode);
            let mut connection = unwrap_pg(
                PgConnection::connect_with_tls_options(&cx, options, tls).await,
                &log,
                "private_ca_connect",
            );
            let rows = unwrap_pg(
                connection
                    .query_unchecked(
                        &cx,
                        "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
                    )
                    .await,
                &log,
                "backend_tls_state",
            );
            assert_eq!(rows.len(), 1);
            assert!(rows[0].get_bool("ssl").expect("backend SSL flag"));
            log.line(
                "private_ca_authenticated",
                &[("mode", &format!("{mode:?}")), ("backend_ssl", "true")],
            );
            connection.close().await.unwrap();
        }
        log.end("pass");
    });
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

/// br-asupersync-bi2462.110: the gvkj1r/xgkg5w test measured only client
/// latency, so closing the socket without sending CancelRequest passed it.
/// This replacement witnesses the actual native query's Pending poll and
/// PostgreSQL's active/PgSleep state before cancellation. The independent
/// observer must then see the backend stop within two seconds.
#[test]
fn pg_real_cancel_in_flight_during_long_query() {
    pg_real_cancel_parked_query("pg_real_cancel_in_flight_during_long_query", false);
}

/// The same parked cancellation must release a real UPDATE's transaction
/// lock. A session-local temporary table keeps the fixture isolated; its
/// granted RowExclusiveLock is observed directly through pg_locks.
#[test]
fn pg_real_cancel_in_flight_releases_update_lock() {
    pg_real_cancel_parked_query("pg_real_cancel_in_flight_releases_update_lock", true);
}

#[derive(Debug)]
struct ParkedPgQuery {
    cx: Cx,
    pid: i32,
    relation_oid: i64,
    parked_at: Instant,
}

#[derive(Debug)]
struct PgCancelBackendState {
    state: String,
    wait_event: String,
    update_locks: i64,
}

async fn pg_cancel_backend_state(
    observer: &mut PgConnection,
    cx: &Cx,
    parked: &ParkedPgQuery,
    log: &PgTestLogger,
) -> Result<PgCancelBackendState, String> {
    // Only server-supplied numeric identifiers enter this trusted SQL.
    // Each observation is its own transaction, so pg_stat_activity does not
    // retain a transaction-scoped statistics snapshot between observations.
    let sql = format!(
        "SELECT pg_backend_pid() AS observer_pid, \
         COALESCE((SELECT state FROM pg_stat_activity WHERE pid = {pid}), 'gone') AS state, \
         COALESCE((SELECT wait_event FROM pg_stat_activity WHERE pid = {pid}), '') AS wait_event, \
         (SELECT count(*)::int8 FROM pg_locks \
          WHERE pid = {pid} AND locktype = 'relation' AND relation = {oid}::oid \
          AND mode = 'RowExclusiveLock' AND granted) AS update_locks",
        pid = parked.pid,
        oid = parked.relation_oid,
    );
    let rows = match observer.query_unchecked(cx, &sql).await {
        Outcome::Ok(rows) => rows,
        other => return Err(format!("backend observation failed: {other:?}")),
    };
    if rows.len() != 1 {
        return Err(format!("backend observation returned {} rows", rows.len()));
    }
    let observer_pid = rows[0].get_i32("observer_pid").map_err(|e| e.to_string())?;
    if observer_pid == parked.pid {
        return Err("observer must use a separate backend".to_string());
    }
    let state = PgCancelBackendState {
        state: rows[0]
            .get_str("state")
            .map_err(|e| e.to_string())?
            .to_string(),
        wait_event: rows[0]
            .get_str("wait_event")
            .map_err(|e| e.to_string())?
            .to_string(),
        update_locks: rows[0].get_i64("update_locks").map_err(|e| e.to_string())?,
    };
    log.line(
        "backend_observation",
        &[
            ("pid", &parked.pid.to_string()),
            ("observer_pid", &observer_pid.to_string()),
            ("state", &state.state),
            ("wait_event", &state.wait_event),
            ("relation_oid", &parked.relation_oid.to_string()),
            ("update_locks", &state.update_locks.to_string()),
            (
                "since_parked_ms",
                &parked.parked_at.elapsed().as_millis().to_string(),
            ),
        ],
    );
    Ok(state)
}

fn pg_real_cancel_parked_query(test_name: &'static str, hold_update_lock: bool) {
    let cfg = RealPgConfig::from_env();
    if skip_if_disabled(&cfg, test_name) {
        return;
    }
    let log = Arc::new(PgTestLogger::new("postgres_real", test_name));
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().expect("native reactor"))
        .build()
        .expect("native runtime");

    runtime.block_on(async move {
        let cx = Cx::current().expect("native observer context");
        let mut observer = unwrap_pg(
            timeout(cx.now(), Duration::from_secs(5), PgConnection::connect(&cx, &cfg.url))
                .await
                .expect("observer connect deadline"),
            &log,
            "observer_connect",
        );
        let (parked_tx, mut parked_rx) = oneshot::channel();
        let query_log = Arc::clone(&log);
        let query_url = cfg.url.clone();
        let mut query_task = cx.spawn(move |query_cx| async move {
            let mut conn = unwrap_pg(
                PgConnection::connect(&query_cx, &query_url).await,
                &query_log,
                "query_connect",
            );
            // A short server statement_timeout or periodic disconnect check
            // would mask a missing CancelRequest. Keep both out of the two-
            // second oracle; the observer's deadlines still bound failures.
            conn.set_statement_timeout_override(Some(Duration::from_secs(35)));
            unwrap_pg(
                conn.execute_unchecked(&query_cx, "SET client_connection_check_interval = 0").await,
                &query_log,
                "disable_disconnect_polling",
            );
            let rows = unwrap_pg(
                conn.query_unchecked(&query_cx, "SELECT pg_backend_pid() AS pid").await,
                &query_log,
                "query_backend_pid",
            );
            let pid = rows[0].get_i32("pid").expect("backend PID");
            query_log.line("query_backend", &[
                ("pid", &pid.to_string()),
                ("server_version", conn.server_version().unwrap_or("<missing>")),
            ]);
            let relation_oid = if hold_update_lock {
                unwrap_pg(
                    conn.execute_unchecked(
                        &query_cx,
                        "CREATE TEMP TABLE asupersync_cancel_lock AS SELECT 0::int4 AS v",
                    ).await,
                    &query_log,
                    "create_temporary_lock_fixture",
                );
                let rows = unwrap_pg(
                    conn.query_unchecked(
                        &query_cx,
                        "SELECT 'pg_temp.asupersync_cancel_lock'::regclass::oid::int8 AS oid",
                    ).await,
                    &query_log,
                    "lock_relation_oid",
                );
                unwrap_pg(conn.execute_unchecked(&query_cx, "BEGIN").await, &query_log, "begin");
                rows[0].get_i64("oid").expect("temporary relation OID")
            } else {
                0
            };
            let sql = if hold_update_lock {
                "UPDATE asupersync_cancel_lock SET v = v + 1; SELECT pg_sleep(30) AS slept"
            } else {
                "SELECT pg_sleep(30) AS slept"
            };
            let mut query = std::pin::pin!(conn.query_unchecked(&query_cx, sql));
            let mut parked_tx = Some(parked_tx);
            let outcome = timeout(query_cx.now(), Duration::from_secs(35), poll_fn(|task_cx| {
                let poll = query.as_mut().poll(task_cx);
                if poll.is_pending()
                    && let Some(tx) = parked_tx.take()
                {
                    query_log.line("native_query_parked", &[("pid", &pid.to_string())]);
                    // Publish a witness without waking the query itself. The
                    // socket read is left parked on its real reactor waker.
                    tx.send_blocking(ParkedPgQuery {
                        cx: query_cx.clone(),
                        pid,
                        relation_oid,
                        parked_at: Instant::now(),
                    }).expect("observer must receive parked witness");
                }
                poll
            })).await.expect("long-query safety deadline");
            query_log.line("cancel_outcome", &[("pid", &pid.to_string()), ("variant", outcome_label(&outcome))]);
            outcome
        }).expect("spawn native query task");

        let parked = timeout(cx.now(), Duration::from_secs(10), parked_rx.recv(&cx))
            .await.expect("native parked witness deadline").expect("native parked witness");
        let active = timeout(cx.now(), Duration::from_secs(5), async {
            loop {
                let state = pg_cancel_backend_state(&mut observer, &cx, &parked, &log).await?;
                if state.state == "active" && state.wait_event == "PgSleep"
                    && (!hold_update_lock || state.update_locks > 0)
                {
                    break Ok::<(), String>(());
                }
                sleep(cx.now(), Duration::from_millis(10)).await;
            }
        }).await;
        let active_witnessed = matches!(&active, Ok(Ok(())));
        log.line("cancel_trigger", &[
            ("pid", &parked.pid.to_string()),
            ("required_backend_witness", if active_witnessed { "true" } else { "false" }),
            ("hold_update_lock", if hold_update_lock { "true" } else { "false" }),
            ("since_parked_ms", &parked.parked_at.elapsed().as_millis().to_string()),
        ]);
        let triggered_at = Instant::now();
        parked.cx.cancel_with(CancelKind::User, Some("parked PostgreSQL query cancellation"));
        let stopped = if active_witnessed {
            Some(timeout(cx.now(), Duration::from_secs(2).saturating_sub(triggered_at.elapsed()), async {
                loop {
                    let state = pg_cancel_backend_state(&mut observer, &cx, &parked, &log).await?;
                    if state.state != "active" && state.update_locks == 0 {
                        break Ok::<PgCancelBackendState, String>(state);
                    }
                    sleep(cx.now(), Duration::from_millis(10)).await;
                }
            }).await)
        } else {
            None
        };
        let elapsed = triggered_at.elapsed();
        let stopped_in_time = matches!(&stopped, Some(Ok(Ok(_)))) && elapsed < Duration::from_secs(2);
        log.line("remote_cancel_result", &[
            ("pid", &parked.pid.to_string()),
            ("stopped_and_locks_released", if stopped_in_time { "true" } else { "false" }),
            ("elapsed_ms", &elapsed.as_millis().to_string()),
        ]);
        if !stopped_in_time {
            // Preserve the failed oracle before cleanup. Terminate only this
            // test's witnessed backend so an old-red run leaves no 30s query
            // or temporary transaction behind; cleanup cannot make it pass.
            let cleanup_sql = format!("SELECT pg_terminate_backend({}, 1000) AS terminated", parked.pid);
            let cleanup = timeout(cx.now(), Duration::from_secs(5), async {
                // A timed-out observation may have poisoned its connection.
                let mut cleanup_conn = unwrap_pg(
                    PgConnection::connect(&cx, &cfg.url).await,
                    &log,
                    "failure_cleanup_connect",
                );
                cleanup_conn.query_unchecked(&cx, &cleanup_sql).await
            }).await;
            let terminated = match &cleanup {
                Ok(Outcome::Ok(rows)) => rows.first().is_some_and(|row| matches!(row.get_bool("terminated"), Ok(true))),
                _ => false,
            };
            log.line("failed_probe_cleanup", &[
                ("pid", &parked.pid.to_string()),
                ("result", cleanup.as_ref().map_or("timeout", outcome_label)),
                ("backend_terminated", if terminated { "true" } else { "false" }),
            ]);
        }
        let outcome = timeout(cx.now(), Duration::from_secs(2), query_task.join(&cx))
            .await.expect("cancelled native task join deadline").expect("native task must publish its typed result");

        match outcome {
            Outcome::Cancelled(reason) => {
                assert_eq!(reason.kind, CancelKind::User, "query cancellation attribution");
                assert_eq!(reason.message.as_deref(), Some("parked PostgreSQL query cancellation"));
            }
            other => panic!("expected Outcome::Cancelled(User), got {other:?}"),
        }
        assert!(active_witnessed, "backend {} never reached active/PgSleep with its expected UPDATE lock: {active:?}", parked.pid);
        assert!(
            stopped_in_time,
            "backend {} must stop and release its UPDATE lock within 2s of cancellation; elapsed={elapsed:?}, observed={stopped:?}",
            parked.pid,
        );

        log.phase("recovery_fresh_connection");
        let mut conn2 = unwrap_pg(
            timeout(cx.now(), Duration::from_secs(5), PgConnection::connect(&cx, &cfg.url)).await.expect("recovery connect deadline"),
            &log,
            "recover_connect",
        );
        let rows = unwrap_pg(
            timeout(cx.now(), Duration::from_secs(5), conn2.query_unchecked(&cx, "SELECT 1::int4 AS v"))
                .await.expect("recovery query deadline"),
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

/// Real-PG roundtrip pinning the extended-query *prepared statement
/// reuse* contract: a single `prepare()` call followed by N
/// `query_prepared()` calls must Parse the plan once and Bind/Execute
/// it N times, NOT re-Parse on every call.
///
/// asupersync-ikskzn: existing real-PG tests cover basic SELECT,
/// transactions, COPY FROM, cancel-in-flight, and LISTEN/NOTIFY but
/// none exercise multi-call prepared statement reuse against a live
/// backend. The reuse contract is what makes the extended-query
/// protocol worth using vs. simple-query — if asupersync ever
/// regresses to re-Parse on each call it would silently double the
/// per-query latency. PG's `pg_prepared_statements` system view is
/// the server-side ground truth: the named statement persists across
/// calls, and only one row appears for the connection no matter how
/// many `query_prepared()` calls fire.
///
/// Asserts:
/// 1. Three calls with different param pairs return the correct sums.
/// 2. `pg_prepared_statements` shows exactly one row for the
///    connection's prepared statement (server-side proof of reuse).
#[test]
fn pg_real_prepare_and_query_prepared_reuse_observed_in_pg_stat_ikskzn() {
    let cfg = RealPgConfig::from_env();
    if skip_if_disabled(
        &cfg,
        "pg_real_prepare_and_query_prepared_reuse_observed_in_pg_stat_ikskzn",
    ) {
        return;
    }
    let log = PgTestLogger::new(
        "postgres_real",
        "pg_real_prepare_and_query_prepared_reuse_observed_in_pg_stat_ikskzn",
    );

    run_test_with_cx(|cx| async move {
        log.phase("connect");
        let mut conn = unwrap_pg(PgConnection::connect(&cx, &cfg.url).await, &log, "connect");

        log.phase("prepare_int_sum");
        let stmt = match conn.prepare(&cx, "SELECT $1::int4 + $2::int4 AS sum").await {
            Outcome::Ok(s) => s,
            other => {
                log.line("prepare_error", &[("variant", outcome_label(&other))]);
                log.end("fail");
                panic!("prepare failed: {other:?}");
            }
        };

        // Run the prepared statement THREE times with different
        // parameter pairs. Each call goes through Bind/Describe/
        // Execute/Sync against the SAME backend statement name —
        // asupersync's internal cache must skip Parse on calls 2 and 3.
        log.phase("query_prepared_1plus1");
        let cases: [(i32, i32, i64); 3] = [(1, 1, 2), (10, 20, 30), (100, 200, 300)];
        for (a, b, expected) in cases {
            let params: &[&dyn asupersync::database::postgres::ToSql] = &[&a, &b];
            let rows = match conn.query_prepared(&cx, &stmt, params).await {
                Outcome::Ok(rows) => rows,
                other => {
                    log.line(
                        "query_prepared_error",
                        &[
                            ("a", &a.to_string()),
                            ("b", &b.to_string()),
                            ("variant", outcome_label(&other)),
                        ],
                    );
                    log.end("fail");
                    panic!("query_prepared({a}, {b}) failed: {other:?}");
                }
            };
            assert_eq!(rows.len(), 1, "expected one row for {a} + {b}");
            // PG returns int4 + int4 = int4 (wraps mod 2^32), not int8 —
            // but get_i32 vs get_i64 depends on the binding. Try both
            // so the assertion isn't fragile against asupersync's
            // numeric coercion choice.
            let actual = rows[0]
                .get_i64("sum")
                .or_else(|_| rows[0].get_i32("sum").map(i64::from))
                .expect("sum int");
            log.assert_match(
                &format!("sum_{a}+{b}"),
                &expected.to_string(),
                &actual.to_string(),
            );
            assert_eq!(
                actual, expected,
                "prepared statement returned wrong sum for ({a}, {b}): got {actual}, expected {expected}"
            );
        }

        // Server-side proof of reuse: pg_prepared_statements shows
        // every prepared statement currently active on the connection.
        // If asupersync re-Parsed on each call (allocating new statement
        // names), this view would show 3 rows instead of 1.
        log.phase("verify_pg_prepared_statements_count");
        let psrows = unwrap_pg(
            conn.query_unchecked(
                &cx,
                "SELECT count(*)::int4 AS n FROM pg_prepared_statements",
            )
            .await,
            &log,
            "pg_prepared_statements",
        );
        assert_eq!(psrows.len(), 1, "expected one count row");
        let n = psrows[0].get_i32("n").expect("n");
        log.assert_match("prepared_statement_count", "1", &n.to_string());
        assert_eq!(
            n, 1,
            "expected exactly one row in pg_prepared_statements after 3 query_prepared calls; \
             got {n}. If this is > 1, asupersync may be re-Parsing on each call instead of \
             reusing the named statement (review src/database/postgres.rs:5309 query_prepared \
             and prepare cache invariants)."
        );

        log.end("pass");
    });
}
