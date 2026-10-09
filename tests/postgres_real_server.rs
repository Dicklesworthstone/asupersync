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
// An integration test is its own crate and does not inherit `src/lib.rs`'s
// `recursion_limit`. Proving `Send` for its async chains exceeds rustc's default
// depth, which the future-incompatible `recursion_depth_exceeding_limit` lint
// (rust-lang #159228) will turn into a hard error.
#![recursion_limit = "256"]

use asupersync::channel::oneshot;
use asupersync::cx::Cx;
use asupersync::database::postgres::{Format, PgConnectOptions, PgConnection, PgError};
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
                // A Unix-domain socket directory is local by construction.
                || opts.host.starts_with('/')
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

/// Export text and binary COPY data, drain a partly consumed export, and run a
/// normal query on the same real PostgreSQL connection afterward.
#[test]
fn pg_real_copy_out_streams_and_drains_then_reuses_connection() {
    let cfg = RealPgConfig::from_env();
    if skip_if_disabled(&cfg, "pg_real_copy_out_streams_and_drains_then_reuses_connection") {
        return;
    }
    let log = PgTestLogger::new(
        "postgres_real",
        "pg_real_copy_out_streams_and_drains_then_reuses_connection",
    );

    run_test_with_cx(|cx| async move {
        log.phase("connect");
        let mut conn = unwrap_pg(PgConnection::connect(&cx, &cfg.url).await, &log, "connect");

        log.phase("copy_text_export");
        let mut copy = unwrap_pg(
            conn.copy_out(
                &cx,
                "COPY (SELECT id, name FROM (VALUES (1, 'alice'), (2, 'bob')) \
                 AS exported_rows(id, name) ORDER BY id) TO STDOUT WITH (FORMAT text)",
            )
            .await,
            &log,
            "copy_text_start",
        );
        assert_eq!(copy.response().overall_format(), Format::Text);
        assert_eq!(copy.response().column_formats(), &[Format::Text, Format::Text]);
        let mut text = Vec::new();
        while let Some(chunk) = unwrap_pg(copy.next_chunk(&cx).await, &log, "copy_text_chunk") {
            text.extend_from_slice(&chunk);
        }
        assert_eq!(text, b"1\talice\n2\tbob\n");
        let complete = unwrap_pg(copy.finish(&cx).await, &log, "copy_text_finish");
        assert_eq!(complete.affected_rows(), 2);
        assert_eq!(complete.bytes_received(), text.len() as u64);
        assert!(complete.chunks_received() > 0);
        log.assert_match("copy_text_rows", "2", &complete.affected_rows().to_string());

        log.phase("copy_binary_export");
        let mut copy = unwrap_pg(
            conn.copy_out(&cx, "COPY (SELECT 42::int4 AS id) TO STDOUT WITH (FORMAT binary)")
                .await,
            &log,
            "copy_binary_start",
        );
        assert_eq!(copy.response().overall_format(), Format::Binary);
        assert_eq!(copy.response().column_formats(), &[Format::Binary]);
        let mut binary = Vec::new();
        while let Some(chunk) = unwrap_pg(copy.next_chunk(&cx).await, &log, "copy_binary_chunk") {
            binary.extend_from_slice(&chunk);
        }
        let mut expected_binary = b"PGCOPY\n\xff\r\n\0".to_vec();
        expected_binary.extend_from_slice(&0u32.to_be_bytes());
        expected_binary.extend_from_slice(&0u32.to_be_bytes());
        expected_binary.extend_from_slice(&1i16.to_be_bytes());
        expected_binary.extend_from_slice(&4i32.to_be_bytes());
        expected_binary.extend_from_slice(&42i32.to_be_bytes());
        expected_binary.extend_from_slice(&(-1i16).to_be_bytes());
        assert_eq!(binary, expected_binary, "binary COPY bytes must remain exact");
        let complete = unwrap_pg(copy.finish(&cx).await, &log, "copy_binary_finish");
        assert_eq!(complete.affected_rows(), 1);
        assert_eq!(complete.bytes_received(), expected_binary.len() as u64);

        log.phase("copy_finish_drains_unread_rows");
        let mut copy = unwrap_pg(
            conn.copy_out(
                &cx,
                "COPY (SELECT generate_series(1, 10000)) TO STDOUT WITH (FORMAT text)",
            )
            .await,
            &log,
            "copy_drain_start",
        );
        let first = unwrap_pg(copy.next_chunk(&cx).await, &log, "copy_drain_first")
            .expect("nonempty export has a first chunk");
        assert!(!first.is_empty());
        let complete = unwrap_pg(copy.finish(&cx).await, &log, "copy_drain_finish");
        assert_eq!(complete.affected_rows(), 10_000);
        let expected_bytes: usize = (1..=10_000).map(|row| row.to_string().len() + 1).sum();
        assert_eq!(complete.bytes_received(), expected_bytes as u64);
        log.assert_match("copy_drained_rows", "10000", &complete.affected_rows().to_string());

        log.phase("copy_server_error");
        let failed_export = match conn.copy_out(&cx, "COPY (SELECT 1 / 0) TO STDOUT").await {
            Outcome::Ok(copy) => copy.finish(&cx).await.map(drop),
            other => other.map(drop),
        };
        match failed_export {
            Outcome::Err(error) => assert_eq!(error.error_code(), Some("22012")),
            other => panic!("expected COPY division-by-zero SQLSTATE 22012, got {other:?}"),
        }

        log.phase("query_after_exports_and_error");
        let rows = unwrap_pg(
            conn.query_unchecked(&cx, "SELECT 42::int4 AS answer").await,
            &log,
            "query_after_copy",
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get_i32("answer").expect("answer int4"), 42);
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

/// A pool built with `PgConnectionManager::reset_session_on_return(true)`
/// hands its next borrower a clean server session on the same backend: no
/// `set_config` tenant value, temporary table, session advisory lock or
/// `LISTEN` registration or statement-timeout override of the previous
/// borrower survives, and a statement handle prepared before the reset
/// re-prepares transparently. The default
/// manager keeps the session, which the control pass pins as documented.
#[test]
fn pg_real_pool_session_reset_isolates_borrowers() {
    use asupersync::database::pool::{AsyncDbPool, DbPoolConfig};
    use asupersync::database::postgres::{PgConnectionManager, ToSql};

    let cfg = RealPgConfig::from_env();
    if skip_if_disabled(&cfg, "pg_real_pool_session_reset_isolates_borrowers") {
        return;
    }
    let log = PgTestLogger::new(
        "postgres_real",
        "pg_real_pool_session_reset_isolates_borrowers",
    );

    run_test_with_cx(|cx| async move {
        for reset in [false, true] {
            log.phase(if reset { "reset_pool" } else { "default_pool" });
            let options = PgConnectOptions::parse(&cfg.url).expect("parse POSTGRES_URL");
            let manager = PgConnectionManager::new(options).reset_session_on_return(reset);
            let pool = AsyncDbPool::new(manager, DbPoolConfig::with_max_size(1));
            let lock_key = if reset { 7_340_101 } else { 7_340_100 };

            let (backend, stmt) = {
                let mut conn = pool.get(&cx).await.expect("first borrow");
                let rows = unwrap_pg(
                    conn.query_unchecked(
                        &cx,
                        &format!(
                            "SELECT pg_backend_pid()::int4 AS pid, \
                             set_config('app.tenant', 'acme', false) AS tenant, \
                             pg_try_advisory_lock({lock_key}) AS locked"
                        ),
                    )
                    .await,
                    &log,
                    "session_state",
                );
                assert!(rows[0].get_bool("locked").expect("locked"));
                unwrap_pg(
                    conn.execute_unchecked(&cx, "CREATE TEMP TABLE borrower_scratch (v int4)")
                        .await,
                    &log,
                    "temp_table",
                );
                unwrap_pg(conn.listen(&cx, "borrower_a_events").await, &log, "listen");
                conn.set_statement_timeout_override(Some(Duration::from_secs(30)));
                let stmt = unwrap_pg(
                    conn.prepare(&cx, "SELECT $1::int4 AS v").await,
                    &log,
                    "prepare",
                );
                (rows[0].get_i32("pid").expect("pid"), stmt)
            };

            let mut conn = pool.get(&cx).await.expect("second borrow");
            let rows = unwrap_pg(
                conn.query_unchecked(
                    &cx,
                    "SELECT pg_backend_pid()::int4 AS pid, \
                     coalesce(current_setting('app.tenant', true), '') AS tenant, \
                     (SELECT count(*)::int4 FROM pg_locks \
                      WHERE locktype = 'advisory' AND pid = pg_backend_pid()) AS locks, \
                     (SELECT count(*)::int4 FROM pg_listening_channels()) AS listening, \
                     to_regclass('pg_temp.borrower_scratch') IS NOT NULL AS has_temp",
                )
                .await,
                &log,
                "inspect_session",
            );
            let row = &rows[0];
            assert_eq!(
                row.get_i32("pid").expect("pid"),
                backend,
                "same backend reused"
            );
            let tenant = row.get_str("tenant").expect("tenant");
            let locks = row.get_i32("locks").expect("locks");
            let listening = row.get_i32("listening").expect("listening");
            let has_temp = row.get_bool("has_temp").expect("has_temp");
            log.line(
                "second_borrower_session",
                &[
                    ("reset", &reset.to_string()),
                    ("tenant", tenant),
                    ("locks", &locks.to_string()),
                    ("listening", &listening.to_string()),
                    ("has_temp", &has_temp.to_string()),
                ],
            );
            if reset {
                assert_eq!((tenant, locks, listening, has_temp), ("", 0, 0, false));
            } else {
                assert_eq!((tenant, locks, listening, has_temp), ("acme", 1, 1, true));
            }

            assert_eq!(
                conn.statement_timeout_override(),
                (!reset).then_some(Duration::from_secs(30)),
                "a reset also clears the previous borrower's timeout override"
            );

            let seven = 7_i32;
            let params: &[&dyn ToSql] = &[&seven];
            let rows = unwrap_pg(
                conn.query_prepared(&cx, &stmt, params).await,
                &log,
                "held_stmt",
            );
            assert_eq!(rows[0].get_i32("v").expect("v"), 7);
            if !reset {
                unwrap_pg(
                    conn.query_unchecked(&cx, "SELECT pg_advisory_unlock_all()")
                        .await,
                    &log,
                    "unlock",
                );
            }
        }
        log.end("pass");
    });
}

/// A host that is an absolute path names the server's Unix-domain socket
/// directory, as in libpq. Set `POSTGRES_SOCKET_DIR` (for example
/// `/var/run/postgresql`) to the server's `unix_socket_directories`; the test
/// connects with the credentials of `POSTGRES_URL` through
/// `<dir>/.s.PGSQL.<port>` and checks that the server sees a socket client
/// (`inet_client_addr()` is NULL). Setting `POSTGRES_URL` itself to
/// `postgres://user:password@/db?host=<dir>` runs every test of this suite
/// over the socket, the CancelRequest journeys included.
#[test]
fn pg_real_unix_socket_host_connects_over_the_socket() {
    let cfg = RealPgConfig::from_env();
    let test_name = "pg_real_unix_socket_host_connects_over_the_socket";
    if skip_if_disabled(&cfg, test_name) {
        return;
    }
    let Ok(dir) = std::env::var("POSTGRES_SOCKET_DIR") else {
        eprintln!(
            r#"{{"suite":"postgres_real","test":"{test_name}","event":"skip","reason":"POSTGRES_SOCKET_DIR not set"}}"#
        );
        return;
    };
    let log = PgTestLogger::new("postgres_real", test_name);

    // The URL spellings that name a socket directory.
    let encoded = dir.replace('/', "%2F");
    let by_host = PgConnectOptions::parse(&format!("postgres://u@{encoded}:6543/db"))
        .expect("percent-encoded socket directory");
    assert_eq!((by_host.host.as_str(), by_host.port), (dir.as_str(), 6543));
    let by_param =
        PgConnectOptions::parse(&format!("postgres:///db?host={dir}")).expect("host parameter");
    assert_eq!(by_param.host, dir);
    assert!(
        PgConnectOptions::parse("postgres:///db").is_err(),
        "still no host"
    );

    run_test_with_cx(|cx| async move {
        let mut options = PgConnectOptions::parse(&cfg.url).expect("parse POSTGRES_URL");
        options.host = dir.clone();
        log.phase("connect_over_socket");
        let mut conn = unwrap_pg(
            PgConnection::connect_with_options(&cx, options).await,
            &log,
            "connect",
        );
        let rows = unwrap_pg(
            conn.query_unchecked(
                &cx,
                "SELECT (inet_client_addr() IS NULL) AS via_socket, 7::int4 AS v",
            )
            .await,
            &log,
            "query",
        );
        assert!(rows[0].get_bool("via_socket").expect("via_socket"));
        assert_eq!(rows[0].get_i32("v").expect("v"), 7);

        log.end("pass");
    });
}

/// One-dimensional arrays round-trip through a real server: `Vec<T>` binds as
/// the matching array type (on the unprepared and the prepared path), a batch
/// lookup takes it through `= ANY($1)`, and array columns decode into
/// `Vec<T>` from the server's text output, including quoting, NULL elements
/// and the empty array.
#[test]
fn pg_real_arrays_bind_and_decode() {
    use asupersync::database::postgres::ToSql;

    let cfg = RealPgConfig::from_env();
    if skip_if_disabled(&cfg, "pg_real_arrays_bind_and_decode") {
        return;
    }
    let log = PgTestLogger::new("postgres_real", "pg_real_arrays_bind_and_decode");

    run_test_with_cx(|cx| async move {
        let mut conn = unwrap_pg(PgConnection::connect(&cx, &cfg.url).await, &log, "connect");

        log.phase("any_batch_lookup");
        let wanted = vec![2_i32, 5, 7, 42];
        let params: &[&dyn ToSql] = &[&wanted];
        let rows = unwrap_pg(
            conn.query_params(
                &cx,
                "SELECT count(*)::int4 AS n FROM generate_series(1, 10) AS g WHERE g = ANY($1)",
                params,
            )
            .await,
            &log,
            "any",
        );
        assert_eq!(rows[0].get_i32("n").expect("n"), 3);

        log.phase("round_trip");
        let ints = vec![1_i64, -2, i64::MAX];
        let names = vec![
            Some("plain".to_string()),
            Some("a b".to_string()),
            Some("q\"u".to_string()),
            Some("back\\slash".to_string()),
            Some(String::new()),
            None,
            Some("NULL".to_string()),
            Some("{x,y}".to_string()),
        ];
        let flags = vec![true, false];
        let floats = vec![1.5_f64, -0.25];
        let blobs = vec![vec![0_u8, 255], Vec::new()];
        let empty: Vec<i32> = Vec::new();
        let params: &[&dyn ToSql] = &[&ints, &names, &flags, &floats, &blobs, &empty];
        let rows = unwrap_pg(
            conn.query_params(
                &cx,
                "SELECT $1 AS ints, $2 AS names, $3 AS flags, $4 AS floats, $5 AS blobs, \
                 $6 AS empty, cardinality($6) AS empty_len",
                params,
            )
            .await,
            &log,
            "round_trip",
        );
        let row = &rows[0];
        assert_eq!(row.get_typed::<Vec<i64>>("ints").expect("ints"), ints);
        assert_eq!(
            row.get_typed::<Vec<Option<String>>>("names")
                .expect("names"),
            names
        );
        assert_eq!(row.get_typed::<Vec<bool>>("flags").expect("flags"), flags);
        assert_eq!(row.get_typed::<Vec<f64>>("floats").expect("floats"), floats);
        assert_eq!(
            row.get_typed::<Vec<Vec<u8>>>("blobs").expect("blobs"),
            blobs
        );
        assert!(
            row.get_typed::<Vec<i32>>("empty")
                .expect("empty")
                .is_empty()
        );
        assert_eq!(row.get_i32("empty_len").expect("empty_len"), 0);

        log.phase("prepared");
        let stmt = unwrap_pg(
            conn.prepare(
                &cx,
                "SELECT array_length($1::text[], 1) AS n, $1::text[] AS same",
            )
            .await,
            &log,
            "prepare",
        );
        let tags = vec!["red", "green", "blue"];
        let params: &[&dyn ToSql] = &[&tags];
        let rows = unwrap_pg(
            conn.query_prepared(&cx, &stmt, params).await,
            &log,
            "query_prepared",
        );
        assert_eq!(rows[0].get_i32("n").expect("n"), 3);
        assert_eq!(
            rows[0].get_typed::<Vec<String>>("same").expect("same"),
            tags
        );

        log.phase("server_literals");
        let rows = unwrap_pg(
            conn.query_unchecked(
                &cx,
                "SELECT '{1,NULL,3}'::int4[] AS sparse, '[0:1]={5,6}'::int2[] AS shifted, \
                 ARRAY['2026-10-08'::date] AS dates",
            )
            .await,
            &log,
            "literals",
        );
        let row = &rows[0];
        assert_eq!(
            row.get_typed::<Vec<Option<i32>>>("sparse").expect("sparse"),
            [Some(1), None, Some(3)]
        );
        assert_eq!(
            row.get_typed::<Vec<i16>>("shifted").expect("shifted"),
            [5, 6]
        );
        assert_eq!(
            row.get_typed::<Vec<String>>("dates").expect("dates"),
            ["2026-10-08"]
        );
        log.end("pass");
    });
}

/// `SystemTime` and `serde_json::Value` round-trip through a real server: a
/// `SystemTime` binds into `timestamptz` and `timestamp` columns (on the
/// unprepared and the prepared path, and as a `timestamptz[]`), decodes back
/// from the text output in a non-UTC session time zone, and a JSON value binds
/// into `json` and `jsonb` columns and decodes from both.
#[test]
fn pg_real_timestamps_and_json_bind_and_decode() {
    use asupersync::database::postgres::ToSql;

    let cfg = RealPgConfig::from_env();
    if skip_if_disabled(&cfg, "pg_real_timestamps_and_json_bind_and_decode") {
        return;
    }
    let log = PgTestLogger::new(
        "postgres_real",
        "pg_real_timestamps_and_json_bind_and_decode",
    );

    run_test_with_cx(|cx| async move {
        let mut conn = unwrap_pg(PgConnection::connect(&cx, &cfg.url).await, &log, "connect");
        // Offsets with minutes in the text output, and a timestamp column
        // that stores the session's wall time.
        unwrap_pg(
            conn.execute_unchecked(&cx, "SET TimeZone = 'Asia/Kolkata'")
                .await,
            &log,
            "set_timezone",
        );
        unwrap_pg(
            conn.execute_unchecked(
                &cx,
                "CREATE TEMP TABLE asupersync_time_json \
                 (id int4, tz timestamptz, local timestamp, doc json, docb jsonb)",
            )
            .await,
            &log,
            "create",
        );

        log.phase("unprepared");
        // 2026-10-08 06:45:50.123456 UTC.
        let instant = UNIX_EPOCH + Duration::from_micros(1_791_441_950_123_456);
        let doc =
            serde_json::json!({"name": "q\"u", "tags": ["a", 1, null], "nested": {"ok": true}});
        let params: &[&dyn ToSql] = &[&1_i32, &instant, &instant, &doc, &doc];
        unwrap_pg(
            conn.execute_params(
                &cx,
                "INSERT INTO asupersync_time_json VALUES ($1, $2, $3, $4, $5)",
                params,
            )
            .await,
            &log,
            "insert",
        );

        log.phase("prepared");
        let before_2000 = UNIX_EPOCH + Duration::from_secs(86_400 * 365);
        let other = serde_json::json!([1, "two", 3.5]);
        // The server types an uncast $3 as `timestamp`; the binary instant
        // would be stored unconverted, unlike row 1's, so it is refused
        // (br-asupersync-qml5yb).
        let uncast = unwrap_pg(
            conn.prepare(
                &cx,
                "INSERT INTO asupersync_time_json VALUES ($1, $2, $3, $4, $5)",
            )
            .await,
            &log,
            "prepare_uncast",
        );
        let params: &[&dyn ToSql] = &[&2_i32, &before_2000, &before_2000, &other, &other];
        assert!(
            matches!(
                conn.execute_prepared(&cx, &uncast, params).await,
                Outcome::Err(PgError::Protocol(_))
            ),
            "an instant bound where the server inferred timestamp must be refused"
        );
        let stmt = unwrap_pg(
            conn.prepare(
                &cx,
                "INSERT INTO asupersync_time_json VALUES ($1, $2, $3::timestamptz, $4, $5)",
            )
            .await,
            &log,
            "prepare",
        );
        unwrap_pg(
            conn.execute_prepared(&cx, &stmt, params).await,
            &log,
            "execute_prepared",
        );

        log.phase("decode");
        let rows = unwrap_pg(
            conn.query_unchecked(
                &cx,
                "SELECT id, tz, local, doc, docb, tz::text AS tz_text, local::text AS local_text, \
                 local AT TIME ZONE 'Asia/Kolkata' AS local_instant \
                 FROM asupersync_time_json ORDER BY id",
            )
            .await,
            &log,
            "select",
        );
        assert_eq!(rows.len(), 2);
        let first = &rows[0];
        assert_eq!(
            first.get_str("tz_text").expect("tz_text"),
            "2026-10-08 12:15:50.123456+05:30"
        );
        assert_eq!(
            first.get_str("local_text").expect("local_text"),
            "2026-10-08 12:15:50.123456"
        );
        assert_eq!(first.get_typed::<SystemTime>("tz").expect("tz"), instant);
        assert_eq!(
            first.get_typed::<serde_json::Value>("doc").expect("doc"),
            doc
        );
        assert_eq!(
            first.get_typed::<serde_json::Value>("docb").expect("docb"),
            doc
        );
        let second = &rows[1];
        assert_eq!(
            second.get_typed::<SystemTime>("tz").expect("tz"),
            before_2000
        );
        // Both paths store the session's wall time in the `timestamp`
        // column: 1971-01-01 00:00 UTC is 05:30 in Kolkata.
        assert_eq!(
            second.get_str("local_text").expect("local_text"),
            "1971-01-01 05:30:00"
        );
        // A `timestamp` names no instant and is refused; read through the
        // zone it was written in, each row gives back its instant.
        assert!(first.get_typed::<SystemTime>("local").is_err());
        for (row, expected) in [(first, instant), (second, before_2000)] {
            assert_eq!(
                row.get_typed::<SystemTime>("local_instant")
                    .expect("local_instant"),
                expected
            );
        }
        assert_eq!(
            second.get_typed::<serde_json::Value>("docb").expect("docb"),
            other
        );

        log.phase("arrays");
        let instants = vec![instant, before_2000];
        let params: &[&dyn ToSql] = &[&instants];
        let rows = unwrap_pg(
            conn.query_params(
                &cx,
                "SELECT $1 AS same, (SELECT count(*)::int4 FROM asupersync_time_json \
                 WHERE tz = ANY($1)) AS matched",
                params,
            )
            .await,
            &log,
            "arrays",
        );
        assert_eq!(
            rows[0].get_typed::<Vec<SystemTime>>("same").expect("same"),
            instants
        );
        assert_eq!(rows[0].get_i32("matched").expect("matched"), 2);

        log.phase("infinity");
        let rows = unwrap_pg(
            conn.query_unchecked(&cx, "SELECT 'infinity'::timestamptz AS forever")
                .await,
            &log,
            "infinity",
        );
        assert!(rows[0].get_typed::<SystemTime>("forever").is_err());
        log.end("pass");
    });
}

/// `Untyped` text binds into columns whose types `text` does not convert to
/// (uuid, numeric, inet, date, interval) and into a comparison, on the
/// unprepared and the prepared path; the same value bound as `&str` is
/// refused, which is what `Untyped` exists for.
#[test]
fn pg_real_untyped_text_binds_where_the_server_infers_the_type() {
    use asupersync::database::postgres::{ToSql, Untyped};

    let cfg = RealPgConfig::from_env();
    if skip_if_disabled(
        &cfg,
        "pg_real_untyped_text_binds_where_the_server_infers_the_type",
    ) {
        return;
    }
    let log = PgTestLogger::new(
        "postgres_real",
        "pg_real_untyped_text_binds_where_the_server_infers_the_type",
    );

    run_test_with_cx(|cx| async move {
        let mut conn = unwrap_pg(PgConnection::connect(&cx, &cfg.url).await, &log, "connect");
        unwrap_pg(
            conn.execute_unchecked(
                &cx,
                "CREATE TEMP TABLE asupersync_untyped \
                 (id uuid, amount numeric(10, 2), addr inet, day date, span interval)",
            )
            .await,
            &log,
            "create",
        );
        let insert = "INSERT INTO asupersync_untyped VALUES ($1, $2, $3, $4, $5)";

        log.phase("typed_text_refused");
        let id = "6f1c2d3e-4b5a-4c6d-8e7f-0123456789ab";
        let params: &[&dyn ToSql] = &[&id, &"12.50", &"10.0.0.1", &"2026-10-08", &"1 day"];
        match conn.execute_params(&cx, insert, params).await {
            Outcome::Err(PgError::Server { code, .. }) => assert_eq!(code, "42804"),
            other => panic!("text into uuid must be refused: {other:?}"),
        }

        log.phase("unprepared");
        let params: &[&dyn ToSql] = &[
            &Untyped(id),
            &Untyped("12.50"),
            &Untyped("10.0.0.1"),
            &Untyped("2026-10-08"),
            &Untyped("1 day 02:00:00"),
        ];
        unwrap_pg(
            conn.execute_params(&cx, insert, params).await,
            &log,
            "insert",
        );

        log.phase("prepared");
        let stmt = unwrap_pg(conn.prepare(&cx, insert).await, &log, "prepare");
        let second = "00000000-0000-0000-0000-000000000002";
        let params: &[&dyn ToSql] = &[
            &Untyped(second),
            &Untyped("0.05"),
            &Untyped("::1"),
            &Untyped("1999-12-31"),
            &Untyped("-3 hours"),
        ];
        unwrap_pg(
            conn.execute_prepared(&cx, &stmt, params).await,
            &log,
            "execute_prepared",
        );

        log.phase("compare");
        let params: &[&dyn ToSql] = &[&Untyped(id)];
        let rows = unwrap_pg(
            conn.query_params(
                &cx,
                "SELECT id::text AS id, amount::text AS amount, addr::text AS addr, \
                 day::text AS day, span::text AS span FROM asupersync_untyped WHERE id = $1",
                params,
            )
            .await,
            &log,
            "select",
        );
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.get_str("id").expect("id"), id);
        assert_eq!(row.get_str("amount").expect("amount"), "12.50");
        assert_eq!(row.get_str("addr").expect("addr"), "10.0.0.1/32");
        assert_eq!(row.get_str("day").expect("day"), "2026-10-08");
        assert_eq!(row.get_str("span").expect("span"), "1 day 02:00:00");
        // Text output of these types also decodes into String directly.
        let rows = unwrap_pg(
            conn.query_unchecked(
                &cx,
                "SELECT id, amount FROM asupersync_untyped ORDER BY day",
            )
            .await,
            &log,
            "select_native",
        );
        assert_eq!(rows[0].get_typed::<String>("id").expect("uuid"), second);
        assert_eq!(
            rows[0].get_typed::<String>("amount").expect("numeric"),
            "0.05"
        );
        log.end("pass");
    });
}
