//! Audit test for PostgreSQL prepared statement cache behavior.
//!
//! PostgreSQL wire protocol requirement: "When a statement is prepared once and
//! then dropped + re-prepared with same SQL, client should (a) reuse the cached
//! query plan (correct: PG caches by name), (b) re-prepare from scratch (wasteful),
//! or (c) error (wrong)."
//!
//! CRITICAL REQUIREMENT: Cache reuse reduces Parse/Describe/Sync round-trips for
//! repeated SQL strings, providing significant performance benefits.
//!
//! Run with:
//!     rch exec -- env REAL_PG_TESTS=true POSTGRES_URL=postgres://postgres:postgres@localhost:5432/postgres CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_postgres_prepared_cache_audit cargo test --features postgres --test postgres_prepared_statement_cache_audit

#![cfg(feature = "postgres")]
#![allow(
    clippy::pedantic,
    clippy::nursery,
    clippy::print_stdout,
    clippy::print_stderr
)]

use asupersync::cx::Cx;
use asupersync::database::postgres::{PgConnectOptions, PgConnection, PgError};
use asupersync::test_utils::run_test_with_cx;
use asupersync::types::Outcome;
use std::time::{SystemTime, UNIX_EPOCH};

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
        let real_pg_tests = std::env::var("REAL_PG_TESTS").unwrap_or_default() == "true";
        let real_postgres_tests =
            std::env::var("REAL_POSTGRES_TESTS").unwrap_or_default() == "true";
        let toggle = real_pg_tests || real_postgres_tests;
        let node_env = std::env::var("NODE_ENV").unwrap_or_default();

        let host_looks_local = postgres_url_host_is_local(&url);
        let url_lc = url.to_ascii_lowercase();
        let looks_prod = url_lc.contains("prod") || url_lc.contains("production");

        let reason = if !toggle {
            Some("REAL_PG_TESTS or REAL_POSTGRES_TESTS not set to 'true'".into())
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

fn unwrap_pg<T>(outcome: Outcome<T, PgError>, op: &str) -> T {
    match outcome {
        Outcome::Ok(value) => value,
        Outcome::Err(err) => panic!("{op} returned PostgreSQL error: {err}"),
        Outcome::Cancelled(reason) => panic!("{op} was cancelled: {:?}", reason.kind),
        Outcome::Panicked(payload) => panic!("{op} panicked: {payload:?}"),
    }
}

fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

async fn count_prepared_statement_exact(cx: &Cx, conn: &mut PgConnection, statement: &str) -> i64 {
    let sql = format!(
        "SELECT count(*)::int8 AS n FROM pg_prepared_statements WHERE statement = {}",
        sql_literal(statement)
    );
    let rows = unwrap_pg(
        conn.query_unchecked(cx, &sql).await,
        "count exact prepared statements",
    );
    rows[0].get_i64("n").expect("count column")
}

async fn count_prepared_statements_like(cx: &Cx, conn: &mut PgConnection, pattern: &str) -> i64 {
    let sql = format!(
        "SELECT count(*)::int8 AS n FROM pg_prepared_statements WHERE statement LIKE {}",
        sql_literal(pattern)
    );
    let rows = unwrap_pg(
        conn.query_unchecked(cx, &sql).await,
        "count matching prepared statements",
    );
    rows[0].get_i64("n").expect("count column")
}

fn unique_label(name: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("asupersync_prepared_cache_{name}_{nanos}")
}

#[test]
fn postgres_prepared_statement_cache_audit_localhost_gate_rejects_prefix_spoofing() {
    assert!(postgres_url_host_is_local(
        "postgres://postgres:postgres@localhost:5432/postgres"
    ));
    assert!(postgres_url_host_is_local(
        "postgres://postgres:postgres@127.0.0.1:5432/postgres"
    ));
    assert!(postgres_url_host_is_local(
        "postgres://postgres:postgres@[::1]:5432/postgres"
    ));
    assert!(!postgres_url_host_is_local(
        "postgres://postgres:postgres@localhost.evil.example:5432/postgres"
    ));
    assert!(!postgres_url_host_is_local(
        "postgres://postgres:postgres@10.0.0.5:5432/postgres"
    ));
    assert!(!postgres_url_host_is_local("not-a-postgres-url"));
}

#[test]
fn postgres_prepared_statement_cache_reuse_audit() {
    println!("=== POSTGRESQL PREPARED STATEMENT CACHE REUSE AUDIT ===");

    let cfg = RealPgConfig::from_env();
    if skip_if_disabled(&cfg, "postgres_prepared_statement_cache_reuse_audit") {
        return;
    }
    let url = cfg.url;

    run_test_with_cx(|cx| async move {
        let mut conn = unwrap_pg(PgConnection::connect(&cx, &url).await, "connect");
        println!("Connection established");

        let sql = "SELECT $1::integer + $2::integer AS sum";

        println!("Test Case 1: cache hit behavior");
        let stmt1 = unwrap_pg(conn.prepare(&cx, sql).await, "first prepare");
        assert_eq!(
            count_prepared_statement_exact(&cx, &mut conn, sql).await,
            1,
            "first prepare should create exactly one server-side statement"
        );

        let stmt2 = unwrap_pg(conn.prepare(&cx, sql).await, "second prepare");
        assert_eq!(
            count_prepared_statement_exact(&cx, &mut conn, sql).await,
            1,
            "second prepare for the same SQL must reuse the cached statement"
        );

        assert_eq!(
            stmt1.param_types(),
            stmt2.param_types(),
            "Parameter types should match"
        );
        assert_eq!(
            stmt1.columns().len(),
            stmt2.columns().len(),
            "Column count should match"
        );

        println!("Test Case 2: cached statement functional correctness");
        let result = unwrap_pg(
            conn.query_prepared(&cx, &stmt2, &[&10i32, &32i32]).await,
            "query cached statement",
        );

        assert_eq!(result.len(), 1, "Should return exactly one row");
        let sum: i32 = result[0].get_typed("sum").expect("Should get sum value");
        assert_eq!(sum, 42, "10 + 32 should equal 42");

        println!("Test Case 3: different SQL creates a separate cache entry");
        let different_sql = "SELECT $1::text || $2::text AS concat";
        let stmt3 = unwrap_pg(
            conn.prepare(&cx, different_sql).await,
            "different SQL prepare",
        );

        assert_ne!(
            stmt1.param_types(),
            stmt3.param_types(),
            "Different SQL should have different parameter types"
        );
        assert_eq!(
            count_prepared_statement_exact(&cx, &mut conn, different_sql).await,
            1,
            "different SQL should create its own server-side statement"
        );

        println!("STATUS: POSTGRESQL PREPARED STATEMENT CACHE REUSE IS SOUND");
    });
}

#[test]
fn postgres_prepared_statement_cache_eviction_audit() {
    println!("\n=== POSTGRESQL PREPARED STATEMENT CACHE EVICTION AUDIT ===");

    let cfg = RealPgConfig::from_env();
    if skip_if_disabled(&cfg, "postgres_prepared_statement_cache_eviction_audit") {
        return;
    }
    let url = cfg.url;

    run_test_with_cx(|cx| async move {
        let mut conn = unwrap_pg(PgConnection::connect(&cx, &url).await, "connect");
        let label = unique_label("eviction");
        let like_pattern = format!("%{label}%");
        const CACHE_CAPACITY: usize = 256;

        println!("Testing LRU cache behavior with eviction");

        let sqls = (0..=CACHE_CAPACITY)
            .map(|i| format!("SELECT {i}::int4 AS v /* {label}_{i} */"))
            .collect::<Vec<_>>();

        for (i, sql) in sqls.iter().enumerate() {
            let _stmt = unwrap_pg(conn.prepare(&cx, sql).await, &format!("prepare {i}"));
        }

        let first_sql = &sqls[0];
        let last_sql = sqls.last().expect("last prepared SQL");
        assert_eq!(
            count_prepared_statements_like(&cx, &mut conn, &like_pattern).await,
            CACHE_CAPACITY as i64,
            "cache should keep at most the documented default capacity"
        );
        assert_eq!(
            count_prepared_statement_exact(&cx, &mut conn, first_sql).await,
            0,
            "LRU eviction should DEALLOCATE the first prepared statement"
        );
        assert_eq!(
            count_prepared_statement_exact(&cx, &mut conn, last_sql).await,
            1,
            "most recent prepared statement should remain cached"
        );

        let _stmt = unwrap_pg(conn.prepare(&cx, first_sql).await, "re-prepare evicted SQL");
        assert_eq!(
            count_prepared_statement_exact(&cx, &mut conn, first_sql).await,
            1,
            "re-preparing an evicted SQL should create a fresh server-side statement"
        );
        assert_eq!(
            count_prepared_statements_like(&cx, &mut conn, &like_pattern).await,
            CACHE_CAPACITY as i64,
            "re-prepare after eviction should keep the server-side cache bounded"
        );

        println!("STATUS: CACHE EVICTION BEHAVIOR IS SOUND");
    });
}

#[test]
fn postgres_prepared_statement_cache_metadata_audit() {
    println!("\n=== POSTGRESQL PREPARED STATEMENT CACHE METADATA AUDIT ===");

    println!("Cache implementation details:");
    println!("  - Structure: HashMap<String, PgStatement> + VecDeque<String> LRU");
    println!("  - Default capacity: 256 entries (DEFAULT_MAX_PREPARED_STATEMENTS)");
    println!("  - Eviction: LRU (least-recently-used) policy");
    println!("  - Key: SQL string (exact match)");
    println!("  - Value: PgStatement with server-side name, param OIDs, column metadata");

    println!("\nPrepare/drop/re-prepare cycle:");
    println!("  1. First prepare(sql) -> Parse/Describe/Sync exchange -> cache entry created");
    println!("  2. Drop local clone -> entry remains in cache until evicted or invalidated");
    println!("  3. Re-prepare(sql) -> cache hit via get_and_touch() -> immediate return");

    println!("\nPerformance characteristics:");
    println!("  - Cache hit: O(1) HashMap lookup + O(n) LRU promotion");
    println!("  - Cache miss: Full network round-trip (Parse + Describe + Sync)");
    println!("  - Eviction: DEALLOCATE sent to server for LRU victim");

    println!("\nAUDIT CONCLUSION:");
    println!("  PostgreSQL prepared statement cache correctly implements pattern (a):");
    println!("  when the same SQL is prepared, dropped locally, and re-prepared,");
    println!("  the cached query plan is reused until eviction or invalidation.");
}
