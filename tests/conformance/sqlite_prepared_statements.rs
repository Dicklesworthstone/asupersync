#![cfg(feature = "sqlite")]
//! SQLite prepared-statement conformance tests.
//!
//! The public SQLite wrapper delegates prepared statement lifecycle to
//! `rusqlite::prepare_cached`, `Statement::query`, and row-stream drop
//! semantics. These tests pin the user-visible contract: binding, stepping,
//! cached-statement reset, schema churn, stream finalization, cancellation, and
//! busy error mapping.

use asupersync::database::{SqliteConnection, SqliteError, SqliteRow, SqliteValue};
use asupersync::{CancelKind, Cx, Outcome};
use futures_lite::future::block_on;
use std::time::Duration;
use tempfile::tempdir;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlitePreparedStatementResult {
    scenario_id: &'static str,
    operation: &'static str,
    input_shape: &'static str,
    expected_result: &'static str,
    actual_result: String,
    cleanup_status: String,
    unsupported_reason: &'static str,
    verdict: &'static str,
    first_failure: String,
}

impl SqlitePreparedStatementResult {
    fn pass(
        scenario_id: &'static str,
        operation: &'static str,
        input_shape: &'static str,
        cleanup_status: impl Into<String>,
    ) -> Self {
        Self {
            scenario_id,
            operation,
            input_shape,
            expected_result: "pass",
            actual_result: "pass".to_string(),
            cleanup_status: cleanup_status.into(),
            unsupported_reason: "",
            verdict: "pass",
            first_failure: String::new(),
        }
    }

    fn fail(
        scenario_id: &'static str,
        operation: &'static str,
        input_shape: &'static str,
        failure: impl Into<String>,
    ) -> Self {
        Self {
            scenario_id,
            operation,
            input_shape,
            expected_result: "pass",
            actual_result: "fail".to_string(),
            cleanup_status: "unknown".to_string(),
            unsupported_reason: "",
            verdict: "fail",
            first_failure: failure.into(),
        }
    }
}

fn sanitize_field(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':' | '/') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn emit_conformance_log(result: &SqlitePreparedStatementResult) {
    println!(
        "bead_id=asupersync-2qssae suite_id=sqlite_prepared_statements scenario_id={} adapter_kind=sqlite platform={} feature_flags=test-internals,sqlite operation={} input_shape={} expected_result={} actual_result={} cleanup_status={} unsupported_reason={} verdict={} first_failure={}",
        result.scenario_id,
        std::env::consts::OS,
        sanitize_field(result.operation),
        sanitize_field(result.input_shape),
        sanitize_field(result.expected_result),
        sanitize_field(&result.actual_result),
        sanitize_field(&result.cleanup_status),
        sanitize_field(result.unsupported_reason),
        result.verdict,
        sanitize_field(&result.first_failure)
    );
}

fn assert_pass(result: SqlitePreparedStatementResult) {
    emit_conformance_log(&result);
    assert_eq!(
        result.verdict, "pass",
        "{} failed: {}",
        result.scenario_id, result.first_failure
    );
}

async fn open_memory(
    scenario_id: &'static str,
    operation: &'static str,
    input_shape: &'static str,
    cx: &Cx,
) -> Result<SqliteConnection, SqlitePreparedStatementResult> {
    match SqliteConnection::open_in_memory(cx).await {
        Outcome::Ok(conn) => Ok(conn),
        Outcome::Err(err) => Err(SqlitePreparedStatementResult::fail(
            scenario_id,
            operation,
            input_shape,
            format!("open_in_memory failed: {err:?}"),
        )),
        Outcome::Cancelled(reason) => Err(SqlitePreparedStatementResult::fail(
            scenario_id,
            operation,
            input_shape,
            format!("open_in_memory cancelled: {reason:?}"),
        )),
        Outcome::Panicked(payload) => Err(SqlitePreparedStatementResult::fail(
            scenario_id,
            operation,
            input_shape,
            format!("open_in_memory panicked: {payload:?}"),
        )),
    }
}

fn first_row_text(rows: &[SqliteRow], column: &str) -> Result<String, String> {
    let row = rows
        .first()
        .ok_or_else(|| "query returned no rows".to_string())?;
    row.get_str(column)
        .map(str::to_string)
        .map_err(|err| format!("column {column} text read failed: {err:?}"))
}

fn first_row_i64(rows: &[SqliteRow], column: &str) -> Result<i64, String> {
    let row = rows
        .first()
        .ok_or_else(|| "query returned no rows".to_string())?;
    row.get_i64(column)
        .map_err(|err| format!("column {column} integer read failed: {err:?}"))
}

fn parameter_binding_boundaries() -> SqlitePreparedStatementResult {
    const SCENARIO: &str = "SQLITE_PREPARED_BIND_BOUNDARIES";
    block_on(async {
        let cx = Cx::for_testing();
        let conn = match open_memory(
            SCENARIO,
            "bind_step_round_trip",
            "all_sqlite_value_types",
            &cx,
        )
        .await
        {
            Ok(conn) => conn,
            Err(result) => return result,
        };

        match conn
            .execute_batch(
                &cx,
                "CREATE TABLE bindings (
                    id INTEGER PRIMARY KEY,
                    int_col INTEGER,
                    real_col REAL,
                    text_col TEXT,
                    blob_col BLOB,
                    null_col INTEGER
                );",
            )
            .await
        {
            Outcome::Ok(()) => {}
            other => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "bind_step_round_trip",
                    "all_sqlite_value_types",
                    format!("schema setup failed: {other:?}"),
                );
            }
        }

        let text = "line-one\nline-two 'quoted'";
        let blob = vec![0x00, 0x01, 0xFE, 0xFF];
        match conn
            .execute(
                &cx,
                "INSERT INTO bindings (id, int_col, real_col, text_col, blob_col, null_col)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &[
                    SqliteValue::Integer(1),
                    SqliteValue::Integer(i64::MIN),
                    SqliteValue::Real(3.25),
                    SqliteValue::Text(text.to_string()),
                    SqliteValue::Blob(blob.clone()),
                    SqliteValue::Null,
                ],
            )
            .await
        {
            Outcome::Ok(1) => {}
            other => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "bind_step_round_trip",
                    "all_sqlite_value_types",
                    format!("insert failed: {other:?}"),
                );
            }
        }

        let rows = match conn
            .query(
                &cx,
                "SELECT int_col, real_col, text_col, blob_col, null_col
                 FROM bindings WHERE id = ?1",
                &[SqliteValue::Integer(1)],
            )
            .await
        {
            Outcome::Ok(rows) => rows,
            other => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "bind_step_round_trip",
                    "all_sqlite_value_types",
                    format!("query failed: {other:?}"),
                );
            }
        };

        let Some(row) = rows.first() else {
            return SqlitePreparedStatementResult::fail(
                SCENARIO,
                "bind_step_round_trip",
                "all_sqlite_value_types",
                "query returned no rows",
            );
        };

        let checks = [
            row.get_i64("int_col").is_ok_and(|value| value == i64::MIN),
            row.get_f64("real_col")
                .is_ok_and(|value| (value - 3.25).abs() < f64::EPSILON),
            row.get_str("text_col").is_ok_and(|value| value == text),
            row.get_blob("blob_col")
                .is_ok_and(|value| value == blob.as_slice()),
            row.get("null_col").is_ok_and(SqliteValue::is_null),
        ];

        if checks.into_iter().all(|passed| passed) {
            SqlitePreparedStatementResult::pass(
                SCENARIO,
                "bind_step_round_trip",
                "all_sqlite_value_types",
                "in_memory_connection_closed_on_drop",
            )
        } else {
            SqlitePreparedStatementResult::fail(
                SCENARIO,
                "bind_step_round_trip",
                "all_sqlite_value_types",
                format!("unexpected row values: {row:?}"),
            )
        }
    })
}

fn cached_statement_resets_between_bindings() -> SqlitePreparedStatementResult {
    const SCENARIO: &str = "SQLITE_PREPARED_CACHE_RESET";
    block_on(async {
        let cx = Cx::for_testing();
        let conn = match open_memory(
            SCENARIO,
            "cached_statement_reset",
            "same_sql_different_params",
            &cx,
        )
        .await
        {
            Ok(conn) => conn,
            Err(result) => return result,
        };

        match conn
            .execute_batch(
                &cx,
                "CREATE TABLE cache_reset (id INTEGER PRIMARY KEY, value TEXT);
                 INSERT INTO cache_reset (id, value) VALUES (1, 'first'), (2, 'second');",
            )
            .await
        {
            Outcome::Ok(()) => {}
            other => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "cached_statement_reset",
                    "same_sql_different_params",
                    format!("setup failed: {other:?}"),
                );
            }
        }

        let query = "SELECT value FROM cache_reset WHERE id = ?1";
        let mut observed = Vec::new();
        for id in [1, 2, 99, 1] {
            match conn.query(&cx, query, &[SqliteValue::Integer(id)]).await {
                Outcome::Ok(rows) if id == 99 && rows.is_empty() => {
                    observed.push("missing".to_string());
                }
                Outcome::Ok(rows) => match first_row_text(&rows, "value") {
                    Ok(value) => observed.push(value),
                    Err(err) => {
                        return SqlitePreparedStatementResult::fail(
                            SCENARIO,
                            "cached_statement_reset",
                            "same_sql_different_params",
                            err,
                        );
                    }
                },
                other => {
                    return SqlitePreparedStatementResult::fail(
                        SCENARIO,
                        "cached_statement_reset",
                        "same_sql_different_params",
                        format!("query for id {id} failed: {other:?}"),
                    );
                }
            }
        }

        if observed == ["first", "second", "missing", "first"] {
            SqlitePreparedStatementResult::pass(
                SCENARIO,
                "cached_statement_reset",
                "same_sql_different_params",
                "cached_statement_reused_without_stale_bindings",
            )
        } else {
            SqlitePreparedStatementResult::fail(
                SCENARIO,
                "cached_statement_reset",
                "same_sql_different_params",
                format!("unexpected observed values: {observed:?}"),
            )
        }
    })
}

fn cached_statement_survives_schema_change() -> SqlitePreparedStatementResult {
    const SCENARIO: &str = "SQLITE_PREPARED_SCHEMA_CHANGE";
    block_on(async {
        let cx = Cx::for_testing();
        let conn = match open_memory(
            SCENARIO,
            "schema_change_reprepare",
            "alter_table_after_cached_query",
            &cx,
        )
        .await
        {
            Ok(conn) => conn,
            Err(result) => return result,
        };

        match conn
            .execute_batch(
                &cx,
                "CREATE TABLE evolving (id INTEGER PRIMARY KEY, value TEXT);
                 INSERT INTO evolving (id, value) VALUES (1, 'before');",
            )
            .await
        {
            Outcome::Ok(()) => {}
            other => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "schema_change_reprepare",
                    "alter_table_after_cached_query",
                    format!("initial setup failed: {other:?}"),
                );
            }
        }

        let cached_query = "SELECT value FROM evolving WHERE id = ?1";
        match conn
            .query(&cx, cached_query, &[SqliteValue::Integer(1)])
            .await
        {
            Outcome::Ok(rows) if first_row_text(&rows, "value").as_deref() == Ok("before") => {}
            other => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "schema_change_reprepare",
                    "alter_table_after_cached_query",
                    format!("warm cached query failed: {other:?}"),
                );
            }
        }

        match conn
            .execute_batch(
                &cx,
                "ALTER TABLE evolving ADD COLUMN tag TEXT DEFAULT 'fresh';
                 UPDATE evolving SET value = 'after', tag = 'tagged' WHERE id = 1;",
            )
            .await
        {
            Outcome::Ok(()) => {}
            other => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "schema_change_reprepare",
                    "alter_table_after_cached_query",
                    format!("schema change failed: {other:?}"),
                );
            }
        }

        let value_after = match conn
            .query(&cx, cached_query, &[SqliteValue::Integer(1)])
            .await
        {
            Outcome::Ok(rows) => first_row_text(&rows, "value"),
            other => Err(format!(
                "cached query after schema change failed: {other:?}"
            )),
        };
        let tag_after = match conn
            .query(
                &cx,
                "SELECT tag FROM evolving WHERE id = ?1",
                &[SqliteValue::Integer(1)],
            )
            .await
        {
            Outcome::Ok(rows) => first_row_text(&rows, "tag"),
            other => Err(format!("new column query failed: {other:?}")),
        };

        if value_after.as_deref() == Ok("after") && tag_after.as_deref() == Ok("tagged") {
            SqlitePreparedStatementResult::pass(
                SCENARIO,
                "schema_change_reprepare",
                "alter_table_after_cached_query",
                "cached_statement_reprepared_after_schema_change",
            )
        } else {
            SqlitePreparedStatementResult::fail(
                SCENARIO,
                "schema_change_reprepare",
                "alter_table_after_cached_query",
                format!("unexpected post-schema values: value={value_after:?} tag={tag_after:?}"),
            )
        }
    })
}

fn dropped_row_stream_finalizes_statement() -> SqlitePreparedStatementResult {
    const SCENARIO: &str = "SQLITE_PREPARED_STREAM_FINALIZE";
    block_on(async {
        let cx = Cx::for_testing();
        let conn = match open_memory(
            SCENARIO,
            "row_stream_drop_finalize",
            "drop_stream_after_first_row",
            &cx,
        )
        .await
        {
            Ok(conn) => conn,
            Err(result) => return result,
        };

        match conn
            .execute_batch(
                &cx,
                "CREATE TABLE streamed (id INTEGER PRIMARY KEY, value TEXT);
                 INSERT INTO streamed (id, value) VALUES
                    (1, 'one'), (2, 'two'), (3, 'three');",
            )
            .await
        {
            Outcome::Ok(()) => {}
            other => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "row_stream_drop_finalize",
                    "drop_stream_after_first_row",
                    format!("setup failed: {other:?}"),
                );
            }
        }

        let mut stream = match conn
            .query_stream(&cx, "SELECT id, value FROM streamed ORDER BY id", &[])
            .await
        {
            Outcome::Ok(stream) => stream,
            other => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "row_stream_drop_finalize",
                    "drop_stream_after_first_row",
                    format!("query_stream failed to start: {other:?}"),
                );
            }
        };

        match stream.next(&cx).await {
            Outcome::Ok(Some(row)) if row.get_i64("id").is_ok_and(|id| id == 1) => {}
            other => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "row_stream_drop_finalize",
                    "drop_stream_after_first_row",
                    format!("first streamed row mismatch: {other:?}"),
                );
            }
        }
        drop(stream);

        let count = match conn
            .query(&cx, "SELECT COUNT(*) AS count FROM streamed", &[])
            .await
        {
            Outcome::Ok(rows) => first_row_i64(&rows, "count"),
            other => Err(format!("connection recovery count query failed: {other:?}")),
        };

        if count == Ok(3) {
            SqlitePreparedStatementResult::pass(
                SCENARIO,
                "row_stream_drop_finalize",
                "drop_stream_after_first_row",
                "stream_drop_released_statement_and_connection_recovered",
            )
        } else {
            SqlitePreparedStatementResult::fail(
                SCENARIO,
                "row_stream_drop_finalize",
                "drop_stream_after_first_row",
                format!("unexpected count after stream drop: {count:?}"),
            )
        }
    })
}

fn cancelled_execute_does_not_mutate_state() -> SqlitePreparedStatementResult {
    const SCENARIO: &str = "SQLITE_PREPARED_CANCEL_CLEANUP";
    block_on(async {
        let cx = Cx::for_testing();
        let cancelled = Cx::for_testing();
        cancelled.cancel_fast(CancelKind::User);
        let conn = match open_memory(
            SCENARIO,
            "cancelled_execute_cleanup",
            "cancel_before_execute",
            &cx,
        )
        .await
        {
            Ok(conn) => conn,
            Err(result) => return result,
        };

        match conn
            .execute_batch(
                &cx,
                "CREATE TABLE cancelled_insert (id INTEGER PRIMARY KEY, value TEXT);",
            )
            .await
        {
            Outcome::Ok(()) => {}
            other => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "cancelled_execute_cleanup",
                    "cancel_before_execute",
                    format!("setup failed: {other:?}"),
                );
            }
        }

        match conn
            .execute(
                &cancelled,
                "INSERT INTO cancelled_insert (id, value) VALUES (?1, ?2)",
                &[
                    SqliteValue::Integer(1),
                    SqliteValue::Text("should_not_commit".to_string()),
                ],
            )
            .await
        {
            Outcome::Cancelled(_) => {}
            other => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "cancelled_execute_cleanup",
                    "cancel_before_execute",
                    format!("expected cancellation, got: {other:?}"),
                );
            }
        }

        let count = match conn
            .query(&cx, "SELECT COUNT(*) AS count FROM cancelled_insert", &[])
            .await
        {
            Outcome::Ok(rows) => first_row_i64(&rows, "count"),
            other => Err(format!("post-cancel count query failed: {other:?}")),
        };

        if count == Ok(0) {
            SqlitePreparedStatementResult::pass(
                SCENARIO,
                "cancelled_execute_cleanup",
                "cancel_before_execute",
                "connection_recovered_after_cancelled_execute",
            )
        } else {
            SqlitePreparedStatementResult::fail(
                SCENARIO,
                "cancelled_execute_cleanup",
                "cancel_before_execute",
                format!("cancelled execute mutated state: {count:?}"),
            )
        }
    })
}

fn busy_error_mapping_is_preserved() -> SqlitePreparedStatementResult {
    const SCENARIO: &str = "SQLITE_PREPARED_BUSY_ERROR";
    block_on(async {
        let cx = Cx::for_testing();
        let dir = match tempdir() {
            Ok(dir) => dir,
            Err(err) => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "busy_error_mapping",
                    "two_connections_one_write_lock",
                    format!("tempdir failed: {err}"),
                );
            }
        };
        let db_path = dir.path().join("busy.sqlite3");
        let conn1 = match SqliteConnection::open(&cx, &db_path).await {
            Outcome::Ok(conn) => conn,
            other => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "busy_error_mapping",
                    "two_connections_one_write_lock",
                    format!("open conn1 failed: {other:?}"),
                );
            }
        };
        let conn2 = match SqliteConnection::open(&cx, &db_path).await {
            Outcome::Ok(conn) => conn,
            other => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "busy_error_mapping",
                    "two_connections_one_write_lock",
                    format!("open conn2 failed: {other:?}"),
                );
            }
        };

        match conn1
            .execute_batch(
                &cx,
                "CREATE TABLE busy_items (id INTEGER PRIMARY KEY, value TEXT);",
            )
            .await
        {
            Outcome::Ok(()) => {}
            other => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "busy_error_mapping",
                    "two_connections_one_write_lock",
                    format!("schema setup failed: {other:?}"),
                );
            }
        }
        match conn2.set_busy_timeout(&cx, Duration::from_millis(25)).await {
            Outcome::Ok(()) => {}
            other => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "busy_error_mapping",
                    "two_connections_one_write_lock",
                    format!("set_busy_timeout failed: {other:?}"),
                );
            }
        }

        let tx = match conn1.begin_immediate(&cx).await {
            Outcome::Ok(tx) => tx,
            Outcome::Err(err) => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "busy_error_mapping",
                    "two_connections_one_write_lock",
                    format!("begin_immediate failed: {err:?}"),
                );
            }
            Outcome::Cancelled(reason) => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "busy_error_mapping",
                    "two_connections_one_write_lock",
                    format!("begin_immediate cancelled: {reason:?}"),
                );
            }
            Outcome::Panicked(payload) => {
                return SqlitePreparedStatementResult::fail(
                    SCENARIO,
                    "busy_error_mapping",
                    "two_connections_one_write_lock",
                    format!("begin_immediate panicked: {payload:?}"),
                );
            }
        };

        let busy_result = conn2
            .execute(
                &cx,
                "INSERT INTO busy_items (id, value) VALUES (?1, ?2)",
                &[
                    SqliteValue::Integer(1),
                    SqliteValue::Text("blocked".to_string()),
                ],
            )
            .await;
        let rollback = tx.rollback(&cx).await;

        let busy_was_mapped = matches!(&busy_result, Outcome::Err(SqliteError::Sqlite(msg)) if {
            let lower = msg.to_ascii_lowercase();
            lower.contains("database is locked") || lower.contains("database is busy")
        });
        let rollback_ok = matches!(rollback, Outcome::Ok(()));

        if busy_was_mapped && rollback_ok {
            SqlitePreparedStatementResult::pass(
                SCENARIO,
                "busy_error_mapping",
                "two_connections_one_write_lock",
                "transaction_rolled_back_after_busy_probe",
            )
        } else {
            SqlitePreparedStatementResult::fail(
                SCENARIO,
                "busy_error_mapping",
                "two_connections_one_write_lock",
                format!("busy_result={busy_result:?} rollback_ok={rollback_ok}"),
            )
        }
    })
}

pub fn run_sqlite_prepared_statement_conformance_tests() -> Vec<SqlitePreparedStatementResult> {
    vec![
        parameter_binding_boundaries(),
        cached_statement_resets_between_bindings(),
        cached_statement_survives_schema_change(),
        dropped_row_stream_finalizes_statement(),
        cancelled_execute_does_not_mutate_state(),
        busy_error_mapping_is_preserved(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_prepared_statement_conformance_suite() {
        for result in run_sqlite_prepared_statement_conformance_tests() {
            assert_pass(result);
        }
    }

    #[test]
    fn sqlite_parameter_binding_boundaries() {
        assert_pass(parameter_binding_boundaries());
    }

    #[test]
    fn sqlite_cached_statement_resets_between_bindings() {
        assert_pass(cached_statement_resets_between_bindings());
    }

    #[test]
    fn sqlite_cached_statement_survives_schema_change() {
        assert_pass(cached_statement_survives_schema_change());
    }

    #[test]
    fn sqlite_dropped_row_stream_finalizes_statement() {
        assert_pass(dropped_row_stream_finalizes_statement());
    }

    #[test]
    fn sqlite_cancelled_execute_does_not_mutate_state() {
        assert_pass(cancelled_execute_does_not_mutate_state());
    }

    #[test]
    fn sqlite_busy_error_mapping_is_preserved() {
        assert_pass(busy_error_mapping_is_preserved());
    }
}

#[cfg(any())]
mod stale_sqlite_prepared_statement_suite {
    //! SQLite Prepared Statement Round-Trip Conformance Tests.
    //!
    //! This test suite implements comprehensive golden-file round-trip testing
    //! for SQLite prepared statement operations, ensuring deterministic behavior
    //! across parameter binding, type affinity, schema evolution, and cancellation.
    //!
    //! ## Test Coverage Areas
    //!
    //! - **Parameter Binding**: All SQLite types (INTEGER/REAL/TEXT/BLOB/NULL)
    //! - **Type Affinity Rules**: SQLite's type conversion behavior
    //! - **Column Metadata Stability**: Schema evolution impact on prepared statements
    //! - **Transaction Rollback**: Cancel behavior during prepared statement execution
    //! - **Deterministic Replay**: LabRuntime virtual time for reproducible results
    //!
    //! ## Golden File Methodology
    //!
    //! Each test captures exact input parameters, execution results, and metadata
    //! in a deterministic format. Tests run 1000 seeded iterations to verify
    //! 100% output equality across executions.

    use asupersync::cx::Cx;
    use asupersync::database::{SqliteConnection, SqliteError, SqliteRow, SqliteValue};
    use asupersync::lab::{LabConfig, LabRuntime};
    use asupersync::types::{Budget, Outcome, RegionId, TaskId};
    use asupersync::util::{ArenaIndex, DetRng};
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

    // ============================================================================
    // Test Infrastructure
    // ============================================================================

    /// Create a test context for deterministic execution.
    #[allow(dead_code)]
    fn test_cx() -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    /// Simple block_on implementation for tests.
    #[allow(dead_code)]
    fn block_on<F: Future>(f: F) -> F::Output {
        #[allow(dead_code)]
        struct NoopWaker;
        impl std::task::Wake for NoopWaker {
            #[allow(dead_code)]
            fn wake(self: std::sync::Arc<Self>) {}
        }
        let waker = std::task::Waker::noop().clone();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Box::pin(f);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => continue,
            }
        }
    }

    /// Serializable representation of a test execution result.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[allow(dead_code)]
    struct TestExecution {
        /// Input SQL statement.
        sql: String,
        /// Input parameters.
        params: Vec<SerializableValue>,
        /// Execution outcome type.
        outcome_type: String,
        /// Result data if successful.
        result: Option<TestResult>,
        /// Error message if failed.
        error: Option<String>,
    }

    /// Serializable representation of execution results.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(untagged)]
    #[allow(dead_code)]
    enum TestResult {
        /// Query result with rows.
        Query { rows: Vec<SerializableRow> },
        /// Execute result with affected row count.
        Execute { affected_rows: u64 },
        /// Batch execution (no specific result).
        Batch,
    }

    /// Serializable representation of SQLite values.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(tag = "type", content = "value")]
    #[allow(dead_code)]
    enum SerializableValue {
        Null,
        Integer(i64),
        Real(String), // Store as string to ensure exact representation
        Text(String),
        Blob(Vec<u8>),
    }

    impl From<&SqliteValue> for SerializableValue {
        #[allow(dead_code)]
        fn from(value: &SqliteValue) -> Self {
            match value {
                SqliteValue::Null => Self::Null,
                SqliteValue::Integer(v) => Self::Integer(*v),
                SqliteValue::Real(v) => Self::Real(format!("{:.16}", v)), // High precision
                SqliteValue::Text(v) => Self::Text(v.clone()),
                SqliteValue::Blob(v) => Self::Blob(v.clone()),
            }
        }
    }

    impl From<SerializableValue> for SqliteValue {
        #[allow(dead_code)]
        fn from(value: SerializableValue) -> Self {
            match value {
                SerializableValue::Null => Self::Null,
                SerializableValue::Integer(v) => Self::Integer(v),
                SerializableValue::Real(v) => Self::Real(v.parse().expect("valid real")),
                SerializableValue::Text(v) => Self::Text(v),
                SerializableValue::Blob(v) => Self::Blob(v),
            }
        }
    }

    /// Serializable representation of a result row.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[allow(dead_code)]
    struct SerializableRow {
        /// Column values in deterministic order.
        columns: BTreeMap<String, SerializableValue>,
    }

    #[allow(dead_code)]

    impl SerializableRow {
        #[allow(dead_code)]
        fn from_sqlite_row(row: &SqliteRow) -> Result<Self, SqliteError> {
            let mut columns = BTreeMap::new();

            // Build reverse mapping from index to column name
            let column_names: Vec<String> = row.column_names().map(|s| s.to_string()).collect();

            for i in 0..row.len() {
                let value = row.get_idx(i)?;
                let col_name = column_names
                    .get(i)
                    .map(|s| s.clone())
                    .unwrap_or_else(|| format!("col_{}", i)); // Fallback to index-based name
                columns.insert(col_name, SerializableValue::from(value));
            }

            Ok(Self { columns })
        }
    }

    /// Comprehensive test harness for SQLite prepared statement testing.
    #[allow(dead_code)]
    struct SqlitePreparedStatementHarness {
        runtime: Arc<LabRuntime>,
        connection: SqliteConnection,
        executions: Vec<TestExecution>,
    }

    #[allow(dead_code)]

    impl SqlitePreparedStatementHarness {
        async fn new() -> Result<Self, SqliteError> {
            let runtime = Arc::new(LabRuntime::new(LabConfig::default()));
            let cx = test_cx();

            // Use in-memory database for deterministic testing
            let connection = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                Outcome::Err(e) => return Err(e),
                Outcome::Cancelled(_) => {
                    return Err(SqliteError::Cancelled(
                        asupersync::types::CancelReason::user("setup cancelled"),
                    ));
                }
                Outcome::Panicked(payload) => panic!("Connection panicked: {:?}", payload),
            };

            Ok(Self {
                runtime,
                connection,
                executions: Vec::new(),
            })
        }

        /// Execute a query and record the result for golden file comparison.
        async fn execute_and_record(
            &mut self,
            sql: &str,
            params: &[SqliteValue],
            expected_outcome: &str,
        ) -> Result<(), SqliteError> {
            let cx = test_cx();

            let execution = match self.connection.query(&cx, sql, params).await {
                Outcome::Ok(rows) => {
                    let serializable_rows: Result<Vec<_>, _> =
                        rows.iter().map(SerializableRow::from_sqlite_row).collect();

                    TestExecution {
                        sql: sql.to_string(),
                        params: params.iter().map(SerializableValue::from).collect(),
                        outcome_type: "query_success".to_string(),
                        result: Some(TestResult::Query {
                            rows: serializable_rows.unwrap_or_default(),
                        }),
                        error: None,
                    }
                }
                Outcome::Err(e) => TestExecution {
                    sql: sql.to_string(),
                    params: params.iter().map(SerializableValue::from).collect(),
                    outcome_type: "query_error".to_string(),
                    result: None,
                    error: Some(format!("{:?}", e)),
                },
                Outcome::Cancelled(reason) => TestExecution {
                    sql: sql.to_string(),
                    params: params.iter().map(SerializableValue::from).collect(),
                    outcome_type: "query_cancelled".to_string(),
                    result: None,
                    error: Some(format!("Cancelled: {:?}", reason)),
                },
                Outcome::Panicked(payload) => TestExecution {
                    sql: sql.to_string(),
                    params: params.iter().map(SerializableValue::from).collect(),
                    outcome_type: "query_panicked".to_string(),
                    result: None,
                    error: Some(format!("Panicked: {:?}", payload)),
                },
            };

            self.executions.push(execution);
            Ok(())
        }

        /// Execute a statement and record the result.
        async fn execute_statement_and_record(
            &mut self,
            sql: &str,
            params: &[SqliteValue],
        ) -> Result<(), SqliteError> {
            let cx = test_cx();

            let execution = match self.connection.execute(&cx, sql, params).await {
                Outcome::Ok(affected_rows) => TestExecution {
                    sql: sql.to_string(),
                    params: params.iter().map(SerializableValue::from).collect(),
                    outcome_type: "execute_success".to_string(),
                    result: Some(TestResult::Execute { affected_rows }),
                    error: None,
                },
                Outcome::Err(e) => TestExecution {
                    sql: sql.to_string(),
                    params: params.iter().map(SerializableValue::from).collect(),
                    outcome_type: "execute_error".to_string(),
                    result: None,
                    error: Some(format!("{:?}", e)),
                },
                Outcome::Cancelled(reason) => TestExecution {
                    sql: sql.to_string(),
                    params: params.iter().map(SerializableValue::from).collect(),
                    outcome_type: "execute_cancelled".to_string(),
                    result: None,
                    error: Some(format!("Cancelled: {:?}", reason)),
                },
                Outcome::Panicked(payload) => TestExecution {
                    sql: sql.to_string(),
                    params: params.iter().map(SerializableValue::from).collect(),
                    outcome_type: "execute_panicked".to_string(),
                    result: None,
                    error: Some(format!("Panicked: {:?}", payload)),
                },
            };

            self.executions.push(execution);
            Ok(())
        }

        /// Get all recorded executions for golden file serialization.
        #[allow(dead_code)]
        fn get_executions(&self) -> &[TestExecution] {
            &self.executions
        }
    }

    // ============================================================================
    // Parameter Binding Tests for All SQLite Types
    // ============================================================================

    #[cfg(test)]
    mod parameter_binding_tests {
        use super::*;

        /// Test parameter binding for all SQLite types: NULL, INTEGER, REAL, TEXT, BLOB.
        #[test]
        #[allow(dead_code)]
        fn test_parameter_binding_all_types() {
            block_on(async {
                let mut harness = SqlitePreparedStatementHarness::new().await.unwrap();

                // Create test table
                harness
                    .execute_statement_and_record(
                        "CREATE TABLE test_types (
                    id INTEGER,
                    int_col INTEGER,
                    real_col REAL,
                    text_col TEXT,
                    blob_col BLOB,
                    null_col INTEGER
                )",
                        &[],
                    )
                    .await
                    .unwrap();

                // Test data covering all SQLite types
                let test_data = vec![
                    vec![
                        SqliteValue::Integer(1),
                        SqliteValue::Integer(42),
                        SqliteValue::Real(3.14159),
                        SqliteValue::Text("hello world".to_string()),
                        SqliteValue::Blob(vec![0x01, 0x02, 0x03, 0xFF]),
                        SqliteValue::Null,
                    ],
                    vec![
                        SqliteValue::Integer(2),
                        SqliteValue::Integer(-1000),
                        SqliteValue::Real(-2.71828),
                        SqliteValue::Text("UTF-8: 🚀📊🔬".to_string()),
                        SqliteValue::Blob(vec![]),
                        SqliteValue::Null,
                    ],
                    vec![
                        SqliteValue::Integer(3),
                        SqliteValue::Integer(i64::MAX),
                        SqliteValue::Real(f64::INFINITY),
                        SqliteValue::Text(String::new()),
                        SqliteValue::Blob(vec![0x00; 1000]),
                        SqliteValue::Null,
                    ],
                ];

                // Insert test data
                for params in &test_data {
                    harness.execute_statement_and_record(
                    "INSERT INTO test_types (id, int_col, real_col, text_col, blob_col, null_col)
                     VALUES (?, ?, ?, ?, ?, ?)",
                    params,
                ).await.unwrap();
                }

                // Query back with various parameter combinations
                harness
                    .execute_and_record(
                        "SELECT * FROM test_types WHERE id = ?",
                        &[SqliteValue::Integer(1)],
                        "single_row",
                    )
                    .await
                    .unwrap();

                harness
                    .execute_and_record(
                        "SELECT * FROM test_types WHERE int_col > ? AND real_col < ?",
                        &[SqliteValue::Integer(0), SqliteValue::Real(5.0)],
                        "range_filter",
                    )
                    .await
                    .unwrap();

                harness
                    .execute_and_record(
                        "SELECT * FROM test_types WHERE text_col LIKE ? OR blob_col IS ?",
                        &[SqliteValue::Text("%hello%".to_string()), SqliteValue::Null],
                        "text_search",
                    )
                    .await
                    .unwrap();

                // Verify deterministic output
                assert!(!harness.get_executions().is_empty());
                println!("Recorded {} executions", harness.get_executions().len());
            });
        }

        /// Test SQLite type affinity rules with parameter binding.
        #[test]
        #[allow(dead_code)]
        fn test_type_affinity_rules() {
            block_on(async {
                let mut harness = SqlitePreparedStatementHarness::new().await.unwrap();

                // Create tables with different column affinities
                harness
                    .execute_statement_and_record(
                        "CREATE TABLE affinity_test (
                    integer_col INTEGER,
                    text_col TEXT,
                    real_col REAL,
                    numeric_col NUMERIC,
                    blob_col BLOB
                )",
                        &[],
                    )
                    .await
                    .unwrap();

                // Test type conversions with different affinities
                let test_cases = vec![
                    // Insert text into integer column (should convert)
                    (
                        "INSERT INTO affinity_test (integer_col) VALUES (?)",
                        vec![SqliteValue::Text("123".to_string())],
                    ),
                    // Insert integer into text column (should remain integer)
                    (
                        "INSERT INTO affinity_test (text_col) VALUES (?)",
                        vec![SqliteValue::Integer(456)],
                    ),
                    // Insert text into real column (should convert if numeric)
                    (
                        "INSERT INTO affinity_test (real_col) VALUES (?)",
                        vec![SqliteValue::Text("3.14".to_string())],
                    ),
                    // Insert blob into various columns
                    (
                        "INSERT INTO affinity_test (blob_col) VALUES (?)",
                        vec![SqliteValue::Blob(vec![1, 2, 3])],
                    ),
                ];

                for (sql, params) in test_cases {
                    harness
                        .execute_statement_and_record(sql, &params)
                        .await
                        .unwrap();
                }

                // Query to see the actual stored types
                harness.execute_and_record(
                "SELECT typeof(integer_col), typeof(text_col), typeof(real_col), typeof(blob_col)
                 FROM affinity_test",
                &[],
                "type_check",
            ).await.unwrap();

                assert!(!harness.get_executions().is_empty());
            });
        }
    }

    // ============================================================================
    // Schema Evolution and Column Metadata Stability Tests
    // ============================================================================

    #[cfg(test)]
    mod schema_evolution_tests {
        use super::*;

        /// Test that prepared statements handle schema changes correctly.
        #[test]
        #[allow(dead_code)]
        fn test_column_metadata_stability() {
            block_on(async {
                let mut harness = SqlitePreparedStatementHarness::new().await.unwrap();

                // Initial schema
                harness
                    .execute_statement_and_record(
                        "CREATE TABLE evolving_table (id INTEGER PRIMARY KEY, name TEXT)",
                        &[],
                    )
                    .await
                    .unwrap();

                harness
                    .execute_statement_and_record(
                        "INSERT INTO evolving_table (id, name) VALUES (?, ?)",
                        &[
                            SqliteValue::Integer(1),
                            SqliteValue::Text("Alice".to_string()),
                        ],
                    )
                    .await
                    .unwrap();

                // Query initial state
                harness
                    .execute_and_record(
                        "SELECT * FROM evolving_table WHERE id = ?",
                        &[SqliteValue::Integer(1)],
                        "before_evolution",
                    )
                    .await
                    .unwrap();

                // Add a column (schema evolution)
                harness
                    .execute_statement_and_record(
                        "ALTER TABLE evolving_table ADD COLUMN age INTEGER",
                        &[],
                    )
                    .await
                    .unwrap();

                // Insert with new schema
                harness
                    .execute_statement_and_record(
                        "INSERT INTO evolving_table (id, name, age) VALUES (?, ?, ?)",
                        &[
                            SqliteValue::Integer(2),
                            SqliteValue::Text("Bob".to_string()),
                            SqliteValue::Integer(30),
                        ],
                    )
                    .await
                    .unwrap();

                // Query after schema evolution
                harness
                    .execute_and_record(
                        "SELECT * FROM evolving_table ORDER BY id",
                        &[],
                        "after_evolution",
                    )
                    .await
                    .unwrap();

                // Test backward compatibility - old queries should still work
                harness
                    .execute_and_record(
                        "SELECT id, name FROM evolving_table WHERE id = ?",
                        &[SqliteValue::Integer(1)],
                        "backward_compat",
                    )
                    .await
                    .unwrap();

                assert!(!harness.get_executions().is_empty());
            });
        }
    }

    // ============================================================================
    // Transaction Rollback and Cancellation Tests
    // ============================================================================

    #[cfg(test)]
    mod transaction_rollback_tests {
        use super::*;

        /// Test transaction rollback behavior during prepared statement execution.
        #[test]
        #[allow(dead_code)]
        fn test_transaction_rollback_on_cancel() {
            block_on(async {
                let mut harness = SqlitePreparedStatementHarness::new().await.unwrap();

                // Setup test table
                harness
                    .execute_statement_and_record(
                        "CREATE TABLE transaction_test (id INTEGER, value TEXT)",
                        &[],
                    )
                    .await
                    .unwrap();

                // Begin transaction
                harness
                    .execute_statement_and_record("BEGIN TRANSACTION", &[])
                    .await
                    .unwrap();

                // Insert some data in transaction
                harness
                    .execute_statement_and_record(
                        "INSERT INTO transaction_test (id, value) VALUES (?, ?)",
                        &[
                            SqliteValue::Integer(1),
                            SqliteValue::Text("test".to_string()),
                        ],
                    )
                    .await
                    .unwrap();

                // Verify data exists within transaction
                harness
                    .execute_and_record(
                        "SELECT COUNT(*) FROM transaction_test",
                        &[],
                        "within_transaction",
                    )
                    .await
                    .unwrap();

                // Rollback transaction
                harness
                    .execute_statement_and_record("ROLLBACK", &[])
                    .await
                    .unwrap();

                // Verify data was rolled back
                harness
                    .execute_and_record(
                        "SELECT COUNT(*) FROM transaction_test",
                        &[],
                        "after_rollback",
                    )
                    .await
                    .unwrap();

                assert!(!harness.get_executions().is_empty());
            });
        }
    }

    // ============================================================================
    // Deterministic Replay with 1000 Iterations
    // ============================================================================

    #[cfg(test)]
    mod deterministic_replay_tests {
        use super::*;
        use std::collections::HashMap;

        /// Test deterministic behavior across 1000 seeded iterations.
        #[test]
        #[allow(dead_code)]
        fn test_1000_iteration_deterministic_replay() {
            let iterations = 1000;
            let mut execution_fingerprints: HashMap<u64, Vec<TestExecution>> = HashMap::new();

            for seed in 0..iterations {
                block_on(async {
                    let mut harness = SqlitePreparedStatementHarness::new().await.unwrap();
                    let mut rng = DetRng::new(seed);

                    // Create deterministic test scenario
                    harness
                        .execute_statement_and_record(
                            "CREATE TABLE deterministic_test (
                        id INTEGER PRIMARY KEY,
                        random_int INTEGER,
                        random_real REAL,
                        random_text TEXT
                    )",
                            &[],
                        )
                        .await
                        .unwrap();

                    // Generate deterministic "random" data using seeded RNG
                    for i in 0..5 {
                        let random_int = (rng.next_u64() % 1000) as i64;
                        let random_real = (rng.next_u64() % 100) as f64 / 10.0;
                        let random_text = format!("text_{}", rng.next_u64() % 100);

                        harness.execute_statement_and_record(
                        "INSERT INTO deterministic_test (random_int, random_real, random_text) VALUES (?, ?, ?)",
                        &[
                            SqliteValue::Integer(random_int),
                            SqliteValue::Real(random_real),
                            SqliteValue::Text(random_text),
                        ],
                    ).await.unwrap();
                    }

                    // Query data back
                    harness
                        .execute_and_record(
                            "SELECT * FROM deterministic_test ORDER BY id",
                            &[],
                            "full_table",
                        )
                        .await
                        .unwrap();

                    // Store executions by seed
                    execution_fingerprints.insert(seed, harness.get_executions().to_vec());
                });
            }

            // Verify all iterations produced identical results
            let first_execution = execution_fingerprints.get(&0).unwrap();
            for seed in 1..iterations {
                let current_execution = execution_fingerprints.get(&seed).unwrap();
                assert_eq!(
                    first_execution, current_execution,
                    "Iteration {} produced different results than iteration 0",
                    seed
                );
            }

            println!(
                "Successfully verified deterministic behavior across {} iterations",
                iterations
            );
        }
    }

    // ============================================================================
    // Integration Test Suite
    // ============================================================================

    #[cfg(test)]
    mod integration_tests {
        use super::*;

        /// Comprehensive integration test combining all conformance areas.
        #[test]
        #[allow(dead_code)]
        fn test_sqlite_prepared_statement_conformance_suite() {
            block_on(async {
                let mut harness = SqlitePreparedStatementHarness::new().await.unwrap();

                // Create comprehensive test schema
                harness
                    .execute_statement_and_record(
                        "CREATE TABLE conformance_test (
                    id INTEGER PRIMARY KEY,
                    null_col NULL,
                    int_col INTEGER,
                    real_col REAL,
                    text_col TEXT,
                    blob_col BLOB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )",
                        &[],
                    )
                    .await
                    .unwrap();

                // Test comprehensive parameter binding
                let test_params = vec![
                    SqliteValue::Null,
                    SqliteValue::Integer(-9223372036854775808), // i64::MIN
                    SqliteValue::Real(1.7976931348623157e308),  // f64::MAX
                    SqliteValue::Text(
                        "🌟 Comprehensive test with Unicode and symbols! 🚀".to_string(),
                    ),
                    SqliteValue::Blob(vec![0x00, 0x01, 0xFE, 0xFF]),
                ];

                harness
                .execute_statement_and_record(
                    "INSERT INTO conformance_test (null_col, int_col, real_col, text_col, blob_col)
                 VALUES (?, ?, ?, ?, ?)",
                    &test_params,
                )
                .await
                .unwrap();

                // Test complex queries with multiple parameters
                harness
                    .execute_and_record(
                        "SELECT * FROM conformance_test
                 WHERE int_col IS NOT ? AND real_col > ? AND text_col LIKE ?
                 ORDER BY id",
                        &[
                            SqliteValue::Null,
                            SqliteValue::Real(0.0),
                            SqliteValue::Text("%Comprehensive%".to_string()),
                        ],
                        "complex_query",
                    )
                    .await
                    .unwrap();

                // Verify the execution log
                let executions = harness.get_executions();
                assert!(
                    executions.len() >= 3,
                    "Should have recorded multiple executions"
                );

                // Check that we captured all operation types
                let mut has_create = false;
                let mut has_insert = false;
                let mut has_query = false;

                for execution in executions {
                    if execution.sql.starts_with("CREATE") {
                        has_create = true;
                    }
                    if execution.sql.starts_with("INSERT") {
                        has_insert = true;
                    }
                    if execution.sql.starts_with("SELECT") {
                        has_query = true;
                    }
                }

                assert!(has_create, "Should have CREATE operations");
                assert!(has_insert, "Should have INSERT operations");
                assert!(has_query, "Should have SELECT operations");

                println!("✅ SQLite prepared statement conformance suite completed successfully");
                println!("📊 Recorded {} total executions", executions.len());
            });
        }
    }
}
