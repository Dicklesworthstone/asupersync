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
