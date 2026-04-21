//! Golden snapshot tests for PostgreSQL query execution log format.
//!
//! Tests that the query execution logging output format remains stable
//! for debugging, monitoring, and audit purposes.

use asupersync::database::postgres::{PgColumn, PgValue, PgError, oid};

/// Simulated query execution result for testing log formatting.
#[derive(Debug)]
struct QueryExecutionResult {
    query_id: u64,
    sql: String,
    columns: Vec<PgColumn>,
    rows: Vec<Vec<PgValue>>,
    elapsed_ms: u64,
    error: Option<PgError>,
}

/// Format a query execution log entry for consistent monitoring output.
fn format_query_execution_log(result: &QueryExecutionResult) -> String {
    let mut log = String::new();

    log.push_str("=== PostgreSQL Query Execution Log ===\n");
    log.push_str(&format!("Query ID: {}\n", result.query_id));
    log.push_str(&format!("SQL: {}\n", result.sql));
    log.push_str(&format!("Execution Time: {}ms\n", result.elapsed_ms));

    if let Some(ref err) = result.error {
        log.push_str(&format!("Status: ERROR\n"));
        log.push_str(&format!("Error: {}\n", err));
        if let Some(code) = err.code() {
            log.push_str(&format!("SQL State: {}\n", code));
        }
        log.push_str(&format!("Is Transient: {}\n", err.is_transient()));
        log.push_str(&format!("Is Retryable: {}\n", err.is_retryable()));
    } else {
        log.push_str(&format!("Status: SUCCESS\n"));
        log.push_str(&format!("Rows Returned: {}\n", result.rows.len()));

        if !result.columns.is_empty() {
            log.push_str("\n--- Column Description ---\n");
            for (i, col) in result.columns.iter().enumerate() {
                log.push_str(&format!("Column {}: {}\n", i, col.name));
                log.push_str(&format!("  Type OID: {}\n", col.type_oid));
                log.push_str(&format!("  Type Size: {}\n", col.type_size));
                log.push_str(&format!("  Table OID: {}\n", col.table_oid));
                log.push_str(&format!("  Column ID: {}\n", col.column_id));
                log.push_str(&format!("  Format: {}\n", col.format_code));
            }
        }

        if !result.rows.is_empty() {
            log.push_str("\n--- Sample Rows (first 3) ---\n");
            for (row_idx, row_values) in result.rows.iter().take(3).enumerate() {
                log.push_str(&format!("Row {}:\n", row_idx));
                for (col_idx, col) in result.columns.iter().enumerate() {
                    if let Some(value) = row_values.get(col_idx) {
                        let value_str = format_pg_value(value);
                        log.push_str(&format!("  {}: {}\n", col.name, value_str));
                    }
                }
            }
            if result.rows.len() > 3 {
                log.push_str(&format!("  ... and {} more rows\n", result.rows.len() - 3));
            }
        }
    }

    log.push_str("=====================================\n");
    log
}

/// Format a PostgreSQL value for display in logs.
fn format_pg_value(value: &PgValue) -> String {
    match value {
        PgValue::Null => "NULL".to_string(),
        PgValue::Bool(b) => b.to_string(),
        PgValue::Int2(i) => i.to_string(),
        PgValue::Int4(i) => i.to_string(),
        PgValue::Int8(i) => i.to_string(),
        PgValue::Float4(f) => f.to_string(),
        PgValue::Float8(f) => f.to_string(),
        PgValue::Text(s) => format!("\"{}\"", s),
        PgValue::Bytes(b) => format!("\\x{}",
            b.iter().map(|byte| format!("{:02x}", byte)).collect::<String>()),
    }
}

/// Create a test column for scenarios.
fn create_test_column(name: &str, type_oid: u32, col_id: i16) -> PgColumn {
    PgColumn {
        name: name.to_string(),
        table_oid: 12345,
        column_id: col_id,
        type_oid,
        type_size: if type_oid == oid::TEXT { -1 } else { 4 },
        type_modifier: -1,
        format_code: 0,
    }
}

#[test]
fn test_query_execution_log_successful_select() {
    // Simulate a successful SELECT query
    let result = QueryExecutionResult {
        query_id: 12345,
        sql: "SELECT id, name, active, score FROM users WHERE score > $1".to_string(),
        columns: vec![
            create_test_column("id", oid::INT4, 1),
            create_test_column("name", oid::TEXT, 2),
            create_test_column("active", oid::BOOL, 3),
            create_test_column("score", oid::FLOAT8, 4),
        ],
        rows: vec![
            vec![
                PgValue::Int4(1),
                PgValue::Text("Alice".to_string()),
                PgValue::Bool(true),
                PgValue::Float8(95.5),
            ],
            vec![
                PgValue::Int4(2),
                PgValue::Text("Bob".to_string()),
                PgValue::Bool(false),
                PgValue::Float8(87.2),
            ],
            vec![
                PgValue::Int4(3),
                PgValue::Text("Charlie".to_string()),
                PgValue::Bool(true),
                PgValue::Null,
            ],
        ],
        elapsed_ms: 45,
        error: None,
    };

    let log = format_query_execution_log(&result);
    insta::assert_snapshot!("successful_select_query", log);
}

#[test]
fn test_query_execution_log_empty_result() {
    // Simulate a SELECT that returns no rows
    let result = QueryExecutionResult {
        query_id: 12346,
        sql: "SELECT COUNT(*) FROM orders WHERE status = 'pending' AND created_at < NOW() - INTERVAL '1 day'".to_string(),
        columns: vec![
            create_test_column("count", oid::INT8, 1),
        ],
        rows: vec![],
        elapsed_ms: 12,
        error: None,
    };

    let log = format_query_execution_log(&result);
    insta::assert_snapshot!("empty_result_query", log);
}

#[test]
fn test_query_execution_log_server_error() {
    // Simulate a server error response
    let result = QueryExecutionResult {
        query_id: 12347,
        sql: "SELECT * FROM nonexistent_table".to_string(),
        columns: vec![],
        rows: vec![],
        elapsed_ms: 5,
        error: Some(PgError::Server {
            code: "42P01".to_string(),
            message: "relation \"nonexistent_table\" does not exist".to_string(),
            detail: Some("The table name might be misspelled".to_string()),
            hint: Some("Check the spelling and case of the table name".to_string()),
        }),
    };

    let log = format_query_execution_log(&result);
    insta::assert_snapshot!("server_error_query", log);
}

#[test]
fn test_query_execution_log_constraint_violation() {
    // Simulate a constraint violation error
    let result = QueryExecutionResult {
        query_id: 12348,
        sql: "INSERT INTO users (email, name) VALUES ($1, $2)".to_string(),
        columns: vec![],
        rows: vec![],
        elapsed_ms: 8,
        error: Some(PgError::Server {
            code: "23505".to_string(),
            message: "duplicate key value violates unique constraint \"users_email_key\"".to_string(),
            detail: Some("Key (email)=(alice@example.com) already exists.".to_string()),
            hint: None,
        }),
    };

    let log = format_query_execution_log(&result);
    insta::assert_snapshot!("constraint_violation_query", log);
}

#[test]
fn test_query_execution_log_mixed_data_types() {
    // Test logging with various PostgreSQL data types
    let result = QueryExecutionResult {
        query_id: 12349,
        sql: "SELECT id, metadata, binary_data, created_at FROM documents WHERE id = $1".to_string(),
        columns: vec![
            create_test_column("id", oid::INT8, 1),
            create_test_column("metadata", oid::JSONB, 2),
            create_test_column("binary_data", oid::BYTEA, 3),
            create_test_column("created_at", oid::TIMESTAMPTZ, 4),
        ],
        rows: vec![
            vec![
                PgValue::Int8(9876543210),
                PgValue::Text("{\"tags\": [\"important\", \"urgent\"]}".to_string()),
                PgValue::Bytes(vec![0xFF, 0x00, 0xAB, 0xCD]),
                PgValue::Text("2024-03-15 14:30:00+00".to_string()),
            ],
        ],
        elapsed_ms: 23,
        error: None,
    };

    let log = format_query_execution_log(&result);
    insta::assert_snapshot!("mixed_data_types_query", log);
}

#[test]
fn test_query_execution_log_transaction_error() {
    // Simulate a transaction-related error
    let result = QueryExecutionResult {
        query_id: 12350,
        sql: "UPDATE accounts SET balance = balance - $1 WHERE account_id = $2".to_string(),
        columns: vec![],
        rows: vec![],
        elapsed_ms: 156,
        error: Some(PgError::Server {
            code: "40001".to_string(),
            message: "could not serialize access due to concurrent update".to_string(),
            detail: None,
            hint: Some("The transaction might succeed if retried.".to_string()),
        }),
    };

    let log = format_query_execution_log(&result);
    insta::assert_snapshot!("transaction_error_query", log);
}

#[test]
fn test_query_execution_log_large_result_set() {
    // Simulate a query with many rows (testing truncation in log)
    let mut rows = Vec::new();
    for i in 1..=100 {
        rows.push(vec![
            PgValue::Int4(i),
            PgValue::Text(format!("Generated data row {}", i)),
        ]);
    }

    let result = QueryExecutionResult {
        query_id: 12351,
        sql: "SELECT seq, data FROM large_table ORDER BY seq LIMIT 100".to_string(),
        columns: vec![
            create_test_column("seq", oid::INT4, 1),
            create_test_column("data", oid::TEXT, 2),
        ],
        rows,
        elapsed_ms: 2340,
        error: None,
    };

    let log = format_query_execution_log(&result);
    insta::assert_snapshot!("large_result_set_query", log);
}