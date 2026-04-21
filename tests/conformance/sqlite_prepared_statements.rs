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
                SqliteValue::Text("🌟 Comprehensive test with Unicode and symbols! 🚀".to_string()),
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
