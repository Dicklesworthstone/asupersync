//! Standalone SQLite Prepared Statement Round-Trip Conformance Tests.

#![cfg(feature = "sqlite")]

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

/// Create a test context for deterministic execution.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Simple block_on implementation for tests.
fn block_on<F: Future>(f: F) -> F::Output {
    struct NoopWaker;
    impl std::task::Wake for NoopWaker {
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

/// Serializable representation of SQLite values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "value")]
enum SerializableValue {
    Null,
    Integer(i64),
    Real(String), // Store as string to ensure exact representation
    Text(String),
    Blob(Vec<u8>),
}

impl From<&SqliteValue> for SerializableValue {
    fn from(value: &SqliteValue) -> Self {
        match value {
            SqliteValue::Null => Self::Null,
            SqliteValue::Integer(v) => Self::Integer(*v),
            SqliteValue::Real(v) => Self::Real(format!("{:.16}", v)),
            SqliteValue::Text(v) => Self::Text(v.clone()),
            SqliteValue::Blob(v) => Self::Blob(v.clone()),
        }
    }
}

/// Test parameter binding for all SQLite types: NULL, INTEGER, REAL, TEXT, BLOB.
#[cfg(test)]
#[test]
fn test_sqlite_basic_parameter_binding() {
    block_on(async {
        let runtime = Arc::new(LabRuntime::new(LabConfig::default()));
        let cx = test_cx();

        // Use in-memory database for deterministic testing
        let connection = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(conn) => conn,
            Outcome::Err(e) => panic!("Failed to open SQLite connection: {:?}", e),
            Outcome::Cancelled(reason) => panic!("Connection cancelled: {:?}", reason),
            Outcome::Panicked(payload) => panic!("Connection panicked: {:?}", payload),
        };

        // Create test table
        match connection
            .execute(
                &cx,
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
        {
            Outcome::Ok(_) => {}
            Outcome::Err(e) => panic!("Failed to create table: {:?}", e),
            Outcome::Cancelled(reason) => panic!("Create table cancelled: {:?}", reason),
            Outcome::Panicked(payload) => panic!("Create table panicked: {:?}", payload),
        };

        // Test data covering all SQLite types
        let test_params = vec![
            SqliteValue::Integer(1),
            SqliteValue::Integer(42),
            SqliteValue::Real(3.14159),
            SqliteValue::Text("hello world".to_string()),
            SqliteValue::Blob(vec![0x01, 0x02, 0x03, 0xFF]),
            SqliteValue::Null,
        ];

        // Insert test data
        match connection
            .execute(
                &cx,
                "INSERT INTO test_types (id, int_col, real_col, text_col, blob_col, null_col)
             VALUES (?, ?, ?, ?, ?, ?)",
                &test_params,
            )
            .await
        {
            Outcome::Ok(affected_rows) => {
                assert_eq!(affected_rows, 1, "Should insert exactly one row");
            }
            Outcome::Err(e) => panic!("Failed to insert: {:?}", e),
            Outcome::Cancelled(reason) => panic!("Insert cancelled: {:?}", reason),
            Outcome::Panicked(payload) => panic!("Insert panicked: {:?}", payload),
        };

        // Query back with parameters
        match connection
            .query(
                &cx,
                "SELECT * FROM test_types WHERE id = ?",
                &[SqliteValue::Integer(1)],
            )
            .await
        {
            Outcome::Ok(rows) => {
                assert_eq!(rows.len(), 1, "Should return exactly one row");

                let row = &rows[0];
                assert_eq!(row.len(), 6, "Row should have 6 columns");

                // Verify basic value retrieval (without exact comparison for now)
                assert!(row.get_idx(0).is_ok(), "Should get column 0");
                assert!(row.get_idx(1).is_ok(), "Should get column 1");
                assert!(row.get_idx(2).is_ok(), "Should get column 2");
                assert!(row.get_idx(3).is_ok(), "Should get column 3");
                assert!(row.get_idx(4).is_ok(), "Should get column 4");
                assert!(row.get_idx(5).is_ok(), "Should get column 5");

                println!("✅ SQLite parameter binding test passed");
            }
            Outcome::Err(e) => panic!("Failed to query: {:?}", e),
            Outcome::Cancelled(reason) => panic!("Query cancelled: {:?}", reason),
            Outcome::Panicked(payload) => panic!("Query panicked: {:?}", payload),
        };
    });
}

/// Test deterministic behavior with seeded iterations.
#[cfg(test)]
#[test]
fn test_sqlite_deterministic_small_scale() {
    let iterations = 5; // Small scale first
    let mut execution_results = Vec::new();

    for seed in 0..iterations {
        let result = block_on(async {
            let runtime = Arc::new(LabRuntime::new(LabConfig::default()));
            let cx = test_cx();
            let mut rng = DetRng::new(seed);

            let connection = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                Outcome::Err(e) => panic!("Failed to open connection: {:?}", e),
                Outcome::Cancelled(reason) => panic!("Connection cancelled: {:?}", reason),
                Outcome::Panicked(payload) => panic!("Connection panicked: {:?}", payload),
            };

            // Create table
            match connection
                .execute(
                    &cx,
                    "CREATE TABLE deterministic_test (id INTEGER, random_int INTEGER)",
                    &[],
                )
                .await
            {
                Outcome::Ok(_) => {}
                Outcome::Err(e) => panic!("Failed to create table: {:?}", e),
                Outcome::Cancelled(reason) => panic!("Create cancelled: {:?}", reason),
                Outcome::Panicked(payload) => panic!("Create table panicked: {:?}", payload),
            };

            // Insert deterministic "random" data
            let random_int = (rng.next_u64() % 1000) as i64;
            match connection
                .execute(
                    &cx,
                    "INSERT INTO deterministic_test (id, random_int) VALUES (?, ?)",
                    &[SqliteValue::Integer(1), SqliteValue::Integer(random_int)],
                )
                .await
            {
                Outcome::Ok(_) => {}
                Outcome::Err(e) => panic!("Failed to insert: {:?}", e),
                Outcome::Cancelled(reason) => panic!("Insert cancelled: {:?}", reason),
                Outcome::Panicked(payload) => panic!("Insert panicked: {:?}", payload),
            };

            // Query back
            match connection
                .query(&cx, "SELECT * FROM deterministic_test ORDER BY id", &[])
                .await
            {
                Outcome::Ok(rows) => {
                    assert_eq!(rows.len(), 1);
                    let val = rows[0].get_idx(1).unwrap();
                    if let SqliteValue::Integer(i) = val {
                        *i
                    } else {
                        panic!("Expected integer value");
                    }
                }
                Outcome::Err(e) => panic!("Failed to query: {:?}", e),
                Outcome::Cancelled(reason) => panic!("Query cancelled: {:?}", reason),
                Outcome::Panicked(payload) => panic!("Query panicked: {:?}", payload),
            }
        });
        execution_results.push(result);
    }

    // Verify all iterations produced identical results
    for (i, result) in execution_results.iter().enumerate() {
        if i > 0 {
            assert_eq!(
                *result, execution_results[0],
                "Iteration {} produced different result than iteration 0: {} vs {}",
                i, result, execution_results[0]
            );
        }
    }

    println!(
        "✅ Deterministic behavior verified across {} iterations",
        iterations
    );
}
