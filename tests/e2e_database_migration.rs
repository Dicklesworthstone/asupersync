//! E2E: Database (SQLite) full lifecycle and migration configuration tests.
//!
//! Tests connection lifecycle, query execution, transactions, error recovery,
//! and RaptorQ migration configuration.

#[macro_use]
mod common;

use asupersync::database::{SqliteConnection, SqliteError, SqliteValue};
use asupersync::migration::{
    configure_migration, DualValue, DualValueError, MigrationFeature, MigrationMode,
};
use asupersync::types::Outcome;
use common::*;

// =========================================================================
// SQLite connection lifecycle
// =========================================================================

#[test]
fn e2e_sqlite_open_in_memory() {
    init_test_logging();
    test_phase!("SQLite Open In-Memory");

    run_test_with_cx(|cx| async move {
        test_section!("Open in-memory connection");
        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(c) => c,
            other => panic!("expected Ok, got {other:?}"),
        };

        assert_with_log!(conn.is_open(), "connection open", true, conn.is_open());

        test_section!("Close connection");
        conn.close().unwrap();
        assert_with_log!(!conn.is_open(), "connection closed", false, conn.is_open());

        test_complete!("e2e_sqlite_open_in_memory");
    });
}

#[test]
fn e2e_sqlite_close_is_idempotent() {
    init_test_logging();
    test_phase!("SQLite Close Idempotent");

    run_test_with_cx(|cx| async move {
        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(c) => c,
            other => panic!("expected Ok, got {other:?}"),
        };

        conn.close().unwrap();
        // Second close should also succeed (no-op)
        conn.close().unwrap();
        assert!(!conn.is_open());

        test_complete!("e2e_sqlite_close_is_idempotent");
    });
}

// =========================================================================
// Query execution
// =========================================================================

#[test]
fn e2e_sqlite_create_table_and_insert() {
    init_test_logging();
    test_phase!("SQLite Create Table and Insert");

    run_test_with_cx(|cx| async move {
        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(c) => c,
            other => panic!("expected Ok, got {other:?}"),
        };

        test_section!("Create table");
        match conn
            .execute_batch(
                &cx,
                "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, age INTEGER)",
            )
            .await
        {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        test_section!("Insert rows");
        let affected = match conn
            .execute(
                &cx,
                "INSERT INTO users (name, age) VALUES (?1, ?2)",
                &[SqliteValue::Text("Alice".into()), SqliteValue::Integer(30)],
            )
            .await
        {
            Outcome::Ok(n) => n,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_with_log!(affected == 1, "one row inserted", 1u64, affected);

        test_section!("Query rows");
        let rows = match conn.query(&cx, "SELECT id, name, age FROM users", &[]).await {
            Outcome::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        tracing::info!(row_count = rows.len(), "query result");
        assert_with_log!(rows.len() == 1, "one row returned", 1, rows.len());
        assert_eq!(rows[0].get_str("name").unwrap(), "Alice");
        assert_eq!(rows[0].get_i64("age").unwrap(), 30);

        test_complete!("e2e_sqlite_create_table_and_insert", rows = 1);
    });
}

#[test]
fn e2e_sqlite_parameterized_queries() {
    init_test_logging();
    test_phase!("SQLite Parameterized Queries");

    run_test_with_cx(|cx| async move {
        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(c) => c,
            other => panic!("expected Ok, got {other:?}"),
        };

        match conn
            .execute_batch(
                &cx,
                "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, price REAL, data BLOB)",
            )
            .await
        {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        test_section!("Insert with all value types");
        match conn
            .execute(
                &cx,
                "INSERT INTO items (name, price, data) VALUES (?1, ?2, ?3)",
                &[
                    SqliteValue::Text("Widget".into()),
                    SqliteValue::Real(9.99),
                    SqliteValue::Blob(vec![0xDE, 0xAD]),
                ],
            )
            .await
        {
            Outcome::Ok(_) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        test_section!("Insert with NULL");
        match conn
            .execute(
                &cx,
                "INSERT INTO items (name, price, data) VALUES (?1, ?2, ?3)",
                &[
                    SqliteValue::Text("NullItem".into()),
                    SqliteValue::Null,
                    SqliteValue::Null,
                ],
            )
            .await
        {
            Outcome::Ok(_) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        test_section!("Read back values");
        let rows = match conn
            .query(
                &cx,
                "SELECT name, price, data FROM items WHERE name = ?1",
                &[SqliteValue::Text("Widget".into())],
            )
            .await
        {
            Outcome::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get_str("name").unwrap(), "Widget");
        assert!((rows[0].get_f64("price").unwrap() - 9.99).abs() < 0.001);
        assert_eq!(rows[0].get_blob("data").unwrap(), &[0xDE, 0xAD]);

        test_section!("Read NULL values");
        let rows = match conn
            .query(
                &cx,
                "SELECT price, data FROM items WHERE name = ?1",
                &[SqliteValue::Text("NullItem".into())],
            )
            .await
        {
            Outcome::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert!(rows[0].get("price").unwrap().is_null());
        assert!(rows[0].get("data").unwrap().is_null());

        test_complete!("e2e_sqlite_parameterized_queries");
    });
}

#[test]
fn e2e_sqlite_query_row() {
    init_test_logging();
    test_phase!("SQLite Query Row");

    run_test_with_cx(|cx| async move {
        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(c) => c,
            other => panic!("expected Ok, got {other:?}"),
        };

        match conn
            .execute_batch(&cx, "CREATE TABLE t (v INTEGER); INSERT INTO t VALUES (42)")
            .await
        {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        test_section!("Query single row");
        let row = match conn.query_row(&cx, "SELECT v FROM t", &[]).await {
            Outcome::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert!(row.is_some());
        assert_eq!(row.unwrap().get_i64("v").unwrap(), 42);

        test_section!("Query no rows");
        let row = match conn
            .query_row(&cx, "SELECT v FROM t WHERE v = 999", &[])
            .await
        {
            Outcome::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert!(row.is_none());

        test_complete!("e2e_sqlite_query_row");
    });
}

#[test]
fn e2e_sqlite_batch_execute() {
    init_test_logging();
    test_phase!("SQLite Batch Execute");

    run_test_with_cx(|cx| async move {
        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(c) => c,
            other => panic!("expected Ok, got {other:?}"),
        };

        test_section!("Execute batch with multiple statements");
        match conn
            .execute_batch(
                &cx,
                "CREATE TABLE a (x INTEGER);
                 CREATE TABLE b (y TEXT);
                 INSERT INTO a VALUES (1);
                 INSERT INTO a VALUES (2);
                 INSERT INTO b VALUES ('hello');",
            )
            .await
        {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        let rows = match conn.query(&cx, "SELECT COUNT(*) as cnt FROM a", &[]).await {
            Outcome::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_eq!(rows[0].get_i64("cnt").unwrap(), 2);

        let rows = match conn.query(&cx, "SELECT y FROM b", &[]).await {
            Outcome::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_eq!(rows[0].get_str("y").unwrap(), "hello");

        test_complete!("e2e_sqlite_batch_execute");
    });
}

#[test]
fn e2e_sqlite_update_and_delete() {
    init_test_logging();
    test_phase!("SQLite Update and Delete");

    run_test_with_cx(|cx| async move {
        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(c) => c,
            other => panic!("expected Ok, got {other:?}"),
        };

        match conn
            .execute_batch(
                &cx,
                "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT);
                 INSERT INTO t (val) VALUES ('a');
                 INSERT INTO t (val) VALUES ('b');
                 INSERT INTO t (val) VALUES ('c');",
            )
            .await
        {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        test_section!("Update row");
        let affected = match conn
            .execute(
                &cx,
                "UPDATE t SET val = ?1 WHERE id = ?2",
                &[SqliteValue::Text("updated".into()), SqliteValue::Integer(2)],
            )
            .await
        {
            Outcome::Ok(n) => n,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_eq!(affected, 1);

        test_section!("Delete row");
        let affected = match conn
            .execute(
                &cx,
                "DELETE FROM t WHERE id = ?1",
                &[SqliteValue::Integer(3)],
            )
            .await
        {
            Outcome::Ok(n) => n,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_eq!(affected, 1);

        test_section!("Verify state");
        let rows = match conn.query(&cx, "SELECT id, val FROM t ORDER BY id", &[]).await {
            Outcome::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get_str("val").unwrap(), "a");
        assert_eq!(rows[1].get_str("val").unwrap(), "updated");

        test_complete!("e2e_sqlite_update_and_delete");
    });
}

// =========================================================================
// Row access
// =========================================================================

#[test]
fn e2e_sqlite_row_column_access() {
    init_test_logging();
    test_phase!("SQLite Row Column Access");

    run_test_with_cx(|cx| async move {
        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(c) => c,
            other => panic!("expected Ok, got {other:?}"),
        };

        match conn
            .execute_batch(&cx, "CREATE TABLE t (a INTEGER, b TEXT); INSERT INTO t VALUES (1, 'x')")
            .await
        {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        let rows = match conn.query(&cx, "SELECT a, b FROM t", &[]).await {
            Outcome::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        let row = &rows[0];

        test_section!("Access by name");
        assert_eq!(row.get_i64("a").unwrap(), 1);
        assert_eq!(row.get_str("b").unwrap(), "x");

        test_section!("Access by index");
        assert_eq!(row.get_idx(0).unwrap(), &SqliteValue::Integer(1));
        assert_eq!(row.get_idx(1).unwrap(), &SqliteValue::Text("x".into()));

        test_section!("Missing column");
        assert!(row.get("nonexistent").is_err());
        assert!(row.get_idx(99).is_err());

        test_section!("Type mismatch");
        assert!(row.get_i64("b").is_err()); // b is text, not integer
        assert!(row.get_str("a").is_err()); // a is integer, not text

        test_section!("Row metadata");
        assert_eq!(row.len(), 2);
        assert!(!row.is_empty());

        test_complete!("e2e_sqlite_row_column_access");
    });
}

// =========================================================================
// Transactions
// =========================================================================

#[test]
fn e2e_sqlite_transaction_commit() {
    init_test_logging();
    test_phase!("SQLite Transaction Commit");

    run_test_with_cx(|cx| async move {
        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(c) => c,
            other => panic!("expected Ok, got {other:?}"),
        };

        match conn
            .execute_batch(&cx, "CREATE TABLE t (v INTEGER)")
            .await
        {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        test_section!("Begin transaction and insert");
        let txn = match conn.begin(&cx).await {
            Outcome::Ok(t) => t,
            Outcome::Err(e) => panic!("begin failed: {e}"),
            _ => panic!("begin cancelled or panicked"),
        };

        match txn
            .execute(&cx, "INSERT INTO t VALUES (?1)", &[SqliteValue::Integer(1)])
            .await
        {
            Outcome::Ok(_) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        match txn
            .execute(&cx, "INSERT INTO t VALUES (?1)", &[SqliteValue::Integer(2)])
            .await
        {
            Outcome::Ok(_) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        test_section!("Commit");
        match txn.commit(&cx).await {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        test_section!("Verify committed data");
        let rows = match conn.query(&cx, "SELECT v FROM t ORDER BY v", &[]).await {
            Outcome::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get_i64("v").unwrap(), 1);
        assert_eq!(rows[1].get_i64("v").unwrap(), 2);

        test_complete!("e2e_sqlite_transaction_commit");
    });
}

#[test]
fn e2e_sqlite_transaction_rollback() {
    init_test_logging();
    test_phase!("SQLite Transaction Rollback");

    run_test_with_cx(|cx| async move {
        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(c) => c,
            other => panic!("expected Ok, got {other:?}"),
        };

        match conn
            .execute_batch(
                &cx,
                "CREATE TABLE t (v INTEGER); INSERT INTO t VALUES (1)",
            )
            .await
        {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        test_section!("Begin transaction and modify");
        let txn = match conn.begin(&cx).await {
            Outcome::Ok(t) => t,
            Outcome::Err(e) => panic!("begin failed: {e}"),
            _ => panic!("begin cancelled or panicked"),
        };

        match txn
            .execute(&cx, "INSERT INTO t VALUES (?1)", &[SqliteValue::Integer(2)])
            .await
        {
            Outcome::Ok(_) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        test_section!("Rollback");
        match txn.rollback(&cx).await {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        test_section!("Verify rollback");
        let rows = match conn.query(&cx, "SELECT v FROM t", &[]).await {
            Outcome::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_with_log!(
            rows.len() == 1,
            "rollback preserved original row only",
            1,
            rows.len()
        );
        assert_eq!(rows[0].get_i64("v").unwrap(), 1);

        test_complete!("e2e_sqlite_transaction_rollback");
    });
}

#[test]
fn e2e_sqlite_transaction_drop_rollback() {
    init_test_logging();
    test_phase!("SQLite Transaction Drop Rollback");

    run_test_with_cx(|cx| async move {
        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(c) => c,
            other => panic!("expected Ok, got {other:?}"),
        };

        match conn
            .execute_batch(
                &cx,
                "CREATE TABLE t (v INTEGER); INSERT INTO t VALUES (1)",
            )
            .await
        {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        test_section!("Begin transaction, insert, then drop without commit");
        {
            let txn = match conn.begin(&cx).await {
                Outcome::Ok(t) => t,
                Outcome::Err(e) => panic!("begin failed: {e}"),
                _ => panic!("begin cancelled or panicked"),
            };
            match txn
                .execute(&cx, "INSERT INTO t VALUES (?1)", &[SqliteValue::Integer(99)])
                .await
            {
                Outcome::Ok(_) => {}
                other => panic!("expected Ok, got {other:?}"),
            }
            // txn dropped here - should auto-rollback
        }

        test_section!("Verify auto-rollback on drop");
        let rows = match conn.query(&cx, "SELECT v FROM t", &[]).await {
            Outcome::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get_i64("v").unwrap(), 1);

        test_complete!("e2e_sqlite_transaction_drop_rollback");
    });
}

#[test]
fn e2e_sqlite_immediate_transaction() {
    init_test_logging();
    test_phase!("SQLite Immediate Transaction");

    run_test_with_cx(|cx| async move {
        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(c) => c,
            other => panic!("expected Ok, got {other:?}"),
        };

        match conn
            .execute_batch(&cx, "CREATE TABLE t (v INTEGER)")
            .await
        {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        let txn = match conn.begin_immediate(&cx).await {
            Outcome::Ok(t) => t,
            Outcome::Err(e) => panic!("begin_immediate failed: {e}"),
            _ => panic!("begin_immediate cancelled or panicked"),
        };
        match txn
            .execute(&cx, "INSERT INTO t VALUES (1)", &[])
            .await
        {
            Outcome::Ok(_) => {}
            other => panic!("expected Ok, got {other:?}"),
        }
        match txn.commit(&cx).await {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        let rows = match conn.query(&cx, "SELECT COUNT(*) as cnt FROM t", &[]).await {
            Outcome::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_eq!(rows[0].get_i64("cnt").unwrap(), 1);

        test_complete!("e2e_sqlite_immediate_transaction");
    });
}

#[test]
fn e2e_sqlite_exclusive_transaction() {
    init_test_logging();
    test_phase!("SQLite Exclusive Transaction");

    run_test_with_cx(|cx| async move {
        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(c) => c,
            other => panic!("expected Ok, got {other:?}"),
        };

        match conn
            .execute_batch(&cx, "CREATE TABLE t (v INTEGER)")
            .await
        {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        let txn = match conn.begin_exclusive(&cx).await {
            Outcome::Ok(t) => t,
            Outcome::Err(e) => panic!("begin_exclusive failed: {e}"),
            _ => panic!("begin_exclusive cancelled or panicked"),
        };
        match txn
            .execute(&cx, "INSERT INTO t VALUES (1)", &[])
            .await
        {
            Outcome::Ok(_) => {}
            other => panic!("expected Ok, got {other:?}"),
        }
        match txn.commit(&cx).await {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        let rows = match conn.query(&cx, "SELECT COUNT(*) as cnt FROM t", &[]).await {
            Outcome::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_eq!(rows[0].get_i64("cnt").unwrap(), 1);

        test_complete!("e2e_sqlite_exclusive_transaction");
    });
}

#[test]
fn e2e_sqlite_transaction_query() {
    init_test_logging();
    test_phase!("SQLite Transaction Query");

    run_test_with_cx(|cx| async move {
        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(c) => c,
            other => panic!("expected Ok, got {other:?}"),
        };

        match conn
            .execute_batch(
                &cx,
                "CREATE TABLE t (v INTEGER); INSERT INTO t VALUES (10); INSERT INTO t VALUES (20)",
            )
            .await
        {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        test_section!("Query within transaction");
        let txn = match conn.begin(&cx).await {
            Outcome::Ok(t) => t,
            Outcome::Err(e) => panic!("begin failed: {e}"),
            _ => panic!("begin cancelled or panicked"),
        };

        let rows = match txn.query(&cx, "SELECT v FROM t ORDER BY v", &[]).await {
            Outcome::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get_i64("v").unwrap(), 10);
        assert_eq!(rows[1].get_i64("v").unwrap(), 20);

        match txn.commit(&cx).await {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        test_complete!("e2e_sqlite_transaction_query");
    });
}

// =========================================================================
// Error recovery
// =========================================================================

#[test]
fn e2e_sqlite_invalid_sql() {
    init_test_logging();
    test_phase!("SQLite Invalid SQL");

    run_test_with_cx(|cx| async move {
        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(c) => c,
            other => panic!("expected Ok, got {other:?}"),
        };

        test_section!("Execute invalid SQL");
        match conn.execute_batch(&cx, "THIS IS NOT SQL").await {
            Outcome::Err(_) => tracing::info!("correctly got error for invalid SQL"),
            other => panic!("expected Err, got {other:?}"),
        }

        test_section!("Connection still usable after error");
        match conn
            .execute_batch(&cx, "CREATE TABLE t (v INTEGER)")
            .await
        {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok after recovery, got {other:?}"),
        }

        test_complete!("e2e_sqlite_invalid_sql");
    });
}

#[test]
fn e2e_sqlite_operations_after_close() {
    init_test_logging();
    test_phase!("SQLite Operations After Close");

    run_test_with_cx(|cx| async move {
        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(c) => c,
            other => panic!("expected Ok, got {other:?}"),
        };

        conn.close().unwrap();

        test_section!("Query on closed connection");
        match conn.query(&cx, "SELECT 1", &[]).await {
            Outcome::Err(_) => tracing::info!("correctly rejected query on closed connection"),
            other => panic!("expected Err, got {other:?}"),
        }

        test_section!("Execute on closed connection");
        match conn.execute(&cx, "SELECT 1", &[]).await {
            Outcome::Err(_) => tracing::info!("correctly rejected execute on closed connection"),
            other => panic!("expected Err, got {other:?}"),
        }

        test_section!("Batch execute on closed connection");
        match conn.execute_batch(&cx, "SELECT 1").await {
            Outcome::Err(_) => {
                tracing::info!("correctly rejected batch execute on closed connection")
            }
            other => panic!("expected Err, got {other:?}"),
        }

        test_complete!("e2e_sqlite_operations_after_close");
    });
}

#[test]
fn e2e_sqlite_constraint_violation() {
    init_test_logging();
    test_phase!("SQLite Constraint Violation");

    run_test_with_cx(|cx| async move {
        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(c) => c,
            other => panic!("expected Ok, got {other:?}"),
        };

        match conn
            .execute_batch(
                &cx,
                "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL)",
            )
            .await
        {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        match conn
            .execute(
                &cx,
                "INSERT INTO t (name) VALUES (?1)",
                &[SqliteValue::Text("Alice".into())],
            )
            .await
        {
            Outcome::Ok(_) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        test_section!("Duplicate unique key");
        match conn
            .execute(
                &cx,
                "INSERT INTO t (name) VALUES (?1)",
                &[SqliteValue::Text("Alice".into())],
            )
            .await
        {
            Outcome::Err(_) => tracing::info!("correctly got constraint violation"),
            other => panic!("expected Err, got {other:?}"),
        }

        test_section!("NOT NULL violation");
        match conn
            .execute(
                &cx,
                "INSERT INTO t (name) VALUES (?1)",
                &[SqliteValue::Null],
            )
            .await
        {
            Outcome::Err(_) => tracing::info!("correctly got NOT NULL violation"),
            other => panic!("expected Err, got {other:?}"),
        }

        test_section!("Connection still usable");
        let rows = match conn.query(&cx, "SELECT COUNT(*) as cnt FROM t", &[]).await {
            Outcome::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_eq!(rows[0].get_i64("cnt").unwrap(), 1);

        test_complete!("e2e_sqlite_constraint_violation");
    });
}

#[test]
fn e2e_sqlite_transaction_error_recovery() {
    init_test_logging();
    test_phase!("SQLite Transaction Error Recovery");

    run_test_with_cx(|cx| async move {
        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(c) => c,
            other => panic!("expected Ok, got {other:?}"),
        };

        match conn
            .execute_batch(
                &cx,
                "CREATE TABLE t (v INTEGER UNIQUE); INSERT INTO t VALUES (1)",
            )
            .await
        {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        test_section!("Transaction with error mid-way");
        let txn = match conn.begin(&cx).await {
            Outcome::Ok(t) => t,
            Outcome::Err(e) => panic!("begin failed: {e}"),
            _ => panic!("begin cancelled or panicked"),
        };

        // First insert succeeds
        match txn
            .execute(&cx, "INSERT INTO t VALUES (2)", &[])
            .await
        {
            Outcome::Ok(_) => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        // Second insert fails (duplicate)
        match txn
            .execute(&cx, "INSERT INTO t VALUES (1)", &[])
            .await
        {
            Outcome::Err(_) => tracing::info!("got expected constraint error in transaction"),
            other => panic!("expected Err, got {other:?}"),
        }

        // Rollback after error
        match txn.rollback(&cx).await {
            Outcome::Ok(()) => {}
            other => panic!("expected Ok rollback, got {other:?}"),
        }

        test_section!("Verify original data intact");
        let rows = match conn.query(&cx, "SELECT v FROM t", &[]).await {
            Outcome::Ok(r) => r,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get_i64("v").unwrap(), 1);

        test_complete!("e2e_sqlite_transaction_error_recovery");
    });
}

// =========================================================================
// SqliteValue and SqliteError types
// =========================================================================

#[test]
fn e2e_sqlite_value_display_and_accessors() {
    init_test_logging();
    test_phase!("SQLite Value Display and Accessors");

    assert_eq!(SqliteValue::Null.to_string(), "NULL");
    assert_eq!(SqliteValue::Integer(42).to_string(), "42");
    assert_eq!(SqliteValue::Real(3.14).to_string(), "3.14");
    assert_eq!(SqliteValue::Text("hi".into()).to_string(), "hi");
    assert_eq!(
        SqliteValue::Blob(vec![1, 2, 3]).to_string(),
        "<blob 3 bytes>"
    );

    assert!(SqliteValue::Null.is_null());
    assert!(!SqliteValue::Integer(0).is_null());
    assert_eq!(SqliteValue::Integer(42).as_integer(), Some(42));
    assert_eq!(SqliteValue::Real(1.0).as_real(), Some(1.0));
    assert_eq!(SqliteValue::Integer(5).as_real(), Some(5.0)); // coercion
    assert_eq!(SqliteValue::Text("x".into()).as_text(), Some("x"));
    assert_eq!(
        SqliteValue::Blob(vec![0xFF]).as_blob(),
        Some(&[0xFF][..])
    );

    // Negative cases
    assert_eq!(SqliteValue::Null.as_integer(), None);
    assert_eq!(SqliteValue::Null.as_real(), None);
    assert_eq!(SqliteValue::Null.as_text(), None);
    assert_eq!(SqliteValue::Null.as_blob(), None);

    test_complete!("e2e_sqlite_value_display_and_accessors");
}

#[test]
fn e2e_sqlite_error_display() {
    init_test_logging();
    test_phase!("SQLite Error Display");

    let err = SqliteError::ConnectionClosed;
    assert!(format!("{err}").contains("closed"));

    let err = SqliteError::ColumnNotFound("col".into());
    assert!(format!("{err}").contains("col"));

    let err = SqliteError::TypeMismatch {
        column: "age".into(),
        expected: "integer",
        actual: "text".into(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("age") && msg.contains("integer") && msg.contains("text"));

    let err = SqliteError::TransactionFinished;
    assert!(format!("{err}").contains("finished"));

    let err = SqliteError::LockPoisoned;
    assert!(format!("{err}").contains("poisoned"));

    test_complete!("e2e_sqlite_error_display");
}

// =========================================================================
// Migration configuration
// =========================================================================

#[test]
fn e2e_migration_mode_decisions() {
    init_test_logging();
    test_phase!("Migration Mode Decisions");

    test_section!("TraditionalOnly");
    assert!(!MigrationMode::TraditionalOnly.should_use_raptorq(None, 0));
    assert!(!MigrationMode::TraditionalOnly.should_use_raptorq(None, 100_000));
    // Explicit hint overrides
    assert!(MigrationMode::TraditionalOnly.should_use_raptorq(Some(true), 0));

    test_section!("SymbolNativeOnly");
    assert!(MigrationMode::SymbolNativeOnly.should_use_raptorq(None, 0));
    assert!(!MigrationMode::SymbolNativeOnly.should_use_raptorq(Some(false), 100_000));

    test_section!("PreferTraditional");
    assert!(!MigrationMode::PreferTraditional.should_use_raptorq(None, 100_000));

    test_section!("PreferSymbolNative");
    assert!(MigrationMode::PreferSymbolNative.should_use_raptorq(None, 0));

    test_section!("Adaptive");
    assert!(!MigrationMode::Adaptive.should_use_raptorq(None, 100));
    assert!(!MigrationMode::Adaptive.should_use_raptorq(None, 1024)); // boundary: not >1024
    assert!(MigrationMode::Adaptive.should_use_raptorq(None, 1025));

    test_complete!("e2e_migration_mode_decisions");
}

#[test]
fn e2e_migration_builder_lifecycle() {
    init_test_logging();
    test_phase!("Migration Builder Lifecycle");

    test_section!("Default config");
    let config = configure_migration().build();
    assert_eq!(config.mode(), MigrationMode::PreferTraditional);
    assert!(config.enabled_features().is_empty());

    test_section!("Enable features individually");
    let config = configure_migration()
        .enable(MigrationFeature::JoinEncoding)
        .enable(MigrationFeature::SymbolTracing)
        .with_mode(MigrationMode::Adaptive)
        .build();
    assert!(config.is_enabled(MigrationFeature::JoinEncoding));
    assert!(config.is_enabled(MigrationFeature::SymbolTracing));
    assert!(!config.is_enabled(MigrationFeature::EpochBarriers));
    assert_eq!(config.mode(), MigrationMode::Adaptive);

    test_section!("Full RaptorQ mode");
    let config = configure_migration().full_raptorq().build();
    assert_eq!(config.mode(), MigrationMode::SymbolNativeOnly);
    for feature in MigrationFeature::all() {
        assert!(config.is_enabled(feature), "missing feature: {feature:?}");
    }

    test_section!("Enable then disable");
    let config = configure_migration()
        .full_raptorq()
        .disable(MigrationFeature::EpochBarriers)
        .disable(MigrationFeature::SymbolCancellation)
        .build();
    assert!(config.is_enabled(MigrationFeature::JoinEncoding));
    assert!(!config.is_enabled(MigrationFeature::EpochBarriers));
    assert!(!config.is_enabled(MigrationFeature::SymbolCancellation));

    test_section!("Per-operation overrides");
    let config = configure_migration()
        .with_mode(MigrationMode::PreferTraditional)
        .override_operation("heavy_join", MigrationMode::SymbolNativeOnly)
        .override_operation("light_op", MigrationMode::TraditionalOnly)
        .build();
    assert_eq!(config.mode_for("heavy_join"), MigrationMode::SymbolNativeOnly);
    assert_eq!(config.mode_for("light_op"), MigrationMode::TraditionalOnly);
    assert_eq!(config.mode_for("unset_op"), MigrationMode::PreferTraditional);

    test_complete!("e2e_migration_builder_lifecycle");
}

#[test]
fn e2e_migration_feature_all() {
    init_test_logging();
    test_phase!("Migration Feature All");

    let all: Vec<_> = MigrationFeature::all().collect();
    assert_eq!(all.len(), 6);
    // Verify no duplicates
    let mut set = std::collections::HashSet::new();
    for f in &all {
        assert!(set.insert(f), "duplicate feature: {f:?}");
    }

    test_complete!("e2e_migration_feature_all");
}

#[test]
fn e2e_dual_value_traditional() {
    init_test_logging();
    test_phase!("DualValue Traditional");

    let value: DualValue<i32> = DualValue::Traditional(42);
    assert!(value.is_traditional());
    assert!(!value.uses_raptorq());
    assert_eq!(value.get().unwrap(), 42);

    test_complete!("e2e_dual_value_traditional");
}

#[test]
fn e2e_dual_value_conversion_roundtrip() {
    init_test_logging();
    test_phase!("DualValue Conversion Roundtrip");

    let config = asupersync::config::EncodingConfig::default();
    let mut value = DualValue::Traditional("hello world".to_string());

    test_section!("Convert to symbol-native");
    value.ensure_symbols(&config);
    assert!(value.uses_raptorq());
    assert!(!value.is_traditional());

    test_section!("Retrieve value from symbol-native");
    assert_eq!(value.get().unwrap(), "hello world");

    test_section!("Second ensure_symbols is no-op");
    value.ensure_symbols(&config);
    assert!(value.uses_raptorq());
    assert_eq!(value.get().unwrap(), "hello world");

    test_complete!("e2e_dual_value_conversion_roundtrip");
}

#[test]
fn e2e_dual_value_debug() {
    init_test_logging();
    test_phase!("DualValue Debug");

    let trad: DualValue<i32> = DualValue::Traditional(42);
    let dbg = format!("{trad:?}");
    assert!(dbg.contains("Traditional"));

    let config = asupersync::config::EncodingConfig::default();
    let mut sym = DualValue::Traditional(vec![1, 2, 3]);
    sym.ensure_symbols(&config);
    let dbg = format!("{sym:?}");
    assert!(dbg.contains("SymbolNative"));

    test_complete!("e2e_dual_value_debug");
}

#[test]
fn e2e_dual_value_error_display() {
    init_test_logging();
    test_phase!("DualValueError Display");

    let err = DualValueError::SerializationFailed("bad data".into());
    assert!(format!("{err}").contains("serialization failed"));
    assert!(format!("{err}").contains("bad data"));

    let err = DualValueError::DeserializationFailed("corrupt".into());
    assert!(format!("{err}").contains("deserialization failed"));

    test_complete!("e2e_dual_value_error_display");
}

#[test]
fn e2e_migration_mode_default() {
    init_test_logging();
    test_phase!("MigrationMode Default");

    assert_eq!(MigrationMode::default(), MigrationMode::PreferTraditional);

    test_complete!("e2e_migration_mode_default");
}

#[test]
fn e2e_migration_config_default() {
    init_test_logging();
    test_phase!("MigrationConfig Default");

    let config = asupersync::migration::MigrationConfig::default();
    assert_eq!(config.mode(), MigrationMode::PreferTraditional);
    assert!(config.enabled_features().is_empty());

    test_complete!("e2e_migration_config_default");
}
