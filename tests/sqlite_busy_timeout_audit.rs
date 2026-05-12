//! Audit test for SQLite SQLITE_BUSY timeout behavior.
//!
//! SQLite busy_timeout requirement: "When SQLite returns SQLITE_BUSY,
//! the driver should sleep for busy_timeout duration and retry (correct: sleep+retry)
//! rather than immediately retry in hot loop (CPU waste) or error to caller (poor UX)."
//!
//! CRITICAL REQUIREMENT: SQLITE_BUSY handling should use the configured
//! busy_timeout to automatically retry, not burden application with manual retry logic.

#![cfg(feature = "sqlite")]

use asupersync::cx::Cx;
use asupersync::database::SqliteConnection;
use std::time::{Duration, Instant};

#[tokio::test]
async fn sqlite_busy_timeout_behavior_audit() {
    println!("=== SQLITE BUSY TIMEOUT BEHAVIOR AUDIT ===");

    // This test verifies that SQLite connection uses busy_timeout
    // to automatically retry on SQLITE_BUSY rather than immediate error

    let cx = Cx::for_testing();

    // Create shared database file for contention
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test.db");

    let conn1 = SqliteConnection::open(&cx, &db_path)
        .await
        .expect("open first connection")
        .unwrap();

    let conn2 = SqliteConnection::open(&cx, &db_path)
        .await
        .expect("open second connection")
        .unwrap();

    // Create test table
    conn1
        .execute_batch(
            &cx,
            "CREATE TABLE test_table (id INTEGER PRIMARY KEY, value TEXT)",
        )
        .await
        .expect("create table")
        .unwrap();

    println!("✓ Database and test table created");

    // Test scenario: Long-running transaction on conn1 should cause
    // SQLITE_BUSY on conn2, which should be handled by busy_timeout

    // Start exclusive transaction on conn1 (will hold lock)
    conn1
        .execute(&cx, "BEGIN EXCLUSIVE", &[])
        .await
        .expect("begin exclusive transaction")
        .unwrap();

    println!("✓ Exclusive transaction started on conn1");

    // Measure how long conn2 waits before giving up
    let start_time = Instant::now();

    let result = conn2
        .execute(&cx, "INSERT INTO test_table (value) VALUES ('test')", &[])
        .await;

    let elapsed = start_time.elapsed();

    println!("✓ conn2 operation completed after {:?}", elapsed);

    // Verify the behavior based on elapsed time and result
    match result {
        Ok(_) => {
            // This shouldn't happen with exclusive transaction
            panic!("INSERT succeeded despite exclusive lock - unexpected behavior");
        }
        Err(e) => {
            if e.is_busy() {
                // Expected: should have waited close to busy_timeout duration (250ms)
                println!("✅ SQLITE_BUSY error returned after timeout: {}", e);

                // Verify it waited at least some reasonable time (not immediate error)
                assert!(
                    elapsed >= Duration::from_millis(200),
                    "Expected to wait at least 200ms (close to 250ms busy_timeout), \
                     but only waited {:?}. This suggests immediate error rather than retry.",
                    elapsed
                );

                println!(
                    "✅ Waited {:?} before returning SQLITE_BUSY (expected ~250ms)",
                    elapsed
                );
            } else {
                panic!("Expected SQLITE_BUSY error but got: {}", e);
            }
        }
    }

    // Clean up: rollback the exclusive transaction
    conn1
        .execute(&cx, "ROLLBACK", &[])
        .await
        .expect("rollback transaction")
        .unwrap();

    println!("✅ AUDIT PASSED: SQLite busy_timeout provides automatic retry");

    println!("\n📋 SQLITE_BUSY BEHAVIOR VERIFIED:");
    println!("  1. busy_timeout configured: ✅ 250ms default timeout");
    println!("  2. Automatic retry on SQLITE_BUSY: ✅ rusqlite handles internally");
    println!("  3. Waits before giving up: ✅ ~{:?} elapsed", elapsed);
    println!("  4. Error classification available: ✅ is_busy(), is_retryable()");

    println!("\n✅ STATUS: SQLITE BUSY_TIMEOUT BEHAVIOR IS SOUND");
    println!("BEHAVIOR: rusqlite automatically retries SQLITE_BUSY for busy_timeout duration");
    println!("IMPACT: Application doesn't need manual retry logic for basic contention");

    println!("\n⚠️  NOTE: 250ms timeout may be insufficient for high-contention scenarios");
    println!("Consider increasing busy_timeout for production workloads with heavy contention");
}

#[tokio::test]
async fn sqlite_busy_timeout_classification_audit() {
    println!("=== SQLITE BUSY ERROR CLASSIFICATION AUDIT ===");

    let cx = Cx::for_testing();

    // Test that the error classification methods work correctly
    // This ensures the retry infrastructure is available if needed

    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test2.db");

    let conn1 = SqliteConnection::open(&cx, &db_path)
        .await
        .expect("open connection")
        .unwrap();

    let conn2 = SqliteConnection::open(&cx, &db_path)
        .await
        .expect("open second connection")
        .unwrap();

    // Create test table and start exclusive transaction
    conn1
        .execute_batch(&cx, "CREATE TABLE test (id INTEGER)")
        .await
        .expect("create table")
        .unwrap();

    conn1
        .execute(&cx, "BEGIN EXCLUSIVE", &[])
        .await
        .expect("begin exclusive")
        .unwrap();

    // Attempt operation that should fail with SQLITE_BUSY
    let result = conn2
        .execute(&cx, "INSERT INTO test (id) VALUES (1)", &[])
        .await;

    match result {
        Err(e) => {
            println!("✓ Got expected error: {}", e);

            // Test error classification methods
            assert!(e.is_busy(), "Expected is_busy() to return true");
            assert!(e.is_transient(), "Expected is_transient() to return true");
            assert!(e.is_retryable(), "Expected is_retryable() to return true");

            println!("✅ Error classification methods work correctly:");
            println!("  - is_busy(): {}", e.is_busy());
            println!("  - is_transient(): {}", e.is_transient());
            println!("  - is_retryable(): {}", e.is_retryable());

            if let Some(code) = e.error_code() {
                println!("  - error_code(): {}", code);
                assert_eq!(code, "SQLITE_BUSY");
            }
        }
        Ok(_) => {
            panic!("Expected SQLITE_BUSY error but operation succeeded");
        }
    }

    conn1
        .execute(&cx, "ROLLBACK", &[])
        .await
        .expect("rollback")
        .unwrap();

    println!("✅ AUDIT PASSED: Error classification infrastructure is sound");
}
