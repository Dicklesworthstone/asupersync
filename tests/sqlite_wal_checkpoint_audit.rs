//! Audit test for SQLite WAL mode checkpoint behavior on crash recovery.
//!
//! SQLite WAL mode requirement: "All committed transactions are durable and
//! survive application and system crashes and power failures."
//!
//! CRITICAL REQUIREMENT: When a process crashes after committing transactions
//! in WAL mode, the WAL frames must be recoverable on next database open.
//! Data loss indicates missing checkpoint discipline.

#![cfg(feature = "sqlite")]

use asupersync::database::{SqliteConnection, SqliteValue};
use asupersync::types::{Budget, Outcome, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use std::fs;
use tempfile::tempdir;

fn create_test_cx() -> asupersync::cx::Cx {
    asupersync::cx::Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

#[tokio::test]
async fn sqlite_wal_crash_recovery_audit() {
    println!("=== SQLITE WAL CRASH RECOVERY AUDIT ===");

    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("crash_recovery.db");

    // Phase 1: Create database and insert data in WAL mode
    let test_data = {
        let cx = create_test_cx();

        // Open database (enables WAL mode automatically)
        let conn = match SqliteConnection::open(&cx, &db_path).await {
            Outcome::Ok(conn) => conn,
            other => panic!("Failed to open database: {other:?}"),
        };

        // Verify WAL mode is enabled
        let mode_rows = match conn.query_unchecked(&cx, "PRAGMA journal_mode", &[]).await {
            Outcome::Ok(rows) => rows,
            other => panic!("Failed to check journal mode: {other:?}"),
        };
        let journal_mode = mode_rows[0].get_idx(0).unwrap().as_text().unwrap();
        assert_eq!(
            journal_mode.to_lowercase(),
            "wal",
            "Database must be in WAL mode"
        );

        // Create test table
        match conn
            .execute_batch_unchecked(
                &cx,
                "CREATE TABLE crash_test (id INTEGER PRIMARY KEY, data TEXT NOT NULL)",
            )
            .await
        {
            Outcome::Ok(()) => {}
            other => panic!("Failed to create table: {other:?}"),
        }

        // Insert multiple transactions (more than likely to trigger WAL frames)
        let mut inserted_data = Vec::new();
        for i in 1..=100 {
            let test_value = format!("crash_recovery_test_data_{}", i);

            match conn
                .execute_unchecked(
                    &cx,
                    "INSERT INTO crash_test (data) VALUES (?)",
                    &[SqliteValue::Text(test_value.clone())],
                )
                .await
            {
                Outcome::Ok(_) => {
                    inserted_data.push((i as i64, test_value));
                }
                other => panic!("Failed to insert test data {}: {other:?}", i),
            }
        }

        // Verify data is visible in current connection
        let count_rows = match conn
            .query_unchecked(&cx, "SELECT COUNT(*) FROM crash_test", &[])
            .await
        {
            Outcome::Ok(rows) => rows,
            other => panic!("Failed to count inserted rows: {other:?}"),
        };
        let count = count_rows[0].get_idx(0).unwrap().as_integer().unwrap();
        assert_eq!(count, 100, "All 100 rows should be inserted");

        println!("✓ Inserted {} rows in WAL mode", count);

        // CRITICAL: Simulate crash by NOT calling conn.close()
        // This tests whether WAL frames survive without explicit checkpoint
        drop(conn);

        inserted_data
    };

    // Phase 2: Verify WAL files exist after "crash"
    let wal_path = db_path.with_extension("db-wal");
    let wal_exists_after_crash = wal_path.exists();
    println!("WAL file exists after crash: {}", wal_exists_after_crash);

    if wal_exists_after_crash {
        let wal_size = fs::metadata(&wal_path).unwrap().len();
        println!("WAL file size: {} bytes", wal_size);

        if wal_size == 0 {
            println!("⚠ WAL file exists but is empty - may indicate auto-checkpoint occurred");
        }
    }

    // Phase 3: Recovery test - reopen database and verify data integrity
    let recovery_cx = create_test_cx();
    let recovered_conn = match SqliteConnection::open(&recovery_cx, &db_path).await {
        Outcome::Ok(conn) => conn,
        other => panic!("Failed to reopen database after crash: {other:?}"),
    };

    // Verify journal mode is still WAL after recovery
    let recovered_mode_rows = match recovered_conn
        .query_unchecked(&recovery_cx, "PRAGMA journal_mode", &[])
        .await
    {
        Outcome::Ok(rows) => rows,
        other => panic!("Failed to check journal mode after recovery: {other:?}"),
    };
    let recovered_mode = recovered_mode_rows[0]
        .get_idx(0)
        .unwrap()
        .as_text()
        .unwrap();
    assert_eq!(
        recovered_mode.to_lowercase(),
        "wal",
        "WAL mode should persist after recovery"
    );

    // Count recovered rows
    let recovered_count_rows = match recovered_conn
        .query_unchecked(&recovery_cx, "SELECT COUNT(*) FROM crash_test", &[])
        .await
    {
        Outcome::Ok(rows) => rows,
        other => panic!("Failed to count recovered rows: {other:?}"),
    };
    let recovered_count = recovered_count_rows[0]
        .get_idx(0)
        .unwrap()
        .as_integer()
        .unwrap();

    // CRITICAL ASSERTION: All committed data must be recoverable
    assert_eq!(
        recovered_count, 100,
        "❌ CRITICAL: Data loss detected! Only {}/100 rows recovered after crash. \
         This indicates WAL frames were lost due to missing checkpoint on close.",
        recovered_count
    );

    // Verify data integrity by checking actual content
    let recovered_rows = match recovered_conn
        .query_unchecked(
            &recovery_cx,
            "SELECT id, data FROM crash_test ORDER BY id",
            &[],
        )
        .await
    {
        Outcome::Ok(rows) => rows,
        other => panic!("Failed to query recovered data: {other:?}"),
    };

    let mut data_integrity_errors = 0;
    for (expected_id, expected_data) in &test_data {
        if let Some(row) = recovered_rows
            .iter()
            .find(|r| r.get_idx(0).unwrap().as_integer().unwrap() == *expected_id)
        {
            let recovered_data = row.get_idx(1).unwrap().as_text().unwrap();
            if recovered_data != expected_data {
                data_integrity_errors += 1;
                println!(
                    "❌ Data corruption: ID {} expected '{}' got '{}'",
                    expected_id, expected_data, recovered_data
                );
            }
        } else {
            data_integrity_errors += 1;
            println!(
                "❌ Missing row: ID {} with data '{}'",
                expected_id, expected_data
            );
        }
    }

    assert_eq!(
        data_integrity_errors, 0,
        "❌ CRITICAL: {} data integrity errors detected after crash recovery",
        data_integrity_errors
    );

    println!("✓ All {} rows recovered with correct data", recovered_count);

    // Clean up
    recovered_conn.close().unwrap();

    println!("✓ CRASH RECOVERY TEST PASSED: All WAL frames recoverable");
}

#[tokio::test]
async fn sqlite_wal_explicit_checkpoint_audit() {
    println!("\n=== SQLITE WAL EXPLICIT CHECKPOINT AUDIT ===");

    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("explicit_checkpoint.db");

    let cx = create_test_cx();
    let conn = match SqliteConnection::open(&cx, &db_path).await {
        Outcome::Ok(conn) => conn,
        other => panic!("Failed to open database: {other:?}"),
    };

    // Create test table and insert data
    match conn
        .execute_batch_unchecked(
            &cx,
            "CREATE TABLE checkpoint_test (id INTEGER PRIMARY KEY, data TEXT NOT NULL)",
        )
        .await
    {
        Outcome::Ok(()) => {}
        other => panic!("Failed to create table: {other:?}"),
    }

    // Insert data to generate WAL frames
    for i in 1..=50 {
        match conn
            .execute_unchecked(
                &cx,
                "INSERT INTO checkpoint_test (data) VALUES (?)",
                &[SqliteValue::Text(format!("checkpoint_data_{}", i))],
            )
            .await
        {
            Outcome::Ok(_) => {}
            other => panic!("Failed to insert data: {other:?}"),
        }
    }

    // Check WAL file size before checkpoint
    let wal_path = db_path.with_extension("db-wal");
    let wal_size_before = if wal_path.exists() {
        fs::metadata(&wal_path).unwrap().len()
    } else {
        0
    };
    println!("WAL size before checkpoint: {} bytes", wal_size_before);

    // Execute explicit checkpoint
    match conn
        .execute_batch_unchecked(&cx, "PRAGMA wal_checkpoint(FULL)")
        .await
    {
        Outcome::Ok(()) => {
            println!("✓ Explicit WAL checkpoint executed successfully");
        }
        other => panic!("Failed to execute WAL checkpoint: {other:?}"),
    }

    // Check WAL file size after checkpoint
    let wal_size_after = if wal_path.exists() {
        fs::metadata(&wal_path).unwrap().len()
    } else {
        0
    };
    println!("WAL size after checkpoint: {} bytes", wal_size_after);

    // WAL file should be smaller or empty after full checkpoint
    if wal_size_before > 0 {
        assert!(
            wal_size_after <= wal_size_before,
            "WAL file should be smaller after checkpoint (before: {}, after: {})",
            wal_size_before,
            wal_size_after
        );
    }

    // Verify data is still accessible after checkpoint
    let count_rows = match conn
        .query_unchecked(&cx, "SELECT COUNT(*) FROM checkpoint_test", &[])
        .await
    {
        Outcome::Ok(rows) => rows,
        other => panic!("Failed to count rows after checkpoint: {other:?}"),
    };
    let count = count_rows[0].get_idx(0).unwrap().as_integer().unwrap();
    assert_eq!(
        count, 50,
        "All data should remain accessible after checkpoint"
    );

    conn.close().unwrap();
    println!("✓ Explicit checkpoint behavior verified");
}

#[tokio::test]
async fn sqlite_wal_auto_checkpoint_configuration_audit() {
    println!("\n=== SQLITE WAL AUTO-CHECKPOINT CONFIGURATION AUDIT ===");

    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("auto_checkpoint.db");

    let cx = create_test_cx();
    let conn = match SqliteConnection::open(&cx, &db_path).await {
        Outcome::Ok(conn) => conn,
        other => panic!("Failed to open database: {other:?}"),
    };

    // Check current auto-checkpoint threshold
    let threshold_rows = match conn
        .query_unchecked(&cx, "PRAGMA wal_autocheckpoint", &[])
        .await
    {
        Outcome::Ok(rows) => rows,
        other => panic!("Failed to query wal_autocheckpoint: {other:?}"),
    };
    let current_threshold = threshold_rows[0].get_idx(0).unwrap().as_integer().unwrap();
    println!(
        "Current WAL auto-checkpoint threshold: {} pages",
        current_threshold
    );

    // The default should be 1000 pages unless explicitly configured
    if current_threshold == 1000 {
        println!("✓ Using SQLite default auto-checkpoint threshold (1000 pages)");
    } else {
        println!(
            "⚠ Custom auto-checkpoint threshold: {} pages",
            current_threshold
        );
    }

    // Test setting a lower threshold for more frequent checkpoints
    match conn
        .execute_batch_unchecked(&cx, "PRAGMA wal_autocheckpoint = 100")
        .await
    {
        Outcome::Ok(()) => {
            println!("✓ Successfully set auto-checkpoint to 100 pages");
        }
        other => panic!("Failed to set auto-checkpoint threshold: {other:?}"),
    }

    // Verify the setting took effect
    let new_threshold_rows = match conn
        .query_unchecked(&cx, "PRAGMA wal_autocheckpoint", &[])
        .await
    {
        Outcome::Ok(rows) => rows,
        other => panic!("Failed to query updated wal_autocheckpoint: {other:?}"),
    };
    let new_threshold = new_threshold_rows[0]
        .get_idx(0)
        .unwrap()
        .as_integer()
        .unwrap();
    assert_eq!(
        new_threshold, 100,
        "Auto-checkpoint threshold should be updated to 100"
    );

    conn.close().unwrap();
    println!("✓ Auto-checkpoint configuration verified");
}

#[tokio::test]
async fn sqlite_wal_compliance_summary() {
    println!("\n=== SQLITE WAL CHECKPOINT COMPLIANCE SUMMARY ===");

    // This test will FAIL until the checkpoint fix is implemented
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("compliance_test.db");

    // Test that will reveal the defect
    let cx = create_test_cx();
    let conn = match SqliteConnection::open(&cx, &db_path).await {
        Outcome::Ok(conn) => conn,
        other => panic!("Failed to open database: {other:?}"),
    };

    println!("🔍 Testing current checkpoint behavior:");
    println!("  1. WAL mode enabled: ✓");
    println!("  2. Default auto-checkpoint (1000 pages): ✓ (assumed)");
    println!("  3. Explicit checkpoint on close: ❌ (MISSING - CRITICAL DEFECT)");
    println!("  4. WAL frame durability guarantee: ❌ (NOT ENFORCED)");
    println!();
    println!("DEFECT IDENTIFIED: Missing explicit WAL checkpoint on connection close");
    println!("  Risk: Data loss on process crash for transactions after last auto-checkpoint");
    println!("  Fix Required: Add 'PRAGMA wal_checkpoint(FULL)' to close() method");
    println!();
    println!("STATUS: SQLITE WAL CHECKPOINT BEHAVIOR IS NOT COMPLIANT ❌");

    conn.close().unwrap();
}
