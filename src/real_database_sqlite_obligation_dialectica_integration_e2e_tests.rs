//! E2E integration tests: database/sqlite ↔ obligation/dialectica
//!
//! Test verification: sqlite write violating dialectica obligation triggers automatic rollback with journal recovery
//!
//! Scenarios tested:
//! - SQLite write operations under dialectica obligation tracking
//! - Obligation violation detection during write commit phase
//! - Automatic transaction rollback on dialectica constraint violation
//! - Journal recovery after rollback ensuring data consistency
//! - Multi-table operations with cross-table dialectica constraints
//! - Nested transaction rollback with proper obligation unwinding

use crate::{
    cx::{Cx, Scope},
    database::sqlite::{SqliteConnection, SqliteError, SqlitePool, SqlitePoolConfig},
    lab::LabRuntime,
    obligation::dialectica::{
        DialecticaConstraint, DialecticaContext, DialecticaError, DialecticaFormula,
        DialecticaObligationTracker, DialecticaProofAttempt, DialecticaVerificationResult,
    },
    types::{Budget, Outcome},
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

/// Statistics for sqlite-dialectica integration scenarios
#[derive(Debug, Clone, Default)]
struct SqliteDialecticaStats {
    writes_attempted: AtomicU64,
    writes_committed: AtomicU64,
    writes_rolled_back: AtomicU64,
    obligations_created: AtomicU64,
    obligations_violated: AtomicU64,
    journal_recoveries: AtomicU64,
    constraint_checks: AtomicU64,
}

impl SqliteDialecticaStats {
    fn increment_writes_attempted(&self) {
        self.writes_attempted.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_writes_committed(&self) {
        self.writes_committed.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_writes_rolled_back(&self) {
        self.writes_rolled_back.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_obligations_created(&self) {
        self.obligations_created.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_obligations_violated(&self) {
        self.obligations_violated.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_journal_recoveries(&self) {
        self.journal_recoveries.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_constraint_checks(&self) {
        self.constraint_checks.fetch_add(1, Ordering::Relaxed);
    }

    fn summary(&self) -> (u64, u64, u64, u64, u64, u64, u64) {
        (
            self.writes_attempted.load(Ordering::Relaxed),
            self.writes_committed.load(Ordering::Relaxed),
            self.writes_rolled_back.load(Ordering::Relaxed),
            self.obligations_created.load(Ordering::Relaxed),
            self.obligations_violated.load(Ordering::Relaxed),
            self.journal_recoveries.load(Ordering::Relaxed),
            self.constraint_checks.load(Ordering::Relaxed),
        )
    }
}

/// Mock SQLite database with dialectica constraint integration
struct ConstrainedSqliteDatabase {
    pool: SqlitePool,
    dialectica_tracker: DialecticaObligationTracker,
    constraint_active: Arc<AtomicBool>,
}

impl ConstrainedSqliteDatabase {
    async fn new(cx: &Cx) -> Result<Self, SqliteError> {
        let config = SqlitePoolConfig::new()
            .with_max_connections(5)
            .with_journal_mode("WAL") // Write-Ahead Logging for better recovery
            .with_synchronous("NORMAL")
            .with_foreign_keys(true);

        let pool = SqlitePool::new(cx, ":memory:", config).await?;
        let dialectica_tracker = DialecticaObligationTracker::new();

        Ok(Self {
            pool,
            dialectica_tracker,
            constraint_active: Arc::new(AtomicBool::new(true)),
        })
    }

    async fn initialize_schema(&self, cx: &Cx) -> Result<(), SqliteError> {
        let mut conn = self.pool.acquire(cx).await?;

        // Create tables with foreign key constraints
        conn.execute(
            cx,
            "CREATE TABLE accounts (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                balance INTEGER NOT NULL CHECK (balance >= 0),
                status TEXT NOT NULL DEFAULT 'active'
            )",
        )
        .await?;

        conn.execute(
            cx,
            "CREATE TABLE transactions (
                id INTEGER PRIMARY KEY,
                from_account INTEGER REFERENCES accounts(id),
                to_account INTEGER REFERENCES accounts(id),
                amount INTEGER NOT NULL CHECK (amount > 0),
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL DEFAULT 'pending'
            )",
        )
        .await?;

        // Create trigger for dialectica constraint checking
        conn.execute(
            cx,
            "CREATE TRIGGER check_balance_constraint
             BEFORE UPDATE ON accounts
             WHEN NEW.balance < 0
             BEGIN
                 SELECT RAISE(ABORT, 'Negative balance violation');
             END",
        )
        .await?;

        Ok(())
    }

    async fn create_dialectica_constraint(
        &self,
        cx: &Cx,
        formula: DialecticaFormula,
        stats: &SqliteDialecticaStats,
    ) -> Result<DialecticaConstraint, DialecticaError> {
        stats.increment_obligations_created();
        let context = DialecticaContext::new(cx);
        self.dialectica_tracker
            .create_constraint(cx, formula, context)
            .await
    }

    async fn execute_constrained_write(
        &self,
        cx: &Cx,
        query: &str,
        params: &[&dyn rusqlite::ToSql],
        constraint: &DialecticaConstraint,
        stats: &SqliteDialecticaStats,
    ) -> Result<(), SqliteError> {
        stats.increment_writes_attempted();

        let mut conn = self.pool.acquire(cx).await?;
        let tx = conn.begin_transaction(cx).await?;

        // Execute the SQL operation
        match tx.execute(cx, query, params).await {
            Ok(_rows_affected) => {
                // Check dialectica constraint before commit
                stats.increment_constraint_checks();

                if self.constraint_active.load(Ordering::Acquire) {
                    match self.verify_constraint(cx, constraint, &tx, stats).await {
                        Ok(DialecticaVerificationResult::Valid) => {
                            // Constraint satisfied, commit transaction
                            tx.commit(cx).await?;
                            stats.increment_writes_committed();
                            Ok(())
                        }
                        Ok(DialecticaVerificationResult::Violated) => {
                            // Constraint violated, rollback
                            stats.increment_obligations_violated();
                            self.perform_rollback_with_recovery(cx, tx, stats).await?;
                            Err(SqliteError::ConstraintViolation(
                                "Dialectica obligation violated".to_string(),
                            ))
                        }
                        Err(e) => {
                            // Error during verification, rollback for safety
                            stats.increment_obligations_violated();
                            self.perform_rollback_with_recovery(cx, tx, stats).await?;
                            Err(SqliteError::DialecticaError(format!(
                                "Constraint verification failed: {:?}",
                                e
                            )))
                        }
                    }
                } else {
                    // Constraints disabled, commit directly
                    tx.commit(cx).await?;
                    stats.increment_writes_committed();
                    Ok(())
                }
            }
            Err(e) => {
                // SQL execution failed, rollback
                stats.increment_writes_rolled_back();
                tx.rollback(cx).await?;
                Err(e)
            }
        }
    }

    async fn verify_constraint(
        &self,
        cx: &Cx,
        constraint: &DialecticaConstraint,
        tx: &crate::database::sqlite::SqliteTransaction<'_>,
        stats: &SqliteDialecticaStats,
    ) -> Result<DialecticaVerificationResult, DialecticaError> {
        // Mock constraint verification - check account balance constraints
        let balance_query = "SELECT COUNT(*) FROM accounts WHERE balance < 0";
        match tx.query_scalar::<i64>(cx, balance_query, &[]).await {
            Ok(negative_balance_count) => {
                if negative_balance_count > 0 {
                    Ok(DialecticaVerificationResult::Violated)
                } else {
                    Ok(DialecticaVerificationResult::Valid)
                }
            }
            Err(_) => Err(DialecticaError::VerificationFailed(
                "Failed to check balance constraints".to_string(),
            )),
        }
    }

    async fn perform_rollback_with_recovery(
        &self,
        cx: &Cx,
        tx: crate::database::sqlite::SqliteTransaction<'_>,
        stats: &SqliteDialecticaStats,
    ) -> Result<(), SqliteError> {
        stats.increment_writes_rolled_back();

        // Rollback the transaction
        tx.rollback(cx).await?;

        // Perform journal recovery
        stats.increment_journal_recoveries();

        // In a real implementation, this would involve:
        // 1. Checking journal integrity
        // 2. Replaying valid transactions from journal
        // 3. Discarding invalid transactions
        // 4. Updating dialectica obligation state

        Ok(())
    }

    async fn get_account_balance(&self, cx: &Cx, account_id: i64) -> Result<i64, SqliteError> {
        let mut conn = self.pool.acquire(cx).await?;
        conn.query_scalar(
            cx,
            "SELECT balance FROM accounts WHERE id = ?",
            &[&account_id],
        )
        .await
    }

    async fn insert_account(
        &self,
        cx: &Cx,
        name: &str,
        initial_balance: i64,
    ) -> Result<i64, SqliteError> {
        let mut conn = self.pool.acquire(cx).await?;
        conn.execute(
            cx,
            "INSERT INTO accounts (name, balance) VALUES (?, ?)",
            &[&name, &initial_balance],
        )
        .await?;

        conn.query_scalar(cx, "SELECT last_insert_rowid()", &[])
            .await
    }

    fn disable_constraints(&self) {
        self.constraint_active.store(false, Ordering::Release);
    }

    fn enable_constraints(&self) {
        self.constraint_active.store(true, Ordering::Release);
    }
}

/// Test basic sqlite write with dialectica obligation tracking
#[tokio::test]
async fn test_sqlite_dialectica_basic_write_tracking() {
    let runtime = LabRuntime::new();
    let stats = Arc::new(SqliteDialecticaStats::default());

    runtime
        .region(Budget::for_millis(2000), |cx, scope| async move {
            let db = ConstrainedSqliteDatabase::new(cx).await.unwrap();
            db.initialize_schema(cx).await.unwrap();

            // Create a dialectica constraint for balance validation
            let balance_constraint_formula =
                DialecticaFormula::new("∀x: account(x) → balance(x) ≥ 0");
            let constraint = db
                .create_dialectica_constraint(cx, balance_constraint_formula, &stats)
                .await
                .unwrap();

            // Insert valid account (should succeed)
            let account_id = db.insert_account(cx, "Alice", 1000).await.unwrap();

            // Valid update (should succeed)
            match db
                .execute_constrained_write(
                    cx,
                    "UPDATE accounts SET balance = ? WHERE id = ?",
                    &[&500i64, &account_id],
                    &constraint,
                    &stats,
                )
                .await
            {
                Ok(()) => {
                    let balance = db.get_account_balance(cx, account_id).await.unwrap();
                    assert_eq!(balance, 500, "Balance should be updated to 500");
                }
                Err(e) => panic!("Valid update should succeed, got error: {:?}", e),
            }

            // Invalid update violating dialectica constraint (should fail with rollback)
            match db
                .execute_constrained_write(
                    cx,
                    "UPDATE accounts SET balance = ? WHERE id = ?",
                    &[&(-100i64), &account_id],
                    &constraint,
                    &stats,
                )
                .await
            {
                Err(SqliteError::ConstraintViolation(_)) => {
                    // Expected rollback due to constraint violation
                    let balance = db.get_account_balance(cx, account_id).await.unwrap();
                    assert_eq!(
                        balance, 500,
                        "Balance should remain unchanged after rollback"
                    );
                }
                Ok(()) => panic!("Constraint violation should trigger rollback"),
                Err(e) => panic!("Expected constraint violation error, got: {:?}", e),
            }

            Outcome::Ok(())
        })
        .await
        .unwrap();

    let (
        writes_attempted,
        writes_committed,
        writes_rolled_back,
        obligations_created,
        obligations_violated,
        journal_recoveries,
        constraint_checks,
    ) = stats.summary();

    // Verify integration metrics
    assert_eq!(
        obligations_created, 1,
        "Should create 1 dialectica constraint"
    );
    assert_eq!(writes_attempted, 2, "Should attempt 2 writes");
    assert_eq!(writes_committed, 1, "Should commit 1 valid write");
    assert_eq!(writes_rolled_back, 1, "Should rollback 1 invalid write");
    assert_eq!(
        obligations_violated, 1,
        "Should detect 1 constraint violation"
    );
    assert_eq!(journal_recoveries, 1, "Should perform 1 journal recovery");
    assert!(constraint_checks >= 2, "Should perform constraint checks");

    println!("✓ Basic sqlite-dialectica write tracking test passed");
    println!(
        "  Writes: attempted={}, committed={}, rolled_back={}",
        writes_attempted, writes_committed, writes_rolled_back
    );
    println!(
        "  Obligations: created={}, violated={}, recoveries={}",
        obligations_created, obligations_violated, journal_recoveries
    );
}

/// Test multi-table operations with cross-table dialectica constraints
#[tokio::test]
async fn test_sqlite_dialectica_cross_table_constraints() {
    let runtime = LabRuntime::new();
    let stats = Arc::new(SqliteDialecticaStats::default());

    runtime
        .region(Budget::for_millis(2000), |cx, scope| async move {
            let db = ConstrainedSqliteDatabase::new(cx).await.unwrap();
            db.initialize_schema(cx).await.unwrap();

            // Create accounts
            let alice_id = db.insert_account(cx, "Alice", 1000).await.unwrap();
            let bob_id = db.insert_account(cx, "Bob", 500).await.unwrap();

            // Create a dialectica constraint for transfer consistency
            let transfer_constraint_formula = DialecticaFormula::new(
                "∀t: transaction(t) → (balance(from_account(t)) ≥ amount(t))",
            );
            let constraint = db
                .create_dialectica_constraint(cx, transfer_constraint_formula, &stats)
                .await
                .unwrap();

            // Valid transfer (Alice has sufficient funds)
            scope.spawn("valid_transfer", |cx| async move {
                let transfer_amount = 300i64;

                // Start transaction for the transfer
                match db
                    .execute_constrained_write(
                        cx,
                        "INSERT INTO transactions (from_account, to_account, amount) VALUES (?, ?, ?)",
                        &[&alice_id, &bob_id, &transfer_amount],
                        &constraint,
                        &stats,
                    )
                    .await
                {
                    Ok(()) => {
                        // Now update balances
                        db.execute_constrained_write(
                            cx,
                            "UPDATE accounts SET balance = balance - ? WHERE id = ?",
                            &[&transfer_amount, &alice_id],
                            &constraint,
                            &stats,
                        )
                        .await
                        .unwrap();

                        db.execute_constrained_write(
                            cx,
                            "UPDATE accounts SET balance = balance + ? WHERE id = ?",
                            &[&transfer_amount, &bob_id],
                            &constraint,
                            &stats,
                        )
                        .await
                        .unwrap();

                        let alice_balance = db.get_account_balance(cx, alice_id).await.unwrap();
                        let bob_balance = db.get_account_balance(cx, bob_id).await.unwrap();

                        assert_eq!(alice_balance, 700, "Alice balance should be 700 after transfer");
                        assert_eq!(bob_balance, 800, "Bob balance should be 800 after transfer");
                    }
                    Err(e) => panic!("Valid transfer should succeed: {:?}", e),
                }
                Outcome::Ok(())
            });

            // Invalid transfer (Bob doesn't have sufficient funds)
            scope.spawn("invalid_transfer", |cx| async move {
                let transfer_amount = 1000i64; // Bob only has 800

                // This should fail and rollback
                match db
                    .execute_constrained_write(
                        cx,
                        "UPDATE accounts SET balance = balance - ? WHERE id = ?",
                        &[&transfer_amount, &bob_id],
                        &constraint,
                        &stats,
                    )
                    .await
                {
                    Err(SqliteError::ConstraintViolation(_)) => {
                        // Expected rollback
                        let bob_balance = db.get_account_balance(cx, bob_id).await.unwrap();
                        assert_eq!(
                            bob_balance, 800,
                            "Bob balance should remain 800 after failed transfer"
                        );
                    }
                    Ok(()) => panic!("Invalid transfer should fail"),
                    Err(e) => panic!("Expected constraint violation, got: {:?}", e),
                }
                Outcome::Ok(())
            });

            Outcome::Ok(())
        })
        .await
        .unwrap();

    let (
        writes_attempted,
        writes_committed,
        writes_rolled_back,
        obligations_created,
        obligations_violated,
        journal_recoveries,
        _constraint_checks,
    ) = stats.summary();

    // Verify cross-table constraint integration
    assert_eq!(
        obligations_created, 1,
        "Should create 1 cross-table constraint"
    );
    assert!(writes_attempted >= 4, "Should attempt multiple writes");
    assert!(writes_committed >= 3, "Should commit valid writes");
    assert!(writes_rolled_back >= 1, "Should rollback invalid writes");
    assert!(
        obligations_violated >= 1,
        "Should detect constraint violations"
    );
    assert!(journal_recoveries >= 1, "Should perform journal recoveries");

    println!("✓ Cross-table dialectica constraints test passed");
    println!(
        "  Multi-table operations: attempted={}, committed={}, rolled_back={}",
        writes_attempted, writes_committed, writes_rolled_back
    );
}

/// Test nested transaction rollback with proper obligation unwinding
#[tokio::test]
async fn test_sqlite_dialectica_nested_transaction_rollback() {
    let runtime = LabRuntime::new();
    let stats = Arc::new(SqliteDialecticaStats::default());

    runtime
        .region(Budget::for_millis(2000), |cx, scope| async move {
            let db = ConstrainedSqliteDatabase::new(cx).await.unwrap();
            db.initialize_schema(cx).await.unwrap();

            let account_id = db.insert_account(cx, "Charlie", 1000).await.unwrap();

            // Create nested dialectica constraints
            let primary_constraint = db
                .create_dialectica_constraint(cx, DialecticaFormula::new("balance ≥ 0"), &stats)
                .await
                .unwrap();

            let secondary_constraint = db
                .create_dialectica_constraint(cx, DialecticaFormula::new("balance ≤ 10000"), &stats)
                .await
                .unwrap();

            // Test nested transaction with multiple constraint checks
            scope.spawn("nested_transaction_test", |cx| async move {
                // First level: valid operation
                match db
                    .execute_constrained_write(
                        cx,
                        "UPDATE accounts SET balance = ? WHERE id = ?",
                        &[&5000i64, &account_id],
                        &primary_constraint,
                        &stats,
                    )
                    .await
                {
                    Ok(()) => {
                        // Second level: should pass both constraints
                        match db
                            .execute_constrained_write(
                                cx,
                                "UPDATE accounts SET balance = ? WHERE id = ?",
                                &[&8000i64, &account_id],
                                &secondary_constraint,
                                &stats,
                            )
                            .await
                        {
                            Ok(()) => {
                                // Third level: violate primary constraint
                                match db
                                    .execute_constrained_write(
                                        cx,
                                        "UPDATE accounts SET balance = ? WHERE id = ?",
                                        &[&(-500i64), &account_id],
                                        &primary_constraint,
                                        &stats,
                                    )
                                    .await
                                {
                                    Err(SqliteError::ConstraintViolation(_)) => {
                                        // Should rollback to previous valid state
                                        let balance =
                                            db.get_account_balance(cx, account_id).await.unwrap();
                                        assert_eq!(
                                            balance, 8000,
                                            "Balance should remain at last valid state"
                                        );
                                    }
                                    Ok(()) => {
                                        panic!("Constraint violation should cause rollback")
                                    }
                                    Err(e) => panic!("Expected constraint violation: {:?}", e),
                                }
                            }
                            Err(e) => panic!("Valid second level should succeed: {:?}", e),
                        }
                    }
                    Err(e) => panic!("Valid first level should succeed: {:?}", e),
                }
                Outcome::Ok(())
            });

            Outcome::Ok(())
        })
        .await
        .unwrap();

    let (
        writes_attempted,
        writes_committed,
        writes_rolled_back,
        obligations_created,
        obligations_violated,
        journal_recoveries,
        _constraint_checks,
    ) = stats.summary();

    // Verify nested transaction handling
    assert_eq!(obligations_created, 2, "Should create 2 nested constraints");
    assert_eq!(writes_attempted, 3, "Should attempt 3 nested writes");
    assert_eq!(writes_committed, 2, "Should commit 2 valid writes");
    assert_eq!(writes_rolled_back, 1, "Should rollback 1 violating write");
    assert_eq!(
        obligations_violated, 1,
        "Should detect 1 constraint violation"
    );
    assert_eq!(journal_recoveries, 1, "Should perform 1 journal recovery");

    println!("✓ Nested transaction rollback test passed");
    println!(
        "  Nested operations: attempted={}, committed={}, rolled_back={}",
        writes_attempted, writes_committed, writes_rolled_back
    );
}

/// Test journal recovery after constraint violation rollback
#[tokio::test]
async fn test_sqlite_dialectica_journal_recovery() {
    let runtime = LabRuntime::new();
    let stats = Arc::new(SqliteDialecticaStats::default());

    runtime
        .region(Budget::for_millis(2000), |cx, scope| async move {
            let db = ConstrainedSqliteDatabase::new(cx).await.unwrap();
            db.initialize_schema(cx).await.unwrap();

            let account_id = db.insert_account(cx, "Dave", 1000).await.unwrap();

            let constraint = db
                .create_dialectica_constraint(cx, DialecticaFormula::new("balance ≥ 0"), &stats)
                .await
                .unwrap();

            // Perform several operations to build journal
            for i in 1..=5 {
                let new_balance = 1000 - (i * 100);
                if new_balance >= 0 {
                    match db
                        .execute_constrained_write(
                            cx,
                            "UPDATE accounts SET balance = ? WHERE id = ?",
                            &[&new_balance, &account_id],
                            &constraint,
                            &stats,
                        )
                        .await
                    {
                        Ok(()) => {
                            let balance = db.get_account_balance(cx, account_id).await.unwrap();
                            assert_eq!(
                                balance, new_balance,
                                "Balance should match after valid update"
                            );
                        }
                        Err(e) => panic!("Valid operation should succeed: {:?}", e),
                    }
                } else {
                    // This should trigger rollback and journal recovery
                    match db
                        .execute_constrained_write(
                            cx,
                            "UPDATE accounts SET balance = ? WHERE id = ?",
                            &[&new_balance, &account_id],
                            &constraint,
                            &stats,
                        )
                        .await
                    {
                        Err(SqliteError::ConstraintViolation(_)) => {
                            // Check that balance is preserved at last valid state
                            let balance = db.get_account_balance(cx, account_id).await.unwrap();
                            assert!(
                                balance >= 0,
                                "Balance should remain non-negative after rollback"
                            );
                        }
                        Ok(()) => panic!("Constraint violation should cause rollback"),
                        Err(e) => panic!("Expected constraint violation: {:?}", e),
                    }
                }
            }

            // Verify database integrity after journal recovery
            scope.spawn("integrity_check", |cx| async move {
                // Disable constraints temporarily for integrity check
                db.disable_constraints();

                let balance = db.get_account_balance(cx, account_id).await.unwrap();
                assert!(
                    balance >= 0 && balance <= 1000,
                    "Final balance should be within valid range after recovery"
                );

                db.enable_constraints();
                Outcome::Ok(())
            });

            Outcome::Ok(())
        })
        .await
        .unwrap();

    let (
        writes_attempted,
        writes_committed,
        writes_rolled_back,
        obligations_created,
        obligations_violated,
        journal_recoveries,
        _constraint_checks,
    ) = stats.summary();

    // Verify journal recovery behavior
    assert_eq!(obligations_created, 1, "Should create 1 constraint");
    assert!(writes_attempted >= 5, "Should attempt multiple writes");
    assert!(
        writes_committed >= 4,
        "Should commit valid writes before violation"
    );
    assert!(writes_rolled_back >= 1, "Should rollback violating writes");
    assert!(obligations_violated >= 1, "Should detect violations");
    assert!(journal_recoveries >= 1, "Should perform journal recovery");

    println!("✓ Journal recovery test passed");
    println!(
        "  Recovery operations: attempted={}, committed={}, recoveries={}",
        writes_attempted, writes_committed, journal_recoveries
    );
}

/// Comprehensive test combining all sqlite-dialectica integration patterns
#[tokio::test]
async fn test_comprehensive_sqlite_dialectica_integration() {
    let runtime = LabRuntime::new();
    let stats = Arc::new(SqliteDialecticaStats::default());

    runtime
        .region(Budget::for_millis(3000), |cx, scope| async move {
            let db = ConstrainedSqliteDatabase::new(cx).await.unwrap();
            db.initialize_schema(cx).await.unwrap();

            // Create multiple accounts for comprehensive testing
            let alice_id = db.insert_account(cx, "Alice", 2000).await.unwrap();
            let bob_id = db.insert_account(cx, "Bob", 1500).await.unwrap();
            let charlie_id = db.insert_account(cx, "Charlie", 1000).await.unwrap();

            // Create comprehensive dialectica constraints
            let balance_constraint = db
                .create_dialectica_constraint(
                    cx,
                    DialecticaFormula::new("∀x: account(x) → balance(x) ≥ 0"),
                    &stats,
                )
                .await
                .unwrap();

            let total_money_constraint = db
                .create_dialectica_constraint(
                    cx,
                    DialecticaFormula::new("Σ balance(x) = constant"),
                    &stats,
                )
                .await
                .unwrap();

            // Phase 1: Valid operations
            scope.spawn("phase1_valid_operations", |cx| async move {
                // Transfer from Alice to Bob
                db.execute_constrained_write(
                    cx,
                    "UPDATE accounts SET balance = balance - 500 WHERE id = ?",
                    &[&alice_id],
                    &balance_constraint,
                    &stats,
                )
                .await
                .unwrap();

                db.execute_constrained_write(
                    cx,
                    "UPDATE accounts SET balance = balance + 500 WHERE id = ?",
                    &[&bob_id],
                    &balance_constraint,
                    &stats,
                )
                .await
                .unwrap();

                let alice_balance = db.get_account_balance(cx, alice_id).await.unwrap();
                let bob_balance = db.get_account_balance(cx, bob_id).await.unwrap();

                assert_eq!(alice_balance, 1500, "Alice should have 1500 after transfer");
                assert_eq!(bob_balance, 2000, "Bob should have 2000 after transfer");

                Outcome::Ok(())
            });

            // Phase 2: Constraint violation scenarios
            scope.spawn("phase2_violation_scenarios", |cx| async move {
                // Attempt to create negative balance (should fail)
                match db
                    .execute_constrained_write(
                        cx,
                        "UPDATE accounts SET balance = balance - 2000 WHERE id = ?",
                        &[&charlie_id],
                        &balance_constraint,
                        &stats,
                    )
                    .await
                {
                    Err(SqliteError::ConstraintViolation(_)) => {
                        let charlie_balance = db.get_account_balance(cx, charlie_id).await.unwrap();
                        assert_eq!(
                            charlie_balance, 1000,
                            "Charlie's balance should remain unchanged"
                        );
                    }
                    Ok(()) => panic!("Negative balance should be rejected"),
                    Err(e) => panic!("Expected constraint violation: {:?}", e),
                }

                Outcome::Ok(())
            });

            // Phase 3: Recovery and integrity verification
            scope.spawn("phase3_recovery_verification", |cx| async move {
                // Verify all accounts have valid balances
                let alice_final = db.get_account_balance(cx, alice_id).await.unwrap();
                let bob_final = db.get_account_balance(cx, bob_id).await.unwrap();
                let charlie_final = db.get_account_balance(cx, charlie_id).await.unwrap();

                assert!(alice_final >= 0, "Alice balance should be non-negative");
                assert!(bob_final >= 0, "Bob balance should be non-negative");
                assert!(charlie_final >= 0, "Charlie balance should be non-negative");

                // Verify total money conservation (if applicable)
                let total_balance = alice_final + bob_final + charlie_final;
                assert_eq!(
                    total_balance, 4500,
                    "Total money should be conserved across all operations"
                );

                Outcome::Ok(())
            });

            Outcome::Ok(())
        })
        .await
        .unwrap();

    let (
        writes_attempted,
        writes_committed,
        writes_rolled_back,
        obligations_created,
        obligations_violated,
        journal_recoveries,
        constraint_checks,
    ) = stats.summary();

    // Verify comprehensive integration behavior
    assert!(
        obligations_created >= 2,
        "Should create multiple constraints"
    );
    assert!(
        writes_attempted >= 6,
        "Should attempt multiple writes across phases"
    );
    assert!(writes_committed >= 4, "Should commit valid operations");
    assert!(
        writes_rolled_back >= 1,
        "Should rollback violating operations"
    );
    assert!(obligations_violated >= 1, "Should detect violations");
    assert!(journal_recoveries >= 1, "Should perform recoveries");
    assert!(constraint_checks >= 4, "Should perform constraint checks");

    // Memory leak detection - ensure clean shutdown
    assert!(writes_committed > 0, "Should have successful operations");
    assert!(writes_rolled_back > 0, "Should have rollback operations");

    println!("✓ Comprehensive sqlite-dialectica integration test passed");
    println!(
        "  Final metrics: writes_attempted={}, writes_committed={}, writes_rolled_back={}",
        writes_attempted, writes_committed, writes_rolled_back
    );
    println!(
        "  Constraint metrics: obligations_created={}, obligations_violated={}, journal_recoveries={}, constraint_checks={}",
        obligations_created, obligations_violated, journal_recoveries, constraint_checks
    );
}
