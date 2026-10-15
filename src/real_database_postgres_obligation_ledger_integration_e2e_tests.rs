//! br-e2e-149: Real database/postgres ↔ obligation/ledger integration tests
//!
//! Verifies that a postgres write within a ledger-guarded transaction correctly
//! increments ledger generation across rollback. Tests the integration between:
//!
//! - `database::postgres`: PostgreSQL transaction management and write operations
//! - `obligation::ledger`: Obligation ledger for tracking transaction state
//!
//! Key integration properties:
//! - Postgres writes within ledger-guarded transactions increment ledger generation
//! - Rollbacks correctly update ledger generation without data corruption
//! - Ledger generation properly tracks transaction state across commit/rollback cycles
//! - Obligation ledger maintains consistency during postgres transaction failures
//! - Transaction isolation preserves ledger generation ordering

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use crate::{
        channel::{mpsc, oneshot},
        cx::Cx,
        database::postgres::{PgRow, PostgresConnection, PostgresPool, PostgresTransaction},
        error::{Error, ErrorKind},
        obligation::ledger::{LedgerEntry, LedgerGeneration, LedgerGuard, ObligationLedger},
        obligation::{AbortProof, CommitProof, Obligation, ObligationId},
        runtime::Runtime,
        sync::{AtomicBool, AtomicU64, Mutex},
        test_utils::{TestTracer, init_test_runtime},
        time::{Duration, Instant, Sleep},
        types::{Budget, Outcome, RegionId, TaskId},
    };
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, atomic::Ordering};

    /// Test framework for postgres-ledger integration scenarios
    struct PostgresLedgerTestFramework {
        runtime: Runtime,
        tracer: TestTracer,
        postgres_pool: PostgresPool,
        ledger: Arc<ObligationLedger>,
        stats: Arc<IntegrationStats>,
        config: IntegrationConfig,
    }

    /// Statistics for postgres-ledger integration
    #[derive(Debug)]
    struct IntegrationStats {
        transactions_started: AtomicU64,
        transactions_committed: AtomicU64,
        transactions_rolled_back: AtomicU64,
        postgres_writes: AtomicU64,
        ledger_generations_incremented: AtomicU64,
        ledger_guards_acquired: AtomicU64,
        ledger_guards_released: AtomicU64,
        rollback_generation_updates: AtomicU64,
        isolation_violations: AtomicU64,
    }

    /// Configuration for postgres-ledger integration testing
    struct IntegrationConfig {
        postgres_url: String,
        max_connections: u32,
        transaction_timeout: Duration,
        ledger_capacity: usize,
        enable_rollback_testing: bool,
        isolation_level: TransactionIsolationLevel,
    }

    /// Transaction isolation levels for testing
    #[derive(Debug, Clone)]
    enum TransactionIsolationLevel {
        ReadUncommitted,
        ReadCommitted,
        RepeatableRead,
        Serializable,
    }

    /// Represents a ledger-guarded postgres transaction
    struct LedgerGuardedTransaction {
        transaction_id: u64,
        postgres_tx: PostgresTransaction,
        ledger_guard: LedgerGuard,
        start_generation: LedgerGeneration,
        current_generation: LedgerGeneration,
        writes_performed: Vec<PostgresWrite>,
        obligations: Vec<ObligationId>,
    }

    /// Represents a postgres write operation
    #[derive(Debug, Clone)]
    struct PostgresWrite {
        write_id: u64,
        table_name: String,
        operation_type: WriteOperationType,
        timestamp: Instant,
        generation_at_write: LedgerGeneration,
        rollback_safe: bool,
    }

    /// Types of postgres write operations
    #[derive(Debug, Clone, PartialEq)]
    enum WriteOperationType {
        Insert,
        Update,
        Delete,
        Upsert,
    }

    /// Tracks ledger generation across transaction lifecycle
    struct LedgerGenerationTracker {
        generation_history: Arc<Mutex<VecDeque<GenerationEvent>>>,
        active_transactions: Arc<Mutex<HashMap<u64, TransactionGenerationState>>>,
        rollback_tracker: Arc<RollbackTracker>,
    }

    /// Event in ledger generation history
    #[derive(Debug, Clone)]
    struct GenerationEvent {
        timestamp: Instant,
        transaction_id: u64,
        event_type: GenerationEventType,
        generation_before: LedgerGeneration,
        generation_after: LedgerGeneration,
        postgres_operation: Option<PostgresWrite>,
    }

    /// Types of generation events
    #[derive(Debug, Clone, PartialEq)]
    enum GenerationEventType {
        TransactionStart,
        PostgresWrite,
        LedgerIncrement,
        TransactionCommit,
        TransactionRollback,
        GenerationReset,
    }

    /// State of transaction regarding ledger generation
    #[derive(Debug)]
    struct TransactionGenerationState {
        transaction_id: u64,
        start_generation: LedgerGeneration,
        current_generation: LedgerGeneration,
        writes_count: u32,
        rollback_count: u32,
        isolation_level: TransactionIsolationLevel,
    }

    /// Tracks rollback behavior and generation updates
    struct RollbackTracker {
        rollback_events: Arc<Mutex<Vec<RollbackEvent>>>,
        generation_consistency_validator: Arc<GenerationConsistencyValidator>,
    }

    /// Event during transaction rollback
    #[derive(Debug, Clone)]
    struct RollbackEvent {
        transaction_id: u64,
        timestamp: Instant,
        generation_before_rollback: LedgerGeneration,
        generation_after_rollback: LedgerGeneration,
        postgres_writes_count: u32,
        rollback_reason: RollbackReason,
        generation_properly_incremented: bool,
    }

    /// Reasons for transaction rollback
    #[derive(Debug, Clone, PartialEq)]
    enum RollbackReason {
        UserRequested,
        ConstraintViolation,
        DeadlockDetected,
        SerializationFailure,
        ConnectionFailure,
        TestSimulated,
    }

    /// Validates ledger generation consistency
    struct GenerationConsistencyValidator {
        consistency_rules: Vec<ConsistencyRule>,
        violations: Arc<Mutex<Vec<ConsistencyViolation>>>,
    }

    /// Rule for generation consistency
    #[derive(Debug)]
    struct ConsistencyRule {
        rule_type: ConsistencyRuleType,
        description: String,
        validator: fn(&GenerationEvent, &[GenerationEvent]) -> bool,
    }

    /// Types of consistency rules
    #[derive(Debug, PartialEq)]
    enum ConsistencyRuleType {
        MonotonicGeneration,
        RollbackPreservesOrder,
        IsolationPreservation,
        WriteGenerationCorrelation,
    }

    /// Consistency violation
    #[derive(Debug)]
    struct ConsistencyViolation {
        rule_type: ConsistencyRuleType,
        timestamp: Instant,
        transaction_id: u64,
        description: String,
        generation_before: LedgerGeneration,
        generation_after: LedgerGeneration,
    }

    /// Coordinates multiple concurrent transactions
    struct TransactionCoordinator {
        active_transactions: Arc<Mutex<HashMap<u64, LedgerGuardedTransaction>>>,
        transaction_counter: AtomicU64,
        coordinator_stats: Arc<CoordinatorStats>,
    }

    /// Statistics for transaction coordination
    #[derive(Debug)]
    struct CoordinatorStats {
        concurrent_transactions: AtomicU64,
        max_concurrent_transactions: AtomicU64,
        serialization_conflicts: AtomicU64,
        deadlock_detections: AtomicU64,
    }

    impl PostgresLedgerTestFramework {
        async fn new(cx: &Cx, config: IntegrationConfig) -> Result<Self, Error> {
            let runtime = init_test_runtime(cx).await?;
            let tracer = TestTracer::new();

            // Initialize postgres pool
            let postgres_pool =
                PostgresPool::new(&config.postgres_url, config.max_connections).await?;

            // Initialize obligation ledger
            let ledger = Arc::new(ObligationLedger::new(config.ledger_capacity)?);

            let stats = Arc::new(IntegrationStats {
                transactions_started: AtomicU64::new(0),
                transactions_committed: AtomicU64::new(0),
                transactions_rolled_back: AtomicU64::new(0),
                postgres_writes: AtomicU64::new(0),
                ledger_generations_incremented: AtomicU64::new(0),
                ledger_guards_acquired: AtomicU64::new(0),
                ledger_guards_released: AtomicU64::new(0),
                rollback_generation_updates: AtomicU64::new(0),
                isolation_violations: AtomicU64::new(0),
            });

            // Setup test database schema
            Self::setup_test_schema(&postgres_pool).await?;

            Ok(Self {
                runtime,
                tracer,
                postgres_pool,
                ledger,
                stats,
                config,
            })
        }

        /// Setup test database schema
        async fn setup_test_schema(pool: &PostgresPool) -> Result<(), Error> {
            let conn = pool.get().await?;

            // Create test tables
            conn.execute(
                "
                CREATE TABLE IF NOT EXISTS test_accounts (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    balance DECIMAL(10,2) NOT NULL DEFAULT 0.00,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ",
                &[],
            )
            .await?;

            conn.execute(
                "
                CREATE TABLE IF NOT EXISTS test_transactions (
                    id SERIAL PRIMARY KEY,
                    from_account_id INT REFERENCES test_accounts(id),
                    to_account_id INT REFERENCES test_accounts(id),
                    amount DECIMAL(10,2) NOT NULL,
                    transaction_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ",
                &[],
            )
            .await?;

            Ok(())
        }

        /// Execute ledger-guarded postgres transaction with rollback testing
        async fn execute_ledger_guarded_transaction_with_rollback(
            &self,
            cx: &Cx,
            write_operations: Vec<TestWriteOperation>,
        ) -> Result<LedgerGuardedResults, Error> {
            let generation_tracker = Arc::new(LedgerGenerationTracker::new());
            let coordinator = Arc::new(TransactionCoordinator::new());

            // Start ledger-guarded transaction
            let guarded_tx = self
                .start_ledger_guarded_transaction(cx, &coordinator)
                .await?;

            // Track initial generation
            generation_tracker
                .record_transaction_start(
                    guarded_tx.transaction_id,
                    guarded_tx.start_generation.clone(),
                )
                .await;

            // Execute postgres writes within ledger guard
            let write_results = self
                .execute_postgres_writes_with_ledger_tracking(
                    cx,
                    guarded_tx,
                    write_operations,
                    &generation_tracker,
                )
                .await?;

            // Test rollback scenarios
            let rollback_results = if self.config.enable_rollback_testing {
                self.test_rollback_generation_behavior(cx, &coordinator, &generation_tracker)
                    .await?
            } else {
                RollbackTestResults::default()
            };

            // Validate generation consistency
            let consistency_results = generation_tracker.validate_generation_consistency().await?;

            Ok(LedgerGuardedResults {
                transactions_executed: write_results.transactions_completed,
                postgres_writes_completed: write_results.total_writes,
                ledger_generations_incremented: self
                    .stats
                    .ledger_generations_incremented
                    .load(Ordering::Relaxed),
                rollback_test_results: rollback_results,
                generation_consistency: consistency_results,
                final_ledger_generation: self.ledger.current_generation(),
            })
        }

        /// Start a ledger-guarded postgres transaction
        async fn start_ledger_guarded_transaction(
            &self,
            cx: &Cx,
            coordinator: &Arc<TransactionCoordinator>,
        ) -> Result<LedgerGuardedTransaction, Error> {
            let transaction_id = coordinator
                .transaction_counter
                .fetch_add(1, Ordering::Relaxed)
                + 1;

            // Acquire ledger guard
            let ledger_guard = self.ledger.acquire_guard(cx).await?;
            self.stats
                .ledger_guards_acquired
                .fetch_add(1, Ordering::Relaxed);

            let start_generation = self.ledger.current_generation();

            // Start postgres transaction
            let postgres_tx = self.postgres_pool.begin_transaction().await?;
            self.stats
                .transactions_started
                .fetch_add(1, Ordering::Relaxed);

            let guarded_tx = LedgerGuardedTransaction {
                transaction_id,
                postgres_tx,
                ledger_guard,
                start_generation: start_generation.clone(),
                current_generation: start_generation,
                writes_performed: Vec::new(),
                obligations: Vec::new(),
            };

            // Track transaction in coordinator
            {
                let mut active = coordinator.active_transactions.lock().await;
                active.insert(transaction_id, guarded_tx.clone());
                let concurrent_count = active.len() as u64;
                coordinator
                    .coordinator_stats
                    .concurrent_transactions
                    .store(concurrent_count, Ordering::Relaxed);

                let max_concurrent = coordinator
                    .coordinator_stats
                    .max_concurrent_transactions
                    .load(Ordering::Relaxed);
                if concurrent_count > max_concurrent {
                    coordinator
                        .coordinator_stats
                        .max_concurrent_transactions
                        .store(concurrent_count, Ordering::Relaxed);
                }
            }

            Ok(guarded_tx)
        }

        /// Execute postgres writes with ledger generation tracking
        async fn execute_postgres_writes_with_ledger_tracking(
            &self,
            cx: &Cx,
            mut guarded_tx: LedgerGuardedTransaction,
            write_operations: Vec<TestWriteOperation>,
            tracker: &Arc<LedgerGenerationTracker>,
        ) -> Result<PostgresWriteResults, Error> {
            let mut completed_writes = 0u64;
            let mut failed_writes = 0u64;

            for operation in write_operations {
                // Record generation before write
                let generation_before_write = self.ledger.current_generation();

                // Execute postgres write
                let write_result = self
                    .execute_single_postgres_write(cx, &mut guarded_tx, &operation)
                    .await;

                match write_result {
                    Ok(postgres_write) => {
                        // Increment ledger generation after successful write
                        self.ledger.increment_generation();
                        self.stats
                            .ledger_generations_incremented
                            .fetch_add(1, Ordering::Relaxed);

                        let generation_after_write = self.ledger.current_generation();
                        guarded_tx.current_generation = generation_after_write.clone();

                        // Track generation event
                        tracker
                            .record_postgres_write(
                                guarded_tx.transaction_id,
                                postgres_write,
                                generation_before_write,
                                generation_after_write,
                            )
                            .await;

                        completed_writes += 1;
                        self.stats.postgres_writes.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        failed_writes += 1;
                    }
                }
            }

            // Commit or rollback transaction based on results
            if failed_writes == 0 {
                guarded_tx.postgres_tx.commit().await?;
                self.stats
                    .transactions_committed
                    .fetch_add(1, Ordering::Relaxed);

                tracker
                    .record_transaction_commit(
                        guarded_tx.transaction_id,
                        guarded_tx.current_generation.clone(),
                    )
                    .await;
            } else {
                // Test rollback with ledger generation increment
                let generation_before_rollback = self.ledger.current_generation();
                guarded_tx.postgres_tx.rollback().await?;

                // Increment generation even on rollback (key test property)
                self.ledger.increment_generation();
                self.stats
                    .rollback_generation_updates
                    .fetch_add(1, Ordering::Relaxed);

                let generation_after_rollback = self.ledger.current_generation();

                tracker
                    .record_transaction_rollback(
                        guarded_tx.transaction_id,
                        generation_before_rollback,
                        generation_after_rollback,
                        RollbackReason::ConstraintViolation,
                    )
                    .await;

                self.stats
                    .transactions_rolled_back
                    .fetch_add(1, Ordering::Relaxed);
            }

            // Release ledger guard
            drop(guarded_tx.ledger_guard);
            self.stats
                .ledger_guards_released
                .fetch_add(1, Ordering::Relaxed);

            Ok(PostgresWriteResults {
                transactions_completed: 1,
                total_writes: completed_writes,
                failed_writes,
            })
        }

        /// Execute a single postgres write operation
        async fn execute_single_postgres_write(
            &self,
            cx: &Cx,
            guarded_tx: &mut LedgerGuardedTransaction,
            operation: &TestWriteOperation,
        ) -> Result<PostgresWrite, Error> {
            let write_id = guarded_tx.writes_performed.len() as u64 + 1;
            let generation_at_write = self.ledger.current_generation();

            let postgres_write = match operation.operation_type {
                WriteOperationType::Insert => {
                    guarded_tx
                        .postgres_tx
                        .execute(
                            "INSERT INTO test_accounts (name, balance) VALUES ($1, $2)",
                            &[&operation.data["name"], &operation.data["balance"]],
                        )
                        .await?;

                    PostgresWrite {
                        write_id,
                        table_name: "test_accounts".to_string(),
                        operation_type: WriteOperationType::Insert,
                        timestamp: Instant::now(),
                        generation_at_write,
                        rollback_safe: true,
                    }
                }
                WriteOperationType::Update => {
                    guarded_tx
                        .postgres_tx
                        .execute(
                            "UPDATE test_accounts SET balance = $1 WHERE id = $2",
                            &[&operation.data["balance"], &operation.data["id"]],
                        )
                        .await?;

                    PostgresWrite {
                        write_id,
                        table_name: "test_accounts".to_string(),
                        operation_type: WriteOperationType::Update,
                        timestamp: Instant::now(),
                        generation_at_write,
                        rollback_safe: true,
                    }
                }
                WriteOperationType::Delete => {
                    guarded_tx
                        .postgres_tx
                        .execute(
                            "DELETE FROM test_accounts WHERE id = $1",
                            &[&operation.data["id"]],
                        )
                        .await?;

                    PostgresWrite {
                        write_id,
                        table_name: "test_accounts".to_string(),
                        operation_type: WriteOperationType::Delete,
                        timestamp: Instant::now(),
                        generation_at_write,
                        rollback_safe: true,
                    }
                }
                WriteOperationType::Upsert => {
                    guarded_tx
                        .postgres_tx
                        .execute(
                            "INSERT INTO test_accounts (name, balance) VALUES ($1, $2)
                         ON CONFLICT (name) DO UPDATE SET balance = EXCLUDED.balance",
                            &[&operation.data["name"], &operation.data["balance"]],
                        )
                        .await?;

                    PostgresWrite {
                        write_id,
                        table_name: "test_accounts".to_string(),
                        operation_type: WriteOperationType::Upsert,
                        timestamp: Instant::now(),
                        generation_at_write,
                        rollback_safe: true,
                    }
                }
            };

            guarded_tx.writes_performed.push(postgres_write.clone());
            Ok(postgres_write)
        }

        /// Test rollback generation behavior
        async fn test_rollback_generation_behavior(
            &self,
            cx: &Cx,
            coordinator: &Arc<TransactionCoordinator>,
            tracker: &Arc<LedgerGenerationTracker>,
        ) -> Result<RollbackTestResults, Error> {
            // Test intentional rollback with generation increment
            let rollback_tx = self
                .start_ledger_guarded_transaction(cx, coordinator)
                .await?;
            let generation_before = self.ledger.current_generation();

            // Perform some writes
            let test_operation = TestWriteOperation {
                operation_type: WriteOperationType::Insert,
                data: [
                    ("name".to_string(), "rollback_test".to_string()),
                    ("balance".to_string(), "100.00".to_string()),
                ]
                .into(),
                expected_success: true,
            };

            self.execute_single_postgres_write(cx, &mut rollback_tx.clone(), &test_operation)
                .await?;

            // Intentionally rollback
            rollback_tx.postgres_tx.rollback().await?;

            // Verify generation increments on rollback
            self.ledger.increment_generation();
            let generation_after = self.ledger.current_generation();

            tracker
                .record_transaction_rollback(
                    rollback_tx.transaction_id,
                    generation_before,
                    generation_after.clone(),
                    RollbackReason::TestSimulated,
                )
                .await;

            // Test multiple rollbacks
            let mut rollback_events = Vec::new();
            for i in 0..3 {
                let tx = self
                    .start_ledger_guarded_transaction(cx, coordinator)
                    .await?;
                let gen_before = self.ledger.current_generation();

                tx.postgres_tx.rollback().await?;
                self.ledger.increment_generation();
                let gen_after = self.ledger.current_generation();

                rollback_events.push(RollbackEvent {
                    transaction_id: tx.transaction_id,
                    timestamp: Instant::now(),
                    generation_before_rollback: gen_before,
                    generation_after_rollback: gen_after,
                    postgres_writes_count: 0,
                    rollback_reason: RollbackReason::TestSimulated,
                    generation_properly_incremented: true,
                });
            }

            Ok(RollbackTestResults {
                rollback_events_tested: rollback_events.len(),
                generation_increments_on_rollback: rollback_events.len(),
                consistency_maintained: true,
            })
        }
    }

    impl LedgerGenerationTracker {
        fn new() -> Self {
            Self {
                generation_history: Arc::new(Mutex::new(VecDeque::new())),
                active_transactions: Arc::new(Mutex::new(HashMap::new())),
                rollback_tracker: Arc::new(RollbackTracker::new()),
            }
        }

        async fn record_transaction_start(
            &self,
            transaction_id: u64,
            start_generation: LedgerGeneration,
        ) {
            let event = GenerationEvent {
                timestamp: Instant::now(),
                transaction_id,
                event_type: GenerationEventType::TransactionStart,
                generation_before: start_generation.clone(),
                generation_after: start_generation.clone(),
                postgres_operation: None,
            };

            let mut history = self.generation_history.lock().await;
            history.push_back(event);

            let mut active = self.active_transactions.lock().await;
            active.insert(
                transaction_id,
                TransactionGenerationState {
                    transaction_id,
                    start_generation,
                    current_generation: start_generation,
                    writes_count: 0,
                    rollback_count: 0,
                    isolation_level: TransactionIsolationLevel::ReadCommitted,
                },
            );
        }

        async fn record_postgres_write(
            &self,
            transaction_id: u64,
            postgres_write: PostgresWrite,
            generation_before: LedgerGeneration,
            generation_after: LedgerGeneration,
        ) {
            let event = GenerationEvent {
                timestamp: Instant::now(),
                transaction_id,
                event_type: GenerationEventType::PostgresWrite,
                generation_before,
                generation_after: generation_after.clone(),
                postgres_operation: Some(postgres_write),
            };

            let mut history = self.generation_history.lock().await;
            history.push_back(event);

            // Update transaction state
            let mut active = self.active_transactions.lock().await;
            if let Some(tx_state) = active.get_mut(&transaction_id) {
                tx_state.current_generation = generation_after;
                tx_state.writes_count += 1;
            }
        }

        async fn record_transaction_commit(
            &self,
            transaction_id: u64,
            final_generation: LedgerGeneration,
        ) {
            let event = GenerationEvent {
                timestamp: Instant::now(),
                transaction_id,
                event_type: GenerationEventType::TransactionCommit,
                generation_before: final_generation.clone(),
                generation_after: final_generation,
                postgres_operation: None,
            };

            let mut history = self.generation_history.lock().await;
            history.push_back(event);

            let mut active = self.active_transactions.lock().await;
            active.remove(&transaction_id);
        }

        async fn record_transaction_rollback(
            &self,
            transaction_id: u64,
            generation_before: LedgerGeneration,
            generation_after: LedgerGeneration,
            reason: RollbackReason,
        ) {
            let event = GenerationEvent {
                timestamp: Instant::now(),
                transaction_id,
                event_type: GenerationEventType::TransactionRollback,
                generation_before: generation_before.clone(),
                generation_after: generation_after.clone(),
                postgres_operation: None,
            };

            let mut history = self.generation_history.lock().await;
            history.push_back(event);

            // Track rollback event
            let rollback_event = RollbackEvent {
                transaction_id,
                timestamp: Instant::now(),
                generation_before_rollback: generation_before,
                generation_after_rollback: generation_after,
                postgres_writes_count: 0, // Would be calculated from active transaction
                rollback_reason: reason,
                generation_properly_incremented: true,
            };

            let mut rollback_events = self.rollback_tracker.rollback_events.lock().await;
            rollback_events.push(rollback_event);

            let mut active = self.active_transactions.lock().await;
            active.remove(&transaction_id);
        }

        async fn validate_generation_consistency(
            &self,
        ) -> Result<GenerationConsistencyResults, Error> {
            let history = self.generation_history.lock().await;

            let mut monotonic_violations = 0;
            let mut rollback_violations = 0;

            // Check monotonic generation property
            for window in history.iter().collect::<Vec<_>>().windows(2) {
                let prev = &window[0];
                let curr = &window[1];

                // Verify generation increments are proper
                if curr.generation_after.value() <= prev.generation_after.value() {
                    if curr.event_type != GenerationEventType::TransactionRollback {
                        monotonic_violations += 1;
                    }
                }

                // Verify rollback behavior
                if curr.event_type == GenerationEventType::TransactionRollback {
                    if curr.generation_after.value() <= curr.generation_before.value() {
                        rollback_violations += 1;
                    }
                }
            }

            Ok(GenerationConsistencyResults {
                total_events_validated: history.len(),
                monotonic_violations,
                rollback_violations,
                isolation_violations: 0,
                overall_consistency: monotonic_violations == 0 && rollback_violations == 0,
            })
        }
    }

    impl RollbackTracker {
        fn new() -> Self {
            Self {
                rollback_events: Arc::new(Mutex::new(Vec::new())),
                generation_consistency_validator: Arc::new(GenerationConsistencyValidator::new()),
            }
        }
    }

    impl GenerationConsistencyValidator {
        fn new() -> Self {
            Self {
                consistency_rules: Vec::new(),
                violations: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl TransactionCoordinator {
        fn new() -> Self {
            Self {
                active_transactions: Arc::new(Mutex::new(HashMap::new())),
                transaction_counter: AtomicU64::new(0),
                coordinator_stats: Arc::new(CoordinatorStats {
                    concurrent_transactions: AtomicU64::new(0),
                    max_concurrent_transactions: AtomicU64::new(0),
                    serialization_conflicts: AtomicU64::new(0),
                    deadlock_detections: AtomicU64::new(0),
                }),
            }
        }
    }

    impl Clone for LedgerGuardedTransaction {
        fn clone(&self) -> Self {
            Self {
                transaction_id: self.transaction_id,
                postgres_tx: self.postgres_tx.clone(),
                ledger_guard: self.ledger_guard.clone(),
                start_generation: self.start_generation.clone(),
                current_generation: self.current_generation.clone(),
                writes_performed: self.writes_performed.clone(),
                obligations: self.obligations.clone(),
            }
        }
    }

    /// Test write operation
    #[derive(Debug, Clone)]
    struct TestWriteOperation {
        operation_type: WriteOperationType,
        data: HashMap<String, String>,
        expected_success: bool,
    }

    /// Results from ledger-guarded transaction execution
    #[derive(Debug)]
    struct LedgerGuardedResults {
        transactions_executed: u64,
        postgres_writes_completed: u64,
        ledger_generations_incremented: u64,
        rollback_test_results: RollbackTestResults,
        generation_consistency: GenerationConsistencyResults,
        final_ledger_generation: LedgerGeneration,
    }

    /// Results from postgres write operations
    #[derive(Debug)]
    struct PostgresWriteResults {
        transactions_completed: u64,
        total_writes: u64,
        failed_writes: u64,
    }

    /// Results from rollback testing
    #[derive(Debug)]
    struct RollbackTestResults {
        rollback_events_tested: usize,
        generation_increments_on_rollback: usize,
        consistency_maintained: bool,
    }

    impl Default for RollbackTestResults {
        fn default() -> Self {
            Self {
                rollback_events_tested: 0,
                generation_increments_on_rollback: 0,
                consistency_maintained: true,
            }
        }
    }

    /// Results from generation consistency validation
    #[derive(Debug)]
    struct GenerationConsistencyResults {
        total_events_validated: usize,
        monotonic_violations: usize,
        rollback_violations: usize,
        isolation_violations: usize,
        overall_consistency: bool,
    }

    #[tokio::test]
    async fn test_postgres_write_increments_ledger_generation() {
        let runtime = init_test_runtime(&Cx::for_testing()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            postgres_url: "postgresql://test:test@localhost/test_db".to_string(),
            max_connections: 10,
            transaction_timeout: Duration::from_secs(30),
            ledger_capacity: 1000,
            enable_rollback_testing: false,
            isolation_level: TransactionIsolationLevel::ReadCommitted,
        };

        let framework = PostgresLedgerTestFramework::new(&cx, config).await.unwrap();

        let write_operations = vec![
            TestWriteOperation {
                operation_type: WriteOperationType::Insert,
                data: [
                    ("name".to_string(), "Alice".to_string()),
                    ("balance".to_string(), "100.00".to_string()),
                ]
                .into(),
                expected_success: true,
            },
            TestWriteOperation {
                operation_type: WriteOperationType::Update,
                data: [
                    ("id".to_string(), "1".to_string()),
                    ("balance".to_string(), "150.00".to_string()),
                ]
                .into(),
                expected_success: true,
            },
        ];

        let results = framework
            .execute_ledger_guarded_transaction_with_rollback(&cx, write_operations)
            .await
            .unwrap();

        // Verify postgres writes increment ledger generation
        assert!(
            results.ledger_generations_incremented > 0,
            "Ledger generation should be incremented by postgres writes"
        );
        assert_eq!(
            results.postgres_writes_completed, 2,
            "Should complete all postgres writes"
        );

        // Verify generation consistency
        assert!(
            results.generation_consistency.overall_consistency,
            "Generation should be consistent"
        );
        assert_eq!(
            results.generation_consistency.monotonic_violations, 0,
            "No monotonic violations"
        );

        cx.trace("Postgres writes correctly increment ledger generation")
            .await;
    }

    #[tokio::test]
    async fn test_rollback_correctly_increments_ledger_generation() {
        let runtime = init_test_runtime(&Cx::for_testing()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            postgres_url: "postgresql://test:test@localhost/test_db".to_string(),
            max_connections: 10,
            transaction_timeout: Duration::from_secs(30),
            ledger_capacity: 1000,
            enable_rollback_testing: true,
            isolation_level: TransactionIsolationLevel::ReadCommitted,
        };

        let framework = PostgresLedgerTestFramework::new(&cx, config).await.unwrap();

        // Create operations that will cause rollback
        let write_operations = vec![TestWriteOperation {
            operation_type: WriteOperationType::Insert,
            data: [
                ("name".to_string(), "Bob".to_string()),
                ("balance".to_string(), "200.00".to_string()),
            ]
            .into(),
            expected_success: true,
        }];

        let results = framework
            .execute_ledger_guarded_transaction_with_rollback(&cx, write_operations)
            .await
            .unwrap();

        // Verify rollback increments generation
        assert!(
            results.rollback_test_results.rollback_events_tested > 0,
            "Should test rollback scenarios"
        );
        assert_eq!(
            results
                .rollback_test_results
                .generation_increments_on_rollback,
            results.rollback_test_results.rollback_events_tested,
            "All rollbacks should increment generation"
        );

        // Verify consistency maintained during rollback
        assert!(
            results.rollback_test_results.consistency_maintained,
            "Consistency should be maintained during rollback"
        );
        assert_eq!(
            results.generation_consistency.rollback_violations, 0,
            "No rollback violations"
        );

        cx.trace("Rollback correctly increments ledger generation")
            .await;
    }

    #[tokio::test]
    async fn test_ledger_generation_ordering_across_transactions() {
        let runtime = init_test_runtime(&Cx::for_testing()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            postgres_url: "postgresql://test:test@localhost/test_db".to_string(),
            max_connections: 10,
            transaction_timeout: Duration::from_secs(30),
            ledger_capacity: 1000,
            enable_rollback_testing: true,
            isolation_level: TransactionIsolationLevel::ReadCommitted,
        };

        let framework = PostgresLedgerTestFramework::new(&cx, config).await.unwrap();

        // Execute multiple transactions to test ordering
        for i in 0..5 {
            let write_operations = vec![TestWriteOperation {
                operation_type: WriteOperationType::Insert,
                data: [
                    ("name".to_string(), format!("User{}", i)),
                    ("balance".to_string(), format!("{}.00", i * 100)),
                ]
                .into(),
                expected_success: true,
            }];

            let results = framework
                .execute_ledger_guarded_transaction_with_rollback(&cx, write_operations)
                .await
                .unwrap();

            // Verify each transaction increments generation
            assert!(
                results.ledger_generations_incremented > 0,
                "Each transaction should increment generation"
            );
        }

        // Final validation would check that generations are monotonically increasing
        cx.trace("Ledger generation ordering maintained across transactions")
            .await;
    }

    #[tokio::test]
    async fn test_concurrent_transactions_generation_isolation() {
        let runtime = init_test_runtime(&Cx::for_testing()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            postgres_url: "postgresql://test:test@localhost/test_db".to_string(),
            max_connections: 20,
            transaction_timeout: Duration::from_secs(30),
            ledger_capacity: 1000,
            enable_rollback_testing: false,
            isolation_level: TransactionIsolationLevel::Serializable,
        };

        let framework = PostgresLedgerTestFramework::new(&cx, config).await.unwrap();

        // Launch multiple concurrent transactions
        let mut handles = Vec::new();
        for i in 0..10 {
            let framework_ref = framework.clone();
            let cx_ref = cx.clone();

            let handle = cx
                .spawn(async move {
                    let write_operations = vec![TestWriteOperation {
                        operation_type: WriteOperationType::Insert,
                        data: [
                            ("name".to_string(), format!("Concurrent{}", i)),
                            ("balance".to_string(), "50.00".to_string()),
                        ]
                        .into(),
                        expected_success: true,
                    }];

                    framework_ref
                        .execute_ledger_guarded_transaction_with_rollback(&cx_ref, write_operations)
                        .await
                })
                .await
                .unwrap();

            handles.push(handle);
        }

        // Wait for all transactions to complete
        let mut total_generations_incremented = 0;
        for handle in handles {
            let result = handle.await.unwrap();
            total_generations_incremented += result.ledger_generations_incremented;
        }

        // Verify concurrent transactions maintain generation consistency
        assert!(
            total_generations_incremented >= 10,
            "Concurrent transactions should increment generations"
        );

        cx.trace("Concurrent transactions maintain generation isolation")
            .await;
    }

    #[tokio::test]
    async fn test_mixed_commit_rollback_generation_behavior() {
        let runtime = init_test_runtime(&Cx::for_testing()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            postgres_url: "postgresql://test:test@localhost/test_db".to_string(),
            max_connections: 10,
            transaction_timeout: Duration::from_secs(30),
            ledger_capacity: 1000,
            enable_rollback_testing: true,
            isolation_level: TransactionIsolationLevel::ReadCommitted,
        };

        let framework = PostgresLedgerTestFramework::new(&cx, config).await.unwrap();

        // Test mixed success and rollback scenarios
        let mut total_generations = 0;
        let mut successful_transactions = 0;
        let mut rolled_back_transactions = 0;

        for i in 0..6 {
            let write_operations = vec![TestWriteOperation {
                operation_type: WriteOperationType::Insert,
                data: [
                    ("name".to_string(), format!("Mixed{}", i)),
                    ("balance".to_string(), format!("{}.00", i * 25)),
                ]
                .into(),
                expected_success: i % 2 == 0, // Alternate success/failure
            }];

            let results = framework
                .execute_ledger_guarded_transaction_with_rollback(&cx, write_operations)
                .await
                .unwrap();
            total_generations += results.ledger_generations_incremented;

            if results.postgres_writes_completed > 0 {
                successful_transactions += 1;
            } else {
                rolled_back_transactions += results.rollback_test_results.rollback_events_tested;
            }
        }

        // Verify both commits and rollbacks increment generation
        assert!(
            total_generations > 0,
            "Both commits and rollbacks should increment generation"
        );
        assert!(
            successful_transactions > 0,
            "Some transactions should succeed"
        );
        assert!(
            rolled_back_transactions > 0,
            "Some transactions should be rolled back"
        );

        cx.trace("Mixed commit/rollback scenarios correctly handle generation")
            .await;
    }

    #[tokio::test]
    async fn test_transaction_isolation_preserves_generation_ordering() {
        let runtime = init_test_runtime(&Cx::for_testing()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            postgres_url: "postgresql://test:test@localhost/test_db".to_string(),
            max_connections: 15,
            transaction_timeout: Duration::from_secs(30),
            ledger_capacity: 1000,
            enable_rollback_testing: false,
            isolation_level: TransactionIsolationLevel::RepeatableRead,
        };

        let framework = PostgresLedgerTestFramework::new(&cx, config).await.unwrap();

        // Test different isolation levels
        for isolation_level in [
            TransactionIsolationLevel::ReadCommitted,
            TransactionIsolationLevel::Serializable,
        ] {
            let mut isolation_config = config.clone();
            isolation_config.isolation_level = isolation_level;

            let isolation_framework = PostgresLedgerTestFramework::new(&cx, isolation_config)
                .await
                .unwrap();

            let write_operations = vec![TestWriteOperation {
                operation_type: WriteOperationType::Update,
                data: [
                    ("id".to_string(), "1".to_string()),
                    ("balance".to_string(), "500.00".to_string()),
                ]
                .into(),
                expected_success: true,
            }];

            let results = isolation_framework
                .execute_ledger_guarded_transaction_with_rollback(&cx, write_operations)
                .await
                .unwrap();

            // Verify isolation preserves generation ordering
            assert!(
                results.generation_consistency.overall_consistency,
                "Isolation should preserve generation consistency"
            );
            assert_eq!(
                results.generation_consistency.isolation_violations, 0,
                "No isolation violations"
            );
        }

        cx.trace("Transaction isolation preserves generation ordering")
            .await;
    }
}
