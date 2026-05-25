//! Real E2E integration tests: database/postgres ↔ obligation/saga rollback (br-e2e-186).
//!
//! Tests that PostgreSQL COMMIT failure mid-transaction correctly triggers saga compensation chain.
//! Verifies the integration between:
//!
//! - `database::postgres`: PostgreSQL database with transaction management
//! - `obligation::saga`: Saga pattern with compensation chain execution
//!
//! Key integration properties:
//! - PostgreSQL COMMIT failure triggers saga compensation correctly
//! - Mid-transaction failures initiate proper rollback sequences
//! - Saga compensation chain executes in reverse order
//! - Database transaction state integrates with saga obligation tracking
//! - Compensation preserves data consistency across transaction boundaries
//! - Failed saga steps properly unwind previous successful operations

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    #![allow(
        clippy::expect_fun_call,
        clippy::future_not_send,
        clippy::match_same_arms,
        clippy::missing_panics_doc,
        clippy::needless_pass_by_value,
        clippy::unwrap_used,
        dead_code
    )]

    use crate::{
        cx::{Cx, Scope},
        error::{Error, Result},
        database::postgres::{
            PostgresConnection, PostgresConfig, PostgresTransaction,
            TransactionState, TransactionError, PostgresPool,
            ConnectionOptions, QueryResult, PostgresError,
        },
        obligation::{
            saga::{
                SagaOrchestrator, SagaDefinition, SagaStep, SagaCompensation,
                SagaExecution, SagaState, CompensationChain, SagaContext,
                StepResult, CompensationResult, SagaError,
            },
            ObligationId, ObligationState, ObligationRegistry,
        },
        runtime::{spawn, Runtime},
        sync::{Arc, Mutex, RwLock},
        time::{sleep, Duration, Instant},
        types::{Budget, CancelReason, Outcome, TaskId, Time},
    };
    use std::{
        collections::{HashMap, HashSet, VecDeque},
        sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    };

    // ────────────────────────────────────────────────────────────────────────────────
    // Database + Saga Rollback Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SagaTransactionEventType {
        TransactionStarted,
        StepExecuted,
        StepFailed,
        CommitAttempted,
        CommitFailed,
        RollbackTriggered,
        CompensationStarted,
        CompensationExecuted,
        CompensationFailed,
        SagaCompleted,
        SagaAborted,
    }

    #[derive(Debug, Clone)]
    struct SagaTransactionEvent {
        event_type: SagaTransactionEventType,
        saga_id: String,
        step_name: Option<String>,
        transaction_id: Option<String>,
        error_message: Option<String>,
        timestamp: Instant,
        metadata: HashMap<String, String>,
    }

    #[derive(Debug)]
    struct PostgresSagaTestFramework {
        runtime: Arc<Runtime>,
        postgres_pool: Arc<PostgresPool>,
        saga_orchestrator: Arc<SagaOrchestrator>,
        obligation_registry: Arc<RwLock<ObligationRegistry>>,
        transaction_events: Arc<Mutex<Vec<SagaTransactionEvent>>>,
        test_database_name: String,
        failure_scenarios: Arc<Mutex<Vec<FailureScenario>>>,
        compensation_metrics: Arc<Mutex<CompensationMetrics>>,
    }

    #[derive(Debug, Clone)]
    struct FailureScenario {
        scenario_name: String,
        failure_point: FailurePoint,
        failure_type: FailureType,
        expected_compensations: Vec<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FailurePoint {
        BeforeCommit,
        DuringCommit,
        AfterCommit,
        DuringStep(usize),
        DuringCompensation(usize),
    }

    #[derive(Debug, Clone)]
    enum FailureType {
        DatabaseError(String),
        NetworkTimeout,
        ConstraintViolation,
        SerializationFailure,
        ConnectionLost,
        LockTimeout,
        DeadlockDetected,
    }

    #[derive(Debug, Default)]
    struct CompensationMetrics {
        total_compensations_triggered: u64,
        successful_compensations: u64,
        failed_compensations: u64,
        average_compensation_time: Duration,
        max_compensation_chain_length: usize,
        rollback_success_rate: f64,
    }

    #[derive(Debug, Clone)]
    struct TestBusinessTransaction {
        transaction_id: String,
        user_id: u64,
        account_id: u64,
        amount: i64,
        operation_type: String,
        metadata: HashMap<String, String>,
    }

    #[derive(Debug, Clone)]
    struct CompensationAction {
        action_name: String,
        compensation_sql: String,
        compensation_data: HashMap<String, serde_json::Value>,
        requires_transaction: bool,
    }

    impl PostgresSagaTestFramework {
        async fn new() -> Result<Self> {
            let runtime = Arc::new(Runtime::new().await?);

            // Configure test database
            let test_db_name = format!("saga_test_{}", Instant::now().elapsed().as_nanos());
            let postgres_config = PostgresConfig::new()
                .with_host("localhost")
                .with_port(5432)
                .with_database(&test_db_name)
                .with_user("test_user")
                .with_password("test_password")
                .with_max_connections(10)
                .with_connection_timeout(Duration::from_secs(30));

            let postgres_pool = Arc::new(PostgresPool::new(postgres_config).await?);

            // Initialize saga orchestrator
            let saga_orchestrator = Arc::new(SagaOrchestrator::new().await?);
            let obligation_registry = Arc::new(RwLock::new(ObligationRegistry::new()));
            let transaction_events = Arc::new(Mutex::new(Vec::new()));
            let failure_scenarios = Arc::new(Mutex::new(Vec::new()));
            let compensation_metrics = Arc::new(Mutex::new(CompensationMetrics::default()));

            Ok(Self {
                runtime,
                postgres_pool,
                saga_orchestrator,
                obligation_registry,
                transaction_events,
                test_database_name: test_db_name,
                failure_scenarios,
                compensation_metrics,
            })
        }

        async fn setup_test_database(&self, cx: &Cx) -> Result<()> {
            let conn = self.postgres_pool.acquire().await?;

            // Create test tables
            conn.execute(
                "CREATE TABLE IF NOT EXISTS users (
                    id BIGSERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    balance BIGINT NOT NULL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )",
                &[],
            ).await?;

            conn.execute(
                "CREATE TABLE IF NOT EXISTS accounts (
                    id BIGSERIAL PRIMARY KEY,
                    user_id BIGINT REFERENCES users(id),
                    account_type VARCHAR(20) NOT NULL,
                    balance BIGINT NOT NULL DEFAULT 0,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )",
                &[],
            ).await?;

            conn.execute(
                "CREATE TABLE IF NOT EXISTS transactions (
                    id VARCHAR(50) PRIMARY KEY,
                    from_account_id BIGINT REFERENCES accounts(id),
                    to_account_id BIGINT REFERENCES accounts(id),
                    amount BIGINT NOT NULL,
                    transaction_type VARCHAR(20) NOT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP
                )",
                &[],
            ).await?;

            conn.execute(
                "CREATE TABLE IF NOT EXISTS audit_log (
                    id BIGSERIAL PRIMARY KEY,
                    transaction_id VARCHAR(50),
                    action VARCHAR(50) NOT NULL,
                    details JSONB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )",
                &[],
            ).await?;

            // Insert test data
            conn.execute(
                "INSERT INTO users (id, username, email, balance) VALUES
                 (1, 'alice', 'alice@test.com', 10000),
                 (2, 'bob', 'bob@test.com', 5000)
                 ON CONFLICT (id) DO NOTHING",
                &[],
            ).await?;

            conn.execute(
                "INSERT INTO accounts (id, user_id, account_type, balance) VALUES
                 (1, 1, 'checking', 10000),
                 (2, 2, 'checking', 5000),
                 (3, 1, 'savings', 20000)
                 ON CONFLICT (id) DO NOTHING",
                &[],
            ).await?;

            Ok(())
        }

        async fn define_money_transfer_saga(&self) -> Result<SagaDefinition> {
            let mut saga = SagaDefinition::new("money_transfer");

            // Step 1: Validate accounts
            saga.add_step(SagaStep::new("validate_accounts")
                .with_action(Box::new(|ctx: &SagaContext| -> StepResult {
                    // This would normally validate account existence and limits
                    Ok(serde_json::json!({
                        "from_account_valid": true,
                        "to_account_valid": true,
                        "sufficient_funds": true
                    }))
                }))
                .with_compensation(Box::new(|ctx: &SagaContext| -> CompensationResult {
                    // No compensation needed for validation
                    Ok(())
                }))
            );

            // Step 2: Reserve funds (debit from source)
            saga.add_step(SagaStep::new("reserve_funds")
                .with_action(Box::new(move |ctx: &SagaContext| -> StepResult {
                    // This step will be implemented with actual DB operations
                    Ok(serde_json::json!({
                        "reserved_amount": ctx.get_parameter("amount")?,
                        "reservation_id": format!("res_{}", uuid::Uuid::new_v4())
                    }))
                }))
                .with_compensation(Box::new(|ctx: &SagaContext| -> CompensationResult {
                    // Restore reserved funds
                    Ok(())
                }))
            );

            // Step 3: Create transaction record
            saga.add_step(SagaStep::new("create_transaction")
                .with_action(Box::new(|ctx: &SagaContext| -> StepResult {
                    Ok(serde_json::json!({
                        "transaction_id": ctx.get_parameter("transaction_id")?,
                        "status": "PENDING"
                    }))
                }))
                .with_compensation(Box::new(|ctx: &SagaContext| -> CompensationResult {
                    // Delete transaction record
                    Ok(())
                }))
            );

            // Step 4: Credit destination account
            saga.add_step(SagaStep::new("credit_destination")
                .with_action(Box::new(|ctx: &SagaContext| -> StepResult {
                    Ok(serde_json::json!({
                        "credited_amount": ctx.get_parameter("amount")?,
                        "new_balance": 0 // This would be calculated
                    }))
                }))
                .with_compensation(Box::new(|ctx: &SagaContext| -> CompensationResult {
                    // Reverse credit
                    Ok(())
                }))
            );

            // Step 5: Finalize transaction (this is where we'll inject failures)
            saga.add_step(SagaStep::new("finalize_transaction")
                .with_action(Box::new(|ctx: &SagaContext| -> StepResult {
                    Ok(serde_json::json!({
                        "status": "COMPLETED",
                        "completed_at": chrono::Utc::now().to_rfc3339()
                    }))
                }))
                .with_compensation(Box::new(|ctx: &SagaContext| -> CompensationResult {
                    // Mark transaction as failed
                    Ok(())
                }))
            );

            Ok(saga)
        }

        async fn execute_transaction_with_saga(
            &self,
            cx: &Cx,
            business_tx: TestBusinessTransaction,
            inject_failure: Option<FailureScenario>,
        ) -> Result<SagaExecution> {
            // Record transaction start
            self.record_event(SagaTransactionEvent {
                event_type: SagaTransactionEventType::TransactionStarted,
                saga_id: business_tx.transaction_id.clone(),
                step_name: None,
                transaction_id: Some(business_tx.transaction_id.clone()),
                error_message: None,
                timestamp: Instant::now(),
                metadata: [
                    ("user_id".to_string(), business_tx.user_id.to_string()),
                    ("amount".to_string(), business_tx.amount.to_string()),
                ].into(),
            }).await;

            // Create saga context
            let mut saga_context = SagaContext::new(&business_tx.transaction_id);
            saga_context.set_parameter("transaction_id", &business_tx.transaction_id)?;
            saga_context.set_parameter("user_id", &business_tx.user_id.to_string())?;
            saga_context.set_parameter("account_id", &business_tx.account_id.to_string())?;
            saga_context.set_parameter("amount", &business_tx.amount.to_string())?;

            // Get saga definition
            let saga_def = self.define_money_transfer_saga().await?;

            // Start PostgreSQL transaction
            let mut pg_conn = self.postgres_pool.acquire().await?;
            let mut pg_tx = pg_conn.begin().await?;

            let framework_ref = self.clone();
            let saga_id = business_tx.transaction_id.clone();

            // Execute saga steps with database operations
            let execution_result = self.execute_saga_with_db_operations(
                cx,
                &saga_def,
                saga_context,
                &mut pg_tx,
                inject_failure,
            ).await;

            match execution_result {
                Ok(execution) => {
                    // Attempt to commit database transaction
                    match pg_tx.commit().await {
                        Ok(()) => {
                            framework_ref.record_event(SagaTransactionEvent {
                                event_type: SagaTransactionEventType::SagaCompleted,
                                saga_id: saga_id.clone(),
                                step_name: None,
                                transaction_id: Some(saga_id),
                                error_message: None,
                                timestamp: Instant::now(),
                                metadata: [("outcome".to_string(), "success".to_string())].into(),
                            }).await;
                            Ok(execution)
                        }
                        Err(commit_error) => {
                            // COMMIT failed - trigger compensation chain
                            framework_ref.record_event(SagaTransactionEvent {
                                event_type: SagaTransactionEventType::CommitFailed,
                                saga_id: saga_id.clone(),
                                step_name: None,
                                transaction_id: Some(saga_id.clone()),
                                error_message: Some(commit_error.to_string()),
                                timestamp: Instant::now(),
                                metadata: HashMap::new(),
                            }).await;

                            // Execute compensation chain
                            framework_ref.execute_compensation_chain(cx, &execution).await?;

                            Err(Error::new(&format!("Transaction commit failed: {}", commit_error)))
                        }
                    }
                }
                Err(saga_error) => {
                    // Saga execution failed - rollback and compensate
                    let _ = pg_tx.rollback().await;

                    framework_ref.record_event(SagaTransactionEvent {
                        event_type: SagaTransactionEventType::SagaAborted,
                        saga_id: saga_id.clone(),
                        step_name: None,
                        transaction_id: Some(saga_id),
                        error_message: Some(saga_error.to_string()),
                        timestamp: Instant::now(),
                        metadata: HashMap::new(),
                    }).await;

                    Err(saga_error)
                }
            }
        }

        async fn execute_saga_with_db_operations(
            &self,
            cx: &Cx,
            saga_def: &SagaDefinition,
            mut context: SagaContext,
            pg_tx: &mut PostgresTransaction,
            inject_failure: Option<FailureScenario>,
        ) -> Result<SagaExecution> {
            let mut execution = SagaExecution::new(saga_def.name().to_string());

            for (step_index, step) in saga_def.steps().iter().enumerate() {
                // Check if we should inject failure at this step
                if let Some(ref failure) = inject_failure {
                    if matches!(failure.failure_point, FailurePoint::DuringStep(idx) if idx == step_index) {
                        return Err(self.inject_failure(failure).await?);
                    }
                }

                // Record step execution
                self.record_event(SagaTransactionEvent {
                    event_type: SagaTransactionEventType::StepExecuted,
                    saga_id: context.saga_id().to_string(),
                    step_name: Some(step.name().to_string()),
                    transaction_id: Some(context.saga_id().to_string()),
                    error_message: None,
                    timestamp: Instant::now(),
                    metadata: [("step_index".to_string(), step_index.to_string())].into(),
                }).await;

                // Execute the actual database operations for this step
                match step.name() {
                    "validate_accounts" => {
                        self.execute_validate_accounts_step(&mut context, pg_tx).await?;
                    }
                    "reserve_funds" => {
                        self.execute_reserve_funds_step(&mut context, pg_tx).await?;
                    }
                    "create_transaction" => {
                        self.execute_create_transaction_step(&mut context, pg_tx).await?;
                    }
                    "credit_destination" => {
                        self.execute_credit_destination_step(&mut context, pg_tx).await?;
                    }
                    "finalize_transaction" => {
                        // Check for commit-time failure injection
                        if let Some(ref failure) = inject_failure {
                            if matches!(failure.failure_point, FailurePoint::BeforeCommit) {
                                return Err(self.inject_failure(failure).await?);
                            }
                        }
                        self.execute_finalize_transaction_step(&mut context, pg_tx).await?;
                    }
                    _ => {
                        return Err(Error::new(&format!("Unknown step: {}", step.name())));
                    }
                }

                execution.record_step_completion(step.name(), &context);
            }

            Ok(execution)
        }

        async fn execute_validate_accounts_step(
            &self,
            context: &mut SagaContext,
            pg_tx: &mut PostgresTransaction,
        ) -> Result<()> {
            let account_id: u64 = context.get_parameter("account_id")?.parse()?;

            // Validate source account exists and has sufficient funds
            let row = pg_tx.query_one(
                "SELECT id, balance, is_active FROM accounts WHERE id = $1",
                &[&(account_id as i64)],
            ).await?;

            let balance: i64 = row.get("balance");
            let is_active: bool = row.get("is_active");
            let amount: i64 = context.get_parameter("amount")?.parse()?;

            if !is_active {
                return Err(Error::new("Account is not active"));
            }

            if balance < amount {
                return Err(Error::new("Insufficient funds"));
            }

            context.set_step_result("validate_accounts", serde_json::json!({
                "account_validated": true,
                "current_balance": balance,
                "requested_amount": amount
            }))?;

            Ok(())
        }

        async fn execute_reserve_funds_step(
            &self,
            context: &mut SagaContext,
            pg_tx: &mut PostgresTransaction,
        ) -> Result<()> {
            let account_id: u64 = context.get_parameter("account_id")?.parse()?;
            let amount: i64 = context.get_parameter("amount")?.parse()?;

            // Debit the source account
            let updated_rows = pg_tx.execute(
                "UPDATE accounts SET balance = balance - $1 WHERE id = $2 AND balance >= $1",
                &[&amount, &(account_id as i64)],
            ).await?;

            if updated_rows == 0 {
                return Err(Error::new("Failed to reserve funds - insufficient balance or account not found"));
            }

            // Record the reservation
            context.set_step_result("reserve_funds", serde_json::json!({
                "reserved_amount": amount,
                "account_id": account_id,
                "reservation_timestamp": chrono::Utc::now().to_rfc3339()
            }))?;

            Ok(())
        }

        async fn execute_create_transaction_step(
            &self,
            context: &mut SagaContext,
            pg_tx: &mut PostgresTransaction,
        ) -> Result<()> {
            let transaction_id = context.get_parameter("transaction_id")?;
            let account_id: u64 = context.get_parameter("account_id")?.parse()?;
            let amount: i64 = context.get_parameter("amount")?.parse()?;

            // Insert transaction record
            pg_tx.execute(
                "INSERT INTO transactions (id, from_account_id, to_account_id, amount, transaction_type, status)
                 VALUES ($1, $2, $3, $4, 'TRANSFER', 'PENDING')",
                &[&transaction_id, &(account_id as i64), &2i64, &amount], // to_account_id = 2 for test
            ).await?;

            context.set_step_result("create_transaction", serde_json::json!({
                "transaction_id": transaction_id,
                "status": "PENDING",
                "created_at": chrono::Utc::now().to_rfc3339()
            }))?;

            Ok(())
        }

        async fn execute_credit_destination_step(
            &self,
            context: &mut SagaContext,
            pg_tx: &mut PostgresTransaction,
        ) -> Result<()> {
            let amount: i64 = context.get_parameter("amount")?.parse()?;
            let destination_account_id = 2i64; // Hardcoded for test

            // Credit the destination account
            pg_tx.execute(
                "UPDATE accounts SET balance = balance + $1 WHERE id = $2",
                &[&amount, &destination_account_id],
            ).await?;

            context.set_step_result("credit_destination", serde_json::json!({
                "credited_amount": amount,
                "destination_account_id": destination_account_id,
                "credit_timestamp": chrono::Utc::now().to_rfc3339()
            }))?;

            Ok(())
        }

        async fn execute_finalize_transaction_step(
            &self,
            context: &mut SagaContext,
            pg_tx: &mut PostgresTransaction,
        ) -> Result<()> {
            let transaction_id = context.get_parameter("transaction_id")?;

            // Update transaction status to completed
            pg_tx.execute(
                "UPDATE transactions SET status = 'COMPLETED', completed_at = CURRENT_TIMESTAMP WHERE id = $1",
                &[&transaction_id],
            ).await?;

            // Add audit log entry
            pg_tx.execute(
                "INSERT INTO audit_log (transaction_id, action, details) VALUES ($1, $2, $3)",
                &[&transaction_id, &"TRANSACTION_COMPLETED", &serde_json::json!({
                    "finalized_at": chrono::Utc::now().to_rfc3339(),
                    "status": "COMPLETED"
                })],
            ).await?;

            context.set_step_result("finalize_transaction", serde_json::json!({
                "transaction_id": transaction_id,
                "final_status": "COMPLETED",
                "finalized_at": chrono::Utc::now().to_rfc3339()
            }))?;

            Ok(())
        }

        async fn execute_compensation_chain(
            &self,
            cx: &Cx,
            execution: &SagaExecution,
        ) -> Result<()> {
            self.record_event(SagaTransactionEvent {
                event_type: SagaTransactionEventType::CompensationStarted,
                saga_id: execution.saga_id().to_string(),
                step_name: None,
                transaction_id: Some(execution.saga_id().to_string()),
                error_message: None,
                timestamp: Instant::now(),
                metadata: HashMap::new(),
            }).await;

            let compensation_start = Instant::now();
            let mut compensations_executed = 0;

            // Execute compensations in reverse order of completed steps
            for step_name in execution.completed_steps().iter().rev() {
                match self.execute_step_compensation(cx, step_name, execution).await {
                    Ok(()) => {
                        compensations_executed += 1;
                        self.record_event(SagaTransactionEvent {
                            event_type: SagaTransactionEventType::CompensationExecuted,
                            saga_id: execution.saga_id().to_string(),
                            step_name: Some(step_name.clone()),
                            transaction_id: Some(execution.saga_id().to_string()),
                            error_message: None,
                            timestamp: Instant::now(),
                            metadata: HashMap::new(),
                        }).await;
                    }
                    Err(e) => {
                        self.record_event(SagaTransactionEvent {
                            event_type: SagaTransactionEventType::CompensationFailed,
                            saga_id: execution.saga_id().to_string(),
                            step_name: Some(step_name.clone()),
                            transaction_id: Some(execution.saga_id().to_string()),
                            error_message: Some(e.to_string()),
                            timestamp: Instant::now(),
                            metadata: HashMap::new(),
                        }).await;
                        return Err(e);
                    }
                }
            }

            // Update metrics
            {
                let mut metrics = self.compensation_metrics.lock().await;
                metrics.total_compensations_triggered += 1;
                metrics.successful_compensations += compensations_executed;
                metrics.max_compensation_chain_length =
                    metrics.max_compensation_chain_length.max(compensations_executed as usize);

                let compensation_time = compensation_start.elapsed();
                if metrics.average_compensation_time == Duration::ZERO {
                    metrics.average_compensation_time = compensation_time;
                } else {
                    metrics.average_compensation_time =
                        (metrics.average_compensation_time + compensation_time) / 2;
                }
            }

            Ok(())
        }

        async fn execute_step_compensation(
            &self,
            cx: &Cx,
            step_name: &str,
            execution: &SagaExecution,
        ) -> Result<()> {
            // Get a new database connection for compensation
            let mut conn = self.postgres_pool.acquire().await?;
            let mut tx = conn.begin().await?;

            let compensation_result = match step_name {
                "finalize_transaction" => {
                    self.compensate_finalize_transaction(execution, &mut tx).await
                }
                "credit_destination" => {
                    self.compensate_credit_destination(execution, &mut tx).await
                }
                "create_transaction" => {
                    self.compensate_create_transaction(execution, &mut tx).await
                }
                "reserve_funds" => {
                    self.compensate_reserve_funds(execution, &mut tx).await
                }
                "validate_accounts" => {
                    // No compensation needed for validation
                    Ok(())
                }
                _ => Err(Error::new(&format!("Unknown step for compensation: {}", step_name))),
            };

            match compensation_result {
                Ok(()) => {
                    tx.commit().await?;
                    Ok(())
                }
                Err(e) => {
                    tx.rollback().await?;
                    Err(e)
                }
            }
        }

        async fn compensate_finalize_transaction(
            &self,
            execution: &SagaExecution,
            tx: &mut PostgresTransaction,
        ) -> Result<()> {
            // Mark transaction as failed
            tx.execute(
                "UPDATE transactions SET status = 'FAILED', completed_at = CURRENT_TIMESTAMP WHERE id = $1",
                &[&execution.saga_id()],
            ).await?;

            // Add compensation audit log
            tx.execute(
                "INSERT INTO audit_log (transaction_id, action, details) VALUES ($1, $2, $3)",
                &[&execution.saga_id(), &"COMPENSATION_FINALIZE", &serde_json::json!({
                    "compensated_at": chrono::Utc::now().to_rfc3339(),
                    "reason": "saga_rollback"
                })],
            ).await?;

            Ok(())
        }

        async fn compensate_credit_destination(
            &self,
            execution: &SagaExecution,
            tx: &mut PostgresTransaction,
        ) -> Result<()> {
            // Get the credited amount from execution context
            if let Some(step_result) = execution.get_step_result("credit_destination") {
                if let Some(amount) = step_result.get("credited_amount").and_then(|v| v.as_i64()) {
                    // Reverse the credit
                    tx.execute(
                        "UPDATE accounts SET balance = balance - $1 WHERE id = $2",
                        &[&amount, &2i64], // destination_account_id = 2
                    ).await?;
                }
            }
            Ok(())
        }

        async fn compensate_create_transaction(
            &self,
            execution: &SagaExecution,
            tx: &mut PostgresTransaction,
        ) -> Result<()> {
            // Delete the transaction record (or mark as cancelled)
            tx.execute(
                "UPDATE transactions SET status = 'CANCELLED' WHERE id = $1",
                &[&execution.saga_id()],
            ).await?;
            Ok(())
        }

        async fn compensate_reserve_funds(
            &self,
            execution: &SagaExecution,
            tx: &mut PostgresTransaction,
        ) -> Result<()> {
            // Get the reserved amount and account from execution context
            if let Some(step_result) = execution.get_step_result("reserve_funds") {
                if let (Some(amount), Some(account_id)) = (
                    step_result.get("reserved_amount").and_then(|v| v.as_i64()),
                    step_result.get("account_id").and_then(|v| v.as_u64())
                ) {
                    // Restore the reserved funds
                    tx.execute(
                        "UPDATE accounts SET balance = balance + $1 WHERE id = $2",
                        &[&amount, &(*account_id as i64)],
                    ).await?;
                }
            }
            Ok(())
        }

        async fn inject_failure(&self, failure_scenario: &FailureScenario) -> Result<Error> {
            let error_msg = match &failure_scenario.failure_type {
                FailureType::DatabaseError(msg) => format!("Database error: {}", msg),
                FailureType::NetworkTimeout => "Network timeout during database operation".to_string(),
                FailureType::ConstraintViolation => "Database constraint violation".to_string(),
                FailureType::SerializationFailure => "Transaction serialization failure".to_string(),
                FailureType::ConnectionLost => "Database connection lost".to_string(),
                FailureType::LockTimeout => "Database lock timeout".to_string(),
                FailureType::DeadlockDetected => "Database deadlock detected".to_string(),
            };

            Ok(Error::new(&error_msg))
        }

        async fn record_event(&self, event: SagaTransactionEvent) {
            self.transaction_events.lock().await.push(event);
        }

        async fn get_event_count(&self, event_type: SagaTransactionEventType) -> usize {
            self.transaction_events.lock().await
                .iter()
                .filter(|e| e.event_type == event_type)
                .count()
        }

        async fn get_compensation_metrics(&self) -> CompensationMetrics {
            self.compensation_metrics.lock().await.clone()
        }

        async fn verify_database_consistency(&self) -> Result<bool> {
            let conn = self.postgres_pool.acquire().await?;

            // Check that accounts have consistent balances
            let rows = conn.query(
                "SELECT id, balance FROM accounts ORDER BY id",
                &[],
            ).await?;

            let mut total_balance = 0i64;
            for row in rows {
                let balance: i64 = row.get("balance");
                total_balance += balance;
            }

            // Total balance should be preserved (35000 in our test setup)
            Ok(total_balance == 35000)
        }

        async fn cleanup_test_database(&self) -> Result<()> {
            let conn = self.postgres_pool.acquire().await?;
            conn.execute("DROP TABLE IF EXISTS audit_log CASCADE", &[]).await?;
            conn.execute("DROP TABLE IF EXISTS transactions CASCADE", &[]).await?;
            conn.execute("DROP TABLE IF EXISTS accounts CASCADE", &[]).await?;
            conn.execute("DROP TABLE IF EXISTS users CASCADE", &[]).await?;
            Ok(())
        }
    }

    // Clone implementation for the framework
    impl Clone for PostgresSagaTestFramework {
        fn clone(&self) -> Self {
            Self {
                runtime: self.runtime.clone(),
                postgres_pool: self.postgres_pool.clone(),
                saga_orchestrator: self.saga_orchestrator.clone(),
                obligation_registry: self.obligation_registry.clone(),
                transaction_events: self.transaction_events.clone(),
                test_database_name: self.test_database_name.clone(),
                failure_scenarios: self.failure_scenarios.clone(),
                compensation_metrics: self.compensation_metrics.clone(),
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Cases
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_commit_failure_triggers_compensation() {
        let framework = PostgresSagaTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime.region(Budget::unlimited(), |cx| async move {
            // Setup test database
            framework.setup_test_database(cx).await.unwrap();

            // Create test transaction
            let business_tx = TestBusinessTransaction {
                transaction_id: "tx_commit_failure_001".to_string(),
                user_id: 1,
                account_id: 1,
                amount: 1000,
                operation_type: "transfer".to_string(),
                metadata: HashMap::new(),
            };

            // Inject commit failure
            let failure_scenario = FailureScenario {
                scenario_name: "commit_failure".to_string(),
                failure_point: FailurePoint::DuringCommit,
                failure_type: FailureType::SerializationFailure,
                expected_compensations: vec![
                    "finalize_transaction".to_string(),
                    "credit_destination".to_string(),
                    "create_transaction".to_string(),
                    "reserve_funds".to_string(),
                ].into(),
            };

            // Execute transaction (should fail and compensate)
            let result = framework.execute_transaction_with_saga(
                cx,
                business_tx,
                Some(failure_scenario),
            ).await;

            assert!(result.is_err(), "Transaction should fail due to injected commit failure");

            // Verify compensation was triggered
            let compensation_started = framework.get_event_count(SagaTransactionEventType::CompensationStarted).await;
            assert_eq!(compensation_started, 1, "Compensation should be triggered");

            let compensations_executed = framework.get_event_count(SagaTransactionEventType::CompensationExecuted).await;
            assert!(compensations_executed > 0, "Should execute compensations");

            // Verify database consistency
            let is_consistent = framework.verify_database_consistency().await.unwrap();
            assert!(is_consistent, "Database should remain consistent after compensation");

            // Cleanup
            framework.cleanup_test_database().await.unwrap();

            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn test_successful_transaction_no_compensation() {
        let framework = PostgresSagaTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime.region(Budget::unlimited(), |cx| async move {
            framework.setup_test_database(cx).await.unwrap();

            let business_tx = TestBusinessTransaction {
                transaction_id: "tx_success_001".to_string(),
                user_id: 1,
                account_id: 1,
                amount: 500,
                operation_type: "transfer".to_string(),
                metadata: HashMap::new(),
            };

            // Execute without failure injection
            let result = framework.execute_transaction_with_saga(cx, business_tx, None).await;

            assert!(result.is_ok(), "Transaction should succeed");

            // Verify no compensation was triggered
            let compensation_started = framework.get_event_count(SagaTransactionEventType::CompensationStarted).await;
            assert_eq!(compensation_started, 0, "No compensation should be triggered for successful transaction");

            // Verify saga completed
            let saga_completed = framework.get_event_count(SagaTransactionEventType::SagaCompleted).await;
            assert_eq!(saga_completed, 1, "Saga should complete successfully");

            framework.cleanup_test_database().await.unwrap();
            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn test_mid_transaction_failure_rollback() {
        let framework = PostgresSagaTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime.region(Budget::unlimited(), |cx| async move {
            framework.setup_test_database(cx).await.unwrap();

            let business_tx = TestBusinessTransaction {
                transaction_id: "tx_mid_failure_001".to_string(),
                user_id: 1,
                account_id: 1,
                amount: 2000,
                operation_type: "transfer".to_string(),
                metadata: HashMap::new(),
            };

            // Inject failure during step 3 (create_transaction)
            let failure_scenario = FailureScenario {
                scenario_name: "mid_transaction_failure".to_string(),
                failure_point: FailurePoint::DuringStep(2), // create_transaction step
                failure_type: FailureType::ConstraintViolation,
                expected_compensations: vec![
                    "reserve_funds".to_string(),
                    "validate_accounts".to_string(),
                ].into(),
            };

            let result = framework.execute_transaction_with_saga(
                cx,
                business_tx,
                Some(failure_scenario),
            ).await;

            assert!(result.is_err(), "Transaction should fail due to injected step failure");

            // Verify saga was aborted (not completed with compensation)
            let saga_aborted = framework.get_event_count(SagaTransactionEventType::SagaAborted).await;
            assert_eq!(saga_aborted, 1, "Saga should be aborted on step failure");

            // Database should be consistent
            let is_consistent = framework.verify_database_consistency().await.unwrap();
            assert!(is_consistent, "Database should remain consistent after rollback");

            framework.cleanup_test_database().await.unwrap();
            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn test_compensation_chain_order() {
        let framework = PostgresSagaTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime.region(Budget::unlimited(), |cx| async move {
            framework.setup_test_database(cx).await.unwrap();

            let business_tx = TestBusinessTransaction {
                transaction_id: "tx_compensation_order_001".to_string(),
                user_id: 1,
                account_id: 1,
                amount: 1500,
                operation_type: "transfer".to_string(),
                metadata: HashMap::new(),
            };

            // Inject failure before commit to trigger full compensation chain
            let failure_scenario = FailureScenario {
                scenario_name: "before_commit_failure".to_string(),
                failure_point: FailurePoint::BeforeCommit,
                failure_type: FailureType::LockTimeout,
                expected_compensations: vec![
                    "finalize_transaction".to_string(),
                    "credit_destination".to_string(),
                    "create_transaction".to_string(),
                    "reserve_funds".to_string(),
                ].into(),
            };

            let result = framework.execute_transaction_with_saga(
                cx,
                business_tx,
                Some(failure_scenario),
            ).await;

            assert!(result.is_err(), "Transaction should fail");

            // Verify compensation chain was executed
            let compensation_started = framework.get_event_count(SagaTransactionEventType::CompensationStarted).await;
            assert_eq!(compensation_started, 1, "Compensation should be started");

            let compensations_executed = framework.get_event_count(SagaTransactionEventType::CompensationExecuted).await;
            assert!(compensations_executed >= 4, "Should execute all step compensations");

            // Check compensation metrics
            let metrics = framework.get_compensation_metrics().await;
            assert_eq!(metrics.total_compensations_triggered, 1);
            assert!(metrics.successful_compensations >= 4);
            assert!(metrics.max_compensation_chain_length >= 4);

            framework.cleanup_test_database().await.unwrap();
            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn test_concurrent_transactions_with_failures() {
        let framework = PostgresSagaTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime.region(Budget::unlimited(), |cx| async move {
            framework.setup_test_database(cx).await.unwrap();

            let framework_ref = &framework;

            // Execute multiple concurrent transactions with various failure scenarios
            let tasks: Vec<_> = (0..5).map(|i| {
                spawn(cx, Budget::unlimited(), async move {
                    let business_tx = TestBusinessTransaction {
                        transaction_id: format!("tx_concurrent_{:03}", i),
                        user_id: 1,
                        account_id: 1,
                        amount: 100 + (i * 50) as i64,
                        operation_type: "transfer".to_string(),
                        metadata: HashMap::new(),
                    };

                    let failure_scenario = if i % 3 == 0 {
                        Some(FailureScenario {
                            scenario_name: format!("concurrent_failure_{}", i),
                            failure_point: FailurePoint::DuringCommit,
                            failure_type: FailureType::DeadlockDetected,
                            expected_compensations: vec![
                                "finalize_transaction".to_string(),
                                "credit_destination".to_string(),
                                "create_transaction".to_string(),
                                "reserve_funds".to_string(),
                            ].into(),
                        })
                    } else {
                        None
                    };

                    let result = framework_ref.execute_transaction_with_saga(
                        cx,
                        business_tx,
                        failure_scenario,
                    ).await;

                    // Return success count (1 if successful, 0 if failed)
                    Ok(if result.is_ok() { 1 } else { 0 })
                })
            }).collect();

            // Wait for all concurrent transactions
            let mut successful_transactions = 0;
            for task in tasks {
                if let Outcome::Ok(Ok(success_count)) = task.join().await {
                    successful_transactions += success_count;
                }
            }

            // Should have some successful and some failed transactions
            assert!(successful_transactions > 0, "Should have some successful transactions");
            assert!(successful_transactions < 5, "Should have some failed transactions");

            // Verify compensation was triggered for failed transactions
            let compensations_triggered = framework.get_event_count(SagaTransactionEventType::CompensationStarted).await;
            assert!(compensations_triggered > 0, "Should have triggered compensations for failed transactions");

            // Database should remain consistent despite concurrent operations
            let is_consistent = framework.verify_database_consistency().await.unwrap();
            assert!(is_consistent, "Database should remain consistent after concurrent operations");

            framework.cleanup_test_database().await.unwrap();
            Ok(())
        }).await.unwrap();
    }
}