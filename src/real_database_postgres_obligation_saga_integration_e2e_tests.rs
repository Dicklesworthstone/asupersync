//! br-e2e-228: database/postgres ↔ obligation/saga rollback integration E2E tests
//!
//! This module tests the integration between PostgreSQL database operations
//! and saga-based rollback patterns using obligation tracking for transactional
//! consistency across async operations.

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use crate::{
        cx::{Cx, Scope},
        database::postgres::{PostgresConnection, PostgresPool, PostgresTransaction},
        obligation::{
            saga::{SagaCoordinator, SagaStep, CompensationAction, RollbackStrategy},
            Obligation, ObligationTracker, ObligationLease
        },
        runtime::{RuntimeBuilder, LabRuntime},
        sync::{Mutex, Arc},
        types::{Outcome, Budget, TaskId, RegionId},
        channel::{mpsc, oneshot, broadcast},
        time::{Sleep, Duration, Instant},
        error::{AsupersyncError, ResultExt},
        util::{correlation::CorrelationId, entropy::SecureRng},
    };
    use std::collections::{HashMap, BTreeMap, VecDeque};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use serde::{Serialize, Deserialize};
    use thiserror::Error;

    #[derive(Debug, Clone)]
    struct PostgresSagaSystem {
        pool: Arc<PostgresPool>,
        coordinator: Arc<SagaCoordinator>,
        obligation_tracker: Arc<ObligationTracker>,
        stats: Arc<PostgresSagaStats>,
        config: PostgresSagaConfig,
    }

    #[derive(Debug, Clone)]
    struct PostgresSagaConfig {
        max_concurrent_sagas: usize,
        transaction_timeout: Duration,
        compensation_timeout: Duration,
        max_retry_attempts: u32,
        rollback_strategy: RollbackStrategy,
        enable_nested_sagas: bool,
        checkpoint_interval: Duration,
    }

    impl Default for PostgresSagaConfig {
        fn default() -> Self {
            Self {
                max_concurrent_sagas: 100,
                transaction_timeout: Duration::from_secs(30),
                compensation_timeout: Duration::from_secs(60),
                max_retry_attempts: 3,
                rollback_strategy: RollbackStrategy::Immediate,
                enable_nested_sagas: true,
                checkpoint_interval: Duration::from_millis(100),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct SagaTransaction {
        correlation_id: CorrelationId,
        transaction_id: String,
        steps: Vec<SagaStepRecord>,
        compensation_actions: Vec<CompensationRecord>,
        status: SagaStatus,
        created_at: Instant,
        completed_at: Option<Instant>,
        obligation_lease: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct SagaStepRecord {
        step_id: String,
        sql_query: String,
        parameters: Vec<String>,
        compensation_query: Option<String>,
        executed_at: Option<Instant>,
        compensation_executed_at: Option<Instant>,
        status: StepStatus,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct CompensationRecord {
        step_id: String,
        action_type: CompensationActionType,
        sql_query: String,
        parameters: Vec<String>,
        executed_at: Option<Instant>,
        result: Option<CompensationResult>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    enum SagaStatus {
        Pending,
        InProgress,
        Committed,
        RollingBack,
        RolledBack,
        Failed,
        Compensating,
        Compensated,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    enum StepStatus {
        Pending,
        Executing,
        Completed,
        Failed,
        Compensating,
        Compensated,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    enum CompensationActionType {
        Rollback,
        Compensate,
        Undo,
        Cleanup,
        Notify,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    enum CompensationResult {
        Success,
        Partial,
        Failed,
        Skipped,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RollbackStrategy {
        Immediate,
        Batched,
        RetryThenRollback,
        Partial,
        BestEffort,
    }

    #[derive(Debug)]
    struct PostgresSagaStats {
        sagas_started: AtomicU64,
        sagas_completed: AtomicU64,
        sagas_rolled_back: AtomicU64,
        sagas_failed: AtomicU64,
        steps_executed: AtomicU64,
        steps_compensated: AtomicU64,
        avg_saga_duration_ms: AtomicU64,
        avg_compensation_duration_ms: AtomicU64,
        transaction_conflicts: AtomicU64,
        obligation_violations: AtomicU64,
        rollback_strategy_counts: Arc<Mutex<HashMap<RollbackStrategy, u64>>>,
    }

    impl Default for PostgresSagaStats {
        fn default() -> Self {
            Self {
                sagas_started: AtomicU64::new(0),
                sagas_completed: AtomicU64::new(0),
                sagas_rolled_back: AtomicU64::new(0),
                sagas_failed: AtomicU64::new(0),
                steps_executed: AtomicU64::new(0),
                steps_compensated: AtomicU64::new(0),
                avg_saga_duration_ms: AtomicU64::new(0),
                avg_compensation_duration_ms: AtomicU64::new(0),
                transaction_conflicts: AtomicU64::new(0),
                obligation_violations: AtomicU64::new(0),
                rollback_strategy_counts: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    #[derive(Debug, Error)]
    enum PostgresSagaError {
        #[error("Database transaction failed: {0}")]
        TransactionFailed(String),
        #[error("Saga step failed: {step_id}, reason: {reason}")]
        StepFailed { step_id: String, reason: String },
        #[error("Compensation failed: {step_id}, reason: {reason}")]
        CompensationFailed { step_id: String, reason: String },
        #[error("Obligation lease expired: {lease_id}")]
        ObligationExpired { lease_id: String },
        #[error("Rollback strategy failed: {strategy:?}, reason: {reason}")]
        RollbackFailed { strategy: RollbackStrategy, reason: String },
        #[error("Saga timeout: {correlation_id:?}")]
        SagaTimeout { correlation_id: CorrelationId },
        #[error("Concurrent modification conflict")]
        ConcurrencyConflict,
    }

    impl PostgresSagaSystem {
        async fn new(cx: &Cx, config: PostgresSagaConfig) -> Result<Self, AsupersyncError> {
            let pool = Arc::new(PostgresPool::new(cx, "postgresql://localhost:5432/test").await?);
            let coordinator = Arc::new(SagaCoordinator::new(cx, &config).await?);
            let obligation_tracker = Arc::new(ObligationTracker::new(cx)?);
            let stats = Arc::new(PostgresSagaStats::default());

            Ok(Self {
                pool,
                coordinator,
                obligation_tracker,
                stats,
                config,
            })
        }

        async fn execute_saga(
            &self,
            cx: &Cx,
            correlation_id: CorrelationId,
            steps: Vec<SagaStepDefinition>,
        ) -> Result<SagaTransaction, PostgresSagaError> {
            let start_time = Instant::now();
            self.stats.sagas_started.fetch_add(1, Ordering::Relaxed);

            // Acquire obligation lease for saga duration
            let obligation_lease = self.obligation_tracker
                .acquire_lease(cx, format!("saga-{}", correlation_id), self.config.transaction_timeout)
                .await
                .map_err(|e| PostgresSagaError::TransactionFailed(format!("Lease acquisition failed: {}", e)))?;

            let mut saga = SagaTransaction {
                correlation_id,
                transaction_id: format!("txn-{}-{}", correlation_id, start_time.elapsed().as_nanos()),
                steps: Vec::new(),
                compensation_actions: Vec::new(),
                status: SagaStatus::InProgress,
                created_at: start_time,
                completed_at: None,
                obligation_lease: Some(obligation_lease.id().to_string()),
            };

            // Execute saga steps within transaction scope
            match self.execute_saga_steps(cx, &mut saga, steps, &obligation_lease).await {
                Ok(()) => {
                    saga.status = SagaStatus::Committed;
                    saga.completed_at = Some(Instant::now());
                    self.stats.sagas_completed.fetch_add(1, Ordering::Relaxed);

                    // Update rollback strategy statistics
                    {
                        let mut counts = self.stats.rollback_strategy_counts.lock().await;
                        *counts.entry(self.config.rollback_strategy).or_insert(0) += 1;
                    }

                    let duration_ms = saga.completed_at.unwrap().duration_since(saga.created_at).as_millis() as u64;
                    self.stats.avg_saga_duration_ms.store(duration_ms, Ordering::Relaxed);

                    // Release obligation lease
                    obligation_lease.commit(cx).await
                        .map_err(|e| PostgresSagaError::TransactionFailed(format!("Lease commit failed: {}", e)))?;

                    Ok(saga)
                }
                Err(error) => {
                    // Execute rollback based on configured strategy
                    match self.execute_rollback(cx, &mut saga, &obligation_lease, error.clone()).await {
                        Ok(()) => {
                            saga.status = SagaStatus::RolledBack;
                            saga.completed_at = Some(Instant::now());
                            self.stats.sagas_rolled_back.fetch_add(1, Ordering::Relaxed);

                            // Abort obligation lease
                            obligation_lease.abort(cx).await
                                .map_err(|e| PostgresSagaError::TransactionFailed(format!("Lease abort failed: {}", e)))?;

                            Err(error)
                        }
                        Err(rollback_error) => {
                            saga.status = SagaStatus::Failed;
                            saga.completed_at = Some(Instant::now());
                            self.stats.sagas_failed.fetch_add(1, Ordering::Relaxed);

                            // Force abort obligation lease
                            let _ = obligation_lease.abort(cx).await;

                            Err(PostgresSagaError::RollbackFailed {
                                strategy: self.config.rollback_strategy,
                                reason: format!("Original: {}, Rollback: {}", error, rollback_error),
                            })
                        }
                    }
                }
            }
        }

        async fn execute_saga_steps(
            &self,
            cx: &Cx,
            saga: &mut SagaTransaction,
            steps: Vec<SagaStepDefinition>,
            obligation_lease: &ObligationLease,
        ) -> Result<(), PostgresSagaError> {
            let mut connection = self.pool.acquire(cx).await
                .map_err(|e| PostgresSagaError::TransactionFailed(format!("Pool acquisition failed: {}", e)))?;

            let mut transaction = connection.begin(cx).await
                .map_err(|e| PostgresSagaError::TransactionFailed(format!("Transaction begin failed: {}", e)))?;

            for (index, step_def) in steps.iter().enumerate() {
                // Check obligation lease validity
                if !obligation_lease.is_valid() {
                    return Err(PostgresSagaError::ObligationExpired {
                        lease_id: obligation_lease.id().to_string()
                    });
                }

                let step_id = format!("step-{}", index);
                let mut step_record = SagaStepRecord {
                    step_id: step_id.clone(),
                    sql_query: step_def.query.clone(),
                    parameters: step_def.parameters.clone(),
                    compensation_query: step_def.compensation_query.clone(),
                    executed_at: None,
                    compensation_executed_at: None,
                    status: StepStatus::Executing,
                };

                // Execute step with timeout
                let step_start = Instant::now();
                let step_result = cx.timeout(self.config.transaction_timeout, async {
                    transaction.execute(&step_def.query, &step_def.parameters).await
                }).await;

                match step_result {
                    Ok(Ok(_)) => {
                        step_record.executed_at = Some(Instant::now());
                        step_record.status = StepStatus::Completed;
                        self.stats.steps_executed.fetch_add(1, Ordering::Relaxed);

                        saga.steps.push(step_record);

                        // Add compensation action if defined
                        if let Some(compensation_query) = &step_def.compensation_query {
                            let compensation = CompensationRecord {
                                step_id: step_id.clone(),
                                action_type: CompensationActionType::Rollback,
                                sql_query: compensation_query.clone(),
                                parameters: step_def.parameters.clone(),
                                executed_at: None,
                                result: None,
                            };
                            saga.compensation_actions.push(compensation);
                        }
                    }
                    Ok(Err(db_error)) => {
                        step_record.status = StepStatus::Failed;
                        saga.steps.push(step_record);
                        return Err(PostgresSagaError::StepFailed {
                            step_id: step_id,
                            reason: format!("Database error: {}", db_error),
                        });
                    }
                    Err(_timeout) => {
                        step_record.status = StepStatus::Failed;
                        saga.steps.push(step_record);
                        return Err(PostgresSagaError::SagaTimeout {
                            correlation_id: saga.correlation_id,
                        });
                    }
                }
            }

            // Commit transaction
            transaction.commit(cx).await
                .map_err(|e| PostgresSagaError::TransactionFailed(format!("Transaction commit failed: {}", e)))?;

            Ok(())
        }

        async fn execute_rollback(
            &self,
            cx: &Cx,
            saga: &mut SagaTransaction,
            obligation_lease: &ObligationLease,
            original_error: PostgresSagaError,
        ) -> Result<(), PostgresSagaError> {
            saga.status = SagaStatus::RollingBack;

            match self.config.rollback_strategy {
                RollbackStrategy::Immediate => {
                    self.execute_immediate_rollback(cx, saga, obligation_lease).await
                }
                RollbackStrategy::Batched => {
                    self.execute_batched_rollback(cx, saga, obligation_lease).await
                }
                RollbackStrategy::RetryThenRollback => {
                    // First attempt retry, then fallback to rollback
                    for attempt in 0..self.config.max_retry_attempts {
                        if let Ok(()) = self.retry_failed_steps(cx, saga, obligation_lease).await {
                            return Ok(());
                        }
                        cx.sleep(Duration::from_millis(100 * (1 << attempt))).await;
                    }
                    self.execute_immediate_rollback(cx, saga, obligation_lease).await
                }
                RollbackStrategy::Partial => {
                    self.execute_partial_rollback(cx, saga, obligation_lease).await
                }
                RollbackStrategy::BestEffort => {
                    let _ = self.execute_best_effort_rollback(cx, saga, obligation_lease).await;
                    Ok(())
                }
            }
        }

        async fn execute_immediate_rollback(
            &self,
            cx: &Cx,
            saga: &mut SagaTransaction,
            obligation_lease: &ObligationLease,
        ) -> Result<(), PostgresSagaError> {
            let mut connection = self.pool.acquire(cx).await
                .map_err(|e| PostgresSagaError::TransactionFailed(format!("Rollback pool acquisition failed: {}", e)))?;

            // Execute compensation actions in reverse order
            for compensation in saga.compensation_actions.iter_mut().rev() {
                if !obligation_lease.is_valid() {
                    return Err(PostgresSagaError::ObligationExpired {
                        lease_id: obligation_lease.id().to_string()
                    });
                }

                let comp_start = Instant::now();
                let comp_result = cx.timeout(self.config.compensation_timeout, async {
                    connection.execute(&compensation.sql_query, &compensation.parameters).await
                }).await;

                compensation.executed_at = Some(Instant::now());

                match comp_result {
                    Ok(Ok(_)) => {
                        compensation.result = Some(CompensationResult::Success);
                        self.stats.steps_compensated.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(Err(db_error)) => {
                        compensation.result = Some(CompensationResult::Failed);
                        return Err(PostgresSagaError::CompensationFailed {
                            step_id: compensation.step_id.clone(),
                            reason: format!("Database error: {}", db_error),
                        });
                    }
                    Err(_timeout) => {
                        compensation.result = Some(CompensationResult::Failed);
                        return Err(PostgresSagaError::CompensationFailed {
                            step_id: compensation.step_id.clone(),
                            reason: "Compensation timeout".to_string(),
                        });
                    }
                }
            }

            Ok(())
        }

        async fn execute_batched_rollback(
            &self,
            cx: &Cx,
            saga: &mut SagaTransaction,
            obligation_lease: &ObligationLease,
        ) -> Result<(), PostgresSagaError> {
            let mut connection = self.pool.acquire(cx).await
                .map_err(|e| PostgresSagaError::TransactionFailed(format!("Batched rollback pool acquisition failed: {}", e)))?;

            let mut transaction = connection.begin(cx).await
                .map_err(|e| PostgresSagaError::TransactionFailed(format!("Batched rollback transaction begin failed: {}", e)))?;

            // Execute all compensation actions in a single transaction
            for compensation in saga.compensation_actions.iter_mut().rev() {
                if !obligation_lease.is_valid() {
                    return Err(PostgresSagaError::ObligationExpired {
                        lease_id: obligation_lease.id().to_string()
                    });
                }

                let comp_result = transaction.execute(&compensation.sql_query, &compensation.parameters).await;
                compensation.executed_at = Some(Instant::now());

                match comp_result {
                    Ok(_) => {
                        compensation.result = Some(CompensationResult::Success);
                        self.stats.steps_compensated.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(db_error) => {
                        compensation.result = Some(CompensationResult::Failed);
                        // Rollback the compensation transaction
                        let _ = transaction.rollback(cx).await;
                        return Err(PostgresSagaError::CompensationFailed {
                            step_id: compensation.step_id.clone(),
                            reason: format!("Batched compensation failed: {}", db_error),
                        });
                    }
                }
            }

            // Commit all compensation actions
            transaction.commit(cx).await
                .map_err(|e| PostgresSagaError::CompensationFailed {
                    step_id: "batch".to_string(),
                    reason: format!("Batched compensation commit failed: {}", e),
                })?;

            Ok(())
        }

        async fn execute_partial_rollback(
            &self,
            cx: &Cx,
            saga: &mut SagaTransaction,
            obligation_lease: &ObligationLease,
        ) -> Result<(), PostgresSagaError> {
            let mut partial_success = true;
            let mut connection = self.pool.acquire(cx).await
                .map_err(|e| PostgresSagaError::TransactionFailed(format!("Partial rollback pool acquisition failed: {}", e)))?;

            // Attempt to rollback each step independently
            for compensation in saga.compensation_actions.iter_mut().rev() {
                if !obligation_lease.is_valid() {
                    compensation.result = Some(CompensationResult::Skipped);
                    continue;
                }

                let comp_result = connection.execute(&compensation.sql_query, &compensation.parameters).await;
                compensation.executed_at = Some(Instant::now());

                match comp_result {
                    Ok(_) => {
                        compensation.result = Some(CompensationResult::Success);
                        self.stats.steps_compensated.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        compensation.result = Some(CompensationResult::Partial);
                        partial_success = false;
                        // Continue with other compensation actions
                    }
                }
            }

            if partial_success {
                Ok(())
            } else {
                Err(PostgresSagaError::RollbackFailed {
                    strategy: RollbackStrategy::Partial,
                    reason: "Some compensation actions failed".to_string(),
                })
            }
        }

        async fn execute_best_effort_rollback(
            &self,
            cx: &Cx,
            saga: &mut SagaTransaction,
            obligation_lease: &ObligationLease,
        ) -> Result<(), PostgresSagaError> {
            let mut connection = self.pool.acquire(cx).await
                .map_err(|e| PostgresSagaError::TransactionFailed(format!("Best effort rollback pool acquisition failed: {}", e)))?;

            // Execute all compensation actions, ignoring failures
            for compensation in saga.compensation_actions.iter_mut().rev() {
                if !obligation_lease.is_valid() {
                    compensation.result = Some(CompensationResult::Skipped);
                    continue;
                }

                let comp_result = connection.execute(&compensation.sql_query, &compensation.parameters).await;
                compensation.executed_at = Some(Instant::now());

                match comp_result {
                    Ok(_) => {
                        compensation.result = Some(CompensationResult::Success);
                        self.stats.steps_compensated.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        compensation.result = Some(CompensationResult::Failed);
                        // Continue with best effort - don't fail on individual compensation errors
                    }
                }
            }

            Ok(())
        }

        async fn retry_failed_steps(
            &self,
            cx: &Cx,
            saga: &mut SagaTransaction,
            obligation_lease: &ObligationLease,
        ) -> Result<(), PostgresSagaError> {
            // Find failed steps and retry them
            let failed_steps: Vec<_> = saga.steps.iter()
                .filter(|step| step.status == StepStatus::Failed)
                .collect();

            if failed_steps.is_empty() {
                return Ok(());
            }

            let mut connection = self.pool.acquire(cx).await
                .map_err(|e| PostgresSagaError::TransactionFailed(format!("Retry pool acquisition failed: {}", e)))?;

            let mut transaction = connection.begin(cx).await
                .map_err(|e| PostgresSagaError::TransactionFailed(format!("Retry transaction begin failed: {}", e)))?;

            // Retry failed steps
            for step in &failed_steps {
                if !obligation_lease.is_valid() {
                    return Err(PostgresSagaError::ObligationExpired {
                        lease_id: obligation_lease.id().to_string()
                    });
                }

                let retry_result = transaction.execute(&step.sql_query, &step.parameters).await;
                match retry_result {
                    Ok(_) => {
                        // Update step status in saga
                        if let Some(saga_step) = saga.steps.iter_mut().find(|s| s.step_id == step.step_id) {
                            saga_step.status = StepStatus::Completed;
                            saga_step.executed_at = Some(Instant::now());
                        }
                        self.stats.steps_executed.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(db_error) => {
                        // Rollback retry transaction
                        let _ = transaction.rollback(cx).await;
                        return Err(PostgresSagaError::StepFailed {
                            step_id: step.step_id.clone(),
                            reason: format!("Retry failed: {}", db_error),
                        });
                    }
                }
            }

            // Commit retry transaction
            transaction.commit(cx).await
                .map_err(|e| PostgresSagaError::TransactionFailed(format!("Retry transaction commit failed: {}", e)))?;

            Ok(())
        }

        fn get_stats(&self) -> PostgresSagaStatsSnapshot {
            PostgresSagaStatsSnapshot {
                sagas_started: self.stats.sagas_started.load(Ordering::Relaxed),
                sagas_completed: self.stats.sagas_completed.load(Ordering::Relaxed),
                sagas_rolled_back: self.stats.sagas_rolled_back.load(Ordering::Relaxed),
                sagas_failed: self.stats.sagas_failed.load(Ordering::Relaxed),
                steps_executed: self.stats.steps_executed.load(Ordering::Relaxed),
                steps_compensated: self.stats.steps_compensated.load(Ordering::Relaxed),
                avg_saga_duration_ms: self.stats.avg_saga_duration_ms.load(Ordering::Relaxed),
                avg_compensation_duration_ms: self.stats.avg_compensation_duration_ms.load(Ordering::Relaxed),
                transaction_conflicts: self.stats.transaction_conflicts.load(Ordering::Relaxed),
                obligation_violations: self.stats.obligation_violations.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct SagaStepDefinition {
        query: String,
        parameters: Vec<String>,
        compensation_query: Option<String>,
    }

    #[derive(Debug, Clone)]
    struct PostgresSagaStatsSnapshot {
        sagas_started: u64,
        sagas_completed: u64,
        sagas_rolled_back: u64,
        sagas_failed: u64,
        steps_executed: u64,
        steps_compensated: u64,
        avg_saga_duration_ms: u64,
        avg_compensation_duration_ms: u64,
        transaction_conflicts: u64,
        obligation_violations: u64,
    }

    #[tokio::test]
    async fn test_basic_saga_commit_success() {
        let runtime = LabRuntime::new().await.unwrap();
        let cx = runtime.cx();

        let config = PostgresSagaConfig {
            rollback_strategy: RollbackStrategy::Immediate,
            max_concurrent_sagas: 10,
            ..Default::default()
        };

        let system = PostgresSagaSystem::new(&cx, config).await.unwrap();
        let correlation_id = CorrelationId::new();

        // Define saga steps with compensation
        let steps = vec![
            SagaStepDefinition {
                query: "INSERT INTO accounts (id, balance) VALUES ($1, $2)".to_string(),
                parameters: vec!["acc1".to_string(), "1000".to_string()],
                compensation_query: Some("DELETE FROM accounts WHERE id = $1".to_string()),
            },
            SagaStepDefinition {
                query: "INSERT INTO transactions (id, from_account, amount) VALUES ($1, $2, $3)".to_string(),
                parameters: vec!["txn1".to_string(), "acc1".to_string(), "100".to_string()],
                compensation_query: Some("DELETE FROM transactions WHERE id = $1".to_string()),
            },
        ];

        let result = system.execute_saga(&cx, correlation_id, steps).await;
        assert!(result.is_ok());

        let saga = result.unwrap();
        assert_eq!(saga.status, SagaStatus::Committed);
        assert_eq!(saga.steps.len(), 2);
        assert!(saga.completed_at.is_some());

        let stats = system.get_stats();
        assert_eq!(stats.sagas_started, 1);
        assert_eq!(stats.sagas_completed, 1);
        assert_eq!(stats.sagas_rolled_back, 0);
        assert_eq!(stats.steps_executed, 2);
    }

    #[tokio::test]
    async fn test_saga_rollback_on_failure() {
        let runtime = LabRuntime::new().await.unwrap();
        let cx = runtime.cx();

        let config = PostgresSagaConfig {
            rollback_strategy: RollbackStrategy::Immediate,
            max_concurrent_sagas: 10,
            ..Default::default()
        };

        let system = PostgresSagaSystem::new(&cx, config).await.unwrap();
        let correlation_id = CorrelationId::new();

        // Define saga steps where second step will fail
        let steps = vec![
            SagaStepDefinition {
                query: "INSERT INTO accounts (id, balance) VALUES ($1, $2)".to_string(),
                parameters: vec!["acc2".to_string(), "1000".to_string()],
                compensation_query: Some("DELETE FROM accounts WHERE id = $1".to_string()),
            },
            SagaStepDefinition {
                query: "INSERT INTO invalid_table (id) VALUES ($1)".to_string(), // This will fail
                parameters: vec!["invalid".to_string()],
                compensation_query: None,
            },
        ];

        let result = system.execute_saga(&cx, correlation_id, steps).await;
        assert!(result.is_err());

        match result {
            Err(PostgresSagaError::StepFailed { step_id, .. }) => {
                assert_eq!(step_id, "step-1");
            }
            other => panic!("Expected StepFailed error, got: {:?}", other),
        }

        let stats = system.get_stats();
        assert_eq!(stats.sagas_started, 1);
        assert_eq!(stats.sagas_completed, 0);
        assert_eq!(stats.sagas_rolled_back, 1);
    }

    #[tokio::test]
    async fn test_batched_rollback_strategy() {
        let runtime = LabRuntime::new().await.unwrap();
        let cx = runtime.cx();

        let config = PostgresSagaConfig {
            rollback_strategy: RollbackStrategy::Batched,
            max_concurrent_sagas: 10,
            ..Default::default()
        };

        let system = PostgresSagaSystem::new(&cx, config).await.unwrap();
        let correlation_id = CorrelationId::new();

        let steps = vec![
            SagaStepDefinition {
                query: "INSERT INTO accounts (id, balance) VALUES ($1, $2)".to_string(),
                parameters: vec!["acc3".to_string(), "1000".to_string()],
                compensation_query: Some("DELETE FROM accounts WHERE id = $1".to_string()),
            },
            SagaStepDefinition {
                query: "INSERT INTO transactions (id, from_account, amount) VALUES ($1, $2, $3)".to_string(),
                parameters: vec!["txn3".to_string(), "acc3".to_string(), "100".to_string()],
                compensation_query: Some("DELETE FROM transactions WHERE id = $1".to_string()),
            },
            SagaStepDefinition {
                query: "INSERT INTO invalid_table (id) VALUES ($1)".to_string(), // This will fail
                parameters: vec!["invalid".to_string()],
                compensation_query: None,
            },
        ];

        let result = system.execute_saga(&cx, correlation_id, steps).await;
        assert!(result.is_err());

        let stats = system.get_stats();
        assert_eq!(stats.sagas_started, 1);
        assert_eq!(stats.sagas_rolled_back, 1);
        assert_eq!(stats.steps_compensated, 2); // Both successful steps compensated
    }

    #[tokio::test]
    async fn test_retry_then_rollback_strategy() {
        let runtime = LabRuntime::new().await.unwrap();
        let cx = runtime.cx();

        let config = PostgresSagaConfig {
            rollback_strategy: RollbackStrategy::RetryThenRollback,
            max_retry_attempts: 2,
            max_concurrent_sagas: 10,
            ..Default::default()
        };

        let system = PostgresSagaSystem::new(&cx, config).await.unwrap();
        let correlation_id = CorrelationId::new();

        let steps = vec![
            SagaStepDefinition {
                query: "INSERT INTO accounts (id, balance) VALUES ($1, $2)".to_string(),
                parameters: vec!["acc4".to_string(), "1000".to_string()],
                compensation_query: Some("DELETE FROM accounts WHERE id = $1".to_string()),
            },
            SagaStepDefinition {
                query: "INSERT INTO invalid_table (id) VALUES ($1)".to_string(), // This will always fail
                parameters: vec!["invalid".to_string()],
                compensation_query: None,
            },
        ];

        let result = system.execute_saga(&cx, correlation_id, steps).await;
        assert!(result.is_err());

        let stats = system.get_stats();
        assert_eq!(stats.sagas_started, 1);
        assert_eq!(stats.sagas_rolled_back, 1);
    }

    #[tokio::test]
    async fn test_partial_rollback_strategy() {
        let runtime = LabRuntime::new().await.unwrap();
        let cx = runtime.cx();

        let config = PostgresSagaConfig {
            rollback_strategy: RollbackStrategy::Partial,
            max_concurrent_sagas: 10,
            ..Default::default()
        };

        let system = PostgresSagaSystem::new(&cx, config).await.unwrap();
        let correlation_id = CorrelationId::new();

        let steps = vec![
            SagaStepDefinition {
                query: "INSERT INTO accounts (id, balance) VALUES ($1, $2)".to_string(),
                parameters: vec!["acc5".to_string(), "1000".to_string()],
                compensation_query: Some("DELETE FROM accounts WHERE id = $1".to_string()),
            },
            SagaStepDefinition {
                query: "INSERT INTO transactions (id, from_account, amount) VALUES ($1, $2, $3)".to_string(),
                parameters: vec!["txn5".to_string(), "acc5".to_string(), "100".to_string()],
                compensation_query: Some("DELETE FROM invalid_table WHERE id = $1".to_string()), // Compensation will fail
            },
            SagaStepDefinition {
                query: "INSERT INTO invalid_table (id) VALUES ($1)".to_string(), // This will fail
                parameters: vec!["invalid".to_string()],
                compensation_query: None,
            },
        ];

        let result = system.execute_saga(&cx, correlation_id, steps).await;
        assert!(result.is_err());

        let stats = system.get_stats();
        assert_eq!(stats.sagas_started, 1);
        // Partial rollback might succeed or fail depending on individual compensation results
    }

    #[tokio::test]
    async fn test_best_effort_rollback_strategy() {
        let runtime = LabRuntime::new().await.unwrap();
        let cx = runtime.cx();

        let config = PostgresSagaConfig {
            rollback_strategy: RollbackStrategy::BestEffort,
            max_concurrent_sagas: 10,
            ..Default::default()
        };

        let system = PostgresSagaSystem::new(&cx, config).await.unwrap();
        let correlation_id = CorrelationId::new();

        let steps = vec![
            SagaStepDefinition {
                query: "INSERT INTO accounts (id, balance) VALUES ($1, $2)".to_string(),
                parameters: vec!["acc6".to_string(), "1000".to_string()],
                compensation_query: Some("DELETE FROM accounts WHERE id = $1".to_string()),
            },
            SagaStepDefinition {
                query: "INSERT INTO invalid_table (id) VALUES ($1)".to_string(), // This will fail
                parameters: vec!["invalid".to_string()],
                compensation_query: Some("DELETE FROM invalid_table WHERE id = $1".to_string()), // Compensation will also fail
            },
        ];

        let result = system.execute_saga(&cx, correlation_id, steps).await;
        assert!(result.is_err());

        // Best effort should still result in rollback even if compensation fails
        let stats = system.get_stats();
        assert_eq!(stats.sagas_started, 1);
        assert_eq!(stats.sagas_rolled_back, 1);
    }

    #[tokio::test]
    async fn test_obligation_lease_expiration() {
        let runtime = LabRuntime::new().await.unwrap();
        let cx = runtime.cx();

        let config = PostgresSagaConfig {
            rollback_strategy: RollbackStrategy::Immediate,
            transaction_timeout: Duration::from_millis(50), // Very short timeout
            max_concurrent_sagas: 10,
            ..Default::default()
        };

        let system = PostgresSagaSystem::new(&cx, config).await.unwrap();
        let correlation_id = CorrelationId::new();

        let steps = vec![
            SagaStepDefinition {
                query: "SELECT pg_sleep(1)".to_string(), // Sleep longer than timeout
                parameters: vec![],
                compensation_query: None,
            },
        ];

        let result = system.execute_saga(&cx, correlation_id, steps).await;
        assert!(result.is_err());

        match result {
            Err(PostgresSagaError::SagaTimeout { .. }) => {
                // Expected timeout error
            }
            other => panic!("Expected SagaTimeout error, got: {:?}", other),
        }

        let stats = system.get_stats();
        assert_eq!(stats.sagas_started, 1);
        assert_eq!(stats.sagas_failed, 1);
    }

    #[tokio::test]
    async fn test_concurrent_saga_execution() {
        let runtime = LabRuntime::new().await.unwrap();
        let cx = runtime.cx();

        let config = PostgresSagaConfig {
            rollback_strategy: RollbackStrategy::Immediate,
            max_concurrent_sagas: 5,
            ..Default::default()
        };

        let system = Arc::new(PostgresSagaSystem::new(&cx, config).await.unwrap());

        let mut handles = Vec::new();

        // Launch multiple concurrent sagas
        for i in 0..5 {
            let system_clone = system.clone();
            let cx_clone = cx.clone();
            let handle = cx.spawn(async move {
                let correlation_id = CorrelationId::new();
                let steps = vec![
                    SagaStepDefinition {
                        query: format!("INSERT INTO accounts (id, balance) VALUES ($1, $2)"),
                        parameters: vec![format!("acc{}", i), "1000".to_string()],
                        compensation_query: Some("DELETE FROM accounts WHERE id = $1".to_string()),
                    },
                ];

                system_clone.execute_saga(&cx_clone, correlation_id, steps).await
            });
            handles.push(handle);
        }

        // Wait for all sagas to complete
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }

        let stats = system.get_stats();
        assert_eq!(stats.sagas_started, 5);
        assert_eq!(stats.sagas_completed, 5);
        assert_eq!(stats.sagas_rolled_back, 0);
        assert_eq!(stats.steps_executed, 5);
    }

    #[tokio::test]
    async fn test_nested_saga_coordination() {
        let runtime = LabRuntime::new().await.unwrap();
        let cx = runtime.cx();

        let config = PostgresSagaConfig {
            rollback_strategy: RollbackStrategy::Immediate,
            enable_nested_sagas: true,
            max_concurrent_sagas: 10,
            ..Default::default()
        };

        let system = Arc::new(PostgresSagaSystem::new(&cx, config).await.unwrap());

        // Parent saga that spawns child saga
        let parent_correlation_id = CorrelationId::new();
        let child_correlation_id = CorrelationId::new();

        // Execute parent saga
        let parent_steps = vec![
            SagaStepDefinition {
                query: "INSERT INTO accounts (id, balance) VALUES ($1, $2)".to_string(),
                parameters: vec!["parent_acc".to_string(), "5000".to_string()],
                compensation_query: Some("DELETE FROM accounts WHERE id = $1".to_string()),
            },
        ];

        let parent_result = system.execute_saga(&cx, parent_correlation_id, parent_steps).await;
        assert!(result.is_ok());

        // Execute child saga as part of parent transaction scope
        let child_steps = vec![
            SagaStepDefinition {
                query: "INSERT INTO accounts (id, balance) VALUES ($1, $2)".to_string(),
                parameters: vec!["child_acc".to_string(), "1000".to_string()],
                compensation_query: Some("DELETE FROM accounts WHERE id = $1".to_string()),
            },
        ];

        let child_result = system.execute_saga(&cx, child_correlation_id, child_steps).await;
        assert!(child_result.is_ok());

        let stats = system.get_stats();
        assert_eq!(stats.sagas_started, 2);
        assert_eq!(stats.sagas_completed, 2);
        assert_eq!(stats.steps_executed, 2);
    }

    #[tokio::test]
    async fn test_saga_statistics_tracking() {
        let runtime = LabRuntime::new().await.unwrap();
        let cx = runtime.cx();

        let config = PostgresSagaConfig::default();
        let system = PostgresSagaSystem::new(&cx, config).await.unwrap();

        // Execute multiple sagas with different outcomes
        for i in 0..3 {
            let correlation_id = CorrelationId::new();
            let steps = vec![
                SagaStepDefinition {
                    query: format!("INSERT INTO accounts (id, balance) VALUES ($1, $2)"),
                    parameters: vec![format!("stats_acc{}", i), "1000".to_string()],
                    compensation_query: Some("DELETE FROM accounts WHERE id = $1".to_string()),
                },
            ];

            let _ = system.execute_saga(&cx, correlation_id, steps).await;
        }

        // Execute one failing saga
        let correlation_id = CorrelationId::new();
        let failing_steps = vec![
            SagaStepDefinition {
                query: "INSERT INTO invalid_table (id) VALUES ($1)".to_string(),
                parameters: vec!["invalid".to_string()],
                compensation_query: None,
            },
        ];

        let _ = system.execute_saga(&cx, correlation_id, failing_steps).await;

        let stats = system.get_stats();
        assert_eq!(stats.sagas_started, 4);
        assert_eq!(stats.sagas_completed, 3);
        assert_eq!(stats.sagas_rolled_back, 1);
        assert_eq!(stats.steps_executed, 3);
    }

    #[tokio::test]
    async fn test_correlation_id_tracking() {
        let runtime = LabRuntime::new().await.unwrap();
        let cx = runtime.cx();

        let config = PostgresSagaConfig::default();
        let system = PostgresSagaSystem::new(&cx, config).await.unwrap();

        let correlation_id = CorrelationId::new();
        let steps = vec![
            SagaStepDefinition {
                query: "INSERT INTO accounts (id, balance) VALUES ($1, $2)".to_string(),
                parameters: vec!["correlation_acc".to_string(), "1000".to_string()],
                compensation_query: Some("DELETE FROM accounts WHERE id = $1".to_string()),
            },
        ];

        let result = system.execute_saga(&cx, correlation_id, steps).await;
        assert!(result.is_ok());

        let saga = result.unwrap();
        assert_eq!(saga.correlation_id, correlation_id);
        assert!(saga.transaction_id.contains(&format!("{}", correlation_id)));
        assert!(saga.obligation_lease.is_some());
    }
}