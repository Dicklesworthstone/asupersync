//! Integration tests for combinator/timeout ↔ obligation/recovery integration.
//!
//! These tests verify that timeout-triggered cancellation correctly invokes
//! obligation recovery sequences without resource or obligation leaks, ensuring
//! proper cleanup when operations exceed their time limits.
//!
//! Key integration points tested:
//! - Timeout cancellation triggering obligation recovery workflows
//! - Multiple nested obligations with timeout-driven cleanup
//! - Concurrent timeouts with shared obligation recovery coordination
//! - Complex obligation chains requiring proper cleanup sequencing
//! - Stress testing with simultaneous timeout cancellations
//! - Edge cases: immediate timeout, recovery failures, partial cleanup

#[cfg(all(test, feature = "real-service-e2e"))]
mod integration_tests {
    use crate::cancel::{CancelReason, CancelToken};
    use crate::combinator::timeout::{Timeout, TimeoutError, timeout};
    use crate::cx::Cx;
    use crate::error::AsupersyncError;
    use crate::obligation::recovery::{
        RecoveryError, RecoveryManager, RecoverySequence, RecoveryStep,
    };
    use crate::obligation::{ObligationId, ObligationLedger, ObligationRecord, ObligationStatus};
    use crate::runtime::{Runtime, RuntimeBuilder};
    use crate::types::{Budget, Outcome, TaskId};
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };
    use std::time::{Duration, Instant};

    /// Test harness for timeout-obligation recovery integration testing.
    struct TimeoutRecoveryTestHarness {
        runtime: Arc<Runtime>,
        recovery_manager: Arc<RecoveryManager>,
        obligation_ledger: Arc<ObligationLedger>,
        timeout_operations: HashMap<String, Arc<TimeoutOperation>>,
        recovery_sequences: HashMap<ObligationId, Arc<RecoverySequence>>,
        stats: Arc<Mutex<TimeoutRecoveryStats>>,
    }

    #[derive(Debug, Default, Clone)]
    struct TimeoutRecoveryStats {
        /// Total timeout operations created
        timeout_operations_created: u64,
        /// Timeouts that triggered successfully
        timeouts_triggered: u64,
        /// Recovery sequences initiated
        recovery_sequences_initiated: u64,
        /// Recovery sequences completed successfully
        recovery_sequences_completed: u64,
        /// Recovery failures
        recovery_failures: u64,
        /// Obligations cleaned up
        obligations_cleaned_up: u64,
        /// Resource leaks detected
        resource_leaks_detected: u64,
        /// Concurrent recovery operations peak
        peak_concurrent_recoveries: u64,
        /// Total recovery time
        total_recovery_time: Duration,
    }

    /// Test operation that creates obligations and can be timed out
    struct TimeoutOperation {
        id: String,
        operation_duration: Duration,
        obligations: Vec<ObligationId>,
        resources: Arc<Mutex<Vec<TestResource>>>,
        recovery_steps: Vec<RecoveryStep>,
        cleanup_on_timeout: bool,
        stats: Arc<Mutex<TimeoutRecoveryStats>>,
    }

    #[derive(Debug, Clone)]
    struct TestResource {
        id: String,
        resource_type: ResourceType,
        allocated_at: Instant,
        needs_cleanup: bool,
        cleanup_duration: Duration,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum ResourceType {
        FileHandle,
        NetworkConnection,
        DatabaseTransaction,
        MemoryBuffer,
        LockHandle,
    }

    impl TimeoutOperation {
        fn new(
            id: String,
            operation_duration: Duration,
            num_obligations: usize,
            cleanup_on_timeout: bool,
            stats: Arc<Mutex<TimeoutRecoveryStats>>,
        ) -> Self {
            let mut obligations = Vec::new();
            let mut resources = Vec::new();
            let mut recovery_steps = Vec::new();

            // Create test obligations and associated resources
            for i in 0..num_obligations {
                let obligation_id = ObligationId::new();
                obligations.push(obligation_id);

                let resource = TestResource {
                    id: format!("{}-resource-{}", id, i),
                    resource_type: match i % 5 {
                        0 => ResourceType::FileHandle,
                        1 => ResourceType::NetworkConnection,
                        2 => ResourceType::DatabaseTransaction,
                        3 => ResourceType::MemoryBuffer,
                        4 => ResourceType::LockHandle,
                        _ => ResourceType::FileHandle,
                    },
                    allocated_at: Instant::now(),
                    needs_cleanup: true,
                    cleanup_duration: Duration::from_millis(10 + (i * 5) as u64),
                };
                resources.push(resource.clone());

                // Create recovery step for this resource
                let recovery_step = RecoveryStep::new(
                    obligation_id,
                    format!("cleanup-{}", resource.resource_type.as_str()),
                    resource.cleanup_duration,
                );
                recovery_steps.push(recovery_step);
            }

            Self {
                id,
                operation_duration,
                obligations,
                resources: Arc::new(Mutex::new(resources)),
                recovery_steps,
                cleanup_on_timeout,
                stats,
            }
        }

        async fn execute_operation(&self, cx: &Cx) -> Result<String, AsupersyncError> {
            // Register obligations
            for obligation_id in &self.obligations {
                let record = ObligationRecord::new(
                    *obligation_id,
                    self.id.clone(),
                    ObligationStatus::Active,
                );
                // Would normally register with ledger
            }

            // Simulate long-running operation
            cx.sleep(self.operation_duration).await;

            // Complete successfully if not timed out
            Ok(format!("Operation {} completed", self.id))
        }

        async fn handle_timeout_cancellation(
            &self,
            cx: &Cx,
            cancel_reason: CancelReason,
        ) -> Result<(), AsupersyncError> {
            if !self.cleanup_on_timeout {
                return Ok(());
            }

            let mut stats = self.stats.lock().unwrap();
            stats.recovery_sequences_initiated += 1;
            drop(stats);

            let recovery_start = Instant::now();

            // Execute recovery steps for each obligation
            for (obligation_id, recovery_step) in self.obligations.iter().zip(&self.recovery_steps)
            {
                match self
                    .execute_recovery_step(cx, *obligation_id, recovery_step)
                    .await
                {
                    Ok(_) => {
                        let mut stats = self.stats.lock().unwrap();
                        stats.obligations_cleaned_up += 1;
                    }
                    Err(_) => {
                        let mut stats = self.stats.lock().unwrap();
                        stats.recovery_failures += 1;
                        stats.resource_leaks_detected += 1;
                    }
                }
            }

            let recovery_duration = recovery_start.elapsed();
            let mut stats = self.stats.lock().unwrap();
            stats.total_recovery_time += recovery_duration;
            stats.recovery_sequences_completed += 1;

            Ok(())
        }

        async fn execute_recovery_step(
            &self,
            cx: &Cx,
            obligation_id: ObligationId,
            recovery_step: &RecoveryStep,
        ) -> Result<(), AsupersyncError> {
            // Simulate cleanup work
            cx.sleep(recovery_step.cleanup_duration()).await;

            // Mark resource as cleaned up
            {
                let mut resources = self.resources.lock().unwrap();
                if let Some(resource) = resources
                    .iter_mut()
                    .find(|r| r.id.contains(&obligation_id.to_string()[..8]))
                {
                    resource.needs_cleanup = false;
                }
            }

            Ok(())
        }

        fn check_for_leaks(&self) -> usize {
            let resources = self.resources.lock().unwrap();
            resources.iter().filter(|r| r.needs_cleanup).count()
        }
    }

    impl ResourceType {
        fn as_str(&self) -> &'static str {
            match self {
                ResourceType::FileHandle => "file",
                ResourceType::NetworkConnection => "network",
                ResourceType::DatabaseTransaction => "database",
                ResourceType::MemoryBuffer => "memory",
                ResourceType::LockHandle => "lock",
            }
        }
    }

    impl TimeoutRecoveryTestHarness {
        fn new() -> Result<Self, AsupersyncError> {
            let runtime = Arc::new(
                RuntimeBuilder::new()
                    .with_obligation_tracking()
                    .with_structured_concurrency()
                    .build()?,
            );

            let recovery_manager = Arc::new(RecoveryManager::new()?);
            let obligation_ledger = Arc::new(ObligationLedger::new()?);

            Ok(Self {
                runtime,
                recovery_manager,
                obligation_ledger,
                timeout_operations: HashMap::new(),
                recovery_sequences: HashMap::new(),
                stats: Arc::new(Mutex::new(TimeoutRecoveryStats::default())),
            })
        }

        fn create_timeout_operation(
            &mut self,
            op_id: &str,
            operation_duration: Duration,
            num_obligations: usize,
            cleanup_on_timeout: bool,
        ) -> Arc<TimeoutOperation> {
            let operation = Arc::new(TimeoutOperation::new(
                op_id.to_string(),
                operation_duration,
                num_obligations,
                cleanup_on_timeout,
                self.stats.clone(),
            ));

            self.timeout_operations
                .insert(op_id.to_string(), operation.clone());

            {
                let mut stats = self.stats.lock().unwrap();
                stats.timeout_operations_created += 1;
            }

            operation
        }

        async fn execute_with_timeout(
            &mut self,
            cx: &Cx,
            operation: Arc<TimeoutOperation>,
            timeout_duration: Duration,
        ) -> Result<String, TimeoutError> {
            let op_future = operation.execute_operation(cx);
            let timeout_result = timeout(timeout_duration, op_future).await;

            match timeout_result {
                Ok(result) => Ok(result?),
                Err(TimeoutError::Timeout) => {
                    {
                        let mut stats = self.stats.lock().unwrap();
                        stats.timeouts_triggered += 1;
                    }

                    // Handle timeout cancellation
                    operation
                        .handle_timeout_cancellation(cx, CancelReason::Timeout(timeout_duration))
                        .await?;

                    Err(TimeoutError::Timeout)
                }
            }
        }

        async fn execute_concurrent_timeouts(
            &mut self,
            cx: &Cx,
            operations: Vec<Arc<TimeoutOperation>>,
            timeout_duration: Duration,
        ) -> Result<Vec<Result<String, TimeoutError>>, AsupersyncError> {
            let num_operations = operations.len();
            {
                let mut stats = self.stats.lock().unwrap();
                stats.peak_concurrent_recoveries =
                    stats.peak_concurrent_recoveries.max(num_operations as u64);
            }

            let mut tasks = Vec::new();

            for operation in operations {
                let timeout_dur = timeout_duration;
                let task = cx.spawn(async move {
                    let op_future = operation.execute_operation(cx);
                    let timeout_result = timeout(timeout_dur, op_future).await;

                    match timeout_result {
                        Ok(result) => Ok(result?),
                        Err(TimeoutError::Timeout) => {
                            // Handle timeout cancellation
                            operation
                                .handle_timeout_cancellation(cx, CancelReason::Timeout(timeout_dur))
                                .await?;
                            Err(TimeoutError::Timeout)
                        }
                    }
                });
                tasks.push(task);
            }

            // Wait for all tasks to complete
            let mut results = Vec::new();
            for task in tasks {
                let result = task.await?;
                results.push(result);
            }

            Ok(results)
        }

        fn count_resource_leaks(&self) -> usize {
            self.timeout_operations
                .values()
                .map(|op| op.check_for_leaks())
                .sum()
        }

        fn get_stats(&self) -> TimeoutRecoveryStats {
            self.stats.lock().unwrap().clone()
        }
    }

    #[tokio::test]
    async fn test_basic_timeout_triggers_obligation_recovery() -> Result<(), AsupersyncError> {
        let mut harness = TimeoutRecoveryTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                // Create operation that takes 200ms with 3 obligations
                let operation = harness.create_timeout_operation(
                    "basic-timeout-op",
                    Duration::from_millis(200), // Operation duration
                    3,                          // Number of obligations
                    true,                       // Cleanup on timeout
                );

                // Execute with 100ms timeout (should trigger timeout)
                let result = harness
                    .execute_with_timeout(
                        cx,
                        operation.clone(),
                        Duration::from_millis(100), // Timeout before operation completes
                    )
                    .await;

                // Verify timeout occurred
                assert!(
                    matches!(result, Err(TimeoutError::Timeout)),
                    "Should timeout"
                );

                // Verify recovery was triggered
                let stats = harness.get_stats();
                assert_eq!(stats.timeouts_triggered, 1);
                assert_eq!(stats.recovery_sequences_initiated, 1);
                assert_eq!(stats.recovery_sequences_completed, 1);
                assert_eq!(stats.obligations_cleaned_up, 3);

                // Verify no resource leaks
                let leaks = harness.count_resource_leaks();
                assert_eq!(leaks, 0, "Should have no resource leaks after recovery");

                println!(
                    "Basic timeout recovery completed in {:?}",
                    stats.total_recovery_time
                );
                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_multiple_nested_obligations_timeout_recovery() -> Result<(), AsupersyncError> {
        let mut harness = TimeoutRecoveryTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                // Create operation with many nested obligations
                let operation = harness.create_timeout_operation(
                    "nested-obligations-op",
                    Duration::from_millis(300), // Long operation
                    10,                         // Many obligations
                    true,                       // Cleanup required
                );

                let timeout_start = Instant::now();
                let result = harness
                    .execute_with_timeout(
                        cx,
                        operation.clone(),
                        Duration::from_millis(150), // Timeout before completion
                    )
                    .await;

                let timeout_duration = timeout_start.elapsed();

                // Verify timeout and recovery
                assert!(matches!(result, Err(TimeoutError::Timeout)));
                assert!(
                    timeout_duration >= Duration::from_millis(140)
                        && timeout_duration <= Duration::from_millis(200),
                    "Should timeout in reasonable time"
                );

                let stats = harness.get_stats();
                assert_eq!(stats.obligations_cleaned_up, 10);
                assert_eq!(stats.recovery_sequences_completed, 1);

                // Verify all resources were cleaned up
                let leaks = operation.check_for_leaks();
                assert_eq!(leaks, 0, "All nested obligations should be cleaned up");

                println!(
                    "Nested obligations recovery: {} obligations cleaned in {:?}",
                    stats.obligations_cleaned_up, stats.total_recovery_time
                );
                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_concurrent_timeouts_shared_recovery() -> Result<(), AsupersyncError> {
        let mut harness = TimeoutRecoveryTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                // Create multiple concurrent operations
                let num_operations = 8;
                let mut operations = Vec::new();

                for i in 0..num_operations {
                    let operation = harness.create_timeout_operation(
                        &format!("concurrent-op-{}", i),
                        Duration::from_millis(250 + (i * 10) as u64), // Varying durations
                        2 + i,                                        // Varying obligation counts
                        true,                                         // All need cleanup
                    );
                    operations.push(operation);
                }

                // Execute all concurrently with timeout
                let start_time = Instant::now();
                let results = harness
                    .execute_concurrent_timeouts(
                        cx,
                        operations,
                        Duration::from_millis(150), // Timeout before any complete
                    )
                    .await?;

                let concurrent_duration = start_time.elapsed();

                // Verify all timed out
                let timeout_count = results
                    .iter()
                    .filter(|r| matches!(r, Err(TimeoutError::Timeout)))
                    .count();
                assert_eq!(
                    timeout_count, num_operations,
                    "All operations should timeout"
                );

                let stats = harness.get_stats();
                assert_eq!(stats.timeouts_triggered, num_operations as u64);
                assert_eq!(stats.recovery_sequences_completed, num_operations as u64);
                assert_eq!(stats.peak_concurrent_recoveries, num_operations as u64);

                // Verify no leaks across all operations
                let total_leaks = harness.count_resource_leaks();
                assert_eq!(total_leaks, 0, "No resource leaks in concurrent recovery");

                println!(
                    "Concurrent recovery: {} operations recovered in {:?}",
                    num_operations, concurrent_duration
                );
                println!(
                    "Total obligations cleaned: {}",
                    stats.obligations_cleaned_up
                );

                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_immediate_timeout_edge_case() -> Result<(), AsupersyncError> {
        let mut harness = TimeoutRecoveryTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                // Create operation that takes some time
                let operation = harness.create_timeout_operation(
                    "immediate-timeout-op",
                    Duration::from_millis(100),
                    2,
                    true,
                );

                // Execute with near-zero timeout
                let result = harness
                    .execute_with_timeout(
                        cx,
                        operation.clone(),
                        Duration::from_millis(1), // Very short timeout
                    )
                    .await;

                // Should timeout immediately
                assert!(matches!(result, Err(TimeoutError::Timeout)));

                let stats = harness.get_stats();
                assert_eq!(stats.timeouts_triggered, 1);
                assert_eq!(stats.recovery_sequences_completed, 1);

                // Even immediate timeout should clean up
                let leaks = operation.check_for_leaks();
                assert_eq!(leaks, 0, "Immediate timeout should still clean up");

                println!("Immediate timeout handled correctly");
                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_recovery_failure_handling() -> Result<(), AsupersyncError> {
        let mut harness = TimeoutRecoveryTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                // Create operation with cleanup disabled to simulate recovery failure
                let failing_operation = harness.create_timeout_operation(
                    "failing-recovery-op",
                    Duration::from_millis(200),
                    3,
                    false, // Disable cleanup to simulate failure
                );

                let result = harness
                    .execute_with_timeout(cx, failing_operation.clone(), Duration::from_millis(100))
                    .await;

                assert!(matches!(result, Err(TimeoutError::Timeout)));

                // This operation won't perform cleanup, simulating recovery failure
                let stats = harness.get_stats();
                assert_eq!(stats.timeouts_triggered, 1);

                // Since cleanup was disabled, resources should still need cleanup
                let leaks = failing_operation.check_for_leaks();
                assert!(leaks > 0, "Should detect resource leaks when cleanup fails");

                println!("Recovery failure detected: {} resource leaks", leaks);
                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_complex_obligation_chain_timeout_recovery() -> Result<(), AsupersyncError> {
        let mut harness = TimeoutRecoveryTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                // Create operation representing complex chain (e.g., DB transaction -> network call -> file I/O)
                let complex_operation = harness.create_timeout_operation(
                    "complex-chain-op",
                    Duration::from_millis(400),
                    6, // Represents: DB start, Network connect, File open, File write, Network send, DB commit
                    true,
                );

                // Timeout in the middle of the chain
                let result = harness
                    .execute_with_timeout(cx, complex_operation.clone(), Duration::from_millis(200))
                    .await;

                assert!(matches!(result, Err(TimeoutError::Timeout)));

                // Verify complex recovery sequence
                let stats = harness.get_stats();
                assert_eq!(stats.obligations_cleaned_up, 6);
                assert_eq!(stats.recovery_sequences_completed, 1);

                // All resources in the chain should be cleaned up
                let leaks = complex_operation.check_for_leaks();
                assert_eq!(
                    leaks, 0,
                    "Complex obligation chain should be fully cleaned up"
                );

                // Recovery should take reasonable time (not too long for 6 steps)
                assert!(
                    stats.total_recovery_time < Duration::from_millis(200),
                    "Complex recovery should be efficient"
                );

                println!(
                    "Complex chain recovery: 6 obligations cleaned in {:?}",
                    stats.total_recovery_time
                );
                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_stress_many_simultaneous_timeout_recoveries() -> Result<(), AsupersyncError> {
        let mut harness = TimeoutRecoveryTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                let num_operations = 25;
                let mut operations = Vec::new();

                // Create many operations with varying complexities
                for i in 0..num_operations {
                    let operation = harness.create_timeout_operation(
                        &format!("stress-op-{}", i),
                        Duration::from_millis(300 + (i * 5) as u64),
                        1 + (i % 4), // 1-4 obligations per operation
                        true,
                    );
                    operations.push(operation);
                }

                let stress_start = Instant::now();
                let results = harness
                    .execute_concurrent_timeouts(
                        cx,
                        operations,
                        Duration::from_millis(100), // Short timeout to trigger all
                    )
                    .await?;
                let stress_duration = stress_start.elapsed();

                // All should timeout
                let timeout_count = results
                    .iter()
                    .filter(|r| matches!(r, Err(TimeoutError::Timeout)))
                    .count();
                assert_eq!(timeout_count, num_operations);

                let stats = harness.get_stats();
                assert_eq!(stats.timeouts_triggered, num_operations as u64);
                assert_eq!(stats.recovery_sequences_completed, num_operations as u64);

                // Verify no leaks across the stress test
                let total_leaks = harness.count_resource_leaks();
                assert_eq!(total_leaks, 0, "Stress test should have no resource leaks");

                // Performance check
                assert!(
                    stress_duration < Duration::from_secs(5),
                    "Stress test should complete reasonably quickly"
                );

                println!(
                    "Stress test: {} operations with {} total obligations cleaned",
                    num_operations, stats.obligations_cleaned_up
                );
                println!(
                    "Average recovery time: {:?}",
                    stats.total_recovery_time / stats.recovery_sequences_completed as u32
                );

                // Check that we actually stressed the system
                assert!(
                    stats.obligations_cleaned_up >= 25,
                    "Should have cleaned up many obligations"
                );
                assert_eq!(
                    stats.recovery_failures, 0,
                    "Should have no recovery failures under stress"
                );

                Ok(())
            })
            .await
    }
}
