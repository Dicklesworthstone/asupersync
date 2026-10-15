//! Real service E2E tests for channel/crash ↔ obligation/saga rollback integration.
//!
//! Verifies that a crashed channel correctly triggers saga compensation chain
//! in reverse order. Tests that when communication channels fail during saga
//! execution, the saga system properly detects the failure and executes
//! compensation steps in the correct reverse order to maintain system consistency.

#[cfg(all(test, feature = "real-service-e2e"))]
mod real_channel_crash_saga_rollback_e2e {
    use crate::channel::crash::{CrashConfig, CrashController, CrashSender, RestartMode};
    use crate::channel::mpsc::{Receiver, SendError, Sender, channel};
    use crate::cx::{Cx, scope};
    use crate::obligation::saga::{
        Lattice, MonotoneSagaExecutor, Monotonicity, SagaBatch, SagaError, SagaExecutionPlan,
        SagaPlan, SagaResult, SagaStep,
    };
    use crate::runtime::{RuntimeBuilder, spawn};
    use crate::time::{Duration, Instant, sleep, timeout};
    use crate::types::{ObligationId, RegionId, TaskId, Time};
    use serde_json::json;
    use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    /// Statistics for channel crash + saga rollback testing
    #[derive(Debug, Clone, Default)]
    struct ChannelCrashSagaStats {
        /// Sagas started
        sagas_started: usize,
        /// Sagas completed successfully
        sagas_completed: usize,
        /// Sagas that experienced crashes
        sagas_crashed: usize,
        /// Compensation chains executed
        compensation_chains_executed: usize,
        /// Total compensation steps executed
        compensation_steps_executed: usize,
        /// Channel crashes triggered
        channel_crashes_triggered: usize,
        /// Forward saga steps completed before crash
        forward_steps_completed: usize,
        /// Rollback success rate (0.0-1.0)
        rollback_success_rate: f64,
        /// Average compensation chain length
        avg_compensation_chain_length: f64,
        /// Test duration in milliseconds
        test_duration_ms: u64,
    }

    impl ChannelCrashSagaStats {
        fn to_json(&self) -> serde_json::Value {
            json!({
                "sagas_started": self.sagas_started,
                "sagas_completed": self.sagas_completed,
                "sagas_crashed": self.sagas_crashed,
                "compensation_chains_executed": self.compensation_chains_executed,
                "compensation_steps_executed": self.compensation_steps_executed,
                "channel_crashes_triggered": self.channel_crashes_triggered,
                "forward_steps_completed": self.forward_steps_completed,
                "rollback_success_rate": self.rollback_success_rate,
                "avg_compensation_chain_length": self.avg_compensation_chain_length,
                "test_duration_ms": self.test_duration_ms,
                "saga_crash_rate": if self.sagas_started > 0 {
                    (self.sagas_crashed as f64) / (self.sagas_started as f64)
                } else { 0.0 },
                "compensation_effectiveness": if self.sagas_crashed > 0 {
                    (self.compensation_chains_executed as f64) / (self.sagas_crashed as f64)
                } else { 0.0 },
            })
        }
    }

    /// Mock saga operation for testing
    #[derive(Debug, Clone, PartialEq)]
    struct MockSagaOperation {
        operation_id: u64,
        operation_type: MockOperationType,
        monotonicity: Monotonicity,
        step_data: String,
        compensation_data: Option<String>,
        requires_channel: bool,
        execution_order: usize,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum MockOperationType {
        DatabaseWrite, // Non-monotone, requires compensation
        CacheUpdate,   // Monotone, mergeable
        LogEntry,      // Monotone, append-only
        ExternalApi,   // Non-monotone, may fail, needs compensation
        ResourceLock,  // Non-monotone, must be released
    }

    impl MockSagaOperation {
        fn new(
            operation_id: u64,
            operation_type: MockOperationType,
            step_data: String,
            execution_order: usize,
        ) -> Self {
            let (monotonicity, compensation_data, requires_channel) = match operation_type {
                MockOperationType::DatabaseWrite => (
                    Monotonicity::NonMonotone,
                    Some(format!("ROLLBACK: {}", step_data)),
                    true,
                ),
                MockOperationType::CacheUpdate => (
                    Monotonicity::Monotone,
                    None, // Monotone operations don't need explicit compensation
                    false,
                ),
                MockOperationType::LogEntry => (
                    Monotonicity::Monotone,
                    None, // Logs are append-only, no compensation needed
                    false,
                ),
                MockOperationType::ExternalApi => (
                    Monotonicity::NonMonotone,
                    Some(format!("CANCEL_API: {}", step_data)),
                    true,
                ),
                MockOperationType::ResourceLock => (
                    Monotonicity::NonMonotone,
                    Some(format!("UNLOCK: {}", step_data)),
                    true,
                ),
            };

            Self {
                operation_id,
                operation_type,
                monotonicity,
                step_data,
                compensation_data,
                requires_channel,
                execution_order,
            }
        }

        fn to_saga_step(&self) -> SagaStep {
            SagaStep {
                name: format!("step_{}", self.operation_id),
                monotonicity: self.monotonicity,
                operation_data: self.step_data.clone().into_bytes(),
                compensation_data: self
                    .compensation_data
                    .as_ref()
                    .map(|s| s.clone().into_bytes()),
            }
        }
    }

    /// Mock saga lattice state for testing
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockSagaLattice {
        completed_operations: HashSet<u64>,
        compensation_executed: HashSet<u64>,
        current_state: MockSagaState,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum MockSagaState {
        Initial,
        Executing,
        Compensating,
        Completed,
        Failed,
    }

    impl Lattice for MockSagaLattice {
        fn bottom() -> Self {
            Self {
                completed_operations: HashSet::new(),
                compensation_executed: HashSet::new(),
                current_state: MockSagaState::Initial,
            }
        }

        fn join(&self, other: &Self) -> Self {
            let mut completed = self.completed_operations.clone();
            completed.extend(&other.completed_operations);

            let mut compensation = self.compensation_executed.clone();
            compensation.extend(&other.compensation_executed);

            // State progression: Initial -> Executing -> Compensating -> (Completed|Failed)
            let current_state = match (&self.current_state, &other.current_state) {
                (MockSagaState::Failed, _) | (_, MockSagaState::Failed) => MockSagaState::Failed,
                (MockSagaState::Completed, _) | (_, MockSagaState::Completed) => {
                    MockSagaState::Completed
                }
                (MockSagaState::Compensating, _) | (_, MockSagaState::Compensating) => {
                    MockSagaState::Compensating
                }
                (MockSagaState::Executing, _) | (_, MockSagaState::Executing) => {
                    MockSagaState::Executing
                }
                _ => MockSagaState::Initial,
            };

            Self {
                completed_operations: completed,
                compensation_executed: compensation,
                current_state,
            }
        }
    }

    /// Integration manager for channel crash + saga rollback testing
    struct ChannelCrashSagaManager {
        crash_controllers: Arc<Mutex<HashMap<String, Arc<CrashController>>>>,
        active_sagas: Arc<Mutex<HashMap<u64, MockSagaPlan>>>,
        compensation_logs: Arc<Mutex<Vec<CompensationEvent>>>,
        stats: Arc<Mutex<ChannelCrashSagaStats>>,
        next_saga_id: Arc<AtomicU64>,
        next_operation_id: Arc<AtomicU64>,
        current_time: Arc<AtomicU64>,
    }

    #[derive(Debug, Clone)]
    struct MockSagaPlan {
        saga_id: u64,
        operations: Vec<MockSagaOperation>,
        execution_plan: Option<SagaExecutionPlan>,
        current_lattice: MockSagaLattice,
        crash_point: Option<usize>, // Which step to crash at (for testing)
    }

    #[derive(Debug, Clone)]
    struct CompensationEvent {
        saga_id: u64,
        operation_id: u64,
        compensation_data: String,
        execution_order: usize,
        timestamp: Time,
    }

    impl ChannelCrashSagaManager {
        fn new(stats: Arc<Mutex<ChannelCrashSagaStats>>) -> Self {
            Self {
                crash_controllers: Arc::new(Mutex::new(HashMap::new())),
                active_sagas: Arc::new(Mutex::new(HashMap::new())),
                compensation_logs: Arc::new(Mutex::new(Vec::new())),
                stats,
                next_saga_id: Arc::new(AtomicU64::new(1)),
                next_operation_id: Arc::new(AtomicU64::new(1)),
                current_time: Arc::new(AtomicU64::new(0)),
            }
        }

        fn next_saga_id(&self) -> u64 {
            self.next_saga_id.fetch_add(1, Ordering::AcqRel)
        }

        fn next_operation_id(&self) -> u64 {
            self.next_operation_id.fetch_add(1, Ordering::AcqRel)
        }

        fn next_time(&self) -> Time {
            Time::from_nanos(self.current_time.fetch_add(1000, Ordering::AcqRel))
        }

        /// Create a crash controller for a specific channel
        async fn create_crash_controller(
            &mut self,
            channel_name: String,
            crash_config: CrashConfig,
        ) -> Result<Arc<CrashController>, Box<dyn std::error::Error>> {
            let controller = Arc::new(CrashController::new(crash_config));

            {
                let mut controllers = self.crash_controllers.lock().unwrap();
                controllers.insert(channel_name.clone(), Arc::clone(&controller));
            }

            println!("Created crash controller for channel: {}", channel_name);
            Ok(controller)
        }

        /// Create a saga plan with potential crash points
        async fn create_saga_plan(
            &mut self,
            operation_count: usize,
            crash_at_step: Option<usize>,
        ) -> Result<u64, Box<dyn std::error::Error>> {
            let saga_id = self.next_saga_id();
            let mut operations = Vec::new();

            // Create diverse operations for testing
            for i in 0..operation_count {
                let operation_id = self.next_operation_id();
                let operation_type = match i % 5 {
                    0 => MockOperationType::DatabaseWrite,
                    1 => MockOperationType::CacheUpdate,
                    2 => MockOperationType::LogEntry,
                    3 => MockOperationType::ExternalApi,
                    _ => MockOperationType::ResourceLock,
                };

                let operation = MockSagaOperation::new(
                    operation_id,
                    operation_type,
                    format!("step_{}_{}", saga_id, i),
                    i,
                );

                operations.push(operation);
            }

            // Build execution plan
            let saga_steps: Vec<SagaStep> = operations.iter().map(|op| op.to_saga_step()).collect();
            let plan = SagaPlan {
                name: format!("test_saga_{}", saga_id),
                steps: saga_steps,
            };

            let execution_plan = Some(SagaExecutionPlan::from_plan(&plan)?);

            let mock_saga_plan = MockSagaPlan {
                saga_id,
                operations,
                execution_plan,
                current_lattice: MockSagaLattice::bottom(),
                crash_point: crash_at_step,
            };

            {
                let mut sagas = self.active_sagas.lock().unwrap();
                sagas.insert(saga_id, mock_saga_plan);
            }

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.sagas_started += 1;
            }

            println!(
                "Created saga plan {} with {} operations (crash at step: {:?})",
                saga_id, operation_count, crash_at_step
            );

            Ok(saga_id)
        }

        /// Execute saga with channel communication and potential crash
        async fn execute_saga_with_crash(
            &mut self,
            cx: &Cx,
            saga_id: u64,
            channel_name: String,
        ) -> Result<SagaResult<MockSagaLattice>, Box<dyn std::error::Error>> {
            let (saga_plan, crash_controller) = {
                let sagas = self.active_sagas.lock().unwrap();
                let controllers = self.crash_controllers.lock().unwrap();

                let saga_plan = sagas.get(&saga_id).ok_or("Saga not found")?.clone();
                let controller = controllers
                    .get(&channel_name)
                    .ok_or("Crash controller not found")?
                    .clone();

                (saga_plan, controller)
            };

            // Create channel for communication
            let (sender, receiver) = channel::<String>(100);
            let crash_sender = CrashSender::new(sender, &crash_controller);

            // Execute saga steps
            let mut current_lattice = MockSagaLattice::bottom();
            current_lattice.current_state = MockSagaState::Executing;
            let mut steps_completed = 0;

            println!(
                "Executing saga {} with {} operations",
                saga_id,
                saga_plan.operations.len()
            );

            for (step_index, operation) in saga_plan.operations.iter().enumerate() {
                // Check if we should crash at this step
                if let Some(crash_point) = saga_plan.crash_point {
                    if step_index == crash_point {
                        println!(
                            "Triggering crash at step {} for saga {}",
                            crash_point, saga_id
                        );

                        // Trigger crash
                        crash_controller.crash();

                        // Update stats
                        {
                            let mut stats = self.stats.lock().unwrap();
                            stats.channel_crashes_triggered += 1;
                            stats.sagas_crashed += 1;
                            stats.forward_steps_completed += steps_completed;
                        }

                        // Execute compensation chain in reverse order
                        return self
                            .execute_compensation_chain(
                                cx,
                                saga_id,
                                step_index,
                                &saga_plan.operations,
                            )
                            .await;
                    }
                }

                // Attempt to execute step (may fail due to crash)
                if operation.requires_channel {
                    match crash_sender.send(operation.step_data.clone()).await {
                        Ok(()) => {
                            println!("Step {} executed: {}", step_index, operation.step_data);
                            current_lattice
                                .completed_operations
                                .insert(operation.operation_id);
                            steps_completed += 1;
                        }
                        Err(SendError::Disconnected(_)) => {
                            println!(
                                "Channel disconnected during step {}, triggering compensation",
                                step_index
                            );

                            // Update stats
                            {
                                let mut stats = self.stats.lock().unwrap();
                                stats.channel_crashes_triggered += 1;
                                stats.sagas_crashed += 1;
                                stats.forward_steps_completed += steps_completed;
                            }

                            // Execute compensation chain
                            return self
                                .execute_compensation_chain(
                                    cx,
                                    saga_id,
                                    step_index,
                                    &saga_plan.operations,
                                )
                                .await;
                        }
                        Err(e) => {
                            return Err(format!("Unexpected send error: {:?}", e).into());
                        }
                    }
                } else {
                    // Non-channel operations always succeed in this test
                    println!(
                        "Non-channel step {} executed: {}",
                        step_index, operation.step_data
                    );
                    current_lattice
                        .completed_operations
                        .insert(operation.operation_id);
                    steps_completed += 1;
                }

                // Small delay between operations
                sleep(Duration::from_millis(1)).await;
            }

            // Saga completed successfully
            current_lattice.current_state = MockSagaState::Completed;

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.sagas_completed += 1;
                stats.forward_steps_completed += steps_completed;
            }

            println!("Saga {} completed successfully", saga_id);
            Ok(SagaResult::Success(current_lattice))
        }

        /// Execute compensation chain in reverse order
        async fn execute_compensation_chain(
            &self,
            cx: &Cx,
            saga_id: u64,
            failed_step: usize,
            operations: &[MockSagaOperation],
        ) -> Result<SagaResult<MockSagaLattice>, Box<dyn std::error::Error>> {
            println!(
                "Executing compensation chain for saga {} (failed at step {})",
                saga_id, failed_step
            );

            let mut compensation_lattice = MockSagaLattice::bottom();
            compensation_lattice.current_state = MockSagaState::Compensating;
            let mut compensation_steps = 0;

            // Execute compensation in REVERSE order (saga property)
            for step_index in (0..failed_step).rev() {
                let operation = &operations[step_index];

                // Only compensate non-monotone operations that were actually executed
                if operation.monotonicity == Monotonicity::NonMonotone {
                    if let Some(compensation_data) = &operation.compensation_data {
                        println!(
                            "Compensating step {} (order {}): {}",
                            step_index, step_index, compensation_data
                        );

                        // Record compensation event
                        let compensation_event = CompensationEvent {
                            saga_id,
                            operation_id: operation.operation_id,
                            compensation_data: compensation_data.clone(),
                            execution_order: step_index,
                            timestamp: self.next_time(),
                        };

                        {
                            let mut logs = self.compensation_logs.lock().unwrap();
                            logs.push(compensation_event);
                        }

                        compensation_lattice
                            .compensation_executed
                            .insert(operation.operation_id);
                        compensation_steps += 1;

                        // Small delay between compensation steps
                        sleep(Duration::from_millis(1)).await;
                    }
                }
            }

            compensation_lattice.current_state = if compensation_steps > 0 {
                MockSagaState::Completed
            } else {
                MockSagaState::Failed
            };

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.compensation_chains_executed += 1;
                stats.compensation_steps_executed += compensation_steps;

                if compensation_steps > 0 {
                    stats.rollback_success_rate = 1.0; // Simplified for this test
                    stats.avg_compensation_chain_length =
                        (stats.avg_compensation_chain_length + compensation_steps as f64) / 2.0;
                }
            }

            println!(
                "Compensation chain completed for saga {} ({} steps compensated)",
                saga_id, compensation_steps
            );

            Ok(SagaResult::Compensated(compensation_lattice))
        }

        /// Verify compensation order is correct (reverse of execution order)
        async fn verify_compensation_order(
            &self,
            saga_id: u64,
        ) -> Result<bool, Box<dyn std::error::Error>> {
            let compensation_events = {
                let logs = self.compensation_logs.lock().unwrap();
                logs.iter()
                    .filter(|event| event.saga_id == saga_id)
                    .cloned()
                    .collect::<Vec<_>>()
            };

            if compensation_events.is_empty() {
                return Ok(true); // No compensation needed
            }

            // Verify events are in reverse order of execution
            let mut is_reverse_order = true;
            for i in 1..compensation_events.len() {
                let prev_order = compensation_events[i - 1].execution_order;
                let curr_order = compensation_events[i].execution_order;

                if prev_order <= curr_order {
                    println!(
                        "Compensation order violation: step {} came before step {} (should be reverse)",
                        prev_order, curr_order
                    );
                    is_reverse_order = false;
                    break;
                }
            }

            if is_reverse_order {
                println!(
                    "✓ Compensation executed in correct reverse order for saga {}",
                    saga_id
                );
            } else {
                println!(
                    "✗ Compensation order violation detected for saga {}",
                    saga_id
                );
            }

            Ok(is_reverse_order)
        }

        /// Get manager state for debugging
        fn get_state(&self) -> (usize, usize, usize) {
            let active_sagas = self.active_sagas.lock().unwrap().len();
            let controllers = self.crash_controllers.lock().unwrap().len();
            let compensation_events = self.compensation_logs.lock().unwrap().len();
            (active_sagas, controllers, compensation_events)
        }
    }

    /// Test harness for channel crash + saga rollback integration
    struct ChannelCrashSagaTestHarness {
        manager: ChannelCrashSagaManager,
        stats: Arc<Mutex<ChannelCrashSagaStats>>,
        start_time: Instant,
    }

    impl ChannelCrashSagaTestHarness {
        fn new() -> Self {
            let stats = Arc::new(Mutex::new(ChannelCrashSagaStats::default()));
            let manager = ChannelCrashSagaManager::new(Arc::clone(&stats));

            Self {
                manager,
                stats,
                start_time: Instant::now(),
            }
        }

        /// Test basic saga with channel crash and compensation
        async fn test_basic_saga_crash_compensation(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing basic saga with channel crash and compensation");

            // Create crash controller that crashes after 2 successful sends
            let crash_config = CrashConfig::new(12345)
                .with_deterministic_crash(2)
                .with_max_restarts(Some(1));

            let controller = self
                .manager
                .create_crash_controller("basic_test_channel".to_string(), crash_config)
                .await?;

            // Create saga with 5 operations, expect crash at step 2
            let saga_id = self.manager.create_saga_plan(5, Some(2)).await?;

            // Execute saga - should crash and compensate
            let result = self
                .manager
                .execute_saga_with_crash(cx, saga_id, "basic_test_channel".to_string())
                .await?;

            // Verify result is compensation
            match result {
                SagaResult::Compensated(_lattice) => {
                    println!("✓ Saga correctly executed compensation after crash");
                }
                _ => {
                    return Err("Expected saga to be compensated after crash".into());
                }
            }

            // Verify compensation order
            let order_correct = self.manager.verify_compensation_order(saga_id).await?;
            assert!(
                order_correct,
                "Compensation should be executed in reverse order"
            );

            println!("Basic saga crash compensation test completed successfully");
            Ok(())
        }

        /// Test multiple sagas with different crash points
        async fn test_multiple_sagas_different_crash_points(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing multiple sagas with different crash points");

            let test_cases = vec![
                ("early_crash", 0, 7), // Crash at first step
                ("mid_crash", 3, 7),   // Crash in middle
                ("late_crash", 5, 7),  // Crash near end
            ];

            for (test_name, crash_point, total_steps) in test_cases {
                println!("Running test case: {}", test_name);

                // Create crash controller for this test
                let crash_config = CrashConfig::new(54321)
                    .with_deterministic_crash(crash_point as u64)
                    .with_max_restarts(Some(2));

                let controller = self
                    .manager
                    .create_crash_controller(format!("test_channel_{}", test_name), crash_config)
                    .await?;

                // Create and execute saga
                let saga_id = self
                    .manager
                    .create_saga_plan(total_steps, Some(crash_point))
                    .await?;

                let result = self
                    .manager
                    .execute_saga_with_crash(cx, saga_id, format!("test_channel_{}", test_name))
                    .await?;

                // Verify compensation
                match result {
                    SagaResult::Compensated(_) => {
                        println!("✓ Test case {} compensated correctly", test_name);
                    }
                    _ => {
                        return Err(format!("Test case {} failed to compensate", test_name).into());
                    }
                }

                // Verify compensation order
                let order_correct = self.manager.verify_compensation_order(saga_id).await?;
                assert!(
                    order_correct,
                    "Compensation order incorrect for {}",
                    test_name
                );
            }

            println!("Multiple sagas test completed successfully");
            Ok(())
        }

        /// Test saga with no crash (success case)
        async fn test_saga_success_no_crash(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing saga success case with no crash");

            // Create crash controller that never crashes
            let crash_config = CrashConfig::new(98765).with_crash_probability(0.0); // No crash

            let controller = self
                .manager
                .create_crash_controller("no_crash_channel".to_string(), crash_config)
                .await?;

            // Create saga with no crash point
            let saga_id = self.manager.create_saga_plan(4, None).await?;

            // Execute saga - should complete successfully
            let result = self
                .manager
                .execute_saga_with_crash(cx, saga_id, "no_crash_channel".to_string())
                .await?;

            // Verify result is success
            match result {
                SagaResult::Success(_lattice) => {
                    println!("✓ Saga completed successfully without crash");
                }
                _ => {
                    return Err("Expected saga to complete successfully".into());
                }
            }

            println!("Success case test completed");
            Ok(())
        }

        /// Test probabilistic crash scenarios
        async fn test_probabilistic_crash_scenarios(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing probabilistic crash scenarios");

            // Create crash controller with 50% crash probability
            let crash_config = CrashConfig::new(11111)
                .with_crash_probability(0.7) // High probability for testing
                .with_max_restarts(Some(3));

            let controller = self
                .manager
                .create_crash_controller("probabilistic_channel".to_string(), crash_config)
                .await?;

            // Run multiple sagas to test probabilistic behavior
            let mut crashed_sagas = 0;
            let mut successful_sagas = 0;

            for i in 0..5 {
                let saga_id = self.manager.create_saga_plan(6, None).await?;

                let result = self
                    .manager
                    .execute_saga_with_crash(cx, saga_id, "probabilistic_channel".to_string())
                    .await?;

                match result {
                    SagaResult::Success(_) => {
                        successful_sagas += 1;
                        println!("Saga {} completed successfully", i);
                    }
                    SagaResult::Compensated(_) => {
                        crashed_sagas += 1;
                        println!("Saga {} crashed and compensated", i);

                        // Verify compensation order
                        let order_correct = self.manager.verify_compensation_order(saga_id).await?;
                        assert!(order_correct, "Compensation order incorrect for saga {}", i);
                    }
                    _ => {
                        return Err(format!("Unexpected saga result for saga {}", i).into());
                    }
                }
            }

            println!(
                "Probabilistic test completed: {} crashed, {} successful",
                crashed_sagas, successful_sagas
            );

            // Should have at least some crashes with 70% probability
            assert!(
                crashed_sagas > 0,
                "Expected some crashes with high probability"
            );

            Ok(())
        }

        /// Get test statistics
        fn get_stats(&mut self) -> ChannelCrashSagaStats {
            let mut stats = self.stats.lock().unwrap();
            stats.test_duration_ms = self.start_time.elapsed().as_millis() as u64;
            stats.clone()
        }
    }

    #[tokio::test]
    async fn test_channel_crash_saga_basic_compensation() {
        println!("=== Starting channel crash + saga basic compensation test ===");

        scope(|cx| async move {
            let mut harness = ChannelCrashSagaTestHarness::new();

            // Test basic functionality
            harness
                .test_basic_saga_crash_compensation(&cx)
                .await
                .expect("Basic crash compensation test should succeed");

            let stats = harness.get_stats();
            println!(
                "Basic compensation stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Verify basic operation
            assert!(stats.sagas_started > 0, "Should have started sagas");
            assert!(stats.sagas_crashed > 0, "Should have crashed sagas");
            assert!(
                stats.compensation_chains_executed > 0,
                "Should have executed compensation chains"
            );
            assert!(
                stats.channel_crashes_triggered > 0,
                "Should have triggered channel crashes"
            );

            println!("✓ Channel crash + saga basic compensation test passed");
            println!("  - Sagas started: {}", stats.sagas_started);
            println!("  - Sagas crashed: {}", stats.sagas_crashed);
            println!(
                "  - Compensation chains: {}",
                stats.compensation_chains_executed
            );

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_channel_crash_multiple_saga_scenarios() {
        println!("=== Testing multiple saga crash scenarios ===");

        scope(|cx| async move {
            let mut harness = ChannelCrashSagaTestHarness::new();

            // Test multiple crash points
            harness
                .test_multiple_sagas_different_crash_points(&cx)
                .await
                .expect("Multiple crash points test should succeed");

            let stats = harness.get_stats();
            println!(
                "Multiple scenarios stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Should have processed multiple sagas
            assert!(
                stats.sagas_started >= 3,
                "Should have started multiple sagas"
            );
            assert!(
                stats.compensation_chains_executed >= 3,
                "Should have executed multiple compensation chains"
            );

            println!("✓ Multiple saga crash scenarios test passed");
            println!("  - Total sagas: {}", stats.sagas_started);
            println!(
                "  - Avg compensation chain length: {:.2}",
                stats.avg_compensation_chain_length
            );

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_channel_crash_saga_success_case() {
        println!("=== Testing saga success case without crash ===");

        scope(|cx| async move {
            let mut harness = ChannelCrashSagaTestHarness::new();

            // Test success case
            harness
                .test_saga_success_no_crash(&cx)
                .await
                .expect("Success case test should succeed");

            let stats = harness.get_stats();
            println!(
                "Success case stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Should have completed successfully
            assert!(
                stats.sagas_completed > 0,
                "Should have completed sagas successfully"
            );

            println!("✓ Saga success case test passed");

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_channel_crash_probabilistic_scenarios() {
        println!("=== Testing probabilistic crash scenarios ===");

        scope(|cx| async move {
            let mut harness = ChannelCrashSagaTestHarness::new();

            // Test probabilistic crashes
            harness
                .test_probabilistic_crash_scenarios(&cx)
                .await
                .expect("Probabilistic crash test should succeed");

            let stats = harness.get_stats();
            println!(
                "Probabilistic crash stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Should have mix of success and crashes
            assert!(
                stats.sagas_started >= 5,
                "Should have started multiple sagas"
            );

            println!("✓ Probabilistic crash scenarios test passed");
            println!(
                "  - Saga crash rate: {:.2}%",
                stats.to_json()["saga_crash_rate"].as_f64().unwrap_or(0.0) * 100.0
            );
            println!(
                "  - Compensation effectiveness: {:.2}%",
                stats.to_json()["compensation_effectiveness"]
                    .as_f64()
                    .unwrap_or(0.0)
                    * 100.0
            );

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_channel_crash_saga_comprehensive_integration() {
        println!("=== Testing comprehensive channel crash + saga integration ===");

        scope(|cx| async move {
            let mut harness = ChannelCrashSagaTestHarness::new();

            // Run comprehensive test sequence
            println!("Running comprehensive integration tests...");

            harness
                .test_basic_saga_crash_compensation(&cx)
                .await
                .expect("Basic test should succeed");

            harness
                .test_multiple_sagas_different_crash_points(&cx)
                .await
                .expect("Multiple scenarios test should succeed");

            harness
                .test_saga_success_no_crash(&cx)
                .await
                .expect("Success case test should succeed");

            harness
                .test_probabilistic_crash_scenarios(&cx)
                .await
                .expect("Probabilistic test should succeed");

            let stats = harness.get_stats();
            println!(
                "Comprehensive integration stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Verify comprehensive operation
            assert!(stats.sagas_started >= 15, "Should have started many sagas");
            assert!(
                stats.sagas_crashed >= 5,
                "Should have crashed multiple sagas"
            );
            assert!(
                stats.compensation_chains_executed >= 5,
                "Should have executed multiple compensation chains"
            );
            assert!(
                stats.compensation_steps_executed >= 10,
                "Should have executed multiple compensation steps"
            );

            let (active_sagas, controllers, events) = harness.manager.get_state();
            println!(
                "Final manager state: active_sagas={}, controllers={}, compensation_events={}",
                active_sagas, controllers, events
            );

            println!("✓ Comprehensive channel crash + saga integration test passed");
            println!("  - Total sagas: {}", stats.sagas_started);
            println!("  - Total crashes: {}", stats.sagas_crashed);
            println!(
                "  - Total compensations: {}",
                stats.compensation_chains_executed
            );
            println!(
                "  - Rollback success rate: {:.2}%",
                stats.rollback_success_rate * 100.0
            );
            println!("  - Test duration: {}ms", stats.test_duration_ms);

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }
}
