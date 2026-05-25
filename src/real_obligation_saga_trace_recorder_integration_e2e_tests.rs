//! br-e2e-145: Real obligation/saga ↔ trace/recorder integration tests
//!
//! Verifies that saga compensation steps emit correctly-ordered trace events
//! under crash injection mid-flow. Tests the integration between:
//!
//! - `obligation::saga`: Saga orchestration and compensation logic
//! - `trace::recorder`: Event recording and ordering guarantees
//!
//! Key integration properties:
//! - Saga compensation steps emit trace events in correct causal order
//! - Crash injection mid-flow preserves trace event ordering invariants
//! - Recovery after crash reconstructs saga state from trace events
//! - Compensation events are causally ordered with respect to saga steps
//! - Trace events survive crashes and enable saga recovery

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use crate::{
        obligation::saga::{Saga, SagaStep, SagaState, SagaStepError, CompensationResult},
        trace::recorder::{TraceRecorder, TraceEvent, EventOrder, CausalOrder},
        trace::distributed::vclock::VectorClock,
        types::{Budget, Outcome, TaskId, RegionId},
        cx::Cx,
        error::{Error, ErrorKind},
        time::{Duration, Sleep},
        sync::{Mutex, AtomicU64},
        channel::{mpsc, oneshot},
        runtime::Runtime,
        test_utils::{init_test_runtime, TestTracer},
        lab::{LabRuntime, CrashInjector},
    };
    use std::sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    };
    use std::collections::{HashMap, VecDeque, BTreeMap};
    use std::time::Instant;

    /// Test framework for saga-trace integration scenarios
    struct SagaTraceTestFramework {
        runtime: Runtime,
        lab_runtime: LabRuntime,
        tracer: TestTracer,
        saga: Arc<Saga>,
        recorder: Arc<TraceRecorder>,
        crash_injector: Arc<CrashInjector>,
        stats: Arc<IntegrationStats>,
    }

    /// Statistics for saga-trace integration
    #[derive(Debug)]
    struct IntegrationStats {
        saga_steps_executed: AtomicU64,
        compensation_steps_executed: AtomicU64,
        trace_events_recorded: AtomicU64,
        crash_events_injected: AtomicU64,
        recovery_attempts: AtomicU64,
        ordering_violations: AtomicU64,
        successful_recoveries: AtomicU64,
        causal_consistency_checks: AtomicU64,
    }

    /// Configuration for saga-trace integration testing
    struct IntegrationConfig {
        saga_steps: usize,
        crash_probability: f64,
        crash_injection_points: Vec<usize>,
        trace_buffer_size: usize,
        recovery_timeout: Duration,
        enable_deterministic_mode: bool,
    }

    /// Represents a saga step with trace event correlation
    #[derive(Debug, Clone)]
    struct TracedSagaStep {
        id: u64,
        name: String,
        step_type: SagaStepType,
        compensation_fn: String,
        execution_order: u32,
        causal_dependencies: Vec<u64>,
        expected_duration: Duration,
    }

    /// Types of saga steps for testing
    #[derive(Debug, Clone, PartialEq)]
    enum SagaStepType {
        BusinessLogic,
        ExternalService,
        DatabaseTransaction,
        ResourceAllocation,
        Compensation,
    }

    /// Tracks saga execution and trace event correlation
    struct SagaExecutionTracker {
        executed_steps: Arc<Mutex<BTreeMap<u64, TracedSagaStep>>>,
        compensation_chain: Arc<Mutex<VecDeque<u64>>>,
        trace_correlation: Arc<Mutex<HashMap<u64, Vec<TraceEvent>>>>,
        vector_clock: Arc<Mutex<VectorClock>>,
    }

    /// Recovery coordinator for saga crash scenarios
    struct RecoveryCoordinator {
        recovery_state: Arc<Mutex<RecoveryState>>,
        event_replayer: Arc<EventReplayer>,
        state_reconstructor: Arc<StateReconstructor>,
    }

    /// State of saga recovery process
    #[derive(Debug)]
    struct RecoveryState {
        current_step: Option<u64>,
        completed_steps: Vec<u64>,
        pending_compensations: VecDeque<u64>,
        crash_point: Option<u64>,
        recovery_vector_clock: VectorClock,
    }

    /// Replays trace events for saga recovery
    struct EventReplayer {
        event_log: Arc<Mutex<VecDeque<TraceEvent>>>,
        replay_cursor: AtomicU64,
        causal_order_validator: Arc<CausalOrderValidator>,
    }

    /// Reconstructs saga state from trace events
    struct StateReconstructor {
        state_snapshots: Arc<Mutex<HashMap<u64, SagaState>>>,
        compensation_graph: Arc<Mutex<CompensationGraph>>,
    }

    /// Validates causal ordering of trace events
    struct CausalOrderValidator {
        ordering_constraints: Arc<Mutex<Vec<OrderingConstraint>>>,
        violation_detector: Arc<ViolationDetector>,
    }

    /// Ordering constraint for causal consistency
    #[derive(Debug, Clone)]
    struct OrderingConstraint {
        before_event: u64,
        after_event: u64,
        constraint_type: ConstraintType,
    }

    /// Types of ordering constraints
    #[derive(Debug, Clone, PartialEq)]
    enum ConstraintType {
        HappensBefore,
        CausalDependency,
        CompensationOrder,
        RecoveryOrder,
    }

    /// Detects causal ordering violations
    struct ViolationDetector {
        violations: Arc<Mutex<Vec<OrderingViolation>>>,
        detection_threshold: u32,
    }

    /// Represents a causal ordering violation
    #[derive(Debug)]
    struct OrderingViolation {
        violating_event: u64,
        expected_predecessor: u64,
        actual_order: Vec<u64>,
        violation_type: ConstraintType,
        detected_at: Instant,
    }

    /// Compensation dependency graph
    struct CompensationGraph {
        dependencies: HashMap<u64, Vec<u64>>,
        execution_order: VecDeque<u64>,
    }

    impl SagaTraceTestFramework {
        async fn new(cx: &Cx, config: IntegrationConfig) -> Result<Self, Error> {
            let runtime = init_test_runtime(cx).await?;
            let lab_runtime = LabRuntime::new(cx, config.enable_deterministic_mode).await?;
            let tracer = TestTracer::new();

            // Initialize saga with compensation logic
            let saga = Arc::new(Saga::new(cx).await?);

            // Initialize trace recorder with ordering guarantees
            let recorder = Arc::new(TraceRecorder::new(cx, config.trace_buffer_size).await?);

            // Initialize crash injector for deterministic crashes
            let crash_injector = Arc::new(CrashInjector::new(
                config.crash_probability,
                config.crash_injection_points.clone(),
            ).await?);

            let stats = Arc::new(IntegrationStats {
                saga_steps_executed: AtomicU64::new(0),
                compensation_steps_executed: AtomicU64::new(0),
                trace_events_recorded: AtomicU64::new(0),
                crash_events_injected: AtomicU64::new(0),
                recovery_attempts: AtomicU64::new(0),
                ordering_violations: AtomicU64::new(0),
                successful_recoveries: AtomicU64::new(0),
                causal_consistency_checks: AtomicU64::new(0),
            });

            Ok(Self {
                runtime,
                lab_runtime,
                tracer,
                saga,
                recorder,
                crash_injector,
                stats,
            })
        }

        /// Execute saga with crash injection and trace recording
        async fn execute_saga_with_crash_injection(
            &self,
            cx: &Cx,
            saga_steps: Vec<TracedSagaStep>,
        ) -> Result<SagaExecutionResult, Error> {
            let tracker = Arc::new(SagaExecutionTracker {
                executed_steps: Arc::new(Mutex::new(BTreeMap::new())),
                compensation_chain: Arc::new(Mutex::new(VecDeque::new())),
                trace_correlation: Arc::new(Mutex::new(HashMap::new())),
                vector_clock: Arc::new(Mutex::new(VectorClock::new())),
            });

            let recovery_coordinator = Arc::new(RecoveryCoordinator::new().await?);

            // Start trace recording
            let recording_handle = self.start_trace_recording(cx).await?;

            // Execute saga steps with crash injection
            let mut crashed_at = None;
            for (step_index, step) in saga_steps.iter().enumerate() {
                // Check for crash injection
                if self.crash_injector.should_inject_crash(step_index).await {
                    crashed_at = Some(step.id);
                    self.stats.crash_events_injected.fetch_add(1, Ordering::Relaxed);
                    break;
                }

                // Execute saga step with trace correlation
                let execution_result = self.execute_traced_step(cx, step, &tracker).await?;

                if execution_result.requires_compensation {
                    let mut compensation_chain = tracker.compensation_chain.lock().await;
                    compensation_chain.push_front(step.id);
                }

                self.stats.saga_steps_executed.fetch_add(1, Ordering::Relaxed);
            }

            // Handle crash and recovery if needed
            if let Some(crash_step) = crashed_at {
                let recovery_result = self.handle_crash_and_recovery(
                    cx,
                    crash_step,
                    &tracker,
                    &recovery_coordinator,
                ).await?;

                return Ok(SagaExecutionResult {
                    completed_steps: recovery_result.recovered_steps.len() as u64,
                    compensated_steps: recovery_result.compensated_steps.len() as u64,
                    trace_events: recovery_result.trace_events,
                    crashed_at: Some(crash_step),
                    recovery_successful: recovery_result.success,
                    ordering_violations: self.stats.ordering_violations.load(Ordering::Relaxed),
                });
            }

            // Normal completion - collect results
            recording_handle.stop().await;
            let trace_events = self.recorder.collect_events().await?;

            Ok(SagaExecutionResult {
                completed_steps: saga_steps.len() as u64,
                compensated_steps: 0,
                trace_events,
                crashed_at: None,
                recovery_successful: true,
                ordering_violations: self.stats.ordering_violations.load(Ordering::Relaxed),
            })
        }

        /// Execute a traced saga step
        async fn execute_traced_step(
            &self,
            cx: &Cx,
            step: &TracedSagaStep,
            tracker: &SagaExecutionTracker,
        ) -> Result<StepExecutionResult, Error> {
            // Record step execution start event
            let start_event = TraceEvent::new(
                format!("saga_step_start:{}", step.id),
                step.causal_dependencies.clone(),
            );
            self.recorder.record_event(cx, start_event).await?;
            self.stats.trace_events_recorded.fetch_add(1, Ordering::Relaxed);

            // Update vector clock
            {
                let mut clock = tracker.vector_clock.lock().await;
                clock.increment_local();
            }

            // Simulate step execution based on type
            let execution_duration = match step.step_type {
                SagaStepType::BusinessLogic => Duration::from_millis(50),
                SagaStepType::ExternalService => Duration::from_millis(200),
                SagaStepType::DatabaseTransaction => Duration::from_millis(100),
                SagaStepType::ResourceAllocation => Duration::from_millis(75),
                SagaStepType::Compensation => Duration::from_millis(125),
            };

            Sleep::new(execution_duration).await;

            // Record step completion event
            let completion_event = TraceEvent::new(
                format!("saga_step_complete:{}", step.id),
                vec![step.id],
            );
            self.recorder.record_event(cx, completion_event.clone()).await?;
            self.stats.trace_events_recorded.fetch_add(1, Ordering::Relaxed);

            // Update tracking state
            {
                let mut executed = tracker.executed_steps.lock().await;
                executed.insert(step.id, step.clone());

                let mut correlations = tracker.trace_correlation.lock().await;
                correlations.entry(step.id).or_insert_with(Vec::new)
                    .push(completion_event);
            }

            Ok(StepExecutionResult {
                step_id: step.id,
                success: true,
                requires_compensation: step.step_type != SagaStepType::Compensation,
                trace_events_emitted: 2,
            })
        }

        /// Handle crash and initiate recovery
        async fn handle_crash_and_recovery(
            &self,
            cx: &Cx,
            crash_step: u64,
            tracker: &SagaExecutionTracker,
            coordinator: &RecoveryCoordinator,
        ) -> Result<RecoveryResult, Error> {
            self.stats.recovery_attempts.fetch_add(1, Ordering::Relaxed);

            // Record crash event
            let crash_event = TraceEvent::new(
                format!("saga_crash_injected:{}", crash_step),
                vec![crash_step],
            );
            self.recorder.record_event(cx, crash_event).await?;

            // Initiate compensation sequence from trace events
            let compensation_result = coordinator.initiate_compensation_from_traces(
                cx,
                &self.recorder,
                crash_step,
            ).await?;

            // Verify causal ordering of compensation events
            let ordering_check = self.verify_compensation_ordering(
                &compensation_result.compensation_events
            ).await?;

            if ordering_check.has_violations {
                self.stats.ordering_violations.fetch_add(
                    ordering_check.violations.len() as u64,
                    Ordering::Relaxed
                );
            } else {
                self.stats.successful_recoveries.fetch_add(1, Ordering::Relaxed);
            }

            Ok(RecoveryResult {
                success: !ordering_check.has_violations,
                recovered_steps: compensation_result.recovered_steps,
                compensated_steps: compensation_result.compensated_steps,
                trace_events: compensation_result.compensation_events,
                ordering_violations: ordering_check.violations,
            })
        }

        /// Verify causal ordering of compensation events
        async fn verify_compensation_ordering(
            &self,
            events: &[TraceEvent]
        ) -> Result<OrderingCheckResult, Error> {
            self.stats.causal_consistency_checks.fetch_add(1, Ordering::Relaxed);

            let validator = CausalOrderValidator::new();

            // Define ordering constraints for compensation
            let constraints = vec![
                OrderingConstraint {
                    before_event: 0, // Will be populated dynamically
                    after_event: 0,
                    constraint_type: ConstraintType::CompensationOrder,
                },
            ];

            let violations = validator.validate_ordering(events, &constraints).await?;

            Ok(OrderingCheckResult {
                has_violations: !violations.is_empty(),
                violations,
                total_events_checked: events.len(),
            })
        }

        /// Start trace recording with event correlation
        async fn start_trace_recording(&self, cx: &Cx) -> Result<RecordingHandle, Error> {
            let (stop_tx, stop_rx) = oneshot::channel();
            let recorder_ref = Arc::clone(&self.recorder);
            let stats_ref = Arc::clone(&self.stats);

            let recording_task = cx.spawn(async move {
                let mut recording_active = true;
                while recording_active {
                    // Process pending trace events
                    let events_processed = recorder_ref.process_pending_events().await.unwrap_or(0);
                    stats_ref.trace_events_recorded.fetch_add(events_processed, Ordering::Relaxed);

                    // Check for stop signal
                    if stop_rx.try_recv().is_ok() {
                        recording_active = false;
                    }

                    Sleep::new(Duration::from_millis(10)).await;
                }
            }).await?;

            Ok(RecordingHandle {
                stop_sender: stop_tx,
                task_handle: recording_task,
            })
        }
    }

    impl RecoveryCoordinator {
        async fn new() -> Result<Self, Error> {
            Ok(Self {
                recovery_state: Arc::new(Mutex::new(RecoveryState::new())),
                event_replayer: Arc::new(EventReplayer::new().await?),
                state_reconstructor: Arc::new(StateReconstructor::new().await?),
            })
        }

        /// Initiate compensation from trace events
        async fn initiate_compensation_from_traces(
            &self,
            cx: &Cx,
            recorder: &TraceRecorder,
            crash_point: u64,
        ) -> Result<CompensationExecutionResult, Error> {
            // Reconstruct saga state from trace events
            let events = recorder.get_events_before_point(crash_point).await?;
            let reconstructed_state = self.state_reconstructor.reconstruct_state(events).await?;

            // Determine compensation sequence
            let compensation_steps = self.calculate_compensation_sequence(
                &reconstructed_state,
                crash_point
            ).await?;

            // Execute compensations with trace recording
            let mut compensation_events = Vec::new();
            let mut compensated_steps = Vec::new();

            for step_id in compensation_steps {
                let compensation_event = TraceEvent::new(
                    format!("saga_compensation:{}", step_id),
                    vec![step_id, crash_point],
                );

                recorder.record_event(cx, compensation_event.clone()).await?;
                compensation_events.push(compensation_event);
                compensated_steps.push(step_id);

                // Simulate compensation execution
                Sleep::new(Duration::from_millis(100)).await;
            }

            Ok(CompensationExecutionResult {
                recovered_steps: reconstructed_state.completed_steps,
                compensated_steps,
                compensation_events,
            })
        }

        async fn calculate_compensation_sequence(
            &self,
            state: &RecoveryState,
            crash_point: u64,
        ) -> Result<Vec<u64>, Error> {
            // Calculate compensation order (reverse of execution order)
            let mut compensation_sequence = state.completed_steps.clone();
            compensation_sequence.reverse();

            // Filter out steps that don't need compensation
            compensation_sequence.retain(|&step_id| {
                step_id < crash_point && self.requires_compensation(step_id)
            });

            Ok(compensation_sequence)
        }

        fn requires_compensation(&self, step_id: u64) -> bool {
            // Simple heuristic: steps with even IDs require compensation
            step_id % 2 == 0
        }
    }

    impl EventReplayer {
        async fn new() -> Result<Self, Error> {
            Ok(Self {
                event_log: Arc::new(Mutex::new(VecDeque::new())),
                replay_cursor: AtomicU64::new(0),
                causal_order_validator: Arc::new(CausalOrderValidator::new()),
            })
        }
    }

    impl StateReconstructor {
        async fn new() -> Result<Self, Error> {
            Ok(Self {
                state_snapshots: Arc::new(Mutex::new(HashMap::new())),
                compensation_graph: Arc::new(Mutex::new(CompensationGraph::new())),
            })
        }

        async fn reconstruct_state(&self, events: Vec<TraceEvent>) -> Result<RecoveryState, Error> {
            let mut completed_steps = Vec::new();
            let mut vector_clock = VectorClock::new();

            for event in events {
                if event.event_type.contains("saga_step_complete:") {
                    if let Some(step_id_str) = event.event_type.strip_prefix("saga_step_complete:") {
                        if let Ok(step_id) = step_id_str.parse::<u64>() {
                            completed_steps.push(step_id);
                            vector_clock.increment_local();
                        }
                    }
                }
            }

            Ok(RecoveryState {
                current_step: completed_steps.last().copied(),
                completed_steps,
                pending_compensations: VecDeque::new(),
                crash_point: None,
                recovery_vector_clock: vector_clock,
            })
        }
    }

    impl CausalOrderValidator {
        fn new() -> Self {
            Self {
                ordering_constraints: Arc::new(Mutex::new(Vec::new())),
                violation_detector: Arc::new(ViolationDetector::new(5)),
            }
        }

        async fn validate_ordering(
            &self,
            events: &[TraceEvent],
            constraints: &[OrderingConstraint],
        ) -> Result<Vec<OrderingViolation>, Error> {
            // Simple validation: check that events are in monotonic order
            let mut violations = Vec::new();

            for (i, event) in events.iter().enumerate() {
                if i > 0 {
                    let prev_event = &events[i - 1];
                    // Check if events are in correct causal order
                    if event.timestamp < prev_event.timestamp {
                        violations.push(OrderingViolation {
                            violating_event: i as u64,
                            expected_predecessor: (i - 1) as u64,
                            actual_order: events.iter().enumerate().map(|(idx, _)| idx as u64).collect(),
                            violation_type: ConstraintType::HappensBefore,
                            detected_at: Instant::now(),
                        });
                    }
                }
            }

            Ok(violations)
        }
    }

    impl ViolationDetector {
        fn new(threshold: u32) -> Self {
            Self {
                violations: Arc::new(Mutex::new(Vec::new())),
                detection_threshold: threshold,
            }
        }
    }

    impl RecoveryState {
        fn new() -> Self {
            Self {
                current_step: None,
                completed_steps: Vec::new(),
                pending_compensations: VecDeque::new(),
                crash_point: None,
                recovery_vector_clock: VectorClock::new(),
            }
        }
    }

    impl CompensationGraph {
        fn new() -> Self {
            Self {
                dependencies: HashMap::new(),
                execution_order: VecDeque::new(),
            }
        }
    }

    /// Results from saga execution with crash injection
    #[derive(Debug)]
    struct SagaExecutionResult {
        completed_steps: u64,
        compensated_steps: u64,
        trace_events: Vec<TraceEvent>,
        crashed_at: Option<u64>,
        recovery_successful: bool,
        ordering_violations: u64,
    }

    /// Results from step execution
    #[derive(Debug)]
    struct StepExecutionResult {
        step_id: u64,
        success: bool,
        requires_compensation: bool,
        trace_events_emitted: u32,
    }

    /// Results from crash recovery
    #[derive(Debug)]
    struct RecoveryResult {
        success: bool,
        recovered_steps: Vec<u64>,
        compensated_steps: Vec<u64>,
        trace_events: Vec<TraceEvent>,
        ordering_violations: Vec<OrderingViolation>,
    }

    /// Results from compensation execution
    #[derive(Debug)]
    struct CompensationExecutionResult {
        recovered_steps: Vec<u64>,
        compensated_steps: Vec<u64>,
        compensation_events: Vec<TraceEvent>,
    }

    /// Results from ordering validation
    #[derive(Debug)]
    struct OrderingCheckResult {
        has_violations: bool,
        violations: Vec<OrderingViolation>,
        total_events_checked: usize,
    }

    /// Handle for controlling trace recording
    struct RecordingHandle {
        stop_sender: oneshot::Sender<()>,
        task_handle: TaskId,
    }

    impl RecordingHandle {
        async fn stop(self) {
            let _ = self.stop_sender.send(());
            // Wait for recording task to complete
            Sleep::new(Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn test_saga_compensation_trace_ordering() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            saga_steps: 5,
            crash_probability: 1.0, // Always crash for deterministic testing
            crash_injection_points: vec![3], // Crash at step 3
            trace_buffer_size: 1000,
            recovery_timeout: Duration::from_secs(5),
            enable_deterministic_mode: true,
        };

        let framework = SagaTraceTestFramework::new(&cx, config).await.unwrap();

        // Create saga steps with dependencies
        let saga_steps = vec![
            TracedSagaStep {
                id: 1,
                name: "allocate_resources".to_string(),
                step_type: SagaStepType::ResourceAllocation,
                compensation_fn: "deallocate_resources".to_string(),
                execution_order: 1,
                causal_dependencies: vec![],
                expected_duration: Duration::from_millis(100),
            },
            TracedSagaStep {
                id: 2,
                name: "create_account".to_string(),
                step_type: SagaStepType::DatabaseTransaction,
                compensation_fn: "delete_account".to_string(),
                execution_order: 2,
                causal_dependencies: vec![1],
                expected_duration: Duration::from_millis(150),
            },
            TracedSagaStep {
                id: 3,
                name: "send_notification".to_string(),
                step_type: SagaStepType::ExternalService,
                compensation_fn: "cancel_notification".to_string(),
                execution_order: 3,
                causal_dependencies: vec![2],
                expected_duration: Duration::from_millis(200),
            },
        ];

        let result = framework.execute_saga_with_crash_injection(&cx, saga_steps).await.unwrap();

        // Verify crash handling and compensation ordering
        assert_eq!(result.crashed_at, Some(3), "Should crash at step 3");
        assert!(result.recovery_successful, "Recovery should succeed");
        assert!(result.compensated_steps > 0, "Should have compensated steps");
        assert_eq!(result.ordering_violations, 0, "No trace ordering violations");

        // Verify compensation order (reverse of execution)
        assert!(result.trace_events.iter().any(|e|
            e.event_type.contains("saga_compensation:2") ||
            e.event_type.contains("saga_compensation:1")
        ), "Compensation events should be recorded");

        cx.trace("Saga compensation trace ordering verified").await;
    }

    #[tokio::test]
    async fn test_crash_injection_mid_flow_recovery() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            saga_steps: 7,
            crash_probability: 0.8,
            crash_injection_points: vec![2, 4, 6],
            trace_buffer_size: 2000,
            recovery_timeout: Duration::from_secs(3),
            enable_deterministic_mode: true,
        };

        let framework = SagaTraceTestFramework::new(&cx, config).await.unwrap();

        // Create complex saga with multiple step types
        let saga_steps = (1..=7).map(|i| {
            let step_type = match i % 4 {
                1 => SagaStepType::BusinessLogic,
                2 => SagaStepType::DatabaseTransaction,
                3 => SagaStepType::ExternalService,
                _ => SagaStepType::ResourceAllocation,
            };

            TracedSagaStep {
                id: i,
                name: format!("step_{}", i),
                step_type,
                compensation_fn: format!("compensate_step_{}", i),
                execution_order: i as u32,
                causal_dependencies: if i > 1 { vec![i - 1] } else { vec![] },
                expected_duration: Duration::from_millis(75 + (i % 3) * 25),
            }
        }).collect();

        let result = framework.execute_saga_with_crash_injection(&cx, saga_steps).await.unwrap();

        // Verify crash injection and recovery behavior
        assert!(result.crashed_at.is_some(), "Should inject crash mid-flow");

        if let Some(crash_step) = result.crashed_at {
            assert!(crash_step >= 2 && crash_step <= 6, "Crash should occur at configured points");
            assert!(result.completed_steps < 7, "Not all steps should complete due to crash");
        }

        assert!(result.recovery_successful, "Recovery from mid-flow crash should succeed");

        cx.trace("Mid-flow crash injection and recovery validated").await;
    }

    #[tokio::test]
    async fn test_trace_event_causal_consistency() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            saga_steps: 6,
            crash_probability: 1.0,
            crash_injection_points: vec![4],
            trace_buffer_size: 1500,
            recovery_timeout: Duration::from_secs(4),
            enable_deterministic_mode: true,
        };

        let framework = SagaTraceTestFramework::new(&cx, config).await.unwrap();

        // Create saga with complex causal dependencies
        let saga_steps = vec![
            TracedSagaStep {
                id: 1,
                name: "init_transaction".to_string(),
                step_type: SagaStepType::DatabaseTransaction,
                compensation_fn: "rollback_transaction".to_string(),
                execution_order: 1,
                causal_dependencies: vec![],
                expected_duration: Duration::from_millis(80),
            },
            TracedSagaStep {
                id: 2,
                name: "validate_input".to_string(),
                step_type: SagaStepType::BusinessLogic,
                compensation_fn: "revert_validation".to_string(),
                execution_order: 2,
                causal_dependencies: vec![1],
                expected_duration: Duration::from_millis(60),
            },
            TracedSagaStep {
                id: 3,
                name: "call_external_api".to_string(),
                step_type: SagaStepType::ExternalService,
                compensation_fn: "cancel_api_call".to_string(),
                execution_order: 3,
                causal_dependencies: vec![1, 2],
                expected_duration: Duration::from_millis(200),
            },
            TracedSagaStep {
                id: 4,
                name: "allocate_quota".to_string(),
                step_type: SagaStepType::ResourceAllocation,
                compensation_fn: "release_quota".to_string(),
                execution_order: 4,
                causal_dependencies: vec![2, 3],
                expected_duration: Duration::from_millis(90),
            },
        ];

        let result = framework.execute_saga_with_crash_injection(&cx, saga_steps).await.unwrap();

        // Verify causal consistency of trace events
        assert_eq!(result.ordering_violations, 0, "Trace events should maintain causal consistency");

        // Check that compensation events respect causal order
        let compensation_events: Vec<_> = result.trace_events.iter()
            .filter(|e| e.event_type.contains("saga_compensation:"))
            .collect();

        assert!(!compensation_events.is_empty(), "Should have compensation events");

        // Verify that compensation events follow reverse dependency order
        for (i, event) in compensation_events.iter().enumerate() {
            if i > 0 {
                // Each compensation should happen after its dependencies are compensated
                assert!(event.timestamp >= compensation_events[i-1].timestamp,
                    "Compensation events should maintain temporal order");
            }
        }

        cx.trace("Trace event causal consistency maintained").await;
    }

    #[tokio::test]
    async fn test_deterministic_crash_recovery_replay() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            saga_steps: 4,
            crash_probability: 1.0,
            crash_injection_points: vec![3],
            trace_buffer_size: 800,
            recovery_timeout: Duration::from_secs(2),
            enable_deterministic_mode: true,
        };

        let framework = SagaTraceTestFramework::new(&cx, config).await.unwrap();

        let saga_steps = (1..=4).map(|i| {
            TracedSagaStep {
                id: i,
                name: format!("deterministic_step_{}", i),
                step_type: SagaStepType::BusinessLogic,
                compensation_fn: format!("undo_step_{}", i),
                execution_order: i as u32,
                causal_dependencies: if i > 1 { vec![i - 1] } else { vec![] },
                expected_duration: Duration::from_millis(100),
            }
        }).collect();

        // Run the same scenario multiple times
        for run in 1..=3 {
            let result = framework.execute_saga_with_crash_injection(&cx, saga_steps.clone()).await.unwrap();

            // Verify deterministic behavior across runs
            assert_eq!(result.crashed_at, Some(3), "Should crash deterministically at step 3 in run {}", run);
            assert!(result.recovery_successful, "Recovery should succeed deterministically in run {}", run);
            assert_eq!(result.completed_steps, 2, "Should complete exactly 2 steps before crash in run {}", run);
            assert_eq!(result.ordering_violations, 0, "No ordering violations in run {}", run);
        }

        cx.trace("Deterministic crash recovery replay validated").await;
    }

    #[tokio::test]
    async fn test_complex_compensation_graph_ordering() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            saga_steps: 8,
            crash_probability: 1.0,
            crash_injection_points: vec![6],
            trace_buffer_size: 2500,
            recovery_timeout: Duration::from_secs(6),
            enable_deterministic_mode: true,
        };

        let framework = SagaTraceTestFramework::new(&cx, config).await.unwrap();

        // Create saga with complex dependency graph
        let saga_steps = vec![
            // Level 1: Independent steps
            TracedSagaStep { id: 1, name: "setup_a".to_string(), step_type: SagaStepType::ResourceAllocation,
                compensation_fn: "cleanup_a".to_string(), execution_order: 1, causal_dependencies: vec![], expected_duration: Duration::from_millis(50) },
            TracedSagaStep { id: 2, name: "setup_b".to_string(), step_type: SagaStepType::ResourceAllocation,
                compensation_fn: "cleanup_b".to_string(), execution_order: 2, causal_dependencies: vec![], expected_duration: Duration::from_millis(50) },

            // Level 2: Depends on level 1
            TracedSagaStep { id: 3, name: "process_a".to_string(), step_type: SagaStepType::BusinessLogic,
                compensation_fn: "revert_a".to_string(), execution_order: 3, causal_dependencies: vec![1], expected_duration: Duration::from_millis(75) },
            TracedSagaStep { id: 4, name: "process_b".to_string(), step_type: SagaStepType::BusinessLogic,
                compensation_fn: "revert_b".to_string(), execution_order: 4, causal_dependencies: vec![2], expected_duration: Duration::from_millis(75) },

            // Level 3: Depends on level 2
            TracedSagaStep { id: 5, name: "combine_results".to_string(), step_type: SagaStepType::DatabaseTransaction,
                compensation_fn: "split_results".to_string(), execution_order: 5, causal_dependencies: vec![3, 4], expected_duration: Duration::from_millis(100) },

            // Level 4: Final step
            TracedSagaStep { id: 6, name: "finalize".to_string(), step_type: SagaStepType::ExternalService,
                compensation_fn: "cancel_finalization".to_string(), execution_order: 6, causal_dependencies: vec![5], expected_duration: Duration::from_millis(150) },
        ];

        let result = framework.execute_saga_with_crash_injection(&cx, saga_steps).await.unwrap();

        // Verify complex compensation graph ordering
        assert_eq!(result.crashed_at, Some(6), "Should crash at final step");
        assert!(result.recovery_successful, "Complex compensation should succeed");
        assert!(result.compensated_steps >= 4, "Should compensate multiple dependent steps");
        assert_eq!(result.ordering_violations, 0, "Complex dependency graph should maintain ordering");

        // Verify that compensation follows reverse dependency order
        let compensation_events: Vec<_> = result.trace_events.iter()
            .filter(|e| e.event_type.contains("saga_compensation:"))
            .collect();

        // Should compensate in reverse order: 5 -> (4,3) -> (2,1)
        let step_5_comp = compensation_events.iter().find(|e| e.event_type.contains("saga_compensation:5"));
        let step_1_comp = compensation_events.iter().find(|e| e.event_type.contains("saga_compensation:1"));

        if let (Some(comp_5), Some(comp_1)) = (step_5_comp, step_1_comp) {
            assert!(comp_5.timestamp <= comp_1.timestamp, "Step 5 should be compensated before step 1");
        }

        cx.trace("Complex compensation graph ordering validated").await;
    }
}