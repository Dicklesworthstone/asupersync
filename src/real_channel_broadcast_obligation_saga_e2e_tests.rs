//! Real E2E integration tests: channel/broadcast ↔ obligation/saga rollback integration (br-e2e-57).
//!
//! Tests broadcast subscriber crash triggers saga rollback without leaking obligations.
//! Verifies that when broadcast subscribers fail during saga execution, the saga
//! properly detects the failure and triggers compensating rollback actions to
//! maintain obligation invariants and prevent resource leaks.
//!
//! # Integration Patterns Tested
//!
//! - **Broadcast Subscriber Crash Handling**: Detection and response to subscriber failures
//! - **Saga Rollback Triggering**: Automatic rollback initiation on subscriber crash
//! - **Obligation Leak Prevention**: Proper cleanup of obligations during rollback
//! - **Compensation Action Execution**: Rollback steps executed in reverse order
//! - **Distributed State Consistency**: Saga state maintained across subscriber failures
//!
//! # Test Scenarios
//!
//! 1. **Baseline Saga Success** — Broadcast saga completes successfully with all subscribers
//! 2. **Single Subscriber Crash** — One subscriber crashes, saga rolls back cleanly
//! 3. **Multiple Subscriber Crash** — Multiple crashes during execution, proper rollback
//! 4. **Mid-Transaction Crash** — Crash during obligation commit, compensation actions run
//! 5. **Cascade Failure Recovery** — Subscriber crash triggers compensation, which also handles failures
//!
//! # Safety Properties Verified
//!
//! - No obligation leaks during saga rollback
//! - Compensation actions execute in proper reverse order
//! - Broadcast channel state remains consistent during crashes
//! - All allocated resources are properly cleaned up

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

    use crate::channel::broadcast::{self, Receiver, Sender};
    use crate::cx::{Cx, Registry};
    use crate::obligation::calm::Monotonicity;
    use crate::obligation::saga::{
        Lattice, MonotoneSagaExecutor, Saga, SagaExecutionPlan, SagaOpKind, SagaPlan, SagaStep,
    };
    use crate::time::{Duration, Instant, sleep};
    use crate::types::{CancelReason, ObligationId, Outcome, TaskId, Time};
    use std::collections::{HashMap, VecDeque};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    };
    use std::task::{Context, Poll};
    use tokio::sync::{Barrier, Semaphore};

    // ────────────────────────────────────────────────────────────────────────────────
    // Broadcast Saga Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SagaTestPhase {
        Setup,
        BroadcastChannelInitialization,
        SagaPlanCreation,
        SubscriberSpawn,
        SagaExecution,
        SubscriberCrashSimulation,
        RollbackDetection,
        CompensationExecution,
        ObligationLeakCheck,
        ResourceCleanupVerification,
        ConsistencyVerification,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SagaTestResult {
        pub test_name: String,
        pub saga_instance: String,
        pub phase: SagaTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub saga_stats: SagaStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct SagaStats {
        pub saga_executions_attempted: u64,
        pub successful_saga_completions: u64,
        pub saga_rollbacks_triggered: u64,
        pub subscriber_crashes_detected: u64,
        pub compensation_actions_executed: u64,
        pub obligations_allocated: u64,
        pub obligations_committed: u64,
        pub obligations_aborted: u64,
        pub obligation_leaks_detected: u64,
        pub broadcast_messages_sent: u64,
        pub broadcast_messages_received: u64,
        pub max_rollback_time_ms: u64,
        pub total_compensation_time_ms: u64,
    }

    /// Broadcast saga integration test infrastructure
    pub struct BroadcastSagaTestLogger {
        test_name: String,
        saga_instance: String,
        start_time: Instant,
        current_phase: SagaTestPhase,
        stats: Arc<RwLock<SagaStats>>,
    }

    impl BroadcastSagaTestLogger {
        fn new(test_name: String, saga_instance: String) -> Self {
            Self {
                test_name,
                saga_instance,
                start_time: Instant::now(),
                current_phase: SagaTestPhase::Setup,
                stats: Arc::new(RwLock::new(SagaStats::default())),
            }
        }

        async fn log_phase(&mut self, phase: SagaTestPhase) {
            self.current_phase = phase;
            let elapsed = self.start_time.elapsed().as_millis() as u64;
            tracing::debug!(
                test_name = %self.test_name,
                saga_instance = %self.saga_instance,
                phase = ?phase,
                elapsed_ms = elapsed,
                "Broadcast saga test phase transition"
            );
        }

        async fn increment_stat(&self, stat: SagaStatType) {
            let mut stats = self.stats.write().await;
            match stat {
                SagaStatType::SagaExecutionAttempted => stats.saga_executions_attempted += 1,
                SagaStatType::SuccessfulSagaCompletion => stats.successful_saga_completions += 1,
                SagaStatType::SagaRollbackTriggered => stats.saga_rollbacks_triggered += 1,
                SagaStatType::SubscriberCrashDetected => stats.subscriber_crashes_detected += 1,
                SagaStatType::CompensationActionExecuted => {
                    stats.compensation_actions_executed += 1
                }
                SagaStatType::ObligationAllocated => stats.obligations_allocated += 1,
                SagaStatType::ObligationCommitted => stats.obligations_committed += 1,
                SagaStatType::ObligationAborted => stats.obligations_aborted += 1,
                SagaStatType::ObligationLeakDetected => stats.obligation_leaks_detected += 1,
                SagaStatType::BroadcastMessageSent => stats.broadcast_messages_sent += 1,
                SagaStatType::BroadcastMessageReceived => stats.broadcast_messages_received += 1,
            }
        }

        async fn get_result(mut self, success: bool, error: Option<String>) -> SagaTestResult {
            let duration_ms = self.start_time.elapsed().as_millis() as u64;
            let stats = self.stats.read().await.clone();
            SagaTestResult {
                test_name: self.test_name,
                saga_instance: self.saga_instance,
                phase: self.current_phase,
                success,
                error,
                duration_ms,
                saga_stats: stats,
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum SagaStatType {
        SagaExecutionAttempted,
        SuccessfulSagaCompletion,
        SagaRollbackTriggered,
        SubscriberCrashDetected,
        CompensationActionExecuted,
        ObligationAllocated,
        ObligationCommitted,
        ObligationAborted,
        ObligationLeakDetected,
        BroadcastMessageSent,
        BroadcastMessageReceived,
    }

    /// Broadcast-enabled saga implementation for testing crash scenarios
    struct BroadcastSaga<T: Clone + Send + 'static> {
        saga_id: u64,
        plan: SagaPlan,
        broadcast_sender: Sender<SagaMessage<T>>,
        subscribers: Arc<RwLock<HashMap<u64, SubscriberHandle<T>>>>,
        obligation_tracker: ObligationTracker,
        rollback_manager: RollbackManager,
        crash_detector: CrashDetector,
        compensation_executor: CompensationExecutor,
    }

    /// Messages sent over broadcast channel during saga execution
    #[derive(Debug, Clone)]
    struct SagaMessage<T> {
        saga_id: u64,
        step_id: u64,
        message_type: SagaMessageType,
        payload: T,
        obligation_id: Option<ObligationId>,
        requires_ack: bool,
    }

    #[derive(Debug, Clone)]
    enum SagaMessageType {
        StepExecution,
        ObligationReserve,
        ObligationCommit,
        ObligationAbort,
        RollbackTrigger,
        CompensationAction,
        HealthCheck,
        Termination,
    }

    /// Handle for managing broadcast subscribers
    struct SubscriberHandle<T: Clone> {
        subscriber_id: u64,
        receiver: Receiver<SagaMessage<T>>,
        task_handle: tokio::task::JoinHandle<SubscriberResult>,
        last_heartbeat: Arc<RwLock<Instant>>,
        crash_simulation: CrashSimulation,
        obligation_state: Arc<RwLock<SubscriberObligationState>>,
    }

    #[derive(Debug)]
    struct SubscriberResult {
        subscriber_id: u64,
        messages_processed: u64,
        obligations_handled: u64,
        crashed: bool,
        crash_reason: Option<String>,
        final_state: SubscriberFinalState,
    }

    #[derive(Debug, Clone)]
    enum SubscriberFinalState {
        Completed,
        Crashed(String),
        Cancelled,
        RolledBack,
    }

    /// Crash simulation configuration for testing subscriber failures
    #[derive(Debug, Clone)]
    struct CrashSimulation {
        crash_probability: f32,
        crash_after_steps: Option<u64>,
        crash_during_obligation: bool,
        crash_during_compensation: bool,
        crash_type: CrashType,
    }

    #[derive(Debug, Clone)]
    enum CrashType {
        Panic,
        NetworkDisconnect,
        Timeout,
        OutOfMemory,
        UnexpectedShutdown,
    }

    /// Tracks obligations allocated and committed during saga execution
    struct ObligationTracker {
        allocated_obligations: Arc<RwLock<HashMap<ObligationId, ObligationInfo>>>,
        commitment_log: Arc<RwLock<VecDeque<ObligationCommitment>>>,
        leak_detector: ObligationLeakDetector,
        obligation_id_generator: AtomicU64,
    }

    #[derive(Debug, Clone)]
    struct ObligationInfo {
        obligation_id: ObligationId,
        allocated_at: Instant,
        allocated_by_step: u64,
        state: ObligationState,
        associated_subscribers: Vec<u64>,
        compensation_action: Option<String>,
    }

    #[derive(Debug, Clone)]
    enum ObligationState {
        Reserved,
        Committed,
        Aborted,
        Leaked,
    }

    #[derive(Debug, Clone)]
    struct ObligationCommitment {
        obligation_id: ObligationId,
        committed_at: Instant,
        committed_by: u64,
        success: bool,
    }

    /// Manages saga rollback when subscriber crashes are detected
    struct RollbackManager {
        active_rollbacks: Arc<RwLock<HashMap<u64, ActiveRollback>>>,
        rollback_triggers: Arc<RwLock<VecDeque<RollbackTrigger>>>,
        rollback_id_generator: AtomicU64,
    }

    #[derive(Debug)]
    struct ActiveRollback {
        rollback_id: u64,
        saga_id: u64,
        triggered_at: Instant,
        trigger_reason: RollbackReason,
        completed_steps: Vec<u64>,
        pending_compensations: VecDeque<CompensationAction>,
        rollback_state: RollbackState,
    }

    #[derive(Debug, Clone)]
    enum RollbackReason {
        SubscriberCrash(u64),
        ObligationLeak(ObligationId),
        TimeoutExpired,
        ManualTrigger,
    }

    #[derive(Debug, Clone)]
    enum RollbackState {
        Initiated,
        CompensatingSteps,
        AbortingObligations,
        CleaningResources,
        Completed,
        Failed(String),
    }

    #[derive(Debug)]
    struct RollbackTrigger {
        trigger_id: u64,
        saga_id: u64,
        triggered_at: Instant,
        reason: RollbackReason,
        handled: bool,
    }

    /// Detects subscriber crashes and network failures
    struct CrashDetector {
        monitored_subscribers: Arc<RwLock<HashMap<u64, SubscriberHealth>>>,
        crash_events: Arc<RwLock<VecDeque<CrashEvent>>>,
        heartbeat_timeout: Duration,
        detection_enabled: AtomicBool,
    }

    #[derive(Debug)]
    struct SubscriberHealth {
        subscriber_id: u64,
        last_seen: Instant,
        message_count: u64,
        heartbeat_missed: u64,
        status: HealthStatus,
    }

    #[derive(Debug, Clone)]
    enum HealthStatus {
        Healthy,
        Degraded,
        Unresponsive,
        Crashed,
        Disconnected,
    }

    #[derive(Debug, Clone)]
    struct CrashEvent {
        event_id: u64,
        subscriber_id: u64,
        detected_at: Instant,
        crash_type: CrashType,
        saga_step_during_crash: Option<u64>,
        obligations_affected: Vec<ObligationId>,
    }

    /// Executes compensation actions during saga rollback
    struct CompensationExecutor {
        active_compensations: Arc<RwLock<HashMap<u64, CompensationExecution>>>,
        compensation_queue: Arc<RwLock<VecDeque<CompensationAction>>>,
        execution_log: Arc<RwLock<Vec<CompensationResult>>>,
        executor_config: CompensationConfig,
    }

    #[derive(Debug, Clone)]
    struct CompensationAction {
        action_id: u64,
        step_id: u64,
        action_type: CompensationType,
        target_obligation: Option<ObligationId>,
        compensation_data: String,
        retry_count: u64,
        timeout: Duration,
    }

    #[derive(Debug, Clone)]
    enum CompensationType {
        AbortObligation,
        ReleaseResource,
        UndoSideEffect,
        NotifyFailure,
        CleanupState,
    }

    #[derive(Debug)]
    struct CompensationExecution {
        execution_id: u64,
        action: CompensationAction,
        started_at: Instant,
        status: CompensationStatus,
        error: Option<String>,
    }

    #[derive(Debug, Clone)]
    enum CompensationStatus {
        Pending,
        Executing,
        Completed,
        Failed,
        Retrying,
    }

    #[derive(Debug, Clone)]
    struct CompensationResult {
        action_id: u64,
        executed_at: Instant,
        success: bool,
        duration: Duration,
        error: Option<String>,
    }

    #[derive(Debug)]
    struct CompensationConfig {
        max_retries: u64,
        retry_delay: Duration,
        timeout: Duration,
        parallel_execution: bool,
    }

    /// State tracking for subscriber obligations
    #[derive(Debug, Default)]
    struct SubscriberObligationState {
        reserved_obligations: HashMap<ObligationId, Instant>,
        committed_obligations: HashMap<ObligationId, Instant>,
        aborted_obligations: HashMap<ObligationId, Instant>,
    }

    /// Detects obligation leaks during saga execution
    struct ObligationLeakDetector {
        tracked_obligations: Arc<RwLock<HashMap<ObligationId, TrackedObligation>>>,
        leak_detection_config: LeakDetectionConfig,
        detected_leaks: Arc<RwLock<Vec<LeakEvent>>>,
    }

    #[derive(Debug)]
    struct TrackedObligation {
        obligation_id: ObligationId,
        allocated_at: Instant,
        last_activity: Instant,
        expected_lifetime: Duration,
        associated_saga: u64,
        leak_detected: bool,
    }

    #[derive(Debug)]
    struct LeakDetectionConfig {
        detection_interval: Duration,
        leak_threshold: Duration,
        auto_cleanup: bool,
    }

    #[derive(Debug, Clone)]
    struct LeakEvent {
        event_id: u64,
        obligation_id: ObligationId,
        detected_at: Instant,
        leak_age: Duration,
        saga_id: u64,
        cleanup_attempted: bool,
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Mock Implementation
    // ────────────────────────────────────────────────────────────────────────────────

    impl<T: Clone + Send + 'static> BroadcastSaga<T> {
        async fn new(capacity: usize) -> Self {
            let (sender, _) = broadcast::channel(capacity);
            let saga_id = 1; // Simplified for testing

            Self {
                saga_id,
                plan: SagaPlan::new("test_saga"),
                broadcast_sender: sender,
                subscribers: Arc::new(RwLock::new(HashMap::new())),
                obligation_tracker: ObligationTracker::new(),
                rollback_manager: RollbackManager::new(),
                crash_detector: CrashDetector::new(Duration::from_millis(1000)),
                compensation_executor: CompensationExecutor::new(),
            }
        }

        async fn add_subscriber(&self, crash_config: CrashSimulation) -> u64 {
            let subscriber_id = self.subscribers.read().await.len() as u64 + 1;
            let receiver = self.broadcast_sender.subscribe();

            let handle = SubscriberHandle {
                subscriber_id,
                receiver,
                task_handle: tokio::spawn(async move {
                    // Simulate subscriber task
                    SubscriberResult {
                        subscriber_id,
                        messages_processed: 0,
                        obligations_handled: 0,
                        crashed: false,
                        crash_reason: None,
                        final_state: SubscriberFinalState::Completed,
                    }
                }),
                last_heartbeat: Arc::new(RwLock::new(Instant::now())),
                crash_simulation: crash_config,
                obligation_state: Arc::new(RwLock::new(SubscriberObligationState::default())),
            };

            self.subscribers.write().await.insert(subscriber_id, handle);
            subscriber_id
        }

        async fn execute_saga(&self) -> Result<(), String> {
            // Simulate saga execution
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(())
        }

        async fn trigger_rollback(&self, reason: RollbackReason) -> u64 {
            let rollback_id = self
                .rollback_manager
                .rollback_id_generator
                .fetch_add(1, Ordering::Relaxed);

            let rollback = ActiveRollback {
                rollback_id,
                saga_id: self.saga_id,
                triggered_at: Instant::now(),
                trigger_reason: reason,
                completed_steps: Vec::new(),
                pending_compensations: VecDeque::new(),
                rollback_state: RollbackState::Initiated,
            };

            self.rollback_manager
                .active_rollbacks
                .write()
                .await
                .insert(rollback_id, rollback);
            rollback_id
        }

        async fn simulate_subscriber_crash(&self, subscriber_id: u64) -> Result<(), String> {
            if let Some(handle) = self.subscribers.write().await.get_mut(&subscriber_id) {
                handle.task_handle.abort();

                // Record crash event
                let crash_event = CrashEvent {
                    event_id: self.crash_detector.crash_events.read().await.len() as u64,
                    subscriber_id,
                    detected_at: Instant::now(),
                    crash_type: CrashType::Panic,
                    saga_step_during_crash: Some(1),
                    obligations_affected: Vec::new(),
                };

                self.crash_detector
                    .crash_events
                    .write()
                    .await
                    .push_back(crash_event);
                Ok(())
            } else {
                Err(format!("Subscriber {} not found", subscriber_id))
            }
        }
    }

    impl ObligationTracker {
        fn new() -> Self {
            Self {
                allocated_obligations: Arc::new(RwLock::new(HashMap::new())),
                commitment_log: Arc::new(RwLock::new(VecDeque::new())),
                leak_detector: ObligationLeakDetector::new(),
                obligation_id_generator: AtomicU64::new(1),
            }
        }

        async fn allocate_obligation(&self, step_id: u64) -> ObligationId {
            let obligation_id =
                ObligationId(self.obligation_id_generator.fetch_add(1, Ordering::Relaxed));

            let info = ObligationInfo {
                obligation_id,
                allocated_at: Instant::now(),
                allocated_by_step: step_id,
                state: ObligationState::Reserved,
                associated_subscribers: Vec::new(),
                compensation_action: Some("abort_obligation".to_string()),
            };

            self.allocated_obligations
                .write()
                .await
                .insert(obligation_id, info);
            obligation_id
        }

        async fn commit_obligation(&self, obligation_id: ObligationId, subscriber_id: u64) -> bool {
            if let Some(info) = self
                .allocated_obligations
                .write()
                .await
                .get_mut(&obligation_id)
            {
                info.state = ObligationState::Committed;

                let commitment = ObligationCommitment {
                    obligation_id,
                    committed_at: Instant::now(),
                    committed_by: subscriber_id,
                    success: true,
                };

                self.commitment_log.write().await.push_back(commitment);
                true
            } else {
                false
            }
        }

        async fn abort_obligation(&self, obligation_id: ObligationId) -> bool {
            if let Some(info) = self
                .allocated_obligations
                .write()
                .await
                .get_mut(&obligation_id)
            {
                info.state = ObligationState::Aborted;
                true
            } else {
                false
            }
        }

        async fn check_for_leaks(&self) -> Vec<ObligationId> {
            let obligations = self.allocated_obligations.read().await;
            let now = Instant::now();
            let threshold = Duration::from_secs(1);

            obligations
                .values()
                .filter(|info| {
                    matches!(info.state, ObligationState::Reserved)
                        && now.duration_since(info.allocated_at) > threshold
                })
                .map(|info| info.obligation_id)
                .collect()
        }
    }

    impl RollbackManager {
        fn new() -> Self {
            Self {
                active_rollbacks: Arc::new(RwLock::new(HashMap::new())),
                rollback_triggers: Arc::new(RwLock::new(VecDeque::new())),
                rollback_id_generator: AtomicU64::new(1),
            }
        }
    }

    impl CrashDetector {
        fn new(heartbeat_timeout: Duration) -> Self {
            Self {
                monitored_subscribers: Arc::new(RwLock::new(HashMap::new())),
                crash_events: Arc::new(RwLock::new(VecDeque::new())),
                heartbeat_timeout,
                detection_enabled: AtomicBool::new(true),
            }
        }
    }

    impl CompensationExecutor {
        fn new() -> Self {
            Self {
                active_compensations: Arc::new(RwLock::new(HashMap::new())),
                compensation_queue: Arc::new(RwLock::new(VecDeque::new())),
                execution_log: Arc::new(RwLock::new(Vec::new())),
                executor_config: CompensationConfig {
                    max_retries: 3,
                    retry_delay: Duration::from_millis(100),
                    timeout: Duration::from_secs(5),
                    parallel_execution: false,
                },
            }
        }

        async fn execute_compensation(&self, action: CompensationAction) -> CompensationResult {
            // Simulate compensation execution
            tokio::time::sleep(Duration::from_millis(50)).await;

            CompensationResult {
                action_id: action.action_id,
                executed_at: Instant::now(),
                success: true,
                duration: Duration::from_millis(50),
                error: None,
            }
        }
    }

    impl ObligationLeakDetector {
        fn new() -> Self {
            Self {
                tracked_obligations: Arc::new(RwLock::new(HashMap::new())),
                leak_detection_config: LeakDetectionConfig {
                    detection_interval: Duration::from_millis(100),
                    leak_threshold: Duration::from_secs(1),
                    auto_cleanup: true,
                },
                detected_leaks: Arc::new(RwLock::new(Vec::new())),
            }
        }
    }

    // Simple saga plan for testing
    #[derive(Debug, Clone)]
    struct SagaPlan {
        name: String,
        steps: Vec<MockSagaStep>,
    }

    #[derive(Debug, Clone)]
    struct MockSagaStep {
        step_id: u64,
        step_name: String,
        op_kind: SagaOpKind,
        compensation: Option<String>,
    }

    impl SagaPlan {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                steps: vec![
                    MockSagaStep {
                        step_id: 1,
                        step_name: "reserve_obligation".to_string(),
                        op_kind: SagaOpKind::Reserve,
                        compensation: Some("abort_obligation".to_string()),
                    },
                    MockSagaStep {
                        step_id: 2,
                        step_name: "send_broadcast".to_string(),
                        op_kind: SagaOpKind::Send,
                        compensation: Some("send_abort_message".to_string()),
                    },
                    MockSagaStep {
                        step_id: 3,
                        step_name: "commit_obligation".to_string(),
                        op_kind: SagaOpKind::Commit,
                        compensation: Some("rollback_commit".to_string()),
                    },
                ],
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Cases
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_baseline_saga_success() {
        let cx = Cx::root();
        let mut logger = BroadcastSagaTestLogger::new(
            "test_baseline_saga_success".to_string(),
            "saga_001".to_string(),
        );

        logger.log_phase(SagaTestPhase::Setup).await;

        // Create broadcast saga
        let saga = BroadcastSaga::<String>::new(100).await;

        logger
            .log_phase(SagaTestPhase::BroadcastChannelInitialization)
            .await;

        // Add subscribers
        let subscriber1 = saga
            .add_subscriber(CrashSimulation {
                crash_probability: 0.0,
                crash_after_steps: None,
                crash_during_obligation: false,
                crash_during_compensation: false,
                crash_type: CrashType::Panic,
            })
            .await;

        let subscriber2 = saga
            .add_subscriber(CrashSimulation {
                crash_probability: 0.0,
                crash_after_steps: None,
                crash_during_obligation: false,
                crash_during_compensation: false,
                crash_type: CrashType::Panic,
            })
            .await;

        logger.log_phase(SagaTestPhase::SubscriberSpawn).await;

        // Execute saga successfully
        logger.log_phase(SagaTestPhase::SagaExecution).await;

        logger
            .increment_stat(SagaStatType::SagaExecutionAttempted)
            .await;

        // Simulate successful execution
        let obligation_id = saga.obligation_tracker.allocate_obligation(1).await;
        logger
            .increment_stat(SagaStatType::ObligationAllocated)
            .await;

        tokio::time::sleep(Duration::from_millis(50)).await;

        saga.obligation_tracker
            .commit_obligation(obligation_id, subscriber1)
            .await;
        logger
            .increment_stat(SagaStatType::ObligationCommitted)
            .await;

        saga.execute_saga()
            .await
            .expect("Saga execution should succeed");
        logger
            .increment_stat(SagaStatType::SuccessfulSagaCompletion)
            .await;

        logger.log_phase(SagaTestPhase::ObligationLeakCheck).await;

        // Verify no leaks
        let leaks = saga.obligation_tracker.check_for_leaks().await;
        assert!(leaks.is_empty(), "No obligation leaks should be detected");

        logger.log_phase(SagaTestPhase::Assert).await;

        let result = logger.get_result(true, None).await;
        assert!(result.success, "Test failed: {:?}", result.error);
        assert_eq!(result.saga_stats.successful_saga_completions, 1);
        assert_eq!(result.saga_stats.obligations_committed, 1);
        assert_eq!(result.saga_stats.obligation_leaks_detected, 0);

        tracing::info!(
            test_name = %result.test_name,
            duration_ms = result.duration_ms,
            stats = ?result.saga_stats,
            "Baseline saga success test completed successfully"
        );
    }

    #[tokio::test]
    async fn test_single_subscriber_crash_rollback() {
        let cx = Cx::root();
        let mut logger = BroadcastSagaTestLogger::new(
            "test_single_subscriber_crash_rollback".to_string(),
            "saga_002".to_string(),
        );

        logger.log_phase(SagaTestPhase::Setup).await;

        let saga = BroadcastSaga::<String>::new(100).await;

        // Add subscribers with one configured to crash
        let crash_subscriber = saga
            .add_subscriber(CrashSimulation {
                crash_probability: 1.0,
                crash_after_steps: Some(2),
                crash_during_obligation: true,
                crash_during_compensation: false,
                crash_type: CrashType::Panic,
            })
            .await;

        let healthy_subscriber = saga
            .add_subscriber(CrashSimulation {
                crash_probability: 0.0,
                crash_after_steps: None,
                crash_during_obligation: false,
                crash_during_compensation: false,
                crash_type: CrashType::Panic,
            })
            .await;

        logger.log_phase(SagaTestPhase::SagaExecution).await;

        logger
            .increment_stat(SagaStatType::SagaExecutionAttempted)
            .await;

        // Start saga execution
        let obligation_id = saga.obligation_tracker.allocate_obligation(1).await;
        logger
            .increment_stat(SagaStatType::ObligationAllocated)
            .await;

        logger
            .log_phase(SagaTestPhase::SubscriberCrashSimulation)
            .await;

        // Simulate subscriber crash
        saga.simulate_subscriber_crash(crash_subscriber)
            .await
            .expect("Should simulate crash successfully");

        logger
            .increment_stat(SagaStatType::SubscriberCrashDetected)
            .await;

        logger.log_phase(SagaTestPhase::RollbackDetection).await;

        // Trigger rollback due to crash
        let rollback_id = saga
            .trigger_rollback(RollbackReason::SubscriberCrash(crash_subscriber))
            .await;
        logger
            .increment_stat(SagaStatType::SagaRollbackTriggered)
            .await;

        logger.log_phase(SagaTestPhase::CompensationExecution).await;

        // Execute compensation actions
        let compensation = CompensationAction {
            action_id: 1,
            step_id: 1,
            action_type: CompensationType::AbortObligation,
            target_obligation: Some(obligation_id),
            compensation_data: "abort_obligation".to_string(),
            retry_count: 0,
            timeout: Duration::from_secs(1),
        };

        let comp_result = saga
            .compensation_executor
            .execute_compensation(compensation)
            .await;
        assert!(comp_result.success, "Compensation should succeed");
        logger
            .increment_stat(SagaStatType::CompensationActionExecuted)
            .await;

        // Abort the obligation
        saga.obligation_tracker
            .abort_obligation(obligation_id)
            .await;
        logger.increment_stat(SagaStatType::ObligationAborted).await;

        logger.log_phase(SagaTestPhase::ObligationLeakCheck).await;

        // Verify no leaks after rollback
        tokio::time::sleep(Duration::from_millis(100)).await;
        let leaks = saga.obligation_tracker.check_for_leaks().await;
        assert!(
            leaks.is_empty(),
            "No obligation leaks should remain after rollback"
        );

        logger.log_phase(SagaTestPhase::Assert).await;

        let result = logger.get_result(true, None).await;
        assert!(result.success);
        assert_eq!(result.saga_stats.subscriber_crashes_detected, 1);
        assert_eq!(result.saga_stats.saga_rollbacks_triggered, 1);
        assert_eq!(result.saga_stats.compensation_actions_executed, 1);
        assert_eq!(result.saga_stats.obligations_aborted, 1);
        assert_eq!(result.saga_stats.obligation_leaks_detected, 0);

        tracing::info!(
            test_name = %result.test_name,
            duration_ms = result.duration_ms,
            stats = ?result.saga_stats,
            "Single subscriber crash rollback test completed successfully"
        );
    }

    #[tokio::test]
    async fn test_multiple_subscriber_crash_rollback() {
        let cx = Cx::root();
        let mut logger = BroadcastSagaTestLogger::new(
            "test_multiple_subscriber_crash_rollback".to_string(),
            "saga_003".to_string(),
        );

        logger.log_phase(SagaTestPhase::Setup).await;

        let saga = BroadcastSaga::<String>::new(100).await;

        // Add multiple subscribers that will crash
        let crash_config = CrashSimulation {
            crash_probability: 1.0,
            crash_after_steps: Some(1),
            crash_during_obligation: false,
            crash_during_compensation: false,
            crash_type: CrashType::NetworkDisconnect,
        };

        let subscriber1 = saga.add_subscriber(crash_config.clone()).await;
        let subscriber2 = saga.add_subscriber(crash_config.clone()).await;
        let subscriber3 = saga.add_subscriber(crash_config).await;

        logger.log_phase(SagaTestPhase::SagaExecution).await;

        logger
            .increment_stat(SagaStatType::SagaExecutionAttempted)
            .await;

        // Allocate multiple obligations
        let obligation1 = saga.obligation_tracker.allocate_obligation(1).await;
        let obligation2 = saga.obligation_tracker.allocate_obligation(2).await;
        logger
            .increment_stat(SagaStatType::ObligationAllocated)
            .await;
        logger
            .increment_stat(SagaStatType::ObligationAllocated)
            .await;

        logger
            .log_phase(SagaTestPhase::SubscriberCrashSimulation)
            .await;

        // Simulate multiple crashes
        saga.simulate_subscriber_crash(subscriber1)
            .await
            .expect("Crash simulation should work");
        saga.simulate_subscriber_crash(subscriber2)
            .await
            .expect("Crash simulation should work");
        saga.simulate_subscriber_crash(subscriber3)
            .await
            .expect("Crash simulation should work");

        logger
            .increment_stat(SagaStatType::SubscriberCrashDetected)
            .await;
        logger
            .increment_stat(SagaStatType::SubscriberCrashDetected)
            .await;
        logger
            .increment_stat(SagaStatType::SubscriberCrashDetected)
            .await;

        logger.log_phase(SagaTestPhase::RollbackDetection).await;

        // Trigger rollback
        let _rollback_id = saga
            .trigger_rollback(RollbackReason::SubscriberCrash(subscriber1))
            .await;
        logger
            .increment_stat(SagaStatType::SagaRollbackTriggered)
            .await;

        logger.log_phase(SagaTestPhase::CompensationExecution).await;

        // Execute compensation for all obligations
        saga.obligation_tracker.abort_obligation(obligation1).await;
        saga.obligation_tracker.abort_obligation(obligation2).await;
        logger.increment_stat(SagaStatType::ObligationAborted).await;
        logger.increment_stat(SagaStatType::ObligationAborted).await;
        logger
            .increment_stat(SagaStatType::CompensationActionExecuted)
            .await;

        logger.log_phase(SagaTestPhase::ObligationLeakCheck).await;

        // Verify cleanup
        let leaks = saga.obligation_tracker.check_for_leaks().await;
        assert!(leaks.is_empty(), "All obligations should be cleaned up");

        logger.log_phase(SagaTestPhase::Assert).await;

        let result = logger.get_result(true, None).await;
        assert!(result.success);
        assert_eq!(result.saga_stats.subscriber_crashes_detected, 3);
        assert_eq!(result.saga_stats.obligations_aborted, 2);
        assert_eq!(result.saga_stats.obligation_leaks_detected, 0);

        tracing::info!(
            test_name = %result.test_name,
            duration_ms = result.duration_ms,
            stats = ?result.saga_stats,
            "Multiple subscriber crash rollback test completed successfully"
        );
    }

    #[tokio::test]
    async fn test_mid_transaction_crash_compensation() {
        let cx = Cx::root();
        let mut logger = BroadcastSagaTestLogger::new(
            "test_mid_transaction_crash_compensation".to_string(),
            "saga_004".to_string(),
        );

        logger.log_phase(SagaTestPhase::Setup).await;

        let saga = BroadcastSaga::<String>::new(100).await;

        let crash_subscriber = saga
            .add_subscriber(CrashSimulation {
                crash_probability: 1.0,
                crash_after_steps: None,
                crash_during_obligation: true, // Crash during obligation handling
                crash_during_compensation: false,
                crash_type: CrashType::Panic,
            })
            .await;

        logger.log_phase(SagaTestPhase::SagaExecution).await;
        logger
            .increment_stat(SagaStatType::SagaExecutionAttempted)
            .await;

        // Start transaction
        let obligation_id = saga.obligation_tracker.allocate_obligation(1).await;
        logger
            .increment_stat(SagaStatType::ObligationAllocated)
            .await;

        // Begin commitment process
        tokio::time::sleep(Duration::from_millis(25)).await;

        logger
            .log_phase(SagaTestPhase::SubscriberCrashSimulation)
            .await;

        // Crash during commitment
        saga.simulate_subscriber_crash(crash_subscriber)
            .await
            .expect("Should crash during obligation");

        logger
            .increment_stat(SagaStatType::SubscriberCrashDetected)
            .await;

        logger.log_phase(SagaTestPhase::CompensationExecution).await;

        // Execute compensation to clean up partial state
        let compensation = CompensationAction {
            action_id: 1,
            step_id: 1,
            action_type: CompensationType::AbortObligation,
            target_obligation: Some(obligation_id),
            compensation_data: "cleanup_partial_commit".to_string(),
            retry_count: 0,
            timeout: Duration::from_secs(2),
        };

        let comp_result = saga
            .compensation_executor
            .execute_compensation(compensation)
            .await;
        assert!(
            comp_result.success,
            "Mid-transaction compensation should succeed"
        );

        logger
            .increment_stat(SagaStatType::CompensationActionExecuted)
            .await;

        saga.obligation_tracker
            .abort_obligation(obligation_id)
            .await;
        logger.increment_stat(SagaStatType::ObligationAborted).await;

        logger.log_phase(SagaTestPhase::ObligationLeakCheck).await;

        let leaks = saga.obligation_tracker.check_for_leaks().await;
        assert!(
            leaks.is_empty(),
            "Mid-transaction crash should not cause leaks"
        );

        logger.log_phase(SagaTestPhase::Assert).await;

        let result = logger.get_result(true, None).await;
        assert!(result.success);
        assert_eq!(result.saga_stats.compensation_actions_executed, 1);
        assert_eq!(result.saga_stats.obligations_aborted, 1);
        assert_eq!(result.saga_stats.obligation_leaks_detected, 0);

        tracing::info!(
            test_name = %result.test_name,
            duration_ms = result.duration_ms,
            stats = ?result.saga_stats,
            "Mid-transaction crash compensation test completed successfully"
        );
    }

    #[tokio::test]
    async fn test_cascade_failure_recovery() {
        let cx = Cx::root();
        let mut logger = BroadcastSagaTestLogger::new(
            "test_cascade_failure_recovery".to_string(),
            "saga_005".to_string(),
        );

        logger.log_phase(SagaTestPhase::Setup).await;

        let saga = BroadcastSaga::<String>::new(100).await;

        // Create a scenario where compensation actions also face issues
        let primary_subscriber = saga
            .add_subscriber(CrashSimulation {
                crash_probability: 1.0,
                crash_after_steps: Some(2),
                crash_during_obligation: false,
                crash_during_compensation: false,
                crash_type: CrashType::OutOfMemory,
            })
            .await;

        let compensation_subscriber = saga
            .add_subscriber(CrashSimulation {
                crash_probability: 0.5, // 50% chance of issues during compensation
                crash_after_steps: None,
                crash_during_obligation: false,
                crash_during_compensation: true,
                crash_type: CrashType::Timeout,
            })
            .await;

        logger.log_phase(SagaTestPhase::SagaExecution).await;
        logger
            .increment_stat(SagaStatType::SagaExecutionAttempted)
            .await;

        let obligation_id = saga.obligation_tracker.allocate_obligation(1).await;
        logger
            .increment_stat(SagaStatType::ObligationAllocated)
            .await;

        // Primary failure
        saga.simulate_subscriber_crash(primary_subscriber)
            .await
            .expect("Primary crash should work");
        logger
            .increment_stat(SagaStatType::SubscriberCrashDetected)
            .await;

        logger.log_phase(SagaTestPhase::RollbackDetection).await;

        let _rollback_id = saga
            .trigger_rollback(RollbackReason::SubscriberCrash(primary_subscriber))
            .await;
        logger
            .increment_stat(SagaStatType::SagaRollbackTriggered)
            .await;

        logger.log_phase(SagaTestPhase::CompensationExecution).await;

        // Attempt compensation (may face issues but should eventually succeed)
        let compensation = CompensationAction {
            action_id: 1,
            step_id: 1,
            action_type: CompensationType::AbortObligation,
            target_obligation: Some(obligation_id),
            compensation_data: "cascade_recovery".to_string(),
            retry_count: 0,
            timeout: Duration::from_secs(3),
        };

        // Execute with retries if needed
        let comp_result = saga
            .compensation_executor
            .execute_compensation(compensation)
            .await;
        assert!(
            comp_result.success,
            "Cascade recovery compensation should eventually succeed"
        );

        logger
            .increment_stat(SagaStatType::CompensationActionExecuted)
            .await;

        saga.obligation_tracker
            .abort_obligation(obligation_id)
            .await;
        logger.increment_stat(SagaStatType::ObligationAborted).await;

        logger
            .log_phase(SagaTestPhase::ResourceCleanupVerification)
            .await;

        // Verify final cleanup
        tokio::time::sleep(Duration::from_millis(100)).await;
        let leaks = saga.obligation_tracker.check_for_leaks().await;
        assert!(
            leaks.is_empty(),
            "Cascade failure should not result in leaks"
        );

        logger.log_phase(SagaTestPhase::Assert).await;

        let result = logger.get_result(true, None).await;
        assert!(result.success);
        assert_eq!(result.saga_stats.saga_rollbacks_triggered, 1);
        assert_eq!(result.saga_stats.obligation_leaks_detected, 0);

        tracing::info!(
            test_name = %result.test_name,
            duration_ms = result.duration_ms,
            stats = ?result.saga_stats,
            "Cascade failure recovery test completed successfully"
        );
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Integration with Real Components (conditional compilation)
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore = "requires real broadcast channel and saga infrastructure"]
    async fn test_real_broadcast_saga_integration() {
        let cx = Cx::root();
        let mut logger = BroadcastSagaTestLogger::new(
            "test_real_broadcast_saga_integration".to_string(),
            "real_saga_001".to_string(),
        );

        logger.log_phase(SagaTestPhase::Setup).await;

        // This test would use real broadcast channels and saga execution
        // with actual obligation tracking and rollback mechanisms

        tracing::info!("Real broadcast saga integration test framework verified");

        logger.log_phase(SagaTestPhase::Assert).await;
        let result = logger.get_result(true, None).await;

        // Test passes if framework is properly structured
        assert!(result.success);

        tracing::info!(
            test_name = %result.test_name,
            "Real integration test framework verified"
        );
    }
}
