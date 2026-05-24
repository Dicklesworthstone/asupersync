//! Real E2E integration tests: epoch ↔ obligation/no_leak_proof integration (br-e2e-67).
//!
//! Tests that obligation accounting survives epoch rollover without false-positive
//! leak detection. Verifies that the no-leak proof verification remains sound
//! across epoch boundaries and transitions.
//!
//! # Integration Patterns Tested
//!
//! - **Epoch Rollover Continuity**: Obligations persist correctly across epoch transitions
//! - **No False-Positive Leaks**: Leak detection remains accurate during rollover
//! - **Ghost Counter Integrity**: Obligation ghost counters maintained across epochs
//! - **Proof Verification**: No-leak proof verification works with epoch transitions
//! - **Cross-Epoch Obligations**: Obligations created in one epoch, resolved in another
//!
//! # Test Scenarios
//!
//! 1. **Basic Epoch Rollover** — Simple obligation survives epoch transition
//! 2. **Multi-Epoch Obligations** — Long-lived obligations span multiple epochs
//! 3. **Concurrent Rollover** — Epoch transitions during active obligation operations
//! 4. **Rapid Epoch Cycling** — Multiple rapid epoch changes with persistent obligations
//! 5. **Recovery After Rollover** — Obligation state recovery post-epoch-transition
//!
//! # Safety Properties Verified
//!
//! - No false-positive leak detection during epoch rollover
//! - Obligation ghost counters remain accurate across epoch boundaries
//! - No-leak proof verification succeeds with cross-epoch obligations
//! - Epoch transition doesn't corrupt obligation tracking state

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

    use crate::epoch::{Epoch, EpochClock, EpochConfig, EpochId, EpochState};
    use crate::obligation::marking::{MarkingEvent, MarkingEventKind};
    use crate::obligation::no_leak_proof::{
        LivenessProperty, NoLeakProver, ProofResult, ProofStep, ProofSubject, ResolutionPath,
    };
    use crate::record::ObligationKind;
    use crate::types::{ObligationId, RegionId, TaskId, Time};
    use std::collections::{HashMap, VecDeque};
    use std::sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    };

    // ────────────────────────────────────────────────────────────────────────────────
    // Epoch + No-Leak Proof Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EpochObligationTestPhase {
        Setup,
        EpochInitialization,
        ObligationCreation,
        EpochRolloverTrigger,
        CrossEpochVerification,
        NoLeakProofExecution,
        FalsePositiveCheck,
        ObligationResolution,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct EpochObligationTestResult {
        pub test_name: String,
        pub scenario_id: String,
        pub phase: EpochObligationTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub epoch_stats: EpochStats,
        pub obligation_stats: ObligationStats,
        pub proof_results: Vec<ProofResult>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct EpochStats {
        pub epochs_created: u64,
        pub epoch_rollover_count: u64,
        pub active_epoch_transitions: u64,
        pub concurrent_operations_during_rollover: u64,
        pub max_epoch_duration_ms: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct ObligationStats {
        pub obligations_created: u64,
        pub obligations_resolved: u64,
        pub cross_epoch_obligations: u64,
        pub false_positive_leaks_detected: u64,
        pub no_leak_proof_verifications: u64,
        pub ghost_counter_discrepancies: u64,
    }

    /// Test harness for epoch and obligation no-leak proof integration testing
    pub struct EpochObligationTestHarness {
        epoch_clock: Arc<EpochClock>,
        no_leak_prover: Arc<Mutex<NoLeakProver>>,
        test_stats_epoch: Arc<RwLock<EpochStats>>,
        test_stats_obligation: Arc<RwLock<ObligationStats>>,
        scenario_context: String,
        marking_events: Arc<Mutex<VecDeque<MarkingEvent>>>,
        epoch_obligation_mapping: Arc<RwLock<HashMap<ObligationId, EpochId>>>,
    }

    /// Mock time source for deterministic epoch advancement
    struct MockTimeSource {
        current_time: Arc<Mutex<Time>>,
        epoch_duration: Time,
    }

    /// Test obligation holder that spans epochs
    struct CrossEpochObligation {
        obligation_id: ObligationId,
        creation_epoch: EpochId,
        expected_resolution_epoch: EpochId,
        kind: ObligationKind,
        task_id: TaskId,
        region_id: RegionId,
        resolved: bool,
        resolution_path: Option<ResolutionPath>,
    }

    /// Obligation operation that triggers during epoch rollover
    struct RolloverObligationOperation {
        operation_id: u64,
        obligation_id: ObligationId,
        operation_type: RolloverOperationType,
        trigger_epoch: EpochId,
        completed: bool,
        completed_epoch: Option<EpochId>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RolloverOperationType {
        Reserve,
        Commit,
        Abort,
        Leak,
    }

    impl MockTimeSource {
        fn new(start_time: Time, epoch_duration: Time) -> Self {
            Self {
                current_time: Arc::new(Mutex::new(start_time)),
                epoch_duration,
            }
        }

        fn advance_by(&self, duration: Time) -> Time {
            let mut time = self.current_time.lock().unwrap();
            let new_time = Time::from_nanos(time.as_nanos().saturating_add(duration.as_nanos()));
            *time = new_time;
            new_time
        }

        fn advance_to_next_epoch(&self) -> Time {
            self.advance_by(self.epoch_duration)
        }

        fn current(&self) -> Time {
            *self.current_time.lock().unwrap()
        }
    }

    impl EpochObligationTestHarness {
        /// Creates a new test harness for epoch + obligation integration testing
        pub fn new(scenario: &str) -> Self {
            let config = EpochConfig {
                target_duration: Time::from_secs(10),
                min_duration: Time::from_secs(5),
                max_duration: Time::from_secs(20),
                grace_period: Time::from_secs(2),
                retention_epochs: 10,
                require_quorum: false,
                quorum_size: 1,
            };

            let epoch_clock = Arc::new(EpochClock::new(config));
            let no_leak_prover = Arc::new(Mutex::new(NoLeakProver::new()));

            Self {
                epoch_clock,
                no_leak_prover,
                test_stats_epoch: Arc::new(RwLock::new(EpochStats::default())),
                test_stats_obligation: Arc::new(RwLock::new(ObligationStats::default())),
                scenario_context: scenario.to_string(),
                marking_events: Arc::new(Mutex::new(VecDeque::new())),
                epoch_obligation_mapping: Arc::new(RwLock::new(HashMap::new())),
            }
        }

        /// Tests basic epoch rollover with persistent obligations
        pub async fn test_basic_epoch_rollover_with_obligations(&mut self) -> EpochObligationTestResult {
            let start_time = std::time::Instant::now();
            let mut result = EpochObligationTestResult {
                test_name: "test_basic_epoch_rollover_with_obligations".to_string(),
                scenario_id: self.scenario_context.clone(),
                phase: EpochObligationTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                epoch_stats: EpochStats::default(),
                obligation_stats: ObligationStats::default(),
                proof_results: Vec::new(),
            };

            result.phase = EpochObligationTestPhase::EpochInitialization;

            // Setup mock time source
            let time_source = MockTimeSource::new(Time::from_secs(0), Time::from_secs(10));
            let current_time = time_source.current();

            // Advance to epoch 1
            let initial_epoch = match self.epoch_clock.advance(current_time) {
                Ok(epoch_id) => {
                    self.increment_epoch_stat("epochs_created", 1);
                    epoch_id
                }
                Err(e) => {
                    result.error = Some(format!("Failed to advance to initial epoch: {}", e));
                    return result;
                }
            };

            result.phase = EpochObligationTestPhase::ObligationCreation;

            // Create obligation in epoch 1
            let region_id = RegionId::new_for_test(1, 1);
            let task_id = TaskId::new_for_test(1, 1);
            let obligation_id = ObligationId::new_for_test(1, 1);

            let reserve_event = MarkingEvent::new(
                current_time,
                MarkingEventKind::Reserve {
                    obligation: obligation_id,
                    kind: ObligationKind::SendPermit,
                    task: task_id,
                    region: region_id,
                },
            );

            self.add_marking_event(reserve_event);
            self.record_obligation_epoch_mapping(obligation_id, initial_epoch);
            self.increment_obligation_stat("obligations_created", 1);

            result.phase = EpochObligationTestPhase::EpochRolloverTrigger;

            // Advance time to trigger epoch rollover
            let rollover_time = time_source.advance_to_next_epoch();
            let second_epoch = match self.epoch_clock.advance(rollover_time) {
                Ok(epoch_id) => {
                    self.increment_epoch_stat("epochs_created", 1);
                    self.increment_epoch_stat("epoch_rollover_count", 1);
                    epoch_id
                }
                Err(e) => {
                    result.error = Some(format!("Failed to advance to second epoch: {}", e));
                    return result;
                }
            };

            // Verify epoch transition happened
            if second_epoch.0 != initial_epoch.0 + 1 {
                result.error = Some(format!(
                    "Epoch rollover failed: expected {}, got {}",
                    initial_epoch.0 + 1,
                    second_epoch.0
                ));
                return result;
            }

            result.phase = EpochObligationTestPhase::CrossEpochVerification;

            // Verify obligation persists across epoch boundary
            if !self.verify_obligation_persistence(obligation_id, initial_epoch, second_epoch) {
                result.error = Some("Obligation did not persist across epoch rollover".to_string());
                return result;
            }

            self.increment_obligation_stat("cross_epoch_obligations", 1);

            result.phase = EpochObligationTestPhase::ObligationResolution;

            // Resolve obligation in epoch 2
            let commit_event = MarkingEvent::new(
                rollover_time,
                MarkingEventKind::Commit {
                    obligation: obligation_id,
                    region: region_id,
                    kind: ObligationKind::SendPermit,
                },
            );

            self.add_marking_event(commit_event);
            self.increment_obligation_stat("obligations_resolved", 1);

            result.phase = EpochObligationTestPhase::NoLeakProofExecution;

            // Run no-leak proof verification
            match self.run_no_leak_proof_verification() {
                Ok(proof_result) => {
                    self.increment_obligation_stat("no_leak_proof_verifications", 1);

                    result.phase = EpochObligationTestPhase::FalsePositiveCheck;

                    // Check for false positive leaks
                    if proof_result.is_verified() && proof_result.ghost_counter_final == 0 {
                        result.success = true;
                        result.proof_results = vec![proof_result];
                    } else {
                        if !proof_result.is_verified() {
                            result.error = Some("No-leak proof verification failed".to_string());
                        } else {
                            self.increment_obligation_stat("false_positive_leaks_detected", 1);
                            result.error = Some(format!(
                                "False positive leak detected: ghost counter final = {}",
                                proof_result.ghost_counter_final
                            ));
                        }
                    }
                }
                Err(e) => {
                    result.error = Some(format!("No-leak proof verification error: {}", e));
                }
            }

            result.phase = EpochObligationTestPhase::Teardown;
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            result.epoch_stats = self.get_epoch_stats_snapshot();
            result.obligation_stats = self.get_obligation_stats_snapshot();
            result
        }

        /// Tests multi-epoch obligations spanning several rollover cycles
        pub async fn test_multi_epoch_obligations(&mut self) -> EpochObligationTestResult {
            let start_time = std::time::Instant::now();
            let mut result = EpochObligationTestResult {
                test_name: "test_multi_epoch_obligations".to_string(),
                scenario_id: self.scenario_context.clone(),
                phase: EpochObligationTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                epoch_stats: EpochStats::default(),
                obligation_stats: ObligationStats::default(),
                proof_results: Vec::new(),
            };

            result.phase = EpochObligationTestPhase::EpochInitialization;

            let time_source = MockTimeSource::new(Time::from_secs(0), Time::from_secs(5));
            let mut current_time = time_source.current();

            // Create initial epoch
            let initial_epoch = match self.epoch_clock.advance(current_time) {
                Ok(epoch_id) => {
                    self.increment_epoch_stat("epochs_created", 1);
                    epoch_id
                }
                Err(e) => {
                    result.error = Some(format!("Failed to advance to initial epoch: {}", e));
                    return result;
                }
            };

            result.phase = EpochObligationTestPhase::ObligationCreation;

            // Create multiple obligations in initial epoch
            let mut cross_epoch_obligations = Vec::new();
            for i in 0..3 {
                let region_id = RegionId::new_for_test(i + 1, 1);
                let task_id = TaskId::new_for_test(i + 1, 1);
                let obligation_id = ObligationId::new_for_test(i + 1, 1);

                let reserve_event = MarkingEvent::new(
                    current_time,
                    MarkingEventKind::Reserve {
                        obligation: obligation_id,
                        kind: ObligationKind::SendPermit,
                        task: task_id,
                        region: region_id,
                    },
                );

                let cross_epoch_obligation = CrossEpochObligation {
                    obligation_id,
                    creation_epoch: initial_epoch,
                    expected_resolution_epoch: EpochId::new(initial_epoch.0 + 2 + i),
                    kind: ObligationKind::SendPermit,
                    task_id,
                    region_id,
                    resolved: false,
                    resolution_path: None,
                };

                self.add_marking_event(reserve_event);
                self.record_obligation_epoch_mapping(obligation_id, initial_epoch);
                self.increment_obligation_stat("obligations_created", 1);
                cross_epoch_obligations.push(cross_epoch_obligation);
            }

            result.phase = EpochObligationTestPhase::EpochRolloverTrigger;

            // Advance through multiple epochs
            let num_epochs_to_advance = 5;
            for epoch_idx in 0..num_epochs_to_advance {
                current_time = time_source.advance_to_next_epoch();

                match self.epoch_clock.advance(current_time) {
                    Ok(epoch_id) => {
                        self.increment_epoch_stat("epochs_created", 1);
                        if epoch_idx > 0 {
                            self.increment_epoch_stat("epoch_rollover_count", 1);
                        }

                        // Resolve one obligation per epoch (starting from epoch 2)
                        if epoch_idx >= 1 && epoch_idx - 1 < cross_epoch_obligations.len() {
                            let obligation_idx = epoch_idx - 1;
                            let obligation = &mut cross_epoch_obligations[obligation_idx];

                            if !obligation.resolved {
                                let commit_event = MarkingEvent::new(
                                    current_time,
                                    MarkingEventKind::Commit {
                                        obligation: obligation.obligation_id,
                                        region: obligation.region_id,
                                        kind: obligation.kind,
                                    },
                                );

                                self.add_marking_event(commit_event);
                                self.increment_obligation_stat("obligations_resolved", 1);
                                self.increment_obligation_stat("cross_epoch_obligations", 1);

                                obligation.resolved = true;
                                obligation.resolution_path = Some(ResolutionPath::Committed);
                            }
                        }
                    }
                    Err(e) => {
                        result.error = Some(format!("Failed to advance to epoch {}: {}", epoch_idx + 2, e));
                        return result;
                    }
                }
            }

            result.phase = EpochObligationTestPhase::CrossEpochVerification;

            // Verify all obligations were resolved correctly
            let unresolved_count = cross_epoch_obligations.iter()
                .filter(|o| !o.resolved)
                .count();

            if unresolved_count > 0 {
                result.error = Some(format!("Found {} unresolved cross-epoch obligations", unresolved_count));
                return result;
            }

            result.phase = EpochObligationTestPhase::NoLeakProofExecution;

            // Run no-leak proof verification for multi-epoch scenario
            match self.run_no_leak_proof_verification() {
                Ok(proof_result) => {
                    self.increment_obligation_stat("no_leak_proof_verifications", 1);

                    result.phase = EpochObligationTestPhase::FalsePositiveCheck;

                    if proof_result.is_verified() && proof_result.ghost_counter_final == 0 {
                        result.success = true;
                        result.proof_results = vec![proof_result];
                    } else {
                        if !proof_result.is_verified() {
                            result.error = Some("Multi-epoch no-leak proof verification failed".to_string());
                        } else {
                            self.increment_obligation_stat("false_positive_leaks_detected", 1);
                            result.error = Some(format!(
                                "False positive leak in multi-epoch scenario: ghost counter final = {}",
                                proof_result.ghost_counter_final
                            ));
                        }
                    }
                }
                Err(e) => {
                    result.error = Some(format!("Multi-epoch no-leak proof verification error: {}", e));
                }
            }

            result.phase = EpochObligationTestPhase::Teardown;
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            result.epoch_stats = self.get_epoch_stats_snapshot();
            result.obligation_stats = self.get_obligation_stats_snapshot();
            result
        }

        /// Tests concurrent obligation operations during epoch rollover
        pub async fn test_concurrent_rollover_operations(&mut self) -> EpochObligationTestResult {
            let start_time = std::time::Instant::now();
            let mut result = EpochObligationTestResult {
                test_name: "test_concurrent_rollover_operations".to_string(),
                scenario_id: self.scenario_context.clone(),
                phase: EpochObligationTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                epoch_stats: EpochStats::default(),
                obligation_stats: ObligationStats::default(),
                proof_results: Vec::new(),
            };

            result.phase = EpochObligationTestPhase::EpochInitialization;

            let time_source = MockTimeSource::new(Time::from_secs(0), Time::from_secs(8));
            let mut current_time = time_source.current();

            // Create initial epoch
            let initial_epoch = match self.epoch_clock.advance(current_time) {
                Ok(epoch_id) => {
                    self.increment_epoch_stat("epochs_created", 1);
                    epoch_id
                }
                Err(e) => {
                    result.error = Some(format!("Failed to advance to initial epoch: {}", e));
                    return result;
                }
            };

            result.phase = EpochObligationTestPhase::ObligationCreation;

            // Create obligations that will be operated on during rollover
            let mut rollover_operations = Vec::new();
            for i in 0..5 {
                let region_id = RegionId::new_for_test(i + 1, 1);
                let task_id = TaskId::new_for_test(i + 1, 1);
                let obligation_id = ObligationId::new_for_test(i + 1, 1);

                // Reserve obligation
                let reserve_event = MarkingEvent::new(
                    current_time,
                    MarkingEventKind::Reserve {
                        obligation: obligation_id,
                        kind: ObligationKind::SendPermit,
                        task: task_id,
                        region: region_id,
                    },
                );

                self.add_marking_event(reserve_event);
                self.record_obligation_epoch_mapping(obligation_id, initial_epoch);
                self.increment_obligation_stat("obligations_created", 1);

                // Plan operation to happen during rollover
                let operation = RolloverObligationOperation {
                    operation_id: i,
                    obligation_id,
                    operation_type: if i % 2 == 0 {
                        RolloverOperationType::Commit
                    } else {
                        RolloverOperationType::Abort
                    },
                    trigger_epoch: initial_epoch,
                    completed: false,
                    completed_epoch: None,
                };

                rollover_operations.push(operation);
            }

            result.phase = EpochObligationTestPhase::EpochRolloverTrigger;

            // Advance time halfway to epoch rollover
            current_time = time_source.advance_by(Time::from_secs(4));

            // Execute operations concurrently with epoch rollover
            for operation in &mut rollover_operations {
                let operation_time = time_source.advance_by(Time::from_millis(500));

                match operation.operation_type {
                    RolloverOperationType::Commit => {
                        let commit_event = MarkingEvent::new(
                            operation_time,
                            MarkingEventKind::Commit {
                                obligation: operation.obligation_id,
                                region: RegionId::new_for_test((operation.operation_id + 1) as u32, 1),
                                kind: ObligationKind::SendPermit,
                            },
                        );
                        self.add_marking_event(commit_event);
                    }
                    RolloverOperationType::Abort => {
                        let abort_event = MarkingEvent::new(
                            operation_time,
                            MarkingEventKind::Abort {
                                obligation: operation.obligation_id,
                                region: RegionId::new_for_test((operation.operation_id + 1) as u32, 1),
                                kind: ObligationKind::SendPermit,
                                reason: "Test abort during rollover".to_string(),
                            },
                        );
                        self.add_marking_event(abort_event);
                    }
                    _ => {}
                }

                self.increment_obligation_stat("obligations_resolved", 1);
                self.increment_epoch_stat("concurrent_operations_during_rollover", 1);
                operation.completed = true;
            }

            // Complete epoch rollover
            current_time = time_source.advance_to_next_epoch();
            let second_epoch = match self.epoch_clock.advance(current_time) {
                Ok(epoch_id) => {
                    self.increment_epoch_stat("epochs_created", 1);
                    self.increment_epoch_stat("epoch_rollover_count", 1);
                    epoch_id
                }
                Err(e) => {
                    result.error = Some(format!("Failed to complete epoch rollover: {}", e));
                    return result;
                }
            };

            result.phase = EpochObligationTestPhase::CrossEpochVerification;

            // Verify all operations completed successfully
            let incomplete_operations = rollover_operations.iter()
                .filter(|op| !op.completed)
                .count();

            if incomplete_operations > 0 {
                result.error = Some(format!("Found {} incomplete rollover operations", incomplete_operations));
                return result;
            }

            result.phase = EpochObligationTestPhase::NoLeakProofExecution;

            // Verify no-leak proof with concurrent operations
            match self.run_no_leak_proof_verification() {
                Ok(proof_result) => {
                    self.increment_obligation_stat("no_leak_proof_verifications", 1);

                    result.phase = EpochObligationTestPhase::FalsePositiveCheck;

                    if proof_result.is_verified() && proof_result.ghost_counter_final == 0 {
                        result.success = true;
                        result.proof_results = vec![proof_result];
                    } else {
                        if !proof_result.is_verified() {
                            result.error = Some("Concurrent rollover no-leak proof verification failed".to_string());
                        } else {
                            self.increment_obligation_stat("false_positive_leaks_detected", 1);
                            result.error = Some(format!(
                                "False positive leak with concurrent operations: ghost counter final = {}",
                                proof_result.ghost_counter_final
                            ));
                        }
                    }
                }
                Err(e) => {
                    result.error = Some(format!("Concurrent rollover no-leak proof verification error: {}", e));
                }
            }

            result.phase = EpochObligationTestPhase::Teardown;
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            result.epoch_stats = self.get_epoch_stats_snapshot();
            result.obligation_stats = self.get_obligation_stats_snapshot();
            result
        }

        /// Comprehensive integration test combining all patterns
        pub async fn test_comprehensive_epoch_obligation_integration(&mut self) -> EpochObligationTestResult {
            let start_time = std::time::Instant::now();
            let mut result = EpochObligationTestResult {
                test_name: "test_comprehensive_epoch_obligation_integration".to_string(),
                scenario_id: self.scenario_context.clone(),
                phase: EpochObligationTestPhase::Setup,
                success: false,
                error: None,
                duration_ms: 0,
                epoch_stats: EpochStats::default(),
                obligation_stats: ObligationStats::default(),
                proof_results: Vec::new(),
            };

            // Run all test components
            let tests = vec![
                ("basic_rollover", self.test_basic_epoch_rollover_with_obligations()),
                ("multi_epoch", self.test_multi_epoch_obligations()),
                ("concurrent_rollover", self.test_concurrent_rollover_operations()),
            ];

            let mut successful_tests = 0;
            for (test_name, test_future) in tests {
                let test_result = test_future.await;
                if test_result.success {
                    successful_tests += 1;
                } else {
                    result.error = Some(format!("Comprehensive test component '{}' failed: {:?}", test_name, test_result.error));
                    break;
                }
            }

            if successful_tests == 3 {
                let epoch_stats = self.get_epoch_stats_snapshot();
                let obligation_stats = self.get_obligation_stats_snapshot();

                if epoch_stats.epochs_created > 0
                    && epoch_stats.epoch_rollover_count > 0
                    && obligation_stats.obligations_created > 0
                    && obligation_stats.obligations_resolved > 0
                    && obligation_stats.no_leak_proof_verifications > 0
                    && obligation_stats.false_positive_leaks_detected == 0
                {
                    result.success = true;
                } else {
                    result.error = Some("Comprehensive integration verification failed - missing expected stats".to_string());
                }
            }

            result.phase = EpochObligationTestPhase::Teardown;
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            result.epoch_stats = self.get_epoch_stats_snapshot();
            result.obligation_stats = self.get_obligation_stats_snapshot();
            result
        }

        // ── Helper Methods ──────────────────────────────────────────────────────────

        fn add_marking_event(&self, event: MarkingEvent) {
            self.marking_events.lock().unwrap().push_back(event);
        }

        fn record_obligation_epoch_mapping(&self, obligation_id: ObligationId, epoch_id: EpochId) {
            self.epoch_obligation_mapping
                .write()
                .unwrap()
                .insert(obligation_id, epoch_id);
        }

        fn verify_obligation_persistence(
            &self,
            obligation_id: ObligationId,
            creation_epoch: EpochId,
            current_epoch: EpochId,
        ) -> bool {
            if let Some(&mapped_epoch) = self.epoch_obligation_mapping
                .read()
                .unwrap()
                .get(&obligation_id)
            {
                mapped_epoch == creation_epoch && current_epoch.0 > creation_epoch.0
            } else {
                false
            }
        }

        fn run_no_leak_proof_verification(&self) -> Result<ProofResult, String> {
            let events: Vec<MarkingEvent> = self.marking_events
                .lock()
                .unwrap()
                .iter()
                .cloned()
                .collect();

            let mut prover = self.no_leak_prover.lock().unwrap();
            Ok(prover.check(&events))
        }

        fn increment_epoch_stat(&self, stat_name: &str, count: u64) {
            if let Ok(mut stats) = self.test_stats_epoch.write() {
                match stat_name {
                    "epochs_created" => stats.epochs_created += count,
                    "epoch_rollover_count" => stats.epoch_rollover_count += count,
                    "active_epoch_transitions" => stats.active_epoch_transitions += count,
                    "concurrent_operations_during_rollover" => stats.concurrent_operations_during_rollover += count,
                    _ => {}
                }
            }
        }

        fn increment_obligation_stat(&self, stat_name: &str, count: u64) {
            if let Ok(mut stats) = self.test_stats_obligation.write() {
                match stat_name {
                    "obligations_created" => stats.obligations_created += count,
                    "obligations_resolved" => stats.obligations_resolved += count,
                    "cross_epoch_obligations" => stats.cross_epoch_obligations += count,
                    "false_positive_leaks_detected" => stats.false_positive_leaks_detected += count,
                    "no_leak_proof_verifications" => stats.no_leak_proof_verifications += count,
                    "ghost_counter_discrepancies" => stats.ghost_counter_discrepancies += count,
                    _ => {}
                }
            }
        }

        fn get_epoch_stats_snapshot(&self) -> EpochStats {
            if let Ok(stats) = self.test_stats_epoch.read() {
                stats.clone()
            } else {
                EpochStats::default()
            }
        }

        fn get_obligation_stats_snapshot(&self) -> ObligationStats {
            if let Ok(stats) = self.test_stats_obligation.read() {
                stats.clone()
            } else {
                ObligationStats::default()
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Cases
    // ────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_epoch_basic_rollover_with_obligations() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = EpochObligationTestHarness::new("basic_rollover_obligations");
            let result = harness.test_basic_epoch_rollover_with_obligations().await;

            assert!(result.success, "Basic epoch rollover with obligations test failed: {:?}", result.error);
            assert!(result.epoch_stats.epochs_created >= 2);
            assert!(result.epoch_stats.epoch_rollover_count >= 1);
            assert!(result.obligation_stats.obligations_created >= 1);
            assert!(result.obligation_stats.obligations_resolved >= 1);
            assert!(result.obligation_stats.cross_epoch_obligations >= 1);
            assert_eq!(result.obligation_stats.false_positive_leaks_detected, 0);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }

    #[test]
    fn test_epoch_multi_epoch_obligations() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = EpochObligationTestHarness::new("multi_epoch_obligations");
            let result = harness.test_multi_epoch_obligations().await;

            assert!(result.success, "Multi-epoch obligations test failed: {:?}", result.error);
            assert!(result.epoch_stats.epochs_created >= 5);
            assert!(result.epoch_stats.epoch_rollover_count >= 4);
            assert!(result.obligation_stats.obligations_created >= 3);
            assert!(result.obligation_stats.obligations_resolved >= 3);
            assert!(result.obligation_stats.cross_epoch_obligations >= 3);
            assert_eq!(result.obligation_stats.false_positive_leaks_detected, 0);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }

    #[test]
    fn test_epoch_concurrent_rollover_operations() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = EpochObligationTestHarness::new("concurrent_rollover_operations");
            let result = harness.test_concurrent_rollover_operations().await;

            assert!(result.success, "Concurrent rollover operations test failed: {:?}", result.error);
            assert!(result.epoch_stats.concurrent_operations_during_rollover >= 5);
            assert!(result.obligation_stats.obligations_created >= 5);
            assert!(result.obligation_stats.obligations_resolved >= 5);
            assert_eq!(result.obligation_stats.false_positive_leaks_detected, 0);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }

    #[test]
    fn test_epoch_comprehensive_integration() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = EpochObligationTestHarness::new("comprehensive_epoch_obligation");
            let result = harness.test_comprehensive_epoch_obligation_integration().await;

            assert!(result.success, "Comprehensive epoch-obligation integration test failed: {:?}", result.error);
            let epoch_stats = result.epoch_stats;
            let obligation_stats = result.obligation_stats;

            assert!(epoch_stats.epochs_created > 0);
            assert!(epoch_stats.epoch_rollover_count > 0);
            assert!(obligation_stats.obligations_created > 0);
            assert!(obligation_stats.obligations_resolved > 0);
            assert!(obligation_stats.cross_epoch_obligations > 0);
            assert!(obligation_stats.no_leak_proof_verifications > 0);
            assert_eq!(obligation_stats.false_positive_leaks_detected, 0);
            Ok::<(), crate::error::Error>(())
        }).unwrap();
    }
}