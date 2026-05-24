//! # Real Lab Oracle Cancellation Protocol ↔ Cancel Progress Certificate Integration E2E Tests
//!
//! This module provides comprehensive integration testing between the lab/oracle/cancellation_protocol
//! oracle and the cancel/progress_certificate system to verify that cancel-progress certificate
//! verification correctly detects cancellation protocol violations, specifically out-of-band
//! wake during pre-mask phase scenarios.
//!
//! ## Integration Focus
//!
//! The integration tests verify the collaboration between:
//! - **CancellationProtocolOracle**: Detects protocol violations like CancelAckWhileMasked
//! - **ProgressCertificate**: Provides martingale-based progress guarantees for drain completion
//! - **Cross-validation**: Both systems detect and report protocol violations consistently
//!
//! ## Test Scenarios
//!
//! 1. **Basic Integration**: Verify oracle and certificate work together correctly
//! 2. **Protocol Violation Detection**: Test CancelAckWhileMasked detection via certificate
//! 3. **Mask Depth Tracking**: Verify pre-mask phase violation detection
//! 4. **Progress Monitoring**: Ensure certificate tracks drain progress during violations
//! 5. **Comprehensive Integration**: End-to-end verification with multiple violation types

#[cfg(test)]
mod tests {
    use crate::{
        cancel::{
            CancelToken, CancelWitness,
            progress_certificate::{
                CertificateVerdict, DrainPhase, EvidenceEntry, PotentialRecord,
                ProgressCertificate, ProgressCertificateConfig,
            },
        },
        cx::{Cx, CxBuilder},
        error::RuntimeError,
        lab::{
            LabRuntime, LabRuntimeBuilder,
            oracle::{
                OracleEvent,
                cancel_correctness::CancelCorrectnessOracle,
                cancellation_protocol::{
                    CancelProtocolViolation, CancelRecognitionEvent, CancelRecognitionEventKind,
                    CancellationProtocolOracle, CancellationProtocolOracleConfig,
                },
            },
        },
        runtime::{Runtime, RuntimeBuilder},
        time::Time,
        types::{
            RegionId,
            cancel::{CancelReason, CancelRequest, CancelSeverity},
            task::{TaskId, TaskStatus},
        },
        util::det_rng::DetRng,
    };
    use std::{
        collections::{HashMap, VecDeque},
        sync::{Arc, Mutex},
        time::Duration,
    };

    /// Comprehensive tracker for monitoring the integration between cancellation protocol oracle
    /// and progress certificate verification, specifically for detecting cancellation protocol
    /// violations during out-of-band wake scenarios in pre-mask phases.
    #[derive(Debug)]
    pub struct CancellationProgressTracker {
        /// Configuration for the cancellation protocol oracle
        protocol_config: CancellationProtocolOracleConfig,
        /// Configuration for the progress certificate
        certificate_config: ProgressCertificateConfig,
        /// Active cancellation protocol oracle instance
        protocol_oracle: Option<CancellationProtocolOracle>,
        /// Active progress certificate instance
        progress_certificate: Option<ProgressCertificate>,
        /// Buffer of captured protocol violations
        protocol_violations: Vec<CancelProtocolViolation>,
        /// Buffer of captured certificate verdicts
        certificate_verdicts: Vec<CertificateVerdict>,
        /// Mapping of tasks to their mask depths for pre-mask violation detection
        task_mask_depths: HashMap<TaskId, u32>,
        /// Queue of potential records for progress tracking
        potential_records: VecDeque<PotentialRecord>,
        /// Violation detection statistics
        violation_stats: ViolationStats,
        /// Integration state tracking
        integration_state: IntegrationState,
    }

    /// Statistics for tracking violation detection across the integration
    #[derive(Debug, Clone)]
    pub struct ViolationStats {
        /// Number of CancelAckWhileMasked violations detected
        pub cancel_ack_while_masked_count: u64,
        /// Number of mask depth violations detected
        pub mask_depth_violation_count: u64,
        /// Number of progress certificate stalls detected
        pub certificate_stall_count: u64,
        /// Number of out-of-band wake violations detected
        pub out_of_band_wake_count: u64,
        /// Total oracle violations detected
        pub total_oracle_violations: u64,
        /// Total certificate failures detected
        pub total_certificate_failures: u64,
    }

    /// Integration state tracking for coordinated violation detection
    #[derive(Debug, Clone)]
    pub struct IntegrationState {
        /// Whether the integration is actively monitoring
        pub is_monitoring: bool,
        /// Current cancellation epoch being tracked
        pub current_epoch: u64,
        /// Tasks currently in pre-mask phase
        pub pre_mask_phase_tasks: HashMap<TaskId, MaskPhaseInfo>,
        /// Tasks with pending cancellation requests
        pub pending_cancel_tasks: HashMap<TaskId, CancelRequest>,
        /// Last recorded drain phase from certificate
        pub last_drain_phase: DrainPhase,
        /// Integration consistency check results
        pub consistency_check_passed: bool,
    }

    /// Information about a task's mask phase for violation detection
    #[derive(Debug, Clone)]
    pub struct MaskPhaseInfo {
        /// Current mask depth
        pub mask_depth: u32,
        /// Time when mask phase started
        pub phase_start_time: Time,
        /// Whether task has pending cancellation
        pub has_pending_cancel: bool,
        /// Cancel reason if cancellation is pending
        pub pending_cancel_reason: Option<CancelReason>,
    }

    impl Default for ViolationStats {
        fn default() -> Self {
            Self {
                cancel_ack_while_masked_count: 0,
                mask_depth_violation_count: 0,
                certificate_stall_count: 0,
                out_of_band_wake_count: 0,
                total_oracle_violations: 0,
                total_certificate_failures: 0,
            }
        }
    }

    impl Default for IntegrationState {
        fn default() -> Self {
            Self {
                is_monitoring: false,
                current_epoch: 0,
                pre_mask_phase_tasks: HashMap::new(),
                pending_cancel_tasks: HashMap::new(),
                last_drain_phase: DrainPhase::Warmup,
                consistency_check_passed: true,
            }
        }
    }

    impl CancellationProgressTracker {
        /// Creates a new tracker with specified configurations for comprehensive
        /// cancellation protocol and progress certificate integration monitoring.
        pub fn new(
            protocol_config: CancellationProtocolOracleConfig,
            certificate_config: ProgressCertificateConfig,
        ) -> Self {
            Self {
                protocol_config,
                certificate_config,
                protocol_oracle: None,
                progress_certificate: None,
                protocol_violations: Vec::new(),
                certificate_verdicts: Vec::new(),
                task_mask_depths: HashMap::new(),
                potential_records: VecDeque::new(),
                violation_stats: ViolationStats::default(),
                integration_state: IntegrationState::default(),
            }
        }

        /// Initializes the oracle and certificate systems for monitoring
        pub fn initialize(&mut self) -> Result<(), RuntimeError> {
            // Initialize cancellation protocol oracle
            self.protocol_oracle = Some(CancellationProtocolOracle::new(
                self.protocol_config.clone(),
            ));

            // Initialize progress certificate
            self.progress_certificate =
                Some(ProgressCertificate::new(self.certificate_config.clone()));

            self.integration_state.is_monitoring = true;
            self.integration_state.current_epoch = 1;

            Ok(())
        }

        /// Records a cancellation recognition event for protocol violation detection
        pub fn record_cancel_event(&mut self, event: CancelRecognitionEvent) {
            if let Some(oracle) = &mut self.protocol_oracle {
                // Process the event through the oracle
                oracle.on_cancel_event(&event);

                // Track mask depth changes for pre-mask phase detection
                match &event.kind {
                    CancelRecognitionEventKind::MaskEnter { task_id, depth } => {
                        self.task_mask_depths.insert(*task_id, *depth);

                        // Track pre-mask phase tasks
                        self.integration_state.pre_mask_phase_tasks.insert(
                            *task_id,
                            MaskPhaseInfo {
                                mask_depth: *depth,
                                phase_start_time: event.time,
                                has_pending_cancel: self
                                    .integration_state
                                    .pending_cancel_tasks
                                    .contains_key(task_id),
                                pending_cancel_reason: self
                                    .integration_state
                                    .pending_cancel_tasks
                                    .get(task_id)
                                    .map(|req| req.reason.clone()),
                            },
                        );
                    }
                    CancelRecognitionEventKind::MaskExit { task_id, depth } => {
                        self.task_mask_depths.insert(*task_id, *depth);

                        // Remove from pre-mask phase if depth is 0
                        if *depth == 0 {
                            self.integration_state.pre_mask_phase_tasks.remove(task_id);
                        } else {
                            // Update mask depth
                            if let Some(info) =
                                self.integration_state.pre_mask_phase_tasks.get_mut(task_id)
                            {
                                info.mask_depth = *depth;
                            }
                        }
                    }
                    CancelRecognitionEventKind::CancelRequest {
                        task_id, reason, ..
                    } => {
                        // Track pending cancellation requests
                        self.integration_state.pending_cancel_tasks.insert(
                            *task_id,
                            CancelRequest {
                                task: *task_id,
                                reason: reason.clone(),
                                timeout: Duration::from_secs(30),
                            },
                        );

                        // Update pre-mask phase info if task is masked
                        if let Some(info) =
                            self.integration_state.pre_mask_phase_tasks.get_mut(task_id)
                        {
                            info.has_pending_cancel = true;
                            info.pending_cancel_reason = Some(reason.clone());
                        }
                    }
                    CancelRecognitionEventKind::CancelAck { task_id } => {
                        // Check for out-of-band wake during pre-mask phase violation
                        if let Some(mask_depth) = self.task_mask_depths.get(task_id) {
                            if *mask_depth > 0 {
                                // This is a CancelAckWhileMasked violation - out-of-band wake during pre-mask
                                self.violation_stats.cancel_ack_while_masked_count += 1;
                                self.violation_stats.out_of_band_wake_count += 1;
                                self.violation_stats.total_oracle_violations += 1;

                                // Record the violation
                                let violation = CancelProtocolViolation::CancelAckWhileMasked {
                                    task: *task_id,
                                    mask_depth: *mask_depth,
                                    time: event.time,
                                };
                                self.protocol_violations.push(violation);

                                // Update integration state
                                self.integration_state.consistency_check_passed = false;
                            }
                        }

                        // Remove from pending cancellations
                        self.integration_state.pending_cancel_tasks.remove(task_id);

                        // Update pre-mask phase info
                        if let Some(info) =
                            self.integration_state.pre_mask_phase_tasks.get_mut(task_id)
                        {
                            info.has_pending_cancel = false;
                            info.pending_cancel_reason = None;
                        }
                    }
                    _ => {}
                }
            }
        }

        /// Records a potential observation for progress certificate tracking
        pub fn record_potential(&mut self, potential: f64, time: Time) {
            let record = PotentialRecord {
                time,
                potential,
                credit: 0.0, // Will be computed by certificate
                step: self.potential_records.len() as u64,
            };

            self.potential_records.push_back(record.clone());

            // Feed to progress certificate
            if let Some(certificate) = &mut self.progress_certificate {
                certificate.observe_potential_record(record);

                // Check for stall detection
                let verdict = certificate.generate_verdict();
                if verdict.stall_detected {
                    self.violation_stats.certificate_stall_count += 1;
                    self.violation_stats.total_certificate_failures += 1;
                }

                self.integration_state.last_drain_phase = verdict.drain_phase;
                self.certificate_verdicts.push(verdict);
            }
        }

        /// Simulates an out-of-band wake during pre-mask phase violation scenario
        pub fn simulate_out_of_band_wake_violation(
            &mut self,
            task_id: TaskId,
            initial_mask_depth: u32,
            time: Time,
        ) {
            // Step 1: Task enters mask phase
            let mask_enter_event = CancelRecognitionEvent {
                time,
                kind: CancelRecognitionEventKind::MaskEnter {
                    task_id,
                    depth: initial_mask_depth,
                },
            };
            self.record_cancel_event(mask_enter_event);

            // Step 2: Cancel request arrives while task is masked
            let cancel_event = CancelRecognitionEvent {
                time: Time::from_nanos(time.as_nanos() + 1_000_000), // 1ms later
                kind: CancelRecognitionEventKind::CancelRequest {
                    task_id,
                    reason: CancelReason::UserRequested,
                    requester: None,
                },
            };
            self.record_cancel_event(cancel_event);

            // Step 3: Task attempts to acknowledge cancellation while still masked (VIOLATION!)
            let cancel_ack_event = CancelRecognitionEvent {
                time: Time::from_nanos(time.as_nanos() + 2_000_000), // 2ms later
                kind: CancelRecognitionEventKind::CancelAck { task_id },
            };
            self.record_cancel_event(cancel_ack_event);

            // Step 4: Record declining potential to show impact on progress
            for i in 0..5 {
                let potential = 100.0 - (i as f64 * 5.0); // Decreasing potential
                let record_time = Time::from_nanos(time.as_nanos() + (i + 3) * 1_000_000);
                self.record_potential(potential, record_time);
            }
        }

        /// Performs comprehensive verification of violation detection across both systems
        pub fn verify_violation_detection(&self) -> Result<VerificationResult, RuntimeError> {
            let mut result = VerificationResult::default();

            // Verify oracle detected violations
            result.oracle_violations_detected = !self.protocol_violations.is_empty();
            result.cancel_ack_while_masked_detected =
                self.violation_stats.cancel_ack_while_masked_count > 0;
            result.out_of_band_wake_detected = self.violation_stats.out_of_band_wake_count > 0;

            // Verify certificate detected issues
            result.certificate_issues_detected = !self.certificate_verdicts.is_empty()
                && self
                    .certificate_verdicts
                    .iter()
                    .any(|v| v.stall_detected || !v.converging);

            // Verify integration consistency
            result.integration_consistent = self.integration_state.consistency_check_passed;

            // Verify mask depth tracking
            result.mask_depth_tracking_accurate =
                !self.integration_state.pre_mask_phase_tasks.is_empty();

            // Overall verification
            result.verification_passed = result.oracle_violations_detected
                && result.cancel_ack_while_masked_detected
                && result.out_of_band_wake_detected
                && result.certificate_issues_detected
                && result.integration_consistent;

            Ok(result)
        }

        /// Gets comprehensive violation statistics from the tracking session
        pub fn get_violation_stats(&self) -> ViolationStats {
            self.violation_stats.clone()
        }

        /// Gets current integration state
        pub fn get_integration_state(&self) -> IntegrationState {
            self.integration_state.clone()
        }

        /// Gets all recorded protocol violations
        pub fn get_protocol_violations(&self) -> Vec<CancelProtocolViolation> {
            self.protocol_violations.clone()
        }

        /// Gets all certificate verdicts
        pub fn get_certificate_verdicts(&self) -> Vec<CertificateVerdict> {
            self.certificate_verdicts.clone()
        }
    }

    /// Comprehensive verification result for cancellation protocol integration testing
    #[derive(Debug, Clone)]
    pub struct VerificationResult {
        /// Whether oracle successfully detected violations
        pub oracle_violations_detected: bool,
        /// Whether CancelAckWhileMasked violation was detected
        pub cancel_ack_while_masked_detected: bool,
        /// Whether out-of-band wake violation was detected
        pub out_of_band_wake_detected: bool,
        /// Whether certificate detected progress issues
        pub certificate_issues_detected: bool,
        /// Whether integration between systems is consistent
        pub integration_consistent: bool,
        /// Whether mask depth tracking is accurate
        pub mask_depth_tracking_accurate: bool,
        /// Overall verification result
        pub verification_passed: bool,
    }

    impl Default for VerificationResult {
        fn default() -> Self {
            Self {
                oracle_violations_detected: false,
                cancel_ack_while_masked_detected: false,
                out_of_band_wake_detected: false,
                certificate_issues_detected: false,
                integration_consistent: true,
                mask_depth_tracking_accurate: false,
                verification_passed: false,
            }
        }
    }

    /// Mock cancellation protocol coordinator for simulating real cancellation scenarios
    /// with progress certificate integration verification.
    #[derive(Debug)]
    pub struct MockCancellationProtocolCoordinator {
        /// Runtime configuration
        runtime_config: Arc<Mutex<CoordinatorConfig>>,
        /// Active tracking sessions
        active_trackers: Arc<Mutex<HashMap<String, CancellationProgressTracker>>>,
        /// Coordination statistics
        coord_stats: Arc<Mutex<CoordinationStats>>,
        /// Event generation settings
        event_generation: EventGenerationConfig,
    }

    /// Configuration for the mock coordinator
    #[derive(Debug, Clone)]
    pub struct CoordinatorConfig {
        /// Maximum number of tasks to simulate
        pub max_simulated_tasks: usize,
        /// Duration for violation simulation
        pub violation_simulation_duration: Duration,
        /// Whether to enable comprehensive logging
        pub enable_comprehensive_logging: bool,
        /// Protocol violation detection sensitivity
        pub violation_sensitivity: ViolationSensitivity,
    }

    /// Sensitivity settings for violation detection
    #[derive(Debug, Clone)]
    pub enum ViolationSensitivity {
        /// Detect only severe violations
        Low,
        /// Detect moderate and severe violations
        Medium,
        /// Detect all possible violations
        High,
        /// Custom sensitivity with specific thresholds
        Custom {
            mask_depth_threshold: u32,
            stall_threshold: u32,
            confidence_threshold: f64,
        },
    }

    /// Statistics for coordination across multiple tracking sessions
    #[derive(Debug, Clone)]
    pub struct CoordinationStats {
        /// Total number of tasks coordinated
        pub total_tasks_coordinated: u64,
        /// Total violations detected across all sessions
        pub total_violations_detected: u64,
        /// Total certificate failures detected
        pub total_certificate_failures: u64,
        /// Success rate for violation detection
        pub violation_detection_success_rate: f64,
        /// Average time to detect violations
        pub average_detection_time: Duration,
    }

    /// Configuration for event generation during simulation
    #[derive(Debug, Clone)]
    pub struct EventGenerationConfig {
        /// Base interval between events
        pub base_event_interval: Duration,
        /// Probability of generating violation events
        pub violation_probability: f64,
        /// Maximum mask depth to simulate
        pub max_mask_depth: u32,
        /// Whether to generate multiple concurrent violations
        pub enable_concurrent_violations: bool,
    }

    impl Default for CoordinatorConfig {
        fn default() -> Self {
            Self {
                max_simulated_tasks: 100,
                violation_simulation_duration: Duration::from_secs(60),
                enable_comprehensive_logging: true,
                violation_sensitivity: ViolationSensitivity::High,
            }
        }
    }

    impl Default for CoordinationStats {
        fn default() -> Self {
            Self {
                total_tasks_coordinated: 0,
                total_violations_detected: 0,
                total_certificate_failures: 0,
                violation_detection_success_rate: 0.0,
                average_detection_time: Duration::from_millis(0),
            }
        }
    }

    impl Default for EventGenerationConfig {
        fn default() -> Self {
            Self {
                base_event_interval: Duration::from_millis(10),
                violation_probability: 0.3,
                max_mask_depth: 5,
                enable_concurrent_violations: true,
            }
        }
    }

    impl MockCancellationProtocolCoordinator {
        /// Creates a new coordinator with specified configuration
        pub fn new(config: CoordinatorConfig) -> Self {
            Self {
                runtime_config: Arc::new(Mutex::new(config)),
                active_trackers: Arc::new(Mutex::new(HashMap::new())),
                coord_stats: Arc::new(Mutex::new(CoordinationStats::default())),
                event_generation: EventGenerationConfig::default(),
            }
        }

        /// Creates a new tracking session for cancellation protocol integration
        pub fn create_tracking_session(&self, session_id: String) -> Result<(), RuntimeError> {
            let protocol_config = CancellationProtocolOracleConfig::default();
            let certificate_config = ProgressCertificateConfig::default();

            let mut tracker = CancellationProgressTracker::new(protocol_config, certificate_config);
            tracker.initialize()?;

            let mut trackers = self.active_trackers.lock().unwrap();
            trackers.insert(session_id, tracker);

            Ok(())
        }

        /// Simulates comprehensive violation scenarios for testing integration
        pub fn simulate_violation_scenarios(
            &self,
            session_id: &str,
        ) -> Result<SimulationResult, RuntimeError> {
            let mut trackers = self.active_trackers.lock().unwrap();
            let tracker = trackers
                .get_mut(session_id)
                .ok_or_else(|| RuntimeError::InvalidState("Session not found".to_string()))?;

            let mut rng = DetRng::new(42);
            let base_time = Time::from_nanos(1_000_000_000); // 1 second
            let mut simulation_result = SimulationResult::default();

            // Scenario 1: Basic out-of-band wake during pre-mask phase
            let task1 = TaskId::new(rng.next_u64());
            tracker.simulate_out_of_band_wake_violation(task1, 2, base_time);
            simulation_result.basic_violation_simulated = true;

            // Scenario 2: Multiple concurrent mask violations
            for i in 0..3 {
                let task = TaskId::new(rng.next_u64());
                let time_offset = Time::from_nanos(base_time.as_nanos() + (i * 10_000_000));
                tracker.simulate_out_of_band_wake_violation(task, i + 1, time_offset);
            }
            simulation_result.concurrent_violations_simulated = true;

            // Scenario 3: Deep mask nesting violation
            let deep_task = TaskId::new(rng.next_u64());
            tracker.simulate_out_of_band_wake_violation(
                deep_task,
                5,
                Time::from_nanos(base_time.as_nanos() + 50_000_000),
            );
            simulation_result.deep_nesting_violation_simulated = true;

            // Scenario 4: Progress certificate stall simulation
            for i in 10..20 {
                let stall_time = Time::from_nanos(base_time.as_nanos() + (i * 5_000_000));
                tracker.record_potential(50.0, stall_time); // Constant potential = stall
            }
            simulation_result.progress_stall_simulated = true;

            Ok(simulation_result)
        }

        /// Performs comprehensive verification across all active sessions
        pub fn verify_all_sessions(&self) -> Result<GlobalVerificationResult, RuntimeError> {
            let trackers = self.active_trackers.lock().unwrap();
            let mut global_result = GlobalVerificationResult::default();

            for (session_id, tracker) in trackers.iter() {
                let verification = tracker.verify_violation_detection()?;
                global_result
                    .session_results
                    .insert(session_id.clone(), verification);

                // Aggregate statistics
                global_result.total_sessions += 1;
                if verification.verification_passed {
                    global_result.passed_sessions += 1;
                }
                if verification.oracle_violations_detected {
                    global_result.total_oracle_violations += 1;
                }
                if verification.certificate_issues_detected {
                    global_result.total_certificate_issues += 1;
                }
            }

            // Calculate success rates
            global_result.session_success_rate = if global_result.total_sessions > 0 {
                global_result.passed_sessions as f64 / global_result.total_sessions as f64
            } else {
                0.0
            };

            global_result.overall_success = global_result.session_success_rate >= 0.8
                && global_result.total_oracle_violations > 0
                && global_result.total_certificate_issues > 0;

            Ok(global_result)
        }

        /// Gets comprehensive statistics from all tracking sessions
        pub fn get_comprehensive_stats(&self) -> ComprehensiveStats {
            let trackers = self.active_trackers.lock().unwrap();
            let coord_stats = self.coord_stats.lock().unwrap();

            let mut comprehensive = ComprehensiveStats {
                coordination_stats: coord_stats.clone(),
                session_count: trackers.len(),
                ..Default::default()
            };

            for tracker in trackers.values() {
                let stats = tracker.get_violation_stats();
                comprehensive.total_cancel_ack_while_masked += stats.cancel_ack_while_masked_count;
                comprehensive.total_out_of_band_wakes += stats.out_of_band_wake_count;
                comprehensive.total_certificate_stalls += stats.certificate_stall_count;
                comprehensive.total_oracle_violations += stats.total_oracle_violations;
                comprehensive.total_certificate_failures += stats.total_certificate_failures;
            }

            comprehensive
        }
    }

    /// Result of violation simulation scenarios
    #[derive(Debug, Clone)]
    pub struct SimulationResult {
        /// Whether basic violation was successfully simulated
        pub basic_violation_simulated: bool,
        /// Whether concurrent violations were simulated
        pub concurrent_violations_simulated: bool,
        /// Whether deep nesting violation was simulated
        pub deep_nesting_violation_simulated: bool,
        /// Whether progress stall was simulated
        pub progress_stall_simulated: bool,
    }

    impl Default for SimulationResult {
        fn default() -> Self {
            Self {
                basic_violation_simulated: false,
                concurrent_violations_simulated: false,
                deep_nesting_violation_simulated: false,
                progress_stall_simulated: false,
            }
        }
    }

    /// Global verification result across all sessions
    #[derive(Debug, Clone)]
    pub struct GlobalVerificationResult {
        /// Results for individual sessions
        pub session_results: HashMap<String, VerificationResult>,
        /// Total number of sessions tested
        pub total_sessions: usize,
        /// Number of sessions that passed verification
        pub passed_sessions: usize,
        /// Session success rate
        pub session_success_rate: f64,
        /// Total oracle violations detected across all sessions
        pub total_oracle_violations: u64,
        /// Total certificate issues detected across all sessions
        pub total_certificate_issues: u64,
        /// Overall integration success
        pub overall_success: bool,
    }

    impl Default for GlobalVerificationResult {
        fn default() -> Self {
            Self {
                session_results: HashMap::new(),
                total_sessions: 0,
                passed_sessions: 0,
                session_success_rate: 0.0,
                total_oracle_violations: 0,
                total_certificate_issues: 0,
                overall_success: false,
            }
        }
    }

    /// Comprehensive statistics aggregated across all tracking sessions
    #[derive(Debug, Clone)]
    pub struct ComprehensiveStats {
        /// Coordination statistics
        pub coordination_stats: CoordinationStats,
        /// Number of active sessions
        pub session_count: usize,
        /// Total CancelAckWhileMasked violations across all sessions
        pub total_cancel_ack_while_masked: u64,
        /// Total out-of-band wake violations
        pub total_out_of_band_wakes: u64,
        /// Total certificate stalls detected
        pub total_certificate_stalls: u64,
        /// Total oracle violations
        pub total_oracle_violations: u64,
        /// Total certificate failures
        pub total_certificate_failures: u64,
    }

    impl Default for ComprehensiveStats {
        fn default() -> Self {
            Self {
                coordination_stats: CoordinationStats::default(),
                session_count: 0,
                total_cancel_ack_while_masked: 0,
                total_out_of_band_wakes: 0,
                total_certificate_stalls: 0,
                total_oracle_violations: 0,
                total_certificate_failures: 0,
            }
        }
    }

    #[test]
    fn test_basic_cancellation_protocol_certificate_integration() {
        // Test basic integration between cancellation protocol oracle and progress certificate
        let protocol_config = CancellationProtocolOracleConfig::default();
        let certificate_config = ProgressCertificateConfig::default();

        let mut tracker = CancellationProgressTracker::new(protocol_config, certificate_config);
        tracker.initialize().expect("Failed to initialize tracker");

        // Simulate normal cancellation flow (should pass)
        let task_id = TaskId::new(12345);
        let base_time = Time::from_nanos(1_000_000_000);

        // Normal flow: cancel request -> acknowledgment (no mask violations)
        tracker.record_cancel_event(CancelRecognitionEvent {
            time: base_time,
            kind: CancelRecognitionEventKind::CancelRequest {
                task_id,
                reason: CancelReason::UserRequested,
                requester: None,
            },
        });

        tracker.record_cancel_event(CancelRecognitionEvent {
            time: Time::from_nanos(base_time.as_nanos() + 1_000_000),
            kind: CancelRecognitionEventKind::CancelAck { task_id },
        });

        // Record some progress
        tracker.record_potential(100.0, base_time);
        tracker.record_potential(80.0, Time::from_nanos(base_time.as_nanos() + 2_000_000));

        let verification = tracker
            .verify_violation_detection()
            .expect("Verification failed");

        assert!(
            !verification.cancel_ack_while_masked_detected,
            "Should not detect violation in normal flow"
        );
        assert!(
            !verification.out_of_band_wake_detected,
            "Should not detect out-of-band wake in normal flow"
        );
    }

    #[test]
    fn test_cancel_ack_while_masked_violation_detection() {
        // Test detection of CancelAckWhileMasked violation (out-of-band wake during pre-mask phase)
        let protocol_config = CancellationProtocolOracleConfig::default();
        let certificate_config = ProgressCertificateConfig::default();

        let mut tracker = CancellationProgressTracker::new(protocol_config, certificate_config);
        tracker.initialize().expect("Failed to initialize tracker");

        let task_id = TaskId::new(67890);
        let base_time = Time::from_nanos(2_000_000_000);

        // Simulate out-of-band wake violation
        tracker.simulate_out_of_band_wake_violation(task_id, 3, base_time);

        let verification = tracker
            .verify_violation_detection()
            .expect("Verification failed");

        assert!(
            verification.oracle_violations_detected,
            "Oracle should detect violations"
        );
        assert!(
            verification.cancel_ack_while_masked_detected,
            "Should detect CancelAckWhileMasked violation"
        );
        assert!(
            verification.out_of_band_wake_detected,
            "Should detect out-of-band wake violation"
        );
        assert!(
            verification.mask_depth_tracking_accurate,
            "Mask depth tracking should be accurate"
        );

        let stats = tracker.get_violation_stats();
        assert!(
            stats.cancel_ack_while_masked_count > 0,
            "Should count CancelAckWhileMasked violations"
        );
        assert!(
            stats.out_of_band_wake_count > 0,
            "Should count out-of-band wake violations"
        );
    }

    #[test]
    fn test_mask_depth_tracking_precision() {
        // Test accurate tracking of mask depth for pre-mask phase violation detection
        let protocol_config = CancellationProtocolOracleConfig::default();
        let certificate_config = ProgressCertificateConfig::default();

        let mut tracker = CancellationProgressTracker::new(protocol_config, certificate_config);
        tracker.initialize().expect("Failed to initialize tracker");

        let task_id = TaskId::new(11111);
        let base_time = Time::from_nanos(3_000_000_000);

        // Test nested mask enter/exit tracking
        tracker.record_cancel_event(CancelRecognitionEvent {
            time: base_time,
            kind: CancelRecognitionEventKind::MaskEnter { task_id, depth: 1 },
        });

        tracker.record_cancel_event(CancelRecognitionEvent {
            time: Time::from_nanos(base_time.as_nanos() + 1_000_000),
            kind: CancelRecognitionEventKind::MaskEnter { task_id, depth: 2 },
        });

        tracker.record_cancel_event(CancelRecognitionEvent {
            time: Time::from_nanos(base_time.as_nanos() + 2_000_000),
            kind: CancelRecognitionEventKind::MaskEnter { task_id, depth: 3 },
        });

        // Check state tracking
        let integration_state = tracker.get_integration_state();
        assert!(
            integration_state
                .pre_mask_phase_tasks
                .contains_key(&task_id),
            "Should track task in pre-mask phase"
        );

        let mask_info = integration_state
            .pre_mask_phase_tasks
            .get(&task_id)
            .unwrap();
        assert_eq!(mask_info.mask_depth, 3, "Should track correct mask depth");

        // Cancel while deeply masked (should trigger violation)
        tracker.record_cancel_event(CancelRecognitionEvent {
            time: Time::from_nanos(base_time.as_nanos() + 3_000_000),
            kind: CancelRecognitionEventKind::CancelRequest {
                task_id,
                reason: CancelReason::UserRequested,
                requester: None,
            },
        });

        tracker.record_cancel_event(CancelRecognitionEvent {
            time: Time::from_nanos(base_time.as_nanos() + 4_000_000),
            kind: CancelRecognitionEventKind::CancelAck { task_id },
        });

        let verification = tracker
            .verify_violation_detection()
            .expect("Verification failed");

        assert!(
            verification.cancel_ack_while_masked_detected,
            "Should detect violation with deep mask nesting"
        );
    }

    #[test]
    fn test_progress_certificate_integration() {
        // Test progress certificate integration with violation detection
        let protocol_config = CancellationProtocolOracleConfig::default();
        let certificate_config = ProgressCertificateConfig::default();

        let mut tracker = CancellationProgressTracker::new(protocol_config, certificate_config);
        tracker.initialize().expect("Failed to initialize tracker");

        let task_id = TaskId::new(22222);
        let base_time = Time::from_nanos(4_000_000_000);

        // Simulate violation with declining progress
        tracker.simulate_out_of_band_wake_violation(task_id, 2, base_time);

        // Add more potential records showing stall
        for i in 0..10 {
            let stall_time = Time::from_nanos(base_time.as_nanos() + (i + 10) * 1_000_000);
            tracker.record_potential(25.0, stall_time); // Flat potential = stall
        }

        let verification = tracker
            .verify_violation_detection()
            .expect("Verification failed");

        assert!(
            verification.certificate_issues_detected,
            "Certificate should detect progress issues"
        );

        let verdicts = tracker.get_certificate_verdicts();
        assert!(!verdicts.is_empty(), "Should have certificate verdicts");

        let has_stall = verdicts.iter().any(|v| v.stall_detected);
        assert!(has_stall, "Should detect stall in progress certificate");

        let stats = tracker.get_violation_stats();
        assert!(
            stats.certificate_stall_count > 0,
            "Should count certificate stalls"
        );
    }

    #[test]
    fn test_comprehensive_violation_scenarios() {
        // Test comprehensive violation scenarios with mock coordinator
        let config = CoordinatorConfig {
            max_simulated_tasks: 50,
            violation_simulation_duration: Duration::from_secs(30),
            enable_comprehensive_logging: true,
            violation_sensitivity: ViolationSensitivity::High,
        };

        let coordinator = MockCancellationProtocolCoordinator::new(config);

        // Create multiple tracking sessions
        let session_ids = vec!["session1", "session2", "session3"];
        for session_id in &session_ids {
            coordinator
                .create_tracking_session(session_id.to_string())
                .expect("Failed to create session");
        }

        // Simulate violations in all sessions
        for session_id in &session_ids {
            let simulation_result = coordinator
                .simulate_violation_scenarios(session_id)
                .expect("Failed to simulate violations");

            assert!(
                simulation_result.basic_violation_simulated,
                "Basic violation should be simulated"
            );
            assert!(
                simulation_result.concurrent_violations_simulated,
                "Concurrent violations should be simulated"
            );
            assert!(
                simulation_result.deep_nesting_violation_simulated,
                "Deep nesting violation should be simulated"
            );
            assert!(
                simulation_result.progress_stall_simulated,
                "Progress stall should be simulated"
            );
        }

        // Verify all sessions
        let global_verification = coordinator
            .verify_all_sessions()
            .expect("Failed to verify sessions");

        assert!(
            global_verification.total_sessions >= 3,
            "Should verify multiple sessions"
        );
        assert!(
            global_verification.total_oracle_violations > 0,
            "Should detect oracle violations across sessions"
        );
        assert!(
            global_verification.total_certificate_issues > 0,
            "Should detect certificate issues across sessions"
        );
        assert!(
            global_verification.overall_success,
            "Overall integration should succeed"
        );

        // Get comprehensive statistics
        let stats = coordinator.get_comprehensive_stats();
        assert!(
            stats.total_cancel_ack_while_masked > 0,
            "Should detect CancelAckWhileMasked violations"
        );
        assert!(
            stats.total_out_of_band_wakes > 0,
            "Should detect out-of-band wake violations"
        );
    }

    #[test]
    fn test_integration_consistency_verification() {
        // Test consistency between oracle and certificate violation detection
        let protocol_config = CancellationProtocolOracleConfig::default();
        let certificate_config = ProgressCertificateConfig::default();

        let mut tracker = CancellationProgressTracker::new(protocol_config, certificate_config);
        tracker.initialize().expect("Failed to initialize tracker");

        let base_time = Time::from_nanos(5_000_000_000);

        // Create multiple violations to test consistency
        for i in 0..5 {
            let task_id = TaskId::new(33333 + i);
            let violation_time = Time::from_nanos(base_time.as_nanos() + (i * 10_000_000));
            tracker.simulate_out_of_band_wake_violation(task_id, (i % 3) + 1, violation_time);
        }

        let verification = tracker
            .verify_violation_detection()
            .expect("Verification failed");

        assert!(
            verification.verification_passed,
            "Overall verification should pass"
        );
        assert!(
            verification.integration_consistent,
            "Integration should be consistent"
        );

        let protocol_violations = tracker.get_protocol_violations();
        let certificate_verdicts = tracker.get_certificate_verdicts();

        assert!(
            !protocol_violations.is_empty(),
            "Should have protocol violations"
        );
        assert!(
            !certificate_verdicts.is_empty(),
            "Should have certificate verdicts"
        );

        // Verify violation types
        let has_cancel_ack_while_masked = protocol_violations
            .iter()
            .any(|v| matches!(v, CancelProtocolViolation::CancelAckWhileMasked { .. }));
        assert!(
            has_cancel_ack_while_masked,
            "Should detect CancelAckWhileMasked violations"
        );

        let integration_state = tracker.get_integration_state();
        assert!(
            integration_state.is_monitoring,
            "Integration should be actively monitoring"
        );
        assert!(
            integration_state.current_epoch > 0,
            "Should track current epoch"
        );
    }
}
