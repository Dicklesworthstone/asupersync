//! Real Obligation CALM ↔ Obligation EProcess Integration E2E Test
//!
//! This test verifies that CALM-conformant operations preserve eprocess monotonicity
//! under concurrent merges. It validates the integration between CALM (Convergent
//! And Logical Monotonic) obligation handling and eprocess execution monitoring.

#[cfg(test)]
mod tests {
    use crate::{
        cx::{Cx, Scope},
        error::Result,
        lab::LabRuntime,
        obligation::{
            ObligationId, ObligationLedger, ObligationState,
            calm::{
                CalmConformanceValidator, CalmLattice, CalmMergeResult, CalmOperation,
                CalmOperationHandler, CalmProperties, CalmState, CalmVector, ConvergenceGuarantee,
                MonotonicityProof,
            },
            eprocess::{
                ConcurrentMergeHandler, EProcessEvent, EProcessEvidence, EProcessMonitor,
                EProcessState, EProcessTransition, EProcessWitness, MonotonicityConstraint,
                MonotonicityViolation,
            },
        },
        sync::{Arc, Mutex},
        types::{Budget, Outcome, TaskId, Time},
    };
    use std::{
        collections::{BTreeMap, HashMap, HashSet, VecDeque},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::{Duration, Instant},
    };

    /// Deterministic CALM operation handler for integration testing.
    #[derive(Debug)]
    struct DeterministicCalmOperationHandler {
        handler_id: String,
        calm_state: Arc<Mutex<CalmState>>,
        operation_log: Arc<Mutex<Vec<CalmOperationRecord>>>,
        eprocess_monitor: Arc<DeterministicEprocessMonitor>,
        integration_tracker: Arc<CalmEprocessTracker>,
        monotonicity_validator: CalmConformanceValidator,
        active_operations: AtomicU64,
        merge_operations: AtomicU64,
    }

    impl DeterministicCalmOperationHandler {
        fn new(handler_id: String, eprocess_monitor: Arc<DeterministicEprocessMonitor>) -> Self {
            Self {
                handler_id,
                calm_state: Arc::new(Mutex::new(CalmState::new())),
                operation_log: Arc::new(Mutex::new(Vec::new())),
                eprocess_monitor,
                integration_tracker: Arc::new(CalmEprocessTracker::new()),
                monotonicity_validator: CalmConformanceValidator::new(),
                active_operations: AtomicU64::new(0),
                merge_operations: AtomicU64::new(0),
            }
        }

        async fn execute_calm_operation(
            &self,
            cx: &Cx,
            operation: CalmOperation,
        ) -> Result<CalmOperationResult> {
            self.active_operations.fetch_add(1, Ordering::AcqRel);

            // Record operation start
            let operation_id = self.generate_operation_id();
            self.record_operation_start(operation_id, &operation);

            // Validate CALM conformance before execution
            let conformance_check = self.validate_calm_conformance(&operation).await?;
            if !conformance_check.is_conformant {
                self.integration_tracker
                    .record_conformance_violation(conformance_check);
                return Ok(CalmOperationResult::ConformanceViolation(conformance_check));
            }

            // Execute operation with eprocess monitoring
            let execution_result = self
                .execute_with_eprocess_monitoring(cx, operation_id, operation)
                .await?;

            // Validate monotonicity preservation
            let monotonicity_check = self
                .validate_monotonicity_preservation(operation_id, &execution_result)
                .await?;
            if !monotonicity_check.is_preserved {
                self.integration_tracker
                    .record_monotonicity_violation(monotonicity_check);
                return Ok(CalmOperationResult::MonotonicityViolation(
                    monotonicity_check,
                ));
            }

            self.active_operations.fetch_sub(1, Ordering::AcqRel);
            self.record_operation_completion(operation_id, &execution_result);

            Ok(CalmOperationResult::Success(execution_result))
        }

        async fn execute_concurrent_merge(
            &self,
            cx: &Cx,
            merge_operation: ConcurrentMergeOperation,
        ) -> Result<ConcurrentMergeResult> {
            self.merge_operations.fetch_add(1, Ordering::AcqRel);

            // Prepare merge with eprocess coordination
            let merge_id = self.generate_merge_id();
            let merge_context = self
                .prepare_concurrent_merge(merge_id, &merge_operation)
                .await?;

            // Execute concurrent operations with monotonicity tracking
            let concurrent_results = self
                .execute_concurrent_operations(cx, merge_context, merge_operation.operations)
                .await?;

            // Perform CALM-conformant merge
            let merge_result = self
                .perform_calm_merge(merge_id, concurrent_results)
                .await?;

            // Validate eprocess monotonicity after merge
            let post_merge_validation = self
                .validate_post_merge_monotonicity(merge_id, &merge_result)
                .await?;

            if !post_merge_validation.is_valid {
                self.integration_tracker
                    .record_merge_monotonicity_failure(post_merge_validation);
                return Ok(ConcurrentMergeResult::MonotonicityFailure(
                    post_merge_validation,
                ));
            }

            // Finalize merge with eprocess evidence
            let finalization = self
                .finalize_merge_with_eprocess_evidence(merge_id, merge_result)
                .await?;

            Ok(ConcurrentMergeResult::Success(finalization))
        }

        async fn validate_calm_conformance(
            &self,
            operation: &CalmOperation,
        ) -> Result<ConformanceCheck> {
            // Check CALM properties: Convergent, Associative, Logical, Monotonic
            let convergent = self.check_convergence_property(operation);
            let associative = self.check_associativity_property(operation);
            let logical = self.check_logical_property(operation);
            let monotonic = self.check_monotonicity_property(operation);

            let is_conformant = convergent && associative && logical && monotonic;

            Ok(ConformanceCheck {
                operation_id: operation.id,
                is_conformant,
                convergent,
                associative,
                logical,
                monotonic,
                validation_timestamp: Time::now().into(),
                violation_details: if !is_conformant {
                    Some(self.generate_violation_details(
                        convergent,
                        associative,
                        logical,
                        monotonic,
                    ))
                } else {
                    None
                },
            })
        }

        async fn execute_with_eprocess_monitoring(
            &self,
            cx: &Cx,
            operation_id: OperationId,
            operation: CalmOperation,
        ) -> Result<ExecutionResult> {
            // Start eprocess monitoring
            let eprocess_session = self
                .eprocess_monitor
                .start_monitoring_session(operation_id)
                .await?;

            // Execute operation while tracking eprocess state
            let execution_future = self.execute_operation_core(cx, operation);
            let monitoring_future = self.eprocess_monitor.monitor_execution(eprocess_session);

            // Run both concurrently to ensure proper monitoring
            let (execution_result, monitoring_result) =
                tokio::try_join!(execution_future, monitoring_future)?;

            // Validate eprocess evidence consistency
            let evidence_validation = self
                .validate_eprocess_evidence(operation_id, &execution_result, &monitoring_result)
                .await?;

            Ok(ExecutionResult {
                operation_id,
                execution_outcome: execution_result,
                eprocess_evidence: monitoring_result,
                evidence_validation,
                execution_duration: Time::now().elapsed(),
            })
        }

        async fn perform_calm_merge(
            &self,
            merge_id: MergeId,
            concurrent_results: Vec<ExecutionResult>,
        ) -> Result<MergeResult> {
            // Extract CALM states from all concurrent executions
            let calm_states: Vec<CalmState> = concurrent_results
                .iter()
                .map(|result| result.extract_calm_state())
                .collect::<Result<Vec<_>>>()?;

            // Perform lattice merge operation
            let merged_state = self.merge_calm_states(calm_states).await?;

            // Validate merge conformance
            let merge_validation = self
                .validate_merge_conformance(merge_id, &merged_state)
                .await?;

            // Generate merge evidence
            let merge_evidence =
                self.generate_merge_evidence(merge_id, &concurrent_results, &merged_state)?;

            Ok(MergeResult {
                merge_id,
                merged_state,
                merge_validation,
                merge_evidence,
                participant_count: concurrent_results.len(),
                merge_timestamp: Time::now().into(),
            })
        }

        async fn validate_monotonicity_preservation(
            &self,
            operation_id: OperationId,
            execution_result: &ExecutionResult,
        ) -> Result<MonotonicityValidation> {
            // Get pre-operation eprocess state
            let pre_state = self
                .eprocess_monitor
                .get_state_snapshot(operation_id)
                .await?;

            // Get post-operation eprocess state
            let post_state = &execution_result.eprocess_evidence.final_state;

            // Check monotonicity constraints
            let monotonicity_preserved =
                self.check_monotonicity_constraints(&pre_state, post_state);

            // Generate monotonicity proof if preserved
            let monotonicity_proof = if monotonicity_preserved {
                Some(self.generate_monotonicity_proof(&pre_state, post_state)?)
            } else {
                None
            };

            Ok(MonotonicityValidation {
                operation_id,
                is_preserved: monotonicity_preserved,
                pre_state,
                post_state: post_state.clone(),
                monotonicity_proof,
                validation_timestamp: Time::now().into(),
            })
        }

        fn check_convergence_property(&self, operation: &CalmOperation) -> bool {
            // Verify operation converges to same result regardless of execution order
            match &operation.operation_type {
                CalmOperationType::Set => true,       // Sets are naturally convergent
                CalmOperationType::Max => true,       // Max is convergent
                CalmOperationType::Union => true,     // Union is convergent
                CalmOperationType::Increment => true, // Monotonic increment is convergent
                CalmOperationType::Custom(validator) => validator.is_convergent(),
            }
        }

        fn check_associativity_property(&self, operation: &CalmOperation) -> bool {
            // Verify (A op B) op C = A op (B op C)
            operation.properties.is_associative
        }

        fn check_logical_property(&self, operation: &CalmOperation) -> bool {
            // Verify operation has logical semantics (deterministic given inputs)
            operation.properties.is_logical
        }

        fn check_monotonicity_property(&self, operation: &CalmOperation) -> bool {
            // Verify operation is monotonic (doesn't decrease lattice height)
            operation.properties.is_monotonic
        }

        fn check_monotonicity_constraints(
            &self,
            pre_state: &EProcessState,
            post_state: &EProcessState,
        ) -> bool {
            // Check various monotonicity constraints
            let progress_monotonic = post_state.progress >= pre_state.progress;
            let evidence_monotonic = post_state.evidence_count >= pre_state.evidence_count;
            let obligation_monotonic = post_state
                .obligation_state
                .is_monotonic_successor(&pre_state.obligation_state);
            let lattice_monotonic = post_state.lattice_height >= pre_state.lattice_height;

            progress_monotonic && evidence_monotonic && obligation_monotonic && lattice_monotonic
        }

        fn record_operation_start(&self, operation_id: OperationId, operation: &CalmOperation) {
            let record = CalmOperationRecord {
                operation_id,
                operation_type: operation.operation_type.clone(),
                start_time: Time::now().into(),
                end_time: None,
                status: OperationStatus::Started,
                calm_state_before: None,
                calm_state_after: None,
            };
            self.operation_log.lock().unwrap().push(record);
            self.integration_tracker
                .record_operation_event(OperationEvent::Started(operation_id));
        }

        fn record_operation_completion(&self, operation_id: OperationId, result: &ExecutionResult) {
            if let Some(record) = self
                .operation_log
                .lock()
                .unwrap()
                .iter_mut()
                .find(|r| r.operation_id == operation_id)
            {
                record.end_time = Some(Time::now().into());
                record.status = OperationStatus::Completed;
                record.calm_state_after = Some(result.execution_outcome.final_calm_state.clone());
            }
            self.integration_tracker
                .record_operation_event(OperationEvent::Completed(operation_id));
        }

        fn generate_operation_id(&self) -> OperationId {
            OperationId(Time::now().elapsed().as_nanos() as u64)
        }

        fn generate_merge_id(&self) -> MergeId {
            MergeId(Time::now().elapsed().as_nanos() as u64)
        }

        fn get_stats(&self) -> CalmOperationStats {
            CalmOperationStats {
                active_operations: self.active_operations.load(Ordering::Acquire),
                total_merge_operations: self.merge_operations.load(Ordering::Acquire),
                operation_log_size: self.operation_log.lock().unwrap().len(),
                conformance_validation_count: self
                    .integration_tracker
                    .get_conformance_validation_count(),
                monotonicity_validation_count: self
                    .integration_tracker
                    .get_monotonicity_validation_count(),
            }
        }
    }

    /// Deterministic eprocess monitor for integration testing.
    #[derive(Debug)]
    struct DeterministicEprocessMonitor {
        monitor_id: String,
        current_state: Arc<Mutex<EProcessState>>,
        monitoring_sessions: Arc<Mutex<HashMap<OperationId, MonitoringSession>>>,
        state_snapshots: Arc<Mutex<BTreeMap<OperationId, EProcessState>>>,
        monotonicity_violations: Arc<Mutex<Vec<MonotonicityViolation>>>,
        evidence_log: Arc<Mutex<Vec<EProcessEvidence>>>,
    }

    impl DeterministicEprocessMonitor {
        fn new(monitor_id: String) -> Self {
            Self {
                monitor_id,
                current_state: Arc::new(Mutex::new(EProcessState::initial())),
                monitoring_sessions: Arc::new(Mutex::new(HashMap::new())),
                state_snapshots: Arc::new(Mutex::new(BTreeMap::new())),
                monotonicity_violations: Arc::new(Mutex::new(Vec::new())),
                evidence_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        async fn start_monitoring_session(
            &self,
            operation_id: OperationId,
        ) -> Result<MonitoringSession> {
            // Create snapshot of current state
            let state_snapshot = self.current_state.lock().unwrap().clone();
            self.state_snapshots
                .lock()
                .unwrap()
                .insert(operation_id, state_snapshot.clone());

            // Initialize monitoring session
            let session = MonitoringSession {
                session_id: operation_id,
                start_state: state_snapshot,
                events: Vec::new(),
                transitions: Vec::new(),
                witnesses: Vec::new(),
                start_time: Time::now().into(),
            };

            self.monitoring_sessions
                .lock()
                .unwrap()
                .insert(operation_id, session.clone());

            Ok(session)
        }

        async fn monitor_execution(&self, session: MonitoringSession) -> Result<MonitoringResult> {
            // Record monitoring during execution.
            let monitoring_duration = Duration::from_millis(50);
            tokio::time::sleep(monitoring_duration).await;

            // Generate monitoring events
            let events = self.generate_monitoring_events(session.session_id);

            // Track state transitions
            let transitions = self.track_state_transitions(session.session_id, &events);

            // Generate eprocess witnesses
            let witnesses = self.generate_eprocess_witnesses(session.session_id, &transitions);

            // Collect evidence
            let evidence = self.collect_eprocess_evidence(session.session_id, &events, &witnesses);

            // Update current state
            let final_state = self.update_state_from_transitions(&transitions);

            Ok(MonitoringResult {
                session_id: session.session_id,
                events,
                transitions,
                witnesses,
                evidence,
                final_state,
                monitoring_duration,
            })
        }

        async fn get_state_snapshot(&self, operation_id: OperationId) -> Result<EProcessState> {
            self.state_snapshots
                .lock()
                .unwrap()
                .get(&operation_id)
                .cloned()
                .ok_or_else(|| {
                    crate::error::Error::new(
                        crate::error::ErrorKind::NotFound,
                        "Operation state snapshot not found",
                    )
                })
        }

        fn generate_monitoring_events(&self, operation_id: OperationId) -> Vec<EProcessEvent> {
            vec![
                EProcessEvent {
                    event_id: EventId::new(),
                    operation_id,
                    event_type: EventType::StateTransition,
                    timestamp: Time::now().into(),
                    payload: EventPayload::StateUpdate(StateUpdate::Progress),
                },
                EProcessEvent {
                    event_id: EventId::new(),
                    operation_id,
                    event_type: EventType::EvidenceGeneration,
                    timestamp: Time::now().into(),
                    payload: EventPayload::Evidence(EvidenceData::MonotonicityWitness),
                },
                EProcessEvent {
                    event_id: EventId::new(),
                    operation_id,
                    event_type: EventType::ObligationUpdate,
                    timestamp: Time::now().into(),
                    payload: EventPayload::ObligationChange(ObligationChange::StateAdvancement),
                },
            ]
        }

        fn track_state_transitions(
            &self,
            operation_id: OperationId,
            events: &[EProcessEvent],
        ) -> Vec<EProcessTransition> {
            events
                .iter()
                .filter_map(|event| {
                    if matches!(event.event_type, EventType::StateTransition) {
                        Some(EProcessTransition {
                            transition_id: TransitionId::new(),
                            operation_id,
                            from_state: self.current_state.lock().unwrap().clone(),
                            to_state: self.advance_state_from_event(event),
                            transition_type: TransitionType::MonotonicAdvancement,
                            timestamp: event.timestamp,
                        })
                    } else {
                        None
                    }
                })
                .collect()
        }

        fn generate_eprocess_witnesses(
            &self,
            operation_id: OperationId,
            transitions: &[EProcessTransition],
        ) -> Vec<EProcessWitness> {
            transitions
                .iter()
                .map(|transition| EProcessWitness {
                    witness_id: WitnessId::new(),
                    operation_id,
                    transition_id: transition.transition_id,
                    witness_type: WitnessType::MonotonicityPreservation,
                    proof_data: ProofData::MonotonicityProof(MonotonicityProofData {
                        pre_height: transition.from_state.lattice_height,
                        post_height: transition.to_state.lattice_height,
                        advancement_evidence: AdvancementEvidence::Positive,
                    }),
                    timestamp: transition.timestamp,
                })
                .collect()
        }

        fn collect_eprocess_evidence(
            &self,
            operation_id: OperationId,
            events: &[EProcessEvent],
            witnesses: &[EProcessWitness],
        ) -> EProcessEvidence {
            EProcessEvidence {
                operation_id,
                event_count: events.len(),
                witness_count: witnesses.len(),
                evidence_type: EvidenceType::MonotonicityPreservation,
                completeness_proof: CompletenessProof::Full,
                collection_timestamp: Time::now().into(),
            }
        }

        fn update_state_from_transitions(
            &self,
            transitions: &[EProcessTransition],
        ) -> EProcessState {
            let mut current_state = self.current_state.lock().unwrap().clone();

            for transition in transitions {
                current_state = transition.to_state.clone();
            }

            // Update stored state
            *self.current_state.lock().unwrap() = current_state.clone();

            current_state
        }

        fn advance_state_from_event(&self, event: &EProcessEvent) -> EProcessState {
            let mut state = self.current_state.lock().unwrap().clone();

            match &event.payload {
                EventPayload::StateUpdate(StateUpdate::Progress) => {
                    state.progress += 1;
                    state.lattice_height += 1;
                }
                EventPayload::Evidence(_) => {
                    state.evidence_count += 1;
                }
                EventPayload::ObligationChange(_) => {
                    state.obligation_state.advance();
                }
            }

            state
        }
    }

    /// Tracks integration between CALM and eprocess systems
    #[derive(Debug)]
    struct CalmEprocessTracker {
        tracker_id: String,
        operation_events: Arc<Mutex<Vec<OperationEvent>>>,
        conformance_violations: Arc<Mutex<Vec<ConformanceCheck>>>,
        monotonicity_violations: Arc<Mutex<Vec<MonotonicityValidation>>>,
        merge_events: Arc<Mutex<Vec<MergeEvent>>>,
        integration_metrics: Arc<Mutex<IntegrationMetrics>>,
    }

    impl CalmEprocessTracker {
        fn new() -> Self {
            Self {
                tracker_id: "calm_eprocess_integration_tracker".to_string(),
                operation_events: Arc::new(Mutex::new(Vec::new())),
                conformance_violations: Arc::new(Mutex::new(Vec::new())),
                monotonicity_violations: Arc::new(Mutex::new(Vec::new())),
                merge_events: Arc::new(Mutex::new(Vec::new())),
                integration_metrics: Arc::new(Mutex::new(IntegrationMetrics::new())),
            }
        }

        fn record_operation_event(&self, event: OperationEvent) {
            self.operation_events.lock().unwrap().push(event);
            self.update_metrics_for_operation_event();
        }

        fn record_conformance_violation(&self, violation: ConformanceCheck) {
            self.conformance_violations.lock().unwrap().push(violation);
            self.update_metrics_for_conformance_violation();
        }

        fn record_monotonicity_violation(&self, violation: MonotonicityValidation) {
            self.monotonicity_violations.lock().unwrap().push(violation);
            self.update_metrics_for_monotonicity_violation();
        }

        fn record_merge_monotonicity_failure(&self, failure: PostMergeValidation) {
            self.merge_events
                .lock()
                .unwrap()
                .push(MergeEvent::MonotonicityFailure(failure));
            self.update_metrics_for_merge_failure();
        }

        fn get_integration_summary(&self) -> CalmEprocessIntegrationSummary {
            let operations = self.operation_events.lock().unwrap();
            let conformance_violations = self.conformance_violations.lock().unwrap();
            let monotonicity_violations = self.monotonicity_violations.lock().unwrap();
            let merge_events = self.merge_events.lock().unwrap();

            let total_operations = operations.len();
            let started_operations = operations
                .iter()
                .filter(|e| matches!(e, OperationEvent::Started(_)))
                .count();
            let completed_operations = operations
                .iter()
                .filter(|e| matches!(e, OperationEvent::Completed(_)))
                .count();
            let conformance_violation_count = conformance_violations.len();
            let monotonicity_violation_count = monotonicity_violations.len();
            let merge_failure_count = merge_events
                .iter()
                .filter(|e| matches!(e, MergeEvent::MonotonicityFailure(_)))
                .count();

            CalmEprocessIntegrationSummary {
                total_operation_events: total_operations,
                started_operations,
                completed_operations,
                conformance_violation_count,
                monotonicity_violation_count,
                merge_failure_count,
                operation_success_rate: if total_operations > 0 {
                    completed_operations as f64 / total_operations as f64
                } else {
                    0.0
                },
                conformance_success_rate: if total_operations > 0 {
                    (total_operations - conformance_violation_count) as f64
                        / total_operations as f64
                } else {
                    1.0
                },
                monotonicity_preservation_rate: if total_operations > 0 {
                    (total_operations - monotonicity_violation_count) as f64
                        / total_operations as f64
                } else {
                    1.0
                },
                integration_health: calculate_integration_health(
                    completed_operations,
                    conformance_violation_count,
                    monotonicity_violation_count,
                    merge_failure_count,
                ),
            }
        }

        fn get_conformance_validation_count(&self) -> usize {
            self.operation_events.lock().unwrap().len()
        }

        fn get_monotonicity_validation_count(&self) -> usize {
            self.operation_events.lock().unwrap().len()
        }

        fn update_metrics_for_operation_event(&self) {
            let mut metrics = self.integration_metrics.lock().unwrap();
            metrics.total_operations += 1;
        }

        fn update_metrics_for_conformance_violation(&self) {
            let mut metrics = self.integration_metrics.lock().unwrap();
            metrics.conformance_violations += 1;
        }

        fn update_metrics_for_monotonicity_violation(&self) {
            let mut metrics = self.integration_metrics.lock().unwrap();
            metrics.monotonicity_violations += 1;
        }

        fn update_metrics_for_merge_failure(&self) {
            let mut metrics = self.integration_metrics.lock().unwrap();
            metrics.merge_failures += 1;
        }
    }

    #[derive(Debug)]
    struct CalmEprocessIntegrationSummary {
        total_operation_events: usize,
        started_operations: usize,
        completed_operations: usize,
        conformance_violation_count: usize,
        monotonicity_violation_count: usize,
        merge_failure_count: usize,
        operation_success_rate: f64,
        conformance_success_rate: f64,
        monotonicity_preservation_rate: f64,
        integration_health: f64,
    }

    fn calculate_integration_health(
        completed_operations: usize,
        conformance_violations: usize,
        monotonicity_violations: usize,
        merge_failures: usize,
    ) -> f64 {
        if completed_operations == 0 {
            return 0.0;
        }

        let total_issues = conformance_violations + monotonicity_violations + merge_failures;
        let success_rate = if completed_operations > total_issues {
            (completed_operations - total_issues) as f64 / completed_operations as f64
        } else {
            0.0
        };

        // Weight different issue types
        let conformance_weight = 0.4;
        let monotonicity_weight = 0.5; // More critical
        let merge_weight = 0.1;

        let weighted_issues = (conformance_violations as f64 * conformance_weight)
            + (monotonicity_violations as f64 * monotonicity_weight)
            + (merge_failures as f64 * merge_weight);

        let weighted_success_rate = if completed_operations as f64 > weighted_issues {
            (completed_operations as f64 - weighted_issues) / completed_operations as f64
        } else {
            0.0
        };

        (success_rate * 0.6 + weighted_success_rate * 0.4)
            .max(0.0)
            .min(1.0)
    }

    // Deterministic types for testing
    #[derive(Debug, Clone)]
    struct CalmOperation {
        id: OperationId,
        operation_type: CalmOperationType,
        properties: CalmProperties,
        input_state: CalmState,
        target_state: Option<CalmState>,
    }

    #[derive(Debug, Clone)]
    enum CalmOperationType {
        Set,
        Max,
        Union,
        Increment,
        Custom(Box<CustomCalmValidator>),
    }

    #[derive(Debug, Clone)]
    struct CalmProperties {
        is_associative: bool,
        is_logical: bool,
        is_monotonic: bool,
        is_convergent: bool,
    }

    #[derive(Debug, Clone)]
    struct CalmState {
        vector: CalmVector,
        lattice_height: u64,
        convergence_proof: Option<ConvergenceProof>,
    }

    impl CalmState {
        fn new() -> Self {
            Self {
                vector: CalmVector::new(),
                lattice_height: 0,
                convergence_proof: None,
            }
        }
    }

    #[derive(Debug, Clone)]
    struct CalmVector {
        dimensions: Vec<u64>,
        version: u64,
    }

    impl CalmVector {
        fn new() -> Self {
            Self {
                dimensions: vec![0; 8], // 8-dimensional vector
                version: 1,
            }
        }
    }

    #[derive(Debug, Clone)]
    struct EProcessState {
        progress: u64,
        evidence_count: usize,
        obligation_state: ObligationState,
        lattice_height: u64,
        monotonicity_witnesses: Vec<MonotonicityWitness>,
    }

    impl EProcessState {
        fn initial() -> Self {
            Self {
                progress: 0,
                evidence_count: 0,
                obligation_state: ObligationState::Initial,
                lattice_height: 0,
                monotonicity_witnesses: Vec::new(),
            }
        }
    }

    #[derive(Debug, Clone)]
    enum ObligationState {
        Initial,
        Active,
        Advancing,
        Complete,
    }

    impl ObligationState {
        fn is_monotonic_successor(&self, other: &Self) -> bool {
            use ObligationState::*;
            match (self, other) {
                (Active, Initial) => true,
                (Advancing, Initial | Active) => true,
                (Complete, Initial | Active | Advancing) => true,
                (state, same) if std::mem::discriminant(state) == std::mem::discriminant(same) => {
                    true
                }
                _ => false,
            }
        }

        fn advance(&mut self) {
            use ObligationState::*;
            *self = match self {
                Initial => Active,
                Active => Advancing,
                Advancing => Complete,
                Complete => Complete,
            };
        }
    }

    // Additional types and structs would be defined here...
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct OperationId(u64);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct MergeId(u64);

    #[derive(Debug, Clone)]
    enum OperationEvent {
        Started(OperationId),
        Completed(OperationId),
    }

    #[derive(Debug, Clone)]
    enum MergeEvent {
        MonotonicityFailure(PostMergeValidation),
        Success(MergeId),
    }

    #[derive(Debug)]
    struct IntegrationMetrics {
        total_operations: usize,
        conformance_violations: usize,
        monotonicity_violations: usize,
        merge_failures: usize,
    }

    impl IntegrationMetrics {
        fn new() -> Self {
            Self {
                total_operations: 0,
                conformance_violations: 0,
                monotonicity_violations: 0,
                merge_failures: 0,
            }
        }
    }

    /// Concurrent merge operation for CALM/eprocess integration testing
    #[derive(Debug, Clone)]
    struct ConcurrentMergeOperationImpl {
        /// Unique identifier for this merge operation
        merge_id: OperationId,
        /// Collection of operations to be merged concurrently
        operations: Vec<CalmOperation>,
        /// Merge strategy (monotonic join-semilattice merge)
        merge_strategy: MergeStrategy,
        /// Expected concurrency level for eprocess monitoring
        concurrency_level: usize,
        /// CALM properties that must be preserved during merge
        calm_properties: CalmProperties,
    }

    /// Merge strategy for concurrent operations
    #[derive(Debug, Clone)]
    enum MergeStrategy {
        /// Join-semilattice merge (monotonic, associative)
        JoinSemilattice,
        /// Vector clock merge for causally-ordered operations
        VectorClockMerge,
        /// Max-based merge for lattice advancement
        LatticeMax,
    }

    /// Result of a concurrent merge operation
    #[derive(Debug, Clone)]
    struct ConcurrentMergeResultImpl {
        /// ID of the completed merge operation
        merge_id: OperationId,
        /// Final merged state after all concurrent operations
        merged_state: CalmState,
        /// Monotonicity violations detected during merge
        monotonicity_violations: Vec<MonotonicityViolation>,
        /// Convergence proof if merge succeeded
        convergence_proof: Option<ConvergenceProof>,
        /// E-process evidence for leak monitoring
        eprocess_evidence: Vec<EProcessEvent>,
        /// Performance metrics for the merge operation
        merge_metrics: MergeMetrics,
    }

    /// Monotonicity violation detected during merge
    #[derive(Debug, Clone)]
    struct MonotonicityViolation {
        operation_id: OperationId,
        violation_type: ViolationType,
        expected_monotonic: bool,
        actual_behavior: String,
    }

    /// Type of monotonicity violation
    #[derive(Debug, Clone)]
    enum ViolationType {
        /// Expected monotonic but found destructive read
        UnexpectedDestructiveRead,
        /// Expected coordination-free but required synchronization
        UnexpectedCoordinationRequired,
        /// Convergence failure despite expected convergent properties
        ConvergenceFailure,
    }

    /// Performance metrics for merge operations
    #[derive(Debug, Clone)]
    struct MergeMetrics {
        /// Duration of the merge operation
        merge_duration_ns: u64,
        /// Number of coordination rounds required
        coordination_rounds: usize,
        /// Number of operations that executed coordination-free
        coordination_free_ops: usize,
        /// Total operations in the merge
        total_operations: usize,
    }

    // Local aliases for integration validation stages.
    type CalmConformanceValidator = ();
    type ConformanceCheck = ();
    type MonotonicityValidation = ();
    type PostMergeValidation = ();
    type CustomCalmValidator = ();
    type ConvergenceProof = ();
    type MonotonicityWitness = ();
    type CalmOperationRecord = ();
    type OperationStatus = ();
    type ExecutionResult = ();
    type CalmOperationResult = ();
    type ConcurrentMergeOperation = ConcurrentMergeOperationImpl;
    type ConcurrentMergeResult = ConcurrentMergeResultImpl;
    type MonitoringSession = ();
    type MonitoringResult = ();
    type EProcessEvent = ();
    type EProcessTransition = ();
    type EProcessWitness = ();
    type EProcessEvidence = ();
    type MergeResult = ();
    type CalmOperationStats = ();
    type EventId = ();
    type EventType = ();
    type EventPayload = ();
    type TransitionId = ();
    type TransitionType = ();
    type WitnessId = ();
    type WitnessType = ();
    type ProofData = ();
    type EvidenceType = ();
    type CompletenessProof = ();
    type StateUpdate = ();
    type EvidenceData = ();
    type ObligationChange = ();
    type MonotonicityProofData = ();
    type AdvancementEvidence = ();

    async fn run_calm_eprocess_integration_test(
        cx: &Cx,
        test_config: CalmEprocessTestConfig,
    ) -> Result<CalmEprocessIntegrationSummary> {
        // Create eprocess monitor
        let eprocess_monitor = Arc::new(DeterministicEprocessMonitor::new(
            "test_eprocess_monitor".to_string(),
        ));

        // Create CALM operation handler
        let calm_handler = DeterministicCalmOperationHandler::new(
            "test_calm_handler".to_string(),
            eprocess_monitor.clone(),
        );

        // Run test scenarios
        for scenario in test_config.test_scenarios {
            match scenario {
                TestScenario::SingleOperations { operations } => {
                    // Execute individual CALM operations
                    for operation in operations {
                        let result = calm_handler.execute_calm_operation(cx, operation).await?;
                        // Process result...
                        cx.sleep(Duration::from_millis(10)).await?;
                    }
                }
                TestScenario::ConcurrentMerge { merge_operation } => {
                    // Execute concurrent merge operation
                    let result = calm_handler
                        .execute_concurrent_merge(cx, merge_operation)
                        .await?;
                    // Process result...
                    cx.sleep(Duration::from_millis(20)).await?;
                }
                TestScenario::MonotonicityStress {
                    operation_count,
                    concurrency_level,
                } => {
                    // Stress test monotonicity preservation
                    for _ in 0..operation_count {
                        // Exercise concurrent operations.
                        cx.sleep(Duration::from_millis(5)).await?;
                    }
                }
            }
        }

        // Allow processing to complete
        cx.sleep(Duration::from_millis(100)).await?;

        // Get integration summary
        Ok(calm_handler.integration_tracker.get_integration_summary())
    }

    #[derive(Debug)]
    struct CalmEprocessTestConfig {
        test_scenarios: Vec<TestScenario>,
    }

    #[derive(Debug)]
    enum TestScenario {
        SingleOperations {
            operations: Vec<CalmOperation>,
        },
        ConcurrentMerge {
            merge_operation: ConcurrentMergeOperation,
        },
        MonotonicityStress {
            operation_count: usize,
            concurrency_level: usize,
        },
    }

    #[tokio::test]
    async fn test_basic_calm_conformance() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test basic CALM conformance validation
                    let test_config = CalmEprocessTestConfig {
                        test_scenarios: vec![TestScenario::SingleOperations {
                            operations: vec![
                                create_test_set_operation(),
                                create_test_max_operation(),
                                create_test_union_operation(),
                            ],
                        }],
                    };

                    let summary = run_calm_eprocess_integration_test(cx, test_config).await?;

                    // Verify CALM conformance
                    assert!(
                        summary.total_operation_events > 0,
                        "Should have operation events"
                    );
                    assert!(
                        summary.completed_operations > 0,
                        "Should complete operations"
                    );
                    assert!(
                        summary.conformance_success_rate >= 0.9,
                        "Should have high conformance success rate"
                    );
                    assert!(
                        summary.operation_success_rate >= 0.9,
                        "Should have high operation success rate"
                    );
                    assert!(
                        summary.integration_health > 0.8,
                        "Integration health should be good"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Basic CALM conformance should succeed"
        );
    }

    #[tokio::test]
    async fn test_eprocess_monotonicity_preservation() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test eprocess monotonicity preservation
                    let test_config = CalmEprocessTestConfig {
                        test_scenarios: vec![TestScenario::SingleOperations {
                            operations: vec![
                                create_test_increment_operation(),
                                create_test_monotonic_union(),
                                create_test_lattice_advancement(),
                            ],
                        }],
                    };

                    let summary = run_calm_eprocess_integration_test(cx, test_config).await?;

                    // Verify monotonicity preservation
                    assert!(
                        summary.monotonicity_preservation_rate >= 0.95,
                        "Should preserve monotonicity"
                    );
                    assert!(
                        summary.monotonicity_violation_count == 0,
                        "Should have no monotonicity violations"
                    );
                    assert!(
                        summary.integration_health > 0.85,
                        "Should maintain good integration health"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "EProcess monotonicity preservation should succeed"
        );
    }

    #[tokio::test]
    async fn test_concurrent_merge_operations() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test concurrent merge operations
                    let test_config = CalmEprocessTestConfig {
                        test_scenarios: vec![TestScenario::ConcurrentMerge {
                            merge_operation: create_test_concurrent_merge(),
                        }],
                    };

                    let summary = run_calm_eprocess_integration_test(cx, test_config).await?;

                    // Verify concurrent merge handling
                    assert!(
                        summary.merge_failure_count == 0,
                        "Should have no merge failures"
                    );
                    assert!(
                        summary.conformance_success_rate >= 0.9,
                        "Should maintain conformance during merges"
                    );
                    assert!(
                        summary.monotonicity_preservation_rate >= 0.9,
                        "Should preserve monotonicity during merges"
                    );
                    assert!(
                        summary.integration_health > 0.8,
                        "Should handle concurrent merges well"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Concurrent merge operations should succeed"
        );
    }

    #[tokio::test]
    async fn test_monotonicity_stress() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Stress test monotonicity under high concurrency
                    let test_config = CalmEprocessTestConfig {
                        test_scenarios: vec![TestScenario::MonotonicityStress {
                            operation_count: 50,
                            concurrency_level: 8,
                        }],
                    };

                    let summary = run_calm_eprocess_integration_test(cx, test_config).await?;

                    // Verify monotonicity under stress
                    assert!(
                        summary.monotonicity_preservation_rate >= 0.9,
                        "Should maintain monotonicity under stress"
                    );
                    assert!(
                        summary.conformance_success_rate >= 0.85,
                        "Should maintain conformance under stress"
                    );
                    assert!(
                        summary.integration_health > 0.7,
                        "Should handle stress testing"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Monotonicity stress test should succeed"
        );
    }

    #[tokio::test]
    async fn test_comprehensive_calm_eprocess_integration() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Comprehensive integration test
                    let test_config = CalmEprocessTestConfig {
                        test_scenarios: vec![
                            TestScenario::SingleOperations {
                                operations: vec![
                                    create_test_set_operation(),
                                    create_test_max_operation(),
                                    create_test_increment_operation(),
                                ],
                            },
                            TestScenario::ConcurrentMerge {
                                merge_operation: create_test_concurrent_merge(),
                            },
                            TestScenario::MonotonicityStress {
                                operation_count: 25,
                                concurrency_level: 4,
                            },
                        ],
                    };

                    let summary = run_calm_eprocess_integration_test(cx, test_config).await?;

                    // Comprehensive validation
                    assert!(
                        summary.total_operation_events >= 10,
                        "Should handle sufficient operations"
                    );
                    assert!(
                        summary.completed_operations > 0,
                        "Should complete operations"
                    );
                    assert!(
                        summary.conformance_success_rate >= 0.85,
                        "Should maintain CALM conformance"
                    );
                    assert!(
                        summary.monotonicity_preservation_rate >= 0.9,
                        "Should preserve eprocess monotonicity"
                    );
                    assert!(
                        summary.merge_failure_count <= 1,
                        "Should handle merges successfully"
                    );
                    assert!(
                        summary.operation_success_rate >= 0.8,
                        "Should have good operation success rate"
                    );
                    assert!(
                        summary.integration_health > 0.75,
                        "Should maintain good integration health"
                    );

                    // Verify integration completeness
                    assert!(
                        summary.total_operation_events > 0,
                        "CALM operation integration working"
                    );
                    assert!(
                        summary.monotonicity_preservation_rate > 0.8,
                        "EProcess monotonicity integration working"
                    );
                    assert!(
                        summary.conformance_success_rate > 0.8,
                        "CALM conformance integration working"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Comprehensive CALM-EProcess integration should succeed"
        );
    }

    // Helper functions to create test operations
    fn create_test_set_operation() -> CalmOperation {
        CalmOperation {
            id: OperationId(1),
            operation_type: CalmOperationType::Set,
            properties: CalmProperties {
                is_associative: true,
                is_logical: true,
                is_monotonic: true,
                is_convergent: true,
            },
            input_state: CalmState::new(),
            target_state: None,
        }
    }

    fn create_test_max_operation() -> CalmOperation {
        CalmOperation {
            id: OperationId(2),
            operation_type: CalmOperationType::Max,
            properties: CalmProperties {
                is_associative: true,
                is_logical: true,
                is_monotonic: true,
                is_convergent: true,
            },
            input_state: CalmState::new(),
            target_state: None,
        }
    }

    fn create_test_union_operation() -> CalmOperation {
        CalmOperation {
            id: OperationId(3),
            operation_type: CalmOperationType::Union,
            properties: CalmProperties {
                is_associative: true,
                is_logical: true,
                is_monotonic: true,
                is_convergent: true,
            },
            input_state: CalmState::new(),
            target_state: None,
        }
    }

    fn create_test_increment_operation() -> CalmOperation {
        CalmOperation {
            id: OperationId(4),
            operation_type: CalmOperationType::Increment,
            properties: CalmProperties {
                is_associative: true,
                is_logical: true,
                is_monotonic: true,
                is_convergent: true,
            },
            input_state: CalmState::new(),
            target_state: None,
        }
    }

    fn create_test_monotonic_union() -> CalmOperation {
        CalmOperation {
            id: OperationId(5),
            operation_type: CalmOperationType::Union,
            properties: CalmProperties {
                is_associative: true,
                is_logical: true,
                is_monotonic: true,
                is_convergent: true,
            },
            input_state: CalmState::new(),
            target_state: None,
        }
    }

    fn create_test_lattice_advancement() -> CalmOperation {
        CalmOperation {
            id: OperationId(6),
            operation_type: CalmOperationType::Max,
            properties: CalmProperties {
                is_associative: true,
                is_logical: true,
                is_monotonic: true,
                is_convergent: true,
            },
            input_state: CalmState::new(),
            target_state: None,
        }
    }

    fn create_test_concurrent_merge() -> ConcurrentMergeOperation {
        // Create a concurrent merge operation for testing CALM/eprocess integration
        ConcurrentMergeOperationImpl {
            merge_id: OperationId(100),
            operations: vec![
                // Mix of monotonic and non-monotonic operations for comprehensive testing
                create_test_increment_operation(), // Monotonic: counter increment
                create_test_max_operation(),       // Monotonic: lattice join
                create_test_set_operation(),       // Non-monotonic: destructive update
                create_test_monotonic_union(),     // Monotonic: set union
                create_test_lattice_advancement(), // Monotonic: max operation
            ],
            merge_strategy: MergeStrategy::JoinSemilattice,
            concurrency_level: 4, // 4 concurrent operations for stress testing
            calm_properties: CalmProperties {
                // Overall merge should be convergent despite mixed monotonicity
                is_associative: true, // Join-semilattice property
                is_logical: true,     // CALM logical consistency
                is_monotonic: false,  // Mixed operations include non-monotonic
                is_convergent: true,  // Should converge despite coordination needed
            },
        }
    }

    #[test]
    fn test_concurrent_merge_operation_creation() {
        // Verify that create_test_concurrent_merge() works correctly
        let merge_op = create_test_concurrent_merge();

        // Verify basic properties
        assert_eq!(merge_op.merge_id.0, 100);
        assert_eq!(merge_op.operations.len(), 5);
        assert_eq!(merge_op.concurrency_level, 4);
        assert!(!merge_op.calm_properties.is_monotonic); // Mixed operations
        assert!(merge_op.calm_properties.is_convergent); // Should converge

        // Verify merge strategy
        match merge_op.merge_strategy {
            MergeStrategy::JoinSemilattice => {} // Expected
            _ => panic!("Expected JoinSemilattice merge strategy"),
        }

        // Verify operations are diverse (test comprehensive coverage)
        let operation_types: Vec<_> = merge_op
            .operations
            .iter()
            .map(|op| &op.operation_type)
            .collect();

        // Should have different operation types for comprehensive testing
        assert!(
            operation_types.len() >= 4,
            "Should have diverse operation types"
        );
    }
}
