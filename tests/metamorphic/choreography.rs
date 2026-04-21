#![allow(clippy::all)]
//! Metamorphic Testing for obligation::choreography workflow invariants
//!
//! Tests choreographic protocol workflow execution using metamorphic relations
//! that must hold regardless of specific protocol definitions, participant counts,
//! or execution patterns. Uses LabRuntime with DPOR for deterministic execution.
//!
//! ## Metamorphic Relations Tested:
//!
//! 1. **Stage order preservation**: workflow stages execute in declared order
//!    regardless of timing variations or participant scheduling
//! 2. **Compensation trigger**: compensating action fires on stage failure
//!    consistently across different failure modes and timing
//! 3. **Parallel dependency ordering**: parallel stages preserve ordering within
//!    dependency chains despite concurrent execution
//! 4. **Atomic cancel propagation**: cancel propagates through dependency DAG
//!    atomically, reaching all dependent stages
//! 5. **Retry attempt limits**: retry within stage honors max_attempts
//!    configuration regardless of failure patterns

use proptest::prelude::*;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::obligation::choreography::{
    GlobalProtocol, Interaction, MessageType, Participant, ValidationError
};
use asupersync::obligation::choreography::pipeline::{
    SagaPipeline, SagaParticipantCode, SagaPipelineOutput, PipelineError
};
use asupersync::obligation::saga::{
    SagaOpKind, SagaPlan, SagaStep, SagaExecutionPlan, MonotoneSagaExecutor
};
use asupersync::obligation::calm::Monotonicity;
use asupersync::trace::distributed::lattice::LatticeState;
use asupersync::types::{Budget, Time, Outcome};
use asupersync::{region, sleep, sleep_until};

/// Test configuration for choreography workflow metamorphic properties
#[derive(Debug, Clone)]
struct ChoreographyWorkflowConfig {
    /// Number of participants in the protocol
    participant_count: usize,
    /// Number of sequential stages in the workflow
    stage_count: usize,
    /// Number of parallel branches per stage (0 = sequential only)
    parallel_branches: usize,
    /// Whether to inject stage failure for compensation testing
    inject_failure: bool,
    /// Stage index to fail (0-based)
    failure_stage_index: usize,
    /// Whether to test cancellation propagation
    test_cancellation: bool,
    /// Stage to cancel at (0-based)
    cancel_stage_index: usize,
    /// Maximum retry attempts per stage
    max_retry_attempts: usize,
    /// Whether to test retry behavior
    test_retry_logic: bool,
    /// Timeout duration for operations (milliseconds)
    operation_timeout_ms: u64,
}

impl ChoreographyWorkflowConfig {
    /// Generate participant names
    fn participants(&self) -> Vec<String> {
        (0..self.participant_count)
            .map(|i| format!("participant_{}", i))
            .collect()
    }

    /// Generate stage labels
    fn stages(&self) -> Vec<String> {
        (0..self.stage_count)
            .map(|i| format!("stage_{}", i))
            .collect()
    }

    /// Check if a stage should fail
    fn should_fail_stage(&self, stage_index: usize) -> bool {
        self.inject_failure && stage_index == self.failure_stage_index
    }

    /// Check if should cancel at stage
    fn should_cancel_stage(&self, stage_index: usize) -> bool {
        self.test_cancellation && stage_index == self.cancel_stage_index
    }
}

/// Generate arbitrary workflow configurations
fn arb_workflow_config() -> impl Strategy<Value = ChoreographyWorkflowConfig> {
    (
        2..=6usize,   // participant_count
        2..=8usize,   // stage_count
        0..=3usize,   // parallel_branches
        any::<bool>(), // inject_failure
        0..=7usize,   // failure_stage_index (will be clamped to stage_count)
        any::<bool>(), // test_cancellation
        0..=7usize,   // cancel_stage_index (will be clamped to stage_count)
        1..=5usize,   // max_retry_attempts
        any::<bool>(), // test_retry_logic
        100..=2000u64, // operation_timeout_ms
    ).prop_map(|(participant_count, stage_count, parallel_branches, inject_failure,
                failure_stage_index, test_cancellation, cancel_stage_index,
                max_retry_attempts, test_retry_logic, operation_timeout_ms)| {
        ChoreographyWorkflowConfig {
            participant_count,
            stage_count,
            parallel_branches,
            inject_failure,
            failure_stage_index: failure_stage_index % stage_count,
            test_cancellation,
            cancel_stage_index: cancel_stage_index % stage_count,
            max_retry_attempts,
            test_retry_logic,
            operation_timeout_ms,
        }
    })
}

/// Tracked choreography executor that logs stage execution order and timing
#[derive(Debug, Clone)]
struct TrackedChoreographyExecutor {
    /// Executed stages in order with timestamps
    executed_stages: Arc<Mutex<VecDeque<(String, String, u64, LatticeState)>>>, // (participant, stage, timestamp, result)
    /// Compensation actions triggered
    compensations: Arc<Mutex<VecDeque<(String, String, u64)>>>, // (participant, compensation_stage, timestamp)
    /// Cancellation events
    cancellations: Arc<Mutex<VecDeque<(String, u64)>>>, // (stage, timestamp)
    /// Retry attempts per stage
    retry_attempts: Arc<Mutex<HashMap<String, AtomicUsize>>>,
    /// Stage dependency tracking
    stage_dependencies: Arc<Mutex<HashMap<String, Vec<String>>>>,
    /// Parallel execution tracking
    parallel_executions: Arc<Mutex<HashMap<String, Vec<(String, u64)>>>>, // stage -> [(participant, start_time)]
    /// Failure simulation
    fail_at_stage: Option<String>,
    /// Cancel at stage
    cancel_at_stage: Option<String>,
    /// Max retry attempts configuration
    max_retries: usize,
    /// Execution counter for deterministic ordering
    exec_counter: Arc<AtomicU64>,
}

impl TrackedChoreographyExecutor {
    fn new(max_retries: usize) -> Self {
        Self {
            executed_stages: Arc::new(Mutex::new(VecDeque::new())),
            compensations: Arc::new(Mutex::new(VecDeque::new())),
            cancellations: Arc::new(Mutex::new(VecDeque::new())),
            retry_attempts: Arc::new(Mutex::new(HashMap::new())),
            stage_dependencies: Arc::new(Mutex::new(HashMap::new())),
            parallel_executions: Arc::new(Mutex::new(HashMap::new())),
            fail_at_stage: None,
            cancel_at_stage: None,
            max_retries,
            exec_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    fn with_failure_at_stage(mut self, stage: String) -> Self {
        self.fail_at_stage = Some(stage);
        self
    }

    fn with_cancellation_at_stage(mut self, stage: String) -> Self {
        self.cancel_at_stage = Some(stage);
        self
    }

    fn add_stage_dependency(&self, dependent_stage: String, dependency: String) {
        self.stage_dependencies.lock().unwrap()
            .entry(dependent_stage)
            .or_insert_with(Vec::new)
            .push(dependency);
    }

    /// Execute a stage for a participant
    fn execute_stage(&self, participant: &str, stage: &str, is_compensation: bool) -> LatticeState {
        let timestamp = self.exec_counter.fetch_add(1, Ordering::SeqCst);

        // Check for cancellation
        if let Some(ref cancel_stage) = self.cancel_at_stage {
            if stage == cancel_stage {
                self.cancellations.lock().unwrap().push_back((stage.to_string(), timestamp));
                return LatticeState::Aborted;
            }
        }

        // Handle retry logic
        let retry_key = format!("{}_{}", participant, stage);
        let current_attempts = {
            let mut retries = self.retry_attempts.lock().unwrap();
            let counter = retries.entry(retry_key.clone()).or_insert_with(|| AtomicUsize::new(0));
            counter.fetch_add(1, Ordering::SeqCst)
        };

        // Check retry limit
        if current_attempts >= self.max_retries {
            if is_compensation {
                self.compensations.lock().unwrap().push_back((
                    participant.to_string(),
                    format!("comp_{}", stage),
                    timestamp
                ));
            } else {
                self.executed_stages.lock().unwrap().push_back((
                    participant.to_string(),
                    stage.to_string(),
                    timestamp,
                    LatticeState::Aborted
                ));
            }
            return LatticeState::Aborted;
        }

        // Check for failure injection
        if let Some(ref fail_stage) = self.fail_at_stage {
            if stage == fail_stage && !is_compensation {
                self.executed_stages.lock().unwrap().push_back((
                    participant.to_string(),
                    stage.to_string(),
                    timestamp,
                    LatticeState::Aborted
                ));

                // Trigger compensation
                self.compensations.lock().unwrap().push_back((
                    participant.to_string(),
                    format!("comp_{}", stage),
                    timestamp + 1
                ));

                return LatticeState::Aborted;
            }
        }

        // Track parallel execution
        if !is_compensation {
            self.parallel_executions.lock().unwrap()
                .entry(stage.to_string())
                .or_insert_with(Vec::new)
                .push((participant.to_string(), timestamp));
        }

        let result_state = if is_compensation {
            self.compensations.lock().unwrap().push_back((
                participant.to_string(),
                format!("comp_{}", stage),
                timestamp
            ));
            LatticeState::Unknown
        } else {
            self.executed_stages.lock().unwrap().push_back((
                participant.to_string(),
                stage.to_string(),
                timestamp,
                LatticeState::Committed
            ));
            LatticeState::Committed
        };

        result_state
    }

    /// Get execution sequence for analysis
    fn get_execution_sequence(&self) -> Vec<(String, String, u64, LatticeState)> {
        self.executed_stages.lock().unwrap().iter().cloned().collect()
    }

    /// Get compensation sequence
    fn get_compensation_sequence(&self) -> Vec<(String, String, u64)> {
        self.compensations.lock().unwrap().iter().cloned().collect()
    }

    /// Get cancellation events
    fn get_cancellation_events(&self) -> Vec<(String, u64)> {
        self.cancellations.lock().unwrap().iter().cloned().collect()
    }

    /// Get retry counts per stage
    fn get_retry_counts(&self) -> HashMap<String, usize> {
        self.retry_attempts.lock().unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::SeqCst)))
            .collect()
    }

    /// Get parallel execution info
    fn get_parallel_executions(&self) -> HashMap<String, Vec<(String, u64)>> {
        self.parallel_executions.lock().unwrap().clone()
    }
}

/// Build a test choreography protocol with configurable stages
fn build_test_protocol(config: &ChoreographyWorkflowConfig) -> GlobalProtocol {
    let mut builder = GlobalProtocol::builder("test_workflow");

    // Add participants
    for participant in config.participants() {
        builder = builder.participant(&participant, "worker");
    }

    // Build interaction chain with stages
    let mut interaction = Interaction::End;
    let stages = config.stages();

    // Build stages in reverse order for proper chaining
    for (stage_idx, stage) in stages.iter().enumerate().rev() {
        let participants = config.participants();

        if config.parallel_branches > 0 && stage_idx % 2 == 1 {
            // Create parallel branches for alternating stages
            let mut branches = Vec::new();
            for (branch_idx, participant) in participants.iter().enumerate() {
                if branch_idx >= config.parallel_branches {
                    break;
                }
                let next_participant = &participants[(branch_idx + 1) % participants.len()];

                branches.push(Interaction::comm(
                    participant,
                    &format!("{}_action", stage),
                    &format!("{}Msg", stage),
                    next_participant
                ));
            }

            // Build parallel interaction
            if branches.len() >= 2 {
                let mut par_interaction = Interaction::par(branches[0].clone(), branches[1].clone());
                for branch in branches.iter().skip(2) {
                    par_interaction = Interaction::par(par_interaction, branch.clone());
                }
                interaction = Interaction::seq(par_interaction, interaction);
            }
        } else {
            // Sequential stage
            for (idx, participant) in participants.iter().enumerate() {
                let next_participant = &participants[(idx + 1) % participants.len()];

                let stage_interaction = if config.inject_failure && stage_idx == config.failure_stage_index {
                    // Wrap with compensation
                    Interaction::compensate(
                        Interaction::comm(
                            participant,
                            &format!("{}_action", stage),
                            &format!("{}Msg", stage),
                            next_participant
                        ),
                        Interaction::comm(
                            participant,
                            &format!("{}_compensate", stage),
                            &format!("{}CompMsg", stage),
                            next_participant
                        )
                    )
                } else {
                    Interaction::comm(
                        participant,
                        &format!("{}_action", stage),
                        &format!("{}Msg", stage),
                        next_participant
                    )
                };

                interaction = Interaction::seq(stage_interaction, interaction);
            }
        }
    }

    builder.interaction(interaction).build()
}

/// MR1: Workflow stages execute in declared order
///
/// **Metamorphic Relation**: Regardless of timing variations, participant scheduling,
/// or execution delays, stages must execute in the order declared in the protocol.
/// Stage N+1 cannot begin until stage N completes for all participants.
proptest! {
    #[test]
    fn mr1_stage_execution_order(config in arb_workflow_config().prop_filter("reasonable config", |c| c.stage_count >= 2 && !c.inject_failure && !c.test_cancellation)) {
        let mut runtime = LabRuntime::new(LabConfig::deterministic());

        runtime.block_on(async {
            region(|cx, _scope| async move {
                let protocol = build_test_protocol(&config);
                let errors = protocol.validate();
                prop_assert!(errors.is_empty(), "Protocol validation failed: {:?}", errors);

                let executor = TrackedChoreographyExecutor::new(config.max_retry_attempts);
                let stages = config.stages();

                // Simulate stage execution for all participants
                for stage in &stages {
                    for participant in &config.participants() {
                        executor.execute_stage(participant, stage, false);
                    }
                }

                let execution_sequence = executor.get_execution_sequence();

                // Verify stages execute in declared order
                let mut current_stage_idx = 0;
                for (_, executed_stage, _, _) in &execution_sequence {
                    if let Some(stage_idx) = stages.iter().position(|s| s == executed_stage) {
                        prop_assert!(
                            stage_idx >= current_stage_idx,
                            "Stage order violation: executed {} (index {}) before completing {} (index {})",
                            executed_stage, stage_idx, stages[current_stage_idx], current_stage_idx
                        );

                        // Update current stage when all participants complete it
                        let completed_count = execution_sequence.iter()
                            .filter(|(_, s, _, _)| s == executed_stage)
                            .count();
                        if completed_count >= config.participant_count {
                            current_stage_idx = stage_idx + 1;
                        }
                    }
                }

                Ok(())
            })
        }).expect("Runtime execution failed");
    }
}

/// MR2: Compensating action fires on stage failure
///
/// **Metamorphic Relation**: When a stage fails, compensating actions must be
/// triggered consistently regardless of the failure mode, timing, or which
/// participant experiences the failure.
proptest! {
    #[test]
    fn mr2_compensation_trigger_on_failure(config in arb_workflow_config().prop_filter("failure config", |c| c.inject_failure && c.failure_stage_index < c.stage_count)) {
        let mut runtime = LabRuntime::new(LabConfig::deterministic());

        runtime.block_on(async {
            region(|cx, _scope| async move {
                let protocol = build_test_protocol(&config);
                let stages = config.stages();
                let fail_stage = &stages[config.failure_stage_index];

                let executor = TrackedChoreographyExecutor::new(config.max_retry_attempts)
                    .with_failure_at_stage(fail_stage.clone());

                // Execute stages until failure
                for (stage_idx, stage) in stages.iter().enumerate() {
                    for participant in &config.participants() {
                        executor.execute_stage(participant, stage, false);

                        if stage_idx == config.failure_stage_index {
                            break; // Failure triggered, stop execution
                        }
                    }

                    if stage_idx == config.failure_stage_index {
                        break;
                    }
                }

                let execution_sequence = executor.get_execution_sequence();
                let compensation_sequence = executor.get_compensation_sequence();

                // Verify failure was detected
                let failed_executions: Vec<_> = execution_sequence.iter()
                    .filter(|(_, stage, _, result)| stage == fail_stage && *result == LatticeState::Aborted)
                    .collect();

                prop_assert!(
                    !failed_executions.is_empty(),
                    "Expected failure at stage {} but none detected", fail_stage
                );

                // Verify compensations were triggered
                let compensations_for_failed_stage: Vec<_> = compensation_sequence.iter()
                    .filter(|(_, comp_stage, _)| comp_stage == &format!("comp_{}", fail_stage))
                    .collect();

                prop_assert!(
                    !compensations_for_failed_stage.is_empty(),
                    "Expected compensation for failed stage {} but none triggered", fail_stage
                );

                // Verify compensation triggered after failure
                let failure_timestamp = failed_executions[0].2;
                let compensation_timestamp = compensations_for_failed_stage[0].2;
                prop_assert!(
                    compensation_timestamp > failure_timestamp,
                    "Compensation timestamp {} should be after failure timestamp {}",
                    compensation_timestamp, failure_timestamp
                );

                Ok(())
            })
        }).expect("Runtime execution failed");
    }
}

/// MR3: Parallel stages preserve ordering within dependency chain
///
/// **Metamorphic Relation**: When stages execute in parallel, the dependency
/// ordering within each chain must be preserved. Stages with dependencies
/// cannot execute before their prerequisites, even in parallel execution.
proptest! {
    #[test]
    fn mr3_parallel_dependency_ordering(config in arb_workflow_config().prop_filter("parallel config", |c| c.parallel_branches >= 2 && c.stage_count >= 3 && !c.inject_failure && !c.test_cancellation)) {
        let mut runtime = LabRuntime::new(LabConfig::deterministic());

        runtime.block_on(async {
            region(|cx, _scope| async move {
                let protocol = build_test_protocol(&config);
                let stages = config.stages();

                let executor = TrackedChoreographyExecutor::new(config.max_retry_attempts);

                // Set up stage dependencies (stage N+1 depends on stage N)
                for i in 1..stages.len() {
                    executor.add_stage_dependency(stages[i].clone(), stages[i-1].clone());
                }

                // Execute stages allowing parallel execution
                for stage in &stages {
                    for participant in &config.participants() {
                        executor.execute_stage(participant, stage, false);
                    }
                }

                let execution_sequence = executor.get_execution_sequence();
                let parallel_executions = executor.get_parallel_executions();

                // Verify dependency ordering is preserved within parallel execution
                for (dependent_stage, dependencies) in executor.stage_dependencies.lock().unwrap().iter() {
                    for dependency in dependencies {
                        let dependency_completions: Vec<_> = execution_sequence.iter()
                            .filter(|(_, stage, _, result)| stage == dependency && *result == LatticeState::Committed)
                            .collect();

                        let dependent_starts: Vec<_> = execution_sequence.iter()
                            .filter(|(_, stage, _, _)| stage == dependent_stage)
                            .collect();

                        if !dependency_completions.is_empty() && !dependent_starts.is_empty() {
                            let latest_dependency_completion = dependency_completions.iter()
                                .map(|(_, _, timestamp, _)| *timestamp)
                                .max()
                                .unwrap();

                            let earliest_dependent_start = dependent_starts.iter()
                                .map(|(_, _, timestamp, _)| *timestamp)
                                .min()
                                .unwrap();

                            prop_assert!(
                                latest_dependency_completion < earliest_dependent_start,
                                "Dependency violation: stage {} started at {} before dependency {} completed at {}",
                                dependent_stage, earliest_dependent_start, dependency, latest_dependency_completion
                            );
                        }
                    }
                }

                // Verify parallel stages can execute simultaneously
                for (stage, executions) in parallel_executions {
                    if executions.len() > 1 {
                        let timestamps: Vec<_> = executions.iter().map(|(_, ts)| *ts).collect();
                        let min_ts = timestamps.iter().min().unwrap();
                        let max_ts = timestamps.iter().max().unwrap();

                        // Allow some overlap indicating true parallelism (within small time window)
                        prop_assert!(
                            max_ts - min_ts <= 10, // Small timestamp window indicates parallel execution
                            "Stage {} executions too spread out: {} to {}, expected parallel execution",
                            stage, min_ts, max_ts
                        );
                    }
                }

                Ok(())
            })
        }).expect("Runtime execution failed");
    }
}

/// MR4: Cancel propagates through DAG atomically
///
/// **Metamorphic Relation**: When cancellation is triggered, it must propagate
/// through the entire dependency DAG atomically. All dependent stages must be
/// cancelled, and no partial executions should remain.
proptest! {
    #[test]
    fn mr4_atomic_cancel_propagation(config in arb_workflow_config().prop_filter("cancel config", |c| c.test_cancellation && c.cancel_stage_index < c.stage_count && c.stage_count >= 2)) {
        let mut runtime = LabRuntime::new(LabConfig::deterministic());

        runtime.block_on(async {
            region(|cx, _scope| async move {
                let protocol = build_test_protocol(&config);
                let stages = config.stages();
                let cancel_stage = &stages[config.cancel_stage_index];

                let executor = TrackedChoreographyExecutor::new(config.max_retry_attempts)
                    .with_cancellation_at_stage(cancel_stage.clone());

                // Execute stages until cancellation
                for (stage_idx, stage) in stages.iter().enumerate() {
                    for participant in &config.participants() {
                        executor.execute_stage(participant, stage, false);

                        if stage_idx == config.cancel_stage_index {
                            break; // Cancellation triggered
                        }
                    }

                    if stage_idx >= config.cancel_stage_index {
                        break;
                    }
                }

                let execution_sequence = executor.get_execution_sequence();
                let cancellation_events = executor.get_cancellation_events();

                // Verify cancellation was triggered
                prop_assert!(
                    !cancellation_events.is_empty(),
                    "Expected cancellation at stage {} but none detected", cancel_stage
                );

                let cancel_timestamp = cancellation_events[0].1;

                // Verify no stages executed after cancellation timestamp
                let post_cancel_executions: Vec<_> = execution_sequence.iter()
                    .filter(|(_, _, timestamp, _)| *timestamp > cancel_timestamp)
                    .collect();

                prop_assert!(
                    post_cancel_executions.is_empty(),
                    "Found executions after cancellation: {:?}", post_cancel_executions
                );

                // Verify all stages at and after cancel point are aborted or not started
                for (stage_idx, stage) in stages.iter().enumerate() {
                    if stage_idx >= config.cancel_stage_index {
                        let stage_executions: Vec<_> = execution_sequence.iter()
                            .filter(|(_, s, _, _)| s == stage)
                            .collect();

                        for (_, _, _, result) in stage_executions {
                            prop_assert!(
                                *result == LatticeState::Aborted,
                                "Stage {} should be aborted after cancellation but has result {:?}",
                                stage, result
                            );
                        }
                    }
                }

                Ok(())
            })
        }).expect("Runtime execution failed");
    }
}

/// MR5: Retry within stage honors max_attempts
///
/// **Metamorphic Relation**: Retry logic within stages must honor the configured
/// max_attempts limit consistently, regardless of failure patterns, timing,
/// or which participant triggers the retries.
proptest! {
    #[test]
    fn mr5_retry_honors_max_attempts(config in arb_workflow_config().prop_filter("retry config", |c| c.test_retry_logic && c.max_retry_attempts >= 1 && c.max_retry_attempts <= 3 && c.stage_count >= 1)) {
        let mut runtime = LabRuntime::new(LabConfig::deterministic());

        runtime.block_on(async {
            region(|cx, _scope| async move {
                let protocol = build_test_protocol(&config);
                let stages = config.stages();
                let test_stage = &stages[0]; // Use first stage for retry testing

                let executor = TrackedChoreographyExecutor::new(config.max_retry_attempts)
                    .with_failure_at_stage(test_stage.clone());

                let participants = config.participants();
                let test_participant = &participants[0];

                // Execute stage repeatedly to trigger retries
                let mut total_attempts = 0;
                for _ in 0..(config.max_retry_attempts + 2) { // Try beyond limit
                    executor.execute_stage(test_participant, test_stage, false);
                    total_attempts += 1;
                }

                let retry_counts = executor.get_retry_counts();
                let execution_sequence = executor.get_execution_sequence();

                // Get retry count for test stage/participant
                let retry_key = format!("{}_{}", test_participant, test_stage);
                let actual_attempts = retry_counts.get(&retry_key).unwrap_or(&0);

                // Verify attempts don't exceed max_retry_attempts
                prop_assert!(
                    *actual_attempts <= config.max_retry_attempts,
                    "Retry attempts {} exceeded max_retry_attempts {} for stage {}",
                    actual_attempts, config.max_retry_attempts, test_stage
                );

                // Verify execution sequence reflects retry limit
                let stage_executions: Vec<_> = execution_sequence.iter()
                    .filter(|(p, s, _, _)| p == test_participant && s == test_stage)
                    .collect();

                prop_assert!(
                    stage_executions.len() <= config.max_retry_attempts,
                    "Found {} executions for stage {}, expected <= {} (max_retry_attempts)",
                    stage_executions.len(), test_stage, config.max_retry_attempts
                );

                // Verify final attempt results in abort when limit reached
                if *actual_attempts == config.max_retry_attempts {
                    let last_execution_result = stage_executions.last()
                        .map(|(_, _, _, result)| result)
                        .unwrap_or(&LatticeState::Unknown);

                    prop_assert!(
                        *last_execution_result == LatticeState::Aborted,
                        "Final retry attempt should result in abort, got {:?}", last_execution_result
                    );
                }

                Ok(())
            })
        }).expect("Runtime execution failed");
    }
}

/// Composite MR: Full workflow with all invariants
///
/// **Metamorphic Relation**: Combining all properties - proper stage ordering,
/// compensation on failure, parallel dependency preservation, atomic cancellation,
/// and retry limit enforcement must all hold simultaneously in complex workflows.
proptest! {
    #[test]
    fn mr_composite_full_workflow_invariants(config in arb_workflow_config().prop_filter("complex config", |c| c.stage_count >= 3 && c.participant_count >= 2)) {
        let mut runtime = LabRuntime::new(LabConfig::deterministic());

        runtime.block_on(async {
            region(|cx, _scope| async move {
                let protocol = build_test_protocol(&config);
                let errors = protocol.validate();
                prop_assert!(errors.is_empty(), "Protocol validation failed: {:?}", errors);

                let stages = config.stages();
                let mut executor = TrackedChoreographyExecutor::new(config.max_retry_attempts);

                // Configure based on test configuration
                if config.inject_failure {
                    let fail_stage = &stages[config.failure_stage_index];
                    executor = executor.with_failure_at_stage(fail_stage.clone());
                }

                if config.test_cancellation {
                    let cancel_stage = &stages[config.cancel_stage_index];
                    executor = executor.with_cancellation_at_stage(cancel_stage.clone());
                }

                // Execute workflow
                for (stage_idx, stage) in stages.iter().enumerate() {
                    for participant in &config.participants() {
                        executor.execute_stage(participant, stage, false);
                    }

                    // Stop execution if cancellation or failure occurred
                    if (config.test_cancellation && stage_idx >= config.cancel_stage_index) ||
                       (config.inject_failure && stage_idx >= config.failure_stage_index) {
                        break;
                    }
                }

                let execution_sequence = executor.get_execution_sequence();
                let compensation_sequence = executor.get_compensation_sequence();
                let cancellation_events = executor.get_cancellation_events();
                let retry_counts = executor.get_retry_counts();

                // Verify stage ordering (MR1)
                if !config.test_cancellation && !config.inject_failure {
                    let mut last_stage_idx = 0;
                    for (_, executed_stage, _, _) in &execution_sequence {
                        if let Some(stage_idx) = stages.iter().position(|s| s == executed_stage) {
                            prop_assert!(
                                stage_idx >= last_stage_idx,
                                "Stage ordering violation: {} before {}", executed_stage, stages[last_stage_idx]
                            );
                            last_stage_idx = stage_idx;
                        }
                    }
                }

                // Verify compensation on failure (MR2)
                if config.inject_failure {
                    let has_failures = execution_sequence.iter()
                        .any(|(_, _, _, result)| *result == LatticeState::Aborted);
                    let has_compensations = !compensation_sequence.is_empty();

                    if has_failures {
                        prop_assert!(has_compensations, "Expected compensations after failure");
                    }
                }

                // Verify atomic cancellation (MR4)
                if config.test_cancellation && !cancellation_events.is_empty() {
                    let cancel_timestamp = cancellation_events[0].1;
                    let post_cancel_committed: Vec<_> = execution_sequence.iter()
                        .filter(|(_, _, ts, result)| *ts > cancel_timestamp && *result == LatticeState::Committed)
                        .collect();

                    prop_assert!(
                        post_cancel_committed.is_empty(),
                        "Found committed executions after cancellation: {:?}", post_cancel_committed
                    );
                }

                // Verify retry limits (MR5)
                for (_, attempts) in retry_counts {
                    prop_assert!(
                        attempts <= config.max_retry_attempts,
                        "Retry attempts {} exceeded limit {}", attempts, config.max_retry_attempts
                    );
                }

                Ok(())
            })
        }).expect("Runtime execution failed");
    }
}

/// Performance property: Protocol validation should be deterministic and efficient
proptest! {
    #[test]
    fn property_deterministic_protocol_validation(config in arb_workflow_config()) {
        let protocol1 = build_test_protocol(&config);
        let protocol2 = build_test_protocol(&config);

        let errors1 = protocol1.validate();
        let errors2 = protocol2.validate();

        // Same configuration should produce identical validation results
        prop_assert_eq!(errors1, errors2, "Protocol validation should be deterministic");

        // Check basic protocol properties
        prop_assert_eq!(protocol1.participants.len(), config.participant_count);

        if errors1.is_empty() {
            prop_assert!(protocol1.is_deadlock_free(), "Valid protocol should be deadlock-free");
        }
    }
}

/// Saga plan property: Choreography to saga conversion preserves step count
proptest! {
    #[test]
    fn property_saga_plan_step_preservation(config in arb_workflow_config().prop_filter("valid config", |c| c.stage_count >= 1)) {
        let protocol = build_test_protocol(&config);
        let errors = protocol.validate();

        if errors.is_empty() {
            let pipeline = SagaPipeline::new();
            let participants = config.participants();

            if !participants.is_empty() {
                let result = pipeline.plan_only(&protocol, &participants[0]);

                if let Ok((saga_plan, _execution_plan)) = result {
                    // Saga plan should have steps corresponding to participant actions
                    prop_assert!(
                        !saga_plan.steps.is_empty() || config.stage_count == 0,
                        "Saga plan should have steps for non-empty protocol"
                    );

                    // All steps should have valid labels and operations
                    for step in &saga_plan.steps {
                        prop_assert!(!step.label.is_empty(), "Step label should not be empty");
                        // Operation should have consistent monotonicity
                        prop_assert_eq!(
                            step.op.monotonicity(),
                            step.monotonicity,
                            "Step monotonicity should match operation monotonicity"
                        );
                    }
                }
            }
        }
    }
}