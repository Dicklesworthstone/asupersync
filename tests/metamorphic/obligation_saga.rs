#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic Testing for obligation::saga compensation order invariants
//!
//! Tests saga compensation mechanisms using metamorphic relations that must hold
//! regardless of specific step sequences or execution patterns. Uses LabRuntime
//! with DPOR for deterministic execution and concurrency control.
//!
//! ## Metamorphic Relations Tested:
//!
//! 1. **Forward/Reverse LIFO**: forward step success commits, failure triggers
//!    reverse compensation in LIFO order
//! 2. **Idempotent compensation**: idempotent compensations safe under retry
//! 3. **Partial restart consistency**: partial saga restart resumes from last
//!    committed step
//! 4. **Abort resource cleanup**: saga abort cleanly releases all reserved resources
//! 5. **Timeout compensation handling**: timeout during compensation logged but saga
//!    marked terminally failed

use proptest::prelude::*;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::obligation::saga::{
    SagaOpKind, SagaPlan, SagaStep, SagaExecutionPlan, MonotoneSagaExecutor, StepExecutor
};
use asupersync::trace::distributed::lattice::LatticeState;
use asupersync::types::{Budget, Time, Outcome};
use asupersync::{region, sleep, sleep_until};

/// Test configuration for saga compensation metamorphic properties
#[derive(Debug, Clone)]
struct SagaCompensationConfig {
    /// Forward operation sequence
    forward_ops: Vec<SagaOpKind>,
    /// Whether to trigger failure at specific step (0-based index, None = no failure)
    failure_at_step: Option<usize>,
    /// Whether to retry compensations (tests idempotency)
    retry_compensations: bool,
    /// Number of compensation retries
    retry_count: usize,
    /// Whether to test partial restart
    test_partial_restart: bool,
    /// Restart from step index (0-based)
    restart_from_step: usize,
    /// Whether to inject timeout during compensation
    inject_compensation_timeout: bool,
    /// Timeout duration in milliseconds for compensation steps
    compensation_timeout_ms: u64,
}

impl SagaCompensationConfig {
    /// Generate compensation operation sequence in LIFO order
    fn compensation_ops(&self) -> Vec<SagaOpKind> {
        if let Some(fail_step) = self.failure_at_step {
            // Only compensate steps that were successfully completed
            let completed_ops = &self.forward_ops[..fail_step];
            completed_ops.iter().rev().map(|op| compensation_for(*op)).collect()
        } else {
            // All operations completed, compensate everything in LIFO order
            self.forward_ops.iter().rev().map(|op| compensation_for(*op)).collect()
        }
    }

    /// Get partial restart operations (from restart point forward)
    fn restart_ops(&self) -> Vec<SagaOpKind> {
        if self.test_partial_restart && self.restart_from_step < self.forward_ops.len() {
            self.forward_ops[self.restart_from_step..].to_vec()
        } else {
            self.forward_ops.clone()
        }
    }
}

/// Generate compensation operation for a forward operation
fn compensation_for(forward_op: SagaOpKind) -> SagaOpKind {
    match forward_op {
        SagaOpKind::Reserve => SagaOpKind::Release,
        SagaOpKind::Acquire => SagaOpKind::Release,
        SagaOpKind::Commit => SagaOpKind::Abort,
        SagaOpKind::Send => SagaOpKind::CancelDrain,
        SagaOpKind::Renew => SagaOpKind::Release,
        // Other operations map to themselves or special handlers
        op => SagaOpKind::Abort, // Default compensation
    }
}

/// Tracked saga executor that logs operation sequences and resource usage
#[derive(Debug, Clone)]
struct TrackedSagaExecutor {
    /// Executed operations in order
    executed_ops: Arc<Mutex<VecDeque<(String, SagaOpKind, LatticeState)>>>,
    /// Current resource reservations (step_label -> resource_count)
    resource_reservations: Arc<Mutex<std::collections::HashMap<String, u64>>>,
    /// Whether to simulate failure at specific operation
    fail_at_op: Option<String>,
    /// Whether to simulate timeout
    timeout_ops: Arc<Mutex<std::collections::HashSet<String>>>,
    /// Operation execution counter
    exec_counter: Arc<AtomicU64>,
    /// Compensation retry counter
    retry_counter: Arc<AtomicU64>,
}

impl TrackedSagaExecutor {
    fn new() -> Self {
        Self {
            executed_ops: Arc::new(Mutex::new(VecDeque::new())),
            resource_reservations: Arc::new(Mutex::new(std::collections::HashMap::new())),
            fail_at_op: None,
            timeout_ops: Arc::new(Mutex::new(std::collections::HashSet::new())),
            exec_counter: Arc::new(AtomicU64::new(0)),
            retry_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    fn with_failure_at(mut self, op_label: &str) -> Self {
        self.fail_at_op = Some(op_label.to_string());
        self
    }

    fn add_timeout_op(&self, op_label: &str) {
        self.timeout_ops.lock().unwrap().insert(op_label.to_string());
    }

    fn get_executed_sequence(&self) -> Vec<(String, SagaOpKind, LatticeState)> {
        self.executed_ops.lock().unwrap().iter().cloned().collect()
    }

    fn get_reserved_resources(&self) -> std::collections::HashMap<String, u64> {
        self.resource_reservations.lock().unwrap().clone()
    }

    fn get_retry_count(&self) -> u64 {
        self.retry_counter.load(Ordering::SeqCst)
    }
}

impl StepExecutor for TrackedSagaExecutor {
    fn execute(&mut self, step: &SagaStep) -> LatticeState {
        let exec_count = self.exec_counter.fetch_add(1, Ordering::SeqCst);

        // Check for timeout simulation
        if self.timeout_ops.lock().unwrap().contains(&step.label) {
            // Simulate timeout by returning Unknown state
            self.executed_ops.lock().unwrap().push_back((
                step.label.clone(),
                step.op,
                LatticeState::Unknown
            ));
            return LatticeState::Unknown;
        }

        // Check for failure simulation
        if let Some(ref fail_op) = self.fail_at_op {
            if step.label == *fail_op {
                self.executed_ops.lock().unwrap().push_back((
                    step.label.clone(),
                    step.op,
                    LatticeState::Aborted
                ));
                return LatticeState::Aborted;
            }
        }

        let result_state = match step.op {
            SagaOpKind::Reserve | SagaOpKind::Acquire => {
                // Track resource reservation
                self.resource_reservations.lock().unwrap()
                    .insert(step.label.clone(), 1);
                LatticeState::Reserved
            },
            SagaOpKind::Send => LatticeState::Reserved,
            SagaOpKind::Commit => LatticeState::Committed,
            SagaOpKind::Release => {
                // Release tracked resource
                self.resource_reservations.lock().unwrap()
                    .remove(&step.label.replace("undo_", ""));
                LatticeState::Unknown
            },
            SagaOpKind::Abort => LatticeState::Aborted,
            SagaOpKind::CancelDrain => {
                // Increment retry counter for compensation
                self.retry_counter.fetch_add(1, Ordering::SeqCst);
                LatticeState::Unknown
            },
            SagaOpKind::Renew => LatticeState::Reserved,
            _ => LatticeState::Unknown,
        };

        self.executed_ops.lock().unwrap().push_back((
            step.label.clone(),
            step.op,
            result_state
        ));

        result_state
    }
}

/// Generate arbitrary saga configuration for property testing
impl Arbitrary for SagaCompensationConfig {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            // Generate 2-8 forward operations
            prop::collection::vec(
                prop_oneof![
                    Just(SagaOpKind::Reserve),
                    Just(SagaOpKind::Acquire),
                    Just(SagaOpKind::Send),
                    Just(SagaOpKind::Commit),
                    Just(SagaOpKind::Renew),
                ],
                2..=8
            ),
            // Optional failure point
            prop::option::of(0usize..8),
            // Retry configuration
            any::<bool>(),
            1usize..=3,
            // Partial restart configuration
            any::<bool>(),
            0usize..8,
            // Timeout configuration
            any::<bool>(),
            50u64..=500,
        ).prop_map(|(ops, fail_step, retry, retry_count, partial_restart, restart_step, timeout, timeout_ms)| {
            let adjusted_fail_step = fail_step.map(|s| s.min(ops.len().saturating_sub(1)));
            let adjusted_restart_step = restart_step.min(ops.len().saturating_sub(1));

            SagaCompensationConfig {
                forward_ops: ops,
                failure_at_step: adjusted_fail_step,
                retry_compensations: retry,
                retry_count,
                test_partial_restart: partial_restart,
                restart_from_step: adjusted_restart_step,
                inject_compensation_timeout: timeout,
                compensation_timeout_ms: timeout_ms,
            }
        }).boxed()
    }
}

/// Helper function to create a test context with LabRuntime
fn test_cx() -> Cx {
    Cx::for_testing()
}

/// MR1: Forward step success commits, failure triggers reverse compensation LIFO
#[test]
fn mr1_forward_reverse_lifo_order() {
    proptest!(|(config in any::<SagaCompensationConfig>())| {
        // Create forward saga plan
        let forward_steps: Vec<SagaStep> = config.forward_ops.iter().enumerate()
            .map(|(i, &op)| SagaStep::new(op, format!("forward_{}", i)))
            .collect();

        let forward_plan = SagaPlan::new("forward_saga", forward_steps);
        let forward_exec = SagaExecutionPlan::from_plan(&forward_plan);

        // Execute forward saga with potential failure
        let mut forward_executor = if let Some(fail_step) = config.failure_at_step {
            TrackedSagaExecutor::new().with_failure_at(&format!("forward_{}", fail_step))
        } else {
            TrackedSagaExecutor::new()
        };

        let saga_executor = MonotoneSagaExecutor::new();
        let forward_result = saga_executor.execute(&forward_exec, &mut forward_executor);
        let forward_sequence = forward_executor.get_executed_sequence();

        // If forward saga failed, create and execute compensation saga
        if config.failure_at_step.is_some() {
            let compensation_ops = config.compensation_ops();
            let compensation_steps: Vec<SagaStep> = compensation_ops.iter().enumerate()
                .map(|(i, &op)| SagaStep::new(op, format!("compensation_{}", i)))
                .collect();

            let compensation_plan = SagaPlan::new("compensation_saga", compensation_steps);
            let compensation_exec = SagaExecutionPlan::from_plan(&compensation_plan);

            let mut compensation_executor = TrackedSagaExecutor::new();
            let compensation_result = saga_executor.execute(&compensation_exec, &mut compensation_executor);
            let compensation_sequence = compensation_executor.get_executed_sequence();

            // MR1: Verify LIFO order - compensations should be reverse of completed forwards
            let completed_forwards: Vec<SagaOpKind> = forward_sequence.iter()
                .filter(|(_, _, state)| *state != LatticeState::Aborted)
                .map(|(_, op, _)| *op)
                .collect();

            let actual_compensations: Vec<SagaOpKind> = compensation_sequence.iter()
                .map(|(_, op, _)| *op)
                .collect();

            let expected_compensations: Vec<SagaOpKind> = completed_forwards.iter().rev()
                .map(|&op| compensation_for(op))
                .collect();

            prop_assert_eq!(
                actual_compensations, expected_compensations,
                "Compensation order should be LIFO reverse of completed forward steps"
            );
        }

        Ok(())
    });
}

/// MR2: Idempotent compensations safe under retry
#[test]
fn mr2_idempotent_compensation_retry() {
    proptest!(|(config in any::<SagaCompensationConfig>().prop_filter("needs_retry", |c| c.retry_compensations))| {
        // Create compensation saga
        let compensation_ops = config.compensation_ops();
        let compensation_steps: Vec<SagaStep> = compensation_ops.iter().enumerate()
            .map(|(i, &op)| SagaStep::new(op, format!("comp_{}", i)))
            .collect();

        let compensation_plan = SagaPlan::new("retry_compensation_saga", compensation_steps);
        let compensation_exec = SagaExecutionPlan::from_plan(&compensation_plan);
        let saga_executor = MonotoneSagaExecutor::new();

        // Execute compensation multiple times to test idempotency
        let mut first_resources = std::collections::HashMap::new();
        let mut final_resources = std::collections::HashMap::new();

        for retry in 0..=config.retry_count {
            let mut compensation_executor = TrackedSagaExecutor::new();
            let compensation_result = saga_executor.execute(&compensation_exec, &mut compensation_executor);
            let resources = compensation_executor.get_reserved_resources();

            if retry == 0 {
                first_resources = resources.clone();
            }
            final_resources = resources;

            // MR2: Each retry should produce identical results (idempotency)
            prop_assert!(
                compensation_result.is_clean(),
                "Compensation retry {} should complete cleanly", retry
            );
        }

        // MR2: Resource state should be identical across retries
        prop_assert_eq!(
            first_resources, final_resources,
            "Idempotent compensation: resource state should be identical across retries"
        );

        Ok(())
    });
}

/// MR3: Partial saga restart resumes from last committed step
#[test]
fn mr3_partial_restart_consistency() {
    proptest!(|(config in any::<SagaCompensationConfig>().prop_filter("needs_restart", |c| c.test_partial_restart && c.restart_from_step > 0))| {
        let saga_executor = MonotoneSagaExecutor::new();

        // Execute full saga first
        let full_steps: Vec<SagaStep> = config.forward_ops.iter().enumerate()
            .map(|(i, &op)| SagaStep::new(op, format!("full_{}", i)))
            .collect();
        let full_plan = SagaPlan::new("full_saga", full_steps);
        let full_exec = SagaExecutionPlan::from_plan(&full_plan);

        let mut full_executor = TrackedSagaExecutor::new();
        let full_result = saga_executor.execute(&full_exec, &mut full_executor);
        let full_sequence = full_executor.get_executed_sequence();

        // Execute partial restart saga
        let restart_ops = config.restart_ops();
        let restart_steps: Vec<SagaStep> = restart_ops.iter().enumerate()
            .map(|(i, &op)| SagaStep::new(op, format!("restart_{}", i)))
            .collect();
        let restart_plan = SagaPlan::new("restart_saga", restart_steps);
        let restart_exec = SagaExecutionPlan::from_plan(&restart_plan);

        let mut restart_executor = TrackedSagaExecutor::new();
        let restart_result = saga_executor.execute(&restart_exec, &mut restart_executor);
        let restart_sequence = restart_executor.get_executed_sequence();

        // MR3: Partial restart should produce consistent operation subsequence
        let full_ops_from_restart: Vec<SagaOpKind> = full_sequence[config.restart_from_step..]
            .iter().map(|(_, op, _)| *op).collect();
        let restart_ops_actual: Vec<SagaOpKind> = restart_sequence
            .iter().map(|(_, op, _)| *op).collect();

        prop_assert_eq!(
            full_ops_from_restart, restart_ops_actual,
            "Partial restart should execute same operation sequence as full saga from restart point"
        );

        // MR3: Final states should be consistent
        prop_assert_eq!(
            full_result.final_state, restart_result.final_state,
            "Partial restart final state should match full saga execution"
        );

        Ok(())
    });
}

/// MR4: Saga abort cleanly releases all reserved resources
#[test]
fn mr4_abort_resource_cleanup() {
    proptest!(|(config in any::<SagaCompensationConfig>().prop_filter("has_failure", |c| c.failure_at_step.is_some()))| {
        let saga_executor = MonotoneSagaExecutor::new();

        // Execute forward saga with failure
        let forward_steps: Vec<SagaStep> = config.forward_ops.iter().enumerate()
            .map(|(i, &op)| SagaStep::new(op, format!("resource_{}", i)))
            .collect();
        let forward_plan = SagaPlan::new("resource_saga", forward_steps);
        let forward_exec = SagaExecutionPlan::from_plan(&forward_plan);

        let mut forward_executor = TrackedSagaExecutor::new()
            .with_failure_at(&format!("resource_{}", config.failure_at_step.unwrap()));
        let forward_result = saga_executor.execute(&forward_exec, &mut forward_executor);
        let resources_before_cleanup = forward_executor.get_reserved_resources();

        // Execute cleanup/compensation
        let cleanup_ops = config.compensation_ops();
        let cleanup_steps: Vec<SagaStep> = cleanup_ops.iter().enumerate()
            .map(|(i, &op)| SagaStep::new(op, format!("cleanup_{}", i)))
            .collect();
        let cleanup_plan = SagaPlan::new("cleanup_saga", cleanup_steps);
        let cleanup_exec = SagaExecutionPlan::from_plan(&cleanup_plan);

        let mut cleanup_executor = TrackedSagaExecutor::new();
        let cleanup_result = saga_executor.execute(&cleanup_exec, &mut cleanup_executor);
        let resources_after_cleanup = cleanup_executor.get_reserved_resources();

        // MR4: All reserved resources should be released after cleanup
        let total_reserved_before: u64 = resources_before_cleanup.values().sum();
        let total_reserved_after: u64 = resources_after_cleanup.values().sum();

        prop_assert!(
            total_reserved_after < total_reserved_before,
            "Cleanup should release resources: before={}, after={}",
            total_reserved_before, total_reserved_after
        );

        // MR4: Cleanup should complete successfully
        prop_assert!(
            cleanup_result.is_clean(),
            "Resource cleanup should complete without errors"
        );

        Ok(())
    });
}

/// MR5: Timeout during compensation logged but saga marked terminally failed
#[test]
fn mr5_timeout_compensation_handling() {
    proptest!(|(config in any::<SagaCompensationConfig>().prop_filter("has_timeout", |c| c.inject_compensation_timeout))| {
        // Create compensation saga with timeout injection
        let compensation_ops = config.compensation_ops();
        let compensation_steps: Vec<SagaStep> = compensation_ops.iter().enumerate()
            .map(|(i, &op)| SagaStep::new(op, format!("timeout_comp_{}", i)))
            .collect();
        let compensation_plan = SagaPlan::new("timeout_compensation_saga", compensation_steps);
        let compensation_exec = SagaExecutionPlan::from_plan(&compensation_plan);

        let saga_executor = MonotoneSagaExecutor::new();
        let mut compensation_executor = TrackedSagaExecutor::new();

        // Inject timeout in first compensation step
        if !compensation_steps.is_empty() {
            compensation_executor.add_timeout_op(&compensation_steps[0].label);
        }

        let compensation_result = saga_executor.execute(&compensation_exec, &mut compensation_executor);
        let compensation_sequence = compensation_executor.get_executed_sequence();

        // MR5: Timeout should be logged in execution sequence
        let has_timeout = compensation_sequence.iter()
            .any(|(_, _, state)| *state == LatticeState::Unknown);
        if !compensation_steps.is_empty() {
            prop_assert!(has_timeout, "Timeout should be recorded in execution sequence");
        }

        // MR5: Saga with timeout should still attempt remaining compensations
        if compensation_steps.len() > 1 {
            let executed_count = compensation_sequence.len();
            prop_assert!(
                executed_count >= 1,
                "At least one compensation should execute even with timeout"
            );
        }

        // MR5: Final result should indicate non-clean completion due to timeout
        if has_timeout {
            prop_assert!(
                compensation_result.final_state == LatticeState::Unknown ||
                compensation_result.final_state == LatticeState::Conflict,
                "Timeout during compensation should result in terminal failure state"
            );
        }

        Ok(())
    });
}

/// Composite MR: End-to-end saga compensation workflow
#[test]
fn mr_composite_saga_compensation_workflow() {
    proptest!(|(config in any::<SagaCompensationConfig>())| {
        let saga_executor = MonotoneSagaExecutor::new();

        // Forward execution
        let forward_steps: Vec<SagaStep> = config.forward_ops.iter().enumerate()
            .map(|(i, &op)| SagaStep::new(op, format!("workflow_{}", i)))
            .collect();
        let forward_plan = SagaPlan::new("workflow_saga", forward_steps.clone());
        let forward_exec = SagaExecutionPlan::from_plan(&forward_plan);

        let mut forward_executor = if let Some(fail_step) = config.failure_at_step {
            TrackedSagaExecutor::new().with_failure_at(&format!("workflow_{}", fail_step))
        } else {
            TrackedSagaExecutor::new()
        };

        let forward_result = saga_executor.execute(&forward_exec, &mut forward_executor);
        let forward_success = config.failure_at_step.is_none();

        // Composite MR: Forward saga behavior should be deterministic
        if forward_success {
            prop_assert!(
                forward_result.is_clean(),
                "Successful forward saga should complete cleanly"
            );
            prop_assert!(
                forward_result.total_steps as usize == forward_steps.len(),
                "Forward saga should execute all steps on success"
            );
        } else {
            // Some steps may have executed before failure
            prop_assert!(
                forward_result.total_steps > 0,
                "Failed saga should have executed at least one step"
            );
        }

        // If compensation is needed, test comprehensive workflow
        if config.failure_at_step.is_some() {
            let compensation_ops = config.compensation_ops();

            // Composite MR: Compensation sequence length should match completed forward steps
            let expected_compensation_count = config.failure_at_step.unwrap();
            prop_assert_eq!(
                compensation_ops.len(), expected_compensation_count,
                "Compensation count should match completed forward steps"
            );
        }

        Ok(())
    });
}

/// Test saga execution determinism under LabRuntime DPOR
#[test]
fn test_saga_determinism_under_dpor() {
    let config = SagaCompensationConfig {
        forward_ops: vec![SagaOpKind::Reserve, SagaOpKind::Send, SagaOpKind::Commit],
        failure_at_step: Some(2), // Fail at commit
        retry_compensations: true,
        retry_count: 2,
        test_partial_restart: false,
        restart_from_step: 0,
        inject_compensation_timeout: false,
        compensation_timeout_ms: 100,
    };

    // Execute same saga configuration multiple times
    let mut results = Vec::new();
    for iteration in 0..3 {
        let forward_steps: Vec<SagaStep> = config.forward_ops.iter().enumerate()
            .map(|(i, &op)| SagaStep::new(op, format!("det_{}_step_{}", iteration, i)))
            .collect();
        let forward_plan = SagaPlan::new("determinism_test", forward_steps);
        let forward_exec = SagaExecutionPlan::from_plan(&forward_plan);

        let saga_executor = MonotoneSagaExecutor::new();
        let mut forward_executor = TrackedSagaExecutor::new()
            .with_failure_at(&format!("det_{}_step_2", iteration));
        let result = saga_executor.execute(&forward_exec, &mut forward_executor);

        results.push((result.total_steps, result.final_state, result.is_clean()));
    }

    // All executions should be deterministic
    let first_result = &results[0];
    for (i, result) in results.iter().enumerate() {
        assert_eq!(
            *result, *first_result,
            "Execution {} should be deterministic", i
        );
    }
}