//! Integration tests for CALM-optimized saga execution (bd-2wrsc.3).
//!
//! Tests monotonicity classification, lattice merge semantics, execution plan
//! batching, order independence, conflict detection, fallback behavior,
//! and evidence ledger integration.

mod common;

use asupersync::obligation::calm::{self, Monotonicity};
use asupersync::obligation::saga::{
    BatchResult, Lattice, MonotoneSagaExecutor, SagaExecutionPlan, SagaExecutionResult,
    SagaOpKind, SagaPlan, SagaStep, StepExecutor,
};
use asupersync::trace::distributed::lattice::LatticeState;
use common::{init_test_logging, test_proptest_config};
use proptest::prelude::*;

// ============================================================================
// Test executor helpers
// ============================================================================

/// A test executor that returns states from a pre-configured sequence.
struct SequentialExecutor {
    states: Vec<LatticeState>,
    idx: usize,
}

impl SequentialExecutor {
    fn new(states: Vec<LatticeState>) -> Self {
        Self { states, idx: 0 }
    }
}

impl StepExecutor for SequentialExecutor {
    fn execute(&mut self, _step: &SagaStep) -> LatticeState {
        let state = self.states[self.idx % self.states.len()];
        self.idx += 1;
        state
    }
}

/// An executor that always returns a fixed state.
struct ConstantExecutor(LatticeState);

impl StepExecutor for ConstantExecutor {
    fn execute(&mut self, _step: &SagaStep) -> LatticeState {
        self.0
    }
}

/// An executor that triggers a monotonicity violation for a named step.
struct ViolatingOnLabelExecutor {
    target_label: String,
}

impl StepExecutor for ViolatingOnLabelExecutor {
    fn execute(&mut self, _step: &SagaStep) -> LatticeState {
        LatticeState::Reserved
    }

    fn validate_monotonicity(
        &self,
        step: &SagaStep,
        _before: &LatticeState,
        _after: &LatticeState,
    ) -> Result<(), String> {
        if step.label == self.target_label {
            Err(format!("violation at step: {}", step.label))
        } else {
            Ok(())
        }
    }
}

// ============================================================================
// All 16 SagaOpKind values for iteration
// ============================================================================

const ALL_OPS: [SagaOpKind; 16] = [
    SagaOpKind::Reserve,
    SagaOpKind::Commit,
    SagaOpKind::Abort,
    SagaOpKind::Send,
    SagaOpKind::Recv,
    SagaOpKind::Acquire,
    SagaOpKind::Renew,
    SagaOpKind::Release,
    SagaOpKind::RegionClose,
    SagaOpKind::Delegate,
    SagaOpKind::CrdtMerge,
    SagaOpKind::CancelRequest,
    SagaOpKind::CancelDrain,
    SagaOpKind::MarkLeaked,
    SagaOpKind::BudgetCheck,
    SagaOpKind::LeakDetection,
];

const MONOTONE_OPS: [SagaOpKind; 7] = [
    SagaOpKind::Reserve,
    SagaOpKind::Send,
    SagaOpKind::Acquire,
    SagaOpKind::Renew,
    SagaOpKind::Delegate,
    SagaOpKind::CrdtMerge,
    SagaOpKind::CancelRequest,
];

const NON_MONOTONE_OPS: [SagaOpKind; 9] = [
    SagaOpKind::Commit,
    SagaOpKind::Abort,
    SagaOpKind::Recv,
    SagaOpKind::Release,
    SagaOpKind::RegionClose,
    SagaOpKind::CancelDrain,
    SagaOpKind::MarkLeaked,
    SagaOpKind::BudgetCheck,
    SagaOpKind::LeakDetection,
];

const ALL_LATTICE_STATES: [LatticeState; 5] = [
    LatticeState::Unknown,
    LatticeState::Reserved,
    LatticeState::Committed,
    LatticeState::Aborted,
    LatticeState::Conflict,
];

// ============================================================================
// 1. Monotonicity classifier correctness
// ============================================================================

#[test]
fn classifier_total_operations_is_16() {
    init_test_logging();
    let classifications = calm::classifications();
    assert_eq!(classifications.len(), 16);
}

#[test]
fn classifier_monotone_count_is_7() {
    init_test_logging();
    let monotone = calm::coordination_free();
    assert_eq!(monotone.len(), 7);
}

#[test]
fn classifier_non_monotone_count_is_9() {
    init_test_logging();
    let non_monotone = calm::coordination_points();
    assert_eq!(non_monotone.len(), 9);
}

#[test]
fn classifier_monotone_ratio() {
    init_test_logging();
    let ratio = calm::monotone_ratio();
    // 7 / 16 = 0.4375
    assert!((ratio - 0.4375).abs() < 0.001, "ratio = {ratio}");
}

#[test]
fn classifier_ground_truth_monotone_operations() {
    init_test_logging();

    // Ground truth: these 7 operations are monotone (only add information).
    let expected_monotone = [
        "Reserve",
        "Send",
        "Acquire",
        "Renew",
        "Delegate",
        "CrdtMerge",
        "CancelRequest",
    ];

    let monotone_ops: Vec<&str> = calm::coordination_free()
        .iter()
        .map(|c| c.operation)
        .collect();

    for op in &expected_monotone {
        assert!(
            monotone_ops.contains(op),
            "{op} should be classified as monotone"
        );
    }
}

#[test]
fn classifier_ground_truth_non_monotone_operations() {
    init_test_logging();

    // Ground truth: these 9 operations are non-monotone (require coordination).
    let expected_non_monotone = [
        "Commit",
        "Abort",
        "Recv",
        "Release",
        "RegionClose",
        "CancelDrain",
        "MarkLeaked",
        "BudgetCheck",
        "LeakDetection",
    ];

    let non_monotone_ops: Vec<&str> = calm::coordination_points()
        .iter()
        .map(|c| c.operation)
        .collect();

    for op in &expected_non_monotone {
        assert!(
            non_monotone_ops.contains(op),
            "{op} should be classified as non-monotone"
        );
    }
}

#[test]
fn classifier_all_have_justifications() {
    init_test_logging();
    for c in calm::classifications() {
        assert!(
            !c.justification.is_empty(),
            "operation {} lacks justification",
            c.operation
        );
    }
}

#[test]
fn saga_op_kind_matches_calm_classification() {
    init_test_logging();

    for op in &ALL_OPS {
        let calm_match = calm::classifications()
            .iter()
            .find(|c| c.operation == op.as_str());
        assert!(
            calm_match.is_some(),
            "SagaOpKind::{} has no CALM classification",
            op.as_str()
        );
        assert_eq!(
            op.monotonicity(),
            calm_match.unwrap().monotonicity,
            "SagaOpKind::{} disagrees with CALM",
            op.as_str()
        );
    }
}

// ============================================================================
// 2. Lattice merge semantics
// ============================================================================

#[test]
fn lattice_commutativity_exhaustive() {
    init_test_logging();
    for &a in &ALL_LATTICE_STATES {
        for &b in &ALL_LATTICE_STATES {
            assert_eq!(
                Lattice::join(&a, &b),
                Lattice::join(&b, &a),
                "commutativity failed for {a:?} ⊔ {b:?}",
            );
        }
    }
}

#[test]
fn lattice_associativity_exhaustive() {
    init_test_logging();
    for &a in &ALL_LATTICE_STATES {
        for &b in &ALL_LATTICE_STATES {
            for &c in &ALL_LATTICE_STATES {
                let lhs = Lattice::join(&Lattice::join(&a, &b), &c);
                let rhs = Lattice::join(&a, &Lattice::join(&b, &c));
                assert_eq!(
                    lhs, rhs,
                    "associativity failed: ({a:?} ⊔ {b:?}) ⊔ {c:?} != {a:?} ⊔ ({b:?} ⊔ {c:?})",
                );
            }
        }
    }
}

#[test]
fn lattice_idempotence_exhaustive() {
    init_test_logging();
    for &a in &ALL_LATTICE_STATES {
        assert_eq!(Lattice::join(&a, &a), a, "idempotence failed for {a:?}",);
    }
}

#[test]
fn lattice_identity_element() {
    init_test_logging();
    let bottom = LatticeState::bottom();
    assert_eq!(bottom, LatticeState::Unknown);
    for &a in &ALL_LATTICE_STATES {
        assert_eq!(Lattice::join(&bottom, &a), a, "identity failed for {a:?}",);
    }
}

#[test]
fn lattice_join_all_empty() {
    init_test_logging();
    let result = LatticeState::join_all(std::iter::empty());
    assert_eq!(result, LatticeState::Unknown);
}

#[test]
fn lattice_join_all_singleton() {
    init_test_logging();
    for &a in &ALL_LATTICE_STATES {
        assert_eq!(LatticeState::join_all([a]), a);
    }
}

#[test]
fn lattice_specific_join_results() {
    init_test_logging();

    // Unknown is bottom.
    assert_eq!(
        Lattice::join(&LatticeState::Unknown, &LatticeState::Reserved),
        LatticeState::Reserved
    );

    // Reserved ⊔ Committed = Committed (progress).
    assert_eq!(
        Lattice::join(&LatticeState::Reserved, &LatticeState::Committed),
        LatticeState::Committed
    );

    // Reserved ⊔ Aborted = Aborted (resolution).
    assert_eq!(
        Lattice::join(&LatticeState::Reserved, &LatticeState::Aborted),
        LatticeState::Aborted
    );

    // Committed ⊔ Aborted = Conflict (incompatible resolutions).
    assert_eq!(
        Lattice::join(&LatticeState::Committed, &LatticeState::Aborted),
        LatticeState::Conflict
    );

    // Conflict absorbs everything.
    for &a in &ALL_LATTICE_STATES {
        assert_eq!(
            Lattice::join(&LatticeState::Conflict, &a),
            LatticeState::Conflict,
            "Conflict should absorb {a:?}",
        );
    }
}

// ============================================================================
// 3. Conflict detection at non-monotone boundaries
// ============================================================================

#[test]
fn conflict_detected_when_committed_meets_aborted() {
    init_test_logging();

    let plan = SagaPlan::new(
        "conflict_test",
        vec![
            SagaStep::new(SagaOpKind::Commit, "commit_step"),
            SagaStep::new(SagaOpKind::Abort, "abort_step"),
        ],
    );
    let exec_plan = SagaExecutionPlan::from_plan(&plan);
    let executor = MonotoneSagaExecutor::new();
    let mut step_exec =
        SequentialExecutor::new(vec![LatticeState::Committed, LatticeState::Aborted]);

    let result = executor.execute(&exec_plan, &mut step_exec);
    assert_eq!(result.final_state, LatticeState::Conflict);
    assert!(!result.is_clean());
}

#[test]
fn no_conflict_when_all_commit() {
    init_test_logging();

    let plan = SagaPlan::new(
        "all_commit",
        vec![
            SagaStep::new(SagaOpKind::Commit, "c1"),
            SagaStep::new(SagaOpKind::Commit, "c2"),
        ],
    );
    let exec_plan = SagaExecutionPlan::from_plan(&plan);
    let executor = MonotoneSagaExecutor::new();
    let mut step_exec =
        SequentialExecutor::new(vec![LatticeState::Committed, LatticeState::Committed]);

    let result = executor.execute(&exec_plan, &mut step_exec);
    assert_eq!(result.final_state, LatticeState::Committed);
    assert!(result.is_clean());
}

// ============================================================================
// 4. Saga execution plan batching
// ============================================================================

#[test]
fn all_monotone_plan_single_coordination_free_batch() {
    init_test_logging();

    let steps: Vec<SagaStep> = MONOTONE_OPS
        .iter()
        .enumerate()
        .map(|(i, &op)| SagaStep::new(op, format!("m{i}")))
        .collect();

    let plan = SagaPlan::new("all_mono", steps);
    assert!((plan.monotone_ratio() - 1.0).abs() < 0.001);

    let exec = SagaExecutionPlan::from_plan(&plan);
    assert_eq!(exec.batches.len(), 1);
    assert!(exec.batches[0].is_coordination_free());
    assert_eq!(exec.coordination_barrier_count(), 0);
    assert_eq!(exec.total_steps(), 7);
}

#[test]
fn all_non_monotone_plan_individual_coordinated_batches() {
    init_test_logging();

    let steps: Vec<SagaStep> = NON_MONOTONE_OPS
        .iter()
        .enumerate()
        .map(|(i, &op)| SagaStep::new(op, format!("nm{i}")))
        .collect();

    let plan = SagaPlan::new("all_nm", steps);
    assert!((plan.monotone_ratio()).abs() < 0.001);

    let exec = SagaExecutionPlan::from_plan(&plan);
    assert_eq!(exec.batches.len(), 9);
    assert_eq!(exec.coordination_barrier_count(), 9);
    assert_eq!(exec.coordination_free_batch_count(), 0);
}

#[test]
fn mixed_plan_correct_batch_structure() {
    init_test_logging();

    // [Reserve(M), Send(M), Commit(NM), Acquire(M), Renew(M), Release(NM), Delegate(M)]
    let plan = SagaPlan::new(
        "mixed",
        vec![
            SagaStep::new(SagaOpKind::Reserve, "r1"),
            SagaStep::new(SagaOpKind::Send, "s1"),
            SagaStep::new(SagaOpKind::Commit, "c1"),
            SagaStep::new(SagaOpKind::Acquire, "a1"),
            SagaStep::new(SagaOpKind::Renew, "n1"),
            SagaStep::new(SagaOpKind::Release, "rel1"),
            SagaStep::new(SagaOpKind::Delegate, "d1"),
        ],
    );

    let exec = SagaExecutionPlan::from_plan(&plan);
    // [Reserve,Send](CF) -> Commit(C) -> [Acquire,Renew](CF) -> Release(C) -> [Delegate](CF)
    assert_eq!(exec.batches.len(), 5);
    assert!(exec.batches[0].is_coordination_free());
    assert_eq!(exec.batches[0].len(), 2);
    assert!(!exec.batches[1].is_coordination_free());
    assert!(exec.batches[2].is_coordination_free());
    assert_eq!(exec.batches[2].len(), 2);
    assert!(!exec.batches[3].is_coordination_free());
    assert!(exec.batches[4].is_coordination_free());
    assert_eq!(exec.batches[4].len(), 1);
    assert_eq!(exec.coordination_barrier_count(), 2);
    assert_eq!(exec.coordination_free_batch_count(), 3);
    assert_eq!(exec.total_steps(), 7);
}

#[test]
fn empty_plan_no_batches() {
    init_test_logging();
    let plan = SagaPlan::new("empty", vec![]);
    let exec = SagaExecutionPlan::from_plan(&plan);
    assert!(exec.batches.is_empty());
    assert_eq!(exec.total_steps(), 0);
    assert_eq!(exec.coordination_barrier_count(), 0);
}

// ============================================================================
// 5. Order independence — monotone batch results are order-independent
// ============================================================================

#[test]
fn order_independence_1000_random_orderings() {
    init_test_logging();

    // 6 monotone steps with different lattice results.
    let ops = [
        SagaOpKind::Reserve,
        SagaOpKind::Send,
        SagaOpKind::Acquire,
        SagaOpKind::Renew,
        SagaOpKind::Delegate,
        SagaOpKind::CrdtMerge,
    ];
    let step_states = [
        LatticeState::Unknown,
        LatticeState::Reserved,
        LatticeState::Reserved,
        LatticeState::Committed,
        LatticeState::Reserved,
        LatticeState::Unknown,
    ];

    // Expected result: join of all states.
    let expected = LatticeState::join_all(step_states.iter().copied());

    // Use a simple PRNG to generate 1000 random permutations.
    let mut rng_state: u64 = 0xCAFE_BABE_DEAD_BEEF;
    for run in 0..1000 {
        // Fisher-Yates shuffle.
        let mut indices: Vec<usize> = (0..ops.len()).collect();
        for i in (1..indices.len()).rev() {
            rng_state = rng_state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let j = (rng_state >> 33) as usize % (i + 1);
            indices.swap(i, j);
        }

        let ordered_steps: Vec<SagaStep> = indices
            .iter()
            .map(|&i| SagaStep::new(ops[i], format!("s{i}")))
            .collect();
        let ordered_states: Vec<LatticeState> = indices.iter().map(|&i| step_states[i]).collect();

        let plan = SagaPlan::new("order_test", ordered_steps);
        let exec_plan = SagaExecutionPlan::from_plan(&plan);
        let executor = MonotoneSagaExecutor::new();
        let mut step_exec = SequentialExecutor::new(ordered_states);

        let result = executor.execute(&exec_plan, &mut step_exec);
        assert_eq!(
            result.final_state, expected,
            "order independence failed for run {run}, permutation: {indices:?}",
        );
    }
}

// ============================================================================
// 6. Executor behavior
// ============================================================================

#[test]
fn executor_all_monotone_zero_barriers() {
    init_test_logging();

    let plan = SagaPlan::new(
        "all_mono",
        vec![
            SagaStep::new(SagaOpKind::Reserve, "r1"),
            SagaStep::new(SagaOpKind::Send, "s1"),
            SagaStep::new(SagaOpKind::Acquire, "a1"),
        ],
    );
    let exec_plan = SagaExecutionPlan::from_plan(&plan);
    let executor = MonotoneSagaExecutor::new();
    let mut step_exec = ConstantExecutor(LatticeState::Reserved);

    let result = executor.execute(&exec_plan, &mut step_exec);
    assert!(result.calm_optimized);
    assert_eq!(result.barrier_count, 0);
    assert_eq!(result.total_steps, 3);
    assert_eq!(result.final_state, LatticeState::Reserved);
    assert!(result.is_clean());
}

#[test]
fn executor_mixed_saga_correct_barriers() {
    init_test_logging();

    let plan = SagaPlan::new(
        "mixed",
        vec![
            SagaStep::new(SagaOpKind::Reserve, "r1"),
            SagaStep::new(SagaOpKind::Send, "s1"),
            SagaStep::new(SagaOpKind::Commit, "c1"),
            SagaStep::new(SagaOpKind::Acquire, "a1"),
        ],
    );
    let exec_plan = SagaExecutionPlan::from_plan(&plan);
    let executor = MonotoneSagaExecutor::new();
    let mut step_exec = SequentialExecutor::new(vec![
        LatticeState::Reserved,
        LatticeState::Reserved,
        LatticeState::Committed,
        LatticeState::Reserved,
    ]);

    let result = executor.execute(&exec_plan, &mut step_exec);
    assert!(result.calm_optimized);
    assert_eq!(result.barrier_count, 1);
    assert_eq!(result.total_steps, 4);
}

#[test]
fn executor_monotonicity_violation_triggers_fallback() {
    init_test_logging();

    let plan = SagaPlan::new(
        "fallback",
        vec![
            SagaStep::new(SagaOpKind::Reserve, "good"),
            SagaStep::new(SagaOpKind::Send, "bad_step"),
            SagaStep::new(SagaOpKind::Acquire, "after"),
        ],
    );
    let exec_plan = SagaExecutionPlan::from_plan(&plan);
    let executor = MonotoneSagaExecutor::new();
    let mut step_exec = ViolatingOnLabelExecutor {
        target_label: "bad_step".to_string(),
    };

    let result = executor.execute(&exec_plan, &mut step_exec);
    assert!(!result.calm_optimized);
    assert!(result.fallback_reason.is_some());
    assert!(
        result
            .fallback_reason
            .as_ref()
            .unwrap()
            .contains("bad_step"),
        "fallback reason should mention the violating step"
    );
}

#[test]
fn executor_without_validation_skips_monotonicity_check() {
    init_test_logging();

    let plan = SagaPlan::new(
        "no_validation",
        vec![
            SagaStep::new(SagaOpKind::Reserve, "bad_step"),
            SagaStep::new(SagaOpKind::Send, "s1"),
        ],
    );
    let exec_plan = SagaExecutionPlan::from_plan(&plan);
    let executor = MonotoneSagaExecutor::without_validation();
    let mut step_exec = ViolatingOnLabelExecutor {
        target_label: "bad_step".to_string(),
    };

    let result = executor.execute(&exec_plan, &mut step_exec);
    // Without validation, should still succeed (violation not detected).
    assert!(result.calm_optimized);
    assert!(result.fallback_reason.is_none());
}

#[test]
fn executor_batch_results_contain_correct_metadata() {
    init_test_logging();

    let plan = SagaPlan::new(
        "metadata",
        vec![
            SagaStep::new(SagaOpKind::Reserve, "r1"),
            SagaStep::new(SagaOpKind::Send, "s1"),
            SagaStep::new(SagaOpKind::Commit, "c1"),
        ],
    );
    let exec_plan = SagaExecutionPlan::from_plan(&plan);
    let executor = MonotoneSagaExecutor::new();
    let mut step_exec = SequentialExecutor::new(vec![
        LatticeState::Reserved,
        LatticeState::Reserved,
        LatticeState::Committed,
    ]);

    let result = executor.execute(&exec_plan, &mut step_exec);
    assert_eq!(result.batch_results.len(), 2);

    // First batch: coordination-free with 2 steps.
    let b0 = &result.batch_results[0];
    assert!(b0.coordination_free);
    assert_eq!(b0.step_count, 2);
    assert_eq!(b0.batch_index, 0);

    // Second batch: coordinated with 1 step.
    let b1 = &result.batch_results[1];
    assert!(!b1.coordination_free);
    assert_eq!(b1.step_count, 1);
}

// ============================================================================
// 7. Evidence ledger integration
// ============================================================================

#[test]
fn evidence_calm_optimized_saga() {
    init_test_logging();

    let result = SagaExecutionResult {
        saga_name: "test_saga".to_string(),
        batch_results: vec![BatchResult {
            batch_index: 0,
            coordination_free: true,
            step_count: 5,
            merged_state: LatticeState::Reserved,
            merge_count: 5,
        }],
        final_state: LatticeState::Reserved,
        calm_optimized: true,
        fallback_reason: None,
        barrier_count: 0,
        total_steps: 5,
    };

    let entry = MonotoneSagaExecutor::build_evidence(&result);
    assert_eq!(entry.component, "saga_executor");
    assert_eq!(entry.action, "calm_optimized");
    assert!(!entry.fallback_active);
    // With 0 barriers and 5 steps, monotone_step_ratio should be 1.0.
    let mono_ratio = entry
        .top_features
        .iter()
        .find(|(k, _)| k == "monotone_step_ratio");
    assert!(mono_ratio.is_some());
    assert!((mono_ratio.unwrap().1 - 1.0).abs() < 0.001);
}

#[test]
fn evidence_fallback_saga() {
    init_test_logging();

    let result = SagaExecutionResult {
        saga_name: "fallback_saga".to_string(),
        batch_results: vec![],
        final_state: LatticeState::Unknown,
        calm_optimized: false,
        fallback_reason: Some("test violation".to_string()),
        barrier_count: 3,
        total_steps: 3,
    };

    let entry = MonotoneSagaExecutor::build_evidence(&result);
    assert_eq!(entry.action, "fully_coordinated");
    assert!(entry.fallback_active);
}

// ============================================================================
// 8. SagaPlan monotone ratio
// ============================================================================

#[test]
fn monotone_ratio_empty_plan() {
    init_test_logging();
    let plan = SagaPlan::new("empty", vec![]);
    assert!((plan.monotone_ratio()).abs() < 0.001);
}

#[test]
fn monotone_ratio_all_monotone() {
    init_test_logging();
    let plan = SagaPlan::new(
        "all_mono",
        vec![
            SagaStep::new(SagaOpKind::Reserve, "r"),
            SagaStep::new(SagaOpKind::Send, "s"),
        ],
    );
    assert!((plan.monotone_ratio() - 1.0).abs() < 0.001);
}

#[test]
fn monotone_ratio_all_non_monotone() {
    init_test_logging();
    let plan = SagaPlan::new(
        "all_nm",
        vec![
            SagaStep::new(SagaOpKind::Commit, "c"),
            SagaStep::new(SagaOpKind::Abort, "a"),
        ],
    );
    assert!((plan.monotone_ratio()).abs() < 0.001);
}

#[test]
fn monotone_ratio_half_and_half() {
    init_test_logging();
    let plan = SagaPlan::new(
        "half",
        vec![
            SagaStep::new(SagaOpKind::Reserve, "r"),
            SagaStep::new(SagaOpKind::Commit, "c"),
            SagaStep::new(SagaOpKind::Send, "s"),
            SagaStep::new(SagaOpKind::Recv, "recv"),
        ],
    );
    assert!((plan.monotone_ratio() - 0.5).abs() < 0.001);
}

// ============================================================================
// 9. SagaStep with_override
// ============================================================================

#[test]
fn saga_step_override_monotonicity() {
    init_test_logging();

    // Override a normally non-monotone op to be monotone.
    let step = SagaStep::with_override(SagaOpKind::Commit, "forced_mono", Monotonicity::Monotone);
    assert_eq!(step.monotonicity, Monotonicity::Monotone);
    assert_eq!(step.op, SagaOpKind::Commit);

    // Override a normally monotone op to be non-monotone.
    let step2 =
        SagaStep::with_override(SagaOpKind::Reserve, "forced_nm", Monotonicity::NonMonotone);
    assert_eq!(step2.monotonicity, Monotonicity::NonMonotone);
}

// ============================================================================
// 10. Deterministic execution — same plan, same result
// ============================================================================

#[test]
fn deterministic_execution_100_runs() {
    init_test_logging();

    let plan = SagaPlan::new(
        "determinism",
        vec![
            SagaStep::new(SagaOpKind::Reserve, "r1"),
            SagaStep::new(SagaOpKind::Send, "s1"),
            SagaStep::new(SagaOpKind::Commit, "c1"),
            SagaStep::new(SagaOpKind::Acquire, "a1"),
            SagaStep::new(SagaOpKind::Release, "rel1"),
        ],
    );
    let exec_plan = SagaExecutionPlan::from_plan(&plan);

    let states = vec![
        LatticeState::Reserved,
        LatticeState::Reserved,
        LatticeState::Committed,
        LatticeState::Reserved,
        LatticeState::Committed,
    ];

    let executor = MonotoneSagaExecutor::new();
    let mut first_exec = SequentialExecutor::new(states.clone());
    let first_result = executor.execute(&exec_plan, &mut first_exec);

    for _ in 1..100 {
        let mut step_exec = SequentialExecutor::new(states.clone());
        let result = executor.execute(&exec_plan, &mut step_exec);
        assert_eq!(result.final_state, first_result.final_state);
        assert_eq!(result.calm_optimized, first_result.calm_optimized);
        assert_eq!(result.barrier_count, first_result.barrier_count);
        assert_eq!(result.total_steps, first_result.total_steps);
    }
}

// ============================================================================
// 11. SagaOpKind display
// ============================================================================

#[test]
fn saga_op_kind_display_all() {
    init_test_logging();

    for &op in &ALL_OPS {
        let name = op.as_str();
        assert!(!name.is_empty());
        assert_eq!(op.to_string(), name);
    }
}

// ============================================================================
// Property-based tests
// ============================================================================

fn arb_lattice_state() -> impl Strategy<Value = LatticeState> {
    prop_oneof![
        Just(LatticeState::Unknown),
        Just(LatticeState::Reserved),
        Just(LatticeState::Committed),
        Just(LatticeState::Aborted),
        Just(LatticeState::Conflict),
    ]
}

fn arb_saga_op_kind() -> impl Strategy<Value = SagaOpKind> {
    (0..ALL_OPS.len()).prop_map(|i| ALL_OPS[i])
}

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// Lattice join is commutative for all states.
    #[test]
    fn proptest_lattice_commutativity(
        a in arb_lattice_state(),
        b in arb_lattice_state(),
    ) {
        prop_assert_eq!(Lattice::join(&a, &b), Lattice::join(&b, &a));
    }

    /// Lattice join is associative for all states.
    #[test]
    fn proptest_lattice_associativity(
        a in arb_lattice_state(),
        b in arb_lattice_state(),
        c in arb_lattice_state(),
    ) {
        let lhs = Lattice::join(&Lattice::join(&a, &b), &c);
        let rhs = Lattice::join(&a, &Lattice::join(&b, &c));
        prop_assert_eq!(lhs, rhs);
    }

    /// Lattice join is idempotent.
    #[test]
    fn proptest_lattice_idempotence(a in arb_lattice_state()) {
        prop_assert_eq!(Lattice::join(&a, &a), a);
    }

    /// Unknown is the identity element.
    #[test]
    fn proptest_lattice_identity(a in arb_lattice_state()) {
        let bottom = LatticeState::bottom();
        prop_assert_eq!(Lattice::join(&bottom, &a), a);
        prop_assert_eq!(Lattice::join(&a, &bottom), a);
    }

    /// Conflict absorbs all elements (top element).
    #[test]
    fn proptest_conflict_is_top(a in arb_lattice_state()) {
        prop_assert_eq!(
            Lattice::join(&LatticeState::Conflict, &a),
            LatticeState::Conflict
        );
    }

    /// Random saga plans always produce valid execution plans.
    #[test]
    fn proptest_random_saga_plan_valid(
        ops in prop::collection::vec(arb_saga_op_kind(), 1..20),
    ) {
        let steps: Vec<SagaStep> = ops
            .iter()
            .enumerate()
            .map(|(i, &op)| SagaStep::new(op, format!("step{i}")))
            .collect();
        let plan = SagaPlan::new("random", steps);
        let exec = SagaExecutionPlan::from_plan(&plan);

        // Total steps in batches should equal plan steps.
        prop_assert_eq!(exec.total_steps(), ops.len());

        // Monotone ratio is consistent.
        let ratio = plan.monotone_ratio();
        prop_assert!((0.0..=1.0).contains(&ratio));
    }

    /// Executing random plans with constant state always produces clean results.
    #[test]
    fn proptest_random_plan_constant_executor(
        ops in prop::collection::vec(arb_saga_op_kind(), 1..15),
        state in arb_lattice_state(),
    ) {
        let steps: Vec<SagaStep> = ops
            .iter()
            .enumerate()
            .map(|(i, &op)| SagaStep::new(op, format!("s{i}")))
            .collect();
        let plan = SagaPlan::new("proptest", steps);
        let exec_plan = SagaExecutionPlan::from_plan(&plan);
        let executor = MonotoneSagaExecutor::without_validation();
        let mut step_exec = ConstantExecutor(state);

        let result = executor.execute(&exec_plan, &mut step_exec);
        prop_assert_eq!(result.total_steps, ops.len());
        // Final state should be the join of the constant state with itself = state.
        prop_assert_eq!(result.final_state, state);
    }

    /// join_all of N copies of a state equals the state (idempotence).
    #[test]
    fn proptest_join_all_idempotent(
        state in arb_lattice_state(),
        n in 1usize..50,
    ) {
        let result = LatticeState::join_all(std::iter::repeat_n(state, n));
        prop_assert_eq!(result, state);
    }
}

// ============================================================================
// CRDT integration — saga states feed into obligation CRDT
// ============================================================================

#[test]
fn crdt_ledger_saga_state_progression() {
    use asupersync::obligation::crdt::CrdtObligationLedger;
    use asupersync::remote::NodeId;

    init_test_logging();

    let mut ledger = CrdtObligationLedger::new(NodeId::new("node-a"));
    let oid = asupersync::types::ObligationId::new_for_test(1, 0);

    // Reserve.
    let state = ledger.record_acquire(oid, asupersync::record::ObligationKind::SendPermit);
    assert_eq!(state, LatticeState::Reserved);

    // Commit.
    let state = ledger.record_commit(oid);
    assert_eq!(state, LatticeState::Committed);

    // Verify the ledger reports no pending obligations.
    assert!(ledger.pending().is_empty());
    assert!(ledger.is_sound());
}

#[test]
fn crdt_ledger_conflict_detection() {
    use asupersync::obligation::crdt::CrdtObligationLedger;
    use asupersync::remote::NodeId;
    use asupersync::trace::distributed::Merge;

    init_test_logging();

    let mut ledger_a = CrdtObligationLedger::new(NodeId::new("node-a"));
    let mut ledger_b = CrdtObligationLedger::new(NodeId::new("node-b"));
    let oid = asupersync::types::ObligationId::new_for_test(10, 0);

    // Node A acquires and commits.
    ledger_a.record_acquire(oid, asupersync::record::ObligationKind::Lease);
    ledger_a.record_commit(oid);

    // Node B acquires and aborts (concurrent with A).
    ledger_b.record_acquire(oid, asupersync::record::ObligationKind::Lease);
    ledger_b.record_abort(oid);

    // Merge: committed ⊔ aborted = conflict.
    ledger_a.merge(&ledger_b);

    let conflicts = ledger_a.conflicts();
    assert_eq!(conflicts.len(), 1, "should detect 1 conflict");
    assert_eq!(conflicts[0].0, oid);
}

#[test]
fn crdt_ledger_merge_commutativity() {
    use asupersync::obligation::crdt::CrdtObligationLedger;
    use asupersync::remote::NodeId;
    use asupersync::trace::distributed::Merge;

    init_test_logging();

    let mut a = CrdtObligationLedger::new(NodeId::new("node-a"));
    let mut b = CrdtObligationLedger::new(NodeId::new("node-b"));
    let oid = asupersync::types::ObligationId::new_for_test(20, 0);

    a.record_acquire(oid, asupersync::record::ObligationKind::SendPermit);
    b.record_acquire(oid, asupersync::record::ObligationKind::SendPermit);
    b.record_commit(oid);

    // Merge a into b vs b into a — same result.
    let mut ab = a.clone();
    ab.merge(&b);

    let mut ba = b.clone();
    ba.merge(&a);

    assert_eq!(ab.get(&oid), ba.get(&oid));
}
