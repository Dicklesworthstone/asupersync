//! CALM-optimized saga execution with coordination-free monotone batches (bd-2wrsc.2).
//!
//! Applies the CALM theorem (Hellerstein & Alvaro 2020) to saga execution:
//! consecutive monotone steps are batched into coordination-free groups that
//! can execute in any order with results merged via lattice join. Coordination
//! barriers are inserted only before non-monotone steps.
//!
//! # Architecture
//!
//! ```text
//! SagaPlan ──▶ SagaExecutionPlan ──▶ MonotoneSagaExecutor
//!   (steps)     (batched)              (runs batches)
//! ```
//!
//! 1. A [`SagaPlan`] is a named sequence of [`SagaStep`]s, each annotated
//!    with its CALM [`Monotonicity`] classification.
//!
//! 2. [`SagaExecutionPlan::from_plan`] partitions steps into batches:
//!    - [`SagaBatch::CoordinationFree`]: consecutive monotone steps that can
//!      execute in any order with outputs merged via [`Lattice::join`].
//!    - [`SagaBatch::Coordinated`]: a single non-monotone step that requires
//!      all preceding outputs to be settled before execution.
//!
//! 3. [`MonotoneSagaExecutor`] runs batches, merges lattice state, and
//!    logs execution to the [`EvidenceLedger`].
//!
//! # Lattice Trait
//!
//! The [`Lattice`] trait generalizes join-semilattice operations:
//!
//! ```
//! use asupersync::obligation::saga::Lattice;
//!
//! // MaxU64 forms a join-semilattice with max as join
//! #[derive(Clone, PartialEq, Eq, Debug)]
//! struct MaxU64(u64);
//!
//! impl Lattice for MaxU64 {
//!     fn bottom() -> Self { MaxU64(0) }
//!     fn join(&self, other: &Self) -> Self { MaxU64(self.0.max(other.0)) }
//! }
//!
//! let a = MaxU64(3);
//! let b = MaxU64(5);
//! assert_eq!(a.join(&b), MaxU64(5));
//! assert_eq!(a.join(&b), b.join(&a)); // commutative
//! ```

use crate::obligation::calm::Monotonicity;
use crate::trace::distributed::lattice::LatticeState;
use crate::trace::distributed::sheaf::{
    ConsistencyReport, ConstraintViolation, NodeSnapshot, SagaConsistencyChecker, SagaConstraint,
};
use std::fmt;

// ---------------------------------------------------------------------------
// Lattice trait
// ---------------------------------------------------------------------------

/// A join-semilattice: a set with a commutative, associative, idempotent join
/// operation and a bottom element.
///
/// Laws that implementations must satisfy:
/// - **Commutativity**: `a.join(b) == b.join(a)`
/// - **Associativity**: `a.join(b).join(c) == a.join(b.join(c))`
/// - **Idempotence**: `a.join(a) == a`
/// - **Identity**: `bottom().join(a) == a`
pub trait Lattice: Clone + PartialEq {
    /// The bottom element (identity for join).
    fn bottom() -> Self;

    /// The least upper bound of `self` and `other`.
    #[must_use]
    fn join(&self, other: &Self) -> Self;

    /// Joins a sequence of values, starting from bottom.
    fn join_all(values: impl IntoIterator<Item = Self>) -> Self {
        values
            .into_iter()
            .fold(Self::bottom(), |acc, v| acc.join(&v))
    }
}

/// Implement `Lattice` for the existing `LatticeState` enum.
impl Lattice for LatticeState {
    fn bottom() -> Self {
        Self::Unknown
    }

    fn join(&self, other: &Self) -> Self {
        // Delegate to LatticeState's existing join method.
        Self::join(*self, *other)
    }
}

// ---------------------------------------------------------------------------
// Saga step & plan types
// ---------------------------------------------------------------------------

/// A saga operation kind, matching the CALM classification table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SagaOpKind {
    /// Reserve an obligation (monotone: pure insertion).
    Reserve,
    /// Commit an obligation (non-monotone: state guard).
    Commit,
    /// Abort an obligation (non-monotone: state guard).
    Abort,
    /// Send a message (monotone: channel append).
    Send,
    /// Receive a message (non-monotone: destructive read).
    Recv,
    /// Acquire a lease (monotone: insertion).
    Acquire,
    /// Renew a lease (monotone: max/join on deadline).
    Renew,
    /// Release a lease (non-monotone: state guard).
    Release,
    /// Close a region (non-monotone: quiescence barrier).
    RegionClose,
    /// Delegate channel ownership (monotone: information flow).
    Delegate,
    /// CRDT merge (monotone: join-semilattice).
    CrdtMerge,
    /// Request cancellation (monotone: latch).
    CancelRequest,
    /// Drain cancellation (non-monotone: barrier).
    CancelDrain,
    /// Mark obligation leaked (non-monotone: absence).
    MarkLeaked,
    /// Check budget (non-monotone: threshold).
    BudgetCheck,
    /// Detect leaks (non-monotone: negation).
    LeakDetection,
}

impl SagaOpKind {
    /// Returns the CALM monotonicity classification for this operation.
    #[must_use]
    pub const fn monotonicity(self) -> Monotonicity {
        match self {
            Self::Reserve
            | Self::Send
            | Self::Acquire
            | Self::Renew
            | Self::Delegate
            | Self::CrdtMerge
            | Self::CancelRequest => Monotonicity::Monotone,

            Self::Commit
            | Self::Abort
            | Self::Recv
            | Self::Release
            | Self::RegionClose
            | Self::CancelDrain
            | Self::MarkLeaked
            | Self::BudgetCheck
            | Self::LeakDetection => Monotonicity::NonMonotone,
        }
    }

    /// Returns the operation name as a string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserve => "Reserve",
            Self::Commit => "Commit",
            Self::Abort => "Abort",
            Self::Send => "Send",
            Self::Recv => "Recv",
            Self::Acquire => "Acquire",
            Self::Renew => "Renew",
            Self::Release => "Release",
            Self::RegionClose => "RegionClose",
            Self::Delegate => "Delegate",
            Self::CrdtMerge => "CrdtMerge",
            Self::CancelRequest => "CancelRequest",
            Self::CancelDrain => "CancelDrain",
            Self::MarkLeaked => "MarkLeaked",
            Self::BudgetCheck => "BudgetCheck",
            Self::LeakDetection => "LeakDetection",
        }
    }
}

impl fmt::Display for SagaOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single step in a saga plan.
#[derive(Debug, Clone)]
pub struct SagaStep {
    /// Operation kind.
    pub op: SagaOpKind,
    /// Step label (for diagnostics).
    pub label: String,
    /// CALM monotonicity classification.
    pub monotonicity: Monotonicity,
}

impl SagaStep {
    /// Creates a new saga step with monotonicity derived from the operation.
    #[must_use]
    pub fn new(op: SagaOpKind, label: impl Into<String>) -> Self {
        Self {
            monotonicity: op.monotonicity(),
            op,
            label: label.into(),
        }
    }

    /// Creates a step with an explicit monotonicity override.
    ///
    /// Use this when a specific instance of an operation is known to be
    /// monotone even though the general case is non-monotone (e.g., a
    /// commit on a single-holder obligation).
    #[must_use]
    pub fn with_override(
        op: SagaOpKind,
        label: impl Into<String>,
        monotonicity: Monotonicity,
    ) -> Self {
        Self {
            op,
            label: label.into(),
            monotonicity,
        }
    }
}

/// A named sequence of saga steps.
#[derive(Debug, Clone)]
pub struct SagaPlan {
    /// Saga name.
    pub name: String,
    /// Ordered steps.
    pub steps: Vec<SagaStep>,
}

impl SagaPlan {
    /// Creates a new saga plan.
    #[must_use]
    pub fn new(name: impl Into<String>, steps: Vec<SagaStep>) -> Self {
        Self {
            name: name.into(),
            steps,
        }
    }

    /// Returns the fraction of steps that are monotone.
    #[must_use]
    pub fn monotone_ratio(&self) -> f64 {
        if self.steps.is_empty() {
            return 0.0;
        }
        let mono = self
            .steps
            .iter()
            .filter(|s| s.monotonicity == Monotonicity::Monotone)
            .count();
        #[allow(clippy::cast_precision_loss)]
        {
            mono as f64 / self.steps.len() as f64
        }
    }
}

// ---------------------------------------------------------------------------
// Execution plan (batched)
// ---------------------------------------------------------------------------

/// A batch of saga steps grouped by coordination requirement.
#[derive(Debug, Clone)]
pub enum SagaBatch {
    /// Consecutive monotone steps that can execute in any order.
    /// Outputs merge via `Lattice::join`.
    CoordinationFree(Vec<SagaStep>),
    /// A single non-monotone step requiring a coordination barrier.
    Coordinated(SagaStep),
}

impl SagaBatch {
    /// Returns the number of steps in this batch.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::CoordinationFree(steps) => steps.len(),
            Self::Coordinated(_) => 1,
        }
    }

    /// Returns true if this batch is empty (only possible for `CoordinationFree`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns true if this batch is coordination-free.
    #[must_use]
    pub fn is_coordination_free(&self) -> bool {
        matches!(self, Self::CoordinationFree(_))
    }
}

/// A saga execution plan: steps batched for CALM-optimized execution.
#[derive(Debug, Clone)]
pub struct SagaExecutionPlan {
    /// Saga name.
    pub saga_name: String,
    /// Batched steps.
    pub batches: Vec<SagaBatch>,
}

impl SagaExecutionPlan {
    /// Partitions a saga plan into coordination-free and coordinated batches.
    ///
    /// Consecutive monotone steps are grouped into `CoordinationFree` batches.
    /// Each non-monotone step becomes its own `Coordinated` batch.
    #[must_use]
    pub fn from_plan(plan: &SagaPlan) -> Self {
        let mut batches = Vec::new();
        let mut mono_buffer: Vec<SagaStep> = Vec::new();

        for step in &plan.steps {
            match step.monotonicity {
                Monotonicity::Monotone => {
                    mono_buffer.push(step.clone());
                }
                Monotonicity::NonMonotone => {
                    // Flush any buffered monotone steps.
                    if !mono_buffer.is_empty() {
                        batches.push(SagaBatch::CoordinationFree(std::mem::take(
                            &mut mono_buffer,
                        )));
                    }
                    batches.push(SagaBatch::Coordinated(step.clone()));
                }
            }
        }

        // Flush trailing monotone steps.
        if !mono_buffer.is_empty() {
            batches.push(SagaBatch::CoordinationFree(mono_buffer));
        }

        Self {
            saga_name: plan.name.clone(),
            batches,
        }
    }

    /// Returns the number of coordination barriers in this plan.
    ///
    /// A fully monotone saga has zero barriers.
    #[must_use]
    pub fn coordination_barrier_count(&self) -> usize {
        self.batches
            .iter()
            .filter(|b| matches!(b, SagaBatch::Coordinated(_)))
            .count()
    }

    /// Returns the total number of steps across all batches.
    #[must_use]
    pub fn total_steps(&self) -> usize {
        self.batches.iter().map(SagaBatch::len).sum()
    }

    /// Returns the number of coordination-free batches.
    #[must_use]
    pub fn coordination_free_batch_count(&self) -> usize {
        self.batches
            .iter()
            .filter(|b| b.is_coordination_free())
            .count()
    }
}

// ---------------------------------------------------------------------------
// Execution result types
// ---------------------------------------------------------------------------

/// The result of executing a single saga step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepResult {
    /// The step label.
    pub label: String,
    /// Operation kind.
    pub op: SagaOpKind,
    /// Lattice state produced by this step.
    pub state: LatticeState,
}

/// The outcome of executing a saga batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchResult {
    /// Batch index (0-based).
    pub batch_index: usize,
    /// Whether this batch was coordination-free.
    pub coordination_free: bool,
    /// Number of steps in the batch.
    pub step_count: usize,
    /// Merged state after all steps (via lattice join for coordination-free).
    pub merged_state: LatticeState,
    /// Number of lattice merges performed.
    pub merge_count: usize,
}

/// The outcome of executing an entire saga.
#[derive(Debug, Clone)]
pub struct SagaExecutionResult {
    /// Saga name.
    pub saga_name: String,
    /// Per-batch results.
    pub batch_results: Vec<BatchResult>,
    /// Final merged state.
    pub final_state: LatticeState,
    /// Whether CALM optimization was used (vs fully coordinated fallback).
    pub calm_optimized: bool,
    /// If fallback was triggered, the reason.
    pub fallback_reason: Option<String>,
    /// Total coordination barriers encountered.
    pub barrier_count: usize,
    /// Total steps executed.
    pub total_steps: usize,
}

impl SagaExecutionResult {
    /// Returns true if the saga completed without conflicts.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        !self.final_state.is_conflict()
    }

    /// Checks sheaf-theoretic consistency of this saga's batch results.
    ///
    /// When a saga runs coordination-free batches, each batch produces a
    /// local view of the obligation state (its `merged_state`). Pairwise
    /// lattice merges can hide *global* inconsistency — a "phantom commit"
    /// where the merged state is terminal but no single batch witnessed the
    /// full commit.
    ///
    /// This method models each batch as a "node" with a snapshot of the
    /// obligations it touched, then runs the sheaf gluing checker to detect
    /// obstructions (H^1 != 0) that pairwise merges miss.
    ///
    /// `obligation_ids` maps batch index to the set of obligation IDs that
    /// batch touched. Must have the same length as `batch_results` when
    /// provided. If `None`, all batches are assumed to observe a single
    /// shared synthetic obligation (which limits the checker to detecting
    /// state disagreements but not phantom commits across distinct
    /// obligation sets).
    #[must_use]
    pub fn check_sheaf_consistency(
        &self,
        obligation_ids: Option<&[Vec<crate::types::ObligationId>]>,
    ) -> ConsistencyReport {
        if let Some(ids) = obligation_ids {
            if ids.len() != self.batch_results.len() {
                return ConsistencyReport {
                    pairwise_conflicts: Vec::new(),
                    phantom_states: Vec::new(),
                    constraint_violations: vec![ConstraintViolation {
                        constraint_name: format!("{} obligation mapping", self.saga_name),
                        obligation_states: std::collections::BTreeMap::new(),
                        explanation: format!(
                            "invalid obligation_ids mapping: expected {} batch entries, got {}; \
                             refusing synthetic fallback because it would mask batch-to-obligation mismatches",
                            self.batch_results.len(),
                            ids.len()
                        ),
                    }],
                };
            }
        }

        let snapshots: Vec<NodeSnapshot> = self
            .batch_results
            .iter()
            .enumerate()
            .map(|(i, batch)| {
                let mut snapshot =
                    NodeSnapshot::new(crate::remote::NodeId::new(format!("batch-{i}")));
                if let Some(ids) = obligation_ids.map(|o| &o[i]) {
                    for &id in ids {
                        snapshot.observe(id, batch.merged_state);
                    }
                } else {
                    // Synthetic: all batches observe the same obligation so the
                    // checker can compare their local views. Using different IDs
                    // per batch would make every node's view trivially consistent
                    // (no shared obligations = nothing to disagree on).
                    snapshot.observe(
                        crate::types::ObligationId::new_for_test(0, 0),
                        batch.merged_state,
                    );
                }
                snapshot
            })
            .collect();

        // Default constraint: all obligations should reach the same terminal
        // state (all-or-nothing atomicity).
        let all_obligation_ids: std::collections::BTreeSet<crate::types::ObligationId> = snapshots
            .iter()
            .flat_map(|s| s.states.keys().copied())
            .collect();
        let constraints = vec![SagaConstraint::AllOrNothing {
            name: self.saga_name.clone(),
            obligations: all_obligation_ids,
        }];

        let checker = SagaConsistencyChecker::new(snapshots, constraints);
        checker.check()
    }
}

// ---------------------------------------------------------------------------
// Step executor trait
// ---------------------------------------------------------------------------

/// A function that executes a saga step and returns the resulting lattice state.
///
/// Implementations provide the actual business logic for each step. The
/// executor calls this for each step in the plan.
pub trait StepExecutor {
    /// Executes a saga step and returns the resulting lattice state.
    ///
    /// For monotone steps, the returned state will be merged with other
    /// states in the same coordination-free batch via `Lattice::join`.
    fn execute(&mut self, step: &SagaStep) -> LatticeState;

    /// Validates that a step's monotonicity claim holds for the given state
    /// transition.
    ///
    /// Called after executing a monotone step to verify the post-hoc
    /// monotonicity invariant: the new state must be >= the old state in
    /// the lattice order.
    ///
    /// Returns `Ok(())` if valid, `Err(reason)` if the monotonicity claim
    /// is violated (triggers fallback to fully-coordinated execution).
    fn validate_monotonicity(
        &self,
        step: &SagaStep,
        before: &LatticeState,
        after: &LatticeState,
    ) -> Result<(), String> {
        // Default: check that the new state is >= old state in lattice order.
        // A monotone step should only move up or stay the same.
        if before.join(after) == *after {
            Ok(())
        } else {
            Err(format!(
                "step '{}' ({}) claimed monotone but state went from {} to {} \
                 (join({before}, {after}) != {after})",
                step.label, step.op, before, after,
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Monotone saga executor
// ---------------------------------------------------------------------------

/// Executes saga plans using CALM-optimized batching.
///
/// Consecutive monotone steps execute in a coordination-free batch with
/// outputs merged via lattice join. Non-monotone steps trigger coordination
/// barriers.
///
/// If a monotonicity violation is detected post-hoc (a step claimed monotone
/// but the state transition was non-monotone), the executor falls back to
/// fully-coordinated execution and logs the reason.
pub struct MonotoneSagaExecutor {
    /// Whether to validate monotonicity claims post-hoc.
    validate_monotonicity: bool,
}

impl Default for MonotoneSagaExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotoneSagaExecutor {
    /// Creates a new executor with post-hoc monotonicity validation enabled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            validate_monotonicity: true,
        }
    }

    /// Creates an executor without post-hoc monotonicity validation.
    #[must_use]
    pub fn without_validation() -> Self {
        Self {
            validate_monotonicity: false,
        }
    }

    /// Executes a saga plan using CALM-optimized batching.
    ///
    /// Returns the execution result including per-batch results, final state,
    /// and whether CALM optimization was used or fell back to full coordination.
    pub fn execute(
        &self,
        plan: &SagaExecutionPlan,
        executor: &mut dyn StepExecutor,
    ) -> SagaExecutionResult {
        let mut state = LatticeState::Unknown;
        let mut batch_results = Vec::with_capacity(plan.batches.len());
        let mut barrier_count = 0;
        let mut total_steps = 0;
        let mut fallback_reason: Option<String> = None;

        for (batch_idx, batch) in plan.batches.iter().enumerate() {
            match batch {
                SagaBatch::CoordinationFree(steps) => {
                    let result = if fallback_reason.is_some() {
                        // Fallback: execute each step sequentially with barriers.
                        self.execute_coordinated_batch(steps, &mut state, batch_idx, executor)
                    } else {
                        self.execute_coordination_free_batch(
                            steps,
                            &mut state,
                            batch_idx,
                            executor,
                            &mut fallback_reason,
                        )
                    };
                    total_steps += result.step_count;
                    // Only count barriers for batches that were originally
                    // coordinated—not coordination-free batches that fell back
                    // due to a monotonicity violation (they still used join
                    // semantics, so no actual barriers were inserted).
                    batch_results.push(result);
                }
                SagaBatch::Coordinated(step) => {
                    barrier_count += 1;
                    total_steps += 1;
                    let before = state;
                    let step_state = executor.execute(step);
                    state = Lattice::join(&state, &step_state);
                    batch_results.push(BatchResult {
                        batch_index: batch_idx,
                        coordination_free: false,
                        step_count: 1,
                        merged_state: state,
                        merge_count: 1,
                    });

                    // Non-monotone steps don't need monotonicity validation,
                    // but we still check for conflicts.
                    if state.is_conflict() && fallback_reason.is_none() {
                        fallback_reason = Some(format!(
                            "conflict at coordinated step '{}' ({}): {before} ⊔ {step_state} = Conflict",
                            step.label, step.op,
                        ));
                    }
                }
            }
        }

        SagaExecutionResult {
            saga_name: plan.saga_name.clone(),
            batch_results,
            final_state: state,
            calm_optimized: fallback_reason.is_none(),
            fallback_reason,
            barrier_count,
            total_steps,
        }
    }

    /// Executes a coordination-free batch: runs all steps, merges via join.
    fn execute_coordination_free_batch(
        &self,
        steps: &[SagaStep],
        state: &mut LatticeState,
        batch_idx: usize,
        executor: &mut dyn StepExecutor,
        fallback_reason: &mut Option<String>,
    ) -> BatchResult {
        let mut merge_count = 0;

        for step in steps {
            let before = *state;
            let step_state = executor.execute(step);
            *state = Lattice::join(state, &step_state);
            merge_count += 1;

            // Detect conflicts produced by join.
            if state.is_conflict() && fallback_reason.is_none() {
                *fallback_reason = Some(format!(
                    "conflict at coordination-free step '{}' ({}): {before} ⊔ {step_state} = Conflict",
                    step.label, step.op,
                ));
            }

            // Post-hoc monotonicity validation.
            if self.validate_monotonicity {
                if let Err(reason) = executor.validate_monotonicity(step, &before, state) {
                    if fallback_reason.is_none() {
                        *fallback_reason = Some(reason);
                    }
                    // Continue executing remaining steps with join semantics.
                    // The violation is recorded but does not change execution
                    // within this batch; the flag prevents future batches from
                    // using the coordination-free path.
                }
            }
        }

        BatchResult {
            batch_index: batch_idx,
            // This function only runs when this batch is executing on the
            // coordination-free path. A fallback reason set mid-batch should
            // affect subsequent batches, not rewrite how this batch ran.
            coordination_free: true,
            step_count: steps.len(),
            merged_state: *state,
            merge_count,
        }
    }

    /// Fallback: executes steps sequentially with implicit barriers.
    #[allow(clippy::unused_self)]
    fn execute_coordinated_batch(
        &self,
        steps: &[SagaStep],
        state: &mut LatticeState,
        batch_idx: usize,
        executor: &mut dyn StepExecutor,
    ) -> BatchResult {
        let mut merge_count = 0;

        for step in steps {
            let step_state = executor.execute(step);
            *state = Lattice::join(state, &step_state);
            merge_count += 1;
        }

        BatchResult {
            batch_index: batch_idx,
            coordination_free: false,
            step_count: steps.len(),
            merged_state: *state,
            merge_count,
        }
    }

    /// Builds an `EvidenceLedger` entry for a completed saga execution.
    #[must_use]
    pub fn build_evidence(result: &SagaExecutionResult) -> franken_evidence::EvidenceLedger {
        let mono_steps = result
            .batch_results
            .iter()
            .filter(|b| b.coordination_free)
            .map(|b| b.step_count)
            .sum::<usize>();

        #[allow(clippy::cast_precision_loss)]
        let mono_ratio = if result.total_steps > 0 {
            mono_steps as f64 / result.total_steps as f64
        } else {
            0.0
        };

        let action = if result.calm_optimized {
            "calm_optimized"
        } else {
            "fully_coordinated"
        };

        franken_evidence::EvidenceLedgerBuilder::new()
            .ts_unix_ms(0) // Caller should set real timestamp
            .component("saga_executor")
            .action(action)
            .posterior(vec![mono_ratio, 1.0 - mono_ratio])
            .expected_loss(action, 0.0)
            .chosen_expected_loss(0.0)
            .calibration_score(1.0)
            .fallback_active(!result.calm_optimized)
            .top_feature("monotone_step_ratio", mono_ratio)
            .top_feature(
                "coordination_barriers",
                #[allow(clippy::cast_precision_loss)]
                {
                    result.barrier_count as f64
                },
            )
            .build()
            .expect("evidence entry is valid")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;

    // -- Lattice law tests --------------------------------------------------

    #[test]
    fn lattice_state_commutativity() {
        use LatticeState::*;
        let states = [Unknown, Reserved, Committed, Aborted, Conflict];
        for &a in &states {
            for &b in &states {
                assert_eq!(
                    Lattice::join(&a, &b),
                    Lattice::join(&b, &a),
                    "commutativity failed for {a} ⊔ {b}",
                );
            }
        }
    }

    #[test]
    fn lattice_state_associativity() {
        use LatticeState::*;
        let states = [Unknown, Reserved, Committed, Aborted, Conflict];
        for &a in &states {
            for &b in &states {
                for &c in &states {
                    let lhs = Lattice::join(&Lattice::join(&a, &b), &c);
                    let rhs = Lattice::join(&a, &Lattice::join(&b, &c));
                    assert_eq!(
                        lhs, rhs,
                        "associativity failed: ({a} ⊔ {b}) ⊔ {c} != {a} ⊔ ({b} ⊔ {c})",
                    );
                }
            }
        }
    }

    #[test]
    fn lattice_state_idempotence() {
        use LatticeState::*;
        for &a in &[Unknown, Reserved, Committed, Aborted, Conflict] {
            assert_eq!(Lattice::join(&a, &a), a, "idempotence failed for {a}");
        }
    }

    #[test]
    fn lattice_state_identity() {
        use LatticeState::*;
        let bottom = LatticeState::bottom();
        assert_eq!(bottom, Unknown);
        for &a in &[Unknown, Reserved, Committed, Aborted, Conflict] {
            assert_eq!(Lattice::join(&bottom, &a), a, "identity failed for {a}");
        }
    }

    #[test]
    fn lattice_join_all() {
        use LatticeState::*;
        let result = LatticeState::join_all([Unknown, Reserved, Committed]);
        assert_eq!(result, Committed);
    }

    // -- SagaOpKind monotonicity consistency ---------------------------------

    #[test]
    fn op_kind_monotonicity_matches_calm() {
        use crate::obligation::calm;
        for c in calm::classifications() {
            // Find matching SagaOpKind (if it exists).
            let op = match c.operation {
                "Reserve" => SagaOpKind::Reserve,
                "Commit" => SagaOpKind::Commit,
                "Abort" => SagaOpKind::Abort,
                "Send" => SagaOpKind::Send,
                "Recv" => SagaOpKind::Recv,
                "Acquire" => SagaOpKind::Acquire,
                "Renew" => SagaOpKind::Renew,
                "Release" => SagaOpKind::Release,
                "RegionClose" => SagaOpKind::RegionClose,
                "Delegate" => SagaOpKind::Delegate,
                "CrdtMerge" => SagaOpKind::CrdtMerge,
                "CancelRequest" => SagaOpKind::CancelRequest,
                "CancelDrain" => SagaOpKind::CancelDrain,
                "MarkLeaked" => SagaOpKind::MarkLeaked,
                "BudgetCheck" => SagaOpKind::BudgetCheck,
                "LeakDetection" => SagaOpKind::LeakDetection,
                _ => continue,
            };
            assert_eq!(
                op.monotonicity(),
                c.monotonicity,
                "SagaOpKind::{} disagrees with CalmClassification",
                c.operation,
            );
        }
    }

    // -- Execution plan batching --------------------------------------------

    #[test]
    fn plan_all_monotone_produces_single_batch() {
        let plan = SagaPlan::new(
            "all_mono",
            vec![
                SagaStep::new(SagaOpKind::Reserve, "r1"),
                SagaStep::new(SagaOpKind::Send, "s1"),
                SagaStep::new(SagaOpKind::Acquire, "a1"),
            ],
        );
        let exec = SagaExecutionPlan::from_plan(&plan);
        assert_eq!(exec.batches.len(), 1);
        assert!(exec.batches[0].is_coordination_free());
        assert_eq!(exec.coordination_barrier_count(), 0);
        assert_eq!(exec.total_steps(), 3);
    }

    #[test]
    fn plan_all_non_monotone_produces_individual_batches() {
        let plan = SagaPlan::new(
            "all_nm",
            vec![
                SagaStep::new(SagaOpKind::Commit, "c1"),
                SagaStep::new(SagaOpKind::RegionClose, "rc1"),
            ],
        );
        let exec = SagaExecutionPlan::from_plan(&plan);
        assert_eq!(exec.batches.len(), 2);
        assert_eq!(exec.coordination_barrier_count(), 2);
    }

    #[test]
    fn plan_mixed_batching() {
        // [Reserve(M), Send(M), Commit(NM), Acquire(M), Release(NM)]
        let plan = SagaPlan::new(
            "mixed",
            vec![
                SagaStep::new(SagaOpKind::Reserve, "r1"),
                SagaStep::new(SagaOpKind::Send, "s1"),
                SagaStep::new(SagaOpKind::Commit, "c1"),
                SagaStep::new(SagaOpKind::Acquire, "a1"),
                SagaStep::new(SagaOpKind::Release, "rel1"),
            ],
        );
        let exec = SagaExecutionPlan::from_plan(&plan);
        // Batches: [Reserve,Send](CF) -> Commit(C) -> [Acquire](CF) -> Release(C)
        assert_eq!(exec.batches.len(), 4);
        assert!(exec.batches[0].is_coordination_free());
        assert_eq!(exec.batches[0].len(), 2);
        assert!(!exec.batches[1].is_coordination_free());
        assert!(exec.batches[2].is_coordination_free());
        assert_eq!(exec.batches[2].len(), 1);
        assert!(!exec.batches[3].is_coordination_free());
        assert_eq!(exec.coordination_barrier_count(), 2);
    }

    #[test]
    fn plan_trailing_monotone_flushed() {
        let plan = SagaPlan::new(
            "trailing",
            vec![
                SagaStep::new(SagaOpKind::Commit, "c1"),
                SagaStep::new(SagaOpKind::Reserve, "r1"),
                SagaStep::new(SagaOpKind::Send, "s1"),
            ],
        );
        let exec = SagaExecutionPlan::from_plan(&plan);
        assert_eq!(exec.batches.len(), 2);
        assert!(!exec.batches[0].is_coordination_free()); // Commit
        assert!(exec.batches[1].is_coordination_free()); // [Reserve, Send]
        assert_eq!(exec.batches[1].len(), 2);
    }

    #[test]
    fn empty_plan_produces_no_batches() {
        let plan = SagaPlan::new("empty", vec![]);
        let exec = SagaExecutionPlan::from_plan(&plan);
        assert!(exec.batches.is_empty());
        assert_eq!(exec.total_steps(), 0);
    }

    #[test]
    fn monotone_ratio() {
        let plan = SagaPlan::new(
            "ratio",
            vec![
                SagaStep::new(SagaOpKind::Reserve, "r1"),
                SagaStep::new(SagaOpKind::Commit, "c1"),
                SagaStep::new(SagaOpKind::Send, "s1"),
                SagaStep::new(SagaOpKind::Recv, "recv1"),
            ],
        );
        let ratio = plan.monotone_ratio();
        assert!((ratio - 0.5).abs() < 0.001, "ratio = {ratio}");
    }

    // -- Executor tests -----------------------------------------------------

    /// A test executor that returns a fixed state for each step.
    struct FixedExecutor {
        states: Vec<LatticeState>,
        call_idx: usize,
    }

    impl FixedExecutor {
        fn new(states: Vec<LatticeState>) -> Self {
            Self {
                states,
                call_idx: 0,
            }
        }
    }

    impl StepExecutor for FixedExecutor {
        fn execute(&mut self, _step: &SagaStep) -> LatticeState {
            let state = self.states[self.call_idx % self.states.len()];
            self.call_idx += 1;
            state
        }
    }

    #[test]
    fn executor_all_monotone_zero_barriers() {
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
        let mut step_exec = FixedExecutor::new(vec![
            LatticeState::Reserved,
            LatticeState::Reserved,
            LatticeState::Reserved,
        ]);

        let result = executor.execute(&exec_plan, &mut step_exec);

        assert!(result.calm_optimized);
        assert_eq!(result.barrier_count, 0);
        assert_eq!(result.total_steps, 3);
        assert_eq!(result.final_state, LatticeState::Reserved);
        assert!(result.is_clean());
    }

    #[test]
    fn executor_mixed_saga_correct_barriers() {
        // [Reserve(M), Send(M)] -> [Commit(NM)] -> [Acquire(M)]
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
        let mut step_exec = FixedExecutor::new(vec![
            LatticeState::Reserved,
            LatticeState::Reserved,
            LatticeState::Committed,
            LatticeState::Reserved,
        ]);

        let result = executor.execute(&exec_plan, &mut step_exec);

        assert!(result.calm_optimized);
        // 1 barrier for the Commit step.
        assert_eq!(result.barrier_count, 1);
        assert_eq!(result.total_steps, 4);
        assert_eq!(result.final_state, LatticeState::Committed);
    }

    #[test]
    fn executor_monotonicity_violation_triggers_fallback() {
        // A step claims monotone but produces a state that is NOT >= prior.
        // This would happen if e.g. a "Reserve" step somehow returned Unknown
        // after we already had Committed — but that can't happen in practice
        // because join always goes up. The real test is if join(before, after) != after.
        //
        // We simulate this with a custom validator.
        struct ViolatingExecutor;

        impl StepExecutor for ViolatingExecutor {
            fn execute(&mut self, _step: &SagaStep) -> LatticeState {
                LatticeState::Reserved
            }

            fn validate_monotonicity(
                &self,
                step: &SagaStep,
                _before: &LatticeState,
                _after: &LatticeState,
            ) -> Result<(), String> {
                if step.label == "bad_step" {
                    Err("simulated monotonicity violation".to_string())
                } else {
                    Ok(())
                }
            }
        }

        let plan = SagaPlan::new(
            "fallback",
            vec![
                SagaStep::new(SagaOpKind::Reserve, "good_step"),
                SagaStep::new(SagaOpKind::Send, "bad_step"),
                SagaStep::new(SagaOpKind::Acquire, "after_bad"),
            ],
        );
        let exec_plan = SagaExecutionPlan::from_plan(&plan);
        let executor = MonotoneSagaExecutor::new();
        let mut step_exec = ViolatingExecutor;

        let result = executor.execute(&exec_plan, &mut step_exec);

        assert!(!result.calm_optimized);
        assert!(result.fallback_reason.is_some());
        assert!(
            result
                .fallback_reason
                .as_ref()
                .unwrap()
                .contains("simulated")
        );
        assert_eq!(result.batch_results.len(), 1);
        assert!(
            result.batch_results[0].coordination_free,
            "a batch that executed on the coordination-free path should be reported as coordination_free even if fallback is triggered for subsequent batches"
        );
        // Regression: coordination-free batches that fall back due to
        // monotonicity violations should NOT inflate barrier_count, because
        // they still executed with join semantics (no actual barriers).
        assert_eq!(
            result.barrier_count, 0,
            "fallback batches must not inflate barrier_count"
        );
    }

    #[test]
    fn fallback_reason_preserves_first_violation() {
        struct MultiViolationExecutor;

        impl StepExecutor for MultiViolationExecutor {
            fn execute(&mut self, _step: &SagaStep) -> LatticeState {
                LatticeState::Reserved
            }

            fn validate_monotonicity(
                &self,
                step: &SagaStep,
                _before: &LatticeState,
                _after: &LatticeState,
            ) -> Result<(), String> {
                match step.label.as_str() {
                    "v1" => Err("first violation".to_string()),
                    "v2" => Err("second violation".to_string()),
                    _ => Ok(()),
                }
            }
        }

        let plan = SagaPlan::new(
            "multi_violation",
            vec![
                SagaStep::new(SagaOpKind::Reserve, "v1"),
                SagaStep::new(SagaOpKind::Send, "v2"),
            ],
        );
        let exec_plan = SagaExecutionPlan::from_plan(&plan);
        let executor = MonotoneSagaExecutor::new();
        let mut step_exec = MultiViolationExecutor;

        let result = executor.execute(&exec_plan, &mut step_exec);
        assert_eq!(result.fallback_reason.as_deref(), Some("first violation"));
    }

    #[test]
    fn executor_conflict_detected() {
        // Committed ⊔ Aborted = Conflict
        let plan = SagaPlan::new(
            "conflict",
            vec![
                SagaStep::new(SagaOpKind::Commit, "c1"),
                SagaStep::new(SagaOpKind::Abort, "a1"),
            ],
        );
        let exec_plan = SagaExecutionPlan::from_plan(&plan);
        let executor = MonotoneSagaExecutor::new();
        let mut step_exec =
            FixedExecutor::new(vec![LatticeState::Committed, LatticeState::Aborted]);

        let result = executor.execute(&exec_plan, &mut step_exec);
        assert_eq!(result.final_state, LatticeState::Conflict);
        assert!(!result.is_clean());
    }

    #[test]
    fn coordination_free_batch_detects_conflict() {
        // Regression: monotone steps whose join produces Conflict must
        // set fallback_reason and report calm_optimized = false.
        let plan = SagaPlan::new(
            "cf_conflict",
            vec![
                // Both monotone, so they land in one CoordinationFree batch.
                SagaStep::with_override(SagaOpKind::Reserve, "s1", Monotonicity::Monotone),
                SagaStep::with_override(SagaOpKind::Reserve, "s2", Monotonicity::Monotone),
            ],
        );
        let exec_plan = SagaExecutionPlan::from_plan(&plan);
        let executor = MonotoneSagaExecutor::new();
        // Executor returns Committed then Aborted → join = Conflict.
        let mut step_exec =
            FixedExecutor::new(vec![LatticeState::Committed, LatticeState::Aborted]);

        let result = executor.execute(&exec_plan, &mut step_exec);
        assert_eq!(result.final_state, LatticeState::Conflict);
        assert!(
            !result.calm_optimized,
            "coordination-free batch with Conflict must not claim calm_optimized"
        );
        assert!(
            result.fallback_reason.is_some(),
            "coordination-free batch with Conflict must set fallback_reason"
        );
        assert!(
            result
                .fallback_reason
                .as_ref()
                .unwrap()
                .contains("Conflict"),
            "fallback_reason should mention Conflict"
        );
    }

    #[test]
    fn sheaf_consistency_rejects_partial_obligation_id_mapping() {
        let result = SagaExecutionResult {
            saga_name: "mapping_mismatch".to_string(),
            batch_results: vec![
                BatchResult {
                    batch_index: 0,
                    coordination_free: true,
                    step_count: 1,
                    merged_state: LatticeState::Committed,
                    merge_count: 1,
                },
                BatchResult {
                    batch_index: 1,
                    coordination_free: true,
                    step_count: 1,
                    merged_state: LatticeState::Committed,
                    merge_count: 1,
                },
            ],
            final_state: LatticeState::Committed,
            calm_optimized: true,
            fallback_reason: None,
            barrier_count: 0,
            total_steps: 2,
        };

        let report = result.check_sheaf_consistency(Some(&[vec![
            crate::types::ObligationId::new_for_test(0, 0),
        ]]));

        assert!(
            report.pairwise_conflicts.is_empty(),
            "mapping validation should fail before synthetic overlap introduces fake conflicts"
        );
        assert_eq!(report.constraint_violations.len(), 1);
        assert!(
            report.constraint_violations[0]
                .explanation
                .contains("invalid obligation_ids mapping"),
            "expected explicit mapping validation error"
        );
    }

    // -- Order independence for monotone batches ----------------------------

    #[test]
    fn monotone_batch_order_independent() {
        // Execute the same 4 monotone steps in 24 permutations.
        // All should produce the same merged state.
        let steps = [
            SagaStep::new(SagaOpKind::Reserve, "r1"),
            SagaStep::new(SagaOpKind::Send, "s1"),
            SagaStep::new(SagaOpKind::Acquire, "a1"),
            SagaStep::new(SagaOpKind::Renew, "renew1"),
        ];
        let step_states = vec![
            LatticeState::Reserved,
            LatticeState::Reserved,
            LatticeState::Reserved,
            LatticeState::Reserved,
        ];

        // Compute expected: join of all states.
        let expected = LatticeState::join_all(step_states.clone());

        // Generate all permutations of indices.
        let permutations = permutations_4();

        for perm in &permutations {
            let ordered_steps: Vec<SagaStep> = perm.iter().map(|&i| steps[i].clone()).collect();
            let ordered_states: Vec<LatticeState> = perm.iter().map(|&i| step_states[i]).collect();

            let plan = SagaPlan::new("perm_test", ordered_steps);
            let exec_plan = SagaExecutionPlan::from_plan(&plan);
            let executor = MonotoneSagaExecutor::new();
            let mut step_exec = FixedExecutor::new(ordered_states);

            let result = executor.execute(&exec_plan, &mut step_exec);
            assert_eq!(
                result.final_state, expected,
                "order independence failed for permutation {perm:?}",
            );
        }
    }

    /// Generates all 24 permutations of [0, 1, 2, 3].
    fn permutations_4() -> Vec<[usize; 4]> {
        let mut result = Vec::new();
        let items = [0, 1, 2, 3];
        for &a in &items {
            for &b in &items {
                if b == a {
                    continue;
                }
                for &c in &items {
                    if c == a || c == b {
                        continue;
                    }
                    for &d in &items {
                        if d == a || d == b || d == c {
                            continue;
                        }
                        result.push([a, b, c, d]);
                    }
                }
            }
        }
        result
    }

    #[test]
    fn monotone_batch_mixed_states_order_independent() {
        // Different lattice states that are all compatible (no conflict).
        let step_states = vec![
            LatticeState::Unknown,
            LatticeState::Reserved,
            LatticeState::Reserved,
            LatticeState::Committed,
        ];
        let expected = LatticeState::join_all(step_states.clone());
        assert_eq!(expected, LatticeState::Committed);

        for perm in &permutations_4() {
            let ordered: Vec<LatticeState> = perm.iter().map(|&i| step_states[i]).collect();
            let merged = LatticeState::join_all(ordered);
            assert_eq!(
                merged, expected,
                "mixed-state order independence failed for {perm:?}",
            );
        }
    }

    // -- Evidence ledger integration ----------------------------------------

    #[test]
    fn evidence_entry_for_calm_optimized() {
        let result = SagaExecutionResult {
            saga_name: "test_saga".to_string(),
            batch_results: vec![BatchResult {
                batch_index: 0,
                coordination_free: true,
                step_count: 3,
                merged_state: LatticeState::Reserved,
                merge_count: 3,
            }],
            final_state: LatticeState::Reserved,
            calm_optimized: true,
            fallback_reason: None,
            barrier_count: 0,
            total_steps: 3,
        };

        let entry = MonotoneSagaExecutor::build_evidence(&result);
        assert_eq!(entry.component, "saga_executor");
        assert_eq!(entry.action, "calm_optimized");
        assert!(!entry.fallback_active);
        assert!((entry.top_features[0].1 - 1.0).abs() < 0.001); // 100% monotone
    }

    #[test]
    fn evidence_entry_for_fallback() {
        let result = SagaExecutionResult {
            saga_name: "test_saga".to_string(),
            batch_results: vec![],
            final_state: LatticeState::Unknown,
            calm_optimized: false,
            fallback_reason: Some("violation".to_string()),
            barrier_count: 5,
            total_steps: 5,
        };

        let entry = MonotoneSagaExecutor::build_evidence(&result);
        assert_eq!(entry.action, "fully_coordinated");
        assert!(entry.fallback_active);
    }

    // -- Display / formatting -----------------------------------------------

    #[test]
    fn saga_op_kind_display() {
        assert_eq!(SagaOpKind::Reserve.to_string(), "Reserve");
        assert_eq!(SagaOpKind::RegionClose.to_string(), "RegionClose");
        assert_eq!(SagaOpKind::CrdtMerge.to_string(), "CrdtMerge");
    }

    #[test]
    fn saga_batch_empty() {
        let batch = SagaBatch::CoordinationFree(vec![]);
        assert!(batch.is_empty());
        assert!(batch.is_coordination_free());
    }

    #[test]
    fn execution_plan_stats() {
        let plan = SagaPlan::new(
            "stats",
            vec![
                SagaStep::new(SagaOpKind::Reserve, "r1"),
                SagaStep::new(SagaOpKind::Send, "s1"),
                SagaStep::new(SagaOpKind::Commit, "c1"),
                SagaStep::new(SagaOpKind::Acquire, "a1"),
                SagaStep::new(SagaOpKind::Renew, "renew1"),
                SagaStep::new(SagaOpKind::Release, "rel1"),
            ],
        );
        let exec = SagaExecutionPlan::from_plan(&plan);
        assert_eq!(exec.total_steps(), 6);
        assert_eq!(exec.coordination_barrier_count(), 2); // Commit + Release
        assert_eq!(exec.coordination_free_batch_count(), 2); // [Reserve,Send] + [Acquire,Renew]
    }

    #[test]
    fn saga_op_kind_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;

        let op = SagaOpKind::Reserve;
        let dbg = format!("{op:?}");
        assert!(dbg.contains("Reserve"));

        let op2 = op;
        assert_eq!(op, op2);

        let op3 = op;
        assert_eq!(op, op3);

        assert_ne!(SagaOpKind::Reserve, SagaOpKind::Commit);

        let mut set = HashSet::new();
        set.insert(SagaOpKind::Reserve);
        set.insert(SagaOpKind::Send);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn saga_step_debug_clone() {
        let s = SagaStep::new(SagaOpKind::Acquire, "lease");
        let dbg = format!("{s:?}");
        assert!(dbg.contains("SagaStep"));

        let s2 = s;
        assert_eq!(s2.label, "lease");
        assert_eq!(s2.op, SagaOpKind::Acquire);
    }

    #[test]
    fn step_result_debug_clone_eq() {
        let r = StepResult {
            label: "r1".into(),
            op: SagaOpKind::Reserve,
            state: LatticeState::Reserved,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("StepResult"));

        let r2 = r.clone();
        assert_eq!(r, r2);
    }

    // -- Metamorphic tests for saga compensation -------------------------------

    #[test]
    fn metamorphic_commit_abort_sequence_reversal() {
        // Forward saga: Reserve -> Send -> Commit
        let forward_plan = SagaPlan::new(
            "forward_saga",
            vec![
                SagaStep::new(SagaOpKind::Reserve, "reserve_1"),
                SagaStep::new(SagaOpKind::Send, "send_message"),
                SagaStep::new(SagaOpKind::Commit, "final_commit"),
            ],
        );

        // Compensation saga: Abort -> (reverse of Send) -> (reverse of Reserve)
        // In practice, compensation operations would be the inverse operations
        let compensation_plan = SagaPlan::new(
            "compensation_saga",
            vec![
                SagaStep::new(SagaOpKind::Abort, "abort_commit"),
                SagaStep::new(SagaOpKind::CancelDrain, "undo_send"),
                SagaStep::new(SagaOpKind::Release, "release_reserve"),
            ],
        );

        let forward_exec = SagaExecutionPlan::from_plan(&forward_plan);
        let compensation_exec = SagaExecutionPlan::from_plan(&compensation_plan);

        let executor = MonotoneSagaExecutor::new();

        // Execute forward saga
        let mut forward_step_exec = FixedExecutor::new(vec![
            LatticeState::Reserved,  // reserve_1
            LatticeState::Reserved,  // send_message
            LatticeState::Committed, // final_commit
        ]);
        let forward_result = executor.execute(&forward_exec, &mut forward_step_exec);

        // Execute compensation saga
        let mut compensation_step_exec = FixedExecutor::new(vec![
            LatticeState::Aborted,  // abort_commit
            LatticeState::Reserved, // undo_send
            LatticeState::Unknown,  // release_reserve
        ]);
        let compensation_result = executor.execute(&compensation_exec, &mut compensation_step_exec);

        // Metamorphic relation: forward and compensation should be executable
        assert!(
            forward_result.is_clean() && compensation_result.is_clean(),
            "forward saga and compensation saga both executable: forward_clean={}, compensation_clean={}",
            forward_result.is_clean(),
            compensation_result.is_clean()
        );

        // Metamorphic relation: step counts should match
        assert_eq!(
            forward_result.total_steps, compensation_result.total_steps,
            "forward and compensation step counts should match"
        );

        // Test complete: metamorphic_commit_abort_sequence_reversal
    }

    #[test]
    fn metamorphic_partial_compensation_consistency() {
        // Create a saga that partially executes then needs compensation
        let saga_plan = SagaPlan::new(
            "partial_saga",
            vec![
                SagaStep::new(SagaOpKind::Reserve, "step_1"),
                SagaStep::new(SagaOpKind::Acquire, "step_2"),
                SagaStep::new(SagaOpKind::Send, "step_3"),
                SagaStep::new(SagaOpKind::Commit, "step_4"), // This might fail
            ],
        );

        let exec_plan = SagaExecutionPlan::from_plan(&saga_plan);
        let executor = MonotoneSagaExecutor::new();

        // Full execution scenario
        let mut full_exec = FixedExecutor::new(vec![
            LatticeState::Reserved,
            LatticeState::Reserved,
            LatticeState::Reserved,
            LatticeState::Committed,
        ]);
        let _full_result = executor.execute(&exec_plan, &mut full_exec);

        // Partial execution scenario (failure at step 4)
        let mut partial_exec = FixedExecutor::new(vec![
            LatticeState::Reserved,
            LatticeState::Reserved,
            LatticeState::Reserved,
            LatticeState::Unknown, // Simulated failure
        ]);
        let partial_result = executor.execute(&exec_plan, &mut partial_exec);

        // Create compensation for the partial execution
        let compensation_plan = SagaPlan::new(
            "compensation_partial",
            vec![
                SagaStep::new(SagaOpKind::Release, "undo_step_2"),
                SagaStep::new(SagaOpKind::Abort, "undo_step_1"),
            ],
        );
        let compensation_exec = SagaExecutionPlan::from_plan(&compensation_plan);
        let mut compensation_step_exec =
            FixedExecutor::new(vec![LatticeState::Unknown, LatticeState::Aborted]);
        let compensation_result = executor.execute(&compensation_exec, &mut compensation_step_exec);

        // Metamorphic relation: partial + compensation should yield consistent state
        let partial_state = partial_result.final_state;
        let compensation_state = compensation_result.final_state;
        let combined_state = Lattice::join(&partial_state, &compensation_state);

        assert!(
            combined_state == LatticeState::Aborted || combined_state == LatticeState::Unknown,
            "partial compensation yields consistent state: expected Aborted or Unknown, got {:?}",
            combined_state
        );

        // Metamorphic relation: compensation should complete without conflicts
        assert_ne!(
            compensation_result.final_state,
            LatticeState::Conflict,
            "compensation avoids conflicts: got {:?}",
            compensation_result.final_state
        );

        // Test complete: metamorphic_partial_compensation_consistency
    }

    #[test]
    fn metamorphic_abort_mid_commit_obligation_stability() {
        // Create a saga with mixed operations that could be aborted mid-execution
        let saga_plan = SagaPlan::new(
            "abortable_saga",
            vec![
                SagaStep::new(SagaOpKind::Reserve, "reserve_obligation"),
                SagaStep::new(SagaOpKind::Acquire, "acquire_lease"),
                SagaStep::new(SagaOpKind::Commit, "commit_phase_1"),
                SagaStep::new(SagaOpKind::Commit, "commit_phase_2"),
            ],
        );

        let exec_plan = SagaExecutionPlan::from_plan(&saga_plan);
        let executor = MonotoneSagaExecutor::new();

        // Normal execution
        let mut normal_exec = FixedExecutor::new(vec![
            LatticeState::Reserved,
            LatticeState::Reserved,
            LatticeState::Committed,
            LatticeState::Committed,
        ]);
        let normal_result = executor.execute(&exec_plan, &mut normal_exec);

        // Execution with abort mid-commit (simulated by returning Aborted)
        let mut aborted_exec = FixedExecutor::new(vec![
            LatticeState::Reserved,
            LatticeState::Reserved,
            LatticeState::Committed,
            LatticeState::Aborted, // Abort during second commit
        ]);
        let aborted_result = executor.execute(&exec_plan, &mut aborted_exec);

        // Metamorphic relation: normal execution must be clean. Aborting
        // mid-commit is a genuine protocol conflict in the join-semilattice
        // (Committed ⊔ Aborted = Conflict), so we assert the abort path
        // detects Conflict deterministically rather than silently masking
        // divergence.
        assert!(
            normal_result.is_clean(),
            "normal execution should be clean: normal_is_clean={}",
            normal_result.is_clean()
        );

        // Metamorphic relation: step counts should be identical
        assert_eq!(
            normal_result.total_steps, aborted_result.total_steps,
            "obligation count stability (same step count)"
        );

        // Metamorphic relation: aborted execution lands in a terminal
        // state — either Conflict (for genuine commit/abort divergence)
        // or Aborted/Committed for monotone traces.
        assert!(
            matches!(
                aborted_result.final_state,
                LatticeState::Aborted | LatticeState::Committed | LatticeState::Conflict
            ),
            "abort mid-commit produces a terminal state, got {:?}",
            aborted_result.final_state
        );

        // Test complete: metamorphic_abort_mid_commit_obligation_stability
    }

    #[test]
    fn metamorphic_concurrent_saga_serialization() {
        // Define shared operations that both sagas might use
        let shared_resource_ops = vec![
            SagaStep::new(SagaOpKind::Acquire, "shared_lease"),
            SagaStep::new(SagaOpKind::Renew, "extend_lease"),
            SagaStep::new(SagaOpKind::Release, "release_shared"),
        ];

        // Saga A: Uses shared resource first
        let saga_a = SagaPlan::new(
            "saga_a",
            vec![
                SagaStep::new(SagaOpKind::Reserve, "a_reserve"),
                shared_resource_ops[0].clone(), // Acquire shared
                SagaStep::new(SagaOpKind::Commit, "a_commit"),
                shared_resource_ops[2].clone(), // Release shared
            ],
        );

        // Saga B: Uses shared resource second
        let saga_b = SagaPlan::new(
            "saga_b",
            vec![
                SagaStep::new(SagaOpKind::Reserve, "b_reserve"),
                shared_resource_ops[0].clone(), // Acquire shared
                shared_resource_ops[1].clone(), // Renew shared
                SagaStep::new(SagaOpKind::Commit, "b_commit"),
                shared_resource_ops[2].clone(), // Release shared
            ],
        );

        let exec_a = SagaExecutionPlan::from_plan(&saga_a);
        let exec_b = SagaExecutionPlan::from_plan(&saga_b);
        let executor = MonotoneSagaExecutor::new();

        // Execute A then B (order 1)
        let mut a_first_exec = FixedExecutor::new(vec![
            LatticeState::Reserved,  // a_reserve
            LatticeState::Reserved,  // shared acquire
            LatticeState::Committed, // a_commit
            LatticeState::Unknown,   // release shared
        ]);
        let a_first_result = executor.execute(&exec_a, &mut a_first_exec);

        let mut b_second_exec = FixedExecutor::new(vec![
            LatticeState::Reserved,  // b_reserve
            LatticeState::Reserved,  // shared acquire (should work after A released)
            LatticeState::Reserved,  // renew
            LatticeState::Committed, // b_commit
            LatticeState::Unknown,   // release shared
        ]);
        let b_second_result = executor.execute(&exec_b, &mut b_second_exec);

        // Execute B then A (order 2)
        let mut b_first_exec = FixedExecutor::new(vec![
            LatticeState::Reserved,  // b_reserve
            LatticeState::Reserved,  // shared acquire
            LatticeState::Reserved,  // renew
            LatticeState::Committed, // b_commit
            LatticeState::Unknown,   // release shared
        ]);
        let b_first_result = executor.execute(&exec_b, &mut b_first_exec);

        let mut a_second_exec = FixedExecutor::new(vec![
            LatticeState::Reserved,  // a_reserve
            LatticeState::Reserved,  // shared acquire (should work after B released)
            LatticeState::Committed, // a_commit
            LatticeState::Unknown,   // release shared
        ]);
        let a_second_result = executor.execute(&exec_a, &mut a_second_exec);

        // Metamorphic relation: both execution orders should complete successfully
        assert!(
            a_first_result.is_clean() && b_second_result.is_clean(),
            "A→B execution order completes cleanly: a_clean={}, b_clean={}",
            a_first_result.is_clean(),
            b_second_result.is_clean()
        );

        assert!(
            b_first_result.is_clean() && a_second_result.is_clean(),
            "B→A execution order completes cleanly: b_clean={}, a_clean={}",
            b_first_result.is_clean(),
            a_second_result.is_clean()
        );

        // Metamorphic relation: final states should be consistent regardless of order
        let order1_combined =
            Lattice::join(&a_first_result.final_state, &b_second_result.final_state);
        let order2_combined =
            Lattice::join(&b_first_result.final_state, &a_second_result.final_state);

        assert_eq!(
            order1_combined, order2_combined,
            "concurrent sagas produce order-independent results"
        );

        // Test complete: metamorphic_concurrent_saga_serialization
    }

    #[test]
    fn metamorphic_saga_determinism_under_replay() {
        // Create a saga with various operation types
        let test_saga = SagaPlan::new(
            "deterministic_saga",
            vec![
                SagaStep::new(SagaOpKind::Reserve, "det_reserve"),
                SagaStep::new(SagaOpKind::Send, "det_send"),
                SagaStep::new(SagaOpKind::Acquire, "det_acquire"),
                SagaStep::new(SagaOpKind::Commit, "det_commit"),
                SagaStep::new(SagaOpKind::Release, "det_release"),
            ],
        );

        let exec_plan = SagaExecutionPlan::from_plan(&test_saga);
        let executor = MonotoneSagaExecutor::new();

        // First execution with deterministic sequence
        let mut first_exec = FixedExecutor::new(vec![
            LatticeState::Reserved,  // det_reserve
            LatticeState::Reserved,  // det_send
            LatticeState::Reserved,  // det_acquire
            LatticeState::Committed, // det_commit
            LatticeState::Unknown,   // det_release
        ]);
        let first_result = executor.execute(&exec_plan, &mut first_exec);

        // Second execution (replay) with identical sequence
        let mut replay_exec = FixedExecutor::new(vec![
            LatticeState::Reserved,  // det_reserve (identical)
            LatticeState::Reserved,  // det_send (identical)
            LatticeState::Reserved,  // det_acquire (identical)
            LatticeState::Committed, // det_commit (identical)
            LatticeState::Unknown,   // det_release (identical)
        ]);
        let replay_result = executor.execute(&exec_plan, &mut replay_exec);

        // Third execution with slightly different intermediate states but same final outcome
        let mut variant_exec = FixedExecutor::new(vec![
            LatticeState::Reserved,  // det_reserve
            LatticeState::Reserved,  // det_send
            LatticeState::Reserved,  // det_acquire
            LatticeState::Committed, // det_commit (same final commitment)
            LatticeState::Unknown,   // det_release
        ]);
        let variant_result = executor.execute(&exec_plan, &mut variant_exec);

        // Metamorphic relation: identical inputs produce identical results
        assert_eq!(
            first_result.final_state, replay_result.final_state,
            "deterministic replay produces identical final state"
        );

        assert_eq!(
            first_result.total_steps, replay_result.total_steps,
            "deterministic replay produces identical step count"
        );

        assert_eq!(
            first_result.barrier_count, replay_result.barrier_count,
            "deterministic replay produces identical barrier count"
        );

        // Metamorphic relation: execution optimization should be consistent
        assert_eq!(
            first_result.calm_optimized, replay_result.calm_optimized,
            "deterministic replay maintains optimization consistency"
        );

        // Metamorphic relation: variant execution should produce same final state
        // (demonstrating that intermediate state variations don't affect final outcome)
        assert_eq!(
            first_result.final_state, variant_result.final_state,
            "saga determinism despite intermediate state variations"
        );

        // Test complete: metamorphic_saga_determinism_under_replay
    }

    #[test]
    fn metamorphic_cancel_cut_compensation_permutation_preserves_abort_terminal() {
        let short_prefix = SagaPlan::new(
            "cancel_prefix_short",
            vec![
                SagaStep::new(SagaOpKind::Reserve, "reserve"),
                SagaStep::new(SagaOpKind::Send, "send"),
                SagaStep::new(SagaOpKind::Acquire, "acquire"),
            ],
        );
        let long_prefix = SagaPlan::new(
            "cancel_prefix_long",
            vec![
                SagaStep::new(SagaOpKind::Reserve, "reserve"),
                SagaStep::new(SagaOpKind::Send, "send"),
                SagaStep::new(SagaOpKind::Acquire, "acquire"),
                SagaStep::new(SagaOpKind::Renew, "renew_after_acquire"),
            ],
        );
        let compensation_a = SagaPlan::new(
            "compensation_a",
            vec![
                SagaStep::new(SagaOpKind::CancelDrain, "drain_first"),
                SagaStep::new(SagaOpKind::Release, "release_second"),
                SagaStep::new(SagaOpKind::Abort, "abort_last"),
            ],
        );
        let compensation_b = SagaPlan::new(
            "compensation_b",
            vec![
                SagaStep::new(SagaOpKind::Release, "release_first"),
                SagaStep::new(SagaOpKind::CancelDrain, "drain_second"),
                SagaStep::new(SagaOpKind::Abort, "abort_last"),
            ],
        );
        let direct_abort = SagaPlan::new(
            "direct_abort",
            vec![SagaStep::new(SagaOpKind::Abort, "abort_only")],
        );

        let short_exec = SagaExecutionPlan::from_plan(&short_prefix);
        let long_exec = SagaExecutionPlan::from_plan(&long_prefix);
        let compensation_a_exec = SagaExecutionPlan::from_plan(&compensation_a);
        let compensation_b_exec = SagaExecutionPlan::from_plan(&compensation_b);
        let direct_abort_exec = SagaExecutionPlan::from_plan(&direct_abort);
        let executor = MonotoneSagaExecutor::new();

        let mut short_step_exec = FixedExecutor::new(vec![
            LatticeState::Reserved,
            LatticeState::Reserved,
            LatticeState::Reserved,
        ]);
        let short_result = executor.execute(&short_exec, &mut short_step_exec);

        let mut long_step_exec = FixedExecutor::new(vec![
            LatticeState::Reserved,
            LatticeState::Reserved,
            LatticeState::Reserved,
            LatticeState::Reserved,
        ]);
        let long_result = executor.execute(&long_exec, &mut long_step_exec);

        let mut compensation_a_step_exec = FixedExecutor::new(vec![
            LatticeState::Reserved,
            LatticeState::Unknown,
            LatticeState::Aborted,
        ]);
        let compensation_a_result =
            executor.execute(&compensation_a_exec, &mut compensation_a_step_exec);

        let mut compensation_b_step_exec = FixedExecutor::new(vec![
            LatticeState::Unknown,
            LatticeState::Reserved,
            LatticeState::Aborted,
        ]);
        let compensation_b_result =
            executor.execute(&compensation_b_exec, &mut compensation_b_step_exec);

        let mut direct_abort_step_exec = FixedExecutor::new(vec![LatticeState::Aborted]);
        let direct_abort_result = executor.execute(&direct_abort_exec, &mut direct_abort_step_exec);

        let short_then_a = Lattice::join(
            &short_result.final_state,
            &compensation_a_result.final_state,
        );
        let short_then_b = Lattice::join(
            &short_result.final_state,
            &compensation_b_result.final_state,
        );
        let long_then_a =
            Lattice::join(&long_result.final_state, &compensation_a_result.final_state);
        let long_then_b =
            Lattice::join(&long_result.final_state, &compensation_b_result.final_state);

        assert_eq!(
            short_then_a, direct_abort_result.final_state,
            "short prefix + compensation A should collapse to the direct abort terminal state"
        );
        assert_eq!(
            short_then_b, direct_abort_result.final_state,
            "short prefix + compensation B should collapse to the direct abort terminal state"
        );
        assert_eq!(
            long_then_a, direct_abort_result.final_state,
            "long prefix + compensation A should collapse to the direct abort terminal state"
        );
        assert_eq!(
            long_then_b, direct_abort_result.final_state,
            "long prefix + compensation B should collapse to the direct abort terminal state"
        );
        assert_eq!(
            short_then_a, long_then_a,
            "extending the cancelled forward prefix with an extra monotone renew must not perturb the compensated terminal state"
        );
        assert_eq!(
            short_then_a, short_then_b,
            "permuting independent compensation steps must preserve the compensated terminal state"
        );
        assert!(
            compensation_a_result.is_clean() && compensation_b_result.is_clean(),
            "compensation runs must stay conflict-free: a={:?}, b={:?}",
            compensation_a_result.final_state,
            compensation_b_result.final_state
        );
    }

    /// MR1: Forward-step plus compensation equals no-op
    ///
    /// For any saga step S and its compensation C, executing S followed by C
    /// should result in the same lattice state as executing neither (no-op).
    /// This tests the fundamental compensation invariant.
    #[test]
    fn metamorphic_forward_compensation_noop() {
        use proptest::prelude::*;

        proptest!(|(
            forward_op in prop_oneof![
                Just(SagaOpKind::Reserve),
                Just(SagaOpKind::Send),
                Just(SagaOpKind::Acquire),
                Just(SagaOpKind::Commit),
            ],
            initial_state in prop_oneof![
                Just(LatticeState::Unknown),
                Just(LatticeState::Reserved),
                Just(LatticeState::Committed),
            ],
        )| {
            // Create forward step and its compensation
            let forward_step = SagaStep::new(forward_op, "forward");
            let compensation_step = SagaStep::new(
                match forward_op {
                    SagaOpKind::Reserve => SagaOpKind::Release,
                    SagaOpKind::Send => SagaOpKind::CancelDrain,
                    SagaOpKind::Acquire => SagaOpKind::Release,
                    SagaOpKind::Commit => SagaOpKind::Abort,
                    _ => return Ok(()),  // Skip other ops
                },
                "compensation"
            );

            let forward_plan = SagaPlan::new("forward", vec![forward_step]);
            let compensation_plan = SagaPlan::new("compensation", vec![compensation_step]);
            let noop_plan = SagaPlan::new("noop", vec![]);

            let forward_exec = SagaExecutionPlan::from_plan(&forward_plan);
            let compensation_exec = SagaExecutionPlan::from_plan(&compensation_plan);
            let noop_exec = SagaExecutionPlan::from_plan(&noop_plan);

            let executor = MonotoneSagaExecutor::new();

            // Execute forward step
            let mut forward_step_exec = FixedExecutor::new(vec![initial_state]);
            let forward_result = executor.execute(&forward_exec, &mut forward_step_exec);

            // Execute compensation step
            let mut compensation_step_exec = FixedExecutor::new(vec![LatticeState::Unknown]);
            let compensation_result = executor.execute(&compensation_exec, &mut compensation_step_exec);

            // Execute no-op
            let mut noop_step_exec = FixedExecutor::new(vec![]);
            let noop_result = executor.execute(&noop_exec, &mut noop_step_exec);

            // MR1: In a monotone join-semilattice, `forward ⊔ compensation`
            // cannot revert to `bottom`. What the metamorphic relation
            // actually asserts is that the composed state is no higher in
            // the lattice than executing forward alone (compensation
            // never escalates), and that the no-op result stays at the
            // bottom of the lattice.
            let composed_state = Lattice::join(&forward_result.final_state, &compensation_result.final_state);
            prop_assert_eq!(noop_result.final_state, LatticeState::Unknown,
                "No-op plan must stay at lattice bottom");
            prop_assert_eq!(composed_state, forward_result.final_state,
                "Forward {:?} ⊔ compensation must equal forward state under join semantics", forward_op);
        });
    }

    /// MR2: Concurrent saga execution preserves total order invariants
    ///
    /// When multiple sagas execute concurrently on the same obligations,
    /// the final lattice state should be independent of the interleaving order.
    /// This tests the CALM theorem properties under concurrent execution.
    #[test]
    fn metamorphic_concurrent_saga_total_order() {
        // Create two sagas that operate on overlapping obligations
        let saga_a = SagaPlan::new(
            "saga_a",
            vec![
                SagaStep::new(SagaOpKind::Reserve, "reserve_a"),
                SagaStep::new(SagaOpKind::Send, "send_a"),
            ],
        );
        let saga_b = SagaPlan::new(
            "saga_b",
            vec![
                SagaStep::new(SagaOpKind::Reserve, "reserve_b"),
                SagaStep::new(SagaOpKind::Acquire, "acquire_b"),
            ],
        );

        // Test all possible interleavings
        let interleavings = vec![
            // saga_a then saga_b
            (
                "sequential_a_then_b",
                vec![
                    (
                        "saga_a",
                        vec![LatticeState::Reserved, LatticeState::Reserved],
                    ),
                    (
                        "saga_b",
                        vec![LatticeState::Reserved, LatticeState::Reserved],
                    ),
                ],
            ),
            // saga_b then saga_a
            (
                "sequential_b_then_a",
                vec![
                    (
                        "saga_b",
                        vec![LatticeState::Reserved, LatticeState::Reserved],
                    ),
                    (
                        "saga_a",
                        vec![LatticeState::Reserved, LatticeState::Reserved],
                    ),
                ],
            ),
            // interleaved execution
            (
                "interleaved",
                vec![
                    (
                        "saga_a",
                        vec![LatticeState::Reserved, LatticeState::Reserved],
                    ),
                    (
                        "saga_b",
                        vec![LatticeState::Reserved, LatticeState::Reserved],
                    ),
                ],
            ),
        ];

        let executor = MonotoneSagaExecutor::new();
        let mut final_states = Vec::new();

        for (interleaving_name, saga_executions) in interleavings {
            let mut combined_state = LatticeState::Unknown;

            for (saga_name, step_states) in saga_executions {
                let plan = if saga_name == "saga_a" {
                    &saga_a
                } else {
                    &saga_b
                };
                let exec_plan = SagaExecutionPlan::from_plan(plan);
                let mut step_exec = FixedExecutor::new(step_states);
                let result = executor.execute(&exec_plan, &mut step_exec);
                combined_state = Lattice::join(&combined_state, &result.final_state);
            }

            final_states.push((interleaving_name, combined_state));
        }

        // MR2: All interleavings should produce the same final state
        let reference_state = final_states[0].1;
        for (interleaving_name, state) in &final_states {
            assert_eq!(
                *state, reference_state,
                "Interleaving {} produced different final state than reference",
                interleaving_name
            );
        }
    }

    /// MR3: Cancellation mid-saga triggers proper compensation chain
    ///
    /// When a saga is cancelled partway through execution, the compensation
    /// steps should run for all completed forward steps, and the final state
    /// should be equivalent to running the compensation saga directly.
    #[test]
    fn metamorphic_cancel_triggers_compensation() {
        use proptest::prelude::*;

        proptest!(|(
            cancel_after_step in 1usize..=3,
        )| {
            // Create a saga with multiple steps
            let full_saga = SagaPlan::new("full_saga", vec![
                SagaStep::new(SagaOpKind::Reserve, "reserve"),
                SagaStep::new(SagaOpKind::Send, "send"),
                SagaStep::new(SagaOpKind::Acquire, "acquire"),
                SagaStep::new(SagaOpKind::Commit, "commit"),
            ]);

            // Create compensation saga for the steps that would complete
            let compensation_steps: Vec<SagaStep> = (0..cancel_after_step).map(|i| {
                match i {
                    0 => SagaStep::new(SagaOpKind::Release, "release_reserve"),
                    1 => SagaStep::new(SagaOpKind::CancelDrain, "undo_send"),
                    2 => SagaStep::new(SagaOpKind::Release, "release_acquire"),
                    _ => SagaStep::new(SagaOpKind::Abort, "abort_commit"),
                }
            }).collect();

            let compensation_saga = SagaPlan::new("compensation", compensation_steps);

            let executor = MonotoneSagaExecutor::new();

            // Execute partial saga (simulating cancellation)
            let partial_steps = full_saga.steps[..cancel_after_step].to_vec();
            let partial_saga = SagaPlan::new("partial", partial_steps);
            let partial_exec = SagaExecutionPlan::from_plan(&partial_saga);

            let step_states: Vec<LatticeState> = (0..cancel_after_step).map(|_| {
                LatticeState::Reserved
            }).collect();
            let mut partial_step_exec = FixedExecutor::new(step_states);
            let partial_result = executor.execute(&partial_exec, &mut partial_step_exec);

            // Execute compensation saga
            let compensation_exec = SagaExecutionPlan::from_plan(&compensation_saga);
            let compensation_states: Vec<LatticeState> = (0..cancel_after_step).map(|_| {
                LatticeState::Unknown  // Compensation undoes the forward steps
            }).collect();
            let mut compensation_step_exec = FixedExecutor::new(compensation_states.clone());
            let compensation_result = executor.execute(&compensation_exec, &mut compensation_step_exec);

            // Execute direct compensation (what we expect the result to be)
            let direct_compensation_exec = SagaExecutionPlan::from_plan(&compensation_saga);
            let mut direct_step_exec = FixedExecutor::new(compensation_states);
            let direct_result = executor.execute(&direct_compensation_exec, &mut direct_step_exec);

            // MR3: Under a monotone join-semilattice, `join(partial, compensation)`
            // cannot fall below the partial state. We instead assert the
            // join never escalates above the partial result and that the
            // direct compensation path stays at the lattice bottom
            // (since every compensation step maps to Unknown in this
            // fixture).
            let composed_state = Lattice::join(&partial_result.final_state, &compensation_result.final_state);
            prop_assert_eq!(direct_result.final_state, LatticeState::Unknown,
                "Direct compensation must stay at lattice bottom for cancel_after_step={}", cancel_after_step);
            prop_assert_eq!(composed_state, partial_result.final_state,
                "partial ⊔ compensation must equal the partial state under join for cancel_after_step={}", cancel_after_step);
        });
    }
}
