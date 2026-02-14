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
                    if !result.coordination_free {
                        barrier_count += result.step_count;
                    }
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

            // Post-hoc monotonicity validation.
            if self.validate_monotonicity {
                if let Err(reason) = executor.validate_monotonicity(step, &before, state) {
                    *fallback_reason = Some(reason);
                    // Continue executing remaining steps sequentially
                    // (already past the violation point).
                }
            }
        }

        BatchResult {
            batch_index: batch_idx,
            coordination_free: fallback_reason.is_none(),
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
            assert_eq!(Lattice::join(&a, &a), a, "idempotence failed for {a}",);
        }
    }

    #[test]
    fn lattice_state_identity() {
        use LatticeState::*;
        let bottom = LatticeState::bottom();
        assert_eq!(bottom, Unknown);
        for &a in &[Unknown, Reserved, Committed, Aborted, Conflict] {
            assert_eq!(Lattice::join(&bottom, &a), a, "identity failed for {a}",);
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
        assert!(result
            .fallback_reason
            .as_ref()
            .unwrap()
            .contains("simulated"));
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
}
