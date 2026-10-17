//! Polynomial Functor Composition Laws for Phase 0 Combinators.
//!
//! This module serves as the formal **law sheet** for asupersync's combinator
//! algebra, documenting every algebraic law that Phase 0 commits to preserving.
//! Future phases (polynomial functor rewrites, streaming pipelines, distributed
//! scheduling) must not violate these laws.
//!
//! # Categorical Perspective
//!
//! Asupersync's combinators can be viewed through polynomial functors where:
//! - **Objects** are outcome-producing computations `F : 1 → Outcome<T,E>`
//! - **Join** is a product-like operation (wait for all, take worst severity)
//! - **Race** is a coproduct-like operation (take first, cancel rest)
//! - **Timeout** is a deadline comonad (tighten time budget, collapse nested)
//! - **Pipeline** is Kleisli composition (sequence stages, short-circuit errors)
//! - **Quorum** interpolates between join and race (M-of-N)
//!
//! The severity lattice `Ok < Err < Cancelled < Panicked` forms a bounded
//! join-semilattice under `join_outcomes`. Budget combination forms a
//! commutative monoid with `INFINITE` as identity.
//!
//! # Law Classification
//!
//! Each law is classified as:
//!
//! - **Unconditional**: Holds for all inputs, regardless of scheduling policy,
//!   timing, or runtime configuration. These are structural guarantees.
//!
//! - **Conditional on Policy**: Holds only when certain runtime policies are
//!   active (e.g., short-circuit vs continue-on-error, winner selection).
//!
//! - **Conditional on Timing**: Holds only given specific timing relationships
//!   between operations (e.g., hedge degenerates depend on whether primary
//!   beats the deadline).
//!
//! # Law Sheet
//!
//! ## Severity Lattice (Unconditional)
//!
//! | Law | Statement | Classification |
//! |-----|-----------|----------------|
//! | SEV-ORDER | `Ok < Err < Cancelled < Panicked` | Unconditional |
//! | SEV-BOUNDED | `∀ o: Ok ≤ severity(o) ≤ Panicked` | Unconditional |
//!
//! ## Join Laws (Unconditional)
//!
//! | Law | Statement | Classification |
//! |-----|-----------|----------------|
//! | JOIN-COMM | `severity(join(a,b)) = severity(join(b,a))` | Unconditional |
//! | JOIN-ASSOC | `severity(join(join(a,b),c)) = severity(join(a,join(b,c)))` | Unconditional |
//! | JOIN-IDEM | `severity(join(a,a)) = severity(a)` | Unconditional |
//! | JOIN-UNIT | `severity(join(Ok,a)) = severity(a)` | Unconditional |
//! | JOIN-ABSORB | `severity(join(Panicked,a)) = Panicked` | Unconditional |
//! | JOIN-WORST | `severity(join(a,b)) ≥ max(severity(a), severity(b))` | Unconditional |
//! | JOIN-ALL-WORST | `severity(join_all(os)) = max(severity(o) for o in os)` | Unconditional |
//!
//! ## Race Laws (Unconditional at severity level)
//!
//! | Law | Statement | Classification |
//! |-----|-----------|----------------|
//! | RACE-COMM | Swapping inputs + flipping winner preserves severity | Unconditional |
//! | RACE-NEVER | `race(f, never) ≃ f` (never = always-cancelled loser) | Unconditional |
//! | RACE-DRAIN | Losers are always cancelled and awaited | Unconditional (invariant) |
//!
//! ## Race–Join Interaction (Conditional)
//!
//! | Law | Statement | Classification |
//! |-----|-----------|----------------|
//! | RACE-JOIN-DIST | `race(join(a,b), join(a,c)) ≃ join(a, race(b,c))` | Conditional on severity only |
//!
//! This distributivity law holds at the severity level but NOT at the value
//! level, because the concrete winner in a race depends on scheduling order.
//!
//! ## Timeout Laws (Unconditional)
//!
//! | Law | Statement | Classification |
//! |-----|-----------|----------------|
//! | TIMEOUT-MIN | `timeout(d1, timeout(d2, f)) ≃ timeout(min(d1,d2), f)` | Unconditional |
//! | TIMEOUT-IDENTITY | `timeout(∞, f) ≃ f` (None deadline = identity) | Unconditional |
//! | TIMEOUT-COMM | `effective(a, Some(b)) = effective(b, Some(a))` | Unconditional |
//! | TIMEOUT-TIGHTEN | `effective(a, Some(b)) ≤ a` | Unconditional |
//!
//! ## Budget Semiring (Unconditional)
//!
//! | Law | Statement | Classification |
//! |-----|-----------|----------------|
//! | BUDGET-ASSOC | `(a ⊕ b) ⊕ c = a ⊕ (b ⊕ c)` | Unconditional |
//! | BUDGET-COMM | `a ⊕ b = b ⊕ a` | Unconditional |
//! | BUDGET-UNIT | `a ⊕ INFINITE = a` (deadline, quotas) | Unconditional |
//! | BUDGET-ABSORB | `a ⊕ ZERO → 0` (quotas only, absorbing element) | Unconditional |
//! | BUDGET-DEADLINE-MIN | Combined deadline = min of inputs | Unconditional |
//! | BUDGET-QUOTA-MIN | Combined poll/cost quota = min of inputs | Unconditional |
//! | BUDGET-PRIORITY-MAX | Combined priority = max of inputs | Unconditional |
//!
//! ## Cancel Strengthen (Unconditional)
//!
//! | Law | Statement | Classification |
//! |-----|-----------|----------------|
//! | CANCEL-IDEM | `a.strengthen(a)` is no-op | Unconditional |
//! | CANCEL-ASSOC | `strengthen(strengthen(a,b),c) = strengthen(a,strengthen(b,c))` | Unconditional |
//! | CANCEL-MONOTONE | `severity(a.strengthen(b)) ≥ severity(a)` | Unconditional |
//! | CANCEL-MAX | `a.strengthen(b).kind = max(a.kind, b.kind)` by PartialOrd | Unconditional |
//!
//! ## Quorum Degeneracies (Unconditional by construction)
//!
//! | Law | Statement | Classification |
//! |-----|-----------|----------------|
//! | QUORUM-JOIN | `quorum(N, N, [f1..fN]) ≃ join_all([f1..fN])` | Unconditional |
//! | QUORUM-RACE | `quorum(1, N, [f1..fN]) ≃ race_all([f1..fN])` in success semantics | Unconditional |
//! | QUORUM-ZERO | `quorum(0, N, [..]) → Ok([])` immediately | Unconditional |
//!
//! ## Hedge Degeneracies (Conditional on Timing)
//!
//! | Law | Statement | Classification |
//! |-----|-----------|----------------|
//! | HEDGE-FAST | If primary completes before deadline: `hedge ≃ primary` | Conditional on timing |
//! | HEDGE-SLOW | If primary exceeds deadline: `hedge ≃ race(primary, backup)` | Conditional on timing |
//! | HEDGE-DRAIN | Loser is always cancelled and drained | Unconditional (invariant) |
//!
//! ## Pipeline Laws (Conditional on Error Policy)
//!
//! | Law | Statement | Classification |
//! |-----|-----------|----------------|
//! | PIPELINE-SEQ | Stages execute sequentially: output(N) = input(N+1) | Unconditional |
//! | PIPELINE-SHORT | First non-Ok stage terminates pipeline | Conditional on `continue_on_error = false` |
//! | PIPELINE-ASSOC | `pipeline(a, pipeline(b, c)) ≃ pipeline(pipeline(a, b), c)` | Conditional on error policy |
//!
//! ## First-Ok Laws
//!
//! | Law | Statement | Classification |
//! |-----|-----------|----------------|
//! | FIRST-OK-FOUND | First Ok result wins, remaining stages skipped | Unconditional |
//! | FIRST-OK-ALL-FAIL | All non-Ok → worst severity returned | Unconditional |
//!
//! ## Structural Invariants (Unconditional)
//!
//! | Invariant | Statement |
//! |-----------|-----------|
//! | NO-ABANDON | Child tasks are never left dangling |
//! | LOSER-DRAIN | In race/timeout/hedge/quorum, losers are cancelled AND awaited |
//! | REGION-QUIESCENCE | All children complete before parent region closes |
//! | CANCEL-PROPAGATION | Parent cancellation propagates to all descendants |
//!
//! # Preservation Constraints for Future Phases
//!
//! When implementing polynomial functor rewrites or distributed scheduling:
//!
//! 1. **Do not break severity-level commutativity/associativity of join.**
//!    These are the core lattice laws.
//!
//! 2. **Do not break timeout-min composition.**
//!    Nested timeout collapsing is relied on for deadline inheritance.
//!
//! 3. **Do not break the loser-drain invariant.**
//!    Resource safety depends on it.
//!
//! 4. **Race-join distributivity is severity-only.**
//!    Do not assume value-level distributivity.
//!
//! 5. **Quorum degeneracies must hold by construction.**
//!    quorum(N,N) = join and quorum(1,N) ≃ race are definitional.

#[cfg(test)]
use crate::types::Severity;
#[cfg(test)]
use crate::types::policy::AggregateDecision;

/// Every committed algebraic law, identified by name.
///
/// This enum serves as a machine-readable catalog of the law sheet.
/// Each variant maps to a row in the law table above.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Law {
    // --- Severity Lattice ---
    /// `Ok < Err < Cancelled < Panicked` total order.
    SeverityOrder,
    /// All outcomes have severity in `[Ok, Panicked]`.
    SeverityBounded,

    // --- Join ---
    /// `severity(join(a,b)) = severity(join(b,a))`.
    JoinCommutativity,
    /// `severity(join(join(a,b),c)) = severity(join(a,join(b,c)))`.
    JoinAssociativity,
    /// `severity(join(a,a)) = severity(a)`.
    JoinIdempotency,
    /// `severity(join(Ok,a)) = severity(a)` — Ok is identity.
    JoinUnit,
    /// `severity(join(Panicked,a)) = Panicked` — absorbing element.
    JoinAbsorb,
    /// `severity(join(a,b)) >= max(severity(a), severity(b))`.
    JoinWorst,
    /// `severity(join_all(os)) = max over os`.
    JoinAllWorst,

    // --- Race ---
    /// Swapping inputs + flipping winner preserves severity.
    RaceCommutativity,
    /// `race(f, never) ≃ f` where never is `Cancelled(RaceLost)`.
    RaceNeverIdentity,
    /// Losers always cancelled and awaited (structural invariant).
    RaceDrain,

    // --- Race-Join Interaction ---
    /// `race(join(a,b), join(a,c)) ≃ join(a, race(b,c))` at severity level.
    RaceJoinDistributivity,

    // --- Timeout ---
    /// `timeout(d1, timeout(d2, f)) ≃ timeout(min(d1,d2), f)`.
    TimeoutMin,
    /// `timeout(None, f) ≃ f` — no deadline is identity.
    TimeoutIdentity,
    /// `effective(a, Some(b)) = effective(b, Some(a))`.
    TimeoutCommutativity,
    /// `effective(a, Some(b)) <= a`.
    TimeoutTighten,

    // --- Budget ---
    /// `(a ⊕ b) ⊕ c = a ⊕ (b ⊕ c)`.
    BudgetAssociativity,
    /// `a ⊕ b = b ⊕ a`.
    BudgetCommutativity,
    /// `a ⊕ INFINITE = a` for deadline and quotas.
    BudgetUnit,
    /// `a ⊕ ZERO → 0` for quotas (absorbing element).
    BudgetAbsorb,
    /// Combined deadline = min of inputs.
    BudgetDeadlineMin,
    /// Combined poll/cost quota = min of inputs.
    BudgetQuotaMin,
    /// Combined priority = max of inputs.
    BudgetPriorityMax,

    // --- Cancel ---
    /// `a.strengthen(a)` is a no-op.
    CancelIdempotency,
    /// `strengthen(strengthen(a,b),c) = strengthen(a,strengthen(b,c))`.
    CancelAssociativity,
    /// `severity(a.strengthen(b)) >= severity(a)`.
    CancelMonotonicity,
    /// `a.strengthen(b).kind = max(a.kind, b.kind)` by `PartialOrd`.
    CancelMax,

    // --- Quorum ---
    /// `quorum(N,N,[f1..fN]) ≃ join_all([f1..fN])`.
    QuorumJoinDegeneracy,
    /// `quorum(1,N,[f1..fN]) ≃ race_all` — first Ok wins.
    QuorumRaceDegeneracy,
    /// `quorum(0,N,[..]) → Ok([])` immediately.
    QuorumZero,

    // --- Hedge ---
    /// If primary beats deadline: `hedge ≃ primary`.
    HedgeFast,
    /// If primary exceeds deadline: `hedge ≃ race(primary, backup)`.
    HedgeSlow,
    /// Hedge loser is always cancelled and drained.
    HedgeDrain,

    // --- Pipeline ---
    /// `output(stage N) = input(stage N+1)`.
    PipelineSequential,
    /// First non-Ok terminates pipeline (when `continue_on_error=false`).
    PipelineShortCircuit,
    /// `pipeline(a, pipeline(b,c)) ≃ pipeline(pipeline(a,b), c)` under short-circuit.
    PipelineAssociativity,

    // --- First-Ok ---
    /// First Ok result wins; remaining stages skipped.
    FirstOkFound,
    /// All non-Ok → worst severity returned.
    FirstOkAllFail,
}

/// Classification of whether a law holds unconditionally or requires
/// specific runtime conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LawClassification {
    /// Holds for all inputs, all policies, all scheduling orders.
    Unconditional,
    /// Holds only at the severity level, not at the value level.
    SeverityLevelOnly,
    /// Holds only when a specific error/scheduling policy is active.
    ConditionalOnPolicy,
    /// Holds only when specific timing relationships between operations hold.
    ConditionalOnTiming,
}

/// A single entry in the law sheet: name, classification, and description.
#[derive(Debug, Clone)]
pub struct LawEntry {
    /// The law identifier.
    pub law: Law,
    /// How broadly the law applies.
    pub classification: LawClassification,
    /// Human-readable statement of the law.
    pub statement: &'static str,
}

/// The complete law sheet for Phase 0 combinators.
///
/// Call [`law_sheet()`] to obtain the full catalog.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn law_sheet() -> Vec<LawEntry> {
    vec![
        // Severity Lattice
        LawEntry {
            law: Law::SeverityOrder,
            classification: LawClassification::Unconditional,
            statement: "Ok < Err < Cancelled < Panicked",
        },
        LawEntry {
            law: Law::SeverityBounded,
            classification: LawClassification::Unconditional,
            statement: "For all outcomes o: Ok <= severity(o) <= Panicked",
        },
        // Join
        LawEntry {
            law: Law::JoinCommutativity,
            classification: LawClassification::Unconditional,
            statement: "severity(join(a,b)) = severity(join(b,a))",
        },
        LawEntry {
            law: Law::JoinAssociativity,
            classification: LawClassification::Unconditional,
            statement: "severity(join(join(a,b),c)) = severity(join(a,join(b,c)))",
        },
        LawEntry {
            law: Law::JoinIdempotency,
            classification: LawClassification::Unconditional,
            statement: "severity(join(a,a)) = severity(a)",
        },
        LawEntry {
            law: Law::JoinUnit,
            classification: LawClassification::Unconditional,
            statement: "severity(join(Ok,a)) = severity(a) — Ok is the identity",
        },
        LawEntry {
            law: Law::JoinAbsorb,
            classification: LawClassification::Unconditional,
            statement: "severity(join(Panicked,a)) = Panicked — Panicked is absorbing",
        },
        LawEntry {
            law: Law::JoinWorst,
            classification: LawClassification::Unconditional,
            statement: "severity(join(a,b)) >= max(severity(a), severity(b))",
        },
        LawEntry {
            law: Law::JoinAllWorst,
            classification: LawClassification::Unconditional,
            statement: "severity(join_all(os)) = max(severity(o) for o in os)",
        },
        // Race
        LawEntry {
            law: Law::RaceCommutativity,
            classification: LawClassification::Unconditional,
            statement: "Swapping inputs + flipping winner preserves severity",
        },
        LawEntry {
            law: Law::RaceNeverIdentity,
            classification: LawClassification::Unconditional,
            statement: "race(f, never) ~= f where never always loses with RaceLost",
        },
        LawEntry {
            law: Law::RaceDrain,
            classification: LawClassification::Unconditional,
            statement: "Losers are always cancelled and awaited (structural invariant)",
        },
        // Race-Join Interaction
        LawEntry {
            law: Law::RaceJoinDistributivity,
            classification: LawClassification::SeverityLevelOnly,
            statement: "race(join(a,b), join(a,c)) ~= join(a, race(b,c)) at severity level only",
        },
        // Timeout
        LawEntry {
            law: Law::TimeoutMin,
            classification: LawClassification::Unconditional,
            statement: "timeout(d1, timeout(d2, f)) ~= timeout(min(d1,d2), f)",
        },
        LawEntry {
            law: Law::TimeoutIdentity,
            classification: LawClassification::Unconditional,
            statement: "timeout(None, f) ~= f — no deadline is identity",
        },
        LawEntry {
            law: Law::TimeoutCommutativity,
            classification: LawClassification::Unconditional,
            statement: "effective(a, Some(b)) = effective(b, Some(a))",
        },
        LawEntry {
            law: Law::TimeoutTighten,
            classification: LawClassification::Unconditional,
            statement: "effective(a, Some(b)) <= a",
        },
        // Budget
        LawEntry {
            law: Law::BudgetAssociativity,
            classification: LawClassification::Unconditional,
            statement: "(a + b) + c = a + (b + c) for budget combine",
        },
        LawEntry {
            law: Law::BudgetCommutativity,
            classification: LawClassification::Unconditional,
            statement: "a + b = b + a for budget combine",
        },
        LawEntry {
            law: Law::BudgetUnit,
            classification: LawClassification::Unconditional,
            statement: "a + INFINITE = a (deadline and quotas)",
        },
        LawEntry {
            law: Law::BudgetAbsorb,
            classification: LawClassification::Unconditional,
            statement: "a + ZERO -> 0 (quotas are absorbed)",
        },
        LawEntry {
            law: Law::BudgetDeadlineMin,
            classification: LawClassification::Unconditional,
            statement: "Combined deadline = min of input deadlines",
        },
        LawEntry {
            law: Law::BudgetQuotaMin,
            classification: LawClassification::Unconditional,
            statement: "Combined poll/cost quota = min of inputs",
        },
        LawEntry {
            law: Law::BudgetPriorityMax,
            classification: LawClassification::Unconditional,
            statement: "Combined priority = max of inputs",
        },
        // Cancel
        LawEntry {
            law: Law::CancelIdempotency,
            classification: LawClassification::Unconditional,
            statement: "a.strengthen(a) is a no-op",
        },
        LawEntry {
            law: Law::CancelAssociativity,
            classification: LawClassification::Unconditional,
            statement: "strengthen(strengthen(a,b),c) = strengthen(a,strengthen(b,c))",
        },
        LawEntry {
            law: Law::CancelMonotonicity,
            classification: LawClassification::Unconditional,
            statement: "severity(a.strengthen(b)) >= severity(a)",
        },
        LawEntry {
            law: Law::CancelMax,
            classification: LawClassification::Unconditional,
            statement: "a.strengthen(b).kind = max(a.kind, b.kind) by PartialOrd",
        },
        // Quorum
        LawEntry {
            law: Law::QuorumJoinDegeneracy,
            classification: LawClassification::Unconditional,
            statement: "quorum(N,N,[f1..fN]) ~= join_all([f1..fN])",
        },
        LawEntry {
            law: Law::QuorumRaceDegeneracy,
            classification: LawClassification::Unconditional,
            statement: "quorum(1,N,[f1..fN]) ~= race_all — first Ok wins",
        },
        LawEntry {
            law: Law::QuorumZero,
            classification: LawClassification::Unconditional,
            statement: "quorum(0,N,[..]) -> Ok([]) immediately",
        },
        // Hedge
        LawEntry {
            law: Law::HedgeFast,
            classification: LawClassification::ConditionalOnTiming,
            statement: "If primary beats deadline: hedge(p,b,d) ~= p",
        },
        LawEntry {
            law: Law::HedgeSlow,
            classification: LawClassification::ConditionalOnTiming,
            statement: "If primary exceeds deadline: hedge(p,b,d) ~= race(p,b)",
        },
        LawEntry {
            law: Law::HedgeDrain,
            classification: LawClassification::Unconditional,
            statement: "Hedge loser is always cancelled and drained",
        },
        // Pipeline
        LawEntry {
            law: Law::PipelineSequential,
            classification: LawClassification::Unconditional,
            statement: "output(stage N) = input(stage N+1)",
        },
        LawEntry {
            law: Law::PipelineShortCircuit,
            classification: LawClassification::ConditionalOnPolicy,
            statement: "First non-Ok terminates pipeline (when continue_on_error=false)",
        },
        LawEntry {
            law: Law::PipelineAssociativity,
            classification: LawClassification::ConditionalOnPolicy,
            statement: "pipeline(a, pipeline(b,c)) ~= pipeline(pipeline(a,b), c) under short-circuit",
        },
        // First-Ok
        LawEntry {
            law: Law::FirstOkFound,
            classification: LawClassification::Unconditional,
            statement: "First Ok result wins; remaining stages never evaluated",
        },
        LawEntry {
            law: Law::FirstOkAllFail,
            classification: LawClassification::Unconditional,
            statement: "All non-Ok -> worst severity returned",
        },
    ]
}

/// Returns only the unconditional laws from the sheet.
#[must_use]
pub fn unconditional_laws() -> Vec<LawEntry> {
    law_sheet()
        .into_iter()
        .filter(|e| e.classification == LawClassification::Unconditional)
        .collect()
}

/// Returns only the conditional laws from the sheet.
#[must_use]
pub fn conditional_laws() -> Vec<LawEntry> {
    law_sheet()
        .into_iter()
        .filter(|e| e.classification != LawClassification::Unconditional)
        .collect()
}

/// Helper: severity of an `AggregateDecision`.
#[cfg(test)]
fn decision_severity<E>(d: &AggregateDecision<E>) -> Severity {
    match d {
        AggregateDecision::AllOk => Severity::Ok,
        AggregateDecision::FirstError(_) => Severity::Err,
        AggregateDecision::Cancelled(_) => Severity::Cancelled,
        AggregateDecision::Panicked { .. } => Severity::Panicked,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "laws_inline_tests.rs"]
mod tests;
