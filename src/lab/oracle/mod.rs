//! Test oracles for verifying runtime invariants.
//!
//! Oracles observe runtime events and verify that the 6 non-negotiable
//! invariants hold. They are used in lab mode for deterministic testing.
//!
//! # The 6 Non-Negotiable Invariants
//!
//! | # | Invariant | Oracle |
//! |---|-----------|--------|
//! | 1 | Structured concurrency – every task is owned by exactly one region | [`TaskLeakOracle`] |
//! | 2 | Region close = quiescence – no live children + all finalizers done | [`QuiescenceOracle`] |
//! | 3 | Cancellation is a protocol – request → drain → finalize | [`CancellationProtocolOracle`] |
//! | 4 | Losers are drained – races must cancel AND fully drain losers | [`LoserDrainOracle`] |
//! | 5 | No obligation leaks – permits/acks/leases must be committed or aborted | [`ObligationLeakOracle`] |
//! | 6 | No ambient authority – effects flow through Cx and explicit capabilities | [`AmbientAuthorityOracle`] |
//!
//! Additionally:
//! - [`FinalizerOracle`] verifies all registered finalizers ran.
//! - [`RegionTreeOracle`] verifies INV-TREE: regions form a proper rooted tree.
//! - [`DeadlineMonotoneOracle`] verifies INV-DEADLINE-MONOTONE: child deadlines ≤ parent deadlines.

pub mod ambient_authority;
pub mod cancellation_protocol;
pub mod deadline_monotone;
pub mod determinism;
pub mod finalizer;
pub mod loser_drain;
pub mod obligation_leak;
pub mod quiescence;
pub mod region_tree;
pub mod task_leak;

pub use ambient_authority::{
    AmbientAuthorityOracle, AmbientAuthorityViolation, CapabilityKind, CapabilitySet,
};
pub use cancellation_protocol::{
    CancellationProtocolOracle, CancellationProtocolViolation, TaskStateKind,
};
pub use deadline_monotone::{DeadlineMonotoneOracle, DeadlineMonotoneViolation};
pub use determinism::{
    assert_deterministic, assert_deterministic_multi, DeterminismOracle, DeterminismViolation,
    TraceEventSummary,
};
pub use finalizer::{FinalizerId, FinalizerOracle, FinalizerViolation};
pub use loser_drain::{LoserDrainOracle, LoserDrainViolation};
pub use obligation_leak::{ObligationLeakOracle, ObligationLeakViolation};
pub use quiescence::{QuiescenceOracle, QuiescenceViolation};
pub use region_tree::{RegionTreeEntry, RegionTreeOracle, RegionTreeViolation};
pub use task_leak::{TaskLeakOracle, TaskLeakViolation};

use crate::types::Time;

/// A violation detected by an oracle.
#[derive(Debug, Clone)]
pub enum OracleViolation {
    /// A task leak was detected.
    TaskLeak(TaskLeakViolation),
    /// An obligation leak was detected.
    ObligationLeak(ObligationLeakViolation),
    /// Quiescence violation on region close.
    Quiescence(QuiescenceViolation),
    /// Race losers were not properly drained.
    LoserDrain(LoserDrainViolation),
    /// Finalizers did not all run.
    Finalizer(FinalizerViolation),
    /// Region tree structure is malformed.
    RegionTree(RegionTreeViolation),
    /// Effects performed without appropriate capabilities.
    AmbientAuthority(AmbientAuthorityViolation),
    /// Child deadline exceeds parent deadline.
    DeadlineMonotone(DeadlineMonotoneViolation),
    /// Cancellation protocol violated.
    CancellationProtocol(CancellationProtocolViolation),
}

impl std::fmt::Display for OracleViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TaskLeak(v) => write!(f, "Task leak: {v}"),
            Self::ObligationLeak(v) => write!(f, "Obligation leak: {v}"),
            Self::Quiescence(v) => write!(f, "Quiescence violation: {v}"),
            Self::LoserDrain(v) => write!(f, "Loser drain violation: {v}"),
            Self::Finalizer(v) => write!(f, "Finalizer violation: {v}"),
            Self::RegionTree(v) => write!(f, "Region tree violation: {v}"),
            Self::AmbientAuthority(v) => write!(f, "Ambient authority violation: {v}"),
            Self::DeadlineMonotone(v) => write!(f, "Deadline monotonicity violation: {v}"),
            Self::CancellationProtocol(v) => write!(f, "Cancellation protocol violation: {v}"),
        }
    }
}

impl std::error::Error for OracleViolation {}

/// Aggregates all oracles for convenient use in lab runtime.
#[derive(Debug, Default)]
pub struct OracleSuite {
    /// Task leak oracle.
    pub task_leak: TaskLeakOracle,
    /// Obligation leak oracle.
    pub obligation_leak: ObligationLeakOracle,
    /// Quiescence oracle.
    pub quiescence: QuiescenceOracle,
    /// Loser drain oracle.
    pub loser_drain: LoserDrainOracle,
    /// Finalizer oracle.
    pub finalizer: FinalizerOracle,
    /// Region tree oracle.
    pub region_tree: RegionTreeOracle,
    /// Ambient authority oracle.
    pub ambient_authority: AmbientAuthorityOracle,
    /// Deadline monotonicity oracle.
    pub deadline_monotone: DeadlineMonotoneOracle,
    /// Cancellation protocol oracle.
    pub cancellation_protocol: CancellationProtocolOracle,
}

impl OracleSuite {
    /// Creates a new oracle suite with all oracles initialized.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks all oracles and returns any violations.
    #[must_use]
    pub fn check_all(&self, now: Time) -> Vec<OracleViolation> {
        let mut violations = Vec::new();

        if let Err(v) = self.task_leak.check(now) {
            violations.push(OracleViolation::TaskLeak(v));
        }

        if let Err(v) = self.obligation_leak.check(now) {
            violations.push(OracleViolation::ObligationLeak(v));
        }

        if let Err(v) = self.quiescence.check() {
            violations.push(OracleViolation::Quiescence(v));
        }

        if let Err(v) = self.loser_drain.check() {
            violations.push(OracleViolation::LoserDrain(v));
        }

        if let Err(v) = self.finalizer.check() {
            violations.push(OracleViolation::Finalizer(v));
        }

        if let Err(v) = self.region_tree.check() {
            violations.push(OracleViolation::RegionTree(v));
        }

        if let Err(v) = self.ambient_authority.check() {
            violations.push(OracleViolation::AmbientAuthority(v));
        }

        if let Err(v) = self.deadline_monotone.check() {
            violations.push(OracleViolation::DeadlineMonotone(v));
        }

        if let Err(v) = self.cancellation_protocol.check() {
            violations.push(OracleViolation::CancellationProtocol(v));
        }

        violations
    }

    /// Resets all oracles to their initial state.
    pub fn reset(&mut self) {
        self.task_leak.reset();
        self.obligation_leak.reset();
        self.quiescence.reset();
        self.loser_drain.reset();
        self.finalizer.reset();
        self.region_tree.reset();
        self.ambient_authority.reset();
        self.deadline_monotone.reset();
        self.cancellation_protocol.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn oracle_suite_default_is_clean() {
        init_test("oracle_suite_default_is_clean");
        let suite = OracleSuite::new();
        let violations = suite.check_all(Time::ZERO);
        let empty = violations.is_empty();
        crate::assert_with_log!(empty, "suite clean", true, empty);
        crate::test_complete!("oracle_suite_default_is_clean");
    }
}
