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
//!
//! # Actor-Specific Oracles
//!
//! - [`ActorLeakOracle`]: Detects actors not properly stopped before region close.
//! - [`SupervisionOracle`]: Verifies supervision tree behavior (restarts, escalation).
//! - [`MailboxOracle`]: Verifies mailbox invariants (capacity, backpressure).

pub mod actor;
pub mod ambient_authority;
pub mod cancellation_protocol;
pub mod deadline_monotone;
pub mod determinism;
pub mod eprocess;
pub mod evidence;
pub mod finalizer;
pub mod loser_drain;
pub mod obligation_leak;
pub mod quiescence;
pub mod region_tree;
pub mod rref_access;
pub mod spork;
pub mod task_leak;

pub use actor::{
    ActorLeakOracle, ActorLeakViolation, MailboxOracle, MailboxViolation, MailboxViolationKind,
    SupervisionOracle, SupervisionViolation, SupervisionViolationKind,
};
pub use ambient_authority::{
    AmbientAuthorityOracle, AmbientAuthorityViolation, CapabilityKind, CapabilitySet,
};
pub use cancellation_protocol::{
    CancellationProtocolOracle, CancellationProtocolViolation, TaskStateKind,
};
pub use deadline_monotone::{DeadlineMonotoneOracle, DeadlineMonotoneViolation};
pub use determinism::{
    DeterminismOracle, DeterminismViolation, TraceEventSummary, assert_deterministic,
    assert_deterministic_multi,
};
pub use eprocess::{EProcess, EProcessConfig, EProcessMonitor, EValue, MonitorResult};
pub use evidence::{
    BayesFactor, DetectionModel, EvidenceEntry, EvidenceLedger, EvidenceLine, EvidenceStrength,
    EvidenceSummary, LogLikelihoodContributions,
};
pub use finalizer::{FinalizerId, FinalizerOracle, FinalizerViolation};
pub use loser_drain::{LoserDrainOracle, LoserDrainViolation};
pub use obligation_leak::{ObligationLeakOracle, ObligationLeakViolation};
pub use quiescence::{QuiescenceOracle, QuiescenceViolation};
pub use region_tree::{RegionTreeEntry, RegionTreeOracle, RegionTreeViolation};
pub use rref_access::{RRefAccessOracle, RRefAccessViolation, RRefAccessViolationKind, RRefId};
pub use spork::{
    DownOrderOracle, DownOrderViolation, RegistryLeaseOracle, RegistryLeaseViolation,
    ReplyLinearityOracle, ReplyLinearityViolation, SupervisorQuiescenceOracle,
    SupervisorQuiescenceViolation,
};
pub use task_leak::{TaskLeakOracle, TaskLeakViolation};

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

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
    /// An actor leak was detected.
    ActorLeak(ActorLeakViolation),
    /// Supervision tree behavior violated.
    Supervision(SupervisionViolation),
    /// Mailbox invariant violated.
    Mailbox(MailboxViolation),
    /// RRef access violation (cross-region, post-close, or witness mismatch).
    RRefAccess(RRefAccessViolation),
    /// GenServer reply dropped without send or abort.
    ReplyLinearity(ReplyLinearityViolation),
    /// Name lease not committed or aborted (stale name).
    RegistryLease(RegistryLeaseViolation),
    /// DOWN messages delivered in non-deterministic order.
    DownOrder(DownOrderViolation),
    /// Supervisor region closed with active children.
    SupervisorQuiescence(SupervisorQuiescenceViolation),
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
            Self::ActorLeak(v) => write!(f, "Actor leak: {v}"),
            Self::Supervision(v) => write!(f, "Supervision violation: {v}"),
            Self::Mailbox(v) => write!(f, "Mailbox violation: {v}"),
            Self::RRefAccess(v) => write!(f, "RRef access violation: {v}"),
            Self::ReplyLinearity(v) => write!(f, "Reply linearity violation: {v}"),
            Self::RegistryLease(v) => write!(f, "Registry lease violation: {v}"),
            Self::DownOrder(v) => write!(f, "DOWN order violation: {v}"),
            Self::SupervisorQuiescence(v) => write!(f, "Supervisor quiescence violation: {v}"),
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
    /// Actor leak oracle.
    pub actor_leak: ActorLeakOracle,
    /// Supervision oracle.
    pub supervision: SupervisionOracle,
    /// Mailbox oracle.
    pub mailbox: MailboxOracle,
    /// RRef access oracle.
    pub rref_access: RRefAccessOracle,
    /// Spork: reply linearity oracle.
    pub reply_linearity: ReplyLinearityOracle,
    /// Spork: registry lease linearity oracle.
    pub registry_lease: RegistryLeaseOracle,
    /// Spork: deterministic DOWN ordering oracle.
    pub down_order: DownOrderOracle,
    /// Spork: supervisor quiescence oracle.
    pub supervisor_quiescence: SupervisorQuiescenceOracle,
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

        if let Err(v) = self.actor_leak.check(now) {
            violations.push(OracleViolation::ActorLeak(v));
        }

        if let Err(v) = self.supervision.check(now) {
            violations.push(OracleViolation::Supervision(v));
        }

        if let Err(v) = self.mailbox.check(now) {
            violations.push(OracleViolation::Mailbox(v));
        }

        if let Err(v) = self.rref_access.check() {
            violations.push(OracleViolation::RRefAccess(v));
        }

        if let Err(v) = self.reply_linearity.check() {
            violations.push(OracleViolation::ReplyLinearity(v));
        }

        if let Err(v) = self.registry_lease.check() {
            violations.push(OracleViolation::RegistryLease(v));
        }

        if let Err(v) = self.down_order.check() {
            violations.push(OracleViolation::DownOrder(v));
        }

        if let Err(v) = self.supervisor_quiescence.check() {
            violations.push(OracleViolation::SupervisorQuiescence(v));
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
        self.actor_leak.reset();
        self.supervision.reset();
        self.mailbox.reset();
        self.rref_access.reset();
        self.reply_linearity.reset();
        self.registry_lease.reset();
        self.down_order.reset();
        self.supervisor_quiescence.reset();
    }

    /// Generates a unified oracle report with per-oracle status and statistics.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn report(&self, now: Time) -> OracleReport {
        let entries = vec![
            OracleEntryReport::from_result(
                "task_leak",
                self.task_leak
                    .check(now)
                    .err()
                    .map(OracleViolation::TaskLeak),
                OracleStats {
                    entities_tracked: self.task_leak.task_count(),
                    events_recorded: self.task_leak.task_count()
                        + self.task_leak.completed_count()
                        + self.task_leak.closed_region_count(),
                },
            ),
            OracleEntryReport::from_result(
                "obligation_leak",
                self.obligation_leak
                    .check(now)
                    .err()
                    .map(OracleViolation::ObligationLeak),
                OracleStats {
                    entities_tracked: self.obligation_leak.obligation_count(),
                    events_recorded: self.obligation_leak.obligation_count()
                        + self.obligation_leak.closed_region_count(),
                },
            ),
            OracleEntryReport::from_result(
                "quiescence",
                self.quiescence
                    .check()
                    .err()
                    .map(OracleViolation::Quiescence),
                OracleStats {
                    entities_tracked: self.quiescence.region_count(),
                    events_recorded: self.quiescence.region_count()
                        + self.quiescence.closed_count(),
                },
            ),
            OracleEntryReport::from_result(
                "loser_drain",
                self.loser_drain
                    .check()
                    .err()
                    .map(OracleViolation::LoserDrain),
                OracleStats {
                    entities_tracked: self.loser_drain.race_count(),
                    events_recorded: self.loser_drain.race_count()
                        + self.loser_drain.completed_race_count(),
                },
            ),
            OracleEntryReport::from_result(
                "finalizer",
                self.finalizer.check().err().map(OracleViolation::Finalizer),
                OracleStats {
                    entities_tracked: self.finalizer.registered_count(),
                    events_recorded: self.finalizer.registered_count()
                        + self.finalizer.ran_count()
                        + self.finalizer.closed_region_count(),
                },
            ),
            OracleEntryReport::from_result(
                "region_tree",
                self.region_tree
                    .check()
                    .err()
                    .map(OracleViolation::RegionTree),
                OracleStats {
                    entities_tracked: self.region_tree.region_count(),
                    events_recorded: self.region_tree.region_count(),
                },
            ),
            OracleEntryReport::from_result(
                "ambient_authority",
                self.ambient_authority
                    .check()
                    .err()
                    .map(OracleViolation::AmbientAuthority),
                OracleStats {
                    entities_tracked: self.ambient_authority.task_count(),
                    events_recorded: self.ambient_authority.task_count()
                        + self.ambient_authority.effect_count(),
                },
            ),
            OracleEntryReport::from_result(
                "deadline_monotone",
                self.deadline_monotone
                    .check()
                    .err()
                    .map(OracleViolation::DeadlineMonotone),
                OracleStats {
                    entities_tracked: self.deadline_monotone.region_count(),
                    events_recorded: self.deadline_monotone.region_count(),
                },
            ),
            OracleEntryReport::from_result(
                "cancellation_protocol",
                self.cancellation_protocol
                    .check()
                    .err()
                    .map(OracleViolation::CancellationProtocol),
                OracleStats {
                    entities_tracked: self.cancellation_protocol.region_count(),
                    events_recorded: self.cancellation_protocol.region_count()
                        + self.cancellation_protocol.cancel_count(),
                },
            ),
            OracleEntryReport::from_result(
                "actor_leak",
                self.actor_leak
                    .check(now)
                    .err()
                    .map(OracleViolation::ActorLeak),
                OracleStats {
                    entities_tracked: self.actor_leak.actor_count(),
                    events_recorded: self.actor_leak.actor_count()
                        + self.actor_leak.stopped_count()
                        + self.actor_leak.closed_region_count(),
                },
            ),
            OracleEntryReport::from_result(
                "supervision",
                self.supervision
                    .check(now)
                    .err()
                    .map(OracleViolation::Supervision),
                OracleStats {
                    entities_tracked: self.supervision.failure_count()
                        + self.supervision.restart_count(),
                    events_recorded: self.supervision.failure_count()
                        + self.supervision.restart_count()
                        + self.supervision.escalation_count(),
                },
            ),
            OracleEntryReport::from_result(
                "mailbox",
                self.mailbox.check(now).err().map(OracleViolation::Mailbox),
                OracleStats {
                    entities_tracked: self.mailbox.mailbox_count(),
                    events_recorded: self.mailbox.mailbox_count(),
                },
            ),
            OracleEntryReport::from_result(
                "rref_access",
                self.rref_access
                    .check()
                    .err()
                    .map(OracleViolation::RRefAccess),
                OracleStats {
                    entities_tracked: self.rref_access.rref_count(),
                    events_recorded: self.rref_access.rref_count()
                        + self.rref_access.task_count()
                        + self.rref_access.closed_region_count(),
                },
            ),
            OracleEntryReport::from_result(
                "reply_linearity",
                self.reply_linearity
                    .check()
                    .err()
                    .map(OracleViolation::ReplyLinearity),
                OracleStats {
                    entities_tracked: self.reply_linearity.created_count(),
                    events_recorded: self.reply_linearity.created_count()
                        + self.reply_linearity.resolved_count(),
                },
            ),
            OracleEntryReport::from_result(
                "registry_lease",
                self.registry_lease
                    .check()
                    .err()
                    .map(OracleViolation::RegistryLease),
                OracleStats {
                    entities_tracked: self.registry_lease.acquired_count(),
                    events_recorded: self.registry_lease.acquired_count()
                        + self.registry_lease.resolved_count(),
                },
            ),
            OracleEntryReport::from_result(
                "down_order",
                self.down_order
                    .check()
                    .err()
                    .map(OracleViolation::DownOrder),
                OracleStats {
                    entities_tracked: self.down_order.monitor_count(),
                    events_recorded: self.down_order.down_count(),
                },
            ),
            OracleEntryReport::from_result(
                "supervisor_quiescence",
                self.supervisor_quiescence
                    .check()
                    .err()
                    .map(OracleViolation::SupervisorQuiescence),
                OracleStats {
                    entities_tracked: self.supervisor_quiescence.supervisor_count(),
                    events_recorded: self.supervisor_quiescence.child_count()
                        + self.supervisor_quiescence.closed_region_count(),
                },
            ),
        ];

        let total = entries.len();
        let passed = entries.iter().filter(|e| e.passed).count();
        let failed = total - passed;

        OracleReport {
            entries,
            total,
            passed,
            failed,
            check_time_nanos: now.as_nanos(),
        }
    }
}

/// Per-oracle statistics snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OracleStats {
    /// Number of entities (tasks, regions, actors, etc.) tracked by this oracle.
    pub entities_tracked: usize,
    /// Number of events (spawns, stops, closes, etc.) recorded.
    pub events_recorded: usize,
}

/// Report for a single oracle within the unified report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleEntryReport {
    /// Oracle invariant name (e.g., "task_leak", "quiescence").
    pub invariant: String,
    /// Whether this oracle passed (no violations).
    pub passed: bool,
    /// Violation description, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violation: Option<String>,
    /// Statistics for this oracle.
    pub stats: OracleStats,
}

impl OracleEntryReport {
    fn from_result(
        invariant: &'static str,
        violation: Option<OracleViolation>,
        stats: OracleStats,
    ) -> Self {
        Self {
            invariant: invariant.to_owned(),
            passed: violation.is_none(),
            violation: violation.map(|v| v.to_string()),
            stats,
        }
    }
}

/// Unified oracle report covering all oracles with per-oracle status and statistics.
///
/// Produced by [`OracleSuite::report()`]. Serializable to JSON for artifact storage
/// and renderable as human-readable text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleReport {
    /// Per-oracle entries in a stable order.
    pub entries: Vec<OracleEntryReport>,
    /// Total number of oracles checked.
    pub total: usize,
    /// Number of oracles that passed.
    pub passed: usize,
    /// Number of oracles that failed (had violations).
    pub failed: usize,
    /// The time (nanoseconds) at which the check was performed.
    pub check_time_nanos: u64,
}

impl OracleReport {
    /// Returns true if all oracles passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }

    /// Returns entries that failed.
    #[must_use]
    pub fn failures(&self) -> Vec<&OracleEntryReport> {
        self.entries.iter().filter(|e| !e.passed).collect()
    }

    /// Returns the entry for a specific invariant.
    #[must_use]
    pub fn entry(&self, invariant: &str) -> Option<&OracleEntryReport> {
        self.entries
            .iter()
            .find(|e| e.invariant.as_str() == invariant)
    }

    /// Serializes the report to JSON.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// Renders the report as human-readable text.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            &mut out,
            "Oracle Report: {}/{} passed ({} failed)",
            self.passed, self.total, self.failed
        );
        let _ = writeln!(&mut out, "Check time: {}ns", self.check_time_nanos);
        let _ = writeln!(&mut out, "---");
        for entry in &self.entries {
            let status = if entry.passed { "PASS" } else { "FAIL" };
            let _ = write!(
                &mut out,
                "[{}] {} (tracked={}, events={})",
                status, entry.invariant, entry.stats.entities_tracked, entry.stats.events_recorded
            );
            if let Some(ref v) = entry.violation {
                let _ = write!(&mut out, " -- {v}");
            }
            let _ = writeln!(&mut out);
        }
        out
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
