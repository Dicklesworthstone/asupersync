//! Self-stabilizing recovery protocol for obligation convergence.
//!
//! After partial failures (node crashes, network partitions, lost messages),
//! the recovery protocol drives the system toward a quiescent, leak-free
//! state using the CRDT obligation ledger.
//!
//! # Design
//!
//! The protocol is self-stabilizing: starting from *any* state (including
//! corrupted or partially-merged states), repeated application of the
//! recovery rules eventually reaches a legitimate state where:
//!
//! 1. No obligations are stuck in `Reserved` beyond the timeout.
//! 2. All conflicts are resolved (via abort-wins or operator escalation).
//! 3. Linearity violations are flagged and the offending obligations aborted.
//!
//! # Recovery State Machine
//!
//! ```text
//! Idle ──(timer)──► Scanning ──► Resolving ──► Idle
//!                       │              │
//!                       └──(clean)─────┘
//! ```
//!
//! - **Idle**: Waiting for the next recovery tick.
//! - **Scanning**: Inspecting the CRDT ledger for anomalies.
//! - **Resolving**: Applying conflict resolution and timeout rules.
//!
//! # Conflict Resolution Rules
//!
//! 1. **Stale obligations**: `Reserved` obligations older than `stale_timeout`
//!    are forcibly aborted (the holder is assumed crashed).
//! 2. **Conflict (Committed ⊔ Aborted)**: Abort-wins policy — the obligation
//!    is driven to `Aborted` for safety (the committed side-effect may need
//!    compensation, but that's outside the obligation system's scope).
//! 3. **Linearity violations**: Obligations acquired or resolved multiple times
//!    are flagged as errors and forcibly aborted.
//!
//! # Convergence Guarantee
//!
//! The protocol converges because:
//! - Each recovery step can only advance obligations toward terminal states.
//! - Terminal states are absorbing in the lattice.
//! - The number of non-terminal obligations is finite and monotonically
//!   decreasing under recovery.
//! - No recovery action can create new obligations or resurrect resolved ones.

use crate::obligation::crdt::{CrdtObligationLedger, LinearityViolation};
use crate::trace::distributed::lattice::LatticeState;
use crate::types::ObligationId;
use std::collections::BTreeMap;
use std::fmt;

/// Configuration for the recovery protocol.
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    /// How long a `Reserved` obligation can remain before being considered stale (nanoseconds).
    pub stale_timeout_ns: u64,
    /// Maximum number of obligations to resolve per recovery tick (prevents storms).
    pub max_resolutions_per_tick: usize,
    /// Whether to auto-resolve conflicts (abort-wins) or just flag them.
    pub auto_resolve_conflicts: bool,
    /// Whether to auto-abort linearity violations.
    pub auto_abort_violations: bool,
}

impl RecoveryConfig {
    /// Returns a default configuration suitable for testing.
    #[must_use]
    pub fn default_for_test() -> Self {
        Self {
            stale_timeout_ns: 5_000_000_000, // 5 seconds
            max_resolutions_per_tick: 100,
            auto_resolve_conflicts: true,
            auto_abort_violations: true,
        }
    }
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            stale_timeout_ns: 30_000_000_000, // 30 seconds
            max_resolutions_per_tick: 50,
            auto_resolve_conflicts: true,
            auto_abort_violations: true,
        }
    }
}

/// The current phase of the recovery state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPhase {
    /// Waiting for the next recovery tick.
    Idle,
    /// Scanning the CRDT ledger for anomalies.
    Scanning,
    /// Applying resolution rules.
    Resolving,
}

impl fmt::Display for RecoveryPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Scanning => write!(f, "Scanning"),
            Self::Resolving => write!(f, "Resolving"),
        }
    }
}

/// An action taken by the recovery protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryAction {
    /// A stale obligation was forcibly aborted.
    StaleAbort {
        /// Obligation that was aborted.
        id: ObligationId,
        /// Age in nanoseconds at the time of abort.
        age_ns: u64,
    },
    /// A conflict was resolved by aborting.
    ConflictResolved {
        /// Obligation that was resolved by abort.
        id: ObligationId,
    },
    /// A linearity violation was detected and the obligation aborted.
    ViolationAborted {
        /// Obligation that violated linearity.
        id: ObligationId,
        /// Total acquire count observed.
        total_acquires: u64,
        /// Total resolve count observed.
        total_resolves: u64,
    },
    /// An anomaly was flagged but not auto-resolved.
    Flagged {
        /// Obligation that was flagged.
        id: ObligationId,
        /// Human-readable reason for the flag.
        reason: String,
    },
}

impl fmt::Display for RecoveryAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleAbort { id, age_ns } => {
                write!(f, "stale-abort {id:?} (age={age_ns}ns)")
            }
            Self::ConflictResolved { id } => {
                write!(f, "conflict-resolved {id:?}")
            }
            Self::ViolationAborted {
                id,
                total_acquires,
                total_resolves,
            } => {
                write!(
                    f,
                    "violation-aborted {id:?} (acquires={total_acquires}, resolves={total_resolves})"
                )
            }
            Self::Flagged { id, reason } => {
                write!(f, "flagged {id:?}: {reason}")
            }
        }
    }
}

/// Result of a single recovery tick.
#[derive(Debug, Clone)]
pub struct RecoveryTickResult {
    /// Actions taken during this tick.
    pub actions: Vec<RecoveryAction>,
    /// Number of obligations still pending after this tick.
    pub remaining_pending: usize,
    /// Number of unresolved conflicts.
    pub remaining_conflicts: usize,
    /// Number of unresolved linearity violations.
    pub remaining_violations: usize,
    /// Whether the system is in a quiescent (clean) state.
    pub is_quiescent: bool,
}

impl RecoveryTickResult {
    /// Returns the number of actions taken.
    #[must_use]
    pub fn action_count(&self) -> usize {
        self.actions.len()
    }
}

/// Self-stabilizing recovery governor for the CRDT obligation ledger.
///
/// The governor inspects the ledger periodically (or on demand) and applies
/// resolution rules to drive the system toward quiescence.
#[derive(Debug)]
pub struct RecoveryGovernor {
    config: RecoveryConfig,
    phase: RecoveryPhase,
    /// Timestamps for when each obligation was first observed as Reserved.
    /// Used for stale detection. BTreeMap for determinism.
    first_seen_reserved: BTreeMap<ObligationId, u64>,
    /// Total ticks executed.
    total_ticks: u64,
    /// Total actions taken across all ticks.
    total_actions: u64,
}

impl RecoveryGovernor {
    /// Creates a new recovery governor with the given configuration.
    #[must_use]
    pub fn new(config: RecoveryConfig) -> Self {
        Self {
            config,
            phase: RecoveryPhase::Idle,
            first_seen_reserved: BTreeMap::new(),
            total_ticks: 0,
            total_actions: 0,
        }
    }

    /// Returns the current recovery phase.
    #[must_use]
    pub fn phase(&self) -> RecoveryPhase {
        self.phase
    }

    /// Returns the total number of recovery ticks executed.
    #[must_use]
    pub fn total_ticks(&self) -> u64 {
        self.total_ticks
    }

    /// Returns the total number of recovery actions taken.
    #[must_use]
    pub fn total_actions(&self) -> u64 {
        self.total_actions
    }

    /// Executes a single recovery tick against the given ledger.
    ///
    /// The `now_ns` parameter is the current time in nanoseconds (must be
    /// monotonically increasing for correct stale detection).
    ///
    /// Returns the actions taken and the resulting system state.
    pub fn tick(&mut self, ledger: &mut CrdtObligationLedger, now_ns: u64) -> RecoveryTickResult {
        self.total_ticks += 1;
        self.phase = RecoveryPhase::Scanning;

        let mut actions = Vec::new();
        let mut budget = self.config.max_resolutions_per_tick;

        // Phase 1: Scan for stale obligations
        self.update_first_seen(ledger, now_ns);

        // Phase 2: Resolve anomalies
        self.phase = RecoveryPhase::Resolving;

        // 2a: Stale obligations (Reserved beyond timeout)
        if budget > 0 {
            let stale_ids = self.find_stale(now_ns);
            for id in stale_ids {
                if budget == 0 {
                    break;
                }
                ledger.record_abort(id);
                let age = now_ns
                    .saturating_sub(self.first_seen_reserved.get(&id).copied().unwrap_or(now_ns));
                actions.push(RecoveryAction::StaleAbort { id, age_ns: age });
                self.first_seen_reserved.remove(&id);
                budget -= 1;
            }
        }

        // 2b: Conflicts
        if budget > 0 {
            let conflicts: Vec<ObligationId> =
                ledger.conflicts().iter().map(|(id, _)| *id).collect();
            for id in conflicts {
                if budget == 0 {
                    break;
                }
                if self.config.auto_resolve_conflicts {
                    // Abort-wins repair: collapse conflict into a single abort.
                    ledger.force_abort_repair(id);
                    actions.push(RecoveryAction::ConflictResolved { id });
                } else {
                    actions.push(RecoveryAction::Flagged {
                        id,
                        reason: "conflict: Committed ⊔ Aborted".to_string(),
                    });
                }
                budget -= 1;
            }
        }

        // 2c: Linearity violations
        if budget > 0 {
            let violations: Vec<LinearityViolation> = ledger.linearity_violations();
            for v in violations {
                if budget == 0 {
                    break;
                }
                if self.config.auto_abort_violations {
                    ledger.force_abort_repair(v.id);
                    actions.push(RecoveryAction::ViolationAborted {
                        id: v.id,
                        total_acquires: v.total_acquires,
                        total_resolves: v.total_resolves,
                    });
                } else {
                    actions.push(RecoveryAction::Flagged {
                        id: v.id,
                        reason: format!(
                            "linearity: acquires={}, resolves={}",
                            v.total_acquires, v.total_resolves
                        ),
                    });
                }
                budget -= 1;
            }
        }

        self.total_actions += actions.len() as u64;
        self.phase = RecoveryPhase::Idle;

        // Compute remaining anomalies
        let remaining_pending = ledger.pending().len();
        let remaining_conflicts = ledger.conflicts().len();
        let remaining_violations = ledger.linearity_violations().len();
        let is_quiescent =
            remaining_pending == 0 && remaining_conflicts == 0 && remaining_violations == 0;

        RecoveryTickResult {
            actions,
            remaining_pending,
            remaining_conflicts,
            remaining_violations,
            is_quiescent,
        }
    }

    /// Updates the first-seen timestamps for currently reserved obligations.
    fn update_first_seen(&mut self, ledger: &CrdtObligationLedger, now_ns: u64) {
        // Remove entries for obligations no longer in Reserved state
        self.first_seen_reserved
            .retain(|id, _| ledger.get(id) == LatticeState::Reserved);

        // Add new entries for newly-seen Reserved obligations.
        for id in ledger.pending() {
            self.first_seen_reserved.entry(id).or_insert(now_ns);
        }
    }

    /// Returns obligations that have exceeded the stale timeout.
    fn find_stale(&self, now_ns: u64) -> Vec<ObligationId> {
        self.first_seen_reserved
            .iter()
            .filter(|(_, first_seen)| {
                now_ns.saturating_sub(**first_seen) >= self.config.stale_timeout_ns
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Resets the governor state (for testing).
    pub fn reset(&mut self) {
        self.phase = RecoveryPhase::Idle;
        self.first_seen_reserved.clear();
        self.total_ticks = 0;
        self.total_actions = 0;
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obligation::crdt::CrdtObligationLedger;
    use crate::record::ObligationKind;
    use crate::remote::NodeId;
    use crate::trace::distributed::crdt::Merge;
    use crate::types::ObligationId;

    fn oid(index: u32) -> ObligationId {
        ObligationId::new_for_test(index, 0)
    }

    fn node(name: &str) -> NodeId {
        NodeId::new(name)
    }

    fn test_config() -> RecoveryConfig {
        RecoveryConfig {
            stale_timeout_ns: 1000,
            max_resolutions_per_tick: 100,
            auto_resolve_conflicts: true,
            auto_abort_violations: true,
        }
    }

    // ── Basic lifecycle ─────────────────────────────────────────────────

    #[test]
    fn governor_starts_idle() {
        let gov = RecoveryGovernor::new(test_config());
        assert_eq!(gov.phase(), RecoveryPhase::Idle);
        assert_eq!(gov.total_ticks(), 0);
    }

    #[test]
    fn clean_ledger_is_quiescent() {
        let mut gov = RecoveryGovernor::new(test_config());
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_commit(oid(1));

        let result = gov.tick(&mut ledger, 0);
        assert!(result.is_quiescent);
        assert_eq!(result.action_count(), 0);
    }

    #[test]
    fn pending_obligation_not_stale_yet() {
        let mut gov = RecoveryGovernor::new(test_config());
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);

        // First tick at t=0: discovers the obligation, sets first_seen
        let result = gov.tick(&mut ledger, 0);
        assert!(!result.is_quiescent);
        assert_eq!(result.action_count(), 0);
        assert_eq!(result.remaining_pending, 1);

        // Second tick at t=500: not yet stale (timeout=1000)
        let result = gov.tick(&mut ledger, 500);
        assert_eq!(result.action_count(), 0);
    }

    // ── Stale obligation recovery ───────────────────────────────────────

    #[test]
    fn stale_obligation_is_aborted() {
        let mut gov = RecoveryGovernor::new(test_config());
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);

        // First tick: discover and set first_seen
        gov.tick(&mut ledger, 0);

        // Second tick after timeout: should abort
        let result = gov.tick(&mut ledger, 2000);
        assert_eq!(result.action_count(), 1);
        assert!(matches!(
            &result.actions[0],
            RecoveryAction::StaleAbort { id, age_ns } if *id == oid(1) && *age_ns >= 1000
        ));
        assert_eq!(ledger.get(&oid(1)), LatticeState::Aborted);
    }

    #[test]
    fn resolved_obligation_not_considered_stale() {
        let mut gov = RecoveryGovernor::new(test_config());
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);

        // First tick at t=0
        gov.tick(&mut ledger, 0);

        // Resolve before timeout
        ledger.record_commit(oid(1));

        // Tick after timeout: should not abort (already committed)
        let result = gov.tick(&mut ledger, 2000);
        assert_eq!(result.action_count(), 0);
        assert_eq!(ledger.get(&oid(1)), LatticeState::Committed);
    }

    // ── Conflict resolution ─────────────────────────────────────────────

    #[test]
    fn conflict_auto_resolved_by_abort() {
        let mut gov = RecoveryGovernor::new(test_config());
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(1), ObligationKind::SendPermit);
        b.record_abort(oid(1));

        // Merge creates conflict
        a.merge(&b);
        assert_eq!(a.get(&oid(1)), LatticeState::Conflict);

        // Recovery resolves it
        let result = gov.tick(&mut a, 0);
        assert!(
            result
                .actions
                .iter()
                .any(|a| matches!(a, RecoveryAction::ConflictResolved { .. }))
        );
    }

    #[test]
    fn conflict_flagged_when_auto_resolve_disabled() {
        let mut config = test_config();
        config.auto_resolve_conflicts = false;
        // Also disable auto-abort for violations: the merged ledger has both a
        // conflict (Committed ⊔ Aborted) and a linearity violation (2 acquires,
        // 2 resolves). If auto_abort_violations is true, force_abort_repair()
        // clears the conflict before remaining_conflicts is computed.
        config.auto_abort_violations = false;
        let mut gov = RecoveryGovernor::new(config);

        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(1), ObligationKind::SendPermit);
        b.record_abort(oid(1));

        a.merge(&b);

        let result = gov.tick(&mut a, 0);
        assert!(
            result
                .actions
                .iter()
                .any(|a| matches!(a, RecoveryAction::Flagged { .. }))
        );
        assert!(result.remaining_conflicts > 0);
    }

    // ── Linearity violation recovery ────────────────────────────────────

    #[test]
    fn linearity_violation_auto_aborted() {
        let mut gov = RecoveryGovernor::new(test_config());
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_acquire(oid(1), ObligationKind::SendPermit); // double acquire

        let result = gov.tick(&mut ledger, 0);
        assert!(
            result
                .actions
                .iter()
                .any(|a| matches!(a, RecoveryAction::ViolationAborted { .. }))
        );
    }

    #[test]
    fn linearity_violation_flagged_when_auto_disabled() {
        let mut config = test_config();
        config.auto_abort_violations = false;
        let mut gov = RecoveryGovernor::new(config);

        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);

        let result = gov.tick(&mut ledger, 0);
        assert!(
            result
                .actions
                .iter()
                .any(|a| matches!(a, RecoveryAction::Flagged { .. }))
        );
    }

    // ── Convergence ─────────────────────────────────────────────────────

    #[test]
    fn repeated_ticks_converge_to_quiescence() {
        let mut gov = RecoveryGovernor::new(test_config());
        let mut ledger = CrdtObligationLedger::new(node("A"));

        // Create a messy state: stale, conflict, violation
        ledger.record_acquire(oid(1), ObligationKind::SendPermit); // will go stale
        ledger.record_acquire(oid(2), ObligationKind::Ack);
        ledger.record_acquire(oid(2), ObligationKind::Ack); // violation

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(3), ObligationKind::Lease);
        b.record_commit(oid(3));
        let mut c = CrdtObligationLedger::new(node("C"));
        c.record_acquire(oid(3), ObligationKind::Lease);
        c.record_abort(oid(3));
        b.merge(&c); // conflict on oid(3)
        ledger.merge(&b);

        // First tick at t=0: resolves conflict and violation, discovers stale
        let r1 = gov.tick(&mut ledger, 0);
        assert!(r1.action_count() > 0);

        // After timeout: stale obligation gets aborted
        let _r2 = gov.tick(&mut ledger, 2000);

        // Should converge: no more pending, conflicts, or violations
        let r3 = gov.tick(&mut ledger, 3000);
        assert!(
            r3.is_quiescent,
            "not quiescent: pending={}, conflicts={}, violations={}",
            r3.remaining_pending, r3.remaining_conflicts, r3.remaining_violations
        );
    }

    #[test]
    fn convergence_is_monotonic() {
        let mut gov = RecoveryGovernor::new(test_config());
        let mut ledger = CrdtObligationLedger::new(node("A"));

        // Create several pending obligations
        for i in 0..5 {
            ledger.record_acquire(oid(i), ObligationKind::SendPermit);
        }

        // Discover all at t=0
        gov.tick(&mut ledger, 0);

        // After timeout: all should be aborted
        let result = gov.tick(&mut ledger, 2000);
        assert_eq!(result.remaining_pending, 0);

        // Additional tick: no more actions needed
        let result2 = gov.tick(&mut ledger, 3000);
        assert_eq!(result2.action_count(), 0);
        assert!(result2.is_quiescent);
    }

    // ── Budget limiting ─────────────────────────────────────────────────

    #[test]
    fn max_resolutions_per_tick_respected() {
        let mut config = test_config();
        config.max_resolutions_per_tick = 2;
        let mut gov = RecoveryGovernor::new(config);

        let mut ledger = CrdtObligationLedger::new(node("A"));
        for i in 0..5 {
            ledger.record_acquire(oid(i), ObligationKind::SendPermit);
        }

        // Discover all
        gov.tick(&mut ledger, 0);

        // After timeout: limited to 2 resolutions
        let result = gov.tick(&mut ledger, 2000);
        assert_eq!(result.action_count(), 2);
        assert_eq!(result.remaining_pending, 3);

        // Next tick resolves 2 more
        let result2 = gov.tick(&mut ledger, 3000);
        assert_eq!(result2.action_count(), 2);
        assert_eq!(result2.remaining_pending, 1);
    }

    // ── Reset ───────────────────────────────────────────────────────────

    #[test]
    fn reset_clears_state() {
        let mut gov = RecoveryGovernor::new(test_config());
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        gov.tick(&mut ledger, 0);

        gov.reset();
        assert_eq!(gov.phase(), RecoveryPhase::Idle);
        assert_eq!(gov.total_ticks(), 0);
        assert_eq!(gov.total_actions(), 0);
    }

    // ── Display ─────────────────────────────────────────────────────────

    #[test]
    fn recovery_action_display() {
        let action = RecoveryAction::StaleAbort {
            id: oid(1),
            age_ns: 5000,
        };
        let display = format!("{action}");
        assert!(display.contains("stale-abort"));
        assert!(display.contains("5000"));
    }

    #[test]
    fn recovery_phase_display() {
        assert_eq!(format!("{}", RecoveryPhase::Idle), "Idle");
        assert_eq!(format!("{}", RecoveryPhase::Scanning), "Scanning");
        assert_eq!(format!("{}", RecoveryPhase::Resolving), "Resolving");
    }

    // ── Partition/heal scenario ─────────────────────────────────────────

    #[test]
    fn partition_heal_converges() {
        let mut gov = RecoveryGovernor::new(test_config());

        // Node A acquires and commits
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        // Node B (partitioned) only saw the acquire
        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(1), ObligationKind::SendPermit);

        // Node B runs recovery: oid(1) appears stale on B
        gov.tick(&mut b, 0);
        let _result = gov.tick(&mut b, 2000);
        // B aborts it (stale)
        assert_eq!(b.get(&oid(1)), LatticeState::Aborted);

        // Partition heals: merge A and B
        a.merge(&b);
        // Committed ⊔ Aborted = Conflict
        assert_eq!(a.get(&oid(1)), LatticeState::Conflict);

        // Recovery resolves the conflict
        let mut gov2 = RecoveryGovernor::new(test_config());
        let result = gov2.tick(&mut a, 0);
        assert!(
            result
                .actions
                .iter()
                .any(|a| matches!(a, RecoveryAction::ConflictResolved { .. }))
        );
    }

    #[test]
    fn recovery_config_debug_clone_default() {
        let c = RecoveryConfig::default();
        let dbg = format!("{:?}", c);
        assert!(dbg.contains("RecoveryConfig"));

        let c2 = c.clone();
        assert_eq!(c2.stale_timeout_ns, 30_000_000_000);
        assert_eq!(c2.max_resolutions_per_tick, 50);

        let c3 = RecoveryConfig::default_for_test();
        assert_eq!(c3.stale_timeout_ns, 5_000_000_000);
    }

    #[test]
    fn recovery_phase_debug_clone_copy_eq() {
        let p = RecoveryPhase::Idle;
        let dbg = format!("{:?}", p);
        assert!(dbg.contains("Idle"));

        let p2 = p.clone();
        assert_eq!(p, p2);

        let p3 = p;
        assert_eq!(p, p3);

        assert_ne!(RecoveryPhase::Idle, RecoveryPhase::Scanning);
    }

    #[test]
    fn recovery_action_debug_clone_eq() {
        let a = RecoveryAction::ConflictResolved {
            id: oid(42),
        };
        let dbg = format!("{:?}", a);
        assert!(dbg.contains("ConflictResolved"));

        let a2 = a.clone();
        assert_eq!(a, a2);

        let a3 = RecoveryAction::Flagged {
            id: oid(1),
            reason: "test".into(),
        };
        assert_ne!(a, a3);
    }

    #[test]
    fn recovery_tick_result_debug_clone() {
        let r = RecoveryTickResult {
            actions: vec![],
            remaining_pending: 0,
            remaining_conflicts: 0,
            remaining_violations: 0,
            is_quiescent: true,
        };
        let dbg = format!("{:?}", r);
        assert!(dbg.contains("RecoveryTickResult"));

        let r2 = r.clone();
        assert!(r2.is_quiescent);
        assert!(r2.actions.is_empty());
    }
}
