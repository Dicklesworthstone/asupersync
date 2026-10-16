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
use std::collections::{BTreeMap, BTreeSet};
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
                write!(f, "[ASUP-E105] stale-abort {id:?} (age={age_ns}ns)")
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
            let stale_ids = self.find_stale(now_ns, budget);
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
        let mut unresolved_conflicts = BTreeSet::new();
        if budget > 0 {
            let conflicts: Vec<ObligationId> = ledger
                .conflicts_iter()
                .take(budget)
                .map(|(id, _)| id)
                .collect();
            for id in conflicts {
                if budget == 0 {
                    break;
                }
                if self.config.auto_resolve_conflicts {
                    // Abort-wins repair: collapse conflict into a single abort.
                    ledger.force_abort_repair(id);
                    actions.push(RecoveryAction::ConflictResolved { id });
                } else {
                    unresolved_conflicts.insert(id);
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
            let violations: Vec<LinearityViolation> =
                ledger.linearity_violations_iter().take(budget).collect();
            for v in violations {
                if budget == 0 {
                    break;
                }
                if unresolved_conflicts.contains(&v.id) {
                    // When conflict auto-resolution is disabled, the conflict
                    // lane owns this obligation. Do not silently repair the
                    // same entry through the linearity path.
                    continue;
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
    fn find_stale(&self, now_ns: u64, limit: usize) -> Vec<ObligationId> {
        self.first_seen_reserved
            .iter()
            .filter(|(_, first_seen)| {
                now_ns.saturating_sub(**first_seen) >= self.config.stale_timeout_ns
            })
            .take(limit)
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
#[path = "recovery_inline_tests.rs"]
mod tests;
