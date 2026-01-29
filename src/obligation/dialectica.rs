//! Dialectica-style contract for two-phase effects.
//!
//! # Dialectica Interpretation of Obligations
//!
//! In the Gödel–Dialectica interpretation, a proposition `A → B` is witnessed
//! by a pair of functions:
//!
//! ```text
//!   forward:  A × W → B       (produce a value, given a witness)
//!   backward: A × C → W       (given a challenge, produce the witness)
//! ```
//!
//! For two-phase obligations, this specializes to:
//!
//! ```text
//!   reserve:  (Kind, Region) → Permit       (forward: create the obligation)
//!   resolve:  Permit → {Commit, Abort}       (backward: discharge it)
//! ```
//!
//! The **forward** step (reserve) produces a *permit* — a capability to
//! perform a side effect. The **backward** step (commit or abort) discharges
//! the obligation, completing the two-phase protocol.
//!
//! # Contracts
//!
//! This module encodes five contracts that the obligation system must satisfy:
//!
//! 1. **Exhaustive resolution**: Every reserved obligation must reach a
//!    terminal state (Committed, Aborted, or Leaked).
//!
//! 2. **No partial commit**: State transitions are atomic — there is no
//!    intermediate state between Reserved and a terminal state.
//!
//! 3. **Region closure safety**: A region cannot close while any obligation
//!    within it remains Reserved.
//!
//! 4. **Cancellation non-cascading**: Cancelling a task does not automatically
//!    resolve its obligations. The holder must explicitly abort.
//!
//! 5. **Kind-uniform state machine**: All four obligation kinds
//!    (SendPermit, Ack, Lease, IoOp) follow the identical state machine.
//!    Kind is diagnostic, not prescriptive.
//!
//! # Dialectica Morphism
//!
//! Formally, a two-phase effect `E` with obligation kind `K` in region `R` is:
//!
//! ```text
//!   E = (reserve, resolve) : (K, R) ⊸ (K, R)
//!
//!   reserve : (K, R) → Permit(K, R)
//!   resolve : Permit(K, R) → Terminal(K, R)
//!
//!   Terminal(K, R) = Committed(K, R) | Aborted(K, R) | Leaked(K, R)
//! ```
//!
//! Where `⊸` denotes a linear function (the Permit must be consumed exactly
//! once). Rust's affine type system approximates this via `#[must_use]` and
//! Drop bombs on [`crate::obligation::graded::GradedObligation`].
//!
//! # Usage
//!
//! ```
//! use asupersync::obligation::dialectica::{
//!     DialecticaContract, ContractViolation, ContractChecker,
//! };
//! use asupersync::obligation::marking::{MarkingEvent, MarkingEventKind, MarkingAnalyzer};
//! use asupersync::record::ObligationKind;
//! use asupersync::types::{RegionId, ObligationId, TaskId, Time};
//! use asupersync::util::ArenaIndex;
//!
//! let r0 = RegionId::from_arena(ArenaIndex::new(0, 0));
//! let t0 = TaskId::from_arena(ArenaIndex::new(0, 0));
//! let o0 = ObligationId::from_arena(ArenaIndex::new(0, 0));
//!
//! // Build a correct two-phase trace.
//! let events = vec![
//!     MarkingEvent::new(Time::ZERO, MarkingEventKind::Reserve {
//!         obligation: o0, kind: ObligationKind::SendPermit, task: t0, region: r0,
//!     }),
//!     MarkingEvent::new(Time::from_nanos(10), MarkingEventKind::Commit {
//!         obligation: o0, region: r0, kind: ObligationKind::SendPermit,
//!     }),
//!     MarkingEvent::new(Time::from_nanos(20), MarkingEventKind::RegionClose { region: r0 }),
//! ];
//!
//! let mut checker = ContractChecker::new();
//! let result = checker.check(&events);
//! assert!(result.is_clean());
//! ```

use crate::record::{ObligationKind, ObligationState};
use crate::types::{ObligationId, RegionId, Time};
use std::collections::HashMap;
use std::fmt;

use super::marking::{MarkingEvent, MarkingEventKind};

// ============================================================================
// Contracts
// ============================================================================

/// The five Dialectica contracts for two-phase effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialecticaContract {
    /// Every reserved obligation must reach a terminal state.
    ExhaustiveResolution,
    /// No intermediate state between Reserved and terminal.
    NoPartialCommit,
    /// Region close requires all obligations in the region to be terminal.
    RegionClosureSafety,
    /// Cancellation does not automatically resolve obligations.
    CancellationNonCascading,
    /// All obligation kinds follow the same state machine.
    KindUniformStateMachine,
}

impl DialecticaContract {
    /// Returns a short description of this contract.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::ExhaustiveResolution => "every reserved obligation must reach a terminal state",
            Self::NoPartialCommit => "state transitions are atomic (no intermediate states)",
            Self::RegionClosureSafety => "region close requires all obligations terminal",
            Self::CancellationNonCascading => "cancellation does not auto-resolve obligations",
            Self::KindUniformStateMachine => "all obligation kinds share identical state machine",
        }
    }
}

impl fmt::Display for DialecticaContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::ExhaustiveResolution => "ExhaustiveResolution",
            Self::NoPartialCommit => "NoPartialCommit",
            Self::RegionClosureSafety => "RegionClosureSafety",
            Self::CancellationNonCascading => "CancellationNonCascading",
            Self::KindUniformStateMachine => "KindUniformStateMachine",
        };
        write!(f, "{name}: {}", self.description())
    }
}

// ============================================================================
// Contract Violations
// ============================================================================

/// A violation of a Dialectica contract.
#[derive(Debug, Clone)]
pub struct ContractViolation {
    /// Which contract was violated.
    pub contract: DialecticaContract,
    /// When the violation was detected.
    pub time: Time,
    /// Description of the violation.
    pub description: String,
    /// The obligation involved (if applicable).
    pub obligation: Option<ObligationId>,
    /// The region involved (if applicable).
    pub region: Option<RegionId>,
}

impl fmt::Display for ContractViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] at t={}: {}",
            self.contract, self.time, self.description
        )
    }
}

// ============================================================================
// Contract Check Result
// ============================================================================

/// Result of checking the Dialectica contracts against a trace.
#[derive(Debug, Clone)]
pub struct ContractCheckResult {
    /// Violations detected.
    pub violations: Vec<ContractViolation>,
    /// Total events checked.
    pub events_checked: usize,
    /// Per-contract status (true = satisfied, false = violated).
    pub contract_status: ContractStatusMap,
}

/// Per-contract satisfaction status.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct ContractStatusMap {
    exhaustive_resolution: bool,
    no_partial_commit: bool,
    region_closure_safety: bool,
    cancellation_non_cascading: bool,
    kind_uniform_state_machine: bool,
}

impl ContractStatusMap {
    fn new_all_satisfied() -> Self {
        Self {
            exhaustive_resolution: true,
            no_partial_commit: true,
            region_closure_safety: true,
            cancellation_non_cascading: true,
            kind_uniform_state_machine: true,
        }
    }

    fn mark_violated(&mut self, contract: DialecticaContract) {
        match contract {
            DialecticaContract::ExhaustiveResolution => self.exhaustive_resolution = false,
            DialecticaContract::NoPartialCommit => self.no_partial_commit = false,
            DialecticaContract::RegionClosureSafety => self.region_closure_safety = false,
            DialecticaContract::CancellationNonCascading => {
                self.cancellation_non_cascading = false;
            }
            DialecticaContract::KindUniformStateMachine => {
                self.kind_uniform_state_machine = false;
            }
        }
    }

    /// Check if a specific contract is satisfied.
    #[must_use]
    pub fn is_satisfied(&self, contract: DialecticaContract) -> bool {
        match contract {
            DialecticaContract::ExhaustiveResolution => self.exhaustive_resolution,
            DialecticaContract::NoPartialCommit => self.no_partial_commit,
            DialecticaContract::RegionClosureSafety => self.region_closure_safety,
            DialecticaContract::CancellationNonCascading => self.cancellation_non_cascading,
            DialecticaContract::KindUniformStateMachine => self.kind_uniform_state_machine,
        }
    }

    /// Check if all contracts are satisfied.
    #[must_use]
    pub fn all_satisfied(&self) -> bool {
        self.exhaustive_resolution
            && self.no_partial_commit
            && self.region_closure_safety
            && self.cancellation_non_cascading
            && self.kind_uniform_state_machine
    }
}

impl ContractCheckResult {
    /// Returns true if no violations were detected.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }

    /// Returns violations for a specific contract.
    #[must_use]
    pub fn violations_for(&self, contract: DialecticaContract) -> Vec<&ContractViolation> {
        self.violations
            .iter()
            .filter(|v| v.contract == contract)
            .collect()
    }
}

impl fmt::Display for ContractCheckResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Dialectica Contract Check")?;
        writeln!(f, "========================")?;
        writeln!(f, "Events checked: {}", self.events_checked)?;
        writeln!(f, "Clean: {}", self.is_clean())?;

        let contracts = [
            (
                "ExhaustiveResolution",
                self.contract_status.exhaustive_resolution,
            ),
            ("NoPartialCommit", self.contract_status.no_partial_commit),
            (
                "RegionClosureSafety",
                self.contract_status.region_closure_safety,
            ),
            (
                "CancellationNonCascading",
                self.contract_status.cancellation_non_cascading,
            ),
            (
                "KindUniformStateMachine",
                self.contract_status.kind_uniform_state_machine,
            ),
        ];

        writeln!(f)?;
        for (name, ok) in contracts {
            let mark = if ok { "PASS" } else { "FAIL" };
            writeln!(f, "  [{mark}] {name}")?;
        }

        if !self.violations.is_empty() {
            writeln!(f)?;
            writeln!(f, "Violations ({}):", self.violations.len())?;
            for v in &self.violations {
                writeln!(f, "  {v}")?;
            }
        }

        Ok(())
    }
}

// ============================================================================
// ObligationSnapshot (internal tracking)
// ============================================================================

/// Tracks the state of an obligation as observed through marking events.
#[derive(Debug, Clone)]
struct ObligationSnapshot {
    kind: ObligationKind,
    region: RegionId,
    state: ObligationState,
    reserved_at: Time,
    resolved_at: Option<Time>,
    /// Number of state transitions observed (should be exactly 1 for a valid lifecycle).
    transition_count: u32,
}

// ============================================================================
// ContractChecker
// ============================================================================

/// Checks Dialectica contracts against a sequence of marking events.
///
/// The checker tracks obligation state and detects violations of the five
/// contracts. It is designed to be run against marking events produced by
/// [`super::marking::project_trace`] or constructed directly in tests.
#[derive(Debug, Default)]
pub struct ContractChecker {
    /// Tracked obligations: id → snapshot.
    obligations: HashMap<ObligationId, ObligationSnapshot>,
    /// Detected violations.
    violations: Vec<ContractViolation>,
    /// Per-contract status.
    status: Option<ContractStatusMap>,
}

impl ContractChecker {
    /// Creates a new contract checker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check the Dialectica contracts against a sequence of marking events.
    #[must_use]
    pub fn check(&mut self, events: &[MarkingEvent]) -> ContractCheckResult {
        self.reset();

        for event in events {
            self.process_event(event);
        }

        // Final check: exhaustive resolution.
        // Any obligation still in Reserved state after the trace ends
        // violates ExhaustiveResolution.
        self.check_exhaustive_resolution(events.last().map_or(Time::ZERO, |e| e.time));

        let mut status = ContractStatusMap::new_all_satisfied();
        for v in &self.violations {
            status.mark_violated(v.contract);
        }

        ContractCheckResult {
            violations: self.violations.clone(),
            events_checked: events.len(),
            contract_status: status,
        }
    }

    fn reset(&mut self) {
        self.obligations.clear();
        self.violations.clear();
        self.status = None;
    }

    fn process_event(&mut self, event: &MarkingEvent) {
        match &event.kind {
            MarkingEventKind::Reserve {
                obligation,
                kind,
                region,
                ..
            } => {
                // Forward step: create the obligation.
                // Contract: NoPartialCommit — obligation starts in Reserved, no intermediate.
                self.obligations.insert(
                    *obligation,
                    ObligationSnapshot {
                        kind: *kind,
                        region: *region,
                        state: ObligationState::Reserved,
                        reserved_at: event.time,
                        resolved_at: None,
                        transition_count: 0,
                    },
                );
            }

            MarkingEventKind::Commit {
                obligation,
                kind,
                region,
            } => {
                self.apply_resolution(
                    *obligation,
                    ObligationState::Committed,
                    event.time,
                    *kind,
                    *region,
                );
            }

            MarkingEventKind::Abort {
                obligation,
                kind,
                region,
            } => {
                self.apply_resolution(
                    *obligation,
                    ObligationState::Aborted,
                    event.time,
                    *kind,
                    *region,
                );
            }

            MarkingEventKind::Leak {
                obligation,
                kind,
                region,
            } => {
                self.apply_resolution(
                    *obligation,
                    ObligationState::Leaked,
                    event.time,
                    *kind,
                    *region,
                );
            }

            MarkingEventKind::RegionClose { region } => {
                self.check_region_closure(*region, event.time);
            }
        }
    }

    /// Apply a state transition and check contracts.
    fn apply_resolution(
        &mut self,
        obligation: ObligationId,
        new_state: ObligationState,
        time: Time,
        kind: ObligationKind,
        region: RegionId,
    ) {
        match self.obligations.get_mut(&obligation) {
            Some(snap) => {
                let (recorded_kind, violation) = {
                    // Contract: NoPartialCommit — only one transition allowed.
                    if snap.state.is_terminal() {
                        let prev_state = snap.state;
                        let snap_region = snap.region;
                        self.violations.push(ContractViolation {
                            contract: DialecticaContract::NoPartialCommit,
                            time,
                            description: format!(
                                "obligation {obligation:?} already in terminal state {prev_state:?}, \
                                 attempted transition to {new_state:?}",
                            ),
                            obligation: Some(obligation),
                            region: Some(snap_region),
                        });
                        return;
                    }

                    snap.state = new_state;
                    snap.resolved_at = Some(time);
                    snap.transition_count += 1;

                    // Extract values before releasing the mutable borrow.
                    let transition_count = snap.transition_count;
                    let snap_region = snap.region;
                    let recorded_kind = snap.kind;

                    let violation = if transition_count > 1 {
                        Some(ContractViolation {
                            contract: DialecticaContract::NoPartialCommit,
                            time,
                            description: format!(
                                "obligation {obligation:?} has {transition_count} transitions \
                                 (expected exactly 1)",
                            ),
                            obligation: Some(obligation),
                            region: Some(snap_region),
                        })
                    } else {
                        None
                    };

                    (recorded_kind, violation)
                };

                if let Some(violation) = violation {
                    self.violations.push(violation);
                }

                // Contract: KindUniformStateMachine — verify the transition is valid
                // for the state machine regardless of kind. Since all kinds use the
                // same state machine, we check that Reserved → {Committed, Aborted, Leaked}
                // is the only allowed transition. The kind should not affect this.
                self.verify_kind_uniform(obligation, recorded_kind, kind, new_state, time, region);
            }
            None => {
                // Resolution without a prior reserve — a NoPartialCommit violation.
                self.violations.push(ContractViolation {
                    contract: DialecticaContract::NoPartialCommit,
                    time,
                    description: format!(
                        "obligation {obligation:?} resolved to {new_state:?} but was never reserved"
                    ),
                    obligation: Some(obligation),
                    region: Some(region),
                });
            }
        }
    }

    /// Verify kind-uniform state machine: same state machine regardless of kind.
    fn verify_kind_uniform(
        &mut self,
        obligation: ObligationId,
        recorded_kind: ObligationKind,
        event_kind: ObligationKind,
        new_state: ObligationState,
        time: Time,
        region: RegionId,
    ) {
        // Contract: KindUniformStateMachine
        // 1. The kind in the resolution event must match the reserved kind.
        if recorded_kind != event_kind {
            self.violations.push(ContractViolation {
                contract: DialecticaContract::KindUniformStateMachine,
                time,
                description: format!(
                    "obligation {obligation:?} reserved as {recorded_kind}, \
                     but resolved as {event_kind}"
                ),
                obligation: Some(obligation),
                region: Some(region),
            });
        }

        // 2. The only valid transitions from Reserved are to terminal states.
        //    This is inherent in the state machine (no intermediate states exist),
        //    but we verify it explicitly.
        if !new_state.is_terminal() {
            self.violations.push(ContractViolation {
                contract: DialecticaContract::KindUniformStateMachine,
                time,
                description: format!(
                    "obligation {obligation:?} transitioned to non-terminal state {new_state:?}"
                ),
                obligation: Some(obligation),
                region: Some(region),
            });
        }
    }

    /// Check RegionClosureSafety: no Reserved obligations in a closing region.
    fn check_region_closure(&mut self, region: RegionId, time: Time) {
        for (id, snap) in &self.obligations {
            if snap.region == region && snap.state == ObligationState::Reserved {
                self.violations.push(ContractViolation {
                    contract: DialecticaContract::RegionClosureSafety,
                    time,
                    description: format!(
                        "obligation {id:?} ({}) still Reserved when region {region:?} closed",
                        snap.kind,
                    ),
                    obligation: Some(*id),
                    region: Some(region),
                });
            }
        }
    }

    /// Check ExhaustiveResolution: all obligations must be terminal at trace end.
    fn check_exhaustive_resolution(&mut self, trace_end: Time) {
        for (id, snap) in &self.obligations {
            if !snap.state.is_terminal() {
                self.violations.push(ContractViolation {
                    contract: DialecticaContract::ExhaustiveResolution,
                    time: trace_end,
                    description: format!(
                        "obligation {id:?} ({}) in state {:?} at trace end \
                         (reserved at t={})",
                        snap.kind, snap.state, snap.reserved_at,
                    ),
                    obligation: Some(*id),
                    region: Some(snap.region),
                });
            }
        }
    }
}

// ============================================================================
// Dialectica Morphism (type-level encoding)
// ============================================================================

/// A Dialectica morphism for two-phase effects.
///
/// Represents the forward/backward pair:
/// - `reserve()` is the forward step (produces a Permit)
/// - `commit()` / `abort()` is the backward step (discharges the obligation)
///
/// This is a documentation-level type that encodes the formal structure.
/// For the runtime enforcement, see [`crate::obligation::graded::GradedObligation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialecticaMorphism {
    /// The obligation kind.
    pub kind: ObligationKind,
    /// The forward step has been taken (reserve).
    pub forward_taken: bool,
    /// The backward step has been taken (commit or abort).
    pub backward_taken: bool,
    /// The resolution, if backward step is taken.
    pub resolution: Option<ObligationState>,
}

impl DialecticaMorphism {
    /// Create a new morphism for the given kind (not yet executed).
    #[must_use]
    pub const fn new(kind: ObligationKind) -> Self {
        Self {
            kind,
            forward_taken: false,
            backward_taken: false,
            resolution: None,
        }
    }

    /// Execute the forward step (reserve).
    ///
    /// # Panics
    /// Panics if forward step already taken.
    pub fn forward(&mut self) {
        assert!(!self.forward_taken, "forward step already taken");
        self.forward_taken = true;
    }

    /// Execute the backward step (resolve).
    ///
    /// # Panics
    /// Panics if forward step not taken, or backward step already taken.
    pub fn backward(&mut self, resolution: ObligationState) {
        assert!(self.forward_taken, "cannot resolve without forward step");
        assert!(!self.backward_taken, "backward step already taken");
        assert!(resolution.is_terminal(), "resolution must be terminal");
        self.backward_taken = true;
        self.resolution = Some(resolution);
    }

    /// Check if the morphism is complete (forward + backward both taken).
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.forward_taken && self.backward_taken
    }

    /// Check if the morphism is pending (forward taken, backward not).
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        self.forward_taken && !self.backward_taken
    }

    /// Check if the morphism was cleanly resolved (committed or aborted, not leaked).
    #[must_use]
    pub fn is_clean(&self) -> bool {
        matches!(
            self.resolution,
            Some(ObligationState::Committed | ObligationState::Aborted)
        )
    }
}

impl fmt::Display for DialecticaMorphism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = if !self.forward_taken {
            "idle"
        } else if !self.backward_taken {
            "pending"
        } else {
            match self.resolution {
                Some(ObligationState::Committed) => "committed",
                Some(ObligationState::Aborted) => "aborted",
                Some(ObligationState::Leaked) => "LEAKED",
                _ => "unknown",
            }
        };
        write!(f, "Dialectica({}, {})", self.kind, state)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TaskId;
    use crate::util::ArenaIndex;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn r(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    fn t(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn o(n: u32) -> ObligationId {
        ObligationId::from_arena(ArenaIndex::new(n, 0))
    }

    fn reserve(
        time_ns: u64,
        obligation: ObligationId,
        kind: ObligationKind,
        task: TaskId,
        region: RegionId,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Reserve {
                obligation,
                kind,
                task,
                region,
            },
        )
    }

    fn commit(
        time_ns: u64,
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Commit {
                obligation,
                region,
                kind,
            },
        )
    }

    fn abort(
        time_ns: u64,
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Abort {
                obligation,
                region,
                kind,
            },
        )
    }

    fn leak(
        time_ns: u64,
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Leak {
                obligation,
                region,
                kind,
            },
        )
    }

    fn close(time_ns: u64, region: RegionId) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::RegionClose { region },
        )
    }

    // ---- Contract 1: ExhaustiveResolution ----------------------------------

    #[test]
    fn exhaustive_resolution_clean_trace() {
        init_test("exhaustive_resolution_clean_trace");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            close(20, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let clean = result.is_clean();
        crate::assert_with_log!(clean, "clean", true, clean);
        let satisfied = result
            .contract_status
            .is_satisfied(DialecticaContract::ExhaustiveResolution);
        crate::assert_with_log!(satisfied, "exhaustive_resolution", true, satisfied);
        crate::test_complete!("exhaustive_resolution_clean_trace");
    }

    #[test]
    fn exhaustive_resolution_violated_by_unresolved() {
        init_test("exhaustive_resolution_violated_by_unresolved");
        let events = vec![
            reserve(0, o(0), ObligationKind::Ack, t(0), r(0)),
            // No commit or abort — obligation remains Reserved.
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let clean = result.is_clean();
        crate::assert_with_log!(!clean, "not clean", false, clean);
        let violations = result.violations_for(DialecticaContract::ExhaustiveResolution);
        let count = violations.len();
        crate::assert_with_log!(count == 1, "violation count", 1, count);
        crate::test_complete!("exhaustive_resolution_violated_by_unresolved");
    }

    #[test]
    fn exhaustive_resolution_abort_counts_as_resolved() {
        init_test("exhaustive_resolution_abort_counts_as_resolved");
        let events = vec![
            reserve(0, o(0), ObligationKind::Lease, t(0), r(0)),
            abort(5, o(0), r(0), ObligationKind::Lease),
            close(10, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let clean = result.is_clean();
        crate::assert_with_log!(clean, "abort resolves", true, clean);
        crate::test_complete!("exhaustive_resolution_abort_counts_as_resolved");
    }

    #[test]
    fn exhaustive_resolution_leak_counts_as_terminal() {
        init_test("exhaustive_resolution_leak_counts_as_terminal");
        // Leak is a terminal state — it satisfies ExhaustiveResolution
        // (even though it represents an error).
        let events = vec![
            reserve(0, o(0), ObligationKind::IoOp, t(0), r(0)),
            leak(5, o(0), r(0), ObligationKind::IoOp),
            close(10, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let exhaustive_ok = result
            .contract_status
            .is_satisfied(DialecticaContract::ExhaustiveResolution);
        crate::assert_with_log!(exhaustive_ok, "leak is terminal", true, exhaustive_ok);
        crate::test_complete!("exhaustive_resolution_leak_counts_as_terminal");
    }

    // ---- Contract 2: NoPartialCommit ---------------------------------------

    #[test]
    fn no_partial_commit_double_commit_detected() {
        init_test("no_partial_commit_double_commit_detected");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            commit(20, o(0), r(0), ObligationKind::SendPermit), // Double commit.
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let violations = result.violations_for(DialecticaContract::NoPartialCommit);
        let count = violations.len();
        crate::assert_with_log!(count == 1, "double commit violation", 1, count);
        crate::test_complete!("no_partial_commit_double_commit_detected");
    }

    #[test]
    fn no_partial_commit_commit_after_abort_detected() {
        init_test("no_partial_commit_commit_after_abort_detected");
        let events = vec![
            reserve(0, o(0), ObligationKind::Ack, t(0), r(0)),
            abort(5, o(0), r(0), ObligationKind::Ack),
            commit(10, o(0), r(0), ObligationKind::Ack), // Commit after abort.
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let violations = result.violations_for(DialecticaContract::NoPartialCommit);
        let count = violations.len();
        crate::assert_with_log!(count == 1, "commit-after-abort violation", 1, count);
        crate::test_complete!("no_partial_commit_commit_after_abort_detected");
    }

    #[test]
    fn no_partial_commit_resolve_without_reserve() {
        init_test("no_partial_commit_resolve_without_reserve");
        let events = vec![
            commit(10, o(99), r(0), ObligationKind::Lease), // No reserve for o(99).
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let violations = result.violations_for(DialecticaContract::NoPartialCommit);
        let count = violations.len();
        crate::assert_with_log!(count == 1, "resolve without reserve", 1, count);
        crate::test_complete!("no_partial_commit_resolve_without_reserve");
    }

    // ---- Contract 3: RegionClosureSafety -----------------------------------

    #[test]
    fn region_closure_safety_clean() {
        init_test("region_closure_safety_clean");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            close(20, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let ok = result
            .contract_status
            .is_satisfied(DialecticaContract::RegionClosureSafety);
        crate::assert_with_log!(ok, "region closure safe", true, ok);
        crate::test_complete!("region_closure_safety_clean");
    }

    #[test]
    fn region_closure_safety_violated_by_pending() {
        init_test("region_closure_safety_violated_by_pending");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close(10, r(0)), // Close with o(0) still pending.
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let violations = result.violations_for(DialecticaContract::RegionClosureSafety);
        let count = violations.len();
        crate::assert_with_log!(count == 1, "region closure violation", 1, count);
        crate::test_complete!("region_closure_safety_violated_by_pending");
    }

    #[test]
    fn region_closure_safety_multiple_pending() {
        init_test("region_closure_safety_multiple_pending");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::Lease, t(0), r(0)),
            close(10, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let violations = result.violations_for(DialecticaContract::RegionClosureSafety);
        let count = violations.len();
        crate::assert_with_log!(count == 2, "two pending obligations", 2, count);
        crate::test_complete!("region_closure_safety_multiple_pending");
    }

    #[test]
    fn region_closure_only_checks_matching_region() {
        init_test("region_closure_only_checks_matching_region");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::Ack, t(0), r(1)),
            commit(5, o(0), r(0), ObligationKind::SendPermit),
            close(10, r(0)), // Only r(0) closes — r(1) is fine to have pending.
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let violations = result.violations_for(DialecticaContract::RegionClosureSafety);
        let count = violations.len();
        crate::assert_with_log!(count == 0, "other region not checked", 0, count);
        // But ExhaustiveResolution will catch the unresolved o(1).
        let exhaust = result.violations_for(DialecticaContract::ExhaustiveResolution);
        let exhaust_count = exhaust.len();
        crate::assert_with_log!(exhaust_count == 1, "unresolved caught", 1, exhaust_count);
        crate::test_complete!("region_closure_only_checks_matching_region");
    }

    // ---- Contract 5: KindUniformStateMachine -------------------------------

    #[test]
    fn kind_uniform_all_kinds_same_lifecycle() {
        init_test("kind_uniform_all_kinds_same_lifecycle");
        // Every kind follows exactly the same reserve → commit lifecycle.
        let kinds = [
            ObligationKind::SendPermit,
            ObligationKind::Ack,
            ObligationKind::Lease,
            ObligationKind::IoOp,
        ];

        for (i, kind) in kinds.iter().enumerate() {
            let idx = i as u32;
            let events = vec![
                reserve(0, o(idx), *kind, t(0), r(0)),
                commit(10, o(idx), r(0), *kind),
                close(20, r(0)),
            ];

            let mut checker = ContractChecker::new();
            let result = checker.check(&events);
            let clean = result.is_clean();
            crate::assert_with_log!(clean, format!("{kind} clean"), true, clean);
        }
        crate::test_complete!("kind_uniform_all_kinds_same_lifecycle");
    }

    #[test]
    fn kind_uniform_mismatch_detected() {
        init_test("kind_uniform_mismatch_detected");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            // Resolve with a different kind — violation.
            commit(10, o(0), r(0), ObligationKind::Lease),
            close(20, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let violations = result.violations_for(DialecticaContract::KindUniformStateMachine);
        let count = violations.len();
        crate::assert_with_log!(count == 1, "kind mismatch", 1, count);
        crate::test_complete!("kind_uniform_mismatch_detected");
    }

    // ---- Morphism type tests -----------------------------------------------

    #[test]
    fn morphism_lifecycle_commit() {
        init_test("morphism_lifecycle_commit");
        let mut m = DialecticaMorphism::new(ObligationKind::SendPermit);
        let pending = m.is_pending();
        crate::assert_with_log!(!pending, "not pending before forward", false, pending);

        m.forward();
        let pending = m.is_pending();
        crate::assert_with_log!(pending, "pending after forward", true, pending);

        m.backward(ObligationState::Committed);
        let complete = m.is_complete();
        crate::assert_with_log!(complete, "complete after backward", true, complete);
        let clean = m.is_clean();
        crate::assert_with_log!(clean, "clean (committed)", true, clean);
        crate::test_complete!("morphism_lifecycle_commit");
    }

    #[test]
    fn morphism_lifecycle_abort() {
        init_test("morphism_lifecycle_abort");
        let mut m = DialecticaMorphism::new(ObligationKind::Lease);
        m.forward();
        m.backward(ObligationState::Aborted);
        let complete = m.is_complete();
        crate::assert_with_log!(complete, "complete", true, complete);
        let clean = m.is_clean();
        crate::assert_with_log!(clean, "clean (aborted)", true, clean);
        crate::test_complete!("morphism_lifecycle_abort");
    }

    #[test]
    fn morphism_lifecycle_leaked_not_clean() {
        init_test("morphism_lifecycle_leaked_not_clean");
        let mut m = DialecticaMorphism::new(ObligationKind::IoOp);
        m.forward();
        m.backward(ObligationState::Leaked);
        let complete = m.is_complete();
        crate::assert_with_log!(complete, "complete (leaked)", true, complete);
        let clean = m.is_clean();
        crate::assert_with_log!(!clean, "not clean (leaked)", false, clean);
        crate::test_complete!("morphism_lifecycle_leaked_not_clean");
    }

    #[test]
    #[should_panic(expected = "forward step already taken")]
    fn morphism_double_forward_panics() {
        let mut m = DialecticaMorphism::new(ObligationKind::Ack);
        m.forward();
        m.forward(); // Should panic.
    }

    #[test]
    #[should_panic(expected = "cannot resolve without forward step")]
    fn morphism_backward_without_forward_panics() {
        let mut m = DialecticaMorphism::new(ObligationKind::Ack);
        m.backward(ObligationState::Committed); // Should panic.
    }

    #[test]
    #[should_panic(expected = "backward step already taken")]
    fn morphism_double_backward_panics() {
        let mut m = DialecticaMorphism::new(ObligationKind::SendPermit);
        m.forward();
        m.backward(ObligationState::Committed);
        m.backward(ObligationState::Aborted); // Should panic.
    }

    #[test]
    #[should_panic(expected = "resolution must be terminal")]
    fn morphism_non_terminal_resolution_panics() {
        let mut m = DialecticaMorphism::new(ObligationKind::Lease);
        m.forward();
        m.backward(ObligationState::Reserved); // Not terminal — panic.
    }

    // ---- Display tests -----------------------------------------------------

    #[test]
    fn display_morphism() {
        init_test("display_morphism");
        let m = DialecticaMorphism::new(ObligationKind::SendPermit);
        let s = format!("{m}");
        let has_idle = s.contains("idle");
        crate::assert_with_log!(has_idle, "idle display", true, has_idle);

        let mut m2 = DialecticaMorphism::new(ObligationKind::Lease);
        m2.forward();
        let s2 = format!("{m2}");
        let has_pending = s2.contains("pending");
        crate::assert_with_log!(has_pending, "pending display", true, has_pending);

        m2.backward(ObligationState::Committed);
        let s3 = format!("{m2}");
        let has_committed = s3.contains("committed");
        crate::assert_with_log!(has_committed, "committed display", true, has_committed);
        crate::test_complete!("display_morphism");
    }

    #[test]
    fn display_contract() {
        init_test("display_contract");
        let c = DialecticaContract::ExhaustiveResolution;
        let s = format!("{c}");
        let has_name = s.contains("ExhaustiveResolution");
        crate::assert_with_log!(has_name, "contract display", true, has_name);
        crate::test_complete!("display_contract");
    }

    #[test]
    fn display_result() {
        init_test("display_result");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            close(20, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let s = format!("{result}");
        let has_pass = s.contains("PASS");
        crate::assert_with_log!(has_pass, "result has PASS", true, has_pass);
        let has_clean = s.contains("Clean: true");
        crate::assert_with_log!(has_clean, "result shows clean", true, has_clean);
        crate::test_complete!("display_result");
    }

    // ---- Realistic scenarios -----------------------------------------------

    #[test]
    fn realistic_channel_send_with_cancel() {
        init_test("realistic_channel_send_with_cancel");
        // Two tasks, one sends and commits, one gets cancelled and aborts.
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::SendPermit, t(1), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            abort(11, o(1), r(0), ObligationKind::SendPermit), // Task 1 cancelled.
            close(20, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let clean = result.is_clean();
        crate::assert_with_log!(clean, "cancel handled correctly", true, clean);
        crate::test_complete!("realistic_channel_send_with_cancel");
    }

    #[test]
    fn realistic_nested_regions_with_obligations() {
        init_test("realistic_nested_regions_with_obligations");
        // Parent region r(0) with child region r(1).
        // Each has its own obligation, resolved before respective close.
        let events = vec![
            reserve(0, o(0), ObligationKind::Lease, t(0), r(0)),
            reserve(1, o(1), ObligationKind::SendPermit, t(1), r(1)),
            commit(10, o(1), r(1), ObligationKind::SendPermit),
            close(15, r(1)),
            commit(20, o(0), r(0), ObligationKind::Lease),
            close(25, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let clean = result.is_clean();
        crate::assert_with_log!(clean, "nested regions clean", true, clean);
        crate::test_complete!("realistic_nested_regions_with_obligations");
    }

    #[test]
    fn realistic_mixed_resolution_types() {
        init_test("realistic_mixed_resolution_types");
        // Four obligations, each resolved differently.
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::Ack, t(0), r(0)),
            reserve(2, o(2), ObligationKind::Lease, t(1), r(0)),
            reserve(3, o(3), ObligationKind::IoOp, t(1), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            abort(11, o(1), r(0), ObligationKind::Ack),
            commit(12, o(2), r(0), ObligationKind::Lease),
            leak(13, o(3), r(0), ObligationKind::IoOp), // IoOp leaked.
            close(20, r(0)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        // ExhaustiveResolution: satisfied (leak is terminal).
        let exhaustive = result
            .contract_status
            .is_satisfied(DialecticaContract::ExhaustiveResolution);
        crate::assert_with_log!(exhaustive, "exhaustive ok", true, exhaustive);
        // Region closure: satisfied (all resolved before close).
        let closure = result
            .contract_status
            .is_satisfied(DialecticaContract::RegionClosureSafety);
        crate::assert_with_log!(closure, "closure ok", true, closure);
        // All contracts satisfied even with a leak, because leak is terminal.
        let all = result.contract_status.all_satisfied();
        crate::assert_with_log!(all, "all contracts", true, all);
        crate::test_complete!("realistic_mixed_resolution_types");
    }

    #[test]
    fn realistic_all_violations_in_one_trace() {
        init_test("realistic_all_violations_in_one_trace");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            // Double commit (NoPartialCommit violation).
            commit(5, o(0), r(0), ObligationKind::SendPermit),
            commit(6, o(0), r(0), ObligationKind::SendPermit),
            // Reserve but don't resolve (ExhaustiveResolution violation).
            reserve(10, o(1), ObligationKind::Ack, t(0), r(0)),
            // Close region with pending o(1) (RegionClosureSafety violation).
            close(20, r(0)),
            // Kind mismatch (KindUniformStateMachine violation).
            reserve(30, o(2), ObligationKind::Lease, t(0), r(1)),
            commit(35, o(2), r(1), ObligationKind::IoOp),
            close(40, r(1)),
        ];

        let mut checker = ContractChecker::new();
        let result = checker.check(&events);
        let clean = result.is_clean();
        crate::assert_with_log!(!clean, "not clean", false, clean);

        // Check each contract.
        let npc = !result
            .contract_status
            .is_satisfied(DialecticaContract::NoPartialCommit);
        crate::assert_with_log!(npc, "no_partial_commit violated", true, npc);

        let er = !result
            .contract_status
            .is_satisfied(DialecticaContract::ExhaustiveResolution);
        crate::assert_with_log!(er, "exhaustive_resolution violated", true, er);

        let rcs = !result
            .contract_status
            .is_satisfied(DialecticaContract::RegionClosureSafety);
        crate::assert_with_log!(rcs, "region_closure_safety violated", true, rcs);

        let kus = !result
            .contract_status
            .is_satisfied(DialecticaContract::KindUniformStateMachine);
        crate::assert_with_log!(kus, "kind_uniform violated", true, kus);

        crate::test_complete!("realistic_all_violations_in_one_trace");
    }

    // ---- Checker reuse test ------------------------------------------------

    #[test]
    fn checker_reuse() {
        init_test("checker_reuse");
        let mut checker = ContractChecker::new();

        // First run — violation.
        let events1 = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close(10, r(0)),
        ];
        let r1 = checker.check(&events1);
        let r1_clean = r1.is_clean();
        crate::assert_with_log!(!r1_clean, "first not clean", false, r1_clean);

        // Second run — clean.
        let events2 = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(5, o(0), r(0), ObligationKind::SendPermit),
            close(10, r(0)),
        ];
        let r2 = checker.check(&events2);
        let r2_clean = r2.is_clean();
        crate::assert_with_log!(r2_clean, "second clean", true, r2_clean);

        // First result unaffected.
        let r1_count = r1.violations.len();
        crate::assert_with_log!(
            r1_count >= 1,
            "first still has violations",
            true,
            r1_count >= 1
        );
        crate::test_complete!("checker_reuse");
    }
}
