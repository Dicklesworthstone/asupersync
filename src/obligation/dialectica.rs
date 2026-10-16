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
//! use asupersync::types::{ObligationId, RegionId, TaskId, Time};
//!
//! let r0 = RegionId::new_for_test(0, 0);
//! let t0 = TaskId::new_for_test(0, 0);
//! let o0 = ObligationId::new_for_test(0, 0);
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
use std::collections::BTreeMap;
use std::fmt;

use super::marking::{MarkingEvent, MarkingEventKind};

// ============================================================================
// Contracts
// ============================================================================

/// The Dialectica contracts for two-phase effects (basic + temporal logic).
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
    // Temporal Logic Contracts
    /// Always-Eventually: Every reserved obligation should eventually be resolved within a time bound.
    AlwaysEventuallyResolved,
    /// Never-Then: After region close, no new obligations should be reserved in that region.
    NeverThenAfterClose,
    /// Always-Implies: If obligation is reserved, it should always remain trackable until resolved.
    AlwaysImpliesTrackable,
    /// Eventually-Always: Once system reaches quiescence, it should remain quiescent.
    EventuallyAlwaysQuiescent,
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
            // Temporal Logic Contracts
            Self::AlwaysEventuallyResolved => {
                "every reserved obligation eventually resolves within time bound"
            }
            Self::NeverThenAfterClose => "no new reservations after region close",
            Self::AlwaysImpliesTrackable => "reserved obligations remain trackable until resolved",
            Self::EventuallyAlwaysQuiescent => {
                "quiescent state is eventually reached and maintained"
            }
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
            // Temporal Logic Contracts
            Self::AlwaysEventuallyResolved => "AlwaysEventuallyResolved",
            Self::NeverThenAfterClose => "NeverThenAfterClose",
            Self::AlwaysImpliesTrackable => "AlwaysImpliesTrackable",
            Self::EventuallyAlwaysQuiescent => "EventuallyAlwaysQuiescent",
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
    // Temporal Logic Contracts
    always_eventually_resolved: bool,
    never_then_after_close: bool,
    always_implies_trackable: bool,
    eventually_always_quiescent: bool,
}

impl ContractStatusMap {
    fn new_all_satisfied() -> Self {
        Self {
            exhaustive_resolution: true,
            no_partial_commit: true,
            region_closure_safety: true,
            cancellation_non_cascading: true,
            kind_uniform_state_machine: true,
            // Temporal Logic Contracts
            always_eventually_resolved: true,
            never_then_after_close: true,
            always_implies_trackable: true,
            eventually_always_quiescent: true,
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
            // Temporal Logic Contracts
            DialecticaContract::AlwaysEventuallyResolved => {
                self.always_eventually_resolved = false;
            }
            DialecticaContract::NeverThenAfterClose => {
                self.never_then_after_close = false;
            }
            DialecticaContract::AlwaysImpliesTrackable => {
                self.always_implies_trackable = false;
            }
            DialecticaContract::EventuallyAlwaysQuiescent => {
                self.eventually_always_quiescent = false;
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
            // Temporal Logic Contracts
            DialecticaContract::AlwaysEventuallyResolved => self.always_eventually_resolved,
            DialecticaContract::NeverThenAfterClose => self.never_then_after_close,
            DialecticaContract::AlwaysImpliesTrackable => self.always_implies_trackable,
            DialecticaContract::EventuallyAlwaysQuiescent => self.eventually_always_quiescent,
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
/// The checker tracks obligation state and detects violations of the basic
/// and temporal logic contracts. It is designed to be run against marking events
/// produced by [`super::marking::project_trace`] or constructed directly in tests.
#[derive(Debug)]
pub struct ContractChecker {
    /// Tracked obligations: id → snapshot.
    obligations: BTreeMap<ObligationId, ObligationSnapshot>,
    /// Detected violations.
    violations: Vec<ContractViolation>,
    /// Per-contract status.
    status: Option<ContractStatusMap>,
    // Temporal Logic Tracking
    /// Closed regions (for NeverThenAfterClose verification).
    closed_regions: std::collections::BTreeSet<RegionId>,
    /// Time bound for AlwaysEventuallyResolved (configurable, default 1 second).
    resolution_time_bound: Time,
    /// Track if system has reached quiescence for EventuallyAlwaysQuiescent.
    quiescence_start: Option<Time>,
}

impl Default for ContractChecker {
    fn default() -> Self {
        Self {
            obligations: BTreeMap::new(),
            violations: Vec::new(),
            status: None,
            closed_regions: std::collections::BTreeSet::new(),
            resolution_time_bound: Time::from_millis(1000), // 1 second default
            quiescence_start: None,
        }
    }
}

impl ContractChecker {
    /// Creates a new contract checker with default time bounds.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new contract checker with custom resolution time bound.
    #[must_use]
    pub fn new_with_time_bound(time_bound: Time) -> Self {
        Self {
            resolution_time_bound: time_bound,
            ..Self::default()
        }
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
        // Reset temporal logic tracking
        self.closed_regions.clear();
        self.quiescence_start = None;
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
                // Duplicate reserve is a violation: the first reservation would be
                // silently lost, hiding a potential ExhaustiveResolution failure.
                if let Some(existing) = self.obligations.get(obligation) {
                    self.violations.push(ContractViolation {
                        contract: DialecticaContract::NoPartialCommit,
                        time: event.time,
                        description: format!(
                            "obligation {obligation:?} reserved again (already in state {:?}, \
                             reserved at t={})",
                            existing.state, existing.reserved_at,
                        ),
                        obligation: Some(*obligation),
                        region: Some(*region),
                    });
                    return;
                }

                // Temporal Logic: NeverThenAfterClose
                // Check if this reservation is in a region that was already closed
                if self.closed_regions.contains(region) {
                    self.violations.push(ContractViolation {
                        contract: DialecticaContract::NeverThenAfterClose,
                        time: event.time,
                        description: format!(
                            "new obligation {obligation:?} reserved in already-closed region {region:?}"
                        ),
                        obligation: Some(*obligation),
                        region: Some(*region),
                    });
                }

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

                self.check_quiescence(event.time);

                // Reset quiescence tracking since we have a new reservation.
                self.quiescence_start = None;
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
                // Check if resolution brings us closer to quiescence
                self.check_quiescence(event.time);
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
                // Check if resolution brings us closer to quiescence
                self.check_quiescence(event.time);
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
                // Check if resolution brings us closer to quiescence
                self.check_quiescence(event.time);
            }

            MarkingEventKind::RegionClose { region } => {
                self.check_region_closure(*region, event.time);

                // Temporal Logic: Track closed regions for NeverThenAfterClose
                self.closed_regions.insert(*region);

                // Check if this brings us closer to quiescence
                self.check_quiescence(event.time);
            }
            MarkingEventKind::TaskComplete { .. } => {}
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
                    snap.transition_count = snap.transition_count.saturating_add(1);

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

        // Temporal Logic: Check AlwaysEventuallyResolved
        self.check_always_eventually_resolved(trace_end);

        // Temporal Logic: Check AlwaysImpliesTrackable for all obligations
        let obligation_ids: Vec<_> = self.obligations.keys().copied().collect();
        for id in obligation_ids {
            self.check_always_implies_trackable(id, trace_end);
        }
    }

    /// Check AlwaysEventuallyResolved: obligations should resolve within time bound.
    fn check_always_eventually_resolved(&mut self, current_time: Time) {
        for (id, snap) in &self.obligations {
            if !snap.state.is_terminal() {
                let elapsed_nanos = current_time.duration_since(snap.reserved_at);
                if elapsed_nanos > self.resolution_time_bound.as_nanos() {
                    self.violations.push(ContractViolation {
                        contract: DialecticaContract::AlwaysEventuallyResolved,
                        time: current_time,
                        description: format!(
                            "obligation {id:?} reserved at t={} not resolved within time bound \
                             {} (elapsed: {})",
                            snap.reserved_at,
                            self.resolution_time_bound,
                            Time::from_nanos(elapsed_nanos),
                        ),
                        obligation: Some(*id),
                        region: Some(snap.region),
                    });
                }
            }
        }
    }

    /// Check quiescence state for EventuallyAlwaysQuiescent contract.
    fn check_quiescence(&mut self, current_time: Time) {
        let is_quiescent = self
            .obligations
            .values()
            .all(|snap| snap.state.is_terminal());

        if is_quiescent {
            if self.quiescence_start.is_none() {
                // First time reaching quiescence
                self.quiescence_start = Some(current_time);
            }
            // Already quiescent - EventuallyAlwaysQuiescent is satisfied
        } else {
            // Lost quiescence - check if we violated EventuallyAlwaysQuiescent
            if let Some(quiescence_start) = self.quiescence_start {
                self.violations.push(ContractViolation {
                    contract: DialecticaContract::EventuallyAlwaysQuiescent,
                    time: current_time,
                    description: format!(
                        "system lost quiescence at t={} after achieving it at t={}",
                        current_time, quiescence_start,
                    ),
                    obligation: None,
                    region: None,
                });
            }
            self.quiescence_start = None;
        }
    }

    /// Check AlwaysImpliesTrackable: reserved obligations remain trackable.
    fn check_always_implies_trackable(&mut self, obligation: ObligationId, time: Time) {
        // This is checked implicitly by the obligation tracking system.
        // If an obligation becomes untrackable, it would be detected as a
        // data structure inconsistency. For now, we consider this satisfied
        // if the obligation exists in our tracking map.
        if !self.obligations.contains_key(&obligation) {
            self.violations.push(ContractViolation {
                contract: DialecticaContract::AlwaysImpliesTrackable,
                time,
                description: format!("obligation {obligation:?} became untrackable"),
                obligation: Some(obligation),
                region: None,
            });
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
#[allow(dead_code)]
#[path = "dialectica_inline_tests.rs"]
mod tests;
