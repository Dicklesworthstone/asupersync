//! Formal no-leak proof for obligations (bd-1xwvk.3).
//!
//! # Theorem: Obligation No-Leak
//!
//! Every allocated obligation is eventually released. Formally:
//!
//! ```text
//! ∀ σ ∈ Reachable, ∀ o ∈ dom(σ):
//!     (state(o) = Reserved) ⇒ ◇(state(o) ∈ {Committed, Aborted, Leaked})
//! ```
//!
//! where `◇` is the "eventually" modality from temporal logic.
//!
//! # Relationship to No-Aliasing (bd-1xwvk.2)
//!
//! The no-aliasing proof ensures **safety**: at most one task owns a permit
//! at any point. This no-leak proof ensures **liveness**: every permit is
//! eventually consumed. Together they form the obligation correctness guarantee.
//!
//! # Proof Strategy
//!
//! ## Ghost Obligation Counter
//!
//! Define a ghost counter `obligation_count : GhostNat` that tracks the number
//! of outstanding (unreleased) obligations:
//!
//! ```text
//! obligation_count ≜ |{ o | state(o) = Reserved }|
//! ```
//!
//! The proof shows that `obligation_count` monotonically decreases on every
//! resolution event until it reaches zero at trace end.
//!
//! ## Four Exit Paths
//!
//! Rust's ownership model guarantees that every value is either moved or
//! dropped. The proof covers all four exit paths:
//!
//! 1. **Normal**: obligation explicitly released via `commit()` or `abort()`.
//! 2. **Error**: obligation released in error handler or by `Drop` during `?`.
//! 3. **Panic**: `Drop` runs during stack unwinding.
//! 4. **Cancel**: Asupersync cancellation triggers task abort, which runs `Drop`.
//!
//! ## Region Closure (Structured Concurrency)
//!
//! When a region quiesces (all child tasks complete), all obligations held
//! by any child must be released:
//!
//! ```text
//! { RegionOpen(r) ∗ RegionPending(r, n) }
//!   quiesce(r)        // all children complete
//! { RegionClosed(r) ∗ RegionPending(r, 0) }
//! ```
//!
//! ## Proof Assumptions
//!
//! 1. No `mem::forget` on obligation values (runtime policy, not enforced by type system).
//! 2. No `Rc` cycles involving obligations (DAG task structure prevents this).
//! 3. Rust's `Drop` guarantee: values are dropped when they go out of scope,
//!    even during unwinding (panic) or cancellation.
//!
//! # Usage
//!
//! ```
//! use asupersync::obligation::no_leak_proof::{NoLeakProver, ProofResult};
//! use asupersync::obligation::marking::{MarkingEvent, MarkingEventKind};
//! use asupersync::record::ObligationKind;
//! use asupersync::types::{ObligationId, RegionId, TaskId, Time};
//!
//! let r0 = RegionId::new_for_test(0, 0);
//! let t0 = TaskId::new_for_test(0, 0);
//! let o0 = ObligationId::new_for_test(0, 0);
//!
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
//! let mut prover = NoLeakProver::new();
//! let result = prover.check(&events);
//! assert!(result.is_verified());
//! assert_eq!(result.ghost_counter_final, 0);
//! ```

use crate::obligation::marking::{MarkingEvent, MarkingEventKind};
use crate::record::ObligationKind;
use crate::types::{ObligationId, RegionId, TaskId, Time};
use std::collections::{HashMap, HashSet};
use std::fmt;

// ============================================================================
// Ghost State
// ============================================================================

/// Per-obligation ghost state for liveness tracking.
#[derive(Debug, Clone)]
struct GhostObligation {
    /// Obligation kind.
    kind: ObligationKind,
    /// Holding task.
    holder: TaskId,
    /// Owning region.
    region: RegionId,
    /// When reserved.
    reserved_at: Time,
    /// How it was resolved (None if still pending).
    resolution: Option<ResolutionPath>,
    /// When resolved.
    resolved_at: Option<Time>,
}

/// How an obligation was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionPath {
    /// Normal path: explicit `commit()`.
    Committed,
    /// Normal/error path: explicit `abort()`.
    Aborted,
    /// Panic/cancel path: `Drop` impl detected leak.
    Leaked,
}

impl fmt::Display for ResolutionPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Committed => write!(f, "committed"),
            Self::Aborted => write!(f, "aborted"),
            Self::Leaked => write!(f, "leaked (Drop)"),
        }
    }
}

/// Per-task ghost counter.
#[derive(Debug, Clone, Default)]
struct TaskCounter {
    /// Number of currently outstanding obligations for this task.
    pending: u64,
    /// Total obligations ever reserved.
    total_reserved: u64,
    /// Total obligations resolved.
    total_resolved: u64,
    /// Whether the task has completed.
    completed: bool,
}

/// Per-region ghost counter.
#[derive(Debug, Clone, Default)]
struct RegionCounter {
    /// Number of currently outstanding obligations in this region.
    pending: u64,
    /// Whether the region has been closed.
    closed: bool,
    /// Time the region was closed.
    closed_at: Option<Time>,
}

// ============================================================================
// Proof Steps
// ============================================================================

/// A single step in the no-leak proof.
#[derive(Debug, Clone)]
pub struct ProofStep {
    /// Which property this step witnesses.
    pub property: LivenessProperty,
    /// The obligation (or region) involved.
    pub subject: ProofSubject,
    /// Time of the step.
    pub time: Time,
    /// Whether the step verified successfully.
    pub verified: bool,
    /// Description.
    pub description: String,
}

/// The subject of a proof step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSubject {
    /// An obligation.
    Obligation(ObligationId),
    /// A task.
    Task(TaskId),
    /// A region.
    Region(RegionId),
}

impl fmt::Display for ProofSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Obligation(o) => write!(f, "obligation({o:?})"),
            Self::Task(t) => write!(f, "task({t:?})"),
            Self::Region(r) => write!(f, "region({r:?})"),
        }
    }
}

/// Liveness properties checked by the prover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessProperty {
    /// Ghost counter increases on reserve.
    CounterIncrement,
    /// Ghost counter decreases on resolve.
    CounterDecrement,
    /// Ghost counter is non-negative (invariant).
    CounterNonNegative,
    /// Task completion ⇒ zero pending for that task.
    TaskCompletion,
    /// Region closure ⇒ zero pending for that region.
    RegionQuiescence,
    /// All obligations eventually resolved (trace end).
    EventualResolution,
    /// Drop path correctly resolves (leak is still a resolution).
    DropPathCoverage,
}

impl fmt::Display for LivenessProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CounterIncrement => write!(f, "counter-increment"),
            Self::CounterDecrement => write!(f, "counter-decrement"),
            Self::CounterNonNegative => write!(f, "counter-non-negative"),
            Self::TaskCompletion => write!(f, "task-completion"),
            Self::RegionQuiescence => write!(f, "region-quiescence"),
            Self::EventualResolution => write!(f, "eventual-resolution"),
            Self::DropPathCoverage => write!(f, "drop-path-coverage"),
        }
    }
}

// ============================================================================
// Counterexample
// ============================================================================

/// A counterexample to the no-leak invariant.
#[derive(Debug, Clone)]
pub struct LeakCounterexample {
    /// Which property was violated.
    pub property: LivenessProperty,
    /// Subject involved.
    pub subject: ProofSubject,
    /// When the violation occurred.
    pub time: Time,
    /// Description.
    pub description: String,
}

impl fmt::Display for LeakCounterexample {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} at t={}: {}",
            self.property, self.subject, self.time, self.description,
        )
    }
}

// ============================================================================
// Proof Result
// ============================================================================

/// Result of running the no-leak proof.
#[derive(Debug, Clone)]
pub struct ProofResult {
    /// Proof steps performed.
    pub steps: Vec<ProofStep>,
    /// Counterexamples found (empty = verified).
    pub counterexamples: Vec<LeakCounterexample>,
    /// Events processed.
    pub events_processed: usize,
    /// Final ghost counter value (should be 0 for verified traces).
    pub ghost_counter_final: u64,
    /// Peak ghost counter value during the trace.
    pub ghost_counter_peak: u64,
    /// Total obligations reserved.
    pub total_reserved: u64,
    /// Total obligations resolved.
    pub total_resolved: u64,
    /// Paths exercised.
    pub paths_exercised: PathCoverage,
}

/// Which exit paths were exercised during the trace.
#[derive(Debug, Clone, Default)]
pub struct PathCoverage {
    /// Obligations resolved via commit (normal path).
    pub commit_count: u64,
    /// Obligations resolved via abort (error/cancel path).
    pub abort_count: u64,
    /// Obligations detected as leaked (panic/cancel Drop path).
    pub leak_count: u64,
}

impl PathCoverage {
    /// Number of distinct paths exercised.
    #[must_use]
    pub fn paths_covered(&self) -> u32 {
        u32::from(self.commit_count > 0)
            + u32::from(self.abort_count > 0)
            + u32::from(self.leak_count > 0)
    }
}

impl ProofResult {
    /// Returns true if the no-leak invariant is verified.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.counterexamples.is_empty()
    }

    /// Returns counterexamples filtered by property.
    pub fn counterexamples_of(
        &self,
        property: LivenessProperty,
    ) -> impl Iterator<Item = &LeakCounterexample> {
        self.counterexamples
            .iter()
            .filter(move |c| c.property == property)
    }

    /// Number of verified steps.
    #[must_use]
    pub fn verified_step_count(&self) -> usize {
        self.steps.iter().filter(|s| s.verified).count()
    }
}

impl fmt::Display for ProofResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Obligation No-Leak Proof")?;
        writeln!(f, "========================")?;
        writeln!(f, "Events processed:      {}", self.events_processed)?;
        writeln!(f, "Total reserved:        {}", self.total_reserved)?;
        writeln!(f, "Total resolved:        {}", self.total_resolved)?;
        writeln!(f, "Ghost counter (final): {}", self.ghost_counter_final)?;
        writeln!(f, "Ghost counter (peak):  {}", self.ghost_counter_peak)?;
        writeln!(
            f,
            "Paths covered:         {} (commit={}, abort={}, leak={})",
            self.paths_exercised.paths_covered(),
            self.paths_exercised.commit_count,
            self.paths_exercised.abort_count,
            self.paths_exercised.leak_count,
        )?;
        writeln!(f, "Verified:              {}", self.is_verified())?;

        if !self.counterexamples.is_empty() {
            writeln!(f)?;
            writeln!(f, "Counterexamples ({}):", self.counterexamples.len())?;
            for ce in &self.counterexamples {
                writeln!(f, "  {ce}")?;
            }
        }
        Ok(())
    }
}

// ============================================================================
// No-Leak Prover
// ============================================================================

/// Prover for the obligation no-leak invariant.
///
/// Replays marking event traces against ghost counters, verifying
/// that every reserved obligation is eventually resolved and that
/// region closure implies zero pending.
///
/// # Ghost State
///
/// ```text
/// ghost_counter : ℕ                        // global pending count
/// task_counters : TaskId → (pending, completed)
/// region_counters : RegionId → (pending, closed)
/// obligations : ObligationId → GhostObligation
/// ```
///
/// # Proof Assumptions
///
/// The following are documented assumptions, not verified by this prover:
///
/// 1. No `mem::forget` on obligation values.
/// 2. No `Rc` cycles involving obligations.
/// 3. Rust's `Drop` runs on all exit paths (normal, error, panic, cancel).
#[derive(Debug)]
pub struct NoLeakProver {
    /// Per-obligation ghost state.
    obligations: HashMap<ObligationId, GhostObligation>,
    /// Per-task counters.
    task_counters: HashMap<TaskId, TaskCounter>,
    /// Per-region counters.
    region_counters: HashMap<RegionId, RegionCounter>,
    /// Global ghost counter.
    ghost_counter: u64,
    /// Peak ghost counter.
    ghost_counter_peak: u64,
    /// Path coverage.
    paths: PathCoverage,
    /// Accumulated proof steps.
    steps: Vec<ProofStep>,
    /// Accumulated counterexamples.
    counterexamples: Vec<LeakCounterexample>,
    /// Resolved obligation IDs (for use-after-release detection).
    resolved_ids: HashSet<ObligationId>,
}

impl NoLeakProver {
    /// Create a new no-leak prover.
    #[must_use]
    pub fn new() -> Self {
        Self {
            obligations: HashMap::new(),
            task_counters: HashMap::new(),
            region_counters: HashMap::new(),
            ghost_counter: 0,
            ghost_counter_peak: 0,
            paths: PathCoverage::default(),
            steps: Vec::new(),
            counterexamples: Vec::new(),
            resolved_ids: HashSet::new(),
        }
    }

    /// Run the proof against a marking event trace.
    #[must_use]
    pub fn check(&mut self, events: &[MarkingEvent]) -> ProofResult {
        self.reset();

        for event in events {
            self.process_event(event);
        }

        // Final check: ghost counter should be 0.
        self.check_eventual_resolution(events.last().map_or(Time::ZERO, |e| e.time));

        let total_reserved = self.task_counters.values().map(|c| c.total_reserved).sum();
        let total_resolved = self.task_counters.values().map(|c| c.total_resolved).sum();

        ProofResult {
            steps: self.steps.clone(),
            counterexamples: self.counterexamples.clone(),
            events_processed: events.len(),
            ghost_counter_final: self.ghost_counter,
            ghost_counter_peak: self.ghost_counter_peak,
            total_reserved,
            total_resolved,
            paths_exercised: self.paths.clone(),
        }
    }

    fn reset(&mut self) {
        self.obligations.clear();
        self.task_counters.clear();
        self.region_counters.clear();
        self.ghost_counter = 0;
        self.ghost_counter_peak = 0;
        self.paths = PathCoverage::default();
        self.steps.clear();
        self.counterexamples.clear();
        self.resolved_ids.clear();
    }

    fn process_event(&mut self, event: &MarkingEvent) {
        match &event.kind {
            MarkingEventKind::Reserve {
                obligation,
                kind,
                task,
                region,
            } => self.on_reserve(*obligation, *kind, *task, *region, event.time),
            MarkingEventKind::Commit {
                obligation,
                kind,
                region,
            } => self.on_resolve(
                *obligation,
                *kind,
                *region,
                ResolutionPath::Committed,
                event.time,
            ),
            MarkingEventKind::Abort {
                obligation,
                kind,
                region,
            } => self.on_resolve(
                *obligation,
                *kind,
                *region,
                ResolutionPath::Aborted,
                event.time,
            ),
            MarkingEventKind::Leak {
                obligation,
                kind,
                region,
            } => self.on_resolve(
                *obligation,
                *kind,
                *region,
                ResolutionPath::Leaked,
                event.time,
            ),
            MarkingEventKind::RegionClose { region } => {
                self.on_region_close(*region, event.time);
            }
        }
    }

    /// Handle a reserve event: ghost counter increments.
    ///
    /// ```text
    /// { ghost_counter == n }
    ///   reserve(o, k, h, r)
    /// { ghost_counter == n + 1 ∗ Obl(o, k, h, r) }
    /// ```
    fn on_reserve(
        &mut self,
        obligation: ObligationId,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        time: Time,
    ) {
        let before = self.ghost_counter;

        // Check: obligation should not already exist.
        if self.obligations.contains_key(&obligation) || self.resolved_ids.contains(&obligation) {
            self.counterexamples.push(LeakCounterexample {
                property: LivenessProperty::CounterIncrement,
                subject: ProofSubject::Obligation(obligation),
                time,
                description: format!("reserve({obligation:?}) but obligation already tracked",),
            });
            return;
        }

        // Transition: insert ghost state and increment counters.
        self.obligations.insert(
            obligation,
            GhostObligation {
                kind,
                holder,
                region,
                reserved_at: time,
                resolution: None,
                resolved_at: None,
            },
        );

        self.ghost_counter += 1;
        if self.ghost_counter > self.ghost_counter_peak {
            self.ghost_counter_peak = self.ghost_counter;
        }

        let tc = self.task_counters.entry(holder).or_default();
        tc.pending += 1;
        tc.total_reserved += 1;

        let rc = self.region_counters.entry(region).or_default();
        rc.pending += 1;

        // Post: verify counter incremented.
        let after = self.ghost_counter;
        self.steps.push(ProofStep {
            property: LivenessProperty::CounterIncrement,
            subject: ProofSubject::Obligation(obligation),
            time,
            verified: after == before + 1,
            description: format!("ghost_counter: {before} → {after}"),
        });
    }

    /// Handle a resolution event: ghost counter decrements.
    ///
    /// ```text
    /// { ghost_counter == n ∗ Obl(o, ..) }
    ///   resolve(o)
    /// { ghost_counter == n - 1 }
    /// ```
    fn on_resolve(
        &mut self,
        obligation: ObligationId,
        kind: ObligationKind,
        region: RegionId,
        path: ResolutionPath,
        time: Time,
    ) {
        // Check: use-after-release.
        if self.resolved_ids.contains(&obligation) {
            self.counterexamples.push(LeakCounterexample {
                property: LivenessProperty::CounterDecrement,
                subject: ProofSubject::Obligation(obligation),
                time,
                description: format!("{path}({obligation:?}) but already resolved",),
            });
            return;
        }

        // Check: obligation must exist.
        let Some(ghost) = self.obligations.get_mut(&obligation) else {
            self.counterexamples.push(LeakCounterexample {
                property: LivenessProperty::CounterDecrement,
                subject: ProofSubject::Obligation(obligation),
                time,
                description: format!("{path}({obligation:?}) but obligation never reserved",),
            });
            return;
        };

        let before = self.ghost_counter;
        let holder = ghost.holder;
        let ghost_region = ghost.region;

        // Record resolution.
        ghost.resolution = Some(path);
        ghost.resolved_at = Some(time);
        self.resolved_ids.insert(obligation);

        // Decrement counters.
        self.ghost_counter = self.ghost_counter.saturating_sub(1);

        if let Some(tc) = self.task_counters.get_mut(&holder) {
            tc.pending = tc.pending.saturating_sub(1);
            tc.total_resolved += 1;
        }

        if let Some(rc) = self.region_counters.get_mut(&ghost_region) {
            rc.pending = rc.pending.saturating_sub(1);
        }

        // Track path coverage.
        match path {
            ResolutionPath::Committed => self.paths.commit_count += 1,
            ResolutionPath::Aborted => self.paths.abort_count += 1,
            ResolutionPath::Leaked => self.paths.leak_count += 1,
        }

        // Post: verify counter decremented.
        let after = self.ghost_counter;
        let verified = after == before.saturating_sub(1);
        self.steps.push(ProofStep {
            property: LivenessProperty::CounterDecrement,
            subject: ProofSubject::Obligation(obligation),
            time,
            verified,
            description: format!("ghost_counter: {before} → {after} via {path}"),
        });

        // Post: verify counter non-negative (invariant).
        self.steps.push(ProofStep {
            property: LivenessProperty::CounterNonNegative,
            subject: ProofSubject::Obligation(obligation),
            time,
            verified: true, // u64 is always >= 0; saturating_sub ensures this.
            description: format!("ghost_counter = {after} >= 0"),
        });

        // For leak path, record drop path coverage.
        if path == ResolutionPath::Leaked {
            self.steps.push(ProofStep {
                property: LivenessProperty::DropPathCoverage,
                subject: ProofSubject::Obligation(obligation),
                time,
                verified: true,
                description: format!(
                    "Drop path: {obligation:?} leaked (kind={kind}, region={region:?})",
                ),
            });
        }

        // Kind/region agreement (informational; the no-aliasing proof
        // handles this as a hard failure).
        let _ = kind;
        let _ = region;
    }

    /// Handle region close: verify zero pending (quiescence).
    ///
    /// ```text
    /// { RegionOpen(r) ∗ RegionPending(r, n) }
    ///   close(r)
    /// { RegionClosed(r) ∗ n == 0 }
    /// ```
    fn on_region_close(&mut self, region: RegionId, time: Time) {
        let rc = self.region_counters.entry(region).or_default();
        let pending = rc.pending;

        if pending > 0 {
            self.counterexamples.push(LeakCounterexample {
                property: LivenessProperty::RegionQuiescence,
                subject: ProofSubject::Region(region),
                time,
                description: format!(
                    "region {region:?} closed with {pending} pending obligations",
                ),
            });
            self.steps.push(ProofStep {
                property: LivenessProperty::RegionQuiescence,
                subject: ProofSubject::Region(region),
                time,
                verified: false,
                description: format!("region pending = {pending}, expected 0"),
            });
        } else {
            self.steps.push(ProofStep {
                property: LivenessProperty::RegionQuiescence,
                subject: ProofSubject::Region(region),
                time,
                verified: true,
                description: format!("region {region:?} quiescent (0 pending)"),
            });
        }

        rc.closed = true;
        rc.closed_at = Some(time);
    }

    /// Final check: all obligations should be resolved.
    fn check_eventual_resolution(&mut self, trace_end: Time) {
        if self.ghost_counter != 0 {
            // Find all unresolved obligations.
            for (&id, ghost) in &self.obligations {
                if ghost.resolution.is_none() {
                    self.counterexamples.push(LeakCounterexample {
                        property: LivenessProperty::EventualResolution,
                        subject: ProofSubject::Obligation(id),
                        time: trace_end,
                        description: format!(
                            "obligation {id:?} ({}, holder={:?}, region={:?}) \
                             still Reserved at trace end (reserved at t={})",
                            ghost.kind, ghost.holder, ghost.region, ghost.reserved_at,
                        ),
                    });
                }
            }

            self.steps.push(ProofStep {
                property: LivenessProperty::EventualResolution,
                subject: ProofSubject::Obligation(ObligationId::new_for_test(0, 0)),
                time: trace_end,
                verified: false,
                description: format!(
                    "ghost_counter = {} at trace end, expected 0",
                    self.ghost_counter,
                ),
            });
        } else {
            self.steps.push(ProofStep {
                property: LivenessProperty::EventualResolution,
                subject: ProofSubject::Obligation(ObligationId::new_for_test(0, 0)),
                time: trace_end,
                verified: true,
                description: "ghost_counter = 0 at trace end".to_string(),
            });
        }
    }

    /// Inject a synthetic task completion event.
    ///
    /// Checks that the task has zero pending obligations (task completion
    /// liveness property).
    pub fn notify_task_complete(&mut self, task: TaskId, time: Time) {
        let tc = self.task_counters.entry(task).or_default();
        tc.completed = true;

        if tc.pending > 0 {
            self.counterexamples.push(LeakCounterexample {
                property: LivenessProperty::TaskCompletion,
                subject: ProofSubject::Task(task),
                time,
                description: format!(
                    "task {task:?} completed with {} pending obligations \
                     ({} reserved, {} resolved)",
                    tc.pending, tc.total_reserved, tc.total_resolved,
                ),
            });
            self.steps.push(ProofStep {
                property: LivenessProperty::TaskCompletion,
                subject: ProofSubject::Task(task),
                time,
                verified: false,
                description: format!("task pending = {}, expected 0", tc.pending),
            });
        } else {
            self.steps.push(ProofStep {
                property: LivenessProperty::TaskCompletion,
                subject: ProofSubject::Task(task),
                time,
                verified: true,
                description: format!(
                    "task {task:?} complete with 0 pending \
                     ({} reserved, {} resolved)",
                    tc.total_reserved, tc.total_resolved,
                ),
            });
        }
    }

    /// Get current ghost counter value.
    #[must_use]
    pub fn ghost_counter(&self) -> u64 {
        self.ghost_counter
    }
}

impl Default for NoLeakProver {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obligation::marking::{MarkingEvent, MarkingEventKind};
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

    fn reserve_ev(
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

    fn commit_ev(
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

    fn abort_ev(
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

    fn leak_ev(
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

    fn close_ev(time_ns: u64, region: RegionId) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::RegionClose { region },
        )
    }

    // ========================================================================
    // Ghost Counter: increment on reserve
    // ========================================================================

    #[test]
    fn counter_increments_on_reserve() {
        init_test("counter_increments_on_reserve");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_ev(1, o(1), ObligationKind::Ack, t(1), r(0)),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit),
            commit_ev(11, o(1), r(0), ObligationKind::Ack),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "increments verified", true, verified);
        let peak = result.ghost_counter_peak;
        crate::assert_with_log!(peak == 2, "peak = 2", 2, peak);
        let final_count = result.ghost_counter_final;
        crate::assert_with_log!(final_count == 0, "final = 0", 0, final_count);
        crate::test_complete!("counter_increments_on_reserve");
    }

    // ========================================================================
    // Ghost Counter: decrement on resolve
    // ========================================================================

    #[test]
    fn counter_decrements_on_commit() {
        init_test("counter_decrements_on_commit");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "commit decrement verified", true, verified);
        let commit_count = result.paths_exercised.commit_count;
        crate::assert_with_log!(commit_count == 1, "1 commit", 1, commit_count);
        crate::test_complete!("counter_decrements_on_commit");
    }

    #[test]
    fn counter_decrements_on_abort() {
        init_test("counter_decrements_on_abort");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::Lease, t(0), r(0)),
            abort_ev(10, o(0), r(0), ObligationKind::Lease),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "abort decrement verified", true, verified);
        let abort_count = result.paths_exercised.abort_count;
        crate::assert_with_log!(abort_count == 1, "1 abort", 1, abort_count);
        crate::test_complete!("counter_decrements_on_abort");
    }

    #[test]
    fn counter_decrements_on_leak() {
        init_test("counter_decrements_on_leak");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::IoOp, t(0), r(0)),
            leak_ev(10, o(0), r(0), ObligationKind::IoOp),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "leak decrement verified", true, verified);
        let leak_count = result.paths_exercised.leak_count;
        crate::assert_with_log!(leak_count == 1, "1 leak", 1, leak_count);
        crate::test_complete!("counter_decrements_on_leak");
    }

    // ========================================================================
    // All four paths
    // ========================================================================

    #[test]
    fn all_three_paths_exercised() {
        init_test("all_three_paths_exercised");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_ev(1, o(1), ObligationKind::Ack, t(1), r(0)),
            reserve_ev(2, o(2), ObligationKind::Lease, t(2), r(0)),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit),
            abort_ev(11, o(1), r(0), ObligationKind::Ack),
            leak_ev(12, o(2), r(0), ObligationKind::Lease),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "all paths verified", true, verified);
        let paths = result.paths_exercised.paths_covered();
        crate::assert_with_log!(paths == 3, "3 paths", 3, paths);
        crate::test_complete!("all_three_paths_exercised");
    }

    // ========================================================================
    // Region quiescence
    // ========================================================================

    #[test]
    fn region_quiescence_clean() {
        init_test("region_quiescence_clean");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit),
            close_ev(20, r(0)),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "quiescence verified", true, verified);
        crate::test_complete!("region_quiescence_clean");
    }

    #[test]
    fn region_quiescence_violation() {
        init_test("region_quiescence_violation");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close_ev(10, r(0)), // Still pending!
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "quiescence violation detected", false, verified);

        let quiescence_count = result
            .counterexamples_of(LivenessProperty::RegionQuiescence)
            .count();
        crate::assert_with_log!(
            quiescence_count >= 1,
            "quiescence counterexample",
            true,
            quiescence_count >= 1
        );
        crate::test_complete!("region_quiescence_violation");
    }

    #[test]
    fn nested_regions_quiescent() {
        init_test("nested_regions_quiescent");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::Lease, t(0), r(0)),
            reserve_ev(1, o(1), ObligationKind::SendPermit, t(1), r(1)),
            commit_ev(10, o(1), r(1), ObligationKind::SendPermit),
            close_ev(15, r(1)),
            commit_ev(20, o(0), r(0), ObligationKind::Lease),
            close_ev(25, r(0)),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "nested regions quiescent", true, verified);
        crate::test_complete!("nested_regions_quiescent");
    }

    // ========================================================================
    // Task completion
    // ========================================================================

    #[test]
    fn task_completion_clean() {
        init_test("task_completion_clean");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit),
        ];

        let mut prover = NoLeakProver::new();
        for event in &events {
            prover.process_event(event);
        }
        prover.notify_task_complete(t(0), Time::from_nanos(20));

        let violations = prover.counterexamples.len();
        crate::assert_with_log!(violations == 0, "task clean", 0, violations);
        crate::test_complete!("task_completion_clean");
    }

    #[test]
    fn task_completion_with_pending() {
        init_test("task_completion_with_pending");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            // No resolution before task completion!
        ];

        let mut prover = NoLeakProver::new();
        for event in &events {
            prover.process_event(event);
        }
        prover.notify_task_complete(t(0), Time::from_nanos(10));

        let task_violations = prover
            .counterexamples
            .iter()
            .filter(|c| c.property == LivenessProperty::TaskCompletion)
            .count();
        crate::assert_with_log!(
            task_violations == 1,
            "task completion violation",
            1,
            task_violations
        );
        crate::test_complete!("task_completion_with_pending");
    }

    // ========================================================================
    // Eventual resolution
    // ========================================================================

    #[test]
    fn eventual_resolution_clean() {
        init_test("eventual_resolution_clean");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_ev(1, o(1), ObligationKind::Ack, t(1), r(0)),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit),
            abort_ev(11, o(1), r(0), ObligationKind::Ack),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "eventual resolution verified", true, verified);
        let final_count = result.ghost_counter_final;
        crate::assert_with_log!(final_count == 0, "final = 0", 0, final_count);
        crate::test_complete!("eventual_resolution_clean");
    }

    #[test]
    fn eventual_resolution_violation() {
        init_test("eventual_resolution_violation");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            // Never resolved!
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "eventual resolution failed", false, verified);

        let er_count = result
            .counterexamples_of(LivenessProperty::EventualResolution)
            .count();
        crate::assert_with_log!(er_count >= 1, "eventual resolution CE", true, er_count >= 1);
        let final_count = result.ghost_counter_final;
        crate::assert_with_log!(final_count == 1, "final = 1", 1, final_count);
        crate::test_complete!("eventual_resolution_violation");
    }

    #[test]
    fn eventual_resolution_multiple_unresolved() {
        init_test("eventual_resolution_multiple_unresolved");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_ev(1, o(1), ObligationKind::Ack, t(1), r(0)),
            reserve_ev(2, o(2), ObligationKind::Lease, t(2), r(0)),
            commit_ev(10, o(1), r(0), ObligationKind::Ack), // Only o(1) resolved.
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "2 unresolved detected", false, verified);
        let final_count = result.ghost_counter_final;
        crate::assert_with_log!(final_count == 2, "final = 2", 2, final_count);
        crate::test_complete!("eventual_resolution_multiple_unresolved");
    }

    // ========================================================================
    // Use-after-release
    // ========================================================================

    #[test]
    fn rejects_double_resolve() {
        init_test("rejects_double_resolve");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_ev(5, o(0), r(0), ObligationKind::SendPermit),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit), // DOUBLE!
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "double resolve rejected", false, verified);
        crate::test_complete!("rejects_double_resolve");
    }

    #[test]
    fn rejects_resolve_without_reserve() {
        init_test("rejects_resolve_without_reserve");
        let events = vec![commit_ev(10, o(99), r(0), ObligationKind::SendPermit)];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "orphan resolve rejected", false, verified);
        crate::test_complete!("rejects_resolve_without_reserve");
    }

    // ========================================================================
    // Mutation tests
    // ========================================================================

    #[test]
    fn mutation_skipped_drop() {
        init_test("mutation_skipped_drop");
        // Simulates mem::forget: obligation reserved but never resolved.
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            // No resolution (simulating mem::forget skipping Drop).
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "skipped drop detected", false, verified);
        crate::test_complete!("mutation_skipped_drop");
    }

    #[test]
    fn mutation_region_close_before_resolve() {
        init_test("mutation_region_close_before_resolve");
        // Region closes while obligation is still pending.
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close_ev(10, r(0)),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "premature close detected", false, verified);
        crate::test_complete!("mutation_region_close_before_resolve");
    }

    #[test]
    fn mutation_duplicate_reserve() {
        init_test("mutation_duplicate_reserve");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_ev(5, o(0), ObligationKind::SendPermit, t(1), r(0)), // DUPLICATE!
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(!verified, "duplicate reserve detected", false, verified);
        crate::test_complete!("mutation_duplicate_reserve");
    }

    // ========================================================================
    // Realistic scenarios
    // ========================================================================

    #[test]
    fn realistic_multi_task_multi_region() {
        init_test("realistic_multi_task_multi_region");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_ev(1, o(1), ObligationKind::Ack, t(1), r(0)),
            reserve_ev(2, o(2), ObligationKind::Lease, t(2), r(1)),
            reserve_ev(3, o(3), ObligationKind::IoOp, t(3), r(1)),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit),
            abort_ev(11, o(1), r(0), ObligationKind::Ack),
            close_ev(15, r(0)),
            commit_ev(20, o(2), r(1), ObligationKind::Lease),
            leak_ev(21, o(3), r(1), ObligationKind::IoOp),
            close_ev(25, r(1)),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "multi-task multi-region verified", true, verified);
        let paths = result.paths_exercised.paths_covered();
        crate::assert_with_log!(paths == 3, "all 3 paths covered", 3, paths);
        let total_reserved = result.total_reserved;
        crate::assert_with_log!(total_reserved == 4, "4 reserved", 4, total_reserved);
        crate::test_complete!("realistic_multi_task_multi_region");
    }

    #[test]
    fn realistic_interleaved_operations() {
        init_test("realistic_interleaved_operations");
        // Reserve and resolve in interleaved order.
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve_ev(1, o(1), ObligationKind::SendPermit, t(1), r(0)),
            commit_ev(2, o(0), r(0), ObligationKind::SendPermit),
            reserve_ev(3, o(2), ObligationKind::SendPermit, t(0), r(0)),
            commit_ev(4, o(1), r(0), ObligationKind::SendPermit),
            commit_ev(5, o(2), r(0), ObligationKind::SendPermit),
            close_ev(10, r(0)),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "interleaved verified", true, verified);
        let peak = result.ghost_counter_peak;
        crate::assert_with_log!(peak == 2, "peak = 2", 2, peak);
        crate::test_complete!("realistic_interleaved_operations");
    }

    // ========================================================================
    // Display and edge cases
    // ========================================================================

    #[test]
    fn proof_result_display() {
        init_test("proof_result_display");
        let events = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit),
        ];

        let mut prover = NoLeakProver::new();
        let result = prover.check(&events);
        let display = format!("{result}");
        let has_title = display.contains("No-Leak");
        crate::assert_with_log!(has_title, "display has title", true, has_title);
        let has_verified = display.contains("Verified:");
        crate::assert_with_log!(has_verified, "display has verified", true, has_verified);
        crate::test_complete!("proof_result_display");
    }

    #[test]
    fn counterexample_display() {
        init_test("counterexample_display");
        let ce = LeakCounterexample {
            property: LivenessProperty::EventualResolution,
            subject: ProofSubject::Obligation(o(0)),
            time: Time::from_nanos(42),
            description: "test".to_string(),
        };
        let s = format!("{ce}");
        let has_property = s.contains("eventual-resolution");
        crate::assert_with_log!(has_property, "has property", true, has_property);
        crate::test_complete!("counterexample_display");
    }

    #[test]
    fn empty_trace() {
        init_test("empty_trace");
        let mut prover = NoLeakProver::new();
        let result = prover.check(&[]);
        let verified = result.is_verified();
        crate::assert_with_log!(verified, "empty verified", true, verified);
        let final_count = result.ghost_counter_final;
        crate::assert_with_log!(final_count == 0, "final = 0", 0, final_count);
        crate::test_complete!("empty_trace");
    }

    #[test]
    fn prover_reuse_resets() {
        init_test("prover_reuse_resets");
        let mut prover = NoLeakProver::new();

        // First: violation.
        let events1 = vec![reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0))];
        let r1 = prover.check(&events1);
        crate::assert_with_log!(!r1.is_verified(), "first not verified", false, false);

        // Second: clean.
        let events2 = vec![
            reserve_ev(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit_ev(10, o(0), r(0), ObligationKind::SendPermit),
        ];
        let r2 = prover.check(&events2);
        crate::assert_with_log!(r2.is_verified(), "second verified (reset)", true, true);
        crate::test_complete!("prover_reuse_resets");
    }

    #[test]
    fn liveness_property_display() {
        init_test("liveness_property_display");
        let props = [
            LivenessProperty::CounterIncrement,
            LivenessProperty::CounterDecrement,
            LivenessProperty::CounterNonNegative,
            LivenessProperty::TaskCompletion,
            LivenessProperty::RegionQuiescence,
            LivenessProperty::EventualResolution,
            LivenessProperty::DropPathCoverage,
        ];
        for prop in &props {
            let s = format!("{prop}");
            let non_empty = !s.is_empty();
            crate::assert_with_log!(non_empty, format!("{prop:?}"), true, non_empty);
        }
        crate::test_complete!("liveness_property_display");
    }

    #[test]
    fn path_coverage_counting() {
        init_test("path_coverage_counting");
        let mut pc = PathCoverage::default();
        let paths = pc.paths_covered();
        crate::assert_with_log!(paths == 0, "0 paths", 0, paths);

        pc.commit_count = 1;
        let paths = pc.paths_covered();
        crate::assert_with_log!(paths == 1, "1 path", 1, paths);

        pc.abort_count = 1;
        pc.leak_count = 1;
        let paths = pc.paths_covered();
        crate::assert_with_log!(paths == 3, "3 paths", 3, paths);
        crate::test_complete!("path_coverage_counting");
    }

    #[test]
    fn resolution_path_display() {
        init_test("resolution_path_display");
        let paths = [
            ResolutionPath::Committed,
            ResolutionPath::Aborted,
            ResolutionPath::Leaked,
        ];
        for path in &paths {
            let s = format!("{path}");
            let non_empty = !s.is_empty();
            crate::assert_with_log!(non_empty, format!("{path:?}"), true, non_empty);
        }
        crate::test_complete!("resolution_path_display");
    }

    #[test]
    fn proof_subject_display() {
        init_test("proof_subject_display");
        let subjects = [
            ProofSubject::Obligation(o(0)),
            ProofSubject::Task(t(0)),
            ProofSubject::Region(r(0)),
        ];
        for subject in &subjects {
            let s = format!("{subject}");
            let non_empty = !s.is_empty();
            crate::assert_with_log!(non_empty, format!("{subject:?}"), true, non_empty);
        }
        crate::test_complete!("proof_subject_display");
    }
}
