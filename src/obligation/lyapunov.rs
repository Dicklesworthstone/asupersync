//! Lyapunov-guided scheduling governor for cancellation convergence.
//!
//! # Purpose
//!
//! A Lyapunov function `V(Σ)` maps runtime state `Σ` to a non-negative real
//! number such that `V` decreases along valid scheduling trajectories toward
//! quiescence. This provides a principled argument that cancellation converges:
//!
//! ```text
//! V(Σ) ≥ 0           (non-negativity)
//! V(Σ) = 0 ⟺ Σ is quiescent  (zero iff quiescent)
//! Σ →ₛ Σ' ⟹ V(Σ') ≤ V(Σ)    (monotone decrease under scheduling steps)
//! ```
//!
//! # Potential Function
//!
//! The candidate potential function combines four observable components:
//!
//! ```text
//! V(Σ) = w_t · |live_tasks(Σ)|
//!      + w_o · Σ_{o ∈ obligations} age(o, now)
//!      + w_r · |draining_regions(Σ)|
//!      + w_d · Σ_{t ∈ tasks} max(0, 1 - slack(t, now) / D₀)
//! ```
//!
//! Where:
//! - `w_t, w_o, w_r, w_d` are non-negative weights
//! - `live_tasks(Σ)` = tasks not in terminal state
//! - `age(o, now)` = `now - o.reserved_at` for pending obligations
//! - `draining_regions(Σ)` = regions in Draining/Finalizing state
//! - `slack(t, now)` = `t.deadline - now` (positive = ahead, negative = overdue)
//! - `D₀` = normalization constant for deadline slack
//!
//! # Governor
//!
//! The [`LyapunovGovernor`] observes runtime state, computes the potential,
//! and produces scheduling priority suggestions that preferentially schedule
//! tasks whose completion maximally decreases `V`.
//!
//! # Usage
//!
//! ```
//! use asupersync::obligation::lyapunov::{
//!     LyapunovGovernor, PotentialWeights, StateSnapshot, SchedulingSuggestion,
//! };
//! use asupersync::types::Time;
//!
//! let weights = PotentialWeights::default();
//! let mut governor = LyapunovGovernor::new(weights);
//!
//! // Take a snapshot of runtime state.
//! let snapshot = StateSnapshot {
//!     time: Time::ZERO,
//!     live_tasks: 5,
//!     pending_obligations: 3,
//!     obligation_age_sum_ns: 150,
//!     draining_regions: 1,
//!     deadline_pressure: 0.0,
//!     pending_send_permits: 3,
//!     pending_acks: 0,
//!     pending_leases: 0,
//!     pending_io_ops: 0,
//!     cancel_requested_tasks: 0,
//!     cancelling_tasks: 0,
//!     finalizing_tasks: 0,
//!     ready_queue_depth: 0,
//! };
//!
//! let v = governor.compute_potential(&snapshot);
//! assert!(v > 0.0);
//!
//! // After some scheduling steps...
//! let snapshot2 = StateSnapshot {
//!     time: Time::from_nanos(100),
//!     live_tasks: 3,
//!     pending_obligations: 1,
//!     obligation_age_sum_ns: 50,
//!     draining_regions: 0,
//!     deadline_pressure: 0.0,
//!     pending_send_permits: 1,
//!     pending_acks: 0,
//!     pending_leases: 0,
//!     pending_io_ops: 0,
//!     cancel_requested_tasks: 0,
//!     cancelling_tasks: 0,
//!     finalizing_tasks: 0,
//!     ready_queue_depth: 0,
//! };
//!
//! let v2 = governor.compute_potential(&snapshot2);
//! assert!(v2 < v);
//! ```

use crate::types::Time;
use std::fmt;

// ============================================================================
// Potential Weights
// ============================================================================

/// Weights for the Lyapunov potential function components.
///
/// Each weight must be non-negative. The default weights are tuned for
/// cancellation drain scenarios where obligation resolution is the bottleneck.
#[derive(Debug, Clone, Copy)]
pub struct PotentialWeights {
    /// Weight for live task count.
    pub w_tasks: f64,
    /// Weight for pending obligation age (ns).
    pub w_obligation_age: f64,
    /// Weight for draining/finalizing region count.
    pub w_draining_regions: f64,
    /// Weight for deadline pressure.
    pub w_deadline_pressure: f64,
}

impl PotentialWeights {
    /// Creates weights with all components equal.
    #[must_use]
    pub const fn uniform(w: f64) -> Self {
        Self {
            w_tasks: w,
            w_obligation_age: w,
            w_draining_regions: w,
            w_deadline_pressure: w,
        }
    }

    /// Creates weights emphasizing obligation drain (cancel-aware scheduling).
    #[must_use]
    pub const fn obligation_focused() -> Self {
        Self {
            w_tasks: 1.0,
            w_obligation_age: 10.0,
            w_draining_regions: 5.0,
            w_deadline_pressure: 2.0,
        }
    }

    /// Creates weights emphasizing deadline compliance.
    #[must_use]
    pub const fn deadline_focused() -> Self {
        Self {
            w_tasks: 1.0,
            w_obligation_age: 2.0,
            w_draining_regions: 3.0,
            w_deadline_pressure: 10.0,
        }
    }

    /// Validates that all weights are finite and non-negative.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.w_tasks >= 0.0
            && self.w_tasks.is_finite()
            && self.w_obligation_age >= 0.0
            && self.w_obligation_age.is_finite()
            && self.w_draining_regions >= 0.0
            && self.w_draining_regions.is_finite()
            && self.w_deadline_pressure >= 0.0
            && self.w_deadline_pressure.is_finite()
    }
}

impl Default for PotentialWeights {
    fn default() -> Self {
        Self {
            w_tasks: 1.0,
            w_obligation_age: 5.0,
            w_draining_regions: 3.0,
            w_deadline_pressure: 2.0,
        }
    }
}

// ============================================================================
// State Snapshot
// ============================================================================

/// A snapshot of observable runtime state for potential computation.
///
/// This is a lightweight aggregate of the state components that feed
/// the Lyapunov potential function. It can be constructed from
/// `RuntimeState` or assembled manually in tests.
#[derive(Debug, Clone)]
pub struct StateSnapshot {
    /// Current virtual time.
    pub time: Time,
    /// Number of live (non-terminal) tasks.
    pub live_tasks: u32,
    /// Number of pending (unresolved) obligations (total).
    pub pending_obligations: u32,
    /// Sum of ages (in nanoseconds) of all pending obligations.
    ///
    /// `Σ (now - obligation.reserved_at)` for each pending obligation.
    pub obligation_age_sum_ns: u64,
    /// Number of regions in Draining or Finalizing state.
    pub draining_regions: u32,
    /// Aggregate deadline pressure in `[0.0, ∞)`.
    ///
    /// Sum of `max(0, 1 - slack / D₀)` for each task with a deadline,
    /// where `slack = deadline - now` and `D₀` is a normalization constant.
    pub deadline_pressure: f64,

    // -- Per-kind obligation breakdown (bd-3rih) --
    /// Pending `SendPermit` obligations.
    pub pending_send_permits: u32,
    /// Pending `Ack` obligations.
    pub pending_acks: u32,
    /// Pending `Lease` obligations.
    pub pending_leases: u32,
    /// Pending `IoOp` obligations (in-flight I/O count).
    pub pending_io_ops: u32,

    // -- Cancellation phase counts (bd-3rih) --
    /// Tasks in `CancelRequested` state (cancel signal sent, not yet acknowledged).
    pub cancel_requested_tasks: u32,
    /// Tasks in `Cancelling` state (running cleanup code).
    pub cancelling_tasks: u32,
    /// Tasks in `Finalizing` state (running finalizers).
    pub finalizing_tasks: u32,

    // -- Queue depth signals (bd-3rih) --
    // These cannot be extracted from `RuntimeState` alone because the
    // scheduler is a separate component. Callers set them after snapshot
    // construction via `with_ready_queue_depth`, or leave them at zero.
    /// Approximate number of tasks sitting in the ready queue.
    pub ready_queue_depth: u32,
}

impl StateSnapshot {
    /// Constructs a snapshot from a live [`RuntimeState`](crate::runtime::RuntimeState).
    ///
    /// Design goals:
    /// - deterministic: only depends on `state` (no ambient time / RNG)
    /// - bounded + allocation-free: scans arenas; does not allocate
    /// - resilient: if a task's `CxInner` lock is poisoned, deadline contribution is skipped
    #[must_use]
    pub fn from_runtime_state(state: &crate::runtime::RuntimeState) -> Self {
        use crate::record::obligation::ObligationKind;

        // Deadline pressure normalization constant D₀ (see module docs).
        // 1s is an intentionally "coarse" knob: pressure reflects tasks that are
        // within ~1s of their deadline (or overdue), not far-future deadlines.
        const DEADLINE_PRESSURE_D0_NS: u64 = 1_000_000_000;

        let now = state.now;

        // -- Task scan: one pass to collect live count, cancel-phase counts,
        //    and deadline pressure. --

        let mut live_tasks: u32 = 0;
        let mut cancel_requested_tasks: u32 = 0;
        let mut cancelling_tasks: u32 = 0;
        let mut finalizing_tasks: u32 = 0;
        let mut deadline_pressure = 0.0_f64;

        for (_, task) in state.tasks_iter() {
            if task.state.is_terminal() {
                continue;
            }
            live_tasks = live_tasks.saturating_add(1);

            // Count cancellation phases.
            match &task.state {
                crate::record::task::TaskState::CancelRequested { .. } => {
                    cancel_requested_tasks = cancel_requested_tasks.saturating_add(1);
                }
                crate::record::task::TaskState::Cancelling { .. } => {
                    cancelling_tasks = cancelling_tasks.saturating_add(1);
                }
                crate::record::task::TaskState::Finalizing { .. } => {
                    finalizing_tasks = finalizing_tasks.saturating_add(1);
                }
                _ => {}
            }

            // Deadline pressure contribution.
            let Some(cx_inner) = task.cx_inner.as_ref() else {
                continue;
            };
            let inner = cx_inner.read();
            let Some(deadline) = inner.budget.deadline else {
                continue;
            };

            let deadline_ns = i128::from(deadline.as_nanos());
            let now_ns = i128::from(now.as_nanos());
            let slack_ns = deadline_ns - now_ns;
            #[allow(clippy::cast_precision_loss)]
            let slack = slack_ns as f64;
            #[allow(clippy::cast_precision_loss)]
            let d0 = DEADLINE_PRESSURE_D0_NS as f64;

            let term = 1.0 - (slack / d0);
            if term > 0.0 {
                deadline_pressure += term;
            }
        }

        // -- Obligation scan: one pass to collect totals + per-kind breakdown. --

        let mut pending_obligations: u32 = 0;
        let mut obligation_age_sum_ns: u64 = 0;
        let mut pending_send_permits: u32 = 0;
        let mut pending_acks: u32 = 0;
        let mut pending_leases: u32 = 0;
        let mut pending_io_ops: u32 = 0;

        for (_, obligation) in state.obligations_iter() {
            if !obligation.is_pending() {
                continue;
            }
            pending_obligations = pending_obligations.saturating_add(1);
            obligation_age_sum_ns =
                obligation_age_sum_ns.saturating_add(now.duration_since(obligation.reserved_at));

            match obligation.kind {
                ObligationKind::SendPermit => {
                    pending_send_permits = pending_send_permits.saturating_add(1);
                }
                ObligationKind::Ack => {
                    pending_acks = pending_acks.saturating_add(1);
                }
                ObligationKind::Lease => {
                    pending_leases = pending_leases.saturating_add(1);
                }
                ObligationKind::IoOp => {
                    pending_io_ops = pending_io_ops.saturating_add(1);
                }
            }
        }

        // -- Region scan: one pass for draining count. --

        let mut draining_regions: u32 = 0;
        for (_, region) in state.regions_iter() {
            match region.state() {
                crate::record::region::RegionState::Draining
                | crate::record::region::RegionState::Finalizing => {
                    draining_regions = draining_regions.saturating_add(1);
                }
                _ => {}
            }
        }

        Self {
            time: now,
            live_tasks,
            pending_obligations,
            obligation_age_sum_ns,
            draining_regions,
            deadline_pressure,
            pending_send_permits,
            pending_acks,
            pending_leases,
            pending_io_ops,
            cancel_requested_tasks,
            cancelling_tasks,
            finalizing_tasks,
            ready_queue_depth: 0, // Set by caller via `with_ready_queue_depth`.
        }
    }

    /// Returns true if the snapshot represents quiescent state
    /// (all activity metrics are zero, consistent with V(Σ) = 0).
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.live_tasks == 0
            && self.pending_obligations == 0
            && self.draining_regions == 0
            && self.deadline_pressure == 0.0
    }

    /// Sets the ready queue depth signal.
    ///
    /// This must be called separately because the scheduler is not accessible
    /// from `RuntimeState` alone. Returns `self` for chaining.
    #[must_use]
    pub fn with_ready_queue_depth(mut self, depth: u32) -> Self {
        self.ready_queue_depth = depth;
        self
    }

    /// Total tasks in any cancellation phase
    /// (`CancelRequested` + `Cancelling` + `Finalizing`).
    #[must_use]
    pub fn total_cancelling_tasks(&self) -> u32 {
        self.cancel_requested_tasks
            .saturating_add(self.cancelling_tasks)
            .saturating_add(self.finalizing_tasks)
    }
}

impl fmt::Display for StateSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Σ(t={}, tasks={}, obligations={}[sp={},ack={},lease={},io={}], \
             age_sum={}ns, draining={}, cancel={}/{}/{}, queue={}, deadline_p={:.2})",
            self.time,
            self.live_tasks,
            self.pending_obligations,
            self.pending_send_permits,
            self.pending_acks,
            self.pending_leases,
            self.pending_io_ops,
            self.obligation_age_sum_ns,
            self.draining_regions,
            self.cancel_requested_tasks,
            self.cancelling_tasks,
            self.finalizing_tasks,
            self.ready_queue_depth,
            self.deadline_pressure,
        )
    }
}

// ============================================================================
// Potential Record
// ============================================================================

/// The computed potential with component breakdown.
#[derive(Debug, Clone)]
pub struct PotentialRecord {
    /// The snapshot used to compute this potential.
    pub snapshot: StateSnapshot,
    /// Total potential value.
    pub total: f64,
    /// Contribution from live tasks.
    pub task_component: f64,
    /// Contribution from obligation age.
    pub obligation_component: f64,
    /// Contribution from draining regions.
    pub region_component: f64,
    /// Contribution from deadline pressure.
    pub deadline_component: f64,
}

impl PotentialRecord {
    /// Returns true if the potential is zero (quiescent).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.total == 0.0
    }
}

impl fmt::Display for PotentialRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "V={:.2} [tasks={:.2}, obligations={:.2}, regions={:.2}, deadlines={:.2}]",
            self.total,
            self.task_component,
            self.obligation_component,
            self.region_component,
            self.deadline_component,
        )
    }
}

// ============================================================================
// Scheduling Suggestion
// ============================================================================

/// A scheduling suggestion from the governor.
///
/// The governor suggests which class of tasks should be prioritized
/// to maximally decrease the potential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulingSuggestion {
    /// Prioritize tasks holding pending obligations (maximize obligation drain).
    DrainObligations,
    /// Prioritize tasks in draining regions (maximize region cleanup).
    DrainRegions,
    /// Prioritize tasks with tight deadlines (minimize deadline violations).
    MeetDeadlines,
    /// No preference — any scheduling order is acceptable.
    NoPreference,
}

impl SchedulingSuggestion {
    /// Returns a short description.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::DrainObligations => "prioritize obligation holders",
            Self::DrainRegions => "prioritize draining region tasks",
            Self::MeetDeadlines => "prioritize deadline-critical tasks",
            Self::NoPreference => "no scheduling preference",
        }
    }
}

impl fmt::Display for SchedulingSuggestion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

// ============================================================================
// Convergence Verdict
// ============================================================================

/// Verdict from convergence analysis.
#[derive(Debug, Clone)]
pub struct ConvergenceVerdict {
    /// Whether the potential is monotonically non-increasing.
    pub monotone: bool,
    /// Whether the final state is quiescent (V = 0).
    pub reached_quiescence: bool,
    /// Maximum potential observed.
    pub v_max: f64,
    /// Final potential observed.
    pub v_final: f64,
    /// Number of steps where potential increased (violations).
    pub increase_count: usize,
    /// Maximum single-step increase (worst violation).
    pub max_increase: f64,
    /// Total number of steps analyzed.
    pub steps: usize,
}

impl ConvergenceVerdict {
    /// Returns true if the system converged (monotone + quiescent).
    #[must_use]
    pub fn converged(&self) -> bool {
        self.monotone && self.reached_quiescence
    }
}

impl fmt::Display for ConvergenceVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Convergence Verdict")?;
        writeln!(f, "===================")?;
        writeln!(f, "Steps:      {}", self.steps)?;
        writeln!(f, "Monotone:   {}", self.monotone)?;
        writeln!(f, "Quiescent:  {}", self.reached_quiescence)?;
        writeln!(f, "Converged:  {}", self.converged())?;
        writeln!(f, "V_max:      {:.4}", self.v_max)?;
        writeln!(f, "V_final:    {:.4}", self.v_final)?;
        if !self.monotone {
            writeln!(f, "Violations: {}", self.increase_count)?;
            writeln!(f, "Max increase: {:.4}", self.max_increase)?;
        }
        Ok(())
    }
}

// ============================================================================
// LyapunovGovernor
// ============================================================================

/// Lyapunov-guided scheduling governor.
///
/// Observes runtime state snapshots, computes potential functions, and
/// provides scheduling suggestions that drive the system toward quiescence.
#[derive(Debug)]
pub struct LyapunovGovernor {
    /// Weights for the potential function.
    weights: PotentialWeights,
    /// History of computed potentials (for convergence analysis).
    /// Bounded to `MAX_HISTORY` entries to prevent unbounded memory growth.
    history: Vec<PotentialRecord>,
}

impl LyapunovGovernor {
    /// Maximum number of history entries retained. When exceeded, the oldest
    /// half is discarded to amortise the removal cost.
    const MAX_HISTORY: usize = 8192;

    /// Creates a new governor with the given weights.
    #[must_use]
    pub fn new(weights: PotentialWeights) -> Self {
        assert!(weights.is_valid(), "weights must be non-negative");
        Self {
            weights,
            history: Vec::new(),
        }
    }

    /// Creates a governor with default weights.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(PotentialWeights::default())
    }

    /// Computes the potential function for a state snapshot.
    ///
    /// Records the result in the history for convergence analysis.
    pub fn compute_potential(&mut self, snapshot: &StateSnapshot) -> f64 {
        let record = self.compute(snapshot);
        let total = record.total;
        self.history.push(record);
        if self.history.len() > Self::MAX_HISTORY {
            let drain_count = Self::MAX_HISTORY / 2;
            self.history.drain(..drain_count);
        }
        total
    }

    /// Computes the potential function with full breakdown (does not record).
    #[must_use]
    pub fn compute_record(&self, snapshot: &StateSnapshot) -> PotentialRecord {
        self.compute(snapshot)
    }

    /// Suggests a scheduling action based on the current potential breakdown.
    ///
    /// The suggestion prioritizes the component with the highest weighted
    /// contribution, since reducing that component decreases V most.
    #[must_use]
    pub fn suggest(&self, snapshot: &StateSnapshot) -> SchedulingSuggestion {
        if snapshot.is_quiescent() {
            return SchedulingSuggestion::NoPreference;
        }

        let record = self.compute(snapshot);

        // Find the dominant component.
        let components = [
            (
                record.obligation_component,
                SchedulingSuggestion::DrainObligations,
            ),
            (record.region_component, SchedulingSuggestion::DrainRegions),
            (
                record.deadline_component,
                SchedulingSuggestion::MeetDeadlines,
            ),
        ];

        components
            .iter()
            .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
            .filter(|(v, _)| *v > 0.0)
            .map_or(SchedulingSuggestion::NoPreference, |(_, s)| *s)
    }

    /// Analyzes the recorded history for convergence properties.
    ///
    /// Returns a verdict on whether the potential was monotonically
    /// non-increasing and whether quiescence was reached.
    #[must_use]
    pub fn analyze_convergence(&self) -> ConvergenceVerdict {
        if self.history.is_empty() {
            return ConvergenceVerdict {
                monotone: true,
                reached_quiescence: false,
                v_max: 0.0,
                v_final: 0.0,
                increase_count: 0,
                max_increase: 0.0,
                steps: 0,
            };
        }

        let mut monotone = true;
        let mut increase_count = 0;
        let mut max_increase = 0.0_f64;
        let mut v_max = 0.0_f64;

        for window in self.history.windows(2) {
            let prev = window[0].total;
            let curr = window[1].total;
            v_max = v_max.max(prev).max(curr);

            let delta = curr - prev;
            if delta > f64::EPSILON {
                monotone = false;
                increase_count += 1;
                max_increase = max_increase.max(delta);
            }
        }

        v_max = v_max.max(self.history.first().map_or(0.0, |r| r.total));

        let v_final = self.history.last().map_or(0.0, |r| r.total);
        let reached_quiescence = v_final.abs() < f64::EPSILON;

        ConvergenceVerdict {
            monotone,
            reached_quiescence,
            v_max,
            v_final,
            increase_count,
            max_increase,
            steps: self.history.len(),
        }
    }

    /// Returns the potential history.
    #[must_use]
    pub fn history(&self) -> &[PotentialRecord] {
        &self.history
    }

    /// Clears the history.
    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    /// Returns the weights.
    #[must_use]
    pub const fn weights(&self) -> &PotentialWeights {
        &self.weights
    }

    fn compute(&self, snapshot: &StateSnapshot) -> PotentialRecord {
        let task_component = self.weights.w_tasks * f64::from(snapshot.live_tasks);

        // Normalize obligation age to seconds for stability.
        // Potential is heuristic; precision loss is acceptable for large ages.
        #[allow(clippy::cast_precision_loss)]
        let age_seconds = snapshot.obligation_age_sum_ns as f64 / 1_000_000_000.0;
        let obligation_component = self.weights.w_obligation_age * age_seconds;

        let region_component =
            self.weights.w_draining_regions * f64::from(snapshot.draining_regions);

        let deadline_component = self.weights.w_deadline_pressure * snapshot.deadline_pressure;

        let total = task_component + obligation_component + region_component + deadline_component;

        PotentialRecord {
            snapshot: snapshot.clone(),
            total,
            task_component,
            obligation_component,
            region_component,
            deadline_component,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::runtime::InvariantViolation;
    use crate::record::ObligationKind;
    use crate::runtime::RuntimeState;
    use crate::types::Budget;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn quiescent_snapshot() -> StateSnapshot {
        StateSnapshot {
            time: Time::ZERO,
            live_tasks: 0,
            pending_obligations: 0,
            obligation_age_sum_ns: 0,
            draining_regions: 0,
            deadline_pressure: 0.0,
            pending_send_permits: 0,
            pending_acks: 0,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: 0,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: 0,
        }
    }

    fn active_snapshot(tasks: u32, obligations: u32, age_ns: u64, draining: u32) -> StateSnapshot {
        StateSnapshot {
            time: Time::from_nanos(age_ns),
            live_tasks: tasks,
            pending_obligations: obligations,
            obligation_age_sum_ns: age_ns,
            draining_regions: draining,
            deadline_pressure: 0.0,
            pending_send_permits: obligations, // default: all send permits
            pending_acks: 0,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: 0,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: 0,
        }
    }

    // ---- RuntimeState snapshot extraction ----------------------------------

    #[test]
    fn snapshot_from_runtime_counts_tasks_obligations_and_regions() {
        init_test("snapshot_from_runtime_counts_tasks_obligations_and_regions");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::unlimited());

        let (task_id, _handle) = state
            .create_task(root, Budget::unlimited(), async {})
            .expect("create_task must succeed");

        let obligation_id = state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create_obligation must succeed");

        // Advance time so the obligation has a non-zero age.
        state.now = Time::from_nanos(100);

        let snap = StateSnapshot::from_runtime_state(&state);
        crate::assert_with_log!(snap.time == state.now, "time", state.now, snap.time);
        crate::assert_with_log!(snap.live_tasks == 1, "live_tasks", 1, snap.live_tasks);
        crate::assert_with_log!(
            snap.pending_obligations == 1,
            "pending_obligations",
            1,
            snap.pending_obligations
        );
        crate::assert_with_log!(
            snap.obligation_age_sum_ns == 100,
            "obligation_age_sum_ns",
            100,
            snap.obligation_age_sum_ns
        );
        crate::assert_with_log!(
            snap.draining_regions == 0,
            "draining_regions",
            0,
            snap.draining_regions
        );

        // Per-kind breakdown: the single obligation is a SendPermit.
        crate::assert_with_log!(
            snap.pending_send_permits == 1,
            "pending_send_permits",
            1,
            snap.pending_send_permits
        );
        crate::assert_with_log!(snap.pending_acks == 0, "pending_acks", 0, snap.pending_acks);
        crate::assert_with_log!(
            snap.pending_leases == 0,
            "pending_leases",
            0,
            snap.pending_leases
        );
        crate::assert_with_log!(
            snap.pending_io_ops == 0,
            "pending_io_ops",
            0,
            snap.pending_io_ops
        );

        // Transition region into Draining and verify it contributes.
        {
            let region = state.region(root).expect("root region exists");
            let ok = region.begin_close(None);
            crate::assert_with_log!(ok, "begin_close", true, ok);
            let ok = region.begin_drain();
            crate::assert_with_log!(ok, "begin_drain", true, ok);
        }

        let snap2 = StateSnapshot::from_runtime_state(&state);
        crate::assert_with_log!(
            snap2.draining_regions == 1,
            "draining_regions after begin_drain",
            1,
            snap2.draining_regions
        );

        // Commit the obligation and verify it no longer contributes.
        state
            .commit_obligation(obligation_id)
            .expect("commit_obligation must succeed");

        let snap3 = StateSnapshot::from_runtime_state(&state);
        crate::assert_with_log!(
            snap3.pending_obligations == 0,
            "pending_obligations after commit",
            0,
            snap3.pending_obligations
        );
        crate::assert_with_log!(
            snap3.pending_send_permits == 0,
            "pending_send_permits after commit",
            0,
            snap3.pending_send_permits
        );

        crate::test_complete!("snapshot_from_runtime_counts_tasks_obligations_and_regions");
    }

    #[test]
    fn snapshot_from_runtime_computes_deadline_pressure() {
        init_test("snapshot_from_runtime_computes_deadline_pressure");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::unlimited());

        // With D₀ = 1s (see StateSnapshot::from_runtime_state), a task with
        // 500ms slack contributes 0.5 pressure.
        let (_task_id, _handle) = state
            .create_task(root, Budget::with_deadline_ns(500_000_000), async {})
            .expect("create_task must succeed");

        state.now = Time::ZERO;
        let snap = StateSnapshot::from_runtime_state(&state);
        let expected = 0.5_f64;
        let ok = (snap.deadline_pressure - expected).abs() < 1e-9;
        crate::assert_with_log!(
            ok,
            "deadline_pressure at t=0",
            expected,
            snap.deadline_pressure
        );

        // Past the deadline, slack is negative => contribution exceeds 1.0.
        state.now = Time::from_nanos(600_000_000);
        let snap2 = StateSnapshot::from_runtime_state(&state);
        let expected_overdue = 1.1_f64;
        let ok2 = (snap2.deadline_pressure - expected_overdue).abs() < 1e-9;
        crate::assert_with_log!(
            ok2,
            "deadline_pressure overdue",
            expected_overdue,
            snap2.deadline_pressure
        );

        crate::test_complete!("snapshot_from_runtime_computes_deadline_pressure");
    }

    // ---- bd-3rih: extended snapshot fields -----------------------------------

    #[test]
    fn with_ready_queue_depth_sets_field() {
        init_test("with_ready_queue_depth_sets_field");
        let snap = quiescent_snapshot().with_ready_queue_depth(42);
        crate::assert_with_log!(
            snap.ready_queue_depth == 42,
            "ready_queue_depth",
            42,
            snap.ready_queue_depth
        );
        crate::test_complete!("with_ready_queue_depth_sets_field");
    }

    #[test]
    fn total_cancelling_tasks_sums_phases() {
        init_test("total_cancelling_tasks_sums_phases");
        let mut snap = quiescent_snapshot();
        snap.cancel_requested_tasks = 3;
        snap.cancelling_tasks = 2;
        snap.finalizing_tasks = 1;
        let total = snap.total_cancelling_tasks();
        crate::assert_with_log!(total == 6, "total_cancelling", 6, total);
        crate::test_complete!("total_cancelling_tasks_sums_phases");
    }

    #[test]
    fn per_kind_obligation_breakdown_sums_to_total() {
        init_test("per_kind_obligation_breakdown_sums_to_total");
        let snap = StateSnapshot {
            time: Time::ZERO,
            live_tasks: 4,
            pending_obligations: 7,
            obligation_age_sum_ns: 0,
            draining_regions: 0,
            deadline_pressure: 0.0,
            pending_send_permits: 2,
            pending_acks: 1,
            pending_leases: 3,
            pending_io_ops: 1,
            cancel_requested_tasks: 0,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: 0,
        };
        let sum = snap.pending_send_permits
            + snap.pending_acks
            + snap.pending_leases
            + snap.pending_io_ops;
        crate::assert_with_log!(
            sum == snap.pending_obligations,
            "per-kind sums to total",
            snap.pending_obligations,
            sum
        );
        crate::test_complete!("per_kind_obligation_breakdown_sums_to_total");
    }

    #[test]
    fn display_includes_extended_fields() {
        init_test("display_includes_extended_fields");
        let mut snap = active_snapshot(3, 2, 100_000_000, 1);
        snap.cancel_requested_tasks = 1;
        snap.cancelling_tasks = 1;
        snap.ready_queue_depth = 5;
        let s = format!("{snap}");
        let has_cancel = s.contains("cancel=1/1/0");
        crate::assert_with_log!(has_cancel, "display shows cancel phases", true, has_cancel);
        let has_queue = s.contains("queue=5");
        crate::assert_with_log!(has_queue, "display shows queue depth", true, has_queue);
        let has_kind = s.contains("sp=2");
        crate::assert_with_log!(has_kind, "display shows per-kind", true, has_kind);
        crate::test_complete!("display_includes_extended_fields");
    }

    // ---- Potential function properties --------------------------------------

    #[test]
    fn potential_zero_iff_quiescent() {
        init_test("potential_zero_iff_quiescent");
        let governor = LyapunovGovernor::with_defaults();

        let v = governor.compute_record(&quiescent_snapshot());
        let is_zero = v.is_zero();
        crate::assert_with_log!(is_zero, "quiescent is zero", true, is_zero);

        let v_active = governor.compute_record(&active_snapshot(1, 0, 0, 0));
        let not_zero = !v_active.is_zero();
        crate::assert_with_log!(not_zero, "active is not zero", true, not_zero);
        crate::test_complete!("potential_zero_iff_quiescent");
    }

    #[test]
    fn potential_non_negative() {
        init_test("potential_non_negative");
        let governor = LyapunovGovernor::with_defaults();

        // Test many state combinations.
        let configs = [
            (0, 0, 0, 0),
            (1, 0, 0, 0),
            (0, 1, 100, 0),
            (5, 3, 1000, 2),
            (100, 50, 1_000_000_000, 10),
        ];

        for (tasks, obligations, age, draining) in configs {
            let snap = active_snapshot(tasks, obligations, age, draining);
            let v = governor.compute_record(&snap);
            let non_neg = v.total >= 0.0;
            crate::assert_with_log!(non_neg, format!("non-negative for {snap}"), true, non_neg);
        }
        crate::test_complete!("potential_non_negative");
    }

    #[test]
    fn potential_increases_with_more_tasks() {
        init_test("potential_increases_with_more_tasks");
        let governor = LyapunovGovernor::with_defaults();

        let v1 = governor.compute_record(&active_snapshot(1, 0, 0, 0));
        let v2 = governor.compute_record(&active_snapshot(5, 0, 0, 0));
        let v3 = governor.compute_record(&active_snapshot(10, 0, 0, 0));

        let inc1 = v2.total > v1.total;
        crate::assert_with_log!(inc1, "more tasks = higher V", true, inc1);
        let inc2 = v3.total > v2.total;
        crate::assert_with_log!(inc2, "even more tasks", true, inc2);
        crate::test_complete!("potential_increases_with_more_tasks");
    }

    #[test]
    fn potential_increases_with_obligation_age() {
        init_test("potential_increases_with_obligation_age");
        let governor = LyapunovGovernor::with_defaults();

        let v1 = governor.compute_record(&active_snapshot(1, 1, 100, 0));
        let v2 = governor.compute_record(&active_snapshot(1, 1, 1_000_000_000, 0));

        let inc = v2.total > v1.total;
        crate::assert_with_log!(inc, "older obligations = higher V", true, inc);
        crate::test_complete!("potential_increases_with_obligation_age");
    }

    #[test]
    fn potential_increases_with_draining_regions() {
        init_test("potential_increases_with_draining_regions");
        let governor = LyapunovGovernor::with_defaults();

        let v1 = governor.compute_record(&active_snapshot(1, 0, 0, 0));
        let v2 = governor.compute_record(&active_snapshot(1, 0, 0, 3));

        let inc = v2.total > v1.total;
        crate::assert_with_log!(inc, "draining regions increase V", true, inc);
        crate::test_complete!("potential_increases_with_draining_regions");
    }

    #[test]
    fn potential_deadline_pressure() {
        init_test("potential_deadline_pressure");
        let governor = LyapunovGovernor::with_defaults();

        let snap_no_pressure = StateSnapshot {
            time: Time::ZERO,
            live_tasks: 1,
            pending_obligations: 0,
            obligation_age_sum_ns: 0,
            draining_regions: 0,
            deadline_pressure: 0.0,
            pending_send_permits: 0,
            pending_acks: 0,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: 0,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: 0,
        };

        let v1 = governor.compute_record(&snap_no_pressure);
        let snap_high_pressure = StateSnapshot {
            deadline_pressure: 5.0,
            ..snap_no_pressure
        };
        let v2 = governor.compute_record(&snap_high_pressure);

        let inc = v2.total > v1.total;
        crate::assert_with_log!(inc, "deadline pressure increases V", true, inc);
        crate::test_complete!("potential_deadline_pressure");
    }

    // ---- Convergence properties --------------------------------------------

    #[test]
    fn convergence_monotone_drain() {
        init_test("convergence_monotone_drain");
        // Simulate a monotone cancellation drain:
        // Tasks and obligations decrease over time.
        let mut governor = LyapunovGovernor::with_defaults();

        let trajectory = vec![
            active_snapshot(10, 5, 500_000_000, 3),
            active_snapshot(8, 4, 400_000_000, 3),
            active_snapshot(6, 3, 250_000_000, 2),
            active_snapshot(4, 2, 100_000_000, 1),
            active_snapshot(2, 1, 30_000_000, 1),
            active_snapshot(1, 0, 0, 0),
            quiescent_snapshot(),
        ];

        for snap in &trajectory {
            governor.compute_potential(snap);
        }

        let verdict = governor.analyze_convergence();
        let mono = verdict.monotone;
        crate::assert_with_log!(mono, "monotone", true, mono);
        let converged = verdict.converged();
        crate::assert_with_log!(converged, "converged", true, converged);
        let v_final = verdict.v_final;
        crate::assert_with_log!(v_final == 0.0, "v_final", 0.0, v_final);
        crate::test_complete!("convergence_monotone_drain");
    }

    #[test]
    fn convergence_non_monotone_detected() {
        init_test("convergence_non_monotone_detected");
        // A trajectory where the potential temporarily increases
        // (e.g., new work spawned during drain).
        let mut governor = LyapunovGovernor::with_defaults();

        let trajectory = vec![
            active_snapshot(5, 2, 100_000_000, 1),
            active_snapshot(3, 1, 50_000_000, 1),
            active_snapshot(6, 3, 200_000_000, 2), // Spike: new work!
            active_snapshot(4, 2, 100_000_000, 1),
            active_snapshot(1, 0, 0, 0),
            quiescent_snapshot(),
        ];

        for snap in &trajectory {
            governor.compute_potential(snap);
        }

        let verdict = governor.analyze_convergence();
        let not_mono = !verdict.monotone;
        crate::assert_with_log!(not_mono, "not monotone", true, not_mono);
        let violations = verdict.increase_count;
        crate::assert_with_log!(violations >= 1, "has violations", true, violations >= 1);
        // Still reaches quiescence.
        let quiescent = verdict.reached_quiescence;
        crate::assert_with_log!(quiescent, "reached quiescence", true, quiescent);
        crate::test_complete!("convergence_non_monotone_detected");
    }

    #[test]
    fn convergence_stuck_not_quiescent() {
        init_test("convergence_stuck_not_quiescent");
        // A trajectory that levels off without reaching quiescence.
        let mut governor = LyapunovGovernor::with_defaults();

        let trajectory = vec![
            active_snapshot(5, 3, 300_000_000, 2),
            active_snapshot(3, 2, 200_000_000, 1),
            active_snapshot(2, 2, 200_000_000, 1),
            active_snapshot(2, 2, 200_000_000, 1), // Stuck.
        ];

        for snap in &trajectory {
            governor.compute_potential(snap);
        }

        let verdict = governor.analyze_convergence();
        let not_converged = !verdict.converged();
        crate::assert_with_log!(not_converged, "not converged", true, not_converged);
        let not_quiescent = !verdict.reached_quiescence;
        crate::assert_with_log!(not_quiescent, "not quiescent", true, not_quiescent);
        crate::test_complete!("convergence_stuck_not_quiescent");
    }

    // ---- Scheduling suggestions --------------------------------------------

    #[test]
    fn suggest_no_preference_when_quiescent() {
        init_test("suggest_no_preference_when_quiescent");
        let governor = LyapunovGovernor::with_defaults();
        let suggestion = governor.suggest(&quiescent_snapshot());
        let is_no_pref = suggestion == SchedulingSuggestion::NoPreference;
        crate::assert_with_log!(is_no_pref, "no preference when quiescent", true, is_no_pref);
        crate::test_complete!("suggest_no_preference_when_quiescent");
    }

    #[test]
    fn suggest_drain_obligations_when_dominant() {
        init_test("suggest_drain_obligations_when_dominant");
        let governor = LyapunovGovernor::new(PotentialWeights::obligation_focused());

        let snap = StateSnapshot {
            time: Time::from_nanos(1_000_000_000),
            live_tasks: 1,
            pending_obligations: 10,
            obligation_age_sum_ns: 5_000_000_000, // 5 seconds total age.
            draining_regions: 0,
            deadline_pressure: 0.0,
            pending_send_permits: 10,
            pending_acks: 0,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: 0,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: 0,
        };

        let suggestion = governor.suggest(&snap);
        let is_obligations = suggestion == SchedulingSuggestion::DrainObligations;
        crate::assert_with_log!(
            is_obligations,
            "suggests draining obligations",
            true,
            is_obligations
        );
        crate::test_complete!("suggest_drain_obligations_when_dominant");
    }

    #[test]
    fn suggest_drain_regions_when_dominant() {
        init_test("suggest_drain_regions_when_dominant");
        let governor = LyapunovGovernor::with_defaults();

        let snap = StateSnapshot {
            time: Time::ZERO,
            live_tasks: 1,
            pending_obligations: 0,
            obligation_age_sum_ns: 0,
            draining_regions: 10, // Many draining regions.
            deadline_pressure: 0.0,
            pending_send_permits: 0,
            pending_acks: 0,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: 0,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: 0,
        };

        let suggestion = governor.suggest(&snap);
        let is_regions = suggestion == SchedulingSuggestion::DrainRegions;
        crate::assert_with_log!(is_regions, "suggests draining regions", true, is_regions);
        crate::test_complete!("suggest_drain_regions_when_dominant");
    }

    #[test]
    fn suggest_meet_deadlines_when_dominant() {
        init_test("suggest_meet_deadlines_when_dominant");
        let governor = LyapunovGovernor::new(PotentialWeights::deadline_focused());

        let snap = StateSnapshot {
            time: Time::ZERO,
            live_tasks: 1,
            pending_obligations: 0,
            obligation_age_sum_ns: 0,
            draining_regions: 0,
            deadline_pressure: 10.0, // Heavy deadline pressure.
            pending_send_permits: 0,
            pending_acks: 0,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: 0,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: 0,
        };

        let suggestion = governor.suggest(&snap);
        let is_deadlines = suggestion == SchedulingSuggestion::MeetDeadlines;
        crate::assert_with_log!(
            is_deadlines,
            "suggests meeting deadlines",
            true,
            is_deadlines
        );
        crate::test_complete!("suggest_meet_deadlines_when_dominant");
    }

    // ---- Weight configurations ---------------------------------------------

    #[test]
    fn weights_uniform() {
        init_test("weights_uniform");
        let w = PotentialWeights::uniform(1.0);
        let valid = w.is_valid();
        crate::assert_with_log!(valid, "uniform valid", true, valid);
        let eps = f64::EPSILON;
        let all_eq = (w.w_tasks - w.w_obligation_age).abs() < eps
            && (w.w_obligation_age - w.w_draining_regions).abs() < eps
            && (w.w_draining_regions - w.w_deadline_pressure).abs() < eps;
        crate::assert_with_log!(all_eq, "all equal", true, all_eq);
        crate::test_complete!("weights_uniform");
    }

    #[test]
    fn weights_obligation_focused() {
        init_test("weights_obligation_focused");
        let w = PotentialWeights::obligation_focused();
        let valid = w.is_valid();
        crate::assert_with_log!(valid, "obligation focused valid", true, valid);
        let ob_dominant = w.w_obligation_age > w.w_tasks;
        crate::assert_with_log!(
            ob_dominant,
            "obligations weighted higher",
            true,
            ob_dominant
        );
        crate::test_complete!("weights_obligation_focused");
    }

    #[test]
    fn weights_deadline_focused() {
        init_test("weights_deadline_focused");
        let w = PotentialWeights::deadline_focused();
        let valid = w.is_valid();
        crate::assert_with_log!(valid, "deadline focused valid", true, valid);
        let dl_dominant = w.w_deadline_pressure > w.w_tasks;
        crate::assert_with_log!(dl_dominant, "deadlines weighted higher", true, dl_dominant);
        crate::test_complete!("weights_deadline_focused");
    }

    // ---- Component isolation -----------------------------------------------

    #[test]
    fn component_isolation_tasks_only() {
        init_test("component_isolation_tasks_only");
        let governor = LyapunovGovernor::new(PotentialWeights {
            w_tasks: 1.0,
            w_obligation_age: 0.0,
            w_draining_regions: 0.0,
            w_deadline_pressure: 0.0,
        });

        let snap = active_snapshot(5, 3, 1_000_000_000, 2);
        let record = governor.compute_record(&snap);

        let only_tasks = record.obligation_component == 0.0
            && record.region_component == 0.0
            && record.deadline_component == 0.0;
        crate::assert_with_log!(only_tasks, "only task component", true, only_tasks);
        let expected = 5.0;
        let close = (record.total - expected).abs() < f64::EPSILON;
        crate::assert_with_log!(close, "total = 5.0", true, close);
        crate::test_complete!("component_isolation_tasks_only");
    }

    // ---- Governor reuse ----------------------------------------------------

    #[test]
    fn governor_reuse_and_clear() {
        init_test("governor_reuse_and_clear");
        let mut governor = LyapunovGovernor::with_defaults();

        governor.compute_potential(&active_snapshot(5, 3, 100_000_000, 1));
        governor.compute_potential(&quiescent_snapshot());

        let len = governor.history().len();
        crate::assert_with_log!(len == 2, "history has 2 entries", 2, len);

        governor.clear_history();
        let len = governor.history().len();
        crate::assert_with_log!(len == 0, "cleared", 0, len);
        crate::test_complete!("governor_reuse_and_clear");
    }

    // ---- Deterministic experiment: cancel drain ----------------------------

    #[test]
    #[allow(clippy::too_many_lines)]
    fn experiment_cancel_drain_converges() {
        init_test("experiment_cancel_drain_converges");
        // Simulate a structured concurrency cancellation scenario:
        //
        // Region r0 with 5 child tasks, each holding 1 obligation.
        // Parent cancels all children. Each step:
        // 1. One task observes cancellation, aborts its obligation, completes.
        // 2. Eventually region drains to quiescence.
        //
        // The Lyapunov potential should decrease monotonically.

        let mut governor = LyapunovGovernor::new(PotentialWeights::obligation_focused());

        // Step 0: 5 tasks, 5 obligations, 1 draining region.
        governor.compute_potential(&StateSnapshot {
            time: Time::ZERO,
            live_tasks: 5,
            pending_obligations: 5,
            obligation_age_sum_ns: 500_000_000, // 100ms each.
            draining_regions: 1,
            deadline_pressure: 0.0,
            pending_send_permits: 5,
            pending_acks: 0,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: 5,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: 0,
        });

        // Step 1: Task 0 aborts obligation, completes.
        governor.compute_potential(&StateSnapshot {
            time: Time::from_nanos(100_000_000),
            live_tasks: 4,
            pending_obligations: 4,
            obligation_age_sum_ns: 480_000_000,
            draining_regions: 1,
            deadline_pressure: 0.0,
            pending_send_permits: 4,
            pending_acks: 0,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: 4,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: 0,
        });

        // Step 2: Task 1 aborts, completes.
        governor.compute_potential(&StateSnapshot {
            time: Time::from_nanos(200_000_000),
            live_tasks: 3,
            pending_obligations: 3,
            obligation_age_sum_ns: 360_000_000,
            draining_regions: 1,
            deadline_pressure: 0.0,
            pending_send_permits: 3,
            pending_acks: 0,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: 3,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: 0,
        });

        // Step 3: Task 2 aborts, completes.
        governor.compute_potential(&StateSnapshot {
            time: Time::from_nanos(300_000_000),
            live_tasks: 2,
            pending_obligations: 2,
            obligation_age_sum_ns: 220_000_000,
            draining_regions: 1,
            deadline_pressure: 0.0,
            pending_send_permits: 2,
            pending_acks: 0,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: 2,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: 0,
        });

        // Step 4: Task 3 aborts, completes.
        governor.compute_potential(&StateSnapshot {
            time: Time::from_nanos(400_000_000),
            live_tasks: 1,
            pending_obligations: 1,
            obligation_age_sum_ns: 80_000_000,
            draining_regions: 1,
            deadline_pressure: 0.0,
            pending_send_permits: 1,
            pending_acks: 0,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: 1,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: 0,
        });

        // Step 5: Last task aborts, region finishes draining.
        governor.compute_potential(&StateSnapshot {
            time: Time::from_nanos(500_000_000),
            live_tasks: 0,
            pending_obligations: 0,
            obligation_age_sum_ns: 0,
            draining_regions: 0,
            deadline_pressure: 0.0,
            pending_send_permits: 0,
            pending_acks: 0,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: 0,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: 0,
        });

        let verdict = governor.analyze_convergence();
        let converged = verdict.converged();
        crate::assert_with_log!(converged, "cancel drain converges", true, converged);

        let mono = verdict.monotone;
        crate::assert_with_log!(mono, "monotone decrease", true, mono);

        let v_max = verdict.v_max;
        let has_max = v_max > 0.0;
        crate::assert_with_log!(has_max, "had nonzero peak", true, has_max);

        // Print the trajectory for inspection.
        for (i, record) in governor.history().iter().enumerate() {
            tracing::info!("Step {i}: {record}");
        }

        crate::test_complete!("experiment_cancel_drain_converges");
    }

    #[test]
    fn experiment_deadline_aware_drain() {
        init_test("experiment_deadline_aware_drain");
        // Simulate a drain with deadline-aware scheduling:
        // Tasks have tight deadlines, governor should suggest MeetDeadlines.

        let governor = LyapunovGovernor::new(PotentialWeights::deadline_focused());

        let snap = StateSnapshot {
            time: Time::from_nanos(900_000_000), // 900ms into a 1s deadline.
            live_tasks: 3,
            pending_obligations: 2,
            obligation_age_sum_ns: 200_000_000,
            draining_regions: 1,
            deadline_pressure: 8.5, // High pressure.
            pending_send_permits: 2,
            pending_acks: 0,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: 0,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: 0,
        };

        let suggestion = governor.suggest(&snap);
        let is_deadlines = suggestion == SchedulingSuggestion::MeetDeadlines;
        crate::assert_with_log!(
            is_deadlines,
            "deadline-focused governor meets deadlines",
            true,
            is_deadlines
        );

        let record = governor.compute_record(&snap);
        let dl_dominant = record.deadline_component > record.obligation_component
            && record.deadline_component > record.region_component;
        crate::assert_with_log!(
            dl_dominant,
            "deadline component dominates",
            true,
            dl_dominant
        );
        crate::test_complete!("experiment_deadline_aware_drain");
    }

    // ---- Display impls -----------------------------------------------------

    #[test]
    fn display_impls() {
        init_test("lyapunov_display_impls");

        let snap = active_snapshot(3, 2, 100_000_000, 1);
        let s = format!("{snap}");
        let has_sigma = s.contains("Σ(");
        crate::assert_with_log!(has_sigma, "snapshot display", true, has_sigma);

        let governor = LyapunovGovernor::with_defaults();
        let record = governor.compute_record(&snap);
        let s = format!("{record}");
        let has_v = s.contains("V=");
        crate::assert_with_log!(has_v, "record display", true, has_v);

        let suggestion = SchedulingSuggestion::DrainObligations;
        let s = format!("{suggestion}");
        let has_priority = s.contains("prioritize");
        crate::assert_with_log!(has_priority, "suggestion display", true, has_priority);

        let verdict = ConvergenceVerdict {
            monotone: true,
            reached_quiescence: true,
            v_max: 10.0,
            v_final: 0.0,
            increase_count: 0,
            max_increase: 0.0,
            steps: 5,
        };
        let s = format!("{verdict}");
        let has_converged = s.contains("Converged");
        crate::assert_with_log!(has_converged, "verdict display", true, has_converged);

        crate::test_complete!("lyapunov_display_impls");
    }

    // ========== bd-25j2: Deterministic potential decrease + quiescence ==========

    /// Helper: yield once in an async context (cooperative scheduling point).
    async fn yield_once() {
        use std::future::Future;
        use std::pin::Pin;
        use std::task::{Context, Poll};

        struct YieldOnce {
            yielded: bool,
        }
        impl Future for YieldOnce {
            type Output = ();
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                if self.yielded {
                    Poll::Ready(())
                } else {
                    self.yielded = true;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }
        YieldOnce { yielded: false }.await;
    }

    /// Run a cancel-drain scenario in the lab runtime and record the potential
    /// trajectory. Returns (governor, is_quiescent).
    fn run_cancel_drain_potential_trajectory(
        seed: u64,
        task_count: usize,
        warmup_steps: usize,
    ) -> (LyapunovGovernor, bool) {
        run_cancel_drain_with_weights(seed, task_count, warmup_steps, PotentialWeights::default())
    }

    fn run_cancel_drain_with_weights(
        seed: u64,
        task_count: usize,
        warmup_steps: usize,
        weights: PotentialWeights,
    ) -> (LyapunovGovernor, bool) {
        use crate::lab::{LabConfig, LabRuntime};
        use crate::types::CancelReason;

        let mut runtime = LabRuntime::new(LabConfig::new(seed));
        let region = runtime.state.create_root_region(Budget::unlimited());

        for _ in 0..task_count {
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::unlimited(), async {
                    for _ in 0..20 {
                        let Some(cx) = crate::cx::Cx::current() else {
                            return;
                        };
                        if cx.checkpoint().is_err() {
                            return;
                        }
                        yield_once().await;
                    }
                })
                .expect("create task");

            runtime.scheduler.lock().schedule(task_id, 0);
        }

        // Warm up: let tasks run before cancelling.
        for _ in 0..warmup_steps {
            runtime.step_for_test();
        }

        // Initiate cancellation.
        let cancel_reason = CancelReason::shutdown();
        let tasks_to_cancel = runtime.state.cancel_request(region, &cancel_reason, None);
        {
            let mut scheduler = runtime.scheduler.lock();
            for (task_id, priority) in tasks_to_cancel {
                scheduler.schedule_cancel(task_id, priority);
            }
        }

        // Record potential at each step during the drain phase.
        let mut governor = LyapunovGovernor::new(weights);
        governor.compute_potential(&StateSnapshot::from_runtime_state(&runtime.state));

        let max_drain_steps = 10_000_u64;
        let mut drain_steps = 0_u64;
        while !runtime.is_quiescent() && drain_steps < max_drain_steps {
            runtime.step_for_test();
            drain_steps += 1;
            governor.compute_potential(&StateSnapshot::from_runtime_state(&runtime.state));
        }

        (governor, runtime.is_quiescent())
    }

    #[test]
    fn lab_cancel_drain_monotone_potential_decrease() {
        init_test("lab_cancel_drain_monotone_potential_decrease");

        let (governor, is_quiescent) = run_cancel_drain_potential_trajectory(0xBD25_0201, 8, 16);

        crate::assert_with_log!(is_quiescent, "quiescent", true, is_quiescent);

        let verdict = governor.analyze_convergence();
        for (i, record) in governor.history().iter().enumerate() {
            tracing::info!("Step {i}: {record}");
        }
        tracing::info!("{verdict}");

        crate::assert_with_log!(verdict.monotone, "monotone", true, verdict.monotone);
        crate::assert_with_log!(
            verdict.reached_quiescence,
            "V=0",
            true,
            verdict.reached_quiescence
        );
        crate::assert_with_log!(verdict.converged(), "converged", true, verdict.converged());

        let had_activity = verdict.v_max > 0.0;
        crate::assert_with_log!(had_activity, "peak V > 0", true, had_activity);

        crate::test_complete!("lab_cancel_drain_monotone_potential_decrease");
    }

    #[test]
    fn lab_cancel_drain_deterministic_potential_trajectory() {
        init_test("lab_cancel_drain_deterministic_potential_trajectory");

        let seed = 0xBD25_DEAD;
        let (gov1, q1) = run_cancel_drain_potential_trajectory(seed, 8, 16);
        let (gov2, q2) = run_cancel_drain_potential_trajectory(seed, 8, 16);

        crate::assert_with_log!(q1 && q2, "both quiescent", true, q1 && q2);

        let h1: Vec<f64> = gov1.history().iter().map(|r| r.total).collect();
        let h2: Vec<f64> = gov2.history().iter().map(|r| r.total).collect();

        crate::assert_with_log!(h1.len() == h2.len(), "same length", h1.len(), h2.len());

        let all_match = h1
            .iter()
            .zip(h2.iter())
            .all(|(a, b)| (a - b).abs() < f64::EPSILON);
        crate::assert_with_log!(all_match, "trajectories match", true, all_match);

        crate::test_complete!("lab_cancel_drain_deterministic_potential_trajectory");
    }

    #[test]
    fn lab_quiescence_invariants_after_cancel_drain() {
        init_test("lab_quiescence_invariants_after_cancel_drain");

        let (governor, is_quiescent) = run_cancel_drain_potential_trajectory(0xBD25_CAFE, 12, 8);

        crate::assert_with_log!(is_quiescent, "quiescent", true, is_quiescent);

        let final_record = governor.history().last().expect("non-empty history");
        let snap = &final_record.snapshot;

        crate::assert_with_log!(snap.live_tasks == 0, "no live tasks", 0, snap.live_tasks);
        crate::assert_with_log!(
            snap.pending_obligations == 0,
            "no obligations",
            0,
            snap.pending_obligations
        );
        crate::assert_with_log!(
            snap.draining_regions == 0,
            "no draining regions",
            0,
            snap.draining_regions
        );
        crate::assert_with_log!(
            snap.is_quiescent(),
            "snapshot quiescent",
            true,
            snap.is_quiescent()
        );

        // Per-kind obligations all zero.
        crate::assert_with_log!(
            snap.pending_send_permits == 0,
            "no sp",
            0,
            snap.pending_send_permits
        );
        crate::assert_with_log!(snap.pending_acks == 0, "no ack", 0, snap.pending_acks);
        crate::assert_with_log!(snap.pending_leases == 0, "no lease", 0, snap.pending_leases);
        crate::assert_with_log!(snap.pending_io_ops == 0, "no io", 0, snap.pending_io_ops);

        // Cancel phase counts all zero.
        crate::assert_with_log!(
            snap.cancel_requested_tasks == 0,
            "no cancel_requested",
            0,
            snap.cancel_requested_tasks
        );
        crate::assert_with_log!(
            snap.cancelling_tasks == 0,
            "no cancelling",
            0,
            snap.cancelling_tasks
        );
        crate::assert_with_log!(
            snap.finalizing_tasks == 0,
            "no finalizing",
            0,
            snap.finalizing_tasks
        );

        let v_zero = final_record.total.abs() < f64::EPSILON;
        crate::assert_with_log!(v_zero, "V = 0", true, v_zero);

        crate::test_complete!("lab_quiescence_invariants_after_cancel_drain");
    }

    #[test]
    fn lab_cancel_drain_with_many_tasks_converges() {
        init_test("lab_cancel_drain_with_many_tasks_converges");

        // Larger scenario: 12 tasks, more warmup steps.
        let (governor, is_quiescent) = run_cancel_drain_potential_trajectory(0xBD25_A1B0, 12, 24);

        crate::assert_with_log!(is_quiescent, "quiescent", true, is_quiescent);

        let verdict = governor.analyze_convergence();
        for (i, record) in governor.history().iter().enumerate() {
            tracing::info!("Step {i}: {record}");
        }
        tracing::info!("{verdict}");

        crate::assert_with_log!(verdict.monotone, "monotone", true, verdict.monotone);
        crate::assert_with_log!(verdict.converged(), "converged", true, verdict.converged());

        crate::test_complete!("lab_cancel_drain_with_many_tasks_converges");
    }

    #[test]
    fn lab_potential_decreases_across_weight_configurations() {
        init_test("lab_potential_decreases_across_weight_configurations");

        let weight_configs = [
            ("default", PotentialWeights::default()),
            ("uniform", PotentialWeights::uniform(1.0)),
            ("obligation_focused", PotentialWeights::obligation_focused()),
            ("deadline_focused", PotentialWeights::deadline_focused()),
        ];

        for (label, weights) in &weight_configs {
            let (governor, is_quiescent) =
                run_cancel_drain_with_weights(0xBD25_0815, 6, 8, *weights);

            crate::assert_with_log!(
                is_quiescent,
                format!("{label}: quiescent"),
                true,
                is_quiescent
            );

            let verdict = governor.analyze_convergence();
            tracing::info!("Weights={label}: {verdict}");

            crate::assert_with_log!(
                verdict.monotone,
                format!("{label}: monotone"),
                true,
                verdict.monotone
            );
            crate::assert_with_log!(
                verdict.converged(),
                format!("{label}: converged"),
                true,
                verdict.converged()
            );
        }

        crate::test_complete!("lab_potential_decreases_across_weight_configurations");
    }

    // =========================================================================
    // Obligation-aware deterministic tests (bd-25j2)
    // =========================================================================

    /// Run a cancel-drain scenario where tasks hold pending obligations.
    fn run_cancel_drain_with_obligations(
        seed: u64,
        task_count: usize,
        obligations_per_task: usize,
        warmup_steps: usize,
        weights: PotentialWeights,
    ) -> (LyapunovGovernor, bool, usize) {
        use crate::lab::{LabConfig, LabRuntime};
        use crate::record::ObligationKind;
        use crate::types::CancelReason;

        // Disable panic-on-leak: we check invariants explicitly after drain.
        let mut runtime = LabRuntime::new(LabConfig::new(seed).panic_on_leak(false));
        let region = runtime.state.create_root_region(Budget::unlimited());

        let obligation_kinds = [
            ObligationKind::SendPermit,
            ObligationKind::Ack,
            ObligationKind::Lease,
            ObligationKind::IoOp,
        ];

        // Create tasks with long-running bodies (won't complete during warmup)
        // and attach obligations immediately so they exist before any steps.
        let mut obligation_ids = Vec::new();
        for t_idx in 0..task_count {
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::unlimited(), async {
                    // Long loop: ensures task is still alive when obligations are
                    // created and when cancellation arrives.
                    for _ in 0..1_000 {
                        let Some(cx) = crate::cx::Cx::current() else {
                            return;
                        };
                        if cx.checkpoint().is_err() {
                            return;
                        }
                        yield_once().await;
                    }
                })
                .expect("create task");

            // Attach obligations before scheduling so they exist while the task
            // is alive.
            for o_idx in 0..obligations_per_task {
                let kind = obligation_kinds[(t_idx + o_idx) % obligation_kinds.len()];
                if let Ok(obl_id) = runtime.state.create_obligation(
                    kind,
                    task_id,
                    region,
                    Some(format!("test-obl-t{t_idx}-o{o_idx}")),
                ) {
                    obligation_ids.push(obl_id);
                }
            }

            runtime.scheduler.lock().schedule(task_id, 0);
        }

        // Warm up: let tasks run a few steps and advance virtual time so
        // obligations accumulate measurable age (the obligation potential
        // component is based on age, not count).
        for _ in 0..warmup_steps {
            runtime.step_for_test();
        }
        // Advance virtual time by 1s so obligation age is non-trivial.
        runtime.advance_time(1_000_000_000);

        let mut governor = LyapunovGovernor::new(weights);
        governor.compute_potential(&StateSnapshot::from_runtime_state(&runtime.state));

        let cancel_reason = CancelReason::shutdown();
        let tasks_to_cancel = runtime.state.cancel_request(region, &cancel_reason, None);
        {
            let mut scheduler = runtime.scheduler.lock();
            for (task_id, priority) in tasks_to_cancel {
                scheduler.schedule_cancel(task_id, priority);
            }
        }

        // Abort obligations as part of cancellation, mimicking real code where
        // task bodies release obligations upon detecting cancel via checkpoint.
        for obl_id in &obligation_ids {
            let _ = runtime
                .state
                .abort_obligation(*obl_id, crate::record::ObligationAbortReason::Cancel);
        }

        governor.compute_potential(&StateSnapshot::from_runtime_state(&runtime.state));

        let mut drain_steps = 0_u64;
        while !runtime.is_quiescent() && drain_steps < 10_000 {
            runtime.step_for_test();
            drain_steps += 1;
            governor.compute_potential(&StateSnapshot::from_runtime_state(&runtime.state));
        }

        let violations = runtime.check_invariants();
        let leak_count = violations
            .iter()
            .filter(|v| matches!(v, InvariantViolation::ObligationLeak { .. }))
            .count();

        (governor, runtime.is_quiescent(), leak_count)
    }

    #[test]
    fn lab_cancel_drain_with_obligations_monotone_decrease() {
        init_test("lab_cancel_drain_with_obligations_monotone_decrease");

        let (governor, is_quiescent, leak_count) =
            run_cancel_drain_with_obligations(0xBD25_0B01, 8, 2, 16, PotentialWeights::default());

        crate::assert_with_log!(is_quiescent, "quiescent", true, is_quiescent);
        crate::assert_with_log!(leak_count == 0, "no obligation leaks", 0usize, leak_count);

        let verdict = governor.analyze_convergence();
        for (i, record) in governor.history().iter().enumerate() {
            tracing::info!("Step {i}: {record}");
        }
        tracing::info!("{verdict}");

        crate::assert_with_log!(verdict.monotone, "monotone", true, verdict.monotone);
        crate::assert_with_log!(
            verdict.reached_quiescence,
            "V=0",
            true,
            verdict.reached_quiescence
        );
        crate::assert_with_log!(verdict.converged(), "converged", true, verdict.converged());

        // The first snapshot (pre-cancel) should reflect pending obligations.
        // Note: obligation_component may be 0 when virtual time hasn't advanced
        // (ages are 0ns), but the obligations themselves should exist.
        let first = &governor.history()[0];
        crate::assert_with_log!(
            first.snapshot.pending_obligations > 0,
            "initial pending obligations > 0",
            true,
            first.snapshot.pending_obligations > 0
        );

        crate::test_complete!("lab_cancel_drain_with_obligations_monotone_decrease");
    }

    #[test]
    fn lab_obligation_leak_oracle_clean_after_drain() {
        init_test("lab_obligation_leak_oracle_clean_after_drain");

        let (governor, is_quiescent, leak_count) =
            run_cancel_drain_with_obligations(0xBD25_1EAC, 10, 3, 8, PotentialWeights::default());

        crate::assert_with_log!(is_quiescent, "quiescent", true, is_quiescent);
        crate::assert_with_log!(leak_count == 0, "zero obligation leaks", 0usize, leak_count);

        let final_record = governor.history().last().expect("non-empty history");
        let snap = &final_record.snapshot;
        crate::assert_with_log!(
            snap.pending_obligations == 0,
            "no pending",
            0,
            snap.pending_obligations
        );
        crate::assert_with_log!(
            snap.pending_send_permits == 0,
            "no sp",
            0,
            snap.pending_send_permits
        );
        crate::assert_with_log!(snap.pending_acks == 0, "no acks", 0, snap.pending_acks);
        crate::assert_with_log!(
            snap.pending_leases == 0,
            "no leases",
            0,
            snap.pending_leases
        );
        crate::assert_with_log!(
            snap.pending_io_ops == 0,
            "no io_ops",
            0,
            snap.pending_io_ops
        );

        crate::test_complete!("lab_obligation_leak_oracle_clean_after_drain");
    }

    #[test]
    fn lab_cancel_drain_with_obligations_deterministic() {
        init_test("lab_cancel_drain_with_obligations_deterministic");

        let seed = 0xBD25_DE70;
        let w = PotentialWeights::default();

        let (gov1, q1, l1) = run_cancel_drain_with_obligations(seed, 6, 2, 12, w);
        let (gov2, q2, l2) = run_cancel_drain_with_obligations(seed, 6, 2, 12, w);

        crate::assert_with_log!(q1 && q2, "both quiescent", true, q1 && q2);
        crate::assert_with_log!(l1 == 0 && l2 == 0, "no leaks", true, l1 == 0 && l2 == 0);

        let h1: Vec<f64> = gov1.history().iter().map(|r| r.total).collect();
        let h2: Vec<f64> = gov2.history().iter().map(|r| r.total).collect();

        crate::assert_with_log!(h1.len() == h2.len(), "same length", h1.len(), h2.len());

        let all_match = h1
            .iter()
            .zip(h2.iter())
            .all(|(a, b)| (a - b).abs() < f64::EPSILON);
        crate::assert_with_log!(all_match, "trajectories match", true, all_match);

        crate::test_complete!("lab_cancel_drain_with_obligations_deterministic");
    }

    #[test]
    fn lab_obligation_focused_weights_converge_with_obligations() {
        init_test("lab_obligation_focused_weights_converge_with_obligations");

        let weights = PotentialWeights::obligation_focused();
        let (governor, is_quiescent, leak_count) =
            run_cancel_drain_with_obligations(0xBD25_0B1F, 8, 3, 8, weights);

        crate::assert_with_log!(is_quiescent, "quiescent", true, is_quiescent);
        crate::assert_with_log!(leak_count == 0, "no leaks", 0usize, leak_count);

        let verdict = governor.analyze_convergence();
        tracing::info!("{verdict}");

        crate::assert_with_log!(verdict.monotone, "monotone", true, verdict.monotone);
        crate::assert_with_log!(verdict.converged(), "converged", true, verdict.converged());

        let first = &governor.history()[0];
        let obl_fraction = if first.total > 0.0 {
            first.obligation_component / first.total
        } else {
            0.0
        };
        tracing::info!(
            "Obligation fraction of initial V: {:.2}% ({:.4} / {:.4})",
            obl_fraction * 100.0,
            first.obligation_component,
            first.total,
        );

        crate::test_complete!("lab_obligation_focused_weights_converge_with_obligations");
    }

    #[test]
    fn lab_quiescence_snapshot_zero_with_obligations() {
        init_test("lab_quiescence_snapshot_zero_with_obligations");

        let (governor, is_quiescent, leak_count) =
            run_cancel_drain_with_obligations(0xBD25_0520, 12, 2, 10, PotentialWeights::default());

        crate::assert_with_log!(is_quiescent, "quiescent", true, is_quiescent);
        crate::assert_with_log!(leak_count == 0, "no leaks", 0usize, leak_count);

        let final_record = governor.history().last().expect("non-empty history");
        let snap = &final_record.snapshot;

        crate::assert_with_log!(snap.live_tasks == 0, "no live tasks", 0, snap.live_tasks);
        crate::assert_with_log!(
            snap.pending_obligations == 0,
            "no obl",
            0,
            snap.pending_obligations
        );
        crate::assert_with_log!(
            snap.draining_regions == 0,
            "no draining",
            0,
            snap.draining_regions
        );
        crate::assert_with_log!(
            snap.obligation_age_sum_ns == 0,
            "age zero",
            0u64,
            snap.obligation_age_sum_ns
        );
        crate::assert_with_log!(
            snap.cancel_requested_tasks == 0,
            "no cr",
            0,
            snap.cancel_requested_tasks
        );
        crate::assert_with_log!(
            snap.cancelling_tasks == 0,
            "no cancelling",
            0,
            snap.cancelling_tasks
        );
        crate::assert_with_log!(
            snap.finalizing_tasks == 0,
            "no finalizing",
            0,
            snap.finalizing_tasks
        );
        crate::assert_with_log!(
            snap.is_quiescent(),
            "quiescent snap",
            true,
            snap.is_quiescent()
        );

        let v_zero = final_record.total.abs() < f64::EPSILON;
        crate::assert_with_log!(v_zero, "V = 0", true, v_zero);

        crate::test_complete!("lab_quiescence_snapshot_zero_with_obligations");
    }
}
