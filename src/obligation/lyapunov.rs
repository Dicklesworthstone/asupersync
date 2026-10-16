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
#[derive(Debug, Clone, Default)]
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
    /// Currently unused at the call site — wiring is pending an upstream
    /// br-asupersync-xxcss5 follow-up; allow(dead_code) keeps the lib
    /// compilable in the meantime.
    #[allow(dead_code)]
    #[inline]
    fn accumulate_cancel_phase_counts(
        task_state: &crate::record::task::TaskState,
        cancel_requested_tasks: &mut u32,
        cancelling_tasks: &mut u32,
        finalizing_tasks: &mut u32,
    ) {
        match task_state {
            crate::record::task::TaskState::CancelRequested { .. } => {
                *cancel_requested_tasks = cancel_requested_tasks.saturating_add(1);
            }
            crate::record::task::TaskState::Cancelling { .. } => {
                *cancelling_tasks = cancelling_tasks.saturating_add(1);
            }
            crate::record::task::TaskState::Finalizing { .. } => {
                *finalizing_tasks = finalizing_tasks.saturating_add(1);
            }
            _ => {}
        }
    }

    /// Constructs a snapshot from a live [`RuntimeState`](crate::runtime::RuntimeState).
    ///
    /// Design goals:
    /// - deterministic: only depends on `state` (no ambient time / RNG)
    /// - bounded + allocation-free: scans arenas; does not allocate
    /// - resilient: if a task's `CxInner` lock is poisoned, deadline contribution is skipped
    #[must_use]
    pub fn from_runtime_state(state: &crate::runtime::RuntimeState) -> Self {
        Self::from_runtime_state_at(state, state.now)
    }

    /// Constructs a snapshot at an explicitly sampled runtime time.
    ///
    /// Production callers pass their timer driver's current time so deadline
    /// pressure and obligation age share the clock used to stamp runtime
    /// effects. Deterministic callers may pass virtual time without reading
    /// any ambient clock. [`Self::from_runtime_state`] retains its existing
    /// behavior of sampling the logical `RuntimeState::now` field.
    #[must_use]
    pub fn from_runtime_state_at(state: &crate::runtime::RuntimeState, now: Time) -> Self {
        Self::from_runtime_state_with_tasks_at(state, &state.tasks, now)
    }

    /// Builds the snapshot with task counters read from an explicit task
    /// table (br-asupersync-sched-hot-path-perf-bt4y5f.2.2 / E1.2
    /// subsystem 3d; E1.1 rows T06/T07/T14).
    ///
    /// Schedulers dispatching against an external shard-A table pass that
    /// table (locked in canonical B → A order) so Lyapunov potential,
    /// cancel-phase counters, and deadline pressure describe the tasks the
    /// workers actually run; region and obligation counters still come from
    /// the unified lifecycle owner. Embedded callers use
    /// [`Self::from_runtime_state`], which passes `&state.tasks`.
    pub fn from_runtime_state_with_tasks(
        state: &crate::runtime::RuntimeState,
        tasks: &crate::runtime::TaskTable,
    ) -> Self {
        Self::from_runtime_state_with_tasks_at(state, tasks, state.now)
    }

    /// Builds a snapshot from an explicit task table and one sampled time.
    ///
    /// The supplied time applies to every time-dependent term. Callers using
    /// a separate dispatch table retain the same state-before-table lock
    /// ordering as [`Self::from_runtime_state_with_tasks`].
    #[must_use]
    pub fn from_runtime_state_with_tasks_at(
        state: &crate::runtime::RuntimeState,
        tasks: &crate::runtime::TaskTable,
        now: Time,
    ) -> Self {
        use crate::record::obligation::ObligationKind;
        use crate::record::task::TaskPhase;

        // Deadline pressure normalization constant D₀ (see module docs).
        // 1s is an intentionally "coarse" knob: pressure reflects tasks that are
        // within ~1s of their deadline (or overdue), not far-future deadlines.
        const DEADLINE_PRESSURE_D0_NS: u64 = 1_000_000_000;
        // -- Task counters (O(1), br-asupersync-xxcss5) --
        let live_tasks = tasks.live_task_count() as u32;
        let cancel_requested_tasks = tasks.count_in_phase(TaskPhase::CancelRequested) as u32;
        let cancelling_tasks = tasks.count_in_phase(TaskPhase::Cancelling) as u32;
        let finalizing_tasks = tasks.count_in_phase(TaskPhase::Finalizing) as u32;

        // -- Deadline pressure O(1) estimation (br-asupersync-xxcss5) --
        // pressure = Σ max(0, 1 - (deadline - now)/D₀)
        // Coarse approximation: Σ (1 - (deadline - now)/D₀) for all tasks with deadlines.
        // This is accurate if most tasks with deadlines are within D₀ of their deadline.
        let tasks_with_deadline = tasks.tasks_with_deadline_count();
        let deadline_pressure = if tasks_with_deadline > 0 {
            let deadline_sum_ns = tasks.deadline_sum_ns();
            let now_ns = u128::from(now.as_nanos());

            #[allow(clippy::cast_precision_loss)]
            let count = tasks_with_deadline as f64;
            #[allow(clippy::cast_precision_loss)]
            let d0 = DEADLINE_PRESSURE_D0_NS as f64;
            #[allow(clippy::cast_precision_loss)]
            let sum_d = deadline_sum_ns as f64;
            #[allow(clippy::cast_precision_loss)]
            let now_f = now_ns as f64;

            // pressure = count - (sum_d / d0) + (count * now / d0)
            let p = count - (sum_d / d0) + (count * now_f / d0);
            p.max(0.0)
        } else {
            0.0
        };

        // -- Obligation counters (O(1), br-asupersync-xxcss5) --
        #[allow(clippy::cast_possible_truncation)]
        let pending_obligations: u32 = state.pending_obligation_count() as u32;
        let now_ns = u128::from(now.as_nanos());
        let pending_reserved_at_sum = state.pending_obligation_reserved_at_sum_ns();
        let total_pending_nanos = now_ns.saturating_mul(u128::from(pending_obligations));
        let obligation_age_sum_ns: u64 = total_pending_nanos
            .saturating_sub(pending_reserved_at_sum)
            .min(u128::from(u64::MAX)) as u64;

        #[allow(clippy::cast_possible_truncation)]
        let pending_send_permits: u32 =
            state.pending_obligation_count_for_kind(ObligationKind::SendPermit) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let pending_acks: u32 = state.pending_obligation_count_for_kind(ObligationKind::Ack) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let pending_leases: u32 = state
            .pending_obligation_count_for_kind(ObligationKind::Lease)
            .saturating_add(
                state.pending_obligation_count_for_kind(ObligationKind::SemaphorePermit),
            )
            .saturating_add(state.pending_obligation_count_for_kind(ObligationKind::Transaction))
            as u32;
        #[allow(clippy::cast_possible_truncation)]
        let pending_io_ops: u32 =
            state.pending_obligation_count_for_kind(ObligationKind::IoOp) as u32;

        // -- Region counter (O(1), br-asupersync-xxcss5) --
        let draining_regions = state.draining_region_count_for_snapshot() as u32;

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
            && self.deadline_pressure.abs() < f64::EPSILON
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
        self.total.abs() < f64::EPSILON
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
        let mut increase_count: usize = 0;
        let mut max_increase = 0.0_f64;
        let mut v_max = 0.0_f64;

        for window in self.history.windows(2) {
            let prev = window[0].total;
            let curr = window[1].total;
            v_max = v_max.max(prev).max(curr);

            let delta = curr - prev;
            if delta > f64::EPSILON {
                monotone = false;
                increase_count = increase_count.saturating_add(1);
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
#[path = "lyapunov_inline_tests.rs"]
mod tests;
