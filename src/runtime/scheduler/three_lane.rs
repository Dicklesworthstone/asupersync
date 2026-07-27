//! Multi-worker 3-lane scheduler with work stealing.
//!
//! This scheduler coordinates multiple worker threads while maintaining
//! strict priority ordering: cancel > timed > ready.
//!
//! # Scheduler fairness contract (bd-17uu, br-asupersync-kznrvh)
//!
//! The cancel lane has strict preemption over timed and ready lanes, but the
//! scheduler's fairness claims are deliberately worker-local and dispatch-step
//! based. They are not wall-clock latency claims and they are not a global
//! total-order proof across all workers.
//!
//! ## Vocabulary
//!
//! For a worker `w`, let `D_w(k)` be the `k`th successful return of
//! `next_task()` for that worker, and let `lane(D_w(k))` be one of:
//!
//! - `C`: cancel lane dispatch
//! - `T`: timed/deadline dispatch
//! - `R`: ready/local-ready/global-ready dispatch
//! - `S`: ready work obtained by stealing from another worker
//!
//! A lane is **eligible** at step `k` only if a task in that lane is visible to
//! this worker at the relevant probe point. For example, a timed task is
//! eligible only when its deadline is due; a `local_ready` task is eligible only
//! to its owner worker; and a task hidden behind an externally held queue lock
//! is not counted as eligible until the lock can be acquired by the scheduler
//! path that owns that queue.
//!
//! Let:
//!
//! - `L_c` be the current base cancel-streak limit.
//! - `E_c(k)` be the effective cancel limit at step `k`: `L_c` normally, or
//!   `2 * L_c` while the governor suggests `DrainObligations` or
//!   `DrainRegions`.
//! - `L_t` be the timed-lane fairness limit.
//! - `L_s` be the fast-queue stolen-work fairness limit.
//!
//! ## Dispatch bounds
//!
//! **Cancel preemption fairness.** If non-cancel work (`T`, `R`, or `S`) is
//! eligible for worker `w` and remains eligible, then after at most `E_c(k)`
//! consecutive `C` dispatches, worker `w` attempts non-cancel work before
//! accepting more cancel work. Equivalently, within the next `E_c(k) + 1`
//! successful dispatch opportunities for that worker, either a non-cancel task
//! is dispatched or non-cancel eligibility disappeared before the fairness
//! gate could observe it.
//!
//! **Timed-lane fairness.** Under `MeetDeadlines`, if ready work (`R` or `S`)
//! is eligible and remains eligible while due timed work is also available,
//! worker `w` attempts ready work after at most `L_t` consecutive timed
//! dispatches.
//!
//! **Stolen-work fairness.** If owner-local ready-heap work is eligible while
//! the fast queue contains stolen ready work, worker `w` gives owner-local work
//! a probe after at most `L_s` consecutive fast-queue dispatches. The
//! non-stealable `local_ready` deque is stronger: it is checked before the
//! fast queue on every ready phase.
//!
//! ## Explicit non-goals
//!
//! - These are dispatch-step bounds, not wall-clock or CPU-time bounds. Worker
//!   dispatch executes exactly one `Future::poll` for the selected task before
//!   returning to the scheduler. The runtime cannot preempt inside that poll, so
//!   CPU-bound futures must still reach their own cooperative yield or
//!   cancellation checkpoint. `RuntimeConfig::poll_budget` applies to direct
//!   `block_on` self-wake spin mitigation, not to worker-lane fairness.
//! - The contract does not claim a global priority total order across workers.
//!   Work stealing operates on ready work only, and owner-local `!Send` work is
//!   intentionally invisible to other workers.
//! - Adaptive cancel-streak mode may change `L_c` at epoch boundaries. Runtime
//!   certificates therefore record both the base limit and the maximum observed
//!   effective limit.
//!
//! ## Proof sketch (per-worker, single-threaded scheduling loop)
//!
//! 1. Each worker maintains a monotone counter `cancel_streak` that increments
//!    on every cancel dispatch and resets to 0 on any non-cancel dispatch (or
//!    when the cancel lane is empty).
//!
//! 2. In `next_task()`, the cancel lane is only consulted when
//!    `cancel_streak < E_c(k)`. Once the effective limit is reached, the
//!    scheduler falls through to timed, ready, and steal.
//!
//! 3. If eligible timed, ready, or stealable ready work is still visible when
//!    `cancel_streak` hits the limit, that work is dispatched next, resetting
//!    `cancel_streak` to 0. Cancel work resumes on the following call to
//!    `next_task()`.
//!
//! 4. If no timed/ready/steal work is available when the limit is hit, a
//!    fallback path allows one more cancel dispatch with cancel_streak reset
//!    to 1. This ensures cancel work is not blocked indefinitely when it is
//!    the only pending work.
//!
//! 5. On backoff/park (no work found), cancel_streak resets to 0. This
//!    prevents stale counters from deferring cancel work after an idle period.
//!
//! **Corollary**: Under sustained cancel injection and sustained non-cancel
//! eligibility, non-cancel work receives a worker-local dispatch opportunity at
//! least every `E_c(k) + 1` scheduling steps, giving a worst-case non-cancel
//! stall of O(`E_c`) dispatch cycles per worker.
//!
//! ## Cross-worker note (br-asupersync-te2u3m)
//!
//! **IMPORTANT LIMITATION**: Fairness is enforced per-worker only. These
//! worker-local bounds DO NOT guarantee global fairness due to work stealing
//! dependencies that can create cross-worker priority inversions.
//!
//! **Global Priority Inversion Risk**: A high-priority task stolen by Worker A
//! may be blocked by Worker A's local cancel streak, while a lower-priority
//! task runs on Worker B. This violates global priority order despite both
//! workers satisfying their local fairness bounds.
//!
//! **Cancel Preemption Invariant Violation**: The per-worker cancel preemption
//! guarantee does not compose globally. Priority inversions can extend beyond
//! any single worker's `E_c(k)` bound when work stealing creates dependencies
//! between workers with different cancel streak states.
//!
//! **Mitigation**: Callers requiring strict global priority order should:
//! 1. Use single-worker deployment (disables work stealing)
//! 2. Monitor global priority inversion via fairness monitoring
//! 3. Consider task affinity to reduce steal-induced dependencies
//!
//! This limitation is inherent to the load-balancing vs. strict-priority tradeoff
//! in multi-worker schedulers. Work stealing operates only on ready work for
//! performance, but sacrifices global priority guarantees.

use crate::cancel::progress_certificate::{DrainPhase, ProgressCertificate};
use crate::obligation::lyapunov::{
    LyapunovGovernor, PotentialWeights, SchedulingSuggestion, StateSnapshot,
};
use crate::observability::spectral_health::{SpectralHealthMonitor, SpectralThresholds};
use crate::runtime::config::SchedulerPlacementMode;
use crate::runtime::io_driver::IoDriverHandle;
use crate::runtime::scheduler::global_injector::{GlobalInjector, PriorityTask};
use crate::runtime::scheduler::local_queue::{self, LocalQueue};
use crate::runtime::scheduler::priority::Scheduler as PriorityScheduler;
use crate::runtime::scheduler::swarm_evidence::{
    SCHEDULER_EVIDENCE_SCHEMA_VERSION, SchedulerEvidenceArtifact, SchedulerEvidenceMetrics,
    SchedulerKnobProfile, SchedulerTopologyDescriptor, SchedulerWorkloadClass,
};
use crate::runtime::scheduler::worker::Parker;
use crate::runtime::stored_task::AnyStoredTask;
use crate::runtime::{RuntimeState, TaskTable};
use crate::sync::ContendedMutex;
use crate::time::TimerDriverHandle;
use crate::tracing_compat::{error, trace};
use crate::types::{CxInner, TaskId, Time};
use crate::util::{CachePadded, DetHashMap, DetHasher, DetRng};
use parking_lot::Mutex;
use parking_lot::RwLock;
use smallvec::SmallVec;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

/// Identifier for a scheduler worker.
pub type WorkerId = usize;

const DEFAULT_CANCEL_STREAK_LIMIT: usize = 16;
const DEFAULT_BROWSER_READY_HANDOFF_LIMIT: usize = 0;
const DEFAULT_STEAL_BATCH_SIZE: usize = 4;
const GLOBAL_READY_BATCH_DRAIN_MIN_DEPTH: usize = 8;
const DEFAULT_ENABLE_PARKING: bool = true;
const LOCAL_SCHEDULER_BURST_BUDGET: usize = 2048;
const LOCAL_SCHEDULER_MIN_CAPACITY: usize = 128;
const LOCAL_SCHEDULER_MAX_CAPACITY: usize = 1024;
const ADAPTIVE_STREAK_ARMS: [usize; 5] = [4, 8, 16, 32, 64];
const ADAPTIVE_UCB_DISCOUNT: f64 = 0.95;
const ADAPTIVE_UCB_CONFIDENCE: f64 = 2.0;
const ADAPTIVE_EPROCESS_LAMBDA: f64 = 0.5;
// Keep a short spin/yield window for wakeup handoff while still reducing
// runaway idle burn on noisy wake paths.
const SPIN_LIMIT: u32 = 8;
const YIELD_LIMIT: u32 = 2;
const EMPTY_BACKOFF_PARK_THRESHOLD: u32 = SPIN_LIMIT + YIELD_LIMIT;
const STALE_DUE_DEADLINE_PARK_NANOS: u64 = 1;
const SHORT_WAIT_LE_5MS_NANOS: u64 = 5_000_000;
const IDLE_IO_POLL_MAX_TIMEOUT: Duration = Duration::from_millis(250);
#[cfg(any(test, feature = "test-internals"))]
const DEFAULT_SCHEDULER_EVIDENCE_MAX_INFLIGHT_MULTIPLIER: usize = 4;

/// Per-worker non-stealable ready queue with O(1) lazy-tombstone cancellation.
///
/// br-asupersync-ayg4ot: cancel-injection previously did `iter().position()`
/// (O(n) scan) + `VecDeque::remove(pos)` (O(n) shift) per cancel, so mass
/// cancellation (region close, FailFast, shutdown) of `K` tasks in a queue of
/// depth `n` was O(K·n) ≈ O(n²). Instead, [`Self::tombstone`] marks a cancelled
/// task O(1) (the task is authoritatively re-queued into the cancel lane by the
/// caller's `move_to_cancel_lane`), and [`Self::pop_front`] drops the stale
/// entry O(1)-amortized when it surfaces. The `present` set bounds the tombstone
/// set to tasks actually in `ready`, so it never leaks, and dedups pushes.
#[derive(Debug)]
pub(crate) struct LocalReadyQueueInner {
    /// Physical FIFO order of pending local task ids (may hold tombstoned ids
    /// until they surface in `pop_front`).
    ready: VecDeque<TaskId>,
    /// Membership index mirroring distinct ids in `ready` (O(1) presence test;
    /// keeps `ready` duplicate-free and bounds `tombstones`).
    present: HashSet<TaskId>,
    /// Cancelled ids still physically present in `ready`. A subset of `present`.
    tombstones: HashSet<TaskId>,
}

impl LocalReadyQueueInner {
    pub(crate) fn new(ready: VecDeque<TaskId>) -> Self {
        let present: HashSet<TaskId> = ready.iter().copied().collect();
        Self {
            ready,
            present,
            tombstones: HashSet::new(),
        }
    }

    /// Enqueue a local task. Duplicate-safe: a task already present is not
    /// re-pushed, but a prior tombstone on it is cleared (it is live again).
    fn push_back(&mut self, task: TaskId) {
        if self.present.insert(task) {
            self.ready.push_back(task);
        } else {
            // Already queued (a stale, possibly-tombstoned entry exists): revive it.
            self.tombstones.remove(&task);
        }
    }

    /// Dequeue the next *live* local task, dropping any tombstoned (cancelled)
    /// stale entries it skips over.
    pub(crate) fn pop_front(&mut self) -> Option<TaskId> {
        while let Some(task) = self.ready.pop_front() {
            self.present.remove(&task);
            if self.tombstones.remove(&task) {
                // Cancelled: already authoritative in the cancel lane; drop stale entry.
                continue;
            }
            return Some(task);
        }
        None
    }

    /// O(1) cancel: mark a queued task so `pop_front` drops its stale entry.
    /// Only marks tasks actually present, so the tombstone set never leaks.
    fn tombstone(&mut self, task: TaskId) {
        if self.present.contains(&task) {
            self.tombstones.insert(task);
        }
    }

    // br-asupersync MAIN-BREAKAGE fix: the only callers are in the
    // `#[cfg(test)] mod tests` below, so gate this to cfg(test). Ungated it
    // tripped `deny(dead_code)` in normal and test-internals lib builds
    // (no non-test caller), breaking every lib build tree-wide.
    #[cfg(test)]
    fn contains(&self, task: &TaskId) -> bool {
        self.present.contains(task) && !self.tombstones.contains(task)
    }

    fn iter(&self) -> impl Iterator<Item = &TaskId> {
        self.ready
            .iter()
            .filter(|task| !self.tombstones.contains(task))
    }

    // br-asupersync MAIN-BREAKAGE fix: callers live in `#[cfg(test)] mod tests`,
    // not behind the `test-internals` feature, so the prior
    // `any(test, feature = "test-internals")` gate left this dead under
    // `deny(dead_code)` in test-internals-only builds.
    #[cfg(test)]
    fn drain(&mut self, _range: std::ops::RangeFull) -> std::vec::IntoIter<TaskId> {
        let mut live = Vec::with_capacity(self.len());
        while let Some(task) = self.pop_front() {
            live.push(task);
        }
        live.into_iter()
    }

    /// Number of *live* (non-tombstoned) queued tasks.
    fn len(&self) -> usize {
        self.present.len().saturating_sub(self.tombstones.len())
    }

    /// True when there are no *live* tasks (all queued ids are tombstoned).
    pub(crate) fn is_empty(&self) -> bool {
        self.present.len() == self.tombstones.len()
    }

    /// Snapshot of the *live* queued task ids in FIFO order (for diagnostics).
    fn snapshot(&self) -> Vec<TaskId> {
        self.ready
            .iter()
            .copied()
            .filter(|t| !self.tombstones.contains(t))
            .collect()
    }
}

impl Extend<TaskId> for LocalReadyQueueInner {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = TaskId>,
    {
        for task in iter {
            self.push_back(task);
        }
    }
}

impl std::ops::Index<usize> for LocalReadyQueueInner {
    type Output = TaskId;

    fn index(&self, index: usize) -> &Self::Output {
        self.iter()
            .nth(index)
            .expect("local-ready live index out of bounds")
    }
}

type LocalReadyQueue = Mutex<LocalReadyQueueInner>;

/// Construct a [`LocalReadyQueue`] seeded with `initial` pending task ids.
fn local_ready_queue(initial: VecDeque<TaskId>) -> LocalReadyQueue {
    Mutex::new(LocalReadyQueueInner::new(initial))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IoPhaseOutcome {
    /// This worker made useful I/O progress (work may now be runnable).
    Progress,
    /// Another worker is currently the reactor leader.
    Follower,
    /// No I/O progress from this worker (leader quick miss or no I/O driver).
    NoProgress,
}

#[inline]
fn select_io_poll_timeout(
    idle_timeout: Option<Duration>,
    fast_queue_empty: bool,
    spawn_mailbox_has_work: bool,
) -> Option<Duration> {
    if fast_queue_empty && !spawn_mailbox_has_work {
        idle_timeout
    } else {
        Some(Duration::ZERO)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackoffTimeoutDecision {
    ParkTimeout { nanos: u64 },
    DeadlineDue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmptyBackoffAction {
    Spin,
    Yield,
    Park,
}

#[inline]
fn select_backoff_deadline(
    io_phase: IoPhaseOutcome,
    timer_deadline: Option<Time>,
    local_deadline: Option<Time>,
    global_deadline: Option<Time>,
) -> Option<Time> {
    if matches!(io_phase, IoPhaseOutcome::Follower) {
        // Followers should not wake on shared global/timer deadlines. The
        // leader handles those deadlines and will wake workers when work is
        // actually runnable. Followers still honor local deadlines.
        local_deadline
    } else {
        [timer_deadline, local_deadline, global_deadline]
            .into_iter()
            .flatten()
            .min()
    }
}

#[inline]
fn record_backoff_deadline_selection(
    metrics: &mut PreemptionMetrics,
    io_phase: IoPhaseOutcome,
    timer_deadline: Option<Time>,
    global_deadline: Option<Time>,
) {
    if matches!(io_phase, IoPhaseOutcome::Follower)
        && (timer_deadline.is_some() || global_deadline.is_some())
    {
        metrics.follower_shared_deadline_ignored += 1;
    }
}

#[inline]
fn record_backoff_timeout_park(
    metrics: &mut PreemptionMetrics,
    io_phase: IoPhaseOutcome,
    nanos: u64,
) {
    metrics.backoff_parks_total += 1;
    metrics.backoff_timeout_parks_total += 1;
    metrics.backoff_timeout_nanos_total = metrics.backoff_timeout_nanos_total.saturating_add(nanos);
    if nanos <= SHORT_WAIT_LE_5MS_NANOS {
        metrics.short_wait_le_5ms += 1;
    }
    if matches!(io_phase, IoPhaseOutcome::Follower) {
        metrics.follower_timeout_parks += 1;
    }
}

#[inline]
fn classify_backoff_timeout_decision(
    _io_phase: IoPhaseOutcome,
    next_deadline: Time,
    now: Time,
) -> BackoffTimeoutDecision {
    if next_deadline <= now {
        BackoffTimeoutDecision::DeadlineDue
    } else {
        let nanos = next_deadline.duration_since(now);
        // Always park even for sub-5ms timeouts. The previous optimisation
        // (SkipShortFollowerTimeout) would `break` the inner backoff loop,
        // but the outer scheduling loop restarted with backoff=0, causing
        // full SPIN_LIMIT+YIELD_LIMIT busy-loops without ever parking.
        // A sub-5ms futex park is far cheaper than that spin storm.
        BackoffTimeoutDecision::ParkTimeout { nanos }
    }
}

#[inline]
fn record_backoff_indefinite_park(metrics: &mut PreemptionMetrics, io_phase: IoPhaseOutcome) {
    metrics.backoff_parks_total += 1;
    metrics.backoff_indefinite_parks += 1;
    if matches!(io_phase, IoPhaseOutcome::Follower) {
        metrics.follower_indefinite_parks += 1;
    }
}

#[inline]
#[allow(clippy::cast_precision_loss)]
#[allow(dead_code)]
fn usize_to_f64(value: usize) -> f64 {
    value as f64
}

#[inline]
#[allow(clippy::cast_precision_loss)]
fn u64_to_f64(value: u64) -> f64 {
    value as f64
}

#[inline]
#[allow(clippy::cast_precision_loss)]
fn normalized_entropy(probs: &[f64]) -> f64 {
    if probs.len() <= 1 {
        return 0.0;
    }
    let mut entropy = 0.0_f64;
    for &p in probs {
        if p > f64::EPSILON {
            entropy = p.mul_add(-p.ln(), entropy);
        }
    }
    let max_entropy = (probs.len() as f64).ln();
    if max_entropy <= f64::EPSILON {
        0.0
    } else {
        (entropy / max_entropy).clamp(0.0, 1.0)
    }
}

/// Snapshot of scheduler-relevant state at an adaptive epoch boundary.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AdaptiveEpochSnapshot {
    potential: f64,
    deadline_pressure: f64,
    effective_limit_exceedances: u64,
    fallback_cancel_dispatches: u64,
}

impl AdaptiveEpochSnapshot {
    fn reward_against(self, end: Self, epoch_steps: u32) -> f64 {
        // Reward lives in [0, 1]. It mixes Lyapunov decrease with fairness and
        // deadline penalties so the online policy has a stable objective.
        let denom = self.potential.abs() + 1.0;
        let normalized_drop = ((self.potential - end.potential) / denom).clamp(-1.0, 1.0);
        let deadline_penalty = ((end.deadline_pressure - self.deadline_pressure).max(0.0)
            / (self.deadline_pressure.abs() + 1.0))
            .clamp(0.0, 1.0);
        let eps = f64::from(epoch_steps.max(1));
        let effective_exceedances = u64_to_f64(
            end.effective_limit_exceedances
                .saturating_sub(self.effective_limit_exceedances),
        );
        // `base_limit_exceedances` is redundant when no governor boost is active
        // (`effective_limit == base_limit`) and actively misleading during
        // DrainObligations/DrainRegions, where the scheduler intentionally
        // allows `cancel_streak` to run into the `(L, 2L]` window. Penalize
        // only true effective-limit violations so adaptive learning does not
        // widen the baseline limit in response to sanctioned drain-mode work.
        let fairness_penalty = effective_exceedances / eps;
        let fallback_penalty = u64_to_f64(
            end.fallback_cancel_dispatches
                .saturating_sub(self.fallback_cancel_dispatches),
        ) / eps;

        let reward = 0.5f64.mul_add(normalized_drop, 0.5);
        let reward = (-0.2f64).mul_add(deadline_penalty, reward);
        let reward = (-0.2f64).mul_add(fairness_penalty.clamp(0.0, 1.0), reward);
        let reward = (-0.1f64).mul_add(fallback_penalty.clamp(0.0, 1.0), reward);

        reward.clamp(0.0, 1.0)
    }
}

/// Discounted UCB1 policy for adaptive cancel-streak limits.
#[derive(Debug, Clone)]
pub(crate) struct AdaptiveCancelStreakPolicy {
    arms: [usize; ADAPTIVE_STREAK_ARMS.len()],
    mean_rewards: [f64; ADAPTIVE_STREAK_ARMS.len()],
    discounted_pulls: [f64; ADAPTIVE_STREAK_ARMS.len()],
    pulls: [u64; ADAPTIVE_STREAK_ARMS.len()],
    selected_arm: usize,
    epoch_steps: u32,
    steps_in_epoch: u32,
    epoch_count: u64,
    reward_ema: f64,
    e_process_log: f64,
    epoch_start: Option<AdaptiveEpochSnapshot>,
}

impl AdaptiveCancelStreakPolicy {
    fn new(epoch_steps: u32) -> Self {
        let arms = ADAPTIVE_STREAK_ARMS;
        Self {
            arms,
            mean_rewards: [0.0; ADAPTIVE_STREAK_ARMS.len()],
            discounted_pulls: [0.0; ADAPTIVE_STREAK_ARMS.len()],
            pulls: [0; ADAPTIVE_STREAK_ARMS.len()],
            selected_arm: 2, // default arm == 16
            epoch_steps: epoch_steps.max(1),
            steps_in_epoch: 0,
            epoch_count: 0,
            reward_ema: 0.5,
            e_process_log: 0.0,
            epoch_start: None,
        }
    }

    fn set_epoch_steps(&mut self, epoch_steps: u32) {
        let epoch_steps = epoch_steps.max(1);
        if self.epoch_steps == epoch_steps {
            return;
        }
        self.epoch_steps = epoch_steps;
        // Drop any in-flight epoch window when the operator changes the
        // configured length. Carrying the old snapshot/progress forward would
        // mix two different epoch regimes into one reward update and skew both
        // learning and the exposed adaptive metrics (br-asupersync-nr5uak).
        self.steps_in_epoch = 0;
        self.epoch_start = None;
    }

    fn abort_epoch(&mut self) {
        self.steps_in_epoch = 0;
        self.epoch_start = None;
    }

    fn reset_to_priors(&mut self) {
        let epoch_steps = self.epoch_steps;
        *self = Self::new(epoch_steps);
    }

    fn current_limit(&self) -> usize {
        self.arms[self.selected_arm]
    }

    fn select_arm_ucb(&self) -> usize {
        let total_discounted_pulls: f64 = self.discounted_pulls.iter().sum();

        // If no arms have been pulled, start with the default arm
        if total_discounted_pulls < f64::EPSILON {
            return 2; // default arm == 16
        }

        for (i, &n_i) in self.discounted_pulls.iter().enumerate() {
            if n_i < f64::EPSILON {
                return i;
            }
        }

        // All arms have prior mass, so the exploration term shared across the
        // scan can be hoisted out of the per-arm loop.
        let exploration_scale = ADAPTIVE_UCB_CONFIDENCE * total_discounted_pulls.ln().sqrt();

        let mut best_arm = 0;
        let mut best_ucb = f64::NEG_INFINITY;

        for i in 0..self.arms.len() {
            let n_i = self.discounted_pulls[i];
            let confidence_bound = exploration_scale / n_i.sqrt();
            let ucb_value = self.mean_rewards[i] + confidence_bound;

            if ucb_value > best_ucb {
                best_ucb = ucb_value;
                best_arm = i;
            }
        }

        best_arm
    }

    fn begin_epoch(&mut self, snapshot: AdaptiveEpochSnapshot) {
        self.epoch_start = Some(snapshot);
    }

    fn on_dispatch(&mut self) -> bool {
        self.steps_in_epoch = self.steps_in_epoch.saturating_add(1);
        self.steps_in_epoch >= self.epoch_steps
    }

    fn complete_epoch(&mut self, end: AdaptiveEpochSnapshot) -> Option<f64> {
        let start = self.epoch_start?;
        let reward = start.reward_against(end, self.epoch_steps);

        let chosen = self.selected_arm;

        // Apply discounting to all arms to handle non-stationary rewards
        for i in 0..self.arms.len() {
            self.discounted_pulls[i] *= ADAPTIVE_UCB_DISCOUNT;
        }

        // Update chosen arm with new reward using incremental mean update
        let old_n = self.discounted_pulls[chosen];
        let new_n = old_n + 1.0;
        let delta = reward - self.mean_rewards[chosen];
        self.mean_rewards[chosen] += delta / new_n;
        self.discounted_pulls[chosen] = new_n;

        self.e_process_log += ADAPTIVE_EPROCESS_LAMBDA
            .mul_add(reward - 0.5, -(ADAPTIVE_EPROCESS_LAMBDA.powi(2) / 8.0));
        self.reward_ema = 0.9f64.mul_add(self.reward_ema, 0.1 * reward);
        self.pulls[chosen] = self.pulls[chosen].saturating_add(1);
        self.epoch_count = self.epoch_count.saturating_add(1);
        self.steps_in_epoch = 0;

        // Select next arm using UCB1
        self.selected_arm = self.select_arm_ucb();

        self.epoch_start = Some(end);
        Some(reward)
    }

    fn e_value(&self) -> f64 {
        self.e_process_log.clamp(-60.0, 60.0).exp()
    }
}

/// Bench-only wrapper for constructing adaptive epoch snapshots from the
/// external `benches/` crate without exposing the internal scheduler type.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, Copy)]
pub struct AdaptivePolicyBenchSnapshot(AdaptiveEpochSnapshot);

#[cfg(feature = "test-internals")]
impl AdaptivePolicyBenchSnapshot {
    /// Create a bench snapshot with the same fields used by the adaptive
    /// cancel-streak reward function.
    #[must_use]
    pub fn new(
        potential: f64,
        deadline_pressure: f64,
        _base_limit_exceedances: u64,
        effective_limit_exceedances: u64,
        fallback_cancel_dispatches: u64,
    ) -> Self {
        Self(AdaptiveEpochSnapshot {
            potential,
            deadline_pressure,
            effective_limit_exceedances,
            fallback_cancel_dispatches,
        })
    }
}

/// Bench-only adapter for exercising the adaptive cancel-streak policy from the
/// external Criterion target without making the policy internals part of the
/// public runtime API.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone)]
pub struct AdaptiveCancelStreakPolicyBench {
    policy: AdaptiveCancelStreakPolicy,
}

#[cfg(feature = "test-internals")]
impl AdaptiveCancelStreakPolicyBench {
    /// Create a new adaptive-policy bench harness.
    #[must_use]
    pub fn new(epoch_steps: u32) -> Self {
        Self {
            policy: AdaptiveCancelStreakPolicy::new(epoch_steps),
        }
    }

    /// Return the fixed number of adaptive cancel-streak arms.
    #[must_use]
    pub fn arm_count(&self) -> usize {
        self.policy.arms.len()
    }

    /// Force the selected arm for the next epoch.
    pub fn force_selected_arm(&mut self, arm_index: usize) {
        assert!(arm_index < self.policy.arms.len(), "arm index out of range");
        self.policy.selected_arm = arm_index;
    }

    /// Seed the policy with synthetic reward and pull history.
    pub fn seed_history(
        &mut self,
        mean_rewards: [f64; ADAPTIVE_STREAK_ARMS.len()],
        discounted_pulls: [f64; ADAPTIVE_STREAK_ARMS.len()],
    ) {
        self.policy.mean_rewards = mean_rewards;
        self.policy.discounted_pulls = discounted_pulls;
    }

    /// Begin an adaptive epoch from a bench snapshot.
    pub fn begin_epoch(&mut self, snapshot: AdaptivePolicyBenchSnapshot) {
        self.policy.begin_epoch(snapshot.0);
    }

    /// Complete an adaptive epoch from a bench snapshot.
    pub fn complete_epoch(&mut self, end: AdaptivePolicyBenchSnapshot) -> Option<f64> {
        self.policy.complete_epoch(end.0)
    }

    /// Inspect the discounted per-arm pull masses used by the adaptive policy.
    #[must_use]
    pub fn discounted_pulls(&self) -> [f64; ADAPTIVE_STREAK_ARMS.len()] {
        self.policy.discounted_pulls
    }

    /// Inspect the current per-arm mean rewards.
    #[must_use]
    pub fn mean_rewards(&self) -> [f64; ADAPTIVE_STREAK_ARMS.len()] {
        self.policy.mean_rewards
    }

    /// Return the current anytime-valid e-process value.
    #[must_use]
    pub fn e_value(&self) -> f64 {
        self.policy.e_value()
    }

    /// Select the next arm using the current UCB state.
    #[must_use]
    pub fn select_arm_ucb(&self) -> usize {
        self.policy.select_arm_ucb()
    }
}

/// Deterministic reasons for selecting a ready-lane batch size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdaptiveBatchDecisionReason {
    /// Adaptive batching is disabled; use the fixed scheduler batch size.
    Disabled,
    /// No adaptive win was detected; keep the fixed scheduler batch size.
    FixedFallback,
    /// Producer contention and backlog justify a temporary larger batch.
    ReadyContentionScaleUp,
    /// Cancel backlog is high enough that ready batching should contract.
    CancelDebtFloor,
    /// Hold the previously-selected larger batch for a short cooldown window.
    CooldownHold,
}

/// Test-facing profile for adaptive ready-batch sizing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveBatchSizingProfile {
    /// Enables adaptive selection when `true`.
    pub enabled: bool,
    /// Smallest batch size allowed while the profile is active.
    pub min_batch_size: usize,
    /// Largest batch size allowed while the profile is active.
    pub max_batch_size: usize,
    /// Minimum ready depth required before the scheduler can scale up.
    pub scale_up_ready_depth: usize,
    /// Minimum observed combiner in-flight depth required before scale-up.
    pub scale_up_in_flight: usize,
    /// Minimum combiner claim-failure delta required before scale-up.
    pub scale_up_claim_failures: usize,
    /// Cancel-debt floor that forces the batch size down to `min_batch_size`.
    pub cancel_debt_floor: usize,
    /// Number of subsequent batch drains that should keep the scaled-up size.
    pub cooldown_steps: usize,
}

impl AdaptiveBatchSizingProfile {
    #[inline]
    fn normalized(self, fixed_batch_size: usize) -> Self {
        let fixed_batch_size = fixed_batch_size.max(1);
        let min_batch_size = self.min_batch_size.max(1);
        let max_batch_size = self
            .max_batch_size
            .max(min_batch_size)
            .max(fixed_batch_size);
        Self {
            enabled: self.enabled,
            min_batch_size,
            max_batch_size,
            scale_up_ready_depth: self.scale_up_ready_depth,
            scale_up_in_flight: self.scale_up_in_flight,
            scale_up_claim_failures: self.scale_up_claim_failures,
            cancel_debt_floor: self.cancel_debt_floor,
            cooldown_steps: self.cooldown_steps,
        }
    }

    #[inline]
    fn contention_scale_up_batch_size(self, fixed_batch_size: usize) -> usize {
        let fixed_batch_size = fixed_batch_size.max(1).min(self.max_batch_size);
        if self.max_batch_size <= fixed_batch_size {
            return fixed_batch_size;
        }

        let headroom = self.max_batch_size.saturating_sub(fixed_batch_size);
        fixed_batch_size
            .saturating_add((headroom / 2).max(1))
            .clamp(self.min_batch_size, self.max_batch_size)
    }
}

/// Snapshot of the last adaptive ready-batch decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveBatchDecisionSnapshot {
    /// Batch size selected for the most recent global-ready drain decision.
    pub selected_batch_size: usize,
    /// Fixed scheduler batch size configured by the operator.
    pub fixed_batch_size: usize,
    /// Ready depth observed at the decision point.
    pub ready_depth: usize,
    /// Cancel backlog observed at the decision point.
    pub cancel_debt: usize,
    /// Highest observed combiner concurrency used to justify the decision.
    pub combiner_in_flight: usize,
    /// Delta in combiner claim failures since the prior decision point.
    pub combiner_claim_failures_delta: usize,
    /// Deterministic reason code for the selected batch size.
    pub reason: AdaptiveBatchDecisionReason,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct AdaptiveBatchRuntimeState {
    active_batch_size: usize,
    cooldown_remaining: usize,
    last_combiner_claim_failures: usize,
    last_snapshot: Option<AdaptiveBatchDecisionSnapshot>,
}

/// Coordination for waking workers.
#[derive(Debug)]
pub(crate) struct WorkerCoordinator {
    parkers: SmallVec<[Parker; 16]>,
    next_wake: CachePadded<AtomicUsize>,
    /// Bitmask for power-of-two worker counts (replaces IDIV with AND).
    /// `None` when the count is zero or non-power-of-two.
    mask: Option<usize>,
    /// I/O driver handle for waking the reactor.
    io_driver: Option<IoDriverHandle>,
}

impl WorkerCoordinator {
    pub(crate) fn new(parkers: SmallVec<[Parker; 16]>, io_driver: Option<IoDriverHandle>) -> Self {
        let count = parkers.len();
        let mask = if count > 0 && count.is_power_of_two() {
            Some(count - 1)
        } else {
            None
        };
        Self {
            parkers,
            next_wake: CachePadded::new(AtomicUsize::new(0)),
            mask,
            io_driver,
        }
    }

    #[inline]
    fn wake_one_parker_prefer_waiter(&self) -> bool {
        let count = self.parkers.len();
        if count == 0 {
            return false;
        }

        let start = self.next_wake.fetch_add(1, Ordering::AcqRel);
        let slot_for = |index: usize| {
            // Use bitmask (AND) when worker count is power-of-two to avoid IDIV.
            self.mask.map_or_else(|| index % count, |mask| index & mask)
        };

        // br-asupersync-ppdgkg: A permit sent to a busy worker can be absorbed
        // while another worker sleeps indefinitely. Search from the
        // round-robin cursor for a Parker that is actually waiting and has no
        // permit yet.
        for offset in 0..count {
            let slot = slot_for(start.wrapping_add(offset));
            if self.parkers[slot].unpark_if_waiting() {
                return true;
            }
        }

        // Nobody is observably parked. Preserve the permit model and
        // round-robin distribution so a worker racing into park consumes a
        // wake instead of sleeping past newly published work.
        self.parkers[slot_for(start)].unpark();
        true
    }

    #[inline]
    pub(crate) fn wake_one(&self) {
        if !self.wake_one_parker_prefer_waiter() {
            return;
        }
        if let Some(io) = &self.io_driver {
            let _ = io.wake();
        }
    }

    /// Publishes one concrete Parker permit without calling the reactor.
    ///
    /// RuntimeState uses this beneath its outer lock after enqueueing deferred
    /// cancellation work. Keeping this boundary Parker-only prevents a
    /// user-supplied reactor callback from running under that lock while still
    /// closing the final-check/park lost-wakeup race.
    #[inline]
    pub(crate) fn wake_one_parker(&self) {
        self.wake_one_parker_prefer_waiter();
    }

    #[inline]
    pub(crate) fn wake_many(&self, num_wakes: usize) {
        let count = self.parkers.len();
        if count == 0 || num_wakes == 0 {
            return;
        }
        if num_wakes >= count {
            self.wake_all();
            return;
        }
        for _ in 0..num_wakes {
            self.wake_one_parker_prefer_waiter();
        }
        if let Some(io) = &self.io_driver {
            let _ = io.wake();
        }
    }

    #[inline]
    pub(crate) fn wake_worker(&self, worker_id: WorkerId) {
        if let Some(parker) = self.parkers.get(worker_id) {
            parker.unpark();
        }
        if let Some(io) = &self.io_driver {
            let _ = io.wake();
        }
    }

    #[inline]
    pub(crate) fn wake_all(&self) {
        for parker in &self.parkers {
            parker.unpark();
        }
        if let Some(io) = &self.io_driver {
            let _ = io.wake();
        }
    }
}

thread_local! {
    static CURRENT_LOCAL: RefCell<Option<Arc<Mutex<PriorityScheduler>>>> =
        const { RefCell::new(None) };
    /// Non-stealable queue for local (`!Send`) tasks.
    ///
    /// Local tasks must never be stolen across workers. This queue is only
    /// drained by the owner worker, never exposed to stealers.
    static CURRENT_LOCAL_READY: RefCell<Option<Arc<LocalReadyQueue>>> =
        const { RefCell::new(None) };
    /// Thread-local worker id for routing local tasks.
    static CURRENT_WORKER_ID: RefCell<Option<WorkerId>> = const { RefCell::new(None) };
}

/// Scoped setter for the thread-local scheduler pointer.
///
/// When active, [`ThreeLaneScheduler::spawn`] will schedule onto this local
/// scheduler instead of injecting into the global ready queue.
#[derive(Debug)]
pub(crate) struct ScopedLocalScheduler {
    prev: Option<Arc<Mutex<PriorityScheduler>>>,
}

impl ScopedLocalScheduler {
    pub(crate) fn new(local: Arc<Mutex<PriorityScheduler>>) -> Self {
        let prev = CURRENT_LOCAL.with(|cell| cell.replace(Some(local)));
        Self { prev }
    }
}

impl Drop for ScopedLocalScheduler {
    fn drop(&mut self) {
        let prev = self.prev.take();
        CURRENT_LOCAL.with(|cell| {
            *cell.borrow_mut() = prev;
        });
    }
}

/// Scoped setter for the thread-local worker id.
pub(crate) struct ScopedWorkerId {
    prev: Option<WorkerId>,
}

impl ScopedWorkerId {
    pub(crate) fn new(id: WorkerId) -> Self {
        let prev = CURRENT_WORKER_ID.with(|cell| cell.replace(Some(id)));
        Self { prev }
    }
}

impl Drop for ScopedWorkerId {
    fn drop(&mut self) {
        let prev = self.prev.take();
        let _ = CURRENT_WORKER_ID.try_with(|cell| {
            *cell.borrow_mut() = prev;
        });
    }
}

pub(crate) struct ScopedLocalReady {
    prev: Option<Arc<LocalReadyQueue>>,
}

impl ScopedLocalReady {
    pub(crate) fn new(queue: Arc<LocalReadyQueue>) -> Self {
        let prev = CURRENT_LOCAL_READY.with(|cell| cell.replace(Some(queue)));
        Self { prev }
    }
}

impl Drop for ScopedLocalReady {
    fn drop(&mut self) {
        CURRENT_LOCAL_READY.with(|cell| {
            *cell.borrow_mut() = self.prev.take();
        });
    }
}

/// Schedules a local (`!Send`) task on the current thread's non-stealable queue.
///
/// Returns `true` if a local-ready queue was available on this thread.
#[inline]
pub(crate) fn schedule_local_task(task: TaskId) -> bool {
    CURRENT_LOCAL_READY.with(|cell| {
        cell.borrow().as_ref().is_some_and(|queue| {
            queue.lock().push_back(task);
            true
        })
    })
}

#[inline]
pub(crate) fn current_worker_id() -> Option<WorkerId> {
    CURRENT_WORKER_ID.with(|cell| *cell.borrow())
}

fn trapped_scc_with_edge_observer<F>(
    adjacency: &[Vec<usize>],
    mut observe_edge: F,
) -> Option<Vec<usize>>
where
    F: FnMut(usize, usize),
{
    struct Tarjan<'a, F> {
        adjacency: &'a [Vec<usize>],
        observe_edge: &'a mut F,
        index: usize,
        stack: Vec<usize>,
        on_stack: Vec<bool>,
        indices: Vec<Option<usize>>,
        lowlink: Vec<usize>,
        trapped: Option<Vec<usize>>,
    }

    impl<F: FnMut(usize, usize)> Tarjan<'_, F> {
        fn strongconnect(&mut self, v: usize) {
            if self.trapped.is_some() {
                return;
            }

            self.indices[v] = Some(self.index);
            self.lowlink[v] = self.index;
            self.index += 1;
            self.stack.push(v);
            self.on_stack[v] = true;

            for &w in &self.adjacency[v] {
                if self.trapped.is_some() {
                    return;
                }

                (self.observe_edge)(v, w);

                if self.indices[w].is_none() {
                    self.strongconnect(w);
                    if self.trapped.is_some() {
                        return;
                    }
                    self.lowlink[v] = self.lowlink[v].min(self.lowlink[w]);
                } else if self.on_stack[w] {
                    self.lowlink[v] = self.lowlink[v].min(self.indices[w].unwrap_or(usize::MAX));
                }
            }

            if self.lowlink[v] == self.indices[v].unwrap_or(usize::MAX) {
                let mut component = Vec::new();
                while let Some(w) = self.stack.pop() {
                    self.on_stack[w] = false;
                    component.push(w);
                    if w == v {
                        break;
                    }
                }

                let cyclic = component.len() > 1
                    || component
                        .first()
                        .is_some_and(|n| self.adjacency[*n].contains(n));
                if cyclic {
                    let component_set: BTreeSet<usize> = component.iter().copied().collect();
                    let mut has_egress = false;
                    for &u in &component {
                        if self.adjacency[u].iter().any(|v| !component_set.contains(v)) {
                            has_egress = true;
                            break;
                        }
                    }
                    if !has_egress {
                        component.sort_unstable();
                        self.trapped = Some(component);
                    }
                }
            }
        }
    }

    let n = adjacency.len();
    let mut tarjan = Tarjan {
        adjacency,
        observe_edge: &mut observe_edge,
        index: 0,
        stack: Vec::new(),
        on_stack: vec![false; n],
        indices: vec![None; n],
        lowlink: vec![0; n],
        trapped: None,
    };

    for v in 0..n {
        if tarjan.indices[v].is_none() {
            tarjan.strongconnect(v);
            if tarjan.trapped.is_some() {
                return tarjan.trapped;
            }
        }
    }

    None
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
// Precise causes are populated as wait-site registration paths are wired up;
// current production snapshots fall back to Unknown.
#[allow(dead_code)]
enum WaitCause {
    Lock,
    Channel,
    Notify,
    Join,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
struct WaitLocation {
    file: Option<&'static str>,
    line: Option<u32>,
    label: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
struct WaitGraphEdgeSnapshot {
    waiter: TaskId,
    cause: WaitCause,
    location: WaitLocation,
}

#[derive(Debug, Clone)]
struct WaitGraphTaskSnapshot {
    id: TaskId,
    waiters: Vec<TaskId>,
    wait_edges: Vec<WaitGraphEdgeSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct DeadlockWaitEdgeReport {
    waiter: TaskId,
    blocked_on: TaskId,
    cause: WaitCause,
    location: WaitLocation,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct DeadlockCycleReport {
    tasks: Vec<TaskId>,
    edges: Vec<DeadlockWaitEdgeReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct WaitGraphSignalReport {
    node_count: usize,
    undirected_edges: Vec<(usize, usize)>,
    trapped_wait_cycle: bool,
    trapped_cycle: Option<DeadlockCycleReport>,
}

fn wait_graph_snapshot_from_state(state: &RuntimeState) -> Vec<WaitGraphTaskSnapshot> {
    // br-asupersync-1ckzhy: minimize allocations under state lock by
    // avoiding filter_map chains and using direct iteration.
    let mut snapshots = Vec::new();

    for (_, task) in state.tasks_iter() {
        if !task.state.is_terminal() {
            let wait_edges = task
                .waiters
                .iter()
                .copied()
                .map(|waiter| WaitGraphEdgeSnapshot {
                    waiter,
                    cause: WaitCause::Unknown,
                    location: WaitLocation::default(),
                })
                .collect();
            snapshots.push(WaitGraphTaskSnapshot {
                id: task.id,
                waiters: task.waiters.to_vec(),
                wait_edges,
            });
        }
    }
    snapshots
}

fn wait_graph_signal_report_from_snapshot(
    tasks: &[WaitGraphTaskSnapshot],
) -> WaitGraphSignalReport {
    let mut live_tasks: Vec<TaskId> = tasks.iter().map(|task| task.id).collect();
    live_tasks.sort();
    let index_by_task: BTreeMap<TaskId, usize> = live_tasks
        .iter()
        .enumerate()
        .map(|(idx, id)| (*id, idx))
        .collect();
    let mut undirected_edges: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut adjacency = vec![Vec::new(); live_tasks.len()];

    for task in tasks {
        let Some(&task_idx) = index_by_task.get(&task.id) else {
            continue;
        };
        for edge in &task.wait_edges {
            if let Some(&waiter_idx) = index_by_task.get(&edge.waiter) {
                adjacency[waiter_idx].push(task_idx);
                if waiter_idx == task_idx {
                    continue;
                }
                undirected_edges.insert(if waiter_idx < task_idx {
                    (waiter_idx, task_idx)
                } else {
                    (task_idx, waiter_idx)
                });
            }
        }
        if task.wait_edges.is_empty() {
            for waiter in &task.waiters {
                if let Some(&waiter_idx) = index_by_task.get(waiter) {
                    adjacency[waiter_idx].push(task_idx);
                    if waiter_idx == task_idx {
                        continue;
                    }
                    undirected_edges.insert(if waiter_idx < task_idx {
                        (waiter_idx, task_idx)
                    } else {
                        (task_idx, waiter_idx)
                    });
                }
            }
        }
    }

    for edges in &mut adjacency {
        edges.sort_unstable();
        edges.dedup();
    }
    let trapped_scc = trapped_scc_with_edge_observer(&adjacency, |_, _| {});
    let trapped_cycle = trapped_scc.as_ref().map(|component| {
        let component_set: BTreeSet<usize> = component.iter().copied().collect();
        let cycle_tasks: Vec<TaskId> = component.iter().map(|idx| live_tasks[*idx]).collect();
        let mut edges = Vec::new();

        for snapshot in tasks {
            let Some(&task_idx) = index_by_task.get(&snapshot.id) else {
                continue;
            };
            if !component_set.contains(&task_idx) {
                continue;
            }

            for edge in &snapshot.wait_edges {
                let Some(&waiter_idx) = index_by_task.get(&edge.waiter) else {
                    continue;
                };
                if component_set.contains(&waiter_idx) {
                    edges.push(DeadlockWaitEdgeReport {
                        waiter: edge.waiter,
                        blocked_on: snapshot.id,
                        cause: edge.cause,
                        location: edge.location,
                    });
                }
            }
            if snapshot.wait_edges.is_empty() {
                for waiter in &snapshot.waiters {
                    let Some(&waiter_idx) = index_by_task.get(waiter) else {
                        continue;
                    };
                    if component_set.contains(&waiter_idx) {
                        edges.push(DeadlockWaitEdgeReport {
                            waiter: *waiter,
                            blocked_on: snapshot.id,
                            cause: WaitCause::Unknown,
                            location: WaitLocation::default(),
                        });
                    }
                }
            }
        }

        edges.sort_by_key(|edge| (edge.waiter, edge.blocked_on, edge.cause, edge.location));
        DeadlockCycleReport {
            tasks: cycle_tasks,
            edges,
        }
    });

    WaitGraphSignalReport {
        node_count: live_tasks.len(),
        undirected_edges: undirected_edges.into_iter().collect(),
        trapped_wait_cycle: trapped_cycle.is_some(),
        trapped_cycle,
    }
}

fn wait_graph_signals_from_snapshot(
    tasks: &[WaitGraphTaskSnapshot],
) -> (usize, Vec<(usize, usize)>, bool) {
    let report = wait_graph_signal_report_from_snapshot(tasks);
    (
        report.node_count,
        report.undirected_edges,
        report.trapped_wait_cycle,
    )
}

#[cfg(test)]
fn wait_graph_signals_from_state(state: &RuntimeState) -> (usize, Vec<(usize, usize)>, bool) {
    let snapshot = wait_graph_snapshot_from_state(state);
    wait_graph_signals_from_snapshot(&snapshot)
}

#[inline]
pub(crate) fn schedule_on_current_local(task: TaskId, priority: u8) -> bool {
    // Fast path: O(1) push to LocalQueue VecDeque
    if LocalQueue::schedule_local(task) {
        return true;
    }
    // Slow path: O(log n) push to PriorityScheduler BinaryHeap
    CURRENT_LOCAL.with(|cell| {
        if let Some(local) = cell.borrow().as_ref() {
            local.lock().schedule(task, priority);
            return true;
        }
        false
    })
}

#[inline]
fn move_local_ready_task_to_cancel_lane(
    local: &Mutex<PriorityScheduler>,
    local_ready: &LocalReadyQueue,
    task: TaskId,
    priority: u8,
) {
    let mut local_guard = local.lock();
    // br-asupersync-ayg4ot: O(1) tombstone instead of O(n) position-scan + O(n)
    // VecDeque::remove. The task is authoritatively re-queued into the cancel
    // lane below; pop_front drops its stale local_ready entry when it surfaces.
    local_ready.lock().tombstone(task);
    local_guard.move_to_cancel_lane(task, priority);
}

#[inline]
pub(crate) fn schedule_cancel_on_current_local(task: TaskId, priority: u8) -> bool {
    CURRENT_LOCAL.with(|cell| {
        let borrow = cell.borrow();
        let Some(local) = borrow.as_ref() else {
            return false;
        };
        // LOCK ORDER: local (A) then local_ready (B) - fixes E→D→B→A→C ordering violation
        // br-asupersync-3hazwm: Corrected lock ordering to prevent deadlock
        let mut local_guard = local.lock();
        CURRENT_LOCAL_READY.with(|lr_cell| {
            if let Some(queue) = lr_cell.borrow().as_ref() {
                // br-asupersync-ayg4ot: O(1) tombstone, not O(n) scan + remove.
                queue.lock().tombstone(task);
            }
        });
        local_guard.move_to_cancel_lane(task, priority);
        drop(local_guard);
        true
    })
}

/// A multi-worker scheduler with 3-lane priority support.
///
/// Each worker maintains a local `PriorityScheduler` for tasks spawned within
/// that worker. Cross-thread wakeups go through the shared `GlobalInjector`.
/// Workers strictly process cancel work before timed, and timed before ready.
///
/// All scheduling paths go through `wake_state.notify()` to provide centralized
/// deduplication, preventing the same task from being scheduled in multiple queues.
#[derive(Debug)]
pub struct ThreeLaneScheduler {
    /// Global injection queue for cross-thread wakeups.
    global: Arc<GlobalInjector>,
    /// Per-worker local schedulers for routing pinned local tasks.
    local_schedulers: Vec<Arc<Mutex<PriorityScheduler>>>,
    /// Per-worker non-stealable queues for local (`!Send`) tasks.
    local_ready: SmallVec<[Arc<LocalReadyQueue>; 16]>,
    /// Per-worker parkers for targeted wakeups.
    parkers: SmallVec<[Parker; 16]>,
    /// Worker handles for thread spawning.
    workers: SmallVec<[ThreeLaneWorker; 16]>,
    /// Shutdown signal.
    shutdown: Arc<AtomicBool>,
    /// Coordination for waking workers.
    coordinator: Arc<WorkerCoordinator>,
    /// Browser-style ready dispatch burst limit before a host-turn handoff.
    ///
    /// `0` disables forced handoff behavior.
    browser_ready_handoff_limit: usize,
    /// Maximum number of ready tasks to steal in one batch.
    steal_batch_size: usize,
    /// Whether workers are allowed to park when idle.
    enable_parking: bool,
    /// Timer driver for processing timer wakeups.
    #[allow(dead_code)] // Timer integration in progress
    timer_driver: Option<TimerDriverHandle>,
    /// Shared runtime state for accessing task records and wake_state.
    state: Arc<ContendedMutex<RuntimeState>>,
    /// Optional sharded task table for hot-path task operations.
    ///
    /// When present, inject/spawn methods use this instead of the full
    /// RuntimeState lock for task record lookups (wake_state, is_local, etc.).
    task_table: Option<Arc<ContendedMutex<TaskTable>>>,
    /// Maximum global ready queue depth (0 = unbounded).
    global_queue_limit: usize,
    /// Optional shared collector for runtime scheduler evidence snapshots.
    scheduler_evidence: Option<Arc<Mutex<SchedulerEvidenceCollector>>>,
    /// Deterministic placement mode for cohort-aware stealing.
    placement_mode: SchedulerPlacementMode,
    /// Explicit worker-to-cohort map currently applied to the scheduler.
    worker_cohort_map: Option<Vec<usize>>,
    /// Number of configured worker cohorts used for locality-aware stealing.
    cohort_count: usize,
    /// Lock-free spawn intake drained by workers at dispatch time
    /// (br-asupersync-dx-core-api-v2-u1z5hn.1.3). `None` in direct mode.
    spawn_mailbox: Option<Arc<crate::runtime::spawn_mailbox::SpawnMailbox>>,
}

/// Discriminator for [`ThreeLaneScheduler::schedule_internal`]
/// (br-asupersync-unay5q).
///
/// `spawn` and `wake` share an identical scheduling body; the only
/// caller-visible divergence is the diagnostic strings emitted when a
/// `!Send` task fails to route. This enum carries those strings so a
/// single hot-path implementation services both entry points.
#[derive(Copy, Clone)]
enum ScheduleIntent {
    Spawn,
    Wake,
}

impl ScheduleIntent {
    /// Message for the `debug_assert!(false, ...)` panic in debug builds when
    /// a `!Send` task cannot be routed. Matches the strings the original
    /// split `spawn` / `wake` functions emitted byte-for-byte.
    fn local_route_failure_assert(self, task: TaskId) -> String {
        match self {
            Self::Spawn => format!(
                "Attempted to spawn local task {task:?} from non-owner thread or outside worker context"
            ),
            Self::Wake => format!(
                "Attempted to wake local task {task:?} via scheduler from non-owner thread. Use Waker instead."
            ),
        }
    }

    /// Message for the `error!(...)` log line in release builds when a
    /// `!Send` task cannot be routed. Matches the original `spawn` / `wake`
    /// strings byte-for-byte.
    fn local_route_failure_log(self) -> &'static str {
        match self {
            Self::Spawn => {
                "spawn: local task cannot be scheduled from non-owner thread, spawn skipped"
            }
            Self::Wake => "wake: local task cannot be woken from non-owner thread, wake skipped",
        }
    }
}

impl ThreeLaneScheduler {
    #[inline]
    fn initial_local_scheduler_capacity(worker_count: usize) -> usize {
        let workers = worker_count.max(1);
        let per_worker = LOCAL_SCHEDULER_BURST_BUDGET.div_ceil(workers);
        per_worker.clamp(LOCAL_SCHEDULER_MIN_CAPACITY, LOCAL_SCHEDULER_MAX_CAPACITY)
    }

    /// Creates a new 3-lane scheduler with the given number of workers.
    ///
    /// br-asupersync-niczb3: `worker_count` MUST be `>= 1`. The
    /// infallible constructors clamp `0` to `1` internally — see
    /// the underlying `new_with_options_and_task_table` — but
    /// callers that want explicit failure on a misconfigured
    /// zero-worker count should prefer
    /// [`try_new_with_options_and_task_table`](Self::try_new_with_options_and_task_table)
    /// or [`try_new`](Self::try_new) which return
    /// `Err(ErrorKind::ConfigError)` instead of clamping. A
    /// zero-worker scheduler can never dispatch any task; pre-fix
    /// the silent clamp existed only to clamp `cancel_streak_limit`,
    /// and `worker_count == 0` produced an empty `workers` Vec that
    /// silently hung `block_on` forever.
    pub fn new(worker_count: usize, state: &Arc<ContendedMutex<RuntimeState>>) -> Self {
        Self::new_with_options(worker_count, state, DEFAULT_CANCEL_STREAK_LIMIT, false, 32)
    }

    /// br-asupersync-niczb3: fallible variant of [`Self::new`] that
    /// rejects `worker_count == 0` with `ErrorKind::ConfigError`
    /// instead of silently clamping.
    pub fn try_new(
        worker_count: usize,
        state: &Arc<ContendedMutex<RuntimeState>>,
    ) -> Result<Self, crate::error::Error> {
        Self::try_new_with_options_and_task_table(
            worker_count,
            state,
            None,
            DEFAULT_CANCEL_STREAK_LIMIT,
            false,
            32,
        )
    }

    /// Creates a new 3-lane scheduler with a configurable cancel streak limit.
    pub fn new_with_cancel_limit(
        worker_count: usize,
        state: &Arc<ContendedMutex<RuntimeState>>,
        cancel_streak_limit: usize,
    ) -> Self {
        Self::new_with_options(worker_count, state, cancel_streak_limit, false, 32)
    }

    /// Creates a new 3-lane scheduler with full configuration options.
    ///
    /// When `enable_governor` is true, each worker maintains a
    /// [`LyapunovGovernor`] that periodically snapshots runtime state and
    /// produces scheduling suggestions. When false, behavior is identical
    /// to the ungoverned baseline.
    pub fn new_with_options(
        worker_count: usize,
        state: &Arc<ContendedMutex<RuntimeState>>,
        cancel_streak_limit: usize,
        enable_governor: bool,
        governor_interval: u32,
    ) -> Self {
        Self::new_with_options_and_task_table(
            worker_count,
            state,
            None,
            cancel_streak_limit,
            enable_governor,
            governor_interval,
        )
    }

    /// Creates a new 3-lane scheduler with full configuration and a sharded task table.
    ///
    /// When `task_table` is `Some`, hot-path operations (task record lookups,
    /// future storage/retrieval, LocalQueue push/pop) lock only the task table
    /// instead of the full RuntimeState. Cross-cutting operations
    /// (`task_completed`, `drain_ready_async_finalizers`) still use RuntimeState.
    /// This constructor is currently a direct integration seam used by tests
    /// and fuzzing; `RuntimeBuilder` still gates the sharded state shape, and
    /// mailbox admission does not yet migrate newly admitted records into this
    /// external table. RuntimeState-created async-finalizer tasks likewise
    /// remain embedded, so this seam does not claim end-to-end execution of
    /// asynchronous finalizers through the external table.
    ///
    /// br-asupersync-niczb3: `worker_count == 0` is silently clamped
    /// to `1` here so existing infallible callers do not regress.
    /// New callers that want strict validation should use
    /// [`try_new_with_options_and_task_table`](Self::try_new_with_options_and_task_table)
    /// which returns `Err(ErrorKind::ConfigError)` for the same
    /// input.
    #[allow(clippy::too_many_lines)]
    pub fn new_with_options_and_task_table(
        worker_count: usize,
        state: &Arc<ContendedMutex<RuntimeState>>,
        task_table: Option<Arc<ContendedMutex<TaskTable>>>,
        cancel_streak_limit: usize,
        enable_governor: bool,
        governor_interval: u32,
    ) -> Self {
        // br-asupersync-niczb3: clamp worker_count >= 1 so the
        // infallible path can never silently produce a zero-worker
        // scheduler that hangs block_on. Callers that want strict
        // rejection of zero use try_new_with_options_and_task_table.
        let worker_count = worker_count.max(1);
        let cancel_streak_limit = cancel_streak_limit.max(1);
        let browser_ready_handoff_limit = DEFAULT_BROWSER_READY_HANDOFF_LIMIT;
        let governor_interval = governor_interval.max(1);
        let steal_batch_size = DEFAULT_STEAL_BATCH_SIZE;
        let enable_parking = DEFAULT_ENABLE_PARKING;
        let global = Arc::new(GlobalInjector::new());
        let scheduler_evidence = None;
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut workers = SmallVec::<[ThreeLaneWorker; 16]>::with_capacity(worker_count);
        let mut parkers = SmallVec::<[Parker; 16]>::with_capacity(worker_count);
        let mut local_schedulers: Vec<Arc<Mutex<PriorityScheduler>>> =
            Vec::with_capacity(worker_count);
        let mut local_ready = SmallVec::<[Arc<LocalReadyQueue>; 16]>::with_capacity(worker_count);
        let local_scheduler_capacity = Self::initial_local_scheduler_capacity(worker_count);

        // Get IO driver and timer driver from runtime state
        let (io_driver, timer_driver) = {
            let guard = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (guard.io_driver_handle(), guard.timer_driver_handle())
        };

        // Create local schedulers first so we can share references for stealing
        for _ in 0..worker_count {
            local_schedulers.push(Arc::new(Mutex::new(PriorityScheduler::with_capacity(
                local_scheduler_capacity,
            ))));
        }
        // Create non-stealable local queues for !Send tasks
        for _ in 0..worker_count {
            local_ready.push(Arc::new(local_ready_queue(VecDeque::with_capacity(32))));
        }

        // Create parkers first
        for _ in 0..worker_count {
            parkers.push(Parker::new());
        }
        let coordinator = Arc::new(WorkerCoordinator::new(parkers.clone(), io_driver.clone()));
        let pending_cancel_dispatch_ready = {
            let mut state = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.set_pending_cancel_dispatch_coordinator(&coordinator);
            state.pending_cancel_dispatch_ready_handle()
        };

        // Create fast queues (O(1) VecDeque) for ready-lane fast path.
        // When a sharded TaskTable is available, back the queues directly
        // against it so push/pop/steal avoid the full RuntimeState lock.
        let fast_queues: Vec<LocalQueue> = (0..worker_count)
            .map(|_| {
                task_table.as_ref().map_or_else(
                    || LocalQueue::new(Arc::clone(state)),
                    |tt| LocalQueue::new_with_task_table(Arc::clone(tt)),
                )
            })
            .collect();

        // Create workers with references to all other workers' schedulers
        for id in 0..worker_count {
            let parker = parkers[id].clone();

            // Stealers: all other workers' local schedulers (excluding self)
            let stealers: SmallVec<[Arc<Mutex<PriorityScheduler>>; 16]> = local_schedulers
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != id)
                .map(|(_, sched)| Arc::clone(sched))
                .collect();
            let heap_stealer_locality: SmallVec<[StealerLocality; 16]> = (0..stealers.len())
                .map(|_| StealerLocality::SameCohort)
                .collect();

            // Fast stealers: O(1) steal from other workers' LocalQueues
            let fast_stealers: SmallVec<[local_queue::Stealer; 16]> = fast_queues
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != id)
                .map(|(_, q)| q.stealer())
                .collect();
            let fast_stealer_locality: SmallVec<[StealerLocality; 16]> = (0..fast_stealers.len())
                .map(|_| StealerLocality::SameCohort)
                .collect();

            workers.push(ThreeLaneWorker {
                id,
                local: Arc::clone(&local_schedulers[id]),
                stealers,
                preferred_heap_stealer_count: worker_count.saturating_sub(1),
                heap_stealer_locality,
                fast_queue: fast_queues[id].clone(),
                global_ready_buffer: Vec::with_capacity(steal_batch_size),
                fast_stealers,
                preferred_fast_stealer_count: worker_count.saturating_sub(1),
                fast_stealer_locality,
                local_ready: Arc::clone(&local_ready[id]),
                all_local_ready: local_ready.clone(),
                all_local_schedulers: local_schedulers.iter().cloned().collect(),
                global: Arc::clone(&global),
                state: Arc::clone(state),
                pending_cancel_dispatch_ready: Arc::clone(&pending_cancel_dispatch_ready),
                task_table: task_table.clone(),
                parker,
                coordinator: Arc::clone(&coordinator),
                spawn_mailbox: None,
                rng: DetRng::new(id as u64),
                shutdown: Arc::clone(&shutdown),
                io_driver: io_driver.clone(),
                timer_driver: timer_driver.clone(),
                steal_buffer: Vec::new(),
                steal_batch_size,
                enable_parking,
                empty_backoff: 0,
                cancel_streak: 0,
                ready_dispatch_streak: 0,
                browser_ready_handoff_limit,
                cancel_streak_limit,
                governor: if enable_governor {
                    Some(LyapunovGovernor::with_defaults())
                } else {
                    None
                },
                cached_suggestion: SchedulingSuggestion::NoPreference,
                // Prime the counter so the very first governor consultation
                // snapshots live state instead of replaying the default
                // `NoPreference` cache for `governor_interval - 1` steps.
                steps_since_snapshot: governor_interval.saturating_sub(1),
                governor_interval,
                preemption_metrics: PreemptionMetrics {
                    adaptive_current_limit: cancel_streak_limit,
                    adaptive_e_value: 1.0,
                    ..PreemptionMetrics::default()
                },
                evidence_sink: None,
                decision_contract: if enable_governor {
                    Some(super::decision_contract::SchedulerDecisionContract::new())
                } else {
                    None
                },
                decision_posterior: if enable_governor {
                    Some(franken_decision::Posterior::uniform(
                        super::decision_contract::state::COUNT,
                    ))
                } else {
                    None
                },
                adaptive_cancel_policy: None,
                spectral_monitor: if enable_governor {
                    Some(SpectralHealthMonitor::new(SpectralThresholds::default()))
                } else {
                    None
                },
                drain_certificate: if enable_governor {
                    Some(ProgressCertificate::with_defaults())
                } else {
                    None
                },
                decision_sequence: 0,
                fairness_monitor: Mutex::new(FairnessMonitor::with_defaults()),
                invariant_monitor: Mutex::new(
                    super::invariant_monitor::SchedulerInvariantMonitor::with_defaults(),
                ),
                fast_queue_dispatch_streak: 0,
                fast_queue_fairness_limit: 4, // Allow max 4 consecutive stolen work dispatches
                timed_dispatch_streak: 0,
                timed_fairness_limit: 6, // Allow max 6 consecutive EDF dispatches before FIFO fairness
                adaptive_batch_profile: None,
                adaptive_batch_state: AdaptiveBatchRuntimeState::default(),
                steal_locality_counters: StealLocalityCounters::default(),
                scheduler_evidence: scheduler_evidence.clone(),
            });
        }

        Self {
            global,
            local_schedulers,
            local_ready,
            parkers,
            workers,
            shutdown,
            coordinator,
            spawn_mailbox: None,
            timer_driver,
            state: Arc::clone(state),
            task_table,
            browser_ready_handoff_limit,
            steal_batch_size,
            enable_parking,
            global_queue_limit: 0,
            scheduler_evidence,
            placement_mode: SchedulerPlacementMode::default(),
            worker_cohort_map: None,
            cohort_count: 1,
        }
    }

    /// br-asupersync-niczb3: fallible variant of
    /// [`new_with_options_and_task_table`](Self::new_with_options_and_task_table)
    /// that rejects `worker_count == 0` with
    /// `ErrorKind::ConfigError` instead of silently clamping to
    /// `1`. Returns `Ok(Self)` for any valid `worker_count >= 1`,
    /// and propagates the same clamp-to-`>=1` rule for
    /// `cancel_streak_limit` and `governor_interval` (those clamps
    /// stay infallible because their default values fall in the
    /// valid range — only an EXPLICITLY-supplied `0` for
    /// `cancel_streak_limit` could be questionable, and the existing
    /// behaviour treats `0` as "fall back to `1`" which is sane).
    ///
    /// New callers that want strict validation against
    /// misconfigured worker counts should prefer this constructor
    /// over the infallible variants. RuntimeBuilder's eventual
    /// migration target is to surface ConfigError through its own
    /// build error path so a typo in `workers = 0` (config file)
    /// produces a clear builder error rather than a silent clamp.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::ConfigError` when `worker_count == 0`.
    pub fn try_new_with_options_and_task_table(
        worker_count: usize,
        state: &Arc<ContendedMutex<RuntimeState>>,
        task_table: Option<Arc<ContendedMutex<TaskTable>>>,
        cancel_streak_limit: usize,
        enable_governor: bool,
        governor_interval: u32,
    ) -> Result<Self, crate::error::Error> {
        if worker_count == 0 {
            return Err(
                crate::error::Error::new(crate::error::ErrorKind::ConfigError).with_message(
                    "ThreeLaneScheduler requires worker_count >= 1; \
                 a zero-worker scheduler cannot dispatch any task and \
                 silently hangs block_on. Use try_new_with_options_and_task_table \
                 to surface this as ConfigError; the infallible \
                 constructors clamp to 1 instead.",
                ),
            );
        }
        Ok(Self::new_with_options_and_task_table(
            worker_count,
            state,
            task_table,
            cancel_streak_limit,
            enable_governor,
            governor_interval,
        ))
    }

    /// Sets the maximum number of ready tasks to steal in one batch.
    ///
    /// Values less than 1 are clamped to 1 to preserve progress guarantees.
    pub fn set_steal_batch_size(&mut self, size: usize) {
        let size = size.max(1);
        self.steal_batch_size = size;
        for worker in &mut self.workers {
            worker.steal_batch_size = size;
            if worker.steal_buffer.capacity() < size {
                worker
                    .steal_buffer
                    .reserve(size - worker.steal_buffer.capacity());
            }
            if worker.global_ready_buffer.capacity() < size {
                worker
                    .global_ready_buffer
                    .reserve(size - worker.global_ready_buffer.capacity());
            }
            worker.reset_adaptive_batch_state();
        }
    }

    /// Installs or removes the adaptive ready-batch sizing profile.
    pub fn set_adaptive_batch_profile(&mut self, profile: Option<AdaptiveBatchSizingProfile>) {
        for worker in &mut self.workers {
            worker.adaptive_batch_profile = profile;
            worker.reset_adaptive_batch_state();
            worker.preemption_metrics.adaptive_batch_scale_up_events = 0;
            worker.preemption_metrics.adaptive_batch_cancel_floor_hits = 0;
            worker.preemption_metrics.adaptive_batch_cooldown_holds = 0;
            worker.preemption_metrics.adaptive_batch_max_selected = worker.fixed_ready_batch_size();
        }
    }

    /// Test and smoke-contract alias for adaptive ready-batch sizing.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-internals"))]
    pub fn set_adaptive_batch_profile_for_test(
        &mut self,
        profile: Option<AdaptiveBatchSizingProfile>,
    ) {
        self.set_adaptive_batch_profile(profile);
    }

    /// Seeds ready-combiner contention counters for deterministic adaptive-batch tests.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-internals"))]
    pub fn seed_ready_combiner_pressure_for_test(
        &self,
        max_in_flight: usize,
        combiner_claim_failures: usize,
    ) {
        self.global
            .seed_ready_combiner_pressure_for_test(max_in_flight, combiner_claim_failures);
    }

    fn ordered_steal_peers(
        worker_id: usize,
        worker_to_cohort: &[usize],
        mode: SchedulerPlacementMode,
    ) -> Vec<usize> {
        let worker_count = worker_to_cohort.len();
        let my_cohort = worker_to_cohort[worker_id];
        let mut peers = (0..worker_count)
            .filter(|&peer_id| peer_id != worker_id)
            .collect::<Vec<_>>();

        match mode {
            SchedulerPlacementMode::LocalityFirst => {
                peers.sort_by_key(|&peer_id| (worker_to_cohort[peer_id] != my_cohort, peer_id));
            }
            SchedulerPlacementMode::LatencyFirst => {
                peers.sort_by_key(|&peer_id| {
                    (
                        worker_to_cohort[peer_id] != my_cohort,
                        Self::worker_slot_distance(worker_id, peer_id, worker_count),
                        peer_id,
                    )
                });
            }
            SchedulerPlacementMode::ThroughputFirst => {
                peers.sort_unstable();
            }
        }

        peers
    }

    #[inline]
    fn preferred_stealer_count(
        mode: SchedulerPlacementMode,
        my_cohort: usize,
        worker_to_cohort: &[usize],
        ordered_peers: &[usize],
    ) -> usize {
        if matches!(mode, SchedulerPlacementMode::ThroughputFirst) {
            return ordered_peers.len();
        }
        ordered_peers
            .iter()
            .take_while(|&&peer_id| worker_to_cohort[peer_id] == my_cohort)
            .count()
    }

    #[inline]
    fn worker_slot_distance(lhs: usize, rhs: usize, worker_count: usize) -> usize {
        let forward = if rhs >= lhs {
            rhs - lhs
        } else {
            worker_count - (lhs - rhs)
        };
        forward.min(worker_count.saturating_sub(forward))
    }

    /// Applies an explicit worker-to-cohort map for locality-aware stealing.
    ///
    /// The active [`SchedulerPlacementMode`] determines whether same-cohort
    /// peers are preferred first or all peers share one randomized steal set.
    pub fn set_worker_cohort_map(
        &mut self,
        worker_to_cohort: &[usize],
    ) -> Result<(), crate::error::Error> {
        let worker_count = self.workers.len();
        if worker_count == 0 {
            return Err(
                crate::error::Error::new(crate::error::ErrorKind::ConfigError)
                    .with_message("worker cohort map requires at least one worker"),
            );
        }
        if worker_to_cohort.len() != worker_count {
            return Err(
                crate::error::Error::new(crate::error::ErrorKind::ConfigError)
                    .with_message("worker cohort map length must match worker_threads".to_string()),
            );
        }

        self.rebuild_worker_stealers(worker_to_cohort);
        self.worker_cohort_map = Some(worker_to_cohort.to_vec());
        self.cohort_count = worker_to_cohort
            .iter()
            .copied()
            .max()
            .map_or(1, |max_cohort| max_cohort.saturating_add(1));

        Ok(())
    }

    /// Sets the scheduler placement mode and rebuilds cohort steal order.
    pub fn set_scheduler_placement_mode(&mut self, mode: SchedulerPlacementMode) {
        self.placement_mode = mode;
        if let Some(worker_to_cohort) = self.worker_cohort_map.clone() {
            self.rebuild_worker_stealers(&worker_to_cohort);
        }
    }

    /// Returns the active scheduler placement mode.
    #[must_use]
    pub const fn scheduler_placement_mode(&self) -> SchedulerPlacementMode {
        self.placement_mode
    }

    fn rebuild_worker_stealers(&mut self, worker_to_cohort: &[usize]) {
        let worker_count = self.workers.len();
        let fast_queues: Vec<_> = self
            .workers
            .iter()
            .map(|worker| worker.fast_queue.clone())
            .collect();
        let local_schedulers = self.local_schedulers.clone();

        for (worker_id, worker) in self.workers.iter_mut().enumerate() {
            let my_cohort = worker_to_cohort[worker_id];
            let ordered_peers =
                Self::ordered_steal_peers(worker_id, worker_to_cohort, self.placement_mode);
            let preferred_count = Self::preferred_stealer_count(
                self.placement_mode,
                my_cohort,
                worker_to_cohort,
                &ordered_peers,
            );

            let mut fast_stealers = SmallVec::<[local_queue::Stealer; 16]>::new();
            let mut fast_stealer_locality = SmallVec::<[StealerLocality; 16]>::new();
            let mut heap_stealers = SmallVec::<[Arc<Mutex<PriorityScheduler>>; 16]>::new();
            let mut heap_stealer_locality = SmallVec::<[StealerLocality; 16]>::new();

            for peer_id in ordered_peers {
                let locality =
                    StealerLocality::from_same_cohort(worker_to_cohort[peer_id] == my_cohort);
                fast_stealers.push(fast_queues[peer_id].stealer());
                fast_stealer_locality.push(locality);
                heap_stealers.push(Arc::clone(&local_schedulers[peer_id]));
                heap_stealer_locality.push(locality);
            }

            debug_assert_eq!(fast_stealers.len(), worker_count.saturating_sub(1));
            debug_assert_eq!(heap_stealers.len(), worker_count.saturating_sub(1));

            worker.fast_stealers = fast_stealers;
            worker.preferred_fast_stealer_count = preferred_count;
            worker.fast_stealer_locality = fast_stealer_locality;
            worker.stealers = heap_stealers;
            worker.preferred_heap_stealer_count = preferred_count;
            worker.heap_stealer_locality = heap_stealer_locality;
            worker.steal_locality_counters = StealLocalityCounters::default();
        }
    }

    #[doc(hidden)]
    #[cfg(feature = "test-internals")]
    pub fn seed_worker_fast_ready_for_test(&mut self, worker_id: usize, task: TaskId) {
        self.workers[worker_id].fast_queue.push(task);
    }

    #[doc(hidden)]
    #[cfg(feature = "test-internals")]
    pub fn seed_worker_priority_ready_for_test(
        &mut self,
        worker_id: usize,
        task: TaskId,
        priority: u8,
    ) {
        self.workers[worker_id]
            .local
            .lock()
            .schedule(task, priority);
    }

    /// Enables or disables worker parking when idle.
    pub fn set_enable_parking(&mut self, enable: bool) {
        self.enable_parking = enable;
        for worker in &mut self.workers {
            worker.enable_parking = enable;
        }
    }

    /// Sets the browser-style ready dispatch burst handoff limit.
    ///
    /// When non-zero, workers force a one-shot handoff after `limit`
    /// consecutive ready-lane dispatches. This is intended for browser
    /// event-loop adapters that need bounded host-turn monopolization.
    pub fn set_browser_ready_handoff_limit(&mut self, limit: usize) {
        self.browser_ready_handoff_limit = limit;
        for worker in &mut self.workers {
            worker.browser_ready_handoff_limit = limit;
            if limit == 0 {
                worker.ready_dispatch_streak = 0;
            }
        }
    }

    /// Enables/disables adaptive cancel-streak selection for all workers.
    ///
    /// When enabled, each worker uses a deterministic discounted-UCB1 policy
    /// over fixed candidate streak limits and updates the selected arm at epoch
    /// boundaries.
    pub fn set_adaptive_cancel_streak(&mut self, enable: bool, epoch_steps: u32) {
        let epoch_steps = epoch_steps.max(1);
        for worker in &mut self.workers {
            if enable {
                if let Some(policy) = worker.adaptive_cancel_policy.as_mut() {
                    policy.set_epoch_steps(epoch_steps);
                } else {
                    worker.adaptive_cancel_policy =
                        Some(AdaptiveCancelStreakPolicy::new(epoch_steps));
                }
                if let Some(policy) = worker.adaptive_cancel_policy.as_ref() {
                    worker.preemption_metrics.adaptive_current_limit = policy.current_limit();
                    worker.preemption_metrics.adaptive_reward_ema = policy.reward_ema;
                    worker.preemption_metrics.adaptive_e_value = policy.e_value();
                }
            } else {
                worker.adaptive_cancel_policy = None;
                worker.preemption_metrics.adaptive_epochs = 0;
                worker.preemption_metrics.adaptive_current_limit = worker.cancel_streak_limit;
                worker.preemption_metrics.adaptive_reward_ema = 0.0;
                worker.preemption_metrics.adaptive_e_value = 1.0;
            }
        }
    }

    /// Sets the global ready queue depth limit (0 = unbounded).
    ///
    /// When the limit is non-zero and the global ready queue reaches this
    /// depth, new injections emit a trace warning. The task is still
    /// scheduled (dropping it would violate structured concurrency) but the
    /// warning signals backpressure to the caller.
    pub fn set_global_queue_limit(&mut self, limit: usize) {
        self.global_queue_limit = limit;
    }

    #[inline]
    fn record_scheduler_evidence_enqueue(&self, task: TaskId) {
        let Some(collector) = &self.scheduler_evidence else {
            return;
        };
        let timestamp_ns = crate::time::wall_now().as_nanos();
        collector.lock().record_task_enqueue(task, timestamp_ns);
    }

    /// Scheduler publication diagnostics and notifiers are observer boundaries.
    /// Once a lane is physically visible, neither a hostile tracing subscriber
    /// nor a fallible wake hook may unwind past the caller and strand the spawn
    /// observer that must run next.
    #[inline]
    fn contain_publication_effect(effect: impl FnOnce()) {
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(effect)) {
            std::mem::forget(payload);
        }
    }

    #[inline]
    fn finish_global_ready_publication(
        &self,
        task: TaskId,
        priority: u8,
        ready_count_before: usize,
    ) {
        let _ = priority;
        Self::contain_publication_effect(|| self.record_scheduler_evidence_enqueue(task));
        if self.global_queue_limit > 0 && ready_count_before >= self.global_queue_limit {
            Self::contain_publication_effect(|| {
                crate::tracing_compat::warn!(
                    ?task,
                    priority,
                    limit = self.global_queue_limit,
                    current = ready_count_before,
                    "inject_ready: global ready queue at capacity, scheduling anyway"
                );
            });
        }
        Self::contain_publication_effect(|| self.wake_one());
    }

    fn scheduler_evidence_remote_steal_ratio_pct(&self) -> Option<u8> {
        let (preferred, remote) =
            self.workers
                .iter()
                .fold((0_u64, 0_u64), |(preferred, remote), worker| {
                    let counters = worker.steal_locality_counters;
                    (
                        preferred
                            .saturating_add(counters.preferred_fast_steals)
                            .saturating_add(counters.preferred_heap_steals),
                        remote
                            .saturating_add(counters.remote_fast_steals)
                            .saturating_add(counters.remote_heap_steals),
                    )
                });
        let total = preferred.saturating_add(remote);
        if total == 0 {
            return None;
        }
        let pct = remote.saturating_mul(100).saturating_add(total / 2) / total;
        Some(u8::try_from(pct.min(100)).expect("remote steal ratio should fit in u8"))
    }

    /// Enables or disables runtime scheduler evidence capture.
    ///
    /// A `sample_window` of `0` disables the collector. Any positive value
    /// installs a shared bounded collector and propagates it to all workers.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn set_scheduler_evidence_window(&mut self, sample_window: usize) {
        let collector = (sample_window > 0)
            .then(|| Arc::new(Mutex::new(SchedulerEvidenceCollector::new(sample_window))));
        self.scheduler_evidence.clone_from(&collector);
        for worker in &mut self.workers {
            worker.scheduler_evidence.clone_from(&collector);
        }
    }

    /// Builds a live scheduler evidence artifact from the current collector snapshot.
    #[must_use]
    pub fn scheduler_evidence_artifact(
        &self,
        run_label: &str,
        workload_class: SchedulerWorkloadClass,
        memory_budget_gib: usize,
    ) -> Option<SchedulerEvidenceArtifact> {
        if self.workers.is_empty() {
            return None;
        }
        let collector = self.scheduler_evidence.as_ref()?;
        let remote_steal_ratio_pct = self.scheduler_evidence_remote_steal_ratio_pct();
        let collector = collector.lock();
        let sample_window = collector.sample_window();
        let (wake_to_run_samples, queue_residency_samples, ready_backlog_samples, cancel_samples) =
            collector.sample_counts();
        let metrics = collector.snapshot_metrics(remote_steal_ratio_pct);
        drop(collector);

        let cancel_streak_limit = self
            .workers
            .first()
            .map_or(DEFAULT_CANCEL_STREAK_LIMIT, |worker| {
                worker.cancel_streak_limit
            });

        Some(SchedulerEvidenceArtifact {
            schema_version: SCHEDULER_EVIDENCE_SCHEMA_VERSION.to_string(),
            run_label: run_label.to_string(),
            workload_class,
            topology: SchedulerTopologyDescriptor {
                worker_threads: self.workers.len(),
                cohort_count: self.cohort_count.max(1),
                memory_budget_gib,
            },
            current_knobs: SchedulerKnobProfile {
                worker_threads: self.workers.len(),
                steal_batch_size: self.steal_batch_size,
                cancel_streak_limit,
                global_queue_limit: self.global_queue_limit,
                parking_enabled: self.enable_parking,
            },
            metrics,
            notes: vec![
                "runtime_capture".to_string(),
                format!("placement_mode={}", self.placement_mode.as_str()),
                format!("sample_window={sample_window}"),
                format!(
                    "sample_counts=wake_to_run:{wake_to_run_samples},queue_residency:{queue_residency_samples},ready_backlog:{ready_backlog_samples},cancel_debt:{cancel_samples}"
                ),
            ],
        })
    }

    #[doc(hidden)]
    #[cfg(any(test, feature = "test-internals"))]
    pub fn worker_mut_for_test(&mut self, worker_id: usize) -> &mut ThreeLaneWorker {
        &mut self.workers[worker_id]
    }

    /// Returns a reference to the global injector.
    #[must_use]
    pub fn global_injector(&self) -> Arc<GlobalInjector> {
        self.global.clone()
    }

    /// Read-only task table access for inject/spawn methods.
    ///
    /// Uses the sharded task table when available, otherwise falls back to
    /// RuntimeState's embedded table.
    #[inline]
    fn with_task_table_ref<R, F: FnOnce(&TaskTable) -> R>(&self, f: F) -> R {
        if let Some(tt) = &self.task_table {
            let guard = tt.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            f(&guard)
        } else {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            f(&state.tasks)
        }
    }

    #[inline]
    fn clear_task_wake_state(&self, task: TaskId) {
        self.with_task_table_ref(|tt| {
            if let Some(record) = tt.task(task) {
                record.wake_state.clear();
            }
        });
    }

    /// Injects a task into the cancel lane for cross-thread wakeup.
    ///
    /// Uses `wake_state.notify()` for centralized deduplication.
    /// If the task is already scheduled, this is a no-op.
    /// If the task record doesn't exist (e.g., in tests), allows injection.
    pub fn inject_cancel(&self, task: TaskId, priority: u8) {
        let (is_local, pinned_worker) = self.with_task_table_ref(|tt| {
            tt.task(task).map_or((false, None), |record| {
                if record.is_local() {
                    record.wake_state.notify();
                }
                (record.is_local(), record.pinned_worker())
            })
        });

        if is_local {
            if let Some(worker_id) = pinned_worker {
                if let Some(local) = self.local_schedulers.get(worker_id) {
                    // LOCK ORDER: local (A) then local_ready (B) - fixes E→D→B→A→C ordering
                    // br-asupersync-3hazwm: Corrected lock ordering to prevent deadlock
                    let mut local_guard = local.lock();
                    if let Some(local_ready) = self.local_ready.get(worker_id) {
                        // br-asupersync-ayg4ot: O(1) tombstone, not O(n) scan + remove.
                        local_ready.lock().tombstone(task);
                    }
                    local_guard.move_to_cancel_lane(task, priority);
                    drop(local_guard);
                    Self::contain_publication_effect(|| {
                        self.record_scheduler_evidence_enqueue(task);
                    });
                    if let Some(parker) = self.parkers.get(worker_id) {
                        Self::contain_publication_effect(|| parker.unpark());
                    }
                    return;
                }
            }
            if schedule_cancel_on_current_local(task, priority) {
                Self::contain_publication_effect(|| {
                    self.record_scheduler_evidence_enqueue(task);
                });
                return;
            }
            // SAFETY: Local (!Send) tasks must only be polled on their owner
            // worker. If we can't route to the correct worker, skipping cancel
            // injection may cause a hang but avoids UB from wrong-thread polling.
            self.clear_task_wake_state(task);
            debug_assert!(
                false,
                "Attempted to inject_cancel local task {task:?} without owner worker"
            );
            Self::contain_publication_effect(|| {
                error!(
                    ?task,
                    "inject_cancel: cannot route local task to owner worker, cancel skipped"
                );
            });
            return;
        }

        // Cancel is the highest-priority lane and PROMOTES a task that may
        // already be queued in a lower lane (ready/timed). Unlike ready/timed
        // injection, cancel injection is NOT gated on `wake_state.notify()`:
        // a task that is already "notified" because it sits in the ready or
        // timed lane must still be promoted into the cancel lane, otherwise a
        // cancel request issued for an already-scheduled task would be silently
        // dropped. We still call `notify()` for wake bookkeeping (it is
        // idempotent), but we always inject into the cancel lane.
        //
        // To avoid a duplicate dispatch (the same task firing from both the
        // cancel and the timed lane), we drop any pending timed entry for this
        // task. The ready lane is FIFO and dispatched after cancel; its stale
        // entry is harmless because the dispatcher consumes wake_state on the
        // cancel pop. The whole sequence runs under the task-table lock so the
        // notify/inject pair stays atomic against concurrent injectors.
        self.with_task_table_ref(|tt| {
            if let Some(record) = tt.task(task) {
                record.wake_state.notify();
            }
            self.global.remove_timed(task);
            self.global.inject_cancel(task, priority);
        });

        Self::contain_publication_effect(|| self.record_scheduler_evidence_enqueue(task));
        Self::contain_publication_effect(|| self.wake_one());
    }

    /// Injects a task into the timed lane for cross-thread wakeup.
    ///
    /// Uses `wake_state.notify()` for centralized deduplication.
    /// If the task is already scheduled, this is a no-op.
    /// If the task record doesn't exist (e.g., in tests), allows injection.
    pub fn inject_timed(&self, task: TaskId, deadline: Time) {
        // Atomic check-and-inject: both the wake_state check and injection happen
        // under the same task table lock to prevent TOCTOU races.
        let injected = self.with_task_table_ref(|tt| {
            match tt.task(task) {
                Some(record) => {
                    if record.wake_state.notify() {
                        // Task state allows scheduling, inject while holding lock
                        self.global.inject_timed(task, deadline);
                        true
                    } else {
                        // Task already scheduled or completed, skip injection
                        false
                    }
                }
                None => {
                    // Task record doesn't exist (e.g., in tests), allow injection
                    self.global.inject_timed(task, deadline);
                    true
                }
            }
        });

        if injected {
            self.record_scheduler_evidence_enqueue(task);
            self.wake_one();
        }
    }

    /// Injects an admitted task into the ready lane with queue-limit diagnostics.
    ///
    /// Admission policy belongs before task creation and must return an explicit
    /// rejection or backpressure result. Once `wake_state.notify()` succeeds,
    /// this path must publish the task: silently dropping it would strand its
    /// join state and any obligations it owns.
    #[inline]
    fn inject_global_ready_checked(&self, task: TaskId, priority: u8) {
        let ready_count_before = self.global.ready_count();
        self.global.inject_ready(task, priority);
        self.finish_global_ready_publication(task, priority, ready_count_before);
    }

    /// Injects a task into the ready lane for cross-thread wakeup.
    ///
    /// Uses `wake_state.notify()` for centralized deduplication.
    /// If the task is already scheduled, this is a no-op.
    /// If the task record doesn't exist (e.g., in tests), allows injection.
    ///
    /// # Panics
    ///
    /// Panics if the task is a local (`!Send`) task. Local tasks must be
    /// scheduled via their `Waker` (which knows the owner) or `spawn` on the
    /// owner thread. Injecting them globally would allow them to be stolen
    /// by the wrong worker, causing data loss.
    pub fn inject_ready(&self, task: TaskId, priority: u8) {
        // Atomic check-and-inject: both the wake_state check and injection happen
        // under the same task table lock to prevent TOCTOU races.
        let (injected, is_local, ready_count_before) = self.with_task_table_ref(|tt| {
            match tt.task(task) {
                Some(record) => {
                    let is_local = record.is_local();
                    if is_local {
                        // Local tasks cannot be globally injected
                        (false, true, 0)
                    } else if record.wake_state.notify() {
                        // Task state allows scheduling, inject while holding lock
                        let ready_count_before = self.global.ready_count();
                        self.global.inject_ready(task, priority);
                        (true, false, ready_count_before)
                    } else {
                        // Task already scheduled or completed, skip injection
                        (false, false, 0)
                    }
                }
                None => {
                    // Task record doesn't exist (e.g., in tests), allow injection
                    let ready_count_before = self.global.ready_count();
                    self.global.inject_ready(task, priority);
                    (true, false, ready_count_before)
                }
            }
        });

        // SAFETY: Local (!Send) tasks must only be polled on their owner worker.
        // Injecting globally would allow wrong-thread polling = UB.
        debug_assert!(
            !is_local,
            "Attempted to globally inject local task {task:?}. Local tasks must be scheduled on their owner thread."
        );
        if is_local {
            error!(
                ?task,
                "inject_ready: refusing to globally inject local task, scheduling skipped"
            );
            return;
        }

        if injected {
            self.finish_global_ready_publication(task, priority, ready_count_before);
            Self::contain_publication_effect(|| {
                trace!(
                    ?task,
                    priority, "inject_ready: task injected into global ready queue"
                );
            });
        } else {
            Self::contain_publication_effect(|| {
                trace!(
                    ?task,
                    priority, "inject_ready: task NOT scheduled (should_schedule=false)"
                );
            });
        }
    }

    /// Spawns a task (shorthand for inject_ready).
    ///
    /// Fast path: when called on a worker thread, pushes to the worker's
    /// `LocalQueue` (O(1) VecDeque) instead of the global injector
    /// or the PriorityScheduler heap.
    ///
    /// # Local Tasks
    ///
    /// If the task is local (`!Send`), it attempts to schedule it on the current
    /// thread if it matches the owner. If called from a non-owner thread, it
    /// attempts to route the task to the pinned worker's `local_ready` queue.
    #[inline]
    pub fn spawn(&self, task: TaskId, priority: u8) {
        self.schedule_internal(task, priority, ScheduleIntent::Spawn);
    }

    /// Wakes a task by injecting it into the ready lane.
    ///
    /// Fast path: when called on a worker thread, pushes to the worker's
    /// `LocalQueue` (O(1)) or `PriorityScheduler` instead of the global
    /// injector. For cancel wakeups, use `inject_cancel` instead.
    ///
    /// # Local Tasks
    ///
    /// If the task is local (`!Send`), it attempts to schedule it on the current
    /// thread if it matches the owner. If called from a non-owner thread, it
    /// attempts to route the task to the pinned worker's `local_ready` queue.
    #[inline]
    pub fn wake(&self, task: TaskId, priority: u8) {
        self.schedule_internal(task, priority, ScheduleIntent::Wake);
    }

    /// Common scheduling path for `spawn` and `wake` (br-asupersync-unay5q).
    ///
    /// Body is byte-identical between the two callers; the only divergence is
    /// the diagnostic strings emitted when a `!Send` task cannot be routed
    /// (different verbs, plus the wake-path's "use Waker instead" hint).
    /// Those strings come from [`ScheduleIntent`] so a single body services
    /// both entry points — keeping the hot scheduling path in one I-cache
    /// line and removing the maintenance hazard that any future
    /// cancel-vs-spawn divergence would otherwise have to be implemented
    /// twice.
    fn schedule_internal(&self, task: TaskId, priority: u8, intent: ScheduleIntent) {
        // Dedup: check wake_state before scheduling anywhere.
        // KNOWN RACE CONDITION (TOCTOU): Same issue as injection methods - race window
        // between checking wake_state.notify() and subsequent scheduling operations.
        let (should_schedule, is_local, pinned_worker) = self.with_task_table_ref(|tt| {
            tt.task(task).map_or((true, false, None), |record| {
                (
                    record.wake_state.notify(),
                    record.is_local(),
                    record.pinned_worker(),
                )
            })
        });

        if !should_schedule {
            return;
        }

        if is_local {
            let current_worker = current_worker_id();
            let is_pinned_here = match (pinned_worker, current_worker) {
                (Some(pw), Some(cw)) => pw == cw,
                (None, Some(_)) => true,
                _ => false,
            };

            // 1. Try scheduling on current thread (fastest, no locks if TLS setup)
            // ONLY if this thread is the owner.
            if is_pinned_here && schedule_local_task(task) {
                self.record_scheduler_evidence_enqueue(task);
                return;
            }

            // 2. Try routing to pinned worker (cross-thread spawn / wake).
            if let Some(worker_id) = pinned_worker {
                if let Some(queue) = self.local_ready.get(worker_id) {
                    queue.lock().push_back(task);
                    self.record_scheduler_evidence_enqueue(task);
                    self.coordinator.wake_worker(worker_id);
                    return;
                }
            }

            // 3. Failure: Cannot route local task. Diagnostic strings vary by
            //    intent (spawn vs wake) — see `ScheduleIntent` for the exact
            //    text the original split functions emitted.
            let assert_msg = intent.local_route_failure_assert(task);
            let _error_msg = intent.local_route_failure_log();
            self.clear_task_wake_state(task);
            debug_assert!(false, "{}", assert_msg);
            error!(?task, "{}", _error_msg);
            return;
        }

        // Fast path 1 & 2: Try local queue (O(1)) then local scheduler (O(log n)) via TLS.
        if schedule_on_current_local(task, priority) {
            self.record_scheduler_evidence_enqueue(task);
            return;
        }

        // Slow path: global injector (off worker thread).
        self.inject_global_ready_checked(task, priority);
    }

    /// Wakes one idle worker.
    #[inline]
    fn wake_one(&self) {
        self.coordinator.wake_one();
    }

    /// Wakes all idle workers.
    pub fn wake_all(&self) {
        self.coordinator.wake_all();
    }

    /// Extract workers to run them in threads.
    /// Attaches the spawn mailbox to this scheduler and all not-yet-taken
    /// workers (br-asupersync-dx-core-api-v2-u1z5hn.1.3). Call before
    /// [`Self::take_workers`].
    pub fn attach_spawn_mailbox(
        &mut self,
        mailbox: Arc<crate::runtime::spawn_mailbox::SpawnMailbox>,
    ) {
        for worker in &mut self.workers {
            worker.spawn_mailbox = Some(Arc::clone(&mailbox));
        }
        self.spawn_mailbox = Some(mailbox);
    }

    /// Wakes one worker after a producer enqueued a spawn request, closing
    /// the lost-wakeup race against a fully parked fleet (enqueue happens
    /// outside the scheduler, so park-side rechecks alone cannot see it).
    pub fn notify_spawn_enqueued(&self) {
        self.coordinator.wake_one();
    }

    /// Returns a detachable notifier equivalent to
    /// [`Self::notify_spawn_enqueued`], for storage inside the producer-side
    /// spawn gateway (br-asupersync-hwjqyo / A2.2).
    #[must_use]
    pub fn spawn_enqueued_notifier(&self) -> Arc<dyn Fn() + Send + Sync> {
        let coordinator = Arc::clone(&self.coordinator);
        Arc::new(move || coordinator.wake_one())
    }

    pub fn take_workers(&mut self) -> Vec<ThreeLaneWorker> {
        std::mem::take(&mut self.workers).into_vec()
    }

    /// Signals all workers to shutdown.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        self.wake_all();
    }

    /// Returns true if shutdown has been signaled.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StealerLocality {
    SameCohort,
    CrossCohort,
}

impl StealerLocality {
    #[inline]
    const fn from_same_cohort(same_cohort: bool) -> Self {
        if same_cohort {
            Self::SameCohort
        } else {
            Self::CrossCohort
        }
    }

    #[inline]
    const fn is_same_cohort(self) -> bool {
        matches!(self, Self::SameCohort)
    }
}

/// A worker thread for the 3-lane scheduler.
#[derive(Debug)]
pub struct ThreeLaneWorker {
    /// Unique worker ID.
    pub id: WorkerId,
    /// Local 3-lane scheduler for this worker.
    pub local: Arc<Mutex<PriorityScheduler>>,
    /// References to other workers' local schedulers for stealing.
    pub stealers: SmallVec<[Arc<Mutex<PriorityScheduler>>; 16]>,
    /// Number of heap stealers in the first randomized placement segment.
    ///
    /// Locality/latency modes use same-cohort peers for this segment;
    /// throughput mode includes every peer in one load-balancing segment.
    preferred_heap_stealer_count: usize,
    /// Locality classification matching each heap stealer slot.
    heap_stealer_locality: SmallVec<[StealerLocality; 16]>,
    /// O(1) local queue for ready tasks (work-stealing fast path).
    ///
    /// Ready tasks spawned/woken on the worker thread are pushed here
    /// (VecDeque, O(1)) instead of the PriorityScheduler (BinaryHeap,
    /// O(log n)). Stealers use FIFO ordering for cache-friendliness.
    pub fast_queue: LocalQueue,
    /// Prefetched FIFO slice from the global ready queue.
    ///
    /// When the shared ready queue is deep, the worker drains a bounded batch
    /// into this buffer so subsequent phase-3 ready dispatches stay local and
    /// avoid repeatedly contending on the injector atomics. The buffer is kept
    /// in reverse order so `pop()` yields the oldest prefetched task first.
    global_ready_buffer: Vec<PriorityTask>,
    /// Stealers for other workers' fast queues (O(1) steal).
    fast_stealers: SmallVec<[local_queue::Stealer; 16]>,
    /// Number of fast stealers in the first randomized placement segment.
    ///
    /// Locality/latency modes use same-cohort peers for this segment;
    /// throughput mode includes every peer in one load-balancing segment.
    preferred_fast_stealer_count: usize,
    /// Locality classification matching each fast stealer slot.
    fast_stealer_locality: SmallVec<[StealerLocality; 16]>,
    /// Non-stealable queue for local (`!Send`) tasks.
    ///
    /// Local tasks are pinned to their owner worker and must never be stolen.
    /// This queue is only drained by the owner worker during `try_ready_work()`.
    local_ready: Arc<LocalReadyQueue>,
    /// References to all workers' non-stealable local queues.
    ///
    /// Used to route local waiters to their owner worker's queue when a task
    /// completes and needs to wake a pinned waiter on a different worker.
    all_local_ready: SmallVec<[Arc<LocalReadyQueue>; 16]>,
    /// Every worker's priority scheduler, indexed by pinned worker id, for
    /// publishing deferred cancellation before any Waker callback runs.
    all_local_schedulers: SmallVec<[Arc<Mutex<PriorityScheduler>>; 16]>,
    /// Global injection queue.
    pub global: Arc<GlobalInjector>,
    /// Shared runtime state.
    pub state: Arc<ContendedMutex<RuntimeState>>,
    /// Lock-free hint for the exceptional deferred-cancellation queue.
    pending_cancel_dispatch_ready: Arc<AtomicBool>,
    /// Optional sharded task table for hot-path task operations.
    ///
    /// When present, `execute()` and scheduling helpers lock this instead
    /// of the full RuntimeState for task record access, future storage,
    /// and wake_state operations.
    pub task_table: Option<Arc<ContendedMutex<TaskTable>>>,
    /// Parking mechanism for idle workers.
    pub parker: Parker,
    /// Coordination for waking other workers.
    pub(crate) coordinator: Arc<WorkerCoordinator>,
    /// Lock-free spawn intake to drain at dispatch time (mailbox mode only).
    pub(crate) spawn_mailbox: Option<Arc<crate::runtime::spawn_mailbox::SpawnMailbox>>,
    /// Deterministic RNG for stealing decisions.
    pub rng: DetRng,
    /// Shutdown signal.
    pub shutdown: Arc<AtomicBool>,
    /// I/O driver handle for polling the reactor (optional).
    pub io_driver: Option<IoDriverHandle>,
    /// Timer driver for processing timer wakeups (optional).
    pub timer_driver: Option<TimerDriverHandle>,
    /// Scratch buffer for stolen tasks (avoid per-steal allocations).
    steal_buffer: Vec<(TaskId, u8)>,
    /// Maximum number of ready tasks to steal in one batch.
    steal_batch_size: usize,
    /// Whether this worker is allowed to park when idle.
    enable_parking: bool,
    /// Persistent empty-work backoff state across idle outer-loop iterations.
    empty_backoff: u32,
    /// Number of consecutive cancel-lane dispatches.
    cancel_streak: usize,
    /// Number of consecutive ready-lane dispatches.
    ready_dispatch_streak: usize,
    /// Browser-style ready dispatch burst limit before yielding host turn.
    ///
    /// `0` disables host-turn handoff gating.
    browser_ready_handoff_limit: usize,
    /// Maximum consecutive cancel-lane dispatches before yielding.
    ///
    /// Fairness guarantee: if timed or ready work is pending, it will be
    /// dispatched after at most `cancel_streak_limit` cancel dispatches.
    cancel_streak_limit: usize,
    /// Lyapunov governor for policy-controlled scheduling suggestions.
    ///
    /// When `Some`, the worker periodically snapshots runtime state and
    /// consults the governor for lane-ordering hints.
    governor: Option<LyapunovGovernor>,
    /// Cached scheduling suggestion from the governor.
    cached_suggestion: SchedulingSuggestion,
    /// Number of scheduling steps since last governor snapshot.
    steps_since_snapshot: u32,
    /// Steps between governor snapshots.
    governor_interval: u32,
    /// Preemption fairness metrics (cancel-lane preemption tracking).
    preemption_metrics: PreemptionMetrics,
    /// Optional evidence sink for scheduler decision tracing (bd-1e2if.3).
    evidence_sink: Option<Arc<dyn crate::evidence_sink::EvidenceSink>>,
    /// Decision contract for principled scheduler action selection (bd-1e2if.6).
    decision_contract: Option<super::decision_contract::SchedulerDecisionContract>,
    /// Posterior maintained across governor invocations (bd-1e2if.6).
    decision_posterior: Option<franken_decision::Posterior>,
    /// Optional adaptive policy for selecting the cancel streak limit.
    adaptive_cancel_policy: Option<AdaptiveCancelStreakPolicy>,
    /// Spectral monitor for topology-aware early warning and overrides.
    spectral_monitor: Option<SpectralHealthMonitor>,
    /// Martingale-based drain progress certificate.
    ///
    /// When the governor is active, the certificate tracks Lyapunov potential
    /// descent during drain phases and provides statistical convergence
    /// verdicts (Azuma–Hoeffding + Freedman bounds) with phase classification
    /// (Warmup / RapidDrain / SlowTail / Stalled / Quiescent).
    drain_certificate: Option<ProgressCertificate>,
    /// Monotone sequence for deterministic decision IDs and timestamps.
    decision_sequence: u64,
    /// Enhanced fairness monitoring for starvation and priority inversion detection.
    fairness_monitor: Mutex<FairnessMonitor>,
    /// Scheduler invariant monitor for comprehensive correctness verification.
    invariant_monitor: Mutex<super::invariant_monitor::SchedulerInvariantMonitor>,
    /// Number of consecutive fast_queue (stolen work) dispatches.
    ///
    /// Tracks fairness between stolen work and local work to prevent starvation.
    /// When this counter exceeds a threshold, local work gets priority.
    fast_queue_dispatch_streak: usize,
    /// Maximum consecutive fast_queue dispatches before yielding to local work.
    ///
    /// Fairness guarantee: local work will be checked after at most this many
    /// consecutive stolen work dispatches.
    fast_queue_fairness_limit: usize,
    /// Number of consecutive timed-lane (EDF) dispatches.
    ///
    /// Tracks fairness between EDF and FIFO work to prevent FIFO starvation.
    /// When this counter exceeds a threshold, ready (FIFO) work gets priority.
    timed_dispatch_streak: usize,
    /// Maximum consecutive timed-lane dispatches before yielding to FIFO work.
    ///
    /// Fairness guarantee: FIFO work will be checked after at most this many
    /// consecutive EDF dispatches, ensuring 1/N quantum fairness invariant.
    timed_fairness_limit: usize,
    /// Optional adaptive profile for ready-lane batch sizing.
    adaptive_batch_profile: Option<AdaptiveBatchSizingProfile>,
    /// Runtime state for the adaptive ready-batch controller.
    adaptive_batch_state: AdaptiveBatchRuntimeState,
    /// Counters tracking preferred-vs-remote steal outcomes.
    steal_locality_counters: StealLocalityCounters,
    /// Optional shared collector for runtime scheduler evidence snapshots.
    scheduler_evidence: Option<Arc<Mutex<SchedulerEvidenceCollector>>>,
}

/// Worker-local counters for preferred-vs-remote steal outcomes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StealLocalityCounters {
    /// Successful same-cohort fast-queue steals.
    pub preferred_fast_steals: u64,
    /// Successful cross-cohort fast-queue steals.
    pub remote_fast_steals: u64,
    /// Successful same-cohort heap-batch steals.
    pub preferred_heap_steals: u64,
    /// Successful cross-cohort heap-batch steals.
    pub remote_heap_steals: u64,
}

#[derive(Debug)]
struct SchedulerEvidenceCollector {
    sample_window: usize,
    max_inflight: usize,
    next_sequence: u64,
    pending_enqueue: DetHashMap<TaskId, (u64, u64)>,
    pending_wake: DetHashMap<TaskId, (u64, u64)>,
    wake_order: VecDeque<(TaskId, u64)>,
    enqueue_order: VecDeque<(TaskId, u64)>,
    wake_to_run_samples_ns: VecDeque<u64>,
    queue_residency_samples_ns: VecDeque<u64>,
    ready_backlog_samples: VecDeque<usize>,
    cancel_debt_samples: VecDeque<usize>,
}

impl SchedulerEvidenceCollector {
    #[cfg(any(test, feature = "test-internals"))]
    fn new(sample_window: usize) -> Self {
        let sample_window = sample_window.max(1);
        Self {
            sample_window,
            max_inflight: sample_window
                .saturating_mul(DEFAULT_SCHEDULER_EVIDENCE_MAX_INFLIGHT_MULTIPLIER)
                .max(sample_window),
            next_sequence: 0,
            pending_enqueue: DetHashMap::default(),
            pending_wake: DetHashMap::default(),
            wake_order: VecDeque::with_capacity(sample_window),
            enqueue_order: VecDeque::with_capacity(sample_window),
            wake_to_run_samples_ns: VecDeque::with_capacity(sample_window),
            queue_residency_samples_ns: VecDeque::with_capacity(sample_window),
            ready_backlog_samples: VecDeque::with_capacity(sample_window),
            cancel_debt_samples: VecDeque::with_capacity(sample_window),
        }
    }

    fn record_task_enqueue(&mut self, task_id: TaskId, timestamp_ns: u64) {
        self.next_sequence = self.next_sequence.saturating_add(1);
        let sequence = self.next_sequence;
        self.pending_enqueue
            .insert(task_id, (timestamp_ns, sequence));
        self.enqueue_order.push_back((task_id, sequence));
        self.pending_wake.insert(task_id, (timestamp_ns, sequence));
        self.wake_order.push_back((task_id, sequence));
        self.trim_pending();
    }

    fn record_task_dispatch(
        &mut self,
        task_id: TaskId,
        dispatch_time_ns: u64,
        ready_backlog: usize,
        cancel_debt: usize,
    ) {
        let sample_window = self.sample_window;
        if let Some((enqueue_time_ns, _)) = self.pending_enqueue.remove(&task_id) {
            Self::push_u64_sample(
                &mut self.queue_residency_samples_ns,
                dispatch_time_ns.saturating_sub(enqueue_time_ns),
                sample_window,
            );
        }
        if let Some((wake_time_ns, _)) = self.pending_wake.remove(&task_id) {
            Self::push_u64_sample(
                &mut self.wake_to_run_samples_ns,
                dispatch_time_ns.saturating_sub(wake_time_ns),
                sample_window,
            );
        }
        Self::push_usize_sample(
            &mut self.ready_backlog_samples,
            ready_backlog,
            sample_window,
        );
        Self::push_usize_sample(&mut self.cancel_debt_samples, cancel_debt, sample_window);
    }

    fn sample_window(&self) -> usize {
        self.sample_window
    }

    fn sample_counts(&self) -> (usize, usize, usize, usize) {
        (
            self.wake_to_run_samples_ns.len(),
            self.queue_residency_samples_ns.len(),
            self.ready_backlog_samples.len(),
            self.cancel_debt_samples.len(),
        )
    }

    fn snapshot_metrics(&self, remote_steal_ratio_pct: Option<u8>) -> SchedulerEvidenceMetrics {
        SchedulerEvidenceMetrics {
            wake_to_run_p50_ns: percentile_u64(&self.wake_to_run_samples_ns, 50),
            wake_to_run_p95_ns: percentile_u64(&self.wake_to_run_samples_ns, 95),
            wake_to_run_p99_ns: percentile_u64(&self.wake_to_run_samples_ns, 99),
            queue_residency_p50_ns: percentile_u64(&self.queue_residency_samples_ns, 50),
            queue_residency_p95_ns: percentile_u64(&self.queue_residency_samples_ns, 95),
            queue_residency_p99_ns: percentile_u64(&self.queue_residency_samples_ns, 99),
            ready_backlog_p95: percentile_usize(&self.ready_backlog_samples, 95),
            ready_backlog_p99: percentile_usize(&self.ready_backlog_samples, 99),
            cancel_debt_p95: percentile_usize(&self.cancel_debt_samples, 95),
            cancel_debt_p99: percentile_usize(&self.cancel_debt_samples, 99),
            remote_steal_ratio_pct,
            cross_cohort_wake_p99_ns: None,
        }
    }

    fn trim_pending(&mut self) {
        while self.pending_enqueue.len() > self.max_inflight {
            let Some((task_id, sequence)) = self.enqueue_order.pop_front() else {
                break;
            };
            if self
                .pending_enqueue
                .get(&task_id)
                .is_some_and(|(_, current_sequence)| *current_sequence == sequence)
            {
                self.pending_enqueue.remove(&task_id);
            }
        }
        while self.pending_wake.len() > self.max_inflight {
            let Some((task_id, sequence)) = self.wake_order.pop_front() else {
                break;
            };
            if self
                .pending_wake
                .get(&task_id)
                .is_some_and(|(_, current_sequence)| *current_sequence == sequence)
            {
                self.pending_wake.remove(&task_id);
            }
        }
    }

    fn push_u64_sample(samples: &mut VecDeque<u64>, value: u64, sample_window: usize) {
        if samples.len() == sample_window {
            samples.pop_front();
        }
        samples.push_back(value);
    }

    fn push_usize_sample(samples: &mut VecDeque<usize>, value: usize, sample_window: usize) {
        if samples.len() == sample_window {
            samples.pop_front();
        }
        samples.push_back(value);
    }
}

fn percentile_index(len: usize, percentile: usize) -> usize {
    debug_assert!(len > 0);
    let percentile = percentile.clamp(1, 100);
    percentile
        .saturating_mul(len)
        .div_ceil(100)
        .saturating_sub(1)
        .min(len.saturating_sub(1))
}

fn percentile_u64(samples: &VecDeque<u64>, percentile: usize) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut values = samples.iter().copied().collect::<Vec<_>>();
    values.sort_unstable();
    values[percentile_index(values.len(), percentile)]
}

fn percentile_usize(samples: &VecDeque<usize>, percentile: usize) -> usize {
    if samples.is_empty() {
        return 0;
    }
    let mut values = samples.iter().copied().collect::<Vec<_>>();
    values.sort_unstable();
    values[percentile_index(values.len(), percentile)]
}

#[derive(Debug, Clone)]
struct WaiterWakeMetadata {
    priority: u8,
    is_local: bool,
    pinned_worker: Option<WorkerId>,
    wake_state: Arc<crate::record::task::TaskWakeState>,
    notified: bool,
}

/// Per-worker metrics tracking cancel-lane preemption and fairness.
#[derive(Debug, Clone, Default)]
pub struct PreemptionMetrics {
    /// Total cancel-lane dispatches.
    pub cancel_dispatches: u64,
    /// Total timed-lane dispatches.
    pub timed_dispatches: u64,
    /// Total ready-lane dispatches.
    pub ready_dispatches: u64,
    /// Browser host-turn handoffs forced by ready-burst fairness controls.
    pub browser_ready_handoff_yields: u64,
    /// Times the cancel streak hit the fairness limit.
    pub fairness_yields: u64,
    /// Worst observed cancel streak immediately before a ready dispatch.
    ///
    /// This records the largest number of consecutive cancel dispatches that a
    /// ready task actually waited through before being selected.
    pub max_ready_dispatch_stall: usize,
    /// Worst observed cancel streak immediately before a timed dispatch.
    ///
    /// This records the largest number of consecutive cancel dispatches that a
    /// due timed task actually waited through before being selected.
    pub max_timed_dispatch_stall: usize,
    /// Number of times a lower-priority global ready dispatch bypassed a
    /// higher-priority local ready task.
    pub ready_priority_inversions: u64,
    /// Largest observed priority gap for a ready-lane inversion.
    pub max_ready_priority_inversion_gap: u8,
    /// Maximum cancel streak observed.
    pub max_cancel_streak: usize,
    /// Fallback cancel dispatches (after limit, no other work available).
    pub fallback_cancel_dispatches: u64,
    /// Number of cancel dispatches where streak exceeded the base limit `L`.
    ///
    /// This can be non-zero when boosted fairness mode is active
    /// (`DrainObligations`/`DrainRegions`), where the effective limit becomes `2L`.
    pub base_limit_exceedances: u64,
    /// Number of cancel dispatches where streak exceeded the effective limit.
    ///
    /// This should remain zero for a healthy scheduler run.
    pub effective_limit_exceedances: u64,
    /// Maximum effective limit observed during dispatch.
    ///
    /// In unboosted mode this is `L`; with drain boosts this can be `2L`.
    pub max_effective_limit_observed: usize,
    /// Number of completed adaptive policy epochs.
    pub adaptive_epochs: u64,
    /// Most recently selected adaptive base cancel streak limit.
    pub adaptive_current_limit: usize,
    /// Exponential moving average of adaptive rewards.
    pub adaptive_reward_ema: f64,
    /// Anytime-valid e-process value for the adaptive reward stream.
    pub adaptive_e_value: f64,
    /// Total backoff parks performed.
    pub backoff_parks_total: u64,
    /// Backoff parks that armed a timeout.
    pub backoff_timeout_parks_total: u64,
    /// Backoff parks with indefinite sleep (no deadline armed).
    pub backoff_indefinite_parks: u64,
    /// Sum of timeout durations armed for backoff parks (nanoseconds).
    pub backoff_timeout_nanos_total: u64,
    /// Timeout parks with short waits (<= 5ms).
    pub short_wait_le_5ms: u64,
    /// Follower loops where shared timer/global deadlines were ignored.
    pub follower_shared_deadline_ignored: u64,
    /// Timeout parks performed while in follower I/O phase.
    pub follower_timeout_parks: u64,
    /// Indefinite parks performed while in follower I/O phase.
    pub follower_indefinite_parks: u64,
    /// Follower short-timeout (<= 5ms) parks intentionally skipped to avoid
    /// wake-timeout futex churn.
    pub follower_short_wait_skip_le_5ms: u64,
    /// Number of times a worker prefetched a bounded FIFO slice from the
    /// global ready queue.
    pub global_ready_batch_drains: u64,
    /// Total ready tasks drained through the global prefetch path.
    pub global_ready_batch_tasks: u64,
    /// Number of times adaptive ready batching scaled above the fixed size.
    pub adaptive_batch_scale_up_events: u64,
    /// Number of times cancel debt forced the batch size down to the floor.
    pub adaptive_batch_cancel_floor_hits: u64,
    /// Number of cooldown windows that held the prior larger batch size.
    pub adaptive_batch_cooldown_holds: u64,
    /// Largest batch size selected by the adaptive ready-batch controller.
    pub adaptive_batch_max_selected: usize,
}

impl PreemptionMetrics {
    const RATIO_BPS_SCALE: u64 = 10_000;

    #[inline]
    fn ratio_bps(numerator: u64, denominator: u64) -> u16 {
        if denominator == 0 {
            return 0;
        }
        let raw = numerator
            .saturating_mul(Self::RATIO_BPS_SCALE)
            .saturating_div(denominator)
            .min(Self::RATIO_BPS_SCALE);
        raw as u16
    }

    /// Returns the average timeout-park duration in nanoseconds.
    ///
    /// Returns `0` when no timeout parks have been recorded.
    #[must_use]
    pub fn avg_timeout_park_nanos(&self) -> u64 {
        if self.backoff_timeout_parks_total == 0 {
            return 0;
        }
        self.backoff_timeout_nanos_total
            .saturating_div(self.backoff_timeout_parks_total)
    }

    /// Returns the proportion of timeout parks that were short waits
    /// (<= 5ms) in basis points.
    ///
    /// `10_000` means 100%.
    #[must_use]
    pub fn short_wait_ratio_bps(&self) -> u16 {
        Self::ratio_bps(self.short_wait_le_5ms, self.backoff_timeout_parks_total)
    }

    /// Returns the follower short-wait avoidance rate in basis points.
    ///
    /// This compares follower short-timeout skips vs follower short-timeout
    /// opportunities (skip + timeout park).
    #[must_use]
    pub fn follower_short_wait_avoidance_bps(&self) -> u16 {
        let opportunities = self
            .follower_short_wait_skip_le_5ms
            .saturating_add(self.follower_timeout_parks);
        Self::ratio_bps(self.follower_short_wait_skip_le_5ms, opportunities)
    }

    /// Returns the worst observed cancel-induced stall across ready/timed lanes.
    #[must_use]
    pub fn max_non_cancel_dispatch_stall(&self) -> usize {
        self.max_ready_dispatch_stall
            .max(self.max_timed_dispatch_stall)
    }
}

/// Configuration for fairness monitoring and starvation detection.
#[derive(Debug, Clone)]
pub struct FairnessConfig {
    /// Maximum time a task can wait before being considered starved (nanoseconds).
    pub starvation_threshold_ns: u64,
    /// Size of the moving window for temporal pattern analysis.
    pub analysis_window_size: usize,
    /// Threshold for detecting priority inversion patterns.
    pub priority_inversion_threshold: u8,
    /// Maximum number of tasks to track for starvation monitoring.
    pub max_tracked_tasks: usize,
    /// Enable detailed per-task tracking (impacts performance).
    pub enable_per_task_tracking: bool,
}

impl Default for FairnessConfig {
    fn default() -> Self {
        Self {
            starvation_threshold_ns: 100_000_000, // 100ms
            analysis_window_size: 1000,
            priority_inversion_threshold: 5,
            max_tracked_tasks: 10_000,
            enable_per_task_tracking: true,
        }
    }
}

/// Per-task tracking information for starvation detection.
#[derive(Debug, Clone)]
struct TaskStarvationInfo {
    /// Task ID being tracked.
    task_id: TaskId,
    /// Priority of the task.
    priority: u8,
    /// Timestamp when task was first enqueued (nanoseconds).
    enqueue_time_ns: u64,
    /// Number of times this task was skipped for higher-priority work.
    skip_count: u32,
    /// Last time this task was skipped (nanoseconds).
    last_skip_time_ns: u64,
    /// Current queue lane (Cancel=0, Timed=1, Ready=2).
    current_lane: u8,
    /// Total time spent waiting across all queue entries.
    total_wait_time_ns: u64,
}

impl TaskStarvationInfo {
    fn new(task_id: TaskId, priority: u8, current_time_ns: u64, lane: u8) -> Self {
        Self {
            task_id,
            priority,
            enqueue_time_ns: current_time_ns,
            skip_count: 0,
            last_skip_time_ns: 0,
            current_lane: lane,
            total_wait_time_ns: 0,
        }
    }

    fn refresh_queue_membership(&mut self, priority: u8, current_time_ns: u64, lane: u8) {
        self.priority = priority;
        self.current_lane = lane;
        self.total_wait_time_ns = self
            .total_wait_time_ns
            .max(self.current_wait_time_ns(current_time_ns));
    }

    fn record_skip(&mut self, current_time_ns: u64) {
        self.skip_count = self.skip_count.saturating_add(1);
        self.last_skip_time_ns = current_time_ns;
        self.total_wait_time_ns = self.current_wait_time_ns(current_time_ns);
    }

    fn current_wait_time_ns(&self, current_time_ns: u64) -> u64 {
        current_time_ns.saturating_sub(self.enqueue_time_ns)
    }

    fn is_starved(&self, threshold_ns: u64, current_time_ns: u64) -> bool {
        self.current_wait_time_ns(current_time_ns) >= threshold_ns
    }
}

/// Priority inversion detection entry.
#[derive(Debug, Clone)]
struct PriorityInversionEvent {
    /// High-priority task that was blocked.
    blocked_task_id: TaskId,
    /// Priority of the blocked task.
    blocked_priority: u8,
    /// Low-priority task that was executed instead.
    executing_task_id: TaskId,
    /// Priority of the executing task.
    executing_priority: u8,
    /// Timestamp when the inversion occurred.
    timestamp_ns: u64,
    /// Duration of the inversion (nanoseconds).
    duration_ns: u64,
}

/// Moving window for temporal pattern analysis.
#[derive(Debug, Clone)]
struct StarvationAnalysisWindow {
    /// Circular buffer of starvation events.
    events: Vec<u64>,
    /// Current write position in the circular buffer.
    write_pos: usize,
    /// Total number of events recorded.
    total_events: u64,
    /// Window size.
    size: usize,
}

impl StarvationAnalysisWindow {
    fn new(size: usize) -> Self {
        Self {
            events: vec![0; size.max(1)],
            write_pos: 0,
            size: size.max(1),
            total_events: 0,
        }
    }

    fn record_event(&mut self, timestamp_ns: u64) {
        self.events[self.write_pos] = timestamp_ns;
        self.write_pos = (self.write_pos + 1) % self.size;
        self.total_events = self.total_events.saturating_add(1);
    }

    fn events_in_window(&self, window_duration_ns: u64, current_time_ns: u64) -> u32 {
        let threshold_time = current_time_ns.saturating_sub(window_duration_ns);
        let mut count = 0;
        let recorded_events = usize::try_from(self.total_events)
            .unwrap_or(usize::MAX)
            .min(self.size);

        for &event_time in self.events.iter().take(recorded_events) {
            if event_time >= threshold_time && event_time <= current_time_ns {
                count += 1;
            }
        }
        count
    }

    fn is_pattern_detected(
        &self,
        min_events: u32,
        window_duration_ns: u64,
        current_time_ns: u64,
    ) -> bool {
        self.events_in_window(window_duration_ns, current_time_ns) >= min_events
    }
}

/// Enhanced fairness monitoring framework for starvation and priority inversion detection.
#[derive(Debug)]
pub struct FairnessMonitor {
    /// Configuration for fairness monitoring.
    config: FairnessConfig,
    /// Per-task starvation tracking information.
    ///
    /// br-asupersync-ks0t6j: BTreeMap (was std::collections::HashMap)
    /// for replay-stable iteration AND deterministic eviction. With
    /// std HashMap's randomised iteration order, two tasks that
    /// share the same `enqueue_time_ns` (common under high-resolution
    /// clocks AND under lab-runtime virtual time that advances in
    /// fixed steps) had their `min_by_key` tiebreak resolved by
    /// per-process iteration order — making the fairness report
    /// non-deterministic across replays and crash-pack hashes
    /// instable. BTreeMap iterates in TaskId order, so eviction is
    /// `(enqueue_time_ns, TaskId)` deterministic even when timestamps
    /// tie. Memory cost is negligible at the documented
    /// `max_tracked_tasks=10_000` cap; lookup is O(log N) ≈ 14 vs
    /// HashMap's amortised O(1) — irrelevant on the bookkeeping path.
    /// Also closes the hash-DoS surface: a multi-tenant deployment
    /// could otherwise influence TaskId allocation order to cluster
    /// HashMap buckets and amplify the per-record_task_enqueue cost.
    tracked_tasks: BTreeMap<TaskId, TaskStarvationInfo>,
    /// Recent priority inversion events.
    priority_inversions: Vec<PriorityInversionEvent>,
    /// Moving window for starvation pattern analysis.
    starvation_window: StarvationAnalysisWindow,
    /// Total starvation events detected.
    total_starvation_events: u64,
    /// Total priority inversion events detected.
    total_priority_inversions: u64,
    /// Maximum observed task wait time.
    max_task_wait_time_ns: u64,
    /// Last cleanup timestamp to prevent unbounded growth.
    last_cleanup_time_ns: u64,
}

impl FairnessMonitor {
    /// Creates a new fairness monitor with the given configuration.
    #[must_use]
    pub fn new(config: FairnessConfig) -> Self {
        let window_size = config.analysis_window_size;
        Self {
            config,
            tracked_tasks: BTreeMap::new(),
            priority_inversions: Vec::new(),
            starvation_window: StarvationAnalysisWindow::new(window_size),
            total_starvation_events: 0,
            total_priority_inversions: 0,
            max_task_wait_time_ns: 0,
            last_cleanup_time_ns: 0,
        }
    }

    /// Creates a new fairness monitor with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(FairnessConfig::default())
    }

    /// Records a task entering a queue for starvation tracking.
    ///
    /// If the task is already being tracked, preserve its accumulated wait/skip
    /// history and only refresh the current lane + priority metadata.
    pub fn record_task_enqueue(
        &mut self,
        task_id: TaskId,
        priority: u8,
        current_time_ns: u64,
        lane: u8,
    ) {
        if !self.config.enable_per_task_tracking {
            return;
        }

        if let Some(info) = self.tracked_tasks.get_mut(&task_id) {
            info.refresh_queue_membership(priority, current_time_ns, lane);
            return;
        }

        // Cleanup old entries if needed
        self.cleanup_if_needed(current_time_ns);

        // Only track up to max_tracked_tasks to prevent unbounded growth.
        //
        // br-asupersync-ks0t6j: tiebreak ties on enqueue_time_ns by
        // TaskId so eviction is fully deterministic across replays
        // even before BTreeMap's sorted-iteration guarantee buys us
        // determinism. The (enqueue_time_ns, *id) key form makes the
        // intent explicit at the call site and survives any future
        // refactor that swaps the storage backend.
        if self.tracked_tasks.len() >= self.config.max_tracked_tasks {
            // Remove oldest entry
            if let Some((oldest_task_id, _)) = self
                .tracked_tasks
                .iter()
                .min_by_key(|(id, info)| (info.enqueue_time_ns, **id))
                .map(|(id, info)| (*id, info.clone()))
            {
                self.tracked_tasks.remove(&oldest_task_id);
            }
        }

        let info = TaskStarvationInfo::new(task_id, priority, current_time_ns, lane);
        self.tracked_tasks.insert(task_id, info);
    }

    /// Records a task being dispatched (removes from tracking).
    pub fn record_task_dispatch(&mut self, task_id: TaskId, current_time_ns: u64) -> Option<u64> {
        if let Some(info) = self.tracked_tasks.remove(&task_id) {
            let wait_time = info.current_wait_time_ns(current_time_ns);
            if wait_time > self.max_task_wait_time_ns {
                self.max_task_wait_time_ns = wait_time;
            }
            Some(wait_time)
        } else {
            None
        }
    }

    /// Records a task being skipped in favor of higher-priority work.
    pub fn record_task_skip(
        &mut self,
        skipped_task_id: TaskId,
        executing_task_id: TaskId,
        executing_priority: u8,
        current_time_ns: u64,
    ) {
        let (should_record_starvation, should_record_inversion, blocked_priority) = {
            if let Some(info) = self.tracked_tasks.get_mut(&skipped_task_id) {
                info.record_skip(current_time_ns);

                let is_starved =
                    info.is_starved(self.config.starvation_threshold_ns, current_time_ns);
                let is_inversion = info.priority > executing_priority;
                let priority = info.priority;

                (is_starved, is_inversion, priority)
            } else {
                (false, false, 0)
            }
        };

        // Record events after releasing the borrow
        if should_record_starvation {
            self.record_starvation_event(current_time_ns);
        }

        if should_record_inversion {
            self.record_priority_inversion(
                skipped_task_id,
                blocked_priority,
                executing_task_id,
                executing_priority,
                current_time_ns,
            );
        }
    }

    /// Records a starvation event for pattern analysis.
    fn record_starvation_event(&mut self, timestamp_ns: u64) {
        self.total_starvation_events = self.total_starvation_events.saturating_add(1);
        self.starvation_window.record_event(timestamp_ns);
    }

    /// Records a priority inversion event.
    fn record_priority_inversion(
        &mut self,
        blocked_task: TaskId,
        blocked_priority: u8,
        executing_task: TaskId,
        executing_priority: u8,
        timestamp_ns: u64,
    ) {
        self.total_priority_inversions = self.total_priority_inversions.saturating_add(1);

        let inversion = PriorityInversionEvent {
            blocked_task_id: blocked_task,
            blocked_priority,
            executing_task_id: executing_task,
            executing_priority,
            timestamp_ns,
            duration_ns: 0, // Will be updated when inversion ends
        };

        self.priority_inversions.push(inversion);

        // Keep only recent inversions to prevent unbounded growth
        const MAX_TRACKED_INVERSIONS: usize = 1000;
        if self.priority_inversions.len() > MAX_TRACKED_INVERSIONS {
            self.priority_inversions
                .drain(0..self.priority_inversions.len() - MAX_TRACKED_INVERSIONS);
        }
    }

    /// Detects if there's a starvation pattern in the current window.
    #[must_use]
    pub fn detect_starvation_pattern(&self, current_time_ns: u64) -> bool {
        const PATTERN_WINDOW_NS: u64 = 1_000_000_000; // 1 second
        const MIN_EVENTS_FOR_PATTERN: u32 = 10;

        self.starvation_window.is_pattern_detected(
            MIN_EVENTS_FOR_PATTERN,
            PATTERN_WINDOW_NS,
            current_time_ns,
        )
    }

    /// Returns the number of currently starved tasks.
    #[must_use]
    pub fn count_starved_tasks(&self, current_time_ns: u64) -> u32 {
        self.tracked_tasks
            .values()
            .filter(|info| info.is_starved(self.config.starvation_threshold_ns, current_time_ns))
            .count() as u32
    }

    /// Returns starvation statistics for monitoring.
    #[must_use]
    pub fn starvation_stats(&self, current_time_ns: u64) -> StarvationStats {
        let currently_starved = self.count_starved_tasks(current_time_ns);
        let total_tracked_wait_time_ns = self
            .tracked_tasks
            .values()
            .map(|info| {
                info.total_wait_time_ns
                    .max(info.current_wait_time_ns(current_time_ns))
            })
            .sum::<u64>();
        let avg_wait_time_ns = if self.tracked_tasks.is_empty() {
            0
        } else {
            total_tracked_wait_time_ns / self.tracked_tasks.len() as u64
        };
        let oldest_tracked_task = self
            .tracked_tasks
            .values()
            .max_by_key(|info| info.current_wait_time_ns(current_time_ns))
            .map(|info| StarvedTaskSummary {
                task_id: info.task_id,
                priority: info.priority,
                current_lane: info.current_lane,
                skip_count: info.skip_count,
                wait_time_ns: info.current_wait_time_ns(current_time_ns),
                total_wait_time_ns: info
                    .total_wait_time_ns
                    .max(info.current_wait_time_ns(current_time_ns)),
            });
        let latest_priority_inversion =
            self.priority_inversions
                .last()
                .map(|event| PriorityInversionSummary {
                    blocked_task_id: event.blocked_task_id,
                    blocked_priority: event.blocked_priority,
                    executing_task_id: event.executing_task_id,
                    executing_priority: event.executing_priority,
                    priority_gap: event
                        .blocked_priority
                        .saturating_sub(event.executing_priority),
                    timestamp_ns: event.timestamp_ns,
                    duration_ns: event.duration_ns,
                });
        let max_priority_inversion_gap = self
            .priority_inversions
            .iter()
            .map(|event| {
                event
                    .blocked_priority
                    .saturating_sub(event.executing_priority)
            })
            .max()
            .unwrap_or(0);

        StarvationStats {
            total_starvation_events: self.total_starvation_events,
            currently_starved_tasks: currently_starved,
            max_task_wait_time_ns: self.max_task_wait_time_ns,
            avg_task_wait_time_ns: avg_wait_time_ns,
            total_priority_inversions: self.total_priority_inversions,
            tracked_tasks_count: self.tracked_tasks.len() as u32,
            pattern_detected: self.detect_starvation_pattern(current_time_ns),
            total_tracked_wait_time_ns,
            oldest_tracked_task,
            max_priority_inversion_gap,
            latest_priority_inversion,
        }
    }

    /// Cleans up old tracking entries to prevent unbounded growth.
    fn cleanup_if_needed(&mut self, current_time_ns: u64) {
        const CLEANUP_INTERVAL_NS: u64 = 60_000_000_000; // 60 seconds
        const MAX_TASK_AGE_NS: u64 = 300_000_000_000; // 5 minutes

        if current_time_ns.saturating_sub(self.last_cleanup_time_ns) < CLEANUP_INTERVAL_NS {
            return;
        }

        self.last_cleanup_time_ns = current_time_ns;

        // Remove tasks that are too old
        let cutoff_time = current_time_ns.saturating_sub(MAX_TASK_AGE_NS);
        self.tracked_tasks
            .retain(|_, info| info.enqueue_time_ns >= cutoff_time);
    }
}

/// Starvation monitoring statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StarvedTaskSummary {
    /// Identifier of the oldest currently tracked task.
    pub task_id: TaskId,
    /// Priority assigned to the tracked task.
    pub priority: u8,
    /// Queue lane where the task is currently tracked (Cancel=0, Timed=1, Ready=2).
    pub current_lane: u8,
    /// Number of times the task has been skipped.
    pub skip_count: u32,
    /// Current wait time for the task.
    pub wait_time_ns: u64,
    /// Total accumulated wait time snapshot recorded for the task.
    pub total_wait_time_ns: u64,
}

/// Summary of the latest observed priority inversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriorityInversionSummary {
    /// High-priority task that was blocked.
    pub blocked_task_id: TaskId,
    /// Priority of the blocked task.
    pub blocked_priority: u8,
    /// Lower-priority task that executed instead.
    pub executing_task_id: TaskId,
    /// Priority of the executing task.
    pub executing_priority: u8,
    /// Difference between blocked and executing priorities.
    pub priority_gap: u8,
    /// Timestamp when the inversion was observed.
    pub timestamp_ns: u64,
    /// Recorded duration of the inversion.
    pub duration_ns: u64,
}

/// Starvation monitoring statistics.
#[derive(Debug, Clone, Default)]
pub struct StarvationStats {
    /// Total starvation events detected.
    pub total_starvation_events: u64,
    /// Number of tasks currently experiencing starvation.
    pub currently_starved_tasks: u32,
    /// Maximum observed task wait time (nanoseconds).
    pub max_task_wait_time_ns: u64,
    /// Average task wait time across all tracked tasks (nanoseconds).
    pub avg_task_wait_time_ns: u64,
    /// Total priority inversion events detected.
    pub total_priority_inversions: u64,
    /// Number of tasks currently being tracked.
    pub tracked_tasks_count: u32,
    /// Whether a starvation pattern has been detected.
    pub pattern_detected: bool,
    /// Sum of the current wait times for all tracked tasks.
    pub total_tracked_wait_time_ns: u64,
    /// Oldest task currently tracked by the monitor.
    pub oldest_tracked_task: Option<StarvedTaskSummary>,
    /// Largest priority gap observed across retained inversion events.
    pub max_priority_inversion_gap: u8,
    /// Most recent priority inversion retained by the monitor.
    pub latest_priority_inversion: Option<PriorityInversionSummary>,
}

/// Deterministic witness for the worker-local cancel-lane fairness contract.
///
/// This compiles the runtime fairness argument into an auditable artifact:
/// if `invariant_holds()` is true, then observed dispatches for one worker
/// respected the maximum effective cancel-streak bound recorded in this
/// certificate.
///
/// This is an observed dispatch-step certificate. It does not prove wall-clock
/// latency, bounded task poll duration, or global priority ordering across
/// workers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreemptionFairnessCertificate {
    /// Worker-local baseline cancel streak limit `L`.
    pub base_limit: usize,
    /// Largest effective limit observed during the run (`L` or `2L`).
    pub effective_limit: usize,
    /// Observed maximum cancel streak in this run.
    pub observed_max_cancel_streak: usize,
    /// Total cancel dispatches.
    pub cancel_dispatches: u64,
    /// Total timed dispatches.
    pub timed_dispatches: u64,
    /// Total ready dispatches.
    pub ready_dispatches: u64,
    /// Times the fairness gate forced a non-cancel attempt.
    pub fairness_yields: u64,
    /// Largest observed cancel streak immediately before a ready dispatch.
    pub observed_max_ready_stall_steps: usize,
    /// Largest observed cancel streak immediately before a timed dispatch.
    pub observed_max_timed_stall_steps: usize,
    /// Number of observed ready-lane priority inversions.
    pub ready_priority_inversions: u64,
    /// Largest observed ready-lane priority gap when an inversion occurred.
    pub max_ready_priority_inversion_gap: u8,
    /// Fallback cancel dispatches used when no other work existed.
    pub fallback_cancel_dispatches: u64,
    /// Count of streak samples above baseline `L`.
    pub base_limit_exceedances: u64,
    /// Count of streak samples above effective limit.
    pub effective_limit_exceedances: u64,
    /// Whether adaptive cancel-streak policy was active.
    pub adaptive_enabled: bool,
    /// Current adaptive base limit (if enabled), otherwise equals `base_limit`.
    pub adaptive_current_limit: usize,
}

impl PreemptionFairnessCertificate {
    /// Returns the worker-local non-cancel dispatch-opportunity bound.
    ///
    /// Under this run's observed policy envelope, sustained eligible
    /// ready/timed/stealable-ready work gets a scheduling opportunity within
    /// `effective_limit + 1` successful dispatch steps by the same worker.
    #[must_use]
    pub fn ready_stall_bound_steps(&self) -> usize {
        self.effective_limit.saturating_add(1)
    }

    /// Returns the largest observed cancel-induced stall across ready/timed work.
    #[must_use]
    pub fn observed_non_cancel_stall_steps(&self) -> usize {
        self.observed_max_ready_stall_steps
            .max(self.observed_max_timed_stall_steps)
    }

    /// Returns `true` when fairness invariants hold for observed dispatches.
    #[must_use]
    pub fn invariant_holds(&self) -> bool {
        self.effective_limit_exceedances == 0
            && self.observed_max_cancel_streak <= self.effective_limit
            && self.ready_priority_inversions == 0
    }

    /// Deterministic hash of the certificate contents for replay/audit linkage.
    #[must_use]
    pub fn witness_hash(&self) -> u64 {
        use std::hash::{Hash, Hasher};

        let mut h = DetHasher::default();
        self.base_limit.hash(&mut h);
        self.effective_limit.hash(&mut h);
        self.observed_max_cancel_streak.hash(&mut h);
        self.cancel_dispatches.hash(&mut h);
        self.timed_dispatches.hash(&mut h);
        self.ready_dispatches.hash(&mut h);
        self.fairness_yields.hash(&mut h);
        self.observed_max_ready_stall_steps.hash(&mut h);
        self.observed_max_timed_stall_steps.hash(&mut h);
        self.ready_priority_inversions.hash(&mut h);
        self.max_ready_priority_inversion_gap.hash(&mut h);
        self.fallback_cancel_dispatches.hash(&mut h);
        self.base_limit_exceedances.hash(&mut h);
        self.effective_limit_exceedances.hash(&mut h);
        self.adaptive_enabled.hash(&mut h);
        self.adaptive_current_limit.hash(&mut h);
        h.finish()
    }
}

/// br-asupersync-9nn568: fired-once warn flag for the
/// `current_time_ns` fallback path. The pre-fix shape silently
/// returned 0 when `timer_driver` was None — the FairnessMonitor
/// then computed every wait_time as 0 - 0 = 0, never crossed the
/// starvation_threshold, never reported priority inversions, never
/// evicted aged-out entries (max_tracked_tasks cap still applied
/// but with meaningless ages), and `starvation_stats()` reported
/// `starvation_events: 0, priority_inversions: 0` to the operator.
/// Production deployments alerting on those counters silently lost
/// their DoS-detection surface. The fix routes through `wall_now()`
/// when no driver is attached and emits a one-time WARN so
/// operators can see the fallback in their logs.
static THREE_LANE_TIME_FALLBACK_WARNED: AtomicBool = AtomicBool::new(false);

/// Closed receipt for a delegated first cancel-lane insertion. It contains no
/// callbacks or owned user data and may safely cross the record-lock boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeferredCancelLanePublication {
    priority: u8,
    wake_target: DeferredCancelWakeTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeferredCancelWakeTarget {
    AnyWorker,
    PinnedWorker(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeferredCancelLaneError {
    MissingPinnedWorker,
    PinnedWorkerUnavailable(usize),
}

impl ThreeLaneWorker {
    /// Returns the current time in nanoseconds for fairness monitoring.
    ///
    /// br-asupersync-9nn568: when the worker has a TimerDriverHandle
    /// attached, use it (replay-deterministic in the lab runtime).
    /// When it does not — a permitted RuntimeBuilder configuration
    /// for minimal-runtime callers — fall back to
    /// [`crate::time::wall_now`] (the same fallback the worker.rs
    /// poll path uses, see br-asupersync-qdkyqs). The previous shape
    /// returned 0, which silently disabled the FairnessMonitor's
    /// starvation + priority-inversion detection — a security-relevant
    /// DoS-detection bypass with no operator-visible warning. We now
    /// emit a one-time WARN through `tracing` so the fallback is at
    /// least surfaced in logs.
    #[inline]
    fn current_time_ns(&self) -> u64 {
        if let Some(timer) = self.timer_driver.as_ref() {
            return timer.now().as_nanos();
        }
        if !THREE_LANE_TIME_FALLBACK_WARNED.swap(true, Ordering::Relaxed) {
            crate::tracing_compat::warn!(
                target: "asupersync::runtime::scheduler::three_lane",
                "br-asupersync-9nn568: ThreeLaneWorker has no TimerDriverHandle attached; \
                 FairnessMonitor falling back to wall_now() for current_time_ns. Replay \
                 determinism in the lab runtime requires a timer driver."
            );
        }
        crate::time::wall_now().as_nanos()
    }

    #[inline]
    fn record_scheduler_evidence_enqueue_at(&self, task: TaskId, timestamp_ns: u64) {
        let Some(collector) = &self.scheduler_evidence else {
            return;
        };
        collector.lock().record_task_enqueue(task, timestamp_ns);
    }

    #[inline]
    fn record_scheduler_evidence_enqueue(&self, task: TaskId) {
        self.record_scheduler_evidence_enqueue_at(task, self.current_time_ns());
    }

    /// Executes a closure with access to the fairness monitor for this worker.
    pub fn with_fairness_monitor<T>(&self, f: impl FnOnce(&FairnessMonitor) -> T) -> T {
        f(&self.fairness_monitor.lock())
    }

    /// Returns starvation statistics from the fairness monitor.
    #[must_use]
    pub fn starvation_stats(&self) -> StarvationStats {
        let current_time = self.current_time_ns();
        self.fairness_monitor.lock().starvation_stats(current_time)
    }

    /// Returns invariant statistics from the monitor.
    #[must_use]
    pub fn invariant_stats(&self) -> super::invariant_monitor::InvariantStats {
        self.invariant_monitor.lock().stats()
    }

    /// Returns all recorded invariant violations.
    #[must_use]
    pub fn invariant_violations(
        &self,
    ) -> std::collections::VecDeque<super::invariant_monitor::InvariantViolation> {
        self.invariant_monitor.lock().violations().clone()
    }

    /// Performs comprehensive scheduler invariant verification.
    ///
    /// This method checks queue consistency, task ownership, and other scheduler
    /// invariants that can be verified from current state. Should be called
    /// periodically in production to catch invariant violations.
    pub fn verify_scheduler_invariants(&mut self) {
        if !self.invariant_monitor.lock().is_enabled() {
            return;
        }

        let current_time = Time::from_nanos(self.current_time_ns());

        // Verify local queue consistency
        {
            let local_ready_guard = self.local_ready.lock();
            let local_ready_tasks: Vec<_> = local_ready_guard.snapshot();

            let ready_snapshot = super::invariant_monitor::QueueSnapshot {
                name: "local_ready_queue".to_string(),
                reported_depth: local_ready_tasks.len(),
                actual_tasks: local_ready_tasks,
                priority_range: if local_ready_guard.is_empty() {
                    None
                } else {
                    Some((0, 255)) // Conservative range for local tasks
                },
                time_range: Some((current_time, current_time)), // Snapshot time
            };

            drop(local_ready_guard);

            self.invariant_monitor
                .lock()
                .verify_queue_consistency(&ready_snapshot, current_time);
        }

        // Verify fast queue consistency
        let fast_queue_tasks = self.fast_queue.snapshot_tasks();
        let fast_snapshot = super::invariant_monitor::QueueSnapshot {
            name: "fast_queue".to_string(),
            reported_depth: fast_queue_tasks.len(),
            actual_tasks: fast_queue_tasks.to_vec(),
            priority_range: None,
            time_range: Some((current_time, current_time)),
        };
        self.invariant_monitor
            .lock()
            .verify_queue_consistency(&fast_snapshot, current_time);
    }

    /// Records task completion for invariant monitoring.
    ///
    /// This should be called when a task finishes execution to track
    /// task lifecycle and detect any invariant violations related
    /// to task completion.
    pub fn record_task_completion(&mut self, task: TaskId) {
        if !self.invariant_monitor.lock().is_enabled() {
            return;
        }

        let current_time = Time::from_nanos(self.current_time_ns());
        self.invariant_monitor
            .lock()
            .record_task_complete(task, self.id, current_time);
    }

    /// Records task cancellation for invariant monitoring.
    ///
    /// This should be called when a task is cancelled to track
    /// cancellation handling and detect leaked cancelled tasks.
    pub fn record_task_cancellation(&mut self, task: TaskId) {
        if !self.invariant_monitor.lock().is_enabled() {
            return;
        }

        let current_time = Time::from_nanos(self.current_time_ns());
        self.invariant_monitor
            .lock()
            .record_task_cancel(task, current_time);
    }

    /// Runs a closure against the task table, using the sharded task table
    /// when available, otherwise falling back to RuntimeState's embedded table.
    ///
    /// This is the hot-path accessor: when `task_table` is `Some`, only the
    /// task shard lock is acquired, avoiding contention with region/obligation
    /// mutations.
    #[inline]
    fn with_task_table<R, F: FnOnce(&mut TaskTable) -> R>(&self, f: F) -> R {
        if let Some(tt) = &self.task_table {
            let mut guard = tt.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            f(&mut guard)
        } else {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            f(&mut state.tasks)
        }
    }

    /// Read-only version of [`with_task_table`] for task record lookups.
    #[inline]
    fn with_task_table_ref<R, F: FnOnce(&TaskTable) -> R>(&self, f: F) -> R {
        if let Some(tt) = &self.task_table {
            let guard = tt.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            f(&guard)
        } else {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            f(&state.tasks)
        }
    }

    /// Returns the preemption fairness metrics for this worker.
    #[must_use]
    pub fn preemption_metrics(&self) -> &PreemptionMetrics {
        &self.preemption_metrics
    }

    /// Returns preferred-vs-remote steal counters for this worker.
    #[must_use]
    pub fn steal_locality_counters(&self) -> StealLocalityCounters {
        self.steal_locality_counters
    }

    /// Applies a runtime regime-shift receipt to the adaptive cancel-streak policy.
    ///
    /// The conservative response to a scheduler metric change-point is to
    /// forget stale EXP3/UCB learning and restart from priors. This method does
    /// not alter queue contents or take an aggressive scheduling action; it only
    /// resets the adaptive controller when it is enabled for a known runtime
    /// series.
    #[must_use]
    pub fn apply_changepoint_detection_to_adaptive_cancel_streak(
        &mut self,
        detection: crate::runtime::changepoint::ChangePointDetection,
    ) -> bool {
        if matches!(
            detection.series,
            crate::runtime::changepoint::RuntimeMetricSeries::Custom(_)
        ) {
            return false;
        }

        let Some(policy) = self.adaptive_cancel_policy.as_mut() else {
            return false;
        };

        policy.reset_to_priors();
        self.preemption_metrics.adaptive_epochs = policy.epoch_count;
        self.preemption_metrics.adaptive_current_limit = policy.current_limit();
        self.preemption_metrics.adaptive_reward_ema = policy.reward_ema;
        self.preemption_metrics.adaptive_e_value = policy.e_value();

        trace!(
            worker_id = self.id,
            series = detection.series.as_str(),
            detector = ?detection.detector,
            direction = ?detection.direction,
            sample_index = detection.sample_index,
            adaptive_limit = self.preemption_metrics.adaptive_current_limit,
            "changepoint reset adaptive cancel-streak policy to priors"
        );

        true
    }

    /// Builds a deterministic fairness certificate from current metrics.
    ///
    /// This certificate is intended for invariant auditing and replay reports.
    #[must_use]
    pub fn preemption_fairness_certificate(&self) -> PreemptionFairnessCertificate {
        let adaptive_current_limit = self.adaptive_cancel_policy.as_ref().map_or(
            self.cancel_streak_limit,
            AdaptiveCancelStreakPolicy::current_limit,
        );
        let effective_limit = self
            .preemption_metrics
            .max_effective_limit_observed
            .max(adaptive_current_limit)
            .max(1);

        PreemptionFairnessCertificate {
            base_limit: adaptive_current_limit,
            effective_limit,
            observed_max_cancel_streak: self.preemption_metrics.max_cancel_streak,
            cancel_dispatches: self.preemption_metrics.cancel_dispatches,
            timed_dispatches: self.preemption_metrics.timed_dispatches,
            ready_dispatches: self.preemption_metrics.ready_dispatches,
            fairness_yields: self.preemption_metrics.fairness_yields,
            observed_max_ready_stall_steps: self.preemption_metrics.max_ready_dispatch_stall,
            observed_max_timed_stall_steps: self.preemption_metrics.max_timed_dispatch_stall,
            ready_priority_inversions: self.preemption_metrics.ready_priority_inversions,
            max_ready_priority_inversion_gap: self
                .preemption_metrics
                .max_ready_priority_inversion_gap,
            fallback_cancel_dispatches: self.preemption_metrics.fallback_cancel_dispatches,
            base_limit_exceedances: self.preemption_metrics.base_limit_exceedances,
            effective_limit_exceedances: self.preemption_metrics.effective_limit_exceedances,
            adaptive_enabled: self.adaptive_cancel_policy.is_some(),
            adaptive_current_limit,
        }
    }

    /// Attaches an evidence sink for scheduler decision tracing.
    pub fn set_evidence_sink(&mut self, sink: Arc<dyn crate::evidence_sink::EvidenceSink>) {
        self.evidence_sink = Some(sink);
    }

    /// Force the cached scheduling suggestion for testing the boosted 2L+1
    /// fairness bound under `DrainObligations`/`DrainRegions`.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn set_cached_suggestion(&mut self, suggestion: SchedulingSuggestion) {
        self.cached_suggestion = suggestion;
    }

    /// Disable the Bayesian decision-contract modulation layer so tests can
    /// observe the raw Lyapunov governor suggestion. The contract's default
    /// near-uniform prior biases toward CONSERVATIVE (=> MeetDeadlines), which
    /// masks the governor's potential-driven DrainObligations/DrainRegions
    /// signal in unit tests that set up an explicit drain scenario.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn disable_decision_contract_for_test(&mut self) {
        self.decision_contract = None;
        self.decision_posterior = None;
    }

    fn emit_scheduler_evidence_for_suggestion(&self, suggestion: SchedulingSuggestion) {
        let Some(ref sink) = self.evidence_sink else {
            return;
        };

        let snapshot = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            StateSnapshot::from_runtime_state(&state)
        };
        let ready_queue_depth = self.ready_queue_depth_signal();
        #[allow(clippy::cast_possible_truncation)]
        let ready_queue_depth = ready_queue_depth as u32;
        let suggestion_str = match suggestion {
            SchedulingSuggestion::MeetDeadlines => "meet_deadlines",
            SchedulingSuggestion::DrainObligations => "drain_obligations",
            SchedulingSuggestion::DrainRegions => "drain_regions",
            SchedulingSuggestion::NoPreference => "no_preference",
        };
        let cancel_depth =
            snapshot.cancel_requested_tasks + snapshot.cancelling_tasks + snapshot.finalizing_tasks;
        crate::evidence_sink::emit_scheduler_evidence(
            sink.as_ref(),
            suggestion_str,
            cancel_depth,
            snapshot.draining_regions,
            ready_queue_depth,
            self.decision_contract
                .as_ref()
                .is_some_and(|_| self.decision_posterior.is_some()),
        );
    }

    #[inline]
    fn current_base_cancel_limit(&self) -> usize {
        self.adaptive_cancel_policy
            .as_ref()
            .map_or(
                self.cancel_streak_limit,
                AdaptiveCancelStreakPolicy::current_limit,
            )
            .max(1)
    }

    fn potential_from_snapshot(snapshot: &StateSnapshot) -> f64 {
        let w = PotentialWeights::default();
        let task_component = w.w_tasks * f64::from(snapshot.live_tasks);
        #[allow(clippy::cast_precision_loss)]
        let obligation_age_seconds = snapshot.obligation_age_sum_ns as f64 / 1_000_000_000.0;
        let obligation_component = w.w_obligation_age * obligation_age_seconds;
        let region_component = w.w_draining_regions * f64::from(snapshot.draining_regions);
        let deadline_component = w.w_deadline_pressure * snapshot.deadline_pressure;
        task_component + obligation_component + region_component + deadline_component
    }

    fn capture_adaptive_snapshot(&self) -> AdaptiveEpochSnapshot {
        let snapshot = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            StateSnapshot::from_runtime_state(&state)
        };
        AdaptiveEpochSnapshot {
            potential: Self::potential_from_snapshot(&snapshot),
            deadline_pressure: snapshot.deadline_pressure,
            effective_limit_exceedances: self.preemption_metrics.effective_limit_exceedances,
            fallback_cancel_dispatches: self.preemption_metrics.fallback_cancel_dispatches,
        }
    }

    fn ensure_adaptive_epoch_started(&mut self) {
        if self
            .adaptive_cancel_policy
            .as_ref()
            .is_none_or(|p| p.epoch_start.is_some())
        {
            return;
        }
        let snap = self.capture_adaptive_snapshot();
        if let Some(policy) = self.adaptive_cancel_policy.as_mut() {
            policy.begin_epoch(snap);
        }
    }

    fn adaptive_on_dispatch(&mut self) {
        self.ensure_adaptive_epoch_started();
        let should_close_epoch = self
            .adaptive_cancel_policy
            .as_mut()
            .is_some_and(AdaptiveCancelStreakPolicy::on_dispatch);
        if !should_close_epoch {
            return;
        }

        let snapshot_end = self.capture_adaptive_snapshot();
        let reward = self
            .adaptive_cancel_policy
            .as_mut()
            .and_then(|p| p.complete_epoch(snapshot_end));

        if let Some(policy) = self.adaptive_cancel_policy.as_ref() {
            self.preemption_metrics.adaptive_epochs = policy.epoch_count;
            self.preemption_metrics.adaptive_current_limit = policy.current_limit();
            self.preemption_metrics.adaptive_reward_ema = policy.reward_ema;
            self.preemption_metrics.adaptive_e_value = policy.e_value();
        }

        if let Some(reward_value) = reward {
            let _ = reward_value;
            // Log the unwrapped f64 directly. The previous form was
            // `if let Some(_reward) = reward { trace!(reward = reward, ...) }`
            // which bound `_reward` but referenced the outer `Option<f64>` —
            // so the emitted field went through tracing's `Value` impl for
            // `Option<T>` rather than for `f64`, leaving the rendering
            // dependent on which adapter is active and producing a
            // `Some(...)`-shaped value when fallbacks pick the Debug path.
            trace!(
                worker_id = self.id,
                reward = reward_value,
                adaptive_limit = self.preemption_metrics.adaptive_current_limit,
                adaptive_epochs = self.preemption_metrics.adaptive_epochs,
                adaptive_e_value = self.preemption_metrics.adaptive_e_value,
                "adaptive cancel-streak epoch update"
            );
        }
    }

    fn abort_adaptive_epoch(&mut self) {
        if let Some(policy) = self.adaptive_cancel_policy.as_mut() {
            policy.abort_epoch();
        }
    }

    fn drive_io_phase(&self) -> IoPhaseOutcome {
        let Some(io) = &self.io_driver else {
            return IoPhaseOutcome::NoProgress;
        };

        let now = self.current_scheduler_time();
        let local_deadline = self.local.lock().next_deadline();
        let timer_deadline = self
            .timer_driver
            .as_ref()
            .and_then(TimerDriverHandle::next_deadline);
        let global_deadline = self.global.peek_earliest_deadline();

        let next_deadline = [timer_deadline, local_deadline, global_deadline]
            .into_iter()
            .flatten()
            .min();

        let timeout = next_deadline
            .map(|deadline| {
                if deadline > now {
                    Duration::from_nanos(deadline.duration_since(now))
                } else {
                    Duration::ZERO
                }
            })
            .or(Some(IDLE_IO_POLL_MAX_TIMEOUT));

        // Do not block in I/O while spawn admission work remains. A denied
        // request produces no runnable task; without this mailbox check, the
        // next request could wait for the full idle I/O timeout before the
        // scheduler loop revisits admission.
        let io_timeout = select_io_poll_timeout(
            timeout,
            self.fast_queue.is_empty(),
            self.pending_cancel_dispatch_ready.load(Ordering::Acquire)
                || self
                    .spawn_mailbox
                    .as_ref()
                    .is_some_and(|mailbox| !mailbox.is_empty()),
        );

        if self.shutdown.load(Ordering::Acquire) {
            return IoPhaseOutcome::NoProgress;
        }

        match io.try_turn_with(io_timeout, |_, _| {}) {
            Ok(Some(n)) => {
                // We successfully polled the reactor (we are the leader for this turn).
                // If n > 0, we woke some tasks.
                // If n == 0 but we had a non-zero timeout, we spent time blocking,
                // so we should continue the loop to check queues again.
                // If n == 0 and timeout was ZERO, we did a quick poll and found nothing.
                if n > 0 || io_timeout != Some(Duration::ZERO) {
                    IoPhaseOutcome::Progress
                } else {
                    IoPhaseOutcome::NoProgress
                }
            }
            Ok(None) | Err(_) => {
                // Another thread is already polling (we are a follower).
                // Do not busy loop. Proceed to backoff/park logic.
                IoPhaseOutcome::Follower
            }
        }
    }

    #[inline]
    fn reset_empty_backoff(&mut self) {
        self.empty_backoff = 0;
    }

    #[inline]
    fn advance_empty_backoff(&mut self) -> EmptyBackoffAction {
        if self.empty_backoff < SPIN_LIMIT {
            self.empty_backoff += 1;
            EmptyBackoffAction::Spin
        } else if self.empty_backoff < EMPTY_BACKOFF_PARK_THRESHOLD {
            self.empty_backoff += 1;
            EmptyBackoffAction::Yield
        } else {
            EmptyBackoffAction::Park
        }
    }

    /// Runs the worker scheduling loop.
    ///
    /// The loop maintains strict priority ordering:
    /// 1. Process expired timers (wakes tasks via their wakers)
    /// 2. Cancel work (global then local)
    /// 3. Timed work (global then local)
    /// 4. Ready work (global then local)
    /// 5. Steal from other workers
    /// 6. Park (with timeout based on next timer deadline)
    pub fn run_loop(&mut self) {
        // Set thread-local scheduler for this worker thread.
        let _guard = ScopedLocalScheduler::new(Arc::clone(&self.local));
        // Set thread-local fast queue for O(1) ready-lane operations.
        let _queue_guard = LocalQueue::set_current(self.fast_queue.clone());
        // Set thread-local non-stealable queue for local (!Send) tasks.
        let _local_ready_guard = ScopedLocalReady::new(Arc::clone(&self.local_ready));
        // Set thread-local worker id for routing pinned local tasks.
        let _worker_guard = ScopedWorkerId::new(self.id);

        while !self.shutdown.load(Ordering::Relaxed) {
            if let Some(task) = self.next_task() {
                self.reset_empty_backoff();
                self.execute(task);
                continue;
            }

            if self.schedule_ready_finalizers() {
                continue;
            }

            // PHASE 5: Drive I/O (Leader/Follower pattern).
            let io_phase = self.drive_io_phase();
            if matches!(io_phase, IoPhaseOutcome::Progress) {
                // We polled I/O, so we might have woken tasks. Continue loop.
                continue;
            }

            // PHASE 6: Backoff before parking
            // Keep this cheap fast-queue probe before the idle loop, then
            // re-check it alongside global work without resetting the
            // persistent empty backoff budget on spurious runnable flicker.
            if !self.fast_queue.is_empty() {
                continue;
            }

            loop {
                // Check shutdown before parking to avoid hanging in the backoff loop.
                if self.shutdown.load(Ordering::Relaxed) {
                    break;
                }

                // Get current time for runnable checks
                let now = self.current_scheduler_time();

                // Lock-free check: ready/cancel queues and the fast queue are
                // concrete runnable work. A merely-due timed entry is only a
                // maybe-runnable signal; after `next_task()` found no task, it
                // must consume the empty backoff budget instead of keeping the
                // worker out of the park branch forever.
                if !self.fast_queue.is_empty()
                    || self.global.has_cancel_work()
                    || self.global.has_ready_work()
                    || self.pending_cancel_dispatch_ready.load(Ordering::Acquire)
                    || self
                        .spawn_mailbox
                        .as_ref()
                        .is_some_and(|mailbox| !mailbox.is_empty())
                {
                    break;
                }

                if self.global.has_runnable_work(now) {
                    match self.advance_empty_backoff() {
                        EmptyBackoffAction::Spin => {
                            crate::runtime::metrics::record_worker_spin();
                            std::hint::spin_loop();
                            break;
                        }
                        EmptyBackoffAction::Yield => {
                            crate::runtime::metrics::record_sched_yield();
                            std::thread::yield_now();
                            break;
                        }
                        EmptyBackoffAction::Park => {}
                    }
                }

                match self.advance_empty_backoff() {
                    EmptyBackoffAction::Spin => {
                        crate::runtime::metrics::record_worker_spin();
                        std::hint::spin_loop();
                    }
                    EmptyBackoffAction::Yield => {
                        crate::runtime::metrics::record_sched_yield();
                        std::thread::yield_now();
                    }
                    EmptyBackoffAction::Park if self.enable_parking => {
                        // About to park: now check mutex-backed local queues.
                        // Deferred from the spin/yield phases to avoid 160 mutex
                        // round-trips per backoff cycle.
                        let (local_has_runnable, local_deadline) = {
                            let mut local = self.local.lock();
                            (local.has_runnable_work(now), local.next_deadline())
                        };
                        let local_ready_has_work = !self.local_ready.lock().is_empty();
                        let spawn_mailbox_has_work = self
                            .spawn_mailbox
                            .as_ref()
                            .is_some_and(|mailbox| !mailbox.is_empty());
                        let local_spawn_lane_has_work =
                            !crate::runtime::spawn_mailbox::local_spawn_lane_is_empty();
                        if local_has_runnable
                            || local_ready_has_work
                            || self.pending_cancel_dispatch_ready.load(Ordering::Acquire)
                            || spawn_mailbox_has_work
                            || local_spawn_lane_has_work
                        {
                            break;
                        }
                        // Park with timeout based on next timer deadline.
                        // If we are the IO leader, we shouldn't even be here (we'd block in epoll).
                        // If we are a follower, we just park until a deadline or woken.
                        let timer_deadline = self
                            .timer_driver
                            .as_ref()
                            .and_then(TimerDriverHandle::next_deadline);
                        let global_deadline = self.global.peek_earliest_deadline();
                        record_backoff_deadline_selection(
                            &mut self.preemption_metrics,
                            io_phase,
                            timer_deadline,
                            global_deadline,
                        );

                        let next_deadline = select_backoff_deadline(
                            io_phase,
                            timer_deadline,
                            local_deadline,
                            global_deadline,
                        );

                        if let Some(next_deadline) = next_deadline {
                            // Re-fetch now to ensure we don't sleep if deadline passed during logic
                            let now = self.current_scheduler_time();
                            match classify_backoff_timeout_decision(io_phase, next_deadline, now) {
                                BackoffTimeoutDecision::ParkTimeout { nanos } => {
                                    record_backoff_timeout_park(
                                        &mut self.preemption_metrics,
                                        io_phase,
                                        nanos,
                                    );
                                    self.parker.park_timeout(Duration::from_nanos(nanos));
                                    // br-asupersync-rr849p: this park was sized
                                    // by the nearest timer/EDF deadline, so on
                                    // wake that deadline is (close to) due.
                                    // Expired wheel timers only fire inside
                                    // `next_task()` (PHASE 0 `process_timers`);
                                    // the inner backoff loop re-checks queues
                                    // but never pumps the wheel, so looping
                                    // here strands due wheel timers (e.g. the
                                    // ~1ms fallback-rewake re-poll chain behind
                                    // every reactor-less read) until another
                                    // thread happens to pump it. Break to the
                                    // outer loop so this worker fires the
                                    // now-due deadline itself.
                                    self.reset_empty_backoff();
                                    break;
                                }
                                BackoffTimeoutDecision::DeadlineDue => {
                                    // `next_task()` already failed to dispatch
                                    // from this due signal. Treat it as a stale
                                    // timed-deadline flicker after the bounded
                                    // busy budget is exhausted, and enter the
                                    // kernel instead of burning another full
                                    // outer-loop spin/yield cycle.
                                    record_backoff_timeout_park(
                                        &mut self.preemption_metrics,
                                        io_phase,
                                        STALE_DUE_DEADLINE_PARK_NANOS,
                                    );
                                    self.parker.park_timeout(Duration::from_nanos(
                                        STALE_DUE_DEADLINE_PARK_NANOS,
                                    ));
                                    // br-asupersync-rr849p: the due signal may
                                    // be an unprocessed WHEEL timer rather than
                                    // a stale timed-lane entry. Only
                                    // `next_task()` can fire wheel timers, so
                                    // break out when the wheel itself is due;
                                    // genuine timed-lane flicker (wheel not
                                    // due) keeps the bounded inner-loop
                                    // behavior.
                                    let wheel_due = self
                                        .timer_driver
                                        .as_ref()
                                        .and_then(TimerDriverHandle::next_deadline)
                                        .is_some_and(|deadline| {
                                            deadline <= self.current_scheduler_time()
                                        });
                                    if wheel_due {
                                        self.reset_empty_backoff();
                                        break;
                                    }
                                }
                            }
                        } else {
                            // Followers park indefinitely.
                            record_backoff_indefinite_park(&mut self.preemption_metrics, io_phase);
                            self.parker.park();
                        }
                        // After waking, re-check queues by continuing the loop.
                        // This fixes a lost-wakeup race where work arrives right as we park.
                        // Reset backoff to spin briefly before parking again (spurious wakeups).
                        self.reset_empty_backoff();
                        // Continue loop to re-check condition (no break!)
                    }
                    EmptyBackoffAction::Park => {
                        // Parking disabled; preserve the historical spin/yield cadence.
                        self.reset_empty_backoff();
                        break;
                    }
                }
            }

            // After backoff/park, reset the consecutive cancel counter.
            // We've given other work a chance during the backoff period.
            self.cancel_streak = 0;
            self.ready_dispatch_streak = 0;
        }
    }

    #[inline]
    fn fixed_ready_batch_size(&self) -> usize {
        self.steal_batch_size.max(1)
    }

    #[inline]
    fn reset_adaptive_batch_state(&mut self) {
        let fixed_batch_size = self.fixed_ready_batch_size();
        let last_combiner_claim_failures = self
            .global
            .ready_combiner_snapshot()
            .combiner_claim_failures;
        self.adaptive_batch_state = AdaptiveBatchRuntimeState {
            active_batch_size: fixed_batch_size,
            cooldown_remaining: 0,
            last_combiner_claim_failures,
            last_snapshot: None,
        };
    }

    #[doc(hidden)]
    #[cfg(any(test, feature = "test-internals"))]
    pub fn adaptive_batch_snapshot_for_test(&self) -> Option<AdaptiveBatchDecisionSnapshot> {
        self.adaptive_batch_state.last_snapshot
    }

    #[inline]
    fn select_ready_batch_decision(&mut self) -> AdaptiveBatchDecisionSnapshot {
        let fixed_batch_size = self.fixed_ready_batch_size();
        let ready_depth = self.global.ready_count();
        let combiner = self.global.ready_combiner_snapshot();
        let cancel_debt = self.cancel_debt_signal();
        let claim_failures_delta = combiner
            .combiner_claim_failures
            .saturating_sub(self.adaptive_batch_state.last_combiner_claim_failures);
        self.adaptive_batch_state.last_combiner_claim_failures = combiner.combiner_claim_failures;

        let mut selected_batch_size = fixed_batch_size;
        let mut reason = AdaptiveBatchDecisionReason::Disabled;

        if let Some(profile) = self.adaptive_batch_profile {
            let profile = profile.normalized(fixed_batch_size);
            if profile.enabled {
                if self.adaptive_batch_state.cooldown_remaining > 0 {
                    selected_batch_size = self
                        .adaptive_batch_state
                        .active_batch_size
                        .max(fixed_batch_size)
                        .clamp(profile.min_batch_size, profile.max_batch_size);
                    self.adaptive_batch_state.cooldown_remaining = self
                        .adaptive_batch_state
                        .cooldown_remaining
                        .saturating_sub(1);
                    self.preemption_metrics.adaptive_batch_cooldown_holds += 1;
                    reason = AdaptiveBatchDecisionReason::CooldownHold;
                } else if cancel_debt >= profile.cancel_debt_floor
                    && fixed_batch_size > profile.min_batch_size
                {
                    selected_batch_size = profile.min_batch_size;
                    self.adaptive_batch_state.active_batch_size = selected_batch_size;
                    self.preemption_metrics.adaptive_batch_cancel_floor_hits += 1;
                    reason = AdaptiveBatchDecisionReason::CancelDebtFloor;
                } else {
                    let combiner_ready = combiner.max_in_flight >= profile.scale_up_in_flight
                        || combiner.current_in_flight >= profile.scale_up_in_flight;
                    let claim_ready = claim_failures_delta >= profile.scale_up_claim_failures;
                    if ready_depth >= profile.scale_up_ready_depth
                        && combiner_ready
                        && claim_ready
                        && profile.max_batch_size > fixed_batch_size
                    {
                        selected_batch_size =
                            profile.contention_scale_up_batch_size(fixed_batch_size);
                        self.adaptive_batch_state.active_batch_size = selected_batch_size;
                        self.adaptive_batch_state.cooldown_remaining = profile.cooldown_steps;
                        self.preemption_metrics.adaptive_batch_scale_up_events += 1;
                        reason = AdaptiveBatchDecisionReason::ReadyContentionScaleUp;
                    } else {
                        selected_batch_size = fixed_batch_size;
                        self.adaptive_batch_state.active_batch_size = selected_batch_size;
                        reason = AdaptiveBatchDecisionReason::FixedFallback;
                    }
                }
            }
        }

        self.preemption_metrics.adaptive_batch_max_selected = self
            .preemption_metrics
            .adaptive_batch_max_selected
            .max(selected_batch_size);

        let snapshot = AdaptiveBatchDecisionSnapshot {
            selected_batch_size,
            fixed_batch_size,
            ready_depth,
            cancel_debt,
            combiner_in_flight: combiner.max_in_flight.max(combiner.current_in_flight),
            combiner_claim_failures_delta: claim_failures_delta,
            reason,
        };
        self.adaptive_batch_state.last_snapshot = Some(snapshot);
        snapshot
    }

    /// Inserts a delegated task's first cancel lane without consulting the task
    /// table, emitting evidence, or waking a worker. Its caller owns the
    /// authoritative record and Cx publication gates, so even an already-awake
    /// worker blocks at record lookup until the caller marks the lane Published.
    fn insert_deferred_cancel_lane_without_wake(
        &self,
        task_id: TaskId,
        priority: u8,
        is_local: bool,
        pinned_worker: Option<usize>,
    ) -> Result<DeferredCancelLanePublication, DeferredCancelLaneError> {
        if is_local {
            let Some(worker_id) = pinned_worker else {
                return Err(DeferredCancelLaneError::MissingPinnedWorker);
            };
            let Some(local) = self.all_local_schedulers.get(worker_id) else {
                return Err(DeferredCancelLaneError::PinnedWorkerUnavailable(worker_id));
            };
            let mut local = local.lock();
            if let Some(local_ready) = self.all_local_ready.get(worker_id) {
                local_ready.lock().tombstone(task_id);
            }
            local.move_to_cancel_lane(task_id, priority);
            drop(local);
            return Ok(DeferredCancelLanePublication {
                priority,
                wake_target: DeferredCancelWakeTarget::PinnedWorker(worker_id),
            });
        }

        self.global.remove_timed(task_id);
        self.global.inject_cancel(task_id, priority);
        Ok(DeferredCancelLanePublication {
            priority,
            wake_target: DeferredCancelWakeTarget::AnyWorker,
        })
    }

    /// Runs subscriber/time-source evidence and worker notification only after
    /// the record and Cx publication gates have been released.
    fn finish_deferred_cancel_lane_publication(
        &self,
        task_id: TaskId,
        publication: DeferredCancelLanePublication,
    ) {
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.record_scheduler_evidence_enqueue(task_id);
        })) {
            // Evidence collection can reach a tracing subscriber or time
            // source. The lane and Cx handoff are already authoritative; leak
            // an opaque panic payload rather than skipping the only worker
            // permit that makes the publication live.
            std::mem::forget(payload);
        }
        match publication.wake_target {
            DeferredCancelWakeTarget::AnyWorker => self.coordinator.wake_one(),
            DeferredCancelWakeTarget::PinnedWorker(worker_id) => {
                self.coordinator.wake_worker(worker_id);
            }
        }
    }

    /// Contains diagnostics on the cancellation consumer so a hostile tracing
    /// subscriber cannot abort the rest of an already-dequeued command batch.
    fn emit_cancel_diagnostic(diagnostic: impl FnOnce()) {
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(diagnostic)) {
            std::mem::forget(payload);
        }
    }

    fn publish_deferred_cancel_task(&self, task_id: TaskId, priority: u8) -> bool {
        let task_location = self.with_task_table_ref(|tasks| {
            tasks.task(task_id).map(|record| {
                record.wake_state.notify();
                (record.is_local(), record.pinned_worker())
            })
        });
        let Some((is_local, pinned_worker)) = task_location else {
            Self::emit_cancel_diagnostic(|| {
                error!(
                    ?task_id,
                    "deferred cancellation task is absent from the task table"
                );
            });
            return false;
        };

        match self.insert_deferred_cancel_lane_without_wake(
            task_id,
            priority,
            is_local,
            pinned_worker,
        ) {
            Ok(publication) => {
                self.finish_deferred_cancel_lane_publication(task_id, publication);
                true
            }
            Err(error) => {
                Self::emit_cancel_diagnostic(|| {
                    let _ = &error;
                    error!(
                        ?task_id,
                        ?error,
                        "deferred cancellation lane insertion failed"
                    );
                });
                false
            }
        }
    }

    /// Applies task-handle cancellation commands on the runtime-owned side of
    /// the scheduler boundary. Producers mutate only checkpoint-visible Cx
    /// state and enqueue plain data; this consumer performs the authoritative
    /// TaskRecord transition, physically publishes every required lane, and
    /// only then dispatches the captured Wakers.
    fn drain_handle_cancel_requests(&self) {
        const HANDLE_CANCEL_BATCH: usize = 16;

        let Some(mailbox) = self.spawn_mailbox.as_ref() else {
            return;
        };
        if mailbox.handle_cancels_are_empty() {
            return;
        }
        let mut requests = Vec::with_capacity(HANDLE_CANCEL_BATCH);
        if mailbox.dequeue_handle_cancels_into(HANDLE_CANCEL_BATCH, &mut requests) == 0 {
            return;
        }

        let requests = crate::runtime::spawn_mailbox::coalesce_handle_cancel_requests(requests);
        let (tasks, delegated, immediate_wakes, immediate_admitted_slots) = if self
            .task_table
            .is_some()
        {
            let (tasks, delegated, mut immediate_wakes, immediate_admitted_slots, new_requests) =
                self.with_task_table(|tt| {
                    let mut tasks = Vec::with_capacity(requests.len());
                    let mut delegated = Vec::new();
                    let mut immediate_wakes = Vec::new();
                    let mut immediate_admitted_slots = Vec::new();
                    let mut new_requests = Vec::new();
                    for request in requests {
                        let task_id = request.task_id;
                        let reason = request.reason;
                        let admitted_slot = request.admitted_slot;
                        let Some((effects, region_id, spawned_at)) =
                            tt.update_task(task_id, |record| {
                                let effects = record.request_cancel_for_handle(&reason);
                                (effects, record.owner, record.created_at)
                            })
                        else {
                            continue;
                        };
                        let (update, task_wakes) = effects.into_parts();
                        if update.newly_cancelled {
                            new_requests.push((task_id, region_id, spawned_at));
                        }
                        match update.route {
                            Some(route) if route.delegated_initial => delegated.push((
                                task_id,
                                route.priority,
                                reason,
                                task_wakes,
                                admitted_slot,
                            )),
                            Some(route) => {
                                tasks.push((task_id, route.priority, task_wakes, admitted_slot));
                            }
                            None => {
                                immediate_wakes.push(task_wakes);
                                if let Some(admitted_slot) = admitted_slot {
                                    immediate_admitted_slots.push(admitted_slot);
                                }
                            }
                        }
                    }
                    (
                        tasks,
                        delegated,
                        immediate_wakes,
                        immediate_admitted_slots,
                        new_requests,
                    )
                });
            if !new_requests.is_empty() {
                let new_requests = new_requests
                    .into_iter()
                    .map(|(task_id, region_id, spawned_at)| {
                        let task_still_live =
                            self.with_task_table_ref(|tt| tt.task(task_id).is_some());
                        (task_id, region_id, spawned_at, !task_still_live)
                    })
                    .collect::<Vec<_>>();
                let state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for (task_id, region_id, spawned_at, allow_retired_noop) in new_requests {
                    if let Some(validation_result) = state.external_handle_cancel_request_violation(
                        task_id,
                        region_id,
                        spawned_at,
                        allow_retired_noop,
                    ) {
                        let mut diagnostic = crate::types::task_context::CancelWakeEffects::empty();
                        diagnostic.push_cancel_protocol_violation(
                            "external-shard task-handle cancellation",
                            validation_result,
                        );
                        immediate_wakes.push(diagnostic);
                    }
                }
            }
            (tasks, delegated, immediate_wakes, immediate_admitted_slots)
        } else {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut tasks = Vec::with_capacity(requests.len());
            let mut delegated = Vec::new();
            let mut immediate_wakes = Vec::new();
            let mut immediate_admitted_slots = Vec::new();
            for request in requests {
                let task_id = request.task_id;
                let reason = request.reason;
                let admitted_slot = request.admitted_slot;
                let task_exists = state.task(task_id).is_some();
                let effects = state.cancel_task_for_handle(task_id, &reason);
                let (route, task_wakes) = effects.into_parts();
                match route {
                    Some(route) if route.delegated_initial => {
                        delegated.push((task_id, route.priority, reason, task_wakes, admitted_slot))
                    }
                    Some(route) => {
                        tasks.push((task_id, route.priority, task_wakes, admitted_slot));
                    }
                    None => {
                        immediate_wakes.push(task_wakes);
                        if task_exists && let Some(admitted_slot) = admitted_slot {
                            immediate_admitted_slots.push(admitted_slot);
                        }
                    }
                }
            }
            drop(state);
            (tasks, delegated, immediate_wakes, immediate_admitted_slots)
        };

        let mut wakes_to_dispatch = immediate_wakes;
        let mut spawn_effects_to_dispatch =
            Vec::with_capacity(immediate_admitted_slots.len() + tasks.len() + delegated.len());
        for admitted_slot in immediate_admitted_slots {
            if let Some(effects) = admitted_slot.take_spawn_effects_if_lane_published() {
                spawn_effects_to_dispatch.push(effects);
            }
        }
        for (task_id, priority, task_wakes, admitted_slot) in tasks {
            if self.publish_deferred_cancel_task(task_id, priority) {
                wakes_to_dispatch.push(task_wakes);
                if let Some(admitted_slot) = admitted_slot
                    && let Some(effects) = admitted_slot.publish_spawn_lane_and_take_effects()
                {
                    spawn_effects_to_dispatch.push(effects);
                }
            } else {
                Self::emit_cancel_diagnostic(|| {
                    error!(
                        ?task_id,
                        priority,
                        "handle cancellation promotion failed; suppressing only this task's \
                         Wakers fail-closed"
                    );
                });
                task_wakes.suppress();
            }
        }

        // A managed pre-admission abort owns the first physical lane. Keep the
        // authoritative record locked while its Cx gate computes the strongest
        // reason, inserts that lane without waking, and transitions to Published.
        // An already-awake worker may pop the queue entry, but it cannot remove
        // or poll the task until this record critical section completes.
        for (task_id, requested_priority, reason, mut task_wakes, admitted_slot) in delegated {
            let mut lane_error = None;
            let effects = if self.task_table.is_some() {
                self.with_task_table(|tt| {
                    tt.update_task(task_id, |record| {
                        record.publish_delegated_cancel_lane(|priority, is_local, pinned_worker| {
                            match self.insert_deferred_cancel_lane_without_wake(
                                task_id,
                                priority,
                                is_local,
                                pinned_worker,
                            ) {
                                Ok(publication) => Some(publication),
                                Err(error) => {
                                    lane_error = Some(error);
                                    None
                                }
                            }
                        })
                    })
                    .unwrap_or_else(|| crate::types::task_context::CancellationEffects::ready(None))
                })
            } else {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.publish_handle_cancel_lane(task_id, |priority, is_local, pinned_worker| {
                    match self.insert_deferred_cancel_lane_without_wake(
                        task_id,
                        priority,
                        is_local,
                        pinned_worker,
                    ) {
                        Ok(publication) => Some(publication),
                        Err(error) => {
                            lane_error = Some(error);
                            None
                        }
                    }
                })
            };
            let (publication, publication_wakes) = effects.into_parts();

            if let Some(publication) = publication {
                // Publish the concrete worker permit before any allocation in
                // effect merging/vector growth can unwind. Cx and TaskRecord
                // are already authoritative, so an early worker is safe.
                self.finish_deferred_cancel_lane_publication(task_id, publication);
                let spawn_effects = admitted_slot
                    .as_ref()
                    .and_then(|slot| slot.publish_spawn_lane_and_take_effects());
                debug_assert!(publication.priority >= requested_priority);
                task_wakes.merge(publication_wakes);
                wakes_to_dispatch.push(task_wakes);
                if let Some(effects) = spawn_effects {
                    spawn_effects_to_dispatch.push(effects);
                }
                continue;
            }

            // Missing/unavailable pinned-worker routes are structural topology
            // errors. Do not internally requeue them: an unchanged command
            // would keep the mailbox permanently nonempty and starve unrelated
            // work. Cx remains DelegatedCancel with its original Wakers pending,
            // so a fresh producer command can retry after repair.
            if let Some(error) = lane_error {
                Self::emit_cancel_diagnostic(|| {
                    let _ = &error;
                    error!(
                        ?task_id,
                        requested_priority,
                        ?error,
                        "delegated handle cancellation lane insertion failed; suppressing only \
                         this attempt's Wakers without an internal retry loop"
                    );
                });
            }
            drop(reason);
            task_wakes.suppress();
            // The failed delegated attempt left the authoritative registry
            // pending for retry/no-op resolution. Retire only its duplicate
            // snapshot now that TaskTable/RuntimeState and Cx are unlocked.
            publication_wakes.retire_without_dispatch();
        }

        // Every callback-free lane publication above has completed before the
        // first potentially hostile spawn observer, RawWaker callback, or
        // destructor runs. Spawn observers stay ahead of cancellation Wakers.
        for effects in spawn_effects_to_dispatch {
            effects.dispatch();
        }
        for wakes in wakes_to_dispatch {
            wakes.dispatch();
        }
    }

    /// Publishes cancellation routes accumulated by Drop/error paths, then
    /// invokes their auxiliary cancellation Wakers after the runtime-state
    /// lock is gone.
    ///
    /// This boundary does not cover other synchronous callbacks a producer may
    /// reach before it enqueues the returned cancellation effects.
    fn drain_deferred_cancel_dispatches(&self) {
        if !self.pending_cancel_dispatch_ready.load(Ordering::Acquire) {
            return;
        }
        let batches = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.take_deferred_cancel_dispatches()
        };
        let mut wakes = Vec::with_capacity(batches.len());
        for batch in batches {
            let (tasks, batch_wakes) = batch.into_parts();
            let mut batch_published = true;
            for (task_id, priority) in tasks {
                batch_published &= self.publish_deferred_cancel_task(task_id, priority);
            }
            wakes.push((batch_published, batch_wakes));
        }
        for (batch_published, batch_wakes) in wakes {
            if batch_published {
                batch_wakes.dispatch();
            } else {
                Self::emit_cancel_diagnostic(|| {
                    error!(
                        "deferred cancellation batch publication was incomplete; suppressing \
                         only that batch's Wakers fail-closed"
                    );
                });
                batch_wakes.suppress();
            }
        }
    }

    /// Select the next task to dispatch, respecting lane priorities and fairness.
    ///
    /// Returns `None` when no work is available across any lane or steal target.
    ///
    /// # Dispatch phases (br-asupersync-uzt6xo)
    ///
    /// The previous documentation listed five phases but the implementation
    /// has grown to seven discrete sections (a Phase 0 timer pre-step, the
    /// original five priority phases, and a Phase 3b local-ready fall-through
    /// that runs only when the fast ready paths in Phase 3 returned nothing).
    /// The doc below now enumerates all seven in execution order, with a
    /// short rationale for why each exists separately.
    ///
    /// **Phase 0 — Timer maintenance**
    /// Process expired timers via the timer-driver handle. This fires wakers
    /// which inject newly-ready tasks into the queues consulted below;
    /// running it FIRST keeps just-expired timer waiters from waiting an
    /// extra dispatch slot. Cheap (no-op when no timer driver is wired).
    ///
    /// **Phase 1 — Highest-priority global queue (suggestion-ordered)**
    /// Single global-queue probe at the top priority dictated by the
    /// governor's `SchedulingSuggestion`: timed-first under
    /// `MeetDeadlines`, otherwise cancel-first. The hot path for
    /// dispatch — most workers exit here when queues are non-empty.
    /// Subject to the cancel-streak fairness bound documented at the
    /// top of this module.
    ///
    /// **Phase 2 — Interleaved local + global priority lanes**
    /// Acquire the local `PriorityScheduler` lock once and check the
    /// remaining cancel/timed lanes in strict suggestion order. The
    /// invariant the prior 5-phase doc claimed (one lock acquisition for
    /// all three lanes) lives here. Drops the lock as soon as a task
    /// is dispatched OR all lanes are empty.
    ///
    /// **Phase 3 — Fast ready paths (no PriorityScheduler lock)**
    /// Lock-free `local_ready` deque pop, then `fast_queue` atomic pop,
    /// then global ready-queue pop. These three queues are checked
    /// without re-acquiring the local lock — ready dispatch should not
    /// pay the priority-scheduler-lock cost when the fast paths can
    /// satisfy it.
    ///
    /// **Phase 3b — Local ready lane (PriorityScheduler-locked)**
    /// When all fast ready paths are empty, fall back to the local
    /// `PriorityScheduler::pop_ready_only_with_hint` which DOES acquire
    /// the lock. Split out from Phase 3 because it has a different
    /// contention profile (mutating, not lock-free) and observability
    /// path (no priority-inversion check is recorded here — the local
    /// path's priorities are already canonical).
    ///
    /// **Phase 4 — Steal from other workers**
    /// `try_steal` walks peer workers' deques. Last resort before
    /// considering the fallback-cancel path; preserves the work-stealing
    /// invariant that idle workers help busy ones before parking.
    ///
    /// **Phase 5 — Fallback cancel (streak-limit-deferred path)**
    /// When `cancel_streak` hit the fairness limit AND no other lane had
    /// work, allow one more cancel dispatch (global + local). The
    /// fairness mechanism prefers blocking cancels over starving
    /// readers; this phase re-admits cancel work only when no fairer
    /// option exists, then resets `cancel_streak = 1` so the next call
    /// re-evaluates after at most `cancel_streak_limit − 1` more cancel
    /// dispatches.
    ///
    /// # Lock-reduction provenance
    ///
    /// Phases 1–2 collapse the previous 3-lock-acquisition path
    /// (`try_cancel_work` → `try_timed_work` → `try_ready_work`) into a
    /// single Phase-2 acquisition for the local fallback. Phases 3 and
    /// 3b together replace the older third sequential probe — fast
    /// paths dispatch most ready work without ever taking the local
    /// lock; only when the fast paths are empty does the lock cost
    /// reappear at Phase 3b.
    #[allow(clippy::too_many_lines)]
    /// Drains a bounded batch from the spawn mailbox and admits each
    /// request under the state lock (br-asupersync-dx-core-api-v2-u1z5hn.1.3).
    ///
    /// Admission failures resolve *after* the lock is released: completion
    /// slots are user code and must not run under the runtime lock.
    /// Admitted tasks are injected into the global ready lane so any worker
    /// can pick them up.
    fn drain_spawn_admissions(&mut self) {
        const SPAWN_ADMISSION_BATCH: usize = 1;

        let Some(mailbox) = self.spawn_mailbox.as_ref() else {
            return;
        };
        if mailbox.spawn_requests_are_empty() {
            return;
        }
        let mailbox = Arc::clone(mailbox);
        let mut requests = Vec::with_capacity(SPAWN_ADMISSION_BATCH);
        if mailbox.dequeue_batch_into(SPAWN_ADMISSION_BATCH, &mut requests) == 0 {
            return;
        }

        let mut admitted: SmallVec<
            [(
                TaskId,
                u8,
                crate::runtime::spawn_mailbox::AdmissionPublication,
                crate::runtime::state::TaskSpawnEffects,
            ); 16],
        > = SmallVec::new();
        let mut denied: SmallVec<
            [(
                crate::runtime::spawn_mailbox::SpawnRequestParts,
                crate::runtime::state::SpawnError,
            ); 4],
        > = SmallVec::new();
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for request in requests {
                match state.admit_spawn_request(request.into_parts()) {
                    crate::runtime::state::SpawnAdmission::Admitted {
                        task_id,
                        priority,
                        cancel_publication,
                        spawn_effects,
                    } => {
                        admitted.push((task_id, priority, cancel_publication, spawn_effects));
                    }
                    crate::runtime::state::SpawnAdmission::Denied { parts, error } => {
                        denied.push((parts, error));
                    }
                }
            }
        }

        // Publish every successfully admitted task before running any callback.
        // A cached cancellation Waker may reenter the scheduler and must see
        // the complete admission batch already visible in a runnable lane.
        let mut cancel_wakes = SmallVec::<
            [crate::types::task_context::CancelWakeEffects; SPAWN_ADMISSION_BATCH],
        >::new();
        let mut spawn_effects =
            SmallVec::<[crate::runtime::state::TaskSpawnEffects; SPAWN_ADMISSION_BATCH]>::new();
        for (task_id, priority, publication, effects) in admitted {
            let (wakes, effects) =
                publication.publish_with_spawn_effects(effects, |cancel_priority| {
                    if let Some(cancel_priority) = cancel_priority {
                        self.global.inject_cancel(task_id, cancel_priority);
                    } else {
                        self.global.inject_ready(task_id, priority);
                    }
                });
            cancel_wakes.push(wakes);
            if let Some(effects) = effects {
                spawn_effects.push(effects);
            }
        }
        // Every task in the admitted batch is now executable. Spawn observers
        // may reenter admission and must see the whole batch already published.
        for effects in spawn_effects {
            effects.dispatch();
        }
        for (parts, error) in denied {
            match error {
                crate::runtime::state::SpawnError::RegionClosed(_)
                | crate::runtime::state::SpawnError::RegionNotFound(_) => {
                    parts.resolve_cancelled(crate::types::CancelReason::new(
                        crate::types::CancelKind::ParentCancelled,
                    ));
                }
                other => parts.resolve_failed(other),
            }
        }
        for wakes in cancel_wakes {
            wakes.dispatch();
        }
    }

    /// Admits owner-pinned local spawn requests parked on this worker's
    /// thread-local lane (br-asupersync-i9y5wb / A2.2a).
    ///
    /// Mirrors [`Self::drain_spawn_admissions`]: admission under one state
    /// lock acquisition, denial slots resolved after release. Admitted
    /// tasks are pinned to this worker, stored in the thread-local task
    /// slot, and scheduled on the non-stealable local queue — they are
    /// never exposed to stealers.
    fn drain_local_spawn_admissions(&mut self) {
        const LOCAL_SPAWN_ADMISSION_BATCH: usize = 16;

        if crate::runtime::spawn_mailbox::local_spawn_lane_is_empty() {
            return;
        }
        let mut requests = Vec::with_capacity(LOCAL_SPAWN_ADMISSION_BATCH);
        if crate::runtime::spawn_mailbox::drain_local_spawn_lane(
            LOCAL_SPAWN_ADMISSION_BATCH,
            &mut requests,
        ) == 0
        {
            return;
        }

        let mut admitted: Vec<(
            TaskId,
            u8,
            crate::runtime::stored_task::LocalStoredTask,
            crate::runtime::spawn_mailbox::AdmissionPublication,
            crate::runtime::state::TaskSpawnEffects,
        )> = Vec::with_capacity(requests.len());
        let mut denied: SmallVec<
            [(
                crate::runtime::spawn_mailbox::LocalSpawnRequest,
                crate::runtime::state::SpawnError,
            ); 4],
        > = SmallVec::new();
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for request in requests {
                match state.admit_local_spawn_request(request) {
                    crate::runtime::state::LocalSpawnAdmission::Admitted {
                        task_id,
                        priority,
                        stored,
                        cancel_publication,
                        spawn_effects,
                    } => {
                        // Admission already pinned the record to this
                        // worker (`admit_local_spawn_request` requires the
                        // owner thread); publish the wake state so the
                        // first schedule is not coalesced away.
                        if let Some(record) = state.task_mut(task_id) {
                            record.wake_state.notify();
                        }
                        admitted.push((
                            task_id,
                            priority,
                            stored,
                            cancel_publication,
                            spawn_effects,
                        ));
                    }
                    crate::runtime::state::LocalSpawnAdmission::Denied { request, error } => {
                        denied.push((request, error));
                    }
                }
            }
        }

        let mut cancel_wakes = SmallVec::<
            [crate::types::task_context::CancelWakeEffects; LOCAL_SPAWN_ADMISSION_BATCH],
        >::new();
        let mut spawn_effects = SmallVec::<
            [crate::runtime::state::TaskSpawnEffects; LOCAL_SPAWN_ADMISSION_BATCH],
        >::new();
        for (task_id, _priority, stored, publication, effects) in admitted {
            crate::runtime::local::store_local_task(task_id, stored);
            let (wakes, effects) =
                publication.publish_with_spawn_effects(effects, |cancel_priority| {
                    if let Some(cancel_priority) = cancel_priority {
                        self.local.lock().schedule_cancel(task_id, cancel_priority);
                    } else {
                        // This worker owns both the thread-local task slot and this
                        // non-stealable queue. Publishing directly cannot take the
                        // missing-TLS failure path of the generic helper.
                        self.local_ready.lock().push_back(task_id);
                    }
                });
            cancel_wakes.push(wakes);
            if let Some(effects) = effects {
                spawn_effects.push(effects);
            }
        }
        // All owner-local task slots and queues are visible before observers
        // can reenter runtime or scheduler state.
        for effects in spawn_effects {
            effects.dispatch();
        }
        for (request, error) in denied {
            match error {
                crate::runtime::state::SpawnError::RegionClosed(_)
                | crate::runtime::state::SpawnError::RegionNotFound(_) => {
                    request.resolve_cancelled(crate::types::CancelReason::new(
                        crate::types::CancelKind::ParentCancelled,
                    ));
                }
                other => request.resolve_failed(other),
            }
        }
        for wakes in cancel_wakes {
            wakes.dispatch();
        }
    }

    pub fn next_task(&mut self) -> Option<TaskId> {
        // PHASE -0.6: TaskHandle abort/JoinFuture Drop enqueue callback-free
        // commands. Apply their authoritative task-state transition here.
        self.drain_handle_cancel_requests();

        // PHASE -0.5: Drop/error paths park auxiliary cancellation effects in
        // RuntimeState. Publish every task before dispatching those Wakers.
        self.drain_deferred_cancel_dispatches();

        // PHASE 0: Process expired timers (fires wakers, which may inject tasks).
        if let Some(timer) = &self.timer_driver {
            let _ = timer.process_timers();
        }

        // PHASE 0.5: Admit pending spawn-mailbox requests
        // (br-asupersync-dx-core-api-v2-u1z5hn.1.3). One atomic emptiness
        // check in direct mode / idle mailbox; bounded batch otherwise.
        self.drain_spawn_admissions();
        // PHASE 0.6: Admit owner-pinned local spawns parked on this
        // worker's thread-local lane (br-asupersync-i9y5wb / A2.2a). One
        // TLS emptiness check when idle.
        self.drain_local_spawn_admissions();

        // Admission publication can run a retained cancellation Waker after
        // making the new task visible. If that callback aborts another managed
        // task, consume its plain command before selecting any runnable work.
        self.drain_handle_cancel_requests();
        self.drain_deferred_cancel_dispatches();
        if self.pending_cancel_dispatch_ready.load(Ordering::Acquire)
            || self
                .spawn_mailbox
                .as_ref()
                .is_some_and(|mailbox| !mailbox.handle_cancels_are_empty())
        {
            // A just-dispatched Waker requested more cancellation. Yield this
            // selection turn so no ordinary ready task is polled ahead of the
            // runtime-owned command/deferred publication on the next turn.
            return None;
        }

        // Consult the governor for scheduling suggestion (amortised).
        let suggestion = self.governor_suggest();
        let base_limit = self.current_base_cancel_limit();
        self.preemption_metrics.adaptive_current_limit = base_limit;

        // Cancel eligibility: effective limit depends on suggestion.
        let effective_limit = match suggestion {
            SchedulingSuggestion::DrainObligations | SchedulingSuggestion::DrainRegions => {
                base_limit.saturating_mul(2)
            }
            _ => base_limit,
        };
        if effective_limit > self.preemption_metrics.max_effective_limit_observed {
            self.preemption_metrics.max_effective_limit_observed = effective_limit;
        }
        let check_cancel = self.cancel_streak < effective_limit;
        if !check_cancel {
            self.preemption_metrics.fairness_yields += 1;
        }

        // ── TIMED FAIRNESS: Prevent EDF starvation of FIFO work ──────────
        let check_timed = self.timed_dispatch_streak < self.timed_fairness_limit;
        if !check_timed && suggestion == SchedulingSuggestion::MeetDeadlines {
            // Timed fairness limit exceeded - force FIFO work to be checked
            // before more EDF dispatches to ensure 1/N quantum fairness
            if let Some(task) = self.try_phase3_ready_work() {
                self.timed_dispatch_streak = 0; // Reset EDF streak
                return Some(task);
            }
            // If no FIFO work available, allow EDF to continue but log fairness yield
            self.preemption_metrics.fairness_yields += 1;
        }

        // Current time for EDF (computed once, reused for global + local).
        let now = self.current_scheduler_time();

        // ── PHASE 1: Highest Priority Global Queue ───────────────────────
        if suggestion == SchedulingSuggestion::MeetDeadlines && check_timed {
            // Deadline pressure: global timed first (if fairness allows).
            if let Some(tt) = self.global.pop_timed_if_due(now) {
                self.record_timed_dispatch();
                self.timed_dispatch_streak += 1; // Track EDF streak
                return Some(self.dispatch_with_adaptive_epoch(tt.task));
            }
        } else {
            // Default / drain: cancel > timed.
            if check_cancel {
                if let Some(pt) = self.global.pop_cancel() {
                    self.cancel_streak += 1;
                    self.ready_dispatch_streak = 0;
                    self.record_cancel_dispatch(base_limit, effective_limit);
                    return Some(self.dispatch_with_adaptive_epoch(pt.task));
                }
            }
        }

        // ── PHASE 2: Interleaved Local and Global Priority Lanes ────────
        // We acquire the local `PriorityScheduler` lock once and check
        // the remaining cancel/timed lanes in strict suggestion order.
        let mut local = self.local.lock();
        let rng_hint = self.rng.next_u64();

        if suggestion == SchedulingSuggestion::MeetDeadlines && check_timed {
            // MeetDeadlines: Timed > Cancel (global timed already checked)
            if let Some(task) = local.pop_timed_only_with_hint(rng_hint, now) {
                drop(local);
                self.record_timed_dispatch();
                self.timed_dispatch_streak += 1; // Track EDF streak
                return Some(self.dispatch_with_adaptive_epoch(task));
            }
            if check_cancel {
                if let Some(pt) = self.global.pop_cancel() {
                    drop(local);
                    self.cancel_streak += 1;
                    self.ready_dispatch_streak = 0;
                    self.record_cancel_dispatch(base_limit, effective_limit);
                    return Some(self.dispatch_with_adaptive_epoch(pt.task));
                }
                if let Some(task) = local.pop_cancel_only_with_hint(rng_hint) {
                    drop(local);
                    self.cancel_streak += 1;
                    self.ready_dispatch_streak = 0;
                    self.record_cancel_dispatch(base_limit, effective_limit);
                    return Some(self.dispatch_with_adaptive_epoch(task));
                }
            }
        } else {
            // Default: Cancel > Timed (global cancel already checked)
            if check_cancel {
                if let Some(task) = local.pop_cancel_only_with_hint(rng_hint) {
                    drop(local);
                    self.cancel_streak += 1;
                    self.ready_dispatch_streak = 0;
                    self.record_cancel_dispatch(base_limit, effective_limit);
                    return Some(self.dispatch_with_adaptive_epoch(task));
                }
            }
            if let Some(tt) = self.global.pop_timed_if_due(now) {
                drop(local);
                self.record_timed_dispatch();
                return Some(self.dispatch_with_adaptive_epoch(tt.task));
            }
            if let Some(task) = local.pop_timed_only_with_hint(rng_hint, now) {
                drop(local);
                self.record_timed_dispatch();
                return Some(self.dispatch_with_adaptive_epoch(task));
            }
        }
        drop(local);

        if self.should_force_ready_handoff() {
            self.preemption_metrics.browser_ready_handoff_yields += 1;
            self.cancel_streak = 0;
            self.ready_dispatch_streak = 0;
            return None;
        }

        if let Some(task) = self.try_phase3_ready_work() {
            return Some(task);
        }

        // ── PHASE 4: Steal from other workers ────────────────────────
        if let Some(task) = self.try_steal() {
            self.record_ready_dispatch();
            return Some(self.dispatch_with_adaptive_epoch(task));
        }

        // ── PHASE 5: Fallback cancel ─────────────────────────────────
        // The streak limit was hit but no other lanes had work.  Allow
        // one more cancel dispatch (global + local).  Sets streak to 1
        // so the next call re-checks ready/timed after at most
        // cancel_streak_limit − 1 more cancel dispatches.
        if !check_cancel {
            if let Some(task) = self.try_cancel_work() {
                self.preemption_metrics.fallback_cancel_dispatches += 1;
                self.cancel_streak = 1;
                self.ready_dispatch_streak = 0;
                self.record_cancel_dispatch(base_limit, effective_limit);
                return Some(self.dispatch_with_adaptive_epoch(task));
            }
            self.cancel_streak = 0;
        }

        self.ready_dispatch_streak = 0;
        None
    }

    #[inline]
    fn should_force_ready_handoff(&self) -> bool {
        let limit = self.browser_ready_handoff_limit;
        if limit == 0 || self.ready_dispatch_streak < limit {
            return false;
        }

        if !self.fast_queue.is_empty()
            || !self.global_ready_buffer.is_empty()
            || self.global.has_ready_work()
        {
            return true;
        }
        if self
            .local_ready
            .try_lock()
            .is_some_and(|queue| !queue.is_empty())
        {
            return true;
        }
        self.local.lock().has_ready_work()
    }

    #[inline]
    fn peek_blocked_local_ready_for_inversion(&self) -> Option<(TaskId, u8)> {
        // Inversion accounting is observability-only. If another path currently
        // owns the local ready heap, do not block the hot fast/global ready
        // dispatch branches just to snapshot the blocked task.
        self.local
            .try_lock()
            .and_then(|mut local| local.peek_ready_task())
    }

    #[inline]
    fn take_global_ready_task(&mut self) -> Option<PriorityTask> {
        if let Some(prefetched) = self.global_ready_buffer.pop() {
            return Some(prefetched);
        }

        let decision = self.select_ready_batch_decision();
        let batch_size = decision.selected_batch_size.max(1);
        let batch_threshold = batch_size
            .saturating_mul(2)
            .max(GLOBAL_READY_BATCH_DRAIN_MIN_DEPTH);
        if batch_size > 1 && self.global.ready_count() >= batch_threshold {
            self.global_ready_buffer.clear();
            let drained = self
                .global
                .pop_ready_batch_into(batch_size, &mut self.global_ready_buffer);
            if drained > 0 {
                self.global_ready_buffer.reverse();
                self.preemption_metrics.global_ready_batch_drains += 1;
                self.preemption_metrics.global_ready_batch_tasks += drained as u64;
                return self.global_ready_buffer.pop();
            }
        }

        self.global.pop_ready()
    }

    fn try_phase3_ready_work(&mut self) -> Option<TaskId> {
        // ── PHASE 3: Fast ready paths (no PriorityScheduler lock) ────
        // Check local_ready first (highest priority: non-stealable local tasks),
        // then apply fairness logic between fast_queue (stolen work) and local work.
        let local_ready_task = self.local_ready.lock().pop_front();
        if let Some(task) = local_ready_task {
            self.record_ready_dispatch();
            self.fast_queue_dispatch_streak = 0; // Reset stolen work streak
            return Some(self.dispatch_with_adaptive_epoch(task));
        }

        // ── FAIRNESS LOGIC: Balance stolen work vs local work ───────
        // If we've dispatched too many consecutive stolen tasks, give local
        // work a chance to prevent starvation.
        let should_prioritize_local =
            self.fast_queue_dispatch_streak >= self.fast_queue_fairness_limit;

        if should_prioritize_local {
            // Check local work first to break stolen work streak
            let rng_hint = self.rng.next_u64();
            let local_task = {
                let mut local = self.local.lock();
                local.pop_ready_only_with_hint(rng_hint)
            };
            if let Some(task) = local_task {
                self.record_ready_dispatch();
                self.fast_queue_dispatch_streak = 0; // Reset stolen work streak
                return Some(self.dispatch_with_adaptive_epoch(task));
            }
        }

        // Check fast_queue (stolen work) if fairness allows it or local was empty
        if let Some(task) = self.fast_queue.pop() {
            if let Some(blocked_local_task) = self.peek_blocked_local_ready_for_inversion() {
                let dispatched_priority = self.task_sched_priority(task);
                self.record_ready_priority_inversion(
                    Some(blocked_local_task),
                    task,
                    dispatched_priority,
                );
            }
            self.record_ready_dispatch();
            self.fast_queue_dispatch_streak += 1; // Track stolen work streak
            return Some(self.dispatch_with_adaptive_epoch(task));
        }

        if let Some(pt) = self.take_global_ready_task() {
            if let Some(blocked_local_task) = self.peek_blocked_local_ready_for_inversion() {
                self.record_ready_priority_inversion(
                    Some(blocked_local_task),
                    pt.task,
                    Some(pt.priority),
                );
            }
            self.record_ready_dispatch();
            self.fast_queue_dispatch_streak = 0; // Reset stolen work streak
            return Some(self.dispatch_with_adaptive_epoch(pt.task));
        }

        // ── PHASE 3b: Local Ready Lane (fallback) ────────────────────
        // All fast paths returned nothing. Check local ready as final fallback.
        if !should_prioritize_local {
            let rng_hint = self.rng.next_u64();
            let local_task = {
                let mut local = self.local.lock();
                local.pop_ready_only_with_hint(rng_hint)
            };
            if let Some(task) = local_task {
                self.record_ready_dispatch();
                self.fast_queue_dispatch_streak = 0; // Reset stolen work streak
                return Some(self.dispatch_with_adaptive_epoch(task));
            }
        }

        None
    }

    /// Record a cancel dispatch and update max streak metric.
    #[inline]
    fn record_cancel_dispatch(&mut self, base_limit: usize, effective_limit: usize) {
        self.preemption_metrics.cancel_dispatches += 1;
        if self.cancel_streak > self.preemption_metrics.max_cancel_streak {
            self.preemption_metrics.max_cancel_streak = self.cancel_streak;
        }
        if self.cancel_streak > base_limit {
            self.preemption_metrics.base_limit_exceedances += 1;
        }
        if self.cancel_streak > effective_limit {
            self.preemption_metrics.effective_limit_exceedances += 1;
        }
        // Reset timed streak when cancel work is dispatched
        self.timed_dispatch_streak = 0;
    }

    #[inline]
    fn record_timed_dispatch(&mut self) {
        if self.cancel_streak > self.preemption_metrics.max_timed_dispatch_stall {
            self.preemption_metrics.max_timed_dispatch_stall = self.cancel_streak;
        }
        self.cancel_streak = 0;
        self.ready_dispatch_streak = 0;
        self.preemption_metrics.timed_dispatches += 1;
        // Note: timed_dispatch_streak is incremented at call sites for fairness tracking
    }

    #[inline]
    fn record_ready_dispatch(&mut self) {
        if self.cancel_streak > self.preemption_metrics.max_ready_dispatch_stall {
            self.preemption_metrics.max_ready_dispatch_stall = self.cancel_streak;
        }
        self.cancel_streak = 0;
        self.ready_dispatch_streak = self.ready_dispatch_streak.saturating_add(1);
        // Reset timed streak when ready work is dispatched
        self.timed_dispatch_streak = 0;
        self.preemption_metrics.ready_dispatches += 1;
    }

    fn record_ready_priority_inversion(
        &mut self,
        blocked_task: Option<(TaskId, u8)>,
        executing_task: TaskId,
        executing_priority: Option<u8>,
    ) {
        let Some((blocked_task, blocked_priority)) = blocked_task else {
            return;
        };
        let Some(executing_priority) = executing_priority else {
            return;
        };
        if blocked_priority <= executing_priority {
            return;
        }
        let timestamp = Time::from_nanos(self.current_time_ns());
        self.preemption_metrics.ready_priority_inversions += 1;
        let gap = blocked_priority.saturating_sub(executing_priority);
        if gap > self.preemption_metrics.max_ready_priority_inversion_gap {
            self.preemption_metrics.max_ready_priority_inversion_gap = gap;
        }
        {
            let mut invariant_monitor = self.invariant_monitor.lock();
            invariant_monitor.record_task_requeue(
                blocked_task,
                "local_ready_heap",
                blocked_priority,
                timestamp,
            );
            invariant_monitor.verify_priority_ordering(
                executing_task,
                executing_priority,
                blocked_task,
                blocked_priority,
                timestamp,
            );
        }
        self.fairness_monitor.lock().record_priority_inversion(
            blocked_task,
            blocked_priority,
            executing_task,
            executing_priority,
            timestamp.as_nanos(),
        );
    }

    #[inline]
    fn task_sched_priority(&self, task: TaskId) -> Option<u8> {
        self.with_task_table_ref(|tt| tt.task(task).map(|record| record.sched_priority))
    }

    #[inline]
    fn dispatch_with_adaptive_epoch(&mut self, task: TaskId) -> TaskId {
        self.ensure_adaptive_epoch_started();
        self.finish_dispatch(task)
    }

    #[inline]
    fn finish_dispatch(&mut self, task: TaskId) -> TaskId {
        // Record task dispatch for fairness monitoring
        let current_time = self.current_time_ns();
        self.fairness_monitor
            .lock()
            .record_task_dispatch(task, current_time);

        // Record task dequeue for invariant verification
        self.invariant_monitor
            .lock()
            .record_task_dispatch(task, Time::from_nanos(current_time));

        if let Some(collector) = &self.scheduler_evidence {
            let ready_backlog = self.ready_queue_depth_signal();
            let cancel_debt = self.cancel_debt_signal();
            collector
                .lock()
                .record_task_dispatch(task, current_time, ready_backlog, cancel_debt);
        }

        task
    }

    #[inline]
    fn ready_queue_depth_signal(&self) -> usize {
        let global_ready = self.global.ready_count();
        let prefetched_global_ready = self.global_ready_buffer.len();
        let fast_ready = self.fast_queue.len();
        let pinned_local_ready = self.local_ready.lock().len();
        let local_priority_ready = self.local.lock().approx_ready_len();

        global_ready
            .saturating_add(prefetched_global_ready)
            .saturating_add(fast_ready)
            .saturating_add(pinned_local_ready)
            .saturating_add(local_priority_ready)
    }

    #[inline]
    fn cancel_debt_signal(&self) -> usize {
        let global_cancel = self.global.cancel_count();
        let local_cancel = self.local.lock().approx_cancel_len();
        global_cancel.saturating_add(local_cancel)
    }

    /// Consult the governor for a scheduling suggestion, taking a fresh
    /// snapshot every `governor_interval` steps. When the governor is
    /// disabled, always returns `NoPreference`.
    #[allow(clippy::too_many_lines)]
    fn governor_suggest(&mut self) -> SchedulingSuggestion {
        let Some(governor) = &self.governor else {
            return SchedulingSuggestion::NoPreference;
        };

        self.steps_since_snapshot += 1;
        if self.steps_since_snapshot < self.governor_interval {
            self.emit_scheduler_evidence_for_suggestion(self.cached_suggestion);
            return self.cached_suggestion;
        }
        self.steps_since_snapshot = 0;

        // Take a snapshot under the state lock.
        // br-asupersync-1ckzhy: minimize allocation and iteration time under lock.
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let snapshot = StateSnapshot::from_runtime_state(&state);

        // br-asupersync-y5n8au + br-asupersync-1ckzhy: extract minimal wait graph
        // data under lock, defer expensive BTree/Tarjan analysis until after drop.
        let wait_graph_snapshot = if self.spectral_monitor.is_some() {
            Some(wait_graph_snapshot_from_state(&state))
        } else {
            None
        };
        drop(state);

        // br-asupersync-1ckzhy: expensive BTree construction, sorting, and trapped-SCC
        // detection (Tarjan's algorithm) happens here AFTER the state lock is dropped.
        let (wait_graph_nodes, wait_graph_edges, trapped_wait_cycle) = wait_graph_snapshot
            .as_ref()
            .map_or((0, Vec::new(), false), |snapshot| {
                wait_graph_signals_from_snapshot(snapshot)
            });

        // Enrich with ready-only queue depth. The governor/decision contract
        // should react to runnable backlog, not to cancel/timed entries that
        // are already represented elsewhere in the snapshot.
        let queue_depth = self.ready_queue_depth_signal();
        #[allow(clippy::cast_possible_truncation)]
        let snapshot = snapshot.with_ready_queue_depth(queue_depth as u32);

        let lyapunov_suggestion = governor.suggest(&snapshot);

        // Feed the drain progress certificate ONLY when the Lyapunov
        // governor indicates a drain phase (DrainObligations or DrainRegions).
        // During normal operation, steady-state potential fluctuation would
        // trigger false stall detection after stall_threshold consecutive
        // non-decreasing observations. By gating on the drain suggestion,
        // the certificate tracks convergence only when convergence is the
        // goal. When the governor leaves drain mode (NoPreference), the
        // certificate is reset for the next drain cycle.
        let drain_verdict = self.drain_certificate.as_mut().and_then(|cert| {
            let is_drain_phase = matches!(
                lyapunov_suggestion,
                SchedulingSuggestion::DrainObligations | SchedulingSuggestion::DrainRegions
            );
            if is_drain_phase {
                cert.observe(governor.compute_record(&snapshot).total);
                // Prevent unbounded memory growth during long drain phases by compacting
                // the observation history (keeping the last 64 observations for debugging)
                // while preserving the O(1) running statistics.
                if cert.len() > 128 {
                    cert.compact(64);
                }
                Some(cert.verdict())
            } else {
                // Not in a drain phase — reset the certificate so stale
                // observations from a prior drain cycle don't carry over.
                if !cert.is_empty() {
                    cert.reset();
                }
                None
            }
        });

        let mut spectral_report = None;
        if let Some(monitor) = self.spectral_monitor.as_mut() {
            if trapped_wait_cycle || wait_graph_nodes > 1 {
                spectral_report = Some(monitor.analyze_with_trapped_cycle(
                    wait_graph_nodes,
                    &wait_graph_edges,
                    trapped_wait_cycle,
                ));
            }
        }

        // Apply decision contract modulation if available (bd-1e2if.6).
        let mut suggestion = if let (Some(contract), Some(posterior)) =
            (&self.decision_contract, &mut self.decision_posterior)
        {
            // Update posterior from snapshot observations.
            let likelihoods =
                super::decision_contract::SchedulerDecisionContract::snapshot_likelihoods(
                    &snapshot,
                );
            posterior.bayesian_update(&likelihoods);

            let probs = posterior.probs();
            #[allow(clippy::cast_precision_loss)]
            let uniform = 1.0 / probs.len().max(1) as f64;
            let max_prob = probs
                .iter()
                .copied()
                .fold(0.0_f64, f64::max)
                .clamp(0.0, 1.0);
            let concentration = if probs.len() > 1 {
                ((max_prob - uniform) / (1.0 - uniform)).clamp(0.0, 1.0)
            } else {
                1.0
            };
            let entropy = normalized_entropy(probs);

            // Split-conformal one-step hit score from spectral monitor, when available.
            let conformal_hit = spectral_report
                .as_ref()
                .and_then(|report| {
                    report.bifurcation.as_ref().and_then(|bw| {
                        bw.conformal_lower_bound_next
                            .map(|lb| u8::from(report.decomposition.fiedler_value >= lb))
                    })
                })
                .map_or(1.0, f64::from);
            let uncertainty_penalty = 0.35f64.mul_add(1.0 - concentration, 0.15 * entropy);
            let conformal_penalty = 0.5 * (1.0 - conformal_hit);
            let calibration_score = (1.0 - uncertainty_penalty - conformal_penalty).clamp(0.0, 1.0);

            // Proxy posterior uncertainty width from concentration + entropy.
            let ci_width = 0.5f64
                .mul_add(1.0 - concentration, 0.25 * entropy)
                .clamp(0.0, 1.0);
            let adaptive_e = self.preemption_metrics.adaptive_e_value.max(1.0);
            let spectral_e = spectral_report
                .as_ref()
                .and_then(|report| {
                    report
                        .bifurcation
                        .as_ref()
                        .map(|bw| bw.deterioration_e_value.max(1.0))
                })
                .unwrap_or(1.0);
            let e_process = adaptive_e.max(spectral_e);

            // Evaluate the contract.
            let seq = self.decision_sequence;
            self.decision_sequence = self.decision_sequence.saturating_add(1);
            let now_ms = self
                .timer_driver
                .as_ref()
                .map_or(seq, |td| td.now().as_millis());
            let random_bits = ((self.id as u128) << 64) | u128::from(seq);
            let ctx = franken_decision::EvalContext {
                calibration_score,
                e_process,
                ci_width,
                decision_id: franken_kernel::DecisionId::from_parts(now_ms, random_bits),
                trace_id: franken_kernel::TraceId::from_parts(
                    now_ms,
                    random_bits ^ 0xA5A5_A5A5_A5A5_A5A5_A5A5,
                ),
                ts_unix_ms: now_ms,
            };
            // br-asupersync-g1pzep: evaluate now returns Result. The
            // contract here is the in-tree RaptorQDecisionContract and
            // should never produce ActionIndexOutOfRange in practice;
            // on error we fall back to the Lyapunov governor's
            // suggestion (the same path used when the franken-decision
            // contract is disabled at runtime).
            let outcome = match franken_decision::evaluate(contract, posterior, &ctx) {
                Ok(o) => o,
                Err(_) => return lyapunov_suggestion,
            };

            // Emit decision audit entry as evidence.
            if let Some(ref sink) = self.evidence_sink {
                let evidence = outcome.audit_entry.to_evidence_ledger();
                sink.emit(&evidence);
            }

            // Map contract action to scheduling suggestion.
            match outcome.action_index {
                super::decision_contract::action::AGGRESSIVE => SchedulingSuggestion::NoPreference,
                super::decision_contract::action::CONSERVATIVE => {
                    SchedulingSuggestion::MeetDeadlines
                }
                // BALANCED: use the Lyapunov governor's suggestion.
                _ => lyapunov_suggestion,
            }
        } else {
            lyapunov_suggestion
        };

        // Spectral topology override: this makes structural health influence the
        // live scheduling path when governor mode is enabled. Mere wait-graph
        // fragmentation is not a trapped wait cycle; the SCC path below owns
        // actual deadlock forcing.
        if let Some(report) = spectral_report.as_ref() {
            let override_suggestion = match report.classification {
                crate::observability::spectral_health::HealthClassification::Deadlocked => {
                    Some(SchedulingSuggestion::DrainObligations)
                }
                crate::observability::spectral_health::HealthClassification::Critical {
                    approaching_disconnect: true,
                    ..
                } => Some(SchedulingSuggestion::DrainObligations),
                _ => report.bifurcation.as_ref().and_then(|bw| {
                    (bw.trend
                        == crate::observability::spectral_health::SpectralTrend::Deteriorating
                        && (bw.confidence >= 0.6 || bw.deterioration_e_value >= 2.0))
                        .then_some(SchedulingSuggestion::DrainRegions)
                }),
            };
            if let Some(ovr) = override_suggestion {
                suggestion = ovr;
            }
        }
        if trapped_wait_cycle {
            suggestion = SchedulingSuggestion::DrainObligations;
        }

        // Drain-certificate override: the certificate is only fed during
        // Lyapunov drain phases (see above), so `drain_verdict` is `Some`
        // only when the governor wants to drain.
        //
        // IMPORTANT: never override a trapped-wait-cycle forced drain. The
        // certificate's quiescence verdict (Lyapunov potential near 0) does
        // NOT mean a structural deadlock is resolved — blocked tasks may
        // have zero potential while remaining permanently stuck.
        if !trapped_wait_cycle {
            if let Some(ref verdict) = drain_verdict {
                match verdict.drain_phase {
                    DrainPhase::Stalled if verdict.stall_detected => {
                        // Drain is in progress but potential has not decreased
                        // for stall_threshold consecutive governor snapshots.
                        // Ensure we are draining obligations specifically (the
                        // most aggressive drain mode).
                        suggestion = SchedulingSuggestion::DrainObligations;
                    }
                    DrainPhase::Quiescent => {
                        // Drain has converged to quiescence — relax back to
                        // normal scheduling. The certificate is reset in the
                        // non-drain branch above on the next governor call.
                        suggestion = SchedulingSuggestion::NoPreference;
                    }
                    _ => {}
                }
            }
        }

        // Emit one evidence record per governor invocation per
        // /reality-check-for-project (br-asupersync-c4r700). Every governor
        // call IS a decision — including "keep the same suggestion" — so
        // gating emission on `suggestion != self.cached_suggestion` masked
        // a fraction of decisions and made evidence collection
        // non-deterministic. The outer `if let Some(ref sink)` keeps the
        // prod-default (sink unconfigured) at zero cost, and `cached_suggestion`
        // is still consulted for the cache-hit fast-return at the top of
        // `governor_suggest` — only the change-detection guard is removed.
        self.emit_scheduler_evidence_for_suggestion(suggestion);

        self.cached_suggestion = suggestion;
        suggestion
    }

    /// Returns the scheduler's current notion of time.
    ///
    /// When no timer driver is installed, use the runtime state's cached clock
    /// so timed-lane dispatch stays consistent with the Lyapunov snapshot.
    fn current_scheduler_time(&self) -> Time {
        if let Some(timer_driver) = self.timer_driver.as_ref() {
            return TimerDriverHandle::now(timer_driver);
        }

        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .now
    }

    /// Runs a single scheduling step.
    ///
    /// Returns `true` if a task was executed.
    pub fn run_once(&mut self) -> bool {
        if self.shutdown.load(Ordering::Relaxed) {
            return false;
        }

        if let Some(task) = self.next_task() {
            self.execute(task);
            return true;
        }

        false
    }

    /// Tries to get cancel work from global or local queues.
    pub(crate) fn try_cancel_work(&mut self) -> Option<TaskId> {
        // Global cancel has priority (cross-thread cancellations)
        if let Some(pt) = self.global.pop_cancel() {
            return Some(pt.task);
        }

        // Local cancel
        let mut local = self.local.lock();
        let rng_hint = self.rng.next_u64();
        local.pop_cancel_only_with_hint(rng_hint)
    }

    /// Tries to get timed work from global or local queues.
    ///
    /// Uses EDF (Earliest Deadline First) ordering. Only returns tasks
    /// whose deadline has passed.
    #[allow(dead_code)] // Scheduler dispatch integration path
    pub(crate) fn try_timed_work(&mut self) -> Option<TaskId> {
        let now = self.current_scheduler_time();

        // Global timed - EDF ordering, only pop if deadline is due
        if let Some(tt) = self.global.pop_timed_if_due(now) {
            return Some(tt.task);
        }

        // Local timed (already EDF ordered)
        let mut local = self.local.lock();
        let rng_hint = self.rng.next_u64();
        local.pop_timed_only_with_hint(rng_hint, now)
    }

    /// Test-only accessor: returns the approximate number of ready tasks
    /// visible to this worker across its local queue, fast queue, and the
    /// shared global queue. Intended for invariant checks in metamorphic
    /// tests; not suitable for runtime decisions because the global count is
    /// shared across workers and can race with other workers' pops.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn ready_count(&self) -> usize {
        let local_ready = self.local_ready.try_lock().map_or(0, |q| q.len());
        let fast = self.fast_queue.len();
        let prefetched_global = self.global_ready_buffer.len();
        let global = self.global.ready_count();
        local_ready + fast + prefetched_global + global
    }

    /// Enqueues a synthetic non-stealable local task for integration tests.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-internals"))]
    pub fn enqueue_pinned_local_for_test(&self, task: TaskId) {
        self.local_ready.lock().push_back(task);
    }

    /// Reports whether a synthetic local task remains queued for integration tests.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-internals"))]
    pub fn contains_pinned_local_for_test(&self, task: TaskId) -> bool {
        self.local_ready.lock().snapshot().contains(&task)
    }

    /// Bench-only accessor for the worker's fast ready queue.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn bench_fast_ready_queue(&self) -> LocalQueue {
        self.fast_queue.clone()
    }

    /// Bench-only accessor for the worker's local priority scheduler mutex.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn bench_local_priority_scheduler(&self) -> Arc<Mutex<PriorityScheduler>> {
        Arc::clone(&self.local)
    }

    /// Bench-only entrypoint for the isolated Phase 3 ready-decision path.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn bench_try_phase3_ready_work(&mut self) -> Option<TaskId> {
        self.try_phase3_ready_work()
    }

    /// Bench-only entrypoint for the isolated steal path.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn bench_try_steal(&mut self) -> Option<TaskId> {
        self.try_steal()
    }

    /// Tries to get ready work from fast queue, global, or local queues.
    #[allow(dead_code)] // Scheduler dispatch integration path
    pub(crate) fn try_ready_work(&mut self) -> Option<TaskId> {
        // Highest priority: drain non-stealable local (!Send) tasks first.
        // These tasks are pinned to this worker and cannot run elsewhere.
        if let Some(task) = self.local_ready.lock().pop_front() {
            return Some(task);
        }

        // Fast path: O(1) pop from local VecDeque (LIFO, cache-friendly).
        if let Some(task) = self.fast_queue.pop() {
            return Some(task);
        }

        // Global ready
        if let Some(pt) = self.take_global_ready_task() {
            return Some(pt.task);
        }

        // Local ready (PriorityScheduler, O(log n) pop)
        let mut local = self.local.lock();
        let rng_hint = self.rng.next_u64();
        local.pop_ready_only_with_hint(rng_hint)
    }

    /// Tries to steal work from other workers.
    ///
    /// Fast path: O(1) steal from other workers' `LocalQueue` VecDeques.
    /// Slow path: O(k log n) steal from PriorityScheduler heaps.
    /// Only steals from ready lanes to preserve cancel/timed priority semantics.
    ///
    /// # Invariant
    ///
    /// Local (`!Send`) tasks are never returned from this method. They are
    /// enqueued exclusively in the non-stealable `local_ready` queue and
    /// never enter stealable structures (fast_queue or PriorityScheduler
    /// ready lane). The `debug_assert!` guards below verify this at runtime
    /// in debug builds.
    pub(crate) fn try_steal(&mut self) -> Option<TaskId> {
        // Fast path: steal from other workers' LocalQueues (O(1) per task).
        if !self.fast_stealers.is_empty() {
            let preferred_len = self
                .preferred_fast_stealer_count
                .min(self.fast_stealers.len());
            if preferred_len > 0 {
                let start = self.rng.next_usize(preferred_len);
                for i in 0..preferred_len {
                    let idx = (start + i) % preferred_len;
                    if let Some(task) = self.fast_stealers[idx].steal() {
                        // Safety invariant: local tasks must never be in stealable queues.
                        debug_assert!(
                            !self.with_task_table_ref(|tt| {
                                tt.task(task)
                                    .is_some_and(crate::record::task::TaskRecord::is_local)
                            }),
                            "BUG: stole a local (!Send) task {task:?} from another worker's fast_queue"
                        );

                        if self.fast_stealer_locality[idx].is_same_cohort() {
                            self.steal_locality_counters.preferred_fast_steals += 1;
                        } else {
                            self.steal_locality_counters.remote_fast_steals += 1;
                        }
                        self.invariant_monitor
                            .lock()
                            .record_task_dispatch(task, Time::from_nanos(self.current_time_ns()));

                        return Some(task);
                    }
                }
            }

            let remote_len = self.fast_stealers.len().saturating_sub(preferred_len);
            if remote_len > 0 {
                let start = self.rng.next_usize(remote_len);
                for i in 0..remote_len {
                    let idx = preferred_len + (start + i) % remote_len;
                    if let Some(task) = self.fast_stealers[idx].steal() {
                        debug_assert!(
                            !self.with_task_table_ref(|tt| {
                                tt.task(task)
                                    .is_some_and(crate::record::task::TaskRecord::is_local)
                            }),
                            "BUG: stole a local (!Send) task {task:?} from another worker's fast_queue"
                        );

                        if self.fast_stealer_locality[idx].is_same_cohort() {
                            self.steal_locality_counters.preferred_fast_steals += 1;
                        } else {
                            self.steal_locality_counters.remote_fast_steals += 1;
                        }
                        self.invariant_monitor
                            .lock()
                            .record_task_dispatch(task, Time::from_nanos(self.current_time_ns()));

                        return Some(task);
                    }
                }
            }
        }

        // Slow path: steal from PriorityScheduler heaps (O(k log n)).
        if self.stealers.is_empty() {
            return None;
        }

        let preferred_len = self.preferred_heap_stealer_count.min(self.stealers.len());

        for &(segment_start, segment_len) in &[
            (0usize, preferred_len),
            (
                preferred_len,
                self.stealers.len().saturating_sub(preferred_len),
            ),
        ] {
            if segment_len == 0 {
                continue;
            }

            let start = self.rng.next_usize(segment_len);
            for i in 0..segment_len {
                let idx = segment_start + (start + i) % segment_len;
                let stealer = &self.stealers[idx];

                // Try to lock without blocking (skip if contended)
                if let Some(mut victim) = stealer.try_lock() {
                    let stolen_count = victim
                        .steal_ready_batch_into(self.steal_batch_size, &mut self.steal_buffer);
                    // Queue mutation is complete. Release the victim before
                    // debug TaskTable inspection or any own-worker queue/
                    // evidence bookkeeping; delegated cancel publication uses
                    // the canonical TaskTable -> Cx -> local-queue order.
                    drop(victim);
                    if stolen_count > 0 {
                        #[cfg(debug_assertions)]
                        {
                            for &(task, _) in &self.steal_buffer[..stolen_count] {
                                let is_local = self.with_task_table_ref(|tt| {
                                    tt.task(task)
                                        .is_some_and(crate::record::task::TaskRecord::is_local)
                                });
                                debug_assert!(
                                    !is_local,
                                    "BUG: stole a local (!Send) task {task:?} from PriorityScheduler"
                                );
                            }
                        }

                        let (first_task, _) = self.steal_buffer[0];
                        if self.heap_stealer_locality[idx].is_same_cohort() {
                            self.steal_locality_counters.preferred_heap_steals += 1;
                        } else {
                            self.steal_locality_counters.remote_heap_steals += 1;
                        }

                        self.invariant_monitor.lock().record_task_dispatch(
                            first_task,
                            Time::from_nanos(self.current_time_ns()),
                        );

                        let steal_back_into_local_ready =
                            stolen_count > 1 && self.local.lock().peek_ready_priority().is_some();

                        if stolen_count > 1 {
                            if steal_back_into_local_ready {
                                let mut local = self.local.lock();
                                for &(task, priority) in &self.steal_buffer[1..stolen_count] {
                                    local.schedule(task, priority);
                                    self.invariant_monitor.lock().record_task_requeue(
                                        task,
                                        "local_ready_stolen",
                                        priority,
                                        Time::from_nanos(self.current_time_ns()),
                                    );
                                }
                            } else {
                                for &(task, priority) in
                                    self.steal_buffer[1..stolen_count].iter().rev()
                                {
                                    self.fast_queue.push(task);
                                    self.invariant_monitor.lock().record_task_requeue(
                                        task,
                                        "fast_queue_stolen",
                                        priority,
                                        Time::from_nanos(self.current_time_ns()),
                                    );
                                }
                            }
                        }

                        return Some(first_task);
                    }
                }
            }
        }

        None
    }

    #[doc(hidden)]
    #[cfg(feature = "test-internals")]
    pub fn steal_once_for_test(&mut self) -> Option<TaskId> {
        self.try_steal()
    }

    /// Schedules a task locally in the appropriate lane.
    ///
    /// Uses `wake_state.notify()` for centralized deduplication.
    /// If the task is already scheduled, this is a no-op.
    /// If the task record doesn't exist (e.g., in tests), allows scheduling.
    pub fn schedule_local(&self, task: TaskId, priority: u8) {
        let should_schedule = self.with_task_table_ref(|tt| {
            tt.task(task).is_none_or(|record| {
                // Local (!Send) tasks must never enter stealable structures.
                if record.is_local() {
                    error!(
                        ?task,
                        "schedule_local: refusing to enqueue local task into PriorityScheduler"
                    );
                    return false;
                }
                record.wake_state.notify()
            })
        });
        if should_schedule {
            let mut local = self.local.lock();
            local.schedule(task, priority);

            // Record task enqueue for fairness monitoring
            let current_time = self.current_time_ns();
            self.fairness_monitor.lock().record_task_enqueue(
                task,
                priority,
                current_time,
                2, // Ready lane = 2
            );

            // Record task enqueue for invariant verification
            self.invariant_monitor.lock().record_task_enqueue(
                task,
                "local_ready_heap",
                priority,
                Time::from_nanos(current_time),
            );

            self.record_scheduler_evidence_enqueue_at(task, current_time);
            self.parker.unpark();
        }
    }

    /// Promotes a local task to the cancel lane, matching global cancel semantics.
    ///
    /// Uses `move_to_cancel_lane` so that a task already in the ready or timed
    /// lane is relocated to the cancel lane.  This mirrors the global path where
    /// `inject_cancel` always injects (allowing duplicates for priority promotion).
    ///
    /// `wake_state.notify()` is still called for coordination with `finish_poll`,
    /// but the promotion itself is unconditional: a cancel must not be silently
    /// dropped just because the task was already scheduled in a lower-priority lane.
    pub fn schedule_local_cancel(&self, task: TaskId, priority: u8) {
        self.with_task_table_ref(|tt| {
            if let Some(record) = tt.task(task) {
                record.wake_state.notify();
            }
        });
        move_local_ready_task_to_cancel_lane(&self.local, &self.local_ready, task, priority);

        // Record task enqueue for fairness monitoring
        let current_time = self.current_time_ns();
        self.fairness_monitor.lock().record_task_enqueue(
            task,
            priority,
            current_time,
            0, // Cancel lane = 0
        );

        // Record task enqueue for invariant verification
        self.invariant_monitor.lock().record_task_requeue(
            task,
            "local_cancel_queue",
            priority,
            Time::from_nanos(current_time),
        );

        self.record_scheduler_evidence_enqueue_at(task, current_time);
        self.parker.unpark();
    }

    /// Schedules a timed task locally.
    ///
    /// Uses `wake_state.notify()` for centralized deduplication.
    /// If the task is already scheduled, this is a no-op.
    /// If the task record doesn't exist (e.g., in tests), allows scheduling.
    pub fn schedule_local_timed(&self, task: TaskId, deadline: Time) {
        let should_schedule = self.with_task_table_ref(|tt| {
            tt.task(task).is_none_or(|record| {
                if record.is_local() {
                    error!(
                        ?task,
                        "schedule_local_timed: refusing to enqueue local task into timed lane"
                    );
                    return false;
                }
                record.wake_state.notify()
            })
        });
        if should_schedule {
            let mut local = self.local.lock();
            local.schedule_timed(task, deadline);

            // Record task enqueue for fairness monitoring
            let current_time = self.current_time_ns();
            self.fairness_monitor.lock().record_task_enqueue(
                task,
                0, // Timed tasks don't have explicit priority, use 0
                current_time,
                1, // Timed lane = 1
            );

            // Record task enqueue for invariant verification
            self.invariant_monitor.lock().record_task_enqueue(
                task,
                "local_timed_queue",
                0, // Timed tasks use priority 0
                Time::from_nanos(current_time),
            );

            self.record_scheduler_evidence_enqueue_at(task, current_time);
            self.parker.unpark();
        }
    }

    /// Looks up waiter routing metadata from the active task-record source.
    ///
    /// In task-table-backed mode, waiter records may exist only in the sharded
    /// task table rather than `RuntimeState::tasks`, so completion-side wake
    /// routing must consult the shard directly.
    fn waiter_wake_metadata(
        &self,
        state: &RuntimeState,
        waiter: TaskId,
    ) -> Option<WaiterWakeMetadata> {
        if let Some(tt) = &self.task_table {
            let guard = tt.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let record = guard.task(waiter)?;
            Some(WaiterWakeMetadata {
                priority: record.sched_priority,
                is_local: record.is_local(),
                pinned_worker: record.pinned_worker(),
                wake_state: Arc::clone(&record.wake_state),
                notified: record.wake_state.notify(),
            })
        } else {
            let record = state.task(waiter)?;
            Some(WaiterWakeMetadata {
                priority: record.sched_priority,
                is_local: record.is_local(),
                pinned_worker: record.pinned_worker(),
                wake_state: Arc::clone(&record.wake_state),
                notified: record.wake_state.notify(),
            })
        }
    }

    /// Wakes a list of dependent tasks (waiters) while holding the RuntimeState lock.
    ///
    /// This handles local/global routing and centralized deduplication via `wake_state`.
    fn wake_dependents_locked(
        &self,
        state: &RuntimeState,
        waiters: impl IntoIterator<Item = TaskId>,
    ) {
        let mut global_tasks = smallvec::SmallVec::<[(TaskId, u8); 16]>::new();
        for waiter in waiters {
            let Some(metadata) = self.waiter_wake_metadata(state, waiter) else {
                continue;
            };
            if metadata.notified {
                if metadata.is_local {
                    if let Some(worker_id) = metadata.pinned_worker {
                        if let Some(queue) = self.all_local_ready.get(worker_id) {
                            queue.lock().push_back(waiter);
                            self.record_scheduler_evidence_enqueue(waiter);
                            self.coordinator.wake_worker(worker_id);
                        } else {
                            // SAFETY: Invalid worker id for a local waiter means
                            // we can't route to the correct queue. Skipping the
                            // wake avoids misrouting the task; clear the dedup
                            // bit so a later valid wake can retry.
                            metadata.wake_state.clear();
                            error!(
                                ?waiter,
                                worker_id,
                                "execute: pinned local waiter has invalid worker id, wake skipped and wake_state cleared"
                            );
                        }
                    } else {
                        // Local task without a pinned worker yet.
                        // Schedule on the current worker's local queue.
                        self.local_ready.lock().push_back(waiter);
                        self.record_scheduler_evidence_enqueue(waiter);
                        self.parker.unpark();
                    }
                } else {
                    // Global waiters are ready tasks.
                    global_tasks.push((waiter, metadata.priority));
                }
            }
        }
        let global_wakes = global_tasks.len();
        if global_wakes > 0 {
            // Increment the counter BEFORE pushing tasks to prevent concurrent stealers
            // from falsely seeing an empty queue and failing to decrement the counter.
            let mut reservation = self.global.reserve_ready_count(global_wakes);
            for (task, priority) in global_tasks {
                self.global.inject_ready_uncounted(task, priority);
                self.record_scheduler_evidence_enqueue(task);
                reservation.publish_one();
            }
            self.coordinator.wake_many(global_wakes);
        }
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn execute(&mut self, task_id: TaskId) {
        // Guard to handle unwinds that escape the explicit poll isolation below
        // before the runtime clears the current task context.
        struct TaskExecutionGuard<'a> {
            worker: &'a ThreeLaneWorker,
            task_id: TaskId,
            completed: bool,
        }

        impl Drop for TaskExecutionGuard<'_> {
            #[allow(clippy::significant_drop_tightening)] // false positive: guard still borrowed by wake_dependents_locked
            fn drop(&mut self) {
                if !self.completed && std::thread::panicking() {
                    let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        // Mark and detach through the same authoritative table
                        // used to begin this poll. Never ask embedded RuntimeState
                        // to complete a record owned by the external shard.
                        let mut detached_record = if self.worker.task_table.is_some() {
                            self.worker.with_task_table(|tt| {
                                let _ = tt.update_task(self.task_id, |record| {
                                    if !record.state.is_terminal() {
                                        record.complete(crate::types::Outcome::Panicked(
                                            crate::types::outcome::PanicPayload::new(
                                                "task panicked during scheduler bookkeeping",
                                            ),
                                        ));
                                    }
                                });
                                tt.remove_task(self.task_id)
                            })
                        } else {
                            self.worker.with_task_table(|tt| {
                                let _ = tt.update_task(self.task_id, |record| {
                                    if !record.state.is_terminal() {
                                        record.complete(crate::types::Outcome::Panicked(
                                            crate::types::outcome::PanicPayload::new(
                                                "task panicked during scheduler bookkeeping",
                                            ),
                                        ));
                                    }
                                });
                            });
                            None
                        };

                        let mut state = self
                            .worker
                            .state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let completion = match detached_record.as_mut() {
                            Some(record) => state.task_completed_from_external_record(record),
                            None => state.task_completed(self.task_id),
                        };
                        let (waiters, cancel_waker_retirements) =
                            completion.into_waiters_and_retirements_without_observers();
                        let finalizers = state.drain_ready_async_finalizers();
                        self.worker.wake_dependents_locked(&state, waiters);
                        let finalizer_publication =
                            self.worker.publish_ready_finalizers(finalizers);
                        drop(state);
                        self.worker
                            .finish_ready_finalizer_publication(finalizer_publication);
                        cancel_waker_retirements.retire();
                        ThreeLaneWorker::retire_detached_task_record(detached_record);
                    }));
                    if let Err(payload) = cleanup {
                        // This guard already runs during an unwind. Contain a
                        // second panic from tracing, metrics, or a foreign
                        // destructor instead of aborting the worker process.
                        std::mem::forget(payload);
                    }
                }
            }
        }

        Self::emit_cancel_diagnostic(|| {
            trace!(task_id = ?task_id, worker_id = self.id, "executing task");
        });

        let (
            mut stored,
            wake_state,
            priority,
            task_cx,
            cx_inner,
            cached_waker,
            cached_cancel_waker,
        ) = {
            // Fast path: single lock for global tasks (remove stored future + read record).
            let merged = self.with_task_table(|tt| {
                let global_stored = tt.remove_stored_future(task_id)?;
                tt.update_task(task_id, |record| {
                    record.start_running();
                    record.wake_state.begin_poll();
                    let priority = record.sched_priority;
                    let wake_state = Arc::clone(&record.wake_state);
                    // Preserve full Cx so scheduler sets CURRENT_CX during poll.
                    let task_cx = record.cx.clone();
                    let cached_waker = record.cached_waker.take();
                    let cached_cancel_waker = record.cached_cancel_waker.take();
                    // Skip cx_inner Arc clone when both wakers are cached with correct
                    // priority. Saves one atomic inc+dec per poll on the hot path.
                    // finish_poll() re-loads from the task table if needed (rare).
                    let both_cached = cached_waker.is_some()
                        && cached_cancel_waker
                            .as_ref()
                            .is_some_and(|(_, p)| *p == priority);
                    let cx_inner = if both_cached {
                        None
                    } else {
                        record.cx_inner.clone()
                    };
                    (
                        AnyStoredTask::Global(global_stored),
                        wake_state,
                        priority,
                        task_cx,
                        cx_inner,
                        cached_waker,
                        cached_cancel_waker,
                    )
                })
            });

            if let Some(result) = merged {
                result
            } else {
                // Slow path: local task (stored in TLS, not in global TaskTable).
                let local = crate::runtime::local::remove_local_task(task_id);
                let Some(local) = local else {
                    return;
                };
                let record_info = self.with_task_table(|tt| {
                    tt.update_task(task_id, |record| {
                        record.start_running();
                        record.wake_state.begin_poll();
                        let priority = record.sched_priority;
                        let wake_state = Arc::clone(&record.wake_state);
                        // Preserve full Cx so scheduler sets CURRENT_CX during poll.
                        let task_cx = record.cx.clone();
                        let cached_waker = record.cached_waker.take();
                        let cached_cancel_waker = record.cached_cancel_waker.take();
                        let both_cached = cached_waker.is_some()
                            && cached_cancel_waker
                                .as_ref()
                                .is_some_and(|(_, p)| *p == priority);
                        let cx_inner = if both_cached {
                            None
                        } else {
                            record.cx_inner.clone()
                        };
                        (
                            wake_state,
                            priority,
                            task_cx,
                            cx_inner,
                            cached_waker,
                            cached_cancel_waker,
                        )
                    })
                });
                let Some((
                    wake_state,
                    priority,
                    task_cx,
                    cx_inner,
                    cached_waker,
                    cached_cancel_waker,
                )) = record_info
                else {
                    return;
                };
                (
                    AnyStoredTask::Local(local),
                    wake_state,
                    priority,
                    task_cx,
                    cx_inner,
                    cached_waker,
                    cached_cancel_waker,
                )
            }
        };

        let is_local = stored.is_local();

        // Reuse cached waker (wakers are now dynamic, so priority check is not needed for correctness,
        // but we still store it in the record).
        let waker = if let Some((w, _)) = cached_waker {
            w
        } else {
            let inner = cx_inner.as_ref().expect("cx_inner missing");
            let fast_cancel = Arc::clone(&inner.read().fast_cancel);
            let weak_inner = Arc::downgrade(inner);
            if is_local {
                Waker::from(Arc::new(ThreeLaneLocalWaker {
                    task_id,
                    priority,
                    wake_state: Arc::clone(&wake_state),
                    local: Arc::clone(&self.local),
                    local_ready: Arc::clone(&self.local_ready),
                    parker: self.parker.clone(),
                    fast_cancel,
                    cx_inner: weak_inner,
                    scheduler_evidence: self.scheduler_evidence.clone(),
                }))
            } else {
                Waker::from(Arc::new(ThreeLaneWaker {
                    task_id,
                    wake_state: Arc::clone(&wake_state),
                    global: Arc::clone(&self.global),
                    coordinator: Arc::clone(&self.coordinator),
                    priority,
                    fast_cancel,
                    cx_inner: weak_inner,
                    scheduler_evidence: self.scheduler_evidence.clone(),
                }))
            }
        };
        // Create/reuse cancel waker.
        // Fast path: when cached with matching priority, skip cx_inner entirely
        // (cx_inner may be None because we skipped the Arc clone above).
        let cancel_waker_for_cache = if cached_cancel_waker
            .as_ref()
            .is_some_and(|(_, p)| *p == priority)
        {
            // Cancel waker cached with correct priority. No cx_inner needed.
            cached_cancel_waker.map(|(w, _)| (w, priority))
        } else {
            // Cache miss: build new cancel waker. cx_inner was cloned above.
            cx_inner.as_ref().map(|inner| {
                let w = if is_local {
                    Waker::from(Arc::new(ThreeLaneLocalCancelWaker {
                        task_id,
                        default_priority: priority,
                        wake_state: Arc::clone(&wake_state),
                        local: Arc::clone(&self.local),
                        local_ready: Arc::clone(&self.local_ready),
                        parker: self.parker.clone(),
                        cx_inner: Arc::downgrade(inner),
                        scheduler_evidence: self.scheduler_evidence.clone(),
                    }))
                } else {
                    Waker::from(Arc::new(CancelLaneWaker {
                        task_id,
                        default_priority: priority,
                        wake_state: Arc::clone(&wake_state),
                        global: Arc::clone(&self.global),
                        coordinator: Arc::clone(&self.coordinator),
                        cx_inner: Arc::downgrade(inner),
                        scheduler_evidence: self.scheduler_evidence.clone(),
                    }))
                };
                // New waker: prepare and retire ownership outside CxInner's
                // lock because custom Waker callbacks may reenter this task.
                let mut incoming_waker = Some(Arc::new(
                    crate::types::task_context::CancelWaker::new(w.clone()),
                ));
                let retired_waker = {
                    let mut guard = inner.write();
                    if guard.cancel_waker_registry_closed {
                        None
                    } else if !guard
                        .cancel_waker
                        .as_ref()
                        .is_some_and(|existing| existing.will_wake(&w))
                    {
                        std::mem::replace(&mut guard.cancel_waker, incoming_waker.take())
                    } else {
                        None
                    }
                };
                drop(retired_waker);
                drop(incoming_waker);
                (w, priority)
            })
        };
        // Install the task context BEFORE creating TaskExecutionGuard so
        // that during panic unwind, TaskExecutionGuard::drop runs first
        // (while Cx is still installed), then _cx_guard is dropped.  This
        // matches the ordering in worker.rs and ensures any cleanup code
        // in the guard's drop can access Cx::current().
        let _cx_guard = crate::cx::Cx::set_current(task_cx);
        let mut guard = TaskExecutionGuard {
            worker: self,
            task_id,
            completed: false,
        };

        // The worker dispatch quantum is one `Future::poll`. Do not loop on a
        // self-woken task here: returning to `next_task()` is what lets cancel,
        // timed, and ready lanes re-evaluate their fairness gates.
        let poll_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut cx = Context::from_waker(&waker);
            stored.poll(&mut cx)
        }));

        let mut credit_adaptive_epoch = true;
        match poll_result {
            Ok(Poll::Ready(outcome)) => {
                if matches!(outcome, crate::types::Outcome::Panicked(_)) {
                    credit_adaptive_epoch = false;
                }
                // Map Outcome<(), ()> to Outcome<(), Error> for record.complete()
                let task_outcome = outcome
                    .map_err(|()| crate::error::Error::new(crate::error::ErrorKind::Internal));
                let (completion_observer, cancel_wakes, detached_record, finalizer_publication) =
                    if self.task_table.is_some() {
                        // The sharded table owns the authoritative record. Reconcile
                        // the checkpoint receipt and terminal outcome there, then
                        // detach the record before taking RuntimeState. This avoids
                        // both the wrong-table completion bug and shard/state lock
                        // nesting around validator, region, and observer work.
                        let (cancel_ack, mut cancel_wakes, mut detached_record) = self
                            .with_task_table(|tt| {
                                let effects = Self::consume_cancel_ack_from_table(tt, task_id);
                                let (cancel_ack, cancel_wakes) = effects.into_parts();
                                let _ = tt.update_task(task_id, |record| {
                                    Self::complete_polled_record(
                                        record,
                                        task_outcome,
                                        cancel_ack.is_some(),
                                    );
                                });
                                let detached_record = tt.remove_task(task_id);
                                (cancel_ack, cancel_wakes, detached_record)
                            });

                        let mut state = self
                            .state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if let Some(receipt) = cancel_ack.as_ref()
                            && let Some(validation_result) = state
                                .external_checkpoint_cancel_materialization_violation(
                                    task_id, receipt, true,
                                )
                        {
                            cancel_wakes.push_cancel_protocol_violation(
                                "external-shard checkpoint cancellation materialization",
                                validation_result,
                            );
                        }
                        let completion = match detached_record.as_mut() {
                            Some(record) => state.task_completed_from_external_record(record),
                            None => state.task_completed(task_id),
                        };
                        let (waiters, completion_observer) = completion.into_parts();
                        let finalizers = state.drain_ready_async_finalizers();
                        self.wake_dependents_locked(&state, waiters);
                        let finalizer_publication = self.publish_ready_finalizers(finalizers);
                        drop(state);
                        (
                            completion_observer,
                            cancel_wakes,
                            detached_record,
                            finalizer_publication,
                        )
                    } else {
                        let mut state = self
                            .state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let (cancel_ack, cancel_wakes) =
                            Self::consume_cancel_ack_locked(&mut state, task_id).into_parts();
                        let _ = state.update_task(task_id, |record| {
                            Self::complete_polled_record(
                                record,
                                task_outcome,
                                cancel_ack.is_some(),
                            );
                        });
                        let (waiters, completion_observer) =
                            state.task_completed(task_id).into_parts();
                        let finalizers = state.drain_ready_async_finalizers();
                        self.wake_dependents_locked(&state, waiters);
                        let finalizer_publication = self.publish_ready_finalizers(finalizers);
                        drop(state);
                        (
                            completion_observer,
                            cancel_wakes,
                            None,
                            finalizer_publication,
                        )
                    };
                guard.completed = true;
                wake_state.clear();
                Self::retire_detached_task_record(detached_record);
                self.finish_ready_finalizer_publication(finalizer_publication);
                completion_observer.dispatch();
                cancel_wakes.dispatch();
            }
            Ok(Poll::Pending) => {
                // Store task back: use task table for hot-path when sharded.
                // Move waker into cache (not clone) since it is not needed after this point.
                // Store task, cache wakers, and reconcile the checkpoint ack in
                // one bookkeeping-aware task-table update.
                let cancel_effects = match stored {
                    AnyStoredTask::Global(t) => self.with_task_table(move |tt| {
                        tt.store_spawned_task(task_id, t);
                        tt.update_task(task_id, |record| {
                            record.cached_waker = Some((waker, priority));
                            record.cached_cancel_waker = cancel_waker_for_cache;
                            record.consume_checkpoint_cancel_ack()
                        })
                        .unwrap_or_else(|| {
                            crate::types::task_context::CancellationEffects::ready(None)
                        })
                    }),
                    AnyStoredTask::Local(t) => {
                        crate::runtime::local::store_local_task(task_id, t);
                        // For local tasks, we also want to cache wakers in the global record
                        // (since record is global).
                        self.with_task_table(move |tt| {
                            tt.update_task(task_id, |record| {
                                record.cached_waker = Some((waker, priority));
                                record.cached_cancel_waker = cancel_waker_for_cache;
                                record.consume_checkpoint_cancel_ack()
                            })
                            .unwrap_or_else(|| {
                                crate::types::task_context::CancellationEffects::ready(None)
                            })
                        })
                    }
                };
                let (cancel_ack, mut cancel_wakes) = cancel_effects.into_parts();
                if let Some(receipt) = cancel_ack.as_ref() {
                    let state = self
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if self.task_table.is_some() {
                        if let Some(validation_result) = state
                            .external_checkpoint_cancel_materialization_violation(
                                task_id, receipt, false,
                            )
                        {
                            cancel_wakes.push_cancel_protocol_violation(
                                "external-shard checkpoint cancellation materialization",
                                validation_result,
                            );
                        }
                    } else if let Some(validation_result) =
                        state.checkpoint_cancel_materialization_violation(task_id, receipt)
                    {
                        cancel_wakes.push_cancel_protocol_violation(
                            "checkpoint cancellation materialization",
                            validation_result,
                        );
                    }
                }
                let acknowledged_priority =
                    cancel_ack.as_ref().map(|receipt| receipt.cleanup_priority);

                if wake_state.finish_poll() || cancel_ack.is_some() {
                    let mut cancel_priority = acknowledged_priority.unwrap_or(priority);
                    let mut schedule_cancel = acknowledged_priority.is_some();
                    // cx_inner may be None if we skipped the Arc clone (both wakers
                    // were cached). Re-load from task table on this rare path.
                    let cx_inner_for_finish = if cx_inner.is_some() {
                        cx_inner
                    } else {
                        self.with_task_table(|tt| tt.task(task_id).and_then(|r| r.cx_inner.clone()))
                    };
                    if !schedule_cancel && let Some(inner) = cx_inner_for_finish.as_ref() {
                        let guard = inner.read();
                        if guard.cancel_requested {
                            schedule_cancel = true;
                            if let Some(reason) = guard.cancel_reason.as_ref() {
                                cancel_priority = reason.cleanup_budget().priority;
                            }
                        }
                    }

                    if is_local {
                        if schedule_cancel {
                            // Cancel still goes to PriorityScheduler for ordering.
                            // Cancel lane is not stolen by steal_ready_batch_into.
                            move_local_ready_task_to_cancel_lane(
                                &self.local,
                                &self.local_ready,
                                task_id,
                                cancel_priority,
                            );
                            self.record_scheduler_evidence_enqueue(task_id);
                        } else {
                            // Push to non-stealable local_ready queue.
                            // Local (!Send) tasks must never enter stealable structures.
                            self.local_ready.lock().push_back(task_id);
                            self.record_scheduler_evidence_enqueue(task_id);
                        }
                        self.parker.unpark();
                    } else {
                        // Schedule to global injector
                        if schedule_cancel {
                            self.global.inject_cancel(task_id, cancel_priority);
                        } else {
                            self.global.inject_ready(task_id, priority);
                        }
                        self.record_scheduler_evidence_enqueue(task_id);
                        self.coordinator.wake_one();
                    }
                }

                guard.completed = true;
                cancel_wakes.dispatch();
            }
            Err(payload) => {
                // Adaptive cancel-streak learning tracks scheduler pressure and
                // cleanup behavior, not arbitrary user-task crashes. A panic can
                // drop live-task potential abruptly and fabricate a "good"
                // reward signal, biasing the policy toward a wider cancel
                // streak for the wrong reason.
                credit_adaptive_epoch = false;
                let panic_message = crate::cx::scope::payload_to_string(&payload);
                // The caught payload is arbitrary user-owned data. Retiring it
                // can panic again or reenter runtime locks, so preserve only
                // the closed message and leak the opaque payload fail-closed.
                std::mem::forget(payload);
                let panic_payload = crate::types::outcome::PanicPayload::new(panic_message);
                let panic_outcome = crate::types::Outcome::Panicked(panic_payload);
                let (completion_observer, cancel_wakes, detached_record, finalizer_publication) =
                    if self.task_table.is_some() {
                        let (cancel_ack, mut cancel_wakes, mut detached_record) = self
                            .with_task_table(|tt| {
                                let effects = Self::consume_cancel_ack_from_table(tt, task_id);
                                let (cancel_ack, cancel_wakes) = effects.into_parts();
                                let _ = tt.update_task(task_id, |record| {
                                    if !record.state.is_terminal() {
                                        record.complete(panic_outcome);
                                    }
                                });
                                let detached_record = tt.remove_task(task_id);
                                (cancel_ack, cancel_wakes, detached_record)
                            });
                        let mut state = self
                            .state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if let Some(receipt) = cancel_ack.as_ref()
                            && let Some(validation_result) = state
                                .external_checkpoint_cancel_materialization_violation(
                                    task_id, receipt, true,
                                )
                        {
                            cancel_wakes.push_cancel_protocol_violation(
                                "external-shard checkpoint cancellation materialization",
                                validation_result,
                            );
                        }
                        let completion = match detached_record.as_mut() {
                            Some(record) => state.task_completed_from_external_record(record),
                            None => state.task_completed(task_id),
                        };
                        let (waiters, completion_observer) = completion.into_parts();
                        let finalizers = state.drain_ready_async_finalizers();
                        self.wake_dependents_locked(&state, waiters);
                        let finalizer_publication = self.publish_ready_finalizers(finalizers);
                        drop(state);
                        (
                            completion_observer,
                            cancel_wakes,
                            detached_record,
                            finalizer_publication,
                        )
                    } else {
                        let mut state = self
                            .state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let (_cancel_ack, cancel_wakes) =
                            Self::consume_cancel_ack_locked(&mut state, task_id).into_parts();
                        let _ = state.update_task(task_id, |record| {
                            if !record.state.is_terminal() {
                                record.complete(panic_outcome);
                            }
                        });
                        let (waiters, completion_observer) =
                            state.task_completed(task_id).into_parts();
                        let finalizers = state.drain_ready_async_finalizers();
                        self.wake_dependents_locked(&state, waiters);
                        let finalizer_publication = self.publish_ready_finalizers(finalizers);
                        drop(state);
                        (
                            completion_observer,
                            cancel_wakes,
                            None,
                            finalizer_publication,
                        )
                    };
                guard.completed = true;
                wake_state.clear();
                Self::retire_detached_task_record(detached_record);
                self.finish_ready_finalizer_publication(finalizer_publication);
                completion_observer.dispatch();
                cancel_wakes.dispatch();
            }
        }
        drop(guard);
        if credit_adaptive_epoch {
            self.adaptive_on_dispatch();
        } else {
            self.abort_adaptive_epoch();
        }
    }

    fn publish_ready_finalizers(
        &self,
        finalizers: smallvec::SmallVec<[(TaskId, u8, crate::runtime::state::TaskSpawnEffects); 2]>,
    ) -> (
        smallvec::SmallVec<[TaskId; 2]>,
        smallvec::SmallVec<[crate::runtime::state::TaskSpawnEffects; 2]>,
    ) {
        let finalizer_wakes = finalizers.len();
        if finalizer_wakes == 0 {
            return (smallvec::SmallVec::new(), smallvec::SmallVec::new());
        }
        let mut tasks = smallvec::SmallVec::new();
        let mut spawn_effects = smallvec::SmallVec::new();
        let mut reservation = self.global.reserve_ready_count(finalizer_wakes);
        for (finalizer_task, priority, effects) in finalizers {
            self.global.inject_ready_uncounted(finalizer_task, priority);
            reservation.publish_one();
            tasks.push(finalizer_task);
            spawn_effects.push(effects);
        }
        (tasks, spawn_effects)
    }

    fn finish_ready_finalizer_publication(
        &self,
        (tasks, spawn_effects): (
            smallvec::SmallVec<[TaskId; 2]>,
            smallvec::SmallVec<[crate::runtime::state::TaskSpawnEffects; 2]>,
        ),
    ) {
        for &task in &tasks {
            Self::emit_cancel_diagnostic(|| self.record_scheduler_evidence_enqueue(task));
        }
        Self::emit_cancel_diagnostic(|| self.coordinator.wake_many(tasks.len()));
        for effects in spawn_effects {
            effects.dispatch();
        }
    }

    fn retire_detached_task_record(record: Option<crate::record::task::TaskRecord>) {
        let Some(record) = record else {
            return;
        };
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(record);
        })) {
            // A detached record may own foreign RawWaker payloads or user-owned
            // context values. It is already absent from every runtime table;
            // contain a hostile destructor at this lock-free retirement boundary.
            std::mem::forget(payload);
        }
    }

    fn schedule_ready_finalizers(&self) -> bool {
        let tasks = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.drain_ready_async_finalizers()
        };
        if tasks.is_empty() {
            return false;
        }
        let publication = self.publish_ready_finalizers(tasks);
        self.finish_ready_finalizer_publication(publication);
        true
    }

    /// Consumes a cancel acknowledgement using the task table shard when available.
    ///
    /// This is the hot-path variant used in Poll::Pending where only task record
    /// access is needed.
    #[allow(dead_code)] // Used in scheduler dispatch + tests
    fn consume_cancel_ack(
        &self,
        task_id: TaskId,
    ) -> crate::types::task_context::CancellationEffects<
        Option<crate::record::task::CheckpointCancelAck>,
    > {
        let effects = self.with_task_table(|tt| Self::consume_cancel_ack_from_table(tt, task_id));
        let (receipt, mut wakes) = effects.into_parts();
        if let Some(receipt) = receipt.as_ref() {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.task_table.is_some() {
                let task_still_live = self.with_task_table_ref(|tt| tt.task(task_id).is_some());
                if let Some(validation_result) = state
                    .external_checkpoint_cancel_materialization_violation(
                        task_id,
                        receipt,
                        !task_still_live,
                    )
                {
                    wakes.push_cancel_protocol_violation(
                        "external-shard checkpoint cancellation materialization",
                        validation_result,
                    );
                }
            } else if let Some(validation_result) =
                state.checkpoint_cancel_materialization_violation(task_id, receipt)
            {
                wakes.push_cancel_protocol_violation(
                    "checkpoint cancellation materialization",
                    validation_result,
                );
            }
        }
        crate::types::task_context::CancellationEffects::new(receipt, wakes)
    }

    fn consume_cancel_ack_locked(
        state: &mut RuntimeState,
        task_id: TaskId,
    ) -> crate::types::task_context::CancellationEffects<
        Option<crate::record::task::CheckpointCancelAck>,
    > {
        state.consume_task_checkpoint_cancel_ack(task_id)
    }

    fn consume_cancel_ack_from_table(
        tt: &mut TaskTable,
        task_id: TaskId,
    ) -> crate::types::task_context::CancellationEffects<
        Option<crate::record::task::CheckpointCancelAck>,
    > {
        tt.update_task(
            task_id,
            crate::record::task::TaskRecord::consume_checkpoint_cancel_ack,
        )
        .unwrap_or_else(|| crate::types::task_context::CancellationEffects::ready(None))
    }

    fn complete_polled_record(
        record: &mut crate::record::task::TaskRecord,
        task_outcome: crate::types::Outcome<(), crate::error::Error>,
        cancel_ack: bool,
    ) {
        if record.state.is_terminal() {
            return;
        }
        let mut completed_via_cancel = false;
        if matches!(task_outcome, crate::types::Outcome::Ok(())) {
            let should_cancel = matches!(
                record.state,
                crate::record::task::TaskState::Cancelling { .. }
                    | crate::record::task::TaskState::Finalizing { .. }
            ) || (cancel_ack
                && matches!(
                    record.state,
                    crate::record::task::TaskState::CancelRequested { .. }
                ));
            if should_cancel {
                if matches!(
                    record.state,
                    crate::record::task::TaskState::CancelRequested { .. }
                ) {
                    let _ = record.acknowledge_cancel();
                }
                if matches!(
                    record.state,
                    crate::record::task::TaskState::Cancelling { .. }
                ) {
                    record.cleanup_done();
                }
                if matches!(
                    record.state,
                    crate::record::task::TaskState::Finalizing { .. }
                ) {
                    record.finalize_done();
                }
                completed_via_cancel = matches!(
                    record.state,
                    crate::record::task::TaskState::Completed(crate::types::Outcome::Cancelled(_))
                );
            }
        }
        if !completed_via_cancel {
            record.complete(task_outcome);
        }
    }
}

struct ThreeLaneWaker {
    task_id: TaskId,
    wake_state: Arc<crate::record::task::TaskWakeState>,
    global: Arc<GlobalInjector>,
    coordinator: Arc<WorkerCoordinator>,
    /// Cached priority to avoid `Weak::upgrade` + `RwLock::read` on every wake.
    /// Safe because `budget.priority` is immutable after task creation.
    priority: u8,
    fast_cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    cx_inner: Weak<RwLock<CxInner>>,
    scheduler_evidence: Option<Arc<Mutex<SchedulerEvidenceCollector>>>,
}

impl ThreeLaneWaker {
    #[inline]
    fn schedule(&self) {
        if self.wake_state.notify() {
            // Check for cancellation to route to correct lane (cancel > ready).
            // This ensures "Losers are drained" with high priority even during I/O wakeups.
            let mut priority = self.priority;
            // Pair with the Release store in `CxInner::fast_cancel` so a wake
            // that observes cancellation also observes the published reason.
            let is_cancelling = self.fast_cancel.load(Ordering::Acquire);

            if is_cancelling {
                if let Some(inner) = self.cx_inner.upgrade() {
                    let guard = inner.read();
                    if let Some(reason) = &guard.cancel_reason {
                        priority = reason.cleanup_budget().priority;
                    }
                }
            }

            if is_cancelling {
                self.global.inject_cancel(self.task_id, priority);
            } else {
                self.global.inject_ready(self.task_id, priority);
            }
            if let Some(collector) = &self.scheduler_evidence {
                collector
                    .lock()
                    .record_task_enqueue(self.task_id, crate::time::wall_now().as_nanos());
            }
            self.coordinator.wake_one();
        }
    }
}

use std::task::Wake;
impl Wake for ThreeLaneWaker {
    #[inline]
    fn wake(self: Arc<Self>) {
        self.schedule();
    }

    #[inline]
    fn wake_by_ref(self: &Arc<Self>) {
        self.schedule();
    }
}

struct ThreeLaneLocalWaker {
    task_id: TaskId,
    /// Cached priority so cancelled local tasks fall back to their base
    /// priority instead of 0 when `cancel_reason` is not yet set.
    priority: u8,
    wake_state: Arc<crate::record::task::TaskWakeState>,
    local: Arc<Mutex<PriorityScheduler>>,
    local_ready: Arc<LocalReadyQueue>,
    parker: Parker,
    fast_cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    cx_inner: Weak<RwLock<CxInner>>,
    scheduler_evidence: Option<Arc<Mutex<SchedulerEvidenceCollector>>>,
}

impl ThreeLaneLocalWaker {
    #[inline]
    fn schedule(&self) {
        if self.wake_state.notify() {
            // Pair with the Release store in `CxInner::fast_cancel` so the
            // local wake path sees cancellation publication before routing.
            let is_cancelling = self.fast_cancel.load(Ordering::Acquire);

            if is_cancelling {
                let mut priority = self.priority;
                if let Some(inner) = self.cx_inner.upgrade() {
                    let guard = inner.read();
                    if let Some(reason) = &guard.cancel_reason {
                        priority = reason.cleanup_budget().priority;
                    }
                }
                // Promote to the local cancel lane, matching `inject_cancel`
                // and `schedule_local_cancel`: a cancelled local task must not
                // remain in the non-stealable ready queue.
                move_local_ready_task_to_cancel_lane(
                    &self.local,
                    &self.local_ready,
                    self.task_id,
                    priority,
                );
            } else {
                // Push to non-stealable local_ready queue.
                self.local_ready.lock().push_back(self.task_id);
            }
            if let Some(collector) = &self.scheduler_evidence {
                collector
                    .lock()
                    .record_task_enqueue(self.task_id, crate::time::wall_now().as_nanos());
            }
            self.parker.unpark();
        }
    }
}

impl Wake for ThreeLaneLocalWaker {
    #[inline]
    fn wake(self: Arc<Self>) {
        self.schedule();
    }

    #[inline]
    fn wake_by_ref(self: &Arc<Self>) {
        self.schedule();
    }
}

struct CancelLaneWaker {
    task_id: TaskId,
    default_priority: u8,
    wake_state: Arc<crate::record::task::TaskWakeState>,
    global: Arc<GlobalInjector>,
    coordinator: Arc<WorkerCoordinator>,
    cx_inner: Weak<RwLock<CxInner>>,
    scheduler_evidence: Option<Arc<Mutex<SchedulerEvidenceCollector>>>,
}

impl CancelLaneWaker {
    #[inline]
    fn schedule(&self) {
        let Some(inner) = self.cx_inner.upgrade() else {
            return;
        };
        let (cancel_requested, priority) = {
            let guard = inner.read();
            let priority = guard
                .cancel_reason
                .as_ref()
                .map_or(self.default_priority, |reason| {
                    reason.cleanup_budget().priority
                });
            (guard.cancel_requested, priority)
        };

        if !cancel_requested {
            return;
        }

        // Always notify (attempt state transition)
        self.wake_state.notify();

        // Always inject to ensure priority promotion, even if already scheduled.
        // See `inject_cancel` for details.
        self.global.inject_cancel(self.task_id, priority);
        if let Some(collector) = &self.scheduler_evidence {
            collector
                .lock()
                .record_task_enqueue(self.task_id, crate::time::wall_now().as_nanos());
        }
        self.coordinator.wake_one();
    }
}

impl Wake for CancelLaneWaker {
    #[inline]
    fn wake(self: Arc<Self>) {
        self.schedule();
    }

    #[inline]
    fn wake_by_ref(self: &Arc<Self>) {
        self.schedule();
    }
}

struct ThreeLaneLocalCancelWaker {
    task_id: TaskId,
    default_priority: u8,
    wake_state: Arc<crate::record::task::TaskWakeState>,
    local: Arc<Mutex<PriorityScheduler>>,
    local_ready: Arc<LocalReadyQueue>,
    parker: Parker,
    cx_inner: Weak<RwLock<CxInner>>,
    scheduler_evidence: Option<Arc<Mutex<SchedulerEvidenceCollector>>>,
}

impl ThreeLaneLocalCancelWaker {
    #[inline]
    fn schedule(&self) {
        let Some(inner) = self.cx_inner.upgrade() else {
            return;
        };
        let (cancel_requested, priority) = {
            let guard = inner.read();
            let priority = guard
                .cancel_reason
                .as_ref()
                .map_or(self.default_priority, |reason| {
                    reason.cleanup_budget().priority
                });
            (guard.cancel_requested, priority)
        };

        if !cancel_requested {
            return;
        }

        // Always notify
        self.wake_state.notify();

        // Promote to local cancel lane, matching global inject_cancel semantics.
        // move_to_cancel_lane relocates from ready/timed if already scheduled.
        {
            move_local_ready_task_to_cancel_lane(
                &self.local,
                &self.local_ready,
                self.task_id,
                priority,
            );
        }
        if let Some(collector) = &self.scheduler_evidence {
            collector
                .lock()
                .record_task_enqueue(self.task_id, crate::time::wall_now().as_nanos());
        }
        self.parker.unpark();
    }
}

impl Wake for ThreeLaneLocalCancelWaker {
    #[inline]
    fn wake(self: Arc<Self>) {
        self.schedule();
    }

    #[inline]
    fn wake_by_ref(self: &Arc<Self>) {
        self.schedule();
    }
}

#[cfg(test)]
#[path = "three_lane_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "three_lane_metamorphic.rs"]
mod three_lane_metamorphic;
