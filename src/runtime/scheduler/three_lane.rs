//! Multi-worker 3-lane scheduler with work stealing.
//!
//! This scheduler coordinates multiple worker threads while maintaining
//! strict priority ordering: cancel > timed > ready.
//!
//! # Cancel-lane preemption with bounded fairness (bd-17uu)
//!
//! The cancel lane has strict preemption over timed and ready lanes, but a
//! fairness mechanism prevents starvation of lower-priority work.
//!
//! ## Invariant
//!
//! **Fairness bound**: If the ready or timed lane has pending work, that work
//! is dispatched after at most `cancel_streak_limit` consecutive cancel-lane
//! dispatches (or `2 * cancel_streak_limit` under `DrainObligations`/`DrainRegions`).
//!
//! ## Proof sketch (per-worker, single-threaded scheduling loop)
//!
//! 1. Each worker maintains a monotone counter `cancel_streak` that increments
//!    on every cancel dispatch and resets to 0 on any non-cancel dispatch (or
//!    when the cancel lane is empty).
//!
//! 2. In `next_task()`, the cancel lane is only consulted when
//!    `cancel_streak < cancel_streak_limit`. Once the limit is reached, the
//!    scheduler falls through to timed, ready, and steal.
//!
//! 3. If timed or ready work is pending when cancel_streak hits the limit,
//!    that work is dispatched next, resetting cancel_streak to 0. Cancel work
//!    resumes on the following call to `next_task()`.
//!
//! 4. If no timed/ready/steal work is available when the limit is hit, a
//!    fallback path allows one more cancel dispatch with cancel_streak reset
//!    to 1. This ensures cancel work is not blocked indefinitely when it is
//!    the only pending work.
//!
//! 5. On backoff/park (no work found), cancel_streak resets to 0. This
//!    prevents stale counters from deferring cancel work after an idle period.
//!
//! **Corollary**: Under sustained cancel injection, the ready lane observes a
//! dispatch slot at least every `cancel_streak_limit + 1` scheduling steps,
//! giving a worst-case ready-lane stall of O(cancel_streak_limit) dispatch
//! cycles per worker.
//!
//! ## Cross-worker note
//!
//! Fairness is enforced per-worker. Global fairness follows from each worker
//! independently bounding its cancel streak. Work stealing operates only on
//! the ready lane, so a worker whose ready lane is starved by cancel work
//! will not have its ready tasks stolen.

use crate::obligation::lyapunov::{LyapunovGovernor, SchedulingSuggestion, StateSnapshot};
use crate::runtime::scheduler::global_injector::GlobalInjector;
use crate::runtime::scheduler::priority::Scheduler as PriorityScheduler;
use crate::runtime::scheduler::worker::Parker;
use crate::runtime::stored_task::AnyStoredTask;
use crate::runtime::RuntimeState;
use crate::time::TimerDriverHandle;
use crate::tracing_compat::trace;
use crate::types::{CxInner, TaskId, Time};
use crate::util::DetRng;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

/// Identifier for a scheduler worker.
pub type WorkerId = usize;

const DEFAULT_CANCEL_STREAK_LIMIT: usize = 16;

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
    /// Worker handles for thread spawning.
    workers: Vec<ThreeLaneWorker>,
    /// Shutdown signal.
    shutdown: Arc<AtomicBool>,
    /// Parkers for waking idle workers.
    parkers: Vec<Parker>,
    /// Round-robin index for waking workers.
    next_wake: AtomicUsize,
    /// Maximum consecutive cancel-lane dispatches before yielding.
    cancel_streak_limit: usize,
    /// Timer driver for processing timer wakeups.
    timer_driver: Option<TimerDriverHandle>,
    /// Shared runtime state for accessing task records and wake_state.
    state: Arc<Mutex<RuntimeState>>,
}

impl ThreeLaneScheduler {
    /// Creates a new 3-lane scheduler with the given number of workers.
    pub fn new(worker_count: usize, state: &Arc<Mutex<RuntimeState>>) -> Self {
        Self::new_with_options(worker_count, state, DEFAULT_CANCEL_STREAK_LIMIT, false, 32)
    }

    /// Creates a new 3-lane scheduler with a configurable cancel streak limit.
    pub fn new_with_cancel_limit(
        worker_count: usize,
        state: &Arc<Mutex<RuntimeState>>,
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
        state: &Arc<Mutex<RuntimeState>>,
        cancel_streak_limit: usize,
        enable_governor: bool,
        governor_interval: u32,
    ) -> Self {
        let cancel_streak_limit = cancel_streak_limit.max(1);
        let governor_interval = governor_interval.max(1);
        let global = Arc::new(GlobalInjector::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::with_capacity(worker_count);
        let mut parkers = Vec::with_capacity(worker_count);
        let mut local_schedulers: Vec<Arc<Mutex<PriorityScheduler>>> =
            Vec::with_capacity(worker_count);

        // Get timer driver from runtime state
        let timer_driver = state
            .lock()
            .expect("runtime state lock poisoned")
            .timer_driver_handle();

        // Create local schedulers first so we can share references for stealing
        for _ in 0..worker_count {
            local_schedulers.push(Arc::new(Mutex::new(PriorityScheduler::new())));
        }

        // Create workers with references to all other workers' schedulers
        for id in 0..worker_count {
            let parker = Parker::new();
            parkers.push(parker.clone());

            // Stealers: all other workers' local schedulers (excluding self)
            let stealers: Vec<_> = local_schedulers
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != id)
                .map(|(_, sched)| Arc::clone(sched))
                .collect();

            workers.push(ThreeLaneWorker {
                id,
                local: Arc::clone(&local_schedulers[id]),
                stealers,
                global: Arc::clone(&global),
                state: Arc::clone(state),
                parker,
                rng: DetRng::new(id as u64),
                shutdown: Arc::clone(&shutdown),
                timer_driver: timer_driver.clone(),
                steal_buffer: Vec::with_capacity(8),
                cancel_streak: 0,
                cancel_streak_limit,
                governor: if enable_governor {
                    Some(LyapunovGovernor::with_defaults())
                } else {
                    None
                },
                cached_suggestion: SchedulingSuggestion::NoPreference,
                steps_since_snapshot: 0,
                governor_interval,
                preemption_metrics: PreemptionMetrics::default(),
            });
        }

        Self {
            global,
            workers,
            shutdown,
            parkers,
            next_wake: AtomicUsize::new(0),
            timer_driver,
            state: Arc::clone(state),
            cancel_streak_limit,
        }
    }

    /// Returns a reference to the global injector.
    pub fn global_injector(&self) -> Arc<GlobalInjector> {
        self.global.clone()
    }

    /// Injects a task into the cancel lane for cross-thread wakeup.
    ///
    /// Uses `wake_state.notify()` for centralized deduplication.
    /// If the task is already scheduled, this is a no-op.
    /// If the task record doesn't exist (e.g., in tests), allows injection.
    pub fn inject_cancel(&self, task: TaskId, priority: u8) {
        // Cancel is the highest-priority lane.  Always inject so that
        // cancellation preempts ready/timed work even if the task is already
        // scheduled in another lane.  Deduplication happens at poll time
        // (finish_poll routes to cancel lane when a cancel is pending).
        self.global.inject_cancel(task, priority);
        self.wake_one();
    }

    /// Injects a task into the timed lane for cross-thread wakeup.
    ///
    /// Uses `wake_state.notify()` for centralized deduplication.
    /// If the task is already scheduled, this is a no-op.
    /// If the task record doesn't exist (e.g., in tests), allows injection.
    pub fn inject_timed(&self, task: TaskId, deadline: Time) {
        let should_schedule = {
            let state = self.state.lock().expect("runtime state lock poisoned");
            state
                .tasks
                .get(task.arena_index())
                .is_none_or(|record| record.wake_state.notify())
        };
        if should_schedule {
            self.global.inject_timed(task, deadline);
            self.wake_one();
        }
    }

    /// Injects a task into the ready lane for cross-thread wakeup.
    ///
    /// Uses `wake_state.notify()` for centralized deduplication.
    /// If the task is already scheduled, this is a no-op.
    /// If the task record doesn't exist (e.g., in tests), allows injection.
    pub fn inject_ready(&self, task: TaskId, priority: u8) {
        let should_schedule = {
            let state = self.state.lock().expect("runtime state lock poisoned");
            state
                .tasks
                .get(task.arena_index())
                .is_none_or(|record| record.wake_state.notify())
        };
        if should_schedule {
            self.global.inject_ready(task, priority);
            self.wake_one();
        }
    }

    /// Spawns a task (shorthand for inject_ready).
    pub fn spawn(&self, task: TaskId, priority: u8) {
        // Optimistic check for local scheduler
        let scheduled_locally = CURRENT_LOCAL.with(|cell| {
            if let Some(local) = cell.borrow().as_ref() {
                // Determine if we should schedule
                let should_schedule = {
                    let state = self.state.lock().expect("runtime state lock poisoned");
                    state
                        .tasks
                        .get(task.arena_index())
                        .is_none_or(|record| record.wake_state.notify())
                };

                if should_schedule {
                    let mut guard = local.lock().expect("local scheduler lock poisoned");
                    guard.schedule(task, priority);
                }
                return true;
            }
            false
        });

        if !scheduled_locally {
            self.inject_ready(task, priority);
        }
    }

    /// Wakes a task by injecting it into the ready lane.
    ///
    /// For cancel wakeups, use `inject_cancel` instead.
    pub fn wake(&self, task: TaskId, priority: u8) {
        self.inject_ready(task, priority);
    }

    /// Wakes one idle worker.
    fn wake_one(&self) {
        let count = self.parkers.len();
        if count == 0 {
            return;
        }

        let idx = self.next_wake.fetch_add(1, Ordering::Relaxed);
        self.parkers[idx % count].unpark();
    }

    /// Wakes all idle workers.
    pub fn wake_all(&self) {
        for parker in &self.parkers {
            parker.unpark();
        }
    }

    /// Extract workers to run them in threads.
    pub fn take_workers(&mut self) -> Vec<ThreeLaneWorker> {
        std::mem::take(&mut self.workers)
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

/// A worker thread for the 3-lane scheduler.
#[derive(Debug)]
pub struct ThreeLaneWorker {
    /// Unique worker ID.
    pub id: WorkerId,
    /// Local 3-lane scheduler for this worker.
    pub local: Arc<Mutex<PriorityScheduler>>,
    /// References to other workers' local schedulers for stealing.
    pub stealers: Vec<Arc<Mutex<PriorityScheduler>>>,
    /// Global injection queue.
    pub global: Arc<GlobalInjector>,
    /// Shared runtime state.
    pub state: Arc<Mutex<RuntimeState>>,
    /// Parking mechanism for idle workers.
    pub parker: Parker,
    /// Deterministic RNG for stealing decisions.
    pub rng: DetRng,
    /// Shutdown signal.
    pub shutdown: Arc<AtomicBool>,
    /// Timer driver for processing timer wakeups (optional).
    pub timer_driver: Option<TimerDriverHandle>,
    /// Scratch buffer for stolen tasks (avoid per-steal allocations).
    steal_buffer: Vec<(TaskId, u8)>,
    /// Number of consecutive cancel-lane dispatches.
    cancel_streak: usize,
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
    /// Times the cancel streak hit the fairness limit.
    pub fairness_yields: u64,
    /// Maximum cancel streak observed.
    pub max_cancel_streak: usize,
    /// Fallback cancel dispatches (after limit, no other work available).
    pub fallback_cancel_dispatches: u64,
}

impl ThreeLaneWorker {
    /// Returns the preemption fairness metrics for this worker.
    #[must_use]
    pub fn preemption_metrics(&self) -> &PreemptionMetrics {
        &self.preemption_metrics
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

        const SPIN_LIMIT: u32 = 64;
        const YIELD_LIMIT: u32 = 16;

        while !self.shutdown.load(Ordering::Acquire) {
            if let Some(task) = self.next_task() {
                self.execute(task);
                continue;
            }

            // PHASE 5: Backoff before parking
            let mut backoff = 0;

            loop {
                // Check shutdown before parking to avoid hanging in the backoff loop.
                if self.shutdown.load(Ordering::Acquire) {
                    break;
                }

                // Quick check for new work in both global and local queues.
                // Previously only checked global, causing unnecessary spinning when
                // local queue had work.
                let local_has_work = self
                    .local
                    .lock()
                    .map(|local| !local.is_empty())
                    .unwrap_or(false);
                if !self.global.is_empty() || local_has_work {
                    break;
                }

                if backoff < SPIN_LIMIT {
                    std::hint::spin_loop();
                    backoff += 1;
                } else if backoff < SPIN_LIMIT + YIELD_LIMIT {
                    std::thread::yield_now();
                    backoff += 1;
                } else {
                    // Park with timeout based on next timer deadline
                    if let Some(timer) = &self.timer_driver {
                        if let Some(next_deadline) = timer.next_deadline() {
                            let now = timer.now();
                            if next_deadline > now {
                                let nanos = next_deadline.duration_since(now);
                                self.parker.park_timeout(Duration::from_nanos(nanos));
                            }
                            // If deadline is due or passed, don't park - loop back to process timers
                        } else {
                            // No pending timers, park indefinitely
                            self.parker.park();
                        }
                    } else {
                        // No timer driver, park indefinitely
                        self.parker.park();
                    }
                    // After waking, re-check queues by continuing the loop.
                    // This fixes a lost-wakeup race where work arrives right as we park.
                    // Reset backoff to spin briefly before parking again (spurious wakeups).
                    backoff = 0;
                    // Continue loop to re-check condition (no break!)
                }
            }

            // After backoff/park, reset the consecutive cancel counter.
            // We've given other work a chance during the backoff period.
            self.cancel_streak = 0;
        }
    }

    /// Select the next task to dispatch, respecting lane priorities and fairness.
    ///
    /// Returns `None` when no work is available across any lane or steal target.
    pub fn next_task(&mut self) -> Option<TaskId> {
        // PHASE 0: Process expired timers (fires wakers, which may inject tasks)
        if let Some(timer) = &self.timer_driver {
            let _ = timer.process_timers();
        }

        // Consult the governor for scheduling suggestion (amortized).
        let suggestion = self.governor_suggest();

        match suggestion {
            SchedulingSuggestion::MeetDeadlines => {
                // Deadline pressure dominates: check timed lane first.
                if let Some(task) = self.try_timed_work() {
                    self.cancel_streak = 0;
                    self.preemption_metrics.timed_dispatches += 1;
                    return Some(task);
                }
                // Then cancel work with standard fairness.
                if self.cancel_streak < self.cancel_streak_limit {
                    if let Some(task) = self.try_cancel_work() {
                        self.cancel_streak += 1;
                        self.record_cancel_dispatch();
                        return Some(task);
                    }
                    self.cancel_streak = 0;
                } else {
                    self.preemption_metrics.fairness_yields += 1;
                }
            }
            SchedulingSuggestion::DrainObligations | SchedulingSuggestion::DrainRegions => {
                // Obligation/region drain dominates: allow longer cancel streaks
                // to accelerate cleanup convergence.
                let boosted_limit = self.cancel_streak_limit.saturating_mul(2);
                if self.cancel_streak < boosted_limit {
                    if let Some(task) = self.try_cancel_work() {
                        self.cancel_streak += 1;
                        self.record_cancel_dispatch();
                        return Some(task);
                    }
                    self.cancel_streak = 0;
                } else {
                    self.preemption_metrics.fairness_yields += 1;
                }
                // Timed work (still respect EDF).
                if let Some(task) = self.try_timed_work() {
                    self.cancel_streak = 0;
                    self.preemption_metrics.timed_dispatches += 1;
                    return Some(task);
                }
            }
            SchedulingSuggestion::NoPreference => {
                // Default lane ordering: cancel > timed > ready.
                if self.cancel_streak < self.cancel_streak_limit {
                    if let Some(task) = self.try_cancel_work() {
                        self.cancel_streak += 1;
                        self.record_cancel_dispatch();
                        return Some(task);
                    }
                    self.cancel_streak = 0;
                } else {
                    self.preemption_metrics.fairness_yields += 1;
                }
                if let Some(task) = self.try_timed_work() {
                    self.cancel_streak = 0;
                    self.preemption_metrics.timed_dispatches += 1;
                    return Some(task);
                }
            }
        }

        // Ready work (always checked regardless of suggestion).
        if let Some(task) = self.try_ready_work() {
            self.cancel_streak = 0;
            self.preemption_metrics.ready_dispatches += 1;
            return Some(task);
        }

        // Steal from other workers.
        if let Some(task) = self.try_steal() {
            self.cancel_streak = 0;
            self.preemption_metrics.ready_dispatches += 1;
            return Some(task);
        }

        // If we hit the fairness limit but no other lanes had work, allow cancel.
        let effective_limit = match suggestion {
            SchedulingSuggestion::DrainObligations | SchedulingSuggestion::DrainRegions => {
                self.cancel_streak_limit.saturating_mul(2)
            }
            _ => self.cancel_streak_limit,
        };
        if self.cancel_streak >= effective_limit {
            if let Some(task) = self.try_cancel_work() {
                // Fallback: no ready work available, so dispatch another cancel.
                // Don't extend the streak peak — the limit bounds the maximum
                // consecutive cancel dispatches before a fairness yield.
                self.preemption_metrics.cancel_dispatches += 1;
                self.preemption_metrics.fallback_cancel_dispatches += 1;
                self.cancel_streak = 0;
                return Some(task);
            }
            self.cancel_streak = 0;
        }

        None
    }

    /// Record a cancel dispatch and update max streak metric.
    #[inline]
    fn record_cancel_dispatch(&mut self) {
        self.preemption_metrics.cancel_dispatches += 1;
        if self.cancel_streak > self.preemption_metrics.max_cancel_streak {
            self.preemption_metrics.max_cancel_streak = self.cancel_streak;
        }
    }

    /// Consult the governor for a scheduling suggestion, taking a fresh
    /// snapshot every `governor_interval` steps. When the governor is
    /// disabled, always returns `NoPreference`.
    fn governor_suggest(&mut self) -> SchedulingSuggestion {
        let Some(governor) = &self.governor else {
            return SchedulingSuggestion::NoPreference;
        };

        self.steps_since_snapshot += 1;
        if self.steps_since_snapshot < self.governor_interval {
            return self.cached_suggestion;
        }
        self.steps_since_snapshot = 0;

        // Take a snapshot under the state lock (bounded work, no allocs).
        let snapshot = {
            let state = self.state.lock().expect("runtime state lock poisoned");
            StateSnapshot::from_runtime_state(&state)
        };

        // Enrich with local queue depth.
        let queue_depth = self.local.lock().map(|local| local.len()).unwrap_or(0);
        #[allow(clippy::cast_possible_truncation)]
        let snapshot = snapshot.with_ready_queue_depth(queue_depth as u32);

        let suggestion = governor.suggest(&snapshot);
        self.cached_suggestion = suggestion;
        suggestion
    }

    /// Runs a single scheduling step.
    ///
    /// Returns `true` if a task was executed.
    pub fn run_once(&mut self) -> bool {
        if self.shutdown.load(Ordering::Acquire) {
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
        let mut local = self.local.lock().expect("local scheduler lock poisoned");
        let rng_hint = self.rng.next_u64();
        local.pop_cancel_only_with_hint(rng_hint)
    }

    /// Tries to get timed work from global or local queues.
    ///
    /// Uses EDF (Earliest Deadline First) ordering. Only returns tasks
    /// whose deadline has passed.
    pub(crate) fn try_timed_work(&mut self) -> Option<TaskId> {
        // Get current time from timer driver or use Time::ZERO (always ready)
        let now = self
            .timer_driver
            .as_ref()
            .map_or(Time::ZERO, TimerDriverHandle::now);

        // Global timed - EDF ordering, only pop if deadline is due
        if let Some(tt) = self.global.pop_timed_if_due(now) {
            return Some(tt.task);
        }

        // Local timed (already EDF ordered)
        let mut local = self.local.lock().expect("local scheduler lock poisoned");
        let rng_hint = self.rng.next_u64();
        local.pop_timed_only_with_hint(rng_hint, now)
    }

    /// Tries to get ready work from global or local queues.
    pub(crate) fn try_ready_work(&mut self) -> Option<TaskId> {
        // Global ready
        if let Some(pt) = self.global.pop_ready() {
            return Some(pt.task);
        }

        // Local ready
        let mut local = self.local.lock().expect("local scheduler lock poisoned");
        let rng_hint = self.rng.next_u64();
        local.pop_ready_only_with_hint(rng_hint)
    }

    /// Tries to steal work from other workers.
    ///
    /// Only steals from ready lanes to preserve cancel/timed priority semantics.
    pub(crate) fn try_steal(&mut self) -> Option<TaskId> {
        if self.stealers.is_empty() {
            return None;
        }

        let len = self.stealers.len();
        let start = self.rng.next_usize(len);

        for i in 0..len {
            let idx = (start + i) % len;
            let stealer = &self.stealers[idx];

            // Try to lock without blocking (skip if contended)
            if let Ok(mut victim) = stealer.try_lock() {
                let stolen_count = victim.steal_ready_batch_into(4, &mut self.steal_buffer);
                if stolen_count > 0 {
                    // Take the first task to execute
                    let (first_task, _) = self.steal_buffer[0];

                    // Push remaining stolen tasks to our local queue
                    if stolen_count > 1 {
                        let mut local = self.local.lock().expect("local scheduler lock poisoned");
                        for &(task, priority) in self.steal_buffer.iter().skip(1) {
                            local.schedule(task, priority);
                        }
                    }

                    return Some(first_task);
                }
            }
        }

        None
    }

    /// Schedules a task locally in the appropriate lane.
    ///
    /// Uses `wake_state.notify()` for centralized deduplication.
    /// If the task is already scheduled, this is a no-op.
    /// If the task record doesn't exist (e.g., in tests), allows scheduling.
    pub fn schedule_local(&self, task: TaskId, priority: u8) {
        let should_schedule = {
            let state = self.state.lock().expect("runtime state lock poisoned");
            state
                .tasks
                .get(task.arena_index())
                .is_none_or(|record| record.wake_state.notify())
        };
        if should_schedule {
            let mut local = self.local.lock().expect("local scheduler lock poisoned");
            local.schedule(task, priority);
        }
    }

    /// Schedules a cancelled task locally.
    ///
    /// Uses `wake_state.notify()` for centralized deduplication.
    /// If the task is already scheduled, this is a no-op.
    /// If the task record doesn't exist (e.g., in tests), allows scheduling.
    pub fn schedule_local_cancel(&self, task: TaskId, priority: u8) {
        let should_schedule = {
            let state = self.state.lock().expect("runtime state lock poisoned");
            state
                .tasks
                .get(task.arena_index())
                .is_none_or(|record| record.wake_state.notify())
        };
        if should_schedule {
            let mut local = self.local.lock().expect("local scheduler lock poisoned");
            local.schedule_cancel(task, priority);
        }
    }

    /// Schedules a timed task locally.
    ///
    /// Uses `wake_state.notify()` for centralized deduplication.
    /// If the task is already scheduled, this is a no-op.
    /// If the task record doesn't exist (e.g., in tests), allows scheduling.
    pub fn schedule_local_timed(&self, task: TaskId, deadline: Time) {
        let should_schedule = {
            let state = self.state.lock().expect("runtime state lock poisoned");
            state
                .tasks
                .get(task.arena_index())
                .is_none_or(|record| record.wake_state.notify())
        };
        if should_schedule {
            let mut local = self.local.lock().expect("local scheduler lock poisoned");
            local.schedule_timed(task, deadline);
        }
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn execute(&self, task_id: TaskId) {
        trace!(task_id = ?task_id, worker_id = self.id, "executing task");

        let (
            mut stored,
            task_cx,
            wake_state,
            priority,
            cx_inner,
            cached_waker,
            cached_cancel_waker,
        ) = {
            let stored = {
                let mut state = self.state.lock().expect("runtime state lock poisoned");

                // Try global storage first.
                state.remove_stored_future(task_id).map_or_else(
                    || {
                        // Try local storage.
                        drop(state); // Drop lock to access TLS
                        let local = crate::runtime::local::remove_local_task(task_id);
                        local.map(AnyStoredTask::Local)
                    },
                    |stored| Some(AnyStoredTask::Global(stored)),
                )
            };

            let Some(stored) = stored else {
                return;
            };

            let mut state = self.state.lock().expect("runtime state lock poisoned");

            let Some(record) = state.tasks.get_mut(task_id.arena_index()) else {
                return;
            };
            record.start_running();
            record.wake_state.begin_poll();
            let priority = record
                .cx_inner
                .as_ref()
                .and_then(|inner| inner.read().ok().map(|cx| cx.budget.priority))
                .unwrap_or(0);
            let task_cx = record.cx.clone();
            let cx_inner = record.cx_inner.clone();
            let wake_state = Arc::clone(&record.wake_state);
            // Take cached wakers to avoid holding the lock during poll
            let cached_waker = record.cached_waker.take();
            let cached_cancel_waker = record.cached_cancel_waker.take();
            drop(state);
            (
                stored,
                task_cx,
                wake_state,
                priority,
                cx_inner,
                cached_waker,
                cached_cancel_waker,
            )
        };

        let is_local = matches!(stored, AnyStoredTask::Local(_));

        // Reuse cached waker if priority hasn't changed, otherwise allocate new one
        let waker = match cached_waker {
            Some((w, cached_priority)) if cached_priority == priority => w,
            _ => {
                if is_local {
                    Waker::from(Arc::new(ThreeLaneLocalWaker {
                        task_id,
                        priority,
                        wake_state: Arc::clone(&wake_state),
                        local: Arc::clone(&self.local),
                        parker: self.parker.clone(),
                    }))
                } else {
                    Waker::from(Arc::new(ThreeLaneWaker {
                        task_id,
                        priority,
                        wake_state: Arc::clone(&wake_state),
                        global: Arc::clone(&self.global),
                        parker: self.parker.clone(),
                    }))
                }
            }
        };
        // Create/reuse cancel waker if cx_inner exists
        let cancel_waker_for_cache = cx_inner.as_ref().map_or_else(
            || None,
            |inner| {
                let cancel_waker = match cached_cancel_waker {
                    Some((w, cached_priority)) if cached_priority == priority => w,
                    _ => {
                        if is_local {
                            Waker::from(Arc::new(ThreeLaneLocalCancelWaker {
                                task_id,
                                default_priority: priority,
                                wake_state: Arc::clone(&wake_state),
                                local: Arc::clone(&self.local),
                                parker: self.parker.clone(),
                                cx_inner: Arc::downgrade(inner),
                            }))
                        } else {
                            Waker::from(Arc::new(CancelLaneWaker {
                                task_id,
                                default_priority: priority,
                                wake_state: Arc::clone(&wake_state),
                                global: Arc::clone(&self.global),
                                parker: self.parker.clone(),
                                cx_inner: Arc::downgrade(inner),
                            }))
                        }
                    }
                };
                if let Ok(mut guard) = inner.write() {
                    guard.cancel_waker = Some(cancel_waker.clone());
                }
                Some((cancel_waker, priority))
            },
        );
        let mut cx = Context::from_waker(&waker);
        let _cx_guard = crate::cx::Cx::set_current(task_cx);

        match stored.poll(&mut cx) {
            Poll::Ready(outcome) => {
                // Map Outcome<(), ()> to Outcome<(), Error> for record.complete()
                let task_outcome = outcome
                    .map_err(|()| crate::error::Error::new(crate::error::ErrorKind::Internal));
                let mut state = self.state.lock().expect("runtime state lock poisoned");
                if let Some(record) = state.tasks.get_mut(task_id.arena_index()) {
                    if !record.state.is_terminal() {
                        record.complete(task_outcome);
                    }
                }

                let waiters = state.task_completed(task_id);
                for waiter in waiters {
                    if let Some(record) = state.tasks.get(waiter.arena_index()) {
                        let waiter_priority = record
                            .cx_inner
                            .as_ref()
                            .and_then(|inner| inner.read().ok().map(|cx| cx.budget.priority))
                            .unwrap_or(0);
                        if record.wake_state.notify() {
                            // Waiters are always ready tasks.
                            // NOTE: If we had local waiters, we'd need to know where to schedule them.
                            // Currently we assume waiters are global or cross-thread wakeable.
                            // If a waiter is local, injecting to global might be wrong!
                            // But `task_completed` doesn't know about waiter locality.
                            // This is a limitation: local tasks waiting on other tasks might be
                            // woken globally.
                            // For now, consistent with Phase 1 Global Injector design for cross-task wakes.
                            self.global.inject_ready(waiter, waiter_priority);
                            self.parker.unpark();
                        }
                    }
                }
                drop(state);
                wake_state.clear();
            }
            Poll::Pending => {
                // Store task back
                match stored {
                    AnyStoredTask::Global(t) => {
                        let mut state = self.state.lock().expect("runtime state lock poisoned");
                        state.store_spawned_task(task_id, t);
                        // Cache wakers back in the task record for reuse on next poll
                        if let Some(record) = state.tasks.get_mut(task_id.arena_index()) {
                            record.cached_waker = Some((waker, priority));
                            record.cached_cancel_waker = cancel_waker_for_cache;
                        }
                    }
                    AnyStoredTask::Local(t) => {
                        crate::runtime::local::store_local_task(task_id, t);
                        // For local tasks, we also want to cache wakers in the global record
                        // (since record is global).
                        let mut state = self.state.lock().expect("runtime state lock poisoned");
                        if let Some(record) = state.tasks.get_mut(task_id.arena_index()) {
                            record.cached_waker = Some((waker, priority));
                            record.cached_cancel_waker = cancel_waker_for_cache;
                        }
                    }
                }

                if wake_state.finish_poll() {
                    let mut cancel_priority = priority;
                    let mut schedule_cancel = false;
                    if let Some(inner) = cx_inner.as_ref() {
                        if let Ok(guard) = inner.read() {
                            if guard.cancel_requested {
                                schedule_cancel = true;
                                if let Some(reason) = guard.cancel_reason.as_ref() {
                                    cancel_priority = reason.cleanup_budget().priority;
                                }
                            }
                        }
                    }

                    if is_local {
                        // Schedule to local queue
                        let mut local = self.local.lock().expect("local scheduler lock poisoned");
                        if schedule_cancel {
                            local.schedule_cancel(task_id, cancel_priority);
                        } else {
                            local.schedule(task_id, priority);
                        }
                    } else {
                        // Schedule to global injector
                        if schedule_cancel {
                            self.global.inject_cancel(task_id, cancel_priority);
                        } else {
                            self.global.inject_ready(task_id, priority);
                        }
                    }
                    self.parker.unpark();
                }
            }
        }
    }
}

struct ThreeLaneWaker {
    task_id: TaskId,
    priority: u8,
    wake_state: Arc<crate::record::task::TaskWakeState>,
    global: Arc<GlobalInjector>,
    parker: Parker,
}

impl ThreeLaneWaker {
    fn schedule(&self) {
        if self.wake_state.notify() {
            self.global.inject_ready(self.task_id, self.priority);
            self.parker.unpark();
        }
    }
}

impl Wake for ThreeLaneWaker {
    fn wake(self: Arc<Self>) {
        self.schedule();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.schedule();
    }
}

struct ThreeLaneLocalWaker {
    task_id: TaskId,
    priority: u8,
    wake_state: Arc<crate::record::task::TaskWakeState>,
    local: Arc<Mutex<PriorityScheduler>>,
    parker: Parker,
}

impl ThreeLaneLocalWaker {
    fn schedule(&self) {
        if self.wake_state.notify() {
            {
                let mut local = self.local.lock().expect("local scheduler lock poisoned");
                local.schedule(self.task_id, self.priority);
            }
            self.parker.unpark();
        }
    }
}

impl Wake for ThreeLaneLocalWaker {
    fn wake(self: Arc<Self>) {
        self.schedule();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.schedule();
    }
}

struct CancelLaneWaker {
    task_id: TaskId,
    default_priority: u8,
    wake_state: Arc<crate::record::task::TaskWakeState>,
    global: Arc<GlobalInjector>,
    parker: Parker,
    cx_inner: Weak<RwLock<CxInner>>,
}

impl CancelLaneWaker {
    fn schedule(&self) {
        let Some(inner) = self.cx_inner.upgrade() else {
            return;
        };
        let (cancel_requested, priority) = match inner.read() {
            Ok(guard) => {
                let priority = guard
                    .cancel_reason
                    .as_ref()
                    .map_or(self.default_priority, |reason| {
                        reason.cleanup_budget().priority
                    });
                (guard.cancel_requested, priority)
            }
            Err(_) => return,
        };

        if !cancel_requested {
            return;
        }

        // Always notify (attempt state transition)
        self.wake_state.notify();

        // Always inject to ensure priority promotion, even if already scheduled.
        // See `inject_cancel` for details.
        self.global.inject_cancel(self.task_id, priority);
        self.parker.unpark();
    }
}

impl Wake for CancelLaneWaker {
    fn wake(self: Arc<Self>) {
        self.schedule();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.schedule();
    }
}

struct ThreeLaneLocalCancelWaker {
    task_id: TaskId,
    default_priority: u8,
    wake_state: Arc<crate::record::task::TaskWakeState>,
    local: Arc<Mutex<PriorityScheduler>>,
    parker: Parker,
    cx_inner: Weak<RwLock<CxInner>>,
}

impl ThreeLaneLocalCancelWaker {
    fn schedule(&self) {
        let Some(inner) = self.cx_inner.upgrade() else {
            return;
        };
        let (cancel_requested, priority) = match inner.read() {
            Ok(guard) => {
                let priority = guard
                    .cancel_reason
                    .as_ref()
                    .map_or(self.default_priority, |reason| {
                        reason.cleanup_budget().priority
                    });
                (guard.cancel_requested, priority)
            }
            Err(_) => return,
        };

        if !cancel_requested {
            return;
        }

        // Always notify
        self.wake_state.notify();

        // Inject to local cancel lane
        {
            let mut local = self.local.lock().expect("local scheduler lock poisoned");
            local.schedule_cancel(self.task_id, priority);
        }
        self.parker.unpark();
    }
}

impl Wake for ThreeLaneLocalCancelWaker {
    fn wake(self: Arc<Self>) {
        self.schedule();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.schedule();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Budget, CancelReason, RegionId};
    use std::time::Duration;

    #[test]
    fn test_three_lane_scheduler_creation() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let scheduler = ThreeLaneScheduler::new(2, &state);

        assert!(!scheduler.is_shutdown());
        assert_eq!(scheduler.workers.len(), 2);
    }

    #[test]
    fn test_three_lane_worker_shutdown() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(2, &state);

        let workers = scheduler.take_workers();
        assert_eq!(workers.len(), 2);

        // Spawn threads for workers
        let handles: Vec<_> = workers
            .into_iter()
            .map(|mut worker| {
                std::thread::spawn(move || {
                    worker.run_loop();
                })
            })
            .collect();

        // Let them run briefly
        std::thread::sleep(Duration::from_millis(10));

        // Signal shutdown
        scheduler.shutdown();

        // Join threads
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_cancel_priority_over_ready() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(1, &state);

        // Inject ready first, then cancel
        scheduler.inject_ready(TaskId::new_for_test(1, 1), 100);
        scheduler.inject_cancel(TaskId::new_for_test(1, 2), 50);

        // Worker should get cancel first
        let mut workers = scheduler.take_workers().into_iter();
        let mut worker = workers.next().unwrap();

        // Cancel should come first
        let task1 = worker.try_cancel_work();
        assert!(task1.is_some());
        assert_eq!(task1.unwrap(), TaskId::new_for_test(1, 2));

        // Ready should come after
        let task2 = worker.try_ready_work();
        assert!(task2.is_some());
        assert_eq!(task2.unwrap(), TaskId::new_for_test(1, 1));
    }

    #[test]
    fn test_cancel_lane_fairness_limit() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 2);

        let cancel_tasks = [
            TaskId::new_for_test(1, 1),
            TaskId::new_for_test(1, 2),
            TaskId::new_for_test(1, 3),
        ];
        let ready_task = TaskId::new_for_test(1, 4);

        for &task_id in &cancel_tasks {
            scheduler.inject_cancel(task_id, 100);
        }
        scheduler.inject_ready(ready_task, 50);

        let mut workers = scheduler.take_workers().into_iter();
        let mut worker = workers.next().unwrap();

        let first = worker.next_task().expect("first dispatch");
        let second = worker.next_task().expect("second dispatch");
        let third = worker.next_task().expect("third dispatch");
        let fourth = worker.next_task().expect("fourth dispatch");

        assert!(cancel_tasks.contains(&first));
        assert!(cancel_tasks.contains(&second));
        assert_eq!(third, ready_task);
        assert!(cancel_tasks.contains(&fourth));
    }

    #[test]
    fn test_stealing_only_from_ready_lane() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(2, &state);

        // Add cancel and ready work to worker 0's local queue
        {
            let workers = &scheduler.workers;
            let mut local0 = workers[0].local.lock().unwrap();
            local0.schedule_cancel(TaskId::new_for_test(1, 1), 100);
            local0.schedule(TaskId::new_for_test(1, 2), 50);
            local0.schedule(TaskId::new_for_test(1, 3), 50);
        }

        // Worker 1 should only be able to steal ready work
        let mut workers = scheduler.take_workers().into_iter();
        let _ = workers.next().unwrap(); // Skip worker 0
        let mut thief_worker = workers.next().unwrap();

        // Stealing should only get ready tasks
        let stolen = thief_worker.try_steal();
        assert!(stolen.is_some());

        // The stolen task should be from ready lane (2 or 3)
        let stolen_id = stolen.unwrap();
        assert!(
            stolen_id == TaskId::new_for_test(1, 2) || stolen_id == TaskId::new_for_test(1, 3),
            "Expected ready task, got cancel task"
        );
    }

    #[test]
    fn execute_completes_task_and_schedules_waiter() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let region = state
            .lock()
            .expect("runtime state lock poisoned")
            .create_root_region(Budget::INFINITE);

        let task_id = {
            let mut guard = state.lock().expect("runtime state lock poisoned");
            let (task_id, _handle) = guard
                .create_task(region, Budget::INFINITE, async {})
                .expect("create task");
            task_id
        };
        let waiter_id = {
            let mut guard = state.lock().expect("runtime state lock poisoned");
            let (waiter_id, _handle) = guard
                .create_task(region, Budget::INFINITE, async {})
                .expect("create task");
            waiter_id
        };

        {
            let mut guard = state.lock().expect("runtime state lock poisoned");
            if let Some(record) = guard.tasks.get_mut(task_id.arena_index()) {
                record.add_waiter(waiter_id);
            }
        }

        let mut scheduler = ThreeLaneScheduler::new(1, &state);
        let worker = scheduler.take_workers().into_iter().next().unwrap();

        worker.execute(task_id);

        let completed = state
            .lock()
            .expect("runtime state lock poisoned")
            .tasks
            .get(task_id.arena_index())
            .is_none();
        assert!(completed, "task should be removed after completion");

        let scheduled_task = worker.global.pop_ready().map(|pt| pt.task);
        assert_eq!(scheduled_task, Some(waiter_id));
    }

    #[test]
    fn test_try_timed_work_checks_deadline() {
        use crate::time::{TimerDriverHandle, VirtualClock};

        // Create state with virtual clock timer driver
        let clock = Arc::new(VirtualClock::new());
        let mut state = RuntimeState::new();
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock.clone()));
        let state = Arc::new(Mutex::new(state));

        let mut scheduler = ThreeLaneScheduler::new(1, &state);

        // Inject a timed task with deadline at t=1000ns
        let task_id = TaskId::new_for_test(1, 1);
        let deadline = Time::from_nanos(1000);
        scheduler.inject_timed(task_id, deadline);

        let mut workers = scheduler.take_workers().into_iter();
        let mut worker = workers.next().unwrap();

        // At t=0, the task should NOT be ready (deadline not yet due)
        // try_timed_work should re-inject the task
        let result = worker.try_timed_work();
        assert!(result.is_none(), "task should not be ready before deadline");

        // Advance clock past deadline
        clock.advance(2000); // t=2000ns, past deadline of 1000ns

        // Now the task should be ready
        let result = worker.try_timed_work();
        assert_eq!(result, Some(task_id), "task should be ready after deadline");
    }

    #[test]
    fn test_worker_has_timer_driver_from_state() {
        use crate::time::{TimerDriverHandle, VirtualClock};

        // Create state with timer driver
        let clock = Arc::new(VirtualClock::new());
        let mut state = RuntimeState::new();
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock.clone()));
        let state = Arc::new(Mutex::new(state));

        let mut scheduler = ThreeLaneScheduler::new(1, &state);
        let workers = scheduler.take_workers();
        let worker = &workers[0];

        // Worker should have timer driver
        assert!(
            worker.timer_driver.is_some(),
            "worker should have timer driver from state"
        );

        // Timer driver should use the same clock
        let timer = worker.timer_driver.as_ref().unwrap();
        assert_eq!(timer.now(), Time::ZERO, "timer should start at zero");

        clock.advance(1000);
        assert_eq!(
            timer.now(),
            Time::from_nanos(1000),
            "timer should reflect clock advance"
        );
    }

    #[test]
    fn test_scheduler_timer_driver_propagates_to_workers() {
        // State without timer driver
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(2, &state);

        // Workers should not have timer driver
        let workers = scheduler.take_workers();
        assert!(workers[0].timer_driver.is_none());
        assert!(workers[1].timer_driver.is_none());

        // Scheduler should not have timer driver
        assert!(scheduler.timer_driver.is_none());
    }

    #[test]
    fn test_run_once_processes_timers() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        use std::sync::atomic::AtomicBool;
        use std::task::{Wake, Waker};

        // Waker that sets a flag when woken
        struct TestWaker(AtomicBool);
        impl Wake for TestWaker {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        // Create state with virtual clock timer driver
        let clock = Arc::new(VirtualClock::new());
        let mut state = RuntimeState::new();
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock.clone()));
        let state = Arc::new(Mutex::new(state));

        let mut scheduler = ThreeLaneScheduler::new(1, &state);

        // Get timer driver to register a timer
        let timer_driver = scheduler.timer_driver.as_ref().unwrap().clone();

        // Register a timer that expires at t=500ns
        let waker_flag = Arc::new(TestWaker(AtomicBool::new(false)));
        let waker = Waker::from(waker_flag.clone());
        let _handle = timer_driver.register(Time::from_nanos(500), waker);

        let mut workers = scheduler.take_workers().into_iter();
        let mut worker = workers.next().unwrap();

        // Timer should not be fired at t=0
        assert!(!waker_flag.0.load(Ordering::SeqCst));

        // run_once should process timers but not fire (deadline not reached)
        worker.run_once();
        assert!(
            !waker_flag.0.load(Ordering::SeqCst),
            "timer should not fire before deadline"
        );

        // Advance clock past deadline
        clock.advance(1000);

        // run_once should now fire the timer
        worker.run_once();
        assert!(
            waker_flag.0.load(Ordering::SeqCst),
            "timer should fire after deadline"
        );
    }

    #[test]
    fn test_timed_work_not_due_stays_in_queue() {
        use crate::time::{TimerDriverHandle, VirtualClock};

        // Create state with virtual clock timer driver
        let clock = Arc::new(VirtualClock::new());
        let mut state = RuntimeState::new();
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));
        let state = Arc::new(Mutex::new(state));

        let mut scheduler = ThreeLaneScheduler::new(1, &state);

        // Inject a timed task with deadline at t=1000ns
        let task_id = TaskId::new_for_test(1, 1);
        let deadline = Time::from_nanos(1000);
        scheduler.inject_timed(task_id, deadline);

        let mut workers = scheduler.take_workers().into_iter();
        let mut worker = workers.next().unwrap();

        // At t=0, task is not ready - stays in queue (not popped)
        let result = worker.try_timed_work();
        assert!(result.is_none());

        // The task should still be in the global queue (was never removed)
        let peeked = worker.global.pop_timed();
        assert!(peeked.is_some(), "task should remain in global queue");
        assert_eq!(peeked.unwrap().task, task_id);
    }

    #[test]
    fn test_edf_ordering_from_global_queue() {
        use crate::time::{TimerDriverHandle, VirtualClock};

        // Create state with virtual clock timer driver at t=1000
        let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(1000)));
        let mut state = RuntimeState::new();
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));
        let state = Arc::new(Mutex::new(state));

        let mut scheduler = ThreeLaneScheduler::new(1, &state);

        // Inject timed tasks with different deadlines (all due, since t=1000)
        let task1 = TaskId::new_for_test(1, 1);
        let task2 = TaskId::new_for_test(1, 2);
        let task3 = TaskId::new_for_test(1, 3);

        // Insert in non-deadline order
        scheduler.inject_timed(task2, Time::from_nanos(500)); // deadline 500
        scheduler.inject_timed(task3, Time::from_nanos(750)); // deadline 750
        scheduler.inject_timed(task1, Time::from_nanos(250)); // deadline 250

        let mut workers = scheduler.take_workers().into_iter();
        let mut worker = workers.next().unwrap();

        // All deadlines are due (t=1000), so should be returned in EDF order
        let first = worker.try_timed_work();
        assert_eq!(
            first,
            Some(task1),
            "earliest deadline (250) should be first"
        );

        let second = worker.try_timed_work();
        assert_eq!(
            second,
            Some(task2),
            "second earliest deadline (500) should be second"
        );

        let third = worker.try_timed_work();
        assert_eq!(
            third,
            Some(task3),
            "third earliest deadline (750) should be third"
        );
    }

    #[test]
    fn test_starvation_avoidance_ready_with_timed() {
        use crate::time::{TimerDriverHandle, VirtualClock};

        // Create state with virtual clock at t=0
        let clock = Arc::new(VirtualClock::new());
        let mut state = RuntimeState::new();
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));
        let state = Arc::new(Mutex::new(state));

        let mut scheduler = ThreeLaneScheduler::new(1, &state);

        // Inject a ready task
        let ready_task = TaskId::new_for_test(1, 1);
        scheduler.inject_ready(ready_task, 100);

        // Inject a timed task with future deadline
        let timed_task = TaskId::new_for_test(1, 2);
        scheduler.inject_timed(timed_task, Time::from_nanos(1000));

        let mut workers = scheduler.take_workers().into_iter();
        let mut worker = workers.next().unwrap();

        // Timed task has future deadline, so should not be returned
        assert!(worker.try_timed_work().is_none());

        // Ready task should be available
        assert_eq!(worker.try_ready_work(), Some(ready_task));
    }

    #[test]
    fn test_cancel_priority_over_timed() {
        use crate::time::{TimerDriverHandle, VirtualClock};

        // Create state with virtual clock at t=1000 (both tasks due)
        let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(1000)));
        let mut state = RuntimeState::new();
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));
        let state = Arc::new(Mutex::new(state));

        let mut scheduler = ThreeLaneScheduler::new(1, &state);

        // Inject a timed task
        let timed_task = TaskId::new_for_test(1, 1);
        scheduler.inject_timed(timed_task, Time::from_nanos(500));

        // Inject a cancel task (lower priority number, but cancel lane has priority)
        let cancel_task = TaskId::new_for_test(1, 2);
        scheduler.inject_cancel(cancel_task, 50);

        let mut workers = scheduler.take_workers().into_iter();
        let mut worker = workers.next().unwrap();

        // Cancel work should come before timed work
        assert_eq!(worker.try_cancel_work(), Some(cancel_task));

        // Then timed work
        assert_eq!(worker.try_timed_work(), Some(timed_task));
    }

    #[test]
    fn cancel_waker_injects_cancel_lane() {
        let task_id = TaskId::new_for_test(1, 1);
        let cx_inner = Arc::new(RwLock::new(CxInner::new(
            RegionId::new_for_test(1, 0),
            task_id,
            Budget::INFINITE,
        )));
        {
            let mut guard = cx_inner.write().expect("lock poisoned");
            guard.cancel_requested = true;
            guard.cancel_reason = Some(CancelReason::timeout());
        }

        let wake_state = Arc::new(crate::record::task::TaskWakeState::new());
        let global = Arc::new(GlobalInjector::new());
        let parker = Parker::new();
        let waker = Waker::from(Arc::new(CancelLaneWaker {
            task_id,
            default_priority: Budget::INFINITE.priority,
            wake_state,
            global: Arc::clone(&global),
            parker,
            cx_inner: Arc::downgrade(&cx_inner),
        }));

        waker.wake_by_ref();

        let task = global.pop_cancel().map(|pt| pt.task);
        assert_eq!(task, Some(task_id));
    }

    // ========== Deduplication Tests (bd-35f9) ==========

    #[test]
    fn test_inject_ready_dedup_prevents_double_schedule() {
        // Create state with a real task record
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let region = state
            .lock()
            .expect("runtime state lock poisoned")
            .create_root_region(Budget::INFINITE);

        let task_id = {
            let mut guard = state.lock().expect("runtime state lock poisoned");
            let (task_id, _handle) = guard
                .create_task(region, Budget::INFINITE, async {})
                .expect("create task");
            task_id
        };

        let scheduler = ThreeLaneScheduler::new(1, &state);

        // First inject should succeed
        scheduler.inject_ready(task_id, 100);
        assert!(
            scheduler.global.has_ready_work(),
            "first inject should add to queue"
        );

        // Second inject should be deduplicated (same task)
        scheduler.inject_ready(task_id, 100);

        // Pop first - should succeed
        let first = scheduler.global.pop_ready();
        assert!(first.is_some(), "first pop should succeed");
        assert_eq!(first.unwrap().task, task_id);

        // Second pop should fail - task was deduplicated
        let second = scheduler.global.pop_ready();
        assert!(second.is_none(), "second pop should fail (deduplicated)");
    }

    #[test]
    fn test_inject_cancel_allows_duplicates_for_priority() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let region = state
            .lock()
            .expect("runtime state lock poisoned")
            .create_root_region(Budget::INFINITE);

        let task_id = {
            let mut guard = state.lock().expect("runtime state lock poisoned");
            let (task_id, _handle) = guard
                .create_task(region, Budget::INFINITE, async {})
                .expect("create task");
            task_id
        };

        let scheduler = ThreeLaneScheduler::new(1, &state);

        // First inject to cancel lane
        scheduler.inject_cancel(task_id, 100);
        assert!(scheduler.global.has_cancel_work());

        // Second inject should NOT be deduplicated (to ensure priority promotion)
        scheduler.inject_cancel(task_id, 100);

        // Both should be in queue
        let first = scheduler.global.pop_cancel();
        assert!(first.is_some());
        let second = scheduler.global.pop_cancel();
        assert!(second.is_some(), "cancel inject always injects");

        // Third check should be empty
        let third = scheduler.global.pop_cancel();
        assert!(third.is_none());
    }

    #[test]
    fn test_inject_cancel_promotes_ready_task() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let region = state
            .lock()
            .expect("runtime state lock poisoned")
            .create_root_region(Budget::INFINITE);

        let task_id = {
            let mut guard = state.lock().expect("runtime state lock poisoned");
            let (task_id, _handle) = guard
                .create_task(region, Budget::INFINITE, async {})
                .expect("create task");
            task_id
        };

        let scheduler = ThreeLaneScheduler::new(1, &state);

        // 1. Schedule task in Ready Lane
        scheduler.inject_ready(task_id, 50);
        assert!(scheduler.global.has_ready_work());
        assert!(!scheduler.global.has_cancel_work());

        // 2. Inject cancel for same task
        // Expected: Should be promoted to Cancel Lane
        scheduler.inject_cancel(task_id, 100);

        // 3. Verify it is now in Cancel Lane (possibly in addition to Ready Lane)
        assert!(
            scheduler.global.has_cancel_work(),
            "Task should be promoted to cancel lane"
        );
    }

    #[test]
    fn test_schedule_local_dedup_prevents_double_schedule() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let region = state
            .lock()
            .expect("runtime state lock poisoned")
            .create_root_region(Budget::INFINITE);

        let task_id = {
            let mut guard = state.lock().expect("runtime state lock poisoned");
            let (task_id, _handle) = guard
                .create_task(region, Budget::INFINITE, async {})
                .expect("create task");
            task_id
        };

        let mut scheduler = ThreeLaneScheduler::new(1, &state);
        let workers = scheduler.take_workers();
        let worker = &workers[0];

        // First schedule to local
        worker.schedule_local(task_id, 100);

        // Second schedule should be deduplicated
        worker.schedule_local(task_id, 100);

        // Check local queue has only one entry
        let count = {
            let local = worker.local.lock().expect("local lock poisoned");
            local.len()
        };
        assert_eq!(count, 1, "should have exactly 1 task, not {count}");
    }

    #[test]
    fn test_local_then_global_dedup() {
        // Test: schedule locally first, then try to inject globally
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let region = state
            .lock()
            .expect("runtime state lock poisoned")
            .create_root_region(Budget::INFINITE);

        let task_id = {
            let mut guard = state.lock().expect("runtime state lock poisoned");
            let (task_id, _handle) = guard
                .create_task(region, Budget::INFINITE, async {})
                .expect("create task");
            task_id
        };

        let mut scheduler = ThreeLaneScheduler::new(1, &state);
        let workers = scheduler.take_workers();
        let worker = &workers[0];

        // Schedule locally first (consumes the notify)
        worker.schedule_local(task_id, 100);

        // Now try global inject - should be deduplicated
        scheduler.global.inject_ready(task_id, 100);
        // Note: We're injecting directly to global to simulate the race

        // But since wake_state was consumed by local, subsequent inject
        // via the scheduler method would be blocked
        // The task is only in local queue
        let local_len = {
            let local = worker.local.lock().expect("local lock poisoned");
            local.len()
        };
        assert_eq!(local_len, 1);
    }

    #[test]
    fn test_multiple_wakes_single_schedule() {
        // Simulate the ThreeLaneWaker behavior
        let task_id = TaskId::new_for_test(1, 1);
        let wake_state = Arc::new(crate::record::task::TaskWakeState::new());
        let global = Arc::new(GlobalInjector::new());
        let parker = Parker::new();

        // Create multiple wakers (simulating cloned wakers)
        let wakers: Vec<_> = (0..10)
            .map(|_| {
                Waker::from(Arc::new(ThreeLaneWaker {
                    task_id,
                    priority: 100,
                    wake_state: Arc::clone(&wake_state),
                    global: Arc::clone(&global),
                    parker: parker.clone(),
                }))
            })
            .collect();

        // Wake all 10 wakers
        for waker in &wakers {
            waker.wake_by_ref();
        }

        // Only one task should be in the queue
        let first = global.pop_ready();
        assert!(first.is_some(), "at least one wake should succeed");

        let second = global.pop_ready();
        assert!(
            second.is_none(),
            "only one wake should succeed, dedup should prevent duplicates"
        );
    }

    #[test]
    fn test_wake_state_cleared_allows_reschedule() {
        // After task completes, wake_state is cleared, allowing new schedule
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let region = state
            .lock()
            .expect("runtime state lock poisoned")
            .create_root_region(Budget::INFINITE);

        let task_id = {
            let mut guard = state.lock().expect("runtime state lock poisoned");
            let (task_id, _handle) = guard
                .create_task(region, Budget::INFINITE, async {})
                .expect("create task");
            task_id
        };

        // Get the wake_state for direct manipulation
        let wake_state = {
            let guard = state.lock().expect("runtime state lock poisoned");
            guard
                .tasks
                .get(task_id.arena_index())
                .map(|r| Arc::clone(&r.wake_state))
                .expect("task should exist")
        };

        let scheduler = ThreeLaneScheduler::new(1, &state);

        // First schedule
        scheduler.inject_ready(task_id, 100);
        let first = scheduler.global.pop_ready();
        assert!(first.is_some());

        // Clear wake state (simulating task completion)
        wake_state.clear();

        // Now should be able to schedule again
        scheduler.inject_ready(task_id, 100);
        let second = scheduler.global.pop_ready();
        assert!(second.is_some(), "should be able to reschedule after clear");
    }

    // ========== Stress Tests ==========
    // These tests are marked #[ignore] for CI and should be run manually.

    #[test]
    #[ignore = "stress test; run manually"]
    fn stress_test_parker_high_contention() {
        use crate::runtime::scheduler::worker::Parker;
        use std::sync::atomic::AtomicUsize;
        use std::thread;

        // 50 threads, 1000 park/unpark cycles each
        let parker = Arc::new(Parker::new());
        let successful_wakes = Arc::new(AtomicUsize::new(0));
        let iterations = 1000;
        let thread_count = 50;

        let handles: Vec<_> = (0..thread_count)
            .map(|i| {
                let p = parker.clone();
                let wakes = successful_wakes.clone();
                thread::spawn(move || {
                    for j in 0..iterations {
                        if i % 2 == 0 {
                            // Parker thread
                            p.park_timeout(Duration::from_millis(10));
                            wakes.fetch_add(1, Ordering::Relaxed);
                        } else {
                            // Unparker thread
                            p.unpark();
                            if j % 10 == 0 {
                                thread::yield_now();
                            }
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread should not panic");
        }

        let total_wakes = successful_wakes.load(Ordering::Relaxed);
        assert!(
            total_wakes > 0,
            "at least some threads should have woken up"
        );
    }

    #[test]
    #[ignore = "stress test; run manually"]
    fn stress_test_scheduler_inject_while_parking() {
        // Race: inject work between empty check and park
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let scheduler = Arc::new(ThreeLaneScheduler::new(4, &state));
        let injected = Arc::new(AtomicUsize::new(0));
        let executed = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(21)); // 20 injectors + 1 main

        // 20 injector threads
        let inject_handles: Vec<_> = (0..20)
            .map(|t| {
                let s = scheduler.clone();
                let inj = injected.clone();
                let b = barrier.clone();
                std::thread::spawn(move || {
                    b.wait();
                    for i in 0..5000 {
                        let task = TaskId::new_for_test(t * 10000 + i, 0);
                        s.inject_ready(task, 50);
                        inj.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        barrier.wait();

        // Let injectors run
        std::thread::sleep(Duration::from_millis(100));

        // Drain the queue
        let exec = executed.clone();
        loop {
            if scheduler.global.pop_ready().is_some() {
                exec.fetch_add(1, Ordering::Relaxed);
            } else {
                break;
            }
        }

        for h in inject_handles {
            h.join().expect("injector should complete");
        }

        // Final drain
        while scheduler.global.pop_ready().is_some() {
            executed.fetch_add(1, Ordering::Relaxed);
        }

        let total_injected = injected.load(Ordering::Relaxed);
        let total_executed = executed.load(Ordering::Relaxed);

        // Due to dedup, executed may be less than injected if same task IDs were used
        // But we should have at least executed something
        assert!(
            total_executed > 0,
            "should have executed some tasks, got {total_executed}"
        );
        assert!(
            total_injected >= total_executed,
            "injected ({total_injected}) should be >= executed ({total_executed})"
        );
    }

    #[test]
    #[ignore = "stress test; run manually"]
    fn stress_test_work_stealing_fairness() {
        use crate::runtime::scheduler::priority::Scheduler as PriorityScheduler;

        // Unbalanced workload: 1 producer, 10 stealers
        let producer_queue = Arc::new(Mutex::new(PriorityScheduler::new()));
        let stolen_count = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(12)); // 1 producer + 10 stealers + 1 main

        // Fill producer queue
        {
            let mut q = producer_queue.lock().unwrap();
            for i in 0..10000 {
                q.schedule(TaskId::new_for_test(i, 0), 50);
            }
        }

        // 10 stealer threads
        let stealer_handles: Vec<_> = (0..10)
            .map(|_| {
                let q = producer_queue.clone();
                let stolen = stolen_count.clone();
                let b = barrier.clone();
                std::thread::spawn(move || {
                    b.wait();
                    let mut local_stolen = 0;
                    loop {
                        let task = {
                            let Ok(mut guard) = q.try_lock() else {
                                continue;
                            };
                            let batch = guard.steal_ready_batch(4);
                            if batch.is_empty() {
                                None
                            } else {
                                Some(batch.len())
                            }
                        };

                        match task {
                            Some(count) => {
                                local_stolen += count;
                                std::thread::yield_now();
                            }
                            None => break,
                        }
                    }
                    stolen.fetch_add(local_stolen, Ordering::Relaxed);
                })
            })
            .collect();

        // Producer thread that keeps adding
        let q = producer_queue.clone();
        let b = barrier.clone();
        let producer = std::thread::spawn(move || {
            b.wait();
            for i in 10000..15000 {
                let mut guard = q.lock().unwrap();
                guard.schedule(TaskId::new_for_test(i, 0), 50);
                drop(guard);
                std::thread::yield_now();
            }
        });

        barrier.wait();

        producer.join().expect("producer should complete");
        for h in stealer_handles {
            h.join().expect("stealer should complete");
        }

        // Drain remaining
        let mut remaining = 0;
        {
            let mut q = producer_queue.lock().unwrap();
            while q.pop().is_some() {
                remaining += 1;
            }
        }

        let total_stolen = stolen_count.load(Ordering::Relaxed);
        let total = total_stolen + remaining;

        // Should have handled all 15000 tasks
        assert!(
            total >= 14000, // Allow some slack for race conditions
            "should handle most tasks, got {total}"
        );
    }

    #[test]
    #[ignore = "stress test; run manually"]
    fn stress_test_global_queue_contention() {
        // High contention: 50 spawners, single queue
        let global = Arc::new(GlobalInjector::new());
        let spawned = Arc::new(AtomicUsize::new(0));
        let consumed = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(61)); // 50 spawners + 10 consumers + 1 main

        // 50 spawner threads
        let spawn_handles: Vec<_> = (0..50)
            .map(|t| {
                let g = global.clone();
                let s = spawned.clone();
                let b = barrier.clone();
                std::thread::spawn(move || {
                    b.wait();
                    for i in 0..2000 {
                        let task = TaskId::new_for_test(t * 100_000 + i, 0);
                        g.inject_ready(task, 50);
                        s.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        // 10 consumer threads
        let consumer_handles: Vec<_> = (0..10)
            .map(|_| {
                let g = global.clone();
                let c = consumed.clone();
                let b = barrier.clone();
                std::thread::spawn(move || {
                    b.wait();
                    let mut local = 0;
                    let mut empty_streak = 0;
                    loop {
                        if g.pop_ready().is_some() {
                            local += 1;
                            empty_streak = 0;
                        } else {
                            empty_streak += 1;
                            if empty_streak > 1000 {
                                break;
                            }
                            std::thread::yield_now();
                        }
                    }
                    c.fetch_add(local, Ordering::Relaxed);
                })
            })
            .collect();

        barrier.wait();

        for h in spawn_handles {
            h.join().expect("spawner should complete");
        }

        // Give consumers time to drain
        std::thread::sleep(Duration::from_millis(100));

        for h in consumer_handles {
            h.join().expect("consumer should complete");
        }

        // Drain remaining
        while global.pop_ready().is_some() {
            consumed.fetch_add(1, Ordering::Relaxed);
        }

        let total_spawned = spawned.load(Ordering::Relaxed);
        let total_consumed = consumed.load(Ordering::Relaxed);

        assert_eq!(total_spawned, 100_000, "should spawn exactly 100k tasks");
        assert!(
            total_consumed >= 99_000, // Allow small slack
            "should consume most tasks, got {total_consumed}"
        );
    }

    #[test]
    fn test_round_robin_wakeup_distribution() {
        // Verify that wake_one distributes wakeups across workers
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let scheduler = ThreeLaneScheduler::new(4, &state);

        // Track which parkers have been woken
        // The next_wake counter starts at 0, so:
        // - Call 1: wakes parker 0 (idx=0 % 4 = 0), next_wake=1
        // - Call 2: wakes parker 1 (idx=1 % 4 = 1), next_wake=2
        // - Call 3: wakes parker 2 (idx=2 % 4 = 2), next_wake=3
        // - Call 4: wakes parker 3 (idx=3 % 4 = 3), next_wake=4
        // - Call 5: wakes parker 0 (idx=4 % 4 = 0), next_wake=5
        // etc.

        // Verify the next_wake counter increments correctly
        let initial = scheduler.next_wake.load(Ordering::Relaxed);
        assert_eq!(initial, 0, "next_wake should start at 0");

        // Wake multiple times and verify counter advances
        for i in 0..8 {
            scheduler.wake_one();
            let current = scheduler.next_wake.load(Ordering::Relaxed);
            assert_eq!(current, i + 1, "next_wake should increment on each wake");
        }

        // Final counter should be 8
        let final_val = scheduler.next_wake.load(Ordering::Relaxed);
        assert_eq!(final_val, 8, "next_wake should be 8 after 8 wakes");

        // Verify round-robin distribution: 8 wakes across 4 workers = 2 per worker
        // (We can't directly verify which parker was woken, but the modulo math
        // guarantees even distribution over time)
    }

    // ========== Governor Integration Tests (bd-2spm) ==========

    #[test]
    fn test_governor_disabled_returns_no_preference() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(1, &state);
        let mut workers = scheduler.take_workers();
        let worker = &mut workers[0];

        assert!(worker.governor.is_none(), "default has no governor");
        let suggestion = worker.governor_suggest();
        assert_eq!(suggestion, SchedulingSuggestion::NoPreference);
    }

    #[test]
    fn test_governor_enabled_quiescent_returns_no_preference() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new_with_options(1, &state, 16, true, 1);
        let mut workers = scheduler.take_workers();
        let worker = &mut workers[0];

        assert!(worker.governor.is_some(), "governor enabled");
        let suggestion = worker.governor_suggest();
        assert_eq!(suggestion, SchedulingSuggestion::NoPreference);
    }

    #[test]
    fn test_governor_meet_deadlines_dispatches_timed_first() {
        use crate::time::{TimerDriverHandle, VirtualClock};

        // State at t=999ms with a task having a 1s deadline.
        // Deadline pressure ≈ 0.999, dominating all other components.
        let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(999_000_000)));
        let mut state = RuntimeState::new();
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));
        state.now = Time::from_nanos(999_000_000);
        let root = state.create_root_region(Budget::unlimited());
        let (_task_id, _handle) = state
            .create_task(root, Budget::with_deadline_ns(1_000_000_000), async {})
            .expect("create task");
        let state = Arc::new(Mutex::new(state));

        let mut scheduler = ThreeLaneScheduler::new_with_options(1, &state, 16, true, 1);

        // Inject a cancel task and an already-due timed task.
        let cancel_task = TaskId::new_for_test(1, 10);
        let timed_task = TaskId::new_for_test(1, 11);
        scheduler.inject_cancel(cancel_task, 100);
        scheduler.inject_timed(timed_task, Time::from_nanos(500_000_000));

        let mut workers = scheduler.take_workers();
        let worker = &mut workers[0];

        // Under MeetDeadlines, timed work is dispatched before cancel.
        let first = worker.next_task();
        assert_eq!(
            first,
            Some(timed_task),
            "timed should be dispatched first under MeetDeadlines"
        );

        let second = worker.next_task();
        assert_eq!(
            second,
            Some(cancel_task),
            "cancel follows timed under MeetDeadlines"
        );
    }

    #[test]
    fn test_governor_drain_obligations_boosts_cancel_streak() {
        use crate::record::ObligationKind;

        // State with a pending obligation aged 1 second (high obligation component).
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::unlimited());
        let (task_id, _handle) = state
            .create_task(root, Budget::unlimited(), async {})
            .expect("create task");
        let _obl = state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");
        state.now = Time::from_nanos(1_000_000_000); // 1s age
        let state = Arc::new(Mutex::new(state));

        // Governor enabled, cancel_streak_limit=2, interval=1.
        let mut scheduler = ThreeLaneScheduler::new_with_options(1, &state, 2, true, 1);

        // Inject 4 cancel tasks and 1 ready task.
        let c1 = TaskId::new_for_test(1, 20);
        let c2 = TaskId::new_for_test(1, 21);
        let c3 = TaskId::new_for_test(1, 22);
        let c4 = TaskId::new_for_test(1, 23);
        let ready = TaskId::new_for_test(1, 24);
        scheduler.inject_cancel(c1, 100);
        scheduler.inject_cancel(c2, 100);
        scheduler.inject_cancel(c3, 100);
        scheduler.inject_cancel(c4, 100);
        scheduler.inject_ready(ready, 50);

        let mut workers = scheduler.take_workers();
        let worker = &mut workers[0];

        // Under DrainObligations, cancel_streak_limit boosted to 4 (2×2).
        // All 4 cancel tasks should dispatch before ready.
        let dispatched: Vec<_> = (0..5).filter_map(|_| worker.next_task()).collect();
        assert_eq!(dispatched.len(), 5, "should dispatch all 5 tasks");

        let cancel_tasks = [c1, c2, c3, c4];
        for (i, &task) in dispatched.iter().take(4).enumerate() {
            assert!(
                cancel_tasks.contains(&task),
                "task {i} should be a cancel task, got {task:?}"
            );
        }
        assert_eq!(
            dispatched[4], ready,
            "ready task should come after all cancel tasks"
        );
    }

    #[test]
    fn test_governor_interval_caches_suggestion() {
        // With interval=4, governor snapshots every 4th call.
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new_with_options(1, &state, 16, true, 4);
        let mut workers = scheduler.take_workers();
        let worker = &mut workers[0];

        assert_eq!(worker.steps_since_snapshot, 0);
        assert_eq!(worker.cached_suggestion, SchedulingSuggestion::NoPreference);

        // Calls 1–3 return cached suggestion without snapshotting.
        for i in 1..=3u32 {
            let s = worker.governor_suggest();
            assert_eq!(s, SchedulingSuggestion::NoPreference);
            assert_eq!(worker.steps_since_snapshot, i);
        }

        // Call 4 takes a snapshot and resets counter.
        let s = worker.governor_suggest();
        assert_eq!(s, SchedulingSuggestion::NoPreference); // quiescent
        assert_eq!(worker.steps_since_snapshot, 0);
    }

    #[test]
    fn test_governor_deterministic_across_workers() {
        use crate::record::ObligationKind;

        // All workers should produce the same suggestion for identical state.
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::unlimited());
        let (task_id, _handle) = state
            .create_task(root, Budget::unlimited(), async {})
            .expect("create task");
        let _obl = state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");
        state.now = Time::from_nanos(2_000_000_000);
        let state = Arc::new(Mutex::new(state));

        let mut scheduler = ThreeLaneScheduler::new_with_options(4, &state, 16, true, 1);
        let mut workers = scheduler.take_workers();

        let suggestions: Vec<_> = workers
            .iter_mut()
            .map(super::ThreeLaneWorker::governor_suggest)
            .collect();

        for s in &suggestions {
            assert_eq!(
                *s, suggestions[0],
                "all workers must agree on scheduling suggestion"
            );
        }
        // With old obligations and no deadlines/draining, should suggest DrainObligations.
        assert_eq!(suggestions[0], SchedulingSuggestion::DrainObligations);
    }

    #[test]
    fn test_governor_backward_compatible_dispatch() {
        // Verify that with governor disabled (default), the dispatch order
        // matches the baseline: cancel > timed > ready (existing tests cover
        // this, but here we explicitly compare against governor-disabled).
        let state = Arc::new(Mutex::new(RuntimeState::new()));

        // Build two schedulers: one with governor, one without.
        let mut sched_off = ThreeLaneScheduler::new(1, &state);
        let mut sched_on = ThreeLaneScheduler::new_with_options(1, &state, 16, true, 1);

        // Inject identical workloads.
        let cancel = TaskId::new_for_test(1, 30);
        let ready = TaskId::new_for_test(1, 31);

        sched_off.inject_cancel(cancel, 100);
        sched_off.inject_ready(ready, 50);
        sched_on.inject_cancel(cancel, 100);
        sched_on.inject_ready(ready, 50);

        let mut workers_off = sched_off.take_workers();
        let w_off = &mut workers_off[0];
        let mut workers_on = sched_on.take_workers();
        let w_on = &mut workers_on[0];

        // Quiescent state → NoPreference → same order as baseline.
        let off_1 = w_off.next_task();
        let on_1 = w_on.next_task();
        assert_eq!(off_1, on_1, "first dispatch should match");
        assert_eq!(off_1, Some(cancel));

        let off_2 = w_off.next_task();
        let on_2 = w_on.next_task();
        assert_eq!(off_2, on_2, "second dispatch should match");
        assert_eq!(off_2, Some(ready));
    }

    // ========================================================================
    // Cancel-lane preemption fairness tests (bd-17uu)
    // ========================================================================

    #[test]
    fn test_preemption_metrics_track_dispatches() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 4);

        for i in 0..3u32 {
            scheduler.inject_cancel(TaskId::new_for_test(1, i), 100);
        }
        for i in 3..5u32 {
            scheduler.inject_ready(TaskId::new_for_test(1, i), 50);
        }

        let mut workers = scheduler.take_workers().into_iter();
        let mut worker = workers.next().unwrap();

        for _ in 0..5 {
            worker.next_task();
        }

        let m = worker.preemption_metrics();
        assert_eq!(m.cancel_dispatches, 3);
        assert_eq!(m.ready_dispatches, 2);
        assert_eq!(
            m.cancel_dispatches + m.ready_dispatches + m.timed_dispatches,
            5
        );
    }

    #[test]
    fn test_preemption_fairness_yield_under_cancel_flood() {
        let limit: usize = 4;
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, limit);

        let cancel_count: u32 = 20;
        let ready_count: u32 = 5;

        for i in 0..cancel_count {
            scheduler.inject_cancel(TaskId::new_for_test(1, i), 100);
        }
        for i in cancel_count..cancel_count + ready_count {
            scheduler.inject_ready(TaskId::new_for_test(1, i), 50);
        }

        let mut workers = scheduler.take_workers().into_iter();
        let mut worker = workers.next().unwrap();

        let total = cancel_count + ready_count;
        for _ in 0..total {
            worker.next_task();
        }

        let m = worker.preemption_metrics();
        assert_eq!(m.cancel_dispatches, u64::from(cancel_count));
        assert_eq!(m.ready_dispatches, u64::from(ready_count));
        assert!(
            m.max_cancel_streak <= limit,
            "max cancel streak {} exceeded limit {}",
            m.max_cancel_streak,
            limit
        );
        assert!(m.fairness_yields > 0, "should yield under cancel flood");
    }

    #[test]
    fn test_preemption_max_streak_bounded_by_limit() {
        for limit in [1, 2, 4, 8, 16] {
            let state = Arc::new(Mutex::new(RuntimeState::new()));
            let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, limit);

            let n_cancel = (limit * 3) as u32;
            for i in 0..n_cancel {
                scheduler.inject_cancel(TaskId::new_for_test(1, i), 100);
            }
            scheduler.inject_ready(TaskId::new_for_test(1, n_cancel), 50);

            let mut workers = scheduler.take_workers().into_iter();
            let mut worker = workers.next().unwrap();

            for _ in 0..=n_cancel {
                worker.next_task();
            }

            let m = worker.preemption_metrics();
            assert!(
                m.max_cancel_streak <= limit,
                "limit={}: max_cancel_streak {} exceeded",
                limit,
                m.max_cancel_streak,
            );
        }
    }

    #[test]
    fn test_preemption_fallback_cancel_when_only_cancel_work() {
        let limit: usize = 2;
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, limit);

        for i in 0..6u32 {
            scheduler.inject_cancel(TaskId::new_for_test(1, i), 100);
        }

        let mut workers = scheduler.take_workers().into_iter();
        let mut worker = workers.next().unwrap();

        let mut count = 0u32;
        for _ in 0..6 {
            if worker.next_task().is_some() {
                count += 1;
            }
        }

        assert_eq!(count, 6);
        let m = worker.preemption_metrics();
        assert_eq!(m.cancel_dispatches, 6);
        assert!(m.fallback_cancel_dispatches > 0, "should use fallback path");
    }

    #[test]
    fn test_local_queue_fast_path() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let scheduler = ThreeLaneScheduler::new(1, &state);

        // Access the worker's local scheduler
        let worker_local = scheduler.workers[0].local.clone();

        // Check global queue is empty
        assert!(!scheduler.global.has_ready_work());

        // Simulate running on worker thread
        {
            let _guard = ScopedLocalScheduler::new(worker_local.clone());
            // Spawn task
            scheduler.spawn(TaskId::new_for_test(1, 1), 100);
        }

        // Global queue should be empty (because it went to local)
        assert!(
            !scheduler.global.has_ready_work(),
            "Global queue should be empty"
        );

        // Local queue should have the task
        let count = {
            let local = worker_local.lock().unwrap();
            local.len()
        };
        assert_eq!(count, 1, "Local queue should have 1 task");

        // Now verify wake also uses local queue
        {
            let _guard = ScopedLocalScheduler::new(worker_local.clone());
            scheduler.wake(TaskId::new_for_test(1, 2), 100);
        }

        // Global queue still empty
        assert!(!scheduler.global.has_ready_work());

        let count = {
            let local = worker_local.lock().unwrap();
            local.len()
        };
        assert_eq!(count, 2, "Local queue should have 2 tasks");

        // Now spawn WITHOUT guard (should go to global)
        scheduler.spawn(TaskId::new_for_test(1, 3), 100);

        assert!(
            scheduler.global.has_ready_work(),
            "Global queue should have task"
        );
    }
}
