//! Worker thread logic.

use crate::observability::metrics::MetricsProvider;
use crate::runtime::RuntimeState;
use crate::runtime::io_driver::IoDriverHandle;
use crate::runtime::panic_isolation::{PanicIsolationConfig, PanicIsolationResult, PanicIsolator};
use crate::runtime::scheduler::global_queue::GlobalQueue;
use crate::runtime::scheduler::local_queue::{LocalQueue, Stealer};
use crate::runtime::scheduler::stealing;
use crate::sync::ContendedMutex;
use crate::time::TimerDriverHandle;
use crate::trace::{TraceBufferHandle, TraceEvent};
use crate::tracing_compat::trace;
use crate::types::{TaskId, Time};
use crate::util::DetRng;
use std::cell::Cell;
use std::convert::TryFrom;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

/// Identifier for a scheduler worker.
pub type WorkerId = usize;

/// Destroy terminal task storage before auditing its holder, outside all
/// runtime and shard locks. A custom future may retain permits even after
/// returning Ready, and its destructor may itself panic.
pub(super) fn retire_terminal_task(
    stored: crate::runtime::stored_task::AnyStoredTask,
) -> Option<crate::types::outcome::PanicPayload> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(stored)))
        .err()
        .map(|payload| {
            let message = crate::cx::scope::payload_to_string(&payload);
            // Match the native poll-panic boundary: an opaque panic payload
            // can panic again on Drop, so retain only its closed message.
            std::mem::forget(payload);
            crate::types::outcome::PanicPayload::new(message)
        })
}

/// Cap on the per-worker `seen_io_tokens` generation table (br-asupersync-414j0b).
///
/// The direct table replaces one colliding slot at a time instead of clearing
/// all history at the cap. That preserves the memory ceiling while avoiding a
/// burst of re-admitted tokens exactly when a busy worker crosses the boundary.
/// Its maximum payload is 65,536 `u64` token slots plus a 1,024-word
/// initialization bitmap (520 KiB per worker).
///
/// Pre-fix the set grew monotonically with cumulative distinct I/O
/// tokens (~24 B × 100k tokens/day → 2.4 MiB/day per worker leaked
/// silently). Post-fix the worst-case footprint is bounded.
pub const MAX_SEEN_IO_TOKENS: usize = 65_536;

const SEEN_IO_TOKEN_SLOT_MASK: u64 = 65_535;
const SEEN_IO_TOKEN_WORD_BITS: usize = 64;

#[derive(Debug, Default)]
#[doc(hidden)] // pub ONLY for the io_token_dedup comparator bench
// (br-asupersync-sched-hot-path-perf-bt4y5f.9); not a supported API.
pub struct SeenIoTokens {
    // Packed tokens include the upstream slab generation. The low 16 index
    // bits select a bounded direct slot; comparing the complete token makes a
    // recycled slab slot a first sight without a table-wide reset.
    slots: Vec<u64>,
    // Token zero is valid, so initialization lives in a compact side bitmap.
    initialized: Vec<u64>,
    occupied: usize,
}

impl SeenIoTokens {
    #[doc(hidden)]
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let slot_capacity = capacity.clamp(1, MAX_SEEN_IO_TOKENS).next_power_of_two();
        Self {
            slots: vec![0; slot_capacity],
            initialized: vec![0; slot_capacity.div_ceil(SEEN_IO_TOKEN_WORD_BITS)],
            occupied: 0,
        }
    }

    #[doc(hidden)]
    #[inline]
    pub fn observe(&mut self, token: u64) -> bool {
        let slot = Self::slot_for(token);
        self.ensure_slot(slot);
        let initialized = self.is_initialized(slot);

        if initialized && self.slots[slot] == token {
            return false;
        }

        if !initialized {
            let word = slot / SEEN_IO_TOKEN_WORD_BITS;
            let mask = 1_u64 << (slot % SEEN_IO_TOKEN_WORD_BITS);
            self.initialized[word] |= mask;
            self.occupied += 1;
        }
        self.slots[slot] = token;
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.occupied
    }

    #[cfg(test)]
    fn contains(&self, token: u64) -> bool {
        let slot = Self::slot_for(token);
        slot < self.slots.len() && self.is_initialized(slot) && self.slots[slot] == token
    }

    #[cfg(test)]
    fn storage_slots(&self) -> usize {
        self.slots.len()
    }

    fn slot_for(token: u64) -> usize {
        usize::try_from(token & SEEN_IO_TOKEN_SLOT_MASK)
            .expect("the masked I/O token slot always fits usize")
    }

    fn ensure_slot(&mut self, slot: usize) {
        if slot < self.slots.len() {
            return;
        }

        let new_len = (slot + 1).next_power_of_two().min(MAX_SEEN_IO_TOKENS);
        self.slots.resize(new_len, 0);
        self.initialized
            .resize(new_len.div_ceil(SEEN_IO_TOKEN_WORD_BITS), 0);
    }

    fn is_initialized(&self, slot: usize) -> bool {
        let word = slot / SEEN_IO_TOKEN_WORD_BITS;
        let mask = 1_u64 << (slot % SEEN_IO_TOKEN_WORD_BITS);
        self.initialized[word] & mask != 0
    }
}

/// A worker thread that executes tasks.
pub struct Worker {
    /// Unique worker ID.
    pub id: WorkerId,
    /// Local task queue for this worker.
    pub local: LocalQueue,
    /// Stealers for other workers' queues.
    pub stealers: Vec<Stealer>,
    /// Global queue shared across workers.
    pub global: Arc<GlobalQueue>,
    /// Shared runtime state.
    pub state: Arc<ContendedMutex<RuntimeState>>,
    /// Parking mechanism for idle workers.
    pub parker: Parker,
    /// Deterministic RNG for stealing decisions.
    pub rng: DetRng,
    /// Shutdown signal.
    pub shutdown: Arc<AtomicBool>,
    /// I/O driver handle (optional).
    pub io_driver: Option<IoDriverHandle>,
    /// Trace buffer for I/O events.
    pub trace: TraceBufferHandle,
    /// Timer driver for timestamps (optional).
    pub timer_driver: Option<TimerDriverHandle>,
    /// Tokens seen for I/O trace emission (generation-aware direct table).
    ///
    /// br-asupersync-414j0b first bounded the set by clearing the whole map
    /// at cap. br-asupersync-sched-hot-path-perf-bt4y5f.9 replaces that
    /// compromise with incremental eviction. br-asupersync-9y4yup keys the
    /// table by the packed reactor token's slot bits: the packed generation
    /// makes slot reuse a one-entry lazy invalidation, while a cap collision
    /// replaces only its direct-mapped entry instead of re-admitting the table.
    seen_io_tokens: SeenIoTokens,
    /// Cached metrics provider — avoids Arc clone per task execution.
    metrics: Arc<dyn MetricsProvider>,
    /// Panic isolation framework for safe task execution.
    panic_isolator: PanicIsolator,
    /// Pre-allocated scratch vec for local waiters (reused across polls).
    scratch_local: Cell<Vec<TaskId>>,
    /// Pre-allocated scratch vec for global waiters (reused across polls).
    scratch_global: Cell<Vec<TaskId>>,
    /// Pre-allocated scratch vec for foreign-worker wakers (reused across polls).
    scratch_foreign_wakers: Cell<Vec<Waker>>,
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Worker")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Worker {
    /// Creates a new worker with the provided queues and state.
    ///
    /// Extracts the E/D instrumentation handles from `state` in one brief
    /// acquisition and delegates to [`new_with_handles`](Self::new_with_handles).
    /// Callers constructing many workers should extract the handles once and
    /// call `new_with_handles` directly so construction does not serialize on
    /// the runtime-state mutex per worker
    /// (br-asupersync-sched-hot-path-perf-bt4y5f.2.2 / E1.2, row W01).
    pub fn new(
        id: WorkerId,
        stealers: Vec<Stealer>,
        global: Arc<GlobalQueue>,
        state: Arc<ContendedMutex<RuntimeState>>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        let (io_driver, trace, timer_driver, metrics) = {
            let guard = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (
                guard.io_driver_handle(),
                guard.trace_handle(),
                guard.timer_driver_handle(),
                guard.metrics_provider(),
            )
        };
        Self::new_with_handles(
            id,
            stealers,
            global,
            state,
            shutdown,
            io_driver,
            trace,
            timer_driver,
            metrics,
        )
    }

    /// Creates a new worker from pre-extracted instrumentation handles,
    /// performing zero `RuntimeState` mutex acquisitions
    /// (br-asupersync-sched-hot-path-perf-bt4y5f.2.2 / E1.2, row W01).
    ///
    /// The `state` Arc is retained for the worker's runtime-table access
    /// paths but is not locked during construction.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_handles(
        id: WorkerId,
        stealers: Vec<Stealer>,
        global: Arc<GlobalQueue>,
        state: Arc<ContendedMutex<RuntimeState>>,
        shutdown: Arc<AtomicBool>,
        io_driver: Option<IoDriverHandle>,
        trace: TraceBufferHandle,
        timer_driver: Option<TimerDriverHandle>,
        metrics: Arc<dyn MetricsProvider>,
    ) -> Self {
        let panic_isolator =
            PanicIsolator::new(PanicIsolationConfig::default(), Arc::clone(&metrics));

        Self {
            id,
            local: LocalQueue::new(Arc::clone(&state)),
            stealers,
            global,
            state,
            parker: Parker::new(),
            rng: DetRng::new(id as u64 + 1), // Simple seed
            shutdown,
            io_driver,
            trace,
            timer_driver,
            seen_io_tokens: SeenIoTokens::with_capacity(32),
            metrics,
            panic_isolator,
            scratch_local: Cell::new(Vec::with_capacity(16)),
            scratch_global: Cell::new(Vec::with_capacity(16)),
            scratch_foreign_wakers: Cell::new(Vec::with_capacity(4)),
        }
    }

    /// Runs the worker scheduling loop.
    pub fn run_loop(&mut self) {
        const SPIN_LIMIT: u32 = 64;
        const YIELD_LIMIT: u32 = 16;

        let _queue_guard = LocalQueue::set_current(self.local.clone());

        while !self.shutdown.load(Ordering::Relaxed) {
            // 1. Try local queue (LIFO)
            if let Some(task) = self.local.pop() {
                self.execute(task);
                continue;
            }

            // 2. Try global queue
            if let Some(task) = self.global.pop() {
                self.execute(task);
                continue;
            }

            // 3. Try stealing from random worker
            if let Some(task) = stealing::steal_task(&self.stealers, &mut self.rng) {
                self.execute(task);
                continue;
            }

            if self.schedule_ready_finalizers() {
                continue;
            }

            // 4. Drive I/O (Leader/Follower pattern)
            // If we can acquire the I/O leader role, we poll the reactor with a short timeout.
            if let Some(io) = &self.io_driver {
                let now = self
                    .timer_driver
                    .as_ref()
                    .map_or(Time::ZERO, TimerDriverHandle::now);
                let trace = &self.trace;
                let seen = &mut self.seen_io_tokens;

                // try_turn_with handles leader election via an atomic flag and drops the
                // inner lock during the blocking poll, allowing concurrent registrations.
                if let Ok(Some(_)) =
                    io.try_turn_with(Some(Duration::from_millis(1)), |event, interest| {
                        let polling_token = event.token.0 as u64;
                        let interest_bits = interest.unwrap_or(event.ready).bits();
                        if seen.observe(polling_token) {
                            trace.record_event(|seq| {
                                TraceEvent::io_requested(seq, now, polling_token, interest_bits)
                            });
                        }
                        trace.record_event(|seq| {
                            TraceEvent::io_ready(seq, now, polling_token, event.ready.bits())
                        });
                    })
                {
                    // We were the leader and polled the reactor. Loop back to check queues.
                    continue;
                }
            }

            // 5. Backoff before parking
            // We spin/yield briefly to avoid the high latency of parking/unparking
            // if new work arrives immediately.
            let mut backoff = 0;

            loop {
                if self.shutdown.load(Ordering::Relaxed) {
                    break;
                }

                // Probe queues directly instead of relying on `is_empty()` snapshots.
                // This avoids missing immediately-available global work due to
                // racing emptiness hints right before a park timeout.
                if let Some(task) = self.pop_backoff_work() {
                    self.execute(task);
                    break;
                }

                if backoff < SPIN_LIMIT {
                    crate::runtime::metrics::record_worker_spin();
                    std::hint::spin_loop();
                    backoff += 1;
                } else if backoff < SPIN_LIMIT + YIELD_LIMIT {
                    crate::runtime::metrics::record_sched_yield();
                    std::thread::yield_now();
                    backoff += 1;
                } else {
                    // Use a moderate timeout so shutdown is observed even if no
                    // explicit unpark signal is delivered while this worker is
                    // parked.  The previous 1ms timeout caused ~3% CPU per idle
                    // worker (1000 wake-ups/sec).  25ms is a good trade-off:
                    // still responsive to shutdown while reducing idle CPU by ~25x.
                    self.parker.park_timeout(Duration::from_millis(25));
                    break;
                }
            }
        }
    }

    #[inline]
    fn pop_backoff_work(&mut self) -> Option<TaskId> {
        self.local
            .pop()
            .or_else(|| self.global.pop())
            .or_else(|| stealing::steal_task(&self.stealers, &mut self.rng))
    }

    #[allow(clippy::too_many_lines)]
    fn execute(&self, task_id: TaskId) {
        use crate::runtime::stored_task::AnyStoredTask;

        // Guard panic-unwind path so a panicking task still transitions to
        // terminal state and wakes dependents instead of leaking obligations.
        struct TaskExecutionGuard<'a> {
            worker: &'a Worker,
            task_id: TaskId,
            completed: bool,
            stored: Option<AnyStoredTask>,
        }

        impl Drop for TaskExecutionGuard<'_> {
            fn drop(&mut self) {
                if !self.completed && std::thread::panicking() {
                    let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        if let Some(stored) = self.stored.take() {
                            let _ = retire_terminal_task(stored);
                        }
                        let mut state = self
                            .worker
                            .state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        state.revoke_obligation_admission_before_completion(self.task_id, None);
                        let _ = state.drain_obligation_posts_before_completion(None);
                        let _ = state.update_task(self.task_id, |record| {
                            if !record.state.is_terminal() {
                                record.complete(crate::types::Outcome::Panicked(
                                    crate::types::outcome::PanicPayload::new(
                                        "task panicked during poll",
                                    ),
                                ));
                            }
                        });

                        let (waiters, cancel_waker_retirements) = state
                            .task_completed(self.task_id)
                            .into_waiters_and_retirements_without_observers();
                        let finalizers = state.drain_ready_async_finalizers();
                        let mut local_waiters = self.worker.scratch_local.take();
                        let mut global_waiters = self.worker.scratch_global.take();
                        let mut foreign_wakers = self.worker.scratch_foreign_wakers.take();
                        local_waiters.clear();
                        global_waiters.clear();
                        foreign_wakers.clear();

                        for waiter in waiters {
                            if let Some(record) = state.task(waiter) {
                                if record.wake_state.notify() {
                                    if record.is_local() {
                                        match record.pinned_worker() {
                                            Some(worker_id) if worker_id == self.worker.id => {
                                                local_waiters.push(waiter);
                                            }
                                            Some(_worker_id) => {
                                                record.wake_state.clear();
                                                if let Some((waker, _)) = &record.cached_waker {
                                                    foreign_wakers.push(waker.clone());
                                                }
                                                // No cached waker: task hasn't been polled yet.
                                                // Clear notified state so the next proper wake
                                                // (via the task's waker on its owning worker)
                                                // is not dedup-suppressed.
                                            }
                                            None => local_waiters.push(waiter),
                                        }
                                    } else {
                                        global_waiters.push(waiter);
                                    }
                                }
                            }
                        }
                        drop(state);
                        cancel_waker_retirements.retire();

                        while let Some(waker) = foreign_wakers.pop() {
                            waker.wake();
                        }

                        for waiter in &global_waiters {
                            self.worker.global.push(*waiter);
                        }
                        self.worker.local.push_many(&local_waiters);
                        self.worker.scratch_local.set(local_waiters);
                        self.worker.scratch_global.set(global_waiters);
                        self.worker.scratch_foreign_wakers.set(foreign_wakers);
                        self.worker.publish_ready_finalizers(finalizers);
                    }));
                    if let Err(payload) = cleanup {
                        // A lifecycle observer or foreign destructor may panic
                        // while this guard is already unwinding. Match the
                        // three-lane guard's secondary-panic containment.
                        std::mem::forget(payload);
                    }
                }
            }
        }

        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            trace!(task_id = ?task_id, worker_id = self.id, "executing task");
        })) {
            std::mem::forget(payload);
        }

        // Check local (thread-local) storage first — no lock required.
        // This saves a full lock round-trip for local tasks (the common
        // case on each worker) versus the previous approach of locking
        // state, failing the global lookup, dropping, then re-locking.
        let local_task = crate::runtime::local::remove_local_task(task_id);

        let (stored, task_cx, wake_state, cached_waker) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);

            if let Some(local_task) = local_task {
                // Local task found — single lock acquisition for record info
                if let Some(record) = state.task_mut(task_id) {
                    record.start_running();
                    record.wake_state.begin_poll();
                    super::three_lane::consume_budget_poll(record);
                    let task_cx = record.cx.clone();
                    let wake_state = Arc::clone(&record.wake_state);
                    let cached = record.cached_waker.take();
                    drop(state);
                    (
                        AnyStoredTask::Local(local_task),
                        task_cx,
                        wake_state,
                        cached,
                    )
                } else {
                    return; // Task record missing
                }
            } else if let Some(stored) = state.remove_stored_future(task_id) {
                // Global task found
                if let Some(record) = state.task_mut(task_id) {
                    record.start_running();
                    record.wake_state.begin_poll();
                    super::three_lane::consume_budget_poll(record);
                    let task_cx = record.cx.clone();
                    let wake_state = Arc::clone(&record.wake_state);
                    let cached = record.cached_waker.take();
                    drop(state);
                    (AnyStoredTask::Global(stored), task_cx, wake_state, cached)
                } else {
                    return; // Task record missing?
                }
            } else {
                return; // Task not found anywhere
            }
        };

        let is_local_task = matches!(&stored, AnyStoredTask::Local(_));
        // br-asupersync-jkb17z: WorkStealingWaker amortization.
        //
        // First-poll waker construction costs 1 heap alloc + 4 Arc::clone
        // atomic refcount bumps (wake_state, global, parker, local). The
        // result is stashed back into `record.cached_waker` after the
        // first Pending return (see save sites at the end of execute()
        // ~lines 544 and 557), so subsequent polls of the same task
        // hit the `Some(w)` reuse path here at zero allocation.
        //
        // For long-lived tasks the per-task cost amortizes to O(1)
        // across all polls of the task. For short-lived per-request
        // tasks (the bead's stated worry) the first-poll cost is the
        // unavoidable minimum — restructuring to a per-Worker waker
        // proto with re-bindable task_id was considered and rejected
        // because (a) wake() needs the task_id to know which task to
        // schedule, (b) the conditional `local: Option<LocalQueue>`
        // depends on per-task is_local, and (c) the heap allocation
        // dominates the 4 atomic bumps anyway.
        //
        // Helper extraction for grep-ability + a single instrumentation
        // hook point if we ever want to count first-poll waker allocs.
        let waker = if let Some((w, _)) = cached_waker {
            w
        } else {
            Self::build_first_poll_waker(
                task_id,
                Arc::clone(&wake_state),
                Arc::clone(&self.global),
                if is_local_task {
                    Some(self.local.clone())
                } else {
                    None
                },
                self.parker.clone(),
            )
        };
        let mut cx = Context::from_waker(&waker);
        let _cx_guard = crate::cx::Cx::set_current(task_cx);
        let mut guard = TaskExecutionGuard {
            worker: self,
            task_id,
            completed: false,
            stored: Some(stored),
        };

        // br-asupersync-qdkyqs: replay-determinism. Sample the
        // worker's installed TimerDriverHandle when present (which
        // returns deterministic logical Time in the lab runtime);
        // fall back to wall_now() when no driver is attached
        // (production-default config). Both paths return
        // [`crate::types::Time`] so the elapsed computation at the
        // bottom of the poll loop is type-uniform. Pre-fix used
        // `std::time::Instant::now()` directly, which baked
        // wall-clock into a metric that — once a future refactor
        // routes scheduler decisions through observability — would
        // diverge across replays.
        let poll_start: crate::types::Time = self
            .timer_driver
            .as_ref()
            .map_or_else(crate::time::wall_now, TimerDriverHandle::now);

        // Get region ID for panic isolation context
        let region_id = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.task(task_id).map_or_else(
                || {
                    // Fallback region ID - this shouldn't happen in normal operation
                    crate::types::RegionId::from_arena(crate::util::ArenaIndex::new(0, 0))
                },
                |record| record.owner,
            )
        };

        let poll_attempt = guard
            .stored
            .as_ref()
            .expect("executing task storage")
            .poll_count()
            .saturating_add(1);
        let poll_attempt = u32::try_from(poll_attempt).unwrap_or(u32::MAX);

        // Isolate the potentially panicking task poll operation
        let poll_result =
            self.panic_isolator
                .isolate_task_execution(task_id, region_id, poll_attempt, || {
                    guard
                        .stored
                        .as_mut()
                        .expect("executing task storage")
                        .poll(&mut cx)
                });

        match poll_result {
            PanicIsolationResult::Success(Poll::Ready(outcome)) => {
                // Map Outcome<(), ()> to Outcome<(), Error> for record.complete()
                let mut task_outcome = outcome
                    .map_err(|()| crate::error::Error::new(crate::error::ErrorKind::Internal));
                if let Some(panic) =
                    retire_terminal_task(guard.stored.take().expect("completed task storage"))
                {
                    if !matches!(task_outcome, crate::types::Outcome::Panicked(_)) {
                        task_outcome = crate::types::Outcome::Panicked(panic);
                    }
                }
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                // Obligation posts made during this poll are applied while
                // the task record is still live, inside the lock this arm
                // already holds (br-asupersync-bi2462.13): a reserve+resolve
                // within one poll is tracked, and an open reservation is
                // caught by the completion-time leak check below.
                state.revoke_obligation_admission_before_completion(task_id, None);
                let _ = state.drain_obligation_posts_before_completion(None);
                let (cancel_ack, cancel_wakes) =
                    Self::consume_cancel_ack_locked(&mut state, task_id).into_parts();
                let cancel_ack = cancel_ack.is_some();
                let _ = state.update_task(task_id, |record| {
                    if !record.state.is_terminal() {
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
                                    crate::record::task::TaskState::Completed(
                                        crate::types::Outcome::Cancelled(_)
                                    )
                                );
                            }
                        }
                        if !completed_via_cancel {
                            record.complete(task_outcome);
                        }
                    }
                });

                let (waiters, completion_observer) = state.task_completed(task_id).into_parts();
                let finalizers = state.drain_ready_async_finalizers();
                let mut local_waiters = self.scratch_local.take();
                let mut global_waiters = self.scratch_global.take();
                let mut foreign_wakers = self.scratch_foreign_wakers.take();
                local_waiters.clear();
                global_waiters.clear();
                foreign_wakers.clear();

                for waiter in waiters {
                    if let Some(record) = state.task(waiter) {
                        if record.wake_state.notify() {
                            if record.is_local() {
                                match record.pinned_worker() {
                                    Some(worker_id) if worker_id == self.id => {
                                        local_waiters.push(waiter);
                                    }
                                    Some(_worker_id) => {
                                        record.wake_state.clear();
                                        if let Some((waker, _)) = &record.cached_waker {
                                            foreign_wakers.push(waker.clone());
                                        }
                                        // No cached waker: task hasn't been polled yet.
                                        // Clear notified state so the next proper wake
                                        // (via the task's waker on its owning worker)
                                        // is not dedup-suppressed.
                                    }
                                    None => local_waiters.push(waiter),
                                }
                            } else {
                                global_waiters.push(waiter);
                            }
                        }
                    }
                }
                drop(state);

                for waiter in &global_waiters {
                    self.global.push(*waiter);
                }
                self.local.push_many(&local_waiters);
                self.publish_ready_finalizers(finalizers);
                guard.completed = true;
                wake_state.clear();
                completion_observer.dispatch();

                while let Some(waker) = foreign_wakers.pop() {
                    waker.wake();
                }

                self.scratch_local.set(local_waiters);
                self.scratch_global.set(global_waiters);
                self.scratch_foreign_wakers.set(foreign_wakers);
                cancel_wakes.dispatch();
            }
            PanicIsolationResult::Success(Poll::Pending) => {
                let is_local = is_local_task;

                let cancel_effects = match guard.stored.take().expect("pending task storage") {
                    AnyStoredTask::Global(t) => {
                        let mut state = self
                            .state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        state.store_spawned_task(task_id, t);
                        if state.has_pending_obligation_posts() {
                            let _ = state.drain_obligation_posts(64);
                        }
                        // Cache waker back in the task record for reuse on next poll
                        let _ = state.update_task(task_id, |record| {
                            // Inspector poll counts (asupersync-bi2462.116).
                            record.increment_polls();
                            record.cached_waker = Some((waker, 0));
                        });
                        Self::consume_cancel_ack_locked(&mut state, task_id)
                    }
                    AnyStoredTask::Local(t) => {
                        crate::runtime::local::store_local_task(task_id, t);
                        // Cache waker for local tasks too (record is in global state)
                        let mut state = self
                            .state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if state.has_pending_obligation_posts() {
                            let _ = state.drain_obligation_posts(64);
                        }
                        let _ = state.update_task(task_id, |record| {
                            record.increment_polls();
                            record.cached_waker = Some((waker, 0));
                        });
                        Self::consume_cancel_ack_locked(&mut state, task_id)
                    }
                };
                let (cancel_ack, cancel_wakes) = cancel_effects.into_parts();

                if wake_state.finish_poll() || cancel_ack.is_some() {
                    // Local tasks must stay on their owning worker. We reschedule
                    // local tasks to the local queue and global tasks to the global queue.
                    // WorkStealingWaker also routes cross-thread wakes for local tasks
                    // back to this local queue to prevent task loss.

                    if is_local {
                        self.local.push(task_id);
                    } else {
                        self.global.push(task_id);
                    }
                    self.parker.unpark();
                }
                guard.completed = true;
                cancel_wakes.dispatch();
            }
            PanicIsolationResult::Panicked(panic_context)
            | PanicIsolationResult::Skipped {
                context: panic_context,
                ..
            } => {
                // Task panicked during poll - convert to structured outcome
                let panic_outcome = self.panic_isolator.panic_to_outcome(&panic_context);
                // Preserve the original poll panic if retiring its remaining
                // fields also panics. Field drops still publish their posts.
                let _ = retire_terminal_task(guard.stored.take().expect("panicked task storage"));

                // Complete the task with panic outcome (similar to Ready case but with panic outcome)
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.revoke_obligation_admission_before_completion(task_id, None);
                let _ = state.drain_obligation_posts_before_completion(None);
                let (_cancel_ack, cancel_wakes) =
                    Self::consume_cancel_ack_locked(&mut state, task_id).into_parts();
                let _ = state.update_task(task_id, |record| {
                    if !record.state.is_terminal() {
                        record.complete(panic_outcome);
                    }
                });

                let (waiters, completion_observer) = state.task_completed(task_id).into_parts();
                let finalizers = state.drain_ready_async_finalizers();
                let mut local_waiters = self.scratch_local.take();
                let mut global_waiters = self.scratch_global.take();
                let mut foreign_wakers = self.scratch_foreign_wakers.take();
                local_waiters.clear();
                global_waiters.clear();
                foreign_wakers.clear();

                for waiter in waiters {
                    if let Some(record) = state.task(waiter) {
                        if record.wake_state.notify() {
                            if record.is_local() {
                                match record.pinned_worker() {
                                    Some(worker_id) if worker_id == self.id => {
                                        local_waiters.push(waiter);
                                    }
                                    Some(_worker_id) => {
                                        record.wake_state.clear();
                                        if let Some((waker, _)) = &record.cached_waker {
                                            foreign_wakers.push(waker.clone());
                                        }
                                    }
                                    None => local_waiters.push(waiter),
                                }
                            } else {
                                global_waiters.push(waiter);
                            }
                        }
                    }
                }
                drop(state);

                for waiter in &global_waiters {
                    self.global.push(*waiter);
                }
                self.local.push_many(&local_waiters);
                self.publish_ready_finalizers(finalizers);
                guard.completed = true;
                wake_state.clear();
                completion_observer.dispatch();

                while let Some(waker) = foreign_wakers.pop() {
                    waker.wake();
                }

                self.scratch_local.set(local_waiters);
                self.scratch_global.set(global_waiters);
                self.scratch_foreign_wakers.set(foreign_wakers);
                cancel_wakes.dispatch();
            }
        }
        let _ = guard.completed;
        // br-asupersync-qdkyqs: matched-pair sample with poll_start
        // (above). `Time::duration_since` returns saturating
        // u64-nanos which we wrap as `Duration` for the metric API.
        // Same TimerDriver-or-wall_now branch as poll_start so the
        // elapsed value is computed from a single clock source per
        // poll.
        let poll_end: crate::types::Time = self
            .timer_driver
            .as_ref()
            .map_or_else(crate::time::wall_now, TimerDriverHandle::now);
        self.metrics
            .scheduler_tick(1, Duration::from_nanos(poll_end.duration_since(poll_start)));
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
        self.publish_ready_finalizers(tasks);
        true
    }

    fn publish_ready_finalizers(
        &self,
        finalizers: smallvec::SmallVec<[(TaskId, u8, crate::runtime::state::TaskSpawnEffects); 2]>,
    ) {
        let mut spawn_effects =
            smallvec::SmallVec::<[crate::runtime::state::TaskSpawnEffects; 2]>::new();
        for (task_id, _priority, effects) in finalizers {
            self.global.push(task_id);
            spawn_effects.push(effects);
        }
        for effects in spawn_effects {
            effects.dispatch();
        }
    }

    #[inline]
    fn consume_cancel_ack_locked(
        state: &mut RuntimeState,
        task_id: TaskId,
    ) -> crate::types::task_context::CancellationEffects<
        Option<crate::record::task::CheckpointCancelAck>,
    > {
        state.consume_task_checkpoint_cancel_ack(task_id)
    }
}

struct WorkStealingWaker {
    task_id: TaskId,
    wake_state: Arc<crate::record::task::TaskWakeState>,
    global: Arc<GlobalQueue>,
    local: Option<LocalQueue>,
    parker: Parker,
}

impl Worker {
    /// Construct a fresh `WorkStealingWaker`-backed [`Waker`]. Called once
    /// per task (on first poll) — subsequent polls reuse the `cached_waker`
    /// stashed into the TaskRecord. See br-asupersync-jkb17z.
    #[inline]
    fn build_first_poll_waker(
        task_id: TaskId,
        wake_state: Arc<crate::record::task::TaskWakeState>,
        global: Arc<GlobalQueue>,
        local: Option<LocalQueue>,
        parker: Parker,
    ) -> Waker {
        Waker::from(Arc::new(WorkStealingWaker {
            task_id,
            wake_state,
            global,
            local,
            parker,
        }))
    }
}

impl WorkStealingWaker {
    #[inline]
    fn schedule(&self) {
        if self.wake_state.notify() {
            if let Some(local) = &self.local {
                local.push(self.task_id);
            } else {
                self.global.push(self.task_id);
            }
            self.parker.unpark();
        }
    }
}

impl Wake for WorkStealingWaker {
    #[inline]
    fn wake(self: Arc<Self>) {
        self.schedule();
    }

    #[inline]
    fn wake_by_ref(self: &Arc<Self>) {
        self.schedule();
    }
}

#[derive(Debug)]
struct ParkerInner {
    notified: AtomicBool,
    waiting: AtomicUsize,
    #[cfg(test)]
    wait_committed: AtomicBool,
    mutex: Mutex<()>,
    cvar: Condvar,
}

/// A mechanism for parking and unparking a worker.
#[derive(Debug, Clone)]
pub struct Parker {
    inner: Arc<ParkerInner>,
}

impl Parker {
    #[inline]
    fn lock_unpoisoned(&self) -> std::sync::MutexGuard<'_, ()> {
        self.inner
            .mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Creates a new parker.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ParkerInner {
                notified: AtomicBool::new(false),
                waiting: AtomicUsize::new(0),
                #[cfg(test)]
                wait_committed: AtomicBool::new(false),
                mutex: Mutex::new(()),
                cvar: Condvar::new(),
            }),
        }
    }

    /// Parks the current thread until notified.
    #[inline]
    pub fn park(&self) {
        self.park_unless(|| false);
    }

    /// Parks with the usual permit semantics unless `ready` is true after
    /// waiter publication. The predicate runs once, under the Parker mutex:
    /// it must be a short readiness check that does not re-enter this Parker.
    #[inline]
    pub(crate) fn park_unless(&self, ready: impl FnOnce() -> bool) {
        self.park_inner(None, ready);
    }

    /// Parks the current thread with a timeout.
    #[inline]
    pub fn park_timeout(&self, duration: Duration) {
        self.park_timeout_unless(duration, || false);
    }

    /// Timed counterpart of `park_unless`. A follower's local deadline must
    /// not let it miss a handoff while it is preparing a timed wait.
    #[inline]
    pub(crate) fn park_timeout_unless(&self, duration: Duration, ready: impl FnOnce() -> bool) {
        self.park_inner(Some(duration), ready);
    }

    #[inline]
    fn park_inner(&self, duration: Option<Duration>, ready: impl FnOnce() -> bool) {
        // Declared after the mutex guard below, so even a panicking predicate
        // withdraws its waiter before that mutex is released (ppdgkg).
        struct WaitingCount<'a>(&'a ParkerInner);
        impl Drop for WaitingCount<'_> {
            fn drop(&mut self) {
                #[cfg(test)]
                self.0.wait_committed.store(false, Ordering::Release);
                self.0.waiting.fetch_sub(1, Ordering::Release);
            }
        }

        if self
            .inner
            .notified
            .compare_exchange(true, false, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }

        if duration.is_some_and(|duration| duration.is_zero()) {
            // Preserve best-effort permit consumption if an unpark races
            // immediately after the initial fast-path check.
            let _ = self.inner.notified.compare_exchange(
                true,
                false,
                Ordering::Acquire,
                Ordering::Relaxed,
            );
            return;
        }

        crate::runtime::metrics::record_worker_park();
        self.inner.waiting.fetch_add(1, Ordering::Release);
        // br-asupersync-re7cz3: pair waiter publication with unpark's permit
        // publication. Also pair with promote_follower's post-release fence:
        // either the leader sees this waiter or ready() sees its released
        // poll flag. Acquire/Release on distinct atomics alone is not enough.
        std::sync::atomic::fence(Ordering::SeqCst);
        let mut guard = self.lock_unpoisoned();
        let waiting = WaitingCount(&self.inner);
        if ready() {
            return;
        }
        #[cfg(test)]
        self.inner.wait_committed.store(true, Ordering::Release);

        if let Some(duration) = duration {
            let (returned_guard, _timeout) = self
                .inner
                .cvar
                .wait_timeout_while(guard, duration, |()| {
                    self.inner
                        .notified
                        .compare_exchange(true, false, Ordering::Acquire, Ordering::Relaxed)
                        .is_err()
                })
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard = returned_guard;
        } else {
            while self
                .inner
                .notified
                .compare_exchange(true, false, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                guard = self
                    .inner
                    .cvar
                    .wait(guard)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }
        drop(waiting);
        drop(guard);
    }

    /// Unparks a parked thread.
    ///
    /// Fast path: if the thread was already notified (common case when a waker
    /// fires for an already-runnable task), the atomic swap returns `true` and
    /// we skip the mutex + condvar entirely.  Only when the previous state was
    /// "not notified" do we acquire the mutex and signal the condvar, which is
    /// the only case where the thread might actually be parked.
    #[inline]
    pub fn unpark(&self) {
        if self
            .inner
            .notified
            .compare_exchange(false, true, Ordering::Release, Ordering::Relaxed)
            .is_err()
        {
            // Already notified — the thread will see it on the next
            // park() fast-path check.  No mutex or condvar needed.
            return;
        }
        crate::runtime::metrics::record_worker_unpark();
        // br-asupersync-re7cz3: Dekker-style store-load barrier — see the
        // matching fence in park()/park_timeout(). Without this, unpark's
        // load on `waiting` could be reordered ahead of the CAS publish on
        // `notified`, observing the pre-park value of `waiting` (0) while
        // the parker is mid-park-prep. The SeqCst fences on both sides
        // form a total order; if THIS side observes waiting == 0 the
        // other side is guaranteed to subsequently observe notified ==
        // true on its post-fence CAS check and return without sleeping.
        std::sync::atomic::fence(Ordering::SeqCst);
        // No waiter currently parked or preparing to park under the mutex.
        // The permit has been published via `notified`, so the next park()
        // will consume it. `waiting` is an optimization hint — a stale read
        // only causes an unnecessary (but harmless) mutex+condvar signal.
        if self.inner.waiting.load(Ordering::Acquire) == 0 {
            return;
        }
        // Was not notified: the thread may be parked. We must acquire the
        // mutex before notify_one to prevent lost wakeups (standard condvar
        // protocol).
        let _guard = self.lock_unpoisoned();
        self.inner.cvar.notify_one();
    }

    /// Publishes a permit only when a thread is currently parked or preparing
    /// to park on this instance.
    ///
    /// The optimistic waiter-count check keeps the common non-waiting scan
    /// lock-free. The second check runs under the condvar mutex, binding the
    /// observed waiter to the notification: a timed-out waiter decrements its
    /// count before releasing this mutex, while a waiter still preparing to
    /// sleep will consume the published permit before entering the condvar.
    ///
    /// Returns `true` only when this call published a new permit for a live
    /// waiter. An already-notified waiter returns `false`, allowing a
    /// coordinator to try another parked worker instead of wasting the wake.
    #[inline]
    pub(crate) fn unpark_if_waiting(&self) -> bool {
        if self.inner.waiting.load(Ordering::Acquire) == 0 {
            return false;
        }

        let _guard = self.lock_unpoisoned();
        if self.inner.waiting.load(Ordering::Acquire) == 0
            || self
                .inner
                .notified
                .compare_exchange(false, true, Ordering::Release, Ordering::Relaxed)
                .is_err()
        {
            return false;
        }

        crate::runtime::metrics::record_worker_unpark();
        self.inner.cvar.notify_one();
        true
    }

    /// The waiter finished its readiness check. With no pending permit this
    /// witnesses the condvar handoff boundary, not just waiter publication.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn wait_committed_for_test(&self) -> bool {
        self.inner.wait_committed.load(Ordering::Acquire)
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn notification_pending_for_test(&self) -> bool {
        self.inner.notified.load(Ordering::Acquire)
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn waiting_count_for_test(&self) -> usize {
        self.inner.waiting.load(Ordering::Acquire)
    }
}

impl Default for Parker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "parker_handoff_tests.rs"]
mod parker_handoff_tests;

#[cfg(test)]
#[path = "worker_inline_tests.rs"]
mod tests;
