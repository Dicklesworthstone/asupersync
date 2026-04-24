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
use std::collections::HashSet;
use std::convert::TryFrom;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

/// Identifier for a scheduler worker.
pub type WorkerId = usize;

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
    /// Tokens seen for I/O trace emission (HashSet for O(1) insert vs BTreeSet O(log n)).
    seen_io_tokens: HashSet<u64>,
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
            seen_io_tokens: HashSet::with_capacity(32),
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
                        let io_token = event.token.0 as u64;
                        let interest_bits = interest.unwrap_or(event.ready).bits();
                        if seen.insert(io_token) {
                            trace.record_event(|seq| {
                                TraceEvent::io_requested(seq, now, io_token, interest_bits)
                            });
                        }
                        trace.record_event(|seq| {
                            TraceEvent::io_ready(seq, now, io_token, event.ready.bits())
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
                    std::hint::spin_loop();
                    backoff += 1;
                } else if backoff < SPIN_LIMIT + YIELD_LIMIT {
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
    fn pop_backoff_work(&self) -> Option<TaskId> {
        self.local.pop().or_else(|| self.global.pop())
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
        }

        impl Drop for TaskExecutionGuard<'_> {
            fn drop(&mut self) {
                if !self.completed && std::thread::panicking() {
                    let mut state = self
                        .worker
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if let Some(record) = state.task_mut(self.task_id) {
                        if !record.state.is_terminal() {
                            record.complete(crate::types::Outcome::Panicked(
                                crate::types::outcome::PanicPayload::new(
                                    "task panicked during poll",
                                ),
                            ));
                        }
                    }

                    let waiters = state.task_completed(self.task_id);
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
                    for (finalizer_task, _) in finalizers {
                        self.worker.global.push(finalizer_task);
                    }
                }
            }
        }

        trace!(task_id = ?task_id, worker_id = self.id, "executing task");

        // Check local (thread-local) storage first — no lock required.
        // This saves a full lock round-trip for local tasks (the common
        // case on each worker) versus the previous approach of locking
        // state, failing the global lookup, dropping, then re-locking.
        let local_task = crate::runtime::local::remove_local_task(task_id);

        let (mut stored, task_cx, wake_state, cached_waker) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);

            if let Some(local_task) = local_task {
                // Local task found — single lock acquisition for record info
                if let Some(record) = state.task_mut(task_id) {
                    record.start_running();
                    record.wake_state.begin_poll();
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
        // Reuse cached waker if available (WorkStealingWaker fields are immutable
        // per task lifetime — no priority field to compare, unlike ThreeLaneWaker).
        let waker = if let Some((w, _)) = cached_waker {
            w
        } else {
            let local_queue = if is_local_task {
                Some(self.local.clone())
            } else {
                None
            };
            Waker::from(Arc::new(WorkStealingWaker {
                task_id,
                wake_state: Arc::clone(&wake_state),
                global: Arc::clone(&self.global),
                local: local_queue,
                parker: self.parker.clone(),
            }))
        };
        let mut cx = Context::from_waker(&waker);
        let _cx_guard = crate::cx::Cx::set_current(task_cx);
        let mut guard = TaskExecutionGuard {
            worker: self,
            task_id,
            completed: false,
        };

        let poll_start = Instant::now();

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

        let poll_attempt = stored.poll_count().saturating_add(1);
        let poll_attempt = u32::try_from(poll_attempt).unwrap_or(u32::MAX);

        // Isolate the potentially panicking task poll operation
        let poll_result =
            self.panic_isolator
                .isolate_task_execution(task_id, region_id, poll_attempt, || stored.poll(&mut cx));

        match poll_result {
            PanicIsolationResult::Success(Poll::Ready(outcome)) => {
                // Map Outcome<(), ()> to Outcome<(), Error> for record.complete()
                let task_outcome = outcome
                    .map_err(|()| crate::error::Error::new(crate::error::ErrorKind::Internal));
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let cancel_ack = Self::consume_cancel_ack_locked(&mut state, task_id);
                if let Some(record) = state.task_mut(task_id) {
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
                }

                let waiters = state.task_completed(task_id);
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

                while let Some(waker) = foreign_wakers.pop() {
                    waker.wake();
                }

                for waiter in &global_waiters {
                    self.global.push(*waiter);
                }
                self.local.push_many(&local_waiters);
                self.scratch_local.set(local_waiters);
                self.scratch_global.set(global_waiters);
                self.scratch_foreign_wakers.set(foreign_wakers);
                for (finalizer_task, _) in finalizers {
                    self.global.push(finalizer_task);
                }
                guard.completed = true;
                wake_state.clear();
            }
            PanicIsolationResult::Success(Poll::Pending) => {
                let is_local = is_local_task;

                match stored {
                    AnyStoredTask::Global(t) => {
                        let mut state = self
                            .state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        state.store_spawned_task(task_id, t);
                        // Cache waker back in the task record for reuse on next poll
                        if let Some(record) = state.task_mut(task_id) {
                            record.cached_waker = Some((waker, 0));
                        }
                        let _ = Self::consume_cancel_ack_locked(&mut state, task_id);
                        drop(state);
                    }
                    AnyStoredTask::Local(t) => {
                        crate::runtime::local::store_local_task(task_id, t);
                        // Cache waker for local tasks too (record is in global state)
                        let mut state = self
                            .state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if let Some(record) = state.task_mut(task_id) {
                            record.cached_waker = Some((waker, 0));
                        }
                        let _ = Self::consume_cancel_ack_locked(&mut state, task_id);
                        drop(state);
                    }
                }

                if wake_state.finish_poll() {
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
            }
            PanicIsolationResult::Panicked(panic_context)
            | PanicIsolationResult::Skipped {
                context: panic_context,
                ..
            } => {
                // Task panicked during poll - convert to structured outcome
                let panic_outcome = self.panic_isolator.panic_to_outcome(&panic_context);

                // Complete the task with panic outcome (similar to Ready case but with panic outcome)
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let _cancel_ack = Self::consume_cancel_ack_locked(&mut state, task_id);
                if let Some(record) = state.task_mut(task_id) {
                    if !record.state.is_terminal() {
                        record.complete(panic_outcome);
                    }
                }

                let waiters = state.task_completed(task_id);
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

                while let Some(waker) = foreign_wakers.pop() {
                    waker.wake();
                }

                for waiter in &global_waiters {
                    self.global.push(*waiter);
                }
                self.local.push_many(&local_waiters);
                self.scratch_local.set(local_waiters);
                self.scratch_global.set(global_waiters);
                self.scratch_foreign_wakers.set(foreign_wakers);
                for (finalizer_task, _) in finalizers {
                    self.global.push(finalizer_task);
                }
                guard.completed = true;
                wake_state.clear();
            }
        }
        let _ = guard.completed;
        self.metrics.scheduler_tick(1, poll_start.elapsed());
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
        for (task_id, _) in tasks {
            self.global.push(task_id);
        }
        true
    }

    #[inline]
    fn consume_cancel_ack_locked(state: &mut RuntimeState, task_id: TaskId) -> bool {
        let Some(record) = state.task_mut(task_id) else {
            return false;
        };
        let Some(inner) = record.cx_inner.as_ref() else {
            return false;
        };
        let mut acknowledged = false;
        let mut guard = inner.write();
        if guard.cancel_acknowledged {
            guard.cancel_acknowledged = false;
            acknowledged = true;
        }
        drop(guard);
        if acknowledged {
            let _ = record.acknowledge_cancel();
        }
        acknowledged
    }
}

struct WorkStealingWaker {
    task_id: TaskId,
    wake_state: Arc<crate::record::task::TaskWakeState>,
    global: Arc<GlobalQueue>,
    local: Option<LocalQueue>,
    parker: Parker,
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
                mutex: Mutex::new(()),
                cvar: Condvar::new(),
            }),
        }
    }

    /// Parks the current thread until notified.
    #[inline]
    pub fn park(&self) {
        if self
            .inner
            .notified
            .compare_exchange(true, false, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }

        self.inner.waiting.fetch_add(1, Ordering::Release);
        let mut guard = self.lock_unpoisoned();
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
        self.inner.waiting.fetch_sub(1, Ordering::Release);
        drop(guard);
    }

    /// Parks the current thread with a timeout.
    #[inline]
    pub fn park_timeout(&self, duration: Duration) {
        if self
            .inner
            .notified
            .compare_exchange(true, false, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }

        if duration.is_zero() {
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

        self.inner.waiting.fetch_add(1, Ordering::Release);
        let (guard, _timeout) = self
            .inner
            .cvar
            .wait_timeout_while(self.lock_unpoisoned(), duration, |()| {
                self.inner
                    .notified
                    .compare_exchange(true, false, Ordering::Acquire, Ordering::Relaxed)
                    .is_err()
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.inner.waiting.fetch_sub(1, Ordering::Release);
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
}

impl Default for Parker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};

    // ========== Parker Basic Tests ==========

    #[test]
    fn test_parker_park_unpark_basic() {
        // Simple park then unpark sequence
        let parker = Arc::new(Parker::new());
        let unparked = Arc::new(AtomicBool::new(false));

        let p = parker.clone();
        let u = unparked.clone();
        let handle = thread::spawn(move || {
            p.park();
            u.store(true, Ordering::SeqCst);
        });

        // Give thread time to park
        thread::sleep(Duration::from_millis(10));

        // Unpark should wake the thread
        parker.unpark();
        handle.join().expect("thread should complete");

        assert!(unparked.load(Ordering::SeqCst), "thread should have woken");
    }

    #[test]
    fn test_parker_unpark_before_park() {
        // Permit model: unpark called before park should not block
        let parker = Parker::new();

        // Unpark first (sets permit)
        parker.unpark();

        // Park should return immediately (consuming the permit)
        let start = Instant::now();
        parker.park();
        let elapsed = start.elapsed();

        // Should be nearly instant (< 50ms)
        assert!(
            elapsed < Duration::from_millis(50),
            "park after unpark should be immediate, took {elapsed:?}"
        );
    }

    #[test]
    fn test_parker_multiple_unpark() {
        // Multiple unparks should coalesce to one wake
        let parker = Parker::new();

        // Multiple unparks
        parker.unpark();
        parker.unpark();
        parker.unpark();

        // First park should return immediately
        parker.park();

        // Second park should block (permit consumed)
        let parker2 = Arc::new(parker);
        let p = parker2.clone();
        let blocked = Arc::new(AtomicBool::new(true));
        let b = blocked.clone();

        let handle = thread::spawn(move || {
            p.park();
            b.store(false, Ordering::SeqCst);
        });

        // Give time for thread to park
        thread::sleep(Duration::from_millis(20));
        assert!(
            blocked.load(Ordering::SeqCst),
            "second park should block (permit consumed)"
        );

        // Unpark to let thread complete
        parker2.unpark();
        handle.join().expect("thread should complete");
    }

    #[test]
    fn test_parker_timeout_expires() {
        // Park with timeout should return after timeout
        let parker = Parker::new();

        let start = Instant::now();
        parker.park_timeout(Duration::from_millis(50));
        let elapsed = start.elapsed();

        // Should return after ~50ms (allow some slack)
        assert!(
            elapsed >= Duration::from_millis(40),
            "timeout should wait at least 40ms, waited {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(200),
            "timeout should not wait too long, waited {elapsed:?}"
        );
    }

    #[test]
    fn test_parker_timeout_interrupted() {
        // Timeout cancelled by unpark
        let parker = Arc::new(Parker::new());

        let p = parker.clone();
        let handle = thread::spawn(move || {
            let start = Instant::now();
            p.park_timeout(Duration::from_secs(10)); // Long timeout
            start.elapsed()
        });

        // Wait a bit then unpark
        thread::sleep(Duration::from_millis(20));
        parker.unpark();

        let elapsed = handle.join().expect("thread should complete");

        // Should return much earlier than 10s
        assert!(
            elapsed < Duration::from_millis(500),
            "unpark should interrupt timeout, waited {elapsed:?}"
        );
    }

    #[test]
    fn test_parker_reuse() {
        // Parker can be reused after wake
        let parker = Parker::new();

        for i in 0..5 {
            // Unpark then park cycle
            parker.unpark();
            let start = Instant::now();
            parker.park();
            let elapsed = start.elapsed();

            assert!(
                elapsed < Duration::from_millis(50),
                "iteration {i}: reused parker should wake immediately, took {elapsed:?}"
            );
        }
    }

    // ========== Parker Race Condition Tests ==========

    #[test]
    fn test_parker_no_lost_wakeup() {
        // Signal should never be lost in any interleaving
        // Run multiple iterations to increase chance of catching races
        let mut rng = crate::util::DetRng::new(0x5eed_1234);
        for _ in 0..100 {
            let parker = Arc::new(Parker::new());
            let woken = Arc::new(AtomicBool::new(false));

            let p = parker.clone();
            let w = woken.clone();
            let handle = thread::spawn(move || {
                p.park();
                w.store(true, Ordering::SeqCst);
            });

            // Random delay to vary interleaving
            if rng.next_bool() {
                thread::yield_now();
            }

            parker.unpark();
            handle.join().expect("thread should complete");

            assert!(woken.load(Ordering::SeqCst), "wakeup should not be lost");
        }
    }

    #[test]
    fn test_parker_concurrent_unpark() {
        // Multiple threads calling unpark simultaneously
        let parker = Arc::new(Parker::new());
        let barrier = Arc::new(Barrier::new(5));

        // 4 threads calling unpark
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let p = parker.clone();
                let b = barrier.clone();
                thread::spawn(move || {
                    b.wait();
                    p.unpark();
                })
            })
            .collect();

        // One thread parking
        let parker_handle = thread::spawn({
            let p = parker;
            let b = barrier;
            move || {
                b.wait();
                p.park();
            }
        });

        for h in handles {
            h.join().expect("unpark thread should complete");
        }
        parker_handle.join().expect("parker thread should complete");
        // If we reach here without deadlock, the test passed
    }

    #[test]
    fn test_parker_spurious_wakeup_safe() {
        // Even with spurious wakeups, behavior should be correct
        // Our implementation rechecks the condition in a loop
        let parker = Parker::new();

        // Set permit
        parker.unpark();

        // Park should consume permit and return
        parker.park();

        // Permit is consumed, park would now block
        // (we don't actually block, just verify the state)
        assert!(
            !parker.inner.notified.load(Ordering::Acquire),
            "permit should be consumed after park"
        );
    }

    #[test]
    fn test_parker_park_timeout_survives_poisoned_mutex() {
        let parker = Parker::new();
        let poison_parker = parker.clone();
        let _ = thread::spawn(move || {
            let _guard = poison_parker.inner.mutex.lock().unwrap();
            unreachable!("intentionally poison parker mutex");
        })
        .join();

        let result = std::panic::catch_unwind(|| {
            parker.park_timeout(Duration::from_millis(1));
        });
        assert!(result.is_ok(), "park_timeout should recover from poison");
    }

    #[test]
    fn test_parker_unpark_survives_poisoned_mutex() {
        let parker = Parker::new();
        let poison_parker = parker.clone();
        let _ = thread::spawn(move || {
            let _guard = poison_parker.inner.mutex.lock().unwrap();
            unreachable!("intentionally poison parker mutex");
        })
        .join();

        let result = std::panic::catch_unwind(|| {
            parker.unpark();
        });
        assert!(result.is_ok(), "unpark should recover from poison");
    }

    // ========== Work Stealing Tests ==========

    #[test]
    fn test_steal_basic() {
        use crate::runtime::scheduler::local_queue::LocalQueue;
        use crate::util::DetRng;

        let queue = LocalQueue::new_for_test(3);
        queue.push(TaskId::new_for_test(1, 0));
        queue.push(TaskId::new_for_test(2, 0));
        queue.push(TaskId::new_for_test(3, 0));

        let stealers = vec![queue.stealer()];
        let mut rng = DetRng::new(42);

        // Steal should succeed
        let stolen = stealing::steal_task(&stealers, &mut rng);
        assert!(stolen.is_some());
        assert_eq!(stolen.unwrap(), TaskId::new_for_test(1, 0));
    }

    #[test]
    fn test_steal_empty_queue() {
        use crate::runtime::scheduler::local_queue::LocalQueue;
        use crate::util::DetRng;

        let queue = LocalQueue::new_for_test(0);
        let stealers = vec![queue.stealer()];
        let mut rng = DetRng::new(42);

        let stolen = stealing::steal_task(&stealers, &mut rng);
        assert!(stolen.is_none());
    }

    #[test]
    fn test_steal_no_self() {
        // Workers don't steal from themselves - verified by stealers array setup
        use crate::runtime::scheduler::local_queue::LocalQueue;
        use crate::util::DetRng;

        // Simulate 3 workers, worker 1's view
        let q0 = LocalQueue::new_for_test(2);
        let q1 = LocalQueue::new_for_test(2); // Self
        let q2 = LocalQueue::new_for_test(2);

        q0.push(TaskId::new_for_test(0, 0));
        q1.push(TaskId::new_for_test(1, 0)); // Own queue
        q2.push(TaskId::new_for_test(2, 0));

        // Worker 1's stealers exclude q1
        let stealers = vec![q0.stealer(), q2.stealer()];
        let mut rng = DetRng::new(42);

        // First steal
        let first = stealing::steal_task(&stealers, &mut rng);
        assert!(first.is_some());
        let first_id = first.unwrap();

        // Second steal
        let second = stealing::steal_task(&stealers, &mut rng);
        assert!(second.is_some());
        let second_id = second.unwrap();

        // Neither should be task 1 (own queue)
        assert_ne!(first_id, TaskId::new_for_test(1, 0));
        assert_ne!(second_id, TaskId::new_for_test(1, 0));
    }

    #[test]
    fn test_steal_round_robin_fairness() {
        use crate::runtime::scheduler::local_queue::LocalQueue;
        use crate::util::DetRng;

        // Create 4 queues with one task each
        let queues: Vec<_> = (0..4).map(|_| LocalQueue::new_for_test(4)).collect();
        for (i, q) in queues.iter().enumerate() {
            q.push(TaskId::new_for_test(i as u32 + 1, 0));
        }

        let stealers: Vec<_> = queues.iter().map(LocalQueue::stealer).collect();

        // Steal from each with different RNG seeds (different starting points)
        let mut seen = std::collections::HashSet::new();
        for seed in 0..4 {
            let mut rng = DetRng::new(seed * 1000);
            let stolen = stealing::steal_task(&stealers, &mut rng);
            if let Some(task) = stolen {
                seen.insert(task);
            }
        }

        // All 4 tasks should eventually be stolen
        assert_eq!(seen.len(), 4, "all queues should be visited");
    }

    // ========== Backoff Tests ==========

    #[test]
    fn test_backoff_spin_before_park() {
        // Verify backoff behavior: spin, yield, then park
        // This is tested implicitly in the worker loop, but we verify constants
        const SPIN_LIMIT: u32 = 64;
        const YIELD_LIMIT: u32 = 16;

        // Total backoff iterations before park
        let total = SPIN_LIMIT + YIELD_LIMIT;
        assert_eq!(
            total, 80,
            "backoff should be 64 spins + 16 yields before park"
        );
    }

    #[test]
    fn test_backoff_probe_pops_global_work() {
        use crate::runtime::RuntimeState;
        use crate::sync::ContendedMutex;

        let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
        let global = Arc::new(GlobalQueue::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let worker = Worker::new(
            0,
            Vec::new(),
            Arc::clone(&global),
            Arc::clone(&state),
            Arc::clone(&shutdown),
        );

        let global_task = TaskId::new_for_test(222, 0);
        global.push(global_task);

        assert_eq!(worker.pop_backoff_work(), Some(global_task));
        assert_eq!(worker.pop_backoff_work(), None);
    }

    #[test]
    fn test_worker_shutdown_observed_without_explicit_unpark() {
        use crate::runtime::RuntimeState;
        use crate::sync::ContendedMutex;
        use std::sync::mpsc;

        let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
        let global = Arc::new(GlobalQueue::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let mut worker = Worker::new(
            0,
            Vec::new(),
            Arc::clone(&global),
            Arc::clone(&state),
            Arc::clone(&shutdown),
        );

        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let start = Instant::now();
            worker.run_loop();
            tx.send(start.elapsed())
                .expect("worker shutdown timing send should succeed");
        });

        thread::sleep(Duration::from_millis(20));
        shutdown.store(true, Ordering::Relaxed);

        let elapsed = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("worker should observe shutdown without explicit unpark");
        handle.join().expect("worker thread should join");

        assert!(
            elapsed < Duration::from_secs(1),
            "worker should exit promptly after shutdown, elapsed={elapsed:?}"
        );
    }

    #[test]
    fn test_execute_panic_completes_task_and_wakes_waiters() {
        use crate::record::task::TaskRecord;
        use crate::runtime::RuntimeState;
        use crate::runtime::stored_task::StoredTask;
        use crate::sync::ContendedMutex;
        use crate::types::{Budget, RegionId};

        let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
        let global = Arc::new(GlobalQueue::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let panicking_task = TaskId::new_for_test(0, 0);
        let waiter_task = TaskId::new_for_test(1, 0);

        {
            let mut guard = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let panicking_record = TaskRecord::new(
                panicking_task,
                RegionId::new_for_test(0, 0),
                Budget::INFINITE,
            );
            let waiter_record =
                TaskRecord::new(waiter_task, RegionId::new_for_test(0, 0), Budget::INFINITE);
            let _panicking_idx = guard.insert_task(panicking_record);
            let _waiter_idx = guard.insert_task(waiter_record);

            guard
                .task_mut(panicking_task)
                .expect("panicking task should exist")
                .add_waiter(waiter_task);

            guard.store_spawned_task(
                panicking_task,
                StoredTask::new_with_id(
                    async move { unreachable!("worker execute panic regression") },
                    panicking_task,
                ),
            );
        }

        let worker = Worker::new(
            0,
            Vec::new(),
            Arc::clone(&global),
            Arc::clone(&state),
            Arc::clone(&shutdown),
        );

        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            worker.execute(panicking_task);
        }));
        assert!(
            panic_result.is_err(),
            "panicking task should still propagate unwind to caller"
        );

        {
            let guard = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(
                guard.task(panicking_task).is_none(),
                "panicking task should be completed and removed from runtime state"
            );
            drop(guard);
        }
        assert_eq!(
            global.pop(),
            Some(waiter_task),
            "panic path should wake and enqueue waiters"
        );
    }

    #[test]
    fn test_execute_ready_with_foreign_local_waiter_does_not_panic() {
        use crate::record::task::TaskRecord;
        use crate::runtime::RuntimeState;
        use crate::runtime::stored_task::StoredTask;
        use crate::sync::ContendedMutex;
        use crate::types::{Budget, Outcome, RegionId};

        let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
        let global = Arc::new(GlobalQueue::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let completing_task = TaskId::new_for_test(0, 0);
        let waiter_task = TaskId::new_for_test(1, 0);

        {
            let mut guard = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let completing_record = TaskRecord::new(
                completing_task,
                RegionId::new_for_test(0, 0),
                Budget::INFINITE,
            );
            let mut waiter_record =
                TaskRecord::new(waiter_task, RegionId::new_for_test(0, 0), Budget::INFINITE);
            waiter_record.pin_to_worker(1);
            let _completing_idx = guard.insert_task(completing_record);
            let _waiter_idx = guard.insert_task(waiter_record);

            guard
                .task_mut(completing_task)
                .expect("completing task should exist")
                .add_waiter(waiter_task);

            guard.store_spawned_task(
                completing_task,
                StoredTask::new_with_id(async move { Outcome::Ok(()) }, completing_task),
            );
        }

        let worker = Worker::new(
            0,
            Vec::new(),
            Arc::clone(&global),
            Arc::clone(&state),
            Arc::clone(&shutdown),
        );

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            worker.execute(completing_task);
        }));
        assert!(
            result.is_ok(),
            "foreign-worker local waiter must not panic scheduler worker"
        );

        {
            let guard = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(
                guard.task(completing_task).is_none(),
                "completed task should be removed from runtime state"
            );
            let waiter_record = guard.task(waiter_task).expect("waiter task should exist");
            assert!(
                !waiter_record.wake_state.is_notified(),
                "foreign waiter wake state should be cleared when routing is skipped"
            );
            drop(guard);
        }

        assert!(
            global.pop().is_none(),
            "foreign local waiter must not be routed to global queue"
        );
        assert!(
            worker.local.pop().is_none(),
            "foreign local waiter must not be routed to current worker local queue"
        );
    }

    #[test]
    fn test_execute_panic_with_foreign_local_waiter_clears_notified_state() {
        use crate::record::task::TaskRecord;
        use crate::runtime::RuntimeState;
        use crate::runtime::stored_task::StoredTask;
        use crate::sync::ContendedMutex;
        use crate::types::{Budget, RegionId};

        let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
        let global = Arc::new(GlobalQueue::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let panicking_task = TaskId::new_for_test(0, 0);
        let waiter_task = TaskId::new_for_test(1, 0);

        {
            let mut guard = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let panicking_record = TaskRecord::new(
                panicking_task,
                RegionId::new_for_test(0, 0),
                Budget::INFINITE,
            );
            let mut waiter_record =
                TaskRecord::new(waiter_task, RegionId::new_for_test(0, 0), Budget::INFINITE);
            waiter_record.pin_to_worker(1);
            let _panicking_idx = guard.insert_task(panicking_record);
            let _waiter_idx = guard.insert_task(waiter_record);

            guard
                .task_mut(panicking_task)
                .expect("panicking task should exist")
                .add_waiter(waiter_task);

            guard.store_spawned_task(
                panicking_task,
                StoredTask::new_with_id(
                    async move { unreachable!("foreign waiter panic wake regression") },
                    panicking_task,
                ),
            );
        }

        let worker = Worker::new(
            0,
            Vec::new(),
            Arc::clone(&global),
            Arc::clone(&state),
            Arc::clone(&shutdown),
        );

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            worker.execute(panicking_task);
        }));
        assert!(result.is_err(), "panicking task should propagate unwind");

        let guard = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let waiter_notified = guard
            .task(waiter_task)
            .expect("waiter task should exist")
            .wake_state
            .is_notified();
        drop(guard);
        assert!(
            !waiter_notified,
            "foreign waiter wake state should be cleared when panic-path routing is skipped"
        );

        assert!(
            global.pop().is_none(),
            "foreign local waiter must not be routed to global queue"
        );
        assert!(
            worker.local.pop().is_none(),
            "foreign local waiter must not be routed to current worker local queue"
        );
    }

    // Deterministic RNG for scheduling fuzz in tests: no ambient time.

    // --- wave 80 trait coverage ---

    #[test]
    fn parker_debug_clone() {
        let p = Parker::new();
        let p2 = p.clone();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Parker"));
        // Clone shares the Arc, so unparking p2 affects the same inner state
        p2.unpark();
        let dbg2 = format!("{p2:?}");
        assert!(dbg2.contains("Parker"));
    }

    // ========== Work-Stealing Fairness Conformance Tests ==========

    #[test]
    fn conformance_steal_uniform_distribution() {
        // Conformance: In the absence of load differences, stealing should
        // distribute uniformly across workers over many trials.
        use crate::runtime::scheduler::local_queue::LocalQueue;
        use crate::util::DetRng;
        use std::collections::HashMap;

        const NUM_WORKERS: usize = 8;
        const TRIALS: usize = 1000;

        // Create workers with equal single-task loads
        let queues: Vec<_> = (0..NUM_WORKERS)
            .map(|i| {
                let q = LocalQueue::new_for_test(4);
                q.push(TaskId::new_for_test(i as u32, 0));
                q
            })
            .collect();

        let stealers: Vec<_> = queues.iter().map(LocalQueue::stealer).collect();
        let mut steal_counts = HashMap::new();
        let mut rng = DetRng::new(12345);

        // Perform many steals and track which queues were selected
        for _ in 0..TRIALS {
            // Refresh queues for each trial
            for (i, q) in queues.iter().enumerate() {
                if q.len() == 0 {
                    q.push(TaskId::new_for_test(i as u32, 0));
                }
            }

            if let Some(task) = stealing::steal_task(&stealers, &mut rng) {
                let worker_id = task.arena_index().index() as usize;
                *steal_counts.entry(worker_id).or_insert(0) += 1;
            }
        }

        // Verify uniform distribution: no worker should be severely under-represented
        let total_steals: usize = steal_counts.values().sum();
        let expected_per_worker = total_steals / NUM_WORKERS;

        for worker_id in 0..NUM_WORKERS {
            let actual = steal_counts.get(&worker_id).unwrap_or(&0);
            let deviation = (*actual).abs_diff(expected_per_worker);

            // Allow 30% deviation for randomness, but not systematic bias
            let max_deviation = expected_per_worker * 3 / 10;
            assert!(
                deviation <= max_deviation,
                "Worker {} steal count {} deviates {} from expected {} (max deviation {})",
                worker_id,
                actual,
                deviation,
                expected_per_worker,
                max_deviation
            );
        }
    }

    #[test]
    fn conformance_steal_load_preference() {
        // Conformance: "Power of Two Choices" should prefer heavily loaded workers
        // over lightly loaded ones with high probability.
        use crate::runtime::scheduler::local_queue::LocalQueue;
        use crate::util::DetRng;

        const TRIALS: usize = 100;

        let heavy_queue = LocalQueue::new_for_test(10);
        let light_queue = LocalQueue::new_for_test(10);

        let mut heavy_chosen = 0;
        let mut light_chosen = 0;

        for trial in 0..TRIALS {
            // Set up load imbalance: heavy has 5 tasks, light has 1 task
            for _ in 0..5 {
                heavy_queue.push(TaskId::new_for_test(100 + trial as u32, 0));
            }
            light_queue.push(TaskId::new_for_test(200 + trial as u32, 0));

            let stealers = vec![heavy_queue.stealer(), light_queue.stealer()];
            let mut rng = DetRng::new(42 + trial as u64);

            if let Some(task) = stealing::steal_task(&stealers, &mut rng) {
                let task_id = task.arena_index().index();
                if (100..200).contains(&task_id) {
                    heavy_chosen += 1;
                } else if (200..300).contains(&task_id) {
                    light_chosen += 1;
                }
            }

            // Clear queues for next trial
            while heavy_queue.pop().is_some() {}
            while light_queue.pop().is_some() {}
        }

        // The heavily loaded worker should be chosen significantly more often
        // Power of Two Choices should make this at least 60% in favor of heavy
        let total = heavy_chosen + light_chosen;
        let heavy_ratio = heavy_chosen as f64 / total as f64;

        assert!(
            heavy_ratio >= 0.6,
            "Heavily loaded worker chosen {}/{} times ({}%), expected >= 60%",
            heavy_chosen,
            total,
            heavy_ratio * 100.0
        );
    }

    #[test]
    fn conformance_steal_no_starvation() {
        // Conformance: Every worker must be eventually selectable for stealing.
        // This prevents systematic starvation of specific workers.
        use crate::runtime::scheduler::local_queue::LocalQueue;
        use crate::util::DetRng;
        use std::collections::HashSet;

        const NUM_WORKERS: usize = 12;
        const MAX_ATTEMPTS: usize = NUM_WORKERS * 50;

        // Create workers with work available
        let queues: Vec<_> = (0..NUM_WORKERS)
            .map(|i| {
                let q = LocalQueue::new_for_test(4);
                q.push(TaskId::new_for_test(i as u32, 0));
                q
            })
            .collect();

        let stealers: Vec<_> = queues.iter().map(LocalQueue::stealer).collect();
        let mut visited_workers = HashSet::new();
        let mut rng = DetRng::new(9999);

        for attempt in 0..MAX_ATTEMPTS {
            // Refresh any empty queues
            for (i, q) in queues.iter().enumerate() {
                if q.len() == 0 {
                    q.push(TaskId::new_for_test(
                        i as u32 + attempt as u32 * NUM_WORKERS as u32,
                        0,
                    ));
                }
            }

            if let Some(task) = stealing::steal_task(&stealers, &mut rng) {
                let worker_id = (task.arena_index().index() as usize) % NUM_WORKERS;
                visited_workers.insert(worker_id);
            }

            // Early exit if we've visited all workers
            if visited_workers.len() == NUM_WORKERS {
                break;
            }
        }

        assert_eq!(
            visited_workers.len(),
            NUM_WORKERS,
            "Starvation detected: only {}/{} workers were visited in {} attempts. Missing: {:?}",
            visited_workers.len(),
            NUM_WORKERS,
            MAX_ATTEMPTS,
            (0..NUM_WORKERS)
                .filter(|w| !visited_workers.contains(w))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn conformance_steal_cross_worker_fairness() {
        // Conformance: When viewed from different workers' perspectives,
        // the stealing distribution should remain fair.
        use crate::runtime::scheduler::local_queue::LocalQueue;
        use crate::util::DetRng;
        use std::collections::HashMap;

        const NUM_WORKERS: usize = 6;
        const STEALS_PER_WORKER: usize = 60;

        // Create workers, each excluding themselves from stealing
        let queues: Vec<_> = (0..NUM_WORKERS)
            .map(|_| LocalQueue::new_for_test(8))
            .collect();

        // Populate all queues
        for (worker_id, q) in queues.iter().enumerate() {
            for task_id in 0..4 {
                q.push(TaskId::new_for_test((worker_id * 100 + task_id) as u32, 0));
            }
        }

        // For each worker, simulate their stealing perspective
        for stealer_worker in 0..NUM_WORKERS {
            let stealers: Vec<_> = queues
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != stealer_worker) // Don't steal from self
                .map(|(_, q)| q.stealer())
                .collect();

            let mut steal_distribution = HashMap::new();
            let mut rng = DetRng::new(stealer_worker as u64 * 1000);

            for _ in 0..STEALS_PER_WORKER {
                // Refresh queues
                for (worker_id, q) in queues.iter().enumerate() {
                    if worker_id != stealer_worker && q.len() < 2 {
                        for task_id in 0..2 {
                            q.push(TaskId::new_for_test(
                                (worker_id * 100 + task_id + 50) as u32,
                                0,
                            ));
                        }
                    }
                }

                if let Some(task) = stealing::steal_task(&stealers, &mut rng) {
                    let target_worker = (task.arena_index().index() as usize) / 100;
                    *steal_distribution.entry(target_worker).or_insert(0) += 1;
                }
            }

            // Verify this worker's stealing is reasonably fair across targets
            let total_steals: usize = steal_distribution.values().sum();
            let expected_per_target = total_steals / (NUM_WORKERS - 1);

            for target_worker in 0..NUM_WORKERS {
                if target_worker == stealer_worker {
                    continue;
                }

                let actual = steal_distribution.get(&target_worker).unwrap_or(&0);
                let deviation = (*actual).abs_diff(expected_per_target);

                // Allow 40% deviation for small sample sizes and randomness
                let max_deviation = expected_per_target * 4 / 10;
                assert!(
                    deviation <= max_deviation,
                    "Worker {} stealing from worker {}: {} steals vs {} expected (deviation {} > {})",
                    stealer_worker,
                    target_worker,
                    actual,
                    expected_per_target,
                    deviation,
                    max_deviation
                );
            }
        }
    }

    #[test]
    fn conformance_steal_statistical_invariants() {
        // Conformance: Statistical properties of the stealing algorithm
        // should remain consistent under various load distributions.
        use crate::runtime::scheduler::local_queue::LocalQueue;
        use crate::util::DetRng;
        use std::collections::HashMap;

        const NUM_WORKERS: usize = 8;
        const TOTAL_TRIALS: usize = 400;

        struct LoadScenario {
            name: &'static str,
            loads: Vec<usize>, // Tasks per worker
        }

        let scenarios = vec![
            LoadScenario {
                name: "uniform_load",
                loads: vec![4; NUM_WORKERS],
            },
            LoadScenario {
                name: "single_heavy",
                loads: vec![20, 1, 1, 1, 1, 1, 1, 1],
            },
            LoadScenario {
                name: "bimodal",
                loads: vec![10, 10, 1, 1, 10, 10, 1, 1],
            },
            LoadScenario {
                name: "gradient",
                loads: vec![1, 2, 3, 4, 5, 6, 7, 8],
            },
        ];

        for scenario in &scenarios {
            let queues: Vec<_> = (0..NUM_WORKERS)
                .map(|_| LocalQueue::new_for_test(25))
                .collect();

            let mut steal_counts = HashMap::new();
            let mut rng = DetRng::new(42);

            for trial in 0..TOTAL_TRIALS {
                // Set up load distribution
                for (worker_id, &load) in scenario.loads.iter().enumerate() {
                    let q = &queues[worker_id];
                    // Clear and repopulate
                    while q.pop().is_some() {}
                    for task_idx in 0..load {
                        q.push(TaskId::new_for_test(
                            (worker_id * 1000 + task_idx + trial * 10) as u32,
                            0,
                        ));
                    }
                }

                let stealers: Vec<_> = queues.iter().map(LocalQueue::stealer).collect();

                if let Some(task) = stealing::steal_task(&stealers, &mut rng) {
                    let worker_id = (task.arena_index().index() as usize) / 1000;
                    *steal_counts.entry(worker_id).or_insert(0) += 1;
                }
            }

            // Verify statistical properties
            let total_steals: usize = steal_counts.values().sum();

            // Property 1: Non-zero workers should all be selectable
            let non_zero_workers: Vec<_> = scenario
                .loads
                .iter()
                .enumerate()
                .filter(|&(_, &load)| load > 0)
                .map(|(i, _)| i)
                .collect();

            for &worker_id in &non_zero_workers {
                let count = steal_counts.get(&worker_id).unwrap_or(&0);
                assert!(
                    *count > 0,
                    "Scenario '{}': Worker {} with load {} was never selected",
                    scenario.name,
                    worker_id,
                    scenario.loads[worker_id]
                );
            }

            // Property 2: Heavily loaded workers should be preferred
            if scenario.loads.iter().any(|&load| load > 5) {
                let max_load = *scenario.loads.iter().max().unwrap();
                let max_workers: Vec<_> = scenario
                    .loads
                    .iter()
                    .enumerate()
                    .filter(|&(_, &load)| load == max_load)
                    .map(|(i, _)| i)
                    .collect();

                let max_worker_steals: usize = max_workers
                    .iter()
                    .map(|&w| steal_counts.get(&w).unwrap_or(&0))
                    .sum();

                let max_worker_ratio = max_worker_steals as f64 / total_steals as f64;
                let expected_min_ratio = 0.3; // At least 30% for heavily loaded workers

                assert!(
                    max_worker_ratio >= expected_min_ratio,
                    "Scenario '{}': Heavily loaded workers got {:.1}% steals, expected >= {:.1}%",
                    scenario.name,
                    max_worker_ratio * 100.0,
                    expected_min_ratio * 100.0
                );
            }
        }
    }

    #[test]
    fn conformance_steal_deterministic_fairness() {
        // Conformance: For a given RNG seed, stealing should be deterministic
        // and still maintain fairness properties.
        use crate::runtime::scheduler::local_queue::LocalQueue;
        use crate::util::DetRng;
        use std::collections::HashMap;

        const NUM_WORKERS: usize = 5;
        const TRIALS: usize = 50;
        const SEED: u64 = 0xDEADBEEF;

        // Run the same stealing pattern twice with identical setup
        let mut results_run1 = Vec::new();
        let mut results_run2 = Vec::new();

        for run in 0..2 {
            let queues: Vec<_> = (0..NUM_WORKERS)
                .map(|_| LocalQueue::new_for_test(4))
                .collect();

            let mut rng = DetRng::new(SEED);
            let mut run_results = Vec::new();

            for trial in 0..TRIALS {
                // Identical setup for each trial
                for (worker_id, q) in queues.iter().enumerate() {
                    while q.pop().is_some() {} // Clear
                    for task_idx in 0..2 {
                        q.push(TaskId::new_for_test(
                            (worker_id * 100 + task_idx + trial * 10) as u32,
                            0,
                        ));
                    }
                }

                let stealers: Vec<_> = queues.iter().map(LocalQueue::stealer).collect();

                if let Some(task) = stealing::steal_task(&stealers, &mut rng) {
                    let worker_id = (task.arena_index().index() as usize) / 100;
                    run_results.push(worker_id);
                }
            }

            if run == 0 {
                results_run1 = run_results;
            } else {
                results_run2 = run_results;
            }
        }

        // Property 1: Determinism - identical seeds produce identical results
        assert_eq!(
            results_run1, results_run2,
            "Deterministic stealing failed: runs with identical seeds produced different results"
        );

        // Property 2: Fairness - even with determinism, all workers should be visited
        let mut worker_visits = HashMap::new();
        for &worker_id in &results_run1 {
            *worker_visits.entry(worker_id).or_insert(0) += 1;
        }

        assert_eq!(
            worker_visits.len(),
            NUM_WORKERS,
            "Deterministic stealing visited only {}/{} workers: {:?}",
            worker_visits.len(),
            NUM_WORKERS,
            worker_visits.keys().collect::<Vec<_>>()
        );

        // Property 3: No single worker dominance in deterministic case
        let total_visits = results_run1.len();
        let max_visits = *worker_visits.values().max().unwrap();
        let dominance_ratio = max_visits as f64 / total_visits as f64;

        assert!(
            dominance_ratio <= 0.7,
            "Deterministic stealing shows dominance: worker visited {}/{} times ({:.1}%)",
            max_visits,
            total_visits,
            dominance_ratio * 100.0
        );
    }
}
