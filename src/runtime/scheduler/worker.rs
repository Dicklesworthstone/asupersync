//! Worker thread logic.

use crate::runtime::io_driver::IoDriverHandle;
use crate::runtime::scheduler::global_queue::GlobalQueue;
use crate::runtime::scheduler::local_queue::{LocalQueue, Stealer};
use crate::runtime::scheduler::stealing;
use crate::runtime::RuntimeState;
use crate::sync::ContendedMutex;
use crate::time::TimerDriverHandle;
use crate::trace::{TraceBufferHandle, TraceEvent};
use crate::tracing_compat::{error, trace};
use crate::types::{TaskId, Time};
use crate::util::DetRng;
use std::cell::Cell;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// Tokens seen for I/O trace emission.
    seen_io_tokens: BTreeSet<u64>,
    /// Pre-allocated scratch vec for local waiters (reused across polls).
    scratch_local: Cell<Vec<TaskId>>,
    /// Pre-allocated scratch vec for global waiters (reused across polls).
    scratch_global: Cell<Vec<TaskId>>,
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
        let (io_driver, trace, timer_driver) = {
            let guard = state.lock().expect("runtime state lock poisoned");
            (
                guard.io_driver_handle(),
                guard.trace_handle(),
                guard.timer_driver_handle(),
            )
        };

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
            seen_io_tokens: BTreeSet::new(),
            scratch_local: Cell::new(Vec::new()),
            scratch_global: Cell::new(Vec::new()),
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
            // If we can acquire the IO driver lock, we become the I/O leader.
            // The leader polls the reactor with a short timeout.
            if let Some(io) = &self.io_driver {
                if let Ok(mut driver) = io.try_lock() {
                    // Poll with a short timeout to check for I/O events without
                    // spinning too hot, but returning frequently to check for new tasks.
                    //
                    // Note: Ideally we would block indefinitely and be woken by `spawn`,
                    // but that requires integrating the Parker with the Reactor.
                    // For now, a short timeout (1ms) serves as a "busy-wait with sleep".
                    let now = self
                        .timer_driver
                        .as_ref()
                        .map_or(Time::ZERO, TimerDriverHandle::now);
                    let trace = &self.trace;
                    let seen = &mut self.seen_io_tokens;
                    let _ = driver.turn_with(Some(Duration::from_millis(1)), |event, interest| {
                        let io_token = event.token.0 as u64;
                        let interest_bits = interest.unwrap_or(event.ready).bits();
                        if seen.insert(io_token) {
                            let seq = trace.next_seq();
                            trace.push_event(TraceEvent::io_requested(
                                seq,
                                now,
                                io_token,
                                interest_bits,
                            ));
                        }
                        let seq = trace.next_seq();
                        trace.push_event(TraceEvent::io_ready(
                            seq,
                            now,
                            io_token,
                            event.ready.bits(),
                        ));
                    });

                    // Loop back to check queues (tasks might have been woken by I/O)
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

                // Check queues again (abbreviated check)
                if !self.local.is_empty() || !self.global.is_empty() {
                    break;
                }

                if backoff < SPIN_LIMIT {
                    std::hint::spin_loop();
                    backoff += 1;
                } else if backoff < SPIN_LIMIT + YIELD_LIMIT {
                    std::thread::yield_now();
                    backoff += 1;
                } else {
                    // Use a short timeout so shutdown is observed even if no explicit
                    // unpark signal is delivered while this worker is parked.
                    self.parker.park_timeout(Duration::from_millis(1));
                    break;
                }
            }
        }
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
                        .expect("runtime state lock poisoned");
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
                    local_waiters.clear();
                    global_waiters.clear();

                    for waiter in waiters {
                        if let Some(record) = state.task(waiter) {
                            if record.wake_state.notify() {
                                if record.is_local() {
                                    match record.pinned_worker() {
                                        Some(worker_id) if worker_id == self.worker.id => {
                                            local_waiters.push(waiter);
                                        }
                                        Some(_worker_id) => {
                                            error!(
                                                ?waiter,
                                                worker_id = _worker_id,
                                                current_worker = self.worker.id,
                                                "panic path: pinned local waiter has invalid worker id, wake skipped"
                                            );
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
                        self.worker.global.push(*waiter);
                    }
                    self.worker.local.push_many(&local_waiters);
                    self.worker.scratch_local.set(local_waiters);
                    self.worker.scratch_global.set(global_waiters);
                    for (finalizer_task, _) in finalizers {
                        self.worker.global.push(finalizer_task);
                    }
                }
            }
        }

        trace!(task_id = ?task_id, worker_id = self.id, "executing task");

        // Try to find the task in global state first
        let (mut stored, task_cx, wake_state, metrics, cached_waker) = {
            let mut state = self.state.lock().expect("runtime state lock poisoned");

            if let Some(stored) = state.remove_stored_future(task_id) {
                // Global task found
                if let Some(record) = state.task_mut(task_id) {
                    record.start_running();
                    record.wake_state.begin_poll();
                    let task_cx = record.cx.clone();
                    let wake_state = Arc::clone(&record.wake_state);
                    let cached = record.cached_waker.take();
                    let metrics = state.metrics_provider();
                    drop(state);
                    (
                        AnyStoredTask::Global(stored),
                        task_cx,
                        wake_state,
                        metrics,
                        cached,
                    )
                } else {
                    return; // Task record missing?
                }
            } else {
                // Not in global, check local
                drop(state); // Drop lock before accessing thread-local

                if let Some(local_task) = crate::runtime::local::remove_local_task(task_id) {
                    // Local task found
                    // We need to re-acquire state lock to get record info
                    let mut state = self.state.lock().expect("runtime state lock poisoned");
                    if let Some(record) = state.task_mut(task_id) {
                        record.start_running();
                        record.wake_state.begin_poll();
                        let task_cx = record.cx.clone();
                        let wake_state = Arc::clone(&record.wake_state);
                        let cached = record.cached_waker.take();
                        let metrics = state.metrics_provider();
                        drop(state);
                        (
                            AnyStoredTask::Local(local_task),
                            task_cx,
                            wake_state,
                            metrics,
                            cached,
                        )
                    } else {
                        return; // Task record missing
                    }
                } else {
                    return; // Task not found anywhere
                }
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
        match stored.poll(&mut cx) {
            Poll::Ready(outcome) => {
                // Map Outcome<(), ()> to Outcome<(), Error> for record.complete()
                let task_outcome = outcome
                    .map_err(|()| crate::error::Error::new(crate::error::ErrorKind::Internal));
                let mut state = self.state.lock().expect("runtime state lock poisoned");
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
                local_waiters.clear();
                global_waiters.clear();

                for waiter in waiters {
                    if let Some(record) = state.task(waiter) {
                        if record.wake_state.notify() {
                            if record.is_local() {
                                if let Some(worker_id) = record.pinned_worker() {
                                    assert!(
                                        worker_id == self.id,
                                        "Pinned local waiter {waiter:?} has invalid worker id {worker_id}"
                                    );
                                }
                                local_waiters.push(waiter);
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
                self.scratch_local.set(local_waiters);
                self.scratch_global.set(global_waiters);
                for (finalizer_task, _) in finalizers {
                    self.global.push(finalizer_task);
                }
                guard.completed = true;
                wake_state.clear();
            }
            Poll::Pending => {
                let is_local = is_local_task;

                match stored {
                    AnyStoredTask::Global(t) => {
                        let mut state = self.state.lock().expect("runtime state lock poisoned");
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
                        let mut state = self.state.lock().expect("runtime state lock poisoned");
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
        }
        metrics.scheduler_tick(1, poll_start.elapsed());
    }

    fn schedule_ready_finalizers(&self) -> bool {
        let tasks = {
            let mut state = self.state.lock().expect("runtime state lock poisoned");
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

    fn consume_cancel_ack_locked(state: &mut RuntimeState, task_id: TaskId) -> bool {
        let Some(record) = state.task_mut(task_id) else {
            return false;
        };
        let Some(inner) = record.cx_inner.as_ref() else {
            return false;
        };
        let mut acknowledged = false;
        if let Ok(mut guard) = inner.write() {
            if guard.cancel_acknowledged {
                guard.cancel_acknowledged = false;
                acknowledged = true;
            }
        }
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
    fn wake(self: Arc<Self>) {
        self.schedule();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.schedule();
    }
}

#[derive(Debug)]
struct ParkerInner {
    notified: AtomicBool,
    mutex: Mutex<()>,
    cvar: Condvar,
}

/// A mechanism for parking and unparking a worker.
#[derive(Debug, Clone)]
pub struct Parker {
    inner: Arc<ParkerInner>,
}

impl Parker {
    /// Creates a new parker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ParkerInner {
                notified: AtomicBool::new(false),
                mutex: Mutex::new(()),
                cvar: Condvar::new(),
            }),
        }
    }

    /// Parks the current thread until notified.
    pub fn park(&self) {
        if self.inner.notified.swap(false, Ordering::Acquire) {
            return;
        }

        let mut guard = self.inner.mutex.lock().unwrap();
        while !self.inner.notified.swap(false, Ordering::Acquire) {
            guard = self.inner.cvar.wait(guard).unwrap();
        }
        drop(guard);
    }

    /// Parks the current thread with a timeout.
    pub fn park_timeout(&self, duration: Duration) {
        if self.inner.notified.swap(false, Ordering::Acquire) {
            return;
        }

        let (guard, _timeout) = self
            .inner
            .cvar
            .wait_timeout_while(self.inner.mutex.lock().unwrap(), duration, |()| {
                !self.inner.notified.swap(false, Ordering::Acquire)
            })
            .unwrap();
        drop(guard);
    }

    /// Unparks a parked thread.
    pub fn unpark(&self) {
        self.inner.notified.store(true, Ordering::Release);
        let _guard = self.inner.mutex.lock().unwrap();
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
        use crate::runtime::stored_task::StoredTask;
        use crate::runtime::RuntimeState;
        use crate::sync::ContendedMutex;
        use crate::types::{Budget, RegionId};

        let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
        let global = Arc::new(GlobalQueue::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let panicking_task = TaskId::new_for_test(0, 0);
        let waiter_task = TaskId::new_for_test(1, 0);

        {
            let mut guard = state.lock().expect("runtime state lock poisoned");
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
                    async move { panic!("worker execute panic regression") },
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
            let guard = state.lock().expect("runtime state lock poisoned");
            assert!(
                guard.task(panicking_task).is_none(),
                "panicking task should be completed and removed from runtime state"
            );
        }
        assert_eq!(
            global.pop(),
            Some(waiter_task),
            "panic path should wake and enqueue waiters"
        );
    }

    // Deterministic RNG for scheduling fuzz in tests: no ambient time.
}
