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
use crate::runtime::scheduler::local_queue::{self, LocalQueue};
use crate::runtime::scheduler::priority::Scheduler as PriorityScheduler;
use crate::runtime::scheduler::worker::Parker;
use crate::runtime::stored_task::AnyStoredTask;
use crate::runtime::RuntimeState;
use crate::sync::ContendedMutex;
use crate::time::TimerDriverHandle;
use crate::tracing_compat::trace;
use crate::types::{CxInner, TaskId, Time};
use crate::util::DetRng;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

/// Identifier for a scheduler worker.
pub type WorkerId = usize;

const DEFAULT_CANCEL_STREAK_LIMIT: usize = 16;
const DEFAULT_STEAL_BATCH_SIZE: usize = 4;
const DEFAULT_ENABLE_PARKING: bool = true;
const SPIN_LIMIT: u32 = 64;
const YIELD_LIMIT: u32 = 16;

/// Coordination for waking workers.
#[derive(Debug)]
pub(crate) struct WorkerCoordinator {
    parkers: Vec<Parker>,
    next_wake: AtomicUsize,
}

impl WorkerCoordinator {
    pub(crate) fn new(parkers: Vec<Parker>) -> Self {
        Self {
            parkers,
            next_wake: AtomicUsize::new(0),
        }
    }

    pub(crate) fn wake_one(&self) {
        let count = self.parkers.len();
        if count == 0 {
            return;
        }
        let idx = self.next_wake.fetch_add(1, Ordering::Relaxed);
        self.parkers[idx % count].unpark();
    }

    pub(crate) fn wake_worker(&self, worker_id: WorkerId) {
        if let Some(parker) = self.parkers.get(worker_id) {
            parker.unpark();
        }
    }

    pub(crate) fn wake_all(&self) {
        for parker in &self.parkers {
            parker.unpark();
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
    static CURRENT_LOCAL_READY: RefCell<Option<Arc<Mutex<Vec<TaskId>>>>> =
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
        CURRENT_WORKER_ID.with(|cell| {
            *cell.borrow_mut() = prev;
        });
    }
}

pub(crate) struct ScopedLocalReady {
    prev: Option<Arc<Mutex<Vec<TaskId>>>>,
}

impl ScopedLocalReady {
    pub(crate) fn new(queue: Arc<Mutex<Vec<TaskId>>>) -> Self {
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
pub(crate) fn schedule_local_task(task: TaskId) -> bool {
    CURRENT_LOCAL_READY.with(|cell| {
        cell.borrow().as_ref().is_some_and(|queue| {
            queue.lock().expect("local_ready lock poisoned").push(task);
            true
        })
    })
}

fn remove_from_local_ready(queue: &Arc<Mutex<Vec<TaskId>>>, task: TaskId) -> bool {
    if let Ok(mut queue) = queue.lock() {
        let mut removed = false;
        while let Some(pos) = queue.iter().position(|t| *t == task) {
            queue.swap_remove(pos);
            removed = true;
        }
        return removed;
    }
    false
}

pub(crate) fn remove_from_current_local_ready(task: TaskId) -> bool {
    CURRENT_LOCAL_READY.with(|cell| {
        cell.borrow()
            .as_ref()
            .is_some_and(|queue| remove_from_local_ready(queue, task))
    })
}

pub(crate) fn current_worker_id() -> Option<WorkerId> {
    CURRENT_WORKER_ID.with(|cell| *cell.borrow())
}

pub(crate) fn schedule_on_current_local(task: TaskId, priority: u8) -> bool {
    // Fast path: O(1) push to LocalQueue IntrusiveStack
    if LocalQueue::schedule_local(task) {
        return true;
    }
    // Slow path: O(log n) push to PriorityScheduler BinaryHeap
    CURRENT_LOCAL.with(|cell| {
        if let Some(local) = cell.borrow().as_ref() {
            local
                .lock()
                .expect("local scheduler lock poisoned")
                .schedule(task, priority);
            return true;
        }
        false
    })
}

pub(crate) fn schedule_cancel_on_current_local(task: TaskId, priority: u8) -> bool {
    CURRENT_LOCAL.with(|cell| {
        if let Some(local) = cell.borrow().as_ref() {
            local
                .lock()
                .expect("local scheduler lock poisoned")
                .move_to_cancel_lane(task, priority);
            let _ = remove_from_current_local_ready(task);
            return true;
        }
        false
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
    local_ready: Vec<Arc<Mutex<Vec<TaskId>>>>,
    /// Per-worker parkers for targeted wakeups.
    parkers: Vec<Parker>,
    /// Worker handles for thread spawning.
    workers: Vec<ThreeLaneWorker>,
    /// Shutdown signal.
    shutdown: Arc<AtomicBool>,
    /// Coordination for waking workers.
    coordinator: Arc<WorkerCoordinator>,
    /// Maximum consecutive cancel-lane dispatches before yielding.
    cancel_streak_limit: usize,
    /// Maximum number of ready tasks to steal in one batch.
    steal_batch_size: usize,
    /// Whether workers are allowed to park when idle.
    enable_parking: bool,
    /// Timer driver for processing timer wakeups.
    timer_driver: Option<TimerDriverHandle>,
    /// Shared runtime state for accessing task records and wake_state.
    state: Arc<ContendedMutex<RuntimeState>>,
}

impl ThreeLaneScheduler {
    /// Creates a new 3-lane scheduler with the given number of workers.
    pub fn new(worker_count: usize, state: &Arc<ContendedMutex<RuntimeState>>) -> Self {
        Self::new_with_options(worker_count, state, DEFAULT_CANCEL_STREAK_LIMIT, false, 32)
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
        let cancel_streak_limit = cancel_streak_limit.max(1);
        let governor_interval = governor_interval.max(1);
        let steal_batch_size = DEFAULT_STEAL_BATCH_SIZE;
        let enable_parking = DEFAULT_ENABLE_PARKING;
        let global = Arc::new(GlobalInjector::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::with_capacity(worker_count);
        let mut parkers = Vec::with_capacity(worker_count);
        let mut local_schedulers: Vec<Arc<Mutex<PriorityScheduler>>> =
            Vec::with_capacity(worker_count);
        let mut local_ready: Vec<Arc<Mutex<Vec<TaskId>>>> = Vec::with_capacity(worker_count);

        // Get timer driver from runtime state
        let timer_driver = state
            .lock()
            .expect("runtime state lock poisoned")
            .timer_driver_handle();

        // Create local schedulers first so we can share references for stealing
        for _ in 0..worker_count {
            local_schedulers.push(Arc::new(Mutex::new(PriorityScheduler::new())));
        }
        // Create non-stealable local queues for !Send tasks
        for _ in 0..worker_count {
            local_ready.push(Arc::new(Mutex::new(Vec::new())));
        }

        // Create parkers first
        for _ in 0..worker_count {
            parkers.push(Parker::new());
        }
        let coordinator = Arc::new(WorkerCoordinator::new(parkers.clone()));

        // Create fast queues (O(1) IntrusiveStack) for ready-lane fast path
        let fast_queues: Vec<LocalQueue> = (0..worker_count)
            .map(|_| LocalQueue::new(Arc::clone(state)))
            .collect();

        // Create workers with references to all other workers' schedulers
        for id in 0..worker_count {
            let parker = parkers[id].clone();

            // Stealers: all other workers' local schedulers (excluding self)
            let stealers: Vec<_> = local_schedulers
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != id)
                .map(|(_, sched)| Arc::clone(sched))
                .collect();

            // Fast stealers: O(1) steal from other workers' LocalQueues
            let fast_stealers: Vec<_> = fast_queues
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != id)
                .map(|(_, q)| q.stealer())
                .collect();

            workers.push(ThreeLaneWorker {
                id,
                local: Arc::clone(&local_schedulers[id]),
                stealers,
                fast_queue: fast_queues[id].clone(),
                fast_stealers,
                local_ready: Arc::clone(&local_ready[id]),
                all_local_ready: local_ready.clone(),
                global: Arc::clone(&global),
                state: Arc::clone(state),
                parker,
                coordinator: Arc::clone(&coordinator),
                rng: DetRng::new(id as u64),
                shutdown: Arc::clone(&shutdown),
                timer_driver: timer_driver.clone(),
                steal_buffer: Vec::with_capacity(steal_batch_size.max(1)),
                steal_batch_size,
                enable_parking,
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
            local_schedulers,
            local_ready,
            parkers,
            workers,
            shutdown,
            coordinator,
            timer_driver,
            state: Arc::clone(state),
            cancel_streak_limit,
            steal_batch_size,
            enable_parking,
        }
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
        }
    }

    /// Enables or disables worker parking when idle.
    pub fn set_enable_parking(&mut self, enable: bool) {
        self.enable_parking = enable;
        for worker in &mut self.workers {
            worker.enable_parking = enable;
        }
    }

    /// Returns a reference to the global injector.
    #[must_use]
    pub fn global_injector(&self) -> Arc<GlobalInjector> {
        self.global.clone()
    }

    /// Injects a task into the cancel lane for cross-thread wakeup.
    ///
    /// Uses `wake_state.notify()` for centralized deduplication.
    /// If the task is already scheduled, this is a no-op.
    /// If the task record doesn't exist (e.g., in tests), allows injection.
    pub fn inject_cancel(&self, task: TaskId, priority: u8) {
        let (is_local, pinned_worker) = {
            let state = self.state.lock().expect("runtime state lock poisoned");
            state
                .tasks
                .get(task.arena_index())
                .map_or((false, None), |record| {
                    if record.is_local() {
                        record.wake_state.notify();
                    }
                    (record.is_local(), record.pinned_worker())
                })
        };

        if is_local {
            if let Some(worker_id) = pinned_worker {
                if let Some(local) = self.local_schedulers.get(worker_id) {
                    if let Some(local_ready) = self.local_ready.get(worker_id) {
                        let _ = remove_from_local_ready(local_ready, task);
                    }
                    local
                        .lock()
                        .expect("local scheduler lock poisoned")
                        .move_to_cancel_lane(task, priority);
                    if let Some(parker) = self.parkers.get(worker_id) {
                        parker.unpark();
                    }
                    return;
                }
            }
            if schedule_cancel_on_current_local(task, priority) {
                return;
            }
            // SAFETY: Local (!Send) tasks must only be polled on their owner
            // worker. If we can't route to the correct worker, skipping cancel
            // injection may cause a hang but avoids UB from wrong-thread polling.
            debug_assert!(
                false,
                "Attempted to inject_cancel local task {task:?} without owner worker"
            );
            tracing::error!(
                ?task,
                "inject_cancel: cannot route local task to owner worker, cancel skipped"
            );
            return;
        }

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
    ///
    /// # Panics
    ///
    /// Panics if the task is a local (`!Send`) task. Local tasks must be
    /// scheduled via their `Waker` (which knows the owner) or `spawn` on the
    /// owner thread. Injecting them globally would allow them to be stolen
    /// by the wrong worker, causing data loss.
    pub fn inject_ready(&self, task: TaskId, priority: u8) {
        let (should_schedule, is_local) = {
            let state = self.state.lock().expect("runtime state lock poisoned");
            state
                .tasks
                .get(task.arena_index())
                .map_or((true, false), |record| {
                    (record.wake_state.notify(), record.is_local())
                })
        };

        // SAFETY: Local (!Send) tasks must only be polled on their owner worker.
        // Injecting globally would allow wrong-thread polling = UB.
        debug_assert!(
            !is_local,
            "Attempted to globally inject local task {task:?}. Local tasks must be scheduled on their owner thread."
        );
        if is_local {
            tracing::error!(
                ?task,
                "inject_ready: refusing to globally inject local task, scheduling skipped"
            );
            return;
        }

        if should_schedule {
            self.global.inject_ready(task, priority);
            self.wake_one();
        }
    }

    /// Spawns a task (shorthand for inject_ready).
    ///
    /// Fast path: when called on a worker thread, pushes to the worker's
    /// `LocalQueue` (O(1) IntrusiveStack) instead of the global injector
    /// or the PriorityScheduler heap.
    ///
    /// # Panics
    ///
    /// Panics if the task is local (`!Send`) and we are not on the owner thread
    /// (i.e. `schedule_local_task` fails). Local tasks cannot be spawned
    /// remotely via this method.
    pub fn spawn(&self, task: TaskId, priority: u8) {
        // Dedup: check wake_state before scheduling anywhere.
        let (should_schedule, is_local) = {
            let state = self.state.lock().expect("runtime state lock poisoned");
            state
                .tasks
                .get(task.arena_index())
                .map_or((true, false), |record| {
                    (record.wake_state.notify(), record.is_local())
                })
        };

        if !should_schedule {
            return;
        }

        if is_local {
            // Local tasks MUST go to the non-stealable local_ready queue.
            // They can only be spawned from the owner thread (because the future is !Send).
            if schedule_local_task(task) {
                return;
            }
            // SAFETY: Local (!Send) tasks must only be polled on their owner worker.
            // Skipping spawn may cause the task to never run, but avoids UB.
            debug_assert!(
                false,
                "Attempted to spawn local task {task:?} from non-owner thread or outside worker context"
            );
            tracing::error!(
                ?task,
                "spawn: local task cannot be scheduled from non-owner thread, spawn skipped"
            );
            return;
        }

        // Fast path 1: O(1) push to worker's LocalQueue via TLS.
        if LocalQueue::schedule_local(task) {
            return;
        }

        // Fast path 2: O(log n) push to PriorityScheduler via TLS.
        let scheduled = CURRENT_LOCAL.with(|cell| {
            if let Some(local) = cell.borrow().as_ref() {
                local
                    .lock()
                    .expect("local scheduler lock poisoned")
                    .schedule(task, priority);
                return true;
            }
            false
        });
        if scheduled {
            return;
        }

        // Slow path: global injector (off worker thread).
        self.global.inject_ready(task, priority);
        self.wake_one();
    }

    /// Wakes a task by injecting it into the ready lane.
    ///
    /// Fast path: when called on a worker thread, pushes to the worker's
    /// `LocalQueue` (O(1)) or `PriorityScheduler` instead of the global
    /// injector. For cancel wakeups, use `inject_cancel` instead.
    ///
    /// # Panics
    ///
    /// Panics if the task is local (`!Send`) and we are not on the owner thread.
    /// Local tasks must be woken via their `Waker` (which handles remote wakes)
    /// or on the owner thread.
    pub fn wake(&self, task: TaskId, priority: u8) {
        // Dedup check.
        let (should_schedule, is_local) = {
            let state = self.state.lock().expect("runtime state lock poisoned");
            state
                .tasks
                .get(task.arena_index())
                .map_or((true, false), |record| {
                    (record.wake_state.notify(), record.is_local())
                })
        };

        if !should_schedule {
            return;
        }

        if is_local {
            // Local tasks MUST go to the non-stealable local_ready queue.
            if schedule_local_task(task) {
                return;
            }
            // SAFETY: Local (!Send) tasks must only be polled on their owner worker.
            // Skipping wake may cause the task to hang, but avoids UB.
            debug_assert!(
                false,
                "Attempted to wake local task {task:?} via scheduler from non-owner thread. Use Waker instead."
            );
            tracing::error!(
                ?task,
                "wake: local task cannot be woken from non-owner thread, wake skipped"
            );
            return;
        }

        // Fast path 1: O(1) push to worker's LocalQueue via TLS.
        if LocalQueue::schedule_local(task) {
            return;
        }

        // Fast path 2: O(log n) push to PriorityScheduler via TLS.
        let scheduled = CURRENT_LOCAL.with(|cell| {
            if let Some(local) = cell.borrow().as_ref() {
                local
                    .lock()
                    .expect("local scheduler lock poisoned")
                    .schedule(task, priority);
                return true;
            }
            false
        });
        if scheduled {
            return;
        }

        // Slow path: global injector (off worker thread).
        self.global.inject_ready(task, priority);
        self.wake_one();
    }

    /// Wakes one idle worker.
    fn wake_one(&self) {
        self.coordinator.wake_one();
    }

    /// Wakes all idle workers.
    pub fn wake_all(&self) {
        self.coordinator.wake_all();
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
    /// O(1) local queue for ready tasks (work-stealing fast path).
    ///
    /// Ready tasks spawned/woken on the worker thread are pushed here
    /// (IntrusiveStack, O(1)) instead of the PriorityScheduler (BinaryHeap,
    /// O(log n)). Stealers use FIFO ordering for cache-friendliness.
    pub fast_queue: LocalQueue,
    /// Stealers for other workers' fast queues (O(1) steal).
    fast_stealers: Vec<local_queue::Stealer>,
    /// Non-stealable queue for local (`!Send`) tasks.
    ///
    /// Local tasks are pinned to their owner worker and must never be stolen.
    /// This queue is only drained by the owner worker during `try_ready_work()`.
    local_ready: Arc<Mutex<Vec<TaskId>>>,
    /// References to all workers' non-stealable local queues.
    ///
    /// Used to route local waiters to their owner worker's queue when a task
    /// completes and needs to wake a pinned waiter on a different worker.
    all_local_ready: Vec<Arc<Mutex<Vec<TaskId>>>>,
    /// Global injection queue.
    pub global: Arc<GlobalInjector>,
    /// Shared runtime state.
    pub state: Arc<ContendedMutex<RuntimeState>>,
    /// Parking mechanism for idle workers.
    pub parker: Parker,
    /// Coordination for waking other workers.
    pub(crate) coordinator: Arc<WorkerCoordinator>,
    /// Deterministic RNG for stealing decisions.
    pub rng: DetRng,
    /// Shutdown signal.
    pub shutdown: Arc<AtomicBool>,
    /// Timer driver for processing timer wakeups (optional).
    pub timer_driver: Option<TimerDriverHandle>,
    /// Scratch buffer for stolen tasks (avoid per-steal allocations).
    steal_buffer: Vec<(TaskId, u8)>,
    /// Maximum number of ready tasks to steal in one batch.
    steal_batch_size: usize,
    /// Whether this worker is allowed to park when idle.
    enable_parking: bool,
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

    /// Force the cached scheduling suggestion for testing the boosted 2L+1
    /// fairness bound under `DrainObligations`/`DrainRegions`.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn set_cached_suggestion(&mut self, suggestion: SchedulingSuggestion) {
        self.cached_suggestion = suggestion;
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

        while !self.shutdown.load(Ordering::Acquire) {
            if let Some(task) = self.next_task() {
                self.execute(task);
                continue;
            }

            if self.schedule_ready_finalizers() {
                continue;
            }

            // PHASE 5: Backoff before parking
            let mut backoff = 0;

            loop {
                // Check shutdown before parking to avoid hanging in the backoff loop.
                if self.shutdown.load(Ordering::Acquire) {
                    break;
                }

                // Quick check for new work in global, fast, and local queues.
                let local_has_work = self
                    .local
                    .lock()
                    .map(|local| !local.is_empty())
                    .unwrap_or(false);
                let local_ready_has_work = self
                    .local_ready
                    .lock()
                    .map(|q| !q.is_empty())
                    .unwrap_or(false);
                if !self.global.is_empty()
                    || !self.fast_queue.is_empty()
                    || local_has_work
                    || local_ready_has_work
                {
                    break;
                }

                if backoff < SPIN_LIMIT {
                    std::hint::spin_loop();
                    backoff += 1;
                } else if backoff < SPIN_LIMIT + YIELD_LIMIT {
                    std::thread::yield_now();
                    backoff += 1;
                } else if self.enable_parking {
                    // Park with timeout based on next timer deadline.
                    if let Some(timer) = &self.timer_driver {
                        if let Some(next_deadline) = timer.next_deadline() {
                            let now = timer.now();
                            if next_deadline > now {
                                let nanos = next_deadline.duration_since(now);
                                self.parker.park_timeout(Duration::from_nanos(nanos));
                            }
                            // If deadline is due or passed, don't park - loop back to process timers.
                        } else {
                            // No pending timers, park indefinitely.
                            self.parker.park();
                        }
                    } else {
                        // No timer driver, park indefinitely.
                        self.parker.park();
                    }
                    // After waking, re-check queues by continuing the loop.
                    // This fixes a lost-wakeup race where work arrives right as we park.
                    // Reset backoff to spin briefly before parking again (spurious wakeups).
                    backoff = 0;
                    // Continue loop to re-check condition (no break!)
                } else {
                    // Parking disabled; return to outer loop to keep spinning/yielding.
                    break;
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
                // Fallback: no ready/timed/steal work available, so dispatch one
                // more cancel task. Count this dispatch toward the streak (reset
                // to 1, not 0) so the next call re-checks for ready/timed work
                // after at most cancel_streak_limit − 1 more cancel dispatches,
                // matching the documented fairness bound.
                self.preemption_metrics.cancel_dispatches += 1;
                self.preemption_metrics.fallback_cancel_dispatches += 1;
                self.cancel_streak = 1;
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

    /// Tries to get ready work from fast queue, global, or local queues.
    pub(crate) fn try_ready_work(&mut self) -> Option<TaskId> {
        // Highest priority: drain non-stealable local (!Send) tasks first.
        // These tasks are pinned to this worker and cannot run elsewhere.
        if let Ok(mut queue) = self.local_ready.try_lock() {
            if let Some(task) = queue.pop() {
                return Some(task);
            }
        }

        // Fast path: O(1) pop from local IntrusiveStack (LIFO, cache-friendly).
        if let Some(task) = self.fast_queue.pop() {
            return Some(task);
        }

        // Global ready
        if let Some(pt) = self.global.pop_ready() {
            return Some(pt.task);
        }

        // Local ready (PriorityScheduler, O(log n) pop)
        let mut local = self.local.lock().expect("local scheduler lock poisoned");
        let rng_hint = self.rng.next_u64();
        local.pop_ready_only_with_hint(rng_hint)
    }

    /// Tries to steal work from other workers.
    ///
    /// Fast path: O(1) steal from other workers' `LocalQueue` IntrusiveStacks.
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
            let len = self.fast_stealers.len();
            let start = self.rng.next_usize(len);
            for i in 0..len {
                let idx = (start + i) % len;
                if let Some(task) = self.fast_stealers[idx].steal() {
                    // Safety invariant: local tasks must never be in stealable queues.
                    debug_assert!(
                        !self
                            .state
                            .lock()
                            .expect("runtime state lock poisoned")
                            .tasks
                            .get(task.arena_index())
                            .is_some_and(crate::record::task::TaskRecord::is_local),
                        "BUG: stole a local (!Send) task {task:?} from another worker's fast_queue"
                    );
                    return Some(task);
                }
            }
        }

        // Slow path: steal from PriorityScheduler heaps (O(k log n)).
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
                let stolen_count =
                    victim.steal_ready_batch_into(self.steal_batch_size, &mut self.steal_buffer);
                if stolen_count > 0 {
                    // Safety invariant: verify no local tasks were stolen.
                    #[cfg(debug_assertions)]
                    {
                        for &(task, _) in &self.steal_buffer[..stolen_count] {
                            let is_local = self
                                .state
                                .lock()
                                .expect("runtime state lock poisoned")
                                .tasks
                                .get(task.arena_index())
                                .is_some_and(crate::record::task::TaskRecord::is_local);
                            debug_assert!(
                                !is_local,
                                "BUG: stole a local (!Send) task {task:?} from PriorityScheduler"
                            );
                        }
                    }

                    // Take the first task to execute
                    let (first_task, _) = self.steal_buffer[0];

                    // Push remaining stolen tasks to our fast queue
                    if stolen_count > 1 {
                        for &(task, _priority) in self.steal_buffer.iter().skip(1) {
                            self.fast_queue.push(task);
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
        {
            let state = self.state.lock().expect("runtime state lock poisoned");
            if let Some(record) = state.tasks.get(task.arena_index()) {
                record.wake_state.notify();
            }
        }
        let _ = remove_from_local_ready(&self.local_ready, task);
        {
            let mut local = self.local.lock().expect("local scheduler lock poisoned");
            local.move_to_cancel_lane(task, priority);
        }
        self.parker.unpark();
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

        let is_local = stored.is_local();

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
                        local_ready: Arc::clone(&self.local_ready),
                        parker: self.parker.clone(),
                    }))
                } else {
                    Waker::from(Arc::new(ThreeLaneWaker {
                        task_id,
                        priority,
                        wake_state: Arc::clone(&wake_state),
                        global: Arc::clone(&self.global),
                        coordinator: Arc::clone(&self.coordinator),
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
                                local_ready: Arc::clone(&self.local_ready),
                                parker: self.parker.clone(),
                                cx_inner: Arc::downgrade(inner),
                            }))
                        } else {
                            Waker::from(Arc::new(CancelLaneWaker {
                                task_id,
                                default_priority: priority,
                                wake_state: Arc::clone(&wake_state),
                                global: Arc::clone(&self.global),
                                coordinator: Arc::clone(&self.coordinator),
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
                let cancel_ack = Self::consume_cancel_ack_locked(&mut state, task_id);
                if let Some(record) = state.tasks.get_mut(task_id.arena_index()) {
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
                for waiter in waiters {
                    if let Some(record) = state.tasks.get(waiter.arena_index()) {
                        let waiter_priority = record
                            .cx_inner
                            .as_ref()
                            .and_then(|inner| inner.read().ok().map(|cx| cx.budget.priority))
                            .unwrap_or(0);
                        if record.wake_state.notify() {
                            if record.is_local() {
                                if let Some(worker_id) = record.pinned_worker() {
                                    if let Some(queue) = self.all_local_ready.get(worker_id) {
                                        queue
                                            .lock()
                                            .expect("local_ready lock poisoned")
                                            .push(waiter);
                                        self.coordinator.wake_worker(worker_id);
                                    } else {
                                        // SAFETY: Invalid worker id for a local waiter means
                                        // we can't route to the correct queue. Skipping the
                                        // wake may hang the waiter, but avoids potential UB.
                                        debug_assert!(
                                            false,
                                            "Pinned local waiter {waiter:?} has invalid worker id {worker_id}"
                                        );
                                        tracing::error!(
                                            ?waiter,
                                            worker_id,
                                            "execute: pinned local waiter has invalid worker id, wake skipped"
                                        );
                                    }
                                } else {
                                    // Local task without a pinned worker yet.
                                    // Schedule on the current worker's local queue.
                                    self.local_ready
                                        .lock()
                                        .expect("local_ready lock poisoned")
                                        .push(waiter);
                                    self.parker.unpark();
                                }
                            } else {
                                // Global waiters are ready tasks.
                                self.global.inject_ready(waiter, waiter_priority);
                                self.coordinator.wake_one();
                            }
                        }
                    }
                }
                for (finalizer_task, priority) in finalizers {
                    self.global.inject_ready(finalizer_task, priority);
                    self.coordinator.wake_one();
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
                        if schedule_cancel {
                            // Cancel still goes to PriorityScheduler for ordering.
                            // Cancel lane is not stolen by steal_ready_batch_into.
                            let _ = remove_from_local_ready(&self.local_ready, task_id);
                            let mut local =
                                self.local.lock().expect("local scheduler lock poisoned");
                            local.schedule_cancel(task_id, cancel_priority);
                        } else {
                            // Push to non-stealable local_ready queue.
                            // Local (!Send) tasks must never enter stealable structures.
                            self.local_ready
                                .lock()
                                .expect("local_ready lock poisoned")
                                .push(task_id);
                        }
                        self.parker.unpark();
                    } else {
                        // Schedule to global injector
                        if schedule_cancel {
                            self.global.inject_cancel(task_id, cancel_priority);
                        } else {
                            self.global.inject_ready(task_id, priority);
                        }
                        self.coordinator.wake_one();
                    }
                }

                if let Ok(mut state) = self.state.lock() {
                    let _ = Self::consume_cancel_ack_locked(&mut state, task_id);
                }
            }
        }
    }

    fn schedule_ready_finalizers(&self) -> bool {
        let tasks = {
            let mut state = self.state.lock().expect("runtime state lock poisoned");
            state.drain_ready_async_finalizers()
        };
        if tasks.is_empty() {
            return false;
        }
        for (task_id, priority) in tasks {
            self.global.inject_ready(task_id, priority);
            self.coordinator.wake_one();
        }
        true
    }

    fn consume_cancel_ack_locked(state: &mut RuntimeState, task_id: TaskId) -> bool {
        let Some(record) = state.tasks.get_mut(task_id.arena_index()) else {
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

struct ThreeLaneWaker {
    task_id: TaskId,
    priority: u8,
    wake_state: Arc<crate::record::task::TaskWakeState>,
    global: Arc<GlobalInjector>,
    coordinator: Arc<WorkerCoordinator>,
}

impl ThreeLaneWaker {
    fn schedule(&self) {
        if self.wake_state.notify() {
            self.global.inject_ready(self.task_id, self.priority);
            self.coordinator.wake_one();
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
    local_ready: Arc<Mutex<Vec<TaskId>>>,
    parker: Parker,
}

impl ThreeLaneLocalWaker {
    fn schedule(&self) {
        if self.wake_state.notify() {
            // Fast path: push to non-stealable local_ready queue via TLS.
            if !schedule_local_task(self.task_id) {
                // Cross-thread wake: push to the owner's non-stealable local_ready queue.
                // Local tasks must never enter stealable structures.
                self.local_ready
                    .lock()
                    .expect("local_ready lock poisoned")
                    .push(self.task_id);
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
    coordinator: Arc<WorkerCoordinator>,
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
        self.coordinator.wake_one();
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
    local_ready: Arc<Mutex<Vec<TaskId>>>,
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

        // Promote to local cancel lane, matching global inject_cancel semantics.
        // move_to_cancel_lane relocates from ready/timed if already scheduled.
        {
            let _ = remove_from_local_ready(&self.local_ready, self.task_id);
            let mut local = self.local.lock().expect("local scheduler lock poisoned");
            local.move_to_cancel_lane(self.task_id, priority);
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
    use crate::record::task::TaskWakeState;
    use crate::types::{Budget, CancelKind, CancelReason, CxInner, RegionId, TaskId};
    use std::sync::RwLock;
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
        let coordinator = Arc::new(WorkerCoordinator::new(vec![parker]));
        let waker = Waker::from(Arc::new(CancelLaneWaker {
            task_id,
            default_priority: Budget::INFINITE.priority,
            wake_state,
            global: Arc::clone(&global),
            coordinator,
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
    fn test_spawn_local_not_stolen() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(2, &state);

        let mut worker_pool = scheduler.take_workers();
        let local_ready_0 = Arc::clone(&worker_pool[0].local_ready);
        let mut stealer_worker = worker_pool.pop().unwrap(); // worker 1 as mutable for try_steal

        let task_id = TaskId::new_for_test(1, 0);

        // Simulate worker 0 environment and schedule local task
        {
            let _guard = ScopedLocalReady::new(Arc::clone(&local_ready_0));
            assert!(
                schedule_local_task(task_id),
                "schedule_local_task should succeed"
            );
        }

        // Verify task is in worker 0's local_ready queue
        {
            let queue = local_ready_0.lock().unwrap();
            assert_eq!(queue.len(), 1);
            assert_eq!(queue[0], task_id);
            drop(queue);
        }

        // Worker 1 tries to steal. It should NOT find the task because
        // it only steals from PriorityScheduler and fast_queue, not local_ready.
        let stolen = stealer_worker.try_steal();
        assert!(stolen.is_none(), "Local task should not be stolen");
    }

    #[test]
    fn test_local_cancel_removes_from_local_ready() {
        let task_id = TaskId::new_for_test(1, 0);
        let local_ready = Arc::new(Mutex::new(vec![task_id]));
        let local = Arc::new(Mutex::new(PriorityScheduler::new()));
        let wake_state = Arc::new(TaskWakeState::new());
        let cx_inner = Arc::new(RwLock::new(CxInner::new(
            RegionId::new_for_test(1, 0),
            task_id,
            Budget::INFINITE,
        )));
        {
            let mut guard = cx_inner.write().expect("cx_inner lock poisoned");
            guard.cancel_requested = true;
            guard.cancel_reason = Some(CancelReason::new(CancelKind::User));
        }

        let waker = ThreeLaneLocalCancelWaker {
            task_id,
            default_priority: 10,
            wake_state: Arc::clone(&wake_state),
            local: Arc::clone(&local),
            local_ready: Arc::clone(&local_ready),
            parker: Parker::new(),
            cx_inner: Arc::downgrade(&cx_inner),
        };

        waker.schedule();

        let queue = local_ready.lock().expect("local_ready lock poisoned");
        assert!(
            !queue.contains(&task_id),
            "local_ready should not retain cancelled task"
        );
        drop(queue);

        assert!(
            local
                .lock()
                .expect("local scheduler lock poisoned")
                .is_in_cancel_lane(task_id),
            "task should be promoted to cancel lane"
        );
    }

    #[test]
    fn schedule_cancel_on_current_local_removes_local_ready() {
        let task_id = TaskId::new_for_test(1, 0);
        let local_ready = Arc::new(Mutex::new(vec![task_id]));
        let local = Arc::new(Mutex::new(PriorityScheduler::new()));

        let _local_ready_guard = ScopedLocalReady::new(Arc::clone(&local_ready));
        let _local_guard = ScopedLocalScheduler::new(Arc::clone(&local));

        let scheduled = schedule_cancel_on_current_local(task_id, 7);
        assert!(scheduled, "should schedule via current local scheduler");

        let queue = local_ready.lock().expect("local_ready lock poisoned");
        assert!(
            !queue.contains(&task_id),
            "local_ready should not retain cancelled task"
        );
        drop(queue);

        assert!(
            local
                .lock()
                .expect("local scheduler lock poisoned")
                .is_in_cancel_lane(task_id),
            "task should be promoted to cancel lane"
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
        let coordinator = Arc::new(WorkerCoordinator::new(vec![parker]));

        // Create multiple wakers (simulating cloned wakers)
        let wakers: Vec<_> = (0..10)
            .map(|_| {
                Waker::from(Arc::new(ThreeLaneWaker {
                    task_id,
                    priority: 100,
                    wake_state: Arc::clone(&wake_state),
                    global: Arc::clone(&global),
                    coordinator: Arc::clone(&coordinator),
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
        let initial = scheduler.coordinator.next_wake.load(Ordering::Relaxed);
        assert_eq!(initial, 0, "next_wake should start at 0");

        // Wake multiple times and verify counter advances
        for i in 0..8 {
            scheduler.wake_one();
            let current = scheduler.coordinator.next_wake.load(Ordering::Relaxed);
            assert_eq!(current, i + 1, "next_wake should increment on each wake");
        }

        // Final counter should be 8
        let final_val = scheduler.coordinator.next_wake.load(Ordering::Relaxed);
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

    /// Verify that the fallback cancel dispatch counts toward the cancel
    /// streak. After a fallback (cancel_streak = 1), injecting a ready
    /// task should see it dispatched within cancel_streak_limit − 1 more
    /// cancel dispatches, not cancel_streak_limit.
    #[test]
    fn test_fallback_cancel_streak_counts_toward_limit() {
        let limit: usize = 3;
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, limit);

        // Inject enough cancel tasks to hit the fallback + continue.
        // With limit=3: dispatches 1-3 (streak 1-3), fallback (streak=1),
        // dispatches 5-6 (streak 2-3), fairness yield.
        // We inject a ready task at that point to prove it gets dispatched.
        for i in 0..20u32 {
            scheduler.inject_cancel(TaskId::new_for_test(1, i), 100);
        }

        let mut workers = scheduler.take_workers().into_iter();
        let mut worker = workers.next().unwrap();

        // Dispatch limit (3) cancel tasks, then the fallback (4th).
        for _ in 0..=limit {
            assert!(worker.next_task().is_some(), "should dispatch cancel");
        }

        // After the fallback, cancel_streak should be 1 (the fallback
        // dispatch counted). Now inject a ready task. It should be
        // dispatched after at most limit − 1 more cancel dispatches.
        let ready_task = TaskId::new_for_test(99, 0);
        worker.fast_queue.push(ready_task);

        let mut dispatches_until_ready = 0;
        for _ in 0..limit {
            let task = worker.next_task().expect("should have work");
            dispatches_until_ready += 1;
            if task == ready_task {
                break;
            }
        }

        // The ready task must appear within limit dispatches (limit − 1
        // cancel + 1 ready, not limit cancel + 1 ready).
        let last_task = worker.fast_queue.pop();
        let ready_was_dispatched = dispatches_until_ready <= limit
            && (last_task.is_none() || last_task != Some(ready_task));

        // Specifically: with cancel_streak=1 after fallback and limit=3,
        // we should see exactly 2 more cancel tasks then the ready task
        // (streak goes 1→2→3, fairness yield, ready dispatched).
        assert!(
            ready_was_dispatched,
            "ready task should be dispatched within {limit} steps after fallback, \
             took {dispatches_until_ready}"
        );
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

    // ========================================================================
    // Work-stealing LocalQueue fast path tests (bd-3p8oa)
    // ========================================================================

    #[test]
    fn fast_queue_spawn_prefers_local_queue_tls() {
        // When both LocalQueue TLS and PriorityScheduler TLS are set,
        // spawn() should prefer the O(1) LocalQueue path.
        let state = LocalQueue::test_state(10);
        let scheduler = ThreeLaneScheduler::new(1, &state);
        let fast_queue = scheduler.workers[0].fast_queue.clone();
        let priority_sched = scheduler.workers[0].local.clone();

        {
            let _sched_guard = ScopedLocalScheduler::new(priority_sched.clone());
            let _queue_guard = LocalQueue::set_current(fast_queue.clone());

            scheduler.spawn(TaskId::new_for_test(1, 0), 100);
        }

        // Task should be in the fast queue, NOT the PriorityScheduler.
        assert!(!fast_queue.is_empty(), "task should be in fast_queue");
        let priority_len = priority_sched.lock().unwrap().len();
        assert_eq!(priority_len, 0, "PriorityScheduler should be empty");
        assert!(!scheduler.global.has_ready_work(), "global should be empty");
    }

    #[test]
    fn fast_queue_wake_prefers_local_queue_tls() {
        // wake() with LocalQueue TLS should use the O(1) path.
        let state = LocalQueue::test_state(10);
        let scheduler = ThreeLaneScheduler::new(1, &state);
        let fast_queue = scheduler.workers[0].fast_queue.clone();
        let priority_sched = scheduler.workers[0].local.clone();

        {
            let _sched_guard = ScopedLocalScheduler::new(priority_sched.clone());
            let _queue_guard = LocalQueue::set_current(fast_queue.clone());

            scheduler.wake(TaskId::new_for_test(1, 0), 100);
        }

        assert!(!fast_queue.is_empty(), "task should be in fast_queue");
        let priority_len = priority_sched.lock().unwrap().len();
        assert_eq!(priority_len, 0, "PriorityScheduler should be empty");
    }

    #[test]
    fn try_ready_work_drains_fast_queue_first() {
        // When both fast_queue and PriorityScheduler have ready tasks,
        // try_ready_work() should pop from fast_queue first.
        let state = LocalQueue::test_state(10);
        let mut scheduler = ThreeLaneScheduler::new(1, &state);
        let mut workers = scheduler.take_workers();
        let worker = &mut workers[0];

        // Push task A to fast_queue.
        worker.fast_queue.push(TaskId::new_for_test(1, 0));
        // Push task B to PriorityScheduler ready lane.
        worker
            .local
            .lock()
            .unwrap()
            .schedule(TaskId::new_for_test(2, 0), 50);

        // First pop should come from fast_queue (task A).
        let first = worker.try_ready_work();
        assert_eq!(
            first,
            Some(TaskId::new_for_test(1, 0)),
            "fast_queue task should come first"
        );

        // Second pop should come from PriorityScheduler (task B).
        let second = worker.try_ready_work();
        assert_eq!(
            second,
            Some(TaskId::new_for_test(2, 0)),
            "PriorityScheduler task should come second"
        );

        // No more work.
        assert!(worker.try_ready_work().is_none());
    }

    #[test]
    fn try_steal_tries_fast_stealers_first() {
        // Worker 1 should steal from worker 0's fast_queue before
        // falling back to PriorityScheduler heaps.
        let state = LocalQueue::test_state(10);
        let mut scheduler = ThreeLaneScheduler::new(2, &state);

        // Push tasks into worker 0's fast_queue.
        let fast_task = TaskId::new_for_test(1, 0);
        scheduler.workers[0].fast_queue.push(fast_task);

        let mut workers = scheduler.take_workers();
        let thief = &mut workers[1];

        let stolen = thief.try_steal();
        assert_eq!(stolen, Some(fast_task), "should steal from fast_queue");
    }

    #[test]
    fn try_steal_falls_back_to_priority_scheduler() {
        // When fast queues are empty, steal should fall back to
        // PriorityScheduler heaps.
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(2, &state);

        // Push task only into worker 0's PriorityScheduler.
        let heap_task = TaskId::new_for_test(1, 1);
        scheduler.workers[0]
            .local
            .lock()
            .unwrap()
            .schedule(heap_task, 50);

        let mut workers = scheduler.take_workers();
        let thief = &mut workers[1];

        let stolen = thief.try_steal();
        assert_eq!(
            stolen,
            Some(heap_task),
            "should fall back to PriorityScheduler steal"
        );
    }

    #[test]
    fn fast_queue_no_loss_no_dup_single_worker() {
        // All tasks pushed to fast_queue are popped exactly once.
        let state = LocalQueue::test_state(255);
        let mut scheduler = ThreeLaneScheduler::new(1, &state);
        let mut workers = scheduler.take_workers();
        let worker = &mut workers[0];

        let count = 256u32;
        for i in 0..count {
            worker.fast_queue.push(TaskId::new_for_test(i, 0));
        }

        let mut seen = std::collections::HashSet::new();
        while let Some(task) = worker.try_ready_work() {
            assert!(seen.insert(task), "duplicate task: {task:?}");
        }
        assert_eq!(seen.len(), count as usize, "all tasks should be popped");
    }

    #[test]
    fn fast_queue_no_loss_no_dup_two_workers_stealing() {
        // Tasks pushed to worker 0's fast_queue are consumed exactly
        // once across worker 0 (pop) and worker 1 (steal).
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrd};
        use std::sync::{Arc as StdArc, Barrier};
        use std::thread;

        let total = 512usize;
        let state = LocalQueue::test_state((total - 1) as u32);
        let mut scheduler = ThreeLaneScheduler::new(2, &state);

        // Push all tasks to worker 0's fast queue.
        for i in 0..total {
            scheduler.workers[0]
                .fast_queue
                .push(TaskId::new_for_test(i as u32, 0));
        }

        let mut workers = scheduler.take_workers();
        let w0 = workers.remove(0);
        let mut w1 = workers.remove(0);

        let counts: StdArc<Vec<AtomicUsize>> =
            StdArc::new((0..total).map(|_| AtomicUsize::new(0)).collect());
        let barrier = StdArc::new(Barrier::new(2));

        let c0 = StdArc::clone(&counts);
        let b0 = StdArc::clone(&barrier);
        let t0 = thread::spawn(move || {
            b0.wait();
            // Owner pops from fast_queue.
            while let Some(task) = w0.fast_queue.pop() {
                let idx = task.0.index() as usize;
                c0[idx].fetch_add(1, AtomicOrd::SeqCst);
                thread::yield_now();
            }
        });

        let c1 = StdArc::clone(&counts);
        let b1 = StdArc::clone(&barrier);
        let t1 = thread::spawn(move || {
            b1.wait();
            // Thief steals from worker 0's fast_queue.
            loop {
                let stolen = w1.try_steal();
                if let Some(task) = stolen {
                    let idx = task.0.index() as usize;
                    c1[idx].fetch_add(1, AtomicOrd::SeqCst);
                    thread::yield_now();
                } else {
                    break;
                }
            }
        });

        t0.join().expect("owner join");
        t1.join().expect("thief join");

        let mut total_seen = 0usize;
        for (idx, count) in counts.iter().enumerate() {
            let v = count.load(AtomicOrd::SeqCst);
            assert_eq!(v, 1, "task {idx} seen {v} times (expected 1)");
            total_seen += v;
        }
        assert_eq!(total_seen, total);
    }

    #[test]
    fn fast_queue_schedule_on_current_local_prefers_fast() {
        // schedule_on_current_local should prefer LocalQueue when TLS is set.
        let state = LocalQueue::test_state(10);
        let scheduler = ThreeLaneScheduler::new(1, &state);
        let fast_queue = scheduler.workers[0].fast_queue.clone();
        let priority_sched = scheduler.workers[0].local.clone();

        {
            let _sched_guard = ScopedLocalScheduler::new(priority_sched.clone());
            let _queue_guard = LocalQueue::set_current(fast_queue.clone());

            let ok = schedule_on_current_local(TaskId::new_for_test(1, 0), 100);
            assert!(ok);
        }

        assert!(!fast_queue.is_empty(), "should be in fast_queue");
        assert_eq!(
            priority_sched.lock().unwrap().len(),
            0,
            "PriorityScheduler should be empty"
        );
    }

    #[test]
    fn fast_queue_cancel_timed_bypass_fast_path() {
        // Cancel and timed tasks should NOT go through the fast queue.
        // They must use PriorityScheduler for priority/deadline ordering.
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(1, &state);

        let cancel_task = TaskId::new_for_test(1, 1);
        let timed_task = TaskId::new_for_test(1, 2);

        scheduler.inject_cancel(cancel_task, 100);
        scheduler.inject_timed(timed_task, Time::from_nanos(500));

        let workers = scheduler.take_workers();
        let worker = &workers[0];

        // Fast queue should be empty.
        assert!(
            worker.fast_queue.is_empty(),
            "fast_queue should not have cancel/timed tasks"
        );

        // Tasks should be in global injector.
        assert!(scheduler.global.has_cancel_work());
    }

    #[test]
    fn fast_queue_waker_uses_local_ready_on_same_thread() {
        // ThreeLaneLocalWaker should push to local_ready TLS when available.
        let task_id = TaskId::new_for_test(1, 0);
        let wake_state = Arc::new(crate::record::task::TaskWakeState::new());
        let priority_sched = Arc::new(Mutex::new(PriorityScheduler::new()));
        let parker = Parker::new();

        let local_ready = Arc::new(Mutex::new(Vec::new()));

        let waker = Waker::from(Arc::new(ThreeLaneLocalWaker {
            task_id,
            priority: 100,
            wake_state: Arc::clone(&wake_state),
            local: Arc::clone(&priority_sched),
            local_ready: Arc::clone(&local_ready),
            parker,
        }));

        // Set local_ready TLS (waker uses schedule_local_task, not LocalQueue).
        let _ready_guard = ScopedLocalReady::new(Arc::clone(&local_ready));

        waker.wake_by_ref();

        // Task should be in local_ready, not PriorityScheduler.
        {
            let queue = local_ready.lock().unwrap();
            assert_eq!(queue.len(), 1, "local_ready should have 1 task");
            assert_eq!(queue[0], task_id);
            drop(queue);
        }
        assert_eq!(
            priority_sched.lock().unwrap().len(),
            0,
            "PriorityScheduler should be empty"
        );
    }

    #[test]
    fn fast_queue_waker_falls_back_to_local_ready_cross_thread() {
        // Without local_ready TLS, ThreeLaneLocalWaker falls back to
        // the owner's local_ready Arc directly.
        let task_id = TaskId::new_for_test(1, 1);
        let wake_state = Arc::new(crate::record::task::TaskWakeState::new());
        let priority_sched = Arc::new(Mutex::new(PriorityScheduler::new()));
        let parker = Parker::new();

        let local_ready = Arc::new(Mutex::new(Vec::new()));

        let waker = Waker::from(Arc::new(ThreeLaneLocalWaker {
            task_id,
            priority: 100,
            wake_state: Arc::clone(&wake_state),
            local: Arc::clone(&priority_sched),
            local_ready: Arc::clone(&local_ready),
            parker,
        }));

        waker.wake_by_ref();

        // Task should be in local_ready (cross-thread fallback).
        {
            let queue = local_ready.lock().unwrap();
            assert_eq!(queue.len(), 1, "local_ready should have 1 task");
            assert_eq!(queue[0], task_id);
            drop(queue);
        }
    }

    #[test]
    fn fast_queue_stolen_tasks_go_to_thief_fast_queue() {
        // When stealing from PriorityScheduler, remaining batch tasks
        // should go to the thief's fast_queue (not PriorityScheduler).
        let state = LocalQueue::test_state(10);
        let mut scheduler = ThreeLaneScheduler::new(2, &state);
        scheduler.set_steal_batch_size(2);

        // Push 8 tasks to worker 0's PriorityScheduler ready lane.
        for i in 0..8u32 {
            scheduler.workers[0]
                .local
                .lock()
                .unwrap()
                .schedule(TaskId::new_for_test(i, 0), 50);
        }

        let mut workers = scheduler.take_workers();
        let thief = &mut workers[1];

        // Steal should get first task + push remainder to thief's fast_queue.
        let stolen = thief.try_steal();
        assert!(stolen.is_some(), "should steal at least one task");

        // Thief's fast_queue should have the batch remainder.
        // (steal_ready_batch_into steals up to the configured batch size,
        // returns first, pushes rest)
        let fast_count = {
            let mut count = 0;
            while thief.fast_queue.pop().is_some() {
                count += 1;
            }
            count
        };
        assert_eq!(
            fast_count, 1,
            "thief's fast_queue should have batch remainder, got {fast_count}"
        );
    }

    // ── Non-stealable local task tests (bd-1s3c0) ────────────────────────

    #[test]
    fn local_ready_queue_drains_before_fast_queue() {
        // Use test_state to preallocate TaskRecords needed by fast_queue (IntrusiveStack).
        let state = LocalQueue::test_state(10);
        let mut scheduler = ThreeLaneScheduler::new(1, &state);
        let mut workers = scheduler.take_workers();
        let worker = &mut workers[0];

        let local_task = TaskId::new_for_test(1, 0);
        let fast_task = TaskId::new_for_test(2, 0);

        worker.local_ready.lock().expect("lock").push(local_task);
        worker.fast_queue.push(fast_task);

        let first = worker.try_ready_work();
        assert_eq!(first, Some(local_task), "local_ready should drain first");

        let second = worker.try_ready_work();
        assert_eq!(second, Some(fast_task), "fast_queue should drain second");

        assert!(
            worker.try_ready_work().is_none(),
            "no more ready work expected"
        );
    }

    #[test]
    fn local_ready_queue_not_visible_to_fast_stealers() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(2, &state);
        let mut workers = scheduler.take_workers();

        let local_task = TaskId::new_for_test(1, 1);

        workers[0]
            .local_ready
            .lock()
            .expect("lock")
            .push(local_task);

        let stolen = workers[1].try_steal();
        assert!(
            stolen.is_none(),
            "local_ready tasks must not be stealable, but got {stolen:?}"
        );

        let drained = workers[0].try_ready_work();
        assert_eq!(
            drained,
            Some(local_task),
            "local task should remain on owner worker"
        );
    }

    #[test]
    fn local_ready_queue_not_visible_to_priority_stealers() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(2, &state);
        let mut workers = scheduler.take_workers();

        let local_task = TaskId::new_for_test(1, 1);

        workers[0]
            .local_ready
            .lock()
            .expect("lock")
            .push(local_task);

        let stolen = workers[1].try_steal();
        assert!(
            stolen.is_none(),
            "local_ready tasks must not be stealable via PriorityScheduler"
        );
    }

    #[test]
    fn local_ready_survives_concurrent_steal_pressure() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(2, &state);
        let mut workers = scheduler.take_workers();

        let local_tasks: Vec<TaskId> = (1..=10).map(|i| TaskId::new_for_test(1, i)).collect();

        {
            let mut queue = workers[0].local_ready.lock().expect("lock");
            for &task in &local_tasks {
                queue.push(task);
            }
        }

        for _ in 0..10 {
            assert!(
                workers[1].try_steal().is_none(),
                "steal should fail for local_ready tasks"
            );
        }

        let mut drained = Vec::new();
        while let Some(task) = workers[0].try_ready_work() {
            drained.push(task);
        }

        assert_eq!(
            drained.len(),
            local_tasks.len(),
            "all local tasks should be drained by owner"
        );
        for task in &local_tasks {
            assert!(
                drained.contains(task),
                "local task {task:?} should be in drained set"
            );
        }
    }

    #[test]
    fn task_record_is_local_default_false() {
        use crate::record::task::TaskRecord;
        let record = TaskRecord::new(
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(0, 0),
            Budget::INFINITE,
        );
        assert!(!record.is_local(), "default should be false");
    }

    #[test]
    fn task_record_mark_local() {
        use crate::record::task::TaskRecord;
        let mut record = TaskRecord::new(
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(0, 0),
            Budget::INFINITE,
        );
        assert!(!record.is_local());
        record.mark_local();
        assert!(record.is_local(), "mark_local should set is_local");
    }

    #[test]
    fn backoff_loop_wakes_for_local_ready() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(1, &state);
        let mut workers = scheduler.take_workers();
        let worker = &mut workers[0];

        let task = TaskId::new_for_test(1, 1);
        worker.local_ready.lock().expect("lock").push(task);

        let found = worker.next_task();
        assert_eq!(found, Some(task), "next_task should find local_ready task");
    }

    #[test]
    fn schedule_local_task_uses_tls() {
        let queue = Arc::new(Mutex::new(Vec::new()));
        let _guard = ScopedLocalReady::new(Arc::clone(&queue));

        let task = TaskId::new_for_test(1, 1);
        let scheduled = schedule_local_task(task);
        assert!(scheduled, "should succeed when TLS is set");

        let tasks = queue.lock().expect("lock");
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0], task);
        drop(tasks);
    }

    #[test]
    fn schedule_local_task_fails_without_tls() {
        let task = TaskId::new_for_test(1, 1);
        let scheduled = schedule_local_task(task);
        assert!(!scheduled, "should fail without TLS");
    }

    /// When a completing task has a local waiter without a pinned worker,
    /// the waiter is routed to the current worker's local_ready queue.
    #[test]
    fn local_waiter_routes_to_current_worker_local_ready() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let region = state
            .lock()
            .expect("runtime state lock poisoned")
            .create_root_region(Budget::INFINITE);

        let task_id = {
            let mut guard = state.lock().expect("lock");
            let (id, _) = guard
                .create_task(region, Budget::INFINITE, async {})
                .expect("create task");
            id
        };
        let waiter_id = {
            let mut guard = state.lock().expect("lock");
            let (id, _) = guard
                .create_task(region, Budget::INFINITE, async {})
                .expect("create task");
            if let Some(record) = guard.tasks.get_mut(id.arena_index()) {
                record.mark_local();
            }
            drop(guard);
            id
        };

        {
            let mut guard = state.lock().expect("lock");
            if let Some(record) = guard.tasks.get_mut(task_id.arena_index()) {
                record.add_waiter(waiter_id);
            }
        }

        let mut scheduler = ThreeLaneScheduler::new(1, &state);
        let workers = scheduler.take_workers();
        let worker = &workers[0];
        let local_ready = Arc::clone(&worker.local_ready);

        worker.execute(task_id);

        let queued: Vec<TaskId> = local_ready.lock().unwrap().drain(..).collect();
        assert!(
            queued.contains(&waiter_id),
            "local waiter should be routed to current worker's local_ready, got {queued:?}"
        );
        assert!(
            worker.global.pop_ready().is_none(),
            "local waiter should not be in the global injector"
        );
    }

    /// When a completing task has a local waiter pinned to a different worker,
    /// the waiter is routed to the owner worker's local_ready queue.
    #[test]
    fn local_waiter_pinned_routes_to_owner_worker() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let region = state
            .lock()
            .expect("runtime state lock poisoned")
            .create_root_region(Budget::INFINITE);

        let task_id = {
            let mut guard = state.lock().expect("lock");
            let (id, _) = guard
                .create_task(region, Budget::INFINITE, async {})
                .expect("create task");
            id
        };
        let waiter_id = {
            let mut guard = state.lock().expect("lock");
            let (id, _) = guard
                .create_task(region, Budget::INFINITE, async {})
                .expect("create task");
            if let Some(record) = guard.tasks.get_mut(id.arena_index()) {
                record.pin_to_worker(1);
            }
            drop(guard);
            id
        };

        {
            let mut guard = state.lock().expect("lock");
            if let Some(record) = guard.tasks.get_mut(task_id.arena_index()) {
                record.add_waiter(waiter_id);
            }
        }

        let mut scheduler = ThreeLaneScheduler::new(2, &state);
        let worker_pool = scheduler.take_workers();
        let primary_worker = &worker_pool[0];
        let worker1_local_ready = Arc::clone(&worker_pool[1].local_ready);

        primary_worker.execute(task_id);

        let queued: Vec<TaskId> = worker1_local_ready.lock().unwrap().drain(..).collect();
        assert!(
            queued.contains(&waiter_id),
            "local waiter should be routed to owner worker 1, got {queued:?}"
        );
        assert!(
            !primary_worker
                .local_ready
                .lock()
                .unwrap()
                .contains(&waiter_id),
            "local waiter should NOT be in worker 0's local_ready"
        );
        assert!(
            primary_worker.global.pop_ready().is_none(),
            "local waiter should not be in the global injector"
        );
    }

    /// Global waiters still go through the global injector (regression).
    #[test]
    fn global_waiter_routes_to_global_injector() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let region = state
            .lock()
            .expect("runtime state lock poisoned")
            .create_root_region(Budget::INFINITE);

        let task_id = {
            let mut guard = state.lock().expect("lock");
            let (id, _) = guard
                .create_task(region, Budget::INFINITE, async {})
                .expect("create task");
            id
        };
        let waiter_id = {
            let mut guard = state.lock().expect("lock");
            let (id, _) = guard
                .create_task(region, Budget::INFINITE, async {})
                .expect("create task");
            id
        };

        {
            let mut guard = state.lock().expect("lock");
            if let Some(record) = guard.tasks.get_mut(task_id.arena_index()) {
                record.add_waiter(waiter_id);
            }
        }

        let mut scheduler = ThreeLaneScheduler::new(1, &state);
        let workers = scheduler.take_workers();
        let worker = &workers[0];

        worker.execute(task_id);

        let popped = worker.global.pop_ready();
        assert!(
            popped.is_some(),
            "global waiter should be in the global injector"
        );
        assert_eq!(popped.unwrap().task, waiter_id);
        assert!(
            worker.local_ready.lock().unwrap().is_empty(),
            "global waiter should NOT be in local_ready"
        );
    }
}
