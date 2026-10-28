//! Blocking pool for executing synchronous operations.
//!
// Allow clippy lints that are allowed at the crate level but not picked up in this module
#![allow(clippy::must_use_candidate)]
//!
//! This module provides a thread pool for running blocking operations without
//! blocking the async runtime. It supports:
//!
//! - **Capacity management**: Configurable min/max threads with dynamic scaling
//! - **Fairness**: FIFO by default, with opt-in priority and bounded fairness turns
//! - **Cancellation**: Soft cancellation with completion tracking
//! - **Shutdown**: Graceful shutdown with bounded drain timeout
//!
//! # Design
//!
//! The blocking pool manages a set of OS threads separate from the async worker
//! threads. When async code needs to perform a blocking operation (file I/O,
//! DNS resolution, CPU-intensive computation), it submits the work to this pool.
//!
//! ## Thread Lifecycle
//!
//! Threads are spawned lazily up to `max_threads`. When idle beyond a threshold,
//! threads above `min_threads` are retired. This balances responsiveness with
//! resource efficiency.
//!
//! ## Cancellation
//!
//! Blocking operations cannot be interrupted mid-execution. Instead, cancellation
//! is "soft": the task is marked cancelled, but a closure that already started
//! runs to completion, and one still queued is skipped. Either way the task's
//! completion is signalled, so waiting on its handle returns.
//!
//! # Example
//!
//! The pool runs `FnOnce()` closures; send a result back over a channel.
//! Async code normally uses [`spawn_blocking`](crate::runtime::spawn_blocking())
//! instead, which awaits the closure's return value.
//!
//! ```
//! use asupersync::runtime::BlockingPool;
//! use std::sync::mpsc;
//!
//! let pool = BlockingPool::new(1, 4);
//! let (tx, rx) = mpsc::channel();
//! let handle = pool.spawn(move || {
//!     let checksum: u64 = (1..=1_000u64).sum();
//!     let _ = tx.send(checksum);
//! });
//! handle.wait(); // blocks this thread until the closure has run
//! assert_eq!(rx.recv().unwrap(), 500_500);
//! pool.shutdown();
//! ```

use crate::runtime::config::BlockingPoolAffinityProfile;
use crate::runtime::pool_sizing::{
    PoolSizingAction, PoolSizingBounds, PoolSizingControllerState, PoolSizingDecision,
    PoolSizingPolicy, PoolSizingTarget, PoolWorkloadEstimate, decide_pool_sizing,
};
use parking_lot::{Condvar, Mutex};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle as ThreadJoinHandle};
use std::time::{Duration, Instant};

#[path = "blocking_pool/priority.rs"]
mod priority;
pub use priority::BlockingQueuePolicy;
use priority::BlockingTaskQueue;

/// Default idle timeout before retiring excess threads.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Time source hook used by timeout accounting paths.
pub type TimeGetter = fn() -> Instant;

/// Sleep hook used by blocking wait loops outside worker threads.
pub type SleepFn = fn(Duration);

fn wall_clock_now() -> Instant {
    Instant::now()
}

fn blocking_thread_sleep(duration: Duration) {
    thread::sleep(duration);
}

/// `None` when the timeout reaches past what `Instant` can represent (such as
/// `Duration::MAX`): the wait then has no deadline instead of panicking on the
/// overflow (br-asupersync-2u7bpm).
fn timeout_deadline(timeout: Duration, time_getter: TimeGetter) -> Option<Instant> {
    time_getter().checked_add(timeout)
}

fn timeout_remaining(deadline: Option<Instant>, time_getter: TimeGetter) -> Duration {
    deadline.map_or(Duration::MAX, |deadline| {
        deadline.saturating_duration_since(time_getter())
    })
}

fn drain_thread_handles(handles: &mut Vec<ThreadJoinHandle<()>>) -> Vec<ThreadJoinHandle<()>> {
    std::mem::take(handles)
}

fn drain_finished_thread_handles(
    handles: &mut Vec<ThreadJoinHandle<()>>,
) -> Vec<ThreadJoinHandle<()>> {
    let mut finished = Vec::new();
    let mut index = 0;
    while index < handles.len() {
        if handles[index].is_finished() {
            finished.push(handles.swap_remove(index));
        } else {
            index += 1;
        }
    }
    finished
}

fn join_thread_handles(handles: Vec<ThreadJoinHandle<()>>) {
    for handle in handles {
        let _ = handle.join();
    }
}

/// A handle to the blocking pool that can be cloned and shared.
#[derive(Clone)]
pub struct BlockingPoolHandle {
    inner: Arc<BlockingPoolInner>,
}

impl fmt::Debug for BlockingPoolHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockingPoolHandle")
            .field(
                "active_threads",
                &self.inner.active_threads.load(Ordering::Relaxed),
            )
            .field(
                "pending_tasks",
                &self.inner.pending_count.load(Ordering::Relaxed),
            )
            .finish()
    }
}

/// The blocking pool for executing synchronous operations.
pub struct BlockingPool {
    inner: Arc<BlockingPoolInner>,
}

/// Snapshot of blocking-pool affinity activity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockingPoolAffinityMetricsSnapshot {
    /// Whether cohort-aware queue routing is enabled.
    pub enabled: bool,
    /// Number of configured cohorts for affinity routing.
    pub cohort_count: usize,
    /// Number of tasks executed directly from a same-cohort queue.
    pub local_queue_dispatches: usize,
    /// Number of preferred-cohort tasks executed from the global spill queue.
    pub spill_dispatches: usize,
    /// Number of times a cohort hint fell back to global spill routing.
    pub fallback_dispatches: usize,
    /// Pending task counts for each cohort-local queue.
    pub cohort_pending_counts: Vec<usize>,
    /// Pending task count in the global spill/default queue.
    pub global_pending_count: usize,
}

impl fmt::Debug for BlockingPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let handles_len = self.inner.thread_handles.lock().len();
        f.debug_struct("BlockingPool")
            .field("min_threads", &self.inner.min_threads)
            .field("max_threads", &self.inner.max_threads)
            .field(
                "active_threads",
                &self.inner.active_threads.load(Ordering::Relaxed),
            )
            .field(
                "pending_tasks",
                &self.inner.pending_count.load(Ordering::Relaxed),
            )
            .field("thread_handles", &handles_len)
            .finish()
    }
}

impl BlockingPoolAffinityState {
    fn from_options(
        options: &BlockingPoolOptions,
        queue_policy: BlockingQueuePolicy,
    ) -> Option<Self> {
        match options.affinity_profile {
            BlockingPoolAffinityProfile::Disabled => None,
            BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit,
                spill_check_interval,
            } => {
                let cohort_count = options.cohort_count?;
                if cohort_count == 0 {
                    return None;
                }
                Some(Self {
                    cohort_count,
                    local_queue_soft_limit,
                    spill_check_interval,
                    cohort_queues: (0..cohort_count)
                        .map(|_| BlockingTaskQueue::new(queue_policy))
                        .collect(),
                    cohort_pending_counts: (0..cohort_count).map(|_| AtomicUsize::new(0)).collect(),
                    local_queue_dispatches: AtomicUsize::new(0),
                    spill_dispatches: AtomicUsize::new(0),
                    fallback_dispatches: AtomicUsize::new(0),
                })
            }
        }
    }

    fn route_task(
        &self,
        global_pending_count: &AtomicUsize,
        task: BlockingTask,
    ) -> Result<(), BlockingTask> {
        let Some(preferred_cohort) = task.preferred_cohort else {
            return Err(task);
        };
        if preferred_cohort >= self.cohort_count {
            self.fallback_dispatches.fetch_add(1, Ordering::Relaxed);
            return Err(task);
        }

        let local_pending = self.cohort_pending_counts[preferred_cohort].load(Ordering::Relaxed);
        if local_pending >= self.local_queue_soft_limit {
            self.fallback_dispatches.fetch_add(1, Ordering::Relaxed);
            return Err(task);
        }

        self.cohort_pending_counts[preferred_cohort].fetch_add(1, Ordering::Relaxed);
        global_pending_count.fetch_add(1, Ordering::Relaxed);
        self.cohort_queues[preferred_cohort].push(task);
        Ok(())
    }

    fn pop_local(&self, cohort: usize) -> Option<(BlockingTask, BlockingTaskDequeueKind)> {
        self.cohort_queues.get(cohort).and_then(|queue| {
            queue.pop().map(|task| {
                self.cohort_pending_counts[cohort].fetch_sub(1, Ordering::Relaxed);
                self.local_queue_dispatches.fetch_add(1, Ordering::Relaxed);
                (task, BlockingTaskDequeueKind::Local)
            })
        })
    }

    fn record_spill_dispatch(&self) {
        self.spill_dispatches.fetch_add(1, Ordering::Relaxed);
    }

    /// Steal a task from any *other* cohort's queue, used only as a last resort
    /// after the worker's own cohort queue and the global queue are both empty.
    ///
    /// Without this, a task routed to a cohort that currently has no live worker
    /// would never be dequeued and its waiter would hang forever. That happens
    /// whenever `cohort_count` exceeds the live worker count (the cohort count is
    /// derived from the scheduler worker map and is independent of the blocking
    /// pool's `min_threads`/`max_threads`), or when idle retirement shrinks the
    /// live worker set back to `min_threads` and leaves a cohort uncovered. Since
    /// worker cohorts are assigned by spawn order, neither routing nor the
    /// thread-id-derived spawn cohort guarantees coverage. Cohort affinity is a
    /// locality *preference*, not a hard partition, so stealing as a last resort
    /// preserves locality (own cohort and global are tried first) while keeping
    /// the pool work-conserving and deadlock-free.
    fn steal_foreign_cohort(
        &self,
        own_cohort: usize,
    ) -> Option<(BlockingTask, BlockingTaskDequeueKind)> {
        for (idx, queue) in self.cohort_queues.iter().enumerate() {
            if idx == own_cohort {
                continue;
            }
            if let Some(task) = queue.pop() {
                self.cohort_pending_counts[idx].fetch_sub(1, Ordering::Relaxed);
                self.spill_dispatches.fetch_add(1, Ordering::Relaxed);
                return Some((task, BlockingTaskDequeueKind::Spill));
            }
        }
        None
    }

    fn snapshot(&self, global_pending_count: usize) -> BlockingPoolAffinityMetricsSnapshot {
        BlockingPoolAffinityMetricsSnapshot {
            enabled: true,
            cohort_count: self.cohort_count,
            local_queue_dispatches: self.local_queue_dispatches.load(Ordering::Relaxed),
            spill_dispatches: self.spill_dispatches.load(Ordering::Relaxed),
            fallback_dispatches: self.fallback_dispatches.load(Ordering::Relaxed),
            cohort_pending_counts: self
                .cohort_pending_counts
                .iter()
                .map(|count| count.load(Ordering::Relaxed))
                .collect(),
            global_pending_count,
        }
    }
}

struct BlockingPoolInner {
    /// Minimum number of threads to keep alive.
    min_threads: usize,
    /// Maximum number of threads allowed (the hard ceiling).
    max_threads: usize,
    /// Live operational cap on spawns (yj2nxx.7), within `[min_threads, max_threads]`.
    ///
    /// Starts at `max_threads`; managed pool sizing may lower it to throttle
    /// spawning and raise it back, but never above `max_threads`. A shrink only
    /// blocks new spawns — threads above the cap retire naturally via idle
    /// timeout, so the atomic claim/retire invariants are preserved.
    live_max_threads: AtomicUsize,
    /// Set when the runtime sized this pool by default, for blocking I/O.
    default_sized: AtomicBool,
    /// Current number of active threads.
    active_threads: AtomicUsize,
    /// In-flight worker hand-offs: a retiring worker that observed pending work
    /// announces a pending replacement here *before* it decrements
    /// `active_threads`, and clears it only *after* the replacement spawn has
    /// been attempted. This closes a shutdown race where `shutdown_and_wait`
    /// could observe `active_threads == 0` in the window between the retiring
    /// worker's decrement and the replacement spawn, declare a clean shutdown,
    /// and leak the replacement's join handle (d679m7).
    replacement_pending: AtomicUsize,
    /// Number of threads currently executing work.
    busy_threads: AtomicUsize,
    /// Number of pending tasks in queue.
    pending_count: AtomicUsize,
    /// Next task ID for tracking.
    next_task_id: AtomicU64,
    /// Monotonic worker thread sequence for deterministic naming.
    next_thread_id: AtomicU64,
    /// Work queue.
    queue: BlockingTaskQueue,
    /// Optional cohort-aware blocking affinity state.
    affinity: Option<BlockingPoolAffinityState>,
    /// Shutdown flag.
    shutdown: AtomicBool,
    /// Condition variable for thread parking.
    condvar: Condvar,
    /// Mutex for condition-variable waits and queue/worker zero-boundary transitions.
    mutex: Mutex<()>,
    /// Idle timeout for excess threads.
    idle_timeout: Duration,
    /// Time source for timeout accounting.
    time_getter: TimeGetter,
    /// Sleep hook for blocking wait loops.
    sleep_fn: SleepFn,
    /// Thread name prefix.
    thread_name_prefix: String,
    /// Callback when a thread starts.
    on_thread_start: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Callback when a thread stops.
    on_thread_stop: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Thread join handles for cleanup.
    thread_handles: Mutex<Vec<ThreadJoinHandle<()>>>,
}

struct BlockingPoolAffinityState {
    cohort_count: usize,
    local_queue_soft_limit: usize,
    spill_check_interval: usize,
    cohort_queues: Vec<BlockingTaskQueue>,
    cohort_pending_counts: Vec<AtomicUsize>,
    local_queue_dispatches: AtomicUsize,
    spill_dispatches: AtomicUsize,
    fallback_dispatches: AtomicUsize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockingTaskDequeueKind {
    Global,
    Local,
    Spill,
}

/// A task submitted to the blocking pool.
struct BlockingTask {
    /// The work to execute.
    work: Box<dyn FnOnce() + Send + 'static>,
    /// Priority (higher = more important under the opt-in priority policy).
    priority: u8,
    /// Preferred cohort for locality-biased routing.
    preferred_cohort: Option<usize>,
    /// Cancellation flag.
    cancelled: Arc<AtomicBool>,
    /// Completion signal.
    completion: Arc<BlockingTaskCompletion>,
}

/// Completion tracking for a blocking task.
struct BlockingTaskCompletion {
    /// Whether the task has completed.
    done: AtomicBool,
    /// Condition variable for waiting.
    condvar: Condvar,
    /// Mutex for condition variable.
    mutex: Mutex<()>,
    /// Time source for timeout accounting.
    time_getter: TimeGetter,
}

impl BlockingTaskCompletion {
    fn new(time_getter: TimeGetter) -> Self {
        Self {
            done: AtomicBool::new(false),
            condvar: Condvar::new(),
            mutex: Mutex::new(()),
            time_getter,
        }
    }

    fn signal_done(&self) {
        self.done.store(true, Ordering::Release);
        let _guard = self.mutex.lock();
        self.condvar.notify_all();
    }

    fn wait(&self) {
        if self.done.load(Ordering::Acquire) {
            return;
        }
        {
            let mut guard = self.mutex.lock();
            while !self.done.load(Ordering::Acquire) {
                self.condvar.wait(&mut guard);
            }
            drop(guard);
        }
    }

    fn wait_timeout(&self, timeout: Duration) -> bool {
        if self.done.load(Ordering::Acquire) {
            return true;
        }
        let deadline = timeout_deadline(timeout, self.time_getter);
        let mut guard = self.mutex.lock();
        while !self.done.load(Ordering::Acquire) {
            let remaining = timeout_remaining(deadline, self.time_getter);
            if remaining.is_zero() {
                return false;
            }
            self.condvar.wait_for(&mut guard, remaining);
        }
        drop(guard);
        true
    }

    fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }
}

/// Handle for a submitted blocking task.
///
/// Provides cancellation and completion waiting.
pub struct BlockingTaskHandle {
    /// Task ID for debugging.
    #[allow(dead_code)]
    task_id: u64,
    /// Cancellation flag.
    cancelled: Arc<AtomicBool>,
    /// Completion tracking.
    completion: Arc<BlockingTaskCompletion>,
}

impl BlockingTaskHandle {
    /// Cancel this task.
    ///
    /// If the task is still queued, it will be skipped when dequeued.
    /// If the task is currently executing, it will run to completion
    /// but its result will be discarded.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Check if the task has been cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Check if the task has completed.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.completion.is_done()
    }

    /// Wait for the task to complete.
    ///
    /// Note: This blocks the calling thread. For async code, use
    /// the async completion mechanism instead.
    pub fn wait(&self) {
        self.completion.wait();
    }

    /// Wait for the task to complete with a timeout.
    ///
    /// Returns `true` if the task completed, `false` if the timeout elapsed.
    #[must_use]
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        self.completion.wait_timeout(timeout)
    }
}

impl fmt::Debug for BlockingTaskHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockingTaskHandle")
            .field("task_id", &self.task_id)
            .field("cancelled", &self.is_cancelled())
            .field("done", &self.is_done())
            .field("completion", &self.completion.is_done())
            .finish()
    }
}

impl BlockingPool {
    /// Creates a new blocking pool with the specified thread limits.
    ///
    /// # Arguments
    ///
    /// * `min_threads` - Minimum number of threads to keep alive
    /// * `max_threads` - Maximum number of threads allowed
    ///
    /// # Panics
    ///
    /// Panics if `max_threads` is 0 or `min_threads > max_threads`.
    #[must_use]
    pub fn new(min_threads: usize, max_threads: usize) -> Self {
        Self::with_config(min_threads, max_threads, BlockingPoolOptions::default())
    }

    /// Creates a new blocking pool with custom options.
    #[must_use]
    pub fn with_config(
        min_threads: usize,
        max_threads: usize,
        options: BlockingPoolOptions,
    ) -> Self {
        Self::with_config_and_queue_policy(
            min_threads,
            max_threads,
            options,
            BlockingQueuePolicy::Fifo,
        )
    }

    /// Creates a blocking pool with an explicit queue-selection policy.
    ///
    /// Existing constructors retain FIFO ordering. Priority scheduling is
    /// opt-in and applies independently within global and cohort queues.
    /// Admission remains unbounded; running closures are never preempted.
    ///
    /// # Panics
    ///
    /// Panics if `max_threads` is zero, `min_threads > max_threads`, or the
    /// thread-name prefix contains an interior NUL byte.
    #[must_use]
    pub fn with_config_and_queue_policy(
        min_threads: usize,
        max_threads: usize,
        options: BlockingPoolOptions,
        queue_policy: BlockingQueuePolicy,
    ) -> Self {
        assert!(max_threads > 0, "max_threads must be at least 1");
        assert!(
            min_threads <= max_threads,
            "min_threads must be less than or equal to max_threads"
        );
        assert!(
            !options.thread_name_prefix.contains('\0'),
            "thread_name_prefix may not contain interior NUL bytes"
        );

        let affinity = BlockingPoolAffinityState::from_options(&options, queue_policy);
        let inner = Arc::new(BlockingPoolInner {
            min_threads,
            max_threads,
            live_max_threads: AtomicUsize::new(max_threads),
            default_sized: AtomicBool::new(false),
            active_threads: AtomicUsize::new(0),
            replacement_pending: AtomicUsize::new(0),
            busy_threads: AtomicUsize::new(0),
            pending_count: AtomicUsize::new(0),
            next_task_id: AtomicU64::new(1),
            next_thread_id: AtomicU64::new(1),
            queue: BlockingTaskQueue::new(queue_policy),
            affinity,
            shutdown: AtomicBool::new(false),
            condvar: Condvar::new(),
            mutex: Mutex::new(()),
            idle_timeout: options.idle_timeout,
            time_getter: options.time_getter,
            sleep_fn: options.sleep_fn,
            thread_name_prefix: options.thread_name_prefix,
            on_thread_start: options.on_thread_start,
            on_thread_stop: options.on_thread_stop,
            thread_handles: Mutex::new(Vec::with_capacity(max_threads)),
        });

        let pool = Self { inner };

        // Spawn minimum threads eagerly
        for _ in 0..min_threads {
            pool.spawn_thread();
        }

        pool
    }

    /// Returns a cloneable handle to this pool.
    #[must_use]
    pub fn handle(&self) -> BlockingPoolHandle {
        BlockingPoolHandle {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Spawns a blocking task.
    ///
    /// The closure will be executed on a blocking pool thread.
    ///
    /// # Returns
    ///
    /// A handle that can be used to cancel or wait for the task.
    pub fn spawn<F>(&self, f: F) -> BlockingTaskHandle
    where
        F: FnOnce() + Send + 'static,
    {
        self.spawn_with_affinity(f, 128, None)
    }

    /// Spawns a blocking task with a preferred cohort for locality-biased routing.
    pub fn spawn_on_cohort<F>(&self, cohort: usize, f: F) -> BlockingTaskHandle
    where
        F: FnOnce() + Send + 'static,
    {
        self.spawn_with_affinity(f, 128, Some(cohort))
    }

    /// Spawns a blocking task with a priority.
    ///
    /// Larger values are preferred when a priority queue policy is selected.
    /// FIFO pools record the value but retain arrival order.
    pub fn spawn_with_priority<F>(&self, f: F, priority: u8) -> BlockingTaskHandle
    where
        F: FnOnce() + Send + 'static,
    {
        self.spawn_with_affinity(f, priority, None)
    }

    /// Spawns a blocking task with both a cohort hint and explicit priority.
    ///
    /// The queue policy selects within the routed queue; existing cohort
    /// locality, spill, and foreign-cohort fairness turns remain in effect.
    pub fn spawn_on_cohort_with_priority<F>(
        &self,
        cohort: usize,
        f: F,
        priority: u8,
    ) -> BlockingTaskHandle
    where
        F: FnOnce() + Send + 'static,
    {
        self.spawn_with_affinity(f, priority, Some(cohort))
    }

    /// Returns the queue-selection policy installed when the pool was built.
    #[must_use]
    pub fn queue_policy(&self) -> BlockingQueuePolicy {
        self.inner.queue.policy()
    }

    fn spawn_with_affinity<F>(
        &self,
        f: F,
        priority: u8,
        preferred_cohort: Option<usize>,
    ) -> BlockingTaskHandle
    where
        F: FnOnce() + Send + 'static,
    {
        let task_id = self.inner.next_task_id.fetch_add(1, Ordering::Relaxed);
        let cancelled = Arc::new(AtomicBool::new(false));
        let completion = Arc::new(BlockingTaskCompletion::new(self.inner.time_getter));
        let handle = BlockingTaskHandle {
            task_id,
            cancelled: Arc::clone(&cancelled),
            completion: Arc::clone(&completion),
        };

        // Contract: after shutdown, new tasks are rejected.
        // Return an already-completed cancelled handle instead of queueing work.
        if self.inner.shutdown.load(Ordering::Acquire) {
            cancelled.store(true, Ordering::Release);
            completion.signal_done();
            return handle;
        }

        let task = BlockingTask {
            work: Box::new(f),
            priority,
            preferred_cohort,
            cancelled: Arc::clone(&cancelled),
            completion: Arc::clone(&completion),
        };

        if !try_enqueue_task(&self.inner, task) {
            cancelled.store(true, Ordering::Release);
            completion.signal_done();
            return handle;
        }

        // Wake a waiting thread or spawn a new one if needed
        self.maybe_spawn_thread();
        self.notify_one();

        handle
    }

    /// Returns a snapshot of locality-routing activity for this pool.
    #[must_use]
    pub fn affinity_metrics(&self) -> BlockingPoolAffinityMetricsSnapshot {
        blocking_pool_affinity_metrics(&self.inner)
    }

    /// Returns the number of pending tasks in the queue.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.inner.pending_count.load(Ordering::Relaxed)
    }

    /// Returns the number of active threads.
    #[must_use]
    pub fn active_threads(&self) -> usize {
        self.inner.active_threads.load(Ordering::Relaxed)
    }

    /// Returns the number of threads currently executing work.
    #[must_use]
    pub fn busy_threads(&self) -> usize {
        self.inner.busy_threads.load(Ordering::Relaxed)
    }

    /// Returns the hard floor and ceiling used by advisory pool-sizing.
    #[must_use]
    pub fn pool_sizing_bounds(&self) -> PoolSizingBounds {
        blocking_pool_sizing_bounds(&self.inner)
    }

    /// Returns the live controller state used by advisory pool-sizing.
    #[must_use]
    pub fn pool_sizing_controller_state(&self) -> PoolSizingControllerState {
        blocking_pool_sizing_controller_state(&self.inner)
    }

    /// Computes an advisory pool-sizing decision without resizing the pool.
    #[must_use]
    pub fn advisory_pool_sizing_decision(
        &self,
        estimate: PoolWorkloadEstimate,
        target: PoolSizingTarget,
    ) -> PoolSizingDecision {
        blocking_pool_advisory_pool_sizing_decision(&self.inner, estimate, target)
    }

    /// The live operational cap on worker spawns (yj2nxx.7).
    ///
    /// Starts at the configured `max_threads` and is adjusted by
    /// [`set_max_threads`](Self::set_max_threads) within
    /// `[min_threads, max_threads]`. `pool_sizing_bounds()` keeps reporting the
    /// configured floor/ceiling.
    #[must_use]
    pub fn current_max_threads(&self) -> usize {
        blocking_pool_current_max_threads(&self.inner)
    }

    /// Set the live spawn cap, clamped into `[min_threads, max_threads]`.
    ///
    /// The configured `max_threads` is the hard ceiling. A shrink only blocks
    /// new spawns; threads above the cap retire naturally via idle timeout, so
    /// the pool's atomic claim/retire invariants are preserved. Returns the
    /// clamped value actually applied.
    pub fn set_max_threads(&self, requested: usize) -> usize {
        blocking_pool_set_max_threads(&self.inner, requested)
    }

    /// Apply a managed pool-sizing decision to the live spawn cap.
    ///
    /// Only [`PoolSizingAction::Resize`] mutates the cap (clamped into the
    /// configured bounds); advisory mode and hysteresis/cadence holds are
    /// no-ops. Returns the applied size when a resize was taken.
    pub fn apply_pool_sizing_decision(&self, decision: &PoolSizingDecision) -> Option<usize> {
        blocking_pool_apply_pool_sizing_decision(&self.inner, decision)
    }

    /// Returns `true` if the pool is shut down.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.inner.shutdown.load(Ordering::Acquire)
    }

    /// Closes admission without waiting for the pool coordination mutex.
    ///
    /// Runtime bounded shutdown uses this as its caller-thread linearization
    /// point: submissions that race the store either completed admission
    /// before it or observe shutdown and fail closed. A reaper must still call
    /// [`shutdown`](Self::shutdown) to coordinate the condition-variable wake
    /// without a lost-wakeup race.
    pub(crate) fn close_admission(&self) {
        self.inner.shutdown.store(true, Ordering::Release);
    }

    /// Initiates shutdown of the pool.
    ///
    /// No new tasks will be accepted. Pending tasks will continue to execute.
    pub fn shutdown(&self) {
        let _guard = self.inner.mutex.lock();
        self.close_admission();
        self.inner.condvar.notify_all();
    }

    /// Shuts down and waits for all threads to exit.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum time to wait for threads to finish
    ///
    /// # Returns
    ///
    /// `true` if all threads exited cleanly, `false` if timeout elapsed.
    pub fn shutdown_and_wait(&self, timeout: Duration) -> bool {
        self.shutdown();

        let deadline = timeout_deadline(timeout, self.inner.time_getter);

        // Wait until no worker is active, no retiring worker has a replacement
        // hand-off in flight (announced in `replacement_pending` before it
        // decrements `active_threads`, cleared after its spawn decision;
        // d679m7), and no accepted job is still queued: a submitter preempted
        // between its enqueue and its `maybe_spawn` starts a worker later, and
        // returning first would leak that worker's never-joined handle and run
        // the job after teardown (mopkmt).
        while self.inner.active_threads.load(Ordering::Acquire) > 0
            || self.inner.replacement_pending.load(Ordering::Acquire) > 0
            || blocking_pool_has_pending_work(&self.inner)
        {
            let remaining = timeout_remaining(deadline, self.inner.time_getter);
            if remaining.is_zero() {
                return false;
            }

            // Wake any waiting threads so they notice the shutdown flag
            self.notify_all();

            // Wait a bit before checking again
            (self.inner.sleep_fn)(Duration::from_millis(10).min(remaining));
        }

        // All workers have retired and no hand-off is pending, so every handle
        // they published is final. Now join the handles to clean up.
        let handles = {
            let mut handles = self.inner.thread_handles.lock();
            drain_thread_handles(&mut handles)
        };
        // Join outside the mutex so exiting workers can still publish
        // replacement handles during shutdown-drain races.
        join_thread_handles(handles);

        true
    }

    fn spawn_thread(&self) {
        spawn_thread_on_inner(&self.inner);
    }

    fn maybe_spawn_thread(&self) {
        maybe_spawn_thread_on_inner(&self.inner);
    }

    fn notify_one(&self) {
        let _guard = self.inner.mutex.lock();
        self.inner.condvar.notify_one();
    }

    fn notify_all(&self) {
        let _guard = self.inner.mutex.lock();
        self.inner.condvar.notify_all();
    }
}

impl Drop for BlockingPool {
    fn drop(&mut self) {
        self.shutdown();
        // Give threads a chance to exit gracefully
        let _ = self.shutdown_and_wait(Duration::from_secs(5));
    }
}

impl BlockingPoolHandle {
    /// Spawns a blocking task.
    pub fn spawn<F>(&self, f: F) -> BlockingTaskHandle
    where
        F: FnOnce() + Send + 'static,
    {
        self.spawn_with_affinity(f, 128, None)
    }

    /// Spawns a blocking task with a preferred cohort for locality-biased routing.
    pub fn spawn_on_cohort<F>(&self, cohort: usize, f: F) -> BlockingTaskHandle
    where
        F: FnOnce() + Send + 'static,
    {
        self.spawn_with_affinity(f, 128, Some(cohort))
    }

    /// Spawns a blocking task with a priority.
    pub fn spawn_with_priority<F>(&self, f: F, priority: u8) -> BlockingTaskHandle
    where
        F: FnOnce() + Send + 'static,
    {
        self.spawn_with_affinity(f, priority, None)
    }

    /// Spawns a blocking task with both a cohort hint and explicit priority.
    ///
    /// The queue policy selects within the routed queue; existing cohort
    /// locality, spill, and foreign-cohort fairness turns remain in effect.
    pub fn spawn_on_cohort_with_priority<F>(
        &self,
        cohort: usize,
        f: F,
        priority: u8,
    ) -> BlockingTaskHandle
    where
        F: FnOnce() + Send + 'static,
    {
        self.spawn_with_affinity(f, priority, Some(cohort))
    }

    /// Returns the queue-selection policy installed when the pool was built.
    #[must_use]
    pub fn queue_policy(&self) -> BlockingQueuePolicy {
        self.inner.queue.policy()
    }

    fn spawn_with_affinity<F>(
        &self,
        f: F,
        priority: u8,
        preferred_cohort: Option<usize>,
    ) -> BlockingTaskHandle
    where
        F: FnOnce() + Send + 'static,
    {
        let task_id = self.inner.next_task_id.fetch_add(1, Ordering::Relaxed);
        let cancelled = Arc::new(AtomicBool::new(false));
        let completion = Arc::new(BlockingTaskCompletion::new(self.inner.time_getter));
        let handle = BlockingTaskHandle {
            task_id,
            cancelled: Arc::clone(&cancelled),
            completion: Arc::clone(&completion),
        };

        // Keep behavior aligned with BlockingPool::spawn_with_priority.
        if self.inner.shutdown.load(Ordering::Acquire) {
            cancelled.store(true, Ordering::Release);
            completion.signal_done();
            return handle;
        }

        let task = BlockingTask {
            work: Box::new(f),
            priority,
            preferred_cohort,
            cancelled: Arc::clone(&cancelled),
            completion: Arc::clone(&completion),
        };

        if !try_enqueue_task(&self.inner, task) {
            cancelled.store(true, Ordering::Release);
            completion.signal_done();
            return handle;
        }

        // Wake a waiting thread or spawn a new one if needed
        maybe_spawn_thread_on_inner(&self.inner);
        {
            let _guard = self.inner.mutex.lock();
            self.inner.condvar.notify_one();
        }

        handle
    }

    /// Returns the number of pending tasks.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.inner.pending_count.load(Ordering::Relaxed)
    }

    /// Returns the number of active threads.
    #[must_use]
    pub fn active_threads(&self) -> usize {
        self.inner.active_threads.load(Ordering::Relaxed)
    }

    /// Returns the number of threads currently executing work.
    #[must_use]
    pub fn busy_threads(&self) -> usize {
        self.inner.busy_threads.load(Ordering::Relaxed)
    }

    /// Returns the hard floor and ceiling used by advisory pool-sizing.
    #[must_use]
    pub fn pool_sizing_bounds(&self) -> PoolSizingBounds {
        blocking_pool_sizing_bounds(&self.inner)
    }

    /// Returns the live controller state used by advisory pool-sizing.
    #[must_use]
    pub fn pool_sizing_controller_state(&self) -> PoolSizingControllerState {
        blocking_pool_sizing_controller_state(&self.inner)
    }

    /// Computes an advisory pool-sizing decision without resizing the pool.
    #[must_use]
    pub fn advisory_pool_sizing_decision(
        &self,
        estimate: PoolWorkloadEstimate,
        target: PoolSizingTarget,
    ) -> PoolSizingDecision {
        blocking_pool_advisory_pool_sizing_decision(&self.inner, estimate, target)
    }

    /// The live operational cap on worker spawns (yj2nxx.7).
    #[must_use]
    pub fn current_max_threads(&self) -> usize {
        blocking_pool_current_max_threads(&self.inner)
    }

    /// Whether the cap was chosen explicitly and so may bound CPU-bound fan-out.
    #[must_use]
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn is_explicitly_sized(&self) -> bool {
        !self.inner.default_sized.load(Ordering::Relaxed)
    }

    /// Records that the runtime sized this pool by default (kpmoy5.1.15).
    pub(crate) fn mark_default_sized(&self) {
        self.inner.default_sized.store(true, Ordering::Relaxed);
    }

    /// Set the live spawn cap, clamped into `[min_threads, max_threads]`.
    ///
    /// See [`BlockingPool::set_max_threads`]; the configured `max_threads` stays
    /// the hard ceiling and a shrink only blocks new spawns.
    pub fn set_max_threads(&self, requested: usize) -> usize {
        blocking_pool_set_max_threads(&self.inner, requested)
    }

    /// Apply a managed pool-sizing decision to the live spawn cap.
    ///
    /// Only [`PoolSizingAction::Resize`] mutates the cap; advisory and
    /// hysteresis/cadence holds are no-ops. Returns the applied size when a
    /// resize was taken.
    pub fn apply_pool_sizing_decision(&self, decision: &PoolSizingDecision) -> Option<usize> {
        blocking_pool_apply_pool_sizing_decision(&self.inner, decision)
    }

    /// Returns a snapshot of locality-routing activity for this handle's pool.
    #[must_use]
    pub fn affinity_metrics(&self) -> BlockingPoolAffinityMetricsSnapshot {
        blocking_pool_affinity_metrics(&self.inner)
    }

    /// Returns `true` if the pool is shut down.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.inner.shutdown.load(Ordering::Acquire)
    }
}

fn try_enqueue_task(inner: &Arc<BlockingPoolInner>, task: BlockingTask) -> bool {
    let _guard = inner.mutex.lock();
    if inner.shutdown.load(Ordering::Acquire) {
        return false;
    }
    if let Some(affinity) = inner.affinity.as_ref() {
        match affinity.route_task(&inner.pending_count, task) {
            Ok(()) => return true,
            Err(task) => {
                inner.pending_count.fetch_add(1, Ordering::Relaxed);
                inner.queue.push(task);
                return true;
            }
        }
    }
    // Count the task before publishing it, as `route_task` does: a worker that
    // pops it at once must not take `pending_count` below zero.
    inner.pending_count.fetch_add(1, Ordering::Relaxed);
    inner.queue.push(task);
    true
}

fn blocking_pool_has_pending_work(inner: &BlockingPoolInner) -> bool {
    inner.pending_count.load(Ordering::Acquire) > 0
}

fn blocking_pool_affinity_metrics(
    inner: &BlockingPoolInner,
) -> BlockingPoolAffinityMetricsSnapshot {
    let global_pending_count =
        inner
            .pending_count
            .load(Ordering::Relaxed)
            .saturating_sub(inner.affinity.as_ref().map_or(0, |affinity| {
                affinity
                    .cohort_pending_counts
                    .iter()
                    .map(|count| count.load(Ordering::Relaxed))
                    .sum::<usize>()
            }));

    match inner.affinity.as_ref() {
        Some(affinity) => affinity.snapshot(global_pending_count),
        None => BlockingPoolAffinityMetricsSnapshot {
            enabled: false,
            cohort_count: 0,
            local_queue_dispatches: 0,
            spill_dispatches: 0,
            fallback_dispatches: 0,
            cohort_pending_counts: Vec::new(),
            global_pending_count,
        },
    }
}

fn blocking_pool_sizing_bounds(inner: &BlockingPoolInner) -> PoolSizingBounds {
    PoolSizingBounds::new(inner.min_threads, inner.max_threads)
}

fn blocking_pool_current_max_threads(inner: &BlockingPoolInner) -> usize {
    inner.live_max_threads.load(Ordering::Relaxed)
}

fn blocking_pool_set_max_threads(inner: &Arc<BlockingPoolInner>, requested: usize) -> usize {
    // The live spawn cap must never reach 0 for a constructed pool. `max_threads`
    // is asserted >= 1 at construction (a max_threads == 0 runtime simply has no
    // pool and rejects `spawn_blocking`), and a pool that accepts work must be
    // able to run at least one task. A 0 cap silently strands every submitted
    // task: `maybe_spawn_thread_on_inner`'s `active < live_max` gate can never
    // fire (0 < 0 is false), so the task is enqueued and a handle is returned,
    // but no worker is ever created and the completion is never signalled —
    // `wait()` hangs forever. This is reachable on any `min_threads == 0`
    // elastic pool via `set_max_threads(0)` or a sizing-controller Resize to 0.
    // Idle retirement to 0 *active* threads is governed by `min_threads`, not by
    // this cap, so flooring the cap at 1 preserves elastic-to-zero behavior while
    // guaranteeing on-demand spawn always works.
    let applied = requested
        .max(inner.min_threads)
        .max(1)
        .min(inner.max_threads);
    inner.live_max_threads.store(applied, Ordering::Relaxed);
    // Jobs queued under a lower cap get their threads now, not one per later
    // submission (br-asupersync-2u7bpm).
    if !inner.shutdown.load(Ordering::Acquire) {
        maybe_spawn_thread_on_inner(inner);
    }
    applied
}

fn blocking_pool_apply_pool_sizing_decision(
    inner: &Arc<BlockingPoolInner>,
    decision: &PoolSizingDecision,
) -> Option<usize> {
    match decision.action {
        PoolSizingAction::Resize { to_size, .. } => {
            Some(blocking_pool_set_max_threads(inner, to_size))
        }
        _ => None,
    }
}

fn blocking_pool_sizing_controller_state(inner: &BlockingPoolInner) -> PoolSizingControllerState {
    PoolSizingControllerState {
        current_size: inner.active_threads.load(Ordering::Relaxed),
        last_resize_epoch: 0,
    }
}

fn blocking_pool_advisory_pool_sizing_decision(
    inner: &BlockingPoolInner,
    estimate: PoolWorkloadEstimate,
    target: PoolSizingTarget,
) -> PoolSizingDecision {
    let mut policy = PoolSizingPolicy::advisory(blocking_pool_sizing_bounds(inner));
    policy.target = target;
    decide_pool_sizing(
        policy,
        blocking_pool_sizing_controller_state(inner),
        estimate,
        0,
    )
}

fn pop_next_blocking_task(
    inner: &BlockingPoolInner,
    assigned_cohort: Option<usize>,
    prefer_local_turn: bool,
) -> Option<(BlockingTask, BlockingTaskDequeueKind)> {
    let pop_global = || {
        inner.queue.pop().map(|task| {
            let kind = if let (Some(_), Some(affinity)) =
                (task.preferred_cohort, inner.affinity.as_ref())
            {
                affinity.record_spill_dispatch();
                BlockingTaskDequeueKind::Spill
            } else {
                BlockingTaskDequeueKind::Global
            };
            (task, kind)
        })
    };

    let Some(cohort) = assigned_cohort else {
        return pop_global();
    };
    let Some(affinity) = inner.affinity.as_ref() else {
        return pop_global();
    };

    if prefer_local_turn {
        affinity
            .pop_local(cohort)
            .or_else(pop_global)
            .or_else(|| affinity.steal_foreign_cohort(cohort))
    } else {
        pop_global()
            .or_else(|| affinity.pop_local(cohort))
            .or_else(|| affinity.steal_foreign_cohort(cohort))
    }
}

/// Configuration options for the blocking pool.
#[derive(Clone)]
pub struct BlockingPoolOptions {
    /// Idle timeout before retiring excess threads.
    pub idle_timeout: Duration,
    /// Time source used for timeout accounting.
    ///
    /// Primarily intended for deterministic tests and custom runtimes that
    /// need blocking-pool waits to align with a controlled clock.
    pub time_getter: TimeGetter,
    /// Sleep hook used by shutdown wait loops outside worker threads.
    ///
    /// Primarily intended for deterministic tests that need to advance a
    /// synthetic clock without sleeping the host thread.
    pub sleep_fn: SleepFn,
    /// Thread name prefix.
    pub thread_name_prefix: String,
    /// Callback when a thread starts.
    pub on_thread_start: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Callback when a thread stops.
    pub on_thread_stop: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Explicit affinity profile for locality-aware blocking queues.
    pub affinity_profile: BlockingPoolAffinityProfile,
    /// Number of scheduler cohorts available for blocking-pool routing.
    pub cohort_count: Option<usize>,
}

impl Default for BlockingPoolOptions {
    fn default() -> Self {
        Self {
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            time_getter: wall_clock_now,
            sleep_fn: blocking_thread_sleep,
            thread_name_prefix: "asupersync".to_string(),
            on_thread_start: None,
            on_thread_stop: None,
            affinity_profile: BlockingPoolAffinityProfile::Disabled,
            cohort_count: None,
        }
    }
}

impl fmt::Debug for BlockingPoolOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockingPoolOptions")
            .field("idle_timeout", &self.idle_timeout)
            .field(
                "custom_time_getter",
                &(!std::ptr::fn_addr_eq(self.time_getter, wall_clock_now as TimeGetter)),
            )
            .field(
                "custom_sleep_fn",
                &(!std::ptr::fn_addr_eq(self.sleep_fn, blocking_thread_sleep as SleepFn)),
            )
            .field("thread_name_prefix", &self.thread_name_prefix)
            .field("on_thread_start", &self.on_thread_start.is_some())
            .field("on_thread_stop", &self.on_thread_stop.is_some())
            .field("affinity_profile", &self.affinity_profile)
            .field("cohort_count", &self.cohort_count)
            .finish()
    }
}

/// Tasks detached from every queue after the last claimed worker fails to
/// spawn. Queue accounting is captured alongside the tasks so invariant checks
/// can run after their user-owned closures have been cancelled and dropped.
struct StrandedBlockingTasks {
    tasks: Vec<BlockingTask>,
    recorded_pending: usize,
    recorded_cohort_pending: usize,
    drained_cohort_tasks: usize,
}

impl StrandedBlockingTasks {
    fn cancel(self) {
        let Self {
            tasks,
            recorded_pending,
            recorded_cohort_pending,
            drained_cohort_tasks,
        } = self;
        let drained_tasks = tasks.len();

        // Keep user-owned closure destruction outside the pool mutex: captured
        // values may re-enter the pool from Drop.
        for task in tasks {
            task.cancelled.store(true, Ordering::Release);
            task.completion.signal_done();
        }

        debug_assert_eq!(
            recorded_pending, drained_tasks,
            "failed worker spawn must drain every pending blocking task"
        );
        debug_assert_eq!(
            recorded_cohort_pending, drained_cohort_tasks,
            "failed worker spawn must restore every cohort queue count"
        );
    }
}

/// Roll back one claimed worker after OS thread creation fails.
///
/// The caller holds `inner.mutex`, which serializes this transition with task
/// submission, other worker spawns, and idle-retirement claims. If another
/// worker remains, queued work stays available to it. If this was the last
/// claim, every queue is detached and its handles are completed as cancelled
/// after the mutex is released.
fn rollback_failed_worker_spawn_locked(inner: &BlockingPoolInner) -> Option<StrandedBlockingTasks> {
    let claimed_workers = inner.active_threads.fetch_sub(1, Ordering::AcqRel);
    debug_assert!(claimed_workers > 0, "failed spawn must own a worker claim");
    if claimed_workers != 1 {
        return None;
    }

    let mut tasks = Vec::new();
    while let Some(task) = inner.queue.pop() {
        tasks.push(task);
    }

    let mut recorded_cohort_pending = 0usize;
    let mut drained_cohort_tasks = 0usize;
    if let Some(affinity) = inner.affinity.as_ref() {
        for (queue, pending) in affinity
            .cohort_queues
            .iter()
            .zip(&affinity.cohort_pending_counts)
        {
            recorded_cohort_pending =
                recorded_cohort_pending.saturating_add(pending.swap(0, Ordering::AcqRel));
            while let Some(task) = queue.pop() {
                drained_cohort_tasks = drained_cohort_tasks.saturating_add(1);
                tasks.push(task);
            }
        }
    }

    let recorded_pending = inner.pending_count.swap(0, Ordering::AcqRel);
    Some(StrandedBlockingTasks {
        tasks,
        recorded_pending,
        recorded_cohort_pending,
        drained_cohort_tasks,
    })
}

/// Spawn a new worker thread on the given pool inner.
fn spawn_thread_on_inner(inner: &Arc<BlockingPoolInner>) {
    // Build the named thread builder before mutating worker accounting.
    // `std::thread::Builder::name` panics on interior NUL bytes, so doing
    // this after incrementing `active_threads` would leak the counter on
    // panic and strand the pool in an inconsistent state.
    let thread_id = inner.next_thread_id.fetch_add(1, Ordering::Relaxed);
    let name = format!("{}-blocking-{}", inner.thread_name_prefix, thread_id);
    let builder = thread::Builder::new().name(name);
    let assigned_cohort = inner
        .affinity
        .as_ref()
        .map(|affinity| ((thread_id.saturating_sub(1)) as usize) % affinity.cohort_count);

    let mut stranded_tasks = None;
    let mut finished_handles = Vec::new();
    // Serialize the worker claim through thread creation and failure recovery.
    // `try_enqueue_task` uses the same mutex, so observing zero workers here
    // gives an authoritative boundary for detaching queues.
    let spawn_guard = inner.mutex.lock();

    // Enforce max_threads atomically to prevent overshoot during concurrent spawns
    // Fix TOCTOU race: use Acquire/Release ordering to prevent multiple threads
    // from seeing stale counts and bypassing the limit simultaneously
    loop {
        let current = inner.active_threads.load(Ordering::Acquire);
        if current >= inner.live_max_threads.load(Ordering::Relaxed) {
            return;
        }

        // Double-check limit before increment to prevent TOCTOU bypass
        if current + 1 > inner.live_max_threads.load(Ordering::Relaxed) {
            return;
        }

        if inner
            .active_threads
            .compare_exchange_weak(current, current + 1, Ordering::Release, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
    }

    let inner_clone = Arc::clone(inner);
    match builder.spawn(move || {
        struct ThreadExitGuard<'a> {
            inner: &'a Arc<BlockingPoolInner>,
            retired_with_claim: bool,
        }

        impl Drop for ThreadExitGuard<'_> {
            fn drop(&mut self) {
                if let Some(ref callback) = self.inner.on_thread_stop {
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        callback();
                    }));
                }

                if !self.retired_with_claim {
                    // A spawn that linearized just before this worker exits may
                    // enqueue work while the worker is already on its exit path.
                    // If this was the last active worker, hand the task off to a
                    // replacement before the pool goes quiescent and strands the
                    // accepted work.
                    //
                    // Bracket the whole decrement -> check -> spawn sequence in
                    // `replacement_pending`, announced *unconditionally* before
                    // the decrement and cleared only *after* the spawn decision.
                    // Without this, a concurrent `shutdown_and_wait` could
                    // observe `active_threads == 0` in the gap before a
                    // replacement is spawned, declare a clean shutdown, and leak
                    // the replacement's never-joined handle (d679m7).
                    //
                    // The pending check MUST stay *after* the decrement, with a
                    // SeqCst fence between them that pairs with the one in
                    // `maybe_spawn_thread_on_inner` (store, fence, load on both
                    // sides): then either this worker observes work enqueued
                    // meanwhile, or that enqueuer sees the decremented count and
                    // spawns a worker itself. Checked before the decrement, or
                    // without the fence on a weak memory model, a task enqueued
                    // in between could be stranded with no worker (mopkmt).
                    self.inner
                        .replacement_pending
                        .fetch_add(1, Ordering::Release);
                    self.inner.active_threads.fetch_sub(1, Ordering::Release);
                    std::sync::atomic::fence(Ordering::SeqCst);
                    if blocking_pool_has_pending_work(self.inner) {
                        maybe_spawn_thread_on_inner(self.inner);
                        let _guard = self.inner.mutex.lock();
                        self.inner.condvar.notify_one();
                    }
                    self.inner
                        .replacement_pending
                        .fetch_sub(1, Ordering::Release);
                }
            }
        }

        let mut guard = ThreadExitGuard {
            inner: &inner_clone,
            retired_with_claim: false,
        };

        // Contained like the stop hook: a start hook that panics on every
        // thread used to kill each worker before its first job, and the exit
        // guard then spawned a replacement that died the same way, so the pool
        // churned threads at full speed, no job ever ran, and shutdown timed
        // out (br-asupersync-mopkmt).
        if let Some(ref callback) = inner_clone.on_thread_start {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                callback();
            }));
        }

        guard.retired_with_claim = blocking_worker_loop(&inner_clone, assigned_cohort);
        let _ = guard.retired_with_claim;
    }) {
        Ok(handle) => {
            let mut handles = inner.thread_handles.lock();
            handles.push(handle);

            // Clean up finished thread handles to prevent unbounded memory
            // growth during workload bursts where threads frequently spawn
            // and retire.
            finished_handles = drain_finished_thread_handles(&mut handles);
        }
        Err(_) => {
            // A failed final worker claim cannot leave accepted tasks with
            // handles that wait forever. Detach them while submissions and
            // retirement are excluded, then signal them after unlocking.
            stranded_tasks = rollback_failed_worker_spawn_locked(inner);
        }
    }

    drop(spawn_guard);
    join_thread_handles(finished_handles);
    if let Some(stranded_tasks) = stranded_tasks {
        stranded_tasks.cancel();
    }
}

impl Drop for BlockingPoolInner {
    fn drop(&mut self) {
        // Handles still here when the last reference goes (a shutdown that
        // timed out) belong to workers that may be exiting right now, often
        // this thread among them. Dropping them would detach those threads
        // (GitHub #80), so finished ones are joined and running ones parked.
        crate::runtime::spawn_blocking::reap_threads(std::mem::take(self.thread_handles.get_mut()));
    }
}

/// Check if we should spawn a new thread and do so if needed.
fn maybe_spawn_thread_on_inner(inner: &Arc<BlockingPoolInner>) {
    // Enqueue half of the Dekker pattern with idle retirement (see the matching
    // fence in blocking_worker_loop): the caller has already STOREd
    // pending_count++; this fence orders that store before the active_threads
    // LOAD below in the global SeqCst order, so a retiree that decremented
    // active_threads concurrently is guaranteed to observe our pending work (or
    // we observe its decrement and spawn a replacement). Prevents a stranded
    // task on a min_threads==0 pool on weak memory models (no-op on x86).
    //
    // Spawn while:
    // 1. We're below max_threads
    // 2. The number of pending tasks exceeds the number of idle threads
    //    (idle = active - busy). This handles bursts of tasks correctly
    //    even before threads have woken up to increment `busy_threads`.
    // More than one thread can be due at once, after a raised cap or several
    // queued tasks; each spawn claims its `active_threads` slot before it
    // returns, so the next pass sees it.
    loop {
        std::sync::atomic::fence(Ordering::SeqCst);
        let active = inner.active_threads.load(Ordering::Relaxed);
        let busy = inner.busy_threads.load(Ordering::Relaxed);
        let pending = inner.pending_count.load(Ordering::Relaxed);
        let idle = active.saturating_sub(busy);
        if active >= inner.live_max_threads.load(Ordering::Relaxed) || pending <= idle {
            return;
        }
        spawn_thread_on_inner(inner);
        if inner.active_threads.load(Ordering::Relaxed) <= active {
            // No worker was added (the cap was reached concurrently, or the
            // thread could not be spawned); the next submission retries.
            return;
        }
    }
}

/// Atomically claims one idle-retirement slot without dropping below min_threads.
///
/// Returns true only for the single worker allowed to retire at the current floor.
fn try_claim_idle_retirement(inner: &BlockingPoolInner) -> bool {
    let mut current = inner.active_threads.load(Ordering::Relaxed);
    loop {
        if current <= inner.min_threads {
            return false;
        }
        match inner.active_threads.compare_exchange_weak(
            current,
            current - 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(next) => current = next,
        }
    }
}

/// Dispatches a cohort-assigned worker makes between turns on which it looks
/// at the other cohorts' queues first.
///
/// `pop_next_blocking_task` reaches another cohort's queue only when the
/// worker's own queue and the global queue are both empty. A task routed to a
/// cohort that no live worker serves would therefore wait for as long as the
/// live workers stay busy (br-asupersync-mopkmt M3). These turns bound that
/// wait while leaving locality the rule.
const FOREIGN_COHORT_TURN_INTERVAL: usize = 16;

/// The worker loop for blocking pool threads.
#[allow(clippy::significant_drop_tightening)] // Condvar wait pattern intentionally holds and rechecks under mutex.
fn blocking_worker_loop(inner: &BlockingPoolInner, assigned_cohort: Option<usize>) -> bool {
    let mut idle_since: Option<Instant> = None;
    let mut local_dispatch_streak = 0usize;
    let mut dispatches_since_foreign_turn = 0usize;
    let mut foreign_cursor = 0usize;

    loop {
        // Try to get work from the queue
        let prefer_local_turn = assigned_cohort.is_some()
            && inner
                .affinity
                .as_ref()
                .is_some_and(|affinity| local_dispatch_streak < affinity.spill_check_interval);
        let foreign_turn = match (assigned_cohort, inner.affinity.as_ref()) {
            (Some(cohort), Some(affinity))
                if dispatches_since_foreign_turn >= FOREIGN_COHORT_TURN_INTERVAL =>
            {
                dispatches_since_foreign_turn = 0;
                affinity.steal_foreign_cohort_after(cohort, &mut foreign_cursor)
            }
            _ => None,
        };
        if let Some((task, dequeue_kind)) = foreign_turn
            .or_else(|| pop_next_blocking_task(inner, assigned_cohort, prefer_local_turn))
        {
            idle_since = None; // Reset idle timer since we got work
            dispatches_since_foreign_turn = dispatches_since_foreign_turn.saturating_add(1);
            local_dispatch_streak = match dequeue_kind {
                BlockingTaskDequeueKind::Local => local_dispatch_streak.saturating_add(1),
                BlockingTaskDequeueKind::Global | BlockingTaskDequeueKind::Spill => 0,
            };

            // Busy first: between the two updates this worker must not look
            // idle while it holds a task, or a task submitted in that window
            // sees an idle thread, spawns none, and waits behind this one
            // although the cap allows more threads (br-asupersync-2u7bpm).
            inner.busy_threads.fetch_add(1, Ordering::Relaxed);
            inner.pending_count.fetch_sub(1, Ordering::Relaxed);

            // Check if task was cancelled before execution. A skipped task still
            // owns its captures, whose destructors may block: destroy them
            // while this worker counts as busy and before the task reports
            // done, as for an executed task. Otherwise the pool sees an idle
            // worker and spawns none for new work (br-asupersync-q1pr9n).
            if task.cancelled.load(Ordering::Acquire) {
                let BlockingTask {
                    work, completion, ..
                } = task;
                let _dropped =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(work)));
                inner.busy_threads.fetch_sub(1, Ordering::Relaxed);
                completion.signal_done();
                continue;
            }

            // Execute the task. Use catch_unwind so a panicking task
            // doesn't leak the busy_threads counter or skip signal_done(),
            // which would cause waiters to hang indefinitely and the
            // worker thread to die (losing on_thread_stop + active_threads
            // decrement).
            let _result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(task.work));
            inner.busy_threads.fetch_sub(1, Ordering::Relaxed);

            // Always signal completion so waiters are unblocked, even
            // if the task panicked.
            task.completion.signal_done();
            // Loop immediately to drain the queue before checking shutdown
            // or park/retire conditions. Without this, the worker falls through
            // to the shutdown check and may exit with queued work remaining.
            continue;
        }

        // No work available, check shutdown
        if inner.shutdown.load(Ordering::Acquire) {
            break;
        }

        // Check if we should retire this thread
        let active = inner.active_threads.load(Ordering::Relaxed);
        if active > inner.min_threads {
            let now = (inner.time_getter)();
            let start = *idle_since.get_or_insert(now);
            let elapsed = now.saturating_duration_since(start);

            if elapsed >= inner.idle_timeout {
                // Serialize the zero-worker transition with submission and
                // worker-spawn failure recovery. Without this guard, a retiree
                // that has decremented active_threads but not yet rechecked the
                // queue could race a failed last-worker spawn draining queues.
                let retirement_guard = inner.mutex.lock();

                // If we've been idle long enough and there's still no work, consider retiring
                if !blocking_pool_has_pending_work(inner) && try_claim_idle_retirement(inner) {
                    // We claimed the retirement slot, meaning active_threads was decremented.
                    // Re-check the queue to ensure we didn't miss a concurrent spawn that
                    // observed our pre-retirement active_threads count and decided not to spawn.
                    //
                    // This is the retiree half of a Dekker pattern: we STORE
                    // active_threads-- (CAS above) then LOAD pending_count
                    // below; the enqueuer STOREs pending_count++ then LOADs
                    // active_threads (in maybe_spawn). Acquire/Release alone
                    // permits both sides to read stale on weak memory models
                    // (e.g. aarch64), stranding the last worker with a task
                    // queued on a min_threads==0 pool. A SeqCst fence between
                    // our store and load — paired with the matching fence on
                    // the enqueue side — forces a total order so at least one
                    // side observes the other's store. (No-op on x86.)
                    std::sync::atomic::fence(Ordering::SeqCst);
                    if !blocking_pool_has_pending_work(inner) {
                        // Retire this thread; active_threads was already decremented atomically.
                        return true;
                    }

                    // A task was enqueued while we were retiring. Undo the retirement.
                    {
                        let mut current = inner.active_threads.load(Ordering::Relaxed);
                        let mut unretired = false;
                        loop {
                            if current >= inner.live_max_threads.load(Ordering::Relaxed) {
                                break;
                            }
                            match inner.active_threads.compare_exchange_weak(
                                current,
                                current + 1,
                                Ordering::Relaxed,
                                Ordering::Relaxed,
                            ) {
                                Ok(_) => {
                                    unretired = true;
                                    break;
                                }
                                Err(next) => current = next,
                            }
                        }
                        if !unretired {
                            // We can't un-retire (max_threads reached) but
                            // a task is waiting. Force un-retire to prevent
                            // task loss — temporarily exceed max_threads.
                            inner.active_threads.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                drop(retirement_guard);
                // If we couldn't retire (e.g. someone else retired and we hit min_threads),
                // reset our idle timer so we don't spin.
                idle_since = None;
                continue;
            }

            let remaining = inner.idle_timeout.saturating_sub(elapsed);

            // Park with remaining timeout.
            let mut guard = inner.mutex.lock();

            // Re-check queue under lock to prevent lost wakeup.
            if blocking_pool_has_pending_work(inner) {
                drop(guard);
                continue;
            }

            if inner.shutdown.load(Ordering::Acquire) {
                drop(guard);
                break;
            }

            let _wait_result = inner.condvar.wait_for(&mut guard, remaining);
            drop(guard);
        } else {
            idle_since = None; // Reset idle timer since we're parked indefinitely

            // We're at min_threads, park indefinitely.
            let mut guard = inner.mutex.lock();

            // Re-check queue under lock to prevent lost wakeup.
            if blocking_pool_has_pending_work(inner) {
                drop(guard);
                continue;
            }

            if inner.shutdown.load(Ordering::Acquire) {
                drop(guard);
                break;
            }

            inner.condvar.wait(&mut guard);
            drop(guard);
        }
    }
    false
}

impl BlockingPoolAffinityState {
    /// Takes a task from the first other cohort with work, starting at
    /// `*cursor`, and moves `*cursor` past that cohort, so successive turns
    /// visit every cohort instead of always draining the lowest-numbered one.
    fn steal_foreign_cohort_after(
        &self,
        own_cohort: usize,
        cursor: &mut usize,
    ) -> Option<(BlockingTask, BlockingTaskDequeueKind)> {
        for step in 0..self.cohort_count {
            let idx = (*cursor + step) % self.cohort_count;
            if idx == own_cohort {
                continue;
            }
            if let Some(task) = self.cohort_queues[idx].pop() {
                self.cohort_pending_counts[idx].fetch_sub(1, Ordering::Relaxed);
                self.spill_dispatches.fetch_add(1, Ordering::Relaxed);
                *cursor = (idx + 1) % self.cohort_count;
                return Some((task, BlockingTaskDequeueKind::Spill));
            }
        }
        None
    }
}

#[cfg(test)]
#[allow(dead_code)]
#[path = "blocking_pool_inline_tests.rs"]
mod tests;

// Metamorphic tests for blocking pool fairness properties
mod metamorphic;

#[cfg(test)]
#[path = "blocking_pool/comprehensive_metamorphic_tests.rs"]
mod comprehensive_metamorphic_tests;
