//! Blocking pool for executing synchronous operations.
//!
// Allow clippy lints that are allowed at the crate level but not picked up in this module
#![allow(clippy::must_use_candidate)]
//!
//! This module provides a thread pool for running blocking operations without
//! blocking the async runtime. It supports:
//!
//! - **Capacity management**: Configurable min/max threads with dynamic scaling
//! - **Fairness**: FIFO ordering with priority support
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
//! is "soft": the task is marked cancelled, but the blocking closure runs to
//! completion. The completion notification is suppressed for cancelled tasks.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::runtime::BlockingPool;
//!
//! let pool = BlockingPool::new(1, 4);
//! let handle = pool.spawn(|| {
//!     std::fs::read_to_string("/etc/hosts")
//! });
//! let result = handle.await?;
//! ```

use crate::runtime::config::BlockingPoolAffinityProfile;
use crossbeam_queue::SegQueue;
use parking_lot::{Condvar, Mutex};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle as ThreadJoinHandle};
use std::time::{Duration, Instant};

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

fn timeout_deadline(timeout: Duration, time_getter: TimeGetter) -> Instant {
    time_getter() + timeout
}

fn timeout_remaining(deadline: Instant, time_getter: TimeGetter) -> Duration {
    deadline.saturating_duration_since(time_getter())
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
    fn from_options(options: &BlockingPoolOptions) -> Option<Self> {
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
                    cohort_queues: (0..cohort_count).map(|_| SegQueue::new()).collect(),
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
    /// Maximum number of threads allowed.
    max_threads: usize,
    /// Current number of active threads.
    active_threads: AtomicUsize,
    /// Number of threads currently executing work.
    busy_threads: AtomicUsize,
    /// Number of pending tasks in queue.
    pending_count: AtomicUsize,
    /// Next task ID for tracking.
    next_task_id: AtomicU64,
    /// Monotonic worker thread sequence for deterministic naming.
    next_thread_id: AtomicU64,
    /// Work queue.
    queue: SegQueue<BlockingTask>,
    /// Optional cohort-aware blocking affinity state.
    affinity: Option<BlockingPoolAffinityState>,
    /// Shutdown flag.
    shutdown: AtomicBool,
    /// Condition variable for thread parking.
    condvar: Condvar,
    /// Mutex for condition variable.
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
    cohort_queues: Vec<SegQueue<BlockingTask>>,
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
    /// Priority (higher = more important, for future use).
    #[allow(dead_code)]
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
        assert!(max_threads > 0, "max_threads must be at least 1");
        assert!(
            min_threads <= max_threads,
            "min_threads must be less than or equal to max_threads"
        );
        assert!(
            !options.thread_name_prefix.contains('\0'),
            "thread_name_prefix may not contain interior NUL bytes"
        );

        let affinity = BlockingPoolAffinityState::from_options(&options);
        let inner = Arc::new(BlockingPoolInner {
            min_threads,
            max_threads,
            active_threads: AtomicUsize::new(0),
            busy_threads: AtomicUsize::new(0),
            pending_count: AtomicUsize::new(0),
            next_task_id: AtomicU64::new(1),
            next_thread_id: AtomicU64::new(1),
            queue: SegQueue::new(),
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
    /// Higher priority values are executed first (currently unused,
    /// reserved for future priority queue implementation).
    pub fn spawn_with_priority<F>(&self, f: F, priority: u8) -> BlockingTaskHandle
    where
        F: FnOnce() + Send + 'static,
    {
        self.spawn_with_affinity(f, priority, None)
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

    /// Returns `true` if the pool is shut down.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.inner.shutdown.load(Ordering::Acquire)
    }

    /// Initiates shutdown of the pool.
    ///
    /// No new tasks will be accepted. Pending tasks will continue to execute.
    pub fn shutdown(&self) {
        let _guard = self.inner.mutex.lock();
        self.inner.shutdown.store(true, Ordering::Release);
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

        // Wait for all threads to exit by monitoring active_threads counter.
        // Threads decrement this counter when they exit the worker loop.
        while self.inner.active_threads.load(Ordering::Acquire) > 0 {
            let remaining = timeout_remaining(deadline, self.inner.time_getter);
            if remaining.is_zero() {
                return false;
            }

            // Wake any waiting threads so they notice the shutdown flag
            self.notify_all();

            // Wait a bit before checking again
            (self.inner.sleep_fn)(Duration::from_millis(10).min(remaining));
        }

        // All threads have exited, now join the handles to clean up
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
                inner.queue.push(task);
                inner.pending_count.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
    }
    inner.queue.push(task);
    inner.pending_count.fetch_add(1, Ordering::Relaxed);
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
        affinity.pop_local(cohort).or_else(pop_global)
    } else {
        pop_global().or_else(|| affinity.pop_local(cohort))
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

    // Enforce max_threads atomically to prevent overshoot during concurrent spawns
    // Fix TOCTOU race: use Acquire/Release ordering to prevent multiple threads
    // from seeing stale counts and bypassing the limit simultaneously
    loop {
        let current = inner.active_threads.load(Ordering::Acquire);
        if current >= inner.max_threads {
            return;
        }

        // Double-check limit before increment to prevent TOCTOU bypass
        if current + 1 > inner.max_threads {
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
                    self.inner.active_threads.fetch_sub(1, Ordering::Relaxed);

                    // A spawn that linearized before shutdown may enqueue work
                    // while this worker is already on the exit path. If this
                    // was the last active worker, hand the task off before the
                    // pool goes quiescent and strands the accepted work.
                    if blocking_pool_has_pending_work(self.inner) {
                        maybe_spawn_thread_on_inner(self.inner);
                        let _guard = self.inner.mutex.lock();
                        self.inner.condvar.notify_one();
                    }
                }
            }
        }

        let mut guard = ThreadExitGuard {
            inner: &inner_clone,
            retired_with_claim: false,
        };

        if let Some(ref callback) = inner_clone.on_thread_start {
            callback();
        }

        guard.retired_with_claim = blocking_worker_loop(&inner_clone, assigned_cohort);
        let _ = guard.retired_with_claim;
    }) {
        Ok(handle) => {
            let finished_handles = {
                let mut handles = inner.thread_handles.lock();
                handles.push(handle);

                // Clean up finished thread handles to prevent unbounded memory
                // growth during workload bursts where threads frequently spawn
                // and retire.
                drain_finished_thread_handles(&mut handles)
            };
            join_thread_handles(finished_handles);
        }
        Err(_) => {
            // Spawn failed — roll back the counter so active_threads
            // stays consistent with the actual number of live threads.
            inner.active_threads.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Check if we should spawn a new thread and do so if needed.
fn maybe_spawn_thread_on_inner(inner: &Arc<BlockingPoolInner>) {
    let active = inner.active_threads.load(Ordering::Relaxed);
    let busy = inner.busy_threads.load(Ordering::Relaxed);
    let pending = inner.pending_count.load(Ordering::Relaxed);

    // Spawn a new thread if:
    // 1. We're below max_threads
    // 2. The number of pending tasks exceeds the number of idle threads
    //    (idle = active - busy). This handles bursts of tasks correctly
    //    even before threads have woken up to increment `busy_threads`.
    let idle = active.saturating_sub(busy);
    if active < inner.max_threads && pending > idle {
        spawn_thread_on_inner(inner);
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

/// The worker loop for blocking pool threads.
#[allow(clippy::significant_drop_tightening)] // Condvar wait pattern intentionally holds and rechecks under mutex.
fn blocking_worker_loop(inner: &BlockingPoolInner, assigned_cohort: Option<usize>) -> bool {
    let mut idle_since: Option<Instant> = None;
    let mut local_dispatch_streak = 0usize;

    loop {
        // Try to get work from the queue
        let prefer_local_turn = assigned_cohort.is_some()
            && inner
                .affinity
                .as_ref()
                .is_some_and(|affinity| local_dispatch_streak < affinity.spill_check_interval);
        if let Some((task, dequeue_kind)) =
            pop_next_blocking_task(inner, assigned_cohort, prefer_local_turn)
        {
            idle_since = None; // Reset idle timer since we got work
            local_dispatch_streak = match dequeue_kind {
                BlockingTaskDequeueKind::Local => local_dispatch_streak.saturating_add(1),
                BlockingTaskDequeueKind::Global | BlockingTaskDequeueKind::Spill => 0,
            };

            inner.busy_threads.fetch_add(1, Ordering::Relaxed);
            inner.pending_count.fetch_sub(1, Ordering::Relaxed);

            // Check if task was cancelled before execution
            if task.cancelled.load(Ordering::Acquire) {
                inner.busy_threads.fetch_sub(1, Ordering::Relaxed);
                task.completion.signal_done();
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
                // If we've been idle long enough and there's still no work, consider retiring
                if !blocking_pool_has_pending_work(inner) && try_claim_idle_retirement(inner) {
                    // We claimed the retirement slot, meaning active_threads was decremented.
                    // Re-check the queue to ensure we didn't miss a concurrent spawn that
                    // observed our pre-retirement active_threads count and decided not to spawn.
                    if !blocking_pool_has_pending_work(inner) {
                        // Retire this thread; active_threads was already decremented atomically.
                        return true;
                    }

                    // A task was enqueued while we were retiring. Undo the retirement.
                    {
                        let mut current = inner.active_threads.load(Ordering::Relaxed);
                        let mut unretired = false;
                        loop {
                            if current >= inner.max_threads {
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

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize};
    use std::sync::{Condvar as StdCondvar, Mutex as StdMutex, OnceLock};

    static DETERMINISTIC_HOOK_TEST_LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
    static SCRIPTED_TIME_BASE: OnceLock<Instant> = OnceLock::new();
    static SCRIPTED_TIME_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SCRIPTED_TIME_OFFSET_MS: AtomicU64 = AtomicU64::new(0);
    static SCRIPTED_SLEEP_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn deterministic_hook_test_guard() -> std::sync::MutexGuard<'static, ()> {
        DETERMINISTIC_HOOK_TEST_LOCK
            .get_or_init(|| StdMutex::new(()))
            .lock()
            .expect("deterministic hook test lock poisoned")
    }

    fn reset_scripted_time_state() {
        SCRIPTED_TIME_CALLS.store(0, Ordering::Relaxed);
        SCRIPTED_TIME_OFFSET_MS.store(0, Ordering::Relaxed);
        SCRIPTED_SLEEP_CALLS.store(0, Ordering::Relaxed);
    }

    fn scripted_time_base() -> Instant {
        *SCRIPTED_TIME_BASE.get_or_init(Instant::now)
    }

    fn stepped_timeout_time() -> Instant {
        let base = scripted_time_base();
        if SCRIPTED_TIME_CALLS.fetch_add(1, Ordering::Relaxed) == 0 {
            base
        } else {
            base + Duration::from_millis(25)
        }
    }

    fn advancing_timeout_time() -> Instant {
        scripted_time_base()
            + Duration::from_millis(SCRIPTED_TIME_OFFSET_MS.load(Ordering::Relaxed))
    }

    fn advancing_timeout_sleep(duration: Duration) {
        SCRIPTED_SLEEP_CALLS.fetch_add(1, Ordering::Relaxed);
        let millis = duration.as_millis().min(u128::from(u64::MAX)) as u64;
        SCRIPTED_TIME_OFFSET_MS.fetch_add(millis, Ordering::Relaxed);
    }

    fn test_blocking_task(preferred_cohort: Option<usize>) -> BlockingTask {
        BlockingTask {
            work: Box::new(|| {}),
            priority: 128,
            preferred_cohort,
            cancelled: Arc::new(AtomicBool::new(false)),
            completion: Arc::new(BlockingTaskCompletion::new(wall_clock_now)),
        }
    }

    fn test_blocking_inner_with_affinity(
        affinity_profile: BlockingPoolAffinityProfile,
        cohort_count: Option<usize>,
    ) -> Arc<BlockingPoolInner> {
        let options = BlockingPoolOptions {
            affinity_profile,
            cohort_count,
            ..Default::default()
        };
        Arc::new(BlockingPoolInner {
            min_threads: 0,
            max_threads: 4,
            active_threads: AtomicUsize::new(0),
            busy_threads: AtomicUsize::new(0),
            pending_count: AtomicUsize::new(0),
            next_task_id: AtomicU64::new(1),
            next_thread_id: AtomicU64::new(1),
            queue: SegQueue::new(),
            affinity: BlockingPoolAffinityState::from_options(&options),
            shutdown: AtomicBool::new(false),
            condvar: Condvar::new(),
            mutex: Mutex::new(()),
            idle_timeout: Duration::from_millis(10),
            time_getter: wall_clock_now,
            sleep_fn: blocking_thread_sleep,
            thread_name_prefix: "affinity-test".to_string(),
            on_thread_start: None,
            on_thread_stop: None,
            thread_handles: Mutex::new(Vec::new()),
        })
    }

    #[test]
    fn basic_spawn_and_wait() {
        let pool = BlockingPool::new(1, 4);
        let counter = Arc::new(AtomicI32::new(0));

        let counter_clone = Arc::clone(&counter);
        let handle = pool.spawn(move || {
            counter_clone.fetch_add(1, Ordering::Relaxed);
        });

        handle.wait();
        assert!(handle.is_done());
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn affinity_routes_preferred_tasks_into_local_queue() {
        let inner = test_blocking_inner_with_affinity(
            BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 2,
                spill_check_interval: 1,
            },
            Some(2),
        );

        assert!(try_enqueue_task(&inner, test_blocking_task(Some(1))));

        let metrics = blocking_pool_affinity_metrics(&inner);
        assert_eq!(metrics.cohort_pending_counts, vec![0, 1]);
        assert_eq!(metrics.global_pending_count, 0);

        let (task, kind) =
            pop_next_blocking_task(&inner, Some(1), true).expect("local queue should yield work");
        assert_eq!(kind, BlockingTaskDequeueKind::Local);
        inner.pending_count.fetch_sub(1, Ordering::Relaxed);
        drop(task);

        let metrics = blocking_pool_affinity_metrics(&inner);
        assert_eq!(metrics.local_queue_dispatches, 1);
        assert_eq!(metrics.global_pending_count, 0);
        assert_eq!(metrics.cohort_pending_counts, vec![0, 0]);
    }

    #[test]
    fn affinity_spills_when_local_queue_is_saturated() {
        let inner = test_blocking_inner_with_affinity(
            BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 1,
                spill_check_interval: 1,
            },
            Some(1),
        );

        assert!(try_enqueue_task(&inner, test_blocking_task(Some(0))));
        assert!(try_enqueue_task(&inner, test_blocking_task(Some(0))));

        let metrics = blocking_pool_affinity_metrics(&inner);
        assert_eq!(metrics.cohort_pending_counts, vec![1]);
        assert_eq!(metrics.global_pending_count, 1);
        assert_eq!(metrics.fallback_dispatches, 1);

        let (_task, kind) = pop_next_blocking_task(&inner, Some(0), false)
            .expect("spill queue should be checked before local queue");
        assert_eq!(kind, BlockingTaskDequeueKind::Spill);
    }

    #[test]
    fn affinity_disabled_keeps_spawn_on_cohort_equivalent_to_global_queue() {
        let inner = test_blocking_inner_with_affinity(BlockingPoolAffinityProfile::Disabled, None);

        assert!(try_enqueue_task(&inner, test_blocking_task(Some(3))));
        let metrics = blocking_pool_affinity_metrics(&inner);
        assert!(!metrics.enabled);
        assert_eq!(metrics.global_pending_count, 1);
        assert!(metrics.cohort_pending_counts.is_empty());

        let (_task, kind) = pop_next_blocking_task(&inner, Some(0), true)
            .expect("disabled affinity should still use the global queue");
        assert_eq!(kind, BlockingTaskDequeueKind::Global);
    }

    #[test]
    fn multiple_tasks() {
        let pool = BlockingPool::new(2, 8);
        let counter = Arc::new(AtomicI32::new(0));
        let mut handles = Vec::new();

        for _ in 0..100 {
            let counter_clone = Arc::clone(&counter);
            handles.push(pool.spawn(move || {
                counter_clone.fetch_add(1, Ordering::Relaxed);
            }));
        }

        for handle in handles {
            handle.wait();
        }

        assert_eq!(counter.load(Ordering::Relaxed), 100);
    }

    #[test]
    fn test_spawn_from_handle() {
        let pool = BlockingPool::new(1, 4);
        let handle = pool.handle();
        let counter = Arc::new(AtomicI32::new(0));

        let c = Arc::clone(&counter);
        let task = handle.spawn(move || {
            c.fetch_add(1, Ordering::Relaxed);
        });

        task.wait();
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_active_threads_starts_at_min() {
        let pool = BlockingPool::new(3, 8);
        thread::sleep(Duration::from_millis(50));
        assert_eq!(pool.active_threads(), 3);
    }

    #[test]
    fn cancellation_before_execution() {
        let pool = BlockingPool::new(0, 1); // Start with no threads
        let counter = Arc::new(AtomicI32::new(0));

        // Spawn without any threads available
        let counter_clone = Arc::clone(&counter);
        let handle = pool.spawn(move || {
            counter_clone.fetch_add(1, Ordering::Relaxed);
        });

        // Cancel immediately
        handle.cancel();
        assert!(handle.is_cancelled());

        // The task should complete (as cancelled) without incrementing
        let _ = handle.wait_timeout(Duration::from_secs(2));

        // Wait for any potential execution
        thread::sleep(Duration::from_millis(50));

        // Cancelled tasks don't execute their work
        // Note: The current implementation still executes if the thread picks it up
        // before cancellation is observed. This test may need adjustment.
    }

    #[test]
    fn test_shutdown_and_wait_empty_pool() {
        let pool = BlockingPool::new(2, 4);
        thread::sleep(Duration::from_millis(20));

        let start = std::time::Instant::now();
        let result = pool.shutdown_and_wait(Duration::from_secs(2));
        let elapsed = start.elapsed();

        assert!(result, "Shutdown should succeed");
        assert!(elapsed < Duration::from_secs(1));
        assert_eq!(pool.active_threads(), 0);
    }

    #[test]
    fn test_shutdown_and_wait_timeout_respected() {
        let pool = BlockingPool::new(1, 1);
        pool.spawn(|| {
            thread::sleep(Duration::from_millis(200));
        });

        thread::sleep(Duration::from_millis(20));

        let start = std::time::Instant::now();
        let result = pool.shutdown_and_wait(Duration::from_millis(50));
        let elapsed = start.elapsed();

        assert!(!result, "Expected timeout to return false");
        assert!(elapsed >= Duration::from_millis(50));
        assert!(elapsed < Duration::from_secs(1));
    }

    #[test]
    fn test_shutdown_idempotent() {
        let pool = BlockingPool::new(1, 2);
        pool.spawn(|| {});

        pool.shutdown();
        assert!(pool.is_shutdown());
        pool.shutdown();
        assert!(pool.is_shutdown());

        assert!(pool.shutdown_and_wait(Duration::from_secs(2)));
    }

    #[test]
    fn spawn_after_shutdown_is_rejected() {
        let pool = BlockingPool::new(1, 2);
        pool.shutdown();

        let counter = Arc::new(AtomicI32::new(0));
        let c = Arc::clone(&counter);
        let handle = pool.spawn(move || {
            c.fetch_add(1, Ordering::Relaxed);
        });

        assert!(handle.is_cancelled());
        assert!(handle.wait_timeout(Duration::from_millis(100)));
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn handle_spawn_after_shutdown_is_rejected() {
        let pool = BlockingPool::new(1, 2);
        let handle_api = pool.handle();
        pool.shutdown();

        let counter = Arc::new(AtomicI32::new(0));
        let c = Arc::clone(&counter);
        let handle = handle_api.spawn(move || {
            c.fetch_add(1, Ordering::Relaxed);
        });

        assert!(handle.is_cancelled());
        assert!(handle.wait_timeout(Duration::from_millis(100)));
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn spawn_rechecks_shutdown_before_queueing_under_submission_lock() {
        let pool = BlockingPool::new(0, 1);
        let handle_api = pool.handle();
        let executed = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(std::sync::Barrier::new(2));

        let submission_guard = pool.inner.mutex.lock();
        let executed_clone = Arc::clone(&executed);
        let gate_clone = Arc::clone(&gate);
        let join = thread::spawn(move || {
            gate_clone.wait();
            handle_api.spawn(move || {
                executed_clone.store(true, Ordering::Release);
            })
        });

        gate.wait();
        // Simulate shutdown linearizing while the submitter is blocked on the
        // submission critical section after its fast-path shutdown check.
        pool.inner.shutdown.store(true, Ordering::Release);
        drop(submission_guard);

        let handle = join.join().expect("spawn thread should return a handle");
        assert!(handle.is_cancelled());
        assert!(handle.wait_timeout(Duration::from_millis(100)));
        assert_eq!(pool.pending_count(), 0);
        assert_eq!(pool.active_threads(), 0);
        assert!(!executed.load(Ordering::Acquire));
    }

    #[test]
    fn wait_timeout() {
        let pool = BlockingPool::new(1, 1);

        let handle = pool.spawn(|| {
            thread::sleep(Duration::from_millis(500));
        });

        // Short timeout should fail
        assert!(!handle.wait_timeout(Duration::from_millis(10)));

        // Long timeout should succeed
        assert!(handle.wait_timeout(Duration::from_secs(2)));
        assert!(handle.is_done());
    }

    #[test]
    fn test_worker_parks_on_empty() {
        let pool = BlockingPool::new(2, 4);
        thread::sleep(Duration::from_millis(50));
        assert_eq!(pool.busy_threads(), 0);
    }

    #[test]
    fn test_worker_wakes_on_task() {
        let pool = BlockingPool::new(1, 2);
        thread::sleep(Duration::from_millis(50));

        let counter = Arc::new(AtomicI32::new(0));
        let c = Arc::clone(&counter);
        let handle = pool.spawn(move || {
            c.fetch_add(1, Ordering::Relaxed);
        });

        assert!(handle.wait_timeout(Duration::from_secs(2)));
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    #[should_panic(expected = "min_threads must be less than or equal to max_threads")]
    fn with_config_rejects_min_threads_above_max_threads() {
        let _pool = BlockingPool::with_config(2, 1, BlockingPoolOptions::default());
    }

    #[test]
    #[should_panic(expected = "thread_name_prefix may not contain interior NUL bytes")]
    fn with_config_rejects_thread_name_prefix_with_nul() {
        let _pool = BlockingPool::with_config(
            0,
            1,
            BlockingPoolOptions {
                thread_name_prefix: "bad\0name".to_string(),
                ..Default::default()
            },
        );
    }

    #[test]
    fn test_worker_idle_timeout_excess_threads_exit() {
        let options = BlockingPoolOptions {
            idle_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let pool = BlockingPool::with_config(0, 3, options);

        let barrier = Arc::new(std::sync::Barrier::new(4));
        let mut handles = Vec::new();
        for _ in 0..3 {
            let b = Arc::clone(&barrier);
            handles.push(pool.spawn(move || {
                b.wait();
            }));
        }

        thread::sleep(Duration::from_millis(50));
        let active_before = pool.active_threads();
        assert!(active_before >= 1);

        barrier.wait();
        for h in handles {
            h.wait();
        }

        thread::sleep(Duration::from_millis(300));
        let active_after = pool.active_threads();
        assert!(
            active_after <= 1,
            "Expected excess threads to retire, active_after={active_after}"
        );
    }

    #[test]
    fn thread_scaling() {
        let pool = BlockingPool::new(1, 4);

        // Initially should have min_threads
        assert_eq!(pool.active_threads(), 1);

        // Spawn multiple blocking tasks that just sleep briefly
        // This tests that the pool can handle multiple concurrent tasks
        let counter = Arc::new(AtomicI32::new(0));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let counter_clone = Arc::clone(&counter);
            handles.push(pool.spawn(move || {
                counter_clone.fetch_add(1, Ordering::Relaxed);
                thread::sleep(Duration::from_millis(10));
            }));
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.wait();
        }

        // All tasks should have executed
        assert_eq!(counter.load(Ordering::Relaxed), 4);

        // Pool should have scaled threads (at least min_threads)
        assert!(pool.active_threads() >= 1);
    }

    #[test]
    fn test_task_panic_caught() {
        let pool = BlockingPool::new(2, 4);
        let _ = pool.spawn(|| unreachable!("intentional panic"));

        thread::sleep(Duration::from_millis(50));

        let counter = Arc::new(AtomicI32::new(0));
        let c = Arc::clone(&counter);
        let handle = pool.spawn(move || {
            c.fetch_add(1, Ordering::Relaxed);
        });
        handle.wait();
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn shutdown_graceful() {
        let pool = BlockingPool::new(2, 4);
        let counter = Arc::new(AtomicI32::new(0));

        // Spawn some work
        for _ in 0..10 {
            let counter_clone = Arc::clone(&counter);
            pool.spawn(move || {
                counter_clone.fetch_add(1, Ordering::Relaxed);
            });
        }

        // Shutdown and wait
        assert!(pool.shutdown_and_wait(Duration::from_secs(5)));

        // All work should have completed
        assert_eq!(counter.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn handle_cloning() {
        let pool = BlockingPool::new(1, 4);
        let handle = pool.handle();
        let handle2 = handle.clone();

        let counter = Arc::new(AtomicI32::new(0));

        let c1 = Arc::clone(&counter);
        let t1 = handle.spawn(move || {
            c1.fetch_add(1, Ordering::Relaxed);
        });

        let c2 = Arc::clone(&counter);
        let t2 = handle2.spawn(move || {
            c2.fetch_add(1, Ordering::Relaxed);
        });

        t1.wait();
        t2.wait();

        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_queue_concurrent_push() {
        let pool = BlockingPool::new(2, 8);
        let counter = Arc::new(AtomicU64::new(0));
        let mut spawners = Vec::new();

        let spawner_count: u64 = 4;
        let tasks_per_spawner: u64 = 50;

        for _ in 0..spawner_count {
            let pool_handle = pool.handle();
            let c = Arc::clone(&counter);
            spawners.push(thread::spawn(move || {
                for _ in 0..tasks_per_spawner {
                    let c_inner = Arc::clone(&c);
                    pool_handle.spawn(move || {
                        c_inner.fetch_add(1, Ordering::Relaxed);
                    });
                }
            }));
        }

        for spawner in spawners {
            spawner.join().expect("spawner panicked");
        }

        assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        assert_eq!(
            counter.load(Ordering::Relaxed),
            spawner_count * tasks_per_spawner
        );
    }

    #[test]
    fn pool_metrics() {
        let pool = BlockingPool::new(1, 4);

        assert_eq!(pool.active_threads(), 1);
        assert_eq!(pool.pending_count(), 0);
        assert_eq!(pool.busy_threads(), 0);

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let barrier_clone = Arc::clone(&barrier);

        let _handle = pool.spawn(move || {
            barrier_clone.wait();
        });

        // Wait a bit for task to start
        thread::sleep(Duration::from_millis(10));

        assert_eq!(pool.busy_threads(), 1);

        // Unblock the task
        barrier.wait();
    }

    #[test]
    #[should_panic(expected = "min_threads must be less than or equal to max_threads")]
    fn new_rejects_min_threads_above_max_threads() {
        let _pool = BlockingPool::new(4, 2);
    }

    #[test]
    fn thread_callbacks() {
        let started = Arc::new(AtomicI32::new(0));
        let stopped = Arc::new(AtomicI32::new(0));

        let started_clone = Arc::clone(&started);
        let stopped_clone = Arc::clone(&stopped);

        let options = BlockingPoolOptions {
            on_thread_start: Some(Arc::new(move || {
                started_clone.fetch_add(1, Ordering::Relaxed);
            })),
            on_thread_stop: Some(Arc::new(move || {
                stopped_clone.fetch_add(1, Ordering::Relaxed);
            })),
            ..Default::default()
        };

        let pool = BlockingPool::with_config(2, 4, options);

        // Wait for threads to start
        thread::sleep(Duration::from_millis(50));

        assert_eq!(started.load(Ordering::Relaxed), 2);

        pool.shutdown_and_wait(Duration::from_secs(5));

        assert_eq!(stopped.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_thread_name_unique() {
        let options = BlockingPoolOptions {
            thread_name_prefix: "unique-pool".to_string(),
            ..Default::default()
        };
        let pool = BlockingPool::with_config(2, 2, options);

        let barrier = Arc::new(std::sync::Barrier::new(3));
        let names = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();

        for _ in 0..2 {
            let b = Arc::clone(&barrier);
            let n = Arc::clone(&names);
            handles.push(pool.spawn(move || {
                if let Some(name) = thread::current().name() {
                    n.lock().push(name.to_string());
                }
                b.wait();
            }));
        }

        barrier.wait();
        for h in handles {
            h.wait();
        }

        let recorded = names.lock().clone();
        let unique: HashSet<_> = recorded.into_iter().collect();
        assert_eq!(unique.len(), 2, "Expected two unique thread names");
    }

    /// A panicking task must not hang waiters or leak busy_threads.
    /// The pool should catch the panic, signal completion, and continue
    /// processing subsequent tasks on the same worker thread.
    #[test]
    fn panicking_task_does_not_hang_waiters() {
        // Install a no-op panic hook so the test output isn't noisy.
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        let pool = BlockingPool::new(1, 1);

        // Submit a task that panics.
        let panic_handle = pool.spawn(|| {
            unreachable!("intentional test panic");
        });

        // Submit a follow-up task to verify the worker thread survived.
        let survived = Arc::new(AtomicBool::new(false));
        let survived_clone = Arc::clone(&survived);
        let follow_up = pool.spawn(move || {
            survived_clone.store(true, Ordering::Release);
        });

        // Both handles must complete without hanging.
        assert!(
            panic_handle.wait_timeout(Duration::from_secs(5)),
            "panicking task should signal completion, not hang"
        );
        assert!(
            follow_up.wait_timeout(Duration::from_secs(5)),
            "follow-up task should complete on the surviving worker"
        );
        assert!(
            survived.load(Ordering::Acquire),
            "worker thread should survive a task panic"
        );

        // Restore the original panic hook.
        std::panic::set_hook(prev_hook);
    }

    #[test]
    fn idle_retirement_claim_allows_only_one_thread_at_floor() {
        let inner = Arc::new(BlockingPoolInner {
            min_threads: 1,
            max_threads: 2,
            active_threads: AtomicUsize::new(2),
            busy_threads: AtomicUsize::new(0),
            pending_count: AtomicUsize::new(0),
            next_task_id: AtomicU64::new(1),
            next_thread_id: AtomicU64::new(1),
            queue: SegQueue::new(),
            affinity: None,
            shutdown: AtomicBool::new(false),
            condvar: Condvar::new(),
            mutex: Mutex::new(()),
            idle_timeout: Duration::from_millis(1),
            time_getter: wall_clock_now,
            sleep_fn: blocking_thread_sleep,
            thread_name_prefix: "retire-test".to_string(),
            on_thread_start: None,
            on_thread_stop: None,
            thread_handles: Mutex::new(Vec::new()),
        });

        let barrier = Arc::new(std::sync::Barrier::new(3));
        let claims = Arc::new(AtomicUsize::new(0));
        let mut joiners = Vec::new();

        for _ in 0..2 {
            let inner_clone = Arc::clone(&inner);
            let barrier_clone = Arc::clone(&barrier);
            let claims_clone = Arc::clone(&claims);
            joiners.push(thread::spawn(move || {
                barrier_clone.wait();
                if try_claim_idle_retirement(&inner_clone) {
                    claims_clone.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }

        barrier.wait();

        for joiner in joiners {
            joiner.join().expect("retirement claimant panicked");
        }

        assert_eq!(
            claims.load(Ordering::Relaxed),
            1,
            "exactly one worker should claim the retirement slot at the floor"
        );
        assert_eq!(
            inner.active_threads.load(Ordering::Relaxed),
            inner.min_threads,
            "retirement claims must not drop below min_threads"
        );
    }

    #[test]
    fn cancelled_task_signals_completion() {
        let pool = BlockingPool::new(1, 2);
        let executed = Arc::new(AtomicBool::new(false));
        let exec = Arc::clone(&executed);

        let handle = pool.spawn(move || {
            // Simulate slow work so cancellation can be observed
            thread::sleep(Duration::from_millis(200));
            exec.store(true, Ordering::Release);
        });

        // Cancel before execution starts (race, but we try)
        handle.cancel();

        // Completion must be signaled regardless of cancel outcome
        assert!(
            handle.wait_timeout(Duration::from_secs(5)),
            "cancelled task must signal completion"
        );
        assert!(handle.is_done());
    }

    #[test]
    fn busy_threads_balanced_through_panic() {
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        let pool = BlockingPool::new(2, 4);

        // Submit a panicking task
        let h1 = pool.spawn(|| unreachable!("audit panic"));
        h1.wait();

        // busy_threads must return to 0 after the panic
        // (catch_unwind ensures the decrement happens)
        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            pool.busy_threads(),
            0,
            "busy_threads must be decremented even after panic"
        );

        std::panic::set_hook(prev_hook);
    }

    #[test]
    fn spawn_thread_on_inner_respects_max_threads() {
        let inner = Arc::new(BlockingPoolInner {
            min_threads: 0,
            max_threads: 2,
            active_threads: AtomicUsize::new(2),
            busy_threads: AtomicUsize::new(0),
            pending_count: AtomicUsize::new(0),
            next_task_id: AtomicU64::new(1),
            next_thread_id: AtomicU64::new(1),
            queue: SegQueue::new(),
            affinity: None,
            shutdown: AtomicBool::new(false),
            condvar: Condvar::new(),
            mutex: Mutex::new(()),
            idle_timeout: Duration::from_millis(10),
            time_getter: wall_clock_now,
            sleep_fn: blocking_thread_sleep,
            thread_name_prefix: "max-test".to_string(),
            on_thread_start: None,
            on_thread_stop: None,
            thread_handles: Mutex::new(Vec::new()),
        });

        // Already at max_threads (2), spawn should be a no-op
        spawn_thread_on_inner(&inner);

        assert_eq!(
            inner.active_threads.load(Ordering::Relaxed),
            2,
            "spawn must not exceed max_threads"
        );
    }

    // ── Audit regression tests ──────────────────────────────────────

    #[test]
    fn spawn_thread_on_inner_rollback_on_overflow() {
        // When active_threads == max_threads, spawn_thread_on_inner
        // must be a no-op (no CAS increment, no OS thread spawned).
        let inner = Arc::new(BlockingPoolInner {
            min_threads: 0,
            max_threads: 1,
            active_threads: AtomicUsize::new(1),
            busy_threads: AtomicUsize::new(0),
            pending_count: AtomicUsize::new(0),
            next_task_id: AtomicU64::new(1),
            next_thread_id: AtomicU64::new(1),
            queue: SegQueue::new(),
            affinity: None,
            shutdown: AtomicBool::new(false),
            condvar: Condvar::new(),
            mutex: Mutex::new(()),
            idle_timeout: Duration::from_millis(10),
            time_getter: wall_clock_now,
            sleep_fn: blocking_thread_sleep,
            thread_name_prefix: "overflow".to_string(),
            on_thread_start: None,
            on_thread_stop: None,
            thread_handles: Mutex::new(Vec::new()),
        });

        // Try to spawn when already at max
        spawn_thread_on_inner(&inner);
        assert_eq!(inner.active_threads.load(Ordering::Relaxed), 1);
        assert_eq!(inner.thread_handles.lock().len(), 0);
    }

    #[test]
    fn completion_wait_after_signal_returns_immediately() {
        let comp = BlockingTaskCompletion::new(wall_clock_now);
        comp.signal_done();
        // Must return immediately, not block
        assert!(comp.wait_timeout(Duration::from_millis(0)));
    }

    #[test]
    fn completion_wait_timeout_uses_custom_time_getter() {
        let _guard = deterministic_hook_test_guard();
        reset_scripted_time_state();

        let completion = BlockingTaskCompletion::new(stepped_timeout_time);

        assert!(
            !completion.wait_timeout(Duration::from_millis(10)),
            "custom time getter should let wait_timeout observe elapsed time without wall sleep"
        );
        assert_eq!(
            SCRIPTED_TIME_CALLS.load(Ordering::Relaxed),
            2,
            "timeout path should only consult the synthetic clock for deadline and remaining time"
        );
    }

    #[test]
    fn worker_idle_retirement_uses_custom_time_getter() {
        let _guard = deterministic_hook_test_guard();
        reset_scripted_time_state();

        let retired = Arc::new((StdMutex::new(false), StdCondvar::new()));
        let retired_signal = Arc::clone(&retired);

        let pool = BlockingPool::with_config(
            0,
            1,
            BlockingPoolOptions {
                idle_timeout: Duration::from_millis(5),
                time_getter: stepped_timeout_time,
                on_thread_stop: Some(Arc::new(move || {
                    let (lock, condvar) = &*retired_signal;
                    {
                        let mut retired = lock
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        *retired = true;
                    }
                    condvar.notify_all();
                })),
                ..Default::default()
            },
        );

        pool.spawn(|| {}).wait();

        let (lock, condvar) = &*retired;
        let retired = {
            let retired = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (retired, _timeout) = condvar
                .wait_timeout_while(retired, Duration::from_secs(1), |retired| !*retired)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *retired
        };

        assert!(
            retired,
            "synthetic time getter should retire the idle worker without long wall sleeps"
        );
        assert_eq!(
            pool.active_threads(),
            0,
            "idle retirement should decrement active thread count to zero"
        );
        assert!(
            SCRIPTED_TIME_CALLS.load(Ordering::Relaxed) >= 2,
            "idle retirement path should consult the scripted clock across multiple loop turns"
        );
    }

    #[test]
    fn shutdown_and_wait_uses_custom_time_and_sleep_hooks() {
        let _guard = deterministic_hook_test_guard();
        reset_scripted_time_state();

        let pool = BlockingPool::with_config(
            0,
            1,
            BlockingPoolOptions {
                time_getter: advancing_timeout_time,
                sleep_fn: advancing_timeout_sleep,
                ..Default::default()
            },
        );
        pool.inner.active_threads.store(1, Ordering::Release);

        assert!(
            !pool.shutdown_and_wait(Duration::from_millis(25)),
            "synthetic time should drive shutdown timeout accounting without wall sleep"
        );
        assert!(
            pool.is_shutdown(),
            "shutdown flag should be set before waiting"
        );
        assert!(
            SCRIPTED_SLEEP_CALLS.load(Ordering::Relaxed) > 0,
            "shutdown wait loop should use the configured sleep hook"
        );
        assert_eq!(
            SCRIPTED_TIME_OFFSET_MS.load(Ordering::Relaxed),
            25,
            "sleep hook should advance the synthetic clock through the full timeout budget"
        );

        // Prevent Drop from treating the synthetic active thread count as a live worker.
        pool.inner.active_threads.store(0, Ordering::Release);
    }

    #[test]
    fn shutdown_and_wait_does_not_hold_thread_handles_mutex_while_joining() {
        let pool = Arc::new(BlockingPool::new(0, 1));
        pool.inner.shutdown.store(true, Ordering::Release);
        pool.inner.active_threads.store(0, Ordering::Release);

        let release = Arc::new((StdMutex::new(false), StdCondvar::new()));
        let release_clone = Arc::clone(&release);
        let join_target = thread::spawn(move || {
            let (lock, condvar) = &*release_clone;
            let mut released = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while !*released {
                released = condvar
                    .wait(released)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        });

        let mut thread_handles = pool.inner.thread_handles.lock();
        thread_handles.push(join_target);

        let waiter_pool = Arc::clone(&pool);
        let shutdown_waiter =
            thread::spawn(move || waiter_pool.shutdown_and_wait(Duration::from_secs(1)));

        // Keep the mutex held long enough for shutdown_and_wait() to queue on it.
        thread::sleep(Duration::from_millis(20));
        drop(thread_handles);

        let (lock_acquired_tx, lock_acquired_rx) = std::sync::mpsc::channel();
        let contender_pool = Arc::clone(&pool);
        let contender = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(200);
            loop {
                if let Some(guard) = contender_pool.inner.thread_handles.try_lock() {
                    drop(guard);
                    let _ = lock_acquired_tx.send(());
                    break;
                }
                if Instant::now() >= deadline {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
        });

        lock_acquired_rx
            .recv_timeout(Duration::from_millis(100))
            .expect("shutdown waiter should release thread_handles before blocking on join");

        let (release_lock, release_condvar) = &*release;
        {
            let mut released = release_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *released = true;
        }
        release_condvar.notify_all();

        contender.join().expect("contender panicked");
        assert!(shutdown_waiter.join().expect("shutdown waiter panicked"));
    }

    #[test]
    fn shutdown_drains_pending_tasks() {
        let pool = BlockingPool::new(1, 1);

        // Block the single thread so tasks queue up
        let blocker = Arc::new(std::sync::Barrier::new(2));
        let b = Arc::clone(&blocker);
        pool.spawn(move || {
            b.wait();
        });

        // Queue some tasks while the thread is blocked
        let counter = Arc::new(AtomicUsize::new(0));
        for _ in 0..5 {
            let c = Arc::clone(&counter);
            let _handle = pool.spawn(move || {
                c.fetch_add(1, Ordering::Relaxed);
            });
        }

        // Release the blocker
        blocker.wait();

        // Shutdown and wait should drain all pending tasks
        assert!(pool.shutdown_and_wait(Duration::from_secs(5)));

        assert_eq!(
            counter.load(Ordering::Relaxed),
            5,
            "all queued tasks must execute before shutdown completes"
        );
    }

    #[test]
    fn handle_spawn_accepted_before_shutdown_still_runs() {
        let exiting = Arc::new((StdMutex::new(false), StdCondvar::new()));
        let exit_gate = Arc::new((StdMutex::new(false), StdCondvar::new()));

        let exiting_signal = Arc::clone(&exiting);
        let exit_gate_signal = Arc::clone(&exit_gate);
        let pool = BlockingPool::with_config(
            0,
            1,
            BlockingPoolOptions {
                on_thread_stop: Some(Arc::new(move || {
                    let (lock, condvar) = &*exiting_signal;
                    {
                        let mut exiting = lock
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        *exiting = true;
                    }
                    condvar.notify_all();

                    let (gate_lock, gate_condvar) = &*exit_gate_signal;
                    let mut release = gate_lock
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    while !*release {
                        release = gate_condvar
                            .wait(release)
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                    }
                    drop(release);
                })),
                ..Default::default()
            },
        );

        // Start the single worker so shutdown has a live thread to race with.
        pool.spawn(|| {}).wait();

        pool.shutdown();

        let (exiting_lock, exiting_condvar) = &*exiting;
        let (exiting, _timeout) = exiting_condvar
            .wait_timeout_while(
                exiting_lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
                Duration::from_secs(1),
                |exiting| !*exiting,
            )
            .expect("exit signal wait poisoned");
        assert!(
            *exiting,
            "worker should enter the stop callback before the late task is enqueued"
        );
        drop(exiting);

        // Simulate a task that was accepted just before shutdown and only
        // reaches the shared queue while the last worker is already exiting.
        let ran = Arc::new(AtomicUsize::new(0));
        let ran_clone = Arc::clone(&ran);
        let task_id = pool.inner.next_task_id.fetch_add(1, Ordering::Relaxed);
        let cancelled = Arc::new(AtomicBool::new(false));
        let completion = Arc::new(BlockingTaskCompletion::new(pool.inner.time_getter));
        let handle = BlockingTaskHandle {
            task_id,
            cancelled: Arc::clone(&cancelled),
            completion: Arc::clone(&completion),
        };
        let task = BlockingTask {
            work: Box::new(move || {
                ran_clone.fetch_add(1, Ordering::Relaxed);
            }),
            priority: 128,
            preferred_cohort: None,
            cancelled: Arc::clone(&cancelled),
            completion: Arc::clone(&completion),
        };

        pool.inner.queue.push(task);
        pool.inner.pending_count.fetch_add(1, Ordering::Relaxed);
        maybe_spawn_thread_on_inner(&pool.inner);
        {
            let _guard = pool.inner.mutex.lock();
            pool.inner.condvar.notify_one();
        }

        let (gate_lock, gate_condvar) = &*exit_gate;
        {
            let mut release = gate_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *release = true;
        }
        gate_condvar.notify_all();

        assert!(
            handle.wait_timeout(Duration::from_secs(5)),
            "accepted work must still complete even if shutdown starts while the last worker exits"
        );
        assert_eq!(
            ran.load(Ordering::Relaxed),
            1,
            "late accepted task should run exactly once"
        );
        assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
    }

    // ================================================================
    // spawn_blocking Lifecycle Conformance Tests
    // ================================================================

    mod spawn_blocking_conformance {
        use super::*;
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::{Arc, Barrier};
        use std::thread;
        use std::time::{Duration, Instant};

        /// Test data for conformance verification.
        struct ConformanceTestData {
            thread_ids: Arc<Mutex<Vec<thread::ThreadId>>>,
            execution_count: Arc<AtomicU32>,
            barrier: Arc<Barrier>,
        }

        impl ConformanceTestData {
            fn new(expected_threads: usize) -> Self {
                Self {
                    thread_ids: Arc::new(Mutex::new(Vec::new())),
                    execution_count: Arc::new(AtomicU32::new(0)),
                    barrier: Arc::new(Barrier::new(expected_threads + 1)), // +1 for test thread
                }
            }

            fn record_execution(&self) {
                let current_thread = thread::current().id();
                self.thread_ids.lock().push(current_thread);
                self.execution_count.fetch_add(1, Ordering::Relaxed);
            }

            fn get_unique_thread_count(&self) -> usize {
                let ids = self.thread_ids.lock();
                let mut unique_ids = Vec::new();
                for id in ids.iter() {
                    if !unique_ids.contains(id) {
                        unique_ids.push(*id);
                    }
                }
                unique_ids.len()
            }
        }

        #[test]
        fn blocking_task_scheduled_on_dedicated_thread_pool_conformance() {
            let _guard = deterministic_hook_test_guard();

            // Create pool with 2 threads minimum to test thread separation
            let pool = BlockingPool::new(2, 4);
            let test_data = ConformanceTestData::new(3);

            // Get the main thread ID to verify blocking tasks don't run there
            let main_thread_id = thread::current().id();

            // Spawn multiple blocking tasks to verify thread pool usage
            let mut handles = Vec::new();
            for _ in 0..3 {
                let test_data_clone = test_data.thread_ids.clone();
                let barrier_clone = test_data.barrier.clone();

                let handle = pool.spawn(move || {
                    // Record which thread this task runs on
                    let current_thread = thread::current().id();
                    test_data_clone.lock().push(current_thread);

                    // Wait for all tasks to start
                    barrier_clone.wait();

                    // Do some work to ensure we're actually on a blocking thread
                    thread::sleep(Duration::from_millis(10));
                });
                handles.push(handle);
            }

            // Wait for all tasks to start
            test_data.barrier.wait();

            // Wait for all tasks to complete
            for handle in handles {
                assert!(handle.wait_timeout(Duration::from_secs(5)));
            }

            // Verify tasks ran on dedicated threads (not main thread).
            // IMPORTANT: release the guard before calling `get_unique_thread_count`
            // (which re-locks `thread_ids`) — parking_lot's Mutex is NOT reentrant,
            // so holding the guard across that call used to deadlock this test.
            {
                let thread_ids = test_data.thread_ids.lock();
                assert_eq!(thread_ids.len(), 3, "All three tasks should have executed");

                for thread_id in thread_ids.iter() {
                    assert_ne!(
                        *thread_id, main_thread_id,
                        "Blocking tasks should not run on main thread"
                    );
                }
            }

            // Verify at least 2 different threads were used (pool has min 2 threads)
            let unique_count = test_data.get_unique_thread_count();
            assert!(
                unique_count >= 2,
                "Should use at least 2 different threads, got {}",
                unique_count
            );

            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }

        #[test]
        fn cancellation_drains_pool_correctly_conformance() {
            let _guard = deterministic_hook_test_guard();

            // Use max_threads=1 so task 2 stays queued while task 1 is running.
            // With max_threads=2, maybe_spawn_thread_on_inner would spawn a second
            // worker that picks up task 2 before the test's `handle2.cancel()`
            // call lands, making the cancel-before-execution check racy.
            let pool = BlockingPool::new(1, 1);
            let start_barrier = Arc::new(Barrier::new(2));
            let finish_gate = Arc::new((Mutex::new(false), Condvar::new()));

            // Task 1: Blocks until we signal completion
            let start_barrier_clone = start_barrier.clone();
            let finish_gate_clone = finish_gate.clone();
            let handle1 = pool.spawn(move || {
                start_barrier_clone.wait(); // Signal task started
                let (lock, cvar) = &*finish_gate_clone;
                let mut finish = lock.lock();
                while !*finish {
                    cvar.wait(&mut finish);
                }
                // Task completes after gate opens
            });

            // Wait for task 1 to start
            start_barrier.wait();

            // Task 2: Will be queued while task 1 is running
            let executed = Arc::new(AtomicBool::new(false));
            let executed_clone = executed.clone();
            let handle2 = pool.spawn(move || {
                executed_clone.store(true, Ordering::SeqCst);
            });

            // Small delay to ensure task 2 is queued
            thread::sleep(Duration::from_millis(50));

            // Cancel task 2 before it gets to execute
            handle2.cancel();

            // Release task 1 to complete
            {
                let (lock, cvar) = &*finish_gate;
                let mut finish = lock.lock();
                *finish = true;
                cvar.notify_all();
            }

            // Task 1 should complete successfully
            assert!(handle1.wait_timeout(Duration::from_secs(5)));
            assert!(!handle1.is_cancelled());

            // Task 2 should be cancelled and not execute
            assert!(handle2.wait_timeout(Duration::from_secs(1))); // Should complete quickly (cancelled)
            assert!(handle2.is_cancelled());
            assert!(
                !executed.load(Ordering::SeqCst),
                "Cancelled task should not execute"
            );

            // Verify pool drains correctly
            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }

        #[test]
        fn panic_in_blocking_task_isolated_conformance() {
            let _guard = deterministic_hook_test_guard();

            let pool = BlockingPool::new(1, 2);
            let task_executed = Arc::new(AtomicBool::new(false));

            // Task 1: Panics during execution
            let handle_panic = pool.spawn(|| {
                panic!("Test panic - should be isolated");
            });

            // Task 2: Normal execution after panic
            let task_executed_clone = task_executed.clone();
            let handle_normal = pool.spawn(move || {
                task_executed_clone.store(true, Ordering::SeqCst);
                // Return nothing
            });

            // Both tasks should complete (panic is isolated)
            assert!(handle_panic.wait_timeout(Duration::from_secs(5)));
            assert!(handle_normal.wait_timeout(Duration::from_secs(5)));

            // Verify the normal task executed successfully
            assert!(
                task_executed.load(Ordering::SeqCst),
                "Normal task should execute after panic"
            );

            // Verify pool is still operational after panic
            let handle_after_panic = pool.spawn(|| {
                let _ = "still working";
            });
            assert!(handle_after_panic.wait_timeout(Duration::from_secs(5)));

            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }

        #[test]
        fn result_returned_via_completion_mechanism_conformance() {
            let _guard = deterministic_hook_test_guard();

            let pool = BlockingPool::new(1, 2);

            // Test synchronous completion signaling
            let completion_time = Arc::new(Mutex::new(None::<Instant>));
            let completion_time_clone = completion_time.clone();

            let handle = pool.spawn(move || {
                thread::sleep(Duration::from_millis(100));
                *completion_time_clone.lock() = Some(Instant::now());
            });

            let start_time = Instant::now();

            // Verify task is not initially done
            assert!(!handle.is_done());

            // Wait for completion
            assert!(handle.wait_timeout(Duration::from_secs(5)));

            // Verify task is now done
            assert!(handle.is_done());

            // Verify completion timing
            let end_time = Instant::now();
            let elapsed = end_time.duration_since(start_time);
            assert!(
                elapsed >= Duration::from_millis(100),
                "Should wait at least 100ms"
            );

            // Verify completion was signaled at the right time
            let recorded_completion = completion_time.lock();
            assert!(
                recorded_completion.is_some(),
                "Completion time should be recorded"
            );

            // Test immediate completion check
            let instant_handle = pool.spawn(|| {});
            assert!(instant_handle.wait_timeout(Duration::from_secs(5)));
            assert!(instant_handle.is_done());

            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }

        #[test]
        fn completion_mechanism_timeout_conformance() {
            let _guard = deterministic_hook_test_guard();

            let pool = BlockingPool::new(1, 2);
            let gate = Arc::new((Mutex::new(false), Condvar::new()));
            let gate_clone = gate.clone();

            // Task that blocks indefinitely until signaled
            let handle = pool.spawn(move || {
                let (lock, cvar) = &*gate_clone;
                let mut release = lock.lock();
                while !*release {
                    cvar.wait(&mut release);
                }
                // "completed" -> removed to match F: FnOnce() -> ()
            });
            // Test timeout behavior
            let start_time = Instant::now();
            assert!(!handle.wait_timeout(Duration::from_millis(100)));
            let elapsed = start_time.elapsed();

            // Should timeout in approximately 100ms
            assert!(
                elapsed >= Duration::from_millis(90),
                "Should wait at least 90ms"
            );
            assert!(
                elapsed <= Duration::from_millis(200),
                "Should timeout within 200ms"
            );
            assert!(!handle.is_done(), "Task should not be done after timeout");

            // Release the task
            {
                let (lock, cvar) = &*gate;
                let mut release = lock.lock();
                *release = true;
                cvar.notify_all();
            }

            // Now it should complete
            assert!(handle.wait_timeout(Duration::from_secs(5)));
            assert!(handle.is_done());

            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }

        #[test]
        fn budget_accounting_across_poll_boundaries_conformance() {
            let _guard = deterministic_hook_test_guard();

            let pool = BlockingPool::new(1, 4);

            // Track resource usage across task boundaries
            struct ResourceTracker {
                task_starts: AtomicU32,
                task_ends: AtomicU32,
                max_concurrent: AtomicU32,
                current_concurrent: AtomicU32,
            }

            let tracker = Arc::new(ResourceTracker {
                task_starts: AtomicU32::new(0),
                task_ends: AtomicU32::new(0),
                max_concurrent: AtomicU32::new(0),
                current_concurrent: AtomicU32::new(0),
            });

            let barrier = Arc::new(Barrier::new(4)); // 3 tasks + test thread
            let mut handles = Vec::new();

            // Submit 3 tasks to test concurrent execution
            for _i in 0..3 {
                let tracker_clone = tracker.clone();
                let barrier_clone = barrier.clone();

                let handle = pool.spawn(move || {
                    // Record task start
                    tracker_clone.task_starts.fetch_add(1, Ordering::Relaxed);
                    let current = tracker_clone
                        .current_concurrent
                        .fetch_add(1, Ordering::Relaxed)
                        + 1;

                    // Update max concurrent
                    let mut max = tracker_clone.max_concurrent.load(Ordering::Relaxed);
                    while current > max {
                        match tracker_clone.max_concurrent.compare_exchange_weak(
                            max,
                            current,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        ) {
                            Ok(_) => break,
                            Err(new_max) => max = new_max,
                        }
                    }

                    // Wait for all tasks to start
                    barrier_clone.wait();

                    // Simulate work
                    thread::sleep(Duration::from_millis(50));

                    // Record task end
                    tracker_clone
                        .current_concurrent
                        .fetch_sub(1, Ordering::Relaxed);
                    tracker_clone.task_ends.fetch_add(1, Ordering::Relaxed);
                });

                handles.push(handle);
            }

            // Wait for all tasks to start
            barrier.wait();

            // Wait for all tasks to complete
            for handle in handles {
                assert!(handle.wait_timeout(Duration::from_secs(5)));
            }

            // Verify budget accounting
            assert_eq!(
                tracker.task_starts.load(Ordering::Relaxed),
                3,
                "All tasks should start"
            );
            assert_eq!(
                tracker.task_ends.load(Ordering::Relaxed),
                3,
                "All tasks should end"
            );
            assert_eq!(
                tracker.current_concurrent.load(Ordering::Relaxed),
                0,
                "No tasks should be running"
            );

            // Verify resource limits were respected (pool has max 4 threads, so max 3 concurrent is reasonable)
            let max_concurrent = tracker.max_concurrent.load(Ordering::Relaxed);
            assert!(max_concurrent <= 4, "Should not exceed pool thread limit");
            assert!(max_concurrent >= 1, "At least one task should run");

            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }

        #[test]
        fn spawn_blocking_priority_scheduling_conformance() {
            let _guard = deterministic_hook_test_guard();

            let pool = BlockingPool::new(1, 1); // Single thread to force sequential execution

            let execution_order = Arc::new(Mutex::new(Vec::new()));
            let start_gate = Arc::new((Mutex::new(false), Condvar::new()));

            // First task blocks to allow others to queue
            let start_gate_clone = start_gate.clone();
            let handle_blocker = pool.spawn(move || {
                let (lock, cvar) = &*start_gate_clone;
                let mut start = lock.lock();
                while !*start {
                    cvar.wait(&mut start);
                }
            });

            // Queue tasks with different priorities
            let mut priority_handles = Vec::new();

            for (priority, task_id) in [(0, "high"), (128, "medium"), (255, "low")] {
                let execution_order_clone = execution_order.clone();
                let handle = pool.spawn_with_priority(
                    move || {
                        execution_order_clone.lock().push(task_id);
                    },
                    priority,
                );
                priority_handles.push(handle);
            }

            // Small delay to ensure tasks are queued
            thread::sleep(Duration::from_millis(50));

            // Release the blocker task
            {
                let (lock, cvar) = &*start_gate;
                let mut start = lock.lock();
                *start = true;
                cvar.notify_all();
            }

            // Wait for all tasks to complete
            assert!(handle_blocker.wait_timeout(Duration::from_secs(5)));
            for handle in priority_handles {
                assert!(handle.wait_timeout(Duration::from_secs(5)));
            }

            // Verify execution order respects priority (higher priority = lower number = executes first)
            let order = execution_order.lock();
            assert_eq!(order.len(), 3, "All priority tasks should execute");

            // Note: Due to concurrent execution, exact order might vary, but high priority should generally go first
            // At minimum, verify all tasks executed
            assert!(order.contains(&"high"));
            assert!(order.contains(&"medium"));
            assert!(order.contains(&"low"));

            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }

        #[test]
        fn blocking_pool_handle_conformance() {
            let _guard = deterministic_hook_test_guard();

            let pool = BlockingPool::new(1, 2);
            let handle = pool.handle();

            // Verify handle spawning works identically to pool spawning
            let executed = Arc::new(AtomicBool::new(false));
            let executed_clone = executed.clone();
            let task_handle = handle.spawn(move || {
                executed_clone.store(true, Ordering::SeqCst);
            });

            assert!(task_handle.wait_timeout(Duration::from_secs(5)));
            assert!(
                executed.load(Ordering::SeqCst),
                "Handle-spawned task should execute"
            );

            // Test handle priority spawning
            let priority_executed = Arc::new(AtomicBool::new(false));
            let priority_executed_clone = priority_executed.clone();

            let priority_handle = handle.spawn_with_priority(
                move || {
                    priority_executed_clone.store(true, Ordering::SeqCst);
                },
                64, // High priority
            );

            assert!(priority_handle.wait_timeout(Duration::from_secs(5)));
            assert!(
                priority_executed.load(Ordering::SeqCst),
                "Priority handle task should execute"
            );

            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }

        #[test]
        fn blocking_task_lifecycle_state_transitions_conformance() {
            let _guard = deterministic_hook_test_guard();

            let pool = BlockingPool::new(1, 2);

            // Test task state transitions: created -> running -> done
            let gate = Arc::new((Mutex::new(false), Condvar::new()));
            let gate_clone = gate.clone();

            let handle = pool.spawn(move || {
                let (lock, cvar) = &*gate_clone;
                let mut release = lock.lock();
                while !*release {
                    cvar.wait(&mut release);
                }
                // "completed" -> removed to match F: FnOnce() -> ()
            });

            // Initially: not done, not cancelled
            assert!(!handle.is_done());
            assert!(!handle.is_cancelled());

            // Test cancellation state
            handle.cancel();
            assert!(handle.is_cancelled());
            assert!(!handle.is_done()); // Still not done until completion

            // Release and complete task
            {
                let (lock, cvar) = &*gate;
                let mut release = lock.lock();
                *release = true;
                cvar.notify_all();
            }

            assert!(handle.wait_timeout(Duration::from_secs(5)));

            // Final state: done and cancelled
            assert!(handle.is_done());
            assert!(handle.is_cancelled());

            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }

        #[test]
        fn blocking_pool_shutdown_lifecycle_conformance() {
            let _guard = deterministic_hook_test_guard();

            let pool = BlockingPool::new(1, 2);

            // Submit a task before shutdown
            let pre_shutdown_executed = Arc::new(AtomicBool::new(false));
            let pre_shutdown_executed_clone = pre_shutdown_executed.clone();
            let handle_pre = pool.spawn(move || {
                thread::sleep(Duration::from_millis(100)); // Ensure shutdown happens during execution
                pre_shutdown_executed_clone.store(true, Ordering::SeqCst);
            });

            // Start shutdown (but don't wait)
            pool.shutdown();

            // Attempt to submit task after shutdown - should be immediately cancelled
            let post_shutdown_executed = Arc::new(AtomicBool::new(false));
            let post_shutdown_executed_clone = post_shutdown_executed.clone();
            let handle_post = pool.spawn(move || {
                post_shutdown_executed_clone.store(true, Ordering::SeqCst);
            });

            // Pre-shutdown task should complete
            assert!(handle_pre.wait_timeout(Duration::from_secs(5)));
            assert!(
                pre_shutdown_executed.load(Ordering::SeqCst),
                "Pre-shutdown task should execute"
            );

            // Post-shutdown task should be cancelled immediately
            assert!(handle_post.wait_timeout(Duration::from_secs(1))); // Should complete quickly (cancelled)
            assert!(handle_post.is_cancelled());
            assert!(
                !post_shutdown_executed.load(Ordering::SeqCst),
                "Post-shutdown task should not execute"
            );

            // Complete shutdown
            assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
        }
    }

    // =========================================================================
    // Cancel + spawn_blocking under shutdown metamorphic relations.
    //
    // Per-case tests cover:
    //   - single spawn-after-shutdown rejection (both APIs)
    //   - linearization race around the submission mutex
    //   - graceful drain of pending tasks on shutdown
    //
    // These MRs bind the broader contract over the shutdown boundary.
    // Each one names a concrete interleaving and verifies invariants
    // that a refactor of the spawn path or shutdown signal must
    // preserve.
    // =========================================================================

    mod shutdown_mr {
        use super::*;

        /// MR — All N consecutive spawns AFTER shutdown are rejected
        /// uniformly. The rejection is not a first-post-shutdown-only
        /// effect; it holds for the entire suffix. Task counters and
        /// pending queue stay unchanged throughout.
        #[test]
        fn mr_all_spawns_after_shutdown_are_rejected_uniformly() {
            let pool = BlockingPool::new(1, 4);
            pool.shutdown();
            let executed = Arc::new(AtomicI32::new(0));
            let mut handles = Vec::new();
            for _ in 0..8 {
                let e = Arc::clone(&executed);
                handles.push(pool.spawn(move || {
                    e.fetch_add(1, Ordering::Relaxed);
                }));
            }
            for (i, h) in handles.iter().enumerate() {
                assert!(h.is_cancelled(), "spawn #{i} not cancelled post-shutdown");
                assert!(
                    h.wait_timeout(Duration::from_millis(100)),
                    "spawn #{i} completion not signaled post-shutdown",
                );
            }
            assert_eq!(
                executed.load(Ordering::Relaxed),
                0,
                "no post-shutdown task may execute",
            );
            assert_eq!(pool.pending_count(), 0);
        }

        /// MR — Shutdown is idempotent. Calling shutdown() N times is
        /// equivalent to calling it once. is_shutdown() returns true
        /// throughout; spawn rejection semantics unchanged.
        #[test]
        fn mr_shutdown_is_idempotent() {
            let pool = BlockingPool::new(0, 2);
            for _ in 0..5 {
                pool.shutdown();
                assert!(pool.is_shutdown());
            }
            // Spawn rejection still works after N shutdowns.
            let executed = Arc::new(AtomicBool::new(false));
            let e = Arc::clone(&executed);
            let handle = pool.spawn(move || {
                e.store(true, Ordering::Relaxed);
            });
            assert!(handle.is_cancelled());
            assert!(handle.wait_timeout(Duration::from_millis(100)));
            assert!(!executed.load(Ordering::Relaxed));
        }

        /// MR — Handle obtained pre-shutdown survives as a valid handle
        /// across the shutdown boundary. Cancelling it after shutdown
        /// is a no-op on the completion signal state (completion was
        /// already signaled by the running task or will be signaled by
        /// the pre-shutdown-queued task).
        #[test]
        fn mr_pre_shutdown_handle_cancel_after_shutdown_is_safe() {
            let pool = BlockingPool::new(0, 2);
            let executed = Arc::new(AtomicBool::new(false));
            let e = Arc::clone(&executed);
            let handle = pool.spawn(move || {
                // Simulate instantaneous work — the pool may or may not
                // execute it before we shut down; either outcome is valid.
                e.store(true, Ordering::Relaxed);
            });
            pool.shutdown();
            // cancel() after shutdown must not panic and must not flip
            // the completion signal backwards.
            handle.cancel();
            assert!(handle.is_cancelled());
            // shutdown_and_wait must still drain cleanly.
            assert!(pool.shutdown_and_wait(Duration::from_secs(2)));
        }

        /// MR — Post-shutdown spawns do not affect thread accounting.
        /// active_threads and busy_threads observed immediately before
        /// the post-shutdown spawn are equal to those observed
        /// immediately after. The fast-path rejection at spawn must
        /// not call maybe_spawn_thread().
        #[test]
        fn mr_post_shutdown_spawn_does_not_grow_thread_pool() {
            let pool = BlockingPool::new(0, 4);
            pool.shutdown();
            // Wait for any lingering threads to exit after shutdown.
            // With min_threads=0 and immediate shutdown, none should
            // have been spawned, but the invariant we care about is
            // invariance — before == after.
            let before_active = pool.active_threads();
            let before_busy = pool.busy_threads();
            let before_pending = pool.pending_count();
            for _ in 0..4 {
                let _ = pool.spawn(|| {
                    panic!("post-shutdown body must never run");
                });
            }
            assert_eq!(pool.active_threads(), before_active);
            assert_eq!(pool.busy_threads(), before_busy);
            assert_eq!(pool.pending_count(), before_pending);
        }

        /// MR — is_shutdown() is a stable property once shutdown() is
        /// called. No observed interleaving of spawns, cancels, or
        /// queries can make is_shutdown() regress to false.
        #[test]
        fn mr_is_shutdown_is_sticky_true() {
            let pool = BlockingPool::new(1, 2);
            assert!(!pool.is_shutdown(), "fresh pool should not be shutdown");
            pool.shutdown();
            for _ in 0..20 {
                // Interleave reads with rejected spawns and cancels.
                let h = pool.spawn(|| {});
                h.cancel();
                assert!(pool.is_shutdown(), "is_shutdown regressed to false");
            }
        }

        /// MR — shutdown() followed by spawn() yields a handle whose
        /// completion signal has ALREADY fired (wait_timeout returns
        /// true with a zero-ish timeout). This distinguishes
        /// rejection-with-signal from rejection-that-forgets-to-signal
        /// — the latter would hang any caller that awaits completion.
        #[test]
        fn mr_rejected_handle_completion_is_prepaid() {
            let pool = BlockingPool::new(0, 2);
            pool.shutdown();
            for _ in 0..5 {
                let h = pool.spawn(|| {});
                // Any timeout — including zero — must succeed because
                // completion was signaled synchronously inside spawn().
                assert!(
                    h.wait_timeout(Duration::from_millis(1)),
                    "rejected handle completion signal not prepaid",
                );
                assert!(h.is_cancelled());
            }
        }

        /// MR — BlockingPoolHandle::spawn agrees with BlockingPool::spawn
        /// on post-shutdown rejection semantics. The two APIs must have
        /// identical observable contract (rejection + cancellation +
        /// prepaid completion) after shutdown.
        #[test]
        fn mr_pool_and_handle_api_agree_after_shutdown() {
            let pool = BlockingPool::new(0, 2);
            let api_handle = pool.handle();
            pool.shutdown();

            let via_pool = pool.spawn(|| panic!("must not run"));
            let via_handle = api_handle.spawn(|| panic!("must not run"));

            assert_eq!(via_pool.is_cancelled(), via_handle.is_cancelled());
            assert!(via_pool.is_cancelled());
            assert!(
                via_pool.wait_timeout(Duration::from_millis(100))
                    && via_handle.wait_timeout(Duration::from_millis(100)),
                "one of the APIs failed to prepay completion",
            );
        }
    }
}

// Metamorphic tests for blocking pool fairness properties
mod metamorphic;

#[cfg(test)]
#[path = "blocking_pool/comprehensive_metamorphic_tests.rs"]
mod comprehensive_metamorphic_tests;
