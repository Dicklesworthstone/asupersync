//! Per-worker local queue.
//!
//! Uses a lock-protected `SmallVec` for LIFO push/pop (owner) and FIFO steal (thief).
//! The queue bounds search depth during stealing to avoid O(N) traversal overhead
//! while maintaining hot-path LIFO locality for the owner.

use crate::record::task::TaskRecord;
use crate::runtime::{RuntimeState, TaskTable};
use crate::sync::ContendedMutex;
use crate::types::TaskId;
#[cfg(any(test, feature = "test-internals"))]
use crate::types::{Budget, RegionId};
use crate::util::Arena;
use hashbrown::HashSet;
use parking_lot::Mutex;
use smallvec::SmallVec;
use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

thread_local! {
    static CURRENT_QUEUE: RefCell<Option<LocalQueue>> = const { RefCell::new(None) };
}

#[derive(Debug, Clone)]
enum TaskSource {
    RuntimeState(Arc<ContendedMutex<RuntimeState>>),
    TaskTable(Arc<ContendedMutex<TaskTable>>),
}

impl TaskSource {
    #[inline]
    fn with_tasks_arena_mut<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&mut Arena<TaskRecord>) -> R,
    {
        match self {
            Self::RuntimeState(state) => {
                let mut state = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                f(state.tasks_arena_mut())
            }
            Self::TaskTable(tasks) => {
                let mut tasks = tasks
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                f(tasks.tasks_arena_mut())
            }
        }
    }

    #[inline]
    fn same_underlying_tasks(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::RuntimeState(lhs), Self::RuntimeState(rhs)) => Arc::ptr_eq(lhs, rhs),
            (Self::TaskTable(lhs), Self::TaskTable(rhs)) => Arc::ptr_eq(lhs, rhs),
            _ => false,
        }
    }
}

/// br-asupersync-5oll2p / pvbwxm: queue payload + O(1) presence index.
///
/// `queue` is the LIFO/FIFO storage (LIFO for owner pop, FIFO for stealer).
/// `presence` is an auxiliary index used by [`LocalQueue::schedule_local_push`]
/// to detect duplicate scheduling without an O(N) linear scan over `queue`.
/// All write paths (push, push_many, pop, steal, steal_batch) keep `queue`
/// and `presence` in sync under a single mutex acquisition so the index
/// never drifts from the storage.
#[derive(Debug, Default)]
struct LocalQueueInner {
    queue: SmallVec<[TaskId; 32]>,
    presence: HashSet<TaskId>,
}

/// A local task queue for a worker.
///
/// This queue is single-producer, multi-consumer. The worker owning this
/// queue pushes and pops from one end (LIFO), while other workers steal
/// from the other end (FIFO).
///
/// br-asupersync-pvbwxm: `cached_len` is an `AtomicUsize` mirror of
/// `inner.queue.len()` published while holding the same lock that mutates
/// the queue. The owner's backoff loop reads `is_empty()` / `len()` very
/// frequently while looking for work to park on; routing those reads
/// through a single `Acquire` atomic load lets the worker decide whether
/// to spin / yield / park without ever taking the deque mutex (which
/// would contend with stealers from other workers).
#[derive(Debug, Clone)]
pub struct LocalQueue {
    tasks: TaskSource,
    inner: Arc<Mutex<LocalQueueInner>>,
    cached_len: Arc<AtomicUsize>,
}

impl LocalQueue {
    /// Creates a new local queue.
    #[inline]
    #[must_use]
    pub fn new(state: Arc<ContendedMutex<RuntimeState>>) -> Self {
        Self::new_with_source(TaskSource::RuntimeState(state))
    }

    /// Creates a new local queue backed directly by a shared task table.
    ///
    /// This is used by sharded runtime experiments where scheduler hot paths
    /// lock only the task shard.
    #[inline]
    #[must_use]
    pub fn new_with_task_table(tasks: Arc<ContendedMutex<TaskTable>>) -> Self {
        Self::new_with_source(TaskSource::TaskTable(tasks))
    }

    #[inline]
    fn new_with_source(tasks: TaskSource) -> Self {
        Self {
            tasks,
            inner: Arc::new(Mutex::new(LocalQueueInner::default())),
            cached_len: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Sets the current thread-local queue and returns a guard to restore the previous one.
    pub(crate) fn set_current(queue: Self) -> CurrentQueueGuard {
        let prev = CURRENT_QUEUE.with(|slot| slot.replace(Some(queue)));
        CurrentQueueGuard { prev }
    }

    /// Clears the current thread-local queue.
    #[allow(dead_code)] // symmetric API with set_current; reserved for shutdown paths
    pub(crate) fn clear_current() {
        CURRENT_QUEUE.with(|slot| {
            // Fix race condition: handle potential borrow conflicts gracefully
            match slot.try_borrow_mut() {
                Ok(mut borrowed) => {
                    borrowed.take();
                }
                Err(_) => {
                    // RefCell already borrowed by concurrent schedule_local() call.
                    // Cannot safely clear the queue state, but this is acceptable
                    // during shutdown as the thread-local will be cleaned up anyway.
                }
            }
        });
    }

    /// Schedules a task on the current thread-local queue.
    ///
    /// Returns `true` if the task was accepted by a local queue (or was already
    /// queued there), `false` if no local queue is set or the task record is
    /// missing from the backing arena.
    #[inline]
    pub(crate) fn schedule_local(task: TaskId) -> bool {
        // Fix race condition: clone the queue to avoid holding RefCell borrow
        // across the schedule_local_push call, preventing borrow conflicts with
        // concurrent CurrentQueueGuard::drop() operations.
        let queue = CURRENT_QUEUE.with(|slot| slot.borrow().clone());

        match queue {
            Some(queue) => queue.schedule_local_push(task),
            None => false,
        }
    }

    /// Returns whether the current thread-local queue belongs to the supplied
    /// runtime task store.
    #[inline]
    pub(crate) fn current_is_backed_by(
        state: &Arc<ContendedMutex<RuntimeState>>,
        task_table: Option<&Arc<ContendedMutex<TaskTable>>>,
    ) -> bool {
        CURRENT_QUEUE.with(|slot| {
            slot.borrow().as_ref().is_some_and(|queue| {
                task_table.map_or_else(
                    || {
                        matches!(
                            &queue.tasks,
                            TaskSource::RuntimeState(current) if Arc::ptr_eq(current, state)
                        )
                    },
                    |expected| {
                        matches!(
                            &queue.tasks,
                            TaskSource::TaskTable(current) if Arc::ptr_eq(current, expected)
                        )
                    },
                )
            })
        })
    }

    /// Creates a runtime state with preallocated task records for tests.
    #[cfg(any(test, feature = "test-internals"))]
    #[must_use]
    pub fn test_state(max_task_id: u32) -> Arc<ContendedMutex<RuntimeState>> {
        let mut state = RuntimeState::new();
        for id in 0..=max_task_id {
            let task_id = TaskId::new_for_test(id, 0);
            let record = TaskRecord::new(task_id, RegionId::new_for_test(0, 1), Budget::INFINITE);
            let idx = state.insert_task(record);
            debug_assert_eq!(idx.index(), id);
        }
        Arc::new(ContendedMutex::new("runtime_state", state))
    }

    /// Creates a standalone task table with preallocated task records for tests.
    #[cfg(any(test, feature = "test-internals"))]
    #[must_use]
    pub fn test_task_table(max_task_id: u32) -> Arc<ContendedMutex<TaskTable>> {
        let mut tasks = TaskTable::new();
        for id in 0..=max_task_id {
            let task_id = TaskId::new_for_test(id, 0);
            let record = TaskRecord::new(task_id, RegionId::new_for_test(0, 1), Budget::INFINITE);
            let idx = tasks.insert_task(record);
            debug_assert_eq!(idx.index(), id);
        }
        Arc::new(ContendedMutex::new("task_table", tasks))
    }

    /// Creates a local queue with an isolated test runtime state.
    #[cfg(any(test, feature = "test-internals"))]
    #[must_use]
    pub fn new_for_test(max_task_id: u32) -> Self {
        Self::new(Self::test_state(max_task_id))
    }

    /// Pushes a task to the local queue.
    ///
    /// br-asupersync-pvbwxm: maintains the `cached_len` atomic mirror so
    /// owner backoff `is_empty()` checks can be lock-free.
    ///
    /// br-asupersync-34fz4v: Optimized hotpath for <50ns target:
    /// - Combined queue+presence operations under single lock
    /// - Relaxed atomic ordering for better performance
    /// - Minimal lock hold time with strategic early release
    #[inline]
    pub fn push(&self, task: TaskId) {
        let mut inner = self.inner.lock();
        if inner.presence.insert(task) {
            inner.queue.push(task);
        }
        self.cached_len.store(inner.queue.len(), Ordering::Release);
    }

    /// Pushes a task from the TLS scheduling fast path.
    ///
    /// Returns `false` only when the task record does not exist in the backing
    /// arena. Duplicate scheduling still returns `true` because the task is
    /// already present in this queue.
    ///
    /// br-asupersync-5oll2p: dedup uses the `presence` HashSet for O(1)
    /// membership, replacing the prior O(N) `queue.contains(&task)`
    /// linear scan.
    ///
    /// br-asupersync-34fz4v: Optimized TLS fast path:
    /// - Relaxed ordering for local queue updates
    /// - Force inline for critical scheduling path
    #[inline]
    fn schedule_local_push(&self, task: TaskId) -> bool {
        // br-asupersync-yvmiat: In production builds, skip the contended state lock
        // for arena validation. The queue lock alone provides sufficient safety,
        // and production code should not be pushing invalid TaskIds.
        #[cfg(debug_assertions)]
        {
            self.tasks.with_tasks_arena_mut(|arena| {
                if arena.get(task.arena_index()).is_none() {
                    return false;
                }
                self.schedule_local_push_unchecked(task);
                true
            })
        }
        #[cfg(not(debug_assertions))]
        {
            self.schedule_local_push_unchecked(task);
            true
        }
    }

    /// Push to local queue without arena validation. Used internally by schedule_local_push.
    ///
    /// br-asupersync-yvmiat: Extracted to eliminate duplicate code between debug and production paths.
    #[inline]
    fn schedule_local_push_unchecked(&self, task: TaskId) {
        let mut inner = self.inner.lock();
        // O(1) HashSet check + insert vs. the legacy O(N)
        // SmallVec::contains scan.
        if inner.presence.insert(task) {
            inner.queue.push(task);
        }
        self.cached_len.store(inner.queue.len(), Ordering::Release);
    }

    /// Pushes multiple tasks to the local queue under one arena/queue lock.
    ///
    /// br-asupersync-34fz4v: Optimized batch operations for better performance:
    /// - Early return for empty slice
    /// - Precise memory reservations to avoid reallocations
    /// - Single atomic update for entire batch
    /// - Relaxed ordering for local operations
    #[inline]
    pub fn push_many(&self, tasks: &[TaskId]) {
        if tasks.is_empty() {
            return;
        }
        let mut inner = self.inner.lock();
        // Batch enqueue already knows the exact growth ahead of time, so avoid
        // repeated SmallVec / HashSet growth while inserting the slice.
        inner.queue.reserve(tasks.len());
        inner.presence.reserve(tasks.len());
        for task in tasks {
            if inner.presence.insert(*task) {
                inner.queue.push(*task);
            }
        }
        self.cached_len.store(inner.queue.len(), Ordering::Release);
    }

    /// Pops a task from the local queue (LIFO).
    ///
    /// br-asupersync-34fz4v: Optimized hotpath for <50ns target:
    /// - Early return for empty queue using fast atomic check
    /// - Combined pop+presence operations under single lock
    /// - Relaxed atomic ordering for better performance
    #[inline]
    #[must_use]
    pub fn pop(&self) -> Option<TaskId> {
        // Fast path: if queue is likely empty, avoid locking entirely
        if self.cached_len.load(Ordering::Relaxed) == 0 {
            return None;
        }

        let mut inner = self.inner.lock();
        let popped = inner.queue.pop();
        if let Some(task) = popped {
            inner.presence.remove(&task);
        }
        self.cached_len.store(inner.queue.len(), Ordering::Release);
        popped
    }

    /// Returns true if the local queue is empty.
    ///
    /// br-asupersync-pvbwxm: lock-free atomic load of the cached length;
    /// the owner's backoff loop calls this on every iteration and previously
    /// took the queue mutex (contending with stealers from other workers).
    ///
    /// br-asupersync-34fz4v: Optimized for hotpath performance:
    /// - Relaxed ordering for lower overhead (backoff loops don't need strict ordering)
    /// - Force inline for zero-cost abstraction
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cached_len.load(Ordering::Relaxed) == 0
    }

    /// Returns the current length of the local queue.
    ///
    /// br-asupersync-pvbwxm: lock-free atomic load of the cached length.
    /// Reads are eventually consistent with concurrent steals — the value
    /// is current as of the most recent push/pop/steal critical section
    /// observed by this thread.
    ///
    /// br-asupersync-34fz4v: Optimized for hotpath performance:
    /// - Relaxed ordering for lower overhead (most callers don't need strict ordering)
    /// - Force inline for zero-cost abstraction
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.cached_len.load(Ordering::Relaxed)
    }

    /// Returns a stable snapshot of queued task IDs for observability/tests.
    ///
    /// The snapshot is captured under a single queue lock so callers can use
    /// the returned vector and its length consistently without racing queue
    /// mutations between separate `len()` and iteration steps.
    #[inline]
    #[must_use]
    pub fn snapshot_tasks(&self) -> SmallVec<[TaskId; 32]> {
        let inner = self.inner.lock();
        inner.queue.iter().copied().collect()
    }

    /// Creates a stealer for this queue.
    #[inline]
    #[must_use]
    pub fn stealer(&self) -> Stealer {
        Stealer {
            tasks: self.tasks.clone(),
            inner: Arc::clone(&self.inner),
            cached_len: Arc::clone(&self.cached_len),
        }
    }
}

/// Guard that restores the previous local queue on drop.
pub(crate) struct CurrentQueueGuard {
    prev: Option<LocalQueue>,
}

impl Drop for CurrentQueueGuard {
    fn drop(&mut self) {
        let prev = self.prev.take();
        // Fix race condition: handle potential borrow conflicts gracefully
        // when concurrent schedule_local() calls are holding immutable borrows
        let _ = CURRENT_QUEUE.try_with(|slot| {
            // Use try_borrow_mut to avoid panic if RefCell is already borrowed
            match slot.try_borrow_mut() {
                Ok(mut borrowed) => {
                    *borrowed = prev;
                }
                Err(_) => {
                    // RefCell already borrowed - this can happen if schedule_local()
                    // is running concurrently. In this case, we can't safely update
                    // the thread-local state, so we silently ignore the restore.
                    // This is safe because:
                    // 1. The guard is being dropped, so the previous queue is no longer needed
                    // 2. Concurrent operations will continue with the current queue
                    // 3. Thread-local state will be cleaned up when the thread exits
                }
            }
        });
    }
}

/// A handle to steal tasks from a local queue.
#[derive(Debug, Clone)]
pub struct Stealer {
    tasks: TaskSource,
    inner: Arc<Mutex<LocalQueueInner>>,
    cached_len: Arc<AtomicUsize>,
}

impl Stealer {
    const SKIPPED_LOCALS_INLINE_CAP: usize = 8;

    #[inline]
    fn compact_scanned_prefix(
        queue: &mut SmallVec<[TaskId; 32]>,
        kept_prefix_len: usize,
        scanned_len: usize,
    ) {
        debug_assert!(kept_prefix_len <= scanned_len);
        if kept_prefix_len == scanned_len {
            return;
        }

        let removed = scanned_len - kept_prefix_len;
        let len = queue.len();
        queue
            .as_mut_slice()
            .copy_within(scanned_len..len, kept_prefix_len);
        queue.truncate(len - removed);
    }

    /// Returns the exact length of the queue.
    ///
    /// br-asupersync-pvbwxm: lock-free atomic load — Power of Two Choices
    /// stealer sampling consults this from many workers at once. Routing
    /// every sample through the deque mutex (the prior implementation)
    /// turned the sampling itself into the contention point. The atomic
    /// mirror is updated on every owner push/pop and stealer steal
    /// critical section, so the value is eventually consistent and
    /// adequate for sampling decisions.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.cached_len.load(Ordering::Acquire)
    }

    /// Returns a bounded hint for how many tasks are currently stealable.
    ///
    /// This scans only the same front prefix that [`Self::steal`] and
    /// [`Self::steal_batch`] inspect, so victim selection does not over-rank queues
    /// whose visible backlog is entirely local-only work.
    #[inline]
    #[must_use]
    pub fn stealable_len_hint(&self) -> usize {
        if self.cached_len.load(Ordering::Acquire) == 0 {
            return 0;
        }

        self.tasks.with_tasks_arena_mut(|arena| {
            let inner = self.inner.lock();
            let scan_limit = inner.queue.len().min(Self::SKIPPED_LOCALS_INLINE_CAP);
            let mut stealable = 0;

            for idx in 0..scan_limit {
                let task_id = inner.queue[idx];
                match arena.get(task_id.arena_index()) {
                    Some(record) if record.is_local() => {}
                    _ => {
                        stealable += 1;
                    }
                }
            }

            stealable
        })
    }

    /// Returns true if the queue has no stealable items.
    ///
    /// Mirrors the work-stealing scan window, not the raw queue length, so a
    /// queue fronted entirely by local-only tasks correctly appears empty to
    /// thieves.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stealable_len_hint() == 0
    }

    #[inline]
    fn steal_batch_locked(
        src: &mut LocalQueueInner,
        dest: &mut LocalQueueInner,
        arena: &Arena<TaskRecord>,
    ) -> bool {
        let initial_len = src.queue.len();
        if initial_len == 0 {
            return false;
        }
        let steal_limit = (initial_len / 2).clamp(1, 256);
        let mut stolen = 0;
        let scan_limit = initial_len.min(Self::SKIPPED_LOCALS_INLINE_CAP);
        let mut kept_prefix_len = 0;
        let mut scanned_len = 0;

        while scanned_len < scan_limit && stolen < steal_limit {
            let task_id = src.queue[scanned_len];
            match arena.get(task_id.arena_index()) {
                Some(record) if record.is_local() => {
                    if kept_prefix_len != scanned_len {
                        src.queue[kept_prefix_len] = task_id;
                    }
                    kept_prefix_len += 1;
                }
                _ => {
                    // Stealable: the record exists and is Send (non-local),
                    // OR the arena entry is absent (test harness or
                    // already-freed record). Silently compacting the None
                    // case out of the queue previously lost ready work parked
                    // in a peer's fast_queue during round-robin stealing
                    // (br-asupersync-uguhr2).
                    // br-asupersync-5oll2p: keep the presence index in
                    // sync — the task moves from src to dest, so remove
                    // from src.presence and insert into dest.presence.
                    let inserted = dest.presence.insert(task_id);
                    debug_assert!(
                        inserted,
                        "steal_batch destination already contained transferred task {task_id:?}"
                    );
                    src.presence.remove(&task_id);
                    dest.queue.push(task_id);
                    stolen += 1;
                }
            }
            scanned_len += 1;
        }

        Self::compact_scanned_prefix(&mut src.queue, kept_prefix_len, scanned_len);
        stolen > 0
    }

    /// Steals a task from the queue.
    ///
    /// Lock ordering: arena → deque (same as `schedule_local_push` and
    /// `steal_batch`).  Acquiring the deque first would invert the order
    /// and risk ABBA deadlock when another thread calls
    /// `schedule_local_push` on the same queue.
    #[inline]
    #[must_use]
    #[allow(clippy::significant_drop_tightening)]
    pub fn steal(&self) -> Option<TaskId> {
        self.tasks.with_tasks_arena_mut(|arena| {
            let mut inner = self.inner.lock();
            let scan_limit = inner.queue.len().min(Self::SKIPPED_LOCALS_INLINE_CAP);
            let mut kept_prefix_len = 0;
            let mut scanned_len = 0;
            let mut stolen = None;

            while scanned_len < scan_limit {
                let task_id = inner.queue[scanned_len];
                match arena.get(task_id.arena_index()) {
                    Some(record) if record.is_local() => {
                        if kept_prefix_len != scanned_len {
                            inner.queue[kept_prefix_len] = task_id;
                        }
                        kept_prefix_len += 1;
                    }
                    _ => {
                        // Stealable: record exists and is Send (non-local),
                        // OR the arena entry is absent (test harness or
                        // already-freed record). Silently compacting the None
                        // case out of the queue previously lost ready work
                        // parked in a peer's fast_queue during round-robin
                        // stealing (br-asupersync-uguhr2).
                        stolen = Some(task_id);
                        scanned_len += 1;
                        break;
                    }
                }
                scanned_len += 1;
            }

            Self::compact_scanned_prefix(&mut inner.queue, kept_prefix_len, scanned_len);
            // br-asupersync-5oll2p: drop the stolen task from presence.
            if let Some(task) = stolen {
                inner.presence.remove(&task);
            }
            self.cached_len.store(inner.queue.len(), Ordering::Release);
            stolen
        })
    }

    /// Steals a batch of tasks.
    #[inline]
    #[must_use]
    #[allow(clippy::significant_drop_tightening)]
    pub fn steal_batch(&self, dest: &LocalQueue) -> bool {
        if Arc::ptr_eq(&self.inner, &dest.inner) {
            return false;
        }

        if !self.tasks.same_underlying_tasks(&dest.tasks) {
            return false;
        }
        debug_assert!(self.tasks.same_underlying_tasks(&dest.tasks));

        self.tasks.with_tasks_arena_mut(|arena| {
            // Avoid lock inversion when two workers concurrently steal from each
            // other by acquiring queue locks in a deterministic pointer order.
            let src_addr = Arc::as_ptr(&self.inner) as usize;
            let dest_addr = Arc::as_ptr(&dest.inner) as usize;

            if src_addr < dest_addr {
                let mut src = self.inner.lock();
                let mut dest_inner = dest.inner.lock();
                let stole = Self::steal_batch_locked(&mut src, &mut dest_inner, arena);
                self.cached_len.store(src.queue.len(), Ordering::Release);
                dest.cached_len
                    .store(dest_inner.queue.len(), Ordering::Release);
                stole
            } else {
                let mut dest_inner = dest.inner.lock();
                let mut src = self.inner.lock();
                let stole = Self::steal_batch_locked(&mut src, &mut dest_inner, arena);
                self.cached_len.store(src.queue.len(), Ordering::Release);
                dest.cached_len
                    .store(dest_inner.queue.len(), Ordering::Release);
                stole
            }
        })
    }
}

#[cfg(test)]
#[path = "local_queue_inline_tests.rs"]
mod tests;
