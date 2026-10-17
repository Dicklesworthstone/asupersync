//! Lane-aware global injection queue.
//!
//! Provides a thread-safe injection point for tasks from outside the worker threads.
//! Tasks are routed to the appropriate priority lane: cancel > timed > ready.

use crate::types::{TaskId, Time};
use crate::util::CachePadded;
use parking_lot::Mutex;
use std::cmp::Ordering as CmpOrdering;
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use super::global_queue::{CountReservation, GlobalFifoQueue};

const READY_COMBINER_IN_FLIGHT_THRESHOLD: usize = 4;
const READY_COMBINER_BACKLOG_THRESHOLD: usize = 256;
const READY_COMBINER_MAX_BATCH: usize = 64;
const READY_COMBINER_MAX_PENDING: usize = READY_COMBINER_MAX_BATCH;

/// A scheduled task with its priority metadata.
#[derive(Debug, Clone, Copy)]
pub struct PriorityTask {
    /// The task identifier.
    pub task: TaskId,
    /// Scheduling priority (0-255, higher = more important).
    pub priority: u8,
}

/// Snapshot of the adaptive ready-lane combiner counters.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct ReadyCombinerSnapshot {
    /// Ready injections that stayed on the direct low-contention path.
    pub direct_injections: usize,
    /// Ready injections deposited into the active combiner's pending batch.
    pub deferred_injections: usize,
    /// Ready injections published by the combiner batch path.
    pub combined_injections: usize,
    /// Ready injections that fell back to the direct queue while combining.
    pub fallback_injections: usize,
    /// Failed compare-exchange attempts to become the active combiner.
    pub combiner_claim_failures: usize,
    /// Number of times the ready lane entered combining mode.
    pub mode_entries: usize,
    /// Number of times the ready lane exited combining mode.
    pub mode_exits: usize,
    /// Number of combiner flushes into the ready queue.
    pub flushes: usize,
    /// Largest batch published by one combiner flush.
    pub max_batch: usize,
    /// Highest observed number of concurrent ready injections in flight.
    pub max_in_flight: usize,
    /// Current number of ready injections in flight.
    pub current_in_flight: usize,
    /// Current number of ready tasks waiting in the combiner pending buffer.
    pub pending_len: usize,
    /// Current approximate ready-queue length.
    pub ready_len: usize,
}

#[derive(Debug, Default)]
struct ReadyCombiner {
    active: CachePadded<AtomicBool>,
    in_flight: CachePadded<AtomicUsize>,
    pending: Mutex<Vec<PriorityTask>>,
    direct_injections: CachePadded<AtomicUsize>,
    deferred_injections: CachePadded<AtomicUsize>,
    combined_injections: CachePadded<AtomicUsize>,
    fallback_injections: CachePadded<AtomicUsize>,
    combiner_claim_failures: CachePadded<AtomicUsize>,
    mode_entries: CachePadded<AtomicUsize>,
    mode_exits: CachePadded<AtomicUsize>,
    flushes: CachePadded<AtomicUsize>,
    max_batch: CachePadded<AtomicUsize>,
    max_in_flight: CachePadded<AtomicUsize>,
}

impl ReadyCombiner {
    #[inline]
    fn begin_injection(&self) -> usize {
        let observed = self.in_flight.fetch_add(1, Ordering::AcqRel) + 1;
        self.max_in_flight.fetch_max(observed, Ordering::Relaxed);
        observed
    }

    #[inline]
    fn finish_injection(&self) {
        let _ = self.in_flight.fetch_sub(1, Ordering::AcqRel);
    }

    #[inline]
    fn should_combine(in_flight: usize, ready_backlog: usize) -> bool {
        in_flight >= READY_COMBINER_IN_FLIGHT_THRESHOLD
            || (in_flight > 1 && ready_backlog >= READY_COMBINER_BACKLOG_THRESHOLD)
    }

    #[inline]
    fn snapshot(&self, ready_len: usize) -> ReadyCombinerSnapshot {
        ReadyCombinerSnapshot {
            direct_injections: self.direct_injections.load(Ordering::Relaxed),
            deferred_injections: self.deferred_injections.load(Ordering::Relaxed),
            combined_injections: self.combined_injections.load(Ordering::Relaxed),
            fallback_injections: self.fallback_injections.load(Ordering::Relaxed),
            combiner_claim_failures: self.combiner_claim_failures.load(Ordering::Relaxed),
            mode_entries: self.mode_entries.load(Ordering::Relaxed),
            mode_exits: self.mode_exits.load(Ordering::Relaxed),
            flushes: self.flushes.load(Ordering::Relaxed),
            max_batch: self.max_batch.load(Ordering::Relaxed),
            max_in_flight: self.max_in_flight.load(Ordering::Relaxed),
            current_in_flight: self.in_flight.load(Ordering::Relaxed),
            pending_len: self.pending.lock().len(),
            ready_len,
        }
    }
}

/// A scheduled task with a deadline.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TimedTask {
    /// The task identifier.
    pub task: TaskId,
    /// Absolute deadline for EDF scheduling.
    pub deadline: Time,
    /// Insertion order for FIFO tiebreaking among equal deadlines.
    generation: u64,
}

impl TimedTask {
    /// Creates a new timed task with the given deadline and generation.
    fn new(task: TaskId, deadline: Time, generation: u64) -> Self {
        Self {
            task,
            deadline,
            generation,
        }
    }
}

impl Ord for TimedTask {
    #[inline]
    fn cmp(&self, other: &Self) -> CmpOrdering {
        // Reverse ordering for min-heap (earliest deadline first).
        // For equal deadlines, lower generation (earlier insertion) comes first.
        other
            .deadline
            .cmp(&self.deadline)
            .then_with(|| {
                let diff = other.generation.wrapping_sub(self.generation).cast_signed();
                diff.cmp(&0)
            })
            .then_with(|| other.task.cmp(&self.task))
    }
}

impl PartialOrd for TimedTask {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

/// Lane-aware global injection queue.
///
/// This queue separates tasks by their scheduling lane to maintain strict
/// priority ordering even for cross-thread wakeups:
/// - Cancel lane: Highest priority, always processed first
/// - Timed lane: EDF ordering (earliest deadline first), processed after cancel
/// - Ready lane: Standard priority ordering, processed last
#[derive(Debug)]
pub struct GlobalInjector {
    /// Cancel lane: tasks with pending cancellation (highest priority).
    cancel_queue: GlobalFifoQueue<PriorityTask>,
    /// Timed lane: tasks with deadlines (EDF ordering via min-heap).
    timed_queue: Mutex<TimedQueue>,
    /// Ready lane: general ready tasks.
    ready_queue: GlobalFifoQueue<PriorityTask>,
    /// Contention-gated combiner for ready-lane producer storms.
    ready_combiner: ReadyCombiner,
    /// Approximate count of timed-lane tasks, allowing callers to skip
    /// acquiring the timed_queue mutex when the lane is empty.
    timed_count: CachePadded<AtomicUsize>,
    /// Cached earliest deadline (nanoseconds) for the timed lane.
    ///
    /// Updated under the timed_queue lock on every inject/pop, so it
    /// always reflects the heap's peek at the time of the last mutation.
    /// `u64::MAX` means "no timed work" or "unknown".  Readers outside
    /// the lock may briefly see a stale value, which is harmless:
    /// stale-low → false positive in `has_runnable_work` (worker tries
    /// a pop that finds nothing); stale-high → caught on the next
    /// spin iteration once the store becomes visible.
    cached_earliest_deadline: CachePadded<AtomicU64>,
}

/// Thread-safe EDF queue for timed tasks.
#[derive(Debug, Default)]
struct TimedQueue {
    /// Min-heap ordered by deadline (earliest first).
    heap: BinaryHeap<TimedTask>,
    /// Next generation number for FIFO tiebreaking.
    next_generation: u64,
}

impl Default for GlobalInjector {
    fn default() -> Self {
        Self {
            cancel_queue: GlobalFifoQueue::default(),
            timed_queue: Mutex::new(TimedQueue::default()),
            ready_queue: GlobalFifoQueue::default(),
            ready_combiner: ReadyCombiner::default(),
            timed_count: CachePadded::new(AtomicUsize::new(0)),
            cached_earliest_deadline: CachePadded::new(AtomicU64::new(u64::MAX)),
        }
    }
}

impl GlobalInjector {
    /// Decrements an advisory counter, saturating at zero.
    ///
    /// Uses `try_update` with `checked_sub` so the counter never wraps to
    /// `usize::MAX`, even transiently.  A `fetch_sub` + store-on-underflow
    /// approach would be slightly cheaper in the common case but would expose
    /// a brief window where readers see `usize::MAX`, which confuses `len()`,
    /// `is_empty()`, and `has_timed_work()` callers.
    #[inline]
    fn saturating_decrement(counter: &AtomicUsize) {
        let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            count.checked_sub(1)
        });
    }

    /// Decrements the timed counter, saturating at zero.
    #[inline]
    fn decrement_timed_count(&self) {
        Self::saturating_decrement(&self.timed_count);
    }

    /// Creates a new empty global injector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Injects a task into the cancel lane.
    ///
    /// Cancel lane tasks have the highest priority and will be processed
    /// before any timed or ready work.
    #[inline]
    pub fn inject_cancel(&self, task: TaskId, priority: u8) {
        self.cancel_queue.push(PriorityTask { task, priority });
    }

    /// Injects a task into the timed lane.
    ///
    /// Timed tasks are scheduled by their deadline (earliest deadline first)
    /// and have priority over ready tasks but not cancel tasks.
    #[inline]
    pub fn inject_timed(&self, task: TaskId, deadline: Time) {
        // Increment counters *before* the push so that `timed_count` is always
        // >= the true heap length.  A brief over-count is harmless (pop just
        // finds an empty heap and saturates back to 0).
        self.timed_count.fetch_add(1, Ordering::Relaxed);
        let mut queue = self.timed_queue.lock();
        let generation = queue.next_generation;
        queue.next_generation += 1;
        queue.heap.push(TimedTask::new(task, deadline, generation));
        // Update cached earliest while under lock — no races with pop paths.
        let earliest = queue
            .heap
            .peek()
            .map_or(u64::MAX, |t| t.deadline.as_nanos());
        self.cached_earliest_deadline
            .store(earliest, Ordering::Relaxed);
        drop(queue);
    }

    /// Injects a task into the ready lane.
    ///
    /// Ready tasks have the lowest lane priority. The global ready queue
    /// uses FIFO ordering for lock-free throughput; per-task priority
    /// ordering is applied by the local `PriorityScheduler` after stealing.
    #[inline]
    pub fn inject_ready(&self, task: TaskId, priority: u8) {
        let entry = PriorityTask { task, priority };
        let in_flight = self.ready_combiner.begin_injection();
        let ready_backlog = self.ready_queue.len();

        if ReadyCombiner::should_combine(in_flight, ready_backlog) {
            self.inject_ready_contentious(entry);
        } else {
            self.ready_queue.push(entry);
            self.ready_combiner
                .direct_injections
                .fetch_add(1, Ordering::Relaxed);
        }

        self.ready_combiner.finish_injection();
    }

    fn inject_ready_contentious(&self, entry: PriorityTask) {
        if self
            .ready_combiner
            .active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.ready_combiner
                .mode_entries
                .fetch_add(1, Ordering::Relaxed);
            self.flush_ready_combiner_with(entry);
            return;
        }

        self.ready_combiner
            .combiner_claim_failures
            .fetch_add(1, Ordering::Relaxed);

        if let Some(mut pending) = self.ready_combiner.pending.try_lock() {
            // The owner releases active while holding this same lock. An
            // accepted entry therefore belongs to its bounded final flush,
            // or to a successor that has already claimed the empty buffer.
            if self.ready_combiner.active.load(Ordering::Acquire)
                && pending.len() < READY_COMBINER_MAX_PENDING
            {
                pending.push(entry);
                self.ready_combiner
                    .deferred_injections
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        self.ready_queue.push(entry);
        self.ready_combiner
            .fallback_injections
            .fetch_add(1, Ordering::Relaxed);
    }

    fn flush_ready_combiner_with(&self, first: PriorityTask) {
        let mut batch = Vec::with_capacity(READY_COMBINER_MAX_BATCH);
        batch.push(first);

        {
            let mut pending = self.ready_combiner.pending.lock();
            let take = (READY_COMBINER_MAX_BATCH - 1).min(pending.len());
            batch.extend(pending.drain(..take));
        }
        self.publish_ready_batch(&mut batch);

        // Continuous arrivals must not keep the injecting worker or reactor
        // inside wake() forever. Take the entire bounded remainder and end
        // this tenure before publishing it. Later arrivals either belong to
        // a successor or publish directly; no entry needs a future injection
        // to make progress. Each tenure publishes at most two 64-entry batches.
        {
            let mut pending = self.ready_combiner.pending.lock();
            batch.append(&mut pending);
            self.ready_combiner.active.store(false, Ordering::Release);
            self.ready_combiner
                .mode_exits
                .fetch_add(1, Ordering::Relaxed);
        }
        self.publish_ready_batch(&mut batch);
    }

    fn publish_ready_batch(&self, batch: &mut Vec<PriorityTask>) {
        let count = batch.len();
        if count == 0 {
            return;
        }

        self.ready_combiner
            .max_batch
            .fetch_max(count, Ordering::Relaxed);
        self.ready_combiner.flushes.fetch_add(1, Ordering::Relaxed);
        self.ready_combiner
            .combined_injections
            .fetch_add(count, Ordering::Relaxed);

        let mut reservation = self.ready_queue.reserve_count(count);
        #[cfg(test)]
        let mut observed = false;
        for entry in batch.drain(..) {
            self.ready_queue.push_uncounted(entry);
            reservation.publish_one();
            #[cfg(test)]
            if !observed {
                observed = true;
                tests::observe_ready_combiner_publication(self);
            }
        }
    }

    /// Injects a ready task without incrementing the atomic counter.
    /// Must be paired with a subsequent call to `add_ready_count`.
    #[inline]
    pub(crate) fn inject_ready_uncounted(&self, task: TaskId, priority: u8) {
        self.ready_queue
            .push_uncounted(PriorityTask { task, priority });
    }

    #[inline]
    pub(crate) fn reserve_ready_count(&self, count: usize) -> CountReservation<'_, PriorityTask> {
        self.ready_queue.reserve_count(count)
    }

    /// Pops a task from the cancel lane.
    ///
    /// Returns `None` if the cancel lane is empty.
    #[inline]
    #[must_use]
    pub fn pop_cancel(&self) -> Option<PriorityTask> {
        self.cancel_queue.pop()
    }

    /// Pops a task from the timed lane (earliest deadline first).
    ///
    /// Returns `None` if the timed lane is empty.
    /// The caller should check if the deadline is due before executing.
    #[inline]
    #[must_use]
    pub fn pop_timed(&self) -> Option<TimedTask> {
        if self.timed_count.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let mut queue = self.timed_queue.lock();
        let result = queue.heap.pop();
        let earliest = queue
            .heap
            .peek()
            .map_or(u64::MAX, |t| t.deadline.as_nanos());
        self.cached_earliest_deadline
            .store(earliest, Ordering::Relaxed);
        drop(queue);
        if result.is_some() {
            self.decrement_timed_count();
        }
        result
    }

    /// Peeks at the earliest deadline in the timed lane without removing it.
    ///
    /// Returns `None` if the timed lane is empty.
    #[inline]
    #[must_use]
    pub fn peek_earliest_deadline(&self) -> Option<Time> {
        if self.timed_count.load(Ordering::Relaxed) == 0 {
            return None;
        }
        // Use the cached earliest deadline to avoid acquiring the mutex.
        // The cache is updated under lock on every inject/pop.
        let cached = self.cached_earliest_deadline.load(Ordering::Relaxed);
        if cached == u64::MAX {
            None
        } else {
            Some(Time::from_nanos(cached))
        }
    }

    /// Pops the earliest timed task only if its deadline is due.
    ///
    /// Returns `None` if the timed lane is empty or if the earliest
    /// deadline is still in the future.
    #[inline]
    #[must_use]
    pub fn pop_timed_if_due(&self, now: Time) -> Option<TimedTask> {
        if self.timed_count.load(Ordering::Relaxed) == 0 {
            return None;
        }
        // Fast path: skip the mutex when the cached earliest deadline is
        // still in the future.  The cache is updated under lock on every
        // inject/pop, so the only inaccuracy is a brief Relaxed-ordering
        // visibility lag — same as the timed_count check above.
        let cached = self.cached_earliest_deadline.load(Ordering::Relaxed);
        if cached != u64::MAX && Time::from_nanos(cached) > now {
            return None;
        }
        let mut queue = self.timed_queue.lock();
        if let Some(entry) = queue.heap.peek() {
            if entry.deadline <= now {
                let result = queue.heap.pop();
                let earliest = queue
                    .heap
                    .peek()
                    .map_or(u64::MAX, |t| t.deadline.as_nanos());
                self.cached_earliest_deadline
                    .store(earliest, Ordering::Relaxed);
                drop(queue);
                if result.is_some() {
                    self.decrement_timed_count();
                }
                return result;
            }
        }
        None
    }

    /// Removes every pending entry for `task` from the timed lane.
    ///
    /// Returns `true` if at least one entry was removed. Used when a task is
    /// promoted from timed to a runnable lane: a stale timed entry left behind
    /// would be a duplicate-dispatch hazard because the global timed heap,
    /// unlike the per-worker [`crate::runtime::scheduler::PriorityScheduler`],
    /// has no `scheduled`-set tombstoning to lazily skip it on pop. The heap has no
    /// key-based removal, so a matching removal filters and rebuilds it.
    pub fn remove_timed(&self, task: TaskId) -> bool {
        if self.timed_count.load(Ordering::Relaxed) == 0 {
            return false;
        }
        let mut queue = self.timed_queue.lock();
        let original_len = queue.heap.len();
        if original_len == 0 || !queue.heap.iter().any(|entry| entry.task == task) {
            return false;
        }
        let retained: BinaryHeap<TimedTask> =
            queue.heap.drain().filter(|t| t.task != task).collect();
        let removed = original_len - retained.len();
        queue.heap = retained;
        let earliest = queue
            .heap
            .peek()
            .map_or(u64::MAX, |t| t.deadline.as_nanos());
        self.cached_earliest_deadline
            .store(earliest, Ordering::Relaxed);
        drop(queue);
        for _ in 0..removed {
            self.decrement_timed_count();
        }
        removed > 0
    }

    /// Pops a task from the ready lane.
    ///
    /// Returns `None` if the ready lane is empty.
    #[inline]
    #[must_use]
    pub fn pop_ready(&self) -> Option<PriorityTask> {
        self.ready_queue.pop()
    }

    /// Pops up to `max` ready tasks in FIFO order into `out`.
    ///
    /// Returns the number of tasks appended to `out`.
    #[inline]
    pub(crate) fn pop_ready_batch_into(&self, max: usize, out: &mut Vec<PriorityTask>) -> usize {
        self.ready_queue.pop_batch_into(max, out)
    }

    /// Returns true if all lanes are empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cancel_queue.is_empty()
            && self.timed_count.load(Ordering::Relaxed) == 0
            && self.ready_queue.is_empty()
    }

    /// Returns true if there is work that can be executed immediately.
    ///
    /// Uses the cached earliest deadline to avoid acquiring the timed_queue
    /// mutex on the hot path.  The cache is updated under lock by every
    /// inject/pop, so the only inaccuracy is a brief Relaxed-ordering
    /// visibility lag (nanoseconds on x86, bounded spin iterations on ARM).
    #[inline]
    #[must_use]
    pub fn has_runnable_work(&self, now: Time) -> bool {
        if !self.cancel_queue.is_empty() || !self.ready_queue.is_empty() {
            return true;
        }
        if self.timed_count.load(Ordering::Relaxed) == 0 {
            return false;
        }
        let earliest = self.cached_earliest_deadline.load(Ordering::Relaxed);
        earliest != u64::MAX && Time::from_nanos(earliest) <= now
    }

    /// Returns the approximate number of pending tasks across all lanes.
    ///
    /// Derived from per-lane counters; avoids a dedicated atomic counter
    /// on every inject/pop.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.cancel_queue.len() + self.timed_count.load(Ordering::Relaxed) + self.ready_queue.len()
    }

    /// Returns true if the cancel lane has pending work.
    #[inline]
    #[must_use]
    pub fn has_cancel_work(&self) -> bool {
        !self.cancel_queue.is_empty()
    }

    /// Returns the approximate number of tasks in the cancel lane.
    #[inline]
    #[must_use]
    pub fn cancel_count(&self) -> usize {
        self.cancel_queue.len()
    }

    /// Returns true if the timed lane has pending work.
    #[inline]
    #[must_use]
    pub fn has_timed_work(&self) -> bool {
        self.timed_count.load(Ordering::Relaxed) > 0
    }

    /// Returns true if the ready lane has pending work.
    #[inline]
    #[must_use]
    pub fn has_ready_work(&self) -> bool {
        !self.ready_queue.is_empty()
    }

    /// Returns the approximate number of tasks in the ready lane.
    #[inline]
    #[must_use]
    pub fn ready_count(&self) -> usize {
        self.ready_queue.len()
    }

    /// Returns a point-in-time snapshot of adaptive ready-lane combiner metrics.
    #[inline]
    #[must_use]
    pub fn ready_combiner_snapshot(&self) -> ReadyCombinerSnapshot {
        self.ready_combiner.snapshot(self.ready_queue.len())
    }

    /// Seeds ready-combiner contention counters for deterministic test harnesses.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-internals"))]
    pub fn seed_ready_combiner_pressure_for_test(
        &self,
        max_in_flight: usize,
        combiner_claim_failures: usize,
    ) {
        self.ready_combiner.active.store(false, Ordering::Release);
        self.ready_combiner.in_flight.store(0, Ordering::Release);
        self.ready_combiner
            .max_in_flight
            .store(max_in_flight, Ordering::Relaxed);
        self.ready_combiner
            .combiner_claim_failures
            .store(combiner_claim_failures, Ordering::Relaxed);
    }
}

#[cfg(test)]
#[path = "global_injector_inline_tests.rs"]
mod tests;
