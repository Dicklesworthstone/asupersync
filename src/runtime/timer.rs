//! Timer heap for deadline management.
//!
//! This module provides a small min-heap of `(deadline, task)` pairs to support
//! deadline-driven wakeups.
//!
//! # Per-task cancel + dedup (br-asupersync-40mcc2)
//!
//! The heap supports per-task cancellation and reschedule-dedup via a
//! lazy-deletion scheme backed by a per-task generation map:
//!
//! * Each `(task, deadline)` heap entry carries the generation number
//!   that was assigned to the task when the entry was pushed.
//! * `current_gen[task]` records the most-recently-issued generation
//!   for that task.
//! * On `pop_expired_into`, an entry is **live** iff its generation
//!   matches `current_gen[entry.task]`. Stale entries (entries whose
//!   `task` was rescheduled or cancelled after the entry was pushed)
//!   are silently skipped.
//! * On `cancel(task)`, we bump `current_gen[task]` so all in-flight
//!   heap entries for that task become stale immediately. The entries
//!   themselves stay in the heap until naturally popped, but they
//!   never fire a wakeup.
//! * On `insert(task, deadline)` we ALSO bump `current_gen[task]` —
//!   meaning any prior entry for the task is implicitly cancelled by
//!   the reschedule. This is the dedup behaviour: only the
//!   most-recently-inserted entry for a task is live.
//!
//! Pre-fix the heap had no per-task index at all — a task that
//! rescheduled N times before its deadline accumulated N entries; on
//! cancel, the entry stayed live until its deadline arrived and then
//! fired a spurious wake on the (now-zombie) task. After-fix memory
//! is bounded by `live_timers + zombie_entries_pending_pop`; the
//! zombie count is bounded by the heap's pop rate × max-deadline.

use crate::types::{TaskId, Time};
use crate::util::DetHashMap;
use std::cmp::Ordering;
use std::collections::BinaryHeap;

#[derive(Debug, Clone, Eq, PartialEq)]
struct TimerEntry {
    deadline: Time,
    task: TaskId,
    generation: u64,
}

impl Ord for TimerEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap (earliest deadline first).
        other
            .deadline
            .cmp(&self.deadline)
            // Lower generation (earlier insertion) wins for equal deadlines.
            .then_with(|| {
                let diff = other.generation.wrapping_sub(self.generation).cast_signed();
                diff.cmp(&0)
            })
            // Fallback to task ID to satisfy Ord/Eq agreement contract
            .then_with(|| other.task.cmp(&self.task))
    }
}

impl PartialOrd for TimerEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A min-heap of timers ordered by deadline.
#[derive(Debug, Default)]
pub struct TimerHeap {
    heap: BinaryHeap<TimerEntry>,
    next_generation: u64,
    /// Most-recently-issued generation per task. An entry in the heap
    /// is "live" iff its `generation` field equals the value here.
    /// Tasks not present in this map have no live timer.
    /// br-asupersync-40mcc2.
    current_gen: DetHashMap<TaskId, u64>,
}

impl TimerHeap {
    /// Creates a new empty timer heap.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of timers in the heap.
    ///
    /// **Note**: this reflects the underlying storage, including
    /// stale-but-not-yet-popped entries. For the count of LIVE timers
    /// (entries that will actually fire a wakeup), use
    /// [`live_len`](Self::live_len).
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Returns the number of LIVE timers — entries whose generation
    /// still matches `current_gen[task]`. A live timer will fire a
    /// wakeup when its deadline elapses; a stale timer will be
    /// silently dropped on pop.
    ///
    /// br-asupersync-40mcc2: this is O(N) over the heap because
    /// BinaryHeap doesn't expose internal traversal cheaply. Use
    /// it for diagnostics, not the hot path.
    #[must_use]
    pub fn live_len(&self) -> usize {
        self.heap
            .iter()
            .filter(|e| self.current_gen.get(&e.task) == Some(&e.generation))
            .count()
    }

    /// Returns true if the heap is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Adds a timer for a task with the given deadline.
    ///
    /// br-asupersync-40mcc2: bumps the per-task generation so any
    /// PRIOR entry for this task in the heap becomes stale and will
    /// be silently dropped on the next pop. Only the most-recently-
    /// inserted entry for a given task is live.
    #[inline]
    pub fn insert(&mut self, task: TaskId, deadline: Time) {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        // Bump current_gen[task] so any prior entry is implicitly
        // cancelled by this reschedule.
        self.current_gen.insert(task, generation);
        self.heap.push(TimerEntry {
            deadline,
            task,
            generation,
        });
    }

    /// Cancel any pending timer for `task`.
    ///
    /// br-asupersync-40mcc2 + br-asupersync-cvn2se/j5srno: bumps the
    /// per-task generation so all in-flight heap entries for this
    /// task become stale, AND physically reaps those stale entries
    /// from the heap. Returns `true` if a timer was active.
    ///
    /// Pre-fix the heap was left to lazy deletion — stale entries
    /// only released their slot when their deadline arrived and
    /// `pop_expired_into` popped them. For long-deadline timers on
    /// short-lived tasks (the bead's concrete scenario: task T sets
    /// `deadline=tomorrow`, runtime processes millions of such
    /// task-lifecycles) the heap accumulated stale entries
    /// proportional to total cancel volume. Eager reap turns the
    /// memory cost into O(N) at cancel-time (where N is the heap
    /// size, capped by the number of distinct LIVE timers); cancel
    /// is rare relative to the per-poll heap-touch frequency, so the
    /// amortised cost is favourable.
    ///
    /// `BinaryHeap` does not support O(log n) remove-by-key, so the
    /// reap is implemented as a predicate retain pass that filters
    /// out entries for the cancelled task and restores heap order.
    pub fn cancel(&mut self, task: TaskId) -> bool {
        if self.current_gen.remove(&task).is_none() {
            return false;
        }
        // br-asupersync-cvn2se/j5srno — eagerly reap the stale heap
        // entries for this task. Without this, a long-deadline timer
        // on a short-lived task left a stale entry sitting in the
        // heap until the deadline arrived; in a long-running runtime
        // this accumulated proportional to cancel volume.
        self.heap.retain(|e| e.task != task);
        true
    }

    /// Returns the earliest deadline, if any. May reflect a stale
    /// (cancelled or rescheduled) entry — use [`Self::pop_expired_into`]
    /// to drain stale-and-expired entries.
    #[inline]
    #[must_use]
    pub fn peek_deadline(&self) -> Option<Time> {
        self.heap.peek().map(|e| e.deadline)
    }

    /// Pops all tasks whose deadline is `<= now` into a caller-supplied buffer.
    ///
    /// The buffer is cleared before use. Using a reusable buffer avoids a heap
    /// allocation on every tick when no timers have expired.
    ///
    /// br-asupersync-40mcc2: stale entries (those whose generation no
    /// longer matches `current_gen[task]`) are silently skipped — they
    /// represent cancelled or rescheduled timers and must NOT fire a
    /// wakeup. Pre-fix the heap had no per-task index, so cancelled
    /// tasks fired spurious wakes that polluted scheduler stats and
    /// wasted reactor dispatch cycles.
    pub fn pop_expired_into(&mut self, now: Time, expired: &mut Vec<TaskId>) {
        expired.clear();
        while let Some(entry) = self.heap.peek() {
            if entry.deadline > now {
                break;
            }
            // Pop the head; check liveness AFTER popping so we don't
            // leave a stale-but-expired entry blocking a live entry
            // behind it.
            let entry = match self.heap.pop() {
                Some(e) => e,
                None => break,
            };
            let is_live = self
                .current_gen
                .get(&entry.task)
                .is_some_and(|g| *g == entry.generation);
            if is_live {
                // Fired — remove the per-task tracking so a later
                // insert() starts fresh.
                self.current_gen.remove(&entry.task);
                expired.push(entry.task);
            }
            // If !is_live, silently drop the stale entry and continue.
        }
    }

    /// Pops all tasks whose deadline is `<= now`.
    ///
    /// Convenience wrapper that allocates a new Vec. Prefer
    /// [`pop_expired_into`](Self::pop_expired_into) on hot paths.
    pub fn pop_expired(&mut self, now: Time) -> Vec<TaskId> {
        let mut expired = Vec::with_capacity(4);
        self.pop_expired_into(now, &mut expired);
        expired
    }

    /// Clears all timers.
    pub fn clear(&mut self) {
        self.heap.clear();
        self.current_gen.clear();
    }
}

#[cfg(test)]
#[path = "timer_inline_tests.rs"]
mod tests;
