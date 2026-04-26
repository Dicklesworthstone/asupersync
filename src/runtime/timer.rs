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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::test_utils::init_test_logging;
    use crate::util::ArenaIndex;
    use proptest::prelude::*;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    #[test]
    fn empty_heap_has_no_deadline() {
        init_test("empty_heap_has_no_deadline");
        let heap = TimerHeap::new();
        crate::assert_with_log!(heap.is_empty(), "heap starts empty", true, heap.is_empty());
        crate::assert_with_log!(
            heap.peek_deadline().is_none(),
            "empty heap has no deadline",
            None::<Time>,
            heap.peek_deadline()
        );
        crate::test_complete!("empty_heap_has_no_deadline");
    }

    #[test]
    fn insert_orders_by_deadline() {
        init_test("insert_orders_by_deadline");
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(200));
        heap.insert(task(2), Time::from_millis(100));
        heap.insert(task(3), Time::from_millis(150));

        crate::assert_with_log!(
            heap.peek_deadline() == Some(Time::from_millis(100)),
            "earliest deadline is kept at top",
            Some(Time::from_millis(100)),
            heap.peek_deadline()
        );
        crate::test_complete!("insert_orders_by_deadline");
    }

    #[test]
    fn pop_expired_returns_all_due_tasks() {
        init_test("pop_expired_returns_all_due_tasks");
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(100));
        heap.insert(task(2), Time::from_millis(200));
        heap.insert(task(3), Time::from_millis(50));

        crate::test_section!("pop");
        let expired = heap.pop_expired(Time::from_millis(125));
        crate::assert_with_log!(
            expired.len() == 2,
            "two tasks expired",
            2usize,
            expired.len()
        );
        crate::assert_with_log!(
            expired.contains(&task(1)),
            "expired contains task 1",
            true,
            expired.contains(&task(1))
        );
        crate::assert_with_log!(
            expired.contains(&task(3)),
            "expired contains task 3",
            true,
            expired.contains(&task(3))
        );
        crate::assert_with_log!(
            heap.peek_deadline() == Some(Time::from_millis(200)),
            "remaining deadline is 200ms",
            Some(Time::from_millis(200)),
            heap.peek_deadline()
        );
        crate::test_complete!("pop_expired_returns_all_due_tasks");
    }

    #[test]
    fn same_deadline_pops_in_insertion_order() {
        init_test("same_deadline_pops_in_insertion_order");
        let mut heap = TimerHeap::new();
        let deadline = Time::from_millis(100);

        heap.insert(task(1), deadline);
        heap.insert(task(2), deadline);
        heap.insert(task(3), deadline);

        let expired = heap.pop_expired(deadline);
        crate::assert_with_log!(
            expired == vec![task(1), task(2), task(3)],
            "same-deadline timers pop deterministically by insertion order",
            vec![task(1), task(2), task(3)],
            expired
        );
        crate::test_complete!("same_deadline_pops_in_insertion_order");
    }

    /// Invariant: clear empties the heap.
    #[test]
    fn clear_empties_heap() {
        init_test("clear_empties_heap");
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(100));
        heap.insert(task(2), Time::from_millis(200));
        crate::assert_with_log!(heap.len() == 2, "len before clear", 2, heap.len());

        heap.clear();
        crate::assert_with_log!(heap.is_empty(), "empty after clear", true, heap.is_empty());
        crate::assert_with_log!(
            heap.is_empty(),
            "heap empty after clear",
            true,
            heap.is_empty()
        );
        let none = heap.peek_deadline().is_none();
        crate::assert_with_log!(none, "no deadline after clear", true, none);
        crate::test_complete!("clear_empties_heap");
    }

    /// Invariant: pop_expired with no expired items returns empty vec.
    #[test]
    fn pop_expired_none_expired() {
        init_test("pop_expired_none_expired");
        let mut heap = TimerHeap::new();
        heap.insert(task(1), Time::from_millis(500));

        let expired = heap.pop_expired(Time::from_millis(100));
        crate::assert_with_log!(expired.is_empty(), "no expired", true, expired.is_empty());
        crate::assert_with_log!(heap.len() == 1, "heap unchanged", 1, heap.len());
        crate::test_complete!("pop_expired_none_expired");
    }

    #[test]
    fn pop_expired_includes_exact_deadline() {
        init_test("pop_expired_includes_exact_deadline");
        let mut heap = TimerHeap::new();
        let deadline = Time::from_millis(250);
        heap.insert(task(7), deadline);

        let expired = heap.pop_expired(deadline);
        crate::assert_with_log!(
            expired == vec![task(7)],
            "task at exact deadline must be treated as expired",
            vec![task(7)],
            expired
        );
        crate::assert_with_log!(
            heap.is_empty(),
            "heap drained after pop",
            true,
            heap.is_empty()
        );
        crate::test_complete!("pop_expired_includes_exact_deadline");
    }

    // =========================================================================
    // Wave 43 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn timer_heap_debug_default() {
        let heap = TimerHeap::default();
        let dbg = format!("{heap:?}");
        assert!(dbg.contains("TimerHeap"), "{dbg}");
        assert!(heap.is_empty());
        assert_eq!(heap.len(), 0);

        let heap2 = TimerHeap::new();
        assert_eq!(format!("{heap2:?}"), dbg);
    }

    #[test]
    fn generation_counter_wraps_without_panicking() {
        init_test("generation_counter_wraps_without_panicking");
        let mut heap = TimerHeap::new();
        heap.next_generation = u64::MAX;

        let deadline = Time::from_millis(10);
        heap.insert(task(1), deadline);
        heap.insert(task(2), deadline);

        let expired = heap.pop_expired(deadline);
        crate::assert_with_log!(
            expired.len() == 2,
            "both wrapped-generation entries are retained and popped",
            2usize,
            expired.len()
        );
        crate::assert_with_log!(
            expired.contains(&task(1)) && expired.contains(&task(2)),
            "wrapped-generation entries are recoverable",
            true,
            expired.contains(&task(1)) && expired.contains(&task(2))
        );
        crate::test_complete!("generation_counter_wraps_without_panicking");
    }

    proptest! {
        #[test]
        fn metamorphic_split_pop_matches_direct_later_frontier(
            deadlines in prop::collection::vec(0u16..512u16, 1..24),
            split_ms in 0u16..512u16,
        ) {
            let mut split_heap = TimerHeap::new();
            let mut direct_heap = TimerHeap::new();

            for (index, deadline_ms) in deadlines.iter().copied().enumerate() {
                let task = task(index as u32 + 1);
                let deadline = Time::from_millis(u64::from(deadline_ms));
                split_heap.insert(task, deadline);
                direct_heap.insert(task, deadline);
            }

            let late_ms = deadlines.iter().copied().max().unwrap_or(0);
            let early_ms = split_ms.min(late_ms);

            let mut split_result = split_heap.pop_expired(Time::from_millis(u64::from(early_ms)));
            split_result.extend(split_heap.pop_expired(Time::from_millis(u64::from(late_ms))));

            let direct_result = direct_heap.pop_expired(Time::from_millis(u64::from(late_ms)));

            prop_assert_eq!(
                split_result,
                direct_result,
                "splitting timer expiration at an earlier frontier must preserve final wake ordering",
            );
            prop_assert!(
                split_heap.is_empty() && direct_heap.is_empty(),
                "both heaps should be drained after popping at the latest inserted deadline",
            );
        }

        #[test]
        fn metamorphic_uniform_deadline_shift_preserves_wake_order(
            deadlines in prop::collection::vec(0u16..512u16, 1..24),
            shift_ms in 0u16..2048u16,
        ) {
            let mut base_heap = TimerHeap::new();
            let mut shifted_heap = TimerHeap::new();
            let mut expected = Vec::with_capacity(deadlines.len());

            for (index, deadline_ms) in deadlines.iter().copied().enumerate() {
                let task = task(index as u32 + 1);
                let deadline = Time::from_millis(u64::from(deadline_ms));
                let shifted_deadline =
                    Time::from_millis(u64::from(deadline_ms) + u64::from(shift_ms));
                base_heap.insert(task, deadline);
                shifted_heap.insert(task, shifted_deadline);
                expected.push((deadline_ms, index, task));
            }

            expected.sort_by_key(|(deadline_ms, index, _)| (*deadline_ms, *index));
            let expected_order = expected
                .into_iter()
                .map(|(_, _, task)| task)
                .collect::<Vec<_>>();

            let latest_ms = deadlines.iter().copied().max().unwrap_or(0);
            let base_result = base_heap.pop_expired(Time::from_millis(u64::from(latest_ms)));
            let shifted_result = shifted_heap.pop_expired(Time::from_millis(
                u64::from(latest_ms) + u64::from(shift_ms),
            ));

            prop_assert_eq!(
                base_result.as_slice(),
                expected_order.as_slice(),
                "wake ordering must follow increasing deadlines and insertion order for ties",
            );
            prop_assert_eq!(
                shifted_result.as_slice(),
                base_result.as_slice(),
                "uniformly shifting every deadline must preserve final wake ordering",
            );
            prop_assert!(
                base_heap.is_empty() && shifted_heap.is_empty(),
                "both heaps should be drained after popping at their latest respective frontier",
            );
        }

        #[test]
        fn metamorphic_parent_deadline_cascade_rearming_siblings_preserves_wake_order(
            parent_ms in 0u16..256u16,
            early_sibling_deltas in prop::collection::vec(0u8..32u8, 0..8),
            future_sibling_offsets in prop::collection::vec(1u8..32u8, 0..8),
            child_offsets in prop::collection::vec(1u8..32u8, 1..8),
        ) {
            let parent_deadline = Time::from_millis(u64::from(parent_ms));
            let mut direct_heap = TimerHeap::new();
            let mut cascade_heap = TimerHeap::new();
            let parent = task(1);
            let mut sibling_deadlines = Vec::with_capacity(
                early_sibling_deltas.len() + future_sibling_offsets.len(),
            );
            let mut future_siblings = Vec::with_capacity(future_sibling_offsets.len());
            let mut next_task = 2u32;

            cascade_heap.insert(parent, parent_deadline);

            for delta in early_sibling_deltas {
                let sibling = task(next_task);
                next_task += 1;
                let deadline_ms = parent_ms.saturating_sub(u16::from(delta));
                let deadline = Time::from_millis(u64::from(deadline_ms));
                direct_heap.insert(sibling, deadline);
                cascade_heap.insert(sibling, deadline);
                sibling_deadlines.push(deadline);
            }

            for offset in future_sibling_offsets {
                let sibling = task(next_task);
                next_task += 1;
                let deadline_ms = parent_ms + u16::from(offset);
                let deadline = Time::from_millis(u64::from(deadline_ms));
                direct_heap.insert(sibling, deadline);
                cascade_heap.insert(sibling, deadline);
                sibling_deadlines.push(deadline);
                future_siblings.push((sibling, deadline));
            }

            for offset in child_offsets {
                let child = task(next_task);
                next_task += 1;
                let deadline = Time::from_millis(u64::from(parent_ms + u16::from(offset)));
                cascade_heap.insert(child, deadline);
            }

            let mut cascade_result = cascade_heap
                .pop_expired(parent_deadline)
                .into_iter()
                .filter(|task| *task != parent)
                .collect::<Vec<_>>();

            cascade_heap.clear();
            for (sibling, deadline) in future_siblings.iter().copied() {
                cascade_heap.insert(sibling, deadline);
            }

            let latest_sibling_deadline =
                sibling_deadlines.iter().copied().max().unwrap_or(parent_deadline);
            cascade_result.extend(cascade_heap.pop_expired(latest_sibling_deadline));

            let direct_result = direct_heap.pop_expired(latest_sibling_deadline);

            prop_assert_eq!(
                cascade_result,
                direct_result,
                "cancelling a parent deadline cascade and re-arming only surviving siblings must preserve sibling wake ordering",
            );
            prop_assert!(
                cascade_heap.is_empty() && direct_heap.is_empty(),
                "both heaps should be drained after replaying sibling deadlines to their shared latest frontier",
            );
        }

        #[test]
        fn metamorphic_late_deadline_cancellation_noise_preserves_earlier_wake_order(
            base_deadlines in prop::collection::vec(0u16..512u16, 1..24),
            late_offsets in prop::collection::vec(1u16..128u16, 1..16),
        ) {
            let mut direct_heap = TimerHeap::new();
            let mut noisy_heap = TimerHeap::new();

            for (index, deadline_ms) in base_deadlines.iter().copied().enumerate() {
                let task = task(index as u32 + 1);
                let deadline = Time::from_millis(u64::from(deadline_ms));
                direct_heap.insert(task, deadline);
                noisy_heap.insert(task, deadline);
            }

            let frontier_ms = base_deadlines.iter().copied().max().unwrap_or(0);
            let frontier = Time::from_millis(u64::from(frontier_ms));

            for (next_task, offset) in (base_deadlines.len() as u32 + 1..).zip(late_offsets.into_iter()) {
                let task = task(next_task);
                let deadline = Time::from_millis(u64::from(frontier_ms) + u64::from(offset));
                noisy_heap.insert(task, deadline);
            }

            let direct_result = direct_heap.pop_expired(frontier);
            let noisy_result = noisy_heap.pop_expired(frontier);

            prop_assert_eq!(
                noisy_result,
                direct_result,
                "late deadlines that are later cancelled must not perturb the earlier wake frontier",
            );
            prop_assert!(
                direct_heap.is_empty(),
                "the direct heap should drain at the latest base deadline frontier",
            );
            prop_assert!(
                noisy_heap
                    .peek_deadline()
                    .is_none_or(|deadline| deadline > frontier),
                "late-only noise should remain strictly after the earlier frontier",
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // br-asupersync-40mcc2 — per-task cancel + reschedule dedup
    // ─────────────────────────────────────────────────────────────────

    /// Reschedule MUST dedup the prior entry. Pre-fix every insert
    /// added a new heap entry without invalidating the previous one;
    /// long-lived tasks accumulated O(reschedules) entries. Post-fix
    /// the per-task generation is bumped on insert, so only the
    /// most-recently-inserted entry is live.
    #[test]
    fn reschedule_dedups_prior_entry() {
        let mut heap = TimerHeap::new();
        let t = task(1);

        // Insert N times with monotonically increasing deadlines.
        // Pre-fix this would fire N wakeups; post-fix only the latest.
        heap.insert(t, Time::from_millis(10));
        heap.insert(t, Time::from_millis(20));
        heap.insert(t, Time::from_millis(30));

        // live_len reports just 1 — the latest insert won.
        assert_eq!(
            heap.live_len(),
            1,
            "reschedule must dedup: only the latest entry is live (got {} live, raw heap size {})",
            heap.live_len(),
            heap.len()
        );

        // Drain past the latest deadline. Should fire exactly ONCE.
        let fired = heap.pop_expired(Time::from_millis(100));
        assert_eq!(
            fired,
            vec![t],
            "reschedule must fire wakeup exactly once (the latest)"
        );

        // Heap is now empty (live entry popped, stale entries silently
        // dropped during the same drain).
        assert!(heap.is_empty(), "drain leaves heap empty");
    }

    /// Cancel makes all prior entries for the task stale; subsequent
    /// pop_expired_into must NOT include the task. Pre-fix the
    /// heap had no cancel API and entries fired spurious wakes on
    /// dropped/cancelled tasks.
    #[test]
    fn cancel_drops_pending_wakeup() {
        let mut heap = TimerHeap::new();
        let t = task(1);

        heap.insert(t, Time::from_millis(10));
        assert_eq!(heap.live_len(), 1);

        let did_cancel = heap.cancel(t);
        assert!(did_cancel, "cancel of an active timer returns true");
        assert_eq!(
            heap.live_len(),
            0,
            "cancel makes the entry stale — live_len drops to 0"
        );

        // The stale entry is still in the underlying heap (lazy
        // deletion) but pop_expired_into MUST NOT include it.
        let fired = heap.pop_expired(Time::from_millis(100));
        assert!(
            fired.is_empty(),
            "cancelled task must NOT fire a wakeup; got {fired:?}"
        );
        assert!(heap.is_empty(), "stale entry drained during pop");

        // Cancel of an already-cancelled (or never-set) timer returns
        // false — gives callers an idempotent path without panic.
        let did_recancel = heap.cancel(t);
        assert!(!did_recancel, "second cancel of same task returns false");
    }

    /// Cancel + immediate reschedule must establish the new timer
    /// cleanly — the new insert wins, and ONLY it fires.
    #[test]
    fn cancel_then_insert_establishes_new_timer_cleanly() {
        let mut heap = TimerHeap::new();
        let t = task(1);

        heap.insert(t, Time::from_millis(10));
        assert!(heap.cancel(t));
        heap.insert(t, Time::from_millis(50));

        let fired_at_20 = heap.pop_expired(Time::from_millis(20));
        assert!(
            fired_at_20.is_empty(),
            "rescheduled timer at t=50 must NOT fire at t=20"
        );

        let fired_at_100 = heap.pop_expired(Time::from_millis(100));
        assert_eq!(
            fired_at_100,
            vec![t],
            "rescheduled timer fires at the new (later) deadline"
        );
    }

    /// Memory-bound regression: N reschedules of the SAME task should
    /// leave at most N raw heap entries pre-pop, and exactly 0 after
    /// a drain past the latest deadline. live_len stays at 1 across
    /// the reschedule sequence (only the latest is live).
    #[test]
    fn reschedule_storm_memory_bounded_by_drain() {
        let mut heap = TimerHeap::new();
        let t = task(1);

        const N: u64 = 1000;
        for i in 1..=N {
            heap.insert(t, Time::from_millis(i * 10));
        }

        // Raw heap size is N (lazy deletion); live_len is 1.
        assert_eq!(heap.len(), N as usize);
        assert_eq!(
            heap.live_len(),
            1,
            "across N reschedules, only the latest entry is live"
        );

        // Drain past the latest deadline.
        let fired = heap.pop_expired(Time::from_millis(N * 10 + 1000));
        assert_eq!(
            fired,
            vec![t],
            "reschedule storm fires the task exactly ONCE (the latest)"
        );
        assert!(
            heap.is_empty(),
            "drain past the latest deadline reclaims all stale entries"
        );
    }

    /// Multiple tasks rescheduling independently: each task fires
    /// only at its OWN latest deadline; cancellations of one task
    /// don't affect others.
    #[test]
    fn multiple_tasks_independent_dedup_and_cancel() {
        let mut heap = TimerHeap::new();
        let t1 = task(1);
        let t2 = task(2);
        let t3 = task(3);

        // t1 reschedules; t2 cancels; t3 single insert.
        heap.insert(t1, Time::from_millis(10));
        heap.insert(t1, Time::from_millis(20));
        heap.insert(t2, Time::from_millis(15));
        heap.cancel(t2);
        heap.insert(t3, Time::from_millis(25));

        assert_eq!(
            heap.live_len(),
            2,
            "t1 latest + t3 = 2 live; t1 stale + t2 cancelled = 0 extra"
        );

        let mut fired = heap.pop_expired(Time::from_millis(100));
        fired.sort();
        let expected = vec![t1, t3];
        assert_eq!(
            fired, expected,
            "t1 fires once at its latest, t3 fires once, t2 silenced by cancel"
        );
        assert!(heap.is_empty());
    }

    /// br-asupersync-cvn2se/j5srno — Conformance: cancel BEFORE the
    /// timer fires must release BOTH the per-task generation entry
    /// AND any heap entries for the task. Pre-fix the heap entry
    /// was left to lazy deletion — for long-deadline timers on
    /// short-lived tasks, the stale entry sat until the deadline
    /// arrived. Across millions of cancel-without-fire cycles the
    /// heap accumulated proportional to total cancel volume.
    #[test]
    fn cancel_before_fire_releases_both_current_gen_and_heap_entry() {
        let mut heap = TimerHeap::new();
        let t = task(7);

        heap.insert(t, Time::from_millis(86_400_000)); // 1 day in the future
        assert_eq!(heap.live_len(), 1);
        assert_eq!(heap.len(), 1, "one heap entry post-insert");

        let did_cancel = heap.cancel(t);
        assert!(did_cancel);

        // Post-fix: cancel reaps the heap entry. live_len AND raw
        // heap size both drop to 0 — no lazy deletion residue.
        assert_eq!(heap.live_len(), 0);
        assert_eq!(
            heap.len(),
            0,
            "br-asupersync-cvn2se/j5srno: heap entry reaped on cancel (no lazy-deletion leak)"
        );
        assert!(heap.is_empty());
    }

    /// br-asupersync-cvn2se/j5srno — Conformance: many distinct
    /// tasks each insert + cancel without firing. Heap size after
    /// every (insert, cancel) cycle stays at 0 — proving no leak
    /// even across high cancel volume.
    #[test]
    fn many_cancel_without_fire_does_not_leak() {
        let mut heap = TimerHeap::new();
        const N: u32 = 1024;
        for i in 0..N {
            let t = task(i + 1);
            heap.insert(t, Time::from_millis(86_400_000 + u64::from(i)));
            assert!(heap.cancel(t));
            assert_eq!(
                heap.len(),
                0,
                "br-asupersync-cvn2se/j5srno: heap must not retain cancelled-before-fire entries (i={i})"
            );
        }
    }

    /// br-asupersync-cvn2se/j5srno — Regression guard: cancel of
    /// task A must NOT touch heap entries for other tasks.
    #[test]
    fn cancel_does_not_disturb_other_tasks_heap_entries() {
        let mut heap = TimerHeap::new();
        let a = task(1);
        let b = task(2);
        let c = task(3);

        heap.insert(a, Time::from_millis(100));
        heap.insert(b, Time::from_millis(200));
        heap.insert(c, Time::from_millis(300));
        assert_eq!(heap.len(), 3);

        assert!(heap.cancel(b));
        assert_eq!(heap.len(), 2, "cancel reaps only b's entry; a and c remain");

        let mut fired = heap.pop_expired(Time::from_millis(1000));
        fired.sort();
        assert_eq!(
            fired,
            vec![a, c],
            "a and c fire normally; b is gone (cancelled before fire)"
        );
        assert!(heap.is_empty());
    }
}
