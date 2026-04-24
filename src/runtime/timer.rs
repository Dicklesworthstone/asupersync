//! Timer heap for deadline management.
//!
//! This module provides a small min-heap of `(deadline, task)` pairs to support
//! deadline-driven wakeups.

use crate::types::{TaskId, Time};
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
}

impl TimerHeap {
    /// Creates a new empty timer heap.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of timers in the heap.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Returns true if the heap is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Adds a timer for a task with the given deadline.
    #[inline]
    pub fn insert(&mut self, task: TaskId, deadline: Time) {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        self.heap.push(TimerEntry {
            deadline,
            task,
            generation,
        });
    }

    /// Returns the earliest deadline, if any.
    #[inline]
    #[must_use]
    pub fn peek_deadline(&self) -> Option<Time> {
        self.heap.peek().map(|e| e.deadline)
    }

    /// Pops all tasks whose deadline is `<= now` into a caller-supplied buffer.
    ///
    /// The buffer is cleared before use. Using a reusable buffer avoids a heap
    /// allocation on every tick when no timers have expired.
    pub fn pop_expired_into(&mut self, now: Time, expired: &mut Vec<TaskId>) {
        expired.clear();
        while let Some(entry) = self.heap.peek() {
            if entry.deadline <= now {
                if let Some(entry) = self.heap.pop() {
                    expired.push(entry.task);
                } else {
                    break;
                }
            } else {
                break;
            }
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
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
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
}
