    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::record::task::TaskRecord;
    use crate::types::{Budget, RegionId};
    use crate::util::ArenaIndex;

    fn region() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(0, 1))
    }

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn setup_arena(count: u32) -> Arena<TaskRecord> {
        let mut arena = Arena::new();
        for i in 0..count {
            let id = task(i);
            let record = TaskRecord::new(id, region(), Budget::INFINITE);
            let idx = arena.insert(record);
            assert_eq!(idx.index(), i);
        }
        arena
    }

    fn pop_all_ring(ring: &mut IntrusiveRing, arena: &mut Arena<TaskRecord>) -> Vec<TaskId> {
        let mut popped = Vec::new();
        while let Some(task_id) = ring.pop_front(arena) {
            popped.push(task_id);
        }
        popped
    }

    fn pop_all_ring_round_robin(
        ring: &mut IntrusiveRing,
        arena: &mut Arena<TaskRecord>,
        worker_count: usize,
    ) -> Vec<Vec<TaskId>> {
        assert!(worker_count > 0);

        let mut drained_by_worker = vec![Vec::new(); worker_count];
        let mut next_worker = 0usize;

        while let Some(task_id) = ring.pop_front(arena) {
            drained_by_worker[next_worker].push(task_id);
            next_worker = (next_worker + 1) % worker_count;
        }

        drained_by_worker
    }

    fn round_robin_dispatch_order(drained_by_worker: &[Vec<TaskId>]) -> Vec<TaskId> {
        let max_depth = drained_by_worker
            .iter()
            .map(std::vec::Vec::len)
            .max()
            .unwrap_or(0);
        let total_len = drained_by_worker
            .iter()
            .map(std::vec::Vec::len)
            .sum::<usize>();
        let mut ordered = Vec::with_capacity(total_len);

        for depth in 0..max_depth {
            for worker_drained in drained_by_worker {
                if let Some(task_id) = worker_drained.get(depth) {
                    ordered.push(*task_id);
                }
            }
        }

        ordered
    }

    fn pop_all_stack(stack: &mut IntrusiveStack, arena: &mut Arena<TaskRecord>) -> Vec<TaskId> {
        let mut popped = Vec::new();
        while let Some(task_id) = stack.pop(arena) {
            popped.push(task_id);
        }
        popped
    }

    #[test]
    fn empty_queue() {
        let ring = IntrusiveRing::new(QUEUE_TAG_READY);
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);
        assert!(ring.peek_front().is_none());
    }

    #[test]
    fn default_ring_uses_ready_tag() {
        let mut arena = setup_arena(1);
        let mut ring = IntrusiveRing::default();
        assert_eq!(ring.tag(), QUEUE_TAG_READY);

        ring.push_back(task(0), &mut arena);
        assert_eq!(ring.pop_front(&mut arena), Some(task(0)));
        assert!(ring.is_empty());
    }

    #[test]
    #[should_panic(expected = "queue tag 0 is reserved")]
    fn ring_rejects_zero_tag() {
        let _ring = IntrusiveRing::new(0);
    }

    #[test]
    #[should_panic(expected = "queue tag 0 is reserved")]
    fn stack_rejects_zero_tag() {
        let _stack = IntrusiveStack::new(0);
    }

    #[test]
    fn push_pop_single() {
        let mut arena = setup_arena(1);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        ring.push_back(task(0), &mut arena);
        assert_eq!(ring.len(), 1);
        assert!(!ring.is_empty());
        assert_eq!(ring.peek_front(), Some(task(0)));

        let popped = ring.pop_front(&mut arena);
        assert_eq!(popped, Some(task(0)));
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);

        // Verify task links are cleared
        let record = arena.get(task(0).arena_index()).unwrap();
        assert!(!record.is_in_queue());
    }

    #[test]
    fn fifo_ordering() {
        let mut arena = setup_arena(5);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        // Push 0, 1, 2, 3, 4
        for i in 0..5 {
            ring.push_back(task(i), &mut arena);
        }
        assert_eq!(ring.len(), 5);

        // Pop should return 0, 1, 2, 3, 4 (FIFO)
        for i in 0..5 {
            let popped = ring.pop_front(&mut arena);
            assert_eq!(popped, Some(task(i)), "expected task {i}");
        }
        assert!(ring.is_empty());
    }

    #[test]
    fn remove_from_middle() {
        let mut arena = setup_arena(5);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        for i in 0..5 {
            ring.push_back(task(i), &mut arena);
        }

        // Remove task 2 from the middle
        let removed = ring.remove(task(2), &mut arena);
        assert!(removed);
        assert_eq!(ring.len(), 4);

        // Verify task 2's links are cleared
        let record = arena.get(task(2).arena_index()).unwrap();
        assert!(!record.is_in_queue());

        // Pop remaining: 0, 1, 3, 4
        assert_eq!(ring.pop_front(&mut arena), Some(task(0)));
        assert_eq!(ring.pop_front(&mut arena), Some(task(1)));
        assert_eq!(ring.pop_front(&mut arena), Some(task(3)));
        assert_eq!(ring.pop_front(&mut arena), Some(task(4)));
        assert!(ring.is_empty());
    }

    #[test]
    fn remove_head() {
        let mut arena = setup_arena(3);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        for i in 0..3 {
            ring.push_back(task(i), &mut arena);
        }

        // Remove head (task 0)
        let removed = ring.remove(task(0), &mut arena);
        assert!(removed);
        assert_eq!(ring.len(), 2);

        // Pop remaining: 1, 2
        assert_eq!(ring.pop_front(&mut arena), Some(task(1)));
        assert_eq!(ring.pop_front(&mut arena), Some(task(2)));
    }

    #[test]
    fn remove_tail() {
        let mut arena = setup_arena(3);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        for i in 0..3 {
            ring.push_back(task(i), &mut arena);
        }

        // Remove tail (task 2)
        let removed = ring.remove(task(2), &mut arena);
        assert!(removed);
        assert_eq!(ring.len(), 2);

        // Pop remaining: 0, 1
        assert_eq!(ring.pop_front(&mut arena), Some(task(0)));
        assert_eq!(ring.pop_front(&mut arena), Some(task(1)));
    }

    #[test]
    fn remove_only_element() {
        let mut arena = setup_arena(1);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        ring.push_back(task(0), &mut arena);
        let removed = ring.remove(task(0), &mut arena);

        assert!(removed);
        assert!(ring.is_empty());
        assert!(ring.head.is_none());
        assert!(ring.tail.is_none());
    }

    #[test]
    fn remove_not_in_queue() {
        let mut arena = setup_arena(2);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        ring.push_back(task(0), &mut arena);

        // Try to remove task 1 which is not in the queue
        let removed = ring.remove(task(1), &mut arena);
        assert!(!removed);
        assert_eq!(ring.len(), 1);
    }

    #[test]
    fn contains() {
        let mut arena = setup_arena(3);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        ring.push_back(task(0), &mut arena);
        ring.push_back(task(1), &mut arena);

        assert!(ring.contains(task(0), &arena));
        assert!(ring.contains(task(1), &arena));
        assert!(!ring.contains(task(2), &arena));

        let _ = ring.pop_front(&mut arena);
        assert!(!ring.contains(task(0), &arena));
        assert!(ring.contains(task(1), &arena));
    }

    #[test]
    fn clear() {
        let mut arena = setup_arena(5);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        for i in 0..5 {
            ring.push_back(task(i), &mut arena);
        }

        ring.clear(&mut arena);
        assert!(ring.is_empty());

        // Verify all tasks have cleared links
        for i in 0..5 {
            let record = arena.get(task(i).arena_index()).unwrap();
            assert!(!record.is_in_queue());
        }
    }

    #[test]
    fn different_queue_tags() {
        let mut arena = setup_arena(4);
        let mut ready_ring = IntrusiveRing::new(QUEUE_TAG_READY);
        let mut cancel_ring = IntrusiveRing::new(QUEUE_TAG_CANCEL);

        // Put tasks 0,1 in ready queue and tasks 2,3 in cancel queue
        ready_ring.push_back(task(0), &mut arena);
        ready_ring.push_back(task(1), &mut arena);
        cancel_ring.push_back(task(2), &mut arena);
        cancel_ring.push_back(task(3), &mut arena);

        // Verify containment
        assert!(ready_ring.contains(task(0), &arena));
        assert!(ready_ring.contains(task(1), &arena));
        assert!(!ready_ring.contains(task(2), &arena));
        assert!(!ready_ring.contains(task(3), &arena));

        assert!(!cancel_ring.contains(task(0), &arena));
        assert!(!cancel_ring.contains(task(1), &arena));
        assert!(cancel_ring.contains(task(2), &arena));
        assert!(cancel_ring.contains(task(3), &arena));

        // Cannot remove task from wrong queue
        assert!(!ready_ring.remove(task(2), &mut arena));
        assert!(!cancel_ring.remove(task(0), &mut arena));

        // Can remove from correct queue
        assert!(ready_ring.remove(task(0), &mut arena));
        assert!(cancel_ring.remove(task(2), &mut arena));
    }

    /// Regression for asupersync-0tv9bv item 7.
    #[test]
    fn same_tag_rings_keep_membership_and_removal_isolated() {
        let mut arena = setup_arena(6);
        let mut left = IntrusiveRing::new(QUEUE_TAG_READY);
        let mut right = IntrusiveRing::new(QUEUE_TAG_READY);
        let mut empty = IntrusiveRing::new(QUEUE_TAG_READY);

        for i in 0..3 {
            left.push_back(task(i), &mut arena);
        }
        for i in 3..6 {
            right.push_back(task(i), &mut arena);
        }

        assert!(!empty.remove(task(4), &mut arena));
        assert_eq!(empty.len(), 0);
        assert!(!empty.contains(task(4), &arena));

        assert!(left.contains(task(1), &arena));
        assert!(!left.contains(task(4), &arena));
        assert!(right.contains(task(4), &arena));
        assert!(!right.contains(task(1), &arena));

        assert!(!left.remove(task(4), &mut arena));
        assert!(!right.remove(task(1), &mut arena));
        assert_eq!(left.len(), 3);
        assert_eq!(right.len(), 3);
        assert_eq!(
            pop_all_ring(&mut left, &mut arena),
            vec![task(0), task(1), task(2)]
        );
        assert_eq!(
            pop_all_ring(&mut right, &mut arena),
            vec![task(3), task(4), task(5)]
        );
    }

    #[test]
    fn interleaved_push_pop() {
        let mut arena = setup_arena(10);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        ring.push_back(task(0), &mut arena);
        ring.push_back(task(1), &mut arena);
        assert_eq!(ring.pop_front(&mut arena), Some(task(0)));

        ring.push_back(task(2), &mut arena);
        assert_eq!(ring.pop_front(&mut arena), Some(task(1)));
        assert_eq!(ring.pop_front(&mut arena), Some(task(2)));

        ring.push_back(task(3), &mut arena);
        ring.push_back(task(4), &mut arena);
        ring.push_back(task(5), &mut arena);

        assert_eq!(ring.len(), 3);
        assert_eq!(ring.pop_front(&mut arena), Some(task(3)));
        assert_eq!(ring.pop_front(&mut arena), Some(task(4)));
        assert_eq!(ring.pop_front(&mut arena), Some(task(5)));
        assert!(ring.is_empty());
    }

    #[test]
    fn high_volume() {
        let count = 1000u32;
        let mut arena = setup_arena(count);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        for i in 0..count {
            ring.push_back(task(i), &mut arena);
        }
        assert_eq!(ring.len(), count as usize);

        for i in 0..count {
            let popped = ring.pop_front(&mut arena);
            assert_eq!(popped, Some(task(i)));
        }
        assert!(ring.is_empty());
    }

    #[test]
    fn reuse_after_pop() {
        let mut arena = setup_arena(2);
        let mut ring = IntrusiveRing::new(QUEUE_TAG_READY);

        // Push and pop task 0
        ring.push_back(task(0), &mut arena);
        assert_eq!(ring.pop_front(&mut arena), Some(task(0)));

        // Re-enqueue task 0
        ring.push_back(task(0), &mut arena);
        ring.push_back(task(1), &mut arena);

        // Should get task 0 first (FIFO)
        assert_eq!(ring.pop_front(&mut arena), Some(task(0)));
        assert_eq!(ring.pop_front(&mut arena), Some(task(1)));
    }

    #[test]
    fn metamorphic_ring_remove_matches_fifo_filter() {
        let mut baseline_arena = setup_arena(8);
        let mut filtered_arena = setup_arena(8);
        let mut baseline = IntrusiveRing::new(QUEUE_TAG_READY);
        let mut filtered = IntrusiveRing::new(QUEUE_TAG_READY);
        let removed = [task(1), task(4), task(6)];

        for i in 0..8 {
            baseline.push_back(task(i), &mut baseline_arena);
            filtered.push_back(task(i), &mut filtered_arena);
        }

        for task_id in removed {
            assert!(filtered.remove(task_id, &mut filtered_arena));
        }

        let expected: Vec<_> = pop_all_ring(&mut baseline, &mut baseline_arena)
            .into_iter()
            .filter(|task_id| !removed.contains(task_id))
            .collect();
        let actual = pop_all_ring(&mut filtered, &mut filtered_arena);

        assert_eq!(actual, expected);
        for task_id in removed {
            let record = filtered_arena
                .get(task_id.arena_index())
                .expect("removed task missing");
            assert!(!record.is_in_queue());
        }
    }

    #[test]
    fn metamorphic_round_robin_ring_drain_preserves_fifo_and_cardinality() {
        let task_count = 12u32;
        let worker_count = 4usize;
        let mut baseline_arena = setup_arena(task_count);
        let mut distributed_arena = setup_arena(task_count);
        let mut baseline = IntrusiveRing::new(QUEUE_TAG_READY);
        let mut distributed = IntrusiveRing::new(QUEUE_TAG_READY);

        for i in 0..task_count {
            baseline.push_back(task(i), &mut baseline_arena);
            distributed.push_back(task(i), &mut distributed_arena);
        }

        let expected = pop_all_ring(&mut baseline, &mut baseline_arena);
        let drained_by_worker =
            pop_all_ring_round_robin(&mut distributed, &mut distributed_arena, worker_count);
        let actual = round_robin_dispatch_order(&drained_by_worker);

        assert_eq!(actual, expected);
        assert_eq!(actual.len(), task_count as usize);

        let mut drain_counts = vec![0usize; task_count as usize];
        for task_id in &actual {
            let task_index =
                usize::try_from(task_id.arena_index().index()).expect("task index fits usize");
            drain_counts[task_index] += 1;
        }
        assert!(
            drain_counts.iter().all(|count| *count == 1),
            "expected every injected task to drain exactly once"
        );

        for (worker_index, worker_drained) in drained_by_worker.iter().enumerate() {
            let expected_worker: Vec<_> = expected
                .iter()
                .copied()
                .skip(worker_index)
                .step_by(worker_count)
                .collect();
            assert_eq!(*worker_drained, expected_worker);
        }

        assert!(distributed.is_empty());
        for i in 0..task_count {
            let record = distributed_arena
                .get(task(i).arena_index())
                .expect("drained task missing");
            assert!(!record.is_in_queue());
        }
    }

    // ── IntrusiveStack tests ─────────────────────────────────────────────

    #[test]
    fn stack_empty() {
        let stack = IntrusiveStack::new(QUEUE_TAG_READY);
        assert!(stack.is_empty());
        assert_eq!(stack.len(), 0);
    }

    #[test]
    fn stack_push_pop_single() {
        let mut arena = setup_arena(1);
        let mut stack = IntrusiveStack::new(QUEUE_TAG_READY);

        stack.push(task(0), &mut arena);
        assert_eq!(stack.len(), 1);
        assert!(!stack.is_empty());

        let popped = stack.pop(&mut arena);
        assert_eq!(popped, Some(task(0)));
        assert!(stack.is_empty());
    }

    #[test]
    fn stack_tracks_local_task_presence() {
        let mut arena = setup_arena(2);
        let mut stack = IntrusiveStack::new(QUEUE_TAG_READY);

        arena
            .get_mut(task(0).arena_index())
            .expect("task record missing")
            .mark_local();

        assert!(!stack.has_local_tasks());
        stack.push(task(0), &mut arena);
        stack.push(task(1), &mut arena);
        assert!(stack.has_local_tasks());

        let (stolen_id, is_local) = stack
            .steal_one_with_locality(&mut arena)
            .expect("oldest task missing");
        assert_eq!(stolen_id, task(0));
        assert!(is_local);
        assert!(!stack.has_local_tasks());

        assert_eq!(stack.pop(&mut arena), Some(task(1)));
        assert!(!stack.has_local_tasks());
    }

    #[test]
    fn stack_lifo_ordering() {
        let mut arena = setup_arena(5);
        let mut stack = IntrusiveStack::new(QUEUE_TAG_READY);

        // Push 0, 1, 2, 3, 4
        for i in 0..5 {
            stack.push(task(i), &mut arena);
        }
        assert_eq!(stack.len(), 5);

        // Pop should return 4, 3, 2, 1, 0 (LIFO)
        for i in (0..5).rev() {
            let popped = stack.pop(&mut arena);
            assert_eq!(popped, Some(task(i)), "expected task {i}");
        }
        assert!(stack.is_empty());
    }

    #[test]
    fn stack_push_bottom_restores_owner_visible_order() {
        let mut arena = setup_arena(3);
        let mut stack = IntrusiveStack::new(QUEUE_TAG_READY);

        stack.push(task(0), &mut arena);
        stack.push(task(1), &mut arena);
        stack.push(task(2), &mut arena);

        // Temporarily remove oldest, then restore at bottom.
        let oldest = stack.steal_one(&mut arena).expect("oldest task missing");
        assert_eq!(oldest, task(0));
        stack.push_bottom(oldest, &mut arena);

        // Owner-observed order should remain unchanged.
        assert_eq!(stack.pop(&mut arena), Some(task(2)));
        assert_eq!(stack.pop(&mut arena), Some(task(1)));
        assert_eq!(stack.pop(&mut arena), Some(task(0)));
        assert_eq!(stack.pop(&mut arena), None);
    }

    #[test]
    fn stack_steal_fifo() {
        let mut arena = setup_arena(8);
        let mut stack = IntrusiveStack::new(QUEUE_TAG_READY);

        // Push 0, 1, 2, 3, 4, 5, 6, 7
        for i in 0..8 {
            stack.push(task(i), &mut arena);
        }

        // Steal should return oldest first (FIFO for stealing)
        let mut stolen = Vec::new();
        stack.steal_batch(4, &mut arena, &mut stolen);
        assert_eq!(stolen.len(), 4);
        // Should have stolen 0, 1, 2, 3 (the oldest)
        for (i, task_id) in stolen.into_iter().enumerate() {
            assert_eq!(task_id, task(i as u32), "stolen task {i}");
        }

        // Remaining should be 7, 6, 5, 4 (LIFO order)
        assert_eq!(stack.len(), 4);
        assert_eq!(stack.pop(&mut arena), Some(task(7)));
        assert_eq!(stack.pop(&mut arena), Some(task(6)));
        assert_eq!(stack.pop(&mut arena), Some(task(5)));
        assert_eq!(stack.pop(&mut arena), Some(task(4)));
    }

    #[test]
    fn stack_steal_batch_into_non_local_preserves_ordering() {
        let mut arena = setup_arena(8);
        let mut src = IntrusiveStack::new(QUEUE_TAG_READY);
        let mut dest = IntrusiveStack::new(QUEUE_TAG_CANCEL);

        for i in 0..8 {
            src.push(task(i), &mut arena);
        }

        let stolen = src.steal_batch_into_non_local(4, &mut arena, &mut dest);
        assert_eq!(stolen, 4);
        assert!(!src.has_local_tasks());
        assert!(!dest.has_local_tasks());

        // Destination receives oldest tasks (0..3), but push-to-top means
        // owner pop order is reverse in destination.
        assert_eq!(dest.pop(&mut arena), Some(task(3)));
        assert_eq!(dest.pop(&mut arena), Some(task(2)));
        assert_eq!(dest.pop(&mut arena), Some(task(1)));
        assert_eq!(dest.pop(&mut arena), Some(task(0)));
        assert_eq!(dest.pop(&mut arena), None);

        // Source retains newest half.
        assert_eq!(src.pop(&mut arena), Some(task(7)));
        assert_eq!(src.pop(&mut arena), Some(task(6)));
        assert_eq!(src.pop(&mut arena), Some(task(5)));
        assert_eq!(src.pop(&mut arena), Some(task(4)));
        assert_eq!(src.pop(&mut arena), None);
    }

    #[test]
    fn stack_steal_batch_into_same_tag_splices_above_existing_destination() {
        let mut arena = setup_arena(8);
        let mut src = IntrusiveStack::new(QUEUE_TAG_READY);
        let mut dest = IntrusiveStack::new(QUEUE_TAG_READY);

        for i in 0..6 {
            src.push(task(i), &mut arena);
        }
        dest.push(task(6), &mut arena);
        dest.push(task(7), &mut arena);

        let stolen = src.steal_batch_into_non_local(3, &mut arena, &mut dest);
        assert_eq!(stolen, 3);
        assert!(!src.has_local_tasks());
        assert!(!dest.has_local_tasks());

        // Stolen oldest source tasks (0..2) sit above the existing destination
        // stack while preserving thief-visible LIFO order.
        assert_eq!(dest.pop(&mut arena), Some(task(2)));
        assert_eq!(dest.pop(&mut arena), Some(task(1)));
        assert_eq!(dest.pop(&mut arena), Some(task(0)));
        assert_eq!(dest.pop(&mut arena), Some(task(7)));
        assert_eq!(dest.pop(&mut arena), Some(task(6)));
        assert_eq!(dest.pop(&mut arena), None);

        // Source retains the newest half.
        assert_eq!(src.pop(&mut arena), Some(task(5)));
        assert_eq!(src.pop(&mut arena), Some(task(4)));
        assert_eq!(src.pop(&mut arena), Some(task(3)));
        assert_eq!(src.pop(&mut arena), None);
    }

    #[test]
    fn stack_work_stealing_semantics() {
        // Simulates owner pushing and popping while thief steals
        let mut arena = setup_arena(10);
        let mut stack = IntrusiveStack::new(QUEUE_TAG_READY);

        // Owner pushes 0, 1, 2, 3, 4, 5
        for i in 0..6 {
            stack.push(task(i), &mut arena);
        }

        // Owner pops most recent (5)
        assert_eq!(stack.pop(&mut arena), Some(task(5)));

        // Stack now has [0, 1, 2, 3, 4] with len=5
        // Thief steals oldest - steal_batch takes at most half the queue
        // (5/2).max(1).min(2) = 2, so 2 tasks stolen
        let mut stolen = Vec::new();
        stack.steal_batch(2, &mut arena, &mut stolen);
        assert_eq!(stolen.len(), 2);
        assert_eq!(stolen[0], task(0)); // Oldest is stolen first
        assert_eq!(stolen[1], task(1));

        // Stack now has [2, 3, 4] with len=3
        // Owner pushes 6
        stack.push(task(6), &mut arena);

        // Stack is [2, 3, 4, 6] - owner pops LIFO (6, 4, 3, 2)
        assert_eq!(stack.pop(&mut arena), Some(task(6)));
        assert_eq!(stack.pop(&mut arena), Some(task(4)));
        assert_eq!(stack.pop(&mut arena), Some(task(3)));
        assert_eq!(stack.pop(&mut arena), Some(task(2)));
        assert!(stack.is_empty());
    }

    #[test]
    fn metamorphic_batch_steal_matches_repeated_single_steals() {
        let mut batch_arena = setup_arena(8);
        let mut single_arena = setup_arena(8);
        let mut batch_stack = IntrusiveStack::new(QUEUE_TAG_READY);
        let mut single_stack = IntrusiveStack::new(QUEUE_TAG_READY);

        for i in 0..8 {
            batch_stack.push(task(i), &mut batch_arena);
            single_stack.push(task(i), &mut single_arena);
        }

        let mut batch_stolen = Vec::new();
        batch_stack.steal_batch(4, &mut batch_arena, &mut batch_stolen);

        let mut single_stolen = Vec::new();
        while single_stolen.len() < batch_stolen.len() {
            single_stolen.push(
                single_stack
                    .steal_one(&mut single_arena)
                    .expect("single steal should match batch partition"),
            );
        }

        assert_eq!(single_stolen, batch_stolen);
        assert_eq!(
            pop_all_stack(&mut single_stack, &mut single_arena),
            pop_all_stack(&mut batch_stack, &mut batch_arena)
        );
    }

    #[test]
    fn metamorphic_restoring_stolen_suffix_reconstructs_owner_order() {
        let mut baseline_arena = setup_arena(6);
        let mut restored_arena = setup_arena(6);
        let mut baseline = IntrusiveStack::new(QUEUE_TAG_READY);
        let mut restored = IntrusiveStack::new(QUEUE_TAG_READY);

        for i in 0..6 {
            baseline.push(task(i), &mut baseline_arena);
            restored.push(task(i), &mut restored_arena);
        }

        let expected = pop_all_stack(&mut baseline, &mut baseline_arena);

        let mut stolen = Vec::new();
        restored.steal_batch(3, &mut restored_arena, &mut stolen);
        for task_id in stolen.into_iter().rev() {
            restored.push_bottom(task_id, &mut restored_arena);
        }

        assert_eq!(pop_all_stack(&mut restored, &mut restored_arena), expected);
        assert!(!restored.has_local_tasks());
    }

    #[test]
    fn stack_steal_from_small() {
        let mut arena = setup_arena(2);
        let mut stack = IntrusiveStack::new(QUEUE_TAG_READY);

        stack.push(task(0), &mut arena);

        // Steal from single-element stack
        let mut stolen = Vec::new();
        stack.steal_batch(4, &mut arena, &mut stolen);
        assert_eq!(stolen.len(), 1);
        assert_eq!(stolen[0], task(0));
        assert!(stack.is_empty());
    }

    #[test]
    fn stack_steal_from_empty() {
        let mut arena = setup_arena(0);
        let mut stack = IntrusiveStack::new(QUEUE_TAG_READY);

        let mut stolen = Vec::new();
        stack.steal_batch(4, &mut arena, &mut stolen);
        assert!(stolen.is_empty());
    }

    #[test]
    fn stack_contains() {
        let mut arena = setup_arena(3);
        let mut stack = IntrusiveStack::new(QUEUE_TAG_READY);

        stack.push(task(0), &mut arena);
        stack.push(task(1), &mut arena);

        assert!(stack.contains(task(0), &arena));
        assert!(stack.contains(task(1), &arena));
        assert!(!stack.contains(task(2), &arena));

        let _ = stack.pop(&mut arena); // Remove task 1
        assert!(stack.contains(task(0), &arena));
        assert!(!stack.contains(task(1), &arena));
    }

    #[test]
    fn stack_steal_one_assume_non_local_rejects_local_when_counter_stale() {
        let mut arena = setup_arena(1);
        let mut stack = IntrusiveStack::new(QUEUE_TAG_READY);

        arena
            .get_mut(task(0).arena_index())
            .expect("task record missing")
            .mark_local();
        stack.push(task(0), &mut arena);
        assert!(stack.has_local_tasks());

        // Simulate stale bookkeeping (e.g., contract violation elsewhere).
        stack.local_count = 0;
        assert!(!stack.has_local_tasks());

        // Fast-path non-local steal must refuse to steal local tasks.
        let stolen = stack.steal_one_assume_non_local(&mut arena);
        assert!(stolen.is_none());
        assert!(stack.has_local_tasks(), "local_count should self-heal");
        assert_eq!(stack.len(), 1);
        assert_eq!(stack.pop(&mut arena), Some(task(0)));
    }

    #[test]
    fn stack_steal_batch_into_non_local_rejects_local_when_counter_stale() {
        let mut arena = setup_arena(3);
        let mut src = IntrusiveStack::new(QUEUE_TAG_READY);
        let mut dest = IntrusiveStack::new(QUEUE_TAG_CANCEL);

        arena
            .get_mut(task(0).arena_index())
            .expect("task record missing")
            .mark_local();

        // Keep local task at bottom (oldest).
        src.push(task(0), &mut arena);
        src.push(task(1), &mut arena);
        src.push(task(2), &mut arena);
        assert!(src.has_local_tasks());

        // Simulate stale bookkeeping.
        src.local_count = 0;
        assert!(!src.has_local_tasks());

        let stolen = src.steal_batch_into_non_local(3, &mut arena, &mut dest);
        assert_eq!(stolen, 0, "must not steal local task via fast path");
        assert!(src.has_local_tasks(), "local_count should self-heal");
        assert_eq!(dest.len(), 0, "destination remains untouched");

        // Source order remains intact for owner pop.
        assert_eq!(src.pop(&mut arena), Some(task(2)));
        assert_eq!(src.pop(&mut arena), Some(task(1)));
        assert_eq!(src.pop(&mut arena), Some(task(0)));
        assert_eq!(src.pop(&mut arena), None);
    }
