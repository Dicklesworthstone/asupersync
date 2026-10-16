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

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn drain_with_lane_if_due(sched: &mut Scheduler, now: Time) -> Vec<(TaskId, DispatchLane)> {
        let mut trace = Vec::new();
        while let Some((task, lane)) = sched.pop_with_lane_if_due(0, now) {
            trace.push((task, lane));
        }
        trace
    }

    #[test]
    fn cancel_lane_has_priority() {
        init_test("cancel_lane_has_priority");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 100);
        sched.schedule_cancel(task(2), 50);

        // Cancel lane should come first despite lower priority
        let first = sched.pop();
        let second = sched.pop();
        crate::assert_with_log!(
            first == Some(task(2)),
            "cancel lane pops first",
            Some(task(2)),
            first
        );
        crate::assert_with_log!(
            second == Some(task(1)),
            "ready lane pops second",
            Some(task(1)),
            second
        );
        crate::test_complete!("cancel_lane_has_priority");
    }

    #[test]
    fn dedup_prevents_double_schedule() {
        init_test("dedup_prevents_double_schedule");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 100);
        sched.schedule(task(1), 100);

        crate::assert_with_log!(
            sched.len() == 1,
            "duplicate schedule is deduped",
            1usize,
            sched.len()
        );
        crate::test_complete!("dedup_prevents_double_schedule");
    }

    #[test]
    fn move_to_cancel_lane_from_ready() {
        init_test("move_to_cancel_lane_from_ready");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule(task(2), 100);

        // Move task 2 to cancel lane
        sched.move_to_cancel_lane(task(2), 100);

        // Task 2 should come first now (cancel lane priority)
        let first = sched.pop();
        let second = sched.pop();
        crate::assert_with_log!(
            first == Some(task(2)),
            "moved task pops first",
            Some(task(2)),
            first
        );
        crate::assert_with_log!(
            second == Some(task(1)),
            "remaining ready task pops next",
            Some(task(1)),
            second
        );
        crate::test_complete!("move_to_cancel_lane_from_ready");
    }

    #[test]
    fn move_to_cancel_lane_from_timed() {
        init_test("move_to_cancel_lane_from_timed");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule_timed(task(2), Time::from_secs(10));

        // Move task 2 to cancel lane
        sched.move_to_cancel_lane(task(2), 100);

        // Task 2 should come first now (cancel lane priority)
        let first = sched.pop();
        let second = sched.pop();
        crate::assert_with_log!(
            first == Some(task(2)),
            "moved timed task pops first",
            Some(task(2)),
            first
        );
        crate::assert_with_log!(
            second == Some(task(1)),
            "ready task pops second",
            Some(task(1)),
            second
        );
        crate::test_complete!("move_to_cancel_lane_from_timed");
    }

    #[test]
    fn move_to_cancel_lane_unscheduled_task() {
        init_test("move_to_cancel_lane_unscheduled_task");
        let mut sched = Scheduler::new();

        // Move unscheduled task to cancel lane
        sched.move_to_cancel_lane(task(1), 100);

        crate::assert_with_log!(
            sched.len() == 1,
            "unscheduled task inserted",
            1usize,
            sched.len()
        );
        crate::assert_with_log!(
            sched.is_in_cancel_lane(task(1)),
            "task is in cancel lane",
            true,
            sched.is_in_cancel_lane(task(1))
        );
        let first = sched.pop();
        crate::assert_with_log!(
            first == Some(task(1)),
            "cancel lane pops task",
            Some(task(1)),
            first
        );
        crate::test_complete!("move_to_cancel_lane_unscheduled_task");
    }

    #[test]
    fn move_to_cancel_lane_updates_priority() {
        init_test("move_to_cancel_lane_updates_priority");
        let mut sched = Scheduler::new();
        sched.schedule_cancel(task(1), 50);
        sched.schedule_cancel(task(2), 100);

        // Move task 1 to cancel lane with higher priority
        sched.move_to_cancel_lane(task(1), 150);

        // Task 1 should now come first due to higher priority
        let first = sched.pop();
        let second = sched.pop();
        crate::assert_with_log!(
            first == Some(task(1)),
            "higher priority task pops first",
            Some(task(1)),
            first
        );
        crate::assert_with_log!(
            second == Some(task(2)),
            "lower priority task pops next",
            Some(task(2)),
            second
        );
        crate::test_complete!("move_to_cancel_lane_updates_priority");
    }

    #[test]
    fn is_in_cancel_lane() {
        init_test("is_in_cancel_lane");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule_cancel(task(2), 100);

        crate::assert_with_log!(
            !sched.is_in_cancel_lane(task(1)),
            "ready task not in cancel lane",
            false,
            sched.is_in_cancel_lane(task(1))
        );
        crate::assert_with_log!(
            sched.is_in_cancel_lane(task(2)),
            "cancel task is in cancel lane",
            true,
            sched.is_in_cancel_lane(task(2))
        );
        crate::test_complete!("is_in_cancel_lane");
    }

    #[test]
    fn exact_dispatch_is_lane_generation_and_deadline_bound() {
        init_test("exact_dispatch_is_lane_generation_and_deadline_bound");

        let mut ready = Scheduler::new();
        ready.schedule(task(1), 7);
        assert_eq!(
            ready.take_exact(task(1), DispatchLane::Cancel, Time::ZERO),
            Err(ExactDispatchError::LaneMismatch {
                actual: DispatchLane::Ready
            })
        );
        assert_eq!(ready.len(), 1, "lane mismatch must not dequeue");
        assert_eq!(
            ready.take_exact(task(1), DispatchLane::Ready, Time::ZERO),
            Ok(())
        );
        assert!(ready.is_empty());

        let deadline = Time::from_nanos(9);
        let mut timed = Scheduler::new();
        timed.schedule_timed(task(2), deadline);
        assert_eq!(
            timed.take_exact(task(2), DispatchLane::Timed, Time::from_nanos(8)),
            Err(ExactDispatchError::TimedNotDue { deadline })
        );
        assert_eq!(timed.len(), 1, "future timed refusal must not dequeue");
        assert_eq!(
            timed.take_exact(task(2), DispatchLane::Timed, deadline),
            Ok(())
        );

        let mut promoted = Scheduler::new();
        promoted.schedule(task(3), 1);
        promoted.move_to_cancel_lane(task(3), 9);
        assert_eq!(
            promoted.take_exact(task(3), DispatchLane::Ready, Time::ZERO),
            Err(ExactDispatchError::LaneMismatch {
                actual: DispatchLane::Cancel
            })
        );
        assert_eq!(
            promoted.take_exact(task(3), DispatchLane::Cancel, Time::ZERO),
            Ok(())
        );

        let mut timed_promoted = Scheduler::new();
        timed_promoted.schedule_timed(task(4), Time::from_secs(60));
        timed_promoted.move_to_cancel_lane(task(4), 9);
        assert_eq!(
            timed_promoted.take_exact(task(4), DispatchLane::Cancel, Time::ZERO),
            Ok(()),
            "cancel promotion must override a future timed tombstone"
        );
        assert_eq!(
            promoted.take_exact(
                TaskId::from_arena(ArenaIndex::new(3, 1)),
                DispatchLane::Cancel,
                Time::ZERO,
            ),
            Err(ExactDispatchError::NotScheduled)
        );
        crate::test_complete!("exact_dispatch_is_lane_generation_and_deadline_bound");
    }

    #[test]
    fn timed_lane_edf_ordering() {
        init_test("timed_lane_edf_ordering");
        let mut sched = Scheduler::new();

        // Schedule task 1 with later deadline (T=100)
        sched.schedule_timed(task(1), Time::from_secs(100));

        // Schedule task 2 with earlier deadline (T=10)
        sched.schedule_timed(task(2), Time::from_secs(10));

        // Task 2 should come first (EDF)
        let first = sched.pop();
        let second = sched.pop();
        crate::assert_with_log!(
            first == Some(task(2)),
            "earlier deadline pops first",
            Some(task(2)),
            first
        );
        crate::assert_with_log!(
            second == Some(task(1)),
            "later deadline pops second",
            Some(task(1)),
            second
        );
        crate::test_complete!("timed_lane_edf_ordering");
    }

    #[test]
    fn timed_lane_priority_over_ready() {
        init_test("timed_lane_priority_over_ready");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 255); // Highest priority ready
        sched.schedule_timed(task(2), Time::from_secs(100)); // Timed

        // Timed lane should come before ready lane
        let first = sched.pop();
        let second = sched.pop();
        crate::assert_with_log!(
            first == Some(task(2)),
            "timed lane pops before ready",
            Some(task(2)),
            first
        );
        crate::assert_with_log!(
            second == Some(task(1)),
            "ready lane pops after timed",
            Some(task(1)),
            second
        );
        crate::test_complete!("timed_lane_priority_over_ready");
    }

    #[test]
    fn scheduler_with_capacity_preallocates_overflow_set() {
        init_test("scheduler_with_capacity_preallocates_overflow_set");
        let sched = Scheduler::with_capacity(1024);
        let has_capacity = sched.scheduled.overflow.capacity() >= 1024;
        crate::assert_with_log!(has_capacity, "overflow preallocation", true, has_capacity);
        crate::test_complete!("scheduler_with_capacity_preallocates_overflow_set");
    }

    #[test]
    fn cancel_lane_priority_over_timed() {
        init_test("cancel_lane_priority_over_timed");
        let mut sched = Scheduler::new();
        sched.schedule_timed(task(1), Time::from_secs(10)); // Urgent deadline
        sched.schedule_cancel(task(2), 1); // Low priority cancel

        // Cancel lane should still come first
        let first = sched.pop();
        let second = sched.pop();
        crate::assert_with_log!(
            first == Some(task(2)),
            "cancel lane pops before timed",
            Some(task(2)),
            first
        );
        crate::assert_with_log!(
            second == Some(task(1)),
            "timed lane pops after cancel",
            Some(task(1)),
            second
        );
        crate::test_complete!("cancel_lane_priority_over_timed");
    }

    // ========== Additional Three-Lane Tests ==========

    #[test]
    fn test_three_lane_push_pop_basic() {
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        assert_eq!(sched.pop(), Some(task(1)));
        assert_eq!(sched.pop(), None);
    }

    #[test]
    fn test_three_lane_fifo_ordering() {
        let mut sched = Scheduler::new();
        // Same priority, should be FIFO
        sched.schedule(task(1), 50);
        sched.schedule(task(2), 50);
        sched.schedule(task(3), 50);

        assert_eq!(sched.pop(), Some(task(1)), "first in, first out");
        assert_eq!(sched.pop(), Some(task(2)));
        assert_eq!(sched.pop(), Some(task(3)));
    }

    #[test]
    fn test_three_lane_priority_lanes_strict() {
        let mut sched = Scheduler::new();
        // Add in reverse order
        sched.schedule(task(1), 100); // ready
        sched.schedule_timed(task(2), Time::from_secs(1)); // timed
        sched.schedule_cancel(task(3), 50); // cancel

        // Strict ordering: cancel > timed > ready
        assert_eq!(sched.pop(), Some(task(3)), "cancel first");
        assert_eq!(sched.pop(), Some(task(2)), "timed second");
        assert_eq!(sched.pop(), Some(task(1)), "ready last");
    }

    #[test]
    fn test_three_lane_empty_detection() {
        let mut sched = Scheduler::new();
        assert!(sched.is_empty());

        sched.schedule(task(1), 50);
        assert!(!sched.is_empty());

        sched.pop();
        assert!(sched.is_empty());
    }

    #[test]
    fn test_three_lane_length_tracking() {
        let mut sched = Scheduler::new();
        assert_eq!(sched.len(), 0);

        sched.schedule(task(1), 50);
        sched.schedule_cancel(task(2), 50);
        sched.schedule_timed(task(3), Time::from_secs(1));

        assert_eq!(sched.len(), 3);

        sched.pop();
        assert_eq!(sched.len(), 2);
    }

    #[test]
    fn test_cancel_lane_priority_ordering() {
        let mut sched = Scheduler::new();
        sched.schedule_cancel(task(1), 50);
        sched.schedule_cancel(task(2), 100); // higher priority
        sched.schedule_cancel(task(3), 75);

        assert_eq!(sched.pop(), Some(task(2)), "highest priority first");
        assert_eq!(sched.pop(), Some(task(3)), "middle priority second");
        assert_eq!(sched.pop(), Some(task(1)), "lowest priority last");
    }

    #[test]
    fn test_ready_lane_priority_ordering() {
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule(task(2), 100);
        sched.schedule(task(3), 75);

        assert_eq!(sched.pop(), Some(task(2)), "highest priority first");
        assert_eq!(sched.pop(), Some(task(3)), "middle priority second");
        assert_eq!(sched.pop(), Some(task(1)), "lowest priority last");
    }

    #[test]
    fn test_steal_ready_batch_basic() {
        let mut sched = Scheduler::new();
        for i in 0..8 {
            sched.schedule(task(i), 50);
        }

        let stolen = sched.steal_ready_batch(4);
        assert!(!stolen.is_empty());
        assert!(stolen.len() <= 4);

        // Verify stolen tasks have correct format
        for (task_id, priority) in &stolen {
            assert_eq!(*priority, 50);
            assert!(task_id.0.index() < 8);
        }
    }

    #[test]
    fn test_steal_only_from_ready() {
        let mut sched = Scheduler::new();
        sched.schedule_cancel(task(1), 100);
        sched.schedule_timed(task(2), Time::from_secs(1));
        sched.schedule(task(3), 50);

        let stolen = sched.steal_ready_batch(10);
        // Only ready task should be stolen
        assert_eq!(stolen.len(), 1);
        assert_eq!(stolen[0].0, task(3));

        // Cancel and timed should still be in scheduler
        assert!(sched.has_cancel_work());
        assert!(sched.has_timed_work());
    }

    #[test]
    fn test_pop_only_methods() {
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule_cancel(task(2), 100);
        sched.schedule_timed(task(3), Time::from_secs(1));

        // pop_cancel_only should only get cancel task
        assert_eq!(sched.pop_cancel_only(), Some(task(2)));
        assert_eq!(sched.pop_cancel_only(), None);

        // pop_timed_only should only get timed task (deadline is 1s, so pass now >= 1s)
        let now = Time::from_secs(1);
        assert_eq!(sched.pop_timed_only(now), Some(task(3)));
        assert_eq!(sched.pop_timed_only(now), None);

        // pop_ready_only should only get ready task
        assert_eq!(sched.pop_ready_only(), Some(task(1)));
        assert_eq!(sched.pop_ready_only(), None);
    }

    #[test]
    fn test_remove_from_scheduler() {
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule(task(2), 50);
        sched.schedule(task(3), 50);

        sched.remove(task(2));

        assert_eq!(sched.len(), 2);
        assert_eq!(sched.pop(), Some(task(1)));
        assert_eq!(sched.pop(), Some(task(3)));
    }

    #[test]
    fn test_clear_scheduler() {
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule_cancel(task(2), 100);
        sched.schedule_timed(task(3), Time::from_secs(1));

        sched.clear();

        assert!(sched.is_empty());
        assert_eq!(sched.len(), 0);
        assert!(!sched.has_cancel_work());
        assert!(!sched.has_timed_work());
        assert!(!sched.has_ready_work());
    }

    #[test]
    fn test_has_work_methods() {
        let mut sched = Scheduler::new();
        assert!(!sched.has_cancel_work());
        assert!(!sched.has_timed_work());
        assert!(!sched.has_ready_work());

        sched.schedule(task(1), 50);
        assert!(sched.has_ready_work());

        sched.schedule_cancel(task(2), 100);
        assert!(sched.has_cancel_work());

        sched.schedule_timed(task(3), Time::from_secs(1));
        assert!(sched.has_timed_work());
    }

    #[test]
    fn test_high_volume_scheduling() {
        let mut sched = Scheduler::new();
        let count = 1000;

        for i in 0..count {
            sched.schedule(task(i), (i % 256) as u8);
        }

        assert_eq!(sched.len(), count as usize);

        let mut popped = 0;
        while sched.pop().is_some() {
            popped += 1;
        }

        assert_eq!(popped, count);
        assert!(sched.is_empty());
    }

    // ── ScheduleCertificate tests ───────────────────────────────────────

    #[test]
    fn certificate_empty() {
        let cert = ScheduleCertificate::new();
        assert_eq!(cert.decisions(), 0);
        assert_eq!(cert.divergence_step(), None);
    }

    #[test]
    fn certificate_deterministic_same_sequence() {
        let mut c1 = ScheduleCertificate::new();
        let mut c2 = ScheduleCertificate::new();

        c1.record(task(1), DispatchLane::Ready, 0);
        c1.record(task(2), DispatchLane::Cancel, 1);
        c1.record(task(3), DispatchLane::Timed, 2);

        c2.record(task(1), DispatchLane::Ready, 0);
        c2.record(task(2), DispatchLane::Cancel, 1);
        c2.record(task(3), DispatchLane::Timed, 2);

        assert!(c1.matches(&c2));
        assert_eq!(c1.hash(), c2.hash());
        assert_eq!(c1.decisions(), 3);
    }

    #[test]
    fn certificate_different_sequences_diverge() {
        let mut c1 = ScheduleCertificate::new();
        let mut c2 = ScheduleCertificate::new();

        c1.record(task(1), DispatchLane::Ready, 0);
        c1.record(task(2), DispatchLane::Ready, 1);

        c2.record(task(2), DispatchLane::Ready, 0);
        c2.record(task(1), DispatchLane::Ready, 1);

        assert!(!c1.matches(&c2));
    }

    #[test]
    fn certificate_lane_matters() {
        let mut c1 = ScheduleCertificate::new();
        let mut c2 = ScheduleCertificate::new();

        c1.record(task(1), DispatchLane::Ready, 0);
        c2.record(task(1), DispatchLane::Cancel, 0);

        assert!(!c1.matches(&c2));
    }

    #[test]
    fn certificate_divergence_tracking() {
        let mut cert = ScheduleCertificate::new();
        cert.record(task(1), DispatchLane::Ready, 0);
        assert_eq!(cert.divergence_step(), None);

        cert.mark_divergence(5);
        assert_eq!(cert.divergence_step(), Some(5));

        // First divergence is sticky.
        cert.mark_divergence(10);
        assert_eq!(cert.divergence_step(), Some(5));
    }

    #[test]
    fn scheduler_mode_default_is_deterministic() {
        assert_eq!(SchedulerMode::default(), SchedulerMode::Deterministic);
    }

    // ── pop_with_lane tests ───────────────────────────────────────────────

    #[test]
    fn pop_with_lane_returns_cancel_lane() {
        init_test("pop_with_lane_returns_cancel_lane");
        let mut sched = Scheduler::new();
        sched.schedule_cancel(task(1), 100);

        let result = sched.pop_with_lane(0);
        crate::assert_with_log!(
            result == Some((task(1), DispatchLane::Cancel)),
            "cancel task dispatches from Cancel lane",
            Some((task(1), DispatchLane::Cancel)),
            result
        );
        crate::test_complete!("pop_with_lane_returns_cancel_lane");
    }

    #[test]
    fn pop_with_lane_returns_timed_lane() {
        init_test("pop_with_lane_returns_timed_lane");
        let mut sched = Scheduler::new();
        sched.schedule_timed(task(1), Time::from_secs(10));

        let result = sched.pop_with_lane(0);
        crate::assert_with_log!(
            result == Some((task(1), DispatchLane::Timed)),
            "timed task dispatches from Timed lane",
            Some((task(1), DispatchLane::Timed)),
            result
        );
        crate::test_complete!("pop_with_lane_returns_timed_lane");
    }

    #[test]
    fn pop_with_lane_returns_ready_lane() {
        init_test("pop_with_lane_returns_ready_lane");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);

        let result = sched.pop_with_lane(0);
        crate::assert_with_log!(
            result == Some((task(1), DispatchLane::Ready)),
            "ready task dispatches from Ready lane",
            Some((task(1), DispatchLane::Ready)),
            result
        );
        crate::test_complete!("pop_with_lane_returns_ready_lane");
    }

    #[test]
    fn pop_with_lane_respects_lane_ordering() {
        init_test("pop_with_lane_respects_lane_ordering");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule_timed(task(2), Time::from_secs(10));
        sched.schedule_cancel(task(3), 10);

        let first = sched.pop_with_lane(0);
        let second = sched.pop_with_lane(0);
        let third = sched.pop_with_lane(0);
        let fourth = sched.pop_with_lane(0);

        crate::assert_with_log!(
            first.map(|(_, l)| l) == Some(DispatchLane::Cancel),
            "cancel dispatches first",
            Some(DispatchLane::Cancel),
            first.map(|(_, l)| l)
        );
        crate::assert_with_log!(
            second.map(|(_, l)| l) == Some(DispatchLane::Timed),
            "timed dispatches second",
            Some(DispatchLane::Timed),
            second.map(|(_, l)| l)
        );
        crate::assert_with_log!(
            third.map(|(_, l)| l) == Some(DispatchLane::Ready),
            "ready dispatches third",
            Some(DispatchLane::Ready),
            third.map(|(_, l)| l)
        );
        crate::assert_with_log!(
            fourth.is_none(),
            "empty scheduler returns None",
            Option::<(TaskId, DispatchLane)>::None,
            fourth
        );
        crate::test_complete!("pop_with_lane_respects_lane_ordering");
    }

    #[test]
    fn pop_with_lane_if_due_skips_future_timed_for_ready() {
        init_test("pop_with_lane_if_due_skips_future_timed_for_ready");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule_timed(task(2), Time::from_secs(100));

        let result = sched.pop_with_lane_if_due(0, Time::from_secs(50));
        crate::assert_with_log!(
            result == Some((task(1), DispatchLane::Ready)),
            "ready task dispatches while timed task is not due",
            Some((task(1), DispatchLane::Ready)),
            result
        );
        crate::test_complete!("pop_with_lane_if_due_skips_future_timed_for_ready");
    }

    #[test]
    fn pop_with_lane_if_due_dispatches_timed_when_due() {
        init_test("pop_with_lane_if_due_dispatches_timed_when_due");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule_timed(task(2), Time::from_secs(100));

        let result = sched.pop_with_lane_if_due(0, Time::from_secs(100));
        crate::assert_with_log!(
            result == Some((task(2), DispatchLane::Timed)),
            "timed task dispatches once deadline is due",
            Some((task(2), DispatchLane::Timed)),
            result
        );
        crate::test_complete!("pop_with_lane_if_due_dispatches_timed_when_due");
    }

    #[test]
    fn pop_non_cancel_with_rng_if_due_skips_future_timed() {
        init_test("pop_non_cancel_with_rng_if_due_skips_future_timed");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);
        sched.schedule_timed(task(2), Time::from_secs(100));

        let result = sched.pop_non_cancel_with_rng_if_due(0, Time::from_secs(50));
        crate::assert_with_log!(
            result == Some((task(1), DispatchLane::Ready)),
            "non-cancel pop dispatches ready when timed is not due",
            Some((task(1), DispatchLane::Ready)),
            result
        );
        crate::test_complete!("pop_non_cancel_with_rng_if_due_skips_future_timed");
    }

    #[test]
    fn pop_with_lane_rng_tiebreak_among_equal_priority() {
        init_test("pop_with_lane_rng_tiebreak_among_equal_priority");
        let run_with_hints = |hints: &[u64]| -> Vec<TaskId> {
            let mut sched = Scheduler::new();
            for i in 0..4 {
                sched.schedule(task(i), 50);
            }

            let mut popped = Vec::new();
            for &hint in hints {
                if let Some((t, lane)) = sched.pop_with_lane(hint) {
                    crate::assert_with_log!(
                        matches!(lane, DispatchLane::Ready),
                        "equal-priority dispatch stays in ready lane",
                        true,
                        true
                    );
                    popped.push(t);
                }
            }
            popped
        };

        let hints_a = [0, 1, 2, 3];
        let hints_b = [0, 1, 2, 3];
        let hints_c = [42, 43, 44, 45];
        let hints_d = [42, 43, 44, 45];

        let order_a = run_with_hints(&hints_a);
        let order_b = run_with_hints(&hints_b);
        let order_c = run_with_hints(&hints_c);
        let order_d = run_with_hints(&hints_d);

        // Same hints from same initial state must be deterministic.
        crate::assert_with_log!(
            order_a == order_b,
            "same hint sequence yields same pop order",
            true,
            order_a == order_b
        );
        // Distinct hints should perturb tie-breaking among equal priorities.
        crate::assert_with_log!(
            order_a != order_c,
            "different hint sequence yields different pop order",
            true,
            order_a != order_c
        );
        crate::assert_with_log!(
            order_c == order_d,
            "alternate hint sequence is also deterministic",
            true,
            order_c == order_d
        );

        // Each run must pop each task exactly once.
        for order in [&order_a, &order_b, &order_c, &order_d] {
            crate::assert_with_log!(
                order.len() == 4,
                "all tasks dispatched",
                4usize,
                order.len()
            );
            let mut sorted = order.clone();
            sorted.sort_by_key(|t| t.arena_index().index());
            let expected = vec![task(0), task(1), task(2), task(3)];
            crate::assert_with_log!(
                sorted == expected,
                "pop order is a permutation of scheduled tasks",
                true,
                sorted == expected
            );
        }
        crate::test_complete!("pop_with_lane_rng_tiebreak_among_equal_priority");
    }

    #[test]
    fn pop_with_lane_rng_can_select_beyond_first_two_equal_priority_entries() {
        init_test("pop_with_lane_rng_can_select_beyond_first_two_equal_priority_entries");

        for (hint, expected) in [(2_u64, task(2)), (3_u64, task(3))] {
            let mut sched = Scheduler::new();
            for i in 0..4 {
                sched.schedule(task(i), 50);
            }

            let (popped, lane) = sched
                .pop_with_lane(hint)
                .expect("scheduler should return a ready task");
            crate::assert_with_log!(
                matches!(lane, DispatchLane::Ready),
                "equal-priority dispatch stays in ready lane",
                true,
                true
            );
            crate::assert_with_log!(
                popped == expected,
                "rng tie-break can reach later equal-priority entries",
                expected,
                popped
            );
        }

        crate::test_complete!(
            "pop_with_lane_rng_can_select_beyond_first_two_equal_priority_entries"
        );
    }

    #[test]
    fn pop_timed_only_with_hint_can_select_beyond_first_two_equal_deadline_entries() {
        init_test("pop_timed_only_with_hint_can_select_beyond_first_two_equal_deadline_entries");

        let deadline = Time::from_secs(10);
        let now = Time::from_secs(100);

        for (hint, expected) in [(2_u64, task(2)), (3_u64, task(3))] {
            let mut sched = Scheduler::new();
            for i in 0..4 {
                sched.schedule_timed(task(i), deadline);
            }

            let popped = sched
                .pop_timed_only_with_hint(hint, now)
                .expect("scheduler should return a timed task");
            crate::assert_with_log!(
                popped == expected,
                "rng tie-break can reach later equal-deadline entries",
                expected,
                popped
            );
        }

        crate::test_complete!(
            "pop_timed_only_with_hint_can_select_beyond_first_two_equal_deadline_entries"
        );
    }

    // ── steal_ready_batch_into tests ──────────────────────────────────────

    #[test]
    fn steal_ready_batch_into_fills_buffer() {
        init_test("steal_ready_batch_into_fills_buffer");
        let mut sched = Scheduler::new();
        for i in 0..10 {
            sched.schedule(task(i), 50);
        }

        let mut buf = Vec::new();
        let count = sched.steal_ready_batch_into(5, &mut buf);

        crate::assert_with_log!(
            count == buf.len(),
            "returned count matches buffer length",
            count,
            buf.len()
        );
        crate::assert_with_log!(count <= 5, "does not exceed max_steal", true, count <= 5);
        crate::assert_with_log!(count > 0, "steals at least one task", true, count > 0);
        crate::test_complete!("steal_ready_batch_into_fills_buffer");
    }

    #[test]
    fn steal_ready_batch_into_does_not_steal_cancel_or_timed() {
        init_test("steal_ready_batch_into_does_not_steal_cancel_or_timed");
        let mut sched = Scheduler::new();
        sched.schedule_cancel(task(1), 100);
        sched.schedule_timed(task(2), Time::from_secs(10));

        let mut buf = Vec::new();
        let count = sched.steal_ready_batch_into(10, &mut buf);

        crate::assert_with_log!(
            count == 0,
            "nothing stolen when ready lane is empty",
            0usize,
            count
        );
        // Cancel and timed tasks should still be present
        crate::assert_with_log!(
            sched.has_cancel_work(),
            "cancel task preserved",
            true,
            sched.has_cancel_work()
        );
        crate::assert_with_log!(
            sched.has_timed_work(),
            "timed task preserved",
            true,
            sched.has_timed_work()
        );
        crate::test_complete!("steal_ready_batch_into_does_not_steal_cancel_or_timed");
    }

    #[test]
    fn steal_ready_batch_into_respects_zero_max() {
        init_test("steal_ready_batch_into_respects_zero_max");
        let mut sched = Scheduler::new();
        for i in 0..4 {
            sched.schedule(task(i), 50);
        }

        let mut buf = Vec::new();
        let count = sched.steal_ready_batch_into(0, &mut buf);

        crate::assert_with_log!(count == 0, "zero max_steal returns zero", 0usize, count);
        crate::assert_with_log!(
            buf.is_empty(),
            "buffer cleared when max_steal is zero",
            true,
            buf.is_empty()
        );
        crate::assert_with_log!(sched.len() == 4, "no tasks removed", 4usize, sched.len());
        crate::test_complete!("steal_ready_batch_into_respects_zero_max");
    }

    #[test]
    fn steal_ready_batch_into_clears_buffer() {
        init_test("steal_ready_batch_into_clears_buffer");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 50);

        let mut buf = vec![(task(99), 255)]; // Pre-existing junk
        let count = sched.steal_ready_batch_into(10, &mut buf);

        crate::assert_with_log!(count == 1, "stole exactly one task", 1usize, count);
        crate::assert_with_log!(
            buf.len() == 1,
            "buffer cleared before filling",
            1usize,
            buf.len()
        );
        crate::assert_with_log!(
            buf[0].0 == task(1),
            "correct task in buffer",
            task(1),
            buf[0].0
        );
        crate::test_complete!("steal_ready_batch_into_clears_buffer");
    }

    #[test]
    fn steal_ready_batch_into_preserves_priority_order() {
        init_test("steal_ready_batch_into_preserves_priority_order");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 10);
        sched.schedule(task(2), 90);
        sched.schedule(task(3), 50);
        sched.schedule(task(4), 80);
        sched.schedule(task(5), 20);
        sched.schedule(task(6), 70);

        let mut buf = Vec::new();
        let count = sched.steal_ready_batch_into(3, &mut buf);

        crate::assert_with_log!(count == 3, "stole requested batch", 3usize, count);
        crate::assert_with_log!(
            buf.windows(2).all(|pair| pair[0].1 >= pair[1].1),
            "stolen batch preserves non-increasing priority order",
            true,
            buf.windows(2).all(|pair| pair[0].1 >= pair[1].1)
        );
        crate::assert_with_log!(
            buf[0] == (task(2), 90),
            "highest priority first",
            (task(2), 90),
            buf[0]
        );
        crate::assert_with_log!(
            buf[1] == (task(4), 80),
            "second-highest priority second",
            (task(4), 80),
            buf[1]
        );
        crate::assert_with_log!(
            buf[2] == (task(6), 70),
            "third-highest priority third",
            (task(6), 70),
            buf[2]
        );
        crate::test_complete!("steal_ready_batch_into_preserves_priority_order");
    }

    #[test]
    fn steal_ready_batch_into_preserves_fifo_within_priority() {
        init_test("steal_ready_batch_into_preserves_fifo_within_priority");
        let mut sched = Scheduler::new();
        for i in 0..6 {
            sched.schedule(task(i), 50);
        }

        let mut buf = Vec::new();
        let count = sched.steal_ready_batch_into(3, &mut buf);

        crate::assert_with_log!(count == 3, "stole requested batch", 3usize, count);
        crate::assert_with_log!(
            buf == vec![(task(0), 50), (task(1), 50), (task(2), 50)],
            "equal-priority steals preserve FIFO generation order",
            vec![(task(0), 50), (task(1), 50), (task(2), 50)],
            buf.clone()
        );
        crate::test_complete!("steal_ready_batch_into_preserves_fifo_within_priority");
    }

    #[test]
    fn steal_ready_batch_into_respects_half_steal_after_cancel_promotion() {
        init_test("steal_ready_batch_into_respects_half_steal_after_cancel_promotion");
        let mut sched = Scheduler::new();
        sched.schedule(task(1), 90);
        sched.schedule(task(2), 80);
        sched.schedule(task(3), 70);
        sched.schedule(task(4), 60);
        sched.schedule(task(5), 50);
        sched.schedule(task(6), 40);

        // Promote the two highest-priority ready tasks into the cancel lane
        // before stealing from the remaining live ready set.
        sched.move_to_cancel_lane(task(1), 200);
        sched.move_to_cancel_lane(task(2), 200);

        let mut buf = Vec::new();
        let count = sched.steal_ready_batch_into(3, &mut buf);

        crate::assert_with_log!(
            count == 2,
            "half-steal is computed over remaining live ready tasks",
            2usize,
            count
        );
        crate::assert_with_log!(
            buf == vec![(task(3), 70), (task(4), 60)],
            "promoted tasks leave the ready lane and the remaining half-steal keeps priority order",
            vec![(task(3), 70), (task(4), 60)],
            buf.clone()
        );

        let (first, lane1) = sched.pop_with_lane(0).expect("first cancel task");
        crate::assert_with_log!(
            first == task(1),
            "first promoted task remains in cancel lane",
            task(1),
            first
        );
        crate::assert_with_log!(
            matches!(lane1, DispatchLane::Cancel),
            "first promoted lane is cancel",
            true,
            true
        );

        let (second, lane2) = sched.pop_with_lane(0).expect("second cancel task");
        crate::assert_with_log!(
            second == task(2),
            "second promoted task remains in cancel lane",
            task(2),
            second
        );
        crate::assert_with_log!(
            matches!(lane2, DispatchLane::Cancel),
            "second promoted lane is cancel",
            true,
            true
        );

        let remaining = sched.pop_with_lane(0);
        crate::assert_with_log!(
            remaining == Some((task(5), DispatchLane::Ready)),
            "highest-priority unstolen ready task remains after cancel and steal activity",
            Some((task(5), DispatchLane::Ready)),
            remaining
        );
        let final_ready = sched.pop_with_lane(0);
        crate::assert_with_log!(
            final_ready == Some((task(6), DispatchLane::Ready)),
            "lowest-priority ready task drains last",
            Some((task(6), DispatchLane::Ready)),
            final_ready
        );
        crate::assert_with_log!(
            sched.is_empty(),
            "scheduler drained cleanly",
            true,
            sched.is_empty()
        );
        crate::test_complete!("steal_ready_batch_into_respects_half_steal_after_cancel_promotion");
    }

    // ── pop_timed_only edge cases ─────────────────────────────────────────

    #[test]
    fn pop_timed_only_respects_deadline_boundary() {
        init_test("pop_timed_only_respects_deadline_boundary");
        let mut sched = Scheduler::new();
        sched.schedule_timed(task(1), Time::from_secs(100));

        // Before deadline: should not dispatch
        let before = sched.pop_timed_only(Time::from_secs(99));
        crate::assert_with_log!(
            before.is_none(),
            "timed task not due before deadline",
            Option::<TaskId>::None,
            before
        );

        // Exactly at deadline: should dispatch
        let at = sched.pop_timed_only(Time::from_secs(100));
        crate::assert_with_log!(
            at == Some(task(1)),
            "timed task dispatches at deadline",
            Some(task(1)),
            at
        );
        crate::test_complete!("pop_timed_only_respects_deadline_boundary");
    }

    #[test]
    fn pop_timed_only_edf_with_mixed_due_status() {
        init_test("pop_timed_only_edf_with_mixed_due_status");
        let mut sched = Scheduler::new();
        sched.schedule_timed(task(1), Time::from_secs(50)); // due
        sched.schedule_timed(task(2), Time::from_secs(200)); // not due
        sched.schedule_timed(task(3), Time::from_secs(75)); // due

        let now = Time::from_secs(100);

        // Should return earliest deadline first
        let first = sched.pop_timed_only(now);
        crate::assert_with_log!(
            first == Some(task(1)),
            "earliest deadline dispatches first",
            Some(task(1)),
            first
        );

        let second = sched.pop_timed_only(now);
        crate::assert_with_log!(
            second == Some(task(3)),
            "second earliest deadline dispatches next",
            Some(task(3)),
            second
        );

        // Task 2 is not due (deadline 200 > now 100)
        let third = sched.pop_timed_only(now);
        crate::assert_with_log!(
            third.is_none(),
            "not-due task is not dispatched",
            Option::<TaskId>::None,
            third
        );
        crate::test_complete!("pop_timed_only_edf_with_mixed_due_status");
    }

    // ---- Cancel preemption: cancel drains before any timed/ready --------

    #[test]
    fn cancel_drains_completely_before_timed_and_ready() {
        init_test("cancel_drains_completely_before_timed_and_ready");
        let mut sched = Scheduler::new();

        // Schedule ready, timed, and cancel tasks in mixed order.
        sched.schedule(task(1), 100);
        sched.schedule_timed(task(2), Time::from_secs(1));
        sched.schedule_cancel(task(3), 50);
        sched.schedule(task(4), 200);
        sched.schedule_cancel(task(5), 100);
        sched.schedule_timed(task(6), Time::from_secs(2));

        // First two pops must be from cancel lane.
        let (_first, lane1) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(
            matches!(lane1, DispatchLane::Cancel),
            "first from cancel",
            true,
            true
        );

        let (_second, lane2) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(
            matches!(lane2, DispatchLane::Cancel),
            "second from cancel",
            true,
            true
        );

        // Now timed lane should drain (EDF order).
        let (_third, lane3) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(
            matches!(lane3, DispatchLane::Timed),
            "third from timed",
            true,
            true
        );

        let (_fourth, lane4) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(
            matches!(lane4, DispatchLane::Timed),
            "fourth from timed",
            true,
            true
        );

        // Finally ready lane.
        let (_fifth, lane5) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(
            matches!(lane5, DispatchLane::Ready),
            "fifth from ready",
            true,
            true
        );

        let (_sixth, lane6) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(
            matches!(lane6, DispatchLane::Ready),
            "sixth from ready",
            true,
            true
        );

        // Scheduler should now be empty.
        crate::assert_with_log!(
            sched.is_empty(),
            "empty after drain",
            true,
            sched.is_empty()
        );
        crate::test_complete!("cancel_drains_completely_before_timed_and_ready");
    }

    // ---- Move to cancel preserves other ready work ----------------------

    #[test]
    fn move_to_cancel_preserves_ready_work() {
        init_test("move_to_cancel_preserves_ready_work");
        let mut sched = Scheduler::new();

        // Schedule three ready tasks.
        sched.schedule(task(1), 100);
        sched.schedule(task(2), 100);
        sched.schedule(task(3), 100);
        let len_before = sched.len();
        crate::assert_with_log!(len_before == 3, "before move", 3, len_before);

        // Move task(2) to cancel lane.
        sched.move_to_cancel_lane(task(2), 200);

        // Total count should remain 3.
        let len_after = sched.len();
        crate::assert_with_log!(len_after == 3, "after move", 3, len_after);

        // First pop should be task(2) from cancel lane.
        let (first, lane) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(first == task(2), "cancel first", task(2), first);
        crate::assert_with_log!(
            matches!(lane, DispatchLane::Cancel),
            "from cancel lane",
            true,
            true
        );

        // Remaining two should be from ready lane.
        let (_, lane2) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(
            matches!(lane2, DispatchLane::Ready),
            "second from ready",
            true,
            true
        );

        let (_, lane3) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(
            matches!(lane3, DispatchLane::Ready),
            "third from ready",
            true,
            true
        );

        crate::assert_with_log!(sched.is_empty(), "empty", true, sched.is_empty());
        crate::test_complete!("move_to_cancel_preserves_ready_work");
    }

    // ---- Interleaved schedule/pop maintains invariants -------------------

    #[test]
    fn interleaved_schedule_pop_correct() {
        init_test("interleaved_schedule_pop_correct");
        let mut sched = Scheduler::new();

        // Schedule and pop interleaved — scheduler should always return
        // highest priority lane first.
        sched.schedule(task(1), 50);
        let first = sched.pop();
        crate::assert_with_log!(first == Some(task(1)), "pop ready", Some(task(1)), first);

        sched.schedule_cancel(task(2), 100);
        sched.schedule(task(3), 200); // higher ready priority but cancel wins

        let second = sched.pop();
        crate::assert_with_log!(
            second == Some(task(2)),
            "cancel preempts",
            Some(task(2)),
            second
        );

        let third = sched.pop();
        crate::assert_with_log!(
            third == Some(task(3)),
            "ready dispatches after cancel drain",
            Some(task(3)),
            third
        );

        crate::assert_with_log!(sched.is_empty(), "empty", true, sched.is_empty());
        crate::test_complete!("interleaved_schedule_pop_correct");
    }

    // ---- EDF with many same-deadline tasks is stable --------------------

    #[test]
    fn edf_same_deadline_fifo_stable() {
        init_test("edf_same_deadline_fifo_stable");
        let mut sched = Scheduler::new();
        let deadline = Time::from_secs(100);

        // Schedule 10 tasks with the same deadline — should dispatch in FIFO order
        // (by generation) when using basic pop.
        for i in 0..10 {
            sched.schedule_timed(task(i), deadline);
        }

        let mut order = Vec::new();
        while let Some(t) = sched.pop() {
            order.push(t);
        }

        crate::assert_with_log!(order.len() == 10, "all dispatched", 10, order.len());

        // Verify FIFO ordering (earlier index = lower task number).
        for window in order.windows(2) {
            let a_idx = window[0].arena_index().index();
            let b_idx = window[1].arena_index().index();
            crate::assert_with_log!(a_idx < b_idx, "FIFO order", true, true);
        }
        crate::test_complete!("edf_same_deadline_fifo_stable");
    }

    #[test]
    fn metamorphic_edf_deadline_tightening_is_monotone() {
        init_test("metamorphic_edf_deadline_tightening_is_monotone");

        fn timed_order(entries: &[(TaskId, Time)]) -> Vec<TaskId> {
            let mut sched = Scheduler::new();
            for &(task, deadline) in entries {
                sched.schedule_timed(task, deadline);
            }

            let mut order = Vec::with_capacity(entries.len());
            while let Some(task) = sched.pop() {
                order.push(task);
            }
            order
        }

        fn position_of(order: &[TaskId], task: TaskId) -> usize {
            order.iter().position(|&entry| entry == task).unwrap()
        }

        let baseline = [
            (task(1), Time::from_secs(40)),
            (task(2), Time::from_secs(15)),
            (task(3), Time::from_secs(90)),
            (task(4), Time::from_secs(25)),
            (task(5), Time::from_secs(60)),
        ];

        let baseline_order = timed_order(&baseline);
        crate::assert_with_log!(
            baseline_order == vec![task(2), task(4), task(1), task(5), task(3)],
            "baseline EDF order",
            vec![task(2), task(4), task(1), task(5), task(3)],
            baseline_order.clone()
        );

        for &(tightened_task, tighter_deadline) in &[
            (task(3), Time::from_secs(10)),
            (task(5), Time::from_secs(20)),
            (task(1), Time::from_secs(5)),
        ] {
            let mut transformed = baseline;
            let baseline_pos = position_of(&baseline_order, tightened_task);
            let baseline_deadline = baseline
                .iter()
                .find(|&&(task, _)| task == tightened_task)
                .map(|&(_, deadline)| deadline)
                .unwrap();

            for (task, deadline) in &mut transformed {
                if *task == tightened_task {
                    *deadline = tighter_deadline;
                }
            }

            let transformed_order = timed_order(&transformed);
            let transformed_pos = position_of(&transformed_order, tightened_task);

            crate::assert_with_log!(
                tighter_deadline < baseline_deadline,
                "transformation strictly tightens deadline",
                true,
                tighter_deadline < baseline_deadline
            );
            crate::assert_with_log!(
                transformed_pos <= baseline_pos,
                "tightened deadline cannot move task later",
                true,
                transformed_pos <= baseline_pos
            );
        }

        crate::test_complete!("metamorphic_edf_deadline_tightening_is_monotone");
    }

    #[test]
    fn metamorphic_cancel_promotion_preserves_waiting_ready_suffix() {
        init_test("metamorphic_cancel_promotion_preserves_waiting_ready_suffix");

        let mut baseline = Scheduler::new();
        let mut promoted = Scheduler::new();
        let entries = [
            (task(1), 10u8),
            (task(2), 50u8),
            (task(3), 40u8),
            (task(4), 20u8),
        ];

        for &(task, priority) in &entries {
            baseline.schedule(task, priority);
            promoted.schedule(task, priority);
        }

        let baseline_trace = drain_with_lane_if_due(&mut baseline, Time::from_secs(1));
        promoted.move_to_cancel_lane(task(3), 200);
        let promoted_trace = drain_with_lane_if_due(&mut promoted, Time::from_secs(1));

        let expected_suffix: Vec<_> = baseline_trace
            .into_iter()
            .filter_map(|(t, _)| (t != task(3)).then_some((t, DispatchLane::Ready)))
            .collect();

        crate::assert_with_log!(
            promoted_trace.first() == Some(&(task(3), DispatchLane::Cancel)),
            "promoted task dispatches first from cancel lane",
            Some((task(3), DispatchLane::Cancel)),
            promoted_trace.first().copied()
        );
        crate::assert_with_log!(
            promoted_trace[1..] == expected_suffix,
            "waiting ready suffix remains intact",
            expected_suffix.clone(),
            promoted_trace[1..].to_vec()
        );

        crate::test_complete!("metamorphic_cancel_promotion_preserves_waiting_ready_suffix");
    }

    #[test]
    fn metamorphic_cancel_priority_shifts_preserve_non_cancel_suffix() {
        init_test("metamorphic_cancel_priority_shifts_preserve_non_cancel_suffix");

        let now = Time::from_secs(100);
        let mut baseline = Scheduler::new();
        let mut shifted = Scheduler::new();

        for sched in [&mut baseline, &mut shifted] {
            sched.schedule_timed(task(1), Time::from_secs(10));
            sched.schedule_timed(task(2), Time::from_secs(20));
            sched.schedule(task(3), 70);
            sched.schedule(task(4), 90);
            sched.schedule_cancel(task(5), 10);
            sched.schedule_cancel(task(6), 20);
        }

        shifted.move_to_cancel_lane(task(5), 200);
        shifted.move_to_cancel_lane(task(6), 150);

        let baseline_trace = drain_with_lane_if_due(&mut baseline, now);
        let shifted_trace = drain_with_lane_if_due(&mut shifted, now);

        let baseline_suffix: Vec<_> = baseline_trace
            .into_iter()
            .filter(|(_, lane)| !matches!(lane, DispatchLane::Cancel))
            .collect();
        let shifted_suffix: Vec<_> = shifted_trace
            .into_iter()
            .filter(|(_, lane)| !matches!(lane, DispatchLane::Cancel))
            .collect();

        crate::assert_with_log!(
            baseline_suffix == shifted_suffix,
            "non-cancel suffix is invariant under cancel-priority shifts",
            baseline_suffix.clone(),
            shifted_suffix.clone()
        );
        crate::assert_with_log!(
            baseline_suffix
                == vec![
                    (task(1), DispatchLane::Timed),
                    (task(2), DispatchLane::Timed),
                    (task(4), DispatchLane::Ready),
                    (task(3), DispatchLane::Ready),
                ],
            "timed-before-ready fairness remains intact",
            vec![
                (task(1), DispatchLane::Timed),
                (task(2), DispatchLane::Timed),
                (task(4), DispatchLane::Ready),
                (task(3), DispatchLane::Ready),
            ],
            baseline_suffix
        );

        crate::test_complete!("metamorphic_cancel_priority_shifts_preserve_non_cancel_suffix");
    }

    #[test]
    fn metamorphic_concurrent_cancel_requests_preserve_total_order() {
        init_test("metamorphic_concurrent_cancel_requests_preserve_total_order");

        let now = Time::from_secs(100);
        let mut forward = Scheduler::new();
        let mut reverse = Scheduler::new();

        for sched in [&mut forward, &mut reverse] {
            sched.schedule(task(1), 40);
            sched.schedule(task(2), 60);
            sched.schedule_timed(task(3), Time::from_secs(5));
            sched.schedule(task(4), 20);
        }

        for &(task, priority) in &[(task(2), 120u8), (task(3), 200u8), (task(1), 160u8)] {
            forward.move_to_cancel_lane(task, priority);
        }
        for &(task, priority) in &[(task(1), 160u8), (task(3), 200u8), (task(2), 120u8)] {
            reverse.move_to_cancel_lane(task, priority);
        }

        let forward_trace = drain_with_lane_if_due(&mut forward, now);
        let reverse_trace = drain_with_lane_if_due(&mut reverse, now);

        crate::assert_with_log!(
            forward_trace == reverse_trace,
            "reordered cancel promotions preserve total order",
            forward_trace.clone(),
            reverse_trace.clone()
        );
        crate::assert_with_log!(
            forward_trace
                == vec![
                    (task(3), DispatchLane::Cancel),
                    (task(1), DispatchLane::Cancel),
                    (task(2), DispatchLane::Cancel),
                    (task(4), DispatchLane::Ready),
                ],
            "distinct final priorities determine stable total order",
            vec![
                (task(3), DispatchLane::Cancel),
                (task(1), DispatchLane::Cancel),
                (task(2), DispatchLane::Cancel),
                (task(4), DispatchLane::Ready),
            ],
            forward_trace
        );

        crate::test_complete!("metamorphic_concurrent_cancel_requests_preserve_total_order");
    }

    // ---- Remove from specific lane doesn't corrupt other lanes ----------

    #[test]
    fn remove_does_not_corrupt_other_lanes() {
        init_test("remove_does_not_corrupt_other_lanes");
        let mut sched = Scheduler::new();

        sched.schedule(task(1), 100);
        sched.schedule_timed(task(2), Time::from_secs(10));
        sched.schedule_cancel(task(3), 200);

        // Remove timed task.
        sched.remove(task(2));
        let len = sched.len();
        crate::assert_with_log!(len == 2, "after remove", 2, len);

        // Cancel and ready should still work.
        let (first, lane1) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(first == task(3), "cancel intact", task(3), first);
        crate::assert_with_log!(
            matches!(lane1, DispatchLane::Cancel),
            "cancel lane",
            true,
            true
        );

        let (second, lane2) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(second == task(1), "ready intact", task(1), second);
        crate::assert_with_log!(
            matches!(lane2, DispatchLane::Ready),
            "ready lane",
            true,
            true
        );

        crate::assert_with_log!(sched.is_empty(), "empty", true, sched.is_empty());
        crate::test_complete!("remove_does_not_corrupt_other_lanes");
    }

    // ---- High-volume cancel/ready interleaving --------------------------

    #[test]
    fn high_volume_cancel_ready_interleaving() {
        init_test("high_volume_cancel_ready_interleaving");
        let mut sched = Scheduler::new();

        // Schedule 50 cancel + 50 ready tasks.
        for i in 0..50 {
            sched.schedule_cancel(task(i), 100);
        }
        for i in 50..100 {
            sched.schedule(task(i), 100);
        }

        let total = sched.len();
        crate::assert_with_log!(total == 100, "total", 100, total);

        // All cancel tasks must dispatch before any ready task.
        let mut cancel_count = 0;
        let mut ready_seen = false;
        while let Some((_, lane)) = sched.pop_with_lane(0) {
            match lane {
                DispatchLane::Cancel => {
                    crate::assert_with_log!(
                        !ready_seen,
                        "no ready before cancel drains",
                        true,
                        true
                    );
                    cancel_count += 1;
                }
                DispatchLane::Ready => {
                    ready_seen = true;
                }
                DispatchLane::Timed | DispatchLane::Stolen => {}
            }
        }

        crate::assert_with_log!(cancel_count == 50, "cancel count", 50, cancel_count);
        crate::assert_with_log!(ready_seen, "ready seen", true, ready_seen);
        crate::assert_with_log!(sched.is_empty(), "empty", true, sched.is_empty());
        crate::test_complete!("high_volume_cancel_ready_interleaving");
    }

    // ── Cancel promotion parity regression tests (bd-1zaql) ─────────────

    #[test]
    fn move_to_cancel_promotes_from_ready() {
        init_test("move_to_cancel_promotes_from_ready");
        let mut sched = Scheduler::new();
        let task = TaskId::new_for_test(1, 0);

        // Schedule in ready lane
        sched.schedule(task, 50);
        crate::assert_with_log!(
            !sched.is_in_cancel_lane(task),
            "not in cancel before promotion",
            true,
            true
        );

        // Promote to cancel lane
        sched.move_to_cancel_lane(task, 100);
        crate::assert_with_log!(
            sched.is_in_cancel_lane(task),
            "in cancel after promotion",
            true,
            true
        );

        // Pop should come from cancel lane
        let (popped, lane) = sched.pop_with_lane(0).expect("should have task");
        crate::assert_with_log!(popped == task, "correct task", task, popped);
        crate::assert_with_log!(
            matches!(lane, DispatchLane::Cancel),
            "dispatched from cancel lane",
            true,
            true
        );

        // Ready lane should be empty (task was removed during promotion)
        crate::assert_with_log!(
            sched.pop_ready_only().is_none(),
            "ready lane empty after promotion",
            true,
            true
        );
        crate::test_complete!("move_to_cancel_promotes_from_ready");
    }

    #[test]
    fn move_to_cancel_promotes_from_timed() {
        init_test("move_to_cancel_promotes_from_timed");
        let mut sched = Scheduler::new();
        let task = TaskId::new_for_test(2, 0);

        // Schedule in timed lane
        sched.schedule_timed(task, Time::from_nanos(5000));
        crate::assert_with_log!(
            !sched.is_in_cancel_lane(task),
            "not in cancel before promotion",
            true,
            true
        );

        // Promote to cancel lane
        sched.move_to_cancel_lane(task, 80);
        crate::assert_with_log!(
            sched.is_in_cancel_lane(task),
            "in cancel after promotion",
            true,
            true
        );

        // Pop should come from cancel lane
        let (popped, lane) = sched.pop_with_lane(0).expect("should have task");
        crate::assert_with_log!(popped == task, "correct task", task, popped);
        crate::assert_with_log!(
            matches!(lane, DispatchLane::Cancel),
            "dispatched from cancel lane",
            true,
            true
        );
        crate::test_complete!("move_to_cancel_promotes_from_timed");
    }

    #[test]
    fn move_to_cancel_idempotent_updates_priority() {
        init_test("move_to_cancel_idempotent_updates_priority");
        let mut sched = Scheduler::new();
        let task = TaskId::new_for_test(3, 0);

        // Schedule in cancel lane at low priority
        sched.schedule_cancel(task, 10);
        crate::assert_with_log!(sched.is_in_cancel_lane(task), "in cancel lane", true, true);

        // Promote again with higher priority (idempotent, updates priority)
        sched.move_to_cancel_lane(task, 200);
        crate::assert_with_log!(
            sched.is_in_cancel_lane(task),
            "still in cancel lane",
            true,
            true
        );

        // Only one task should be in scheduler
        crate::assert_with_log!(sched.len() == 1, "exactly one task", 1usize, sched.len());
        crate::test_complete!("move_to_cancel_idempotent_updates_priority");
    }

    #[test]
    fn schedule_cancel_promotes_from_ready() {
        init_test("schedule_cancel_promotes_from_ready");
        let mut sched = Scheduler::new();
        let task = TaskId::new_for_test(4, 0);

        // Schedule in ready lane
        sched.schedule(task, 50);

        // schedule_cancel should promote to cancel lane when already scheduled
        sched.schedule_cancel(task, 100);
        crate::assert_with_log!(
            sched.is_in_cancel_lane(task),
            "schedule_cancel promotes from ready",
            true,
            true
        );
        crate::test_complete!("schedule_cancel_promotes_from_ready");
    }

    #[test]
    fn repeated_cancel_requests_are_idempotent() {
        init_test("repeated_cancel_requests_are_idempotent");
        let mut sched = Scheduler::new();
        let task = TaskId::new_for_test(5, 0);

        // First cancel
        sched.move_to_cancel_lane(task, 50);
        crate::assert_with_log!(
            sched.len() == 1,
            "one task after first cancel",
            1usize,
            sched.len()
        );

        // Repeated cancel (same priority)
        sched.move_to_cancel_lane(task, 50);
        crate::assert_with_log!(
            sched.len() == 1,
            "still one task after repeat",
            1usize,
            sched.len()
        );

        // Repeated cancel (higher priority)
        sched.move_to_cancel_lane(task, 200);
        crate::assert_with_log!(
            sched.len() == 1,
            "still one task after priority bump",
            1usize,
            sched.len()
        );
        crate::test_complete!("repeated_cancel_requests_are_idempotent");
    }

    #[test]
    fn scheduled_set_collision_slot_clears_when_generations_drain() {
        init_test("scheduled_set_collision_slot_clears_when_generations_drain");
        let mut sched = Scheduler::new();
        let idx = 777_u32;
        let g0 = TaskId::from_arena(ArenaIndex::new(idx, 0));
        let g1 = TaskId::from_arena(ArenaIndex::new(idx, 1));
        let g2 = TaskId::from_arena(ArenaIndex::new(idx, 2));

        // Trigger dense collision tracking for this index.
        sched.schedule(g0, 10);
        sched.schedule(g1, 20);
        assert_eq!(
            sched.scheduled.dense[idx as usize],
            ScheduledSet::DENSE_COLLISION
        );

        // Remove both colliding generations. The slot should collapse back to empty dense state.
        sched.remove(g0);
        sched.remove(g1);
        assert_eq!(sched.scheduled.dense[idx as usize], 0);
        assert!(sched.scheduled.overflow.iter().all(|t| t.0.index() != idx));

        // New generation should use dense storage directly (not overflow fallback).
        sched.schedule(g2, 30);
        assert_ne!(
            sched.scheduled.dense[idx as usize],
            ScheduledSet::DENSE_COLLISION
        );
        assert!(!sched.scheduled.overflow.contains(&g2));
    }

    #[test]
    fn scheduled_set_collision_slot_collapses_to_single_remaining_generation() {
        init_test("scheduled_set_collision_slot_collapses_to_single_remaining_generation");
        let mut sched = Scheduler::new();
        let idx = 314_u32;
        let g0 = TaskId::from_arena(ArenaIndex::new(idx, 0));
        let g1 = TaskId::from_arena(ArenaIndex::new(idx, 1));

        sched.schedule(g0, 10);
        sched.schedule(g1, 20);
        assert_eq!(
            sched.scheduled.dense[idx as usize],
            ScheduledSet::DENSE_COLLISION
        );

        // Remove one generation; the remaining one should be restored to dense tracking.
        sched.remove(g1);
        let expected_tag = u64::from(g0.0.generation()) + 1;
        assert_eq!(sched.scheduled.dense[idx as usize], expected_tag);
        assert!(!sched.scheduled.overflow.contains(&g0));
    }

    #[test]
    fn observability_ignores_stale_lane_entries() {
        init_test("observability_ignores_stale_lane_entries");
        let mut sched = Scheduler::new();
        let stale_cancel = TaskId::new_for_test(910, 0);
        let stale_ready = TaskId::new_for_test(911, 0);
        let stale_timed = TaskId::new_for_test(912, 0);

        sched.cancel_lane.push(SchedulerEntry {
            task: stale_cancel,
            priority: 200,
            generation: 0,
        });
        sched.ready_lane.push(SchedulerEntry {
            task: stale_ready,
            priority: 150,
            generation: 0,
        });
        sched.timed_lane.push(TimedEntry {
            task: stale_timed,
            deadline: Time::from_secs(5),
            generation: 0,
        });

        crate::assert_with_log!(
            !sched.has_cancel_work(),
            "stale cancel entry ignored",
            true,
            !sched.has_cancel_work()
        );
        crate::assert_with_log!(
            !sched.has_ready_work(),
            "stale ready entry ignored",
            true,
            !sched.has_ready_work()
        );
        crate::assert_with_log!(
            !sched.has_timed_work(),
            "stale timed entry ignored",
            true,
            !sched.has_timed_work()
        );
        crate::assert_with_log!(
            !sched.has_runnable_work(Time::from_secs(10)),
            "stale entries do not report runnable work",
            true,
            !sched.has_runnable_work(Time::from_secs(10))
        );
        crate::assert_with_log!(
            sched.next_deadline().is_none(),
            "stale timed entry does not report a deadline",
            true,
            sched.next_deadline().is_none()
        );
        crate::assert_with_log!(
            sched.peek_ready_task().is_none(),
            "stale ready entry does not become peek head",
            true,
            sched.peek_ready_task().is_none()
        );
        crate::assert_with_log!(
            sched.peek_ready_priority().is_none(),
            "stale ready priority ignored",
            true,
            sched.peek_ready_priority().is_none()
        );
        crate::assert_with_log!(
            sched.cancel_lane.is_empty()
                && sched.ready_lane.is_empty()
                && sched.timed_lane.is_empty(),
            "stale heads pruned from all lanes",
            true,
            sched.cancel_lane.is_empty()
                && sched.ready_lane.is_empty()
                && sched.timed_lane.is_empty()
        );
        crate::test_complete!("observability_ignores_stale_lane_entries");
    }

    #[test]
    fn ready_observability_skips_stale_head() {
        init_test("ready_observability_skips_stale_head");
        let mut sched = Scheduler::new();
        let stale_ready = TaskId::new_for_test(920, 0);
        let live_ready = TaskId::new_for_test(921, 0);

        sched.ready_lane.push(SchedulerEntry {
            task: stale_ready,
            priority: 250,
            generation: 0,
        });
        sched.schedule(live_ready, 10);

        crate::assert_with_log!(
            sched.has_ready_work(),
            "live ready work remains visible behind stale head",
            true,
            sched.has_ready_work()
        );
        crate::assert_with_log!(
            sched.peek_ready_task() == Some((live_ready, 10)),
            "peek_ready_task skips stale head",
            Some((live_ready, 10)),
            sched.peek_ready_task()
        );
        crate::assert_with_log!(
            sched.peek_ready_priority() == Some(10),
            "peek_ready_priority skips stale head",
            Some(10u8),
            sched.peek_ready_priority()
        );
        crate::assert_with_log!(
            sched.has_runnable_work(Time::from_nanos(1_000_000_000)),
            "ready work remains runnable despite stale head",
            true,
            sched.has_runnable_work(Time::from_nanos(1_000_000_000))
        );
        crate::assert_with_log!(
            sched.ready_lane.len() == 1,
            "stale ready head pruned to live frontier",
            1usize,
            sched.ready_lane.len()
        );
        crate::test_complete!("ready_observability_skips_stale_head");
    }

    #[test]
    fn timed_observability_skips_stale_head() {
        init_test("timed_observability_skips_stale_head");
        let mut sched = Scheduler::new();
        let stale_timed = TaskId::new_for_test(930, 0);
        let live_timed = TaskId::new_for_test(931, 0);
        let live_deadline = Time::from_secs(8);

        sched.timed_lane.push(TimedEntry {
            task: stale_timed,
            deadline: Time::from_secs(1),
            generation: 0,
        });
        sched.schedule_timed(live_timed, live_deadline);

        crate::assert_with_log!(
            sched.has_timed_work(),
            "live timed work remains visible behind stale head",
            true,
            sched.has_timed_work()
        );
        crate::assert_with_log!(
            sched.next_deadline() == Some(live_deadline),
            "next_deadline ignores stale earlier head",
            Some(live_deadline),
            sched.next_deadline()
        );
        crate::assert_with_log!(
            !sched.has_runnable_work(Time::from_secs(7)),
            "future live deadline remains non-runnable",
            true,
            !sched.has_runnable_work(Time::from_secs(7))
        );
        crate::assert_with_log!(
            sched.has_runnable_work(live_deadline),
            "live timed task becomes runnable at its own deadline",
            true,
            sched.has_runnable_work(live_deadline)
        );
        crate::assert_with_log!(
            sched.timed_lane.len() == 1,
            "stale timed head pruned to live frontier",
            1usize,
            sched.timed_lane.len()
        );
        crate::test_complete!("timed_observability_skips_stale_head");
    }

    // ── Audit regression tests (asupersync-10x0x.78) ─────────────────────

    #[test]
    fn schedule_timed_does_not_move_existing_ready_task() {
        init_test("schedule_timed_does_not_move_existing_ready_task");
        let mut sched = Scheduler::new();

        // Schedule task in ready lane first.
        sched.schedule(task(1), 100);
        assert!(sched.has_ready_work());

        // Attempt to schedule the same task in timed lane — should be a no-op.
        sched.schedule_timed(task(1), Time::from_secs(50));
        crate::assert_with_log!(sched.len() == 1, "still one task", 1usize, sched.len());
        crate::assert_with_log!(
            sched.has_ready_work(),
            "task remains in ready lane",
            true,
            sched.has_ready_work()
        );
        crate::assert_with_log!(
            !sched.has_timed_work(),
            "timed lane stays empty",
            true,
            !sched.has_timed_work()
        );

        // Pop should come from ready lane, not timed.
        let (popped, lane) = sched.pop_with_lane(0).unwrap();
        crate::assert_with_log!(popped == task(1), "correct task", task(1), popped);
        crate::assert_with_log!(
            matches!(lane, DispatchLane::Ready),
            "dispatched from ready lane",
            true,
            true
        );
        crate::test_complete!("schedule_timed_does_not_move_existing_ready_task");
    }

    #[test]
    fn steal_ready_batch_maintains_scheduled_set_invariant() {
        init_test("steal_ready_batch_maintains_scheduled_set_invariant");
        let mut sched = Scheduler::new();
        for i in 0..6 {
            sched.schedule(task(i), 50);
        }
        let before = sched.len();
        crate::assert_with_log!(before == 6, "6 tasks before steal", 6usize, before);

        let stolen = sched.steal_ready_batch(3);
        let after = sched.len();

        // len must decrease by exactly the number stolen.
        crate::assert_with_log!(
            before - after == stolen.len(),
            "len decreases by stolen count",
            stolen.len(),
            before - after
        );

        // None of the stolen tasks should be in the scheduler anymore.
        for (t, _) in &stolen {
            crate::assert_with_log!(
                !sched.is_in_cancel_lane(*t),
                "stolen task not in cancel",
                true,
                true
            );
        }

        // Remaining tasks should still pop correctly.
        let mut remaining = 0;
        while sched.pop().is_some() {
            remaining += 1;
        }
        crate::assert_with_log!(
            remaining == after,
            "remaining tasks pop correctly",
            after,
            remaining
        );
        crate::test_complete!("steal_ready_batch_maintains_scheduled_set_invariant");
    }

    #[test]
    fn dense_tag_at_max_generation_does_not_collide_with_sentinel() {
        init_test("dense_tag_at_max_generation_does_not_collide_with_sentinel");
        let mut sched = Scheduler::new();
        let max_gen = u32::MAX;
        let t = TaskId::from_arena(ArenaIndex::new(0, max_gen));

        // The tag for u32::MAX generation is u32::MAX + 1 = 4294967296.
        // This must NOT equal DENSE_COLLISION (u64::MAX).
        let tag = u64::from(max_gen) + 1;
        assert_ne!(tag, ScheduledSet::DENSE_COLLISION, "tag != sentinel");

        sched.schedule(t, 100);
        crate::assert_with_log!(sched.len() == 1, "inserted", 1usize, sched.len());

        let popped = sched.pop();
        crate::assert_with_log!(popped == Some(t), "popped correctly", Some(t), popped);
        crate::assert_with_log!(sched.is_empty(), "empty after pop", true, sched.is_empty());
        crate::test_complete!("dense_tag_at_max_generation_does_not_collide_with_sentinel");
    }

    #[test]
    fn move_to_cancel_lower_priority_is_noop() {
        init_test("move_to_cancel_lower_priority_is_noop");
        let mut sched = Scheduler::new();

        // Place task in cancel lane with high priority.
        sched.schedule_cancel(task(1), 200);
        sched.schedule_cancel(task(2), 50);

        // Try to "promote" task(1) with lower priority — should be a no-op.
        sched.move_to_cancel_lane(task(1), 100);

        // Task(1) should still come first (higher original priority).
        let first = sched.pop().unwrap();
        let second = sched.pop().unwrap();
        crate::assert_with_log!(
            first == task(1),
            "original high-priority task first",
            task(1),
            first
        );
        crate::assert_with_log!(
            second == task(2),
            "lower-priority task second",
            task(2),
            second
        );
        crate::test_complete!("move_to_cancel_lower_priority_is_noop");
    }

    #[test]
    fn certificate_uses_deterministic_hasher() {
        // Regression: ScheduleCertificate must produce identical hashes across
        // Rust versions. Previously used std DefaultHasher which is not
        // guaranteed stable; now uses DetHasher with a fixed seed.
        let mut c1 = ScheduleCertificate::new();
        c1.record(task(42), DispatchLane::Cancel, 0);
        c1.record(task(7), DispatchLane::Ready, 1);
        c1.record(task(13), DispatchLane::Timed, 2);

        // The hash must be non-zero (meaningful accumulation).
        assert_ne!(c1.hash(), 0, "certificate hash should be non-zero");

        // Running the same sequence again must produce the exact same hash.
        let mut c2 = ScheduleCertificate::new();
        c2.record(task(42), DispatchLane::Cancel, 0);
        c2.record(task(7), DispatchLane::Ready, 1);
        c2.record(task(13), DispatchLane::Timed, 2);

        assert_eq!(
            c1.hash(),
            c2.hash(),
            "identical sequences must produce identical hashes"
        );
        assert!(c1.matches(&c2));
    }

    #[test]
    fn pop_timed_only_with_hint_groups_by_deadline_not_now() {
        init_test("pop_timed_only_with_hint_groups_by_deadline_not_now");
        let mut sched = Scheduler::new();
        let deadline = Time::from_secs(10);

        // Schedule 3 tasks with the same deadline.
        sched.schedule_timed(task(1), deadline);
        sched.schedule_timed(task(2), deadline);
        sched.schedule_timed(task(3), deadline);

        let now = Time::from_secs(100); // well past deadline

        // Pop all three with different rng hints.
        let mut popped = Vec::new();
        for hint in 0..3 {
            if let Some(t) = sched.pop_timed_only_with_hint(hint, now) {
                popped.push(t);
            }
        }

        crate::assert_with_log!(
            popped.len() == 3,
            "all three dispatched",
            3usize,
            popped.len()
        );
        crate::assert_with_log!(
            sched.is_empty(),
            "empty after all pops",
            true,
            sched.is_empty()
        );
        crate::test_complete!("pop_timed_only_with_hint_groups_by_deadline_not_now");
    }

    #[test]
    fn tie_break_index_uses_full_u64_entropy() {
        // Regression: tie-break index must use all 64 bits so scheduling remains
        // deterministic across 32-bit and 64-bit targets.
        let idx = Scheduler::tie_break_index(1u64 << 32, 3);
        assert_eq!(idx, 1);
    }

    // ── ScheduledSet collision path tests (br-3narc.2.1) ─────────────────

    #[test]
    fn scheduled_set_dense_collision_same_index_different_gen() {
        init_test("scheduled_set_dense_collision_same_index_different_gen");
        // Two TaskIds with the same arena index but different generations
        // should trigger DENSE_COLLISION and fall through to overflow.
        let mut set = ScheduledSet::with_capacity(64);
        let t1 = TaskId(ArenaIndex::new(5, 0)); // index=5, gen=0
        let t2 = TaskId(ArenaIndex::new(5, 1)); // index=5, gen=1

        assert!(set.insert(t1), "first insert succeeds");
        assert!(set.insert(t2), "second insert at same index succeeds");
        assert_eq!(set.len(), 2, "both tasks are tracked");

        // Dense slot should be DENSE_COLLISION
        assert_eq!(
            set.dense[5],
            ScheduledSet::DENSE_COLLISION,
            "slot should be in collision mode"
        );

        // Both should be in overflow
        assert!(set.overflow.contains(&t1));
        assert!(set.overflow.contains(&t2));
        crate::test_complete!("scheduled_set_dense_collision_same_index_different_gen");
    }

    #[test]
    fn scheduled_set_collision_collapse_after_remove() {
        init_test("scheduled_set_collision_collapse_after_remove");
        let mut set = ScheduledSet::with_capacity(64);
        let t1 = TaskId(ArenaIndex::new(7, 0));
        let t2 = TaskId(ArenaIndex::new(7, 1));

        set.insert(t1);
        set.insert(t2);
        assert_eq!(set.dense[7], ScheduledSet::DENSE_COLLISION);

        // Remove t1: only t2 remains → should collapse back to dense
        assert!(set.remove(t1));
        assert_eq!(set.len(), 1);

        // After collapse, dense slot should store t2's tag, not DENSE_COLLISION
        let expected_tag = u64::from(t2.0.generation()) + 1;
        assert_eq!(
            set.dense[7], expected_tag,
            "slot should collapse to remaining task's tag"
        );
        // t2 should no longer be in overflow
        assert!(
            !set.overflow.contains(&t2),
            "remaining task should move back to dense tracking"
        );
        crate::test_complete!("scheduled_set_collision_collapse_after_remove");
    }

    #[test]
    fn scheduled_set_collision_no_collapse_with_multiple_remaining() {
        init_test("scheduled_set_collision_no_collapse_with_multiple_remaining");
        let mut set = ScheduledSet::with_capacity(64);
        let t1 = TaskId(ArenaIndex::new(3, 0));
        let t2 = TaskId(ArenaIndex::new(3, 1));
        let t3 = TaskId(ArenaIndex::new(3, 2));

        set.insert(t1);
        set.insert(t2);
        set.insert(t3);
        assert_eq!(set.len(), 3);
        assert_eq!(set.dense[3], ScheduledSet::DENSE_COLLISION);

        // Remove one: two remain → should stay in collision mode
        set.remove(t1);
        assert_eq!(set.len(), 2);
        assert_eq!(
            set.dense[3],
            ScheduledSet::DENSE_COLLISION,
            "slot should stay in collision mode with 2 remaining"
        );
        crate::test_complete!("scheduled_set_collision_no_collapse_with_multiple_remaining");
    }

    #[test]
    fn scheduled_set_dedup_in_collision_mode() {
        init_test("scheduled_set_dedup_in_collision_mode");
        let mut set = ScheduledSet::with_capacity(64);
        let t1 = TaskId(ArenaIndex::new(10, 0));
        let t2 = TaskId(ArenaIndex::new(10, 1));

        set.insert(t1);
        set.insert(t2);
        assert_eq!(set.len(), 2);

        // Re-inserting t1 should be deduplicated
        assert!(!set.insert(t1), "duplicate insert should return false");
        assert_eq!(set.len(), 2, "length should not change on duplicate");
        crate::test_complete!("scheduled_set_dedup_in_collision_mode");
    }

    #[test]
    fn scheduled_set_overflow_for_high_index() {
        init_test("scheduled_set_overflow_for_high_index");
        // TaskId with an index beyond MAX_DENSE_LEN should go straight to overflow
        let mut set = ScheduledSet::with_capacity(64);
        let high_idx = (ScheduledSet::MAX_DENSE_LEN + 100) as u32;
        let t = TaskId(ArenaIndex::new(high_idx, 0));

        assert!(set.insert(t));
        assert_eq!(set.len(), 1);
        assert!(set.overflow.contains(&t));

        assert!(set.remove(t));
        assert_eq!(set.len(), 0);
        crate::test_complete!("scheduled_set_overflow_for_high_index");
    }

    #[test]
    fn scheduled_set_grow_dense_to_fit() {
        init_test("scheduled_set_grow_dense_to_fit");
        // Start with a small set and insert a task beyond initial dense range
        let mut set = ScheduledSet::with_capacity(64);
        let initial_len = set.dense.len();

        // Insert at an index just beyond initial dense capacity
        let idx = (initial_len + 10) as u32;
        let t = TaskId(ArenaIndex::new(idx, 0));
        assert!(set.insert(t));
        assert!(
            set.dense.len() > initial_len,
            "dense vector should have grown"
        );
        assert_eq!(set.len(), 1);

        // Should be in dense path (not overflow)
        let expected_tag = u64::from(t.0.generation()) + 1;
        assert_eq!(set.dense[idx as usize], expected_tag);
        crate::test_complete!("scheduled_set_grow_dense_to_fit");
    }

    // ── Scheduler integration: collision tasks dispatch correctly (br-3narc.2.1) ──

    #[test]
    fn scheduler_handles_collision_tasks_correctly() {
        init_test("scheduler_handles_collision_tasks_correctly");
        let mut sched = Scheduler::new();

        // Schedule two tasks with the same arena index but different generations
        let t1 = TaskId(ArenaIndex::new(5, 0));
        let t2 = TaskId(ArenaIndex::new(5, 1));
        sched.schedule(t1, 50);
        sched.schedule(t2, 100);

        // Both should be dispatchable
        let first = sched.pop();
        let second = sched.pop();

        // Higher priority should come first
        crate::assert_with_log!(
            first == Some(t2),
            "higher priority task dispatches first",
            Some(t2),
            first
        );
        crate::assert_with_log!(
            second == Some(t1),
            "lower priority task dispatches second",
            Some(t1),
            second
        );
        assert!(sched.is_empty());
        crate::test_complete!("scheduler_handles_collision_tasks_correctly");
    }

    // ── ScheduleCertificate determinism across independent runs (br-3narc.2.1) ──

    #[test]
    fn certificate_determinism_independent_schedulers() {
        init_test("certificate_determinism_independent_schedulers");
        // Two independent scheduler instances with same task sequence
        // should produce matching certificates.
        let mut sched1 = Scheduler::new();
        let mut sched2 = Scheduler::new();
        let mut cert1 = ScheduleCertificate::new();
        let mut cert2 = ScheduleCertificate::new();

        // Same sequence of operations on both
        for i in 0..10 {
            sched1.schedule(task(i), (i % 3) as u8 * 50);
            sched2.schedule(task(i), (i % 3) as u8 * 50);
        }

        let mut step = 0u64;
        while let Some((t1, lane1)) = sched1.pop_with_lane(0) {
            let (t2, lane2) = sched2
                .pop_with_lane(0)
                .expect("both should have same tasks");
            assert_eq!(t1, t2, "same dispatch order at step {step}");
            assert_eq!(lane1, lane2, "same lane at step {step}");
            cert1.record(t1, lane1, step);
            cert2.record(t2, lane2, step);
            step += 1;
        }
        assert!(
            sched2.pop().is_none(),
            "both schedulers should drain together"
        );

        crate::assert_with_log!(
            cert1.matches(&cert2),
            "certificates from identical sequences must match",
            true,
            cert1.matches(&cert2)
        );
        crate::assert_with_log!(
            cert1.hash() == cert2.hash(),
            "certificate hashes must be identical",
            cert1.hash(),
            cert2.hash()
        );
        crate::test_complete!("certificate_determinism_independent_schedulers");
    }

    // ── steal_ready_batch_into half-steal invariant (br-3narc.2.1) ────────

    #[test]
    fn steal_ready_batch_into_steals_at_most_half() {
        init_test("steal_ready_batch_into_steals_at_most_half");
        let mut sched = Scheduler::new();
        let total = 20;
        for i in 0..total {
            sched.schedule(task(i), 50);
        }

        let mut buf = Vec::new();
        let count = sched.steal_ready_batch_into(100, &mut buf);

        // Should steal at most half: 20/2 = 10
        crate::assert_with_log!(
            count <= total as usize / 2,
            "steal should take at most half",
            true,
            count <= total as usize / 2
        );
        // Remaining tasks should still be in scheduler
        let remaining = sched.len();
        assert_eq!(
            remaining + count,
            total as usize,
            "stolen + remaining = total"
        );
        crate::test_complete!("steal_ready_batch_into_steals_at_most_half");
    }
