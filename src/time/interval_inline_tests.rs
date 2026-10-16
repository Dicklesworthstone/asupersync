    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    // =========================================================================
    // MissedTickBehavior Tests
    // =========================================================================

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn a_tick_at_time_max_is_the_last_until_reset() {
        init_test("a_tick_at_time_max_is_the_last_until_reset");
        let mut interval = Interval::new(Time::ZERO, Duration::MAX);
        assert_eq!(interval.poll_tick(Time::MAX), Some(Time::ZERO));
        assert_eq!(interval.poll_tick(Time::MAX), Some(Time::MAX));
        assert_eq!(
            interval.poll_tick(Time::MAX),
            None,
            "nothing comes after Time::MAX"
        );
        assert_eq!(interval.tick(Time::MAX), Time::MAX);
        assert_eq!(interval.poll_tick(Time::MAX), None);

        interval.reset_after(Time::ZERO, Duration::from_secs(1));
        assert_eq!(
            interval.poll_tick(Time::from_secs(1)),
            Some(Time::from_secs(1))
        );
    }

    #[test]
    fn missed_tick_behavior_default_is_burst() {
        init_test("missed_tick_behavior_default_is_burst");
        crate::assert_with_log!(
            MissedTickBehavior::default() == MissedTickBehavior::Burst,
            "default behavior",
            MissedTickBehavior::Burst,
            MissedTickBehavior::default()
        );
        crate::test_complete!("missed_tick_behavior_default_is_burst");
    }

    #[test]
    fn missed_tick_behavior_constructors() {
        init_test("missed_tick_behavior_constructors");
        crate::assert_with_log!(
            MissedTickBehavior::burst() == MissedTickBehavior::Burst,
            "burst",
            MissedTickBehavior::Burst,
            MissedTickBehavior::burst()
        );
        crate::assert_with_log!(
            MissedTickBehavior::delay() == MissedTickBehavior::Delay,
            "delay",
            MissedTickBehavior::Delay,
            MissedTickBehavior::delay()
        );
        crate::assert_with_log!(
            MissedTickBehavior::skip() == MissedTickBehavior::Skip,
            "skip",
            MissedTickBehavior::Skip,
            MissedTickBehavior::skip()
        );
        crate::test_complete!("missed_tick_behavior_constructors");
    }

    #[test]
    fn missed_tick_behavior_display() {
        init_test("missed_tick_behavior_display");
        let burst = format!("{}", MissedTickBehavior::Burst);
        let delay = format!("{}", MissedTickBehavior::Delay);
        let skip = format!("{}", MissedTickBehavior::Skip);
        crate::assert_with_log!(burst == "Burst", "display burst", "Burst", burst);
        crate::assert_with_log!(delay == "Delay", "display delay", "Delay", delay);
        crate::assert_with_log!(skip == "Skip", "display skip", "Skip", skip);
        crate::test_complete!("missed_tick_behavior_display");
    }

    // =========================================================================
    // Interval Construction Tests
    // =========================================================================

    #[test]
    fn interval_new() {
        init_test("interval_new");
        let interval = Interval::new(Time::from_secs(5), Duration::from_millis(100));
        crate::assert_with_log!(
            interval.deadline() == Time::from_secs(5),
            "deadline",
            Time::from_secs(5),
            interval.deadline()
        );
        crate::assert_with_log!(
            interval.period() == Duration::from_millis(100),
            "period",
            Duration::from_millis(100),
            interval.period()
        );
        crate::assert_with_log!(
            interval.missed_tick_behavior() == MissedTickBehavior::Burst,
            "missed tick behavior",
            MissedTickBehavior::Burst,
            interval.missed_tick_behavior()
        );
        crate::test_complete!("interval_new");
    }

    #[test]
    #[should_panic(expected = "interval period must be non-zero")]
    fn interval_zero_period_panics() {
        init_test("interval_zero_period_panics");
        let _ = Interval::new(Time::ZERO, Duration::ZERO);
    }

    #[test]
    fn interval_function() {
        init_test("interval_function");
        let int = interval(Time::from_secs(10), Duration::from_millis(50));
        crate::assert_with_log!(
            int.deadline() == Time::from_secs(10),
            "deadline",
            Time::from_secs(10),
            int.deadline()
        );
        crate::assert_with_log!(
            int.period() == Duration::from_millis(50),
            "period",
            Duration::from_millis(50),
            int.period()
        );
        crate::test_complete!("interval_function");
    }

    #[test]
    fn interval_at_function() {
        init_test("interval_at_function");
        let int = interval_at(Time::from_secs(5), Duration::from_millis(25));
        crate::assert_with_log!(
            int.deadline() == Time::from_secs(5),
            "deadline",
            Time::from_secs(5),
            int.deadline()
        );
        crate::assert_with_log!(
            int.period() == Duration::from_millis(25),
            "period",
            Duration::from_millis(25),
            int.period()
        );
        crate::test_complete!("interval_at_function");
    }

    // =========================================================================
    // Basic Tick Tests
    // =========================================================================

    #[test]
    fn tick_first_is_at_start_time() {
        init_test("tick_first_is_at_start_time");
        let mut interval = Interval::new(Time::from_secs(1), Duration::from_millis(100));
        let tick = interval.tick(Time::from_secs(1));
        crate::assert_with_log!(tick == Time::from_secs(1), "tick", Time::from_secs(1), tick);
        crate::test_complete!("tick_first_is_at_start_time");
    }

    #[test]
    fn tick_advances_by_period() {
        init_test("tick_advances_by_period");
        let mut interval = Interval::new(Time::ZERO, Duration::from_millis(100));

        let t0 = interval.tick(Time::ZERO);
        crate::assert_with_log!(t0 == Time::ZERO, "tick 0", Time::ZERO, t0);
        let t1 = interval.tick(Time::from_millis(100));
        crate::assert_with_log!(
            t1 == Time::from_millis(100),
            "tick 100",
            Time::from_millis(100),
            t1
        );
        let t2 = interval.tick(Time::from_millis(200));
        crate::assert_with_log!(
            t2 == Time::from_millis(200),
            "tick 200",
            Time::from_millis(200),
            t2
        );
        crate::test_complete!("tick_advances_by_period");
    }

    #[test]
    fn tick_before_deadline_returns_deadline_without_advancing() {
        init_test("tick_before_deadline_returns_deadline_without_advancing");
        let mut interval = Interval::new(Time::from_secs(1), Duration::from_millis(100));

        let early = interval.tick(Time::from_millis(500));
        crate::assert_with_log!(
            early == Time::from_secs(1),
            "early tick observes deadline",
            Time::from_secs(1),
            early
        );
        crate::assert_with_log!(
            interval.deadline() == Time::from_secs(1),
            "deadline preserved",
            Time::from_secs(1),
            interval.deadline()
        );

        let first = interval.tick(Time::from_secs(1));
        crate::assert_with_log!(
            first == Time::from_secs(1),
            "first ready tick",
            Time::from_secs(1),
            first
        );
        crate::assert_with_log!(
            interval.deadline() == Time::from_millis(1100),
            "deadline advances only after ready tick",
            Time::from_millis(1100),
            interval.deadline()
        );
        crate::test_complete!("tick_before_deadline_returns_deadline_without_advancing");
    }

    #[test]
    fn tick_multiple_periods() {
        init_test("tick_multiple_periods");
        let mut interval = Interval::new(Time::ZERO, Duration::from_secs(1));

        for i in 0..10 {
            let expected = Time::from_secs(i);
            let actual = interval.tick(expected);
            crate::assert_with_log!(actual == expected, "tick", expected, actual);
        }
        crate::test_complete!("tick_multiple_periods");
    }

    // =========================================================================
    // Poll Tick Tests
    // =========================================================================

    #[test]
    fn poll_tick_before_deadline() {
        init_test("poll_tick_before_deadline");
        let mut interval = Interval::new(Time::from_secs(1), Duration::from_millis(100));
        // Skip first tick
        interval.tick(Time::from_secs(1));

        // Now deadline is at 1.1s, poll at 1.05s should return None
        let expected: Option<Time> = None;
        let actual = interval.poll_tick(Time::from_millis(1050));
        crate::assert_with_log!(actual == expected, "poll before deadline", expected, actual);
        crate::test_complete!("poll_tick_before_deadline");
    }

    #[test]
    fn poll_tick_at_deadline() {
        init_test("poll_tick_at_deadline");
        let mut interval = Interval::new(Time::from_secs(1), Duration::from_millis(100));
        interval.tick(Time::from_secs(1));

        // Deadline is at 1.1s
        let tick = interval.poll_tick(Time::from_millis(1100));
        let expected = Some(Time::from_millis(1100));
        crate::assert_with_log!(tick == expected, "poll at deadline", expected, tick);
        crate::test_complete!("poll_tick_at_deadline");
    }

    #[test]
    fn poll_tick_after_deadline() {
        init_test("poll_tick_after_deadline");
        let mut interval = Interval::new(Time::from_secs(1), Duration::from_millis(100));
        interval.tick(Time::from_secs(1));

        // Poll past deadline
        let tick = interval.poll_tick(Time::from_millis(1200));
        let expected = Some(Time::from_millis(1100));
        crate::assert_with_log!(tick == expected, "poll after deadline", expected, tick);
        crate::test_complete!("poll_tick_after_deadline");
    }

    // =========================================================================
    // Missed Tick Behavior: Burst Tests
    // =========================================================================

    #[test]
    fn burst_catches_up_missed_ticks() {
        init_test("burst_catches_up_missed_ticks");
        let mut interval = Interval::new(Time::ZERO, Duration::from_millis(100));
        interval.set_missed_tick_behavior(MissedTickBehavior::Burst);

        // First tick
        let first = interval.tick(Time::ZERO);
        crate::assert_with_log!(first == Time::ZERO, "first tick", Time::ZERO, first);

        // Miss several ticks - advance to 350ms
        // In Burst mode, we should get ticks at 100, 200, 300 by calling tick repeatedly
        let tick1 = interval.tick(Time::from_millis(350));
        crate::assert_with_log!(
            tick1 == Time::from_millis(100),
            "first missed tick",
            Time::from_millis(100),
            tick1
        );

        let tick2 = interval.tick(Time::from_millis(350));
        crate::assert_with_log!(
            tick2 == Time::from_millis(200),
            "second missed tick",
            Time::from_millis(200),
            tick2
        );

        let tick3 = interval.tick(Time::from_millis(350));
        crate::assert_with_log!(
            tick3 == Time::from_millis(300),
            "third missed tick",
            Time::from_millis(300),
            tick3
        );

        // Now deadline should be at 400ms
        crate::assert_with_log!(
            interval.deadline() == Time::from_millis(400),
            "deadline after catch-up",
            Time::from_millis(400),
            interval.deadline()
        );
        crate::test_complete!("burst_catches_up_missed_ticks");
    }

    // =========================================================================
    // Missed Tick Behavior: Delay Tests
    // =========================================================================

    #[test]
    fn delay_resets_from_now() {
        init_test("delay_resets_from_now");
        let mut interval = Interval::new(Time::ZERO, Duration::from_millis(100));
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        // First tick
        let first = interval.tick(Time::ZERO);
        crate::assert_with_log!(first == Time::ZERO, "first tick", Time::ZERO, first);

        // Miss several ticks - advance to 350ms
        let tick = interval.tick(Time::from_millis(350));
        crate::assert_with_log!(
            tick == Time::from_millis(100),
            "tick returns deadline",
            Time::from_millis(100),
            tick
        );

        // But next deadline is 100ms from 350ms = 450ms
        crate::assert_with_log!(
            interval.deadline() == Time::from_millis(450),
            "deadline reset",
            Time::from_millis(450),
            interval.deadline()
        );
        crate::test_complete!("delay_resets_from_now");
    }

    // =========================================================================
    // Missed Tick Behavior: Skip Tests
    // =========================================================================

    #[test]
    fn skip_jumps_to_next_aligned() {
        init_test("skip_jumps_to_next_aligned");
        let mut interval = Interval::new(Time::ZERO, Duration::from_millis(100));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // First tick
        let first = interval.tick(Time::ZERO);
        crate::assert_with_log!(first == Time::ZERO, "first tick", Time::ZERO, first);

        // Miss several ticks - advance to 350ms
        let tick = interval.tick(Time::from_millis(350));
        crate::assert_with_log!(
            tick == Time::from_millis(100),
            "tick returns deadline",
            Time::from_millis(100),
            tick
        );

        // Skip should jump to next aligned: 400ms (4 periods from start)
        crate::assert_with_log!(
            interval.deadline() == Time::from_millis(400),
            "deadline aligned",
            Time::from_millis(400),
            interval.deadline()
        );
        crate::test_complete!("skip_jumps_to_next_aligned");
    }

    #[test]
    fn skip_aligns_correctly() {
        init_test("skip_aligns_correctly");
        let mut interval = Interval::new(Time::ZERO, Duration::from_millis(100));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // First tick
        interval.tick(Time::ZERO);

        // Jump way ahead to 999ms
        interval.tick(Time::from_millis(999));

        // Should align to 1000ms (next multiple of 100 after 999)
        crate::assert_with_log!(
            interval.deadline() == Time::from_millis(1000),
            "deadline aligned",
            Time::from_millis(1000),
            interval.deadline()
        );
        crate::test_complete!("skip_aligns_correctly");
    }

    #[test]
    fn tick_and_poll_tick_ready_paths_match_state_transition() {
        init_test("tick_and_poll_tick_ready_paths_match_state_transition");

        let cases = [
            (MissedTickBehavior::Burst, Time::from_millis(100)),
            (MissedTickBehavior::Burst, Time::from_millis(350)),
            (MissedTickBehavior::Delay, Time::from_millis(100)),
            (MissedTickBehavior::Delay, Time::from_millis(350)),
            (MissedTickBehavior::Skip, Time::from_millis(100)),
            (MissedTickBehavior::Skip, Time::from_millis(350)),
        ];

        for (behavior, now) in cases {
            let mut poll_interval = Interval::new(Time::ZERO, Duration::from_millis(100));
            poll_interval.set_missed_tick_behavior(behavior);
            let first_poll = poll_interval.poll_tick(Time::ZERO);

            let mut tick_interval = Interval::new(Time::ZERO, Duration::from_millis(100));
            tick_interval.set_missed_tick_behavior(behavior);
            let first_tick = tick_interval.tick(Time::ZERO);

            crate::assert_with_log!(
                first_poll == Some(first_tick),
                "initial tick relation",
                Some(first_tick),
                first_poll
            );

            let polled = poll_interval.poll_tick(now);
            let ticked = tick_interval.tick(now);

            crate::assert_with_log!(
                polled == Some(ticked),
                "ready tick output relation",
                Some(ticked),
                polled
            );
            crate::assert_with_log!(
                poll_interval.deadline() == tick_interval.deadline(),
                "ready tick deadline transition",
                tick_interval.deadline(),
                poll_interval.deadline()
            );
        }

        crate::test_complete!("tick_and_poll_tick_ready_paths_match_state_transition");
    }

    // =========================================================================
    // Reset Tests
    // =========================================================================

    #[test]
    fn reset_changes_deadline() {
        init_test("reset_changes_deadline");
        let mut interval = Interval::new(Time::ZERO, Duration::from_millis(100));

        interval.tick(Time::ZERO);
        crate::assert_with_log!(
            interval.deadline() == Time::from_millis(100),
            "initial deadline",
            Time::from_millis(100),
            interval.deadline()
        );

        interval.reset(Time::from_secs(10));
        crate::assert_with_log!(
            interval.deadline() == Time::from_secs(10),
            "reset deadline",
            Time::from_secs(10),
            interval.deadline()
        );

        // First tick after reset is at reset time
        let tick = interval.tick(Time::from_secs(10));
        crate::assert_with_log!(
            tick == Time::from_secs(10),
            "tick after reset",
            Time::from_secs(10),
            tick
        );
        crate::test_complete!("reset_changes_deadline");
    }

    #[test]
    fn reset_at() {
        init_test("reset_at");
        let mut interval = Interval::new(Time::ZERO, Duration::from_millis(100));
        interval.reset_at(Time::from_millis(500));
        crate::assert_with_log!(
            interval.deadline() == Time::from_millis(500),
            "reset_at deadline",
            Time::from_millis(500),
            interval.deadline()
        );
        crate::test_complete!("reset_at");
    }

    #[test]
    fn reset_after() {
        init_test("reset_after");
        let mut interval = Interval::new(Time::ZERO, Duration::from_millis(100));
        interval.reset_after(Time::from_secs(5), Duration::from_millis(200));
        crate::assert_with_log!(
            interval.deadline() == Time::from_millis(5200),
            "reset_after deadline",
            Time::from_millis(5200),
            interval.deadline()
        );
        crate::test_complete!("reset_after");
    }

    // =========================================================================
    // Utility Methods Tests
    // =========================================================================

    #[test]
    fn remaining_before_deadline() {
        init_test("remaining_before_deadline");
        let interval = Interval::new(Time::from_secs(10), Duration::from_millis(100));
        let remaining = interval.remaining(Time::from_secs(9));
        crate::assert_with_log!(
            remaining == Duration::from_secs(1),
            "remaining before deadline",
            Duration::from_secs(1),
            remaining
        );
        crate::test_complete!("remaining_before_deadline");
    }

    #[test]
    fn remaining_at_deadline() {
        init_test("remaining_at_deadline");
        let interval = Interval::new(Time::from_secs(10), Duration::from_millis(100));
        let remaining = interval.remaining(Time::from_secs(10));
        crate::assert_with_log!(
            remaining == Duration::ZERO,
            "remaining at deadline",
            Duration::ZERO,
            remaining
        );
        crate::test_complete!("remaining_at_deadline");
    }

    #[test]
    fn remaining_after_deadline() {
        init_test("remaining_after_deadline");
        let interval = Interval::new(Time::from_secs(10), Duration::from_millis(100));
        let remaining = interval.remaining(Time::from_secs(15));
        crate::assert_with_log!(
            remaining == Duration::ZERO,
            "remaining after deadline",
            Duration::ZERO,
            remaining
        );
        crate::test_complete!("remaining_after_deadline");
    }

    #[test]
    fn is_ready_checks_deadline() {
        init_test("is_ready_checks_deadline");
        let interval = Interval::new(Time::from_secs(10), Duration::from_millis(100));

        let before = interval.is_ready(Time::from_secs(9));
        crate::assert_with_log!(!before, "ready before deadline", false, before);
        let at = interval.is_ready(Time::from_secs(10));
        crate::assert_with_log!(at, "ready at deadline", true, at);
        let after = interval.is_ready(Time::from_secs(11));
        crate::assert_with_log!(after, "ready after deadline", true, after);
        crate::test_complete!("is_ready_checks_deadline");
    }

    #[test]
    fn set_missed_tick_behavior() {
        init_test("set_missed_tick_behavior");
        let mut interval = Interval::new(Time::ZERO, Duration::from_millis(100));

        crate::assert_with_log!(
            interval.missed_tick_behavior() == MissedTickBehavior::Burst,
            "default behavior",
            MissedTickBehavior::Burst,
            interval.missed_tick_behavior()
        );

        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        crate::assert_with_log!(
            interval.missed_tick_behavior() == MissedTickBehavior::Skip,
            "updated behavior",
            MissedTickBehavior::Skip,
            interval.missed_tick_behavior()
        );
        crate::test_complete!("set_missed_tick_behavior");
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn very_small_period() {
        init_test("very_small_period");
        let mut interval = Interval::new(Time::ZERO, Duration::from_nanos(1));
        let first = interval.tick(Time::ZERO);
        crate::assert_with_log!(first == Time::ZERO, "first tick", Time::ZERO, first);
        let second = interval.tick(Time::from_nanos(1));
        crate::assert_with_log!(
            second == Time::from_nanos(1),
            "second tick",
            Time::from_nanos(1),
            second
        );
        crate::test_complete!("very_small_period");
    }

    #[test]
    fn very_large_period() {
        init_test("very_large_period");
        let mut interval = Interval::new(Time::ZERO, Duration::from_secs(31_536_000)); // 1 year
        let first = interval.tick(Time::ZERO);
        crate::assert_with_log!(first == Time::ZERO, "first tick", Time::ZERO, first);
        let period = interval.period();
        crate::assert_with_log!(
            period == Duration::from_secs(31_536_000),
            "period",
            Duration::from_secs(31_536_000),
            period
        );
        crate::test_complete!("very_large_period");
    }

    #[test]
    fn deadline_near_max() {
        init_test("deadline_near_max");
        let mut interval = Interval::new(
            Time::from_nanos(u64::MAX - 1_000_000_000),
            Duration::from_secs(1),
        );

        // First tick should be at the start time
        let tick = interval.tick(Time::from_nanos(u64::MAX - 1_000_000_000));
        crate::assert_with_log!(
            tick == Time::from_nanos(u64::MAX - 1_000_000_000),
            "first tick",
            Time::from_nanos(u64::MAX - 1_000_000_000),
            tick
        );

        // Next deadline should saturate at MAX
        crate::assert_with_log!(
            interval.deadline() == Time::MAX,
            "deadline saturates",
            Time::MAX,
            interval.deadline()
        );
        crate::test_complete!("deadline_near_max");
    }

    #[test]
    fn duration_max_period_saturates_first_tick_deadline() {
        init_test("duration_max_period_saturates_first_tick_deadline");
        let start = Time::from_nanos(7);
        let mut interval = Interval::new(start, Duration::MAX);

        let tick = interval.tick(start);
        crate::assert_with_log!(tick == start, "first tick", start, tick);
        crate::assert_with_log!(
            interval.deadline() == Time::MAX,
            "deadline saturates",
            Time::MAX,
            interval.deadline()
        );
        crate::test_complete!("duration_max_period_saturates_first_tick_deadline");
    }

    #[test]
    fn poll_tick_with_duration_max_period_saturates_deadline() {
        init_test("poll_tick_with_duration_max_period_saturates_deadline");
        let start = Time::from_nanos(11);
        let mut interval = Interval::new(start, Duration::MAX);

        let tick = interval.poll_tick(start);
        crate::assert_with_log!(tick == Some(start), "poll tick", Some(start), tick);
        crate::assert_with_log!(
            interval.deadline() == Time::MAX,
            "deadline saturates after poll_tick",
            Time::MAX,
            interval.deadline()
        );
        crate::test_complete!("poll_tick_with_duration_max_period_saturates_deadline");
    }

    #[test]
    fn reset_after_duration_max_saturates_deadline() {
        init_test("reset_after_duration_max_saturates_deadline");
        let mut interval = Interval::new(Time::ZERO, Duration::from_millis(100));
        interval.reset_after(Time::from_nanos(42), Duration::MAX);

        crate::assert_with_log!(
            interval.deadline() == Time::MAX,
            "reset_after saturates",
            Time::MAX,
            interval.deadline()
        );
        crate::test_complete!("reset_after_duration_max_saturates_deadline");
    }

    #[test]
    fn clone_creates_independent_copy() {
        init_test("clone_creates_independent_copy");
        let mut interval1 = Interval::new(Time::ZERO, Duration::from_millis(100));
        interval1.tick(Time::ZERO);

        let interval2 = interval1.clone();

        // Both should have same state
        let deadline1 = interval1.deadline();
        let deadline2 = interval2.deadline();
        crate::assert_with_log!(
            deadline1 == deadline2,
            "deadlines match",
            deadline1,
            deadline2
        );

        // Advancing one doesn't affect the other
        interval1.tick(Time::from_millis(100));
        let advanced_deadline1 = interval1.deadline();
        let advanced_deadline2 = interval2.deadline();
        crate::assert_with_log!(
            advanced_deadline1 != advanced_deadline2,
            "deadlines diverge",
            "not equal",
            (advanced_deadline1, advanced_deadline2)
        );
        crate::test_complete!("clone_creates_independent_copy");
    }

    // --- wave 77 trait coverage ---

    #[test]
    fn missed_tick_behavior_debug_clone_copy_eq_hash_default() {
        use std::collections::HashSet;

        fn assert_clone<T: Clone>() {}
        fn assert_copy<T: Copy>() {}

        let b = MissedTickBehavior::default();
        assert_eq!(b, MissedTickBehavior::Burst);
        assert_clone::<MissedTickBehavior>();
        assert_copy::<MissedTickBehavior>();
        assert_ne!(b, MissedTickBehavior::Delay);
        assert_ne!(b, MissedTickBehavior::Skip);
        let dbg = format!("{b:?}");
        assert!(dbg.contains("Burst"));
        let mut set = HashSet::new();
        set.insert(b);
        assert!(set.contains(&MissedTickBehavior::Burst));
    }
