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

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn init_test(test_name: &str) {
        init_test_logging();
        crate::test_phase!(test_name);
    }

    #[test]
    fn wake_and_drain() {
        init_test("wake_and_drain");
        let state = Arc::new(WakerState::new());
        let waker = state.waker_for(task(1));

        crate::test_section!("wake");
        waker.wake_by_ref();

        crate::test_section!("drain");
        let woken = state.drain_woken();
        crate::assert_with_log!(
            woken == vec![task(1)],
            "drain should return the woken task",
            vec![task(1)],
            woken
        );
        let empty = state.drain_woken().is_empty();
        crate::assert_with_log!(empty, "second drain should be empty", true, empty);
        crate::test_complete!("wake_and_drain");
    }

    #[test]
    fn dedup_multiple_wakes() {
        init_test("dedup_multiple_wakes");
        let state = Arc::new(WakerState::new());
        let waker = state.waker_for(task(1));

        crate::test_section!("wake");
        waker.wake_by_ref();
        waker.wake_by_ref();
        waker.wake();

        crate::test_section!("verify");
        let woken = state.drain_woken();
        crate::assert_with_log!(woken.len() == 1, "woken list should dedup", 1, woken.len());
        crate::test_complete!("dedup_multiple_wakes");
    }

    #[test]
    fn wake_after_drain_requeues_task() {
        init_test("wake_after_drain_requeues_task");
        let state = Arc::new(WakerState::new());
        let waker = state.waker_for(task(4));

        waker.wake_by_ref();
        let first = state.drain_woken();
        crate::assert_with_log!(
            first == vec![task(4)],
            "first wake should queue task",
            vec![task(4)],
            first
        );

        waker.wake_by_ref();
        let second = state.drain_woken();
        crate::assert_with_log!(
            second == vec![task(4)],
            "task should be re-queueable after drain",
            vec![task(4)],
            second
        );
        crate::test_complete!("wake_after_drain_requeues_task");
    }

    #[test]
    fn repeated_waker_requests_reuse_live_task_waker() {
        init_test("repeated_waker_requests_reuse_live_task_waker");
        let state = Arc::new(WakerState::new());

        let first = state.waker_for(task(7));
        let second = state.waker_for(task(7));
        crate::assert_with_log!(
            first.will_wake(&second),
            "same task/source should reuse live task waker allocation",
            true,
            first.will_wake(&second)
        );

        let timer = state.waker_for_source(task(7), WakeSource::Timer);
        crate::assert_with_log!(
            !first.will_wake(&timer),
            "different wake source keeps distinct attribution",
            true,
            !first.will_wake(&timer)
        );

        first.wake_by_ref();
        second.wake_by_ref();
        timer.wake_by_ref();
        let woken = state.drain_woken();
        crate::assert_with_log!(
            woken == vec![task(7)],
            "reused and attributed wakers still dedup by task",
            vec![task(7)],
            woken
        );
        crate::test_complete!("repeated_waker_requests_reuse_live_task_waker");
    }

    #[test]
    fn waker_for_source_timer() {
        init_test("waker_for_source_timer");
        let state = Arc::new(WakerState::new());
        let waker = state.waker_for_source(task(1), WakeSource::Timer);

        waker.wake_by_ref();
        let woken = state.drain_woken();
        crate::assert_with_log!(
            woken == vec![task(1)],
            "timer waker should wake task",
            vec![task(1)],
            woken
        );
        crate::test_complete!("waker_for_source_timer");
    }

    #[test]
    fn waker_for_source_io() {
        init_test("waker_for_source_io");
        let state = Arc::new(WakerState::new());
        let waker = state.waker_for_source(task(2), WakeSource::Io { fd: 7 });

        waker.wake();
        let woken = state.drain_woken();
        crate::assert_with_log!(
            woken == vec![task(2)],
            "io waker should wake task",
            vec![task(2)],
            woken
        );
        crate::test_complete!("waker_for_source_io");
    }

    #[test]
    fn waker_for_source_explicit() {
        init_test("waker_for_source_explicit");
        let state = Arc::new(WakerState::new());
        let waker = state.waker_for_source(task(3), WakeSource::Explicit);

        waker.wake_by_ref();
        let woken = state.drain_woken();
        crate::assert_with_log!(
            woken == vec![task(3)],
            "explicit waker should wake task",
            vec![task(3)],
            woken
        );
        crate::test_complete!("waker_for_source_explicit");
    }

    /// Invariant: has_woken returns false when empty, true after wake.
    #[test]
    fn has_woken_tracks_state() {
        init_test("has_woken_tracks_state");
        let state = Arc::new(WakerState::new());
        let has_none = !state.has_woken();
        crate::assert_with_log!(has_none, "no woken initially", true, has_none);

        let waker = state.waker_for(task(1));
        waker.wake_by_ref();
        crate::assert_with_log!(
            state.has_woken(),
            "has woken after wake",
            true,
            state.has_woken()
        );

        state.drain_woken();
        let drained = !state.has_woken();
        crate::assert_with_log!(drained, "no woken after drain", true, drained);
        crate::test_complete!("has_woken_tracks_state");
    }

    /// Invariant: multiple tasks wake independently and drain order is stable.
    #[test]
    fn multi_task_waking_is_deterministically_sorted() {
        init_test("multi_task_waking_is_deterministically_sorted");
        let state = Arc::new(WakerState::new());

        let w1 = state.waker_for(task(10));
        let w2 = state.waker_for(task(20));
        let w3 = state.waker_for(task(30));

        w3.wake();
        w1.wake();
        w2.wake();

        let woken = state.drain_woken();
        let expected = vec![task(10), task(20), task(30)];
        crate::assert_with_log!(woken.len() == 3, "3 tasks woken", 3, woken.len());
        crate::assert_with_log!(
            woken == expected,
            "drain_woken returns stable ascending task order",
            expected,
            woken
        );
        crate::test_complete!("multi_task_waking_is_deterministically_sorted");
    }

    #[test]
    fn wake_source_equality() {
        init_test("wake_source_equality");
        let timer = WakeSource::Timer;
        let io = WakeSource::Io { fd: 3 };
        let explicit = WakeSource::Explicit;
        let unknown = WakeSource::Unknown;

        crate::assert_with_log!(
            timer == WakeSource::Timer,
            "timer eq",
            true,
            timer == WakeSource::Timer
        );
        crate::assert_with_log!(timer != io, "timer != io", true, timer != io);
        crate::assert_with_log!(io != explicit, "io != explicit", true, io != explicit);
        crate::assert_with_log!(
            explicit != unknown,
            "explicit != unknown",
            true,
            explicit != unknown
        );
        crate::assert_with_log!(
            WakeSource::Io { fd: 3 } == WakeSource::Io { fd: 3 },
            "io fd eq",
            true,
            WakeSource::Io { fd: 3 } == WakeSource::Io { fd: 3 }
        );
        crate::assert_with_log!(
            WakeSource::Io { fd: 3 } != WakeSource::Io { fd: 5 },
            "io fd neq",
            true,
            WakeSource::Io { fd: 3 } != WakeSource::Io { fd: 5 }
        );
        crate::test_complete!("wake_source_equality");
    }

    #[test]
    fn wake_source_labels_are_stable() {
        init_test("wake_source_labels_are_stable");
        crate::assert_with_log!(
            WakeSource::Timer.label() == "timer",
            "timer label is stable",
            "timer",
            WakeSource::Timer.label()
        );
        crate::assert_with_log!(
            WakeSource::Io { fd: 9 }.label() == "io",
            "io label is stable",
            "io",
            WakeSource::Io { fd: 9 }.label()
        );
        crate::assert_with_log!(
            WakeSource::Explicit.label() == "explicit",
            "explicit label is stable",
            "explicit",
            WakeSource::Explicit.label()
        );
        crate::assert_with_log!(
            WakeSource::Unknown.label() == "unknown",
            "unknown label is stable",
            "unknown",
            WakeSource::Unknown.label()
        );
        crate::test_complete!("wake_source_labels_are_stable");
    }
