    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::cx::Cx;
    use crate::test_utils::init_test_logging;
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::task::{Context, Waker};

    // =========================================================================
    // Construction Tests
    // =========================================================================

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    static CURRENT_TIME: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn wall_now_falls_back_when_current_cx_has_no_timer_driver() {
        init_test("wall_now_falls_back_when_current_cx_has_no_timer_driver");

        let cx = Cx::new(
            RegionId::new_for_test(0, 6),
            TaskId::new_for_test(0, 6),
            Budget::INFINITE,
        );
        let _guard = Cx::set_current(Some(cx));

        let first = wall_now();
        let second = wall_now();

        crate::assert_with_log!(
            second >= first,
            "wall clock remains monotonic",
            true,
            second >= first
        );
        crate::test_complete!("wall_now_falls_back_when_current_cx_has_no_timer_driver");
    }

    /// Regression: the production [`WallClock`](crate::time::driver::WallClock)
    /// timer driver and `wall_now()`'s capability-free fallback must measure
    /// elapsed time from the *same* process epoch.
    ///
    /// Before the fix each `WallClock::new()` captured its own
    /// `Instant::now()` epoch, distinct from `wall_now()`'s `START_TIME`
    /// fallback epoch. A request-budget deadline computed via `wall_now()` was
    /// then evaluated by the deadline monitor against `timer_driver.now()` on a
    /// *different* epoch; once process uptime exceeded the request timeout every
    /// such request was born already past its deadline and cancelled
    /// immediately — surfacing as spurious "pool acquire cancelled" DB failures
    /// under load.
    #[test]
    fn wall_clock_instances_share_process_epoch() {
        use crate::time::driver::{TimeSource, WallClock};
        init_test("wall_clock_instances_share_process_epoch");

        let first = WallClock::new();
        std::thread::sleep(Duration::from_millis(20));
        let second = WallClock::new();

        let a = first.now().as_nanos();
        let b = second.now().as_nanos();

        // Same shared epoch => readings taken back-to-back agree within a small
        // delta, NOT separated by the 20ms gap a per-instance epoch produces.
        let delta = a.abs_diff(b);
        crate::assert_with_log!(
            delta < 5_000_000,
            "WallClock instances share one process epoch (delta < 5ms)",
            true,
            delta < 5_000_000
        );
        // The later clock measures from the earlier shared epoch, so it observes
        // the 20ms that elapsed before it was even constructed.
        crate::assert_with_log!(
            b >= 15_000_000,
            "later WallClock observes pre-construction elapsed time",
            true,
            b >= 15_000_000
        );
        crate::test_complete!("wall_clock_instances_share_process_epoch");
    }

    fn get_time() -> Time {
        Time::from_nanos(CURRENT_TIME.load(Ordering::SeqCst))
    }

    #[test]
    fn new_creates_sleep_with_deadline() {
        init_test("new_creates_sleep_with_deadline");
        let sleep = Sleep::new(Time::from_secs(5));
        crate::assert_with_log!(
            sleep.deadline() == Time::from_secs(5),
            "deadline",
            Time::from_secs(5),
            sleep.deadline()
        );
        crate::assert_with_log!(!sleep.was_polled(), "not polled", false, sleep.was_polled());
        crate::test_complete!("new_creates_sleep_with_deadline");
    }

    #[test]
    fn after_computes_deadline() {
        init_test("after_computes_deadline");
        let now = Time::from_secs(10);
        let sleep = Sleep::after(now, Duration::from_secs(5));
        crate::assert_with_log!(
            sleep.deadline() == Time::from_secs(15),
            "deadline",
            Time::from_secs(15),
            sleep.deadline()
        );
        crate::test_complete!("after_computes_deadline");
    }

    #[test]
    fn after_saturates() {
        init_test("after_saturates");
        let now = Time::from_nanos(u64::MAX - 1000);
        let sleep = Sleep::after(now, Duration::from_secs(1));
        crate::assert_with_log!(
            sleep.deadline() == Time::MAX,
            "deadline",
            Time::MAX,
            sleep.deadline()
        );
        crate::test_complete!("after_saturates");
    }

    #[test]
    fn sleep_function() {
        init_test("sleep_function");
        let now = Time::from_millis(100);
        let s = sleep(now, Duration::from_millis(50));
        crate::assert_with_log!(
            s.deadline() == Time::from_millis(150),
            "deadline",
            Time::from_millis(150),
            s.deadline()
        );
        crate::test_complete!("sleep_function");
    }

    #[test]
    fn sleep_until_function() {
        init_test("sleep_until_function");
        let s = sleep_until(Time::from_secs(42));
        crate::assert_with_log!(
            s.deadline() == Time::from_secs(42),
            "deadline",
            Time::from_secs(42),
            s.deadline()
        );
        crate::test_complete!("sleep_until_function");
    }

    // =========================================================================
    // Time Getter Tests
    // =========================================================================

    #[test]
    fn with_time_getter() {
        init_test("with_time_getter");
        CURRENT_TIME.store(0, Ordering::SeqCst);

        let sleep = Sleep::with_time_getter(Time::from_secs(5), get_time);

        // Time is 0, should be pending
        let elapsed = sleep.is_elapsed(get_time());
        crate::assert_with_log!(!elapsed, "not elapsed", false, elapsed);

        // Advance time past deadline
        CURRENT_TIME.store(6_000_000_000, Ordering::SeqCst);
        let elapsed = sleep.is_elapsed(get_time());
        crate::assert_with_log!(elapsed, "elapsed", true, elapsed);
        crate::test_complete!("with_time_getter");
    }

    #[test]
    fn custom_time_getter_wakes_promptly_after_logical_time_advance() {
        init_test("custom_time_getter_wakes_promptly_after_logical_time_advance");
        CURRENT_TIME.store(0, Ordering::SeqCst);

        let woken = Arc::new(AtomicBool::new(false));
        let waker = waker_that_sets(Arc::clone(&woken));
        let mut task_cx = Context::from_waker(&waker);
        let mut sleep = Sleep::with_time_getter(Time::from_secs(10), get_time);

        let first = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            first.is_pending(),
            "first pending",
            true,
            first.is_pending()
        );

        CURRENT_TIME.store(Time::from_secs(10).as_nanos(), Ordering::SeqCst);

        let wait_deadline = Instant::now() + Duration::from_millis(500);
        while !woken.load(Ordering::SeqCst) && Instant::now() < wait_deadline {
            std::thread::sleep(Duration::from_millis(1));
        }

        let woke = woken.load(Ordering::SeqCst);
        crate::assert_with_log!(woke, "waker fired", true, woke);

        let second = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(second.is_ready(), "second ready", true, second.is_ready());
        crate::test_complete!("custom_time_getter_wakes_promptly_after_logical_time_advance");
    }

    thread_local! {
        static DRIVER_CUSTOM_TIME: std::cell::Cell<Time> = const { std::cell::Cell::new(Time::ZERO) };
    }

    fn driver_custom_now() -> Time {
        DRIVER_CUSTOM_TIME.with(std::cell::Cell::get)
    }

    fn custom_clock_context(timer: &TimerDriverHandle) -> Cx {
        Cx::new_with_drivers(
            RegionId::new_for_test(0, 120),
            TaskId::new_for_test(0, 120),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        )
    }

    #[test]
    fn custom_clock_sleep_translates_remaining_duration_across_epochs() {
        for (driver_start, custom_start) in [(100, 0), (0, 100), (100, 100)] {
            let clock = Arc::new(VirtualClock::new());
            clock.set(Time::from_secs(driver_start));
            let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
            let _current = Cx::set_current(Some(custom_clock_context(&timer)));
            DRIVER_CUSTOM_TIME.with(|now| now.set(Time::from_secs(custom_start)));
            let mut sleep =
                Sleep::with_time_getter(Time::from_secs(custom_start + 5), driver_custom_now);
            let woke = Arc::new(AtomicBool::new(false));
            let waker = waker_that_sets(Arc::clone(&woke));
            let mut cx = Context::from_waker(&waker);

            assert!(Pin::new(&mut sleep).poll(&mut cx).is_pending());
            assert_eq!(timer.pending_count(), 1);
            assert_eq!(
                timer.next_deadline(),
                Some(Time::from_secs(driver_start + 5))
            );
            assert!(sleep.state.lock().fallback.is_none());

            clock.set(Time::from_secs(driver_start + 5));
            DRIVER_CUSTOM_TIME.with(|now| now.set(Time::from_secs(custom_start + 5)));
            assert_eq!(timer.process_timers(), 1);
            assert!(woke.load(Ordering::SeqCst));
            assert!(Pin::new(&mut sleep).poll(&mut cx).is_ready());
            assert_eq!(timer.pending_count(), 0);
        }
    }

    #[test]
    fn custom_clock_driver_wake_rearms_until_its_own_deadline() {
        let clock = Arc::new(VirtualClock::new());
        clock.set(Time::from_secs(100));
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let _current = Cx::set_current(Some(custom_clock_context(&timer)));
        DRIVER_CUSTOM_TIME.with(|now| now.set(Time::ZERO));
        let mut sleep = Sleep::with_time_getter(Time::from_secs(5), driver_custom_now);
        let old_woke = Arc::new(AtomicBool::new(false));
        let old_waker = waker_that_sets(Arc::clone(&old_woke));
        let mut old_cx = Context::from_waker(&old_waker);
        assert!(Pin::new(&mut sleep).poll(&mut old_cx).is_pending());

        let woke = Arc::new(AtomicBool::new(false));
        let waker = waker_that_sets(Arc::clone(&woke));
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut sleep).poll(&mut cx).is_pending());
        clock.set(Time::from_secs(105));
        assert_eq!(timer.process_timers(), 1);
        assert!(!old_woke.load(Ordering::SeqCst));
        assert!(woke.load(Ordering::SeqCst));
        assert!(Pin::new(&mut sleep).poll(&mut cx).is_pending());
        assert_eq!(timer.next_deadline(), Some(Time::from_secs(110)));
        assert_eq!(timer.pending_count(), 1);

        clock.set(Time::from_secs(110));
        assert_eq!(timer.process_timers(), 1);
        assert!(sleep.poll_with_time(Time::ZERO).is_pending());
        assert_eq!(timer.pending_count(), 0);
        assert!(Pin::new(&mut sleep).poll(&mut cx).is_pending());
        assert_eq!(timer.next_deadline(), Some(Time::from_secs(115)));

        DRIVER_CUSTOM_TIME.with(|now| now.set(Time::from_secs(5)));
        assert!(Pin::new(&mut sleep).poll(&mut cx).is_ready());
        assert_eq!(timer.pending_count(), 0);
    }

    #[test]
    fn custom_clock_migration_reset_and_drop_retire_the_registered_driver() {
        DRIVER_CUSTOM_TIME.with(|now| now.set(Time::from_secs(100)));
        let first_clock = Arc::new(VirtualClock::new());
        let first = TimerDriverHandle::with_virtual_clock(first_clock);
        let _first_current = Cx::set_current(Some(custom_clock_context(&first)));
        let mut sleep = Sleep::with_time_getter(Time::from_secs(110), driver_custom_now);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut sleep).poll(&mut cx).is_pending());
        assert_eq!(first.next_deadline(), Some(Time::from_secs(10)));

        let second_clock = Arc::new(VirtualClock::new());
        second_clock.set(Time::from_secs(200));
        let second = TimerDriverHandle::with_virtual_clock(second_clock);
        let _second_current = Cx::set_current(Some(custom_clock_context(&second)));
        assert!(Pin::new(&mut sleep).poll(&mut cx).is_pending());
        assert_eq!(first.pending_count(), 0);
        assert_eq!(second.next_deadline(), Some(Time::from_secs(210)));

        sleep.reset(Time::from_secs(103));
        assert_eq!(second.pending_count(), 0);
        assert!(Pin::new(&mut sleep).poll(&mut cx).is_pending());
        assert_eq!(second.next_deadline(), Some(Time::from_secs(203)));
        drop(sleep);
        assert_eq!(first.pending_count(), 0);
        assert_eq!(second.pending_count(), 0);
    }

    #[test]
    fn custom_clock_horizon_wake_does_not_complete_the_wait() {
        let clock = Arc::new(VirtualClock::new());
        clock.set(Time::from_secs(100));
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let _current = Cx::set_current(Some(custom_clock_context(&timer)));
        DRIVER_CUSTOM_TIME.with(|now| now.set(Time::ZERO));
        let deadline = Time::from_secs(8 * 24 * 60 * 60);
        let mut sleep = Sleep::with_time_getter(deadline, driver_custom_now);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut sleep).poll(&mut cx).is_pending());
        assert!(sleep.state.lock().registered_partial);

        let horizon = duration_to_nanos(timer.max_timer_duration());
        clock.set(Time::from_secs(100).saturating_add_nanos(horizon));
        DRIVER_CUSTOM_TIME.with(|now| now.set(Time::from_nanos(horizon)));
        assert_eq!(timer.process_timers(), 1);
        assert!(Pin::new(&mut sleep).poll(&mut cx).is_pending());
        assert_eq!(timer.pending_count(), 1);
        assert_eq!(
            timer.next_deadline(),
            Some(deadline.saturating_add_nanos(Time::from_secs(100).as_nanos()))
        );

        clock.set(deadline.saturating_add_nanos(Time::from_secs(100).as_nanos()));
        DRIVER_CUSTOM_TIME.with(|now| now.set(deadline));
        assert_eq!(timer.process_timers(), 1);
        assert!(Pin::new(&mut sleep).poll(&mut cx).is_ready());
        assert_eq!(timer.pending_count(), 0);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_custom_clock_sleep_wakes_without_waiting_for_its_epoch_offset() {
        fn offset_now() -> Time {
            Cx::current()
                .expect("native task context")
                .now()
                .saturating_add_nanos(Time::from_secs(100).as_nanos())
        }

        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("native runtime");
        runtime.block_on(runtime.handle().spawn(async {
            let owner = Cx::current().expect("native task context");
            let timer = owner.timer_driver().expect("native timer driver");
            let mut sleep =
                Sleep::with_time_getter(offset_now().saturating_add_nanos(20_000_000), offset_now);
            let mut parked = false;
            let wait = std::future::poll_fn(|cx| {
                let result = Pin::new(&mut sleep).poll(cx);
                if result.is_pending() && !parked {
                    parked = true;
                    assert_eq!(timer.pending_count(), 1, "custom sleep is registered");
                }
                result
            });
            let result =
                crate::time::TimeoutFuture::after(owner.now(), Duration::from_secs(2), wait).await;
            assert_eq!(result, Ok(()));
            assert!(parked, "the custom sleep must actually park before waking");
            assert_eq!(timer.pending_count(), 0);
        }));
    }

    // =========================================================================
    // is_elapsed and remaining Tests
    // =========================================================================

    #[test]
    fn is_elapsed_before_deadline() {
        init_test("is_elapsed_before_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let elapsed = sleep.is_elapsed(Time::from_secs(5));
        crate::assert_with_log!(!elapsed, "not elapsed", false, elapsed);
        crate::test_complete!("is_elapsed_before_deadline");
    }

    #[test]
    fn is_elapsed_at_deadline() {
        init_test("is_elapsed_at_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let elapsed = sleep.is_elapsed(Time::from_secs(10));
        crate::assert_with_log!(elapsed, "elapsed", true, elapsed);
        crate::test_complete!("is_elapsed_at_deadline");
    }

    #[test]
    fn is_elapsed_after_deadline() {
        init_test("is_elapsed_after_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let elapsed = sleep.is_elapsed(Time::from_secs(15));
        crate::assert_with_log!(elapsed, "elapsed", true, elapsed);
        crate::test_complete!("is_elapsed_after_deadline");
    }

    #[test]
    fn remaining_before_deadline() {
        init_test("remaining_before_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let remaining = sleep.remaining(Time::from_secs(7));
        crate::assert_with_log!(
            remaining == Duration::from_secs(3),
            "remaining",
            Duration::from_secs(3),
            remaining
        );
        crate::test_complete!("remaining_before_deadline");
    }

    #[test]
    fn remaining_at_deadline() {
        init_test("remaining_at_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let remaining = sleep.remaining(Time::from_secs(10));
        crate::assert_with_log!(
            remaining == Duration::ZERO,
            "remaining",
            Duration::ZERO,
            remaining
        );
        crate::test_complete!("remaining_at_deadline");
    }

    #[test]
    fn remaining_after_deadline() {
        init_test("remaining_after_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let remaining = sleep.remaining(Time::from_secs(15));
        crate::assert_with_log!(
            remaining == Duration::ZERO,
            "remaining",
            Duration::ZERO,
            remaining
        );
        crate::test_complete!("remaining_after_deadline");
    }

    // =========================================================================
    // poll_with_time Tests
    // =========================================================================

    #[test]
    fn poll_with_time_before_deadline() {
        init_test("poll_with_time_before_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let poll = sleep.poll_with_time(Time::from_secs(5));
        crate::assert_with_log!(poll.is_pending(), "pending", true, poll.is_pending());
        crate::assert_with_log!(sleep.was_polled(), "was polled", true, sleep.was_polled());
        crate::test_complete!("poll_with_time_before_deadline");
    }

    #[test]
    fn poll_with_time_at_deadline() {
        init_test("poll_with_time_at_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let poll = sleep.poll_with_time(Time::from_secs(10));
        crate::assert_with_log!(poll.is_ready(), "ready", true, poll.is_ready());
        crate::test_complete!("poll_with_time_at_deadline");
    }

    #[test]
    fn poll_with_time_after_deadline() {
        init_test("poll_with_time_after_deadline");
        let sleep = Sleep::new(Time::from_secs(10));
        let poll = sleep.poll_with_time(Time::from_secs(15));
        crate::assert_with_log!(poll.is_ready(), "ready", true, poll.is_ready());
        crate::test_complete!("poll_with_time_after_deadline");
    }

    #[test]
    fn poll_with_time_zero_deadline() {
        init_test("poll_with_time_zero_deadline");
        let sleep = Sleep::new(Time::ZERO);
        let poll = sleep.poll_with_time(Time::ZERO);
        crate::assert_with_log!(poll.is_ready(), "ready", true, poll.is_ready());
        crate::test_complete!("poll_with_time_zero_deadline");
    }

    #[test]
    fn poll_ready_with_time_before_deadline_does_not_register() {
        init_test("poll_ready_with_time_before_deadline_does_not_register");
        let sleep = Sleep::new(Time::from_secs(10));

        let poll = sleep.poll_ready_with_time(Time::from_secs(5));

        crate::assert_with_log!(poll.is_pending(), "pending", true, poll.is_pending());
        crate::assert_with_log!(!sleep.was_polled(), "not polled", false, sleep.was_polled());
        let state = sleep.state.lock();
        crate::assert_with_log!(
            state.timer_handle.is_none(),
            "timer handle absent",
            true,
            state.timer_handle.is_none()
        );
        crate::assert_with_log!(
            state.fallback.is_none(),
            "fallback absent",
            true,
            state.fallback.is_none()
        );
        crate::test_complete!("poll_ready_with_time_before_deadline_does_not_register");
    }

    #[test]
    fn poll_ready_with_time_at_deadline_completes() {
        init_test("poll_ready_with_time_at_deadline_completes");
        let sleep = Sleep::new(Time::from_secs(10));

        let poll = sleep.poll_ready_with_time(Time::from_secs(10));

        crate::assert_with_log!(poll.is_ready(), "ready", true, poll.is_ready());
        crate::assert_with_log!(sleep.was_polled(), "was polled", true, sleep.was_polled());
        crate::test_complete!("poll_ready_with_time_at_deadline_completes");
    }

    #[test]
    fn poll_with_time_repoll_after_completion_panics() {
        init_test("poll_with_time_repoll_after_completion_panics");
        let sleep = Sleep::new(Time::from_secs(10));

        let first = sleep.poll_with_time(Time::from_secs(10));
        crate::assert_with_log!(first.is_ready(), "first ready", true, first.is_ready());

        let repoll = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = sleep.poll_with_time(Time::from_secs(10));
        }));
        crate::assert_with_log!(repoll.is_err(), "repoll panics", true, repoll.is_err());

        crate::test_complete!("poll_with_time_repoll_after_completion_panics");
    }

    // =========================================================================
    // Reset Tests
    // =========================================================================

    #[test]
    fn reset_changes_deadline() {
        init_test("reset_changes_deadline");
        let mut sleep = Sleep::new(Time::from_secs(10));

        // Poll it
        let _ = sleep.poll_with_time(Time::from_secs(5));
        crate::assert_with_log!(sleep.was_polled(), "was polled", true, sleep.was_polled());

        // Reset
        sleep.reset(Time::from_secs(20));
        crate::assert_with_log!(
            sleep.deadline() == Time::from_secs(20),
            "deadline",
            Time::from_secs(20),
            sleep.deadline()
        );
        crate::assert_with_log!(
            !sleep.was_polled(),
            "reset clears polled",
            false,
            sleep.was_polled()
        ); // Reset clears polled flag
        crate::test_complete!("reset_changes_deadline");
    }

    #[test]
    fn reset_after_changes_deadline() {
        init_test("reset_after_changes_deadline");
        let mut sleep = Sleep::new(Time::from_secs(10));
        sleep.reset_after(Time::from_secs(5), Duration::from_secs(3));
        crate::assert_with_log!(
            sleep.deadline() == Time::from_secs(8),
            "deadline",
            Time::from_secs(8),
            sleep.deadline()
        );
        crate::test_complete!("reset_after_changes_deadline");
    }

    #[test]
    fn reset_after_completion_allows_sleep_reuse() {
        init_test("reset_after_completion_allows_sleep_reuse");
        let mut sleep = Sleep::new(Time::from_secs(10));

        let first = sleep.poll_with_time(Time::from_secs(10));
        crate::assert_with_log!(first.is_ready(), "first ready", true, first.is_ready());

        sleep.reset(Time::from_secs(20));

        let second = sleep.poll_with_time(Time::from_secs(15));
        crate::assert_with_log!(
            second.is_pending(),
            "pending after reset before deadline",
            true,
            second.is_pending()
        );

        let third = sleep.poll_with_time(Time::from_secs(20));
        crate::assert_with_log!(
            third.is_ready(),
            "ready after reset",
            true,
            third.is_ready()
        );

        crate::test_complete!("reset_after_completion_allows_sleep_reuse");
    }

    // =========================================================================
    // Timer Driver Integration Tests
    // =========================================================================

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn waker_that_sets(flag: Arc<AtomicBool>) -> Waker {
        struct FlagWaker {
            flag: Arc<AtomicBool>,
        }

        impl Wake for FlagWaker {
            fn wake(self: Arc<Self>) {
                self.flag.store(true, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.flag.store(true, Ordering::SeqCst);
            }
        }

        Waker::from(Arc::new(FlagWaker { flag }))
    }

    #[test]
    fn stale_fallback_registration_cannot_claim_replacement_waker() {
        init_test("stale_fallback_registration_cannot_claim_replacement_waker");
        let stale_registration = Arc::new(AtomicBool::new(true));
        let current_registration = Arc::new(AtomicBool::new(false));
        let woke = Arc::new(AtomicBool::new(false));
        let mut replacement_waker = Some(waker_that_sets(Arc::clone(&woke)));

        let stale_wake = fallback_waker_for_completion(
            Some(&current_registration),
            &stale_registration,
            &mut replacement_waker,
        )
        .expect("stale completion preserves wake delivery without claiming ownership");
        assert!(replacement_waker.is_some());
        assert!(!woke.load(Ordering::SeqCst));
        stale_wake.wake();
        assert!(woke.load(Ordering::SeqCst));
        woke.store(false, Ordering::SeqCst);

        let detached_wake =
            fallback_waker_for_completion(None, &stale_registration, &mut replacement_waker)
                .expect("driver transition preserves wake delivery without claiming ownership");
        assert!(replacement_waker.is_some());
        detached_wake.wake();
        assert!(woke.load(Ordering::SeqCst));
        woke.store(false, Ordering::SeqCst);

        fallback_waker_for_completion(
            Some(&current_registration),
            &current_registration,
            &mut replacement_waker,
        )
        .expect("current fallback owns the replacement waker")
        .wake();
        assert!(replacement_waker.is_none());
        assert!(woke.load(Ordering::SeqCst));
        crate::test_complete!("stale_fallback_registration_cannot_claim_replacement_waker");
    }

    #[test]
    fn drop_cancels_timer_registration() {
        init_test("drop_cancels_timer_registration");

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock);
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let mut sleep = Sleep::after(timer.now(), Duration::from_secs(1));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let poll = Pin::new(&mut sleep).poll(&mut cx);
        crate::assert_with_log!(poll.is_pending(), "pending", true, poll.is_pending());
        crate::assert_with_log!(
            timer.pending_count() == 1,
            "timer registered",
            1,
            timer.pending_count()
        );

        drop(sleep);

        crate::assert_with_log!(
            timer.pending_count() == 0,
            "timer cancelled on drop",
            0,
            timer.pending_count()
        );
        crate::test_complete!("drop_cancels_timer_registration");
    }

    #[test]
    fn reset_cancels_old_timer_and_re_registers_on_poll() {
        init_test("reset_cancels_old_timer_and_re_registers_on_poll");

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let mut sleep = Sleep::after(timer.now(), Duration::from_secs(5));
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let first_poll = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "first poll pending",
            true,
            first_poll.is_pending()
        );
        crate::assert_with_log!(
            timer.pending_count() == 1,
            "first timer registration",
            1,
            timer.pending_count()
        );

        sleep.reset(Time::from_secs(10));
        crate::assert_with_log!(
            timer.pending_count() == 0,
            "reset cancels previous timer",
            0,
            timer.pending_count()
        );
        let reset_released_waker = sleep.state.lock().waker.is_none();
        crate::assert_with_log!(
            reset_released_waker,
            "reset releases previous task waker",
            true,
            reset_released_waker
        );
        crate::assert_with_log!(
            sleep.deadline() == Time::from_secs(10),
            "deadline updated on reset",
            Time::from_secs(10),
            sleep.deadline()
        );

        let second_poll = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            second_poll.is_pending(),
            "second poll pending after reset",
            true,
            second_poll.is_pending()
        );
        crate::assert_with_log!(
            timer.pending_count() == 1,
            "timer re-registered after reset",
            1,
            timer.pending_count()
        );

        clock.set(Time::from_secs(9));
        let fired_before_deadline = timer.process_timers();
        crate::assert_with_log!(
            fired_before_deadline == 0,
            "no timers fire before new deadline",
            0,
            fired_before_deadline
        );

        clock.set(Time::from_secs(10));
        let _ = timer.process_timers();
        let ready_poll = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            ready_poll.is_ready(),
            "sleep ready at reset deadline",
            true,
            ready_poll.is_ready()
        );
        crate::assert_with_log!(
            timer.pending_count() == 0,
            "timer registration cleared on completion",
            0,
            timer.pending_count()
        );

        crate::test_complete!("reset_cancels_old_timer_and_re_registers_on_poll");
    }

    /// br-asupersync-2u7bpm L3: a re-poll with a new waker updates the timer.
    /// When the wheel had already retired the registration (it fired after
    /// the poll's readiness check, before its waker ran), `update` returned
    /// the stale handle unchanged and registered nothing, so the new waker was
    /// never woken.
    #[test]
    fn repoll_with_a_new_waker_after_the_wheel_retired_the_timer_wakes_the_new_waker() {
        init_test("repoll_with_a_new_waker_after_the_wheel_retired_the_timer_wakes_the_new_waker");

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let mut sleep = Sleep::after(timer.now(), Duration::from_secs(5));
        let first_woken = Arc::new(AtomicBool::new(false));
        let first = waker_that_sets(Arc::clone(&first_woken));
        assert!(
            Pin::new(&mut sleep)
                .poll(&mut Context::from_waker(&first))
                .is_pending()
        );

        // The wheel retires the registration before this Sleep sees it fire.
        let handle = sleep.state.lock().timer_handle.expect("a registered timer");
        assert!(timer.cancel(&handle));

        let second_woken = Arc::new(AtomicBool::new(false));
        let second = waker_that_sets(Arc::clone(&second_woken));
        assert!(
            Pin::new(&mut sleep)
                .poll(&mut Context::from_waker(&second))
                .is_pending()
        );

        clock.set(Time::from_secs(5));
        let _ = timer.process_timers();
        assert!(
            second_woken.load(Ordering::SeqCst),
            "the waker of the latest poll is woken at the deadline"
        );
        assert!(
            Pin::new(&mut sleep)
                .poll(&mut Context::from_waker(&second))
                .is_ready()
        );
        crate::test_complete!(
            "repoll_with_a_new_waker_after_the_wheel_retired_the_timer_wakes_the_new_waker"
        );
    }

    #[test]
    fn sleep_beyond_max_horizon_re_registers_and_does_not_fire_early() {
        init_test("sleep_beyond_max_horizon_re_registers_and_does_not_fire_early");

        // The wheel's default max_timer_duration is 7 days (wheel.rs). A sleep
        // whose deadline is 8 days out is clamped by the wheel and its timer
        // fires EARLY at the 7-day horizon. The sleep must treat that early fire
        // as a re-arm signal (re-register for the true deadline), NOT as
        // completion (br-asupersync-sleep-horizon-early-youlxs).
        const HORIZON_SECS: u64 = 7 * 24 * 60 * 60; // 604_800 (default max horizon)
        const DEADLINE_SECS: u64 = 8 * 24 * 60 * 60; // 691_200 (one day past horizon)

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let mut sleep = Sleep::after(timer.now(), Duration::from_secs(DEADLINE_SECS));
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        // First poll registers a clamped timer at the 7-day horizon.
        let first = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            first.is_pending(),
            "first poll pending",
            true,
            first.is_pending()
        );
        crate::assert_with_log!(
            timer.pending_count() == 1,
            "clamped timer registered",
            1,
            timer.pending_count()
        );

        // Fire the clamped timer at the horizon. The true deadline is still a day
        // away, so the sleep must stay pending and re-register.
        clock.set(Time::from_secs(HORIZON_SECS));
        let fired = timer.process_timers();
        crate::assert_with_log!(fired == 1, "clamped timer fires at horizon", 1, fired);
        let early = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            early.is_pending(),
            "must NOT complete early at the clamp horizon",
            true,
            early.is_pending()
        );
        crate::assert_with_log!(
            timer.pending_count() == 1,
            "timer re-registered for the true deadline",
            1,
            timer.pending_count()
        );

        // Nothing fires before the true deadline.
        clock.set(Time::from_secs(DEADLINE_SECS - 1));
        let none = timer.process_timers();
        crate::assert_with_log!(none == 0, "no fire before true deadline", 0, none);
        let still = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            still.is_pending(),
            "still pending before true deadline",
            true,
            still.is_pending()
        );

        // At the true deadline the sleep completes.
        clock.set(Time::from_secs(DEADLINE_SECS));
        let _ = timer.process_timers();
        let done = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            done.is_ready(),
            "ready at the true deadline",
            true,
            done.is_ready()
        );

        crate::test_complete!("sleep_beyond_max_horizon_re_registers_and_does_not_fire_early");
    }

    #[test]
    fn sleep_of_exactly_the_horizon_from_mid_tick_does_not_complete_early() {
        init_test("sleep_of_exactly_the_horizon_from_mid_tick_does_not_complete_early");

        // The wheel clamps a registration against its current 1 ms tick, which
        // can be up to 1 ms behind the clock. A sleep of exactly the 7-day
        // horizon started 0.5 ms into a tick is clamped to fire 0.5 ms before
        // its deadline; that fire must re-arm the sleep, not complete it
        // (br-asupersync-m85zfi LOW 2).
        const HORIZON_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;
        const MID_TICK_NS: u64 = 500_000;

        let clock = Arc::new(VirtualClock::new());
        clock.set(Time::from_nanos(MID_TICK_NS));
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let mut sleep = Sleep::after(timer.now(), Duration::from_nanos(HORIZON_NS));
        let deadline = Time::from_nanos(MID_TICK_NS + HORIZON_NS);
        crate::assert_with_log!(
            sleep.deadline() == deadline,
            "deadline is the horizon past mid-tick",
            deadline,
            sleep.deadline()
        );
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let first = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            first.is_pending(),
            "first poll pending",
            true,
            first.is_pending()
        );

        // The clamped timer fires at tick 0 plus the horizon, 0.5 ms early.
        clock.set(Time::from_nanos(HORIZON_NS));
        let fired = timer.process_timers();
        crate::assert_with_log!(fired == 1, "the clamped timer fires early", 1, fired);
        let early = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            early.is_pending(),
            "must NOT complete 0.5 ms before the deadline",
            true,
            early.is_pending()
        );
        crate::assert_with_log!(
            timer.pending_count() == 1,
            "re-registered for the true deadline",
            1,
            timer.pending_count()
        );

        clock.set(deadline);
        let _ = timer.process_timers();
        let done = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            done.is_ready(),
            "ready at the deadline",
            true,
            done.is_ready()
        );

        crate::test_complete!("sleep_of_exactly_the_horizon_from_mid_tick_does_not_complete_early");
    }

    #[test]
    #[should_panic(expected = "Sleep polled after completion")]
    fn future_repoll_after_completion_panics() {
        init_test("future_repoll_after_completion_panics");

        let mut sleep = Sleep::new(Time::from_secs(0));
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let first = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(first.is_ready(), "first ready", true, first.is_ready());

        let _ = Pin::new(&mut sleep).poll(&mut task_cx);

        crate::test_complete!("future_repoll_after_completion_panics");
    }

    #[test]
    fn poll_with_new_timer_driver_migrates_registration() {
        init_test("poll_with_new_timer_driver_migrates_registration");

        let clock1 = Arc::new(VirtualClock::new());
        let timer1 = TimerDriverHandle::with_virtual_clock(clock1);
        let cx1 = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 1),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer1.clone()),
            None,
        );
        let _guard1 = Cx::set_current(Some(cx1));

        let mut sleep = Sleep::after(timer1.now(), Duration::from_secs(5));
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let first_poll = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "first poll pending",
            true,
            first_poll.is_pending()
        );
        crate::assert_with_log!(
            timer1.pending_count() == 1,
            "timer1 has registration",
            1,
            timer1.pending_count()
        );

        let clock2 = Arc::new(VirtualClock::new());
        let timer2 = TimerDriverHandle::with_virtual_clock(clock2);
        let cx2 = Cx::new_with_drivers(
            RegionId::new_for_test(0, 2),
            TaskId::new_for_test(0, 2),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer2.clone()),
            None,
        );
        {
            let _guard2 = Cx::set_current(Some(cx2));

            let second_poll = Pin::new(&mut sleep).poll(&mut task_cx);
            crate::assert_with_log!(
                second_poll.is_pending(),
                "second poll pending on new driver",
                true,
                second_poll.is_pending()
            );
            crate::assert_with_log!(
                timer1.pending_count() == 0,
                "timer1 registration canceled after migration",
                0,
                timer1.pending_count()
            );
            crate::assert_with_log!(
                timer2.pending_count() == 1,
                "timer2 owns migrated registration",
                1,
                timer2.pending_count()
            );

            drop(sleep);
            crate::assert_with_log!(
                timer2.pending_count() == 0,
                "drop cancels migrated timer registration",
                0,
                timer2.pending_count()
            );
        }

        crate::test_complete!("poll_with_new_timer_driver_migrates_registration");
    }

    #[test]
    fn poll_after_timer_fire_stays_ready_across_driver_migration() {
        init_test("poll_after_timer_fire_stays_ready_across_driver_migration");

        let clock1 = Arc::new(VirtualClock::new());
        let timer1 = TimerDriverHandle::with_virtual_clock(clock1.clone());
        let cx1 = Cx::new_with_drivers(
            RegionId::new_for_test(0, 3),
            TaskId::new_for_test(0, 3),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer1.clone()),
            None,
        );
        let _guard1 = Cx::set_current(Some(cx1));

        let mut sleep = Sleep::after(timer1.now(), Duration::from_secs(5));
        let woke = Arc::new(AtomicBool::new(false));
        let waker = waker_that_sets(Arc::clone(&woke));
        let mut task_cx = Context::from_waker(&waker);

        let first_poll = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "first poll pending",
            true,
            first_poll.is_pending()
        );

        clock1.set(Time::from_secs(6));
        let fired = timer1.process_timers();
        crate::assert_with_log!(fired == 1, "old driver fires timer once", 1usize, fired);
        crate::assert_with_log!(
            woke.load(Ordering::SeqCst),
            "timer wake reached task waker",
            true,
            woke.load(Ordering::SeqCst)
        );

        let clock2 = Arc::new(VirtualClock::new());
        let timer2 = TimerDriverHandle::with_virtual_clock(clock2);
        let cx2 = Cx::new_with_drivers(
            RegionId::new_for_test(0, 4),
            TaskId::new_for_test(0, 4),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer2.clone()),
            None,
        );
        let _guard2 = Cx::set_current(Some(cx2));

        let second_poll = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            second_poll.is_ready(),
            "fired timer remains ready on new driver",
            true,
            second_poll.is_ready()
        );
        crate::assert_with_log!(
            timer2.pending_count() == 0,
            "new driver does not re-arm an already fired sleep",
            0,
            timer2.pending_count()
        );

        crate::test_complete!("poll_after_timer_fire_stays_ready_across_driver_migration");
    }

    #[test]
    fn poll_after_fallback_wake_stays_ready_on_driver() {
        init_test("poll_after_fallback_wake_stays_ready_on_driver");

        let _guard = Cx::set_current(None);

        let mut sleep = Sleep::after(wall_now(), Duration::from_millis(10));
        let woke = Arc::new(AtomicBool::new(false));
        let waker = waker_that_sets(Arc::clone(&woke));
        let mut task_cx = Context::from_waker(&waker);

        let first_poll = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "first poll pending",
            true,
            first_poll.is_pending()
        );

        let start = Instant::now();
        while !woke.load(Ordering::SeqCst) && start.elapsed() < Duration::from_millis(250) {
            std::thread::sleep(Duration::from_millis(1));
        }
        crate::assert_with_log!(
            woke.load(Ordering::SeqCst),
            "fallback thread wakes task",
            true,
            woke.load(Ordering::SeqCst)
        );

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock);
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 5),
            TaskId::new_for_test(0, 5),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard2 = Cx::set_current(Some(cx));

        let second_poll = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            second_poll.is_ready(),
            "fallback wake remains ready after driver appears",
            true,
            second_poll.is_ready()
        );
        crate::assert_with_log!(
            timer.pending_count() == 0,
            "driver does not re-arm an already fired fallback sleep",
            0,
            timer.pending_count()
        );

        crate::test_complete!("poll_after_fallback_wake_stays_ready_on_driver");
    }

    // =========================================================================
    // Clone Tests
    // =========================================================================

    #[test]
    fn clone_copies_deadline() {
        init_test("clone_copies_deadline");
        let original = Sleep::new(Time::from_secs(10));
        let cloned = original.clone();
        crate::assert_with_log!(
            original.deadline() == Time::from_secs(10),
            "original deadline",
            Time::from_secs(10),
            original.deadline()
        );
        crate::assert_with_log!(
            cloned.deadline() == Time::from_secs(10),
            "cloned deadline",
            Time::from_secs(10),
            cloned.deadline()
        );
        crate::test_complete!("clone_copies_deadline");
    }

    #[test]
    fn clone_has_fresh_polled_flag() {
        init_test("clone_has_fresh_polled_flag");
        let original = Sleep::new(Time::from_secs(10));
        let _ = original.poll_with_time(Time::from_secs(5));
        crate::assert_with_log!(
            original.was_polled(),
            "original polled",
            true,
            original.was_polled()
        );

        let cloned = original.clone();
        crate::assert_with_log!(
            original.was_polled(),
            "original still polled",
            true,
            original.was_polled()
        );
        crate::assert_with_log!(
            !cloned.was_polled(),
            "cloned not polled",
            false,
            cloned.was_polled()
        );
        crate::test_complete!("clone_has_fresh_polled_flag");
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn zero_duration_sleep() {
        init_test("zero_duration_sleep");
        let now = Time::from_secs(10);
        let sleep = sleep(now, Duration::ZERO);
        crate::assert_with_log!(
            sleep.deadline() == Time::from_secs(10),
            "deadline",
            Time::from_secs(10),
            sleep.deadline()
        );

        // Should be immediately ready
        let poll = sleep.poll_with_time(now);
        crate::assert_with_log!(poll.is_ready(), "ready", true, poll.is_ready());
        crate::test_complete!("zero_duration_sleep");
    }

    #[test]
    fn max_time_deadline() {
        init_test("max_time_deadline");
        let sleep = Sleep::new(Time::MAX);
        let poll = sleep.poll_with_time(Time::from_secs(1000));
        crate::assert_with_log!(poll.is_pending(), "pending", true, poll.is_pending());

        // Only ready at MAX
        let poll = sleep.poll_with_time(Time::MAX);
        crate::assert_with_log!(poll.is_ready(), "ready at max", true, poll.is_ready());
        crate::test_complete!("max_time_deadline");
    }

    #[test]
    fn time_zero_deadline() {
        init_test("time_zero_deadline");
        let sleep = Sleep::new(Time::ZERO);

        // Any non-zero time is past deadline
        let poll = sleep.poll_with_time(Time::from_nanos(1));
        crate::assert_with_log!(poll.is_ready(), "ready", true, poll.is_ready());
        crate::test_complete!("time_zero_deadline");
    }

    // =========================================================================
    // Metamorphic Testing: Sleep Cancel Relations
    // =========================================================================

    /// MR1: Cancellation idempotency - reset(reset(sleep)) ≡ reset(sleep)
    /// Tests that multiple resets to the same deadline are equivalent to a single reset.
    #[test]
    fn mr_cancel_idempotency() {
        init_test("mr_cancel_idempotency");

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 100),
            TaskId::new_for_test(0, 100),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let initial_deadline = Time::from_secs(10);
        let reset_deadline = Time::from_secs(20);

        // Create two identical sleeps
        let mut sleep1 = Sleep::new(initial_deadline);
        let mut sleep2 = Sleep::new(initial_deadline);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        // Poll both to register timers
        let _ = Pin::new(&mut sleep1).poll(&mut task_cx);
        let _ = Pin::new(&mut sleep2).poll(&mut task_cx);

        // Reset once vs reset twice to same deadline
        sleep1.reset(reset_deadline); // Single reset
        sleep2.reset(reset_deadline); // Double reset (first)
        sleep2.reset(reset_deadline); // Double reset (second)

        // Both should behave identically
        crate::assert_with_log!(
            sleep1.deadline() == sleep2.deadline(),
            "deadlines equal after reset idempotency",
            sleep1.deadline(),
            sleep2.deadline()
        );
        crate::assert_with_log!(
            sleep1.was_polled() == sleep2.was_polled(),
            "polled state equal after reset idempotency",
            sleep1.was_polled(),
            sleep2.was_polled()
        );

        // Both should poll identically
        let poll1 = Pin::new(&mut sleep1).poll(&mut task_cx);
        let poll2 = Pin::new(&mut sleep2).poll(&mut task_cx);
        crate::assert_with_log!(
            poll1.is_pending() && poll2.is_pending(),
            "both pending after reset idempotency",
            true,
            poll1.is_pending() && poll2.is_pending()
        );

        // Fire both and check they complete identically
        clock.set(reset_deadline);
        let _ = timer.process_timers();
        let final1 = Pin::new(&mut sleep1).poll(&mut task_cx);
        let final2 = Pin::new(&mut sleep2).poll(&mut task_cx);
        crate::assert_with_log!(
            final1.is_ready() && final2.is_ready(),
            "both ready after timer fires",
            true,
            final1.is_ready() && final2.is_ready()
        );

        crate::test_complete!("mr_cancel_idempotency");
    }

    /// MR2: Cancel after fire is no-op
    /// Tests that operations on a completed Sleep have no effect.
    #[test]
    fn mr_cancel_after_fire_noop() {
        init_test("mr_cancel_after_fire_noop");

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 101),
            TaskId::new_for_test(0, 101),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let deadline = Time::from_secs(5);
        let mut sleep = Sleep::new(deadline);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        // Poll to register timer
        let initial = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            initial.is_pending(),
            "initial poll pending",
            true,
            initial.is_pending()
        );

        // Fire the timer
        clock.set(deadline);
        let _ = timer.process_timers();
        let fired = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            fired.is_ready(),
            "sleep ready after timer fires",
            true,
            fired.is_ready()
        );

        // After completion, timer should be deregistered
        crate::assert_with_log!(
            timer.pending_count() == 0,
            "no timers pending after completion",
            0,
            timer.pending_count()
        );

        // Now test that reset after completion works (creates fresh timer)
        let new_deadline = Time::from_secs(10);
        sleep.reset(new_deadline);
        crate::assert_with_log!(
            sleep.deadline() == new_deadline,
            "deadline updated after reset",
            new_deadline,
            sleep.deadline()
        );
        crate::assert_with_log!(
            !sleep.was_polled(),
            "polled flag cleared after reset",
            false,
            sleep.was_polled()
        );

        // Should be able to use normally after reset
        let after_reset = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            after_reset.is_pending(),
            "pending after reset on completed sleep",
            true,
            after_reset.is_pending()
        );

        crate::test_complete!("mr_cancel_after_fire_noop");
    }

    /// MR3: Reset-after-cancel yields fresh timer
    /// Tests that reset() creates a completely independent timer registration.
    #[test]
    fn mr_reset_after_cancel_fresh() {
        init_test("mr_reset_after_cancel_fresh");

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 102),
            TaskId::new_for_test(0, 102),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let original_deadline = Time::from_secs(5);
        let reset_deadline = Time::from_secs(15);
        let mut sleep = Sleep::new(original_deadline);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        // Register original timer
        let _ = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            timer.pending_count() == 1,
            "original timer registered",
            1,
            timer.pending_count()
        );

        // Reset cancels old timer and prepares for new one
        sleep.reset(reset_deadline);
        crate::assert_with_log!(
            timer.pending_count() == 0,
            "reset cancels original timer",
            0,
            timer.pending_count()
        );
        crate::assert_with_log!(
            sleep.deadline() == reset_deadline,
            "deadline updated by reset",
            reset_deadline,
            sleep.deadline()
        );

        // Poll registers new timer
        let after_reset = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            after_reset.is_pending(),
            "pending after reset",
            true,
            after_reset.is_pending()
        );
        crate::assert_with_log!(
            timer.pending_count() == 1,
            "new timer registered after reset",
            1,
            timer.pending_count()
        );

        // Original deadline should not fire the reset timer
        clock.set(original_deadline);
        let original_fires = timer.process_timers();
        crate::assert_with_log!(
            original_fires == 0,
            "original deadline does not fire reset timer",
            0,
            original_fires
        );
        let still_pending = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            still_pending.is_pending(),
            "sleep still pending at original deadline",
            true,
            still_pending.is_pending()
        );

        // Reset deadline should fire
        clock.set(reset_deadline);
        let reset_fires = timer.process_timers();
        crate::assert_with_log!(
            reset_fires == 1,
            "reset deadline fires timer",
            1,
            reset_fires
        );
        let ready = Pin::new(&mut sleep).poll(&mut task_cx);
        crate::assert_with_log!(
            ready.is_ready(),
            "sleep ready at reset deadline",
            true,
            ready.is_ready()
        );

        crate::test_complete!("mr_reset_after_cancel_fresh");
    }

    /// MR4: N sleeps with same deadline fire in deterministic order under LabRuntime
    /// Tests that timer firing order is consistent across multiple identical sleeps.
    #[test]
    fn mr_deterministic_order_same_deadline() {
        init_test("mr_deterministic_order_same_deadline");

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 103),
            TaskId::new_for_test(0, 103),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let shared_deadline = Time::from_secs(10);
        let mut sleeps = Vec::new();
        let mut woke_flags = Vec::new();

        // Create multiple sleeps with same deadline and register them
        for i in 0..5 {
            let mut sleep = Sleep::new(shared_deadline);
            let woke = Arc::new(AtomicBool::new(false));
            let waker = waker_that_sets(Arc::clone(&woke));
            let mut task_cx = Context::from_waker(&waker);

            // Register each timer in order
            let poll = Pin::new(&mut sleep).poll(&mut task_cx);
            crate::assert_with_log!(
                poll.is_pending(),
                &format!("sleep {} pending", i),
                true,
                poll.is_pending()
            );

            sleeps.push(sleep);
            woke_flags.push(woke);
        }

        crate::assert_with_log!(
            timer.pending_count() == 5,
            "all timers registered",
            5,
            timer.pending_count()
        );

        // Fire all timers at deadline
        clock.set(shared_deadline);
        let fired_count = timer.process_timers();
        crate::assert_with_log!(
            fired_count == 5,
            "all timers fire at deadline",
            5,
            fired_count
        );

        // All wakers should fire
        for (i, woke) in woke_flags.iter().enumerate() {
            crate::assert_with_log!(
                woke.load(Ordering::SeqCst),
                &format!("waker {} fired", i),
                true,
                woke.load(Ordering::SeqCst)
            );
        }

        // All sleeps should be ready when polled with fresh context
        for (i, sleep) in sleeps.iter_mut().enumerate() {
            let waker = noop_waker();
            let mut task_cx = Context::from_waker(&waker);
            let ready = Pin::new(sleep).poll(&mut task_cx);
            crate::assert_with_log!(
                ready.is_ready(),
                &format!("sleep {} ready after timer fire", i),
                true,
                ready.is_ready()
            );
        }

        crate::assert_with_log!(
            timer.pending_count() == 0,
            "no pending timers after completion",
            0,
            timer.pending_count()
        );

        crate::test_complete!("mr_deterministic_order_same_deadline");
    }

    /// MR5: Drop cancellation removes from wheel atomically
    /// Tests that dropping a Sleep cleanly removes its timer registration.
    #[test]
    fn mr_drop_removes_atomically() {
        init_test("mr_drop_removes_atomically");

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 104),
            TaskId::new_for_test(0, 104),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        crate::assert_with_log!(
            timer.pending_count() == 0,
            "timer starts empty",
            0,
            timer.pending_count()
        );

        // Scope to control when Sleep is dropped
        {
            let mut sleep = Sleep::new(Time::from_secs(10));
            let waker = noop_waker();
            let mut task_cx = Context::from_waker(&waker);

            // Register timer
            let poll = Pin::new(&mut sleep).poll(&mut task_cx);
            crate::assert_with_log!(
                poll.is_pending(),
                "sleep pending after registration",
                true,
                poll.is_pending()
            );
            crate::assert_with_log!(
                timer.pending_count() == 1,
                "timer registered",
                1,
                timer.pending_count()
            );

            // Test timer is functional
            clock.set(Time::from_secs(5));
            let midway_fires = timer.process_timers();
            crate::assert_with_log!(
                midway_fires == 0,
                "timer does not fire before deadline",
                0,
                midway_fires
            );

            // Sleep will be dropped here, should cancel timer
        }

        // Verify timer was cancelled on drop
        crate::assert_with_log!(
            timer.pending_count() == 0,
            "timer cancelled on drop",
            0,
            timer.pending_count()
        );

        // Verify timer wheel is clean - no spurious fires
        clock.set(Time::from_secs(10));
        let dropped_fires = timer.process_timers();
        crate::assert_with_log!(
            dropped_fires == 0,
            "no spurious fires after drop",
            0,
            dropped_fires
        );

        clock.set(Time::from_secs(15));
        let later_fires = timer.process_timers();
        crate::assert_with_log!(
            later_fires == 0,
            "timer wheel remains clean",
            0,
            later_fires
        );

        crate::test_complete!("mr_drop_removes_atomically");
    }

    /// Composite MR: Cancellation composition properties
    /// Tests that combinations of operations preserve metamorphic relations.
    #[test]
    fn mr_cancellation_composition() {
        init_test("mr_cancellation_composition");

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 105),
            TaskId::new_for_test(0, 105),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        // Test: clone + reset preserves independence
        let original = Sleep::new(Time::from_secs(5));
        let mut cloned = original.clone();

        let _ = Pin::new(&mut cloned).poll(&mut task_cx);
        crate::assert_with_log!(
            timer.pending_count() == 1,
            "cloned sleep registers independently",
            1,
            timer.pending_count()
        );

        cloned.reset(Time::from_secs(10));
        crate::assert_with_log!(
            original.deadline() == Time::from_secs(5),
            "original unaffected by clone reset",
            Time::from_secs(5),
            original.deadline()
        );
        crate::assert_with_log!(
            cloned.deadline() == Time::from_secs(10),
            "cloned deadline updated",
            Time::from_secs(10),
            cloned.deadline()
        );

        // Test: multiple resets + drop is equivalent to single drop
        let mut sleep1 = Sleep::new(Time::from_secs(1));
        let mut sleep2 = Sleep::new(Time::from_secs(1));

        let _ = Pin::new(&mut sleep1).poll(&mut task_cx);
        let _ = Pin::new(&mut sleep2).poll(&mut task_cx);
        crate::assert_with_log!(
            timer.pending_count() == 2,
            "reset clone was cancelled; direct sleeps registered",
            2,
            timer.pending_count()
        );

        // sleep1: reset multiple times then drop
        sleep1.reset(Time::from_secs(2));
        sleep1.reset(Time::from_secs(3));
        sleep1.reset(Time::from_secs(4));
        drop(sleep1);

        // sleep2: drop directly
        drop(sleep2);

        // Both should result in same timer state (only cloned sleep remains)
        crate::assert_with_log!(
            timer.pending_count() == 0,
            "multiple resets + drop ≡ direct drop",
            0,
            timer.pending_count()
        );

        crate::test_complete!("mr_cancellation_composition");
    }

    #[test]
    fn off_cx_wall_clock_sleep_completes_via_shared_fallback() {
        init_test("off_cx_wall_clock_sleep_completes_via_shared_fallback");
        // No Cx is set on this thread, so Cx::current() is None: a wall-clock
        // sleep must route through the process-global shared fallback timer
        // (not a per-Sleep OS thread) and still fire
        // (br-asupersync-runtime-cpu-overhaul-5vt09v.3.5).
        crate::assert_with_log!(
            Cx::current().is_none(),
            "no ambient Cx",
            true,
            Cx::current().is_none()
        );
        let mut s = sleep(wall_now(), Duration::from_millis(20));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let give_up = Instant::now() + Duration::from_secs(2);
        loop {
            if Pin::new(&mut s).poll(&mut cx).is_ready() {
                break;
            }
            crate::assert_with_log!(
                Instant::now() < give_up,
                "off-Cx sleep fired within 2s",
                true,
                Instant::now() < give_up
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        crate::test_complete!("off_cx_wall_clock_sleep_completes_via_shared_fallback");
    }

    #[cfg(feature = "runtime-metrics")]
    #[test]
    fn off_cx_sleeps_share_one_fallback_thread() {
        init_test("off_cx_sleeps_share_one_fallback_thread");
        // N off-Cx wall-clock sleeps must register with the single shared
        // fallback driver, NOT spawn one OS thread each (the churn this fix
        // targets). Counters are process-global and the suite runs in parallel,
        // so assert robust bounds: registrations grow by >= N (they used the
        // driver), and thread spawns grow by < N (not one-per-sleep).
        let n: u64 = 8;
        let before = crate::runtime::metrics::snapshot();
        for _ in 0..n {
            let mut s = sleep(wall_now(), Duration::from_millis(5));
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let give_up = Instant::now() + Duration::from_secs(2);
            loop {
                if Pin::new(&mut s).poll(&mut cx).is_ready() {
                    break;
                }
                assert!(Instant::now() < give_up, "off-Cx sleep stalled");
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let after = crate::runtime::metrics::snapshot();
        let registered = after.timers_registered - before.timers_registered;
        let spawned = after.timer_threads_spawned - before.timer_threads_spawned;
        crate::assert_with_log!(
            registered >= n,
            "off-Cx sleeps registered with shared driver",
            true,
            registered >= n
        );
        crate::assert_with_log!(
            spawned < n,
            "shared pump, not one thread per sleep",
            true,
            spawned < n
        );
        crate::test_complete!("off_cx_sleeps_share_one_fallback_thread");
    }

    #[test]
    fn sleep_with_driver_registers_without_spawning_thread() {
        init_test("sleep_with_driver_registers_without_spawning_thread");
        // Positive counterpart to the off-Cx fallback tests: a Sleep polled WITH
        // a bound timer driver must register on that driver's wheel and create
        // NO per-Sleep fallback OS thread. This is the premise of the whole fix
        // — when a driver IS installed (the normal RuntimeBuilder / enable_time
        // path) there is no per-Sleep churn
        // (br-asupersync-runtime-cpu-overhaul-5vt09v.3.6).
        //
        // Both assertions are driver-local / per-Sleep (NOT the process-global
        // timer_threads_spawned counter), so they stay deterministic under the
        // parallel test runner — a concurrent test cannot perturb this driver's
        // pending count or this Sleep's fallback slot.
        let driver = TimerDriverHandle::with_wall_clock();
        let deadline = Time::from_nanos(
            driver.now().as_nanos() + duration_to_nanos(Duration::from_millis(100)),
        );
        let mut s = Sleep::with_timer_driver(deadline, driver.clone());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        // First poll registers on the driver's wheel and returns Pending.
        let first = Pin::new(&mut s).poll(&mut cx);
        crate::assert_with_log!(
            first.is_pending(),
            "driver-backed sleep pending on first poll",
            true,
            first.is_pending()
        );
        crate::assert_with_log!(
            driver.pending_count() == 1,
            "driver-backed sleep registered exactly one timer on the wheel",
            1usize,
            driver.pending_count()
        );
        // The whole point: a driver-backed sleep takes the timer-driver poll
        // branch and never reaches the no-driver `std::thread::spawn` path, so
        // its per-Sleep fallback slot stays empty.
        let no_fallback = s.state.lock().fallback.is_none();
        crate::assert_with_log!(
            no_fallback,
            "driver-backed sleep created no per-Sleep fallback thread",
            true,
            no_fallback
        );
        // Drive it to completion through the (passive) wall-clock driver so the
        // registration is cleaned up and we prove it still fires.
        let give_up = Instant::now() + Duration::from_secs(2);
        loop {
            let _ = driver.process_timers();
            if Pin::new(&mut s).poll(&mut cx).is_ready() {
                break;
            }
            assert!(Instant::now() < give_up, "driver-backed sleep stalled");
            std::thread::sleep(Duration::from_millis(1));
        }
        crate::test_complete!("sleep_with_driver_registers_without_spawning_thread");
    }

    #[test]
    fn missing_timer_driver_warns_exactly_once() {
        init_test("missing_timer_driver_warns_exactly_once");
        // The fallback warn must fire on the FIRST take and never again
        // (br-asupersync-runtime-cpu-overhaul-5vt09v.3.5). Test the once-claim
        // primitive against a LOCAL flag so the assertion is deterministic and
        // independent of process-global state / parallel test ordering (the real
        // call site uses the module-global FALLBACK_TIMER_WARNED, which other
        // off-Cx tests may have already flipped).
        let flag = AtomicBool::new(false);
        let first = claim_first_call(&flag);
        crate::assert_with_log!(first, "first call claims the warn", true, first);
        // Every subsequent call must observe the flag already set.
        for _ in 0..5 {
            let again = claim_first_call(&flag);
            crate::assert_with_log!(!again, "subsequent calls do not re-warn", false, again);
        }
        // Calling the real warn helper must not panic regardless of whether the
        // process-global flag was already consumed by another test.
        warn_missing_timer_driver_once();
        warn_missing_timer_driver_once();
        crate::test_complete!("missing_timer_driver_warns_exactly_once");
    }

    /// Closed while a test holds the fallback thread inside its clock.
    static GATE_CLOSED: AtomicBool = AtomicBool::new(false);
    /// Set once the fallback thread is blocked inside the closed clock.
    static INSIDE_GATED_CLOCK: AtomicBool = AtomicBool::new(false);

    /// A logical clock that never reaches the deadline and blocks its caller
    /// while the gate is closed.
    fn gated_clock() -> Time {
        while GATE_CLOSED.load(Ordering::Acquire) {
            INSIDE_GATED_CLOCK.store(true, Ordering::Release);
            std::thread::sleep(Duration::from_millis(1));
        }
        Time::ZERO
    }

    /// GitHub #80 (BZ19951), the timer sibling of spawn_blocking's fallback: a
    /// Sleep with a custom clock and no timer driver runs on its own fallback
    /// thread. Dropping the Sleep stopped that thread and dropped its JoinHandle,
    /// detaching a thread that was exiting at that moment (pthread_detach can
    /// fault on glibc before 2.43). Here the thread is held inside the clock when
    /// the Sleep is dropped, so it is provably still running: its handle must be
    /// parked, not dropped, and joined once the thread has finished.
    #[test]
    fn a_dropped_custom_clock_sleep_parks_its_running_fallback_thread() {
        init_test("a_dropped_custom_clock_sleep_parks_its_running_fallback_thread");
        let mut sleep = Sleep::with_time_getter(Time::from_secs(1_000_000), gated_clock);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut sleep).poll(&mut cx).is_pending());
        let worker = sleep
            .state
            .lock()
            .fallback
            .as_ref()
            .map(|fallback| fallback.thread.id())
            .expect("a custom clock without a timer driver runs on a fallback thread");
        GATE_CLOSED.store(true, Ordering::Release);
        let start = Instant::now();
        while !INSIDE_GATED_CLOCK.load(Ordering::Acquire) {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "fallback thread never polled its clock"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(sleep);
        assert_eq!(
            crate::runtime::spawn_blocking::parked_thread(worker),
            Some(false),
            "the running fallback thread's handle was dropped (detached) instead of parked"
        );
        GATE_CLOSED.store(false, Ordering::Release);
        while crate::runtime::spawn_blocking::parked_thread(worker) == Some(false) {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "fallback thread never exited"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        crate::runtime::spawn_blocking::reap_threads(Vec::new());
        assert_eq!(
            crate::runtime::spawn_blocking::parked_thread(worker),
            None,
            "a finished parked fallback thread was not joined"
        );
        crate::test_complete!("a_dropped_custom_clock_sleep_parks_its_running_fallback_thread");
    }
