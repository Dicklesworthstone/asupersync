    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::time::{CoalescingConfig, TimerWheelConfig};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // =========================================================================
    // VirtualClock Tests
    // =========================================================================

    #[test]
    fn timer_publication_wakes_shared_reactors_only_for_earlier_deadlines() {
        use crate::runtime::reactor::LabReactor;

        let driver = TimerDriver::new();
        let first = Arc::new(LabReactor::new());
        let second = Arc::new(LabReactor::new());
        for reactor in [&first, &second] {
            let erased: Arc<dyn Reactor> = reactor.clone();
            driver.register_deadline_reactor(Arc::downgrade(&erased));
        }
        let far = driver.register(Time::from_secs(60), futures_waker());
        assert!(first.check_and_clear_wake());
        assert!(second.check_and_clear_wake());
        let later = driver.register(Time::from_secs(90), futures_waker());
        assert!(!first.check_and_clear_wake());
        assert!(!second.check_and_clear_wake());
        assert_eq!(driver.next_deadline(), Some(Time::from_secs(60)));

        let near = driver.update(&later, Time::from_secs(10), futures_waker());
        assert!(first.check_and_clear_wake());
        assert!(second.check_and_clear_wake());
        assert_eq!(driver.pending_count(), 2);
        assert_eq!(
            driver.update(&later, Time::from_secs(1), futures_waker()),
            later,
            "a stale update must not publish a timer or a wake"
        );
        assert!(!first.check_and_clear_wake());
        assert!(!second.check_and_clear_wake());
        assert_eq!(driver.pending_count(), 2);

        assert!(driver.cancel(&near));
        assert_eq!(driver.next_deadline(), Some(Time::from_secs(60)));
        let replacement = driver.register(Time::from_secs(20), futures_waker());
        assert!(first.check_and_clear_wake());
        assert!(second.check_and_clear_wake());
        assert!(driver.cancel(&replacement));
        assert!(driver.cancel(&far));
        assert_eq!(driver.next_deadline(), None);
        driver.register(Time::from_secs(120), futures_waker());
        assert!(first.check_and_clear_wake());
        assert!(second.check_and_clear_wake());
    }

    #[test]
    fn timer_publication_compares_the_clamped_wake_deadline() {
        use crate::runtime::reactor::LabReactor;

        let driver = TimerDriver::new();
        let reactor = Arc::new(LabReactor::new());
        let erased: Arc<dyn Reactor> = reactor.clone();
        driver.register_deadline_reactor(Arc::downgrade(&erased));
        assert_eq!(driver.next_deadline(), None);
        driver.register(Time::from_nanos(u64::MAX), futures_waker());
        assert!(reactor.check_and_clear_wake());
        let horizon = Time::from_nanos(duration_to_nanos_saturating(
            driver.wheel.lock().config().max_timer_duration,
        ));
        assert_eq!(driver.next_deadline(), Some(horizon));
        driver.register(Time::from_nanos(u64::MAX - 1), futures_waker());
        assert!(
            !reactor.check_and_clear_wake(),
            "the same clamped deadline must not repeatedly wake the reactor"
        );
    }

    #[test]
    fn timer_publication_reactor_registrations_are_weak_and_deduplicated() {
        use crate::runtime::reactor::LabReactor;

        let driver = TimerDriver::new();
        let reactor: Arc<dyn Reactor> = Arc::new(LabReactor::new());
        let weak = Arc::downgrade(&reactor);
        driver.register_deadline_reactor(weak.clone());
        driver.register_deadline_reactor(weak.clone());
        assert_eq!(driver.deadline_reactors.lock().len(), 1);
        drop(reactor);
        assert!(
            weak.upgrade().is_none(),
            "timer must not retain the reactor"
        );
        driver.register(Time::from_secs(1), futures_waker());
        assert!(driver.deadline_reactors.lock().is_empty());
    }

    #[test]
    fn virtual_clock_starts_at_zero() {
        init_test("virtual_clock_starts_at_zero");
        let clock = VirtualClock::new();
        let now = clock.now();
        crate::assert_with_log!(now == Time::ZERO, "clock starts at zero", Time::ZERO, now);
        crate::test_complete!("virtual_clock_starts_at_zero");
    }

    #[test]
    fn virtual_clock_starting_at() {
        init_test("virtual_clock_starting_at");
        let clock = VirtualClock::starting_at(Time::from_secs(10));
        let now = clock.now();
        crate::assert_with_log!(
            now == Time::from_secs(10),
            "clock starts at 10s",
            Time::from_secs(10),
            now
        );
        crate::test_complete!("virtual_clock_starting_at");
    }

    #[test]
    fn virtual_clock_advance() {
        init_test("virtual_clock_advance");
        let clock = VirtualClock::new();
        clock.advance(1_000_000_000); // 1 second
        let now = clock.now();
        crate::assert_with_log!(
            now == Time::from_secs(1),
            "advance 1s",
            Time::from_secs(1),
            now
        );

        clock.advance(500_000_000); // 0.5 seconds
        let nanos = clock.now().as_nanos();
        crate::assert_with_log!(nanos == 1_500_000_000, "advance 0.5s", 1_500_000_000, nanos);
        crate::test_complete!("virtual_clock_advance");
    }

    #[test]
    fn virtual_clock_advance_saturates_at_time_max() {
        init_test("virtual_clock_advance_saturates_at_time_max");
        let clock = VirtualClock::starting_at(Time::from_nanos(u64::MAX - 5));

        clock.advance(10);

        let now = clock.now();
        crate::assert_with_log!(
            now == Time::MAX,
            "advance saturates at Time::MAX",
            Time::MAX,
            now
        );
        crate::test_complete!("virtual_clock_advance_saturates_at_time_max");
    }

    #[test]
    fn virtual_clock_advance_to() {
        init_test("virtual_clock_advance_to");
        let clock = VirtualClock::new();
        clock.advance_to(Time::from_secs(5));
        let now = clock.now();
        crate::assert_with_log!(
            now == Time::from_secs(5),
            "advance_to 5s",
            Time::from_secs(5),
            now
        );

        // Advancing to past time is no-op
        clock.advance_to(Time::from_secs(3));
        let now_after = clock.now();
        crate::assert_with_log!(
            now_after == Time::from_secs(5),
            "advance_to past is no-op",
            Time::from_secs(5),
            now_after
        );
        crate::test_complete!("virtual_clock_advance_to");
    }

    #[test]
    fn virtual_clock_set() {
        init_test("virtual_clock_set");
        let clock = VirtualClock::new();
        clock.set(Time::from_secs(100));
        let now = clock.now();
        crate::assert_with_log!(
            now == Time::from_secs(100),
            "set to 100s",
            Time::from_secs(100),
            now
        );

        // Set can go backwards
        clock.set(Time::from_secs(50));
        let now_back = clock.now();
        crate::assert_with_log!(
            now_back == Time::from_secs(50),
            "set backwards to 50s",
            Time::from_secs(50),
            now_back
        );
        crate::test_complete!("virtual_clock_set");
    }

    #[test]
    fn virtual_clock_set_updates_frozen_time_while_paused() {
        init_test("virtual_clock_set_updates_frozen_time_while_paused");
        let clock = VirtualClock::starting_at(Time::from_secs(1));
        clock.pause();

        clock.set(Time::from_secs(9));

        let now = clock.now();
        crate::assert_with_log!(
            now == Time::from_secs(9),
            "set updates the frozen clock view while paused",
            Time::from_secs(9),
            now
        );

        clock.resume();
        let resumed_now = clock.now();
        crate::assert_with_log!(
            resumed_now == Time::from_secs(9),
            "resume continues from the explicitly set time",
            Time::from_secs(9),
            resumed_now
        );
        crate::test_complete!("virtual_clock_set_updates_frozen_time_while_paused");
    }

    #[test]
    fn virtual_clock_pause_freezes_time() {
        init_test("virtual_clock_pause_freezes_time");
        let clock = VirtualClock::new();
        clock.advance(1_000_000_000); // 1 second
        clock.pause();

        let paused = clock.is_paused();
        crate::assert_with_log!(paused, "is_paused", true, paused);

        let frozen = clock.now();
        crate::assert_with_log!(
            frozen == Time::from_secs(1),
            "frozen at 1s",
            Time::from_secs(1),
            frozen
        );

        // Advance is a no-op while paused
        clock.advance(5_000_000_000);
        let still_frozen = clock.now();
        crate::assert_with_log!(
            still_frozen == Time::from_secs(1),
            "still frozen at 1s",
            Time::from_secs(1),
            still_frozen
        );

        // advance_to is also a no-op while paused
        clock.advance_to(Time::from_secs(100));
        let still_frozen2 = clock.now();
        crate::assert_with_log!(
            still_frozen2 == Time::from_secs(1),
            "still frozen after advance_to",
            Time::from_secs(1),
            still_frozen2
        );
        crate::test_complete!("virtual_clock_pause_freezes_time");
    }

    #[test]
    fn virtual_clock_resume_unfreezes() {
        init_test("virtual_clock_resume_unfreezes");
        let clock = VirtualClock::new();
        clock.advance(1_000_000_000);
        clock.pause();
        clock.resume();

        let resumed = !clock.is_paused();
        crate::assert_with_log!(resumed, "not paused", true, resumed);

        // Advance works again
        clock.advance(2_000_000_000);
        let now = clock.now();
        crate::assert_with_log!(
            now == Time::from_secs(3),
            "resumed and advanced",
            Time::from_secs(3),
            now
        );
        crate::test_complete!("virtual_clock_resume_unfreezes");
    }

    // =========================================================================
    // BrowserMonotonicClock Tests
    // =========================================================================

    #[test]
    fn browser_clock_first_sample_rebases_without_jump() {
        init_test("browser_clock_first_sample_rebases_without_jump");
        let clock = BrowserMonotonicClock::default();
        crate::assert_with_log!(
            clock.now() == Time::ZERO,
            "starts at zero",
            Time::ZERO,
            clock.now()
        );

        let t = clock.observe_host_time(Duration::from_millis(250));
        crate::assert_with_log!(
            t == Time::ZERO,
            "first sample is baseline only",
            Time::ZERO,
            t
        );
        crate::test_complete!("browser_clock_first_sample_rebases_without_jump");
    }

    #[test]
    fn browser_clock_clamps_regression_monotonically() {
        init_test("browser_clock_clamps_regression_monotonically");
        let clock = BrowserMonotonicClock::new(BrowserClockConfig {
            max_forward_step: Duration::ZERO,
            jitter_floor: Duration::ZERO,
        });

        let _ = clock.observe_host_time(Duration::from_millis(100));
        let t1 = clock.observe_host_time(Duration::from_millis(130));
        crate::assert_with_log!(
            t1 == Time::from_millis(30),
            "advances with forward host sample",
            Time::from_millis(30),
            t1
        );

        let t2 = clock.observe_host_time(Duration::from_millis(120));
        crate::assert_with_log!(
            t2 == Time::from_millis(30),
            "regressed host sample does not move clock backward",
            Time::from_millis(30),
            t2
        );

        let t3 = clock.observe_host_time(Duration::from_millis(150));
        crate::assert_with_log!(
            t3 == Time::from_millis(50),
            "clock resumes monotonic progression after regression",
            Time::from_millis(50),
            t3
        );
        crate::test_complete!("browser_clock_clamps_regression_monotonically");
    }

    #[test]
    fn browser_clock_jitter_floor_accumulates_small_deltas() {
        init_test("browser_clock_jitter_floor_accumulates_small_deltas");
        let clock = BrowserMonotonicClock::new(BrowserClockConfig {
            max_forward_step: Duration::ZERO,
            jitter_floor: Duration::from_millis(10),
        });

        let _ = clock.observe_host_time(Duration::from_millis(100));
        let t1 = clock.observe_host_time(Duration::from_millis(103));
        crate::assert_with_log!(t1 == Time::ZERO, "sub-floor delta deferred", Time::ZERO, t1);
        crate::assert_with_log!(
            clock.pending_catch_up() == Duration::from_millis(3),
            "pending catch-up tracks deferred jitter",
            Duration::from_millis(3),
            clock.pending_catch_up()
        );

        let t2 = clock.observe_host_time(Duration::from_millis(110));
        crate::assert_with_log!(
            t2 == Time::from_millis(10),
            "accumulated jitter released at floor",
            Time::from_millis(10),
            t2
        );
        crate::assert_with_log!(
            clock.pending_catch_up() == Duration::ZERO,
            "pending catch-up drained",
            Duration::ZERO,
            clock.pending_catch_up()
        );
        crate::test_complete!("browser_clock_jitter_floor_accumulates_small_deltas");
    }

    #[test]
    fn browser_clock_limits_catch_up_per_observation() {
        init_test("browser_clock_limits_catch_up_per_observation");
        let clock = BrowserMonotonicClock::new(BrowserClockConfig {
            max_forward_step: Duration::from_millis(50),
            jitter_floor: Duration::ZERO,
        });

        let _ = clock.observe_host_time(Duration::ZERO);
        let t1 = clock.observe_host_time(Duration::from_millis(200));
        crate::assert_with_log!(
            t1 == Time::from_millis(50),
            "first catch-up slice capped",
            Time::from_millis(50),
            t1
        );
        crate::assert_with_log!(
            clock.pending_catch_up() == Duration::from_millis(150),
            "remaining catch-up retained",
            Duration::from_millis(150),
            clock.pending_catch_up()
        );

        let t2 = clock.observe_host_time(Duration::from_millis(200));
        crate::assert_with_log!(
            t2 == Time::from_millis(100),
            "second slice advances deterministically",
            Time::from_millis(100),
            t2
        );
        crate::assert_with_log!(
            clock.pending_catch_up() == Duration::from_millis(100),
            "catch-up debt decreases by cap",
            Duration::from_millis(100),
            clock.pending_catch_up()
        );
        crate::test_complete!("browser_clock_limits_catch_up_per_observation");
    }

    #[test]
    fn browser_clock_suspend_resume_rebases_without_jump() {
        init_test("browser_clock_suspend_resume_rebases_without_jump");
        let clock = BrowserMonotonicClock::new(BrowserClockConfig {
            max_forward_step: Duration::ZERO,
            jitter_floor: Duration::ZERO,
        });

        let _ = clock.observe_host_time(Duration::from_millis(100));
        let t1 = clock.observe_host_time(Duration::from_millis(120));
        crate::assert_with_log!(
            t1 == Time::from_millis(20),
            "advances before suspend",
            Time::from_millis(20),
            t1
        );

        clock.suspend();
        crate::assert_with_log!(
            clock.is_suspended(),
            "clock suspended",
            true,
            clock.is_suspended()
        );
        let t2 = clock.observe_host_time(Duration::from_millis(500));
        crate::assert_with_log!(
            t2 == Time::from_millis(20),
            "suspended clock does not advance",
            Time::from_millis(20),
            t2
        );

        clock.resume();
        crate::assert_with_log!(
            !clock.is_suspended(),
            "clock resumed",
            false,
            clock.is_suspended()
        );

        let t3 = clock.observe_host_time(Duration::from_millis(700));
        crate::assert_with_log!(
            t3 == Time::from_millis(20),
            "first post-resume sample rebases",
            Time::from_millis(20),
            t3
        );
        let t4 = clock.observe_host_time(Duration::from_millis(730));
        crate::assert_with_log!(
            t4 == Time::from_millis(50),
            "post-resume progression uses new baseline",
            Time::from_millis(50),
            t4
        );
        crate::test_complete!("browser_clock_suspend_resume_rebases_without_jump");
    }

    static FAKE_HOST_NANOS: AtomicU64 = AtomicU64::new(0);

    fn fake_host_nanos() -> u64 {
        FAKE_HOST_NANOS.load(Ordering::SeqCst)
    }

    /// fqdvqn item 5: a wasm32 `RuntimeBuilder` gave its timer driver a
    /// `BrowserMonotonicClock::default()` that nothing fed, so the driver's
    /// time stayed at zero and no nonzero sleep or timeout ever fired. A
    /// host-sampled clock reads the host on every `now()`, through the same
    /// rebase and forward-step policy, so a timer driver on it fires.
    #[test]
    fn browser_clock_with_a_host_sampler_advances_on_every_read() {
        init_test("browser_clock_with_a_host_sampler_advances_on_every_read");
        FAKE_HOST_NANOS.store(5_000_000, Ordering::SeqCst);
        let clock = Arc::new(BrowserMonotonicClock::with_host_sampler(
            BrowserClockConfig {
                max_forward_step: Duration::from_millis(250),
                jitter_floor: Duration::ZERO,
            },
            fake_host_nanos,
        ));
        assert_eq!(clock.now(), Time::ZERO, "the first read is the baseline");
        FAKE_HOST_NANOS.store(25_000_000, Ordering::SeqCst);
        assert_eq!(clock.now(), Time::from_millis(20), "a read takes the host");

        // A long host gap is caught up one forward step per read.
        FAKE_HOST_NANOS.store(1_025_000_000, Ordering::SeqCst);
        let reads: Vec<Time> = (0..5).map(|_| clock.now()).collect();
        assert_eq!(
            reads,
            [270, 520, 770, 1020, 1020].map(Time::from_millis).to_vec()
        );

        // A timer driver on the clock fires a due timer.
        let driver = TimerDriver::with_clock(Arc::clone(&clock));
        driver.register(Time::from_millis(1050), futures_waker());
        assert_eq!(driver.process_timers(), 0, "not due yet");
        FAKE_HOST_NANOS.store(1_055_000_000, Ordering::SeqCst);
        assert_eq!(driver.process_timers(), 1, "due once the host moves on");

        // A clock nothing samples stays where it is, as before.
        let unfed = BrowserMonotonicClock::default();
        FAKE_HOST_NANOS.store(9_000_000_000, Ordering::SeqCst);
        assert_eq!(unfed.now(), Time::ZERO);
        crate::test_complete!("browser_clock_with_a_host_sampler_advances_on_every_read");
    }

    // =========================================================================
    // WallClock Tests
    // =========================================================================

    #[test]
    fn duration_to_nanos_saturates_at_u64_max() {
        init_test("duration_to_nanos_saturates_at_u64_max");
        let nanos = duration_to_nanos_saturating(Duration::MAX);
        crate::assert_with_log!(nanos == u64::MAX, "duration saturates", u64::MAX, nanos);
        crate::test_complete!("duration_to_nanos_saturates_at_u64_max");
    }

    #[test]
    fn wall_clock_uses_shared_process_epoch() {
        init_test("wall_clock_uses_shared_process_epoch");
        let before = crate::time::sleep::wall_now().as_nanos();
        let clock = WallClock::new();
        let now = clock.now().as_nanos();
        let after = crate::time::sleep::wall_now().as_nanos();

        crate::assert_with_log!(
            now >= before,
            "clock not before process wall_now",
            before,
            now
        );
        crate::assert_with_log!(now <= after, "clock not after process wall_now", after, now);
        crate::test_complete!("wall_clock_uses_shared_process_epoch");
    }

    #[test]
    fn wall_clock_advances() {
        init_test("wall_clock_advances");
        let clock = WallClock::new();
        let t1 = clock.now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t2 = clock.now();
        crate::assert_with_log!(t2 > t1, "clock advances", "t2 > t1", (t1, t2));
        crate::test_complete!("wall_clock_advances");
    }

    // =========================================================================
    // TimerDriver Tests
    // =========================================================================

    #[test]
    fn timer_driver_new() {
        init_test("timer_driver_new");
        let driver = TimerDriver::new();
        crate::assert_with_log!(driver.is_empty(), "driver empty", true, driver.is_empty());
        crate::assert_with_log!(
            driver.pending_count() == 0,
            "pending count",
            0,
            driver.pending_count()
        );
        crate::test_complete!("timer_driver_new");
    }

    #[test]
    fn timer_driver_register() {
        init_test("timer_driver_register");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock);

        let waker = futures_waker();
        let handle = driver.register(Time::from_secs(1), waker);

        crate::assert_with_log!(handle.id() == 0, "handle id", 0, handle.id());
        crate::assert_with_log!(
            driver.pending_count() == 1,
            "pending count",
            1,
            driver.pending_count()
        );
        crate::assert_with_log!(
            !driver.is_empty(),
            "driver not empty",
            false,
            driver.is_empty()
        );
        crate::test_complete!("timer_driver_register");
    }

    #[test]
    fn timer_driver_next_deadline() {
        init_test("timer_driver_next_deadline");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock);

        let expected: Option<Time> = None;
        let actual = driver.next_deadline();
        crate::assert_with_log!(actual == expected, "empty next_deadline", expected, actual);

        driver.register(Time::from_secs(5), futures_waker());
        driver.register(Time::from_secs(3), futures_waker());
        driver.register(Time::from_secs(7), futures_waker());

        // Should return earliest deadline
        let expected = Some(Time::from_secs(3));
        let actual = driver.next_deadline();
        crate::assert_with_log!(actual == expected, "earliest deadline", expected, actual);
        crate::test_complete!("timer_driver_next_deadline");
    }

    #[test]
    fn timer_driver_next_deadline_clamps_overdue_timer_to_now() {
        init_test("timer_driver_next_deadline_clamps_overdue_timer_to_now");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock.clone());

        driver.register(Time::from_secs(3), futures_waker());
        clock.set(Time::from_secs(10));

        let actual = driver.next_deadline();
        let expected = Some(Time::from_secs(10));
        crate::assert_with_log!(
            actual == expected,
            "overdue timer is reported as immediately due",
            expected,
            actual
        );
        crate::test_complete!("timer_driver_next_deadline_clamps_overdue_timer_to_now");
    }

    // br-asupersync-m85zfi LOW 3: a coalesced group fires at the end of its
    // window, never before a member's deadline. This test used to expect the
    // group to be due immediately (1 ms).
    #[test]
    fn timer_driver_next_deadline_reports_the_window_end_for_a_coalesced_group() {
        init_test("timer_driver_next_deadline_reports_the_window_end_for_a_coalesced_group");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver {
            clock: clock.clone(),
            observed_deadline: AtomicU64::new(u64::MAX),
            armed: AtomicBool::new(false),
            deadline_reactors: Mutex::new(Vec::new()),
            wheel: Mutex::new(TimerWheel::with_config(
                Time::ZERO,
                TimerWheelConfig::default(),
                CoalescingConfig::new()
                    .coalesce_window(Duration::from_millis(5))
                    .min_group_size(2)
                    .enable(),
            )),
        };

        driver.register(Time::from_millis(2), futures_waker());
        driver.register(Time::from_millis(4), futures_waker());
        clock.set(Time::from_millis(1));

        let actual = driver.next_deadline();
        let expected = Some(Time::from_millis(5));
        crate::assert_with_log!(
            actual == expected,
            "driver reports the window end for the coalesced group",
            expected,
            actual
        );
        crate::test_complete!(
            "timer_driver_next_deadline_reports_the_window_end_for_a_coalesced_group"
        );
    }

    // br-asupersync-7yq1pv + m85zfi LOW 3: a driver built with coalescing
    // fires a window's timers together at the window end, never early.
    #[test]
    fn coalescing_driver_fires_a_window_at_its_end_and_never_early() {
        init_test("coalescing_driver_fires_a_window_at_its_end_and_never_early");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock_and_config(
            clock.clone(),
            TimerWheelConfig::default(),
            CoalescingConfig::enabled_with_window(Duration::from_millis(100)),
        );
        let first = Arc::new(AtomicBool::new(false));
        let second = Arc::new(AtomicBool::new(false));
        driver.register(Time::from_millis(30), waker_that_sets(first.clone()));
        driver.register(Time::from_millis(31), waker_that_sets(second.clone()));

        clock.set(Time::from_millis(31));
        let fired = driver.process_timers();
        crate::assert_with_log!(fired == 0, "due timers wait for the window end", 0, fired);
        let next = driver.next_deadline();
        crate::assert_with_log!(
            next == Some(Time::from_millis(100)),
            "the window end is the next deadline",
            Some(Time::from_millis(100)),
            next
        );

        clock.set(Time::from_millis(100));
        let fired = driver.process_timers();
        crate::assert_with_log!(fired == 2, "the window fires together", 2, fired);
        crate::assert_with_log!(
            first.load(Ordering::SeqCst) && second.load(Ordering::SeqCst),
            "both wakers ran",
            true,
            first.load(Ordering::SeqCst) && second.load(Ordering::SeqCst)
        );
        crate::test_complete!("coalescing_driver_fires_a_window_at_its_end_and_never_early");
    }

    // The wall-clock handle really carries its coalescing setting. A fresh
    // wall clock starts near zero, so with a one-hour window a timer 30 s out
    // belongs to the window that ends at one hour.
    #[test]
    fn wall_clock_coalescing_handle_reports_the_window_end() {
        init_test("wall_clock_coalescing_handle_reports_the_window_end");
        let coalesced = TimerDriverHandle::with_wall_clock_coalescing(
            CoalescingConfig::enabled_with_window(Duration::from_hours(1)),
        );
        let plain = TimerDriverHandle::with_wall_clock();
        let mut timers = Vec::new();
        let mut deadlines = Vec::new();
        for handle in [&coalesced, &plain] {
            let deadline = handle.now() + Duration::from_secs(30);
            timers.push(handle.register(deadline, futures_waker()));
            deadlines.push(deadline);
        }

        let next = coalesced.next_deadline();
        crate::assert_with_log!(
            next == Some(Time::from_secs(3600)),
            "the coalescing driver waits for the window end",
            Some(Time::from_secs(3600)),
            next
        );
        let next = plain.next_deadline();
        crate::assert_with_log!(
            next == Some(deadlines[1]),
            "the plain driver reports the timer's own deadline",
            Some(deadlines[1]),
            next
        );
        crate::test_complete!("wall_clock_coalescing_handle_reports_the_window_end");
    }

    // A runtime built with a coalescing driver never wakes a sleep before its
    // deadline. An early-firing window (the old behavior) completed a sleep
    // as soon as the timer wheel first ran.
    #[test]
    fn runtime_with_a_coalescing_timer_driver_never_wakes_a_sleep_early() {
        const WINDOW_NS: u64 = 50_000_000;
        init_test("runtime_with_a_coalescing_timer_driver_never_wakes_a_sleep_early");
        let timers = TimerDriverHandle::with_wall_clock_coalescing(
            CoalescingConfig::enabled_with_window(Duration::from_nanos(WINDOW_NS)),
        );
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .with_timer_driver(timers)
            .build()
            .expect("build runtime");
        // Read both instants from the runtime's (coalescing) timer clock.
        let (deadline, woke) = runtime.block_on(async {
            let cx = crate::cx::Cx::current().expect("runtime context");
            let start = cx.now();
            crate::time::sleep(start, Duration::from_millis(30)).await;
            (start + Duration::from_millis(30), cx.now())
        });
        // A lone timer is a group of one: it fires at the first window
        // boundary at or after its deadline. Waking at the deadline itself
        // would mean the runtime is not using the coalescing driver.
        let window_end = Time::from_nanos(deadline.as_nanos().div_ceil(WINDOW_NS) * WINDOW_NS);
        crate::assert_with_log!(
            woke >= window_end,
            "the sleep wakes at its window end, never before its deadline",
            window_end,
            woke
        );
        crate::assert_with_log!(
            woke < window_end + Duration::from_secs(5),
            "the sleep wakes promptly once its window ends",
            "under 5 s after the window end",
            woke
        );
        crate::test_complete!("runtime_with_a_coalescing_timer_driver_never_wakes_a_sleep_early");
    }

    #[test]
    fn timer_driver_register_after_idle_gap_uses_current_clock_baseline() {
        init_test("timer_driver_register_after_idle_gap_uses_current_clock_baseline");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock.clone());
        let woken = Arc::new(AtomicBool::new(false));

        clock.set(Time::from_secs(8 * 24 * 60 * 60));
        let deadline = clock.now() + Duration::from_secs(1);
        driver.register(deadline, waker_that_sets(woken.clone()));

        let next = driver.next_deadline();
        let expected_next = Some(deadline);
        crate::assert_with_log!(
            next == expected_next,
            "idle-gap registration keeps the true short future deadline",
            expected_next,
            next
        );

        let fired_early = driver.process_timers();
        crate::assert_with_log!(
            fired_early == 0,
            "freshly registered short timer does not fire immediately after idle gap",
            0usize,
            fired_early
        );
        crate::assert_with_log!(
            !woken.load(Ordering::SeqCst),
            "waker not called before the new short deadline",
            false,
            woken.load(Ordering::SeqCst)
        );

        clock.advance(2_000_000_000);
        let fired = driver.process_timers();
        crate::assert_with_log!(
            fired == 1,
            "timer fires once the real post-idle deadline passes",
            1usize,
            fired
        );
        crate::assert_with_log!(
            woken.load(Ordering::SeqCst),
            "waker called after the real deadline",
            true,
            woken.load(Ordering::SeqCst)
        );
        crate::test_complete!("timer_driver_register_after_idle_gap_uses_current_clock_baseline");
    }

    #[test]
    fn timer_driver_register_resamples_clock_after_waiting_for_wheel_lock() {
        init_test("timer_driver_register_resamples_clock_after_waiting_for_wheel_lock");
        let clock = Arc::new(VirtualClock::new());
        let driver = Arc::new(TimerDriver::with_clock(clock.clone()));
        let deadline = Time::from_secs(8 * 24 * 60 * 60 + 1);

        let wheel_guard = driver.wheel.lock();
        let driver_for_thread = Arc::clone(&driver);
        let register_thread =
            std::thread::spawn(move || driver_for_thread.register(deadline, futures_waker()));

        clock.set(Time::from_secs(8 * 24 * 60 * 60));
        drop(wheel_guard);

        let register_handle = register_thread
            .join()
            .expect("register thread should complete without panicking");
        let next = driver.next_deadline();
        let expected_next = Some(deadline);
        crate::assert_with_log!(
            next == expected_next,
            "register re-samples clock after lock wait so long absolute deadlines are not stale-clamped",
            expected_next,
            next
        );

        let fired_early = driver.process_timers();
        crate::assert_with_log!(
            fired_early == 0,
            "waiting on the wheel lock does not make the newly registered timer immediately due",
            0usize,
            fired_early
        );

        clock.advance(2_000_000_000);
        let fired = driver.process_timers();
        crate::assert_with_log!(
            fired == 1,
            "timer still fires once the true absolute deadline passes",
            1usize,
            fired
        );
        let cancelled_after_fire = driver.cancel(&register_handle);
        crate::assert_with_log!(
            !cancelled_after_fire,
            "fired timer is no longer cancellable",
            false,
            cancelled_after_fire
        );
        crate::test_complete!("timer_driver_register_resamples_clock_after_waiting_for_wheel_lock");
    }

    /// Runs `process_timers` on another thread while this thread holds the
    /// wheel lock. Returns its result if it finished within `wait`.
    fn process_timers_while_wheel_locked(
        driver: &Arc<TimerDriver>,
        wait: Duration,
    ) -> Option<usize> {
        let wheel_guard = driver.wheel.lock();
        let (tx, rx) = std::sync::mpsc::channel();
        let driver_for_thread = Arc::clone(driver);
        let worker = std::thread::spawn(move || {
            let _ = tx.send(driver_for_thread.process_timers());
        });
        let fired = rx.recv_timeout(wait).ok();
        drop(wheel_guard);
        worker.join().expect("process_timers thread");
        fired
    }

    #[test]
    fn timer_driver_idle_process_timers_takes_no_wheel_lock() {
        init_test("timer_driver_idle_process_timers_takes_no_wheel_lock");
        let clock = Arc::new(VirtualClock::new());
        let driver = Arc::new(TimerDriver::with_clock(clock.clone()));

        // Never armed: an idle dispatch returns without waiting for the lock.
        let idle = process_timers_while_wheel_locked(&driver, Duration::from_secs(5));
        crate::assert_with_log!(
            idle == Some(0),
            "process_timers on a never-armed wheel finishes while the wheel lock is held",
            Some(0usize),
            idle
        );

        // Armed: the same call must take the lock (planted negative; it shows
        // the probe observes the locking path).
        let handle = driver.register(Time::from_secs(1), futures_waker());
        let armed = process_timers_while_wheel_locked(&driver, Duration::from_millis(200));
        crate::assert_with_log!(
            armed.is_none(),
            "process_timers with an armed timer waits for the wheel lock",
            None::<usize>,
            armed
        );

        // Cancelled: idle again.
        let cancelled = driver.cancel(&handle);
        crate::assert_with_log!(cancelled, "the armed timer cancels", true, cancelled);
        let after_cancel = process_timers_while_wheel_locked(&driver, Duration::from_secs(5));
        crate::assert_with_log!(
            after_cancel == Some(0),
            "process_timers after the last timer is cancelled takes no lock",
            Some(0usize),
            after_cancel
        );

        // Fired: idle again once the last timer has expired.
        let _ = driver.register(Time::from_secs(1), futures_waker());
        clock.advance(2_000_000_000);
        let fired = driver.process_timers();
        crate::assert_with_log!(fired == 1, "the due timer fires", 1usize, fired);
        let after_fire = process_timers_while_wheel_locked(&driver, Duration::from_secs(5));
        crate::assert_with_log!(
            after_fire == Some(0),
            "process_timers after the last timer fired takes no lock",
            Some(0usize),
            after_fire
        );

        // Cleared: idle again.
        let _ = driver.register(Time::from_secs(10), futures_waker());
        driver.clear();
        let after_clear = process_timers_while_wheel_locked(&driver, Duration::from_secs(5));
        crate::assert_with_log!(
            after_clear == Some(0),
            "process_timers after clear takes no lock",
            Some(0usize),
            after_clear
        );
        crate::test_complete!("timer_driver_idle_process_timers_takes_no_wheel_lock");
    }

    /// Records, when its last clone drops, whether the driver's wheel lock
    /// was free at that moment. A waker can own the last reference to a task
    /// whose drop cancels a timer, re-entering the driver: dropped under the
    /// wheel lock, that would deadlock (br-asupersync-m85zfi LOW 5).
    struct LockProbeWaker {
        driver: std::sync::Weak<TimerDriver>,
        drops: Arc<Mutex<Vec<bool>>>,
    }

    // Not a no-op waker by accident: what the probe measures is its Drop.
    #[allow(clippy::manual_noop_waker)]
    impl Wake for LockProbeWaker {
        fn wake(self: Arc<Self>) {}
    }

    impl Drop for LockProbeWaker {
        fn drop(&mut self) {
            // After the driver itself is gone there is no lock to observe.
            if let Some(driver) = self.driver.upgrade() {
                let lock_free = driver.wheel.try_lock().is_some();
                self.drops.lock().push(lock_free);
            }
        }
    }

    fn lock_probe_waker(driver: &Arc<TimerDriver>, drops: &Arc<Mutex<Vec<bool>>>) -> Waker {
        Arc::new(LockProbeWaker {
            driver: Arc::downgrade(driver),
            drops: Arc::clone(drops),
        })
        .into()
    }

    /// Takes the probe drops recorded since the last call and asserts that
    /// there was at least one (planted negative: the path under test really
    /// discarded a waker) and that each saw the wheel lock free.
    fn assert_probes_dropped_unlocked(path: &str, drops: &Arc<Mutex<Vec<bool>>>) {
        let seen = std::mem::take(&mut *drops.lock());
        tracing::info!(path, dropped = seen.len(), ?seen, "probe waker drops");
        crate::assert_with_log!(
            !seen.is_empty(),
            format!("{path}: the discarded probe waker dropped"),
            "at least one drop",
            seen.len()
        );
        crate::assert_with_log!(
            seen.iter().all(|lock_free| *lock_free),
            format!("{path}: every discarded waker dropped after the wheel lock was released"),
            "all true",
            seen
        );
    }

    #[test]
    fn timer_driver_drops_discarded_wakers_after_releasing_the_wheel_lock() {
        init_test("timer_driver_drops_discarded_wakers_after_releasing_the_wheel_lock");
        let drops = Arc::new(Mutex::new(Vec::new()));

        // Cancelling the last timer purges the wheel's storage.
        let driver = Arc::new(TimerDriver::new());
        let handle = driver.register(Time::from_secs(1), lock_probe_waker(&driver, &drops));
        assert!(driver.cancel(&handle));
        assert_probes_dropped_unlocked("cancel of the last timer", &drops);

        // update() cancels the entry it replaces.
        let driver = Arc::new(TimerDriver::new());
        let handle = driver.register(Time::from_secs(1), lock_probe_waker(&driver, &drops));
        let _updated = driver.update(&handle, Time::from_secs(2), futures_waker());
        assert_probes_dropped_unlocked("update", &drops);

        // clear() drops every stored entry.
        let driver = Arc::new(TimerDriver::new());
        let _handle = driver.register(Time::from_secs(1), lock_probe_waker(&driver, &drops));
        driver.clear();
        assert_probes_dropped_unlocked("clear", &drops);

        // A cancelled entry stays in its slot while another timer is live,
        // until process_timers reaches that slot.
        let clock = Arc::new(VirtualClock::new());
        let driver = Arc::new(TimerDriver::with_clock(clock.clone()));
        let handle = driver.register(Time::from_millis(10), lock_probe_waker(&driver, &drops));
        let _live = driver.register(Time::from_secs(60), futures_waker());
        assert!(driver.cancel(&handle));
        assert!(
            drops.lock().is_empty(),
            "the cancelled entry is still stored"
        );
        clock.advance(20_000_000);
        assert_eq!(driver.process_timers(), 0);
        assert_probes_dropped_unlocked("process_timers sweeping a cancelled entry", &drops);

        // A cancelled timer beyond the wheel's range sits in overflow until
        // next_deadline pops it from the top.
        let driver = Arc::new(TimerDriver::new());
        let far = driver.register(
            Time::from_secs(2 * 24 * 60 * 60),
            lock_probe_waker(&driver, &drops),
        );
        let _live = driver.register(Time::from_secs(60), futures_waker());
        assert!(driver.cancel(&far));
        assert!(
            drops.lock().is_empty(),
            "the cancelled overflow entry is still stored"
        );
        assert_eq!(driver.next_deadline(), Some(Time::from_secs(60)));
        assert_probes_dropped_unlocked("next_deadline popping a cancelled overflow entry", &drops);

        // Compaction, once cancellations outnumber twice the live timers
        // plus the slack.
        let driver = Arc::new(TimerDriver::new());
        let _live = driver.register(Time::from_secs(60), futures_waker());
        let handles: Vec<_> = (0..1_100)
            .map(|_| driver.register(Time::from_secs(30), lock_probe_waker(&driver, &drops)))
            .collect();
        for handle in &handles {
            assert!(driver.cancel(handle));
        }
        assert_probes_dropped_unlocked("compaction", &drops);

        crate::test_complete!("timer_driver_drops_discarded_wakers_after_releasing_the_wheel_lock");
    }

    #[test]
    fn timer_driver_process_expired() {
        init_test("timer_driver_process_expired");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock.clone());

        let woken = Arc::new(AtomicBool::new(false));
        let woken_clone = woken.clone();

        let waker = waker_that_sets(woken_clone);
        driver.register(Time::from_secs(1), waker);

        // Time is 0, no timers should fire
        let processed = driver.process_timers();
        crate::assert_with_log!(processed == 0, "process_timers at t=0", 0, processed);
        let woken_now = woken.load(Ordering::SeqCst);
        crate::assert_with_log!(!woken_now, "not woken", false, woken_now);

        // Advance time past deadline
        clock.advance(2_000_000_000); // 2 seconds
        let processed = driver.process_timers();
        crate::assert_with_log!(processed == 1, "process_timers after advance", 1, processed);
        let woken_now = woken.load(Ordering::SeqCst);
        crate::assert_with_log!(woken_now, "woken", true, woken_now);

        // No more timers
        crate::assert_with_log!(driver.is_empty(), "driver empty", true, driver.is_empty());
        crate::test_complete!("timer_driver_process_expired");
    }

    #[test]
    fn timer_driver_does_not_fire_while_clock_paused() {
        init_test("timer_driver_does_not_fire_while_clock_paused");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock.clone());

        let woken = Arc::new(AtomicBool::new(false));
        let waker = waker_that_sets(woken.clone());
        driver.register(Time::from_secs(1), waker);

        clock.pause();
        clock.advance(2_000_000_000);
        let fired_while_paused = driver.process_timers();
        crate::assert_with_log!(
            fired_while_paused == 0,
            "paused clock does not advance timers",
            0,
            fired_while_paused
        );
        crate::assert_with_log!(
            !woken.load(Ordering::SeqCst),
            "waker not called while paused",
            false,
            woken.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            driver.pending_count() == 1,
            "timer remains pending while paused",
            1,
            driver.pending_count()
        );

        clock.resume();
        clock.advance(2_000_000_000);
        let fired_after_resume = driver.process_timers();
        crate::assert_with_log!(
            fired_after_resume == 1,
            "timer fires after resume and advance",
            1,
            fired_after_resume
        );
        crate::assert_with_log!(
            woken.load(Ordering::SeqCst),
            "waker called after resume",
            true,
            woken.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(driver.is_empty(), "driver empty", true, driver.is_empty());
        crate::test_complete!("timer_driver_does_not_fire_while_clock_paused");
    }

    #[test]
    fn timer_driver_multiple_timers() {
        init_test("timer_driver_multiple_timers");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock.clone());

        let count = Arc::new(AtomicU64::new(0));

        for i in 1..=5 {
            let count_clone = count.clone();
            let waker = waker_that_increments(count_clone);
            driver.register(Time::from_secs(i), waker);
        }

        crate::assert_with_log!(
            driver.pending_count() == 5,
            "pending count",
            5,
            driver.pending_count()
        );

        // Advance to t=3, should fire 3 timers
        clock.set(Time::from_secs(3));
        let processed = driver.process_timers();
        crate::assert_with_log!(processed == 3, "process_timers at t=3", 3, processed);
        let count_now = count.load(Ordering::SeqCst);
        crate::assert_with_log!(count_now == 3, "count at t=3", 3, count_now);
        crate::assert_with_log!(
            driver.pending_count() == 2,
            "pending count after t=3",
            2,
            driver.pending_count()
        );

        // Advance to t=10, should fire remaining 2
        clock.set(Time::from_secs(10));
        let processed = driver.process_timers();
        crate::assert_with_log!(processed == 2, "process_timers at t=10", 2, processed);
        let count_now = count.load(Ordering::SeqCst);
        crate::assert_with_log!(count_now == 5, "count at t=10", 5, count_now);
        crate::assert_with_log!(driver.is_empty(), "driver empty", true, driver.is_empty());
        crate::test_complete!("timer_driver_multiple_timers");
    }

    #[test]
    fn timer_driver_update_cancels_old_handle() {
        init_test("timer_driver_update_cancels_old_handle");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock.clone());

        let counter = Arc::new(AtomicU64::new(0));
        let waker = waker_that_increments(counter.clone());
        let handle = driver.register(Time::from_secs(5), waker);

        let waker2 = waker_that_increments(counter.clone());
        let _new_handle = driver.update(&handle, Time::from_secs(2), waker2);

        clock.set(Time::from_secs(3));
        let processed = driver.process_timers();
        crate::assert_with_log!(processed == 1, "process_timers at t=3", 1, processed);
        let count_now = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count_now == 1, "counter", 1, count_now);

        clock.set(Time::from_secs(10));
        let processed = driver.process_timers();
        crate::assert_with_log!(processed == 0, "process_timers at t=10", 0, processed);
        let count_now = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count_now == 1, "counter stable", 1, count_now);
        crate::test_complete!("timer_driver_update_cancels_old_handle");
    }

    #[test]
    fn timer_driver_update_rejects_stale_handle_without_registering_new_timer() {
        init_test("timer_driver_update_rejects_stale_handle_without_registering_new_timer");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock.clone());

        let stale_counter = Arc::new(AtomicU64::new(0));
        let stale_handle = driver.register(Time::from_secs(5), futures_waker());
        let cancelled = driver.cancel(&stale_handle);
        crate::assert_with_log!(
            cancelled,
            "live handle cancelled before stale update",
            true,
            cancelled
        );

        let returned = driver.update(
            &stale_handle,
            Time::from_secs(2),
            waker_that_increments(Arc::clone(&stale_counter)),
        );
        crate::assert_with_log!(
            returned == stale_handle,
            "stale update returns unchanged handle",
            stale_handle,
            returned
        );
        crate::assert_with_log!(
            driver.pending_count() == 0,
            "stale update leaves pending timer count unchanged",
            0,
            driver.pending_count()
        );

        clock.set(Time::from_secs(3));
        let early_processed = driver.process_timers();
        crate::assert_with_log!(
            early_processed == 0,
            "stale update does not create an early timer",
            0usize,
            early_processed
        );
        crate::assert_with_log!(
            stale_counter.load(Ordering::SeqCst) == 0,
            "stale update waker not fired",
            0u64,
            stale_counter.load(Ordering::SeqCst)
        );

        clock.set(Time::from_secs(6));
        let processed = driver.process_timers();
        crate::assert_with_log!(
            processed == 0,
            "stale timer never fires later",
            0usize,
            processed
        );
        crate::assert_with_log!(
            stale_counter.load(Ordering::SeqCst) == 0,
            "stale timer never registered",
            0u64,
            stale_counter.load(Ordering::SeqCst)
        );
        crate::test_complete!(
            "timer_driver_update_rejects_stale_handle_without_registering_new_timer"
        );
    }

    #[test]
    fn timer_driver_update_after_idle_gap_keeps_future_deadline() {
        init_test("timer_driver_update_after_idle_gap_keeps_future_deadline");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock.clone());
        let counter = Arc::new(AtomicU64::new(0));
        let handle = driver.register(Time::from_secs(10), waker_that_increments(counter.clone()));

        clock.set(Time::from_secs(8 * 24 * 60 * 60));
        let updated_deadline = clock.now() + Duration::from_secs(2);
        let updated = driver.update(
            &handle,
            updated_deadline,
            waker_that_increments(counter.clone()),
        );
        crate::assert_with_log!(
            updated != handle,
            "live timer update after idle gap still produces a fresh handle",
            "different handle",
            (handle, updated)
        );

        let expected_next = Some(updated_deadline);
        let next = driver.next_deadline();
        crate::assert_with_log!(
            next == expected_next,
            "updated deadline remains in the future after idle gap",
            expected_next,
            next
        );

        let fired_early = driver.process_timers();
        crate::assert_with_log!(
            fired_early == 0,
            "updated timer does not fire immediately after idle gap",
            0usize,
            fired_early
        );
        crate::assert_with_log!(
            counter.load(Ordering::SeqCst) == 0,
            "counter not incremented before updated deadline",
            0u64,
            counter.load(Ordering::SeqCst)
        );

        clock.advance(3_000_000_000);
        let fired = driver.process_timers();
        crate::assert_with_log!(
            fired == 1,
            "updated timer fires after the true future deadline",
            1usize,
            fired
        );
        crate::assert_with_log!(
            counter.load(Ordering::SeqCst) == 1,
            "updated timer fires exactly once",
            1u64,
            counter.load(Ordering::SeqCst)
        );
        crate::test_complete!("timer_driver_update_after_idle_gap_keeps_future_deadline");
    }

    #[test]
    fn timer_driver_clear() {
        init_test("timer_driver_clear");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock);

        driver.register(Time::from_secs(1), futures_waker());
        driver.register(Time::from_secs(2), futures_waker());

        crate::assert_with_log!(
            driver.pending_count() == 2,
            "pending count",
            2,
            driver.pending_count()
        );
        driver.clear();
        crate::assert_with_log!(driver.is_empty(), "driver empty", true, driver.is_empty());
        crate::test_complete!("timer_driver_clear");
    }

    #[test]
    fn timer_driver_now() {
        init_test("timer_driver_now");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock.clone());

        let now = driver.now();
        crate::assert_with_log!(now == Time::ZERO, "now at zero", Time::ZERO, now);

        clock.advance(1_000_000_000);
        let now = driver.now();
        crate::assert_with_log!(
            now == Time::from_secs(1),
            "now after advance",
            Time::from_secs(1),
            now
        );
        crate::test_complete!("timer_driver_now");
    }

    #[test]
    fn timer_driver_with_browser_clock_respects_catch_up_cap() {
        init_test("timer_driver_with_browser_clock_respects_catch_up_cap");
        let clock = Arc::new(BrowserMonotonicClock::new(BrowserClockConfig {
            max_forward_step: Duration::from_millis(50),
            jitter_floor: Duration::ZERO,
        }));
        let driver = TimerDriver::with_clock(clock.clone());
        let woken = Arc::new(AtomicBool::new(false));

        let _ = clock.observe_host_time(Duration::ZERO);
        driver.register(Time::from_millis(80), waker_that_sets(woken.clone()));

        let _ = clock.observe_host_time(Duration::from_millis(100));
        let fired_1 = driver.process_timers();
        crate::assert_with_log!(
            fired_1 == 0,
            "first capped catch-up does not fire 80ms timer",
            0usize,
            fired_1
        );

        let _ = clock.observe_host_time(Duration::from_millis(100));
        let fired_2 = driver.process_timers();
        crate::assert_with_log!(
            fired_2 == 1,
            "second catch-up slice fires timer",
            1usize,
            fired_2
        );
        crate::assert_with_log!(
            woken.load(Ordering::SeqCst),
            "timer waker called after bounded catch-up",
            true,
            woken.load(Ordering::SeqCst)
        );
        crate::test_complete!("timer_driver_with_browser_clock_respects_catch_up_cap");
    }

    // =========================================================================
    // TimerHandle Tests
    // =========================================================================

    #[test]
    fn timer_handle_id_and_generation() {
        init_test("timer_handle_id_and_generation");
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriver::with_clock(clock);

        let h1 = driver.register(Time::from_secs(1), futures_waker());
        let h2 = driver.register(Time::from_secs(2), futures_waker());

        crate::assert_with_log!(h1.id() == 0, "h1 id", 0, h1.id());
        crate::assert_with_log!(h2.id() == 1, "h2 id", 1, h2.id());
        let gen1 = h1.generation();
        let gen2 = h2.generation();
        crate::assert_with_log!(
            gen1 != gen2,
            "generation differs",
            "not equal",
            (gen1, gen2)
        );
        crate::test_complete!("timer_handle_id_and_generation");
    }

    // =========================================================================
    // TimerDriverHandle Tests (bd-rpsc)
    // =========================================================================

    #[test]
    fn timer_driver_handle_with_virtual_clock() {
        init_test("timer_driver_handle_with_virtual_clock");
        let clock = Arc::new(VirtualClock::new());
        let handle = TimerDriverHandle::with_virtual_clock(clock.clone());

        let now = handle.now();
        crate::assert_with_log!(now == Time::ZERO, "initial time", Time::ZERO, now);

        clock.advance(1_000_000_000);
        let now = handle.now();
        crate::assert_with_log!(
            now == Time::from_secs(1),
            "time after advance",
            Time::from_secs(1),
            now
        );
        crate::test_complete!("timer_driver_handle_with_virtual_clock");
    }

    #[test]
    fn timer_driver_handle_register_and_cancel() {
        init_test("timer_driver_handle_register_and_cancel");
        let clock = Arc::new(VirtualClock::new());
        let handle = TimerDriverHandle::with_virtual_clock(clock.clone());

        let woken = Arc::new(AtomicBool::new(false));
        let waker = waker_that_sets(woken.clone());
        let timer_handle = handle.register(Time::from_secs(5), waker);

        // Cancel before firing
        let cancelled = handle.cancel(&timer_handle);
        crate::assert_with_log!(cancelled, "timer cancelled", true, cancelled);

        // Advance past deadline and process - nothing should fire
        clock.set(Time::from_secs(10));
        let fired = handle.process_timers();
        crate::assert_with_log!(fired == 0, "no timers fire after cancel", 0usize, fired);
        let woken_val = woken.load(Ordering::SeqCst);
        crate::assert_with_log!(!woken_val, "waker not called", false, woken_val);
        crate::test_complete!("timer_driver_handle_register_and_cancel");
    }

    #[test]
    fn timer_driver_handle_update_reschedules() {
        init_test("timer_driver_handle_update_reschedules");
        let clock = Arc::new(VirtualClock::new());
        let handle = TimerDriverHandle::with_virtual_clock(clock.clone());

        let counter = Arc::new(AtomicU64::new(0));
        let waker = waker_that_increments(counter.clone());
        let timer_handle = handle.register(Time::from_secs(5), waker);

        // Update to fire at 2s instead
        let waker2 = waker_that_increments(counter.clone());
        let _new_handle = handle.update(&timer_handle, Time::from_secs(2), waker2);

        // Advance to 3s - should fire the updated timer
        clock.set(Time::from_secs(3));
        let fired = handle.process_timers();
        crate::assert_with_log!(fired == 1, "updated timer fires", 1usize, fired);
        let count = counter.load(Ordering::SeqCst);
        crate::assert_with_log!(count == 1, "counter incremented", 1u64, count);

        // Advance to 10s - old deadline should not fire again
        clock.set(Time::from_secs(10));
        let fired = handle.process_timers();
        crate::assert_with_log!(fired == 0, "old timer cancelled", 0usize, fired);
        crate::test_complete!("timer_driver_handle_update_reschedules");
    }

    #[test]
    fn timer_driver_handle_next_deadline() {
        init_test("timer_driver_handle_next_deadline");
        let clock = Arc::new(VirtualClock::new());
        let handle = TimerDriverHandle::with_virtual_clock(clock);

        let no_deadline = handle.next_deadline();
        crate::assert_with_log!(
            no_deadline.is_none(),
            "no deadline when empty",
            true,
            no_deadline.is_none()
        );

        let _ = handle.register(Time::from_secs(10), futures_waker());
        let _ = handle.register(Time::from_secs(3), futures_waker());
        let _ = handle.register(Time::from_secs(7), futures_waker());

        let next = handle.next_deadline();
        crate::assert_with_log!(
            next == Some(Time::from_secs(3)),
            "earliest deadline returned",
            Some(Time::from_secs(3)),
            next
        );
        crate::test_complete!("timer_driver_handle_next_deadline");
    }

    #[test]
    fn timer_driver_handle_next_deadline_clamps_overdue_timer_to_now() {
        init_test("timer_driver_handle_next_deadline_clamps_overdue_timer_to_now");
        let clock = Arc::new(VirtualClock::new());
        let handle = TimerDriverHandle::with_virtual_clock(clock.clone());

        let _ = handle.register(Time::from_secs(4), futures_waker());
        clock.set(Time::from_secs(9));

        let next = handle.next_deadline();
        crate::assert_with_log!(
            next == Some(Time::from_secs(9)),
            "handle reports overdue timer as immediately due",
            Some(Time::from_secs(9)),
            next
        );
        crate::test_complete!("timer_driver_handle_next_deadline_clamps_overdue_timer_to_now");
    }

    #[test]
    fn timer_driver_handle_ptr_eq() {
        init_test("timer_driver_handle_ptr_eq");
        let clock = Arc::new(VirtualClock::new());
        let handle1 = TimerDriverHandle::with_virtual_clock(clock.clone());
        let handle2 = TimerDriverHandle::with_virtual_clock(clock);

        // Different driver instances, even with same clock
        let eq = handle1.ptr_eq(&handle2);
        crate::assert_with_log!(!eq, "different drivers not equal", false, eq);
        crate::test_complete!("timer_driver_handle_ptr_eq");
    }

    #[test]
    fn timer_driver_handle_with_browser_clock() {
        init_test("timer_driver_handle_with_browser_clock");
        let clock = Arc::new(BrowserMonotonicClock::new(BrowserClockConfig {
            max_forward_step: Duration::ZERO,
            jitter_floor: Duration::ZERO,
        }));
        let handle = TimerDriverHandle::with_browser_clock(clock.clone());

        let _ = clock.observe_host_time(Duration::from_millis(20));
        let _ = clock.observe_host_time(Duration::from_millis(35));
        let now = handle.now();
        crate::assert_with_log!(
            now == Time::from_millis(15),
            "driver handle reflects browser clock advancement",
            Time::from_millis(15),
            now
        );
        crate::test_complete!("timer_driver_handle_with_browser_clock");
    }

    /// br-asupersync-rr849p: a near timer must keep firing (and must keep
    /// being reported by `next_deadline`) while a far timer is pending.
    ///
    /// The default-built runtime currently has no I/O reactor, so every
    /// `TcpStream` read re-polls through a ~1ms fallback timer
    /// (`fallback_rewake`). Registering a coexisting long timer (e.g. the 4s
    /// `Sleep` inside a `timeout()` wrapper) must not strand or shadow the
    /// near fallback timers — if it does, every reactor-less read stalls
    /// until the far deadline, which is exactly the rr849p symptom.
    #[test]
    fn near_timer_fires_while_far_timer_pending() {
        init_test("near_timer_fires_while_far_timer_pending");
        let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(1)));
        let driver = TimerDriver::with_clock(Arc::clone(&clock));

        // Far timer: 4 seconds out (mirrors the rr849p timeout() Sleep).
        let far_flag = Arc::new(AtomicBool::new(false));
        let _far = driver.register(
            Time::from_nanos(clock.now().as_nanos() + 4_000_000_000),
            waker_that_sets(Arc::clone(&far_flag)),
        );

        // Simulated fallback-rewake loop: register now+1ms, advance 1ms,
        // process. 1000 steps = 1 virtual second, crossing several level-0
        // wheel revolutions so cascade/skip paths are exercised.
        for step in 0..1_000u64 {
            let woken = Arc::new(AtomicBool::new(false));
            let deadline = Time::from_nanos(clock.now().as_nanos() + 1_000_000);
            let _near = driver.register(deadline, waker_that_sets(Arc::clone(&woken)));

            let reported = driver.next_deadline();
            let near_reported = reported == Some(deadline);
            crate::assert_with_log!(
                near_reported,
                &format!("next_deadline reports the near timer at step {step}"),
                Some(deadline),
                reported
            );

            clock.advance(1_000_000);
            driver.process_timers();
            let fired = woken.load(Ordering::SeqCst);
            crate::assert_with_log!(
                fired,
                &format!("near timer fires at step {step} while the far timer is pending"),
                true,
                fired
            );
        }

        let far_fired_early = far_flag.load(Ordering::SeqCst);
        crate::assert_with_log!(
            !far_fired_early,
            "far timer has not fired after 1 virtual second",
            false,
            far_fired_early
        );

        clock.advance(3_100_000_000);
        driver.process_timers();
        let far_fired = far_flag.load(Ordering::SeqCst);
        crate::assert_with_log!(
            far_fired,
            "far timer fires once its deadline passes",
            true,
            far_fired
        );
        crate::test_complete!("near_timer_fires_while_far_timer_pending");
    }

    /// br-asupersync-rr849p: same invariant with deliberately tick-UNALIGNED
    /// virtual times and the production registration order (first fallback
    /// re-poll timer registered BEFORE the far timeout Sleep). The wall clock
    /// registers near timers at arbitrary sub-millisecond offsets, so this
    /// exercises truncation paths (mid-tick `now`, deadlines crossing tick
    /// boundaries, partial advances) the aligned variant cannot reach.
    #[test]
    fn near_timer_fires_while_far_timer_pending_unaligned() {
        init_test("near_timer_fires_while_far_timer_pending_unaligned");
        let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(1_000_000_123)));
        let driver = TimerDriver::with_clock(Arc::clone(&clock));

        // Production order: near fallback timer first, far Sleep second.
        let first_near = Arc::new(AtomicBool::new(false));
        let _n0 = driver.register(
            Time::from_nanos(clock.now().as_nanos() + 1_000_000),
            waker_that_sets(Arc::clone(&first_near)),
        );
        let far_flag = Arc::new(AtomicBool::new(false));
        let _far = driver.register(
            Time::from_nanos(clock.now().as_nanos() + 4_000_000_000),
            waker_that_sets(Arc::clone(&far_flag)),
        );

        clock.advance(1_500_000);
        driver.process_timers();
        let first_fired = first_near.load(Ordering::SeqCst);
        crate::assert_with_log!(
            first_fired,
            "first near timer fires with the far timer registered after it",
            true,
            first_fired
        );

        // Unaligned chain: two uneven sub-steps per iteration so the wheel
        // sees mid-tick `now` values on both register and process.
        for step in 0..2_000u64 {
            let woken = Arc::new(AtomicBool::new(false));
            let deadline = Time::from_nanos(clock.now().as_nanos() + 1_000_000);
            let _near = driver.register(deadline, waker_that_sets(Arc::clone(&woken)));

            clock.advance(641_337);
            driver.process_timers();
            clock.advance(400_000);
            driver.process_timers();

            let fired = woken.load(Ordering::SeqCst);
            crate::assert_with_log!(
                fired,
                &format!("unaligned near timer fires at step {step} with far timer pending"),
                true,
                fired
            );
        }

        let far_fired_early = far_flag.load(Ordering::SeqCst);
        crate::assert_with_log!(
            !far_fired_early,
            "far timer has not fired after ~2.1 virtual seconds",
            false,
            far_fired_early
        );
        clock.advance(2_100_000_000);
        driver.process_timers();
        let far_fired = far_flag.load(Ordering::SeqCst);
        crate::assert_with_log!(
            far_fired,
            "far timer fires once its deadline passes",
            true,
            far_fired
        );
        crate::test_complete!("near_timer_fires_while_far_timer_pending_unaligned");
    }

    /// br-asupersync-rr849p: wall-clock + concurrent-processor variant.
    /// Production drives the shared wheel from several worker threads plus
    /// the block_on thread; this runs background processors against the
    /// foreground fallback re-poll chain with a far timer pending. The bug
    /// presents as a multi-second stall, so the generous 500ms per-step
    /// budget cleanly separates it from scheduler jitter on loaded hosts.
    #[test]
    fn near_timer_fires_while_far_timer_pending_wall_clock_concurrent() {
        init_test("near_timer_fires_while_far_timer_pending_wall_clock_concurrent");
        let driver = TimerDriverHandle::with_wall_clock();

        let far_flag = Arc::new(AtomicBool::new(false));
        let _far = driver.register(
            Time::from_nanos(driver.now().as_nanos() + 60_000_000_000),
            waker_that_sets(Arc::clone(&far_flag)),
        );

        let stop = Arc::new(AtomicBool::new(false));
        let processors: Vec<_> = (0..2)
            .map(|_| {
                let driver = driver.clone();
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Acquire) {
                        let _ = driver.process_timers();
                        std::thread::sleep(Duration::from_micros(200));
                    }
                })
            })
            .collect();

        for step in 0..200u64 {
            let woken = Arc::new(AtomicBool::new(false));
            let deadline = Time::from_nanos(driver.now().as_nanos() + 1_000_000);
            let _near = driver.register(deadline, waker_that_sets(Arc::clone(&woken)));

            let start = std::time::Instant::now();
            let mut fired = false;
            while start.elapsed() < Duration::from_millis(500) {
                let _ = driver.process_timers();
                if woken.load(Ordering::SeqCst) {
                    fired = true;
                    break;
                }
                std::thread::sleep(Duration::from_micros(300));
            }
            crate::assert_with_log!(
                fired,
                &format!(
                    "wall-clock near timer fires within 500ms at step {step} with far timer pending"
                ),
                true,
                fired
            );
        }

        stop.store(true, Ordering::Release);
        for processor in processors {
            processor.join().expect("processor thread");
        }
        let far_fired_early = far_flag.load(Ordering::SeqCst);
        crate::assert_with_log!(
            !far_fired_early,
            "60s far timer has not fired during the chain",
            false,
            far_fired_early
        );
        crate::test_complete!("near_timer_fires_while_far_timer_pending_wall_clock_concurrent");
    }

    // =========================================================================
    // Helper Functions
    // =========================================================================

    /// Creates a no-op waker for testing.
    fn futures_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    /// Creates a waker that sets an AtomicBool when woken.
    fn waker_that_sets(flag: Arc<AtomicBool>) -> Waker {
        // We create a new FlagWaker that shares the flag
        // by wrapping the Arc<AtomicBool> in another struct
        struct SharedFlagWaker {
            flag: Arc<AtomicBool>,
        }

        use std::task::Wake;
        impl Wake for SharedFlagWaker {
            fn wake(self: Arc<Self>) {
                self.flag.store(true, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.flag.store(true, Ordering::SeqCst);
            }
        }

        Arc::new(SharedFlagWaker { flag }).into()
    }

    /// A waker that increments a counter when woken.
    struct CounterWaker {
        counter: Arc<AtomicU64>,
    }

    use std::task::Wake;
    impl Wake for CounterWaker {
        fn wake(self: Arc<Self>) {
            self.counter.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Creates a waker that increments an AtomicU64 when woken.
    fn waker_that_increments(counter: Arc<AtomicU64>) -> Waker {
        Arc::new(CounterWaker { counter }).into()
    }

    // =============================================================================
    // CONFORMANCE TESTS: Timer Driver Integration
    // =============================================================================

    #[test]
    fn conformance_timer_driver_precision_wall_clock() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_timer_driver_precision_wall_clock");

        // Test timer precision with wall clock time source
        let wall_clock = Arc::new(WallClock::new());
        let driver = Arc::new(TimerDriver::with_clock(wall_clock.clone()));
        let handle = TimerDriverHandle::new(driver);

        let counter = Arc::new(AtomicU64::new(0));

        // Test short timer (within level 0)
        let short_duration = Duration::from_millis(5);
        let start_time = wall_clock.now();

        let _timer_id = handle.register(
            handle
                .now()
                .saturating_add_nanos(short_duration.as_nanos().min(u128::from(u64::MAX)) as u64),
            waker_that_increments(counter.clone()),
        );

        // Busy wait for timer to fire (this is a test, so it's acceptable)
        let timeout = start_time.saturating_add_nanos(
            Duration::from_millis(100)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        while wall_clock.now() < timeout && counter.load(Ordering::SeqCst) == 0 {
            let _ = handle.process_timers();
            std::thread::sleep(Duration::from_millis(1));
        }

        let end_time = wall_clock.now();
        let elapsed = Duration::from_nanos(end_time.duration_since(start_time));

        crate::assert_with_log!(
            counter.load(Ordering::SeqCst) > 0,
            "wall clock timer fired",
            true,
            counter.load(Ordering::SeqCst) > 0
        );

        crate::assert_with_log!(
            elapsed >= short_duration,
            &format!(
                "wall clock timer did not fire before deadline: {:?} >= {:?}",
                elapsed, short_duration
            ),
            true,
            elapsed >= short_duration
        );

        // Wall-clock tests run under shared CI/RCH hosts, so scheduler latency
        // can dominate the 5ms timer period even when the timer driver is
        // correct. Keep the bound below the 100ms test timeout while allowing
        // loaded-host jitter.
        let tolerance = Duration::from_millis(50);
        crate::assert_with_log!(
            elapsed <= short_duration + tolerance,
            &format!(
                "timer precision within tolerance: {:?} <= {:?}",
                elapsed,
                short_duration + tolerance
            ),
            true,
            elapsed <= short_duration + tolerance
        );

        crate::test_complete!("conformance_timer_driver_precision_wall_clock");
    }

    #[test]
    fn conformance_timer_driver_virtual_clock() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_timer_driver_virtual_clock");

        // Test timer behavior with virtual clock (deterministic time)
        let virtual_clock = Arc::new(VirtualClock::new());
        let driver = Arc::new(TimerDriver::with_clock(virtual_clock.clone()));
        let handle = TimerDriverHandle::new(driver);

        let counter = Arc::new(AtomicU64::new(0));

        // Register multiple timers with virtual clock
        let durations = [
            Duration::from_millis(10),
            Duration::from_millis(50),
            Duration::from_millis(100),
            Duration::from_millis(500),
        ];

        let mut timer_ids = Vec::new();
        for duration in &durations {
            let timer_id = handle.register(
                handle
                    .now()
                    .saturating_add_nanos(duration.as_nanos().min(u128::from(u64::MAX)) as u64),
                waker_that_increments(counter.clone()),
            );
            timer_ids.push(timer_id);
        }

        // Advance virtual time precisely and check firing
        let advance_steps = [
            Duration::from_millis(15),  // Should fire first timer
            Duration::from_millis(60),  // Should fire second timer
            Duration::from_millis(110), // Should fire third timer
            Duration::from_millis(510), // Should fire fourth timer
        ];

        let mut expected_fired = 0;
        for advance_duration in &advance_steps {
            virtual_clock.advance(advance_duration.as_nanos() as u64);
            let _ = handle.process_timers();

            expected_fired += 1;
            let actual_fired = counter.load(Ordering::SeqCst);

            crate::assert_with_log!(
                actual_fired == expected_fired,
                &format!(
                    "virtual time advance fired correct number: {} at {:?}",
                    actual_fired, advance_duration
                ),
                expected_fired,
                actual_fired
            );
        }

        crate::test_complete!("conformance_timer_driver_virtual_clock");
    }

    #[test]
    fn conformance_timer_driver_concurrent_registrations() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_timer_driver_concurrent_registrations");

        // Test concurrent timer registrations with driver handle
        let virtual_clock = Arc::new(VirtualClock::new());
        let driver = Arc::new(TimerDriver::with_clock(virtual_clock.clone()));
        let handle = TimerDriverHandle::new(driver);

        const TIMER_COUNT: usize = 1000;
        let counters: Vec<_> = (0..TIMER_COUNT)
            .map(|_| Arc::new(AtomicU64::new(0)))
            .collect();

        // Register many timers concurrently
        let mut timer_ids = Vec::new();
        for (i, counter) in counters.iter().enumerate() {
            let duration = Duration::from_millis(10 + (i as u64 % 100)); // Varying durations
            let timer_id = handle.register(
                handle
                    .now()
                    .saturating_add_nanos(duration.as_nanos().min(u128::from(u64::MAX)) as u64),
                waker_that_increments(counter.clone()),
            );
            timer_ids.push(timer_id);
        }

        crate::assert_with_log!(
            handle.pending_count() == TIMER_COUNT,
            "all timers registered",
            TIMER_COUNT,
            handle.pending_count()
        );

        // Advance time to fire all timers
        virtual_clock.advance(Duration::from_millis(200).as_nanos() as u64);
        let _ = handle.process_timers();

        let fired_count = counters
            .iter()
            .map(|c| usize::from(c.load(Ordering::SeqCst) > 0))
            .sum::<usize>();

        crate::assert_with_log!(
            fired_count == TIMER_COUNT,
            "all timers fired",
            TIMER_COUNT,
            fired_count
        );

        crate::assert_with_log!(
            handle.pending_count() == 0,
            "no pending timers after firing",
            0usize,
            handle.pending_count()
        );

        crate::test_complete!("conformance_timer_driver_concurrent_registrations");
    }

    #[test]
    fn conformance_timer_driver_cancellation_cleanup() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_timer_driver_cancellation_cleanup");

        // Test timer cancellation through driver handle
        let virtual_clock = Arc::new(VirtualClock::new());
        let driver = Arc::new(TimerDriver::with_clock(virtual_clock.clone()));
        let handle = TimerDriverHandle::new(driver);

        let counter = Arc::new(AtomicU64::new(0));

        // Register timer and immediately cancel
        let timer_id = handle.register(
            handle.now().saturating_add_nanos(
                Duration::from_millis(100)
                    .as_nanos()
                    .min(u128::from(u64::MAX)) as u64,
            ),
            waker_that_increments(counter.clone()),
        );
        crate::assert_with_log!(
            handle.pending_count() == 1,
            "timer registered",
            1usize,
            handle.pending_count()
        );

        let cancelled = handle.cancel(&timer_id);
        crate::assert_with_log!(cancelled, "timer cancelled", true, cancelled);

        crate::assert_with_log!(
            handle.pending_count() == 0,
            "timer removed from pending",
            0usize,
            handle.pending_count()
        );

        // Advance past deadline - cancelled timer should not fire
        virtual_clock.advance(Duration::from_millis(200).as_nanos() as u64);
        let _ = handle.process_timers();

        crate::assert_with_log!(
            counter.load(Ordering::SeqCst) == 0,
            "cancelled timer did not fire",
            0u64,
            counter.load(Ordering::SeqCst)
        );

        // Double cancellation should return false
        let double_cancel = handle.cancel(&timer_id);
        crate::assert_with_log!(
            !double_cancel,
            "double cancel returns false",
            false,
            double_cancel
        );

        crate::test_complete!("conformance_timer_driver_cancellation_cleanup");
    }

    #[test]
    fn conformance_timer_driver_browser_clock_monotonic() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_timer_driver_browser_clock_monotonic");

        // Test browser clock maintains monotonicity
        let config = BrowserClockConfig::default();
        let browser_clock = Arc::new(BrowserMonotonicClock::new(config));

        let driver = Arc::new(TimerDriver::with_clock(browser_clock.clone()));
        let handle = TimerDriverHandle::new(driver);

        let counter = Arc::new(AtomicU64::new(0));

        // Simulate host time samples including regression (negative delta)
        let host_samples = [0.0, 10.0, 20.0, 15.0, 30.0]; // 15.0 is regression

        let mut last_time = Time::ZERO;
        for &sample_ms in &host_samples {
            browser_clock.observe_host_time(Duration::from_millis(sample_ms as u64));
            let current_time = browser_clock.now();

            // Time should never go backward
            crate::assert_with_log!(
                current_time >= last_time,
                &format!(
                    "monotonic time: {:?} >= {:?} at sample {sample_ms}",
                    current_time, last_time
                ),
                true,
                current_time >= last_time
            );

            last_time = current_time;
        }

        // Register a timer and verify it works with browser clock
        let _timer_id = handle.register(
            handle.now().saturating_add_nanos(
                Duration::from_millis(5)
                    .as_nanos()
                    .min(u128::from(u64::MAX)) as u64,
            ),
            waker_that_increments(counter.clone()),
        );

        // Advance browser clock
        browser_clock.observe_host_time(Duration::from_millis(50));
        let _ = handle.process_timers();

        crate::assert_with_log!(
            counter.load(Ordering::SeqCst) > 0,
            "timer fired with browser clock",
            true,
            counter.load(Ordering::SeqCst) > 0
        );

        crate::test_complete!("conformance_timer_driver_browser_clock_monotonic");
    }
