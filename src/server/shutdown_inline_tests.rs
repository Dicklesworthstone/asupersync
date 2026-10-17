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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_NOW: AtomicU64 = AtomicU64::new(0);
    // The injected function pointer is also read by Sleep's helper thread.
    // Keep that cross-thread clock while isolating parallel fixture owners.
    static TEST_CLOCK_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn set_test_time(nanos: u64) {
        TEST_NOW.store(nanos, Ordering::SeqCst);
    }

    fn lock_test_clock(nanos: u64) -> parking_lot::MutexGuard<'static, ()> {
        let guard = TEST_CLOCK_LOCK.lock();
        set_test_time(nanos);
        guard
    }

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
    }

    fn set_trigger_immediate_pre_phase_hook(hook: Option<Box<dyn FnMut()>>) {
        TRIGGER_IMMEDIATE_PRE_PHASE_HOOK.with(|slot| {
            *slot.borrow_mut() = hook;
        });
    }

    struct FlagWaker(Arc<AtomicBool>);

    impl std::task::Wake for FlagWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn initial_state_is_running() {
        init_test("initial_state_is_running");
        let signal = ShutdownSignal::new();
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Running,
            "phase",
            ShutdownPhase::Running,
            signal.phase()
        );
        crate::assert_with_log!(
            !signal.is_draining(),
            "not draining",
            false,
            signal.is_draining()
        );
        crate::assert_with_log!(
            !signal.is_shutting_down(),
            "not shutting down",
            false,
            signal.is_shutting_down()
        );
        crate::assert_with_log!(
            !signal.is_stopped(),
            "not stopped",
            false,
            signal.is_stopped()
        );
        crate::test_complete!("initial_state_is_running");
    }

    #[test]
    fn begin_drain_transitions_to_draining() {
        init_test("begin_drain_transitions_to_draining");
        let signal = ShutdownSignal::new();
        let initiated = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(initiated, "initiated", true, initiated);
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Draining,
            "phase",
            ShutdownPhase::Draining,
            signal.phase()
        );
        crate::assert_with_log!(
            signal.is_draining(),
            "is draining",
            true,
            signal.is_draining()
        );
        crate::assert_with_log!(
            signal.is_shutting_down(),
            "is shutting down",
            true,
            signal.is_shutting_down()
        );
        let has_deadline = signal.drain_deadline().is_some();
        crate::assert_with_log!(has_deadline, "has deadline", true, has_deadline);
        crate::test_complete!("begin_drain_transitions_to_draining");
    }

    #[test]
    fn begin_drain_idempotent() {
        init_test("begin_drain_idempotent");
        let signal = ShutdownSignal::new();
        let first = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(first, "first drain", true, first);

        let second = signal.begin_drain(Duration::from_secs(60));
        crate::assert_with_log!(!second, "second drain rejected", false, second);

        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Draining,
            "still draining",
            ShutdownPhase::Draining,
            signal.phase()
        );
        crate::test_complete!("begin_drain_idempotent");
    }

    #[test]
    fn with_time_getter_controls_deadline_and_duration() {
        init_test("with_time_getter_controls_deadline_and_duration");
        let _clock = lock_test_clock(0);
        let signal = ShutdownSignal::with_time_getter(test_time);

        let initiated = signal.begin_drain(Duration::from_nanos(25));
        crate::assert_with_log!(initiated, "initiated", true, initiated);
        crate::assert_with_log!(
            signal.drain_start() == Some(Time::from_nanos(0)),
            "drain start uses injected clock",
            Some(Time::from_nanos(0)),
            signal.drain_start()
        );
        crate::assert_with_log!(
            signal.drain_deadline() == Some(Time::from_nanos(25)),
            "deadline uses injected clock",
            Some(Time::from_nanos(25)),
            signal.drain_deadline()
        );

        set_test_time(80);
        let stats = signal.collect_stats(2, 1);
        crate::assert_with_log!(
            stats.duration == Duration::from_nanos(80),
            "duration uses injected clock",
            Duration::from_nanos(80),
            stats.duration
        );
        crate::test_complete!("with_time_getter_controls_deadline_and_duration");
    }

    #[test]
    fn new_captures_timer_driver_from_current_context() {
        init_test("new_captures_timer_driver_from_current_context");
        let virtual_clock = Arc::new(VirtualClock::starting_at(Time::from_secs(42)));
        let timer_driver = TimerDriverHandle::with_virtual_clock(Arc::clone(&virtual_clock));
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(7, 0),
            TaskId::new_for_test(9, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer_driver),
            None,
        );

        let signal = {
            let _guard = Cx::set_current(Some(cx));
            ShutdownSignal::new()
        };

        let initiated = signal.begin_drain(Duration::from_secs(3));
        crate::assert_with_log!(initiated, "initiated", true, initiated);
        crate::assert_with_log!(
            signal.drain_start() == Some(Time::from_secs(42)),
            "captured driver sets drain start",
            Some(Time::from_secs(42)),
            signal.drain_start()
        );
        crate::assert_with_log!(
            signal.drain_deadline() == Some(Time::from_secs(45)),
            "captured driver sets drain deadline",
            Some(Time::from_secs(45)),
            signal.drain_deadline()
        );

        virtual_clock.advance(7_000_000_000);
        let stats = signal.collect_stats(1, 0);
        crate::assert_with_log!(
            stats.duration == Duration::from_secs(7),
            "captured driver sets stats duration",
            Duration::from_secs(7),
            stats.duration
        );
        crate::test_complete!("new_captures_timer_driver_from_current_context");
    }

    /// A drain waiting for its deadline keeps waiting when the waiting task
    /// is cancelled; it used to complete at once, so the drain loop spun.
    #[test]
    fn wait_until_ignores_the_waiting_tasks_cancellation() {
        init_test("wait_until_ignores_the_waiting_tasks_cancellation");
        let virtual_clock = Arc::new(VirtualClock::starting_at(Time::from_secs(10)));
        let timer_driver = TimerDriverHandle::with_virtual_clock(Arc::clone(&virtual_clock));
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(7, 2),
            TaskId::new_for_test(9, 2),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer_driver.clone()),
            None,
        );
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx));
        let signal = ShutdownSignal::new();
        let waker = std::task::Waker::noop();
        let mut task_cx = std::task::Context::from_waker(waker);
        let mut wait = std::pin::pin!(signal.wait_until(Time::from_secs(3_610)));
        for _ in 0..2 {
            assert!(
                std::future::Future::poll(wait.as_mut(), &mut task_cx).is_pending(),
                "a cancelled waiter still waits for the deadline"
            );
        }
        virtual_clock.advance_to(Time::from_secs(3_610));
        let _ = timer_driver.process_timers();
        assert!(std::future::Future::poll(wait.as_mut(), &mut task_cx).is_ready());
    }

    #[test]
    fn wait_until_uses_captured_timer_driver_without_ambient_context() {
        init_test("wait_until_uses_captured_timer_driver_without_ambient_context");
        let virtual_clock = Arc::new(VirtualClock::starting_at(Time::from_secs(10)));
        let timer_driver = TimerDriverHandle::with_virtual_clock(Arc::clone(&virtual_clock));
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(7, 1),
            TaskId::new_for_test(9, 1),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer_driver.clone()),
            None,
        );

        let signal = {
            let _guard = Cx::set_current(Some(cx));
            ShutdownSignal::new()
        };
        let _no_cx = Cx::set_current(None);

        let waker = std::task::Waker::noop();
        let mut task_cx = std::task::Context::from_waker(waker);
        let deadline = Time::from_secs(12);
        let mut wait = std::pin::pin!(signal.wait_until(deadline));

        let first_poll = std::future::Future::poll(wait.as_mut(), &mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "wait is pending before deadline",
            true,
            first_poll.is_pending()
        );
        crate::assert_with_log!(
            timer_driver.pending_count() == 1,
            "captured timer driver owns registration",
            1,
            timer_driver.pending_count()
        );

        virtual_clock.advance(1_000_000_000);
        let fired_before_deadline = timer_driver.process_timers();
        crate::assert_with_log!(
            fired_before_deadline == 0,
            "timer does not fire before deadline",
            0,
            fired_before_deadline
        );

        virtual_clock.advance(1_000_000_000);
        let fired_at_deadline = timer_driver.process_timers();
        crate::assert_with_log!(
            fired_at_deadline == 1,
            "captured timer driver fires at deadline",
            1,
            fired_at_deadline
        );

        let second_poll = std::future::Future::poll(wait.as_mut(), &mut task_cx);
        crate::assert_with_log!(
            second_poll.is_ready(),
            "wait becomes ready after captured timer fires",
            true,
            second_poll.is_ready()
        );
        crate::assert_with_log!(
            timer_driver.pending_count() == 0,
            "registration clears after completion",
            0,
            timer_driver.pending_count()
        );
        crate::test_complete!("wait_until_uses_captured_timer_driver_without_ambient_context");
    }

    #[test]
    fn wait_until_with_time_getter_wakes_after_logical_clock_advance() {
        init_test("wait_until_with_time_getter_wakes_after_logical_clock_advance");
        let _clock = lock_test_clock(0);
        let signal = ShutdownSignal::with_time_getter(test_time);

        let woke = Arc::new(AtomicBool::new(false));
        let waker = std::task::Waker::from(Arc::new(FlagWaker(Arc::clone(&woke))));
        let mut task_cx = std::task::Context::from_waker(&waker);
        let deadline = Time::from_secs(10);
        let mut wait = std::pin::pin!(signal.wait_until(deadline));

        let first_poll = std::future::Future::poll(wait.as_mut(), &mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "wait is pending before deadline",
            true,
            first_poll.is_pending()
        );

        set_test_time(deadline.as_nanos());

        let second_poll = std::future::Future::poll(wait.as_mut(), &mut task_cx);
        crate::assert_with_log!(
            second_poll.is_ready(),
            "wait becomes ready after logical deadline",
            true,
            second_poll.is_ready()
        );
        crate::test_complete!("wait_until_with_time_getter_wakes_after_logical_clock_advance");
    }

    #[test]
    fn force_close_from_draining() {
        init_test("force_close_from_draining");
        let signal = ShutdownSignal::new();
        let began = signal.begin_drain(Duration::from_secs(1));
        crate::assert_with_log!(began, "begin drain", true, began);

        let forced = signal.begin_force_close();
        crate::assert_with_log!(forced, "force close", true, forced);
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::ForceClosing,
            "phase",
            ShutdownPhase::ForceClosing,
            signal.phase()
        );
        crate::test_complete!("force_close_from_draining");
    }

    #[test]
    fn force_close_waiter_is_not_consumed_by_drain_transition() {
        init_test("force_close_waiter_is_not_consumed_by_drain_transition");
        let signal = ShutdownSignal::new();
        let woke = Arc::new(AtomicBool::new(false));
        let waker = std::task::Waker::from(Arc::new(FlagWaker(Arc::clone(&woke))));
        let mut task_cx = std::task::Context::from_waker(&waker);
        let mut wait = Box::pin(signal.wait_for_phase(ShutdownPhase::ForceClosing));

        let first_poll = std::future::Future::poll(wait.as_mut(), &mut task_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "force-close waiter starts pending",
            true,
            first_poll.is_pending()
        );

        let began = signal.begin_drain(Duration::from_secs(1));
        crate::assert_with_log!(began, "begin drain", true, began);
        crate::assert_with_log!(
            !woke.load(Ordering::SeqCst),
            "drain transition does not consume force-close waiter",
            false,
            woke.load(Ordering::SeqCst)
        );

        let forced = signal.begin_force_close();
        crate::assert_with_log!(forced, "force close", true, forced);
        crate::assert_with_log!(
            woke.load(Ordering::SeqCst),
            "force-close transition wakes force-close waiter",
            true,
            woke.load(Ordering::SeqCst)
        );

        let second_poll = std::future::Future::poll(wait.as_mut(), &mut task_cx);
        crate::assert_with_log!(
            second_poll.is_ready(),
            "force-close waiter completes after target transition",
            true,
            second_poll.is_ready()
        );
        crate::test_complete!("force_close_waiter_is_not_consumed_by_drain_transition");
    }

    #[test]
    fn force_close_only_from_draining() {
        init_test("force_close_only_from_draining");
        let signal = ShutdownSignal::new();

        // Can't force close from Running
        let forced = signal.begin_force_close();
        crate::assert_with_log!(!forced, "can't force from running", false, forced);
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Running,
            "still running",
            ShutdownPhase::Running,
            signal.phase()
        );
        crate::test_complete!("force_close_only_from_draining");
    }

    #[test]
    fn mark_stopped() {
        init_test("mark_stopped");
        let signal = ShutdownSignal::new();
        let began = signal.begin_drain(Duration::from_secs(1));
        crate::assert_with_log!(began, "begin drain", true, began);
        let forced = signal.begin_force_close();
        crate::assert_with_log!(forced, "force close", true, forced);
        signal.mark_stopped();

        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Stopped,
            "stopped",
            ShutdownPhase::Stopped,
            signal.phase()
        );
        crate::assert_with_log!(signal.is_stopped(), "is stopped", true, signal.is_stopped());
        crate::test_complete!("mark_stopped");
    }

    #[test]
    fn trigger_immediate_skips_drain() {
        init_test("trigger_immediate_skips_drain");
        let signal = ShutdownSignal::new();
        signal.trigger_immediate();

        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::ForceClosing,
            "force-closing immediately",
            ShutdownPhase::ForceClosing,
            signal.phase()
        );
        crate::assert_with_log!(
            !signal.is_stopped(),
            "not stopped until mark_stopped",
            false,
            signal.is_stopped()
        );
        crate::test_complete!("trigger_immediate_skips_drain");
    }

    #[test]
    fn trigger_immediate_records_force_close_metadata_without_prior_drain() {
        init_test("trigger_immediate_records_force_close_metadata_without_prior_drain");
        let _clock = lock_test_clock(123);
        let signal = ShutdownSignal::with_time_getter(test_time);

        signal.trigger_immediate();

        crate::assert_with_log!(
            signal.drain_start() == Some(Time::from_nanos(123)),
            "immediate start uses injected clock",
            Some(Time::from_nanos(123)),
            signal.drain_start()
        );
        crate::assert_with_log!(
            signal.drain_deadline() == Some(Time::from_nanos(123)),
            "immediate deadline is current time",
            Some(Time::from_nanos(123)),
            signal.drain_deadline()
        );
        crate::test_complete!("trigger_immediate_records_force_close_metadata_without_prior_drain");
    }

    #[test]
    fn trigger_immediate_does_not_regress_stopped_phase() {
        init_test("trigger_immediate_does_not_regress_stopped_phase");
        let signal = ShutdownSignal::new();
        signal.mark_stopped();

        signal.trigger_immediate();

        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Stopped,
            "stopped phase preserved",
            ShutdownPhase::Stopped,
            signal.phase()
        );
        crate::test_complete!("trigger_immediate_does_not_regress_stopped_phase");
    }

    #[test]
    fn trigger_immediate_preserves_stopped_phase_under_interleaved_mark_stopped() {
        init_test("trigger_immediate_preserves_stopped_phase_under_interleaved_mark_stopped");
        let signal = ShutdownSignal::new();
        let hook_signal = signal.clone();
        set_trigger_immediate_pre_phase_hook(Some(Box::new(move || {
            hook_signal.mark_stopped();
        })));

        signal.trigger_immediate();

        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Stopped,
            "interleaved mark_stopped keeps terminal phase",
            ShutdownPhase::Stopped,
            signal.phase()
        );
        crate::assert_with_log!(
            signal.is_stopped(),
            "signal remains stopped after interleaving",
            true,
            signal.is_stopped()
        );
        crate::test_complete!(
            "trigger_immediate_preserves_stopped_phase_under_interleaved_mark_stopped"
        );
    }

    #[test]
    fn trigger_immediate_overrides_interleaved_begin_drain_metadata() {
        init_test("trigger_immediate_overrides_interleaved_begin_drain_metadata");
        let _clock = lock_test_clock(123);
        let signal = ShutdownSignal::with_time_getter(test_time);
        let hook_signal = signal.clone();
        set_trigger_immediate_pre_phase_hook(Some(Box::new(move || {
            let began = hook_signal.begin_drain(Duration::from_secs(30));
            assert!(began, "hook begin_drain should succeed");
        })));

        signal.trigger_immediate();

        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::ForceClosing,
            "interleaved begin_drain still reaches force-closing",
            ShutdownPhase::ForceClosing,
            signal.phase()
        );
        crate::assert_with_log!(
            signal.drain_start() == Some(Time::from_nanos(123)),
            "original drain start is retained",
            Some(Time::from_nanos(123)),
            signal.drain_start()
        );
        crate::assert_with_log!(
            signal.drain_deadline() == Some(Time::from_nanos(123)),
            "immediate trigger overwrites graceful-drain deadline",
            Some(Time::from_nanos(123)),
            signal.drain_deadline()
        );
        crate::test_complete!("trigger_immediate_overrides_interleaved_begin_drain_metadata");
    }

    #[test]
    fn subscribe_receives_shutdown() {
        init_test("subscribe_receives_shutdown");
        let signal = ShutdownSignal::new();
        let receiver = signal.subscribe();

        let not_shutting = receiver.is_shutting_down();
        crate::assert_with_log!(!not_shutting, "not shutting", false, not_shutting);

        let began = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(began, "begin drain", true, began);

        let shutting = receiver.is_shutting_down();
        crate::assert_with_log!(shutting, "shutting down", true, shutting);
        crate::test_complete!("subscribe_receives_shutdown");
    }

    #[test]
    fn display_formatting() {
        init_test("display_formatting");
        let cases = [
            (ShutdownPhase::Running, "Running"),
            (ShutdownPhase::Draining, "Draining"),
            (ShutdownPhase::ForceClosing, "ForceClosing"),
            (ShutdownPhase::Stopped, "Stopped"),
        ];
        for (phase, expected) in cases {
            let actual = format!("{phase}");
            crate::assert_with_log!(actual == expected, "phase display", expected, actual);
        }
        crate::test_complete!("display_formatting");
    }

    #[test]
    fn clone_shares_state() {
        init_test("clone_shares_state");
        let signal = ShutdownSignal::new();
        let cloned = signal.clone();

        let began = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(began, "begin drain", true, began);

        crate::assert_with_log!(
            cloned.is_draining(),
            "clone sees drain",
            true,
            cloned.is_draining()
        );
        crate::test_complete!("clone_shares_state");
    }

    // ====================================================================
    // Async integration tests
    // ====================================================================

    #[test]
    fn phase_changed_fires_on_drain() {
        init_test("phase_changed_fires_on_drain");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let signal2 = signal.clone();

            // Spawn a thread that will begin drain after a short delay
            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                let began = signal2.begin_drain(Duration::from_secs(30));
                assert!(began, "begin drain should succeed");
            });

            // Wait for the phase change
            signal.wait_for_phase(ShutdownPhase::Draining).await;
            let new_phase = signal.phase();
            crate::assert_with_log!(
                new_phase == ShutdownPhase::Draining,
                "phase after drain",
                ShutdownPhase::Draining,
                new_phase
            );

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("phase_changed_fires_on_drain");
    }

    #[test]
    fn phase_changed_fires_on_force_close() {
        init_test("phase_changed_fires_on_force_close");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let began = signal.begin_drain(Duration::from_secs(30));
            crate::assert_with_log!(began, "begin drain", true, began);

            let signal2 = signal.clone();
            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                let forced = signal2.begin_force_close();
                assert!(forced, "force close should succeed");
            });

            signal.wait_for_phase(ShutdownPhase::ForceClosing).await;
            let new_phase = signal.phase();
            crate::assert_with_log!(
                new_phase == ShutdownPhase::ForceClosing,
                "phase after force close",
                ShutdownPhase::ForceClosing,
                new_phase
            );

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("phase_changed_fires_on_force_close");
    }

    #[test]
    fn phase_changed_fires_on_mark_stopped() {
        init_test("phase_changed_fires_on_mark_stopped");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let began = signal.begin_drain(Duration::from_secs(30));
            crate::assert_with_log!(began, "begin drain", true, began);
            let forced = signal.begin_force_close();
            crate::assert_with_log!(forced, "force close", true, forced);

            let signal2 = signal.clone();
            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                signal2.mark_stopped();
            });

            signal.wait_for_phase(ShutdownPhase::Stopped).await;
            let new_phase = signal.phase();
            crate::assert_with_log!(
                new_phase == ShutdownPhase::Stopped,
                "phase after stopped",
                ShutdownPhase::Stopped,
                new_phase
            );

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("phase_changed_fires_on_mark_stopped");
    }

    #[test]
    fn phase_changed_fires_on_immediate() {
        init_test("phase_changed_fires_on_immediate");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let signal2 = signal.clone();

            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                signal2.trigger_immediate();
            });

            signal.wait_for_phase(ShutdownPhase::ForceClosing).await;
            let new_phase = signal.phase();
            crate::assert_with_log!(
                new_phase == ShutdownPhase::ForceClosing,
                "phase after immediate",
                ShutdownPhase::ForceClosing,
                new_phase
            );

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("phase_changed_fires_on_immediate");
    }

    #[test]
    fn full_lifecycle_phase_transitions() {
        init_test("full_lifecycle_phase_transitions");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();

            // Phase 1: Running
            crate::assert_with_log!(
                signal.phase() == ShutdownPhase::Running,
                "starts running",
                ShutdownPhase::Running,
                signal.phase()
            );

            // Phase 2: Draining (triggered from another thread)
            {
                let sig = signal.clone();
                let h = std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(10));
                    let began = sig.begin_drain(Duration::from_secs(1));
                    assert!(began, "begin drain should succeed");
                });
                signal.wait_for_phase(ShutdownPhase::Draining).await;
                let p = signal.phase();
                crate::assert_with_log!(
                    p == ShutdownPhase::Draining,
                    "draining",
                    ShutdownPhase::Draining,
                    p
                );
                h.join().expect("thread panicked");
            }

            // Phase 3: ForceClosing
            {
                let sig = signal.clone();
                let h = std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(10));
                    let forced = sig.begin_force_close();
                    assert!(forced, "force close should succeed");
                });
                signal.wait_for_phase(ShutdownPhase::ForceClosing).await;
                let p = signal.phase();
                crate::assert_with_log!(
                    p == ShutdownPhase::ForceClosing,
                    "force closing",
                    ShutdownPhase::ForceClosing,
                    p
                );
                h.join().expect("thread panicked");
            }

            // Phase 4: Stopped
            {
                let sig = signal.clone();
                let h = std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(10));
                    sig.mark_stopped();
                });
                signal.wait_for_phase(ShutdownPhase::Stopped).await;
                let p = signal.phase();
                crate::assert_with_log!(
                    p == ShutdownPhase::Stopped,
                    "stopped",
                    ShutdownPhase::Stopped,
                    p
                );
                h.join().expect("thread panicked");
            }
        });
        crate::test_complete!("full_lifecycle_phase_transitions");
    }

    #[test]
    fn subscriber_receives_drain_signal() {
        init_test("subscriber_receives_drain_signal");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let mut receiver = signal.subscribe();

            let not_shutting = receiver.is_shutting_down();
            crate::assert_with_log!(!not_shutting, "not shutting down", false, not_shutting);

            // Trigger drain from thread
            let sig = signal.clone();
            let h = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(10));
                let began = sig.begin_drain(Duration::from_secs(30));
                assert!(began, "begin drain should succeed");
            });

            // Wait for the underlying signal
            receiver.wait().await;

            let shutting = receiver.is_shutting_down();
            crate::assert_with_log!(shutting, "is shutting down", true, shutting);

            h.join().expect("thread panicked");
        });
        crate::test_complete!("subscriber_receives_drain_signal");
    }

    #[test]
    fn subscriber_receives_mark_stopped_without_prior_drain() {
        init_test("subscriber_receives_mark_stopped_without_prior_drain");
        crate::test_utils::run_test(|| async {
            let signal = ShutdownSignal::new();
            let mut receiver = signal.subscribe();
            let signal2 = signal.clone();

            let handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(10));
                signal2.mark_stopped();
            });

            receiver.wait().await;

            let shutting = receiver.is_shutting_down();
            crate::assert_with_log!(shutting, "receiver sees shutdown", true, shutting);
            crate::assert_with_log!(
                signal.phase() == ShutdownPhase::Stopped,
                "phase after mark_stopped",
                ShutdownPhase::Stopped,
                signal.phase()
            );

            handle.join().expect("thread panicked");
        });
        crate::test_complete!("subscriber_receives_mark_stopped_without_prior_drain");
    }

    // ====================================================================
    // Stats collection tests
    // ====================================================================

    #[test]
    fn collect_stats_before_drain() {
        init_test("collect_stats_before_drain");
        let signal = ShutdownSignal::new();

        let stats = signal.collect_stats(0, 0);
        crate::assert_with_log!(stats.drained == 0, "drained", 0, stats.drained);
        crate::assert_with_log!(
            stats.force_closed == 0,
            "force_closed",
            0,
            stats.force_closed
        );
        // Duration should be zero since drain hasn't started
        crate::assert_with_log!(
            stats.duration == Duration::ZERO,
            "duration zero",
            Duration::ZERO,
            stats.duration
        );
        crate::test_complete!("collect_stats_before_drain");
    }

    #[test]
    fn collect_stats_after_drain() {
        init_test("collect_stats_after_drain");
        let signal = ShutdownSignal::new();

        let began = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(began, "drain started", true, began);

        // Small sleep to ensure measurable duration
        std::thread::sleep(Duration::from_millis(5));

        let stats = signal.collect_stats(10, 3);
        crate::assert_with_log!(stats.drained == 10, "drained", 10, stats.drained);
        crate::assert_with_log!(
            stats.force_closed == 3,
            "force_closed",
            3,
            stats.force_closed
        );

        let nonzero = stats.duration > Duration::ZERO;
        crate::assert_with_log!(nonzero, "nonzero duration", true, nonzero);
        crate::test_complete!("collect_stats_after_drain");
    }

    #[test]
    fn drain_start_tracking() {
        init_test("drain_start_tracking");
        let signal = ShutdownSignal::new();

        let before = signal.drain_start();
        crate::assert_with_log!(
            before.is_none(),
            "no start before drain",
            true,
            before.is_none()
        );

        let began = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(began, "drain started", true, began);

        let after = signal.drain_start();
        crate::assert_with_log!(after.is_some(), "start after drain", true, after.is_some());
        crate::test_complete!("drain_start_tracking");
    }

    #[test]
    fn concurrent_begin_drain_only_one_wins() {
        init_test("concurrent_begin_drain_only_one_wins");
        let signal = ShutdownSignal::new();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let winners = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..2 {
            let sig = signal.clone();
            let b = std::sync::Arc::clone(&barrier);
            let w = std::sync::Arc::clone(&winners);
            handles.push(std::thread::spawn(move || {
                b.wait();
                if sig.begin_drain(Duration::from_secs(30)) {
                    w.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }));
        }

        barrier.wait();
        for h in handles {
            h.join().expect("thread panicked");
        }

        let winner_count = winners.load(std::sync::atomic::Ordering::Relaxed);
        crate::assert_with_log!(winner_count == 1, "exactly one winner", 1, winner_count);
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Draining,
            "phase is draining",
            ShutdownPhase::Draining,
            signal.phase()
        );
        crate::test_complete!("concurrent_begin_drain_only_one_wins");
    }

    #[test]
    fn mark_stopped_from_draining_skips_force_close() {
        init_test("mark_stopped_from_draining_skips_force_close");
        let signal = ShutdownSignal::new();
        let began = signal.begin_drain(Duration::from_secs(30));
        crate::assert_with_log!(began, "begin drain", true, began);

        // Directly mark stopped without going through ForceClosing
        signal.mark_stopped();
        crate::assert_with_log!(
            signal.phase() == ShutdownPhase::Stopped,
            "stopped from draining",
            ShutdownPhase::Stopped,
            signal.phase()
        );
        crate::test_complete!("mark_stopped_from_draining_skips_force_close");
    }

    #[test]
    fn shutdown_phase_debug_clone_copy_eq() {
        let p = ShutdownPhase::Draining;
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Draining"), "{dbg}");
        let copied: ShutdownPhase = p;
        let cloned = p;
        assert_eq!(copied, cloned);
        assert_ne!(p, ShutdownPhase::Running);
    }

    #[test]
    fn shutdown_stats_debug_clone() {
        let s = ShutdownStats {
            drained: 5,
            force_closed: 1,
            duration: Duration::from_secs(3),
            drain_report: None,
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("ShutdownStats"), "{dbg}");
        let cloned = s;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    // ------------------------------------------------------------------
    // Request-aware drain certificate (D2.1, br-...-eeexl1.2)
    // ------------------------------------------------------------------

    fn t(nanos: u64) -> Time {
        Time::from_nanos(nanos)
    }

    /// A clean drain from N in-flight requests down to zero reaches
    /// quiescence with nothing stranded and a converging certificate.
    #[test]
    fn drain_tracker_clean_drain_reaches_quiescence() {
        init_test("drain_tracker_clean_drain_reaches_quiescence");
        let mut tracker = GracefulDrainTracker::new(50, t(0));
        // Steady descent: 50 -> 0 in 10 even steps.
        for step in 1..=10 {
            let remaining = 50 - step * 5;
            tracker.observe(remaining);
        }
        assert_eq!(tracker.remaining(), 0);
        let report = tracker.finish(t(1_000_000), false);

        assert_eq!(report.requests_at_drain_start, 50);
        assert_eq!(report.requests_completed, 50);
        assert_eq!(report.requests_stranded, 0);
        assert!(report.reached_quiescence);
        assert!(!report.hard_deadline_hit);
        assert!(
            report.converging,
            "a monotone descent to zero must read as converging: {report:?}"
        );
        assert_eq!(report.drain_duration, Duration::from_millis(1));
        crate::test_complete!("drain_tracker_clean_drain_reaches_quiescence");
    }

    /// A drain that plateaus (no progress) is classified as stalled and
    /// strands the remaining requests when the hard deadline is hit.
    #[test]
    fn drain_tracker_stalled_drain_strands_requests() {
        init_test("drain_tracker_stalled_drain_strands_requests");
        let mut tracker = GracefulDrainTracker::new(8, t(0));
        // Stuck at 5 in-flight for many ticks: no progress.
        for _ in 0..40 {
            tracker.observe(5);
        }
        let report = tracker.finish(t(5_000_000), true);

        assert_eq!(report.requests_at_drain_start, 8);
        assert_eq!(report.requests_stranded, 5);
        assert_eq!(report.requests_completed, 3);
        assert!(!report.reached_quiescence);
        assert!(report.hard_deadline_hit);
        assert!(
            matches!(report.final_phase, DrainPhase::Stalled),
            "a long plateau must classify as stalled, got {}",
            report.final_phase
        );
        assert!(report.stall_detected, "stall must be detected: {report:?}");
        crate::test_complete!("drain_tracker_stalled_drain_strands_requests");
    }

    /// A partial drain that hits the hard deadline mid-descent strands only
    /// the still-in-flight requests and counts the rest as completed.
    #[test]
    fn drain_tracker_partial_drain_accounts_completed_and_stranded() {
        init_test("drain_tracker_partial_drain_accounts_completed_and_stranded");
        let mut tracker = GracefulDrainTracker::new(20, t(0));
        for remaining in [16, 12, 9, 7] {
            tracker.observe(remaining);
        }
        let report = tracker.finish(t(2_000_000), true);

        assert_eq!(report.requests_completed, 13);
        assert_eq!(report.requests_stranded, 7);
        assert_eq!(report.observations, 5); // initial + 4 observations
        assert!(report.hard_deadline_hit);
        assert!(!report.reached_quiescence);
        crate::test_complete!("drain_tracker_partial_drain_accounts_completed_and_stranded");
    }

    /// The report rendering is deterministic and golden-stable. The float
    /// fields are produced by the certificate from the fixed observation
    /// series, so the whole block is reproducible.
    #[test]
    fn drain_report_display_is_golden_stable() {
        init_test("drain_report_display_is_golden_stable");
        // A directly-constructed report keeps the golden independent of the
        // certificate's internal float evolution (which has its own tests);
        // this pins the operator-facing rendering contract.
        let report = GracefulDrainReport {
            requests_at_drain_start: 50,
            requests_completed: 50,
            requests_stranded: 0,
            requests_at_escalation: None,
            observations: 11,
            final_phase: DrainPhase::Quiescent,
            converging: true,
            confidence_bound: 0.987_654,
            estimated_remaining_steps: Some(0.0),
            stall_detected: false,
            reached_quiescence: true,
            hard_deadline_hit: false,
            drain_duration: Duration::from_millis(42),
        };
        let expected = "\
Graceful Drain Report
=====================
Requests at start:  50
Requests completed: 50
Requests stranded:  0
At escalation:      never
Observations:       11
Final drain phase:  quiescent
Converging:         true
Confidence bound:   0.987654
Est. remaining:     0.0 steps
Stall detected:     false
Reached quiescence: true
Hard deadline hit:  false
Drain duration:     42ms
";
        assert_eq!(report.to_string(), expected);
        crate::test_complete!("drain_report_display_is_golden_stable");
    }

    /// The estimated-remaining `None` branch renders as `N/A`.
    #[test]
    fn drain_report_display_handles_unknown_remaining() {
        init_test("drain_report_display_handles_unknown_remaining");
        let report = GracefulDrainReport {
            requests_at_drain_start: 3,
            requests_completed: 0,
            requests_stranded: 3,
            requests_at_escalation: Some(3),
            observations: 1,
            final_phase: DrainPhase::Warmup,
            converging: false,
            confidence_bound: 0.0,
            estimated_remaining_steps: None,
            stall_detected: false,
            reached_quiescence: false,
            hard_deadline_hit: true,
            drain_duration: Duration::ZERO,
        };
        let rendered = report.to_string();
        assert!(rendered.contains("Est. remaining:     N/A"), "{rendered}");
        assert!(
            rendered.contains("Final drain phase:  warmup"),
            "{rendered}"
        );
        assert!(rendered.contains("At escalation:      3"), "{rendered}");
        assert!(rendered.contains("Drain duration:     0ms"), "{rendered}");
        crate::test_complete!("drain_report_display_handles_unknown_remaining");
    }

    /// The supervisor records the in-flight count at the escalation
    /// transition; the report keeps the completed-vs-interrupted boundary
    /// (br-asupersync-server-stack-hardening-eeexl1.2, D2.4).
    #[test]
    fn supervisor_records_requests_at_escalation() {
        init_test("supervisor_records_requests_at_escalation");
        let mut supervisor =
            GracefulDrainSupervisor::new(5, t(0), Duration::from_secs(1), Duration::from_secs(10));

        // Within the soft budget: no escalation recorded.
        assert_eq!(supervisor.observe(5, t(500_000_000)), DrainStep::Continue);

        // Soft deadline elapses with 3 still in flight: escalation fires once
        // and captures the boundary.
        assert_eq!(supervisor.observe(3, t(1_500_000_000)), DrainStep::Escalate);
        assert_eq!(supervisor.observe(1, t(2_000_000_000)), DrainStep::Continue);
        assert_eq!(
            supervisor.observe(0, t(2_500_000_000)),
            DrainStep::Quiescent
        );

        let report = supervisor.finish(t(2_500_000_000), false);
        assert_eq!(report.requests_at_escalation, Some(3));
        assert_eq!(report.requests_completed, 5);
        assert!(report.reached_quiescence);
        crate::test_complete!("supervisor_records_requests_at_escalation");
    }

    /// A drain that reaches quiescence inside the soft budget never
    /// escalates, and the report says so.
    #[test]
    fn supervisor_reports_never_escalated_on_clean_drain() {
        init_test("supervisor_reports_never_escalated_on_clean_drain");
        let mut supervisor =
            GracefulDrainSupervisor::new(2, t(0), Duration::from_secs(1), Duration::from_secs(10));
        assert_eq!(supervisor.observe(1, t(200_000_000)), DrainStep::Continue);
        assert_eq!(supervisor.observe(0, t(400_000_000)), DrainStep::Quiescent);

        let report = supervisor.finish(t(400_000_000), false);
        assert_eq!(report.requests_at_escalation, None);
        assert!(report.to_string().contains("At escalation:      never"));
        crate::test_complete!("supervisor_reports_never_escalated_on_clean_drain");
    }

    /// If another driver path force-closes at the soft deadline before the
    /// supervisor's next tick, the report still preserves the last observed
    /// in-flight count as the escalation boundary.
    #[test]
    fn supervisor_records_external_escalation_before_quiescent_tick() {
        init_test("supervisor_records_external_escalation_before_quiescent_tick");
        let mut supervisor =
            GracefulDrainSupervisor::new(5, t(0), Duration::from_secs(1), Duration::from_secs(10));
        assert_eq!(supervisor.observe(5, t(500_000_000)), DrainStep::Continue);
        assert!(supervisor.record_external_escalation());
        assert_eq!(
            supervisor.observe(0, t(1_100_000_000)),
            DrainStep::Quiescent
        );

        let report = supervisor.finish(t(1_100_000_000), false);
        assert_eq!(report.requests_at_escalation, Some(5));
        assert!(report.reached_quiescence);
        crate::test_complete!("supervisor_records_external_escalation_before_quiescent_tick");
    }

    /// `finish` clamps a backward clock to a zero duration rather than
    /// underflowing.
    #[test]
    fn drain_tracker_backward_clock_is_zero_duration() {
        init_test("drain_tracker_backward_clock_is_zero_duration");
        let mut tracker = GracefulDrainTracker::new(2, t(1_000));
        tracker.observe(0);
        let report = tracker.finish(t(500), false);
        assert_eq!(report.drain_duration, Duration::ZERO);
        assert!(report.reached_quiescence);
        crate::test_complete!("drain_tracker_backward_clock_is_zero_duration");
    }

    // ------------------------------------------------------------------
    // Drain supervisor decision state machine (D2.2a)
    // ------------------------------------------------------------------

    /// A drain that empties before the soft budget reports Continue then
    /// Quiescent, never escalating.
    #[test]
    fn drain_supervisor_clean_drain_never_escalates() {
        init_test("drain_supervisor_clean_drain_never_escalates");
        let mut sup = GracefulDrainSupervisor::new(
            10,
            t(0),
            Duration::from_secs(30),
            Duration::from_secs(60),
        );
        assert_eq!(sup.observe(6, t(1_000_000_000)), DrainStep::Continue);
        assert_eq!(sup.observe(2, t(2_000_000_000)), DrainStep::Continue);
        assert_eq!(sup.observe(0, t(3_000_000_000)), DrainStep::Quiescent);
        assert!(!sup.escalated());
        let report = sup.finish(t(3_000_000_000), false);
        assert!(report.reached_quiescence);
        assert_eq!(report.requests_stranded, 0);
        crate::test_complete!("drain_supervisor_clean_drain_never_escalates");
    }

    /// Crossing the soft budget with requests still in flight escalates
    /// exactly once, then keeps reporting Continue until the hard deadline.
    #[test]
    fn drain_supervisor_escalates_once_at_soft_budget() {
        init_test("drain_supervisor_escalates_once_at_soft_budget");
        let mut sup =
            GracefulDrainSupervisor::new(5, t(0), Duration::from_secs(10), Duration::from_secs(30));
        // Before the soft deadline: keep waiting.
        assert_eq!(sup.observe(5, t(5_000_000_000)), DrainStep::Continue);
        // First observation at/after the soft deadline escalates.
        assert_eq!(sup.observe(4, t(10_000_000_000)), DrainStep::Escalate);
        assert!(sup.escalated());
        // Subsequent observations in the escalation window do not re-escalate.
        assert_eq!(sup.observe(3, t(12_000_000_000)), DrainStep::Continue);
        assert_eq!(sup.observe(2, t(20_000_000_000)), DrainStep::Continue);
        crate::test_complete!("drain_supervisor_escalates_once_at_soft_budget");
    }

    /// Reaching the hard deadline with requests still in flight reports
    /// HardDeadline; the report records the stranded requests.
    #[test]
    fn drain_supervisor_hard_deadline_strands_remaining() {
        init_test("drain_supervisor_hard_deadline_strands_remaining");
        let mut sup =
            GracefulDrainSupervisor::new(8, t(0), Duration::from_secs(10), Duration::from_secs(20));
        assert_eq!(sup.observe(6, t(10_000_000_000)), DrainStep::Escalate);
        assert_eq!(sup.observe(4, t(20_000_000_000)), DrainStep::HardDeadline);
        let report = sup.finish(t(20_000_000_000), true);
        assert!(report.hard_deadline_hit);
        assert_eq!(report.requests_stranded, 4);
        assert_eq!(report.requests_completed, 4);
        assert!(!report.reached_quiescence);
        crate::test_complete!("drain_supervisor_hard_deadline_strands_remaining");
    }

    /// Quiescence wins over a simultaneously-elapsed hard deadline: a tick
    /// that observes zero in-flight reports Quiescent even past the deadline.
    #[test]
    fn drain_supervisor_quiescence_beats_hard_deadline() {
        init_test("drain_supervisor_quiescence_beats_hard_deadline");
        let mut sup =
            GracefulDrainSupervisor::new(3, t(0), Duration::from_secs(10), Duration::from_secs(20));
        // Past the hard deadline, but the count hit zero this tick.
        assert_eq!(sup.observe(0, t(25_000_000_000)), DrainStep::Quiescent);
        let report = sup.finish(t(25_000_000_000), false);
        assert!(report.reached_quiescence);
        assert_eq!(report.requests_stranded, 0);
        crate::test_complete!("drain_supervisor_quiescence_beats_hard_deadline");
    }

    /// `hard_budget` is clamped up to at least `drain_budget` so the hard
    /// deadline can never precede the soft escalation point.
    #[test]
    fn drain_supervisor_clamps_hard_budget_below_soft() {
        init_test("drain_supervisor_clamps_hard_budget_below_soft");
        let sup = GracefulDrainSupervisor::new(
            1,
            t(0),
            Duration::from_secs(30),
            Duration::from_secs(5), // smaller than the soft budget
        );
        assert!(
            sup.hard_deadline() >= sup.drain_deadline(),
            "hard deadline must not precede the soft deadline"
        );
        crate::test_complete!("drain_supervisor_clamps_hard_budget_below_soft");
    }
