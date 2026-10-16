    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
    use crate::cx::Cx;
    use crate::runtime::yield_now;
    use crate::signal::ShutdownController;
    use crate::types::Budget;
    use parking_lot::Mutex;
    use serde_json::Value;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn poll_once<F: std::future::Future + Unpin>(fut: &mut F) -> Poll<F::Output> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        std::pin::Pin::new(fut).poll(&mut cx)
    }

    fn poll_until_ready<F: Future + Unpin>(fut: &mut F, max_polls: usize) -> Option<F::Output> {
        for _ in 0..max_polls {
            if let Poll::Ready(output) = poll_once(fut) {
                return Some(output);
            }
        }
        None
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct ShutdownThenComplete {
        shutdown: Option<ShutdownController>,
        remaining_pending_polls: usize,
        value: i32,
    }

    impl ShutdownThenComplete {
        fn new(shutdown: ShutdownController, remaining_pending_polls: usize, value: i32) -> Self {
            Self {
                shutdown: Some(shutdown),
                remaining_pending_polls,
                value,
            }
        }
    }

    impl Future for ShutdownThenComplete {
        type Output = i32;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if let Some(shutdown) = self.shutdown.take() {
                shutdown.shutdown();
            }

            if self.remaining_pending_polls == 0 {
                return Poll::Ready(self.value);
            }

            self.remaining_pending_polls -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    struct ShutdownThenPending {
        shutdown: Option<ShutdownController>,
    }

    impl ShutdownThenPending {
        fn new(shutdown: ShutdownController) -> Self {
            Self {
                shutdown: Some(shutdown),
            }
        }
    }

    impl Future for ShutdownThenPending {
        type Output = i32;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if let Some(shutdown) = self.shutdown.take() {
                shutdown.shutdown();
            }

            Poll::Pending
        }
    }

    thread_local! {
        static TEST_GRACE_TIME_BASE: std::time::Instant = std::time::Instant::now();
        static TEST_GRACE_TIME_NANOS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    fn test_grace_time_now() -> std::time::Instant {
        TEST_GRACE_TIME_BASE.with(|base| {
            let offset = Duration::from_nanos(TEST_GRACE_TIME_NANOS.with(std::cell::Cell::get));
            base.checked_add(offset).unwrap_or(*base)
        })
    }

    fn test_shutdown_time_now() -> Time {
        Time::from_nanos(TEST_GRACE_TIME_NANOS.with(std::cell::Cell::get))
    }

    struct ShutdownThenAdvanceTimeAndComplete {
        shutdown: Option<ShutdownController>,
        advance_nanos: u64,
        complete_after_pending_polls: usize,
        value: i32,
    }

    impl ShutdownThenAdvanceTimeAndComplete {
        fn new(
            shutdown: ShutdownController,
            advance_nanos: u64,
            complete_after_pending_polls: usize,
            value: i32,
        ) -> Self {
            Self {
                shutdown: Some(shutdown),
                advance_nanos,
                complete_after_pending_polls,
                value,
            }
        }
    }

    impl Future for ShutdownThenAdvanceTimeAndComplete {
        type Output = i32;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if let Some(shutdown) = self.shutdown.take() {
                shutdown.shutdown();
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            if self.complete_after_pending_polls == 0 {
                return Poll::Ready(self.value);
            }

            TEST_GRACE_TIME_NANOS
                .with(|nanos| nanos.set(nanos.get().saturating_add(self.advance_nanos)));
            self.complete_after_pending_polls -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    struct ShutdownThenAdvanceTimeAndPending {
        shutdown: Option<ShutdownController>,
        advance_nanos: u64,
    }

    impl ShutdownThenAdvanceTimeAndPending {
        fn new(shutdown: ShutdownController, advance_nanos: u64) -> Self {
            Self {
                shutdown: Some(shutdown),
                advance_nanos,
            }
        }
    }

    impl Future for ShutdownThenAdvanceTimeAndPending {
        type Output = i32;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if let Some(shutdown) = self.shutdown.take() {
                shutdown.shutdown();
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            TEST_GRACE_TIME_NANOS
                .with(|nanos| nanos.set(nanos.get().saturating_add(self.advance_nanos)));
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    #[test]
    fn graceful_outcome_completed() {
        init_test("graceful_outcome_completed");
        let outcome: GracefulOutcome<i32> = GracefulOutcome::Completed(42);
        let completed = outcome.is_completed();
        crate::assert_with_log!(completed, "completed", true, completed);
        let shutdown = outcome.is_shutdown();
        crate::assert_with_log!(!shutdown, "not shutdown", false, shutdown);
        let value = outcome.into_completed();
        crate::assert_with_log!(value == Some(42), "value", Some(42), value);
        crate::test_complete!("graceful_outcome_completed");
    }

    #[test]
    fn graceful_outcome_shutdown() {
        init_test("graceful_outcome_shutdown");
        let outcome: GracefulOutcome<i32> = GracefulOutcome::ShutdownSignaled;
        let completed = outcome.is_completed();
        crate::assert_with_log!(!completed, "not completed", false, completed);
        let shutdown = outcome.is_shutdown();
        crate::assert_with_log!(shutdown, "shutdown", true, shutdown);
        let value = outcome.into_completed();
        let none = value.is_none();
        crate::assert_with_log!(none, "value none", true, none);
        crate::test_complete!("graceful_outcome_shutdown");
    }

    #[test]
    fn graceful_outcome_map() {
        init_test("graceful_outcome_map");
        let outcome: GracefulOutcome<i32> = GracefulOutcome::Completed(21);
        let mapped = outcome.map(|x| x * 2);
        let value = mapped.into_completed();
        crate::assert_with_log!(value == Some(42), "mapped value", Some(42), value);

        let outcome: GracefulOutcome<i32> = GracefulOutcome::ShutdownSignaled;
        let mapped = outcome.map(|x| x * 2);
        let shutdown = mapped.is_shutdown();
        crate::assert_with_log!(shutdown, "mapped shutdown", true, shutdown);
        crate::test_complete!("graceful_outcome_map");
    }

    #[test]
    fn with_graceful_shutdown_already_shutdown() {
        init_test("with_graceful_shutdown_already_shutdown");
        let controller = ShutdownController::new();
        controller.shutdown();
        let receiver = controller.subscribe();

        // Use std::future::ready which is Unpin
        let ready_fut = std::future::ready(42);
        let fut = with_graceful_shutdown(ready_fut, receiver);
        let mut boxed = Box::pin(fut);

        // Should immediately return ShutdownSignaled.
        match poll_once(&mut boxed) {
            Poll::Ready(outcome) => {
                let shutdown = outcome.is_shutdown();
                crate::assert_with_log!(shutdown, "shutdown", true, shutdown);
            }
            Poll::Pending => {
                crate::assert_with_log!(
                    false,
                    "already-shutdown future should be ready",
                    true,
                    false
                );
            }
        }
        crate::test_complete!("with_graceful_shutdown_already_shutdown");
    }

    #[test]
    fn graceful_builder_config() {
        init_test("graceful_builder_config");
        let controller = ShutdownController::new();
        let receiver = controller.subscribe();

        let builder = GracefulBuilder::new(receiver)
            .grace_period(Duration::from_secs(60))
            .logging(false);

        let grace_period = builder.config().grace_period;
        crate::assert_with_log!(
            grace_period == Duration::from_secs(60),
            "grace_period",
            Duration::from_secs(60),
            grace_period
        );
        let log_events = builder.config().log_events;
        crate::assert_with_log!(!log_events, "log_events false", false, log_events);
        crate::test_complete!("graceful_builder_config");
    }

    #[test]
    fn graceful_builder_run_completes_within_grace_period_after_shutdown() {
        init_test("graceful_builder_run_completes_within_grace_period_after_shutdown");
        let controller = ShutdownController::new();
        let receiver = controller.subscribe();
        let builder = GracefulBuilder::new(receiver)
            .grace_period(Duration::from_millis(50))
            .logging(false);
        let fut = ShutdownThenComplete::new(controller, 1, 42);
        let result = futures_lite::future::block_on(builder.run(fut));

        crate::assert_with_log!(
            matches!(result, GracefulOutcome::Completed(42)),
            "future completed during grace period",
            "GracefulOutcome::Completed(42)",
            result
        );
        crate::test_complete!("graceful_builder_run_completes_within_grace_period_after_shutdown");
    }

    #[test]
    fn graceful_builder_run_returns_shutdown_after_grace_period_elapses() {
        init_test("graceful_builder_run_returns_shutdown_after_grace_period_elapses");
        let controller = ShutdownController::new();
        let receiver = controller.subscribe();
        let builder = GracefulBuilder::new(receiver)
            .grace_period(Duration::from_millis(10))
            .logging(false);
        let fut = ShutdownThenPending::new(controller);
        let result = futures_lite::future::block_on(builder.run(fut));

        crate::assert_with_log!(
            matches!(result, GracefulOutcome::ShutdownSignaled),
            "future interrupted after grace period elapsed",
            "GracefulOutcome::ShutdownSignaled",
            result
        );
        crate::test_complete!("graceful_builder_run_returns_shutdown_after_grace_period_elapses");
    }

    #[test]
    fn grace_period_guard() {
        init_test("grace_period_guard");
        TEST_GRACE_TIME_NANOS.with(|n| n.set(0));
        let guard =
            GracePeriodGuard::with_time_getter(Duration::from_millis(100), test_grace_time_now);
        let elapsed = guard.is_elapsed();
        crate::assert_with_log!(!elapsed, "not elapsed", false, elapsed);
        let remaining = guard.remaining();
        crate::assert_with_log!(
            remaining == Duration::from_millis(100),
            "remaining == 100ms",
            Duration::from_millis(100),
            remaining
        );

        TEST_GRACE_TIME_NANOS.with(|n| n.set(40_000_000));
        let elapsed = guard.is_elapsed();
        crate::assert_with_log!(!elapsed, "not elapsed at 40ms", false, elapsed);
        let remaining = guard.remaining();
        crate::assert_with_log!(
            remaining == Duration::from_millis(60),
            "remaining == 60ms",
            Duration::from_millis(60),
            remaining
        );

        TEST_GRACE_TIME_NANOS.with(|n| n.set(150_000_000));
        let elapsed = guard.is_elapsed();
        crate::assert_with_log!(elapsed, "elapsed at 150ms", true, elapsed);
        let remaining = guard.remaining();
        crate::assert_with_log!(
            remaining == Duration::ZERO,
            "remaining zero",
            Duration::ZERO,
            remaining
        );
        crate::test_complete!("grace_period_guard");
    }

    #[test]
    fn graceful_config_builder() {
        init_test("graceful_config_builder");
        TEST_GRACE_TIME_NANOS.with(|n| n.set(0));
        let config = GracefulConfig::default()
            .with_grace_period(Duration::from_secs(10))
            .with_logging(false)
            .with_time_getter(test_shutdown_time_now);

        crate::assert_with_log!(
            config.grace_period == Duration::from_secs(10),
            "grace_period",
            Duration::from_secs(10),
            config.grace_period
        );
        crate::assert_with_log!(
            !config.log_events,
            "log_events false",
            false,
            config.log_events
        );
        crate::assert_with_log!(
            config
                .time_getter
                .is_some_and(|time_getter| time_getter() == Time::ZERO),
            "time_getter",
            true,
            config.time_getter.map(|time_getter| time_getter())
        );
        crate::test_complete!("graceful_config_builder");
    }

    #[test]
    fn graceful_builder_run_completes_with_time_getter() {
        init_test("graceful_builder_run_completes_with_time_getter");
        TEST_GRACE_TIME_NANOS.with(|n| n.set(0));
        let controller = ShutdownController::new();
        let receiver = controller.subscribe();
        let builder = GracefulBuilder::new(receiver)
            .grace_period(Duration::from_millis(10))
            .logging(false)
            .time_getter(test_shutdown_time_now);
        let fut = ShutdownThenAdvanceTimeAndComplete::new(controller, 4_000_000, 1, 42);
        let mut run = Box::pin(builder.run(fut));
        let result = poll_until_ready(&mut run, 4);

        crate::assert_with_log!(
            matches!(result, Some(GracefulOutcome::Completed(42))),
            "future completed within deterministic grace period",
            "Some(GracefulOutcome::Completed(42))",
            result
        );
        crate::test_complete!("graceful_builder_run_completes_with_time_getter");
    }

    #[test]
    fn graceful_builder_run_times_out_with_time_getter() {
        init_test("graceful_builder_run_times_out_with_time_getter");
        TEST_GRACE_TIME_NANOS.with(|n| n.set(0));
        let controller = ShutdownController::new();
        let receiver = controller.subscribe();
        let builder = GracefulBuilder::new(receiver)
            .grace_period(Duration::from_millis(10))
            .logging(false)
            .time_getter(test_shutdown_time_now);
        let fut = ShutdownThenAdvanceTimeAndPending::new(controller, 15_000_000);
        let mut run = Box::pin(builder.run(fut));
        let result = poll_until_ready(&mut run, 3);

        crate::assert_with_log!(
            matches!(result, Some(GracefulOutcome::ShutdownSignaled)),
            "future times out from deterministic grace-period clock",
            "Some(GracefulOutcome::ShutdownSignaled)",
            result
        );
        crate::test_complete!("graceful_builder_run_times_out_with_time_getter");
    }

    #[test]
    fn graceful_builder_run_completes_during_shutdown_under_lab_runtime() {
        init_test("graceful_builder_run_completes_during_shutdown_under_lab_runtime");

        let config = TestConfig::new()
            .with_seed(0x6A00_5101)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let (result, checkpoints) = LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = Cx::current().expect("lab runtime should install a current Cx");
            let shutdown_task_cx = cx.clone();
            let controller = ShutdownController::new();
            let receiver = controller.subscribe();
            let checkpoints = Arc::new(Mutex::new(Vec::<Value>::new()));

            let shutdown_checkpoints = Arc::clone(&checkpoints);
            let shutdown_task = LabRuntimeTarget::spawn(&shutdown_task_cx, Budget::INFINITE, {
                let controller = controller.clone();
                async move {
                    yield_now().await;
                    let event = serde_json::json!({
                        "phase": "shutdown_requested",
                        "after_yields": 1,
                    });
                    tracing::info!(event = %event, "graceful_lab_checkpoint");
                    shutdown_checkpoints.lock().push(event);
                    controller.shutdown();
                }
            });

            yield_now().await;

            let task_checkpoints = Arc::clone(&checkpoints);
            let result = GracefulBuilder::new(receiver)
                .grace_period(Duration::from_secs(1))
                .logging(false)
                .run(async move {
                    let started = serde_json::json!({
                        "phase": "task_started",
                        "yield_count": 2,
                    });
                    tracing::info!(event = %started, "graceful_lab_checkpoint");
                    task_checkpoints.lock().push(started);

                    yield_now().await;
                    yield_now().await;

                    let completed = serde_json::json!({
                        "phase": "task_completed",
                        "value": 42,
                    });
                    tracing::info!(event = %completed, "graceful_lab_checkpoint");
                    task_checkpoints.lock().push(completed);
                    42
                })
                .await;

            let shutdown_outcome = shutdown_task.await;
            crate::assert_with_log!(
                matches!(shutdown_outcome, crate::types::Outcome::Ok(())),
                "shutdown task completes successfully",
                true,
                matches!(shutdown_outcome, crate::types::Outcome::Ok(()))
            );

            (result, checkpoints.lock().clone())
        });

        crate::assert_with_log!(
            matches!(result, GracefulOutcome::Completed(42)),
            "graceful builder completes task during shutdown grace period",
            "GracefulOutcome::Completed(42)",
            result
        );
        crate::assert_with_log!(
            checkpoints.len() == 3,
            "graceful lab runtime emits three checkpoints",
            3,
            checkpoints.len()
        );
        crate::assert_with_log!(
            checkpoints[0]["phase"] == "task_started",
            "task starts before shutdown request",
            "task_started",
            checkpoints[0]["phase"].clone()
        );
        crate::assert_with_log!(
            checkpoints[1]["phase"] == "shutdown_requested",
            "shutdown request recorded second",
            "shutdown_requested",
            checkpoints[1]["phase"].clone()
        );
        crate::assert_with_log!(
            checkpoints[2]["phase"] == "task_completed",
            "task completion recorded after shutdown request",
            "task_completed",
            checkpoints[2]["phase"].clone()
        );

        let violations = runtime.oracles.check_all(runtime.now());
        crate::assert_with_log!(
            violations.is_empty(),
            "graceful lab runtime leaves no oracle violations",
            true,
            violations.is_empty()
        );

        crate::test_complete!("graceful_builder_run_completes_during_shutdown_under_lab_runtime");
    }

    // =========================================================================
    // Wave 27: Data-type trait coverage
    // =========================================================================

    #[test]
    fn graceful_outcome_debug() {
        let completed: GracefulOutcome<i32> = GracefulOutcome::Completed(42);
        let dbg = format!("{completed:?}");
        assert!(dbg.contains("Completed"));
        assert!(dbg.contains("42"));

        let shutdown: GracefulOutcome<i32> = GracefulOutcome::ShutdownSignaled;
        let dbg = format!("{shutdown:?}");
        assert!(dbg.contains("ShutdownSignaled"));
    }

    #[test]
    fn graceful_outcome_clone_copy() {
        let outcome: GracefulOutcome<i32> = GracefulOutcome::Completed(7);
        let cloned = outcome;
        let copied = outcome; // Copy
        assert_eq!(cloned, copied);
        assert_eq!(cloned, GracefulOutcome::Completed(7));
    }

    #[test]
    fn graceful_outcome_eq() {
        let a: GracefulOutcome<i32> = GracefulOutcome::Completed(1);
        let b: GracefulOutcome<i32> = GracefulOutcome::Completed(1);
        let c: GracefulOutcome<i32> = GracefulOutcome::Completed(2);
        let d: GracefulOutcome<i32> = GracefulOutcome::ShutdownSignaled;
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn graceful_config_debug() {
        let config = GracefulConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("GracefulConfig"));
        assert!(dbg.contains("grace_period"));
        assert!(dbg.contains("log_events"));
    }

    #[test]
    fn graceful_config_clone() {
        let config = GracefulConfig::default()
            .with_grace_period(Duration::from_secs(5))
            .with_logging(false);
        let config2 = config;
        assert_eq!(config2.grace_period, Duration::from_secs(5));
        assert!(!config2.log_events);
    }

    #[test]
    fn graceful_config_default_values() {
        let config = GracefulConfig::default();
        assert_eq!(config.grace_period, Duration::from_secs(30));
        assert!(config.log_events);
        assert!(config.time_getter.is_none());
    }

    #[test]
    fn grace_period_guard_debug() {
        let guard = GracePeriodGuard::new(Duration::from_secs(60));
        let dbg = format!("{guard:?}");
        assert!(dbg.contains("GracePeriodGuard"));
        assert!(dbg.contains("duration"));
    }

    #[test]
    fn grace_period_guard_duration_accessor() {
        let guard = GracePeriodGuard::new(Duration::from_millis(500));
        assert_eq!(guard.duration(), Duration::from_millis(500));
    }

    #[test]
    fn grace_period_guard_started_at_accessor() {
        TEST_GRACE_TIME_NANOS.with(|n| n.set(3_000_000));
        let guard = GracePeriodGuard::with_time_getter(Duration::from_secs(1), test_grace_time_now);
        assert_eq!(guard.started_at(), test_grace_time_now());
    }

    #[test]
    fn grace_period_guard_remaining_and_elapsed_at() {
        TEST_GRACE_TIME_NANOS.with(|n| n.set(0));
        let guard =
            GracePeriodGuard::with_time_getter(Duration::from_millis(250), test_grace_time_now);

        let at_100 = guard
            .started_at()
            .checked_add(Duration::from_millis(100))
            .expect("test instant should not overflow");
        assert_eq!(guard.remaining_at(at_100), Duration::from_millis(150));
        assert!(!guard.is_elapsed_at(at_100));

        let at_260 = guard
            .started_at()
            .checked_add(Duration::from_millis(260))
            .expect("test instant should not overflow");
        assert_eq!(guard.remaining_at(at_260), Duration::ZERO);
        assert!(guard.is_elapsed_at(at_260));
    }
