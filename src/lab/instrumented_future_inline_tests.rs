    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::task::{Poll, Waker};

    /// A simple noop waker for testing.
    /// Creates a noop waker for testing.
    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    /// A future that yields a specific number of times before completing.
    struct YieldingFuture {
        yields_remaining: u32,
        value: i32,
    }

    impl YieldingFuture {
        fn new(yields: u32, value: i32) -> Self {
            Self {
                yields_remaining: yields,
                value,
            }
        }
    }

    impl Future for YieldingFuture {
        type Output = i32;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.yields_remaining > 0 {
                self.yields_remaining -= 1;
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(self.value)
            }
        }
    }

    /// Helper to poll a pinned future to completion using a safe waker.
    fn poll_to_completion<F: Future>(future: F) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Box::pin(future);

        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(output) => return output,
                Poll::Pending => {}
            }
        }
    }

    #[test]
    fn recording_mode_tracks_await_points() {
        let future = YieldingFuture::new(3, 42);
        let instrumented = InstrumentedFuture::recording(future);

        let result = poll_to_completion(instrumented);

        match result {
            InstrumentedPollResult::Inner(value) => assert_eq!(value, 42),
            InstrumentedPollResult::CancellationInjected(_) => {
                panic!("should not inject in recording mode")
            }
        }
    }

    #[test]
    fn recording_captures_all_await_points() {
        let future = YieldingFuture::new(3, 42);
        let injector = CancellationInjector::recording();
        let instrumented = InstrumentedFuture::new(future, injector.clone());

        let _ = poll_to_completion(instrumented);

        // 3 yields + 1 final completion = 4 polls
        let recorded = injector.recorded_points();
        assert_eq!(recorded, vec![1, 2, 3, 4]);
    }

    #[test]
    fn injection_at_specific_sequence() {
        let future = YieldingFuture::new(5, 42);
        let injector = CancellationInjector::inject_at(3);
        let instrumented = InstrumentedFuture::new(future, injector.clone());

        let result = poll_to_completion(instrumented);

        match result {
            InstrumentedPollResult::CancellationInjected(point) => {
                assert_eq!(point, 3);
            }
            InstrumentedPollResult::Inner(_) => {
                panic!("should have injected cancellation")
            }
        }

        // Should have recorded points 1, 2, 3 before cancellation
        let recorded = injector.recorded_points();
        assert_eq!(recorded, vec![1, 2, 3]);
        assert_eq!(injector.injection_count(), 1);
    }

    #[test]
    fn injection_every_nth() {
        let future = YieldingFuture::new(10, 42);
        let injector = CancellationInjector::inject_every_nth(4);
        let instrumented = InstrumentedFuture::new(future, injector.clone());

        let result = poll_to_completion(instrumented);

        match result {
            InstrumentedPollResult::CancellationInjected(point) => {
                assert_eq!(point, 4); // First multiple of 4
            }
            InstrumentedPollResult::Inner(_) => {
                panic!("should have injected cancellation")
            }
        }

        assert_eq!(injector.recorded_points(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn with_strategy_at_point_preserves_task_id_for_injection() {
        let task_id = TaskId::from_arena(crate::util::ArenaIndex::new(11, 0));
        let point = AwaitPoint::new(Some(task_id), 3);
        let injector = CancellationInjector::with_strategy(InjectionStrategy::AtPoint(point));

        assert!(injector.should_inject_at(3));
        assert_eq!(injector.injection_count(), 1);
    }

    #[test]
    fn await_point_identification() {
        let task_id = TaskId::from_arena(crate::util::ArenaIndex::new(1, 0));
        let point = AwaitPoint::new(Some(task_id), 5);

        assert_eq!(point.task_id, Some(task_id));
        assert_eq!(point.sequence, 5);

        let anon = AwaitPoint::anonymous(10);
        assert_eq!(anon.task_id, None);
        assert_eq!(anon.sequence, 10);
    }

    #[test]
    fn instrumented_future_tracks_await_count() {
        let future = YieldingFuture::new(2, 42);
        let instrumented = InstrumentedFuture::recording(future);
        let mut pinned = Box::pin(instrumented);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First poll
        assert!(matches!(pinned.as_mut().poll(&mut cx), Poll::Pending));
        assert_eq!(pinned.await_count(), 1);

        // Second poll
        assert!(matches!(pinned.as_mut().poll(&mut cx), Poll::Pending));
        assert_eq!(pinned.await_count(), 2);

        // Third poll (completes)
        assert!(matches!(pinned.as_mut().poll(&mut cx), Poll::Ready(_)));
        assert_eq!(pinned.await_count(), 3);
    }

    #[test]
    fn cancellation_is_idempotent() {
        let future = YieldingFuture::new(5, 42);
        let injector = CancellationInjector::inject_at(2);
        let instrumented = InstrumentedFuture::new(future, injector);
        let mut pinned = Box::pin(instrumented);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First poll: pending
        assert!(matches!(pinned.as_mut().poll(&mut cx), Poll::Pending));
        assert!(!pinned.was_cancelled());

        // Second poll: cancellation injected
        let result = pinned.as_mut().poll(&mut cx);
        assert!(matches!(
            result,
            Poll::Ready(InstrumentedPollResult::CancellationInjected(2))
        ));
        assert!(pinned.was_cancelled());
        assert_eq!(pinned.injection_point(), Some(2));

        // Third poll: still cancelled (idempotent)
        let result = pinned.as_mut().poll(&mut cx);
        assert!(matches!(
            result,
            Poll::Ready(InstrumentedPollResult::CancellationInjected(2))
        ));
    }

    #[test]
    fn strategy_never_does_not_inject() {
        let injector = CancellationInjector::with_strategy(InjectionStrategy::Never);

        assert!(!injector.should_inject_at(1));
        assert!(!injector.should_inject_at(100));
        assert!(!injector.should_inject_at(1000));
    }

    #[test]
    fn clear_recorded_works() {
        let injector = CancellationInjector::recording();

        injector.record_await(1);
        injector.record_await(2);
        injector.record_await(3);

        assert_eq!(injector.recorded_points().len(), 3);

        injector.clear_recorded();

        assert!(injector.recorded_points().is_empty());
    }

    // ========== Tests for extended strategies ==========

    #[test]
    fn strategy_all_points_selects_all() {
        let recorded = vec![1, 2, 3, 4, 5];
        let strategy = InjectionStrategy::AllPoints;
        let selected = strategy.select_points(&recorded, 42);
        assert_eq!(selected, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn strategy_first_n_selects_first() {
        let recorded = vec![1, 2, 3, 4, 5];
        let strategy = InjectionStrategy::FirstN(3);
        let selected = strategy.select_points(&recorded, 42);
        assert_eq!(selected, vec![1, 2, 3]);
    }

    #[test]
    fn strategy_first_n_handles_overflow() {
        let recorded = vec![1, 2];
        let strategy = InjectionStrategy::FirstN(5);
        let selected = strategy.select_points(&recorded, 42);
        assert_eq!(selected, vec![1, 2]);
    }

    #[test]
    fn strategy_specific_points_filters() {
        let recorded = vec![1, 2, 3, 4, 5];
        let strategy = InjectionStrategy::SpecificPoints(vec![2, 4, 6]);
        let selected = strategy.select_points(&recorded, 42);
        // 6 is not in recorded, so only 2 and 4
        assert_eq!(selected, vec![2, 4]);
    }

    #[test]
    fn strategy_random_sample_is_deterministic() {
        let recorded = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let strategy = InjectionStrategy::RandomSample(3);

        // Same seed should give same results
        let selected1 = strategy.select_points(&recorded, 12345);
        let selected2 = strategy.select_points(&recorded, 12345);
        assert_eq!(selected1, selected2);

        // Different seed should (likely) give different results
        let selected3 = strategy.select_points(&recorded, 99999);
        // With high probability they differ; we check the length at least
        assert_eq!(selected3.len(), 3);
    }

    #[test]
    fn strategy_random_sample_respects_count() {
        let recorded = vec![1, 2, 3, 4, 5];
        let strategy = InjectionStrategy::RandomSample(3);
        let selected = strategy.select_points(&recorded, 42);
        assert_eq!(selected.len(), 3);
    }

    #[test]
    fn strategy_probabilistic_is_deterministic() {
        let recorded: Vec<u64> = (1..=20).collect();
        let strategy = InjectionStrategy::Probabilistic(0.5);

        let selected1 = strategy.select_points(&recorded, 42);
        let selected2 = strategy.select_points(&recorded, 42);
        assert_eq!(selected1, selected2);
    }

    #[test]
    fn strategy_probabilistic_respects_probability() {
        let recorded: Vec<u64> = (1..=100).collect();

        // With p=1.0, should select all
        let strategy_all = InjectionStrategy::Probabilistic(1.0);
        let selected_all = strategy_all.select_points(&recorded, 42);
        assert_eq!(selected_all.len(), 100);

        // With p=0.0, should select none
        let strategy_none = InjectionStrategy::Probabilistic(0.0);
        let selected_none = strategy_none.select_points(&recorded, 42);
        assert!(selected_none.is_empty());
    }

    #[test]
    fn strategy_every_nth_selects_multiples() {
        let recorded = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let strategy = InjectionStrategy::EveryNth(3);
        let selected = strategy.select_points(&recorded, 42);
        // 3, 6, 9 are multiples of 3
        assert_eq!(selected, vec![3, 6, 9]);
    }

    // ========== Tests for InjectionRunner ==========

    #[test]
    fn injection_runner_recording_phase() {
        let mut runner = InjectionRunner::new(42);

        let report = runner.run_with_injection(
            InjectionStrategy::Never,
            |injector| {
                let future = YieldingFuture::new(3, 42);
                InstrumentedFuture::new(future, injector)
            },
            |instrumented| {
                let _ = poll_to_completion(instrumented);
                InjectionOutcome::Success
            },
        );

        // Recording run with Never strategy = no injection runs
        assert_eq!(report.total_await_points, 4); // 3 yields + 1 completion
        assert_eq!(report.tests_run, 0);
        assert!(report.all_passed());
    }

    #[test]
    fn injection_runner_resets_mode_after_run() {
        let mut runner = InjectionRunner::new(42);

        let _ = runner.run_with_injection(
            InjectionStrategy::FirstN(1),
            |injector| {
                let future = YieldingFuture::new(2, 7);
                InstrumentedFuture::new(future, injector)
            },
            |instrumented| {
                let _ = poll_to_completion(instrumented);
                InjectionOutcome::Success
            },
        );

        assert_eq!(runner.current_mode(), InjectionMode::Recording);
    }

    #[test]
    fn injection_runner_all_points_strategy() {
        let mut runner = InjectionRunner::new(42);

        let report = runner.run_with_injection(
            InjectionStrategy::AllPoints,
            |injector| {
                let future = YieldingFuture::new(3, 42);
                InstrumentedFuture::new(future, injector)
            },
            |instrumented| {
                let result = poll_to_completion(instrumented);
                // Both completion and cancellation are acceptable
                match result {
                    InstrumentedPollResult::Inner(_)
                    | InstrumentedPollResult::CancellationInjected(_) => InjectionOutcome::Success,
                }
            },
        );

        // Should run injection at all 4 await points
        assert_eq!(report.total_await_points, 4);
        assert_eq!(report.tests_run, 4);
        assert!(report.all_passed());
    }

    #[test]
    fn injection_runner_first_n_strategy() {
        let mut runner = InjectionRunner::new(42);

        let report = runner.run_with_injection(
            InjectionStrategy::FirstN(2),
            |injector| {
                let future = YieldingFuture::new(5, 42);
                InstrumentedFuture::new(future, injector)
            },
            |instrumented| {
                let _ = poll_to_completion(instrumented);
                InjectionOutcome::Success
            },
        );

        // Should only run at first 2 points
        assert_eq!(report.tests_run, 2);
        assert!(report.all_passed());
    }

    #[test]
    fn injection_runner_tracks_failures() {
        let mut runner = InjectionRunner::new(42);

        let report = runner.run_with_injection(
            InjectionStrategy::AllPoints,
            |injector| {
                let future = YieldingFuture::new(3, 42);
                InstrumentedFuture::new(future, injector)
            },
            |instrumented| {
                let result = poll_to_completion(instrumented);
                // Fail on cancellation at point 2
                match result {
                    InstrumentedPollResult::CancellationInjected(2) => {
                        InjectionOutcome::AssertionFailed("Failed at point 2".to_string())
                    }
                    _ => InjectionOutcome::Success,
                }
            },
        );

        // Should have 1 failure
        assert_eq!(report.failures, 1);
        assert!(!report.all_passed());

        let failures = report.failures();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].injection_point, 2);
    }

    #[test]
    fn injection_report_from_results() {
        let results = vec![
            InjectionResult::success(1, 0),
            InjectionResult::success(2, 1),
            InjectionResult::panic(3, "test panic".to_string(), 2),
        ];

        let report = InjectionReport::from_results(results, 5, "AllPoints");

        assert_eq!(report.total_await_points, 5);
        assert_eq!(report.tests_run, 3);
        assert_eq!(report.successes, 2);
        assert_eq!(report.failures, 1);
        assert!(!report.all_passed());
        assert_eq!(report.seed, 0); // Default seed
    }

    #[test]
    fn injection_report_from_results_with_seed() {
        let results = vec![InjectionResult::success(1, 0)];
        let report = InjectionReport::from_results_with_seed(results, 3, "FirstN(1)", 12345);

        assert_eq!(report.seed, 12345);
        assert_eq!(report.strategy, "FirstN(1)");
    }

    #[test]
    fn injection_report_to_json() {
        let results = vec![
            InjectionResult::success(1, 0),
            InjectionResult::panic(2, "test error".to_string(), 1),
        ];
        let report = InjectionReport::from_results_with_seed(results, 5, "AllPoints", 42);

        let json = report.to_json();
        assert!(json.contains("\"total_await_points\": 5"));
        assert!(json.contains("\"seed\": 42"));
        assert!(json.contains("\"passed\": false"));
        assert!(json.contains("\"injection_point\": 1"));
        assert!(json.contains("\"injection_point\": 2"));
    }

    #[test]
    fn injection_report_to_junit_xml() {
        let results = vec![
            InjectionResult::success(1, 0),
            InjectionResult::panic(2, "test error".to_string(), 1),
        ];
        let report = InjectionReport::from_results(results, 5, "AllPoints");

        let xml = report.to_junit_xml();
        assert!(xml.contains("<?xml version=\"1.0\""));
        assert!(xml.contains("<testsuite name=\"CancellationInjection\""));
        assert!(xml.contains("tests=\"2\" failures=\"1\""));
        assert!(xml.contains("<testcase name=\"await_point_1\""));
        assert!(xml.contains("<failure message=\"Panic: test error\""));
    }

    #[test]
    fn injection_report_display() {
        let results = vec![
            InjectionResult::success(1, 0),
            InjectionResult::panic(2, "test error".to_string(), 1),
        ];
        let report = InjectionReport::from_results_with_seed(results, 5, "AllPoints", 42);

        let display = format!("{report}");
        assert!(display.contains("Cancellation Injection Test Report"));
        assert!(display.contains("Await points discovered: 5"));
        assert!(display.contains("Passed: 1"));
        assert!(display.contains("Failed: 1"));
        assert!(display.contains("Seed: 42"));
        assert!(display.contains("To reproduce:"));
    }

    #[test]
    fn injection_report_reproduction_code() {
        let results = vec![];
        let report = InjectionReport::from_results_with_seed(results, 0, "Test", 99999);

        let code = report.reproduction_code(5);
        assert!(code.contains("with_seed(99999)"));
        assert!(code.contains("with_injection_point(5)"));
    }

    #[test]
    fn injection_result_outcome_summary() {
        assert_eq!(InjectionResult::success(1, 0).outcome_summary(), "Success");
        assert_eq!(
            InjectionResult::panic(1, "boom".to_string(), 0).outcome_summary(),
            "Panic: boom"
        );
        assert_eq!(
            InjectionResult {
                injection_point: 1,
                outcome: InjectionOutcome::Timeout,
                await_points_before: 0,
            }
            .outcome_summary(),
            "Timeout"
        );
    }

    #[test]
    fn await_point_with_source_location() {
        let point = AwaitPoint::anonymous(5).with_source("src/test.rs:42");
        assert_eq!(point.source_location(), Some("src/test.rs:42"));

        let point_no_source = AwaitPoint::anonymous(5);
        assert_eq!(point_no_source.source_location(), None);
    }

    #[test]
    fn injection_mode_default_is_recording() {
        let runner = InjectionRunner::new(42);
        assert_eq!(runner.current_mode(), InjectionMode::Recording);
    }

    #[test]
    fn run_simple_with_success_check() {
        let mut runner = InjectionRunner::new(42);

        let report = runner.run_simple(
            InjectionStrategy::FirstN(2),
            |injector| {
                let future = YieldingFuture::new(3, 42);
                InstrumentedFuture::new(future, injector)
            },
            |result| {
                // Accept both completion and cancellation
                match result {
                    InstrumentedPollResult::Inner(val) => *val == 42,
                    InstrumentedPollResult::CancellationInjected(_) => true,
                }
            },
        );

        assert_eq!(report.tests_run, 2);
        assert!(report.all_passed());
    }

    // ── derive-trait coverage (wave 73) ──────────────────────────────────

    #[test]
    fn await_point_debug_clone_eq_hash() {
        use std::collections::HashSet;

        let p1 = AwaitPoint::anonymous(5);
        let p2 = p1.clone();
        assert_eq!(p1, p2);

        let p3 = AwaitPoint::anonymous(6);
        assert_ne!(p1, p3);

        let mut set = HashSet::new();
        set.insert(p1.clone());
        set.insert(p2);
        assert_eq!(set.len(), 1);
        set.insert(p3);
        assert_eq!(set.len(), 2);

        let dbg = format!("{p1:?}");
        assert!(dbg.contains("AwaitPoint"));
    }

    #[test]
    fn injection_mode_debug_clone_copy_eq_default() {
        let m = InjectionMode::default();
        assert_eq!(m, InjectionMode::Recording);

        let m2 = m; // Copy
        let m3 = m;
        assert_eq!(m2, m3);

        let inj = InjectionMode::Injecting { target: 42 };
        let inj2 = inj; // Copy
        assert_eq!(inj, inj2);
        assert_ne!(m, inj);

        let dbg = format!("{inj:?}");
        assert!(dbg.contains("Injecting"));
    }

    #[test]
    fn injection_outcome_debug_clone_eq() {
        let o1 = InjectionOutcome::Success;
        let o2 = o1.clone();
        assert_eq!(o1, o2);

        let o3 = InjectionOutcome::Timeout;
        assert_ne!(o1, o3);

        let o4 = InjectionOutcome::Panic("boom".to_string());
        let o5 = o4.clone();
        assert_eq!(o4, o5);

        let dbg = format!("{o4:?}");
        assert!(dbg.contains("Panic"));
        assert!(dbg.contains("boom"));
    }

    #[test]
    fn instrumented_poll_result_debug_clone_copy_eq() {
        let r1: InstrumentedPollResult<i32> = InstrumentedPollResult::Inner(42);
        let r2 = r1; // Copy
        let r3 = r1;
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);

        let r4: InstrumentedPollResult<i32> = InstrumentedPollResult::CancellationInjected(5);
        assert_ne!(r1, r4);
        let r5 = r4; // Copy
        assert_eq!(r4, r5);

        let dbg = format!("{r1:?}");
        assert!(dbg.contains("Inner"));
    }
