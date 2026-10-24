    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::{RegionId, Time};
    use crate::util::ArenaIndex;

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

        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            if self.yields_remaining > 0 {
                self.yields_remaining -= 1;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(self.value)
            }
        }
    }

    struct NeverReadyFuture;

    impl Future for NeverReadyFuture {
        type Output = i32;

        fn poll(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    }

    #[test]
    fn lab_injection_config_builder() {
        let config = LabInjectionConfig::new(42)
            .with_strategy(InjectionStrategy::AllPoints)
            .with_all_oracles()
            .stop_on_failure(true)
            .max_steps_per_run(1000);

        assert_eq!(config.seed(), 42);
        assert!(matches!(config.strategy(), InjectionStrategy::AllPoints));
        assert!(config.use_all_oracles);
        assert!(config.stop_on_failure);
        assert_eq!(config.max_steps_per_run, Some(1000));
    }

    #[test]
    fn lab_injection_runner_recording_phase() {
        let config = LabInjectionConfig::new(42).with_strategy(InjectionStrategy::Never);
        let mut runner = LabInjectionRunner::new(config);

        let report = runner.run_simple(|injector| {
            let future = YieldingFuture::new(3, 42);
            InstrumentedFuture::new(future, injector)
        });

        // Recording run with Never strategy = no injection runs
        assert_eq!(report.total_await_points, 4);
        assert_eq!(report.tests_run, 0);
        assert!(report.all_passed());
    }

    #[test]
    fn lab_injection_runner_all_points() {
        let config = LabInjectionConfig::new(42).with_strategy(InjectionStrategy::AllPoints);
        let mut runner = LabInjectionRunner::new(config);

        let report = runner.run_simple(|injector| {
            let future = YieldingFuture::new(3, 42);
            InstrumentedFuture::new(future, injector)
        });

        // Should run at all 4 await points
        assert_eq!(report.total_await_points, 4);
        assert_eq!(report.tests_run, 4);
        assert!(report.all_passed());
    }

    #[test]
    fn lab_injection_runner_with_oracles() {
        let config = LabInjectionConfig::new(42)
            .with_strategy(InjectionStrategy::FirstN(2))
            .with_all_oracles();
        let mut runner = LabInjectionRunner::new(config);

        let report = runner.run_with_lab(|injector, _runtime, _oracles| {
            let future = YieldingFuture::new(3, 42);
            InstrumentedFuture::new(future, injector)
        });

        // Should run at first 2 points with oracle checks
        assert_eq!(report.tests_run, 2);
        assert!(report.all_passed());
        // No oracle violations expected since we're not creating any state
        for result in &report.results {
            assert!(result.oracle_violations.is_empty());
        }
    }

    /// br-asupersync-vcu2oz H2: with_all_oracles checked only the suite passed
    /// to the test, which nothing feeds, so a run that left the lab runtime in
    /// violation passed. Here the test closes a region around a live task.
    #[test]
    fn lab_injection_with_all_oracles_checks_the_runtime_state() {
        let close_a_region_around_a_live_task =
            |injector: Arc<CancellationInjector>,
             runtime: &mut LabRuntime,
             _oracles: &mut OracleSuite| {
                let root = runtime
                    .state
                    .create_root_region(crate::types::Budget::INFINITE);
                let _task = runtime
                    .state
                    .create_task(root, crate::types::Budget::INFINITE, async {})
                    .expect("create task");
                runtime
                    .state
                    .region(root)
                    .expect("region exists")
                    .set_state(crate::record::region::RegionState::Closed);
                InstrumentedFuture::new(YieldingFuture::new(2, 42), injector)
            };

        let mut checked = LabInjectionRunner::new(
            LabInjectionConfig::new(42)
                .with_strategy(InjectionStrategy::AllPoints)
                .with_all_oracles(),
        );
        let report = checked.run_with_lab(close_a_region_around_a_live_task);
        assert_eq!(report.tests_run, 3);
        for result in &report.results {
            assert!(result.injection.is_success(), "{result:?}");
            assert!(
                result
                    .oracle_violations
                    .iter()
                    .any(|violation| matches!(violation, OracleViolation::Quiescence(_))),
                "the region closed around a live task is reported: {result:?}"
            );
        }
        assert!(!report.all_passed());

        let mut unchecked = LabInjectionRunner::new(
            LabInjectionConfig::new(42).with_strategy(InjectionStrategy::AllPoints),
        );
        let report = unchecked.run_with_lab(close_a_region_around_a_live_task);
        assert_eq!(report.tests_run, 3);
        assert!(
            report.all_passed(),
            "without with_all_oracles only the injection is checked"
        );
    }

    #[test]
    fn lab_injection_oracles_check_the_runtime_state() {
        use crate::lab::oracle::CancellationProtocolViolation;

        let config = LabInjectionConfig::new(42)
            .with_strategy(InjectionStrategy::FirstN(1))
            .with_all_oracles();
        let mut runner = LabInjectionRunner::new(config);

        let report = runner.run_with_lab(|injector, runtime, _oracles| {
            let root = runtime
                .state
                .create_root_region(crate::types::Budget::INFINITE);
            let _child = runtime
                .state
                .create_child_region(root, crate::types::Budget::INFINITE)
                .expect("create child");
            runtime
                .state
                .region(root)
                .expect("root exists")
                .cancel_request(crate::types::CancelReason::shutdown());
            InstrumentedFuture::new(YieldingFuture::new(3, 42), injector)
        });

        assert_eq!(report.tests_run, 1);
        let reports_the_child = |violation: &OracleViolation| {
            matches!(
                violation,
                OracleViolation::CancellationProtocol(
                    CancellationProtocolViolation::CancelNotPropagated { .. }
                )
            )
        };
        assert!(
            report
                .results
                .iter()
                .all(|result| result.oracle_violations.iter().any(reports_the_child)),
            "the uncancelled child must be reported: {:?}",
            report.results
        );
    }

    #[test]
    fn lab_builder_api() {
        let report = lab(42)
            .with_cancellation_injection(InjectionStrategy::FirstN(2))
            .with_all_oracles()
            .run(|injector| {
                let future = YieldingFuture::new(3, 42);
                InstrumentedFuture::new(future, injector)
            });

        assert_eq!(report.tests_run, 2);
        assert!(report.all_passed());
    }

    #[test]
    fn lab_injection_deterministic() {
        // Same config should give same results
        let run1 = lab(12345)
            .with_cancellation_injection(InjectionStrategy::RandomSample(2))
            .run(|injector| {
                let future = YieldingFuture::new(5, 42);
                InstrumentedFuture::new(future, injector)
            });

        let run2 = lab(12345)
            .with_cancellation_injection(InjectionStrategy::RandomSample(2))
            .run(|injector| {
                let future = YieldingFuture::new(5, 42);
                InstrumentedFuture::new(future, injector)
            });

        // Same seed should select same injection points
        assert_eq!(run1.tests_run, run2.tests_run);
        for (r1, r2) in run1.results.iter().zip(run2.results.iter()) {
            assert_eq!(r1.injection.injection_point, r2.injection.injection_point);
        }
    }

    #[test]
    fn lab_injection_marks_unreached_target_as_failure() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let invocation_count = Arc::new(AtomicUsize::new(0));
        let config = LabInjectionConfig::new(42).with_strategy(InjectionStrategy::FirstN(2));
        let mut runner = LabInjectionRunner::new(config);

        let report = runner.run_simple({
            let invocation_count = Arc::clone(&invocation_count);
            move |injector| {
                // Recording run discovers several points; subsequent injection runs
                // intentionally complete quickly, so higher targets may be unreachable.
                let call_index = invocation_count.fetch_add(1, Ordering::Relaxed);
                let yields = if call_index == 0 { 2 } else { 0 };
                let future = YieldingFuture::new(yields, 42);
                InstrumentedFuture::new(future, injector)
            }
        });

        assert_eq!(report.tests_run, 2);
        assert_eq!(report.successes, 1);
        assert_eq!(report.failures, 1);
        assert!(matches!(
            report.results[1].injection.outcome,
            InjectionOutcome::AssertionFailed(_)
        ));
        assert_eq!(report.results[1].injection.injection_point, 2);
    }

    #[test]
    fn lab_injection_max_steps_bounds_recording_poll_loop() {
        let config = LabInjectionConfig::new(42)
            .with_strategy(InjectionStrategy::AllPoints)
            .max_steps_per_run(3);
        let mut runner = LabInjectionRunner::new(config);

        let report =
            runner.run_simple(|injector| InstrumentedFuture::new(NeverReadyFuture, injector));

        assert_eq!(report.total_await_points, 3);
        assert_eq!(report.tests_run, 1);
        assert_eq!(report.failures, 1);
        assert!(matches!(
            report.results[0].injection.outcome,
            InjectionOutcome::Timeout
        ));
        assert_eq!(runner.current_mode(), InjectionMode::Recording);
    }

    #[test]
    fn lab_injection_report_categorize_failures() {
        let results = vec![
            LabInjectionResult {
                injection: InjectionResult::success(1, 0),
                oracle_violations: vec![],
            },
            LabInjectionResult {
                injection: InjectionResult::panic(2, "test panic".to_string(), 1),
                oracle_violations: vec![],
            },
            LabInjectionResult {
                injection: InjectionResult::success(3, 2),
                oracle_violations: vec![OracleViolation::TaskLeak(
                    crate::lab::oracle::task_leak::TaskLeakViolation {
                        region: RegionId::from_arena(ArenaIndex::new(0, 1)),
                        leaked_tasks: vec![],
                        region_close_time: Time::ZERO,
                    },
                )],
            },
        ];

        let report = LabInjectionReport::from_results(results, 5, "Test", 42);

        let (injection_failures, oracle_failures) = report.categorize_failures();
        assert_eq!(injection_failures.len(), 1);
        assert_eq!(oracle_failures.len(), 1);
        assert_eq!(injection_failures[0].injection.injection_point, 2);
        assert_eq!(oracle_failures[0].injection.injection_point, 3);
    }

    #[test]
    fn lab_injection_stop_on_failure() {
        let config = LabInjectionConfig::new(42)
            .with_strategy(InjectionStrategy::AllPoints)
            .stop_on_failure(true);
        let mut runner = LabInjectionRunner::new(config);

        // Simple test with yielding future - tests that stop_on_failure config works
        let report = runner.run_simple(|injector| {
            let future = YieldingFuture::new(3, 42);
            InstrumentedFuture::new(future, injector)
        });

        // Should have run all 4 points (no failures in our simple test)
        assert_eq!(report.total_await_points, 4);
        assert!(report.all_passed());
    }

    #[test]
    fn lab_injection_report_to_json() {
        let results = vec![
            LabInjectionResult {
                injection: InjectionResult::success(1, 0),
                oracle_violations: vec![],
            },
            LabInjectionResult {
                injection: InjectionResult::panic(2, "test panic".to_string(), 1),
                oracle_violations: vec![],
            },
        ];

        let report = LabInjectionReport::from_results(results, 5, "AllPoints", 12345);
        let json = report.to_json();

        assert_eq!(json["summary"]["total_await_points"], 5);
        assert_eq!(json["summary"]["tests_run"], 2);
        assert_eq!(json["summary"]["passed"], 1);
        assert_eq!(json["summary"]["failed"], 1);
        assert_eq!(json["summary"]["seed"], 12345);
        assert_eq!(json["summary"]["verdict"], "FAIL");
        assert_eq!(json["failures"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn lab_injection_report_to_junit_xml() {
        let results = vec![
            LabInjectionResult {
                injection: InjectionResult::success(1, 0),
                oracle_violations: vec![],
            },
            LabInjectionResult {
                injection: InjectionResult::panic(2, "test panic".to_string(), 1),
                oracle_violations: vec![],
            },
        ];

        let report = LabInjectionReport::from_results(results, 5, "AllPoints", 12345);
        let xml = report.to_junit_xml();

        assert!(xml.contains("testsuite"));
        assert!(xml.contains("tests=\"2\""));
        assert!(xml.contains("failures=\"1\""));
        assert!(xml.contains("await_point_1"));
        assert!(xml.contains("await_point_2"));
        assert!(xml.contains("<failure"));
        assert!(xml.contains("Seed: 12345"));
    }

    #[test]
    fn lab_injection_report_display() {
        let results = vec![
            LabInjectionResult {
                injection: InjectionResult::success(1, 0),
                oracle_violations: vec![],
            },
            LabInjectionResult {
                injection: InjectionResult::panic(2, "test panic".to_string(), 1),
                oracle_violations: vec![],
            },
        ];

        let report = LabInjectionReport::from_results(results, 5, "AllPoints", 12345);
        let display = format!("{report}");

        assert!(display.contains("Cancellation Injection Test Report"));
        assert!(display.contains("Await points discovered: 5"));
        assert!(display.contains("Points tested: 2"));
        assert!(display.contains("Passed: 1"));
        assert!(display.contains("Failed: 1"));
        assert!(display.contains("Verdict: FAIL"));
        assert!(display.contains("Await point 2"));
        assert!(display.contains("Seed: 12345"));
        assert!(display.contains("To reproduce:"));
    }

    #[test]
    fn lab_injection_result_reproduction_code() {
        let result = LabInjectionResult {
            injection: InjectionResult::success(42, 5),
            oracle_violations: vec![],
        };

        let code = result.reproduction_code(12345);
        assert!(code.contains("LabInjectionConfig::new(12345)"));
        assert!(code.contains("InjectionStrategy::AtSequence(42)"));
        assert!(code.contains("InstrumentedFuture::new"));
    }

    #[test]
    fn lab_injection_window_around_strategy() {
        let config = LabInjectionConfig::new(42).with_strategy(InjectionStrategy::WindowAround {
            center: 3,
            radius: 1,
        });
        let mut runner = LabInjectionRunner::new(config);

        let report = runner.run_simple(|injector| {
            let future = YieldingFuture::new(5, 42);
            InstrumentedFuture::new(future, injector)
        });

        // Points are 1..=6, window [2,4] = 3 points
        assert_eq!(report.tests_run, 3);
        assert!(report.all_passed());
    }

    #[test]
    fn lab_injection_except_first_strategy() {
        let config = LabInjectionConfig::new(42).with_strategy(InjectionStrategy::ExceptFirst(3));
        let mut runner = LabInjectionRunner::new(config);

        let report = runner.run_simple(|injector| {
            let future = YieldingFuture::new(5, 42);
            InstrumentedFuture::new(future, injector)
        });

        // 6 total points, skip first 3 = 3 remaining
        assert_eq!(report.tests_run, 3);
        assert!(report.all_passed());
    }

    #[test]
    fn lab_injection_last_n_strategy() {
        let config = LabInjectionConfig::new(42).with_strategy(InjectionStrategy::LastN(2));
        let mut runner = LabInjectionRunner::new(config);

        let report = runner.run_simple(|injector| {
            let future = YieldingFuture::new(5, 42);
            InstrumentedFuture::new(future, injector)
        });

        // 6 total points, last 2 = 2 tested
        assert_eq!(report.tests_run, 2);
        assert!(report.all_passed());
    }

    #[test]
    fn lab_injection_reproduce_config() {
        let results = vec![
            LabInjectionResult {
                injection: InjectionResult::success(1, 0),
                oracle_violations: vec![],
            },
            LabInjectionResult {
                injection: InjectionResult::panic(3, "test panic".to_string(), 2),
                oracle_violations: vec![],
            },
        ];

        let report = LabInjectionReport::from_results(results, 5, "AllPoints", 42);

        // reproduce_config should target the specific injection point
        let repro = report.reproduce_config(3);
        assert_eq!(repro.seed(), 42);
        assert!(matches!(repro.strategy(), InjectionStrategy::AtSequence(3)));
        assert!(repro.use_all_oracles);
    }

    #[test]
    fn lab_injection_reproduce_all_failures() {
        let results = vec![
            LabInjectionResult {
                injection: InjectionResult::success(1, 0),
                oracle_violations: vec![],
            },
            LabInjectionResult {
                injection: InjectionResult::panic(3, "panic a".to_string(), 2),
                oracle_violations: vec![],
            },
            LabInjectionResult {
                injection: InjectionResult::panic(5, "panic b".to_string(), 4),
                oracle_violations: vec![],
            },
        ];

        let report = LabInjectionReport::from_results(results, 10, "AllPoints", 99);
        let repros = report.reproduce_all_failures();

        assert_eq!(repros.len(), 2);
        assert_eq!(repros[0].0, 3);
        assert_eq!(repros[1].0, 5);
        assert_eq!(repros[0].1.seed(), 99);
        assert_eq!(repros[1].1.seed(), 99);
    }

    #[test]
    fn lab_injection_window_around_edge_cases() {
        // Window with center at 1, radius 0 (single point)
        let strategy = InjectionStrategy::WindowAround {
            center: 1,
            radius: 0,
        };
        let points = strategy.select_points(&[1, 2, 3, 4, 5], 0);
        assert_eq!(points, vec![1]);

        // Window at the start (saturating subtraction handles underflow)
        let strategy = InjectionStrategy::WindowAround {
            center: 1,
            radius: 5,
        };
        let points = strategy.select_points(&[1, 2, 3, 4, 5], 0);
        assert_eq!(points, vec![1, 2, 3, 4, 5]);

        // Window with no matching points
        let strategy = InjectionStrategy::WindowAround {
            center: 100,
            radius: 2,
        };
        let points = strategy.select_points(&[1, 2, 3], 0);
        assert!(points.is_empty());
    }

    #[test]
    fn lab_injection_except_first_edge_cases() {
        // Skip more than available
        let strategy = InjectionStrategy::ExceptFirst(100);
        let points = strategy.select_points(&[1, 2, 3], 0);
        assert!(points.is_empty());

        // Skip zero
        let strategy = InjectionStrategy::ExceptFirst(0);
        let points = strategy.select_points(&[1, 2, 3], 0);
        assert_eq!(points, vec![1, 2, 3]);
    }

    #[test]
    fn lab_injection_last_n_edge_cases() {
        // Request more than available
        let strategy = InjectionStrategy::LastN(100);
        let points = strategy.select_points(&[1, 2, 3], 0);
        assert_eq!(points, vec![1, 2, 3]);

        // Request zero
        let strategy = InjectionStrategy::LastN(0);
        let points = strategy.select_points(&[1, 2, 3], 0);
        assert!(points.is_empty());
    }

    /// br-asupersync-vcu2oz: the operation, child, timer, and finalizer must
    /// really run through Lab scheduling. Fixed seeds also pin replay order.
    fn owned_injection_workflow(seed: u64) -> (LabInjectionReport, Vec<(usize, u8, u64)>) {
        use crate::channel::mpsc;
        use crate::cx::Cx;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let runs = Arc::new(AtomicUsize::new(0));
        let finalized = Arc::new(AtomicUsize::new(0));
        let cancelled_children = Arc::new(AtomicUsize::new(0));
        let events = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let report = lab(seed)
            .with_cancellation_injection(InjectionStrategy::AllPoints)
            .with_all_oracles()
            .max_steps(200)
            .run_owned_with_lab({
                let runs = Arc::clone(&runs);
                let finalized = Arc::clone(&finalized);
                let cancelled_children = Arc::clone(&cancelled_children);
                let events = Arc::clone(&events);
                move |injector, runtime, _oracles, region| {
                    let run = runs.fetch_add(1, Ordering::SeqCst);
                    let final_events = Arc::clone(&events);
                    let finalized = Arc::clone(&finalized);
                    assert!(runtime.state.register_async_finalizer(region, async move {
                        let cx = Cx::current().expect("admitted async finalizer");
                        let start = cx.now();
                        final_events.lock().push((run, 5, start.as_nanos()));
                        crate::time::sleep(start, Duration::from_millis(2)).await;
                        assert!(cx.now() >= start.saturating_add_nanos(2_000_000));
                        final_events.lock().push((run, 6, cx.now().as_nanos()));
                        finalized.fetch_add(1, Ordering::SeqCst);
                    }));

                    let events = Arc::clone(&events);
                    let cancelled_children = Arc::clone(&cancelled_children);
                    InstrumentedFuture::new(
                        async move {
                            let cx = Cx::current().expect("admitted injection operation");
                            assert_eq!(cx.region_id(), region);
                            events.lock().push((run, 0, cx.now().as_nanos()));
                            let (started, mut observed_start) = mpsc::channel(1);
                            let child_events = Arc::clone(&events);
                            let mut child = cx
                                .spawn(move |child_cx| async move {
                                    child_events.lock().push((run, 1, child_cx.now().as_nanos()));
                                    started
                                        .send(&child_cx, ())
                                        .await
                                        .expect("announce child start");
                                    crate::time::sleep(child_cx.now(), Duration::from_millis(5))
                                        .await;
                                    if child_cx.checkpoint().is_err() {
                                        // Completion after acknowledgement must survive
                                        // one more Pending while the region is draining.
                                        crate::runtime::yield_now().await;
                                        cancelled_children.fetch_add(1, Ordering::SeqCst);
                                        child_events.lock().push((run, 3, child_cx.now().as_nanos()));
                                    } else {
                                        child_events.lock().push((run, 2, child_cx.now().as_nanos()));
                                    }
                                    42_u32
                                })
                                .expect("admit owned child");
                            observed_start
                                .recv(&cx)
                                .await
                                .expect("child really parked on its timer");
                            assert_eq!(child.join(&cx).await.expect("join timer child"), 42);
                            events.lock().push((run, 4, cx.now().as_nanos()));
                        },
                        injector,
                    )
                }
            });

        assert!(report.all_passed(), "seed={seed} report={report:?}");
        assert_eq!(report.tests_run, report.total_await_points);
        assert!(
            report.total_await_points >= 3,
            "spawn/park/join polls must be observed"
        );
        assert_eq!(runs.load(Ordering::SeqCst), report.tests_run + 1);
        assert_eq!(finalized.load(Ordering::SeqCst), report.tests_run + 1);
        assert!(
            cancelled_children.load(Ordering::SeqCst) > 0,
            "a parked child must drain after injection"
        );
        let events = events.lock().clone();
        (report, events)
    }

    #[test]
    fn owned_injection_drives_children_timers_finalizers_and_replays_deterministically() {
        for seed in [7, 19, 53] {
            let (first, first_events) = owned_injection_workflow(seed);
            let (second, second_events) = owned_injection_workflow(seed);
            assert_eq!(first.to_json(), second.to_json(), "seed={seed}");
            assert_eq!(
                first_events, second_events,
                "real dispatch order, seed={seed}"
            );
        }
    }

    #[test]
    fn owned_injection_retires_held_channel_permits_before_region_finalizers() {
        use crate::channel::mpsc;
        use crate::cx::Cx;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let finalized = Arc::new(AtomicUsize::new(0));
        let held = Arc::new(AtomicUsize::new(0));
        let report = lab(0xCACE)
            .with_cancellation_injection(InjectionStrategy::AllPoints)
            .with_all_oracles()
            .max_steps(100)
            .run_owned_with_lab({
                let finalized = Arc::clone(&finalized);
                let held = Arc::clone(&held);
                move |injector, runtime, _oracles, region| {
                    let (sender, receiver) = mpsc::channel::<u32>(1);
                    let inspect = sender.clone();
                    let finalized = Arc::clone(&finalized);
                    assert!(runtime.state.register_sync_finalizer(region, move || {
                        assert_eq!(
                            inspect.debug_counts(), (0, 0),
                            "permit resolved before close"
                        );
                        finalized.fetch_add(1, Ordering::SeqCst);
                    }));
                    let held = Arc::clone(&held);
                    InstrumentedFuture::new(
                        async move {
                            let cx = Cx::current().expect("real operation context");
                            let permit = sender.reserve(&cx).await.expect("reserve tracked slot");
                            assert_eq!(sender.debug_counts(), (0, 1));
                            held.fetch_add(1, Ordering::SeqCst);
                            crate::runtime::yield_now().await;
                            drop(permit);
                            drop(receiver);
                        },
                        injector,
                    )
                }
            });
        assert!(report.all_passed(), "{report:?}");
        assert_eq!(report.total_await_points, 2);
        assert_eq!(
            held.load(Ordering::SeqCst), 2,
            "recording and second-point injection held a permit"
        );
        assert_eq!(finalized.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn owned_injection_does_not_repoll_a_task_without_a_wake() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let polls = Arc::new(AtomicUsize::new(0));
        let mut runner = LabInjectionRunner::new(
            LabInjectionConfig::new(0xCACE)
                .with_strategy(InjectionStrategy::AllPoints)
                .max_steps_per_run(8),
        );
        let report = runner.run_owned({
            let polls = Arc::clone(&polls);
            move |injector| {
                let polls = Arc::clone(&polls);
                InstrumentedFuture::new(
                    std::future::poll_fn(move |_| {
                        polls.fetch_add(1, Ordering::SeqCst);
                        std::task::Poll::<()>::Pending
                    }),
                    injector,
                )
            }
        });
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(report.total_await_points, 1);
        assert_eq!(report.failures, 1);
        assert_eq!(report.results[0].injection.injection_point, 0);
        assert!(matches!(
            report.results[0].injection.outcome,
            InjectionOutcome::Timeout
        ));
        assert_eq!(runner.current_mode(), InjectionMode::Recording);
    }

    #[test]
    fn owned_injection_cannot_pass_with_an_escaped_task_in_an_open_region() {
        let mut runner = LabInjectionRunner::new(
            LabInjectionConfig::new(0xCACE)
                .with_strategy(InjectionStrategy::Never)
                .max_steps_per_run(12),
        );
        // No with_all_oracles: the owned execution contract itself requires
        // a terminal run, even though the snapshot task-leak oracle permits
        // live work in a region that has not closed.
        let report = runner.run_owned_with_lab(|injector, runtime, _oracles, owned| {
            let escaped = runtime.state.create_root_region(Budget::INFINITE);
            assert_ne!(escaped, owned);
            let (task, _join) = runtime
                .state
                .create_task(escaped, Budget::INFINITE, std::future::pending::<()>())
                .unwrap();
            runtime.scheduler.lock().schedule(task, 0);
            InstrumentedFuture::new(async { 42_u32 }, injector)
        });
        assert_eq!(report.tests_run, 1, "a failed recording must be reported");
        assert_eq!(report.results[0].injection.injection_point, 0);
        assert!(matches!(
            report.results[0].injection.outcome,
            InjectionOutcome::Timeout
        ));
        assert!(!report.all_passed());
    }

    #[test]
    fn owned_injection_step_budget_includes_async_finalizer_drain() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let finalizer_polls = Arc::new(AtomicUsize::new(0));
        let report = lab(0xCACE)
            .with_cancellation_injection(InjectionStrategy::Never)
            .max_steps(8)
            .run_owned_with_lab({
                let finalizer_polls = Arc::clone(&finalizer_polls);
                move |injector, runtime, _oracles, region| {
                    let finalizer_polls = Arc::clone(&finalizer_polls);
                    assert!(runtime.state.register_async_finalizer(
                        region,
                        std::future::poll_fn(move |_| {
                            finalizer_polls.fetch_add(1, Ordering::SeqCst);
                            std::task::Poll::<()>::Pending
                        }),
                    ));
                    InstrumentedFuture::new(async { 42_u32 }, injector)
                }
            });
        assert_eq!(
            finalizer_polls.load(Ordering::SeqCst), 1,
            "the admitted finalizer really parked"
        );
        assert_eq!(report.tests_run, 1);
        assert!(matches!(
            report.results[0].injection.outcome,
            InjectionOutcome::Timeout
        ));
        assert!(
            !report.all_passed(),
            "a ready operation cannot conceal unfinished cleanup"
        );
    }

    #[test]
    fn owned_injection_recording_panics_and_oracle_failures_are_not_silent() {
        let mut runner = LabInjectionRunner::new(
            LabInjectionConfig::new(0xCACE)
                .with_strategy(InjectionStrategy::Never)
                .with_all_oracles()
                .max_steps_per_run(20),
        );
        let panic_report = runner.run_owned(|injector| {
            InstrumentedFuture::new(
                async {
                    panic!("owned recording panic");
                },
                injector,
            )
        });
        assert_eq!(panic_report.tests_run, 1);
        assert!(matches!(
            &panic_report.results[0].injection.outcome,
            InjectionOutcome::Panic(message) if message.contains("owned recording panic")
        ));
        assert_eq!(runner.current_mode(), InjectionMode::Recording);

        let oracle_report = runner.run_owned_with_lab(|injector, _runtime, oracles, region| {
            let task = crate::types::TaskId::from_arena(ArenaIndex::new(999, 1));
            oracles.task_leak.on_spawn(task, region, Time::ZERO);
            oracles.task_leak.on_region_close(region, Time::ZERO);
            InstrumentedFuture::new(async { 42_u32 }, injector)
        });
        assert_eq!(
            oracle_report.tests_run, 1,
            "Never still checks its recording run"
        );
        assert!(oracle_report.results[0].injection.is_success());
        assert!(oracle_report.results[0]
            .oracle_violations
            .iter()
            .any(|violation| matches!(violation, OracleViolation::TaskLeak(_))));
        assert!(!oracle_report.all_passed());
    }

    #[test]
    fn owned_injection_rejects_an_unreached_target_and_restores_runner_mode() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let invocations = Arc::new(AtomicUsize::new(0));
        let mut runner = LabInjectionRunner::new(
            LabInjectionConfig::new(0xCACE)
                .with_strategy(InjectionStrategy::AllPoints)
                .stop_on_failure(true)
                .max_steps_per_run(50),
        );
        let report = runner.run_owned({
            let invocations = Arc::clone(&invocations);
            move |injector| {
                let yields = if invocations.fetch_add(1, Ordering::SeqCst) == 0 {
                    2
                } else {
                    0
                };
                InstrumentedFuture::new(YieldingFuture::new(yields, 42), injector)
            }
        });
        assert_eq!(report.total_await_points, 3);
        assert_eq!(report.tests_run, 2);
        assert_eq!(report.successes, 1);
        assert_eq!(report.failures, 1);
        assert!(matches!(
            &report.results[1].injection.outcome,
            InjectionOutcome::AssertionFailed(message) if message.contains("target 2 was not reached")
        ));
        assert_eq!(runner.current_mode(), InjectionMode::Recording);
    }
