    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Debug)]
    struct RecordingFixture {
        name: String,
        events: Arc<Mutex<Vec<String>>>,
        live: Arc<AtomicBool>,
        fail_start: bool,
        healthy_after_start: bool,
        stop_failures_remaining: Arc<AtomicUsize>,
    }

    impl RecordingFixture {
        fn new(name: &str, events: Arc<Mutex<Vec<String>>>) -> Self {
            Self {
                name: name.to_string(),
                events,
                live: Arc::new(AtomicBool::new(false)),
                fail_start: false,
                healthy_after_start: true,
                stop_failures_remaining: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn failing_start(mut self) -> Self {
            self.fail_start = true;
            self
        }

        fn unhealthy(mut self) -> Self {
            self.healthy_after_start = false;
            self
        }

        fn failing_stop_once(mut self) -> Self {
            self.stop_failures_remaining = Arc::new(AtomicUsize::new(1));
            self
        }
    }

    impl FixtureService for RecordingFixture {
        fn name(&self) -> &str {
            &self.name
        }

        fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            self.events.lock().push(format!("start:{}", self.name));
            self.live.store(true, Ordering::SeqCst);
            if self.fail_start {
                return Err(format!("injected start failure for {}", self.name).into());
            }
            Ok(())
        }

        // See the note on `advance_transaction_generation` in
        // `database::sqlite`: `fetch_update` is deprecated on the pinned
        // nightly and absent from the stable subset, so the stable-compatible
        // spelling stays with an explicit allow.
        #[allow(deprecated)]
        fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            if self
                .stop_failures_remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                self.events.lock().push(format!("stop-error:{}", self.name));
                return Err(format!("injected stop failure for {}", self.name).into());
            }
            self.events.lock().push(format!("stop:{}", self.name));
            self.live.store(false, Ordering::SeqCst);
            Ok(())
        }

        fn is_healthy(&self) -> bool {
            self.live.load(Ordering::SeqCst) && self.healthy_after_start
        }

        fn has_live_resource(&self) -> bool {
            self.live.load(Ordering::SeqCst)
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_log_level_ordering() {
        init_test("test_log_level_ordering");
        let error_warn = TestLogLevel::Error < TestLogLevel::Warn;
        crate::assert_with_log!(error_warn, "error < warn", true, error_warn);
        let warn_info = TestLogLevel::Warn < TestLogLevel::Info;
        crate::assert_with_log!(warn_info, "warn < info", true, warn_info);
        let info_debug = TestLogLevel::Info < TestLogLevel::Debug;
        crate::assert_with_log!(info_debug, "info < debug", true, info_debug);
        let debug_trace = TestLogLevel::Debug < TestLogLevel::Trace;
        crate::assert_with_log!(debug_trace, "debug < trace", true, debug_trace);
        crate::test_complete!("test_log_level_ordering");
    }

    #[test]
    fn test_log_level_from_str() {
        init_test("test_log_level_from_str");
        let error = "error".parse();
        let ok = matches!(error, Ok(TestLogLevel::Error));
        crate::assert_with_log!(ok, "parse error", true, ok);
        let error_upper = "ERROR".parse();
        let ok = matches!(error_upper, Ok(TestLogLevel::Error));
        crate::assert_with_log!(ok, "parse ERROR", true, ok);
        let warn = "warn".parse();
        let ok = matches!(warn, Ok(TestLogLevel::Warn));
        crate::assert_with_log!(ok, "parse warn", true, ok);
        let warning = "warning".parse();
        let ok = matches!(warning, Ok(TestLogLevel::Warn));
        crate::assert_with_log!(ok, "parse warning", true, ok);
        let info = "info".parse();
        let ok = matches!(info, Ok(TestLogLevel::Info));
        crate::assert_with_log!(ok, "parse info", true, ok);
        let debug_level = "debug".parse();
        let ok = matches!(debug_level, Ok(TestLogLevel::Debug));
        crate::assert_with_log!(ok, "parse debug", true, ok);
        let trace = "trace".parse();
        let ok = matches!(trace, Ok(TestLogLevel::Trace));
        crate::assert_with_log!(ok, "parse trace", true, ok);
        let invalid: Result<TestLogLevel, ()> = "invalid".parse();
        let ok = invalid.is_err();
        crate::assert_with_log!(ok, "parse invalid", true, ok);
        crate::test_complete!("test_log_level_from_str");
    }

    #[test]
    fn test_logger_captures_events() {
        init_test("test_logger_captures_events");
        let logger = TestLogger::new(TestLogLevel::Trace);

        logger.log(TestEvent::TaskSpawn {
            task_id: 1,
            name: Some("worker".into()),
        });
        logger.log(TestEvent::TaskPoll {
            task_id: 1,
            result: "pending",
        });
        logger.log(TestEvent::TaskComplete {
            task_id: 1,
            outcome: "ok",
        });

        let count = logger.event_count();
        crate::assert_with_log!(count == 3, "event_count", 3, count);
        crate::test_complete!("test_logger_captures_events");
    }

    #[test]
    fn test_logger_trace_level_is_not_verbose_by_default() {
        init_test("test_logger_trace_level_is_not_verbose_by_default");
        let logger = TestLogger::new(TestLogLevel::Trace);
        crate::assert_with_log!(
            !logger.verbose,
            "trace level should not imply immediate stderr output",
            false,
            logger.verbose
        );
        crate::test_complete!("test_logger_trace_level_is_not_verbose_by_default");
    }

    #[test]
    fn test_logger_filters_by_level() {
        init_test("test_logger_filters_by_level");
        let logger = TestLogger::new(TestLogLevel::Info);

        // This should be captured (Info level)
        logger.log(TestEvent::TaskSpawn {
            task_id: 1,
            name: None,
        });

        // This should NOT be captured (Trace level)
        logger.log(TestEvent::TaskPoll {
            task_id: 1,
            result: "pending",
        });

        let count = logger.event_count();
        crate::assert_with_log!(count == 1, "event_count", 1, count);
        crate::test_complete!("test_logger_filters_by_level");
    }

    #[test]
    fn test_logger_report_includes_statistics() {
        init_test("test_logger_report_includes_statistics");
        let logger = TestLogger::new(TestLogLevel::Trace);

        logger.log(TestEvent::TaskSpawn {
            task_id: 1,
            name: None,
        });
        logger.log(TestEvent::TaskSpawn {
            task_id: 2,
            name: None,
        });
        logger.log(TestEvent::TaskComplete {
            task_id: 1,
            outcome: "ok",
        });

        let report = logger.report();
        let has_spawns = report.contains("Task spawns: 2");
        crate::assert_with_log!(has_spawns, "report contains task spawns", true, has_spawns);
        let has_events = report.contains("3 events");
        crate::assert_with_log!(has_events, "report contains events count", true, has_events);
        crate::test_complete!("test_logger_report_includes_statistics");
    }

    #[test]
    fn test_busy_loop_detection() {
        init_test("test_busy_loop_detection");
        let logger = TestLogger::new(TestLogLevel::Trace);

        // Log some empty polls
        for _ in 0..3 {
            logger.log(TestEvent::ReactorPoll {
                timeout: None,
                events_returned: 0,
                duration: Duration::from_micros(10),
            });
        }

        // This should pass (3 <= 5)
        logger.assert_no_busy_loop(5);
        crate::test_complete!("test_busy_loop_detection");
    }

    #[test]
    #[should_panic(expected = "Busy loop detected")]
    fn test_busy_loop_detection_fails() {
        init_test("test_busy_loop_detection_fails");
        let logger = TestLogger::new(TestLogLevel::Trace);

        // Log too many empty polls
        for _ in 0..10 {
            logger.log(TestEvent::ReactorPoll {
                timeout: None,
                events_returned: 0,
                duration: Duration::from_micros(10),
            });
        }

        // This should fail (10 > 5)
        logger.assert_no_busy_loop(5);
    }

    #[test]
    fn test_task_completion_check() {
        init_test("test_task_completion_check");
        let logger = TestLogger::new(TestLogLevel::Trace);

        logger.log(TestEvent::TaskSpawn {
            task_id: 1,
            name: None,
        });
        logger.log(TestEvent::TaskComplete {
            task_id: 1,
            outcome: "ok",
        });

        // Should pass
        logger.assert_all_tasks_completed();
        crate::test_complete!("test_task_completion_check");
    }

    #[test]
    #[should_panic(expected = "Task leak detected")]
    fn test_task_completion_check_fails() {
        init_test("test_task_completion_check_fails");
        let logger = TestLogger::new(TestLogLevel::Trace);

        logger.log(TestEvent::TaskSpawn {
            task_id: 1,
            name: None,
        });
        // No completion event

        logger.assert_all_tasks_completed();
    }

    #[test]
    fn test_macros() {
        init_test("test_macros");
        let logger = TestLogger::new(TestLogLevel::Debug);

        test_log!(logger, "test", "Message with arg: {}", 42);
        test_error!(logger, "io", "Error message");
        test_warn!(logger, "perf", "Warning message");

        let count = logger.event_count();
        crate::assert_with_log!(count == 3, "event_count", 3, count);
        crate::test_complete!("test_macros");
    }

    #[test]
    fn test_interest_display() {
        init_test("test_interest_display");
        let readable = format!("{}", Interest::READABLE);
        crate::assert_with_log!(readable == "R", "readable display", "R", readable);
        let writable = format!("{}", Interest::WRITABLE);
        crate::assert_with_log!(writable == "W", "writable display", "W", writable);
        let both = format!("{}", Interest::BOTH);
        crate::assert_with_log!(both == "RW", "both display", "RW", both);
        crate::test_complete!("test_interest_display");
    }

    #[test]
    fn test_event_display() {
        init_test("test_event_display");
        let event = TestEvent::TaskSpawn {
            task_id: 42,
            name: Some("worker".into()),
        };
        let rendered = format!("{event}");
        let has_task = rendered.contains("task=42");
        crate::assert_with_log!(has_task, "rendered task id", true, has_task);
        let has_worker = rendered.contains("worker");
        crate::assert_with_log!(has_worker, "rendered worker name", true, has_worker);
        crate::test_complete!("test_event_display");
    }

    // ====================================================================
    // TestHarness tests
    // ====================================================================

    #[test]
    fn test_harness_basic_flow() {
        init_test("test_harness_basic_flow");
        let mut harness = TestHarness::new("basic_flow");

        harness.enter_phase("setup");
        harness.assert_true("always true", true);
        harness.exit_phase();

        harness.enter_phase("exercise");
        harness.assert_eq("equality", &42, &42);
        harness.exit_phase();

        let summary = harness.finish();
        assert_eq!(summary.test_name, "basic_flow");
        assert!(summary.passed);
        assert_eq!(summary.total_assertions, 2);
        assert_eq!(summary.passed_assertions, 2);
        assert_eq!(summary.failed_assertions, 0);
        crate::test_complete!("test_harness_basic_flow");
    }

    #[test]
    fn test_harness_nested_phases() {
        init_test("test_harness_nested_phases");
        let mut harness = TestHarness::new("nested");

        harness.enter_phase("outer");
        harness.enter_phase("inner");
        assert_eq!(harness.current_phase_path(), "outer > inner");
        harness.exit_phase();
        harness.exit_phase();

        let summary = harness.finish();
        assert!(summary.passed);
        assert_eq!(summary.phases.len(), 1); // one root
        crate::test_complete!("test_harness_nested_phases");
    }

    #[test]
    fn test_harness_failed_assertion_recorded() {
        init_test("test_harness_failed_assertion_recorded");
        let mut harness = TestHarness::new("fail_test");

        harness.enter_phase("check");
        // Don't panic, just record
        let passed = harness.assert_eq("mismatch", &1, &2);
        assert!(!passed);
        harness.exit_phase();

        let summary = harness.finish();
        assert!(!summary.passed);
        assert_eq!(summary.failed_assertions, 1);
        crate::test_complete!("test_harness_failed_assertion_recorded");
    }

    #[test]
    fn test_harness_json_serialization() {
        init_test("test_harness_json_serialization");
        let mut harness = TestHarness::new("json_test");
        harness.assert_true("ok", true);
        let json = harness.finish_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(parsed["test_name"], "json_test");
        assert_eq!(parsed["passed"], true);
        crate::test_complete!("test_harness_json_serialization");
    }

    #[test]
    fn test_report_aggregator() {
        init_test("test_report_aggregator");
        let mut agg = TestReportAggregator::new();

        // Test 1: passing
        let mut h1 = TestHarness::new("test_a");
        h1.enter_phase("setup");
        h1.assert_true("ok", true);
        h1.exit_phase();
        agg.add(h1.finish());

        // Test 2: failing
        let mut h2 = TestHarness::new("test_b");
        h2.enter_phase("check");
        h2.assert_eq("bad", &1, &2);
        h2.exit_phase();
        agg.add(h2.finish());

        let report = agg.report();
        assert_eq!(report.total_tests, 2);
        assert_eq!(report.passed_tests, 1);
        assert_eq!(report.failed_tests, 1);
        assert_eq!(report.total_assertions, 2);
        assert_eq!(report.passed_assertions, 1);
        assert_eq!(report.coverage_matrix.len(), 2);
        assert_eq!(report.coverage_matrix[0].phases_exercised, vec!["setup"]);
        assert_eq!(report.coverage_matrix[1].phases_exercised, vec!["check"]);

        // Verify JSON round-trip
        let json = agg.report_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(parsed["total_tests"], 2);
        crate::test_complete!("test_report_aggregator");
    }

    #[test]
    fn test_harness_macros() {
        init_test("test_harness_macros");
        let mut harness = TestHarness::new("macro_test");
        harness_phase!(harness, "setup");
        harness_assert!(harness, "truthy", true);
        harness_assert_eq!(harness, "equal", 5, 5);
        harness_phase_exit!(harness);
        let summary = harness.finish();
        assert!(summary.passed);
        assert_eq!(summary.total_assertions, 2);
        crate::test_complete!("test_harness_macros");
    }

    #[test]
    fn test_assert_eq_log_macro_evaluates_operands_once_on_failure() {
        init_test("test_assert_eq_log_macro_evaluates_operands_once_on_failure");
        let logger = TestLogger::new(TestLogLevel::Info);
        let left_calls = Arc::new(AtomicUsize::new(0));
        let right_calls = Arc::new(AtomicUsize::new(0));
        let left_counter = Arc::clone(&left_calls);
        let right_counter = Arc::clone(&right_calls);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq_log!(
                logger,
                {
                    left_counter.fetch_add(1, Ordering::Relaxed);
                    1
                },
                {
                    right_counter.fetch_add(1, Ordering::Relaxed);
                    2
                }
            );
        }));

        assert!(result.is_err());
        assert_eq!(left_calls.load(Ordering::Relaxed), 1);
        assert_eq!(right_calls.load(Ordering::Relaxed), 1);
        crate::test_complete!("test_assert_eq_log_macro_evaluates_operands_once_on_failure");
    }

    #[test]
    fn test_harness_assert_eq_macro_evaluates_operands_once_on_failure() {
        init_test("test_harness_assert_eq_macro_evaluates_operands_once_on_failure");
        let expected_calls = Arc::new(AtomicUsize::new(0));
        let actual_calls = Arc::new(AtomicUsize::new(0));
        let expected_counter = Arc::clone(&expected_calls);
        let actual_counter = Arc::clone(&actual_calls);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut harness = TestHarness::new("harness_macro_eval_once");
            harness_phase!(harness, "setup");
            harness_assert_eq!(
                harness,
                "mismatch",
                {
                    expected_counter.fetch_add(1, Ordering::Relaxed);
                    10
                },
                {
                    actual_counter.fetch_add(1, Ordering::Relaxed);
                    11
                }
            );
        }));

        assert!(result.is_err());
        assert_eq!(expected_calls.load(Ordering::Relaxed), 1);
        assert_eq!(actual_calls.load(Ordering::Relaxed), 1);
        crate::test_complete!("test_harness_assert_eq_macro_evaluates_operands_once_on_failure");
    }

    // ====================================================================
    // TestContext tests
    // ====================================================================

    #[test]
    fn test_context_creation() {
        init_test("test_context_creation");
        let ctx = TestContext::new("ctx_test", 0xCAFE)
            .with_subsystem("scheduler")
            .with_invariant("no_leaks");

        assert_eq!(ctx.test_id, "ctx_test");
        assert_eq!(ctx.seed, 0xCAFE);
        assert_eq!(ctx.subsystem.as_deref(), Some("scheduler"));
        assert_eq!(ctx.invariant.as_deref(), Some("no_leaks"));
        crate::test_complete!("test_context_creation");
    }

    #[test]
    fn test_context_display() {
        init_test("test_context_display");
        let ctx = TestContext::new("disp_test", 42).with_subsystem("raptorq");
        let rendered = format!("{ctx}");
        assert!(rendered.contains("test_id=disp_test"));
        assert!(rendered.contains("seed=0x2A"));
        assert!(rendered.contains("subsystem=raptorq"));
        crate::test_complete!("test_context_display");
    }

    #[test]
    fn test_context_serialization() {
        init_test("test_context_serialization");
        let ctx = TestContext::new("ser_test", 0xDEAD)
            .with_subsystem("obligation")
            .with_invariant("committed_or_aborted");

        let json = serde_json::to_string(&ctx).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed["test_id"], "ser_test");
        assert_eq!(parsed["seed"], 0xDEAD);
        assert_eq!(parsed["subsystem"], "obligation");
        assert_eq!(parsed["invariant"], "committed_or_aborted");
        crate::test_complete!("test_context_serialization");
    }

    #[test]
    fn test_harness_with_context() {
        init_test("test_harness_with_context");
        let ctx = TestContext::new("harness_ctx", 0xBEEF)
            .with_subsystem("cancellation")
            .with_invariant("losers_drained");

        let mut harness = TestHarness::with_context("ctx_harness", ctx);
        assert!(harness.context().is_some());
        assert_eq!(harness.context().unwrap().test_id, "harness_ctx");

        harness.enter_phase("verify");
        harness.assert_true("context present", harness.context().is_some());
        harness.exit_phase();

        let summary = harness.finish();
        assert!(summary.passed);
        assert!(summary.context.is_some());
        assert_eq!(summary.context.unwrap().seed, 0xBEEF);
        crate::test_complete!("test_harness_with_context");
    }

    #[test]
    fn test_harness_without_context() {
        init_test("test_harness_without_context");
        let harness = TestHarness::new("no_ctx");
        assert!(harness.context().is_none());

        let summary = harness.finish();
        assert!(summary.context.is_none());
        crate::test_complete!("test_harness_without_context");
    }

    #[test]
    fn test_structured_macros() {
        init_test("test_structured_macros");
        let ctx = TestContext::new("macro_ctx", 0x42)
            .with_subsystem("sync")
            .with_invariant("no_deadlock");

        // These should compile and not panic.
        test_structured!(ctx, "simple message");
        test_structured!(ctx, "with fields", count = 5);
        test_structured!(ctx, "multi fields", count = 5, label = "test");
        crate::test_complete!("test_structured_macros");
    }

    // ----------------------------------------------------------------
    // Seed derivation tests
    // ----------------------------------------------------------------

    #[test]
    fn test_seed_derivation_deterministic() {
        init_test("test_seed_derivation_deterministic");
        let root = 0xDEAD_BEEF;
        assert_eq!(
            derive_component_seed(root, "scheduler"),
            derive_component_seed(root, "scheduler")
        );
        assert_eq!(
            derive_scenario_seed(root, "cancel"),
            derive_scenario_seed(root, "cancel")
        );
        assert_eq!(derive_entropy_seed(root, 0), derive_entropy_seed(root, 0));
        crate::test_complete!("test_seed_derivation_deterministic");
    }

    #[test]
    fn test_seed_derivation_unique() {
        init_test("test_seed_derivation_unique");
        let root = 0xDEAD_BEEF;
        assert_ne!(
            derive_component_seed(root, "scheduler"),
            derive_component_seed(root, "io")
        );
        assert_ne!(
            derive_scenario_seed(root, "cancel"),
            derive_scenario_seed(root, "join")
        );
        assert_ne!(derive_entropy_seed(root, 0), derive_entropy_seed(root, 1));
        // Component and scenario with same name differ due to prefix.
        assert_ne!(
            derive_component_seed(root, "cancel"),
            derive_scenario_seed(root, "cancel")
        );
        crate::test_complete!("test_seed_derivation_unique");
    }

    #[test]
    fn test_seed_derivation_cross_platform_stability() {
        init_test("test_seed_derivation_cross_platform_stability");
        // Pinned value for regression: FNV-1a of 0xDEAD_BEEF + "scheduler".
        let root = 0xDEAD_BEEF;
        let expected = 13_888_874_950_133_950_416;
        assert_eq!(
            derive_component_seed(root, "scheduler"),
            expected,
            "seed derivation must be platform-stable"
        );
        crate::test_complete!("test_seed_derivation_cross_platform_stability");
    }

    #[test]
    fn test_context_seed_methods() {
        init_test("test_context_seed_methods");
        let ctx = TestContext::new("seed_test", 0xCAFE);
        assert_eq!(
            ctx.component_seed("io"),
            derive_component_seed(0xCAFE, "io")
        );
        assert_eq!(
            ctx.scenario_seed("cancel"),
            derive_scenario_seed(0xCAFE, "cancel")
        );
        assert_eq!(ctx.entropy_seed(5), derive_entropy_seed(0xCAFE, 5));
        crate::test_complete!("test_context_seed_methods");
    }

    #[test]
    fn test_context_from_live_dual_run_preserves_identity() {
        init_test("test_context_from_live_dual_run_preserves_identity");
        let identity = DualRunScenarioIdentity::phase1(
            "phase1.cancel.race.one_loser",
            "cancel.race",
            "cancel.race.v1",
            "winner completes, loser drains",
            0xCAFE,
        );
        let ctx = TestContext::from_live_dual_run(&identity);

        assert_eq!(ctx.test_id, "phase1.cancel.race.one_loser");
        assert_eq!(ctx.seed, 0xCAFE);
        assert_eq!(ctx.adapter.as_deref(), Some(LIVE_CURRENT_THREAD_ADAPTER));
        assert_eq!(ctx.surface_id(), Some("cancel.race"));
        assert_eq!(ctx.surface_contract_version(), Some("cancel.race.v1"));
        assert_eq!(ctx.seed_lineage_id(), Some("phase1.cancel.race.one_loser"));
        assert!(ctx.execution_instance_id().is_some());

        crate::test_complete!("test_context_from_live_dual_run_preserves_identity");
    }

    // ----------------------------------------------------------------
    // ReproManifest tests
    // ----------------------------------------------------------------

    #[test]
    fn test_repro_manifest_from_context() {
        init_test("test_repro_manifest_from_context");
        let ctx = TestContext::new("obligation_leak", 42)
            .with_subsystem("obligation")
            .with_invariant("committed_or_aborted");
        let manifest = ReproManifest::from_context(&ctx, false);
        assert_eq!(manifest.seed, 42);
        assert_eq!(manifest.scenario_id, "obligation_leak");
        assert_eq!(
            manifest.invariant_ids,
            vec!["committed_or_aborted".to_string()]
        );
        assert_eq!(manifest.subsystem.as_deref(), Some("obligation"));
        assert_eq!(manifest.failure_class, FAILURE_CLASS_ASSERTION_FAILURE);
        assert_eq!(
            manifest.replay_command,
            "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_test_logging_obligation_leak ASUPERSYNC_SEED=0x2A cargo test obligation_leak -- --nocapture",
            "default replay command should be deterministic and target-dir qualified"
        );
        assert!(
            !manifest.replay_command.contains("rch exec -- cargo test"),
            "default replay command must not use bare rch cargo routing"
        );
        assert!(!manifest.trace_fingerprint.is_empty());
        assert!(!manifest.passed);
        crate::test_complete!("test_repro_manifest_from_context");
    }

    #[test]
    fn test_repro_manifest_helper_setters() {
        init_test("test_repro_manifest_helper_setters");
        let manifest = ReproManifest::new(0xBEEF, "helper_test", false)
            .with_entropy_seed(0xCAFE)
            .with_config_hash("cfg_hash")
            .with_trace_fingerprint("trace_fp")
            .with_input_digest("input_digest")
            .with_oracle_violations(["oracle_a", "oracle_b"])
            .with_subsystem("scheduler")
            .with_invariant("no_leaks")
            .with_invariant_ids(["quiescence", "no_leaks", "quiescence"])
            .with_replay_command(
                "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_test_logging_helper_test ASUPERSYNC_SEED=0xBEEF cargo test helper_test -- --nocapture",
            )
            .with_failure_class("assertion_failure")
            .with_artifact_paths(["b.json", "a.json", "b.json"])
            .with_trace_file("traces/run.jsonl")
            .with_input_file("inputs/failing.json");

        assert_eq!(manifest.entropy_seed, Some(0xCAFE));
        assert_eq!(manifest.config_hash.as_deref(), Some("cfg_hash"));
        assert_eq!(manifest.trace_fingerprint, "trace_fp");
        assert_eq!(manifest.input_digest.as_deref(), Some("input_digest"));
        assert_eq!(manifest.oracle_violations.len(), 2);
        assert_eq!(manifest.subsystem.as_deref(), Some("scheduler"));
        assert_eq!(manifest.invariant.as_deref(), Some("no_leaks"));
        assert_eq!(
            manifest.invariant_ids,
            vec!["no_leaks".to_string(), "quiescence".to_string()]
        );
        assert_eq!(manifest.failure_class, "assertion_failure");
        assert!(
            manifest.replay_command.contains(
                "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_test_logging_helper_test ASUPERSYNC_SEED=0xBEEF cargo test helper_test -- --nocapture"
            )
        );
        assert!(
            !manifest.replay_command.contains("rch exec -- cargo test"),
            "explicit replay command fixture must not use bare rch cargo routing"
        );
        assert_eq!(
            manifest.artifact_paths,
            vec!["a.json".to_string(), "b.json".to_string()]
        );
        assert_eq!(manifest.trace_file.as_deref(), Some("traces/run.jsonl"));
        assert_eq!(manifest.input_file.as_deref(), Some("inputs/failing.json"));
        crate::test_complete!("test_repro_manifest_helper_setters");
    }

    #[test]
    fn test_repro_manifest_json_roundtrip() {
        init_test("test_repro_manifest_json_roundtrip");
        let mut manifest = ReproManifest::new(0xCAFE, "roundtrip_test", true);
        manifest.entropy_seed = Some(0xBEEF);
        manifest.config_hash = Some("abc123".to_string());
        let json = manifest.to_json().expect("serialize");
        let parsed: ReproManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.seed, manifest.seed);
        assert_eq!(parsed.scenario_id, manifest.scenario_id);
        assert_eq!(parsed.entropy_seed, manifest.entropy_seed);
        assert_eq!(parsed.schema_version, ARTIFACT_SCHEMA_VERSION);
        crate::test_complete!("test_repro_manifest_json_roundtrip");
    }

    #[test]
    fn test_repro_manifest_optional_fields_omitted() {
        init_test("test_repro_manifest_optional_fields_omitted");
        let manifest = ReproManifest::new(0, "minimal_test", true);
        let json = manifest.to_json().expect("serialize");
        assert!(!json.contains("entropy_seed"));
        assert!(!json.contains("config_hash"));
        assert!(!json.contains("oracle_violations"));
        assert!(json.contains("\"invariant_ids\": []"));
        assert!(json.contains("\"artifact_paths\": []"));
        assert!(json.contains("\"failure_class\": \"passed\""));
        assert!(json.contains("\"replay_command\":"));
        assert!(json.contains("\"trace_fingerprint\":"));
        crate::test_complete!("test_repro_manifest_optional_fields_omitted");
    }

    #[test]
    fn test_replay_context_from_manifest() {
        init_test("test_replay_context_from_manifest");
        let mut manifest = ReproManifest::new(0xDEAD, "replay_scenario", false);
        manifest.subsystem = Some("scheduler".to_string());
        manifest.invariant = Some("quiescence".to_string());
        let ctx = replay_context_from_manifest(&manifest);
        assert_eq!(ctx.test_id, "replay_scenario");
        assert_eq!(ctx.seed, 0xDEAD);
        assert_eq!(ctx.subsystem.as_deref(), Some("scheduler"));
        crate::test_complete!("test_replay_context_from_manifest");
    }

    #[test]
    fn test_replay_context_from_manifest_restores_dual_run_metadata() {
        init_test("test_replay_context_from_manifest_restores_dual_run_metadata");
        let identity = DualRunScenarioIdentity::phase1(
            "phase1.cancel.race.one_loser",
            "cancel.race",
            "cancel.race.v1",
            "winner completes, loser drains",
            0xDEAD,
        );
        let ctx = TestContext::from_live_dual_run(&identity);
        let manifest = ReproManifest::from_context(&ctx, false);
        let replay_ctx = replay_context_from_manifest(&manifest);

        assert_eq!(
            replay_ctx.adapter.as_deref(),
            Some(LIVE_CURRENT_THREAD_ADAPTER)
        );
        assert_eq!(replay_ctx.surface_id(), Some("cancel.race"));
        assert_eq!(
            replay_ctx.surface_contract_version(),
            Some("cancel.race.v1")
        );
        assert_eq!(
            replay_ctx.seed_lineage_id(),
            Some("phase1.cancel.race.one_loser")
        );
        assert!(replay_ctx.execution_instance_id().is_some());

        crate::test_complete!("test_replay_context_from_manifest_restores_dual_run_metadata");
    }

    // ----------------------------------------------------------------
    // ----------------------------------------------------------------
    // Failure Triage Pipeline tests (bd-1ex7)
    // ----------------------------------------------------------------

    #[test]
    fn test_repro_manifest_env_snapshot() {
        init_test("test_repro_manifest_env_snapshot");
        let env = capture_test_env();
        for (key, _) in &env {
            crate::assert_with_log!(
                key.starts_with("ASUPERSYNC_") || key == "RUST_LOG",
                "env key filtered",
                "ASUPERSYNC_* or RUST_LOG",
                key
            );
        }
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        crate::assert_with_log!(keys == sorted, "env keys sorted", true, keys == sorted);
        crate::test_complete!("test_repro_manifest_env_snapshot");
    }

    #[test]
    fn test_repro_manifest_with_phases_and_failure_reason() {
        init_test("test_repro_manifest_with_phases_and_failure_reason");
        let manifest = ReproManifest::new(0xBEEF, "phase_test", false)
            .with_phases(vec![
                "setup".to_string(),
                "exercise".to_string(),
                "verify".to_string(),
            ])
            .with_failure_reason("assertion failed: expected 5, got 3");

        crate::assert_with_log!(
            manifest.phases_executed.len() == 3,
            "three phases",
            3,
            manifest.phases_executed.len()
        );
        crate::assert_with_log!(
            manifest.failure_reason.is_some(),
            "failure reason set",
            true,
            manifest.failure_reason.is_some()
        );
        crate::assert_with_log!(
            manifest.failure_class == FAILURE_CLASS_ASSERTION_FAILURE,
            "failure class set on failure reason",
            FAILURE_CLASS_ASSERTION_FAILURE,
            manifest.failure_class
        );

        let json = manifest.to_json().expect("serialize");
        let parsed: ReproManifest = serde_json::from_str(&json).expect("deserialize");
        crate::assert_with_log!(
            parsed.phases_executed == manifest.phases_executed,
            "phases roundtrip",
            manifest.phases_executed.len(),
            parsed.phases_executed.len()
        );
        crate::assert_with_log!(
            parsed.failure_reason == manifest.failure_reason,
            "failure_reason roundtrip",
            manifest.failure_reason,
            parsed.failure_reason
        );
        crate::test_complete!("test_repro_manifest_with_phases_and_failure_reason");
    }

    #[test]
    fn test_repro_manifest_contract_validation_v1() {
        init_test("test_repro_manifest_contract_validation_v1");
        let manifest = ReproManifest::new(0x1234, "contract_ok", false)
            .with_trace_fingerprint("fp_1234")
            .with_invariant_ids(["cancel_protocol", "no_obligation_leaks"])
            .with_replay_command(
                "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_test_logging_contract_ok ASUPERSYNC_SEED=0x1234 cargo test contract_ok -- --nocapture",
            )
            .with_failure_class(FAILURE_CLASS_ASSERTION_FAILURE)
            .with_artifact_paths([
                "target/test-artifacts/contract_ok/event_log.txt",
                "target/test-artifacts/contract_ok/repro_manifest.json",
            ]);

        crate::assert_with_log!(
            manifest.validate_contract_v1().is_ok(),
            "manifest satisfies v1 contract",
            true,
            manifest.validate_contract_v1().is_ok()
        );
        crate::test_complete!("test_repro_manifest_contract_validation_v1");
    }

    #[test]
    fn test_repro_manifest_contract_validation_rejects_unsorted_ids() {
        init_test("test_repro_manifest_contract_validation_rejects_unsorted_ids");
        let mut manifest = ReproManifest::new(0x9999, "contract_bad", false)
            .with_trace_fingerprint("fp_9999")
            .with_replay_command(
                "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_test_logging_contract_bad ASUPERSYNC_SEED=0x9999 cargo test contract_bad -- --nocapture",
            )
            .with_failure_class(FAILURE_CLASS_ASSERTION_FAILURE)
            .with_artifact_paths([
                "target/test-artifacts/contract_bad/repro_manifest.json",
                "target/test-artifacts/contract_bad/event_log.txt",
            ]);
        manifest.invariant_ids = vec!["z_last".to_string(), "a_first".to_string()];

        let err = manifest
            .validate_contract_v1()
            .expect_err("unsorted invariant_ids should fail");
        crate::assert_with_log!(
            err.contains("invariant_ids must be sorted"),
            "contract rejects unsorted invariant_ids",
            true,
            err
        );
        crate::test_complete!("test_repro_manifest_contract_validation_rejects_unsorted_ids");
    }

    #[test]
    fn test_repro_manifest_empty_new_fields_omitted() {
        init_test("test_repro_manifest_empty_new_fields_omitted");
        let manifest = ReproManifest::new(42, "minimal", true);
        let json = manifest.to_json().expect("serialize");
        crate::assert_with_log!(
            !json.contains("phases_executed"),
            "empty phases omitted",
            true,
            !json.contains("phases_executed")
        );
        crate::assert_with_log!(
            !json.contains("env_snapshot"),
            "empty env omitted",
            true,
            !json.contains("env_snapshot")
        );
        crate::assert_with_log!(
            !json.contains("failure_reason"),
            "null failure_reason omitted",
            true,
            !json.contains("failure_reason")
        );
        crate::test_complete!("test_repro_manifest_empty_new_fields_omitted");
    }

    #[test]
    fn test_harness_repro_manifest_on_failure() {
        init_test("test_harness_repro_manifest_on_failure");
        let ctx = TestContext::new("harness_failure_test", 0xF00D)
            .with_subsystem("scheduler")
            .with_invariant("quiescence");
        let mut harness = TestHarness::with_context("harness_failure_test", ctx);

        harness.enter_phase("setup");
        harness.assert_true("always passes", true);
        harness.exit_phase();

        harness.enter_phase("exercise");
        harness.record_assertion("value check", false, "10", "5");
        harness.exit_phase();

        let manifest = harness.repro_manifest(false);
        crate::assert_with_log!(
            manifest.seed == 0xF00D,
            "seed from context",
            0xF00Du64,
            manifest.seed
        );
        crate::assert_with_log!(
            manifest.subsystem.as_deref() == Some("scheduler"),
            "subsystem from context",
            Some("scheduler"),
            manifest.subsystem.as_deref()
        );
        crate::assert_with_log!(
            manifest.phases_executed.len() == 2,
            "two phases captured",
            2,
            manifest.phases_executed.len()
        );
        crate::assert_with_log!(
            manifest.failure_reason.is_some(),
            "failure reason populated",
            true,
            manifest.failure_reason.is_some()
        );
        crate::assert_with_log!(
            manifest.failure_class == FAILURE_CLASS_ASSERTION_FAILURE,
            "failure class populated",
            FAILURE_CLASS_ASSERTION_FAILURE,
            manifest.failure_class
        );
        crate::assert_with_log!(
            manifest.replay_command.contains(
                "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_test_logging_harness_failure_test ASUPERSYNC_SEED=0xF00D cargo test harness_failure_test -- --nocapture"
            ),
            "replay command populated",
            true,
            manifest.replay_command.contains(
                "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_test_logging_harness_failure_test ASUPERSYNC_SEED=0xF00D cargo test harness_failure_test -- --nocapture"
            )
        );
        crate::assert_with_log!(
            !manifest.replay_command.contains("rch exec -- cargo test"),
            "replay command target-dir qualified",
            true,
            manifest.replay_command
        );
        crate::test_complete!("test_harness_repro_manifest_on_failure");
    }

    #[test]
    #[allow(unsafe_code)]
    fn test_harness_finish_auto_generates_manifest_on_failure() {
        init_test("test_harness_finish_auto_generates_manifest_on_failure");
        let _guard = crate::test_utils::env_lock();
        let tmp = std::env::temp_dir().join("asupersync_harness_manifest_test");
        let _ = std::fs::remove_dir_all(&tmp);

        // SAFETY: tests serialize env access with test_utils::env_lock.
        unsafe { std::env::set_var("ASUPERSYNC_TEST_ARTIFACTS_DIR", tmp.display().to_string()) };
        let ctx = TestContext::new("auto_manifest", 0xCAFE).with_subsystem("time");
        let mut harness = TestHarness::with_context("auto_manifest", ctx);

        harness.enter_phase("setup");
        harness.exit_phase();
        harness.enter_phase("verify");
        harness.record_assertion("fail_check", false, "true", "false");
        harness.exit_phase();

        let summary = harness.finish();

        let has_manifest = summary
            .failure_artifacts
            .iter()
            .any(|a| a.contains("repro_manifest.json"));
        crate::assert_with_log!(
            has_manifest,
            "repro_manifest.json in artifacts",
            true,
            has_manifest
        );

        if let Some(manifest_path) = summary
            .failure_artifacts
            .iter()
            .find(|a| a.contains("repro_manifest.json"))
        {
            let loaded = load_repro_manifest(std::path::Path::new(manifest_path))
                .expect("load auto-generated manifest");
            crate::assert_with_log!(
                loaded.seed == 0xCAFE,
                "manifest seed correct",
                0xCAFEu64,
                loaded.seed
            );
            crate::assert_with_log!(
                !loaded.passed,
                "manifest shows failure",
                false,
                loaded.passed
            );
            crate::assert_with_log!(
                loaded.phases_executed.len() == 2,
                "phases captured in manifest",
                2,
                loaded.phases_executed.len()
            );
            crate::assert_with_log!(
                loaded.failure_class == FAILURE_CLASS_ASSERTION_FAILURE,
                "failure class captured in manifest",
                FAILURE_CLASS_ASSERTION_FAILURE,
                loaded.failure_class
            );
        }

        // SAFETY: tests serialize env access with test_utils::env_lock.
        unsafe { std::env::remove_var("ASUPERSYNC_TEST_ARTIFACTS_DIR") };
        let _ = std::fs::remove_dir_all(&tmp);
        crate::test_complete!("test_harness_finish_auto_generates_manifest_on_failure");
    }

    #[test]
    fn test_capture_replay_manifest_roundtrip() {
        init_test("test_capture_replay_manifest_roundtrip");
        let ctx = TestContext::new("cancel_drain", 0xDEAD_CAFE)
            .with_subsystem("obligation")
            .with_invariant("no_leaks");
        let mut harness = TestHarness::with_context("cancel_drain", ctx);

        harness.enter_phase("setup_regions");
        harness.assert_true("region created", true);
        harness.exit_phase();
        harness.enter_phase("cancel_and_drain");
        harness.record_assertion("leak check", false, "0 leaks", "2 leaks");
        harness.exit_phase();

        let manifest = harness.repro_manifest(false);

        let tmp = std::env::temp_dir().join("asupersync_replay_roundtrip");
        let path = manifest.write_to_dir(&tmp).expect("write manifest");

        let loaded = load_repro_manifest(&path).expect("load manifest");
        let replay_ctx = replay_context_from_manifest(&loaded);

        crate::assert_with_log!(
            replay_ctx.seed == 0xDEAD_CAFE,
            "replay seed matches",
            0xDEAD_CAFEu64,
            replay_ctx.seed
        );
        crate::assert_with_log!(
            replay_ctx.test_id == "cancel_drain",
            "replay test_id matches",
            "cancel_drain",
            replay_ctx.test_id
        );
        crate::assert_with_log!(
            loaded.phases_executed.len() == 2,
            "phases preserved on disk",
            2,
            loaded.phases_executed.len()
        );
        crate::assert_with_log!(
            loaded.failure_reason.is_some(),
            "failure reason preserved on disk",
            true,
            loaded.failure_reason.is_some()
        );
        crate::assert_with_log!(
            loaded.validate_contract_v1().is_ok(),
            "manifest remains v1 contract-valid after disk roundtrip",
            true,
            loaded.validate_contract_v1().is_ok()
        );

        let _ = std::fs::remove_dir_all(tmp.join("cancel_drain"));
        crate::test_complete!("test_capture_replay_manifest_roundtrip");
    }

    // E2E Environment Orchestration tests
    // ----------------------------------------------------------------

    #[test]
    fn test_port_allocator_allocates_unique_ports() {
        init_test("test_port_allocator_allocates_unique_ports");
        let mut alloc = PortAllocator::new();
        let p1 = alloc.allocate("http").expect("allocate http");
        let p2 = alloc.allocate("ws").expect("allocate ws");
        let p3 = alloc.allocate("grpc").expect("allocate grpc");
        assert_ne!(p1, p2, "ports must be unique");
        assert_ne!(p2, p3, "ports must be unique");
        assert_ne!(p1, p3, "ports must be unique");
        assert!(p1 > 0);
        assert_eq!(alloc.count(), 3);
        crate::test_complete!("test_port_allocator_allocates_unique_ports");
    }

    #[test]
    fn test_port_allocator_lookup_by_label() {
        init_test("test_port_allocator_lookup_by_label");
        let mut alloc = PortAllocator::new();
        let port = alloc.allocate("my_service").expect("allocate");
        assert_eq!(alloc.port_for("my_service"), Some(port));
        assert_eq!(alloc.port_for("nonexistent"), None);
        crate::test_complete!("test_port_allocator_lookup_by_label");
    }

    #[test]
    fn test_port_allocator_allocate_n() {
        init_test("test_port_allocator_allocate_n");
        let mut alloc = PortAllocator::new();
        let ports = alloc.allocate_n("worker", 4).expect("allocate_n");
        assert_eq!(ports.len(), 4);
        let mut sorted = ports;
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 4, "all ports must be unique");
        assert!(alloc.port_for("worker_0").is_some());
        assert!(alloc.port_for("worker_3").is_some());
        crate::test_complete!("test_port_allocator_allocate_n");
    }

    #[test]
    fn test_noop_fixture_service_lifecycle() {
        init_test("test_noop_fixture_service_lifecycle");
        let mut svc = NoOpFixtureService::new("test_echo");
        assert_eq!(svc.name(), "test_echo");
        assert!(!svc.is_healthy());
        svc.start().expect("start");
        assert!(svc.is_healthy());
        svc.stop().expect("stop");
        assert!(!svc.is_healthy());
        crate::test_complete!("test_noop_fixture_service_lifecycle");
    }

    #[test]
    fn test_environment_metadata_fields() {
        init_test("test_environment_metadata_fields");
        let ctx = TestContext::new("env_meta_test", 0xBEEF);
        let mut env = TestEnvironment::new(ctx);
        let _ = env.allocate_port("http").expect("allocate");
        env.register_service(Box::new(NoOpFixtureService::new("echo_svc")));
        let meta = env.metadata();
        assert_eq!(meta.test_id, "env_meta_test");
        assert_eq!(meta.seed, 0xBEEF);
        assert_eq!(meta.ports.len(), 1);
        assert_eq!(meta.services.len(), 1);
        crate::test_complete!("test_environment_metadata_fields");
    }

    #[test]
    fn test_environment_metadata_json_roundtrip() {
        init_test("test_environment_metadata_json_roundtrip");
        let ctx = TestContext::new("json_meta", 42);
        let env = TestEnvironment::new(ctx);
        let meta = env.metadata();
        let json = meta.to_json().expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed["test_id"], "json_meta");
        assert_eq!(parsed["seed"], 42);
        crate::test_complete!("test_environment_metadata_json_roundtrip");
    }

    #[test]
    fn test_environment_service_lifecycle() {
        init_test("test_environment_service_lifecycle");
        let ctx = TestContext::new("svc_lifecycle", 1);
        let mut env = TestEnvironment::new(ctx);
        env.register_service(Box::new(NoOpFixtureService::new("svc_a")));
        env.register_service(Box::new(NoOpFixtureService::new("svc_b")));
        let health = env.health_check();
        assert!(!health[0].1);
        assert!(!health[1].1);
        env.start_all_services().expect("start all");
        let health = env.health_check();
        assert!(health[0].1);
        assert!(health[1].1);
        env.teardown();
        let health = env.health_check();
        assert!(!health[0].1);
        assert!(!health[1].1);
        crate::test_complete!("test_environment_service_lifecycle");
    }

    #[test]
    fn test_environment_start_failure_rolls_back_in_reverse_order() {
        init_test("test_environment_start_failure_rolls_back_in_reverse_order");
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut env = TestEnvironment::new(TestContext::new("start_rollback", 2));
        env.register_service(Box::new(RecordingFixture::new("first", events.clone())));
        env.register_service(Box::new(
            RecordingFixture::new("second", events.clone()).failing_start(),
        ));

        let error = env
            .start_all_services()
            .expect_err("second fixture must fail startup");
        assert!(error.to_string().contains("second"));
        assert_eq!(
            *events.lock(),
            ["start:first", "start:second", "stop:second", "stop:first"]
        );
        assert!(
            env.orphaned_services().is_empty(),
            "transactional rollback must not leak resources"
        );
        crate::test_complete!("test_environment_start_failure_rolls_back_in_reverse_order");
    }

    #[test]
    fn test_environment_readiness_failure_stops_every_service() {
        init_test("test_environment_readiness_failure_stops_every_service");
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut env = TestEnvironment::new(TestContext::new("readiness_rollback", 3));
        env.register_service(Box::new(RecordingFixture::new("ready", events.clone())));
        env.register_service(Box::new(
            RecordingFixture::new("unhealthy", events.clone()).unhealthy(),
        ));

        let error = env
            .start_all_services_until_healthy(Duration::ZERO)
            .expect_err("unhealthy fixture must fail");
        assert!(
            error.to_string().contains("failed readiness"),
            "readiness failure remains distinct from start failure: {error}"
        );
        assert_eq!(
            *events.lock(),
            [
                "start:ready",
                "start:unhealthy",
                "stop:unhealthy",
                "stop:ready"
            ]
        );
        assert!(env.orphaned_services().is_empty());
        crate::test_complete!("test_environment_readiness_failure_stops_every_service");
    }

    #[test]
    fn test_environment_retries_failed_teardown_and_reports_orphan() {
        init_test("test_environment_retries_failed_teardown_and_reports_orphan");
        let events = Arc::new(Mutex::new(Vec::new()));
        let callback_count = Arc::new(AtomicUsize::new(0));
        let callback_count_for_teardown = callback_count.clone();
        let mut env = TestEnvironment::new(TestContext::new("teardown_retry", 4));
        env.register_service(Box::new(
            RecordingFixture::new("retry", events.clone()).failing_stop_once(),
        ));
        env.on_teardown(move || {
            callback_count_for_teardown.fetch_add(1, Ordering::SeqCst);
        });
        env.start_all_services().expect("start fixture");

        env.teardown();
        assert_eq!(env.orphaned_services(), ["retry"]);
        assert_eq!(env.teardown_errors().len(), 1);
        assert_eq!(callback_count.load(Ordering::SeqCst), 1);

        env.teardown();
        assert!(env.orphaned_services().is_empty());
        assert!(env.teardown_errors().is_empty());
        assert_eq!(callback_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            *events.lock(),
            ["start:retry", "stop-error:retry", "stop:retry"]
        );
        crate::test_complete!("test_environment_retries_failed_teardown_and_reports_orphan");
    }

    #[test]
    fn test_environment_port_isolation() {
        init_test("test_environment_port_isolation");
        let mut env_a = TestEnvironment::new(TestContext::new("env_a", 1));
        let mut env_b = TestEnvironment::new(TestContext::new("env_b", 2));
        let port_a = env_a.allocate_port("http").expect("allocate a");
        let port_b = env_b.allocate_port("http").expect("allocate b");
        assert_ne!(
            port_a, port_b,
            "concurrent environments must get distinct ports"
        );
        crate::test_complete!("test_environment_port_isolation");
    }

    #[test]
    fn test_environment_teardown_idempotent() {
        init_test("test_environment_teardown_idempotent");
        let mut env = TestEnvironment::new(TestContext::new("idempotent", 0));
        env.register_service(Box::new(NoOpFixtureService::new("svc")));
        env.start_all_services().expect("start");
        env.teardown();
        env.teardown();
        env.teardown();
        crate::test_complete!("test_environment_teardown_idempotent");
    }

    #[test]
    fn test_environment_on_teardown_callbacks() {
        init_test("test_environment_on_teardown_callbacks");
        let counter = Arc::new(AtomicUsize::new(0));
        let c1 = counter.clone();
        let c2 = counter.clone();
        let mut env = TestEnvironment::new(TestContext::new("callbacks", 0));
        env.on_teardown(move || {
            c1.fetch_add(1, Ordering::SeqCst);
        });
        env.on_teardown(move || {
            c2.fetch_add(10, Ordering::SeqCst);
        });
        env.teardown();
        assert_eq!(counter.load(Ordering::SeqCst), 11, "both callbacks ran");
        crate::test_complete!("test_environment_on_teardown_callbacks");
    }

    #[test]
    fn test_environment_metadata_write_artifact() {
        init_test("test_environment_metadata_write_artifact");
        let mut env = TestEnvironment::new(TestContext::new("artifact_write", 0xABCD));
        let _ = env.allocate_port("tcp").expect("allocate");
        let tmp = std::env::temp_dir().join("asupersync_env_meta_test");
        let meta = env.metadata();
        let path = meta.write_to_dir(&tmp).expect("write metadata");
        let content = std::fs::read_to_string(&path).expect("read");
        let parsed: serde_json::Value = serde_json::from_str(&content).expect("parse");
        assert_eq!(parsed["test_id"], "artifact_write");
        assert_eq!(parsed["seed"], 0xABCD);
        let _ = std::fs::remove_dir_all(tmp.join("artifact_write"));
        crate::test_complete!("test_environment_metadata_write_artifact");
    }

    // =========================================================================
    // Tests for concrete fixture services (bd-76y5)
    // =========================================================================

    #[test]
    fn test_wait_until_healthy_immediate() {
        init_test("test_wait_until_healthy_immediate");
        let mut svc = NoOpFixtureService::new("fast_svc");
        svc.start().expect("start");
        let elapsed = wait_until_healthy(&svc, Duration::from_secs(1)).expect("healthy");
        assert!(elapsed < Duration::from_millis(100));
        crate::test_complete!("test_wait_until_healthy_immediate");
    }

    #[test]
    fn test_wait_until_healthy_timeout() {
        init_test("test_wait_until_healthy_timeout");
        let svc = NoOpFixtureService::new("never_starts");
        // Not started, so is_healthy() is always false.
        let result = wait_until_healthy(&svc, Duration::from_millis(200));
        assert!(result.is_err(), "should timeout");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("not healthy"),
            "error should mention health: {err_msg}"
        );
        crate::test_complete!("test_wait_until_healthy_timeout");
    }

    #[cfg(unix)]
    fn shell_identity() -> PinnedProcessIdentity {
        use sha2::Digest as _;
        let binary = std::path::PathBuf::from("/bin/sh");
        let digest = sha2::Sha256::digest(std::fs::read(&binary).expect("read /bin/sh"));
        PinnedProcessIdentity::new(binary, hex::encode(digest), "asupersync-fixture-shell-v1")
            .with_version_args(["-c", "printf asupersync-fixture-shell-v1"])
    }

    #[cfg(unix)]
    fn fixture_ack_pipe(
        log_dir: &std::path::Path,
    ) -> (std::path::PathBuf, std::fs::File, std::fs::File) {
        use std::os::unix::fs::OpenOptionsExt as _;

        let path = log_dir.join("child-ready.pipe");
        nix::unistd::mkfifo(
            &path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .expect("create private fixture acknowledgement pipe");
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .expect("open acknowledgement reader without waiting for the child");
        // Keep an unwritten writer alive so no-writer EOF/HUP cannot look
        // like an acknowledgement on platforms with different FIFO polling.
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .expect("open acknowledgement keeper without waiting for the child");
        (path, reader, writer)
    }

    #[cfg(unix)]
    fn wait_for_fixture_ack(mut reader: &std::fs::File, timeout: Duration) -> std::io::Result<()> {
        use std::io::Read as _;
        use std::os::fd::AsFd as _;

        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "child did not acknowledge its completed output",
                ));
            }
            let mut fds = [nix::poll::PollFd::new(
                reader.as_fd(),
                nix::poll::PollFlags::POLLIN,
            )];
            let poll_timeout = nix::poll::PollTimeout::try_from(remaining)
                .expect("fixture acknowledgement timeout fits poll");
            match nix::poll::poll(&mut fds, poll_timeout) {
                Ok(0) | Err(nix::errno::Errno::EINTR) => continue,
                Err(error) => return Err(error.into()),
                Ok(_) => {}
            }
            let mut acknowledgement = [0_u8; 1];
            match reader.read(&mut acknowledgement) {
                Ok(1) if acknowledgement == *b"R" => return Ok(()),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
                Ok(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "child closed the acknowledgement pipe without the ready byte",
                    ));
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_process_fixture_pinned_lifecycle_and_redacted_logs() {
        init_test("test_process_fixture_pinned_lifecycle_and_redacted_logs");
        let log_dir = tempfile::tempdir().expect("fixture log dir");
        let (ack_path, ack_reader, _ack_writer) = fixture_ack_pipe(log_dir.path());
        let hold_path = log_dir.path().join("child-hold.pipe");
        nix::unistd::mkfifo(
            &hold_path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .expect("create private fixture hold pipe");
        let mut fixture = ProcessFixtureService::new(
            "shell-service",
            shell_identity(),
            log_dir.path(),
        )
        .with_secret_env("FIXTURE_SECRET", "fixture-secret-123")
        .with_env("FIXTURE_READY", ack_path.as_os_str())
        .with_env("FIXTURE_HOLD", hold_path.as_os_str())
        .with_args([
            "-c",
            "printf '%s' \"$FIXTURE_SECRET\"; printf '%s' \"$FIXTURE_SECRET\" >&2; printf R > \"$FIXTURE_READY\"; IFS= read -r release < \"$FIXTURE_HOLD\"",
        ])
        .with_startup_timeout(Duration::from_secs(1));

        fixture.start().expect("start pinned fixture");
        assert!(fixture.is_healthy());
        assert!(fixture.has_live_resource());
        // Running proves liveness, not that the child has executed either
        // printf. The child acknowledges both writes, then blocks until stop
        // kills it; there is no fixed sleep that can expire under host load.
        let acknowledgement = wait_for_fixture_ack(&ack_reader, Duration::from_secs(1));
        fixture.stop().expect("stop pinned fixture");
        fixture.stop().expect("repeated stop is idempotent");
        assert!(!fixture.has_live_resource());

        let logs = fixture.captured_logs();
        acknowledgement.unwrap_or_else(|error| {
            panic!("child output acknowledgement failed: {error}; logs={logs:?}")
        });
        assert_eq!(logs.stdout, "<redacted>");
        assert_eq!(logs.stderr, "<redacted>");
        assert!(!logs.stdout.contains("fixture-secret-123"));
        assert!(!logs.stderr.contains("fixture-secret-123"));
        assert_eq!(
            std::fs::read_to_string(&fixture.stdout_path).expect("read sanitized stdout file"),
            "<redacted>"
        );
        assert_eq!(
            std::fs::read_to_string(&fixture.stderr_path).expect("read sanitized stderr file"),
            "<redacted>"
        );
        crate::test_complete!("test_process_fixture_pinned_lifecycle_and_redacted_logs");
    }

    #[cfg(unix)]
    #[test]
    fn test_process_fixture_running_without_child_ack_is_rejected() {
        init_test("test_process_fixture_running_without_child_ack_is_rejected");
        let log_dir = tempfile::tempdir().expect("fixture log dir");
        let (ack_path, ack_reader, _ack_writer) = fixture_ack_pipe(log_dir.path());
        let mut fixture = ProcessFixtureService::new("no-ack", shell_identity(), log_dir.path())
            .with_env("FIXTURE_READY", ack_path.as_os_str())
            .with_args(["-c", "IFS= read -r release < \"$FIXTURE_READY\""])
            .with_startup_timeout(Duration::from_secs(1));

        fixture.start().expect("start child held before output");
        assert!(fixture.is_healthy(), "Running observes the live child");
        let acknowledgement = wait_for_fixture_ack(&ack_reader, Duration::from_millis(75));
        fixture.stop().expect("stop child without acknowledgement");
        assert!(!fixture.has_live_resource());
        let error = acknowledgement.expect_err("liveness must not substitute for child output");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(fixture.captured_logs(), FixtureLogs::default());
        crate::test_complete!("test_process_fixture_running_without_child_ack_is_rejected");
    }

    #[cfg(unix)]
    #[test]
    fn test_process_fixture_rejects_digest_and_version_drift() {
        init_test("test_process_fixture_rejects_digest_and_version_drift");
        let log_dir = tempfile::tempdir().expect("fixture log dir");
        let wrong_digest =
            PinnedProcessIdentity::new("/bin/sh", "0".repeat(64), "asupersync-fixture-shell-v1")
                .with_version_args(["-c", "printf asupersync-fixture-shell-v1"]);
        let mut digest_fixture =
            ProcessFixtureService::new("digest-drift", wrong_digest, log_dir.path());
        let digest_error = digest_fixture
            .start()
            .expect_err("digest drift must fail closed");
        assert!(digest_error.to_string().contains("digest mismatch"));
        assert!(!digest_fixture.has_live_resource());

        let mut version_identity = shell_identity();
        version_identity.expected_version = "different-version".to_string();
        let mut version_fixture =
            ProcessFixtureService::new("version-drift", version_identity, log_dir.path());
        let version_error = version_fixture
            .start()
            .expect_err("version drift must fail closed");
        assert!(version_error.to_string().contains("version mismatch"));
        assert!(!version_fixture.has_live_resource());
        crate::test_complete!("test_process_fixture_rejects_digest_and_version_drift");
    }

    #[cfg(unix)]
    #[test]
    fn test_process_fixture_rejects_ambient_working_directory() {
        init_test("test_process_fixture_rejects_ambient_working_directory");
        let mut relative_logs =
            ProcessFixtureService::new("relative-logs", shell_identity(), "relative-fixture-logs");
        let error = relative_logs
            .start()
            .expect_err("relative log directory must fail closed");
        assert!(error.to_string().contains("log directory must be absolute"));
        assert!(!relative_logs.has_live_resource());

        let log_dir = tempfile::tempdir().expect("fixture log dir");
        let missing_work_dir = log_dir.path().join("missing");
        let mut missing =
            ProcessFixtureService::new("missing-work-dir", shell_identity(), log_dir.path())
                .with_current_dir(&missing_work_dir);
        let error = missing
            .start()
            .expect_err("missing working directory must fail closed");
        assert!(
            error
                .to_string()
                .contains("working directory must be an existing absolute directory")
        );
        assert!(!missing_work_dir.exists());
        assert!(!missing.has_live_resource());
        crate::test_complete!("test_process_fixture_rejects_ambient_working_directory");
    }

    #[cfg(unix)]
    #[test]
    fn test_process_fixture_captures_crash_and_readiness_timeout() {
        init_test("test_process_fixture_captures_crash_and_readiness_timeout");
        let crash_logs = tempfile::tempdir().expect("crash log dir");
        let mut crashing =
            ProcessFixtureService::new("crashing", shell_identity(), crash_logs.path())
                .with_args(["-c", "printf crash-detail >&2; exit 17"])
                // An unscheduled shell can remain Running before its first
                // instruction. No process can satisfy this readiness probe,
                // so startup must observe the actual crash instead.
                .with_readiness(ProcessReadiness::Tcp(
                    "127.0.0.1:0"
                        .parse()
                        .expect("unavailable loopback endpoint"),
                ))
                .with_startup_timeout(Duration::from_secs(1));
        let crash_error = crashing
            .start()
            .expect_err("early process exit must fail readiness");
        assert!(crash_error.to_string().contains("exited before readiness"));
        assert!(crash_error.to_string().contains("exit status: 17"));
        assert!(crash_error.to_string().contains("crash-detail"));
        assert!(!crashing.has_live_resource());

        let timeout_logs = tempfile::tempdir().expect("timeout log dir");
        let unavailable: std::net::SocketAddr =
            "127.0.0.1:0".parse().expect("loopback socket address");
        let mut timing_out =
            ProcessFixtureService::new("timing-out", shell_identity(), timeout_logs.path())
                .with_args(["-c", "exec /bin/sleep 5"])
                .with_readiness(ProcessReadiness::Tcp(unavailable))
                .with_startup_timeout(Duration::from_millis(75));
        let timeout_error = timing_out
            .start()
            .expect_err("unavailable readiness port must time out");
        assert!(timeout_error.to_string().contains("readiness timed out"));
        assert!(!timing_out.has_live_resource());
        timing_out
            .stop()
            .expect("timeout cleanup remains idempotent");
        crate::test_complete!("test_process_fixture_captures_crash_and_readiness_timeout");
    }

    #[test]
    fn test_temp_dir_fixture_lifecycle() {
        init_test("test_temp_dir_fixture_lifecycle");
        let mut fixture = TempDirFixture::new("scratch");
        assert!(!fixture.is_healthy());
        assert!(fixture.path().is_none());

        fixture.start().expect("start");
        assert!(fixture.is_healthy());
        let path = fixture.path().expect("path exists").to_owned();
        assert!(path.is_dir());
        assert!(
            path.to_string_lossy().contains("asupersync-scratch-"),
            "prefix should match: {path:?}"
        );

        fixture.stop().expect("stop");
        assert!(!fixture.is_healthy());
        assert!(!path.is_dir(), "temp dir should be cleaned up");

        crate::test_complete!("test_temp_dir_fixture_lifecycle");
    }

    #[test]
    fn test_temp_dir_fixture_custom_prefix() {
        init_test("test_temp_dir_fixture_custom_prefix");
        let mut fixture = TempDirFixture::new("custom").with_prefix("myprefix-");
        fixture.start().expect("start");
        let path = fixture.path().expect("path exists");
        assert!(
            path.to_string_lossy().contains("myprefix-"),
            "custom prefix should appear: {path:?}"
        );
        crate::test_complete!("test_temp_dir_fixture_custom_prefix");
    }

    #[test]
    fn test_in_process_service_lifecycle() {
        init_test("test_in_process_service_lifecycle");
        let running = Arc::new(AtomicBool::new(false));
        let mut svc = InProcessService::new(
            "echo",
            running.clone(),
            |state: &mut Arc<AtomicBool>| {
                state.store(true, Ordering::SeqCst);
                Ok(())
            },
            |state: &mut Arc<AtomicBool>| {
                state.store(false, Ordering::SeqCst);
                Ok(())
            },
            |state: &Arc<AtomicBool>| state.load(Ordering::SeqCst),
        );

        assert_eq!(svc.name(), "echo");
        assert!(!svc.is_healthy());

        svc.start().expect("start");
        assert!(svc.is_healthy());
        assert!(running.load(Ordering::SeqCst));

        svc.stop().expect("stop");
        assert!(!svc.is_healthy());
        assert!(!running.load(Ordering::SeqCst));

        crate::test_complete!("test_in_process_service_lifecycle");
    }

    #[test]
    fn test_docker_fixture_service_name_and_container() {
        init_test("test_docker_fixture_service_name_and_container");
        let svc = DockerFixtureService::new("redis", "redis:7-alpine")
            .with_port_map(16379, 6379)
            .with_secret_env("REDIS_PASSWORD", "fixture-secret")
            .with_health_cmd(vec!["redis-cli", "ping"]);

        assert_eq!(svc.name(), "redis");
        assert!(
            svc.container_name().starts_with("asupersync-test-redis-"),
            "container name format: {}",
            svc.container_name()
        );
        assert!(!svc.is_healthy(), "not started yet");
        assert!(
            !DockerFixtureService::image_is_pinned("redis:7-alpine"),
            "mutable tags must not qualify as pinned fixture identities"
        );
        assert!(DockerFixtureService::image_is_pinned(
            "redis@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(
            !format!("{svc:?}").contains("fixture-secret"),
            "debug output must not expose secret environment values"
        );
        crate::test_complete!("test_docker_fixture_service_name_and_container");
    }

    #[test]
    fn test_environment_with_temp_dir_fixture() {
        init_test("test_environment_with_temp_dir_fixture");
        let ctx = TestContext::new("env_tempdir", 0x1234);
        let mut env = TestEnvironment::new(ctx);

        let mut tmp = TempDirFixture::new("workdir");
        tmp.start().expect("start");
        assert!(tmp.is_healthy());
        let dir_path = tmp.path().expect("path").to_owned();

        env.register_service(Box::new(tmp));
        let meta = env.metadata();
        assert_eq!(meta.services.len(), 1);
        assert_eq!(meta.services[0], "workdir");

        env.teardown();
        // After teardown the temp dir should be cleaned up.
        assert!(!dir_path.is_dir(), "temp dir cleaned up after env teardown");
        crate::test_complete!("test_environment_with_temp_dir_fixture");
    }

    #[test]
    fn test_environment_with_in_process_service() {
        init_test("test_environment_with_in_process_service");
        let flag = Arc::new(AtomicBool::new(false));
        let svc = InProcessService::new(
            "mock_http",
            flag.clone(),
            |s: &mut Arc<AtomicBool>| {
                s.store(true, Ordering::SeqCst);
                Ok(())
            },
            |s: &mut Arc<AtomicBool>| {
                s.store(false, Ordering::SeqCst);
                Ok(())
            },
            |s: &Arc<AtomicBool>| s.load(Ordering::SeqCst),
        );

        let ctx = TestContext::new("env_inproc", 42);
        let mut env = TestEnvironment::new(ctx);
        env.register_service(Box::new(svc));
        env.start_all_services().expect("start all");

        let health = env.health_check();
        assert!(health[0].1, "in-process service should be healthy");
        assert!(flag.load(Ordering::SeqCst));

        env.teardown();
        assert!(!flag.load(Ordering::SeqCst), "stopped after teardown");
        crate::test_complete!("test_environment_with_in_process_service");
    }
