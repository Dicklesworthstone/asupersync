    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use serde_json::json;

    #[derive(Clone, Copy)]
    struct ConformanceManifestTest {
        name: &'static str,
        invariant: &'static str,
    }

    #[derive(Clone)]
    struct ConformanceManifestComponent {
        component: &'static str,
        target: &'static str,
        tests: Vec<ConformanceManifestTest>,
    }

    fn render_conformance_manifest_yaml(components: &[ConformanceManifestComponent]) -> String {
        let mut components = components.to_vec();
        components.sort_unstable_by(|left, right| {
            left.component
                .cmp(right.component)
                .then(left.target.cmp(right.target))
        });

        let mut rendered = String::from(
            "schema_version: conformance-manifest/v1\nmodule: asupersync::conformance\ncomponents:\n",
        );

        for component in &mut components {
            component
                .tests
                .sort_unstable_by(|left, right| left.name.cmp(right.name));
            rendered.push_str(&format!(
                "  - component: {}\n    target: {}\n    tests:\n",
                component.component, component.target
            ));

            for test in &component.tests {
                rendered.push_str(&format!(
                    "      - name: {}\n        invariant: {}\n",
                    test.name, test.invariant
                ));
            }
        }

        rendered
    }

    fn scrub_conformance_markdown(markdown: &str) -> String {
        markdown
            .lines()
            .map(|line| {
                if line.starts_with("Generated At: ") {
                    "Generated At: [TIMESTAMP]".to_string()
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn scrub_conformance_report(events: &[ConformanceEvent]) -> serde_json::Value {
        json!(
            events
                .iter()
                .map(|event| match event {
                    ConformanceEvent::TestStart { name } => json!({
                        "event": "start",
                        "name": name,
                    }),
                    ConformanceEvent::TestPassed { name } => json!({
                        "event": "passed",
                        "name": name,
                    }),
                    ConformanceEvent::TestFailed { name, .. } => json!({
                        "event": "failed",
                        "name": name,
                        "message": "[MESSAGE]",
                    }),
                })
                .collect::<Vec<_>>()
        )
    }

    #[test]
    fn test_config_default() {
        let config = TestConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.rng_seed, Some(0xDEAD_BEEF));
        assert!(!config.tracing_enabled);
        assert_eq!(config.max_steps, Some(100_000));
    }

    #[test]
    fn test_config_builder() {
        let config = TestConfig::new()
            .with_timeout(Duration::from_secs(60))
            .with_seed(42)
            .with_tracing(true)
            .with_max_steps(1000);

        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.rng_seed, Some(42));
        assert!(config.tracing_enabled);
        assert_eq!(config.max_steps, Some(1000));
    }

    #[test]
    fn test_lab_runtime_target_create() {
        let config = TestConfig::new().with_seed(12345);
        let runtime = LabRuntimeTarget::create_runtime(config);

        // Verify runtime was created with correct seed
        assert_eq!(runtime.config().seed, 12345);
    }

    #[test]
    fn test_lab_runtime_target_block_on() {
        let config = TestConfig::default();
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let result = LabRuntimeTarget::block_on(&mut runtime, async { 42 });

        assert_eq!(result, 42);
    }

    /// A task that reserves a oneshot permit (a SendPermit obligation it holds)
    /// and hands it to a real thread is parked on work outside the lab. The
    /// harness must wait for that thread instead of counting idle steps: those
    /// tripped the futurelock oracle whenever the thread was slower than the
    /// threshold's worth of steps (asupersync-a95wv9). A 64-step threshold makes
    /// the old loop trip it on every run; the thread answers after 50 ms.
    #[test]
    fn lab_runtime_target_waits_for_a_permit_sent_from_a_real_thread() {
        let config = crate::lab::LabConfig::new(7)
            .max_steps(20_000)
            .futurelock_max_idle_steps(64);
        let mut runtime = crate::lab::LabRuntime::new(config);

        let value = LabRuntimeTarget::block_on(&mut runtime, async {
            let cx = Cx::current().expect("lab root task installs a Cx");
            let (tx, mut rx) = crate::channel::oneshot::channel::<u32>();
            let permit = tx.reserve(&cx).expect("reserve before the hand-off");
            let sender = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(50));
                permit.send(7).expect("the receiver is still waiting");
            });
            let value = rx.recv(&cx).await.expect("the thread sends");
            sender.join().expect("sender thread");
            value
        });

        assert_eq!(value, 7);
    }

    #[test]
    fn test_lab_runtime_target_advance_time() {
        let config = TestConfig::default();
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let before = LabRuntimeTarget::now(&runtime);
        LabRuntimeTarget::advance_time(&mut runtime, Duration::from_secs(1));
        let after = LabRuntimeTarget::now(&runtime);

        assert!(after > before);
        assert_eq!(after.checked_sub(before).unwrap(), Duration::from_secs(1));
    }

    #[test]
    fn test_lab_runtime_target_quiescence() {
        let config = TestConfig::default();
        let runtime = LabRuntimeTarget::create_runtime(config);

        // Fresh runtime should be quiescent
        assert!(LabRuntimeTarget::is_quiescent(&runtime));
    }

    #[test]
    fn test_config_debug() {
        let cfg = TestConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("TestConfig"));
    }

    #[test]
    fn test_config_clone() {
        let cfg = TestConfig::new().with_seed(99).with_tracing(true);
        let cfg2 = cfg;
        assert_eq!(cfg2.rng_seed, Some(99));
        assert!(cfg2.tracing_enabled);
    }

    #[test]
    fn test_config_without_seed() {
        let cfg = TestConfig::new().without_seed();
        assert!(cfg.rng_seed.is_none());
    }

    #[test]
    fn test_config_with_budget() {
        let budget = Budget::with_deadline_at_secs(100);
        let cfg = TestConfig::new().with_budget(budget);
        assert_eq!(cfg.root_budget, budget);
    }

    #[test]
    fn test_config_with_timeout() {
        let cfg = TestConfig::new().with_timeout(Duration::from_secs(60));
        assert_eq!(cfg.timeout, Duration::from_secs(60));
    }

    #[test]
    fn task_handle_id() {
        let tid = TaskId::new_for_test(5, 0);
        let handle = TaskHandle::new(tid, async { Outcome::Ok(42) });
        assert_eq!(handle.id(), Some(tid));
    }

    #[test]
    fn region_handle_id() {
        let rid = RegionId::new_for_test(3, 0);
        let handle = RegionHandle::new(rid, async {});
        assert_eq!(handle.id(), Some(rid));
    }

    #[test]
    fn lab_runtime_target_with_tracing() {
        let config = TestConfig::new().with_seed(42).with_tracing(true);
        let runtime = LabRuntimeTarget::create_runtime(config);
        assert_eq!(runtime.config().seed, 42);
        assert_eq!(runtime.config().trace_capacity, 64 * 1024);
    }

    #[test]
    fn lab_runtime_target_without_seed() {
        let config = TestConfig::new().without_seed();
        let runtime = LabRuntimeTarget::create_runtime(config);
        // Should use default seed 0xDEAD_BEEF when None
        assert_eq!(runtime.config().seed, 0xDEAD_BEEF);
    }

    #[test]
    fn lab_runtime_target_spawn_registers_real_task_handle() {
        let config = TestConfig::default();
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let (task_id, outcome) = LabRuntimeTarget::block_on(&mut runtime, async {
            let cx = Cx::current().expect("root task should have a current Cx");
            let handle = LabRuntimeTarget::spawn(&cx, Budget::INFINITE, async { 42_u8 });

            assert_eq!(handle.id(), None);
            crate::runtime::yield_now().await;

            let task_id = handle
                .id()
                .expect("task id should be resolved after the first scheduler turn");
            let outcome = handle.await;
            (task_id, outcome)
        });

        assert_ne!(task_id, TaskId::new_for_test(0, 0));
        assert_eq!(outcome, Outcome::Ok(42));
    }

    #[test]
    fn lab_runtime_target_create_region_and_cancel_before_registration_closes_region() {
        let config = TestConfig::default();
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let region_id = LabRuntimeTarget::block_on(&mut runtime, async {
            let cx = Cx::current().expect("root task should have a current Cx");
            let region = LabRuntimeTarget::create_region(&cx, Budget::INFINITE);
            let region_id = Arc::clone(&region.region_id);
            assert_eq!(region.id(), None);

            LabRuntimeTarget::cancel(&cx, &region, CancelReason::user("conformance-test"));
            region.await;
            (*region_id.lock()).expect("region id should resolve once the region has been created")
        });

        assert_ne!(region_id, RegionId::new_for_test(0, 0));
    }

    #[test]
    fn reporter_snapshot_scrubs_failure_messages() {
        fn passing_test(_config: &TestConfig) {}

        fn failing_test(_config: &TestConfig) {
            std::panic::resume_unwind(Box::new(String::from(
                "expected deterministic failure payload",
            )));
        }

        let tests = [
            ConformanceTestFn {
                name: "pass_case",
                test_fn: passing_test,
            },
            ConformanceTestFn {
                name: "fail_case",
                test_fn: failing_test,
            },
        ];
        let mut events = Vec::new();
        let (passed, failed) =
            run_conformance_tests_with_reporter(&tests, &TestConfig::default(), |event| {
                events.push(event);
            });

        assert_eq!((passed, failed), (1, 1));
        insta::assert_json_snapshot!(
            "conformance_report_scrubbed",
            json!({
                "summary": {
                    "passed": passed,
                    "failed": failed,
                },
                "events": scrub_conformance_report(&events),
            })
        );
    }

    #[test]
    fn report_markdown_snapshot_scrubs_generated_timestamps() {
        fn passing_test(_config: &TestConfig) {}

        fn failing_test(_config: &TestConfig) {
            std::panic::resume_unwind(Box::new(String::from("deterministic markdown failure")));
        }

        fn render_scenario_markdown(
            tests: &[ConformanceTestFn],
            generated_at_epoch_secs: u64,
        ) -> String {
            let mut events = Vec::new();
            let (passed, failed) =
                run_conformance_tests_with_reporter(tests, &TestConfig::default(), |event| {
                    events.push(event);
                });
            scrub_conformance_markdown(&render_conformance_report_markdown(
                passed,
                failed,
                &events,
                generated_at_epoch_secs,
            ))
        }

        let snapshot = [
            "## passing".to_string(),
            render_scenario_markdown(
                &[ConformanceTestFn {
                    name: "pass_only",
                    test_fn: passing_test,
                }],
                1_700_000_001,
            ),
            "## failing".to_string(),
            render_scenario_markdown(
                &[ConformanceTestFn {
                    name: "fail_only",
                    test_fn: failing_test,
                }],
                1_800_000_002,
            ),
            "## mixed".to_string(),
            render_scenario_markdown(
                &[
                    ConformanceTestFn {
                        name: "pass_first",
                        test_fn: passing_test,
                    },
                    ConformanceTestFn {
                        name: "fail_second",
                        test_fn: failing_test,
                    },
                    ConformanceTestFn {
                        name: "pass_third",
                        test_fn: passing_test,
                    },
                ],
                1_900_000_003,
            ),
        ]
        .join("\n\n");

        insta::assert_snapshot!("conformance_report_markdown_scrubbed", snapshot);
    }

    #[test]
    fn conformance_manifest_yaml_component_matrix_snapshot() {
        let snapshot = render_conformance_manifest_yaml(&[
            ConformanceManifestComponent {
                component: "runtime-target",
                target: "LabRuntimeTarget",
                tests: vec![
                    ConformanceManifestTest {
                        name: "test_lab_runtime_target_advance_time",
                        invariant: "virtual time advances by the requested duration without wall-clock drift",
                    },
                    ConformanceManifestTest {
                        name: "lab_runtime_target_spawn_registers_real_task_handle",
                        invariant: "spawned conformance tasks resolve from pending handles to registered task ids",
                    },
                    ConformanceManifestTest {
                        name: "lab_runtime_target_create_region_and_cancel_before_registration_closes_region",
                        invariant: "region registration resolves before cancellation completes closure",
                    },
                    ConformanceManifestTest {
                        name: "test_lab_runtime_target_create",
                        invariant: "runtime creation forwards the requested deterministic seed",
                    },
                ],
            },
            ConformanceManifestComponent {
                component: "config",
                target: "TestConfig",
                tests: vec![
                    ConformanceManifestTest {
                        name: "test_config_default",
                        invariant: "default config preserves the canonical timeout, seed, tracing, and step budget",
                    },
                    ConformanceManifestTest {
                        name: "test_config_with_budget",
                        invariant: "root budget overrides are preserved in the default config chain",
                    },
                    ConformanceManifestTest {
                        name: "test_config_builder",
                        invariant: "builder setters preserve explicit timeout, seed, tracing, and max-step overrides",
                    },
                    ConformanceManifestTest {
                        name: "test_config_without_seed",
                        invariant: "seedless configuration is represented explicitly for nondeterministic targets",
                    },
                ],
            },
            ConformanceManifestComponent {
                component: "reporting",
                target: "ConformanceEvent",
                tests: vec![
                    ConformanceManifestTest {
                        name: "report_markdown_snapshot_scrubs_generated_timestamps",
                        invariant: "markdown reports scrub generated timestamps while preserving summary ordering",
                    },
                    ConformanceManifestTest {
                        name: "reporter_snapshot_scrubs_failure_messages",
                        invariant: "structured reports preserve pass-fail ordering while redacting failure payloads",
                    },
                ],
            },
            ConformanceManifestComponent {
                component: "handles",
                target: "TaskHandle/RegionHandle",
                tests: vec![
                    ConformanceManifestTest {
                        name: "region_handle_id",
                        invariant: "region handles surface the registered region id once available",
                    },
                    ConformanceManifestTest {
                        name: "task_handle_id",
                        invariant: "task handles surface the registered task id once available",
                    },
                ],
            },
        ]);

        insta::assert_snapshot!("conformance_manifest_yaml_component_matrix", snapshot);
    }
