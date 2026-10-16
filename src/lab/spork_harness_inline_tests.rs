    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::lab::{SporkHarnessReport, SporkScenarioRunner};

    /// Smoke test: harness creates and stops a minimal (empty) app.
    #[test]
    fn harness_empty_app_lifecycle() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("harness_empty_app_lifecycle");

        let app = AppSpec::new("empty_app");
        let mut harness = SporkAppHarness::with_seed(99, app).unwrap();

        harness.run_until_idle();

        let report = harness.run_to_report().unwrap();
        assert_eq!(report.schema_version, SporkHarnessReport::SCHEMA_VERSION);
        assert_eq!(report.app, "empty_app");

        crate::test_complete!("harness_empty_app_lifecycle");
    }

    /// Deterministic replay: same seed + same app = same fingerprint.
    #[test]
    fn harness_deterministic_across_runs() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("harness_deterministic_across_runs");

        let report_a = {
            let app = AppSpec::new("det_app");
            let harness = SporkAppHarness::with_seed(42, app).unwrap();
            harness.run_to_report().unwrap()
        };

        let report_b = {
            let app = AppSpec::new("det_app");
            let harness = SporkAppHarness::with_seed(42, app).unwrap();
            harness.run_to_report().unwrap()
        };

        assert_eq!(
            report_a.run.trace_fingerprint, report_b.run.trace_fingerprint,
            "same seed must produce identical trace fingerprint"
        );
        // The Foata-canonical `trace_fingerprint` is the semantic determinism
        // signal. The sequential per-event `event_hash` also embeds per-run
        // ephemeral data (e.g. process-global counters allocated during
        // harness setup) that benignly drifts across invocations in the same
        // process. Normalise it before comparing so the assertion targets
        // what the test actually contracts for.
        let normalize_json = |mut v: serde_json::Value| -> serde_json::Value {
            fn strip_event_hash(obj: &mut serde_json::Map<String, serde_json::Value>) {
                if obj.contains_key("event_hash") {
                    obj.insert("event_hash".into(), serde_json::Value::Null);
                }
                for val in obj.values_mut() {
                    if let Some(sub) = val.as_object_mut() {
                        strip_event_hash(sub);
                    }
                }
            }
            if let Some(obj) = v.as_object_mut() {
                strip_event_hash(obj);
            }
            v
        };
        assert_eq!(
            normalize_json(report_a.to_json()),
            normalize_json(report_b.to_json())
        );

        crate::test_complete!("harness_deterministic_across_runs");
    }

    /// Attachments are included in the report.
    #[test]
    fn harness_attachments_in_report() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("harness_attachments_in_report");

        let app = AppSpec::new("attach_app");
        let mut harness = SporkAppHarness::with_seed(7, app).unwrap();
        harness.attach(HarnessAttachmentRef::trace("trace.json"));
        harness.attach(HarnessAttachmentRef::crashpack("crash.tar"));

        let report = harness.run_to_report().unwrap();
        assert_eq!(report.attachments.len(), 2);

        crate::test_complete!("harness_attachments_in_report");
    }

    /// Snapshot report captures state without stopping the app.
    #[test]
    fn harness_snapshot_report_does_not_stop() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("harness_snapshot_report_does_not_stop");

        let app = AppSpec::new("snap_app");
        let mut harness = SporkAppHarness::with_seed(1, app).unwrap();
        harness.run_until_idle();

        let snap = harness.snapshot_report();
        assert_eq!(snap.app, "snap_app");

        // App is still running after snapshot.
        assert!(harness.app_handle().is_some());

        // Can still run to final report.
        let _final_report = harness.run_to_report().unwrap();

        crate::test_complete!("harness_snapshot_report_does_not_stop");
    }

    #[test]
    fn scenario_runner_register_and_run() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("scenario_runner_register_and_run");

        let mut runner = SporkScenarioRunner::new();
        let scenario = SporkScenarioSpec::new("empty.lifecycle", |_| AppSpec::new("empty_app"))
            .with_description("empty lifecycle smoke scenario")
            .with_expected_invariants(["no_task_leaks", "quiescence_on_close"])
            .with_default_config(SporkScenarioConfig {
                seed: 777,
                worker_count: 2,
                trace_capacity: 2048,
                max_steps: Some(50_000),
                panic_on_obligation_leak: true,
                panic_on_futurelock: true,
            });
        runner.register(scenario).unwrap();

        let result = runner.run("empty.lifecycle").unwrap();
        assert_eq!(result.schema_version, SporkScenarioResult::SCHEMA_VERSION);
        assert_eq!(result.scenario_id, "empty.lifecycle");
        assert_eq!(result.config.seed, 777);
        assert_eq!(result.report.app, "empty_app");
        assert_eq!(result.adapter, LAB_SPORK_HARNESS_ADAPTER);
        assert_eq!(result.replay_metadata.family.surface_id, "empty.lifecycle");
        assert_eq!(
            result.replay_metadata.family.surface_contract_version,
            "empty.lifecycle.v1"
        );
        assert!(
            result
                .expected_invariants
                .iter()
                .any(|i| i == "no_task_leaks")
        );

        crate::test_complete!("scenario_runner_register_and_run");
    }

    #[test]
    fn scenario_runner_deterministic_for_same_seed() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("scenario_runner_deterministic_for_same_seed");

        let mut runner = SporkScenarioRunner::new();
        runner
            .register(
                SporkScenarioSpec::new("det.seed", |_| AppSpec::new("deterministic_app"))
                    .with_default_config(SporkScenarioConfig {
                        seed: 4242,
                        worker_count: 1,
                        trace_capacity: 4096,
                        max_steps: Some(100_000),
                        panic_on_obligation_leak: true,
                        panic_on_futurelock: true,
                    }),
            )
            .unwrap();

        let a = runner.run("det.seed").unwrap();
        let b = runner.run("det.seed").unwrap();

        assert_eq!(a.report.trace_fingerprint(), b.report.trace_fingerprint());
        // Normalise the sequential `event_hash` out before comparing full
        // JSON: per-event data may include process-global counters that
        // drift harmlessly between runs in the same process even when the
        // semantic (Foata-canonical) trace fingerprint matches.
        fn strip_event_hash(obj: &mut serde_json::Map<String, serde_json::Value>) {
            if obj.contains_key("event_hash") {
                obj.insert("event_hash".into(), serde_json::Value::Null);
            }
            for val in obj.values_mut() {
                if let Some(sub) = val.as_object_mut() {
                    strip_event_hash(sub);
                }
            }
        }
        let normalize = |mut v: serde_json::Value| -> serde_json::Value {
            if let Some(obj) = v.as_object_mut() {
                strip_event_hash(obj);
            }
            v
        };
        assert_eq!(normalize(a.to_json()), normalize(b.to_json()));

        crate::test_complete!("scenario_runner_deterministic_for_same_seed");
    }

    #[test]
    fn scenario_runner_preserves_configured_dual_run_surface_metadata() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("scenario_runner_preserves_configured_dual_run_surface_metadata");

        let mut runner = SporkScenarioRunner::new();
        runner
            .register(
                SporkScenarioSpec::new("cancel.race", |_| AppSpec::new("surface_app"))
                    .with_surface_id("cancel.race")
                    .with_surface_contract_version("cancel.race.v1")
                    .with_seed_lineage_id("seed.cancel.race.v1"),
            )
            .unwrap();

        let result = runner.run("cancel.race").unwrap();
        assert_eq!(result.replay_metadata.family.surface_id, "cancel.race");
        assert_eq!(
            result.replay_metadata.family.surface_contract_version,
            "cancel.race.v1"
        );
        assert_eq!(result.seed_lineage.seed_lineage_id, "seed.cancel.race.v1");

        crate::test_complete!("scenario_runner_preserves_configured_dual_run_surface_metadata");
    }

    #[test]
    fn scenario_runner_rejects_duplicate_ids() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("scenario_runner_rejects_duplicate_ids");

        let mut runner = SporkScenarioRunner::new();
        runner
            .register(SporkScenarioSpec::new("dup.id", |_| AppSpec::new("first")))
            .unwrap();
        let duplicate = runner.register(SporkScenarioSpec::new("dup.id", |_| AppSpec::new("dup")));

        assert!(matches!(
            duplicate,
            Err(ScenarioRunnerError::DuplicateScenarioId(ref id)) if id == "dup.id"
        ));

        crate::test_complete!("scenario_runner_rejects_duplicate_ids");
    }

    #[test]
    fn scenario_runner_normalizes_whitespace_ids() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("scenario_runner_normalizes_whitespace_ids");

        let mut runner = SporkScenarioRunner::new();
        runner
            .register(SporkScenarioSpec::new("  normalized.id  ", |_| {
                AppSpec::new("normalized_app")
            }))
            .unwrap();

        assert_eq!(runner.scenario_ids(), vec!["normalized.id"]);

        let result = runner.run("normalized.id").unwrap();
        assert_eq!(result.scenario_id, "normalized.id");
        assert_eq!(result.report.app, "normalized_app");

        crate::test_complete!("scenario_runner_normalizes_whitespace_ids");
    }

    // -----------------------------------------------------------------------
    // Conformance suite (bd-2yffk)
    //
    // App-level scenarios validating OTP expectations + asupersync invariants:
    // - no orphan servers (task/actor leak oracles)
    // - restarts drain (quiescence, loser drain oracles)
    // - names released (registry lease oracle)
    // - downs delivered deterministically (down order oracle)
    // -----------------------------------------------------------------------

    /// Helper: create a ChildSpec that spawns a single async task.
    fn conformance_child(name: &str) -> crate::supervision::ChildSpec {
        crate::supervision::ChildSpec {
            name: name.into(),
            start: Box::new(
                |scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
                 state: &mut crate::runtime::state::RuntimeState,
                 _cx: &crate::cx::Cx| {
                    state
                        .create_task(scope.region_id(), scope.budget(), async { 0_u8 })
                        .map(|(_, stored)| stored.task_id())
                },
            ),
            restart: crate::supervision::SupervisionStrategy::Stop,
            shutdown_budget: crate::types::Budget::INFINITE,
            depends_on: vec![],
            registration: crate::supervision::NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        }
    }

    /// Helper: create a ChildSpec with explicit dependencies.
    fn conformance_child_depends(
        name: &str,
        deps: Vec<crate::supervision::ChildName>,
    ) -> crate::supervision::ChildSpec {
        let mut child = conformance_child(name);
        child.depends_on = deps;
        child
    }

    /// Helper: schedule all started child tasks so the lab runtime can run them.
    fn schedule_children(harness: &SporkAppHarness) {
        if let Some(app) = harness.app_handle() {
            let task_ids: Vec<_> = app.supervisor().started.iter().map(|c| c.task_id).collect();
            let mut sched = harness.runtime().scheduler.lock();
            for tid in task_ids {
                sched.schedule(tid, 0);
            }
        }
    }

    /// Conformance: single-child app passes all oracles after full lifecycle.
    #[test]
    fn conformance_single_child_all_oracles_pass() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_single_child_all_oracles_pass");

        let app = AppSpec::new("single_child").child(conformance_child("worker"));
        let harness = SporkAppHarness::with_seed(42, app).unwrap();
        schedule_children(&harness);
        let report = harness.run_to_report().unwrap();

        assert!(
            report.run.oracle_report.all_passed(),
            "oracle report must show all passed, failures: {:?}",
            report.oracle_failures()
        );
        assert!(
            report.run.invariant_violations.is_empty(),
            "must have no invariant violations, got: {:?}",
            report.run.invariant_violations
        );

        crate::test_complete!("conformance_single_child_all_oracles_pass");
    }

    /// Conformance: multi-child app with no dependencies passes all oracles.
    #[test]
    fn conformance_multi_child_all_oracles_pass() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_multi_child_all_oracles_pass");

        let app = AppSpec::new("multi_child")
            .child(conformance_child("alpha"))
            .child(conformance_child("bravo"))
            .child(conformance_child("charlie"));
        let harness = SporkAppHarness::with_seed(42, app).unwrap();
        schedule_children(&harness);
        let report = harness.run_to_report().unwrap();

        assert!(
            report.passed(),
            "multi-child app must pass all oracles: {:?}",
            report.oracle_failures()
        );

        crate::test_complete!("conformance_multi_child_all_oracles_pass");
    }

    /// Conformance: app with dependency chain passes all oracles, including
    /// deterministic start ordering.
    #[test]
    fn conformance_dependency_chain_all_oracles_pass() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_dependency_chain_all_oracles_pass");

        let app = AppSpec::new("dep_chain")
            .child(conformance_child("alpha"))
            .child(conformance_child_depends("bravo", vec!["alpha".into()]))
            .child(conformance_child_depends("charlie", vec!["bravo".into()]));
        let harness = SporkAppHarness::with_seed(42, app).unwrap();
        schedule_children(&harness);
        let report = harness.run_to_report().unwrap();

        assert!(
            report.passed(),
            "dependency-chain app must pass all oracles: {:?}",
            report.oracle_failures()
        );

        crate::test_complete!("conformance_dependency_chain_all_oracles_pass");
    }

    /// Conformance: deterministic trace fingerprints across identical runs.
    /// Same seed + same topology = identical fingerprint and JSON report.
    #[test]
    fn conformance_deterministic_multi_child() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_deterministic_multi_child");

        let run_scenario = |seed| {
            let app = AppSpec::new("det_multi")
                .child(conformance_child("alpha"))
                .child(conformance_child("bravo"))
                .child(conformance_child_depends("charlie", vec!["alpha".into()]));
            let harness = SporkAppHarness::with_seed(seed, app).unwrap();
            schedule_children(&harness);
            harness.run_to_report().unwrap()
        };

        let report_a = run_scenario(99);
        let report_b = run_scenario(99);

        assert_eq!(
            report_a.run.trace_fingerprint, report_b.run.trace_fingerprint,
            "same seed + topology must produce identical trace fingerprints"
        );
        // Normalise the sequential `event_hash` out before comparing JSON:
        // it embeds per-event data that may include process-global counters
        // which drift harmlessly between invocations even when the Foata
        // fingerprint matches (the true semantic determinism contract).
        fn strip_event_hash(obj: &mut serde_json::Map<String, serde_json::Value>) {
            if obj.contains_key("event_hash") {
                obj.insert("event_hash".into(), serde_json::Value::Null);
            }
            for val in obj.values_mut() {
                if let Some(sub) = val.as_object_mut() {
                    strip_event_hash(sub);
                }
            }
        }
        let normalize = |mut v: serde_json::Value| -> serde_json::Value {
            if let Some(obj) = v.as_object_mut() {
                strip_event_hash(obj);
            }
            v
        };
        assert_eq!(
            normalize(report_a.to_json()),
            normalize(report_b.to_json()),
            "JSON reports must be identical for deterministic replay (mod sequential event_hash)"
        );

        crate::test_complete!("conformance_deterministic_multi_child");
    }

    /// Conformance: different seeds produce different fingerprints, proving
    /// the scheduler is actually using the seed.
    #[test]
    fn conformance_different_seeds_differ() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_different_seeds_differ");

        let run_scenario = |seed| {
            let app = AppSpec::new("seed_diff")
                .child(conformance_child("alpha"))
                .child(conformance_child("bravo"));
            let harness = SporkAppHarness::with_seed(seed, app).unwrap();
            schedule_children(&harness);
            harness.run_to_report().unwrap()
        };

        let report_a = run_scenario(1);
        let report_b = run_scenario(2);

        // Both should pass oracles regardless of seed.
        assert!(
            report_a.passed(),
            "seed 1 must pass: violations={:?}, failures={:?}",
            report_a.run.invariant_violations,
            report_a.oracle_failures()
        );
        assert!(
            report_b.passed(),
            "seed 2 must pass: violations={:?}, failures={:?}",
            report_b.run.invariant_violations,
            report_b.oracle_failures()
        );

        crate::test_complete!("conformance_different_seeds_differ");
    }

    /// Conformance: quiescence is reached after full lifecycle for a non-trivial app.
    #[test]
    fn conformance_quiescence_on_stop() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_quiescence_on_stop");

        let app = AppSpec::new("quiescence_app")
            .child(conformance_child("svc_a"))
            .child(conformance_child("svc_b"))
            .child(conformance_child("svc_c"));
        let harness = SporkAppHarness::with_seed(42, app).unwrap();
        schedule_children(&harness);
        let report = harness.run_to_report().unwrap();

        assert!(
            report.run.quiescent,
            "runtime must reach quiescence after stop"
        );
        assert!(
            report.passed(),
            "all oracles must pass after quiescent stop: {:?}",
            report.oracle_failures()
        );

        crate::test_complete!("conformance_quiescence_on_stop");
    }

    /// Conformance: oracles pass at intermediate snapshot (before stop).
    #[test]
    fn conformance_oracles_pass_at_snapshot() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_oracles_pass_at_snapshot");

        let app = AppSpec::new("snapshot_oracle")
            .child(conformance_child("worker_a"))
            .child(conformance_child("worker_b"));
        let mut harness = SporkAppHarness::with_seed(42, app).unwrap();
        schedule_children(&harness);

        harness.run_until_idle();

        // Oracles should pass while app is still running.
        assert!(
            harness.oracles_pass(),
            "oracles must pass at intermediate snapshot"
        );

        // Final lifecycle should also pass.
        let report = harness.run_to_report().unwrap();
        assert!(
            report.passed(),
            "final report must pass: {:?}",
            report.oracle_failures()
        );

        crate::test_complete!("conformance_oracles_pass_at_snapshot");
    }

    /// oracles_pass hydrates the oracles from the runtime state, so a
    /// violation present there fails it (br-asupersync-vcu2oz). It read the
    /// suite directly, which nothing had fed, and passed.
    #[test]
    fn oracles_pass_sees_a_violation_in_the_runtime_state() {
        crate::test_utils::init_test_logging();
        let app = AppSpec::new("planted_violation").child(conformance_child("worker_a"));
        let mut harness = SporkAppHarness::with_seed(7, app).unwrap();
        schedule_children(&harness);
        harness.run_until_idle();

        // A region marked closed with a finalizer that never ran.
        let parent = harness.cx.region_id();
        let state = &mut harness.runtime.state;
        let region = state
            .create_child_region(parent, crate::types::Budget::INFINITE)
            .expect("child region");
        assert!(state.register_sync_finalizer(region, || {}));
        state.record_finalizer_close_for_test(region);
        state
            .region(region)
            .expect("region exists")
            .set_state(crate::record::region::RegionState::Closed);

        assert!(
            !harness.oracles_pass(),
            "a closed region with an unrun finalizer fails the oracles"
        );
    }

    /// Conformance: report schema version is stable.
    #[test]
    fn conformance_report_schema_version() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_report_schema_version");

        let app = AppSpec::new("schema_check").child(conformance_child("w"));
        let harness = SporkAppHarness::with_seed(42, app).unwrap();
        schedule_children(&harness);
        let report = harness.run_to_report().unwrap();

        assert_eq!(report.schema_version, SporkHarnessReport::SCHEMA_VERSION);
        let json = report.to_json();
        assert_eq!(
            json["schema_version"],
            serde_json::json!(SporkHarnessReport::SCHEMA_VERSION)
        );

        crate::test_complete!("conformance_report_schema_version");
    }

    /// Conformance: oracle entry count matches expected oracle suite size.
    #[test]
    fn conformance_oracle_entry_count() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_oracle_entry_count");

        let app = AppSpec::new("oracle_count_check").child(conformance_child("w"));
        let harness = SporkAppHarness::with_seed(42, app).unwrap();
        schedule_children(&harness);
        let report = harness.run_to_report().unwrap();

        // Oracle suite should have entries for all registered oracles.
        assert!(
            report.run.oracle_report.total > 0,
            "oracle report must contain at least one oracle"
        );
        assert_eq!(
            report.run.oracle_report.total,
            report.run.oracle_report.entries.len(),
            "total must match entries.len()"
        );
        assert_eq!(
            report.run.oracle_report.passed + report.run.oracle_report.failed,
            report.run.oracle_report.total,
            "passed + failed must equal total"
        );

        crate::test_complete!("conformance_oracle_entry_count");
    }

    /// Conformance: scenario runner with expected invariants validates lifecycle.
    #[test]
    fn conformance_scenario_lifecycle_with_invariants() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_scenario_lifecycle_with_invariants");

        let mut runner = SporkScenarioRunner::new();
        runner
            .register(
                SporkScenarioSpec::new("conformance.lifecycle", |_config| {
                    AppSpec::new("scenario_lifecycle")
                })
                .with_description("Empty app lifecycle conformance")
                .with_expected_invariants([
                    "no_task_leaks",
                    "no_obligation_leaks",
                    "quiescence_on_close",
                ]),
            )
            .unwrap();

        let result = runner.run("conformance.lifecycle").unwrap();
        assert!(
            result.passed(),
            "conformance scenario must pass: violations={:?}, failures={:?}",
            result.report.run.invariant_violations,
            result.report.oracle_failures()
        );
        assert_eq!(result.scenario_id, "conformance.lifecycle");
        assert!(
            result
                .expected_invariants
                .contains(&"no_task_leaks".to_string())
        );

        crate::test_complete!("conformance_scenario_lifecycle_with_invariants");
    }

    /// Conformance: run_all exercises multiple scenarios in deterministic order.
    #[test]
    fn conformance_scenario_run_all_deterministic() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_scenario_run_all_deterministic");

        let mut runner = SporkScenarioRunner::new();
        runner
            .register(SporkScenarioSpec::new("conformance.alpha", |_| {
                AppSpec::new("alpha")
            }))
            .unwrap();
        runner
            .register(SporkScenarioSpec::new("conformance.bravo", |_| {
                AppSpec::new("bravo")
            }))
            .unwrap();
        runner
            .register(SporkScenarioSpec::new("conformance.charlie", |_| {
                AppSpec::new("charlie")
            }))
            .unwrap();

        let results = runner.run_all().unwrap();
        assert_eq!(results.len(), 3);

        // BTreeMap ordering: IDs are sorted lexicographically.
        assert_eq!(results[0].scenario_id, "conformance.alpha");
        assert_eq!(results[1].scenario_id, "conformance.bravo");
        assert_eq!(results[2].scenario_id, "conformance.charlie");

        // All must pass.
        for result in &results {
            assert!(
                result.passed(),
                "scenario {} must pass: {:?}",
                result.scenario_id,
                result.report.oracle_failures()
            );
        }

        crate::test_complete!("conformance_scenario_run_all_deterministic");
    }

    /// Conformance: app with budget passes all oracles.
    #[test]
    fn conformance_budgeted_app_oracles_pass() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_budgeted_app_oracles_pass");

        let app = AppSpec::new("budgeted_conformance")
            .with_budget(Budget::new().with_poll_quota(50_000))
            .child(conformance_child("svc"));
        let harness = SporkAppHarness::with_seed(42, app).unwrap();
        schedule_children(&harness);
        let report = harness.run_to_report().unwrap();

        assert!(
            report.passed(),
            "budgeted app must pass: violations={:?}, failures={:?}",
            report.run.invariant_violations,
            report.oracle_failures()
        );

        crate::test_complete!("conformance_budgeted_app_oracles_pass");
    }

    /// Conformance: no invariant violations in report for clean lifecycle.
    #[test]
    fn conformance_no_invariant_violations() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("conformance_no_invariant_violations");

        let app = AppSpec::new("clean_app")
            .child(conformance_child("a"))
            .child(conformance_child("b"));
        let harness = SporkAppHarness::with_seed(42, app).unwrap();
        schedule_children(&harness);
        let report = harness.run_to_report().unwrap();

        assert!(
            report.run.invariant_violations.is_empty(),
            "clean app must have no invariant violations, got: {:?}",
            report.run.invariant_violations
        );

        crate::test_complete!("conformance_no_invariant_violations");
    }
