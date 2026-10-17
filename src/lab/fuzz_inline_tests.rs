    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::Budget;

    #[test]
    fn fuzz_no_violations_with_simple_task() {
        let report = fuzz_quick(42, 10, |runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 1 })
                .expect("t");
            runtime.scheduler.lock().schedule(t, 0);
            runtime.run_until_quiescent();
        });

        assert!(!report.has_findings());
        assert_eq!(report.iterations, 10);
        assert!(report.unique_certificates >= 1);
    }

    #[test]
    fn fuzz_config_builder() {
        let config = FuzzConfig::new(0, 100)
            .worker_count(4)
            .max_steps(5000)
            .minimize(false);
        assert_eq!(config.worker_count, 4);
        assert_eq!(config.max_steps, 5000);
        assert!(!config.minimize);
    }

    #[test]
    fn fuzz_two_tasks_no_violations() {
        let report = fuzz_quick(0, 20, |runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t1, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t1");
            let (t2, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t2");
            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(t1, 0);
                sched.schedule(t2, 0);
            }
            runtime.run_until_quiescent();
        });

        assert!(!report.has_findings());
    }

    #[test]
    fn fuzz_report_seed_accessors() {
        let report = FuzzReport {
            iterations: 5,
            entropy_seed: 99,
            findings: vec![FuzzFinding {
                seed: 42,
                entropy_seed: 99,
                steps: 10,
                violations: vec![],
                certificate_hash: 123,
                trace_fingerprint: 456,
                minimized_seed: Some(3),
            }],
            violation_counts: BTreeMap::new(),
            unique_certificates: 1,
        };

        assert_eq!(report.finding_seeds(), vec![42]);
        assert_eq!(report.minimized_seeds(), vec![3]);
        assert!(report.has_findings());
    }

    #[test]
    fn fuzz_deterministic_same_seed_same_result() {
        let run = |seed: u64| -> usize {
            let report = fuzz_quick(seed, 5, |runtime| {
                let region = runtime.state.create_root_region(Budget::INFINITE);
                let (t, _) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async { 42 })
                    .expect("t");
                runtime.scheduler.lock().schedule(t, 0);
                runtime.run_until_quiescent();
            });
            report.unique_certificates
        };

        let r1 = run(77);
        let r2 = run(77);
        assert_eq!(r1, r2);
    }

    // =========================================================================
    // Wave 46 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn fuzz_config_debug_clone_defaults() {
        let cfg = FuzzConfig::new(42, 100);
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("FuzzConfig"), "{dbg}");
        assert_eq!(cfg.base_seed, 42);
        assert_eq!(cfg.entropy_seed, 42);
        assert_eq!(cfg.iterations, 100);
        assert_eq!(cfg.max_steps, 100_000);
        assert_eq!(cfg.worker_count, 1);
        assert!(cfg.minimize);
        assert_eq!(cfg.minimize_attempts, 96);
        let cloned = cfg.clone();
        assert_eq!(cloned.base_seed, cfg.base_seed);
        assert_eq!(cloned.iterations, cfg.iterations);
    }

    #[test]
    fn fuzz_finding_debug_clone() {
        let finding = FuzzFinding {
            seed: 99,
            entropy_seed: 7,
            steps: 500,
            violations: vec![],
            certificate_hash: 12345,
            trace_fingerprint: 67890,
            minimized_seed: Some(7),
        };
        let dbg = format!("{finding:?}");
        assert!(dbg.contains("FuzzFinding"), "{dbg}");
        let cloned = finding;
        assert_eq!(cloned.seed, 99);
        assert_eq!(cloned.entropy_seed, 7);
        assert_eq!(cloned.steps, 500);
        assert_eq!(cloned.certificate_hash, 12345);
        assert_eq!(cloned.trace_fingerprint, 67890);
        assert_eq!(cloned.minimized_seed, Some(7));
    }

    #[test]
    fn fuzz_harness_keeps_entropy_seed_stable_across_iterations() {
        let observed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = std::sync::Arc::clone(&observed);
        let harness = FuzzHarness::new(FuzzConfig::new(7, 3));

        harness.run(move |runtime| {
            captured
                .lock()
                .expect("lock observed seeds")
                .push((runtime.config().seed, runtime.config().entropy_seed));
        });

        let observed = observed.lock().expect("lock observed seeds");
        assert_eq!(
            observed.as_slice(),
            &[(7, 7), (8, 7), (9, 7)],
            "campaign iterations must vary schedule seed without mutating entropy seed"
        );
    }

    #[test]
    fn fuzz_report_debug_empty() {
        let report = FuzzReport {
            iterations: 0,
            entropy_seed: 55,
            findings: vec![],
            violation_counts: BTreeMap::new(),
            unique_certificates: 0,
        };
        let dbg = format!("{report:?}");
        assert!(dbg.contains("FuzzReport"), "{dbg}");
        assert!(!report.has_findings());
        assert!(report.finding_seeds().is_empty());
        assert!(report.minimized_seeds().is_empty());
    }

    #[test]
    fn regression_corpus_is_sorted_and_minimized() {
        let report = FuzzReport {
            iterations: 3,
            entropy_seed: 0x7777,
            findings: vec![
                FuzzFinding {
                    seed: 44,
                    entropy_seed: 0x7777,
                    steps: 100,
                    violations: vec![
                        InvariantViolation::QuiescenceViolation,
                        InvariantViolation::QuiescenceViolation,
                    ],
                    certificate_hash: 0xB,
                    trace_fingerprint: 0xBB,
                    minimized_seed: Some(3),
                },
                FuzzFinding {
                    seed: 13,
                    entropy_seed: 0x7777,
                    steps: 200,
                    violations: vec![InvariantViolation::Futurelock {
                        task: crate::types::TaskId::new_for_test(1, 0),
                        region: crate::types::RegionId::new_for_test(1, 0),
                        idle_steps: 1,
                        held: Vec::new(),
                        last_checkpoint_message: None,
                    }],
                    certificate_hash: 0xA,
                    trace_fingerprint: 0xAA,
                    minimized_seed: None,
                },
            ],
            violation_counts: BTreeMap::new(),
            unique_certificates: 2,
        };

        let corpus = report.to_regression_corpus(1234);
        assert_eq!(corpus.schema_version, 1);
        assert_eq!(corpus.base_seed, 1234);
        assert_eq!(corpus.entropy_seed, 0x7777);
        assert_eq!(corpus.iterations, 3);
        assert_eq!(corpus.cases.len(), 2);

        // Sorted by replay_seed then deterministic tie-breakers.
        assert_eq!(corpus.cases[0].seed, 44);
        assert_eq!(corpus.cases[0].replay_seed, 3);
        assert_eq!(
            corpus.cases[0].violation_categories,
            vec!["quiescence_violation"]
        );

        assert_eq!(corpus.cases[1].seed, 13);
        assert_eq!(corpus.cases[1].replay_seed, 13);
        assert_eq!(corpus.cases[1].violation_categories, vec!["futurelock"]);
    }

    #[test]
    fn regression_corpus_replay_seeds_preserve_violation_categories() {
        let config = FuzzConfig::new(0x6C6F_7265_6D71_6505, 4)
            .worker_count(2)
            .max_steps(256)
            .minimize(true);
        let harness = FuzzHarness::new(config.clone());

        let scenario = |runtime: &mut LabRuntime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            for _ in 0..3 {
                let (task_id, _) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async {})
                    .expect("create scheduled task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }
            let _unscheduled = runtime
                .state
                .create_task(root, Budget::INFINITE, async {})
                .expect("create unscheduled task");
            runtime.run_until_quiescent();
        };

        let report = harness.run(scenario);
        assert!(report.has_findings(), "expected minimized fuzz findings");
        let corpus = report.to_regression_corpus(config.base_seed);
        assert!(
            !corpus.cases.is_empty(),
            "regression corpus must include failing replay seeds"
        );

        for case in &corpus.cases {
            let first_replay = harness.run_single(case.replay_seed, &scenario);
            assert!(
                !first_replay.violations.is_empty(),
                "replay seed {} should still violate an invariant",
                case.replay_seed
            );
            let replay_categories = sorted_violation_categories(&first_replay.violations);
            assert_eq!(
                replay_categories, case.violation_categories,
                "replay seed {} changed violation categories",
                case.replay_seed
            );

            // Deterministic replay seeds must produce stable certificates and traces.
            let second_replay = harness.run_single(case.replay_seed, &scenario);
            assert_eq!(
                first_replay.certificate_hash,
                second_replay.certificate_hash
            );
            assert_eq!(
                first_replay.trace_fingerprint,
                second_replay.trace_fingerprint
            );
        }
    }

    #[test]
    fn minimize_seed_requires_full_violation_category_match() {
        let harness = FuzzHarness::new(FuzzConfig::new(20, 1));
        let scenario = |runtime: &mut LabRuntime| {
            let seed = runtime.config().seed;
            let region = runtime.state.create_root_region(Budget::INFINITE);

            // Always leave one task unscheduled so every failing seed reports task_leak.
            let _leaked = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("create leaked task");

            // Only seeds >= 20 also force-close the region while the leaked
            // task is still live, adding quiescence_violation to the baseline
            // task_leak category.
            if seed >= 20 {
                runtime
                    .state
                    .region(region)
                    .expect("region exists")
                    .set_state(crate::record::region::RegionState::Closed);
            }
        };

        let original = harness.run_single(20, &scenario);
        assert_eq!(
            sorted_violation_categories(&original.violations),
            vec!["quiescence_violation", "task_leak"]
        );

        let smaller = harness.run_single(19, &scenario);
        assert_eq!(
            sorted_violation_categories(&smaller.violations),
            vec!["task_leak"]
        );

        let minimized = harness.minimize_seed(20, &scenario);
        assert_eq!(
            minimized, None,
            "smaller seeds do not preserve the original full violation category set"
        );
    }

    #[test]
    fn fuzz_report_promotes_findings_into_replayable_scenarios() {
        let report = FuzzReport {
            iterations: 1,
            entropy_seed: 0x44,
            findings: vec![FuzzFinding {
                seed: 0xABCD,
                entropy_seed: 0x44,
                steps: 10,
                violations: vec![InvariantViolation::TaskLeak { count: 1 }],
                certificate_hash: 0x101,
                trace_fingerprint: 0x202,
                minimized_seed: Some(0x55),
            }],
            violation_counts: BTreeMap::from([("task_leak".to_string(), 1)]),
            unique_certificates: 1,
        };

        let promoted = report.to_promoted_findings("scheduler.surface", "v1");
        assert_eq!(promoted.len(), 1);
        assert_eq!(promoted[0].original_seed, 0xABCD);
        assert_eq!(promoted[0].replay_seed, 0x55);
        assert_eq!(promoted[0].trace_fingerprint, 0x202);
        assert_eq!(promoted[0].violation_categories, vec!["task_leak"]);
    }

    #[test]
    fn regression_corpus_promotes_cases_with_campaign_lineage() {
        let corpus = FuzzRegressionCorpus {
            schema_version: 1,
            base_seed: 0xCAFE,
            entropy_seed: 0x77,
            iterations: 2,
            cases: vec![FuzzRegressionCase {
                seed: 0x10,
                replay_seed: 0x08,
                entropy_seed: 0x77,
                certificate_hash: 0x111,
                trace_fingerprint: 0x222,
                violation_categories: vec!["task_leak".to_string()],
            }],
        };

        let promoted = corpus.to_promoted_scenarios("scheduler.surface", "v1");
        assert_eq!(promoted.len(), 1);
        assert_eq!(promoted[0].campaign_base_seed, Some(0xCAFE));
        assert_eq!(promoted[0].campaign_iteration, Some(0));
        assert_eq!(promoted[0].original_seed, 0x10);
        assert_eq!(promoted[0].replay_seed, 0x08);
        assert_eq!(
            promoted[0].identity.seed_plan.entropy_seed_override,
            Some(0x77)
        );
        assert_eq!(
            promoted[0].violation_categories,
            vec!["task_leak".to_string()]
        );
    }

    #[test]
    fn minimized_findings_keep_violation_payload_consistent_with_replay_seed() {
        let harness = FuzzHarness::new(FuzzConfig::new(20, 1));
        let scenario = |runtime: &mut LabRuntime| {
            let seed = runtime.config().seed;
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let leak_count = if seed >= 20 { 2 } else { 1 };
            for _ in 0..leak_count {
                let _leaked = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async {})
                    .expect("create leaked task");
            }
        };

        let report = harness.run(scenario);
        let finding = report
            .findings
            .first()
            .expect("campaign should surface a minimized finding");
        assert_eq!(finding.minimized_seed, Some(0));

        let replay = harness.run_single(0, &scenario);
        assert_eq!(finding.steps, replay.steps);
        assert_eq!(finding.violations, replay.violations);
        assert_eq!(finding.certificate_hash, replay.certificate_hash);
        assert_eq!(finding.trace_fingerprint, replay.trace_fingerprint);
        assert_eq!(
            finding.violations,
            vec![InvariantViolation::TaskLeak { count: 1 }]
        );
    }

    #[test]
    fn promoted_regression_scenarios_preserve_entropy_seed_override() {
        let report = FuzzReport {
            iterations: 1,
            entropy_seed: 0xBADA,
            findings: vec![FuzzFinding {
                seed: 0x20,
                entropy_seed: 0xBADA,
                steps: 4,
                violations: vec![InvariantViolation::TaskLeak { count: 1 }],
                certificate_hash: 0xAB,
                trace_fingerprint: 0xCD,
                minimized_seed: Some(0x02),
            }],
            violation_counts: BTreeMap::from([("task_leak".to_string(), 1)]),
            unique_certificates: 1,
        };

        let promoted = report.to_promoted_regression_scenarios(0x20, "scheduler.surface", "v1");
        assert_eq!(promoted.len(), 1);
        assert_eq!(
            promoted[0].identity.seed_plan.entropy_seed_override,
            Some(0xBADA)
        );
    }

    #[test]
    fn ipejce_panicking_test_closure_recorded_as_finding_not_aborting_campaign() {
        // br-asupersync-ipejce: a fuzz target that panics on input
        // must show up as a TestPanic finding rather than aborting
        // the entire campaign. The campaign continues to subsequent
        // seeds and records each panic separately.
        let cfg = FuzzConfig::new(0xDEADBEEF, 1).worker_count(1).max_steps(16);
        let campaign = super::FuzzHarness::new(cfg);
        let panic_message = "deliberate test failure";
        let result = campaign.run_single(0xDEADBEEF, &|_runtime: &mut LabRuntime| {
            panic!("{}", panic_message); // ubs:ignore - test helper
        });
        // The panic was caught and recorded; the campaign did NOT
        // abort.  `result.violations` contains the TestPanic with
        // the original payload.
        let saw_panic = result.violations.iter().any(|v| {
            matches!(
                v,
                InvariantViolation::TestPanic { message } if message.contains(panic_message)
            )
        });
        assert!(
            saw_panic,
            "TestPanic.message should preserve the panic payload: {:?}",
            result.violations
        );
    }
