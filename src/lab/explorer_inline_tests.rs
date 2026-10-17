    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::lab::runtime::ObligationLeak;
    use crate::record::ObligationKind;
    use crate::trace::{TraceData, TraceEventKind};
    use crate::types::{Budget, ObligationId, RegionId, TaskId, Time};
    use insta::assert_json_snapshot;
    use serde_json::Value as JsonValue;
    use std::collections::BTreeMap;
    use std::fs;
    use tempfile::NamedTempFile;

    /// Comprehensive scrubber for DPOR exploration transcript golden artifacts.
    ///
    /// Scrubs all non-deterministic fields that vary between runs while preserving
    /// the structural integrity and meaningful patterns in exploration transcripts.
    fn scrub_exploration_transcript(value: &mut JsonValue) {
        match value {
            JsonValue::Object(map) => {
                for (key, entry) in map.iter_mut() {
                    match key.as_str() {
                        // Seeds and derived values
                        "seed" => *entry = JsonValue::String("[SEED]".to_string()),
                        "violation_seeds" => {
                            if let JsonValue::Array(seeds) = entry {
                                for seed in seeds {
                                    *seed = JsonValue::String("[SEED]".to_string());
                                }
                            }
                        }
                        "certificate_divergences" => {
                            if let JsonValue::Array(pairs) = entry {
                                for pair in pairs {
                                    if let JsonValue::Array(seeds) = pair {
                                        for seed in seeds {
                                            *seed = JsonValue::String("[SEED]".to_string());
                                        }
                                    }
                                }
                            }
                        }

                        // Hash values and fingerprints (deterministic but opaque)
                        "fingerprint" => {
                            if let JsonValue::Number(n) = entry {
                                if n.as_u64().is_some() {
                                    *entry = JsonValue::String("[FINGERPRINT]".to_string());
                                }
                            }
                        }
                        "certificate_hash" => {
                            if let JsonValue::Number(n) = entry {
                                if n.as_u64().is_some() {
                                    *entry = JsonValue::String("[CERT_HASH]".to_string());
                                }
                            }
                        }

                        // Step counts (execution-dependent)
                        "steps" => {
                            if let JsonValue::Number(n) = entry {
                                if n.as_u64().is_some() {
                                    *entry = JsonValue::String("[STEPS]".to_string());
                                }
                            }
                        }

                        // Class run counts map (preserve structure, scrub keys)
                        "class_run_counts" => {
                            if let JsonValue::Object(counts) = entry {
                                let scrubbed_counts: serde_json::Map<String, JsonValue> = counts
                                    .iter()
                                    .enumerate()
                                    .map(|(i, (_, v))| (format!("[FINGERPRINT_{}]", i), v.clone()))
                                    .collect();
                                *entry = JsonValue::Object(scrubbed_counts);
                            }
                        }

                        // Topological scores with fingerprint scrubbing
                        "score" => {
                            if let JsonValue::Object(score_map) = entry {
                                if let Some(fp) = score_map.get_mut("fingerprint") {
                                    *fp = JsonValue::String("[FINGERPRINT]".to_string());
                                }
                            }
                        }

                        _ => scrub_exploration_transcript(entry),
                    }
                }
            }
            JsonValue::Array(entries) => {
                for entry in entries {
                    scrub_exploration_transcript(entry);
                }
            }
            JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_) => {}
        }
    }

    /// Legacy scrubber for backward compatibility with existing tests.
    fn scrub_seed_fields(value: &mut JsonValue) {
        scrub_exploration_transcript(value);
    }

    fn scenario_discovery_report_v2() -> ExplorationReport {
        ExplorationReport {
            total_runs: 3,
            unique_classes: 2,
            violations: vec![ViolationReport {
                seed: 11,
                steps: 21,
                violations: vec![InvariantViolation::TaskLeak { count: 2 }],
                fingerprint: 7001,
            }],
            coverage: CoverageMetrics {
                equivalence_classes: 2,
                total_runs: 3,
                new_class_discoveries: 2,
                class_run_counts: BTreeMap::from([(7001_u64, 2_usize), (7002_u64, 1_usize)]),
                novelty_histogram: BTreeMap::from([(0_u32, 1_usize), (1_u32, 2_usize)]),
                saturation: SaturationMetrics {
                    window: 10,
                    saturated: false,
                    existing_class_hits: 1,
                    runs_since_last_new_class: Some(1),
                },
            },
            top_unexplored: vec![
                UnexploredSeed {
                    seed: 44,
                    score: Some(TopologicalScore {
                        novelty: 3,
                        persistence_sum: 15,
                        fingerprint: 991,
                    }),
                },
                UnexploredSeed {
                    seed: 45,
                    score: None,
                },
            ],
            runs: vec![
                RunResult {
                    seed: 11,
                    steps: 21,
                    fingerprint: 7001,
                    is_new_class: true,
                    violations: vec![InvariantViolation::TaskLeak { count: 2 }],
                    certificate_hash: 17_001,
                },
                RunResult {
                    seed: 12,
                    steps: 13,
                    fingerprint: 7001,
                    is_new_class: false,
                    violations: Vec::new(),
                    certificate_hash: 17_002,
                },
                RunResult {
                    seed: 13,
                    steps: 8,
                    fingerprint: 7002,
                    is_new_class: true,
                    violations: Vec::new(),
                    certificate_hash: 17_099,
                },
            ],
        }
    }

    #[test]
    fn explore_single_task_no_violations() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(42, 5));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 42 })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
            runtime.run_until_quiescent();
        });

        assert!(!report.has_violations());
        assert_eq!(report.total_runs, 5);
        // Each seed produces distinct RNG values in the trace, so fingerprints
        // differ even for a single task. This is correct: the full trace
        // (including RNG) distinguishes runs. Schedule-level equivalence
        // will be handled by DPOR's filtered independence relation.
        assert!(report.unique_classes >= 1);
    }

    #[test]
    fn explore_two_independent_tasks_discovers_classes() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(0, 20));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t1, _, t1_spawn_effects) = runtime
                .state
                .create_task_with_deferred_spawn_effects(region, Budget::INFINITE, async {})
                .expect("t1");
            let (t2, _, t2_spawn_effects) = runtime
                .state
                .create_task_with_deferred_spawn_effects(region, Budget::INFINITE, async {})
                .expect("t2");
            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(t1, 0);
                sched.schedule(t2, 0);
            }
            t1_spawn_effects.dispatch();
            t2_spawn_effects.dispatch();
            runtime.run_until_quiescent();
        });

        assert!(!report.has_violations());
        assert_eq!(report.total_runs, 20);
        // Two independent no-yield tasks may produce different traces
        // depending on scheduling order, but the trace events are simple
        // enough that we might get 1 or 2 classes.
        assert!(report.unique_classes >= 1);
    }

    #[test]
    fn coverage_metrics_track_discovery() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(100, 10));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t1, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t1");
            runtime.scheduler.lock().schedule(t1, 0);
            runtime.run_until_quiescent();
        });

        let cov = &report.coverage;
        assert_eq!(cov.total_runs, 10);
        assert!(cov.equivalence_classes >= 1);
        assert!(cov.new_class_discoveries >= 1);
        // Discovery rate should be between 0 and 1 inclusive.
        assert!(cov.discovery_rate() > 0.0);
        assert!(cov.discovery_rate() <= 1.0);
        let hist_total: usize = cov.novelty_histogram.values().copied().sum();
        assert_eq!(hist_total, cov.total_runs);
        assert_eq!(cov.saturation.window, DEFAULT_SATURATION_WINDOW);
    }

    #[test]
    fn violation_seeds_are_recorded() {
        // This test just verifies the reporting mechanism works.
        // We don't inject real violations here; we just check the API.
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(42, 3));
        let report = explorer.explore(|runtime| {
            let _region = runtime.state.create_root_region(Budget::INFINITE);
            runtime.run_until_quiescent();
        });

        // No violations expected.
        assert!(report.violation_seeds().is_empty());
    }

    #[test]
    fn explorer_config_builder() {
        let config = ExplorerConfig::new(42, 50)
            .worker_count(4)
            .max_steps(10_000);
        assert_eq!(config.base_seed, 42);
        assert_eq!(config.max_runs, 50);
        assert_eq!(config.worker_count, 4);
        assert_eq!(config.max_steps_per_run, 10_000);
    }

    #[test]
    fn discovery_rate_correct() {
        let mut novelty_histogram = BTreeMap::new();
        novelty_histogram.insert(0, 7);
        novelty_histogram.insert(1, 3);
        let saturation = SaturationMetrics {
            window: DEFAULT_SATURATION_WINDOW,
            saturated: false,
            existing_class_hits: 7,
            runs_since_last_new_class: Some(7),
        };
        let metrics = CoverageMetrics {
            equivalence_classes: 3,
            total_runs: 10,
            new_class_discoveries: 3,
            class_run_counts: BTreeMap::new(),
            novelty_histogram,
            saturation,
        };
        assert!((metrics.discovery_rate() - 0.3).abs() < 1e-10);
    }

    // ── DPOR Explorer tests ─────────────────────────────────────────────

    #[test]
    fn dpor_explore_single_task_no_violations() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(42, 10));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 42 })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
            runtime.run_until_quiescent();
        });

        assert!(!report.has_violations());
        assert!(report.unique_classes >= 1);
    }

    #[test]
    fn dpor_explore_two_tasks_discovers_classes() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(0, 20));
        let report = explorer.explore(|runtime| {
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

        assert!(!report.has_violations());
        assert!(report.unique_classes >= 1);
    }

    #[test]
    fn dpor_coverage_metrics_populated() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(42, 5));
        let _report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t1, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t1");
            runtime.scheduler.lock().schedule(t1, 0);
            runtime.run_until_quiescent();
        });

        let metrics = explorer.dpor_coverage();
        assert!(metrics.base.total_runs >= 1);
        assert!(metrics.base.equivalence_classes >= 1);
        // Efficiency should be between 0 and 1.
        assert!(metrics.efficiency >= 0.0);
        assert!(metrics.efficiency <= 1.0);
    }

    #[test]
    fn dpor_explorer_respects_max_runs() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(0, 3));
        let report = explorer.explore(|runtime| {
            let _region = runtime.state.create_root_region(Budget::INFINITE);
            runtime.run_until_quiescent();
        });

        assert!(report.total_runs <= 3);
    }

    #[test]
    fn dpor_queue_promotes_pending_seed_to_front() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(0, 4));

        assert!(explorer.enqueue_seed_back(99));
        assert!(explorer.enqueue_seed_front(99));
        assert_eq!(
            explorer
                .work_queue
                .iter()
                .copied()
                .filter(|seed| *seed == 99)
                .count(),
            1
        );
        assert_eq!(explorer.work_queue.front().copied(), Some(99));
        assert!(explorer.pending_seeds.contains(&99));
    }

    #[test]
    fn dpor_report_keeps_unexplored_seed_when_run_budget_is_exhausted() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(0, 1));
        assert!(explorer.enqueue_seed_back(99));

        let report = explorer.explore(|runtime| {
            let _region = runtime.state.create_root_region(Budget::INFINITE);
            runtime.run_until_quiescent();
        });

        assert_eq!(report.total_runs, 1);
        assert_eq!(
            report
                .top_unexplored
                .iter()
                .map(|entry| entry.seed)
                .collect::<Vec<_>>(),
            vec![99]
        );
    }

    // ── Certificate integration tests ───────────────────────────────────

    #[test]
    fn certificate_hash_populated_in_run_results() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(42, 3));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 1 })
                .expect("t");
            runtime.scheduler.lock().schedule(t, 0);
            runtime.run_until_quiescent();
        });

        // Every run should have a non-zero certificate hash (tasks were polled).
        for r in &report.runs {
            assert_ne!(r.certificate_hash, 0, "seed {} had zero cert hash", r.seed);
        }
    }

    #[test]
    fn same_seed_produces_same_certificate() {
        let run = |seed: u64| -> u64 {
            let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(seed, 1));
            explorer.explore(|runtime| {
                let region = runtime.state.create_root_region(Budget::INFINITE);
                let (t, _) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async { 99 })
                    .expect("t");
                runtime.scheduler.lock().schedule(t, 0);
                runtime.run_until_quiescent();
            });
            let first = explorer
                .results()
                .first()
                .expect("explorer should record at least one run");
            first.certificate_hash
        };

        let h1 = run(77);
        let h2 = run(77);
        assert_eq!(h1, h2, "same seed should yield same certificate");
    }

    #[test]
    fn different_seeds_may_produce_different_certificates() {
        let run = |seed: u64| -> u64 {
            let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(seed, 1));
            explorer.explore(|runtime| {
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
            let first = explorer
                .results()
                .first()
                .expect("explorer should record at least one run");
            first.certificate_hash
        };

        // With two tasks and different seeds, the scheduling order may differ.
        // Collect several seeds and check we see at least 1 unique hash.
        let hashes: BTreeSet<u64> = (0..10).map(run).collect();
        assert!(!hashes.is_empty());
    }

    #[test]
    fn certificates_consistent_with_single_task() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(0, 5));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 42 })
                .expect("t");
            runtime.scheduler.lock().schedule(t, 0);
            runtime.run_until_quiescent();
        });

        // certificate_divergences checks within same fingerprint class.
        // Even if no two runs share a fingerprint, no divergences is correct.
        assert!(report.certificates_consistent());
    }

    #[test]
    fn dpor_certificate_hash_populated() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(42, 5));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 1 })
                .expect("t");
            runtime.scheduler.lock().schedule(t, 0);
            runtime.run_until_quiescent();
        });

        for r in &report.runs {
            assert_ne!(r.certificate_hash, 0, "seed {} had zero cert hash", r.seed);
        }
    }

    #[test]
    fn json_summary_includes_core_fields() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(7, 2));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
            runtime.run_until_quiescent();
        });

        let json = report.to_json_string().expect("json");
        let value: JsonValue = serde_json::from_str(&json).expect("parse");
        assert!(value.get("total_runs").is_some());
        assert!(value.get("unique_classes").is_some());
        assert!(value.get("coverage").is_some());
        assert!(value.get("violations").is_some());
        assert!(value.get("violation_seeds").is_some());
    }

    #[test]
    fn json_summary_can_be_written() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(11, 1));
        let report = explorer.explore(|runtime| {
            let _region = runtime.state.create_root_region(Budget::INFINITE);
            runtime.run_until_quiescent();
        });

        let tmp = NamedTempFile::new().expect("tmp");
        report
            .write_json_summary(tmp.path(), false)
            .expect("write json");
        let contents = fs::read_to_string(tmp.path()).expect("read");
        let value: JsonValue = serde_json::from_str(&contents).expect("parse");
        assert!(value.get("coverage").is_some());
    }

    #[test]
    fn scenario_discovery_output_v2_scrubbed_snapshot() {
        let mut value = serde_json::to_value(scenario_discovery_report_v2().to_json_summary())
            .expect("serialize scenario report");
        scrub_seed_fields(&mut value);
        assert_json_snapshot!("scenario_discovery_output_v2_scrubbed", value);
    }

    // ── Golden Artifact Tests for DPOR Exploration Transcripts ──────────────

    #[test]
    fn golden_schedule_explorer_single_task_transcript() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(42, 5));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 42 })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
            runtime.run_until_quiescent();
        });

        let mut transcript =
            serde_json::to_value(report.to_json_summary()).expect("serialize exploration report");
        scrub_exploration_transcript(&mut transcript);
        assert_json_snapshot!("schedule_explorer_single_task_transcript", transcript);
    }

    #[test]
    fn golden_schedule_explorer_concurrent_tasks_transcript() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(0, 10).worker_count(2));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t1, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 1 })
                .expect("t1");
            let (t2, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 2 })
                .expect("t2");
            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(t1, 0);
                sched.schedule(t2, 0);
            }
            runtime.run_until_quiescent();
        });

        let mut transcript =
            serde_json::to_value(report.to_json_summary()).expect("serialize exploration report");
        scrub_exploration_transcript(&mut transcript);
        assert_json_snapshot!("schedule_explorer_concurrent_tasks_transcript", transcript);
    }

    #[test]
    fn golden_dpor_explorer_basic_exploration_transcript() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(0, 8));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t1, _, t1_spawn_effects) = runtime
                .state
                .create_task_with_deferred_spawn_effects(region, Budget::INFINITE, async {})
                .expect("t1");
            let (t2, _, t2_spawn_effects) = runtime
                .state
                .create_task_with_deferred_spawn_effects(region, Budget::INFINITE, async {})
                .expect("t2");
            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(t1, 0);
                sched.schedule(t2, 0);
            }
            t1_spawn_effects.dispatch();
            t2_spawn_effects.dispatch();
            runtime.run_until_quiescent();
        });

        let mut transcript = serde_json::to_value(report.to_json_summary())
            .expect("serialize dpor exploration report");
        scrub_exploration_transcript(&mut transcript);
        assert_json_snapshot!("dpor_explorer_basic_exploration_transcript", transcript);
    }

    #[test]
    fn golden_dpor_coverage_metrics_transcript() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(42, 5));
        let _report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t1, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t1");
            runtime.scheduler.lock().schedule(t1, 0);
            runtime.run_until_quiescent();
        });

        let coverage = explorer.dpor_coverage();
        let mut transcript =
            serde_json::to_value(&coverage).expect("serialize dpor coverage metrics");
        scrub_exploration_transcript(&mut transcript);
        assert_json_snapshot!("dpor_coverage_metrics_transcript", transcript);
    }

    #[test]
    fn golden_topology_explorer_homology_scoring_transcript() {
        // Create a scenario with triangle-like trace structure for homology
        let mut explorer = TopologyExplorer::new(ExplorerConfig::new(7, 3));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);

            // Create three tasks that form a triangle dependency pattern
            let (t1, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t1");
            let (t2, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t2");
            let (t3, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t3");

            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(t1, 0);
                sched.schedule(t2, 0);
                sched.schedule(t3, 0);
            }
            runtime.run_until_quiescent();
        });

        // Test the exploration report from topology-prioritized exploration
        let mut transcript = serde_json::to_value(report.to_json_summary())
            .expect("serialize topology exploration report");
        scrub_exploration_transcript(&mut transcript);
        assert_json_snapshot!("topology_explorer_homology_scoring_transcript", transcript);
    }

    #[test]
    fn golden_exploration_report_with_violations_transcript() {
        // Create a synthetic violation scenario for golden testing
        let obligation_leak = InvariantViolation::ObligationLeak {
            leaks: vec![ObligationLeak {
                obligation: ObligationId::new_for_test(3, 1),
                kind: ObligationKind::Ack,
                holder: TaskId::new_for_test(2, 1),
                region: RegionId::new_for_test(1, 1),
            }],
        };
        let violations = vec![ViolationReport {
            seed: 123,
            steps: 45,
            violations: vec![
                InvariantViolation::TaskLeak { count: 2 },
                obligation_leak.clone(),
            ],
            fingerprint: 9876,
        }];

        let report = ExplorationReport {
            total_runs: 10,
            unique_classes: 5,
            violations,
            coverage: CoverageMetrics {
                equivalence_classes: 5,
                total_runs: 10,
                new_class_discoveries: 5,
                class_run_counts: BTreeMap::from([
                    (1000_u64, 3_usize),
                    (2000_u64, 2_usize),
                    (3000_u64, 2_usize),
                    (4000_u64, 2_usize),
                    (5000_u64, 1_usize),
                ]),
                novelty_histogram: BTreeMap::from([(0_u32, 5_usize), (1_u32, 5_usize)]),
                saturation: SaturationMetrics {
                    window: 10,
                    saturated: false,
                    existing_class_hits: 5,
                    runs_since_last_new_class: Some(2),
                },
            },
            top_unexplored: vec![UnexploredSeed {
                seed: 999,
                score: Some(TopologicalScore {
                    novelty: 2,
                    persistence_sum: 100,
                    fingerprint: 5555,
                }),
            }],
            runs: vec![
                RunResult {
                    seed: 100,
                    steps: 20,
                    fingerprint: 1000,
                    is_new_class: true,
                    violations: Vec::new(),
                    certificate_hash: 8000,
                },
                RunResult {
                    seed: 123,
                    steps: 45,
                    fingerprint: 9876,
                    is_new_class: true,
                    violations: vec![InvariantViolation::TaskLeak { count: 2 }, obligation_leak],
                    certificate_hash: 8123,
                },
            ],
        };

        let mut transcript =
            serde_json::to_value(report.to_json_summary()).expect("serialize violation report");
        scrub_exploration_transcript(&mut transcript);
        assert_json_snapshot!("exploration_report_with_violations_transcript", transcript);
    }

    #[test]
    fn golden_saturation_metrics_detailed_transcript() {
        // Create a scenario that tests saturation detection
        let metrics = SaturationMetrics {
            window: 10,
            saturated: true,
            existing_class_hits: 15,
            runs_since_last_new_class: Some(8),
        };

        let mut transcript = serde_json::to_value(&metrics).expect("serialize saturation metrics");
        scrub_exploration_transcript(&mut transcript);
        assert_json_snapshot!("saturation_metrics_detailed_transcript", transcript);
    }

    #[test]
    fn golden_coverage_trends_transcript() {
        // Test coverage evolution over multiple runs
        let coverage = CoverageMetrics {
            equivalence_classes: 8,
            total_runs: 25,
            new_class_discoveries: 8,
            class_run_counts: BTreeMap::from([
                (100_u64, 5_usize), // Frequent class
                (200_u64, 4_usize), // Common class
                (300_u64, 3_usize), // Less common
                (400_u64, 3_usize),
                (500_u64, 2_usize),
                (600_u64, 2_usize),
                (700_u64, 2_usize),
                (800_u64, 1_usize), // Rare classes
                (900_u64, 1_usize),
                (1000_u64, 2_usize),
            ]),
            novelty_histogram: BTreeMap::from([
                (0_u32, 17_usize), // Existing class hits
                (1_u32, 8_usize),  // New class discoveries
            ]),
            saturation: SaturationMetrics {
                window: 10,
                saturated: true,
                existing_class_hits: 17,
                runs_since_last_new_class: Some(5),
            },
        };

        let mut transcript = serde_json::to_value(&coverage).expect("serialize coverage metrics");
        scrub_exploration_transcript(&mut transcript);
        assert_json_snapshot!("coverage_trends_transcript", transcript);
    }

    #[test]
    fn schedule_report_includes_per_run_results() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(21, 3));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (task, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("task");
            runtime.scheduler.lock().schedule(task, 0);
            runtime.run_until_quiescent();
        });

        assert_eq!(report.runs.len(), report.total_runs);
        assert!(!report.runs.is_empty());
    }

    #[test]
    fn dpor_report_includes_per_run_results() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(31, 3));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (task, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("task");
            runtime.scheduler.lock().schedule(task, 0);
            runtime.run_until_quiescent();
        });

        assert_eq!(report.runs.len(), report.total_runs);
        assert!(!report.runs.is_empty());
    }

    #[test]
    fn topology_frontier_upgrades_pending_seed_score() {
        let mut explorer = TopologyExplorer::new(ExplorerConfig::new(10, 2));
        let low_score = TopologicalScore {
            novelty: 1,
            persistence_sum: 2,
            fingerprint: seed_fingerprint(99),
        };
        let high_score = TopologicalScore {
            novelty: 2,
            persistence_sum: 5,
            fingerprint: seed_fingerprint(99),
        };

        assert!(explorer.push_frontier_seed(99, low_score));
        assert!(explorer.push_frontier_seed(99, high_score));
        assert_eq!(
            explorer.pending_frontier.get(&99).copied(),
            Some(high_score)
        );
        assert_eq!(
            explorer
                .top_unexplored(2)
                .into_iter()
                .find(|entry| entry.seed == 99)
                .and_then(|entry| entry.score),
            Some(high_score)
        );
        assert!(!explorer.push_frontier_seed(99, low_score));
    }

    #[test]
    fn topology_report_keeps_unexplored_seed_when_run_budget_is_exhausted() {
        let mut explorer = TopologyExplorer::new(ExplorerConfig::new(10, 1));
        let score = TopologicalScore {
            novelty: 1,
            persistence_sum: 2,
            fingerprint: seed_fingerprint(99),
        };
        assert!(explorer.push_frontier_seed(99, score));

        let report = explorer.explore(|runtime| {
            let _region = runtime.state.create_root_region(Budget::INFINITE);
            runtime.run_until_quiescent();
        });

        assert_eq!(report.total_runs, 1);
        assert_eq!(
            report
                .top_unexplored
                .iter()
                .map(|entry| entry.seed)
                .collect::<Vec<_>>(),
            vec![10]
        );
    }

    #[test]
    fn topology_report_includes_per_run_results() {
        let mut explorer = TopologyExplorer::new(ExplorerConfig::new(41, 3));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (task, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("task");
            runtime.scheduler.lock().schedule(task, 0);
            runtime.run_until_quiescent();
        });

        assert_eq!(report.runs.len(), report.total_runs);
        assert!(!report.runs.is_empty());
    }

    #[test]
    fn topology_scoring_detects_unfilled_triangle_h1_class() {
        let trace = vec![
            TraceEvent::new(
                1,
                Time::from_nanos(10),
                TraceEventKind::ChaosInjection,
                TraceData::Chaos {
                    kind: "triangle-a".to_string(),
                    task: None,
                    detail: "write global state".to_string(),
                },
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(20),
                TraceEventKind::ChaosInjection,
                TraceData::Chaos {
                    kind: "triangle-b".to_string(),
                    task: None,
                    detail: "write global state".to_string(),
                },
            ),
            TraceEvent::new(
                3,
                Time::from_nanos(30),
                TraceEventKind::ChaosInjection,
                TraceData::Chaos {
                    kind: "triangle-c".to_string(),
                    task: None,
                    detail: "write global state".to_string(),
                },
            ),
        ];

        let mut seen_classes = BTreeSet::new();
        let ledger = score_trace_topology(&trace, &mut seen_classes, seed_fingerprint(7));

        assert_eq!(ledger.score.novelty, 1);
        assert_eq!(ledger.entries.len(), 1);
        assert_eq!(ledger.entries[0].class.death, usize::MAX);
        assert!(
            (3..6).contains(&ledger.entries[0].class.birth),
            "triangle H1 birth should come from an edge column"
        );
    }

    #[test]
    fn exploration_mode_debug_clone_copy_default_eq() {
        let m = ExplorationMode::default();
        assert_eq!(m, ExplorationMode::Baseline);

        let dbg = format!("{m:?}");
        assert!(dbg.contains("Baseline"));

        let m2 = m;
        assert_eq!(m, m2);

        let m3 = m;
        assert_eq!(m, m3);

        assert_ne!(
            ExplorationMode::Baseline,
            ExplorationMode::TopologyPrioritized
        );
    }

    #[test]
    fn explorer_config_debug_clone_default() {
        let c = ExplorerConfig::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("ExplorerConfig"));

        let c2 = c;
        assert_eq!(c2.base_seed, 0);
        assert_eq!(c2.max_runs, 100);
        assert!(c2.record_traces);
    }

    #[test]
    fn saturation_metrics_debug_clone() {
        let s = SaturationMetrics {
            window: 10,
            saturated: false,
            existing_class_hits: 5,
            runs_since_last_new_class: Some(3),
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("SaturationMetrics"));

        let s2 = s;
        assert_eq!(s2.window, 10);
        assert!(!s2.saturated);
    }

    #[test]
    fn conformal_calibration_flags_only_the_anomalous_seed() {
        // Every seed builds the same two tasks except the last, which builds
        // forty. Its oracle metrics deviate from the calibration set although
        // no seed differs in anything else. It is last so that it never
        // joins the calibration set of another scored run.
        const RUNS: usize = 24;
        const CALIBRATION: usize = 8;
        let anomalous = u64::try_from(RUNS - 1).unwrap();
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(0, RUNS))
            .with_conformal_calibration(ConformalConfig::new(0.2).min_samples(CALIBRATION));
        explorer.explore(|runtime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            let tasks = if runtime.config().seed == anomalous { 40 } else { 2 };
            for _ in 0..tasks {
                let _task = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async {})
                    .expect("create task");
            }
        });

        let calibrator = explorer
            .conformal_calibrator()
            .expect("calibration was enabled");
        assert_eq!(calibrator.calibration_samples(), RUNS);
        assert_eq!(explorer.conformal_reports().len(), RUNS - CALIBRATION);
        assert_eq!(explorer.conformal_anomaly_seeds(), vec![anomalous]);
    }

    #[test]
    fn conformal_calibration_is_off_by_default() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(0, 4));
        explorer.explore(|runtime| {
            let _root = runtime.state.create_root_region(Budget::INFINITE);
        });
        assert!(explorer.conformal_calibrator().is_none());
        assert!(explorer.conformal_reports().is_empty());
    }
