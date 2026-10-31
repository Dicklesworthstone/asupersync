    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::lab::scenario::{
        ChaosSection, FaultAction, FaultEvent, LabSection, MinimizationSection, NetworkSection,
        Scenario,
    };
    use std::collections::BTreeMap;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn minimal_scenario() -> Scenario {
        Scenario {
            schema_version: 1,
            id: "test-minimal".to_string(),
            description: "Minimal test scenario".to_string(),
            lab: LabSection::default(),
            chaos: ChaosSection::Off,
            network: NetworkSection::default(),
            ..Scenario::default()
        }
    }

    fn exact_scenario_limits() -> ExactScheduleLimits {
        ExactScheduleLimits::new(256, 256, 64, 1024, 128)
    }

    fn exact_scenario_checkpoint_limits() -> ExactScheduleCheckpointLimits {
        ExactScheduleCheckpointLimits {
            max_encoded_bytes: 1 << 20,
            max_prefixes: 1024,
            max_decisions: 8192,
            max_dispatches: 16384,
            max_decoded_bytes: 1 << 20,
        }
    }

    fn exact_channel_scenario() -> Scenario {
        let mut scenario = minimal_scenario();
        scenario.id = "exact-channel-handoff".to_owned();
        scenario.participants = vec![
            participant_with("sender", "sender", "messages", serde_json::json!(1)),
            participant_with("receiver", "receiver", "capacity", serde_json::json!(1)),
        ];
        scenario
    }

    #[test]
    fn exact_scenario_explores_real_channel_choices_and_replays_receipts() {
        init_test("exact_scenario_explores_real_channel_choices_and_replays_receipts");
        let scenario = exact_channel_scenario();
        let report = ScenarioRunner::explore_schedules(
            &scenario, None, exact_scenario_limits(), false,
        ).unwrap();
        assert!(report.passed(), "{}", report.to_json());
        assert!(report.runs.len() > 1, "both initially runnable tasks must be explored");
        let choices: BTreeSet<_> = report.runs.iter().map(|run| {
            run.execution.execution.decisions()[0].selected().task().0
        }).collect();
        assert_eq!(choices.len(), 2, "sender-first and receiver-first are real choices");
        assert!(report.runs.iter().any(|run| {
            run.execution.execution.decisions().iter().any(|d| d.enabled().len() == 1)
        }), "the channel dependency must constrain later choices");
        for run in &report.runs {
            let schedule = run.execution.schedule.as_ref().expect("complete receipt");
            let replay = ScenarioRunner::replay_schedule(
                &scenario, Some(scenario.lab.seed), run, ForcedScheduleLimits::new(64, 256),
            ).expect("each exact scenario receipt executes independently");
            assert!(replay.passed(), "{}", replay.to_json());
            assert_eq!(replay.execution.schedule_hash, schedule.terminal_schedule_hash());
            assert_eq!(replay.lab.steps_total, run.execution.lab.steps_total);
            assert_eq!(replay.oracle_report.to_json(), run.oracle_report.to_json());
        }
        assert!(matches!(ScenarioRunner::replay_schedule(
            &scenario, None, &report.runs[0], ForcedScheduleLimits::new(0, 256),
        ), Err(ScenarioScheduleError::Replay(ForcedScheduleError::DispatchLimitExceeded { .. }))));
        assert!(matches!(ScenarioRunner::replay_schedule(
            &scenario, None, &report.runs[0], ForcedScheduleLimits::new(64, 0),
        ), Err(ScenarioScheduleError::Replay(ForcedScheduleError::WorkLimitExceeded { .. }))));
        crate::test_complete!("exact_scenario_explores_real_channel_choices_and_replays_receipts");
    }

    #[test]
    fn exact_scenario_batches_resume_in_the_same_order_without_repeating_work() {
        init_test("exact_scenario_batches_resume_in_the_same_order_without_repeating_work");
        let scenario = exact_channel_scenario();
        let full = ScenarioRunner::explore_schedules(
            &scenario, None, exact_scenario_limits(), false,
        ).unwrap();
        assert!(full.passed(), "{}", full.to_json());
        let mut limits = exact_scenario_limits();
        limits.max_runs = 1;
        let mut checkpoint = ScenarioRunner::new_schedule_checkpoint(&scenario, None, limits).unwrap();
        let mut actual = Vec::new();
        for _ in 0..full.runs.len() {
            let batch = ScenarioRunner::resume_schedules(
                &scenario, None, limits, &mut checkpoint, false,
            ).unwrap();
            assert_eq!(batch.runs.len(), 1);
            actual.push(batch.runs[0].execution.execution.clone());
            if checkpoint.pending_prefix_count() == 0 {
                assert!(batch.passed(), "{}", batch.to_json());
            } else {
                assert_eq!(batch.termination, ExactScheduleSearchTermination::RunLimit);
                assert!(!batch.passed());
            }
        }
        assert_eq!(checkpoint.pending_prefix_count(), 0);
        assert_eq!(actual, full.runs.iter().map(|run| run.execution.execution.clone()).collect::<Vec<_>>());
        assert_eq!(checkpoint.progress(), full.progress);
        let done = ScenarioRunner::resume_schedules(
            &scenario, None, limits, &mut checkpoint, false,
        ).unwrap();
        assert!(done.runs.is_empty());
        assert!(done.passed());
        crate::test_complete!("exact_scenario_batches_resume_in_the_same_order_without_repeating_work");
    }

    #[test]
    fn exact_scenario_checkpoint_roundtrip_preserves_frontier_and_unverified_history() {
        init_test("exact_scenario_checkpoint_roundtrip_preserves_frontier_and_unverified_history");
        let scenario = exact_channel_scenario();
        let mut limits = exact_scenario_limits();
        limits.max_runs = 1;
        let mut checkpoint = ScenarioRunner::new_schedule_checkpoint(&scenario, None, limits).unwrap();
        let bytes = checkpoint.to_canonical_bytes(exact_scenario_checkpoint_limits()).unwrap();
        assert_eq!(ScenarioScheduleCheckpoint::from_canonical_bytes(
            &bytes, exact_scenario_checkpoint_limits(),
        ).unwrap(), checkpoint, "an empty history needs no historical evidence");
        let first = ScenarioRunner::resume_schedules(
            &scenario, None, limits, &mut checkpoint, false,
        ).unwrap();
        assert_eq!(first.progress.runs, 1);
        let bytes = checkpoint.to_canonical_bytes(exact_scenario_checkpoint_limits()).unwrap();
        let mut decoded = ScenarioScheduleCheckpoint::from_canonical_bytes(
            &bytes, exact_scenario_checkpoint_limits(),
        ).unwrap();
        assert_eq!(decoded.to_canonical_bytes(exact_scenario_checkpoint_limits()).unwrap(), bytes);
        assert!(!decoded.historical_progress_verified());
        let observed = ScenarioRunner::resume_schedules(
            &scenario, None, exact_scenario_limits(), &mut checkpoint, false,
        ).unwrap();
        let resumed = ScenarioRunner::resume_schedules(
            &scenario, None, exact_scenario_limits(), &mut decoded, false,
        ).unwrap();
        assert!(observed.passed(), "{}", observed.to_json());
        assert_eq!(resumed.termination, ExactScheduleSearchTermination::SearchExhausted);
        assert!(resumed.runs.iter().all(ScenarioScheduleRun::passed));
        assert!(!resumed.passed(), "loaded counters must not become proof of unseen runs");
        assert_eq!(resumed.progress, observed.progress);
        assert_eq!(resumed.runs.iter().map(|r| &r.execution.execution).collect::<Vec<_>>(),
            observed.runs.iter().map(|r| &r.execution.execution).collect::<Vec<_>>());
        crate::test_complete!("exact_scenario_checkpoint_roundtrip_preserves_frontier_and_unverified_history");
    }

    #[test]
    fn exact_scenario_remembers_real_workload_failures_after_resume() {
        init_test("exact_scenario_remembers_real_workload_failures_after_resume");
        let mut scenario = minimal_scenario();
        scenario.id = "exact-restart-budget-failure".to_owned();
        scenario.oracles = vec!["quiescence".to_owned()];
        scenario.participants = vec![
            participant_with("supervisor", "supervisor", "max_restarts", serde_json::json!(0)),
            participant_with("worker", "worker", "fail_times", serde_json::json!(1)),
            participant("receiver", "receiver"),
        ];
        let mut checkpoint = ScenarioRunner::new_schedule_checkpoint(
            &scenario, None, exact_scenario_limits(),
        ).unwrap();
        let first = ScenarioRunner::resume_schedules(
            &scenario, None, exact_scenario_limits(), &mut checkpoint, true,
        ).unwrap();
        assert_eq!(first.termination, ExactScheduleSearchTermination::Stopped);
        assert_eq!(first.runs.len(), 1);
        assert_eq!(first.scenario_failed, 1);
        assert!(first.runs[0].execution.lab.quiescent);
        assert!(first.runs[0].execution.lab.invariant_violations.iter().any(|v| v.starts_with("workload:")),
            "{}", first.to_json());
        let replay = ScenarioRunner::replay_schedule(
            &scenario, None, &first.runs[0], ForcedScheduleLimits::new(64, 256),
        ).expect("the failing workload still has an exact executable receipt");
        assert!(!replay.passed());
        assert_eq!(replay.lab.invariant_violations, first.runs[0].execution.lab.invariant_violations);
        assert_eq!(replay.oracle_report.to_json(), first.runs[0].oracle_report.to_json());
        assert!(checkpoint.pending_prefix_count() > 0);
        let bytes = checkpoint.to_canonical_bytes(exact_scenario_checkpoint_limits()).unwrap();
        let mut restored = ScenarioScheduleCheckpoint::from_canonical_bytes(
            &bytes, exact_scenario_checkpoint_limits(),
        ).unwrap();
        assert_eq!(restored.scenario_failed(), 1);
        let later = ScenarioRunner::resume_schedules(
            &scenario, None, exact_scenario_limits(), &mut restored, false,
        ).unwrap();
        assert!(!later.passed());
        assert!(later.scenario_failed >= 1);
        assert_eq!(later.to_json()["scenario_failed"], later.scenario_failed);
        crate::test_complete!("exact_scenario_remembers_real_workload_failures_after_resume");
    }

    #[test]
    fn exact_scenario_limits_never_claim_exhausted_success() {
        init_test("exact_scenario_limits_never_claim_exhausted_success");
        let scenario = exact_channel_scenario();
        let mut limits = exact_scenario_limits();
        limits.max_runs = 1;
        let run_limited = ScenarioRunner::explore_schedules(&scenario, None, limits, false).unwrap();
        assert_eq!(run_limited.termination, ExactScheduleSearchTermination::RunLimit);
        assert!(run_limited.pending_prefixes > 0);
        assert!(!run_limited.passed());
        limits = exact_scenario_limits();
        limits.max_work_per_run = 1;
        let work_limited = ScenarioRunner::explore_schedules(&scenario, None, limits, false).unwrap();
        assert_eq!(work_limited.termination, ExactScheduleSearchTermination::IncompleteRun);
        assert!(work_limited.progress.incomplete > 0);
        assert!(!work_limited.passed());
        assert!(work_limited.runs.iter().all(|run| run.execution.schedule.is_none()));
        assert!(matches!(ScenarioRunner::replay_schedule(
            &scenario, None, &work_limited.runs[0], ForcedScheduleLimits::new(64, 256),
        ), Err(ScenarioScheduleError::MissingReplayReceipt)));
        limits = exact_scenario_limits();
        limits.max_runs = 0;
        assert!(matches!(ScenarioRunner::new_schedule_checkpoint(&scenario, None, limits),
            Err(ScenarioScheduleError::Configuration(ExactScheduleConfigError::ZeroLimit))));
        crate::test_complete!("exact_scenario_limits_never_claim_exhausted_success");
    }

    #[test]
    fn exact_scenario_rejects_changed_inputs_before_consuming_the_frontier() {
        init_test("exact_scenario_rejects_changed_inputs_before_consuming_the_frontier");
        let scenario = exact_channel_scenario();
        let original = ScenarioRunner::new_schedule_checkpoint(&scenario, None, exact_scenario_limits()).unwrap();
        let source = ScenarioRunner::explore_schedules(
            &scenario, None, exact_scenario_limits(), false,
        ).unwrap();
        for change in 0..4 {
            let mut changed = scenario.clone();
            match change {
                0 => { changed.participants[0].properties.insert("messages".to_owned(), serde_json::json!(2)); }
                1 => changed.oracles = vec!["quiescence".to_owned()],
                2 => changed.lab.entropy_seed = Some(99),
                _ => changed.lab.seed += 1,
            }
            let mut checkpoint = original.clone();
            assert!(matches!(ScenarioRunner::resume_schedules(
                &changed, None, exact_scenario_limits(), &mut checkpoint, false,
            ), Err(ScenarioScheduleError::Resume(ExactScheduleResumeError::WorkloadMismatch))));
            assert_eq!(checkpoint, original);
            assert!(matches!(ScenarioRunner::replay_schedule(
                &changed, None, &source.runs[0], ForcedScheduleLimits::new(64, 256),
            ), Err(ScenarioScheduleError::ReplayWorkloadMismatch)));
        }
        assert!(matches!(ScenarioRunner::replay_schedule(
            &scenario, Some(scenario.lab.seed + 1), &source.runs[0], ForcedScheduleLimits::new(64, 256),
        ), Err(ScenarioScheduleError::ReplayWorkloadMismatch)));
        crate::test_complete!("exact_scenario_rejects_changed_inputs_before_consuming_the_frontier");
    }

    #[test]
    fn exact_scenario_refuses_unexecuted_effects_and_empty_or_partial_workloads() {
        init_test("exact_scenario_refuses_unexecuted_effects_and_empty_or_partial_workloads");
        let scenario = exact_channel_scenario();
        let mut cases = Vec::new();
        let mut changed = scenario.clone();
        changed.faults.push(FaultEvent {
            at_ms: 1, action: FaultAction::HostCrash,
            args: BTreeMap::from([("host".to_owned(), serde_json::json!("sender"))]),
        });
        cases.push(changed);
        let mut changed = scenario.clone();
        changed.cancellation = Some(crate::lab::scenario::CancellationSection {
            strategy: crate::lab::scenario::CancellationStrategy::Never,
            count: None, probability: None,
        });
        cases.push(changed);
        let mut changed = scenario.clone();
        changed.participants.push(participant("unbound", "external-service"));
        cases.push(changed);
        cases.push(minimal_scenario());
        for changed in cases {
            assert!(matches!(ScenarioRunner::new_schedule_checkpoint(&changed, None, exact_scenario_limits()),
                Err(ScenarioScheduleError::Unsupported { .. })), "{}", changed.id);
        }
        let mut changed = scenario.clone();
        changed.lab.worker_count = 2;
        assert!(matches!(ScenarioRunner::new_schedule_checkpoint(&changed, None, exact_scenario_limits()),
            Err(ScenarioScheduleError::Configuration(ExactScheduleConfigError::MultipleWorkers))));
        changed = scenario;
        changed.chaos = ChaosSection::Light;
        assert!(matches!(ScenarioRunner::new_schedule_checkpoint(&changed, None, exact_scenario_limits()),
            Err(ScenarioScheduleError::Configuration(ExactScheduleConfigError::ChaosEnabled))));
        crate::test_complete!("exact_scenario_refuses_unexecuted_effects_and_empty_or_partial_workloads");
    }

    #[test]
    fn exact_scenario_checkpoint_rejects_corruption_counts_and_excess_storage() {
        init_test("exact_scenario_checkpoint_rejects_corruption_counts_and_excess_storage");
        let scenario = exact_channel_scenario();
        let checkpoint = ScenarioRunner::new_schedule_checkpoint(&scenario, None, exact_scenario_limits()).unwrap();
        let limits = exact_scenario_checkpoint_limits();
        let bytes = checkpoint.to_canonical_bytes(limits).unwrap();
        for end in 0..bytes.len() {
            assert!(ScenarioScheduleCheckpoint::from_canonical_bytes(&bytes[..end], limits).is_err());
        }
        let mut corrupt = bytes.clone();
        corrupt[12] ^= 1;
        assert_eq!(ScenarioScheduleCheckpoint::from_canonical_bytes(&corrupt, limits).unwrap_err(),
            ExactScheduleCheckpointError::Checksum);
        let end = corrupt.len() - 32;
        let digest = ScenarioScheduleCheckpoint::checksum(&corrupt[..end]);
        corrupt[end..].copy_from_slice(&digest);
        assert_eq!(ScenarioScheduleCheckpoint::from_canonical_bytes(&corrupt, limits).unwrap_err(),
            ExactScheduleCheckpointError::Shape, "one failed run cannot fit an empty history");
        let mut tiny = limits;
        tiny.max_encoded_bytes = bytes.len() - 1;
        assert_eq!(ScenarioScheduleCheckpoint::from_canonical_bytes(&bytes, tiny).unwrap_err(),
            ExactScheduleCheckpointError::ByteLimit);
        assert_eq!(checkpoint.to_canonical_bytes(tiny).unwrap_err(), ExactScheduleCheckpointError::ByteLimit);
        tiny = limits;
        tiny.max_prefixes = 0;
        assert_eq!(ScenarioScheduleCheckpoint::from_canonical_bytes(&bytes, tiny).unwrap_err(),
            ExactScheduleCheckpointError::PrefixLimit);
        crate::test_complete!("exact_scenario_checkpoint_rejects_corruption_counts_and_excess_storage");
    }

    #[test]
    fn run_minimal_scenario() {
        init_test("run_minimal_scenario");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::run(&scenario).unwrap();
        assert!(result.passed(), "minimal scenario should pass");
        assert_eq!(result.scenario_id, "test-minimal");
        assert_eq!(result.seed, 42);
        assert_eq!(result.faults_injected, 0);
        assert_eq!(result.adapter, LAB_SCENARIO_RUNNER_ADAPTER);
        assert_eq!(result.replay_metadata.family.surface_id, "test-minimal");
        assert_eq!(
            result.replay_metadata.family.surface_contract_version,
            "test-minimal.v1"
        );
        assert_eq!(result.seed_lineage.seed_lineage_id, "seed.test-minimal.v1");
        crate::test_complete!("run_minimal_scenario");
    }

    #[test]
    fn run_with_seed_preserves_family_and_tracks_execution_seed() {
        init_test("run_with_seed_preserves_family_and_tracks_execution_seed");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::run_with_seed(&scenario, Some(7)).unwrap();

        assert_eq!(result.seed, 7);
        assert_eq!(result.replay_metadata.family.id, "test-minimal");
        assert_eq!(result.replay_metadata.effective_seed, 7);
        assert_eq!(result.seed_lineage.canonical_seed, 42);
        assert_eq!(result.seed_lineage.lab_effective_seed, 7);

        crate::test_complete!("run_with_seed_preserves_family_and_tracks_execution_seed");
    }

    #[test]
    fn passed_requires_quiescence() {
        init_test("passed_requires_quiescence");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::run(&scenario).unwrap();
        assert!(result.passed());

        let mut forced_non_quiescent = result;
        forced_non_quiescent.lab_report.quiescent = false;
        assert!(!forced_non_quiescent.passed());
        crate::test_complete!("passed_requires_quiescence");
    }

    #[test]
    fn run_with_seed_override() {
        init_test("run_with_seed_override");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::run_with_seed(&scenario, Some(123)).unwrap();
        assert_eq!(result.seed, 123);
        assert!(result.passed());
        crate::test_complete!("run_with_seed_override");
    }

    #[test]
    fn run_with_faults() {
        init_test("run_with_faults");
        let mut scenario = minimal_scenario();
        scenario.faults = vec![
            FaultEvent {
                at_ms: 10,
                action: FaultAction::Partition,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("from".into(), serde_json::json!("alice"));
                    m.insert("to".into(), serde_json::json!("bob"));
                    m
                },
            },
            FaultEvent {
                at_ms: 50,
                action: FaultAction::Heal,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("from".into(), serde_json::json!("alice"));
                    m.insert("to".into(), serde_json::json!("bob"));
                    m
                },
            },
        ];
        let result = ScenarioRunner::run(&scenario).unwrap();
        assert!(result.passed());
        assert_eq!(result.faults_injected, 2);
        crate::test_complete!("run_with_faults");
    }

    #[test]
    fn run_with_all_fault_types() {
        init_test("run_with_all_fault_types");
        let mut scenario = minimal_scenario();
        scenario.participants = vec![
            crate::lab::scenario::Participant {
                name: "alice".to_string(),
                role: "sender".to_string(),
                properties: BTreeMap::new(),
            },
            crate::lab::scenario::Participant {
                name: "bob".to_string(),
                role: "receiver".to_string(),
                properties: BTreeMap::new(),
            },
        ];
        scenario.faults = vec![
            FaultEvent {
                at_ms: 10,
                action: FaultAction::Partition,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("from".into(), serde_json::json!("alice"));
                    m.insert("to".into(), serde_json::json!("bob"));
                    m
                },
            },
            FaultEvent {
                at_ms: 20,
                action: FaultAction::Heal,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("from".into(), serde_json::json!("alice"));
                    m.insert("to".into(), serde_json::json!("bob"));
                    m
                },
            },
            FaultEvent {
                at_ms: 30,
                action: FaultAction::DiskPressure,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("path".into(), serde_json::json!("target/proof"));
                    m.insert("bytes".into(), serde_json::json!(4096));
                    m
                },
            },
            FaultEvent {
                at_ms: 40,
                action: FaultAction::DiskRecovered,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("path".into(), serde_json::json!("target/proof"));
                    m
                },
            },
            FaultEvent {
                at_ms: 50,
                action: FaultAction::DelayedCleanup,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("phase".into(), serde_json::json!("finalizers"));
                    m.insert("delay_ms".into(), serde_json::json!(25));
                    m
                },
            },
            FaultEvent {
                at_ms: 60,
                action: FaultAction::ProcessStall,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("host".into(), serde_json::json!("alice"));
                    m.insert("duration_ms".into(), serde_json::json!(40));
                    m
                },
            },
            FaultEvent {
                at_ms: 70,
                action: FaultAction::ProcessResume,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("host".into(), serde_json::json!("alice"));
                    m
                },
            },
            FaultEvent {
                at_ms: 80,
                action: FaultAction::HostCrash,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("host".into(), serde_json::json!("bob"));
                    m
                },
            },
            FaultEvent {
                at_ms: 90,
                action: FaultAction::HostRestart,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("host".into(), serde_json::json!("bob"));
                    m
                },
            },
            FaultEvent {
                at_ms: 100,
                action: FaultAction::ClockSkew,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("host".into(), serde_json::json!("alice"));
                    m.insert("skew_ms".into(), serde_json::json!(5));
                    m
                },
            },
            FaultEvent {
                at_ms: 110,
                action: FaultAction::ClockReset,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("host".into(), serde_json::json!("alice"));
                    m
                },
            },
        ];
        let result = ScenarioRunner::run(&scenario).unwrap();
        assert!(result.passed());
        assert_eq!(result.faults_injected, 11);
        crate::test_complete!("run_with_all_fault_types");
    }

    #[test]
    fn process_stall_counterexample_keeps_causal_event_under_small_cap() {
        init_test("process_stall_counterexample_keeps_causal_event_under_small_cap");
        let mut scenario = minimal_scenario();
        scenario.participants = vec![crate::lab::scenario::Participant {
            name: "alice".to_string(),
            role: "worker".to_string(),
            properties: BTreeMap::new(),
        }];
        scenario.minimization = MinimizationSection {
            enabled: true,
            max_evaluations: Some(4),
            max_counterexample_events: Some(1),
        };
        scenario.faults = vec![
            FaultEvent {
                at_ms: 10,
                action: FaultAction::DiskPressure,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("path".into(), serde_json::json!("target/proof"));
                    m.insert("bytes".into(), serde_json::json!(4096));
                    m
                },
            },
            FaultEvent {
                at_ms: 20,
                action: FaultAction::DelayedCleanup,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("phase".into(), serde_json::json!("finalizers"));
                    m.insert("delay_ms".into(), serde_json::json!(25));
                    m
                },
            },
            FaultEvent {
                at_ms: 30,
                action: FaultAction::ProcessStall,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("host".into(), serde_json::json!("alice"));
                    m.insert("duration_ms".into(), serde_json::json!(1_000));
                    m
                },
            },
        ];

        let result = ScenarioRunner::run(&scenario).unwrap();
        let counterexample = result
            .minimized_counterexample
            .expect("active process stall should emit a counterexample");

        assert_eq!(counterexample.max_counterexample_events, 1);
        assert_eq!(counterexample.prefix_len, 1);
        assert_eq!(counterexample.fault_log_prefix.len(), 1);
        let retained = &counterexample.fault_log_prefix[0];
        assert_eq!(retained.action, "process_stall");
        assert!(
            retained
                .args_summary
                .split(',')
                .any(|arg| arg == "host=alice"),
            "counterexample must retain the causal stalled host"
        );
        crate::test_complete!("process_stall_counterexample_keeps_causal_event_under_small_cap");
    }

    #[test]
    fn validation_rejects_bad_scenario() {
        init_test("validation_rejects_bad_scenario");
        let mut scenario = minimal_scenario();
        scenario.id = String::new(); // invalid
        let result = ScenarioRunner::run(&scenario);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ScenarioRunnerError::Validation { .. }
        ));
        crate::test_complete!("validation_rejects_bad_scenario");
    }

    #[test]
    fn unknown_oracle_rejected() {
        init_test("unknown_oracle_rejected");
        let mut scenario = minimal_scenario();
        scenario.oracles = vec!["nonexistent_oracle".to_string()];
        let result = ScenarioRunner::run(&scenario);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ScenarioRunnerError::UnknownOracle(_)
        ));
        crate::test_complete!("unknown_oracle_rejected");
    }

    #[test]
    fn oracle_filtering_works() {
        init_test("oracle_filtering_works");
        let mut scenario = minimal_scenario();
        scenario.oracles = vec!["task_leak".to_string(), "obligation_leak".to_string()];
        let result = ScenarioRunner::run(&scenario).unwrap();
        assert_eq!(result.oracle_report.checked.len(), 2);
        assert!(
            result
                .oracle_report
                .checked
                .contains(&"task_leak".to_string())
        );
        assert!(
            result
                .oracle_report
                .checked
                .contains(&"obligation_leak".to_string())
        );
        crate::test_complete!("oracle_filtering_works");
    }

    #[test]
    fn oracle_all_checks_everything() {
        init_test("oracle_all_checks_everything");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::run(&scenario).unwrap();
        // "all" should check every oracle
        assert_eq!(
            result.oracle_report.checked.len(),
            OracleRegistry::reported_names().len()
        );
        crate::test_complete!("oracle_all_checks_everything");
    }

    #[test]
    fn replay_determinism() {
        init_test("replay_determinism");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::validate_replay(&scenario).unwrap();
        assert!(result.passed());
        crate::test_complete!("replay_determinism");
    }

    #[test]
    fn explore_seeds_basic() {
        init_test("explore_seeds_basic");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::explore_seeds(&scenario, 0, 5).unwrap();
        assert_eq!(result.seeds_explored, 5);
        assert_eq!(result.passed, 5);
        assert_eq!(result.failed, 0);
        assert!(result.all_passed());
        assert!(result.unique_fingerprints >= 1);
        crate::test_complete!("explore_seeds_basic");
    }

    #[test]
    fn explore_seeds_reports_each_run() {
        init_test("explore_seeds_reports_each_run");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::explore_seeds(&scenario, 100, 3).unwrap();
        assert_eq!(result.runs.len(), 3);
        assert_eq!(result.runs[0].seed, 100);
        assert_eq!(result.runs[1].seed, 101);
        assert_eq!(result.runs[2].seed, 102);
        crate::test_complete!("explore_seeds_reports_each_run");
    }

    #[test]
    fn result_to_json_roundtrip() {
        init_test("result_to_json_roundtrip");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::run(&scenario).unwrap();
        let json = result.to_json();
        assert_eq!(json["scenario_id"], "test-minimal");
        assert_eq!(json["seed"], 42);
        assert!(json["passed"].as_bool().unwrap());
        assert!(json["certificate"]["event_hash"].is_u64());
        crate::test_complete!("result_to_json_roundtrip");
    }

    #[test]
    fn exploration_to_json() {
        init_test("exploration_to_json");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::explore_seeds(&scenario, 0, 2).unwrap();
        let json = result.to_json();
        assert_eq!(json["seeds_explored"], 2);
        assert!(json["runs"].is_array());
        assert_eq!(json["runs"].as_array().unwrap().len(), 2);
        crate::test_complete!("exploration_to_json");
    }

    #[test]
    fn replay_trace_available_when_enabled() {
        init_test("replay_trace_available_when_enabled");
        let mut scenario = minimal_scenario();
        scenario.lab.replay_recording = true;
        let result = ScenarioRunner::run(&scenario).unwrap();
        // ScenarioRunner always enables replay recording
        assert!(result.replay_trace.is_some());
        crate::test_complete!("replay_trace_available_when_enabled");
    }

    #[test]
    fn certificates_stable_across_runs() {
        init_test("certificates_stable_across_runs");
        let scenario = minimal_scenario();
        let r1 = ScenarioRunner::run(&scenario).unwrap();
        let r2 = ScenarioRunner::run(&scenario).unwrap();
        assert_eq!(r1.certificate, r2.certificate);
        crate::test_complete!("certificates_stable_across_runs");
    }

    #[test]
    fn different_seeds_may_differ() {
        init_test("different_seeds_may_differ");
        let scenario = minimal_scenario();
        let r1 = ScenarioRunner::run_with_seed(&scenario, Some(1)).unwrap();
        let r2 = ScenarioRunner::run_with_seed(&scenario, Some(2)).unwrap();
        // Seeds 1 and 2 should both pass (empty scenario)
        assert!(r1.passed());
        assert!(r2.passed());
        // They may or may not have the same fingerprint (empty scenario probably same)
        crate::test_complete!("different_seeds_may_differ");
    }

    #[test]
    fn chaos_scenario_runs() {
        init_test("chaos_scenario_runs");
        let mut scenario = minimal_scenario();
        scenario.chaos = ChaosSection::Light;
        let result = ScenarioRunner::run(&scenario).unwrap();
        // Light chaos with no tasks should still pass
        assert!(result.passed());
        crate::test_complete!("chaos_scenario_runs");
    }

    #[test]
    fn fault_args_summary_formatting() {
        init_test("fault_args_summary_formatting");
        let mut args = BTreeMap::new();
        args.insert("from".to_string(), serde_json::json!("alice"));
        args.insert("to".to_string(), serde_json::json!("bob"));
        let summary = ScenarioRunner::fault_args_summary(&args);
        assert!(summary.contains("from=alice"));
        assert!(summary.contains("to=bob"));
        crate::test_complete!("fault_args_summary_formatting");
    }

    #[test]
    fn error_display_validation() {
        init_test("error_display_validation");
        let err = ScenarioRunnerError::Validation {
            scenario_id: "invalid-smoke".into(),
            errors: vec![ValidationError {
                field: "id".into(),
                message: "empty".into(),
            }],
        };
        let msg = err.to_string();
        assert!(msg.contains("validation failed"));
        assert!(msg.contains("invalid-smoke"));
        assert!(msg.contains("1 issue(s)"));
        assert!(msg.contains("id"));
        crate::test_complete!("error_display_validation");
    }

    #[test]
    fn error_display_unknown_oracle() {
        init_test("error_display_unknown_oracle");
        let err = ScenarioRunnerError::UnknownOracle("bad_oracle".into());
        assert!(err.to_string().contains("bad_oracle"));
        assert!(err.to_string().contains("valid names:"));
        crate::test_complete!("error_display_unknown_oracle");
    }

    #[test]
    fn error_display_divergence() {
        init_test("error_display_divergence");
        let err = ScenarioRunnerError::ReplayDivergence {
            seed: 42,
            first: TraceCertificateSnapshot {
                event_hash: 1,
                schedule_hash: 2,
                steps: 100,
                trace_fingerprint: 3,
            },
            second: TraceCertificateSnapshot {
                event_hash: 4,
                schedule_hash: 5,
                steps: 100,
                trace_fingerprint: 6,
            },
        };
        let msg = err.to_string();
        assert!(msg.starts_with("[ASUP-E401]"));
        assert!(msg.contains("seed 42"));
        assert!(msg.contains("divergence"));
        crate::test_complete!("error_display_divergence");
    }

    // ── participant workloads (asupersync-39okzv) ────────────────────────

    fn participant(name: &str, role: &str) -> crate::lab::scenario::Participant {
        crate::lab::scenario::Participant {
            name: name.to_string(),
            role: role.to_string(),
            properties: BTreeMap::new(),
        }
    }

    fn participant_with(
        name: &str,
        role: &str,
        key: &str,
        value: serde_json::Value,
    ) -> crate::lab::scenario::Participant {
        let mut participant = participant(name, role);
        participant.properties.insert(key.to_string(), value);
        participant
    }

    /// Two senders and two receivers with default properties: 32 values.
    fn sender_receiver_scenario() -> Scenario {
        let mut scenario = minimal_scenario();
        scenario.id = "test-sender-receiver".to_string();
        scenario.participants = vec![
            participant("alice", "sender"),
            participant("bob", "receiver"),
            participant("carol", "sender"),
            participant("dave", "receiver"),
        ];
        scenario
    }

    fn tasks_with_role(tasks: &[BoundTask], role: WorkloadRole) -> Vec<&BoundTask> {
        tasks.iter().filter(|task| task.role == role).collect()
    }

    fn failure_detail(result: &ScenarioRunResult) -> String {
        let failed_oracles: Vec<_> = result
            .oracle_report
            .entries
            .iter()
            .filter(|entry| !entry.passed)
            .map(|entry| (entry.invariant.clone(), entry.violation.clone()))
            .collect();
        format!(
            "quiescent={} violations={:?} failed_oracles={failed_oracles:?}",
            result.lab_report.quiescent, result.lab_report.invariant_violations
        )
    }

    #[test]
    fn participant_bindings_classify_roles_exactly() {
        init_test("participant_bindings_classify_roles_exactly");
        let mut scenario = minimal_scenario();
        let none = ScenarioRunner::participant_bindings(&scenario);
        assert!(none.is_empty());
        assert_eq!(none.summary_line(), None);

        scenario.participants = vec![
            participant("alice", "sender"),
            participant("bob", "receiver"),
            participant("carol", "Sender"),
            participant("dave", "coordinator"),
            participant("erin", ""),
            participant("frank", "receiver"),
        ];
        let bindings = ScenarioRunner::participant_bindings(&scenario);
        let names = |entries: &[ParticipantBinding]| {
            entries
                .iter()
                .map(|entry| entry.name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&bindings.bound), ["alice", "bob", "frank"]);
        assert_eq!(names(&bindings.unbound), ["carol", "dave", "erin"]);
        assert!(!bindings.implicit_sink);
        assert_eq!(
            bindings.summary_line().as_deref(),
            Some(
                "Participants: 3 bound (sender, receiver), 3 unbound (Sender, coordinator, <none>)"
            )
        );
        assert!(!bindings.implicit_supervisor);
        assert!(!bindings.implicit_coordinator);
        assert_eq!(
            ParticipantBindings::BOUND_ROLES,
            [
                "sender",
                "receiver",
                "swarm",
                "supervisor",
                "worker",
                "saga-coordinator",
                "saga-participant",
                "primary",
                "replica",
                "lease-grantor",
                "lease-holder",
                "hub",
                "peer"
            ]
        );

        scenario.participants = vec![
            participant("producer-a", "sender"),
            participant("producer-b", "sender"),
        ];
        let senders_only = ScenarioRunner::participant_bindings(&scenario);
        assert!(senders_only.implicit_sink);
        assert_eq!(
            senders_only.summary_line().as_deref(),
            Some("Participants: 2 bound (sender), 0 unbound")
        );

        scenario.participants = vec![participant("b", "local-peer")];
        assert_eq!(
            ScenarioRunner::participant_bindings(&scenario)
                .summary_line()
                .as_deref(),
            Some("Participants: 0 bound, 1 unbound (local-peer)")
        );
        crate::test_complete!("participant_bindings_classify_roles_exactly");
    }

    #[test]
    fn unbound_participants_schedule_no_work() {
        init_test("unbound_participants_schedule_no_work");
        let baseline = ScenarioRunner::run(&minimal_scenario()).unwrap();
        let mut scenario = minimal_scenario();
        scenario.participants = vec![
            participant("node-a", "local-peer"),
            participant("node-b", "Receiver"),
        ];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(tasks.is_empty());
        assert_eq!(result.lab_report.steps_total, 0);
        assert_eq!(
            result.certificate, baseline.certificate,
            "unbound participants must leave the empty-lab trace untouched"
        );
        assert!(result.passed());
        crate::test_complete!("unbound_participants_schedule_no_work");
    }

    #[test]
    fn sender_receiver_workload_executes_real_steps() {
        init_test("sender_receiver_workload_executes_real_steps");
        let scenario = sender_receiver_scenario();
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        assert!(result.lab_report.steps_total > 0);
        assert_eq!(
            result.oracle_report.checked.len(),
            OracleRegistry::reported_names().len()
        );
        assert_eq!(result.oracle_report.failed_count, 0);

        let senders = tasks_with_role(&tasks, WorkloadRole::Sender);
        let receivers = tasks_with_role(&tasks, WorkloadRole::Receiver);
        assert_eq!((senders.len(), receivers.len(), tasks.len()), (2, 2, 4));
        let committed: u64 = senders
            .iter()
            .map(|task| count(&task.counters.committed))
            .sum();
        let delivered: u64 = receivers
            .iter()
            .map(|task| count(&task.counters.delivered))
            .sum();
        let received: u64 = receivers
            .iter()
            .map(|task| count(&task.counters.received))
            .sum();
        assert_eq!(committed, 2 * DEFAULT_SENDER_MESSAGES);
        assert_eq!(delivered, committed);
        assert_eq!(received, committed);
        for task in &tasks {
            let summary = task.counter_summary();
            assert!(task.spawn_refusal.is_none(), "{}: {summary}", task.name);
            assert!(
                task.counters.finished.load(Ordering::Relaxed),
                "{}: {summary}",
                task.name
            );
            assert_eq!(
                count(&task.counters.cancelled),
                0,
                "{}: {summary}",
                task.name
            );
            assert_eq!(
                count(&task.counters.unexpected),
                0,
                "{}: {summary}",
                task.name
            );
        }
        for receiver in &receivers {
            assert!(receiver.counters.drained_to_close.load(Ordering::Relaxed));
            // Two senders rotating over two receivers give each one half.
            assert_eq!(count(&receiver.counters.received), DEFAULT_SENDER_MESSAGES);
        }
        crate::test_complete!("sender_receiver_workload_executes_real_steps");
    }

    #[test]
    fn sender_receiver_workload_is_deterministic_and_replays() {
        init_test("sender_receiver_workload_is_deterministic_and_replays");
        let scenario = sender_receiver_scenario();
        let first = ScenarioRunner::run(&scenario).unwrap();
        let second = ScenarioRunner::run(&scenario).unwrap();
        assert_eq!(first.certificate, second.certificate);
        assert!(first.certificate.steps > 0);

        let empty = ScenarioRunner::run(&minimal_scenario()).unwrap();
        assert_ne!(
            first.certificate.event_hash, empty.certificate.event_hash,
            "the bound workload must leave events in the trace"
        );

        let replayed = ScenarioRunner::validate_replay(&scenario).expect("same seed must replay");
        assert_eq!(replayed.certificate, first.certificate);
        assert!(replayed.passed(), "{}", failure_detail(&replayed));

        let identity = ScenarioRunner::scenario_identity(&scenario, None);
        let via_identity = ScenarioRunner::run_with_identity(&scenario, &identity).unwrap();
        assert!(via_identity.certificate.steps > 0);
        assert!(via_identity.passed(), "{}", failure_detail(&via_identity));
        crate::test_complete!("sender_receiver_workload_is_deterministic_and_replays");
    }

    #[test]
    fn senders_without_receivers_drain_into_implicit_sink() {
        init_test("senders_without_receivers_drain_into_implicit_sink");
        let mut scenario = minimal_scenario();
        scenario.participants = vec![
            participant("producer-a", "sender"),
            participant("producer-b", "sender"),
        ];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        let sinks = tasks_with_role(&tasks, WorkloadRole::Sink);
        assert_eq!(sinks.len(), 1);
        let sink = sinks[0];
        assert_eq!(sink.name, IMPLICIT_SINK_NAME);
        assert_eq!(
            count(&sink.counters.received),
            2 * DEFAULT_SENDER_MESSAGES,
            "{}",
            sink.counter_summary()
        );
        assert!(sink.counters.drained_to_close.load(Ordering::Relaxed));
        assert_eq!(count(&sink.counters.out_of_order), 0);
        crate::test_complete!("senders_without_receivers_drain_into_implicit_sink");
    }

    #[test]
    fn receivers_without_senders_see_a_closed_channel() {
        init_test("receivers_without_senders_see_a_closed_channel");
        let mut scenario = minimal_scenario();
        scenario.participants = vec![participant("bob", "receiver")];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        assert!(result.lab_report.steps_total > 0);
        assert_eq!(tasks.len(), 1);
        assert_eq!(count(&tasks[0].counters.received), 0);
        assert!(tasks[0].counters.drained_to_close.load(Ordering::Relaxed));
        crate::test_complete!("receivers_without_senders_see_a_closed_channel");
    }

    #[test]
    fn bound_participant_properties_are_validated() {
        init_test("bound_participant_properties_are_validated");
        let mut scenario = minimal_scenario();
        scenario.participants = vec![
            participant_with("alice", "sender", "messages", serde_json::json!("many")),
            participant_with("bob", "receiver", "capacity", serde_json::json!(0)),
            participant_with(
                "carol",
                "receiver",
                "capacity",
                serde_json::json!(MAX_RECEIVER_CAPACITY + 1),
            ),
            // Unbound roles keep free-form properties.
            participant_with("dave", "coordinator", "capacity", serde_json::json!(0)),
            participant_with(
                "erin",
                "sender",
                "messages",
                serde_json::json!(MAX_SENDER_MESSAGES + 1),
            ),
        ];
        match ScenarioRunner::run(&scenario) {
            Err(ScenarioRunnerError::Validation { errors, .. }) => {
                let fields: Vec<_> = errors.iter().map(|error| error.field.as_str()).collect();
                assert_eq!(
                    fields,
                    [
                        "participants.alice.properties.messages",
                        "participants.bob.properties.capacity",
                        "participants.carol.properties.capacity",
                        "participants.erin.properties.messages",
                    ]
                );
            }
            other => panic!("expected a participant property validation error, got {other:?}"),
        }

        scenario.participants = vec![
            participant_with("alice", "sender", "messages", serde_json::json!(0)),
            participant_with(
                "bob",
                "receiver",
                "capacity",
                serde_json::json!(MAX_RECEIVER_CAPACITY),
            ),
        ];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        assert_eq!(count(&tasks[0].counters.committed), 0);
        assert!(tasks[1].counters.drained_to_close.load(Ordering::Relaxed));
        crate::test_complete!("bound_participant_properties_are_validated");
    }

    /// The command-line JSON says whether anything ran and what was bound.
    #[test]
    fn json_with_bindings_reports_whether_a_workload_ran() {
        init_test("json_with_bindings_reports_whether_a_workload_ran");
        let empty = minimal_scenario();
        let result = ScenarioRunner::run(&empty).unwrap();
        let json = result.to_json_with_bindings(&ScenarioRunner::participant_bindings(&empty));
        assert_eq!(json["workload_ran"], false);
        assert!(json.get("participant_bindings").is_none(), "{json}");
        assert_eq!(json["scenario_id"], result.to_json()["scenario_id"]);

        let bound = sender_receiver_scenario();
        let result = ScenarioRunner::run(&bound).unwrap();
        let json = result.to_json_with_bindings(&ScenarioRunner::participant_bindings(&bound));
        assert_eq!(json["workload_ran"], true);
        assert_eq!(json["participant_bindings"]["bound"][0]["name"], "alice");
        assert_eq!(json["participant_bindings"]["bound"][1]["role"], "receiver");
        crate::test_complete!("json_with_bindings_reports_whether_a_workload_ran");
    }

    /// Deliberate-failure control target (see the 39okzv notes): if the sender
    /// forgets its permit instead of sending it, this test must fail on the
    /// `obligation_leak` oracle.
    #[test]
    fn two_phase_permits_are_obligations_the_leak_oracle_sees() {
        init_test("two_phase_permits_are_obligations_the_leak_oracle_sees");
        let mut scenario = minimal_scenario();
        scenario.id = "test-permit-obligations".to_string();
        // A leak must surface as an oracle verdict, not as a runtime panic.
        scenario.lab.panic_on_obligation_leak = false;
        scenario.oracles = vec!["obligation_leak".to_string()];
        // messages <= capacity: the sender never waits, even if permits leak.
        scenario.participants = vec![
            participant_with("alice", "sender", "messages", serde_json::json!(4)),
            participant_with("bob", "receiver", "capacity", serde_json::json!(4)),
        ];

        let plan = WorkloadPlan::from_scenario(&scenario).expect("valid plan");
        let mut runtime = LabRuntime::new(ScenarioRunner::lab_config_for(&scenario, None));
        let workload = ParticipantWorkload::spawn(&mut runtime, &plan, &scenario.network);
        runtime.run_until_quiescent();

        let report = runtime.report();
        let entry = report
            .oracle_report
            .entry("obligation_leak")
            .expect("obligation leak oracle is registered");
        assert!(
            entry.passed,
            "every reserved permit must be committed: {entry:?}"
        );
        assert_eq!(runtime.state.leak_count(), 0);
        let stats = runtime
            .state
            .obligation_gateway()
            .expect("the lab installs an obligation gateway")
            .mailbox()
            .stats();
        assert_eq!(stats.reserved, 4, "four permits were reserved: {stats:?}");
        assert_eq!(stats.committed, 4, "four permits were sent: {stats:?}");
        assert_eq!(stats.leaked, 0, "{stats:?}");
        assert_eq!(runtime.state.pending_obligation_count(), 0);

        let mut violations = Vec::new();
        let tasks = workload.finish(&mut violations);
        assert!(violations.is_empty(), "{violations:?}");
        assert_eq!(count(&tasks[1].counters.received), 4);

        let result = ScenarioRunner::run(&scenario).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        crate::test_complete!("two_phase_permits_are_obligations_the_leak_oracle_sees");
    }

    #[test]
    fn cancellation_mid_protocol_still_resolves_every_obligation() {
        init_test("cancellation_mid_protocol_still_resolves_every_obligation");
        let mut scenario = minimal_scenario();
        scenario.id = "test-cancel-mid-protocol".to_string();
        scenario.chaos = ChaosSection::Custom {
            cancel_probability: 0.1,
            delay_probability: 0.0,
            delay_min_ms: 0,
            delay_max_ms: 10,
            io_error_probability: 0.0,
            wakeup_storm_probability: 0.0,
            budget_exhaustion_probability: 0.0,
        };
        scenario.participants = vec![
            participant_with("alice", "sender", "messages", serde_json::json!(24)),
            participant_with("bob", "receiver", "capacity", serde_json::json!(2)),
            participant_with("carol", "receiver", "capacity", serde_json::json!(2)),
        ];

        let mut cancelled = 0_u64;
        let mut cancelled_holding = 0_u64;
        for seed in 0..8 {
            let (result, tasks) = ScenarioRunner::run_seeded(&scenario, Some(seed)).unwrap();
            assert!(result.passed(), "seed {seed}: {}", failure_detail(&result));
            let sender = &tasks[0];
            let c = &sender.counters;
            cancelled_holding += count(&c.cancelled_holding);
            let committed = count(&c.committed);
            assert!(
                committed + count(&c.cancelled) + count(&c.disconnected) <= sender.planned,
                "seed {seed}: {}",
                sender.counter_summary()
            );
            let receivers = tasks_with_role(&tasks, WorkloadRole::Receiver);
            let delivered: u64 = receivers
                .iter()
                .map(|task| count(&task.counters.delivered))
                .sum();
            let received: u64 = receivers
                .iter()
                .map(|task| count(&task.counters.received))
                .sum();
            assert_eq!(delivered, committed, "seed {seed}");
            assert!(received <= delivered, "seed {seed}");
            cancelled += tasks
                .iter()
                .map(|task| count(&task.counters.cancelled))
                .sum::<u64>();
        }
        assert!(
            cancelled > 0,
            "a 10% per-dispatch cancel rate must cancel some reserve or receive across eight seeds"
        );
        // The sender yields while it holds each permit, so some cancellations
        // land on a live obligation, and every run above still passed the
        // obligation-leak oracle. The sender aborts such a permit, but a run
        // whose cancelled sender forgets it instead reports no leak either:
        // this check proves that cancellation reaches a held permit, not the
        // abort.
        assert!(
            cancelled_holding > 0,
            "some cancellation must arrive while a permit is held"
        );
        crate::test_complete!("cancellation_mid_protocol_still_resolves_every_obligation");
    }

    // ── swarm, supervisor and worker workloads (asupersync-y1dzts) ───────

    fn swarm_scenario(members: usize) -> Scenario {
        let mut scenario = minimal_scenario();
        scenario.id = "test-swarm".to_string();
        // Each member leaves a spawn and a completion event in the trace; a
        // truncated trace fails the run.
        scenario.lab.trace_capacity = 16_384;
        scenario.participants = vec![participant_with(
            "swarm",
            "swarm",
            "tasks",
            serde_json::json!(members),
        )];
        scenario
    }

    /// The tally of the run's swarm and the value of its shared counter.
    fn swarm_tally_of(tasks: &[BoundTask]) -> (SwarmTally, u64) {
        let (task, members) = tasks
            .iter()
            .find_map(|task| match &task.detail {
                BoundDetail::Swarm(members) => Some((task, members)),
                _ => None,
            })
            .expect("a swarm task record");
        (task.swarm_tally(members), count(&members.touches))
    }

    fn supervisor_state<'a>(tasks: &'a [BoundTask], name: &str) -> &'a SupervisorState {
        tasks
            .iter()
            .find_map(|task| match &task.detail {
                BoundDetail::Supervisor(state) if task.name == name => Some(Arc::as_ref(state)),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no supervisor record named {name}"))
    }

    fn supervisor_summary(tasks: &[BoundTask], name: &str) -> SupervisorSummary {
        supervisor_state(tasks, name)
            .summary
            .lock()
            .clone()
            .unwrap_or_else(|| panic!("supervisor {name} returned no report"))
    }

    fn worker_names(state: &SupervisorState) -> Vec<&str> {
        state
            .workers
            .iter()
            .map(|worker| worker.name.as_str())
            .collect()
    }

    /// One supervisor and three workers that fail 3, 0 and 1 (default) times.
    fn supervisor_scenario() -> Scenario {
        let mut scenario = minimal_scenario();
        scenario.id = "test-supervisor-worker".to_string();
        scenario.participants = vec![
            participant("sup", "supervisor"),
            participant_with("flaky", "worker", "fail_times", serde_json::json!(3)),
            participant_with("steady", "worker", "fail_times", serde_json::json!(0)),
            participant("plain", "worker"),
        ];
        scenario
    }

    #[test]
    fn swarm_spawns_every_member_and_every_member_completes() {
        init_test("swarm_spawns_every_member_and_every_member_completes");
        let members = 500_usize;
        let expected = members as u64;
        let scenario = swarm_scenario(members);
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        assert!(
            result.lab_report.steps_total >= expected,
            "{} steps for {members} members",
            result.lab_report.steps_total
        );

        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].role, WorkloadRole::Swarm);
        assert_eq!(tasks[0].planned, expected);
        assert!(tasks[0].spawn_refusal.is_none());
        let (tally, touches) = swarm_tally_of(&tasks);
        assert_eq!(
            tally,
            SwarmTally {
                spawned: expected,
                completed: expected,
                ..SwarmTally::default()
            }
        );
        // Every member ran every step: once per yield and once to finish.
        assert_eq!(touches, expected * (SWARM_MEMBER_YIELDS as u64 + 1));

        let second = ScenarioRunner::run(&scenario).unwrap();
        assert_eq!(second.certificate, result.certificate);
        let replayed = ScenarioRunner::validate_replay(&scenario).expect("same seed must replay");
        assert_eq!(replayed.certificate, result.certificate);
        let empty = ScenarioRunner::run(&minimal_scenario()).unwrap();
        assert_ne!(
            result.certificate.event_hash, empty.certificate.event_hash,
            "the swarm must leave events in the trace"
        );
        crate::test_complete!("swarm_spawns_every_member_and_every_member_completes");
    }

    #[test]
    fn swarm_members_stopped_by_chaos_are_counted_not_failed() {
        init_test("swarm_members_stopped_by_chaos_are_counted_not_failed");
        let members = 200_u64;
        let mut scenario = swarm_scenario(200);
        scenario.id = "test-swarm-chaos".to_string();
        scenario.chaos = ChaosSection::Custom {
            cancel_probability: 0.05,
            delay_probability: 0.1,
            delay_min_ms: 0,
            delay_max_ms: 50,
            io_error_probability: 0.0,
            wakeup_storm_probability: 0.01,
            budget_exhaustion_probability: 0.01,
        };

        let mut cancelled = 0_u64;
        for seed in 0..4 {
            let (result, tasks) = ScenarioRunner::run_seeded(&scenario, Some(seed)).unwrap();
            assert!(result.passed(), "seed {seed}: {}", failure_detail(&result));
            let (tally, _) = swarm_tally_of(&tasks);
            assert_eq!(tally.spawned, members, "seed {seed}: {tally:?}");
            assert_eq!(
                tally.completed + tally.cancelled,
                members,
                "seed {seed}: {tally:?}"
            );
            cancelled += tally.cancelled;
        }
        assert!(
            cancelled > 0,
            "5% cancellation and 1% budget exhaustion per dispatch must stop some member across four seeds"
        );
        crate::test_complete!("swarm_members_stopped_by_chaos_are_counted_not_failed");
    }

    /// Deliberate-failure control target (see the y1dzts notes): if workers
    /// are bound as `ManagedRestartMode::Temporary`, the supervisor never
    /// restarts them and this test must fail.
    #[test]
    fn supervisor_restarts_each_worker_exactly_fail_times() {
        init_test("supervisor_restarts_each_worker_exactly_fail_times");
        let scenario = supervisor_scenario();
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        assert!(result.lab_report.steps_total > 0);

        let sup = tasks
            .iter()
            .find(|task| task.name == "sup")
            .expect("supervisor record");
        assert_eq!(sup.role, WorkloadRole::Supervisor);
        // The default restart budget is the workers' total failure count.
        assert_eq!(sup.planned, 3 + DEFAULT_WORKER_FAIL_TIMES);
        assert_eq!(sup.joins, [JoinState::Completed]);
        let state = supervisor_state(&tasks, "sup");
        assert_eq!(worker_names(state), ["flaky", "steady", "plain"]);

        let summary = supervisor_summary(&tasks, "sup");
        assert_eq!(summary.exit, ControllerExit::Completed);
        assert_eq!(summary.restart_batches, 3 + DEFAULT_WORKER_FAIL_TIMES);
        for (name, fail_times) in [
            ("flaky", 3),
            ("steady", 0),
            ("plain", DEFAULT_WORKER_FAIL_TIMES),
        ] {
            let child = summary
                .children
                .iter()
                .find(|child| child.name == name)
                .unwrap_or_else(|| panic!("no report for {name}: {summary:?}"));
            assert_eq!(child.exit, ChildExit::Succeeded, "{name}: {child:?}");
            assert_eq!(child.generations, fail_times + 1, "{name}: {child:?}");

            let worker = state
                .workers
                .iter()
                .find(|worker| worker.name == name)
                .expect("assigned worker");
            assert_eq!(count(&worker.state.attempts), fail_times + 1, "{name}");
            assert_eq!(count(&worker.state.failures), fail_times, "{name}");
            assert_eq!(count(&worker.state.cancelled), 0, "{name}");
            assert_eq!(count(&worker.state.unexpected), 0, "{name}");

            let record = tasks
                .iter()
                .find(|task| task.name == name)
                .expect("worker record");
            assert_eq!(record.role, WorkloadRole::Worker);
            assert_eq!(record.planned, fail_times);
        }

        let second = ScenarioRunner::run(&scenario).unwrap();
        assert_eq!(second.certificate, result.certificate);
        let replayed = ScenarioRunner::validate_replay(&scenario).expect("same seed must replay");
        assert_eq!(replayed.certificate, result.certificate);
        assert!(replayed.passed(), "{}", failure_detail(&replayed));
        let identity = ScenarioRunner::scenario_identity(&scenario, None);
        let via_identity = ScenarioRunner::run_with_identity(&scenario, &identity).unwrap();
        assert!(via_identity.certificate.steps > 0);
        assert!(via_identity.passed(), "{}", failure_detail(&via_identity));
        crate::test_complete!("supervisor_restarts_each_worker_exactly_fail_times");
    }

    #[test]
    fn exhausted_restart_budget_is_a_workload_violation() {
        init_test("exhausted_restart_budget_is_a_workload_violation");
        let mut scenario = minimal_scenario();
        scenario.id = "test-restart-budget".to_string();
        scenario.participants = vec![
            participant_with("sup", "supervisor", "max_restarts", serde_json::json!(1)),
            participant_with("flaky", "worker", "fail_times", serde_json::json!(3)),
        ];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(!result.passed());
        let violations = &result.lab_report.invariant_violations;
        let workload: Vec<&String> = violations
            .iter()
            .filter(|violation| violation.starts_with("workload:"))
            .collect();
        assert_eq!(workload.len(), 1, "{violations:?}");
        assert!(
            workload[0].starts_with("workload:worker:flaky:never_succeeded:"),
            "{violations:?}"
        );

        // The budget admitted one restart; the second failure stopped the
        // worker without escalating.
        assert_eq!(tasks[0].planned, 1);
        let summary = supervisor_summary(&tasks, "sup");
        assert_eq!(summary.exit, ControllerExit::Completed);
        assert_eq!(summary.restart_batches, 1);
        assert_eq!(summary.children.len(), 1);
        assert_eq!(summary.children[0].generations, 2);
        assert_eq!(summary.children[0].exit, ChildExit::Failed(2));
        crate::test_complete!("exhausted_restart_budget_is_a_workload_violation");
    }

    #[test]
    fn workers_go_round_robin_to_supervisors_and_orphans_get_an_implicit_one() {
        init_test("workers_go_round_robin_to_supervisors_and_orphans_get_an_implicit_one");
        let mut scenario = minimal_scenario();
        scenario.id = "test-supervision-topology".to_string();
        scenario.participants = vec![
            participant("w1", "worker"),
            participant("s1", "supervisor"),
            participant("w2", "worker"),
            participant("s2", "supervisor"),
            participant("w3", "worker"),
        ];
        let bindings = ScenarioRunner::participant_bindings(&scenario);
        assert!(!bindings.implicit_supervisor);
        assert_eq!(
            bindings.summary_line().as_deref(),
            Some("Participants: 5 bound (worker, supervisor), 0 unbound")
        );
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        assert_eq!(worker_names(supervisor_state(&tasks, "s1")), ["w1", "w3"]);
        assert_eq!(worker_names(supervisor_state(&tasks, "s2")), ["w2"]);
        assert_eq!(supervisor_summary(&tasks, "s1").restart_batches, 2);
        assert_eq!(supervisor_summary(&tasks, "s2").restart_batches, 1);

        scenario.participants = vec![participant("w1", "worker"), participant("w2", "worker")];
        let bindings = ScenarioRunner::participant_bindings(&scenario);
        assert!(bindings.implicit_supervisor);
        assert!(!bindings.implicit_sink);
        assert_eq!(
            bindings.summary_line().as_deref(),
            Some("Participants: 2 bound (worker), 0 unbound")
        );
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        let implicit = tasks
            .iter()
            .find(|task| task.name == IMPLICIT_SUPERVISOR_NAME)
            .expect("implicit supervisor record");
        assert_eq!(implicit.role, WorkloadRole::Supervisor);
        assert_eq!(
            worker_names(supervisor_state(&tasks, IMPLICIT_SUPERVISOR_NAME)),
            ["w1", "w2"]
        );
        let summary = supervisor_summary(&tasks, IMPLICIT_SUPERVISOR_NAME);
        assert_eq!(summary.restart_batches, 2);
        assert!(
            summary
                .children
                .iter()
                .all(|child| child.exit == ChildExit::Succeeded),
            "{summary:?}"
        );

        // A supervisor without workers still runs its controller.
        scenario.participants = vec![participant("s1", "supervisor")];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        assert!(result.lab_report.steps_total > 0);
        assert_eq!(tasks[0].planned, 0);
        let summary = supervisor_summary(&tasks, "s1");
        assert_eq!(summary.exit, ControllerExit::Completed);
        assert!(summary.children.is_empty());
        crate::test_complete!(
            "workers_go_round_robin_to_supervisors_and_orphans_get_an_implicit_one"
        );
    }

    #[test]
    fn swarm_supervisor_and_worker_properties_are_validated() {
        init_test("swarm_supervisor_and_worker_properties_are_validated");
        let mut scenario = minimal_scenario();
        scenario.participants = vec![
            participant_with("a", "swarm", "tasks", serde_json::json!(0)),
            participant_with(
                "b",
                "swarm",
                "tasks",
                serde_json::json!(MAX_SWARM_TASKS + 1),
            ),
            participant_with("c", "swarm", "tasks", serde_json::json!("many")),
            participant_with("d", "supervisor", "max_restarts", serde_json::json!(-1)),
            participant_with(
                "e",
                "supervisor",
                "max_restarts",
                serde_json::json!(u64::from(u32::MAX) + 1),
            ),
            participant_with(
                "f",
                "worker",
                "fail_times",
                serde_json::json!(MAX_WORKER_FAIL_TIMES + 1),
            ),
            participant_with("g", "worker", "fail_times", serde_json::json!(1.5)),
            // Unbound roles keep free-form properties.
            participant_with("h", "Worker", "fail_times", serde_json::json!(-1)),
        ];
        match ScenarioRunner::run(&scenario) {
            Err(ScenarioRunnerError::Validation { errors, .. }) => {
                let fields: Vec<_> = errors.iter().map(|error| error.field.as_str()).collect();
                assert_eq!(
                    fields,
                    [
                        "participants.a.properties.tasks",
                        "participants.b.properties.tasks",
                        "participants.c.properties.tasks",
                        "participants.d.properties.max_restarts",
                        "participants.e.properties.max_restarts",
                        "participants.f.properties.fail_times",
                        "participants.g.properties.fail_times",
                    ]
                );
            }
            other => panic!("expected a participant property validation error, got {other:?}"),
        }

        // The default task count and zero restarts and failures run.
        scenario.participants = vec![
            participant("swarm", "swarm"),
            participant_with("sup", "supervisor", "max_restarts", serde_json::json!(0)),
            participant_with("steady", "worker", "fail_times", serde_json::json!(0)),
        ];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        let (tally, _) = swarm_tally_of(&tasks);
        assert_eq!(tally.completed, DEFAULT_SWARM_TASKS as u64, "{tally:?}");
        let summary = supervisor_summary(&tasks, "sup");
        assert_eq!(summary.restart_batches, 0);
        assert_eq!(summary.children[0].generations, 1);
        assert_eq!(summary.children[0].exit, ChildExit::Succeeded);
        crate::test_complete!("swarm_supervisor_and_worker_properties_are_validated");
    }

    #[test]
    fn supervised_workers_stopped_by_chaos_are_counted_not_failed() {
        init_test("supervised_workers_stopped_by_chaos_are_counted_not_failed");
        let mut scenario = supervisor_scenario();
        scenario.id = "test-supervisor-chaos".to_string();
        scenario.chaos = ChaosSection::Custom {
            cancel_probability: 0.1,
            delay_probability: 0.0,
            delay_min_ms: 0,
            delay_max_ms: 10,
            io_error_probability: 0.0,
            wakeup_storm_probability: 0.0,
            budget_exhaustion_probability: 0.0,
        };

        let mut stopped = 0_u64;
        for seed in 0..8 {
            let (result, tasks) = ScenarioRunner::run_seeded(&scenario, Some(seed)).unwrap();
            assert!(result.passed(), "seed {seed}: {}", failure_detail(&result));
            let state = supervisor_state(&tasks, "sup");
            let summary = state.summary.lock().clone();
            for worker in &state.workers {
                let child = summary.as_ref().and_then(|summary| {
                    summary
                        .children
                        .iter()
                        .find(|child| child.name == worker.name)
                });
                match child {
                    Some(child) if child.exit == ChildExit::Succeeded => assert_eq!(
                        child.generations,
                        worker.fail_times + 1,
                        "seed {seed}: {}: {child:?}",
                        worker.name
                    ),
                    _ => stopped += 1,
                }
            }
        }
        assert!(
            stopped > 0,
            "a 10% per-dispatch cancel rate must stop some worker across eight seeds"
        );
        crate::test_complete!("supervised_workers_stopped_by_chaos_are_counted_not_failed");
    }

    fn lifecycle_scenario() -> Scenario {
        let mut scenario = minimal_scenario();
        scenario.id = "test-worker-lifecycle".to_owned();
        let mut worker = participant_with("worker", "worker", "fail_times", serde_json::json!(0));
        worker.properties.insert("lifecycle".to_owned(), serde_json::json!({"work_ms": 500}));
        scenario.participants = vec![participant("sup", "supervisor"), worker];
        scenario
    }

    fn lifecycle_fault(at_ms: u64, action: FaultAction, host: &str) -> FaultEvent {
        let mut args = BTreeMap::from([("host".to_owned(), serde_json::json!(host))]);
        if action == FaultAction::ProcessStall {
            args.insert("duration_ms".to_owned(), serde_json::json!(200));
        }
        FaultEvent { at_ms, action, args }
    }

    #[test]
    fn lifecycle_crash_replaces_the_actual_worker_and_replay_repeats_its_work() {
        init_test("lifecycle_crash_replaces_the_actual_worker_and_replay_repeats_its_work");
        let mut scenario = lifecycle_scenario();
        scenario.faults = vec![
            lifecycle_fault(150, FaultAction::HostCrash, "worker"),
            lifecycle_fault(400, FaultAction::HostRestart, "worker"),
        ];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        assert!(result.lab_report.quiescent);
        assert_eq!(result.lab_report.now_nanos, 900_000_000);
        let summary = supervisor_summary(&tasks, "sup");
        assert_eq!(summary.restart_batches, 1);
        assert_eq!(summary.children[0].generations, 2);
        assert_eq!(summary.children[0].exit, ChildExit::Succeeded);
        let worker = &supervisor_state(&tasks, "sup").workers[0];
        assert_eq!(count(&worker.state.attempts), 2);
        assert_eq!(count(&worker.state.crashes), 1);
        assert_eq!(count(&worker.state.failures), 1);
        assert_eq!(count(&worker.state.cancelled), 0);

        // Legacy control: the same faults remain records when the worker has
        // not opted in. It finishes once, before either timed fault.
        let mut legacy = scenario.clone();
        legacy.participants[1].properties.remove("lifecycle");
        let (legacy_result, legacy_tasks) = ScenarioRunner::run_seeded(&legacy, None).unwrap();
        assert!(legacy_result.passed());
        assert_eq!(legacy_result.lab_report.now_nanos, 400_000_000);
        assert_eq!(supervisor_summary(&legacy_tasks, "sup").children[0].generations, 1);
        assert_ne!(result.certificate.event_hash, legacy_result.certificate.event_hash);

        let replay = ScenarioRunner::validate_replay(&scenario).unwrap();
        assert!(replay.passed());
        assert_eq!(replay.certificate, result.certificate);
        let identity = ScenarioRunner::scenario_identity(&scenario, None);
        let identified = ScenarioRunner::run_with_identity(&scenario, &identity).unwrap();
        assert!(identified.passed());
        assert_eq!(identified.lab_report.now_nanos, 900_000_000);
        assert!(ScenarioRunner::explore_seeds(&scenario, 1, 3).unwrap().all_passed());
        crate::test_complete!("lifecycle_crash_replaces_the_actual_worker_and_replay_repeats_its_work");
    }

    #[test]
    fn lifecycle_stalls_pause_active_work_and_resume_by_timer_or_explicit_fault() {
        init_test("lifecycle_stalls_pause_active_work_and_resume_by_timer_or_explicit_fault");
        for (resume, expected_ms) in [(None, 700), (Some(150), 550), (Some(400), 700)] {
            let mut scenario = lifecycle_scenario();
            scenario.faults.push(lifecycle_fault(100, FaultAction::ProcessStall, "worker"));
            if let Some(at) = resume {
                scenario.faults.push(lifecycle_fault(at, FaultAction::ProcessResume, "worker"));
            }
            let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
            assert!(result.passed(), "resume={resume:?}: {}", failure_detail(&result));
            assert_eq!(result.lab_report.now_nanos, expected_ms * 1_000_000);
            let summary = supervisor_summary(&tasks, "sup");
            assert_eq!(summary.children[0].generations, 1);
            assert_eq!(summary.restart_batches, 0);
            assert_eq!(count(&supervisor_state(&tasks, "sup").workers[0].state.crashes), 0);
        }
        crate::test_complete!("lifecycle_stalls_pause_active_work_and_resume_by_timer_or_explicit_fault");
    }

    #[test]
    fn lifecycle_fault_at_the_completion_instant_precedes_the_due_timer() {
        init_test("lifecycle_fault_at_the_completion_instant_precedes_the_due_timer");
        for action in [FaultAction::HostCrash, FaultAction::ProcessStall] {
            let mut scenario = lifecycle_scenario();
            scenario.faults.push(lifecycle_fault(500, action.clone(), "worker"));
            let expected_ms = if action == FaultAction::HostCrash {
                scenario.faults.push(lifecycle_fault(700, FaultAction::HostRestart, "worker"));
                1200
            } else {
                700
            };
            let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
            assert!(result.passed(), "{action:?}: {}", failure_detail(&result));
            assert_eq!(result.lab_report.now_nanos, expected_ms * 1_000_000);
            assert_eq!(supervisor_summary(&tasks, "sup").children[0].generations,
                if action == FaultAction::HostCrash { 2 } else { 1 });
        }
        crate::test_complete!("lifecycle_fault_at_the_completion_instant_precedes_the_due_timer");
    }

    #[test]
    fn lifecycle_repeated_crash_while_down_is_one_failure_and_each_recovery_resets_work() {
        init_test("lifecycle_repeated_crash_while_down_is_one_failure_and_each_recovery_resets_work");
        let mut scenario = lifecycle_scenario();
        scenario.faults = vec![
            lifecycle_fault(150, FaultAction::HostCrash, "worker"),
            lifecycle_fault(200, FaultAction::HostCrash, "worker"),
            lifecycle_fault(300, FaultAction::HostRestart, "worker"),
            lifecycle_fault(500, FaultAction::HostCrash, "worker"),
            lifecycle_fault(600, FaultAction::HostRestart, "worker"),
        ];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        assert_eq!(result.lab_report.now_nanos, 1_100_000_000);
        let summary = supervisor_summary(&tasks, "sup");
        assert_eq!(summary.restart_batches, 2);
        assert_eq!(summary.children[0].generations, 3);
        assert_eq!(count(&supervisor_state(&tasks, "sup").workers[0].state.crashes), 2);
        crate::test_complete!("lifecycle_repeated_crash_while_down_is_one_failure_and_each_recovery_resets_work");
    }

    #[test]
    fn lifecycle_crashes_do_not_consume_the_workers_configured_failures() {
        init_test("lifecycle_crashes_do_not_consume_the_workers_configured_failures");
        let mut scenario = lifecycle_scenario();
        scenario.participants[1].properties.insert("fail_times".to_owned(), serde_json::json!(2));
        scenario.faults = vec![
            lifecycle_fault(150, FaultAction::HostCrash, "worker"),
            lifecycle_fault(400, FaultAction::HostRestart, "worker"),
        ];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        assert_eq!(result.lab_report.now_nanos, 1_900_000_000);
        let summary = supervisor_summary(&tasks, "sup");
        assert_eq!(summary.restart_batches, 3);
        assert_eq!(summary.children[0].generations, 4);
        let worker = &supervisor_state(&tasks, "sup").workers[0];
        assert_eq!(count(&worker.state.failures), 3);
        assert_eq!(count(&worker.state.crashes), 1);
        crate::test_complete!("lifecycle_crashes_do_not_consume_the_workers_configured_failures");
    }

    #[test]
    fn lifecycle_crashes_do_not_override_an_explicit_restart_budget() {
        init_test("lifecycle_crashes_do_not_override_an_explicit_restart_budget");
        let mut scenario = lifecycle_scenario();
        scenario.participants[0].properties.insert("max_restarts".to_owned(), serde_json::json!(0));
        scenario.faults = vec![
            lifecycle_fault(150, FaultAction::HostCrash, "worker"),
            lifecycle_fault(400, FaultAction::HostRestart, "worker"),
        ];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(!result.passed());
        assert!(result.lab_report.quiescent);
        assert_eq!(result.lab_report.now_nanos, 400_000_000);
        assert_eq!(tasks[0].planned, 0);
        let summary = supervisor_summary(&tasks, "sup");
        assert_eq!(summary.restart_batches, 0);
        assert_eq!(summary.children[0].generations, 1);
        assert_eq!(summary.children[0].exit, ChildExit::Failed(1));
        assert!(result.lab_report.invariant_violations.iter().any(|v|
            v.starts_with("workload:worker:worker:never_succeeded:")));
        crate::test_complete!("lifecycle_crashes_do_not_override_an_explicit_restart_budget");
    }

    #[test]
    fn lifecycle_missing_restart_returns_an_incomplete_run_without_spinning() {
        init_test("lifecycle_missing_restart_returns_an_incomplete_run_without_spinning");
        let mut scenario = lifecycle_scenario();
        scenario.faults = vec![lifecycle_fault(150, FaultAction::HostCrash, "worker")];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(!result.passed());
        assert!(!result.lab_report.quiescent);
        assert_eq!(result.lab_report.now_nanos, 150_000_000);
        assert!(result.lab_report.steps_total < 10_000);
        let worker = &supervisor_state(&tasks, "sup").workers[0];
        assert_eq!(count(&worker.state.attempts), 2);
        assert_eq!(count(&worker.state.crashes), 1);
        assert!(result.lab_report.invariant_violations.iter().any(|v|
            v.starts_with("workload:supervisor:sup:no_report:")));
        crate::test_complete!("lifecycle_missing_restart_returns_an_incomplete_run_without_spinning");
    }

    #[test]
    fn lifecycle_offline_and_stalled_workers_are_still_cancellable_and_drained() {
        init_test("lifecycle_offline_and_stalled_workers_are_still_cancellable_and_drained");
        for action in [FaultAction::HostCrash, FaultAction::ProcessStall] {
            let mut scenario = lifecycle_scenario();
            scenario.faults = vec![lifecycle_fault(100, action.clone(), "worker")];
            let plan = ScenarioRunner::workload_plan(&scenario).unwrap();
            let mut runtime = LabRuntime::new(ScenarioRunner::lab_config_for(&scenario, None));
            let workload = ParticipantWorkload::spawn(&mut runtime, &plan, &scenario.network);
            ScenarioRunner::inject_faults(&mut runtime, &scenario, &workload);
            runtime.run_until_idle();
            let state = supervisor_state(&workload.tasks, "sup");
            let worker = &state.workers[0];
            assert_eq!(count(&worker.state.attempts), if action == FaultAction::HostCrash { 2 } else { 1 });
            assert!(state.summary.lock().is_none(), "controller is parked on its child");
            assert!(!runtime.is_quiescent());

            workload.handles[0].1.abort();
            runtime.run_until_idle();
            assert!(runtime.is_quiescent(), "{action:?}: cancellation must drain the child");
            assert_eq!(runtime.now(), Time::from_millis(100));
            assert_eq!(runtime.state.timer_driver_handle().unwrap().pending_count(), 0);
            let mut violations = Vec::new();
            let tasks = workload.finish(&mut violations);
            assert!(violations.is_empty(), "{action:?}: {violations:?}");
            assert_eq!(count(&supervisor_state(&tasks, "sup").workers[0].state.cancelled), 1);
        }
        crate::test_complete!("lifecycle_offline_and_stalled_workers_are_still_cancellable_and_drained");
    }

    #[test]
    fn lifecycle_shared_host_crashes_each_bound_worker_but_leaves_other_hosts_running() {
        init_test("lifecycle_shared_host_crashes_each_bound_worker_but_leaves_other_hosts_running");
        let mut scenario = lifecycle_scenario();
        scenario.participants[1].properties.insert("lifecycle".to_owned(), serde_json::json!({"work_ms": 500, "host": "sup"}));
        let mut second = scenario.participants[1].clone();
        second.name = "second".to_owned();
        let mut independent = scenario.participants[1].clone();
        independent.name = "independent".to_owned();
        independent.properties.insert("lifecycle".to_owned(), serde_json::json!({"work_ms": 500}));
        scenario.participants.extend([second, independent]);
        scenario.faults = vec![
            lifecycle_fault(150, FaultAction::HostCrash, "sup"),
            lifecycle_fault(400, FaultAction::HostRestart, "sup"),
        ];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        assert_eq!(result.lab_report.now_nanos, 900_000_000);
        let state = supervisor_state(&tasks, "sup");
        assert_eq!(state.workers.iter().map(|w| count(&w.state.crashes)).collect::<Vec<_>>(), [1, 1, 0]);
        let summary = supervisor_summary(&tasks, "sup");
        assert_eq!(summary.restart_batches, 2);
        assert_eq!(summary.children.iter().map(|c| c.generations).collect::<Vec<_>>(), [2, 2, 1]);
        crate::test_complete!("lifecycle_shared_host_crashes_each_bound_worker_but_leaves_other_hosts_running");
    }

    #[test]
    fn lifecycle_plan_refuses_malformed_or_unbounded_properties_before_running() {
        init_test("lifecycle_plan_refuses_malformed_or_unbounded_properties_before_running");
        for value in [
            serde_json::json!(true), serde_json::json!({}),
            serde_json::json!({"work_ms": 0}), serde_json::json!({"work_ms": 60_001}),
            serde_json::json!({"work_ms": 1.5}), serde_json::json!({"work_ms": 1, "host": "missing"}),
            serde_json::json!({"work_ms": 1, "typo": true}),
        ] {
            let mut scenario = lifecycle_scenario();
            scenario.participants[1].properties.insert("lifecycle".to_owned(), value.clone());
            let error = ScenarioRunner::run(&scenario).unwrap_err();
            assert!(error.to_string().contains("properties.lifecycle"), "{value}: {error}");
        }
        let mut scenario = lifecycle_scenario();
        let mut fault = lifecycle_fault(1, FaultAction::ProcessStall, "worker");
        fault.args.insert("duration_ms".to_owned(), serde_json::json!(60_001));
        scenario.faults = vec![fault];
        assert!(ScenarioRunner::run(&scenario).unwrap_err().to_string().contains("duration_ms"));
        crate::test_complete!("lifecycle_plan_refuses_malformed_or_unbounded_properties_before_running");
    }

    #[test]
    fn lifecycle_exhausted_virtual_clock_fails_instead_of_spinning_inside_a_poll() {
        init_test("lifecycle_exhausted_virtual_clock_fails_instead_of_spinning_inside_a_poll");
        let mut scenario = lifecycle_scenario();
        scenario.faults = vec![
            lifecycle_fault(0, FaultAction::HostCrash, "worker"),
            lifecycle_fault(u64::MAX, FaultAction::HostRestart, "worker"),
        ];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(!result.passed());
        assert!(result.lab_report.steps_total < 1000);
        assert_eq!(result.lab_report.now_nanos, u64::MAX);
        let worker = &supervisor_state(&tasks, "sup").workers[0];
        assert_eq!(count(&worker.state.crashes), 1);
        // Generation 2 resumes at u64::MAX and exhausts the clock. The derived
        // budget (one restart) is per one-minute sliding window (4d28c9992), and
        // the t=0 crash restart has aged out of it by then, so the supervisor
        // admits exactly one more generation, which exhausts the clock too; its
        // own restart at u64::MAX then fills the window and stops the worker.
        assert_eq!(count(&worker.state.unexpected), 2);
        let summary = supervisor_summary(&tasks, "sup");
        assert_eq!(summary.restart_batches, 2);
        assert_eq!(summary.children[0].generations, 3);
        assert_eq!(summary.children[0].exit, ChildExit::Failed(3));
        assert!(result.lab_report.invariant_violations.iter().any(|v|
            v.starts_with("workload:worker:worker:unexpected_outcome:")));
        crate::test_complete!("lifecycle_exhausted_virtual_clock_fails_instead_of_spinning_inside_a_poll");
    }

    fn saga_record<'a>(tasks: &'a [BoundTask], name: &str) -> &'a SagaRecord {
        tasks
            .iter()
            .find_map(|task| match &task.detail {
                BoundDetail::SagaCoordinator(record) if task.name == name => Some(&**record),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no saga coordinator named {name}"))
    }

    fn saga_steps(record: &SagaRecord) -> Vec<(&str, &'static str)> {
        record
            .participants
            .iter()
            .map(|(name, step)| (name.as_str(), step_label(step.load(Ordering::Relaxed))))
            .collect()
    }

    fn saga_scenario(participants: usize) -> Scenario {
        let mut scenario = minimal_scenario();
        scenario.id = "test-saga".to_string();
        scenario.participants = vec![participant("coord", "saga-coordinator")];
        scenario.participants.extend(
            (0..participants).map(|index| participant(&format!("p{index}"), "saga-participant")),
        );
        scenario
    }

    fn link_fault(at_ms: u64, action: FaultAction, to: &str) -> FaultEvent {
        FaultEvent {
            at_ms,
            action,
            args: BTreeMap::from([
                ("from".to_string(), serde_json::json!("coord")),
                ("to".to_string(), serde_json::json!(to)),
            ]),
        }
    }

    #[test]
    fn saga_completes_when_every_participant_applies_its_step() {
        init_test("saga_completes_when_every_participant_applies_its_step");
        let scenario = saga_scenario(3);
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));

        let record = saga_record(&tasks, "coord");
        assert_eq!(*record.end.lock(), Some(SagaEnd::Completed));
        assert_eq!(count(&record.registered), 3);
        assert_eq!(count(&record.lost), 0);
        assert!(record.compensated.lock().is_empty());
        assert_eq!(
            saga_steps(record),
            [("p0", "applied"), ("p1", "applied"), ("p2", "applied")]
        );
        // One step every DEFAULT_SAGA_STEP_MS of virtual time.
        assert!(
            result.lab_report.now_nanos >= 3 * DEFAULT_SAGA_STEP_MS * 1_000_000,
            "virtual time {} ns",
            result.lab_report.now_nanos
        );
        for task in tasks_with_role(&tasks, WorkloadRole::SagaParticipant) {
            assert_eq!(count(&task.counters.received), 1, "{}", task.name);
            assert_eq!(count(&task.counters.committed), 1, "{}", task.name);
            assert!(task.counters.drained_to_close.load(Ordering::Relaxed));
        }
        crate::test_complete!("saga_completes_when_every_participant_applies_its_step");
    }

    /// Steps run at 50, 100 and 150 ms. The link to p2 is cut at 120 ms, so
    /// its request is lost and the coordinator times out at 200 ms. The
    /// saga then undoes p1 and p0 after fencing p2, and never asks p3.
    #[test]
    fn partition_loses_a_request_and_the_saga_compensates_in_reverse() {
        init_test("partition_loses_a_request_and_the_saga_compensates_in_reverse");
        let mut scenario = saga_scenario(4);
        scenario.faults = vec![
            link_fault(120, FaultAction::Partition, "p2"),
            link_fault(400, FaultAction::Heal, "p2"),
        ];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));

        let record = saga_record(&tasks, "coord");
        assert_eq!(
            *record.end.lock(),
            Some(SagaEnd::Aborted("p2 timed out".to_owned()))
        );
        assert_eq!(count(&record.lost), 1);
        assert_eq!(count(&record.registered), 3);
        assert_eq!(*record.compensated.lock(), [2, 1, 0]);
        assert_eq!(
            saga_steps(record),
            [
                ("p0", "undone"),
                ("p1", "undone"),
                ("p2", "fenced"),
                ("p3", "pending")
            ]
        );
        let p2 = tasks.iter().find(|task| task.name == "p2").expect("p2");
        assert_eq!(count(&p2.counters.received), 0);
        crate::test_complete!("partition_loses_a_request_and_the_saga_compensates_in_reverse");
    }

    /// The shipped fixture's partition reaches the workload. Without chaos
    /// the coordinator asks participant-i at 50 * (i + 1) ms plus the LAN
    /// round trips before it (2-10 ms each), so participant-7's request, at
    /// about 440 ms, crosses the link cut from 200 to 800 ms and the saga
    /// times out.
    #[test]
    fn saga_partition_fixture_compensates_the_steps_before_the_cut_link() {
        init_test("saga_partition_fixture_compensates_the_steps_before_the_cut_link");
        let yaml = include_str!("../../frankenlab/examples/scenarios/03_saga_partition.yaml");
        let mut scenario: Scenario = serde_yaml::from_str(yaml).expect("parse 03_saga_partition");
        scenario.chaos = ChaosSection::Off;
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));

        let record = saga_record(&tasks, "coordinator");
        assert_eq!(
            *record.end.lock(),
            Some(SagaEnd::Aborted("participant-7 timed out".to_owned()))
        );
        assert_eq!(count(&record.lost), 1);
        assert_eq!(*record.compensated.lock(), [7, 6, 5, 4, 3, 2, 1, 0]);
        let steps = saga_steps(record);
        assert_eq!(steps.len(), 10);
        assert!(
            steps[..7].iter().all(|(_, state)| *state == "undone"),
            "{steps:?}"
        );
        assert_eq!(
            steps[7..],
            [
                ("participant-7", "fenced"),
                ("participant-8", "pending"),
                ("participant-9", "pending")
            ]
        );
        crate::test_complete!("saga_partition_fixture_compensates_the_steps_before_the_cut_link");
    }

    fn planted_task(
        role: WorkloadRole,
        detail: BoundDetail,
        joins: Vec<JoinState>,
        counters: WorkloadCounters,
    ) -> BoundTask {
        BoundTask {
            name: "t".to_owned(),
            role,
            planned: 1,
            spawn_refusal: None,
            counters: Arc::new(counters),
            detail,
            joins,
        }
    }

    fn violation_kinds(task: &BoundTask) -> Vec<String> {
        let mut violations = Vec::new();
        task.collect_violations(&mut violations);
        violations
            .iter()
            .map(|violation| violation.split(':').nth(3).unwrap_or_default().to_owned())
            .collect()
    }

    /// A panicked workload task, and a sender disconnected by a drain that
    /// had reported its channel closed, are violations even when every other
    /// counter looks clean (br-asupersync-nq2dgn).
    #[test]
    fn panicked_tasks_and_premature_disconnects_are_workload_violations() {
        init_test("panicked_tasks_and_premature_disconnects_are_workload_violations");
        let receiver = |joins| {
            planted_task(
                WorkloadRole::Receiver,
                BoundDetail::Channel,
                joins,
                WorkloadCounters::default(),
            )
        };
        assert!(violation_kinds(&receiver(vec![JoinState::Completed])).is_empty());
        assert_eq!(
            violation_kinds(&receiver(vec![JoinState::Panicked])),
            ["panicked"]
        );
        let participant = planted_task(
            WorkloadRole::SagaParticipant,
            BoundDetail::SagaParticipant,
            vec![JoinState::Panicked],
            WorkloadCounters::default(),
        );
        assert_eq!(violation_kinds(&participant), ["panicked"]);

        let sender = WorkloadCounters::default();
        let drain = WorkloadCounters::default();
        note_disconnect(&sender, &drain);
        assert_eq!(count(&sender.premature_disconnects), 0);
        drain.drained_to_close.store(true, Ordering::Relaxed);
        note_disconnect(&sender, &drain);
        assert_eq!(count(&sender.disconnected), 2);
        assert_eq!(count(&sender.premature_disconnects), 1);
        let sender = planted_task(
            WorkloadRole::Sender,
            BoundDetail::Channel,
            vec![JoinState::Completed],
            sender,
        );
        assert_eq!(violation_kinds(&sender), ["premature_disconnect"]);
        crate::test_complete!("panicked_tasks_and_premature_disconnects_are_workload_violations");
    }

    fn link(
        latency_ms: Option<u64>,
        packet_loss: Option<f64>,
    ) -> crate::lab::scenario::LinkConditions {
        crate::lab::scenario::LinkConditions {
            latency: latency_ms.map(|ms| LatencySpec::Fixed { ms }),
            packet_loss,
            packet_corrupt: None,
            packet_duplicate: None,
            packet_reorder: None,
            bandwidth: None,
        }
    }

    #[test]
    fn network_model_follows_the_preset_and_link_overrides() {
        init_test("network_model_follows_the_preset_and_link_overrides");
        let ideal = NetworkModel::new(&NetworkSection::default(), 7);
        assert_eq!(ideal.transit("a", "b"), Some(Duration::ZERO));

        let mut section = NetworkSection {
            preset: NetworkPreset::Lan,
            ..NetworkSection::default()
        };
        section.links.insert("a->b".to_owned(), link(Some(7), None));
        section
            .links
            .insert("b->a".to_owned(), link(None, Some(1.0)));
        let model = NetworkModel::new(&section, 7);
        assert_eq!(model.transit("a", "b"), Some(Duration::from_millis(7)));
        assert_eq!(model.transit("b", "a"), None);
        for _ in 0..64 {
            // LAN: 1-5 ms, and its 0.01% loss may drop one.
            if let Some(delay) = model.transit("a", "c") {
                assert!(
                    (Duration::from_millis(1)..=Duration::from_millis(5)).contains(&delay),
                    "{delay:?}"
                );
            }
        }

        // Same seed, same draws; another seed, other draws.
        let draws = |seed| {
            let model = NetworkModel::new(&section, seed);
            (0..32).map(|_| model.transit("a", "c")).collect::<Vec<_>>()
        };
        assert_eq!(draws(11), draws(11));
        assert_ne!(draws(11), draws(12));
        crate::test_complete!("network_model_follows_the_preset_and_link_overrides");
    }

    /// Saga messages cross the network: a lost reply, a request slower than
    /// the reply budget, and latency within it.
    #[test]
    fn network_latency_and_loss_reach_saga_messages() {
        init_test("network_latency_and_loss_reach_saga_messages");
        let run = |links: Vec<(&str, crate::lab::scenario::LinkConditions)>| {
            let mut scenario = saga_scenario(2);
            for (key, conditions) in links {
                scenario.network.links.insert(key.to_owned(), conditions);
            }
            let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
            assert!(result.passed(), "{}", failure_detail(&result));
            let record = saga_record(&tasks, "coord");
            (
                record.end.lock().clone(),
                count(&record.lost),
                record.compensated.lock().clone(),
                saga_steps(record)
                    .into_iter()
                    .map(|(_, state)| state)
                    .collect::<Vec<_>>(),
            )
        };

        // p0 applies its step but the reply is dropped: the timeout aborts
        // the saga, and the compensation undoes the applied step.
        assert_eq!(
            run(vec![("p0->coord", link(None, Some(1.0)))]),
            (
                Some(SagaEnd::Aborted("p0 timed out".to_owned())),
                1,
                vec![0],
                vec!["undone", "pending"]
            )
        );
        // p1's request takes 60 ms, longer than the 50 ms reply budget: the
        // saga aborts before it arrives, so p1's step is fenced.
        assert_eq!(
            run(vec![("coord->p1", link(Some(60), None))]),
            (
                Some(SagaEnd::Aborted("p1 timed out".to_owned())),
                0,
                vec![1, 0],
                vec!["undone", "fenced"]
            )
        );
        // A 40 ms round trip fits the budget.
        assert_eq!(
            run(vec![
                ("coord->p0", link(Some(20), None)),
                ("p0->coord", link(Some(20), None)),
            ]),
            (
                Some(SagaEnd::Completed),
                0,
                vec![],
                vec!["applied", "applied"]
            )
        );
        crate::test_complete!("network_latency_and_loss_reach_saga_messages");
    }

    fn replication_record<'a>(tasks: &'a [BoundTask], name: &str) -> &'a ReplicationRecord {
        tasks
            .iter()
            .find_map(|task| match &task.detail {
                BoundDetail::Primary(record) if task.name == name => Some(&**record),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no primary named {name}"))
    }

    fn replica_logs(record: &ReplicationRecord) -> Vec<(String, Vec<u64>)> {
        record
            .replicas
            .iter()
            .map(|(name, log)| (name.clone(), log.lock().clone()))
            .collect()
    }

    fn replication_scenario(replicas: usize, writes: u64) -> Scenario {
        let mut scenario = minimal_scenario();
        scenario.id = "test-replication".to_string();
        scenario.participants = vec![participant_with(
            "p",
            "primary",
            "writes",
            serde_json::json!(writes),
        )];
        scenario
            .participants
            .extend((0..replicas).map(|index| participant(&format!("r{index}"), "replica")));
        scenario
    }

    fn partition_fault(at_ms: u64, action: FaultAction, from: &str, to: &str) -> FaultEvent {
        FaultEvent {
            at_ms,
            action,
            args: BTreeMap::from([
                ("from".to_string(), serde_json::json!(from)),
                ("to".to_string(), serde_json::json!(to)),
            ]),
        }
    }

    #[test]
    fn replication_ships_the_whole_log_to_every_replica() {
        init_test("replication_ships_the_whole_log_to_every_replica");
        let scenario = replication_scenario(2, 10);
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        let record = replication_record(&tasks, "p");
        let expected: Vec<u64> = (0..10).collect();
        assert_eq!(*record.log.lock(), expected);
        assert!(record.converged.load(Ordering::Relaxed));
        assert_eq!(count(&record.lost), 0);
        assert_eq!(
            replica_logs(record),
            [
                ("r0".to_owned(), expected.clone()),
                ("r1".to_owned(), expected)
            ]
        );
        crate::test_complete!("replication_ships_the_whole_log_to_every_replica");
    }

    /// Rounds start 50 ms apart. r1's link is cut from 120 to 360 ms, and a
    /// lost batch costs its round the 50 ms reply budget, so the rounds at
    /// 150, 250 and 350 ms lose r1's batch; the round at 450 ms catches it
    /// up. Without the heal it keeps the two entries it had, a safe prefix.
    #[test]
    fn a_partitioned_replica_catches_up_after_the_heal() {
        init_test("a_partitioned_replica_catches_up_after_the_heal");
        let mut scenario = replication_scenario(2, 10);
        scenario.faults = vec![
            partition_fault(120, FaultAction::Partition, "p", "r1"),
            partition_fault(360, FaultAction::Heal, "p", "r1"),
        ];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        let record = replication_record(&tasks, "p");
        let expected: Vec<u64> = (0..10).collect();
        assert!(record.converged.load(Ordering::Relaxed));
        assert_eq!(count(&record.lost), 3);
        assert_eq!(replica_logs(record)[1], ("r1".to_owned(), expected));

        scenario.faults.pop();
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        let record = replication_record(&tasks, "p");
        assert!(!record.converged.load(Ordering::Relaxed));
        assert_eq!(replica_logs(record)[1], ("r1".to_owned(), vec![0, 1]));
        assert_eq!(replica_logs(record)[0].1.len(), 10);
        crate::test_complete!("a_partitioned_replica_catches_up_after_the_heal");
    }

    /// Half of r0's replies are dropped, so the primary ships again entries
    /// r0 already applied. r0 skips the overlap: its log stays duplicate-free.
    #[test]
    fn lost_replies_resend_entries_the_replica_skips() {
        init_test("lost_replies_resend_entries_the_replica_skips");
        let mut scenario = replication_scenario(1, 10);
        scenario
            .network
            .links
            .insert("r0->p".to_owned(), link(None, Some(0.5)));
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        let record = replication_record(&tasks, "p");
        assert!(count(&record.lost) > 0);
        assert!(record.converged.load(Ordering::Relaxed));
        let expected: Vec<u64> = (0..10).collect();
        assert_eq!(replica_logs(record), [("r0".to_owned(), expected)]);
        // Every lost reply followed an applied batch, so the next batch
        // overlapped; r0 still applied each entry exactly once.
        let r0 = tasks.iter().find(|task| task.name == "r0").expect("r0");
        assert_eq!(count(&r0.counters.committed), 10);
        crate::test_complete!("lost_replies_resend_entries_the_replica_skips");
    }

    /// The shipped fixture: node-b's link is cut from 200 to 800 ms while
    /// node-a writes 20 entries, one every 50 ms.
    #[test]
    fn composed_partition_fixture_replica_converges_after_the_heal() {
        init_test("composed_partition_fixture_replica_converges_after_the_heal");
        let yaml = include_str!("../../examples/scenarios/composed_partition_test.yaml");
        let scenario: Scenario = serde_yaml::from_str(yaml).expect("parse composed fixture");
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        let record = replication_record(&tasks, "node-a");
        assert!(record.converged.load(Ordering::Relaxed));
        assert!(count(&record.lost) > 0, "the partition must cost batches");
        let expected: Vec<u64> = (0..DEFAULT_PRIMARY_WRITES).collect();
        assert_eq!(replica_logs(record), [("node-b".to_owned(), expected)]);
        crate::test_complete!("composed_partition_fixture_replica_converges_after_the_heal");
    }

    #[test]
    fn replication_checker_flags_diverged_replicas_and_a_missing_end() {
        init_test("replication_checker_flags_diverged_replicas_and_a_missing_end");
        let record = |replicas: Vec<Vec<u64>>| ReplicationRecord {
            log: Mutex::new(vec![0, 1, 2]),
            replicas: replicas
                .into_iter()
                .enumerate()
                .map(|(index, log)| (format!("r{index}"), Arc::new(Mutex::new(log))))
                .collect(),
            ..ReplicationRecord::default()
        };
        let kinds = |record: &ReplicationRecord, finished: bool| {
            let mut violations = Vec::new();
            record.collect_violations("workload:primary:p", finished, false, &mut violations);
            violations
                .iter()
                .map(|violation| violation.split(':').nth(3).unwrap_or_default().to_owned())
                .collect::<Vec<_>>()
        };
        assert!(kinds(&record(vec![vec![], vec![0, 1], vec![0, 1, 2]]), true).is_empty());
        assert_eq!(kinds(&record(vec![vec![0, 5]]), true), ["diverged"]);
        assert_eq!(kinds(&record(vec![vec![0, 1, 2, 3]]), true), ["diverged"]);
        assert_eq!(kinds(&record(vec![vec![0]]), false), ["no_end"]);
        crate::test_complete!("replication_checker_flags_diverged_replicas_and_a_missing_end");
    }

    #[test]
    fn primary_properties_are_validated() {
        init_test("primary_properties_are_validated");
        let mut scenario = minimal_scenario();
        scenario.participants = vec![
            participant_with(
                "a",
                "primary",
                "writes",
                serde_json::json!(MAX_PRIMARY_WRITES + 1),
            ),
            participant_with("b", "primary", "writes", serde_json::json!("many")),
            participant_with("c", "primary", "write_ms", serde_json::json!(0)),
        ];
        match ScenarioRunner::run(&scenario) {
            Err(ScenarioRunnerError::Validation { errors, .. }) => {
                let fields: Vec<_> = errors.iter().map(|error| error.field.as_str()).collect();
                assert_eq!(
                    fields,
                    [
                        "participants.a.properties.writes",
                        "participants.b.properties.writes",
                        "participants.c.properties.write_ms",
                    ]
                );
            }
            other => panic!("expected a participant property validation error, got {other:?}"),
        }
        crate::test_complete!("primary_properties_are_validated");
    }

    fn lease_record<'a>(tasks: &'a [BoundTask], name: &str) -> &'a LeaseRecord {
        tasks
            .iter()
            .find_map(|task| match &task.detail {
                BoundDetail::LeaseGrantor(record) if task.name == name => Some(&**record),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no lease grantor named {name}"))
    }

    fn tenures(record: &LeaseRecord) -> Vec<(String, u64, u64, TenureEnd)> {
        record
            .tenures
            .lock()
            .iter()
            .map(|tenure| {
                (
                    tenure.holder.clone(),
                    tenure.start.as_millis(),
                    tenure.end.as_millis(),
                    tenure.ending,
                )
            })
            .collect()
    }

    /// Grantor `g` (100 ms grants) and holders `h1` and `h2`. `h2` asks first
    /// at 5 ms, after `h1` has the lease, and then every 30 ms.
    fn lease_scenario(h1: &[(&str, serde_json::Value)]) -> Scenario {
        let mut scenario = minimal_scenario();
        scenario.id = "test-lease".to_string();
        let mut first = participant("h1", "lease-holder");
        for (key, value) in h1 {
            first.properties.insert((*key).to_string(), value.clone());
        }
        let mut second = participant_with("h2", "lease-holder", "start_ms", serde_json::json!(5));
        second
            .properties
            .insert("renew_ms".to_string(), serde_json::json!(30));
        scenario.participants = vec![participant("g", "lease-grantor"), first, second];
        scenario
    }

    fn skew_fault(at_ms: u64, host: &str, skew_ms: i64) -> FaultEvent {
        FaultEvent {
            at_ms,
            action: FaultAction::ClockSkew,
            args: BTreeMap::from([
                ("host".to_string(), serde_json::json!(host)),
                ("skew_ms".to_string(), serde_json::json!(skew_ms)),
            ]),
        }
    }

    /// h1 holds from 0 ms and renews at 40, 80, 120 and 160 ms (each grant
    /// ends for h1 90 ms after its request), then releases at 200 ms. h2's
    /// requests at 5, 35, ..., 185 ms are refused; at 215 ms it gets the
    /// lease, renews every 30 ms and releases at 365 ms.
    #[test]
    fn lease_holders_take_turns() {
        init_test("lease_holders_take_turns");
        let scenario = lease_scenario(&[]);
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        let record = lease_record(&tasks, "g");
        assert_eq!(
            tenures(record),
            [
                ("h1".to_owned(), 0, 200, TenureEnd::Released),
                ("h2".to_owned(), 215, 365, TenureEnd::Released),
            ]
        );
        assert_eq!(count(&record.grants), 10);
        assert_eq!(count(&record.refused), 7);
        assert_eq!(count(&record.lost), 0);
        crate::test_complete!("lease_holders_take_turns");
    }

    /// At 20 ms g's clock jumps 70 ms ahead, so h1's first grant runs out at
    /// g at 30 ms instead of 100 ms. Without a margin h1 believes it until
    /// 100 ms, but g grants h2 the lease at 35 ms and refuses h1's renewals:
    /// two holders. A 70 ms margin ends h1's belief at 30 ms after each
    /// request; renewing every 20 ms it keeps the lease safely until it
    /// releases it at 100 ms, and h2 gets it at 125 ms.
    #[test]
    fn grantor_clock_skew_needs_the_holder_margin() {
        init_test("grantor_clock_skew_needs_the_holder_margin");
        let mut scenario = lease_scenario(&[("margin_ms", serde_json::json!(0))]);
        scenario.faults = vec![skew_fault(20, "g", 70)];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(!result.passed());
        let workload: Vec<_> = result
            .lab_report
            .invariant_violations
            .iter()
            .filter(|violation| violation.starts_with("workload:"))
            .cloned()
            .collect();
        assert_eq!(
            workload,
            ["workload:lease-grantor:g:double_holder:h1@0..100ms,h2@35..185ms"]
        );
        assert_eq!(
            tenures(lease_record(&tasks, "g"))[0],
            ("h1".to_owned(), 0, 100, TenureEnd::Expired)
        );

        let mut scenario = lease_scenario(&[
            ("margin_ms", serde_json::json!(70)),
            ("renew_ms", serde_json::json!(20)),
        ]);
        scenario.faults = vec![skew_fault(20, "g", 70)];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        assert_eq!(
            tenures(lease_record(&tasks, "g")),
            [
                ("h1".to_owned(), 0, 100, TenureEnd::Released),
                ("h2".to_owned(), 125, 275, TenureEnd::Released),
            ]
        );
        crate::test_complete!("grantor_clock_skew_needs_the_holder_margin");
    }

    /// The shipped fixture: node-a holds node-b's lease through four
    /// renewals while node-b's clock runs 1 ms ahead, and releases it.
    #[test]
    fn clock_skew_lease_fixture_holds_and_releases() {
        init_test("clock_skew_lease_fixture_holds_and_releases");
        let yaml = include_str!("../../examples/scenarios/clock_skew_lease.yaml");
        let scenario: Scenario = serde_yaml::from_str(yaml).expect("parse lease fixture");
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        let record = lease_record(&tasks, "node-b");
        let held = tenures(record);
        assert_eq!(held.len(), 1, "{held:?}");
        assert_eq!(held[0].0, "node-a");
        assert_eq!(held[0].3, TenureEnd::Released);
        assert_eq!(
            (
                count(&record.grants),
                count(&record.refused),
                count(&record.lost)
            ),
            (5, 0, 0)
        );
        crate::test_complete!("clock_skew_lease_fixture_holds_and_releases");
    }

    #[test]
    fn lease_checker_flags_overlapping_holders_only() {
        init_test("lease_checker_flags_overlapping_holders_only");
        let tenure = |holder: &str, start: u64, end: u64| Tenure {
            holder: holder.to_owned(),
            start: Time::from_millis(start),
            end: Time::from_millis(end),
            ending: TenureEnd::Released,
        };
        let kinds = |held: Vec<Tenure>| {
            let record = LeaseRecord {
                tenures: Mutex::new(held),
                ..LeaseRecord::default()
            };
            let mut violations = Vec::new();
            record.collect_violations("workload:lease-grantor:g", &mut violations);
            violations
        };
        assert!(kinds(vec![tenure("a", 0, 100), tenure("b", 100, 200)]).is_empty());
        assert!(kinds(vec![tenure("a", 0, 100), tenure("a", 50, 150)]).is_empty());
        assert_eq!(
            kinds(vec![tenure("a", 0, 100), tenure("b", 50, 150)]),
            ["workload:lease-grantor:g:double_holder:a@0..100ms,b@50..150ms"]
        );
        crate::test_complete!("lease_checker_flags_overlapping_holders_only");
    }

    #[test]
    fn clock_faults_offset_one_participant_clock() {
        init_test("clock_faults_offset_one_participant_clock");
        let clocks = ClockTable::default();
        let now = Time::from_millis(50);
        clocks.apply(&skew_fault(0, "a", 30));
        clocks.apply(&skew_fault(0, "b", -80));
        assert_eq!(clocks.local("a", now), Time::from_millis(80));
        assert_eq!(clocks.local("b", now), Time::ZERO);
        assert_eq!(clocks.local("c", now), now);
        clocks.apply(&FaultEvent {
            at_ms: 0,
            action: FaultAction::ClockReset,
            args: BTreeMap::from([("host".to_string(), serde_json::json!("a"))]),
        });
        assert_eq!(clocks.local("a", now), now);
        crate::test_complete!("clock_faults_offset_one_participant_clock");
    }

    #[test]
    fn lease_properties_are_validated() {
        init_test("lease_properties_are_validated");
        let mut scenario = minimal_scenario();
        scenario.participants = vec![
            participant_with(
                "g",
                "lease-grantor",
                "initial_lease_ms",
                serde_json::json!(0),
            ),
            participant_with(
                "h0",
                "lease-holder",
                "renewals",
                serde_json::json!(MAX_LEASE_RENEWALS + 1),
            ),
            participant_with("h1", "lease-holder", "renew_ms", serde_json::json!(0)),
            participant_with("h2", "lease-holder", "margin_ms", serde_json::json!("wide")),
        ];
        match ScenarioRunner::run(&scenario) {
            Err(ScenarioRunnerError::Validation { errors, .. }) => {
                let fields: Vec<_> = errors.iter().map(|error| error.field.as_str()).collect();
                assert_eq!(
                    fields,
                    [
                        "participants.g.properties.initial_lease_ms",
                        "participants.h0.properties.renewals",
                        "participants.h1.properties.renew_ms",
                        "participants.h2.properties.margin_ms",
                    ]
                );
            }
            other => panic!("expected a participant property validation error, got {other:?}"),
        }
        crate::test_complete!("lease_properties_are_validated");
    }

    fn hub_record<'a>(tasks: &'a [BoundTask], name: &str) -> &'a HubRecord {
        tasks
            .iter()
            .find_map(|task| match &task.detail {
                BoundDetail::Hub(record) if task.name == name => Some(&**record),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no hub named {name}"))
    }

    fn peer_stats(record: &HubRecord, peer: &str) -> PeerStats {
        record
            .peers
            .iter()
            .find(|(name, _)| name == peer)
            .map(|(_, stats)| stats.lock().clone())
            .unwrap_or_else(|| panic!("hub has no peer named {peer}"))
    }

    /// Hub `h` pings p0 and p1 three times. The h->p0 link takes 10 ms and the
    /// p1->h link 30 ms; every other link is instant. A link that drops every
    /// ping loses each round's ping after the echo timeout.
    #[test]
    fn hub_pings_every_peer_and_times_the_echoes() {
        init_test("hub_pings_every_peer_and_times_the_echoes");
        let run = |p1_link: (&str, crate::lab::scenario::LinkConditions)| {
            let mut scenario = minimal_scenario();
            scenario.id = "test-hub".to_string();
            let mut hub = participant_with("h", "hub", "rounds", serde_json::json!(3));
            hub.properties
                .insert("timeout_ms".to_string(), serde_json::json!(50));
            scenario.participants = vec![hub, participant("p0", "peer"), participant("p1", "peer")];
            scenario
                .network
                .links
                .insert("h->p0".to_owned(), link(Some(10), None));
            scenario
                .network
                .links
                .insert(p1_link.0.to_owned(), p1_link.1);
            let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
            assert!(result.passed(), "{}", failure_detail(&result));
            let record = hub_record(&tasks, "h");
            (
                peer_stats(record, "p0"),
                peer_stats(record, "p1"),
                count(&record.lost),
            )
        };
        let ms = Duration::from_millis;
        let (p0, p1, lost) = run(("p1->h", link(Some(30), None)));
        assert_eq!(
            (p0.echoed, p0.lost, p0.round_trips),
            (3, 0, vec![ms(10); 3])
        );
        assert_eq!(
            (p1.echoed, p1.lost, p1.round_trips),
            (3, 0, vec![ms(30); 3])
        );
        assert_eq!(lost, 0);

        let (p0, p1, lost) = run(("h->p1", link(None, Some(1.0))));
        assert_eq!((p0.echoed, p0.lost), (3, 0));
        assert_eq!((p1.echoed, p1.lost, p1.mismatched), (0, 3, 0));
        assert_eq!(lost, 3);
        crate::test_complete!("hub_pings_every_peer_and_times_the_echoes");
    }

    /// The shipped fixture: with chaos off, each peer's round trips follow
    /// the a->peer link model (b fixed 1 ms, c uniform 20-80 ms, d normal
    /// 600 +- 50 ms; the echoes cross instant links). As shipped, under light
    /// chaos, the run passes.
    #[test]
    fn custom_latency_model_fixture_round_trips_follow_its_links() {
        init_test("custom_latency_model_fixture_round_trips_follow_its_links");
        let yaml = include_str!("../../examples/scenarios/custom_latency_model.yaml");
        let shipped: Scenario = serde_yaml::from_str(yaml).expect("parse latency fixture");
        let (result, _) = ScenarioRunner::run_seeded(&shipped, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));

        let mut calm = shipped;
        calm.chaos = ChaosSection::Off;
        let (result, tasks) = ScenarioRunner::run_seeded(&calm, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        let record = hub_record(&tasks, "a");
        let ms = Duration::from_millis;
        for (peer, low, high) in [
            ("b", ms(1), ms(1)),
            ("c", ms(20), ms(80)),
            ("d", ms(400), ms(800)),
        ] {
            let stats = peer_stats(record, peer);
            assert_eq!(
                stats.echoed + stats.lost,
                DEFAULT_HUB_ROUNDS,
                "{peer}: {stats:?}"
            );
            assert!(stats.echoed > 0, "{peer}: {stats:?}");
            assert!(
                stats
                    .round_trips
                    .iter()
                    .all(|trip| (low..=high).contains(trip)),
                "{peer}: {stats:?}"
            );
        }
        crate::test_complete!("custom_latency_model_fixture_round_trips_follow_its_links");
    }

    #[test]
    fn hub_checker_flags_mismatched_echoes_and_a_missing_end() {
        init_test("hub_checker_flags_mismatched_echoes_and_a_missing_end");
        let record = HubRecord {
            peers: vec![
                ("p0".to_owned(), Mutex::new(PeerStats::default())),
                (
                    "p1".to_owned(),
                    Mutex::new(PeerStats {
                        mismatched: 1,
                        ..PeerStats::default()
                    }),
                ),
            ],
            ..HubRecord::default()
        };
        let mut violations = Vec::new();
        record.collect_violations("workload:hub:h", true, false, &mut violations);
        assert_eq!(
            violations,
            ["workload:hub:h:echo_mismatch:p1:mismatched=1,echoed=0"]
        );
        let mut violations = Vec::new();
        record.collect_violations("workload:hub:h", false, true, &mut violations);
        assert_eq!(violations.len(), 1, "cancelled: no no_end");
        let mut violations = Vec::new();
        record.collect_violations("workload:hub:h", false, false, &mut violations);
        assert_eq!(violations.len(), 2);
        assert!(violations[1].starts_with("workload:hub:h:no_end"));
        crate::test_complete!("hub_checker_flags_mismatched_echoes_and_a_missing_end");
    }

    #[test]
    fn hub_properties_are_validated() {
        init_test("hub_properties_are_validated");
        let mut scenario = minimal_scenario();
        scenario.participants = vec![
            participant_with("h0", "hub", "rounds", serde_json::json!(MAX_HUB_ROUNDS + 1)),
            participant_with("h1", "hub", "interval_ms", serde_json::json!(0)),
            participant_with("h2", "hub", "timeout_ms", serde_json::json!("soon")),
        ];
        match ScenarioRunner::run(&scenario) {
            Err(ScenarioRunnerError::Validation { errors, .. }) => {
                let fields: Vec<_> = errors.iter().map(|error| error.field.as_str()).collect();
                assert_eq!(
                    fields,
                    [
                        "participants.h0.properties.rounds",
                        "participants.h1.properties.interval_ms",
                        "participants.h2.properties.timeout_ms",
                    ]
                );
            }
            other => panic!("expected a participant property validation error, got {other:?}"),
        }
        crate::test_complete!("hub_properties_are_validated");
    }

    #[test]
    fn saga_participants_go_round_robin_and_orphans_get_an_implicit_coordinator() {
        init_test("saga_participants_go_round_robin_and_orphans_get_an_implicit_coordinator");
        let mut scenario = minimal_scenario();
        scenario.participants = vec![
            participant("a", "saga-participant"),
            participant("c1", "saga-coordinator"),
            participant("b", "saga-participant"),
            participant_with("c2", "saga-coordinator", "step_ms", serde_json::json!(5)),
            participant("c", "saga-participant"),
        ];
        let bindings = ScenarioRunner::participant_bindings(&scenario);
        assert_eq!(bindings.bound.len(), 5);
        assert!(!bindings.implicit_coordinator);
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        let names = |record: &SagaRecord| {
            record
                .participants
                .iter()
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(saga_record(&tasks, "c1")), ["a", "c"]);
        assert_eq!(names(saga_record(&tasks, "c2")), ["b"]);

        scenario.participants = vec![
            participant("a", "saga-participant"),
            participant("b", "saga-participant"),
        ];
        assert!(ScenarioRunner::participant_bindings(&scenario).implicit_coordinator);
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        let record = saga_record(&tasks, IMPLICIT_COORDINATOR_NAME);
        assert_eq!(names(record), ["a", "b"]);
        assert_eq!(*record.end.lock(), Some(SagaEnd::Completed));
        crate::test_complete!(
            "saga_participants_go_round_robin_and_orphans_get_an_implicit_coordinator"
        );
    }

    #[test]
    fn saga_step_interval_is_validated() {
        init_test("saga_step_interval_is_validated");
        let mut scenario = minimal_scenario();
        scenario.participants = vec![
            participant_with("a", "saga-coordinator", "step_ms", serde_json::json!(0)),
            participant_with(
                "b",
                "saga-coordinator",
                "step_ms",
                serde_json::json!(MAX_SAGA_STEP_MS + 1),
            ),
            participant_with(
                "c",
                "saga-coordinator",
                "step_ms",
                serde_json::json!("soon"),
            ),
            participant_with(
                "d",
                "saga-coordinator",
                "step_ms",
                serde_json::json!(MAX_SAGA_STEP_MS),
            ),
        ];
        match ScenarioRunner::run(&scenario) {
            Err(ScenarioRunnerError::Validation { errors, .. }) => {
                let fields: Vec<_> = errors.iter().map(|error| error.field.as_str()).collect();
                assert_eq!(
                    fields,
                    [
                        "participants.a.properties.step_ms",
                        "participants.b.properties.step_ms",
                        "participants.c.properties.step_ms",
                    ]
                );
            }
            other => panic!("expected a participant property validation error, got {other:?}"),
        }
        crate::test_complete!("saga_step_interval_is_validated");
    }

    #[test]
    fn sagas_stopped_by_chaos_never_leave_a_step_applied() {
        init_test("sagas_stopped_by_chaos_never_leave_a_step_applied");
        let mut scenario = saga_scenario(5);
        scenario.chaos = ChaosSection::Custom {
            cancel_probability: 0.1,
            delay_probability: 0.0,
            delay_min_ms: 0,
            delay_max_ms: 10,
            io_error_probability: 0.0,
            wakeup_storm_probability: 0.0,
            budget_exhaustion_probability: 0.0,
        };
        let mut aborted = 0_u64;
        for seed in 0..8 {
            let (result, tasks) = ScenarioRunner::run_seeded(&scenario, Some(seed)).unwrap();
            assert!(result.passed(), "seed {seed}: {}", failure_detail(&result));
            let record = saga_record(&tasks, "coord");
            let steps = saga_steps(record);
            if *record.end.lock() == Some(SagaEnd::Completed) {
                assert!(
                    steps.iter().all(|(_, state)| *state == "applied"),
                    "seed {seed}: {steps:?}"
                );
            } else {
                aborted += 1;
                assert!(
                    steps.iter().all(|(_, state)| *state != "applied"),
                    "seed {seed}: {steps:?}"
                );
            }
        }
        assert!(
            aborted > 0,
            "a 10% per-dispatch cancel rate must stop some saga across eight seeds"
        );
        crate::test_complete!("sagas_stopped_by_chaos_never_leave_a_step_applied");
    }

    /// The checker flags each broken end state; planted records stand in for
    /// a saga implementation that got it wrong.
    #[test]
    fn saga_checker_flags_partial_commits_leftover_steps_and_misordered_compensation() {
        init_test("saga_checker_flags_partial_commits_leftover_steps_and_misordered_compensation");
        let record = |end: SagaEnd, states: &[u8], compensated: Vec<usize>| SagaRecord {
            participants: states
                .iter()
                .enumerate()
                .map(|(index, state)| (format!("p{index}"), Arc::new(AtomicU8::new(*state))))
                .collect(),
            registered: AtomicU64::new(u64::try_from(compensated.len()).unwrap_or(u64::MAX)),
            lost: AtomicU64::new(0),
            compensated: Mutex::new(compensated),
            end: Mutex::new(Some(end)),
        };
        let kinds = |record: &SagaRecord| {
            let mut violations = Vec::new();
            record.collect_violations("workload:saga-coordinator:coord", false, &mut violations);
            violations
                .iter()
                .map(|violation| violation.split(':').nth(3).unwrap_or_default().to_owned())
                .collect::<Vec<_>>()
        };

        let clean_abort = record(
            SagaEnd::Aborted("p1 refused".to_owned()),
            &[STEP_UNDONE, STEP_FENCED],
            vec![1, 0],
        );
        assert!(kinds(&clean_abort).is_empty(), "{:?}", kinds(&clean_abort));
        let partial_commit = record(SagaEnd::Completed, &[STEP_APPLIED, STEP_PENDING], vec![]);
        assert_eq!(kinds(&partial_commit), ["incomplete_commit"]);
        let leftover = record(SagaEnd::Cancelled, &[STEP_APPLIED, STEP_FENCED], vec![1, 0]);
        assert_eq!(kinds(&leftover), ["applied_after_abort"]);
        let misordered = record(
            SagaEnd::Aborted("p1 timed out".to_owned()),
            &[STEP_UNDONE, STEP_FENCED],
            vec![0, 1],
        );
        assert_eq!(kinds(&misordered), ["compensation_order"]);

        let step = AtomicU8::new(STEP_PENDING);
        assert_eq!(compensate_step(&step), "fenced");
        assert_eq!(step.load(Ordering::Relaxed), STEP_FENCED);
        let step = AtomicU8::new(STEP_APPLIED);
        assert_eq!(compensate_step(&step), "undone");
        assert_eq!(compensate_step(&step), "already undone");
        crate::test_complete!(
            "saga_checker_flags_partial_commits_leftover_steps_and_misordered_compensation"
        );
    }

    // ── derive-trait coverage (wave 73) ──────────────────────────────────

    #[test]
    fn trace_certificate_snapshot_debug_clone_copy_eq() {
        let cert = TraceCertificateSnapshot {
            event_hash: 111,
            schedule_hash: 222,
            steps: 333,
            trace_fingerprint: 444,
        };
        let cert2 = cert; // Copy
        let cert3 = cert;
        assert_eq!(cert, cert2);
        assert_eq!(cert2, cert3);
        let dbg = format!("{cert:?}");
        assert!(dbg.contains("TraceCertificateSnapshot"));
        assert!(dbg.contains("111"));
    }

    #[test]
    fn exploration_run_summary_debug_clone() {
        let s = ExplorationRunSummary {
            seed: 42,
            passed: true,
            steps: 100,
            fingerprint: 999,
            failures: vec![],
        };
        let s2 = s;
        assert_eq!(s2.seed, 42);
        assert!(s2.passed);
        assert_eq!(s2.steps, 100);
        assert_eq!(s2.fingerprint, 999);
        assert!(s2.failures.is_empty());
        let dbg = format!("{s2:?}");
        assert!(dbg.contains("ExplorationRunSummary"));
    }

    #[test]
    fn scenario_exploration_result_debug_clone() {
        let r = ScenarioExplorationResult {
            scenario_id: "test-explore".to_string(),
            seeds_explored: 10,
            passed: 8,
            failed: 2,
            unique_fingerprints: 3,
            runs: vec![ExplorationRunSummary {
                seed: 0,
                passed: true,
                steps: 50,
                fingerprint: 1,
                failures: vec![],
            }],
            first_failure_seed: Some(5),
        };
        let r2 = r;
        assert_eq!(r2.scenario_id, "test-explore");
        assert_eq!(r2.seeds_explored, 10);
        assert_eq!(r2.first_failure_seed, Some(5));
        assert_eq!(r2.runs.len(), 1);
        let dbg = format!("{r2:?}");
        assert!(dbg.contains("ScenarioExplorationResult"));
    }
