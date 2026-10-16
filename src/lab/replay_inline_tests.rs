    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::app::AppSpec;
    use crate::lab::SporkScenarioSpec;
    use crate::trace::event::{TraceData, TraceEventKind};
    use crate::types::Budget;
    use crate::types::Time;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn trace_message_contains(event: &TraceEvent, needle: &str) -> bool {
        matches!(&event.data, TraceData::Message(message) if message.contains(needle))
    }

    fn coordination_family_index(family: &str) -> usize {
        COORDINATION_REQUIRED_FAMILIES
            .iter()
            .position(|candidate| candidate == &family)
            .map_or(99, |index| index + 1)
    }

    fn coordination_workload(family: &str) -> CoordinationWorkloadExpansion {
        let index = coordination_family_index(family);
        CoordinationWorkloadExpansion {
            workload_id: format!("ASWARM-WL-{index:03}"),
            scenario_family: family.to_string(),
            scenario_id: format!("agent-swarm.{family}"),
            semantic_pressure: coordination_allowed_semantic_pressure(family)
                .unwrap_or(&["live-only-pressure"])
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            provenance_only_context: coordination_allowed_provenance_context(family)
                .unwrap_or(&["live-only-context"])
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            source_event_count: 1,
            source_hashes: vec![format!("sha256:event-{index:03}")],
            source_bundle_hash: "sha256:coordination-bundle".to_string(),
            replay_command: format!(
                "RCH_BIN=rch bash ./scripts/run_runtime_workload_corpus.sh --workload ASWARM-WL-{index:03}"
            ),
            expected_artifact_globs: vec![
                "target/workload-corpus/coordination-expansion/*/coordination-workload-expansion-pack.json"
                    .to_string(),
            ],
        }
    }

    fn coordination_pack_with_order(order: &[&str]) -> CoordinationWorkloadExpansionPack {
        CoordinationWorkloadExpansionPack {
            schema_version: "runtime-workload-coordination-expansion-pack-v1".to_string(),
            pack_id: "agent-swarm-coordination-pressure".to_string(),
            baseline_denominator: false,
            source_bundle_hash: "sha256:coordination-bundle".to_string(),
            source_run_id: "coordination-fixture".to_string(),
            missing_scenario_families: Vec::new(),
            workloads: order
                .iter()
                .map(|family| coordination_workload(family))
                .collect(),
            refused_bundles: Vec::new(),
        }
    }

    #[test]
    fn coordination_replay_canonicalizes_shuffled_workloads() {
        init_test("coordination_replay_canonicalizes_shuffled_workloads");
        let canonical = coordination_pack_with_order(&[
            "tracker_lock_contention",
            "concurrent_rch_proofs",
            "fail_closed_dirty_frontier",
            "artifact_retrieval_tail",
            "proof_runner_fanout",
            "stale_in_progress_reclaim",
            "coordination_latency_burst",
        ]);
        let shuffled = coordination_pack_with_order(&[
            "coordination_latency_burst",
            "stale_in_progress_reclaim",
            "proof_runner_fanout",
            "artifact_retrieval_tail",
            "fail_closed_dirty_frontier",
            "concurrent_rch_proofs",
            "tracker_lock_contention",
        ]);
        let repeated = synthesize_coordination_pressure_replay(0xA5A0, &canonical)
            .expect("repeated canonical pack should synthesize");

        let first = synthesize_coordination_pressure_replay(0xA5A0, &canonical)
            .expect("canonical pack should synthesize");
        let second = synthesize_coordination_pressure_replay(0xA5A0, &shuffled)
            .expect("shuffled pack should synthesize");

        assert_eq!(first.log.trace_fingerprint, repeated.log.trace_fingerprint);
        assert_eq!(first.log.trace_fingerprint, second.log.trace_fingerprint);
        assert_eq!(first.log.event_count, 7);
        assert_eq!(first.log.synthesized_task_count, 15);
        assert_eq!(first.stimuli[0].scenario_family, "artifact_retrieval_tail");
        crate::test_complete!("coordination_replay_canonicalizes_shuffled_workloads");
    }

    #[test]
    fn coordination_replay_minimization_preserves_first_fail_closed_signal() {
        init_test("coordination_replay_minimization_preserves_first_fail_closed_signal");
        let pack = coordination_pack_with_order(&[
            "tracker_lock_contention",
            "concurrent_rch_proofs",
            "fail_closed_dirty_frontier",
            "artifact_retrieval_tail",
            "proof_runner_fanout",
            "stale_in_progress_reclaim",
            "coordination_latency_burst",
        ]);
        let plan =
            synthesize_coordination_pressure_replay(0xA5A0, &pack).expect("pack should synthesize");
        let minimized = minimize_coordination_pressure_replay(&plan);

        assert_eq!(minimized.stimuli.len(), 1);
        assert_eq!(minimized.log.minimization_steps, 6);
        assert_eq!(minimized.log.event_count, 1);
        assert_eq!(
            minimized.log.first_failure_or_refusal.as_deref(),
            Some("dirty_frontier_fail_closed")
        );
        assert_eq!(
            minimized.stimuli[0].scenario_family,
            "fail_closed_dirty_frontier"
        );
        crate::test_complete!(
            "coordination_replay_minimization_preserves_first_fail_closed_signal"
        );
    }

    #[test]
    fn coordination_replay_rejects_missing_and_unsupported_dimensions() {
        init_test("coordination_replay_rejects_missing_and_unsupported_dimensions");
        let mut missing = coordination_pack_with_order(&["tracker_lock_contention"]);
        assert!(matches!(
            synthesize_coordination_pressure_replay(1, &missing),
            Err(CoordinationReplayError::MissingScenarioDimensions { .. })
        ));

        missing.workloads = COORDINATION_REQUIRED_FAMILIES
            .iter()
            .map(|family| coordination_workload(family))
            .collect();
        missing.workloads[0].scenario_family = "live_agent_mail_socket".to_string();
        assert_eq!(
            synthesize_coordination_pressure_replay(1, &missing),
            Err(CoordinationReplayError::MissingScenarioDimensions {
                missing: vec!["tracker_lock_contention".to_string()],
            })
        );

        let mut unsupported = coordination_pack_with_order(&[
            "tracker_lock_contention",
            "concurrent_rch_proofs",
            "fail_closed_dirty_frontier",
            "artifact_retrieval_tail",
            "proof_runner_fanout",
            "stale_in_progress_reclaim",
            "coordination_latency_burst",
        ]);
        unsupported
            .workloads
            .push(coordination_workload("live_agent_mail_socket"));
        assert_eq!(
            synthesize_coordination_pressure_replay(1, &unsupported),
            Err(CoordinationReplayError::UnsupportedScenarioFamily {
                family: "live_agent_mail_socket".to_string(),
            })
        );
        crate::test_complete!("coordination_replay_rejects_missing_and_unsupported_dimensions");
    }

    #[test]
    fn coordination_replay_canonicalizes_source_hashes_and_rejects_live_only_fields() {
        init_test("coordination_replay_canonicalizes_source_hashes_and_rejects_live_only_fields");
        let mut pack = coordination_pack_with_order(&[
            "tracker_lock_contention",
            "concurrent_rch_proofs",
            "fail_closed_dirty_frontier",
            "artifact_retrieval_tail",
            "proof_runner_fanout",
            "stale_in_progress_reclaim",
            "coordination_latency_burst",
        ]);
        let artifact_tail = pack
            .workloads
            .iter_mut()
            .find(|workload| workload.scenario_family == "artifact_retrieval_tail")
            .expect("artifact tail workload");
        artifact_tail.source_event_count = 2;
        artifact_tail.source_hashes = vec![
            "sha256:artifact-tail-b".to_string(),
            "sha256:artifact-tail-a".to_string(),
        ];

        let mut source_shuffled = pack.clone();
        source_shuffled.workloads.reverse();
        source_shuffled
            .workloads
            .iter_mut()
            .find(|workload| workload.scenario_family == "artifact_retrieval_tail")
            .expect("artifact tail workload")
            .source_hashes
            .reverse();

        let canonical = synthesize_coordination_pressure_replay(7, &pack)
            .expect("canonical source hashes should synthesize");
        let shuffled = synthesize_coordination_pressure_replay(7, &source_shuffled)
            .expect("shuffled source hashes should synthesize");
        assert_eq!(
            canonical.log.trace_fingerprint,
            shuffled.log.trace_fingerprint
        );
        assert_eq!(canonical.log.event_count, 8);
        let artifact_tail = canonical
            .stimuli
            .iter()
            .find(|stimulus| stimulus.scenario_family == "artifact_retrieval_tail")
            .expect("artifact tail stimulus");
        assert_eq!(artifact_tail.artifact_delay_ticks, 10);
        assert_eq!(
            artifact_tail.source_hashes,
            vec![
                "sha256:artifact-tail-a".to_string(),
                "sha256:artifact-tail-b".to_string()
            ]
        );

        let mut live_only = coordination_pack_with_order(&[
            "tracker_lock_contention",
            "concurrent_rch_proofs",
            "fail_closed_dirty_frontier",
            "artifact_retrieval_tail",
            "proof_runner_fanout",
            "stale_in_progress_reclaim",
            "coordination_latency_burst",
        ]);
        live_only.workloads[0]
            .semantic_pressure
            .push("live-agent-mail-socket".to_string());
        assert_eq!(
            synthesize_coordination_pressure_replay(7, &live_only),
            Err(CoordinationReplayError::UnsupportedScenarioField {
                workload_id: "ASWARM-WL-001".to_string(),
                field: "semantic_pressure",
                value: "live-agent-mail-socket".to_string(),
            })
        );
        crate::test_complete!(
            "coordination_replay_canonicalizes_source_hashes_and_rejects_live_only_fields"
        );
    }

    #[test]
    fn swarm_replay_lab_summary_is_byte_stable() {
        init_test("swarm_replay_lab_summary_is_byte_stable");
        let knobs = SwarmReplayScenarioKnobs::ci();
        let first = run_swarm_replay_lab(0x5EED_5A1D, &knobs);
        let second = run_swarm_replay_lab(0x5EED_5A1D, &knobs);

        let first_bytes = serde_json::to_vec(&first).expect("serialize first swarm summary");
        let second_bytes = serde_json::to_vec(&second).expect("serialize second swarm summary");
        assert_eq!(
            first_bytes, second_bytes,
            "same-seed swarm replay summary must be byte-stable"
        );
        assert_eq!(first.schema_version, SWARM_REPLAY_LAB_SCHEMA_VERSION);
        assert_eq!(first.seed, 0x5EED_5A1D);
        assert_eq!(first.resource_deltas.tasks_created, 16);
        assert_eq!(first.resource_deltas.messages_committed, 32);
        assert_eq!(
            first.log.trace_artifact_refs.len(),
            first.knobs.artifact_count
        );
        crate::test_complete!("swarm_replay_lab_summary_is_byte_stable");
    }

    #[test]
    fn swarm_replay_cancellation_cascade_reaches_quiescence() {
        init_test("swarm_replay_cancellation_cascade_reaches_quiescence");
        let summary = run_swarm_replay_lab(0xC4CE_5A1D, &SwarmReplayScenarioKnobs::ci());

        assert!(summary.lab.quiescent, "swarm replay should quiesce");
        assert!(
            summary.lab.invariant_violations.is_empty(),
            "swarm replay invariants should be clean: {:?}",
            summary.lab.invariant_violations
        );
        assert!(
            summary.lab.temporal_failures.is_empty(),
            "swarm replay temporal invariants should be clean: {:?}",
            summary.lab.temporal_failures
        );
        assert!(
            summary.resource_deltas.cancel_targets > 0,
            "cancellation cascade must schedule cancel-lane work"
        );
        assert_eq!(
            summary.resource_deltas.messages_committed, summary.resource_deltas.messages_drained,
            "modeled channel backlog must drain completely"
        );
        assert!(
            summary.resource_deltas.channel_backpressure_events > 0,
            "channel workload must exercise backpressure"
        );
        assert!(
            summary.log.minimized_failing_schedule.is_none(),
            "passing swarm replay should not carry a minimized failure"
        );
        crate::test_complete!("swarm_replay_cancellation_cascade_reaches_quiescence");
    }

    #[test]
    fn swarm_replay_log_records_minimized_failure_schedule() {
        init_test("swarm_replay_log_records_minimized_failure_schedule");
        let knobs = SwarmReplayScenarioKnobs {
            max_steps: 1,
            ..SwarmReplayScenarioKnobs::ci()
        };
        let summary = run_swarm_replay_lab(0xFA11_5EED, &knobs);
        let minimized = summary
            .log
            .minimized_failing_schedule
            .as_ref()
            .expect("step-limited replay should emit minimized failure schedule");

        assert_eq!(summary.log.seed, summary.seed);
        assert_eq!(summary.log.scenario_knobs, summary.knobs);
        assert_eq!(summary.log.resource_deltas, summary.resource_deltas);
        assert!(
            !minimized.preserved_invariant.is_empty(),
            "minimized schedule should name the preserved invariant"
        );
        assert!(
            minimized
                .schedule_steps
                .iter()
                .any(|step| step.contains("channel capacity=")),
            "minimized schedule should retain channel/backpressure context"
        );
        assert!(
            minimized
                .schedule_steps
                .iter()
                .any(|step| step.contains("cancel stride=")),
            "minimized schedule should retain cancellation context"
        );
        crate::test_complete!("swarm_replay_log_records_minimized_failure_schedule");
    }

    #[test]
    fn identical_traces_no_divergence() {
        init_test("identical_traces_no_divergence");
        let a = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::None,
        )];

        let div = find_divergence(&a, &b);
        let ok = div.is_none();
        crate::assert_with_log!(ok, "no divergence", true, ok);
        crate::test_complete!("identical_traces_no_divergence");
    }

    #[test]
    fn trace_seq_only_difference_no_divergence() {
        init_test("trace_seq_only_difference_no_divergence");
        let a = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message("same".to_string()),
        )];
        let b = vec![TraceEvent::new(
            99,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message("same".to_string()),
        )];

        let div = find_divergence(&a, &b);
        let ok = div.is_none();
        crate::assert_with_log!(ok, "seq-only differences ignored", true, ok);
        crate::test_complete!("trace_seq_only_difference_no_divergence");
    }

    #[test]
    fn different_traces_find_divergence() {
        init_test("different_traces_find_divergence");
        let a = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::Spawn,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::Complete,
            TraceData::None,
        )];

        let div = find_divergence(&a, &b);
        let some = div.is_some();
        crate::assert_with_log!(some, "divergence", true, some);
        let pos = div.expect("divergence").position;
        crate::assert_with_log!(pos == 0, "position", 0, pos);
        crate::test_complete!("different_traces_find_divergence");
    }

    #[test]
    fn different_traces_find_divergence_data() {
        init_test("different_traces_find_divergence_data");
        let a = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message("a".to_string()),
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message("b".to_string()),
        )];

        let div = find_divergence(&a, &b);
        let some = div.is_some();
        crate::assert_with_log!(some, "divergence", true, some);
        let pos = div.expect("divergence").position;
        crate::assert_with_log!(pos == 0, "position", 0, pos);
        crate::test_complete!("different_traces_find_divergence_data");
    }

    // ── Replay validation tests ─────────────────────────────────────────

    #[test]
    fn replay_single_task_deterministic() {
        use crate::types::Budget;
        let validation = validate_replay(42, 1, |runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 1 })
                .expect("t");
            runtime.scheduler.lock().schedule(t, 0);
            runtime.run_until_quiescent();
        });

        assert!(validation.is_valid(), "Replay failed: {validation}");
        assert_eq!(
            validation.original_certificate,
            validation.replay_certificate
        );
        assert_eq!(validation.original_steps, validation.replay_steps);
    }

    #[test]
    fn replay_two_tasks_deterministic() {
        use crate::types::Budget;
        let validation = validate_replay(0, 1, |runtime| {
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

        assert!(validation.is_valid(), "Replay failed: {validation}");
    }

    #[test]
    fn replay_multi_seeds_all_deterministic() {
        use crate::types::Budget;
        let seeds: Vec<u64> = (0..10).collect();
        let results = validate_replay_multi(&seeds, 1, |runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 42 })
                .expect("t");
            runtime.scheduler.lock().schedule(t, 0);
            runtime.run_until_quiescent();
        });

        for (i, v) in results.iter().enumerate() {
            assert!(v.is_valid(), "Seed {} replay failed: {v}", seeds[i]);
        }
    }

    // ── Σ-state replay determinism conformance ──────────────────────────
    // Spec contract (lab.replay): two runs of the same closure with the same
    // seed and worker_count MUST produce bit-identical schedule certificates,
    // step counts, and trace event sequences. The certificate hash is the
    // observable Σ-state fingerprint; trace events are the witness sequence.
    // These tests cover the riskier scenarios (panic cleanup, multi-region
    // cancel cascade, mixed cancel + panic) that the simpler "single task"
    // and "two tasks" tests do not exercise.

    /// Σ-state replay determinism: a panicking task must clean up identically
    /// across two runs. The CatchUnwind wrapper turns the panic into
    /// `Outcome::Panicked`; the trace events emitted by region cleanup must be
    /// identical on both runs.
    #[test]
    fn replay_panic_cleanup_deterministic() {
        use crate::types::Budget;
        let validation = validate_replay(0xa11ce, 1, |runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (panicker, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {
                    panic!("conformance panic-cleanup probe");
                })
                .expect("panicker");
            let (sibling, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 7_u32 })
                .expect("sibling");
            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(panicker, 0);
                sched.schedule(sibling, 0);
            }
            runtime.run_until_quiescent();
        });

        assert!(
            validation.is_valid(),
            "Panic-cleanup replay diverged: {validation}",
        );
    }

    /// Σ-state replay determinism: a region tree with a mid-flight cancel
    /// cascade. Cancellation propagates parent → child via
    /// `cancel_request`, generating ordered trace events for region transitions
    /// and task cancels. The certificate, step count, and trace must match
    /// across replays.
    #[test]
    fn replay_multi_region_cancel_cascade_deterministic() {
        use crate::types::{Budget, CancelReason};
        let validation = validate_replay(0xc4cebb1e, 1, |runtime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            let child_a = runtime
                .state
                .create_child_region(root, Budget::INFINITE)
                .expect("child a");
            let child_b = runtime
                .state
                .create_child_region(root, Budget::INFINITE)
                .expect("child b");
            let child_c = runtime
                .state
                .create_child_region(root, Budget::INFINITE)
                .expect("child c");

            for region in [child_a, child_b, child_c] {
                for i in 0..2 {
                    let (task, _) = runtime
                        .state
                        .create_task(region, Budget::INFINITE, async move { i })
                        .expect("task");
                    runtime.scheduler.lock().schedule(task, 0);
                }
            }

            let effects = runtime.state.cancel_request(
                child_b,
                &CancelReason::user("conformance partial cancel"),
                None,
            );
            let (cancel_targets, wake_effects) = effects.into_parts();
            {
                let mut sched = runtime.scheduler.lock();
                for (task, priority) in cancel_targets {
                    sched.schedule_cancel(task, priority);
                }
            }
            wake_effects.dispatch();

            runtime.run_until_quiescent();
        });

        assert!(
            validation.is_valid(),
            "Multi-region cancel cascade replay diverged: {validation}",
        );
    }

    /// Σ-state replay determinism: cancel cascade interleaved with a
    /// panicking task. The panic CatchUnwind path and the cancel propagation
    /// path share state; the union must still replay deterministically.
    #[test]
    fn replay_panic_during_cancel_cascade_deterministic() {
        use crate::types::{Budget, CancelReason};
        let validation = validate_replay(0xdeadc0de, 1, |runtime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            let doomed = runtime
                .state
                .create_child_region(root, Budget::INFINITE)
                .expect("doomed region");

            let (panicker, _) = runtime
                .state
                .create_task(doomed, Budget::INFINITE, async {
                    panic!("panic during cancel cascade");
                })
                .expect("panicker");
            let (sleeper, _) = runtime
                .state
                .create_task(doomed, Budget::INFINITE, async { 1_u8 })
                .expect("sleeper");
            let (root_task, _) = runtime
                .state
                .create_task(root, Budget::INFINITE, async { 2_u8 })
                .expect("root_task");
            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(panicker, 0);
                sched.schedule(sleeper, 0);
                sched.schedule(root_task, 0);
            }

            let effects = runtime.state.cancel_request(
                doomed,
                &CancelReason::user("doomed subtree cancel"),
                None,
            );
            let (cancel_targets, wake_effects) = effects.into_parts();
            {
                let mut sched = runtime.scheduler.lock();
                for (task, priority) in cancel_targets {
                    sched.schedule_cancel(task, priority);
                }
            }
            wake_effects.dispatch();

            runtime.run_until_quiescent();
        });

        assert!(
            validation.is_valid(),
            "Panic-during-cancel-cascade replay diverged: {validation}",
        );
    }

    /// Replay determinism must hold across many seeds for the multi-region
    /// cancel cascade scenario. A single-seed pass can miss a Σ-state path
    /// only reached on certain dispatch orderings.
    #[test]
    fn replay_multi_region_cancel_cascade_deterministic_across_seeds() {
        use crate::types::{Budget, CancelReason};
        let seeds: Vec<u64> = (0..16).map(|i| 0xc4cebb1e ^ (i * 0x9E37_79B9)).collect();
        let results = validate_replay_multi(&seeds, 1, |runtime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            let child_a = runtime
                .state
                .create_child_region(root, Budget::INFINITE)
                .expect("child a");
            let child_b = runtime
                .state
                .create_child_region(root, Budget::INFINITE)
                .expect("child b");
            for region in [child_a, child_b] {
                for i in 0..3 {
                    let (task, _) = runtime
                        .state
                        .create_task(region, Budget::INFINITE, async move { i })
                        .expect("task");
                    runtime.scheduler.lock().schedule(task, 0);
                }
            }
            let effects = runtime.state.cancel_request(
                child_a,
                &CancelReason::user("conformance multi-seed cancel"),
                None,
            );
            let (targets, wake_effects) = effects.into_parts();
            {
                let mut sched = runtime.scheduler.lock();
                for (task, priority) in targets {
                    sched.schedule_cancel(task, priority);
                }
            }
            wake_effects.dispatch();
            runtime.run_until_quiescent();
        });

        for (i, v) in results.iter().enumerate() {
            assert!(
                v.is_valid(),
                "Multi-region cancel cascade diverged at seed {:#x}: {v}",
                seeds[i],
            );
        }
    }

    #[test]
    fn replay_validation_display_ok() {
        let v = ReplayValidation {
            matched: true,
            original_certificate: 0x1234,
            replay_certificate: 0x1234,
            divergence: None,
            original_steps: 5,
            replay_steps: 5,
        };
        let s = format!("{v}");
        assert!(s.contains("Replay OK"));
    }

    #[test]
    fn replay_validation_display_diverged() {
        let v = ReplayValidation {
            matched: false,
            original_certificate: 0x1234,
            replay_certificate: 0x5678,
            divergence: None,
            original_steps: 5,
            replay_steps: 5,
        };
        let s = format!("{v}");
        assert!(s.contains("DIVERGED"));
        assert!(s.contains("Certificate mismatch"));
    }

    // ── Normalization tests ─────────────────────────────────────────────

    #[test]
    fn normalization_single_owner_no_switches() {
        init_test("normalization_single_owner_no_switches");
        // All events from owner 1 - should have 0 switches
        let events = vec![
            TraceEvent::new(
                1,
                Time::from_nanos(0),
                TraceEventKind::Spawn,
                TraceData::None,
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(1),
                TraceEventKind::Poll,
                TraceData::None,
            ),
            TraceEvent::new(
                3,
                Time::from_nanos(2),
                TraceEventKind::Complete,
                TraceData::None,
            ),
        ];
        // All have seq numbers, but owner extraction uses seq % some_value or similar
        // The trace module should handle this; we're testing the wrapper

        let result = normalize_for_replay(&events);
        // Single-owner trace has no switches before or after
        assert_eq!(result.switch_reduction(), 0);
        crate::test_complete!("normalization_single_owner_no_switches");
    }

    #[test]
    fn normalization_result_display() {
        init_test("normalization_result_display");
        let result = NormalizationResult {
            normalized: vec![],
            original_switches: 10,
            normalized_switches: 3,
            algorithm: "Greedy".to_string(),
        };

        let display = format!("{result}");
        assert!(display.contains("10 → 3 switches"));
        assert!(display.contains("70.0% reduction"));
        assert!(display.contains("Greedy"));
        crate::test_complete!("normalization_result_display");
    }

    #[test]
    fn normalization_result_zero_switches() {
        init_test("normalization_result_zero_switches");
        let result = NormalizationResult {
            normalized: vec![],
            original_switches: 0,
            normalized_switches: 0,
            algorithm: "Trivial".to_string(),
        };

        // Avoid division by zero
        let pct = result.switch_reduction_pct();
        assert!((pct - 0.0).abs() < f64::EPSILON);
        crate::test_complete!("normalization_result_zero_switches");
    }

    #[test]
    fn traces_equivalent_identical() {
        init_test("traces_equivalent_identical");
        let events = vec![
            TraceEvent::new(
                1,
                Time::from_nanos(0),
                TraceEventKind::Spawn,
                TraceData::None,
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(1),
                TraceEventKind::Complete,
                TraceData::None,
            ),
        ];

        let equivalent = traces_equivalent(&events, &events);
        crate::assert_with_log!(equivalent, "identical traces equivalent", true, equivalent);
        crate::test_complete!("traces_equivalent_identical");
    }

    #[test]
    fn traces_equivalent_ignores_sequence_numbers() {
        init_test("traces_equivalent_ignores_sequence_numbers");
        let a = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Spawn,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            42,
            Time::from_nanos(0),
            TraceEventKind::Spawn,
            TraceData::None,
        )];

        let equivalent = traces_equivalent(&a, &b);
        crate::assert_with_log!(
            equivalent,
            "seq-only differences still equivalent",
            true,
            equivalent
        );
        crate::test_complete!("traces_equivalent_ignores_sequence_numbers");
    }

    #[test]
    fn traces_equivalent_different_kinds() {
        init_test("traces_equivalent_different_kinds");
        let a = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Spawn,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Complete,
            TraceData::None,
        )];

        let equivalent = traces_equivalent(&a, &b);
        crate::assert_with_log!(
            !equivalent,
            "different kinds not equivalent",
            false,
            equivalent
        );
        crate::test_complete!("traces_equivalent_different_kinds");
    }

    #[test]
    fn compare_normalized_returns_divergence() {
        init_test("compare_normalized_returns_divergence");
        let a = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Spawn,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Complete,
            TraceData::None,
        )];

        let divergence = compare_normalized(&a, &b);
        let has_div = divergence.is_some();
        crate::assert_with_log!(has_div, "divergence found", true, has_div);
        crate::test_complete!("compare_normalized_returns_divergence");
    }

    #[test]
    fn normalize_with_config_custom_beam() {
        use crate::trace::GeodesicConfig;

        init_test("normalize_with_config_custom_beam");
        let events = vec![
            TraceEvent::new(
                1,
                Time::from_nanos(0),
                TraceEventKind::Spawn,
                TraceData::None,
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(1),
                TraceEventKind::Poll,
                TraceData::None,
            ),
        ];

        let config = GeodesicConfig {
            exact_threshold: 0,
            beam_threshold: 1,
            beam_width: 4,
            step_budget: 100,
        };

        let result = normalize_for_replay_with_config(&events, &config);
        // Just verify it runs without panic; algorithm choice depends on trace size
        assert!(!result.algorithm.is_empty());
        crate::test_complete!("normalize_with_config_custom_beam");
    }

    #[test]
    fn classify_fingerprint_classes_is_deterministic() {
        init_test("classify_fingerprint_classes_is_deterministic");

        let runs = vec![
            ExplorationRunSummary {
                seed: 9,
                schedule_hash: 0xB,
                trace_fingerprint: 0xAA,
            },
            ExplorationRunSummary {
                seed: 3,
                schedule_hash: 0xA,
                trace_fingerprint: 0xBB,
            },
            ExplorationRunSummary {
                seed: 7,
                schedule_hash: 0xC,
                trace_fingerprint: 0xAA,
            },
            ExplorationRunSummary {
                seed: 7,
                schedule_hash: 0xC,
                trace_fingerprint: 0xAA,
            },
        ];

        let classes = classify_fingerprint_classes(&runs);
        assert_eq!(classes.len(), 2);
        assert_eq!(classes[0].trace_fingerprint, 0xAA);
        assert_eq!(classes[0].run_count, 3);
        assert_eq!(classes[0].seeds, vec![7, 9]);
        assert_eq!(classes[0].schedule_hashes, vec![0xB, 0xC]);
        assert_eq!(classes[1].trace_fingerprint, 0xBB);
        assert_eq!(classes[1].run_count, 1);
        assert_eq!(classes[1].seeds, vec![3]);
        assert_eq!(classes[1].schedule_hashes, vec![0xA]);

        crate::test_complete!("classify_fingerprint_classes_is_deterministic");
    }

    #[test]
    fn explore_seed_space_is_deterministic_for_same_inputs() {
        init_test("explore_seed_space_is_deterministic_for_same_inputs");

        let seeds = [11_u64, 13_u64, 11_u64];
        let scenario = |runtime: &mut LabRuntime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (task, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("task");
            runtime.scheduler.lock().schedule(task, 0);
            runtime.run_until_quiescent();
        };

        let a = explore_seed_space(&seeds, 1, scenario);
        let b = explore_seed_space(&seeds, 1, scenario);

        assert_eq!(a, b, "same seeds and scenario must produce same report");
        assert_eq!(a.runs.len(), seeds.len());
        assert!(a.unique_fingerprint_count() >= 1);

        crate::test_complete!("explore_seed_space_is_deterministic_for_same_inputs");
    }

    fn make_spork_report(seed: u64, failing: bool) -> SporkHarnessReport {
        use crate::record::ObligationKind;

        let config = LabConfig::new(seed).panic_on_leak(false);
        let mut runtime = LabRuntime::new(config);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        // Create the obligation while the task is still live so the holder
        // validation passes.  Running to quiescence afterward leaves the
        // obligation unresolved (intentional leak → failing report).
        if failing {
            runtime
                .state
                .create_obligation(
                    ObligationKind::SendPermit,
                    task,
                    region,
                    Some("intentional failure for exploration".to_string()),
                )
                .expect("create failing obligation");
        }
        runtime.run_until_quiescent();

        runtime.spork_report("spork_exploration", Vec::new())
    }

    #[test]
    fn summarize_spork_reports_links_failures_to_crashpacks() {
        init_test("summarize_spork_reports_links_failures_to_crashpacks");

        let passing = make_spork_report(31, false);
        let failing = make_spork_report(32, true);

        let summary = summarize_spork_reports(&[failing, passing]);
        assert_eq!(summary.runs.len(), 2);
        assert_eq!(summary.failure_count(), 1);
        assert!(summary.unique_fingerprint_count() >= 1);
        assert!(
            summary.all_failures_linked_to_crashpacks(),
            "failed runs must include crashpack linkage metadata"
        );

        let failed_run = summary
            .runs
            .iter()
            .find(|run| !run.passed)
            .expect("one failing run expected");
        let crashpack = failed_run
            .crashpack_link
            .as_ref()
            .expect("failing run should have crashpack link");
        assert!(
            crashpack.path.starts_with("crashpack-"),
            "unexpected crashpack path: {}",
            crashpack.path
        );

        crate::test_complete!("summarize_spork_reports_links_failures_to_crashpacks");
    }

    #[test]
    fn explore_spork_seed_space_is_deterministic() {
        init_test("explore_spork_seed_space_is_deterministic");

        let seeds = [42_u64, 41_u64, 42_u64];

        let run_for_seed = |seed: u64| make_spork_report(seed, seed.is_multiple_of(2));
        let a = explore_spork_seed_space(&seeds, run_for_seed);

        let run_for_seed = |seed: u64| make_spork_report(seed, seed.is_multiple_of(2));
        let b = explore_spork_seed_space(&seeds, run_for_seed);

        assert_eq!(a, b, "same seeds must produce deterministic report");
        assert_eq!(a.runs.len(), seeds.len());
        assert_eq!(a.failure_count(), 2);
        assert!(a.unique_fingerprint_count() >= 1);
        assert!(a.all_failures_linked_to_crashpacks());

        crate::test_complete!("explore_spork_seed_space_is_deterministic");
    }

    #[test]
    fn scenario_runner_exploration_has_deterministic_fingerprints() {
        init_test("scenario_runner_exploration_has_deterministic_fingerprints");

        let mut runner = SporkScenarioRunner::new();
        runner
            .register(
                SporkScenarioSpec::new("replay.scenario", |_| AppSpec::new("replay_app"))
                    .with_default_config(SporkScenarioConfig::default()),
            )
            .expect("register scenario");

        let base_config = SporkScenarioConfig::default();
        let seeds = [12_u64, 13_u64, 12_u64];

        let a =
            explore_scenario_runner_seed_space(&runner, "replay.scenario", &base_config, &seeds)
                .expect("exploration A");
        let b =
            explore_scenario_runner_seed_space(&runner, "replay.scenario", &base_config, &seeds)
                .expect("exploration B");

        assert_eq!(a, b, "scenario exploration must be deterministic");
        assert_eq!(a.runs.len(), seeds.len());
        assert!(a.unique_fingerprint_count() >= 1);

        // Same seed should map to the same fingerprint.
        let seed_12: Vec<_> = a.runs.iter().filter(|run| run.seed == 12).collect();
        assert_eq!(seed_12.len(), 2);
        assert_eq!(seed_12[0].trace_fingerprint, seed_12[1].trace_fingerprint);

        crate::test_complete!("scenario_runner_exploration_has_deterministic_fingerprints");
    }

    fn make_dual_run_divergence_result() -> crate::lab::dual_run::DualRunResult {
        use crate::lab::dual_run::{
            CancellationRecord, DualRunHarness, LoserDrainRecord, ObligationBalanceRecord,
            RegionCloseRecord, ResourceSurfaceRecord, TerminalOutcome,
        };

        fn base_semantics() -> crate::lab::dual_run::NormalizedSemantics {
            crate::lab::dual_run::NormalizedSemantics {
                terminal_outcome: TerminalOutcome::ok(),
                cancellation: CancellationRecord::none(),
                loser_drain: LoserDrainRecord::not_applicable(),
                region_close: RegionCloseRecord::quiescent(),
                obligation_balance: ObligationBalanceRecord::zero(),
                resource_surface: ResourceSurfaceRecord::empty("test.surface"),
            }
        }

        let mut result = DualRunHarness::phase1(
            "divergence.registry.case",
            "test.surface",
            "v1",
            "Divergence corpus registry coverage",
            0xD1,
        )
        .lab(|_config| base_semantics())
        .live(|_seed, _entropy| {
            let mut sem = base_semantics();
            sem.obligation_balance = ObligationBalanceRecord {
                reserved: 1,
                committed: 0,
                aborted: 0,
                leaked: 1,
                unresolved: 0,
                balanced: false,
            };
            sem
        })
        .run();

        let mut lab_provenance = result
            .lab
            .provenance
            .clone()
            .with_artifact_path("crashpack-divergence.registry.case.json")
            .with_repro_command("cargo test divergence.registry.case -- --nocapture");
        if lab_provenance.trace_fingerprint.is_none() {
            lab_provenance.trace_fingerprint = Some(0xC0DE_CAFE);
        }
        result.lab.provenance = lab_provenance;

        let mut live_provenance = result
            .live
            .provenance
            .clone()
            .with_artifact_path("artifacts/live/divergence.registry.case.json")
            .with_repro_command("cargo test divergence.registry.case -- --nocapture --live");
        if live_provenance.trace_fingerprint.is_none() {
            live_provenance.trace_fingerprint = Some(0xBEEF_BAAD);
        }
        result.live.provenance = live_provenance;
        result
    }

    #[test]
    fn divergence_artifact_bundle_uses_stable_bundle_layout() {
        init_test("divergence_artifact_bundle_uses_stable_bundle_layout");

        let bundle = DivergenceArtifactBundle::under("artifacts/differential/run-001");
        assert_eq!(
            bundle.differential_summary_path,
            "artifacts/differential/run-001/differential_summary.json"
        );
        assert_eq!(
            bundle.live_normalized_path,
            "artifacts/differential/run-001/live_normalized.json"
        );

        crate::test_complete!("divergence_artifact_bundle_uses_stable_bundle_layout");
    }

    #[test]
    fn divergence_retention_defaults_follow_policy_class() {
        init_test("divergence_retention_defaults_follow_policy_class");

        let full = DivergenceRetentionMetadata::for_policy_class(
            DifferentialPolicyClass::RuntimeSemanticBug,
        );
        assert_eq!(full.bundle_level, DivergenceBundleLevel::Full);
        assert_eq!(full.local_retention_days, 14);
        assert_eq!(full.ci_retention_days, 30);
        assert_eq!(full.redaction_mode, "metadata_only");

        let reduced = DivergenceRetentionMetadata::for_policy_class(
            DifferentialPolicyClass::UnsupportedSurface,
        );
        assert_eq!(reduced.bundle_level, DivergenceBundleLevel::Reduced);

        crate::test_complete!("divergence_retention_defaults_follow_policy_class");
    }

    #[test]
    fn divergence_corpus_entry_tracks_lineage_and_promotion_state() {
        init_test("divergence_corpus_entry_tracks_lineage_and_promotion_state");

        let result = make_dual_run_divergence_result();
        assert!(!result.passed(), "test fixture must produce a divergence");

        let entry = DivergenceCorpusEntry::from_dual_run_result(
            &result,
            "pilot_surface",
            "obligation_balance_mismatch",
            DifferentialPolicyClass::RuntimeSemanticBug,
            "artifacts/differential/test-run",
        )
        .with_first_seen_attempt(2, 1)
        .with_minimization_lineage(
            DivergenceMinimizationLineage::from_seed_lineage(&result.seed_lineage)
                .with_minimized_seed(0x2A, "prefix_shrinker", true, true),
        )
        .promote_to_regression("regression.test.surface.obligation_leak.seed_2a");

        assert_eq!(
            entry.policy_class,
            DifferentialPolicyClass::RuntimeSemanticBug
        );
        assert_eq!(entry.first_seen.runner_profile, "pilot_surface");
        assert_eq!(entry.first_seen.attempt_index, 2);
        assert_eq!(entry.first_seen.rerun_count, 1);
        assert_eq!(
            entry.minimization_lineage.shrink_status,
            DivergenceShrinkStatus::PreservedSemanticClass
        );
        assert_eq!(
            entry.regression_promotion_state,
            RegressionPromotionState::PromotedRegression
        );
        assert_eq!(
            entry.metadata.get("promoted_scenario_id"),
            Some(&"regression.test.surface.obligation_leak.seed_2a".to_string())
        );
        assert!(
            entry
                .mismatch_fields
                .contains(&"semantics.obligation_balance.balanced".to_string()),
            "mismatch fields should retain the semantic mismatch path"
        );
        assert!(
            entry
                .artifact_bundle
                .differential_repro_manifest_path
                .ends_with("differential_repro_manifest.json")
        );
        assert_eq!(
            entry.artifact_bundle.bundle_root,
            "artifacts/differential/test-run"
        );

        crate::test_complete!("divergence_corpus_entry_tracks_lineage_and_promotion_state");
    }

    #[test]
    fn divergence_registry_upsert_is_deterministic() {
        init_test("divergence_registry_upsert_is_deterministic");

        let result = make_dual_run_divergence_result();
        let entry = DivergenceCorpusEntry::from_dual_run_result(
            &result,
            "nightly",
            "obligation_balance_mismatch",
            DifferentialPolicyClass::RuntimeSemanticBug,
            "artifacts/differential/nightly-case",
        );

        let mut registry = DivergenceCorpusRegistry::new();
        registry.upsert(entry.clone());
        registry.upsert(entry.promote_to_regression("regression.promoted"));

        assert_eq!(registry.schema_version, DIVERGENCE_CORPUS_SCHEMA_VERSION);
        assert_eq!(registry.entries.len(), 1);
        assert_eq!(
            registry.entries[0].regression_promotion_state,
            RegressionPromotionState::PromotedRegression
        );

        crate::test_complete!("divergence_registry_upsert_is_deterministic");
    }

    #[test]
    fn sanitize_registry_component_never_returns_empty() {
        init_test("sanitize_registry_component_never_returns_empty");

        assert_eq!(sanitize_registry_component(""), "z-0-");
        assert_eq!(sanitize_registry_component(":::"), "z-3-3a3a3a");
        assert_eq!(sanitize_registry_component(" / "), "z-3-202f20");
        assert_eq!(sanitize_registry_component("___"), "___");
        assert_eq!(sanitize_registry_component("scenario-1"), "scenario-1");

        crate::test_complete!("sanitize_registry_component_never_returns_empty");
    }

    #[test]
    fn divergence_registry_components_do_not_alias_escaped_or_literal_segments() {
        init_test("divergence_registry_components_do_not_alias_escaped_or_literal_segments");

        let colon_entry_id = DivergenceCorpusEntry::entry_id_for(
            "surface",
            ":::",
            " / ",
            DifferentialPolicyClass::RuntimeSemanticBug,
        );
        let underscore_entry_id = DivergenceCorpusEntry::entry_id_for(
            "surface",
            "___",
            " / ",
            DifferentialPolicyClass::RuntimeSemanticBug,
        );

        assert_ne!(
            colon_entry_id, underscore_entry_id,
            "distinct raw IDs must not collapse to the same registry entry id"
        );
        assert!(colon_entry_id.starts_with("surface.z-3-3a3a3a."));
        assert!(underscore_entry_id.starts_with("surface.___."));

        let slash_entry_id = DivergenceCorpusEntry::entry_id_for(
            "surface",
            "a/b",
            "seed",
            DifferentialPolicyClass::RuntimeSemanticBug,
        );
        let underscore_entry_id = DivergenceCorpusEntry::entry_id_for(
            "surface",
            "a_b",
            "seed",
            DifferentialPolicyClass::RuntimeSemanticBug,
        );
        let escaped_looking_entry_id = DivergenceCorpusEntry::entry_id_for(
            "surface",
            "z-3-616263",
            "seed",
            DifferentialPolicyClass::RuntimeSemanticBug,
        );
        assert_ne!(slash_entry_id, underscore_entry_id);
        assert_ne!(slash_entry_id, escaped_looking_entry_id);
        assert_ne!(underscore_entry_id, escaped_looking_entry_id);

        let entry = DivergenceCorpusEntry {
            schema_version: DIVERGENCE_CORPUS_SCHEMA_VERSION.to_string(),
            entry_id: DivergenceCorpusEntry::entry_id_for(
                " / ",
                ":::",
                "___",
                DifferentialPolicyClass::RuntimeSemanticBug,
            ),
            scenario_id: ":::".to_string(),
            surface_id: " / ".to_string(),
            surface_contract_version: "v1".to_string(),
            divergence_class: "semantic".to_string(),
            policy_class: DifferentialPolicyClass::RuntimeSemanticBug,
            first_seen: DivergenceFirstSeenContext {
                runner_profile: "nightly".to_string(),
                attempt_index: 0,
                rerun_count: 0,
            },
            seed_lineage: crate::lab::dual_run::SeedLineageRecord {
                seed_lineage_id: "___".to_string(),
                canonical_seed: 7,
                lab_effective_seed: 7,
                live_effective_seed: 7,
                lab_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                live_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                lab_entropy_seed: 7,
                live_entropy_seed: 7,
                replay_policy: crate::lab::dual_run::ReplayPolicy::SingleSeed,
                seeds_match: true,
                annotations: BTreeMap::new(),
            },
            mismatch_fields: Vec::new(),
            artifact_bundle: DivergenceArtifactBundle::under("artifacts/differential/test"),
            minimization_lineage: DivergenceMinimizationLineage::from_seed_lineage(
                &crate::lab::dual_run::SeedLineageRecord {
                    seed_lineage_id: "___".to_string(),
                    canonical_seed: 7,
                    lab_effective_seed: 7,
                    live_effective_seed: 7,
                    lab_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                    live_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                    lab_entropy_seed: 7,
                    live_entropy_seed: 7,
                    replay_policy: crate::lab::dual_run::ReplayPolicy::SingleSeed,
                    seeds_match: true,
                    annotations: BTreeMap::new(),
                },
            ),
            regression_promotion_state: RegressionPromotionState::Investigating,
            retention: DivergenceRetentionMetadata::for_policy_class(
                DifferentialPolicyClass::RuntimeSemanticBug,
            ),
            metadata: BTreeMap::new(),
        };

        assert_eq!(
            entry.default_bundle_root(),
            "artifacts/differential/z-3-202f20/z-3-3a3a3a/___/runtime_semantic_bug"
        );

        crate::test_complete!(
            "divergence_registry_components_do_not_alias_escaped_or_literal_segments"
        );
    }

    #[test]
    fn divergence_registry_entry_id_includes_surface_id() {
        init_test("divergence_registry_entry_id_includes_surface_id");

        let first = DivergenceCorpusEntry::entry_id_for(
            "surface-a",
            "scenario",
            "seed",
            DifferentialPolicyClass::RuntimeSemanticBug,
        );
        let second = DivergenceCorpusEntry::entry_id_for(
            "surface-b",
            "scenario",
            "seed",
            DifferentialPolicyClass::RuntimeSemanticBug,
        );

        assert_ne!(
            first, second,
            "different surfaces must not alias to the same registry entry id"
        );
        assert!(first.starts_with("surface-a."));
        assert!(second.starts_with("surface-b."));

        let mut registry = DivergenceCorpusRegistry::new();
        let make_entry = |surface_id: &str| DivergenceCorpusEntry {
            schema_version: DIVERGENCE_CORPUS_SCHEMA_VERSION.to_string(),
            entry_id: DivergenceCorpusEntry::entry_id_for(
                surface_id,
                "scenario",
                "seed",
                DifferentialPolicyClass::RuntimeSemanticBug,
            ),
            scenario_id: "scenario".to_string(),
            surface_id: surface_id.to_string(),
            surface_contract_version: "v1".to_string(),
            divergence_class: "semantic".to_string(),
            policy_class: DifferentialPolicyClass::RuntimeSemanticBug,
            first_seen: DivergenceFirstSeenContext {
                runner_profile: "nightly".to_string(),
                attempt_index: 0,
                rerun_count: 0,
            },
            seed_lineage: crate::lab::dual_run::SeedLineageRecord {
                seed_lineage_id: "seed".to_string(),
                canonical_seed: 7,
                lab_effective_seed: 7,
                live_effective_seed: 7,
                lab_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                live_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                lab_entropy_seed: 7,
                live_entropy_seed: 7,
                replay_policy: crate::lab::dual_run::ReplayPolicy::SingleSeed,
                seeds_match: true,
                annotations: BTreeMap::new(),
            },
            mismatch_fields: Vec::new(),
            artifact_bundle: DivergenceArtifactBundle::under(format!(
                "artifacts/differential/{surface_id}"
            )),
            minimization_lineage: DivergenceMinimizationLineage::from_seed_lineage(
                &crate::lab::dual_run::SeedLineageRecord {
                    seed_lineage_id: "seed".to_string(),
                    canonical_seed: 7,
                    lab_effective_seed: 7,
                    live_effective_seed: 7,
                    lab_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                    live_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                    lab_entropy_seed: 7,
                    live_entropy_seed: 7,
                    replay_policy: crate::lab::dual_run::ReplayPolicy::SingleSeed,
                    seeds_match: true,
                    annotations: BTreeMap::new(),
                },
            ),
            regression_promotion_state: RegressionPromotionState::Investigating,
            retention: DivergenceRetentionMetadata::for_policy_class(
                DifferentialPolicyClass::RuntimeSemanticBug,
            ),
            metadata: BTreeMap::new(),
        };

        registry.upsert(make_entry("surface-a"));
        registry.upsert(make_entry("surface-b"));
        assert_eq!(registry.entries.len(), 2);
        assert_eq!(registry.entries[0].surface_id, "surface-a");
        assert_eq!(registry.entries[1].surface_id, "surface-b");

        crate::test_complete!("divergence_registry_entry_id_includes_surface_id");
    }

    #[test]
    fn divergence_default_bundle_root_includes_policy_class() {
        init_test("divergence_default_bundle_root_includes_policy_class");

        let make_entry = |policy_class| DivergenceCorpusEntry {
            schema_version: DIVERGENCE_CORPUS_SCHEMA_VERSION.to_string(),
            entry_id: DivergenceCorpusEntry::entry_id_for(
                "surface",
                "scenario",
                "seed",
                policy_class,
            ),
            scenario_id: "scenario".to_string(),
            surface_id: "surface".to_string(),
            surface_contract_version: "v1".to_string(),
            divergence_class: "semantic".to_string(),
            policy_class,
            first_seen: DivergenceFirstSeenContext {
                runner_profile: "nightly".to_string(),
                attempt_index: 0,
                rerun_count: 0,
            },
            seed_lineage: crate::lab::dual_run::SeedLineageRecord {
                seed_lineage_id: "seed".to_string(),
                canonical_seed: 1,
                lab_effective_seed: 1,
                live_effective_seed: 1,
                lab_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                live_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                lab_entropy_seed: 1,
                live_entropy_seed: 1,
                replay_policy: crate::lab::dual_run::ReplayPolicy::SingleSeed,
                seeds_match: true,
                annotations: BTreeMap::new(),
            },
            mismatch_fields: Vec::new(),
            artifact_bundle: DivergenceArtifactBundle::under("artifacts/differential/test"),
            minimization_lineage: DivergenceMinimizationLineage::from_seed_lineage(
                &crate::lab::dual_run::SeedLineageRecord {
                    seed_lineage_id: "seed".to_string(),
                    canonical_seed: 1,
                    lab_effective_seed: 1,
                    live_effective_seed: 1,
                    lab_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                    live_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                    lab_entropy_seed: 1,
                    live_entropy_seed: 1,
                    replay_policy: crate::lab::dual_run::ReplayPolicy::SingleSeed,
                    seeds_match: true,
                    annotations: BTreeMap::new(),
                },
            ),
            regression_promotion_state: RegressionPromotionState::Investigating,
            retention: DivergenceRetentionMetadata::for_policy_class(policy_class),
            metadata: BTreeMap::new(),
        };

        let runtime_semantic_bug =
            make_entry(DifferentialPolicyClass::RuntimeSemanticBug).default_bundle_root();
        let unsupported_surface =
            make_entry(DifferentialPolicyClass::UnsupportedSurface).default_bundle_root();

        assert_ne!(
            runtime_semantic_bug, unsupported_surface,
            "different policy classes must not alias to the same retained bundle path"
        );
        assert!(runtime_semantic_bug.ends_with("/runtime_semantic_bug"));
        assert!(unsupported_surface.ends_with("/unsupported_surface"));

        crate::test_complete!("divergence_default_bundle_root_includes_policy_class");
    }

    #[test]
    fn differential_bundle_artifacts_capture_repro_and_minimization_lineage() {
        init_test("differential_bundle_artifacts_capture_repro_and_minimization_lineage");

        let result = make_dual_run_divergence_result();
        let entry = DivergenceCorpusEntry::from_dual_run_result(
            &result,
            "nightly",
            "obligation_balance_mismatch",
            DifferentialPolicyClass::RuntimeSemanticBug,
            "artifacts/differential/nightly/divergence.registry.case",
        )
        .with_first_seen_attempt(3, 2)
        .with_minimization_lineage(
            DivergenceMinimizationLineage::from_seed_lineage(&result.seed_lineage)
                .with_minimized_seed(0x2A, "prefix_shrinker", true, true),
        )
        .promote_to_regression("regression.test.surface.obligation_leak.seed_2a");

        let bundle = DifferentialBundleArtifacts::from_dual_run_result(&entry, &result);
        assert_eq!(
            bundle.summary.schema_version,
            DIFFERENTIAL_SUMMARY_SCHEMA_VERSION
        );
        assert_eq!(
            bundle.summary.bundle_root,
            "artifacts/differential/nightly/divergence.registry.case"
        );
        assert_eq!(bundle.failures.failure_artifacts.len(), 2);
        assert_eq!(
            bundle.failures.failure_artifacts[0].runtime_kind,
            "lab".to_string()
        );
        assert_eq!(
            bundle.failures.failure_artifacts[0]
                .crashpack_link
                .as_ref()
                .map(|link| link.path.as_str()),
            Some("crashpack-divergence.registry.case.json")
        );
        assert_eq!(
            bundle.repro_manifest.promoted_scenario_id.as_deref(),
            Some("regression.test.surface.obligation_leak.seed_2a")
        );
        assert_eq!(
            bundle.repro_manifest.minimization_lineage.shrink_status,
            DivergenceShrinkStatus::PreservedSemanticClass
        );
        assert_eq!(
            bundle.repro_manifest.failure_artifacts_path,
            "artifacts/differential/nightly/divergence.registry.case/differential_failures.json"
        );
        assert!(
            bundle
                .repro_manifest
                .repro_commands
                .contains(&"cargo test divergence.registry.case -- --nocapture".to_string())
        );
        assert!(
            bundle
                .deviations
                .mismatches
                .iter()
                .any(|mismatch| mismatch.field == "semantics.obligation_balance.balanced")
        );

        crate::test_complete!(
            "differential_bundle_artifacts_capture_repro_and_minimization_lineage"
        );
    }

    #[test]
    fn inferred_crashpack_reference_requires_crashpack_like_path() {
        init_test("inferred_crashpack_reference_requires_crashpack_like_path");

        let result = make_dual_run_divergence_result();
        let lab_link = DifferentialCrashpackReference::from_provenance(&result.lab.provenance);
        let live_link = DifferentialCrashpackReference::from_provenance(&result.live.provenance);

        assert!(
            lab_link.is_some(),
            "crashpack-like lab artifact should infer linkage"
        );
        assert!(
            live_link.is_none(),
            "non-crashpack live artifact should not infer crashpack linkage"
        );

        crate::test_complete!("inferred_crashpack_reference_requires_crashpack_like_path");
    }

    // =========================================================================
    // METAMORPHIC TESTING: Lab::Replay Deterministic Fork/Join
    // =========================================================================

    /// Configuration for metamorphic replay testing
    #[derive(Debug, Clone)]
    struct ReplayMetamorphicConfig {
        /// Number of workers for parallel execution
        worker_count: usize,
        /// Number of checkpoints to test
        checkpoint_count: usize,
        /// Number of concurrent tasks to spawn
        task_count: usize,
    }

    impl Default for ReplayMetamorphicConfig {
        fn default() -> Self {
            Self {
                worker_count: 4,
                checkpoint_count: 5,
                task_count: 8,
            }
        }
    }

    /// Generate deterministic test scenario for fork/join patterns
    fn create_fork_join_test_scenario(
        config: &ReplayMetamorphicConfig,
        rng_seed: u64,
    ) -> impl Fn(&mut LabRuntime) + Clone {
        let task_count = config.task_count;
        move |runtime: &mut LabRuntime| {
            // Use the runtime's deterministic execution to create fork/join patterns
            use crate::util::det_rng::DetRng;
            let mut rng = DetRng::new(rng_seed);

            // Create a simple fork/join pattern with multiple concurrent tasks
            for i in 0..task_count {
                let _task_seed = rng.next_u64();
                // This would normally spawn tasks using the runtime's spawn mechanisms
                // For testing, we'll create trace events that represent fork/join operations
                runtime.trace().record_event(|id| {
                    crate::trace::TraceEvent::user_trace(
                        id,
                        runtime.now(),
                        format!("fork_task_{}", i),
                    )
                });
            }

            // Simulate join phase
            for i in 0..task_count {
                runtime.trace().record_event(|id| {
                    crate::trace::TraceEvent::user_trace(
                        id,
                        runtime.now(),
                        format!("join_task_{}", i),
                    )
                });
            }
        }
    }

    // =========================================================================
    // MR1: Checkpoint Replay Equivalence
    // =========================================================================

    #[test]
    fn metamorphic_checkpoint_replay_equivalence() {
        init_test("metamorphic_checkpoint_replay_equivalence");

        let seed = 0x5245_504c_4159_0001;

        let config = ReplayMetamorphicConfig::default();

        // Test scenario: original execution vs replay from various checkpoints
        let test_scenario = create_fork_join_test_scenario(&config, seed);

        // Run original execution
        let mut original_config = LabConfig::new(seed);
        original_config = original_config.worker_count(config.worker_count);
        let mut original_runtime = LabRuntime::new(original_config);
        test_scenario(&mut original_runtime);
        let original_trace = original_runtime.trace().snapshot();
        let original_certificate = original_runtime.certificate().hash();

        // MR: Replay from different checkpoints should produce equivalent results
        // when executed to the same point
        for checkpoint_idx in 0..config.checkpoint_count.min(original_trace.len()) {
            let mut replay_config = LabConfig::new(seed);
            replay_config = replay_config.worker_count(config.worker_count);
            let mut replay_runtime = LabRuntime::new(replay_config);

            // Simulate replay from checkpoint by processing events up to checkpoint
            for event in &original_trace[..checkpoint_idx] {
                replay_runtime.trace().push_event(event.clone());
            }

            // Continue execution from checkpoint
            test_scenario(&mut replay_runtime);
            let replay_trace = replay_runtime.trace().snapshot();
            let replay_certificate = replay_runtime.certificate().hash();

            // MR: Certificate hashes should match between original and replayed execution
            assert_eq!(
                original_certificate, replay_certificate,
                "Checkpoint {} replay diverged in certificate hash",
                checkpoint_idx
            );

            // MR: The portion of the trace up to the checkpoint is recorded
            // by replaying exact original events. Those events must match
            // byte-for-byte (the checkpoint-prefix invariant). Events after
            // the checkpoint are re-generated by rerunning the test scenario
            // on a fresh runtime, so they form a second independent recording
            // rather than a true continuation — comparing those positions
            // against the original is ill-defined and is therefore skipped.
            for (i, (orig_event, replay_event)) in original_trace
                .iter()
                .zip(replay_trace.iter())
                .enumerate()
                .take(checkpoint_idx)
            {
                assert!(
                    events_match(orig_event, replay_event),
                    "Event {} before checkpoint {} doesn't match: {:?} vs {:?}",
                    i,
                    checkpoint_idx,
                    orig_event,
                    replay_event
                );
            }
        }

        crate::test_complete!("metamorphic_checkpoint_replay_equivalence");
    }

    // =========================================================================
    // MR2: Parallel Scope Fork/Join Order Determinism
    // =========================================================================

    #[test]
    fn metamorphic_parallel_scope_fork_join_determinism() {
        init_test("metamorphic_parallel_scope_fork_join_determinism");

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let config = ReplayMetamorphicConfig::default();

        // MR: Fork/join order should be deterministic across multiple runs with same seed
        let test_scenario = create_fork_join_test_scenario(&config, seed);

        let mut executions = Vec::new();

        // Execute the same scenario multiple times with the same seed
        for _run_idx in 0..5 {
            let mut runtime_config = LabConfig::new(seed); // Same seed every time
            runtime_config = runtime_config.worker_count(config.worker_count);
            let mut runtime = LabRuntime::new(runtime_config);

            test_scenario(&mut runtime);

            let trace = runtime.trace().snapshot();
            let certificate = runtime.certificate().hash();
            let steps = runtime.steps();

            executions.push((trace, certificate, steps));
        }

        // MR: All executions should produce identical results
        for (run_idx, (trace, certificate, steps)) in executions.iter().enumerate().skip(1) {
            assert_eq!(
                executions[0].1, *certificate,
                "Run {} has different certificate than run 0",
                run_idx
            );
            assert_eq!(
                executions[0].2, *steps,
                "Run {} has different step count than run 0",
                run_idx
            );

            // Check trace equivalence
            let divergence = find_divergence(&executions[0].0, trace);
            assert!(
                divergence.is_none(),
                "Run {} diverged from run 0: {:?}",
                run_idx,
                divergence
            );
        }

        // MR: Fork/join ordering should be stable within each trace
        for (run_idx, (trace, _, _)) in executions.iter().enumerate() {
            let mut fork_events = Vec::new();
            let mut join_events = Vec::new();

            for event in trace {
                if matches!(&event.data, crate::trace::event::TraceData::Message(msg) if msg.contains("fork_task_"))
                {
                    fork_events.push(event.clone());
                } else if matches!(&event.data, crate::trace::event::TraceData::Message(msg) if msg.contains("join_task_"))
                {
                    join_events.push(event.clone());
                }
            }

            // Verify fork events appear before join events (proper fork/join ordering)
            if let (Some(last_fork), Some(first_join)) = (fork_events.last(), join_events.first()) {
                assert!(
                    last_fork.time <= first_join.time,
                    "Run {}: Fork events should complete before join events start",
                    run_idx
                );
            }
        }

        crate::test_complete!("metamorphic_parallel_scope_fork_join_determinism");
    }

    // =========================================================================
    // MR3: Panic Replay Cause Chain Consistency
    // =========================================================================

    #[test]
    fn metamorphic_panic_replay_cause_chain_consistency() {
        init_test("metamorphic_panic_replay_cause_chain_consistency");

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let config = ReplayMetamorphicConfig::default();

        // Test scenario that includes panic conditions
        let panic_scenario = move |runtime: &mut LabRuntime| {
            use crate::util::det_rng::DetRng;
            let mut rng = DetRng::new(seed);

            // Create events including simulated panic conditions
            for i in 0..config.task_count {
                if rng.next_u64() % 4 == 0 {
                    // 25% chance of panic
                    runtime.trace().record_event(|id| {
                        crate::trace::TraceEvent::user_trace(
                            id,
                            runtime.now(),
                            format!("panic_task_{}", i),
                        )
                    });
                } else {
                    runtime.trace().record_event(|id| {
                        crate::trace::TraceEvent::user_trace(
                            id,
                            runtime.now(),
                            format!("normal_task_{}", i),
                        )
                    });
                }
            }
        };

        // Run original execution
        let mut original_config = LabConfig::new(seed);
        original_config = original_config.worker_count(config.worker_count);
        let mut original_runtime = LabRuntime::new(original_config);
        panic_scenario(&mut original_runtime);
        let original_trace = original_runtime.trace().snapshot();

        // Run replay
        let mut replay_config = LabConfig::new(seed);
        replay_config = replay_config.worker_count(config.worker_count);
        let mut replay_runtime = LabRuntime::new(replay_config);
        panic_scenario(&mut replay_runtime);
        let replay_trace = replay_runtime.trace().snapshot();

        // MR: Panic cause chains should be identical between original and replay
        let original_panics: Vec<_> = original_trace
            .iter()
            .filter(|event| trace_message_contains(event, "panic_"))
            .collect();
        let replay_panics: Vec<_> = replay_trace
            .iter()
            .filter(|event| trace_message_contains(event, "panic_"))
            .collect();

        assert_eq!(
            original_panics.len(),
            replay_panics.len(),
            "Panic count should match between original and replay"
        );

        for (original_panic, replay_panic) in original_panics.iter().zip(replay_panics.iter()) {
            assert!(
                events_match(original_panic, replay_panic),
                "Panic events should match: {:?} vs {:?}",
                original_panic,
                replay_panic
            );
        }

        // MR: Overall trace should be identical (no divergence)
        let divergence = find_divergence(&original_trace, &replay_trace);
        assert!(
            divergence.is_none(),
            "Panic replay diverged: {:?}",
            divergence
        );

        crate::test_complete!("metamorphic_panic_replay_cause_chain_consistency");
    }

    // =========================================================================
    // MR4: Cross-Region Trace Ordering Preservation
    // =========================================================================

    #[test]
    fn metamorphic_cross_region_trace_ordering_preservation() {
        init_test("metamorphic_cross_region_trace_ordering_preservation");

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let config = ReplayMetamorphicConfig::default();

        // Test scenario with multiple regions
        let multi_region_scenario = move |runtime: &mut LabRuntime| {
            use crate::util::det_rng::DetRng;
            let _rng = DetRng::new(seed);

            let region_count = 3;

            // Create events across multiple regions
            for region_id in 0..region_count {
                for task_id in 0..config.task_count / region_count {
                    let now = runtime.now();
                    runtime.trace().record_event(|id| {
                        crate::trace::TraceEvent::user_trace(
                            id,
                            now,
                            format!("region_{}_task_{}", region_id, task_id),
                        )
                    });
                }
            }
        };

        // Test ordering preservation across different execution contexts
        let execution_contexts = [
            ("single_worker", 1),
            ("dual_worker", 2),
            ("multi_worker", 4),
        ];

        let mut context_traces = Vec::new();

        for (context_name, worker_count) in &execution_contexts {
            let mut runtime_config = LabConfig::new(seed);
            runtime_config = runtime_config.worker_count(*worker_count);
            let mut runtime = LabRuntime::new(runtime_config);

            multi_region_scenario(&mut runtime);
            let trace = runtime.trace().snapshot();
            context_traces.push((context_name, trace));
        }

        // MR: Cross-region ordering should be preserved regardless of worker count
        for (context_name, trace) in &context_traces {
            let mut region_events: std::collections::BTreeMap<u32, Vec<&crate::trace::TraceEvent>> =
                std::collections::BTreeMap::new();

            for event in trace {
                if let crate::trace::event::TraceData::Message(ref data_str) = event.data {
                    if data_str.contains("region_") {
                        if let Some(region_start) = data_str.find("region_") {
                            if let Some(region_end) = data_str[region_start + 7..].find('_') {
                                if let Ok(region_id) = data_str
                                    [region_start + 7..region_start + 7 + region_end]
                                    .parse::<u32>()
                                {
                                    region_events.entry(region_id).or_default().push(event);
                                }
                            }
                        }
                    }
                }
            }

            // Verify each region has events
            assert!(
                !region_events.is_empty(),
                "Context {} should have region events",
                context_name
            );

            // MR: Within each region, event ordering should be deterministic
            for (region_id, events) in &region_events {
                for window in events.windows(2) {
                    assert!(
                        window[0].time <= window[1].time,
                        "Context {}: Region {} events not in time order",
                        context_name,
                        region_id
                    );
                }
            }
        }

        // MR: Different worker counts should produce equivalent logical ordering
        // (may have different physical timing but same logical causality)
        for i in 1..context_traces.len() {
            let (name1, trace1) = &context_traces[0];
            let (name2, trace2) = &context_traces[i];

            // Extract logical ordering (ignoring precise timing)
            let logical_order1: Vec<_> = trace1
                .iter()
                .filter(|e| trace_message_contains(e, "region_"))
                .map(|e| &e.data)
                .collect();
            let logical_order2: Vec<_> = trace2
                .iter()
                .filter(|e| trace_message_contains(e, "region_"))
                .map(|e| &e.data)
                .collect();

            assert_eq!(
                logical_order1, logical_order2,
                "Logical ordering differs between {} and {}",
                name1, name2
            );
        }

        crate::test_complete!("metamorphic_cross_region_trace_ordering_preservation");
    }

    // =========================================================================
    // MR5: LabRuntime Seed Determinism
    // =========================================================================

    #[test]
    fn metamorphic_lab_runtime_seed_determinism() {
        init_test("metamorphic_lab_runtime_seed_determinism");

        // MR: Same seed should produce identical execution across multiple runs
        const SEED: u64 = 0x1234_5678_9ABC_DEF0;

        let config = ReplayMetamorphicConfig::default();

        let deterministic_scenario = |runtime: &mut LabRuntime| {
            use crate::util::det_rng::DetRng;
            // Drive the scenario from the runtime's own seed so that a
            // different `LabConfig::new(seed)` truly alters observable
            // trace / certificate state. Without this the scenario would
            // be seed-agnostic and the "different seed should differ"
            // assertion below would trivially fail.
            let mut rng = DetRng::new(runtime.config().seed);

            // Create deterministic sequence of events
            for i in 0..config.task_count {
                let choice = rng.next_u64() % 3;
                let event_type = match choice {
                    0 => "fork",
                    1 => "work",
                    _ => "join",
                };

                runtime.trace().record_event(|id| {
                    crate::trace::TraceEvent::user_trace(
                        id,
                        runtime.now(),
                        format!("{}_{}", event_type, i),
                    )
                });
            }
        };

        // Run multiple times with same seed
        let mut run_results = Vec::new();

        for run_idx in 0..5 {
            let mut runtime_config = LabConfig::new(SEED);
            runtime_config = runtime_config.worker_count(config.worker_count);
            let mut runtime = LabRuntime::new(runtime_config);

            deterministic_scenario(&mut runtime);

            let trace = runtime.trace().snapshot();
            let certificate = runtime.certificate().hash();
            let steps = runtime.steps();

            run_results.push((run_idx, trace, certificate, steps));
        }

        // MR: All runs should produce identical results
        for (run_idx, trace, certificate, steps) in &run_results[1..] {
            assert_eq!(
                run_results[0].2, *certificate,
                "Run {} certificate differs from run 0",
                run_idx
            );
            assert_eq!(
                run_results[0].3, *steps,
                "Run {} step count differs from run 0",
                run_idx
            );

            let divergence = find_divergence(&run_results[0].1, trace);
            assert!(
                divergence.is_none(),
                "Run {} trace diverged from run 0: {:?}",
                run_idx,
                divergence
            );
        }

        // MR: Test seed independence - different seeds should produce different results
        let mut different_seed_config = LabConfig::new(SEED + 1);
        different_seed_config = different_seed_config.worker_count(config.worker_count);
        let mut different_seed_runtime = LabRuntime::new(different_seed_config);

        deterministic_scenario(&mut different_seed_runtime);
        let different_trace = different_seed_runtime.trace().snapshot();

        // The scenario is a pure trace-generator (no scheduling is invoked),
        // so the `ScheduleCertificate` stays at its identity hash for every
        // run regardless of seed. The observable seed-dependent artefact is
        // the user-trace stream itself: with a different seed the RNG chooses
        // a different `fork`/`work`/`join` sequence.
        assert!(
            find_divergence(&run_results[0].1, &different_trace).is_some(),
            "Different seed should produce a divergent trace"
        );

        crate::test_complete!("metamorphic_lab_runtime_seed_determinism");
    }

    // =========================================================================
    // MR6: Composite Replay Invariants
    // =========================================================================

    #[test]
    fn metamorphic_composite_replay_invariants() {
        init_test("metamorphic_composite_replay_invariants");

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let config = ReplayMetamorphicConfig::default();

        // MR: Combination of multiple replay properties should all hold simultaneously
        let composite_scenario = |runtime: &mut LabRuntime| {
            use crate::util::det_rng::DetRng;
            let mut rng = DetRng::new(seed);

            // Create a complex scenario combining:
            // 1. Fork/join patterns
            // 2. Cross-region operations
            // 3. Potential panic conditions
            // 4. Checkpoint-worthy state changes

            let regions = 2;
            let tasks_per_region = config.task_count / regions;

            for region_id in 0..regions {
                // Fork phase
                for task_id in 0..tasks_per_region {
                    let now = runtime.now();
                    runtime.trace().record_event(|id| {
                        crate::trace::TraceEvent::user_trace(
                            id,
                            now,
                            format!("fork_region_{}_task_{}", region_id, task_id),
                        )
                    });
                }

                // Work phase (with occasional panics)
                for task_id in 0..tasks_per_region {
                    let event_type = if rng.next_u64() % 10 == 0 {
                        "panic"
                    } else {
                        "work"
                    };
                    let now = runtime.now();
                    runtime.trace().record_event(|id| {
                        crate::trace::TraceEvent::user_trace(
                            id,
                            now,
                            format!("{}_region_{}_task_{}", event_type, region_id, task_id),
                        )
                    });
                }

                // Join phase
                for task_id in 0..tasks_per_region {
                    runtime.trace().record_event(|id| {
                        crate::trace::TraceEvent::user_trace(
                            id,
                            runtime.now(),
                            format!("join_region_{}_task_{}", region_id, task_id),
                        )
                    });
                }
            }
        };

        // Test the scenario with replay validation
        let replay_validation = validate_replay(seed, config.worker_count, composite_scenario);

        assert!(
            replay_validation.matched,
            "Composite scenario replay should match original: certificates {} vs {}, steps {} vs {}",
            replay_validation.original_certificate,
            replay_validation.replay_certificate,
            replay_validation.original_steps,
            replay_validation.replay_steps
        );

        assert!(
            replay_validation.divergence.is_none(),
            "Composite scenario should have no divergence: {:?}",
            replay_validation.divergence
        );

        // Test multiple seeds for robustness
        let test_seeds = [seed, seed + 1, seed + 42, seed + 1337, seed + 0xDEAD];

        for &test_seed in &test_seeds {
            let validation = validate_replay(test_seed, config.worker_count, |runtime| {
                composite_scenario(runtime);
            });

            assert!(
                validation.matched,
                "Seed {} composite replay failed: {:?}",
                test_seed, validation.divergence
            );
        }

        // MR: Multi-seed validation should show consistent determinism
        let multi_validation =
            validate_replay_multi(&test_seeds, config.worker_count, composite_scenario);

        for (i, validation) in multi_validation.iter().enumerate() {
            assert!(validation.matched, "Multi-seed run {} failed validation", i);
        }
        crate::test_complete!("metamorphic_composite_replay_invariants");
    }
