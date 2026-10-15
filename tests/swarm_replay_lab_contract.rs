//! Contract tests for deterministic swarm replay lab scenarios.

use asupersync::lab::{
    SWARM_AGENT_RUN_SCHEMA_VERSION, SWARM_HANDOFF_VERIFICATION_SCHEMA_VERSION,
    SWARM_PRESSURE_SCHEMA_VERSION, SWARM_REPLAY_SCHEMA_VERSION, SwarmAgentRunEventKind,
    SwarmAgentRunScenario, SwarmDiskPressureLevel, SwarmDiskPressureTransition,
    SwarmHandoffCapsule, SwarmHandoffCommit, SwarmHandoffDecision, SwarmHandoffDirtyOwner,
    SwarmHandoffDirtyPath, SwarmHandoffInboxAck, SwarmHandoffProofCommand, SwarmHandoffReservation,
    SwarmPressureEventKind, SwarmPressureLane, SwarmPressureScenario, SwarmRchWorkerEvent,
    SwarmRchWorkerEventKind, SwarmReplayAdmissionDecision, SwarmReplayAdmissionDrainResult,
    SwarmReplayBudgetClass, SwarmReplayError, SwarmReplayEventKind, SwarmReplayScenario,
    SwarmReplayTaskStatus, run_swarm_agent_run_scenario, run_swarm_pressure_scenario,
    run_swarm_replay_scenario, verify_swarm_handoff_capsule,
};

fn cancellation_scenario(seed: u64) -> SwarmReplayScenario {
    SwarmReplayScenario {
        scenario_id: "swarm-cancel-cascade".to_string(),
        seed,
        worker_count: 3,
        cohort_count: 3,
        region_count: 3,
        tasks_per_region: 5,
        yields_per_task: 8,
        yield_jitter: 3,
        channel_capacity: 6,
        messages_per_task: 3,
        semaphore_permits_per_task: 1,
        pool_slots_per_task: 1,
        obligations_per_task: 3,
        timer_ticks_per_task: 2,
        cancellation_tree_depth: 3,
        artifact_bytes_per_task: 128,
        region_task_admission_limit: None,
        region_over_limit_decision: SwarmReplayAdmissionDecision::Shed,
        region_memory_bytes_per_task: 1024,
        region_queue_depth_units_per_task: 1,
        region_blocking_pool_units_per_task: 1,
        region_cleanup_poll_quota_per_task: 1,
        cancel_after_steps: Some(4),
        max_steps: 20_000,
    }
}

fn completion_scenario(seed: u64) -> SwarmReplayScenario {
    SwarmReplayScenario {
        scenario_id: "swarm-normal-completion".to_string(),
        seed,
        worker_count: 2,
        cohort_count: 1,
        region_count: 2,
        tasks_per_region: 4,
        yields_per_task: 2,
        yield_jitter: 4,
        channel_capacity: 8,
        messages_per_task: 2,
        semaphore_permits_per_task: 1,
        pool_slots_per_task: 2,
        obligations_per_task: 2,
        timer_ticks_per_task: 1,
        cancellation_tree_depth: 2,
        artifact_bytes_per_task: 64,
        region_task_admission_limit: None,
        region_over_limit_decision: SwarmReplayAdmissionDecision::Shed,
        region_memory_bytes_per_task: 1024,
        region_queue_depth_units_per_task: 1,
        region_blocking_pool_units_per_task: 1,
        region_cleanup_poll_quota_per_task: 1,
        cancel_after_steps: None,
        max_steps: 20_000,
    }
}

fn pressure_scenario(seed: u64) -> SwarmPressureScenario {
    SwarmPressureScenario {
        scenario_id: "swarm-pressure-64-worker-red-disk".to_string(),
        seed,
        worker_count: 64,
        interactive_tasks: 128,
        proof_tasks: 96,
        cleanup_requests: 4,
        rch_workers_initial: 16,
        disk_pressure_transitions: vec![
            SwarmDiskPressureTransition {
                at_step: 0,
                level: SwarmDiskPressureLevel::Green,
            },
            SwarmDiskPressureTransition {
                at_step: 3,
                level: SwarmDiskPressureLevel::Red,
            },
            SwarmDiskPressureTransition {
                at_step: 18,
                level: SwarmDiskPressureLevel::Green,
            },
        ],
        rch_worker_events: vec![
            SwarmRchWorkerEvent {
                at_step: 5,
                kind: SwarmRchWorkerEventKind::Loss,
                worker_delta: 16,
            },
            SwarmRchWorkerEvent {
                at_step: 24,
                kind: SwarmRchWorkerEventKind::Recovery,
                worker_delta: 12,
            },
        ],
        interactive_latency_bound_steps: 4,
        max_steps: 50_000,
    }
}

fn agent_scale_pressure_scenario(seed: u64, agent_count: usize) -> SwarmPressureScenario {
    let proof_tasks = agent_count / 2;
    let cleanup_requests = (agent_count / 25).max(1);
    SwarmPressureScenario {
        scenario_id: format!("asw-pressure-{agent_count}-agent-workload"),
        seed,
        worker_count: agent_count.clamp(4, 64),
        interactive_tasks: agent_count,
        proof_tasks,
        cleanup_requests,
        rch_workers_initial: (agent_count / 8).clamp(2, 24),
        disk_pressure_transitions: vec![
            SwarmDiskPressureTransition {
                at_step: 0,
                level: SwarmDiskPressureLevel::Green,
            },
            SwarmDiskPressureTransition {
                at_step: 1,
                level: SwarmDiskPressureLevel::Red,
            },
            SwarmDiskPressureTransition {
                at_step: 32,
                level: SwarmDiskPressureLevel::Green,
            },
        ],
        rch_worker_events: vec![
            SwarmRchWorkerEvent {
                at_step: 4,
                kind: SwarmRchWorkerEventKind::Loss,
                worker_delta: (agent_count / 8).clamp(2, 24),
            },
            SwarmRchWorkerEvent {
                at_step: 40,
                kind: SwarmRchWorkerEventKind::Recovery,
                worker_delta: (agent_count / 10).max(2),
            },
        ],
        interactive_latency_bound_steps: 4,
        max_steps: 50_000,
    }
}

fn agent_run_scenario(seed: u64) -> SwarmAgentRunScenario {
    SwarmAgentRunScenario {
        scenario_id: "asw-agent-run-claim-proof-blocker-crash".to_string(),
        seed,
        agent_count: 6,
        rch_workers: 2,
        rch_refusal_agent: Some(1),
        validation_blocker_agent: Some(3),
        crash_agent: Some(5),
        max_steps: 20_000,
    }
}

fn replay_scale_scenario(
    label: &str,
    seed: u64,
    worker_count: usize,
    cohort_count: usize,
    region_count: usize,
    tasks_per_region: usize,
) -> SwarmReplayScenario {
    SwarmReplayScenario {
        scenario_id: format!("swarm-replay-{label}"),
        seed,
        worker_count,
        cohort_count,
        region_count,
        tasks_per_region,
        yields_per_task: 2,
        yield_jitter: 2,
        channel_capacity: tasks_per_region.saturating_mul(2).max(4),
        messages_per_task: 2,
        semaphore_permits_per_task: 1,
        pool_slots_per_task: 1,
        obligations_per_task: 2,
        timer_ticks_per_task: 2,
        cancellation_tree_depth: 3,
        artifact_bytes_per_task: 32,
        region_task_admission_limit: None,
        region_over_limit_decision: SwarmReplayAdmissionDecision::Shed,
        region_memory_bytes_per_task: 1024,
        region_queue_depth_units_per_task: 1,
        region_blocking_pool_units_per_task: 1,
        region_cleanup_poll_quota_per_task: 1,
        cancel_after_steps: None,
        max_steps: 80_000,
    }
}

fn fresh_handoff_capsule() -> SwarmHandoffCapsule {
    SwarmHandoffCapsule {
        capsule_id: "handoff-asw10-0001".to_string(),
        current_agent: "GreenMountain".to_string(),
        generated_at_epoch_secs: 1_779_660_000,
        expected_docs_hash: Some("docs:ag-v1".to_string()),
        observed_docs_hash: Some("docs:ag-v1".to_string()),
        expected_main_hash: Some("main:abc123".to_string()),
        observed_main_hash: Some("main:abc123".to_string()),
        claimed_bead_ids: vec!["asupersync-oxqrae.10".to_string()],
        active_reservations: vec![SwarmHandoffReservation {
            path_pattern: "src/lab/swarm_replay.rs".to_string(),
            holder_agent: "GreenMountain".to_string(),
            observed_at_epoch_secs: 1_779_660_000,
            expires_at_epoch_secs: 1_779_663_600,
        }],
        dirty_paths: Vec::new(),
        proof_commands: vec![SwarmHandoffProofCommand {
            command: "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_p6 cargo test -p asupersync --test swarm_replay_lab_contract handoff_capsule".to_string(),
            remote_required: true,
            remote_observed: true,
            exit_status: Some(0),
            first_blocker: None,
        }],
        inbox_acks: vec![SwarmHandoffInboxAck {
            message_id: 15_914,
            ack_required: true,
            acknowledged: true,
        }],
        pushed_commits: vec![SwarmHandoffCommit {
            commit_id: "abc1234".to_string(),
            pushed_to_main: true,
            synced_to_master: true,
            recorded_in_beads_comment: true,
        }],
        first_blocker: None,
    }
}

#[test]
fn swarm_replay_summary_is_byte_stable_for_same_seed() {
    let scenario = cancellation_scenario(0x5A5A_2026);
    let first = run_swarm_replay_scenario(&scenario).expect("first swarm replay run");
    let second = run_swarm_replay_scenario(&scenario).expect("second swarm replay run");

    assert_eq!(first, second, "same seed and knobs must replay identically");
    assert_eq!(first.schema_version, SWARM_REPLAY_SCHEMA_VERSION);
    assert!(first.quiescent, "cancel cascade must drain to quiescence");
    assert_eq!(first.worker_count, scenario.worker_count);
    assert_eq!(first.cohort_count, scenario.cohort_count);
    assert_eq!(first.task_count, scenario.task_count());
    assert_eq!(first.scheduled_task_count, scenario.task_count());
    assert_eq!(first.terminal_task_count, scenario.task_count());
    assert_eq!(first.non_terminal_task_count, 0);
    assert!(first.cancellation_requests > 0);
    assert!(first.cancellation_drain_steps > 0);
    assert_eq!(
        first.cancellation_tree_depth,
        scenario.cancellation_tree_depth
    );
    assert_eq!(
        first.channel_reservations,
        scenario.task_count() * scenario.messages_per_task
    );
    assert_eq!(
        first.channel_commits + first.channel_aborts,
        first.channel_reservations
    );
    assert_eq!(
        first.semaphore_acquires,
        scenario.task_count() * scenario.semaphore_permits_per_task
    );
    assert_eq!(first.semaphore_releases, first.semaphore_acquires);
    assert_eq!(
        first.pool_checkouts,
        scenario.task_count() * scenario.pool_slots_per_task
    );
    assert_eq!(first.pool_checkins, first.pool_checkouts);
    assert_eq!(
        first.obligation_commits + first.obligation_aborts,
        scenario.task_count() * scenario.obligations_per_task
    );
    assert_eq!(first.timer_registrations, scenario.task_count());
    assert_eq!(
        first.timer_wakeups,
        scenario.task_count() * scenario.timer_ticks_per_task
    );
    assert_eq!(first.trace_digest.len(), 16);
    assert!(first.invariant_violations.is_empty());
    assert!(
        first
            .event_log
            .iter()
            .any(|event| event.kind == SwarmReplayEventKind::CancellationRequested),
        "summary must record runtime cancellation requests"
    );
    for kind in [
        SwarmReplayEventKind::SemaphoreAcquired,
        SwarmReplayEventKind::PoolSlotCheckedOut,
        SwarmReplayEventKind::MessageReserved,
        SwarmReplayEventKind::TimerAdvanced,
        SwarmReplayEventKind::ObligationAborted,
        SwarmReplayEventKind::MessageAborted,
    ] {
        assert!(
            first.event_log.iter().any(|event| event.kind == kind),
            "summary must record {kind:?}"
        );
    }
    assert!(
        first
            .task_outcomes
            .iter()
            .any(|outcome| outcome.status == SwarmReplayTaskStatus::Cancelled),
        "at least one task must observe cancellation"
    );

    let first_json = serde_json::to_string_pretty(&first).expect("serialize first summary");
    let second_json = serde_json::to_string_pretty(&second).expect("serialize second summary");
    assert_eq!(
        first_json, second_json,
        "serialized replay summaries must be byte stable"
    );
}

#[test]
fn swarm_pressure_simulator_models_64_workers_red_disk_and_rch_recovery() {
    let scenario = pressure_scenario(0x64C0_A11D_2026);
    let first = run_swarm_pressure_scenario(&scenario).expect("first pressure run");
    let second = run_swarm_pressure_scenario(&scenario).expect("second pressure run");

    assert_eq!(first, second, "same seed and knobs must replay identically");
    assert_eq!(first.schema_version, SWARM_PRESSURE_SCHEMA_VERSION);
    assert_eq!(first.worker_count, 64);
    assert_eq!(first.interactive_tasks, scenario.interactive_tasks);
    assert_eq!(first.proof_tasks, scenario.proof_tasks);
    assert_eq!(first.cleanup_requests, scenario.cleanup_requests);
    assert!(
        first.quiescent,
        "pressure simulator must drain to quiescence"
    );
    assert_eq!(
        first.task_leaks, 0,
        "tracked LabRuntime tasks must not leak"
    );
    assert_eq!(first.non_terminal_task_count, 0);
    assert_eq!(first.terminal_task_count, first.scheduled_task_count);
    assert!(
        first.max_interactive_admission_latency_steps <= first.interactive_latency_bound_steps,
        "interactive lane latency must remain bounded under red disk/rch pressure"
    );
    assert!(
        first.proof_throttled_count > 0,
        "bursty proof work must be throttled while disk/rch pressure is unsafe"
    );
    assert_eq!(
        first.cleanup_authorization_required_count, scenario.cleanup_requests,
        "cleanup requests must remain explicit human-authorization handoffs"
    );
    assert_eq!(
        first.auto_delete_command_count, 0,
        "simulator must never emit cleanup auto-delete commands"
    );
    assert_eq!(first.disk_pressure_transition_count, 3);
    assert_eq!(first.rch_worker_loss_events, 1);
    assert_eq!(first.rch_worker_recovery_events, 1);
    assert!(first.invariant_violations.is_empty());

    for kind in [
        SwarmPressureEventKind::DiskPressureChanged,
        SwarmPressureEventKind::RchWorkersLost,
        SwarmPressureEventKind::RchWorkersRecovered,
        SwarmPressureEventKind::InteractiveAdmitted,
        SwarmPressureEventKind::ProofThrottled,
        SwarmPressureEventKind::CleanupRequested,
    ] {
        assert!(
            first.event_log.iter().any(|event| event.kind == kind),
            "pressure event log must include {kind:?}"
        );
    }
    assert!(
        first.event_log.iter().any(|event| {
            event.kind == SwarmPressureEventKind::InteractiveAdmitted
                && event.lane == Some(SwarmPressureLane::Interactive)
                && event.disk_pressure == SwarmDiskPressureLevel::Red
        }),
        "sustained interactive work must remain admissible during red disk pressure"
    );
    assert!(
        first.event_log.iter().all(|event| {
            event.kind != SwarmPressureEventKind::CleanupRequested
                || (!event.cleanup_authorized && event.auto_delete_command_count == 0)
        }),
        "cleanup events must be report-only until explicit authorization"
    );

    let first_json = serde_json::to_vec(&first).expect("serialize first pressure summary");
    let second_json = serde_json::to_vec(&second).expect("serialize second pressure summary");
    assert_eq!(
        first_json, second_json,
        "pressure summary JSON must be byte stable"
    );
}

#[test]
fn swarm_pressure_simulator_bounds_10_50_200_agent_workloads() {
    for (seed, agent_count) in [
        (0xA5A5_0010, 10usize),
        (0xA5A5_0050, 50usize),
        (0xA5A5_0200, 200usize),
    ] {
        let scenario = agent_scale_pressure_scenario(seed, agent_count);
        let first = run_swarm_pressure_scenario(&scenario).expect("first agent-scale run");
        let second = run_swarm_pressure_scenario(&scenario).expect("second agent-scale run");

        assert_eq!(
            first, second,
            "{agent_count}-agent scenario must replay identically"
        );
        assert_eq!(first.schema_version, SWARM_PRESSURE_SCHEMA_VERSION);
        assert_eq!(first.interactive_tasks, agent_count);
        assert!(
            first.quiescent,
            "{agent_count}-agent pressure run must drain to quiescence"
        );
        assert_eq!(
            first.task_leaks, 0,
            "{agent_count}-agent pressure run must not leak tasks"
        );
        assert_eq!(first.non_terminal_task_count, 0);
        assert_eq!(first.terminal_task_count, first.scheduled_task_count);
        assert!(
            first.max_interactive_admission_latency_steps <= first.interactive_latency_bound_steps,
            "{agent_count}-agent interactive admission must remain bounded"
        );
        assert_eq!(
            first.cleanup_authorization_required_count, scenario.cleanup_requests,
            "{agent_count}-agent cleanup work must stay an explicit handoff"
        );
        assert_eq!(
            first.auto_delete_command_count, 0,
            "{agent_count}-agent simulator must never emit auto-delete commands"
        );
        assert!(
            first.proof_throttled_count > 0,
            "{agent_count}-agent proof lane must throttle under unsafe disk/rch pressure"
        );
        assert!(
            first
                .event_log
                .iter()
                .filter(|event| event.kind == SwarmPressureEventKind::CleanupRequested)
                .all(|event| !event.cleanup_authorized && event.auto_delete_command_count == 0),
            "{agent_count}-agent cleanup events must remain report-only"
        );
        assert!(
            first.event_log.iter().any(|event| {
                event.kind == SwarmPressureEventKind::ProofThrottled
                    && (event.disk_pressure == SwarmDiskPressureLevel::Red
                        || event.rch_workers_available == 0)
            }),
            "{agent_count}-agent proof throttling must cite unsafe disk/rch pressure"
        );
        let max_queue_depth = first
            .event_log
            .iter()
            .map(|event| event.queue_depth)
            .max()
            .unwrap_or(0);
        assert!(
            max_queue_depth < agent_count,
            "{agent_count}-agent modeled queue depth must stay within submitted work"
        );

        let first_json = serde_json::to_vec(&first).expect("serialize first agent-scale summary");
        let second_json =
            serde_json::to_vec(&second).expect("serialize second agent-scale summary");
        assert_eq!(
            first_json, second_json,
            "{agent_count}-agent JSON summary must be byte stable"
        );
    }
}

#[test]
fn deterministic_agent_run_lab_models_claim_reserve_proof_commit_blocker_and_recovery() {
    let scenario = agent_run_scenario(0xA5A5_A5A5_2026);
    let first = run_swarm_agent_run_scenario(&scenario).expect("first agent-run lab");
    let second = run_swarm_agent_run_scenario(&scenario).expect("second agent-run lab");

    assert_eq!(first, second, "same seed and knobs must replay identically");
    assert_eq!(first.schema_version, SWARM_AGENT_RUN_SCHEMA_VERSION);
    assert_eq!(first.agent_count, scenario.agent_count);
    assert!(first.quiescent, "agent-run lab must drain to quiescence");
    assert_eq!(first.scheduled_task_count, scenario.agent_count);
    assert_eq!(first.terminal_task_count, scenario.agent_count);
    assert_eq!(first.non_terminal_task_count, 0);
    assert_eq!(first.task_leaks, 0);
    assert_eq!(first.bead_claim_count, scenario.agent_count);
    assert_eq!(first.file_reservations_acquired, scenario.agent_count);
    assert_eq!(first.file_reservations_released, scenario.agent_count);
    assert_eq!(first.mail_message_count, scenario.agent_count);
    assert_eq!(first.rch_proof_attempt_count, scenario.agent_count - 1);
    assert_eq!(first.rch_remote_refusal_count, 1);
    assert_eq!(first.validation_blocker_count, 1);
    assert_eq!(first.crashed_agent_count, 1);
    assert_eq!(first.recovery_handoff_count, 3);
    assert_eq!(first.proof_pass_count, 3);
    assert_eq!(first.commit_count, first.proof_pass_count);
    assert!(first.no_duplicate_ownership);
    assert!(first.no_leaked_reservations);
    assert!(first.no_false_green_proof);
    assert!(first.non_mutating);
    assert!(!first.forbidden_actions.runs_cargo);
    assert!(!first.forbidden_actions.runs_git_mutation);
    assert!(!first.forbidden_actions.runs_beads_mutation);
    assert!(!first.forbidden_actions.runs_agent_mail_mutation);
    assert!(!first.forbidden_actions.runs_destructive_command);
    assert!(
        first
            .replay_command
            .contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_p6"),
        "replay command must preserve the pane-6 target dir"
    );
    assert!(
        first.replay_command.contains(
            "deterministic_agent_run_lab_models_claim_reserve_proof_commit_blocker_and_recovery"
        ),
        "replay command must point at this contract"
    );
    assert_eq!(
        first.first_blocker.as_deref(),
        Some("rch remote required refused local fallback: no admissible worker")
    );

    for kind in [
        SwarmAgentRunEventKind::BeadClaimed,
        SwarmAgentRunEventKind::FileReserved,
        SwarmAgentRunEventKind::MailSent,
        SwarmAgentRunEventKind::RchProofStarted,
        SwarmAgentRunEventKind::RchProofRemoteRefused,
        SwarmAgentRunEventKind::ValidationBlocked,
        SwarmAgentRunEventKind::RchProofPassed,
        SwarmAgentRunEventKind::CommitRecorded,
        SwarmAgentRunEventKind::AgentCrashed,
        SwarmAgentRunEventKind::RecoveryHandoffEmitted,
        SwarmAgentRunEventKind::FileReservationReleased,
    ] {
        assert!(
            first.event_log.iter().any(|event| event.kind == kind),
            "agent-run log must include {kind:?}"
        );
    }
    assert!(
        first
            .event_log
            .iter()
            .all(|event| !event.mutates_real_services),
        "deterministic lab events must not mutate live services"
    );
    assert!(
        first
            .event_log
            .iter()
            .filter(|event| event.kind == SwarmAgentRunEventKind::CommitRecorded)
            .all(|event| event
                .commit_id
                .as_deref()
                .is_some_and(|id| id.starts_with("simulated-main-"))),
        "commits must be simulated ids gated by green proof"
    );
    assert!(
        first
            .event_log
            .iter()
            .filter(|event| event.kind == SwarmAgentRunEventKind::RecoveryHandoffEmitted)
            .all(|event| event
                .artifact_refs
                .iter()
                .any(|artifact| artifact.ends_with("/handoff.json"))),
        "failure handoffs must carry replay artifact refs"
    );

    let first_json = serde_json::to_vec(&first).expect("serialize first agent run");
    let second_json = serde_json::to_vec(&second).expect("serialize second agent run");
    assert_eq!(
        first_json, second_json,
        "agent-run JSON summary must be byte stable"
    );
}

#[test]
fn handoff_capsule_verifier_allows_fresh_self_contained_capsule() {
    let capsule = fresh_handoff_capsule();
    let first = verify_swarm_handoff_capsule(&capsule);
    let second = verify_swarm_handoff_capsule(&capsule);

    assert_eq!(first, second, "verification must be deterministic");
    assert_eq!(
        first.schema_version,
        SWARM_HANDOFF_VERIFICATION_SCHEMA_VERSION
    );
    assert_eq!(first.capsule_id, capsule.capsule_id);
    assert_eq!(first.decision, SwarmHandoffDecision::Continue);
    assert!(first.reasons.is_empty());
    assert_eq!(first.stale_evidence_count, 0);
    assert_eq!(first.coordination_required_count, 0);
    assert_eq!(first.unsafe_issue_count, 0);
    assert_eq!(first.next_action, "continue from capsule");
    assert!(first.self_contained);
    assert!(
        !first.mutates_external_state,
        "handoff verification must not mutate Git, Beads, Agent Mail, or RCH"
    );

    let first_json = serde_json::to_vec(&first).expect("serialize first handoff verification");
    let second_json = serde_json::to_vec(&second).expect("serialize second handoff verification");
    assert_eq!(
        first_json, second_json,
        "handoff verifier JSON must be byte stable"
    );
}

#[test]
fn handoff_capsule_verifier_fails_closed_for_compaction_gaps() {
    let mut stale_docs = fresh_handoff_capsule();
    stale_docs.observed_docs_hash = Some("docs:changed".to_string());
    let verification = verify_swarm_handoff_capsule(&stale_docs);
    assert_eq!(
        verification.decision,
        SwarmHandoffDecision::NarrowRefreshRequired
    );
    assert!(
        verification
            .reasons
            .iter()
            .any(|reason| reason.code == "stale_docs_hash")
    );

    let mut missing_proof = fresh_handoff_capsule();
    missing_proof.proof_commands.clear();
    let verification = verify_swarm_handoff_capsule(&missing_proof);
    assert_eq!(
        verification.decision,
        SwarmHandoffDecision::UnsafeToContinue
    );
    assert!(
        verification
            .reasons
            .iter()
            .any(|reason| reason.code == "missing_proof_command")
    );
    assert!(!verification.self_contained);

    let mut local_fallback = fresh_handoff_capsule();
    local_fallback.proof_commands[0].remote_observed = false;
    let verification = verify_swarm_handoff_capsule(&local_fallback);
    assert_eq!(
        verification.decision,
        SwarmHandoffDecision::UnsafeToContinue
    );
    assert!(
        verification
            .reasons
            .iter()
            .any(|reason| reason.code == "missing_remote_proof")
    );

    let mut stale_reservation = fresh_handoff_capsule();
    stale_reservation.active_reservations[0].expires_at_epoch_secs =
        stale_reservation.active_reservations[0].observed_at_epoch_secs;
    let verification = verify_swarm_handoff_capsule(&stale_reservation);
    assert_eq!(
        verification.decision,
        SwarmHandoffDecision::NarrowRefreshRequired
    );
    assert!(
        verification
            .reasons
            .iter()
            .any(|reason| reason.code == "stale_reservation")
    );

    let mut dirty_owned = fresh_handoff_capsule();
    dirty_owned.dirty_paths.push(SwarmHandoffDirtyPath {
        path: "src/lab/swarm_replay.rs".to_string(),
        owner: SwarmHandoffDirtyOwner::CurrentAgent,
        owner_agent: Some("GreenMountain".to_string()),
    });
    let verification = verify_swarm_handoff_capsule(&dirty_owned);
    assert_eq!(
        verification.decision,
        SwarmHandoffDecision::NarrowRefreshRequired
    );
    assert!(
        verification
            .reasons
            .iter()
            .any(|reason| reason.code == "dirty_owned_path")
    );

    let mut dirty_peer = fresh_handoff_capsule();
    dirty_peer.dirty_paths.push(SwarmHandoffDirtyPath {
        path: "src/atp/inbox/mod.rs".to_string(),
        owner: SwarmHandoffDirtyOwner::PeerAgent,
        owner_agent: Some("SunnyWillow".to_string()),
    });
    let verification = verify_swarm_handoff_capsule(&dirty_peer);
    assert_eq!(verification.decision, SwarmHandoffDecision::CoordinateFirst);
    assert!(
        verification
            .reasons
            .iter()
            .any(|reason| reason.code == "dirty_peer_path")
    );

    let mut uncommented_commit = fresh_handoff_capsule();
    uncommented_commit.pushed_commits[0].recorded_in_beads_comment = false;
    let verification = verify_swarm_handoff_capsule(&uncommented_commit);
    assert_eq!(verification.decision, SwarmHandoffDecision::CoordinateFirst);
    assert!(
        verification
            .reasons
            .iter()
            .any(|reason| reason.code == "pushed_commit_missing_comment")
    );

    let mut unresolved_ack = fresh_handoff_capsule();
    unresolved_ack.inbox_acks[0].acknowledged = false;
    let verification = verify_swarm_handoff_capsule(&unresolved_ack);
    assert_eq!(verification.decision, SwarmHandoffDecision::CoordinateFirst);
    assert!(
        verification
            .reasons
            .iter()
            .any(|reason| reason.code == "unresolved_inbox_ack")
    );
    assert!(
        !verification.mutates_external_state,
        "verifier must remain classification-only even on unsafe handoffs"
    );
}

#[test]
fn swarm_replay_normal_completion_emits_artifact_and_backlog_summary() {
    let scenario = completion_scenario(0xC0FF_EE11);
    let summary = run_swarm_replay_scenario(&scenario).expect("normal completion run");

    assert!(summary.quiescent);
    assert_eq!(summary.cancellation_requests, 0);
    assert_eq!(summary.task_count, scenario.task_count());
    assert_eq!(summary.terminal_task_count, scenario.task_count());
    assert_eq!(summary.non_terminal_task_count, 0);
    assert_eq!(
        summary.channel_commits,
        scenario.task_count() * scenario.messages_per_task
    );
    assert_eq!(summary.channel_aborts, 0);
    assert_eq!(
        summary.obligation_commits,
        scenario.task_count() * scenario.obligations_per_task
    );
    assert_eq!(summary.obligation_aborts, 0);
    assert_eq!(summary.timer_registrations, scenario.task_count());
    assert_eq!(
        summary.timer_wakeups,
        scenario.task_count() * scenario.timer_ticks_per_task
    );
    assert_eq!(summary.task_outcomes.len(), scenario.task_count());
    assert!(
        summary
            .task_outcomes
            .iter()
            .all(|outcome| outcome.status == SwarmReplayTaskStatus::Completed),
        "non-cancelled scenario should complete every task"
    );
    assert!(
        summary.artifact_bytes_emitted
            >= scenario
                .artifact_bytes_per_task
                .saturating_mul(scenario.task_count()),
        "completed tasks must emit modeled artifact bytes"
    );
    assert!(
        summary.channel_backlog_peak <= scenario.channel_capacity,
        "backlog accounting must respect modeled channel capacity"
    );
    assert_eq!(
        summary.shrink_hint.event_prefix_len,
        summary.event_log.len(),
        "non-failing scenario shrink prefix should cover the full log"
    );
}

#[test]
fn swarm_replay_region_admission_accepts_exact_limit_without_leaks() {
    let mut scenario = completion_scenario(0xAD1D_0001);
    scenario.region_task_admission_limit = Some(scenario.tasks_per_region);
    scenario.cancel_after_steps = None;

    let summary = run_swarm_replay_scenario(&scenario).expect("exact admission scenario");

    assert_eq!(summary.task_count, scenario.task_count());
    assert_eq!(summary.scheduled_task_count, scenario.task_count());
    assert_eq!(summary.admitted_task_count, scenario.task_count());
    assert_eq!(summary.rejected_task_count, 0);
    assert_eq!(summary.deferred_task_count, 0);
    assert_eq!(summary.shed_task_count, 0);
    assert_eq!(summary.admission_cancelled_task_count, 0);
    assert_eq!(summary.terminal_task_count, summary.scheduled_task_count);
    assert_eq!(summary.non_terminal_task_count, 0);
    assert!(summary.quiescent);
    assert_eq!(summary.admission_records.len(), scenario.region_count);
    assert!(
        summary.admission_records.iter().all(|record| {
            record.region_id.is_some()
                && record.budget_class == SwarmReplayBudgetClass::RunnableTaskSlots
                && record.decision == SwarmReplayAdmissionDecision::Accept
                && record.requested_tasks == scenario.tasks_per_region
                && record.admitted_tasks == scenario.tasks_per_region
                && record.rejected_tasks == 0
                && record.after_remaining_units == 0
                && record.refusal.is_none()
                && !record.cancellation_requested
                && record.drain_result == SwarmReplayAdmissionDrainResult::NotRequired
                && record.quiescence_verdict
        }),
        "exact-limit records must include region id, budget class, counters, and quiescence"
    );
    assert!(
        summary.event_log.iter().any(|event| {
            event.kind == SwarmReplayEventKind::AdmissionAccepted
                && event.region_id.is_some()
                && event.budget_class == Some(SwarmReplayBudgetClass::RunnableTaskSlots)
        }),
        "event log must include accepted admission evidence"
    );
}

#[test]
fn swarm_replay_region_admission_sheds_over_limit_without_scheduling_rejected_work() {
    let mut scenario = completion_scenario(0xAD1D_0002);
    scenario.region_count = 2;
    scenario.tasks_per_region = 5;
    scenario.region_task_admission_limit = Some(2);
    scenario.region_over_limit_decision = SwarmReplayAdmissionDecision::Shed;
    scenario.cancel_after_steps = None;

    let summary = run_swarm_replay_scenario(&scenario).expect("shed admission scenario");

    assert_eq!(summary.task_count, 10);
    assert_eq!(summary.scheduled_task_count, 4);
    assert_eq!(summary.admitted_task_count, 4);
    assert_eq!(summary.rejected_task_count, 6);
    assert_eq!(summary.shed_task_count, 6);
    assert_eq!(summary.deferred_task_count, 0);
    assert_eq!(summary.admission_cancelled_task_count, 0);
    assert_eq!(
        summary.channel_reservations,
        summary.scheduled_task_count * scenario.messages_per_task
    );
    assert_eq!(
        summary.obligation_commits + summary.obligation_aborts,
        summary.scheduled_task_count * scenario.obligations_per_task
    );
    assert_eq!(summary.terminal_task_count, summary.scheduled_task_count);
    assert_eq!(summary.non_terminal_task_count, 0);
    assert!(summary.quiescent);
    assert!(
        summary.admission_records.iter().all(|record| {
            record.decision == SwarmReplayAdmissionDecision::Shed
                && record.admitted_tasks == 2
                && record.rejected_tasks == 3
                && record.before_remaining_units == 2
                && record.after_remaining_units == 0
                && record.region_id.is_some()
                && record.quiescence_verdict
        }),
        "shed records must preserve over-limit counters and quiescence"
    );
    assert!(
        summary
            .event_log
            .iter()
            .any(|event| event.kind == SwarmReplayEventKind::AdmissionShed),
        "event log must include shed admission evidence"
    );
}

#[test]
fn swarm_replay_region_admission_defers_over_limit_without_resource_leaks() {
    let mut scenario = completion_scenario(0xAD1D_0005);
    scenario.region_count = 1;
    scenario.tasks_per_region = 6;
    scenario.region_task_admission_limit = Some(3);
    scenario.region_over_limit_decision = SwarmReplayAdmissionDecision::Defer;
    scenario.cancel_after_steps = None;

    let summary = run_swarm_replay_scenario(&scenario).expect("defer admission scenario");

    assert_eq!(summary.task_count, 6);
    assert_eq!(summary.scheduled_task_count, 3);
    assert_eq!(summary.admitted_task_count, 3);
    assert_eq!(summary.rejected_task_count, 3);
    assert_eq!(summary.deferred_task_count, 3);
    assert_eq!(summary.shed_task_count, 0);
    assert_eq!(summary.admission_cancelled_task_count, 0);
    assert_eq!(summary.terminal_task_count, summary.scheduled_task_count);
    assert_eq!(summary.non_terminal_task_count, 0);
    assert_eq!(
        summary.channel_reservations,
        summary.scheduled_task_count * scenario.messages_per_task
    );
    assert_eq!(
        summary.timer_registrations, summary.scheduled_task_count,
        "deferred work must not register timers or scheduler resources"
    );
    assert!(summary.quiescent);
    assert_eq!(summary.admission_records.len(), 1);
    let record = &summary.admission_records[0];
    assert_eq!(record.decision, SwarmReplayAdmissionDecision::Defer);
    assert_eq!(record.requested_tasks, 6);
    assert_eq!(record.admitted_tasks, 3);
    assert_eq!(record.rejected_tasks, 3);
    assert_eq!(record.before_remaining_units, 3);
    assert_eq!(record.after_remaining_units, 0);
    assert_eq!(
        record.drain_result,
        SwarmReplayAdmissionDrainResult::NotRequired
    );
    assert!(record.region_id.is_some());
    assert!(record.quiescence_verdict);
    assert!(
        summary
            .event_log
            .iter()
            .any(|event| event.kind == SwarmReplayEventKind::AdmissionDeferred),
        "event log must include deferred admission evidence"
    );
}

#[test]
fn swarm_replay_region_admission_cancels_admitted_prefix_and_drains() {
    let mut scenario = completion_scenario(0xAD1D_0003);
    scenario.region_count = 1;
    scenario.tasks_per_region = 5;
    scenario.yields_per_task = 8;
    scenario.yield_jitter = 0;
    scenario.region_task_admission_limit = Some(2);
    scenario.region_over_limit_decision = SwarmReplayAdmissionDecision::Cancel;
    scenario.cancel_after_steps = None;

    let summary = run_swarm_replay_scenario(&scenario).expect("cancel admission scenario");

    assert_eq!(summary.task_count, 5);
    assert_eq!(summary.scheduled_task_count, 2);
    assert_eq!(summary.admitted_task_count, 2);
    assert_eq!(summary.rejected_task_count, 3);
    assert_eq!(summary.admission_cancelled_task_count, 3);
    assert!(summary.cancellation_requests > 0);
    assert_eq!(summary.terminal_task_count, summary.scheduled_task_count);
    assert_eq!(summary.non_terminal_task_count, 0);
    assert!(summary.quiescent);
    assert!(
        summary
            .task_outcomes
            .iter()
            .any(|outcome| outcome.status == SwarmReplayTaskStatus::Cancelled),
        "admission cancellation must be observed by admitted tasks"
    );
    assert!(
        summary.admission_records.iter().all(|record| {
            record.decision == SwarmReplayAdmissionDecision::Cancel
                && record.cancellation_requested
                && record.drain_result == SwarmReplayAdmissionDrainResult::Quiescent
                && record.quiescence_verdict
        }),
        "cancel records must carry drain and quiescence evidence"
    );
    assert!(
        summary.event_log.iter().any(|event| {
            event.kind == SwarmReplayEventKind::CancellationRequested
                && event.budget_class == Some(SwarmReplayBudgetClass::CleanupDrainWork)
        }),
        "event log must include cancellation/drain evidence"
    );
}

#[test]
fn swarm_replay_region_admission_empty_budget_fails_closed_without_leaks() {
    let mut scenario = completion_scenario(0xAD1D_0004);
    scenario.region_count = 2;
    scenario.tasks_per_region = 3;
    scenario.region_task_admission_limit = Some(0);
    scenario.region_over_limit_decision = SwarmReplayAdmissionDecision::Cancel;
    scenario.cancel_after_steps = None;

    let summary = run_swarm_replay_scenario(&scenario).expect("empty admission scenario");

    assert_eq!(summary.task_count, 6);
    assert_eq!(summary.scheduled_task_count, 0);
    assert_eq!(summary.admitted_task_count, 0);
    assert_eq!(summary.rejected_task_count, 6);
    assert_eq!(summary.admission_cancelled_task_count, 6);
    assert_eq!(summary.terminal_task_count, 0);
    assert_eq!(summary.non_terminal_task_count, 0);
    assert_eq!(summary.channel_reservations, 0);
    assert_eq!(summary.obligation_commits + summary.obligation_aborts, 0);
    assert!(summary.quiescent);
    assert_eq!(summary.admission_records.len(), scenario.region_count);
    assert!(
        summary.admission_records.iter().all(|record| {
            record.region_id.is_none()
                && record.decision == SwarmReplayAdmissionDecision::Cancel
                && record.admitted_tasks == 0
                && record.rejected_tasks == scenario.tasks_per_region
                && record.refusal.is_some()
                && !record.cancellation_requested
                && record.drain_result == SwarmReplayAdmissionDrainResult::RefusedBeforeRegion
                && record.quiescence_verdict
        }),
        "empty budget must fail closed before region creation"
    );
}

#[test]
fn swarm_replay_models_resource_surfaces_for_small_medium_and_large_configs() {
    for scenario in [
        replay_scale_scenario("small", 0x5A11, 2, 1, 2, 3),
        replay_scale_scenario("medium", 0x5A12, 8, 2, 5, 10),
        replay_scale_scenario("large", 0x5A13, 64, 8, 10, 20),
    ] {
        let first = run_swarm_replay_scenario(&scenario).expect("first scale run");
        let second = run_swarm_replay_scenario(&scenario).expect("second scale run");
        let task_count = scenario.task_count();

        assert_eq!(
            first, second,
            "{} must replay byte-identically",
            scenario.scenario_id
        );
        assert!(first.quiescent, "{} must quiesce", scenario.scenario_id);
        assert_eq!(first.worker_count, scenario.worker_count);
        assert_eq!(first.cohort_count, scenario.cohort_count);
        assert_eq!(first.region_count, scenario.region_count);
        assert_eq!(first.task_count, task_count);
        assert_eq!(first.scheduled_task_count, task_count);
        assert_eq!(first.terminal_task_count, task_count);
        assert_eq!(first.non_terminal_task_count, 0);
        assert_eq!(
            first.channel_reservations,
            task_count * scenario.messages_per_task
        );
        assert_eq!(first.channel_commits, first.channel_reservations);
        assert_eq!(first.channel_aborts, 0);
        assert_eq!(
            first.semaphore_acquires,
            task_count * scenario.semaphore_permits_per_task
        );
        assert_eq!(first.semaphore_releases, first.semaphore_acquires);
        assert_eq!(
            first.pool_checkouts,
            task_count * scenario.pool_slots_per_task
        );
        assert_eq!(first.pool_checkins, first.pool_checkouts);
        assert_eq!(
            first.obligation_commits,
            task_count * scenario.obligations_per_task
        );
        assert_eq!(first.obligation_aborts, 0);
        assert_eq!(first.timer_registrations, task_count);
        assert_eq!(
            first.timer_wakeups,
            task_count * scenario.timer_ticks_per_task
        );
        assert_eq!(
            first.cancellation_tree_depth,
            scenario.cancellation_tree_depth
        );
        assert_eq!(first.cancellation_drain_steps, 0);
        assert_eq!(
            first.trace_digest,
            format!("{:016x}", first.trace_fingerprint)
        );
        assert!(
            first.invariant_violations.is_empty(),
            "{} must not produce runtime invariant violations",
            scenario.scenario_id
        );
        for kind in [
            SwarmReplayEventKind::SemaphoreAcquired,
            SwarmReplayEventKind::PoolSlotCheckedOut,
            SwarmReplayEventKind::MessageReserved,
            SwarmReplayEventKind::TimerAdvanced,
            SwarmReplayEventKind::MessageCommitted,
            SwarmReplayEventKind::ObligationCommitted,
            SwarmReplayEventKind::ArtifactEmitted,
            SwarmReplayEventKind::Completed,
        ] {
            assert!(
                first.event_log.iter().any(|event| event.kind == kind),
                "{} missing {kind:?}",
                scenario.scenario_id
            );
        }
    }
}

#[test]
fn swarm_replay_different_seed_changes_schedule_observation() {
    let first = run_swarm_replay_scenario(&completion_scenario(1)).expect("seed 1");
    let second = run_swarm_replay_scenario(&completion_scenario(2)).expect("seed 2");

    assert_ne!(
        first.completion_order, second.completion_order,
        "different seeds should expose different deterministic schedule observations"
    );
}

#[test]
fn swarm_replay_validation_fails_closed_for_bad_knobs() {
    let mut zero_capacity = cancellation_scenario(10);
    zero_capacity.channel_capacity = 0;
    assert_eq!(
        run_swarm_replay_scenario(&zero_capacity).unwrap_err(),
        SwarmReplayError::ZeroChannelCapacity
    );

    let mut runaway = cancellation_scenario(10);
    runaway.region_count = 101;
    runaway.tasks_per_region = 100;
    assert!(matches!(
        run_swarm_replay_scenario(&runaway),
        Err(SwarmReplayError::TooManyTasks { .. })
    ));

    let mut impossible_cancel = cancellation_scenario(10);
    impossible_cancel.cancel_after_steps = Some(impossible_cancel.max_steps);
    assert!(matches!(
        run_swarm_replay_scenario(&impossible_cancel),
        Err(SwarmReplayError::CancelStepBeyondMax { .. })
    ));

    let mut overflowing_jitter = cancellation_scenario(10);
    overflowing_jitter.yield_jitter = usize::MAX;
    assert_eq!(
        run_swarm_replay_scenario(&overflowing_jitter).unwrap_err(),
        SwarmReplayError::YieldJitterOverflow
    );
}
