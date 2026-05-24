//! Contract tests for deterministic swarm replay lab scenarios.

use asupersync::lab::{
    SWARM_AGENT_RUN_SCHEMA_VERSION, SWARM_PRESSURE_SCHEMA_VERSION, SWARM_REPLAY_SCHEMA_VERSION,
    SwarmAgentRunEventKind, SwarmAgentRunScenario, SwarmDiskPressureLevel,
    SwarmDiskPressureTransition, SwarmPressureEventKind, SwarmPressureLane, SwarmPressureScenario,
    SwarmRchWorkerEvent, SwarmRchWorkerEventKind, SwarmReplayError, SwarmReplayEventKind,
    SwarmReplayScenario, SwarmReplayTaskStatus, run_swarm_agent_run_scenario,
    run_swarm_pressure_scenario, run_swarm_replay_scenario,
};

fn cancellation_scenario(seed: u64) -> SwarmReplayScenario {
    SwarmReplayScenario {
        scenario_id: "swarm-cancel-cascade".to_string(),
        seed,
        worker_count: 3,
        region_count: 3,
        tasks_per_region: 5,
        yields_per_task: 8,
        yield_jitter: 3,
        channel_capacity: 6,
        messages_per_task: 3,
        artifact_bytes_per_task: 128,
        cancel_after_steps: Some(4),
        max_steps: 20_000,
    }
}

fn completion_scenario(seed: u64) -> SwarmReplayScenario {
    SwarmReplayScenario {
        scenario_id: "swarm-normal-completion".to_string(),
        seed,
        worker_count: 2,
        region_count: 2,
        tasks_per_region: 4,
        yields_per_task: 2,
        yield_jitter: 4,
        channel_capacity: 8,
        messages_per_task: 2,
        artifact_bytes_per_task: 64,
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

#[test]
fn swarm_replay_summary_is_byte_stable_for_same_seed() {
    let scenario = cancellation_scenario(0x5A5A_2026);
    let first = run_swarm_replay_scenario(&scenario).expect("first swarm replay run");
    let second = run_swarm_replay_scenario(&scenario).expect("second swarm replay run");

    assert_eq!(first, second, "same seed and knobs must replay identically");
    assert_eq!(first.schema_version, SWARM_REPLAY_SCHEMA_VERSION);
    assert!(first.quiescent, "cancel cascade must drain to quiescence");
    assert_eq!(first.task_count, scenario.task_count());
    assert_eq!(first.scheduled_task_count, scenario.task_count());
    assert_eq!(first.terminal_task_count, scenario.task_count());
    assert_eq!(first.non_terminal_task_count, 0);
    assert!(first.cancellation_requests > 0);
    assert!(first.invariant_violations.is_empty());
    assert!(
        first
            .event_log
            .iter()
            .any(|event| event.kind == SwarmReplayEventKind::CancellationRequested),
        "summary must record runtime cancellation requests"
    );
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
fn swarm_replay_normal_completion_emits_artifact_and_backlog_summary() {
    let scenario = completion_scenario(0xC0FF_EE11);
    let summary = run_swarm_replay_scenario(&scenario).expect("normal completion run");

    assert!(summary.quiescent);
    assert_eq!(summary.cancellation_requests, 0);
    assert_eq!(summary.task_count, scenario.task_count());
    assert_eq!(summary.terminal_task_count, scenario.task_count());
    assert_eq!(summary.non_terminal_task_count, 0);
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
