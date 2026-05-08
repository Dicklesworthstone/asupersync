//! Contract tests for deterministic swarm replay lab scenarios.

use asupersync::lab::{
    SWARM_REPLAY_SCHEMA_VERSION, SwarmReplayError, SwarmReplayEventKind, SwarmReplayScenario,
    SwarmReplayTaskStatus, run_swarm_replay_scenario,
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
