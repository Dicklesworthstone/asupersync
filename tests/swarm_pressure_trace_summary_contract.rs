//! Contract tests for swarm pressure trace summaries.

use asupersync::lab::{
    SWARM_REPLAY_SCHEMA_VERSION, SwarmDiskPressureLevel, SwarmDiskPressureTransition,
    SwarmPressureTraceVerdict, SwarmReplayAdmissionDecision, SwarmReplayScenario,
    run_swarm_replay_scenario, summarize_swarm_replay_trace, summarize_swarm_trace_artifact_json,
};
use serde_json::{Value, json};

fn healthy_replay_scenario() -> SwarmReplayScenario {
    SwarmReplayScenario {
        scenario_id: "trace-summary-healthy".to_string(),
        seed: 0x57A9_E001,
        worker_count: 2,
        cohort_count: 1,
        region_count: 2,
        tasks_per_region: 3,
        yields_per_task: 2,
        yield_jitter: 1,
        channel_capacity: 8,
        messages_per_task: 2,
        semaphore_permits_per_task: 1,
        pool_slots_per_task: 1,
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
        max_steps: 10_000,
    }
}

fn cancellation_storm_scenario() -> SwarmReplayScenario {
    SwarmReplayScenario {
        scenario_id: "trace-summary-cancel-storm".to_string(),
        seed: 0x57A9_CACE,
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
        cancel_after_steps: Some(2),
        max_steps: 20_000,
    }
}

fn admission_rejection_scenario() -> SwarmReplayScenario {
    SwarmReplayScenario {
        scenario_id: "trace-summary-admission-rejection".to_string(),
        seed: 0x57A9_A11D,
        region_count: 2,
        tasks_per_region: 5,
        region_task_admission_limit: Some(2),
        region_over_limit_decision: SwarmReplayAdmissionDecision::Shed,
        ..healthy_replay_scenario()
    }
}

fn projection(value: &Value) -> Value {
    json!({
        "verdict": value["verdict"],
        "scenario_id": value["scenario_id"],
        "required_fields_present": value["required_fields_present"],
        "missing_required_fields": value["missing_required_fields"],
        "regions_declared": value["region_lifecycle"]["regions_declared"],
        "scheduled_tasks": value["task_lifecycle"]["scheduled_tasks"],
        "task_leaks": value["task_lifecycle"]["task_leaks"],
        "losers_drained": value["cancellation"]["losers_drained"],
        "obligations_fields_present": value["obligations"]["fields_present"],
        "unresolved_obligations": value["obligations"]["unresolved_obligations"],
        "admission_shed": value["admission"]["shed"],
        "queue_peak": value["queue_pressure"]["peak_queue_depth"],
    })
}

#[test]
fn healthy_replay_trace_summary_has_stable_json_and_text() {
    let replay = run_swarm_replay_scenario(&healthy_replay_scenario()).expect("healthy replay");
    let summary = summarize_swarm_replay_trace(&replay);
    let summary_json = serde_json::to_value(&summary).expect("summary json");
    let text = asupersync::lab::render_swarm_pressure_trace_text(&summary);

    eprintln!("{text}");

    assert_eq!(summary.verdict, SwarmPressureTraceVerdict::Pass);
    assert!(summary.required_fields_present);
    assert!(summary.obligation_leak_suspects.is_empty());
    assert_eq!(
        summary.obligations.committed_obligations + summary.obligations.aborted_obligations,
        replay.obligation_commits + replay.obligation_aborts
    );
    assert_eq!(
        projection(&summary_json),
        json!({
            "verdict": "pass",
            "scenario_id": "trace-summary-healthy",
            "required_fields_present": true,
            "missing_required_fields": [],
            "regions_declared": 2,
            "scheduled_tasks": 6,
            "task_leaks": 0,
            "losers_drained": true,
            "obligations_fields_present": true,
            "unresolved_obligations": 0,
            "admission_shed": 0,
            "queue_peak": 3,
        })
    );
    assert!(text.contains("verdict: Pass required_fields_present=true missing=none"));
    assert!(text.contains("obligation_leak_suspects:\n- none"));
}

#[test]
fn cancellation_storm_trace_summary_proves_losers_drained() {
    let replay =
        run_swarm_replay_scenario(&cancellation_storm_scenario()).expect("cancellation replay");
    let summary = summarize_swarm_replay_trace(&replay);
    let text = asupersync::lab::render_swarm_pressure_trace_text(&summary);

    eprintln!("{text}");

    assert_eq!(summary.verdict, SwarmPressureTraceVerdict::Pass);
    assert!(summary.cancellation.cancellation_requests > 0);
    assert!(summary.cancellation.cancelled_tasks > 0);
    assert!(summary.cancellation.losers_drained);
    assert!(!summary.longest_drains.is_empty());
    assert_eq!(summary.obligations.unresolved_obligations, 0);
    assert!(text.contains("longest_drains:\n- scope=global:cancellation"));
}

#[test]
fn admission_rejection_trace_summary_routes_budget_followup() {
    let replay =
        run_swarm_replay_scenario(&admission_rejection_scenario()).expect("admission replay");
    let summary = summarize_swarm_replay_trace(&replay);
    let text = asupersync::lab::render_swarm_pressure_trace_text(&summary);

    eprintln!("{text}");

    assert_eq!(summary.verdict, SwarmPressureTraceVerdict::Pass);
    assert_eq!(summary.admission.shed, 2);
    assert!(summary.admission.first_rejection.is_some());
    assert!(
        summary
            .routing_hints
            .iter()
            .any(|hint| { hint.contains("first admission blocker") && hint.contains("rejected") })
    );
    assert!(text.contains("admission: accepted=0 deferred=0 shed=2"));
}

#[test]
fn deadlock_or_lost_wakeup_suspect_fails_with_route_hint() {
    let mut replay = run_swarm_replay_scenario(&healthy_replay_scenario()).expect("healthy replay");
    replay.quiescent = false;
    replay.non_terminal_task_count = 1;
    replay
        .invariant_violations
        .push("lost-wakeup suspect: notify waiter remained pending".to_string());

    let summary = summarize_swarm_replay_trace(&replay);
    let text = asupersync::lab::render_swarm_pressure_trace_text(&summary);

    eprintln!("{text}");

    assert_eq!(summary.verdict, SwarmPressureTraceVerdict::Fail);
    assert_eq!(
        summary.first_invariant_violation.as_deref(),
        Some("lost-wakeup suspect: notify waiter remained pending")
    );
    assert!(
        summary
            .routing_hints
            .iter()
            .any(|hint| hint.contains("quiescence owner"))
    );
    assert_eq!(summary.obligation_leak_suspects.len(), 1);
    assert_eq!(
        summary.obligation_leak_suspects[0].route_hint,
        "src/obligation and src/cancel"
    );
    assert!(text.contains("first_invariant_violation: lost-wakeup suspect"));
}

#[test]
fn missing_obligation_fields_never_render_false_green() {
    let replay = run_swarm_replay_scenario(&healthy_replay_scenario()).expect("healthy replay");
    let mut value = serde_json::to_value(&replay).expect("replay json");
    let object = value.as_object_mut().expect("replay object");
    object.remove("obligation_commits");
    object.remove("obligation_aborts");

    let summary = summarize_swarm_trace_artifact_json(&value);
    let text = asupersync::lab::render_swarm_pressure_trace_text(&summary);

    eprintln!("{text}");

    assert_eq!(summary.verdict, SwarmPressureTraceVerdict::Incomplete);
    assert!(!summary.required_fields_present);
    assert_eq!(
        summary.missing_required_fields,
        vec![
            "obligation_commits".to_string(),
            "obligation_aborts".to_string(),
        ]
    );
    assert!(text.contains("verdict: Incomplete"));
}

#[test]
fn pressure_lab_artifact_summarizes_throttle_but_stays_incomplete_without_obligations() {
    use asupersync::lab::{
        SwarmPressureScenario, SwarmRchWorkerEvent, SwarmRchWorkerEventKind,
        run_swarm_pressure_scenario, summarize_swarm_pressure_trace,
    };

    let pressure = run_swarm_pressure_scenario(&SwarmPressureScenario {
        scenario_id: "trace-summary-pressure-red-disk".to_string(),
        seed: 0x57A9_D15C,
        worker_count: 8,
        interactive_tasks: 12,
        proof_tasks: 10,
        cleanup_requests: 2,
        rch_workers_initial: 2,
        disk_pressure_transitions: vec![
            SwarmDiskPressureTransition {
                at_step: 0,
                level: SwarmDiskPressureLevel::Green,
            },
            SwarmDiskPressureTransition {
                at_step: 1,
                level: SwarmDiskPressureLevel::Red,
            },
        ],
        rch_worker_events: vec![SwarmRchWorkerEvent {
            at_step: 2,
            kind: SwarmRchWorkerEventKind::Loss,
            worker_delta: 2,
        }],
        interactive_latency_bound_steps: 3,
        max_steps: 10_000,
    })
    .expect("pressure run");

    let summary = summarize_swarm_pressure_trace(&pressure);
    let text = asupersync::lab::render_swarm_pressure_trace_text(&summary);

    eprintln!("{text}");

    assert_eq!(summary.verdict, SwarmPressureTraceVerdict::Incomplete);
    assert!(!summary.required_fields_present);
    assert!(!summary.missing_required_fields.is_empty());
    assert!(summary.admission.proof_throttled > 0);
    assert!(summary.queue_pressure.peak_queue_depth > 0);
    assert!(text.contains("obligations: fields_present=false"));
}

#[test]
fn replay_json_entrypoint_matches_typed_summary_when_fields_are_present() {
    let replay = run_swarm_replay_scenario(&healthy_replay_scenario()).expect("healthy replay");
    let value = serde_json::to_value(&replay).expect("replay json");
    let from_json = summarize_swarm_trace_artifact_json(&value);
    let typed = summarize_swarm_replay_trace(&replay);

    assert_eq!(from_json.verdict, typed.verdict);
    assert_eq!(from_json.source_schema_version, SWARM_REPLAY_SCHEMA_VERSION);
    assert_eq!(from_json.task_lifecycle, typed.task_lifecycle);
    assert_eq!(from_json.obligations, typed.obligations);
}

#[test]
fn unsupported_schema_is_incomplete_without_claiming_present_schema_missing() {
    let value = json!({
        "schema_version": "asupersync.future-trace.v99",
        "scenario_id": "trace-summary-unknown-schema",
        "seed": 99,
    });

    let summary = summarize_swarm_trace_artifact_json(&value);
    let text = asupersync::lab::render_swarm_pressure_trace_text(&summary);

    eprintln!("{text}");

    assert_eq!(summary.verdict, SwarmPressureTraceVerdict::Incomplete);
    assert_eq!(summary.source_schema_version, "asupersync.future-trace.v99");
    assert!(summary.missing_required_fields.is_empty());
    assert!(
        summary
            .first_invariant_violation
            .as_deref()
            .is_some_and(|violation| violation.contains("unsupported swarm trace schema version"))
    );
    assert!(text.contains("source: Unknown"));
}
