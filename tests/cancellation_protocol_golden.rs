//! Golden snapshot for cancellation protocol trace v2.

use asupersync::lab::oracle::CancellationProtocolOracle;
use asupersync::record::task::TaskState;
use asupersync::types::{Budget, CancelReason, MAX_MASK_DEPTH, Outcome, RegionId, TaskId, Time};
use insta::assert_json_snapshot;
use serde_json::{Value, json};

fn task_id(idx: u32) -> TaskId {
    TaskId::new_for_test(idx, 0)
}

fn region_id(idx: u32) -> RegionId {
    RegionId::new_for_test(idx, 0)
}

fn render_trace_v2(
    scenario_id: &str,
    oracle: &CancellationProtocolOracle,
    region: RegionId,
    task: TaskId,
    cancel_request: Option<Value>,
    transitions: Vec<Value>,
) -> Value {
    let mut violations = oracle
        .all_violations()
        .into_iter()
        .map(|violation| violation.to_string())
        .collect::<Vec<_>>();
    violations.sort();

    let check = match oracle.check() {
        Ok(()) => "ok".to_string(),
        Err(violation) => violation.to_string(),
    };

    json!({
        "version": 2,
        "scenario_id": scenario_id,
        "summary": {
            "check": check,
            "region_count": oracle.region_count(),
            "cancelled_region_count": oracle.cancel_count(),
            "task_count": 1,
            "violation_count": violations.len(),
        },
        "regions": [
            {
                "region": region.to_string(),
                "cancelled": oracle.cancelled_regions().contains_key(&region),
                "cancel_reason": oracle
                    .cancelled_regions()
                    .get(&region)
                    .map(|reason| format!("{:?}", reason.kind)),
            }
        ],
        "tasks": [
            {
                "task": task.to_string(),
                "region": region.to_string(),
                "state": format!("{:?}", oracle.task_state(task).expect("task state")),
                "mask_depth": oracle.task_mask_depth(task).expect("task mask depth"),
                "has_cancel_request": oracle.has_cancel_request(task),
                "cancel_request": cancel_request,
                "transitions": transitions,
            }
        ],
        "violations": violations,
    })
}

fn happy_trace_v2() -> Value {
    let mut oracle = CancellationProtocolOracle::new();
    let task = task_id(0);
    let region = region_id(0);
    let reason = CancelReason::timeout();
    let cleanup_budget = Budget::INFINITE;
    let transitions = vec![
        json!({"from": "Created", "to": "Running", "time_nanos": 0}),
        json!({"from": "Running", "to": "CancelRequested", "time_nanos": 100}),
        json!({"from": "CancelRequested", "to": "Cancelling", "time_nanos": 200}),
        json!({"from": "Cancelling", "to": "Finalizing", "time_nanos": 300}),
        json!({"from": "Finalizing", "to": "CompletedCancelled", "time_nanos": 400}),
    ];

    oracle.on_region_create(region, None);
    oracle.on_task_create(task, region);
    oracle.on_transition(task, &TaskState::Created, &TaskState::Running, Time::ZERO);
    oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(100));
    oracle.on_transition(
        task,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget,
        },
        Time::from_nanos(100),
    );
    oracle.on_cancel_ack(task, Time::from_nanos(200));
    oracle.on_transition(
        task,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget,
        },
        Time::from_nanos(200),
    );
    oracle.on_transition(
        task,
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget,
        },
        Time::from_nanos(300),
    );
    oracle.on_transition(
        task,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        Time::from_nanos(400),
    );

    render_trace_v2(
        "happy_path",
        &oracle,
        region,
        task,
        Some(json!({
            "requested_at_nanos": 100,
            "reason": "Timeout",
            "acknowledged": true,
            "polls_since": 0,
        })),
        transitions,
    )
}

fn late_cancel_trace_v2() -> Value {
    let mut oracle = CancellationProtocolOracle::new();
    let task = task_id(0);
    let region = region_id(0);
    let reason = CancelReason::timeout();
    let cleanup_budget = Budget::INFINITE;
    let transitions = vec![
        json!({"from": "Created", "to": "Running", "time_nanos": 0}),
        json!({"from": "Running", "to": "CancelRequested", "time_nanos": 100}),
    ];

    oracle.on_region_create(region, None);
    oracle.on_task_create(task, region);
    oracle.on_transition(task, &TaskState::Created, &TaskState::Running, Time::ZERO);
    oracle.on_cancel_request(task, reason.clone(), Time::from_nanos(100));
    oracle.on_transition(
        task,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason,
            cleanup_budget,
        },
        Time::from_nanos(100),
    );
    for _ in 0..=(MAX_MASK_DEPTH + 1) {
        oracle.on_task_poll(task);
    }

    render_trace_v2(
        "late_cancel_ack",
        &oracle,
        region,
        task,
        Some(json!({
            "requested_at_nanos": 100,
            "reason": "Timeout",
            "acknowledged": false,
            "polls_since": MAX_MASK_DEPTH + 2,
        })),
        transitions,
    )
}

fn reentrant_trace_v2() -> Value {
    let mut oracle = CancellationProtocolOracle::new();
    let task = task_id(0);
    let region = region_id(0);
    let cleanup_budget = Budget::INFINITE;
    let initial_reason = CancelReason::user("stop");
    let strengthened_reason = CancelReason::shutdown();
    let transitions = vec![
        json!({"from": "Running", "to": "CancelRequested", "time_nanos": 100}),
        json!({"from": "CancelRequested", "to": "CancelRequested", "time_nanos": 150}),
        json!({"from": "CancelRequested", "to": "Cancelling", "time_nanos": 200}),
        json!({"from": "Cancelling", "to": "Finalizing", "time_nanos": 300}),
        json!({"from": "Finalizing", "to": "CompletedCancelled", "time_nanos": 400}),
    ];

    oracle.on_region_create(region, None);
    oracle.on_task_create(task, region);
    oracle.on_cancel_request(task, initial_reason.clone(), Time::from_nanos(100));
    oracle.on_transition(
        task,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: initial_reason,
            cleanup_budget,
        },
        Time::from_nanos(100),
    );
    oracle.on_cancel_request(task, strengthened_reason.clone(), Time::from_nanos(150));
    oracle.on_transition(
        task,
        &TaskState::CancelRequested {
            reason: CancelReason::user("stop"),
            cleanup_budget,
        },
        &TaskState::CancelRequested {
            reason: strengthened_reason.clone(),
            cleanup_budget,
        },
        Time::from_nanos(150),
    );
    oracle.on_cancel_ack(task, Time::from_nanos(175));
    oracle.on_transition(
        task,
        &TaskState::CancelRequested {
            reason: strengthened_reason.clone(),
            cleanup_budget,
        },
        &TaskState::Cancelling {
            reason: strengthened_reason.clone(),
            cleanup_budget,
        },
        Time::from_nanos(200),
    );
    oracle.on_transition(
        task,
        &TaskState::Cancelling {
            reason: strengthened_reason.clone(),
            cleanup_budget,
        },
        &TaskState::Finalizing {
            reason: strengthened_reason.clone(),
            cleanup_budget,
        },
        Time::from_nanos(300),
    );
    oracle.on_transition(
        task,
        &TaskState::Finalizing {
            reason: strengthened_reason.clone(),
            cleanup_budget,
        },
        &TaskState::Completed(Outcome::Cancelled(strengthened_reason)),
        Time::from_nanos(400),
    );

    render_trace_v2(
        "reentrant_cancel_strengthening",
        &oracle,
        region,
        task,
        Some(json!({
            "requested_at_nanos": 100,
            "reason": "Shutdown",
            "acknowledged": true,
            "polls_since": 0,
        })),
        transitions,
    )
}

#[test]
fn trace_bundle_v2() {
    let golden = json!({
        "happy_path": happy_trace_v2(),
        "late_cancel_ack": late_cancel_trace_v2(),
        "reentrant_cancel_strengthening": reentrant_trace_v2(),
    });

    assert_json_snapshot!("trace_bundle_v2", golden);
}
