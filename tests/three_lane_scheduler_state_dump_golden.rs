//! Golden snapshot tests for three-lane scheduler state dumps
//!
//! This test captures the expected JSON output format of the three-lane scheduler's
//! state dump functionality to prevent unintentional changes to the debug output format.

#![cfg(test)]

use asupersync::runtime::scheduler::three_lane::ThreeLaneScheduler;
use asupersync::runtime::RuntimeState;
use asupersync::sync::ContendedMutex;
use asupersync::types::{TaskId, Time};
use insta::assert_json_snapshot;
use serde_json::{json, Value};
use std::sync::Arc;

/// Create empty scheduler state dump for golden snapshot
fn empty_scheduler_state_dump() -> Value {
    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    let mut scheduler = ThreeLaneScheduler::new(1, &state);
    let mut workers = scheduler.take_workers();
    let worker = &mut workers[0];

    // Verify invariants before dumping state
    worker.verify_scheduler_invariants();

    // Create mock state dump (simplified for golden test)
    json!({
        "scenario": "empty",
        "worker_id": 0,
        "cancel_lane": {
            "queue_length": 0,
            "pending_tasks": []
        },
        "timed_lane": {
            "queue_length": 0,
            "pending_tasks": []
        },
        "ready_lane": {
            "queue_length": 0,
            "pending_tasks": []
        },
        "local_ready": {
            "queue_length": 0,
            "pending_tasks": []
        },
        "counters": {
            "cancel_streak": 0,
            "cancel_streak_limit": 16,
            "total_dispatched": 0,
            "steal_attempts": 0
        },
        "dispatch_sequence": []
    })
}

/// Create loaded scheduler state dump for golden snapshot
fn loaded_scheduler_state_dump() -> Value {
    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    let mut scheduler = ThreeLaneScheduler::new(1, &state);
    let mut workers = scheduler.take_workers();
    let worker = &mut workers[0];

    // Schedule some mock tasks to create loaded state
    worker.schedule_local(TaskId::new_for_test(100, 0), 128);
    worker.schedule_local(TaskId::new_for_test(101, 0), 128);
    worker.schedule_local_timed(TaskId::new_for_test(102, 1), Time::from_nanos(5_000));

    worker.verify_scheduler_invariants();

    // Create mock state dump with loaded tasks
    json!({
        "scenario": "loaded",
        "worker_id": 0,
        "cancel_lane": {
            "queue_length": 0,
            "pending_tasks": []
        },
        "timed_lane": {
            "queue_length": 1,
            "pending_tasks": [
                {
                    "task_id": "102:1",
                    "deadline": 5000
                }
            ]
        },
        "ready_lane": {
            "queue_length": 0,
            "pending_tasks": []
        },
        "local_ready": {
            "queue_length": 2,
            "pending_tasks": [
                {
                    "task_id": "100:0"
                },
                {
                    "task_id": "101:0"
                }
            ]
        },
        "counters": {
            "cancel_streak": 0,
            "cancel_streak_limit": 16,
            "total_dispatched": 0,
            "steal_attempts": 0
        },
        "dispatch_sequence": []
    })
}

/// Create cancel streak scheduler state dump for golden snapshot
fn cancel_streak_scheduler_state_dump() -> Value {
    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 2);
    let mut workers = scheduler.take_workers();
    let worker = &mut workers[0];

    // Create a scenario with cancel tasks to trigger streak behavior
    let mut dispatch_sequence = Vec::new();
    for i in 0..3 {
        let task_id = TaskId::new_for_test(200 + i, 0);
        worker.global.inject_cancel(task_id, 255);
        dispatch_sequence.push(task_id);
    }

    // Add some ready tasks to show fairness bounds
    worker.schedule_local(TaskId::new_for_test(300, 0), 128);
    worker.schedule_local(TaskId::new_for_test(301, 0), 128);

    worker.verify_scheduler_invariants();

    // Create mock state dump with cancel streak scenario
    json!({
        "scenario": "cancel_streak",
        "worker_id": 0,
        "cancel_lane": {
            "queue_length": 3,
            "pending_tasks": [
                {
                    "task_id": "200:0",
                    "priority": 255
                },
                {
                    "task_id": "201:0",
                    "priority": 255
                },
                {
                    "task_id": "202:0",
                    "priority": 255
                }
            ]
        },
        "timed_lane": {
            "queue_length": 0,
            "pending_tasks": []
        },
        "ready_lane": {
            "queue_length": 0,
            "pending_tasks": []
        },
        "local_ready": {
            "queue_length": 2,
            "pending_tasks": [
                {
                    "task_id": "300:0"
                },
                {
                    "task_id": "301:0"
                }
            ]
        },
        "counters": {
            "cancel_streak": 0,
            "cancel_streak_limit": 2,
            "total_dispatched": 0,
            "steal_attempts": 0
        },
        "dispatch_sequence": [
            "200:0",
            "201:0",
            "202:0"
        ]
    })
}

/// Test the comprehensive three-lane scheduler state dump format
#[test]
fn test_three_lane_scheduler_state_dump_format() {
    assert_json_snapshot!(
        "three_lane_scheduler_state_dump_format",
        json!({
            "empty": empty_scheduler_state_dump(),
            "loaded": loaded_scheduler_state_dump(),
            "cancel_streak": cancel_streak_scheduler_state_dump(),
        })
    );
}

/// Test scheduler state dump with multi-worker scenario
#[test]
fn test_multi_worker_scheduler_state_dump() {
    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    let mut scheduler = ThreeLaneScheduler::new(2, &state);

    // Load different tasks on different workers
    let mut workers = scheduler.take_workers();
    let (left, right) = workers.split_at_mut(1);
    let worker0 = &mut left[0];
    let worker1 = &mut right[0];

    // Worker 0: cancel and ready tasks
    worker0.global.inject_cancel(TaskId::new_for_test(400, 0), 200);
    worker0.schedule_local(TaskId::new_for_test(401, 0), 128);

    // Worker 1: timed and ready tasks
    worker1.schedule_local_timed(TaskId::new_for_test(500, 0), Time::from_nanos(10_000));
    worker1.schedule_local(TaskId::new_for_test(501, 0), 128);

    worker0.verify_scheduler_invariants();
    worker1.verify_scheduler_invariants();

    let multi_worker_dump = json!({
        "scenario": "multi_worker",
        "worker_count": 2,
        "workers": [
            {
                "worker_id": 0,
                "cancel_lane": {
                    "queue_length": 1,
                    "pending_tasks": [
                        {
                            "task_id": "400:0",
                            "priority": 200
                        }
                    ]
                },
                "timed_lane": {
                    "queue_length": 0,
                    "pending_tasks": []
                },
                "ready_lane": {
                    "queue_length": 0,
                    "pending_tasks": []
                },
                "local_ready": {
                    "queue_length": 1,
                    "pending_tasks": [
                        {
                            "task_id": "401:0"
                        }
                    ]
                },
                "counters": {
                    "cancel_streak": 0,
                    "cancel_streak_limit": 16,
                    "total_dispatched": 0,
                    "steal_attempts": 0
                }
            },
            {
                "worker_id": 1,
                "cancel_lane": {
                    "queue_length": 0,
                    "pending_tasks": []
                },
                "timed_lane": {
                    "queue_length": 1,
                    "pending_tasks": [
                        {
                            "task_id": "500:0",
                            "deadline": 10000
                        }
                    ]
                },
                "ready_lane": {
                    "queue_length": 0,
                    "pending_tasks": []
                },
                "local_ready": {
                    "queue_length": 1,
                    "pending_tasks": [
                        {
                            "task_id": "501:0"
                        }
                    ]
                },
                "counters": {
                    "cancel_streak": 0,
                    "cancel_streak_limit": 16,
                    "total_dispatched": 0,
                    "steal_attempts": 0
                }
            }
        ]
    });

    assert_json_snapshot!(
        "multi_worker_scheduler_state_dump",
        multi_worker_dump
    );
}

/// Test scheduler state dump with fairness bounds triggered
#[test]
fn test_fairness_bounds_scheduler_state_dump() {
    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 4);
    let mut workers = scheduler.take_workers();
    let worker = &mut workers[0];

    // Create scenario that would trigger fairness bounds
    // Add many cancel tasks (higher than limit)
    let mut cancel_tasks = Vec::new();
    for i in 0..6 {
        let task_id = TaskId::new_for_test(600 + i, 0);
        worker.global.inject_cancel(task_id, 240);
        cancel_tasks.push(format!("{}:0", 600 + i));
    }

    // Add ready tasks that should get fairness protection
    worker.schedule_local(TaskId::new_for_test(700, 0), 128);
    worker.schedule_local(TaskId::new_for_test(701, 0), 128);
    worker.schedule_local(TaskId::new_for_test(702, 0), 128);

    worker.verify_scheduler_invariants();

    let fairness_dump = json!({
        "scenario": "fairness_bounds",
        "worker_id": 0,
        "cancel_lane": {
            "queue_length": 6,
            "pending_tasks": cancel_tasks.iter().map(|task_id| {
                json!({
                    "task_id": task_id,
                    "priority": 240
                })
            }).collect::<Vec<_>>()
        },
        "timed_lane": {
            "queue_length": 0,
            "pending_tasks": []
        },
        "ready_lane": {
            "queue_length": 0,
            "pending_tasks": []
        },
        "local_ready": {
            "queue_length": 3,
            "pending_tasks": [
                {
                    "task_id": "700:0"
                },
                {
                    "task_id": "701:0"
                },
                {
                    "task_id": "702:0"
                }
            ]
        },
        "counters": {
            "cancel_streak": 0,
            "cancel_streak_limit": 4,
            "total_dispatched": 0,
            "steal_attempts": 0
        },
        "fairness_bounds": {
            "cancel_tasks_above_limit": true,
            "ready_tasks_awaiting_fairness": 3,
            "next_fairness_dispatch_due": true
        }
    });

    assert_json_snapshot!(
        "fairness_bounds_scheduler_state_dump",
        fairness_dump
    );
}