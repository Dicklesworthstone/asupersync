//! Contract tests for ECOSYSTEM-PARITY G.1 task-inspector wire payloads.

#![allow(missing_docs)]

use std::collections::BTreeMap;

use asupersync::observability::{
    TASK_CONSOLE_WIRE_SCHEMA_V1, TaskConsoleWireSnapshot, TaskDetailsWire, TaskRegionCountWire,
    TaskStateInfo, TaskSummary, TaskSummaryWire,
};
use asupersync::types::{ObligationId, RegionId, TaskId, Time};

#[test]
fn wire_snapshot_schema_and_round_trip() {
    let summary = TaskSummaryWire {
        total_tasks: 2,
        created: 0,
        running: 2,
        cancelling: 0,
        completed: 0,
        stuck_count: 0,
        by_region: vec![TaskRegionCountWire {
            region_id: RegionId::new_for_test(7, 0),
            task_count: 2,
        }],
    };
    let task_a = TaskDetailsWire {
        id: TaskId::new_for_test(1, 0),
        region_id: RegionId::new_for_test(7, 0),
        state: TaskStateInfo::Running,
        phase: "Running".to_string(),
        poll_count: 5,
        polls_remaining: 15,
        created_at: Time::from_nanos(10),
        age_nanos: 30,
        time_since_last_poll_nanos: Some(5),
        wake_pending: true,
        obligations: vec![ObligationId::new_for_test(2, 0)],
        waiters: vec![TaskId::new_for_test(3, 0)],
    };
    let task_b = TaskDetailsWire {
        id: TaskId::new_for_test(8, 0),
        region_id: RegionId::new_for_test(7, 0),
        state: TaskStateInfo::Running,
        phase: "Running".to_string(),
        poll_count: 2,
        polls_remaining: 20,
        created_at: Time::from_nanos(12),
        age_nanos: 28,
        time_since_last_poll_nanos: None,
        wake_pending: false,
        obligations: vec![],
        waiters: vec![],
    };

    let snapshot =
        TaskConsoleWireSnapshot::new(Time::from_nanos(100), summary, vec![task_b, task_a]);
    assert!(snapshot.has_expected_schema());
    assert_eq!(snapshot.schema_version, TASK_CONSOLE_WIRE_SCHEMA_V1);
    assert_eq!(snapshot.tasks[0].id, TaskId::new_for_test(1, 0));
    assert_eq!(snapshot.tasks[1].id, TaskId::new_for_test(8, 0));

    let encoded = snapshot.to_json().expect("snapshot should encode");
    let decoded = TaskConsoleWireSnapshot::from_json(&encoded).expect("snapshot should decode");
    assert_eq!(decoded, snapshot);
}

#[test]
fn summary_wire_conversion_preserves_counts() {
    let mut by_region = BTreeMap::new();
    by_region.insert(RegionId::new_for_test(1, 0), 3);
    by_region.insert(RegionId::new_for_test(2, 0), 1);
    let summary = TaskSummary {
        total_tasks: 4,
        created: 1,
        running: 2,
        cancelling: 1,
        completed: 0,
        by_region,
        stuck_count: 1,
    };

    let wire = TaskSummaryWire::from(summary);
    assert_eq!(wire.total_tasks, 4);
    assert_eq!(wire.created, 1);
    assert_eq!(wire.running, 2);
    assert_eq!(wire.cancelling, 1);
    assert_eq!(wire.completed, 0);
    assert_eq!(wire.stuck_count, 1);
    assert_eq!(wire.by_region.len(), 2);
    assert_eq!(wire.by_region[0].region_id, RegionId::new_for_test(1, 0));
    assert_eq!(wire.by_region[0].task_count, 3);
    assert_eq!(wire.by_region[1].region_id, RegionId::new_for_test(2, 0));
    assert_eq!(wire.by_region[1].task_count, 1);
}
