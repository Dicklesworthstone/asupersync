//! Integration tests for ECOSYSTEM-PARITY G.3 console viewer behavior.

#![cfg(feature = "cli")]
#![allow(missing_docs)]

use std::process::Command;

use asupersync::observability::{
    TaskConsoleWireSnapshot, TaskDetailsWire, TaskRegionCountWire, TaskStateInfo, TaskSummaryWire,
};
use asupersync::types::{RegionId, TaskId, Time};
use tempfile::tempdir;

fn sample_snapshot() -> TaskConsoleWireSnapshot {
    let summary = TaskSummaryWire {
        total_tasks: 2,
        created: 0,
        running: 2,
        cancelling: 0,
        completed: 0,
        stuck_count: 0,
        by_region: vec![TaskRegionCountWire {
            region_id: RegionId::new_for_test(10, 0),
            task_count: 2,
        }],
    };
    let first = TaskDetailsWire {
        id: TaskId::new_for_test(1, 0),
        region_id: RegionId::new_for_test(10, 0),
        state: TaskStateInfo::Running,
        phase: "Running".to_string(),
        poll_count: 5,
        polls_remaining: 20,
        created_at: Time::from_nanos(10),
        age_nanos: 200,
        time_since_last_poll_nanos: Some(5),
        wake_pending: true,
        obligations: vec![],
        waiters: vec![],
    };
    let second = TaskDetailsWire {
        id: TaskId::new_for_test(3, 0),
        region_id: RegionId::new_for_test(10, 0),
        state: TaskStateInfo::Running,
        phase: "Running".to_string(),
        poll_count: 2,
        polls_remaining: 30,
        created_at: Time::from_nanos(20),
        age_nanos: 150,
        time_since_last_poll_nanos: None,
        wake_pending: false,
        obligations: vec![],
        waiters: vec![],
    };
    TaskConsoleWireSnapshot::new(Time::from_nanos(999), summary, vec![second, first])
}

fn asupersync_bin() -> String {
    std::env::var("CARGO_BIN_EXE_asupersync").expect("integration tests require asupersync binary")
}

#[test]
fn task_console_view_emits_json_summary_and_truncates_tasks() {
    let dir = tempdir().expect("tempdir");
    let snapshot_path = dir.path().join("task_console_snapshot.json");
    let snapshot = sample_snapshot();
    std::fs::write(
        &snapshot_path,
        snapshot.to_json().expect("serialize snapshot"),
    )
    .expect("write snapshot");

    let output = Command::new(asupersync_bin())
        .arg("--format")
        .arg("json")
        .arg("doctor")
        .arg("task-console-view")
        .arg("--snapshot")
        .arg(&snapshot_path)
        .arg("--max-tasks")
        .arg("1")
        .output()
        .expect("run asupersync doctor task-console-view");

    assert!(
        output.status.success(),
        "command should succeed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let payload: serde_json::Value = serde_json::from_str(stdout.trim()).expect("parse stdout");
    assert_eq!(payload["schema_matches_expected"], true);
    assert_eq!(payload["total_tasks"], 2);
    assert_eq!(payload["shown_tasks"], 1);
    assert_eq!(payload["truncated"], true);
    assert_eq!(payload["summary"]["total_tasks"], 2);
    assert_eq!(payload["tasks"].as_array().expect("tasks array").len(), 1);
}

#[test]
fn task_console_view_rejects_schema_mismatch_without_override() {
    let dir = tempdir().expect("tempdir");
    let snapshot_path = dir.path().join("task_console_snapshot_bad_schema.json");
    let mut snapshot = sample_snapshot();
    snapshot.schema_version = "asupersync.task_console_wire.experimental".to_string();
    std::fs::write(
        &snapshot_path,
        snapshot.to_json().expect("serialize snapshot"),
    )
    .expect("write snapshot");

    let output = Command::new(asupersync_bin())
        .arg("--format")
        .arg("json")
        .arg("doctor")
        .arg("task-console-view")
        .arg("--snapshot")
        .arg(&snapshot_path)
        .output()
        .expect("run asupersync doctor task-console-view");

    assert!(
        !output.status.success(),
        "command should fail on bad schema"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("Unexpected task-console schema version"),
        "stderr should include schema error, got: {stderr}"
    );
}
