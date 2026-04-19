//! Metamorphic testing for observability::task_inspector.
//!
//! Tests metamorphic relations for task inspector snapshots and state consistency
//! without requiring oracle problem solutions.
//!
//! Verified metamorphic relations:
//! 1. Snapshot captures all active tasks (completeness)
//! 2. Snapshot after cancel reflects state (cancellation consistency)
//! 3. Concurrent snapshots commutative (deterministic ordering)
//! 4. Wire format round-trip consistency (serialization)
//! 5. Summary consistency between snapshot and inspector

use asupersync::lab::LabRuntime;
use asupersync::observability::{TaskInspector, TaskInspectorConfig, TaskStateInfo};
use asupersync::runtime::RuntimeState;
use asupersync::types::{Budget, CancelReason};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[allow(clippy::arc_with_non_send_sync)]
fn shared_state(state: RuntimeState) -> Arc<RuntimeState> {
    Arc::new(state)
}

/// MR1: Snapshot Completeness - snapshot captures all active tasks.
///
/// Metamorphic relation: For any runtime state, the number of tasks in the snapshot
/// should equal the number of active (non-terminal) tasks in the runtime.
#[test]
fn mr1_snapshot_completeness() -> TestResult {
    // Use a deterministic seed for reproducible testing
    let mut runtime = LabRuntime::with_seed(0);
    let region = runtime.state.create_root_region(Budget::INFINITE);

    // Create some tasks
    let (_task1, _) = runtime.state.create_task(region, Budget::INFINITE, async {
        // Simple task that completes quickly
        42
    })?;

    let (_task2, _) = runtime.state.create_task(region, Budget::INFINITE, async {
        // Another simple task that completes quickly
        84
    })?;

    // Run tasks to completion for deterministic state
    runtime.run_until_quiescent();

    // Create inspector by transferring ownership of the state
    let inspector = TaskInspector::new(shared_state(runtime.state), None);

    // Get snapshot and manual count
    let snapshot = inspector.wire_snapshot();
    let active_tasks = inspector.list_active_tasks();
    let manual_task_count = inspector.list_tasks().len();

    // MR: snapshot.summary.total_tasks == active_tasks.len() + completed_count
    let completed_count = inspector
        .list_tasks()
        .into_iter()
        .filter(|t| t.is_terminal())
        .count();

    assert_eq!(
        snapshot.summary.total_tasks,
        active_tasks.len() + completed_count,
        "Snapshot completeness violated: total_tasks != active + completed"
    );

    assert_eq!(
        snapshot.summary.total_tasks, manual_task_count,
        "Snapshot completeness violated: total_tasks != manual count"
    );

    Ok(())
}

/// MR2: Cancellation State Consistency - snapshot after cancel reflects state.
///
/// Metamorphic relation: If we take snapshot S1, trigger cancellation, then take
/// snapshot S2, the number of cancelling tasks in S2 should be >= S1.
#[test]
fn mr2_cancellation_state_consistency() -> TestResult {
    let mut state = RuntimeState::new();
    let region = state.create_root_region(Budget::INFINITE);

    // Create some tasks that respect cancellation
    let (_task1, _handle1) = state.create_task(region, Budget::INFINITE, async move {})?;

    let (_task2, _handle2) = state.create_task(region, Budget::INFINITE, async {
        // Another task
    })?;

    let mut shared = shared_state(state);

    // Take first snapshot
    let snapshot1 = TaskInspector::new(shared.clone(), None).wire_snapshot();

    // Trigger actual runtime cancellation on the region that owns the tasks.
    let tasks_to_cancel = Arc::get_mut(&mut shared)
        .expect("snapshot inspector should not retain the state")
        .cancel_request(region, &CancelReason::timeout(), None);

    // Take second snapshot
    let snapshot2 = TaskInspector::new(shared, None).wire_snapshot();

    // MR: actual cancel propagation moves both tasks into a cancellation phase.
    assert!(
        snapshot2.summary.cancelling == snapshot1.summary.cancelling + tasks_to_cancel.len(),
        "Cancellation consistency violated: after={}, before={}, requested={}",
        snapshot2.summary.cancelling,
        snapshot1.summary.cancelling,
        tasks_to_cancel.len()
    );

    // Additional invariant: total tasks should remain the same
    assert_eq!(
        snapshot1.summary.total_tasks, snapshot2.summary.total_tasks,
        "Task count changed during cancellation"
    );

    Ok(())
}

/// MR3: Concurrent Snapshots Commutativity - concurrent snapshots are deterministic.
///
/// Metamorphic relation: Two snapshots taken at the same logical time should
/// contain the same task information (modulo timestamp fields).
#[test]
fn mr3_concurrent_snapshots_commutativity() -> TestResult {
    let mut state = RuntimeState::new();
    let region = state.create_root_region(Budget::INFINITE);

    // Create a stable task state
    let (_task, _) = state.create_task(region, Budget::INFINITE, async {
        // Simple task
    })?;

    let inspector = TaskInspector::new(shared_state(state), None);

    // Take two snapshots at the same logical time
    let snapshot1 = inspector.wire_snapshot();
    let snapshot2 = inspector.wire_snapshot();

    // MR: snapshots taken at same time have same content (ignoring timestamps)
    assert_eq!(
        snapshot1.summary.total_tasks, snapshot2.summary.total_tasks,
        "Concurrent snapshots have different task counts"
    );

    assert_eq!(
        snapshot1.summary.running, snapshot2.summary.running,
        "Concurrent snapshots have different running counts"
    );

    assert_eq!(
        snapshot1.summary.completed, snapshot2.summary.completed,
        "Concurrent snapshots have different completed counts"
    );

    assert_eq!(
        snapshot1.tasks.len(),
        snapshot2.tasks.len(),
        "Concurrent snapshots have different task detail counts"
    );

    // Task IDs should be identical
    let ids1: HashSet<_> = snapshot1.tasks.iter().map(|t| t.id).collect();
    let ids2: HashSet<_> = snapshot2.tasks.iter().map(|t| t.id).collect();
    assert_eq!(ids1, ids2, "Concurrent snapshots have different task IDs");

    Ok(())
}

/// MR4: Wire Format Round-Trip - encode(decode(encoded)) == encoded.
///
/// Metamorphic relation: Serialization and deserialization should preserve content.
#[test]
fn mr4_wire_format_round_trip() -> TestResult {
    let mut state = RuntimeState::new();
    let region = state.create_root_region(Budget::INFINITE);

    // Create diverse task states
    let (_task1, _) = state.create_task(region, Budget::INFINITE, async {
        // A running task
    })?;

    let (_task2, _) = state.create_task(region, Budget::INFINITE, async {
        // This will complete quickly
    })?;

    let inspector = TaskInspector::new(shared_state(state), None);
    let snapshot = inspector.wire_snapshot();
    let snapshot_json = snapshot.to_json()?;

    // MR: Round-trip serialization preserves content
    let parsed = asupersync::observability::TaskConsoleWireSnapshot::from_json(&snapshot_json)?;
    let re_encoded = parsed.to_json()?;

    assert_eq!(
        snapshot_json, re_encoded,
        "Wire format round-trip changed content"
    );

    Ok(())
}

/// MR5: Summary Consistency - inspector summary matches snapshot summary.
///
/// Metamorphic relation: The summary from inspector.summary() should match
/// the summary field in inspector.wire_snapshot().
#[test]
fn mr5_summary_consistency() -> TestResult {
    let mut state = RuntimeState::new();
    let region = state.create_root_region(Budget::INFINITE);

    // Spawn tasks in different states
    let (_task1, _) = state.create_task(region, Budget::INFINITE, async {
        // First task
    })?;

    let (_task2, _) = state.create_task(region, Budget::INFINITE, async {
        // Second task
    })?;

    let inspector = TaskInspector::new(shared_state(state), None);

    let snapshot = inspector.wire_snapshot();
    let summary = inspector.summary();

    // MR: Summary consistency across different API calls
    assert_eq!(
        snapshot.summary.total_tasks, summary.total_tasks,
        "Summary total_tasks mismatch between snapshot and summary"
    );

    assert_eq!(
        snapshot.summary.running, summary.running,
        "Summary running mismatch between snapshot and summary"
    );

    assert_eq!(
        snapshot.summary.completed, summary.completed,
        "Summary completed mismatch between snapshot and summary"
    );

    assert_eq!(
        snapshot.summary.cancelling, summary.cancelling,
        "Summary cancelling mismatch between snapshot and summary"
    );

    Ok(())
}

/// MR6: Task Count Conservation - various count methods should be consistent.
///
/// Metamorphic relation: Different ways of counting tasks should yield
/// consistent results.
#[test]
fn mr6_task_count_conservation() -> TestResult {
    let mut state = RuntimeState::new();
    let region = state.create_root_region(Budget::INFINITE);

    // Spawn various tasks
    let (_task1, _) = state.create_task(region, Budget::INFINITE, async {
        // First task
    })?;

    let (_task2, _) = state.create_task(region, Budget::INFINITE, async {
        // This completes immediately
    })?;

    let inspector = TaskInspector::new(shared_state(state), None);

    let snapshot = inspector.wire_snapshot();
    let all_tasks = inspector.list_tasks();
    let active_tasks = inspector.list_active_tasks();

    // MR: Conservation of task counts
    assert_eq!(
        snapshot.tasks.len(),
        all_tasks.len(),
        "Task count mismatch between snapshot and list_tasks"
    );

    let manual_active_count = all_tasks.iter().filter(|t| !t.is_terminal()).count();
    assert_eq!(
        active_tasks.len(),
        manual_active_count,
        "Active task count mismatch between list_active_tasks and manual count"
    );

    // Sanity check: active + terminal = total
    let terminal_count = all_tasks.iter().filter(|t| t.is_terminal()).count();
    assert_eq!(
        active_tasks.len() + terminal_count,
        all_tasks.len(),
        "Active + terminal != total task count"
    );

    Ok(())
}

/// MR7: Schema Version Consistency - all snapshots have expected schema.
///
/// Metamorphic relation: All wire snapshots should have consistent schema version.
#[test]
fn mr7_schema_version_consistency() -> TestResult {
    // Test with empty state first
    let state1 = RuntimeState::new();
    let inspector1 = TaskInspector::new(shared_state(state1), None);
    let snapshot1 = inspector1.wire_snapshot();

    // Test with state that has tasks
    let mut state2 = RuntimeState::new();
    let region = state2.create_root_region(Budget::INFINITE);
    let (_task, _) = state2.create_task(region, Budget::INFINITE, async {
        // Task for schema consistency test
    })?;

    let inspector2 = TaskInspector::new(shared_state(state2), None);
    let snapshot2 = inspector2.wire_snapshot();

    // MR: Schema version consistency
    assert!(
        snapshot1.has_expected_schema(),
        "First snapshot has unexpected schema version"
    );

    assert!(
        snapshot2.has_expected_schema(),
        "Second snapshot has unexpected schema version"
    );

    assert_eq!(
        snapshot1.schema_version, snapshot2.schema_version,
        "Schema versions differ between snapshots"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = TaskInspectorConfig::default();
        assert_eq!(config.stuck_task_threshold, Duration::from_secs(30));
        assert!(config.show_obligations);
        assert!(config.highlight_stuck_tasks);
    }

    #[test]
    fn test_task_state_info_names() {
        assert_eq!(TaskStateInfo::Created.name(), "Created");
        assert_eq!(TaskStateInfo::Running.name(), "Running");
        assert_eq!(
            TaskStateInfo::Completed {
                outcome: "Ok".to_string()
            }
            .name(),
            "Completed"
        );
    }
}
