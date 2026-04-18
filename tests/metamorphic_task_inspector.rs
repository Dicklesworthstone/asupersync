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

use asupersync::cx::{Cx, Scope};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::observability::{TaskInspector, TaskInspectorConfig, TaskStateInfo};
use asupersync::runtime::yield_now;
use asupersync::types::{Budget, CancelReason, Time};
use asupersync::spawn;
use std::collections::HashSet;
use std::time::Duration;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// MR1: Snapshot Completeness - snapshot captures all active tasks.
///
/// Metamorphic relation: For any runtime state, the number of tasks in the snapshot
/// should equal the number of active (non-terminal) tasks in the runtime.
#[tokio::test]
async fn mr1_snapshot_completeness() -> TestResult {
    let runtime = LabRuntime::with_seed(0);

    runtime.scope(|_cx: &Cx, scope: &Scope| async move {
        let inspector = TaskInspector::new(runtime.state(), None);

        // Spawn some tasks
        let _task1 = spawn!(scope, async {
            yield_now().await;
        });
        let _task2 = spawn!(scope, async {
            yield_now().await;
        });

        // Allow tasks to start
        yield_now().await;

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
            snapshot.summary.total_tasks,
            manual_task_count,
            "Snapshot completeness violated: total_tasks != manual count"
        );

        Ok(())
    }).await?;

    Ok(())
}

/// MR2: Cancellation State Consistency - snapshot after cancel reflects state.
///
/// Metamorphic relation: If we take snapshot S1, trigger cancellation, then take
/// snapshot S2, the number of cancelling tasks in S2 should be >= S1.
#[tokio::test]
async fn mr2_cancellation_state_consistency() -> TestResult {
    let runtime = LabRuntime::with_seed(0);

    let (snapshot1, snapshot2) = runtime
        .scope(|cx: &Cx, scope: &Scope| async move {
            let inspector = TaskInspector::new(runtime.state(), None);

            // Spawn some long-running tasks
            let _task1 = spawn!(scope, async {
                yield_now().await;
                yield_now().await; // Give them time to start
            });
            let _task2 = spawn!(scope, async {
                yield_now().await;
                yield_now().await;
            });

            yield_now().await;
            let snapshot1 = inspector.wire_snapshot();

            // Trigger cancellation
            cx.cancel_fast(CancelReason::user("test cancellation"));
            yield_now().await;

            let snapshot2 = inspector.wire_snapshot();
            Ok((snapshot1, snapshot2))
        })
        .await?;

    // MR: cancelling_count_after >= cancelling_count_before
    assert!(
        snapshot2.summary.cancelling >= snapshot1.summary.cancelling,
        "Cancellation consistency violated: after={}, before={}",
        snapshot2.summary.cancelling,
        snapshot1.summary.cancelling
    );

    // Additional invariant: total tasks should remain the same
    assert_eq!(
        snapshot1.summary.total_tasks,
        snapshot2.summary.total_tasks,
        "Task count changed during cancellation"
    );

    Ok(())
}

/// MR3: Concurrent Snapshots Commutativity - concurrent snapshots are deterministic.
///
/// Metamorphic relation: Two snapshots taken at the same logical time should
/// contain the same task information (modulo timestamp fields).
#[tokio::test]
async fn mr3_concurrent_snapshots_commutativity() -> TestResult {
    let runtime = LabRuntime::with_seed(0);

    let (snapshot1, snapshot2) = runtime
        .scope(|_cx: &Cx, scope: &Scope| async move {
            let inspector = TaskInspector::new(runtime.state(), None);

            // Create a stable task state
            let _task = spawn!(scope, async {
                yield_now().await;
            });

            yield_now().await;

            // Take two snapshots at the same logical time
            let snapshot1 = inspector.wire_snapshot();
            let snapshot2 = inspector.wire_snapshot();

            Ok((snapshot1, snapshot2))
        })
        .await?;

    // MR: snapshots taken at same time have same content (ignoring timestamps)
    assert_eq!(
        snapshot1.summary.total_tasks,
        snapshot2.summary.total_tasks,
        "Concurrent snapshots have different task counts"
    );

    assert_eq!(
        snapshot1.summary.running,
        snapshot2.summary.running,
        "Concurrent snapshots have different running counts"
    );

    assert_eq!(
        snapshot1.summary.completed,
        snapshot2.summary.completed,
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
#[tokio::test]
async fn mr4_wire_format_round_trip() -> TestResult {
    let runtime = LabRuntime::with_seed(0);

    let snapshot_json: String = runtime
        .scope(|_cx: &Cx, scope: &Scope| async move {
            let inspector = TaskInspector::new(runtime.state(), None);

            // Create diverse task states
            let _running_task = spawn!(scope, async {
                yield_now().await;
            });

            let _completing_task = spawn!(scope, async {
                // This will complete quickly
            });

            yield_now().await;

            let snapshot = inspector.wire_snapshot();
            Ok(snapshot.to_json()?)
        })
        .await?;

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
#[tokio::test]
async fn mr5_summary_consistency() -> TestResult {
    let runtime = LabRuntime::with_seed(0);

    runtime.scope(|_cx: &Cx, scope: &Scope| async move {
        let inspector = TaskInspector::new(runtime.state(), None);

        // Spawn tasks in different states
        let _task1 = spawn!(scope, async {
            yield_now().await;
        });
        let _task2 = spawn!(scope, async {
            yield_now().await;
        });

        yield_now().await;

        let snapshot = inspector.wire_snapshot();
        let summary = inspector.summary();

        // MR: Summary consistency across different API calls
        assert_eq!(
            snapshot.summary.total_tasks,
            summary.total_tasks,
            "Summary total_tasks mismatch between snapshot and summary"
        );

        assert_eq!(
            snapshot.summary.running,
            summary.running,
            "Summary running mismatch between snapshot and summary"
        );

        assert_eq!(
            snapshot.summary.completed,
            summary.completed,
            "Summary completed mismatch between snapshot and summary"
        );

        assert_eq!(
            snapshot.summary.cancelling,
            summary.cancelling,
            "Summary cancelling mismatch between snapshot and summary"
        );

        Ok(())
    }).await?;

    Ok(())
}

/// MR6: Task Count Conservation - various count methods should be consistent.
///
/// Metamorphic relation: Different ways of counting tasks should yield
/// consistent results.
#[tokio::test]
async fn mr6_task_count_conservation() -> TestResult {
    let runtime = LabRuntime::with_seed(0);

    runtime.scope(|_cx: &Cx, scope: &Scope| async move {
        let inspector = TaskInspector::new(runtime.state(), None);

        // Spawn various tasks
        let _task1 = spawn!(scope, async {
            yield_now().await;
        });
        let _task2 = spawn!(scope, async {
            // This completes immediately
        });

        yield_now().await;

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
    }).await?;

    Ok(())
}

/// MR7: Schema Version Consistency - all snapshots have expected schema.
///
/// Metamorphic relation: All wire snapshots should have consistent schema version.
#[tokio::test]
async fn mr7_schema_version_consistency() -> TestResult {
    let runtime = LabRuntime::with_seed(0);

    runtime.scope(|_cx: &Cx, scope: &Scope| async move {
        let inspector = TaskInspector::new(runtime.state(), None);

        // Take multiple snapshots
        let snapshot1 = inspector.wire_snapshot();

        let _task = spawn!(scope, async {
            yield_now().await;
        });

        yield_now().await;
        let snapshot2 = inspector.wire_snapshot();

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
            snapshot1.schema_version,
            snapshot2.schema_version,
            "Schema versions differ between snapshots"
        );

        Ok(())
    }).await?;

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