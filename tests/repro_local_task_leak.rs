//! Tombstone guard for the local-task leak reproduction.
//!
//! The executable regression lives in `src/runtime/scheduler/three_lane.rs`.
//! Keep this integration target as a guard so the old reproduction path fails if
//! the real test is renamed or removed without updating this breadcrumb.

const THREE_LANE_SOURCE: &str = include_str!("../src/runtime/scheduler/three_lane.rs");
const MOVED_REGRESSION_TEST: &str = "fn test_local_task_cross_thread_wake_routes_correctly()";

#[test]
fn moved_local_task_leak_regression_still_exists() {
    assert!(
        THREE_LANE_SOURCE.contains(MOVED_REGRESSION_TEST),
        "moved local-task leak regression test is missing from three_lane.rs"
    );
}
