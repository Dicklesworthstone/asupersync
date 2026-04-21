#![allow(warnings)]
#![allow(clippy::all)]
//! Integration tests for the Region Leak Detection Oracle
//!
//! These tests verify that the oracle correctly detects various forms of
//! region lifecycle violations and structured concurrency issues.

use asupersync::lab::oracle::region_leak::{RegionLeakConfig, RegionLeakOracle};
use asupersync::types::{Budget, Outcome, RegionId, TaskId};
use std::time::Duration;

#[test]
fn oracle_detects_stuck_region_creation() {
    let mut oracle = RegionLeakOracle::new(RegionLeakConfig {
        max_creation_delay: Duration::from_millis(10),
        max_closing_time: Duration::from_secs(1),
        max_finalizing_time: Duration::from_secs(1),
        max_task_lifetime: Duration::from_secs(1),
        max_idle_time: Duration::from_secs(1),
        continuous_checking: false,
        fail_fast_mode: false,
        max_violations_tracked: 10,
        include_stack_traces: false,
    });

    // Create a region but don't activate it
    oracle.on_region_created(RegionId::testing_default(), None, None, Budget::INFINITE);

    // Wait longer than the max creation delay
    std::thread::sleep(Duration::from_millis(20));

    // Should detect a stuck creation violation
    let violations = oracle.check_for_violations().unwrap();
    assert!(!violations.is_empty());
    assert!(matches!(
        violations[0].violation_type,
        asupersync::lab::oracle::region_leak::ViolationType::StuckCreation
    ));
}

#[test]
fn oracle_allows_normal_region_lifecycle() {
    let mut oracle = RegionLeakOracle::with_defaults();

    // Normal region lifecycle
    oracle.on_region_created(RegionId::testing_default(), None, None, Budget::INFINITE);
    oracle.on_region_activated(RegionId::testing_default());
    oracle.on_task_spawned(TaskId::testing_default(), RegionId::testing_default(), None);
    oracle.on_task_polled(TaskId::testing_default());
    oracle.on_task_completed(TaskId::testing_default(), Outcome::Ok(()));
    oracle.on_region_closing(RegionId::testing_default(), 0);
    oracle.on_region_closed(RegionId::testing_default());

    // Should have no violations
    let violations = oracle.check_for_violations().unwrap();
    assert!(violations.is_empty());
}

#[test]
fn oracle_detects_orphaned_tasks() {
    let mut oracle = RegionLeakOracle::with_defaults();

    // Create region and spawn task
    oracle.on_region_created(RegionId::testing_default(), None, None, Budget::INFINITE);
    oracle.on_task_spawned(TaskId::testing_default(), RegionId::testing_default(), None);

    // Close region without completing task (violation!)
    oracle.on_region_closing(RegionId::testing_default(), 0);
    oracle.on_region_closed(RegionId::testing_default());

    // Should detect orphaned tasks
    let violations = oracle.check_for_violations().unwrap();
    assert!(!violations.is_empty());
    assert!(matches!(
        violations[0].violation_type,
        asupersync::lab::oracle::region_leak::ViolationType::OrphanedTasks
    ));
}

#[test]
fn oracle_statistics_tracking() {
    let mut oracle = RegionLeakOracle::with_defaults();

    // Create some activity
    oracle.on_region_created(RegionId::testing_default(), None, None, Budget::INFINITE);
    oracle.on_task_spawned(TaskId::testing_default(), RegionId::testing_default(), None);
    oracle.on_task_completed(TaskId::testing_default(), Outcome::Ok(()));
    oracle.on_region_closed(RegionId::testing_default());

    let stats = oracle.statistics();
    assert_eq!(stats.total_regions_created, 1);
    assert_eq!(stats.total_regions_closed, 1);
    assert_eq!(stats.total_tasks_spawned, 1);
    assert_eq!(stats.total_tasks_completed, 1);
}

#[test]
fn oracle_reset_clears_state() {
    let mut oracle = RegionLeakOracle::with_defaults();

    // Add some activity
    oracle.on_region_created(RegionId::testing_default(), None, None, Budget::INFINITE);
    oracle.on_task_spawned(TaskId::testing_default(), RegionId::testing_default(), None);

    let stats_before = oracle.statistics();
    assert!(stats_before.total_regions_created > 0);

    // Reset and check
    oracle.reset();
    let stats_after = oracle.statistics();
    assert_eq!(stats_after.total_regions_created, 0);
    assert_eq!(stats_after.total_tasks_spawned, 0);
}
