//! Integration test for cross-module lock ordering enforcement.
//!
//! This test demonstrates the enhanced lock ordering system that prevents
//! deadlocks when operations span multiple asupersync modules.

#![cfg(test)]

use super::lock_ordering::LockModule;

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
use super::lock_ordering::{
    LockOrderEnforcer, LockRank, check_acquire_with_module, clear_held_locks,
    record_acquire_with_module, record_release_with_module,
};

#[test]
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn test_cross_module_enforcement_example() {
    clear_held_locks();

    // Scenario: Task in runtime module needs to coordinate with obligation tracking
    // This should work fine when done in the correct order
    check_acquire_with_module("runtime_tasks", LockRank::Tasks, LockModule::Runtime);
    record_acquire_with_module("runtime_tasks", LockRank::Tasks, LockModule::Runtime);

    check_acquire_with_module(
        "obligation_ledger",
        LockRank::Obligations,
        LockModule::Obligation,
    );
    record_acquire_with_module(
        "obligation_ledger",
        LockRank::Obligations,
        LockModule::Obligation,
    );

    // Clean up in reverse order
    record_release_with_module(
        "obligation_ledger",
        LockRank::Obligations,
        LockModule::Obligation,
    );
    record_release_with_module("runtime_tasks", LockRank::Tasks, LockModule::Runtime);
}

#[test]
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
#[should_panic(expected = "CROSS-MODULE DEADLOCK PREVENTION")]
fn test_cross_module_violation_obligation_while_holding_cancel() {
    clear_held_locks();

    // Hold a Cancel module lock
    record_acquire_with_module("cancel_protocol", LockRank::Tasks, LockModule::Cancel);

    // This should panic - trying to acquire Obligation lock while holding Cancel lock
    check_acquire_with_module(
        "obligation_tracker",
        LockRank::Obligations,
        LockModule::Obligation,
    );
}

#[test]
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
#[should_panic(expected = "CROSS-MODULE DEADLOCK PREVENTION")]
fn test_cross_module_violation_runtime_while_holding_obligation() {
    clear_held_locks();

    // Hold an Obligation lock
    record_acquire_with_module(
        "obligation_state",
        LockRank::Obligations,
        LockModule::Obligation,
    );

    // This should panic - trying to acquire Task lock while holding Obligation lock
    check_acquire_with_module("runtime_scheduler", LockRank::Tasks, LockModule::Runtime);
}

#[test]
fn test_module_detection_from_names() {
    // Test that the module detection works correctly for different naming patterns
    assert_eq!(
        LockModule::from_name("runtime_scheduler_queue"),
        LockModule::Runtime
    );
    assert_eq!(LockModule::from_name("sync_mutex_guard"), LockModule::Sync);
    assert_eq!(LockModule::from_name("cx_scope_handle"), LockModule::Cx);
    assert_eq!(
        LockModule::from_name("cancel_token_state"),
        LockModule::Cancel
    );
    assert_eq!(
        LockModule::from_name("obligation_tracker_ledger"),
        LockModule::Obligation
    );
    assert_eq!(
        LockModule::from_name("channel_mpsc_sender"),
        LockModule::Channel
    );
    assert_eq!(LockModule::from_name("io_tcp_stream"), LockModule::Io);
    assert_eq!(
        LockModule::from_name("unknown_component"),
        LockModule::Other
    );
}

/// Example of how the enhanced API could be used in practice.
/// This test shows the intended usage pattern for the LockOrderEnforcer.
#[test]
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn test_lock_order_enforcer_usage_example() {
    clear_held_locks();

    // Create enforcers for different locks
    let runtime_lock =
        LockOrderEnforcer::with_module("runtime_task_queue", LockRank::Tasks, LockModule::Runtime);

    let obligation_lock = LockOrderEnforcer::new("obligation_tracker", LockRank::Obligations);

    // Use them in the correct order
    runtime_lock.acquire();
    obligation_lock.acquire();

    // Release in reverse order
    obligation_lock.release();
    runtime_lock.release();
}
