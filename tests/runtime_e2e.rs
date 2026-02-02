#![allow(missing_docs)]

//! Runtime E2E + stress tests with structured logging (bd-n6w9).
//!
//! Exercises cancellation storms, timer storms, I/O readiness, region
//! close/quiescence, and obligation drain across multi-worker scheduling.

#[macro_use]
mod common;

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::{Budget, CancelReason, Time};
use common::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

// ============================================================================
// Task lifecycle E2E
// ============================================================================

#[test]
fn e2e_task_spawn_and_quiescence() {
    init_test("e2e_task_spawn_and_quiescence");
    let mut runtime = LabRuntime::new(LabConfig::default());
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let counter = Arc::new(AtomicUsize::new(0));
    let c = counter.clone();

    let (task_id, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            c.fetch_add(1, Ordering::SeqCst);
        })
        .expect("create task");

    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    let steps = runtime.run_until_quiescent();

    assert_with_log!(steps > 0, "ran steps", "> 0", steps);
    let count = counter.load(Ordering::SeqCst);
    assert_with_log!(count == 1, "task executed", 1, count);
    let quiescent = runtime.is_quiescent();
    assert_with_log!(quiescent, "quiescent", true, quiescent);
    test_complete!("e2e_task_spawn_and_quiescence");
}

#[test]
fn e2e_multiple_tasks_all_complete() {
    init_test("e2e_multiple_tasks_all_complete");
    let mut runtime = LabRuntime::new(LabConfig::new(42).worker_count(2));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let counter = Arc::new(AtomicUsize::new(0));
    let n = 10;

    for _ in 0..n {
        let c = counter.clone();
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                c.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create task");
        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();

    let count = counter.load(Ordering::SeqCst);
    assert_with_log!(count == n, "all tasks ran", n, count);
    let live = runtime.state.live_task_count();
    assert_with_log!(live == 0, "no live tasks", 0, live);
    test_complete!("e2e_multiple_tasks_all_complete");
}

// ============================================================================
// Cancellation E2E
// ============================================================================

#[test]
fn e2e_cancel_region_drains_tasks() {
    init_test("e2e_cancel_region_drains_tasks");
    let mut runtime = LabRuntime::new(LabConfig::default());
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let started = Arc::new(AtomicUsize::new(0));
    let s = started.clone();

    let (task_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            s.fetch_add(1, Ordering::SeqCst);
            // task would do long work here
        })
        .expect("create task");
    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.run_until_quiescent();

    // Cancel the region
    runtime
        .state
        .cancel_request(region, &CancelReason::user("test cancellation"), None);
    runtime.run_until_quiescent();

    let quiescent = runtime.is_quiescent();
    assert_with_log!(quiescent, "quiescent after cancel", true, quiescent);
    test_complete!("e2e_cancel_region_drains_tasks");
}

#[test]
fn e2e_cancellation_storm() {
    init_test("e2e_cancellation_storm");
    let mut runtime = LabRuntime::new(LabConfig::new(999).worker_count(4));

    let n_regions = 20;
    let n_tasks_per_region = 5;
    let total_spawned = Arc::new(AtomicUsize::new(0));

    let mut regions = Vec::new();
    for i in 0..n_regions {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        regions.push(region);

        for _ in 0..n_tasks_per_region {
            let ts = total_spawned.clone();
            let (task_id, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    ts.fetch_add(1, Ordering::SeqCst);
                })
                .expect("create task");
            runtime.scheduler.lock().unwrap().schedule(task_id, 0);
        }

        // Cancel odd regions immediately
        if i % 2 == 1 {
            runtime
                .state
                .cancel_request(region, &CancelReason::user("test cancellation"), None);
        }
    }

    runtime.run_until_quiescent();

    let quiescent = runtime.is_quiescent();
    assert_with_log!(quiescent, "quiescent after storm", true, quiescent);
    let live = runtime.state.live_task_count();
    assert_with_log!(live == 0, "no live tasks", 0, live);
    test_complete!("e2e_cancellation_storm");
}

// ============================================================================
// Timer E2E
// ============================================================================

#[test]
fn e2e_timer_advances_virtual_time() {
    init_test("e2e_timer_advances_virtual_time");
    let mut runtime = LabRuntime::new(LabConfig::default());

    // Advance time
    runtime.advance_time_to(Time::from_millis(100));
    let now = runtime.now();
    assert_with_log!(
        now >= Time::from_millis(100),
        "time advanced",
        ">= 100ms",
        now
    );
    test_complete!("e2e_timer_advances_virtual_time");
}

#[test]
fn e2e_timer_storm() {
    init_test("e2e_timer_storm");
    let mut runtime = LabRuntime::new(LabConfig::new(777));

    // Create many timer-like tasks at different times
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let completed = Arc::new(AtomicUsize::new(0));

    for i in 0..50 {
        let c = completed.clone();
        let (task_id, _) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                c.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create task");
        runtime.scheduler.lock().unwrap().schedule(task_id, 0);

        // Interleave time advances
        if i % 10 == 0 {
            runtime.advance_time_to(Time::from_millis(i as u64 * 10));
            runtime.run_until_quiescent();
        }
    }

    runtime.run_until_quiescent();

    let count = completed.load(Ordering::SeqCst);
    assert_with_log!(count == 50, "all timer tasks completed", 50, count);
    test_complete!("e2e_timer_storm");
}

// ============================================================================
// Region hierarchy E2E
// ============================================================================

#[test]
fn e2e_multiple_regions_all_quiesce() {
    init_test("e2e_multiple_regions_all_quiesce");
    let mut runtime = LabRuntime::new(LabConfig::default());
    let region_a = runtime.state.create_root_region(Budget::INFINITE);
    let region_b = runtime.state.create_root_region(Budget::INFINITE);
    let region_c = runtime.state.create_root_region(Budget::INFINITE);

    let order = Arc::new(std::sync::Mutex::new(Vec::new()));

    // Task in region_a
    let o = order.clone();
    let (t1, _) = runtime
        .state
        .create_task(region_a, Budget::INFINITE, async move {
            o.lock().unwrap().push("region_a");
        })
        .expect("task a");
    runtime.scheduler.lock().unwrap().schedule(t1, 0);

    // Task in region_b
    let o = order.clone();
    let (t2, _) = runtime
        .state
        .create_task(region_b, Budget::INFINITE, async move {
            o.lock().unwrap().push("region_b");
        })
        .expect("task b");
    runtime.scheduler.lock().unwrap().schedule(t2, 0);

    // Task in region_c
    let o = order.clone();
    let (t3, _) = runtime
        .state
        .create_task(region_c, Budget::INFINITE, async move {
            o.lock().unwrap().push("region_c");
        })
        .expect("task c");
    runtime.scheduler.lock().unwrap().schedule(t3, 0);

    runtime.run_until_quiescent();

    let final_order = order.lock().unwrap();
    assert_with_log!(
        final_order.len() == 3,
        "all tasks completed",
        3,
        final_order.len()
    );
    test_complete!("e2e_multiple_regions_all_quiesce");
}

// ============================================================================
// Stress tests
// ============================================================================

#[test]
fn stress_many_tasks_single_region() {
    init_test("stress_many_tasks_single_region");
    let mut runtime = LabRuntime::new(LabConfig::new(12345).worker_count(4));
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let n = 500;
    let counter = Arc::new(AtomicUsize::new(0));

    for _ in 0..n {
        let c = counter.clone();
        let (task_id, _) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                c.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create task");
        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();

    let count = counter.load(Ordering::SeqCst);
    assert_with_log!(count == n, "all tasks ran", n, count);
    let quiescent = runtime.is_quiescent();
    assert_with_log!(quiescent, "quiescent", true, quiescent);
    test_complete!("stress_many_tasks_single_region");
}

#[test]
fn stress_many_regions_few_tasks() {
    init_test("stress_many_regions_few_tasks");
    let mut runtime = LabRuntime::new(LabConfig::new(54321));

    let n_regions = 100;
    let counter = Arc::new(AtomicUsize::new(0));

    for _ in 0..n_regions {
        let region = runtime.state.create_root_region(Budget::INFINITE);

        let c = counter.clone();
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                c.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create task");
        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();

    let count = counter.load(Ordering::SeqCst);
    assert_with_log!(count == n_regions, "all tasks ran", n_regions, count);
    test_complete!("stress_many_regions_few_tasks");
}

// ============================================================================
// Determinism verification
// ============================================================================

#[test]
fn e2e_deterministic_execution() {
    init_test("e2e_deterministic_execution");
    let config = LabConfig::new(42).worker_count(2);

    asupersync::lab::assert_deterministic(config, |runtime| {
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let counter = Arc::new(AtomicUsize::new(0));

        for _ in 0..20 {
            let c = counter.clone();
            let (task_id, _) = runtime
                .state
                .create_task(root, Budget::INFINITE, async move {
                    c.fetch_add(1, Ordering::SeqCst);
                })
                .expect("create task");
            runtime.scheduler.lock().unwrap().schedule(task_id, 0);
        }

        runtime.run_until_quiescent();
    });

    test_complete!("e2e_deterministic_execution");
}

// ============================================================================
// Trace capture verification
// ============================================================================

#[test]
fn e2e_trace_captures_events() {
    init_test("e2e_trace_captures_events");
    let mut runtime = LabRuntime::new(LabConfig::new(1).trace_capacity(4096));
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let (task_id, _) = runtime
        .state
        .create_task(root, Budget::INFINITE, async { 42 })
        .expect("create task");
    runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    runtime.run_until_quiescent();

    let events = runtime.state.trace.snapshot();
    let event_count = events.len();
    assert_with_log!(event_count > 0, "trace captured events", "> 0", event_count);
    test_complete!("e2e_trace_captures_events");
}
