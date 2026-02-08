#![allow(missing_docs)]

//! Sharding correctness tests (unit + lab).
//!
//! Validates invariants after the sharding refactor (bd-2ijqf):
//! - Lock ordering (implied by absence of deadlocks)
//! - No task leaks
//! - No obligation leaks
//! - Deterministic trace replay

#[macro_use]
mod common;

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::obligation::ObligationKind;
use asupersync::types::Budget;
use common::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn init() {
    init_test_logging();
}

#[test]
fn sharding_region_close_quiescence() {
    init();
    let seed = 0x544152445_u64; // "SHARDS"
    let config = LabConfig::new(seed).max_steps(10_000);

    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let completed = Arc::new(AtomicUsize::new(0));

    // Spawn 10 tasks that yield multiple times
    for _ in 0..10 {
        let completed = completed.clone();
        let (task_id, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                for _ in 0..5 {
                    asupersync::runtime::yield_now().await;
                }
                completed.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create task");
        runtime.scheduler.lock().unwrap().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();

    let report = runtime.report();
    assert!(report.quiescent, "Runtime must be quiescent");
    assert!(
        report.invariant_violations.is_empty(),
        "No invariant violations: {:?}",
        report.invariant_violations
    );
    assert_eq!(completed.load(Ordering::SeqCst), 10, "All tasks completed");
}

#[test]
fn sharding_obligation_resolution() {
    init();
    let seed = 0x4F424C4947_u64; // "OBLIG"
    let config = LabConfig::new(seed);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    // Create a task (holder for obligations)
    let (task_id, _handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async {
            asupersync::runtime::yield_now().await;
        })
        .expect("create task");
    runtime.scheduler.lock().unwrap().schedule(task_id, 0);

    // Create and immediately commit obligations
    for i in 0..5 {
        let obl = runtime
            .state
            .create_obligation(
                ObligationKind::SendPermit,
                task_id,
                root,
                Some(format!("test-obl-{i}")),
            )
            .expect("create obligation");
        runtime
            .state
            .commit_obligation(obl)
            .expect("commit obligation");
    }

    runtime.run_until_quiescent();

    let report = runtime.report();
    assert!(report.quiescent, "Runtime must be quiescent after obligation resolution");
    assert!(
        report.invariant_violations.is_empty(),
        "No invariant violations: {:?}",
        report.invariant_violations
    );
}

#[test]
fn sharding_cancellation_drain() {
    init();
    let seed = 0x43414E43454C_u64; // "CANCEL"
    let config = LabConfig::new(seed);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    // Create a task that yields many times (simulating long-running work)
    let completed = Arc::new(AtomicUsize::new(0));
    let completed_clone = completed.clone();
    let (task_id, _handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            for _ in 0..100 {
                asupersync::runtime::yield_now().await;
            }
            completed_clone.fetch_add(1, Ordering::SeqCst);
        })
        .expect("create task");
    runtime.scheduler.lock().unwrap().schedule(task_id, 0);

    // Create an obligation held by the task
    let obl = runtime
        .state
        .create_obligation(ObligationKind::SendPermit, task_id, root, None)
        .expect("create obligation");

    // Cancel the region (should cancel the task and drain obligations)
    let tasks_to_schedule = runtime
        .state
        .cancel_request(root, &asupersync::types::CancelReason::user("test"), None);
    for (tid, priority) in tasks_to_schedule {
        runtime
            .scheduler
            .lock()
            .unwrap()
            .schedule(tid, priority);
    }

    // Abort the obligation (simulating cleanup during cancellation)
    let _ = runtime.state.abort_obligation(
        obl,
        asupersync::record::obligation::ObligationAbortReason::Cancel,
    );

    runtime.run_until_quiescent();

    let report = runtime.report();
    assert!(report.quiescent, "Runtime must be quiescent after cancellation drain");
    assert!(
        report.invariant_violations.is_empty(),
        "No invariant violations: {:?}",
        report.invariant_violations
    );
}

#[test]
fn sharding_trace_replay_determinism() {
    init();
    let seed = 0x5245504C4159_u64; // "REPLAY"

    fn setup_scenario(runtime: &mut LabRuntime) {
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let completed = Arc::new(AtomicUsize::new(0));

        for i in 0..5 {
            let completed = completed.clone();
            let (task_id, _handle) = runtime
                .state
                .create_task(root, Budget::INFINITE, async move {
                    for _ in 0..3 {
                        asupersync::runtime::yield_now().await;
                    }
                    completed.fetch_add(1, Ordering::SeqCst);
                    i // return value doesn't matter, just needs to capture i
                })
                .expect("create task");
            runtime.scheduler.lock().unwrap().schedule(task_id, 0);
        }
    }

    // Run 1
    let mut runtime1 = LabRuntime::new(LabConfig::new(seed));
    setup_scenario(&mut runtime1);
    runtime1.run_until_quiescent();
    let report1 = runtime1.report();

    // Run 2
    let mut runtime2 = LabRuntime::new(LabConfig::new(seed));
    setup_scenario(&mut runtime2);
    runtime2.run_until_quiescent();
    let report2 = runtime2.report();

    assert_eq!(
        report1.trace_fingerprint, report2.trace_fingerprint,
        "Trace fingerprints must match"
    );
    assert_eq!(
        report1.steps_total, report2.steps_total,
        "Total steps must match"
    );
}
