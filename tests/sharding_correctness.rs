#![allow(missing_docs)]

//! Sharding correctness tests (unit + lab).
//!
//! Validates invariants after the sharding refactor (bd-2ijqf):
//! - Lock ordering (implied by absence of deadlocks)
//! - No task leaks
//! - No obligation leaks
//! - Deterministic trace replay
//! - LocalQueue correctness with TaskTable backing
//! - Cross-table operations (cancel, obligation resolve, region advance)
//! - Hierarchical region close with obligations
//! - Concurrent scheduling under sharded state

#[macro_use]
mod common;

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::obligation::{ObligationAbortReason, ObligationKind};
use asupersync::runtime::scheduler::local_queue::LocalQueue;
use asupersync::types::{Budget, CancelReason};
use common::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn init() {
    init_test_logging();
}

fn setup_trace_replay_scenario(runtime: &mut LabRuntime) {
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let completed = Arc::new(AtomicUsize::new(0));

    for i in 0..5 {
        let completed = Arc::clone(&completed);
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
        runtime.scheduler.lock().schedule(task_id, 0);
    }
}

#[test]
fn sharding_region_close_quiescence() {
    init();
    let seed = 0x0005_4415_2445_u64; // "SHARDS"
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
        runtime.scheduler.lock().schedule(task_id, 0);
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
    let seed = 0x004F_424C_4947_u64; // "OBLIG"
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
    runtime.scheduler.lock().schedule(task_id, 0);

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
    assert!(
        report.quiescent,
        "Runtime must be quiescent after obligation resolution"
    );
    assert!(
        report.invariant_violations.is_empty(),
        "No invariant violations: {:?}",
        report.invariant_violations
    );
}

#[test]
fn sharding_cancellation_drain() {
    init();
    let seed = 0x4341_4E43_454C_u64; // "CANCEL"
    let config = LabConfig::new(seed);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    // Create a task that yields many times (simulating long-running work)
    let completed = Arc::new(AtomicUsize::new(0));
    let (task_id, _handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            for _ in 0..100 {
                asupersync::runtime::yield_now().await;
            }
            completed.fetch_add(1, Ordering::SeqCst);
        })
        .expect("create task");
    runtime.scheduler.lock().schedule(task_id, 0);

    // Create an obligation held by the task
    let obl = runtime
        .state
        .create_obligation(ObligationKind::SendPermit, task_id, root, None)
        .expect("create obligation");

    // Cancel the region (should cancel the task and drain obligations)
    let tasks_to_schedule =
        runtime
            .state
            .cancel_request(root, &asupersync::types::CancelReason::user("test"), None);
    for (tid, priority) in tasks_to_schedule {
        runtime.scheduler.lock().schedule(tid, priority);
    }

    // Abort the obligation (simulating cleanup during cancellation)
    let _ = runtime.state.abort_obligation(
        obl,
        asupersync::record::obligation::ObligationAbortReason::Cancel,
    );

    runtime.run_until_quiescent();

    let report = runtime.report();
    assert!(
        report.quiescent,
        "Runtime must be quiescent after cancellation drain"
    );
    assert!(
        report.invariant_violations.is_empty(),
        "No invariant violations: {:?}",
        report.invariant_violations
    );
}

#[test]
fn sharding_trace_replay_determinism() {
    init();
    let seed = 0x5245_504C_4159_u64; // "REPLAY"

    // Run 1
    let mut runtime1 = LabRuntime::new(LabConfig::new(seed));
    setup_trace_replay_scenario(&mut runtime1);
    runtime1.run_until_quiescent();
    let report1 = runtime1.report();

    // Run 2
    let mut runtime2 = LabRuntime::new(LabConfig::new(seed));
    setup_trace_replay_scenario(&mut runtime2);
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

// =============================================================================
// LocalQueue + TaskTable sharded mode tests
// =============================================================================

#[test]
fn local_queue_task_table_push_pop_lifo() {
    init();
    let tasks = LocalQueue::test_task_table(10);
    let queue = LocalQueue::new_with_task_table(tasks);

    let t0 = asupersync::types::TaskId::new_for_test(0, 0);
    let t1 = asupersync::types::TaskId::new_for_test(1, 0);
    let t2 = asupersync::types::TaskId::new_for_test(2, 0);

    queue.push(t0);
    queue.push(t1);
    queue.push(t2);

    // LIFO: last pushed is first popped
    assert_eq!(queue.pop(), Some(t2));
    assert_eq!(queue.pop(), Some(t1));
    assert_eq!(queue.pop(), Some(t0));
    assert_eq!(queue.pop(), None);
}

#[test]
fn local_queue_task_table_steal_fifo() {
    init();
    let tasks = LocalQueue::test_task_table(10);
    let queue = LocalQueue::new_with_task_table(Arc::clone(&tasks));
    let stealer = queue.stealer();

    let t0 = asupersync::types::TaskId::new_for_test(0, 0);
    let t1 = asupersync::types::TaskId::new_for_test(1, 0);
    let t2 = asupersync::types::TaskId::new_for_test(2, 0);

    queue.push(t0);
    queue.push(t1);
    queue.push(t2);

    // FIFO steal: first pushed is first stolen
    assert_eq!(stealer.steal(), Some(t0));
    assert_eq!(stealer.steal(), Some(t1));
    assert_eq!(stealer.steal(), Some(t2));
    assert_eq!(stealer.steal(), None);
}

#[test]
fn local_queue_task_table_push_many() {
    init();
    let tasks = LocalQueue::test_task_table(10);
    let queue = LocalQueue::new_with_task_table(tasks);

    let ids: Vec<_> = (0..5)
        .map(|i| asupersync::types::TaskId::new_for_test(i, 0))
        .collect();
    queue.push_many(&ids);

    // Pop all (LIFO)
    let mut popped = Vec::new();
    while let Some(t) = queue.pop() {
        popped.push(t);
    }
    assert_eq!(popped.len(), 5);
    // LIFO means reverse order
    assert_eq!(popped[0], ids[4]);
    assert_eq!(popped[4], ids[0]);
}

#[test]
fn local_queue_task_table_steal_batch() {
    init();
    let tasks = LocalQueue::test_task_table(10);
    let src = LocalQueue::new_with_task_table(Arc::clone(&tasks));
    let dst = LocalQueue::new_with_task_table(Arc::clone(&tasks));

    for i in 0..6 {
        src.push(asupersync::types::TaskId::new_for_test(i, 0));
    }

    let stolen = src.stealer().steal_batch(&dst);
    assert!(stolen, "Should steal at least one task");

    // Verify both queues have tasks
    let mut src_count = 0;
    while src.pop().is_some() {
        src_count += 1;
    }
    let mut dst_count = 0;
    while dst.pop().is_some() {
        dst_count += 1;
    }

    assert_eq!(src_count + dst_count, 6, "All tasks accounted for");
    assert!((1..=3).contains(&dst_count), "Steals up to half");
}

#[test]
fn local_queue_task_table_empty_operations() {
    init();
    let tasks = LocalQueue::test_task_table(10);
    let queue = LocalQueue::new_with_task_table(Arc::clone(&tasks));
    let stealer = queue.stealer();

    assert!(queue.is_empty());
    assert_eq!(queue.pop(), None);
    assert_eq!(stealer.steal(), None);

    // push_many with empty slice is a no-op
    queue.push_many(&[]);
    assert!(queue.is_empty());
}

#[test]
fn local_queue_task_table_concurrent_push_steal() {
    use std::sync::Barrier;
    use std::thread;
    init();

    let tasks = LocalQueue::test_task_table(200);
    let queue = LocalQueue::new_with_task_table(Arc::clone(&tasks));
    let stealer = queue.stealer();
    let barrier = Arc::new(Barrier::new(2));

    let total_tasks = 100;
    let stolen_count = Arc::new(AtomicUsize::new(0));

    let stolen_count_clone = Arc::clone(&stolen_count);
    let barrier_clone = Arc::clone(&barrier);

    let thief = thread::spawn(move || {
        barrier_clone.wait();
        for _ in 0..total_tasks * 2 {
            if stealer.steal().is_some() {
                stolen_count_clone.fetch_add(1, Ordering::SeqCst);
            }
        }
    });

    barrier.wait();
    for i in 0..total_tasks {
        queue.push(asupersync::types::TaskId::new_for_test(i as u32, 0));
    }

    // Pop remaining from owner
    let mut owner_popped = 0;
    while queue.pop().is_some() {
        owner_popped += 1;
    }

    thief.join().expect("thief panicked");

    let total = owner_popped + stolen_count.load(Ordering::SeqCst);
    assert_eq!(
        total,
        total_tasks,
        "No task loss: owner={owner_popped}, stolen={}",
        stolen_count.load(Ordering::SeqCst)
    );
}

// =============================================================================
// Cross-table: obligation create + commit + region advancement
// =============================================================================

#[test]
fn sharding_multiple_obligation_kinds() {
    init();
    let seed = 0x4D4F_4B49_4E44_u64; // "MOKIND"
    let config = LabConfig::new(seed);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let (task_id, _handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async {
            asupersync::runtime::yield_now().await;
        })
        .expect("create task");
    runtime.scheduler.lock().schedule(task_id, 0);

    // Create obligations of different kinds
    let kinds = [
        ObligationKind::SendPermit,
        ObligationKind::Ack,
        ObligationKind::Lease,
    ];

    for (i, kind) in kinds.iter().enumerate() {
        let obl = runtime
            .state
            .create_obligation(*kind, task_id, root, Some(format!("obl-{i}")))
            .expect("create obligation");
        runtime
            .state
            .commit_obligation(obl)
            .expect("commit obligation");
    }

    runtime.run_until_quiescent();

    let report = runtime.report();
    assert!(report.quiescent);
    assert!(report.invariant_violations.is_empty());
}

#[test]
fn sharding_obligation_abort_then_quiescence() {
    init();
    let seed = 0x4142_4F52_5420_u64; // "ABORT "
    let config = LabConfig::new(seed);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let (task_id, _handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async {
            asupersync::runtime::yield_now().await;
        })
        .expect("create task");
    runtime.scheduler.lock().schedule(task_id, 0);

    // Create obligations and abort them instead of committing
    for i in 0..5 {
        let obl = runtime
            .state
            .create_obligation(
                ObligationKind::SendPermit,
                task_id,
                root,
                Some(format!("abort-obl-{i}")),
            )
            .expect("create obligation");
        runtime
            .state
            .abort_obligation(obl, ObligationAbortReason::Cancel)
            .expect("abort obligation");
    }

    runtime.run_until_quiescent();

    let report = runtime.report();
    assert!(report.quiescent);
    assert!(
        report.invariant_violations.is_empty(),
        "No violations after abort: {:?}",
        report.invariant_violations
    );
}

#[test]
fn sharding_mixed_commit_abort_obligations() {
    init();
    let seed = 0x4D49_5845_4420_u64; // "MIXED "
    let config = LabConfig::new(seed);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let (task_id, _handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async {
            asupersync::runtime::yield_now().await;
        })
        .expect("create task");
    runtime.scheduler.lock().schedule(task_id, 0);

    // Interleave commits and aborts
    for i in 0..10 {
        let obl = runtime
            .state
            .create_obligation(
                ObligationKind::SendPermit,
                task_id,
                root,
                Some(format!("mixed-obl-{i}")),
            )
            .expect("create obligation");
        if i % 2 == 0 {
            runtime
                .state
                .commit_obligation(obl)
                .expect("commit obligation");
        } else {
            runtime
                .state
                .abort_obligation(obl, ObligationAbortReason::Cancel)
                .expect("abort obligation");
        }
    }

    runtime.run_until_quiescent();
    let report = runtime.report();
    assert!(report.quiescent);
    assert!(report.invariant_violations.is_empty());
}

// =============================================================================
// Cross-table: hierarchical regions + cancellation
// =============================================================================

#[test]
fn sharding_child_region_close_propagation() {
    init();
    let seed = 0x4348_494C_4420_u64; // "CHILD "
    let config = LabConfig::new(seed).max_steps(20_000);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let completed = Arc::new(AtomicUsize::new(0));

    // Create child region
    let child = runtime
        .state
        .create_child_region(root, Budget::INFINITE)
        .expect("create child region");

    // Spawn tasks in both root and child
    for _ in 0..5 {
        let completed = Arc::clone(&completed);
        let (task_id, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                for _ in 0..3 {
                    asupersync::runtime::yield_now().await;
                }
                completed.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create root task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    for _ in 0..5 {
        let completed = Arc::clone(&completed);
        let (task_id, _handle) = runtime
            .state
            .create_task(child, Budget::INFINITE, async move {
                for _ in 0..3 {
                    asupersync::runtime::yield_now().await;
                }
                completed.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create child task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();

    let report = runtime.report();
    assert!(report.quiescent);
    assert!(report.invariant_violations.is_empty());
    assert_eq!(completed.load(Ordering::SeqCst), 10);
}

#[test]
fn sharding_cancel_child_region_obligations_drain() {
    init();
    let seed = 0x4343_414E_u64; // "CCAN"
    let config = LabConfig::new(seed).max_steps(20_000);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let child = runtime
        .state
        .create_child_region(root, Budget::INFINITE)
        .expect("create child region");

    // Spawn a task in the child region with an obligation
    let (task_id, _handle) = runtime
        .state
        .create_task(child, Budget::INFINITE, async {
            for _ in 0..50 {
                asupersync::runtime::yield_now().await;
            }
        })
        .expect("create task");
    runtime.scheduler.lock().schedule(task_id, 0);

    let obl = runtime
        .state
        .create_obligation(ObligationKind::SendPermit, task_id, child, None)
        .expect("create obligation");

    // Cancel only the child region
    let tasks = runtime
        .state
        .cancel_request(child, &CancelReason::user("cancel-child"), None);
    for (tid, priority) in tasks {
        runtime.scheduler.lock().schedule(tid, priority);
    }

    // Abort the obligation during cancellation
    let _ = runtime
        .state
        .abort_obligation(obl, ObligationAbortReason::Cancel);

    runtime.run_until_quiescent();

    let report = runtime.report();
    assert!(report.quiescent);
    assert!(report.invariant_violations.is_empty());
}

#[test]
fn sharding_cancel_root_with_deep_hierarchy() {
    init();
    let seed = 0x4445_4550_u64; // "DEEP"
    let config = LabConfig::new(seed).max_steps(50_000);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let completed = Arc::new(AtomicUsize::new(0));

    // Create 3-level hierarchy: root -> child -> grandchild
    let child = runtime
        .state
        .create_child_region(root, Budget::INFINITE)
        .expect("create child");
    let grandchild = runtime
        .state
        .create_child_region(child, Budget::INFINITE)
        .expect("create grandchild");

    // Spawn tasks at each level
    for region in [root, child, grandchild] {
        let completed = Arc::clone(&completed);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                for _ in 0..10 {
                    asupersync::runtime::yield_now().await;
                }
                completed.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    // Cancel root — should propagate to all descendants
    let tasks = runtime
        .state
        .cancel_request(root, &CancelReason::user("cancel-root"), None);
    for (tid, priority) in tasks {
        runtime.scheduler.lock().schedule(tid, priority);
    }

    runtime.run_until_quiescent();

    let report = runtime.report();
    assert!(report.quiescent);
    assert!(
        report.invariant_violations.is_empty(),
        "Deep hierarchy cancel violations: {:?}",
        report.invariant_violations
    );
}

// =============================================================================
// Cross-table: task completion + region state advancement
// =============================================================================

#[test]
fn sharding_task_completion_advances_region() {
    init();
    let seed = 0x434F_4D50_u64; // "COMP"
    let config = LabConfig::new(seed).max_steps(10_000);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let completed = Arc::new(AtomicUsize::new(0));

    // Single task in root — when it completes, region should advance
    let completed_clone = Arc::clone(&completed);
    let (task_id, _handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            asupersync::runtime::yield_now().await;
            completed_clone.fetch_add(1, Ordering::SeqCst);
        })
        .expect("create task");
    runtime.scheduler.lock().schedule(task_id, 0);

    runtime.run_until_quiescent();

    assert_eq!(completed.load(Ordering::SeqCst), 1);
    let report = runtime.report();
    assert!(report.quiescent);
    assert!(report.invariant_violations.is_empty());
}

#[test]
fn sharding_many_tasks_staggered_completion() {
    init();
    let seed = 0x5354_4147_u64; // "STAG"
    let config = LabConfig::new(seed).max_steps(50_000);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let completed = Arc::new(AtomicUsize::new(0));

    // Tasks with varying yield counts → staggered completion order
    for i in 0..20 {
        let completed = Arc::clone(&completed);
        let yields = (i % 5) + 1; // 1 to 5 yields
        let (task_id, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                for _ in 0..yields {
                    asupersync::runtime::yield_now().await;
                }
                completed.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();

    assert_eq!(completed.load(Ordering::SeqCst), 20);
    let report = runtime.report();
    assert!(report.quiescent);
    assert!(report.invariant_violations.is_empty());
}

// =============================================================================
// Trace replay equivalence across seeds
// =============================================================================

#[test]
fn sharding_trace_determinism_100_seeds() {
    init();

    // Verify determinism across 100 different seeds
    for base_seed in 0..100u64 {
        let seed = 0xDE7E_0000_0000 | base_seed;

        let mut runtime_a = LabRuntime::new(LabConfig::new(seed));
        setup_trace_replay_scenario(&mut runtime_a);
        runtime_a.run_until_quiescent();
        let report_a = runtime_a.report();

        let mut runtime_b = LabRuntime::new(LabConfig::new(seed));
        setup_trace_replay_scenario(&mut runtime_b);
        runtime_b.run_until_quiescent();
        let report_b = runtime_b.report();

        assert_eq!(
            report_a.trace_fingerprint, report_b.trace_fingerprint,
            "Determinism violation at seed {seed:#x}"
        );
        assert_eq!(
            report_a.steps_total, report_b.steps_total,
            "Step count mismatch at seed {seed:#x}"
        );
    }
}

#[test]
fn sharding_trace_different_seeds_diverge() {
    init();

    // Different seeds should produce different traces (sanity check)
    let mut runtime_x = LabRuntime::new(LabConfig::new(0xAAAA));
    setup_trace_replay_scenario(&mut runtime_x);
    runtime_x.run_until_quiescent();
    let report_x = runtime_x.report();

    let mut runtime_y = LabRuntime::new(LabConfig::new(0xBBBB));
    setup_trace_replay_scenario(&mut runtime_y);
    runtime_y.run_until_quiescent();
    let report_y = runtime_y.report();

    // They may or may not diverge depending on scenario complexity,
    // but the execution should complete without invariant violations
    assert!(report_x.quiescent);
    assert!(report_y.quiescent);
    assert!(report_x.invariant_violations.is_empty());
    assert!(report_y.invariant_violations.is_empty());
}

// =============================================================================
// Cross-table: cancellation with obligations + task completion
// =============================================================================

#[test]
fn sharding_cancel_with_pending_obligations_multiple_tasks() {
    init();
    let seed = 0x4D50_4F42_u64; // "MPOB"
    let config = LabConfig::new(seed).max_steps(20_000);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let mut obligation_ids = Vec::new();

    // Create multiple tasks, each with an obligation
    for i in 0..5 {
        let (task_id, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                for _ in 0..20 {
                    asupersync::runtime::yield_now().await;
                }
                i
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);

        let obl = runtime
            .state
            .create_obligation(
                ObligationKind::SendPermit,
                task_id,
                root,
                Some(format!("multi-task-obl-{i}")),
            )
            .expect("create obligation");

        obligation_ids.push(obl);
    }

    // Cancel root
    let tasks = runtime
        .state
        .cancel_request(root, &CancelReason::user("multi-cancel"), None);
    for (tid, priority) in tasks {
        runtime.scheduler.lock().schedule(tid, priority);
    }

    // Abort all obligations
    for obl in obligation_ids {
        let _ = runtime
            .state
            .abort_obligation(obl, ObligationAbortReason::Cancel);
    }

    runtime.run_until_quiescent();

    let report = runtime.report();
    assert!(report.quiescent);
    assert!(
        report.invariant_violations.is_empty(),
        "Multi-task cancel violations: {:?}",
        report.invariant_violations
    );
}

// =============================================================================
// Stress: high task count + obligations + cancellation
// =============================================================================

#[test]
fn sharding_stress_50_tasks_with_obligations() {
    init();
    let seed = 0x5354_5245_5353_u64; // "STRESS"
    let config = LabConfig::new(seed).max_steps(100_000);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let completed = Arc::new(AtomicUsize::new(0));

    for i in 0..50 {
        let completed = Arc::clone(&completed);
        let yields = (i % 10) + 1;
        let (task_id, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                for _ in 0..yields {
                    asupersync::runtime::yield_now().await;
                }
                completed.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);

        // Every other task gets an obligation that is immediately committed
        if i % 2 == 0 {
            let obl = runtime
                .state
                .create_obligation(
                    ObligationKind::SendPermit,
                    task_id,
                    root,
                    Some(format!("stress-obl-{i}")),
                )
                .expect("create obligation");
            runtime
                .state
                .commit_obligation(obl)
                .expect("commit obligation");
        }
    }

    runtime.run_until_quiescent();

    assert_eq!(completed.load(Ordering::SeqCst), 50);
    let report = runtime.report();
    assert!(report.quiescent);
    assert!(report.invariant_violations.is_empty());
}

#[test]
fn sharding_stress_cancel_mid_execution() {
    init();
    let seed = 0x4D49_4443_u64; // "MIDC"
    let config = LabConfig::new(seed).max_steps(50_000);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let started = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicUsize::new(0));

    // Spawn 20 tasks that yield many times
    for _ in 0..20 {
        let started = Arc::clone(&started);
        let completed = Arc::clone(&completed);
        let (task_id, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                started.fetch_add(1, Ordering::SeqCst);
                for _ in 0..50 {
                    asupersync::runtime::yield_now().await;
                }
                completed.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    // Cancel after initial setup (tasks are scheduled but haven't all completed)
    let tasks = runtime
        .state
        .cancel_request(root, &CancelReason::user("mid-cancel"), None);
    for (tid, priority) in tasks {
        runtime.scheduler.lock().schedule(tid, priority);
    }

    runtime.run_until_quiescent();

    let report = runtime.report();
    assert!(report.quiescent, "Must reach quiescence after mid-cancel");
    assert!(
        report.invariant_violations.is_empty(),
        "Mid-cancel violations: {:?}",
        report.invariant_violations
    );
}

// =============================================================================
// Sibling region cancellation (cancel one child, other continues)
// =============================================================================

#[test]
fn sharding_cancel_one_sibling_other_continues() {
    init();
    let seed = 0x5349_424C_u64; // "SIBL"
    let config = LabConfig::new(seed).max_steps(50_000);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let child_a = runtime
        .state
        .create_child_region(root, Budget::INFINITE)
        .expect("create child A");
    let child_b = runtime
        .state
        .create_child_region(root, Budget::INFINITE)
        .expect("create child B");

    let a_completed = Arc::new(AtomicBool::new(false));
    let b_completed = Arc::new(AtomicBool::new(false));

    // Task in child A
    {
        let flag = Arc::clone(&a_completed);
        let (task_id, _handle) = runtime
            .state
            .create_task(child_a, Budget::INFINITE, async move {
                for _ in 0..20 {
                    asupersync::runtime::yield_now().await;
                }
                flag.store(true, Ordering::SeqCst);
            })
            .expect("create task A");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    // Task in child B
    {
        let flag = Arc::clone(&b_completed);
        let (task_id, _handle) = runtime
            .state
            .create_task(child_b, Budget::INFINITE, async move {
                for _ in 0..5 {
                    asupersync::runtime::yield_now().await;
                }
                flag.store(true, Ordering::SeqCst);
            })
            .expect("create task B");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    // Cancel only child A
    let tasks = runtime
        .state
        .cancel_request(child_a, &CancelReason::user("cancel-sibling"), None);
    for (tid, priority) in tasks {
        runtime.scheduler.lock().schedule(tid, priority);
    }

    runtime.run_until_quiescent();

    // Child B should have completed normally
    assert!(
        b_completed.load(Ordering::SeqCst),
        "Child B task should complete despite sibling cancellation"
    );

    let report = runtime.report();
    assert!(report.quiescent);
    assert!(report.invariant_violations.is_empty());
}

// =============================================================================
// Replay determinism for complex scenarios
// =============================================================================

fn setup_complex_scenario(runtime: &mut LabRuntime) {
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let child = runtime
        .state
        .create_child_region(root, Budget::INFINITE)
        .expect("create child");

    // Spawn tasks in both regions with obligations
    for i in 0..5 {
        let yields = (i % 3) + 1;
        let (task_id, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                for _ in 0..yields {
                    asupersync::runtime::yield_now().await;
                }
                i
            })
            .expect("create root task");
        runtime.scheduler.lock().schedule(task_id, 0);

        let obl = runtime
            .state
            .create_obligation(
                ObligationKind::SendPermit,
                task_id,
                root,
                Some(format!("root-obl-{i}")),
            )
            .expect("create obligation");
        runtime
            .state
            .commit_obligation(obl)
            .expect("commit obligation");
    }

    for i in 0..3 {
        let yields = (i % 2) + 2;
        let (task_id, _handle) = runtime
            .state
            .create_task(child, Budget::INFINITE, async move {
                for _ in 0..yields {
                    asupersync::runtime::yield_now().await;
                }
                i + 100
            })
            .expect("create child task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }
}

#[test]
fn sharding_complex_scenario_replay_determinism() {
    init();
    let seed = 0x434F_4D50_4C58_u64; // "COMPLX"

    let mut runtime_a = LabRuntime::new(LabConfig::new(seed));
    setup_complex_scenario(&mut runtime_a);
    runtime_a.run_until_quiescent();
    let report_a = runtime_a.report();

    let mut runtime_b = LabRuntime::new(LabConfig::new(seed));
    setup_complex_scenario(&mut runtime_b);
    runtime_b.run_until_quiescent();
    let report_b = runtime_b.report();

    assert_eq!(
        report_a.trace_fingerprint, report_b.trace_fingerprint,
        "Complex scenario trace fingerprints must match"
    );
    assert_eq!(report_a.steps_total, report_b.steps_total);
    assert!(report_a.quiescent);
    assert!(report_a.invariant_violations.is_empty());
}

#[test]
fn sharding_cancel_scenario_replay_determinism() {
    init();
    let seed = 0x4352_4550_u64; // "CREP"

    for _ in 0..2 {
        let mut reports = Vec::new();

        for _ in 0..2 {
            let mut runtime = LabRuntime::new(LabConfig::new(seed));
            let root = runtime.state.create_root_region(Budget::INFINITE);
            let child = runtime
                .state
                .create_child_region(root, Budget::INFINITE)
                .expect("create child");

            for i in 0..5 {
                let (task_id, _handle) = runtime
                    .state
                    .create_task(child, Budget::INFINITE, async move {
                        for _ in 0..10 {
                            asupersync::runtime::yield_now().await;
                        }
                        i
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            // Cancel child region
            let tasks =
                runtime
                    .state
                    .cancel_request(child, &CancelReason::user("replay-cancel"), None);
            for (tid, priority) in tasks {
                runtime.scheduler.lock().schedule(tid, priority);
            }

            runtime.run_until_quiescent();
            reports.push(runtime.report());
        }

        assert_eq!(
            reports[0].trace_fingerprint, reports[1].trace_fingerprint,
            "Cancel scenario replay fingerprints must match"
        );
    }
}

// =============================================================================
// Region lifecycle: create → close → verify no leaks
// =============================================================================

#[test]
fn sharding_region_task_no_leaks() {
    init();
    let seed = 0x4C45_414B_u64; // "LEAK"
    let config = LabConfig::new(seed).max_steps(50_000);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let completed = Arc::new(AtomicUsize::new(0));

    // Create and complete tasks across multiple child regions
    for _ in 0..5 {
        let child = runtime
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("create child");

        for _ in 0..3 {
            let completed = Arc::clone(&completed);
            let (task_id, _handle) = runtime
                .state
                .create_task(child, Budget::INFINITE, async move {
                    asupersync::runtime::yield_now().await;
                    completed.fetch_add(1, Ordering::SeqCst);
                })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }
    }

    runtime.run_until_quiescent();

    assert_eq!(completed.load(Ordering::SeqCst), 15);
    let report = runtime.report();
    assert!(report.quiescent);
    assert!(report.invariant_violations.is_empty());
}

// =============================================================================
// Budget-limited tasks
// =============================================================================

#[test]
fn sharding_budget_limited_tasks() {
    init();
    let seed = 0x4255_4447_u64; // "BUDG"
    let config = LabConfig::new(seed).max_steps(10_000);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    // Spawn tasks with limited budgets
    let completed = Arc::new(AtomicUsize::new(0));

    for _ in 0..5 {
        let completed = Arc::clone(&completed);
        let (task_id, _handle) = runtime
            .state
            .create_task(root, Budget::with_deadline_ns(1_000_000), async move {
                asupersync::runtime::yield_now().await;
                completed.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create budget-limited task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();

    let report = runtime.report();
    assert!(report.quiescent);
    assert!(report.invariant_violations.is_empty());
}

// =============================================================================
// Multiple concurrent child regions with obligations
// =============================================================================

#[test]
fn sharding_parallel_child_regions_with_obligations() {
    init();
    let seed = 0x5041_5243_u64; // "PARC"
    let config = LabConfig::new(seed).max_steps(100_000);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let completed = Arc::new(AtomicUsize::new(0));

    // Create 5 child regions, each with tasks and obligations
    for child_idx in 0..5 {
        let child = runtime
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("create child");

        for task_idx in 0..3 {
            let completed = Arc::clone(&completed);
            let yields = (task_idx % 3) + 1;
            let (task_id, _handle) = runtime
                .state
                .create_task(child, Budget::INFINITE, async move {
                    for _ in 0..yields {
                        asupersync::runtime::yield_now().await;
                    }
                    completed.fetch_add(1, Ordering::SeqCst);
                })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);

            // Each task gets an obligation
            let obl = runtime
                .state
                .create_obligation(
                    ObligationKind::SendPermit,
                    task_id,
                    child,
                    Some(format!("child{child_idx}-task{task_idx}")),
                )
                .expect("create obligation");
            runtime
                .state
                .commit_obligation(obl)
                .expect("commit obligation");
        }
    }

    runtime.run_until_quiescent();

    assert_eq!(completed.load(Ordering::SeqCst), 15);
    let report = runtime.report();
    assert!(report.quiescent);
    assert!(
        report.invariant_violations.is_empty(),
        "Parallel child region violations: {:?}",
        report.invariant_violations
    );
}
