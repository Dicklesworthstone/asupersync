//! Cancellation Stress E2E Suite (bd-jj62v).
//!
//! Stress tests for cancellation protocol under adversarial conditions:
//!   - Cancellation storms: rapid fire cancel requests across many tasks
//!   - Timeout cascades: nested region timeouts propagating inward
//!   - Race losers: concurrent cancel + complete racing
//!   - Finalizer-heavy workloads: many finalizers during cancel drain
//!   - Mask depth stress: deep cancel masking under cancellation
//!
//! All tests use deterministic seeds and structured logging for replay.
//!
//! Cross-references:
//!   CancellationProtocolOracle: src/lab/oracle/cancellation_protocol.rs
//!   Cancel state machine: src/types/cancel.rs
//!   Conformance tests: tests/cancellation_conformance.rs

#[macro_use]
mod common;

use asupersync::lab::oracle::CancellationProtocolOracle;
use asupersync::record::task::TaskState;
use asupersync::types::{Budget, CancelKind, CancelReason, Outcome, RegionId, TaskId, Time};
use common::*;

fn region(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

fn task(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}

fn t(nanos: u64) -> Time {
    Time::from_nanos(nanos)
}

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

/// Run a full cancel protocol sequence on a task:
/// Running -> CancelRequested -> Cancelling -> Finalizing -> Completed(Cancelled)
fn run_cancel_sequence(
    oracle: &mut CancellationProtocolOracle,
    tid: TaskId,
    reason: CancelReason,
    request_time: u64,
    complete_time: u64,
) {
    let budget = Budget::INFINITE;

    oracle.on_cancel_request(tid, reason.clone(), t(request_time));
    oracle.on_transition(
        tid,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        t(request_time),
    );
    oracle.on_cancel_ack(tid, t(request_time + 1));
    oracle.on_transition(
        tid,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        t(request_time + 1),
    );
    oracle.on_transition(
        tid,
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        t(complete_time - 1),
    );
    oracle.on_transition(
        tid,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        t(complete_time),
    );
}

// ============================================================================
// Cancellation Storm
// ============================================================================

/// Cancel 50 tasks in a single region simultaneously.
#[test]
fn cancel_storm_single_region() {
    init_test("cancel_storm_single_region");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    oracle.on_region_create(root, None);
    oracle.on_region_cancel(root, CancelReason::new(CancelKind::User), t(5));

    let n_tasks: u32 = 50;
    for i in 0..n_tasks {
        oracle.on_task_create(task(i), root);
        oracle.on_transition(task(i), &TaskState::Created, &TaskState::Running, t(6));
    }

    for i in 0..n_tasks {
        let req_time = 10 + u64::from(i) * 3;
        run_cancel_sequence(
            &mut oracle,
            task(i),
            CancelReason::new(CancelKind::User),
            req_time,
            req_time + 10,
        );
    }

    oracle.on_region_close(root, t(500));

    let result = oracle.check();
    assert_with_log!(result.is_ok(), "storm: no violations", true, result.is_ok());

    let violations = oracle.all_violations();
    assert_with_log!(
        violations.is_empty(),
        "storm: 0 violations",
        0,
        violations.len()
    );

    test_complete!("cancel_storm_single_region");
}

/// Cancel storm with mixed cancel reasons.
#[test]
fn cancel_storm_mixed_reasons() {
    init_test("cancel_storm_mixed_reasons");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    oracle.on_region_create(root, None);

    let n_tasks: u32 = 20;
    let reasons = [
        CancelReason::new(CancelKind::User),
        CancelReason::new(CancelKind::Timeout),
        CancelReason::new(CancelKind::Shutdown),
        CancelReason::new(CancelKind::FailFast),
    ];

    for i in 0..n_tasks {
        oracle.on_task_create(task(i), root);
        oracle.on_transition(task(i), &TaskState::Created, &TaskState::Running, t(5));
    }

    for i in 0..n_tasks {
        let reason = reasons[(i as usize) % reasons.len()].clone();
        let req_time = 10 + u64::from(i) * 4;
        run_cancel_sequence(&mut oracle, task(i), reason, req_time, req_time + 10);
    }

    oracle.on_region_close(root, t(500));

    let result = oracle.check();
    assert_with_log!(
        result.is_ok(),
        "mixed storm: no violations",
        true,
        result.is_ok()
    );

    test_complete!("cancel_storm_mixed_reasons");
}

// ============================================================================
// Timeout Cascades
// ============================================================================

/// 5-level nested regions where outer timeout propagates to all descendants.
#[test]
fn timeout_cascade_5_levels() {
    init_test("timeout_cascade_5_levels");

    let mut oracle = CancellationProtocolOracle::new();
    let regions: Vec<RegionId> = (0..5).map(|i| region(i)).collect();
    oracle.on_region_create(regions[0], None);
    for i in 1..5 {
        oracle.on_region_create(regions[i], Some(regions[i - 1]));
    }

    let tasks: Vec<TaskId> = (0..5).map(|i| task(i)).collect();
    for i in 0..5 {
        oracle.on_task_create(tasks[i], regions[i]);
        oracle.on_transition(tasks[i], &TaskState::Created, &TaskState::Running, t(5));
    }

    // Propagate region cancel to all regions (root = Timeout, children = ParentCancelled)
    oracle.on_region_cancel(regions[0], CancelReason::timeout(), t(100));
    for i in 1..5 {
        oracle.on_region_cancel(
            regions[i],
            CancelReason::new(CancelKind::ParentCancelled),
            t(100),
        );
    }

    for i in 0..5 {
        // Root task cancelled for Timeout, descendants for ParentCancelled
        let reason = if i == 0 {
            CancelReason::timeout()
        } else {
            CancelReason::new(CancelKind::ParentCancelled)
        };
        let req_time = 110 + (i as u64) * 10;
        run_cancel_sequence(&mut oracle, tasks[i], reason, req_time, req_time + 8);
    }

    for i in (0..5).rev() {
        oracle.on_region_close(regions[i], t(300 + (4 - i as u64) * 10));
    }

    let result = oracle.check();
    assert_with_log!(
        result.is_ok(),
        "cascade: no violations",
        true,
        result.is_ok()
    );

    test_complete!("timeout_cascade_5_levels");
}

/// Wide tree: 1 parent with 10 child regions, each with 3 tasks.
#[test]
fn timeout_cascade_wide_tree() {
    init_test("timeout_cascade_wide_tree");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    oracle.on_region_create(root, None);

    let n_children: u32 = 10;
    let tasks_per_child: u32 = 3;

    for c in 0..n_children {
        let child_region = region(1 + c);
        oracle.on_region_create(child_region, Some(root));
        for t_idx in 0..tasks_per_child {
            let tid = task(c * tasks_per_child + t_idx);
            oracle.on_task_create(tid, child_region);
            oracle.on_transition(tid, &TaskState::Created, &TaskState::Running, t(5));
        }
    }

    oracle.on_region_cancel(root, CancelReason::new(CancelKind::User), t(50));
    // Propagate cancel to all child regions
    for c in 0..n_children {
        oracle.on_region_cancel(
            region(1 + c),
            CancelReason::new(CancelKind::ParentCancelled),
            t(50),
        );
    }

    let mut time_counter = 100u64;
    for c in 0..n_children {
        for t_idx in 0..tasks_per_child {
            let tid = task(c * tasks_per_child + t_idx);
            let reason = CancelReason::new(CancelKind::ParentCancelled);
            run_cancel_sequence(&mut oracle, tid, reason, time_counter, time_counter + 8);
            time_counter += 10;
        }
    }

    for c in 0..n_children {
        oracle.on_region_close(region(1 + c), t(500 + u64::from(c)));
    }
    oracle.on_region_close(root, t(600));

    let result = oracle.check();
    assert_with_log!(
        result.is_ok(),
        "wide cascade: no violations",
        true,
        result.is_ok()
    );

    test_complete!("timeout_cascade_wide_tree");
}

// ============================================================================
// Race Losers
// ============================================================================

/// Task completes normally just before cancel request arrives.
#[test]
fn race_complete_before_cancel() {
    init_test("race_complete_before_cancel");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let worker = task(0);

    oracle.on_region_create(root, None);
    oracle.on_task_create(worker, root);
    oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(10));
    oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::Completed(Outcome::Ok(())),
        t(50),
    );

    oracle.on_region_close(root, t(100));

    let result = oracle.check();
    assert_with_log!(
        result.is_ok(),
        "race: complete before cancel ok",
        true,
        result.is_ok()
    );

    test_complete!("race_complete_before_cancel");
}

/// Multiple tasks: some complete normally, others get cancelled.
#[test]
fn race_mixed_completion_modes() {
    init_test("race_mixed_completion_modes");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    oracle.on_region_create(root, None);

    let n_tasks: u32 = 10;
    for i in 0..n_tasks {
        oracle.on_task_create(task(i), root);
        oracle.on_transition(task(i), &TaskState::Created, &TaskState::Running, t(5));
    }

    for i in 0..n_tasks {
        let tid = task(i);
        if i % 2 == 0 {
            oracle.on_transition(
                tid,
                &TaskState::Running,
                &TaskState::Completed(Outcome::Ok(())),
                t(50 + u64::from(i)),
            );
        } else {
            let reason = CancelReason::new(CancelKind::User);
            let req_time = 50 + u64::from(i) * 3;
            run_cancel_sequence(&mut oracle, tid, reason, req_time, req_time + 10);
        }
    }

    oracle.on_region_close(root, t(300));

    let result = oracle.check();
    assert_with_log!(
        result.is_ok(),
        "mixed modes: no violations",
        true,
        result.is_ok()
    );

    test_complete!("race_mixed_completion_modes");
}

// ============================================================================
// Cancel Mask Depth Stress
// ============================================================================

/// Task enters cancel-masked sections during cancellation.
#[test]
fn cancel_mask_depth_stress() {
    init_test("cancel_mask_depth_stress");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let worker = task(0);

    oracle.on_region_create(root, None);
    oracle.on_task_create(worker, root);
    oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(5));

    for i in 0..5u64 {
        oracle.on_mask_enter(worker, t(10 + i));
    }

    oracle.on_cancel_request(worker, CancelReason::new(CancelKind::User), t(50));

    for i in 0..5u64 {
        oracle.on_mask_exit(worker, t(60 + i));
    }

    let reason = CancelReason::new(CancelKind::User);
    let budget = Budget::INFINITE;
    oracle.on_transition(
        worker,
        &TaskState::Running,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        t(70),
    );
    oracle.on_cancel_ack(worker, t(71));
    oracle.on_transition(
        worker,
        &TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        t(71),
    );
    oracle.on_transition(
        worker,
        &TaskState::Cancelling {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        t(80),
    );
    oracle.on_transition(
        worker,
        &TaskState::Finalizing {
            reason: reason.clone(),
            cleanup_budget: budget,
        },
        &TaskState::Completed(Outcome::Cancelled(reason)),
        t(90),
    );

    oracle.on_region_close(root, t(200));

    let result = oracle.check();
    assert_with_log!(
        result.is_ok(),
        "mask depth: no violations",
        true,
        result.is_ok()
    );

    test_complete!("cancel_mask_depth_stress");
}

// ============================================================================
// Cancel Chain Attribution
// ============================================================================

/// Cancel reason chains: user -> parent -> parent -> parent.
#[test]
fn cancel_chain_attribution() {
    init_test("cancel_chain_attribution");

    let root_reason = CancelReason::new(CancelKind::User);
    let child1_reason =
        CancelReason::new(CancelKind::ParentCancelled).with_cause(root_reason.clone());
    let child2_reason =
        CancelReason::new(CancelKind::ParentCancelled).with_cause(child1_reason.clone());
    let child3_reason =
        CancelReason::new(CancelKind::ParentCancelled).with_cause(child2_reason.clone());

    let mut depth = 0u32;
    let mut current = Some(&child3_reason);
    while let Some(r) = current {
        depth += 1;
        current = r.cause();
    }

    assert_with_log!(depth == 4, "chain depth is 4", 4, depth);

    let mut r = &child3_reason;
    while let Some(cause) = r.cause() {
        r = cause;
    }
    let root_kind_match = r.kind == CancelKind::User;
    assert_with_log!(root_kind_match, "root cause is User", true, root_kind_match);

    test_complete!("cancel_chain_attribution");
}

// ============================================================================
// Negative Tests
// ============================================================================

/// Task cancel-requested but never acknowledged -> violation expected.
#[test]
fn negative_cancel_not_acked() {
    init_test("negative_cancel_not_acked");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    let worker = task(0);

    oracle.on_region_create(root, None);
    oracle.on_task_create(worker, root);
    oracle.on_transition(worker, &TaskState::Created, &TaskState::Running, t(5));

    oracle.on_cancel_request(worker, CancelReason::new(CancelKind::User), t(10));

    for _ in 0..20 {
        oracle.on_task_poll(worker);
    }

    oracle.on_region_close(root, t(200));

    let violations = oracle.all_violations();
    let has_violations = !violations.is_empty();
    assert_with_log!(
        has_violations,
        "negative: violations detected",
        true,
        has_violations
    );

    test_complete!("negative_cancel_not_acked");
}

// ============================================================================
// Deterministic Replay
// ============================================================================

/// Verify that the same seed produces identical cancellation sequences.
#[test]
fn deterministic_cancel_replay() {
    init_test("deterministic_cancel_replay");

    let seed: u64 = 0xCAFE_BABE;
    let mut results = Vec::new();

    for run in 0..2u32 {
        let mut oracle = CancellationProtocolOracle::new();
        let root = region(0);
        oracle.on_region_create(root, None);

        let n_tasks = 10u32;
        for i in 0..n_tasks {
            oracle.on_task_create(task(i), root);
            oracle.on_transition(task(i), &TaskState::Created, &TaskState::Running, t(5));
        }

        let mut order: Vec<u32> = (0..n_tasks).collect();
        for i in 0..n_tasks as usize {
            let j = ((seed.wrapping_mul(i as u64 + 1)) % n_tasks as u64) as usize;
            order.swap(i, j);
        }

        for (idx, &task_id) in order.iter().enumerate() {
            let reason = CancelReason::new(CancelKind::User);
            let req_time = 10 + (idx as u64) * 4;
            run_cancel_sequence(&mut oracle, task(task_id), reason, req_time, req_time + 10);
        }

        oracle.on_region_close(root, t(500));
        let result = oracle.check();
        results.push(result.is_ok());

        tracing::info!(run = run, ok = results.last().unwrap(), "replay run");
    }

    assert_with_log!(
        results[0] == results[1],
        "deterministic replay",
        results[0],
        results[1]
    );
    assert_with_log!(results[0], "replay: both pass", true, results[0]);

    test_complete!("deterministic_cancel_replay");
}

// ============================================================================
// Finalizer-Heavy Workload
// ============================================================================

/// 20 tasks all entering finalizer phase simultaneously.
#[test]
fn finalizer_heavy_workload() {
    init_test("finalizer_heavy_workload");

    let mut oracle = CancellationProtocolOracle::new();
    let root = region(0);
    oracle.on_region_create(root, None);
    oracle.on_region_cancel(root, CancelReason::new(CancelKind::Shutdown), t(5));

    let n_tasks: u32 = 20;
    let reason = CancelReason::new(CancelKind::Shutdown);
    let budget = Budget::INFINITE;

    for i in 0..n_tasks {
        oracle.on_task_create(task(i), root);
        oracle.on_transition(task(i), &TaskState::Created, &TaskState::Running, t(6));
    }

    for i in 0..n_tasks {
        let tid = task(i);
        oracle.on_cancel_request(tid, reason.clone(), t(10));
        oracle.on_transition(
            tid,
            &TaskState::Running,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget: budget,
            },
            t(10),
        );
    }

    for i in 0..n_tasks {
        let tid = task(i);
        oracle.on_cancel_ack(tid, t(20));
        oracle.on_transition(
            tid,
            &TaskState::CancelRequested {
                reason: reason.clone(),
                cleanup_budget: budget,
            },
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget: budget,
            },
            t(20),
        );
    }

    for i in 0..n_tasks {
        let tid = task(i);
        oracle.on_transition(
            tid,
            &TaskState::Cancelling {
                reason: reason.clone(),
                cleanup_budget: budget,
            },
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget: budget,
            },
            t(30),
        );
    }

    for i in 0..n_tasks {
        let tid = task(i);
        oracle.on_transition(
            tid,
            &TaskState::Finalizing {
                reason: reason.clone(),
                cleanup_budget: budget,
            },
            &TaskState::Completed(Outcome::Cancelled(reason.clone())),
            t(40 + u64::from(i)),
        );
    }

    oracle.on_region_close(root, t(200));

    let result = oracle.check();
    assert_with_log!(
        result.is_ok(),
        "finalizer heavy: no violations",
        true,
        result.is_ok()
    );

    test_complete!("finalizer_heavy_workload");
}
