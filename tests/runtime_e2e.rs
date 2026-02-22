#![allow(missing_docs)]

//! Runtime E2E + stress tests with structured logging (bd-n6w9, bd-21f9).
//!
//! Exercises cancellation storms, timer storms, I/O readiness, region
//! close/quiescence, obligation lifecycle, budget enforcement, and
//! structured concurrency invariants across multi-worker scheduling.

#[macro_use]
mod common;

use asupersync::channel::mpsc;
use asupersync::channel::session::{tracked_channel, tracked_oneshot};
use asupersync::cx::Cx;
use asupersync::error::ErrorKind;
use asupersync::lab::chaos::ChaosConfig;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::obligation::graded::{GradedScope, SendPermit};
use asupersync::record::task::TaskState;
use asupersync::record::{
    AdmissionError, AdmissionKind, ObligationAbortReason, ObligationKind, RegionLimits,
};
use asupersync::runtime::state::RuntimeState;
use asupersync::runtime::{global_alloc_count, yield_now};
use asupersync::test_logging::TestHarness;
use asupersync::trace::replayer::TraceReplayer;
use asupersync::types::{Budget, CancelKind, CancelReason, Outcome, RegionId, TaskId, Time};
use asupersync::util::ArenaIndex;
use common::*;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

static ALLOC_TEST_GUARD: Mutex<()> = Mutex::new(());

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

/// Create a child region under the given parent.
fn create_child_region(state: &mut RuntimeState, parent: RegionId) -> RegionId {
    use asupersync::record::region::RegionRecord;
    let idx = state.regions.insert(RegionRecord::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        Some(parent),
        Budget::INFINITE,
    ));
    let id = RegionId::from_arena(idx);
    state.region_mut(id).expect("region missing").id = id;
    state
        .region_mut(parent)
        .expect("parent missing")
        .add_child(id)
        .expect("add child");
    id
}

fn cancel_region(runtime: &mut LabRuntime, region: RegionId, reason: &CancelReason) -> usize {
    let tasks = runtime.state.cancel_request(region, reason, None);
    let mut cancel_count = 0usize;
    let mut scheduler = runtime.scheduler.lock();
    for (task, priority) in tasks {
        scheduler.schedule_cancel(task, priority);
        cancel_count += 1;
    }
    drop(scheduler);
    cancel_count
}

fn spawn_cancellable_loop(
    runtime: &mut LabRuntime,
    region: RegionId,
    iterations: usize,
    counter: Option<Arc<AtomicUsize>>,
) -> TaskId {
    let (task_id, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            for _ in 0..iterations {
                let Some(cx) = Cx::current() else {
                    return;
                };
                if cx.checkpoint().is_err() {
                    return;
                }
                if let Some(counter) = counter.as_ref() {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
                yield_now().await;
            }
        })
        .expect("create cancellable task");
    runtime.scheduler.lock().schedule(task_id, 0);
    task_id
}

fn collect_replay_failure_artifacts(
    harness: &mut TestHarness,
    runtime: &mut LabRuntime,
    label: &str,
) {
    let Some(trace) = runtime.finish_replay_trace() else {
        harness.collect_artifact(
            &format!("{label}_replay_error.txt"),
            "replay trace not captured (recording disabled)",
        );
        return;
    };

    if let Ok(json) = serde_json::to_string_pretty(&trace) {
        harness.collect_artifact(&format!("{label}_replay_trace.json"), &json);
    }

    let mut replayer = TraceReplayer::new(trace.clone());
    let mut replay_ok = true;
    for event in &trace.events {
        if let Err(err) = replayer.verify_and_advance(event) {
            replay_ok = false;
            harness.collect_artifact(
                &format!("{label}_replay_error.txt"),
                &format!("replay divergence: {err}"),
            );
            break;
        }
    }
    if replay_ok && !replayer.is_completed() {
        harness.collect_artifact(
            &format!("{label}_replay_error.txt"),
            "replayer did not complete",
        );
    }
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

    runtime.scheduler.lock().schedule(task_id, 0);
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
        runtime.scheduler.lock().schedule(task_id, 0);
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

    let (task_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            started.fetch_add(1, Ordering::SeqCst);
            // task would do long work here
        })
        .expect("create task");
    runtime.scheduler.lock().schedule(task_id, 0);
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

    for i in 0..n_regions {
        let region = runtime.state.create_root_region(Budget::INFINITE);

        for _ in 0..n_tasks_per_region {
            let ts = total_spawned.clone();
            let (task_id, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    ts.fetch_add(1, Ordering::SeqCst);
                })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
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
// Cancellation Stress Suite (bd-jj62v)
// ============================================================================

#[test]
fn e2e_cancellation_storm_with_chaos_replay() {
    let seed = 0x00C0_FFEE_u64;
    let ctx = TestContext::new("cancel_storm_chaos", seed)
        .with_subsystem("cancellation")
        .with_invariant("quiescence");
    let mut harness = TestHarness::with_context("e2e_cancellation_storm_with_chaos_replay", ctx);
    init_test_logging();

    let chaos = ChaosConfig::new(seed)
        .with_cancel_probability(0.35)
        .with_delay_probability(0.1)
        .with_delay_range(Duration::from_micros(1)..Duration::from_micros(50));
    let config = LabConfig::new(seed)
        .with_default_replay_recording()
        .with_chaos(chaos)
        .worker_count(4)
        .trace_capacity(16 * 1024);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    harness.enter_phase("spawn");
    let task_count = 80usize;
    let progress = Arc::new(AtomicUsize::new(0));
    for _ in 0..task_count {
        let counter = Some(progress.clone());
        spawn_cancellable_loop(&mut runtime, root, 32, counter);
    }
    harness.exit_phase();

    harness.enter_phase("run");
    runtime.run_until_quiescent();
    harness.exit_phase();

    harness.enter_phase("verify");
    let mut passed = true;
    let live = runtime.state.live_task_count();
    passed &= harness.assert_eq("no_live_tasks", &0usize, &live);
    let quiescent = runtime.is_quiescent();
    passed &= harness.assert_true("quiescent", quiescent);
    let stats = runtime.chaos_stats();
    passed &= harness.assert_true("chaos_decisions_made", stats.decision_points > 0);
    passed &= harness.assert_true("chaos_cancellations_injected", stats.cancellations > 0);
    let progress_count = progress.load(Ordering::SeqCst);
    passed &= harness.assert_true("some_progress_made", progress_count > 0);
    harness.exit_phase();

    if !passed {
        collect_replay_failure_artifacts(&mut harness, &mut runtime, "cancel_storm_chaos");
    }

    let summary = harness.finish();
    assert!(
        summary.passed,
        "cancel storm chaos failed: {}",
        serde_json::to_string_pretty(&summary).unwrap()
    );
}

#[test]
fn e2e_timeout_cascade_with_replay() {
    let seed = 0x51A7_F00Du64;
    let ctx = TestContext::new("timeout_cascade", seed)
        .with_subsystem("cancellation")
        .with_invariant("timeout_cascade");
    let mut harness = TestHarness::with_context("e2e_timeout_cascade_with_replay", ctx);
    init_test_logging();

    let config = LabConfig::new(seed)
        .with_default_replay_recording()
        .worker_count(2)
        .trace_capacity(16 * 1024);
    let mut runtime = LabRuntime::new(config);

    let budget = Budget::new().with_deadline(Time::from_millis(25));
    let root = runtime.state.create_root_region(budget);
    let child = runtime
        .state
        .create_child_region(root, budget)
        .expect("child region");
    let grandchild = runtime
        .state
        .create_child_region(child, budget)
        .expect("grandchild region");

    harness.enter_phase("spawn");
    let mut task_ids = Vec::new();
    for &region in &[root, child, grandchild] {
        for _ in 0..3 {
            task_ids.push(spawn_cancellable_loop(&mut runtime, region, 1024, None));
        }
    }
    harness.exit_phase();

    harness.enter_phase("warmup");
    for _ in 0..50 {
        runtime.step_for_test();
    }
    runtime.advance_time_to(Time::from_millis(30));
    harness.exit_phase();

    harness.enter_phase("cancel");
    let reason = CancelReason::timeout();
    let scheduled = cancel_region(&mut runtime, root, &reason);
    harness.assert_true("cancel_scheduled", scheduled > 0);
    runtime.run_until_quiescent();
    harness.exit_phase();

    harness.enter_phase("verify");
    let mut passed = true;
    let quiescent = runtime.is_quiescent();
    passed &= harness.assert_true("quiescent", quiescent);
    let live = runtime.state.live_task_count();
    passed &= harness.assert_eq("no_live_tasks", &0usize, &live);

    for region in [root, child, grandchild] {
        let record = runtime.state.region(region).expect("region record");
        let Some(reason) = record.cancel_reason() else {
            passed &= harness.assert_true("region_has_cancel_reason", false);
            continue;
        };
        passed &= harness.assert_eq(
            "cancel_root_kind_timeout",
            &CancelKind::Timeout,
            &reason.root_cause().kind,
        );
    }

    for task_id in task_ids {
        let cancelled = runtime.state.task(task_id).is_none_or(|task| {
            matches!(
                &task.state,
                TaskState::Completed(Outcome::Cancelled(reason))
                    if reason.root_cause().kind == CancelKind::Timeout
            )
        });
        passed &= harness.assert_true("task_cancelled_or_cleaned", cancelled);
    }
    harness.exit_phase();

    if !passed {
        collect_replay_failure_artifacts(&mut harness, &mut runtime, "timeout_cascade");
    }

    let summary = harness.finish();
    assert!(
        summary.passed,
        "timeout cascade failed: {}",
        serde_json::to_string_pretty(&summary).unwrap()
    );
}

#[test]
fn e2e_race_loser_cancellation_drain() {
    let seed = 0xFACE_FEED_u64;
    let ctx = TestContext::new("race_loser_drain", seed)
        .with_subsystem("cancellation")
        .with_invariant("loser_drain");
    let mut harness = TestHarness::with_context("e2e_race_loser_cancellation_drain", ctx);
    init_test_logging();

    let config = LabConfig::new(seed)
        .with_default_replay_recording()
        .worker_count(2)
        .trace_capacity(16 * 1024);
    let mut runtime = LabRuntime::new(config);

    let root = runtime.state.create_root_region(Budget::INFINITE);
    let winner_region = runtime
        .state
        .create_child_region(root, Budget::INFINITE)
        .expect("winner region");
    let loser_region_a = runtime
        .state
        .create_child_region(root, Budget::INFINITE)
        .expect("loser region a");
    let loser_region_b = runtime
        .state
        .create_child_region(root, Budget::INFINITE)
        .expect("loser region b");

    let winner_done = Arc::new(AtomicUsize::new(0));
    let winner_counter = winner_done.clone();

    harness.enter_phase("spawn");
    let (winner_task, _winner_handle) = runtime
        .state
        .create_task(winner_region, Budget::INFINITE, async move {
            winner_counter.fetch_add(1, Ordering::SeqCst);
            yield_now().await;
        })
        .expect("winner task");
    runtime.scheduler.lock().schedule(winner_task, 0);

    let loser_task_a = spawn_cancellable_loop(&mut runtime, loser_region_a, 4096, None);
    let loser_task_b = spawn_cancellable_loop(&mut runtime, loser_region_b, 4096, None);
    harness.exit_phase();

    harness.enter_phase("run_until_winner");
    let mut steps = 0u64;
    while winner_done.load(Ordering::SeqCst) == 0 && steps < 500 {
        runtime.step_for_test();
        steps += 1;
    }
    let winner_completed = winner_done.load(Ordering::SeqCst) > 0;
    harness.assert_true("winner_completed", winner_completed);
    harness.exit_phase();

    harness.enter_phase("cancel_losers");
    cancel_region(&mut runtime, loser_region_a, &CancelReason::race_loser());
    cancel_region(&mut runtime, loser_region_b, &CancelReason::race_loser());
    runtime.run_until_quiescent();
    harness.exit_phase();

    harness.enter_phase("verify");
    let mut passed = true;
    passed &= harness.assert_true("quiescent", runtime.is_quiescent());
    passed &= harness.assert_eq("no_live_tasks", &0usize, &runtime.state.live_task_count());

    for task_id in [loser_task_a, loser_task_b] {
        let cancelled = runtime.state.task(task_id).is_none_or(|task| {
            matches!(
                &task.state,
                TaskState::Completed(Outcome::Cancelled(reason))
                    if reason.root_cause().kind == CancelKind::RaceLost
            )
        });
        passed &= harness.assert_true("loser_cancelled_or_cleaned", cancelled);
    }
    harness.exit_phase();

    if !passed {
        collect_replay_failure_artifacts(&mut harness, &mut runtime, "race_loser_drain");
    }

    let summary = harness.finish();
    assert!(
        summary.passed,
        "race loser drain failed: {}",
        serde_json::to_string_pretty(&summary).unwrap()
    );
}

#[test]
fn e2e_finalizer_heavy_cancel_workload() {
    let seed = 0xF17E_BA5Eu64;
    let ctx = TestContext::new("finalizer_heavy_cancel", seed)
        .with_subsystem("cancellation")
        .with_invariant("finalizer");
    let mut harness = TestHarness::with_context("e2e_finalizer_heavy_cancel_workload", ctx);
    init_test_logging();

    let config = LabConfig::new(seed)
        .with_default_replay_recording()
        .worker_count(2)
        .trace_capacity(16 * 1024);
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let sync_count = 24usize;
    let async_count = 24usize;
    let sync_done = Arc::new(AtomicUsize::new(0));
    let async_done = Arc::new(AtomicUsize::new(0));

    harness.enter_phase("register_finalizers");
    for _ in 0..sync_count {
        let counter = sync_done.clone();
        let ok = runtime.state.register_sync_finalizer(region, move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        harness.assert_true("sync_finalizer_registered", ok);
    }
    for _ in 0..async_count {
        let counter = async_done.clone();
        let ok = runtime.state.register_async_finalizer(region, async move {
            counter.fetch_add(1, Ordering::SeqCst);
            yield_now().await;
        });
        harness.assert_true("async_finalizer_registered", ok);
    }
    harness.exit_phase();

    harness.enter_phase("cancel");
    cancel_region(&mut runtime, region, &CancelReason::shutdown());
    runtime.run_until_quiescent();
    harness.exit_phase();

    harness.enter_phase("verify");
    let mut passed = true;
    passed &= harness.assert_eq(
        "sync_finalizers_ran",
        &sync_count,
        &sync_done.load(Ordering::SeqCst),
    );
    passed &= harness.assert_eq(
        "async_finalizers_ran",
        &async_count,
        &async_done.load(Ordering::SeqCst),
    );
    let record = runtime.state.region(region).expect("region record");
    passed &= harness.assert_true("finalizers_empty", record.finalizers_empty());
    passed &= harness.assert_true("quiescent", runtime.is_quiescent());
    harness.exit_phase();

    if !passed {
        collect_replay_failure_artifacts(&mut harness, &mut runtime, "finalizer_heavy");
    }

    let summary = harness.finish();
    assert!(
        summary.passed,
        "finalizer heavy workload failed: {}",
        serde_json::to_string_pretty(&summary).unwrap()
    );
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

    for i in 0u64..50 {
        let c = completed.clone();
        let (task_id, _) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                c.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);

        // Interleave time advances
        if i % 10 == 0 {
            runtime.advance_time_to(Time::from_millis(i * 10));
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

    let order = Arc::new(Mutex::new(Vec::new()));

    // Task in region_a
    let o = order.clone();
    let (t1, _) = runtime
        .state
        .create_task(region_a, Budget::INFINITE, async move {
            o.lock().push("region_a");
        })
        .expect("task a");
    runtime.scheduler.lock().schedule(t1, 0);

    // Task in region_b
    let o = order.clone();
    let (t2, _) = runtime
        .state
        .create_task(region_b, Budget::INFINITE, async move {
            o.lock().push("region_b");
        })
        .expect("task b");
    runtime.scheduler.lock().schedule(t2, 0);

    // Task in region_c
    let o = order.clone();
    let (t3, _) = runtime
        .state
        .create_task(region_c, Budget::INFINITE, async move {
            o.lock().push("region_c");
        })
        .expect("task c");
    runtime.scheduler.lock().schedule(t3, 0);

    runtime.run_until_quiescent();

    let final_len = {
        let final_order = order.lock();
        final_order.len()
    };
    assert_with_log!(final_len == 3, "all tasks completed", 3, final_len);
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
        runtime.scheduler.lock().schedule(task_id, 0);
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
        runtime.scheduler.lock().schedule(task_id, 0);
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
            runtime.scheduler.lock().schedule(task_id, 0);
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
    runtime.scheduler.lock().schedule(task_id, 0);
    runtime.run_until_quiescent();

    let events = runtime.state.trace.snapshot();
    let event_count = events.len();
    assert_with_log!(event_count > 0, "trace captured events", "> 0", event_count);
    test_complete!("e2e_trace_captures_events");
}

// ============================================================================
// bd-21f9: Structured Concurrency — Nested Regions (TestHarness)
// ============================================================================

#[test]
fn e2e_nested_region_create_teardown() {
    let mut harness = TestHarness::new("e2e_nested_region_create_teardown");
    init_test_logging();

    harness.enter_phase("setup");
    let mut runtime = LabRuntime::new(LabConfig::default());
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let child = create_child_region(&mut runtime.state, root);
    let grandchild = create_child_region(&mut runtime.state, child);
    tracing::info!(root = ?root, child = ?child, grandchild = ?grandchild, "region tree created");
    harness.exit_phase();

    harness.enter_phase("spawn_tasks");
    let counter = Arc::new(AtomicUsize::new(0));
    // Spawn tasks at each level
    for (region, label) in [(root, "root"), (child, "child"), (grandchild, "grandchild")] {
        let c = counter.clone();
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                c.fetch_add(1, Ordering::SeqCst);
            })
            .unwrap_or_else(|e| panic!("create {label} task: {e}"));
        runtime.scheduler.lock().schedule(task_id, 0);
    }
    harness.exit_phase();

    harness.enter_phase("execute");
    runtime.run_until_quiescent();
    let count = counter.load(Ordering::SeqCst);
    tracing::info!(completed = count, "tasks completed");
    harness.assert_eq("all_levels_completed", &3usize, &count);
    harness.exit_phase();

    harness.enter_phase("verify");
    harness.assert_true("quiescent", runtime.is_quiescent());
    harness.assert_eq("no_live_tasks", &0usize, &runtime.state.live_task_count());
    harness.exit_phase();

    let summary = harness.finish();
    assert!(
        summary.passed,
        "test failed: {}",
        serde_json::to_string_pretty(&summary).unwrap()
    );
}

#[test]
fn e2e_cancellation_propagates_through_region_tree() {
    let mut harness = TestHarness::new("e2e_cancellation_propagates_through_region_tree");
    init_test_logging();

    harness.enter_phase("setup");
    let mut runtime = LabRuntime::new(LabConfig::default());
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let child_a = create_child_region(&mut runtime.state, root);
    let child_b = create_child_region(&mut runtime.state, root);
    let grandchild = create_child_region(&mut runtime.state, child_a);
    tracing::info!("4-node region tree created");
    harness.exit_phase();

    harness.enter_phase("spawn");
    let started = Arc::new(AtomicUsize::new(0));
    for region in [root, child_a, child_b, grandchild] {
        let s = started.clone();
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                s.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }
    harness.exit_phase();

    harness.enter_phase("run_and_cancel");
    runtime.run_until_quiescent();
    let ran = started.load(Ordering::SeqCst);
    tracing::info!(ran = ran, "tasks completed before cancel");

    // Cancel root — should propagate
    runtime
        .state
        .cancel_request(root, &CancelReason::user("tree cancel"), None);
    runtime.run_until_quiescent();
    harness.exit_phase();

    harness.enter_phase("verify");
    harness.assert_true("quiescent_after_cancel", runtime.is_quiescent());
    harness.assert_eq("no_live_tasks", &0usize, &runtime.state.live_task_count());
    harness.exit_phase();

    let summary = harness.finish();
    assert!(summary.passed);
}

#[test]
fn e2e_obligation_lifecycle() {
    let mut harness = TestHarness::new("e2e_obligation_lifecycle");
    init_test_logging();

    harness.enter_phase("setup");
    let mut runtime = LabRuntime::new(LabConfig::default());
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let (task_id, _) = runtime
        .state
        .create_task(root, Budget::INFINITE, async {})
        .expect("create task");
    runtime.scheduler.lock().schedule(task_id, 0);
    harness.exit_phase();

    harness.enter_phase("create_obligation");
    let obligation = runtime
        .state
        .create_obligation(
            ObligationKind::SendPermit,
            task_id,
            root,
            Some("test send permit".to_string()),
        )
        .expect("create obligation");
    tracing::info!(obligation = ?obligation, "obligation created");
    harness.exit_phase();

    harness.enter_phase("commit_obligation");
    let hold_ns = runtime.state.commit_obligation(obligation);
    harness.assert_true("commit_succeeded", hold_ns.is_ok());
    tracing::info!(hold_ns = ?hold_ns, "obligation committed");
    harness.exit_phase();

    harness.enter_phase("verify_double_commit_fails");
    let double = runtime.state.commit_obligation(obligation);
    harness.assert_true("double_commit_is_err", double.is_err());
    harness.exit_phase();

    let summary = harness.finish();
    assert!(summary.passed);
}

#[test]
fn e2e_obligation_abort_on_cancel() {
    let mut harness = TestHarness::new("e2e_obligation_abort_on_cancel");
    init_test_logging();

    harness.enter_phase("setup");
    let mut runtime = LabRuntime::new(LabConfig::default());
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let (task_id, _) = runtime
        .state
        .create_task(root, Budget::INFINITE, async {})
        .expect("create task");
    runtime.scheduler.lock().schedule(task_id, 0);
    harness.exit_phase();

    harness.enter_phase("create_and_abort");
    let obligation = runtime
        .state
        .create_obligation(ObligationKind::Lease, task_id, root, None)
        .expect("create obligation");

    let abort_result = runtime.state.abort_obligation(
        obligation,
        asupersync::record::ObligationAbortReason::Cancel,
    );
    harness.assert_true("abort_succeeded", abort_result.is_ok());
    harness.exit_phase();

    harness.enter_phase("verify");
    runtime.run_until_quiescent();
    harness.assert_true("quiescent", runtime.is_quiescent());
    harness.exit_phase();

    let summary = harness.finish();
    assert!(summary.passed);
}

// ============================================================================
// bd-105vq: Leak Regression E2E Suite + Logging
// ============================================================================

#[test]
#[allow(clippy::too_many_lines)]
fn e2e_leak_regression_obligations_and_heap_limits() {
    let _guard = ALLOC_TEST_GUARD.lock();
    init_test("e2e_leak_regression_obligations_and_heap_limits");

    test_section!("setup");
    let mut runtime = LabRuntime::new(LabConfig::new(0x00BA_5EED).worker_count(2));
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let heap_limit = std::mem::size_of::<u64>() * 2;
    let limits = RegionLimits {
        max_obligations: Some(3),
        max_heap_bytes: Some(heap_limit),
        ..RegionLimits::unlimited()
    };
    let limits_set = runtime.state.set_region_limits(root, limits);
    assert_with_log!(limits_set, "limits set", true, limits_set);

    let counter = Arc::new(AtomicUsize::new(0));
    let task_id = spawn_cancellable_loop(&mut runtime, root, 128, Some(counter.clone()));

    test_section!("heap_allocations");
    let baseline_allocs = global_alloc_count();
    tracing::info!(baseline_allocs, "baseline global alloc count");
    {
        let region = runtime
            .state
            .regions
            .get(root.arena_index())
            .expect("region missing");
        let idx1 = region.heap_alloc(10u64).expect("heap alloc 1");
        let idx2 = region.heap_alloc(20u64).expect("heap alloc 2");
        tracing::info!(idx1 = ?idx1, idx2 = ?idx2, "heap alloc indices");

        let stats = region.heap_stats();
        tracing::info!(stats = ?stats, "heap stats after allocs");

        let err = region.heap_alloc(30u64).expect_err("heap limit enforced");
        match err {
            AdmissionError::LimitReached {
                kind: AdmissionKind::HeapBytes,
                limit,
                live,
            } => {
                assert_with_log!(limit == heap_limit, "heap limit applied", heap_limit, limit);
                assert_with_log!(
                    live == heap_limit,
                    "heap live bytes tracked",
                    heap_limit,
                    live
                );
            }
            other => panic!("unexpected heap admission error: {other:?}"),
        }
    }

    test_section!("obligation_admission");
    let mut obligations = Vec::new();
    for (idx, kind) in [
        ObligationKind::SendPermit,
        ObligationKind::Lease,
        ObligationKind::Ack,
    ]
    .iter()
    .enumerate()
    {
        let ob = runtime
            .state
            .create_obligation(*kind, task_id, root, Some(format!("leak regression {idx}")))
            .expect("create obligation");
        obligations.push(ob);
        tracing::info!(obligation = ?ob, kind = ?kind, "obligation created");
    }
    let denied = runtime.state.create_obligation(
        ObligationKind::IoOp,
        task_id,
        root,
        Some("limit".to_string()),
    );
    let denied = matches!(denied, Err(ref err) if err.kind() == ErrorKind::AdmissionDenied);
    assert_with_log!(denied, "obligation admission denied", true, denied);

    let pending = runtime.state.pending_obligation_count();
    assert_with_log!(
        pending == obligations.len(),
        "pending obligations tracked",
        obligations.len(),
        pending
    );

    test_section!("cancel_and_abort");
    let scheduled = cancel_region(&mut runtime, root, &CancelReason::user("leak regression"));
    tracing::info!(scheduled, "cancel scheduled");
    for ob in obligations {
        let result = runtime
            .state
            .abort_obligation(ob, ObligationAbortReason::Cancel);
        assert_with_log!(result.is_ok(), "abort obligation", true, result.is_ok());
    }
    runtime.run_until_quiescent();

    test_section!("verify");
    let ran = counter.load(Ordering::SeqCst);
    tracing::info!(ran, "cancellable loop iterations");
    let pending_after = runtime.state.pending_obligation_count();
    assert_with_log!(
        pending_after == 0,
        "pending obligations drained",
        0,
        pending_after
    );
    let live_tasks = runtime.state.live_task_count();
    assert_with_log!(live_tasks == 0, "no live tasks", 0, live_tasks);

    if let Some(region) = runtime.state.region(root) {
        let stats = region.heap_stats();
        tracing::info!(stats = ?stats, "heap stats after close");
        assert_with_log!(stats.live == 0, "heap live reclaimed", 0u64, stats.live);
        assert_with_log!(
            stats.bytes_live == 0,
            "heap bytes reclaimed",
            0u64,
            stats.bytes_live
        );
    }

    let after_allocs = global_alloc_count();
    tracing::info!(
        baseline_allocs,
        after_allocs,
        "global alloc count after close"
    );

    test_complete!(
        "e2e_leak_regression_obligations_and_heap_limits",
        obligations = 3,
        heap_limit = heap_limit,
        iterations = ran
    );
}

#[test]
fn e2e_budget_poll_quota_enforcement() {
    let mut harness = TestHarness::new("e2e_budget_poll_quota_enforcement");
    init_test_logging();

    harness.enter_phase("setup");
    let mut runtime = LabRuntime::new(LabConfig::default());
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let tight_budget = Budget::new().with_poll_quota(5);
    harness.exit_phase();

    harness.enter_phase("spawn_with_budget");
    let polls = Arc::new(AtomicUsize::new(0));
    let p = polls.clone();
    let (task_id, _) = runtime
        .state
        .create_task(root, tight_budget, async move {
            p.fetch_add(1, Ordering::SeqCst);
        })
        .expect("create task");
    runtime.scheduler.lock().schedule(task_id, 0);
    harness.exit_phase();

    harness.enter_phase("execute");
    runtime.run_until_quiescent();
    let poll_count = polls.load(Ordering::SeqCst);
    tracing::info!(poll_count = poll_count, "task completed");
    // Task should complete (it's a simple future that completes in 1 poll)
    harness.assert_eq("task_completed", &1usize, &poll_count);
    harness.exit_phase();

    let summary = harness.finish();
    assert!(summary.passed);
}

#[test]
fn e2e_complex_workload_quiescence() {
    let mut harness = TestHarness::new("e2e_complex_workload_quiescence");
    init_test_logging();

    harness.enter_phase("setup");
    let mut runtime = LabRuntime::new(LabConfig::new(7777).worker_count(4));
    harness.exit_phase();

    harness.enter_phase("spawn_complex_tree");
    let total = Arc::new(AtomicUsize::new(0));
    let expected_tasks = 60;

    // Create 3 root regions, each with 2 children, each with 10 tasks
    for _ in 0..3 {
        let root = runtime.state.create_root_region(Budget::INFINITE);
        for _ in 0..2 {
            let child = create_child_region(&mut runtime.state, root);
            for _ in 0..10 {
                let t = total.clone();
                let (task_id, _) = runtime
                    .state
                    .create_task(child, Budget::INFINITE, async move {
                        t.fetch_add(1, Ordering::SeqCst);
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }
        }
    }
    tracing::info!(expected = expected_tasks, "spawned complex workload");
    harness.exit_phase();

    harness.enter_phase("execute");
    runtime.run_until_quiescent();
    let completed = total.load(Ordering::SeqCst);
    tracing::info!(completed = completed, "workload completed");
    harness.assert_eq("all_tasks_completed", &expected_tasks, &completed);
    harness.exit_phase();

    harness.enter_phase("verify");
    harness.assert_true("quiescent", runtime.is_quiescent());
    harness.assert_eq("no_live_tasks", &0usize, &runtime.state.live_task_count());
    harness.exit_phase();

    let summary = harness.finish();
    assert!(summary.passed);
}

#[test]
fn e2e_deterministic_nested_regions() {
    let mut harness = TestHarness::new("e2e_deterministic_nested_regions");
    init_test_logging();

    harness.enter_phase("determinism_check");
    let config = LabConfig::new(1234).worker_count(2);

    asupersync::lab::assert_deterministic(config, |runtime| {
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let child = create_child_region(&mut runtime.state, root);

        let counter = Arc::new(AtomicUsize::new(0));

        for _ in 0..10 {
            let c = counter.clone();
            let (task_id, _) = runtime
                .state
                .create_task(child, Budget::INFINITE, async move {
                    c.fetch_add(1, Ordering::SeqCst);
                })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        runtime.run_until_quiescent();
    });
    harness.assert_true("determinism_verified", true);
    harness.exit_phase();

    let summary = harness.finish();
    assert!(summary.passed);
}

#[test]
fn e2e_report_aggregation() {
    init_test("e2e_report_aggregation");

    let mut agg = asupersync::test_logging::TestReportAggregator::new();

    // Run a mini sub-test
    let mut h1 = TestHarness::new("sub_region_test");
    h1.enter_phase("setup");
    let mut runtime = LabRuntime::new(LabConfig::default());
    let root = runtime.state.create_root_region(Budget::INFINITE);
    h1.assert_true("root_created", root.arena_index().index() < u32::MAX);
    h1.exit_phase();
    agg.add(h1.finish());

    // Another sub-test
    let mut h2 = TestHarness::new("sub_cancel_test");
    h2.enter_phase("cancel");
    h2.assert_true("ok", true);
    h2.exit_phase();
    agg.add(h2.finish());

    let report = agg.report();
    assert_eq!(report.total_tests, 2);
    assert_eq!(report.passed_tests, 2);
    assert_eq!(report.coverage_matrix.len(), 2);

    tracing::info!(
        json = %agg.report_json(),
        "aggregated coverage report"
    );
    test_complete!("e2e_report_aggregation");
}

// ============================================================================
// bd-2l6g: Cancellation Protocol Stress Tests
// ============================================================================

/// Stress: cancel during region with pending obligations (commit-or-abort).
#[test]
fn e2e_cancel_with_pending_obligations() {
    init_test("e2e_cancel_with_pending_obligations");

    test_section!("setup");
    let mut runtime = LabRuntime::new(LabConfig::new(0xCAFE).worker_count(2));
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let (task_id, _) = runtime
        .state
        .create_task(root, Budget::INFINITE, async {})
        .expect("create task");
    runtime.scheduler.lock().schedule(task_id, 0);

    test_section!("create_obligations");
    let mut obligations = Vec::new();
    for kind in [
        ObligationKind::SendPermit,
        ObligationKind::Lease,
        ObligationKind::Ack,
    ] {
        let ob = runtime
            .state
            .create_obligation(kind, task_id, root, Some(format!("stress {kind:?}")))
            .expect("create obligation");
        obligations.push(ob);
        tracing::info!(obligation = ?ob, kind = ?kind, "obligation created");
    }
    let pending = runtime.state.pending_obligation_count();
    assert_with_log!(pending >= 3, "obligations pending", ">= 3", pending);

    test_section!("cancel_with_obligations_live");
    runtime
        .state
        .cancel_request(root, &CancelReason::user("cancel with obligations"), None);

    test_section!("abort_obligations");
    for ob in &obligations {
        let _ = runtime
            .state
            .abort_obligation(*ob, asupersync::record::ObligationAbortReason::Cancel);
    }

    test_section!("drain");
    runtime.run_until_quiescent();

    test_section!("verify");
    let quiescent = runtime.is_quiescent();
    assert_with_log!(quiescent, "quiescent", true, quiescent);
    let live = runtime.state.live_task_count();
    assert_with_log!(live == 0, "no live tasks", 0, live);
    test_complete!("e2e_cancel_with_pending_obligations");
}

/// Stress: deep cancel propagation through 10-level region tree.
#[test]
fn e2e_deep_cancel_propagation() {
    init_test("e2e_deep_cancel_propagation");

    test_section!("build_deep_tree");
    let mut runtime = LabRuntime::new(LabConfig::new(0xDEE9));
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let depth = 10;
    let mut regions = vec![root];
    let mut current = root;
    for level in 1..depth {
        let child = create_child_region(&mut runtime.state, current);
        regions.push(child);
        current = child;
        tracing::info!(level = level, region = ?child, "created level");
    }

    test_section!("spawn_tasks_at_every_level");
    let counter = Arc::new(AtomicUsize::new(0));
    for &region in &regions {
        let c = counter.clone();
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                c.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    test_section!("run_tasks");
    runtime.run_until_quiescent();
    let ran = counter.load(Ordering::SeqCst);
    tracing::info!(ran = ran, depth = depth, "tasks completed before cancel");
    assert_with_log!(ran == depth, "all levels ran", depth, ran);

    test_section!("cancel_root_propagates");
    runtime
        .state
        .cancel_request(root, &CancelReason::shutdown(), None);
    runtime.run_until_quiescent();

    test_section!("verify");
    let quiescent = runtime.is_quiescent();
    assert_with_log!(quiescent, "quiescent after deep cancel", true, quiescent);
    let live = runtime.state.live_task_count();
    assert_with_log!(live == 0, "no live tasks after deep cancel", 0, live);
    test_complete!(
        "e2e_deep_cancel_propagation",
        depth = depth,
        tasks_ran = ran
    );
}

/// Stress: concurrent cancellations from multiple cancel reasons.
#[test]
fn e2e_concurrent_cancel_reasons() {
    init_test("e2e_concurrent_cancel_reasons");

    test_section!("setup");
    let mut runtime = LabRuntime::new(LabConfig::new(0xCC).worker_count(4));
    let n_regions = 30;
    let completed = Arc::new(AtomicUsize::new(0));

    let reasons = [
        CancelReason::user("user cancel"),
        CancelReason::timeout(),
        CancelReason::deadline(),
        CancelReason::shutdown(),
        CancelReason::poll_quota(),
        CancelReason::race_lost(),
    ];

    test_section!("spawn_regions_and_tasks");
    let mut region_ids = Vec::new();
    for _ in 0..n_regions {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        region_ids.push(region);

        for _ in 0..3 {
            let c = completed.clone();
            let (task_id, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    c.fetch_add(1, Ordering::SeqCst);
                })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }
    }
    tracing::info!(
        regions = n_regions,
        tasks = n_regions * 3,
        "spawned workload"
    );

    test_section!("fire_cancellations");
    for (i, region) in region_ids.iter().enumerate() {
        let reason = &reasons[i % reasons.len()];
        runtime.state.cancel_request(*region, reason, None);
        tracing::info!(
            region = ?region,
            kind = ?reason.kind,
            "cancel request fired"
        );
    }

    test_section!("drain");
    runtime.run_until_quiescent();

    test_section!("verify");
    let quiescent = runtime.is_quiescent();
    assert_with_log!(
        quiescent,
        "quiescent after concurrent cancels",
        true,
        quiescent
    );
    let live = runtime.state.live_task_count();
    assert_with_log!(live == 0, "no live tasks", 0, live);
    test_complete!("e2e_concurrent_cancel_reasons", regions = n_regions);
}

/// Stress: cancel with timers — interleave time advances with cancellation.
#[test]
fn e2e_cancel_with_timer_interleave() {
    init_test("e2e_cancel_with_timer_interleave");

    test_section!("setup");
    let mut runtime = LabRuntime::new(LabConfig::new(0xD1_E0).worker_count(2));
    let completed = Arc::new(AtomicUsize::new(0));
    let cancelled_count = Arc::new(AtomicUsize::new(0));

    test_section!("spawn_timed_regions");
    let n_waves = 5u64;
    let tasks_per_wave = 10;

    for wave in 0..n_waves {
        let root = runtime.state.create_root_region(Budget::INFINITE);

        for _ in 0..tasks_per_wave {
            let c = completed.clone();
            let (task_id, _) = runtime
                .state
                .create_task(root, Budget::INFINITE, async move {
                    c.fetch_add(1, Ordering::SeqCst);
                })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        // Advance time between waves
        runtime.advance_time_to(Time::from_millis((wave + 1) * 100));

        // Cancel every other wave before it runs
        if wave % 2 == 0 {
            runtime
                .state
                .cancel_request(root, &CancelReason::timeout(), None);
            cancelled_count.fetch_add(1, Ordering::SeqCst);
            tracing::info!(wave = wave, "cancelled wave");
        }

        // Let some tasks run between waves
        for _ in 0..5 {
            runtime.step_for_test();
        }
    }

    test_section!("drain");
    runtime.run_until_quiescent();

    test_section!("verify");
    let total = completed.load(Ordering::SeqCst);
    let cancels = cancelled_count.load(Ordering::SeqCst);
    tracing::info!(
        completed = total,
        cancels = cancels,
        "timer interleave done"
    );
    let quiescent = runtime.is_quiescent();
    assert_with_log!(quiescent, "quiescent", true, quiescent);
    let live = runtime.state.live_task_count();
    assert_with_log!(live == 0, "no live tasks", 0, live);
    test_complete!(
        "e2e_cancel_with_timer_interleave",
        completed = total,
        cancels = cancels
    );
}

/// Stress: loser drain after races — cancel the losing region after a "winner" completes.
#[test]
fn e2e_race_loser_drain() {
    init_test("e2e_race_loser_drain");

    test_section!("setup");
    let mut runtime = LabRuntime::new(LabConfig::new(0xEACE).worker_count(4));
    let winner_completed = Arc::new(AtomicUsize::new(0));
    let n_races = 10;

    test_section!("run_races");
    for race_idx in 0..n_races {
        let region_a = runtime.state.create_root_region(Budget::INFINITE);
        let region_b = runtime.state.create_root_region(Budget::INFINITE);

        // Spawn "racer" tasks in both regions
        let w = winner_completed.clone();
        let (ta, _) = runtime
            .state
            .create_task(region_a, Budget::INFINITE, async move {
                w.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create task a");
        runtime.scheduler.lock().schedule(ta, 0);

        let (tb, _) = runtime
            .state
            .create_task(region_b, Budget::INFINITE, async move {
                // "loser" work
            })
            .expect("create task b");
        runtime.scheduler.lock().schedule(tb, 0);

        // Run a few steps so "winner" likely completes
        for _ in 0..3 {
            runtime.step_for_test();
        }

        // Cancel the loser region
        runtime
            .state
            .cancel_request(region_b, &CancelReason::race_lost(), None);

        tracing::info!(race = race_idx, "race loser cancelled");
    }

    test_section!("drain");
    runtime.run_until_quiescent();

    test_section!("verify");
    let winners = winner_completed.load(Ordering::SeqCst);
    tracing::info!(winners = winners, total_races = n_races, "races completed");
    let quiescent = runtime.is_quiescent();
    assert_with_log!(quiescent, "quiescent after races", true, quiescent);
    let live = runtime.state.live_task_count();
    assert_with_log!(live == 0, "no live tasks", 0, live);
    test_complete!("e2e_race_loser_drain", winners = winners, races = n_races);
}

/// Stress: cancel during obligation commit — create obligation, cancel region, then try commit.
#[test]
fn e2e_cancel_interrupts_obligation_commit() {
    init_test("e2e_cancel_interrupts_obligation_commit");

    test_section!("setup");
    let mut runtime = LabRuntime::new(LabConfig::new(0x0B16));
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let (task_id, _) = runtime
        .state
        .create_task(root, Budget::INFINITE, async {})
        .expect("create task");
    runtime.scheduler.lock().schedule(task_id, 0);

    test_section!("create_obligations_then_cancel");
    let ob1 = runtime
        .state
        .create_obligation(ObligationKind::SendPermit, task_id, root, None)
        .expect("create ob1");
    let ob2 = runtime
        .state
        .create_obligation(ObligationKind::Lease, task_id, root, None)
        .expect("create ob2");
    let ob3 = runtime
        .state
        .create_obligation(ObligationKind::Ack, task_id, root, None)
        .expect("create ob3");
    tracing::info!(ob1 = ?ob1, ob2 = ?ob2, ob3 = ?ob3, "obligations created");

    // Cancel region while obligations are still pending
    runtime
        .state
        .cancel_request(root, &CancelReason::user("mid-obligation cancel"), None);
    tracing::info!("cancel fired with 3 pending obligations");

    test_section!("mixed_commit_abort");
    // Commit one — may or may not succeed depending on cancel state
    let commit_result = runtime.state.commit_obligation(ob1);
    tracing::info!(commit_result = ?commit_result, "ob1 commit after cancel");

    // Abort the rest
    let _ = runtime
        .state
        .abort_obligation(ob2, asupersync::record::ObligationAbortReason::Cancel);
    let _ = runtime
        .state
        .abort_obligation(ob3, asupersync::record::ObligationAbortReason::Cancel);
    // Also abort ob1 if commit failed
    if commit_result.is_err() {
        let _ = runtime
            .state
            .abort_obligation(ob1, asupersync::record::ObligationAbortReason::Cancel);
    }

    test_section!("drain");
    runtime.run_until_quiescent();

    test_section!("verify");
    let quiescent = runtime.is_quiescent();
    assert_with_log!(quiescent, "quiescent", true, quiescent);
    test_complete!("e2e_cancel_interrupts_obligation_commit");
}

/// Stress: deterministic cancellation storm — verify identical results across replays.
#[test]
fn e2e_deterministic_cancel_storm() {
    init_test("e2e_deterministic_cancel_storm");

    test_section!("determinism_check");
    let config = LabConfig::new(0x5DEB).worker_count(4);

    asupersync::lab::assert_deterministic(config, |runtime| {
        let n_regions = 15;
        let counter = Arc::new(AtomicUsize::new(0));

        for i in 0..n_regions {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            let child = create_child_region(&mut runtime.state, root);

            for _ in 0..4 {
                let c = counter.clone();
                let (task_id, _) = runtime
                    .state
                    .create_task(child, Budget::INFINITE, async move {
                        c.fetch_add(1, Ordering::SeqCst);
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            // Cancel every 3rd region
            if i % 3 == 0 {
                runtime
                    .state
                    .cancel_request(root, &CancelReason::user("storm"), None);
            }
        }

        runtime.run_until_quiescent();
    });

    test_complete!("e2e_deterministic_cancel_storm");
}

// ============================================================================
// Obligation lifecycle E2E (bd-275by)
// ============================================================================

#[test]
fn e2e_obligation_tracked_channel_commit() {
    let seed = 0xC0FF_EE17u64;
    let ctx = TestContext::new("obligation_tracked_channel_commit", seed)
        .with_subsystem("obligation")
        .with_invariant("two_phase_commit")
        .with_invariant("quiescence");
    let mut harness = TestHarness::with_context("e2e_obligation_tracked_channel_commit", ctx);
    init_test_logging();

    let config = LabConfig::new(seed)
        .with_default_replay_recording()
        .trace_capacity(8 * 1024)
        .max_steps(10_000);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let (tx, mut rx) = tracked_channel::<u32>(1);
    let recv_value = Arc::new(Mutex::new(None));
    let recv_value_clone = recv_value.clone();
    let proof_kind = Arc::new(Mutex::new(None));
    let proof_kind_clone = proof_kind.clone();

    harness.enter_phase("spawn");
    let (send_task, _handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().expect("cx");
            let permit = tx.reserve(&cx).await.expect("reserve");
            let proof = permit.send(7);
            *proof_kind_clone.lock() = Some(proof.kind());
        })
        .expect("create send task");
    runtime.scheduler.lock().schedule(send_task, 0);

    let (recv_task, _handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().expect("cx");
            let value = rx.recv(&cx).await.expect("recv");
            *recv_value_clone.lock() = Some(value);
        })
        .expect("create recv task");
    runtime.scheduler.lock().schedule(recv_task, 0);
    harness.exit_phase();

    harness.enter_phase("run");
    runtime.run_until_quiescent();
    harness.exit_phase();

    harness.enter_phase("verify");
    let mut passed = true;
    let value = *recv_value.lock();
    passed &= harness.assert_eq("recv_value", &Some(7u32), &value);
    let kind = *proof_kind.lock();
    passed &= harness.assert_eq("proof_kind", &Some(ObligationKind::SendPermit), &kind);
    passed &= harness.assert_true("quiescent", runtime.is_quiescent());
    let pending = runtime.state.pending_obligation_count();
    passed &= harness.assert_eq("pending_obligations", &0usize, &pending);
    harness.exit_phase();

    if !passed {
        collect_replay_failure_artifacts(
            &mut harness,
            &mut runtime,
            "obligation_tracked_channel_commit",
        );
    }

    let summary = harness.finish();
    assert!(
        summary.passed,
        "tracked channel commit failed: {}",
        serde_json::to_string_pretty(&summary).unwrap()
    );
}

#[test]
fn e2e_obligation_tracked_oneshot_abort() {
    let seed = 0xAB0F_700Du64;
    let ctx = TestContext::new("obligation_tracked_oneshot_abort", seed)
        .with_subsystem("obligation")
        .with_invariant("two_phase_abort")
        .with_invariant("quiescence");
    let mut harness = TestHarness::with_context("e2e_obligation_tracked_oneshot_abort", ctx);
    init_test_logging();

    let config = LabConfig::new(seed)
        .with_default_replay_recording()
        .trace_capacity(8 * 1024)
        .max_steps(10_000);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let (tx, rx) = tracked_oneshot::<u32>();
    let recv_closed = Arc::new(Mutex::new(None));
    let recv_closed_clone = recv_closed.clone();
    let proof_kind = Arc::new(Mutex::new(None));
    let proof_kind_clone = proof_kind.clone();

    harness.enter_phase("spawn");
    let (send_task, _handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().expect("cx");
            let permit = tx.reserve(&cx);
            let proof = permit.abort();
            *proof_kind_clone.lock() = Some(proof.kind());
        })
        .expect("create oneshot abort task");
    runtime.scheduler.lock().schedule(send_task, 0);

    let (recv_task, _handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().expect("cx");
            let result = rx.recv(&cx).await;
            let closed = matches!(result, Err(asupersync::channel::oneshot::RecvError::Closed));
            *recv_closed_clone.lock() = Some(closed);
        })
        .expect("create oneshot recv task");
    runtime.scheduler.lock().schedule(recv_task, 0);
    harness.exit_phase();

    harness.enter_phase("run");
    runtime.run_until_quiescent();
    harness.exit_phase();

    harness.enter_phase("verify");
    let mut passed = true;
    let closed = *recv_closed.lock();
    passed &= harness.assert_eq("recv_closed", &Some(true), &closed);
    let kind = *proof_kind.lock();
    passed &= harness.assert_eq("proof_kind", &Some(ObligationKind::SendPermit), &kind);
    passed &= harness.assert_true("quiescent", runtime.is_quiescent());
    let pending = runtime.state.pending_obligation_count();
    passed &= harness.assert_eq("pending_obligations", &0usize, &pending);
    harness.exit_phase();

    if !passed {
        collect_replay_failure_artifacts(
            &mut harness,
            &mut runtime,
            "obligation_tracked_oneshot_abort",
        );
    }

    let summary = harness.finish();
    assert!(
        summary.passed,
        "tracked oneshot abort failed: {}",
        serde_json::to_string_pretty(&summary).unwrap()
    );
}

#[test]
fn e2e_obligation_cancel_mid_reserve() {
    let seed = 0xCA11_BA5Eu64;
    let ctx = TestContext::new("obligation_cancel_mid_reserve", seed)
        .with_subsystem("obligation")
        .with_invariant("cancel_reserve");
    let mut harness = TestHarness::with_context("e2e_obligation_cancel_mid_reserve", ctx);
    init_test_logging();

    let config = LabConfig::new(seed)
        .with_default_replay_recording()
        .trace_capacity(8 * 1024)
        .max_steps(10_000);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let (tx, _rx) = tracked_channel::<u32>(1);
    let proof = tx.try_reserve().expect("reserve slot").send(1);
    assert_eq!(proof.kind(), ObligationKind::SendPermit);

    let reserve_result = Arc::new(Mutex::new(None));
    let reserve_result_clone = reserve_result.clone();

    harness.enter_phase("spawn");
    let (reserve_task, _handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().expect("cx");
            let result = tx.reserve(&cx).await.map(|_permit| ());
            *reserve_result_clone.lock() = Some(result);
        })
        .expect("create reserve task");
    runtime.scheduler.lock().schedule(reserve_task, 0);
    harness.exit_phase();

    harness.enter_phase("block_then_cancel");
    for _ in 0..3 {
        runtime.step_for_test();
    }
    let reason = CancelReason::user("mid-reserve cancel");
    let scheduled = cancel_region(&mut runtime, root, &reason);
    harness.assert_true("cancel_scheduled", scheduled > 0);
    harness.exit_phase();

    harness.enter_phase("run");
    runtime.run_until_quiescent();
    harness.exit_phase();

    harness.enter_phase("verify");
    let mut passed = true;
    let result = *reserve_result.lock();
    let cancelled = matches!(result, Some(Err(mpsc::SendError::Cancelled(()))));
    passed &= harness.assert_true("reserve_cancelled", cancelled);
    passed &= harness.assert_true("quiescent", runtime.is_quiescent());
    let pending = runtime.state.pending_obligation_count();
    passed &= harness.assert_eq("pending_obligations", &0usize, &pending);
    harness.exit_phase();

    if !passed {
        collect_replay_failure_artifacts(
            &mut harness,
            &mut runtime,
            "obligation_cancel_mid_reserve",
        );
    }

    let summary = harness.finish();
    assert!(
        summary.passed,
        "cancel mid-reserve failed: {}",
        serde_json::to_string_pretty(&summary).unwrap()
    );
}

#[test]
fn e2e_obligation_token_leak_detection() {
    let seed = 0x1EA5E_u64;
    let ctx = TestContext::new("obligation_token_leak_detection", seed)
        .with_subsystem("obligation")
        .with_invariant("graded_scope_leak");
    let mut harness = TestHarness::with_context("e2e_obligation_token_leak_detection", ctx);
    init_test_logging();

    let config = LabConfig::new(seed)
        .with_default_replay_recording()
        .trace_capacity(8 * 1024)
        .max_steps(10_000);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let leak_detected = Arc::new(Mutex::new(None));
    let leak_detected_clone = leak_detected.clone();

    harness.enter_phase("spawn");
    let (leak_task, _handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            let mut scope = GradedScope::open("graded_scope_leak");
            let token = scope.reserve_token::<SendPermit>("leaky_send_permit");
            let _raw = token.into_raw();
            let leaked = scope.close().is_err();
            *leak_detected_clone.lock() = Some(leaked);
        })
        .expect("create leak task");
    runtime.scheduler.lock().schedule(leak_task, 0);
    harness.exit_phase();

    harness.enter_phase("run");
    runtime.run_until_quiescent();
    harness.exit_phase();

    harness.enter_phase("verify");
    let mut passed = true;
    let leaked = *leak_detected.lock();
    passed &= harness.assert_eq("leak_detected", &Some(true), &leaked);
    passed &= harness.assert_true("quiescent", runtime.is_quiescent());
    harness.exit_phase();

    if !passed {
        collect_replay_failure_artifacts(
            &mut harness,
            &mut runtime,
            "obligation_token_leak_detection",
        );
    }

    let summary = harness.finish();
    assert!(
        summary.passed,
        "obligation token leak detection failed: {}",
        serde_json::to_string_pretty(&summary).unwrap()
    );
}
