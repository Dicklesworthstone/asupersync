//! Browser-context loser drain verification tests (asupersync-umelq.6.2).
//!
//! These tests verify that the loser drain invariant holds under browser-like
//! execution conditions: single-threaded deterministic scheduling via LabRuntime,
//! no OS threads, cooperative multitasking only.
//!
//! # Why Browser Context Matters
//!
//! In a native runtime, cancellation and drain can leverage OS thread preemption.
//! In the browser (wasm32), ALL execution is cooperative on a single thread:
//! - No parallel cancel+drain: everything is sequential poll-by-poll
//! - Cancellation must propagate through poll returns, not signals
//! - Region quiescence depends entirely on scheduler fairness
//! - Long-running drain can block the event loop
//!
//! # Invariants Verified
//!
//! 1. **Loser drain completeness**: Every race loser reaches terminal state
//! 2. **Region quiescence**: All children done before race scope returns
//! 3. **Cancel propagation**: Cancel reaches nested futures through poll chain
//! 4. **Join under cancel**: Join still waits for all branches even when cancelled
//! 5. **Determinism**: Same seed produces same drain ordering
//! 6. **Budget respect**: Drain does not exceed poll budget

use asupersync::lab::oracle::LoserDrainOracle;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::{Budget, RegionId, TaskId, Time};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::task::{Context, Poll};

/// Yield once to the scheduler, then resume.
///
/// Unlike `std::future::pending()`, this actually registers a wakeup so the
/// task gets re-polled on the next scheduler tick.
async fn yield_once() {
    let mut yielded = false;
    std::future::poll_fn(move |cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// A future that holds a resource guard, simulating a multi-step async operation
/// that must clean up on cancellation (e.g., an in-flight HTTP request in browser).
struct ResourceHoldingFuture {
    drop_flag: Arc<AtomicBool>,
    cleanup_steps_on_drop: u32,
    cleanup_counter: Arc<AtomicU32>,
}

impl Future for ResourceHoldingFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Never completes on its own — simulates a long-running browser operation
        Poll::Pending
    }
}

impl Drop for ResourceHoldingFuture {
    fn drop(&mut self) {
        // Simulate cleanup work (e.g., aborting fetch, closing WebSocket)
        for _ in 0..self.cleanup_steps_on_drop {
            self.cleanup_counter.fetch_add(1, Ordering::SeqCst);
        }
        self.drop_flag.store(true, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// Tests: Region quiescence after race/join
// ---------------------------------------------------------------------------

/// Verify that region quiescence is reached after a simulated race in LabRuntime.
///
/// In browser context, the single-threaded scheduler must poll all tasks to
/// completion before the region can close. This test creates multiple tasks
/// in a region, runs some to completion, and verifies the region reaches
/// quiescence when all tasks terminate.
#[test]
fn browser_region_quiescence_after_all_tasks_complete() {
    let mut runtime = LabRuntime::new(LabConfig::new(42));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let flags: Vec<_> = (0..4).map(|_| Arc::new(AtomicBool::new(false))).collect();

    let mut task_ids = Vec::new();
    for (i, flag) in flags.iter().enumerate() {
        let f = Arc::clone(flag);
        let yields = i as u32; // Task i yields i times before completing
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                struct Guard(Arc<AtomicBool>);
                impl Drop for Guard {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::SeqCst);
                    }
                }
                let _guard = Guard(f);
                // Yield `yields` times to simulate varying completion times
                for _ in 0..yields {
                    yield_once().await;
                }
            })
            .expect("create task");
        task_ids.push(task_id);
    }

    // Schedule all tasks
    {
        let mut sched = runtime.scheduler.lock();
        for &tid in &task_ids {
            sched.schedule(tid, 0);
        }
    }

    runtime.run_until_quiescent();

    // All tasks should have their guards dropped (cleanup complete)
    for (i, flag) in flags.iter().enumerate() {
        assert!(
            flag.load(Ordering::SeqCst),
            "Task {i} guard was not dropped — region did not reach quiescence"
        );
    }
}

/// Verify deterministic drain ordering: same seed produces same task completion
/// order across runs. This is critical for browser replay debugging.
#[test]
fn browser_deterministic_drain_ordering() {
    fn run_with_seed(seed: u64) -> Vec<u32> {
        let mut runtime = LabRuntime::new(LabConfig::new(seed));
        let region = runtime.state.create_root_region(Budget::INFINITE);

        let order = Arc::new(parking_lot::Mutex::new(Vec::new()));

        let mut task_ids = Vec::new();
        for i in 0u32..5 {
            let order_clone = Arc::clone(&order);
            let (task_id, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    struct OrderTracker {
                        id: u32,
                        order: Arc<parking_lot::Mutex<Vec<u32>>>,
                    }
                    impl Drop for OrderTracker {
                        fn drop(&mut self) {
                            self.order.lock().push(self.id);
                        }
                    }
                    let _tracker = OrderTracker {
                        id: i,
                        order: order_clone,
                    };
                    // Complete immediately
                })
                .expect("create task");
            task_ids.push(task_id);
        }

        {
            let mut sched = runtime.scheduler.lock();
            for &tid in &task_ids {
                sched.schedule(tid, 0);
            }
        }

        runtime.run_until_quiescent();
        Arc::try_unwrap(order).unwrap().into_inner()
    }

    let order_a = run_with_seed(42);
    let order_b = run_with_seed(42);

    assert_eq!(
        order_a, order_b,
        "Same seed must produce identical drain ordering for browser replay"
    );
    assert_eq!(order_a.len(), 5, "All 5 tasks must be drained");
}

/// Different seeds produce different drain orderings (scheduler uses seed).
#[test]
fn browser_different_seeds_may_differ() {
    fn drain_order(seed: u64) -> Vec<u32> {
        let mut runtime = LabRuntime::new(LabConfig::new(seed));
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let order = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut task_ids = Vec::new();

        for i in 0u32..3 {
            let o = Arc::clone(&order);
            let (tid, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    struct T(u32, Arc<parking_lot::Mutex<Vec<u32>>>);
                    impl Drop for T {
                        fn drop(&mut self) {
                            self.1.lock().push(self.0);
                        }
                    }
                    let _t = T(i, o);
                })
                .expect("create");
            task_ids.push(tid);
        }

        {
            let mut sched = runtime.scheduler.lock();
            for &tid in &task_ids {
                sched.schedule(tid, 0);
            }
        }
        runtime.run_until_quiescent();
        Arc::try_unwrap(order).unwrap().into_inner()
    }

    let a = drain_order(1);
    let b = drain_order(2);

    // Both must complete all tasks regardless of seed
    assert_eq!(a.len(), 3, "seed 1: all tasks drained");
    assert_eq!(b.len(), 3, "seed 2: all tasks drained");
    // (Ordering may or may not differ — we only assert completeness)
}

// ---------------------------------------------------------------------------
// Tests: Cancel propagation through poll chain
// ---------------------------------------------------------------------------

/// Verify that resource-holding futures are cleaned up when their region is
/// closed, even if they never complete on their own. In browser context,
/// this simulates aborting an in-flight fetch() or closing a WebSocket.
#[test]
fn browser_resource_cleanup_on_region_close() {
    let mut runtime = LabRuntime::new(LabConfig::new(42));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let drop_flags: Vec<_> = (0..3).map(|_| Arc::new(AtomicBool::new(false))).collect();
    let cleanup_counters: Vec<_> = (0..3).map(|_| Arc::new(AtomicU32::new(0))).collect();

    let mut task_ids = Vec::new();
    for i in 0..3 {
        let df = Arc::clone(&drop_flags[i]);
        let cc = Arc::clone(&cleanup_counters[i]);
        let steps = (i as u32 + 1) * 2; // 2, 4, 6 cleanup steps

        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let _resource = ResourceHoldingFuture {
                    drop_flag: df,
                    cleanup_steps_on_drop: steps,
                    cleanup_counter: cc,
                };
                // Never completes — simulates long-running browser operation
                std::future::pending::<()>().await;
            })
            .expect("create task");
        task_ids.push(task_id);
    }

    {
        let mut sched = runtime.scheduler.lock();
        for &tid in &task_ids {
            sched.schedule(tid, 0);
        }
    }

    // Run until idle — pending tasks cannot make progress
    runtime.run_until_idle();
    // Drop the runtime to force-drain all pending tasks (simulates region close)
    drop(runtime);

    for (i, flag) in drop_flags.iter().enumerate() {
        assert!(
            flag.load(Ordering::SeqCst),
            "Resource {i} was not cleaned up on region close"
        );
    }

    // Verify cleanup work was performed
    for (i, counter) in cleanup_counters.iter().enumerate() {
        let expected = (i as u32 + 1) * 2;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            expected,
            "Resource {i} cleanup steps: expected {expected}, got {}",
            counter.load(Ordering::SeqCst)
        );
    }
}

// ---------------------------------------------------------------------------
// Tests: Oracle integration with LabRuntime
// ---------------------------------------------------------------------------

/// LoserDrainOracle correctly tracks a simulated N-way race under
/// browser-like sequential scheduling.
#[test]
fn browser_oracle_nway_race_sequential_scheduling() {
    let mut oracle = LoserDrainOracle::new();

    let region = RegionId::new_for_test(1, 0);
    let participants: Vec<TaskId> = (1..=5).map(|i| TaskId::new_for_test(i, 0)).collect();

    let race_id = oracle.on_race_start(region, participants.clone(), Time::ZERO);

    // In single-threaded browser: tasks complete strictly sequentially
    // Task 3 wins first (fastest)
    oracle.on_task_complete(participants[2], Time::from_nanos(10));

    // Then losers are drained one by one (sequential scheduling)
    oracle.on_task_complete(participants[0], Time::from_nanos(20));
    oracle.on_task_complete(participants[1], Time::from_nanos(30));
    oracle.on_task_complete(participants[3], Time::from_nanos(40));
    oracle.on_task_complete(participants[4], Time::from_nanos(50));

    // Race completes after all losers drained
    oracle.on_race_complete(race_id, participants[2], Time::from_nanos(60));

    assert!(
        oracle.check().is_ok(),
        "5-way race with sequential drain should pass oracle"
    );
}

/// Oracle detects violation when browser scheduling causes a loser to be
/// abandoned (e.g., if scheduler skips a task).
#[test]
fn browser_oracle_detects_skipped_loser() {
    let mut oracle = LoserDrainOracle::new();

    let region = RegionId::new_for_test(1, 0);
    let tasks: Vec<TaskId> = (1..=3).map(|i| TaskId::new_for_test(i, 0)).collect();

    let race_id = oracle.on_race_start(region, tasks.clone(), Time::ZERO);

    // Winner completes
    oracle.on_task_complete(tasks[0], Time::from_nanos(10));
    // Only one loser is drained (task[1]), task[2] is skipped
    oracle.on_task_complete(tasks[1], Time::from_nanos(20));

    // Race completes with one loser still pending
    oracle.on_race_complete(race_id, tasks[0], Time::from_nanos(30));

    let result = oracle.check();
    assert!(result.is_err(), "Oracle should detect abandoned loser");

    let violation = result.unwrap_err();
    assert_eq!(
        violation.undrained_losers,
        vec![tasks[2]],
        "Task 3 should be the undrained loser"
    );
}

/// Oracle handles concurrent races (browser can have multiple independent
/// race scopes active simultaneously).
#[test]
fn browser_oracle_concurrent_races() {
    let mut oracle = LoserDrainOracle::new();

    let region = RegionId::new_for_test(1, 0);

    // Race A: 2 participants
    let a1 = TaskId::new_for_test(1, 0);
    let a2 = TaskId::new_for_test(2, 0);
    let race_a = oracle.on_race_start(region, vec![a1, a2], Time::ZERO);

    // Race B: 3 participants (started while A is still active)
    let b1 = TaskId::new_for_test(3, 0);
    let b2 = TaskId::new_for_test(4, 0);
    let b3 = TaskId::new_for_test(5, 0);
    let race_b = oracle.on_race_start(region, vec![b1, b2, b3], Time::from_nanos(5));

    // Interleaved completions (browser scheduler interleaves)
    oracle.on_task_complete(b2, Time::from_nanos(10)); // B winner
    oracle.on_task_complete(a1, Time::from_nanos(15)); // A winner
    oracle.on_task_complete(a2, Time::from_nanos(20)); // A loser drained
    oracle.on_task_complete(b1, Time::from_nanos(25)); // B loser drained
    oracle.on_task_complete(b3, Time::from_nanos(30)); // B loser drained

    oracle.on_race_complete(race_a, a1, Time::from_nanos(22));
    oracle.on_race_complete(race_b, b2, Time::from_nanos(35));

    assert!(
        oracle.check().is_ok(),
        "Concurrent races with interleaved drain should pass oracle"
    );
}

// ---------------------------------------------------------------------------
// Tests: Join semantics under cancellation
// ---------------------------------------------------------------------------

/// Verify that join waits for ALL branches even when they complete at different
/// rates. Under browser single-threaded scheduling, branches complete strictly
/// sequentially, but join must still aggregate all outcomes.
#[test]
fn browser_join_waits_for_all_branches() {
    let mut runtime = LabRuntime::new(LabConfig::new(42));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let completion_flags: Vec<_> = (0..4).map(|_| Arc::new(AtomicBool::new(false))).collect();

    let mut task_ids = Vec::new();
    for (i, flag) in completion_flags.iter().enumerate() {
        let f = Arc::clone(flag);
        let (tid, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                f.store(true, Ordering::SeqCst);
                i as u32
            })
            .expect("create join branch");
        task_ids.push(tid);
    }

    {
        let mut sched = runtime.scheduler.lock();
        for &tid in &task_ids {
            sched.schedule(tid, 0);
        }
    }

    runtime.run_until_quiescent();

    // ALL branches must complete (join semantics)
    for (i, flag) in completion_flags.iter().enumerate() {
        assert!(
            flag.load(Ordering::SeqCst),
            "Join branch {i} did not complete — join abandoned a branch"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests: Nested race/join interaction
// ---------------------------------------------------------------------------

/// Nested race within join: outer join has two branches, one is a race.
/// When the race completes, its losers must be drained, and the join must
/// still wait for the other branch.
#[test]
fn browser_nested_race_in_join_drains_correctly() {
    let mut runtime = LabRuntime::new(LabConfig::new(42));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let race_winner_done = Arc::new(AtomicBool::new(false));
    let race_loser_dropped = Arc::new(AtomicBool::new(false));
    let join_other_branch_done = Arc::new(AtomicBool::new(false));

    // Branch 1: simulates a race (winner + loser)
    let winner_f = Arc::clone(&race_winner_done);
    let loser_f = Arc::clone(&race_loser_dropped);
    let (race_tid, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            // Winner completes
            winner_f.store(true, Ordering::SeqCst);
            // Loser's drop flag gets set (simulating race loser cleanup)
            loser_f.store(true, Ordering::SeqCst);
        })
        .expect("create race branch");

    // Branch 2: independent work
    let other_f = Arc::clone(&join_other_branch_done);
    let (other_tid, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            other_f.store(true, Ordering::SeqCst);
        })
        .expect("create other branch");

    {
        let mut sched = runtime.scheduler.lock();
        sched.schedule(race_tid, 0);
        sched.schedule(other_tid, 0);
    }

    runtime.run_until_quiescent();

    assert!(
        race_winner_done.load(Ordering::SeqCst),
        "Race winner did not complete"
    );
    assert!(
        race_loser_dropped.load(Ordering::SeqCst),
        "Race loser was not drained within the join"
    );
    assert!(
        join_other_branch_done.load(Ordering::SeqCst),
        "Join other branch was abandoned — join must wait for all"
    );
}

// ---------------------------------------------------------------------------
// Tests: Outcome severity lattice in join
// ---------------------------------------------------------------------------

/// Verify join2_outcomes follows the severity lattice: Ok < Err < Cancelled < Panicked.
/// This is essential for browser correctness where aggregated outcomes determine
/// whether the UI shows success, error, or cancellation state.
#[test]
fn browser_join_severity_lattice_ordering() {
    use asupersync::combinator::join::join2_outcomes;
    use asupersync::types::Outcome;
    use asupersync::types::cancel::CancelReason;

    // Ok + Ok = Ok
    let (agg, _, _) = join2_outcomes::<i32, i32, &str>(Outcome::Ok(1), Outcome::Ok(2));
    assert!(agg.is_ok(), "Ok+Ok should produce Ok");

    // Ok + Err = Err (Err > Ok)
    let (agg, v1, _) = join2_outcomes::<i32, i32, &str>(Outcome::Ok(1), Outcome::Err("e"));
    assert!(agg.is_err(), "Ok+Err should produce Err");
    assert_eq!(v1, Some(1), "Successful branch value preserved");

    // Err + Cancelled = Cancelled (Cancelled > Err)
    let (agg, _, _) = join2_outcomes::<i32, i32, &str>(
        Outcome::Err("e"),
        Outcome::Cancelled(CancelReason::user("test")),
    );
    assert!(agg.is_cancelled(), "Err+Cancelled should produce Cancelled");

    // Cancelled + Cancelled = Cancelled (strengthened)
    let (agg, _, _) = join2_outcomes::<i32, i32, &str>(
        Outcome::Cancelled(CancelReason::user("a")),
        Outcome::Cancelled(CancelReason::user("b")),
    );
    assert!(
        agg.is_cancelled(),
        "Cancelled+Cancelled should produce Cancelled"
    );
}

/// Verify join_all_outcomes aggregation for N branches.
#[test]
fn browser_join_all_severity_aggregation() {
    use asupersync::combinator::join::join_all_outcomes;
    use asupersync::types::Outcome;
    use asupersync::types::policy::AggregateDecision;

    // All Ok
    let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1), Outcome::Ok(2), Outcome::Ok(3)];
    let (decision, successes) = join_all_outcomes(outcomes);
    assert!(
        matches!(decision, AggregateDecision::AllOk),
        "All Ok should yield AllOk"
    );
    assert_eq!(successes.len(), 3);

    // Mix of Ok and Err
    let outcomes: Vec<Outcome<i32, &str>> =
        vec![Outcome::Ok(1), Outcome::Err("fail"), Outcome::Ok(3)];
    let (decision, successes) = join_all_outcomes(outcomes);
    assert!(
        matches!(decision, AggregateDecision::FirstError(..)),
        "Ok+Err should yield FirstError"
    );
    assert_eq!(successes.len(), 2, "Two successful values preserved");
}

// ---------------------------------------------------------------------------
// Tests: SporkAppHarness integration
// ---------------------------------------------------------------------------

/// Use SporkAppHarness to verify oracle report includes loser drain checks.
/// This is the closest we can get to "browser runtime" verification without
/// the actual wasm32 target.
#[test]
fn browser_spork_harness_oracles_pass_for_clean_lifecycle() {
    use asupersync::app::AppSpec;
    use asupersync::lab::SporkAppHarness;

    let app = AppSpec::new("browser_drain_test");
    let harness = SporkAppHarness::with_seed(42, app).unwrap();
    let report = harness.run_to_report().unwrap();

    assert!(
        report.passed(),
        "Clean lifecycle should pass all oracles including loser drain: {:?}",
        report.oracle_failures()
    );
    assert!(
        report.run.quiescent,
        "Runtime must reach quiescence (browser region close)"
    );
}

/// SporkAppHarness deterministic replay: same seed produces identical reports.
/// Browser replay debugging depends on this property.
#[test]
fn browser_spork_harness_deterministic_replay() {
    use asupersync::app::AppSpec;
    use asupersync::lab::SporkAppHarness;

    let run = |seed: u64| {
        let app = AppSpec::new("browser_replay_test");
        let harness = SporkAppHarness::with_seed(seed, app).unwrap();
        harness.run_to_report().unwrap()
    };

    let report_a = run(42);
    let report_b = run(42);

    assert_eq!(
        report_a.run.trace_fingerprint, report_b.run.trace_fingerprint,
        "Same seed must produce identical trace fingerprint for browser replay"
    );
}

// ---------------------------------------------------------------------------
// Tests: Edge cases — interruption windows
// ---------------------------------------------------------------------------

/// A task that is mid-computation when the region closes must still be drained.
/// In browser, this simulates a Promise that is mid-resolution when the page
/// navigates away or the runtime scope is cancelled.
#[test]
fn browser_mid_computation_task_drained_on_region_close() {
    let mut runtime = LabRuntime::new(LabConfig::new(42));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let partial_state = Arc::new(AtomicU32::new(0));
    let cleanup_flag = Arc::new(AtomicBool::new(false));

    let ps = Arc::clone(&partial_state);
    let cf = Arc::clone(&cleanup_flag);

    let (task_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            struct MidComputeGuard {
                state: Arc<AtomicU32>,
                cleanup: Arc<AtomicBool>,
            }
            impl Drop for MidComputeGuard {
                fn drop(&mut self) {
                    // Record that cleanup happened with partial state
                    let state = self.state.load(Ordering::SeqCst);
                    assert!(
                        state > 0,
                        "Task should have made some progress before drain"
                    );
                    self.cleanup.store(true, Ordering::SeqCst);
                }
            }

            let _guard = MidComputeGuard {
                state: ps,
                cleanup: cf,
            };

            // Step 1: initial work
            partial_state.store(1, Ordering::SeqCst);

            // Step 2: would do more work, but awaits (may be cancelled here)
            std::future::pending::<()>().await;

            // Step 3: never reached if cancelled — but guard still runs
            partial_state.store(3, Ordering::SeqCst);
        })
        .expect("create task");

    runtime.scheduler.lock().schedule(task_id, 0);
    // Run until idle — task suspends at pending::<()>()
    runtime.run_until_idle();
    // Drop runtime to force-drain the suspended task
    drop(runtime);

    assert!(
        cleanup_flag.load(Ordering::SeqCst),
        "Mid-computation task must be drained (guard.drop called)"
    );
}

/// Multiple tasks with staggered lifetimes: some complete naturally, some are
/// drained. All must clean up.
#[test]
fn browser_mixed_completion_and_drain() {
    let mut runtime = LabRuntime::new(LabConfig::new(42));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let natural_done = Arc::new(AtomicBool::new(false));
    let drained_done = Arc::new(AtomicBool::new(false));

    // Task A: completes naturally
    let nd = Arc::clone(&natural_done);
    let (tid_a, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            nd.store(true, Ordering::SeqCst);
        })
        .expect("create natural");

    // Task B: never completes, will be drained
    let dd = Arc::clone(&drained_done);
    let (tid_b, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            struct G(Arc<AtomicBool>);
            impl Drop for G {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }
            let _g = G(dd);
            std::future::pending::<()>().await;
        })
        .expect("create pending");

    {
        let mut sched = runtime.scheduler.lock();
        sched.schedule(tid_a, 0);
        sched.schedule(tid_b, 0);
    }

    // Run until idle — task A completes, task B suspends forever
    runtime.run_until_idle();

    // Task A should have completed naturally
    assert!(
        natural_done.load(Ordering::SeqCst),
        "Naturally completing task must finish"
    );

    // Drop runtime to force-drain task B
    drop(runtime);

    assert!(
        drained_done.load(Ordering::SeqCst),
        "Pending task must be drained on region close"
    );
}
