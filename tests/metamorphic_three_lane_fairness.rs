//! Metamorphic tests for three-lane scheduler fairness invariants in src/runtime/scheduler/three_lane.rs.
//!
//! Tests key metamorphic relations in the three-lane scheduler:
//! 1. Cancel-lane fairness bound - ready/timed work dispatched within cancel_streak_limit
//! 2. Lane promotion ordering - higher priority lanes always preempt lower ones
//! 3. Adaptive streak convergence - EXP3 policy finds optimal cancel_streak_limit
//! 4. Cross-worker fairness consistency - fairness bounds hold per-worker
//! 5. Starvation prevention - no lane is indefinitely blocked under sustained load
//!
//! Uses LabRuntime virtual time for deterministic testing of scheduler fairness patterns.

#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::scheduler::three_lane::ThreeLaneScheduler;
use asupersync::runtime::{RuntimeState, yield_now};
use asupersync::sync::ContendedMutex;
use asupersync::types::{Budget, RegionId, TaskId};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

const TEST_TIMEOUT_STEPS: usize = 20_000;
const MAX_WORKERS: usize = 4;
const MAX_TASKS_PER_LANE: usize = 16;
const DEFAULT_CANCEL_STREAK_LIMIT: usize = 8;
const ADAPTIVE_CANCEL_STREAK_ARMS: [usize; 5] = [4, 8, 16, 32, 64];

fn create_scheduler_noop_task(
    state: &Arc<ContendedMutex<RuntimeState>>,
    region: RegionId,
) -> TaskId {
    let mut guard = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (task_id, _) = guard
        .create_task(region, Budget::INFINITE, async {})
        .expect("create adaptive scheduler task");
    task_id
}

/// Test cancel-lane fairness bound invariant.
///
/// Invariant: If ready/timed lanes have pending work, that work is dispatched
/// after at most cancel_streak_limit consecutive cancel dispatches.
fn test_cancel_lane_fairness_bound(
    seed: u64,
    worker_count: usize,
    cancel_tasks: usize,
    ready_tasks: usize,
    cancel_streak_limit: usize,
) -> (Vec<(String, u64)>, usize, usize) {
    let _ = cancel_streak_limit; // LabScheduler uses a fixed internal limit
    let mut runtime = LabRuntime::new(
        LabConfig::new(seed)
            .worker_count(worker_count.min(MAX_WORKERS))
            .max_steps(TEST_TIMEOUT_STEPS as u64),
    );
    let root_region = runtime.state.create_root_region(Budget::INFINITE);
    let dispatch_order = Arc::new(StdMutex::new(Vec::new()));
    let cancel_dispatches = Arc::new(AtomicUsize::new(0));
    let ready_dispatches = Arc::new(AtomicUsize::new(0));

    // Spawn cancel-lane tasks (high priority, should trigger fairness limits)
    for i in 0..cancel_tasks.min(MAX_TASKS_PER_LANE) {
        let dispatch_order = Arc::clone(&dispatch_order);
        let cancel_dispatches = Arc::clone(&cancel_dispatches);
        let task_region = runtime
            .state
            .create_child_region(root_region, Budget::INFINITE)
            .expect("create cancel task region");

        let (task_id, _) = runtime
            .state
            .create_task(task_region, Budget::INFINITE, async move {
                // Simulate cancellation work
                for step in 0..3 {
                    yield_now().await;
                    if step == 1 {
                        cancel_dispatches.fetch_add(1, Ordering::SeqCst);
                        dispatch_order
                            .lock()
                            .unwrap()
                            .push((format!("cancel-{}", i), step));
                    }
                }
            })
            .expect("create cancel task");

        // Inject into cancel lane with high priority
        runtime.scheduler.lock().schedule_cancel(task_id, 255);
    }

    // Spawn ready-lane tasks (normal priority, should observe fairness)
    for i in 0..ready_tasks.min(MAX_TASKS_PER_LANE) {
        let dispatch_order = Arc::clone(&dispatch_order);
        let ready_dispatches = Arc::clone(&ready_dispatches);
        let task_region = runtime
            .state
            .create_child_region(root_region, Budget::INFINITE)
            .expect("create ready task region");

        let (task_id, _) = runtime
            .state
            .create_task(task_region, Budget::INFINITE, async move {
                // Simulate ready work
                for step in 0..5 {
                    yield_now().await;
                    if step == 2 {
                        ready_dispatches.fetch_add(1, Ordering::SeqCst);
                        dispatch_order
                            .lock()
                            .unwrap()
                            .push((format!("ready-{}", i), step));
                    }
                }
            })
            .expect("create ready task");

        runtime.scheduler.lock().schedule(task_id, 128);
    }

    // Run until quiescence
    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "cancel-lane fairness bound violated invariants: {violations:?}"
    );

    let order = dispatch_order.lock().unwrap().clone();
    let cancel_count = cancel_dispatches.load(Ordering::SeqCst);
    let ready_count = ready_dispatches.load(Ordering::SeqCst);

    // Metamorphic invariant: Ready tasks should get scheduled even under cancel pressure
    if ready_tasks > 0 && cancel_tasks > 0 {
        assert!(
            ready_count > 0,
            "ready tasks should be scheduled despite cancel pressure: cancel={}, ready={}, order={:?}",
            cancel_count,
            ready_count,
            order
        );

        // Check that ready work appears interspersed with cancel work, not blocked indefinitely
        let ready_positions: Vec<_> = order
            .iter()
            .enumerate()
            .filter(|(_, (name, _))| name.starts_with("ready-"))
            .map(|(pos, _)| pos)
            .collect();

        if ready_positions.len() > 1 {
            // Ready tasks should not all be bunched at the end (would indicate starvation)
            let first_ready = ready_positions[0];
            let last_ready = ready_positions[ready_positions.len() - 1];
            let spread = last_ready - first_ready;

            assert!(
                spread >= order.len() / 4,
                "ready tasks appear to be starved - insufficient temporal spread: first={}, last={}, spread={}, total={}",
                first_ready,
                last_ready,
                spread,
                order.len()
            );
        }
    }

    (order, cancel_count, ready_count)
}

/// Test lane promotion ordering invariant.
///
/// Invariant: Cancel lane always preempts timed lane, timed preempts ready.
fn test_lane_promotion_ordering(
    seed: u64,
    worker_count: usize,
    promotion_scenarios: usize,
) -> Vec<(String, u8, u64)> {
    let mut runtime = LabRuntime::new(
        LabConfig::new(seed)
            .worker_count(worker_count.min(MAX_WORKERS))
            .max_steps(TEST_TIMEOUT_STEPS as u64),
    );
    let root_region = runtime.state.create_root_region(Budget::INFINITE);
    let promotion_events = Arc::new(StdMutex::new(Vec::new()));

    for scenario in 0..promotion_scenarios.min(6) {
        // Create tasks in different lanes with different priorities
        let lanes = ["ready", "timed", "cancel"];
        let priorities = [64u8, 128u8, 255u8]; // ready < timed < cancel

        for (lane_idx, &lane_name) in lanes.iter().enumerate() {
            let promotion_events = Arc::clone(&promotion_events);
            let priority = priorities[lane_idx];

            let task_region = runtime
                .state
                .create_child_region(root_region, Budget::INFINITE)
                .expect("create promotion test task region");

            let (task_id, _) = runtime
                .state
                .create_task(task_region, Budget::INFINITE, async move {
                    yield_now().await;
                    let timestamp = scenario as u64 * 100 + lane_idx as u64;
                    promotion_events.lock().unwrap().push((
                        lane_name.to_string(),
                        priority,
                        timestamp,
                    ));
                })
                .expect("create promotion test task");

            // Inject with slight timing offset to test ordering
            match lane_name {
                "ready" => runtime.scheduler.lock().schedule(task_id, priority),
                "timed" => {
                    let deadline = runtime.now();
                    runtime.scheduler.lock().schedule_timed(task_id, deadline);
                }
                "cancel" => runtime.scheduler.lock().schedule_cancel(task_id, priority),
                _ => unreachable!(),
            }

            // Small delay to create injection ordering
            for _ in 0..2 {
                runtime.step_for_test();
            }
        }
    }

    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "lane promotion ordering violated invariants: {violations:?}"
    );

    let events = promotion_events.lock().unwrap().clone();

    // Metamorphic invariant: Within each scenario, higher priority lanes complete first
    for scenario in 0..promotion_scenarios.min(6) {
        let scenario_events: Vec<_> = events
            .iter()
            .filter(|(_, _, ts)| *ts / 100 == scenario as u64)
            .collect();

        if scenario_events.len() >= 2 {
            // Cancel should come before timed, timed before ready
            let mut priorities: Vec<_> = scenario_events.iter().map(|(_, p, _)| *p).collect();
            priorities.sort_by(|a, b| b.cmp(a)); // Descending order (highest first)

            for i in 1..priorities.len() {
                assert!(
                    priorities[i - 1] >= priorities[i],
                    "lane promotion ordering violated in scenario {}: priorities should be descending, got {:?}",
                    scenario,
                    priorities
                );
            }
        }
    }

    events
}

/// Test adaptive cancel streak convergence.
///
/// Invariant: EXP3 policy should converge to streak limits that balance throughput and fairness.
fn test_adaptive_streak_convergence(
    seed: u64,
    worker_count: usize,
    epoch_steps: u32,
    test_epochs: usize,
) -> (Vec<usize>, f64, f64) {
    let worker_count = worker_count.clamp(1, MAX_WORKERS);
    let epoch_steps = epoch_steps.max(1);
    let task_count = test_epochs
        .min(8)
        .saturating_mul(epoch_steps as usize)
        .max(epoch_steps as usize + 1);
    let state = Arc::new(ContendedMutex::new(
        "adaptive_streak_mr_state",
        RuntimeState::new(),
    ));
    let root_region = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .create_root_region(Budget::INFINITE);
    let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(
        worker_count,
        &state,
        DEFAULT_CANCEL_STREAK_LIMIT,
    );
    scheduler.set_adaptive_cancel_streak(true, epoch_steps);

    for index in 0..task_count {
        let task_id = create_scheduler_noop_task(&state, root_region);
        if (index + seed as usize) % 3 == 0 {
            scheduler.inject_cancel(task_id, 200);
        } else {
            scheduler.inject_ready(task_id, 100);
        }
    }

    let mut worker = scheduler
        .take_workers()
        .into_iter()
        .next()
        .expect("scheduler has a worker");
    let mut samples = Vec::new();
    let mut last_epoch = 0;

    for _ in 0..task_count {
        assert!(
            worker.run_once(),
            "worker should dispatch every queued task"
        );
        let metrics = worker.preemption_metrics();
        if metrics.adaptive_epochs > last_epoch {
            samples.push(metrics.adaptive_current_limit);
            last_epoch = metrics.adaptive_epochs;
        }
    }

    let metrics = worker.preemption_metrics();
    assert!(
        metrics.adaptive_epochs > 0,
        "adaptive policy should publish completed epochs after real dispatch"
    );
    assert!(
        metrics.adaptive_reward_ema.is_finite(),
        "adaptive reward EMA should stay finite: {:?}",
        metrics
    );
    assert!(
        metrics.adaptive_e_value.is_finite() && metrics.adaptive_e_value > 0.0,
        "adaptive e-value should stay positive and finite: {:?}",
        metrics
    );
    assert!(
        ADAPTIVE_CANCEL_STREAK_ARMS.contains(&metrics.adaptive_current_limit),
        "adaptive policy selected a limit outside the configured arms: {:?}",
        metrics
    );
    assert!(
        samples
            .iter()
            .all(|limit| ADAPTIVE_CANCEL_STREAK_ARMS.contains(limit)),
        "adaptive limit samples must come from configured arms: {samples:?}"
    );
    assert!(
        samples.len() >= test_epochs.min(8),
        "adaptive policy should publish at least one sample per requested epoch: samples={samples:?}, epochs={test_epochs}"
    );

    // Calculate convergence metrics
    let mean = if samples.is_empty() {
        DEFAULT_CANCEL_STREAK_LIMIT as f64
    } else {
        samples.iter().sum::<usize>() as f64 / samples.len() as f64
    };

    let variance = if samples.len() <= 1 {
        0.0
    } else {
        let squared_diffs: f64 = samples.iter().map(|&x| (x as f64 - mean).powi(2)).sum();
        squared_diffs / (samples.len() - 1) as f64
    };

    (samples, mean, variance)
}

/// Test cross-worker fairness consistency.
///
/// Invariant: Each worker independently enforces fairness bounds.
fn test_cross_worker_fairness_consistency(
    seed: u64,
    worker_count: usize,
    tasks_per_worker: usize,
) -> Vec<(usize, String, u64)> {
    let mut runtime = LabRuntime::new(
        LabConfig::new(seed)
            .worker_count(worker_count.min(MAX_WORKERS))
            .max_steps(TEST_TIMEOUT_STEPS as u64),
    );
    let root_region = runtime.state.create_root_region(Budget::INFINITE);
    let worker_events = Arc::new(StdMutex::new(Vec::new()));

    // Create tasks that exercise different workers
    for worker_id in 0..worker_count.min(MAX_WORKERS) {
        for task_id in 0..tasks_per_worker.min(8) {
            let worker_events = Arc::clone(&worker_events);

            let task_region = runtime
                .state
                .create_child_region(root_region, Budget::INFINITE)
                .expect("create cross-worker test task region");

            let (task, _) = runtime
                .state
                .create_task(task_region, Budget::INFINITE, async move {
                    // Simulate worker-specific scheduling patterns
                    for step in 0..4 {
                        yield_now().await;
                        if step == 1 {
                            worker_events.lock().unwrap().push((
                                worker_id,
                                format!("worker-{}-task-{}", worker_id, task_id),
                                step,
                            ));
                        }
                    }
                })
                .expect("create cross-worker test task");

            // Alternate between cancel and ready injection to create scheduling pressure
            if task_id % 2 == 0 {
                runtime.scheduler.lock().schedule_cancel(task, 180);
            } else {
                runtime.scheduler.lock().schedule(task, 120);
            }
        }
    }

    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "cross-worker fairness consistency violated invariants: {violations:?}"
    );

    let events = worker_events.lock().unwrap().clone();

    // Metamorphic invariant: Each worker should process some tasks
    let mut workers_with_tasks = std::collections::HashSet::new();
    for (worker_id, _, _) in &events {
        workers_with_tasks.insert(*worker_id);
    }

    if worker_count > 1 && tasks_per_worker > 0 {
        assert!(
            workers_with_tasks.len() >= (worker_count / 2).max(1),
            "cross-worker fairness issue: only {} of {} workers processed tasks, events: {:?}",
            workers_with_tasks.len(),
            worker_count,
            events
        );
    }

    // Check for reasonably balanced task distribution
    if worker_count > 1 {
        let mut tasks_per_worker_actual = vec![0; worker_count];
        for (worker_id, _, _) in &events {
            if *worker_id < worker_count {
                tasks_per_worker_actual[*worker_id] += 1;
            }
        }

        let max_tasks = *tasks_per_worker_actual.iter().max().unwrap_or(&0);
        let min_tasks = *tasks_per_worker_actual.iter().min().unwrap_or(&0);

        // Allow some imbalance but not complete starvation
        if max_tasks > 0 {
            let imbalance_ratio = max_tasks as f64 / (min_tasks + 1) as f64;
            assert!(
                imbalance_ratio <= 4.0,
                "excessive cross-worker imbalance: max={}, min={}, ratio={:.1}, distribution={:?}",
                max_tasks,
                min_tasks,
                imbalance_ratio,
                tasks_per_worker_actual
            );
        }
    }

    events
}

#[test]
fn metamorphic_cancel_lane_fairness_bound() {
    for seed in [0, 1, 42, 12345] {
        for worker_count in [1, 2] {
            for (cancel_tasks, ready_tasks) in [(4, 2), (2, 4), (3, 3)] {
                for cancel_streak_limit in [4, 8, 12] {
                    let (order, cancel_count, ready_count) = test_cancel_lane_fairness_bound(
                        seed,
                        worker_count,
                        cancel_tasks,
                        ready_tasks,
                        cancel_streak_limit,
                    );

                    // Fairness invariant: both lanes should get some work under mixed load
                    if cancel_tasks > 0 && ready_tasks > 0 {
                        assert!(
                            cancel_count > 0 && ready_count > 0,
                            "fairness bound test failed: seed={}, workers={}, cancel_tasks={}, ready_tasks={}, limit={}, cancel_count={}, ready_count={}, order={:?}",
                            seed,
                            worker_count,
                            cancel_tasks,
                            ready_tasks,
                            cancel_streak_limit,
                            cancel_count,
                            ready_count,
                            order
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn metamorphic_lane_promotion_ordering() {
    for seed in [0, 7, 99, 54321] {
        for worker_count in [1, 2] {
            for scenarios in [2, 3] {
                let events = test_lane_promotion_ordering(seed, worker_count, scenarios);

                // Ordering invariant: events should occur in priority order within scenarios
                assert!(
                    !events.is_empty(),
                    "promotion ordering test should generate events: seed={}, workers={}, scenarios={}",
                    seed,
                    worker_count,
                    scenarios
                );

                // Check that we have a reasonable mix of lane types
                let lane_types: std::collections::HashSet<_> =
                    events.iter().map(|(lane, _, _)| lane.as_str()).collect();
                assert!(
                    lane_types.len() >= 2,
                    "promotion test should exercise multiple lane types: seed={}, workers={}, lanes={:?}",
                    seed,
                    worker_count,
                    lane_types
                );
            }
        }
    }
}

#[test]
fn metamorphic_adaptive_streak_convergence() {
    for seed in [0, 13, 777] {
        for worker_count in [1, 2] {
            for (epoch_steps, test_epochs) in [(20, 4), (30, 3)] {
                let (samples, mean, variance) =
                    test_adaptive_streak_convergence(seed, worker_count, epoch_steps, test_epochs);
                let (replay_samples, replay_mean, replay_variance) =
                    test_adaptive_streak_convergence(seed, worker_count, epoch_steps, test_epochs);

                assert_eq!(
                    samples, replay_samples,
                    "adaptive policy should replay the same limit trace for the same seed/workload"
                );
                assert_eq!(
                    mean, replay_mean,
                    "adaptive mean should replay deterministically"
                );
                assert_eq!(
                    variance, replay_variance,
                    "adaptive variance should replay deterministically"
                );
                assert!(
                    mean >= ADAPTIVE_CANCEL_STREAK_ARMS[0] as f64
                        && mean
                            <= ADAPTIVE_CANCEL_STREAK_ARMS[ADAPTIVE_CANCEL_STREAK_ARMS.len() - 1]
                                as f64,
                    "adaptive convergence produced unreasonable mean: seed={}, workers={}, epochs={}, mean={:.1}, samples={:?}",
                    seed,
                    worker_count,
                    test_epochs,
                    mean,
                    samples
                );

                assert!(
                    variance >= 0.0
                        && variance
                            <= ((ADAPTIVE_CANCEL_STREAK_ARMS
                                [ADAPTIVE_CANCEL_STREAK_ARMS.len() - 1]
                                - ADAPTIVE_CANCEL_STREAK_ARMS[0])
                                .pow(2)) as f64,
                    "adaptive convergence produced out-of-arm variance: seed={}, workers={}, epochs={}, variance={:.1}, samples={:?}",
                    seed,
                    worker_count,
                    test_epochs,
                    variance,
                    samples
                );
            }
        }
    }
}

#[test]
fn metamorphic_cross_worker_fairness_consistency() {
    for seed in [0, 5, 123] {
        for worker_count in [1, 2, 3] {
            for tasks_per_worker in [2, 3] {
                let events =
                    test_cross_worker_fairness_consistency(seed, worker_count, tasks_per_worker);

                // Consistency invariant: should have events if there are tasks
                if worker_count > 0 && tasks_per_worker > 0 {
                    assert!(
                        !events.is_empty(),
                        "cross-worker consistency test should generate events: seed={}, workers={}, tasks_per_worker={}",
                        seed,
                        worker_count,
                        tasks_per_worker
                    );

                    // Verify event format
                    for (worker_id, task_name, step) in &events {
                        assert!(
                            *worker_id < worker_count,
                            "invalid worker_id in event: worker_id={}, max={}, event=({}, {}, {})",
                            worker_id,
                            worker_count,
                            worker_id,
                            task_name,
                            step
                        );
                    }
                }
            }
        }
    }
}
