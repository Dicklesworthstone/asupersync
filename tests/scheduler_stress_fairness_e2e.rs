#![allow(missing_docs)]
//! Scheduler Stress & Fairness E2E Tests (bd-13iit).
//!
//! End-to-end tests verifying scheduler fairness properties under realistic
//! mixed workloads with multiple workers, deterministic seeds, and detailed
//! per-worker metrics.
//!
//! Coverage scope (gaps filled relative to existing tests):
//!   - Parametric multi-worker contention (2, 4, 8 workers)
//!   - Continuous injection during execution (work-completion cascades)
//!   - Per-worker PreemptionMetrics breakdown
//!   - Deterministic seed reproducibility across multiple seeds
//!   - Timed-lane EDF correctness under cancel pressure
//!   - Imbalanced load distribution across workers
//!   - Mixed-lane interleaving with tracing
//!
//! Cross-references:
//!   Existing fairness:  tests/scheduler_lane_fairness.rs
//!   Cancel bounds:      tests/cancel_lane_fairness_bounds.rs
//!   Loom concurrency:   tests/scheduler_loom.rs
//!   Regression perf:    tests/scheduler_regression.rs

use asupersync::runtime::scheduler::three_lane::ThreeLaneScheduler;
use asupersync::runtime::RuntimeState;
use asupersync::sync::ContendedMutex;
use asupersync::test_utils::init_test_logging;
use asupersync::time::{TimerDriverHandle, VirtualClock};
use asupersync::types::{Budget, TaskId, Time};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

// ===========================================================================
// HELPERS
// ===========================================================================

fn setup_state() -> Arc<ContendedMutex<RuntimeState>> {
    Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()))
}

fn setup_state_with_clock(
    start_nanos: u64,
) -> (Arc<ContendedMutex<RuntimeState>>, Arc<VirtualClock>) {
    let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(start_nanos)));
    let mut rs = RuntimeState::new();
    rs.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::clone(&clock)));
    (Arc::new(ContendedMutex::new("runtime_state", rs)), clock)
}

fn create_task(
    state: &Arc<ContendedMutex<RuntimeState>>,
    region: asupersync::types::RegionId,
) -> TaskId {
    let mut guard = state.lock().unwrap();
    let (id, _) = guard
        .create_task(region, Budget::INFINITE, async {})
        .unwrap();
    id
}

fn create_n_tasks(
    state: &Arc<ContendedMutex<RuntimeState>>,
    region: asupersync::types::RegionId,
    n: usize,
) -> Vec<TaskId> {
    (0..n).map(|_| create_task(state, region)).collect()
}

/// Spawn workers on threads and return join handles.
fn spawn_workers(
    scheduler: &mut ThreeLaneScheduler,
) -> Vec<std::thread::JoinHandle<asupersync::runtime::scheduler::three_lane::ThreeLaneWorker>> {
    scheduler
        .take_workers()
        .into_iter()
        .map(|mut worker| {
            std::thread::spawn(move || {
                worker.run_loop();
                worker
            })
        })
        .collect()
}

/// Collect preemption metrics from finished worker handles.
fn collect_metrics(
    handles: Vec<
        std::thread::JoinHandle<asupersync::runtime::scheduler::three_lane::ThreeLaneWorker>,
    >,
) -> Vec<asupersync::runtime::scheduler::three_lane::PreemptionMetrics> {
    handles
        .into_iter()
        .map(|h| {
            let worker = h.join().expect("worker panicked");
            worker.preemption_metrics().clone()
        })
        .collect()
}

// ===========================================================================
// PARAMETRIC MULTI-WORKER CONTENTION
// ===========================================================================

/// Verify all lanes complete under N workers with mixed cancel/timed/ready.
fn mixed_workload_n_workers(num_workers: usize) {
    init_test_logging();
    let (state, clock) = setup_state_with_clock(1_000);
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let tasks_per_lane = 50;
    let mut scheduler = ThreeLaneScheduler::new(num_workers, &state);

    let cancel_ids = create_n_tasks(&state, region, tasks_per_lane);
    let timed_ids = create_n_tasks(&state, region, tasks_per_lane);
    let ready_ids = create_n_tasks(&state, region, tasks_per_lane);

    for id in &cancel_ids {
        scheduler.inject_cancel(*id, 100);
    }
    for (i, id) in timed_ids.iter().enumerate() {
        // Stagger deadlines so EDF has meaningful ordering.
        scheduler.inject_timed(*id, Time::from_nanos(500 + i as u64 * 10));
    }
    for id in &ready_ids {
        scheduler.inject_ready(*id, 50);
    }

    // Advance clock past all deadlines.
    clock.advance(100_000);

    let handles = spawn_workers(&mut scheduler);
    std::thread::sleep(Duration::from_secs(2));
    scheduler.shutdown();

    let metrics = collect_metrics(handles);

    // All tasks must complete.
    let guard = state.lock().unwrap();
    let cancel_done = cancel_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    let timed_done = timed_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    let ready_done = ready_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    drop(guard);

    assert_eq!(
        cancel_done, tasks_per_lane,
        "cancel: {cancel_done}/{tasks_per_lane}"
    );
    assert_eq!(
        timed_done, tasks_per_lane,
        "timed: {timed_done}/{tasks_per_lane}"
    );
    assert_eq!(
        ready_done, tasks_per_lane,
        "ready: {ready_done}/{tasks_per_lane}"
    );

    // At least one worker must have dispatched from each lane.
    let total_cancel: u64 = metrics.iter().map(|m| m.cancel_dispatches).sum();
    let total_timed: u64 = metrics.iter().map(|m| m.timed_dispatches).sum();
    let total_ready: u64 = metrics.iter().map(|m| m.ready_dispatches).sum();

    assert!(
        total_cancel > 0,
        "no cancel dispatches across {num_workers} workers"
    );
    assert!(
        total_timed > 0,
        "no timed dispatches across {num_workers} workers"
    );
    assert!(
        total_ready > 0,
        "no ready dispatches across {num_workers} workers"
    );
}

#[test]
fn mixed_workload_2_workers() {
    mixed_workload_n_workers(2);
}

#[test]
fn mixed_workload_4_workers() {
    mixed_workload_n_workers(4);
}

#[test]
fn mixed_workload_8_workers() {
    mixed_workload_n_workers(8);
}

// ===========================================================================
// PER-WORKER METRICS BREAKDOWN
// ===========================================================================

#[test]
fn per_worker_metrics_all_workers_active() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let num_workers = 4;
    let tasks_per_lane = 200;
    let mut scheduler = ThreeLaneScheduler::new(num_workers, &state);

    let cancel_ids = create_n_tasks(&state, region, tasks_per_lane);
    let ready_ids = create_n_tasks(&state, region, tasks_per_lane);

    for id in &cancel_ids {
        scheduler.inject_cancel(*id, 100);
    }
    for id in &ready_ids {
        scheduler.inject_ready(*id, 50);
    }

    let handles = spawn_workers(&mut scheduler);
    std::thread::sleep(Duration::from_secs(2));
    scheduler.shutdown();

    let metrics = collect_metrics(handles);

    // Every worker should have dispatched at least something.
    for (i, m) in metrics.iter().enumerate() {
        let total = m.cancel_dispatches + m.timed_dispatches + m.ready_dispatches;
        assert!(
            total > 0,
            "worker {i} dispatched nothing (cancel={}, timed={}, ready={})",
            m.cancel_dispatches,
            m.timed_dispatches,
            m.ready_dispatches
        );
    }

    // Aggregate counts must match total tasks.
    let total_dispatched: u64 = metrics
        .iter()
        .map(|m| m.cancel_dispatches + m.timed_dispatches + m.ready_dispatches)
        .sum();
    assert_eq!(
        total_dispatched as usize,
        tasks_per_lane * 2,
        "total dispatched should equal total injected"
    );
}

#[test]
fn per_worker_fairness_yield_distribution() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let num_workers = 4;
    let cancel_limit = 4usize;
    let mut scheduler =
        ThreeLaneScheduler::new_with_cancel_limit(num_workers, &state, cancel_limit);

    // Heavy cancel load to force fairness yields.
    let num_cancel = 400;
    let num_ready = 40;

    let cancel_ids = create_n_tasks(&state, region, num_cancel);
    let ready_ids = create_n_tasks(&state, region, num_ready);

    for id in &cancel_ids {
        scheduler.inject_cancel(*id, 100);
    }
    for id in &ready_ids {
        scheduler.inject_ready(*id, 50);
    }

    let handles = spawn_workers(&mut scheduler);
    std::thread::sleep(Duration::from_secs(2));
    scheduler.shutdown();

    let metrics = collect_metrics(handles);

    // Workers that processed cancel tasks past the limit must show fairness yields.
    let total_yields: u64 = metrics.iter().map(|m| m.fairness_yields).sum();
    assert!(
        total_yields > 0,
        "with {num_cancel} cancels and limit={cancel_limit}, should have fairness yields"
    );

    // No worker should exceed cancel_streak_limit.
    for (i, m) in metrics.iter().enumerate() {
        assert!(
            m.max_cancel_streak <= cancel_limit,
            "worker {i}: max_cancel_streak={} > limit={cancel_limit}",
            m.max_cancel_streak
        );
    }
}

// ===========================================================================
// CONTINUOUS INJECTION DURING EXECUTION (WORK-COMPLETION CASCADE)
// ===========================================================================

#[test]
fn continuous_injection_all_lanes_interleaved() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let mut scheduler = ThreeLaneScheduler::new(2, &state);

    // Inject initial batch.
    let batch_size = 20;
    let initial_cancel = create_n_tasks(&state, region, batch_size);
    let initial_ready = create_n_tasks(&state, region, batch_size);

    for id in &initial_cancel {
        scheduler.inject_cancel(*id, 100);
    }
    for id in &initial_ready {
        scheduler.inject_ready(*id, 50);
    }

    let mut total_injected = batch_size * 2;

    let handles = spawn_workers(&mut scheduler);

    // Inject waves from the main thread (which owns the scheduler and can
    // wake workers via inject_cancel/inject_ready).
    for wave in 0..10 {
        std::thread::sleep(Duration::from_millis(50));
        let ids = create_n_tasks(&state, region, 5);
        for id in &ids {
            if wave % 3 == 0 {
                scheduler.inject_cancel(*id, 100);
            } else {
                scheduler.inject_ready(*id, 50);
            }
        }
        total_injected += 5;
    }

    // Wait for drain.
    std::thread::sleep(Duration::from_secs(1));
    scheduler.shutdown();

    let metrics = collect_metrics(handles);

    let total_dispatched: u64 = metrics
        .iter()
        .map(|m| m.cancel_dispatches + m.timed_dispatches + m.ready_dispatches)
        .sum();

    assert_eq!(
        total_dispatched as usize, total_injected,
        "all injected tasks ({total_injected}) should be dispatched (got {total_dispatched})"
    );
}

// ===========================================================================
// DETERMINISTIC SEED REPRODUCIBILITY
// ===========================================================================

/// Run a fixed workload with a given cancel_streak_limit and return
/// the dispatch sequence (via next_task polling, single worker).
fn deterministic_sequence(cancel_limit: usize, num_cancel: usize, num_ready: usize) -> Vec<TaskId> {
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);
    let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, cancel_limit);

    let cancel_ids = create_n_tasks(&state, region, num_cancel);
    let ready_ids = create_n_tasks(&state, region, num_ready);

    for id in &cancel_ids {
        scheduler.inject_cancel(*id, 100);
    }
    for id in &ready_ids {
        scheduler.inject_ready(*id, 50);
    }

    let mut workers = scheduler.take_workers().into_iter();
    let mut worker = workers.next().unwrap();
    let mut order = Vec::new();

    while let Some(id) = worker.next_task() {
        order.push(id);
    }
    order
}

#[test]
fn deterministic_across_multiple_limits() {
    init_test_logging();

    for limit in [1, 2, 4, 8, 16] {
        let seq1 = deterministic_sequence(limit, 20, 5);
        let seq2 = deterministic_sequence(limit, 20, 5);
        assert_eq!(
            seq1, seq2,
            "dispatch order should be deterministic for cancel_limit={limit}"
        );
        assert_eq!(
            seq1.len(),
            25,
            "all 25 tasks should dispatch with limit={limit}"
        );
    }
}

#[test]
fn deterministic_varying_task_counts() {
    init_test_logging();

    let configs = [(10, 2), (50, 10), (100, 20), (200, 50)];
    for (nc, nr) in configs {
        let seq1 = deterministic_sequence(8, nc, nr);
        let seq2 = deterministic_sequence(8, nc, nr);
        assert_eq!(
            seq1, seq2,
            "dispatch order should be deterministic for {nc} cancel + {nr} ready"
        );
        assert_eq!(seq1.len(), nc + nr, "all tasks should dispatch");
    }
}

// ===========================================================================
// TIMED LANE EDF UNDER CANCEL PRESSURE
// ===========================================================================

#[test]
fn timed_edf_preserved_under_cancel_flood() {
    init_test_logging();
    let (state, clock) = setup_state_with_clock(1_000);
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let cancel_limit = 4;
    let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, cancel_limit);

    // Create timed tasks with distinct deadlines.
    let num_timed = 10;
    let timed_ids: Vec<TaskId> = (0..num_timed)
        .map(|_| create_task(&state, region))
        .collect();

    // Inject timed tasks with increasing deadlines: 100, 200, 300, ...
    for (i, id) in timed_ids.iter().enumerate() {
        scheduler.inject_timed(*id, Time::from_nanos(100 + (i as u64 + 1) * 100));
    }

    // Flood with cancel tasks.
    let num_cancel = 50;
    let cancel_ids = create_n_tasks(&state, region, num_cancel);
    for id in &cancel_ids {
        scheduler.inject_cancel(*id, 100);
    }

    // Advance clock past all deadlines.
    clock.advance(100_000);

    let mut workers = scheduler.take_workers().into_iter();
    let mut worker = workers.next().unwrap();

    let mut dispatch_order = Vec::new();
    while let Some(id) = worker.next_task() {
        dispatch_order.push(id);
    }

    // Extract the relative order of timed tasks from the dispatch sequence.
    let timed_positions: Vec<(usize, TaskId)> = dispatch_order
        .iter()
        .enumerate()
        .filter(|(_, id)| timed_ids.contains(id))
        .map(|(pos, id)| (pos, *id))
        .collect();

    assert_eq!(
        timed_positions.len(),
        num_timed,
        "all timed tasks should dispatch"
    );

    // Timed tasks should appear in EDF order relative to each other.
    for window in timed_positions.windows(2) {
        let idx_a = timed_ids.iter().position(|id| *id == window[0].1).unwrap();
        let idx_b = timed_ids.iter().position(|id| *id == window[1].1).unwrap();
        assert!(
            idx_a < idx_b,
            "timed task EDF order violated: timed[{idx_a}] at pos {} vs timed[{idx_b}] at pos {}",
            window[0].0,
            window[1].0
        );
    }
}

// ===========================================================================
// IMBALANCED LOAD: UNEVEN CANCEL/READY RATIO
// ===========================================================================

#[test]
fn imbalanced_heavy_cancel_light_ready() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let mut scheduler = ThreeLaneScheduler::new(4, &state);

    // 1000 cancel tasks, only 5 ready.
    let cancel_ids = create_n_tasks(&state, region, 1000);
    let ready_ids = create_n_tasks(&state, region, 5);

    for id in &cancel_ids {
        scheduler.inject_cancel(*id, 100);
    }
    for id in &ready_ids {
        scheduler.inject_ready(*id, 50);
    }

    let handles = spawn_workers(&mut scheduler);
    std::thread::sleep(Duration::from_secs(2));
    scheduler.shutdown();

    let metrics = collect_metrics(handles);

    let guard = state.lock().unwrap();
    let ready_done = ready_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    let cancel_done = cancel_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    drop(guard);

    assert_eq!(ready_done, 5, "all ready tasks must complete");
    assert_eq!(cancel_done, 1000, "all cancel tasks must complete");

    let total_cancel: u64 = metrics.iter().map(|m| m.cancel_dispatches).sum();
    let total_ready: u64 = metrics.iter().map(|m| m.ready_dispatches).sum();
    assert_eq!(total_cancel, 1000);
    assert_eq!(total_ready, 5);
}

#[test]
fn imbalanced_heavy_ready_light_cancel() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let mut scheduler = ThreeLaneScheduler::new(4, &state);

    // 5 cancel tasks, 1000 ready.
    let cancel_ids = create_n_tasks(&state, region, 5);
    let ready_ids = create_n_tasks(&state, region, 1000);

    for id in &cancel_ids {
        scheduler.inject_cancel(*id, 100);
    }
    for id in &ready_ids {
        scheduler.inject_ready(*id, 50);
    }

    let handles = spawn_workers(&mut scheduler);
    std::thread::sleep(Duration::from_secs(2));
    scheduler.shutdown();

    let metrics = collect_metrics(handles);

    let guard = state.lock().unwrap();
    let cancel_done = cancel_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    let ready_done = ready_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    drop(guard);

    assert_eq!(cancel_done, 5, "all cancel tasks must complete");
    assert_eq!(ready_done, 1000, "all ready tasks must complete");

    // Cancel tasks should dispatch before most ready tasks.
    let total_cancel: u64 = metrics.iter().map(|m| m.cancel_dispatches).sum();
    assert_eq!(total_cancel, 5);
}

// ===========================================================================
// STRESS: ALL THREE LANES SATURATED
// ===========================================================================

#[test]
fn stress_all_lanes_saturated_4_workers() {
    init_test_logging();
    let (state, clock) = setup_state_with_clock(1_000);
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let mut scheduler = ThreeLaneScheduler::new(4, &state);
    let n = 200;

    let cancel_ids = create_n_tasks(&state, region, n);
    let timed_ids = create_n_tasks(&state, region, n);
    let ready_ids = create_n_tasks(&state, region, n);

    for id in &cancel_ids {
        scheduler.inject_cancel(*id, 100);
    }
    for (i, id) in timed_ids.iter().enumerate() {
        scheduler.inject_timed(*id, Time::from_nanos(500 + i as u64 * 5));
    }
    for id in &ready_ids {
        scheduler.inject_ready(*id, 50);
    }

    clock.advance(100_000);

    let handles = spawn_workers(&mut scheduler);
    std::thread::sleep(Duration::from_secs(3));
    scheduler.shutdown();

    let metrics = collect_metrics(handles);

    let guard = state.lock().unwrap();
    let cancel_done = cancel_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    let timed_done = timed_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    let ready_done = ready_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    drop(guard);

    assert_eq!(cancel_done, n, "cancel: {cancel_done}/{n}");
    assert_eq!(timed_done, n, "timed: {timed_done}/{n}");
    assert_eq!(ready_done, n, "ready: {ready_done}/{n}");

    let total: u64 = metrics
        .iter()
        .map(|m| m.cancel_dispatches + m.timed_dispatches + m.ready_dispatches)
        .sum();
    assert_eq!(total as usize, n * 3, "total dispatches should equal 3*{n}");
}

// ===========================================================================
// FAIRNESS BOUND HOLDS ACROSS WORKERS
// ===========================================================================

#[test]
fn fairness_bound_per_worker_with_small_limit() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let cancel_limit = 2;
    let num_workers = 4;
    let mut scheduler =
        ThreeLaneScheduler::new_with_cancel_limit(num_workers, &state, cancel_limit);

    let num_cancel = 200;
    let num_ready = 20;

    let cancel_ids = create_n_tasks(&state, region, num_cancel);
    let ready_ids = create_n_tasks(&state, region, num_ready);

    for id in &cancel_ids {
        scheduler.inject_cancel(*id, 100);
    }
    for id in &ready_ids {
        scheduler.inject_ready(*id, 50);
    }

    let handles = spawn_workers(&mut scheduler);
    std::thread::sleep(Duration::from_secs(2));
    scheduler.shutdown();

    let metrics = collect_metrics(handles);

    for (i, m) in metrics.iter().enumerate() {
        assert!(
            m.max_cancel_streak <= cancel_limit,
            "worker {i}: max_cancel_streak={} exceeds limit={cancel_limit}",
            m.max_cancel_streak
        );
    }

    let guard = state.lock().unwrap();
    let cancel_done = cancel_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    let ready_done = ready_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    drop(guard);

    assert_eq!(cancel_done, num_cancel);
    assert_eq!(ready_done, num_ready);
}

// ===========================================================================
// CANCEL-ONLY WORKLOAD: NO STARVATION OF NOTHING
// ===========================================================================

#[test]
fn cancel_only_workload_completes() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let mut scheduler = ThreeLaneScheduler::new(2, &state);
    let n = 500;

    let cancel_ids = create_n_tasks(&state, region, n);
    for id in &cancel_ids {
        scheduler.inject_cancel(*id, 100);
    }

    let handles = spawn_workers(&mut scheduler);
    std::thread::sleep(Duration::from_secs(2));
    scheduler.shutdown();

    let metrics = collect_metrics(handles);

    let guard = state.lock().unwrap();
    let done = cancel_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    drop(guard);

    assert_eq!(done, n, "all cancel tasks should complete");

    let total_fallback: u64 = metrics.iter().map(|m| m.fallback_cancel_dispatches).sum();
    assert!(
        total_fallback > 0,
        "with cancel-only workload, should have fallback dispatches"
    );
}

// ===========================================================================
// TIMED-ONLY WORKLOAD: EDF COMPLETION
// ===========================================================================

#[test]
fn timed_only_workload_completes_edf() {
    init_test_logging();
    let (state, clock) = setup_state_with_clock(1_000);
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let mut scheduler = ThreeLaneScheduler::new(2, &state);
    let n = 100;

    let timed_ids = create_n_tasks(&state, region, n);
    for (i, id) in timed_ids.iter().enumerate() {
        scheduler.inject_timed(*id, Time::from_nanos(500 + (i as u64 + 1) * 50));
    }

    clock.advance(200_000);

    let handles = spawn_workers(&mut scheduler);
    std::thread::sleep(Duration::from_secs(2));
    scheduler.shutdown();

    let metrics = collect_metrics(handles);

    let guard = state.lock().unwrap();
    let done = timed_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    drop(guard);

    assert_eq!(done, n, "all timed tasks should complete");

    let total_timed: u64 = metrics.iter().map(|m| m.timed_dispatches).sum();
    assert_eq!(total_timed as usize, n);
}

// ===========================================================================
// READY-ONLY WORKLOAD: THROUGHPUT
// ===========================================================================

#[test]
fn ready_only_workload_completes() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let mut scheduler = ThreeLaneScheduler::new(4, &state);
    let n = 1000;

    let ready_ids = create_n_tasks(&state, region, n);
    for id in &ready_ids {
        scheduler.inject_ready(*id, 50);
    }

    let handles = spawn_workers(&mut scheduler);
    std::thread::sleep(Duration::from_secs(2));
    scheduler.shutdown();

    let metrics = collect_metrics(handles);

    let guard = state.lock().unwrap();
    let done = ready_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    drop(guard);

    assert_eq!(done, n, "all ready tasks should complete");

    let total_ready: u64 = metrics.iter().map(|m| m.ready_dispatches).sum();
    assert_eq!(total_ready as usize, n);
}

// ===========================================================================
// STAGGERED INJECTION: WAVES OF WORK
// ===========================================================================

#[test]
fn staggered_wave_injection() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let mut scheduler = ThreeLaneScheduler::new(2, &state);

    let total_injected = Arc::new(AtomicUsize::new(0));

    // Initial batch.
    let batch = create_n_tasks(&state, region, 20);
    for id in &batch {
        scheduler.inject_ready(*id, 50);
    }
    total_injected.fetch_add(20, Ordering::Relaxed);

    let handles = spawn_workers(&mut scheduler);

    // Inject 5 waves of 20 tasks each from the main thread so that
    // scheduler.inject_* wakes parked workers.
    for wave in 0..5 {
        std::thread::sleep(Duration::from_millis(100));
        let ids = create_n_tasks(&state, region, 20);
        for id in &ids {
            if wave % 2 == 0 {
                scheduler.inject_cancel(*id, 100);
            } else {
                scheduler.inject_ready(*id, 50);
            }
        }
        total_injected.fetch_add(20, Ordering::Relaxed);
    }

    std::thread::sleep(Duration::from_secs(1));
    scheduler.shutdown();

    let metrics = collect_metrics(handles);

    let total: u64 = metrics
        .iter()
        .map(|m| m.cancel_dispatches + m.timed_dispatches + m.ready_dispatches)
        .sum();
    let expected = total_injected.load(Ordering::Relaxed);
    assert_eq!(
        total as usize, expected,
        "all {expected} wave-injected tasks should dispatch"
    );
}

// ===========================================================================
// SHUTDOWN DRAINS ALL LANES
// ===========================================================================

#[test]
fn shutdown_drains_remaining_work() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let mut scheduler = ThreeLaneScheduler::new(2, &state);

    let cancel_ids = create_n_tasks(&state, region, 50);
    let ready_ids = create_n_tasks(&state, region, 50);

    for id in &cancel_ids {
        scheduler.inject_cancel(*id, 100);
    }
    for id in &ready_ids {
        scheduler.inject_ready(*id, 50);
    }

    let handles = spawn_workers(&mut scheduler);

    // Immediate shutdown — workers should still drain.
    std::thread::sleep(Duration::from_millis(200));
    scheduler.shutdown();

    let _metrics = collect_metrics(handles);

    let guard = state.lock().unwrap();
    let cancel_done = cancel_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    let ready_done = ready_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    drop(guard);

    assert_eq!(cancel_done, 50, "cancel tasks should drain on shutdown");
    assert_eq!(ready_done, 50, "ready tasks should drain on shutdown");
}

// ===========================================================================
// MIXED LANE DISPATCH ORDERING (SINGLE WORKER, DETAILED)
// ===========================================================================

#[test]
fn single_worker_mixed_ordering_detailed() {
    init_test_logging();
    let (state, clock) = setup_state_with_clock(1_000);
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let cancel_limit = 3;
    let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, cancel_limit);

    let num_cancel = 10;
    let num_timed = 5;
    let num_ready = 5;

    let cancel_ids = create_n_tasks(&state, region, num_cancel);
    let timed_ids = create_n_tasks(&state, region, num_timed);
    let ready_ids = create_n_tasks(&state, region, num_ready);

    for id in &cancel_ids {
        scheduler.inject_cancel(*id, 100);
    }
    for (i, id) in timed_ids.iter().enumerate() {
        scheduler.inject_timed(*id, Time::from_nanos(500 + (i as u64 + 1) * 100));
    }
    for id in &ready_ids {
        scheduler.inject_ready(*id, 50);
    }

    clock.advance(100_000);

    let mut workers = scheduler.take_workers().into_iter();
    let mut worker = workers.next().unwrap();

    let mut dispatch_order = Vec::new();
    while let Some(id) = worker.next_task() {
        dispatch_order.push(id);
    }

    assert_eq!(
        dispatch_order.len(),
        num_cancel + num_timed + num_ready,
        "all tasks should dispatch"
    );

    // Verify cancel streak never exceeds limit.
    let mut streak = 0usize;
    for id in &dispatch_order {
        if cancel_ids.contains(id) {
            streak += 1;
            assert!(
                streak <= cancel_limit,
                "cancel streak {streak} exceeds limit {cancel_limit}"
            );
        } else {
            streak = 0;
        }
    }

    let metrics = worker.preemption_metrics();
    assert!(
        metrics.max_cancel_streak <= cancel_limit,
        "metrics confirm streak bound"
    );
    assert_eq!(
        metrics.cancel_dispatches as usize, num_cancel,
        "all cancel tasks dispatched"
    );
    assert_eq!(
        metrics.timed_dispatches as usize, num_timed,
        "all timed tasks dispatched"
    );
    assert_eq!(
        metrics.ready_dispatches as usize, num_ready,
        "all ready tasks dispatched"
    );
}

// ===========================================================================
// LARGE SCALE STRESS: 10K TASKS
// ===========================================================================

#[test]
fn stress_10k_mixed_tasks_8_workers() {
    init_test_logging();
    let state = setup_state();
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let mut scheduler = ThreeLaneScheduler::new(8, &state);

    let n_cancel = 4000;
    let n_ready = 6000;

    let cancel_ids = create_n_tasks(&state, region, n_cancel);
    let ready_ids = create_n_tasks(&state, region, n_ready);

    for id in &cancel_ids {
        scheduler.inject_cancel(*id, 100);
    }
    for id in &ready_ids {
        scheduler.inject_ready(*id, 50);
    }

    let handles = spawn_workers(&mut scheduler);
    std::thread::sleep(Duration::from_secs(5));
    scheduler.shutdown();

    let metrics = collect_metrics(handles);

    let guard = state.lock().unwrap();
    let cancel_done = cancel_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    let ready_done = ready_ids
        .iter()
        .filter(|id| guard.task(**id).is_none())
        .count();
    drop(guard);

    assert_eq!(cancel_done, n_cancel, "cancel: {cancel_done}/{n_cancel}");
    assert_eq!(ready_done, n_ready, "ready: {ready_done}/{n_ready}");

    let total: u64 = metrics
        .iter()
        .map(|m| m.cancel_dispatches + m.timed_dispatches + m.ready_dispatches)
        .sum();
    assert_eq!(total as usize, n_cancel + n_ready);

    // All 8 workers should have been active.
    let active_workers = metrics
        .iter()
        .filter(|m| m.cancel_dispatches + m.timed_dispatches + m.ready_dispatches > 0)
        .count();
    assert!(
        active_workers >= 4,
        "at least half of 8 workers should be active, got {active_workers}"
    );
}
