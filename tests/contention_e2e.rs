#![allow(missing_docs)]
//! E2E Contention Harness + Structured Artifacts (bd-ecaeo).
//!
//! Exercises scheduler hot paths (spawn/wake/cancel, LocalQueue, obligations)
//! and emits structured JSON artifacts with lock contention metrics, worker
//! preemption metrics, and oracle verdicts.
//!
//! Run: `cargo test --test contention_e2e --features lock-metrics -- --nocapture`
//! Artifacts: written to `target/contention/` when present or CI is set.

mod common;

use asupersync::runtime::scheduler::three_lane::{PreemptionMetrics, ThreeLaneScheduler};
use asupersync::runtime::RuntimeState;
use asupersync::sync::{ContendedMutex, LockMetricsSnapshot};
use asupersync::test_utils::init_test_logging;
use asupersync::time::{TimerDriverHandle, VirtualClock};
use asupersync::types::{Budget, TaskId, Time};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

// ===========================================================================
// CONSTANTS
// ===========================================================================

const DEFAULT_SEED: u64 = 0xC0A7_E2D0;
const ARTIFACTS_DIR_ENV: &str = "ASUPERSYNC_CONTENTION_ARTIFACTS_DIR";

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
    (
        Arc::new(ContendedMutex::new("runtime_state", rs)),
        clock,
    )
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

fn collect_metrics(
    handles: Vec<
        std::thread::JoinHandle<asupersync::runtime::scheduler::three_lane::ThreeLaneWorker>,
    >,
) -> Vec<PreemptionMetrics> {
    handles
        .into_iter()
        .map(|h| {
            let worker = h.join().expect("worker panicked");
            worker.preemption_metrics().clone()
        })
        .collect()
}

fn artifacts_dir() -> Option<std::path::PathBuf> {
    if let Ok(value) = std::env::var(ARTIFACTS_DIR_ENV) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(std::path::PathBuf::from(trimmed));
        }
    }

    if std::env::var("CI").is_ok() {
        return Some(std::path::PathBuf::from("target/contention"));
    }

    None
}

fn write_artifact(name: &str, json: &serde_json::Value) {
    let Some(dir) = artifacts_dir() else {
        // Always log to tracing even without file output.
        tracing::info!(artifact = %name, payload = %json, "contention artifact (no dir)");
        return;
    };

    if let Err(err) = std::fs::create_dir_all(&dir) {
        tracing::warn!(error = %err, "failed to create contention artifact dir");
        return;
    }

    let path = dir.join(name);
    match serde_json::to_string_pretty(json) {
        Ok(content) => {
            if let Err(err) = std::fs::write(&path, &content) {
                tracing::warn!(error = %err, path = %path.display(), "failed to write artifact");
            } else {
                tracing::info!(path = %path.display(), "contention artifact written");
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to serialize artifact");
        }
    }
}

fn snapshot_to_json(snap: &LockMetricsSnapshot) -> serde_json::Value {
    serde_json::json!({
        "name": snap.name,
        "acquisitions": snap.acquisitions,
        "contentions": snap.contentions,
        "wait_ns": snap.wait_ns,
        "hold_ns": snap.hold_ns,
        "max_wait_ns": snap.max_wait_ns,
        "max_hold_ns": snap.max_hold_ns,
    })
}

fn preemption_metrics_to_json(metrics: &[PreemptionMetrics]) -> Vec<serde_json::Value> {
    metrics
        .iter()
        .enumerate()
        .map(|(i, m)| {
            serde_json::json!({
                "worker_id": i,
                "cancel_dispatches": m.cancel_dispatches,
                "timed_dispatches": m.timed_dispatches,
                "ready_dispatches": m.ready_dispatches,
                "fairness_yields": m.fairness_yields,
                "max_cancel_streak": m.max_cancel_streak,
                "fallback_cancel_dispatches": m.fallback_cancel_dispatches,
            })
        })
        .collect()
}

// ===========================================================================
// HARNESS: MIXED WORKLOAD WITH METRICS
// ===========================================================================

/// Runs a mixed cancel/timed/ready workload with N workers and collects
/// lock contention + worker preemption metrics.
fn run_mixed_workload(
    test_name: &str,
    num_workers: usize,
    tasks_per_lane: usize,
    seed: u64,
) -> serde_json::Value {
    init_test_logging();

    let (state, clock) = setup_state_with_clock(1_000);

    // Reset metrics before workload (clear any setup noise).
    state.reset_metrics();

    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    let cancel_ids = create_n_tasks(&state, region, tasks_per_lane);
    let timed_ids = create_n_tasks(&state, region, tasks_per_lane);
    let ready_ids = create_n_tasks(&state, region, tasks_per_lane);

    let mut scheduler = ThreeLaneScheduler::new(num_workers, &state);

    for id in &cancel_ids {
        scheduler.inject_cancel(*id, 100);
    }
    for (i, id) in timed_ids.iter().enumerate() {
        scheduler.inject_timed(*id, Time::from_nanos(500 + i as u64 * 10));
    }
    for id in &ready_ids {
        scheduler.inject_ready(*id, 50);
    }

    // Advance clock past all timed deadlines.
    clock.advance(100_000);

    // Run workers.
    let handles = spawn_workers(&mut scheduler);
    std::thread::sleep(Duration::from_secs(2));
    scheduler.shutdown();

    let worker_metrics = collect_metrics(handles);

    // Snapshot lock metrics.
    let lock_snapshot = state.snapshot();

    // Oracle: verify all tasks completed.
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
    let total_tasks = guard.tasks.len();
    drop(guard);

    let oracle_pass = cancel_done == tasks_per_lane
        && timed_done == tasks_per_lane
        && ready_done == tasks_per_lane;

    // Total worker dispatch counts.
    let total_cancel: u64 = worker_metrics.iter().map(|m| m.cancel_dispatches).sum();
    let total_timed: u64 = worker_metrics.iter().map(|m| m.timed_dispatches).sum();
    let total_ready: u64 = worker_metrics.iter().map(|m| m.ready_dispatches).sum();

    let artifact = serde_json::json!({
        "test": test_name,
        "seed": seed,
        "num_workers": num_workers,
        "tasks_per_lane": tasks_per_lane,
        "total_tasks_spawned": tasks_per_lane * 3,
        "lock_metrics": snapshot_to_json(&lock_snapshot),
        "worker_metrics": preemption_metrics_to_json(&worker_metrics),
        "dispatch_totals": {
            "cancel": total_cancel,
            "timed": total_timed,
            "ready": total_ready,
        },
        "oracle": {
            "all_tasks_completed": oracle_pass,
            "cancel_completed": cancel_done,
            "timed_completed": timed_done,
            "ready_completed": ready_done,
            "remaining_task_records": total_tasks,
        },
    });

    tracing::info!(
        test = %test_name,
        workers = num_workers,
        tasks_per_lane = tasks_per_lane,
        acquisitions = lock_snapshot.acquisitions,
        contentions = lock_snapshot.contentions,
        wait_ns = lock_snapshot.wait_ns,
        hold_ns = lock_snapshot.hold_ns,
        oracle_pass = oracle_pass,
        "contention harness result"
    );

    assert!(oracle_pass, "Oracle failed: not all tasks completed. cancel={cancel_done}/{tasks_per_lane} timed={timed_done}/{tasks_per_lane} ready={ready_done}/{tasks_per_lane}");

    artifact
}

// ===========================================================================
// TESTS
// ===========================================================================

#[test]
fn contention_2_workers_50_tasks() {
    let artifact = run_mixed_workload("contention_2w_50t", 2, 50, DEFAULT_SEED);
    write_artifact("contention_2w_50t.json", &artifact);
}

#[test]
fn contention_4_workers_100_tasks() {
    let artifact = run_mixed_workload("contention_4w_100t", 4, 100, DEFAULT_SEED);
    write_artifact("contention_4w_100t.json", &artifact);
}

#[test]
fn contention_8_workers_200_tasks() {
    let artifact = run_mixed_workload("contention_8w_200t", 8, 200, DEFAULT_SEED);
    write_artifact("contention_8w_200t.json", &artifact);
}

/// High-contention scenario: many workers, few tasks.
#[test]
fn contention_high_workers_low_tasks() {
    let artifact = run_mixed_workload("contention_8w_10t", 8, 10, DEFAULT_SEED);
    write_artifact("contention_8w_10t.json", &artifact);
}

/// Single-worker baseline (no real contention expected).
#[test]
fn contention_single_worker_baseline() {
    let artifact = run_mixed_workload("contention_1w_50t", 1, 50, DEFAULT_SEED);
    write_artifact("contention_1w_50t.json", &artifact);
}

/// Exercises region create/task spawn paths under contention (simpler than obligations).
#[test]
fn contention_task_spawn_lifecycle() {
    init_test_logging();

    let state = setup_state();
    state.reset_metrics();

    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);
    let done = Arc::new(AtomicUsize::new(0));

    // Multiple threads concurrently spawn tasks.
    let num_threads = 4;
    let tasks_per_thread = 50;

    let mut handles = Vec::new();
    for _ in 0..num_threads {
        let state = Arc::clone(&state);
        let done = Arc::clone(&done);
        handles.push(std::thread::spawn(move || {
            for _ in 0..tasks_per_thread {
                let mut guard = state.lock().unwrap();
                let task_result = guard.create_task(region, Budget::INFINITE, async {});
                if task_result.is_ok() {
                    done.fetch_add(1, Ordering::SeqCst);
                }
                drop(guard);
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }

    let lock_snapshot = state.snapshot();
    let completed = done.load(Ordering::SeqCst);

    let artifact = serde_json::json!({
        "test": "contention_task_spawn_lifecycle",
        "num_threads": num_threads,
        "tasks_per_thread": tasks_per_thread,
        "total_completed": completed,
        "lock_metrics": snapshot_to_json(&lock_snapshot),
        "oracle": {
            "all_completed": completed == num_threads * tasks_per_thread,
        },
    });

    tracing::info!(
        completed = completed,
        acquisitions = lock_snapshot.acquisitions,
        contentions = lock_snapshot.contentions,
        "task spawn lifecycle contention"
    );

    write_artifact("contention_task_spawn_lifecycle.json", &artifact);

    assert_eq!(
        completed,
        num_threads * tasks_per_thread,
        "not all task spawns completed"
    );
}

/// Exercises region create paths under contention.
#[test]
fn contention_region_lifecycle() {
    init_test_logging();

    let state = setup_state();
    let root = state.lock().unwrap().create_root_region(Budget::INFINITE);
    state.reset_metrics();

    let num_threads = 4;
    let regions_per_thread = 25;
    let done = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..num_threads {
        let state = Arc::clone(&state);
        let done = Arc::clone(&done);
        handles.push(std::thread::spawn(move || {
            for _ in 0..regions_per_thread {
                let child = {
                    let mut guard = state.lock().unwrap();
                    guard.create_child_region(root, Budget::INFINITE)
                };
                if child.is_ok() {
                    done.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }

    let lock_snapshot = state.snapshot();
    let completed = done.load(Ordering::SeqCst);

    let artifact = serde_json::json!({
        "test": "contention_region_lifecycle",
        "num_threads": num_threads,
        "regions_per_thread": regions_per_thread,
        "total_completed": completed,
        "lock_metrics": snapshot_to_json(&lock_snapshot),
        "oracle": {
            "all_completed": completed == num_threads * regions_per_thread,
        },
    });

    tracing::info!(
        completed = completed,
        acquisitions = lock_snapshot.acquisitions,
        contentions = lock_snapshot.contentions,
        "region lifecycle contention"
    );

    write_artifact("contention_region_lifecycle.json", &artifact);

    assert_eq!(
        completed,
        num_threads * regions_per_thread,
        "not all region cycles completed"
    );
}

/// Combined harness: runs all scenarios and emits a single summary artifact.
#[test]
fn contention_combined_summary() {
    let scenarios = vec![
        run_mixed_workload("1w_50t", 1, 50, DEFAULT_SEED),
        run_mixed_workload("2w_50t", 2, 50, DEFAULT_SEED),
        run_mixed_workload("4w_100t", 4, 100, DEFAULT_SEED),
        run_mixed_workload("8w_200t", 8, 200, DEFAULT_SEED),
    ];

    let summary = serde_json::json!({
        "harness": "contention_e2e",
        "seed": DEFAULT_SEED,
        "scenarios": scenarios,
    });

    write_artifact("contention_combined_summary.json", &summary);
}
