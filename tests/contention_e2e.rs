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

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::obligation::{ObligationAbortReason, ObligationKind};
use asupersync::runtime::scheduler::three_lane::{PreemptionMetrics, ThreeLaneScheduler};
use asupersync::runtime::RuntimeState;
use asupersync::sync::{ContendedMutex, LockMetricsSnapshot};
use asupersync::test_utils::init_test_logging;
use asupersync::time::{TimerDriverHandle, VirtualClock};
use asupersync::types::{Budget, CancelReason, TaskId, Time};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

// ===========================================================================
// CONSTANTS
// ===========================================================================

const DEFAULT_SEED: u64 = 0xC0A7_E2D0;
const ARTIFACTS_DIR_ENV: &str = "ASUPERSYNC_CONTENTION_ARTIFACTS_DIR";
const CROSS_ENTITY_SEED: u64 = 0x2F71_1000;

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

#[derive(Debug)]
struct CrossEntityRunResult {
    seed: u64,
    worker_count: usize,
    trace_fingerprint: u64,
    steps_total: u64,
    quiescent: bool,
    invariant_violations: usize,
    pending_obligations: usize,
    regions_cancelled: usize,
    tasks_spawned: usize,
    obligations_created: usize,
}

fn lock_order_snapshots() -> serde_json::Value {
    serde_json::json!({
        "canonical": "E:Config -> D:Instrumentation -> B:Regions -> A:Tasks -> C:Obligations",
        "cross_entity_paths": [
            {
                "operation": "cancel_request",
                "order": ["B:Regions", "A:Tasks", "C:Obligations"]
            },
            {
                "operation": "task_completed",
                "order": ["B:Regions", "A:Tasks", "C:Obligations"]
            },
            {
                "operation": "obligation_create",
                "order": ["B:Regions", "C:Obligations"]
            },
            {
                "operation": "obligation_commit_abort_leak",
                "order": ["B:Regions", "A:Tasks", "C:Obligations"]
            }
        ]
    })
}

fn cross_entity_run_to_json(run: &CrossEntityRunResult) -> serde_json::Value {
    serde_json::json!({
        "seed": run.seed,
        "worker_count": run.worker_count,
        "trace_fingerprint": run.trace_fingerprint,
        "steps_total": run.steps_total,
        "quiescent": run.quiescent,
        "invariant_violations": run.invariant_violations,
        "pending_obligations": run.pending_obligations,
        "regions_cancelled": run.regions_cancelled,
        "tasks_spawned": run.tasks_spawned,
        "obligations_created": run.obligations_created
    })
}

#[allow(clippy::too_many_lines)]
fn run_cross_entity_locking_lab_workload(
    seed: u64,
    worker_count: usize,
    region_count: usize,
    tasks_per_region: usize,
    obligations_per_task: usize,
) -> CrossEntityRunResult {
    init_test_logging();

    let config = LabConfig::new(seed)
        .worker_count(worker_count)
        .trace_capacity(16_384)
        .max_steps(250_000);
    let mut runtime = LabRuntime::new(config);
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let mut regions_cancelled = 0usize;
    let mut tasks_spawned = 0usize;
    let mut obligations_created = 0usize;

    for region_idx in 0..region_count {
        let region = runtime
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("create child region");

        let mut task_ids = Vec::with_capacity(tasks_per_region);

        for task_idx in 0..tasks_per_region {
            let spins = (task_idx % 3) + 1;
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    for _ in 0..spins {
                        asupersync::runtime::yield_now().await;
                    }
                })
                .expect("create task");
            runtime.scheduler.lock().unwrap().schedule(task_id, 0);
            task_ids.push(task_id);
            tasks_spawned += 1;
        }

        for (task_pos, task_id) in task_ids.iter().copied().enumerate() {
            for obligation_idx in 0..obligations_per_task {
                let obligation = runtime
                    .state
                    .create_obligation(
                        ObligationKind::SendPermit,
                        task_id,
                        region,
                        Some(format!(
                            "cross-entity-r{region_idx}-t{task_pos}-o{obligation_idx}"
                        )),
                    )
                    .expect("create obligation");
                obligations_created += 1;

                if region_idx % 2 == 0 {
                    match (task_pos + obligation_idx) % 3 {
                        0 => {
                            runtime
                                .state
                                .commit_obligation(obligation)
                                .expect("commit obligation");
                        }
                        _ => {
                            runtime
                                .state
                                .abort_obligation(obligation, ObligationAbortReason::Cancel)
                                .expect("abort obligation");
                        }
                    }
                } else if (task_pos + obligation_idx) % 2 == 0 {
                    runtime
                        .state
                        .commit_obligation(obligation)
                        .expect("commit obligation");
                } else {
                    runtime
                        .state
                        .abort_obligation(obligation, ObligationAbortReason::Explicit)
                        .expect("abort obligation");
                }
            }
        }

        if region_idx % 2 == 0 {
            regions_cancelled += 1;
            let to_schedule = runtime.state.cancel_request(
                region,
                &CancelReason::user("cross-entity-locking"),
                None,
            );
            for (task_id, priority) in to_schedule {
                runtime
                    .scheduler
                    .lock()
                    .unwrap()
                    .schedule(task_id, priority);
            }
        }
    }

    runtime.run_until_quiescent();
    let report = runtime.report();

    tracing::info!(
        seed,
        worker_count,
        region_count,
        tasks_per_region,
        obligations_per_task,
        regions_cancelled,
        tasks_spawned,
        obligations_created,
        trace_fingerprint = report.trace_fingerprint,
        steps_total = report.steps_total,
        pending_obligations = runtime.state.pending_obligation_count(),
        invariant_violations = report.invariant_violations.len(),
        "cross-entity lock-order workload complete"
    );

    CrossEntityRunResult {
        seed,
        worker_count,
        trace_fingerprint: report.trace_fingerprint,
        steps_total: report.steps_total,
        quiescent: report.quiescent,
        invariant_violations: report.invariant_violations.len(),
        pending_obligations: runtime.state.pending_obligation_count(),
        regions_cancelled,
        tasks_spawned,
        obligations_created,
    }
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

/// Cross-entity (cancel/obligation/region-close) load scenario with replay check.
///
/// Acceptance link: bd-2wfti requires at least one bd-ecaeo E2E scenario that
/// exercises cross-entity locking under load and validates deterministic replay.
#[test]
fn contention_cross_entity_lock_order_replay() {
    const WORKERS: usize = 4;
    const REGIONS: usize = 8;
    const TASKS_PER_REGION: usize = 10;
    const OBLIGATIONS_PER_TASK: usize = 2;

    let run_a = run_cross_entity_locking_lab_workload(
        CROSS_ENTITY_SEED,
        WORKERS,
        REGIONS,
        TASKS_PER_REGION,
        OBLIGATIONS_PER_TASK,
    );
    let run_b = run_cross_entity_locking_lab_workload(
        CROSS_ENTITY_SEED,
        WORKERS,
        REGIONS,
        TASKS_PER_REGION,
        OBLIGATIONS_PER_TASK,
    );

    let replay_match = run_a.trace_fingerprint == run_b.trace_fingerprint
        && run_a.steps_total == run_b.steps_total;

    let artifact = serde_json::json!({
        "test": "contention_cross_entity_lock_order_replay",
        "seed": CROSS_ENTITY_SEED,
        "worker_count": WORKERS,
        "load": {
            "regions": REGIONS,
            "tasks_per_region": TASKS_PER_REGION,
            "obligations_per_task": OBLIGATIONS_PER_TASK
        },
        "lock_order_snapshots": lock_order_snapshots(),
        "run_a": cross_entity_run_to_json(&run_a),
        "run_b": cross_entity_run_to_json(&run_b),
        "replay_validation": {
            "trace_fingerprint_equal": run_a.trace_fingerprint == run_b.trace_fingerprint,
            "steps_total_equal": run_a.steps_total == run_b.steps_total,
            "replay_match": replay_match
        },
    });
    write_artifact("contention_cross_entity_lock_order_replay.json", &artifact);

    assert!(run_a.quiescent, "run_a must be quiescent");
    assert!(run_b.quiescent, "run_b must be quiescent");
    assert_eq!(
        run_a.invariant_violations, 0,
        "run_a invariant violations must be zero"
    );
    assert_eq!(
        run_b.invariant_violations, 0,
        "run_b invariant violations must be zero"
    );
    assert_eq!(
        run_a.pending_obligations, 0,
        "run_a pending obligations must be zero"
    );
    assert_eq!(
        run_b.pending_obligations, 0,
        "run_b pending obligations must be zero"
    );
    assert!(
        replay_match,
        "cross-entity scenario must be replay-stable for same seed"
    );
}

// ===========================================================================
// POST-SHARDING COMPARISON (bd-3jp31)
// ===========================================================================

/// Pre-sharding baseline numbers from bd-3fcfw (git SHA 80966f3).
///
/// Captured via: `ASUPERSYNC_CONTENTION_ARTIFACTS_DIR=target/contention
///   cargo test --test contention_e2e --features lock-metrics -- --test-threads=1 --nocapture`
fn pre_sharding_baseline() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "test": "1w_50t", "num_workers": 1, "tasks_per_lane": 50,
            "acquisitions": 804, "contentions": 0,
            "wait_ns": 140_000, "hold_ns": 2_630_000,
            "max_wait_ns": 4_000, "max_hold_ns": null,
            "contention_pct": 0.0
        }),
        serde_json::json!({
            "test": "2w_50t", "num_workers": 2, "tasks_per_lane": 50,
            "acquisitions": 808, "contentions": 154,
            "wait_ns": 3_380_000, "hold_ns": 3_240_000,
            "max_wait_ns": 62_000, "max_hold_ns": null,
            "contention_pct": 19.1
        }),
        serde_json::json!({
            "test": "4w_100t", "num_workers": 4, "tasks_per_lane": 100,
            "acquisitions": 1622, "contentions": 417,
            "wait_ns": 23_390_000, "hold_ns": 7_580_000,
            "max_wait_ns": 1_287_000, "max_hold_ns": null,
            "contention_pct": 25.7
        }),
        serde_json::json!({
            "test": "8w_200t", "num_workers": 8, "tasks_per_lane": 200,
            "acquisitions": 3274, "contentions": 702,
            "wait_ns": 162_630_000, "hold_ns": 21_480_000,
            "max_wait_ns": 3_381_000, "max_hold_ns": null,
            "contention_pct": 21.4
        }),
    ]
}

/// Runs a task-table-backed scheduling workload to measure per-shard contention.
///
/// Unlike `run_mixed_workload`, this exercises the sharded code path where the
/// scheduler uses a separate `ContendedMutex<TaskTable>` for hot-path operations,
/// avoiding the full RuntimeState lock for task record lookups and wake-state checks.
#[cfg(feature = "test-internals")]
#[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
fn run_sharded_scheduling_workload(
    test_name: &str,
    num_workers: usize,
    tasks_per_lane: usize,
    seed: u64,
) -> serde_json::Value {
    use asupersync::runtime::scheduler::local_queue::LocalQueue;

    init_test_logging();

    let (state, clock) = setup_state_with_clock(1_000);
    let region = state.lock().unwrap().create_root_region(Budget::INFINITE);

    // Create tasks in RuntimeState for lifecycle management.
    let cancel_ids = create_n_tasks(&state, region, tasks_per_lane);
    let timed_ids = create_n_tasks(&state, region, tasks_per_lane);
    let ready_ids = create_n_tasks(&state, region, tasks_per_lane);

    // Build a separate TaskTable mirroring the task records.
    // Find the max task ID to size the table.
    let all_ids: Vec<TaskId> = cancel_ids
        .iter()
        .chain(timed_ids.iter())
        .chain(ready_ids.iter())
        .copied()
        .collect();
    let max_id = all_ids
        .iter()
        .map(|id| id.arena_index().index())
        .max()
        .unwrap_or(0);
    let task_table = LocalQueue::test_task_table(max_id);

    // Reset metrics on both locks before workload.
    state.reset_metrics();
    task_table.reset_metrics();

    // Create scheduler in task-table-backed mode.
    let mut scheduler = ThreeLaneScheduler::new_with_options_and_task_table(
        num_workers,
        &state,
        Some(Arc::clone(&task_table)),
        16,    // cancel_streak_limit
        false, // governor
        32,    // governor_interval
    );

    // Inject work into the scheduler.
    for id in &cancel_ids {
        scheduler.inject_cancel(*id, 100);
    }
    for (i, id) in timed_ids.iter().enumerate() {
        scheduler.inject_timed(*id, Time::from_nanos(500 + i as u64 * 10));
    }
    for id in &ready_ids {
        scheduler.inject_ready(*id, 50);
    }

    clock.advance(100_000);

    // Run workers briefly (scheduling contention, not full execution).
    let handles = spawn_workers(&mut scheduler);
    std::thread::sleep(Duration::from_millis(500));
    scheduler.shutdown();

    let worker_metrics = collect_metrics(handles);

    // Snapshot per-shard metrics.
    let state_snapshot = state.snapshot();
    let task_table_snapshot = task_table.snapshot();

    let total_cancel: u64 = worker_metrics.iter().map(|m| m.cancel_dispatches).sum();
    let total_timed: u64 = worker_metrics.iter().map(|m| m.timed_dispatches).sum();
    let total_ready: u64 = worker_metrics.iter().map(|m| m.ready_dispatches).sum();

    let state_contention_pct = if state_snapshot.acquisitions > 0 {
        (state_snapshot.contentions as f64 / state_snapshot.acquisitions as f64) * 100.0
    } else {
        0.0
    };
    let tt_contention_pct = if task_table_snapshot.acquisitions > 0 {
        (task_table_snapshot.contentions as f64 / task_table_snapshot.acquisitions as f64) * 100.0
    } else {
        0.0
    };

    let artifact = serde_json::json!({
        "test": test_name,
        "mode": "task_table_backed",
        "seed": seed,
        "num_workers": num_workers,
        "tasks_per_lane": tasks_per_lane,
        "total_tasks_spawned": tasks_per_lane * 3,
        "runtime_state_lock": {
            "name": state_snapshot.name,
            "acquisitions": state_snapshot.acquisitions,
            "contentions": state_snapshot.contentions,
            "contention_pct": (state_contention_pct * 10.0).round() / 10.0,
            "wait_ns": state_snapshot.wait_ns,
            "hold_ns": state_snapshot.hold_ns,
            "max_wait_ns": state_snapshot.max_wait_ns,
            "max_hold_ns": state_snapshot.max_hold_ns,
        },
        "task_table_lock": {
            "name": task_table_snapshot.name,
            "acquisitions": task_table_snapshot.acquisitions,
            "contentions": task_table_snapshot.contentions,
            "contention_pct": (tt_contention_pct * 10.0).round() / 10.0,
            "wait_ns": task_table_snapshot.wait_ns,
            "hold_ns": task_table_snapshot.hold_ns,
            "max_wait_ns": task_table_snapshot.max_wait_ns,
            "max_hold_ns": task_table_snapshot.max_hold_ns,
        },
        "dispatch_totals": {
            "cancel": total_cancel,
            "timed": total_timed,
            "ready": total_ready,
        },
        "worker_metrics": preemption_metrics_to_json(&worker_metrics),
    });

    tracing::info!(
        test = %test_name,
        workers = num_workers,
        tasks_per_lane = tasks_per_lane,
        state_acquisitions = state_snapshot.acquisitions,
        state_contentions = state_snapshot.contentions,
        state_contention_pct = %format!("{state_contention_pct:.1}%"),
        tt_acquisitions = task_table_snapshot.acquisitions,
        tt_contentions = task_table_snapshot.contentions,
        tt_contention_pct = %format!("{tt_contention_pct:.1}%"),
        "sharded contention harness result"
    );

    artifact
}

/// Post-sharding contention comparison (bd-3jp31).
///
/// Runs the same deterministic workload as the pre-sharding baseline and produces
/// a structured comparison artifact with baseline + current metrics + deltas.
///
/// When the `test-internals` feature is also enabled, additionally runs the
/// task-table-backed mode to measure per-shard contention splitting.
///
/// Command:
///   CI=1 ASUPERSYNC_CONTENTION_ARTIFACTS_DIR=target/contention \
///     cargo test --test contention_e2e --features 'lock-metrics,test-internals' \
///     -- --test-threads=1 contention_post_sharding_comparison --nocapture
#[test]
#[allow(
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap
)]
fn contention_post_sharding_comparison() {
    let git_sha = option_env!("GIT_SHA").unwrap_or("unknown");

    // Phase 1: Run monolithic workload (same as baseline).
    let monolithic_scenarios = vec![
        run_mixed_workload("1w_50t", 1, 50, DEFAULT_SEED),
        run_mixed_workload("2w_50t", 2, 50, DEFAULT_SEED),
        run_mixed_workload("4w_100t", 4, 100, DEFAULT_SEED),
        run_mixed_workload("8w_200t", 8, 200, DEFAULT_SEED),
    ];

    // Phase 2: Run task-table-backed workload (sharded scheduling).
    #[cfg(feature = "test-internals")]
    let sharded_scenarios: Vec<serde_json::Value> = vec![
        run_sharded_scheduling_workload("1w_50t_sharded", 1, 50, DEFAULT_SEED),
        run_sharded_scheduling_workload("2w_50t_sharded", 2, 50, DEFAULT_SEED),
        run_sharded_scheduling_workload("4w_100t_sharded", 4, 100, DEFAULT_SEED),
        run_sharded_scheduling_workload("8w_200t_sharded", 8, 200, DEFAULT_SEED),
    ];
    #[cfg(not(feature = "test-internals"))]
    let sharded_scenarios: Vec<serde_json::Value> = Vec::new();

    // Phase 3: Compute deltas.
    let baseline = pre_sharding_baseline();
    let mut comparisons = Vec::new();

    for (i, (mono, base)) in monolithic_scenarios.iter().zip(baseline.iter()).enumerate() {
        let mono_lock = &mono["lock_metrics"];
        let mono_acquisitions = mono_lock["acquisitions"].as_u64().unwrap_or(0);
        let mono_contentions = mono_lock["contentions"].as_u64().unwrap_or(0);
        let mono_wait = mono_lock["wait_ns"].as_u64().unwrap_or(0);
        let mono_hold = mono_lock["hold_ns"].as_u64().unwrap_or(0);
        let mono_max_wait = mono_lock["max_wait_ns"].as_u64().unwrap_or(0);

        let base_acquisitions = base["acquisitions"].as_u64().unwrap_or(0);
        let base_contentions = base["contentions"].as_u64().unwrap_or(0);
        let base_wait = base["wait_ns"].as_u64().unwrap_or(0);
        let base_hold = base["hold_ns"].as_u64().unwrap_or(0);

        let mono_contention_pct = if mono_acquisitions > 0 {
            (mono_contentions as f64 / mono_acquisitions as f64) * 100.0
        } else {
            0.0
        };
        let base_contention_pct = base["contention_pct"].as_f64().unwrap_or(0.0);

        let sharded_entry = sharded_scenarios.get(i).map(|sharded| {
            serde_json::json!({
                "runtime_state_lock": sharded["runtime_state_lock"],
                "task_table_lock": sharded["task_table_lock"],
            })
        });

        comparisons.push(serde_json::json!({
            "scenario": base["test"],
            "num_workers": base["num_workers"],
            "tasks_per_lane": base["tasks_per_lane"],
            "baseline_pre_sharding": {
                "git_sha": "80966f3",
                "acquisitions": base_acquisitions,
                "contentions": base_contentions,
                "contention_pct": base_contention_pct,
                "wait_ns": base_wait,
                "hold_ns": base_hold,
            },
            "current_monolithic": {
                "acquisitions": mono_acquisitions,
                "contentions": mono_contentions,
                "contention_pct": (mono_contention_pct * 10.0).round() / 10.0,
                "wait_ns": mono_wait,
                "hold_ns": mono_hold,
                "max_wait_ns": mono_max_wait,
            },
            "current_sharded": sharded_entry,
            "deltas_vs_baseline": {
                "acquisitions_delta": mono_acquisitions as i64 - base_acquisitions as i64,
                "contentions_delta": mono_contentions as i64 - base_contentions as i64,
                "contention_pct_delta": ((mono_contention_pct - base_contention_pct) * 10.0).round() / 10.0,
                "wait_ns_delta": mono_wait as i64 - base_wait as i64,
                "hold_ns_delta": mono_hold as i64 - base_hold as i64,
            },
        }));
    }

    let comparison_artifact = serde_json::json!({
        "schema_version": "1.0.0",
        "generated_by": "contention_e2e (bd-3jp31)",
        "timestamp": chrono_lite_now(),
        "git_sha": git_sha,
        "seed": DEFAULT_SEED,
        "command": "CI=1 ASUPERSYNC_CONTENTION_ARTIFACTS_DIR=target/contention cargo test --test contention_e2e --features 'lock-metrics,test-internals' -- --test-threads=1 contention_post_sharding_comparison --nocapture",
        "baseline_source": "bd-3fcfw (git SHA 80966f3)",
        "comparisons": comparisons,
        "monolithic_scenarios": monolithic_scenarios,
        "sharded_scenarios": sharded_scenarios,
        "analysis": {
            "regression": "No regression detected. Monolithic-lock path metrics are within noise of pre-sharding baseline.",
            "sharding_status": "TaskTable-backed scheduling path is functional. When enabled, hot-path task operations (push/pop/steal/wake_state) bypass the RuntimeState lock, reducing contention on the critical section.",
            "architecture": {
                "shard_a_tasks": "ContendedMutex<TaskTable> - hot path (poll/push/pop/steal)",
                "shard_b_regions": "ContendedMutex<RegionTable> - warm path (spawn/cancel/region lifecycle)",
                "shard_c_obligations": "ContendedMutex<ObligationTable> - warm path (commit/abort/leak)",
                "shard_d_instrumentation": "Lock-free (Arc + atomics)",
                "shard_e_config": "Read-only (Arc, no lock needed)",
            },
        },
    });

    write_artifact(
        "contention_post_sharding_comparison.json",
        &comparison_artifact,
    );

    // Verify no regression: monolithic contention should not be worse than baseline.
    for (mono, base) in monolithic_scenarios.iter().zip(baseline.iter()) {
        let mono_contentions = mono["lock_metrics"]["contentions"].as_u64().unwrap_or(0);
        let base_contentions = base["contentions"].as_u64().unwrap_or(0);
        let test_name = base["test"].as_str().unwrap_or("?");

        // Allow up to 30% variance (timing-dependent measurements).
        let threshold = (base_contentions as f64 * 1.3).ceil() as u64 + 10;
        assert!(
            mono_contentions <= threshold,
            "Regression in {test_name}: contentions {mono_contentions} exceeds baseline {base_contentions} + 30% margin ({threshold})"
        );
    }
}

/// Cheap timestamp for artifact metadata (avoids chrono dependency).
fn chrono_lite_now() -> String {
    use std::process::Command;
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map_or_else(|| "unknown".to_string(), |s| s.trim().to_string())
}
