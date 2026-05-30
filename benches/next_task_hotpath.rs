//! Focused benchmark for next_task() hot dispatch loop in three_lane.rs
//!
//! This micro-benchmark measures the performance bottlenecks in the core
//! scheduler dispatch loop by testing next_task() in isolation with various
//! queue states and workloads.

#![cfg(feature = "test-internals")]

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;

use asupersync::record::task::TaskRecord;
use asupersync::runtime::RuntimeState;
use asupersync::runtime::scheduler::three_lane::{ThreeLaneScheduler, ThreeLaneWorker};
use asupersync::sync::ContendedMutex;
use asupersync::types::{Budget, RegionId, TaskId, Time};

/// Creates a test TaskId from an index.
fn task(id: u32) -> TaskId {
    TaskId::new_for_test(id, 0)
}

/// Creates a test RegionId.
fn region() -> RegionId {
    RegionId::testing_default()
}

fn setup_runtime_state(task_count: u32) -> Arc<ContendedMutex<RuntimeState>> {
    let mut state = RuntimeState::new();
    for i in 0..task_count {
        let id = task(i);
        let record = TaskRecord::new(id, region(), Budget::INFINITE);
        let idx = state.tasks.insert(record);
        assert_eq!(idx.index(), i);
    }
    Arc::new(ContendedMutex::new("next_task_hotpath_state", state))
}

/// Setup worker with various queue states for benchmarking
fn setup_worker_with_tasks(
    ready_tasks: u32,
    cancel_tasks: u32,
    timed_tasks: u32,
) -> ThreeLaneWorker {
    let task_count = ready_tasks + cancel_tasks + timed_tasks;
    let runtime_state = setup_runtime_state(task_count);
    let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &runtime_state, 16);

    // Inject ready tasks
    for i in 0..ready_tasks {
        scheduler.inject_ready(task(i), 50);
    }

    // Inject cancel tasks
    for i in ready_tasks..(ready_tasks + cancel_tasks) {
        scheduler.inject_cancel(task(i), 100);
    }

    // Inject timed tasks at Time::ZERO so they are due under a fresh RuntimeState clock.
    for i in (ready_tasks + cancel_tasks)..(ready_tasks + cancel_tasks + timed_tasks) {
        scheduler.inject_timed(task(i), Time::ZERO);
    }

    scheduler
        .take_workers()
        .into_iter()
        .next()
        .expect("single-worker scheduler should provide one worker")
}

fn bench_next_task_empty_queues(c: &mut Criterion) {
    c.bench_function("next_task/empty_queues", |b| {
        b.iter_batched(
            || setup_worker_with_tasks(0, 0, 0),
            |mut worker| {
                let result = worker.next_task();
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_next_task_single_ready(c: &mut Criterion) {
    c.bench_function("next_task/single_ready", |b| {
        b.iter_batched(
            || setup_worker_with_tasks(1, 0, 0),
            |mut worker| {
                let result = worker.next_task();
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_next_task_single_cancel(c: &mut Criterion) {
    c.bench_function("next_task/single_cancel", |b| {
        b.iter_batched(
            || setup_worker_with_tasks(0, 1, 0),
            |mut worker| {
                let result = worker.next_task();
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_next_task_single_timed(c: &mut Criterion) {
    c.bench_function("next_task/single_timed", |b| {
        b.iter_batched(
            || setup_worker_with_tasks(0, 0, 1),
            |mut worker| {
                let result = worker.next_task();
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_next_task_mixed_workload(c: &mut Criterion) {
    let mut group = c.benchmark_group("next_task/mixed_workload");

    for &(ready, cancel, timed) in &[(10, 5, 5), (50, 25, 25), (100, 50, 50)] {
        group.bench_with_input(
            BenchmarkId::new("tasks", format!("r{}_c{}_t{}", ready, cancel, timed)),
            &(ready, cancel, timed),
            |b, &(r, c, t)| {
                b.iter_batched(
                    || setup_worker_with_tasks(r, c, t),
                    |mut worker| {
                        let result = worker.next_task();
                        black_box(result)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
    group.finish();
}

fn bench_next_task_dispatch_sequence(c: &mut Criterion) {
    c.bench_function("next_task/dispatch_sequence_10", |b| {
        b.iter_batched(
            || setup_worker_with_tasks(10, 0, 0),
            |mut worker| {
                let mut results = Vec::with_capacity(10);
                for _ in 0..10 {
                    if let Some(task) = worker.next_task() {
                        results.push(task);
                    }
                }
                black_box(results)
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_next_task_cancel_streak_limit(c: &mut Criterion) {
    c.bench_function("next_task/cancel_streak_fairness", |b| {
        b.iter_batched(
            || {
                let mut worker = setup_worker_with_tasks(1, 20, 0); // 1 ready, 20 cancel
                // Fill cancel streak to trigger fairness mechanism
                for _ in 0..15 {
                    let _ = worker.next_task(); // Should consume cancel tasks
                }
                worker
            },
            |mut worker| {
                // This call should trigger fairness yield and dispatch ready task
                let result = worker.next_task();
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    benches,
    bench_next_task_empty_queues,
    bench_next_task_single_ready,
    bench_next_task_single_cancel,
    bench_next_task_single_timed,
    bench_next_task_mixed_workload,
    bench_next_task_dispatch_sequence,
    bench_next_task_cancel_streak_limit,
);

criterion_main!(benches);
