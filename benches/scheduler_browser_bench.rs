//! Browser scheduler benchmark suite for Asupersync.
//!
//! Benchmarks browser-specific scheduling features:
//! - Ready handoff overhead at various burst limits
//! - Browser profile throughput (single-worker, no parking, handoff enabled)
//! - Mixed-lane dispatch under browser configuration
//! - Cancel preemption latency in browser mode
//!
//! Run:
//!   cargo bench --bench scheduler_browser_bench
//!
//! These benchmarks complement the general scheduler_benchmark.rs suite
//! by focusing on the browser event-loop adapter constraints.

#![allow(missing_docs)]
#![allow(clippy::semicolon_if_nothing_returned)]

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use asupersync::record::task::TaskRecord;
use asupersync::runtime::RuntimeState;
use asupersync::runtime::scheduler::{Scheduler, ThreeLaneScheduler};
use asupersync::sync::ContendedMutex;
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use std::sync::Arc;

// =============================================================================
// HELPERS
// =============================================================================

fn task(id: u32) -> TaskId {
    TaskId::new_for_test(id, 0)
}

fn region() -> RegionId {
    RegionId::from_arena(ArenaIndex::new(0, 0))
}

fn setup_runtime_state(max_task_id: u32) -> Arc<ContendedMutex<RuntimeState>> {
    let mut state = RuntimeState::new();
    for i in 0..=max_task_id {
        let id = task(i);
        let record = TaskRecord::new(id, region(), Budget::INFINITE);
        let idx = state.tasks.insert(record);
        assert_eq!(idx.index(), i);
    }
    Arc::new(ContendedMutex::new("runtime_state", state))
}

// =============================================================================
// BROWSER READY HANDOFF BENCHMARKS
// =============================================================================

/// Measures the overhead of the browser ready-handoff mechanism at
/// various burst limits. Quantifies the yield cost as a function of
/// the `browser_ready_handoff_limit` setting.
fn bench_browser_ready_handoff(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/browser_ready_handoff");

    // Ready handoff yield overhead: measures dispatch throughput with
    // handoff enabled at various limits.
    for &limit in &[4usize, 8, 16, 32, 64] {
        let task_count = 256u32;
        group.throughput(Throughput::Elements(u64::from(task_count)));
        group.bench_with_input(
            BenchmarkId::new("ready_burst_with_handoff", limit),
            &limit,
            |b, &limit| {
                b.iter_batched(
                    || {
                        let state = setup_runtime_state(task_count);
                        let mut sched = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 16);
                        sched.set_browser_ready_handoff_limit(limit);
                        for i in 0..task_count {
                            sched.inject_ready(task(i), 50);
                        }
                        sched
                    },
                    |mut sched| {
                        let mut workers = sched.take_workers().into_iter();
                        let mut worker = workers.next().unwrap();
                        let mut dispatched = 0u64;
                        // Keep polling until all tasks dispatched.
                        // Worker returns None on handoff yield; we re-enter.
                        loop {
                            match worker.next_task() {
                                Some(_) => dispatched += 1,
                                None => {
                                    if dispatched >= u64::from(task_count) {
                                        break;
                                    }
                                    // Handoff yield - re-enter worker loop
                                    // (simulates browser event loop returning control)
                                    continue;
                                }
                            }
                        }
                        black_box(dispatched)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // Baseline: no handoff (limit=0)
    {
        let task_count = 256u32;
        group.throughput(Throughput::Elements(u64::from(task_count)));
        group.bench_function("ready_burst_no_handoff", |b| {
            b.iter_batched(
                || {
                    let state = setup_runtime_state(task_count);
                    let sched = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 16);
                    // browser_ready_handoff_limit defaults to 0 (disabled)
                    for i in 0..task_count {
                        sched.inject_ready(task(i), 50);
                    }
                    sched
                },
                |mut sched| {
                    let mut workers = sched.take_workers().into_iter();
                    let mut worker = workers.next().unwrap();
                    let mut dispatched = 0u64;
                    while worker.next_task().is_some() {
                        dispatched += 1;
                    }
                    black_box(dispatched)
                },
                BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

// =============================================================================
// BROWSER PROFILE THROUGHPUT
// =============================================================================

/// Full browser profile: single-worker, handoff enabled, cancel+ready mixed.
/// Models a realistic browser event-loop workload.
fn bench_browser_profile_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/browser_profile");
    group.sample_size(50);

    // Realistic browser workload: mostly ready tasks with periodic cancel
    // and timed work, handoff limit active.
    for &(ready_n, cancel_n, timed_n) in &[(100u32, 10u32, 5u32), (500, 50, 25), (1000, 100, 50)] {
        let total = ready_n + cancel_n + timed_n;
        group.throughput(Throughput::Elements(u64::from(total)));
        group.bench_with_input(
            BenchmarkId::new("mixed_workload", total),
            &(ready_n, cancel_n, timed_n),
            |b, &(ready_n, cancel_n, timed_n)| {
                b.iter_batched(
                    || {
                        let total = ready_n + cancel_n + timed_n;
                        let state = setup_runtime_state(total);
                        let mut sched = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 16);
                        sched.set_browser_ready_handoff_limit(32);

                        let mut id = 0u32;
                        for _ in 0..cancel_n {
                            sched.inject_cancel(task(id), 100);
                            id += 1;
                        }
                        for _ in 0..timed_n {
                            sched.inject_ready(task(id), 50);
                            id += 1;
                        }
                        for _ in 0..ready_n {
                            sched.inject_ready(task(id), 30);
                            id += 1;
                        }
                        sched
                    },
                    |mut sched| {
                        let mut workers = sched.take_workers().into_iter();
                        let mut worker = workers.next().unwrap();
                        let mut dispatched = 0u64;
                        loop {
                            match worker.next_task() {
                                Some(_) => dispatched += 1,
                                None => break,
                            }
                        }
                        black_box(dispatched)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// =============================================================================
// CANCEL PREEMPTION UNDER BROWSER MODE
// =============================================================================

/// Measures cancel dispatch latency when browser ready-handoff is active.
/// Verifies that handoff yields do not interfere with cancel priority.
fn bench_browser_cancel_preemption(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/browser_cancel_preemption");

    // Cancel-only dispatch with handoff enabled (should not trigger yields
    // since there's no ready work to yield to).
    for &count in &[100u64, 1000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("cancel_only_with_handoff", count),
            &count,
            |b, &count| {
                b.iter_batched(
                    || {
                        let state = setup_runtime_state(count as u32);
                        let mut sched = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 16);
                        sched.set_browser_ready_handoff_limit(8);
                        for i in 0..count as u32 {
                            sched.inject_cancel(task(i), 100);
                        }
                        sched
                    },
                    |mut sched| {
                        let mut workers = sched.take_workers().into_iter();
                        let mut worker = workers.next().unwrap();
                        let mut dispatched = 0u64;
                        while worker.next_task().is_some() {
                            dispatched += 1;
                        }
                        black_box(dispatched)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // Ready stall depth with handoff: how quickly does a ready task
    // get dispatched when cancel work dominates and handoff is active?
    for &handoff_limit in &[4usize, 16, 64] {
        let cancel_n = 50u32;
        group.bench_with_input(
            BenchmarkId::new("ready_stall_depth_with_handoff", handoff_limit),
            &handoff_limit,
            |b, &handoff_limit| {
                b.iter_batched(
                    || {
                        let state = setup_runtime_state(cancel_n + 1);
                        let mut sched = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 8);
                        sched.set_browser_ready_handoff_limit(handoff_limit);
                        for i in 0..cancel_n {
                            sched.inject_cancel(task(i), 100);
                        }
                        sched.inject_ready(task(cancel_n), 50);
                        sched
                    },
                    |mut sched| {
                        let mut workers = sched.take_workers().into_iter();
                        let mut worker = workers.next().unwrap();
                        let ready_id = task(cancel_n);
                        let mut steps = 0u64;
                        loop {
                            steps += 1;
                            match worker.next_task() {
                                Some(dispatched) if dispatched == ready_id => break,
                                Some(_) => {}
                                None => {
                                    // Handoff yield - continue polling
                                    continue;
                                }
                            }
                            if steps > 200 {
                                break;
                            }
                        }
                        black_box(steps)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// =============================================================================
// FAIRNESS CERTIFICATE MEASUREMENT
// =============================================================================

/// Measures the cost of producing fairness metrics under browser config.
/// This benchmarks the overhead of tracking preemption metrics during dispatch.
fn bench_browser_fairness_metrics(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/browser_fairness_metrics");

    // Mixed workload: measure total dispatch with metrics collection
    for &task_count in &[100u64, 500, 2000] {
        group.throughput(Throughput::Elements(task_count));
        group.bench_with_input(
            BenchmarkId::new("metrics_overhead", task_count),
            &task_count,
            |b, &task_count| {
                let cancel_n = (task_count / 5) as u32;
                let ready_n = task_count as u32 - cancel_n;
                b.iter_batched(
                    || {
                        let state = setup_runtime_state(task_count as u32);
                        let mut sched = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 8);
                        sched.set_browser_ready_handoff_limit(16);
                        for i in 0..cancel_n {
                            sched.inject_cancel(task(i), 100);
                        }
                        for i in cancel_n..cancel_n + ready_n {
                            sched.inject_ready(task(i), 50);
                        }
                        sched
                    },
                    |mut sched| {
                        let mut workers = sched.take_workers().into_iter();
                        let mut worker = workers.next().unwrap();
                        let mut dispatched = 0u64;
                        loop {
                            match worker.next_task() {
                                Some(_) => dispatched += 1,
                                None => break,
                            }
                        }
                        let metrics = worker.preemption_metrics().clone();
                        black_box((dispatched, metrics))
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// =============================================================================
// PRIORITY SCHEDULER BROWSER MODE
// =============================================================================

/// Benchmarks the PriorityScheduler in browser-typical workloads
/// (dominated by ready tasks, occasional cancel).
fn bench_browser_priority_scheduler(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/browser_priority");

    // Ready-dominated workload (90% ready, 10% cancel)
    for &count in &[100u64, 1000, 5000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("ready_dominated", count),
            &count,
            |b, &count| {
                b.iter(|| {
                    let mut scheduler = Scheduler::new();
                    for i in 0..count as u32 {
                        if i % 10 == 0 {
                            scheduler.schedule_cancel(task(i), 100);
                        } else {
                            scheduler.schedule(task(i), (i % 64) as u8);
                        }
                    }
                    let mut popped = 0u64;
                    while scheduler.pop().is_some() {
                        popped += 1;
                    }
                    black_box(popped)
                })
            },
        );
    }

    // Uniform priority (common browser case: all tasks equal priority)
    for &count in &[100u64, 1000, 5000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("uniform_priority", count),
            &count,
            |b, &count| {
                b.iter(|| {
                    let mut scheduler = Scheduler::new();
                    for i in 0..count as u32 {
                        scheduler.schedule(task(i), 0);
                    }
                    let mut popped = 0u64;
                    while scheduler.pop().is_some() {
                        popped += 1;
                    }
                    black_box(popped)
                })
            },
        );
    }

    group.finish();
}

// =============================================================================
// MAIN
// =============================================================================

criterion_group!(
    benches,
    bench_browser_ready_handoff,
    bench_browser_profile_throughput,
    bench_browser_cancel_preemption,
    bench_browser_fairness_metrics,
    bench_browser_priority_scheduler,
);

criterion_main!(benches);
