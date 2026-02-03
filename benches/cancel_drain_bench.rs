//! Cancel/drain latency benchmark suite for Asupersync (bd-19rj).
//!
//! Benchmarks the performance of cancellation, drain, and governor operations:
//! - Cancel injection/dispatch through GlobalInjector
//! - Mixed cancel+ready dispatch through PriorityScheduler
//! - Governor suggest() and compute_potential() latency
//! - StateSnapshot construction cost from RuntimeState
//! - Convergence analysis on governor history
//!
//! Performance targets:
//! - Governor suggest(): < 50ns (quiescent fast path)
//! - Potential compute_record(): < 100ns
//! - StateSnapshot construction: < 10µs per 1000 tasks

#![allow(missing_docs)]
#![allow(clippy::semicolon_if_nothing_returned)]

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};

use asupersync::obligation::lyapunov::{LyapunovGovernor, PotentialWeights, StateSnapshot};
use asupersync::record::task::TaskRecord;
use asupersync::runtime::scheduler::{GlobalInjector, Scheduler, ThreeLaneScheduler};
use asupersync::runtime::RuntimeState;
use asupersync::types::{Budget, RegionId, TaskId, Time};
use asupersync::util::ArenaIndex;
use std::sync::{Arc, Mutex};

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

fn task(id: u32) -> TaskId {
    TaskId::new_for_test(id, 0)
}

fn region() -> RegionId {
    RegionId::from_arena(ArenaIndex::new(0, 0))
}

fn setup_runtime_state(max_task_id: u32) -> Arc<Mutex<RuntimeState>> {
    let mut state = RuntimeState::new();
    for i in 0..=max_task_id {
        let id = task(i);
        let record = TaskRecord::new(id, region(), Budget::INFINITE);
        let idx = state.tasks.insert(record);
        assert_eq!(idx.index(), i);
    }
    Arc::new(Mutex::new(state))
}

// =============================================================================
// CANCEL DISPATCH LATENCY
// =============================================================================

/// Benchmarks cancel-lane injection and dispatch through GlobalInjector.
fn bench_cancel_dispatch(c: &mut Criterion) {
    let mut group = c.benchmark_group("cancel_dispatch");

    for &count in &[10u32, 100, 1000] {
        group.throughput(Throughput::Elements(u64::from(count)));

        // Cancel injection + pop through GlobalInjector (raw dispatch path)
        group.bench_with_input(
            BenchmarkId::new("inject_pop_global", count),
            &count,
            |b, &n| {
                b.iter_batched(
                    || {
                        let injector = GlobalInjector::new();
                        for i in 0..n {
                            injector.inject_cancel(task(i), 5);
                        }
                        injector
                    },
                    |injector| {
                        let mut dispatched = 0u32;
                        while injector.pop_cancel().is_some() {
                            dispatched += 1;
                        }
                        black_box(dispatched)
                    },
                    BatchSize::SmallInput,
                )
            },
        );

        // Cancel injection through ThreeLaneScheduler (full path: wake_state
        // notify + GlobalInjector + wake_one)
        group.bench_with_input(
            BenchmarkId::new("inject_via_scheduler", count),
            &count,
            |b, &n| {
                b.iter_batched(
                    || setup_runtime_state(n),
                    |state| {
                        let sched = ThreeLaneScheduler::new(1, &state);
                        for i in 0..n {
                            sched.inject_cancel(task(i), 5);
                        }
                        black_box(())
                    },
                    BatchSize::SmallInput,
                )
            },
        );

        // Cancel injection with governor enabled (measures additional overhead)
        group.bench_with_input(
            BenchmarkId::new("inject_via_scheduler_governor", count),
            &count,
            |b, &n| {
                b.iter_batched(
                    || setup_runtime_state(n),
                    |state| {
                        let sched = ThreeLaneScheduler::new_with_options(1, &state, 16, true, 1);
                        for i in 0..n {
                            sched.inject_cancel(task(i), 5);
                        }
                        black_box(())
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// =============================================================================
// MIXED CANCEL + READY DISPATCH FAIRNESS
// =============================================================================

/// Benchmarks mixed cancel + ready dispatch through PriorityScheduler.
///
/// PriorityScheduler maintains the 3-lane priority ordering (cancel > timed >
/// ready). This measures throughput when both cancel and ready work are present.
fn bench_cancel_ready_mixed(c: &mut Criterion) {
    let mut group = c.benchmark_group("cancel_ready_mixed");

    for &ready_count in &[50u32, 200, 500] {
        let cancel_count = ready_count;
        let total = cancel_count + ready_count;
        group.throughput(Throughput::Elements(u64::from(total)));

        group.bench_with_input(BenchmarkId::new("pop_all", total), &ready_count, |b, &n| {
            b.iter_batched(
                || {
                    let mut sched = Scheduler::new();
                    for i in 0..n {
                        sched.schedule_cancel(task(i), 5);
                    }
                    for i in n..2 * n {
                        sched.schedule(task(i), 3);
                    }
                    sched
                },
                |mut sched| {
                    let mut total = 0u32;
                    while sched.pop().is_some() {
                        total += 1;
                    }
                    black_box(total)
                },
                BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

// =============================================================================
// GOVERNOR SUGGESTION LATENCY
// =============================================================================

/// Benchmarks the Lyapunov governor's suggest() function in isolation,
/// measuring pure decision overhead for different state configurations.
fn bench_governor_suggest(c: &mut Criterion) {
    let mut group = c.benchmark_group("governor_suggest");

    // Quiescent state — fast path (early return)
    group.bench_function("quiescent", |b| {
        let governor = LyapunovGovernor::with_defaults();
        let snapshot = StateSnapshot {
            time: Time::ZERO,
            live_tasks: 0,
            pending_obligations: 0,
            obligation_age_sum_ns: 0,
            draining_regions: 0,
            deadline_pressure: 0.0,
            pending_send_permits: 0,
            pending_acks: 0,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: 0,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: 0,
        };
        b.iter(|| black_box(governor.suggest(black_box(&snapshot))))
    });

    // Obligation-dominated state → DrainObligations
    group.bench_function("obligation_dominated", |b| {
        let governor = LyapunovGovernor::with_defaults();
        let snapshot = StateSnapshot {
            time: Time::ZERO,
            live_tasks: 100,
            pending_obligations: 50,
            obligation_age_sum_ns: 5_000_000_000,
            draining_regions: 2,
            deadline_pressure: 0.5,
            pending_send_permits: 10,
            pending_acks: 20,
            pending_leases: 15,
            pending_io_ops: 5,
            cancel_requested_tasks: 10,
            cancelling_tasks: 5,
            finalizing_tasks: 3,
            ready_queue_depth: 50,
        };
        b.iter(|| black_box(governor.suggest(black_box(&snapshot))))
    });

    // Deadline-dominated state → MeetDeadlines
    group.bench_function("deadline_dominated", |b| {
        let governor = LyapunovGovernor::with_defaults();
        let snapshot = StateSnapshot {
            time: Time::ZERO,
            live_tasks: 100,
            pending_obligations: 5,
            obligation_age_sum_ns: 100_000_000,
            draining_regions: 0,
            deadline_pressure: 50.0,
            pending_send_permits: 0,
            pending_acks: 5,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: 3,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: 80,
        };
        b.iter(|| black_box(governor.suggest(black_box(&snapshot))))
    });

    // Region-drain dominated state → DrainRegions
    group.bench_function("region_drain", |b| {
        let governor = LyapunovGovernor::with_defaults();
        let snapshot = StateSnapshot {
            time: Time::ZERO,
            live_tasks: 50,
            pending_obligations: 10,
            obligation_age_sum_ns: 200_000_000,
            draining_regions: 20,
            deadline_pressure: 1.0,
            pending_send_permits: 3,
            pending_acks: 5,
            pending_leases: 2,
            pending_io_ops: 0,
            cancel_requested_tasks: 15,
            cancelling_tasks: 10,
            finalizing_tasks: 5,
            ready_queue_depth: 20,
        };
        b.iter(|| black_box(governor.suggest(black_box(&snapshot))))
    });

    group.finish();
}

// =============================================================================
// POTENTIAL FUNCTION V(Σ) COMPUTATION
// =============================================================================

/// Benchmarks the Lyapunov potential function computation with different
/// weight configurations.
fn bench_potential_compute(c: &mut Criterion) {
    let mut group = c.benchmark_group("potential_compute");

    let snapshot = StateSnapshot {
        time: Time::ZERO,
        live_tasks: 200,
        pending_obligations: 80,
        obligation_age_sum_ns: 10_000_000_000,
        draining_regions: 5,
        deadline_pressure: 15.0,
        pending_send_permits: 20,
        pending_acks: 30,
        pending_leases: 20,
        pending_io_ops: 10,
        cancel_requested_tasks: 25,
        cancelling_tasks: 10,
        finalizing_tasks: 5,
        ready_queue_depth: 100,
    };

    group.bench_function("default_weights", |b| {
        let governor = LyapunovGovernor::with_defaults();
        b.iter(|| black_box(governor.compute_record(black_box(&snapshot))))
    });

    group.bench_function("uniform_weights", |b| {
        let governor = LyapunovGovernor::new(PotentialWeights::uniform(1.0));
        b.iter(|| black_box(governor.compute_record(black_box(&snapshot))))
    });

    group.bench_function("obligation_focused", |b| {
        let governor = LyapunovGovernor::new(PotentialWeights::obligation_focused());
        b.iter(|| black_box(governor.compute_record(black_box(&snapshot))))
    });

    group.bench_function("deadline_focused", |b| {
        let governor = LyapunovGovernor::new(PotentialWeights::deadline_focused());
        b.iter(|| black_box(governor.compute_record(black_box(&snapshot))))
    });

    group.finish();
}

// =============================================================================
// STATE SNAPSHOT FROM RUNTIMESTATE
// =============================================================================

/// Benchmarks StateSnapshot construction from RuntimeState with varying
/// task counts. This is the amortized cost paid per governor interval.
fn bench_state_snapshot(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_snapshot");

    for &n in &[100u32, 1000, 10000] {
        group.throughput(Throughput::Elements(u64::from(n)));
        group.bench_with_input(BenchmarkId::new("from_runtime_state", n), &n, |b, &n| {
            let state = setup_runtime_state(n);
            b.iter(|| {
                let guard = state.lock().expect("runtime state lock poisoned");
                black_box(StateSnapshot::from_runtime_state(&guard))
            })
        });
    }

    group.finish();
}

// =============================================================================
// CONVERGENCE ANALYSIS
// =============================================================================

/// Benchmarks the convergence analysis on governor history of varying lengths.
///
/// Simulates a monotonically decreasing potential (convergence scenario) and
/// measures the cost of `analyze_convergence()` on the recorded history.
fn bench_convergence_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("convergence_analysis");

    for &steps in &[10u32, 100, 1000] {
        group.bench_with_input(BenchmarkId::new("analyze", steps), &steps, |b, &n| {
            b.iter_batched(
                || {
                    let mut governor = LyapunovGovernor::with_defaults();
                    for i in 0..n {
                        let remaining = n - i;
                        let snapshot = StateSnapshot {
                            time: Time::ZERO,
                            live_tasks: remaining,
                            pending_obligations: remaining / 2,
                            obligation_age_sum_ns: u64::from(remaining) * 100_000_000,
                            draining_regions: remaining / 10,
                            deadline_pressure: f64::from(remaining) * 0.1,
                            pending_send_permits: 0,
                            pending_acks: 0,
                            pending_leases: 0,
                            pending_io_ops: 0,
                            cancel_requested_tasks: remaining / 5,
                            cancelling_tasks: remaining / 10,
                            finalizing_tasks: remaining / 20,
                            ready_queue_depth: remaining,
                        };
                        governor.compute_potential(&snapshot);
                    }
                    governor
                },
                |governor| black_box(governor.analyze_convergence()),
                BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

// =============================================================================
// GOVERNOR OVERHEAD (SUGGEST + POTENTIAL WITH HISTORY)
// =============================================================================

/// Benchmarks the governor overhead under realistic conditions:
/// repeated suggest() calls with history recording.
fn bench_governor_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("governor_overhead");

    let busy_snapshot = StateSnapshot {
        time: Time::ZERO,
        live_tasks: 500,
        pending_obligations: 100,
        obligation_age_sum_ns: 20_000_000_000,
        draining_regions: 10,
        deadline_pressure: 25.0,
        pending_send_permits: 30,
        pending_acks: 40,
        pending_leases: 20,
        pending_io_ops: 10,
        cancel_requested_tasks: 50,
        cancelling_tasks: 20,
        finalizing_tasks: 10,
        ready_queue_depth: 200,
    };

    // suggest() with default weights (pure decision, no recording)
    group.bench_function("suggest_default", |b| {
        let governor = LyapunovGovernor::with_defaults();
        b.iter(|| black_box(governor.suggest(black_box(&busy_snapshot))))
    });

    // suggest() with obligation-focused weights
    group.bench_function("suggest_obligation_focused", |b| {
        let governor = LyapunovGovernor::new(PotentialWeights::obligation_focused());
        b.iter(|| black_box(governor.suggest(black_box(&busy_snapshot))))
    });

    // compute_record() (full breakdown, no history)
    group.bench_function("compute_record", |b| {
        let governor = LyapunovGovernor::with_defaults();
        b.iter(|| black_box(governor.compute_record(black_box(&busy_snapshot))))
    });

    // compute_potential() loop (records to history + convergence check)
    group.bench_function("potential_loop_100_steps", |b| {
        b.iter_batched(
            LyapunovGovernor::with_defaults,
            |mut governor| {
                for _ in 0..100 {
                    governor.compute_potential(&busy_snapshot);
                }
                black_box(governor.analyze_convergence())
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

// =============================================================================
// MAIN
// =============================================================================

criterion_group!(
    benches,
    bench_cancel_dispatch,
    bench_cancel_ready_mixed,
    bench_governor_suggest,
    bench_potential_compute,
    bench_state_snapshot,
    bench_convergence_analysis,
    bench_governor_overhead,
);

criterion_main!(benches);
