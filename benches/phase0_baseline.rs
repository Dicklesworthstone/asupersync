//! Phase 0 baseline benchmarks for Asupersync.
//!
//! These benchmarks establish performance baselines for the Phase 0 kernel:
//! - Core type operations (Outcome, Budget, CancelReason)
//! - Arena operations (insert, get, remove)
//! - Scheduler operations (schedule, pop)
//! - RuntimeState operations (region create, cancel request)
//! - Combinator operations (join, race, timeout)
//! - Lab runtime operations
//!
//! Benchmarks use deterministic inputs (fixed seeds) to ensure reproducibility.

#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use asupersync::combinator::{effective_deadline, join2_outcomes, race2_outcomes, TimeoutConfig};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::{ObligationKind, ObligationRecord, RegionRecord, TaskRecord};
use asupersync::runtime::{RuntimeState, Scheduler};
use asupersync::types::{Budget, CancelKind, CancelReason, ObligationId, Outcome, RegionId, TaskId, Time};
use asupersync::util::{Arena, ArenaIndex};

// =============================================================================
// CORE TYPE BENCHMARKS
// =============================================================================

fn bench_outcome_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("outcome");

    // Benchmark severity comparison
    group.bench_function("severity_ok", |b| {
        let outcome: Outcome<i32, &str> = Outcome::Ok(42);
        b.iter(|| black_box(outcome.severity()))
    });

    group.bench_function("severity_cancelled", |b| {
        let outcome: Outcome<i32, &str> =
            Outcome::Cancelled(CancelReason::new(CancelKind::User));
        b.iter(|| black_box(outcome.severity()))
    });

    // Benchmark outcome aggregation (worst wins)
    group.bench_function("join_ok_ok", |b| {
        let o1: Outcome<(), ()> = Outcome::Ok(());
        let o2: Outcome<(), ()> = Outcome::Ok(());
        b.iter(|| black_box(join2_outcomes(o1.clone(), o2.clone())))
    });

    group.bench_function("join_ok_cancelled", |b| {
        let o1: Outcome<(), ()> = Outcome::Ok(());
        let o2: Outcome<(), ()> = Outcome::Cancelled(CancelReason::new(CancelKind::Timeout));
        b.iter(|| black_box(join2_outcomes(o1.clone(), o2.clone())))
    });

    group.finish();
}

fn bench_budget_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("budget");

    // Benchmark budget creation
    group.bench_function("create_infinite", |b| {
        b.iter(|| black_box(Budget::INFINITE))
    });

    group.bench_function("create_with_deadline", |b| {
        b.iter(|| {
            black_box(
                Budget::new()
                    .with_deadline(Time::from_nanos(1_000_000_000))
                    .with_poll_quota(1000),
            )
        })
    });

    // Benchmark budget combination (product semiring)
    group.bench_function("combine", |b| {
        let b1 = Budget::new()
            .with_deadline(Time::from_nanos(1_000_000_000))
            .with_poll_quota(1000);
        let b2 = Budget::new()
            .with_deadline(Time::from_nanos(500_000_000))
            .with_poll_quota(2000);
        b.iter(|| black_box(b1.combine(b2)))
    });

    group.finish();
}

fn bench_cancel_reason_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("cancel_reason");

    // Benchmark creation
    group.bench_function("create_user", |b| {
        b.iter(|| black_box(CancelReason::new(CancelKind::User)))
    });

    group.bench_function("create_timeout", |b| {
        b.iter(|| black_box(CancelReason::new(CancelKind::Timeout)))
    });

    // Benchmark strengthen (idempotent merge)
    group.bench_function("strengthen_same", |b| {
        let r1 = CancelReason::new(CancelKind::User);
        let r2 = CancelReason::new(CancelKind::User);
        b.iter(|| black_box(r1.clone().strengthen(&r2)))
    });

    group.bench_function("strengthen_different", |b| {
        let r1 = CancelReason::new(CancelKind::User);
        let r2 = CancelReason::new(CancelKind::Timeout);
        b.iter(|| black_box(r1.clone().strengthen(&r2)))
    });

    group.finish();
}

// =============================================================================
// ARENA BENCHMARKS
// =============================================================================

fn bench_arena_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("arena");

    // Benchmark insert
    group.bench_function("insert", |b| {
        let mut arena: Arena<u64> = Arena::new();
        b.iter(|| {
            let idx = arena.insert(42u64);
            black_box(idx);
        })
    });

    // Benchmark get (hit)
    group.bench_function("get_hit", |b| {
        let mut arena: Arena<u64> = Arena::new();
        let idx = arena.insert(42u64);
        b.iter(|| black_box(arena.get(idx)))
    });

    // Benchmark insert + remove cycle
    group.bench_function("insert_remove_cycle", |b| {
        let mut arena: Arena<u64> = Arena::new();
        b.iter(|| {
            let idx = arena.insert(42u64);
            let removed = arena.remove(idx);
            black_box(removed);
        })
    });

    // Benchmark iteration over populated arena
    group.bench_function("iterate_1000", |b| {
        let mut arena: Arena<u64> = Arena::new();
        for i in 0..1000 {
            arena.insert(i);
        }
        b.iter(|| {
            let sum: u64 = arena.iter().map(|(_, v)| *v).sum();
            black_box(sum)
        })
    });

    group.finish();
}

// =============================================================================
// SCHEDULER BENCHMARKS
// =============================================================================

fn bench_scheduler_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler");

    // Benchmark schedule (ready lane)
    group.bench_function("schedule_ready", |b| {
        let mut scheduler = Scheduler::new();
        let mut task_counter = 0u64;
        b.iter(|| {
            task_counter += 1;
            let task_id = TaskId::from_arena(ArenaIndex::new(task_counter as u32, 0));
            scheduler.schedule(task_id, 128);
            black_box(task_id);
        })
    });

    // Benchmark schedule + pop cycle
    group.bench_function("schedule_pop_cycle", |b| {
        let mut scheduler = Scheduler::new();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        b.iter(|| {
            scheduler.schedule(task_id, 128);
            let popped = scheduler.pop();
            black_box(popped);
        })
    });

    // Benchmark pop from mixed lanes
    group.bench_function("pop_mixed_lanes", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let mut scheduler = Scheduler::new();
                // Add to all three lanes
                scheduler.schedule(TaskId::from_arena(ArenaIndex::new(1, 0)), 128);
                scheduler.schedule_timed(TaskId::from_arena(ArenaIndex::new(2, 0)), 200);
                scheduler.schedule_cancel(TaskId::from_arena(ArenaIndex::new(3, 0)), 255);

                let start = std::time::Instant::now();
                // Cancel lane should be first
                let _ = scheduler.pop();
                let _ = scheduler.pop();
                let _ = scheduler.pop();
                total += start.elapsed();
            }
            total
        })
    });

    // Benchmark wake deduplication (schedule same task twice)
    group.bench_function("dedup_schedule", |b| {
        let mut scheduler = Scheduler::new();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        scheduler.schedule(task_id, 128);
        b.iter(|| {
            scheduler.schedule(task_id, 128); // Should be no-op
            black_box(scheduler.len());
        })
    });

    group.finish();
}

// =============================================================================
// RUNTIME STATE BENCHMARKS
// =============================================================================

fn bench_runtime_state_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("runtime_state");

    // Benchmark state creation
    group.bench_function("create", |b| {
        b.iter(|| black_box(RuntimeState::new()))
    });

    // Benchmark root region creation
    group.bench_function("create_root_region", |b| {
        let mut state = RuntimeState::new();
        b.iter(|| {
            // Note: This will keep creating regions, but that's fine for benchmarking
            let id = state.create_root_region(Budget::INFINITE);
            black_box(id);
        })
    });

    // Benchmark quiescence check (empty state)
    group.bench_function("is_quiescent_empty", |b| {
        let state = RuntimeState::new();
        b.iter(|| black_box(state.is_quiescent()))
    });

    // Benchmark live counts
    group.bench_function("live_task_count_empty", |b| {
        let state = RuntimeState::new();
        b.iter(|| black_box(state.live_task_count()))
    });

    group.finish();
}

// =============================================================================
// RECORD CREATION BENCHMARKS
// =============================================================================

fn bench_record_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("record");

    let region_id = RegionId::from_arena(ArenaIndex::new(0, 0));
    let task_id = TaskId::from_arena(ArenaIndex::new(0, 0));

    // Benchmark TaskRecord creation
    group.bench_function("task_record_new", |b| {
        b.iter(|| black_box(TaskRecord::new(task_id, region_id, Budget::INFINITE)))
    });

    // Benchmark RegionRecord creation
    group.bench_function("region_record_new", |b| {
        b.iter(|| black_box(RegionRecord::new(region_id, None, Budget::INFINITE)))
    });

    // Benchmark ObligationRecord creation
    group.bench_function("obligation_record_new", |b| {
        let obl_id = ObligationId::from_arena(ArenaIndex::new(0, 0));
        b.iter(|| {
            black_box(ObligationRecord::new(
                obl_id,
                ObligationKind::SendPermit,
                task_id,
                region_id,
            ))
        })
    });

    group.finish();
}

// =============================================================================
// COMBINATOR BENCHMARKS
// =============================================================================

fn bench_combinator_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("combinator");

    // Benchmark join2_outcomes
    group.bench_function("join2_outcomes_ok", |b| {
        let o1: Outcome<i32, ()> = Outcome::Ok(1);
        let o2: Outcome<i32, ()> = Outcome::Ok(2);
        b.iter(|| black_box(join2_outcomes(o1.clone(), o2.clone())))
    });

    // Benchmark race2_outcomes
    group.bench_function("race2_outcomes", |b| {
        let o1: Outcome<i32, ()> = Outcome::Ok(1);
        let o2: Outcome<i32, ()> = Outcome::Ok(2);
        b.iter(|| black_box(race2_outcomes(o1.clone(), o2.clone())))
    });

    // Benchmark effective_deadline computation
    group.bench_function("effective_deadline_nested", |b| {
        let outer = TimeoutConfig {
            deadline: Time::from_nanos(1_000_000_000),
            inherited: None,
        };
        let inner_deadline = Time::from_nanos(500_000_000);
        b.iter(|| black_box(effective_deadline(&outer, inner_deadline)))
    });

    group.finish();
}

// =============================================================================
// LAB RUNTIME BENCHMARKS
// =============================================================================

fn bench_lab_runtime_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("lab_runtime");

    // Benchmark creation
    group.bench_function("create", |b| {
        b.iter(|| {
            let config = LabConfig::new(12345);
            black_box(LabRuntime::new(config))
        })
    });

    // Benchmark with_seed convenience constructor
    group.bench_function("with_seed", |b| {
        b.iter(|| black_box(LabRuntime::with_seed(12345)))
    });

    // Benchmark time query
    group.bench_function("now", |b| {
        let runtime = LabRuntime::with_seed(12345);
        b.iter(|| black_box(runtime.now()))
    });

    // Benchmark steps query
    group.bench_function("steps", |b| {
        let runtime = LabRuntime::with_seed(12345);
        b.iter(|| black_box(runtime.steps()))
    });

    group.finish();
}

// =============================================================================
// THROUGHPUT BENCHMARKS
// =============================================================================

fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");

    // Measure task record creation throughput
    for size in [100, 1000, 10000].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("task_records", size),
            size,
            |b, &size| {
                let region_id = RegionId::from_arena(ArenaIndex::new(0, 0));
                b.iter(|| {
                    for i in 0..size {
                        let task_id = TaskId::from_arena(ArenaIndex::new(i as u32, 0));
                        black_box(TaskRecord::new(task_id, region_id, Budget::INFINITE));
                    }
                })
            },
        );
    }

    // Measure scheduler throughput
    for size in [100, 1000, 10000].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("scheduler_cycles", size),
            size,
            |b, &size| {
                b.iter(|| {
                    let mut scheduler = Scheduler::new();
                    for i in 0..size {
                        let task_id = TaskId::from_arena(ArenaIndex::new(i as u32, 0));
                        scheduler.schedule(task_id, 128);
                    }
                    for _ in 0..size {
                        black_box(scheduler.pop());
                    }
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
    bench_outcome_operations,
    bench_budget_operations,
    bench_cancel_reason_operations,
    bench_arena_operations,
    bench_scheduler_operations,
    bench_runtime_state_operations,
    bench_record_creation,
    bench_combinator_operations,
    bench_lab_runtime_operations,
    bench_throughput,
);

criterion_main!(benches);
