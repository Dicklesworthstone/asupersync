//! Phase 0 baseline benchmarks for Asupersync.
//!
//! These benchmarks establish performance baselines for the Phase 0 kernel:
//! - Core type operations (Outcome, Budget, CancelReason)
//! - Arena operations (insert, get, remove)
//! - RuntimeState operations (region create, cancel request)
//! - Combinator operations (join, race, timeout)
//! - Lab runtime operations
//!
//! Benchmarks use deterministic inputs (fixed seeds) to ensure reproducibility.
//!
//! Note: Some scheduler benchmarks require internal IDs and are tested through
//! the RuntimeState API instead of direct scheduler access.

#![allow(missing_docs)]
#![allow(clippy::semicolon_if_nothing_returned)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::explicit_iter_loop)]

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};

use asupersync::combinator::race::{race2_outcomes, RaceWinner};
use asupersync::combinator::{effective_deadline, join2_outcomes, TimeoutConfig};
use asupersync::config::RaptorQConfig;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::raptorq::{RaptorQReceiverBuilder, RaptorQSenderBuilder};
use asupersync::runtime::RuntimeState;
use asupersync::transport::mock::{mock_channel, MockTransportConfig};
use asupersync::types::{Budget, CancelKind, CancelReason, ObjectId, ObjectParams, Outcome, Time};
use asupersync::util::Arena;
use asupersync::Cx;

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
        let outcome: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::new(CancelKind::User));
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
// RUNTIME STATE BENCHMARKS
// =============================================================================

fn bench_runtime_state_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("runtime_state");

    // Benchmark state creation
    group.bench_function("create", |b| b.iter(|| black_box(RuntimeState::new())));

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

    // Benchmark cancel_request on a region
    group.bench_function("cancel_request_region", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let mut state = RuntimeState::new();
                let region = state.create_root_region(Budget::INFINITE);
                let reason = CancelReason::timeout();

                let start = std::time::Instant::now();
                let tasks = state.cancel_request(region, &reason, None);
                total += start.elapsed();
                black_box(tasks);
            }
            total
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

    // Benchmark race2_outcomes (with correct 3-argument signature)
    group.bench_function("race2_outcomes_first_wins", |b| {
        let o1: Outcome<i32, ()> = Outcome::Ok(1);
        let o2: Outcome<i32, ()> = Outcome::Cancelled(CancelReason::race_loser());
        b.iter(|| black_box(race2_outcomes(RaceWinner::First, o1.clone(), o2.clone())))
    });

    group.bench_function("race2_outcomes_second_wins", |b| {
        let o1: Outcome<i32, ()> = Outcome::Cancelled(CancelReason::race_loser());
        let o2: Outcome<i32, ()> = Outcome::Ok(2);
        b.iter(|| black_box(race2_outcomes(RaceWinner::Second, o1.clone(), o2.clone())))
    });

    // Benchmark effective_deadline computation (correct signature: Time, Option<Time>)
    group.bench_function("effective_deadline_with_existing", |b| {
        let requested = Time::from_nanos(1_000_000_000);
        let existing = Some(Time::from_nanos(500_000_000));
        b.iter(|| black_box(effective_deadline(requested, existing)))
    });

    group.bench_function("effective_deadline_no_existing", |b| {
        let requested = Time::from_nanos(1_000_000_000);
        b.iter(|| black_box(effective_deadline(requested, None)))
    });

    // Benchmark TimeoutConfig creation and resolution
    group.bench_function("timeout_config_new", |b| {
        b.iter(|| black_box(TimeoutConfig::new(Time::from_nanos(1_000_000_000))))
    });

    group.bench_function("timeout_config_resolve", |b| {
        let config = TimeoutConfig::new(Time::from_nanos(1_000_000_000));
        let existing = Some(Time::from_nanos(500_000_000));
        b.iter(|| black_box(config.resolve(existing)))
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

    // Measure region creation throughput via RuntimeState
    for &size in &[100, 1000, 10000] {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::new("region_creates", size),
            &size,
            |b, &size| {
                b.iter(|| {
                    let mut state = RuntimeState::new();
                    for _ in 0..size {
                        black_box(state.create_root_region(Budget::INFINITE));
                    }
                })
            },
        );
    }

    // Measure arena throughput
    for &size in &[100, 1000, 10000] {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::new("arena_inserts", size),
            &size,
            |b, &size| {
                b.iter(|| {
                    let mut arena: Arena<u64> = Arena::new();
                    for i in 0..size {
                        arena.insert(i as u64);
                    }
                    black_box(arena.len())
                })
            },
        );
    }

    // Measure budget combine throughput
    for &size in &[100, 1000, 10000] {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::new("budget_combines", size),
            &size,
            |b, &size| {
                let budget = Budget::new()
                    .with_deadline(Time::from_nanos(1_000_000_000))
                    .with_poll_quota(1000);
                b.iter(|| {
                    let mut combined = Budget::INFINITE;
                    for _ in 0..size {
                        combined = combined.combine(budget);
                    }
                    black_box(combined)
                })
            },
        );
    }

    group.finish();
}

// =============================================================================
// TIME TYPE BENCHMARKS
// =============================================================================

fn bench_time_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("time");

    group.bench_function("from_nanos", |b| {
        b.iter(|| black_box(Time::from_nanos(1_000_000_000)))
    });

    group.bench_function("from_millis", |b| {
        b.iter(|| black_box(Time::from_millis(1000)))
    });

    group.bench_function("from_secs", |b| b.iter(|| black_box(Time::from_secs(1))));

    group.bench_function("as_nanos", |b| {
        let t = Time::from_secs(1);
        b.iter(|| black_box(t.as_nanos()))
    });

    group.bench_function("saturating_add_nanos", |b| {
        let t = Time::from_secs(1);
        b.iter(|| black_box(t.saturating_add_nanos(500_000_000)))
    });

    group.bench_function("duration_since", |b| {
        let t1 = Time::from_secs(2);
        let t2 = Time::from_secs(1);
        b.iter(|| black_box(t1.duration_since(t2)))
    });

    group.finish();
}

// =============================================================================
// RAPTORQ PIPELINE BENCHMARKS
// =============================================================================

fn bench_raptorq_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("raptorq/pipeline");

    let sizes = [64_usize * 1024, 256 * 1024, 1024 * 1024];
    let cx: Cx = Cx::for_testing();

    for &size in &sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("send_receive", size), &size, |b, &size| {
            let data = vec![0_u8; size];
            let config = raptorq_config_for_size(size);
            let params = object_params_for(&config, size);
            let object_id = params.object_id;

            b.iter_batched(
                || {
                    let (sink, stream) = mock_channel(MockTransportConfig::reliable());
                    let sender = RaptorQSenderBuilder::new()
                        .config(config.clone())
                        .transport(sink)
                        .build()
                        .expect("build sender");
                    let receiver = RaptorQReceiverBuilder::new()
                        .config(config.clone())
                        .source(stream)
                        .build()
                        .expect("build receiver");
                    (sender, receiver)
                },
                |(mut sender, mut receiver)| {
                    let send_outcome = sender
                        .send_object(&cx, object_id, &data)
                        .expect("send object");
                    let recv_outcome = receiver
                        .receive_object(&cx, &params)
                        .expect("receive object");
                    black_box(send_outcome);
                    black_box(recv_outcome);
                },
                BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

fn raptorq_config_for_size(size: usize) -> RaptorQConfig {
    let mut config = RaptorQConfig::default();
    if size > config.encoding.max_block_size {
        config.encoding.max_block_size = size;
    }
    config
}

fn object_params_for(config: &RaptorQConfig, size: usize) -> ObjectParams {
    let symbol_size = usize::from(config.encoding.symbol_size);
    let symbols_per_block = ((size + symbol_size.saturating_sub(1)) / symbol_size) as u16;
    ObjectParams::new(
        ObjectId::new_for_test(1),
        size as u64,
        config.encoding.symbol_size,
        1,
        symbols_per_block,
    )
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
    bench_runtime_state_operations,
    bench_combinator_operations,
    bench_lab_runtime_operations,
    bench_throughput,
    bench_time_operations,
    bench_raptorq_pipeline,
);

criterion_main!(benches);
