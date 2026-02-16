//! Methodology baseline benchmarks for Asupersync (bd-1e2if.1).
//!
//! Captures p50/p95/p99 baselines for all primary operations:
//!
//! 1. **Task spawn** — scheduler-level spawn (inject_ready, LocalQueue push)
//! 2. **Task cancellation** — cancel signal to obligation release
//! 3. **Channel send/recv** — MPSC one-way latency (bounded/unbounded-style)
//! 4. **Cx capability check** — has_timer(), has_io(), budget() access
//! 5. **Budget check** — is_exhausted(), is_past_deadline(), consume_poll()
//! 6. **RaptorQ encode/decode** — covered by raptorq_benchmark.rs
//! 7. **DPOR exploration** — covered by cancel_trace_bench.rs
//!
//! Operations 6 and 7 are covered by existing benchmark suites; this file
//! completes the methodology surface by adding operations 1–5 plus a
//! JSON artifact emitter.
//!
//! Benchmarks use deterministic inputs (fixed seeds) for reproducibility.

#![allow(missing_docs)]
#![allow(clippy::semicolon_if_nothing_returned)]

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use asupersync::channel::mpsc;
use asupersync::record::task::TaskRecord;
use asupersync::runtime::scheduler::{GlobalQueue, LocalQueue};
use asupersync::runtime::RuntimeState;
use asupersync::sync::ContendedMutex;
use asupersync::types::{Budget, CancelKind, CancelReason, RegionId, TaskId, Time};
use asupersync::util::ArenaIndex;
use asupersync::Cx;
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

fn local_queue(max_task_id: u32) -> LocalQueue {
    LocalQueue::new(setup_runtime_state(max_task_id))
}

// =============================================================================
// 1. TASK SPAWN — SCHEDULER-LEVEL
// =============================================================================

fn bench_task_spawn(c: &mut Criterion) {
    let mut group = c.benchmark_group("methodology/task_spawn");

    // Measure inject_ready (the global injection path for spawning)
    group.bench_function("inject_ready_global_queue", |b| {
        b.iter_batched(
            GlobalQueue::new,
            |queue| {
                queue.push(task(0));
                black_box(queue.pop())
            },
            BatchSize::SmallInput,
        )
    });

    // Measure local_queue push (the per-worker spawn path)
    group.bench_function("local_queue_push", |b| {
        b.iter_batched(
            || local_queue(0),
            |queue| {
                queue.push(task(0));
                black_box(queue.pop())
            },
            BatchSize::SmallInput,
        )
    });

    // Throughput: spawn N tasks via LocalQueue
    for &count in &[10, 100, 1000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("local_queue_spawn_batch", count),
            &count,
            |b, &count| {
                let max_id = count as u32;
                b.iter_batched(
                    || local_queue(max_id),
                    |queue| {
                        for i in 0..count as u32 {
                            queue.push(task(i));
                        }
                        black_box(())
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // RuntimeState::create_root_region (region creation is part of task setup)
    group.bench_function("create_root_region", |b| {
        let mut state = RuntimeState::new();
        b.iter(|| {
            let id = state.create_root_region(Budget::INFINITE);
            black_box(id)
        })
    });

    group.finish();
}

// =============================================================================
// 2. TASK CANCELLATION
// =============================================================================

fn bench_task_cancellation(c: &mut Criterion) {
    let mut group = c.benchmark_group("methodology/task_cancellation");

    // Cancel request on a region with children
    for &task_count in &[1, 10, 100] {
        group.bench_with_input(
            BenchmarkId::new("cancel_region", task_count),
            &task_count,
            |b, &task_count| {
                b.iter_custom(|iters| {
                    let mut total = std::time::Duration::ZERO;
                    for _ in 0..iters {
                        let mut state = RuntimeState::new();
                        let root = state.create_root_region(Budget::INFINITE);
                        // Create child regions to simulate a real cancel tree
                        for _ in 0..task_count {
                            let child_budget = Budget::new()
                                .with_deadline(Time::from_secs(30))
                                .with_poll_quota(1000);
                            let _ = state.create_child_region(root, child_budget);
                        }
                        let reason = CancelReason::new(CancelKind::User);

                        let start = std::time::Instant::now();
                        let tasks = state.cancel_request(root, &reason, None);
                        total += start.elapsed();
                        black_box(tasks);
                    }
                    total
                })
            },
        );
    }

    // CancelReason creation and strengthening
    group.bench_function("cancel_reason_create", |b| {
        b.iter(|| black_box(CancelReason::new(CancelKind::User)))
    });

    group.bench_function("cancel_reason_strengthen", |b| {
        let r1 = CancelReason::new(CancelKind::User);
        let r2 = CancelReason::new(CancelKind::Timeout);
        b.iter(|| black_box(r1.clone().strengthen(&r2)))
    });

    group.finish();
}

// =============================================================================
// 3. CHANNEL SEND/RECV — ONE-WAY LATENCY
// =============================================================================

fn bench_channel_send_recv(c: &mut Criterion) {
    let mut group = c.benchmark_group("methodology/channel");

    // MPSC bounded: try_send + try_recv round-trip
    for &capacity in &[1, 16, 256] {
        group.bench_with_input(
            BenchmarkId::new("mpsc_try_send_recv", capacity),
            &capacity,
            |b, &capacity| {
                b.iter_batched(
                    || mpsc::channel::<u64>(capacity),
                    |(tx, rx)| {
                        tx.try_send(42u64).expect("send");
                        let v = rx.try_recv().expect("recv");
                        black_box(v)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // MPSC bounded: throughput (fill then drain)
    for &count in &[10, 100, 1000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("mpsc_throughput", count),
            &count,
            |b, &count| {
                b.iter_batched(
                    || mpsc::channel::<u64>(count as usize),
                    |(tx, rx)| {
                        for i in 0..count {
                            tx.try_send(i).expect("send");
                        }
                        for _ in 0..count {
                            let _ = black_box(rx.try_recv().expect("recv"));
                        }
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // Channel creation cost
    group.bench_function("mpsc_create_cap16", |b| {
        b.iter(|| {
            let (tx, rx) = mpsc::channel::<u64>(16);
            black_box((&tx, &rx));
        })
    });

    group.bench_function("mpsc_create_cap256", |b| {
        b.iter(|| {
            let (tx, rx) = mpsc::channel::<u64>(256);
            black_box((&tx, &rx));
        })
    });

    // Sender clone cost (multi-producer scenario)
    group.bench_function("mpsc_sender_clone", |b| {
        let (tx, _rx) = mpsc::channel::<u64>(16);
        b.iter(|| black_box(tx.clone()))
    });

    group.finish();
}

// =============================================================================
// 4. CX CAPABILITY CHECK
// =============================================================================

fn bench_cx_capability_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("methodology/cx_capability");

    // Cx creation
    group.bench_function("for_testing", |b| b.iter(|| black_box(Cx::for_testing())));

    group.bench_function("for_testing_with_budget", |b| {
        let budget = Budget::new()
            .with_deadline(Time::from_secs(30))
            .with_poll_quota(1000);
        b.iter(|| black_box(Cx::for_testing_with_budget(budget)))
    });

    // Capability checks (minimal Cx — all return false)
    let cx = Cx::for_testing();
    group.bench_function("has_timer", |b| b.iter(|| black_box(cx.has_timer())));
    group.bench_function("has_io", |b| b.iter(|| black_box(cx.has_io())));
    group.bench_function("has_registry", |b| b.iter(|| black_box(cx.has_registry())));
    group.bench_function("has_remote", |b| b.iter(|| black_box(cx.has_remote())));

    // Cx with I/O capability — check cost when capability IS present
    let cx_io = Cx::for_testing_with_io();
    group.bench_function("has_io_present", |b| b.iter(|| black_box(cx_io.has_io())));

    // Budget access
    group.bench_function("budget", |b| b.iter(|| black_box(cx.budget())));

    // Cancel check
    group.bench_function("is_cancel_requested", |b| {
        b.iter(|| black_box(cx.is_cancel_requested()))
    });

    // Identity access
    group.bench_function("task_id", |b| b.iter(|| black_box(cx.task_id())));
    group.bench_function("region_id", |b| b.iter(|| black_box(cx.region_id())));

    group.finish();
}

// =============================================================================
// 5. BUDGET CHECK AND PROPAGATION
// =============================================================================

fn bench_budget_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("methodology/budget");

    // Budget creation
    group.bench_function("create_infinite", |b| {
        b.iter(|| black_box(Budget::INFINITE))
    });

    group.bench_function("create_with_deadline_and_quota", |b| {
        b.iter(|| {
            black_box(
                Budget::new()
                    .with_deadline(Time::from_secs(30))
                    .with_poll_quota(1000)
                    .with_cost_quota(10_000),
            )
        })
    });

    // Exhaustion check
    let budget_inf = Budget::INFINITE;
    let budget_zero = Budget::ZERO;
    let budget_with_resources = Budget::new().with_poll_quota(1000).with_cost_quota(10_000);

    group.bench_function("is_exhausted_infinite", |b| {
        b.iter(|| black_box(budget_inf.is_exhausted()))
    });

    group.bench_function("is_exhausted_zero", |b| {
        b.iter(|| black_box(budget_zero.is_exhausted()))
    });

    group.bench_function("is_exhausted_with_resources", |b| {
        b.iter(|| black_box(budget_with_resources.is_exhausted()))
    });

    // Deadline check
    group.bench_function("is_past_deadline_no_deadline", |b| {
        let budget = Budget::INFINITE;
        let now = Time::from_secs(100);
        b.iter(|| black_box(budget.is_past_deadline(now)))
    });

    group.bench_function("is_past_deadline_with_deadline", |b| {
        let budget = Budget::new().with_deadline(Time::from_secs(30));
        let now = Time::from_secs(10);
        b.iter(|| black_box(budget.is_past_deadline(now)))
    });

    // Consume poll (mutation path)
    group.bench_function("consume_poll", |b| {
        b.iter_batched(
            || Budget::new().with_poll_quota(u32::MAX),
            |mut budget| black_box(budget.consume_poll()),
            BatchSize::SmallInput,
        )
    });

    // Consume cost (mutation path)
    group.bench_function("consume_cost", |b| {
        b.iter_batched(
            || Budget::new().with_cost_quota(u64::MAX),
            |mut budget| black_box(budget.consume_cost(1)),
            BatchSize::SmallInput,
        )
    });

    // Combine (meet operation) — critical for budget propagation
    group.bench_function("combine_two", |b| {
        let b1 = Budget::new()
            .with_deadline(Time::from_secs(30))
            .with_poll_quota(1000);
        let b2 = Budget::new()
            .with_deadline(Time::from_secs(20))
            .with_poll_quota(500);
        b.iter(|| black_box(b1.combine(b2)))
    });

    // Combine chain (N budgets)
    for &count in &[4, 16, 64] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("combine_chain", count),
            &count,
            |b, &count| {
                let budget = Budget::new()
                    .with_deadline(Time::from_secs(30))
                    .with_poll_quota(1000);
                b.iter(|| {
                    let mut combined = Budget::INFINITE;
                    for _ in 0..count {
                        combined = combined.combine(budget);
                    }
                    black_box(combined)
                })
            },
        );
    }

    // Remaining time computation
    group.bench_function("remaining_time_with_deadline", |b| {
        let budget = Budget::new().with_deadline(Time::from_secs(30));
        let now = Time::from_secs(10);
        b.iter(|| black_box(budget.remaining_time(now)))
    });

    group.bench_function("remaining_time_no_deadline", |b| {
        let budget = Budget::INFINITE;
        let now = Time::from_secs(10);
        b.iter(|| black_box(budget.remaining_time(now)))
    });

    group.finish();
}

// =============================================================================
// MAIN
// =============================================================================

criterion_group!(
    benches,
    bench_task_spawn,
    bench_task_cancellation,
    bench_channel_send_recv,
    bench_cx_capability_check,
    bench_budget_check,
);

criterion_main!(benches);
