#![cfg(feature = "test-internals")]
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

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};

use asupersync::Cx;
use asupersync::channel::mpsc;
use asupersync::obligation::ledger::ObligationLedger;
use asupersync::record::task::TaskRecord;
use asupersync::record::{ObligationAbortReason, ObligationKind};
use asupersync::runtime::RuntimeState;
use asupersync::runtime::scheduler::{GlobalQueue, LocalQueue};
use asupersync::sync::ContendedMutex;
use asupersync::types::{Budget, CancelKind, CancelReason, ObligationId, RegionId, TaskId, Time};
use std::sync::Arc;

// =============================================================================
// HELPERS
// =============================================================================

fn task(id: u32) -> TaskId {
    TaskId::new_for_test(id, 0)
}

fn region() -> RegionId {
    RegionId::testing_default()
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

fn setup_obligation_ledger_with_probe(count: u32) -> (ObligationLedger, ObligationId) {
    let mut ledger = ObligationLedger::new();
    let mut probe_id = None;

    for i in 0..count {
        let kind = match i % 3 {
            0 => ObligationKind::SendPermit,
            1 => ObligationKind::Ack,
            _ => ObligationKind::Lease,
        };
        let acquired_at = Time::from_nanos(u64::from(i) + 1);
        let token = ledger.acquire(kind, task(i % 8), region(), acquired_at);
        probe_id.get_or_insert_with(|| token.id());

        match i % 4 {
            0 => {
                ledger.commit(token, Time::from_nanos(u64::from(i) + 10_000));
            }
            1 => {
                ledger.abort(
                    token,
                    Time::from_nanos(u64::from(i) + 10_000),
                    ObligationAbortReason::Explicit,
                );
            }
            _ => {
                let _pending = token;
            }
        }
    }

    (
        ledger,
        probe_id.expect("obligation benchmark fixture must create at least one obligation"),
    )
}

fn setup_obligation_ledger(count: u32) -> ObligationLedger {
    setup_obligation_ledger_with_probe(count).0
}

// =============================================================================
// 1. TASK SPAWN — SCHEDULER-LEVEL
// =============================================================================

fn bench_task_spawn(c: &mut Criterion) {
    let mut group = c.benchmark_group("methodology/task_spawn");

    // Measure inject_ready (the global injection path for spawning)
    group.bench_function("inject_ready_global_queue", |b: &mut criterion::Bencher| {
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
    group.bench_function("local_queue_push", |b: &mut criterion::Bencher| {
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
    group.bench_function("create_root_region", |b: &mut criterion::Bencher| {
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
                        let effects = state.cancel_request(root, &reason, None);
                        total += start.elapsed();
                        let (tasks, cancel_wakes) = effects.into_parts();
                        cancel_wakes.suppress();
                        black_box(tasks);
                    }
                    total
                })
            },
        );
    }

    // CancelReason creation and strengthening
    group.bench_function("cancel_reason_create", |b: &mut criterion::Bencher| {
        b.iter(|| black_box(CancelReason::new(CancelKind::User)))
    });

    group.bench_function("cancel_reason_strengthen", |b: &mut criterion::Bencher| {
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
                    |(tx, mut rx)| {
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
                    |(tx, mut rx)| {
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

    // MPSC bounded: batch receive throughput through the public recv_many API.
    for &(count, batch_limit) in &[(100usize, 8usize), (1000, 32), (10_000, 128)] {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::new(
                "mpsc_recv_many_throughput",
                format!("{count}_limit{batch_limit}"),
            ),
            &(count, batch_limit),
            |b, &(count, batch_limit)| {
                b.iter_batched(
                    || {
                        let cx = Cx::for_testing();
                        let (tx, rx) = mpsc::channel::<u64>(count);
                        for value in 0..count as u64 {
                            tx.try_send(value).expect("send");
                        }
                        (cx, rx, Vec::with_capacity(batch_limit))
                    },
                    |(cx, mut rx, mut buffer)| {
                        let mut received = 0usize;
                        while received < count {
                            buffer.clear();
                            let drained = futures_lite::future::block_on(rx.recv_many(
                                &cx,
                                &mut buffer,
                                batch_limit,
                            ))
                            .expect("recv_many");
                            if drained == 0 {
                                break;
                            }
                            received += drained;
                            black_box(&buffer);
                        }
                        black_box(received)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // Channel creation cost
    group.bench_function("mpsc_create_cap16", |b: &mut criterion::Bencher| {
        b.iter(|| {
            let (tx, rx) = mpsc::channel::<u64>(16);
            black_box((&tx, &rx));
        })
    });

    group.bench_function("mpsc_create_cap256", |b: &mut criterion::Bencher| {
        b.iter(|| {
            let (tx, rx) = mpsc::channel::<u64>(256);
            black_box((&tx, &rx));
        })
    });

    // Sender clone cost (multi-producer scenario)
    group.bench_function("mpsc_sender_clone", |b: &mut criterion::Bencher| {
        let (tx, _rx) = mpsc::channel::<u64>(16);
        b.iter(|| black_box(tx.clone()))
    });

    // Weak sender upgrade/drop models dynamic handle lifecycles in
    // multi-producer topologies (e.g., registries/routers holding weak handles).
    group.bench_function("mpsc_weak_sender_upgrade", |b: &mut criterion::Bencher| {
        let (tx, _rx) = mpsc::channel::<u64>(16);
        let weak = tx.downgrade();
        b.iter(|| {
            let upgraded = weak.upgrade().expect("upgrade should succeed");
            black_box(upgraded);
        })
    });

    // Pending reserve cancellation removes the sender's FIFO waiter token.
    // The oldest waiter is the common cancellation/baton-pass case.
    for &waiter_count in &[64usize, 512, 4096] {
        group.bench_with_input(
            BenchmarkId::new("mpsc_cancel_oldest_waiter", waiter_count),
            &waiter_count,
            |b, &waiter_count| {
                b.iter_batched(
                    || mpsc::MpscWaiterCancelFixture::oldest(waiter_count),
                    |fixture| black_box(fixture.remove_target()),
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// =============================================================================
// 4. CX CAPABILITY CHECK
// =============================================================================

fn bench_cx_capability_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("methodology/cx_capability");

    // Cx creation
    group.bench_function("for_testing", |b: &mut criterion::Bencher| {
        b.iter(|| black_box(Cx::for_testing()))
    });

    group.bench_function("for_testing_with_budget", |b: &mut criterion::Bencher| {
        let budget = Budget::new()
            .with_deadline(Time::from_secs(30))
            .with_poll_quota(1000);
        b.iter(|| black_box(Cx::for_testing_with_budget(budget)))
    });

    // Capability checks (minimal Cx — all return false)
    let cx = Cx::for_testing();
    group.bench_function("has_timer", |b: &mut criterion::Bencher| {
        b.iter(|| black_box(cx.has_timer()))
    });
    group.bench_function("has_io", |b: &mut criterion::Bencher| {
        b.iter(|| black_box(cx.has_io()))
    });
    group.bench_function("has_registry", |b: &mut criterion::Bencher| {
        b.iter(|| black_box(cx.has_registry()))
    });
    group.bench_function("has_remote", |b: &mut criterion::Bencher| {
        b.iter(|| black_box(cx.has_remote()))
    });

    // Cx with I/O capability — check cost when capability IS present
    let cx_io = Cx::for_testing_with_io();
    group.bench_function("has_io_present", |b: &mut criterion::Bencher| {
        b.iter(|| black_box(cx_io.has_io()))
    });

    // Budget access
    group.bench_function("budget", |b: &mut criterion::Bencher| {
        b.iter(|| black_box(cx.budget()))
    });

    // Cancel check
    group.bench_function("is_cancel_requested", |b: &mut criterion::Bencher| {
        b.iter(|| black_box(cx.is_cancel_requested()))
    });

    // Identity access
    group.bench_function("task_id", |b: &mut criterion::Bencher| {
        b.iter(|| black_box(cx.task_id()))
    });
    group.bench_function("region_id", |b: &mut criterion::Bencher| {
        b.iter(|| black_box(cx.region_id()))
    });

    group.finish();
}

// =============================================================================
// 5. BUDGET CHECK AND PROPAGATION
// =============================================================================

#[allow(clippy::too_many_lines)]
fn bench_budget_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("methodology/budget");

    // Budget creation
    group.bench_function("create_infinite", |b: &mut criterion::Bencher| {
        b.iter(|| black_box(Budget::INFINITE))
    });

    group.bench_function(
        "create_with_deadline_and_quota",
        |b: &mut criterion::Bencher| {
            b.iter(|| {
                black_box(
                    Budget::new()
                        .with_deadline(Time::from_secs(30))
                        .with_poll_quota(1000)
                        .with_cost_quota(10_000),
                )
            })
        },
    );

    // Exhaustion check
    let budget_inf = Budget::INFINITE;
    let budget_zero = Budget::ZERO;
    let budget_with_resources = Budget::new().with_poll_quota(1000).with_cost_quota(10_000);

    group.bench_function("is_exhausted_infinite", |b: &mut criterion::Bencher| {
        b.iter(|| black_box(budget_inf.is_exhausted()))
    });

    group.bench_function("is_exhausted_zero", |b: &mut criterion::Bencher| {
        b.iter(|| black_box(budget_zero.is_exhausted()))
    });

    group.bench_function(
        "is_exhausted_with_resources",
        |b: &mut criterion::Bencher| b.iter(|| black_box(budget_with_resources.is_exhausted())),
    );

    // Deadline check
    group.bench_function(
        "is_past_deadline_no_deadline",
        |b: &mut criterion::Bencher| {
            let budget = Budget::INFINITE;
            let now = Time::from_secs(100);
            b.iter(|| black_box(budget.is_past_deadline(now)))
        },
    );

    group.bench_function(
        "is_past_deadline_with_deadline",
        |b: &mut criterion::Bencher| {
            let budget = Budget::new().with_deadline(Time::from_secs(30));
            let now = Time::from_secs(10);
            b.iter(|| black_box(budget.is_past_deadline(now)))
        },
    );

    // Consume poll (mutation path)
    group.bench_function("consume_poll", |b: &mut criterion::Bencher| {
        b.iter_batched(
            || Budget::new().with_poll_quota(u32::MAX),
            |mut budget| black_box(budget.consume_poll()),
            BatchSize::SmallInput,
        )
    });

    // Consume cost (mutation path)
    group.bench_function("consume_cost", |b: &mut criterion::Bencher| {
        b.iter_batched(
            || Budget::new().with_cost_quota(u64::MAX),
            |mut budget| black_box(budget.consume_cost(1)),
            BatchSize::SmallInput,
        )
    });

    // Combine (meet operation) — critical for budget propagation
    group.bench_function("combine_two", |b: &mut criterion::Bencher| {
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
    group.bench_function(
        "remaining_time_with_deadline",
        |b: &mut criterion::Bencher| {
            let budget = Budget::new().with_deadline(Time::from_secs(30));
            let now = Time::from_secs(10);
            b.iter(|| black_box(budget.remaining_time(now)))
        },
    );

    group.bench_function(
        "remaining_time_no_deadline",
        |b: &mut criterion::Bencher| {
            let budget = Budget::INFINITE;
            let now = Time::from_secs(10);
            b.iter(|| black_box(budget.remaining_time(now)))
        },
    );

    group.finish();
}

// =============================================================================
// 6. OBLIGATION QUERY SNAPSHOTS
// =============================================================================

#[allow(clippy::too_many_lines)]
fn bench_obligation_query(c: &mut Criterion) {
    let mut group = c.benchmark_group("methodology/obligation_query");

    group.bench_function("acquire_pending", |b: &mut criterion::Bencher| {
        b.iter_batched(
            ObligationLedger::new,
            |mut ledger| {
                let token = ledger.acquire(
                    ObligationKind::Lease,
                    task(0),
                    region(),
                    Time::from_nanos(1),
                );
                black_box(token.id())
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("acquire_commit", |b: &mut criterion::Bencher| {
        b.iter_batched(
            ObligationLedger::new,
            |mut ledger| {
                let token = ledger.acquire(
                    ObligationKind::Lease,
                    task(0),
                    region(),
                    Time::from_nanos(1),
                );
                black_box(ledger.commit(token, Time::from_nanos(2)))
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("acquire_abort", |b: &mut criterion::Bencher| {
        b.iter_batched(
            ObligationLedger::new,
            |mut ledger| {
                let token = ledger.acquire(
                    ObligationKind::Lease,
                    task(0),
                    region(),
                    Time::from_nanos(1),
                );
                black_box(ledger.abort(token, Time::from_nanos(2), ObligationAbortReason::Explicit))
            },
            BatchSize::SmallInput,
        )
    });

    for &count in &[16u32, 256, 4096] {
        group.throughput(Throughput::Elements(u64::from(count)));

        group.bench_with_input(
            BenchmarkId::new("counts_for_region", count),
            &count,
            |b, &count| {
                b.iter_batched(
                    || setup_obligation_ledger(count),
                    |ledger| black_box(ledger.counts_for_region(region())),
                    BatchSize::LargeInput,
                )
            },
        );

        group.bench_with_input(
            BenchmarkId::new("counts_for_task", count),
            &count,
            |b, &count| {
                b.iter_batched(
                    || setup_obligation_ledger(count),
                    |ledger| black_box(ledger.counts_for_task(task(0))),
                    BatchSize::LargeInput,
                )
            },
        );

        group.bench_with_input(
            BenchmarkId::new("counts_for_kind", count),
            &count,
            |b, &count| {
                b.iter_batched(
                    || setup_obligation_ledger(count),
                    |ledger| black_box(ledger.counts_for_kind(ObligationKind::Lease)),
                    BatchSize::LargeInput,
                )
            },
        );

        group.bench_with_input(
            BenchmarkId::new("obligation_state", count),
            &count,
            |b, &count| {
                b.iter_batched(
                    || setup_obligation_ledger_with_probe(count),
                    |(ledger, probe_id)| black_box(ledger.obligation_state(probe_id)),
                    BatchSize::LargeInput,
                )
            },
        );

        group.bench_with_input(
            BenchmarkId::new("audit_region", count),
            &count,
            |b, &count| {
                b.iter_batched(
                    || setup_obligation_ledger(count),
                    |ledger| black_box(ledger.audit_region(region(), Time::from_nanos(20_000))),
                    BatchSize::LargeInput,
                )
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
    bench_task_spawn,
    bench_task_cancellation,
    bench_channel_send_recv,
    bench_cx_capability_check,
    bench_budget_check,
    bench_obligation_query,
);

const PHASE6_BASELINE_ENV: &str = "ASUPERSYNC_PHASE6_BASELINE";
const PHASE6_THRESHOLD_ENV: &str = "ASUPERSYNC_PHASE6_MAX_REGRESSION_PCT";
const PHASE6_MAX_REGRESSION_PCT: f64 = 5.0;

#[derive(Deserialize)]
struct TrackedBaseline {
    schema_version: String,
    baselines: Vec<TrackedBaselineRow>,
}

#[derive(Deserialize)]
struct TrackedBaselineRow {
    operation: String,
    p50_ns: f64,
}

#[derive(Deserialize)]
struct CriterionEstimates {
    median: CriterionPointEstimate,
}

#[derive(Deserialize)]
struct CriterionPointEstimate {
    point_estimate: f64,
}

fn criterion_home() -> PathBuf {
    env::var_os("CRITERION_HOME").map_or_else(
        || {
            env::var_os("CARGO_TARGET_DIR").map_or_else(
                || PathBuf::from("target/criterion"),
                |target| PathBuf::from(target).join("criterion"),
            )
        },
        PathBuf::from,
    )
}

fn criterion_directory(operation: &str) -> Result<PathBuf, String> {
    if operation.matches('/').count() < 2 {
        return Err(format!(
            "tracked Phase 6 operation {operation:?} must contain a group and benchmark name"
        ));
    }
    // Criterion makes the group id filename-safe as one component. These
    // operations use `methodology/<group>` as the group id, followed by the
    // function and optional value components, so only the first slash becomes
    // an underscore on disk.
    Ok(PathBuf::from(operation.replacen('/', "_", 1)))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, label: &str) -> Result<T, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read {label} {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot parse {label} {}: {error}", path.display()))
}

fn run_phase6_p50_gate() -> Result<(), String> {
    let Some(baseline_path) = env::var_os(PHASE6_BASELINE_ENV) else {
        return Ok(());
    };

    let threshold = env::var(PHASE6_THRESHOLD_ENV)
        .map_err(|_| format!("{PHASE6_THRESHOLD_ENV} must be set to 5"))?
        .parse::<f64>()
        .map_err(|error| format!("{PHASE6_THRESHOLD_ENV} must be numeric: {error}"))?;
    if threshold.to_bits() != PHASE6_MAX_REGRESSION_PCT.to_bits() {
        return Err(format!(
            "{PHASE6_THRESHOLD_ENV} must be exactly {PHASE6_MAX_REGRESSION_PCT}, got {threshold}"
        ));
    }

    let baseline_path = PathBuf::from(baseline_path);
    let baseline: TrackedBaseline = read_json(&baseline_path, "tracked Phase 6 baseline")?;
    if baseline.schema_version != "1.0.0" {
        return Err(format!(
            "tracked Phase 6 baseline schema must be 1.0.0, got {:?}",
            baseline.schema_version
        ));
    }
    if baseline.baselines.is_empty() {
        return Err("tracked Phase 6 baseline contains no rows".to_string());
    }

    let criterion_home = criterion_home();
    let mut operations = BTreeSet::new();
    let mut regressions = Vec::new();

    for row in &baseline.baselines {
        if row.operation.is_empty() {
            return Err("tracked Phase 6 baseline contains an empty operation".to_string());
        }
        if !operations.insert(row.operation.as_str()) {
            return Err(format!(
                "tracked Phase 6 baseline contains duplicate operation {:?}",
                row.operation
            ));
        }
        if !row.p50_ns.is_finite() || row.p50_ns <= 0.0 {
            return Err(format!(
                "tracked Phase 6 baseline operation {:?} has invalid p50_ns",
                row.operation
            ));
        }

        let estimates_path = criterion_home
            .join(criterion_directory(&row.operation)?)
            .join("new/estimates.json");
        let estimates: CriterionEstimates =
            read_json(&estimates_path, "Phase 6 Criterion estimates")?;
        let candidate_p50_ns = estimates.median.point_estimate;
        if !candidate_p50_ns.is_finite() || candidate_p50_ns <= 0.0 {
            return Err(format!(
                "Phase 6 candidate operation {:?} has invalid median.point_estimate",
                row.operation
            ));
        }

        let delta_pct = (candidate_p50_ns / row.p50_ns - 1.0) * 100.0;
        if delta_pct > PHASE6_MAX_REGRESSION_PCT {
            regressions.push(format!(
                "{}: {:.2} -> {:.2} (+{:.2}%)",
                row.operation, row.p50_ns, candidate_p50_ns, delta_pct
            ));
        }
    }

    if regressions.is_empty() {
        println!(
            "[PHASE6] p50 gate passed: {} tracked rows compared at 5.00%; untracked Criterion rows are outside this gate.",
            baseline.baselines.len()
        );
        Ok(())
    } else {
        Err(format!(
            "p50 regressions (>5.00%):\n  - {}",
            regressions.join("\n  - ")
        ))
    }
}

fn main() {
    benches();
    Criterion::default().configure_from_args().final_summary();
    if let Err(error) = run_phase6_p50_gate() {
        eprintln!("[PHASE6] baseline gate failed: {error}");
        std::process::exit(2);
    }
}
