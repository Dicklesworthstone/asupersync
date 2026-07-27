//! Global-injector throughput benchmarks
//! (br-asupersync-sched-hot-path-perf-bt4y5f.1; decision instrument for the
//! queue-upgrade lever br-asupersync-sched-hot-path-perf-bt4y5f.5).
//!
//! Measures the three-lane `GlobalInjector` push/pop surface in isolation —
//! the structure an LCRQ-style FAA queue would have to beat:
//!
//! - `ready_push_pop_cycle` / `cancel_push_pop_cycle`: single-thread
//!   inject-then-drain floor for the lock-free ready lane and the cancel lane.
//! - `timed_push_pop_due` / `timed_push_remove`: timed-lane heap insert with
//!   due-pop and cancel-path removal (the timed counters + cached-earliest
//!   fast path live here).
//! - `mixed_lane_drain`: 192 ready + 32 cancel + 32 timed injected, then
//!   drained in scheduler lane order (cancel → timed-due → ready).
//! - `ready_contended_push/{4,8}`: N persistent producer threads push a fixed
//!   disjoint batch each behind a start barrier, then the measured thread
//!   drains everything. Producer-side contention is the LCRQ target; the
//!   drain keeps every iteration's total work identical (deterministic
//!   totals; interleavings vary as with any real contention measurement).
//!
//! Workloads are fixed-size and seed-free, so iterations are comparable and
//! cheap enough for the Phase 6 preflight lane.

#![cfg(feature = "test-internals")]
#![allow(missing_docs)]

use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};

use asupersync::runtime::scheduler::GlobalInjector;
use asupersync::types::{TaskId, Time};

mod phase6_gate;

const ITEMS_PER_ITER: usize = 256;
const MIXED_READY: usize = 192;
const MIXED_CANCEL: usize = 32;
const MIXED_TIMED: usize = 32;

fn task(id: usize) -> TaskId {
    TaskId::new_for_test(u32::try_from(id).expect("bench task ids fit u32"), 0)
}

fn bench_single_thread_lanes(c: &mut Criterion) {
    let mut group = c.benchmark_group("sched/injector");
    group.throughput(Throughput::Elements(ITEMS_PER_ITER as u64));
    group.sample_size(20);

    let injector = GlobalInjector::new();
    group.bench_function("ready_push_pop_cycle", |b| {
        b.iter(|| {
            for i in 0..ITEMS_PER_ITER {
                injector.inject_ready(task(i), 50);
            }
            let mut popped = 0usize;
            while let Some(entry) = injector.pop_ready() {
                black_box(&entry);
                popped += 1;
            }
            assert_eq!(popped, ITEMS_PER_ITER, "ready lane must drain fully");
        });
    });

    group.bench_function("cancel_push_pop_cycle", |b| {
        b.iter(|| {
            for i in 0..ITEMS_PER_ITER {
                injector.inject_cancel(task(i), 200);
            }
            let mut popped = 0usize;
            while let Some(entry) = injector.pop_cancel() {
                black_box(&entry);
                popped += 1;
            }
            assert_eq!(popped, ITEMS_PER_ITER, "cancel lane must drain fully");
        });
    });

    group.bench_function("timed_push_pop_due", |b| {
        b.iter(|| {
            for i in 0..ITEMS_PER_ITER {
                injector.inject_timed(task(i), Time::ZERO);
            }
            let now = Time::from_secs(1);
            let mut popped = 0usize;
            while let Some(entry) = injector.pop_timed_if_due(now) {
                black_box(&entry);
                popped += 1;
            }
            assert_eq!(popped, ITEMS_PER_ITER, "timed lane must drain fully");
        });
    });

    group.bench_function("timed_push_remove", |b| {
        b.iter(|| {
            for i in 0..ITEMS_PER_ITER {
                injector.inject_timed(task(i), Time::ZERO);
            }
            let mut removed = 0usize;
            for i in 0..ITEMS_PER_ITER {
                if injector.remove_timed(task(i)) {
                    removed += 1;
                }
            }
            assert_eq!(removed, ITEMS_PER_ITER, "every timed entry must remove");
        });
    });

    group.bench_function("mixed_lane_drain", |b| {
        b.iter(|| {
            for i in 0..MIXED_READY {
                injector.inject_ready(task(i), 50);
            }
            for i in 0..MIXED_CANCEL {
                injector.inject_cancel(task(MIXED_READY + i), 200);
            }
            for i in 0..MIXED_TIMED {
                injector.inject_timed(task(MIXED_READY + MIXED_CANCEL + i), Time::ZERO);
            }
            let now = Time::from_secs(1);
            let mut popped = 0usize;
            while let Some(entry) = injector.pop_cancel() {
                black_box(&entry);
                popped += 1;
            }
            while let Some(entry) = injector.pop_timed_if_due(now) {
                black_box(&entry);
                popped += 1;
            }
            while let Some(entry) = injector.pop_ready() {
                black_box(&entry);
                popped += 1;
            }
            assert_eq!(
                popped,
                MIXED_READY + MIXED_CANCEL + MIXED_TIMED,
                "all lanes must drain fully"
            );
        });
    });

    group.finish();
}

fn bench_contended_ready_push(c: &mut Criterion) {
    let mut group = c.benchmark_group("sched/injector");
    group.throughput(Throughput::Elements(ITEMS_PER_ITER as u64));
    group.sample_size(20);

    for producers in [4usize, 8] {
        assert_eq!(
            ITEMS_PER_ITER % producers,
            0,
            "work must divide evenly across producers"
        );
        let per_producer = ITEMS_PER_ITER / producers;
        let injector = Arc::new(GlobalInjector::new());
        let start = Arc::new(Barrier::new(producers + 1));
        let submitted = Arc::new(Barrier::new(producers + 1));
        let stop = Arc::new(AtomicBool::new(false));
        let producer_failed = Arc::new(AtomicBool::new(false));

        std::thread::scope(|scope| {
            for producer in 0..producers {
                let injector = Arc::clone(&injector);
                let start = Arc::clone(&start);
                let submitted = Arc::clone(&submitted);
                let stop = Arc::clone(&stop);
                let producer_failed = Arc::clone(&producer_failed);
                scope.spawn(move || {
                    loop {
                        start.wait();
                        if stop.load(Ordering::Acquire) {
                            break;
                        }
                        let pushed = catch_unwind(AssertUnwindSafe(|| {
                            let base = producer * per_producer;
                            for i in 0..per_producer {
                                injector.inject_ready(task(base + i), 50);
                            }
                        }));
                        if pushed.is_err() {
                            producer_failed.store(true, Ordering::Release);
                        }
                        submitted.wait();
                    }
                });
            }

            group.bench_function(
                criterion::BenchmarkId::new("ready_contended_push", producers),
                |b| {
                    b.iter(|| {
                        start.wait();
                        submitted.wait();
                        assert!(
                            !producer_failed.load(Ordering::Acquire),
                            "a producer thread panicked"
                        );
                        let mut popped = 0usize;
                        while let Some(entry) = injector.pop_ready() {
                            black_box(&entry);
                            popped += 1;
                        }
                        assert_eq!(popped, ITEMS_PER_ITER, "contended ready lane must drain");
                    });
                },
            );

            stop.store(true, Ordering::Release);
            start.wait();
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_single_thread_lanes,
    bench_contended_ready_push
);

fn main() {
    benches();
    Criterion::default().configure_from_args().final_summary();
    if let Err(error) = phase6_gate::run_phase6_p50_gate("sched/injector/") {
        eprintln!("[PHASE6] baseline gate failed: {error}");
        std::process::exit(2);
    }
}
