//! Contended MPSC channel benchmarks
//! (br-asupersync-sched-hot-path-perf-bt4y5f.1; decision instrument for the
//! flat-combining lever br-asupersync-sched-hot-path-perf-bt4y5f.5).
//!
//! Pins the current multi-producer cost of `channel::mpsc` — the surface a
//! flat-combining submission layer would have to beat:
//!
//! - `try_send_recv_cycle`: single-thread floor — 256 `try_send` into an
//!   ample-capacity channel, then 256 `try_recv`.
//! - `reserve_send_recv_cycle`: the two-phase cancel-safe path
//!   (`reserve(&cx).await` → `permit.send`) at the same shape, so the
//!   two-phase overhead over `try_send` stays measured.
//! - `try_send_contended/{4,8}`: N barrier-synced producer threads each push
//!   their disjoint 256/N items through a capacity-64 channel (spin-retry on
//!   Full) while the measured thread drains exactly 256 items. Producer-side
//!   CAS traffic plus consumer wakeover is the flat-combining target.
//!
//! Fixed item counts and capacities, no randomness: iteration totals are
//! identical every round (interleavings vary, as with any real contention).

#![cfg(feature = "test-internals")]
#![allow(missing_docs)]

use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};

use asupersync::Cx;
use asupersync::channel::mpsc;

mod phase6_gate;

const ITEMS_PER_ITER: usize = 256;
const CONTENDED_CAPACITY: usize = 64;
const AMPLE_CAPACITY: usize = 1024;

fn bench_single_thread(c: &mut Criterion) {
    let mut group = c.benchmark_group("sched/channel_contended");
    group.throughput(Throughput::Elements(ITEMS_PER_ITER as u64));
    group.sample_size(20);

    group.bench_function("try_send_recv_cycle", |b| {
        let (tx, mut rx) = mpsc::channel::<u64>(AMPLE_CAPACITY);
        b.iter(|| {
            for i in 0..ITEMS_PER_ITER as u64 {
                tx.try_send(black_box(i)).expect("ample capacity");
            }
            let mut received = 0usize;
            while let Ok(value) = rx.try_recv() {
                black_box(value);
                received += 1;
            }
            assert_eq!(received, ITEMS_PER_ITER, "cycle must drain fully");
        });
    });

    group.bench_function("reserve_send_recv_cycle", |b| {
        let cx = Cx::for_testing();
        let (tx, mut rx) = mpsc::channel::<u64>(AMPLE_CAPACITY);
        b.iter(|| {
            futures_lite::future::block_on(async {
                for i in 0..ITEMS_PER_ITER as u64 {
                    let permit = tx.reserve(&cx).await.expect("ample capacity");
                    permit.send(black_box(i));
                }
            });
            let mut received = 0usize;
            while let Ok(value) = rx.try_recv() {
                black_box(value);
                received += 1;
            }
            assert_eq!(received, ITEMS_PER_ITER, "cycle must drain fully");
        });
    });

    group.finish();
}

fn bench_contended_producers(c: &mut Criterion) {
    let mut group = c.benchmark_group("sched/channel_contended");
    group.throughput(Throughput::Elements(ITEMS_PER_ITER as u64));
    group.sample_size(20);

    for producers in [4usize, 8] {
        assert_eq!(
            ITEMS_PER_ITER % producers,
            0,
            "work must divide evenly across producers"
        );
        let per_producer = ITEMS_PER_ITER / producers;
        let (tx, mut rx) = mpsc::channel::<u64>(CONTENDED_CAPACITY);
        let start = Arc::new(Barrier::new(producers + 1));
        let done = Arc::new(Barrier::new(producers + 1));
        let stop = Arc::new(AtomicBool::new(false));
        let producer_failed = Arc::new(AtomicBool::new(false));

        std::thread::scope(|scope| {
            for producer in 0..producers {
                let tx = tx.clone();
                let start = Arc::clone(&start);
                let done = Arc::clone(&done);
                let stop = Arc::clone(&stop);
                let producer_failed = Arc::clone(&producer_failed);
                scope.spawn(move || {
                    loop {
                        start.wait();
                        if stop.load(Ordering::Acquire) {
                            break;
                        }
                        let pushed = catch_unwind(AssertUnwindSafe(|| {
                            let base = (producer * per_producer) as u64;
                            for i in 0..per_producer as u64 {
                                let mut value = base + i;
                                // Spin-retry on Full: the consumer is draining
                                // concurrently, so capacity always reopens.
                                loop {
                                    match tx.try_send(value) {
                                        Ok(()) => break,
                                        Err(mpsc::SendError::Full(returned)) => {
                                            value = returned;
                                            std::hint::spin_loop();
                                        }
                                        Err(other) => panic!("unexpected send failure: {other}"),
                                    }
                                }
                            }
                        }));
                        if pushed.is_err() {
                            producer_failed.store(true, Ordering::Release);
                        }
                        done.wait();
                    }
                });
            }

            group.bench_function(
                criterion::BenchmarkId::new("try_send_contended", producers),
                |b| {
                    b.iter(|| {
                        start.wait();
                        let mut received = 0usize;
                        while received < ITEMS_PER_ITER {
                            match rx.try_recv() {
                                Ok(value) => {
                                    black_box(value);
                                    received += 1;
                                }
                                Err(_) => std::hint::spin_loop(),
                            }
                        }
                        done.wait();
                        assert!(
                            !producer_failed.load(Ordering::Acquire),
                            "a producer thread panicked"
                        );
                    });
                },
            );

            stop.store(true, Ordering::Release);
            start.wait();
        });
    }

    group.finish();
}

criterion_group!(benches, bench_single_thread, bench_contended_producers);

fn main() {
    benches();
    Criterion::default().configure_from_args().final_summary();
    if let Err(error) = phase6_gate::run_phase6_p50_gate("sched/channel_contended/") {
        eprintln!("[PHASE6] baseline gate failed: {error}");
        std::process::exit(2);
    }
}
