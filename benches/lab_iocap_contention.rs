//! Benchmark for br-asupersync-jyqjh9 — proves the sharded-counter
//! optimization on `LabIoCap::record_submit` / `record_complete`.
//!
//! Pre-fix: two adjacent `AtomicU64` counters in the same struct →
//! same cache line → false-sharing ping-pong on every concurrent
//! submit/complete pair AND no scaling across N writer threads on
//! the SAME counter.
//!
//! Post-fix: each counter is sharded `LAB_IOCAP_SHARD_COUNT=8` ways
//! across cache-padded `AtomicU64`s; thread-local shard index keeps
//! the hot path to a single masked `fetch_add`. Expected scaling is
//! near-linear up to `LAB_IOCAP_SHARD_COUNT` writer threads.
//!
//! This bench measures throughput at 1, 2, 4, 8, 16 writer threads
//! against a shared `Arc<LabIoCap>` for both `record_submit` and a
//! mixed `submit + complete` workload (the realistic I/O case).

#![cfg(feature = "test-internals")]

use asupersync::io::LabIoCap;
use criterion::{Criterion, criterion_group, criterion_main, BenchmarkId, Throughput};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

const OPS_PER_THREAD: u64 = 100_000;

fn bench_record_submit(c: &mut Criterion) {
    let mut group = c.benchmark_group("io_cap/record_submit");
    group.measurement_time(Duration::from_secs(3));
    group.warm_up_time(Duration::from_millis(500));

    for &threads in &[1usize, 2, 4, 8, 16] {
        let total_ops = OPS_PER_THREAD * threads as u64;
        group.throughput(Throughput::Elements(total_ops));
        group.bench_with_input(
            BenchmarkId::from_parameter(threads),
            &threads,
            |b, &threads| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let cap = Arc::new(LabIoCap::new_for_tests());
                        let barrier = Arc::new(Barrier::new(threads));
                        let mut handles = Vec::with_capacity(threads);
                        let start = std::time::Instant::now();
                        for _ in 0..threads {
                            let cap = Arc::clone(&cap);
                            let barrier = Arc::clone(&barrier);
                            handles.push(thread::spawn(move || {
                                barrier.wait();
                                for _ in 0..OPS_PER_THREAD {
                                    cap.record_submit();
                                }
                            }));
                        }
                        for h in handles {
                            h.join().expect("worker thread join");
                        }
                        total += start.elapsed();
                        // Validation: total submits across shards must
                        // equal threads × OPS_PER_THREAD. Catches a
                        // sharding bug (lost increments) before any
                        // perf claim.
                        assert_eq!(cap.submitted_total(), threads as u64 * OPS_PER_THREAD);
                    }
                    total
                });
            },
        );
    }
    group.finish();
}

fn bench_record_submit_complete_mixed(c: &mut Criterion) {
    let mut group = c.benchmark_group("io_cap/submit_complete_mixed");
    group.measurement_time(Duration::from_secs(3));
    group.warm_up_time(Duration::from_millis(500));

    // Mixed workload: each worker does record_submit + record_complete
    // back-to-back, modeling the realistic I/O lifecycle. Pre-fix this
    // was the worst case for false sharing because submit and complete
    // counters lived adjacent.
    for &threads in &[1usize, 2, 4, 8, 16] {
        let total_ops = OPS_PER_THREAD * threads as u64 * 2;
        group.throughput(Throughput::Elements(total_ops));
        group.bench_with_input(
            BenchmarkId::from_parameter(threads),
            &threads,
            |b, &threads| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let cap = Arc::new(LabIoCap::new_for_tests());
                        let barrier = Arc::new(Barrier::new(threads));
                        let mut handles = Vec::with_capacity(threads);
                        let start = std::time::Instant::now();
                        for _ in 0..threads {
                            let cap = Arc::clone(&cap);
                            let barrier = Arc::clone(&barrier);
                            handles.push(thread::spawn(move || {
                                barrier.wait();
                                for _ in 0..OPS_PER_THREAD {
                                    cap.record_submit();
                                    cap.record_complete();
                                }
                            }));
                        }
                        for h in handles {
                            h.join().expect("worker thread join");
                        }
                        total += start.elapsed();
                        assert_eq!(cap.submitted_total(), threads as u64 * OPS_PER_THREAD);
                        assert_eq!(cap.completed_total(), threads as u64 * OPS_PER_THREAD);
                    }
                    total
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = bench_record_submit, bench_record_submit_complete_mixed
);
criterion_main!(benches);
