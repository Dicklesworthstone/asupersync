//! Benchmark atomic memory ordering performance impact.
//!
//! Measures the performance difference between SeqCst and weaker orderings
//! for common atomic operation patterns in the scheduler hot paths.

#![cfg(feature = "test-internals")]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;

/// Benchmark counter increment patterns with different orderings.
fn bench_counter_increment(c: &mut Criterion) {
    let mut group = c.benchmark_group("counter_increment");
    group.throughput(Throughput::Elements(1_000_000));

    let orderings = [("relaxed", Ordering::Relaxed), ("seqcst", Ordering::SeqCst)];

    for (name, ordering) in orderings {
        group.bench_with_input(
            BenchmarkId::new("single_thread", name),
            &ordering,
            |b, &ordering| {
                let counter = AtomicU64::new(0);
                b.iter(|| {
                    for _ in 0..1_000_000 {
                        black_box(counter.fetch_add(1, ordering));
                    }
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("multi_thread_4", name),
            &ordering,
            |b, &ordering| {
                let counter = Arc::new(AtomicU64::new(0));
                b.iter(|| {
                    let handles: Vec<_> = (0..4)
                        .map(|_| {
                            let counter = Arc::clone(&counter);
                            thread::spawn(move || {
                                for _ in 0..250_000 {
                                    black_box(counter.fetch_add(1, ordering));
                                }
                            })
                        })
                        .collect();

                    for handle in handles {
                        handle.join().unwrap();
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark flag operations with different orderings.
fn bench_flag_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("flag_operations");
    group.throughput(Throughput::Elements(1_000_000));

    let test_cases = [
        (
            "store_relaxed_load_relaxed",
            Ordering::Relaxed,
            Ordering::Relaxed,
        ),
        (
            "store_release_load_acquire",
            Ordering::Release,
            Ordering::Acquire,
        ),
        (
            "store_seqcst_load_seqcst",
            Ordering::SeqCst,
            Ordering::SeqCst,
        ),
    ];

    for (name, store_ordering, load_ordering) in test_cases {
        group.bench_with_input(
            BenchmarkId::new("single_thread", name),
            &(store_ordering, load_ordering),
            |b, &(store_ordering, load_ordering)| {
                let flag = AtomicBool::new(false);
                b.iter(|| {
                    for i in 0..1_000_000 {
                        flag.store(i % 2 == 0, store_ordering);
                        black_box(flag.load(load_ordering));
                    }
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("producer_consumer", name),
            &(store_ordering, load_ordering),
            |b, &(store_ordering, load_ordering)| {
                let flag = Arc::new(AtomicBool::new(false));
                b.iter(|| {
                    let producer_flag = Arc::clone(&flag);
                    let consumer_flag = Arc::clone(&flag);

                    let producer = thread::spawn(move || {
                        for i in 0..500_000 {
                            producer_flag.store(i % 2 == 0, store_ordering);
                        }
                    });

                    let consumer = thread::spawn(move || {
                        for _ in 0..500_000 {
                            black_box(consumer_flag.load(load_ordering));
                        }
                    });

                    producer.join().unwrap();
                    consumer.join().unwrap();
                });
            },
        );
    }

    group.finish();
}

/// Benchmark scheduler-like counter patterns.
fn bench_scheduler_counter_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler_counters");
    group.throughput(Throughput::Elements(100_000));

    // Simulate pattern from scheduler where multiple counters are updated
    let orderings = [("relaxed", Ordering::Relaxed), ("seqcst", Ordering::SeqCst)];

    for (name, ordering) in orderings {
        group.bench_with_input(
            BenchmarkId::new("multi_counter", name),
            &ordering,
            |b, &ordering| {
                let task_count = Arc::new(AtomicU64::new(0));
                let wake_count = Arc::new(AtomicU64::new(0));
                let steal_count = Arc::new(AtomicU64::new(0));

                b.iter(|| {
                    let handles: Vec<_> = (0..4)
                        .map(|_| {
                            let task_count = Arc::clone(&task_count);
                            let wake_count = Arc::clone(&wake_count);
                            let steal_count = Arc::clone(&steal_count);

                            thread::spawn(move || {
                                for i in 0..25_000 {
                                    task_count.fetch_add(1, ordering);
                                    if i % 3 == 0 {
                                        wake_count.fetch_add(1, ordering);
                                    }
                                    if i % 7 == 0 {
                                        steal_count.fetch_add(1, ordering);
                                    }
                                }
                            })
                        })
                        .collect();

                    for handle in handles {
                        handle.join().unwrap();
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_counter_increment,
    bench_flag_operations,
    bench_scheduler_counter_patterns
);
criterion_main!(benches);
