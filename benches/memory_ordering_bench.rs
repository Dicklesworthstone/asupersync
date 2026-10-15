//! Memory ordering benchmark for atomic operations
//!
//! Measures performance impact of different atomic ordering choices
//! to validate optimization benefits.

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

fn bench_counter_orderings(c: &mut Criterion) {
    let mut group = c.benchmark_group("atomic_counters");

    // Single-threaded counter benchmarks
    group.bench_function("counter_seqcst", |b| {
        let counter = AtomicU64::new(0);
        b.iter(|| {
            for _ in 0..1000 {
                black_box(counter.fetch_add(1, Ordering::SeqCst));
            }
        });
    });

    group.bench_function("counter_relaxed", |b| {
        let counter = AtomicU64::new(0);
        b.iter(|| {
            for _ in 0..1000 {
                black_box(counter.fetch_add(1, Ordering::Relaxed));
            }
        });
    });

    // Multi-threaded counter benchmarks
    group.bench_function("counter_seqcst_mt", |b| {
        b.iter(|| {
            let counter = Arc::new(AtomicU64::new(0));
            let mut handles = Vec::new();

            for _ in 0..4 {
                let counter = Arc::clone(&counter);
                handles.push(thread::spawn(move || {
                    for _ in 0..250 {
                        counter.fetch_add(1, Ordering::SeqCst);
                    }
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }

            black_box(counter.load(Ordering::SeqCst));
        });
    });

    group.bench_function("counter_relaxed_mt", |b| {
        b.iter(|| {
            let counter = Arc::new(AtomicU64::new(0));
            let mut handles = Vec::new();

            for _ in 0..4 {
                let counter = Arc::clone(&counter);
                handles.push(thread::spawn(move || {
                    for _ in 0..250 {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }

            black_box(counter.load(Ordering::Relaxed));
        });
    });

    group.finish();
}

fn bench_flag_orderings(c: &mut Criterion) {
    let mut group = c.benchmark_group("atomic_flags");

    // Store/load patterns for boolean flags
    group.bench_function("flag_seqcst", |b| {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        b.iter(|| {
            flag.store(true, Ordering::SeqCst);
            black_box(flag.load(Ordering::SeqCst));
        });
    });

    group.bench_function("flag_acq_rel", |b| {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        b.iter(|| {
            flag.store(true, Ordering::Release);
            black_box(flag.load(Ordering::Acquire));
        });
    });

    group.bench_function("flag_relaxed", |b| {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        b.iter(|| {
            flag.store(true, Ordering::Relaxed);
            black_box(flag.load(Ordering::Relaxed));
        });
    });

    group.finish();
}

fn bench_id_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("id_generation");

    // Simulate ID generator patterns
    group.bench_function("id_gen_seqcst", |b| {
        let next_id = Arc::new(AtomicU64::new(1));
        b.iter(|| {
            for _ in 0..1000 {
                black_box(next_id.fetch_add(1, Ordering::SeqCst));
            }
        });
    });

    group.bench_function("id_gen_relaxed", |b| {
        let next_id = Arc::new(AtomicU64::new(1));
        b.iter(|| {
            for _ in 0..1000 {
                black_box(next_id.fetch_add(1, Ordering::Relaxed));
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_counter_orderings,
    bench_flag_orderings,
    bench_id_generation
);
criterion_main!(benches);
