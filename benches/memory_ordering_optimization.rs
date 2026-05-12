//! Benchmark for memory ordering optimizations in channel hot paths.
//!
//! Measures the performance impact of optimizing memory ordering from Acquire to Relaxed
//! for telemetry and API reads in broadcast and watch channels.

use asupersync::channel::broadcast;
use asupersync::channel::watch;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};

fn bench_broadcast_receiver_count_hot_path(c: &mut Criterion) {
    let (sender, _) = broadcast::channel::<u32>(16);

    c.bench_function("broadcast_receiver_count_hot_path", |b| {
        b.iter(|| {
            for _ in 0..1000 {
                black_box(sender.receiver_count());
            }
        })
    });
}

fn bench_watch_receiver_count_hot_path(c: &mut Criterion) {
    let (sender, _) = watch::channel(42u32);

    c.bench_function("watch_receiver_count_hot_path", |b| {
        b.iter(|| {
            for _ in 0..1000 {
                black_box(sender.receiver_count());
            }
        })
    });
}

fn bench_atomic_ordering_comparison(c: &mut Criterion) {
    let counter = AtomicUsize::new(0);

    c.bench_function("atomic_load_relaxed", |b| {
        b.iter(|| {
            for _ in 0..1000 {
                black_box(counter.load(Ordering::Relaxed));
            }
        })
    });

    c.bench_function("atomic_load_acquire", |b| {
        b.iter(|| {
            for _ in 0..1000 {
                black_box(counter.load(Ordering::Acquire));
            }
        })
    });
}

fn bench_broadcast_telemetry_snapshot(c: &mut Criterion) {
    let (sender, _) = broadcast::channel::<u32>(16);

    c.bench_function("broadcast_telemetry_snapshot", |b| {
        b.iter(|| {
            black_box(sender.telemetry_snapshot(1));
        })
    });
}

criterion_group!(
    memory_ordering_benches,
    bench_broadcast_receiver_count_hot_path,
    bench_watch_receiver_count_hot_path,
    bench_atomic_ordering_comparison,
    bench_broadcast_telemetry_snapshot
);
criterion_main!(memory_ordering_benches);
