#![cfg(feature = "test-internals")]
//! Spawn-throughput benchmark: direct vs mailbox admission
//! (br-asupersync-dx-core-api-v2-u1z5hn.1.3, parent AC 4).
//!
//! Measures the full runtime spawn path — `RuntimeHandle::spawn` through
//! task completion — under single-producer and contended multi-producer
//! loads, in both `SpawnAdmissionMode::Direct` (state lock per spawn) and
//! `SpawnAdmissionMode::Mailbox` (lock-free enqueue, worker-side batch
//! admission). The contended case is the one the mailbox exists for: the
//! direct path serializes every producer on the `RuntimeState` lock.
//!
//! Deterministic inputs; throughput in spawned tasks per second.

#![allow(missing_docs)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use asupersync::runtime::builder::{Runtime, RuntimeBuilder};
use asupersync::runtime::config::SpawnAdmissionMode;

const SPAWNS_PER_ITER: usize = 1_000;

fn build_runtime(mode: SpawnAdmissionMode, workers: usize) -> Runtime {
    RuntimeBuilder::new()
        .worker_threads(workers)
        .spawn_admission(mode)
        .build()
        .expect("build benchmark runtime")
}

/// Spawn `SPAWNS_PER_ITER` trivial tasks from one producer thread and wait
/// for all of them to finish (completion observed via a shared counter so
/// the measurement covers admission + execution, not just enqueue).
fn spawn_burst_single(runtime: &Runtime, counter: &Arc<AtomicUsize>) {
    let handle = runtime.handle();
    counter.store(0, Ordering::SeqCst);
    for _ in 0..SPAWNS_PER_ITER {
        let counter = Arc::clone(counter);
        drop(handle.spawn(async move {
            counter.fetch_add(1, Ordering::Relaxed);
        }));
    }
    while counter.load(Ordering::SeqCst) < SPAWNS_PER_ITER {
        std::hint::spin_loop();
    }
}

/// Spawn from `producers` OS threads concurrently (SPAWNS_PER_ITER total),
/// then wait for completion. This is the lock-contention scenario.
fn spawn_burst_contended(runtime: &Runtime, counter: &Arc<AtomicUsize>, producers: usize) {
    let per_producer = SPAWNS_PER_ITER / producers;
    counter.store(0, Ordering::SeqCst);
    std::thread::scope(|scope| {
        for _ in 0..producers {
            let handle = runtime.handle();
            let counter = Arc::clone(counter);
            scope.spawn(move || {
                for _ in 0..per_producer {
                    let counter = Arc::clone(&counter);
                    drop(handle.spawn(async move {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }));
                }
            });
        }
    });
    let expected = per_producer * producers;
    while counter.load(Ordering::SeqCst) < expected {
        std::hint::spin_loop();
    }
}

fn bench_spawn_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("spawn_throughput");
    group.throughput(Throughput::Elements(SPAWNS_PER_ITER as u64));
    group.sample_size(20);

    for (label, mode) in [
        ("direct", SpawnAdmissionMode::Direct),
        ("mailbox", SpawnAdmissionMode::Mailbox),
    ] {
        let runtime = build_runtime(mode, 4);
        let counter = Arc::new(AtomicUsize::new(0));
        group.bench_function(BenchmarkId::new("single_producer", label), |b| {
            b.iter(|| spawn_burst_single(black_box(&runtime), &counter));
        });
        drop(runtime);

        for producers in [4usize, 8] {
            let runtime = build_runtime(mode, 4);
            let counter = Arc::new(AtomicUsize::new(0));
            group.bench_function(
                BenchmarkId::new(format!("contended_{producers}_producers"), label),
                |b| {
                    b.iter(|| {
                        spawn_burst_contended(black_box(&runtime), &counter, producers);
                    });
                },
            );
            drop(runtime);
        }
    }

    group.finish();
}

criterion_group!(benches, bench_spawn_throughput);
criterion_main!(benches);
