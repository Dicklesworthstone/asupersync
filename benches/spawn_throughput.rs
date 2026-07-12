#![cfg(feature = "test-internals")]
//! Spawn-throughput and join-completion benchmarks: direct vs mailbox admission
//! (br-asupersync-dx-core-api-v2-u1z5hn.1.3, parent AC 4).
//!
//! Measures the full runtime spawn path — `RuntimeHandle::spawn` through
//! task completion — under single-producer and contended multi-producer
//! loads, in both `SpawnAdmissionMode::Direct` (state lock per spawn) and
//! `SpawnAdmissionMode::Mailbox` (lock-free enqueue, worker-side batch
//! admission). The contended case is the one the mailbox exists for: the
//! direct path serializes every producer on the `RuntimeState` lock.
//! The join-completion group measures the caller-visible cost of collecting
//! completed [`TaskHandle`](asupersync::runtime::TaskHandle) values in the same
//! deterministic batch shape.
//! The spawn-throughput groups stop when every task body has executed. Runtime
//! task-record teardown may trail a body counter: repeated iterations amortize
//! most cleanup into later samples, while the final cleanup tail can fall
//! outside the measurement.
//!
//! Deterministic inputs; throughput in spawned tasks per second.

#![allow(missing_docs)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::time::Duration;

use asupersync::runtime::builder::{Runtime, RuntimeBuilder};
use asupersync::runtime::config::SpawnAdmissionMode;

const SPAWNS_PER_ITER: usize = 1_000;

struct CompletionLatch {
    completed: AtomicUsize,
    wait_lock: Mutex<()>,
    ready: Condvar,
}

impl CompletionLatch {
    fn new() -> Self {
        Self {
            completed: AtomicUsize::new(0),
            wait_lock: Mutex::new(()),
            ready: Condvar::new(),
        }
    }

    fn reset(&self) {
        self.completed.store(0, Ordering::SeqCst);
    }

    fn complete(&self, expected: usize) {
        let completed = self.completed.fetch_add(1, Ordering::Release) + 1;
        if completed == expected {
            let _guard = self
                .wait_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.ready.notify_one();
        }
    }

    fn wait(&self, expected: usize) {
        let guard = self
            .wait_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_guard, timeout) = self
            .ready
            .wait_timeout_while(guard, Duration::from_secs(30), |_| {
                self.completed.load(Ordering::Acquire) < expected
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let completed = self.completed.load(Ordering::Acquire);
        assert_eq!(
            completed,
            expected,
            "benchmark task-body completion mismatch (timed_out={})",
            timeout.timed_out()
        );
    }
}

struct ProducerStopGuard<'a> {
    stop: &'a AtomicBool,
    start: &'a Barrier,
}

impl Drop for ProducerStopGuard<'_> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.start.wait();
    }
}

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
fn spawn_burst_single(runtime: &Runtime, completion: &Arc<CompletionLatch>) {
    let handle = runtime.handle();
    completion.reset();
    for _ in 0..SPAWNS_PER_ITER {
        let completion = Arc::clone(completion);
        drop(handle.spawn(async move {
            completion.complete(SPAWNS_PER_ITER);
        }));
    }
    completion.wait(SPAWNS_PER_ITER);
}

/// Release persistent producer threads for one exact burst, wait until every
/// spawn call has returned, then wait for every task body to execute.
fn run_contended_iteration(
    completion: &CompletionLatch,
    start: &Barrier,
    submitted: &Barrier,
    producer_failed: &AtomicBool,
    expected: usize,
) {
    completion.reset();
    start.wait();
    submitted.wait();
    assert!(
        !producer_failed.load(Ordering::Acquire),
        "a persistent producer panicked while submitting its burst"
    );
    completion.wait(expected);
}

/// Spawn `SPAWNS_PER_ITER` trivial tasks and await every returned handle.
///
/// This isolates the handle-completion collection path that higher-level
/// fan-out helpers build on, while keeping the task body itself constant and
/// deterministic.
fn join_handle_completion_batch(runtime: &Runtime) {
    runtime.block_on(async {
        let handle = Runtime::current_handle().expect("block_on installs runtime handle");
        let mut joins = Vec::with_capacity(SPAWNS_PER_ITER);
        for value in 0..SPAWNS_PER_ITER {
            joins.push(handle.spawn(async move { value }));
        }

        let mut checksum = 0usize;
        for join in joins {
            checksum = checksum.wrapping_add(join.await);
        }
        black_box(checksum);
    });
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
        let completion = Arc::new(CompletionLatch::new());
        group.bench_function(BenchmarkId::new("single_producer_latched", label), |b| {
            b.iter(|| spawn_burst_single(black_box(&runtime), &completion));
        });
        drop(runtime);

        for producers in [4usize, 8] {
            assert_eq!(
                SPAWNS_PER_ITER % producers,
                0,
                "the benchmark must divide work evenly across producers"
            );
            let per_producer = SPAWNS_PER_ITER / producers;
            let runtime = build_runtime(mode, 4);
            let completion = Arc::new(CompletionLatch::new());
            let ready = Arc::new(Barrier::new(producers + 1));
            let start = Arc::new(Barrier::new(producers + 1));
            let submitted = Arc::new(Barrier::new(producers + 1));
            let stop = Arc::new(AtomicBool::new(false));
            let producer_failed = Arc::new(AtomicBool::new(false));

            std::thread::scope(|scope| {
                for _ in 0..producers {
                    let handle = runtime.handle();
                    let completion = Arc::clone(&completion);
                    let ready = Arc::clone(&ready);
                    let start = Arc::clone(&start);
                    let submitted = Arc::clone(&submitted);
                    let stop = Arc::clone(&stop);
                    let producer_failed = Arc::clone(&producer_failed);

                    scope.spawn(move || {
                        ready.wait();
                        loop {
                            start.wait();
                            if stop.load(Ordering::Acquire) {
                                break;
                            }

                            let submitted_without_panic = catch_unwind(AssertUnwindSafe(|| {
                                for _ in 0..per_producer {
                                    let completion = Arc::clone(&completion);
                                    drop(handle.spawn(async move {
                                        completion.complete(SPAWNS_PER_ITER);
                                    }));
                                }
                            }))
                            .is_ok();
                            if !submitted_without_panic {
                                producer_failed.store(true, Ordering::Release);
                            }
                            submitted.wait();
                        }
                    });
                }

                ready.wait();
                let _stop_guard = ProducerStopGuard {
                    stop: &stop,
                    start: &start,
                };

                group.bench_function(
                    BenchmarkId::new(
                        format!("contended_persistent_latched_{producers}_producers"),
                        label,
                    ),
                    |b| {
                        b.iter(|| {
                            run_contended_iteration(
                                &completion,
                                &start,
                                &submitted,
                                &producer_failed,
                                SPAWNS_PER_ITER,
                            );
                        });
                    },
                );
            });
            drop(runtime);
        }
    }

    group.finish();
}

fn bench_join_handle_completion(c: &mut Criterion) {
    let mut group = c.benchmark_group("join_handle_completion");
    group.throughput(Throughput::Elements(SPAWNS_PER_ITER as u64));
    group.sample_size(20);

    for (label, mode) in [
        ("direct", SpawnAdmissionMode::Direct),
        ("mailbox", SpawnAdmissionMode::Mailbox),
    ] {
        let runtime = build_runtime(mode, 4);
        group.bench_function(BenchmarkId::new("spawn_then_await_all", label), |b| {
            b.iter(|| join_handle_completion_batch(black_box(&runtime)));
        });
        drop(runtime);
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_spawn_throughput,
    bench_join_handle_completion
);
criterion_main!(benches);
