//! Virtual time wheel profiling harness: cancel storm performance analysis
//!
//! Targets potential bottlenecks:
//! 1. cleanup_cancelled() - O(n log n) heap ID collection + BTreeSet operations
//! 2. BinaryHeap rebalancing during mass pop operations
//! 3. BTreeSet cancelled.remove() during advance_to() iterations
//!
//! Usage:
//! cargo build --profile release-perf --bench virtual_time_wheel_cancel_storm
//! samply record --save-only -o wheel_cancel_storm.json -- ./target/release-perf/deps/virtual_time_wheel_cancel_storm-*

use asupersync::lab::virtual_time_wheel::VirtualTimerWheel;
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, RawWaker, RawWakerVTable, Waker};

/// Lightweight waker for benchmarking (doesn't actually wake anything)
fn noop_waker() -> Waker {
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(std::ptr::null(), &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );

    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
}

/// Counting waker to verify operations
#[derive(Debug)]
struct CountingWaker {
    wake_count: AtomicUsize,
}

impl CountingWaker {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            wake_count: AtomicUsize::new(0),
        })
    }

    fn wake_count(&self) -> usize {
        self.wake_count.load(Ordering::Acquire)
    }

    fn reset(&self) {
        self.wake_count.store(0, Ordering::Release);
    }
}

fn counting_waker(counter: Arc<CountingWaker>) -> Waker {
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |data| {
            let counter = unsafe { Arc::from_raw(data as *const CountingWaker) };
            let cloned = counter.clone();
            std::mem::forget(counter);
            RawWaker::new(Arc::into_raw(cloned) as *const (), &VTABLE)
        },
        |data| {
            let counter = unsafe { Arc::from_raw(data as *const CountingWaker) };
            counter.wake_count.fetch_add(1, Ordering::AcqRel);
            std::mem::forget(counter);
        },
        |data| {
            let counter = unsafe { &*(data as *const CountingWaker) };
            counter.wake_count.fetch_add(1, Ordering::AcqRel);
        },
        |data| unsafe {
            Arc::from_raw(data as *const CountingWaker);
        },
    );

    unsafe { Waker::from_raw(RawWaker::new(Arc::into_raw(counter) as *const (), &VTABLE)) }
}

/// Cancel storm scenario: insert many timers, cancel most, then advance
fn bench_cancel_storm(c: &mut Criterion) {
    let mut group = c.benchmark_group("virtual_time_wheel_cancel_storm");

    // Test different scales to identify algorithmic complexity
    let timer_counts = [1000, 2500, 5000, 10000, 20000];

    for &timer_count in &timer_counts {
        group.throughput(Throughput::Elements(timer_count as u64));

        group.bench_with_input(
            BenchmarkId::new("insert_cancel_advance", timer_count),
            &timer_count,
            |b, &timer_count| {
                b.iter_with_setup(
                    || {
                        // Setup: Create wheel and pre-generate wakers for reuse
                        let mut wheel = VirtualTimerWheel::new();
                        let counter = CountingWaker::new();
                        let waker = counting_waker(counter.clone());

                        // Insert timers spread across time range
                        let mut handles = Vec::with_capacity(timer_count);
                        for i in 0..timer_count {
                            let deadline = (i % 1000) as u64 + 1; // Spread across 1000 ticks
                            let handle = wheel.insert(deadline, waker.clone());
                            handles.push(handle);
                        }

                        (wheel, handles, counter)
                    },
                    |(mut wheel, handles, counter)| {
                        // PROFILING TARGET 1: Cancel storm (90% of timers)
                        let cancel_count = (timer_count * 9) / 10;
                        for handle in handles.into_iter().take(cancel_count) {
                            wheel.cancel(handle);
                        }

                        // PROFILING TARGET 2: Advance through all timers
                        // This triggers cleanup_cancelled() and BinaryHeap operations
                        let expired = black_box(wheel.advance_to(1000));

                        // Verify correctness
                        let expected_remaining = timer_count - cancel_count;
                        assert!(
                            expired.len() <= expected_remaining,
                            "Too many timers fired: {} > {}",
                            expired.len(),
                            expected_remaining
                        );

                        black_box(counter.wake_count());
                    },
                );
            },
        );
    }

    group.finish();
}

/// Benchmark just the cleanup_cancelled operation in isolation
fn bench_cleanup_cancelled_isolation(c: &mut Criterion) {
    let mut group = c.benchmark_group("cleanup_cancelled_isolation");

    let timer_counts = [1000, 5000, 10000, 25000];

    for &timer_count in &timer_counts {
        group.bench_with_input(
            BenchmarkId::new("cleanup_heavy_cancellation", timer_count),
            &timer_count,
            |b, &timer_count| {
                b.iter_with_setup(
                    || {
                        let mut wheel = VirtualTimerWheel::new();
                        let waker = noop_waker();
                        let mut handles = Vec::with_capacity(timer_count);

                        // Insert timers
                        for i in 0..timer_count {
                            let deadline = (i % 100) as u64 + 1;
                            let handle = wheel.insert(deadline, waker.clone());
                            handles.push(handle);
                        }

                        // Cancel 80% to create a large cancelled set
                        let cancel_count = (timer_count * 8) / 10;
                        for handle in handles.into_iter().take(cancel_count) {
                            wheel.cancel(handle);
                        }

                        wheel
                    },
                    |mut wheel| {
                        // PROFILING TARGET: This forces cleanup_cancelled() execution
                        // Expected bottleneck: BTreeSet creation from heap iteration
                        let expired = black_box(wheel.advance_to(101));
                        black_box(expired);
                    },
                );
            },
        );
    }

    group.finish();
}

/// Benchmark heap operations under different cancellation patterns
fn bench_heap_rebalance_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("heap_rebalance_patterns");

    // Test different cancellation patterns
    group.bench_function("sequential_cancel_advance", |b| {
        b.iter_with_setup(
            || {
                let mut wheel = VirtualTimerWheel::new();
                let waker = noop_waker();
                let timer_count = 10000;
                let mut handles = Vec::with_capacity(timer_count);

                // Insert timers with sequential deadlines
                for i in 0..timer_count {
                    let handle = wheel.insert(i as u64 + 1, waker.clone());
                    handles.push(handle);
                }

                // Cancel every other timer (creates interleaved pattern)
                for (idx, handle) in handles.into_iter().enumerate() {
                    if idx % 2 == 0 {
                        wheel.cancel(handle);
                    }
                }

                wheel
            },
            |mut wheel| {
                // Advance through all timers - measures heap.pop() + cancelled.remove()
                let expired = black_box(wheel.advance_to(10001));
                black_box(expired);
            },
        );
    });

    group.bench_function("random_deadline_cancel_storm", |b| {
        b.iter_with_setup(
            || {
                let mut wheel = VirtualTimerWheel::new();
                let waker = noop_waker();
                let timer_count = 10000;
                let mut handles = Vec::with_capacity(timer_count);

                // Insert timers with random-ish deadlines (creates heap churn)
                for i in 0..timer_count {
                    let deadline = ((i * 17 + 42) % 1000) as u64 + 1;
                    let handle = wheel.insert(deadline, waker.clone());
                    handles.push(handle);
                }

                // Cancel most timers to stress cleanup path
                for handle in handles.into_iter().take((timer_count * 95) / 100) {
                    wheel.cancel(handle);
                }

                wheel
            },
            |mut wheel| {
                let expired = black_box(wheel.advance_to(1001));
                black_box(expired);
            },
        );
    });

    group.finish();
}

/// Benchmark next_deadline() which has a hot loop for cancelled timer cleanup
fn bench_next_deadline_cancelled_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("next_deadline_cancelled_scan");

    group.bench_function("scan_cancelled_heavy", |b| {
        b.iter_with_setup(
            || {
                let mut wheel = VirtualTimerWheel::new();
                let waker = noop_waker();
                let timer_count = 5000;

                // Insert timers, but cancel the earliest ones
                // This forces next_deadline() to scan through many cancelled entries
                for i in 0..timer_count {
                    let handle = wheel.insert(i as u64 + 1, waker.clone());
                    if i < (timer_count * 9) / 10 {
                        // Cancel 90% of earliest timers
                        wheel.cancel(handle);
                    }
                }

                wheel
            },
            |mut wheel| {
                // PROFILING TARGET: Scans through cancelled timers to find next valid deadline
                let deadline = black_box(wheel.next_deadline());
                black_box(deadline);
            },
        );
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_cancel_storm,
    bench_cleanup_cancelled_isolation,
    bench_heap_rebalance_patterns,
    bench_next_deadline_cancelled_scan
);
criterion_main!(benches);
