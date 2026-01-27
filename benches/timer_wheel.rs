//! Timer wheel benchmarks for Asupersync.
//!
//! These benchmarks measure performance of the hierarchical timing wheel:
//! - Timer insertion (O(1) expected)
//! - Timer cancellation (O(1) expected)
//! - Time advancement/tick (O(expired) expected)
//! - Large-scale scenarios (10K timers)
//! - Coalescing overhead
//!
//! Performance targets:
//! - Insert: < 100ns per timer
//! - Cancel: < 50ns per timer
//! - Tick (no expiry): < 50ns per tick

#![allow(missing_docs)]
#![allow(clippy::semicolon_if_nothing_returned)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Wake, Waker};
use std::time::Duration;

use asupersync::time::{CoalescingConfig, TimerWheel, TimerWheelConfig};
use asupersync::types::Time;

// =============================================================================
// TEST WAKER
// =============================================================================

struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
    fn wake_by_ref(self: &Arc<Self>) {}
}

fn noop_waker() -> Waker {
    Arc::new(NoopWaker).into()
}

struct CounterWaker {
    counter: Arc<AtomicU64>,
}

impl Wake for CounterWaker {
    fn wake(self: Arc<Self>) {
        self.counter.fetch_add(1, Ordering::Relaxed);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.counter.fetch_add(1, Ordering::Relaxed);
    }
}

fn counter_waker(counter: Arc<AtomicU64>) -> Waker {
    Arc::new(CounterWaker { counter }).into()
}

// =============================================================================
// INSERTION BENCHMARKS
// =============================================================================

fn bench_timer_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("timer_wheel/insert");

    // Single insert
    group.bench_function("single", |b| {
        let mut wheel = TimerWheel::new();
        b.iter(|| {
            let handle = wheel.register(Time::from_millis(100), noop_waker());
            black_box(handle);
        });
    });

    // Insert into different time ranges
    group.bench_function("level0_1ms", |b| {
        let mut wheel = TimerWheel::new();
        b.iter(|| {
            let handle = wheel.register(Time::from_millis(1), noop_waker());
            black_box(handle);
        });
    });

    group.bench_function("level1_1s", |b| {
        let mut wheel = TimerWheel::new();
        b.iter(|| {
            let handle = wheel.register(Time::from_secs(1), noop_waker());
            black_box(handle);
        });
    });

    group.bench_function("level2_1min", |b| {
        let mut wheel = TimerWheel::new();
        b.iter(|| {
            let handle = wheel.register(Time::from_secs(60), noop_waker());
            black_box(handle);
        });
    });

    group.bench_function("level3_1h", |b| {
        let mut wheel = TimerWheel::new();
        b.iter(|| {
            let handle = wheel.register(Time::from_secs(3600), noop_waker());
            black_box(handle);
        });
    });

    group.bench_function("overflow_48h", |b| {
        let mut wheel = TimerWheel::new();
        b.iter(|| {
            let handle = wheel.register(Time::from_secs(48 * 3600), noop_waker());
            black_box(handle);
        });
    });

    group.finish();
}

// =============================================================================
// CANCELLATION BENCHMARKS
// =============================================================================

fn bench_timer_cancel(c: &mut Criterion) {
    let mut group = c.benchmark_group("timer_wheel/cancel");

    // Cancel (generation-based, O(1))
    group.bench_function("single", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            let mut wheel = TimerWheel::new();

            // Pre-register handles
            let handles: Vec<_> = (0..iters)
                .map(|i| wheel.register(Time::from_millis(100 + i), noop_waker()))
                .collect();

            let start = std::time::Instant::now();
            for handle in handles {
                black_box(wheel.cancel(&handle));
            }
            total += start.elapsed();
            total
        });
    });

    // Cancel already cancelled (should be fast - just HashMap lookup)
    group.bench_function("already_cancelled", |b| {
        let mut wheel = TimerWheel::new();
        let handle = wheel.register(Time::from_millis(100), noop_waker());
        wheel.cancel(&handle);

        b.iter(|| {
            black_box(wheel.cancel(&handle));
        });
    });

    group.finish();
}

// =============================================================================
// TICK/EXPIRY BENCHMARKS
// =============================================================================

fn bench_timer_tick(c: &mut Criterion) {
    let mut group = c.benchmark_group("timer_wheel/tick");

    // Tick with no timers
    group.bench_function("empty_wheel", |b| {
        let mut wheel = TimerWheel::new();
        let mut time = Time::ZERO;
        b.iter(|| {
            time = time.saturating_add_nanos(1_000_000); // 1ms
            let wakers = wheel.collect_expired(time);
            black_box(wakers);
        });
    });

    // Tick with timers but none expiring
    group.bench_function("no_expiry_100_timers", |b| {
        let mut wheel = TimerWheel::new();
        // All timers at 1 hour
        for _ in 0..100 {
            wheel.register(Time::from_secs(3600), noop_waker());
        }

        let mut time = Time::ZERO;
        b.iter(|| {
            time = time.saturating_add_nanos(1_000_000); // 1ms
            let wakers = wheel.collect_expired(time);
            black_box(wakers);
        });
    });

    // Tick with single expiry
    group.bench_function("single_expiry", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;

            for i in 0..iters {
                let mut wheel = TimerWheel::new();
                wheel.register(Time::from_millis(1), noop_waker());

                let start = std::time::Instant::now();
                let wakers = wheel.collect_expired(Time::from_millis(1 + i));
                total += start.elapsed();
                black_box(wakers);
            }
            total
        });
    });

    // Large time jump
    group.bench_function("large_jump_1h", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;

            for _ in 0..iters {
                let mut wheel = TimerWheel::new();
                wheel.register(Time::from_secs(3600), noop_waker());

                let start = std::time::Instant::now();
                let wakers = wheel.collect_expired(Time::from_secs(3600));
                total += start.elapsed();
                black_box(wakers);
            }
            total
        });
    });

    group.finish();
}

// =============================================================================
// THROUGHPUT BENCHMARKS (10K TIMERS)
// =============================================================================

fn bench_throughput_10k(c: &mut Criterion) {
    let mut group = c.benchmark_group("timer_wheel/throughput");

    for &size in &[1_000usize, 10_000usize] {
        let size_u64 = u64::try_from(size).expect("size fits u64");
        group.throughput(Throughput::Elements(size_u64));

        // Insert throughput
        group.bench_with_input(BenchmarkId::new("insert", size), &size, |b, &size| {
            b.iter(|| {
                let mut wheel = TimerWheel::new();
                for i in 0..size_u64 {
                    wheel.register(Time::from_millis(i + 1), noop_waker());
                }
                black_box(wheel.len());
            });
        });

        // Cancel throughput
        group.bench_with_input(BenchmarkId::new("cancel", size), &size, |b, &size| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;

                for _ in 0..iters {
                    let mut wheel = TimerWheel::new();
                    let handles: Vec<_> = (0..size_u64)
                        .map(|i| wheel.register(Time::from_millis(i + 1), noop_waker()))
                        .collect();

                    let start = std::time::Instant::now();
                    for handle in handles {
                        wheel.cancel(&handle);
                    }
                    total += start.elapsed();
                }
                total
            });
        });

        // Fire throughput (all at once)
        group.bench_with_input(BenchmarkId::new("fire_all", size), &size, |b, &size| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;

                for _ in 0..iters {
                    let mut wheel = TimerWheel::new();
                    let counter = Arc::new(AtomicU64::new(0));

                    // All timers at same deadline
                    for _ in 0..size {
                        wheel.register(Time::from_millis(100), counter_waker(counter.clone()));
                    }

                    let start = std::time::Instant::now();
                    let wakers = wheel.collect_expired(Time::from_millis(100));
                    for waker in &wakers {
                        waker.wake_by_ref();
                    }
                    total += start.elapsed();

                    assert_eq!(counter.load(Ordering::Relaxed), size_u64);
                }
                total
            });
        });
    }

    group.finish();
}

// =============================================================================
// COALESCING BENCHMARKS
// =============================================================================

fn bench_coalescing(c: &mut Criterion) {
    let mut group = c.benchmark_group("timer_wheel/coalescing");

    // Overhead of coalescing vs non-coalescing
    group.bench_function("disabled_100_timers", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;

            for _ in 0..iters {
                let mut wheel = TimerWheel::new(); // Coalescing disabled

                // 100 timers spread over 1ms
                for i in 0..100 {
                    wheel.register(Time::from_nanos(i * 10_000), noop_waker());
                }

                let start = std::time::Instant::now();
                let wakers = wheel.collect_expired(Time::from_millis(1));
                total += start.elapsed();
                black_box(wakers);
            }
            total
        });
    });

    group.bench_function("enabled_100_timers", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;

            for _ in 0..iters {
                let coalescing = CoalescingConfig::enabled_with_window(Duration::from_millis(1));
                let mut wheel =
                    TimerWheel::with_config(Time::ZERO, TimerWheelConfig::default(), coalescing);

                // 100 timers spread over 1ms
                for i in 0..100 {
                    wheel.register(Time::from_nanos(i * 10_000), noop_waker());
                }

                let start = std::time::Instant::now();
                let wakers = wheel.collect_expired(Time::from_millis(1));
                total += start.elapsed();
                black_box(wakers);
            }
            total
        });
    });

    // Coalescing group size calculation
    group.bench_function("group_size_calculation", |b| {
        let coalescing = CoalescingConfig::enabled_with_window(Duration::from_millis(1));
        let mut wheel =
            TimerWheel::with_config(Time::ZERO, TimerWheelConfig::default(), coalescing);

        // 100 timers spread over 0.5ms
        for i in 0..100 {
            wheel.register(Time::from_nanos(i * 5_000), noop_waker());
        }
        // Move timers to ready
        wheel.collect_expired(Time::ZERO);

        b.iter(|| {
            black_box(wheel.coalescing_group_size(Time::from_nanos(500_000)));
        });
    });

    group.finish();
}

// =============================================================================
// OVERFLOW HANDLING BENCHMARKS
// =============================================================================

fn bench_overflow(c: &mut Criterion) {
    let mut group = c.benchmark_group("timer_wheel/overflow");

    // Insert into overflow
    group.bench_function("insert_overflow", |b| {
        let mut wheel = TimerWheel::new();
        b.iter(|| {
            // 48 hours, definitely in overflow
            let handle = wheel.register(Time::from_secs(48 * 3600), noop_waker());
            black_box(handle);
        });
    });

    // Promotion from overflow
    group.bench_function("promote_100_overflow", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;

            for _ in 0..iters {
                let mut wheel = TimerWheel::new();

                // 100 timers in overflow (spread over 48-72 hours)
                for i in 0..100 {
                    wheel.register(Time::from_secs(48 * 3600 + i * 360), noop_waker());
                }
                assert!(wheel.overflow_count() >= 100);

                // Jump to 48 hours - should promote all
                let start = std::time::Instant::now();
                let wakers = wheel.collect_expired(Time::from_secs(72 * 3600));
                total += start.elapsed();

                assert_eq!(wakers.len(), 100);
            }
            total
        });
    });

    group.finish();
}

// =============================================================================
// CONFIGURATION BENCHMARKS
// =============================================================================

fn bench_config(c: &mut Criterion) {
    let mut group = c.benchmark_group("timer_wheel/config");

    // Default construction
    group.bench_function("new_default", |b| {
        b.iter(|| {
            black_box(TimerWheel::new());
        });
    });

    // Custom config construction
    group.bench_function("new_with_config", |b| {
        let config = TimerWheelConfig::new()
            .max_wheel_duration(Duration::from_secs(86400))
            .max_timer_duration(Duration::from_secs(604_800));
        let coalescing = CoalescingConfig::enabled_with_window(Duration::from_millis(1));

        b.iter(|| {
            black_box(TimerWheel::with_config(
                Time::ZERO,
                config.clone(),
                coalescing.clone(),
            ));
        });
    });

    // try_register validation overhead
    group.bench_function("try_register_validation", |b| {
        let config = TimerWheelConfig::new().max_timer_duration(Duration::from_secs(3600));
        let mut wheel = TimerWheel::with_config(Time::ZERO, config, CoalescingConfig::default());

        b.iter(|| {
            // Just under max
            let result = wheel.try_register(Time::from_secs(3599), noop_waker());
            let _ = black_box(result);
        });
    });

    group.finish();
}

// =============================================================================
// MAIN
// =============================================================================

criterion_group!(
    benches,
    bench_timer_insert,
    bench_timer_cancel,
    bench_timer_tick,
    bench_throughput_10k,
    bench_coalescing,
    bench_overflow,
    bench_config,
);

criterion_main!(benches);
