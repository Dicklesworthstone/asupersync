//! Timer wheel benchmarks for Asupersync.
//!
//! These benchmarks measure performance of the hierarchical timing wheel
//! and compare it against alternative data structures:
//!
//! ## Wheel-only benchmarks
//! - Timer insertion (O(1) expected)
//! - Timer cancellation (O(1) expected)
//! - Time advancement/tick (O(expired) expected)
//! - Large-scale scenarios (10K timers)
//! - Coalescing overhead
//!
//! ## Comparison benchmarks
//! - BTreeMap<u64, Vec<Waker>> — ordered map (O(log n) insert/remove)
//! - BinaryHeap<(Reverse<u64>, Waker)> — priority queue (O(log n) push/pop)
//! - Vec<(u64, Waker)> — unsorted vector (O(1) push, O(n) scan)
//!
//! Performance targets:
//! - Insert: < 100ns per timer
//! - Cancel: < 50ns per timer
//! - Tick (no expiry): < 50ns per tick
//!
//! ## Benchmark Results (10K timers)
//!
//! Run: `cargo bench --bench timer_wheel -- comparison/`
//!
//! ### Insert (10K elements)
//! | Structure    | Time      | Throughput     | vs. Wheel |
//! |-------------|-----------|----------------|-----------|
//! | TimerWheel  | 1.28 ms   | 7.83 Melem/s   | 1.00x     |
//! | BTreeMap    | 2.26 ms   | 4.43 Melem/s   | 1.76x slower |
//! | BinaryHeap  | 1.18 ms   | 8.47 Melem/s   | 0.92x     |
//! | Vec         | 0.48 ms   | 20.86 Melem/s  | 0.37x     |
//!
//! ### Cancel (10K elements)
//! | Structure    | Time      | Throughput     | vs. Wheel |
//! |-------------|-----------|----------------|-----------|
//! | TimerWheel  | 0.52 ms   | 19.39 Melem/s  | 1.00x     |
//! | BTreeMap    | 1.38 ms   | 7.26 Melem/s   | 2.67x slower |
//! | BinaryHeap  | 0.58 ms   | 17.19 Melem/s  | 1.13x slower |
//! | Vec         | 21.42 ms  | 0.47 Melem/s   | 41.2x slower |
//!
//! ### Expire All (10K elements)
//! | Structure    | Time      | Throughput     | vs. Wheel |
//! |-------------|-----------|----------------|-----------|
//! | TimerWheel  | 1.67 ms   | 5.98 Melem/s   | 1.00x     |
//! | BTreeMap    | 0.24 ms   | 41.56 Melem/s  | 0.14x     |
//! | BinaryHeap  | 0.89 ms   | 11.18 Melem/s  | 0.53x     |
//! | Vec         | 0.13 ms   | 74.54 Melem/s  | 0.08x     |
//!
//! ### Mixed Workload (10K elements: insert + cancel 1/3 + expire in steps)
//! | Structure    | Time      | Throughput     | vs. Wheel |
//! |-------------|-----------|----------------|-----------|
//! | TimerWheel  | 3.27 ms   | 3.06 Melem/s   | 1.00x     |
//! | BTreeMap    | 3.05 ms   | 3.28 Melem/s   | 0.93x     |
//! | BinaryHeap  | 2.25 ms   | 4.44 Melem/s   | 0.69x     |
//! | Vec         | 13.20 ms  | 0.76 Melem/s   | 4.04x slower |
//!
//! ### Analysis
//!
//! The timer wheel trades raw throughput for consistency:
//! - **Cancel**: 2.67x faster than BTreeMap at 10K. This is the primary
//!   advantage — O(1) generation-based cancel vs. O(log n) tree removal.
//! - **Insert**: 1.76x faster than BTreeMap. O(1) slot placement vs. O(log n)
//!   tree insertion.
//! - **Expire**: BTreeMap wins at bulk expiry because `split_off` moves entire
//!   subtrees in O(log n). The wheel must traverse slots. Vec wins because
//!   `retain` is a single sequential scan.
//! - **Mixed**: Roughly competitive with BTreeMap; cancel advantage offsets
//!   expire overhead. Vec collapses due to O(n) cancel.
//! - **Vec** is fastest for insert and expire (sequential memory) but O(n)
//!   cancel makes it unusable at scale.
//!
//! The wheel's real advantage shows in the *cancel* path, which is critical
//! for connection timeout management where most timers are cancelled before
//! expiry (typical server pattern).

#![allow(missing_docs)]
#![allow(clippy::semicolon_if_nothing_returned)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::{BTreeMap, BinaryHeap};
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
        group.bench_with_input(BenchmarkId::new("insert", size), &size, |b, &_size| {
            b.iter(|| {
                let mut wheel = TimerWheel::new();
                for i in 0..size_u64 {
                    wheel.register(Time::from_millis(i + 1), noop_waker());
                }
                black_box(wheel.len());
            });
        });

        // Cancel throughput
        group.bench_with_input(BenchmarkId::new("cancel", size), &size, |b, &_size| {
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
        group.bench_with_input(BenchmarkId::new("fire_all", size), &size, |b, &_size| {
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
// ALTERNATIVE IMPLEMENTATIONS (for comparison)
// =============================================================================

/// BTreeMap-based timer store: O(log n) insert, O(log n) remove, O(k) expire.
struct BTreeTimers {
    /// deadline_nanos → list of wakers at that deadline.
    map: BTreeMap<u64, Vec<Waker>>,
    /// reverse index for O(log n) cancel by id.
    id_to_deadline: std::collections::HashMap<u64, u64>,
    next_id: u64,
}

impl BTreeTimers {
    fn new() -> Self {
        Self {
            map: BTreeMap::new(),
            id_to_deadline: std::collections::HashMap::new(),
            next_id: 0,
        }
    }

    fn insert(&mut self, deadline_nanos: u64, waker: Waker) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.map.entry(deadline_nanos).or_default().push(waker);
        self.id_to_deadline.insert(id, deadline_nanos);
        id
    }

    fn cancel(&mut self, id: u64) -> bool {
        if let Some(deadline) = self.id_to_deadline.remove(&id) {
            if let std::collections::btree_map::Entry::Occupied(mut entry) =
                self.map.entry(deadline)
            {
                let wakers = entry.get_mut();
                if wakers.len() <= 1 {
                    entry.remove();
                } else {
                    wakers.pop(); // approximate — removes last, not specific id
                }
            }
            true
        } else {
            false
        }
    }

    fn collect_expired(&mut self, now_nanos: u64) -> Vec<Waker> {
        let mut expired = Vec::new();
        // Split off all entries up to and including `now`.
        let remaining = self.map.split_off(&(now_nanos + 1));
        for (_deadline, wakers) in std::mem::replace(&mut self.map, remaining) {
            expired.extend(wakers);
        }
        expired
    }

    fn len(&self) -> usize {
        self.id_to_deadline.len()
    }
}

/// BinaryHeap-based timer store: O(log n) push, O(n) cancel, O(k log n) expire.
struct HeapTimers {
    heap: BinaryHeap<std::cmp::Reverse<(u64, u64)>>, // Reverse for min-heap by (deadline, id)
    wakers: std::collections::HashMap<u64, Waker>,
    next_id: u64,
}

impl HeapTimers {
    fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
            wakers: std::collections::HashMap::new(),
            next_id: 0,
        }
    }

    fn insert(&mut self, deadline_nanos: u64, waker: Waker) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.heap.push(std::cmp::Reverse((deadline_nanos, id)));
        self.wakers.insert(id, waker);
        id
    }

    fn cancel(&mut self, id: u64) -> bool {
        // Lazy deletion: mark removed but leave in heap.
        self.wakers.remove(&id).is_some()
    }

    fn collect_expired(&mut self, now_nanos: u64) -> Vec<Waker> {
        let mut expired = Vec::new();
        while let Some(&std::cmp::Reverse((deadline, id))) = self.heap.peek() {
            if deadline > now_nanos {
                break;
            }
            self.heap.pop();
            if let Some(waker) = self.wakers.remove(&id) {
                expired.push(waker);
            }
            // else: cancelled entry, skip
        }
        expired
    }

    fn len(&self) -> usize {
        self.wakers.len()
    }
}

/// Vec-based timer store: O(1) push, O(n) cancel, O(n) expire.
struct VecTimers {
    entries: Vec<(u64, u64, Option<Waker>)>, // (deadline_nanos, id, waker)
    next_id: u64,
}

impl VecTimers {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_id: 0,
        }
    }

    fn insert(&mut self, deadline_nanos: u64, waker: Waker) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.entries.push((deadline_nanos, id, Some(waker)));
        id
    }

    fn cancel(&mut self, id: u64) -> bool {
        for entry in &mut self.entries {
            if entry.1 == id && entry.2.is_some() {
                entry.2 = None;
                return true;
            }
        }
        false
    }

    fn collect_expired(&mut self, now_nanos: u64) -> Vec<Waker> {
        let mut expired = Vec::new();
        self.entries.retain(|(deadline, _id, waker)| {
            if *deadline <= now_nanos {
                if let Some(w) = waker.clone() {
                    expired.push(w);
                }
                false
            } else {
                true
            }
        });
        expired
    }

    fn len(&self) -> usize {
        self.entries.iter().filter(|e| e.2.is_some()).count()
    }
}

// =============================================================================
// COMPARISON: INSERT THROUGHPUT
// =============================================================================

fn bench_comparison_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("comparison/insert");

    for &size in &[100usize, 1_000, 10_000] {
        let size_u64 = size as u64;
        group.throughput(Throughput::Elements(size_u64));

        group.bench_with_input(BenchmarkId::new("timer_wheel", size), &size, |b, &_| {
            b.iter(|| {
                let mut wheel = TimerWheel::new();
                for i in 0..size_u64 {
                    wheel.register(Time::from_millis(i + 1), noop_waker());
                }
                black_box(wheel.len());
            });
        });

        group.bench_with_input(BenchmarkId::new("btree_map", size), &size, |b, &_| {
            b.iter(|| {
                let mut timers = BTreeTimers::new();
                for i in 0..size_u64 {
                    timers.insert((i + 1) * 1_000_000, noop_waker()); // millis → nanos
                }
                black_box(timers.len());
            });
        });

        group.bench_with_input(BenchmarkId::new("binary_heap", size), &size, |b, &_| {
            b.iter(|| {
                let mut timers = HeapTimers::new();
                for i in 0..size_u64 {
                    timers.insert((i + 1) * 1_000_000, noop_waker());
                }
                black_box(timers.len());
            });
        });

        group.bench_with_input(BenchmarkId::new("vec_linear", size), &size, |b, &_| {
            b.iter(|| {
                let mut timers = VecTimers::new();
                for i in 0..size_u64 {
                    timers.insert((i + 1) * 1_000_000, noop_waker());
                }
                black_box(timers.len());
            });
        });
    }

    group.finish();
}

// =============================================================================
// COMPARISON: CANCEL THROUGHPUT
// =============================================================================

fn bench_comparison_cancel(c: &mut Criterion) {
    let mut group = c.benchmark_group("comparison/cancel");

    for &size in &[100usize, 1_000, 10_000] {
        let size_u64 = size as u64;
        group.throughput(Throughput::Elements(size_u64));

        group.bench_with_input(BenchmarkId::new("timer_wheel", size), &size, |b, &_| {
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

        group.bench_with_input(BenchmarkId::new("btree_map", size), &size, |b, &_| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let mut timers = BTreeTimers::new();
                    let ids: Vec<_> = (0..size_u64)
                        .map(|i| timers.insert((i + 1) * 1_000_000, noop_waker()))
                        .collect();

                    let start = std::time::Instant::now();
                    for id in ids {
                        timers.cancel(id);
                    }
                    total += start.elapsed();
                }
                total
            });
        });

        group.bench_with_input(BenchmarkId::new("binary_heap", size), &size, |b, &_| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let mut timers = HeapTimers::new();
                    let ids: Vec<_> = (0..size_u64)
                        .map(|i| timers.insert((i + 1) * 1_000_000, noop_waker()))
                        .collect();

                    let start = std::time::Instant::now();
                    for id in ids {
                        timers.cancel(id);
                    }
                    total += start.elapsed();
                }
                total
            });
        });

        group.bench_with_input(BenchmarkId::new("vec_linear", size), &size, |b, &_| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let mut timers = VecTimers::new();
                    let ids: Vec<_> = (0..size_u64)
                        .map(|i| timers.insert((i + 1) * 1_000_000, noop_waker()))
                        .collect();

                    let start = std::time::Instant::now();
                    for id in ids {
                        timers.cancel(id);
                    }
                    total += start.elapsed();
                }
                total
            });
        });
    }

    group.finish();
}

// =============================================================================
// COMPARISON: EXPIRE THROUGHPUT
// =============================================================================

fn bench_comparison_expire(c: &mut Criterion) {
    let mut group = c.benchmark_group("comparison/expire");

    for &size in &[100usize, 1_000, 10_000] {
        let size_u64 = size as u64;
        group.throughput(Throughput::Elements(size_u64));

        // All timers expire at once — measures bulk expiry.
        group.bench_with_input(BenchmarkId::new("timer_wheel", size), &size, |b, &_| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let mut wheel = TimerWheel::new();
                    for i in 0..size_u64 {
                        wheel.register(Time::from_millis(i + 1), noop_waker());
                    }

                    let start = std::time::Instant::now();
                    let wakers = wheel.collect_expired(Time::from_millis(size_u64 + 1));
                    total += start.elapsed();
                    assert_eq!(wakers.len(), size);
                }
                total
            });
        });

        group.bench_with_input(BenchmarkId::new("btree_map", size), &size, |b, &_| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let mut timers = BTreeTimers::new();
                    for i in 0..size_u64 {
                        timers.insert((i + 1) * 1_000_000, noop_waker());
                    }

                    let start = std::time::Instant::now();
                    let wakers = timers.collect_expired((size_u64 + 1) * 1_000_000);
                    total += start.elapsed();
                    assert_eq!(wakers.len(), size);
                }
                total
            });
        });

        group.bench_with_input(BenchmarkId::new("binary_heap", size), &size, |b, &_| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let mut timers = HeapTimers::new();
                    for i in 0..size_u64 {
                        timers.insert((i + 1) * 1_000_000, noop_waker());
                    }

                    let start = std::time::Instant::now();
                    let wakers = timers.collect_expired((size_u64 + 1) * 1_000_000);
                    total += start.elapsed();
                    assert_eq!(wakers.len(), size);
                }
                total
            });
        });

        group.bench_with_input(BenchmarkId::new("vec_linear", size), &size, |b, &_| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let mut timers = VecTimers::new();
                    for i in 0..size_u64 {
                        timers.insert((i + 1) * 1_000_000, noop_waker());
                    }

                    let start = std::time::Instant::now();
                    let wakers = timers.collect_expired((size_u64 + 1) * 1_000_000);
                    total += start.elapsed();
                    assert_eq!(wakers.len(), size);
                }
                total
            });
        });
    }

    group.finish();
}

// =============================================================================
// COMPARISON: MIXED WORKLOAD (insert, tick, cancel cycle)
// =============================================================================

fn bench_comparison_mixed(c: &mut Criterion) {
    let mut group = c.benchmark_group("comparison/mixed");

    // Mixed workload: insert N timers spread over time, advance time in
    // steps, expiring some and cancelling others. Models realistic server
    // usage where connections arrive, some time out, some are cancelled.
    for &size in &[1_000usize, 10_000] {
        let size_u64 = size as u64;
        group.throughput(Throughput::Elements(size_u64));

        group.bench_with_input(BenchmarkId::new("timer_wheel", size), &size, |b, &_| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let mut wheel = TimerWheel::new();

                    let start = std::time::Instant::now();
                    // Insert all timers at staggered deadlines.
                    let handles: Vec<_> = (0..size_u64)
                        .map(|i| wheel.register(Time::from_millis(i * 10 + 10), noop_waker()))
                        .collect();

                    // Cancel every 3rd timer.
                    for (idx, handle) in handles.iter().enumerate() {
                        if idx % 3 == 0 {
                            wheel.cancel(handle);
                        }
                    }

                    // Advance time in steps, collecting expired.
                    let mut collected = 0;
                    for step in (0..size_u64 * 10 + 20).step_by(100) {
                        let wakers = wheel.collect_expired(Time::from_millis(step));
                        collected += wakers.len();
                    }
                    total += start.elapsed();
                    black_box(collected);
                }
                total
            });
        });

        group.bench_with_input(BenchmarkId::new("btree_map", size), &size, |b, &_| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let mut timers = BTreeTimers::new();

                    let start = std::time::Instant::now();
                    let ids: Vec<_> = (0..size_u64)
                        .map(|i| timers.insert((i * 10 + 10) * 1_000_000, noop_waker()))
                        .collect();

                    for (idx, &id) in ids.iter().enumerate() {
                        if idx % 3 == 0 {
                            timers.cancel(id);
                        }
                    }

                    let mut collected = 0;
                    for step in (0..size_u64 * 10 + 20).step_by(100) {
                        let wakers = timers.collect_expired(step * 1_000_000);
                        collected += wakers.len();
                    }
                    total += start.elapsed();
                    black_box(collected);
                }
                total
            });
        });

        group.bench_with_input(BenchmarkId::new("binary_heap", size), &size, |b, &_| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let mut timers = HeapTimers::new();

                    let start = std::time::Instant::now();
                    let ids: Vec<_> = (0..size_u64)
                        .map(|i| timers.insert((i * 10 + 10) * 1_000_000, noop_waker()))
                        .collect();

                    for (idx, &id) in ids.iter().enumerate() {
                        if idx % 3 == 0 {
                            timers.cancel(id);
                        }
                    }

                    let mut collected = 0;
                    for step in (0..size_u64 * 10 + 20).step_by(100) {
                        let wakers = timers.collect_expired(step * 1_000_000);
                        collected += wakers.len();
                    }
                    total += start.elapsed();
                    black_box(collected);
                }
                total
            });
        });

        group.bench_with_input(BenchmarkId::new("vec_linear", size), &size, |b, &_| {
            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let mut timers = VecTimers::new();

                    let start = std::time::Instant::now();
                    let ids: Vec<_> = (0..size_u64)
                        .map(|i| timers.insert((i * 10 + 10) * 1_000_000, noop_waker()))
                        .collect();

                    for (idx, &id) in ids.iter().enumerate() {
                        if idx % 3 == 0 {
                            timers.cancel(id);
                        }
                    }

                    let mut collected = 0;
                    for step in (0..size_u64 * 10 + 20).step_by(100) {
                        let wakers = timers.collect_expired(step * 1_000_000);
                        collected += wakers.len();
                    }
                    total += start.elapsed();
                    black_box(collected);
                }
                total
            });
        });
    }

    group.finish();
}

// =============================================================================
// COMPARISON: MEMORY (approximate via allocation size)
// =============================================================================

fn bench_comparison_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("comparison/memory_proxy");

    // Memory benchmarks measure "time to insert N + time to collect all",
    // which serves as a proxy for allocation/deallocation overhead.
    // Lower is better for cache-friendly structures.
    for &size in &[1_000usize, 10_000] {
        let size_u64 = size as u64;
        group.throughput(Throughput::Elements(size_u64));

        group.bench_with_input(
            BenchmarkId::new("timer_wheel_alloc_free", size),
            &size,
            |b, &_| {
                b.iter(|| {
                    let mut wheel = TimerWheel::new();
                    for i in 0..size_u64 {
                        wheel.register(Time::from_millis(i + 1), noop_waker());
                    }
                    let wakers = wheel.collect_expired(Time::from_millis(size_u64 + 1));
                    black_box(wakers.len());
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("btree_alloc_free", size),
            &size,
            |b, &_| {
                b.iter(|| {
                    let mut timers = BTreeTimers::new();
                    for i in 0..size_u64 {
                        timers.insert((i + 1) * 1_000_000, noop_waker());
                    }
                    let wakers = timers.collect_expired((size_u64 + 1) * 1_000_000);
                    black_box(wakers.len());
                });
            },
        );

        group.bench_with_input(BenchmarkId::new("heap_alloc_free", size), &size, |b, &_| {
            b.iter(|| {
                let mut timers = HeapTimers::new();
                for i in 0..size_u64 {
                    timers.insert((i + 1) * 1_000_000, noop_waker());
                }
                let wakers = timers.collect_expired((size_u64 + 1) * 1_000_000);
                black_box(wakers.len());
            });
        });

        group.bench_with_input(BenchmarkId::new("vec_alloc_free", size), &size, |b, &_| {
            b.iter(|| {
                let mut timers = VecTimers::new();
                for i in 0..size_u64 {
                    timers.insert((i + 1) * 1_000_000, noop_waker());
                }
                let wakers = timers.collect_expired((size_u64 + 1) * 1_000_000);
                black_box(wakers.len());
            });
        });
    }

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

criterion_group!(
    comparison_benches,
    bench_comparison_insert,
    bench_comparison_cancel,
    bench_comparison_expire,
    bench_comparison_mixed,
    bench_comparison_memory,
);

criterion_main!(benches, comparison_benches);
