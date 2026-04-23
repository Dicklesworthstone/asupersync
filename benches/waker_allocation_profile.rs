//! Performance benchmarks for waker allocation hot paths.
//!
//! This benchmark suite profiles memory allocation patterns in the waker module,
//! focusing on allocation-heavy operations during task waking patterns.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use asupersync::runtime::waker::{WakerState, WakeSource};
use asupersync::types::TaskId;
use asupersync::util::ArenaIndex;
use std::sync::Arc;
use std::task::Wake;

/// Scenario A: Waker creation burst (allocator stress test)
///
/// Simulates rapid task spawning where many wakers are created in quick succession.
/// This tests Arc allocation and TaskWaker struct allocation patterns.
fn bench_waker_creation_burst(c: &mut Criterion) {
    let mut group = c.benchmark_group("waker_creation_burst");

    let test_cases = [
        (100, "small_burst"),
        (1000, "medium_burst"),
        (10000, "large_burst"),
        (100000, "massive_burst"),
    ];

    for (count, case_name) in test_cases {
        group.throughput(Throughput::Elements(count as u64));

        group.bench_with_input(
            BenchmarkId::new("create_for_unknown", case_name),
            &count,
            |b, &count| {
                b.iter(|| {
                    let state = Arc::new(WakerState::new());
                    let mut wakers = Vec::with_capacity(count as usize);
                    for i in 0..count {
                        let task_id = TaskId::from_arena(ArenaIndex::new(i, 0));
                        let waker = state.waker_for(black_box(task_id));
                        wakers.push(black_box(waker));
                    }
                    black_box(wakers)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("create_for_timer", case_name),
            &count,
            |b, &count| {
                b.iter(|| {
                    let state = Arc::new(WakerState::new());
                    let mut wakers = Vec::with_capacity(count as usize);
                    for i in 0..count {
                        let task_id = TaskId::from_arena(ArenaIndex::new(i, 0));
                        let waker = state.waker_for_source(black_box(task_id), WakeSource::Timer);
                        wakers.push(black_box(waker));
                    }
                    black_box(wakers)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("create_for_io", case_name),
            &count,
            |b, &count| {
                b.iter(|| {
                    let state = Arc::new(WakerState::new());
                    let mut wakers = Vec::with_capacity(count as usize);
                    for i in 0..count {
                        let task_id = TaskId::from_arena(ArenaIndex::new(i, 0));
                        let waker = state.waker_for_source(
                            black_box(task_id),
                            WakeSource::Io { fd: (i % 1024) as i32 }
                        );
                        wakers.push(black_box(waker));
                    }
                    black_box(wakers)
                });
            },
        );
    }

    group.finish();
}

/// Scenario B: Waker reuse patterns
///
/// Simulates different patterns of waker usage: create-once vs recreate vs shared.
/// This tests allocation amortization strategies.
fn bench_waker_reuse_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("waker_reuse_patterns");

    let iterations = 10000;
    group.throughput(Throughput::Elements(iterations as u64));

    // Pattern 1: Create new waker for every wake operation
    group.bench_function("recreate_per_wake", |b| {
        b.iter(|| {
            let state = Arc::new(WakerState::new());
            for i in 0..iterations {
                let task_id = TaskId::from_arena(ArenaIndex::new(i, 0));
                let waker = state.waker_for(black_box(task_id));
                waker.wake_by_ref();
            }
            black_box(state.drain_woken())
        });
    });

    // Pattern 2: Create waker once, reuse for multiple operations
    group.bench_function("reuse_single_waker", |b| {
        b.iter(|| {
            let state = Arc::new(WakerState::new());
            let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
            let waker = state.waker_for(black_box(task_id));

            for _ in 0..iterations {
                waker.wake_by_ref();
                black_box(state.drain_woken());
            }
        });
    });

    // Pattern 3: Create waker pool, cycle through them
    group.bench_function("waker_pool_cycling", |b| {
        b.iter(|| {
            let state = Arc::new(WakerState::new());
            let pool_size = 100;
            let wakers: Vec<_> = (0..pool_size)
                .map(|i| {
                    let task_id = TaskId::from_arena(ArenaIndex::new(i, 0));
                    state.waker_for(task_id)
                })
                .collect();

            for i in 0..iterations {
                let waker = &wakers[i % pool_size];
                waker.wake_by_ref();
            }
            black_box(state.drain_woken())
        });
    });

    group.finish();
}

/// Scenario C: Wake storm (high-contention allocation)
///
/// Simulates scenarios where many tasks are woken simultaneously.
/// Tests lock contention on the woken set under allocation pressure.
fn bench_wake_storms(c: &mut Criterion) {
    let mut group = c.benchmark_group("wake_storms");

    let test_cases = [
        (10, 100, "light_storm"),      // 10 wakers, 100 operations each
        (100, 100, "medium_storm"),    // 100 wakers, 100 operations each
        (1000, 10, "heavy_storm"),     // 1000 wakers, 10 operations each
        (10000, 1, "burst_storm"),     // 10000 wakers, 1 operation each
    ];

    for (waker_count, ops_per_waker, case_name) in test_cases {
        let total_ops = waker_count * ops_per_waker;
        group.throughput(Throughput::Elements(total_ops as u64));

        group.bench_with_input(
            BenchmarkId::new("sequential_wakes", case_name),
            &(waker_count, ops_per_waker),
            |b, &(waker_count, ops_per_waker)| {
                b.iter(|| {
                    let state = Arc::new(WakerState::new());
                    let wakers: Vec<_> = (0..waker_count)
                        .map(|i| {
                            let task_id = TaskId::from_arena(ArenaIndex::new(i, 0));
                            state.waker_for(task_id)
                        })
                        .collect();

                    for waker in &wakers {
                        for _ in 0..ops_per_waker {
                            waker.wake_by_ref();
                        }
                    }

                    black_box(state.drain_woken())
                });
            },
        );

        // Simulate parallel waking (although still single-threaded for benchmarking)
        group.bench_with_input(
            BenchmarkId::new("interleaved_wakes", case_name),
            &(waker_count, ops_per_waker),
            |b, &(waker_count, ops_per_waker)| {
                b.iter(|| {
                    let state = Arc::new(WakerState::new());
                    let wakers: Vec<_> = (0..waker_count)
                        .map(|i| {
                            let task_id = TaskId::from_arena(ArenaIndex::new(i, 0));
                            state.waker_for(task_id)
                        })
                        .collect();

                    for op in 0..ops_per_waker {
                        for waker in &wakers {
                            waker.wake_by_ref();
                        }
                    }

                    black_box(state.drain_woken())
                });
            },
        );
    }

    group.finish();
}

/// Scenario D: Allocation lifecycle patterns
///
/// Tests different patterns of waker lifecycle management.
fn bench_allocation_lifecycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("allocation_lifecycle");

    let test_size = 1000;
    group.throughput(Throughput::Elements(test_size as u64));

    // Pattern 1: Create, use immediately, drop
    group.bench_function("immediate_use_drop", |b| {
        b.iter(|| {
            let state = Arc::new(WakerState::new());
            for i in 0..test_size {
                let task_id = TaskId::from_arena(ArenaIndex::new(i, 0));
                let waker = state.waker_for(black_box(task_id));
                waker.wake();
                // Waker drops here
            }
            black_box(state.drain_woken())
        });
    });

    // Pattern 2: Create all, use all, drop all
    group.bench_function("bulk_create_use_drop", |b| {
        b.iter(|| {
            let state = Arc::new(WakerState::new());

            // Creation phase
            let wakers: Vec<_> = (0..test_size)
                .map(|i| {
                    let task_id = TaskId::from_arena(ArenaIndex::new(i, 0));
                    state.waker_for(task_id)
                })
                .collect();

            // Usage phase
            for waker in &wakers {
                waker.wake_by_ref();
            }

            // Drop phase (automatic)
            black_box(state.drain_woken())
        });
    });

    // Pattern 3: Create, clone, use clones
    group.bench_function("clone_and_use", |b| {
        b.iter(|| {
            let state = Arc::new(WakerState::new());
            let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
            let base_waker = state.waker_for(task_id);

            for _ in 0..test_size {
                let cloned_waker = base_waker.clone();
                cloned_waker.wake();
            }

            black_box(state.drain_woken())
        });
    });

    group.finish();
}

/// Scenario E: Memory pressure simulation
///
/// Tests waker allocation behavior under different memory pressure conditions.
fn bench_memory_pressure(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_pressure");

    // Simulate different allocation pressures by pre-allocating ballast
    let pressure_levels = [
        (0, "no_pressure"),
        (1_000_000, "light_pressure"),     // 1MB ballast
        (10_000_000, "medium_pressure"),   // 10MB ballast
        (100_000_000, "high_pressure"),    // 100MB ballast
    ];

    for (ballast_bytes, pressure_name) in pressure_levels {
        group.bench_with_input(
            BenchmarkId::new("waker_creation_under_pressure", pressure_name),
            &ballast_bytes,
            |b, &ballast_bytes| {
                b.iter(|| {
                    // Create memory pressure
                    let _ballast: Vec<u8> = if ballast_bytes > 0 {
                        vec![0u8; ballast_bytes]
                    } else {
                        Vec::new()
                    };

                    // Test waker creation under pressure
                    let state = Arc::new(WakerState::new());
                    let mut wakers = Vec::new();

                    for i in 0..1000 {
                        let task_id = TaskId::from_arena(ArenaIndex::new(i, 0));
                        let waker = state.waker_for(black_box(task_id));
                        wakers.push(waker);
                    }

                    // Use wakers
                    for waker in &wakers {
                        waker.wake_by_ref();
                    }

                    black_box(state.drain_woken())
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_waker_creation_burst,
    bench_waker_reuse_patterns,
    bench_wake_storms,
    bench_allocation_lifecycle,
    bench_memory_pressure
);
criterion_main!(benches);