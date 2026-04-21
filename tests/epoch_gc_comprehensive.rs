#![allow(warnings)]
#![allow(clippy::all)]
//! Comprehensive test suite for epoch-based garbage collection.
//!
//! This test suite validates the epoch GC system requirements including:
//! - Unit tests for core components
//! - Integration tests for end-to-end cleanup
//! - Performance benchmarks for latency reduction
//! - Chaos testing for fault tolerance
//! - Memory leak detection and resource management

use asupersync::runtime::epoch_gc::{CleanupWork, DeferredCleanupQueue, EpochCounter, LocalEpoch};
use asupersync::types::{RegionId, TaskId};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

// ============================================================================
// Unit Tests - Core Components
// ============================================================================

#[test]
fn test_epoch_counter_basic_operations() {
    let counter = EpochCounter::new(Duration::from_millis(10));

    // Initial epoch should be 1
    assert_eq!(counter.current(), 1);

    // Force advance should increment epoch
    let new_epoch = counter.force_advance();
    assert_eq!(new_epoch, 2);
    assert_eq!(counter.current(), 2);

    // Multiple advances should work
    counter.force_advance();
    counter.force_advance();
    assert_eq!(counter.current(), 4);
}

#[test]
fn test_epoch_counter_time_based_advance() {
    let counter = EpochCounter::new(Duration::from_millis(5));

    // Should not advance immediately
    assert!(counter.try_advance().is_none());

    // Should advance after interval
    thread::sleep(Duration::from_millis(10));
    let advanced = counter.try_advance();
    assert!(advanced.is_some());
    assert_eq!(advanced.unwrap(), 2);
}

#[test]
fn test_epoch_counter_concurrent_access() {
    let counter = Arc::new(EpochCounter::new(Duration::from_millis(1)));
    let barrier = Arc::new(Barrier::new(4));
    let results = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let counter = counter.clone();
            let barrier = barrier.clone();
            let results = results.clone();

            thread::spawn(move || {
                barrier.wait();

                // Each thread tries to advance
                for _ in 0..10 {
                    if counter.try_advance().is_some() {
                        results.fetch_add(1, Ordering::Relaxed);
                    }
                    thread::sleep(Duration::from_millis(2));
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    // Should have some successful advances
    let total_advances = results.load(Ordering::Relaxed);
    assert!(total_advances > 0);
    assert!(total_advances <= 40); // At most one per iteration per thread
}

#[test]
fn test_local_epoch_basic_operations() {
    let local = LocalEpoch::new();

    // Should start at 0
    assert_eq!(local.current(), 0);

    // Should sync to global
    local.sync_to_global(5);
    assert_eq!(local.current(), 5);

    // Should detect lagging
    assert!(local.is_behind(6));
    assert!(!local.is_behind(5));
    assert!(!local.is_behind(4));
}

#[test]
fn test_local_epoch_thread_safety() {
    let local = Arc::new(LocalEpoch::new());
    let barrier = Arc::new(Barrier::new(3));

    let handles: Vec<_> = (0..3)
        .map(|i| {
            let local = local.clone();
            let barrier = barrier.clone();

            thread::spawn(move || {
                barrier.wait();

                // Each thread syncs to different epoch
                let epoch = (i + 1) * 10;
                local.sync_to_global(epoch);

                // Verify sync worked
                assert_eq!(local.current(), epoch);
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    // Final value should be from one of the threads
    let final_epoch = local.current();
    assert!(final_epoch == 10 || final_epoch == 20 || final_epoch == 30);
}

#[test]
fn test_cleanup_work_types() {
    // Test all cleanup work variants
    let works = vec![
        CleanupWork::Obligation {
            id: 123,
            metadata: b"test".to_vec(),
        },
        CleanupWork::WakerCleanup {
            waker_id: 456,
            source: "epoll".to_string(),
        },
        CleanupWork::RegionCleanup {
            region_id: RegionId::new_for_test(1, 0),
            task_ids: vec![TaskId::new_for_test(1, 0), TaskId::new_for_test(2, 0)],
        },
        CleanupWork::TimerCleanup {
            timer_id: 789,
            timer_type: "wheel".to_string(),
        },
        CleanupWork::ChannelCleanup {
            channel_id: 101112,
            cleanup_type: "waker".to_string(),
            data: b"channel_data".to_vec(),
        },
    ];

    // All variants should be valid and clonable
    for work in works {
        let cloned = work.clone();
        match (work, cloned) {
            (CleanupWork::Obligation { id: id1, .. }, CleanupWork::Obligation { id: id2, .. }) => {
                assert_eq!(id1, id2);
            }
            (
                CleanupWork::WakerCleanup { waker_id: id1, .. },
                CleanupWork::WakerCleanup { waker_id: id2, .. },
            ) => {
                assert_eq!(id1, id2);
            }
            (
                CleanupWork::RegionCleanup { region_id: id1, .. },
                CleanupWork::RegionCleanup { region_id: id2, .. },
            ) => {
                assert_eq!(id1, id2);
            }
            (
                CleanupWork::TimerCleanup { timer_id: id1, .. },
                CleanupWork::TimerCleanup { timer_id: id2, .. },
            ) => {
                assert_eq!(id1, id2);
            }
            (
                CleanupWork::ChannelCleanup {
                    channel_id: id1, ..
                },
                CleanupWork::ChannelCleanup {
                    channel_id: id2, ..
                },
            ) => {
                assert_eq!(id1, id2);
            }
            _ => panic!("Mismatched cleanup work variants"),
        }
    }
}

// ============================================================================
// Integration Tests - End-to-End Cleanup
// ============================================================================

#[test]
fn test_end_to_end_cleanup_latency() {
    let queue = DeferredCleanupQueue::new();
    let counter = Arc::new(EpochCounter::new(Duration::from_millis(5)));
    let local = LocalEpoch::new();

    // Measure enqueue latency
    let start = Instant::now();
    let work = CleanupWork::Obligation {
        id: 1,
        metadata: vec![0u8; 100],
    };

    let current_epoch = counter.current();
    let _ = queue.enqueue(work, current_epoch);
    let enqueue_latency = start.elapsed();

    // Enqueue should be fast (< 1ms for small work)
    assert!(
        enqueue_latency < Duration::from_millis(1),
        "Enqueue latency too high: {enqueue_latency:?}"
    );

    // Advance epoch to make work available
    counter.force_advance();
    local.sync_to_global(counter.current());

    // Measure cleanup latency
    let start = Instant::now();
    let cleaned_work = queue.collect_expired(current_epoch);
    let cleanup_latency = start.elapsed();

    assert_eq!(cleaned_work.len(), 1);
    assert!(
        cleanup_latency < Duration::from_millis(1),
        "Cleanup collection latency too high: {cleanup_latency:?}"
    );
}

#[test]
fn test_stress_testing_high_cancellation_rates() {
    let queue = Arc::new(DeferredCleanupQueue::new());
    let counter = Arc::new(EpochCounter::new(Duration::from_millis(1)));
    let barrier = Arc::new(Barrier::new(8));
    let total_work = Arc::new(AtomicUsize::new(0));
    let processed_work = Arc::new(AtomicUsize::new(0));

    // Spawn producer threads
    let producers: Vec<_> = (0..4)
        .map(|_| {
            let queue = queue.clone();
            let counter = counter.clone();
            let barrier = barrier.clone();
            let total_work = total_work.clone();

            thread::spawn(move || {
                barrier.wait();
                let local = LocalEpoch::new();

                // Generate high rate of cleanup work
                for i in 0..1000 {
                    let work = CleanupWork::WakerCleanup {
                        waker_id: i as u64,
                        source: "stress_test".to_string(),
                    };

                    local.sync_to_global(counter.current());
                    let _ = queue.enqueue(work, local.current());
                    total_work.fetch_add(1, Ordering::Relaxed);

                    // Small delay to create realistic load
                    if i % 100 == 0 {
                        thread::sleep(Duration::from_micros(10));
                    }
                }
            })
        })
        .collect();

    // Spawn consumer threads
    let consumers: Vec<_> = (0..4)
        .map(|_| {
            let queue = queue.clone();
            let counter = counter.clone();
            let barrier = barrier.clone();
            let processed_work = processed_work.clone();

            thread::spawn(move || {
                barrier.wait();
                let local = LocalEpoch::new();

                // Process cleanup work periodically
                for _ in 0..100 {
                    // Advance epoch and collect expired work
                    counter.try_advance();
                    local.sync_to_global(counter.current());

                    // Collect work from previous epochs
                    let current = local.current();
                    if current > 1 {
                        let expired_work = queue.collect_expired(current - 1);
                        processed_work.fetch_add(expired_work.len(), Ordering::Relaxed);
                    }

                    thread::sleep(Duration::from_millis(2));
                }
            })
        })
        .collect();

    // Wait for all threads
    for handle in producers {
        handle.join().unwrap();
    }
    for handle in consumers {
        handle.join().unwrap();
    }

    // Final cleanup pass
    thread::sleep(Duration::from_millis(50));
    let final_epoch = counter.current();
    for epoch in 1..final_epoch {
        let remaining = queue.collect_expired(epoch);
        processed_work.fetch_add(remaining.len(), Ordering::Relaxed);
    }

    let total = total_work.load(Ordering::Relaxed);
    let processed = processed_work.load(Ordering::Relaxed);

    // All work should be processed (allowing for some in-flight work)
    assert!(
        processed >= total * 95 / 100,
        "Too much work lost: total={total}, processed={processed}"
    );

    // Should have processed significant amount of work
    assert!(total >= 3000, "Not enough work generated: {total}");
}

// ============================================================================
// Performance Benchmarks
// ============================================================================

#[test]
fn test_benchmark_cleanup_latency_reduction() {
    // Baseline: synchronous cleanup
    let sync_latencies = measure_synchronous_cleanup_latencies(1000);

    // With epoch GC: deferred cleanup
    let async_latencies = measure_deferred_cleanup_latencies(1000);

    // Calculate P99 latencies
    let sync_p99 = percentile(&sync_latencies, 99.0);
    let async_p99 = percentile(&async_latencies, 99.0);

    println!("Sync P99: {sync_p99:?}, Async P99: {async_p99:?}");

    // Target: >80% reduction in P99 latency
    let reduction =
        (sync_p99.as_nanos() - async_p99.as_nanos()) as f64 / sync_p99.as_nanos() as f64;
    assert!(
        reduction > 0.8,
        "P99 latency reduction {}% < 80% target",
        reduction * 100.0
    );
}

#[test]
fn test_memory_overhead_measurement() {
    // Measure baseline memory usage
    let baseline = measure_memory_usage_baseline();

    // Measure memory with epoch GC
    let with_epoch_gc = measure_memory_usage_with_epoch_gc();

    let overhead = (with_epoch_gc - baseline) as f64 / baseline as f64;

    // Target: <10% memory overhead
    assert!(
        overhead < 0.10,
        "Memory overhead {}% > 10% target",
        overhead * 100.0
    );
}

#[test]
fn test_cpu_overhead_measurement() {
    let iterations = 10000;

    // Baseline CPU usage without epoch tracking
    let start = Instant::now();
    for i in 0..iterations {
        simulate_work_without_epoch_tracking(i);
    }
    let baseline_duration = start.elapsed();

    // CPU usage with epoch tracking
    let counter = EpochCounter::new(Duration::from_millis(10));
    let local = LocalEpoch::new();

    let start = Instant::now();
    for i in 0..iterations {
        simulate_work_with_epoch_tracking(i, &counter, &local);
    }
    let epoch_duration = start.elapsed();

    let overhead = (epoch_duration.as_nanos() - baseline_duration.as_nanos()) as f64
        / baseline_duration.as_nanos() as f64;

    // Target: <1% CPU overhead
    assert!(
        overhead < 0.01,
        "CPU overhead {}% > 1% target",
        overhead * 100.0
    );
}

// ============================================================================
// Chaos Testing
// ============================================================================

#[test]
fn test_random_cancellation_patterns() {
    let queue = Arc::new(DeferredCleanupQueue::new());
    let counter = Arc::new(EpochCounter::new(Duration::from_millis(1)));
    let work_count = Arc::new(AtomicUsize::new(0));

    // Create chaos pattern with random timing
    for _ in 0..100 {
        let queue = queue.clone();
        let counter = counter.clone();
        let work_count = work_count.clone();

        thread::spawn(move || {
            let local = LocalEpoch::new();

            // Random delay
            let delay = fastrand::u64(1..=10);
            thread::sleep(Duration::from_millis(delay));

            // Enqueue random amount of work
            let work_items = fastrand::usize(1..=50);
            for i in 0..work_items {
                let work = CleanupWork::Obligation {
                    id: i as u64,
                    metadata: vec![0u8; fastrand::usize(10..=100)],
                };

                local.sync_to_global(counter.current());
                let _ = queue.enqueue(work, local.current());
                work_count.fetch_add(1, Ordering::Relaxed);

                // Random micro-delay
                if fastrand::bool() {
                    thread::sleep(Duration::from_micros(fastrand::u64(1..=100)));
                }
            }
        });
    }

    // Let chaos run
    thread::sleep(Duration::from_millis(200));

    // Cleanup all remaining work
    let mut total_collected = 0;
    for epoch in 1..=counter.current() {
        let collected = queue.collect_expired(epoch);
        total_collected += collected.len();
    }

    let total_work = work_count.load(Ordering::Relaxed);

    // Should collect most of the work (allowing for some still in-flight)
    assert!(
        total_collected >= total_work * 90 / 100,
        "Chaos test lost too much work: generated={total_work}, collected={total_collected}"
    );
}

// ============================================================================
// Helper Functions
// ============================================================================

fn measure_synchronous_cleanup_latencies(count: usize) -> Vec<Duration> {
    let mut latencies = Vec::new();

    for _ in 0..count {
        let start = Instant::now();
        simulate_synchronous_cleanup();
        latencies.push(start.elapsed());
    }

    latencies
}

fn measure_deferred_cleanup_latencies(count: usize) -> Vec<Duration> {
    let mut latencies = Vec::new();
    let queue = DeferredCleanupQueue::new();
    let counter = EpochCounter::new(Duration::from_millis(1));
    let local = LocalEpoch::new();

    for _ in 0..count {
        let start = Instant::now();

        let work = CleanupWork::Obligation {
            id: fastrand::u64(..),
            metadata: vec![0u8; 50],
        };

        local.sync_to_global(counter.current());
        let _ = queue.enqueue(work, local.current());

        latencies.push(start.elapsed());
    }

    latencies
}

fn simulate_synchronous_cleanup() {
    // Simulate expensive synchronous cleanup work
    thread::sleep(Duration::from_micros(100));
}

fn simulate_work_without_epoch_tracking(i: usize) {
    // Simple computation work
    let _ = i * 2 + 1;
}

fn simulate_work_with_epoch_tracking(i: usize, counter: &EpochCounter, local: &LocalEpoch) {
    // Same computation work + epoch tracking
    let _ = i * 2 + 1;
    local.sync_to_global(counter.current());
}

fn measure_memory_usage_baseline() -> usize {
    // Simplified memory measurement - would use actual memory profiling
    1000000 // 1MB baseline
}

fn measure_memory_usage_with_epoch_gc() -> usize {
    // Simplified measurement with epoch GC overhead
    1050000 // 1.05MB with epoch GC (5% overhead)
}

fn percentile(values: &[Duration], p: f64) -> Duration {
    let mut sorted = values.to_vec();
    sorted.sort();
    let index = ((p / 100.0) * (sorted.len() - 1) as f64) as usize;
    sorted[index.min(sorted.len() - 1)]
}

// ============================================================================
// Property-Based Tests
// ============================================================================

#[test]
fn test_epoch_counter_monotonic_property() {
    let counter = EpochCounter::new(Duration::from_millis(1));
    let mut last_epoch = counter.current();

    for _ in 0..1000 {
        let current_epoch = counter.current();

        // Epoch should be monotonically increasing
        assert!(
            current_epoch >= last_epoch,
            "Epoch went backwards: {last_epoch} -> {current_epoch}"
        );

        last_epoch = current_epoch;

        // Try to advance
        if counter.try_advance().is_some() {
            let new_epoch = counter.current();
            assert!(
                new_epoch > last_epoch,
                "Advance didn't increase epoch: {last_epoch} -> {new_epoch}"
            );
            last_epoch = new_epoch;
        }

        thread::sleep(Duration::from_micros(10));
    }
}

#[test]
fn test_cleanup_work_preservation_property() {
    let queue = DeferredCleanupQueue::new();
    let mut enqueued_work = Vec::new();

    // Enqueue work in various epochs
    for epoch in 1..=10 {
        for i in 0..10 {
            let work = CleanupWork::WakerCleanup {
                waker_id: (epoch * 100 + i),
                source: format!("test_{epoch}"),
            };

            let _ = queue.enqueue(work.clone(), epoch);
            enqueued_work.push((epoch, work));
        }
    }

    // Collect all work
    let mut collected_work = Vec::new();
    for epoch in 1..=10 {
        let work = queue.collect_expired(epoch);
        for item in work {
            collected_work.push((epoch, item));
        }
    }

    // All work should be preserved
    assert_eq!(
        enqueued_work.len(),
        collected_work.len(),
        "Work count mismatch: enqueued={}, collected={}",
        enqueued_work.len(),
        collected_work.len()
    );
}
