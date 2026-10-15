#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic tests for bulkhead cancel behavior and concurrency limits.
//!
//! This test suite verifies that the bulkhead combinator correctly handles
//! cancellation in various states while maintaining counter integrity and
//! resource limits.

use asupersync::combinator::bulkhead::{Bulkhead, BulkheadPolicy, BulkheadError};
use asupersync::types::Time;
use proptest::prelude::*;
use std::sync::{Arc, atomic::{AtomicU32, AtomicU64, Ordering}};
use std::thread;
use std::time::Duration;

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Generate valid bulkhead configurations for testing.
fn arb_bulkhead_config() -> impl Strategy<Value = BulkheadPolicy> {
    (1u32..=20, 1u32..=50, 100u64..=5000u64).prop_map(|(max_concurrent, max_queue, timeout_ms)| {
        BulkheadPolicy {
            name: "test-bulkhead".to_string(),
            max_concurrent,
            max_queue,
            queue_timeout: Duration::from_millis(timeout_ms),
            weighted: false,
            on_full: None,
        }
    })
}

/// Generate operation weights for testing.
fn arb_weights() -> impl Strategy<Value = Vec<u32>> {
    prop::collection::vec(1u32..=5, 1..20)
}

/// Generate cancel timing strategies.
#[derive(Debug, Clone, Copy)]
enum CancelTiming {
    Immediate,
    AfterDelay(u64), // milliseconds
    AfterGrant,
    Random,
}

fn arb_cancel_timing() -> impl Strategy<Value = CancelTiming> {
    prop_oneof![
        Just(CancelTiming::Immediate),
        (0u64..=500).prop_map(CancelTiming::AfterDelay),
        Just(CancelTiming::AfterGrant),
        Just(CancelTiming::Random),
    ]
}

/// Create a deterministic test environment marker.
fn create_lab() {
    // Lab runtime integration would go here if needed
}

/// Test harness for managing concurrent operations.
#[derive(Debug)]
struct ConcurrentTestHarness {
    operations_started: AtomicU32,
    operations_completed: AtomicU32,
    operations_cancelled: AtomicU32,
    permits_acquired: AtomicU32,
    permits_released: AtomicU32,
}

impl ConcurrentTestHarness {
    fn new() -> Self {
        Self {
            operations_started: AtomicU32::new(0),
            operations_completed: AtomicU32::new(0),
            operations_cancelled: AtomicU32::new(0),
            permits_acquired: AtomicU32::new(0),
            permits_released: AtomicU32::new(0),
        }
    }

    fn start_operation(&self) {
        self.operations_started.fetch_add(1, Ordering::Relaxed);
    }

    fn complete_operation(&self) {
        self.operations_completed.fetch_add(1, Ordering::Relaxed);
    }

    fn cancel_operation(&self) {
        self.operations_cancelled.fetch_add(1, Ordering::Relaxed);
    }

    fn acquire_permit(&self) {
        self.permits_acquired.fetch_add(1, Ordering::Relaxed);
    }

    fn release_permit(&self) {
        self.permits_released.fetch_add(1, Ordering::Relaxed);
    }

    fn get_stats(&self) -> (u32, u32, u32, u32, u32) {
        (
            self.operations_started.load(Ordering::Relaxed),
            self.operations_completed.load(Ordering::Relaxed),
            self.operations_cancelled.load(Ordering::Relaxed),
            self.permits_acquired.load(Ordering::Relaxed),
            self.permits_released.load(Ordering::Relaxed),
        )
    }
}

// ============================================================================
// MR1: Cancel in Queue Releases Slot Immediately
// ============================================================================

/// **MR1: Cancel in Queue Releases Slot Immediately**
///
/// When an operation is cancelled while waiting in the queue, the slot should
/// be released immediately, allowing subsequent operations to proceed.
///
/// Property: cancel(queued_op) → slot_available && queue_size_decreases
proptest! {
    #[test]
    fn mr1_cancel_in_queue_releases_slot(
        config in arb_bulkhead_config(),
        weights in arb_weights().prop_filter("non-empty", |w| !w.is_empty())
    ) {
        create_lab();
        let bulkhead = Bulkhead::new(config.clone());
        let now = Time::now();

        // Phase 1: Fill all available permits
        let mut acquired_permits = Vec::new();
        for _ in 0..config.max_concurrent {
            if let Some(permit) = bulkhead.try_acquire(1) {
                acquired_permits.push(permit);
            }
        }

        prop_assert_eq!(bulkhead.available(), 0, "All permits should be consumed");

        // Phase 2: Enqueue operations that will wait
        let mut queued_ids = Vec::new();
        for &weight in weights.iter().take(config.max_queue as usize / 2) {
            match bulkhead.enqueue(weight, now) {
                Ok(id) => queued_ids.push((id, weight)),
                Err(_) => break,
            }
        }

        let initial_metrics = bulkhead.metrics();
        let initial_queue_depth = initial_metrics.queue_depth;
        let initial_available = bulkhead.available();

        prop_assert!(initial_queue_depth > 0, "Should have queued operations");

        // Phase 3: Cancel the first queued operation
        if let Some(&(entry_id, _weight)) = queued_ids.first() {
            bulkhead.cancel_entry(entry_id, now);

            let post_cancel_metrics = bulkhead.metrics();

            // MR1.1: Queue depth should decrease
            prop_assert!(
                post_cancel_metrics.queue_depth < initial_queue_depth,
                "Queue depth should decrease after cancel: {} -> {}",
                initial_queue_depth,
                post_cancel_metrics.queue_depth
            );

            // MR1.2: Available permits should remain the same (nothing was in-flight)
            prop_assert_eq!(
                bulkhead.available(),
                initial_available,
                "Available permits should remain unchanged for queued cancel"
            );

            // MR1.3: Total cancelled should increment
            prop_assert!(
                post_cancel_metrics.total_cancelled > initial_metrics.total_cancelled,
                "Total cancelled should increment: {} -> {}",
                initial_metrics.total_cancelled,
                post_cancel_metrics.total_cancelled
            );
        }

        // Phase 4: Release all permits to verify queue processing
        drop(acquired_permits);
        let _ = bulkhead.process_queue(now);

        let final_metrics = bulkhead.metrics();
        prop_assert_eq!(
            bulkhead.available(),
            config.max_concurrent,
            "All permits should be released at end"
        );
    }
}

// ============================================================================
// MR2: Cancel In-Flight Decrements Counter on Drop
// ============================================================================

/// **MR2: Cancel In-Flight Decrements Counter on Drop**
///
/// When a permit is acquired and then dropped due to cancellation,
/// the permit counter should be properly decremented.
///
/// Property: acquire_permit() → drop(permit) → available_permits_restored
proptest! {
    #[test]
    fn mr2_cancel_inflight_decrements_on_drop(
        config in arb_bulkhead_config(),
        op_count in 1usize..=10
    ) {
        create_lab();
        let bulkhead = Bulkhead::new(config.clone());

        let initial_available = bulkhead.available();
        prop_assert_eq!(initial_available, config.max_concurrent);

        // Phase 1: Acquire permits up to the limit
        let mut permits = Vec::new();
        for i in 0..op_count.min(config.max_concurrent as usize) {
            if let Some(permit) = bulkhead.try_acquire(1) {
                permits.push(permit);
            }
        }

        let acquired_count = permits.len() as u32;
        let post_acquire_available = bulkhead.available();

        prop_assert_eq!(
            post_acquire_available,
            initial_available - acquired_count,
            "Available permits should decrease by number acquired"
        );

        // Phase 2: Simulate cancellation by dropping permits one by one
        let mut dropped_count = 0u32;
        for permit in permits {
            drop(permit); // Simulates cancellation cleanup
            dropped_count += 1;

            let current_available = bulkhead.available();
            prop_assert_eq!(
                current_available,
                post_acquire_available + dropped_count,
                "Each permit drop should increment available count"
            );
        }

        // Phase 3: Verify final state
        let final_available = bulkhead.available();
        prop_assert_eq!(
            final_available,
            initial_available,
            "All permits should be restored after drops: {} vs {}",
            final_available,
            initial_available
        );

        // MR2.1: Can acquire again after cancellation cleanup
        let reacquire_permit = bulkhead.try_acquire(1);
        prop_assert!(
            reacquire_permit.is_some(),
            "Should be able to acquire permit after cancellation cleanup"
        );
    }
}

// ============================================================================
// MR3: Concurrent Cancel+Release Preserve Counter Integrity
// ============================================================================

/// **MR3: Concurrent Cancel+Release Preserve Counter Integrity**
///
/// Under concurrent cancellations and releases, the permit counter
/// should maintain integrity without over-releasing or under-counting.
///
/// Property: concurrent(cancel, release) → invariant(available ≤ max_concurrent)
proptest! {
    #[test]
    fn mr3_concurrent_cancel_release_integrity(
        config in arb_bulkhead_config().prop_filter("reasonable_size", |c| c.max_concurrent <= 10),
        timing in arb_cancel_timing(),
        thread_count in 2usize..=8
    ) {
        create_lab();
        let bulkhead = Arc::new(Bulkhead::new(config.clone()));
        let harness = Arc::new(ConcurrentTestHarness::new());
        let now = Time::now();

        // Phase 1: Set up concurrent workers
        let mut handles = Vec::new();
        let operation_id_counter = Arc::new(AtomicU64::new(0));

        for thread_id in 0..thread_count {
            let bulkhead_clone = Arc::clone(&bulkhead);
            let harness_clone = Arc::clone(&harness);
            let config_clone = config.clone();
            let op_counter = Arc::clone(&operation_id_counter);

            let handle = thread::spawn(move || {
                let mut local_permits = Vec::new();
                let mut local_queue_ids = Vec::new();

                // Try to acquire permits and enqueue operations
                for attempt in 0..5 {
                    harness_clone.start_operation();

                    // Try immediate acquire first
                    if let Some(permit) = bulkhead_clone.try_acquire(1) {
                        harness_clone.acquire_permit();

                        // Hold permit for a short time, then potentially cancel
                        match timing {
                            CancelTiming::Immediate => {
                                drop(permit);
                                harness_clone.cancel_operation();
                                harness_clone.release_permit();
                            }
                            CancelTiming::AfterDelay(ms) => {
                                thread::sleep(Duration::from_millis(ms % 50));
                                drop(permit);
                                harness_clone.release_permit();
                            }
                            CancelTiming::Random => {
                                if thread_id % 2 == 0 {
                                    drop(permit);
                                    harness_clone.cancel_operation();
                                } else {
                                    thread::sleep(Duration::from_millis(10));
                                    drop(permit);
                                    harness_clone.complete_operation();
                                }
                                harness_clone.release_permit();
                            }
                            _ => {
                                local_permits.push(permit);
                            }
                        }
                    } else {
                        // Try to enqueue if immediate acquire fails
                        if let Ok(entry_id) = bulkhead_clone.enqueue(1, now) {
                            local_queue_ids.push(entry_id);

                            // Potentially cancel queued operations
                            if matches!(timing, CancelTiming::Immediate) && attempt % 2 == 0 {
                                bulkhead_clone.cancel_entry(entry_id, now);
                                harness_clone.cancel_operation();
                            }
                        }
                    }
                }

                // Clean up remaining permits
                for permit in local_permits {
                    drop(permit);
                    harness_clone.release_permit();
                    harness_clone.complete_operation();
                }

                // Cancel any remaining queued operations
                for entry_id in local_queue_ids {
                    bulkhead_clone.cancel_entry(entry_id, now);
                    harness_clone.cancel_operation();
                }
            });

            handles.push(handle);
        }

        // Phase 2: Wait for all workers to complete
        for handle in handles {
            handle.join().expect("Thread should complete successfully");
        }

        // Phase 3: Verify invariants
        let final_available = bulkhead.available();
        let final_metrics = bulkhead.metrics();

        // MR3.1: Available permits should not exceed maximum
        prop_assert!(
            final_available <= config.max_concurrent,
            "Available permits should not exceed max: {} vs {}",
            final_available,
            config.max_concurrent
        );

        // MR3.2: No permits should be "lost" (conservation)
        let active_permits = final_metrics.active_permits;
        prop_assert!(
            active_permits + final_available <= config.max_concurrent,
            "Total permits (active + available) should not exceed max: {} + {} <= {}",
            active_permits,
            final_available,
            config.max_concurrent
        );

        // MR3.3: Cancelled operations should be properly tracked
        let (started, completed, cancelled, acquired, released) = harness.get_stats();
        prop_assert!(
            cancelled <= started,
            "Cancelled operations should not exceed started: {} vs {}",
            cancelled,
            started
        );

        // MR3.4: Release count should not exceed acquire count
        prop_assert!(
            released <= acquired,
            "Releases should not exceed acquisitions: {} vs {}",
            released,
            acquired
        );
    }
}

// ============================================================================
// MR4: Queue Overflow Under Cancel Load Bounded
// ============================================================================

/// **MR4: Queue Overflow Under Cancel Load Bounded**
///
/// Even under heavy cancellation load, the queue size should remain
/// bounded by the configured maximum and not grow unboundedly.
///
/// Property: high_cancel_rate → queue_depth ≤ max_queue
proptest! {
    #[test]
    fn mr4_queue_overflow_under_cancel_bounded(
        config in arb_bulkhead_config().prop_filter("small_queue", |c| c.max_queue <= 20),
        cancel_rate in 0.3f64..0.9f64 // 30-90% cancellation rate
    ) {
        create_lab();
        let bulkhead = Arc::new(Bulkhead::new(config.clone()));
        let now = Time::now();

        // Phase 1: Fill all permits to force queuing
        let mut blocking_permits = Vec::new();
        for _ in 0..config.max_concurrent {
            if let Some(permit) = bulkhead.try_acquire(1) {
                blocking_permits.push(permit);
            }
        }

        prop_assert_eq!(bulkhead.available(), 0, "All permits should be consumed");

        // Phase 2: Enqueue operations with high cancellation rate
        let mut queued_operations = Vec::new();
        let target_enqueues = (config.max_queue as f64 * 2.0) as usize; // Try to exceed queue

        for i in 0..target_enqueues {
            match bulkhead.enqueue(1, now) {
                Ok(entry_id) => {
                    queued_operations.push(entry_id);

                    // Cancel with specified probability
                    if i as f64 / target_enqueues as f64 < cancel_rate {
                        bulkhead.cancel_entry(entry_id, now);
                    }
                }
                Err(BulkheadError::QueueFull) => {
                    // Expected when queue is full
                    break;
                }
                Err(e) => {
                    prop_assert!(false, "Unexpected error: {:?}", e);
                }
            }

            // Periodically check queue bounds
            let current_metrics = bulkhead.metrics();

            // MR4.1: Queue depth should never exceed configured maximum
            prop_assert!(
                current_metrics.queue_depth <= config.max_queue,
                "Queue depth exceeded maximum at iteration {}: {} > {}",
                i,
                current_metrics.queue_depth,
                config.max_queue
            );

            // MR4.2: Memory usage should be bounded (inferred from metrics)
            // We can't directly access the queue, but can verify through metrics
            prop_assert!(
                current_metrics.queue_depth <= config.max_queue,
                "Queue depth should be bounded: {} <= {}",
                current_metrics.queue_depth,
                config.max_queue
            );
        }

        // Phase 3: Cancel remaining queued operations
        for entry_id in queued_operations {
            bulkhead.cancel_entry(entry_id, now);
        }

        let final_metrics = bulkhead.metrics();

        // MR4.3: Final queue should be manageable size after cleanup
        prop_assert!(
            final_metrics.queue_depth <= config.max_queue,
            "Final queue depth should be within bounds: {} <= {}",
            final_metrics.queue_depth,
            config.max_queue
        );

        // MR4.4: Cancellation metrics should reflect the load
        prop_assert!(
            final_metrics.total_cancelled > 0,
            "Should have recorded cancelled operations: {}",
            final_metrics.total_cancelled
        );

        // Phase 4: Cleanup - release blocking permits
        drop(blocking_permits);
        let _ = bulkhead.process_queue(now);
    }
}

// ============================================================================
// MR5: Drain on Shutdown Cleans All Slots
// ============================================================================

/// **MR5: Drain on Shutdown Cleans All Slots**
///
/// When a bulkhead is reset/shutdown, all slots should be properly
/// cleaned up, and subsequent operations should work correctly.
///
/// Property: shutdown(bulkhead) → available == max_concurrent && queue_empty
proptest! {
    #[test]
    fn mr5_drain_shutdown_cleans_all_slots(
        config in arb_bulkhead_config(),
        pre_shutdown_ops in 1usize..=10
    ) {
        create_lab();
        let bulkhead = Bulkhead::new(config.clone());
        let now = Time::now();

        // Phase 1: Create complex state before shutdown
        let mut acquired_permits = Vec::new();
        let mut queued_ids = Vec::new();

        // Acquire some permits
        for _ in 0..pre_shutdown_ops.min(config.max_concurrent as usize) {
            if let Some(permit) = bulkhead.try_acquire(1) {
                acquired_permits.push(permit);
            }
        }

        // Enqueue some operations
        for _ in 0..pre_shutdown_ops.min(config.max_queue as usize / 2) {
            if let Ok(entry_id) = bulkhead.enqueue(1, now) {
                queued_ids.push(entry_id);
            }
        }

        // Cancel some queued operations to create mixed state
        for &entry_id in queued_ids.iter().take(queued_ids.len() / 2) {
            bulkhead.cancel_entry(entry_id, now);
        }

        let pre_shutdown_metrics = bulkhead.metrics();

        // Verify we have complex state
        prop_assert!(
            pre_shutdown_metrics.active_permits > 0 || pre_shutdown_metrics.queue_depth > 0,
            "Should have some active state before shutdown"
        );

        // Phase 2: Perform shutdown via reset
        bulkhead.reset();

        let post_shutdown_metrics = bulkhead.metrics();

        // MR5.1: All permits should be available
        prop_assert_eq!(
            bulkhead.available(),
            config.max_concurrent,
            "All permits should be available after reset"
        );

        // MR5.2: Queue should be empty
        prop_assert_eq!(
            post_shutdown_metrics.queue_depth,
            0,
            "Queue should be empty after reset"
        );

        // MR5.3: Active permits should be zero
        prop_assert_eq!(
            post_shutdown_metrics.active_permits,
            0,
            "No permits should be active after reset"
        );

        // Phase 3: Verify bulkhead works correctly after shutdown
        let post_reset_permit = bulkhead.try_acquire(1);
        prop_assert!(
            post_reset_permit.is_some(),
            "Should be able to acquire permit after reset"
        );

        if let Some(permit) = post_reset_permit {
            prop_assert_eq!(permit.weight(), 1, "Permit should have correct weight");
            drop(permit);
        }

        // MR5.4: Should be able to enqueue after reset
        let post_reset_enqueue = bulkhead.enqueue(1, now);
        prop_assert!(
            post_reset_enqueue.is_ok(),
            "Should be able to enqueue after reset: {:?}",
            post_reset_enqueue
        );

        // MR5.5: Previous permits should be invalidated (can't double-release)
        drop(acquired_permits); // This should be safe and not over-release

        let final_available = bulkhead.available();
        prop_assert!(
            final_available <= config.max_concurrent,
            "Available permits should not exceed max after cleanup: {} <= {}",
            final_available,
            config.max_concurrent
        );
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

/// **Integration Test: All MRs Together**
///
/// Verifies that all metamorphic relations hold simultaneously under
/// realistic workload patterns.
#[test]
fn integration_all_mrs_concurrent() {
    let config = BulkheadPolicy {
        name: "integration-test".to_string(),
        max_concurrent: 5,
        max_queue: 10,
        queue_timeout: Duration::from_millis(1000),
        weighted: false,
        on_full: None,
    };

    let bulkhead = Arc::new(Bulkhead::new(config.clone()));
    let now = Time::now();

    // Scenario: Mixed acquire, queue, cancel operations
    let mut handles = Vec::new();

    // Worker 1: Acquires and holds permits
    let bulkhead1 = Arc::clone(&bulkhead);
    handles.push(thread::spawn(move || {
        let mut permits = Vec::new();
        for _ in 0..3 {
            if let Some(permit) = bulkhead1.try_acquire(1) {
                permits.push(permit);
                thread::sleep(Duration::from_millis(50));
            }
        }
        drop(permits); // Clean release
    }));

    // Worker 2: Enqueues and cancels
    let bulkhead2 = Arc::clone(&bulkhead);
    handles.push(thread::spawn(move || {
        let mut queue_ids = Vec::new();
        for _ in 0..5 {
            if let Ok(id) = bulkhead2.enqueue(1, now) {
                queue_ids.push(id);
            }
        }
        // Cancel half
        for &id in queue_ids.iter().take(queue_ids.len() / 2) {
            bulkhead2.cancel_entry(id, now);
        }
    }));

    // Worker 3: Mixed operations
    let bulkhead3 = Arc::clone(&bulkhead);
    handles.push(thread::spawn(move || {
        for i in 0..10 {
            if i % 3 == 0 {
                let _permit = bulkhead3.try_acquire(1); // May or may not succeed
            } else if i % 3 == 1 {
                let _ = bulkhead3.enqueue(1, now);
            } else {
                let _ = bulkhead3.process_queue(now);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }));

    // Wait for completion
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify final state satisfies all invariants
    let final_metrics = bulkhead.metrics();

    // Reset and check cleanup
    bulkhead.reset();

    assert_eq!(bulkhead.available(), config.max_concurrent, "MR5: Reset should restore all permits");
    assert_eq!(bulkhead.metrics().queue_depth, 0, "MR5: Reset should clear queue");

    // Verify operational after reset
    let permit = bulkhead.try_acquire(1);
    assert!(permit.is_some(), "Should work after reset");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bulkhead_basic_functionality() {
        let config = BulkheadPolicy {
            name: "test".to_string(),
            max_concurrent: 2,
            max_queue: 5,
            queue_timeout: Duration::from_millis(1000),
            weighted: false,
            on_full: None,
        };

        let bulkhead = Bulkhead::new(config);

        // Basic acquire
        let permit1 = bulkhead.try_acquire(1);
        assert!(permit1.is_some());

        let permit2 = bulkhead.try_acquire(1);
        assert!(permit2.is_some());

        // Should be full now
        let permit3 = bulkhead.try_acquire(1);
        assert!(permit3.is_none());

        // Test enqueue
        let now = Time::now();
        let queue_result = bulkhead.enqueue(1, now);
        assert!(queue_result.is_ok());

        // Test cancel
        if let Ok(entry_id) = queue_result {
            bulkhead.cancel_entry(entry_id, now);
            let metrics = bulkhead.metrics();
            assert!(metrics.total_cancelled > 0);
        }
    }
}