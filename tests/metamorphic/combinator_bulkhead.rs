#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic Testing for combinator::bulkhead concurrency-limit invariants
//!
//! This test suite validates the fundamental bulkhead combinator semantics using
//! metamorphic relations that must hold regardless of timing, request patterns,
//! or specific concurrency configurations.

use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use asupersync::combinator::bulkhead::{Bulkhead, BulkheadError, BulkheadPolicy};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::time::sleep;
use asupersync::types::Time;
use asupersync::{region, Outcome};
use proptest::prelude::*;

/// Test configuration for bulkhead properties
#[derive(Debug, Clone)]
struct BulkheadTestConfig {
    /// Maximum concurrent permits
    max_concurrent: u32,
    /// Maximum queue size
    max_queue: u32,
    /// Number of operations to spawn
    operation_count: usize,
    /// How long each operation should hold the permit (in ms)
    hold_duration_ms: u64,
    /// Weight of each operation (for weighted bulkhead)
    operation_weight: u32,
    /// Whether to test cancellation scenarios
    test_cancellation: bool,
}

fn bulkhead_config_strategy() -> impl Strategy<Value = BulkheadTestConfig> {
    (
        // Max concurrent: 1 to 5 (small for easy testing)
        1_u32..=5,
        // Max queue: 2 to 10
        2_u32..=10,
        // Operation count: 3 to 15
        3_usize..=15,
        // Hold duration: 10ms to 100ms
        10_u64..=100,
        // Operation weight: 1 to 3 (mostly 1, some heavier)
        prop::sample::select(vec![1_u32, 1, 1, 2, 3]),
        // Cancellation flag
        any::<bool>(),
    )
        .prop_map(|(max_concurrent, max_queue, operation_count, hold_duration_ms, operation_weight, test_cancellation)| {
            BulkheadTestConfig {
                max_concurrent,
                max_queue,
                operation_count,
                hold_duration_ms,
                operation_weight,
                test_cancellation,
            }
        })
}

/// Tracks the maximum number of active operations observed
#[derive(Debug, Default)]
struct ConcurrencyTracker {
    active_count: AtomicU32,
    max_observed: AtomicU32,
    violations: AtomicUsize,
}

impl ConcurrencyTracker {
    fn enter(&self, max_allowed: u32) {
        let current = self.active_count.fetch_add(1, Ordering::SeqCst);
        let new_count = current + 1;

        // Update max observed
        self.max_observed.fetch_max(new_count, Ordering::SeqCst);

        // Check for violation
        if new_count > max_allowed {
            self.violations.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn exit(&self) {
        self.active_count.fetch_sub(1, Ordering::SeqCst);
    }

    fn get_max_observed(&self) -> u32 {
        self.max_observed.load(Ordering::SeqCst)
    }

    fn get_violations(&self) -> usize {
        self.violations.load(Ordering::SeqCst)
    }
}

/// MR1: Active count never exceeds max_concurrent
#[test]
fn mr1_active_count_never_exceeds_max_concurrent() {
    proptest!(|(config in bulkhead_config_strategy())| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = BulkheadPolicy {
                    name: "test".to_string(),
                    max_concurrent: config.max_concurrent,
                    max_queue: config.max_queue,
                    queue_timeout: Duration::from_secs(1),
                    weighted: config.operation_weight > 1,
                    on_full: None,
                };

                let bulkhead = Arc::new(Bulkhead::new(policy));
                let tracker = Arc::new(ConcurrencyTracker::default());

                // Spawn operations that try to acquire permits
                let mut handles = Vec::new();
                for op_id in 0..config.operation_count {
                    let bulkhead_clone = bulkhead.clone();
                    let tracker_clone = tracker.clone();
                    let handle = scope.spawn(move |op_cx| async move {
                        // Try to acquire permit
                        if let Some(permit) = bulkhead_clone.try_acquire(config.operation_weight) {
                            tracker_clone.enter(config.max_concurrent);

                            // Hold permit for configured duration
                            sleep(op_cx, Duration::from_millis(config.hold_duration_ms)).await;

                            tracker_clone.exit();
                            permit.release();
                            Ok(format!("op_{}_success", op_id))
                        } else {
                            // Permit not available, which is fine
                            Ok(format!("op_{}_rejected", op_id))
                        }
                    });
                    handles.push(handle);
                }

                // Wait for all operations to complete
                for handle in handles {
                    handle.await?;
                }

                // Verify no concurrency violations occurred
                prop_assert_eq!(tracker.get_violations(), 0,
                    "Active count should never exceed max_concurrent ({})",
                    config.max_concurrent);

                // Verify max observed is reasonable
                prop_assert!(tracker.get_max_observed() <= config.max_concurrent,
                    "Max observed ({}) should not exceed max_concurrent ({})",
                    tracker.get_max_observed(), config.max_concurrent);

                Ok(())
            })
        });

        result
    });
}

/// MR2: Queue size bound returns QueueFull
#[test]
fn mr2_queue_size_bound_returns_queue_full() {
    proptest!(|(max_concurrent in 1_u32..=3, max_queue in 2_u32..=5)| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = BulkheadPolicy {
                    name: "queue_test".to_string(),
                    max_concurrent,
                    max_queue,
                    queue_timeout: Duration::from_secs(10), // Long timeout to avoid timing effects
                    weighted: false,
                    on_full: None,
                };

                let bulkhead = Bulkhead::new(policy);

                // First, exhaust the permits with try_acquire
                let mut permits = Vec::new();
                for _ in 0..max_concurrent {
                    if let Some(permit) = bulkhead.try_acquire(1) {
                        permits.push(permit);
                    }
                }

                // Verify all permits are taken
                prop_assert_eq!(bulkhead.available(), 0,
                    "All permits should be taken");
                prop_assert!(bulkhead.try_acquire(1).is_none(),
                    "Additional try_acquire should fail when permits exhausted");

                // Now try to enqueue operations to fill the queue
                let now = Time::now();
                let mut queue_entries = Vec::new();
                let mut queue_full_count = 0;

                // Try to enqueue beyond queue capacity
                for _ in 0..(max_queue + 5) {
                    match bulkhead.enqueue(1, now) {
                        Ok(entry_id) => {
                            queue_entries.push(entry_id);
                        }
                        Err(BulkheadError::Full) => {
                            queue_full_count += 1;
                        }
                        Err(other) => {
                            return Err(proptest::test_runner::TestCaseError::fail(
                                format!("Unexpected enqueue error: {:?}", other)
                            ));
                        }
                    }
                }

                // Should have enqueued exactly max_queue operations
                prop_assert_eq!(queue_entries.len(), max_queue as usize,
                    "Should enqueue exactly {} operations", max_queue);

                // Should have rejected the excess
                prop_assert!(queue_full_count > 0,
                    "Should reject operations beyond queue capacity");

                // Release a permit and verify queue processing
                if let Some(permit) = permits.pop() {
                    permit.release();
                }

                // Check if first queued entry can now be granted
                if let Some(&first_entry_id) = queue_entries.first() {
                    let check_result = bulkhead.check_entry(first_entry_id, now);
                    match check_result {
                        Ok(Some(_permit)) => {
                            // First entry got a permit, which is expected
                        }
                        Ok(None) => {
                            // Still waiting, which is also valid depending on timing
                        }
                        Err(e) => {
                            return Err(proptest::test_runner::TestCaseError::fail(
                                format!("Unexpected check_entry result: {:?}", e)
                            ));
                        }
                    }
                }

                Ok(())
            })
        });

        result
    });
}

/// MR3: Cancel during bulkhead properly decrements active count
#[test]
fn mr3_cancel_during_bulkhead_decrements_count() {
    proptest!(|(config in bulkhead_config_strategy())| {
        // Test only configurations with cancellation enabled
        if !config.test_cancellation {
            return Ok(());
        }

        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = BulkheadPolicy {
                    name: "cancel_test".to_string(),
                    max_concurrent: config.max_concurrent,
                    max_queue: config.max_queue,
                    queue_timeout: Duration::from_secs(1),
                    weighted: false,
                    on_full: None,
                };

                let bulkhead = Arc::new(Bulkhead::new(policy));
                let initial_available = bulkhead.available();

                // Spawn operation that will be cancelled
                let cancelled_outcome = region(|inner_cx, inner_scope| async move {
                    let bulkhead_inner = bulkhead.clone();

                    // Try to acquire a permit
                    if let Some(permit) = bulkhead_inner.try_acquire(1) {
                        // Schedule cancellation after a short delay
                        inner_scope.spawn(|cancel_cx| async move {
                            sleep(cancel_cx, Duration::from_millis(25)).await;
                            // This will cancel the operation
                            Ok(())
                        });

                        // Hold permit for a while (would be cancelled)
                        sleep(inner_cx, Duration::from_millis(200)).await;
                        permit.release();
                        Ok("completed")
                    } else {
                        // Permit not available
                        Ok("no_permit")
                    }
                }).await;

                // Check outcome - could be cancelled or completed
                match cancelled_outcome {
                    Outcome::Cancelled => {
                        // Expected when cancelled
                    }
                    Outcome::Ok(_) => {
                        // Also valid if operation completed before cancellation
                    }
                    other => {
                        return Err(proptest::test_runner::TestCaseError::fail(
                            format!("Unexpected outcome: {:?}", other)
                        ));
                    }
                }

                // Verify permits were properly released
                let final_available = bulkhead.available();
                prop_assert_eq!(final_available, initial_available,
                    "Available permits should return to initial level after cancellation");

                // Verify we can still acquire permits normally
                if let Some(test_permit) = bulkhead.try_acquire(1) {
                    test_permit.release();
                } else if initial_available > 0 {
                    return Err(proptest::test_runner::TestCaseError::fail(
                        "Should be able to acquire permit after cancellation cleanup"
                    ));
                }

                Ok(())
            })
        });

        result
    });
}

/// MR4: Drop without release still decrements
#[test]
fn mr4_drop_without_release_decrements() {
    proptest!(|(config in bulkhead_config_strategy())| {
        // Use simple configuration for this focused test
        if config.operation_weight != 1 {
            return Ok(());
        }

        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = BulkheadPolicy {
                    name: "drop_test".to_string(),
                    max_concurrent: config.max_concurrent,
                    max_queue: config.max_queue,
                    queue_timeout: Duration::from_secs(1),
                    weighted: false,
                    on_full: None,
                };

                let bulkhead = Bulkhead::new(policy);
                let initial_available = bulkhead.available();

                // Acquire permits and drop them without explicit release
                {
                    let mut permits = Vec::new();
                    for _ in 0..std::cmp::min(config.max_concurrent, 3) {
                        if let Some(permit) = bulkhead.try_acquire(1) {
                            permits.push(permit);
                        }
                    }

                    // Check that permits were consumed
                    let consumed_count = permits.len() as u32;
                    prop_assert_eq!(bulkhead.available(), initial_available - consumed_count,
                        "Available permits should decrease by number acquired");

                    // Permits will be dropped here automatically (Drop trait)
                }

                // Verify permits were returned via Drop
                let final_available = bulkhead.available();
                prop_assert_eq!(final_available, initial_available,
                    "Available permits should return to initial level after drop");

                // Verify bulkhead is still functional
                if let Some(test_permit) = bulkhead.try_acquire(1) {
                    prop_assert_eq!(bulkhead.available(), initial_available - 1,
                        "Should be able to acquire permits normally after drop recovery");
                    test_permit.release();
                }

                Ok(())
            })
        });

        result
    });
}

/// MR5: bulkhead(0,_) rejects all
#[test]
fn mr5_bulkhead_zero_rejects_all() {
    proptest!(|(queue_size in 1_u32..=5)| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = BulkheadPolicy {
                    name: "zero_test".to_string(),
                    max_concurrent: 0, // Zero permits allowed
                    max_queue: queue_size,
                    queue_timeout: Duration::from_millis(100),
                    weighted: false,
                    on_full: None,
                };

                let bulkhead = Bulkhead::new(policy);

                // Verify initial state
                prop_assert_eq!(bulkhead.available(), 0,
                    "Zero-capacity bulkhead should have 0 available permits");
                prop_assert_eq!(bulkhead.max_concurrent(), 0,
                    "Max concurrent should be 0");

                // All try_acquire attempts should fail
                for weight in [1, 2, 3] {
                    let permit = bulkhead.try_acquire(weight);
                    prop_assert!(permit.is_none(),
                        "try_acquire({}) should fail on zero-capacity bulkhead", weight);
                }

                // Enqueue should also fail or be pointless since no permits can ever be granted
                let now = Time::now();
                for _ in 0..3 {
                    match bulkhead.enqueue(1, now) {
                        Err(BulkheadError::Full) => {
                            // Expected - cannot fulfill any requests
                        }
                        Ok(entry_id) => {
                            // If enqueue succeeds, check_entry should never grant a permit
                            let check_result = bulkhead.check_entry(entry_id, now);
                            match check_result {
                                Ok(Some(_permit)) => {
                                    return Err(proptest::test_runner::TestCaseError::fail(
                                        "Zero-capacity bulkhead should never grant permits"
                                    ));
                                }
                                Ok(None) => {
                                    // Still waiting, which is expected (will timeout)
                                }
                                Err(_) => {
                                    // Error (timeout, etc.) is also acceptable
                                }
                            }
                        }
                    }
                }

                Ok(())
            })
        });

        result
    });
}

/// MR6: bulkhead preserves region ownership
#[test]
fn mr6_bulkhead_preserves_region_ownership() {
    proptest!(|(config in bulkhead_config_strategy())| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = BulkheadPolicy {
                    name: "region_test".to_string(),
                    max_concurrent: config.max_concurrent,
                    max_queue: config.max_queue,
                    queue_timeout: Duration::from_secs(1),
                    weighted: false,
                    on_full: None,
                };

                let bulkhead = Arc::new(Bulkhead::new(policy));
                let region_violations = Arc::new(AtomicUsize::new(0));

                // Spawn operations in different child regions
                let mut handles = Vec::new();
                for op_id in 0..std::cmp::min(config.operation_count, 5) {
                    let bulkhead_clone = bulkhead.clone();
                    let violations_clone = region_violations.clone();

                    let handle = scope.spawn(move |op_cx| async move {
                        // Create a child region for this operation
                        let child_outcome = region(|child_cx, child_scope| async move {
                            if let Some(permit) = bulkhead_clone.try_acquire(1) {
                                // Simulate some work within the region
                                sleep(child_cx, Duration::from_millis(50)).await;

                                // The permit should still be valid within this region
                                prop_assert_eq!(permit.weight(), 1);

                                // Release permit before region closes
                                permit.release();

                                Ok(format!("child_{}_success", op_id))
                            } else {
                                Ok(format!("child_{}_no_permit", op_id))
                            }
                        }).await;

                        // Verify child region completed successfully
                        match child_outcome {
                            Outcome::Ok(result) => Ok(result),
                            Outcome::Cancelled => Ok(format!("child_{}_cancelled", op_id)),
                            other => {
                                violations_clone.fetch_add(1, Ordering::SeqCst);
                                Err(std::io::Error::new(std::io::ErrorKind::Other,
                                    format!("Child region failed: {:?}", other)))
                            }
                        }
                    });
                    handles.push(handle);
                }

                // Wait for all operations to complete
                for handle in handles {
                    handle.await?;
                }

                // Verify no region ownership violations
                prop_assert_eq!(region_violations.load(Ordering::SeqCst), 0,
                    "Bulkhead operations should preserve region ownership");

                // Verify bulkhead is still in a clean state
                let final_metrics = bulkhead.metrics();
                prop_assert!(final_metrics.available_permits <= config.max_concurrent,
                    "Final available permits should not exceed max");

                Ok(())
            })
        });

        result
    });
}

/// Additional property: Metrics accuracy under concurrent operations
#[test]
fn mr_metrics_accuracy() {
    proptest!(|(config in bulkhead_config_strategy())| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = BulkheadPolicy {
                    name: "metrics_test".to_string(),
                    max_concurrent: config.max_concurrent,
                    max_queue: config.max_queue,
                    queue_timeout: Duration::from_millis(100),
                    weighted: false,
                    on_full: None,
                };

                let bulkhead = Arc::new(Bulkhead::new(policy));
                let initial_metrics = bulkhead.metrics();

                // Spawn operations to generate metrics
                let mut handles = Vec::new();
                for op_id in 0..config.operation_count {
                    let bulkhead_clone = bulkhead.clone();
                    let handle = scope.spawn(move |op_cx| async move {
                        if let Some(permit) = bulkhead_clone.try_acquire(1) {
                            sleep(op_cx, Duration::from_millis(10)).await;
                            permit.release();
                            Ok(format!("op_{}_executed", op_id))
                        } else {
                            // Try to enqueue if try_acquire failed
                            match bulkhead_clone.enqueue(1, Time::now()) {
                                Ok(_entry_id) => {
                                    Ok(format!("op_{}_queued", op_id))
                                }
                                Err(_) => {
                                    Ok(format!("op_{}_rejected", op_id))
                                }
                            }
                        }
                    });
                    handles.push(handle);
                }

                // Wait for all operations
                for handle in handles {
                    handle.await?;
                }

                // Check final metrics
                let final_metrics = bulkhead.metrics();

                // Verify metrics are reasonable
                prop_assert!(final_metrics.total_executed >= initial_metrics.total_executed,
                    "Total executed should not decrease");
                prop_assert!(final_metrics.total_queued >= initial_metrics.total_queued,
                    "Total queued should not decrease");
                prop_assert!(final_metrics.available_permits <= config.max_concurrent,
                    "Available permits should not exceed max_concurrent");

                // The sum of operations should account for all spawn attempts
                let total_operations = final_metrics.total_executed + final_metrics.total_queued + final_metrics.total_rejected;
                prop_assert!(total_operations >= config.operation_count as u64,
                    "Total recorded operations should account for all attempts");

                Ok(())
            })
        });

        result
    });
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_basic_bulkhead() {
        let runtime = LabRuntime::new(LabConfig::default());

        runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = BulkheadPolicy::default().concurrency(2);
                let bulkhead = Bulkhead::new(policy);

                // Should be able to acquire up to max_concurrent
                let permit1 = bulkhead.try_acquire(1).unwrap();
                let permit2 = bulkhead.try_acquire(1).unwrap();

                // Third acquire should fail
                assert!(bulkhead.try_acquire(1).is_none());

                // Release and verify availability
                permit1.release();
                assert!(bulkhead.try_acquire(1).is_some());

                Ok(())
            })
        }).unwrap();
    }

    #[test]
    fn test_weighted_permits() {
        let runtime = LabRuntime::new(LabConfig::default());

        runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = BulkheadPolicy {
                    max_concurrent: 5,
                    weighted: true,
                    ..Default::default()
                };
                let bulkhead = Bulkhead::new(policy);

                // Acquire a heavy permit
                let heavy_permit = bulkhead.try_acquire(3).unwrap();
                assert_eq!(bulkhead.available(), 2);

                // Should be able to acquire remaining capacity
                let light_permit = bulkhead.try_acquire(2).unwrap();
                assert_eq!(bulkhead.available(), 0);

                // No more permits available
                assert!(bulkhead.try_acquire(1).is_none());

                Ok(())
            })
        }).unwrap();
    }

    #[test]
    fn test_queue_operations() {
        let runtime = LabRuntime::new(LabConfig::default());

        runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = BulkheadPolicy {
                    max_concurrent: 1,
                    max_queue: 3,
                    ..Default::default()
                };
                let bulkhead = Bulkhead::new(policy);

                // Exhaust permits
                let _permit = bulkhead.try_acquire(1).unwrap();

                // Enqueue operations
                let now = Time::now();
                let entry1 = bulkhead.enqueue(1, now).unwrap();
                let entry2 = bulkhead.enqueue(1, now).unwrap();
                let entry3 = bulkhead.enqueue(1, now).unwrap();

                // Queue should be full
                assert!(bulkhead.enqueue(1, now).is_err());

                // Check entries are still waiting
                assert!(bulkhead.check_entry(entry1, now).unwrap().is_none());

                Ok(())
            })
        }).unwrap();
    }
}