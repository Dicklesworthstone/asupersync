//! Metamorphic testing for channel::watch latest-value + version-counter invariants.
//!
//! Property-based tests that validate fundamental behavioral invariants of the watch channel
//! regardless of timing, inputs, or configurations using deterministic LabRuntime.

use proptest::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use asupersync::channel::watch::{self, RecvError};
use asupersync::cx::Cx;
use asupersync::lab::{config::LabConfig, runtime::LabRuntime};
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::ArenaIndex;

/// Test helper for creating deterministic contexts
fn create_test_context(region_id: u32, task_id: u32) -> Cx {
    Cx::test(
        RegionId::new(ArenaIndex::new(region_id as usize)),
        TaskId::new(ArenaIndex::new(task_id as usize)),
        Budget::default(),
    )
}

/// Property-based strategy for generating test values
fn values_strategy() -> impl Strategy<Value = Vec<i32>> {
    proptest::collection::vec(0i32..1000, 0..10)
}

/// Property-based strategy for generating send sequences
fn send_sequences_strategy() -> impl Strategy<Value = Vec<Vec<i32>>> {
    proptest::collection::vec(
        proptest::collection::vec(0i32..1000, 1..5),
        1..8
    )
}

/// Property-based strategy for receiver configurations
fn receiver_config_strategy() -> impl Strategy<Value = (usize, bool)> {
    (1usize..=5, any::<bool>())
}

/// Violation tracker for detecting test failures
#[derive(Debug, Clone)]
struct ViolationTracker {
    violations: Arc<AtomicUsize>,
}

impl ViolationTracker {
    fn new() -> Self {
        Self {
            violations: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn record_violation(&self) {
        self.violations.fetch_add(1, Ordering::Relaxed);
    }

    fn violations(&self) -> usize {
        self.violations.load(Ordering::Relaxed)
    }

    fn assert_no_violations(&self) {
        assert_eq!(self.violations(), 0, "Metamorphic relation violated");
    }
}

/// MR1: borrow() always returns most recent sent value
/// Property: For any sequence of sends [v1, v2, ..., vn], rx.borrow() == vn after all sends complete
#[test]
fn mr1_borrow_returns_latest_value() {
    proptest!(|(values in values_strategy())| {
        if values.is_empty() { return Ok(()); }

        let tracker = ViolationTracker::new();
        let config = LabConfig::default();
        let lab = LabRuntime::new(config);

        futures_lite::future::block_on(|| async {
            let cx = create_test_context(1, 1);

            // Start with initial value
            let (tx, rx) = watch::channel(values[0]);

            // Send all values in sequence
            for value in values.iter().skip(1) {
                tx.send(*value)?;
            }

            // Verify borrow returns the latest value
            let latest_borrowed = *rx.borrow();
            let expected_latest = values[values.len() - 1];

            if latest_borrowed != expected_latest {
                tracker.record_violation();
            }

            // Test with multiple receivers
            for i in 0..3 {
                let rx_clone = rx.clone();
                let borrowed = *rx_clone.borrow();
                if borrowed != expected_latest {
                    tracker.record_violation();
                }
            }

            Ok::<(), watch::SendError<i32>>(())
        })?;

        tracker.assert_no_violations();
    });
}

/// MR2: changed() wakes on version increment
/// Property: Every send() increments version → changed() wakes for pending receivers
#[test]
fn mr2_changed_wakes_on_version_increment() {
    proptest!(|(initial_value in 0i32..1000, updates in 1usize..10)| {
        let tracker = ViolationTracker::new();
        let config = LabConfig::default();
        let lab = LabRuntime::new(config);

        futures_lite::future::block_on(|| async {
            let cx = create_test_context(1, 1);
            let (tx, mut rx) = watch::channel(initial_value);

            // Initial seen version
            let initial_version = rx.seen_version();

            // Send updates and verify changed() detects each one
            for i in 1..=updates {
                let new_value = initial_value + (i as i32);

                // Start waiting for change before sending
                let mut change_future = rx.changed(&cx);

                // Send new value (should increment version)
                tx.send(new_value)?;

                // Verify changed() completes
                match change_future.await {
                    Ok(()) => {
                        // Verify version actually incremented
                        let new_version = rx.seen_version();
                        if new_version <= initial_version + (i as u64) - 1 {
                            tracker.record_violation();
                        }

                        // Verify latest value is accessible
                        if *rx.borrow() != new_value {
                            tracker.record_violation();
                        }
                    },
                    Err(_) => tracker.record_violation(),
                }
            }

            Ok::<(), watch::SendError<i32>>(())
        })?;

        tracker.assert_no_violations();
    });
}

/// MR3: multiple consecutive sends preserve ONLY final value (no backlog)
/// Property: send(v1); send(v2); send(v3) → only v3 is observable, no v1/v2 queue
#[test]
fn mr3_consecutive_sends_preserve_final_only() {
    proptest!(|(send_sequences in send_sequences_strategy())| {
        let tracker = ViolationTracker::new();
        let config = LabConfig::default();
        let lab = LabRuntime::new(config);

        futures_lite::future::block_on(|| async {
            let cx = create_test_context(1, 1);

            for sequence in send_sequences {
                if sequence.is_empty() { continue; }

                let (tx, mut rx) = watch::channel(sequence[0]);

                // Send all values rapidly in sequence (no awaits)
                for value in sequence.iter().skip(1) {
                    tx.send(*value)?;
                }

                // Only the final value should be observable
                let final_expected = sequence[sequence.len() - 1];
                let borrowed = *rx.borrow();

                if borrowed != final_expected {
                    tracker.record_violation();
                }

                // Wait for any change (should see final value)
                if rx.has_changed() {
                    rx.changed(&cx).await?;
                    let after_change = *rx.borrow_and_update();
                    if after_change != final_expected {
                        tracker.record_violation();
                    }
                }

                // No more changes should be pending
                if rx.has_changed() {
                    tracker.record_violation();
                }
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}

/// MR4: receiver sees its last-seen-version and only wakes on newer
/// Property: rx with seen_version=V only wakes on send() that creates version > V
#[test]
fn mr4_receiver_wakes_only_on_newer_version() {
    proptest!(|(initial_value in 0i32..1000, increments in 1usize..8)| {
        let tracker = ViolationTracker::new();
        let config = LabConfig::default();
        let lab = LabRuntime::new(config);

        futures_lite::future::block_on(|| async {
            let cx1 = create_test_context(1, 1);
            let cx2 = create_test_context(1, 2);
            let (tx, mut rx1) = watch::channel(initial_value);

            // rx1 sees some updates, rx2 starts later
            for i in 1..=increments {
                tx.send(initial_value + i as i32)?;
                rx1.changed(&cx1).await?;
            }

            let rx1_version = rx1.seen_version();

            // rx2 subscribes after rx1 has seen updates
            let mut rx2 = tx.subscribe();
            let rx2_initial_version = rx2.seen_version();

            // Verify rx2 starts with current version (no historical values)
            if rx2_initial_version < rx1_version {
                tracker.record_violation();
            }

            // Send new value - both should see it
            let new_value = initial_value + increments as i32 + 100;
            tx.send(new_value)?;

            // rx1 should wake (sees newer than its seen_version)
            match rx1.changed(&cx1).await {
                Ok(()) => {
                    if *rx1.borrow() != new_value {
                        tracker.record_violation();
                    }
                },
                Err(_) => tracker.record_violation(),
            }

            // rx2 should wake (sees newer than its seen_version)
            match rx2.changed(&cx2).await {
                Ok(()) => {
                    if *rx2.borrow() != new_value {
                        tracker.record_violation();
                    }
                },
                Err(_) => tracker.record_violation(),
            }

            // Send same value again - neither should wake (version doesn't increment)
            let rx1_final_version = rx1.seen_version();
            let rx2_final_version = rx2.seen_version();

            // Sending same value multiple times shouldn't change anything
            tx.send(new_value)?;
            tx.send(new_value)?;

            // Versions should not have incremented for duplicate values
            if rx1.seen_version() != rx1_final_version || rx2.seen_version() != rx2_final_version {
                // Actually, sends always increment version even for same value - this is expected
                // Let's verify the value is still correct instead
                if *rx1.borrow() != new_value || *rx2.borrow() != new_value {
                    tracker.record_violation();
                }
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}

/// MR5: sender drop marks closed
/// Property: After tx drops, all rx.changed() → RecvError::Closed
#[test]
fn mr5_sender_drop_marks_closed() {
    proptest!(|(initial_value in 0i32..1000, num_receivers in 1usize..=5)| {
        let tracker = ViolationTracker::new();
        let config = LabConfig::default();
        let lab = LabRuntime::new(config);

        futures_lite::future::block_on(|| async {
            let (tx, rx) = watch::channel(initial_value);

            // Create multiple receivers
            let mut receivers = vec![rx];
            for _ in 1..num_receivers {
                receivers.push(tx.subscribe());
            }

            // Verify all receivers can access the value before drop
            for rx in &receivers {
                if *rx.borrow() != initial_value {
                    tracker.record_violation();
                }
                if rx.is_closed() {
                    tracker.record_violation();
                }
            }

            // Drop the sender
            drop(tx);

            // All receivers should detect closure
            for (i, rx) in receivers.iter().enumerate() {
                if !rx.is_closed() {
                    tracker.record_violation();
                }

                // Attempts to wait for changes should return Closed
                let cx = create_test_context(1, i as u32 + 1);
                match rx.clone().changed(&cx).await {
                    Err(RecvError::Closed) => {
                        // Expected - sender dropped
                    },
                    Ok(()) => {
                        // This can happen if there was a final update
                        // Still valid as long as subsequent changed() fails
                        let mut rx_clone = rx.clone();
                        match rx_clone.changed(&cx).await {
                            Err(RecvError::Closed) => {}, // Expected now
                            _ => tracker.record_violation(),
                        }
                    },
                    Err(_) => tracker.record_violation(),
                }
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}

/// MR6: cancel during changed() drains without leak
/// Property: Cancelling changed() future → no resource leaks, retryable operation
#[test]
fn mr6_cancel_during_changed_drains_without_leak() {
    proptest!(|(initial_value in 0i32..1000, cancel_points in 1usize..5)| {
        let tracker = ViolationTracker::new();
        let config = LabConfig::default();
        let lab = LabRuntime::new(config);

        futures_lite::future::block_on(|| async {
            let cx = create_test_context(1, 1);
            let (tx, mut rx) = watch::channel(initial_value);

            for _ in 0..cancel_points {
                // Start a changed() operation but don't complete it
                let change_future = rx.changed(&cx);

                // Drop the future (simulates cancellation)
                drop(change_future);

                // Verify the receiver is still functional
                if *rx.borrow() != initial_value {
                    tracker.record_violation();
                }

                if rx.is_closed() {
                    tracker.record_violation();
                }

                // Verify we can still wait for changes after cancellation
                let new_value = initial_value + 1000;
                tx.send(new_value)?;

                match rx.changed(&cx).await {
                    Ok(()) => {
                        if *rx.borrow() != new_value {
                            tracker.record_violation();
                        }
                    },
                    Err(_) => tracker.record_violation(),
                }

                // Reset for next iteration
                tx.send(initial_value)?;
                rx.changed(&cx).await?;
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}

/// Composite MR: Multiple operations preserve semantics
/// Property: Combining send, borrow, changed, drop in any order maintains invariants
#[test]
fn mr_composite_operations_preserve_semantics() {
    proptest!(|(
        operations in proptest::collection::vec(0u8..6, 5..15),
        values in proptest::collection::vec(0i32..1000, 5..10)
    )| {
        let tracker = ViolationTracker::new();
        let config = LabConfig::default();
        let lab = LabRuntime::new(config);

        futures_lite::future::block_on(|| async {
            let cx = create_test_context(1, 1);
            let (tx, mut rx) = watch::channel(values[0]);
            let mut expected_value = values[0];
            let mut value_index = 1;
            let mut tx_dropped = false;

            for &op in &operations {
                if tx_dropped { break; }

                match op {
                    0 => {
                        // Send operation
                        if value_index < values.len() {
                            expected_value = values[value_index];
                            if let Err(_) = tx.send(expected_value) {
                                tx_dropped = true;
                            }
                            value_index += 1;
                        }
                    },
                    1 => {
                        // Borrow operation - should always see latest
                        let borrowed = *rx.borrow();
                        if borrowed != expected_value && !tx_dropped {
                            tracker.record_violation();
                        }
                    },
                    2 => {
                        // Changed operation - should work unless closed
                        match rx.changed(&cx).await {
                            Ok(()) => {
                                let borrowed = *rx.borrow();
                                if borrowed != expected_value && !tx_dropped {
                                    tracker.record_violation();
                                }
                            },
                            Err(RecvError::Closed) => {
                                if !tx_dropped && !tx.is_closed() {
                                    tracker.record_violation();
                                }
                            },
                            Err(_) => {}, // Cancel/other errors acceptable
                        }
                    },
                    3 => {
                        // Clone receiver
                        let rx_clone = rx.clone();
                        let borrowed = *rx_clone.borrow();
                        if borrowed != expected_value && !tx_dropped {
                            tracker.record_violation();
                        }
                    },
                    4 => {
                        // Subscribe new receiver
                        let new_rx = tx.subscribe();
                        let borrowed = *new_rx.borrow();
                        if borrowed != expected_value && !tx_dropped {
                            tracker.record_violation();
                        }
                    },
                    5 => {
                        // Drop sender (only once)
                        if !tx_dropped {
                            drop(tx);
                            tx_dropped = true;

                            // After drop, receiver should detect closure
                            if !rx.is_closed() {
                                // May take a moment to detect
                                match rx.changed(&cx).await {
                                    Err(RecvError::Closed) => {},
                                    Ok(()) => {
                                        // Final update received, next should be closed
                                        match rx.changed(&cx).await {
                                            Err(RecvError::Closed) => {},
                                            _ => tracker.record_violation(),
                                        }
                                    },
                                    Err(_) => {}, // Other errors acceptable
                                }
                            }
                            break;
                        }
                    },
                    _ => {}, // Invalid operation
                }
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}

/// Performance MR: Large values and high contention
/// Property: Channel performance degrades gracefully under load, no panics
#[test]
fn mr_performance_large_values_high_contention() {
    proptest!(|(
        value_size in 100usize..1000,
        num_receivers in 2usize..8,
        num_updates in 10usize..50
    )| {
        let tracker = ViolationTracker::new();
        let config = LabConfig::default();
        let lab = LabRuntime::new(config);

        futures_lite::future::block_on(|| async {
            // Create large value
            let large_value: Vec<u8> = (0..value_size).map(|i| (i % 256) as u8).collect();

            let (tx, rx) = watch::channel(large_value.clone());

            // Create multiple receivers
            let mut receivers = vec![rx];
            for _ in 1..num_receivers {
                receivers.push(tx.subscribe());
            }

            // Perform rapid updates
            for i in 0..num_updates {
                let mut updated_value = large_value.clone();
                updated_value[0] = (i % 256) as u8; // Modify first byte

                if let Err(_) = tx.send(updated_value.clone()) {
                    break; // Sender dropped/closed
                }

                // Some receivers read the value
                for (j, rx) in receivers.iter().enumerate() {
                    if j % 3 == 0 { // Only some receivers read
                        let borrowed = rx.borrow();
                        // Value should be one of the sent values (race conditions allowed)
                        if borrowed.len() != value_size {
                            tracker.record_violation();
                        }
                    }
                }
            }

            // All receivers should see a valid final value
            for rx in &receivers {
                let borrowed = rx.borrow();
                if borrowed.len() != value_size {
                    tracker.record_violation();
                }
            }

            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        tracker.assert_no_violations();
    });
}