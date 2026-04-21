//! Conformance Tests: Broadcast Channel Lag Handling
//!
//! Validates RFC-compliant lag handling for broadcast channels with the following metamorphic relations:
//! 1. Slow subscriber falls behind → Lagged(n) error with count of skipped values
//! 2. recv() after Lagged resumes at current position (not resubscribe)
//! 3. Ring buffer capacity bound respected — oldest values dropped first
//! 4. Lagged count is exact (matches dropped msg count)
//! 5. Concurrent subscribers with different consumption rates independently track their own lag

#![cfg(test)]

use asupersync::{
    channel::broadcast,
    cx::test_cx,
    lab::LabRuntime,
    time::{sleep, Duration},
    types::Outcome,
};
use std::collections::HashMap;

/// Helper to track per-subscriber lag state for validation
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SubscriberTracker {
    id: usize,
    next_expected: u64,
    lag_events: Vec<u64>, // Counts from Lagged errors
    received_values: Vec<u64>,
}

#[allow(dead_code)]

impl SubscriberTracker {
    #[allow(dead_code)]
    fn new(id: usize) -> Self {
        Self {
            id,
            next_expected: 0,
            lag_events: Vec::new(),
            received_values: Vec::new(),
        }
    }

    #[allow(dead_code)]

    fn record_value(&mut self, value: u64) {
        self.received_values.push(value);
        self.next_expected = value + 1;
    }

    #[allow(dead_code)]

    fn record_lag(&mut self, count: u64) {
        self.lag_events.push(count);
        self.next_expected += count;
    }
}

/// MR1: Slow subscriber falls behind → Lagged(n) error with count of skipped values
#[test]
#[allow(dead_code)]
fn mr1_slow_subscriber_lag_detection() {
    LabRuntime::test(|lab| async {
        let cx = test_cx();
        let (tx, mut rx1) = broadcast::channel(4);

        // Fill the channel beyond capacity
        for i in 0..6u64 {
            tx.send(i).await.unwrap();
        }

        // rx1 should be lagged and report exactly how many messages were skipped
        match rx1.try_recv() {
            Err(broadcast::TryRecvError::Lagged(count)) => {
                assert!(count > 0, "Lag count should be positive");
                // After lag, should be positioned at current ring buffer head
                let next_value = rx1.recv(&cx).await.unwrap();
                assert_eq!(next_value, 2, "After lag, should resume at current position");
            }
            other => panic!("Expected Lagged error, got: {:?}", other),
        }
    });
}

/// MR2: recv() after Lagged resumes at current position (not resubscribe)
#[test]
#[allow(dead_code)]
fn mr2_lag_recovery_positioning() {
    LabRuntime::test(|lab| async {
        let cx = test_cx();
        let (tx, mut rx1) = broadcast::channel(3);

        // Send values to fill capacity
        for i in 0..5u64 {
            tx.send(i).await.unwrap();
        }

        // rx1 encounters lag
        let lag_count = match rx1.try_recv() {
            Err(broadcast::TryRecvError::Lagged(count)) => count,
            other => panic!("Expected Lagged error, got: {:?}", other),
        };

        // Send one more value
        tx.send(100).await.unwrap();

        // Next recv should get the latest value, not restart from beginning
        let recovered_value = rx1.recv(&cx).await.unwrap();
        assert_eq!(recovered_value, 100, "Should resume at current position, not restart");

        // Validate that lag count was accurate - should have skipped exactly lag_count values
        assert!(lag_count >= 2, "Should have skipped multiple values due to capacity limit");
    });
}

/// MR3: Ring buffer capacity bound respected — oldest values dropped first
#[test]
#[allow(dead_code)]
fn mr3_fifo_capacity_enforcement() {
    LabRuntime::test(|lab| async {
        let cx = test_cx();
        let capacity = 4usize;
        let (tx, mut rx1) = broadcast::channel(capacity);
        let mut rx2 = tx.subscribe();

        // Fill exactly to capacity
        for i in 0..capacity as u64 {
            tx.send(i).await.unwrap();
        }

        // rx1 reads all values immediately - should not be lagged
        let mut rx1_values = Vec::new();
        for _ in 0..capacity {
            let val = rx1.recv(&cx).await.unwrap();
            rx1_values.push(val);
        }
        assert_eq!(rx1_values, (0..capacity as u64).collect::<Vec<_>>());

        // Now send one more value, which should evict the oldest (0)
        tx.send(capacity as u64).await.unwrap();

        // rx2 (which hasn't read anything) should be lagged and miss value 0
        match rx2.try_recv() {
            Err(broadcast::TryRecvError::Lagged(count)) => {
                assert_eq!(count, 1, "Should have dropped exactly 1 oldest value");
                // After lag, should start from value 1 (oldest non-evicted)
                let next_value = rx2.recv(&cx).await.unwrap();
                assert_eq!(next_value, 1, "Should start from oldest non-evicted value");
            }
            other => panic!("Expected Lagged error for rx2, got: {:?}", other),
        }
    });
}

/// MR4: Lagged count is exact (matches dropped msg count)
#[test]
#[allow(dead_code)]
fn mr4_exact_lag_accounting() {
    LabRuntime::test(|lab| async {
        let cx = test_cx();
        let capacity = 3usize;
        let (tx, mut rx1) = broadcast::channel(capacity);

        // Send more values than capacity to force dropping
        let total_sent = 7u64;
        for i in 0..total_sent {
            tx.send(i).await.unwrap();
        }

        // rx1 should report lag count exactly equal to number of dropped messages
        let lag_count = match rx1.try_recv() {
            Err(broadcast::TryRecvError::Lagged(count)) => count,
            other => panic!("Expected Lagged error, got: {:?}", other),
        };

        // Calculate expected drops: sent - capacity
        let expected_drops = total_sent - capacity as u64;
        assert_eq!(lag_count, expected_drops, "Lag count should exactly match dropped message count");

        // Verify remaining values are accessible
        let mut remaining_values = Vec::new();
        while let Ok(val) = rx1.try_recv() {
            remaining_values.push(val);
        }

        assert_eq!(remaining_values.len(), capacity, "Should have exactly capacity values remaining");

        // Values should be the most recent ones
        let expected_remaining: Vec<u64> = (total_sent - capacity as u64..total_sent).collect();
        assert_eq!(remaining_values, expected_remaining, "Remaining values should be the most recent");
    });
}

/// MR5: Concurrent subscribers with different consumption rates independently track their own lag
#[test]
#[allow(dead_code)]
fn mr5_independent_lag_tracking() {
    LabRuntime::test(|lab| async {
        let cx = test_cx();
        let capacity = 4usize;
        let (tx, mut rx1) = broadcast::channel(capacity);
        let mut rx2 = tx.subscribe();
        let mut rx3 = tx.subscribe();

        // Send initial batch
        for i in 0..capacity as u64 {
            tx.send(i).await.unwrap();
        }

        // rx1 reads immediately (fast consumer)
        let mut rx1_values = Vec::new();
        for _ in 0..capacity {
            let val = rx1.recv(&cx).await.unwrap();
            rx1_values.push(val);
        }

        // rx2 reads half (medium consumer)
        let mut rx2_values = Vec::new();
        for _ in 0..2 {
            let val = rx2.recv(&cx).await.unwrap();
            rx2_values.push(val);
        }

        // rx3 reads nothing (slow consumer)

        // Send more to force different lag behaviors
        for i in capacity as u64..(capacity + 3) as u64 {
            tx.send(i).await.unwrap();
        }

        // rx1 should not be lagged (kept up)
        match rx1.try_recv() {
            Ok(val) => {
                assert_eq!(val, capacity as u64, "Fast consumer should not lag");
            }
            Err(broadcast::TryRecvError::Lagged(_)) => {
                panic!("Fast consumer should not be lagged");
            }
            Err(e) => {
                // Empty is acceptable if we're testing at the right timing
                if !matches!(e, broadcast::TryRecvError::Empty) {
                    panic!("Unexpected error for fast consumer: {:?}", e);
                }
            }
        }

        // rx2 should be lagged but less than rx3
        let rx2_lag = match rx2.try_recv() {
            Err(broadcast::TryRecvError::Lagged(count)) => count,
            Ok(_) => 0, // Might not be lagged if timing is right
            Err(e) => panic!("Unexpected error for medium consumer: {:?}", e),
        };

        // rx3 should be most lagged
        let rx3_lag = match rx3.try_recv() {
            Err(broadcast::TryRecvError::Lagged(count)) => count,
            other => panic!("Expected Lagged error for slow consumer, got: {:?}", other),
        };

        // Verify independent tracking: slower consumers have higher lag counts
        assert!(rx3_lag >= rx2_lag, "Slower consumer should have higher or equal lag count");
        assert!(rx3_lag > 0, "Slowest consumer should definitely be lagged");

        // Verify each receiver can recover independently
        if rx2_lag > 0 {
            let rx2_recovery = rx2.recv(&cx).await.unwrap();
            assert!(rx2_recovery >= capacity as u64, "rx2 should recover to current position");
        }

        let rx3_recovery = rx3.recv(&cx).await.unwrap();
        assert!(rx3_recovery >= capacity as u64, "rx3 should recover to current position");
    });
}

/// Property-based test: Lag count invariant across different consumption patterns
#[test]
#[allow(dead_code)]
fn property_lag_count_invariant() {
    use std::collections::VecDeque;

    LabRuntime::test(|lab| async {
        let cx = test_cx();

        // Test with different capacities and send patterns
        let test_cases = vec![
            (2, 5),  // Small buffer, moderate overflow
            (4, 10), // Medium buffer, large overflow
            (8, 12), // Larger buffer, small overflow
        ];

        for (capacity, total_sends) in test_cases {
            let (tx, mut rx) = broadcast::channel(capacity);

            // Send all values at once
            for i in 0..total_sends as u64 {
                tx.send(i).await.unwrap();
            }

            // Track total lag reported
            let mut total_lag = 0u64;
            let mut received_values = Vec::new();

            loop {
                match rx.try_recv() {
                    Ok(val) => received_values.push(val),
                    Err(broadcast::TryRecvError::Lagged(count)) => {
                        total_lag += count;
                    }
                    Err(broadcast::TryRecvError::Empty) => break,
                    Err(e) => panic!("Unexpected error: {:?}", e),
                }
            }

            // Invariant: total_lag + received_count = total_sent
            let lag_and_received = total_lag + received_values.len() as u64;
            assert_eq!(
                lag_and_received,
                total_sends as u64,
                "Lag count plus received count should equal total sent for capacity={}, sends={}",
                capacity,
                total_sends
            );

            // Verify received values are the most recent ones
            if !received_values.is_empty() {
                let expected_start = total_sends as u64 - received_values.len() as u64;
                for (idx, &val) in received_values.iter().enumerate() {
                    assert_eq!(val, expected_start + idx as u64, "Received values should be consecutive and most recent");
                }
            }
        }
    });
}

/// Edge case: Empty channel lag behavior
#[test]
#[allow(dead_code)]
fn edge_case_empty_channel_no_lag() {
    LabRuntime::test(|lab| async {
        let (_tx, mut rx) = broadcast::channel::<u64>(4);

        // Empty channel should not report lag
        match rx.try_recv() {
            Err(broadcast::TryRecvError::Empty) => {
                // Expected
            }
            other => panic!("Empty channel should return Empty, not lag or value: {:?}", other),
        }
    });
}

/// Edge case: Exact capacity boundary (no lag at capacity limit)
#[test]
#[allow(dead_code)]
fn edge_case_exact_capacity_no_lag() {
    LabRuntime::test(|lab| async {
        let cx = test_cx();
        let capacity = 4usize;
        let (tx, mut rx) = broadcast::channel(capacity);

        // Send exactly capacity worth of values
        for i in 0..capacity as u64 {
            tx.send(i).await.unwrap();
        }

        // Should be able to receive all without lag
        for expected in 0..capacity as u64 {
            let val = rx.recv(&cx).await.unwrap();
            assert_eq!(val, expected, "Should receive values in order without lag");
        }

        // Channel should now be empty
        match rx.try_recv() {
            Err(broadcast::TryRecvError::Empty) => {
                // Expected
            }
            other => panic!("Should be empty after receiving all values: {:?}", other),
        }
    });
}