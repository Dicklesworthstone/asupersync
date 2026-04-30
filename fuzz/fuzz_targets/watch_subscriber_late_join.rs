//! Fuzz watch channel subscriber-late-join semantics.
//!
//! Tests arbitrary update sequence with a subscriber added at a random point
//! to ensure the late subscriber sees the latest value (not historical values).
//! Validates that new subscribers always observe the current state.
//!
//! Critical invariants:
//! - Late subscriber sees latest value via borrow() immediately
//! - Late subscriber does not see historical values
//! - Late subscriber starts with seen_version = current_version
//! - Subsequent changes are properly detected by the late subscriber

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::channel::watch;
use std::sync::{Arc, Barrier};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Arbitrary)]
struct WatchConfig {
    /// Update values to send (1-50)
    update_values: Vec<u32>,
    /// Point at which to add late subscriber (index into update_values)
    late_join_point: u8,
    /// Delay patterns for updates (microseconds)
    update_delays: Vec<u16>,
    /// Values to send after late subscriber joins
    post_join_updates: Vec<u32>,
}

#[derive(Debug, Clone, Arbitrary)]
struct WatchSequence {
    /// Test configuration
    config: WatchConfig,
    /// Whether to test multiple late subscribers
    multiple_late_subscribers: bool,
    /// Whether to test borrow vs borrow_and_update behavior
    test_update_tracking: bool,
}

impl WatchSequence {
    fn max_updates() -> usize {
        50 // Keep test duration reasonable
    }

    fn max_post_join() -> usize {
        20 // Additional updates after late join
    }
}

/// Result tracking for test execution
#[derive(Debug, Clone)]
struct LateJoinResult {
    /// Value the late subscriber saw immediately after joining
    initial_value_seen: u32,
    /// Expected value (should be latest at join time)
    expected_latest_value: u32,
    /// Sequence of all update values sent before late join
    historical_values: Vec<u32>,
    /// Whether the seen value matches expected latest
    correct_latest_value: bool,
    /// Whether the seen value is not a historical value
    not_historical_value: bool,
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let sequence: WatchSequence = match unstructured.arbitrary() {
        Ok(seq) => seq,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if sequence.config.update_values.is_empty()
        || sequence.config.update_values.len() > WatchSequence::max_updates()
        || sequence.config.post_join_updates.len() > WatchSequence::max_post_join() {
        return;
    }

    let update_count = sequence.config.update_values.len();
    let late_join_point = (sequence.config.late_join_point as usize).min(update_count.saturating_sub(1));

    // Create watch channel with initial value
    let initial_value = 0u32;
    let (sender, _initial_receiver) = watch::channel(initial_value);

    // Track the test state
    let historical_values = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let latest_value_at_join = Arc::new(AtomicUsize::new(0));
    let late_join_barrier = Arc::new(Barrier::new(2)); // Main thread + late subscriber thread

    // Start the update sequence in the main thread
    let sender_clone = sender.clone();
    let historical_values_clone = Arc::clone(&historical_values);
    let latest_value_clone = Arc::clone(&latest_value_at_join);
    let barrier_clone = Arc::clone(&late_join_barrier);

    let update_handle = thread::spawn(move || {
        let mut all_sent_values = vec![initial_value];

        // Send updates before late join point
        for (i, &value) in sequence.config.update_values.iter().enumerate() {
            // Apply delay if specified
            if let Some(&delay) = sequence.config.update_delays.get(i) {
                if delay > 0 {
                    thread::sleep(Duration::from_micros(delay as u64));
                }
            }

            // Send the update
            if sender_clone.send(value).is_ok() {
                all_sent_values.push(value);
                historical_values_clone.lock().push(value);
            }

            // Signal late subscriber to join at the specified point
            if i == late_join_point {
                latest_value_clone.store(value as usize, Ordering::SeqCst);
                barrier_clone.wait(); // Signal late subscriber can now join
            }
        }

        // Send post-join updates to test change detection
        for &value in &sequence.config.post_join_updates {
            thread::sleep(Duration::from_millis(5)); // Small delay
            let _ = sender_clone.send(value);
        }

        all_sent_values
    });

    // Wait for the signal to create late subscriber
    late_join_barrier.wait();

    // Create late subscriber at the specified point
    let late_subscriber = sender.subscribe();

    // Immediately check what value the late subscriber sees
    let initial_value_seen = late_subscriber.borrow_and_clone();
    let expected_latest = latest_value_at_join.load(Ordering::SeqCst) as u32;
    let historical_snapshot = historical_values.lock().clone();

    // Validate late subscriber behavior
    let result = LateJoinResult {
        initial_value_seen,
        expected_latest_value: expected_latest,
        historical_values: historical_snapshot.clone(),
        correct_latest_value: initial_value_seen == expected_latest,
        not_historical_value: !historical_snapshot.contains(&initial_value_seen) || initial_value_seen == expected_latest,
    };

    // Core assertions for late subscriber semantics
    assert!(result.correct_latest_value,
        "Late subscriber saw wrong value: expected latest {} but saw {}",
        result.expected_latest_value, result.initial_value_seen);

    assert!(result.not_historical_value,
        "Late subscriber saw historical value: saw {} which is in historical list {:?} but should see latest {}",
        result.initial_value_seen, result.historical_values, result.expected_latest_value);

    // Test change detection for late subscriber
    if sequence.test_update_tracking && !sequence.config.post_join_updates.is_empty() {
        let mut late_subscriber_mut = late_subscriber;

        // The late subscriber should start with seen_version = current_version
        let initial_seen_version = late_subscriber_mut.seen_version();
        assert!(!late_subscriber_mut.has_changed(),
            "Late subscriber should not see changes immediately after join");

        // Wait for post-join updates to complete
        update_handle.join().expect("Update thread should complete");

        // Small delay to ensure updates propagate
        thread::sleep(Duration::from_millis(10));

        // After post-join updates, late subscriber should detect changes
        if !sequence.config.post_join_updates.is_empty() {
            assert!(late_subscriber_mut.has_changed(),
                "Late subscriber should detect changes after post-join updates");

            let updated_value = late_subscriber_mut.borrow_and_clone();
            let expected_final = sequence.config.post_join_updates.last().copied().unwrap();
            assert_eq!(updated_value, expected_final,
                "Late subscriber should see final post-join value {} but saw {}",
                expected_final, updated_value);
        }
    } else {
        // Just wait for updates to complete
        update_handle.join().expect("Update thread should complete");
    }

    // Test multiple late subscribers if requested
    if sequence.multiple_late_subscribers {
        let late_subscriber_2 = sender.subscribe();
        let late_subscriber_3 = sender.subscribe();

        let value_2 = late_subscriber_2.borrow_and_clone();
        let value_3 = late_subscriber_3.borrow_and_clone();

        // All late subscribers should see the same current value
        assert_eq!(value_2, value_3,
            "Multiple late subscribers should see same value: {} vs {}",
            value_2, value_3);

        // Send one more update to test all subscribers see it
        let final_test_value = 99999u32;
        if sender.send(final_test_value).is_ok() {
            thread::sleep(Duration::from_millis(5));

            // All subscribers should see the new value
            let new_value_2 = late_subscriber_2.borrow_and_clone();
            let new_value_3 = late_subscriber_3.borrow_and_clone();

            assert_eq!(new_value_2, final_test_value);
            assert_eq!(new_value_3, final_test_value);
            assert_eq!(new_value_2, new_value_3);
        }
    }

    // Additional invariant: late subscriber should have reasonable seen_version
    let final_seen_version = late_subscriber.seen_version();
    assert!(final_seen_version > 0 || sequence.config.update_values.is_empty(),
        "Late subscriber seen_version should be > 0 for non-empty update sequence, got {}",
        final_seen_version);

    // Verify no value is lost - latest value should always be accessible
    let final_current_value = sender.borrow().clone();
    let receiver_final_value = late_subscriber.borrow_and_clone();
    assert_eq!(final_current_value, receiver_final_value,
        "Sender and receiver should see same final value: {} vs {}",
        final_current_value, receiver_final_value);
});