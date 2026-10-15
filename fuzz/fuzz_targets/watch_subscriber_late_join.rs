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

use arbitrary::{Arbitrary, Unstructured};
use asupersync::channel::watch;
use libfuzzer_sys::fuzz_target;

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

fn observe_update_delay_shape(delays: &[u16]) -> u64 {
    delays
        .iter()
        .take(WatchSequence::max_updates())
        .fold(0u64, |sum, delay| sum.saturating_add(u64::from(*delay)))
}

fn send_watch_update(sender: &watch::Sender<u32>, value: u32, context: &str) {
    match sender.send(value) {
        Ok(()) => {}
        Err(error) => {
            panic!("{context} watch update send failed for value {value}: {error:?}");
        }
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
        || sequence.config.post_join_updates.len() > WatchSequence::max_post_join()
    {
        return;
    }

    let update_count = sequence.config.update_values.len();
    let late_join_point =
        (sequence.config.late_join_point as usize).min(update_count.saturating_sub(1));
    let delay_shape = observe_update_delay_shape(&sequence.config.update_delays);
    let max_delay_shape =
        (0..WatchSequence::max_updates()).fold(0u64, |sum, _| sum + u64::from(u16::MAX));
    assert!(
        delay_shape <= max_delay_shape,
        "watch delay shape exceeded configured bound: {delay_shape} > {max_delay_shape}"
    );

    // Create watch channel with initial value
    let initial_value = 0u32;
    let (sender, _initial_receiver) = watch::channel(initial_value);

    // Replay deterministically: watch::Sender is intentionally single-producer.
    let mut historical_values = Vec::new();
    let mut all_sent_values = vec![initial_value];
    let mut latest_value_at_join = initial_value;

    for (i, &value) in sequence.config.update_values.iter().enumerate() {
        send_watch_update(&sender, value, "Pre-late-join");
        all_sent_values.push(value);
        historical_values.push(value);

        if i == late_join_point {
            latest_value_at_join = value;
            break;
        }
    }

    // Create late subscriber at the specified point
    let mut late_subscriber = sender.subscribe();

    // Immediately check what value the late subscriber sees
    let initial_value_seen = late_subscriber.borrow_and_clone();
    let expected_latest = latest_value_at_join;
    let historical_snapshot = historical_values.clone();

    // Validate late subscriber behavior
    let result = LateJoinResult {
        initial_value_seen,
        expected_latest_value: expected_latest,
        historical_values: historical_snapshot.clone(),
        correct_latest_value: initial_value_seen == expected_latest,
        not_historical_value: !historical_snapshot.contains(&initial_value_seen)
            || initial_value_seen == expected_latest,
    };

    // Core assertions for late subscriber semantics
    assert!(
        result.correct_latest_value,
        "Late subscriber saw wrong value: expected latest {} but saw {}",
        result.expected_latest_value, result.initial_value_seen
    );

    assert!(
        result.not_historical_value,
        "Late subscriber saw historical value: saw {} which is in historical list {:?} but should see latest {}",
        result.initial_value_seen, result.historical_values, result.expected_latest_value
    );

    // The late subscriber should start with seen_version = current_version.
    let initial_seen_version = late_subscriber.seen_version();
    assert!(
        initial_seen_version > 0,
        "Late subscriber seen_version should reflect pre-join sends, got {initial_seen_version}"
    );
    assert!(
        !late_subscriber.has_changed(),
        "Late subscriber should not see changes immediately after join"
    );

    for &value in sequence
        .config
        .update_values
        .iter()
        .skip(late_join_point + 1)
    {
        send_watch_update(&sender, value, "Post-late-join sequence");
        all_sent_values.push(value);
    }

    for &value in &sequence.config.post_join_updates {
        send_watch_update(&sender, value, "Post-join");
        all_sent_values.push(value);
    }

    let Some(final_sent_value) = all_sent_values.last().copied() else {
        panic!("Watch fuzz sequence must retain at least the initial value");
    };
    assert_eq!(
        *sender.borrow(),
        final_sent_value,
        "Watch sender should expose the latest sent value"
    );

    // Test change detection for late subscriber.
    if sequence.test_update_tracking
        && let Some(expected_final) = sequence.config.post_join_updates.last().copied()
    {
        assert!(
            late_subscriber.has_changed(),
            "Late subscriber should detect changes after post-join updates"
        );

        let updated_value = late_subscriber.borrow_and_update_clone();
        assert_eq!(
            updated_value, expected_final,
            "Late subscriber should see final post-join value {} but saw {}",
            expected_final, updated_value
        );
        assert!(
            !late_subscriber.has_changed(),
            "borrow_and_update_clone should acknowledge the final post-join value"
        );
    }

    // Test multiple late subscribers if requested
    if sequence.multiple_late_subscribers {
        let late_subscriber_2 = sender.subscribe();
        let late_subscriber_3 = sender.subscribe();

        let value_2 = late_subscriber_2.borrow_and_clone();
        let value_3 = late_subscriber_3.borrow_and_clone();

        // All late subscribers should see the same current value
        assert_eq!(
            value_2, value_3,
            "Multiple late subscribers should see same value: {} vs {}",
            value_2, value_3
        );

        // Send one more update to test all subscribers see it
        let final_test_value = 99999u32;
        send_watch_update(&sender, final_test_value, "Multiple-late-subscriber");
        all_sent_values.push(final_test_value);

        // All subscribers should see the new value
        let new_value_2 = late_subscriber_2.borrow_and_clone();
        let new_value_3 = late_subscriber_3.borrow_and_clone();

        assert_eq!(new_value_2, final_test_value);
        assert_eq!(new_value_3, final_test_value);
        assert_eq!(new_value_2, new_value_3);
    }

    // Additional invariant: late subscriber should have reasonable seen_version
    let final_seen_version = late_subscriber.seen_version();
    assert!(
        final_seen_version > 0 || sequence.config.update_values.is_empty(),
        "Late subscriber seen_version should be > 0 for non-empty update sequence, got {}",
        final_seen_version
    );

    // Verify no value is lost - latest value should always be accessible
    let final_current_value = *sender.borrow();
    let receiver_final_value = late_subscriber.borrow_and_clone();
    assert_eq!(
        final_current_value, receiver_final_value,
        "Sender and receiver should see same final value: {} vs {}",
        final_current_value, receiver_final_value
    );
});
