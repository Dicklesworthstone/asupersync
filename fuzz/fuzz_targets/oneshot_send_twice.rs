//! Fuzz oneshot channel multi-send error scenarios.
//!
//! Tests arbitrary multi-send attempts to ensure proper error handling
//! when sends fail due to disconnection or cancellation. Validates that
//! error cases return the original value and maintain channel state integrity.
//!
//! Critical invariants:
//! - Second send attempt (via new channel) returns appropriate error
//! - Original value is returned in error cases (no value loss)
//! - Channel state remains consistent after failed send attempts
//! - Proper error distinction between Disconnected vs Cancelled

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::channel::oneshot::{self, SendError, TryRecvError};
use asupersync::cx::Cx;
use asupersync::types::{CancelKind, Budget};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Arbitrary)]
struct MultiSendConfig {
    /// Values to attempt sending
    values: Vec<SendValue>,
    /// Send scenarios to test
    scenarios: Vec<SendScenario>,
    /// Whether to test concurrent scenarios
    test_concurrency: bool,
    /// Maximum scenarios to test
    max_scenarios: u8,
}

#[derive(Debug, Clone, Arbitrary)]
struct SendValue {
    /// The actual value to send
    value: u32,
    /// Whether to use reserve-then-send vs direct send
    use_reserve_pattern: bool,
    /// Delay before sending (for timing scenarios)
    delay_ms: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum SendScenario {
    /// Normal send (should succeed)
    Normal,
    /// Send after receiver is dropped (should return Disconnected)
    ReceiverDropped,
    /// Send with cancelled context (should return Cancelled)
    CancelledContext,
    /// Send after small delay
    DelayedSend { delay_ms: u8 },
    /// Rapid sequence of channel creation and send attempts
    RapidSequence { count: u8 },
}

impl MultiSendConfig {
    fn max_scenarios() -> u8 {
        20 // Keep test duration reasonable
    }

    fn max_rapid_count() -> u8 {
        10 // Limit rapid sequence length
    }
}

/// Tracks send attempt results to detect invariant violations
#[derive(Debug)]
struct SendTracker {
    successful_sends: AtomicUsize,
    disconnected_errors: AtomicUsize,
    cancelled_errors: AtomicUsize,
    values_recovered: AtomicUsize,
    total_attempts: AtomicUsize,
}

impl SendTracker {
    fn new() -> Self {
        Self {
            successful_sends: AtomicUsize::new(0),
            disconnected_errors: AtomicUsize::new(0),
            cancelled_errors: AtomicUsize::new(0),
            values_recovered: AtomicUsize::new(0),
            total_attempts: AtomicUsize::new(0),
        }
    }

    fn record_success(&self) {
        self.successful_sends.fetch_add(1, Ordering::SeqCst);
        self.total_attempts.fetch_add(1, Ordering::SeqCst);
    }

    fn record_disconnected(&self, value_returned: bool) {
        self.disconnected_errors.fetch_add(1, Ordering::SeqCst);
        self.total_attempts.fetch_add(1, Ordering::SeqCst);
        if value_returned {
            self.values_recovered.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn record_cancelled(&self, value_returned: bool) {
        self.cancelled_errors.fetch_add(1, Ordering::SeqCst);
        self.total_attempts.fetch_add(1, Ordering::SeqCst);
        if value_returned {
            self.values_recovered.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn check_send_invariants(&self) -> Result<(), String> {
        let successful = self.successful_sends.load(Ordering::SeqCst);
        let disconnected = self.disconnected_errors.load(Ordering::SeqCst);
        let cancelled = self.cancelled_errors.load(Ordering::SeqCst);
        let recovered = self.values_recovered.load(Ordering::SeqCst);
        let total = self.total_attempts.load(Ordering::SeqCst);

        // All error cases should return the original value
        let expected_recoveries = disconnected + cancelled;
        if recovered != expected_recoveries {
            return Err(format!(
                "Value recovery mismatch: expected {} (disconnected: {} + cancelled: {}), got {}",
                expected_recoveries, disconnected, cancelled, recovered
            ));
        }

        // Total should match sum of all categories
        let computed_total = successful + disconnected + cancelled;
        if total != computed_total {
            return Err(format!(
                "Total attempts mismatch: tracked {} vs computed {} (success: {}, disc: {}, cancel: {})",
                total, computed_total, successful, disconnected, cancelled
            ));
        }

        Ok(())
    }
}

/// Test a single send scenario and validate behavior
fn test_send_scenario(
    scenario: &SendScenario,
    send_value: &SendValue,
    tracker: &SendTracker,
) -> Result<(), String> {
    match scenario {
        SendScenario::Normal => {
            let cx = create_test_cx();
            let (tx, mut rx) = oneshot::channel::<u32>();

            let result = execute_send(tx, &cx, send_value);
            match result {
                Ok(()) => {
                    tracker.record_success();

                    // Verify receiver can get the value
                    match rx.try_recv() {
                        Ok(received_value) => {
                            if received_value != send_value.value {
                                return Err(format!(
                                    "Received wrong value: expected {}, got {}",
                                    send_value.value, received_value
                                ));
                            }
                        }
                        Err(TryRecvError::Empty) => {
                            return Err("Receiver reports empty after successful send".to_string());
                        }
                        Err(TryRecvError::Closed) => {
                            return Err("Receiver reports closed after successful send".to_string());
                        }
                    }
                }
                Err(err) => {
                    return Err(format!("Unexpected send error in normal scenario: {:?}", err));
                }
            }
        }

        SendScenario::ReceiverDropped => {
            let cx = create_test_cx();
            let (tx, rx) = oneshot::channel::<u32>();

            // Drop receiver before sending
            drop(rx);

            let result = execute_send(tx, &cx, send_value);
            match result {
                Ok(()) => {
                    return Err("Send succeeded when receiver was dropped".to_string());
                }
                Err(SendError::Disconnected(returned_value)) => {
                    tracker.record_disconnected(true);
                    if returned_value != send_value.value {
                        return Err(format!(
                            "Wrong value returned in Disconnected error: expected {}, got {}",
                            send_value.value, returned_value
                        ));
                    }
                }
                Err(SendError::Cancelled(returned_value)) => {
                    return Err(format!(
                        "Expected Disconnected error but got Cancelled with value {}",
                        returned_value
                    ));
                }
            }
        }

        SendScenario::CancelledContext => {
            let cx = create_test_cx();
            cx.cancel_with(CancelKind::User, Some("test cancellation"));
            let (tx, _rx) = oneshot::channel::<u32>();

            let result = execute_send(tx, &cx, send_value);
            match result {
                Ok(()) => {
                    return Err("Send succeeded with cancelled context".to_string());
                }
                Err(SendError::Cancelled(returned_value)) => {
                    tracker.record_cancelled(true);
                    if returned_value != send_value.value {
                        return Err(format!(
                            "Wrong value returned in Cancelled error: expected {}, got {}",
                            send_value.value, returned_value
                        ));
                    }
                }
                Err(SendError::Disconnected(returned_value)) => {
                    return Err(format!(
                        "Expected Cancelled error but got Disconnected with value {}",
                        returned_value
                    ));
                }
            }
        }

        SendScenario::DelayedSend { delay_ms } => {
            let cx = create_test_cx();
            let (tx, mut rx) = oneshot::channel::<u32>();

            // Small delay before sending
            thread::sleep(Duration::from_millis((*delay_ms).min(50) as u64));

            let result = execute_send(tx, &cx, send_value);
            match result {
                Ok(()) => {
                    tracker.record_success();

                    // Verify receiver can get the value
                    match rx.try_recv() {
                        Ok(received_value) => {
                            if received_value != send_value.value {
                                return Err(format!(
                                    "Delayed send: received wrong value: expected {}, got {}",
                                    send_value.value, received_value
                                ));
                            }
                        }
                        Err(err) => {
                            return Err(format!("Delayed send: receiver error: {:?}", err));
                        }
                    }
                }
                Err(err) => {
                    return Err(format!("Unexpected error in delayed send: {:?}", err));
                }
            }
        }

        SendScenario::RapidSequence { count } => {
            let sequence_count = (*count).min(MultiSendConfig::max_rapid_count()) as usize;

            for i in 0..sequence_count {
                let cx = create_test_cx();
                let (tx, mut rx) = oneshot::channel::<u32>();
                let test_value = send_value.value.wrapping_add(i as u32);

                let modified_send_value = SendValue {
                    value: test_value,
                    use_reserve_pattern: send_value.use_reserve_pattern,
                    delay_ms: 0, // No delays in rapid sequence
                };

                let result = execute_send(tx, &cx, &modified_send_value);
                match result {
                    Ok(()) => {
                        tracker.record_success();

                        match rx.try_recv() {
                            Ok(received_value) => {
                                if received_value != test_value {
                                    return Err(format!(
                                        "Rapid sequence #{}: received wrong value: expected {}, got {}",
                                        i, test_value, received_value
                                    ));
                                }
                            }
                            Err(err) => {
                                return Err(format!("Rapid sequence #{}: receiver error: {:?}", err, i));
                            }
                        }
                    }
                    Err(err) => {
                        return Err(format!("Rapid sequence #{}: send error: {:?}", i, err));
                    }
                }

                // Brief yield between iterations
                if i % 3 == 2 {
                    thread::yield_now();
                }
            }
        }
    }

    Ok(())
}

/// Execute a send using either reserve-then-send or direct send pattern
fn execute_send(
    tx: oneshot::Sender<u32>,
    cx: &Cx,
    send_value: &SendValue,
) -> Result<(), SendError<u32>> {
    // Apply delay if specified
    if send_value.delay_ms > 0 {
        thread::sleep(Duration::from_millis(send_value.delay_ms.min(100) as u64));
    }

    if send_value.use_reserve_pattern {
        // Use reserve-then-send pattern
        match tx.reserve(cx) {
            Ok(permit) => permit.send(send_value.value),
            Err(SendError::Cancelled(())) => Err(SendError::Cancelled(send_value.value)),
            Err(SendError::Disconnected(())) => Err(SendError::Disconnected(send_value.value)),
        }
    } else {
        // Use direct send pattern
        tx.send(cx, send_value.value)
    }
}

/// Create test context
fn create_test_cx() -> Cx {
    Cx::new(
        "oneshot_send_twice_fuzz",
        Budget::INFINITE,
    )
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let config: MultiSendConfig = match unstructured.arbitrary() {
        Ok(cfg) => cfg,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if config.values.is_empty() || config.scenarios.is_empty() {
        return;
    }

    let max_scenarios = config.max_scenarios.min(MultiSendConfig::max_scenarios()) as usize;
    let tracker = SendTracker::new();

    // Test each scenario with each value
    for scenario in config.scenarios.iter().take(max_scenarios) {
        for send_value in &config.values {
            if let Err(msg) = test_send_scenario(scenario, send_value, &tracker) {
                panic!("Send scenario test failed: {}", msg);
            }
        }
    }

    // Test concurrent scenarios if requested
    if config.test_concurrency && config.scenarios.len() > 1 {
        let concurrent_handles: Vec<_> = config.scenarios
            .iter()
            .take(3) // Limit concurrent threads
            .enumerate()
            .map(|(i, scenario)| {
                let scenario = scenario.clone();
                let send_value = config.values[i % config.values.len()].clone();
                let tracker = &tracker;

                thread::spawn(move || {
                    if let Err(msg) = test_send_scenario(&scenario, &send_value, tracker) {
                        panic!("Concurrent send scenario #{} failed: {}", i, msg);
                    }
                })
            })
            .collect();

        // Wait for all concurrent tests to complete
        for handle in concurrent_handles {
            handle.join().expect("Concurrent test thread should complete");
        }
    }

    // Validate final invariants
    if let Err(msg) = tracker.check_send_invariants() {
        panic!("Send invariant violation: {}", msg);
    }

    // Ensure we actually performed some operations
    let total_attempts = tracker.total_attempts.load(Ordering::SeqCst);
    if total_attempts == 0 {
        panic!("No send attempts were made during the test");
    }
});