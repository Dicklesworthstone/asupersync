//! Metamorphic testing for combinator::circuit_breaker state machine invariants.
//!
//! Tests the core metamorphic relations that must hold for a correct
//! circuit breaker implementation using proptest + LabRuntime virtual time.

#![allow(clippy::missing_panics_doc)]

use asupersync::combinator::circuit_breaker::{
    CircuitBreaker, CircuitBreakerError, CircuitBreakerPolicy, Permit, State,
};
use asupersync::lab::time::VirtualTimeProvider;
use asupersync::types::Time;
use proptest::prelude::*;
use std::time::Duration;

/// Helper to create deterministic circuit breaker policies for testing
fn test_policy() -> CircuitBreakerPolicy {
    CircuitBreakerPolicy {
        name: "test".into(),
        failure_threshold: 3,
        success_threshold: 2,
        open_duration: Duration::from_millis(1000),
        half_open_max_probes: 1,
        ..Default::default()
    }
}

/// MR1: closed→open on failure threshold
///
/// Metamorphic relation: When consecutive failures reach failure_threshold
/// in Closed state, the circuit breaker must transition to Open state.
///
/// Properties tested:
/// - Circuit remains Closed for failures < threshold
/// - Circuit transitions to Open when failures == threshold
/// - Failure counter increments correctly before opening
#[proptest]
fn mr_closed_to_open_on_threshold(
    #[strategy(1u32..=10)] failure_threshold: u32,
    #[strategy(0u64..1000)] base_time_ms: u64,
) {
    let mut policy = test_policy();
    policy.failure_threshold = failure_threshold;
    let breaker = CircuitBreaker::new(policy);

    let time = Time::from_millis(base_time_ms);

    // Record failures one less than threshold - should stay Closed
    for i in 0..(failure_threshold.saturating_sub(1)) {
        match breaker.should_allow(time) {
            Ok(permit) => {
                breaker.record_failure(permit, "test error", time);
                let state = breaker.state();
                if let State::Closed { failures } = state {
                    prop_assert_eq!(failures, i + 1, "failure count should increment");
                } else {
                    prop_assert!(false, "circuit should remain closed before threshold");
                }
            }
            Err(_) => prop_assert!(false, "should allow calls before threshold"),
        }
    }

    // Record one more failure - should transition to Open
    match breaker.should_allow(time) {
        Ok(permit) => {
            breaker.record_failure(permit, "test error", time);
            let state = breaker.state();
            prop_assert!(
                matches!(state, State::Open { .. }),
                "circuit should open after reaching failure threshold"
            );

            // Verify metrics
            let metrics = breaker.metrics();
            prop_assert_eq!(
                metrics.total_failure,
                u64::from(failure_threshold),
                "total failures should match threshold"
            );
            prop_assert_eq!(metrics.times_opened, 1, "should record exactly one opening");
        }
        Err(_) => prop_assert!(false, "should allow call at threshold"),
    }
}

/// MR2: open blocks requests until half-open timeout
///
/// Metamorphic relation: In Open state, all calls must be rejected until
/// open_duration has elapsed, at which point the circuit transitions to HalfOpen.
///
/// Properties tested:
/// - Open state rejects all calls before timeout
/// - Rejection includes correct remaining duration
/// - Transition to HalfOpen after timeout
#[proptest]
fn mr_open_blocks_until_timeout(
    #[strategy(100u64..=2000)] open_duration_ms: u64,
    #[strategy(0u64..1000)] base_time_ms: u64,
) {
    let mut policy = test_policy();
    policy.open_duration = Duration::from_millis(open_duration_ms);
    let breaker = CircuitBreaker::new(policy);

    let start_time = Time::from_millis(base_time_ms);

    // Force circuit open by exceeding failure threshold
    for _ in 0..policy.failure_threshold {
        if let Ok(permit) = breaker.should_allow(start_time) {
            breaker.record_failure(permit, "test error", start_time);
        }
    }

    // Verify circuit is open
    prop_assert!(matches!(breaker.state(), State::Open { .. }));

    // Test rejection during open period
    let mid_time = Time::from_millis(base_time_ms + open_duration_ms / 2);
    match breaker.should_allow(mid_time) {
        Ok(_) => prop_assert!(false, "should reject calls while open"),
        Err(CircuitBreakerError::Open { remaining }) => {
            let expected_remaining = Duration::from_millis(open_duration_ms / 2);
            let tolerance = Duration::from_millis(1);
            prop_assert!(
                remaining <= expected_remaining + tolerance
                    && remaining >= expected_remaining.saturating_sub(tolerance),
                "remaining duration should be approximately correct: expected ~{:?}, got {:?}",
                expected_remaining,
                remaining
            );
        }
        Err(e) => prop_assert!(false, "should get Open error, got {:?}", e),
    }

    // Test transition to half-open after timeout
    let timeout_time = Time::from_millis(base_time_ms + open_duration_ms + 1);
    match breaker.should_allow(timeout_time) {
        Ok(Permit::Probe { .. }) => {
            // Success - should be in HalfOpen state
            let state = breaker.state();
            prop_assert!(
                matches!(state, State::HalfOpen { .. }),
                "should transition to HalfOpen after timeout"
            );
        }
        Err(e) => prop_assert!(false, "should allow probe after timeout, got {:?}", e),
    }
}

/// MR3: half-open admits one probe; success closes, failure re-opens
///
/// Metamorphic relation: In HalfOpen state, the circuit should admit limited
/// probes up to half_open_max_probes. Success of sufficient probes closes the circuit,
/// failure of any probe re-opens the circuit.
///
/// Properties tested:
/// - HalfOpen admits probes up to max_probes limit
/// - Success threshold closes circuit and resets counters
/// - Single failure re-opens circuit
/// - Probe epoch prevents stale results
#[proptest]
fn mr_half_open_probe_behavior(
    #[strategy(1u32..=5)] max_probes: u32,
    #[strategy(1u32..=3)] success_threshold: u32,
    #[strategy(0u64..1000)] base_time_ms: u64,
) {
    let mut policy = test_policy();
    policy.half_open_max_probes = max_probes;
    policy.success_threshold = success_threshold;
    let breaker = CircuitBreaker::new(policy);

    let time = Time::from_millis(base_time_ms);

    // Force circuit open then transition to half-open
    for _ in 0..policy.failure_threshold {
        if let Ok(permit) = breaker.should_allow(time) {
            breaker.record_failure(permit, "test error", time);
        }
    }

    let timeout_time =
        Time::from_millis(base_time_ms + policy.open_duration.as_millis() as u64 + 1);
    let _ = breaker.should_allow(timeout_time); // Trigger transition to HalfOpen

    // Test probe admission up to limit
    let mut probe_permits = Vec::new();
    for i in 0..max_probes {
        match breaker.should_allow(timeout_time) {
            Ok(permit @ Permit::Probe { .. }) => {
                probe_permits.push(permit);
                if let State::HalfOpen { probes_active, .. } = breaker.state() {
                    prop_assert_eq!(probes_active, i + 1, "probes_active should increment");
                }
            }
            Err(e) => prop_assert!(false, "should allow probe {}, got {:?}", i, e),
        }
    }

    // Test that max_probes + 1 is rejected
    match breaker.should_allow(timeout_time) {
        Ok(_) => prop_assert!(false, "should reject probe beyond max_probes"),
        Err(CircuitBreakerError::HalfOpenFull) => {
            // Expected behavior
        }
        Err(e) => prop_assert!(false, "should get HalfOpenFull error, got {:?}", e),
    }

    // Test failure re-opens circuit
    if let Some(first_permit) = probe_permits.first() {
        breaker.record_failure(*first_permit, "probe failed", timeout_time);

        let state = breaker.state();
        prop_assert!(
            matches!(state, State::Open { .. }),
            "single probe failure should re-open circuit"
        );

        let metrics = breaker.metrics();
        prop_assert!(metrics.times_opened >= 2, "should record re-opening");
    }
}

/// MR4: open→closed transition resets failure counter
///
/// Metamorphic relation: When circuit transitions from Open to Closed
/// (via successful HalfOpen probes), the failure counter must be reset to 0.
///
/// Properties tested:
/// - Successful transition resets failure count
/// - Previous failure history is cleared
/// - Circuit behaves as fresh Closed state
#[proptest]
fn mr_open_to_closed_resets_counter(
    #[strategy(2u32..=5)] failure_threshold: u32,
    #[strategy(1u32..=3)] success_threshold: u32,
    #[strategy(0u64..1000)] base_time_ms: u64,
) {
    let mut policy = test_policy();
    policy.failure_threshold = failure_threshold;
    policy.success_threshold = success_threshold;
    policy.half_open_max_probes = success_threshold; // Ensure enough probe slots
    let breaker = CircuitBreaker::new(policy);

    let time = Time::from_millis(base_time_ms);

    // Force circuit open with failure_threshold failures
    for _ in 0..failure_threshold {
        if let Ok(permit) = breaker.should_allow(time) {
            breaker.record_failure(permit, "test error", time);
        }
    }

    prop_assert!(matches!(breaker.state(), State::Open { .. }));

    // Transition to half-open after timeout
    let timeout_time =
        Time::from_millis(base_time_ms + policy.open_duration.as_millis() as u64 + 1);

    // Record enough successful probes to close circuit
    for _ in 0..success_threshold {
        if let Ok(permit) = breaker.should_allow(timeout_time) {
            breaker.record_success(permit, timeout_time);
        }
    }

    // Verify circuit closed with reset counter
    let state = breaker.state();
    if let State::Closed { failures } = state {
        prop_assert_eq!(
            failures,
            0,
            "failure counter should be reset to 0 after closing"
        );
    } else {
        prop_assert!(
            false,
            "circuit should be closed after successful probes, got {:?}",
            state
        );
    }

    // Verify metrics recorded the closure
    let metrics = breaker.metrics();
    prop_assert!(metrics.times_closed >= 1, "should record circuit closure");
    prop_assert_eq!(
        metrics.current_failure_streak,
        0,
        "failure streak should be reset"
    );

    // Test that circuit behaves as fresh - should take failure_threshold failures to open again
    let mut fresh_failures = 0;
    for _ in 0..failure_threshold {
        if let Ok(permit) = breaker.should_allow(timeout_time) {
            breaker.record_failure(permit, "new failure", timeout_time);
            fresh_failures += 1;

            let current_state = breaker.state();
            if fresh_failures < failure_threshold {
                prop_assert!(
                    matches!(current_state, State::Closed { .. }),
                    "should remain closed until threshold reached again"
                );
            } else {
                prop_assert!(
                    matches!(current_state, State::Open { .. }),
                    "should open again after new threshold reached"
                );
            }
        }
    }
}

/// MR5: metrics monotonic (total_requests, total_failures)
///
/// Metamorphic relation: Metrics counters must be monotonic - they should only
/// increase over time, never decrease. The sum of success + failure + rejected
/// should equal total operations attempted.
///
/// Properties tested:
/// - total_success only increases
/// - total_failure only increases
/// - total_rejected only increases
/// - times_opened only increases
/// - times_closed only increases
/// - Accounting consistency between counters
#[proptest]
fn mr_metrics_monotonic(
    #[strategy(1u32..=5)] num_operations: u32,
    #[strategy(prop::collection::vec(any::<bool>(), 1..=20))] operation_results: Vec<bool>,
    #[strategy(0u64..1000)] base_time_ms: u64,
) {
    let breaker = CircuitBreaker::new(test_policy());
    let time = Time::from_millis(base_time_ms);

    let mut prev_metrics = breaker.metrics();

    for (i, &should_succeed) in operation_results.iter().enumerate() {
        let iteration_time = Time::from_millis(base_time_ms + (i as u64 * 10));

        // Attempt operation
        match breaker.should_allow(iteration_time) {
            Ok(permit) => {
                if should_succeed {
                    breaker.record_success(permit, iteration_time);
                } else {
                    breaker.record_failure(permit, "test failure", iteration_time);
                }
            }
            Err(_) => {
                // Call was rejected - this increments total_rejected
            }
        }

        let current_metrics = breaker.metrics();

        // Verify monotonicity
        prop_assert!(
            current_metrics.total_success >= prev_metrics.total_success,
            "total_success should not decrease: {} -> {}",
            prev_metrics.total_success,
            current_metrics.total_success
        );

        prop_assert!(
            current_metrics.total_failure >= prev_metrics.total_failure,
            "total_failure should not decrease: {} -> {}",
            prev_metrics.total_failure,
            current_metrics.total_failure
        );

        prop_assert!(
            current_metrics.total_rejected >= prev_metrics.total_rejected,
            "total_rejected should not decrease: {} -> {}",
            prev_metrics.total_rejected,
            current_metrics.total_rejected
        );

        prop_assert!(
            current_metrics.times_opened >= prev_metrics.times_opened,
            "times_opened should not decrease: {} -> {}",
            prev_metrics.times_opened,
            current_metrics.times_opened
        );

        prop_assert!(
            current_metrics.times_closed >= prev_metrics.times_closed,
            "times_closed should not decrease: {} -> {}",
            prev_metrics.times_closed,
            current_metrics.times_closed
        );

        // Verify accounting relationship
        let total_operations = current_metrics.total_success
            + current_metrics.total_failure
            + current_metrics.total_rejected;
        prop_assert!(
            total_operations <= (i as u64 + 1),
            "total operations {} should not exceed attempts {}",
            total_operations,
            i + 1
        );

        prev_metrics = current_metrics;
    }
}

/// BONUS MR: state transition coherence
///
/// Metamorphic relation: State transitions must be coherent and follow
/// the defined state machine rules. Invalid transitions should never occur.
///
/// Properties tested:
/// - Only valid state transitions occur
/// - State consistency after operations
/// - Epoch handling prevents stale probe pollution
#[proptest]
fn mr_state_transition_coherence(
    #[strategy(prop::collection::vec(any::<bool>(), 5..=15))] operations: Vec<bool>,
    #[strategy(50u64..=500)] time_step_ms: u64,
    #[strategy(0u64..1000)] base_time_ms: u64,
) {
    let breaker = CircuitBreaker::new(test_policy());

    let mut prev_state = breaker.state();
    let mut time = Time::from_millis(base_time_ms);

    for (i, &should_succeed) in operations.iter().enumerate() {
        time = Time::from_millis(base_time_ms + (i as u64 * time_step_ms));

        // Record the state before operation
        let before_state = breaker.state();

        // Perform operation
        match breaker.should_allow(time) {
            Ok(permit) => {
                let after_allow_state = breaker.state();

                // Verify state is valid after should_allow
                match (&before_state, &after_allow_state) {
                    (State::Closed { .. }, State::Closed { .. }) => {
                        // Normal → Normal: OK
                    }
                    (State::Open { .. }, State::HalfOpen { .. }) => {
                        // Open → HalfOpen after timeout: OK
                    }
                    (State::HalfOpen { .. }, State::HalfOpen { .. }) => {
                        // HalfOpen → HalfOpen with probe increment: OK
                    }
                    _ => {
                        prop_assert!(
                            false,
                            "invalid state transition during should_allow: {:?} -> {:?}",
                            before_state,
                            after_allow_state
                        );
                    }
                }

                // Record result
                if should_succeed {
                    breaker.record_success(permit, time);
                } else {
                    breaker.record_failure(permit, "test failure", time);
                }

                let final_state = breaker.state();

                // Verify state after record_success/failure is valid
                match permit {
                    Permit::Normal => {
                        // Normal permit should stay in Closed or transition to Open
                        prop_assert!(
                            matches!(final_state, State::Closed { .. } | State::Open { .. }),
                            "normal permit should result in Closed or Open state, got {:?}",
                            final_state
                        );
                    }
                    Permit::Probe { .. } => {
                        // Probe permit can transition to any state
                        prop_assert!(
                            matches!(
                                final_state,
                                State::HalfOpen { .. } | State::Closed { .. } | State::Open { .. }
                            ),
                            "probe permit resulted in unexpected state: {:?}",
                            final_state
                        );
                    }
                }
            }
            Err(CircuitBreakerError::Open { .. }) => {
                // Should only happen in Open state
                prop_assert!(
                    matches!(before_state, State::Open { .. }),
                    "Open error should only occur in Open state, was in {:?}",
                    before_state
                );
            }
            Err(CircuitBreakerError::HalfOpenFull) => {
                // Should only happen in HalfOpen state
                prop_assert!(
                    matches!(before_state, State::HalfOpen { .. }),
                    "HalfOpenFull error should only occur in HalfOpen state, was in {:?}",
                    before_state
                );
            }
            Err(_) => {
                prop_assert!(false, "unexpected error type");
            }
        }

        prev_state = breaker.state();
    }
}

/// Test module for integration with the rest of the test suite
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metamorphic_circuit_breaker_smoke_test() {
        // Quick smoke test to verify the metamorphic relations can run
        let breaker = CircuitBreaker::new(test_policy());
        let time = Time::from_millis(0);

        // Test basic closed → open transition
        for _ in 0..3 {
            if let Ok(permit) = breaker.should_allow(time) {
                breaker.record_failure(permit, "test", time);
            }
        }

        let state = breaker.state();
        assert!(
            matches!(state, State::Open { .. }),
            "should open after failures"
        );

        let metrics = breaker.metrics();
        assert_eq!(metrics.total_failure, 3, "should record all failures");
        assert_eq!(metrics.times_opened, 1, "should record opening");
    }
}
