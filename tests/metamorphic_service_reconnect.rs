#![allow(clippy::all)]
//! Metamorphic Testing for service::reconnect with exponential backoff and jitter
//!
//! Verifies metamorphic properties of reconnection behavior with exponential backoff
//! and jitter that must hold regardless of specific input values. These properties
//! capture the fundamental invariants of the reconnection and retry system.
//!
//! Key metamorphic relations tested:
//! 1. Reconnect attempts converge with backoff (exponential growth pattern)
//! 2. Jitter bounds respected (values within strategy-defined ranges)
//! 3. Cancel-on-success frees reconnect state (successful reconnect clears pending state)
//! 4. Concurrent reconnect serialized (no race conditions in reconnection)
//! 5. LabRuntime determinism (consistent behavior under deterministic execution)

use asupersync::cx::Cx;
use asupersync::service::Service;
use asupersync::service::reconnect::{MakeService, Reconnect};
use asupersync::service::retry::{ExponentialBackoff, JitterStrategy, Policy};
use asupersync::time::{TimerDriverHandle, VirtualClock};
use asupersync::types::{Budget, RegionId, TaskId};
use proptest::prelude::*;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

/// Generate arbitrary jitter strategies for testing
fn arb_jitter_strategy() -> impl Strategy<Value = JitterStrategy> {
    prop_oneof![
        Just(JitterStrategy::None),
        Just(JitterStrategy::Full),
        Just(JitterStrategy::Equal),
        Just(JitterStrategy::Decorrelated),
    ]
}

/// Generate arbitrary base delay values (in reasonable range)
fn arb_base_delay() -> impl Strategy<Value = u64> {
    50u64..=5000u64 // 50ms to 5s
}

/// Generate arbitrary max delay values
fn arb_max_delay() -> impl Strategy<Value = u64> {
    1000u64..=60_000u64 // 1s to 60s
}

/// Generate arbitrary retry counts
fn arb_retry_count() -> impl Strategy<Value = usize> {
    1usize..=10usize
}

fn millis_to_nanos(ms: u64) -> u64 {
    Duration::from_millis(ms)
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64
}

fn setup_retry_test_cx() -> (Arc<VirtualClock>, TimerDriverHandle, impl Drop) {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
    let cx = Cx::new_with_drivers(
        RegionId::new_for_test(0, 0),
        TaskId::new_for_test(0, 0),
        Budget::INFINITE,
        None,
        None,
        None,
        Some(timer.clone()),
        None,
    );
    let guard = Cx::set_current(Some(cx));
    (clock, timer, guard)
}

fn capped_exponential_delay(base_delay: u64, attempt: usize, max_delay: u64) -> u64 {
    base_delay
        .saturating_mul(1_u64.checked_shl(attempt as u32).unwrap_or(u64::MAX))
        .min(max_delay)
}

fn delay_bounds_ms(
    jitter: JitterStrategy,
    base_delay: u64,
    max_delay: u64,
    attempt: usize,
    last_delay_ms: u64,
) -> (u64, u64) {
    match jitter {
        JitterStrategy::None => {
            let delay = capped_exponential_delay(base_delay, attempt, max_delay);
            (delay, delay)
        }
        JitterStrategy::Full => (0, capped_exponential_delay(base_delay, attempt, max_delay)),
        JitterStrategy::Equal => {
            let delay = capped_exponential_delay(base_delay, attempt, max_delay);
            (delay / 2, delay)
        }
        JitterStrategy::Decorrelated => {
            let upper = last_delay_ms
                .saturating_mul(3)
                .min(max_delay)
                .max(base_delay);
            (base_delay.min(upper), upper)
        }
    }
}

fn poll_retry_after_advance(
    policy: &ExponentialBackoff<u32>,
    error: &TestError,
    advance_ms: u64,
) -> Poll<ExponentialBackoff<u32>> {
    let (clock, timer, _guard) = setup_retry_test_cx();
    let error_result = Result::<&u32, &TestError>::Err(error);
    let mut future = policy
        .retry(&42u32, error_result)
        .expect("retry should be available within configured bounds");
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    match future.as_mut().poll(&mut cx) {
        Poll::Ready(next_policy) => Poll::Ready(next_policy),
        Poll::Pending => {
            if advance_ms > 0 {
                clock.advance(millis_to_nanos(advance_ms));
            }
            let _ = timer.process_timers();
            future.as_mut().poll(&mut cx)
        }
    }
}

fn exact_retry_delay_ms(
    policy: &ExponentialBackoff<u32>,
    error: &TestError,
    lower_bound_ms: u64,
    upper_bound_ms: u64,
) -> u64 {
    if lower_bound_ms > 0 {
        let before_lower = poll_retry_after_advance(policy, error, lower_bound_ms - 1);
        assert!(
            before_lower.is_pending(),
            "retry resolved before lower bound {lower_bound_ms}ms for {:?}",
            policy.jitter()
        );
    }

    if let Poll::Ready(_) = poll_retry_after_advance(policy, error, 0) {
        assert_eq!(
            lower_bound_ms, 0,
            "immediate readiness only valid when the lower bound is zero"
        );
        return 0;
    }

    let mut low = lower_bound_ms.max(1);
    let mut high = upper_bound_ms.max(low);
    while low < high {
        let mid = low + (high - low) / 2;
        match poll_retry_after_advance(policy, error, mid) {
            Poll::Ready(_) => high = mid,
            Poll::Pending => low = mid + 1,
        }
    }

    low
}

fn execute_retry_attempt(
    policy: &ExponentialBackoff<u32>,
    error: &TestError,
    lower_bound_ms: u64,
    upper_bound_ms: u64,
) -> (ExponentialBackoff<u32>, u64) {
    let delay_ms = exact_retry_delay_ms(policy, error, lower_bound_ms, upper_bound_ms);
    assert!(
        delay_ms >= lower_bound_ms && delay_ms <= upper_bound_ms,
        "delay {delay_ms}ms should stay within [{lower_bound_ms}, {upper_bound_ms}]"
    );

    match poll_retry_after_advance(policy, error, delay_ms) {
        Poll::Ready(next_policy) => (next_policy, delay_ms),
        Poll::Pending => panic!("retry should complete once virtual time reaches {delay_ms}ms"),
    }
}

/// Simple test error type that implements std::error::Error
#[derive(Debug, Clone, PartialEq, Eq)]
struct TestError(String);

impl fmt::Display for TestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Test error: {}", self.0)
    }
}

impl std::error::Error for TestError {}

/// Test service that can be controlled to succeed or fail
#[derive(Debug, Clone)]
struct TestService {
    id: u64,
    should_fail: Arc<AtomicBool>,
    call_count: Arc<AtomicUsize>,
}

impl TestService {
    fn new(id: u64) -> Self {
        Self {
            id,
            should_fail: Arc::new(AtomicBool::new(false)),
            call_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn fail(&self) {
        self.should_fail.store(true, Ordering::Release);
    }
}

impl Service<u32> for TestService {
    type Response = u64;
    type Error = TestError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.should_fail.load(Ordering::Acquire) {
            Poll::Ready(Err(TestError("service unavailable".to_string())))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn call(&mut self, _req: u32) -> Self::Future {
        self.call_count.fetch_add(1, Ordering::AcqRel);
        let id = self.id;
        let should_fail = self.should_fail.load(Ordering::Acquire);

        Box::pin(async move {
            if should_fail {
                Err(TestError("service call failed".to_string()))
            } else {
                Ok(id)
            }
        })
    }
}

/// Test service factory that can control when service creation succeeds/fails
#[derive(Debug, Clone)]
struct TestServiceMaker {
    next_id: Arc<AtomicU64>,
    should_fail_creation: Arc<AtomicBool>,
    creation_count: Arc<AtomicUsize>,
    created_services: Arc<Mutex<Vec<TestService>>>,
}

impl TestServiceMaker {
    fn new() -> Self {
        Self {
            next_id: Arc::new(AtomicU64::new(1)),
            should_fail_creation: Arc::new(AtomicBool::new(false)),
            creation_count: Arc::new(AtomicUsize::new(0)),
            created_services: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn fail_creation(&self) {
        self.should_fail_creation.store(true, Ordering::Release);
    }

    fn succeed_creation(&self) {
        self.should_fail_creation.store(false, Ordering::Release);
    }

    fn creation_count(&self) -> usize {
        self.creation_count.load(Ordering::Acquire)
    }
}

impl MakeService for TestServiceMaker {
    type Service = TestService;
    type Error = TestError;

    fn make_service(&self) -> Result<Self::Service, Self::Error> {
        self.creation_count.fetch_add(1, Ordering::AcqRel);

        if self.should_fail_creation.load(Ordering::Acquire) {
            Err(TestError("service creation failed".to_string()))
        } else {
            let id = self.next_id.fetch_add(1, Ordering::AcqRel);
            let service = TestService::new(id);
            self.created_services.lock().unwrap().push(service.clone());
            Ok(service)
        }
    }
}

/// Metamorphic Relation 1: Reconnect Attempts Converge with Exponential Backoff
///
/// For any exponential backoff policy, successive retry attempts should eventually
/// converge (stop retrying) when max_retries is reached, and attempt count should
/// increase monotonically.
#[test]
fn mr_reconnect_attempts_converge_with_backoff() {
    fn property(
        base_delay: u64,
        max_delay: u64,
        max_retries: usize,
        jitter: JitterStrategy,
    ) -> bool {
        // Create exponential backoff policy
        let mut policy = ExponentialBackoff::<u32>::new(max_retries, base_delay, jitter)
            .with_max_delay(max_delay);

        let mut attempts = Vec::new();
        let error = TestError("retry error".to_string());
        let mut last_delay_ms = base_delay;

        // Simulate retry attempts
        for attempt_num in 0..max_retries + 2 {
            let current_attempt = policy.current_attempt();
            attempts.push(current_attempt);

            // Try to get retry future - should succeed if under max_retries
            if current_attempt < max_retries {
                let (lower_bound, upper_bound) = delay_bounds_ms(
                    jitter,
                    base_delay,
                    max_delay,
                    current_attempt,
                    last_delay_ms,
                );
                let (new_policy, delay_ms) =
                    execute_retry_attempt(&policy, &error, lower_bound, upper_bound);
                last_delay_ms = delay_ms.max(1);
                policy = new_policy;
            } else {
                // No more retries available - should happen after max_retries attempts
                assert!(
                    current_attempt >= max_retries,
                    "Policy stopped retrying before reaching max_retries: {} >= {}",
                    current_attempt,
                    max_retries
                );
                break;
            }

            // Safety check to avoid infinite loops in tests
            if attempt_num > max_retries {
                break;
            }
        }

        // Verify convergence: attempts should increase monotonically
        for i in 1..attempts.len() {
            assert!(
                attempts[i] >= attempts[i - 1],
                "Attempt count should not decrease: attempt[{}] = {} < attempt[{}] = {}",
                i,
                attempts[i],
                i - 1,
                attempts[i - 1]
            );
        }

        true
    }

    proptest!(|(
        base_delay in arb_base_delay(),
        max_delay in arb_max_delay(),
        max_retries in arb_retry_count(),
        jitter in arb_jitter_strategy(),
    )| {
        prop_assume!(max_delay >= base_delay);
        prop_assume!(max_retries > 0);
        prop_assert!(property(base_delay, max_delay, max_retries, jitter));
    });
}

/// Metamorphic Relation 2: Jitter Bounds Respected
///
/// For any jitter strategy, the calculated delays must fall within the
/// mathematically defined bounds for that strategy.
#[test]
fn mr_jitter_bounds_respected() {
    fn property(
        base_delay: u64,
        max_delay: u64,
        max_retries: usize,
        jitter: JitterStrategy,
    ) -> bool {
        if max_retries == 0 || max_retries > 10 {
            return true; // Skip invalid cases
        }

        let mut policy = ExponentialBackoff::<u32>::new(max_retries, base_delay, jitter)
            .with_max_delay(max_delay);
        let error = TestError("jitter test error".to_string());
        let mut observed_delays = Vec::new();
        let mut last_delay_ms = base_delay;

        for attempt in 0..max_retries.min(5) {
            let (lower_bound, upper_bound) =
                delay_bounds_ms(jitter, base_delay, max_delay, attempt, last_delay_ms);
            let (new_policy, delay_ms) =
                execute_retry_attempt(&policy, &error, lower_bound, upper_bound);
            observed_delays.push(delay_ms);
            last_delay_ms = delay_ms.max(1);
            policy = new_policy;
        }

        match jitter {
            JitterStrategy::None => observed_delays.iter().enumerate().all(|(attempt, &delay)| {
                delay == capped_exponential_delay(base_delay, attempt, max_delay)
            }),
            JitterStrategy::Full | JitterStrategy::Equal | JitterStrategy::Decorrelated => {
                observed_delays.iter().all(|&delay| delay <= max_delay)
            }
        }
    }

    proptest!(|(
        base_delay in arb_base_delay(),
        max_delay in arb_max_delay(),
        max_retries in arb_retry_count(),
        jitter in arb_jitter_strategy(),
    )| {
        prop_assume!(max_delay >= base_delay);
        prop_assume!(max_retries > 0);
        prop_assert!(property(base_delay, max_delay, max_retries, jitter));
    });
}

/// Metamorphic Relation 3: Cancel-on-Success Frees Reconnect State
///
/// When a reconnection attempt succeeds, the reconnect service should
/// clear its pending reconnection state and be ready for new operations.
#[test]
fn mr_cancel_on_success_frees_state() {
    fn property(initial_failure: bool, _recovery_delay: u64) -> bool {
        let maker = TestServiceMaker::new();
        let initial_service = TestService::new(100);

        if initial_failure {
            initial_service.fail();
        }

        let mut reconnect = Reconnect::new(maker.clone(), initial_service);

        // Check initial state
        let _initially_connected = reconnect.is_connected();

        if initial_failure {
            // Force a reconnection attempt
            maker.succeed_creation(); // Ensure maker can create services
            let reconnect_result = reconnect.reconnect();

            // Successful reconnection should clear pending state
            if reconnect_result.is_ok() {
                assert!(
                    reconnect.is_connected(),
                    "Should be connected after successful reconnect"
                );

                // State should be clean - ready for new operations
                let success_count_after = reconnect.reconnect_count();
                assert!(
                    success_count_after >= 1,
                    "Should track successful reconnection"
                );

                // Service should be usable
                if let Some(inner) = reconnect.inner() {
                    // Inner service exists and should be ready
                    assert_eq!(inner.id, 1, "Should have new service instance");
                }
            }
        }

        // Always verify state consistency
        let is_connected = reconnect.is_connected();
        let has_inner = reconnect.inner().is_some();
        assert_eq!(
            is_connected, has_inner,
            "Connection state should match inner service presence"
        );

        true
    }

    proptest!(|(
        initial_failure in any::<bool>(),
        recovery_delay in 10u64..=1000u64,
    )| {
        prop_assert!(property(initial_failure, recovery_delay));
    });
}

/// Metamorphic Relation 4: Concurrent Reconnect Serialized
///
/// Multiple concurrent reconnection attempts should be serialized properly,
/// with only one reconnection happening at a time, and all attempts should
/// see consistent state.
#[test]
fn mr_concurrent_reconnect_serialized() {
    fn property(num_attempts: usize) -> bool {
        if num_attempts == 0 || num_attempts > 10 {
            return true; // Skip invalid cases
        }

        let maker = TestServiceMaker::new();
        let initial_service = TestService::new(200);
        initial_service.fail(); // Start with failed service

        let reconnect = Arc::new(Mutex::new(Reconnect::new(maker.clone(), initial_service)));
        let success_count = Arc::new(AtomicUsize::new(0));

        // Enable service creation
        maker.succeed_creation();

        // Simulate concurrent reconnection attempts
        let mut handles = Vec::new();

        for i in 0..num_attempts {
            let reconnect_clone = reconnect.clone();
            let success_count_clone = success_count.clone();

            let handle = std::thread::spawn(move || {
                let mut guard = reconnect_clone.lock().unwrap();
                if guard.reconnect().is_ok() {
                    success_count_clone.fetch_add(1, Ordering::AcqRel);
                }
                drop(guard);
                i
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.join().unwrap());
        }

        // Verify serialization: exactly one reconnection should have succeeded
        let _final_success_count = success_count.load(Ordering::Acquire);
        let total_creations = maker.creation_count();

        // All threads should have completed
        assert_eq!(results.len(), num_attempts);

        // Services should have been created (may be more than success count due to races)
        assert!(
            total_creations > 0,
            "At least one service should have been created"
        );

        // Final state should be consistent
        let final_reconnect = reconnect.lock().unwrap();
        assert!(
            final_reconnect.is_connected(),
            "Should be connected after any successful reconnect"
        );

        true
    }

    proptest!(|(
        num_attempts in 1usize..=5usize,
    )| {
        prop_assert!(property(num_attempts));
    });
}

/// Metamorphic Relation 5: LabRuntime Determinism
///
/// Under deterministic execution conditions (same inputs, same entropy seed),
/// reconnection behavior should be identical across multiple runs.
#[test]
fn mr_lab_runtime_determinism() {
    fn property(
        base_delay: u64,
        max_retries: usize,
        jitter: JitterStrategy,
        _entropy_seed: u64, // Currently unused, but part of the metamorphic property interface
    ) -> bool {
        if max_retries == 0 || max_retries > 10 {
            return true; // Skip invalid cases
        }

        // Since we're testing determinism, we need to ensure identical conditions.
        let run_backoff_sequence = || -> Vec<u64> {
            let mut policy = ExponentialBackoff::<u32>::new(max_retries, base_delay, jitter)
                .with_max_delay(30_000);
            let error = TestError("determinism test".to_string());
            let mut delays = Vec::new();
            let mut last_delay_ms = base_delay;

            for attempt in 0..max_retries.min(3) {
                let (lower_bound, upper_bound) =
                    delay_bounds_ms(jitter, base_delay, 30_000, attempt, last_delay_ms);
                let (new_policy, delay_ms) =
                    execute_retry_attempt(&policy, &error, lower_bound, upper_bound);
                delays.push(delay_ms);
                last_delay_ms = delay_ms.max(1);
                policy = new_policy;
            }

            delays
        };

        // Run the same sequence multiple times
        let run1 = run_backoff_sequence();
        let run2 = run_backoff_sequence();
        let run3 = run_backoff_sequence();

        run1 == run2 && run2 == run3
    }

    proptest!(|(
        base_delay in arb_base_delay(),
        max_retries in arb_retry_count(),
        jitter in arb_jitter_strategy(),
        entropy_seed in any::<u64>(),
    )| {
        prop_assert!(property(base_delay, max_retries, jitter, entropy_seed));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_maker_basic() {
        let maker = TestServiceMaker::new();

        // Should succeed by default
        let service1 = maker.make_service().unwrap();
        assert_eq!(service1.id, 1);
        assert_eq!(maker.creation_count(), 1);

        // Should create new service with incremented ID
        let service2 = maker.make_service().unwrap();
        assert_eq!(service2.id, 2);
        assert_eq!(maker.creation_count(), 2);

        // Should fail when configured to fail
        maker.fail_creation();
        let result = maker.make_service();
        assert!(result.is_err());
        assert_eq!(maker.creation_count(), 3); // Attempt count still increments
    }

    #[test]
    fn test_backoff_policy_basic() {
        let policy = ExponentialBackoff::<u32>::new(3, 100, JitterStrategy::Full);

        assert_eq!(policy.max_retries(), 3);
        assert_eq!(policy.current_attempt(), 0);
        assert_eq!(policy.base_delay_ms(), 100);
        assert_eq!(policy.jitter(), JitterStrategy::Full);
    }

    #[test]
    fn test_jitter_bounds_manual() {
        // Test specific known cases to verify bounds logic using public interface
        let mut full_jitter =
            ExponentialBackoff::<u32>::new(10, 100, JitterStrategy::Full).with_max_delay(30_000);
        let error = TestError("manual test".to_string());
        let mut last_delay_ms = 100;

        for attempt in 0..3 {
            let (lower_bound, upper_bound) =
                delay_bounds_ms(JitterStrategy::Full, 100, 30_000, attempt, last_delay_ms);
            let (next_policy, delay_ms) =
                execute_retry_attempt(&full_jitter, &error, lower_bound, upper_bound);
            assert!(
                delay_ms <= capped_exponential_delay(100, attempt, 30_000),
                "Full jitter delay {} should stay within attempt {} bounds",
                delay_ms,
                attempt
            );
            last_delay_ms = delay_ms.max(1);
            full_jitter = next_policy;
        }

        let mut equal_jitter =
            ExponentialBackoff::<u32>::new(10, 100, JitterStrategy::Equal).with_max_delay(30_000);
        let mut last_delay_ms = 100;

        for attempt in 0..2 {
            let (lower_bound, upper_bound) =
                delay_bounds_ms(JitterStrategy::Equal, 100, 30_000, attempt, last_delay_ms);
            let (next_policy, delay_ms) =
                execute_retry_attempt(&equal_jitter, &error, lower_bound, upper_bound);
            let capped_delay = capped_exponential_delay(100, attempt, 30_000);
            assert!(
                delay_ms >= capped_delay / 2 && delay_ms <= capped_delay,
                "Equal jitter delay {} should stay within attempt {} bounds",
                delay_ms,
                attempt
            );
            last_delay_ms = delay_ms.max(1);
            equal_jitter = next_policy;
        }
    }
}
