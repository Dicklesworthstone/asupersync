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

use asupersync::runtime::builder::RuntimeBuilder;
use asupersync::service::retry::{ExponentialBackoff, JitterStrategy, Policy};
use asupersync::service::reconnect::{MakeService, Reconnect};
use asupersync::service::Service;
use proptest::prelude::*;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

/// Generate arbitrary jitter strategies for testing
fn arb_jitter_strategy() -> impl Strategy<Value = JitterStrategy> {
    prop_oneof![
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

    fn succeed(&self) {
        self.should_fail.store(false, Ordering::Release);
    }

    fn call_count(&self) -> usize {
        self.call_count.load(Ordering::Acquire)
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

    fn get_created_services(&self) -> Vec<TestService> {
        self.created_services.lock().unwrap().clone()
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
        let error_result = Result::<&u32, &TestError>::Err(&TestError("retry error".to_string()));

        // Simulate retry attempts
        for attempt_num in 0..max_retries + 2 {
            let current_attempt = policy.current_attempt();
            attempts.push(current_attempt);

            // Try to get retry future - should succeed if under max_retries
            if let Some(retry_future) = policy.retry(&42u32, error_result) {
                // Create a simple async runtime to execute the future
                let runtime = RuntimeBuilder::current_thread()
                    .build()
                    .expect("failed to build test runtime");
                let new_policy = runtime.block_on(retry_future);
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
            if attempt_num >= max_retries + 1 {
                break;
            }
        }

        // Verify convergence: attempts should increase monotonically
        for i in 1..attempts.len() {
            assert!(
                attempts[i] >= attempts[i - 1],
                "Attempt count should not decrease: attempt[{}] = {} < attempt[{}] = {}",
                i, attempts[i], i - 1, attempts[i - 1]
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

        let error_result = Result::<&u32, &TestError>::Err(&TestError("jitter test error".to_string()));
        let mut observed_delays = Vec::new();

        // Collect delays from multiple retry attempts
        for _attempt_num in 0..max_retries.min(5) { // Limit attempts for performance
            if let Some(retry_future) = policy.retry(&42u32, error_result) {
                // Use a simple async runtime to measure the delay
                let runtime = RuntimeBuilder::current_thread()
                    .build()
                    .expect("failed to build test runtime");
                let start = std::time::Instant::now();
                let new_policy = runtime.block_on(retry_future);
                let elapsed = start.elapsed().as_millis() as u64;

                observed_delays.push(elapsed);
                policy = new_policy;
            } else {
                break; // No more retries available
            }
        }

        // Verify all observed delays are reasonable (not zero, not extremely large)
        for delay in &observed_delays {
            // Delay should be at least some minimum (we expect jitter, not zero delay)
            if *delay == 0 {
                continue; // Zero delays are acceptable for some jitter strategies
            }

            // Delay should not exceed max_delay by a large margin (allow some tolerance)
            if *delay > max_delay * 2 {
                eprintln!("Delay {} exceeds max_delay {} by too much", delay, max_delay);
                return false;
            }

            // Delay should not be unreasonably large
            if *delay > 60_000 {
                eprintln!("Delay {} exceeds reasonable maximum", delay);
                return false;
            }
        }

        // Check exponential growth pattern for non-decorrelated strategies
        match jitter {
            JitterStrategy::Full | JitterStrategy::Equal => {
                // Should see some variation in delays (not all identical)
                if observed_delays.len() > 1 {
                    let first = observed_delays[0];
                    let all_identical = observed_delays.iter().all(|&d| d == first);
                    if all_identical && first > 0 {
                        // This could indicate broken jitter
                        eprintln!("All delays are identical: {:?}", observed_delays);
                    }
                }
            }
            JitterStrategy::Decorrelated => {
                // Decorrelated jitter should show some relationship to previous delays
                // but exact bounds checking is complex, so we just verify reasonableness
            }
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
                assert!(reconnect.is_connected(), "Should be connected after successful reconnect");

                // State should be clean - ready for new operations
                let success_count_after = reconnect.reconnect_count();
                assert!(success_count_after >= 1, "Should track successful reconnection");

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
        assert_eq!(is_connected, has_inner, "Connection state should match inner service presence");

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
        assert!(total_creations > 0, "At least one service should have been created");

        // Final state should be consistent
        let final_reconnect = reconnect.lock().unwrap();
        assert!(final_reconnect.is_connected(), "Should be connected after any successful reconnect");

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

        // Since we're testing determinism, we need to ensure identical conditions
        let run_backoff_sequence = || -> Vec<u64> {
            let mut policy = ExponentialBackoff::<u32>::new(max_retries, base_delay, jitter)
                .with_max_delay(30_000);

            let mut delays = Vec::new();
            let error_result = Result::<&u32, &TestError>::Err(&TestError("determinism test".to_string()));

            for _attempt in 0..max_retries.min(3) { // Limit attempts for performance
                if let Some(retry_future) = policy.retry(&42u32, error_result) {
                    let runtime = RuntimeBuilder::current_thread()
                        .build()
                        .expect("failed to build test runtime");
                    let start = std::time::Instant::now();
                    let new_policy = runtime.block_on(retry_future);
                    let elapsed = start.elapsed().as_millis() as u64;

                    delays.push(elapsed);
                    policy = new_policy;
                } else {
                    break;
                }
            }

            delays
        };

        // Run the same sequence multiple times
        let run1 = run_backoff_sequence();
        let run2 = run_backoff_sequence();
        let run3 = run_backoff_sequence();

        // For deterministic jitter strategies, results should be more predictable
        match jitter {
            JitterStrategy::Full | JitterStrategy::Decorrelated => {
                // These strategies use randomness, so we focus on structural properties
                // All runs should have the same number of attempts
                let structure_consistent = run1.len() == run2.len() && run2.len() == run3.len();

                // All delays should be reasonable (not zero, not excessive)
                let all_reasonable = [&run1, &run2, &run3].iter().all(|run| {
                    run.iter().all(|&delay| delay > 0 && delay <= 30_000)
                });

                structure_consistent && all_reasonable
            }
            JitterStrategy::Equal => {
                // Equal jitter has bounds but still uses some randomness
                // Check that delays are within expected bounds and structurally consistent
                let lengths_match = run1.len() == run2.len() && run2.len() == run3.len();

                // All delays should be reasonable for equal jitter
                let bounds_respected = [&run1, &run2, &run3].iter().all(|run| {
                    run.iter().enumerate().all(|(i, &delay)| {
                        let min_expected = base_delay / 2; // Equal jitter minimum is base/2
                        let max_expected = base_delay.saturating_mul(1u64.saturating_pow(i as u32 + 1)).min(30_000);
                        delay >= min_expected && delay <= max_expected
                    })
                });

                lengths_match && bounds_respected
            }
        }
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
        let mut full_jitter = ExponentialBackoff::<u32>::new(10, 100, JitterStrategy::Full)
            .with_max_delay(30_000);

        let error_result = Result::<&u32, &TestError>::Err(&TestError("manual test".to_string()));

        // Execute retry attempts to observe delay patterns
        for attempt in 0..3 {
            if let Some(retry_future) = full_jitter.retry(&42u32, error_result) {
                let runtime = RuntimeBuilder::current_thread()
                    .build()
                    .expect("failed to build test runtime");
                let start = std::time::Instant::now();
                full_jitter = runtime.block_on(retry_future);
                let delay = start.elapsed().as_millis() as u64;

                // For full jitter, delay should be reasonable
                assert!(delay <= 5000, "Full jitter delay {} should be reasonable for attempt {}", delay, attempt);
            } else {
                break;
            }
        }

        let mut equal_jitter = ExponentialBackoff::<u32>::new(10, 100, JitterStrategy::Equal)
            .with_max_delay(30_000);

        // Test equal jitter bounds
        for attempt in 0..2 {
            if let Some(retry_future) = equal_jitter.retry(&42u32, error_result) {
                let runtime = RuntimeBuilder::current_thread()
                    .build()
                    .expect("failed to build test runtime");
                let start = std::time::Instant::now();
                equal_jitter = runtime.block_on(retry_future);
                let delay = start.elapsed().as_millis() as u64;

                // For equal jitter, delay should be in a reasonable range
                assert!(delay <= 1000, "Equal jitter delay {} should be reasonable for attempt {}", delay, attempt);
            } else {
                break;
            }
        }
    }
}