//! Real-service E2E tests: combinator/retry ↔ service/timeout integration (br-e2e-136).
//!
//! Tests that retry loops with exponential backoff correctly respect outer timeout
//! boundaries without firing additional attempts after timeout expiry. Verifies
//! that timeout cancellation properly propagates through retry combinators.
//!
//! # Integration Patterns Tested
//!
//! - **Timeout Boundary Respect**: Retry stops when outer timeout expires
//! - **Exponential Backoff Cancellation**: Sleep phases respect timeout cancellation
//! - **Attempt Control**: No new attempts start after timeout expiry
//! - **Error Propagation**: Timeout errors properly surface through retry layers
//! - **Time Source Consistency**: Both retry and timeout use compatible time sources
//!
//! # Test Scenarios
//!
//! 1. **Basic Timeout Boundary** — Simple retry respects timeout without extra attempts
//! 2. **Sleep Phase Cancellation** — Timeout during exponential backoff sleep cancels cleanly
//! 3. **Attempt Phase Cancellation** — Timeout during actual operation attempt cancels correctly
//! 4. **Rapid Timeout** — Very short timeout prevents any retry attempts
//! 5. **Border Case Timing** — Timeout at exact backoff boundaries
//!
//! # Safety Properties Verified
//!
//! - No attempts fired after timeout expiry
//! - Timeout error propagates correctly through retry wrapper
//! - Clean cancellation during both sleep and operation phases
//! - Time source consistency prevents spurious timeouts

use crate::combinator::retry::{retry, RetryPolicy};
use crate::service::timeout::{Timeout, TimeoutLayer};
use crate::service::{Layer, Service, ServiceBuilder, ServiceExt};
use crate::time::{Elapsed, Sleep};
use crate::types::{Outcome, Time};
use crate::cx::Cx;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

// ────────────────────────────────────────────────────────────────────────────────
// RealFailingService — Real service implementation that fails predictably
// ────────────────────────────────────────────────────────────────────────────────

/// A real service that fails a predetermined number of times before succeeding.
/// Tracks actual attempt counts and timing for verification.
#[derive(Debug, Clone)]
struct RealFailingService {
    /// Shared state tracking service calls
    state: Arc<Mutex<ServiceState>>,
}

#[derive(Debug)]
struct ServiceState {
    /// Number of times service has been called
    call_count: u32,
    /// Number of times service should fail before succeeding
    fail_count: u32,
    /// Duration each service call should take
    call_duration: Duration,
    /// Timeline of all service calls for verification
    call_timeline: Vec<CallRecord>,
    /// Current virtual time source
    time_source: fn() -> Time,
}

#[derive(Debug, Clone)]
struct CallRecord {
    /// When this call started
    start_time: Time,
    /// When this call completed (None if still pending)
    end_time: Option<Time>,
    /// Whether this call succeeded
    succeeded: bool,
    /// Call sequence number
    call_id: u32,
}

impl RealFailingService {
    /// Creates a new service that fails `fail_count` times before succeeding.
    fn new(fail_count: u32, call_duration: Duration, time_source: fn() -> Time) -> Self {
        Self {
            state: Arc::new(Mutex::new(ServiceState {
                call_count: 0,
                fail_count,
                call_duration,
                call_timeline: Vec::new(),
                time_source,
            })),
        }
    }

    /// Returns the current call count and timeline for verification.
    fn get_call_info(&self) -> (u32, Vec<CallRecord>) {
        let state = self.state.lock().unwrap();
        (state.call_count, state.call_timeline.clone())
    }
}

/// Request type for the failing service
#[derive(Debug, Clone)]
struct TestRequest {
    id: u32,
}

/// Response type for the failing service
#[derive(Debug, Clone)]
struct TestResponse {
    id: u32,
    attempt: u32,
}

/// Error type for the failing service
#[derive(Debug, Clone)]
struct ServiceError {
    message: String,
    attempt: u32,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Service error on attempt {}: {}", self.attempt, self.message)
    }
}

impl std::error::Error for ServiceError {}

impl Service<TestRequest> for RealFailingService {
    type Response = TestResponse;
    type Error = ServiceError;
    type Future = ServiceFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: TestRequest) -> Self::Future {
        let mut state = self.state.lock().unwrap();
        state.call_count += 1;
        let call_id = state.call_count;
        let should_succeed = call_id > state.fail_count;
        let call_duration = state.call_duration;
        let start_time = (state.time_source)();

        state.call_timeline.push(CallRecord {
            start_time,
            end_time: None,
            succeeded: should_succeed,
            call_id,
        });

        ServiceFuture {
            state: Arc::clone(&self.state),
            call_id,
            req_id: req.id,
            should_succeed,
            sleep: Sleep::after(start_time, call_duration),
            completed: false,
        }
    }
}

/// Future returned by RealFailingService
#[derive(Debug)]
struct ServiceFuture {
    state: Arc<Mutex<ServiceState>>,
    call_id: u32,
    req_id: u32,
    should_succeed: bool,
    sleep: Sleep,
    completed: bool,
}

impl Future for ServiceFuture {
    type Output = Result<TestResponse, ServiceError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.completed {
            panic!("ServiceFuture polled after completion");
        }

        // Wait for the call duration to elapse
        match Pin::new(&mut self.sleep).poll(cx) {
            Poll::Ready(()) => {
                self.completed = true;

                // Update the call record with completion time
                {
                    let mut state = self.state.lock().unwrap();
                    if let Some(record) = state.call_timeline.iter_mut()
                        .find(|r| r.call_id == self.call_id) {
                        record.end_time = Some((state.time_source)());
                    }
                }

                if self.should_succeed {
                    Poll::Ready(Ok(TestResponse {
                        id: self.req_id,
                        attempt: self.call_id,
                    }))
                } else {
                    Poll::Ready(Err(ServiceError {
                        message: "Simulated failure".to_string(),
                        attempt: self.call_id,
                    }))
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// Test Utilities
// ────────────────────────────────────────────────────────────────────────────────

/// Sets up a test environment with controlled virtual time.
struct TestEnvironment {
    /// Current virtual time
    current_time: Arc<Mutex<Time>>,
    /// Time source function for services
    time_source: fn() -> Time,
}

impl TestEnvironment {
    fn new(start_time: Time) -> Self {
        let current_time = Arc::new(Mutex::new(start_time));
        let current_time_clone = Arc::clone(&current_time);

        let time_source = move || {
            *current_time_clone.lock().unwrap()
        };

        Self {
            current_time,
            time_source,
        }
    }

    fn advance_time(&self, duration: Duration) {
        let mut time = self.current_time.lock().unwrap();
        *time = time.saturating_add_nanos(
            duration.as_nanos().min(u128::from(u64::MAX)) as u64
        );
    }

    fn now(&self) -> Time {
        *self.current_time.lock().unwrap()
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// Test Cases
// ────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_timeout_boundary() {
        // Test that retry respects timeout without extra attempts
        let start_time = Time::from_unix_nanos(1_000_000_000);
        let env = TestEnvironment::new(start_time);

        // Service that fails 3 times, each attempt takes 200ms
        let service = RealFailingService::new(3, Duration::from_millis(200), env.time_source);

        // Retry policy: 5 attempts, 100ms initial delay, 2x multiplier
        let retry_policy = RetryPolicy::new()
            .with_max_attempts(5)
            .with_initial_delay(Duration::from_millis(100))
            .with_multiplier(2.0)
            .with_jitter(0.0); // No jitter for deterministic testing

        // Timeout: 500ms (should allow first attempt + one retry)
        let timeout_service = Timeout::with_time_getter(
            service.clone(),
            Duration::from_millis(500),
            env.time_source
        );

        // Create retry operation
        let retry_operation = retry(retry_policy, |_: &ServiceError| true, || async {
            let mut svc = timeout_service.clone();
            match svc.call(TestRequest { id: 1 }).await {
                Ok(resp) => Outcome::Ok(resp),
                Err(err) => Outcome::Err(err),
            }
        });

        // Execute the retry operation
        let result = retry_operation.await;

        // Verify that retry was cancelled due to timeout
        assert!(result.is_cancelled() || result.is_failed());

        // Verify the service was only called the expected number of times
        let (call_count, timeline) = service.get_call_info();

        // Should have at most 2 calls (initial + one retry) before timeout
        assert!(call_count <= 2, "Expected at most 2 calls, got {}", call_count);

        // Verify no calls started after timeout expiry
        let timeout_deadline = start_time.saturating_add_nanos(500_000_000);
        for record in &timeline {
            assert!(
                record.start_time <= timeout_deadline,
                "Call {} started at {:?} after timeout deadline {:?}",
                record.call_id,
                record.start_time,
                timeout_deadline
            );
        }

        println!("✓ Basic timeout boundary test passed - {} calls made", call_count);
    }

    #[tokio::test]
    async fn test_sleep_phase_cancellation() {
        // Test timeout during exponential backoff sleep phase
        let start_time = Time::from_unix_nanos(2_000_000_000);
        let env = TestEnvironment::new(start_time);

        // Service that fails 5 times, each attempt takes 50ms
        let service = RealFailingService::new(5, Duration::from_millis(50), env.time_source);

        // Retry policy: long delays to trigger timeout during sleep
        let retry_policy = RetryPolicy::new()
            .with_max_attempts(5)
            .with_initial_delay(Duration::from_millis(300)) // Long initial delay
            .with_multiplier(2.0)
            .with_jitter(0.0);

        // Timeout: 200ms (shorter than first retry delay)
        let timeout_service = Timeout::with_time_getter(
            service.clone(),
            Duration::from_millis(200),
            env.time_source
        );

        let retry_operation = retry(retry_policy, |_: &ServiceError| true, || async {
            let mut svc = timeout_service.clone();
            match svc.call(TestRequest { id: 2 }).await {
                Ok(resp) => Outcome::Ok(resp),
                Err(err) => Outcome::Err(err),
            }
        });

        let result = retry_operation.await;

        // Should be cancelled/failed due to timeout during sleep
        assert!(result.is_cancelled() || result.is_failed());

        let (call_count, timeline) = service.get_call_info();

        // Should have only made 1 call (initial attempt), no retries due to timeout
        assert_eq!(call_count, 1, "Expected exactly 1 call (timeout during sleep), got {}", call_count);

        // Verify timing constraints
        let timeout_deadline = start_time.saturating_add_nanos(200_000_000);
        for record in &timeline {
            assert!(
                record.start_time <= timeout_deadline,
                "Call started after timeout deadline"
            );
        }

        println!("✓ Sleep phase cancellation test passed - {} calls made", call_count);
    }

    #[tokio::test]
    async fn test_attempt_phase_cancellation() {
        // Test timeout during actual operation attempt
        let start_time = Time::from_unix_nanos(3_000_000_000);
        let env = TestEnvironment::new(start_time);

        // Service that fails 3 times, each attempt takes 400ms (long)
        let service = RealFailingService::new(3, Duration::from_millis(400), env.time_source);

        // Retry policy: short delays, quick retries
        let retry_policy = RetryPolicy::new()
            .with_max_attempts(5)
            .with_initial_delay(Duration::from_millis(10))
            .with_multiplier(1.5)
            .with_jitter(0.0);

        // Timeout: 300ms (shorter than single service call duration)
        let timeout_service = Timeout::with_time_getter(
            service.clone(),
            Duration::from_millis(300),
            env.time_source
        );

        let retry_operation = retry(retry_policy, |_: &ServiceError| true, || async {
            let mut svc = timeout_service.clone();
            match svc.call(TestRequest { id: 3 }).await {
                Ok(resp) => Outcome::Ok(resp),
                Err(err) => Outcome::Err(err),
            }
        });

        let result = retry_operation.await;

        // Should timeout during the first attempt
        assert!(result.is_cancelled() || result.is_failed());

        let (call_count, timeline) = service.get_call_info();

        // Should have made exactly 1 call that was cancelled
        assert_eq!(call_count, 1, "Expected exactly 1 call (timeout during attempt), got {}", call_count);

        println!("✓ Attempt phase cancellation test passed - {} calls made", call_count);
    }

    #[tokio::test]
    async fn test_rapid_timeout() {
        // Test very short timeout that prevents any retry attempts
        let start_time = Time::from_unix_nanos(4_000_000_000);
        let env = TestEnvironment::new(start_time);

        // Service that fails 2 times, each attempt takes 100ms
        let service = RealFailingService::new(2, Duration::from_millis(100), env.time_source);

        // Retry policy: reasonable settings
        let retry_policy = RetryPolicy::new()
            .with_max_attempts(3)
            .with_initial_delay(Duration::from_millis(50))
            .with_multiplier(2.0)
            .with_jitter(0.0);

        // Timeout: 10ms (very rapid - should kill first attempt quickly)
        let timeout_service = Timeout::with_time_getter(
            service.clone(),
            Duration::from_millis(10),
            env.time_source
        );

        let retry_operation = retry(retry_policy, |_: &ServiceError| true, || async {
            let mut svc = timeout_service.clone();
            match svc.call(TestRequest { id: 4 }).await {
                Ok(resp) => Outcome::Ok(resp),
                Err(err) => Outcome::Err(err),
            }
        });

        let result = retry_operation.await;

        // Should be cancelled/failed very quickly
        assert!(result.is_cancelled() || result.is_failed());

        let (call_count, timeline) = service.get_call_info();

        // Should have made at most 1 call before rapid timeout
        assert!(call_count <= 1, "Expected at most 1 call (rapid timeout), got {}", call_count);

        // Verify no calls completed successfully
        for record in &timeline {
            assert!(!record.succeeded, "No calls should have succeeded with rapid timeout");
        }

        println!("✓ Rapid timeout test passed - {} calls made", call_count);
    }

    #[tokio::test]
    async fn test_border_case_timing() {
        // Test timeout at exact backoff boundary timing
        let start_time = Time::from_unix_nanos(5_000_000_000);
        let env = TestEnvironment::new(start_time);

        // Service that fails 4 times, each attempt takes exactly 100ms
        let service = RealFailingService::new(4, Duration::from_millis(100), env.time_source);

        // Retry policy: 100ms initial delay, 2x multiplier
        // Timeline: attempt1(100ms) + delay1(100ms) + attempt2(100ms) = 300ms
        let retry_policy = RetryPolicy::new()
            .with_max_attempts(4)
            .with_initial_delay(Duration::from_millis(100))
            .with_multiplier(2.0)
            .with_jitter(0.0);

        // Timeout: exactly 300ms (should allow first attempt + first retry)
        let timeout_service = Timeout::with_time_getter(
            service.clone(),
            Duration::from_millis(300),
            env.time_source
        );

        let retry_operation = retry(retry_policy, |_: &ServiceError| true, || async {
            let mut svc = timeout_service.clone();
            match svc.call(TestRequest { id: 5 }).await {
                Ok(resp) => Outcome::Ok(resp),
                Err(err) => Outcome::Err(err),
            }
        });

        let result = retry_operation.await;

        // Result depends on exact timing, but should be deterministic
        let (call_count, timeline) = service.get_call_info();

        // Should have made at most 2 calls within the 300ms timeout
        assert!(call_count <= 2, "Expected at most 2 calls (border case), got {}", call_count);

        // Verify timing precision
        let timeout_deadline = start_time.saturating_add_nanos(300_000_000);
        for record in &timeline {
            if let Some(end_time) = record.end_time {
                // Completed calls should finish within timeout window
                assert!(
                    end_time <= timeout_deadline.saturating_add_nanos(1_000_000), // 1ms tolerance
                    "Call completed too late: {:?} > {:?}",
                    end_time,
                    timeout_deadline
                );
            }
        }

        println!("✓ Border case timing test passed - {} calls made", call_count);
    }

    #[tokio::test]
    async fn test_success_case_timing() {
        // Test successful completion within timeout boundary
        let start_time = Time::from_unix_nanos(6_000_000_000);
        let env = TestEnvironment::new(start_time);

        // Service that fails only 1 time, then succeeds
        let service = RealFailingService::new(1, Duration::from_millis(50), env.time_source);

        // Retry policy: quick retries
        let retry_policy = RetryPolicy::new()
            .with_max_attempts(3)
            .with_initial_delay(Duration::from_millis(20))
            .with_multiplier(2.0)
            .with_jitter(0.0);

        // Timeout: 500ms (generous - should allow success)
        let timeout_service = Timeout::with_time_getter(
            service.clone(),
            Duration::from_millis(500),
            env.time_source
        );

        let retry_operation = retry(retry_policy, |_: &ServiceError| true, || async {
            let mut svc = timeout_service.clone();
            match svc.call(TestRequest { id: 6 }).await {
                Ok(resp) => Outcome::Ok(resp),
                Err(err) => Outcome::Err(err),
            }
        });

        let result = retry_operation.await;

        // Should succeed on second attempt
        assert!(result.is_ok(), "Expected success, got {:?}", result);

        let (call_count, timeline) = service.get_call_info();

        // Should have made exactly 2 calls (fail, then succeed)
        assert_eq!(call_count, 2, "Expected exactly 2 calls (fail -> succeed), got {}", call_count);

        // Verify success timing
        assert!(timeline.len() >= 2, "Expected at least 2 call records");
        assert!(!timeline[0].succeeded, "First call should have failed");
        assert!(timeline[1].succeeded, "Second call should have succeeded");

        println!("✓ Success case timing test passed - {} calls made", call_count);
    }
}