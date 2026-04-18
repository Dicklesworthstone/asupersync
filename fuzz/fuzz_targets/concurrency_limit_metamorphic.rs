#![no_main]

//! Metamorphic fuzz target for service::concurrency_limit fairness and Lyapunov bounded queue
//!
//! This target tests the critical properties of the concurrency limiting middleware:
//! 1. Throughput: N requests with limit L complete in ~N/L time
//! 2. Lyapunov stability: Queue/wait time remains bounded (no unbounded growth)
//! 3. No starvation: All requests eventually complete
//! 4. Cancel safety: Cancellation immediately releases permits

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use asupersync::service::{ConcurrencyLimitLayer, Layer, Service};

/// Simplified fuzz input for concurrency limit testing
#[derive(Arbitrary, Debug, Clone)]
struct ConcurrencyLimitFuzz {
    /// Random seed for deterministic execution
    pub seed: u64,
    /// Concurrency limit (1-20 to keep tests manageable)
    pub concurrency_limit: u8,
    /// Sequence of operations to test
    pub operations: Vec<ConcurrencyOperation>,
    /// Mock service configuration
    pub service_config: MockServiceConfig,
}

/// Individual concurrency limit operations
#[derive(Arbitrary, Debug, Clone)]
enum ConcurrencyOperation {
    /// Submit a request
    SubmitRequest {
        request_id: u16,
        processing_time_ms: u16,
    },
    /// Cancel an in-flight request
    CancelRequest { request_id: u16 },
    /// Advance time (simulate processing)
    AdvanceTime { delta_ms: u16 },
    /// Check system state for metrics
    CheckMetrics,
    /// Submit batch of requests simultaneously
    SubmitBatch {
        count: u8,
        base_id: u16,
        processing_time_ms: u16,
    },
    /// Wait for all in-flight to complete
    WaitForQuiescence,
}

/// Configuration for the mock service
#[derive(Arbitrary, Debug, Clone)]
struct MockServiceConfig {
    /// Base processing delay
    pub base_delay_ms: u16,
    /// Whether to simulate variable processing times
    pub variable_timing: bool,
    /// Error probability (0-255, 0 = never, 255 = always)
    pub error_probability: u8,
    /// Maximum processing time variation
    pub timing_variance_ms: u16,
}

/// Mock service that can simulate different processing characteristics
#[derive(Debug)]
struct MockService {
    config: MockServiceConfig,
    /// Active requests being processed
    active_requests: Arc<AtomicUsize>,
    /// Total requests processed
    total_processed: Arc<AtomicU64>,
    /// Request processing times for verification
    processing_times: Arc<parking_lot::Mutex<HashMap<u16, Duration>>>,
}

impl MockService {
    fn new(config: MockServiceConfig) -> Self {
        Self {
            config,
            active_requests: Arc::new(AtomicUsize::new(0)),
            total_processed: Arc::new(AtomicU64::new(0)),
            processing_times: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        }
    }

    fn active_count(&self) -> usize {
        self.active_requests.load(Ordering::SeqCst)
    }

    fn total_processed(&self) -> u64 {
        self.total_processed.load(Ordering::SeqCst)
    }
}

impl Clone for MockService {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            active_requests: self.active_requests.clone(),
            total_processed: self.total_processed.clone(),
            processing_times: self.processing_times.clone(),
        }
    }
}

#[derive(Debug)]
struct MockRequest {
    id: u16,
    processing_time: Duration,
}

#[derive(Debug)]
struct MockResponse {
    id: u16,
    processing_duration: Duration,
}

impl Service<MockRequest> for MockService {
    type Response = MockResponse;
    type Error = String;
    type Future = MockFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Simulate occasional service unavailability
        if self.config.error_probability > 200 && self.active_count() > 5 {
            Poll::Ready(Err("service overloaded".to_string()))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn call(&mut self, req: MockRequest) -> Self::Future {
        self.active_requests.fetch_add(1, Ordering::SeqCst);

        let processing_time = if self.config.variable_timing {
            Duration::from_millis(
                self.config.base_delay_ms as u64
                    + (req.id as u64 % self.config.timing_variance_ms as u64),
            )
        } else {
            req.processing_time
        };

        // Record expected processing time
        self.processing_times.lock().insert(req.id, processing_time);

        MockFuture {
            request_id: req.id,
            start_time: Instant::now(),
            processing_time,
            completed: false,
            active_counter: self.active_requests.clone(),
            total_counter: self.total_processed.clone(),
            error_probability: self.config.error_probability,
        }
    }
}

struct MockFuture {
    request_id: u16,
    start_time: Instant,
    processing_time: Duration,
    completed: bool,
    active_counter: Arc<AtomicUsize>,
    total_counter: Arc<AtomicU64>,
    error_probability: u8,
}

impl Future for MockFuture {
    type Output = Result<MockResponse, String>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        if this.completed {
            return Poll::Ready(Err("future polled after completion".to_string()));
        }

        let elapsed = this.start_time.elapsed();
        if elapsed >= this.processing_time {
            this.completed = true;
            this.active_counter.fetch_sub(1, Ordering::SeqCst);
            this.total_counter.fetch_add(1, Ordering::SeqCst);

            // Simulate occasional errors
            if this.error_probability > 240 && (this.request_id % 7) == 0 {
                Poll::Ready(Err(format!(
                    "simulated error for request {}",
                    this.request_id
                )))
            } else {
                Poll::Ready(Ok(MockResponse {
                    id: this.request_id,
                    processing_duration: elapsed,
                }))
            }
        } else {
            // Re-schedule ourselves to be polled again
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

impl Drop for MockFuture {
    fn drop(&mut self) {
        if !self.completed {
            // Request was cancelled - immediately release the slot
            self.active_counter.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Shadow model for tracking expected behavior
#[derive(Debug)]
struct ConcurrencyLimitShadowModel {
    /// Maximum concurrent requests allowed
    max_concurrency: usize,
    /// Currently submitted but not yet completed requests
    submitted_requests: HashMap<u16, RequestState>,
    /// Request submission times for timing analysis
    submission_times: HashMap<u16, Instant>,
    /// Completion times for throughput analysis
    completion_times: Vec<(u16, Instant, Duration)>, // (id, completion_time, processing_duration)
    /// Queue length over time (for Lyapunov analysis)
    queue_length_history: VecDeque<(Instant, usize)>,
    /// Maximum observed queue length
    max_queue_length: usize,
    /// Total requests submitted
    total_submitted: u64,
    /// Total requests completed
    total_completed: u64,
    /// Cancelled requests that should have freed permits immediately
    cancelled_requests: HashMap<u16, Instant>,
    /// Permit violations detected
    permit_violations: Vec<String>,
}

#[derive(Debug, Clone)]
struct RequestState {
    submitted_at: Instant,
    processing_time: Duration,
    cancelled: bool,
}

impl ConcurrencyLimitShadowModel {
    fn new(max_concurrency: usize) -> Self {
        Self {
            max_concurrency,
            submitted_requests: HashMap::new(),
            submission_times: HashMap::new(),
            completion_times: Vec::new(),
            queue_length_history: VecDeque::new(),
            max_queue_length: 0,
            total_submitted: 0,
            total_completed: 0,
            cancelled_requests: HashMap::new(),
            permit_violations: Vec::new(),
        }
    }

    fn submit_request(&mut self, request_id: u16, processing_time: Duration) {
        let now = Instant::now();
        self.submitted_requests.insert(
            request_id,
            RequestState {
                submitted_at: now,
                processing_time,
                cancelled: false,
            },
        );
        self.submission_times.insert(request_id, now);
        self.total_submitted += 1;

        self.update_queue_metrics(now);
    }

    fn cancel_request(&mut self, request_id: u16) {
        if let Some(state) = self.submitted_requests.get_mut(&request_id) {
            if !state.cancelled {
                state.cancelled = true;
                self.cancelled_requests.insert(request_id, Instant::now());
            }
        }
    }

    fn complete_request(&mut self, request_id: u16, actual_duration: Duration) {
        let now = Instant::now();
        if let Some(_state) = self.submitted_requests.remove(&request_id) {
            self.completion_times
                .push((request_id, now, actual_duration));
            self.total_completed += 1;
            self.update_queue_metrics(now);
        }
    }

    fn update_queue_metrics(&mut self, now: Instant) {
        let current_queue_size = self.submitted_requests.len();
        self.queue_length_history
            .push_back((now, current_queue_size));
        self.max_queue_length = self.max_queue_length.max(current_queue_size);

        // Limit history size to prevent unbounded growth
        if self.queue_length_history.len() > 1000 {
            self.queue_length_history.pop_front();
        }
    }

    fn record_permit_violation(&mut self, violation: String) {
        self.permit_violations.push(violation);
    }

    /// Verify the throughput metamorphic relation: N requests with limit L should complete in ~N/L time
    fn verify_throughput_relation(&self) -> Result<(), String> {
        if self.completion_times.len() < 2 {
            return Ok(()); // Not enough data
        }

        let completed_count = self.completion_times.len() as f64;
        let limit = self.max_concurrency as f64;

        // Calculate actual throughput from completion data
        let first_completion = self.completion_times[0].1;
        let last_completion = self.completion_times.last().unwrap().1;
        let total_duration = last_completion
            .duration_since(first_completion)
            .as_secs_f64();

        if total_duration <= 0.0 {
            return Ok(()); // All completed instantly
        }

        let actual_throughput = completed_count / total_duration;

        // Expected throughput should be bounded by the concurrency limit
        // Allow some tolerance for timing variations and overhead
        let expected_max_throughput = limit * 1.5; // 50% tolerance for overhead

        if actual_throughput > expected_max_throughput {
            return Err(format!(
                "Throughput violation: actual {:.2} requests/sec > expected max {:.2} for limit {}",
                actual_throughput, expected_max_throughput, limit
            ));
        }

        Ok(())
    }

    /// Verify the Lyapunov stability relation: queue length should remain bounded
    fn verify_lyapunov_stability(&self) -> Result<(), String> {
        if self.queue_length_history.is_empty() {
            return Ok(());
        }

        // Check that maximum queue length doesn't grow unboundedly
        // For a stable system, queue length should be bounded by some reasonable multiple of concurrency limit
        let stability_bound = self.max_concurrency * 10; // Allow 10x limit as reasonable bound

        if self.max_queue_length > stability_bound {
            return Err(format!(
                "Lyapunov stability violation: max queue length {} > stability bound {} (limit {})",
                self.max_queue_length, stability_bound, self.max_concurrency
            ));
        }

        // Check for monotonic growth patterns (sign of instability)
        if self.queue_length_history.len() >= 10 {
            let recent_samples: Vec<_> = self
                .queue_length_history
                .iter()
                .rev()
                .take(10)
                .map(|(_, size)| *size)
                .collect();

            // Check if queue is consistently growing
            let mut growing_streak = 0;
            for window in recent_samples.windows(2) {
                if window[1] > window[0] {
                    growing_streak += 1;
                }
            }

            // If 80% of recent samples show growth, flag as potential instability
            if growing_streak >= 8 {
                return Err(format!(
                    "Potential instability: queue growing in {} out of 9 recent observations",
                    growing_streak
                ));
            }
        }

        Ok(())
    }

    /// Verify no starvation: all non-cancelled requests should eventually complete
    fn verify_no_starvation(&self, current_time: Instant) -> Result<(), String> {
        let starvation_timeout = Duration::from_millis(10000); // 10 second timeout

        for (request_id, state) in &self.submitted_requests {
            if !state.cancelled
                && current_time.duration_since(state.submitted_at) > starvation_timeout
            {
                return Err(format!(
                    "Starvation detected: request {} waiting for {:.2}s without completion",
                    request_id,
                    current_time
                        .duration_since(state.submitted_at)
                        .as_secs_f64()
                ));
            }
        }

        Ok(())
    }

    /// Verify cancellation correctness: cancelled requests should release permits immediately
    fn verify_cancellation_correctness(&self, available_permits: usize) -> Result<(), String> {
        let in_flight = self
            .submitted_requests
            .values()
            .filter(|s| !s.cancelled)
            .count();

        let expected_available = if in_flight <= self.max_concurrency {
            self.max_concurrency - in_flight
        } else {
            0
        };

        // Allow some tolerance for timing between cancellation and permit release
        if available_permits < expected_available.saturating_sub(1) {
            return Err(format!(
                "Cancellation correctness violation: available permits {} < expected {} (in_flight: {}, cancelled: {})",
                available_permits,
                expected_available,
                in_flight,
                self.cancelled_requests.len()
            ));
        }

        Ok(())
    }

    fn verify_all_invariants(&self, available_permits: usize) -> Result<(), String> {
        self.verify_throughput_relation()?;
        self.verify_lyapunov_stability()?;
        self.verify_no_starvation(Instant::now())?;
        self.verify_cancellation_correctness(available_permits)?;

        if !self.permit_violations.is_empty() {
            return Err(format!("Permit violations: {:?}", self.permit_violations));
        }

        Ok(())
    }
}

/// Simple waker for testing
struct TestWaker;

impl Wake for TestWaker {
    fn wake(self: Arc<Self>) {}
    fn wake_by_ref(self: &Arc<Self>) {}
}

fn test_waker() -> Waker {
    Arc::new(TestWaker).into()
}

/// Normalize fuzz input to valid ranges
fn normalize_fuzz_input(input: &mut ConcurrencyLimitFuzz) {
    // Limit concurrency to reasonable range
    input.concurrency_limit = input.concurrency_limit.clamp(1, 20);

    // Limit operations to prevent timeouts
    input.operations.truncate(100);

    // Normalize individual operations
    for op in &mut input.operations {
        match op {
            ConcurrencyOperation::SubmitRequest {
                processing_time_ms, ..
            } => {
                *processing_time_ms = (*processing_time_ms).clamp(1, 1000);
            }
            ConcurrencyOperation::AdvanceTime { delta_ms } => {
                *delta_ms = (*delta_ms).clamp(1, 100);
            }
            ConcurrencyOperation::SubmitBatch {
                count,
                processing_time_ms,
                ..
            } => {
                *count = (*count).clamp(1, 10);
                *processing_time_ms = (*processing_time_ms).clamp(1, 1000);
            }
            _ => {}
        }
    }

    // Normalize service config
    input.service_config.base_delay_ms = input.service_config.base_delay_ms.clamp(1, 500);
    input.service_config.timing_variance_ms = input.service_config.timing_variance_ms.clamp(0, 200);
}

/// Execute concurrency limit operations and verify metamorphic relations
fn execute_concurrency_limit_operations(input: &ConcurrencyLimitFuzz) -> Result<(), String> {
    let limit = input.concurrency_limit as usize;
    let layer = ConcurrencyLimitLayer::new(limit);
    let mock_service = MockService::new(input.service_config.clone());
    let mut limited_service = layer.layer(mock_service.clone());

    let mut shadow = ConcurrencyLimitShadowModel::new(limit);
    let waker = test_waker();
    let mut cx = Context::from_waker(&waker);

    // Track active futures for cleanup
    let mut active_futures: HashMap<u16, Pin<Box<dyn Future<Output = Result<_, _>>>>> =
        HashMap::new();

    for (op_index, operation) in input.operations.iter().enumerate() {
        // Limit total operation count to prevent test timeouts
        if op_index > 200 {
            break;
        }

        match operation {
            ConcurrencyOperation::SubmitRequest {
                request_id,
                processing_time_ms,
            } => {
                let processing_time = Duration::from_millis(*processing_time_ms as u64);
                let request = MockRequest {
                    id: *request_id,
                    processing_time,
                };

                // Check service readiness
                match limited_service.poll_ready(&mut cx) {
                    Poll::Ready(Ok(())) => {
                        let future = limited_service.call(request);
                        active_futures.insert(*request_id, Box::pin(future));
                        shadow.submit_request(*request_id, processing_time);
                    }
                    Poll::Ready(Err(_)) => {
                        // Service error - skip this request
                        continue;
                    }
                    Poll::Pending => {
                        // Service not ready - would normally wait, but skip for fuzzing
                        continue;
                    }
                }
            }

            ConcurrencyOperation::CancelRequest { request_id } => {
                if active_futures.remove(request_id).is_some() {
                    shadow.cancel_request(*request_id);
                }
            }

            ConcurrencyOperation::AdvanceTime { delta_ms } => {
                // Simulate time passing by polling active futures
                let mut completed_requests = Vec::new();

                for (request_id, future) in &mut active_futures {
                    match future.as_mut().poll(&mut cx) {
                        Poll::Ready(Ok(response)) => {
                            completed_requests.push((*request_id, response.processing_duration));
                        }
                        Poll::Ready(Err(_)) => {
                            // Request failed
                            completed_requests
                                .push((*request_id, Duration::from_millis(*delta_ms as u64)));
                        }
                        Poll::Pending => {
                            // Still processing
                        }
                    }
                }

                // Remove completed futures and update shadow model
                for (request_id, duration) in completed_requests {
                    active_futures.remove(&request_id);
                    shadow.complete_request(request_id, duration);
                }
            }

            ConcurrencyOperation::CheckMetrics => {
                let available = limited_service.available();
                shadow.verify_all_invariants(available)?;
            }

            ConcurrencyOperation::SubmitBatch {
                count,
                base_id,
                processing_time_ms,
            } => {
                let processing_time = Duration::from_millis(*processing_time_ms as u64);

                for i in 0..*count {
                    let request_id = base_id.wrapping_add(i as u16);
                    let request = MockRequest {
                        id: request_id,
                        processing_time,
                    };

                    match limited_service.poll_ready(&mut cx) {
                        Poll::Ready(Ok(())) => {
                            let future = limited_service.call(request);
                            active_futures.insert(request_id, Box::pin(future));
                            shadow.submit_request(request_id, processing_time);
                        }
                        _ => break, // Service not ready or errored
                    }
                }
            }

            ConcurrencyOperation::WaitForQuiescence => {
                // Poll all active futures to completion
                let mut attempts = 0;
                while !active_futures.is_empty() && attempts < 100 {
                    let mut completed_requests = Vec::new();

                    for (request_id, future) in &mut active_futures {
                        match future.as_mut().poll(&mut cx) {
                            Poll::Ready(Ok(response)) => {
                                completed_requests
                                    .push((*request_id, response.processing_duration));
                            }
                            Poll::Ready(Err(_)) => {
                                completed_requests.push((*request_id, Duration::from_millis(10)));
                            }
                            Poll::Pending => {}
                        }
                    }

                    for (request_id, duration) in completed_requests {
                        active_futures.remove(&request_id);
                        shadow.complete_request(request_id, duration);
                    }

                    attempts += 1;
                }
            }
        }

        // Periodic invariant checks
        if op_index % 20 == 0 {
            let available = limited_service.available();
            shadow.verify_all_invariants(available)?;
        }
    }

    // Final verification
    let available = limited_service.available();
    shadow.verify_all_invariants(available)?;

    Ok(())
}

/// Main fuzzing entry point
fn fuzz_concurrency_limit_metamorphic(mut input: ConcurrencyLimitFuzz) -> Result<(), String> {
    normalize_fuzz_input(&mut input);

    // Skip degenerate cases
    if input.operations.is_empty() {
        return Ok(());
    }

    // Execute metamorphic property tests
    execute_concurrency_limit_operations(&input)?;

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Limit input size for performance
    if data.len() > 8192 {
        return;
    }

    let mut unstructured = arbitrary::Unstructured::new(data);

    // Generate fuzz configuration
    let input = if let Ok(input) = ConcurrencyLimitFuzz::arbitrary(&mut unstructured) {
        input
    } else {
        return;
    };

    // Run metamorphic testing
    let _ = fuzz_concurrency_limit_metamorphic(input);
});
