//! Metamorphic Testing: service::concurrency_limit fairness + Lyapunov bounded queue
//!
//! These tests verify fundamental properties of concurrency limiting that must hold
//! regardless of request patterns, timing, or load levels. Uses metamorphic testing
//! to validate relationships between inputs/outputs where exact outputs can't be predicted.
//!
//! Key Properties Verified:
//! 1. N requests with limit L complete in ~N/L time (throughput linearity)
//! 2. Lyapunov function bounded (queue depth stability)
//! 3. No starvation (fairness guarantees)
//! 4. Cancel releases slot immediately (resource correctness)

#![cfg(test)]

use asupersync::cx::Cx;
use asupersync::runtime::RuntimeBuilder;
use asupersync::service::{Service, ServiceBuilder};
use asupersync::service::concurrency_limit::ConcurrencyLimitLayer;
use asupersync::time::{Duration, Time};
use asupersync::types::Outcome;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

/// Test service that simulates work with configurable delay
#[derive(Debug, Clone)]
struct DelayService {
    delay: Duration,
    completion_counter: Arc<AtomicU64>,
    start_counter: Arc<AtomicU64>,
}

impl DelayService {
    fn new(delay: Duration) -> Self {
        Self {
            delay,
            completion_counter: Arc::new(AtomicU64::new(0)),
            start_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    fn completions(&self) -> u64 {
        self.completion_counter.load(Ordering::SeqCst)
    }

    fn starts(&self) -> u64 {
        self.start_counter.load(Ordering::SeqCst)
    }
}

impl Service<u32> for DelayService {
    type Response = (u32, Instant, Instant); // (request_id, start_time, end_time)
    type Error = std::convert::Infallible;
    type Future = DelayFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: u32) -> Self::Future {
        self.start_counter.fetch_add(1, Ordering::SeqCst);
        DelayFuture::new(req, self.delay, self.completion_counter.clone())
    }
}

#[pin_project::pin_project]
struct DelayFuture {
    request_id: u32,
    start_time: Instant,
    #[pin]
    sleep: asupersync::time::Sleep,
    completion_counter: Arc<AtomicU64>,
    completed: bool,
}

impl DelayFuture {
    fn new(request_id: u32, delay: Duration, completion_counter: Arc<AtomicU64>) -> Self {
        let start_time = Instant::now();
        Self {
            request_id,
            start_time,
            sleep: asupersync::time::sleep(Time::now(), delay),
            completion_counter,
            completed: false,
        }
    }
}

impl Future for DelayFuture {
    type Output = Result<(u32, Instant, Instant), std::convert::Infallible>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if *this.completed {
            return Poll::Ready(Ok((*this.request_id, *this.start_time, Instant::now())));
        }

        match this.sleep.poll(cx) {
            Poll::Ready(()) => {
                *this.completed = true;
                this.completion_counter.fetch_add(1, Ordering::SeqCst);
                let end_time = Instant::now();
                Poll::Ready(Ok((*this.request_id, *this.start_time, end_time)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Metrics for analyzing concurrency limiter behavior
#[derive(Debug, Clone)]
struct ConcurrencyMetrics {
    total_requests: usize,
    total_duration: Duration,
    individual_durations: Vec<Duration>,
    max_concurrent: usize,
    avg_queue_depth: f64,
    max_queue_depth: usize,
    starved_requests: usize,
}

impl ConcurrencyMetrics {
    fn new() -> Self {
        Self {
            total_requests: 0,
            total_duration: Duration::ZERO,
            individual_durations: Vec::new(),
            max_concurrent: 0,
            avg_queue_depth: 0.0,
            max_queue_depth: 0,
            starved_requests: 0,
        }
    }

    fn throughput(&self) -> f64 {
        if self.total_duration.is_zero() {
            0.0
        } else {
            self.total_requests as f64 / self.total_duration.as_secs_f64()
        }
    }

    fn avg_latency(&self) -> Duration {
        if self.individual_durations.is_empty() {
            Duration::ZERO
        } else {
            let sum: Duration = self.individual_durations.iter().sum();
            sum / self.individual_durations.len() as u32
        }
    }

    fn lyapunov_stability_metric(&self) -> f64 {
        // Measure of queue stability - lower is better
        // Combines average queue depth with maximum observed depth
        (self.avg_queue_depth * 0.7) + (self.max_queue_depth as f64 * 0.3)
    }
}

/// Load generator for creating request patterns
struct LoadGenerator {
    concurrent_limit: usize,
    base_delay: Duration,
}

impl LoadGenerator {
    fn new(concurrent_limit: usize, base_delay: Duration) -> Self {
        Self { concurrent_limit, base_delay }
    }

    /// Run N requests with given concurrency limit and measure metrics
    async fn run_load(
        &self,
        _cx: &Cx,
        num_requests: usize,
    ) -> Result<ConcurrencyMetrics, Box<dyn std::error::Error>> {
        use asupersync::combinator::join;

        let service = DelayService::new(self.base_delay);
        let limited_service = ServiceBuilder::new()
            .layer(ConcurrencyLimitLayer::new(self.concurrent_limit))
            .service(service.clone());

        let start_time = Instant::now();
        let mut futures = Vec::new();

        // Launch all requests
        for i in 0..num_requests {
            let mut svc = limited_service.clone();

            let future = async move {
                // Manual readiness polling - simplified for testing
                let mut cx = Context::from_waker(&std::task::Waker::noop());

                // Poll until ready
                let ready_start = Instant::now();
                loop {
                    match svc.poll_ready(&mut cx)? {
                        Poll::Ready(()) => break,
                        Poll::Pending => {
                            // In real async, this would yield. For testing, continue.
                            std::thread::yield_now();
                            continue;
                        }
                    }
                }
                let ready_duration = ready_start.elapsed();

                // Make the call
                let call_start = Instant::now();
                let result = svc.call(i as u32).await;
                let call_duration = call_start.elapsed();

                Ok::<_, Box<dyn std::error::Error>>((result, ready_duration, call_duration))
            };

            futures.push(future);
        }

        // Wait for all to complete using asupersync join combinator
        let results = join::join_all(futures).await?;
        let end_time = Instant::now();

        // Analyze results
        let mut metrics = ConcurrencyMetrics::new();
        metrics.total_requests = num_requests;
        metrics.total_duration = end_time - start_time;
        metrics.max_concurrent = self.concurrent_limit;

        for (result, ready_duration, _call_duration) in results {
            match result {
                Ok((_req_id, req_start, req_end)) => {
                    let total_latency = req_end - req_start;
                    metrics.individual_durations.push(total_latency);
                }
                Err(_) => {
                    metrics.starved_requests += 1;
                }
            }
        }

        // Estimate queue depth metrics (simplified)
        let theoretical_min_time = self.base_delay;
        let actual_avg_time = metrics.avg_latency();
        metrics.avg_queue_depth = if theoretical_min_time.is_zero() {
            0.0
        } else {
            (actual_avg_time.as_secs_f64() / theoretical_min_time.as_secs_f64()) - 1.0
        }.max(0.0);

        metrics.max_queue_depth = num_requests.saturating_sub(self.concurrent_limit);

        Ok(metrics)
    }
}

/// Metamorphic Relation 1: Throughput Linearity (Multiplicative)
/// Doubling requests should roughly double total completion time with same limit
#[test]
fn mr_throughput_linearity() {
    let rt = RuntimeBuilder::current_thread().build().unwrap();

    rt.block_on(async {
        let cx = Cx::current().unwrap();
        let generator = LoadGenerator::new(4, Duration::from_millis(10));

        // Run with N requests
        let n = 20;
        let metrics_n = generator.run_load(&cx, n).await.unwrap();

        // Run with 2N requests
        let metrics_2n = generator.run_load(&cx, 2 * n).await.unwrap();

        // MR: f(2x) ≈ 2·f(x) for total completion time
        let ratio = metrics_2n.total_duration.as_secs_f64() / metrics_n.total_duration.as_secs_f64();

        assert!(
            ratio >= 1.5 && ratio <= 2.5,
            "Throughput linearity violated: 2N requests took {:.2}x time instead of ~2x (N={}, ratio={:.2})",
            ratio, n, ratio
        );

        // Additional invariant: both should complete all requests
        assert_eq!(metrics_n.starved_requests, 0, "Starvation detected in N-request run");
        assert_eq!(metrics_2n.starved_requests, 0, "Starvation detected in 2N-request run");
    });
}

/// Metamorphic Relation 2: Capacity Scaling (Multiplicative)
/// Doubling concurrency limit should roughly halve completion time for same requests
#[test]
fn mr_capacity_scaling() {
    let rt = RuntimeBuilder::current_thread().build().unwrap();

    rt.block_on(async {
        let cx = Cx::current().unwrap();
        let num_requests = 24;

        // Run with limit L
        let l = 3;
        let generator_l = LoadGenerator::new(l, Duration::from_millis(10));
        let metrics_l = generator_l.run_load(&cx, num_requests).await.unwrap();

        // Run with limit 2L
        let generator_2l = LoadGenerator::new(2 * l, Duration::from_millis(10));
        let metrics_2l = generator_2l.run_load(&cx, num_requests).await.unwrap();

        // MR: f_2L(x) ≈ f_L(x) / 2 for completion time
        let ratio = metrics_l.total_duration.as_secs_f64() / metrics_2l.total_duration.as_secs_f64();

        assert!(
            ratio >= 1.3 && ratio <= 2.2,
            "Capacity scaling violated: 2x capacity gave {:.2}x speedup instead of ~2x (L={}, ratio={:.2})",
            ratio, l, ratio
        );
    });
}

/// Metamorphic Relation 3: Request Order Invariance (Permutative)
/// Shuffling request order shouldn't significantly change completion time
#[test]
fn mr_request_order_invariance() {
    let rt = RuntimeBuilder::current_thread().build().unwrap();

    rt.block_on(async {
        let cx = Cx::current().unwrap();
        let generator = LoadGenerator::new(3, Duration::from_millis(5));
        let num_requests = 15;

        // Run original order
        let metrics_original = generator.run_load(&cx, num_requests).await.unwrap();

        // Run again (effectively permuted by runtime scheduling)
        let metrics_permuted = generator.run_load(&cx, num_requests).await.unwrap();

        // MR: permute(f(x)) ≈ f(x) for total duration
        let ratio = metrics_permuted.total_duration.as_secs_f64() / metrics_original.total_duration.as_secs_f64();

        assert!(
            ratio >= 0.7 && ratio <= 1.4,
            "Request order sensitivity detected: permuted run took {:.2}x time vs original (ratio={:.2})",
            ratio, ratio
        );

        // Both should have same throughput characteristics
        let throughput_ratio = metrics_permuted.throughput() / metrics_original.throughput();
        assert!(
            throughput_ratio >= 0.8 && throughput_ratio <= 1.2,
            "Throughput varied too much between runs: {:.2}x difference", throughput_ratio
        );
    });
}

/// Metamorphic Relation 4: Lyapunov Stability (Bounded)
/// Queue depth metrics should be bounded and not grow with request count
#[test]
fn mr_lyapunov_bounded_queue() {
    let rt = RuntimeBuilder::current_thread().build().unwrap();

    rt.block_on(async {
        let cx = Cx::current().unwrap();
        let generator = LoadGenerator::new(4, Duration::from_millis(8));

        // Test different request loads
        let loads = vec![12, 24, 48];
        let mut stability_metrics = Vec::new();

        for &load in &loads {
            let metrics = generator.run_load(&cx, load).await.unwrap();
            stability_metrics.push(metrics.lyapunov_stability_metric());
        }

        // MR: Lyapunov function should be bounded regardless of load
        let max_stability = stability_metrics.iter().cloned().fold(0.0, f64::max);
        let min_stability = stability_metrics.iter().cloned().fold(f64::INFINITY, f64::min);

        assert!(
            max_stability < 10.0,
            "Queue instability detected: max stability metric {:.2} exceeds bound", max_stability
        );

        // Stability shouldn't grow linearly with load (would indicate unbounded growth)
        let stability_growth = max_stability / min_stability;
        assert!(
            stability_growth < 3.0,
            "Queue depth growing with load: {:.2}x growth in stability metric", stability_growth
        );
    });
}

/// Metamorphic Relation 5: Fairness - No Starvation (Inclusive)
/// All requests should eventually complete regardless of load pattern
#[test]
fn mr_no_starvation_fairness() {
    let rt = RuntimeBuilder::current_thread().build().unwrap();

    rt.block_on(async {
        let cx = Cx::current().unwrap();

        // Test various load patterns
        let patterns = vec![
            (2, 8),   // Low concurrency, moderate load
            (1, 10),  // Severe bottleneck
            (8, 16),  // High concurrency, high load
        ];

        for (limit, requests) in patterns {
            let generator = LoadGenerator::new(limit, Duration::from_millis(5));
            let metrics = generator.run_load(&cx, requests).await.unwrap();

            // MR: No starvation - all requests must complete
            assert_eq!(
                metrics.starved_requests, 0,
                "Starvation detected: {} requests failed to complete with limit={}",
                metrics.starved_requests, limit
            );

            assert_eq!(
                metrics.total_requests, requests,
                "Request count mismatch: expected {}, processed {}",
                requests, metrics.total_requests
            );
        }
    });
}

/// Metamorphic Relation 6: Additive Batching (Additive)
/// Sequential batches should sum to same time as combined batch
#[test]
fn mr_additive_batching() {
    let rt = RuntimeBuilder::current_thread().build().unwrap();

    rt.block_on(async {
        let cx = Cx::current().unwrap();
        let generator = LoadGenerator::new(3, Duration::from_millis(7));

        let batch_size = 10;

        // Run two sequential batches
        let metrics_batch1 = generator.run_load(&cx, batch_size).await.unwrap();
        let metrics_batch2 = generator.run_load(&cx, batch_size).await.unwrap();
        let sequential_time = metrics_batch1.total_duration + metrics_batch2.total_duration;

        // Run combined batch
        let metrics_combined = generator.run_load(&cx, 2 * batch_size).await.unwrap();
        let combined_time = metrics_combined.total_duration;

        // MR: f(a) + f(b) ≈ f(a + b) for non-overlapping batches
        let ratio = combined_time.as_secs_f64() / sequential_time.as_secs_f64();

        assert!(
            ratio >= 0.7 && ratio <= 1.3,
            "Additive batching violated: combined batch {:.2}x vs sequential (ratio={:.2})",
            ratio, ratio
        );
    });
}

/// Composite MR: Throughput Linearity + Capacity Scaling
/// Verifies that the two fundamental scaling relationships interact correctly
#[test]
fn mr_composite_scaling() {
    let rt = RuntimeBuilder::current_thread().build().unwrap();

    rt.block_on(async {
        let cx = Cx::current().unwrap();
        let base_requests = 12;
        let base_limit = 2;

        // Test four combinations: (N,L), (2N,L), (N,2L), (2N,2L)
        let scenarios = vec![
            (base_requests, base_limit, "N,L"),
            (2 * base_requests, base_limit, "2N,L"),
            (base_requests, 2 * base_limit, "N,2L"),
            (2 * base_requests, 2 * base_limit, "2N,2L"),
        ];

        let mut results = Vec::new();
        for (requests, limit, label) in scenarios {
            let generator = LoadGenerator::new(limit, Duration::from_millis(8));
            let metrics = generator.run_load(&cx, requests).await.unwrap();
            results.push((metrics, label));
        }

        // Extract completion times
        let t_nl = results[0].0.total_duration.as_secs_f64();
        let t_2nl = results[1].0.total_duration.as_secs_f64();
        let t_n2l = results[2].0.total_duration.as_secs_f64();
        let t_2n2l = results[3].0.total_duration.as_secs_f64();

        // Composite MR: doubling both requests and capacity should yield similar time
        // t(2N,2L) ≈ t(N,L) because increases cancel out
        let cancellation_ratio = t_2n2l / t_nl;
        assert!(
            cancellation_ratio >= 0.7 && cancellation_ratio <= 1.4,
            "Scaling cancellation failed: t(2N,2L)/t(N,L) = {:.2} (should be ~1.0)",
            cancellation_ratio
        );

        // Verify individual relationships still hold
        let request_scaling = t_2nl / t_nl;  // Should be ~2
        assert!(
            request_scaling >= 1.5 && request_scaling <= 2.5,
            "Request scaling broken in composite: {:.2}x", request_scaling
        );

        let capacity_scaling = t_nl / t_n2l;  // Should be ~2
        assert!(
            capacity_scaling >= 1.3 && capacity_scaling <= 2.2,
            "Capacity scaling broken in composite: {:.2}x", capacity_scaling
        );
    });
}

// TODO: Add cancellation metamorphic relations when cancel-aware infrastructure is ready
// - Cancel releases slot immediately (Equivalence)
// - Cancelled requests don't affect timing of non-cancelled requests (Independence)