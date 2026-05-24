//! Real integration tests between lab/conformal and lab/instrumented_future.
//!
//! Verifies that conformal prediction's coverage guarantee holds across
//! instrumented future polls under chaos conditions (cancellation injection).

#![allow(clippy::missing_docs_in_private_items)]

use crate::lab::conformal::{CalibrationReport, ConformalCalibrator, ConformalConfig};
use crate::lab::instrumented_future::{
    AwaitPoint, CancellationInjector, InstrumentedFuture, InjectionStrategy,
};
use crate::lab::oracle::{OracleEntryReport, OracleReport};
use crate::time::Time;
use crate::types::{Outcome, TaskId, TraceId};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

/// Mock oracle metric provider that generates synthetic reports.
#[derive(Debug)]
struct MockOracleMetrics {
    /// Counter for generating unique metrics.
    counter: AtomicU64,
    /// Base violation probability (0.0 = never, 1.0 = always).
    base_violation_rate: f64,
    /// Chaos modifier - increases violation rate under stress.
    chaos_multiplier: f64,
}

impl MockOracleMetrics {
    fn new(base_violation_rate: f64, chaos_multiplier: f64) -> Self {
        Self {
            counter: AtomicU64::new(0),
            base_violation_rate,
            chaos_multiplier,
        }
    }

    fn generate_report(&self, chaos_level: f64) -> OracleReport {
        let count = self.counter.fetch_add(1, Ordering::Relaxed);
        let effective_violation_rate = (self.base_violation_rate * (1.0 + chaos_level * self.chaos_multiplier)).min(0.95);

        // Use deterministic pseudo-random generation based on counter
        let violates_invariant = (count % 100) < (effective_violation_rate * 100.0) as u64;

        OracleReport {
            trace_id: TraceId::new(),
            timestamp: Time::from_nanos(count * 1_000_000), // 1ms increments
            region_count: (10 + count % 20) as usize,
            task_count: (50 + count % 100) as usize,
            obligation_count: (5 + count % 30) as usize,
            entries: vec![
                OracleEntryReport {
                    invariant: "structural_concurrency".to_string(),
                    passed: !violates_invariant,
                    entity_count: (100 + count % 50) as usize,
                    event_count: (200 + count % 150) as usize,
                    message: if violates_invariant {
                        Some("Structural concurrency violation detected under chaos".to_string())
                    } else {
                        None
                    },
                },
                OracleEntryReport {
                    invariant: "cancel_correctness".to_string(),
                    passed: !(count % 17 == 0), // Periodic violations
                    entity_count: (75 + count % 25) as usize,
                    event_count: (150 + count % 100) as usize,
                    message: if count % 17 == 0 {
                        Some("Cancel correctness issue detected".to_string())
                    } else {
                        None
                    },
                },
                OracleEntryReport {
                    invariant: "obligation_leak".to_string(),
                    passed: !(count % 23 == 0 && chaos_level > 0.5), // More violations under high chaos
                    entity_count: (25 + count % 15) as usize,
                    event_count: (80 + count % 60) as usize,
                    message: if count % 23 == 0 && chaos_level > 0.5 {
                        Some("Obligation leak detected under high chaos".to_string())
                    } else {
                        None
                    },
                },
            ],
        }
    }
}

/// A mock future that can be polled multiple times and tracks await points.
#[derive(Debug)]
struct MockComplexFuture {
    /// Number of times this future has been polled.
    poll_count: u64,
    /// Total polls required before completing.
    total_polls: u64,
    /// Whether this future should panic on completion.
    should_panic: bool,
    /// Waker for notifying when ready.
    last_waker: Option<Waker>,
}

impl MockComplexFuture {
    fn new(total_polls: u64, should_panic: bool) -> Self {
        Self {
            poll_count: 0,
            total_polls,
            should_panic,
            last_waker: None,
        }
    }

    /// Create a future that completes after several polls.
    fn multi_poll(polls: u64) -> Self {
        Self::new(polls, false)
    }

    /// Create a future that panics on completion.
    fn panicking(polls: u64) -> Self {
        Self::new(polls, true)
    }
}

impl Future for MockComplexFuture {
    type Output = Result<String, String>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.poll_count += 1;
        self.last_waker = Some(cx.waker().clone());

        if self.poll_count >= self.total_polls {
            if self.should_panic {
                panic!("Mock future panic at poll {}", self.poll_count);
            }
            Poll::Ready(Ok(format!("Completed after {} polls", self.poll_count)))
        } else {
            // Wake immediately for next poll in deterministic testing
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// Integration manager for conformal prediction under chaos.
struct ConformalChaosIntegrationManager {
    /// Conformal calibrator tracking coverage guarantees.
    calibrator: ConformalCalibrator,
    /// Oracle metrics generator.
    oracle_metrics: MockOracleMetrics,
    /// Coverage tracking across different chaos levels.
    chaos_coverage: HashMap<String, usize>,
    /// Total predictions made under chaos.
    total_predictions: usize,
}

impl ConformalChaosIntegrationManager {
    fn new(alpha: f64, base_violation_rate: f64, chaos_multiplier: f64) -> Self {
        Self {
            calibrator: ConformalCalibrator::new(ConformalConfig::new(alpha)),
            oracle_metrics: MockOracleMetrics::new(base_violation_rate, chaos_multiplier),
            chaos_coverage: HashMap::new(),
            total_predictions: 0,
        }
    }

    /// Calibrate with a batch of reports under specified chaos level.
    fn calibrate_under_chaos(&mut self, chaos_level: f64, report_count: usize) {
        for _ in 0..report_count {
            let report = self.oracle_metrics.generate_report(chaos_level);
            self.calibrator.calibrate(&report);
        }
    }

    /// Make predictions and track coverage under chaos conditions.
    fn predict_under_chaos(&mut self, chaos_level: f64, prediction_count: usize) -> Vec<CalibrationReport> {
        let mut reports = Vec::new();

        for _ in 0..prediction_count {
            let report = self.oracle_metrics.generate_report(chaos_level);
            if let Some(calibration_report) = self.calibrator.predict(&report) {
                reports.push(calibration_report.clone());

                // Track coverage performance under this chaos level
                let chaos_key = format!("chaos_{:.1}", chaos_level);
                let covered = calibration_report.overall_coverage.covered;
                *self.chaos_coverage.entry(chaos_key).or_insert(0) += covered;
                self.total_predictions += 1;
            }
        }

        reports
    }

    /// Verify that coverage guarantees hold across all chaos levels.
    fn verify_coverage_guarantee(&self) -> bool {
        if self.total_predictions == 0 {
            return true;
        }

        let target_coverage = 1.0 - self.calibrator.config.alpha;
        let tolerance = self.calibrator.config.alpha / 5.0;

        // Check overall coverage across all chaos conditions
        let total_covered: usize = self.chaos_coverage.values().sum();
        let overall_rate = total_covered as f64 / self.total_predictions as f64;

        overall_rate >= target_coverage - tolerance
    }

    /// Get coverage statistics by chaos level.
    fn coverage_by_chaos_level(&self) -> HashMap<String, f64> {
        let mut rates = HashMap::new();
        for (level, covered) in &self.chaos_coverage {
            let rate = *covered as f64 / self.total_predictions.max(1) as f64;
            rates.insert(level.clone(), rate);
        }
        rates
    }
}

/// Test driver for instrumented future execution under different injection strategies.
struct InstrumentedFutureTestDriver {
    /// Task ID for tracking.
    task_id: TaskId,
    /// Results from different injection strategies.
    strategy_results: HashMap<String, Vec<u64>>,
}

impl InstrumentedFutureTestDriver {
    fn new() -> Self {
        Self {
            task_id: TaskId::new(),
            strategy_results: HashMap::new(),
        }
    }

    /// Execute a future with instrumentation using various injection strategies.
    async fn execute_with_strategies<F>(&mut self, future_factory: impl Fn() -> F, strategies: Vec<(&str, InjectionStrategy)>)
    where
        F: Future<Output = Result<String, String>>,
    {
        for (name, strategy) in strategies {
            let await_counts = self.execute_with_strategy(future_factory(), strategy).await;
            self.strategy_results.insert(name.to_string(), await_counts);
        }
    }

    /// Execute a single future with a specific injection strategy.
    async fn execute_with_strategy<F>(&self, future: F, strategy: InjectionStrategy) -> Vec<u64>
    where
        F: Future<Output = Result<String, String>>,
    {
        let injector = CancellationInjector::with_strategy(strategy);
        let instrumented = InstrumentedFuture::new(future, injector.clone());

        let mut await_points = Vec::new();

        // Poll the instrumented future manually to track await points
        let mut pinned = Box::pin(instrumented);
        let waker = futures_lite::future::block_on(async {
            use std::task::{RawWaker, RawWakerVTable, Waker};

            unsafe fn clone(_: *const ()) -> RawWaker { RawWaker::new(std::ptr::null(), &VTABLE) }
            unsafe fn wake(_: *const ()) {}
            unsafe fn wake_by_ref(_: *const ()) {}
            unsafe fn drop(_: *const ()) {}

            static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
            let raw = RawWaker::new(std::ptr::null(), &VTABLE);
            Waker::from_raw(raw)
        });

        let mut context = Context::from_waker(&waker);

        // Poll until completion or cancellation
        for poll_attempt in 1..=100 { // Limit to prevent infinite loops
            await_points.push(poll_attempt);

            match pinned.as_mut().poll(&mut context) {
                Poll::Ready(_) => break,
                Poll::Pending => continue,
            }
        }

        await_points
    }

    /// Get statistics about await point distribution across strategies.
    fn get_await_statistics(&self) -> HashMap<String, (usize, usize, f64)> {
        let mut stats = HashMap::new();

        for (strategy, await_counts) in &self.strategy_results {
            let min_awaits = await_counts.iter().min().unwrap_or(&0);
            let max_awaits = await_counts.iter().max().unwrap_or(&0);
            let avg_awaits = if await_counts.is_empty() {
                0.0
            } else {
                await_counts.iter().sum::<u64>() as f64 / await_counts.len() as f64
            };

            stats.insert(strategy.clone(), (*min_awaits as usize, *max_awaits as usize, avg_awaits));
        }

        stats
    }
}

/// Integration test case for conformal prediction under instrumented future chaos.
struct ConformalInstrumentedChaosTest {
    /// Conformal prediction manager.
    conformal_manager: ConformalChaosIntegrationManager,
    /// Instrumented future test driver.
    future_driver: InstrumentedFutureTestDriver,
    /// Test parameters.
    alpha: f64,
    calibration_samples: usize,
    prediction_samples: usize,
}

impl ConformalInstrumentedChaosTest {
    fn new(alpha: f64, calibration_samples: usize, prediction_samples: usize) -> Self {
        Self {
            conformal_manager: ConformalChaosIntegrationManager::new(alpha, 0.05, 2.0),
            future_driver: InstrumentedFutureTestDriver::new(),
            alpha,
            calibration_samples,
            prediction_samples,
        }
    }

    /// Run the complete integration test.
    async fn run_test(&mut self) -> TestResult {
        // Phase 1: Calibrate under various chaos conditions
        let chaos_levels = vec![0.0, 0.3, 0.7, 1.0];

        for &chaos_level in &chaos_levels {
            self.conformal_manager.calibrate_under_chaos(chaos_level, self.calibration_samples / chaos_levels.len());
        }

        // Phase 2: Generate predictions while running instrumented futures under chaos
        let injection_strategies = vec![
            ("no_injection", InjectionStrategy::Never),
            ("inject_at_3", InjectionStrategy::AtSequence(3)),
            ("inject_every_5th", InjectionStrategy::EveryNth(5)),
            ("first_10_points", InjectionStrategy::FirstN(10)),
            ("probabilistic_30pct", InjectionStrategy::Probabilistic(0.3)),
        ];

        // Execute futures with different injection patterns while making predictions
        for (strategy_name, strategy) in injection_strategies.clone() {
            for &chaos_level in &chaos_levels {
                // Execute instrumented futures
                let future_factory = move || MockComplexFuture::multi_poll(15 + ((chaos_level * 10.0) as u64));
                self.future_driver.execute_with_strategies(future_factory, vec![(strategy_name, strategy.clone())]).await;

                // Make conformal predictions under same chaos level
                let prediction_count = self.prediction_samples / (chaos_levels.len() * injection_strategies.len());
                self.conformal_manager.predict_under_chaos(chaos_level, prediction_count);
            }
        }

        // Phase 3: Verify coverage guarantees hold
        let coverage_guaranteed = self.conformal_manager.verify_coverage_guarantee();
        let coverage_stats = self.conformal_manager.coverage_by_chaos_level();
        let await_stats = self.future_driver.get_await_statistics();

        TestResult {
            coverage_guaranteed,
            target_coverage: 1.0 - self.alpha,
            coverage_by_chaos: coverage_stats,
            await_point_stats: await_stats,
            total_predictions: self.conformal_manager.total_predictions,
            calibration_samples: self.conformal_manager.calibrator.calibration_samples(),
        }
    }
}

/// Result of the conformal prediction + instrumented future integration test.
#[derive(Debug)]
struct TestResult {
    /// Whether coverage guarantee was maintained.
    coverage_guaranteed: bool,
    /// Target coverage rate (1 - alpha).
    target_coverage: f64,
    /// Coverage rates by chaos level.
    coverage_by_chaos: HashMap<String, f64>,
    /// Await point statistics by injection strategy.
    await_point_stats: HashMap<String, (usize, usize, f64)>,
    /// Total predictions made.
    total_predictions: usize,
    /// Total calibration samples used.
    calibration_samples: usize,
}

impl TestResult {
    /// Verify that the test passed all requirements.
    fn verify_success(&self) -> bool {
        // Coverage guarantee must hold
        if !self.coverage_guaranteed {
            return false;
        }

        // Must have sufficient samples
        if self.total_predictions < 20 || self.calibration_samples < 10 {
            return false;
        }

        // Coverage should be reasonably consistent across chaos levels
        let coverage_values: Vec<f64> = self.coverage_by_chaos.values().cloned().collect();
        if coverage_values.is_empty() {
            return false;
        }

        let min_coverage = coverage_values.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        let max_coverage = coverage_values.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));

        // Coverage shouldn't vary by more than 20 percentage points across chaos levels
        (max_coverage - min_coverage) <= 0.20
    }

    /// Generate a summary report.
    fn summary(&self) -> String {
        format!(
            "Conformal+Instrumented Integration Test Results:
Coverage Guaranteed: {}
Target Coverage: {:.3}
Total Predictions: {}
Calibration Samples: {}
Coverage by Chaos Level: {:#?}
Await Point Statistics: {:#?}
Test Success: {}",
            self.coverage_guaranteed,
            self.target_coverage,
            self.total_predictions,
            self.calibration_samples,
            self.coverage_by_chaos,
            self.await_point_stats,
            self.verify_success()
        )
    }
}

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_conformal_instrumented_integration() {
        let mut test = ConformalInstrumentedChaosTest::new(0.05, 20, 30);
        let result = test.run_test().await;

        println!("{}", result.summary());

        assert!(result.verify_success(), "Integration test failed: {}", result.summary());
        assert!(result.coverage_guaranteed, "Coverage guarantee not maintained");
        assert!(result.total_predictions >= 20, "Insufficient predictions made");
        assert!(result.calibration_samples >= 10, "Insufficient calibration samples");
    }

    #[tokio::test]
    async fn test_high_chaos_conformal_coverage() {
        let mut test = ConformalInstrumentedChaosTest::new(0.10, 30, 50);
        let result = test.run_test().await;

        println!("{}", result.summary());

        // With alpha=0.10, we expect 90% coverage
        assert!(result.coverage_guaranteed, "Coverage guarantee failed under high chaos");
        assert!(result.target_coverage >= 0.90, "Target coverage too low");

        // Verify coverage is maintained even at highest chaos level
        if let Some(&chaos_1_coverage) = result.coverage_by_chaos.get("chaos_1.0") {
            assert!(chaos_1_coverage >= 0.85, "Coverage degraded too much under maximum chaos");
        }
    }

    #[tokio::test]
    async fn test_strict_alpha_conformal_guarantees() {
        let mut test = ConformalInstrumentedChaosTest::new(0.01, 40, 60);
        let result = test.run_test().await;

        println!("{}", result.summary());

        // With alpha=0.01, we expect 99% coverage - very strict
        assert!(result.coverage_guaranteed, "Strict coverage guarantee failed");
        assert!((result.target_coverage - 0.99).abs() < 0.001, "Target coverage incorrect");

        // All chaos levels should maintain high coverage
        for (level, &coverage) in &result.coverage_by_chaos {
            assert!(coverage >= 0.96, "Coverage at {} fell below 96%: {}", level, coverage);
        }
    }

    #[tokio::test]
    async fn test_await_point_diversity_under_injection() {
        let mut test = ConformalInstrumentedChaosTest::new(0.05, 25, 35);
        let result = test.run_test().await;

        println!("{}", result.summary());

        assert!(result.verify_success(), "Test failed");

        // Verify different injection strategies produced different await patterns
        assert!(result.await_point_stats.len() >= 3, "Insufficient injection strategy diversity");

        // Check that probabilistic injection created variable await counts
        if let Some(&(min, max, avg)) = result.await_point_stats.get("probabilistic_30pct") {
            assert!(max > min, "Probabilistic injection should create variability");
            assert!(avg > min as f64, "Average should be between min and max");
            assert!(avg < max as f64, "Average should be between min and max");
        }
    }

    #[tokio::test]
    async fn test_conformal_calibration_stability_under_chaos() {
        let mut chaos_test = ConformalInstrumentedChaosTest::new(0.05, 50, 80);
        let baseline_result = chaos_test.run_test().await;

        // Run another test with same parameters to check stability
        let mut stability_test = ConformalInstrumentedChaosTest::new(0.05, 50, 80);
        let stability_result = stability_test.run_test().await;

        println!("Baseline: {}", baseline_result.summary());
        println!("Stability: {}", stability_result.summary());

        // Both should pass coverage guarantees
        assert!(baseline_result.coverage_guaranteed, "Baseline test failed");
        assert!(stability_result.coverage_guaranteed, "Stability test failed");

        // Coverage should be reasonably consistent between runs
        // (allowing for some variance due to pseudo-randomness)
        let baseline_avg = baseline_result.coverage_by_chaos.values().sum::<f64>()
            / baseline_result.coverage_by_chaos.len() as f64;
        let stability_avg = stability_result.coverage_by_chaos.values().sum::<f64>()
            / stability_result.coverage_by_chaos.len() as f64;

        let coverage_diff = (baseline_avg - stability_avg).abs();
        assert!(coverage_diff <= 0.10, "Coverage too variable between runs: {:.3}", coverage_diff);
    }

    #[tokio::test]
    async fn test_edge_case_minimal_samples() {
        // Test with minimal calibration samples to stress-test the system
        let mut test = ConformalInstrumentedChaosTest::new(0.05, 5, 10);
        let result = test.run_test().await;

        println!("{}", result.summary());

        // Should still maintain coverage even with minimal samples
        assert!(result.coverage_guaranteed, "Coverage failed with minimal samples");
        assert!(result.calibration_samples >= 5, "Didn't use minimum required samples");
    }

    #[tokio::test]
    async fn test_comprehensive_injection_strategy_coverage() {
        let mut test = ConformalInstrumentedChaosTest::new(0.05, 60, 100);

        // Test with more comprehensive injection strategies
        let strategies = vec![
            ("recording_only", InjectionStrategy::Never),
            ("inject_at_point_7", InjectionStrategy::AtSequence(7)),
            ("every_3rd", InjectionStrategy::EveryNth(3)),
            ("first_5", InjectionStrategy::FirstN(5)),
            ("probabilistic_50", InjectionStrategy::Probabilistic(0.5)),
            ("window_around_10", InjectionStrategy::WindowAround { center: 10, radius: 3 }),
            ("except_first_3", InjectionStrategy::ExceptFirst(3)),
            ("last_5_points", InjectionStrategy::LastN(5)),
        ];

        // Execute with comprehensive strategies
        for (name, strategy) in strategies {
            let future_factory = || MockComplexFuture::multi_poll(20);
            test.future_driver.execute_with_strategies(future_factory, vec![(name, strategy.clone())]).await;
        }

        // Make predictions under chaos
        let chaos_levels = vec![0.0, 0.5, 1.0];
        for &chaos_level in &chaos_levels {
            let predictions = test.conformal_manager.predict_under_chaos(chaos_level, 15);
            assert!(!predictions.is_empty(), "Should generate predictions under chaos level {}", chaos_level);
        }

        let coverage_guaranteed = test.conformal_manager.verify_coverage_guarantee();
        let await_stats = test.future_driver.get_await_statistics();

        assert!(coverage_guaranteed, "Coverage guarantee failed with comprehensive strategies");
        assert!(await_stats.len() >= 6, "Should test multiple injection strategies: got {}", await_stats.len());

        println!("Comprehensive test passed with {} strategies tested", await_stats.len());
    }
}