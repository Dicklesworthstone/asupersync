//! Core invariant testing infrastructure for structured concurrency obligations.
//!
//! This module provides the harness and traits for systematically testing
//! all obligation invariants across different scenarios and stress conditions.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use asupersync::types::{ObligationId, RegionId};
use super::obligation_tracker::{ObligationTracker, InvariantViolation, InvariantViolationType};

/// Main harness for running obligation invariant tests
pub struct ObligationInvariantHarness {
    tracker: ObligationTracker,
    config: InvariantTestConfig,
    results: HashMap<String, InvariantTestResult>,
}

/// Configuration for invariant testing
#[derive(Debug, Clone)]
pub struct InvariantTestConfig {
    /// Timeout for individual test scenarios
    pub test_timeout: Duration,
    /// Number of stress test iterations
    pub stress_iterations: usize,
    /// Concurrency level for stress tests
    pub stress_concurrency: usize,
    /// Whether to enable debug logging
    pub debug_logging: bool,
    /// Leak detection timeout
    pub leak_detection_timeout: Duration,
    /// Resource tracking enabled
    pub track_resources: bool,
}

/// Context provided to invariant tests
pub struct ObligationTestContext {
    pub tracker: ObligationTracker,
    pub config: InvariantTestConfig,
    pub test_start: Instant,
}

/// Result of an invariant test
#[derive(Debug, Clone)]
pub struct InvariantTestResult {
    pub test_name: String,
    pub category: InvariantTestCategory,
    pub outcome: TestOutcome,
    pub duration: Duration,
    pub violations: Vec<InvariantViolation>,
    pub metrics: TestMetrics,
}

/// Categories of invariant tests
#[derive(Debug, Clone, PartialEq)]
pub enum InvariantTestCategory {
    NoLeakValidation,
    RegionQuiescence,
    CancelPropagation,
    ResourceCleanup,
    TemporalSafety,
    CompositeInvariant,
}

/// Test outcome classification
#[derive(Debug, Clone, PartialEq)]
pub enum TestOutcome {
    Pass,
    Fail,
    Timeout,
    Error(String),
}

/// Metrics collected during test execution
#[derive(Debug, Clone, Default)]
pub struct TestMetrics {
    pub obligations_created: usize,
    pub obligations_resolved: usize,
    pub regions_created: usize,
    pub regions_closed: usize,
    pub resources_allocated: usize,
    pub resources_freed: usize,
    pub cancellation_events: usize,
    pub peak_active_obligations: usize,
    pub peak_memory_usage: Option<usize>,
}

/// Trait for implementing specific invariant tests
pub trait ObligationInvariantTest: Send + Sync {
    /// Name of the invariant test
    fn invariant_name(&self) -> &str;

    /// Category of the invariant test
    fn test_category(&self) -> InvariantTestCategory;

    /// Description of what the test validates
    fn description(&self) -> &str;

    /// Run the invariant test with the provided context
    fn run_test<'a>(
        &'a self,
        ctx: &'a ObligationTestContext,
    ) -> Pin<Box<dyn Future<Output = InvariantTestResult> + Send + 'a>>;

    /// Validate the invariant holds after test execution
    fn validate_invariant(&self, tracker: &ObligationTracker) -> bool;

    /// Expected violations for negative tests (tests that should detect violations)
    fn expected_violations(&self) -> Vec<InvariantViolationType> {
        Vec::new()
    }

    /// Whether this is a stress test requiring high concurrency
    fn is_stress_test(&self) -> bool {
        false
    }

    /// Whether this test intentionally violates invariants (negative test)
    fn is_negative_test(&self) -> bool {
        false
    }
}

impl ObligationInvariantHarness {
    /// Create a new invariant test harness
    pub fn new(config: InvariantTestConfig) -> Self {
        Self {
            tracker: ObligationTracker::new(),
            config,
            results: HashMap::new(),
        }
    }

    /// Run a single invariant test
    pub fn run_test<T: ObligationInvariantTest>(&mut self, test: T) -> InvariantTestResult {
        let test_name = test.invariant_name().to_string();

        if self.config.debug_logging {
            println!("Running invariant test: {}", test_name);
        }

        // Reset tracker state before test
        self.tracker.reset();

        let context = ObligationTestContext {
            tracker: self.tracker.clone(),
            config: self.config.clone(),
            test_start: Instant::now(),
        };

        let test_start = Instant::now();

        // Run test (without timeout for simplicity)
        let result = test.run_test(&context).await;

        // Post-test invariant validation
        let post_violations = self.tracker.validate_invariants();
        let invariant_holds = test.validate_invariant(&self.tracker);

        let final_result = if result.outcome == TestOutcome::Pass {
            // Check if invariants actually hold
            if test.is_negative_test() {
                // Negative test should detect expected violations
                let expected = test.expected_violations();
                let detected_types: Vec<_> = post_violations.iter()
                    .map(|v| v.violation_type.clone())
                    .collect();

                if expected.iter().all(|exp| detected_types.contains(exp)) {
                    TestOutcome::Pass
                } else {
                    TestOutcome::Fail
                }
            } else {
                // Positive test should have no violations and invariant should hold
                if post_violations.is_empty() && invariant_holds {
                    TestOutcome::Pass
                } else {
                    TestOutcome::Fail
                }
            }
        } else {
            result.outcome
        };

        let final_test_result = InvariantTestResult {
            test_name: test_name.clone(),
            category: result.category,
            outcome: final_result,
            duration: test_start.elapsed(),
            violations: [result.violations, post_violations].concat(),
            metrics: result.metrics,
        };

        self.results.insert(test_name, final_test_result.clone());
        final_test_result
    }

    /// Run a test suite of multiple invariant tests
    pub async fn run_test_suite<T: ObligationInvariantTest>(
        &mut self,
        tests: Vec<T>,
    ) -> TestSuiteResult {
        let mut results = Vec::new();
        let suite_start = Instant::now();

        for test in tests {
            let result = self.run_test(test).await;
            results.push(result);
        }

        let summary = self.calculate_summary(&results);
        TestSuiteResult {
            results,
            total_duration: suite_start.elapsed(),
            summary,
        }
    }

    /// Run stress tests with serial execution (simplified for compatibility)
    pub async fn run_stress_test<T: ObligationInvariantTest + Clone>(
        &mut self,
        test: T,
        iterations: usize,
        _concurrency: usize, // Ignored for now - run serially
    ) -> StressTestResult {
        let test_name = test.invariant_name().to_string();

        if self.config.debug_logging {
            println!("Running stress test: {} ({} iterations)", test_name, iterations);
        }

        let stress_start = Instant::now();
        let mut all_results = Vec::new();
        let mut violation_counts = HashMap::new();

        // Run tests serially for simplicity
        for _ in 0..iterations {
            let test_clone = test.clone();
            let mut harness_clone = ObligationInvariantHarness::new(
                self.config.clone(),
            );

            let result = harness_clone.run_test(test_clone).await;

            // Count violation types
            for violation in &result.violations {
                *violation_counts.entry(violation.violation_type.clone()).or_insert(0) += 1;
            }
            all_results.push(result);
        }

        StressTestResult {
            test_name,
            iterations: all_results.len(),
            concurrency: 1, // Serial execution
            total_duration: stress_start.elapsed(),
            results: all_results,
            violation_summary: violation_counts,
            peak_metrics: self.calculate_peak_metrics(&all_results),
        }
    }

    /// Get all test results
    pub fn get_results(&self) -> &HashMap<String, InvariantTestResult> {
        &self.results
    }

    /// Calculate test suite summary statistics
    fn calculate_summary(&self, results: &[InvariantTestResult]) -> TestSuiteSummary {
        let total = results.len();
        let passed = results.iter().filter(|r| r.outcome == TestOutcome::Pass).count();
        let failed = results.iter().filter(|r| r.outcome == TestOutcome::Fail).count();
        let timeouts = results.iter().filter(|r| r.outcome == TestOutcome::Timeout).count();
        let errors = total - passed - failed - timeouts;

        let total_violations: usize = results.iter().map(|r| r.violations.len()).sum();

        TestSuiteSummary {
            total_tests: total,
            passed,
            failed,
            timeouts,
            errors,
            total_violations,
            success_rate: if total > 0 { passed as f64 / total as f64 } else { 0.0 },
        }
    }

    /// Calculate peak metrics across stress test results
    fn calculate_peak_metrics(&self, results: &[InvariantTestResult]) -> TestMetrics {
        let mut peak = TestMetrics::default();

        for result in results {
            peak.obligations_created = peak.obligations_created.max(result.metrics.obligations_created);
            peak.obligations_resolved = peak.obligations_resolved.max(result.metrics.obligations_resolved);
            peak.regions_created = peak.regions_created.max(result.metrics.regions_created);
            peak.regions_closed = peak.regions_closed.max(result.metrics.regions_closed);
            peak.resources_allocated = peak.resources_allocated.max(result.metrics.resources_allocated);
            peak.resources_freed = peak.resources_freed.max(result.metrics.resources_freed);
            peak.cancellation_events = peak.cancellation_events.max(result.metrics.cancellation_events);
            peak.peak_active_obligations = peak.peak_active_obligations.max(result.metrics.peak_active_obligations);

            if let (Some(existing), Some(new)) = (peak.peak_memory_usage, result.metrics.peak_memory_usage) {
                peak.peak_memory_usage = Some(existing.max(new));
            } else if result.metrics.peak_memory_usage.is_some() {
                peak.peak_memory_usage = result.metrics.peak_memory_usage;
            }
        }

        peak
    }
}

/// Result of running a complete test suite
#[derive(Debug)]
pub struct TestSuiteResult {
    pub results: Vec<InvariantTestResult>,
    pub total_duration: Duration,
    pub summary: TestSuiteSummary,
}

/// Summary statistics for a test suite
#[derive(Debug)]
pub struct TestSuiteSummary {
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub timeouts: usize,
    pub errors: usize,
    pub total_violations: usize,
    pub success_rate: f64,
}

/// Result of stress testing
#[derive(Debug)]
pub struct StressTestResult {
    pub test_name: String,
    pub iterations: usize,
    pub concurrency: usize,
    pub total_duration: Duration,
    pub results: Vec<InvariantTestResult>,
    pub violation_summary: HashMap<InvariantViolationType, usize>,
    pub peak_metrics: TestMetrics,
}

impl Default for InvariantTestConfig {
    fn default() -> Self {
        Self {
            test_timeout: Duration::from_secs(30),
            stress_iterations: 100,
            stress_concurrency: 10,
            debug_logging: false,
            leak_detection_timeout: Duration::from_secs(5),
            track_resources: true,
        }
    }
}

impl fmt::Display for InvariantTestCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvariantTestCategory::NoLeakValidation => write!(f, "No Leak Validation"),
            InvariantTestCategory::RegionQuiescence => write!(f, "Region Quiescence"),
            InvariantTestCategory::CancelPropagation => write!(f, "Cancel Propagation"),
            InvariantTestCategory::ResourceCleanup => write!(f, "Resource Cleanup"),
            InvariantTestCategory::TemporalSafety => write!(f, "Temporal Safety"),
            InvariantTestCategory::CompositeInvariant => write!(f, "Composite Invariant"),
        }
    }
}

impl fmt::Display for TestOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TestOutcome::Pass => write!(f, "PASS"),
            TestOutcome::Fail => write!(f, "FAIL"),
            TestOutcome::Timeout => write!(f, "TIMEOUT"),
            TestOutcome::Error(msg) => write!(f, "ERROR: {}", msg),
        }
    }
}

impl fmt::Display for TestSuiteSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tests: {}, Passed: {}, Failed: {}, Timeouts: {}, Errors: {}, Success Rate: {:.1}%, Violations: {}",
               self.total_tests, self.passed, self.failed, self.timeouts, self.errors,
               self.success_rate * 100.0, self.total_violations)
    }
}

/// Helper macro for creating simple invariant tests
#[macro_export]
macro_rules! invariant_test {
    (
        name: $name:expr,
        category: $category:expr,
        description: $desc:expr,
        test: |$ctx:ident| $test_body:expr
    ) => {
        struct InvariantTestImpl;

        impl ObligationInvariantTest for InvariantTestImpl {
            fn invariant_name(&self) -> &str { $name }
            fn test_category(&self) -> InvariantTestCategory { $category }
            fn description(&self) -> &str { $desc }

            fn run_test<'a>(
                &'a self,
                $ctx: &'a ObligationTestContext,
            ) -> Pin<Box<dyn Future<Output = InvariantTestResult> + Send + 'a>> {
                Box::pin(async move { $test_body.await })
            }

            fn validate_invariant(&self, tracker: &ObligationTracker) -> bool {
                tracker.get_invariant_violations().is_empty() && !tracker.has_active_obligations()
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::test_helpers::*;

    #[tokio::test]
    async fn test_harness_basic_functionality() {
        let runtime = create_test_runtime().await;
        let config = InvariantTestConfig::default();
        let mut harness = ObligationInvariantHarness::new(runtime, config);

        // Simple test that should pass
        struct PassingTest;
        impl ObligationInvariantTest for PassingTest {
            fn invariant_name(&self) -> &str { "passing_test" }
            fn test_category(&self) -> InvariantTestCategory { InvariantTestCategory::NoLeakValidation }
            fn description(&self) -> &str { "A test that should pass" }

            fn run_test<'a>(&'a self, _ctx: &'a ObligationTestContext)
                -> Pin<Box<dyn Future<Output = InvariantTestResult> + Send + 'a>>
            {
                Box::pin(async move {
                    InvariantTestResult {
                        test_name: "passing_test".to_string(),
                        category: InvariantTestCategory::NoLeakValidation,
                        outcome: TestOutcome::Pass,
                        duration: Duration::from_millis(1),
                        violations: Vec::new(),
                        metrics: TestMetrics::default(),
                    }
                })
            }

            fn validate_invariant(&self, _tracker: &ObligationTracker) -> bool { true }
        }

        let result = harness.run_test(PassingTest).await;
        assert_eq!(result.outcome, TestOutcome::Pass);
        assert_eq!(result.test_name, "passing_test");
    }
}