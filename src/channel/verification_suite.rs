//! Comprehensive channel atomicity verification suite.
//!
//! This module provides the main entry point for verifying atomicity guarantees
//! across all channel types under various stress conditions, cancellation
//! scenarios, and edge cases.

#![allow(dead_code)]

use super::atomicity_test::{AtomicityOracle, AtomicityTestConfig};
use super::stress_test::{StressTestConfig, mpsc_stress_test};
use crate::channel::{broadcast, mpsc, oneshot, watch};
use crate::cx::Cx;
use crate::runtime::RuntimeBuilder;
use crate::time::{timeout, wall_now};

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopReason {
    FailFast,
    MaxDuration,
}

impl StopReason {
    const fn message(self) -> &'static str {
        match self {
            Self::FailFast => "fail-fast triggered",
            Self::MaxDuration => "verification duration exceeded",
        }
    }
}

/// Comprehensive test suite configuration.
#[derive(Debug, Clone)]
pub struct VerificationSuiteConfig {
    /// Test all channel types.
    pub test_all_channels: bool,
    /// Include high-stress scenarios.
    pub include_stress_tests: bool,
    /// Include edge case scenarios.
    pub include_edge_cases: bool,
    /// Include cancellation timing tests.
    pub include_cancellation_tests: bool,
    /// Maximum time to spend on verification.
    pub max_duration: Duration,
    /// Fail fast on first violation.
    pub fail_fast: bool,
}

impl Default for VerificationSuiteConfig {
    fn default() -> Self {
        Self {
            test_all_channels: true,
            include_stress_tests: true,
            include_edge_cases: true,
            include_cancellation_tests: true,
            max_duration: Duration::from_secs(60),
            fail_fast: true,
        }
    }
}

/// Results from the complete verification suite.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Total test duration.
    pub total_duration: Duration,
    /// Number of test cases executed.
    pub tests_executed: usize,
    /// Number of test cases passed.
    pub tests_passed: usize,
    /// Results by test category.
    pub results_by_category: HashMap<String, CategoryResult>,
    /// Overall pass/fail status.
    pub overall_success: bool,
    /// Summary of any violations found.
    pub violation_summary: String,
}

/// Results for a category of tests.
#[derive(Debug, Clone)]
pub struct CategoryResult {
    /// Number of tests in this category.
    pub test_count: usize,
    /// Number of passed tests.
    pub passed_count: usize,
    /// Total messages processed.
    pub total_messages: u64,
    /// Average throughput.
    pub avg_throughput: f64,
    /// Any violations detected.
    pub violations: u64,
    /// Details of failures.
    pub failure_details: Vec<String>,
}

impl Default for CategoryResult {
    fn default() -> Self {
        Self {
            test_count: 0,
            passed_count: 0,
            total_messages: 0,
            avg_throughput: 0.0,
            violations: 0,
            failure_details: Vec::new(),
        }
    }
}

/// Main verification suite runner.
pub struct VerificationSuite {
    config: VerificationSuiteConfig,
    start_time: Instant,
    results: HashMap<String, CategoryResult>,
}

impl VerificationSuite {
    /// Creates a new verification suite with the given configuration.
    pub fn new(config: VerificationSuiteConfig) -> Self {
        Self {
            config,
            start_time: Instant::now(),
            results: HashMap::new(),
        }
    }

    /// Runs the complete verification suite.
    pub async fn run(&mut self) -> VerificationResult {
        self.start_time = Instant::now();
        let mut total_tests = 0;
        let mut total_passed = 0;
        let mut overall_success = true;
        let mut violation_summary = String::new();

        if self.stop_reason_after(true) == Some(StopReason::MaxDuration) {
            Self::append_summary(&mut violation_summary, StopReason::MaxDuration.message());
            overall_success = false;
            return self.build_result(
                total_tests,
                total_passed,
                overall_success,
                violation_summary,
            );
        }

        // Test MPSC channels
        if self.config.test_all_channels {
            let (tests, passed, success) = self.test_mpsc_channels().await;
            total_tests += tests;
            total_passed += passed;
            if !success {
                overall_success = false;
                Self::append_summary(&mut violation_summary, "MPSC violations detected");
            }
            if self.apply_stop_reason_after(success, &mut violation_summary, &mut overall_success) {
                return self.build_result(
                    total_tests,
                    total_passed,
                    overall_success,
                    violation_summary,
                );
            }
        }

        // Test other channel types
        if self.config.test_all_channels {
            let (tests, passed, success) = self.test_other_channels().await;
            total_tests += tests;
            total_passed += passed;
            if !success {
                overall_success = false;
                Self::append_summary(&mut violation_summary, "Other channel violations detected");
            }
            if self.apply_stop_reason_after(success, &mut violation_summary, &mut overall_success) {
                return self.build_result(
                    total_tests,
                    total_passed,
                    overall_success,
                    violation_summary,
                );
            }
        }

        // Edge case testing
        if self.config.include_edge_cases {
            let (tests, passed, success) = self.test_edge_cases().await;
            total_tests += tests;
            total_passed += passed;
            if !success {
                overall_success = false;
                Self::append_summary(&mut violation_summary, "Edge case violations detected");
            }
            if self.apply_stop_reason_after(success, &mut violation_summary, &mut overall_success) {
                return self.build_result(
                    total_tests,
                    total_passed,
                    overall_success,
                    violation_summary,
                );
            }
        }

        // Cancellation timing tests
        if self.config.include_cancellation_tests {
            let (tests, passed, success) = self.test_cancellation_timing().await;
            total_tests += tests;
            total_passed += passed;
            if !success {
                overall_success = false;
                Self::append_summary(
                    &mut violation_summary,
                    "Cancellation timing violations detected",
                );
            }
            if self.apply_stop_reason_after(success, &mut violation_summary, &mut overall_success) {
                return self.build_result(
                    total_tests,
                    total_passed,
                    overall_success,
                    violation_summary,
                );
            }
        }

        self.build_result(
            total_tests,
            total_passed,
            overall_success,
            violation_summary,
        )
    }

    fn build_result(
        &self,
        total_tests: usize,
        total_passed: usize,
        overall_success: bool,
        mut violation_summary: String,
    ) -> VerificationResult {
        if violation_summary.is_empty() {
            violation_summary = "No violations detected".to_string();
        }

        VerificationResult {
            total_duration: self.start_time.elapsed(),
            tests_executed: total_tests,
            tests_passed: total_passed,
            results_by_category: self.results.clone(),
            overall_success,
            violation_summary,
        }
    }

    fn apply_stop_reason_after(
        &self,
        category_success: bool,
        violation_summary: &mut String,
        overall_success: &mut bool,
    ) -> bool {
        let Some(reason) = self.stop_reason_after(category_success) else {
            return false;
        };

        Self::append_summary(violation_summary, reason.message());
        *overall_success = false;
        true
    }

    fn stop_reason_after(&self, category_success: bool) -> Option<StopReason> {
        if self.config.fail_fast && !category_success {
            Some(StopReason::FailFast)
        } else if self.start_time.elapsed() >= self.config.max_duration {
            Some(StopReason::MaxDuration)
        } else {
            None
        }
    }

    fn append_summary(summary: &mut String, message: &str) {
        if !summary.is_empty() {
            summary.push_str("; ");
        }
        summary.push_str(message);
    }

    fn should_stop_category(&self, all_passed: bool) -> bool {
        self.stop_reason_after(all_passed).is_some()
    }

    fn finish_category(
        &mut self,
        name: &str,
        category: CategoryResult,
        all_passed: bool,
    ) -> (usize, usize, bool) {
        self.results.insert(name.to_string(), category);
        (
            self.results[name].test_count,
            self.results[name].passed_count,
            all_passed,
        )
    }

    /// Test MPSC channel atomicity under various conditions.
    async fn test_mpsc_channels(&mut self) -> (usize, usize, bool) {
        let mut category = CategoryResult::default();
        let mut all_passed = true;

        println!("=== Testing MPSC Channel Atomicity ===");

        // Basic atomicity test
        category.test_count += 1;
        let basic_config = AtomicityTestConfig {
            capacity: 10,
            num_producers: 4,
            messages_per_producer: 100,
            cancel_probability: 0.0,
            check_invariants: true,
            ..Default::default()
        };

        if self.run_basic_mpsc_test(basic_config, "Basic MPSC").await {
            category.passed_count += 1;
            category.total_messages += 400;
        } else {
            all_passed = false;
            category
                .failure_details
                .push("Basic MPSC test failed".to_string());
        }
        if self.should_stop_category(all_passed) {
            return self.finish_category("MPSC", category, all_passed);
        }

        // High concurrency test
        if self.config.include_stress_tests {
            category.test_count += 1;
            let stress_config = StressTestConfig {
                base: AtomicityTestConfig {
                    capacity: 16,
                    num_producers: 12,
                    messages_per_producer: 500,
                    cancel_probability: 0.15,
                    check_invariants: true,
                    ..Default::default()
                },
                stress_rounds: 3,
                round_duration: Duration::from_secs(4),
                escalating_cancellation: true,
            };

            match mpsc_stress_test(stress_config).await {
                Ok(result) => {
                    if result.atomicity_maintained {
                        category.passed_count += 1;
                        category.total_messages += result.total_messages;
                        category.avg_throughput += result.avg_throughput;
                        println!(
                            "  High concurrency MPSC: PASSED ({} msg/s)",
                            result.avg_throughput
                        );
                    } else {
                        all_passed = false;
                        category.violations += result.total_violations;
                        category.failure_details.push(format!(
                            "High concurrency MPSC failed: {} violations",
                            result.total_violations
                        ));
                    }
                }
                Err(e) => {
                    all_passed = false;
                    category
                        .failure_details
                        .push(format!("High concurrency MPSC error: {e}"));
                }
            }
            if self.should_stop_category(all_passed) {
                return self.finish_category("MPSC", category, all_passed);
            }
        }

        // Extreme cancellation test
        if self.config.include_cancellation_tests {
            category.test_count += 1;
            let cancel_config = AtomicityTestConfig {
                capacity: 5,
                num_producers: 6,
                messages_per_producer: 200,
                cancel_probability: 0.6, // Very high cancellation rate
                check_invariants: true,
                ..Default::default()
            };

            if self
                .run_basic_mpsc_test(cancel_config, "Extreme Cancellation MPSC")
                .await
            {
                category.passed_count += 1;
                category.total_messages += 200; // Approximate due to cancellations
            } else {
                all_passed = false;
                category
                    .failure_details
                    .push("Extreme cancellation MPSC test failed".to_string());
            }
        }

        self.finish_category("MPSC", category, all_passed)
    }

    /// Test other channel types for basic correctness.
    async fn test_other_channels(&mut self) -> (usize, usize, bool) {
        let mut category = CategoryResult::default();
        let mut all_passed = true;

        println!("=== Testing Other Channel Types ===");

        // Oneshot channel test
        category.test_count += 1;
        if self.test_oneshot_atomicity().await {
            category.passed_count += 1;
            println!("  Oneshot channels: PASSED");
        } else {
            all_passed = false;
            category
                .failure_details
                .push("Oneshot test failed".to_string());
        }
        if self.should_stop_category(all_passed) {
            return self.finish_category("Other", category, all_passed);
        }

        // Broadcast channel test
        category.test_count += 1;
        if self.test_broadcast_atomicity().await {
            category.passed_count += 1;
            println!("  Broadcast channels: PASSED");
        } else {
            all_passed = false;
            category
                .failure_details
                .push("Broadcast test failed".to_string());
        }
        if self.should_stop_category(all_passed) {
            return self.finish_category("Other", category, all_passed);
        }

        // Watch channel test
        category.test_count += 1;
        if self.test_watch_atomicity().await {
            category.passed_count += 1;
            println!("  Watch channels: PASSED");
        } else {
            all_passed = false;
            category
                .failure_details
                .push("Watch test failed".to_string());
        }

        self.finish_category("Other", category, all_passed)
    }

    /// Test edge cases and boundary conditions.
    async fn test_edge_cases(&mut self) -> (usize, usize, bool) {
        let mut category = CategoryResult::default();
        let mut all_passed = true;

        println!("=== Testing Edge Cases ===");

        // Capacity-1 channel
        category.test_count += 1;
        let tiny_config = AtomicityTestConfig {
            capacity: 1,
            num_producers: 3,
            messages_per_producer: 50,
            cancel_probability: 0.0,
            check_invariants: true,
            ..Default::default()
        };

        if self
            .run_basic_mpsc_test(tiny_config, "Capacity-1 Channel")
            .await
        {
            category.passed_count += 1;
        } else {
            all_passed = false;
            category
                .failure_details
                .push("Capacity-1 test failed".to_string());
        }
        if self.should_stop_category(all_passed) {
            return self.finish_category("EdgeCases", category, all_passed);
        }

        // Very large capacity channel
        category.test_count += 1;
        let large_config = AtomicityTestConfig {
            capacity: 1000,
            num_producers: 2,
            messages_per_producer: 10,
            cancel_probability: 0.0,
            check_invariants: true,
            ..Default::default()
        };

        if self
            .run_basic_mpsc_test(large_config, "Large Capacity Channel")
            .await
        {
            category.passed_count += 1;
        } else {
            all_passed = false;
            category
                .failure_details
                .push("Large capacity test failed".to_string());
        }

        self.finish_category("EdgeCases", category, all_passed)
    }

    /// Test cancellation timing scenarios.
    async fn test_cancellation_timing(&mut self) -> (usize, usize, bool) {
        let mut category = CategoryResult::default();
        let mut all_passed = true;

        println!("=== Testing Cancellation Timing ===");

        // Test cancellation during different phases
        for (phase_name, cancel_prob) in [
            ("Reserve Phase", 0.8),
            ("Commit Phase", 0.3),
            ("Mixed Timing", 0.5),
        ] {
            category.test_count += 1;
            let timing_config = AtomicityTestConfig {
                capacity: 8,
                num_producers: 2,
                messages_per_producer: 5,
                cancel_probability: cancel_prob,
                check_invariants: true,
                ..Default::default()
            };

            if self.run_basic_mpsc_test(timing_config, phase_name).await {
                category.passed_count += 1;
            } else {
                all_passed = false;
                category
                    .failure_details
                    .push(format!("{phase_name} test failed"));
            }
            if self.should_stop_category(all_passed) {
                return self.finish_category("CancellationTiming", category, all_passed);
            }
        }

        self.finish_category("CancellationTiming", category, all_passed)
    }

    /// Run a basic MPSC atomicity test with the given configuration.
    async fn run_basic_mpsc_test(&self, config: AtomicityTestConfig, test_name: &str) -> bool {
        let oracle = Arc::new(AtomicityOracle::new(config.clone()));
        let (sender, receiver) = mpsc::channel::<u32>(config.capacity);
        let expected_messages = config.num_producers * config.messages_per_producer;

        let test_result = match RuntimeBuilder::current_thread().build() {
            Ok(runtime) => {
                let handle = runtime.handle();
                let oracle_for_test = Arc::clone(&oracle);
                runtime.block_on(async move {
                    match timeout(wall_now(), Duration::from_secs(10), async move {
                        // Start consumer
                        let consumer_oracle = Arc::clone(&oracle_for_test);
                        let consumer = handle.spawn(async move {
                            let cx = Cx::for_testing();
                            super::atomicity_test::consumer_task(
                                receiver,
                                consumer_oracle,
                                expected_messages,
                                &cx,
                            )
                            .await
                        });

                        // Start producers
                        let mut producers = Vec::new();
                        for i in 0..config.num_producers {
                            let sender = sender.clone();
                            let producer_oracle = Arc::clone(&oracle_for_test);
                            let injector =
                                Arc::new(super::atomicity_test::CancellationInjector::new(
                                    config.cancel_probability,
                                ));

                            let messages: Vec<u32> = (0..config.messages_per_producer)
                                .map(|j| (i * config.messages_per_producer + j) as u32)
                                .collect();

                            let producer = handle.spawn(async move {
                                let cx = Cx::for_testing();
                                super::atomicity_test::producer_task(
                                    sender,
                                    producer_oracle,
                                    injector,
                                    messages,
                                    &cx,
                                )
                                .await
                            });
                            producers.push(producer);
                        }

                        // Wait for producers
                        for producer in producers {
                            if producer.await.is_err() {
                                return false;
                            }
                        }

                        // Close channel and wait for consumer
                        drop(sender);
                        match consumer.await {
                            Ok(_) => oracle_for_test.verify_final_consistency(),
                            Err(_) => false,
                        }
                    })
                    .await
                    {
                        Ok(consistent) => consistent,
                        Err(_) => {
                            eprintln!("  {test_name}: TIMEOUT");
                            false
                        }
                    }
                })
            }
            Err(e) => {
                eprintln!("  {test_name}: runtime build failed: {e}");
                false
            }
        };

        if test_result {
            println!("  {test_name}: PASSED");
        } else {
            println!("  {test_name}: FAILED");
        }

        test_result
    }

    /// Test oneshot channel atomicity.
    async fn test_oneshot_atomicity(&self) -> bool {
        // Oneshot is inherently atomic - test basic correctness
        match RuntimeBuilder::current_thread().build() {
            Ok(runtime) => runtime.block_on(async move {
                let cx = Cx::for_testing();

                for i in 0..100 {
                    let (sender, mut receiver) = oneshot::channel::<u32>();

                    if i % 2 == 0 {
                        sender.send(&cx, i).unwrap();
                        let value = receiver.recv(&cx).await.unwrap();
                        assert_eq!(value, i);
                    } else {
                        drop(sender);
                        assert!(receiver.recv(&cx).await.is_err());
                    }
                }
                true
            }),
            Err(_) => false,
        }
    }

    /// Test broadcast channel atomicity.
    async fn test_broadcast_atomicity(&self) -> bool {
        match RuntimeBuilder::current_thread().build() {
            Ok(runtime) => runtime.block_on(async move {
                let cx = Cx::for_testing();
                let (sender, initial_receiver) = broadcast::channel::<u32>(50);

                let mut receivers = vec![initial_receiver];
                for _ in 1..5 {
                    receivers.push(sender.subscribe());
                }

                for i in 0..100 {
                    if sender.send(&cx, i).is_err() {
                        break;
                    }
                }

                drop(sender);

                for mut receiver in receivers {
                    let mut missed_messages = 0;
                    let mut received = Vec::new();
                    loop {
                        match receiver.recv(&cx).await {
                            Ok(value) => received.push(value),
                            Err(broadcast::RecvError::Lagged(missed)) => {
                                missed_messages += missed;
                            }
                            Err(broadcast::RecvError::Closed) => break,
                            Err(_) => return false,
                        }
                    }

                    if missed_messages != 50 {
                        return false;
                    }
                    if received.len() != 50 || !received.iter().copied().eq(50..100) {
                        return false;
                    }
                }
                true
            }),
            Err(_) => false,
        }
    }

    /// Test watch channel atomicity.
    async fn test_watch_atomicity(&self) -> bool {
        match RuntimeBuilder::current_thread().build() {
            Ok(runtime) => runtime.block_on(async move {
                let cx = Cx::for_testing();
                let (sender, _) = watch::channel::<u32>(0);

                let mut receiver = sender.subscribe();

                for i in 1..=50 {
                    sender.send(i).unwrap();
                }

                let _ = receiver.changed(&cx).await;
                let final_value = *receiver.borrow();
                assert_eq!(final_value, 50);
                true
            }),
            Err(_) => false,
        }
    }
}

/// Run the complete channel atomicity verification suite.
pub async fn run_verification_suite() -> VerificationResult {
    let config = VerificationSuiteConfig::default();
    let mut suite = VerificationSuite::new(config);
    suite.run().await
}

/// Run a quick verification suite for CI.
pub async fn run_quick_verification() -> VerificationResult {
    let config = VerificationSuiteConfig {
        test_all_channels: true,
        include_stress_tests: false, // Skip stress tests for speed
        include_edge_cases: true,
        include_cancellation_tests: false, // Cancellation timing is covered by the full suite
        max_duration: Duration::from_secs(30),
        fail_fast: true,
    };
    let mut suite = VerificationSuite::new(config);
    suite.run().await
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use futures_lite::future;

    #[test]
    fn test_quick_verification_suite() {
        let result = future::block_on(run_quick_verification());

        println!("Quick Verification Results:");
        println!("  Duration: {:?}", result.total_duration);
        println!("  Tests: {}/{}", result.tests_passed, result.tests_executed);
        println!("  Success: {}", result.overall_success);
        println!("  Summary: {}", result.violation_summary);

        for (category, category_result) in &result.results_by_category {
            println!(
                "  {}: {}/{} passed",
                category, category_result.passed_count, category_result.test_count
            );
            if category_result.violations > 0 {
                println!("    Violations: {}", category_result.violations);
            }
            for failure in &category_result.failure_details {
                println!("    Failure: {failure}");
            }
        }

        assert!(
            result.overall_success,
            "Verification suite failed: {}",
            result.violation_summary
        );
        assert_eq!(
            result.tests_passed, result.tests_executed,
            "Some tests failed"
        );
    }

    #[test]
    fn fail_fast_stop_reason_is_configured() {
        let fail_fast_suite = VerificationSuite::new(VerificationSuiteConfig {
            fail_fast: true,
            max_duration: Duration::from_secs(60),
            ..VerificationSuiteConfig::default()
        });
        assert_eq!(
            fail_fast_suite.stop_reason_after(false),
            Some(StopReason::FailFast)
        );

        let keep_going_suite = VerificationSuite::new(VerificationSuiteConfig {
            fail_fast: false,
            max_duration: Duration::from_secs(60),
            ..VerificationSuiteConfig::default()
        });
        assert_eq!(keep_going_suite.stop_reason_after(false), None);
    }

    #[test]
    fn zero_max_duration_stops_before_running_categories() {
        let result = future::block_on(async {
            let mut suite = VerificationSuite::new(VerificationSuiteConfig {
                max_duration: Duration::ZERO,
                ..VerificationSuiteConfig::default()
            });
            suite.run().await
        });

        assert_eq!(result.tests_executed, 0);
        assert_eq!(result.tests_passed, 0);
        assert!(!result.overall_success);
        assert!(
            result
                .violation_summary
                .contains(StopReason::MaxDuration.message())
        );
        assert!(result.results_by_category.is_empty());
    }

    #[test]
    #[ignore = "Long-running test"]
    fn test_full_verification_suite() {
        let result = future::block_on(run_verification_suite());

        println!("Full Verification Results:");
        println!("  Duration: {:?}", result.total_duration);
        println!("  Tests: {}/{}", result.tests_passed, result.tests_executed);
        println!("  Success: {}", result.overall_success);

        assert!(
            result.overall_success,
            "Verification suite failed: {}",
            result.violation_summary
        );
    }
}
