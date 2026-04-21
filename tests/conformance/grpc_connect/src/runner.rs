#![allow(warnings)]
#![allow(clippy::all)]
//! Test runner implementation for parallel execution and test management

use crate::{ConformanceResult, ConformanceConfig, TestCategory, TestStatus};
use anyhow::Result;
use asupersync::cx::Cx;
use std::collections::HashMap;
use std::time::Instant;
use tracing::{info, debug, warn};

/// Parallel test runner for conformance tests
#[allow(dead_code)]
pub struct ParallelTestRunner {
    config: ConformanceConfig,
}

#[allow(dead_code)]

impl ParallelTestRunner {
    #[allow(dead_code)]
    pub fn new(config: ConformanceConfig) -> Self {
        Self { config }
    }

    /// Run tests in parallel with concurrency control
    pub async fn run_tests<F, Fut>(&self, cx: &Cx, test_cases: Vec<(&str, F)>) -> Result<Vec<ConformanceResult>>
    where
        F: Fn() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<ConformanceResult>> + Send,
    {
        info!("Running {} tests in parallel", test_cases.len());

        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(4)); // Limit concurrency
        let mut tasks = Vec::new();

        for (test_name, test_fn) in test_cases {
            let permit = semaphore.clone().acquire_owned().await?;
            let test_name = test_name.to_string();

            let task = tokio::spawn(async move {
                let _permit = permit; // Hold permit for task duration
                let start_time = Instant::now();

                debug!("Starting test: {}", test_name);

                match test_fn().await {
                    Ok(mut result) => {
                        result.duration = start_time.elapsed();
                        debug!("Completed test: {} in {:?}", test_name, result.duration);
                        result
                    }
                    Err(e) => {
                        warn!("Test {} failed with error: {:?}", test_name, e);
                        ConformanceResult {
                            test_name: test_name.clone(),
                            category: TestCategory::ErrorHandling, // Default category for errors
                            status: TestStatus::Error,
                            duration: start_time.elapsed(),
                            error_message: Some(e.to_string()),
                            metadata: Default::default(),
                        }
                    }
                }
            });

            tasks.push(task);
        }

        let mut results = Vec::new();
        for task in tasks {
            match task.await {
                Ok(result) => results.push(result),
                Err(e) => {
                    warn!("Task join error: {:?}", e);
                }
            }
        }

        info!("Completed {} tests in parallel", results.len());
        Ok(results)
    }

    /// Generate test execution summary
    #[allow(dead_code)]
    pub fn generate_summary(&self, results: &[ConformanceResult]) -> TestSummary {
        let mut summary = TestSummary::default();

        for result in results {
            summary.total_tests += 1;

            match result.status {
                TestStatus::Passed => summary.passed_tests += 1,
                TestStatus::Failed => summary.failed_tests += 1,
                TestStatus::Skipped => summary.skipped_tests += 1,
                TestStatus::Error => summary.error_tests += 1,
            }

            summary.total_duration += result.duration;
            summary.by_category
                .entry(result.category)
                .or_default()
                .push(result.clone());
        }

        summary
    }
}

/// Test execution summary
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct TestSummary {
    pub total_tests: u32,
    pub passed_tests: u32,
    pub failed_tests: u32,
    pub skipped_tests: u32,
    pub error_tests: u32,
    pub total_duration: std::time::Duration,
    pub by_category: HashMap<TestCategory, Vec<ConformanceResult>>,
}

#[allow(dead_code)]

impl TestSummary {
    #[allow(dead_code)]
    pub fn success_rate(&self) -> f64 {
        if self.total_tests == 0 {
            return 0.0;
        }
        self.passed_tests as f64 / self.total_tests as f64 * 100.0
    }

    #[allow(dead_code)]

    pub fn print_summary(&self) {
        info!("=== Test Execution Summary ===");
        info!("Total tests: {}", self.total_tests);
        info!("Passed: {} ({:.1}%)", self.passed_tests, self.success_rate());
        info!("Failed: {}", self.failed_tests);
        info!("Skipped: {}", self.skipped_tests);
        info!("Errors: {}", self.error_tests);
        info!("Total duration: {:?}", self.total_duration);

        for (category, results) in &self.by_category {
            let category_passed = results.iter().filter(|r| r.status == TestStatus::Passed).count();
            let category_total = results.len();
            info!("{:?}: {}/{} passed", category, category_passed, category_total);
        }
    }
}