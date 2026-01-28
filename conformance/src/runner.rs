//! Test runner for executing conformance tests.
//!
//! The `TestRunner` executes conformance tests against one or more runtime
//! implementations and collects results. When running in comparison mode,
//! it runs each test against both runtimes and compares the outcomes.

use crate::logging::{with_test_logger, ConformanceTestLogger, TestEvent};
use crate::{ConformanceTest, RuntimeInterface, TestCategory, TestResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Configuration for test execution.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// Categories to run (empty = all).
    pub categories: Vec<TestCategory>,
    /// Tags to filter by (empty = all).
    pub tags: Vec<String>,
    /// Specific test IDs to run (empty = all).
    pub test_ids: Vec<String>,
    /// Timeout per test.
    pub timeout: Duration,
    /// Whether to continue on failure.
    pub fail_fast: bool,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            categories: Vec::new(),
            tags: Vec::new(),
            test_ids: Vec::new(),
            timeout: Duration::from_secs(30),
            fail_fast: false,
        }
    }
}

impl RunConfig {
    /// Create a new configuration with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter to specific categories.
    pub fn with_categories(mut self, categories: Vec<TestCategory>) -> Self {
        self.categories = categories;
        self
    }

    /// Filter to specific tags.
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Filter to specific test IDs.
    pub fn with_test_ids(mut self, test_ids: Vec<String>) -> Self {
        self.test_ids = test_ids;
        self
    }

    /// Set the timeout per test.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set whether to stop on first failure.
    pub fn with_fail_fast(mut self, fail_fast: bool) -> Self {
        self.fail_fast = fail_fast;
        self
    }
}

/// Summary of a test run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    /// Total number of tests executed.
    pub total: usize,
    /// Number of tests that passed.
    pub passed: usize,
    /// Number of tests that failed.
    pub failed: usize,
    /// Number of tests that were skipped.
    pub skipped: usize,
    /// Total execution time.
    pub duration_ms: u64,
    /// Individual test results.
    pub results: Vec<SingleRunResult>,
}

impl RunSummary {
    /// Create an empty summary.
    pub fn new() -> Self {
        Self {
            total: 0,
            passed: 0,
            failed: 0,
            skipped: 0,
            duration_ms: 0,
            results: Vec::new(),
        }
    }

    /// Check if all tests passed.
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }
}

impl Default for RunSummary {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of running a single test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleRunResult {
    /// Test ID.
    pub test_id: String,
    /// Test name.
    pub test_name: String,
    /// Test category.
    pub category: TestCategory,
    /// The test result.
    pub result: TestResult,
}

/// Result of running a test with structured events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteTestResult {
    /// Test ID.
    pub test_id: String,
    /// Test name.
    pub test_name: String,
    /// Test category.
    pub category: TestCategory,
    /// Expected behavior description.
    pub expected: String,
    /// Test result payload.
    pub result: TestResult,
    /// Structured events captured during execution.
    pub events: Vec<TestEvent>,
}

/// Summary of a full conformance suite run with structured events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteResult {
    /// Runtime name.
    pub runtime_name: String,
    /// Total number of tests executed.
    pub total: usize,
    /// Number of tests that passed.
    pub passed: usize,
    /// Number of tests that failed.
    pub failed: usize,
    /// Number of tests that were skipped.
    pub skipped: usize,
    /// Total execution time.
    pub duration_ms: u64,
    /// Individual test results.
    pub results: Vec<SuiteTestResult>,
}

impl SuiteResult {
    /// Create a new suite result.
    pub fn new(runtime_name: impl Into<String>) -> Self {
        Self {
            runtime_name: runtime_name.into(),
            total: 0,
            passed: 0,
            failed: 0,
            skipped: 0,
            duration_ms: 0,
            results: Vec::new(),
        }
    }

    fn push<RT: RuntimeInterface>(
        &mut self,
        test: &ConformanceTest<RT>,
        result: TestResult,
        events: Vec<TestEvent>,
    ) {
        if result.passed {
            self.passed += 1;
        } else {
            self.failed += 1;
        }

        self.results.push(SuiteTestResult {
            test_id: test.meta.id.clone(),
            test_name: test.meta.name.clone(),
            category: test.meta.category,
            expected: test.meta.expected.clone(),
            result,
            events,
        });
    }
}

/// Result of comparing a test run between two runtimes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonResult {
    /// Test ID.
    pub test_id: String,
    /// Test name.
    pub test_name: String,
    /// Test category.
    pub category: TestCategory,
    /// Result from the first runtime.
    pub runtime_a_result: TestResult,
    /// Result from the second runtime.
    pub runtime_b_result: TestResult,
    /// Name of runtime A.
    pub runtime_a_name: String,
    /// Name of runtime B.
    pub runtime_b_name: String,
    /// Comparison status.
    pub status: ComparisonStatus,
}

/// Status of comparing test results between two runtimes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComparisonStatus {
    /// Both runtimes passed with equivalent behavior.
    BothPassedEquivalent,
    /// Both runtimes passed but with different behavior (may be acceptable).
    BothPassedDifferent {
        /// Description of the difference.
        difference: String,
    },
    /// Both runtimes failed with the same error.
    BothFailedSame,
    /// Both runtimes failed but with different errors.
    BothFailedDifferent {
        /// Error from runtime A.
        error_a: String,
        /// Error from runtime B.
        error_b: String,
    },
    /// Runtime A passed but runtime B failed (unexpected).
    OnlyAPassed {
        /// Error from runtime B.
        error_b: String,
    },
    /// Runtime B passed but runtime A failed.
    OnlyBPassed {
        /// Error from runtime A.
        error_a: String,
    },
}

impl ComparisonStatus {
    /// Check if this comparison indicates success (both passed).
    pub fn is_success(&self) -> bool {
        matches!(
            self,
            ComparisonStatus::BothPassedEquivalent | ComparisonStatus::BothPassedDifferent { .. }
        )
    }

    /// Check if runtime A had an issue.
    pub fn runtime_a_failed(&self) -> bool {
        matches!(
            self,
            ComparisonStatus::OnlyBPassed { .. }
                | ComparisonStatus::BothFailedSame
                | ComparisonStatus::BothFailedDifferent { .. }
        )
    }
}

/// Summary of a comparison run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonSummary {
    /// Total tests compared.
    pub total: usize,
    /// Tests where both runtimes passed equivalently.
    pub both_passed_equivalent: usize,
    /// Tests where both passed but differed.
    pub both_passed_different: usize,
    /// Tests where both failed the same way.
    pub both_failed_same: usize,
    /// Tests where both failed differently.
    pub both_failed_different: usize,
    /// Tests where only runtime A passed.
    pub only_a_passed: usize,
    /// Tests where only runtime B passed.
    pub only_b_passed: usize,
    /// Total duration.
    pub duration_ms: u64,
    /// Individual comparison results.
    pub results: Vec<ComparisonResult>,
}

impl ComparisonSummary {
    /// Create an empty summary.
    pub fn new() -> Self {
        Self {
            total: 0,
            both_passed_equivalent: 0,
            both_passed_different: 0,
            both_failed_same: 0,
            both_failed_different: 0,
            only_a_passed: 0,
            only_b_passed: 0,
            duration_ms: 0,
            results: Vec::new(),
        }
    }

    /// Check if all tests had acceptable outcomes.
    pub fn all_acceptable(&self) -> bool {
        self.only_a_passed == 0 && self.only_b_passed == 0 && self.both_failed_different == 0
    }

    /// Add a comparison result.
    pub fn add_result(&mut self, result: ComparisonResult) {
        match &result.status {
            ComparisonStatus::BothPassedEquivalent => self.both_passed_equivalent += 1,
            ComparisonStatus::BothPassedDifferent { .. } => self.both_passed_different += 1,
            ComparisonStatus::BothFailedSame => self.both_failed_same += 1,
            ComparisonStatus::BothFailedDifferent { .. } => self.both_failed_different += 1,
            ComparisonStatus::OnlyAPassed { .. } => self.only_a_passed += 1,
            ComparisonStatus::OnlyBPassed { .. } => self.only_b_passed += 1,
        }
        self.total += 1;
        self.results.push(result);
    }
}

impl Default for ComparisonSummary {
    fn default() -> Self {
        Self::new()
    }
}

/// Test runner that executes conformance tests.
pub struct TestRunner<'a, RT: RuntimeInterface> {
    /// The runtime to test against.
    runtime: &'a RT,
    /// Runtime name for logging.
    runtime_name: &'a str,
    /// Configuration.
    config: RunConfig,
}

impl<'a, RT: RuntimeInterface> TestRunner<'a, RT> {
    /// Create a new test runner.
    pub fn new(runtime: &'a RT, runtime_name: &'a str, config: RunConfig) -> Self {
        Self {
            runtime,
            runtime_name,
            config,
        }
    }

    /// Get the runtime name.
    pub fn name(&self) -> &str {
        self.runtime_name
    }

    /// Run all tests that match the configuration.
    pub fn run_all(&self, tests: &[ConformanceTest<RT>]) -> RunSummary {
        let start = Instant::now();
        let filtered = self.filter_tests(tests);

        let mut summary = RunSummary::new();

        for test in filtered {
            let result = self.run_single(test);

            if result.passed {
                summary.passed += 1;
            } else {
                summary.failed += 1;
                if self.config.fail_fast {
                    summary.results.push(SingleRunResult {
                        test_id: test.meta.id.clone(),
                        test_name: test.meta.name.clone(),
                        category: test.meta.category,
                        result,
                    });
                    break;
                }
            }

            summary.results.push(SingleRunResult {
                test_id: test.meta.id.clone(),
                test_name: test.meta.name.clone(),
                category: test.meta.category,
                result,
            });
        }

        summary.total = summary.results.len();
        summary.duration_ms = start.elapsed().as_millis() as u64;

        summary
    }

    /// Run all tests with structured logging enabled.
    pub fn run_all_with_logs(&self, tests: &[ConformanceTest<RT>]) -> SuiteResult {
        let start = Instant::now();
        let filtered = self.filter_tests(tests);

        let mut summary = SuiteResult::new(self.runtime_name);

        for test in filtered {
            let (result, events) = self.run_single_with_logger(test);
            let passed = result.passed;
            summary.push(test, result, events);

            if !passed && self.config.fail_fast {
                break;
            }
        }

        summary.total = summary.results.len();
        summary.duration_ms = start.elapsed().as_millis() as u64;
        summary
    }

    /// Run a single test.
    pub fn run_single(&self, test: &ConformanceTest<RT>) -> TestResult {
        let start = Instant::now();

        // Catch panics
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| test.run(self.runtime)));

        let duration = start.elapsed();

        match result {
            Ok(mut test_result) => {
                test_result.duration_ms = Some(duration.as_millis() as u64);
                test_result
            }
            Err(panic) => {
                let message = if let Some(s) = panic.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown panic".to_string()
                };

                TestResult::failed(format!("Test panicked: {message}"))
                    .with_duration(duration.as_millis() as u64)
            }
        }
    }

    /// Run a single test and return structured events.
    pub fn run_single_with_logger(
        &self,
        test: &ConformanceTest<RT>,
    ) -> (TestResult, Vec<TestEvent>) {
        let logger = ConformanceTestLogger::new(&test.meta.name, &test.meta.expected);
        let start = Instant::now();

        let result = with_test_logger(&logger, || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| test.run(self.runtime)))
        });

        let duration = start.elapsed();

        let mut test_result = match result {
            Ok(mut test_result) => {
                test_result.duration_ms = Some(duration.as_millis() as u64);
                test_result
            }
            Err(panic) => {
                let message = if let Some(s) = panic.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown panic".to_string()
                };

                TestResult::failed(format!("Test panicked: {message}"))
                    .with_duration(duration.as_millis() as u64)
            }
        };

        // Ensure duration is always set.
        if test_result.duration_ms.is_none() {
            test_result.duration_ms = Some(duration.as_millis() as u64);
        }

        let events = logger.events();
        (test_result, events)
    }

    /// Filter tests based on configuration.
    fn filter_tests<'b>(&self, tests: &'b [ConformanceTest<RT>]) -> Vec<&'b ConformanceTest<RT>> {
        tests
            .iter()
            .filter(|test| {
                // Filter by category
                if !self.config.categories.is_empty()
                    && !self.config.categories.contains(&test.meta.category)
                {
                    return false;
                }

                // Filter by test ID
                if !self.config.test_ids.is_empty() && !self.config.test_ids.contains(&test.meta.id)
                {
                    return false;
                }

                // Filter by tags
                if !self.config.tags.is_empty() {
                    let has_tag = self
                        .config
                        .tags
                        .iter()
                        .any(|tag| test.meta.tags.contains(tag));
                    if !has_tag {
                        return false;
                    }
                }

                true
            })
            .collect()
    }
}

/// Run the full conformance suite and collect structured logs.
pub fn run_conformance_suite<RT: RuntimeInterface>(
    runtime: &RT,
    runtime_name: &str,
    config: RunConfig,
) -> SuiteResult {
    let tests = crate::tests::all_tests::<RT>();
    let runner = TestRunner::new(runtime, runtime_name, config);
    runner.run_all_with_logs(&tests)
}

/// Compare test results between two runtimes.
pub fn compare_results(
    runtime_a_name: &str,
    runtime_b_name: &str,
    result_a: &TestResult,
    result_b: &TestResult,
) -> ComparisonStatus {
    match (result_a.passed, result_b.passed) {
        (true, true) => {
            // Both passed - check if checkpoints match
            if result_a.checkpoints == result_b.checkpoints {
                ComparisonStatus::BothPassedEquivalent
            } else {
                ComparisonStatus::BothPassedDifferent {
                    difference: format!(
                        "{} had {} checkpoints, {} had {}",
                        runtime_a_name,
                        result_a.checkpoints.len(),
                        runtime_b_name,
                        result_b.checkpoints.len()
                    ),
                }
            }
        }
        (false, false) => {
            // Both failed - check if errors match
            let error_a = result_a
                .message
                .clone()
                .unwrap_or_else(|| "Unknown error".to_string());
            let error_b = result_b
                .message
                .clone()
                .unwrap_or_else(|| "Unknown error".to_string());

            if error_a == error_b {
                ComparisonStatus::BothFailedSame
            } else {
                ComparisonStatus::BothFailedDifferent { error_a, error_b }
            }
        }
        (true, false) => ComparisonStatus::OnlyAPassed {
            error_b: result_b
                .message
                .clone()
                .unwrap_or_else(|| "Unknown error".to_string()),
        },
        (false, true) => ComparisonStatus::OnlyBPassed {
            error_a: result_a
                .message
                .clone()
                .unwrap_or_else(|| "Unknown error".to_string()),
        },
    }
}

/// Run comparison between two runtimes.
pub fn run_comparison<RTA: RuntimeInterface, RTB: RuntimeInterface>(
    runtime_a: &RTA,
    runtime_a_name: &str,
    runtime_b: &RTB,
    runtime_b_name: &str,
    tests_a: &[ConformanceTest<RTA>],
    tests_b: &[ConformanceTest<RTB>],
    config: RunConfig,
) -> ComparisonSummary {
    let start = Instant::now();
    let mut summary = ComparisonSummary::new();

    // Build map of tests by ID
    let tests_a_map: HashMap<&str, &ConformanceTest<RTA>> =
        tests_a.iter().map(|t| (t.meta.id.as_str(), t)).collect();
    let tests_b_map: HashMap<&str, &ConformanceTest<RTB>> =
        tests_b.iter().map(|t| (t.meta.id.as_str(), t)).collect();

    // Find common test IDs
    let common_ids: Vec<&str> = tests_a_map
        .keys()
        .filter(|id| tests_b_map.contains_key(*id))
        .copied()
        .collect();

    let runner_a = TestRunner::new(runtime_a, runtime_a_name, config.clone());
    let runner_b = TestRunner::new(runtime_b, runtime_b_name, config.clone());

    for id in common_ids {
        let test_a = tests_a_map[id];
        let test_b = tests_b_map[id];

        // Apply filters
        if !config.categories.is_empty() && !config.categories.contains(&test_a.meta.category) {
            continue;
        }
        if !config.test_ids.is_empty() && !config.test_ids.contains(&test_a.meta.id) {
            continue;
        }
        if !config.tags.is_empty() {
            let has_tag = config.tags.iter().any(|tag| test_a.meta.tags.contains(tag));
            if !has_tag {
                continue;
            }
        }

        // Run on both runtimes
        let result_a = runner_a.run_single(test_a);
        let result_b = runner_b.run_single(test_b);

        // Compare
        let status = compare_results(runtime_a_name, runtime_b_name, &result_a, &result_b);

        summary.add_result(ComparisonResult {
            test_id: test_a.meta.id.clone(),
            test_name: test_a.meta.name.clone(),
            category: test_a.meta.category,
            runtime_a_result: result_a,
            runtime_b_result: result_b,
            runtime_a_name: runtime_a_name.to_string(),
            runtime_b_name: runtime_b_name.to_string(),
            status,
        });

        if config.fail_fast && !summary.results.last().is_none_or(|r| r.status.is_success()) {
            break;
        }
    }

    summary.duration_ms = start.elapsed().as_millis() as u64;
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::TestEventKind;
    use crate::{
        BroadcastRecvError, BroadcastReceiver, BroadcastSender, MpscReceiver, MpscSender,
        OneshotRecvError, OneshotSender, WatchRecvError, WatchReceiver, WatchSender,
    };
    use std::future::Future;
    use std::marker::PhantomData;
    use std::net::SocketAddr;
    use std::path::Path;
    use std::pin::Pin;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    #[test]
    fn run_config_default() {
        let config = RunConfig::default();
        assert!(config.categories.is_empty());
        assert!(config.tags.is_empty());
        assert!(!config.fail_fast);
    }

    #[test]
    fn run_config_builder() {
        let config = RunConfig::new()
            .with_categories(vec![TestCategory::IO])
            .with_tags(vec!["tcp".to_string()])
            .with_timeout(Duration::from_secs(60))
            .with_fail_fast(true);

        assert_eq!(config.categories, vec![TestCategory::IO]);
        assert_eq!(config.tags, vec!["tcp".to_string()]);
        assert_eq!(config.timeout, Duration::from_secs(60));
        assert!(config.fail_fast);
    }

    #[test]
    fn run_summary_all_passed() {
        let mut summary = RunSummary::new();
        summary.passed = 5;
        summary.failed = 0;
        assert!(summary.all_passed());

        summary.failed = 1;
        assert!(!summary.all_passed());
    }

    #[test]
    fn comparison_status_is_success() {
        assert!(ComparisonStatus::BothPassedEquivalent.is_success());
        assert!(ComparisonStatus::BothPassedDifferent {
            difference: "test".to_string()
        }
        .is_success());
        assert!(!ComparisonStatus::BothFailedSame.is_success());
        assert!(!ComparisonStatus::OnlyAPassed {
            error_b: "err".to_string()
        }
        .is_success());
        assert!(!ComparisonStatus::OnlyBPassed {
            error_a: "err".to_string()
        }
        .is_success());
    }

    #[test]
    fn compare_results_both_passed() {
        let result_a = TestResult::passed();
        let result_b = TestResult::passed();

        let status = compare_results("A", "B", &result_a, &result_b);
        assert!(matches!(status, ComparisonStatus::BothPassedEquivalent));
    }

    #[test]
    fn compare_results_both_failed_same() {
        let result_a = TestResult::failed("error");
        let result_b = TestResult::failed("error");

        let status = compare_results("A", "B", &result_a, &result_b);
        assert!(matches!(status, ComparisonStatus::BothFailedSame));
    }

    #[test]
    fn compare_results_both_failed_different() {
        let result_a = TestResult::failed("error A");
        let result_b = TestResult::failed("error B");

        let status = compare_results("A", "B", &result_a, &result_b);
        assert!(matches!(
            status,
            ComparisonStatus::BothFailedDifferent { .. }
        ));
    }

    #[test]
    fn compare_results_only_a_passed() {
        let result_a = TestResult::passed();
        let result_b = TestResult::failed("error B");

        let status = compare_results("A", "B", &result_a, &result_b);
        assert!(matches!(status, ComparisonStatus::OnlyAPassed { .. }));
    }

    #[test]
    fn compare_results_only_b_passed() {
        let result_a = TestResult::failed("error A");
        let result_b = TestResult::passed();

        let status = compare_results("A", "B", &result_a, &result_b);
        assert!(matches!(status, ComparisonStatus::OnlyBPassed { .. }));
    }

    #[test]
    fn comparison_summary_add_result() {
        let mut summary = ComparisonSummary::new();

        summary.add_result(ComparisonResult {
            test_id: "test-1".to_string(),
            test_name: "Test 1".to_string(),
            category: TestCategory::IO,
            runtime_a_result: TestResult::passed(),
            runtime_b_result: TestResult::passed(),
            runtime_a_name: "A".to_string(),
            runtime_b_name: "B".to_string(),
            status: ComparisonStatus::BothPassedEquivalent,
        });

        assert_eq!(summary.total, 1);
        assert_eq!(summary.both_passed_equivalent, 1);
        assert!(summary.all_acceptable());

        summary.add_result(ComparisonResult {
            test_id: "test-2".to_string(),
            test_name: "Test 2".to_string(),
            category: TestCategory::IO,
            runtime_a_result: TestResult::failed("error"),
            runtime_b_result: TestResult::passed(),
            runtime_a_name: "A".to_string(),
            runtime_b_name: "B".to_string(),
            status: ComparisonStatus::OnlyBPassed {
                error_a: "error".to_string(),
            },
        });

        assert_eq!(summary.total, 2);
        assert_eq!(summary.only_b_passed, 1);
        assert!(!summary.all_acceptable());
    }

    #[test]
    fn run_all_with_logs_captures_checkpoint() {
        let runtime = DummyRuntime;
        let test = ConformanceTest::new(
            TestMeta {
                id: "log-001".to_string(),
                name: "logger checkpoint".to_string(),
                description: "records checkpoints in logger".to_string(),
                category: TestCategory::Spawn,
                tags: vec!["logger".to_string()],
                expected: "checkpoint is captured".to_string(),
            },
            |_rt| {
                crate::checkpoint("checkpoint-1", serde_json::json!({"value": 1}));
                TestResult::passed()
            },
        );

        let runner = TestRunner::new(&runtime, "dummy", RunConfig::default());
        let summary = runner.run_all_with_logs(&[test]);

        assert_eq!(summary.total, 1);
        let events = &summary.results[0].events;
        assert!(events.iter().any(|e| e.kind == TestEventKind::Checkpoint));
    }

    #[test]
    fn run_comparison_with_dummy_runtime() {
        let runtime_a = DummyRuntime;
        let runtime_b = DummyRuntime;

        let meta = TestMeta {
            id: "cmp-001".to_string(),
            name: "comparison baseline".to_string(),
            description: "comparison test returns pass".to_string(),
            category: TestCategory::Spawn,
            tags: vec!["comparison".to_string()],
            expected: "both runtimes pass".to_string(),
        };

        let tests_a = vec![ConformanceTest::new(meta.clone(), |_rt| TestResult::passed())];
        let tests_b = vec![ConformanceTest::new(meta, |_rt| TestResult::passed())];

        let summary = run_comparison(
            &runtime_a,
            "A",
            &tests_a,
            &runtime_b,
            "B",
            &tests_b,
            RunConfig::default(),
        );

        assert_eq!(summary.total, 1);
        assert_eq!(summary.both_passed_equivalent, 1);
    }

    // ---------------------------------------------------------------------
    // Dummy runtime for runner unit tests
    // ---------------------------------------------------------------------

    struct DummyRuntime;

    #[derive(Clone)]
    struct DummyMpscSender<T>(PhantomData<T>);

    struct DummyMpscReceiver<T>(PhantomData<T>);

    #[derive(Clone)]
    struct DummyOneshotSender<T>(PhantomData<T>);

    #[derive(Clone)]
    struct DummyBroadcastSender<T>(PhantomData<T>);

    struct DummyBroadcastReceiver<T>(PhantomData<T>);

    #[derive(Clone)]
    struct DummyWatchSender<T>(PhantomData<T>);

    #[derive(Clone)]
    struct DummyWatchReceiver<T>(PhantomData<T>);

    struct DummyFile;

    struct DummyTcpListener;

    struct DummyTcpStream;

    struct DummyUdpSocket;

    impl<T: Send> MpscSender<T> for DummyMpscSender<T> {
        fn send(&self, _value: T) -> Pin<Box<dyn Future<Output = Result<(), T>> + Send + '_>> {
            Box::pin(async { panic!("dummy mpsc send") })
        }
    }

    impl<T: Send> MpscReceiver<T> for DummyMpscReceiver<T> {
        fn recv(&mut self) -> Pin<Box<dyn Future<Output = Option<T>> + Send + '_>> {
            Box::pin(async { panic!("dummy mpsc recv") })
        }
    }

    impl<T: Send> OneshotSender<T> for DummyOneshotSender<T> {
        fn send(self, _value: T) -> Result<(), T> {
            panic!("dummy oneshot send")
        }
    }

    impl<T: Send + Clone + 'static> BroadcastSender<T> for DummyBroadcastSender<T> {
        fn send(&self, _value: T) -> Result<usize, T> {
            panic!("dummy broadcast send")
        }

        fn subscribe(&self) -> Box<dyn BroadcastReceiver<T>> {
            Box::new(DummyBroadcastReceiver(PhantomData))
        }
    }

    impl<T: Send + Clone + 'static> BroadcastReceiver<T> for DummyBroadcastReceiver<T> {
        fn recv(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = Result<T, BroadcastRecvError>> + Send + '_>> {
            Box::pin(async { panic!("dummy broadcast recv") })
        }
    }

    impl<T: Send + Sync> WatchSender<T> for DummyWatchSender<T> {
        fn send(&self, _value: T) -> Result<(), T> {
            panic!("dummy watch send")
        }
    }

    impl<T: Send + Sync + Clone> WatchReceiver<T> for DummyWatchReceiver<T> {
        fn changed(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = Result<(), WatchRecvError>> + Send + '_>> {
            Box::pin(async { panic!("dummy watch recv") })
        }

        fn borrow_and_clone(&self) -> T {
            panic!("dummy watch borrow")
        }
    }

    impl crate::AsyncFile for DummyFile {
        fn write_all<'a>(
            &'a mut self,
            _buf: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>> {
            Box::pin(async { panic!("dummy file write") })
        }

        fn read_exact<'a>(
            &'a mut self,
            _buf: &'a mut [u8],
        ) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>> {
            Box::pin(async { panic!("dummy file read_exact") })
        }

        fn read_to_end<'a>(
            &'a mut self,
            _buf: &'a mut Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<usize>> + Send + 'a>> {
            Box::pin(async { panic!("dummy file read_to_end") })
        }

        fn seek<'a>(
            &'a mut self,
            _pos: std::io::SeekFrom,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<u64>> + Send + 'a>> {
            Box::pin(async { panic!("dummy file seek") })
        }

        fn sync_all(&self) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + '_>> {
            Box::pin(async { panic!("dummy file sync") })
        }

        fn shutdown(&mut self) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + '_>> {
            Box::pin(async { panic!("dummy file shutdown") })
        }
    }

    impl crate::TcpListener for DummyTcpListener {
        type Stream = DummyTcpStream;

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            panic!("dummy tcp local_addr")
        }

        fn accept(
            &self,
        ) -> Pin<
            Box<
                dyn Future<Output = std::io::Result<(Self::Stream, SocketAddr)>> + Send + '_,
            >,
        > {
            Box::pin(async { panic!("dummy tcp accept") })
        }
    }

    impl crate::TcpStream for DummyTcpStream {
        fn peer_addr(&self) -> std::io::Result<SocketAddr> {
            panic!("dummy tcp peer_addr")
        }

        fn read_exact<'a>(
            &'a mut self,
            _buf: &'a mut [u8],
        ) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>> {
            Box::pin(async { panic!("dummy tcp read_exact") })
        }

        fn write_all<'a>(
            &'a mut self,
            _buf: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>> {
            Box::pin(async { panic!("dummy tcp write_all") })
        }

        fn shutdown(&mut self) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + '_>> {
            Box::pin(async { panic!("dummy tcp shutdown") })
        }
    }

    impl crate::UdpSocket for DummyUdpSocket {
        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            panic!("dummy udp local_addr")
        }

        fn send_to<'a>(
            &'a self,
            _buf: &'a [u8],
            _addr: SocketAddr,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<usize>> + Send + 'a>> {
            Box::pin(async { panic!("dummy udp send_to") })
        }

        fn recv_from<'a>(
            &'a self,
            _buf: &'a mut [u8],
        ) -> Pin<Box<dyn Future<Output = std::io::Result<(usize, SocketAddr)>> + Send + 'a>> {
            Box::pin(async { panic!("dummy udp recv_from") })
        }
    }

    impl RuntimeInterface for DummyRuntime {
        type JoinHandle<T: Send + 'static> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;
        type MpscSender<T: Send + 'static> = DummyMpscSender<T>;
        type MpscReceiver<T: Send + 'static> = DummyMpscReceiver<T>;
        type OneshotSender<T: Send + 'static> = DummyOneshotSender<T>;
        type OneshotReceiver<T: Send + 'static> =
            Pin<Box<dyn Future<Output = Result<T, OneshotRecvError>> + Send>>;
        type BroadcastSender<T: Send + Clone + 'static> = DummyBroadcastSender<T>;
        type BroadcastReceiver<T: Send + Clone + 'static> = DummyBroadcastReceiver<T>;
        type WatchSender<T: Send + Sync + 'static> = DummyWatchSender<T>;
        type WatchReceiver<T: Send + Sync + Clone + 'static> = DummyWatchReceiver<T>;
        type File = DummyFile;
        type TcpListener = DummyTcpListener;
        type TcpStream = DummyTcpStream;
        type UdpSocket = DummyUdpSocket;

        fn spawn<F>(&self, future: F) -> Self::JoinHandle<F::Output>
        where
            F: Future + Send + 'static,
            F::Output: Send + 'static,
        {
            Box::pin(async move { future.await })
        }

        fn block_on<F: Future>(&self, future: F) -> F::Output {
            block_on_simple(future)
        }

        fn sleep(&self, _duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(async move {})
        }

        fn timeout<'a, F: Future + Send + 'a>(
            &'a self,
            _duration: Duration,
            future: F,
        ) -> Pin<Box<dyn Future<Output = Result<F::Output, crate::TimeoutError>> + Send + 'a>>
        where
            F::Output: Send,
        {
            Box::pin(async move { Ok(future.await) })
        }

        fn mpsc_channel<T: Send + 'static>(
            &self,
            _capacity: usize,
        ) -> (Self::MpscSender<T>, Self::MpscReceiver<T>) {
            (DummyMpscSender(PhantomData), DummyMpscReceiver(PhantomData))
        }

        fn oneshot_channel<T: Send + 'static>(
            &self,
        ) -> (Self::OneshotSender<T>, Self::OneshotReceiver<T>) {
            let receiver: Self::OneshotReceiver<T> =
                Box::pin(async { panic!("dummy oneshot recv") });
            (DummyOneshotSender(PhantomData), receiver)
        }

        fn broadcast_channel<T: Send + Clone + 'static>(
            &self,
            _capacity: usize,
        ) -> (Self::BroadcastSender<T>, Self::BroadcastReceiver<T>) {
            (
                DummyBroadcastSender(PhantomData),
                DummyBroadcastReceiver(PhantomData),
            )
        }

        fn watch_channel<T: Send + Sync + Clone + 'static>(
            &self,
            _initial: T,
        ) -> (Self::WatchSender<T>, Self::WatchReceiver<T>) {
            (DummyWatchSender(PhantomData), DummyWatchReceiver(PhantomData))
        }

        fn file_create<'a>(
            &'a self,
            _path: &'a Path,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Self::File>> + Send + 'a>> {
            Box::pin(async { panic!("dummy file create") })
        }

        fn file_open<'a>(
            &'a self,
            _path: &'a Path,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Self::File>> + Send + 'a>> {
            Box::pin(async { panic!("dummy file open") })
        }

        fn tcp_listen<'a>(
            &'a self,
            _addr: &'a str,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Self::TcpListener>> + Send + 'a>> {
            Box::pin(async { panic!("dummy tcp listen") })
        }

        fn tcp_connect<'a>(
            &'a self,
            _addr: SocketAddr,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Self::TcpStream>> + Send + 'a>> {
            Box::pin(async { panic!("dummy tcp connect") })
        }

        fn udp_bind<'a>(
            &'a self,
            _addr: &'a str,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Self::UdpSocket>> + Send + 'a>> {
            Box::pin(async { panic!("dummy udp bind") })
        }
    }

    fn block_on_simple<F: Future>(mut future: F) -> F::Output {
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        fn wake(_: *const ()) {}
        fn wake_by_ref(_: *const ()) {}
        fn drop(_: *const ()) {}

        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);

        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
        let mut context = Context::from_waker(&waker);
        let mut future = unsafe { Pin::new_unchecked(&mut future) };

        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
