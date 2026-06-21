//! Conformance test harness infrastructure for runtime+scheduler components.
//!
//! Provides the core types and utilities for building spec-derived conformance
//! test matrices across the runtime+scheduler domain.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Test verdict for conformance checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestVerdict {
    Pass,
    Fail(String),
    Skip(String),
    ExpectedGap(String), // Documented divergence.
}

/// RFC-style requirement levels for coverage tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementLevel {
    Must,   // MUST comply - critical for correctness
    Should, // SHOULD comply - best practice
    May,    // MAY implement - optional feature
}

impl RequirementLevel {
    /// Returns the weight of this requirement level for scoring.
    pub fn weight(self) -> f64 {
        match self {
            Self::Must => 1.0,
            Self::Should => 0.5,
            Self::May => 0.1,
        }
    }
}

/// Test categories for organizational purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TestCategory {
    // Remote execution categories
    DistributedStructuredConcurrency,
    NamedComputationContract,
    RemoteCapabilityModel,
    RemoteLeaseManagement,
    RemoteMessageProtocol,
    RemoteTaskLifecycle,

    // Kernel categories
    SnapshotContract,
    ControllerRegistration,
    VersionCompatibility,
    ObservabilityContract,

    // Reactor categories
    IoEventNotification,
    RegistrationLifecycle,
    EdgeTriggeredMode,
    ThreadSafety,
    PlatformAbstraction,

    // Scheduler categories
    TaskExecution,
    WorkStealing,
    LoadBalancing,
    PriorityScheduling,
    CancellationLane,
    TaskPoolManagement,
    PanicIsolation,
    MetricsCollection,
}

/// Test result with metadata.
#[derive(Debug, Clone)]
pub struct ConformanceTestResult {
    pub test_name: &'static str,
    pub requirement_level: RequirementLevel,
    pub category: TestCategory,
    pub verdict: TestVerdict,
    pub spec_section: Option<&'static str>,
    pub duration_micros: Option<u64>,
}

impl ConformanceTestResult {
    /// Creates a new passing test result.
    pub fn pass(test_name: &'static str, level: RequirementLevel, category: TestCategory) -> Self {
        Self {
            test_name,
            requirement_level: level,
            category,
            verdict: TestVerdict::Pass,
            spec_section: None,
            duration_micros: None,
        }
    }

    /// Creates a new failing test result.
    pub fn fail(
        test_name: &'static str,
        level: RequirementLevel,
        category: TestCategory,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            test_name,
            requirement_level: level,
            category,
            verdict: TestVerdict::Fail(reason.into()),
            spec_section: None,
            duration_micros: None,
        }
    }

    /// Creates a new documented-gap test result.
    pub fn expected_gap(
        test_name: &'static str,
        level: RequirementLevel,
        category: TestCategory,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            test_name,
            requirement_level: level,
            category,
            verdict: TestVerdict::ExpectedGap(reason.into()),
            spec_section: None,
            duration_micros: None,
        }
    }

    /// Adds spec section information.
    pub fn with_spec_section(mut self, section: &'static str) -> Self {
        self.spec_section = Some(section);
        self
    }

    /// Adds execution duration.
    pub fn with_duration(mut self, micros: u64) -> Self {
        self.duration_micros = Some(micros);
        self
    }

    /// Returns true if this test passed or is a documented gap.
    pub fn is_successful(&self) -> bool {
        matches!(
            self.verdict,
            TestVerdict::Pass | TestVerdict::ExpectedGap(_)
        )
    }

    /// Returns true if this is a hard failure (not expected).
    pub fn is_hard_failure(&self) -> bool {
        matches!(self.verdict, TestVerdict::Fail(_))
    }
}

/// Coverage statistics for a conformance test suite.
#[derive(Debug, Clone)]
pub struct CoverageStats {
    pub total_tests: usize,
    pub passing: usize,
    pub failing: usize,
    pub expected_failures: usize,
    pub skipped: usize,
    pub must_score: f64,
    pub should_score: f64,
    pub may_score: f64,
}

impl CoverageStats {
    /// Calculate coverage statistics from test results.
    pub fn from_results(results: &[ConformanceTestResult]) -> Self {
        let total_tests = results.len();
        let passing = results
            .iter()
            .filter(|r| matches!(r.verdict, TestVerdict::Pass))
            .count();
        let failing = results
            .iter()
            .filter(|r| matches!(r.verdict, TestVerdict::Fail(_)))
            .count();
        let expected_failures = results
            .iter()
            .filter(|r| matches!(r.verdict, TestVerdict::ExpectedGap(_)))
            .count();
        let skipped = results
            .iter()
            .filter(|r| matches!(r.verdict, TestVerdict::Skip(_)))
            .count();

        let (must_pass, must_total) = Self::count_by_level(results, RequirementLevel::Must);
        let (should_pass, should_total) = Self::count_by_level(results, RequirementLevel::Should);
        let (may_pass, may_total) = Self::count_by_level(results, RequirementLevel::May);

        let must_score = if must_total > 0 {
            must_pass as f64 / must_total as f64
        } else {
            1.0
        };
        let should_score = if should_total > 0 {
            should_pass as f64 / should_total as f64
        } else {
            1.0
        };
        let may_score = if may_total > 0 {
            may_pass as f64 / may_total as f64
        } else {
            1.0
        };

        Self {
            total_tests,
            passing,
            failing,
            expected_failures,
            skipped,
            must_score,
            should_score,
            may_score,
        }
    }

    fn count_by_level(
        results: &[ConformanceTestResult],
        level: RequirementLevel,
    ) -> (usize, usize) {
        let level_results: Vec<_> = results
            .iter()
            .filter(|r| r.requirement_level == level)
            .collect();
        let passed = level_results.iter().filter(|r| r.is_successful()).count();
        (passed, level_results.len())
    }

    /// Returns true if the test suite meets minimum conformance thresholds.
    pub fn is_conformant(&self) -> bool {
        // MUST requirements need 95%+ compliance
        self.must_score >= 0.95 && self.failing == 0
    }

    /// Generate a coverage report markdown.
    pub fn generate_report(&self) -> String {
        format!(
            "# Runtime+Scheduler Conformance Report\n\n\
            ## Summary\n\n\
            - **Total tests**: {}\n\
            - **Passing**: {}\n\
            - **Failing**: {}\n\
            - **Expected failures**: {}\n\
            - **Skipped**: {}\n\n\
            ## Compliance Scores\n\n\
            | Level | Score | Status |\n\
            |-------|-------|--------|\n\
            | MUST | {:.1}% | {} |\n\
            | SHOULD | {:.1}% | {} |\n\
            | MAY | {:.1}% | {} |\n\n\
            ## Overall Conformance: {}\n\n\
            ## Detailed Test Results\n\n\
            Detailed per-test rows are exposed by the harness result vectors; \
            this aggregate report intentionally carries summary counts and \
            compliance scores only.\n",
            self.total_tests,
            self.passing,
            self.failing,
            self.expected_failures,
            self.skipped,
            self.must_score * 100.0,
            if self.must_score >= 0.95 {
                "✅"
            } else {
                "❌"
            },
            self.should_score * 100.0,
            if self.should_score >= 0.80 {
                "✅"
            } else {
                "❌"
            },
            self.may_score * 100.0,
            if self.may_score >= 0.50 { "✅" } else { "❌" },
            if self.is_conformant() {
                "✅ CONFORMANT"
            } else {
                "❌ NON-CONFORMANT"
            }
        )
    }
}

/// Deterministic time provider for testing.
#[derive(Debug, Clone)]
pub struct MockTime {
    current: Arc<std::sync::Mutex<asupersync::types::Time>>,
}

impl MockTime {
    pub fn new() -> Self {
        Self {
            current: Arc::new(std::sync::Mutex::new(asupersync::types::Time::from_nanos(
                0,
            ))),
        }
    }

    pub fn advance(&self, duration: Duration) {
        let mut current = self.current.lock().unwrap();
        *current = *current + duration;
    }

    pub fn now(&self) -> asupersync::types::Time {
        *self.current.lock().unwrap()
    }
}

/// Main conformance test harness for runtime+scheduler components.
pub struct RuntimeConformanceHarness {
    mock_time: MockTime,
    test_counter: Arc<AtomicUsize>,
}

impl RuntimeConformanceHarness {
    /// Create a new runtime conformance test harness.
    pub fn new() -> Self {
        Self {
            mock_time: MockTime::new(),
            test_counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Get the next test sequence number.
    pub fn next_test_id(&self) -> usize {
        self.test_counter.fetch_add(1, Ordering::SeqCst)
    }

    /// Get the deterministic time provider.
    pub fn time(&self) -> &MockTime {
        &self.mock_time
    }

    /// Run a single conformance test with timing.
    pub fn run_test<F>(
        &self,
        test_fn: F,
        name: &'static str,
        level: RequirementLevel,
        category: TestCategory,
    ) -> ConformanceTestResult
    where
        F: FnOnce() -> TestVerdict,
    {
        let start = std::time::Instant::now();
        let verdict = test_fn();
        let duration = start.elapsed();

        ConformanceTestResult {
            test_name: name,
            requirement_level: level,
            category,
            verdict,
            spec_section: None,
            duration_micros: Some(duration.as_micros() as u64),
        }
    }

    /// Verify a condition and return appropriate verdict.
    pub fn verify(&self, condition: bool, failure_message: &str) -> TestVerdict {
        if condition {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail(failure_message.into())
        }
    }
}

impl Default for RuntimeConformanceHarness {
    fn default() -> Self {
        Self::new()
    }
}

/// Run every runtime-side conformance harness and return one aggregate result set.
///
/// `tests/conformance/mod.rs` consumes this function when it builds the overall
/// conformance report. Keeping the aggregation here avoids duplicating the
/// runtime/kernel/reactor/remote/scheduler grouping logic in the report layer.
pub fn run_full_runtime_conformance_suite() -> Vec<ConformanceTestResult> {
    let mut results = Vec::new();

    let mut kernel_harness = super::kernel_conformance::KernelConformanceHarness::new();
    results.extend(kernel_harness.run_full_suite());

    let mut reactor_harness = super::reactor_conformance::ReactorConformanceHarness::new();
    results.extend(reactor_harness.run_full_suite());

    let mut remote_harness = super::remote_conformance::RemoteConformanceHarness::new();
    results.extend(remote_harness.run_full_suite());

    let mut scheduler_harness = super::scheduler_conformance::SchedulerConformanceHarness::new();
    results.extend(scheduler_harness.run_full_suite());

    results
}

/// Run the full runtime+scheduler conformance suite and return its markdown
/// report. Free-function wrapper for callers that want a one-shot "produce a
/// report" entry point without depending on `CoverageStats` plumbing.
pub fn generate_conformance_report() -> String {
    let results = run_full_runtime_conformance_suite();
    let stats = CoverageStats::from_results(&results);
    stats.generate_report()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_stats_calculation() {
        let results = vec![
            ConformanceTestResult::pass(
                "test1",
                RequirementLevel::Must,
                TestCategory::TaskExecution,
            ),
            ConformanceTestResult::fail(
                "test2",
                RequirementLevel::Must,
                TestCategory::TaskExecution,
                "failed",
            ),
            ConformanceTestResult::expected_gap(
                "test3",
                RequirementLevel::Should,
                TestCategory::WorkStealing,
                "known issue",
            ),
        ];

        let stats = CoverageStats::from_results(&results);
        assert_eq!(stats.total_tests, 3);
        assert_eq!(stats.passing, 1);
        assert_eq!(stats.failing, 1);
        assert_eq!(stats.expected_failures, 1);
        assert_eq!(stats.must_score, 0.5); // 1/2 MUST tests passed
    }

    #[test]
    fn conformance_thresholds() {
        let passing_results = vec![
            ConformanceTestResult::pass(
                "test1",
                RequirementLevel::Must,
                TestCategory::TaskExecution,
            ),
            ConformanceTestResult::pass(
                "test2",
                RequirementLevel::Must,
                TestCategory::TaskExecution,
            ),
        ];
        let passing_stats = CoverageStats::from_results(&passing_results);
        assert!(passing_stats.is_conformant());

        let failing_results = vec![
            ConformanceTestResult::pass(
                "test1",
                RequirementLevel::Must,
                TestCategory::TaskExecution,
            ),
            ConformanceTestResult::fail(
                "test2",
                RequirementLevel::Must,
                TestCategory::TaskExecution,
                "failed",
            ),
        ];
        let failing_stats = CoverageStats::from_results(&failing_results);
        assert!(!failing_stats.is_conformant()); // 50% MUST score < 95%
    }

    #[test]
    fn mock_time_advancement() {
        let mock_time = MockTime::new();
        let initial = mock_time.now();

        mock_time.advance(Duration::from_millis(100));
        let after = mock_time.now();

        assert!(after > initial);
    }
}
