//! HTTP/3 RFC 9114 conformance test suite.
//!
//! This module validates compliance with RFC 9114 requirements using systematic
//! spec-derived tests. Each test case maps to specific MUST/SHOULD clauses.

use serde::Serialize;
use std::time::{Duration, Instant};

pub mod connection_preface_tests;

/// Conformance test result for HTTP/3 RFC 9114.
#[derive(Debug, Clone, Serialize)]
pub struct H3ConformanceResult {
    /// Test identifier (RFC section reference).
    pub test_id: String,
    /// Human-readable description.
    pub description: String,
    /// Test category.
    pub category: TestCategory,
    /// Requirement level from RFC.
    pub requirement_level: RequirementLevel,
    /// Test verdict.
    pub verdict: TestVerdict,
    /// Execution time.
    pub elapsed_ms: u64,
    /// Additional notes or error details.
    pub notes: Option<String>,
}

/// HTTP/3 conformance test categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum TestCategory {
    /// Connection preface validation (RFC 9114 Section 6.1).
    ConnectionPreface,
    /// Stream type validation (RFC 9114 Section 6.2).
    StreamTypes,
    /// Control stream management (RFC 9114 Section 6.2.1).
    ControlStream,
    /// Settings frame handling (RFC 9114 Section 7.2.4).
    Settings,
    /// QPACK encoder/decoder streams (RFC 9204 Section 5.1.2).
    QpackStreams,
}

/// Requirement level from RFC keywords.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum RequirementLevel {
    /// MUST requirements (mandatory).
    Must,
    /// SHOULD requirements (recommended).
    Should,
    /// MAY requirements (optional).
    May,
}

/// Test verdict classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum TestVerdict {
    /// Test passed.
    Pass,
    /// Test failed.
    Fail,
    /// Test was skipped.
    Skipped,
    /// Expected failure (known issue).
    ExpectedFailure,
}

/// Wrapper for timed test execution.
fn timed_test<F, T>(test_fn: F) -> (Result<T, String>, u64)
where
    F: FnOnce() -> Result<T, String>,
{
    let start = Instant::now();
    let result = test_fn();
    let elapsed_ms = start.elapsed().as_millis() as u64;
    (result, elapsed_ms)
}

/// HTTP/3 conformance harness for RFC 9114.
pub struct H3ConformanceHarness {
    test_cases: Vec<Box<dyn ConformanceTest>>,
}

/// Trait for implementing HTTP/3 conformance tests.
pub trait ConformanceTest: Send + Sync {
    fn test_id(&self) -> &str;
    fn description(&self) -> &str;
    fn category(&self) -> TestCategory;
    fn requirement_level(&self) -> RequirementLevel;
    fn run(&self) -> H3ConformanceResult;
}

impl H3ConformanceHarness {
    /// Create a new HTTP/3 conformance harness.
    pub fn new() -> Self {
        Self {
            test_cases: Vec::new(),
        }
    }

    /// Run all HTTP/3 conformance tests.
    pub fn run_all_tests(&self) -> Vec<H3ConformanceResult> {
        let mut results = Vec::new();

        // Connection preface tests (RFC 9114 Section 6.1)
        results.extend(connection_preface_tests::run_connection_preface_tests());

        results
    }

    /// Get coverage report for RFC 9114 requirements.
    pub fn coverage_report(&self) -> CoverageReport {
        let results = self.run_all_tests();
        CoverageReport::generate(&results)
    }
}

/// Coverage report for conformance testing.
#[derive(Debug, Clone, Serialize)]
pub struct CoverageReport {
    /// Total number of tests.
    pub total_tests: usize,
    /// Number of passing tests.
    pub passed: usize,
    /// Number of failing tests.
    pub failed: usize,
    /// Number of skipped tests.
    pub skipped: usize,
    /// Coverage percentage for MUST requirements.
    pub must_coverage: f64,
}

impl CoverageReport {
    /// Generate a coverage report from test results.
    pub fn generate(results: &[H3ConformanceResult]) -> Self {
        let total_tests = results.len();
        let passed = results.iter().filter(|r| r.verdict == TestVerdict::Pass).count();
        let failed = results.iter().filter(|r| r.verdict == TestVerdict::Fail).count();
        let skipped = results.iter().filter(|r| r.verdict == TestVerdict::Skipped).count();

        let must_tests: Vec<_> = results.iter()
            .filter(|r| r.requirement_level == RequirementLevel::Must)
            .collect();
        let must_passed = must_tests.iter()
            .filter(|r| r.verdict == TestVerdict::Pass)
            .count();

        let must_coverage = if !must_tests.is_empty() {
            (must_passed as f64 / must_tests.len() as f64) * 100.0
        } else {
            0.0
        };

        Self {
            total_tests,
            passed,
            failed,
            skipped,
            must_coverage,
        }
    }
}

impl Default for H3ConformanceHarness {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_h3_conformance_harness_integration() {
        let harness = H3ConformanceHarness::new();
        let results = harness.run_all_tests();

        // Verify we have all expected tests
        assert_eq!(results.len(), 4, "Should have 4 connection preface tests");

        // Verify all tests have proper structure
        for result in &results {
            assert!(!result.test_id.is_empty());
            assert!(!result.description.is_empty());
            assert_eq!(result.requirement_level, RequirementLevel::Must);
            assert!(result.elapsed_ms > 0);
        }

        // Verify test IDs are unique
        let mut test_ids: Vec<&str> = results.iter().map(|r| r.test_id.as_str()).collect();
        test_ids.sort();
        test_ids.dedup();
        assert_eq!(test_ids.len(), 4, "All test IDs should be unique");

        // Verify coverage report
        let coverage = harness.coverage_report();
        assert_eq!(coverage.total_tests, 4);
        assert!(coverage.must_coverage >= 0.0);
    }

    #[test]
    fn test_h3_conformance_categories() {
        let harness = H3ConformanceHarness::new();
        let results = harness.run_all_tests();

        // Verify we have tests for all major categories
        let categories: std::collections::HashSet<TestCategory> = results
            .iter()
            .map(|r| r.category)
            .collect();

        assert!(categories.contains(&TestCategory::ConnectionPreface));
        assert!(categories.contains(&TestCategory::Settings));
        assert!(categories.contains(&TestCategory::StreamTypes));
    }
}