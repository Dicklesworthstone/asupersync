//! RaptorQ Differential Testing Framework
//!
//! This crate implements Pattern 1 (Differential Testing) from the conformance
//! harness methodology. It provides byte-for-byte comparison with canonical
//! RaptorQ reference implementations for cross-implementation conformance validation.
//!
//! # Overview
//!
//! The framework consists of:
//! - **Reference Integration**: Calls to external reference implementations
//! - **Fixture Management**: Golden files with reference implementation outputs
//! - **Differential Testing**: Byte-level comparison of encode/decode results
//! - **Provenance Tracking**: Version and command tracking for fixture regeneration
//!
//! # Usage
//!
//! ```rust,no_run
//! use raptorq_differential::*;
//!
//! // Load and run differential tests
//! let harness = DifferentialHarness::new("tests/fixtures");
//! let results = harness.run_all_tests().unwrap();
//!
//! // Generate new fixtures from reference implementation
//! let generator = FixtureGenerator::new();
//! generator.generate_reference_fixtures("path/to/reference").unwrap();
//! ```

pub mod reference_integration;
pub mod fixture_loader;
pub mod differential_tests;
pub mod provenance;

// Re-export main types for convenience
pub use reference_integration::{
    ReferenceImplementation, ReferenceOutput, ReferenceError, ImplementationInfo,
};
pub use fixture_loader::{
    FixtureLoader, FixtureSet, FixtureEntry, FixtureMetadata, FixtureError,
};
pub use differential_tests::{
    DifferentialHarness, DifferentialTest, DifferentialResult, ComparisonStats,
    TestSuite, TestCase, TestParameters,
};
pub use provenance::{
    ProvenanceTracker, GenerationInfo, FixtureProvenance, ProvenanceError,
};

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::collections::HashMap;

/// Main entry point for running the complete differential test suite
pub fn run_differential_suite<P: AsRef<Path>>(fixture_dir: P) -> Result<DifferentialSuiteResults, DifferentialSuiteError> {
    let harness = DifferentialHarness::new(fixture_dir)?;
    let results = harness.run_all_tests()?;

    Ok(DifferentialSuiteResults {
        total_tests: results.total_tests(),
        passed_tests: results.passed_tests(),
        failed_tests: results.failed_tests(),
        test_results: results,
        comparison_stats: harness.get_comparison_stats(),
    })
}

/// Results from running the complete differential test suite
#[derive(Debug, Clone)]
pub struct DifferentialSuiteResults {
    /// Total number of tests executed
    pub total_tests: usize,
    /// Number of tests that passed
    pub passed_tests: usize,
    /// Number of tests that failed
    pub failed_tests: usize,
    /// Detailed test results
    pub test_results: DifferentialResult,
    /// Comparison statistics
    pub comparison_stats: ComparisonStats,
}

impl DifferentialSuiteResults {
    /// Returns true if all tests passed
    pub fn is_success(&self) -> bool {
        self.failed_tests == 0 && self.total_tests > 0
    }

    /// Returns the pass rate as a percentage
    pub fn pass_rate(&self) -> f64 {
        if self.total_tests == 0 {
            0.0
        } else {
            (self.passed_tests as f64 / self.total_tests as f64) * 100.0
        }
    }

    /// Generates a summary report
    pub fn summary_report(&self) -> String {
        format!(
            "RaptorQ Differential Testing Results\n\
            ===================================\n\
            \n\
            Tests: {}/{} passed ({:.1}%)\n\
            Bytes compared: {}\n\
            Mismatches: {}\n\
            Average comparison time: {:?}\n\
            \n\
            Status: {}\n",
            self.passed_tests,
            self.total_tests,
            self.pass_rate(),
            self.comparison_stats.total_bytes_compared,
            self.comparison_stats.total_mismatches,
            self.comparison_stats.average_comparison_time,
            if self.is_success() { "✅ ALL TESTS PASSED" } else { "❌ SOME TESTS FAILED" }
        )
    }
}

/// Errors that can occur during differential test suite execution
#[derive(Debug, thiserror::Error)]
pub enum DifferentialSuiteError {
    #[error("Harness initialization failed: {0}")]
    HarnessInit(#[from] DifferentialHarnessError),

    #[error("Test execution failed: {0}")]
    TestExecution(String),

    #[error("Fixture loading failed: {0}")]
    FixtureLoading(#[from] FixtureError),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Errors that can occur during differential harness operations
#[derive(Debug, thiserror::Error)]
pub enum DifferentialHarnessError {
    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Reference implementation not found: {0}")]
    ReferenceNotFound(String),

    #[error("Invalid fixture directory: {0}")]
    InvalidFixtureDirectory(String),
}

/// Configuration for differential testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialConfig {
    /// Path to reference implementation binary
    pub reference_binary: Option<String>,
    /// Maximum allowed byte mismatches before test fails
    pub max_allowed_mismatches: usize,
    /// Timeout for reference implementation calls (seconds)
    pub reference_timeout_secs: u64,
    /// Whether to generate new fixtures if missing
    pub generate_missing_fixtures: bool,
    /// Test case filtering patterns
    pub test_filters: Vec<String>,
    /// Parallel test execution
    pub parallel_execution: bool,
}

impl Default for DifferentialConfig {
    fn default() -> Self {
        Self {
            reference_binary: None,
            max_allowed_mismatches: 0, // Strict by default
            reference_timeout_secs: 30,
            generate_missing_fixtures: false,
            test_filters: vec![],
            parallel_execution: true,
        }
    }
}

/// Convenience function for running a single differential test
pub fn run_single_test<P: AsRef<Path>>(
    fixture_path: P,
    our_implementation_result: &[u8]
) -> Result<bool, DifferentialSuiteError> {
    let loader = FixtureLoader::new();
    let fixture = loader.load_fixture(fixture_path)?;

    let matches = fixture.reference_output == our_implementation_result;

    if !matches {
        eprintln!(
            "Differential test failed:\n  Expected {} bytes\n  Got {} bytes\n  First mismatch at byte {}",
            fixture.reference_output.len(),
            our_implementation_result.len(),
            find_first_mismatch(&fixture.reference_output, our_implementation_result).unwrap_or(0)
        );
    }

    Ok(matches)
}

/// Finds the first byte position where two byte arrays differ
fn find_first_mismatch(expected: &[u8], actual: &[u8]) -> Option<usize> {
    expected.iter()
        .zip(actual.iter())
        .enumerate()
        .find_map(|(i, (a, b))| if a != b { Some(i) } else { None })
        .or_else(|| {
            // Check for length differences
            if expected.len() != actual.len() {
                Some(std::cmp::min(expected.len(), actual.len()))
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_differential_config_default() {
        let config = DifferentialConfig::default();
        assert_eq!(config.max_allowed_mismatches, 0);
        assert_eq!(config.reference_timeout_secs, 30);
        assert!(!config.generate_missing_fixtures);
        assert!(config.parallel_execution);
    }

    #[test]
    fn test_find_first_mismatch() {
        let a = b"hello world";
        let b = b"hello earth";

        assert_eq!(find_first_mismatch(a, b), Some(6));
        assert_eq!(find_first_mismatch(a, a), None);

        let c = b"hello";
        assert_eq!(find_first_mismatch(a, c), Some(5));
    }

    #[test]
    fn test_suite_results_pass_rate() {
        let results = DifferentialSuiteResults {
            total_tests: 10,
            passed_tests: 8,
            failed_tests: 2,
            test_results: DifferentialResult::default(),
            comparison_stats: ComparisonStats::default(),
        };

        assert_eq!(results.pass_rate(), 80.0);
        assert!(!results.is_success());
    }

    #[test]
    fn test_suite_results_success() {
        let results = DifferentialSuiteResults {
            total_tests: 5,
            passed_tests: 5,
            failed_tests: 0,
            test_results: DifferentialResult::default(),
            comparison_stats: ComparisonStats::default(),
        };

        assert_eq!(results.pass_rate(), 100.0);
        assert!(results.is_success());
    }

    #[test]
    fn test_single_test_success() {
        let temp_dir = TempDir::new().unwrap();
        // This would test the single test runner, but requires fixture setup
        // Left as integration test placeholder
    }
}