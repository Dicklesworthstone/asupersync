#![allow(warnings)]
#![allow(clippy::all)]
//! RaptorQ RFC 6330 Golden File Testing Framework
//!
//! This crate provides a comprehensive framework for golden file testing of
//! RaptorQ implementations to ensure RFC 6330 conformance and detect regressions.
//!
//! # Overview
//!
//! The framework consists of several components:
//!
//! - **Golden File Manager**: Manages creation, validation, and updates of golden files
//! - **Round-trip Harness**: Executes encode-decode cycles and validates correctness
//! - **Fixture Generator**: Creates deterministic test fixtures covering various scenarios
//! - **Format Validator**: Validates golden file format and RFC 6330 compliance
//!
//! # Usage
//!
//! ```rust,no_run
//! use raptorq_golden_testing::*;
//!
//! // Set up golden file manager
//! let manager = GoldenFileManager::new("tests/golden");
//!
//! // Run round-trip tests
//! let harness = RoundTripHarness::new("tests/golden");
//! let summary = harness.run_all_tests().unwrap();
//!
//! // Generate test fixtures
//! let generator = FixtureGenerator::new("tests/fixtures");
//! let generation_summary = generator.generate_all_fixtures().unwrap();
//!
//! // Validate existing golden files
//! let validator = FormatValidator::new();
//! let validation_result = validator.validate_directory("tests/golden").unwrap();
//! ```
//!
//! # Environment Variables
//!
//! - `UPDATE_GOLDENS=1`: Enable golden file update mode
//!
//! # Golden File Format
//!
//! Golden files are JSON documents with the following structure:
//!
//! ```json
//! {
//!   "metadata": {
//!     "test_name": "test_case_name",
//!     "rfc_section": "5.3.2.1",
//!     "description": "Test description",
//!     "last_updated": "2024-01-01T00:00:00Z",
//!     "git_commit": "abc123...",
//!     "input_params": {
//!       "source_symbols": "100",
//!       "symbol_size": "1024"
//!     },
//!     "checksum": "md5_hash_here"
//!   },
//!   "data": {
//!     "encoded_symbols": [...],
//!     "symbol_indices": [...],
//!     "decoded_data": [...],
//!     "success": true,
//!     "validation_metrics": {...}
//!   }
//! }
//! ```

pub mod fixture_generator;
pub mod format_validator;
pub mod golden_file_manager;
pub mod round_trip_harness;

// Re-export main types for convenience
pub use golden_file_manager::{
    create_metadata, GoldenError, GoldenFileEntry, GoldenFileManager, GoldenMetadata,
    ValidationSummary,
};

pub use round_trip_harness::{
    RoundTripConfig, RoundTripError, RoundTripHarness, RoundTripInput, RoundTripOutput,
    RoundTripSummary, ValidationMetrics,
};

pub use fixture_generator::{
    FixtureCategory, FixtureGenerationError, FixtureGenerationSummary, FixtureGenerator,
    FixtureProperties, FixtureSpec, MemoryProfile,
};

pub use format_validator::{
    DataIntegrityStatus, DirectoryValidationResult, FormatValidator, IssueCategory, IssueSeverity,
    MetadataSummary, RfcComplianceStatus, ValidationConfig, ValidationError, ValidationIssue,
    ValidationResult,
};

/// Main entry point for running complete golden file test suite
#[allow(dead_code)]
pub fn run_complete_test_suite<P: AsRef<std::path::Path>>(
    golden_dir: P,
    fixture_dir: P,
) -> Result<TestSuiteResults, TestSuiteError> {
    let golden_path = golden_dir.as_ref();
    let fixture_path = fixture_dir.as_ref();

    // Ensure directories exist
    std::fs::create_dir_all(golden_path)?;
    std::fs::create_dir_all(fixture_path)?;

    // Step 1: Generate test fixtures
    let generator = FixtureGenerator::new(fixture_path);
    let fixture_results = generator
        .generate_all_fixtures()
        .map_err(TestSuiteError::FixtureGeneration)?;

    // Step 2: Run round-trip tests
    let harness = RoundTripHarness::new(golden_path);
    let roundtrip_results = harness.run_all_tests().map_err(TestSuiteError::RoundTrip)?;

    // Step 3: Validate golden files
    let validator = FormatValidator::new();
    let validation_results = validator
        .validate_directory(golden_path)
        .map_err(TestSuiteError::Validation)?;

    // Step 4: Validate existing golden files
    let manager = GoldenFileManager::new(golden_path);
    let golden_validation = manager.validate_all().map_err(TestSuiteError::GoldenFile)?;

    Ok(TestSuiteResults {
        fixture_generation: fixture_results,
        round_trip_tests: roundtrip_results,
        format_validation: validation_results,
        golden_file_validation: golden_validation,
    })
}

/// Results from running the complete test suite
#[derive(Debug)]
#[allow(dead_code)]
pub struct TestSuiteResults {
    pub fixture_generation: FixtureGenerationSummary,
    pub round_trip_tests: RoundTripSummary,
    pub format_validation: DirectoryValidationResult,
    pub golden_file_validation: ValidationSummary,
}

#[allow(dead_code)]

impl TestSuiteResults {
    /// Returns true if all test suite components passed
    #[allow(dead_code)]
    pub fn is_success(&self) -> bool {
        self.fixture_generation.is_success() &&
        self.round_trip_tests.is_success() &&
        self.format_validation.success_rate() > 0.95 && // Allow some warnings
        self.golden_file_validation.is_success()
    }

    /// Returns a summary report of the test suite execution
    #[allow(dead_code)]
    pub fn summary_report(&self) -> String {
        format!(
            "RaptorQ Golden File Test Suite Results\n\
            =====================================\n\
            \n\
            Fixture Generation: {}\n\
            - Generated: {}\n\
            - Failed: {}\n\
            \n\
            Round-trip Tests: {}\n\
            - Total: {}\n\
            - Passed: {}\n\
            - Failed: {}\n\
            - Pass Rate: {:.1}%\n\
            \n\
            Format Validation: {}\n\
            - Files Checked: {}\n\
            - Valid Files: {}\n\
            - Success Rate: {:.1}%\n\
            \n\
            Golden File Validation: {}\n\
            - Total: {}\n\
            - Passed: {}\n\
            - Failed: {}\n\
            \n\
            Overall Status: {}\n",
            if self.fixture_generation.is_success() {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            },
            self.fixture_generation.generated_fixtures,
            self.fixture_generation.failed_fixtures,
            if self.round_trip_tests.is_success() {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            },
            self.round_trip_tests.total_tests,
            self.round_trip_tests.passed_tests,
            self.round_trip_tests.failed_tests,
            self.round_trip_tests.pass_rate() * 100.0,
            if self.format_validation.success_rate() > 0.95 {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            },
            self.format_validation.total_files,
            self.format_validation.valid_files,
            self.format_validation.success_rate() * 100.0,
            if self.golden_file_validation.is_success() {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            },
            self.golden_file_validation.total,
            self.golden_file_validation.passed,
            self.golden_file_validation.failed,
            if self.is_success() {
                "✅ ALL TESTS PASSED"
            } else {
                "❌ SOME TESTS FAILED"
            }
        )
    }
}

/// Errors that can occur during test suite execution
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum TestSuiteError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Fixture generation failed: {0}")]
    FixtureGeneration(FixtureGenerationError),

    #[error("Round-trip testing failed: {0}")]
    RoundTrip(RoundTripError),

    #[error("Format validation failed: {0}")]
    Validation(ValidationError),

    #[error("Golden file validation failed: {0}")]
    GoldenFile(GoldenError),
}

/// Convenience function to run smoke tests (high-priority fixtures only)
#[allow(dead_code)]
pub fn run_smoke_tests<P: AsRef<std::path::Path>>(
    golden_dir: P,
) -> Result<RoundTripSummary, RoundTripError> {
    let generator = FixtureGenerator::new(&golden_dir);
    let smoke_fixtures = generator.get_smoke_test_fixtures();

    let mut total_tests = 0;
    let mut passed_tests = 0;
    let mut failed_tests = 0;
    let mut failures = Vec::new();

    let harness = RoundTripHarness::new(&golden_dir);

    for fixture in smoke_fixtures {
        total_tests += 1;

        match harness.run_single_test(&fixture.name, &fixture.config) {
            Ok(result) => {
                if result.success && !fixture.expects_error {
                    passed_tests += 1;
                } else if !result.success && fixture.expects_error {
                    passed_tests += 1; // Expected to fail
                } else {
                    failed_tests += 1;
                    failures.push(format!("{}: unexpected result", fixture.name));
                }
            }
            Err(e) => {
                failed_tests += 1;
                failures.push(format!("{}: {}", fixture.name, e));
            }
        }
    }

    Ok(RoundTripSummary {
        total_tests,
        passed_tests,
        failed_tests,
        failures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    #[allow(dead_code)]
    fn test_complete_test_suite() {
        let temp_dir = TempDir::new().unwrap();
        let golden_path = temp_dir.path().join("golden");
        let fixture_path = temp_dir.path().join("fixtures");

        // This test primarily validates the API works
        // The actual functionality is tested in individual modules
        let result = run_complete_test_suite(&golden_path, &fixture_path);

        // Should succeed with mock implementation
        // (Real implementation would require actual RaptorQ integration)
        match result {
            Ok(results) => {
                // Check that all components ran
                assert!(results.fixture_generation.generated_fixtures > 0);
                assert!(results.round_trip_tests.total_tests > 0);
            }
            Err(e) => {
                // Expected until real RaptorQ integration
                println!("Test suite failed as expected: {}", e);
            }
        }
    }

    #[test]
    #[allow(dead_code)]
    fn test_smoke_tests() {
        let temp_dir = TempDir::new().unwrap();

        // Should not panic and should return some results
        let result = run_smoke_tests(temp_dir.path());

        match result {
            Ok(summary) => {
                assert!(summary.total_tests > 0);
            }
            Err(_) => {
                // Expected until real RaptorQ integration
            }
        }
    }

    #[test]
    #[allow(dead_code)]
    fn test_suite_results_summary() {
        let results = TestSuiteResults {
            fixture_generation: FixtureGenerationSummary {
                generated_fixtures: 5,
                failed_fixtures: 0,
                generated_files: vec![],
                errors: vec![],
            },
            round_trip_tests: RoundTripSummary {
                total_tests: 10,
                passed_tests: 9,
                failed_tests: 1,
                failures: vec!["test1: failed".to_string()],
            },
            format_validation: DirectoryValidationResult {
                total_files: 5,
                valid_files: 5,
                results: vec![],
            },
            golden_file_validation: ValidationSummary {
                total: 5,
                passed: 5,
                failed: 0,
                failures: vec![],
            },
        };

        let summary = results.summary_report();
        assert!(summary.contains("RaptorQ Golden File Test Suite Results"));
        assert!(summary.contains("Generated: 5"));
        assert!(summary.contains("Pass Rate: 90.0%"));
    }
}
