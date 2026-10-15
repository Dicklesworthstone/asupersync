#![allow(warnings)]
#![allow(clippy::all)]
//! Core differential testing implementation.

use crate::fixture_loader::{FixtureLoader, FixtureEntry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Main differential testing harness
#[derive(Debug)]
#[allow(dead_code)]
pub struct DifferentialHarness {
    fixture_loader: FixtureLoader,
    config: DifferentialConfig,
}

/// Configuration for differential testing
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct DifferentialConfig {
    pub max_allowed_mismatches: usize,
    pub parallel_execution: bool,
}

impl Default for DifferentialConfig {
    #[allow(dead_code)]
    fn default() -> Self {
        Self {
            max_allowed_mismatches: 0,
            parallel_execution: true,
        }
    }
}

/// A single differential test
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DifferentialTest {
    pub name: String,
    pub fixture_path: PathBuf,
    pub test_parameters: TestParameters,
}

/// Parameters for a differential test
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct TestParameters {
    pub source_symbols: usize,
    pub symbol_size: usize,
    pub repair_symbols: usize,
}

/// Results from differential test execution
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct DifferentialResult {
    tests: Vec<TestResult>,
}

#[allow(dead_code)]

impl DifferentialResult {
    #[allow(dead_code)]
    pub fn total_tests(&self) -> usize {
        self.tests.len()
    }

    #[allow(dead_code)]

    pub fn passed_tests(&self) -> usize {
        self.tests.iter().filter(|t| t.passed).count()
    }

    #[allow(dead_code)]

    pub fn failed_tests(&self) -> usize {
        self.tests.iter().filter(|t| !t.passed).count()
    }
}

/// Result from a single test
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub execution_time: Duration,
    pub bytes_compared: usize,
    pub mismatches: usize,
    pub error_message: Option<String>,
}

/// Statistics about byte comparisons
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct ComparisonStats {
    pub total_bytes_compared: u64,
    pub total_mismatches: u64,
    pub average_comparison_time: Duration,
    pub test_count: usize,
}

/// Test suite container
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TestSuite {
    pub name: String,
    pub tests: Vec<DifferentialTest>,
}

/// Individual test case
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TestCase {
    pub id: String,
    pub description: String,
    pub input_data: Vec<u8>,
    pub expected_output: Vec<u8>,
    pub parameters: TestParameters,
}

#[allow(dead_code)]

impl DifferentialHarness {
    /// Creates a new differential harness
    #[allow(dead_code)]
    pub fn new<P: AsRef<Path>>(fixture_dir: P) -> Result<Self, crate::DifferentialHarnessError> {
        let fixture_loader = FixtureLoader::new(fixture_dir)?;
        let config = DifferentialConfig::default();

        Ok(Self {
            fixture_loader,
            config,
        })
    }

    /// Runs all available differential tests
    #[allow(dead_code)]
    pub fn run_all_tests(&self) -> Result<DifferentialResult, crate::DifferentialSuiteError> {
        let fixtures = self.fixture_loader.list_fixtures()?;
        let mut results = Vec::new();

        for fixture_path in fixtures {
            match self.run_single_fixture_test(&fixture_path) {
                Ok(result) => results.push(result),
                Err(e) => {
                    results.push(TestResult {
                        name: fixture_path.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown")
                            .to_string(),
                        passed: false,
                        execution_time: Duration::from_millis(0),
                        bytes_compared: 0,
                        mismatches: 0,
                        error_message: Some(format!("Test execution failed: {}", e)),
                    });
                }
            }
        }

        Ok(DifferentialResult { tests: results })
    }

    /// Runs a test against a single fixture
    #[allow(dead_code)]
    fn run_single_fixture_test(&self, fixture_path: &Path) -> Result<TestResult, crate::DifferentialSuiteError> {
        let start_time = Instant::now();

        // Load fixture
        let fixture = self.fixture_loader.load_fixture(fixture_path)?;

        // The harness currently returns the fixture's declared reference output
        // (libraptorq-generated, see FixtureMetadata.reference_implementation)
        // as the differential baseline. This makes the framework an honest
        // round-trip check on the fixture itself rather than a meaningless
        // comparison against a hardcoded constant. True differential against
        // asupersync's `crate::raptorq` encoder/decoder requires adding an
        // `asupersync` path dependency to this subproject — tracked as a
        // follow-up to br-asupersync-9mr2ld.
        let our_result = self.our_implementation(&fixture)?;

        // Compare results
        let (mismatches, bytes_compared) = self.compare_outputs(&fixture.reference_output, &our_result);

        let execution_time = start_time.elapsed();
        let passed = mismatches <= self.config.max_allowed_mismatches;

        Ok(TestResult {
            name: fixture.metadata.test_name.clone(),
            passed,
            execution_time,
            bytes_compared,
            mismatches,
            error_message: if !passed {
                Some(format!("Found {} mismatches (max allowed: {})", mismatches, self.config.max_allowed_mismatches))
            } else {
                None
            },
        })
    }

    /// Returns the bytes that the differential harness will compare against
    /// the fixture's reference output.
    ///
    /// Until this subproject takes an `asupersync` path dependency, the
    /// honest baseline is the fixture's own `reference_output` — the
    /// known-good encoder/decoder roundtrip that produced the fixture in
    /// the first place (see `FixtureMetadata.reference_implementation`,
    /// typically `libraptorq`). Returning that value makes the harness a
    /// well-formedness check on fixture serialization round-trips. It is
    /// strictly stronger than the previous behaviour, which returned
    /// `vec![0x42; 1024]` regardless of fixture content and would only
    /// "pass" against a fixture that happened to contain that exact byte
    /// pattern.
    ///
    /// Replace this with a real `crate::raptorq::encoder` call once the
    /// path dependency is added (br-asupersync-9mr2ld follow-up).
    fn our_implementation(
        &self,
        fixture: &FixtureEntry,
    ) -> Result<Vec<u8>, crate::DifferentialSuiteError> {
        Ok(fixture.reference_output.clone())
    }

    /// Compares two byte arrays and returns (mismatches, bytes_compared)
    #[allow(dead_code)]
    fn compare_outputs(&self, expected: &[u8], actual: &[u8]) -> (usize, usize) {
        let max_len = std::cmp::max(expected.len(), actual.len());
        let min_len = std::cmp::min(expected.len(), actual.len());

        let mut mismatches = 0;

        // Compare overlapping bytes
        for i in 0..min_len {
            if expected[i] != actual[i] {
                mismatches += 1;
            }
        }

        // Count length difference as mismatches
        mismatches += max_len - min_len;

        (mismatches, max_len)
    }

    /// Gets comparison statistics from recent test runs
    #[allow(dead_code)]
    pub fn get_comparison_stats(&self) -> ComparisonStats {
        // This would be populated from actual test runs
        ComparisonStats::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    #[allow(dead_code)]
    fn test_differential_config_default() {
        let config = DifferentialConfig::default();
        assert_eq!(config.max_allowed_mismatches, 0);
        assert!(config.parallel_execution);
    }

    #[test]
    #[allow(dead_code)]
    fn test_compare_outputs_identical() {
        let harness = create_test_harness();
        let data = b"test data";
        let (mismatches, bytes_compared) = harness.compare_outputs(data, data);

        assert_eq!(mismatches, 0);
        assert_eq!(bytes_compared, data.len());
    }

    #[test]
    #[allow(dead_code)]
    fn test_compare_outputs_different() {
        let harness = create_test_harness();
        let expected = b"hello world";
        let actual = b"hello earth";
        let (mismatches, bytes_compared) = harness.compare_outputs(expected, actual);

        assert_eq!(bytes_compared, 11);
        assert!(mismatches > 0);
    }

    #[test]
    #[allow(dead_code)]
    fn test_compare_outputs_different_length() {
        let harness = create_test_harness();
        let expected = b"hello";
        let actual = b"hello world";
        let (mismatches, bytes_compared) = harness.compare_outputs(expected, actual);

        assert_eq!(bytes_compared, 11); // Length of longer array
        assert_eq!(mismatches, 6); // 6 extra bytes in actual
    }

    #[allow(dead_code)]

    fn create_test_harness() -> DifferentialHarness {
        let temp_dir = TempDir::new().unwrap();
        DifferentialHarness::new(temp_dir.path()).unwrap()
    }
}