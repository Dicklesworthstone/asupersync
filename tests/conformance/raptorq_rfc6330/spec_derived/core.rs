//! Comprehensive spec-derived tests for RFC 6330 RaptorQ implementation.
//!
//! This module implements systematic test coverage for every MUST and SHOULD clause
//! in RFC 6330 sections 4-5, providing requirement-to-test traceability and
//! compliance scoring.
//!
//! # Test Organization
//!
//! Tests are organized by RFC section and requirement level:
//! - **Parameter Derivation**: K, K', systematic index, tuple parameters
//! - **Encoding Process**: Systematic symbols, repair symbols, ESI validation
//! - **Decoding Process**: Constraint matrix, Gaussian elimination, reconstruction
//! - **Integration**: End-to-end conformance and edge cases

// Module declarations moved to lib.rs

use std::collections::HashMap;
use std::time::Duration;

/// RFC 6330 requirement levels from the specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

impl std::fmt::Display for RequirementLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequirementLevel::Must => write!(f, "MUST"),
            RequirementLevel::Should => write!(f, "SHOULD"),
            RequirementLevel::May => write!(f, "MAY"),
        }
    }
}

/// A conformance test case mapped to a specific RFC 6330 requirement.
pub struct Rfc6330ConformanceCase {
    /// Unique identifier for the test case (e.g., "RFC6330-4.2.1").
    pub id: &'static str,
    /// RFC section this test covers (e.g., "4.2").
    pub section: &'static str,
    /// Requirement level from the specification.
    pub level: RequirementLevel,
    /// Human-readable description of the requirement being tested.
    pub description: &'static str,
    /// The test function to execute.
    pub test_fn: fn(&ConformanceContext) -> ConformanceResult,
}

/// Context provided to conformance test functions.
pub struct ConformanceContext {
    /// Test configuration parameters.
    pub config: ConformanceConfig,
    /// Timeout for individual test execution.
    pub timeout: Duration,
    /// Whether to enable verbose logging.
    pub verbose: bool,
}

/// Configuration for conformance testing.
#[derive(Debug, Clone)]
pub struct ConformanceConfig {
    /// Object sizes to test (in symbols).
    pub test_object_sizes: Vec<usize>,
    /// Symbol sizes to test (in bytes).
    pub test_symbol_sizes: Vec<usize>,
    /// Maximum ESI values to test for repair symbols.
    pub max_esi_values: Vec<u32>,
    /// Loss patterns for integration testing.
    pub loss_patterns: Vec<LossPattern>,
    /// Whether to test edge cases.
    pub include_edge_cases: bool,
    /// Random seed for deterministic testing.
    pub random_seed: u64,
}

impl Default for ConformanceConfig {
    fn default() -> Self {
        Self {
            test_object_sizes: vec![10, 100, 1000, 10000],
            test_symbol_sizes: vec![64, 256, 1024, 4096],
            max_esi_values: vec![100, 1000, 10000],
            loss_patterns: vec![
                LossPattern::None,
                LossPattern::Uniform(0.1),
                LossPattern::Burst(5),
                LossPattern::Random(0.2),
            ],
            include_edge_cases: true,
            random_seed: 12345,
        }
    }
}

/// Different loss patterns for testing decode scenarios.
#[derive(Debug, Clone, PartialEq)]
pub enum LossPattern {
    /// No symbol loss.
    None,
    /// Uniform random loss with given probability.
    Uniform(f64),
    /// Burst loss of consecutive symbols.
    Burst(usize),
    /// Random loss with given probability.
    Random(f64),
}

/// Result from executing a conformance test case.
pub struct ConformanceResult {
    /// Whether the test passed.
    pub passed: bool,
    /// Duration the test took to execute.
    pub duration: Duration,
    /// Detailed test metrics.
    pub metrics: HashMap<String, f64>,
    /// Error message if the test failed.
    pub error_message: Option<String>,
    /// Additional details about the test execution.
    pub details: Vec<String>,
}

impl ConformanceResult {
    /// Create a new passing result.
    pub fn pass() -> Self {
        Self {
            passed: true,
            duration: Duration::ZERO,
            metrics: HashMap::new(),
            error_message: None,
            details: Vec::new(),
        }
    }

    /// Create a new failing result with error message.
    pub fn fail(message: impl Into<String>) -> Self {
        Self {
            passed: false,
            duration: Duration::ZERO,
            metrics: HashMap::new(),
            error_message: Some(message.into()),
            details: Vec::new(),
        }
    }

    /// Add a metric to the result.
    pub fn with_metric(mut self, name: impl Into<String>, value: f64) -> Self {
        self.metrics.insert(name.into(), value);
        self
    }

    /// Add a detail message to the result.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.details.push(detail.into());
        self
    }

    /// Set the test duration.
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }
}

/// Comprehensive test suite runner for RFC 6330 conformance.
pub struct Rfc6330ConformanceSuite {
    /// All registered test cases.
    test_cases: Vec<Rfc6330ConformanceCase>,
    /// Test configuration.
    config: ConformanceConfig,
    /// Whether to fail fast on first failure.
    fail_fast: bool,
}

impl Rfc6330ConformanceSuite {
    /// Create a new conformance test suite.
    pub fn new() -> Self {
        let mut suite = Self {
            test_cases: Vec::new(),
            config: ConformanceConfig::default(),
            fail_fast: false,
        };

        // Register all test cases
        suite.register_all_tests();
        suite
    }

    /// Configure the test suite.
    pub fn with_config(mut self, config: ConformanceConfig) -> Self {
        self.config = config;
        self
    }

    /// Enable or disable fail-fast behavior.
    pub fn with_fail_fast(mut self, fail_fast: bool) -> Self {
        self.fail_fast = fail_fast;
        self
    }

    /// Run all conformance tests.
    pub fn run_all(&self) -> ConformanceReport {
        let start_time = std::time::Instant::now();
        let mut results = HashMap::new();
        let mut total_passed = 0;
        let mut total_failed = 0;

        for test_case in &self.test_cases {
            let context = ConformanceContext {
                config: self.config.clone(),
                timeout: Duration::from_secs(60),
                verbose: false,
            };

            let test_start = std::time::Instant::now();
            let result = (test_case.test_fn)(&context);
            let test_duration = test_start.elapsed();

            let final_result = ConformanceResult {
                duration: test_duration,
                ..result
            };

            if final_result.passed {
                total_passed += 1;
            } else {
                total_failed += 1;
            }

            results.insert(test_case.id.to_string(), (test_case.clone(), final_result));

            // Fail fast if requested
            if self.fail_fast && !results[test_case.id].1.passed {
                break;
            }
        }

        ConformanceReport {
            total_tests: self.test_cases.len(),
            passed_tests: total_passed,
            failed_tests: total_failed,
            total_duration: start_time.elapsed(),
            results,
        }
    }

    /// Run only tests for a specific requirement level.
    pub fn run_by_level(&self, level: RequirementLevel) -> ConformanceReport {
        let filtered_tests: Vec<_> = self.test_cases
            .iter()
            .filter(|tc| tc.level == level)
            .collect();

        let start_time = std::time::Instant::now();
        let mut results = HashMap::new();
        let mut total_passed = 0;
        let mut total_failed = 0;

        for test_case in filtered_tests {
            let context = ConformanceContext {
                config: self.config.clone(),
                timeout: Duration::from_secs(60),
                verbose: false,
            };

            let result = (test_case.test_fn)(&context);

            if result.passed {
                total_passed += 1;
            } else {
                total_failed += 1;
            }

            results.insert(test_case.id.to_string(), ((*test_case).clone(), result));
        }

        ConformanceReport {
            total_tests: results.len(),
            passed_tests: total_passed,
            failed_tests: total_failed,
            total_duration: start_time.elapsed(),
            results,
        }
    }

    /// Register all test cases from the different modules.
    fn register_all_tests(&mut self) {
        // Parameter derivation tests
        crate::parameter_derivation::register_tests(self);

        // Encoding process tests
        crate::encoding_process::register_tests(self);

        // Decoding process tests
        crate::decoding_process::register_tests(self);

        // Integration tests
        crate::integration::register_tests(self);
    }

    /// Add a test case to the suite.
    pub fn add_test_case(&mut self, test_case: Rfc6330ConformanceCase) {
        self.test_cases.push(test_case);
    }
}

impl Default for Rfc6330ConformanceSuite {
    fn default() -> Self {
        Self::new()
    }
}

/// Report from running the RFC 6330 conformance test suite.
pub struct ConformanceReport {
    /// Total number of tests executed.
    pub total_tests: usize,
    /// Number of tests that passed.
    pub passed_tests: usize,
    /// Number of tests that failed.
    pub failed_tests: usize,
    /// Total duration for all tests.
    pub total_duration: Duration,
    /// Individual test results.
    pub results: HashMap<String, (Rfc6330ConformanceCase, ConformanceResult)>,
}

impl ConformanceReport {
    /// Calculate the overall pass rate.
    pub fn pass_rate(&self) -> f64 {
        if self.total_tests == 0 {
            1.0
        } else {
            self.passed_tests as f64 / self.total_tests as f64
        }
    }

    /// Get compliance score by requirement level.
    pub fn compliance_score_by_level(&self) -> HashMap<RequirementLevel, f64> {
        let mut scores = HashMap::new();

        for level in [RequirementLevel::Must, RequirementLevel::Should, RequirementLevel::May] {
            let level_tests: Vec<_> = self.results.values()
                .filter(|(tc, _)| tc.level == level)
                .collect();

            let total = level_tests.len();
            let passed = level_tests.iter().filter(|(_, result)| result.passed).count();

            let score = if total == 0 {
                1.0
            } else {
                passed as f64 / total as f64
            };

            scores.insert(level, score);
        }

        scores
    }

    /// Print a detailed report.
    pub fn print_detailed_report(&self) {
        println!("=== RFC 6330 CONFORMANCE TEST REPORT ===");
        println!("Total Tests: {}", self.total_tests);
        println!("Passed: {}", self.passed_tests);
        println!("Failed: {}", self.failed_tests);
        println!("Pass Rate: {:.1}%", self.pass_rate() * 100.0);
        println!("Duration: {:?}", self.total_duration);
        println!();

        // Compliance by requirement level
        println!("=== COMPLIANCE BY REQUIREMENT LEVEL ===");
        let compliance_scores = self.compliance_score_by_level();
        for level in [RequirementLevel::Must, RequirementLevel::Should, RequirementLevel::May] {
            if let Some(&score) = compliance_scores.get(&level) {
                println!("{}: {:.1}%", level, score * 100.0);
            }
        }
        println!();

        // Failed tests detail
        if self.failed_tests > 0 {
            println!("=== FAILED TESTS ===");
            for (test_id, (test_case, result)) in &self.results {
                if !result.passed {
                    println!("\n{} ({})", test_id, test_case.section);
                    println!("  Level: {}", test_case.level);
                    println!("  Description: {}", test_case.description);
                    println!("  Duration: {:?}", result.duration);

                    if let Some(error) = &result.error_message {
                        println!("  Error: {}", error);
                    }

                    if !result.details.is_empty() {
                        println!("  Details:");
                        for detail in &result.details {
                            println!("    - {}", detail);
                        }
                    }
                }
            }
        }

        // Summary by section
        println!("\n=== SUMMARY BY RFC SECTION ===");
        let mut section_summary: HashMap<String, (usize, usize)> = HashMap::new();
        for (_, (test_case, result)) in &self.results {
            let entry = section_summary.entry(test_case.section.to_string()).or_insert((0, 0));
            if result.passed {
                entry.0 += 1;
            } else {
                entry.1 += 1;
            }
        }

        for (section, (passed, failed)) in section_summary {
            let total = passed + failed;
            let rate = if total == 0 { 100.0 } else { passed as f64 / total as f64 * 100.0 };
            println!("Section {}: {}/{} ({:.1}% pass rate)", section, passed, total, rate);
        }
    }
}

impl Clone for Rfc6330ConformanceCase {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            section: self.section,
            level: self.level,
            description: self.description,
            test_fn: self.test_fn,
        }
    }
}

/// Utility functions for conformance testing.
pub mod utils {
    use super::*;

    /// Generate test object sizes covering edge cases.
    pub fn generate_test_object_sizes() -> Vec<usize> {
        let mut sizes = vec![
            1, 2, 3, 4, 5,           // Very small
            10, 50, 100,             // Small
            256, 512, 1000,          // Medium
            4096, 8192, 10000,       // Large
            65536, 100000,           // Very large
        ];

        // Add boundary values around systematic index table limits
        sizes.extend_from_slice(&[8191, 8192, 8193]); // Around common limits

        sizes
    }

    /// Generate test symbol sizes covering typical use cases.
    pub fn generate_test_symbol_sizes() -> Vec<usize> {
        vec![
            1, 4, 8, 16, 32,         // Small symbols
            64, 128, 256, 512,       // Common sizes
            1024, 2048, 4096,        // Large symbols
            8192, 16384,             // Very large
        ]
    }

    /// Create a deterministic pseudo-random number generator.
    pub fn create_test_rng(seed: u64) -> TestRng {
        TestRng::new(seed)
    }
}

/// Simple deterministic RNG for testing.
pub struct TestRng {
    state: u64,
}

impl TestRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u32(&mut self) -> u32 {
        // Linear congruential generator
        self.state = self.state.wrapping_mul(1103515245).wrapping_add(12345);
        (self.state >> 16) as u32
    }

    pub fn next_f64(&mut self) -> f64 {
        self.next_u32() as f64 / u32::MAX as f64
    }
}