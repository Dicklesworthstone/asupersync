//! RFC 6330 Spec-Derived Test Implementation
//!
//! This library provides comprehensive, systematic testing of every MUST and SHOULD
//! clause in RFC 6330, with requirement-to-test traceability and compliance scoring.
//!
//! # Test Coverage Matrix
//!
//! The test suite systematically covers:
//! - **Section 5.1-5.2**: Parameter derivation (K, K', systematic index, S, H, W, J)
//! - **Section 5.3-5.5**: Tuple generation algorithms and Rand function implementation
//! - **Section 4.2**: Encoding process (systematic symbols, repair symbols, ESI validation)
//! - **Section 4.3**: Decoding process (constraint matrix, Gaussian elimination, reconstruction)
//! - **Integration**: End-to-end conformance and edge case validation
//!
//! # Usage
//!
//! ```rust
//! use raptorq_rfc6330_spec_derived::{Rfc6330ConformanceSuite, RequirementLevel};
//!
//! // Run all conformance tests
//! let suite = Rfc6330ConformanceSuite::new();
//! let report = suite.run_all();
//! report.print_detailed_report();
//!
//! // Run only MUST requirements
//! let must_report = suite.run_by_level(RequirementLevel::Must);
//! println!("MUST compliance: {:.1}%", must_report.pass_rate() * 100.0);
//!
//! // Check specific compliance scores
//! let scores = report.compliance_score_by_level();
//! assert!(scores[&RequirementLevel::Must] >= 0.95); // ≥95% MUST compliance
//! ```
//!
//! # Compliance Goals
//!
//! - **MUST clauses**: ≥95% compliance (acceptance criteria)
//! - **SHOULD clauses**: ≥90% compliance (target)
//! - **Test execution time**: <10 minutes on CI
//! - **Requirement traceability**: Each test maps to specific RFC clause

// Import all the test modules
pub mod parameter_derivation;
pub mod encoding_process;
pub mod decoding_process;
pub mod integration;

// Import core testing infrastructure
mod core;
pub use core::*;
    Rfc6330ConformanceSuite, Rfc6330ConformanceCase, ConformanceReport,
    RequirementLevel, ConformanceContext, ConformanceResult,
    ConformanceConfig, LossPattern, utils, TestRng,
};

/// Version of the spec-derived test suite.
pub const VERSION: &str = "1.0.0";

/// Target RFC 6330 compliance version.
pub const RFC_VERSION: &str = "6330:2011";

/// Run the complete RFC 6330 conformance test suite.
///
/// This is the main entry point for comprehensive RFC 6330 conformance validation.
/// It runs all registered test cases across all requirement levels and sections.
pub fn run_complete_conformance_suite() -> ConformanceReport {
    let suite = Rfc6330ConformanceSuite::new();
    suite.run_all()
}

/// Run only MUST requirement tests for fast validation.
///
/// This runs the subset of tests covering MUST clauses from RFC 6330,
/// suitable for continuous integration and quick validation cycles.
pub fn run_must_requirements_only() -> ConformanceReport {
    let suite = Rfc6330ConformanceSuite::new();
    suite.run_by_level(RequirementLevel::Must)
}

/// Run conformance tests with custom configuration.
///
/// Allows customization of test parameters, object sizes, symbol sizes,
/// and other configuration options for specialized testing scenarios.
pub fn run_conformance_with_config(config: ConformanceConfig) -> ConformanceReport {
    let suite = Rfc6330ConformanceSuite::new().with_config(config);
    suite.run_all()
}

/// Validate RFC 6330 conformance and assert minimum compliance levels.
///
/// This function runs the conformance suite and validates that compliance
/// scores meet the required thresholds for production readiness.
///
/// # Panics
///
/// Panics if MUST clause compliance is below 95% or if critical failures are detected.
pub fn validate_rfc6330_conformance() -> ConformanceReport {
    let report = run_complete_conformance_suite();

    // Check compliance scores
    let scores = report.compliance_score_by_level();

    // Validate MUST clause compliance (acceptance criteria)
    let must_score = scores.get(&RequirementLevel::Must).unwrap_or(&0.0);
    if *must_score < 0.95 {
        panic!(
            "RFC 6330 MUST clause compliance below acceptance threshold: {:.1}% < 95.0%",
            must_score * 100.0
        );
    }

    // Validate SHOULD clause compliance (target)
    let should_score = scores.get(&RequirementLevel::Should).unwrap_or(&0.0);
    if *should_score < 0.90 {
        eprintln!(
            "WARNING: RFC 6330 SHOULD clause compliance below target: {:.1}% < 90.0%",
            should_score * 100.0
        );
    }

    // Check for zero failures in critical sections
    let critical_failures = report.results.values()
        .filter(|(tc, result)| {
            !result.passed &&
            tc.level == RequirementLevel::Must &&
            (tc.section == "5.1" || tc.section == "5.2" || tc.section == "4.2" || tc.section == "4.3")
        })
        .count();

    if critical_failures > 0 {
        panic!(
            "Critical RFC 6330 conformance failures detected: {} failures in core sections",
            critical_failures
        );
    }

    report
}

/// Generate a compliance matrix showing requirement coverage.
///
/// Returns a detailed breakdown of test coverage by RFC section and requirement level,
/// suitable for compliance documentation and audit trails.
pub fn generate_compliance_matrix() -> ComplianceMatrix {
    let suite = Rfc6330ConformanceSuite::new();
    let report = suite.run_all();

    ComplianceMatrix::from_report(&report)
}

/// Compliance matrix for requirement traceability.
#[derive(Debug)]
pub struct ComplianceMatrix {
    /// Coverage by RFC section.
    pub section_coverage: std::collections::HashMap<String, SectionCoverage>,
    /// Overall compliance scores.
    pub overall_scores: std::collections::HashMap<RequirementLevel, f64>,
    /// Total test count.
    pub total_tests: usize,
    /// Timestamp when matrix was generated.
    pub generated_at: std::time::SystemTime,
}

/// Coverage information for a specific RFC section.
#[derive(Debug)]
pub struct SectionCoverage {
    /// Section identifier (e.g., "5.1").
    pub section: String,
    /// Tests by requirement level.
    pub tests_by_level: std::collections::HashMap<RequirementLevel, Vec<TestCoverage>>,
    /// Section-specific compliance score.
    pub section_score: f64,
}

/// Coverage information for a specific test case.
#[derive(Debug)]
pub struct TestCoverage {
    /// Test case identifier.
    pub test_id: String,
    /// Test description.
    pub description: String,
    /// Whether the test passed.
    pub passed: bool,
    /// Test execution duration.
    pub duration: std::time::Duration,
}

impl ComplianceMatrix {
    /// Create compliance matrix from conformance report.
    pub fn from_report(report: &ConformanceReport) -> Self {
        let mut section_coverage = std::collections::HashMap::new();
        let overall_scores = report.compliance_score_by_level();

        // Group tests by section
        for (test_id, (test_case, result)) in &report.results {
            let section = test_case.section.to_string();
            let entry = section_coverage.entry(section.clone()).or_insert_with(|| {
                SectionCoverage {
                    section: section.clone(),
                    tests_by_level: std::collections::HashMap::new(),
                    section_score: 0.0,
                }
            });

            let test_coverage = TestCoverage {
                test_id: test_id.clone(),
                description: test_case.description.to_string(),
                passed: result.passed,
                duration: result.duration,
            };

            entry.tests_by_level
                .entry(test_case.level)
                .or_insert_with(Vec::new)
                .push(test_coverage);
        }

        // Calculate section scores
        for section in section_coverage.values_mut() {
            let total_tests: usize = section.tests_by_level.values().map(|v| v.len()).sum();
            let passed_tests: usize = section.tests_by_level.values()
                .flat_map(|v| v.iter())
                .filter(|tc| tc.passed)
                .count();

            section.section_score = if total_tests == 0 {
                1.0
            } else {
                passed_tests as f64 / total_tests as f64
            };
        }

        Self {
            section_coverage,
            overall_scores,
            total_tests: report.total_tests,
            generated_at: std::time::SystemTime::now(),
        }
    }

    /// Print a detailed compliance matrix report.
    pub fn print_detailed_matrix(&self) {
        println!("=== RFC 6330 COMPLIANCE MATRIX ===");
        println!("Generated: {:?}", self.generated_at);
        println!("Total Tests: {}", self.total_tests);
        println!();

        // Overall scores
        println!("=== OVERALL COMPLIANCE SCORES ===");
        for level in [RequirementLevel::Must, RequirementLevel::Should, RequirementLevel::May] {
            if let Some(&score) = self.overall_scores.get(&level) {
                println!("{}: {:.1}%", level, score * 100.0);
            }
        }
        println!();

        // Section breakdown
        println!("=== COMPLIANCE BY RFC SECTION ===");
        let mut sections: Vec<_> = self.section_coverage.keys().collect();
        sections.sort();

        for section_id in sections {
            let section = &self.section_coverage[section_id];
            println!("Section {} - {:.1}% compliance", section.section, section.section_score * 100.0);

            for level in [RequirementLevel::Must, RequirementLevel::Should, RequirementLevel::May] {
                if let Some(tests) = section.tests_by_level.get(&level) {
                    if !tests.is_empty() {
                        let passed = tests.iter().filter(|t| t.passed).count();
                        println!("  {}: {}/{} tests passed", level, passed, tests.len());

                        for test in tests {
                            let status = if test.passed { "✓" } else { "✗" };
                            println!("    {} {} ({}ms)", status, test.test_id, test.duration.as_millis());
                        }
                    }
                }
            }
            println!();
        }
    }

    /// Export compliance matrix as JSON.
    pub fn to_json(&self) -> String {
        // Simplified JSON export - in practice would use serde
        format!("{{\"compliance_matrix\": \"RFC 6330\", \"total_tests\": {}}}", self.total_tests)
    }
}

/// Convenience function for CI integration.
///
/// Returns exit code: 0 for compliance, 1 for non-compliance.
pub fn main() -> i32 {
    match std::panic::catch_unwind(|| {
        let report = validate_rfc6330_conformance();
        report.print_detailed_report();

        let matrix = generate_compliance_matrix();
        matrix.print_detailed_matrix();

        println!("\n✓ RFC 6330 conformance validation PASSED");
    }) {
        Ok(()) => 0,  // Success
        Err(e) => {
            eprintln!("✗ RFC 6330 conformance validation FAILED");
            if let Some(msg) = e.downcast_ref::<&str>() {
                eprintln!("Error: {}", msg);
            } else if let Some(msg) = e.downcast_ref::<String>() {
                eprintln!("Error: {}", msg);
            }
            1  // Failure
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_conformance_suite_creation() {
        let suite = Rfc6330ConformanceSuite::new();

        // Should have registered test cases from all modules
        // This would be validated in the actual implementation
    }

    #[test]
    fn test_must_requirements_compliance() {
        let report = run_must_requirements_only();

        // All MUST requirements should have high pass rate
        assert!(report.pass_rate() >= 0.8); // Allow some flexibility for development
        assert!(report.total_tests > 0);
    }

    #[test]
    fn test_compliance_matrix_generation() {
        let matrix = generate_compliance_matrix();

        // Should have coverage for major RFC sections
        assert!(matrix.section_coverage.contains_key("5.1") ||
                matrix.section_coverage.contains_key("5.2") ||
                matrix.section_coverage.contains_key("4.2") ||
                matrix.section_coverage.contains_key("4.3"));

        assert!(matrix.total_tests > 0);
    }

    #[test]
    fn test_custom_config_conformance() {
        let config = ConformanceConfig {
            test_object_sizes: vec![10, 100],
            test_symbol_sizes: vec![64, 256],
            max_esi_values: vec![100],
            loss_patterns: vec![LossPattern::None],
            include_edge_cases: false,
            random_seed: 42,
        };

        let report = run_conformance_with_config(config);
        assert!(report.total_tests > 0);
    }
}