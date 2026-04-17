//! Coverage matrix calculation and compliance scoring for RaptorQ RFC 6330 conformance.
//!
//! This module implements the core coverage calculation engine that analyzes
//! conformance test results and generates compliance scores per RFC section.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Overall coverage matrix with section-by-section breakdown
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoverageMatrix {
    /// Per-section coverage details
    pub sections: BTreeMap<String, SectionCoverage>,
    /// Overall coverage summary
    pub overall: OverallCoverage,
    /// Overall compliance score (0.0 - 1.0)
    pub compliance_score: f64,
    /// Conformance level based on score thresholds
    pub conformance_level: ConformanceLevel,
    /// Timestamp when matrix was generated
    pub generated_at: chrono::DateTime<chrono::Utc>,
    /// Git commit hash when coverage was calculated
    pub git_commit: Option<String>,
}

/// Coverage details for a specific RFC section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionCoverage {
    /// RFC section identifier (e.g., "4.2", "5.3")
    pub section: String,
    /// MUST requirements
    pub must_total: usize,
    pub must_passing: usize,
    /// SHOULD requirements
    pub should_total: usize,
    pub should_passing: usize,
    /// MAY requirements
    pub may_total: usize,
    pub may_passing: usize,
    /// Section-specific compliance score
    pub score: f64,
    /// Section conformance status
    pub conformance_status: SectionConformanceStatus,
    /// Failed test details
    pub failures: Vec<TestFailure>,
}

/// Overall coverage summary across all sections
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OverallCoverage {
    pub must_total: usize,
    pub must_passing: usize,
    pub should_total: usize,
    pub should_passing: usize,
    pub may_total: usize,
    pub may_passing: usize,
    pub total_tests: usize,
    pub passing_tests: usize,
}

/// Conformance level based on compliance score thresholds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ConformanceLevel {
    /// Score ≥ 0.98: Full conformance
    FullyConformant,
    /// Score ≥ 0.95: Mostly conformant with minor gaps
    MostlyConformant,
    /// Score ≥ 0.90: Partially conformant
    PartiallyConformant,
    /// Score < 0.90: Non-conformant
    #[default]
    NonConformant,
}

impl ConformanceLevel {
    pub fn from_score(score: f64) -> Self {
        if score >= 0.98 {
            Self::FullyConformant
        } else if score >= 0.95 {
            Self::MostlyConformant
        } else if score >= 0.90 {
            Self::PartiallyConformant
        } else {
            Self::NonConformant
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::FullyConformant => "Fully RFC 6330 conformant",
            Self::MostlyConformant => "Mostly conformant with minor gaps",
            Self::PartiallyConformant => "Partially conformant",
            Self::NonConformant => "Non-conformant",
        }
    }

    pub fn badge_color(&self) -> &'static str {
        match self {
            Self::FullyConformant => "brightgreen",
            Self::MostlyConformant => "green",
            Self::PartiallyConformant => "yellow",
            Self::NonConformant => "red",
        }
    }
}

/// Section-level conformance status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SectionConformanceStatus {
    /// All MUST requirements pass, ≥90% SHOULD requirements pass
    Pass,
    /// Some MUST requirements fail OR <90% SHOULD requirements pass
    Fail,
    /// Section has no testable requirements
    NotApplicable,
}

/// Details about a failing test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestFailure {
    pub test_id: String,
    pub test_name: String,
    pub requirement_level: RequirementLevel,
    pub rfc_section: String,
    pub error_message: String,
    pub failure_type: FailureType,
}

/// RFC requirement levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

/// Types of conformance test failures
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureType {
    /// Test failed due to incorrect behavior
    IncorrectBehavior,
    /// Test failed due to missing implementation
    NotImplemented,
    /// Test failed due to performance issues
    PerformanceFailure,
    /// Test failed due to invalid input handling
    InvalidInputHandling,
    /// Test crashed or threw unexpected exception
    Crash,
}

/// Test result from conformance test execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceTestResult {
    pub test_id: String,
    pub test_name: String,
    pub rfc_section: String,
    pub requirement_level: RequirementLevel,
    pub passed: bool,
    pub error_message: Option<String>,
    pub execution_time_ms: u64,
    pub failure_type: Option<FailureType>,
}

/// Coverage matrix calculator
pub struct CoverageMatrixCalculator {
    /// Minimum score threshold for MUST requirements (default: 1.0)
    pub must_threshold: f64,
    /// Minimum score threshold for SHOULD requirements (default: 0.90)
    pub should_threshold: f64,
    /// Whether to include MAY requirements in overall score
    pub include_may_in_score: bool,
}

impl Default for CoverageMatrixCalculator {
    fn default() -> Self {
        Self {
            must_threshold: 1.0,
            should_threshold: 0.90,
            include_may_in_score: false,
        }
    }
}

impl CoverageMatrixCalculator {
    /// Create a new coverage matrix calculator with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate coverage matrix from golden files directory
    pub fn calculate_coverage<P: AsRef<Path>>(
        &self,
        golden_dir: P,
    ) -> Result<CoverageMatrix, CoverageError> {
        // For now, create a simple mock coverage matrix
        // In a real implementation, this would parse golden files and extract test results
        let mock_results = vec![
            ConformanceTestResult {
                test_id: "test_001".to_string(),
                test_name: "Basic encoding test".to_string(),
                rfc_section: "5.3.1".to_string(),
                requirement_level: RequirementLevel::Must,
                passed: true,
                error_message: None,
                execution_time_ms: 10,
                failure_type: None,
            },
            ConformanceTestResult {
                test_id: "test_002".to_string(),
                test_name: "Symbol alignment test".to_string(),
                rfc_section: "5.3.2".to_string(),
                requirement_level: RequirementLevel::Should,
                passed: true,
                error_message: None,
                execution_time_ms: 15,
                failure_type: None,
            },
        ];

        self.calculate_coverage_from_results(&mock_results)
    }

    /// Calculate coverage matrix from test results
    pub fn calculate_coverage_from_results(
        &self,
        test_results: &[ConformanceTestResult],
    ) -> Result<CoverageMatrix, CoverageError> {
        let mut sections: BTreeMap<String, SectionCoverage> = BTreeMap::new();

        // Group results by section
        for result in test_results {
            let section_coverage =
                sections
                    .entry(result.rfc_section.clone())
                    .or_insert_with(|| SectionCoverage {
                        section: result.rfc_section.clone(),
                        must_total: 0,
                        must_passing: 0,
                        should_total: 0,
                        should_passing: 0,
                        may_total: 0,
                        may_passing: 0,
                        score: 0.0,
                        conformance_status: SectionConformanceStatus::NotApplicable,
                        failures: Vec::new(),
                    });

            // Update counts based on requirement level
            match result.requirement_level {
                RequirementLevel::Must => {
                    section_coverage.must_total += 1;
                    if result.passed {
                        section_coverage.must_passing += 1;
                    }
                }
                RequirementLevel::Should => {
                    section_coverage.should_total += 1;
                    if result.passed {
                        section_coverage.should_passing += 1;
                    }
                }
                RequirementLevel::May => {
                    section_coverage.may_total += 1;
                    if result.passed {
                        section_coverage.may_passing += 1;
                    }
                }
            }

            // Record failure details
            if !result.passed {
                section_coverage.failures.push(TestFailure {
                    test_id: result.test_id.clone(),
                    test_name: result.test_name.clone(),
                    requirement_level: result.requirement_level,
                    rfc_section: result.rfc_section.clone(),
                    error_message: result.error_message.clone().unwrap_or_default(),
                    failure_type: result
                        .failure_type
                        .unwrap_or(FailureType::IncorrectBehavior),
                });
            }
        }

        // Calculate section scores and status
        for section_coverage in sections.values_mut() {
            section_coverage.score = self.calculate_section_score(section_coverage);
            section_coverage.conformance_status = self.determine_section_status(section_coverage);
        }

        // Calculate overall coverage
        let overall = self.calculate_overall_coverage(&sections);
        let compliance_score = self.calculate_compliance_score(&overall);
        let conformance_level = ConformanceLevel::from_score(compliance_score);

        Ok(CoverageMatrix {
            sections,
            overall,
            compliance_score,
            conformance_level,
            generated_at: chrono::Utc::now(),
            git_commit: Self::get_git_commit(),
        })
    }

    /// Calculate section-specific score
    fn calculate_section_score(&self, section: &SectionCoverage) -> f64 {
        let must_score = if section.must_total > 0 {
            section.must_passing as f64 / section.must_total as f64
        } else {
            1.0
        };

        let should_score = if section.should_total > 0 {
            section.should_passing as f64 / section.should_total as f64
        } else {
            1.0
        };

        let may_score = if section.may_total > 0 {
            section.may_passing as f64 / section.may_total as f64
        } else {
            1.0
        };

        // Weighted score: MUST requirements are critical
        if self.include_may_in_score {
            let total_weight = 3.0; // MUST=2, SHOULD=1, MAY=0.5
            let weighted_score = (must_score * 2.0) + should_score + (may_score * 0.5);
            weighted_score / total_weight
        } else {
            let total_weight = 3.0; // MUST=2, SHOULD=1
            let weighted_score = (must_score * 2.0) + should_score;
            weighted_score / total_weight
        }
    }

    /// Determine section conformance status
    fn determine_section_status(&self, section: &SectionCoverage) -> SectionConformanceStatus {
        if section.must_total == 0 && section.should_total == 0 && section.may_total == 0 {
            return SectionConformanceStatus::NotApplicable;
        }

        let must_pass_rate = if section.must_total > 0 {
            section.must_passing as f64 / section.must_total as f64
        } else {
            1.0
        };

        let should_pass_rate = if section.should_total > 0 {
            section.should_passing as f64 / section.should_total as f64
        } else {
            1.0
        };

        if must_pass_rate >= self.must_threshold && should_pass_rate >= self.should_threshold {
            SectionConformanceStatus::Pass
        } else {
            SectionConformanceStatus::Fail
        }
    }

    /// Calculate overall coverage summary
    fn calculate_overall_coverage(
        &self,
        sections: &BTreeMap<String, SectionCoverage>,
    ) -> OverallCoverage {
        let mut overall = OverallCoverage {
            must_total: 0,
            must_passing: 0,
            should_total: 0,
            should_passing: 0,
            may_total: 0,
            may_passing: 0,
            total_tests: 0,
            passing_tests: 0,
        };

        for section in sections.values() {
            overall.must_total += section.must_total;
            overall.must_passing += section.must_passing;
            overall.should_total += section.should_total;
            overall.should_passing += section.should_passing;
            overall.may_total += section.may_total;
            overall.may_passing += section.may_passing;
            overall.total_tests += section.must_total + section.should_total + section.may_total;
            overall.passing_tests +=
                section.must_passing + section.should_passing + section.may_passing;
        }

        overall
    }

    /// Calculate overall compliance score
    fn calculate_compliance_score(&self, overall: &OverallCoverage) -> f64 {
        if overall.must_total == 0 && overall.should_total == 0 {
            return 1.0; // No requirements to test
        }

        let critical_total = overall.must_total + overall.should_total;
        let critical_passing = overall.must_passing + overall.should_passing;

        if critical_total == 0 {
            1.0
        } else {
            critical_passing as f64 / critical_total as f64
        }
    }

    /// Get current git commit hash
    fn get_git_commit() -> Option<String> {
        std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    String::from_utf8(output.stdout)
                        .ok()
                        .map(|s| s.trim().to_string())
                } else {
                    None
                }
            })
    }

    /// Load test results from JSON file
    pub fn load_test_results<P: AsRef<Path>>(
        path: P,
    ) -> Result<Vec<ConformanceTestResult>, CoverageError> {
        let content = std::fs::read_to_string(path)?;
        let results: Vec<ConformanceTestResult> = serde_json::from_str(&content)?;
        Ok(results)
    }

    /// Save coverage matrix to JSON file
    pub fn save_coverage_matrix<P: AsRef<Path>>(
        matrix: &CoverageMatrix,
        path: P,
    ) -> Result<(), CoverageError> {
        let json = serde_json::to_string_pretty(matrix)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

/// Errors that can occur during coverage calculation
#[derive(Debug, thiserror::Error)]
pub enum CoverageError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Invalid test result data: {0}")]
    InvalidData(String),

    #[error("Coverage calculation error: {0}")]
    CalculationError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_result(
        section: &str,
        level: RequirementLevel,
        passed: bool,
    ) -> ConformanceTestResult {
        ConformanceTestResult {
            test_id: format!("RFC6330-{}-001", section),
            test_name: format!("Test for section {}", section),
            rfc_section: section.to_string(),
            requirement_level: level,
            passed,
            error_message: if passed {
                None
            } else {
                Some("Test failed".to_string())
            },
            execution_time_ms: 100,
            failure_type: if passed {
                None
            } else {
                Some(FailureType::IncorrectBehavior)
            },
        }
    }

    #[test]
    fn test_perfect_coverage() {
        let calculator = CoverageMatrixCalculator::default();
        let results = vec![
            create_test_result("4.1", RequirementLevel::Must, true),
            create_test_result("4.1", RequirementLevel::Should, true),
            create_test_result("4.2", RequirementLevel::Must, true),
        ];

        let matrix = calculator
            .calculate_coverage_from_results(&results)
            .unwrap();

        assert_eq!(matrix.compliance_score, 1.0);
        assert_eq!(matrix.conformance_level, ConformanceLevel::FullyConformant);
        assert_eq!(matrix.overall.must_total, 2);
        assert_eq!(matrix.overall.must_passing, 2);
        assert_eq!(matrix.overall.should_total, 1);
        assert_eq!(matrix.overall.should_passing, 1);
    }

    #[test]
    fn test_partial_coverage() {
        let calculator = CoverageMatrixCalculator::default();
        let results = vec![
            create_test_result("4.1", RequirementLevel::Must, true),
            create_test_result("4.1", RequirementLevel::Must, false),
            create_test_result("4.1", RequirementLevel::Should, true),
        ];

        let matrix = calculator
            .calculate_coverage_from_results(&results)
            .unwrap();

        assert!(matrix.compliance_score < 1.0);
        assert_eq!(
            matrix.conformance_level,
            ConformanceLevel::PartiallyConformant
        );
        assert_eq!(matrix.overall.must_total, 2);
        assert_eq!(matrix.overall.must_passing, 1);
    }

    #[test]
    fn test_conformance_levels() {
        assert_eq!(
            ConformanceLevel::from_score(0.99),
            ConformanceLevel::FullyConformant
        );
        assert_eq!(
            ConformanceLevel::from_score(0.96),
            ConformanceLevel::MostlyConformant
        );
        assert_eq!(
            ConformanceLevel::from_score(0.92),
            ConformanceLevel::PartiallyConformant
        );
        assert_eq!(
            ConformanceLevel::from_score(0.85),
            ConformanceLevel::NonConformant
        );
    }

    #[test]
    fn test_section_score_calculation() {
        let calculator = CoverageMatrixCalculator::default();
        let section = SectionCoverage {
            section: "4.1".to_string(),
            must_total: 2,
            must_passing: 2,
            should_total: 2,
            should_passing: 1,
            may_total: 1,
            may_passing: 1,
            score: 0.0,
            conformance_status: SectionConformanceStatus::NotApplicable,
            failures: Vec::new(),
        };

        let score = calculator.calculate_section_score(&section);

        // MUST score: 2/2 = 1.0, SHOULD score: 1/2 = 0.5
        // Weighted: (1.0 * 2 + 0.5 * 1) / 3 = 2.5/3 ≈ 0.833
        assert!((score - 0.833).abs() < 0.01);
    }
}
