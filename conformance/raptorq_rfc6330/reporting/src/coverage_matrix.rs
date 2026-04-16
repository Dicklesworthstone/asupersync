//! Coverage Matrix Engine for RFC 6330 Conformance Reporting
//!
//! Implements automated coverage calculation from conformance test results,
//! section-by-section scoring with MUST/SHOULD/MAY breakdown, and overall
//! conformance level determination.

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

use crate::raptorq_rfc6330::{ConformanceResult, TestExecution, RequirementLevel};

/// Overall conformance status based on coverage thresholds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConformanceLevel {
    /// ≥95% MUST clause coverage, ≥90% SHOULD clause coverage
    FullyConformant,
    /// ≥85% MUST clause coverage, ≥70% SHOULD clause coverage
    PartiallyConformant,
    /// Below partial conformance thresholds
    NonConformant,
}

impl std::fmt::Display for ConformanceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConformanceLevel::FullyConformant => write!(f, "✅ Fully Conformant"),
            ConformanceLevel::PartiallyConformant => write!(f, "⚠️ Partially Conformant"),
            ConformanceLevel::NonConformant => write!(f, "❌ Non-Conformant"),
        }
    }
}

/// Conformance status for individual RFC sections
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SectionConformanceStatus {
    Pass,
    Warning,
    Fail,
}

impl std::fmt::Display for SectionConformanceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SectionConformanceStatus::Pass => write!(f, "✅ Pass"),
            SectionConformanceStatus::Warning => write!(f, "⚠️ Warning"),
            SectionConformanceStatus::Fail => write!(f, "❌ Fail"),
        }
    }
}

/// Coverage statistics for individual RFC sections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionCoverage {
    pub section: String,           // "4.2", "5.3", etc.
    pub title: String,             // Human-readable section title
    pub must_total: usize,         // Total MUST clauses in section
    pub must_passing: usize,       // Passing MUST clauses
    pub should_total: usize,       // Total SHOULD clauses in section
    pub should_passing: usize,     // Passing SHOULD clauses
    pub may_total: usize,          // Total MAY clauses in section
    pub may_passing: usize,        // Passing MAY clauses
    pub score: f64,               // (must_passing + should_passing) / (must_total + should_total)
    pub conformance_status: SectionConformanceStatus,
    pub failing_tests: Vec<String>, // IDs of failing test cases
}

impl SectionCoverage {
    /// Create a new section coverage record
    pub fn new(section: String, title: String) -> Self {
        Self {
            section,
            title,
            must_total: 0,
            must_passing: 0,
            should_total: 0,
            should_passing: 0,
            may_total: 0,
            may_passing: 0,
            score: 0.0,
            conformance_status: SectionConformanceStatus::Fail,
            failing_tests: Vec::new(),
        }
    }

    /// Calculate section score and conformance status
    pub fn calculate_score(&mut self) {
        let total_required = self.must_total + self.should_total;
        let total_passing = self.must_passing + self.should_passing;

        self.score = if total_required == 0 {
            100.0 // No requirements = perfect score
        } else {
            (total_passing as f64 / total_required as f64) * 100.0
        };

        // Determine conformance status based on thresholds
        let must_coverage = if self.must_total == 0 {
            100.0
        } else {
            (self.must_passing as f64 / self.must_total as f64) * 100.0
        };

        self.conformance_status = if must_coverage >= 95.0 && self.score >= 90.0 {
            SectionConformanceStatus::Pass
        } else if must_coverage >= 85.0 && self.score >= 70.0 {
            SectionConformanceStatus::Warning
        } else {
            SectionConformanceStatus::Fail
        };
    }

    /// Get MUST clause coverage percentage
    pub fn must_coverage_percent(&self) -> f64 {
        if self.must_total == 0 {
            100.0
        } else {
            (self.must_passing as f64 / self.must_total as f64) * 100.0
        }
    }

    /// Get SHOULD clause coverage percentage
    pub fn should_coverage_percent(&self) -> f64 {
        if self.should_total == 0 {
            100.0
        } else {
            (self.should_passing as f64 / self.should_total as f64) * 100.0
        }
    }

    /// Get MAY clause coverage percentage
    pub fn may_coverage_percent(&self) -> f64 {
        if self.may_total == 0 {
            100.0
        } else {
            (self.may_passing as f64 / self.may_total as f64) * 100.0
        }
    }
}

/// Overall coverage statistics across all sections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverallCoverage {
    pub must_total: usize,
    pub must_passing: usize,
    pub should_total: usize,
    pub should_passing: usize,
    pub may_total: usize,
    pub may_passing: usize,
    pub total_tests: usize,
    pub passing_tests: usize,
    pub failing_tests: usize,
    pub skipped_tests: usize,
}

impl OverallCoverage {
    /// Create new overall coverage record
    pub fn new() -> Self {
        Self {
            must_total: 0,
            must_passing: 0,
            should_total: 0,
            should_passing: 0,
            may_total: 0,
            may_passing: 0,
            total_tests: 0,
            passing_tests: 0,
            failing_tests: 0,
            skipped_tests: 0,
        }
    }

    /// Calculate MUST clause coverage percentage
    pub fn must_coverage_percent(&self) -> f64 {
        if self.must_total == 0 {
            100.0
        } else {
            (self.must_passing as f64 / self.must_total as f64) * 100.0
        }
    }

    /// Calculate SHOULD clause coverage percentage
    pub fn should_coverage_percent(&self) -> f64 {
        if self.should_total == 0 {
            100.0
        } else {
            (self.should_passing as f64 / self.should_total as f64) * 100.0
        }
    }

    /// Calculate MAY clause coverage percentage
    pub fn may_coverage_percent(&self) -> f64 {
        if self.may_total == 0 {
            100.0
        } else {
            (self.may_passing as f64 / self.may_total as f64) * 100.0
        }
    }

    /// Calculate overall test pass rate
    pub fn test_pass_rate(&self) -> f64 {
        if self.total_tests == 0 {
            100.0
        } else {
            (self.passing_tests as f64 / self.total_tests as f64) * 100.0
        }
    }
}

/// Complete coverage matrix with section breakdown and overall statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageMatrix {
    pub sections: BTreeMap<String, SectionCoverage>,
    pub overall: OverallCoverage,
    pub compliance_score: f64,  // (MUST_passing + SHOULD_passing) / (MUST_total + SHOULD_total)
    pub conformance_level: ConformanceLevel,
    pub generated_at: String,   // ISO timestamp
    pub rfc_version: String,    // "RFC 6330"
    pub implementation_version: String, // Git commit or version tag
}

impl CoverageMatrix {
    /// Create new coverage matrix
    pub fn new(implementation_version: String) -> Self {
        Self {
            sections: BTreeMap::new(),
            overall: OverallCoverage::new(),
            compliance_score: 0.0,
            conformance_level: ConformanceLevel::NonConformant,
            generated_at: chrono::Utc::now().to_rfc3339(),
            rfc_version: "RFC 6330".to_string(),
            implementation_version,
        }
    }

    /// Calculate coverage matrix from test execution results
    pub fn from_test_results(
        executions: &[TestExecution],
        implementation_version: String,
    ) -> Self {
        let mut matrix = Self::new(implementation_version);

        // Group tests by section
        let mut section_tests: BTreeMap<String, Vec<&TestExecution>> = BTreeMap::new();
        for execution in executions {
            let section = execution.test.section();
            section_tests.entry(section.to_string())
                .or_default()
                .push(execution);
        }

        // Calculate coverage for each section
        for (section, tests) in section_tests {
            let mut section_coverage = SectionCoverage::new(
                section.clone(),
                format!("Section {}", section), // TODO: Get actual titles from RFC
            );

            for test_execution in tests {
                let level = test_execution.test.requirement_level();
                let is_passing = matches!(test_execution.result, ConformanceResult::Pass);

                match level {
                    RequirementLevel::Must => {
                        section_coverage.must_total += 1;
                        if is_passing {
                            section_coverage.must_passing += 1;
                        } else {
                            section_coverage.failing_tests.push(test_execution.test.rfc_clause().to_string());
                        }
                    }
                    RequirementLevel::Should => {
                        section_coverage.should_total += 1;
                        if is_passing {
                            section_coverage.should_passing += 1;
                        } else {
                            section_coverage.failing_tests.push(test_execution.test.rfc_clause().to_string());
                        }
                    }
                    RequirementLevel::May => {
                        section_coverage.may_total += 1;
                        if is_passing {
                            section_coverage.may_passing += 1;
                        }
                        // MAY failures don't count as failing tests
                    }
                }
            }

            section_coverage.calculate_score();
            matrix.sections.insert(section, section_coverage);
        }

        // Calculate overall statistics
        for section_coverage in matrix.sections.values() {
            matrix.overall.must_total += section_coverage.must_total;
            matrix.overall.must_passing += section_coverage.must_passing;
            matrix.overall.should_total += section_coverage.should_total;
            matrix.overall.should_passing += section_coverage.should_passing;
            matrix.overall.may_total += section_coverage.may_total;
            matrix.overall.may_passing += section_coverage.may_passing;
        }

        // Count test results
        for execution in executions {
            matrix.overall.total_tests += 1;
            match &execution.result {
                ConformanceResult::Pass => {
                    matrix.overall.passing_tests += 1;
                }
                ConformanceResult::Fail { .. } => {
                    matrix.overall.failing_tests += 1;
                }
                ConformanceResult::Skipped { .. } => {
                    matrix.overall.skipped_tests += 1;
                }
                ConformanceResult::ExpectedFailure { .. } => {
                    matrix.overall.passing_tests += 1; // XFAIL counts as passing
                }
            }
        }

        // Calculate compliance score and conformance level
        matrix.calculate_compliance_score();
        matrix
    }

    /// Calculate overall compliance score and conformance level
    fn calculate_compliance_score(&mut self) {
        let total_required = self.overall.must_total + self.overall.should_total;
        let total_passing = self.overall.must_passing + self.overall.should_passing;

        self.compliance_score = if total_required == 0 {
            100.0
        } else {
            (total_passing as f64 / total_required as f64) * 100.0
        };

        // Determine conformance level
        let must_coverage = self.overall.must_coverage_percent();
        let should_coverage = self.overall.should_coverage_percent();

        self.conformance_level = if must_coverage >= 95.0 && should_coverage >= 90.0 {
            ConformanceLevel::FullyConformant
        } else if must_coverage >= 85.0 && should_coverage >= 70.0 {
            ConformanceLevel::PartiallyConformant
        } else {
            ConformanceLevel::NonConformant
        };
    }

    /// Get overall conformance status for compatibility
    pub fn overall_status(&self) -> ConformanceLevel {
        self.conformance_level
    }

    /// Get sections that are failing conformance
    pub fn failing_sections(&self) -> Vec<&SectionCoverage> {
        self.sections
            .values()
            .filter(|s| s.conformance_status == SectionConformanceStatus::Fail)
            .collect()
    }

    /// Get sections with warnings
    pub fn warning_sections(&self) -> Vec<&SectionCoverage> {
        self.sections
            .values()
            .filter(|s| s.conformance_status == SectionConformanceStatus::Warning)
            .collect()
    }

    /// Generate conformance badge color based on compliance score
    pub fn badge_color(&self) -> &'static str {
        match self.conformance_level {
            ConformanceLevel::FullyConformant => "brightgreen",
            ConformanceLevel::PartiallyConformant => "yellow",
            ConformanceLevel::NonConformant => "red",
        }
    }

    /// Generate conformance badge text
    pub fn badge_text(&self) -> String {
        match self.conformance_level {
            ConformanceLevel::FullyConformant => format!("{:.1}% Conformant", self.compliance_score),
            ConformanceLevel::PartiallyConformant => format!("{:.1}% Partial", self.compliance_score),
            ConformanceLevel::NonConformant => format!("{:.1}% Non-Conformant", self.compliance_score),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raptorq_rfc6330::{ConformanceTest, ConformanceContext, TestCategory};

    // Mock test implementation for testing
    struct MockTest {
        clause: String,
        section: String,
        level: RequirementLevel,
        category: TestCategory,
        description: String,
    }

    impl ConformanceTest for MockTest {
        fn rfc_clause(&self) -> &str { &self.clause }
        fn section(&self) -> &str { &self.section }
        fn requirement_level(&self) -> RequirementLevel { self.level }
        fn category(&self) -> TestCategory { self.category }
        fn description(&self) -> &str { &self.description }
        fn run(&self, _ctx: &ConformanceContext) -> ConformanceResult {
            ConformanceResult::Pass
        }
        fn tags(&self) -> Vec<&str> { vec![] }
    }

    #[test]
    fn test_coverage_matrix_calculation() {
        let tests: Vec<Box<dyn ConformanceTest>> = vec![
            Box::new(MockTest {
                clause: "RFC6330-4.1.1".to_string(),
                section: "4.1".to_string(),
                level: RequirementLevel::Must,
                category: TestCategory::Unit,
                description: "Test 1".to_string(),
            }),
            Box::new(MockTest {
                clause: "RFC6330-4.1.2".to_string(),
                section: "4.1".to_string(),
                level: RequirementLevel::Should,
                category: TestCategory::Unit,
                description: "Test 2".to_string(),
            }),
        ];

        let executions: Vec<TestExecution> = tests.iter().map(|test| {
            TestExecution {
                test: test.as_ref(),
                result: ConformanceResult::Pass,
                duration: std::time::Duration::from_millis(100),
                timestamp: std::time::SystemTime::now(),
            }
        }).collect();

        let matrix = CoverageMatrix::from_test_results(&executions, "test-version".to_string());

        assert_eq!(matrix.overall.must_total, 1);
        assert_eq!(matrix.overall.must_passing, 1);
        assert_eq!(matrix.overall.should_total, 1);
        assert_eq!(matrix.overall.should_passing, 1);
        assert_eq!(matrix.compliance_score, 100.0);
        assert_eq!(matrix.conformance_level, ConformanceLevel::FullyConformant);
    }

    #[test]
    fn test_section_coverage_calculation() {
        let mut section = SectionCoverage::new("4.1".to_string(), "Test Section".to_string());

        section.must_total = 10;
        section.must_passing = 9;  // 90% MUST coverage
        section.should_total = 5;
        section.should_passing = 4; // 80% SHOULD coverage

        section.calculate_score();

        assert_eq!(section.must_coverage_percent(), 90.0);
        assert_eq!(section.should_coverage_percent(), 80.0);
        assert!((section.score - 86.67).abs() < 0.1); // (9+4)/(10+5) * 100
        assert_eq!(section.conformance_status, SectionConformanceStatus::Warning);
    }

    #[test]
    fn test_conformance_level_determination() {
        let mut matrix = CoverageMatrix::new("test-version".to_string());

        // Test FullyConformant
        matrix.overall.must_total = 20;
        matrix.overall.must_passing = 19;  // 95% MUST
        matrix.overall.should_total = 10;
        matrix.overall.should_passing = 9; // 90% SHOULD
        matrix.calculate_compliance_score();
        assert_eq!(matrix.conformance_level, ConformanceLevel::FullyConformant);

        // Test PartiallyConformant
        matrix.overall.must_passing = 17;  // 85% MUST
        matrix.overall.should_passing = 7; // 70% SHOULD
        matrix.calculate_compliance_score();
        assert_eq!(matrix.conformance_level, ConformanceLevel::PartiallyConformant);

        // Test NonConformant
        matrix.overall.must_passing = 15;  // 75% MUST (below 85% threshold)
        matrix.calculate_compliance_score();
        assert_eq!(matrix.conformance_level, ConformanceLevel::NonConformant);
    }
}