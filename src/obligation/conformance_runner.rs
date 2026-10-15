//! Unified conformance test runner for obligation system components.
//!
//! This module orchestrates all conformance test harnesses in the obligation
//! system and generates a comprehensive compliance report covering:
//!
//! 1. **E-Process Martingales**: Statistical leak detection conformance
//! 2. **Static Leak Checker**: Abstract interpretation analysis conformance
//! 3. **Graded Types**: Type-level obligation safety conformance
//!
//! The runner implements Pattern 4 (Spec-Derived Test Matrix) from the
//! testing-conformance-harnesses skill, providing systematic verification
//! of mathematical and safety requirements.

use super::eprocess::conformance::EProcessConformanceHarness;
use super::graded_conformance::GradedConformanceHarness;
use super::leak_check_conformance::LeakCheckConformanceHarness;

/// Unified conformance test runner for all obligation system components.
pub struct ObligationConformanceRunner {
    eprocess_harness: EProcessConformanceHarness,
    leak_check_harness: LeakCheckConformanceHarness,
    graded_harness: GradedConformanceHarness,
    overall_results: Vec<ComponentResult>,
}

/// Results for a specific component's conformance testing.
#[derive(Debug, Clone)]
pub struct ComponentResult {
    /// Component name (e.g., "E-Process", "Leak Checker").
    pub component: &'static str,
    /// Total number of requirements tested.
    pub total_tests: usize,
    /// Number of MUST requirements.
    pub must_tests: usize,
    /// Number of SHOULD requirements.
    pub should_tests: usize,
    /// Number of passing tests.
    pub passed_tests: usize,
    /// Number of failing tests.
    pub failed_tests: usize,
    /// Number of expected failures (XFAIL).
    pub xfail_tests: usize,
    /// Number of skipped tests.
    pub skipped_tests: usize,
    /// MUST requirement compliance percentage.
    pub must_compliance: f64,
    /// Overall compliance verdict.
    pub verdict: ComplianceVerdict,
}

/// Overall compliance verdict for a component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceVerdict {
    /// All critical requirements pass (≥95% MUST compliance).
    Conformant,
    /// Some critical requirements fail (<95% MUST compliance).
    NonConformant,
    /// Testing was incomplete or inconclusive.
    Inconclusive,
}

impl ObligationConformanceRunner {
    /// Creates a new unified conformance runner.
    pub fn new() -> Self {
        Self {
            eprocess_harness: EProcessConformanceHarness::new(),
            leak_check_harness: LeakCheckConformanceHarness::new(),
            graded_harness: GradedConformanceHarness::new(),
            overall_results: Vec::new(),
        }
    }

    /// Runs all conformance test harnesses and collects results.
    pub fn run_all_conformance_tests(&mut self) {
        self.overall_results.clear();

        // Run E-Process conformance tests
        self.eprocess_harness.run_all();
        let eprocess_result = self.analyze_eprocess_results();
        self.overall_results.push(eprocess_result);

        // Run Leak Checker conformance tests
        self.leak_check_harness.run_all();
        let leak_check_result = self.analyze_leak_check_results();
        self.overall_results.push(leak_check_result);

        // Run Graded Types conformance tests
        self.graded_harness.run_all();
        let graded_result = self.analyze_graded_results();
        self.overall_results.push(graded_result);
    }

    /// Generates a comprehensive compliance report covering all components.
    pub fn generate_compliance_report(&self) -> String {
        let mut report = String::new();

        report.push_str("# Obligation System Conformance Report\n\n");
        report.push_str(&format!(
            "Generated: {}\n\n",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or_else(
                    |_| "Unknown time".to_string(),
                    |d| format!("Unix timestamp: {}", d.as_secs()),
                )
        ));

        report.push_str("## Executive Summary\n\n");
        report.push_str("| Component | Total Tests | MUST Pass/Total | Verdict |\n");
        report.push_str("|-----------|-------------|-----------------|----------|\n");

        let mut overall_conformant = true;
        for result in &self.overall_results {
            let verdict_str = match result.verdict {
                ComplianceVerdict::Conformant => "✅ CONFORMANT",
                ComplianceVerdict::NonConformant => {
                    overall_conformant = false;
                    "❌ NON-CONFORMANT"
                }
                ComplianceVerdict::Inconclusive => {
                    overall_conformant = false;
                    "⚠️ INCONCLUSIVE"
                }
            };

            report.push_str(&format!(
                "| {} | {} | {}/{} ({:.1}%) | {} |\n",
                result.component,
                result.total_tests,
                result.passed_tests.min(result.must_tests), // MUST passed
                result.must_tests,
                result.must_compliance,
                verdict_str
            ));
        }

        report.push_str("\n### Overall System Verdict\n\n");
        if overall_conformant {
            report.push_str("🎉 **SYSTEM CONFORMANT**: All critical obligation safety requirements satisfied\n\n");
        } else {
            report.push_str("❌ **SYSTEM NON-CONFORMANT**: Critical obligation safety requirements not satisfied\n\n");
        }

        // Individual component reports
        report.push_str("## Component Details\n\n");

        report.push_str("### E-Process Martingale Analysis\n\n");
        report.push_str(&self.eprocess_harness.compliance_matrix());
        report.push_str("\n\n");

        report.push_str("### Static Leak Checker Analysis\n\n");
        report.push_str(&self.leak_check_harness.compliance_matrix());
        report.push_str("\n\n");

        report.push_str("### Graded Types Analysis\n\n");
        report.push_str(&self.graded_harness.compliance_matrix());
        report.push_str("\n\n");

        // Coverage Analysis
        report.push_str("## Coverage Analysis\n\n");
        report.push_str("### Requirements by Category\n\n");

        let total_must: usize = self.overall_results.iter().map(|r| r.must_tests).sum();
        let total_should: usize = self.overall_results.iter().map(|r| r.should_tests).sum();
        let total_tests: usize = self.overall_results.iter().map(|r| r.total_tests).sum();

        report.push_str(&format!(
            "- **MUST requirements**: {} ({:.1}% of total)\n",
            total_must,
            (total_must as f64 / total_tests as f64) * 100.0
        ));
        report.push_str(&format!(
            "- **SHOULD requirements**: {} ({:.1}% of total)\n",
            total_should,
            (total_should as f64 / total_tests as f64) * 100.0
        ));
        report.push_str(&format!("- **Total requirements**: {}\n\n", total_tests));

        // Failure Analysis
        let total_failures: usize = self.overall_results.iter().map(|r| r.failed_tests).sum();
        if total_failures > 0 {
            report.push_str("### Failure Analysis\n\n");
            report.push_str(&format!(
                "❌ **{} requirements failing** - requires immediate attention\n\n",
                total_failures
            ));

            for result in &self.overall_results {
                if result.failed_tests > 0 {
                    report.push_str(&format!(
                        "**{}**: {} failures\n",
                        result.component, result.failed_tests
                    ));
                }
            }
            report.push('\n');
        }

        // Recommendations
        report.push_str("## Recommendations\n\n");

        if overall_conformant {
            report.push_str("✅ The obligation system demonstrates full conformance to safety requirements.\n\n");
            report.push_str("**Maintenance Actions:**\n");
            report.push_str("- Continue running conformance tests on every change\n");
            report.push_str("- Monitor for performance regressions in e-process calculations\n");
            report.push_str("- Review and update test cases when new obligation kinds are added\n");
        } else {
            report.push_str(
                "❌ **CRITICAL**: The obligation system has failing safety requirements.\n\n",
            );
            report.push_str("**Immediate Actions Required:**\n");
            report.push_str("- Fix all failing MUST requirements before deployment\n");
            report.push_str("- Investigate root causes of non-conformance\n");
            report.push_str("- Add regression tests for fixed issues\n");
        }

        report
    }

    /// Returns results for a specific component.
    pub fn component_result(&self, component: &str) -> Option<&ComponentResult> {
        self.overall_results
            .iter()
            .find(|r| r.component == component)
    }

    /// Returns true if all components are conformant.
    pub fn is_system_conformant(&self) -> bool {
        self.overall_results
            .iter()
            .all(|r| r.verdict == ComplianceVerdict::Conformant)
    }

    /// Returns the total number of failing requirements across all components.
    pub fn total_failures(&self) -> usize {
        self.overall_results.iter().map(|r| r.failed_tests).sum()
    }

    fn analyze_eprocess_results(&self) -> ComponentResult {
        let results = self.eprocess_harness.results();
        self.analyze_component_results(
            "E-Process Martingales",
            results.iter().map(|r| (r.level, r.status)).collect(),
        )
    }

    fn analyze_leak_check_results(&self) -> ComponentResult {
        let results = self.leak_check_harness.results();
        self.analyze_component_results(
            "Static Leak Checker",
            results.iter().map(|r| (r.level, r.status)).collect(),
        )
    }

    fn analyze_graded_results(&self) -> ComponentResult {
        let results = self.graded_harness.results();
        self.analyze_component_results(
            "Graded Types",
            results.iter().map(|r| (r.level, r.status)).collect(),
        )
    }

    fn analyze_component_results<Level, Status>(
        &self,
        component: &'static str,
        results: Vec<(Level, Status)>,
    ) -> ComponentResult
    where
        Level: RequirementLevelTrait,
        Status: TestStatusTrait,
    {
        let total_tests = results.len();
        let mut must_tests = 0;
        let mut should_tests = 0;
        let mut passed_tests = 0;
        let mut failed_tests = 0;
        let mut xfail_tests = 0;
        let mut skipped_tests = 0;
        let mut must_passed = 0;

        for (level, status) in results {
            match level.level_type() {
                LevelType::Must => {
                    must_tests += 1;
                    if status.is_pass() {
                        must_passed += 1;
                    }
                }
                LevelType::Should => should_tests += 1,
                LevelType::May => {}
            }

            match status.status_type() {
                StatusType::Pass => passed_tests += 1,
                StatusType::Fail => failed_tests += 1,
                StatusType::XFail => xfail_tests += 1,
                StatusType::Skip => skipped_tests += 1,
            }
        }

        let must_compliance = if must_tests > 0 {
            (must_passed as f64 / must_tests as f64) * 100.0
        } else {
            100.0
        };

        let verdict = if must_compliance >= 95.0 && failed_tests == 0 {
            ComplianceVerdict::Conformant
        } else if failed_tests > 0 {
            ComplianceVerdict::NonConformant
        } else {
            ComplianceVerdict::Inconclusive
        };

        ComponentResult {
            component,
            total_tests,
            must_tests,
            should_tests,
            passed_tests,
            failed_tests,
            xfail_tests,
            skipped_tests,
            must_compliance,
            verdict,
        }
    }
}

// Trait abstractions to handle different result types
trait RequirementLevelTrait {
    fn level_type(&self) -> LevelType;
}

trait TestStatusTrait {
    fn status_type(&self) -> StatusType;
    fn is_pass(&self) -> bool;
}

#[derive(Debug, Clone, Copy)]
enum LevelType {
    Must,
    Should,
    May,
}

#[derive(Debug, Clone, Copy)]
enum StatusType {
    Pass,
    Fail,
    XFail,
    Skip,
}

// Implement traits for e-process types
impl RequirementLevelTrait for super::eprocess::conformance::RequirementLevel {
    fn level_type(&self) -> LevelType {
        match self {
            Self::Must => LevelType::Must,
            Self::Should => LevelType::Should,
            Self::May => LevelType::May,
        }
    }
}

impl TestStatusTrait for super::eprocess::conformance::TestStatus {
    fn status_type(&self) -> StatusType {
        match self {
            Self::Pass => StatusType::Pass,
            Self::Fail => StatusType::Fail,
            Self::Skip => StatusType::Skip,
            Self::XFail => StatusType::XFail,
        }
    }

    fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }
}

// Implement traits for leak check types
impl RequirementLevelTrait for super::leak_check_conformance::RequirementLevel {
    fn level_type(&self) -> LevelType {
        match self {
            Self::Must => LevelType::Must,
            Self::Should => LevelType::Should,
            Self::May => LevelType::May,
        }
    }
}

impl TestStatusTrait for super::leak_check_conformance::TestStatus {
    fn status_type(&self) -> StatusType {
        match self {
            Self::Pass => StatusType::Pass,
            Self::Fail => StatusType::Fail,
            Self::Skip => StatusType::Skip,
            Self::XFail => StatusType::XFail,
        }
    }

    fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }
}

// Implement traits for graded types
impl RequirementLevelTrait for super::graded_conformance::RequirementLevel {
    fn level_type(&self) -> LevelType {
        match self {
            Self::Must => LevelType::Must,
            Self::Should => LevelType::Should,
            Self::May => LevelType::May,
        }
    }
}

impl TestStatusTrait for super::graded_conformance::TestStatus {
    fn status_type(&self) -> StatusType {
        match self {
            Self::Pass => StatusType::Pass,
            Self::Fail => StatusType::Fail,
            Self::Skip => StatusType::Skip,
            Self::XFail => StatusType::XFail,
        }
    }

    fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }
}

impl Default for ObligationConformanceRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn conformance_runner_executes_all_harnesses() {
        let mut runner = ObligationConformanceRunner::new();
        runner.run_all_conformance_tests();

        // Should have results for all three components
        assert_eq!(runner.overall_results.len(), 3);

        let component_names: Vec<_> = runner.overall_results.iter().map(|r| r.component).collect();

        assert!(component_names.contains(&"E-Process Martingales"));
        assert!(component_names.contains(&"Static Leak Checker"));
        assert!(component_names.contains(&"Graded Types"));
    }

    #[test]
    fn compliance_report_generation() {
        let mut runner = ObligationConformanceRunner::new();
        runner.run_all_conformance_tests();

        let report = runner.generate_compliance_report();

        // Should contain key sections
        assert!(report.contains("Obligation System Conformance Report"));
        assert!(report.contains("Executive Summary"));
        assert!(report.contains("Component Details"));
        assert!(report.contains("E-Process Martingale Analysis"));
        assert!(report.contains("Static Leak Checker Analysis"));
        assert!(report.contains("Graded Types Analysis"));
    }

    #[test]
    fn component_result_access() {
        let mut runner = ObligationConformanceRunner::new();
        runner.run_all_conformance_tests();

        let eprocess_result = runner.component_result("E-Process Martingales");
        assert!(eprocess_result.is_some());

        let nonexistent = runner.component_result("Nonexistent Component");
        assert!(nonexistent.is_none());
    }
}
