//! RFC 6330 RaptorQ Conformance Testing Infrastructure
//!
//! This module provides a comprehensive conformance testing framework for validating
//! RFC 6330 compliance in the asupersync RaptorQ implementation.
//!
//! # Architecture
//!
//! The conformance testing infrastructure follows Pattern 4 (Spec-Derived Tests)
//! from the conformance harness methodology:
//! - `ConformanceTest` trait for systematic requirement validation
//! - `ConformanceRunner` for test execution and result collection
//! - `CoverageMatrix` for compliance scoring and reporting
//! - `ConformanceResult` for structured test outcomes
//!
//! # Usage
//!
//! ```rust
//! use asupersync_conformance::raptorq_rfc6330::*;
//!
//! let runner = ConformanceRunner::new();
//! let results = runner.run_all_tests()?;
//! let coverage = CoverageMatrix::from_results(&results);
//! assert!(coverage.overall_score() >= 0.95); // 95% conformance requirement
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, Instant};

// ============================================================================
// Core Conformance Types
// ============================================================================

/// RFC 6330 requirement level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RequirementLevel {
    /// MUST clause - conformance critical
    Must,
    /// SHOULD clause - recommended behavior
    Should,
    /// MAY clause - optional behavior
    May,
}

impl fmt::Display for RequirementLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequirementLevel::Must => write!(f, "MUST"),
            RequirementLevel::Should => write!(f, "SHOULD"),
            RequirementLevel::May => write!(f, "MAY"),
        }
    }
}

/// Test category for requirement classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestCategory {
    /// Unit testable - can be tested in isolation
    Unit,
    /// Integration testable - requires multiple components
    Integration,
    /// Edge case - boundary conditions and error scenarios
    EdgeCase,
    /// Performance constraint - algorithmic complexity requirements
    Performance,
    /// Differential - best tested against reference implementation
    Differential,
}

/// Structured conformance test result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum ConformanceResult {
    /// Test passed - requirement satisfied
    Pass,
    /// Test failed - requirement violated
    Fail {
        reason: String,
        details: Option<String>,
    },
    /// Test skipped - not applicable or dependencies missing
    Skipped {
        reason: String,
    },
    /// Expected failure - documented intentional divergence
    ExpectedFailure {
        reason: String,
        discrepancy_id: String, // Reference to DISCREPANCIES.md entry
    },
}

impl ConformanceResult {
    /// Check if result represents a passing test (Pass or ExpectedFailure)
    pub fn is_passing(&self) -> bool {
        matches!(self, ConformanceResult::Pass | ConformanceResult::ExpectedFailure { .. })
    }

    /// Check if result represents a conformance failure
    pub fn is_failing(&self) -> bool {
        matches!(self, ConformanceResult::Fail { .. })
    }

    /// Get human-readable result description
    pub fn description(&self) -> String {
        match self {
            ConformanceResult::Pass => "PASS".to_string(),
            ConformanceResult::Fail { reason, .. } => format!("FAIL: {reason}"),
            ConformanceResult::Skipped { reason } => format!("SKIP: {reason}"),
            ConformanceResult::ExpectedFailure { reason, discrepancy_id } => {
                format!("XFAIL: {reason} (see {discrepancy_id})")
            }
        }
    }
}

/// Test execution context and configuration
#[derive(Debug, Clone)]
pub struct ConformanceContext {
    /// Test timeout for individual conformance tests
    pub timeout: Duration,
    /// Enable differential testing against reference implementation
    pub enable_differential: bool,
    /// Path to reference implementation fixtures
    pub fixtures_path: Option<std::path::PathBuf>,
    /// Random seed for reproducible test execution
    pub random_seed: u64,
    /// Enable verbose logging for debugging
    pub verbose: bool,
}

impl Default for ConformanceContext {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            enable_differential: false,
            fixtures_path: None,
            random_seed: 42,
            verbose: false,
        }
    }
}

// ============================================================================
// Core Conformance Trait
// ============================================================================

/// Core trait for RFC 6330 conformance tests
///
/// Each conformance test validates one specific requirement from RFC 6330,
/// providing systematic coverage of the specification with structured results.
///
/// # Example Implementation
///
/// ```rust
/// use asupersync_conformance::raptorq_rfc6330::*;
///
/// struct LookupTableV0Test;
///
/// impl ConformanceTest for LookupTableV0Test {
///     fn rfc_clause(&self) -> &str { "RFC6330-5.5.1" }
///     fn section(&self) -> &str { "5.5" }
///     fn requirement_level(&self) -> RequirementLevel { RequirementLevel::Must }
///     fn category(&self) -> TestCategory { TestCategory::Unit }
///     fn description(&self) -> &str {
///         "Lookup table V0 MUST match RFC 6330 values exactly"
///     }
///
///     fn run(&self, _ctx: &ConformanceContext) -> ConformanceResult {
///         // Validate V0 table implementation
///         for i in 0..256 {
///             if crate::raptorq::rfc6330::V0[i] != RFC_V0_REFERENCE[i] {
///                 return ConformanceResult::Fail {
///                     reason: format!("V0[{i}] mismatch"),
///                     details: Some(format!("expected: {}, actual: {}",
///                         RFC_V0_REFERENCE[i], crate::raptorq::rfc6330::V0[i]))
///                 };
///             }
///         }
///         ConformanceResult::Pass
///     }
/// }
/// ```
pub trait ConformanceTest: Send + Sync {
    /// RFC clause identifier (e.g., "RFC6330-5.5.1")
    fn rfc_clause(&self) -> &str;

    /// RFC section number (e.g., "5.5")
    fn section(&self) -> &str;

    /// Requirement level (MUST, SHOULD, MAY)
    fn requirement_level(&self) -> RequirementLevel;

    /// Test category classification
    fn category(&self) -> TestCategory;

    /// Human-readable test description
    fn description(&self) -> &str;

    /// Execute the conformance test
    fn run(&self, ctx: &ConformanceContext) -> ConformanceResult;

    /// Test name for identification (defaults to RFC clause)
    fn name(&self) -> String {
        self.rfc_clause().to_string()
    }

    /// Test dependencies - RFC clauses that must pass first
    fn dependencies(&self) -> Vec<&str> {
        Vec::new()
    }

    /// Test tags for filtering and organization
    fn tags(&self) -> Vec<&str> {
        Vec::new()
    }
}

// ============================================================================
// Test Execution Engine
// ============================================================================

/// Execution result for a single conformance test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestExecution {
    /// Test identifier
    pub test_name: String,
    /// RFC clause being tested
    pub rfc_clause: String,
    /// RFC section
    pub section: String,
    /// Requirement level
    pub level: RequirementLevel,
    /// Test category
    pub category: TestCategory,
    /// Test description
    pub description: String,
    /// Test result
    pub result: ConformanceResult,
    /// Execution duration
    pub duration: Duration,
    /// Execution timestamp
    pub timestamp: std::time::SystemTime,
}

/// Comprehensive test execution runner for RFC 6330 conformance
pub struct ConformanceRunner {
    /// Registered conformance tests
    tests: Vec<Box<dyn ConformanceTest>>,
    /// Test execution context
    context: ConformanceContext,
}

impl ConformanceRunner {
    /// Create new conformance runner with default context
    pub fn new() -> Self {
        Self {
            tests: Vec::new(),
            context: ConformanceContext::default(),
        }
    }

    /// Create conformance runner with custom context
    pub fn with_context(context: ConformanceContext) -> Self {
        Self {
            tests: Vec::new(),
            context,
        }
    }

    /// Register a conformance test
    pub fn register_test<T: ConformanceTest + 'static>(&mut self, test: T) {
        self.tests.push(Box::new(test));
    }

    /// Register multiple conformance tests
    pub fn register_tests<I, T>(&mut self, tests: I)
    where
        I: IntoIterator<Item = T>,
        T: ConformanceTest + 'static,
    {
        for test in tests {
            self.register_test(test);
        }
    }

    /// Run all registered conformance tests
    pub fn run_all_tests(&self) -> Vec<TestExecution> {
        self.run_tests_by_filter(|_| true)
    }

    /// Run tests for specific RFC section
    pub fn run_section_tests(&self, section: &str) -> Vec<TestExecution> {
        self.run_tests_by_filter(|test| test.section() == section)
    }

    /// Run tests for specific requirement level
    pub fn run_level_tests(&self, level: RequirementLevel) -> Vec<TestExecution> {
        self.run_tests_by_filter(|test| test.requirement_level() == level)
    }

    /// Run tests matching category
    pub fn run_category_tests(&self, category: TestCategory) -> Vec<TestExecution> {
        self.run_tests_by_filter(|test| test.category() == category)
    }

    /// Run tests matching predicate filter
    pub fn run_tests_by_filter<F>(&self, filter: F) -> Vec<TestExecution>
    where
        F: Fn(&dyn ConformanceTest) -> bool,
    {
        let mut executions = Vec::new();

        for test in &self.tests {
            if filter(test.as_ref()) {
                let start = Instant::now();
                let timestamp = std::time::SystemTime::now();

                // Execute test with timeout
                if self.context.verbose {
                    eprintln!("Running conformance test: {}", test.name());
                }

                let test_result = test.run(&self.context);
                let duration = start.elapsed();

                if self.context.verbose {
                    eprintln!("  Result: {}", test_result.description());
                    eprintln!("  Duration: {duration:?}");
                }

                executions.push(TestExecution {
                    test_name: test.name(),
                    rfc_clause: test.rfc_clause().to_string(),
                    section: test.section().to_string(),
                    level: test.requirement_level(),
                    category: test.category(),
                    description: test.description().to_string(),
                    result: test_result,
                    duration,
                    timestamp,
                });
            }
        }

        executions
    }

    /// Get count of registered tests
    pub fn test_count(&self) -> usize {
        self.tests.len()
    }

    /// Get count of tests by requirement level
    pub fn test_count_by_level(&self, level: RequirementLevel) -> usize {
        self.tests.iter()
            .filter(|test| test.requirement_level() == level)
            .count()
    }

    /// Get test names for debugging
    pub fn test_names(&self) -> Vec<String> {
        self.tests.iter().map(|test| test.name()).collect()
    }
}

impl Default for ConformanceRunner {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Coverage Matrix and Compliance Scoring
// ============================================================================

/// Section-level coverage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionCoverage {
    /// RFC section identifier
    pub section: String,
    /// Section title/description
    pub title: String,
    /// MUST requirement counts
    pub must_total: usize,
    pub must_passing: usize,
    /// SHOULD requirement counts
    pub should_total: usize,
    pub should_passing: usize,
    /// MAY requirement counts
    pub may_total: usize,
    pub may_passing: usize,
    /// Section conformance score (0.0 - 1.0)
    pub score: f64,
    /// Section conformance status
    pub status: ConformanceStatus,
}

impl SectionCoverage {
    /// Calculate section conformance score
    fn calculate_score(&mut self) {
        let weighted_total = (self.must_total * 2) + self.should_total;
        let weighted_passing = (self.must_passing * 2) + self.should_passing;

        self.score = if weighted_total > 0 {
            weighted_passing as f64 / weighted_total as f64
        } else {
            1.0 // No requirements = perfect score
        };

        // Determine conformance status based on MUST clause coverage
        self.status = if self.must_total > 0 {
            let must_score = self.must_passing as f64 / self.must_total as f64;
            if must_score >= 0.95 {
                ConformanceStatus::Conformant
            } else if must_score >= 0.80 {
                ConformanceStatus::PartiallyConformant
            } else {
                ConformanceStatus::NonConformant
            }
        } else {
            ConformanceStatus::Conformant
        };
    }
}

/// Overall conformance status classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConformanceStatus {
    /// ≥95% MUST clause coverage
    Conformant,
    /// 80-94% MUST clause coverage
    PartiallyConformant,
    /// <80% MUST clause coverage
    NonConformant,
}

impl fmt::Display for ConformanceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConformanceStatus::Conformant => write!(f, "✅ Conformant"),
            ConformanceStatus::PartiallyConformant => write!(f, "⚠️ Partially Conformant"),
            ConformanceStatus::NonConformant => write!(f, "❌ Non-Conformant"),
        }
    }
}

/// Comprehensive coverage matrix for RFC 6330 conformance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageMatrix {
    /// Per-section coverage breakdown
    pub sections: BTreeMap<String, SectionCoverage>,
    /// Overall conformance statistics
    pub overall: OverallCoverage,
    /// Report generation timestamp
    pub generated_at: std::time::SystemTime,
}

/// Overall conformance coverage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverallCoverage {
    /// Total requirement counts
    pub total_requirements: usize,
    pub must_requirements: usize,
    pub should_requirements: usize,
    pub may_requirements: usize,

    /// Passing requirement counts
    pub passing_requirements: usize,
    pub must_passing: usize,
    pub should_passing: usize,
    pub may_passing: usize,

    /// Failed requirement counts
    pub failed_requirements: usize,
    pub must_failed: usize,
    pub should_failed: usize,
    pub may_failed: usize,

    /// Skipped requirement counts
    pub skipped_requirements: usize,

    /// Overall conformance score (0.0 - 1.0)
    pub conformance_score: f64,
    /// Overall conformance status
    pub conformance_status: ConformanceStatus,
}

impl CoverageMatrix {
    /// Generate coverage matrix from test execution results
    pub fn from_results(results: &[TestExecution]) -> Self {
        let mut sections: BTreeMap<String, SectionCoverage> = BTreeMap::new();

        // Initialize section data from RFC requirements matrix
        let rfc_sections = load_rfc_section_metadata();
        for (section_id, title) in rfc_sections {
            sections.insert(section_id.clone(), SectionCoverage {
                section: section_id,
                title,
                must_total: 0,
                must_passing: 0,
                should_total: 0,
                should_passing: 0,
                may_total: 0,
                may_passing: 0,
                score: 0.0,
                status: ConformanceStatus::NonConformant,
            });
        }

        // Populate coverage data from test results
        for execution in results {
            if let Some(section_coverage) = sections.get_mut(&execution.section) {
                match execution.level {
                    RequirementLevel::Must => {
                        section_coverage.must_total += 1;
                        if execution.result.is_passing() {
                            section_coverage.must_passing += 1;
                        }
                    }
                    RequirementLevel::Should => {
                        section_coverage.should_total += 1;
                        if execution.result.is_passing() {
                            section_coverage.should_passing += 1;
                        }
                    }
                    RequirementLevel::May => {
                        section_coverage.may_total += 1;
                        if execution.result.is_passing() {
                            section_coverage.may_passing += 1;
                        }
                    }
                }
            }
        }

        // Calculate section scores
        for section_coverage in sections.values_mut() {
            section_coverage.calculate_score();
        }

        // Calculate overall statistics
        let overall = calculate_overall_coverage(&sections);

        Self {
            sections,
            overall,
            generated_at: std::time::SystemTime::now(),
        }
    }

    /// Get overall conformance score (0.0 - 1.0)
    pub fn overall_score(&self) -> f64 {
        self.overall.conformance_score
    }

    /// Get overall conformance status
    pub fn overall_status(&self) -> ConformanceStatus {
        self.overall.conformance_status
    }

    /// Check if implementation meets minimum conformance threshold
    pub fn meets_conformance_threshold(&self) -> bool {
        matches!(self.overall.conformance_status, ConformanceStatus::Conformant)
    }

    /// Get sections failing conformance requirements
    pub fn failing_sections(&self) -> Vec<&SectionCoverage> {
        self.sections.values()
            .filter(|section| matches!(section.status, ConformanceStatus::NonConformant))
            .collect()
    }
}

/// Calculate overall coverage statistics from section data
fn calculate_overall_coverage(sections: &BTreeMap<String, SectionCoverage>) -> OverallCoverage {
    let mut overall = OverallCoverage {
        total_requirements: 0,
        must_requirements: 0,
        should_requirements: 0,
        may_requirements: 0,
        passing_requirements: 0,
        must_passing: 0,
        should_passing: 0,
        may_passing: 0,
        failed_requirements: 0,
        must_failed: 0,
        should_failed: 0,
        may_failed: 0,
        skipped_requirements: 0,
        conformance_score: 0.0,
        conformance_status: ConformanceStatus::NonConformant,
    };

    for section in sections.values() {
        overall.must_requirements += section.must_total;
        overall.should_requirements += section.should_total;
        overall.may_requirements += section.may_total;

        overall.must_passing += section.must_passing;
        overall.should_passing += section.should_passing;
        overall.may_passing += section.may_passing;

        overall.must_failed += section.must_total - section.must_passing;
        overall.should_failed += section.should_total - section.should_passing;
        overall.may_failed += section.may_total - section.may_passing;
    }

    overall.total_requirements = overall.must_requirements + overall.should_requirements + overall.may_requirements;
    overall.passing_requirements = overall.must_passing + overall.should_passing + overall.may_passing;
    overall.failed_requirements = overall.must_failed + overall.should_failed + overall.may_failed;

    // Calculate weighted conformance score (MUST clauses worth 2x, SHOULD worth 1x)
    let weighted_total = (overall.must_requirements * 2) + overall.should_requirements;
    let weighted_passing = (overall.must_passing * 2) + overall.should_passing;

    overall.conformance_score = if weighted_total > 0 {
        weighted_passing as f64 / weighted_total as f64
    } else {
        1.0
    };

    // Determine overall conformance status based on MUST clause coverage
    let must_score = if overall.must_requirements > 0 {
        overall.must_passing as f64 / overall.must_requirements as f64
    } else {
        1.0
    };

    overall.conformance_status = if must_score >= 0.95 {
        ConformanceStatus::Conformant
    } else if must_score >= 0.80 {
        ConformanceStatus::PartiallyConformant
    } else {
        ConformanceStatus::NonConformant
    };

    overall
}

/// Load RFC section metadata for coverage matrix initialization
fn load_rfc_section_metadata() -> Vec<(String, String)> {
    vec![
        ("4.1".to_string(), "Objects and Source Blocks".to_string()),
        ("4.2".to_string(), "Encoding Process".to_string()),
        ("4.3".to_string(), "Decoding Process".to_string()),
        ("5.1".to_string(), "Systematic Index".to_string()),
        ("5.2".to_string(), "Parameter Derivation".to_string()),
        ("5.3".to_string(), "Tuple Generation".to_string()),
        ("5.4".to_string(), "Constraint Matrix Structure".to_string()),
        ("5.5".to_string(), "Lookup Tables".to_string()),
    ]
}

// ============================================================================
// JSON-Line Logging for CI Integration
// ============================================================================

/// JSON-line log entry for CI integration
#[derive(Debug, Serialize)]
pub struct ConformanceLogEntry {
    pub timestamp: String,
    pub rfc_clause: String,
    pub section: String,
    pub level: RequirementLevel,
    pub status: String,
    pub duration_ms: u64,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discrepancy_id: Option<String>,
}

/// Generate JSON-line logs for CI consumption
pub fn generate_jsonl_logs(executions: &[TestExecution]) -> String {
    let mut logs = String::new();

    for execution in executions {
        let entry = ConformanceLogEntry {
            timestamp: execution.timestamp
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_string(),
            rfc_clause: execution.rfc_clause.clone(),
            section: execution.section.clone(),
            level: execution.level,
            status: match &execution.result {
                ConformanceResult::Pass => "PASS".to_string(),
                ConformanceResult::Fail { .. } => "FAIL".to_string(),
                ConformanceResult::Skipped { .. } => "SKIP".to_string(),
                ConformanceResult::ExpectedFailure { .. } => "XFAIL".to_string(),
            },
            duration_ms: execution.duration.as_millis() as u64,
            description: execution.description.clone(),
            failure_reason: match &execution.result {
                ConformanceResult::Fail { reason, .. } => Some(reason.clone()),
                ConformanceResult::Skipped { reason } => Some(reason.clone()),
                ConformanceResult::ExpectedFailure { reason, .. } => Some(reason.clone()),
                _ => None,
            },
            discrepancy_id: match &execution.result {
                ConformanceResult::ExpectedFailure { discrepancy_id, .. } => {
                    Some(discrepancy_id.clone())
                }
                _ => None,
            },
        };

        if let Ok(json) = serde_json::to_string(&entry) {
            logs.push_str(&json);
            logs.push('\n');
        }
    }

    logs
}