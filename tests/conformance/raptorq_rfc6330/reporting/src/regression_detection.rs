#![allow(clippy::all)]
//! Regression Detection Module
//!
//! This module provides functionality for detecting regressions in RaptorQ conformance
//! test results by comparing current test outcomes against historical baselines.

use crate::coverage_matrix::{CoverageMatrix, CoverageMatrixCalculator};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Configuration for regression detection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct RegressionConfig {
    /// Minimum conformance score to consider as passing (0.0 to 1.0)
    pub min_conformance_score: f64,
    /// Maximum allowed drop in conformance score before flagging as regression
    pub max_score_drop: f64,
    /// Number of historical runs to consider for baseline
    pub baseline_window: usize,
    /// Paths to historical conformance data
    pub historical_data_paths: Vec<PathBuf>,
    /// Whether to fail on any test failures (strict mode)
    pub strict_mode: bool,
}

impl Default for RegressionConfig {
    #[allow(dead_code)]
    fn default() -> Self {
        Self {
            min_conformance_score: 0.95,
            max_score_drop: 0.05,
            baseline_window: 10,
            historical_data_paths: vec![],
            strict_mode: false,
        }
    }
}

/// Historical conformance data point
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ConformanceSnapshot {
    /// Timestamp when this snapshot was taken
    pub timestamp: DateTime<Utc>,
    /// Git commit hash (if available)
    pub commit_hash: Option<String>,
    /// Overall conformance matrix for this snapshot
    pub coverage_matrix: CoverageMatrix,
    /// Build/environment information
    pub build_info: BuildInfo,
}

/// Build and environment information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct BuildInfo {
    /// Rust version used for the build
    pub rust_version: String,
    /// Target platform/architecture
    pub target_platform: String,
    /// Build profile (debug/release)
    pub build_profile: String,
    /// Additional build flags or environment variables
    pub environment: HashMap<String, String>,
}

impl Default for BuildInfo {
    #[allow(dead_code)]
    fn default() -> Self {
        Self {
            rust_version: "unknown".to_string(),
            target_platform: std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string()),
            build_profile: "unknown".to_string(),
            environment: HashMap::new(),
        }
    }
}

/// Result of regression detection analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct RegressionAnalysis {
    /// Whether any regressions were detected
    pub has_regressions: bool,
    /// Current conformance score
    pub current_score: f64,
    /// Baseline conformance score (average of recent historical data)
    pub baseline_score: f64,
    /// Change in score from baseline (negative indicates regression)
    pub score_change: f64,
    /// Detailed regression findings
    pub regressions: Vec<RegressionFinding>,
    /// Summary statistics
    pub summary: RegressionSummary,
}

/// Individual regression finding
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct RegressionFinding {
    /// Type of regression detected
    pub regression_type: RegressionType,
    /// Severity level
    pub severity: RegressionSeverity,
    /// Human-readable description
    pub description: String,
    /// Affected RFC section or test category
    pub affected_section: String,
    /// Previous state/value
    pub previous_value: String,
    /// Current state/value
    pub current_value: String,
    /// Suggested remediation steps
    pub remediation_suggestions: Vec<String>,
}

/// Types of regressions that can be detected
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub enum RegressionType {
    /// Overall conformance score dropped significantly
    ConformanceScoreDrop,
    /// New test failures appeared
    NewTestFailures,
    /// Previously passing tests now fail
    TestStatusRegression,
    /// Code coverage decreased
    CoverageDecrease,
    /// Performance regression (if timing data available)
    PerformanceRegression,
    /// Critical RFC section compliance lost
    CriticalComplianceLoss,
}

/// Severity levels for regressions
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(dead_code)]
pub enum RegressionSeverity {
    /// Critical regression that should block releases
    Critical,
    /// High severity that needs immediate attention
    High,
    /// Medium severity that should be addressed soon
    Medium,
    /// Low severity for informational purposes
    Low,
}

/// Summary statistics for regression analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct RegressionSummary {
    /// Total number of regressions found
    pub total_regressions: usize,
    /// Count by severity level
    pub by_severity: HashMap<RegressionSeverity, usize>,
    /// Count by regression type
    pub by_type: HashMap<RegressionType, usize>,
    /// Historical trend (improving/stable/declining)
    pub trend: ConformanceTrend,
}

/// Trend analysis for conformance over time
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ConformanceTrend {
    /// Conformance is improving over time
    Improving,
    /// Conformance is stable
    Stable,
    /// Conformance is declining
    Declining,
    /// Not enough data to determine trend
    Insufficient,
}

/// Main regression detection engine
#[allow(dead_code)]
pub struct RegressionDetector {
    config: RegressionConfig,
    calculator: CoverageMatrixCalculator,
}

#[allow(dead_code)]

impl RegressionDetector {
    /// Create a new regression detector with the given configuration
    #[allow(dead_code)]
    pub fn new(config: RegressionConfig) -> Self {
        Self {
            config,
            calculator: CoverageMatrixCalculator::new(),
        }
    }

    /// Create a regression detector with default configuration
    #[allow(dead_code)]
    pub fn default() -> Self {
        Self::new(RegressionConfig::default())
    }

    /// Detect regressions by comparing current results against historical baseline
    #[allow(dead_code)]
    pub fn detect_regressions(
        &self,
        current_matrix: &CoverageMatrix,
        golden_dir: &Path,
    ) -> Result<RegressionAnalysis> {
        // Load historical conformance data
        let historical_data = self.load_historical_data()?;

        if historical_data.is_empty() {
            return Ok(RegressionAnalysis {
                has_regressions: false,
                current_score: current_matrix.compliance_score,
                baseline_score: current_matrix.compliance_score,
                score_change: 0.0,
                regressions: vec![],
                summary: RegressionSummary {
                    total_regressions: 0,
                    by_severity: HashMap::new(),
                    by_type: HashMap::new(),
                    trend: ConformanceTrend::Insufficient,
                },
            });
        }

        // Calculate baseline from recent historical data
        let baseline = self.calculate_baseline(&historical_data)?;

        // Detect various types of regressions
        let mut regressions = Vec::new();

        // 1. Overall conformance score regression
        if let Some(finding) = self.detect_score_regression(current_matrix, &baseline)? {
            regressions.push(finding);
        }

        // 2. New test failures
        regressions.extend(self.detect_new_test_failures(current_matrix, &baseline)?);

        // 3. Critical section compliance loss
        regressions.extend(self.detect_critical_compliance_loss(current_matrix, &baseline)?);

        // 4. Coverage decrease
        if let Some(finding) = self.detect_coverage_decrease(current_matrix, &baseline)? {
            regressions.push(finding);
        }

        // Calculate trend
        let trend = self.calculate_trend(&historical_data);

        // Build summary
        let summary = self.build_summary(&regressions, trend);

        Ok(RegressionAnalysis {
            has_regressions: !regressions.is_empty(),
            current_score: current_matrix.compliance_score,
            baseline_score: baseline.coverage_matrix.compliance_score,
            score_change: current_matrix.compliance_score
                - baseline.coverage_matrix.compliance_score,
            regressions,
            summary,
        })
    }

    /// Store a conformance snapshot for future regression detection
    #[allow(dead_code)]
    pub fn store_snapshot(
        &self,
        coverage_matrix: &CoverageMatrix,
        commit_hash: Option<String>,
        output_path: &Path,
    ) -> Result<()> {
        let snapshot = ConformanceSnapshot {
            timestamp: Utc::now(),
            commit_hash,
            coverage_matrix: coverage_matrix.clone(),
            build_info: self.collect_build_info()?,
        };

        let json = serde_json::to_string_pretty(&snapshot)
            .context("Failed to serialize conformance snapshot")?;

        std::fs::write(output_path, json)
            .with_context(|| format!("Failed to write snapshot to {}", output_path.display()))?;

        Ok(())
    }

    /// Load historical conformance data from configured paths
    #[allow(dead_code)]
    fn load_historical_data(&self) -> Result<Vec<ConformanceSnapshot>> {
        let mut snapshots = Vec::new();

        for path in &self.config.historical_data_paths {
            if path.exists() {
                let content = std::fs::read_to_string(path)
                    .with_context(|| format!("Failed to read {}", path.display()))?;

                let snapshot: ConformanceSnapshot = serde_json::from_str(&content)
                    .with_context(|| format!("Failed to parse snapshot from {}", path.display()))?;

                snapshots.push(snapshot);
            }
        }

        // Sort by timestamp (newest first) and take the configured window
        snapshots.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        snapshots.truncate(self.config.baseline_window);

        Ok(snapshots)
    }

    /// Calculate baseline metrics from historical data
    #[allow(dead_code)]
    fn calculate_baseline(
        &self,
        historical_data: &[ConformanceSnapshot],
    ) -> Result<ConformanceSnapshot> {
        if historical_data.is_empty() {
            anyhow::bail!("No historical data available for baseline calculation");
        }

        // For now, use the most recent snapshot as baseline
        // In the future, we could calculate averages or use more sophisticated methods
        Ok(historical_data[0].clone())
    }

    /// Detect overall conformance score regression
    #[allow(dead_code)]
    fn detect_score_regression(
        &self,
        current: &CoverageMatrix,
        baseline: &ConformanceSnapshot,
    ) -> Result<Option<RegressionFinding>> {
        let current_score = current.compliance_score;
        let baseline_score = baseline.coverage_matrix.compliance_score;
        let score_drop = baseline_score - current_score;

        if score_drop > self.config.max_score_drop {
            let severity = if score_drop > 0.20 {
                RegressionSeverity::Critical
            } else if score_drop > 0.10 {
                RegressionSeverity::High
            } else {
                RegressionSeverity::Medium
            };

            return Ok(Some(RegressionFinding {
                regression_type: RegressionType::ConformanceScoreDrop,
                severity,
                description: format!(
                    "Overall conformance score dropped by {:.1}% (from {:.1}% to {:.1}%)",
                    score_drop * 100.0,
                    baseline_score * 100.0,
                    current_score * 100.0
                ),
                affected_section: "Overall".to_string(),
                previous_value: format!("{:.1}%", baseline_score * 100.0),
                current_value: format!("{:.1}%", current_score * 100.0),
                remediation_suggestions: vec![
                    "Review recent changes to RaptorQ implementation".to_string(),
                    "Check for newly introduced test failures".to_string(),
                    "Verify that all RFC 6330 requirements are still met".to_string(),
                ],
            }));
        }

        Ok(None)
    }

    /// Detect new test failures compared to baseline
    #[allow(dead_code)]
    fn detect_new_test_failures(
        &self,
        current: &CoverageMatrix,
        baseline: &ConformanceSnapshot,
    ) -> Result<Vec<RegressionFinding>> {
        let mut findings = Vec::new();

        // Compare section coverage to find new failures
        for (section, current_coverage) in &current.sections {
            if let Some(baseline_coverage) = baseline.coverage_matrix.sections.get(section) {
                let current_failures = current_coverage.failures.len();
                let baseline_failures = baseline_coverage.failures.len();

                if current_failures > baseline_failures {
                    let new_failures = current_failures - baseline_failures;

                    findings.push(RegressionFinding {
                        regression_type: RegressionType::NewTestFailures,
                        severity: RegressionSeverity::High,
                        description: format!(
                            "{} new test failure(s) in section {}",
                            new_failures, section
                        ),
                        affected_section: section.clone(),
                        previous_value: format!("{} failures", baseline_failures),
                        current_value: format!("{} failures", current_failures),
                        remediation_suggestions: vec![
                            format!("Investigate new failures in RFC section {}", section),
                            "Check test logs for failure details".to_string(),
                            "Verify implementation changes didn't break existing functionality"
                                .to_string(),
                        ],
                    });
                }
            }
        }

        Ok(findings)
    }

    /// Detect loss of critical section compliance
    #[allow(dead_code)]
    fn detect_critical_compliance_loss(
        &self,
        current: &CoverageMatrix,
        baseline: &ConformanceSnapshot,
    ) -> Result<Vec<RegressionFinding>> {
        let mut findings = Vec::new();

        for (section, current_coverage) in &current.sections {
            if let Some(baseline_coverage) = baseline.coverage_matrix.sections.get(section) {
                // Check if we lost PASS status in a critical section
                if baseline_coverage.conformance_status
                    == crate::coverage_matrix::SectionConformanceStatus::Pass
                    && current_coverage.conformance_status
                        != crate::coverage_matrix::SectionConformanceStatus::Pass
                {
                    findings.push(RegressionFinding {
                        regression_type: RegressionType::CriticalComplianceLoss,
                        severity: RegressionSeverity::Critical,
                        description: format!(
                            "Lost passing status in critical RFC section {}",
                            section
                        ),
                        affected_section: section.clone(),
                        previous_value: "Passing".to_string(),
                        current_value: format!("{:?}", current_coverage.conformance_status),
                        remediation_suggestions: vec![
                            format!("Restore full compliance for RFC section {}", section),
                            "This is a critical regression that may affect interoperability"
                                .to_string(),
                            "Review implementation against RFC 6330 requirements".to_string(),
                        ],
                    });
                }
            }
        }

        Ok(findings)
    }

    /// Detect coverage decrease
    #[allow(dead_code)]
    fn detect_coverage_decrease(
        &self,
        current: &CoverageMatrix,
        baseline: &ConformanceSnapshot,
    ) -> Result<Option<RegressionFinding>> {
        let current_total = current.overall.total_tests;
        let current_passing = current.overall.passing_tests;
        let current_coverage = if current_total > 0 {
            current_passing as f64 / current_total as f64
        } else {
            1.0
        };

        let baseline_total = baseline.coverage_matrix.overall.total_tests;
        let baseline_passing = baseline.coverage_matrix.overall.passing_tests;
        let baseline_coverage = if baseline_total > 0 {
            baseline_passing as f64 / baseline_total as f64
        } else {
            1.0
        };

        let coverage_drop = baseline_coverage - current_coverage;

        if coverage_drop > 0.05 {
            // 5% coverage drop threshold
            return Ok(Some(RegressionFinding {
                regression_type: RegressionType::CoverageDecrease,
                severity: RegressionSeverity::Medium,
                description: format!("Test coverage decreased by {:.1}%", coverage_drop * 100.0),
                affected_section: "Test Coverage".to_string(),
                previous_value: format!("{:.1}%", baseline_coverage * 100.0),
                current_value: format!("{:.1}%", current_coverage * 100.0),
                remediation_suggestions: vec![
                    "Add tests to cover newly identified requirements".to_string(),
                    "Ensure no existing tests were accidentally removed".to_string(),
                ],
            }));
        }

        Ok(None)
    }

    /// Calculate conformance trend from historical data
    #[allow(dead_code)]
    fn calculate_trend(&self, historical_data: &[ConformanceSnapshot]) -> ConformanceTrend {
        if historical_data.len() < 3 {
            return ConformanceTrend::Insufficient;
        }

        let scores: Vec<f64> = historical_data
            .iter()
            .map(|snapshot| snapshot.coverage_matrix.compliance_score)
            .collect();

        // Simple linear trend calculation
        let n = scores.len() as f64;
        let sum_x: f64 = (0..scores.len()).map(|i| i as f64).sum();
        let sum_y: f64 = scores.iter().sum();
        let sum_xy: f64 = scores.iter().enumerate().map(|(i, &y)| i as f64 * y).sum();
        let sum_x2: f64 = (0..scores.len()).map(|i| (i as f64).powi(2)).sum();

        let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x.powi(2));

        if slope > 0.01 {
            ConformanceTrend::Improving
        } else if slope < -0.01 {
            ConformanceTrend::Declining
        } else {
            ConformanceTrend::Stable
        }
    }

    /// Build regression analysis summary
    #[allow(dead_code)]
    fn build_summary(
        &self,
        regressions: &[RegressionFinding],
        trend: ConformanceTrend,
    ) -> RegressionSummary {
        let mut by_severity = HashMap::new();
        let mut by_type = HashMap::new();

        for regression in regressions {
            *by_severity.entry(regression.severity).or_insert(0) += 1;
            *by_type.entry(regression.regression_type).or_insert(0) += 1;
        }

        RegressionSummary {
            total_regressions: regressions.len(),
            by_severity,
            by_type,
            trend,
        }
    }

    /// Collect current build and environment information
    #[allow(dead_code)]
    fn collect_build_info(&self) -> Result<BuildInfo> {
        let mut environment = HashMap::new();

        // Collect some basic environment information
        if let Ok(value) = std::env::var("CARGO_PKG_VERSION") {
            environment.insert("CARGO_PKG_VERSION".to_string(), value);
        }
        if let Ok(value) = std::env::var("RUSTFLAGS") {
            environment.insert("RUSTFLAGS".to_string(), value);
        }

        Ok(BuildInfo {
            rust_version: std::env::var("RUSTC_VERSION").unwrap_or_else(|_| "unknown".to_string()),
            target_platform: std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string()),
            build_profile: if cfg!(debug_assertions) {
                "debug".to_string()
            } else {
                "release".to_string()
            },
            environment,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(dead_code)]
    fn test_regression_config_default() {
        let config = RegressionConfig::default();
        assert_eq!(config.min_conformance_score, 0.95);
        assert_eq!(config.max_score_drop, 0.05);
        assert_eq!(config.baseline_window, 10);
    }

    #[test]
    #[allow(dead_code)]
    fn test_build_info_default() {
        let build_info = BuildInfo::default();
        assert!(!build_info.target_platform.is_empty());
    }

    #[test]
    #[allow(dead_code)]
    fn test_regression_detector_creation() {
        let config = RegressionConfig::default();
        let detector = RegressionDetector::new(config);
        assert_eq!(detector.config.min_conformance_score, 0.95);
    }

    #[test]
    #[allow(dead_code)]
    fn test_conformance_trend_ordering() {
        assert!(RegressionSeverity::Critical > RegressionSeverity::High);
        assert!(RegressionSeverity::High > RegressionSeverity::Medium);
        assert!(RegressionSeverity::Medium > RegressionSeverity::Low);
    }

    #[test]
    #[allow(dead_code)]
    fn test_store_snapshot() {
        use tempfile::NamedTempFile;

        let detector = RegressionDetector::default();
        let mut matrix = CoverageMatrix::default();
        matrix.compliance_score = 0.95;

        let temp_file = NamedTempFile::new().unwrap();
        let result = detector.store_snapshot(&matrix, Some("abc123".to_string()), temp_file.path());

        assert!(result.is_ok());
        assert!(temp_file.path().exists());

        // Verify the content can be read back
        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        let snapshot: ConformanceSnapshot = serde_json::from_str(&content).unwrap();
        assert_eq!(snapshot.commit_hash, Some("abc123".to_string()));
        assert_eq!(snapshot.coverage_matrix.compliance_score, 0.95);
    }
}
