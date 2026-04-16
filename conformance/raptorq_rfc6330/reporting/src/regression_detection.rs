//! Conformance Regression Detection and Historical Tracking
//!
//! Implements historical compliance tracking, regression detection with
//! configurable thresholds, and trend analysis for long-term conformance
//! maintenance.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};

use crate::coverage_matrix::CoverageMatrix;

/// Historical conformance record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceRecord {
    pub timestamp: String,           // ISO timestamp
    pub commit_sha: String,          // Git commit hash
    pub branch: String,              // Git branch name
    pub compliance_score: f64,       // Overall compliance score
    pub must_coverage: f64,          // MUST clause coverage percentage
    pub should_coverage: f64,        // SHOULD clause coverage percentage
    pub total_tests: usize,          // Total test count
    pub passing_tests: usize,        // Passing test count
    pub conformance_level: String,   // FullyConformant, PartiallyConformant, NonConformant
    pub section_scores: BTreeMap<String, f64>, // Per-section scores
}

impl ConformanceRecord {
    /// Create conformance record from coverage matrix
    pub fn from_matrix(matrix: &CoverageMatrix, commit_sha: String, branch: String) -> Self {
        let section_scores = matrix.sections
            .iter()
            .map(|(k, v)| (k.clone(), v.score))
            .collect();

        Self {
            timestamp: matrix.generated_at.clone(),
            commit_sha,
            branch,
            compliance_score: matrix.compliance_score,
            must_coverage: matrix.overall.must_coverage_percent(),
            should_coverage: matrix.overall.should_coverage_percent(),
            total_tests: matrix.overall.total_tests,
            passing_tests: matrix.overall.passing_tests,
            conformance_level: format!("{:?}", matrix.conformance_level),
            section_scores,
        }
    }
}

/// Historical conformance database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceHistory {
    pub records: Vec<ConformanceRecord>,
    pub last_updated: String,
}

impl ConformanceHistory {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            last_updated: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Load history from JSON file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, std::io::Error> {
        let contents = fs::read_to_string(path)?;
        serde_json::from_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Save history to JSON file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), std::io::Error> {
        let contents = serde_json::to_string_pretty(self)?;
        fs::write(path, contents)
    }

    /// Add new conformance record
    pub fn add_record(&mut self, record: ConformanceRecord) {
        self.records.push(record);
        self.last_updated = chrono::Utc::now().to_rfc3339();

        // Keep only last 100 records to prevent unbounded growth
        if self.records.len() > 100 {
            self.records.drain(0..self.records.len() - 100);
        }
    }

    /// Get the most recent conformance record
    pub fn latest_record(&self) -> Option<&ConformanceRecord> {
        self.records.last()
    }

    /// Get conformance records for a specific branch
    pub fn records_for_branch(&self, branch: &str) -> Vec<&ConformanceRecord> {
        self.records
            .iter()
            .filter(|r| r.branch == branch)
            .collect()
    }

    /// Calculate conformance trend (positive = improving, negative = declining)
    pub fn compliance_trend(&self, branch: &str, window_size: usize) -> Option<f64> {
        let branch_records = self.records_for_branch(branch);
        if branch_records.len() < 2 {
            return None;
        }

        let recent_records: Vec<_> = branch_records
            .iter()
            .rev()
            .take(window_size.max(2))
            .collect();

        if recent_records.len() < 2 {
            return None;
        }

        let latest_score = recent_records[0].compliance_score;
        let baseline_score = recent_records[recent_records.len() - 1].compliance_score;

        Some(latest_score - baseline_score)
    }

    /// Get records within a time range
    pub fn records_since(&self, since: &str) -> Vec<&ConformanceRecord> {
        self.records
            .iter()
            .filter(|r| r.timestamp > since)
            .collect()
    }
}

/// Regression detection configuration
#[derive(Debug, Clone)]
pub struct RegressionConfig {
    pub compliance_threshold: f64,    // Minimum acceptable compliance score
    pub must_threshold: f64,          // Minimum acceptable MUST coverage
    pub should_threshold: f64,        // Minimum acceptable SHOULD coverage
    pub max_score_drop: f64,          // Maximum allowable score drop
    pub baseline_branch: String,      // Branch to compare against (e.g., "main")
    pub window_size: usize,           // Number of commits for trend analysis
}

impl Default for RegressionConfig {
    fn default() -> Self {
        Self {
            compliance_threshold: 90.0,   // 90% minimum compliance
            must_threshold: 95.0,         // 95% minimum MUST coverage
            should_threshold: 85.0,       // 85% minimum SHOULD coverage
            max_score_drop: 5.0,          // 5% maximum drop allowed
            baseline_branch: "main".to_string(),
            window_size: 10,              // Last 10 commits
        }
    }
}

/// Regression detection result
#[derive(Debug, Clone, PartialEq)]
pub enum RegressionResult {
    Pass,
    Warning(String),
    Fail(String),
}

impl RegressionResult {
    pub fn is_failure(&self) -> bool {
        matches!(self, RegressionResult::Fail(_))
    }

    pub fn is_warning(&self) -> bool {
        matches!(self, RegressionResult::Warning(_))
    }

    pub fn message(&self) -> Option<&str> {
        match self {
            RegressionResult::Pass => None,
            RegressionResult::Warning(msg) | RegressionResult::Fail(msg) => Some(msg),
        }
    }
}

/// Conformance regression detector
pub struct RegressionDetector {
    config: RegressionConfig,
    history: ConformanceHistory,
}

impl RegressionDetector {
    pub fn new(config: RegressionConfig, history: ConformanceHistory) -> Self {
        Self { config, history }
    }

    /// Load detector from history file with default config
    pub fn load_from_file<P: AsRef<Path>>(history_path: P) -> Result<Self, std::io::Error> {
        let history = ConformanceHistory::load_from_file(history_path)
            .unwrap_or_else(|_| ConformanceHistory::new());
        Ok(Self::new(RegressionConfig::default(), history))
    }

    /// Check for conformance regressions
    pub fn check_regression(&self, current: &CoverageMatrix, commit_sha: String, branch: String) -> RegressionResult {
        // Check absolute thresholds
        if let Some(failure) = self.check_absolute_thresholds(current) {
            return failure;
        }

        // Check for regressions against baseline
        if let Some(regression) = self.check_baseline_regression(current, &branch) {
            return regression;
        }

        // Check trend analysis
        if let Some(trend_issue) = self.check_trend_regression(&branch) {
            return trend_issue;
        }

        RegressionResult::Pass
    }

    /// Check absolute conformance thresholds
    fn check_absolute_thresholds(&self, matrix: &CoverageMatrix) -> Option<RegressionResult> {
        let must_coverage = matrix.overall.must_coverage_percent();
        let should_coverage = matrix.overall.should_coverage_percent();
        let compliance_score = matrix.compliance_score;

        if must_coverage < self.config.must_threshold {
            return Some(RegressionResult::Fail(format!(
                "MUST coverage {:.1}% below threshold {:.1}%",
                must_coverage, self.config.must_threshold
            )));
        }

        if should_coverage < self.config.should_threshold {
            return Some(RegressionResult::Warning(format!(
                "SHOULD coverage {:.1}% below threshold {:.1}%",
                should_coverage, self.config.should_threshold
            )));
        }

        if compliance_score < self.config.compliance_threshold {
            return Some(RegressionResult::Fail(format!(
                "Compliance score {:.1}% below threshold {:.1}%",
                compliance_score, self.config.compliance_threshold
            )));
        }

        None
    }

    /// Check for regression against baseline branch
    fn check_baseline_regression(&self, current: &CoverageMatrix, branch: &str) -> Option<RegressionResult> {
        if branch == self.config.baseline_branch {
            return None; // Don't compare baseline against itself
        }

        let baseline_records = self.history.records_for_branch(&self.config.baseline_branch);
        if let Some(baseline) = baseline_records.last() {
            let score_drop = baseline.compliance_score - current.compliance_score;

            if score_drop > self.config.max_score_drop {
                return Some(RegressionResult::Fail(format!(
                    "Compliance score dropped {:.1}% from baseline (was {:.1}%, now {:.1}%)",
                    score_drop, baseline.compliance_score, current.compliance_score
                )));
            }

            // Check for significant section regressions
            for (section, current_section) in &current.sections {
                if let Some(baseline_score) = baseline.section_scores.get(section) {
                    let section_drop = baseline_score - current_section.score;
                    if section_drop > self.config.max_score_drop {
                        return Some(RegressionResult::Warning(format!(
                            "Section {} score dropped {:.1}% from baseline",
                            section, section_drop
                        )));
                    }
                }
            }
        }

        None
    }

    /// Check trend-based regression detection
    fn check_trend_regression(&self, branch: &str) -> Option<RegressionResult> {
        if let Some(trend) = self.history.compliance_trend(branch, self.config.window_size) {
            if trend < -self.config.max_score_drop {
                return Some(RegressionResult::Warning(format!(
                    "Negative compliance trend detected: {:.1}% drop over {} commits",
                    -trend, self.config.window_size
                )));
            }
        }

        None
    }

    /// Update history with new conformance record
    pub fn update_history(&mut self, matrix: &CoverageMatrix, commit_sha: String, branch: String) {
        let record = ConformanceRecord::from_matrix(matrix, commit_sha, branch);
        self.history.add_record(record);
    }

    /// Save updated history to file
    pub fn save_history<P: AsRef<Path>>(&self, path: P) -> Result<(), std::io::Error> {
        self.history.save_to_file(path)
    }

    /// Generate regression analysis report
    pub fn generate_analysis_report(&self, branch: &str) -> String {
        let mut report = String::new();

        report.push_str("# Conformance Regression Analysis\n\n");

        let branch_records = self.history.records_for_branch(branch);
        if branch_records.is_empty() {
            report.push_str("No historical data available for regression analysis.\n");
            return report;
        }

        // Recent history
        report.push_str("## Recent History\n\n");
        report.push_str("| Commit | Compliance | MUST | SHOULD | Tests | Status |\n");
        report.push_str("|---------|------------|------|--------|-------|--------|\n");

        for record in branch_records.iter().rev().take(10) {
            let short_sha = if record.commit_sha.len() > 7 {
                &record.commit_sha[0..7]
            } else {
                &record.commit_sha
            };

            report.push_str(&format!(
                "| {} | {:.1}% | {:.1}% | {:.1}% | {}/{} | {} |\n",
                short_sha,
                record.compliance_score,
                record.must_coverage,
                record.should_coverage,
                record.passing_tests,
                record.total_tests,
                record.conformance_level
            ));
        }
        report.push_str("\n");

        // Trend analysis
        if let Some(trend) = self.history.compliance_trend(branch, self.config.window_size) {
            report.push_str("## Trend Analysis\n\n");
            if trend > 0.0 {
                report.push_str(&format!("✅ **Improving trend**: +{:.1}% over last {} commits\n\n", trend, self.config.window_size));
            } else if trend < -1.0 {
                report.push_str(&format!("⚠️ **Declining trend**: {:.1}% over last {} commits\n\n", trend, self.config.window_size));
            } else {
                report.push_str(&format!("➡️ **Stable trend**: {:.1}% over last {} commits\n\n", trend, self.config.window_size));
            }
        }

        // Thresholds
        report.push_str("## Configured Thresholds\n\n");
        report.push_str(&format!("- **Compliance Score**: ≥{:.1}%\n", self.config.compliance_threshold));
        report.push_str(&format!("- **MUST Coverage**: ≥{:.1}%\n", self.config.must_threshold));
        report.push_str(&format!("- **SHOULD Coverage**: ≥{:.1}%\n", self.config.should_threshold));
        report.push_str(&format!("- **Maximum Score Drop**: {:.1}%\n", self.config.max_score_drop));
        report.push_str(&format!("- **Baseline Branch**: {}\n", self.config.baseline_branch));

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage_matrix::{CoverageMatrix, OverallCoverage, ConformanceLevel};

    fn create_test_matrix(compliance_score: f64) -> CoverageMatrix {
        let mut matrix = CoverageMatrix::new("test-version".to_string());
        matrix.compliance_score = compliance_score;
        matrix.overall.must_total = 100;
        matrix.overall.must_passing = (compliance_score * 100.0 / 100.0) as usize;
        matrix.overall.should_total = 50;
        matrix.overall.should_passing = (compliance_score * 50.0 / 100.0) as usize;
        matrix
    }

    #[test]
    fn test_conformance_record_creation() {
        let matrix = create_test_matrix(95.0);
        let record = ConformanceRecord::from_matrix(&matrix, "abc123".to_string(), "main".to_string());

        assert_eq!(record.commit_sha, "abc123");
        assert_eq!(record.branch, "main");
        assert_eq!(record.compliance_score, 95.0);
    }

    #[test]
    fn test_history_management() {
        let mut history = ConformanceHistory::new();
        let record = ConformanceRecord::from_matrix(
            &create_test_matrix(90.0),
            "abc123".to_string(),
            "main".to_string()
        );

        history.add_record(record);
        assert_eq!(history.records.len(), 1);
        assert!(history.latest_record().is_some());
    }

    #[test]
    fn test_regression_detection() {
        let config = RegressionConfig {
            compliance_threshold: 90.0,
            must_threshold: 95.0,
            max_score_drop: 5.0,
            ..Default::default()
        };

        let detector = RegressionDetector::new(config, ConformanceHistory::new());

        // Test passing case
        let good_matrix = create_test_matrix(95.0);
        let result = detector.check_regression(&good_matrix, "abc123".to_string(), "feature".to_string());
        assert_eq!(result, RegressionResult::Pass);

        // Test failing case
        let bad_matrix = create_test_matrix(80.0);
        let result = detector.check_regression(&bad_matrix, "def456".to_string(), "feature".to_string());
        assert!(result.is_failure());
    }

    #[test]
    fn test_trend_analysis() {
        let mut history = ConformanceHistory::new();

        // Add declining trend
        for i in (85..95).rev() {
            let record = ConformanceRecord::from_matrix(
                &create_test_matrix(i as f64),
                format!("commit{}", i),
                "main".to_string()
            );
            history.add_record(record);
        }

        let trend = history.compliance_trend("main", 5);
        assert!(trend.is_some());
        assert!(trend.unwrap() < 0.0); // Declining trend
    }
}