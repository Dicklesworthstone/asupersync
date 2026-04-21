//! RaptorQ RFC 6330 Conformance Reporting and Maintenance Pipeline
//!
//! This crate provides a comprehensive framework for generating conformance reports
//! and maintaining RaptorQ test infrastructure. It brings together coverage analysis,
//! compliance reporting, regression detection, and automated maintenance workflows
//! into a production-ready system.
//!
//! # Overview
//!
//! The reporting pipeline consists of several integrated components:
//!
//! - **Coverage Matrix**: Calculates conformance coverage across RFC 6330 sections
//! - **Compliance Reports**: Generates multi-format reports (Markdown, HTML, JSON, SVG)
//! - **Regression Detection**: Detects regressions by comparing against historical baselines
//! - **Maintenance Workflows**: Automated cleanup and maintenance of test fixtures
//!
//! # Usage
//!
//! ```rust,no_run
//! use raptorq_conformance_reporting::*;
//!
//! // Calculate coverage matrix
//! let calculator = coverage_matrix::CoverageMatrixCalculator::new();
//! let matrix = calculator.calculate_coverage("tests/golden").unwrap();
//!
//! // Generate compliance report
//! let generator = compliance_report::ComplianceReportGenerator::new();
//! let report = generator.generate_report(
//!     &matrix,
//!     None,
//!     compliance_report::ReportFormat::Markdown
//! ).unwrap();
//!
//! // Check for regressions
//! let detector = regression_detection::RegressionDetector::default();
//! let analysis = detector.detect_regressions(&matrix, "tests/golden").unwrap();
//!
//! // Run maintenance workflow
//! let workflow = maintenance_workflows::MaintenanceWorkflow::default();
//! let result = workflow.execute_maintenance(
//!     "tests/golden",
//!     "tests/fixtures",
//!     "output"
//! ).unwrap();
//! ```
//!
//! # CLI Tools
//!
//! Three CLI tools are provided for different aspects of the workflow:
//!
//! - `generate_compliance_report`: Generate conformance reports in multiple formats
//! - `check_conformance_regression`: Detect regressions against historical baselines
//! - `maintain_fixtures`: Automated maintenance of test fixtures and golden files
//!
//! # Environment Variables
//!
//! - `RFC6330_BASELINE_DIR`: Default directory for historical regression baselines
//! - `RFC6330_REPORT_TEMPLATE_DIR`: Custom template directory for report generation

pub mod compliance_report;
pub mod coverage_matrix;
pub mod maintenance_workflows;
pub mod regression_detection;

// Re-export main types for convenience
pub use coverage_matrix::{
    ConformanceLevel, CoverageMatrix, CoverageMatrixCalculator, SectionCoverage,
};

pub use compliance_report::{ComplianceReportGenerator, ReportConfig, ReportFormat};

pub use regression_detection::{
    ConformanceSnapshot, ConformanceTrend, RegressionAnalysis, RegressionConfig,
    RegressionDetector, RegressionFinding, RegressionSeverity, RegressionType,
};

pub use maintenance_workflows::{
    FileHealthStatus, MaintenanceAction, MaintenanceActionType, MaintenanceConfig,
    MaintenanceResult, MaintenanceWorkflow,
};

/// Main entry point for running the complete conformance reporting pipeline
#[allow(dead_code)]
pub fn run_complete_reporting_pipeline<P: AsRef<std::path::Path>>(
    golden_dir: P,
    fixture_dir: P,
    output_dir: P,
    baseline_dir: Option<P>,
) -> Result<ReportingPipelineResults, ReportingPipelineError> {
    let golden_path = golden_dir.as_ref();
    let fixture_path = fixture_dir.as_ref();
    let output_path = output_dir.as_ref();

    // Ensure directories exist
    std::fs::create_dir_all(output_path)?;

    // Step 1: Calculate coverage matrix
    let calculator = CoverageMatrixCalculator::new();
    let coverage_matrix = calculator
        .calculate_coverage(golden_path)
        .map_err(ReportingPipelineError::CoverageCalculation)?;

    // Step 2: Generate compliance reports
    let report_generator = ComplianceReportGenerator::new();
    let markdown_report = report_generator
        .generate_report(&coverage_matrix, None, ReportFormat::Markdown)
        .map_err(ReportingPipelineError::ReportGeneration)?;

    let json_report = report_generator
        .generate_report(&coverage_matrix, None, ReportFormat::Json)
        .map_err(ReportingPipelineError::ReportGeneration)?;

    // Step 3: Regression detection (if baseline available)
    let regression_analysis = if let Some(baseline_path) = baseline_dir {
        let mut regression_config = RegressionConfig::default();
        regression_config.historical_data_paths = vec![baseline_path.as_ref().to_path_buf()];

        let detector = RegressionDetector::new(regression_config);
        Some(
            detector
                .detect_regressions(&coverage_matrix, golden_path)
                .map_err(ReportingPipelineError::RegressionDetection)?,
        )
    } else {
        None
    };

    // Step 4: Maintenance workflow
    let workflow = MaintenanceWorkflow::default();
    let maintenance_result = workflow
        .execute_maintenance(golden_path, fixture_path, output_path)
        .map_err(ReportingPipelineError::Maintenance)?;

    // Write reports to output directory
    std::fs::write(output_path.join("compliance_report.md"), markdown_report)?;
    std::fs::write(output_path.join("compliance_report.json"), json_report)?;

    Ok(ReportingPipelineResults {
        coverage_matrix,
        regression_analysis,
        maintenance_result,
        output_directory: output_path.to_path_buf(),
    })
}

/// Results from running the complete reporting pipeline
#[derive(Debug)]
#[allow(dead_code)]
pub struct ReportingPipelineResults {
    pub coverage_matrix: CoverageMatrix,
    pub regression_analysis: Option<RegressionAnalysis>,
    pub maintenance_result: MaintenanceResult,
    pub output_directory: std::path::PathBuf,
}

#[allow(dead_code)]

impl ReportingPipelineResults {
    /// Returns true if the pipeline completed successfully with no critical issues
    #[allow(dead_code)]
    pub fn is_success(&self) -> bool {
        let coverage_ok = self.coverage_matrix.compliance_score >= 0.95;
        let regression_ok = self
            .regression_analysis
            .as_ref()
            .map(|r| !r.has_regressions)
            .unwrap_or(true);
        let maintenance_ok = self.maintenance_result.errors.is_empty();

        coverage_ok && regression_ok && maintenance_ok
    }

    /// Returns a summary report of the pipeline execution
    #[allow(dead_code)]
    pub fn summary_report(&self) -> String {
        format!(
            "RaptorQ Conformance Reporting Pipeline Results\n\
            =============================================\n\
            \n\
            Coverage Analysis: {}\n\
            - Overall Score: {:.1}%\n\
            - Total Tests: {}\n\
            - Passed Tests: {}\n\
            - Failed Tests: {}\n\
            \n\
            Regression Analysis: {}\n\
            - Has Regressions: {}\n\
            - Total Findings: {}\n\
            \n\
            Maintenance: {}\n\
            - Actions Performed: {}\n\
            - Files Cleaned: {}\n\
            - Errors: {}\n\
            \n\
            Overall Status: {}\n\
            Output Directory: {}\n",
            "✅ COMPLETED",
            self.coverage_matrix.compliance_score * 100.0,
            self.coverage_matrix.overall.total_tests,
            self.coverage_matrix.overall.passing_tests,
            self.coverage_matrix.overall.total_tests - self.coverage_matrix.overall.passing_tests,
            if self.regression_analysis.is_some() {
                "✅ COMPLETED"
            } else {
                "⏭️ SKIPPED"
            },
            self.regression_analysis
                .as_ref()
                .map(|r| r.has_regressions)
                .unwrap_or(false),
            self.regression_analysis
                .as_ref()
                .map(|r| r.regressions.len())
                .unwrap_or(0),
            "✅ COMPLETED",
            self.maintenance_result.actions_performed.len(),
            self.maintenance_result.cleaned_files.len(),
            self.maintenance_result.errors.len(),
            if self.is_success() {
                "✅ SUCCESS"
            } else {
                "❌ ISSUES DETECTED"
            },
            self.output_directory.display()
        )
    }
}

/// Errors that can occur during pipeline execution
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum ReportingPipelineError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Coverage calculation failed: {0}")]
    CoverageCalculation(anyhow::Error),

    #[error("Report generation failed: {0}")]
    ReportGeneration(anyhow::Error),

    #[error("Regression detection failed: {0}")]
    RegressionDetection(anyhow::Error),

    #[error("Maintenance workflow failed: {0}")]
    Maintenance(anyhow::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    #[allow(dead_code)]
    fn test_pipeline_results_success_determination() {
        let mut coverage_matrix = CoverageMatrix::default();
        coverage_matrix.compliance_score = 0.98;

        let maintenance_result = MaintenanceResult {
            timestamp: chrono::Utc::now(),
            actions_performed: vec![],
            cleaned_files: vec![],
            updated_files: vec![],
            errors: vec![],
            statistics: maintenance_workflows::MaintenanceStatistics {
                files_processed: 0,
                files_cleaned: 0,
                files_updated: 0,
                space_reclaimed: 0,
                duration_seconds: 0.0,
                file_types: std::collections::HashMap::new(),
            },
        };

        let results = ReportingPipelineResults {
            coverage_matrix,
            regression_analysis: None,
            maintenance_result,
            output_directory: std::path::PathBuf::from("/tmp"),
        };

        assert!(results.is_success());
    }

    #[test]
    #[allow(dead_code)]
    fn test_pipeline_results_summary_report() {
        let mut coverage_matrix = CoverageMatrix::default();
        coverage_matrix.compliance_score = 0.95;
        coverage_matrix.overall.total_tests = 100;
        coverage_matrix.overall.passing_tests = 95;

        let maintenance_result = MaintenanceResult {
            timestamp: chrono::Utc::now(),
            actions_performed: vec![],
            cleaned_files: vec![],
            updated_files: vec![],
            errors: vec![],
            statistics: maintenance_workflows::MaintenanceStatistics {
                files_processed: 0,
                files_cleaned: 0,
                files_updated: 0,
                space_reclaimed: 0,
                duration_seconds: 0.0,
                file_types: std::collections::HashMap::new(),
            },
        };

        let results = ReportingPipelineResults {
            coverage_matrix,
            regression_analysis: None,
            maintenance_result,
            output_directory: std::path::PathBuf::from("/tmp"),
        };

        let summary = results.summary_report();
        assert!(summary.contains("95.0%"));
        assert!(summary.contains("100"));
        assert!(summary.contains("SUCCESS"));
    }

    #[test]
    #[allow(dead_code)]
    fn test_complete_pipeline_api() {
        let temp_dir = TempDir::new().unwrap();
        let golden_path = temp_dir.path().join("golden");
        let fixture_path = temp_dir.path().join("fixtures");
        let output_path = temp_dir.path().join("output");

        // Create directories
        std::fs::create_dir_all(&golden_path).unwrap();
        std::fs::create_dir_all(&fixture_path).unwrap();

        // This would fail with real implementation since we don't have actual test data
        // but validates the API design
        let result = run_complete_reporting_pipeline(
            &golden_path,
            &fixture_path,
            &output_path,
            None::<&std::path::Path>,
        );

        // Should fail gracefully due to missing test data
        assert!(result.is_err());
    }
}
