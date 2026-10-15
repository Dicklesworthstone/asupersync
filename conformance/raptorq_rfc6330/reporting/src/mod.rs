//! RFC 6330 RaptorQ Conformance Reporting and Maintenance Pipeline
//!
//! This module implements the MATRIX and MAINTAIN phases of the conformance loop,
//! providing automated compliance reporting, coverage tracking, CI integration,
//! and fixture maintenance workflows for long-term conformance validation.

pub mod compliance_report;
pub mod coverage_matrix;
pub mod maintenance_workflows;
pub mod regression_detection;

// Re-export main types for convenience
pub use compliance_report::{
    ComplianceReportGenerator, OutputFormat, ReportConfig, generate_ci_summary,
};
pub use coverage_matrix::{ConformanceLevel, CoverageMatrix, OverallCoverage, SectionCoverage};
pub use maintenance_workflows::{
    MaintenanceAction, MaintenanceConfig, MaintenanceManager, MaintenanceResult, ReferenceVersion,
};
pub use regression_detection::{
    ConformanceHistory, RegressionConfig, RegressionDetector, RegressionResult,
};

// Import conformance types from main module
use crate::raptorq_rfc6330::TestExecution;

/// Main reporting pipeline that integrates all reporting and maintenance components
pub struct ReportingPipeline {
    report_generator: ComplianceReportGenerator,
    regression_detector: RegressionDetector,
    maintenance_manager: Option<MaintenanceManager>,
}

impl ReportingPipeline {
    /// Create new reporting pipeline with default configuration
    pub fn with_default_config() -> Self {
        let report_config = ReportConfig::default();
        let regression_config = RegressionConfig::default();
        let history = ConformanceHistory::new();

        Self {
            report_generator: ComplianceReportGenerator::new(report_config),
            regression_detector: RegressionDetector::new(regression_config, history),
            maintenance_manager: None,
        }
    }

    /// Create reporting pipeline with custom configuration
    pub fn new(
        report_config: ReportConfig,
        regression_config: RegressionConfig,
        history: ConformanceHistory,
    ) -> Self {
        Self {
            report_generator: ComplianceReportGenerator::new(report_config),
            regression_detector: RegressionDetector::new(regression_config, history),
            maintenance_manager: None,
        }
    }

    /// Enable fixture maintenance with configuration
    pub fn with_maintenance(
        mut self,
        maintenance_config: MaintenanceConfig,
        fixture_base_path: std::path::PathBuf,
    ) -> Self {
        self.maintenance_manager = Some(MaintenanceManager::new(
            maintenance_config,
            fixture_base_path,
        ));
        self
    }

    /// Generate complete compliance report from test executions
    pub fn generate_report(
        &self,
        executions: &[TestExecution],
        implementation_version: String,
    ) -> String {
        let matrix = CoverageMatrix::from_test_results(executions, implementation_version);
        self.report_generator.generate_report(&matrix)
    }

    /// Check for conformance regressions
    pub fn check_regression(
        &mut self,
        executions: &[TestExecution],
        implementation_version: String,
        commit_sha: String,
        branch: String,
    ) -> RegressionResult {
        let matrix = CoverageMatrix::from_test_results(executions, implementation_version);

        let result =
            self.regression_detector
                .check_regression(&matrix, commit_sha.clone(), branch.clone());

        // Update history for future regression detection
        self.regression_detector
            .update_history(&matrix, commit_sha, branch);

        result
    }

    /// Generate CI summary data for automated processing
    pub fn generate_ci_summary(
        &self,
        executions: &[TestExecution],
        implementation_version: String,
    ) -> serde_json::Value {
        let matrix = CoverageMatrix::from_test_results(executions, implementation_version);
        serde_json::Value::Object(generate_ci_summary(&matrix).into_iter().collect())
    }

    /// Execute maintenance workflows
    pub fn run_maintenance(&mut self, dry_run: bool) -> Vec<MaintenanceResult> {
        if let Some(ref mut manager) = self.maintenance_manager {
            let actions = manager.check_for_updates();
            actions
                .into_iter()
                .filter_map(|action| manager.execute_action(action, dry_run).ok())
                .collect()
        } else {
            vec![]
        }
    }

    /// Save regression history to file
    pub fn save_history<P: AsRef<std::path::Path>>(&self, path: P) -> Result<(), std::io::Error> {
        self.regression_detector.save_history(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raptorq_rfc6330::{
        ConformanceResult, EvidenceKind, EvidenceMetadata, RequirementLevel, TestCategory,
        TestStatus,
    };

    fn passing_execution(
        rfc_clause: &str,
        section: &str,
        level: RequirementLevel,
    ) -> TestExecution {
        TestExecution {
            test_name: rfc_clause.to_string(),
            rfc_clause: rfc_clause.to_string(),
            section: section.to_string(),
            level,
            category: TestCategory::Unit,
            description: format!("{rfc_clause} pipeline fixture"),
            result: ConformanceResult::Pass,
            evidence: EvidenceMetadata {
                evidence_kind: EvidenceKind::LiveChecked,
                test_status: TestStatus::Pass,
                blocker_id: None,
                fixture_reference: None,
                production_seam_path: Some("conformance/raptorq_rfc6330/reporting".to_string()),
            },
            duration: std::time::Duration::from_millis(100),
            timestamp: std::time::SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn test_pipeline_integration() {
        let pipeline = ReportingPipeline::with_default_config();

        let executions = vec![passing_execution(
            "RFC6330-4.1.1",
            "4.1",
            RequirementLevel::Must,
        )];

        let report = pipeline.generate_report(&executions, "test-v1.0.0".to_string());
        assert!(report.contains("RFC 6330 RaptorQ Conformance Report"));
        assert!(report.contains("✅ Fully Conformant"));

        let ci_summary = pipeline.generate_ci_summary(&executions, "test-v1.0.0".to_string());
        assert!(ci_summary["conformance_level"].is_string());
        assert!(ci_summary["compliance_score"].is_number());
    }

    #[test]
    fn test_regression_detection_integration() {
        let mut pipeline = ReportingPipeline::with_default_config();

        let executions = vec![passing_execution(
            "RFC6330-4.1.1",
            "4.1",
            RequirementLevel::Must,
        )];

        let result = pipeline.check_regression(
            &executions,
            "test-v1.0.0".to_string(),
            "abc123".to_string(),
            "main".to_string(),
        );

        assert_eq!(result, RegressionResult::Pass);
    }
}
