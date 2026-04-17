//! Maintenance Workflows Module
//!
//! This module provides automated maintenance workflows for RaptorQ conformance testing,
//! including fixture cleanup, golden file maintenance, and automated reporting.

use crate::compliance_report::ComplianceReportGenerator;
use crate::coverage_matrix::CoverageMatrixCalculator;
use crate::regression_detection::RegressionDetector;
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Configuration for maintenance workflows
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceConfig {
    /// Maximum age for golden files before they're considered stale (in days)
    pub max_golden_age_days: i64,
    /// Maximum age for fixture files before cleanup (in days)
    pub max_fixture_age_days: i64,
    /// Maximum number of historical snapshots to keep
    pub max_snapshots_to_keep: usize,
    /// Paths to monitor for maintenance
    pub monitored_paths: Vec<PathBuf>,
    /// Whether to perform aggressive cleanup
    pub aggressive_cleanup: bool,
    /// Size threshold for large files (in bytes)
    pub large_file_threshold: u64,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            max_golden_age_days: 30,
            max_fixture_age_days: 7,
            max_snapshots_to_keep: 50,
            monitored_paths: vec![],
            aggressive_cleanup: false,
            large_file_threshold: 10 * 1024 * 1024, // 10MB
        }
    }
}

/// Result of maintenance workflow execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceResult {
    /// Timestamp when maintenance was performed
    pub timestamp: DateTime<Utc>,
    /// Summary of actions performed
    pub actions_performed: Vec<MaintenanceAction>,
    /// Files that were cleaned up
    pub cleaned_files: Vec<PathBuf>,
    /// Files that were updated
    pub updated_files: Vec<PathBuf>,
    /// Any errors encountered during maintenance
    pub errors: Vec<String>,
    /// Statistics about the maintenance operation
    pub statistics: MaintenanceStatistics,
}

/// Individual maintenance action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceAction {
    /// Type of action performed
    pub action_type: MaintenanceActionType,
    /// Description of the action
    pub description: String,
    /// Files affected by this action
    pub affected_files: Vec<PathBuf>,
    /// Whether the action was successful
    pub successful: bool,
    /// Any error message if action failed
    pub error_message: Option<String>,
}

/// Types of maintenance actions
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MaintenanceActionType {
    /// Cleanup old golden files
    CleanupGoldenFiles,
    /// Cleanup old fixture files
    CleanupFixtures,
    /// Update stale golden files
    UpdateGoldenFiles,
    /// Cleanup historical snapshots
    CleanupSnapshots,
    /// Compress large files
    CompressFiles,
    /// Validate file integrity
    ValidateFiles,
    /// Generate maintenance report
    GenerateReport,
}

/// Statistics about maintenance operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceStatistics {
    /// Total files processed
    pub files_processed: usize,
    /// Total files cleaned up
    pub files_cleaned: usize,
    /// Total files updated
    pub files_updated: usize,
    /// Total space reclaimed (in bytes)
    pub space_reclaimed: u64,
    /// Duration of maintenance operation
    pub duration_seconds: f64,
    /// File type breakdown
    pub file_types: HashMap<String, usize>,
}

/// File health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHealthStatus {
    /// Path to the file
    pub path: PathBuf,
    /// File size in bytes
    pub size_bytes: u64,
    /// Last modified timestamp
    pub last_modified: DateTime<Utc>,
    /// Age of the file in days
    pub age_days: i64,
    /// Whether the file is considered stale
    pub is_stale: bool,
    /// Whether the file is considered large
    pub is_large: bool,
    /// File health score (0.0 to 1.0)
    pub health_score: f64,
    /// Recommended actions
    pub recommended_actions: Vec<MaintenanceActionType>,
}

/// Main maintenance workflow engine
pub struct MaintenanceWorkflow {
    config: MaintenanceConfig,
    calculator: CoverageMatrixCalculator,
    report_generator: ComplianceReportGenerator,
    regression_detector: RegressionDetector,
}

impl MaintenanceWorkflow {
    /// Create a new maintenance workflow with the given configuration
    pub fn new(config: MaintenanceConfig) -> Self {
        Self {
            config,
            calculator: CoverageMatrixCalculator::new(),
            report_generator: ComplianceReportGenerator::new(),
            regression_detector: RegressionDetector::default(),
        }
    }

    /// Create a maintenance workflow with default configuration
    pub fn default() -> Self {
        Self::new(MaintenanceConfig::default())
    }

    /// Execute the complete maintenance workflow
    pub fn execute_maintenance(
        &self,
        golden_dir: &Path,
        fixture_dir: &Path,
        output_dir: &Path,
    ) -> Result<MaintenanceResult> {
        let start_time = std::time::Instant::now();
        let mut actions = Vec::new();
        let mut cleaned_files = Vec::new();
        let mut updated_files = Vec::new();
        let mut errors = Vec::new();

        // Ensure output directory exists
        std::fs::create_dir_all(output_dir).with_context(|| {
            format!("Failed to create output directory {}", output_dir.display())
        })?;

        // 1. Cleanup stale golden files
        match self.cleanup_golden_files(golden_dir) {
            Ok((action, files)) => {
                actions.push(action);
                cleaned_files.extend(files);
            }
            Err(e) => errors.push(format!("Golden file cleanup failed: {}", e)),
        }

        // 2. Cleanup stale fixtures
        match self.cleanup_fixture_files(fixture_dir) {
            Ok((action, files)) => {
                actions.push(action);
                cleaned_files.extend(files);
            }
            Err(e) => errors.push(format!("Fixture cleanup failed: {}", e)),
        }

        // 3. Update outdated golden files
        match self.update_golden_files(golden_dir) {
            Ok((action, files)) => {
                actions.push(action);
                updated_files.extend(files);
            }
            Err(e) => errors.push(format!("Golden file update failed: {}", e)),
        }

        // 4. Cleanup historical snapshots
        match self.cleanup_historical_snapshots(output_dir) {
            Ok((action, files)) => {
                actions.push(action);
                cleaned_files.extend(files);
            }
            Err(e) => errors.push(format!("Snapshot cleanup failed: {}", e)),
        }

        // 5. Validate file integrity
        match self.validate_file_integrity(golden_dir) {
            Ok(action) => actions.push(action),
            Err(e) => errors.push(format!("File validation failed: {}", e)),
        }

        // 6. Generate maintenance report
        match self.generate_maintenance_report(output_dir, &actions) {
            Ok(action) => actions.push(action),
            Err(e) => errors.push(format!("Report generation failed: {}", e)),
        }

        let duration = start_time.elapsed();
        let statistics =
            self.calculate_statistics(&actions, &cleaned_files, &updated_files, duration);

        Ok(MaintenanceResult {
            timestamp: Utc::now(),
            actions_performed: actions,
            cleaned_files,
            updated_files,
            errors,
            statistics,
        })
    }

    /// Analyze file health across the conformance test directories
    pub fn analyze_file_health(
        &self,
        golden_dir: &Path,
        fixture_dir: &Path,
    ) -> Result<Vec<FileHealthStatus>> {
        let mut health_statuses = Vec::new();
        let now = Utc::now();

        // Analyze golden files
        if golden_dir.exists() {
            for entry in WalkDir::new(golden_dir) {
                let entry = entry.context("Failed to read directory entry")?;
                if entry.file_type().is_file() {
                    let path = entry.path().to_path_buf();
                    let metadata = entry.metadata().context("Failed to read file metadata")?;

                    let modified_time = metadata
                        .modified()
                        .context("Failed to get modification time")?
                        .into();
                    let age_days = (now - modified_time).num_days();

                    let status = self.assess_file_health(&path, metadata.len(), age_days)?;
                    health_statuses.push(status);
                }
            }
        }

        // Analyze fixture files
        if fixture_dir.exists() {
            for entry in WalkDir::new(fixture_dir) {
                let entry = entry.context("Failed to read directory entry")?;
                if entry.file_type().is_file() {
                    let path = entry.path().to_path_buf();
                    let metadata = entry.metadata().context("Failed to read file metadata")?;

                    let modified_time = metadata
                        .modified()
                        .context("Failed to get modification time")?
                        .into();
                    let age_days = (now - modified_time).num_days();

                    let status = self.assess_file_health(&path, metadata.len(), age_days)?;
                    health_statuses.push(status);
                }
            }
        }

        Ok(health_statuses)
    }

    /// Generate automated maintenance recommendations
    pub fn generate_recommendations(&self, health_statuses: &[FileHealthStatus]) -> Vec<String> {
        let mut recommendations = Vec::new();

        let stale_files: Vec<_> = health_statuses
            .iter()
            .filter(|status| status.is_stale)
            .collect();

        let large_files: Vec<_> = health_statuses
            .iter()
            .filter(|status| status.is_large)
            .collect();

        let unhealthy_files: Vec<_> = health_statuses
            .iter()
            .filter(|status| status.health_score < 0.5)
            .collect();

        if !stale_files.is_empty() {
            recommendations.push(format!(
                "Clean up {} stale files older than {} days",
                stale_files.len(),
                self.config.max_golden_age_days
            ));
        }

        if !large_files.is_empty() {
            recommendations.push(format!(
                "Consider compressing {} large files (>{} bytes)",
                large_files.len(),
                self.config.large_file_threshold
            ));
        }

        if !unhealthy_files.is_empty() {
            recommendations.push(format!(
                "Review {} files with low health scores",
                unhealthy_files.len()
            ));
        }

        if health_statuses.len() > self.config.max_snapshots_to_keep * 2 {
            recommendations.push(
                "Consider reducing the number of files in the conformance test directories"
                    .to_string(),
            );
        }

        if recommendations.is_empty() {
            recommendations.push("No maintenance actions recommended at this time".to_string());
        }

        recommendations
    }

    /// Cleanup stale golden files
    fn cleanup_golden_files(&self, golden_dir: &Path) -> Result<(MaintenanceAction, Vec<PathBuf>)> {
        let mut cleaned_files = Vec::new();
        let cutoff_date = Utc::now() - Duration::days(self.config.max_golden_age_days);

        if !golden_dir.exists() {
            return Ok((
                MaintenanceAction {
                    action_type: MaintenanceActionType::CleanupGoldenFiles,
                    description: "Golden directory does not exist".to_string(),
                    affected_files: vec![],
                    successful: true,
                    error_message: None,
                },
                cleaned_files,
            ));
        }

        for entry in WalkDir::new(golden_dir) {
            let entry = entry.context("Failed to read directory entry")?;
            if entry.file_type().is_file() {
                let path = entry.path();
                let metadata = entry.metadata().context("Failed to read file metadata")?;
                let modified_time: DateTime<Utc> = metadata
                    .modified()
                    .context("Failed to get modification time")?
                    .into();

                if modified_time < cutoff_date {
                    if self.config.aggressive_cleanup {
                        std::fs::remove_file(path)
                            .with_context(|| format!("Failed to remove file {}", path.display()))?;
                        cleaned_files.push(path.to_path_buf());
                    }
                }
            }
        }

        Ok((
            MaintenanceAction {
                action_type: MaintenanceActionType::CleanupGoldenFiles,
                description: format!("Cleaned up {} stale golden files", cleaned_files.len()),
                affected_files: cleaned_files.clone(),
                successful: true,
                error_message: None,
            },
            cleaned_files,
        ))
    }

    /// Cleanup stale fixture files
    fn cleanup_fixture_files(
        &self,
        fixture_dir: &Path,
    ) -> Result<(MaintenanceAction, Vec<PathBuf>)> {
        let mut cleaned_files = Vec::new();
        let cutoff_date = Utc::now() - Duration::days(self.config.max_fixture_age_days);

        if !fixture_dir.exists() {
            return Ok((
                MaintenanceAction {
                    action_type: MaintenanceActionType::CleanupFixtures,
                    description: "Fixture directory does not exist".to_string(),
                    affected_files: vec![],
                    successful: true,
                    error_message: None,
                },
                cleaned_files,
            ));
        }

        for entry in WalkDir::new(fixture_dir) {
            let entry = entry.context("Failed to read directory entry")?;
            if entry.file_type().is_file() {
                let path = entry.path();
                let metadata = entry.metadata().context("Failed to read file metadata")?;
                let modified_time: DateTime<Utc> = metadata
                    .modified()
                    .context("Failed to get modification time")?
                    .into();

                if modified_time < cutoff_date {
                    if self.config.aggressive_cleanup {
                        std::fs::remove_file(path)
                            .with_context(|| format!("Failed to remove file {}", path.display()))?;
                        cleaned_files.push(path.to_path_buf());
                    }
                }
            }
        }

        Ok((
            MaintenanceAction {
                action_type: MaintenanceActionType::CleanupFixtures,
                description: format!("Cleaned up {} stale fixture files", cleaned_files.len()),
                affected_files: cleaned_files.clone(),
                successful: true,
                error_message: None,
            },
            cleaned_files,
        ))
    }

    /// Update outdated golden files
    fn update_golden_files(&self, golden_dir: &Path) -> Result<(MaintenanceAction, Vec<PathBuf>)> {
        let updated_files = Vec::new(); // TODO: Implement golden file updating logic

        Ok((
            MaintenanceAction {
                action_type: MaintenanceActionType::UpdateGoldenFiles,
                description: "Golden file update not yet implemented".to_string(),
                affected_files: updated_files.clone(),
                successful: true,
                error_message: None,
            },
            updated_files,
        ))
    }

    /// Cleanup historical snapshots
    fn cleanup_historical_snapshots(
        &self,
        output_dir: &Path,
    ) -> Result<(MaintenanceAction, Vec<PathBuf>)> {
        let mut cleaned_files = Vec::new();
        let snapshots_pattern = output_dir.join("snapshots");

        if !snapshots_pattern.exists() {
            return Ok((
                MaintenanceAction {
                    action_type: MaintenanceActionType::CleanupSnapshots,
                    description: "No snapshots directory found".to_string(),
                    affected_files: vec![],
                    successful: true,
                    error_message: None,
                },
                cleaned_files,
            ));
        }

        // Collect all snapshot files with their timestamps
        let mut snapshots = Vec::new();
        for entry in WalkDir::new(&snapshots_pattern) {
            let entry = entry.context("Failed to read directory entry")?;
            if entry.file_type().is_file()
                && entry.path().extension().and_then(|s| s.to_str()) == Some("json")
            {
                let path = entry.path();
                let metadata = entry.metadata().context("Failed to read file metadata")?;
                let modified_time: DateTime<Utc> = metadata
                    .modified()
                    .context("Failed to get modification time")?
                    .into();
                snapshots.push((path.to_path_buf(), modified_time));
            }
        }

        // Sort by timestamp (newest first) and remove excess
        snapshots.sort_by(|a, b| b.1.cmp(&a.1));
        if snapshots.len() > self.config.max_snapshots_to_keep {
            let to_remove = &snapshots[self.config.max_snapshots_to_keep..];

            for (path, _) in to_remove {
                if self.config.aggressive_cleanup {
                    std::fs::remove_file(path)
                        .with_context(|| format!("Failed to remove snapshot {}", path.display()))?;
                    cleaned_files.push(path.clone());
                }
            }
        }

        Ok((
            MaintenanceAction {
                action_type: MaintenanceActionType::CleanupSnapshots,
                description: format!("Cleaned up {} old snapshots", cleaned_files.len()),
                affected_files: cleaned_files.clone(),
                successful: true,
                error_message: None,
            },
            cleaned_files,
        ))
    }

    /// Validate file integrity
    fn validate_file_integrity(&self, golden_dir: &Path) -> Result<MaintenanceAction> {
        let mut validated_files = Vec::new();
        let mut errors = Vec::new();

        if golden_dir.exists() {
            for entry in WalkDir::new(golden_dir) {
                let entry = entry.context("Failed to read directory entry")?;
                if entry.file_type().is_file() {
                    let path = entry.path();

                    // Basic validation: try to read the file
                    match std::fs::read_to_string(path) {
                        Ok(_) => {
                            validated_files.push(path.to_path_buf());
                        }
                        Err(e) => {
                            errors.push(format!("Failed to read {}: {}", path.display(), e));
                        }
                    }
                }
            }
        }

        Ok(MaintenanceAction {
            action_type: MaintenanceActionType::ValidateFiles,
            description: format!(
                "Validated {} files, {} errors found",
                validated_files.len(),
                errors.len()
            ),
            affected_files: validated_files,
            successful: errors.is_empty(),
            error_message: if errors.is_empty() {
                None
            } else {
                Some(errors.join("; "))
            },
        })
    }

    /// Generate maintenance report
    fn generate_maintenance_report(
        &self,
        output_dir: &Path,
        actions: &[MaintenanceAction],
    ) -> Result<MaintenanceAction> {
        let report_path = output_dir.join("maintenance_report.md");

        let mut report_content = String::new();
        report_content.push_str("# Maintenance Report\n\n");
        report_content.push_str(&format!(
            "Generated: {}\n\n",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ));

        report_content.push_str("## Actions Performed\n\n");
        for action in actions {
            report_content.push_str(&format!("### {:?}\n", action.action_type));
            report_content.push_str(&format!("- **Description:** {}\n", action.description));
            report_content.push_str(&format!("- **Success:** {}\n", action.successful));
            report_content.push_str(&format!(
                "- **Files Affected:** {}\n",
                action.affected_files.len()
            ));
            if let Some(ref error) = action.error_message {
                report_content.push_str(&format!("- **Error:** {}\n", error));
            }
            report_content.push_str("\n");
        }

        std::fs::write(&report_path, report_content).with_context(|| {
            format!(
                "Failed to write maintenance report to {}",
                report_path.display()
            )
        })?;

        Ok(MaintenanceAction {
            action_type: MaintenanceActionType::GenerateReport,
            description: "Generated maintenance report".to_string(),
            affected_files: vec![report_path],
            successful: true,
            error_message: None,
        })
    }

    /// Assess the health of a single file
    fn assess_file_health(
        &self,
        path: &Path,
        size_bytes: u64,
        age_days: i64,
    ) -> Result<FileHealthStatus> {
        let is_stale = age_days > self.config.max_golden_age_days;
        let is_large = size_bytes > self.config.large_file_threshold;

        // Calculate health score based on various factors
        let mut health_score = 1.0;

        // Age factor (files get unhealthier as they age)
        if age_days > self.config.max_golden_age_days {
            health_score *= 0.5;
        } else if age_days > self.config.max_golden_age_days / 2 {
            health_score *= 0.8;
        }

        // Size factor (very large files are less healthy)
        if is_large {
            health_score *= 0.7;
        }

        // Recommend actions based on health factors
        let mut recommended_actions = Vec::new();
        if is_stale {
            recommended_actions.push(MaintenanceActionType::CleanupGoldenFiles);
        }
        if is_large {
            recommended_actions.push(MaintenanceActionType::CompressFiles);
        }
        if health_score < 0.6 {
            recommended_actions.push(MaintenanceActionType::ValidateFiles);
        }

        Ok(FileHealthStatus {
            path: path.to_path_buf(),
            size_bytes,
            last_modified: Utc::now() - Duration::days(age_days),
            age_days,
            is_stale,
            is_large,
            health_score,
            recommended_actions,
        })
    }

    /// Calculate statistics for maintenance operations
    fn calculate_statistics(
        &self,
        actions: &[MaintenanceAction],
        cleaned_files: &[PathBuf],
        updated_files: &[PathBuf],
        duration: std::time::Duration,
    ) -> MaintenanceStatistics {
        let mut file_types = HashMap::new();

        // Count file types for cleaned and updated files
        for file in cleaned_files.iter().chain(updated_files.iter()) {
            if let Some(ext) = file.extension().and_then(|s| s.to_str()) {
                *file_types.entry(ext.to_string()).or_insert(0) += 1;
            } else {
                *file_types.entry("no_extension".to_string()).or_insert(0) += 1;
            }
        }

        // Calculate approximate space reclaimed (would need actual file sizes for accuracy)
        let estimated_space_per_file = 1024 * 1024; // 1MB estimate
        let space_reclaimed = (cleaned_files.len() as u64) * estimated_space_per_file;

        MaintenanceStatistics {
            files_processed: actions.iter().map(|a| a.affected_files.len()).sum(),
            files_cleaned: cleaned_files.len(),
            files_updated: updated_files.len(),
            space_reclaimed,
            duration_seconds: duration.as_secs_f64(),
            file_types,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_maintenance_config_default() {
        let config = MaintenanceConfig::default();
        assert_eq!(config.max_golden_age_days, 30);
        assert_eq!(config.max_fixture_age_days, 7);
        assert_eq!(config.max_snapshots_to_keep, 50);
        assert_eq!(config.large_file_threshold, 10 * 1024 * 1024);
    }

    #[test]
    fn test_maintenance_workflow_creation() {
        let config = MaintenanceConfig::default();
        let workflow = MaintenanceWorkflow::new(config);
        assert_eq!(workflow.config.max_golden_age_days, 30);
    }

    #[test]
    fn test_file_health_assessment() {
        let workflow = MaintenanceWorkflow::default();
        let path = PathBuf::from("test.json");

        // Test young, small file (should be healthy)
        let health = workflow.assess_file_health(&path, 1024, 1).unwrap();
        assert!(health.health_score > 0.9);
        assert!(!health.is_stale);
        assert!(!health.is_large);

        // Test old, large file (should be unhealthy)
        let health = workflow
            .assess_file_health(&path, 20 * 1024 * 1024, 60)
            .unwrap();
        assert!(health.health_score < 0.5);
        assert!(health.is_stale);
        assert!(health.is_large);
    }

    #[test]
    fn test_maintenance_action_types() {
        let action = MaintenanceAction {
            action_type: MaintenanceActionType::CleanupGoldenFiles,
            description: "Test action".to_string(),
            affected_files: vec![],
            successful: true,
            error_message: None,
        };

        assert_eq!(
            action.action_type,
            MaintenanceActionType::CleanupGoldenFiles
        );
        assert!(action.successful);
        assert!(action.error_message.is_none());
    }

    #[test]
    fn test_empty_directory_maintenance() {
        let workflow = MaintenanceWorkflow::default();
        let temp_dir = TempDir::new().unwrap();

        let result = workflow.execute_maintenance(
            &temp_dir.path().join("golden"),
            &temp_dir.path().join("fixtures"),
            &temp_dir.path().join("output"),
        );

        assert!(result.is_ok());
        let maintenance_result = result.unwrap();
        assert!(!maintenance_result.actions_performed.is_empty());
        assert!(maintenance_result.cleaned_files.is_empty());
    }
}
