//! Fixture Maintenance and Automation Workflows
//!
//! Implements automated fixture maintenance, reference implementation version
//! tracking, and workflow automation for long-term conformance testing maintenance.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::Command;

const VERSION_METADATA_FILE: &str = ".reference-version.json";

/// Reference implementation version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceVersion {
    pub name: String,                       // e.g., "raptorq-go"
    pub version: String,                    // e.g., "v1.2.3"
    pub commit_hash: String,                // Git commit hash
    pub last_updated: String,               // ISO timestamp
    pub fixture_directory: PathBuf,         // Where fixtures are stored
    pub generation_command: String,         // Command to regenerate fixtures
    pub validation_command: Option<String>, // Command to validate fixtures
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FixtureVersionMetadata {
    schema_version: u8,
    name: String,
    version: String,
    commit_hash: String,
    generation_command: String,
    validation_command: Option<String>,
}

impl ReferenceVersion {
    pub fn new(name: String, fixture_directory: PathBuf) -> Self {
        Self {
            name,
            version: "unknown".to_string(),
            commit_hash: "unknown".to_string(),
            last_updated: chrono::Utc::now().to_rfc3339(),
            fixture_directory,
            generation_command: "echo 'No generation command configured'".to_string(),
            validation_command: None,
        }
    }

    /// Update version information from git repository
    pub fn update_from_git<P: AsRef<Path>>(&mut self, repo_path: P) -> Result<(), std::io::Error> {
        let repo_path = repo_path.as_ref();
        let repo_path_arg = repo_path.to_string_lossy();

        // Get latest commit hash
        if let Ok(output) = Command::new("git")
            .args(["-C", repo_path_arg.as_ref(), "rev-parse", "HEAD"])
            .output()
            && output.status.success()
        {
            self.commit_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
        }

        // Get latest tag version
        if let Ok(output) = Command::new("git")
            .args([
                "-C",
                repo_path_arg.as_ref(),
                "describe",
                "--tags",
                "--abbrev=0",
            ])
            .output()
            && output.status.success()
        {
            self.version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        }

        self.last_updated = chrono::Utc::now().to_rfc3339();
        Ok(())
    }

    /// Check if fixtures need regeneration based on version changes
    pub fn needs_regeneration(&self) -> bool {
        // Check if fixture directory exists and has content
        if !self.fixture_directory.exists() {
            return true;
        }

        let has_fixture_files = match fs::read_dir(&self.fixture_directory) {
            Ok(entries) => entries.filter_map(Result::ok).any(|entry| {
                let path = entry.path();
                path.is_file() && !is_version_metadata_path(&path)
            }),
            Err(_) => return true,
        };

        if !has_fixture_files {
            return true;
        }

        match self.read_version_metadata() {
            Ok(metadata) => metadata != self.expected_version_metadata(),
            Err(_) => true,
        }
    }

    /// Generate fixtures using the configured command
    pub fn generate_fixtures(
        &self,
        dry_run: bool,
    ) -> Result<FixtureGenerationResult, std::io::Error> {
        if dry_run {
            return Ok(FixtureGenerationResult {
                success: true,
                command: self.generation_command.clone(),
                output: "DRY RUN: Command would be executed".to_string(),
                files_generated: vec![],
                duration: std::time::Duration::from_millis(0),
            });
        }

        // Ensure fixture directory exists
        fs::create_dir_all(&self.fixture_directory)?;

        let start = std::time::Instant::now();

        // Execute generation command
        let output = if cfg!(target_os = "windows") {
            Command::new("cmd")
                .args(["/C", self.generation_command.as_str()])
                .current_dir(&self.fixture_directory)
                .output()?
        } else {
            Command::new("sh")
                .arg("-c")
                .arg(&self.generation_command)
                .current_dir(&self.fixture_directory)
                .output()?
        };

        let duration = start.elapsed();
        let success = output.status.success();
        let output_str = String::from_utf8_lossy(&output.stdout).to_string()
            + &String::from_utf8_lossy(&output.stderr);

        let files_generated = if success {
            self.write_version_metadata()?;
            self.list_generated_files()?
        } else {
            vec![]
        };

        Ok(FixtureGenerationResult {
            success,
            command: self.generation_command.clone(),
            output: output_str,
            files_generated,
            duration,
        })
    }

    /// Validate fixtures using the configured validation command
    pub fn validate_fixtures(&self) -> Result<FixtureValidationResult, std::io::Error> {
        let Some(validation_command) = &self.validation_command else {
            return Ok(FixtureValidationResult {
                success: true,
                command: "No validation configured".to_string(),
                output: "Validation skipped - no command configured".to_string(),
                issues: vec![],
            });
        };

        let output = if cfg!(target_os = "windows") {
            Command::new("cmd")
                .args(["/C", validation_command.as_str()])
                .current_dir(&self.fixture_directory)
                .output()?
        } else {
            Command::new("sh")
                .arg("-c")
                .arg(validation_command)
                .current_dir(&self.fixture_directory)
                .output()?
        };

        let success = output.status.success();
        let output_str = String::from_utf8_lossy(&output.stdout).to_string()
            + &String::from_utf8_lossy(&output.stderr);

        // Parse validation issues (simplified - would need more sophisticated parsing)
        let issues = if !success {
            vec!["Validation command failed".to_string()]
        } else {
            vec![]
        };

        Ok(FixtureValidationResult {
            success,
            command: validation_command.clone(),
            output: output_str,
            issues,
        })
    }

    /// List files in fixture directory
    fn list_generated_files(&self) -> Result<Vec<PathBuf>, std::io::Error> {
        let mut files = vec![];

        if self.fixture_directory.exists() {
            for entry in fs::read_dir(&self.fixture_directory)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() && !is_version_metadata_path(&path) {
                    files.push(path);
                }
            }
        }

        files.sort();
        Ok(files)
    }

    fn version_metadata_path(&self) -> PathBuf {
        self.fixture_directory.join(VERSION_METADATA_FILE)
    }

    fn expected_version_metadata(&self) -> FixtureVersionMetadata {
        FixtureVersionMetadata {
            schema_version: 1,
            name: self.name.clone(),
            version: self.version.clone(),
            commit_hash: self.commit_hash.clone(),
            generation_command: self.generation_command.clone(),
            validation_command: self.validation_command.clone(),
        }
    }

    fn read_version_metadata(&self) -> Result<FixtureVersionMetadata, std::io::Error> {
        let bytes = fs::read(self.version_metadata_path())?;
        serde_json::from_slice(&bytes).map_err(invalid_metadata_error)
    }

    fn write_version_metadata(&self) -> Result<(), std::io::Error> {
        fs::create_dir_all(&self.fixture_directory)?;
        let bytes = serde_json::to_vec_pretty(&self.expected_version_metadata())
            .map_err(invalid_metadata_error)?;
        fs::write(self.version_metadata_path(), bytes)
    }
}

fn is_version_metadata_path(path: &Path) -> bool {
    path.file_name() == Some(OsStr::new(VERSION_METADATA_FILE))
}

fn invalid_metadata_error(error: serde_json::Error) -> std::io::Error {
    Error::new(ErrorKind::InvalidData, error)
}

/// Result of fixture generation operation
#[derive(Debug, Clone)]
pub struct FixtureGenerationResult {
    pub success: bool,
    pub command: String,
    pub output: String,
    pub files_generated: Vec<PathBuf>,
    pub duration: std::time::Duration,
}

/// Result of fixture validation operation
#[derive(Debug, Clone)]
pub struct FixtureValidationResult {
    pub success: bool,
    pub command: String,
    pub output: String,
    pub issues: Vec<String>,
}

/// Configuration for maintenance workflows
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceConfig {
    pub auto_regenerate: bool,      // Automatically regenerate fixtures
    pub validation_required: bool,  // Require validation before accepting fixtures
    pub backup_old_fixtures: bool,  // Backup fixtures before regeneration
    pub notification_enabled: bool, // Send notifications on changes
    pub max_fixture_age_days: u64,  // Maximum age before flagging for review
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            auto_regenerate: false,      // Conservative default - manual control
            validation_required: true,   // Always validate
            backup_old_fixtures: true,   // Safety first
            notification_enabled: false, // Avoid spam
            max_fixture_age_days: 30,    // Monthly review cycle
        }
    }
}

/// Maintenance workflow manager
pub struct MaintenanceManager {
    config: MaintenanceConfig,
    reference_versions: HashMap<String, ReferenceVersion>,
    fixture_base_path: PathBuf,
}

impl MaintenanceManager {
    pub fn new(config: MaintenanceConfig, fixture_base_path: PathBuf) -> Self {
        Self {
            config,
            reference_versions: HashMap::new(),
            fixture_base_path,
        }
    }

    /// Add reference implementation to track
    pub fn add_reference(&mut self, name: String, mut reference: ReferenceVersion) {
        // Ensure fixture directory is relative to base path
        if reference.fixture_directory.is_relative() {
            reference.fixture_directory = self.fixture_base_path.join(reference.fixture_directory);
        }

        self.reference_versions.insert(name, reference);
    }

    /// Check all reference implementations for updates
    pub fn check_for_updates(&mut self) -> Vec<MaintenanceAction> {
        let mut actions = Vec::new();

        for (name, reference) in &mut self.reference_versions {
            // Check if fixtures are outdated
            if reference.needs_regeneration() {
                actions.push(MaintenanceAction::RegenerateFixtures {
                    reference_name: name.clone(),
                    reason: "Missing or empty fixtures".to_string(),
                });
            }

            // Check fixture age
            if let Ok(age_days) = Self::calculate_fixture_age(&reference.fixture_directory)
                && age_days > self.config.max_fixture_age_days
            {
                actions.push(MaintenanceAction::ReviewRequired {
                    reference_name: name.clone(),
                    reason: format!("Fixtures are {} days old", age_days),
                });
            }
        }

        actions
    }

    /// Execute maintenance action
    pub fn execute_action(
        &self,
        action: MaintenanceAction,
        dry_run: bool,
    ) -> Result<MaintenanceResult, std::io::Error> {
        match action {
            MaintenanceAction::RegenerateFixtures {
                reference_name,
                reason,
            } => {
                let Some(reference) = self.reference_versions.get(&reference_name) else {
                    return Ok(MaintenanceResult::Error {
                        action_type: "regenerate".to_string(),
                        message: format!("Reference '{}' not found", reference_name),
                    });
                };

                // Backup old fixtures if configured
                if self.config.backup_old_fixtures && !dry_run {
                    self.backup_fixtures(&reference.fixture_directory)?;
                }

                // Generate fixtures
                match reference.generate_fixtures(dry_run) {
                    Ok(gen_result) => {
                        if gen_result.success {
                            // Validate if required
                            if self.config.validation_required {
                                match reference.validate_fixtures() {
                                    Ok(val_result) => {
                                        if val_result.success {
                                            Ok(MaintenanceResult::Success {
                                                action_type: "regenerate".to_string(),
                                                message: format!(
                                                    "Generated and validated {} fixtures",
                                                    gen_result.files_generated.len()
                                                ),
                                                details: format!(
                                                    "Reason: {}\nCommand: {}\nOutput: {}",
                                                    reason, gen_result.command, gen_result.output
                                                ),
                                            })
                                        } else {
                                            Ok(MaintenanceResult::Warning {
                                                action_type: "regenerate".to_string(),
                                                message: "Fixtures generated but validation failed"
                                                    .to_string(),
                                                details: val_result.output,
                                            })
                                        }
                                    }
                                    Err(e) => Ok(MaintenanceResult::Error {
                                        action_type: "regenerate".to_string(),
                                        message: format!("Validation error: {}", e),
                                    }),
                                }
                            } else {
                                Ok(MaintenanceResult::Success {
                                    action_type: "regenerate".to_string(),
                                    message: format!(
                                        "Generated {} fixtures",
                                        gen_result.files_generated.len()
                                    ),
                                    details: gen_result.output,
                                })
                            }
                        } else {
                            Ok(MaintenanceResult::Error {
                                action_type: "regenerate".to_string(),
                                message: "Fixture generation failed".to_string(),
                            })
                        }
                    }
                    Err(e) => Ok(MaintenanceResult::Error {
                        action_type: "regenerate".to_string(),
                        message: format!("Generation error: {}", e),
                    }),
                }
            }

            MaintenanceAction::ReviewRequired {
                reference_name,
                reason,
            } => Ok(MaintenanceResult::Warning {
                action_type: "review".to_string(),
                message: format!("Review required for '{}': {}", reference_name, reason),
                details: "Manual review and action needed".to_string(),
            }),
        }
    }

    /// Calculate age of fixtures in days
    fn calculate_fixture_age(fixture_dir: &Path) -> Result<u64, std::io::Error> {
        if !fixture_dir.exists() {
            return Ok(u64::MAX); // Very old if missing
        }

        let mut newest_time = std::time::SystemTime::UNIX_EPOCH;

        for entry in fs::read_dir(fixture_dir)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if let Ok(modified) = metadata.modified()
                && modified > newest_time
            {
                newest_time = modified;
            }
        }

        let duration = std::time::SystemTime::now()
            .duration_since(newest_time)
            .map_err(|_| std::io::Error::other("Time calculation error"))?;

        Ok(duration.as_secs() / 86400) // Convert to days
    }

    /// Backup fixtures before regeneration
    fn backup_fixtures(&self, fixture_dir: &Path) -> Result<(), std::io::Error> {
        if !fixture_dir.exists() {
            return Ok(()); // Nothing to backup
        }

        let backup_dir = fixture_dir.with_extension("backup");
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let backup_path = backup_dir.join(format!("backup_{}", timestamp));

        fs::create_dir_all(&backup_path)?;

        // Copy all files to backup
        for entry in fs::read_dir(fixture_dir)? {
            let entry = entry?;
            if entry.path().is_file() {
                let dest = backup_path.join(entry.file_name());
                fs::copy(entry.path(), dest)?;
            }
        }

        Ok(())
    }

    /// Generate maintenance report
    pub fn generate_maintenance_report(&mut self) -> String {
        let mut report = String::new();

        report.push_str("# Conformance Fixture Maintenance Report\n\n");
        report.push_str(&format!(
            "**Generated:** {}\n\n",
            chrono::Utc::now().to_rfc3339()
        ));

        // Configuration
        report.push_str("## Configuration\n\n");
        report.push_str(&format!(
            "- **Auto Regenerate**: {}\n",
            self.config.auto_regenerate
        ));
        report.push_str(&format!(
            "- **Validation Required**: {}\n",
            self.config.validation_required
        ));
        report.push_str(&format!(
            "- **Backup Old Fixtures**: {}\n",
            self.config.backup_old_fixtures
        ));
        report.push_str(&format!(
            "- **Max Fixture Age**: {} days\n\n",
            self.config.max_fixture_age_days
        ));

        // Reference implementations
        report.push_str("## Reference Implementations\n\n");
        report.push_str("| Name | Version | Last Updated | Fixture Path | Status |\n");
        report.push_str("|------|---------|--------------|--------------|--------|\n");

        for (name, reference) in &self.reference_versions {
            let status = if reference.fixture_directory.exists() {
                let age = Self::calculate_fixture_age(&reference.fixture_directory).unwrap_or(999);

                if age > self.config.max_fixture_age_days {
                    format!("⚠️ {} days old", age)
                } else {
                    "✅ Current".to_string()
                }
            } else {
                "❌ Missing".to_string()
            };

            report.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                name,
                reference.version,
                reference
                    .last_updated
                    .split('T')
                    .next()
                    .unwrap_or("unknown"),
                reference.fixture_directory.display(),
                status
            ));
        }
        report.push('\n');

        // Recommended actions
        let actions = self.check_for_updates();
        if !actions.is_empty() {
            report.push_str("## Recommended Actions\n\n");
            for action in actions {
                match action {
                    MaintenanceAction::RegenerateFixtures {
                        reference_name,
                        reason,
                    } => {
                        report.push_str(&format!(
                            "- 🔄 **Regenerate fixtures** for '{}': {}\n",
                            reference_name, reason
                        ));
                    }
                    MaintenanceAction::ReviewRequired {
                        reference_name,
                        reason,
                    } => {
                        report.push_str(&format!(
                            "- 👀 **Review required** for '{}': {}\n",
                            reference_name, reason
                        ));
                    }
                }
            }
        } else {
            report
                .push_str("## Status\n\n✅ All fixtures are current and no actions required.\n\n");
        }

        report
    }
}

/// Maintenance action that needs to be taken
#[derive(Debug, Clone)]
pub enum MaintenanceAction {
    RegenerateFixtures {
        reference_name: String,
        reason: String,
    },
    ReviewRequired {
        reference_name: String,
        reason: String,
    },
}

/// Result of executing a maintenance action
#[derive(Debug, Clone)]
pub enum MaintenanceResult {
    Success {
        action_type: String,
        message: String,
        details: String,
    },
    Warning {
        action_type: String,
        message: String,
        details: String,
    },
    Error {
        action_type: String,
        message: String,
    },
}

impl MaintenanceResult {
    pub fn is_success(&self) -> bool {
        matches!(self, MaintenanceResult::Success { .. })
    }

    pub fn is_error(&self) -> bool {
        matches!(self, MaintenanceResult::Error { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_reference_version_creation() {
        let temp_dir = TempDir::new().unwrap();
        let reference =
            ReferenceVersion::new("test-ref".to_string(), temp_dir.path().to_path_buf());

        assert_eq!(reference.name, "test-ref");
        assert_eq!(reference.fixture_directory, temp_dir.path());
    }

    #[test]
    fn test_needs_regeneration() {
        let temp_dir = TempDir::new().unwrap();
        let reference =
            ReferenceVersion::new("test-ref".to_string(), temp_dir.path().to_path_buf());

        // Empty directory should need regeneration
        assert!(reference.needs_regeneration());

        // Fixture bytes without matching reference metadata are stale.
        fs::write(temp_dir.path().join("test.txt"), "test").unwrap();
        assert!(reference.needs_regeneration());

        // Matching version metadata marks the fixture set current.
        reference.write_version_metadata().unwrap();
        assert!(!reference.needs_regeneration());
    }

    #[test]
    fn test_needs_regeneration_detects_reference_version_change() {
        let temp_dir = TempDir::new().unwrap();
        let mut reference =
            ReferenceVersion::new("test-ref".to_string(), temp_dir.path().to_path_buf());
        reference.version = "v1.0.0".to_string();
        reference.commit_hash = "abc123".to_string();

        fs::write(temp_dir.path().join("fixture.bin"), "fixture").unwrap();
        reference.write_version_metadata().unwrap();
        assert!(!reference.needs_regeneration());

        reference.commit_hash = "def456".to_string();
        assert!(reference.needs_regeneration());
    }

    #[test]
    fn test_generate_fixtures_writes_reference_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let mut reference =
            ReferenceVersion::new("test-ref".to_string(), temp_dir.path().to_path_buf());
        reference.version = "v1.2.3".to_string();
        reference.commit_hash = "cafebabe".to_string();
        reference.generation_command = "printf fixture > generated.bin".to_string();
        reference.validation_command = Some("test -s generated.bin".to_string());

        let result = reference.generate_fixtures(false).unwrap();

        assert!(result.success);
        assert_eq!(result.files_generated.len(), 1);
        assert!(temp_dir.path().join("generated.bin").exists());
        assert!(temp_dir.path().join(VERSION_METADATA_FILE).exists());
        assert!(!reference.needs_regeneration());
    }

    #[test]
    fn test_maintenance_manager_actions() {
        let temp_dir = TempDir::new().unwrap();
        let config = MaintenanceConfig::default();
        let mut manager = MaintenanceManager::new(config, temp_dir.path().to_path_buf());

        let reference = ReferenceVersion::new("test-ref".to_string(), PathBuf::from("empty-dir"));
        manager.add_reference("test".to_string(), reference);

        let actions = manager.check_for_updates();
        assert!(!actions.is_empty());

        // Should recommend regeneration for empty directory
        match &actions[0] {
            MaintenanceAction::RegenerateFixtures { reference_name, .. } => {
                assert_eq!(reference_name, "test");
            }
            _ => panic!("Expected RegenerateFixtures action"),
        }
    }
}
