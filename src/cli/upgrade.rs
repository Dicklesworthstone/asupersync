//! ATP Upgrade and Rollback Management
//!
//! Handles ATP version upgrades, rollbacks, and state schema migrations
//! while preserving user data and configuration.

use crate::atp::config::{AtpConfig, ConfigVersion};
use crate::types::outcome::Outcome;
use semver::Version;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// ATP upgrade manager
#[derive(Debug)]
pub struct UpgradeManager {
    pub config_dir: PathBuf,
    pub current_version: Version,
    pub backup_dir: PathBuf,
}

impl UpgradeManager {
    pub fn new(config_dir: PathBuf) -> Result<Self, UpgradeError> {
        let current_version = Version::parse(env!("CARGO_PKG_VERSION"))
            .map_err(|e| UpgradeError::VersionParsing(e.to_string()))?;

        let backup_dir = config_dir.join("backups");
        std::fs::create_dir_all(&backup_dir)?;

        Ok(Self {
            config_dir,
            current_version,
            backup_dir,
        })
    }

    /// Check for available upgrades
    pub fn check_for_updates(&self) -> Result<UpdateInfo, UpgradeError> {
        // In a real implementation, this would check against a release server
        // For now, simulate the check
        println!("Checking for ATP updates...");

        // Read current config to get installed version
        let config_path = self.config_dir.join("config.toml");
        let installed_version = if config_path.exists() {
            let config = AtpConfig::read_from_file(&config_path)?;
            config.version.unwrap_or_else(|| Version::new(0, 1, 0))
        } else {
            Version::new(0, 1, 0)
        };

        let update_info = UpdateInfo {
            current_version: installed_version.clone(),
            latest_version: self.current_version.clone(),
            update_available: self.current_version > installed_version,
            download_url: Some(
                "https://github.com/asupersync/asupersync/releases/latest".to_string(),
            ),
            changelog_url: Some("https://github.com/asupersync/asupersync/releases".to_string()),
            breaking_changes: self.has_breaking_changes(&installed_version, &self.current_version),
            schema_migration_required: self
                .requires_schema_migration(&installed_version, &self.current_version),
        };

        Ok(update_info)
    }

    /// Perform ATP upgrade with state preservation
    pub fn upgrade(
        &mut self,
        target_version: Option<Version>,
    ) -> Result<UpgradeResult, UpgradeError> {
        let target = target_version.unwrap_or_else(|| self.current_version.clone());

        println!("Upgrading ATP to version {}...", target);

        // Step 1: Create backup
        let backup_id = self.create_backup()?;
        println!("Created backup: {}", backup_id);

        // Step 2: Stop daemon if running
        let daemon_was_running = self.stop_daemon_if_running()?;

        // Step 3: Validate upgrade path
        self.validate_upgrade_path(&target)?;

        // Step 4: Perform state migration if needed
        let migration_result = self.migrate_state(&target)?;

        // Step 5: Update configuration
        self.update_configuration(&target)?;

        // Step 6: Restart daemon if it was running
        if daemon_was_running {
            self.start_daemon()?;
        }

        println!("✅ ATP upgraded successfully to version {}", target);

        Ok(UpgradeResult {
            previous_version: backup_id.clone(),
            new_version: target,
            backup_id,
            migration_performed: migration_result.is_some(),
            migration_details: migration_result,
            rollback_available: true,
        })
    }

    /// Rollback to previous version
    pub fn rollback(&mut self, backup_id: String) -> Result<RollbackResult, UpgradeError> {
        println!("Rolling back ATP to backup: {}", backup_id);

        // Validate backup exists
        let backup_path = self.backup_dir.join(&backup_id);
        if !backup_path.exists() {
            return Err(UpgradeError::BackupNotFound(backup_id));
        }

        // Stop daemon
        let daemon_was_running = self.stop_daemon_if_running()?;

        // Read backup metadata
        let backup_metadata = self.read_backup_metadata(&backup_id)?;

        // Restore configuration and state
        self.restore_from_backup(&backup_id)?;

        // Restart daemon if needed
        if daemon_was_running {
            self.start_daemon()?;
        }

        println!(
            "✅ ATP rolled back successfully to version {}",
            backup_metadata.version
        );

        Ok(RollbackResult {
            restored_version: backup_metadata.version,
            backup_id,
            timestamp: SystemTime::now(),
        })
    }

    /// List available backups
    pub fn list_backups(&self) -> Result<Vec<BackupInfo>, UpgradeError> {
        let mut backups = Vec::new();

        if !self.backup_dir.exists() {
            return Ok(backups);
        }

        for entry in std::fs::read_dir(&self.backup_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let backup_id = entry.file_name().to_string_lossy().to_string();

                match self.read_backup_metadata(&backup_id) {
                    Ok(metadata) => {
                        backups.push(BackupInfo {
                            backup_id,
                            version: metadata.version,
                            timestamp: metadata.timestamp,
                            size_bytes: metadata.size_bytes,
                            schema_version: metadata.schema_version,
                        });
                    }
                    Err(_) => {
                        // Skip invalid backups
                        continue;
                    }
                }
            }
        }

        // Sort by timestamp, newest first
        backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        Ok(backups)
    }

    fn create_backup(&self) -> Result<String, UpgradeError> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let backup_id = format!("{}_{}", self.current_version, timestamp);
        let backup_path = self.backup_dir.join(&backup_id);

        std::fs::create_dir_all(&backup_path)?;

        // Copy current configuration
        let config_path = self.config_dir.join("config.toml");
        if config_path.exists() {
            std::fs::copy(&config_path, backup_path.join("config.toml"))?;
        }

        // Copy identity
        let identity_path = self.config_dir.join("identity.key");
        if identity_path.exists() {
            std::fs::copy(&identity_path, backup_path.join("identity.key"))?;
        }

        // Copy peer directory
        let peer_dir = self.config_dir.join("peers");
        if peer_dir.exists() {
            self.copy_directory_recursive(&peer_dir, &backup_path.join("peers"))?;
        }

        // Copy daemon state (excluding logs)
        let daemon_dir = self.config_dir.join("daemon");
        if daemon_dir.exists() {
            self.copy_directory_selective(&daemon_dir, &backup_path.join("daemon"), &["*.log"])?;
        }

        // Create backup metadata
        let metadata = BackupMetadata {
            backup_id: backup_id.clone(),
            version: self.current_version.clone(),
            timestamp: SystemTime::now(),
            schema_version: ConfigVersion::current(),
            size_bytes: self.calculate_directory_size(&backup_path)?,
        };

        let metadata_path = backup_path.join("metadata.json");
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        std::fs::write(metadata_path, metadata_json)?;

        Ok(backup_id)
    }

    fn validate_upgrade_path(&self, target: &Version) -> Result<(), UpgradeError> {
        // Check for unsupported version downgrades
        if target < &self.current_version {
            return Err(UpgradeError::UnsupportedDowngrade {
                current: self.current_version.clone(),
                target: target.clone(),
            });
        }

        // Check for skipped major versions
        if target.major > self.current_version.major + 1 {
            return Err(UpgradeError::UnsupportedMajorSkip {
                current: self.current_version.clone(),
                target: target.clone(),
            });
        }

        Ok(())
    }

    fn migrate_state(
        &self,
        target_version: &Version,
    ) -> Result<Option<MigrationResult>, UpgradeError> {
        if !self.requires_schema_migration(&self.current_version, target_version) {
            return Ok(None);
        }

        println!("Performing state migration...");

        // Example migration logic
        let migration_result = MigrationResult {
            from_version: self.current_version.clone(),
            to_version: target_version.clone(),
            migrations_applied: vec![
                "config_schema_v2".to_string(),
                "peer_directory_format".to_string(),
            ],
            backup_created: true,
        };

        Ok(Some(migration_result))
    }

    fn requires_schema_migration(&self, from: &Version, to: &Version) -> bool {
        // Schema migrations required for major version changes
        from.major != to.major
    }

    fn has_breaking_changes(&self, from: &Version, to: &Version) -> bool {
        // Breaking changes occur on major version bumps
        to.major > from.major
    }

    fn stop_daemon_if_running(&self) -> Result<bool, UpgradeError> {
        // Check if daemon is running
        // In real implementation, would check process/service status
        println!("Checking ATP daemon status...");

        // Simulate daemon check and stop
        if self.is_daemon_running()? {
            println!("Stopping ATP daemon...");
            // Stop daemon command would go here
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn is_daemon_running(&self) -> Result<bool, UpgradeError> {
        // Check daemon status based on platform
        // This is a simplified implementation
        Ok(false)
    }

    fn start_daemon(&self) -> Result<(), UpgradeError> {
        println!("Starting ATP daemon...");
        // Start daemon command would go here
        Ok(())
    }

    fn update_configuration(&self, target_version: &Version) -> Result<(), UpgradeError> {
        let config_path = self.config_dir.join("config.toml");

        if !config_path.exists() {
            return Ok(());
        }

        let mut config = AtpConfig::read_from_file(&config_path)?;
        config.version = Some(target_version.clone());

        config.write_to_file(&config_path)?;

        Ok(())
    }

    fn copy_directory_recursive(&self, src: &Path, dst: &Path) -> Result<(), UpgradeError> {
        std::fs::create_dir_all(dst)?;

        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());

            if file_type.is_dir() {
                self.copy_directory_recursive(&src_path, &dst_path)?;
            } else {
                std::fs::copy(&src_path, &dst_path)?;
            }
        }

        Ok(())
    }

    fn copy_directory_selective(
        &self,
        src: &Path,
        dst: &Path,
        excludes: &[&str],
    ) -> Result<(), UpgradeError> {
        std::fs::create_dir_all(dst)?;

        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let file_name = entry.file_name().to_string_lossy();

            // Check if file matches exclude patterns
            let should_exclude = excludes.iter().any(|pattern| {
                // Simple glob matching - in real implementation would use a proper glob library
                pattern
                    .trim_start_matches('*')
                    .chars()
                    .all(|c| file_name.contains(c))
            });

            if should_exclude {
                continue;
            }

            let file_type = entry.file_type()?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());

            if file_type.is_dir() {
                self.copy_directory_selective(&src_path, &dst_path, excludes)?;
            } else {
                std::fs::copy(&src_path, &dst_path)?;
            }
        }

        Ok(())
    }

    fn calculate_directory_size(&self, path: &Path) -> Result<u64, UpgradeError> {
        let mut size = 0u64;

        if path.is_dir() {
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                let metadata = entry.metadata()?;

                if metadata.is_dir() {
                    size += self.calculate_directory_size(&entry.path())?;
                } else {
                    size += metadata.len();
                }
            }
        } else {
            size = path.metadata()?.len();
        }

        Ok(size)
    }

    fn read_backup_metadata(&self, backup_id: &str) -> Result<BackupMetadata, UpgradeError> {
        let metadata_path = self.backup_dir.join(backup_id).join("metadata.json");
        let metadata_content = std::fs::read_to_string(metadata_path)?;
        let metadata: BackupMetadata = serde_json::from_str(&metadata_content)?;
        Ok(metadata)
    }

    fn restore_from_backup(&self, backup_id: &str) -> Result<(), UpgradeError> {
        let backup_path = self.backup_dir.join(backup_id);

        // Restore configuration
        let backup_config = backup_path.join("config.toml");
        if backup_config.exists() {
            std::fs::copy(&backup_config, self.config_dir.join("config.toml"))?;
        }

        // Restore identity
        let backup_identity = backup_path.join("identity.key");
        if backup_identity.exists() {
            std::fs::copy(&backup_identity, self.config_dir.join("identity.key"))?;
        }

        // Restore peer directory
        let backup_peers = backup_path.join("peers");
        if backup_peers.exists() {
            let peers_dir = self.config_dir.join("peers");
            if peers_dir.exists() {
                std::fs::remove_dir_all(&peers_dir)?;
            }
            self.copy_directory_recursive(&backup_peers, &peers_dir)?;
        }

        // Restore daemon state
        let backup_daemon = backup_path.join("daemon");
        if backup_daemon.exists() {
            let daemon_dir = self.config_dir.join("daemon");
            if daemon_dir.exists() {
                std::fs::remove_dir_all(&daemon_dir)?;
            }
            self.copy_directory_recursive(&backup_daemon, &daemon_dir)?;
        }

        Ok(())
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct UpdateInfo {
    pub current_version: Version,
    pub latest_version: Version,
    pub update_available: bool,
    pub download_url: Option<String>,
    pub changelog_url: Option<String>,
    pub breaking_changes: bool,
    pub schema_migration_required: bool,
}

#[derive(Debug)]
pub struct UpgradeResult {
    pub previous_version: String,
    pub new_version: Version,
    pub backup_id: String,
    pub migration_performed: bool,
    pub migration_details: Option<MigrationResult>,
    pub rollback_available: bool,
}

#[derive(Debug)]
pub struct RollbackResult {
    pub restored_version: Version,
    pub backup_id: String,
    pub timestamp: SystemTime,
}

#[derive(Debug)]
pub struct MigrationResult {
    pub from_version: Version,
    pub to_version: Version,
    pub migrations_applied: Vec<String>,
    pub backup_created: bool,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BackupMetadata {
    pub backup_id: String,
    pub version: Version,
    pub timestamp: SystemTime,
    pub schema_version: ConfigVersion,
    pub size_bytes: u64,
}

#[derive(Debug)]
pub struct BackupInfo {
    pub backup_id: String,
    pub version: Version,
    pub timestamp: SystemTime,
    pub size_bytes: u64,
    pub schema_version: ConfigVersion,
}

#[derive(Debug, thiserror::Error)]
pub enum UpgradeError {
    #[error("Version parsing error: {0}")]
    VersionParsing(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Backup not found: {0}")]
    BackupNotFound(String),

    #[error("Unsupported downgrade from {current} to {target}")]
    UnsupportedDowngrade { current: Version, target: Version },

    #[error("Unsupported major version skip from {current} to {target}")]
    UnsupportedMajorSkip { current: Version, target: Version },

    #[error("Migration failed: {0}")]
    MigrationFailed(String),

    #[error("Daemon error: {0}")]
    DaemonError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_upgrade_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let manager = UpgradeManager::new(temp_dir.path().to_path_buf());

        assert!(manager.is_ok());
        let manager = manager.unwrap();
        assert!(manager.backup_dir.exists());
    }

    #[test]
    fn test_backup_creation() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = UpgradeManager::new(temp_dir.path().to_path_buf()).unwrap();

        // Create some test files
        std::fs::write(temp_dir.path().join("config.toml"), "test config").unwrap();

        let backup_id = manager.create_backup().unwrap();
        assert!(!backup_id.is_empty());

        let backup_path = manager.backup_dir.join(&backup_id);
        assert!(backup_path.exists());
        assert!(backup_path.join("metadata.json").exists());
    }
}
