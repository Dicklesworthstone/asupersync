//! ATP Upgrade and Rollback Management
//!
//! Handles ATP version upgrades, rollbacks, and state schema migrations
//! while preserving user data and configuration.

use crate::cli::atp_config::{AtpInstallConfig, ConfigError, ConfigVersion};
use semver::Version;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, SystemTimeError};

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

        let installed_version = self.installed_version()?;

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
        let installed_version = self.installed_version()?;
        let target = target_version.unwrap_or_else(|| self.current_version.clone());

        println!("Upgrading ATP to version {}...", target);

        // Step 1: Validate upgrade path before any filesystem side effects.
        self.validate_upgrade_path(&installed_version, &target)?;

        // Step 2: Create backup
        let backup_id = self.create_backup()?;
        println!("Created backup: {}", backup_id);

        // Step 3: Stop daemon if running
        let daemon_was_running = self.stop_daemon_if_running()?;

        // Step 4: Perform state migration if needed
        let migration_result = self.migrate_state(&installed_version, &target)?;

        // Step 5: Update configuration
        self.update_configuration(&target)?;

        // Step 6: Restart daemon if it was running
        if daemon_was_running {
            self.start_daemon()?;
        }

        println!("✅ ATP upgraded successfully to version {}", target);

        Ok(UpgradeResult {
            previous_version: installed_version.to_string(),
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
                        // Skip invalid backups.
                    }
                }
            }
        }

        // Sort by timestamp, newest first
        backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        Ok(backups)
    }

    fn create_backup(&self) -> Result<String, UpgradeError> {
        let installed_version = self.installed_version()?;
        let timestamp = unix_time_secs()?;

        let backup_id = format!("{installed_version}_{timestamp}");
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
            Self::copy_directory_recursive(&peer_dir, &backup_path.join("peers"))?;
        }

        // Copy daemon state (excluding logs)
        let daemon_dir = self.config_dir.join("daemon");
        if daemon_dir.exists() {
            Self::copy_directory_selective(&daemon_dir, &backup_path.join("daemon"), &["*.log"])?;
        }

        // Create backup metadata
        let metadata = BackupMetadata {
            backup_id: backup_id.clone(),
            version: installed_version,
            timestamp: SystemTime::now(),
            schema_version: ConfigVersion::current(),
            size_bytes: Self::calculate_directory_size(&backup_path)?,
        };

        let metadata_path = backup_path.join("metadata.json");
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        std::fs::write(metadata_path, metadata_json)?;

        Ok(backup_id)
    }

    fn validate_upgrade_path(
        &self,
        installed: &Version,
        target: &Version,
    ) -> Result<(), UpgradeError> {
        // Check for unsupported version downgrades
        if target < installed {
            return Err(UpgradeError::UnsupportedDowngrade {
                current: installed.clone(),
                target: target.clone(),
            });
        }

        // Check for skipped major versions
        if target.major > installed.major + 1 {
            return Err(UpgradeError::UnsupportedMajorSkip {
                current: installed.clone(),
                target: target.clone(),
            });
        }

        Ok(())
    }

    fn migrate_state(
        &self,
        installed_version: &Version,
        target_version: &Version,
    ) -> Result<Option<MigrationResult>, UpgradeError> {
        if !self.requires_schema_migration(installed_version, target_version) {
            return Ok(None);
        }

        println!("Performing state migration...");

        // Example migration logic
        let migration_result = MigrationResult {
            from_version: installed_version.clone(),
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

    fn installed_version(&self) -> Result<Version, UpgradeError> {
        let config_path = self.config_dir.join("config.toml");
        if !config_path.exists() {
            return Ok(Version::new(0, 1, 0));
        }

        let config = AtpInstallConfig::read_from_file(&config_path)?;
        Ok(config.version.unwrap_or_else(|| Version::new(0, 1, 0)))
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

        let mut config = AtpInstallConfig::read_from_file(&config_path)?;
        config.version = Some(target_version.clone());

        config.write_to_file(&config_path)?;

        Ok(())
    }

    fn copy_directory_recursive(src: &Path, dst: &Path) -> Result<(), UpgradeError> {
        std::fs::create_dir_all(dst)?;

        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());

            if file_type.is_dir() {
                Self::copy_directory_recursive(&src_path, &dst_path)?;
            } else {
                std::fs::copy(&src_path, &dst_path)?;
            }
        }

        Ok(())
    }

    fn copy_directory_selective(
        src: &Path,
        dst: &Path,
        excludes: &[&str],
    ) -> Result<(), UpgradeError> {
        std::fs::create_dir_all(dst)?;

        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();

            let should_exclude = excludes
                .iter()
                .any(|pattern| matches_simple_exclude_pattern(&file_name, pattern));

            if should_exclude {
                continue;
            }

            let file_type = entry.file_type()?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());

            if file_type.is_dir() {
                Self::copy_directory_selective(&src_path, &dst_path, excludes)?;
            } else {
                std::fs::copy(&src_path, &dst_path)?;
            }
        }

        Ok(())
    }

    fn calculate_directory_size(path: &Path) -> Result<u64, UpgradeError> {
        let mut size = 0u64;

        if path.is_dir() {
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                let metadata = entry.metadata()?;

                if metadata.is_dir() {
                    size += Self::calculate_directory_size(&entry.path())?;
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

        self.restore_file_from_backup(
            &backup_path.join("config.toml"),
            &self.config_dir.join("config.toml"),
        )?;
        self.restore_file_from_backup(
            &backup_path.join("identity.key"),
            &self.config_dir.join("identity.key"),
        )?;
        self.restore_directory_from_backup(
            &backup_path.join("peers"),
            &self.config_dir.join("peers"),
        )?;
        self.restore_directory_from_backup(
            &backup_path.join("daemon"),
            &self.config_dir.join("daemon"),
        )?;

        Ok(())
    }

    fn restore_file_from_backup(
        &self,
        backup_file: &Path,
        target: &Path,
    ) -> Result<(), UpgradeError> {
        if !backup_file.exists() {
            return Ok(());
        }

        let temp_target = sibling_restore_temp_path(target)?;
        if temp_target.exists() {
            return Err(UpgradeError::RestoreCollision(temp_target));
        }
        std::fs::copy(backup_file, &temp_target)?;
        self.preserve_existing_path(target)?;
        std::fs::rename(&temp_target, target)?;
        Ok(())
    }

    fn restore_directory_from_backup(
        &self,
        backup_dir: &Path,
        target: &Path,
    ) -> Result<(), UpgradeError> {
        if !backup_dir.exists() {
            return Ok(());
        }

        let temp_target = sibling_restore_temp_path(target)?;
        if temp_target.exists() {
            return Err(UpgradeError::RestoreCollision(temp_target));
        }
        Self::copy_directory_recursive(backup_dir, &temp_target)?;
        self.preserve_existing_path(target)?;
        std::fs::rename(&temp_target, target)?;
        Ok(())
    }

    fn preserve_existing_path(&self, path: &Path) -> Result<(), UpgradeError> {
        if !path.exists() {
            return Ok(());
        }

        let preserved = preserved_restore_path(path)?;
        std::fs::rename(path, &preserved)?;
        Ok(())
    }
}

fn unix_time_secs() -> Result<u64, UpgradeError> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs())
}

fn matches_simple_exclude_pattern(file_name: &str, pattern: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix('*') {
        return file_name.ends_with(suffix);
    }
    file_name == pattern
}

fn sibling_restore_temp_path(path: &Path) -> Result<PathBuf, UpgradeError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| UpgradeError::InvalidRestoreTarget(path.to_path_buf()))?;
    Ok(parent.join(format!(".{file_name}.restore-tmp-{}", unix_time_secs()?)))
}

fn preserved_restore_path(path: &Path) -> Result<PathBuf, UpgradeError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| UpgradeError::InvalidRestoreTarget(path.to_path_buf()))?;
    let timestamp = unix_time_secs()?;

    for index in 0..1000 {
        let candidate = parent.join(format!("{file_name}.pre-rollback-{timestamp}-{index}"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(UpgradeError::RestoreCollision(
        parent.join(format!("{file_name}.pre-rollback-{timestamp}")),
    ))
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

    #[error("Clock error: {0}")]
    ClockError(String),

    #[error("Backup not found: {0}")]
    BackupNotFound(String),

    #[error("Invalid rollback restore target: {0}")]
    InvalidRestoreTarget(PathBuf),

    #[error("Rollback restore path already exists: {0}")]
    RestoreCollision(PathBuf),

    #[error("Unsupported downgrade from {current} to {target}")]
    UnsupportedDowngrade { current: Version, target: Version },

    #[error("Unsupported major version skip from {current} to {target}")]
    UnsupportedMajorSkip { current: Version, target: Version },

    #[error("Migration failed: {0}")]
    MigrationFailed(String),

    #[error("Daemon error: {0}")]
    DaemonError(String),
}

impl From<ConfigError> for UpgradeError {
    fn from(e: ConfigError) -> Self {
        Self::ConfigError(e.to_string())
    }
}

impl From<SystemTimeError> for UpgradeError {
    fn from(e: SystemTimeError) -> Self {
        Self::ClockError(format!("system clock is before UNIX_EPOCH: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn install_config(root: &Path, version: Version) -> AtpInstallConfig {
        AtpInstallConfig {
            schema_version: ConfigVersion::current(),
            version: Some(version),
            identity_path: root.join("identity.key"),
            inbox_dir: root.join("inbox"),
            peer_dir: root.join("peers"),
            daemon_state_dir: root.join("daemon"),
            receive_safety_policy: crate::cli::atp_config::ReceiveSafetyPolicy::AlwaysAsk,
            proof_retention_policy: crate::cli::atp_config::ProofRetentionPolicy::Days(30),
            enable_tailscale: false,
            allow_relays: true,
            logging_level: "info".to_string(),
            service_platform: "test".to_string(),
            service_daemon_enabled: false,
            service_auto_start: false,
        }
    }

    fn write_install_config(root: &Path, version: Version) {
        install_config(root, version)
            .write_to_file(&root.join("config.toml"))
            .expect("write install config");
    }

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
        let manager = UpgradeManager::new(temp_dir.path().to_path_buf()).unwrap();

        // Create some test files
        write_install_config(temp_dir.path(), Version::new(0, 2, 0));

        let backup_id = manager.create_backup().unwrap();
        assert!(!backup_id.is_empty());

        let backup_path = manager.backup_dir.join(&backup_id);
        assert!(backup_path.exists());
        assert!(backup_path.join("metadata.json").exists());
    }

    #[test]
    fn backup_metadata_records_installed_version_not_binary_version() {
        let temp_dir = TempDir::new().unwrap();
        let manager = UpgradeManager::new(temp_dir.path().to_path_buf()).unwrap();
        let installed = Version::new(0, 2, 0);
        write_install_config(temp_dir.path(), installed.clone());

        let backup_id = manager.create_backup().expect("backup");
        let metadata = manager
            .read_backup_metadata(&backup_id)
            .expect("backup metadata");

        assert_eq!(metadata.version, installed);
    }

    #[test]
    fn upgrade_rejects_downgrade_before_creating_backup() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = UpgradeManager::new(temp_dir.path().to_path_buf()).unwrap();
        write_install_config(temp_dir.path(), Version::new(0, 2, 0));

        let err = manager
            .upgrade(Some(Version::new(0, 1, 0)))
            .expect_err("downgrade should be rejected");

        assert!(matches!(err, UpgradeError::UnsupportedDowngrade { .. }));
        assert_eq!(
            std::fs::read_dir(&manager.backup_dir).unwrap().count(),
            0,
            "invalid upgrade paths should not create backup side effects"
        );
    }

    #[test]
    fn selective_backup_excludes_only_matching_suffix_logs() {
        let temp_dir = TempDir::new().unwrap();
        let src = temp_dir.path().join("daemon-src");
        let dst = temp_dir.path().join("daemon-dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("worker.log"), "skip").unwrap();
        std::fs::write(src.join("dialog.txt"), "keep").unwrap();

        UpgradeManager::copy_directory_selective(&src, &dst, &["*.log"]).expect("selective copy");

        assert!(!dst.join("worker.log").exists());
        assert_eq!(
            std::fs::read_to_string(dst.join("dialog.txt")).unwrap(),
            "keep"
        );
    }

    #[test]
    fn rollback_preserves_existing_directories_before_restore() {
        let temp_dir = TempDir::new().unwrap();
        let manager = UpgradeManager::new(temp_dir.path().to_path_buf()).unwrap();
        let backup_id = "0.2.0_100";
        let backup_path = manager.backup_dir.join(backup_id);
        std::fs::create_dir_all(backup_path.join("peers")).unwrap();
        std::fs::write(backup_path.join("peers").join("restored.peer"), "restored").unwrap();
        let metadata = BackupMetadata {
            backup_id: backup_id.to_string(),
            version: Version::new(0, 2, 0),
            timestamp: SystemTime::now(),
            schema_version: ConfigVersion::current(),
            size_bytes: 1,
        };
        std::fs::write(
            backup_path.join("metadata.json"),
            serde_json::to_string_pretty(&metadata).unwrap(),
        )
        .unwrap();

        let peers_dir = temp_dir.path().join("peers");
        std::fs::create_dir_all(&peers_dir).unwrap();
        std::fs::write(peers_dir.join("current.peer"), "current").unwrap();

        manager.restore_from_backup(backup_id).expect("restore");

        assert_eq!(
            std::fs::read_to_string(peers_dir.join("restored.peer")).unwrap(),
            "restored"
        );
        let preserved_peer_dir = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("peers.pre-rollback-"))
            })
            .expect("preserved current peers directory");
        assert_eq!(
            std::fs::read_to_string(preserved_peer_dir.join("current.peer")).unwrap(),
            "current"
        );
    }
}
