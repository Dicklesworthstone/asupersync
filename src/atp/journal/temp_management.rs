//! Temporary File and Path Management for Sparse Writer Operations

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_SAFE_FILENAME_COMPONENT_LEN: usize = 96;

static NEXT_MANAGER_ID: AtomicU64 = AtomicU64::new(1);

/// Manager for temporary file paths and lifecycle
pub struct TempPathManager {
    /// Base directory for temporary files
    base_dir: PathBuf,
    /// Quarantine directory for failed operations
    quarantine_dir: PathBuf,
    /// Process-unique manager identifier included in generated names
    manager_id: u64,
    /// Counter for unique temp file generation
    counter: AtomicU64,
    /// Active temporary files being tracked
    active_temps: HashMap<PathBuf, TempFileInfo>,
    /// Configuration for temp file management
    config: TempManagementConfig,
}

/// Configuration for temporary file management
#[derive(Debug, Clone)]
pub struct TempManagementConfig {
    /// Prefix for temporary files
    pub temp_prefix: String,
    /// Maximum age before temp files are considered stale
    pub max_temp_age: std::time::Duration,
    /// Maximum number of temp files to track
    pub max_active_temps: usize,
    /// Whether to use process ID in temp names
    pub include_pid_in_name: bool,
    /// Whether to create quarantine directory automatically
    pub auto_create_quarantine: bool,
    /// Permissions for temporary files (Unix only)
    pub temp_file_permissions: Option<u32>,
    /// Permissions for temporary directories (Unix only)
    pub temp_dir_permissions: Option<u32>,
}

impl Default for TempManagementConfig {
    fn default() -> Self {
        Self {
            temp_prefix: "atp_sparse".to_string(),
            max_temp_age: std::time::Duration::from_hours(24),
            max_active_temps: 1000,
            include_pid_in_name: true,
            auto_create_quarantine: true,
            temp_file_permissions: Some(0o600), // rw-------
            temp_dir_permissions: Some(0o700),  // rwx------
        }
    }
}

/// Information about a temporary file being managed
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TempFileInfo {
    /// When the temp file was created
    created_at: SystemTime,
    /// Associated object ID or operation
    operation_id: String,
    /// Current state of the temp file
    state: PathState,
    /// Size of the temp file if known
    size: Option<u64>,
    /// Whether the file has been committed
    committed: bool,
    /// Reason for quarantine if applicable
    quarantine_reason: Option<String>,
}

/// Public snapshot of a managed temporary file.
#[derive(Debug, Clone)]
pub struct TempFileSnapshot {
    /// When the temp file was created
    pub created_at: SystemTime,
    /// Associated object ID or operation
    pub operation_id: String,
    /// Current state of the temp file
    pub state: PathState,
    /// Size of the temp file if known
    pub size: Option<u64>,
    /// Whether the file has been committed
    pub committed: bool,
    /// Reason for quarantine if applicable
    pub quarantine_reason: Option<String>,
}

impl TempFileInfo {
    fn snapshot(&self) -> TempFileSnapshot {
        TempFileSnapshot {
            created_at: self.created_at,
            operation_id: self.operation_id.clone(),
            state: self.state.clone(),
            size: self.size,
            committed: self.committed,
            quarantine_reason: self.quarantine_reason.clone(),
        }
    }
}

/// Current state of a temporary file path
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathState {
    /// File is being created/written
    Creating,
    /// File is being actively written to
    Writing,
    /// File is being verified
    Verifying,
    /// File is ready for commit
    ReadyToCommit,
    /// File is being committed
    Committing,
    /// File has been successfully committed
    Committed,
    /// File is being quarantined due to failure
    Quarantining,
    /// File has been quarantined
    Quarantined { reason: String },
    /// File is being cleaned up
    CleaningUp,
    /// File has been cleaned up
    CleanedUp,
}

/// Reason for quarantining a file
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineReason {
    /// Write operation was cancelled
    Cancelled,
    /// Verification failed
    VerificationFailed,
    /// Commit operation failed
    CommitFailed,
    /// Corruption detected
    CorruptionDetected,
    /// File became too old without completion
    StaleFile,
    /// User-requested quarantine
    UserRequested,
    /// System error occurred
    SystemError(String),
}

impl QuarantineReason {
    /// Get human-readable description
    pub fn description(&self) -> String {
        match self {
            Self::Cancelled => "Operation was cancelled".to_string(),
            Self::VerificationFailed => "Verification failed".to_string(),
            Self::CommitFailed => "Commit operation failed".to_string(),
            Self::CorruptionDetected => "Data corruption detected".to_string(),
            Self::StaleFile => "File became stale without completion".to_string(),
            Self::UserRequested => "User requested quarantine".to_string(),
            Self::SystemError(msg) => format!("System error: {}", msg),
        }
    }

    /// Get severity level (0 = info, 100 = critical)
    pub fn severity(&self) -> u8 {
        match self {
            Self::Cancelled => 20,
            Self::UserRequested => 30,
            Self::StaleFile => 40,
            Self::CommitFailed => 60,
            Self::VerificationFailed => 70,
            Self::SystemError(_) => 80,
            Self::CorruptionDetected => 100,
        }
    }
}

impl TempPathManager {
    /// Create a new temporary path manager
    pub fn new(base_dir: impl AsRef<Path>) -> Self {
        Self::with_config(base_dir, TempManagementConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(base_dir: impl AsRef<Path>, config: TempManagementConfig) -> Self {
        let base_dir = base_dir.as_ref().to_path_buf();
        let quarantine_dir = base_dir.join(".quarantine");

        let manager = Self {
            base_dir,
            quarantine_dir,
            manager_id: NEXT_MANAGER_ID.fetch_add(1, Ordering::Relaxed),
            counter: AtomicU64::new(1),
            active_temps: HashMap::new(),
            config,
        };

        // Create directories if needed
        manager.ensure_directories().ok();

        manager
    }

    /// Create a new temporary file path
    pub fn create_temp_path(&mut self, operation_id: &str) -> Result<PathBuf, TempManagementError> {
        // Check limits
        if self.active_temps.len() >= self.config.max_active_temps {
            return Err(TempManagementError::TooManyTempFiles);
        }

        // Generate unique filename
        let filename = self.generate_temp_filename(operation_id)?;
        let temp_path = self.base_dir.join(filename);

        // Track the new temp file
        let temp_info = TempFileInfo {
            created_at: SystemTime::now(),
            operation_id: operation_id.to_string(),
            state: PathState::Creating,
            size: None,
            committed: false,
            quarantine_reason: None,
        };

        self.active_temps.insert(temp_path.clone(), temp_info);

        Ok(temp_path)
    }

    /// Update the state of a temporary file
    pub fn update_temp_state(
        &mut self,
        path: &Path,
        state: PathState,
    ) -> Result<(), TempManagementError> {
        match self.active_temps.get_mut(path) {
            Some(info) => {
                info.state = state;
                Ok(())
            }
            None => Err(TempManagementError::TempFileNotFound(path.to_path_buf())),
        }
    }

    /// Update the size of a temporary file
    pub fn update_temp_size(&mut self, path: &Path, size: u64) -> Result<(), TempManagementError> {
        match self.active_temps.get_mut(path) {
            Some(info) => {
                info.size = Some(size);
                Ok(())
            }
            None => Err(TempManagementError::TempFileNotFound(path.to_path_buf())),
        }
    }

    /// Mark a temporary file as committed
    pub fn mark_committed(
        &mut self,
        temp_path: &Path,
        _final_path: &Path,
    ) -> Result<(), TempManagementError> {
        if let Some(info) = self.active_temps.get_mut(temp_path) {
            info.committed = true;
            info.state = PathState::Committed;
        }

        // Remove from active tracking
        self.active_temps.remove(temp_path);

        Ok(())
    }

    /// Quarantine a temporary file
    pub fn quarantine_file(
        &mut self,
        temp_path: &Path,
        reason: &str,
    ) -> Result<PathBuf, TempManagementError> {
        // Ensure quarantine directory exists
        self.ensure_quarantine_dir()?;

        // Generate quarantine path
        let quarantine_path = self.generate_quarantine_path(temp_path, reason)?;

        // Move file to quarantine
        fs::rename(temp_path, &quarantine_path)
            .map_err(|e| TempManagementError::QuarantineMoveFailed(e.to_string()))?;

        // Update tracking info
        if let Some(info) = self.active_temps.get_mut(temp_path) {
            info.state = PathState::Quarantined {
                reason: reason.to_string(),
            };
            info.quarantine_reason = Some(reason.to_string());
        }

        // Remove from active temps
        self.active_temps.remove(temp_path);

        Ok(quarantine_path)
    }

    /// Clean up a temporary file
    pub fn cleanup_temp_file(&mut self, temp_path: &Path) -> Result<(), TempManagementError> {
        // Remove the file
        if temp_path.exists() {
            fs::remove_file(temp_path)
                .map_err(|e| TempManagementError::CleanupFailed(e.to_string()))?;
        }

        // Update tracking
        if let Some(info) = self.active_temps.get_mut(temp_path) {
            info.state = PathState::CleanedUp;
        }

        // Remove from tracking
        self.active_temps.remove(temp_path);

        Ok(())
    }

    /// Get information about a temporary file
    pub fn get_temp_info(&self, temp_path: &Path) -> Option<TempFileSnapshot> {
        self.active_temps.get(temp_path).map(TempFileInfo::snapshot)
    }

    /// Get list of all active temporary files
    pub fn list_active_temps(&self) -> Vec<&PathBuf> {
        self.active_temps.keys().collect()
    }

    /// Clean up stale temporary files
    pub fn cleanup_stale_files(&mut self) -> Result<Vec<PathBuf>, TempManagementError> {
        let now = SystemTime::now();
        let max_age = self.config.max_temp_age;
        let mut cleaned_files = Vec::new();

        // Find stale files
        let stale_paths: Vec<PathBuf> = self
            .active_temps
            .iter()
            .filter_map(|(path, info)| {
                if let Ok(age) = now.duration_since(info.created_at) {
                    if age > max_age && !info.committed {
                        Some(path.clone())
                    } else {
                        None
                    }
                } else {
                    // File has future timestamp, consider it stale
                    Some(path.clone())
                }
            })
            .collect();

        // Clean up stale files
        for path in stale_paths {
            if path.exists() {
                // Try to quarantine first
                if self.config.auto_create_quarantine {
                    if let Ok(quarantine_path) = self.quarantine_file(&path, "stale_file") {
                        cleaned_files.push(quarantine_path);
                    }
                } else {
                    // Just remove it
                    if self.cleanup_temp_file(&path).is_ok() {
                        cleaned_files.push(path);
                    }
                }
            } else {
                // File already gone, just remove from tracking
                self.active_temps.remove(&path);
                cleaned_files.push(path);
            }
        }

        Ok(cleaned_files)
    }

    /// Get statistics about temporary file usage
    pub fn get_stats(&self) -> TempPathStats {
        let active_count = self.active_temps.len();
        let total_size = self
            .active_temps
            .values()
            .filter_map(|info| info.size)
            .sum();

        let state_counts: HashMap<String, usize> = self
            .active_temps
            .values()
            .map(|info| match &info.state {
                PathState::Creating => "creating".to_string(),
                PathState::Writing => "writing".to_string(),
                PathState::Verifying => "verifying".to_string(),
                PathState::ReadyToCommit => "ready_to_commit".to_string(),
                PathState::Committing => "committing".to_string(),
                PathState::Committed => "committed".to_string(),
                PathState::Quarantining => "quarantining".to_string(),
                PathState::Quarantined { .. } => "quarantined".to_string(),
                PathState::CleaningUp => "cleaning_up".to_string(),
                PathState::CleanedUp => "cleaned_up".to_string(),
            })
            .fold(HashMap::new(), |mut acc, state| {
                *acc.entry(state).or_insert(0) += 1;
                acc
            });

        TempPathStats {
            active_count,
            total_size,
            state_counts,
            base_dir: self.base_dir.clone(),
            quarantine_dir: self.quarantine_dir.clone(),
        }
    }

    // Private helper methods

    fn generate_temp_filename(&self, operation_id: &str) -> Result<String, TempManagementError> {
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let temp_prefix = safe_filename_component(
            &self.config.temp_prefix,
            "atp_sparse",
            MAX_SAFE_FILENAME_COMPONENT_LEN,
        );
        let mut filename = format!(
            "{}.{}.{}.{}",
            temp_prefix, timestamp, self.manager_id, counter
        );

        if self.config.include_pid_in_name {
            let pid = std::process::id();
            filename.push_str(&format!(".{}", pid));
        }

        let safe_operation_id =
            safe_filename_component(operation_id, "operation", MAX_SAFE_FILENAME_COMPONENT_LEN);

        filename.push_str(&format!(".{}.tmp", safe_operation_id));

        Ok(filename)
    }

    fn generate_quarantine_path(
        &self,
        original_path: &Path,
        reason: &str,
    ) -> Result<PathBuf, TempManagementError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let original_name = original_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let safe_original_name =
            safe_filename_component(original_name, "unknown", MAX_SAFE_FILENAME_COMPONENT_LEN);

        let safe_reason =
            safe_filename_component(reason, "quarantine", MAX_SAFE_FILENAME_COMPONENT_LEN);
        let quarantine_name = format!("{}.{}.{}", safe_original_name, safe_reason, timestamp);

        Ok(self.quarantine_dir.join(quarantine_name))
    }

    fn ensure_directories(&self) -> Result<(), TempManagementError> {
        // Create base directory
        if !self.base_dir.exists() {
            fs::create_dir_all(&self.base_dir)
                .map_err(|e| TempManagementError::DirectoryCreation(e.to_string()))?;
        }

        // Set permissions if specified
        #[cfg(unix)]
        {
            if let Some(perms) = self.config.temp_dir_permissions {
                use std::os::unix::fs::PermissionsExt;
                let permissions = fs::Permissions::from_mode(perms);
                fs::set_permissions(&self.base_dir, permissions)
                    .map_err(|e| TempManagementError::PermissionsSetting(e.to_string()))?;
            }
        }

        // Create quarantine directory if auto-create is enabled
        if self.config.auto_create_quarantine {
            self.ensure_quarantine_dir()?;
        }

        Ok(())
    }

    fn ensure_quarantine_dir(&self) -> Result<(), TempManagementError> {
        if !self.quarantine_dir.exists() {
            fs::create_dir_all(&self.quarantine_dir)
                .map_err(|e| TempManagementError::QuarantineDirectoryCreation(e.to_string()))?;

            #[cfg(unix)]
            {
                if let Some(perms) = self.config.temp_dir_permissions {
                    use std::os::unix::fs::PermissionsExt;
                    let permissions = fs::Permissions::from_mode(perms);
                    fs::set_permissions(&self.quarantine_dir, permissions)
                        .map_err(|e| TempManagementError::PermissionsSetting(e.to_string()))?;
                }
            }
        }

        Ok(())
    }
}

fn safe_filename_component(input: &str, fallback: &str, max_len: usize) -> String {
    let mut component = String::new();
    for ch in input.chars() {
        let safe = if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            ch
        } else {
            '_'
        };
        if component.len() >= max_len {
            break;
        }
        component.push(safe);
    }

    if component.is_empty() {
        fallback.to_string()
    } else {
        component
    }
}

/// Statistics about temporary path usage
#[derive(Debug, Clone)]
pub struct TempPathStats {
    /// Number of active temporary files
    pub active_count: usize,
    /// Total size of all tracked temporary files
    pub total_size: u64,
    /// Count of files by state
    pub state_counts: HashMap<String, usize>,
    /// Base directory for temporary files
    pub base_dir: PathBuf,
    /// Quarantine directory
    pub quarantine_dir: PathBuf,
}

/// Errors that can occur during temporary path management
#[derive(Debug, thiserror::Error)]
pub enum TempManagementError {
    #[error("Too many temporary files active")]
    TooManyTempFiles,

    #[error("Temporary file not found: {0}")]
    TempFileNotFound(PathBuf),

    #[error("Directory creation failed: {0}")]
    DirectoryCreation(String),

    #[error("Quarantine directory creation failed: {0}")]
    QuarantineDirectoryCreation(String),

    #[error("Quarantine move failed: {0}")]
    QuarantineMoveFailed(String),

    #[error("Cleanup failed: {0}")]
    CleanupFailed(String),

    #[error("Permissions setting failed: {0}")]
    PermissionsSetting(String),

    #[error("Invalid filename: {0}")]
    InvalidFilename(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn test_temp_path_creation() {
        let temp_dir = std::env::temp_dir().join("atp_test_temp_mgmt");
        let mut manager = TempPathManager::new(&temp_dir);

        let temp_path = manager.create_temp_path("test_operation").unwrap();
        assert!(temp_path.to_string_lossy().contains("atp_sparse"));
        assert!(temp_path.to_string_lossy().contains("test_operation"));

        // Should be tracked
        assert!(manager.get_temp_info(&temp_path).is_some());
        assert_eq!(manager.list_active_temps().len(), 1);

        // Cleanup
        manager.cleanup_temp_file(&temp_path).unwrap();
        assert!(manager.get_temp_info(&temp_path).is_none());

        // Clean up test directory
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_temp_paths_are_unique_across_managers() {
        let temp_dir = std::env::temp_dir().join("atp_test_temp_manager_uniqueness");
        let mut manager_a = TempPathManager::new(&temp_dir);
        let mut manager_b = TempPathManager::new(&temp_dir);

        let temp_a = manager_a.create_temp_path("same_operation").unwrap();
        let temp_b = manager_b.create_temp_path("same_operation").unwrap();

        assert_ne!(temp_a, temp_b);
        assert_eq!(temp_a.parent(), Some(temp_dir.as_path()));
        assert_eq!(temp_b.parent(), Some(temp_dir.as_path()));

        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_quarantine_reason_is_single_safe_path_component() {
        let temp_dir = std::env::temp_dir().join("atp_test_quarantine_reason_safety");
        let mut manager = TempPathManager::new(&temp_dir);

        let temp_path = manager.create_temp_path("quarantine_reason").unwrap();
        File::create(&temp_path).unwrap();

        let quarantine_path = manager
            .quarantine_file(&temp_path, "../../escape/attempt")
            .unwrap();
        assert_eq!(
            quarantine_path.parent(),
            Some(manager.quarantine_dir.as_path())
        );
        let quarantine_name = quarantine_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap();
        assert!(quarantine_name.contains("______escape_attempt"));
        assert!(!quarantine_name.contains('/'));
        assert!(!quarantine_name.contains(".."));

        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_quarantine_original_name_is_single_safe_path_component() {
        let temp_dir = std::env::temp_dir().join("atp_test_quarantine_original_safety");
        let manager = TempPathManager::new(&temp_dir);
        let original_path = PathBuf::from("bad name..\n\t.tmp");

        let quarantine_path = manager
            .generate_quarantine_path(&original_path, "../../escape/attempt")
            .unwrap();
        assert_eq!(
            quarantine_path.parent(),
            Some(manager.quarantine_dir.as_path())
        );
        let quarantine_name = quarantine_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap();
        assert!(quarantine_name.starts_with("bad_name_____tmp."));
        assert!(quarantine_name.contains("______escape_attempt"));
        assert!(!quarantine_name.contains('/'));
        assert!(!quarantine_name.contains(".."));
        assert!(!quarantine_name.contains('\n'));
        assert!(!quarantine_name.contains('\t'));
    }

    #[test]
    fn test_temp_file_states() {
        let temp_dir = std::env::temp_dir().join("atp_test_states");
        let mut manager = TempPathManager::new(&temp_dir);

        let temp_path = manager.create_temp_path("state_test").unwrap();

        // Check initial state
        let info = manager.get_temp_info(&temp_path).unwrap();
        assert_eq!(info.state, PathState::Creating);

        // Update state
        manager
            .update_temp_state(&temp_path, PathState::Writing)
            .unwrap();
        let info = manager.get_temp_info(&temp_path).unwrap();
        assert_eq!(info.state, PathState::Writing);

        // Update size
        manager.update_temp_size(&temp_path, 1024).unwrap();
        let info = manager.get_temp_info(&temp_path).unwrap();
        assert_eq!(info.size, Some(1024));

        // Cleanup
        manager.cleanup_temp_file(&temp_path).unwrap();
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_quarantine_functionality() {
        let temp_dir = std::env::temp_dir().join("atp_test_quarantine");
        let mut manager = TempPathManager::new(&temp_dir);

        let temp_path = manager.create_temp_path("quarantine_test").unwrap();

        // Create the actual file
        File::create(&temp_path).unwrap();

        // Quarantine the file
        let quarantine_path = manager.quarantine_file(&temp_path, "test_reason").unwrap();

        // Original should be gone, quarantine should exist
        assert!(!temp_path.exists());
        assert!(quarantine_path.exists());
        assert!(quarantine_path.to_string_lossy().contains("test_reason"));

        // Should not be in active temps anymore
        assert!(manager.get_temp_info(&temp_path).is_none());

        // Cleanup
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_stale_file_cleanup() {
        let temp_dir = std::env::temp_dir().join("atp_test_stale");
        let mut config = TempManagementConfig::default();
        config.max_temp_age = std::time::Duration::from_millis(1); // Very short age
        config.auto_create_quarantine = false; // Just remove, don't quarantine

        let mut manager = TempPathManager::with_config(&temp_dir, config);

        let temp_path = manager.create_temp_path("stale_test").unwrap();
        File::create(&temp_path).unwrap();

        // Wait for file to become stale
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Clean up stale files
        let cleaned = manager.cleanup_stale_files().unwrap();
        assert_eq!(cleaned.len(), 1);
        assert!(!temp_path.exists());

        // Cleanup
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_quarantine_reason_properties() {
        let cancelled = QuarantineReason::Cancelled;
        assert_eq!(cancelled.severity(), 20);
        assert!(cancelled.description().contains("cancelled"));

        let corruption = QuarantineReason::CorruptionDetected;
        assert_eq!(corruption.severity(), 100);
        assert!(corruption.description().contains("corruption"));
    }

    #[test]
    fn test_stats_collection() {
        let temp_dir = std::env::temp_dir().join("atp_test_stats");
        let mut manager = TempPathManager::new(&temp_dir);

        // Create a few temp files
        let temp1 = manager.create_temp_path("stats_test1").unwrap();
        let temp2 = manager.create_temp_path("stats_test2").unwrap();

        manager.update_temp_size(&temp1, 1024).unwrap();
        manager.update_temp_size(&temp2, 2048).unwrap();
        manager
            .update_temp_state(&temp2, PathState::Writing)
            .unwrap();

        let stats = manager.get_stats();
        assert_eq!(stats.active_count, 2);
        assert_eq!(stats.total_size, 3072);

        // Check state counts
        assert_eq!(stats.state_counts.get("creating"), Some(&1));
        assert_eq!(stats.state_counts.get("writing"), Some(&1));

        // Cleanup
        manager.cleanup_temp_file(&temp1).unwrap();
        manager.cleanup_temp_file(&temp2).unwrap();
        std::fs::remove_dir_all(&temp_dir).ok();
    }
}
