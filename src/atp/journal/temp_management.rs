//! Temporary File and Path Management for Sparse Writer Operations

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_SAFE_FILENAME_COMPONENT_LEN: usize = 96;

static NEXT_MANAGER_ID: AtomicU64 = AtomicU64::new(1);

/// Internal creation failure, retaining the writer's existing error taxonomy.
#[derive(Debug)]
pub(crate) enum TempFileCreationError {
    Path(TempManagementError),
    Open(std::io::Error),
}

/// Manager for temporary file paths and lifecycle
pub struct TempPathManager {
    /// Base directory for temporary files
    base_dir: PathBuf,
    /// Quarantine directory for failed operations
    quarantine_dir: PathBuf,
    /// A final filename must never be acquired as private staging, even absent.
    protected_file_name: Option<OsString>,
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
    /// Creation permissions for new directories (Unix only), filtered by umask.
    /// Existing destinations and quarantine directories are never chmoded.
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

    /// Prepare the normal manager while excluding this writer's final filename
    /// from exclusive staging acquisition. Neither existence nor uniqueness
    /// proves that an absent name is private rather than a public destination.
    pub(crate) fn for_destination(final_path: &Path) -> Self {
        let parent = final_path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut manager = Self::new(parent);
        manager.protected_file_name = final_path.file_name().map(OsString::from);
        manager
    }

    /// Create with custom configuration
    pub fn with_config(base_dir: impl AsRef<Path>, config: TempManagementConfig) -> Self {
        let base_dir = base_dir.as_ref().to_path_buf();
        let quarantine_dir = base_dir.join(".quarantine");

        let manager = Self {
            base_dir,
            quarantine_dir,
            protected_file_name: None,
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
        let temp_path = self.next_temp_path(operation_id)?;
        self.track_temp_path(&temp_path, operation_id);
        Ok(temp_path)
    }

    fn next_temp_path(&self, operation_id: &str) -> Result<PathBuf, TempManagementError> {
        if self.active_temps.len() >= self.config.max_active_temps {
            return Err(TempManagementError::TooManyTempFiles);
        }
        Ok(self.base_dir.join(self.generate_temp_filename(operation_id)?))
    }

    fn track_temp_path(&mut self, temp_path: &Path, operation_id: &str) {
        let temp_info = TempFileInfo {
            created_at: SystemTime::now(),
            operation_id: operation_id.to_string(),
            state: PathState::Creating,
            size: None,
            committed: false,
            quarantine_reason: None,
        };

        self.active_temps.insert(temp_path.to_path_buf(), temp_info);
    }

    /// Acquire a new staging inode and retain the same descriptor for its writer.
    /// Name collisions never authorize opening, deleting, or tracking another
    /// file. Creation modes apply before the first payload byte, subject to umask.
    pub(crate) fn create_temp_file(
        &mut self,
        operation_id: &str,
    ) -> Result<(PathBuf, fs::File), TempFileCreationError> {
        let permissions = self.config.temp_file_permissions;
        self.create_temp_file_with(operation_id, |path| Self::open_new_file(path, permissions))
    }

    fn open_new_file(path: &Path, permissions: Option<u32>) -> std::io::Result<fs::File> {
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            if let Some(mode) = permissions {
                options.mode(mode);
            }
        }
        #[cfg(not(unix))]
        let _ = permissions;
        options.open(path)
    }

    // The existing opener seam retains its semantics. Production always uses
    // ordinary name generation and exclusive creation, without user callbacks.
    fn create_temp_file_with(
        &mut self,
        operation_id: &str,
        open: impl FnMut(&Path) -> std::io::Result<fs::File>,
    ) -> Result<(PathBuf, fs::File), TempFileCreationError> {
        self.create_temp_file_from(
            operation_id,
            |manager| manager.next_temp_path(operation_id),
            open,
        )
    }

    // A separate candidate supplier makes destination collisions deterministic
    // in tests without relying on a clock tick or changing the production names.
    fn create_temp_file_from(
        &mut self,
        operation_id: &str,
        mut next: impl FnMut(&Self) -> Result<PathBuf, TempManagementError>,
        mut open: impl FnMut(&Path) -> std::io::Result<fs::File>,
    ) -> Result<(PathBuf, fs::File), TempFileCreationError> {
        for _ in 0..8 {
            let path = next(self).map_err(TempFileCreationError::Path)?;
            if self.is_protected_destination(&path) {
                // Check BEFORE the opener. create_new alone would happily
                // create an absent final path and expose unfinished payload.
                continue;
            }
            match open(&path) {
                Ok(file) => {
                    // Do not track unowned collision paths: stale cleanup must
                    // never treat those names as this manager's discarded work.
                    self.track_temp_path(&path, operation_id);
                    return Ok((path, file));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(TempFileCreationError::Open(error)),
            }
        }
        Err(TempFileCreationError::Open(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "staging file creation exhausted eight name attempts",
        )))
    }

    fn is_protected_destination(&self, path: &Path) -> bool {
        match (&self.protected_file_name, path.file_name()) {
            (Some(protected), Some(candidate)) => {
                // Generated names are ASCII. Conservatively exclude ASCII case
                // variants too, including when the host filesystem folds case.
                // This is not a general path-alias or parent-race confinement.
                candidate.as_encoded_bytes().eq_ignore_ascii_case(protected.as_encoded_bytes())
            }
            _ => false,
        }
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

    /// Get statistics about temporary path usage
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
        // The destination may be an existing user/shared directory. Creating a
        // writer is not permission to replace that directory's access policy.
        self.create_directory(&self.base_dir)
            .map_err(|e| TempManagementError::DirectoryCreation(e.to_string()))?;

        if self.config.auto_create_quarantine {
            self.ensure_quarantine_dir()?;
        }

        Ok(())
    }

    fn ensure_quarantine_dir(&self) -> Result<(), TempManagementError> {
        self.create_directory(&self.quarantine_dir)
            .map_err(|e| TempManagementError::QuarantineDirectoryCreation(e.to_string()))
    }

    fn create_directory(&self, path: &Path) -> std::io::Result<()> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            if let Some(mode) = self.config.temp_dir_permissions {
                // Apply permissions at creation, not through a later pathname
                // chmod. The same mode covers newly created ancestors. Existing
                // directories, including those created by another concurrent
                // manager, retain their permissions and the process umask wins.
                builder.mode(mode);
            }
        }
        // Do not use exists()+chmod: it can both reconfigure an unrelated
        // directory and follow a pathname replaced after the existence check.
        // This remains ordinary path-based creation, not path confinement.
        builder.create(path)
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

#[cfg(test)]
#[path = "temp_directory_tests.rs"]
mod directory_tests;

#[cfg(test)]
mod destination_tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn absent_destination_is_skipped_before_open_for_both_staging_roles() {
        for operation in ["original-object", "verified-publication"] {
            for upper_case in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let final_path = root.path().join("atp_sparse.123.4.5.6.object.tmp");
                let mut manager = TempPathManager::for_destination(&final_path);
                let candidate = if upper_case {
                    root.path().join("ATP_SPARSE.123.4.5.6.OBJECT.TMP")
                } else {
                    final_path.clone()
                };
                let private = root.path().join("private-copy.tmp");
                let mut names = [candidate.clone(), private.clone()].into_iter();
                let opens = Cell::new(0);
                let (path, file) = manager.create_temp_file_from(
                    operation,
                    |_| Ok(names.next().expect("two candidates suffice")),
                    |path| {
                        opens.set(opens.get() + 1);
                        assert_eq!(path, private);
                        assert!(!final_path.exists());
                        TempPathManager::open_new_file(path, Some(0o600))
                    },
                ).unwrap();
                assert_eq!(opens.get(), 1);
                assert_eq!(path, private);
                assert!(!final_path.exists());
                assert!(!candidate.exists());
                assert!(manager.get_temp_info(&candidate).is_none());
                assert_eq!(manager.list_active_temps(), vec![&private]);
                assert_eq!(file.metadata().unwrap().len(), 0);
            }
        }
    }

    #[test]
    fn eight_protected_candidates_exhaust_without_any_file_or_ownership() {
        let root = tempfile::tempdir().unwrap();
        let final_path = root.path().join("reserved.tmp");
        let mut manager = TempPathManager::for_destination(&final_path);
        let attempts = Cell::new(0);
        let result = manager.create_temp_file_from(
            "verified-publication",
            |_| {
                attempts.set(attempts.get() + 1);
                Ok(final_path.clone())
            },
            |_| panic!("protected destination reached the opener"),
        );
        assert!(matches!(result, Err(TempFileCreationError::Open(error))
            if error.kind() == std::io::ErrorKind::AlreadyExists));
        assert_eq!(attempts.get(), 8);
        assert!(manager.list_active_temps().is_empty());
        assert!(!final_path.exists());
        // Exclusion does not consume tracked-file capacity or disable normal use.
        manager.config.max_active_temps = 1;
        let (private, _file) = manager.create_temp_file("ordinary").unwrap();
        assert_ne!(private, final_path);
        assert_eq!(manager.list_active_temps().len(), 1);
    }

    #[test]
    fn excluded_names_and_existing_collisions_never_become_cleanup_targets() {
        let root = tempfile::tempdir().unwrap();
        let final_path = root.path().join("destination.tmp");
        let occupied = root.path().join("occupied.tmp");
        let private = root.path().join("private.tmp");
        fs::write(&occupied, b"not owned by the writer").unwrap();
        let mut manager = TempPathManager::for_destination(&final_path);
        let mut names = [final_path.clone(), occupied.clone(), private.clone()].into_iter();
        let opens = Cell::new(0);
        let (path, file) = manager.create_temp_file_from(
            "original-object",
            |_| Ok(names.next().expect("three candidates suffice")),
            |path| {
                opens.set(opens.get() + 1);
                TempPathManager::open_new_file(path, Some(0o600))
            },
        ).unwrap();
        assert_eq!(opens.get(), 2);
        assert_eq!(path, private);
        assert_eq!(manager.list_active_temps(), vec![&private]);
        drop(file);
        manager.active_temps.get_mut(&private).unwrap().created_at = UNIX_EPOCH;
        let cleaned = manager.cleanup_stale_files().unwrap();
        assert_eq!(cleaned.len(), 1);
        assert_eq!(fs::read(occupied).unwrap(), b"not owned by the writer");
        assert!(!final_path.exists());
        assert!(manager.list_active_temps().is_empty());
    }

    #[test]
    fn destination_reservation_preserves_capacity_refusal_and_default_manager_behavior() {
        let root = tempfile::tempdir().unwrap();
        let final_path = root.path().join("destination.tmp");
        let mut manager = TempPathManager::for_destination(&final_path);
        assert_eq!(manager.base_dir, root.path());
        assert!(manager.is_protected_destination(&final_path));
        manager.config.max_active_temps = 0;
        assert!(matches!(manager.create_temp_file_with("original-object",
            |_| panic!("zero capacity reached opener")),
            Err(TempFileCreationError::Path(TempManagementError::TooManyTempFiles))));
        assert!(manager.list_active_temps().is_empty());
        assert!(!final_path.exists());
        let ordinary = TempPathManager::new(root.path());
        assert!(!ordinary.is_protected_destination(&final_path));
    }
}
