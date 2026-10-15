//! Commit Policies for Atomic Operations and Durability Guarantees

use std::path::Path;

/// Policy for when to perform fsync operations
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FsyncPolicy {
    /// Never fsync (fastest, least durable)
    Never,
    /// Fsync after every write operation
    EveryWrite,
    /// Fsync only verified chunks
    #[default]
    VerifiedChunks,
    /// Fsync only before final commit
    BeforeCommit,
}

impl FsyncPolicy {
    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::Never => "No fsync - fastest but no durability guarantees",
            Self::EveryWrite => "Fsync after every write - slowest but most durable",
            Self::VerifiedChunks => "Fsync only verified chunks - balanced approach",
            Self::BeforeCommit => "Fsync before commit - good durability with performance",
        }
    }

    /// Get relative performance impact (0 = fastest, 100 = slowest)
    pub fn performance_impact(&self) -> u8 {
        match self {
            Self::Never => 0,
            Self::BeforeCommit => 20,
            Self::VerifiedChunks => 50,
            Self::EveryWrite => 100,
        }
    }

    /// Get durability guarantees level (0 = none, 100 = strongest)
    pub fn durability_level(&self) -> u8 {
        match self {
            Self::Never => 0,
            Self::BeforeCommit => 70,
            Self::VerifiedChunks => 85,
            Self::EveryWrite => 100,
        }
    }
}

/// Policy for atomic commit operations
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CommitPolicy {
    /// Atomic rename (POSIX guarantee within same filesystem)
    #[default]
    AtomicRename,
    /// Copy then verify integrity
    CopyAndVerify,
    /// Hard link then unlink (preserves original)
    LinkAndUnlink,
}

impl CommitPolicy {
    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::AtomicRename => "Atomic rename - fastest, requires same filesystem",
            Self::CopyAndVerify => "Copy and verify - safe across filesystems",
            Self::LinkAndUnlink => "Hard link then unlink - preserves original during operation",
        }
    }

    /// Check if policy is safe for cross-filesystem operations
    pub fn supports_cross_filesystem(&self) -> bool {
        match self {
            Self::AtomicRename => false,
            Self::CopyAndVerify => true,
            Self::LinkAndUnlink => false, // Hard links don't work across filesystems
        }
    }

    /// Get relative safety level (0 = basic, 100 = maximum safety)
    pub fn safety_level(&self) -> u8 {
        match self {
            Self::AtomicRename => 80,
            Self::LinkAndUnlink => 90,
            Self::CopyAndVerify => 100,
        }
    }

    /// Get relative performance level (0 = slowest, 100 = fastest)
    pub fn performance_level(&self) -> u8 {
        match self {
            Self::CopyAndVerify => 20,
            Self::LinkAndUnlink => 60,
            Self::AtomicRename => 100,
        }
    }
}

/// Atomic operation policy combining fsync and commit strategies
#[derive(Debug, Clone)]
pub struct AtomicPolicy {
    /// When to perform fsync operations
    pub fsync_policy: FsyncPolicy,
    /// How to perform atomic commits
    pub commit_policy: CommitPolicy,
    /// Whether to sync parent directories
    pub sync_parent_dir: bool,
    /// Whether to verify after commit
    pub verify_after_commit: bool,
    /// Maximum retry attempts for failed operations
    pub max_retries: u32,
    /// Backup policy for failed operations
    pub backup_policy: BackupPolicy,
}

impl Default for AtomicPolicy {
    fn default() -> Self {
        Self {
            fsync_policy: FsyncPolicy::default(),
            commit_policy: CommitPolicy::default(),
            sync_parent_dir: true,
            verify_after_commit: false,
            max_retries: 3,
            backup_policy: BackupPolicy::default(),
        }
    }
}

/// Policy for handling backup and rollback scenarios
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BackupPolicy {
    /// No backup, overwrite existing files
    None,
    /// Create backup with timestamp suffix
    Timestamped,
    /// Create backup with .bak suffix
    Suffix,
    /// Move existing to quarantine directory
    #[default]
    Quarantine,
}

impl BackupPolicy {
    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::None => "No backup - overwrite existing files",
            Self::Timestamped => "Create timestamped backup files",
            Self::Suffix => "Create .bak backup files",
            Self::Quarantine => "Move existing files to quarantine directory",
        }
    }

    /// Generate backup filename for the given original path
    pub fn generate_backup_path(&self, original: &Path) -> Option<std::path::PathBuf> {
        match self {
            Self::None => None,
            Self::Timestamped => {
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                Some(original.with_extension(format!("bak.{}", timestamp)))
            }
            Self::Suffix => Some(original.with_extension("bak")),
            Self::Quarantine => {
                let filename = original.file_name()?;
                let parent = original.parent().unwrap_or_else(|| Path::new("."));
                Some(parent.join(".quarantine").join(filename))
            }
        }
    }
}

/// Error recovery policy for various failure scenarios
#[derive(Debug, Clone)]
pub struct ErrorRecoveryPolicy {
    /// How to handle partial write failures
    pub partial_write_recovery: PartialWriteRecovery,
    /// How to handle commit failures
    pub commit_failure_recovery: CommitFailureRecovery,
    /// How to handle verification failures
    pub verification_failure_recovery: VerificationFailureRecovery,
    /// Whether to attempt automatic recovery
    pub enable_auto_recovery: bool,
    /// Maximum time to spend on recovery attempts
    pub recovery_timeout: std::time::Duration,
}

/// Policy for recovering from partial write failures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartialWriteRecovery {
    /// Fail immediately on partial write
    FailFast,
    /// Retry the failed portion
    RetryPartial,
    /// Start over from beginning
    StartOver,
    /// Quarantine and report
    QuarantineAndReport,
}

/// Policy for recovering from commit failures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitFailureRecovery {
    /// Fail and leave temp file
    FailAndLeave,
    /// Retry with different policy
    RetryWithFallback,
    /// Move to quarantine
    MoveToQuarantine,
    /// Report and clean up
    ReportAndCleanup,
}

/// Policy for recovering from verification failures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationFailureRecovery {
    /// Fail immediately
    FailFast,
    /// Quarantine the file
    Quarantine,
    /// Retry verification
    RetryVerification,
    /// Allow with warning
    AllowWithWarning,
}

impl Default for ErrorRecoveryPolicy {
    fn default() -> Self {
        Self {
            partial_write_recovery: PartialWriteRecovery::RetryPartial,
            commit_failure_recovery: CommitFailureRecovery::RetryWithFallback,
            verification_failure_recovery: VerificationFailureRecovery::Quarantine,
            enable_auto_recovery: true,
            recovery_timeout: std::time::Duration::from_secs(30),
        }
    }
}

/// Complete atomic operation configuration
#[derive(Debug, Clone)]
pub struct AtomicOperationConfig {
    /// Core atomic policy
    pub atomic_policy: AtomicPolicy,
    /// Error recovery configuration
    pub recovery_policy: ErrorRecoveryPolicy,
    /// Platform-specific optimizations
    pub platform_optimizations: bool,
    /// Enable detailed operation logging
    pub enable_operation_log: bool,
    /// Custom commit hooks
    pub pre_commit_hooks: Vec<String>,
    /// Post-commit hooks
    pub post_commit_hooks: Vec<String>,
}

impl Default for AtomicOperationConfig {
    fn default() -> Self {
        Self {
            atomic_policy: AtomicPolicy::default(),
            recovery_policy: ErrorRecoveryPolicy::default(),
            platform_optimizations: true,
            enable_operation_log: true,
            pre_commit_hooks: Vec::new(),
            post_commit_hooks: Vec::new(),
        }
    }
}

impl AtomicOperationConfig {
    /// Create a configuration optimized for speed
    pub fn fast_config() -> Self {
        Self {
            atomic_policy: AtomicPolicy {
                fsync_policy: FsyncPolicy::Never,
                commit_policy: CommitPolicy::AtomicRename,
                sync_parent_dir: false,
                verify_after_commit: false,
                max_retries: 1,
                backup_policy: BackupPolicy::None,
            },
            recovery_policy: ErrorRecoveryPolicy {
                partial_write_recovery: PartialWriteRecovery::FailFast,
                commit_failure_recovery: CommitFailureRecovery::FailAndLeave,
                verification_failure_recovery: VerificationFailureRecovery::FailFast,
                enable_auto_recovery: false,
                recovery_timeout: std::time::Duration::from_secs(1),
            },
            platform_optimizations: true,
            enable_operation_log: false,
            pre_commit_hooks: Vec::new(),
            post_commit_hooks: Vec::new(),
        }
    }

    /// Create a configuration optimized for safety
    pub fn safe_config() -> Self {
        Self {
            atomic_policy: AtomicPolicy {
                fsync_policy: FsyncPolicy::EveryWrite,
                commit_policy: CommitPolicy::CopyAndVerify,
                sync_parent_dir: true,
                verify_after_commit: true,
                max_retries: 5,
                backup_policy: BackupPolicy::Quarantine,
            },
            recovery_policy: ErrorRecoveryPolicy {
                partial_write_recovery: PartialWriteRecovery::QuarantineAndReport,
                commit_failure_recovery: CommitFailureRecovery::MoveToQuarantine,
                verification_failure_recovery: VerificationFailureRecovery::Quarantine,
                enable_auto_recovery: true,
                recovery_timeout: std::time::Duration::from_secs(300),
            },
            platform_optimizations: false, // Disable for maximum compatibility
            enable_operation_log: true,
            pre_commit_hooks: Vec::new(),
            post_commit_hooks: Vec::new(),
        }
    }

    /// Create a balanced configuration
    pub fn balanced_config() -> Self {
        Self::default()
    }

    /// Validate configuration consistency
    pub fn validate(&self) -> Result<(), PolicyValidationError> {
        // Check for conflicting policies
        if matches!(self.atomic_policy.fsync_policy, FsyncPolicy::Never)
            && self.atomic_policy.verify_after_commit
        {
            return Err(PolicyValidationError::ConflictingPolicies(
                "Cannot verify after commit without fsync".to_string(),
            ));
        }

        if self.atomic_policy.max_retries > 10 {
            return Err(PolicyValidationError::InvalidConfiguration(
                "Maximum retries should not exceed 10".to_string(),
            ));
        }

        if self.recovery_policy.recovery_timeout.as_secs() > 3600 {
            return Err(PolicyValidationError::InvalidConfiguration(
                "Recovery timeout should not exceed 1 hour".to_string(),
            ));
        }

        Ok(())
    }
}

/// Errors that can occur during policy validation
#[derive(Debug, thiserror::Error)]
pub enum PolicyValidationError {
    #[error("Conflicting policies: {0}")]
    ConflictingPolicies(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Unsupported combination: {0}")]
    UnsupportedCombination(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fsync_policy_properties() {
        let never = FsyncPolicy::Never;
        assert_eq!(never.performance_impact(), 0);
        assert_eq!(never.durability_level(), 0);

        let every_write = FsyncPolicy::EveryWrite;
        assert_eq!(every_write.performance_impact(), 100);
        assert_eq!(every_write.durability_level(), 100);
    }

    #[test]
    fn test_commit_policy_properties() {
        let atomic = CommitPolicy::AtomicRename;
        assert!(!atomic.supports_cross_filesystem());
        assert_eq!(atomic.performance_level(), 100);

        let copy = CommitPolicy::CopyAndVerify;
        assert!(copy.supports_cross_filesystem());
        assert_eq!(copy.safety_level(), 100);
    }

    #[test]
    fn test_backup_policy_path_generation() {
        let original = Path::new("/tmp/test.txt");

        let timestamped = BackupPolicy::Timestamped;
        let backup = timestamped.generate_backup_path(original).unwrap();
        assert!(backup.to_string_lossy().contains("bak."));

        let suffix = BackupPolicy::Suffix;
        let backup = suffix.generate_backup_path(original).unwrap(); // ubs:ignore - test oracle
        assert_eq!(backup, Path::new("/tmp/test.bak"));

        let quarantine = BackupPolicy::Quarantine;
        let backup = quarantine.generate_backup_path(original).unwrap();
        assert_eq!(backup, Path::new("/tmp/.quarantine/test.txt"));

        let none = BackupPolicy::None;
        assert!(none.generate_backup_path(original).is_none());
    }

    #[test]
    fn test_config_validation() {
        // Valid default config
        let config = AtomicOperationConfig::default();
        assert!(config.validate().is_ok());

        // Fast config should be valid
        let fast_config = AtomicOperationConfig::fast_config();
        assert!(fast_config.validate().is_ok());

        // Safe config should be valid
        let safe_config = AtomicOperationConfig::safe_config();
        assert!(safe_config.validate().is_ok());

        // Invalid config with too many retries
        let mut invalid_config = AtomicOperationConfig::default();
        invalid_config.atomic_policy.max_retries = 20;
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_policy_configurations() {
        let fast = AtomicOperationConfig::fast_config();
        assert_eq!(fast.atomic_policy.fsync_policy, FsyncPolicy::Never);
        assert_eq!(fast.atomic_policy.commit_policy, CommitPolicy::AtomicRename);
        assert!(!fast.recovery_policy.enable_auto_recovery);

        let safe = AtomicOperationConfig::safe_config();
        assert_eq!(safe.atomic_policy.fsync_policy, FsyncPolicy::EveryWrite);
        assert_eq!(
            safe.atomic_policy.commit_policy,
            CommitPolicy::CopyAndVerify
        );
        assert!(safe.recovery_policy.enable_auto_recovery);
    }
}
