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
