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
