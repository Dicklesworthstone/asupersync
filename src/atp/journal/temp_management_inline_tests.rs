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
