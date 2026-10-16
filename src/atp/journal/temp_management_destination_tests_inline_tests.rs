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
