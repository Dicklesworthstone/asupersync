    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_capability_validation() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        std::fs::write(&config_path, "# test config").unwrap();

        let controller = SecureDaemonController::new(
            RegionId::new_for_test(1, 0),
            vec![DaemonControlCapability::Status],
            std::env::current_exe().unwrap(),
            config_path,
        )
        .unwrap();

        // Status capability should work
        assert!(
            controller
                .require_capability(DaemonControlCapability::Status)
                .is_ok()
        );

        // Start capability should fail
        assert!(
            controller
                .require_capability(DaemonControlCapability::Start)
                .is_err()
        );
    }

    #[test]
    fn test_daemon_controller_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        std::fs::write(&config_path, "# test config").unwrap();

        let controller = SecureDaemonController::new(
            RegionId::new_for_test(1, 0),
            vec![
                DaemonControlCapability::Status,
                DaemonControlCapability::Start,
            ],
            std::env::current_exe().unwrap(),
            config_path,
        );

        assert!(controller.is_ok());
    }

    #[test]
    fn test_invalid_daemon_path() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        std::fs::write(&config_path, "# test config").unwrap();

        let controller = SecureDaemonController::new(
            RegionId::new_for_test(1, 0),
            vec![DaemonControlCapability::Status],
            PathBuf::from("/nonexistent/daemon"),
            config_path,
        );

        assert!(controller.is_err());
    }

    #[test]
    fn windows_executable_extension_matching_uses_pathext_semantics() {
        assert!(path_has_windows_executable_extension(
            Path::new("atpd.ExE"),
            Some(std::ffi::OsStr::new(".COM;.EXE;.BAT;.CMD"))
        ));
        assert!(path_has_windows_executable_extension(
            Path::new("atpd.cmd"),
            Some(std::ffi::OsStr::new("EXE;CMD"))
        ));
        assert!(!path_has_windows_executable_extension(
            Path::new("atpd.sh"),
            Some(std::ffi::OsStr::new(".COM;.EXE;.BAT;.CMD"))
        ));
        assert!(!path_has_windows_executable_extension(
            Path::new("atpd"),
            Some(std::ffi::OsStr::new(".COM;.EXE;.BAT;.CMD"))
        ));
    }

    #[test]
    fn test_atp_daemon_controller_factory() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        std::fs::write(&config_path, "# test config").unwrap();

        let controller = create_atp_daemon_controller(
            RegionId::new_for_test(1, 0),
            vec![DaemonControlCapability::Status],
            temp_dir.path(),
        );

        assert!(controller.is_ok());
    }
