    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_first_run_setup_creation() {
        let setup = FirstRunSetup::new();
        assert!(setup.is_ok());

        let setup = setup.unwrap();
        assert!(!setup.config_dir.as_os_str().is_empty());
        assert!(!setup.inbox_dir.as_os_str().is_empty());
    }

    #[test]
    fn test_service_platform_detection() {
        let integration = ServiceIntegration::detect_platform();
        assert!(integration.is_ok());

        let integration = integration.unwrap();
        assert!(!integration.start_command().is_empty());
        assert!(!integration.stop_command().is_empty());
    }

    #[test]
    fn test_directory_creation() {
        let temp_dir = TempDir::new().unwrap();
        let mut setup = FirstRunSetup::new().unwrap();
        setup.config_dir = temp_dir.path().join("atp");
        setup.inbox_dir = temp_dir.path().join("inbox");
        setup.peer_dir = setup.config_dir.join("peers");
        setup.daemon_state_dir = setup.config_dir.join("daemon");

        let result = setup.create_directories();
        assert!(result.is_ok());

        assert!(setup.config_dir.exists());
        assert!(setup.inbox_dir.exists());
        assert!(setup.peer_dir.exists());
        assert!(setup.daemon_state_dir.exists());
    }

    #[test]
    fn initialize_configuration_writes_install_config_and_reuses_identity() {
        let temp_dir = TempDir::new().unwrap();
        let mut setup = FirstRunSetup::new().unwrap();
        setup.config_dir = temp_dir.path().join("atp");
        setup.inbox_dir = temp_dir.path().join("inbox");
        setup.identity_path = setup.config_dir.join("identity.key");
        setup.peer_dir = setup.config_dir.join("peers");
        setup.daemon_state_dir = setup.config_dir.join("daemon");
        setup.service_integration.enable_daemon = false;
        setup.create_directories().unwrap();

        let first = setup.initialize_configuration().unwrap();
        let second = setup.initialize_configuration().unwrap();
        let config = AtpInstallConfig::read_from_file(&first.config_path).unwrap();

        assert_eq!(first.identity_fingerprint, second.identity_fingerprint);
        assert_eq!(config.schema_version, ConfigVersion::current());
        assert_eq!(config.identity_path, setup.identity_path);
        assert_eq!(config.inbox_dir, setup.inbox_dir);
        assert!(first.config_path.exists());
    }

    /// Test that all completion assets referenced in generate_shell_completions exist.
    /// This prevents compilation failures when include_str! references missing files.
    #[test]
    fn test_completion_assets_exist() {
        // Test that all completion assets referenced in the code exist
        // This prevents the compilation failure described in asupersync-qbim6h

        // These are the files referenced by include_str! in generate_shell_completions
        let completion_files = [
            "completion/atp.bash",
            "completion/atp.zsh",
            "completion/atp.fish",
        ];

        for file_path in &completion_files {
            let full_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/cli")
                .join(file_path);

            assert!(
                full_path.exists(),
                "Completion asset {} does not exist at {}. This will cause compilation failure when first_run.rs is built.",
                file_path,
                full_path.display()
            );

            // Also verify the file is not empty
            let content = std::fs::read_to_string(&full_path)
                .unwrap_or_else(|_| panic!("Failed to read completion asset {}", file_path));

            assert!(
                !content.trim().is_empty(),
                "Completion asset {} exists but is empty. This may cause runtime issues.",
                file_path
            );
        }
    }
