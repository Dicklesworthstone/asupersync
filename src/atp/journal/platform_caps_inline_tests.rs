    use super::*;

    #[test]
    fn test_platform_detection() {
        let cx = crate::cx::Cx::for_testing();
        let caps = futures_lite::future::block_on(PlatformCapabilities::detect(&cx));
        assert!(caps.is_ok());

        let caps = caps.unwrap();

        // Basic sanity checks
        assert!(!caps.filesystem.fs_type.is_empty());
        assert!(caps.filesystem.block_size > 0);
        assert!(caps.io_capabilities.max_io_size > 0);
    }

    #[test]
    fn test_filesystem_feature_detection() {
        let cx = crate::cx::Cx::for_testing();
        let temp_dir = std::env::temp_dir();
        let caps =
            futures_lite::future::block_on(PlatformCapabilities::detect_for_path(&cx, &temp_dir));
        assert!(caps.is_ok());

        let caps = caps.unwrap();

        // Most temp directories should support basic operations
        assert!(caps.atomic_operations.atomic_rename_same_fs);
    }

    #[test]
    fn test_os_type_detection() {
        let os_type = PlatformCapabilities::detect_os_type();

        // Should detect a known OS type in CI
        #[cfg(target_os = "linux")]
        assert_eq!(os_type, OsType::Linux);

        #[cfg(target_os = "macos")]
        assert_eq!(os_type, OsType::MacOS);

        #[cfg(target_os = "windows")]
        assert_eq!(os_type, OsType::Windows);
    }

    #[test]
    fn capability_probe_files_do_not_overwrite_existing_sentinels() {
        let temp_root = std::env::temp_dir();
        let test_dir = PlatformCapabilities::unique_probe_path(&temp_root, "sentinel_dir");
        std::fs::create_dir(&test_dir).unwrap();

        let sentinels = [
            (".atp_prealloc_test", b"keep prealloc sentinel".as_slice()),
            (".atp_link_test1", b"keep link source sentinel".as_slice()),
            (".atp_link_test2", b"keep link target sentinel".as_slice()),
        ];

        for (name, contents) in sentinels {
            std::fs::write(test_dir.join(name), contents).unwrap();
        }

        let _ = PlatformCapabilities::test_preallocation_support(&test_dir);
        let _ = PlatformCapabilities::test_atomic_rename_support(&test_dir);
        let _ = PlatformCapabilities::test_hard_link_support(&test_dir);

        for (name, contents) in sentinels {
            assert_eq!(std::fs::read(test_dir.join(name)).unwrap(), contents);
            std::fs::remove_file(test_dir.join(name)).unwrap();
        }
        std::fs::remove_dir(test_dir).unwrap();
    }
