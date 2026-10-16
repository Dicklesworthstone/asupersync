    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_secure_path_creation() {
        let temp_dir = TempDir::new().unwrap();
        let secure_path = SecurePath::new(temp_dir.path()).unwrap();
        assert_eq!(
            secure_path.base_directory(),
            temp_dir.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn test_invalid_base_directory() {
        let result = SecurePath::new("/nonexistent/directory");
        assert!(result.is_err());
        match result.unwrap_err() {
            PathSecurityError::BaseDirectoryInaccessible { .. } => (),
            other => panic!("Expected BaseDirectoryInaccessible, got {:?}", other),
        }
    }

    #[test]
    fn test_valid_path_validation() {
        let temp_dir = TempDir::new().unwrap();
        let secure_path = SecurePath::new(temp_dir.path()).unwrap();

        let validated = secure_path.validate_path("configs/app.toml").unwrap();
        let expected = temp_dir
            .path()
            .canonicalize()
            .unwrap()
            .join("configs/app.toml");
        assert_eq!(validated.as_path(), expected);
        assert_eq!(validated.original_path(), "configs/app.toml");
    }

    #[test]
    fn test_path_traversal_attack() {
        let temp_dir = TempDir::new().unwrap();
        let secure_path = SecurePath::new(temp_dir.path()).unwrap();

        let result = secure_path.validate_path("../../etc/passwd");
        assert!(result.is_err());
        match result.unwrap_err() {
            PathSecurityError::OutsideAllowedBounds { .. } => (),
            other => panic!("Expected OutsideAllowedBounds, got {:?}", other),
        }
    }

    #[test]
    fn test_empty_path() {
        let temp_dir = TempDir::new().unwrap();
        let secure_path = SecurePath::new(temp_dir.path()).unwrap();

        let result = secure_path.validate_path("");
        assert!(result.is_err());
        match result.unwrap_err() {
            PathSecurityError::InvalidPath { .. } => (),
            other => panic!("Expected InvalidPath, got {:?}", other),
        }
    }

    #[test]
    fn test_null_byte_path() {
        let temp_dir = TempDir::new().unwrap();
        let secure_path = SecurePath::new(temp_dir.path()).unwrap();

        let result = secure_path.validate_path("file\0.txt");
        assert!(result.is_err());
        match result.unwrap_err() {
            PathSecurityError::InvalidPath { .. } => (),
            other => panic!("Expected InvalidPath, got {:?}", other),
        }
    }

    #[test]
    fn test_secure_file_operations() {
        let temp_dir = TempDir::new().unwrap();
        let secure_path = SecurePath::new(temp_dir.path()).unwrap();

        // Test write and read
        let content = "Hello, secure world!";
        secure_path.write_string("test.txt", content).unwrap();
        let read_content = secure_path.read_to_string("test.txt").unwrap();
        assert_eq!(read_content, content);

        // Test bytes operations
        let bytes = b"Binary data";
        secure_path.write_bytes("binary.dat", bytes).unwrap();
        let read_bytes = secure_path.read_bytes("binary.dat").unwrap();
        assert_eq!(read_bytes, bytes);
    }

    #[test]
    fn test_secure_copy_operation() {
        let temp_dir = TempDir::new().unwrap();
        let secure_path = SecurePath::new(temp_dir.path()).unwrap();

        // Create source file
        let content = "File to copy";
        secure_path.write_string("source.txt", content).unwrap();

        // Copy file
        let bytes_copied = secure_path
            .copy_file("source.txt", "destination.txt")
            .unwrap();
        assert!(bytes_copied > 0);

        // Verify copy
        let copied_content = secure_path.read_to_string("destination.txt").unwrap();
        assert_eq!(copied_content, content);
    }

    #[test]
    fn test_directory_creation() {
        let temp_dir = TempDir::new().unwrap();
        let secure_path = SecurePath::new(temp_dir.path()).unwrap();

        // Writing to nested path should create directories
        secure_path
            .write_string("nested/dirs/file.txt", "content")
            .unwrap();

        // Verify the file was created
        let content = secure_path.read_to_string("nested/dirs/file.txt").unwrap();
        assert_eq!(content, "content");
    }

    #[cfg(unix)]
    #[test]
    fn write_preparation_revalidates_parent_after_creation() {
        let temp_dir = TempDir::new().unwrap();
        let outside_dir = TempDir::new().unwrap();
        let secure_path = SecurePath::new(temp_dir.path()).unwrap();
        let validated = secure_path.validate_path("staged/file.txt").unwrap();

        std::os::unix::fs::symlink(outside_dir.path(), temp_dir.path().join("staged")).unwrap();

        let error = secure_path
            .prepare_validated_write_path(&validated)
            .expect_err("parent symlink swap must be rejected");
        match error {
            PathSecurityError::OutsideAllowedBounds { path, allowed_base } => {
                // The reported path is canonical; the temp dir may sit behind
                // a symlinked mount point (macOS /var -> /private/var).
                let outside_canonical = outside_dir
                    .path()
                    .canonicalize()
                    .unwrap_or_else(|_| outside_dir.path().to_path_buf());
                assert!(
                    path.starts_with(&outside_canonical.display().to_string()),
                    "{path} must start with {}",
                    outside_canonical.display()
                );
                assert_eq!(
                    allowed_base,
                    secure_path.base_directory().display().to_string()
                );
            }
            other => panic!("Expected OutsideAllowedBounds, got {:?}", other),
        }
    }

    #[cfg(unix)]
    #[test]
    fn no_follow_write_rejects_final_symlink_swap() {
        let temp_dir = TempDir::new().unwrap();
        let outside_dir = TempDir::new().unwrap();
        let link_path = temp_dir.path().join("target.txt");
        let escaped_path = outside_dir.path().join("escaped.txt");
        std::os::unix::fs::symlink(&escaped_path, &link_path).unwrap();

        let error =
            write_all_no_follow(&link_path, b"blocked").expect_err("symlink write must fail");
        assert_eq!(error.raw_os_error(), Some(libc::ELOOP));
        assert!(!escaped_path.exists());
    }
