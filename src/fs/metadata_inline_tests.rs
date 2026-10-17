    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::time::{Duration, SystemTime};
    use tempfile::tempdir;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_metadata_file_basic() {
        init_test("test_metadata_file_basic");
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("file.txt");
        fs::write(&path, b"hello").expect("write");

        let meta = Metadata::from_std(fs::metadata(&path).expect("metadata"));
        crate::assert_with_log!(meta.is_file(), "is_file", true, meta.is_file());
        crate::assert_with_log!(!meta.is_dir(), "is_dir", false, meta.is_dir());
        crate::assert_with_log!(meta.len() == 5, "len", 5, meta.len());
        crate::assert_with_log!(!meta.is_empty(), "is_empty", false, meta.is_empty());

        let file_type = meta.file_type();
        crate::assert_with_log!(file_type.is_file(), "file_type", true, file_type.is_file());
        crate::assert_with_log!(
            !file_type.is_dir(),
            "file_type dir",
            false,
            file_type.is_dir()
        );
        crate::test_complete!("test_metadata_file_basic");
    }

    #[test]
    fn test_metadata_dir_basic() {
        init_test("test_metadata_dir_basic");
        let dir = tempdir().expect("tempdir");
        let meta = Metadata::from_std(fs::metadata(dir.path()).expect("metadata"));
        crate::assert_with_log!(meta.is_dir(), "is_dir", true, meta.is_dir());
        crate::assert_with_log!(!meta.is_file(), "is_file", false, meta.is_file());
        let file_type = meta.file_type();
        crate::assert_with_log!(file_type.is_dir(), "file_type", true, file_type.is_dir());
        crate::test_complete!("test_metadata_dir_basic");
    }

    #[test]
    fn test_metadata_empty_file() {
        init_test("test_metadata_empty_file");
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("empty.txt");
        fs::File::create(&path).expect("create");

        let meta = Metadata::from_std(fs::metadata(&path).expect("metadata"));
        crate::assert_with_log!(meta.is_empty(), "empty", true, meta.is_empty());

        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open");
        writeln!(file, "data").expect("write data");
        let meta = Metadata::from_std(fs::metadata(&path).expect("metadata"));
        crate::assert_with_log!(!meta.is_empty(), "not empty", false, meta.is_empty());
        crate::test_complete!("test_metadata_empty_file");
    }

    #[test]
    fn test_metadata_modified_time() {
        init_test("test_metadata_modified_time");
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("mtime.txt");
        fs::write(&path, b"time").expect("write");

        let meta = Metadata::from_std(fs::metadata(&path).expect("metadata"));
        let modified = meta.modified().expect("modified");
        let now = SystemTime::now();
        let diff = match now.duration_since(modified) {
            Ok(delta) => delta,
            Err(err) => err.duration(),
        };
        crate::assert_with_log!(
            diff <= Duration::from_secs(60),
            "modified within 60s",
            true,
            diff <= Duration::from_secs(60)
        );
        crate::test_complete!("test_metadata_modified_time");
    }

    #[test]
    fn test_permissions_readonly_roundtrip() {
        init_test("test_permissions_readonly_roundtrip");
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("perm.txt");
        fs::write(&path, b"perm").expect("write");

        let mut perms = Metadata::from_std(fs::metadata(&path).expect("metadata")).permissions();
        perms.set_readonly(true);
        fs::set_permissions(&path, perms.into_inner()).expect("set permissions");
        let readonly = Metadata::from_std(fs::metadata(&path).expect("metadata"))
            .permissions()
            .readonly();
        crate::assert_with_log!(readonly, "readonly", true, readonly);

        let mut perms = Metadata::from_std(fs::metadata(&path).expect("metadata")).permissions();
        perms.set_readonly(false);
        fs::set_permissions(&path, perms.into_inner()).expect("set permissions");
        let readonly = Metadata::from_std(fs::metadata(&path).expect("metadata"))
            .permissions()
            .readonly();
        crate::assert_with_log!(!readonly, "readonly off", false, readonly);
        crate::test_complete!("test_permissions_readonly_roundtrip");
    }

    #[cfg(unix)]
    #[test]
    fn test_metadata_symlink() {
        use std::os::unix::fs::symlink;
        init_test("test_metadata_symlink");
        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("target.txt");
        let link = dir.path().join("link.txt");
        fs::write(&target, b"link").expect("write");
        symlink(&target, &link).expect("symlink");

        let meta = Metadata::from_std(fs::symlink_metadata(&link).expect("metadata"));
        crate::assert_with_log!(meta.is_symlink(), "is_symlink", true, meta.is_symlink());
        crate::test_complete!("test_metadata_symlink");
    }

    // =========================================================================
    // Wave 53 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn metadata_debug_clone() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("dbg.txt");
        fs::write(&path, b"test").expect("write");
        let meta = Metadata::from_std(fs::metadata(&path).expect("metadata"));
        let dbg = format!("{meta:?}");
        assert!(dbg.contains("Metadata"), "{dbg}");
        let cloned = meta;
        assert_eq!(cloned.len(), 4);
    }

    #[test]
    fn file_type_debug_clone() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("ft.txt");
        fs::write(&path, b"x").expect("write");
        let ft = Metadata::from_std(fs::metadata(&path).expect("metadata")).file_type();
        let dbg = format!("{ft:?}");
        assert!(dbg.contains("FileType"), "{dbg}");
        let cloned = ft;
        assert!(cloned.is_file());
    }

    #[test]
    fn permissions_debug_clone() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("pm.txt");
        fs::write(&path, b"y").expect("write");
        let perms = Metadata::from_std(fs::metadata(&path).expect("metadata")).permissions();
        let dbg = format!("{perms:?}");
        assert!(dbg.contains("Permissions"), "{dbg}");
        let cloned = perms.clone();
        assert_eq!(cloned.readonly(), perms.readonly());
    }
