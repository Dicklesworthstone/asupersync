    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn document(generation: u64, ids: &[&str]) -> Vec<u8> {
        serde_json::to_vec(&json!({"schema_version": 1, "generation": generation,
            "revoked_certificates": ids}))
        .unwrap()
    }
    fn directory() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "atpd-revocations-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        path
    }
    fn write(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        File::open(path.parent().unwrap())
            .unwrap()
            .sync_all()
            .unwrap();
    }

    #[test]
    fn policy_versions_are_monotonic_and_cannot_restore_authority() {
        let a = "11".repeat(32);
        let b = "22".repeat(32);
        let old = Snapshot::decode(&document(7, &[&a])).unwrap();
        assert!(old.follows(&old).is_ok());
        assert!(
            Snapshot::decode(&document(9, &[&a, &b]))
                .unwrap()
                .follows(&old)
                .is_ok()
        );
        for candidate in [
            document(6, &[&a]),
            document(7, &[&a, &b]),
            document(8, &[]),
            document(8, &[&b]),
        ] {
            assert!(Snapshot::decode(&candidate).unwrap().follows(&old).is_err());
        }
    }

    #[test]
    fn strict_policy_parser_bounds_input_and_rejects_ambiguous_fields() {
        let id = "12".repeat(32);
        for bytes in [
            document(0, &[]),
            document(1, &[&id, &id]),
            document(1, &["bad"]),
            b"{\"schema_version\":1,\"generation\":1,\"revoked_certificates\":[],\"extra\":true}"
                .to_vec(),
            b"{\"schema_version\":1,\"generation\":1,\"generation\":2,\"revoked_certificates\":[]}"
                .to_vec(),
            vec![b' '; MAX_POLICY_BYTES + 1],
        ] {
            assert!(Snapshot::decode(&bytes).is_err());
        }
        let many = vec![id.as_str(); MAX_REVOKED_RESUME_CLIENTS + 1];
        assert!(Snapshot::decode(&document(1, &many)).is_err());
    }

    #[test]
    fn policy_file_is_private_complete_and_survives_an_independent_reopen() {
        let path = directory().join("policy.json");
        assert!(read_policy(&path).is_err());
        assert!(!path.exists());
        let bytes = document(1, &[&"33".repeat(32)]);
        write(&path, &bytes);
        let first = read_policy(&path).unwrap();
        let second = read_policy(&path).unwrap();
        assert_eq!(first.snapshot, second.snapshot);
        assert_eq!(first.directory, second.directory);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_policy(&path).is_err());
    }

    #[test]
    fn symlinks_hardlinks_oversized_and_torn_policy_files_are_refused() {
        let parent = directory();
        let path = parent.join("valid");
        write(&path, &document(1, &[]));
        std::os::unix::fs::symlink(&path, parent.join("symlink")).unwrap();
        assert!(read_policy(&parent.join("symlink")).is_err());
        std::fs::hard_link(&path, parent.join("alias")).unwrap();
        assert!(read_policy(&path).is_err());
        write(&parent.join("torn"), b"{\"schema_version\":1,");
        assert!(read_policy(&parent.join("torn")).is_err());
        write(&parent.join("large"), &vec![b' '; MAX_POLICY_BYTES + 1]);
        assert!(read_policy(&parent.join("large")).is_err());
        assert!(read_policy(Path::new("relative.json")).is_err());
    }
