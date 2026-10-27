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

    fn session_document(generation: u64, clients: &[&str], keys: &[(&str, &str)]) -> Vec<u8> {
        let sessions: Vec<_> = keys.iter().map(|(certificate, nonce)| json!({
            "certificate_sha256": certificate, "stream_nonce": nonce,
        })).collect();
        serde_json::to_vec(&json!({
            "schema_version": 2, "generation": generation,
            "revoked_certificates": clients, "revoked_sessions": sessions,
        })).unwrap()
    }

    #[test]
    fn session_policy_requires_explicit_v2_and_rejects_ambiguous_or_unbounded_keys() {
        let certificate = "ab".repeat(32);
        let nonce = "cd".repeat(32);
        let valid = session_document(1, &[], &[(&certificate, &nonce)]);
        let snapshot = Snapshot::decode(&valid).unwrap();
        assert_eq!(snapshot.version, 2);
        assert_eq!(snapshot.sessions.len(), 1);
        assert!(snapshot.revoked.is_empty());
        // This is the same strict shape used by the previous implementation.
        assert!(serde_json::from_slice::<DocumentV1>(&valid).is_err());
        let mut document: Value = serde_json::from_slice(&valid).unwrap();
        for version in [0, 1, 3] {
            document["schema_version"] = json!(version);
            assert!(Snapshot::decode(&serde_json::to_vec(&document).unwrap()).is_err());
        }
        document["schema_version"] = json!(2);
        document["revoked_sessions"][0]["extra"] = json!(true);
        assert!(Snapshot::decode(&serde_json::to_vec(&document).unwrap()).is_err());
        let upper_certificate = certificate.to_ascii_uppercase();
        let upper_nonce = nonce.to_ascii_uppercase();
        for bytes in [
            session_document(1, &[], &[(&certificate, "bad")]),
            session_document(1, &[], &[("bad", &nonce)]),
            session_document(1, &[], &[
                (&certificate, &nonce), (&upper_certificate, &upper_nonce),
            ]),
            br#"{"schema_version":1,"generation":1,"revoked_certificates":[],"revoked_sessions":null}"#.to_vec(),
            br#"{"schema_version":2,"generation":1,"revoked_certificates":[]}"#.to_vec(),
            br#"{"schema_version":2,"generation":1,"revoked_certificates":[],"revoked_sessions":null}"#.to_vec(),
            br#"{"schema_version":2,"schema_version":2,"generation":1,"revoked_certificates":[],"revoked_sessions":[]}"#.to_vec(),
        ] {
            assert!(Snapshot::decode(&bytes).is_err());
        }
        let many = vec![(certificate.as_str(), nonce.as_str()); MAX_REVOKED_RESUME_SESSIONS + 1];
        assert!(Snapshot::decode(&session_document(1, &[], &many)).is_err());
    }

    #[test]
    fn session_policy_never_removes_a_key_or_downgrades_to_certificate_only() {
        let a = "11".repeat(32);
        let b = "22".repeat(32);
        let first = "aa".repeat(32);
        let second = "bb".repeat(32);
        let legacy = Snapshot::decode(&document(7, &[&a])).unwrap();
        let policy = Snapshot::decode(&session_document(8, &[&a], &[(&b, &first)])).unwrap();
        assert!(policy.follows(&legacy).is_ok());
        assert!(policy.follows(&policy).is_ok());
        let successor = session_document(9, &[&a], &[(&b, &first), (&b, &second)]);
        assert!(Snapshot::decode(&successor).unwrap().follows(&policy).is_ok());
        for candidate in [
            document(9, &[&a, &b]),
            session_document(7, &[&a], &[(&b, &first)]),
            session_document(8, &[&a], &[(&b, &first), (&b, &second)]),
            session_document(9, &[&a, &b], &[]),
            session_document(9, &[], &[(&b, &first)]),
            session_document(9, &[&a], &[(&b, &second)]),
        ] {
            assert!(Snapshot::decode(&candidate).unwrap().follows(&policy).is_err());
        }
    }

    #[test]
    fn protected_session_policy_reopens_with_the_exact_authenticated_key() {
        let path = directory().join("sessions.json");
        let certificate = "23".repeat(32);
        let nonce = "45".repeat(32);
        let bytes = session_document(19, &[], &[(&certificate, &nonce)]);
        write(&path, &bytes);
        let first = read_policy(&path).unwrap();
        let reopened = read_policy(&path).unwrap();
        assert_eq!(first.snapshot, reopened.snapshot);
        assert_eq!(first.directory, reopened.directory);
        assert_eq!(reopened.snapshot.version, 2);
        assert_eq!(reopened.snapshot.generation, 19);
        assert_eq!(
            reopened.snapshot.sessions.into_iter().collect::<Vec<_>>(),
            vec![ResumeSessionKey {
                client: NativeClientCertificateId::from_sha256([0x23; 32]),
                nonce: [0x45; 32],
            }],
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
