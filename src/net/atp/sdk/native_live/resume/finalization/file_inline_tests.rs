    use super::super::{Hello, initial, offer};
    use super::*;
    use sha2::{Digest, Sha256};

    fn checkpoint() -> FinalProofCheckpoint {
        let hello = Hello {
            nonce: [4; 32],
            epoch_bytes: 8,
            max_bytes: 64,
        };
        FinalProofCheckpoint {
            offered: offer(&hello).try_into().unwrap(),
            agreed: offer(&hello).try_into().unwrap(),
            receipt: super::super::LiveStreamReceipt {
                prefix: initial(&hello),
                source_sha256: Sha256::digest(b"").into(),
            },
            server_certificate: [3; 32],
            remote: "127.0.0.1:8443".parse().unwrap(),
            domain: "localhost".to_owned(),
        }
    }
    fn path() -> PathBuf {
        let directory = tempfile::tempdir().unwrap().keep();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        directory.join("sender.checkpoint")
    }

    #[test]
    fn create_only_lock_and_reopen_preserve_exact_intent() {
        let path = path();
        let store = FinalProofFile::create_new(&path).unwrap();
        assert!(!store.is_persisted());
        assert!(store.checkpoint().is_err());
        let bytes = checkpoint().to_canonical_bytes().unwrap();
        store.storage.write_once(&bytes).unwrap();
        assert!(store.storage.write_once(&bytes).is_err());
        assert!(FinalProofFile::create_new(&path).is_err());
        assert!(FinalProofFile::open_existing(&path).is_err());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(store);
        let reopened = FinalProofFile::open_existing(&path).unwrap();
        assert!(reopened.is_persisted());
        assert_eq!(
            reopened.checkpoint().unwrap().to_canonical_bytes().unwrap(),
            bytes
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn missing_empty_torn_and_oversized_files_never_become_success() {
        let missing = path();
        assert!(FinalProofFile::open_existing(&missing).is_err());
        assert!(!missing.exists());
        let valid = checkpoint().to_canonical_bytes().unwrap();
        for bytes in [
            vec![],
            valid[..valid.len() - 1].to_vec(),
            vec![0; MAX_FINAL_PROOF_CHECKPOINT_BYTES + 1],
        ] {
            let path = path();
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            file.write_all(&bytes).unwrap();
            drop(file);
            assert!(FinalProofFile::open_existing(&path).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
    }

    #[test]
    fn public_mode_symlinks_and_extra_hard_links_are_refused() {
        let path = path();
        let store = FinalProofFile::create_new(&path).unwrap();
        store
            .storage
            .write_once(&checkpoint().to_canonical_bytes().unwrap())
            .unwrap();
        drop(store);
        let alias = path.with_extension("alias");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(FinalProofFile::open_existing(&alias).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(FinalProofFile::open_existing(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&path, path.with_extension("hard-link")).unwrap();
        assert!(FinalProofFile::open_existing(&path).is_err());
    }
