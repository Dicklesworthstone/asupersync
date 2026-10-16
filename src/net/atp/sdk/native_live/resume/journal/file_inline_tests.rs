    use super::super::{Hello, PendingIntent, advance, digest, encode_epoch, initial, offer};
    use super::*;

    fn path() -> PathBuf {
        let directory = tempfile::tempdir().unwrap().keep();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        directory.join("sender.journal")
    }

    fn sample() -> SenderCheckpoint {
        let hello = Hello {
            nonce: [7; 32],
            epoch_bytes: 8,
            max_bytes: 64,
        };
        let prefix = initial(&hello);
        let epoch = encode_epoch(&prefix, b"abcdefgh");
        let next = advance(&prefix, &epoch, 8, 64).unwrap();
        SenderCheckpoint {
            offered: offer(&hello).try_into().unwrap(),
            agreed: offer(&hello).try_into().unwrap(),
            prefix,
            prefix_hash: digest(&Sha256::new()),
            read_hash: Sha256::digest(b"abcdefgh").into(),
            server: [3; 32],
            remote: "127.0.0.1:8443".parse().unwrap(),
            domain: "localhost".into(),
            used: 1,
            maximum: 4,
            eof: false,
            pending: Some(PendingIntent {
                bytes: 8,
                hash: Sha256::digest(b"abcdefgh").into(),
                chain: next.chain,
            }),
        }
    }

    fn acknowledged(old: &SenderCheckpoint) -> SenderCheckpoint {
        let mut next = old.clone();
        next.prefix.bytes += old.pending_bytes() as u64;
        next.prefix.epochs += 1;
        next.prefix.chain = old.pending.as_ref().unwrap().chain;
        next.prefix_hash = old.read_hash;
        next.pending = None;
        next
    }

    #[test]
    fn transitions_survive_reopen_without_resetting_bounds_or_attempts() {
        let path = path();
        let store = SenderJournalFile::create_new(&path, 3).unwrap();
        let first = sample();
        assert_eq!(store.storage.append(first.clone()).unwrap(), 1);
        assert_eq!(store.storage.append(first.clone()).unwrap(), 1);
        let mut next = acknowledged(&first);
        next.used = 2;
        assert_eq!(store.storage.append(next.clone()).unwrap(), 2);
        next.eof = true;
        assert_eq!(store.storage.append(next.clone()).unwrap(), 3);
        assert_eq!(store.storage.append(next.clone()).unwrap(), 3);
        let before = std::fs::read(&path).unwrap();
        let mut exhausted = next.clone();
        exhausted.used = 3;
        assert_eq!(
            store.storage.append(exhausted).unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        drop(store);
        let reopened = SenderJournalFile::open_existing(&path).unwrap();
        assert_eq!(reopened.persisted_snapshots(), 3);
        assert_eq!(reopened.maximum_snapshots(), 3);
        let loaded = reopened.checkpoint().unwrap();
        assert_eq!(
            loaded.to_canonical_bytes().unwrap().as_slice(),
            next.to_canonical_bytes().unwrap().as_slice()
        );
        assert_eq!(loaded.attempts(), 2);
        assert!(loaded.source_eof());
    }

    #[test]
    fn create_only_exclusive_ownership_survives_a_returned_wrapper() {
        let path = path();
        let store = SenderJournalFile::create_new(&path, 3).unwrap();
        store.storage.append(sample()).unwrap();
        let running = Arc::clone(&store.storage);
        drop(store);
        assert!(SenderJournalFile::create_new(&path, 3).is_err());
        assert!(SenderJournalFile::open_existing(&path).is_err());
        drop(running);
        assert!(SenderJournalFile::open_existing(&path).is_ok());
    }

    #[test]
    fn torn_corrupt_and_impossible_history_is_never_repaired() {
        let source = path();
        let store = SenderJournalFile::create_new(&source, 3).unwrap();
        store.storage.append(sample()).unwrap();
        drop(store);
        let valid = std::fs::read(&source).unwrap();
        for variant in 0..5 {
            let mut bytes = valid.clone();
            match variant {
                0 => {
                    bytes.pop();
                }
                1 => {
                    bytes.push(0);
                }
                2 => {
                    bytes[HEADER + 40] ^= 1;
                }
                3 => {
                    bytes[HEADER] = 1;
                }
                4 => {
                    bytes.extend_from_slice(&valid[HEADER..]);
                    let start = HEADER + RECORD;
                    bytes[start..start + 8].copy_from_slice(&1_u64.to_be_bytes());
                    // Re-sign an invalid peer-identity transition to ensure
                    // record checksums cannot substitute for semantic validation.
                    bytes[start + 16 + 240] ^= 1;
                    let n = usize::from(u16::from_be_bytes([bytes[start + 8], bytes[start + 9]]));
                    let end = start + 16 + n - 32;
                    let mut h = Sha256::new();
                    h.update(b"asupersync.atp.sender-checkpoint.v1");
                    h.update(&bytes[start + 16..end]);
                    bytes[end..end + 32].copy_from_slice(&h.finalize());
                    let hash = checksum(
                        &bytes[HEADER + BODY..HEADER + RECORD],
                        &bytes[start..start + BODY],
                    );
                    bytes[start + BODY..start + RECORD].copy_from_slice(&hash);
                }
                _ => unreachable!(),
            }
            let rejected = path();
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&rejected)
                .unwrap();
            file.write_all(&bytes).unwrap();
            drop(file);
            assert!(SenderJournalFile::open_existing(&rejected).is_err());
            assert_eq!(std::fs::read(&rejected).unwrap(), bytes);
        }
    }

    #[test]
    fn uncertain_append_poison_is_sticky_and_does_not_hide_tail_damage() {
        let path = path();
        let store = SenderJournalFile::create_new(&path, 3).unwrap();
        let first = sample();
        store.storage.append(first.clone()).unwrap();
        let mut corruptor = OpenOptions::new().append(true).open(&path).unwrap();
        corruptor.write_all(&[0]).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(store.storage.append(acknowledged(&first)).is_err());
        assert!(store.storage.state.lock().poisoned);
        assert!(store.storage.append(first).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn missing_empty_aliased_and_nonprivate_journals_are_refused() {
        let missing = path();
        assert!(SenderJournalFile::open_existing(&missing).is_err());
        assert!(!missing.exists());
        assert!(SenderJournalFile::create_new(&missing, 0).is_err());
        assert!(!missing.exists());
        let store = SenderJournalFile::create_new(&missing, 1).unwrap();
        drop(store);
        assert!(SenderJournalFile::open_existing(&missing).is_err());
        let path = path();
        let store = SenderJournalFile::create_new(&path, 1).unwrap();
        store.storage.append(sample()).unwrap();
        drop(store);
        let symlink = path.with_extension("symlink");
        std::os::unix::fs::symlink(&path, &symlink).unwrap();
        assert!(SenderJournalFile::open_existing(&symlink).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(SenderJournalFile::open_existing(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&path, path.with_extension("hardlink")).unwrap();
        assert!(SenderJournalFile::open_existing(&path).is_err());
    }
