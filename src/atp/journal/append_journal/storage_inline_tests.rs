    use super::*;

    fn key() -> AuthKey { AuthKey::from_seed(42) }

    fn config(path: &Path) -> JournalConfig {
        JournalConfig {
            base_dir: path.to_owned(),
            max_journal_size: u64::MAX,
            ..JournalConfig::default()
        }
    }

    fn accept(peer: &str) -> JournalRecord {
        JournalRecord::Accept {
            transfer_id: "transfer".to_owned(), peer_id: peer.to_owned(), timestamp: 1,
            auth_tag: AuthenticationTag::zero(),
        }
    }

    fn cancel() -> JournalRecord {
        JournalRecord::Cancellation {
            transfer_id: "transfer".to_owned(), reason: "stop".to_owned(), timestamp: 2,
            auth_tag: AuthenticationTag::zero(),
        }
    }

    fn assert_fenced(journal: &mut AppendJournal) {
        assert!(journal.storage_failed);
        assert!(journal.writer.is_none());
        assert!(matches!(journal.append_with_storage(accept("must not run"),
            |_, _, _| panic!("failed journal reached another write")),
            Outcome::Err(JournalError::WriteFailure(_))));
        assert!(matches!(journal.flush(), Outcome::Err(JournalError::WriteFailure(_))));
        assert!(matches!(journal.compact(), Outcome::Err(JournalError::WriteFailure(_))));
        assert!(matches!(journal.get_resume_summary("transfer"),
            Outcome::Err(JournalError::WriteFailure(_))));
    }

    #[test]
    fn unrecoverable_frame_sizes_refuse_without_opening_or_poisoning() {
        assert_eq!(frame_length(MAX_JOURNAL_FRAME_BYTES).unwrap(), 16 * 1024 * 1024);
        assert!(frame_length(MAX_JOURNAL_FRAME_BYTES + 1).is_err());
        assert!(frame_length(usize::MAX).is_err());
        let root = tempfile::tempdir().unwrap();
        let mut journal = AppendJournal::new(config(root.path()), key()).unwrap();
        let result = journal.append(accept(&"x".repeat(MAX_JOURNAL_FRAME_BYTES)));
        assert!(matches!(result, Outcome::Err(JournalError::Serialization(_))));
        assert!(!journal.storage_failed);
        assert!(journal.writer.is_none());
        assert_eq!(journal.sequence, 0);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
        assert_eq!(journal.append(accept("valid")).unwrap(), 0);
    }

    #[test]
    fn partial_frame_error_requires_reopen_and_never_appends_behind_torn_bytes() {
        for force_sync in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let cfg = JournalConfig { force_sync, ..config(root.path()) };
            let mut journal = AppendJournal::new(cfg.clone(), key()).unwrap();
            journal.append(accept("before")).unwrap();
            let path = journal_file_path(root.path(), 0);
            let before = std::fs::read(&path).unwrap();
            let result = journal.append_with_storage(cancel(), |writer, encoded, _| {
                let prefix = frame_length(encoded.len())?.to_le_bytes();
                writer.write_all(&prefix[..2]).unwrap();
                writer.flush().unwrap();
                Err(JournalError::WriteFailure("partial frame witness".to_owned()))
            });
            assert!(matches!(result, Outcome::Err(JournalError::WriteFailure(message))
                if message == "partial frame witness"));
            assert_fenced(&mut journal);
            let damaged = std::fs::read(&path).unwrap();
            assert_eq!(&damaged[..before.len()], before);
            assert_eq!(damaged.len(), before.len() + 2);
            drop(journal);
            assert_eq!(std::fs::read(&path).unwrap(), damaged);
            let mut recovered = AppendJournal::new(cfg.clone(), key()).unwrap();
            assert_eq!(recovered.generation, 1);
            assert_eq!(recovered.append(accept("after")).unwrap(), 1);
            drop(recovered);
            let reopened = AppendJournal::new(cfg, key()).unwrap();
            let records = reopened.get_transfer_entries("transfer").unwrap();
            assert_eq!(records.len(), 2);
            assert_eq!(records[1].record, accept("after").with_signature(&key()));
            assert_eq!(std::fs::read(path).unwrap(), damaged);
        }
    }

    #[test]
    fn complete_frame_followed_by_sync_error_cannot_hide_a_cancellation() {
        let root = tempfile::tempdir().unwrap();
        let cfg = config(root.path());
        let mut journal = AppendJournal::new(cfg.clone(), key()).unwrap();
        journal.append(accept("before")).unwrap();
        let result = journal.append_with_storage(cancel(), |writer, encoded, _| {
            append_frame(writer, encoded, false)?;
            Err(JournalError::SyncFailure("barrier witness".to_owned()))
        });
        assert!(matches!(result, Outcome::Err(JournalError::SyncFailure(message))
            if message == "barrier witness"));
        assert_eq!(journal.sequence, 1); // No false receipt for the uncertain frame.
        assert_fenced(&mut journal);
        drop(journal);
        let mut recovered = AppendJournal::new(cfg, key()).unwrap();
        assert_eq!(recovered.sequence, 2); // Disk actually contains the entire frame.
        assert_eq!(recovered.get_resume_summary("transfer").unwrap().status,
            TransferResumeStatus::Cancelled { reason: "stop".to_owned() });
        assert_eq!(recovered.append(accept("later")).unwrap(), 2);
    }

    #[test]
    fn unwinding_discards_buffered_bytes_but_preserves_completed_os_effects() {
        for flush_before_panic in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let cfg = config(root.path());
            let mut journal = AppendJournal::new(cfg.clone(), key()).unwrap();
            journal.append(accept("before")).unwrap();
            let path = journal_file_path(root.path(), 0);
            let before = std::fs::read(&path).unwrap();
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                journal.append_with_storage(cancel(), |writer, encoded, _| {
                    if flush_before_panic {
                        append_frame(writer, encoded, false).unwrap();
                    } else {
                        writer.write_all(b"buffered but never accepted").unwrap();
                        assert!(!writer.buffer().is_empty());
                    }
                    panic!("journal storage panic witness");
                })
            }));
            assert!(panic.is_err());
            assert_fenced(&mut journal);
            let after = std::fs::read(&path).unwrap();
            if !flush_before_panic { assert_eq!(after, before); }
            drop(journal);
            assert_eq!(std::fs::read(path).unwrap(), after);
            let recovered = AppendJournal::new(cfg, key()).unwrap();
            assert_eq!(recovered.sequence, if flush_before_panic { 2 } else { 1 });
            assert_eq!(recovered.get_resume_summary("transfer").unwrap().is_resumable(),
                !flush_before_panic);
        }
    }

    #[test]
    fn failed_explicit_flush_discards_its_buffer_without_destructor_retry() {
        let root = tempfile::tempdir().unwrap();
        let cfg = config(root.path());
        let mut journal = AppendJournal::new(cfg.clone(), key()).unwrap();
        journal.append(accept("before")).unwrap();
        let path = journal_file_path(root.path(), 0);
        let before = std::fs::read(&path).unwrap();
        journal.writer.as_mut().unwrap().write_all(b"pending").unwrap();
        let result = journal.flush_with_storage(|_| {
            Err(JournalError::SyncFailure("flush witness".to_owned()))
        });
        assert!(matches!(result, Outcome::Err(JournalError::SyncFailure(message))
            if message == "flush witness"));
        assert_fenced(&mut journal);
        drop(journal);
        assert_eq!(std::fs::read(path).unwrap(), before);
        assert_eq!(AppendJournal::new(cfg, key()).unwrap().sequence, 1);
    }

    #[test]
    fn public_append_handles_a_real_read_only_descriptor_failure() {
        let root = tempfile::tempdir().unwrap();
        let mut journal = AppendJournal::new(config(root.path()), key()).unwrap();
        journal.append(accept("before")).unwrap();
        let path = journal_file_path(root.path(), 0);
        let before = std::fs::read(&path).unwrap();
        journal.writer = Some(BufWriter::new(File::open(&path).unwrap()));
        assert!(matches!(journal.append(cancel()), Outcome::Err(JournalError::SyncFailure(_))));
        assert_fenced(&mut journal);
        drop(journal);
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    fn native_recovery_observes_uncertain_terminal_frame_before_reactivating_bitmap() {
        use crate::atp::journal::{ChunkBitmap, ChunkState, recover_journal_and_bitmap};
        use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
        use std::time::Duration;

        for workers in [1, 2] {
            let root = tempfile::tempdir().unwrap();
            let journal_dir = root.path().join("journal");
            let bitmap_dir = root.path().join("bitmaps");
            std::fs::create_dir_all(&bitmap_dir).unwrap();
            let cfg = config(&journal_dir);
            let mut journal = AppendJournal::new(cfg, key()).unwrap();
            journal.append(JournalRecord::Offer {
                transfer_id: "transfer".to_owned(),
                object_id: ObjectId::content(ContentId::from_bytes(b"data")),
                manifest_root: MerkleRoot::new([1; 32]), total_size: 4, timestamp: 1,
                auth_tag: AuthenticationTag::zero(),
            }).unwrap();
            for record in [
                JournalRecord::ChunkReceived { transfer_id: "transfer".to_owned(),
                    chunk_offset: 0, chunk_size: 4, chunk_hash: [7; 32], timestamp: 2,
                    auth_tag: AuthenticationTag::zero() },
                JournalRecord::ChunkVerified { transfer_id: "transfer".to_owned(),
                    chunk_offset: 0, chunk_size: 4, verified_hash: [7; 32], timestamp: 3,
                    auth_tag: AuthenticationTag::zero() },
                JournalRecord::ChunkWritten { transfer_id: "transfer".to_owned(),
                    chunk_offset: 0, chunk_size: 4, file_path: "stage".to_owned(), timestamp: 4,
                    auth_tag: AuthenticationTag::zero() },
            ] { journal.append(record).unwrap(); }
            let mut bitmap = ChunkBitmap::new("transfer".to_owned(), 4, 4, 1);
            bitmap.update_chunk_state(0, ChunkState::Written, 4, Some([7; 32]));
            let old_bytes = bitmap.serialize_to_bytes();
            let bitmap_path = bitmap_dir.join("transfer_transfer.bitmap");
            std::fs::write(&bitmap_path, &old_bytes).unwrap();
            assert!(journal.append_with_storage(cancel(), |writer, encoded, _| {
                append_frame(writer, encoded, false)?;
                Err(JournalError::SyncFailure("terminal barrier witness".to_owned()))
            }).is_err());
            assert_fenced(&mut journal);
            drop(journal);
            let builder = if workers == 1 { RuntimeBuilder::current_thread() }
                else { RuntimeBuilder::new().worker_threads(workers) };
            let runtime = builder.blocking_threads(1, 2).build().unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (recovered, active) = recover_journal_and_bitmap(
                    &cx, &journal_file_path(&journal_dir, 0), &bitmap_dir, &key(),
                ).await.unwrap();
                assert!(active.is_empty());
                assert!(matches!(recovered.get_resume_summary("transfer").unwrap().status,
                    TransferResumeStatus::Cancelled { .. }));
                assert!(!bitmap_path.exists());
                assert_eq!(std::fs::read(bitmap_path.with_extension("bitmap.stale")).unwrap(), old_bytes);
            });
            let report = runtime.shutdown_drained(Duration::from_secs(5));
            assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
        }
    }
