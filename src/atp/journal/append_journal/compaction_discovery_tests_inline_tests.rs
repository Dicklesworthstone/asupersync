    #[allow(clippy::wildcard_imports)]
    use super::*;

    fn config(base: &Path) -> JournalConfig {
        JournalConfig {
            base_dir: base.to_owned(),
            force_sync: false,
            max_journal_size: u64::MAX,
            max_generations: 0,
            ..JournalConfig::default()
        }
    }

    fn key() -> AuthKey { AuthKey::from_seed(42) }

    fn accepted() -> JournalRecord {
        JournalRecord::Accept {
            transfer_id: "discovery".to_owned(), peer_id: "peer".to_owned(),
            timestamp: 1, auth_tag: AuthenticationTag::zero(),
        }
    }

    fn cancelled() -> JournalRecord {
        JournalRecord::Cancellation {
            transfer_id: "discovery".to_owned(), reason: "terminal evidence".to_owned(),
            timestamp: 2, auth_tag: AuthenticationTag::zero(),
        }
    }

    fn fixture(path: &Path, records: &[(u64, JournalRecord)]) -> Vec<u8> {
        let mut file = OpenOptions::new().create_new(true).write(true).open(path).unwrap();
        for (sequence, record) in records {
            let entry = JournalEntry::try_new(*sequence, record.clone().with_signature(&key())).unwrap();
            write_entry(&mut file, &entry).unwrap();
        }
        file.sync_all().unwrap();
        std::fs::read(path).unwrap()
    }

    #[test]
    fn noncanonical_generations_cannot_hide_terminal_records_or_alias_a_real_generation() {
        for alias in ["journal_gen_1.dat", "journal_gen_0000001.dat"] {
            for canonical_exists in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let base = directory.path();
                let original = fixture(&journal_file_path(base, 0), &[(0, accepted())]);
                let terminal = fixture(&base.join(alias), &[(1, cancelled())]);
                if canonical_exists {
                    fixture(&journal_file_path(base, 1), &[]);
                }
                assert!(matches!(AppendJournal::new(config(base), key()),
                    Outcome::Err(JournalError::Deserialization(reason)) if reason.contains("noncanonical")));
                assert_eq!(std::fs::read(journal_file_path(base, 0)).unwrap(), original);
                assert_eq!(std::fs::read(base.join(alias)).unwrap(), terminal);
                if canonical_exists {
                    assert!(std::fs::read(journal_file_path(base, 1)).unwrap().is_empty());
                } else {
                    assert!(!journal_file_path(base, 1).exists());
                }
                assert!(!journal_file_path(base, 2).exists());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn generation_symlinks_are_refused_without_following_or_repairing_them() {
        for kind in ["dangling", "regular-target", "self-loop"] {
            let directory = tempfile::tempdir().unwrap();
            let base = directory.path();
            let original = fixture(&journal_file_path(base, 0), &[(0, accepted())]);
            let target = base.join("separate-evidence");
            let target_bytes = if kind == "regular-target" {
                Some(fixture(&target, &[(1, cancelled())]))
            } else { None };
            let link = journal_file_path(base, 1);
            let selected = if kind == "self-loop" { link.clone() } else { target.clone() };
            std::os::unix::fs::symlink(&selected, &link).unwrap();
            assert!(matches!(AppendJournal::new(config(base), key()),
                Outcome::Err(JournalError::ReadFailure(reason)) if reason.contains("regular")));
            assert_eq!(std::fs::read(journal_file_path(base, 0)).unwrap(), original);
            assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
            assert_eq!(std::fs::read_link(link).unwrap(), selected);
            if let Some(bytes) = target_bytes { assert_eq!(std::fs::read(target).unwrap(), bytes); }
            else { assert!(!target.exists()); }
            assert!(!journal_file_path(base, 2).exists());
        }
    }

    #[test]
    fn a_directory_named_as_a_generation_is_not_opened_as_a_journal() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        let original = fixture(&journal_file_path(base, 0), &[(0, accepted())]);
        std::fs::create_dir(journal_file_path(base, 1)).unwrap();
        assert!(matches!(AppendJournal::new(config(base), key()),
            Outcome::Err(JournalError::ReadFailure(reason)) if reason.contains("regular")));
        assert_eq!(std::fs::read(journal_file_path(base, 0)).unwrap(), original);
        assert!(journal_file_path(base, 1).is_dir());
        assert!(!journal_file_path(base, 2).exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_socket_named_as_a_generation_is_refused_during_discovery() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        fixture(&journal_file_path(base, 0), &[(0, accepted())]);
        let _socket = std::os::unix::net::UnixListener::bind(journal_file_path(base, 1)).unwrap();
        assert!(matches!(AppendJournal::new(config(base), key()),
            Outcome::Err(JournalError::ReadFailure(reason)) if reason.contains("regular")));
        assert!(!journal_file_path(base, 2).exists());
    }

    #[test]
    fn disappearance_after_discovery_is_not_a_successful_partial_history() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        let original = fixture(&journal_file_path(base, 0), &[(0, accepted())]);
        let journal = AppendJournal::new(config(base), key()).unwrap();
        // Pass the exact snapshot a scan would return before generation 1 was
        // lost. No timed race or destructive fixture operation is necessary.
        assert!(matches!(journal.read_generation_history(vec![0, 1]),
            Outcome::Err(JournalError::FileOpen(_))));
        assert_eq!(std::fs::read(journal_file_path(base, 0)).unwrap(), original);
        assert!(!journal_file_path(base, 1).exists());
    }

    #[test]
    fn compaction_discovery_failure_fences_the_writer_without_retiring_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        let mut journal = AppendJournal::new(config(base), key()).unwrap();
        journal.append(accepted()).unwrap();
        journal.append(cancelled()).unwrap();
        journal.flush().unwrap();
        let original = std::fs::read(journal_file_path(base, 0)).unwrap();
        let alias = base.join("journal_gen_1.dat");
        let alias_bytes = fixture(&alias, &[(2, accepted())]);
        assert!(matches!(journal.compact(),
            Outcome::Err(JournalError::Deserialization(reason)) if reason.contains("noncanonical")));
        assert!(journal.get_resume_summary("discovery").is_err());
        assert!(journal.append(accepted()).is_err());
        assert_eq!(std::fs::read(journal_file_path(base, 0)).unwrap(), original);
        assert_eq!(std::fs::read(alias).unwrap(), alias_bytes);
        assert!(!journal_file_path(base, 1).exists());
    }

    #[test]
    fn bounded_frontier_and_identical_snapshot_copies_keep_their_existing_semantics() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        fixture(&journal_file_path(base, 0), &[(0, accepted())]);
        let original_reader = AppendJournal::new(config(base), key()).unwrap();
        let high = 1_u64 << 40;
        fixture(&journal_file_path(base, high), &[(0, accepted()), (1, cancelled())]);
        fixture(&base.join("journal_gen_1.dat.backup"), &[(2, accepted())]);
        std::fs::create_dir(base.join("not-a-journal")).unwrap();
        assert_eq!(original_reader.read_all_entries_from_disk().unwrap().len(), 1);
        let recovered = AppendJournal::new(config(base), key()).unwrap();
        assert_eq!(recovered.get_stats().generation, high);
        assert_eq!(recovered.read_all_entries_from_disk().unwrap().len(), 2);
        assert!(matches!(recovered.get_resume_summary("discovery").unwrap().status,
            TransferResumeStatus::Cancelled { reason } if reason == "terminal evidence"));
        // An older frontier stays scoped even if a later generation is invalid.
        fixture(&base.join("journal_gen_2.dat"), &[(2, accepted())]);
        assert_eq!(original_reader.read_all_entries_from_disk().unwrap().len(), 1);
        assert!(AppendJournal::new(config(base), key()).is_err());
    }

    #[test]
    fn reordered_and_duplicate_frames_cannot_be_normalized_into_valid_history() {
        let orders: &[&[u64]] = &[
            &[0, 1, 2], &[0, 2, 1], &[1, 0, 2], &[1, 2, 0],
            &[2, 0, 1], &[2, 1, 0], &[0, 1, 1, 2],
        ];
        for order in orders {
            let directory = tempfile::tempdir().unwrap();
            let base = directory.path();
            let records: Vec<_> = order.iter().map(|sequence| {
                (*sequence, if *sequence == 2 { cancelled() } else { accepted() })
            }).collect();
            let original = fixture(&journal_file_path(base, 0), &records);
            let recovered = AppendJournal::new(config(base), key());
            if *order == &[0_u64, 1, 2][..] {
                assert_eq!(recovered.unwrap().read_all_entries_from_disk().unwrap().len(), 3);
            } else {
                assert!(matches!(recovered,
                    Outcome::Err(JournalError::Deserialization(reason)) if reason.contains("non-increasing")));
            }
            assert_eq!(std::fs::read(journal_file_path(base, 0)).unwrap(), original);
            assert!(!journal_file_path(base, 1).exists());
        }
    }

    #[test]
    fn missing_interior_sequences_refuse_even_with_valid_signed_ordered_frames() {
        for split in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let base = directory.path();
            let first = if split { vec![(0, accepted())] }
                else { vec![(0, accepted()), (2, cancelled())] };
            let original = fixture(&journal_file_path(base, 0), &first);
            let last = if split {
                Some(fixture(&journal_file_path(base, 9), &[(2, cancelled())]))
            } else { None };
            assert!(matches!(AppendJournal::new(config(base), key()),
                Outcome::Err(JournalError::Deserialization(reason)) if reason.contains("sequence gap")));
            assert_eq!(std::fs::read(journal_file_path(base, 0)).unwrap(), original);
            if let Some(last) = last { assert_eq!(std::fs::read(journal_file_path(base, 9)).unwrap(), last); }
            assert!(!journal_file_path(base, 10).exists());
        }
    }

    #[test]
    fn other_generations_can_fill_snapshot_gaps_without_duplicate_replay() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        let original = fixture(&journal_file_path(base, 0), &[
            (0, accepted()), (1, accepted()), (2, accepted()), (3, cancelled()),
        ]);
        fixture(&journal_file_path(base, 1), &[(0, accepted()), (2, accepted())]);
        let mut recovered = AppendJournal::new(config(base), key()).unwrap();
        assert_eq!(recovered.get_stats().sequence, 4);
        assert_eq!(recovered.read_all_entries_from_disk().unwrap().len(), 4);
        assert!(matches!(recovered.get_resume_summary("discovery").unwrap().status,
            TransferResumeStatus::Cancelled { .. }));
        let other = JournalRecord::Accept {
            transfer_id: "independent".to_owned(), peer_id: "peer".to_owned(),
            timestamp: 4, auth_tag: AuthenticationTag::zero(),
        };
        assert_eq!(recovered.append(other).unwrap(), 4);
        recovered.flush().unwrap();
        assert_eq!(std::fs::read(journal_file_path(base, 0)).unwrap(), original);
        drop(recovered);
        let mut reopened = AppendJournal::new(config(base), key()).unwrap();
        assert_eq!(reopened.read_all_entries_from_disk().unwrap().len(), 5);
        reopened.compact().unwrap();
        drop(reopened);
        let reopened = AppendJournal::new(config(base), key()).unwrap();
        assert_eq!(reopened.read_all_entries_from_disk().unwrap().len(), 6);
        assert!(matches!(reopened.get_resume_summary("discovery").unwrap().status,
            TransferResumeStatus::Cancelled { .. }));
        assert_eq!(reopened.get_transfer_entries("independent").unwrap().len(), 1);
    }

    #[test]
    fn nonzero_retained_origins_and_high_sequence_boundaries_do_not_expand_the_span() {
        for origin in [17, 1_u64 << 40, u64::MAX - 2] {
            let directory = tempfile::tempdir().unwrap();
            let base = directory.path();
            fixture(&journal_file_path(base, 0), &[(origin, accepted()), (origin + 1, cancelled())]);
            let recovered = AppendJournal::new(config(base), key()).unwrap();
            assert_eq!(recovered.get_stats().sequence, origin + 2);
            assert_eq!(recovered.read_all_entries_from_disk().unwrap().len(), 2);
        }
        let directory = tempfile::tempdir().unwrap();
        fixture(&journal_file_path(directory.path(), 0), &[(0, accepted()), (u64::MAX, cancelled())]);
        assert!(matches!(AppendJournal::new(config(directory.path()), key()),
            Outcome::Err(JournalError::Deserialization(reason)) if reason.contains("sequence gap")));
        let directory = tempfile::tempdir().unwrap();
        fixture(&journal_file_path(directory.path(), 0), &[(u64::MAX, accepted())]);
        assert!(matches!(AppendJournal::new(config(directory.path()), key()),
            Outcome::Err(JournalError::Deserialization(reason)) if reason.contains("exhausted")));
    }

    #[test]
    fn reordered_snapshot_discovered_after_open_cannot_authorize_retention() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        let original = fixture(&journal_file_path(base, 0), &[(0, accepted()), (1, cancelled())]);
        let snapshot_path = journal_file_path(base, 1);
        fixture(&snapshot_path, &[(0, accepted()), (1, cancelled())]);
        let mut journal = AppendJournal::new(config(base), key()).unwrap();
        let mut reversed = Vec::new();
        for (sequence, record) in [(1, cancelled()), (0, accepted())] {
            let entry = JournalEntry::try_new(sequence, record.with_signature(&key())).unwrap();
            storage::write_frame(&mut reversed, &entry.encode()).unwrap();
        }
        // Fault only a test-owned snapshot after the real reader has opened it.
        // The original generation remains available and is never deleted here.
        std::fs::write(&snapshot_path, &reversed).unwrap();
        assert!(matches!(journal.compact(),
            Outcome::Err(JournalError::Deserialization(reason)) if reason.contains("non-increasing")));
        assert!(journal.storage_failed);
        assert!(journal.get_resume_summary("discovery").is_err());
        assert_eq!(std::fs::read(journal_file_path(base, 0)).unwrap(), original);
        assert_eq!(std::fs::read(snapshot_path).unwrap(), reversed);
        assert!(!journal_file_path(base, 2).exists());
    }
