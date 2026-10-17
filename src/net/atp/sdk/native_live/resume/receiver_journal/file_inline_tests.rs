    use super::super::super::{Hello, advance, digest, encode_epoch, initial, offer};
    use super::*;

    fn files() -> (PathBuf, PathBuf) {
        let directory = tempfile::tempdir().unwrap().keep();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        (
            directory.join("receiver.wal"),
            directory.join("receiver.data"),
        )
    }
    fn limits() -> ReceiverFileLimits {
        ReceiverFileLimits {
            max_data_bytes: 64,
            max_snapshots: 16,
            max_journal_bytes: 65536,
        }
    }
    fn checkpoints() -> (ReceiverCheckpoint, ReceiverCheckpoint, ReceiverCheckpoint) {
        let hello = Hello {
            nonce: [9; 32],
            epoch_bytes: 8,
            max_bytes: 64,
        };
        let start = ReceiverCheckpoint {
            client: NativeClientCertificateId::from_sha256([3; 32]),
            offered: offer(&hello).try_into().unwrap(),
            agreed: offer(&hello).try_into().unwrap(),
            prefix: initial(&hello),
            prefix_hash: digest(&Sha256::new()),
            pending_hash: digest(&Sha256::new()),
            used: 1,
            maximum: 4,
            phase: ReceiverCheckpointPhase::Receiving,
            pending: Zeroizing::new(Vec::new()),
        };
        let mut pending = start.clone();
        pending.pending = Zeroizing::new(encode_epoch(&start.prefix, b"abcdefgh"));
        pending.pending_hash = Sha256::digest(b"abcdefgh").into();
        let mut stable = pending.clone();
        stable.prefix = advance(&start.prefix, &pending.pending, 8, 64).unwrap();
        stable.prefix_hash = pending.pending_hash;
        stable.pending = Zeroizing::new(Vec::new());
        (start, pending, stable)
    }
    fn append_data(store: &ReceiverJournalFile, bytes: &[u8]) {
        (&store.storage.data).write_all(bytes).unwrap();
        store.storage.data.sync_all().unwrap();
    }

    fn finalizing_files(
        limits: ReceiverFileLimits,
        empty: bool,
    ) -> (PathBuf, PathBuf, LiveStreamReceipt) {
        let (journal, data) = files();
        let (start, pending, stable) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits).unwrap();
        store.storage.append(start.clone()).unwrap();
        let mut finalizing = if empty {
            start
        } else {
            store.storage.append(pending).unwrap();
            append_data(&store, b"abcdefgh");
            store.storage.append(stable.clone()).unwrap();
            stable
        };
        finalizing.phase = ReceiverCheckpointPhase::Finalizing;
        store.storage.append(finalizing.clone()).unwrap();
        (journal, data, finalizing.receipt())
    }

    #[test]
    fn resolve_finalizing_revalidates_and_records_completion_without_replacing_files() {
        for empty in [false, true] {
            let (journal, data, expected) = finalizing_files(limits(), empty);
            let history = std::fs::read(&journal).unwrap();
            let payload = std::fs::read(&data).unwrap();
            let journal_inode = std::fs::metadata(&journal).unwrap().ino();
            let data_inode = std::fs::metadata(&data).unwrap().ino();
            let mut store = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
            let before = store.checkpoint().unwrap();
            let observer = store.observer();
            assert_eq!(before.phase(), ReceiverCheckpointPhase::Finalizing);
            assert!(before.committed_receipt().is_none());
            let records = store.storage.state.lock().records;
            assert_eq!(store.resolve_finalizing().unwrap(), expected);
            assert_eq!(store.storage.state.lock().records, records + 1);
            let saved = store.checkpoint().unwrap();
            assert_eq!(saved.phase(), ReceiverCheckpointPhase::Committed);
            assert_eq!(saved.committed_receipt(), Some(expected.clone()));
            assert_eq!(saved.attempts(), before.attempts());
            assert_eq!(saved.maximum_attempts(), before.maximum_attempts());
            assert_eq!(
                observer.checkpoint().unwrap().committed_receipt(),
                Some(expected.clone())
            );
            let committed_history = std::fs::read(&journal).unwrap();
            assert!(committed_history.starts_with(&history));
            assert!(committed_history.len() > history.len());
            assert_eq!(store.resolve_finalizing().unwrap(), expected);
            assert_eq!(std::fs::read(&journal).unwrap(), committed_history);
            assert_eq!(store.storage.state.lock().records, records + 1);
            assert_eq!(std::fs::read(&data).unwrap(), payload);
            assert_eq!(std::fs::metadata(&journal).unwrap().ino(), journal_inode);
            assert_eq!(std::fs::metadata(&data).unwrap().ino(), data_inode);
            drop(store);
            let reopened = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
            assert_eq!(
                reopened.checkpoint().unwrap().committed_receipt(),
                Some(expected)
            );
            // Ordinary handoff still rejects Finalizing, but this durable
            // completion is eligible for authenticated Proof-only restoration.
            let session = reopened.service_session().unwrap();
            assert_eq!(std::fs::read(&journal).unwrap(), committed_history);
            assert!(ReceiverJournalFile::open_existing(&journal, &data).is_err());
            drop(session);
        }
    }

    #[test]
    fn resolve_finalizing_refuses_modified_data_length_and_replaced_identity() {
        for corruption in ["hash", "short", "extra", "inode", "link"] {
            let (journal, data, _) = finalizing_files(limits(), false);
            let history = std::fs::read(&journal).unwrap();
            let mut store = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
            match corruption {
                "hash" => {
                    let mut file = OpenOptions::new().write(true).open(&data).unwrap();
                    file.write_all(b"X").unwrap();
                    file.sync_all().unwrap();
                }
                "short" => {
                    let file = OpenOptions::new().write(true).open(&data).unwrap();
                    file.set_len(4).unwrap();
                    file.sync_all().unwrap();
                }
                "extra" => append_data(&store, b"X"),
                "inode" => {
                    std::fs::rename(&data, data.with_extension("retained-original")).unwrap();
                    let mut replacement = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&data)
                        .unwrap();
                    replacement.write_all(b"abcdefgh").unwrap();
                    replacement.sync_all().unwrap();
                }
                "link" => std::fs::hard_link(&data, data.with_extension("second-link")).unwrap(),
                _ => unreachable!(),
            }
            assert_eq!(
                store.resolve_finalizing().unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{corruption}"
            );
            assert_eq!(std::fs::read(&journal).unwrap(), history, "{corruption}");
            assert_eq!(
                store.observer().checkpoint().unwrap().phase(),
                ReceiverCheckpointPhase::Finalizing
            );
        }
    }

    #[test]
    fn resolve_finalizing_requires_intent_and_confirmed_journal_ownership() {
        let (journal, data) = files();
        let (start, _, _) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        store.storage.append(start).unwrap();
        drop(store);
        let mut store = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        let history = std::fs::read(&journal).unwrap();
        assert_eq!(
            store.resolve_finalizing().unwrap_err().to_string(),
            "receiver has no final commit intent"
        );
        assert_eq!(std::fs::read(&journal).unwrap(), history);

        let (journal, data, _) = finalizing_files(limits(), false);
        let mut store = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        let history = std::fs::read(&journal).unwrap();
        // A pending checkpoint owns the storage operation. Resolution must not
        // run concurrently with it or discard a dropped wait's pending result.
        store.pending = Some(Box::pin(std::future::pending()));
        assert_eq!(
            store.resolve_finalizing().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(std::fs::read(&journal).unwrap(), history);
        drop(store);

        let mut store = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        let mut external = OpenOptions::new().append(true).open(&journal).unwrap();
        external.write_all(&[0]).unwrap();
        external.sync_all().unwrap();
        let modified = std::fs::read(&journal).unwrap();
        assert_eq!(
            store.resolve_finalizing().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(std::fs::read(&journal).unwrap(), modified);
        store.storage.state.lock().poisoned = true;
        assert_eq!(
            store.resolve_finalizing().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(std::fs::read(&journal).unwrap(), modified);
    }

    #[test]
    fn resolve_finalizing_cannot_claim_completion_when_the_terminal_record_does_not_fit() {
        let (journal, data, _) = finalizing_files(
            ReceiverFileLimits {
                max_snapshots: 5,
                ..limits()
            },
            false,
        );
        // Retain coverage for a Finalizing WAL produced by the old writer,
        // which admitted this record with only four total snapshot slots.
        // New appenders refuse that transition before the commit can start.
        let mut legacy = std::fs::read(&journal).unwrap();
        legacy[8..12].copy_from_slice(&4_u32.to_be_bytes());
        let mut previous = hash(&[], &legacy[..64]);
        legacy[64..HEADER].copy_from_slice(&previous);
        let mut at = HEADER;
        while at < legacy.len() {
            let size = u32::from_be_bytes(legacy[at + 8..at + 12].try_into().unwrap()) as usize;
            let end = at + 16 + size;
            previous = hash(&previous, &legacy[at..end]);
            legacy[end..end + 32].copy_from_slice(&previous);
            at = end + 32;
        }
        std::fs::write(&journal, &legacy).unwrap();
        let history = std::fs::read(&journal).unwrap();
        let mut store = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        assert_eq!(store.storage.state.lock().records, 4);
        assert_eq!(
            store
                .storage
                .append(store.checkpoint().unwrap())
                .unwrap_err()
                .kind(),
            io::ErrorKind::StorageFull
        );
        assert_eq!(
            store.resolve_finalizing().unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        assert_eq!(
            store.checkpoint().unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        assert_eq!(
            store.observer().checkpoint().unwrap().phase(),
            ReceiverCheckpointPhase::Finalizing
        );
        assert_eq!(std::fs::read(&journal).unwrap(), history);
        assert_eq!(std::fs::read(&data).unwrap(), b"abcdefgh");
        drop(store);
        let mut reopened = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        assert_eq!(
            reopened.checkpoint().unwrap().phase(),
            ReceiverCheckpointPhase::Finalizing
        );
        assert_eq!(
            reopened.resolve_finalizing().unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        assert_eq!(std::fs::read(&journal).unwrap(), history);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn finalizing_reserves_terminal_capacity_across_profiles_reopen_and_retry() {
        for compact in [false, true] {
            for empty in [false, true] {
                for byte_limit in [false, true] {
                    for fits in [false, true] {
                        let (journal, data) = files();
                        let intent = journal.with_extension("intent");
                        let (start, pending, stable) = checkpoints();
                        let header = if compact { 128 } else { 96 };
                        // The terminal records carry no pending payload. These
                        // independent format bounds include every frame/checksum.
                        let terminal_bytes = 365;
                        let epoch_bytes = if compact { 477 } else { 453 };
                        let complete_bytes = header
                            + 3 * terminal_bytes
                            + if empty { 0 } else { epoch_bytes + terminal_bytes };
                        let complete_records = if empty { 3 } else { 5 };
                        let limits = ReceiverFileLimits {
                            max_data_bytes: 64,
                            max_snapshots: complete_records - u32::from(!fits && !byte_limit),
                            max_journal_bytes: complete_bytes - u64::from(!fits && byte_limit),
                        };
                        let store = if compact {
                            ReceiverJournalFile::create_new_compact(
                                &journal,
                                &data,
                                &intent,
                                ReceiverCompactFileLimits {
                                    max_data_bytes: limits.max_data_bytes,
                                    max_snapshots: limits.max_snapshots,
                                    max_journal_bytes: limits.max_journal_bytes,
                                },
                            )
                        } else {
                            ReceiverJournalFile::create_new(&journal, &data, limits)
                        }
                        .unwrap();
                        store.storage.append(start.clone()).unwrap();
                        let mut finalizing = if empty {
                            start
                        } else {
                            store.storage.append(pending).unwrap();
                            append_data(&store, b"abcdefgh");
                            store.storage.append(stable.clone()).unwrap();
                            stable
                        };
                        finalizing.phase = ReceiverCheckpointPhase::Finalizing;
                        let before = std::fs::read(&journal).unwrap();
                        let result = store.storage.append(finalizing.clone());
                        if fits {
                            result.unwrap();
                            let admitted = std::fs::read(&journal).unwrap();
                            // Identical retries reuse Finalizing; an attempt
                            // update cannot steal its one reserved terminal slot.
                            store.storage.append(finalizing.clone()).unwrap();
                            let mut retry = finalizing.clone();
                            retry.used += 1;
                            assert_eq!(
                                store.storage.append(retry).unwrap_err().kind(),
                                io::ErrorKind::StorageFull
                            );
                            assert_eq!(std::fs::read(&journal).unwrap(), admitted);
                        } else {
                            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::StorageFull);
                            assert_eq!(std::fs::read(&journal).unwrap(), before);
                            assert!(!store.storage.state.lock().poisoned);
                            assert_eq!(
                                store.observer().checkpoint().unwrap().phase(),
                                ReceiverCheckpointPhase::Receiving
                            );
                        }
                        drop(store);
                        let mut reopened = if compact {
                            ReceiverJournalFile::open_existing_compact(&journal, &data, &intent)
                        } else {
                            ReceiverJournalFile::open_existing(&journal, &data)
                        }
                        .unwrap();
                        if fits {
                            assert_eq!(
                                reopened.resolve_finalizing().unwrap(),
                                finalizing.receipt()
                            );
                            let complete = std::fs::read(&journal).unwrap();
                            assert_eq!(complete.len() as u64, complete_bytes);
                            assert_eq!(reopened.storage.state.lock().records, complete_records);
                            assert_eq!(
                                reopened.resolve_finalizing().unwrap(),
                                finalizing.receipt()
                            );
                            assert_eq!(std::fs::read(&journal).unwrap(), complete);
                        } else {
                            assert_eq!(
                                reopened.storage.append(finalizing).unwrap_err().kind(),
                                io::ErrorKind::StorageFull
                            );
                            assert_eq!(std::fs::read(&journal).unwrap(), before);
                            assert_eq!(
                                reopened.checkpoint().unwrap().phase(),
                                ReceiverCheckpointPhase::Receiving
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn exact_inode_and_pending_intent_survive_reopen_with_partial_data() {
        let (journal, data) = files();
        let (start, pending, stable) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        store.storage.append(start).unwrap();
        store.storage.append(pending.clone()).unwrap();
        append_data(&store, b"abc");
        assert!(ReceiverJournalFile::open_existing(&journal, &data).is_err());
        let before = std::fs::read(&journal).unwrap();
        let inode = std::fs::metadata(&data).unwrap().ino();
        drop(store);
        let reopened = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        assert_eq!(
            reopened
                .checkpoint()
                .unwrap()
                .to_canonical_bytes()
                .unwrap()
                .as_slice(),
            pending.to_canonical_bytes().unwrap().as_slice()
        );
        assert_eq!(std::fs::read(&data).unwrap(), b"abc");
        append_data(&reopened, b"defgh");
        reopened.storage.append(stable).unwrap();
        drop(reopened);
        let complete = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        assert_eq!(complete.checkpoint().unwrap().prefix().bytes, 8);
        assert_eq!(std::fs::metadata(&data).unwrap().ino(), inode);
        assert_eq!(std::fs::read(&data).unwrap(), b"abcdefgh");
        assert!(std::fs::read(&journal).unwrap().starts_with(&before));
    }

    #[test]
    fn snapshot_exhaustion_is_persistent_and_identical_records_are_idempotent() {
        let (journal, data) = files();
        let (start, pending, _) = checkpoints();
        let store = ReceiverJournalFile::create_new(
            &journal,
            &data,
            ReceiverFileLimits {
                max_snapshots: 1,
                ..limits()
            },
        )
        .unwrap();
        store.storage.append(start.clone()).unwrap();
        let bytes = std::fs::read(&journal).unwrap();
        store.storage.append(start).unwrap();
        assert_eq!(std::fs::read(&journal).unwrap(), bytes);
        assert_eq!(
            store.storage.append(pending.clone()).unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        drop(store);
        let reopened = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        assert_eq!(
            reopened.storage.append(pending).unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        assert_eq!(std::fs::read(&journal).unwrap(), bytes);
        assert_eq!(std::fs::metadata(&data).unwrap().len(), 0);
    }

    #[test]
    fn a_device_number_changed_by_a_reboot_does_not_refuse_recovery() {
        let (journal, data) = files();
        let (start, _, _) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        store.storage.append(start).unwrap();
        drop(store);
        // Change both recorded device numbers, then reseal the header and the
        // record chain the way a writer before the reboot would have sealed
        // them.
        let mut bytes = std::fs::read(&journal).unwrap();
        bytes[39] ^= 1;
        bytes[55] ^= 1;
        let mut previous = hash(&[], &bytes[..64]);
        bytes[64..HEADER].copy_from_slice(&previous);
        let mut at = HEADER;
        while at < bytes.len() {
            let size = u32::from_be_bytes(bytes[at + 8..at + 12].try_into().unwrap()) as usize;
            let end = at + 16 + size;
            previous = hash(&previous, &bytes[at..end]);
            bytes[end..end + 32].copy_from_slice(&previous);
            at = end + 32;
        }
        std::fs::write(&journal, &bytes).unwrap();
        let reopened = ReceiverJournalFile::open_existing(&journal, &data)
            .expect("the recorded inodes still match");
        assert_eq!(reopened.checkpoint().unwrap().prefix().bytes, 0);
    }

    #[test]
    fn torn_history_and_inode_replacement_are_refused_without_repairs() {
        let (journal, data) = files();
        let (start, _, _) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        store.storage.append(start).unwrap();
        drop(store);
        let pristine = std::fs::read(&journal).unwrap();
        let broken = journal.with_extension("torn");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&broken)
            .unwrap();
        file.write_all(&pristine).unwrap();
        file.write_all(&[0]).unwrap();
        drop(file);
        assert!(ReceiverJournalFile::open_existing(&broken, &data).is_err());
        assert_eq!(std::fs::read(&broken).unwrap().len(), pristine.len() + 1);
        let other = data.with_extension("other");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&other)
            .unwrap();
        assert!(ReceiverJournalFile::open_existing(&journal, &other).is_err());
        let alias = data.with_extension("alias");
        std::os::unix::fs::symlink(&data, &alias).unwrap();
        assert!(ReceiverJournalFile::open_existing(&journal, &alias).is_err());
        assert_eq!(std::fs::read(&journal).unwrap(), pristine);
    }

    #[test]
    fn uncertain_append_is_sticky_and_commit_cannot_skip_its_intent_record() {
        let (journal, data) = files();
        let (start, pending, _) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        store.storage.append(start.clone()).unwrap();
        let mut committed = start.clone();
        committed.phase = ReceiverCheckpointPhase::Committed;
        assert!(store.storage.append(committed).is_err());
        let mut external = OpenOptions::new().append(true).open(&journal).unwrap();
        external.write_all(&[0]).unwrap();
        external.sync_all().unwrap();
        assert!(store.storage.append(pending).is_err());
        assert!(store.storage.append(start).is_err());
        assert!(store.storage.state.lock().poisoned);
        assert_eq!(std::fs::metadata(&data).unwrap().len(), 0);
    }

    #[test]
    fn shared_factory_handoff_keeps_both_locks_without_writing_or_binding() {
        let (journal, data) = files();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        let before = std::fs::read(&journal).unwrap();
        let session = store.service_session().unwrap();
        assert_eq!(std::fs::read(&journal).unwrap(), before);
        assert_eq!(std::fs::metadata(&data).unwrap().len(), 0);
        for path in [&journal, &data] {
            let other = OpenOptions::new().read(true).write(true).open(path).unwrap();
            assert!(other.try_lock().is_err());
        }
        drop(session);
        for path in [&journal, &data] {
            let other = OpenOptions::new().read(true).write(true).open(path).unwrap();
            assert!(other.try_lock().is_ok());
        }
        assert_eq!(std::fs::read(&journal).unwrap(), before);
    }

    #[test]
    fn shared_handoff_retains_history_and_refuses_uncertain_or_unrecorded_state() {
        let (journal, data) = files();
        let (start, pending, _) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        store.storage.append(start).unwrap();
        store.storage.append(pending).unwrap();
        append_data(&store, b"abc");
        drop(store);
        let before = std::fs::read(&journal).unwrap();
        let reopened = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
        let session = reopened.service_session().unwrap();
        assert_eq!(std::fs::read(&journal).unwrap(), before);
        assert_eq!(std::fs::read(&data).unwrap(), b"abc");
        assert!(ReceiverJournalFile::open_existing(&journal, &data).is_err());
        drop(session);

        let (journal, data) = files();
        let (start, _, _) = checkpoints();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        store.storage.append(start.clone()).unwrap();
        let mut uncertain = start;
        uncertain.phase = ReceiverCheckpointPhase::Finalizing;
        store.storage.append(uncertain).unwrap();
        drop(store);
        let before = std::fs::read(&journal).unwrap();
        assert!(ReceiverJournalFile::open_existing(&journal, &data).unwrap().service_session().is_err());
        assert_eq!(std::fs::read(&journal).unwrap(), before);

        let (journal, data) = files();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        append_data(&store, b"unrecorded");
        assert!(store.service_session().is_err());
        assert_eq!(std::fs::read(&data).unwrap(), b"unrecorded");
    }

    #[test]
    fn observer_is_nonblocking_nonowning_and_distinguishes_commit_intent() {
        let (journal, data) = files();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        let observer = store.observer();
        let copy = observer.clone();
        assert_eq!(observer.checkpoint().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        let (start, _, _) = checkpoints();
        store.storage.append(start.clone()).unwrap();
        let snapshot = observer.checkpoint().unwrap();
        assert_eq!(snapshot.prefix().bytes, 0);
        assert!(snapshot.committed_receipt().is_none());
        {
            // Calling from the thread that already owns this lock must not deadlock.
            let _updating = store.storage.state.lock();
            assert_eq!(copy.checkpoint().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        }
        let mut finalizing = start;
        finalizing.phase = ReceiverCheckpointPhase::Finalizing;
        store.storage.append(finalizing.clone()).unwrap();
        assert_eq!(observer.checkpoint().unwrap().phase(), ReceiverCheckpointPhase::Finalizing);
        assert!(observer.checkpoint().unwrap().committed_receipt().is_none());
        store.storage.commit(&finalizing.receipt()).unwrap();
        let mut committed = finalizing;
        committed.phase = ReceiverCheckpointPhase::Committed;
        store.storage.append(committed.clone()).unwrap();
        let confirmed = copy.checkpoint().unwrap();
        assert_eq!(confirmed.committed_receipt(), committed.committed_receipt());
        let history = std::fs::read(&journal).unwrap();
        assert!(!format!("{observer:?}").contains("receiver.wal"));
        drop(store);
        assert_eq!(observer.checkpoint().unwrap_err().kind(), io::ErrorKind::NotConnected);
        assert_eq!(copy.checkpoint().unwrap_err().kind(), io::ErrorKind::NotConnected);
        // Neither observers nor returned snapshots keep the original locks alive.
        for path in [&journal, &data] {
            assert!(OpenOptions::new().read(true).write(true).open(path).unwrap().try_lock().is_ok());
        }
        assert_eq!(std::fs::read(&journal).unwrap(), history);
        assert_eq!(confirmed.phase(), ReceiverCheckpointPhase::Committed);
        assert_eq!(snapshot.phase(), ReceiverCheckpointPhase::Receiving);
    }

    #[test]
    fn observer_refuses_unconfirmed_persistence_without_fabricating_a_new_snapshot() {
        let (journal, data) = files();
        let store = ReceiverJournalFile::create_new(&journal, &data, limits()).unwrap();
        let observer = store.observer();
        let (start, pending, _) = checkpoints();
        store.storage.append(start).unwrap();
        let prior = observer.checkpoint().unwrap();
        let mut corruptor = OpenOptions::new().append(true).open(&journal).unwrap();
        corruptor.write_all(&[0]).unwrap();
        corruptor.sync_all().unwrap();
        assert!(store.storage.append(pending).is_err());
        assert!(store.storage.state.lock().poisoned);
        assert_eq!(observer.checkpoint().unwrap_err().kind(), io::ErrorKind::Other);
        assert_eq!(prior.pending_bytes(), 0);
        assert!(prior.committed_receipt().is_none());
        assert_eq!(std::fs::metadata(&data).unwrap().len(), 0);
    }

    fn compact_limits() -> ReceiverCompactFileLimits {
        ReceiverCompactFileLimits {
            max_data_bytes: 64,
            max_snapshots: 32,
            max_journal_bytes: 65_536,
        }
    }

    fn compact_epoch(
        previous: &ReceiverCheckpoint,
        bytes: &[u8],
        hash: &mut Sha256,
    ) -> (ReceiverCheckpoint, ReceiverCheckpoint) {
        let agreed = super::super::decode_offer(&previous.agreed).unwrap();
        let mut pending = previous.clone();
        pending.pending = Zeroizing::new(encode_epoch(&previous.prefix, bytes));
        hash.update(bytes);
        pending.pending_hash = digest(hash);
        let mut stable = pending.clone();
        stable.prefix = advance(
            &previous.prefix,
            &pending.pending,
            agreed.epoch_bytes,
            agreed.max_bytes,
        )
        .unwrap();
        stable.prefix_hash = pending.pending_hash;
        stable.pending = Zeroizing::new(Vec::new());
        (pending, stable)
    }

    #[test]
    fn compact_default_budgets_cover_four_gib_of_full_epochs_without_payload_history() {
        let limits = ReceiverCompactFileLimits::default();
        limits.validate().unwrap();
        let hello = Hello {
            nonce: [9; 32],
            epoch_bytes: 65_536,
            max_bytes: 4 * 1024 * 1024 * 1024,
        };
        let mut start = checkpoints().0;
        start.offered = offer(&hello).try_into().unwrap();
        start.agreed = start.offered;
        start.prefix = initial(&hello);
        let (pending, stable) = compact_epoch(&start, &vec![42; 65_536], &mut Sha256::new());
        let start_bytes = compact::encode(&start.to_canonical_bytes().unwrap()).unwrap();
        let pending_bytes = compact::encode(&pending.to_canonical_bytes().unwrap()).unwrap();
        let stable_bytes = compact::encode(&stable.to_canonical_bytes().unwrap()).unwrap();
        assert_eq!(pending.to_canonical_bytes().unwrap().len(), 65_933);
        assert_eq!(pending_bytes.len(), 429);
        assert_eq!(stable_bytes.len(), 317);
        let epochs = hello.max_bytes / hello.epoch_bytes as u64;
        let snapshots = 2 * epochs + 3;
        let wal_bytes = compact::HEADER as u64
            + epochs * (pending_bytes.len() + stable_bytes.len() + 96) as u64
            + 3 * (start_bytes.len() + 48) as u64;
        assert_eq!(snapshots, 131_075);
        assert_eq!(wal_bytes, 55_182_535);
        assert!(snapshots <= u64::from(limits.max_snapshots));
        assert!(wal_bytes <= limits.max_journal_bytes);
        assert_eq!(compact::INTENT_BYTES, 131_328);
        // The legacy limits and V1 admission remain unchanged.
        assert!(limits.storage_limits().validate().is_err());
    }

    #[test]
    fn compact_history_rehydrates_after_both_slots_are_reused_and_rejects_changed_old_data() {
        let (journal, data) = files();
        let intent = data.with_extension("intent");
        let store =
            ReceiverJournalFile::create_new_compact(&journal, &data, &intent, compact_limits())
                .unwrap();
        let mut stable = checkpoints().0;
        store.storage.append(stable.clone()).unwrap();
        let mut hash = Sha256::new();
        let mut content = Vec::new();
        for epoch in 0..8_u8 {
            let bytes = [epoch + 1; 8];
            let (pending, next) = compact_epoch(&stable, &bytes, &mut hash);
            store.storage.append(pending).unwrap();
            append_data(&store, &bytes);
            store.storage.append(next.clone()).unwrap();
            content.extend_from_slice(&bytes);
            stable = next;
        }
        let inodes: Vec<_> = [&journal, &data, &intent]
            .iter()
            .map(|path| std::fs::metadata(path).unwrap().ino())
            .collect();
        stable.phase = ReceiverCheckpointPhase::Finalizing;
        store.storage.append(stable.clone()).unwrap();
        drop(store);
        let history = std::fs::read(&journal).unwrap();
        let mut reopened =
            ReceiverJournalFile::open_existing_compact(&journal, &data, &intent).unwrap();
        assert_eq!(reopened.checkpoint().unwrap().prefix().bytes, 64);
        assert_eq!(reopened.checkpoint().unwrap().attempts(), 1);
        assert_eq!(reopened.resolve_finalizing().unwrap(), stable.receipt());
        assert_eq!(std::fs::read(&data).unwrap(), content);
        assert!(std::fs::read(&journal).unwrap().starts_with(&history));
        for (path, inode) in [&journal, &data, &intent].iter().zip(inodes) {
            assert_eq!(std::fs::metadata(path).unwrap().ino(), inode);
        }
        assert_eq!(std::fs::metadata(&intent).unwrap().len(), 131_328);
        drop(reopened);
        assert!(ReceiverJournalFile::open_existing(&journal, &data).is_err());

        // Epoch zero's slot has been overwritten several times. Its original
        // data bytes must still match the commitment in its historical record.
        let history = std::fs::read(&journal).unwrap();
        let mut corruptor = OpenOptions::new().write(true).open(&data).unwrap();
        corruptor.write_all(b"X").unwrap();
        corruptor.sync_all().unwrap();
        assert_eq!(
            ReceiverJournalFile::open_existing_compact(&journal, &data, &intent)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(std::fs::read(&journal).unwrap(), history);
    }

    #[test]
    fn compact_pending_slots_restore_every_surviving_tail_and_keep_all_three_locks() {
        for surviving in 0..=8 {
            let (journal, data) = files();
            let intent = data.with_extension("intent");
            let (start, pending, _) = checkpoints();
            let store =
                ReceiverJournalFile::create_new_compact(&journal, &data, &intent, compact_limits())
                    .unwrap();
            store.storage.append(start).unwrap();
            store.storage.append(pending.clone()).unwrap();
            append_data(&store, &b"abcdefgh"[..surviving]);
            let history = std::fs::read(&journal).unwrap();
            drop(store);
            let reopened =
                ReceiverJournalFile::open_existing_compact(&journal, &data, &intent).unwrap();
            assert_eq!(
                reopened.checkpoint().unwrap().to_canonical_bytes().unwrap().as_slice(),
                pending.to_canonical_bytes().unwrap().as_slice()
            );
            let session = reopened.service_session().unwrap();
            for path in [&journal, &data, &intent] {
                assert!(
                    OpenOptions::new().read(true).write(true).open(path).unwrap().try_lock().is_err()
                );
            }
            assert_eq!(std::fs::read(&data).unwrap(), b"abcdefgh"[..surviving]);
            assert_eq!(std::fs::read(&journal).unwrap(), history);
            drop(session);
            for path in [&journal, &data, &intent] {
                assert!(
                    OpenOptions::new().read(true).write(true).open(path).unwrap().try_lock().is_ok()
                );
            }
        }
    }

    #[test]
    fn compact_prepared_or_torn_next_slot_does_not_erase_the_last_checkpoint() {
        for torn in [false, true] {
            let (journal, data) = files();
            let intent = data.with_extension("intent");
            let (start, pending, stable) = checkpoints();
            let store =
                ReceiverJournalFile::create_new_compact(&journal, &data, &intent, compact_limits())
                    .unwrap();
            store.storage.append(start).unwrap();
            store.storage.append(pending).unwrap();
            append_data(&store, b"abcdefgh");
            store.storage.append(stable.clone()).unwrap();
            let history = std::fs::read(&journal).unwrap();
            let slots = std::fs::read(&intent).unwrap();
            let mut hash = Sha256::new();
            hash.update(b"abcdefgh");
            let (next, _) = compact_epoch(&stable, b"ijklmnop", &mut hash);
            // The precise boundary is after next-slot synchronization and
            // before its intent WAL append. A process death loses only that
            // unrecorded preparation; the completed prefix remains authoritative.
            store.storage.intent.as_ref().unwrap().stage(&next).unwrap();
            if torn {
                let mut corruptor = OpenOptions::new().write(true).open(&intent).unwrap();
                corruptor.seek(SeekFrom::Start((compact::INTENT_BYTES / 2) as u64)).unwrap();
                corruptor.write_all(b"torn").unwrap();
                corruptor.sync_all().unwrap();
            }
            assert_eq!(
                &std::fs::read(&intent).unwrap()[..compact::INTENT_BYTES / 2],
                &slots[..compact::INTENT_BYTES / 2]
            );
            drop(store);
            let reopened =
                ReceiverJournalFile::open_existing_compact(&journal, &data, &intent).unwrap();
            assert_eq!(
                reopened.checkpoint().unwrap().to_canonical_bytes().unwrap().as_slice(),
                stable.to_canonical_bytes().unwrap().as_slice()
            );
            assert_eq!(std::fs::read(&journal).unwrap(), history);
            assert_eq!(std::fs::read(&data).unwrap(), b"abcdefgh");
        }
    }

    #[test]
    fn compact_retry_and_persistent_quotas_never_rewrite_the_active_pending_slot() {
        for snapshot_limit in [false, true] {
            let (journal, data) = files();
            let intent = data.with_extension("intent");
            let (start, pending, _) = checkpoints();
            let limits = ReceiverCompactFileLimits {
                max_snapshots: if snapshot_limit { 3 } else { 32 },
                max_journal_bytes: if snapshot_limit { 65_536 } else { 128 + 365 + 2 * 477 },
                ..compact_limits()
            };
            let store =
                ReceiverJournalFile::create_new_compact(&journal, &data, &intent, limits).unwrap();
            store.storage.append(start).unwrap();
            store.storage.append(pending.clone()).unwrap();
            append_data(&store, b"abc");
            let slots = std::fs::read(&intent).unwrap();
            let mut retry = pending;
            retry.used = 2;
            store.storage.append(retry.clone()).unwrap();
            let history = std::fs::read(&journal).unwrap();
            store.storage.append(retry.clone()).unwrap();
            assert_eq!(std::fs::read(&journal).unwrap(), history);
            assert_eq!(std::fs::read(&intent).unwrap(), slots);
            retry.used = 3;
            assert_eq!(store.storage.append(retry.clone()).unwrap_err().kind(), io::ErrorKind::StorageFull);
            drop(store);
            let reopened =
                ReceiverJournalFile::open_existing_compact(&journal, &data, &intent).unwrap();
            assert_eq!(reopened.checkpoint().unwrap().attempts(), 2);
            assert_eq!(reopened.storage.append(retry).unwrap_err().kind(), io::ErrorKind::StorageFull);
            assert_eq!(std::fs::read(&journal).unwrap(), history);
            assert_eq!(std::fs::read(&intent).unwrap(), slots);
            assert_eq!(std::fs::read(&data).unwrap(), b"abc");
        }
    }

    #[test]
    fn compact_partial_recovery_refuses_corrupt_or_replaced_intent_without_repair() {
        for damage in ["payload", "short", "inode", "link", "permissions"] {
            let (journal, data) = files();
            let intent = data.with_extension("intent");
            let (start, pending, _) = checkpoints();
            let store =
                ReceiverJournalFile::create_new_compact(&journal, &data, &intent, compact_limits())
                    .unwrap();
            store.storage.append(start).unwrap();
            store.storage.append(pending).unwrap();
            append_data(&store, b"abc");
            let slots = std::fs::read(&intent).unwrap();
            let history = std::fs::read(&journal).unwrap();
            drop(store);
            match damage {
                "payload" => {
                    let mut file = OpenOptions::new().write(true).open(&intent).unwrap();
                    file.seek(SeekFrom::Start(48 + 80 + 4)).unwrap();
                    file.write_all(b"X").unwrap();
                    file.sync_all().unwrap();
                }
                "short" => {
                    let file = OpenOptions::new().write(true).open(&intent).unwrap();
                    file.set_len(131_327).unwrap();
                    file.sync_all().unwrap();
                }
                "inode" => {
                    std::fs::rename(&intent, intent.with_extension("retained-original")).unwrap();
                    let mut replacement = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&intent)
                        .unwrap();
                    replacement.write_all(&slots).unwrap();
                    replacement.sync_all().unwrap();
                }
                "link" => std::fs::hard_link(&intent, intent.with_extension("second-link")).unwrap(),
                "permissions" => {
                    std::fs::set_permissions(&intent, std::fs::Permissions::from_mode(0o640)).unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(
                ReceiverJournalFile::open_existing_compact(&journal, &data, &intent)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData,
                "{damage}"
            );
            assert_eq!(std::fs::read(&journal).unwrap(), history, "{damage}");
            assert_eq!(std::fs::read(&data).unwrap(), b"abc", "{damage}");
        }
    }

    #[test]
    fn compact_torn_reused_payload_falls_back_to_durable_history_and_continues() {
        let (journal, data) = files();
        let intent = data.with_extension("intent");
        let store =
            ReceiverJournalFile::create_new_compact(&journal, &data, &intent, compact_limits())
                .unwrap();
        let mut stable = checkpoints().0;
        store.storage.append(stable.clone()).unwrap();
        let mut hash = Sha256::new();
        for bytes in [b"abcdefgh", b"ijklmnop"] {
            let (pending, next) = compact_epoch(&stable, bytes, &mut hash);
            store.storage.append(pending).unwrap();
            append_data(&store, bytes);
            store.storage.append(next.clone()).unwrap();
            stable = next;
        }
        let history = std::fs::read(&journal).unwrap();
        let slots = std::fs::read(&intent).unwrap();
        let (pending, next) = compact_epoch(&stable, b"qrstuvwx", &mut hash);
        store.storage.intent.as_ref().unwrap().stage(&pending).unwrap();
        // Model torn sector persistence during epoch two's reuse of slot zero:
        // retain epoch zero's matching header/checksum and epoch header, but
        // leave the new payload underneath. No epoch-two intent record exists.
        let mut torn = OpenOptions::new().write(true).open(&intent).unwrap();
        torn.write_all(&slots[..48 + 80]).unwrap();
        torn.sync_all().unwrap();
        let mixed = std::fs::read(&intent).unwrap();
        assert_eq!(&mixed[..48 + 80], &slots[..48 + 80]);
        assert_ne!(&mixed[48 + 80..48 + 88], &slots[48 + 80..48 + 88]);
        assert_eq!(std::fs::read(&journal).unwrap(), history);
        drop(torn);
        drop(store);

        let reopened =
            ReceiverJournalFile::open_existing_compact(&journal, &data, &intent).unwrap();
        assert_eq!(
            reopened.checkpoint().unwrap().to_canonical_bytes().unwrap().as_slice(),
            stable.to_canonical_bytes().unwrap().as_slice()
        );
        assert_eq!(std::fs::read(&data).unwrap(), b"abcdefghijklmnop");
        assert_eq!(std::fs::read(&journal).unwrap(), history);
        // The next admitted epoch can reuse the unrecorded slot and continue.
        reopened.storage.append(pending).unwrap();
        append_data(&reopened, b"qrstuvwx");
        reopened.storage.append(next).unwrap();
        drop(reopened);
        let restored =
            ReceiverJournalFile::open_existing_compact(&journal, &data, &intent).unwrap();
        assert_eq!(restored.checkpoint().unwrap().prefix().bytes, 24);
        assert_eq!(std::fs::read(&data).unwrap(), b"abcdefghijklmnopqrstuvwx");
        assert!(std::fs::read(&journal).unwrap().starts_with(&history));
    }
