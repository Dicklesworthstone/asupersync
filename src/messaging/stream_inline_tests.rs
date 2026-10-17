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
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_region(index: u32) -> RegionId {
        RegionId::new_for_test(index, 1)
    }

    fn stream_config(filter: &str) -> StreamConfig {
        StreamConfig {
            subject_filter: SubjectPattern::new(filter),
            ..StreamConfig::default()
        }
    }

    fn make_default_stream() -> Stream<InMemoryStorageBackend> {
        Stream::new(
            "test-stream",
            test_region(1),
            Time::from_secs(0),
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("create test stream")
    }

    #[derive(Debug, Default)]
    struct TruncateSkipsOnceBackend {
        inner: InMemoryStorageBackend,
        skip_next_truncate: bool,
    }

    impl StorageBackend for TruncateSkipsOnceBackend {
        fn append(&mut self, record: StreamRecord) -> Result<(), StreamError> {
            self.inner.append(record)
        }

        fn get(&self, seq: u64) -> Result<Option<StreamRecord>, StreamError> {
            self.inner.get(seq)
        }

        fn range(&self, seqs: RangeInclusive<u64>) -> Result<Vec<StreamRecord>, StreamError> {
            self.inner.range(seqs)
        }

        fn truncate_through(&mut self, through_seq: u64) -> Result<Vec<StreamRecord>, StreamError> {
            if self.skip_next_truncate {
                self.skip_next_truncate = false;
                return Ok(Vec::new());
            }
            self.inner.truncate_through(through_seq)
        }

        fn snapshot(&self) -> Result<StorageSnapshot, StreamError> {
            self.inner.snapshot()
        }
    }

    #[test]
    fn stream_lifecycle_append_read_and_close() {
        let mut stream = Stream::new(
            "orders",
            test_region(1),
            Time::from_secs(5),
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        let first = stream
            .append(
                Subject::new("orders.created"),
                b"alpha".to_vec(),
                Time::from_secs(6),
            )
            .expect("append first");
        let second = stream
            .append(
                Subject::new("orders.updated"),
                b"beta".to_vec(),
                Time::from_secs(7),
            )
            .expect("append second");

        assert_eq!(first.seq, 1);
        assert_eq!(second.seq, 2);
        assert_eq!(stream.get(1).expect("get first"), Some(first));
        assert_eq!(stream.range(1..=2).expect("range").len(), 2);
        assert_eq!(stream.state().msg_count, 2);
        assert_eq!(stream.state().first_seq, 1);
        assert_eq!(stream.state().last_seq, 2);

        stream.begin_close();
        assert!(stream.is_quiescent());
        stream.close().expect("close");
        assert_eq!(stream.state().lifecycle, StreamLifecycle::Closed);
    }

    #[test]
    fn stream_rejects_subjects_outside_capture_policy() {
        let mut stream = Stream::new(
            "orders",
            test_region(1),
            Time::ZERO,
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        let error = stream
            .append(
                Subject::new("payments.created"),
                b"wrong-subject".to_vec(),
                Time::from_secs(1),
            )
            .expect_err("subject outside capture policy");

        assert_eq!(
            error,
            StreamError::SubjectNotCaptured {
                subject: "payments.created".to_owned(),
                filter: "orders.>".to_owned(),
            }
        );
        assert_eq!(stream.state().msg_count, 0);
    }

    #[test]
    fn reply_capture_policy_accepts_inbox_subjects() {
        let mut config = stream_config("orders.>");
        config.capture_policy = CapturePolicy::IncludeReplySubjects;
        let mut stream = Stream::new(
            "orders",
            test_region(1),
            Time::ZERO,
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        let record = stream
            .append(
                Subject::new("_INBOX.orders.worker.1"),
                b"reply".to_vec(),
                Time::from_secs(1),
            )
            .expect("reply capture");

        assert_eq!(record.seq, 1);
        assert_eq!(stream.state().msg_count, 1);
    }

    #[test]
    fn limits_retention_prunes_oldest_records() {
        let mut config = stream_config("orders.>");
        config.max_msgs = 2;
        let mut stream = Stream::new(
            "orders",
            test_region(1),
            Time::ZERO,
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        stream
            .append(
                Subject::new("orders.created"),
                b"one".to_vec(),
                Time::from_secs(1),
            )
            .expect("append one");
        stream
            .append(
                Subject::new("orders.updated"),
                b"two".to_vec(),
                Time::from_secs(2),
            )
            .expect("append two");
        stream
            .append(
                Subject::new("orders.cancelled"),
                b"three".to_vec(),
                Time::from_secs(3),
            )
            .expect("append three");

        assert_eq!(stream.state().msg_count, 2);
        assert_eq!(stream.state().first_seq, 2);
        assert_eq!(stream.state().last_seq, 3);
        assert!(stream.get(1).expect("get first").is_none());
        assert!(stream.get(2).expect("get second").is_some());
        assert!(stream.get(3).expect("get third").is_some());
    }

    #[test]
    fn limits_retention_prunes_by_byte_budget() {
        let mut config = stream_config("orders.>");
        config.max_bytes = 7;
        let mut stream = Stream::new(
            "orders",
            test_region(2),
            Time::ZERO,
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        stream
            .append(
                Subject::new("orders.created"),
                b"four".to_vec(),
                Time::from_secs(1),
            )
            .expect("append first");
        stream
            .append(
                Subject::new("orders.updated"),
                b"five!".to_vec(),
                Time::from_secs(2),
            )
            .expect("append second");

        assert_eq!(stream.state().msg_count, 1);
        assert_eq!(stream.state().byte_count, 5);
        assert_eq!(stream.state().first_seq, 2);
        assert_eq!(stream.state().last_seq, 2);
        assert!(stream.get(1).expect("get first").is_none());
        assert_eq!(
            stream
                .get(2)
                .expect("get second")
                .expect("retained second")
                .payload,
            b"five!".to_vec()
        );
    }

    #[test]
    fn limits_retention_prunes_only_after_age_boundary_is_exceeded() {
        let mut config = stream_config("orders.>");
        config.max_age = Some(Duration::from_secs(5));
        let mut stream = Stream::new(
            "orders",
            test_region(3),
            Time::ZERO,
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        stream
            .append(
                Subject::new("orders.created"),
                b"first".to_vec(),
                Time::from_secs(1),
            )
            .expect("append first");
        stream
            .append(
                Subject::new("orders.updated"),
                b"second".to_vec(),
                Time::from_secs(6),
            )
            .expect("append boundary");

        assert_eq!(stream.state().msg_count, 2);
        assert!(
            stream.get(1).expect("get first").is_some(),
            "age equal to limit should be retained"
        );

        stream
            .append(
                Subject::new("orders.cancelled"),
                b"third".to_vec(),
                Time::from_secs(7),
            )
            .expect("append past boundary");

        assert_eq!(stream.state().msg_count, 2);
        assert_eq!(stream.state().first_seq, 2);
        assert_eq!(stream.state().last_seq, 3);
        assert!(
            stream.get(1).expect("get first").is_none(),
            "age above limit should prune oldest"
        );
        assert!(stream.get(2).expect("get second").is_some());
        assert!(stream.get(3).expect("get third").is_some());
    }

    #[test]
    fn non_limits_retention_modes_preserve_records_even_with_limits_set() {
        for retention in [RetentionPolicy::WorkQueue, RetentionPolicy::Interest] {
            let mut config = stream_config("orders.>");
            config.retention = retention;
            config.max_msgs = 1;
            config.max_bytes = 1;
            config.max_age = Some(Duration::from_secs(1));
            let mut stream = Stream::new(
                "orders",
                test_region(4),
                Time::ZERO,
                config,
                InMemoryStorageBackend::default(),
            )
            .expect("stream");

            stream
                .append(
                    Subject::new("orders.created"),
                    b"first".to_vec(),
                    Time::from_secs(1),
                )
                .expect("append first");
            stream
                .append(
                    Subject::new("orders.updated"),
                    b"second".to_vec(),
                    Time::from_secs(10),
                )
                .expect("append second");

            assert_eq!(stream.state().msg_count, 2, "retention={retention:?}");
            assert_eq!(stream.state().first_seq, 1, "retention={retention:?}");
            assert_eq!(stream.state().last_seq, 2, "retention={retention:?}");
            assert!(
                stream.get(1).expect("get first").is_some(),
                "retention={retention:?}"
            );
            assert!(
                stream.get(2).expect("get second").is_some(),
                "retention={retention:?}"
            );
        }
    }

    #[test]
    fn stream_rejects_appends_after_begin_close_and_after_close() {
        let mut stream = Stream::new(
            "orders",
            test_region(5),
            Time::ZERO,
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        stream.begin_close();
        let closing_error = stream
            .append(
                Subject::new("orders.created"),
                b"late".to_vec(),
                Time::from_secs(1),
            )
            .expect_err("closing stream must reject append");
        assert_eq!(
            closing_error,
            StreamError::NotAcceptingAppends {
                name: "orders".to_owned(),
                lifecycle: StreamLifecycle::Closing,
            }
        );

        let mut closed_stream = Stream::new(
            "payments",
            test_region(6),
            Time::ZERO,
            stream_config("payments.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");
        closed_stream.close().expect("close");

        let closed_error = closed_stream
            .append(
                Subject::new("payments.created"),
                b"late".to_vec(),
                Time::from_secs(1),
            )
            .expect_err("closed stream must reject append");
        assert_eq!(
            closed_error,
            StreamError::NotAcceptingAppends {
                name: "payments".to_owned(),
                lifecycle: StreamLifecycle::Closed,
            }
        );
    }

    #[test]
    fn consumer_ids_are_monotonic_and_unknown_detach_is_ignored() {
        let mut stream = Stream::new(
            "orders",
            test_region(7),
            Time::ZERO,
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        let first = stream.attach_consumer();
        let second = stream.attach_consumer();

        assert_eq!(first, 1);
        assert_eq!(second, 2);
        assert_eq!(stream.state().consumer_count, 2);
        assert!(!stream.detach_consumer(999));
        assert_eq!(stream.state().consumer_count, 2);
        assert!(stream.detach_consumer(first));
        assert_eq!(stream.state().consumer_count, 1);
        assert!(stream.detach_consumer(second));
        assert_eq!(stream.state().consumer_count, 0);
    }

    #[test]
    fn close_waits_for_child_regions_and_consumers_to_drain() {
        let mut stream = Stream::new(
            "orders",
            test_region(10),
            Time::ZERO,
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");
        let consumer = stream.attach_consumer();
        stream
            .add_mirror_region(test_region(11))
            .expect("mirror region");
        stream
            .add_source_region(test_region(12))
            .expect("source region");

        let error = stream.close().expect_err("not quiescent");
        assert_eq!(
            error,
            StreamError::NotQuiescent {
                name: "orders".to_owned(),
                consumers: 1,
                mirrors: 1,
                sources: 1,
            }
        );

        assert!(stream.detach_consumer(consumer));
        assert!(stream.remove_mirror_region(test_region(11)));
        assert!(stream.remove_source_region(test_region(12)));
        assert!(stream.is_quiescent());
        stream.close().expect("close after drain");
        assert_eq!(stream.state().lifecycle, StreamLifecycle::Closed);
    }

    #[test]
    fn child_regions_must_differ_from_owner_region() {
        let mut stream = Stream::new(
            "orders",
            test_region(10),
            Time::ZERO,
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        let error = stream
            .add_mirror_region(test_region(10))
            .expect_err("owner region cannot be its own child");
        assert_eq!(
            error,
            StreamError::ChildRegionMustDiffer {
                owner: test_region(10),
                child: test_region(10),
            }
        );
    }

    #[test]
    fn snapshot_captures_state_storage_and_child_regions() {
        let mut stream = Stream::new(
            "orders",
            test_region(20),
            Time::from_secs(10),
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        stream
            .append(
                Subject::new("orders.created"),
                b"payload".to_vec(),
                Time::from_secs(11),
            )
            .expect("append");
        stream
            .add_mirror_region(test_region(21))
            .expect("mirror region");
        stream
            .add_source_region(test_region(22))
            .expect("source region");
        let consumer = stream.attach_consumer();

        let snapshot = stream.snapshot().expect("snapshot");
        assert_eq!(snapshot.name, "orders");
        assert_eq!(snapshot.region_id, test_region(20));
        assert_eq!(snapshot.state.msg_count, 1);
        assert_eq!(snapshot.storage.records.len(), 1);
        assert_eq!(snapshot.consumer_ids, vec![consumer]);
        assert_eq!(snapshot.mirror_regions, vec![test_region(21)]);
        assert_eq!(snapshot.source_regions, vec![test_region(22)]);

        assert!(stream.detach_consumer(consumer));
    }

    #[test]
    fn restore_from_snapshot_scrubs_live_attachments_but_preserves_records() {
        let mut stream = Stream::new(
            "orders",
            test_region(30),
            Time::from_secs(10),
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");
        stream
            .append(
                Subject::new("orders.created"),
                b"payload".to_vec(),
                Time::from_secs(11),
            )
            .expect("append");
        let consumer = stream.attach_consumer();
        stream
            .add_mirror_region(test_region(31))
            .expect("mirror region");
        stream
            .add_source_region(test_region(32))
            .expect("source region");

        let snapshot = stream.snapshot().expect("snapshot");
        let restored = Stream::restore_from_snapshot(&snapshot, test_region(40)).expect("restore");
        let restored_snapshot = restored.snapshot().expect("restored snapshot");

        assert_eq!(snapshot.storage, restored_snapshot.storage);
        assert_eq!(restored_snapshot.name, "orders");
        assert_eq!(restored_snapshot.region_id, test_region(40));
        assert_eq!(restored_snapshot.config, snapshot.config);
        assert_eq!(
            restored_snapshot.state.created_at,
            snapshot.state.created_at
        );
        assert_eq!(restored_snapshot.state.msg_count, snapshot.state.msg_count);
        assert_eq!(
            restored_snapshot.state.byte_count,
            snapshot.state.byte_count
        );
        assert_eq!(restored_snapshot.state.first_seq, snapshot.state.first_seq);
        assert_eq!(restored_snapshot.state.last_seq, snapshot.state.last_seq);
        assert_eq!(restored_snapshot.consumer_ids, Vec::<u64>::new());
        assert!(restored_snapshot.is_quiescent());
        assert_eq!(snapshot.consumer_ids, vec![consumer]);
        assert_eq!(snapshot.mirror_regions, vec![test_region(31)]);
        assert_eq!(snapshot.source_regions, vec![test_region(32)]);
    }

    #[test]
    fn restore_from_snapshot_rebuilds_dedup_index() {
        let mut config = stream_config("orders.>");
        config.dedupe_window = Some(Duration::from_secs(60));

        let mut stream = Stream::new(
            "orders",
            test_region(50),
            Time::from_secs(10),
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("stream");
        stream
            .append(
                Subject::new("orders.created"),
                b"same-payload".to_vec(),
                Time::from_secs(11),
            )
            .expect("append");

        let snapshot = stream.snapshot().expect("snapshot");
        let mut restored =
            Stream::restore_from_snapshot(&snapshot, test_region(51)).expect("restore");
        let err = restored
            .append(
                Subject::new("orders.created"),
                b"same-payload".to_vec(),
                Time::from_secs(20),
            )
            .expect_err("duplicate within dedupe window must be rejected");

        assert_eq!(
            err,
            StreamError::DuplicateDetected {
                subject: "orders.created".to_owned(),
                existing_seq: 1,
            }
        );
    }

    fn temp_wal_dir(test_name: &str) -> PathBuf {
        let unique = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock drift")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "asupersync-stream-wal-{test_name}-{nanos}-{unique}"
        ));
        fs::create_dir_all(&path).expect("create temp wal dir");
        path
    }

    fn wal_record(seq: u64, subject: &str, payload: &[u8], published_at: Time) -> StreamRecord {
        StreamRecord {
            seq,
            subject: Subject::new(subject),
            payload: payload.to_vec(),
            published_at,
        }
    }

    #[test]
    fn wal_backend_round_trips_records_after_reopen() {
        let dir = temp_wal_dir("round-trip");
        let config =
            WalStorageConfig::new(&dir, DeliveryClass::DurableOrdered).with_segment_max_bytes(1024);
        let first = wal_record(1, "orders.created", b"alpha", Time::from_secs(1));
        let second = wal_record(2, "orders.updated", b"beta", Time::from_secs(2));

        let mut backend = WalStorageBackend::open(config.clone()).expect("open wal");
        backend.append(first.clone()).expect("append first");
        backend.append(second.clone()).expect("append second");
        assert_eq!(backend.segment_count(), 1);

        let reopened = WalStorageBackend::open(config).expect("reopen wal");
        assert_eq!(reopened.get(1).expect("get first"), Some(first));
        assert_eq!(reopened.get(2).expect("get second"), Some(second));
        assert_eq!(reopened.snapshot().expect("snapshot").records.len(), 2);
    }

    #[test]
    fn wal_backend_rotates_segments_and_replays_truncation_markers() {
        let dir = temp_wal_dir("rotate-truncate");
        let config =
            WalStorageConfig::new(&dir, DeliveryClass::DurableOrdered).with_segment_max_bytes(1);
        let mut backend = WalStorageBackend::open(config.clone()).expect("open wal");

        backend
            .append(wal_record(1, "orders.created", b"one", Time::from_secs(1)))
            .expect("append one");
        backend
            .append(wal_record(2, "orders.updated", b"two", Time::from_secs(2)))
            .expect("append two");
        backend
            .append(wal_record(
                3,
                "orders.cancelled",
                b"three",
                Time::from_secs(3),
            ))
            .expect("append three");

        assert_eq!(backend.segment_count(), 3);
        let removed = backend.truncate_through(2).expect("truncate through");
        assert_eq!(removed.len(), 2);
        assert_eq!(backend.segment_count(), 2);
        let segment_files = fs::read_dir(&dir)
            .expect("read wal dir")
            .filter_map(Result::ok)
            .count();
        assert_eq!(segment_files, 2);

        let reopened = WalStorageBackend::open(config).expect("reopen wal");
        assert!(reopened.get(1).expect("get first").is_none());
        assert!(reopened.get(2).expect("get second").is_none());
        assert_eq!(
            reopened
                .get(3)
                .expect("get third")
                .expect("retained third")
                .payload,
            b"three".to_vec()
        );
    }

    #[test]
    fn wal_backend_truncates_torn_tail_during_recovery() {
        let dir = temp_wal_dir("torn-tail");
        let config =
            WalStorageConfig::new(&dir, DeliveryClass::DurableOrdered).with_segment_max_bytes(1024);
        let mut backend = WalStorageBackend::open(config.clone()).expect("open wal");
        let record = wal_record(1, "orders.created", b"alpha", Time::from_secs(1));
        backend.append(record.clone()).expect("append record");

        let segment_path = backend.segments[0].path.clone();
        let valid_len = fs::metadata(&segment_path).expect("segment metadata").len();
        let mut file = OpenOptions::new()
            .append(true)
            .open(&segment_path)
            .expect("open append");
        file.write_all(br#"{"kind":"append","record":"torn"#)
            .expect("write torn tail");
        drop(file);

        let recovered = WalStorageBackend::open(config).expect("recover wal");
        let repaired_len = fs::metadata(&segment_path).expect("segment metadata").len();
        assert_eq!(repaired_len, valid_len);
        assert_eq!(recovered.get(1).expect("get first"), Some(record));
        assert_eq!(recovered.snapshot().expect("snapshot").records.len(), 1);
    }

    #[test]
    fn wal_backend_can_restore_from_snapshot() {
        let dir = temp_wal_dir("snapshot-restore");
        let config = WalStorageConfig::new(&dir, DeliveryClass::ForensicReplayable)
            .with_segment_max_bytes(1024);
        let snapshot = StorageSnapshot {
            records: vec![
                wal_record(1, "orders.created", b"alpha", Time::from_secs(1)),
                wal_record(2, "orders.updated", b"beta", Time::from_secs(2)),
            ],
        };

        let restored = WalStorageBackend::from_snapshot(config.clone(), &snapshot)
            .expect("restore from snapshot");
        assert_eq!(restored.snapshot().expect("snapshot"), snapshot);

        let reopened = WalStorageBackend::open(config).expect("reopen wal");
        assert_eq!(reopened.snapshot().expect("snapshot"), snapshot);
    }

    #[test]
    fn wal_backend_restore_rejects_non_empty_directory() {
        let dir = temp_wal_dir("restore-non-empty");
        fs::write(dir.join("stray.txt"), b"occupied").expect("write stray file");
        let config =
            WalStorageConfig::new(&dir, DeliveryClass::DurableOrdered).with_segment_max_bytes(1024);

        let error = WalStorageBackend::from_snapshot(config, &StorageSnapshot::default())
            .expect_err("non-empty wal directory must be rejected");
        assert_eq!(
            error,
            StreamError::WalAlreadyInitialized {
                path: dir.display().to_string(),
            }
        );
    }

    #[test]
    fn wal_backend_open_rejects_non_contiguous_recovered_records() {
        let dir = temp_wal_dir("open-gap");
        let segment_path = dir.join("segment-00000000000000000000.wal");
        let first = serde_json::to_string(&WalEntry::Append {
            record: wal_record(1, "orders.created", b"alpha", Time::from_secs(1)),
        })
        .expect("serialize first");
        let third = serde_json::to_string(&WalEntry::Append {
            record: wal_record(3, "orders.updated", b"beta", Time::from_secs(2)),
        })
        .expect("serialize third");
        fs::write(&segment_path, format!("{first}\n{third}\n")).expect("write wal segment");

        let config =
            WalStorageConfig::new(&dir, DeliveryClass::DurableOrdered).with_segment_max_bytes(1024);
        let error =
            WalStorageBackend::open(config).expect_err("corrupted recovered wal must be rejected");
        assert_eq!(
            error,
            StreamError::InvalidRecoveredSequence {
                previous_seq: Some(1),
                current_seq: 3,
            }
        );
    }

    #[test]
    fn stream_rejects_recovered_storage_with_non_contiguous_sequences() {
        let storage = InMemoryStorageBackend {
            records: VecDeque::from([
                wal_record(2, "orders.created", b"alpha", Time::from_secs(1)),
                wal_record(4, "orders.updated", b"beta", Time::from_secs(2)),
            ]),
        };

        let error = Stream::new(
            "orders",
            test_region(31),
            Time::from_secs(10),
            stream_config("orders.>"),
            storage,
        )
        .expect_err("corrupted retained window must be rejected");
        assert_eq!(
            error,
            StreamError::InvalidRecoveredSequence {
                previous_seq: Some(2),
                current_seq: 4,
            }
        );
    }

    #[test]
    fn stream_new_rehydrates_state_from_recovered_wal_storage() {
        let dir = temp_wal_dir("stream-rehydrate");
        let config =
            WalStorageConfig::new(&dir, DeliveryClass::DurableOrdered).with_segment_max_bytes(1024);
        let mut backend = WalStorageBackend::open(config.clone()).expect("open wal");
        backend
            .append(wal_record(
                1,
                "orders.created",
                b"alpha",
                Time::from_secs(1),
            ))
            .expect("append first");
        backend
            .append(wal_record(2, "orders.updated", b"beta", Time::from_secs(2)))
            .expect("append second");

        let reopened_backend = WalStorageBackend::open(config).expect("reopen wal");
        let mut stream = Stream::new(
            "orders",
            test_region(30),
            Time::from_secs(10),
            stream_config("orders.>"),
            reopened_backend,
        )
        .expect("stream");

        assert_eq!(stream.state().msg_count, 2);
        assert_eq!(stream.state().first_seq, 1);
        assert_eq!(stream.state().last_seq, 2);
        let appended = stream
            .append(
                Subject::new("orders.cancelled"),
                b"gamma".to_vec(),
                Time::from_secs(11),
            )
            .expect("append third");
        assert_eq!(appended.seq, 3);
    }

    // ── Two-phase append tests ────────────────────────────────────

    #[test]
    fn reserve_then_commit_append() {
        let mut stream = make_default_stream();
        let mut permit = stream
            .reserve_append(Subject::new("orders.created"), Time::from_secs(1))
            .expect("reserve");

        let record = stream
            .commit_append(&mut permit, b"payload".to_vec())
            .expect("commit");

        assert_eq!(record.seq, 1);
        assert_eq!(record.payload, b"payload".to_vec());
        assert!(permit.is_committed());
        assert_eq!(permit.committed_seq(), Some(1));
        assert_eq!(stream.state().msg_count, 1);
    }

    #[test]
    fn reserve_then_abort_leaves_stream_empty() {
        let mut stream = make_default_stream();
        let permit = stream
            .reserve_append(Subject::new("orders.created"), Time::from_secs(1))
            .expect("reserve");

        permit.abort();
        assert_eq!(
            stream.state().msg_count,
            0,
            "aborted permit must not store anything"
        );
        let record = stream
            .append(
                Subject::new("orders.created"),
                b"after-abort".to_vec(),
                Time::from_secs(2),
            )
            .expect("append after abort");
        assert_eq!(
            record.seq, 1,
            "aborted permits must not burn sequence numbers"
        );
    }

    #[test]
    fn reserve_then_drop_leaves_stream_empty() {
        let mut stream = make_default_stream();
        {
            let _permit = stream
                .reserve_append(Subject::new("orders.created"), Time::from_secs(1))
                .expect("reserve");
            // dropped without commit
        }
        assert_eq!(
            stream.state().msg_count,
            0,
            "dropped permit must not store anything"
        );
        let record = stream
            .append(
                Subject::new("orders.created"),
                b"after-drop".to_vec(),
                Time::from_secs(2),
            )
            .expect("append after drop");
        assert_eq!(
            record.seq, 1,
            "dropped permits must not burn sequence numbers"
        );
    }

    #[test]
    fn double_commit_returns_error() {
        let mut stream = make_default_stream();
        let mut permit = stream
            .reserve_append(Subject::new("orders.created"), Time::from_secs(1))
            .expect("reserve");

        let _ = stream
            .commit_append(&mut permit, b"first".to_vec())
            .expect("first commit");

        let err = stream
            .commit_append(&mut permit, b"second".to_vec())
            .expect_err("second commit must fail");

        assert!(
            matches!(err, StreamError::PermitAlreadyCommitted { seq: 1 }),
            "expected PermitAlreadyCommitted, got {err:?}"
        );
    }

    #[test]
    fn out_of_order_commits_assign_sequences_in_commit_order() {
        let mut stream = make_default_stream();

        let mut permit1 = stream
            .reserve_append(Subject::new("orders.created"), Time::from_secs(1))
            .expect("reserve 1");
        let mut permit2 = stream
            .reserve_append(Subject::new("orders.created"), Time::from_secs(2))
            .expect("reserve 2");

        // Commit in reverse order. The storage log should remain contiguous and
        // ordered by durable commit, not by reservation timing.
        let r2 = stream
            .commit_append(&mut permit2, b"second".to_vec())
            .expect("commit 2");
        let r1 = stream
            .commit_append(&mut permit1, b"first".to_vec())
            .expect("commit 1");

        assert_eq!(r2.seq, 1);
        assert_eq!(r1.seq, 2);
        assert_eq!(permit2.committed_seq(), Some(1));
        assert_eq!(permit1.committed_seq(), Some(2));
        assert_eq!(
            stream.range(1..=2).expect("range"),
            vec![r2, r1],
            "retained storage must stay ordered by committed sequence"
        );

        let snapshot = stream.snapshot().expect("snapshot");
        let reopened = Stream::new(
            "test-stream",
            test_region(1),
            Time::from_secs(0),
            stream_config("orders.>"),
            InMemoryStorageBackend {
                records: snapshot.storage.records.into(),
            },
        )
        .expect("reopen from contiguous retained records");
        assert_eq!(reopened.state().first_seq, 1);
        assert_eq!(reopened.state().last_seq, 2);
    }

    // ── Dedup window tests ────────────────────────────────────────

    #[test]
    fn dedup_window_rejects_duplicate_within_window() {
        let config = StreamConfig {
            dedupe_window: Some(Duration::from_secs(60)),
            ..StreamConfig::default()
        };
        let mut stream = Stream::new(
            "dedup-stream",
            test_region(1),
            Time::from_secs(0),
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("create stream");

        stream
            .append(
                Subject::new("fabric.default"),
                b"unique".to_vec(),
                Time::from_secs(1),
            )
            .expect("first append");

        let err = stream
            .append(
                Subject::new("fabric.default"),
                b"unique".to_vec(),
                Time::from_secs(2),
            )
            .expect_err("duplicate must be rejected");

        assert!(
            matches!(err, StreamError::DuplicateDetected { .. }),
            "expected DuplicateDetected, got {err:?}"
        );
    }

    #[test]
    fn dedup_window_allows_same_payload_after_window_expires() {
        let config = StreamConfig {
            dedupe_window: Some(Duration::from_secs(10)),
            ..StreamConfig::default()
        };
        let mut stream = Stream::new(
            "dedup-expire-stream",
            test_region(1),
            Time::from_secs(0),
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("create stream");

        stream
            .append(
                Subject::new("fabric.default"),
                b"data".to_vec(),
                Time::from_secs(1),
            )
            .expect("first append");

        // 15 seconds later — outside the 10s window.
        stream
            .append(
                Subject::new("fabric.default"),
                b"data".to_vec(),
                Time::from_secs(16),
            )
            .expect("append after window expiry should succeed");

        assert_eq!(stream.state().msg_count, 2);
    }

    #[test]
    fn dedup_window_forgets_records_truncated_by_retention() {
        let config = StreamConfig {
            retention: RetentionPolicy::Limits,
            max_msgs: 1,
            dedupe_window: Some(Duration::from_secs(60)),
            ..StreamConfig::default()
        };
        let mut stream = Stream::new(
            "dedup-retention-stream",
            test_region(1),
            Time::from_secs(0),
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("create stream");

        stream
            .append(
                Subject::new("fabric.default"),
                b"same".to_vec(),
                Time::from_secs(1),
            )
            .expect("first append");
        stream
            .append(
                Subject::new("fabric.default"),
                b"other".to_vec(),
                Time::from_secs(2),
            )
            .expect("second append triggers retention");

        assert!(
            stream.get(1).expect("get truncated first").is_none(),
            "retention should remove the first record from storage"
        );

        let third = stream
            .append(
                Subject::new("fabric.default"),
                b"same".to_vec(),
                Time::from_secs(3),
            )
            .expect("dedup must forget records truncated by retention");

        assert_eq!(third.seq, 3);
        assert_eq!(stream.state().msg_count, 1);
        assert_eq!(stream.state().last_seq, 3);
        assert!(
            stream.get(2).expect("get truncated second").is_none(),
            "max_msgs=1 should retain only the newest record"
        );
        assert_eq!(
            stream
                .get(3)
                .expect("get retained third")
                .map(|record| record.payload),
            Some(b"same".to_vec())
        );
    }

    #[test]
    fn retention_recovers_after_transient_noop_truncate() {
        let config = StreamConfig {
            retention: RetentionPolicy::Limits,
            max_msgs: 1,
            ..StreamConfig::default()
        };
        let mut stream = Stream::new(
            "retention-repair-stream",
            test_region(1),
            Time::from_secs(0),
            config,
            TruncateSkipsOnceBackend {
                inner: InMemoryStorageBackend::default(),
                skip_next_truncate: true,
            },
        )
        .expect("create stream");

        stream
            .append(
                Subject::new("fabric.default"),
                b"first".to_vec(),
                Time::from_secs(1),
            )
            .expect("append first");
        stream
            .append(
                Subject::new("fabric.default"),
                b"second".to_vec(),
                Time::from_secs(2),
            )
            .expect("append second should recover after transient truncate no-op");

        assert_eq!(stream.state().msg_count, 1);
        assert_eq!(stream.state().first_seq, 2);
        assert_eq!(stream.state().last_seq, 2);
        assert!(stream.get(1).expect("first removed").is_none());
        assert_eq!(
            stream
                .get(2)
                .expect("second retained")
                .map(|record| record.payload),
            Some(b"second".to_vec())
        );
    }

    #[test]
    fn dedup_window_allows_different_payload_same_subject() {
        let config = StreamConfig {
            dedupe_window: Some(Duration::from_secs(60)),
            ..StreamConfig::default()
        };
        let mut stream = Stream::new(
            "dedup-diff-stream",
            test_region(1),
            Time::from_secs(0),
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("create stream");

        stream
            .append(
                Subject::new("fabric.default"),
                b"data-1".to_vec(),
                Time::from_secs(1),
            )
            .expect("first append");

        stream
            .append(
                Subject::new("fabric.default"),
                b"data-2".to_vec(),
                Time::from_secs(2),
            )
            .expect("different payload should not be a dup");

        assert_eq!(stream.state().msg_count, 2);
    }

    #[test]
    fn dedup_disabled_by_default() {
        let mut stream = make_default_stream();

        stream
            .append(
                Subject::new("orders.created"),
                b"same".to_vec(),
                Time::from_secs(1),
            )
            .expect("first");
        stream
            .append(
                Subject::new("orders.created"),
                b"same".to_vec(),
                Time::from_secs(2),
            )
            .expect("second — dedup disabled by default");

        assert_eq!(stream.state().msg_count, 2);
    }

    #[test]
    fn dedup_works_with_reserve_commit_path() {
        let config = StreamConfig {
            dedupe_window: Some(Duration::from_secs(60)),
            ..StreamConfig::default()
        };
        let mut stream = Stream::new(
            "dedup-reserve-stream",
            test_region(1),
            Time::from_secs(0),
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("create stream");

        stream
            .append(
                Subject::new("fabric.default"),
                b"data".to_vec(),
                Time::from_secs(1),
            )
            .expect("direct append");

        let mut permit = stream
            .reserve_append(Subject::new("fabric.default"), Time::from_secs(2))
            .expect("reserve");

        let err = stream
            .commit_append(&mut permit, b"data".to_vec())
            .expect_err("dedup should catch duplicate at commit time");

        assert!(
            matches!(err, StreamError::DuplicateDetected { .. }),
            "expected DuplicateDetected, got {err:?}"
        );
        assert!(
            !permit.is_committed(),
            "permit should not be marked committed on dedup failure"
        );

        let unique = stream
            .append(
                Subject::new("fabric.default"),
                b"fresh".to_vec(),
                Time::from_secs(3),
            )
            .expect("append after dedup failure");
        assert_eq!(
            unique.seq, 2,
            "failed commit must not burn a sequence number"
        );
    }

    #[test]
    fn reserved_permit_cannot_commit_after_stream_begins_closing() {
        let mut stream = make_default_stream();
        let mut permit = stream
            .reserve_append(Subject::new("orders.created"), Time::from_secs(1))
            .expect("reserve");

        stream.begin_close();
        let err = stream
            .commit_append(&mut permit, b"payload".to_vec())
            .expect_err("closing stream must reject commit from prior permit");

        assert!(
            matches!(
                err,
                StreamError::NotAcceptingAppends {
                    ref name,
                    lifecycle: StreamLifecycle::Closing,
                } if name == "test-stream"
            ),
            "expected NotAcceptingAppends(Closing), got {err:?}"
        );
        assert!(
            !permit.is_committed(),
            "failed close-boundary commit must leave permit uncommitted"
        );
    }

    #[test]
    fn reserved_permit_cannot_commit_after_stream_closes() {
        let mut stream = make_default_stream();
        let mut permit = stream
            .reserve_append(Subject::new("orders.created"), Time::from_secs(1))
            .expect("reserve");

        stream.close().expect("close");
        let err = stream
            .commit_append(&mut permit, b"payload".to_vec())
            .expect_err("closed stream must reject commit from prior permit");

        assert!(
            matches!(
                err,
                StreamError::NotAcceptingAppends {
                    ref name,
                    lifecycle: StreamLifecycle::Closed,
                } if name == "test-stream"
            ),
            "expected NotAcceptingAppends(Closed), got {err:?}"
        );
        assert!(
            !permit.is_committed(),
            "failed closed-stream commit must leave permit uncommitted"
        );
    }

    #[test]
    fn consumed_permit_still_reports_already_committed_after_stream_closes() {
        let mut stream = make_default_stream();
        let mut permit = stream
            .reserve_append(Subject::new("orders.created"), Time::from_secs(1))
            .expect("reserve");

        let record = stream
            .commit_append(&mut permit, b"payload".to_vec())
            .expect("commit");
        assert_eq!(record.seq, 1);

        stream.close().expect("close");
        let err = stream
            .commit_append(&mut permit, b"again".to_vec())
            .expect_err("consumed permit must stay consumed after close");

        assert!(
            matches!(err, StreamError::PermitAlreadyCommitted { seq: 1 }),
            "expected PermitAlreadyCommitted, got {err:?}"
        );
    }

    #[test]
    fn permit_cannot_commit_into_different_stream() {
        let mut left = make_default_stream();
        let mut right = Stream::new(
            "other-stream",
            test_region(2),
            Time::from_secs(0),
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("create second stream");

        let mut permit = left
            .reserve_append(Subject::new("orders.created"), Time::from_secs(1))
            .expect("reserve on left");
        let err = right
            .commit_append(&mut permit, b"payload".to_vec())
            .expect_err("permit must stay bound to the reserving stream");

        assert!(
            matches!(
                err,
                StreamError::PermitStreamMismatch {
                    ref permit_name,
                    permit_region,
                    ref stream_name,
                    stream_region,
                } if permit_name == "test-stream"
                    && permit_region == test_region(1)
                    && stream_name == "other-stream"
                    && stream_region == test_region(2)
            ),
            "expected PermitStreamMismatch, got {err:?}"
        );
    }
