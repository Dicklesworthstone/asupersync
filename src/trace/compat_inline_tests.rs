    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::trace::file::{TraceWriter, write_trace};
    use crate::trace::replay::CompactTaskId;
    use tempfile::NamedTempFile;

    #[test]
    fn compatibility_check_current_version() {
        assert_eq!(
            check_schema_compatibility(REPLAY_SCHEMA_VERSION),
            CompatibilityResult::Compatible
        );
    }

    #[test]
    fn compatibility_check_older_version() {
        // When we add version 2, version 1 should need migration
        // For now with only version 1, this tests the boundary
        if REPLAY_SCHEMA_VERSION > 1 {
            assert!(matches!(
                check_schema_compatibility(1),
                CompatibilityResult::NeedsMigration { .. }
            ));
        }
    }

    #[test]
    fn compatibility_check_newer_version() {
        let result = check_schema_compatibility(REPLAY_SCHEMA_VERSION + 1);
        assert!(matches!(result, CompatibilityResult::TooNew { .. }));
    }

    #[test]
    fn compat_reader_reads_valid_trace() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
        ];

        write_trace(path, &metadata, &events).expect("write trace");

        let mut reader = CompatReader::open(path).expect("open reader");
        assert_eq!(reader.metadata().seed, 42);
        assert_eq!(reader.event_count(), 2);

        let e1 = reader.read_event().expect("read").expect("event");
        assert!(matches!(e1, ReplayEvent::RngSeed { seed: 42 }));

        let e2 = reader.read_event().expect("read").expect("event");
        assert!(matches!(e2, ReplayEvent::TaskScheduled { .. }));

        assert_eq!(reader.read_event().expect("read"), None);
        assert!(!reader.stats().has_issues());
    }

    #[test]
    fn compat_reader_rejects_zero_version_and_compression_mismatch() {
        let temp = NamedTempFile::new().expect("create temp file");
        write_trace(temp.path(), &TraceMetadata::new(42), &[]).expect("write trace");
        let baseline = std::fs::read(temp.path()).expect("read trace");

        let mut zero_version = baseline.clone();
        zero_version[TRACE_MAGIC.len()..TRACE_MAGIC.len() + 2].copy_from_slice(&0u16.to_le_bytes());
        std::fs::write(temp.path(), zero_version).expect("write zero-version trace");
        assert!(matches!(
            CompatReader::open(temp.path()),
            Err(TraceFileError::UnsupportedVersion { found: 0, .. })
        ));

        let mut mismatched_compression = baseline;
        mismatched_compression[TRACE_MAGIC.len() + 4] = 1;
        std::fs::write(temp.path(), mismatched_compression)
            .expect("write mismatched compression byte");
        assert!(matches!(
            CompatReader::open(temp.path()),
            Err(TraceFileError::UnsupportedCompression(1))
        ));
    }

    #[test]
    fn compat_reader_loads_known_events_without_issues() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        // Write a trace with known events
        let mut writer = TraceWriter::create(path).expect("create writer");
        writer
            .write_metadata(&TraceMetadata::new(42))
            .expect("write metadata");
        writer
            .write_event(&ReplayEvent::RngSeed { seed: 42 })
            .expect("write event");
        // Note: we can't easily inject an unknown event type in this test
        // because we'd need to write raw bytes. The compat reader will be
        // tested more thoroughly when we actually have version migrations.
        writer.finish().expect("finish");

        let (events, stats) = CompatReader::open(path)
            .expect("open reader")
            .load_all()
            .expect("load all");

        assert_eq!(events.len(), 1);
        assert!(!stats.has_issues());
    }

    #[test]
    fn compat_reader_rejects_unknown_event_types_without_skipping() {
        use std::io::Write;
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        // Manually construct a trace file with an unknown event type
        let mut file = std::fs::File::create(path).expect("create file");

        // Write header
        file.write_all(super::TRACE_MAGIC).expect("write magic");
        file.write_all(&2u16.to_le_bytes()).expect("write version");
        file.write_all(&0u16.to_le_bytes()).expect("write flags");
        file.write_all(&[0u8]).expect("write compression byte");

        // Write metadata
        let metadata = TraceMetadata::new(42);
        let meta_bytes = rmp_serde::to_vec(&metadata).expect("serialize metadata");
        file.write_all(&(meta_bytes.len() as u32).to_le_bytes())
            .expect("write meta len");
        file.write_all(&meta_bytes).expect("write metadata");

        // Write event count (3 events: known, unknown, known)
        file.write_all(&3u64.to_le_bytes())
            .expect("write event count");

        // Event 1: Known event (RngSeed)
        let event1 = ReplayEvent::RngSeed { seed: 100 };
        let event1_bytes = rmp_serde::to_vec(&event1).expect("serialize event1");
        file.write_all(&(event1_bytes.len() as u32).to_le_bytes())
            .expect("write event1 len");
        file.write_all(&event1_bytes).expect("write event1");

        // Event 2: Unknown event type (manually crafted msgpack)
        // This is a map with {"type": "FutureEventType", "data": 123}
        let unknown_event = rmp_serde::to_vec(&serde_json::json!({
            "type": "FutureEventType",
            "some_field": 12345
        }))
        .expect("serialize unknown event");
        file.write_all(&(unknown_event.len() as u32).to_le_bytes())
            .expect("write unknown event len");
        file.write_all(&unknown_event).expect("write unknown event");

        // Event 3: Known event (TaskYielded)
        let event3 = ReplayEvent::TaskYielded {
            task: CompactTaskId(42),
        };
        let event3_bytes = rmp_serde::to_vec(&event3).expect("serialize event3");
        file.write_all(&(event3_bytes.len() as u32).to_le_bytes())
            .expect("write event3 len");
        file.write_all(&event3_bytes).expect("write event3");

        file.flush().expect("flush");
        drop(file);

        let mut reader = CompatReader::open(path).expect("open reader");
        let first = reader.read_event().expect("read").expect("known event");
        assert!(matches!(first, ReplayEvent::RngSeed { seed: 100 }));
        let error = reader
            .read_event()
            .expect_err("unknown event must fail closed");
        assert!(matches!(error, TraceFileError::Deserialize(_)));
        assert_eq!(reader.stats().events_read, 1);
        assert_eq!(reader.stats().events_skipped, 0);
    }

    #[test]
    fn compat_reader_read_event_compat_returns_skipped_info() {
        use std::io::Write;
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        // Manually construct a trace with an unknown event
        let mut file = std::fs::File::create(path).expect("create file");
        file.write_all(super::TRACE_MAGIC).expect("write magic");
        file.write_all(&2u16.to_le_bytes()).expect("write version");
        file.write_all(&0u16.to_le_bytes()).expect("write flags");
        file.write_all(&[0u8]).expect("write compression byte");

        let metadata = TraceMetadata::new(42);
        let meta_bytes = rmp_serde::to_vec(&metadata).expect("serialize metadata");
        file.write_all(&(meta_bytes.len() as u32).to_le_bytes())
            .expect("write meta len");
        file.write_all(&meta_bytes).expect("write metadata");
        file.write_all(&1u64.to_le_bytes())
            .expect("write event count");

        // Write unknown event
        let unknown = rmp_serde::to_vec(&serde_json::json!({
            "type": "NewEventInV99",
            "new_field": "value"
        }))
        .expect("serialize");
        file.write_all(&(unknown.len() as u32).to_le_bytes())
            .expect("write len");
        file.write_all(&unknown).expect("write event");
        file.flush().expect("flush");
        drop(file);

        // Read with detailed compat info
        let mut reader = CompatReader::open(path).expect("open reader");

        let event = reader
            .read_event_compat()
            .expect("read")
            .expect("should have event");

        match event {
            CompatEvent::Skipped { reason, raw_bytes } => {
                assert!(reason.contains("NewEventInV99") || !reason.is_empty());
                assert!(!raw_bytes.is_empty());
            }
            CompatEvent::Event(_) => panic!("expected skipped event"),
        }
    }

    fn write_header_with_metadata(file: &mut std::fs::File) {
        use std::io::Write;
        file.write_all(super::TRACE_MAGIC).expect("write magic");
        file.write_all(&2u16.to_le_bytes()).expect("write version");
        file.write_all(&0u16.to_le_bytes()).expect("write flags");
        file.write_all(&[0u8]).expect("write compression byte");

        let metadata = TraceMetadata::new(42);
        let meta_bytes = rmp_serde::to_vec(&metadata).expect("serialize metadata");
        file.write_all(&(meta_bytes.len() as u32).to_le_bytes())
            .expect("write meta len");
        file.write_all(&meta_bytes).expect("write metadata");
    }

    #[test]
    fn compat_reader_read_event_errors_on_truncated_stream() {
        use std::io::Write;
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();
        let mut file = std::fs::File::create(path).expect("create file");
        write_header_with_metadata(&mut file);
        // Declare one event but write none.
        file.write_all(&1u64.to_le_bytes())
            .expect("write event count");
        file.flush().expect("flush");
        drop(file);

        let mut reader = CompatReader::open(path).expect("open reader");
        let err = reader
            .read_event()
            .expect_err("truncated event stream must error");
        assert!(matches!(err, TraceFileError::Io(_)), "got: {err:?}");
    }

    #[test]
    fn compat_reader_read_event_compat_errors_on_truncated_stream() {
        use std::io::Write;
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();
        let mut file = std::fs::File::create(path).expect("create file");
        write_header_with_metadata(&mut file);
        // Declare one event but write none.
        file.write_all(&1u64.to_le_bytes())
            .expect("write event count");
        file.flush().expect("flush");
        drop(file);

        let mut reader = CompatReader::open(path).expect("open reader");
        let err = reader
            .read_event_compat()
            .expect_err("truncated event stream must error");
        assert!(matches!(err, TraceFileError::Io(_)), "got: {err:?}");
    }

    #[test]
    fn compat_event_iterator_errors_on_truncated_stream() {
        use std::io::Write;
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();
        let mut file = std::fs::File::create(path).expect("create file");
        write_header_with_metadata(&mut file);
        // Declare one event but write none.
        file.write_all(&1u64.to_le_bytes())
            .expect("write event count");
        file.flush().expect("flush");
        drop(file);

        let mut iter = CompatReader::open(path).expect("open reader").events();
        let first = iter
            .next()
            .expect("iterator should emit an error for the missing event");
        assert!(
            matches!(first, Err(TraceFileError::Io(_))),
            "got: {first:?}"
        );
    }

    #[test]
    fn compat_stats_tracking() {
        let mut stats = CompatStats::default();

        stats.record_read();
        stats.record_read();
        stats.record_skipped(Some("UnknownEvent"));
        stats.record_skipped(Some("UnknownEvent")); // duplicate type
        stats.record_skipped(Some("AnotherUnknown"));
        stats.record_migrated();

        assert_eq!(stats.events_read, 3); // 2 read + 1 migrated
        assert_eq!(stats.events_skipped, 3);
        assert_eq!(stats.events_migrated, 1);
        assert_eq!(stats.unknown_event_types.len(), 2);
        assert!(stats.has_issues());
    }

    #[test]
    fn migrator_no_migrations_needed() {
        let migrator = TraceMigrator::new();

        let metadata = TraceMetadata::new(42);
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];

        let result = migrator.migrate(metadata.clone(), events.clone(), REPLAY_SCHEMA_VERSION);
        assert!(result.is_some());

        let (new_meta, new_events) = result.unwrap();
        assert_eq!(new_meta.seed, metadata.seed);
        assert_eq!(new_events.len(), events.len());
    }

    #[test]
    fn migrator_can_migrate_check() {
        let migrator = TraceMigrator::new();

        // No migrations registered, so can only "migrate" same version
        assert!(migrator.can_migrate(1, 1));
        assert!(!migrator.can_migrate(1, 2)); // No migration registered
        assert!(!migrator.can_migrate(2, 1)); // Reverse migration is not implicit identity
    }

    // Example migration for testing
    struct TestMigration;

    impl TraceMigration for TestMigration {
        fn from_version(&self) -> u32 {
            1
        }
        fn to_version(&self) -> u32 {
            2
        }
        fn migrate_event(&self, event: ReplayEvent) -> Option<ReplayEvent> {
            Some(event) // Pass through unchanged
        }
    }

    #[test]
    fn migrator_with_registered_migration() {
        let migrator = TraceMigrator::new().with_migration(TestMigration);

        assert!(migrator.can_migrate(1, 2));
        assert!(!migrator.can_migrate(1, 3)); // No v2->v3 migration

        let mut metadata = TraceMetadata::new(42);
        metadata.version = 1;
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];

        let result = migrator.migrate(metadata, events, 2);
        assert!(result.is_some());

        let (new_meta, _) = result.unwrap();
        assert_eq!(new_meta.version, 2);
    }

    // =========================================================================
    // Wave 26: Data-type trait coverage
    // =========================================================================

    #[test]
    fn compatibility_result_debug_compatible() {
        let r = CompatibilityResult::Compatible;
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Compatible"));
    }

    #[test]
    fn compatibility_result_debug_needs_migration() {
        let r = CompatibilityResult::NeedsMigration { from: 1, to: 3 };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("NeedsMigration"));
        assert!(dbg.contains('1'));
        assert!(dbg.contains('3'));
    }

    #[test]
    fn compatibility_result_debug_too_old() {
        let r = CompatibilityResult::TooOld {
            found: 0,
            min_supported: 1,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("TooOld"));
        assert!(dbg.contains('0'));
    }

    #[test]
    fn compatibility_result_debug_too_new() {
        let r = CompatibilityResult::TooNew {
            found: 99,
            max_supported: 2,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("TooNew"));
        assert!(dbg.contains("99"));
    }

    #[test]
    fn compatibility_result_clone() {
        let r = CompatibilityResult::NeedsMigration { from: 1, to: 2 };
        let r2 = r.clone();
        assert_eq!(r, r2);
    }

    #[test]
    fn compatibility_result_eq_different_variants() {
        assert_ne!(
            CompatibilityResult::Compatible,
            CompatibilityResult::TooNew {
                found: 5,
                max_supported: 3,
            }
        );
    }

    #[test]
    fn check_schema_compatibility_version_zero() {
        let result = check_schema_compatibility(0);
        assert!(matches!(
            result,
            CompatibilityResult::TooOld {
                found: 0,
                min_supported: 1,
            }
        ));
    }

    #[test]
    fn compat_event_debug_event_variant() {
        let event = CompatEvent::Event(ReplayEvent::RngSeed { seed: 7 });
        let dbg = format!("{event:?}");
        assert!(dbg.contains("Event"));
        assert!(dbg.contains("RngSeed"));
    }

    #[test]
    fn compat_event_debug_skipped_variant() {
        let event = CompatEvent::Skipped {
            reason: "unknown type".to_string(),
            raw_bytes: vec![0xde, 0xad],
        };
        let dbg = format!("{event:?}");
        assert!(dbg.contains("Skipped"));
        assert!(dbg.contains("unknown type"));
    }

    #[test]
    fn compat_stats_default_zeroed() {
        let stats = CompatStats::default();
        assert_eq!(stats.events_read, 0);
        assert_eq!(stats.events_skipped, 0);
        assert_eq!(stats.events_migrated, 0);
        assert!(stats.unknown_event_types.is_empty());
    }

    #[test]
    fn compat_stats_clone() {
        let mut stats = CompatStats::default();
        stats.record_read();
        stats.record_skipped(Some("FooEvent"));
        let stats2 = stats.clone();
        assert_eq!(stats2.events_read, 1);
        assert_eq!(stats2.events_skipped, 1);
        assert_eq!(stats2.unknown_event_types.len(), 1);
    }

    #[test]
    fn compat_stats_debug() {
        let stats = CompatStats::default();
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("CompatStats"));
        assert!(dbg.contains("events_read"));
    }

    #[test]
    fn compat_stats_has_issues_false_when_clean() {
        let mut stats = CompatStats::default();
        stats.record_read();
        stats.record_read();
        stats.record_migrated();
        assert!(!stats.has_issues());
    }

    #[test]
    fn compat_stats_record_skipped_none_type() {
        let mut stats = CompatStats::default();
        stats.record_skipped(None);
        assert_eq!(stats.events_skipped, 1);
        assert!(stats.unknown_event_types.is_empty());
        assert!(stats.has_issues());
    }

    #[test]
    fn migrator_default_trait() {
        let m1 = TraceMigrator::new();
        let m2 = TraceMigrator::default();
        // Both should be empty migrators with identical behavior
        assert!(m1.can_migrate(1, 1));
        assert!(m2.can_migrate(1, 1));
        assert!(!m1.can_migrate(1, 2));
        assert!(!m2.can_migrate(1, 2));
    }
