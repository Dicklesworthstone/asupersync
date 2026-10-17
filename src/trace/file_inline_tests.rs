    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::trace::replay::CompactTaskId;
    use serde_json::json;
    use std::io::Write;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::NamedTempFile;

    fn sample_events() -> Vec<ReplayEvent> {
        vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TimeAdvanced {
                from_nanos: 0,
                to_nanos: 1_000_000,
            },
            ReplayEvent::TaskYielded {
                task: CompactTaskId(1),
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 1,
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 0,
            },
        ]
    }

    fn write_v2_trace(
        path: &std::path::Path,
        metadata: &TraceMetadata,
        events: &[ReplayEvent],
        declared_events: u64,
    ) {
        let mut file = std::fs::File::create(path).expect("create v2 trace");
        file.write_all(TRACE_MAGIC).expect("write magic");
        file.write_all(&2u16.to_le_bytes()).expect("write version");
        file.write_all(&0u16.to_le_bytes()).expect("write flags");
        file.write_all(&[0]).expect("write compression");
        let metadata_bytes = rmp_serde::to_vec(metadata).expect("serialize metadata");
        file.write_all(&(metadata_bytes.len() as u32).to_le_bytes())
            .expect("write metadata length");
        file.write_all(&metadata_bytes).expect("write metadata");
        file.write_all(&declared_events.to_le_bytes())
            .expect("write event count");
        for event in events {
            let event_bytes = rmp_serde::to_vec(event).expect("serialize event");
            file.write_all(&(event_bytes.len() as u32).to_le_bytes())
                .expect("write event length");
            file.write_all(&event_bytes).expect("write event");
        }
        file.flush().expect("flush v2 trace");
    }

    fn write_v1_trace(path: &std::path::Path, metadata: &TraceMetadata, events: &[ReplayEvent]) {
        let mut file = std::fs::File::create(path).expect("create v1 trace");
        file.write_all(TRACE_MAGIC).expect("write magic");
        file.write_all(&1u16.to_le_bytes()).expect("write version");
        file.write_all(&0u16.to_le_bytes()).expect("write flags");
        let metadata_bytes = rmp_serde::to_vec(metadata).expect("serialize metadata");
        file.write_all(&(metadata_bytes.len() as u32).to_le_bytes())
            .expect("write metadata length");
        file.write_all(&metadata_bytes).expect("write metadata");
        file.write_all(&(events.len() as u64).to_le_bytes())
            .expect("write event count");
        for event in events {
            let event_bytes = rmp_serde::to_vec(event).expect("serialize event");
            file.write_all(&(event_bytes.len() as u32).to_le_bytes())
                .expect("write event length");
            file.write_all(&event_bytes).expect("write event");
        }
        file.flush().expect("flush v1 trace");
    }

    fn write_header_with_raw_compression(
        file: &mut std::fs::File,
        flags: u16,
        compression_byte: u8,
    ) {
        let metadata = TraceMetadata::new(42);
        let meta_bytes = rmp_serde::to_vec(&metadata).expect("serialize metadata");

        file.write_all(TRACE_MAGIC).expect("write magic");
        file.write_all(&2u16.to_le_bytes()).expect("write version");
        file.write_all(&flags.to_le_bytes()).expect("write flags");
        file.write_all(&[compression_byte])
            .expect("write compression");
        file.write_all(&(meta_bytes.len() as u32).to_le_bytes())
            .expect("write metadata length");
        file.write_all(&meta_bytes).expect("write metadata");
    }

    fn write_header_with_metadata(file: &mut std::fs::File, compression: CompressionMode) {
        let flags = if compression.is_compressed() {
            FLAG_COMPRESSED
        } else {
            0
        };
        write_header_with_raw_compression(file, flags, compression.to_byte());
    }

    fn trace_file_layout_summary(path: &std::path::Path) -> serde_json::Value {
        let bytes = std::fs::read(path).expect("read trace bytes");
        let version = u16::from_le_bytes(
            bytes[TRACE_MAGIC.len()..TRACE_MAGIC.len() + 2]
                .try_into()
                .expect("version bytes"),
        );
        let flags = u16::from_le_bytes(
            bytes[TRACE_MAGIC.len() + 2..TRACE_MAGIC.len() + 4]
                .try_into()
                .expect("flag bytes"),
        );
        let compression_byte = bytes[TRACE_MAGIC.len() + 4];
        let meta_len = u32::from_le_bytes(
            bytes[TRACE_MAGIC.len() + 5..LEGACY_HEADER_SIZE]
                .try_into()
                .expect("metadata length bytes"),
        );
        let event_count_offset = HEADER_SIZE + meta_len as usize;
        let event_count = u64::from_le_bytes(
            bytes[event_count_offset..event_count_offset + 8]
                .try_into()
                .expect("event count bytes"),
        );

        let mut metadata =
            serde_json::to_value(TraceReader::open(path).expect("open reader").metadata())
                .expect("serialize metadata");
        if let Some(obj) = metadata.as_object_mut() {
            if let Some(recorded_at) = obj.get_mut("recorded_at") {
                *recorded_at = json!("[recorded_at]");
            }
        }

        json!({
            "magic": std::str::from_utf8(TRACE_MAGIC).expect("trace magic is valid utf8"),
            "version": version,
            "flags_hex": format!("{flags:#06x}"),
            "compression_byte": compression_byte,
            "meta_len": meta_len,
            "event_count": event_count,
            "metadata": metadata,
            "events": sample_events(),
        })
    }

    fn scrub_metadata_for_snapshot(metadata: &TraceMetadata) -> serde_json::Value {
        let mut metadata = serde_json::to_value(metadata).expect("serialize metadata");
        if let Some(obj) = metadata.as_object_mut() {
            if let Some(recorded_at) = obj.get_mut("recorded_at") {
                *recorded_at = json!("[recorded_at]");
            }
        }
        metadata
    }

    fn trace_file_roundtrip_summary(path: &std::path::Path) -> serde_json::Value {
        let (reader_event_count, reader_metadata) = {
            let reader = TraceReader::open(path).expect("open reader");
            (
                reader.event_count(),
                scrub_metadata_for_snapshot(reader.metadata()),
            )
        };

        let (metadata, events) = read_trace(path).expect("read trace");

        json!({
            "reader": {
                "event_count": reader_event_count,
                "metadata": reader_metadata,
            },
            "read_trace": {
                "metadata": scrub_metadata_for_snapshot(&metadata),
                "events": events,
            },
        })
    }

    // =========================================================================
    // Pure data-type tests (wave 40 – CyanBarn)
    // =========================================================================

    #[test]
    fn compression_mode_debug_clone_copy_eq_default() {
        let def = CompressionMode::default();
        assert_eq!(def, CompressionMode::None);
        let copied = def;
        let cloned = def;
        assert_eq!(copied, cloned);
        assert!(!def.is_compressed());
        let dbg = format!("{def:?}");
        assert!(dbg.contains("None"));
    }

    #[test]
    fn trace_file_config_debug_clone_default() {
        let def = TraceFileConfig::default();
        assert_eq!(def.compression, CompressionMode::None);
        assert_eq!(def.chunk_size, DEFAULT_COMPRESSION_CHUNK_SIZE);
        assert!(def.max_events.is_none());
        let cloned = def.clone();
        assert_eq!(cloned.compression, CompressionMode::None);
        let dbg = format!("{def:?}");
        assert!(dbg.contains("TraceFileConfig"));
    }

    #[test]
    fn trace_file_error_debug_display() {
        let err = TraceFileError::InvalidMagic;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("InvalidMagic"));
        let display = format!("{err}");
        assert!(display.contains("magic"));

        let version_err = TraceFileError::UnsupportedVersion {
            expected: 2,
            found: 99,
        };
        let display2 = format!("{version_err}");
        assert!(display2.contains("99"));
    }

    #[test]
    fn trace_file_layout_snapshot_scrubs_recorded_at() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata {
            version: REPLAY_SCHEMA_VERSION,
            seed: 42,
            recorded_at: 1_726_133_456_789_000_000,
            config_hash: 0xfeed_beef_cafe_babe,
            description: Some("trace file layout snapshot".to_string()),
        };
        let events = sample_events();

        write_trace(path, &metadata, &events).expect("write trace");

        insta::assert_json_snapshot!(
            "trace_file_layout_scrubbed_recorded_at",
            trace_file_layout_summary(path)
        );
    }

    #[test]
    fn write_and_read_roundtrip() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata::new(42).with_description("test trace");
        let events = sample_events();

        // Write
        write_trace(path, &metadata, &events).expect("write trace");

        // Read
        let (read_meta, read_events) = read_trace(path).expect("read trace");

        assert_eq!(read_meta.seed, metadata.seed);
        assert_eq!(read_meta.description, metadata.description);
        assert_eq!(read_events.len(), events.len());

        for (orig, read) in events.iter().zip(read_events.iter()) {
            assert_eq!(orig, read);
        }
    }

    #[test]
    fn current_trace_header_carries_metadata_and_event_digests() {
        let temp = NamedTempFile::new().expect("create temp file");
        let metadata = TraceMetadata::new(42);
        let events = sample_events();
        write_trace(temp.path(), &metadata, &events).expect("write trace");

        let bytes = std::fs::read(temp.path()).expect("read trace");
        let version = u16::from_le_bytes(
            bytes[TRACE_MAGIC.len()..TRACE_MAGIC.len() + 2]
                .try_into()
                .expect("version bytes"),
        );
        let flags = u16::from_le_bytes(
            bytes[TRACE_MAGIC.len() + 2..TRACE_MAGIC.len() + 4]
                .try_into()
                .expect("flags bytes"),
        );
        assert_eq!(version, TRACE_FILE_VERSION);
        assert_eq!(flags & FLAG_CHECKSUMMED, FLAG_CHECKSUMMED);
        assert_eq!(
            TraceReader::open(temp.path())
                .expect("open current trace")
                .load_all()
                .expect("verify current trace"),
            events
        );
    }

    #[test]
    fn zero_file_version_and_mismatched_compression_byte_fail_closed() {
        let temp = NamedTempFile::new().expect("create temp file");
        write_trace(temp.path(), &TraceMetadata::new(42), &sample_events()).expect("write trace");
        let baseline = std::fs::read(temp.path()).expect("read trace");

        let mut zero_version = baseline.clone();
        zero_version[TRACE_MAGIC.len()..TRACE_MAGIC.len() + 2].copy_from_slice(&0u16.to_le_bytes());
        std::fs::write(temp.path(), zero_version).expect("write zero-version trace");
        assert!(matches!(
            TraceReader::open(temp.path()),
            Err(TraceFileError::UnsupportedVersion { found: 0, .. })
        ));

        let mut mismatched_compression = baseline;
        mismatched_compression[TRACE_MAGIC.len() + 4] = 1;
        std::fs::write(temp.path(), mismatched_compression)
            .expect("write mismatched compression byte");
        assert!(matches!(
            TraceReader::open(temp.path()),
            Err(TraceFileError::UnsupportedCompression(1))
        ));
    }

    #[test]
    fn metadata_checksum_mismatch_fails_before_decode() {
        let temp = NamedTempFile::new().expect("create temp file");
        write_trace(temp.path(), &TraceMetadata::new(42), &sample_events()).expect("write trace");

        let mut bytes = std::fs::read(temp.path()).expect("read trace");
        bytes[LEGACY_HEADER_SIZE] ^= 0x01;
        std::fs::write(temp.path(), bytes).expect("corrupt metadata digest");

        let error = match TraceReader::open(temp.path()) {
            Ok(_) => panic!("checksum must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            TraceFileError::ChecksumMismatch {
                section: "metadata"
            }
        ));
    }

    #[test]
    fn event_stream_checksum_mismatch_is_fail_closed() {
        let temp = NamedTempFile::new().expect("create temp file");
        let metadata = TraceMetadata::new(42);
        let events = sample_events();
        write_trace(temp.path(), &metadata, &events).expect("write trace");

        let mut bytes = std::fs::read(temp.path()).expect("read trace");
        let meta_len = rmp_serde::to_vec(&metadata)
            .expect("serialize metadata")
            .len();
        let event_digest_offset = HEADER_SIZE + meta_len + 8;
        bytes[event_digest_offset] ^= 0x01;
        std::fs::write(temp.path(), bytes).expect("corrupt event digest");

        let error = TraceReader::open(temp.path())
            .expect("header remains valid")
            .load_all()
            .expect_err("event digest must fail");
        assert!(matches!(
            error,
            TraceFileError::ChecksumMismatch {
                section: "event stream"
            }
        ));
    }

    #[test]
    fn v2_reader_and_non_overwriting_migration_preserve_semantics_and_source() {
        let source = NamedTempFile::new().expect("create source");
        let output_dir = tempfile::tempdir().expect("create output dir");
        let output = output_dir.path().join("migrated.trace");
        let metadata = TraceMetadata::new(7).with_description("legacy-v2");
        let events = sample_events();
        write_v2_trace(source.path(), &metadata, &events, events.len() as u64);
        let source_bytes = std::fs::read(source.path()).expect("read source baseline");

        let legacy_reader = TraceReader::open(source.path()).expect("open v2");
        assert_eq!(legacy_reader.file_version(), 2);
        assert_eq!(legacy_reader.load_all().expect("read v2"), events);

        let receipt = migrate_trace_file(source.path(), &output).expect("migrate v2");
        assert_eq!(receipt.source_version, 2);
        assert_eq!(receipt.target_version, TRACE_FILE_VERSION);
        assert_eq!(receipt.events_copied, events.len() as u64);
        assert_eq!(
            std::fs::read(source.path()).expect("read source after migration"),
            source_bytes,
            "migration must preserve the rollback source byte-for-byte"
        );

        let migrated = TraceReader::open(&output).expect("open migrated trace");
        assert_eq!(migrated.file_version(), TRACE_FILE_VERSION);
        assert_eq!(migrated.metadata(), &metadata);
        assert_eq!(migrated.load_all().expect("read migrated trace"), events);
    }

    #[test]
    fn v1_reader_and_migration_preserve_semantics_and_source() {
        let source = NamedTempFile::new().expect("create source");
        let output_dir = tempfile::tempdir().expect("create output dir");
        let output = output_dir.path().join("migrated.trace");
        let metadata = TraceMetadata::new(5).with_description("legacy-v1");
        let events = sample_events();
        write_v1_trace(source.path(), &metadata, &events);
        let source_bytes = std::fs::read(source.path()).expect("read source baseline");

        let reader = TraceReader::open(source.path()).expect("open v1");
        assert_eq!(reader.file_version(), 1);
        assert_eq!(reader.load_all().expect("read v1"), events);

        let receipt = migrate_trace_file(source.path(), &output).expect("migrate v1");
        assert_eq!(receipt.source_version, 1);
        assert_eq!(receipt.target_version, TRACE_FILE_VERSION);
        assert_eq!(receipt.events_copied, events.len() as u64);
        assert_eq!(
            std::fs::read(source.path()).expect("read source after migration"),
            source_bytes
        );
        assert_eq!(
            TraceReader::open(&output)
                .expect("open migrated trace")
                .load_all()
                .expect("read migrated trace"),
            events
        );
    }

    #[test]
    fn migration_refuses_same_or_existing_destination_without_overwrite() {
        let source = NamedTempFile::new().expect("create source");
        let destination = NamedTempFile::new().expect("create destination");
        let destination_before = b"do not overwrite".to_vec();
        std::fs::write(destination.path(), &destination_before).expect("seed destination");
        write_v2_trace(source.path(), &TraceMetadata::new(17), &sample_events(), 3);

        assert!(matches!(
            migrate_trace_file(source.path(), source.path()),
            Err(TraceFileError::MigrationInputOutputSame)
        ));
        assert!(matches!(
            migrate_trace_file(source.path(), destination.path()),
            Err(TraceFileError::MigrationDestinationExists)
        ));
        assert_eq!(
            std::fs::read(destination.path()).expect("read destination"),
            destination_before
        );
    }

    #[test]
    fn a7_migration_failure_never_publishes_partial_output_or_leaves_staging_file() {
        let directory = tempfile::tempdir().expect("create migration directory");
        let source = directory.path().join("truncated-v2.trace");
        let destination = directory.path().join("must-not-exist.trace");
        let events = sample_events();
        write_v2_trace(&source, &TraceMetadata::new(19), &events[..3], 3);
        let source_before = std::fs::read(&source).expect("read complete v2 source");
        std::fs::write(&source, &source_before[..source_before.len() - 1])
            .expect("truncate final event");
        let truncated_source = std::fs::read(&source).expect("read truncated source");

        assert!(migrate_trace_file(&source, &destination).is_err());
        assert!(
            !destination.exists(),
            "failed migration must not publish a partial destination"
        );
        assert_eq!(
            std::fs::read(&source).expect("read rollback source"),
            truncated_source,
            "failed migration must preserve its rollback source"
        );

        let staging_prefix = ".must-not-exist.trace.asupersync-migrate-";
        let staging_paths = std::fs::read_dir(directory.path())
            .expect("read migration directory")
            .map(|entry| entry.expect("read directory entry").file_name())
            .filter(|name| name.to_string_lossy().starts_with(staging_prefix))
            .collect::<Vec<_>>();
        assert!(
            staging_paths.is_empty(),
            "failed migration left staging paths: {staging_paths:?}"
        );
    }

    #[test]
    fn bounded_recovery_returns_verified_v2_prefix_and_terminal_error() {
        let source = NamedTempFile::new().expect("create source");
        let metadata = TraceMetadata::new(9);
        let events = sample_events();
        write_v2_trace(source.path(), &metadata, &events[..2], 3);

        let recovery = recover_trace_prefix(source.path(), 10).expect("recover prefix");
        assert_eq!(recovery.file_version, 2);
        assert_eq!(recovery.declared_events, 3);
        assert_eq!(recovery.recovered_events, events[..2]);
        assert!(matches!(
            recovery.status,
            TraceRecoveryStatus::Partial { next_event: 2, .. }
        ));
    }

    #[test]
    fn bounded_recovery_never_exceeds_caller_event_limit() {
        let source = NamedTempFile::new().expect("create source");
        let events = sample_events();
        write_v2_trace(
            source.path(),
            &TraceMetadata::new(11),
            &events,
            events.len() as u64,
        );

        let recovery = recover_trace_prefix(source.path(), 2).expect("recover bounded prefix");
        assert_eq!(recovery.recovered_events, events[..2]);
        assert_eq!(
            recovery.status,
            TraceRecoveryStatus::LimitReached { max_events: 2 }
        );
    }

    #[test]
    fn trace_file_roundtrip_serialization_summary() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata {
            version: REPLAY_SCHEMA_VERSION,
            seed: 7,
            recorded_at: 1_726_133_456_789_000_000,
            config_hash: 0x1020_3040_5060_7080,
            description: Some("trace file round-trip snapshot".to_string()),
        };
        let events = sample_events();

        write_trace(path, &metadata, &events).expect("write trace");

        insta::assert_json_snapshot!(
            "trace_file_roundtrip_serialization_summary",
            trace_file_roundtrip_summary(path)
        );
    }

    #[cfg(not(feature = "trace-compression"))]
    #[test]
    fn compressed_header_without_feature_reports_compression_not_available() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();
        let mut file = std::fs::File::create(path).expect("create file");
        write_header_with_raw_compression(&mut file, FLAG_COMPRESSED, 1);
        file.write_all(&0u64.to_le_bytes())
            .expect("write event count");
        file.flush().expect("flush");
        drop(file);

        let err = TraceReader::open(path).expect_err("compressed trace must require feature");
        assert!(
            matches!(err, TraceFileError::CompressionNotAvailable),
            "got: {err:?}"
        );
    }

    #[test]
    fn streaming_write_and_read() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata::new(123);
        let events = sample_events();

        // Streaming write
        {
            let mut writer = TraceWriter::create(path).expect("create writer");
            writer.write_metadata(&metadata).expect("write metadata");
            for event in &events {
                writer.write_event(event).expect("write event");
            }
            assert_eq!(writer.event_count(), events.len() as u64);
            writer.finish().expect("finish");
        }

        // Streaming read
        {
            let reader = TraceReader::open(path).expect("open reader");
            assert_eq!(reader.metadata().seed, 123);
            assert_eq!(reader.event_count(), events.len() as u64);

            let mut count = 0;
            for result in reader.events() {
                let event = result.expect("read event");
                assert_eq!(event, events[count]);
                count += 1;
            }
            assert_eq!(count, events.len());
        }
    }

    #[test]
    fn reader_rewind() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events();
        write_trace(path, &metadata, &events).expect("write trace");

        let mut reader = TraceReader::open(path).expect("open reader");

        // Read first two events
        let e1 = reader.read_event().expect("read").expect("event");
        let e2 = reader.read_event().expect("read").expect("event");
        assert_eq!(reader.events_read(), 2);

        // Rewind and verify we get the same events
        reader.rewind().expect("rewind");
        assert_eq!(reader.events_read(), 0);

        let e1_again = reader.read_event().expect("read").expect("event");
        let e2_again = reader.read_event().expect("read").expect("event");
        assert_eq!(e1, e1_again);
        assert_eq!(e2, e2_again);
    }

    #[test]
    fn empty_trace() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata::new(0);
        write_trace(path, &metadata, &[]).expect("write empty trace");

        let (read_meta, read_events) = read_trace(path).expect("read empty trace");
        assert_eq!(read_meta.seed, 0);
        assert!(read_events.is_empty());
    }

    #[test]
    fn large_trace() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let event_count = 10_000;

        // Generate large trace
        let events: Vec<_> = (0..event_count)
            .map(|i| ReplayEvent::TaskScheduled {
                task: CompactTaskId(i),
                at_tick: i,
            })
            .collect();

        write_trace(path, &metadata, &events).expect("write large trace");

        // Read with streaming
        let reader = TraceReader::open(path).expect("open reader");
        assert_eq!(reader.event_count(), event_count);

        let mut count = 0u64;
        for result in reader.events() {
            let event = result.expect("read event");
            if let ReplayEvent::TaskScheduled { task, at_tick } = event {
                assert_eq!(task.0, count);
                assert_eq!(at_tick, count);
            } else {
                unreachable!("unexpected event type");
            }
            count += 1;
        }
        assert_eq!(count, event_count);
    }

    #[test]
    fn invalid_magic() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        // Write garbage
        std::fs::write(path, b"NOT A TRACE FILE").expect("write garbage");

        let result = TraceReader::open(path);
        assert!(matches!(result, Err(TraceFileError::InvalidMagic)));
    }

    #[test]
    fn reader_read_event_errors_on_truncated_stream() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();
        let mut file = std::fs::File::create(path).expect("create file");
        write_header_with_metadata(&mut file, CompressionMode::None);
        file.write_all(&1u64.to_le_bytes())
            .expect("write event count");
        file.flush().expect("flush");
        drop(file);

        let mut reader = TraceReader::open(path).expect("open reader");
        let err = reader
            .read_event()
            .expect_err("missing declared event must error");
        assert!(matches!(err, TraceFileError::Truncated), "got: {err:?}");
    }

    #[test]
    fn event_iterator_errors_on_truncated_stream() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();
        let mut file = std::fs::File::create(path).expect("create file");
        write_header_with_metadata(&mut file, CompressionMode::None);
        file.write_all(&1u64.to_le_bytes())
            .expect("write event count");
        file.flush().expect("flush");
        drop(file);

        let mut iter = TraceReader::open(path).expect("open reader").events();
        let first = iter
            .next()
            .expect("iterator should emit an error for the missing event");
        assert!(
            matches!(first, Err(TraceFileError::Truncated)),
            "got: {first:?}"
        );
    }

    #[test]
    fn file_size_reasonable() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events: Vec<_> = (0..1000)
            .map(|i| ReplayEvent::TaskScheduled {
                task: CompactTaskId(i),
                at_tick: i,
            })
            .collect();

        write_trace(path, &metadata, &events).expect("write trace");

        let file_size = std::fs::metadata(path).expect("metadata").len();
        let file_size = u32::try_from(file_size).expect("trace file size fits u32 for test");
        let bytes_per_event = f64::from(file_size) / 1000.0;

        // Should be well under 64 bytes per event
        assert!(
            bytes_per_event < 40.0,
            "File size too large: {bytes_per_event:.1} bytes/event"
        );
    }

    #[test]
    fn writer_already_finished_error() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let mut writer = TraceWriter::create(path).expect("create writer");
        writer
            .write_metadata(&TraceMetadata::new(42))
            .expect("write metadata");
        writer.finish().expect("finish");

        // Attempting to use a finished writer should not be possible
        // because finish() consumes self, so this is compile-time safety
    }

    #[test]
    fn write_event_requires_metadata_first() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let mut writer = TraceWriter::create(path).expect("create writer");
        let err = writer
            .write_event(&ReplayEvent::RngSeed { seed: 42 })
            .expect_err("events before metadata must be rejected");
        assert!(matches!(err, TraceFileError::MetadataNotWritten));

        drop(writer);

        let file_len = std::fs::metadata(path).expect("metadata").len();
        assert_eq!(
            file_len, 0,
            "rejecting pre-header events must not scribble an event count at offset zero"
        );
    }

    #[test]
    fn finish_requires_metadata_first() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let writer = TraceWriter::create(path).expect("create writer");
        let err = writer
            .finish()
            .expect_err("finish without metadata must be rejected");
        assert!(matches!(err, TraceFileError::MetadataNotWritten));

        let file_len = std::fs::metadata(path).expect("metadata").len();
        assert_eq!(
            file_len, 0,
            "failed finish without metadata must leave the new file empty"
        );
    }

    #[test]
    fn write_metadata_rejects_duplicate_headers_without_corrupting_file() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let mut writer = TraceWriter::create(path).expect("create writer");
        writer.write_metadata(&metadata).expect("write metadata");
        let err = writer
            .write_metadata(&metadata)
            .expect_err("duplicate metadata must be rejected");
        assert!(matches!(err, TraceFileError::MetadataAlreadyWritten));

        writer.finish().expect("finish");

        let reader = TraceReader::open(path).expect("open reader");
        assert_eq!(reader.metadata().seed, metadata.seed);
        assert_eq!(reader.event_count(), 0);
    }

    #[test]
    fn write_stops_at_max_events() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();
        let metadata = TraceMetadata::new(42);
        let events = sample_events();

        let config = TraceFileConfig::new().with_max_events(Some(2));
        let mut writer = TraceWriter::create_with_config(path, config).expect("create writer");
        writer.write_metadata(&metadata).expect("write metadata");
        for event in &events {
            writer.write_event(event).expect("write event");
        }
        writer.finish().expect("finish");

        let reader = TraceReader::open(path).expect("open reader");
        assert_eq!(reader.event_count(), 2);
    }

    #[test]
    fn write_stops_at_max_file_size() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let meta_len = rmp_serde::to_vec(&metadata)
            .expect("serialize metadata")
            .len() as u64;
        let header_bytes = HEADER_SIZE as u64 + meta_len + 8 + TRACE_CHECKSUM_LEN as u64;

        let config = TraceFileConfig::new().with_max_file_size(header_bytes);
        let mut writer = TraceWriter::create_with_config(path, config).expect("create writer");
        writer.write_metadata(&metadata).expect("write metadata");
        writer
            .write_event(&ReplayEvent::RngSeed { seed: 42 })
            .expect("write event");
        writer.finish().expect("finish");

        let reader = TraceReader::open(path).expect("open reader");
        assert_eq!(reader.event_count(), 0);
    }

    #[test]
    fn write_limit_callback_invoked() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let hits = Arc::new(AtomicUsize::new(0));
        let hit_ref = Arc::clone(&hits);
        let action = LimitAction::Callback(Arc::new(move |_info| {
            hit_ref.fetch_add(1, Ordering::SeqCst);
            LimitAction::StopRecording
        }));

        let config = TraceFileConfig::new()
            .with_max_events(Some(1))
            .on_limit(action);
        let mut writer = TraceWriter::create_with_config(path, config).expect("create writer");
        writer
            .write_metadata(&TraceMetadata::new(42))
            .expect("write metadata");
        writer
            .write_event(&ReplayEvent::RngSeed { seed: 1 })
            .expect("write event");
        writer
            .write_event(&ReplayEvent::RngSeed { seed: 2 })
            .expect("write event");
        writer.finish().expect("finish");

        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    #[cfg(target_family = "unix")]
    fn disk_full_is_handled() {
        let path = std::path::Path::new("/dev/full");
        if !path.exists() {
            return;
        }

        let Ok(mut writer) = TraceWriter::create(path) else {
            return;
        };

        // write_metadata buffers to BufWriter, which may not immediately
        // write to disk. We need to finish() to flush and detect ENOSPC.
        let _ = writer.write_metadata(&TraceMetadata::new(42));
        let result = writer.finish();
        assert!(matches!(
            result,
            Err(TraceFileError::Io(err)) if is_disk_full_os_error(err.raw_os_error())
        ));
    }

    // =========================================================================
    // Compression Tests (feature-gated)
    // =========================================================================

    #[cfg(feature = "trace-compression")]
    mod compression_tests {
        use super::*;

        #[test]
        fn write_trace_with_config_writes_compressed_trace() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();

            let metadata = TraceMetadata::new(42).with_description("compressed helper trace");
            let events = sample_events();
            let config = TraceFileConfig::new().with_compression(CompressionMode::Lz4 { level: 1 });

            write_trace_with_config(path, &metadata, &events, config).expect("write trace");

            let reader = TraceReader::open(path).expect("open reader");
            assert!(reader.is_compressed());
            assert_eq!(reader.compression(), CompressionMode::Lz4 { level: 1 });
            assert_eq!(reader.load_all().expect("load all"), events);
        }

        #[test]
        fn compressed_write_and_read_roundtrip() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();

            let metadata = TraceMetadata::new(42).with_description("compressed trace");
            let events = sample_events();

            // Write with compression
            let config = TraceFileConfig::new().with_compression(CompressionMode::Lz4 { level: 1 });
            let mut writer = TraceWriter::create_with_config(path, config).expect("create writer");
            writer.write_metadata(&metadata).expect("write metadata");
            for event in &events {
                writer.write_event(event).expect("write event");
            }
            writer.finish().expect("finish");

            // Read (auto-detects compression)
            let reader = TraceReader::open(path).expect("open reader");
            assert!(reader.is_compressed());
            assert_eq!(reader.metadata().seed, metadata.seed);
            assert_eq!(reader.event_count(), events.len() as u64);

            let read_events = reader.load_all().expect("load all");
            assert_eq!(read_events.len(), events.len());
            for (orig, read) in events.iter().zip(read_events.iter()) {
                assert_eq!(orig, read);
            }
        }

        #[test]
        fn compressed_event_stream_checksum_mismatch_is_fail_closed() {
            let temp = NamedTempFile::new().expect("create temp file");
            let metadata = TraceMetadata::new(42);
            let events = sample_events();
            let config = TraceFileConfig::new().with_compression(CompressionMode::Lz4 { level: 1 });
            write_trace_with_config(temp.path(), &metadata, &events, config)
                .expect("write compressed trace");

            let mut bytes = std::fs::read(temp.path()).expect("read trace");
            let metadata_len = rmp_serde::to_vec(&metadata)
                .expect("serialize metadata")
                .len();
            let event_digest_offset = HEADER_SIZE + metadata_len + 8;
            bytes[event_digest_offset] ^= 0x01;
            std::fs::write(temp.path(), bytes).expect("corrupt event digest");

            let error = TraceReader::open(temp.path())
                .expect("header remains valid")
                .load_all()
                .expect_err("compressed event checksum must fail");
            assert!(matches!(
                error,
                TraceFileError::ChecksumMismatch {
                    section: "event stream"
                }
            ));
        }

        #[test]
        fn compressed_streaming_read() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();

            let metadata = TraceMetadata::new(123);
            let events = sample_events();

            // Write with compression
            let config = TraceFileConfig::new().with_compression(CompressionMode::Lz4 { level: 1 });
            let mut writer = TraceWriter::create_with_config(path, config).expect("create writer");
            writer.write_metadata(&metadata).expect("write metadata");
            for event in &events {
                writer.write_event(event).expect("write event");
            }
            writer.finish().expect("finish");

            // Streaming read
            let reader = TraceReader::open(path).expect("open reader");
            assert!(reader.is_compressed());

            let mut count = 0;
            for result in reader.events() {
                let event = result.expect("read event");
                assert_eq!(event, events[count]);
                count += 1;
            }
            assert_eq!(count, events.len());
        }

        #[test]
        fn large_compressed_trace() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();

            let metadata = TraceMetadata::new(42);
            let event_count = 10_000u64;

            // Generate large trace
            let events: Vec<_> = (0..event_count)
                .map(|i| ReplayEvent::TaskScheduled {
                    task: CompactTaskId(i),
                    at_tick: i,
                })
                .collect();

            // Write with compression
            let config = TraceFileConfig::new()
                .with_compression(CompressionMode::Lz4 { level: 1 })
                .with_chunk_size(8 * 1024); // 8KB chunks for more chunks in test
            let mut writer = TraceWriter::create_with_config(path, config).expect("create writer");
            writer.write_metadata(&metadata).expect("write metadata");
            for event in &events {
                writer.write_event(event).expect("write event");
            }
            writer.finish().expect("finish");

            // Read with streaming
            let reader = TraceReader::open(path).expect("open reader");
            assert!(reader.is_compressed());
            assert_eq!(reader.event_count(), event_count);

            let mut count = 0u64;
            for result in reader.events() {
                let event = result.expect("read event");
                if let ReplayEvent::TaskScheduled { task, at_tick } = event {
                    assert_eq!(task.0, count);
                    assert_eq!(at_tick, count);
                } else {
                    unreachable!("unexpected event type");
                }
                count += 1;
            }
            assert_eq!(count, event_count);
        }

        #[test]
        fn compression_ratio() {
            let temp_uncompressed = NamedTempFile::new().expect("create temp file");
            let temp_compressed = NamedTempFile::new().expect("create temp file");

            let metadata = TraceMetadata::new(42);
            let event_count = 5000u64;

            // Generate trace with repetitive data (good for compression)
            let events: Vec<_> = (0..event_count)
                .map(|i| ReplayEvent::TaskScheduled {
                    task: CompactTaskId(i % 100), // Repetitive task IDs
                    at_tick: i,
                })
                .collect();

            // Write uncompressed
            {
                let mut writer =
                    TraceWriter::create(temp_uncompressed.path()).expect("create writer");
                writer.write_metadata(&metadata).expect("write metadata");
                for event in &events {
                    writer.write_event(event).expect("write event");
                }
                writer.finish().expect("finish");
            }

            // Write compressed
            {
                let config =
                    TraceFileConfig::new().with_compression(CompressionMode::Lz4 { level: 1 });
                let mut writer = TraceWriter::create_with_config(temp_compressed.path(), config)
                    .expect("create writer");
                writer.write_metadata(&metadata).expect("write metadata");
                for event in &events {
                    writer.write_event(event).expect("write event");
                }
                writer.finish().expect("finish");
            }

            let uncompressed_size = std::fs::metadata(temp_uncompressed.path())
                .expect("metadata")
                .len();
            let compressed_size = std::fs::metadata(temp_compressed.path())
                .expect("metadata")
                .len();

            #[allow(clippy::cast_precision_loss)]
            let ratio = uncompressed_size as f64 / compressed_size as f64;

            // LZ4 should achieve at least 2x compression on this repetitive data
            assert!(
                ratio > 2.0,
                "Compression ratio {ratio:.2}x is below expected 2x minimum"
            );
        }

        #[test]
        fn compressed_rewind() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();

            let metadata = TraceMetadata::new(42);
            let events = sample_events();

            // Write with compression
            let config = TraceFileConfig::new().with_compression(CompressionMode::Lz4 { level: 1 });
            let mut writer = TraceWriter::create_with_config(path, config).expect("create writer");
            writer.write_metadata(&metadata).expect("write metadata");
            for event in &events {
                writer.write_event(event).expect("write event");
            }
            writer.finish().expect("finish");

            let mut reader = TraceReader::open(path).expect("open reader");
            assert!(reader.is_compressed());

            // Read first two events
            let e1 = reader.read_event().expect("read").expect("event");
            let e2 = reader.read_event().expect("read").expect("event");
            assert_eq!(reader.events_read(), 2);

            // Rewind and verify we get the same events
            reader.rewind().expect("rewind");
            assert_eq!(reader.events_read(), 0);

            let e1_again = reader.read_event().expect("read").expect("event");
            let e2_again = reader.read_event().expect("read").expect("event");
            assert_eq!(e1, e1_again);
            assert_eq!(e2, e2_again);
        }

        #[test]
        fn uncompressed_still_readable() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();

            let metadata = TraceMetadata::new(42);
            let events = sample_events();

            // Write without compression
            write_trace(path, &metadata, &events).expect("write trace");

            // Should read successfully and report not compressed
            let reader = TraceReader::open(path).expect("open reader");
            assert!(!reader.is_compressed());
            assert_eq!(reader.event_count(), events.len() as u64);

            let read_events = reader.load_all().expect("load all");
            assert_eq!(read_events, events);
        }

        #[test]
        fn reader_read_event_errors_on_truncated_compressed_stream() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();
            let mut file = std::fs::File::create(path).expect("create file");
            write_header_with_metadata(&mut file, CompressionMode::Lz4 { level: 1 });
            file.write_all(&1u64.to_le_bytes())
                .expect("write event count");
            file.flush().expect("flush");
            drop(file);

            let mut reader = TraceReader::open(path).expect("open reader");
            let err = reader
                .read_event()
                .expect_err("missing compressed chunk must error");
            assert!(matches!(err, TraceFileError::Truncated), "got: {err:?}");
        }

        #[test]
        fn event_iterator_errors_on_truncated_compressed_stream() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();
            let mut file = std::fs::File::create(path).expect("create file");
            write_header_with_metadata(&mut file, CompressionMode::Lz4 { level: 1 });
            file.write_all(&1u64.to_le_bytes())
                .expect("write event count");
            file.flush().expect("flush");
            drop(file);

            let mut iter = TraceReader::open(path).expect("open reader").events();
            let first = iter
                .next()
                .expect("iterator should emit an error for the missing chunk");
            assert!(
                matches!(first, Err(TraceFileError::Truncated)),
                "got: {first:?}"
            );
        }

        #[test]
        fn reader_read_event_rejects_oversized_event_len_in_compressed_stream() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();
            let mut file = std::fs::File::create(path).expect("create file");
            write_header_with_metadata(&mut file, CompressionMode::Lz4 { level: 1 });
            file.write_all(&1u64.to_le_bytes())
                .expect("write event count");

            let oversized_len = u32::try_from(MAX_EVENT_LEN + 1).expect("event limit fits in u32");
            let compressed = lz4_flex::compress_prepend_size(&oversized_len.to_le_bytes());
            let chunk_len = u32::try_from(compressed.len()).expect("compressed chunk fits in u32");
            file.write_all(&chunk_len.to_le_bytes())
                .expect("write chunk len");
            file.write_all(&compressed).expect("write chunk");
            file.flush().expect("flush");
            drop(file);

            let mut reader = TraceReader::open(path).expect("open reader");
            let err = reader
                .read_event()
                .expect_err("oversized event len must error");
            assert!(
                matches!(
                    err,
                    TraceFileError::OversizedField {
                        field: "event_len",
                        actual,
                        max,
                    } if actual == (MAX_EVENT_LEN as u64) + 1 && max == MAX_EVENT_LEN as u64
                ),
                "got: {err:?}"
            );
        }

        #[test]
        fn event_iterator_rejects_oversized_event_len_in_compressed_stream() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();
            let mut file = std::fs::File::create(path).expect("create file");
            write_header_with_metadata(&mut file, CompressionMode::Lz4 { level: 1 });
            file.write_all(&1u64.to_le_bytes())
                .expect("write event count");

            let oversized_len = u32::try_from(MAX_EVENT_LEN + 1).expect("event limit fits in u32");
            let compressed = lz4_flex::compress_prepend_size(&oversized_len.to_le_bytes());
            let chunk_len = u32::try_from(compressed.len()).expect("compressed chunk fits in u32");
            file.write_all(&chunk_len.to_le_bytes())
                .expect("write chunk len");
            file.write_all(&compressed).expect("write chunk");
            file.flush().expect("flush");
            drop(file);

            let mut iter = TraceReader::open(path).expect("open reader").events();
            let first = iter
                .next()
                .expect("iterator should emit an error for oversized event len");
            assert!(
                matches!(
                    first,
                    Err(TraceFileError::OversizedField {
                        field: "event_len",
                        actual,
                        max,
                    }) if actual == (MAX_EVENT_LEN as u64) + 1 && max == MAX_EVENT_LEN as u64
                ),
                "got: {first:?}"
            );
        }
    }
