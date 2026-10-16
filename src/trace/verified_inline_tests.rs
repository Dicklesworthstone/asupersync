    #![allow(clippy::pedantic, clippy::nursery, missing_docs)]
    use super::*;
    use crate::trace::file::{HEADER_SIZE, TRACE_MAGIC, write_trace};
    use crate::trace::replay::REPLAY_SCHEMA_VERSION;
    use std::io::{Seek, SeekFrom};
    use tempfile::NamedTempFile;

    fn metadata() -> TraceMetadata {
        TraceMetadata {
            version: REPLAY_SCHEMA_VERSION, seed: 42, recorded_at: 0,
            config_hash: 17, description: Some("verified replay".to_owned()),
        }
    }

    fn events() -> Vec<ReplayEvent> {
        (0..8).map(|seed| ReplayEvent::RngSeed { seed }).collect()
    }

    fn limits() -> TraceReadLimits { TraceReadLimits::new(10_000, 4 * 1024 * 1024) }

    fn write_legacy(path: &Path, events: &[ReplayEvent], declared: u64) {
        let mut file = File::create(path).unwrap();
        file.write_all(TRACE_MAGIC).unwrap();
        file.write_all(&2u16.to_le_bytes()).unwrap();
        file.write_all(&0u16.to_le_bytes()).unwrap();
        file.write_all(&[0]).unwrap();
        let metadata = rmp_serde::to_vec(&metadata()).unwrap();
        file.write_all(&(metadata.len() as u32).to_le_bytes()).unwrap();
        file.write_all(&metadata).unwrap();
        file.write_all(&declared.to_le_bytes()).unwrap();
        for event in events {
            let bytes = rmp_serde::to_vec(event).unwrap();
            file.write_all(&(bytes.len() as u32).to_le_bytes()).unwrap();
            file.write_all(&bytes).unwrap();
        }
    }

    use std::fs::File;

    #[test]
    fn verified_roundtrip_has_conservative_hints_and_continues_after_direct_reads() {
        let temp = NamedTempFile::new().unwrap();
        write_trace(temp.path(), &metadata(), &events()).unwrap();
        let mut reader = VerifiedTraceReader::open(temp.path(), limits()).unwrap();
        assert_eq!(reader.metadata(), &metadata());
        assert_eq!(reader.size_hint(), (0, Some(8)));
        assert_eq!(reader.next_event().unwrap(), Some(events()[0].clone()));
        assert_eq!(reader.events_consumed(), 1);
        assert_eq!(reader.size_hint(), (0, Some(7)));
        let tail: Vec<_> = reader.by_ref().collect::<Result<_, _>>().unwrap();
        assert_eq!(tail, events()[1..]);
        assert!(reader.is_complete());
        assert_eq!(reader.size_hint(), (0, Some(0)));
        assert!(reader.next().is_none());
        assert!(reader.next().is_none());
    }

    #[test]
    fn every_checkpoint_position_roundtrips_and_resumes_the_correct_suffix() {
        let temp = NamedTempFile::new().unwrap();
        write_trace(temp.path(), &metadata(), &events()).unwrap();
        let mut reader = VerifiedTraceReader::open(temp.path(), limits()).unwrap();
        for position in 0..=events().len() {
            let checkpoint = reader.checkpoint().unwrap();
            assert_eq!(checkpoint.position(), position as u64);
            assert_eq!(checkpoint.total_events(), events().len() as u64);
            let decoded = VerifiedReplayCheckpoint::from_bytes(&checkpoint.to_bytes()).unwrap();
            assert_eq!(decoded, checkpoint);
            let mut resumed = VerifiedTraceReader::resume(temp.path(), decoded, limits()).unwrap();
            assert_eq!(resumed.events_consumed(), position as u64);
            let tail: Vec<_> = resumed.by_ref().collect::<Result<_, _>>().unwrap();
            assert_eq!(tail, events()[position..]);
            assert!(resumed.is_complete());
            let _ = reader.next_event().unwrap();
        }
    }

    #[test]
    fn checkpoint_rejects_a_changed_unread_suffix_with_identical_metadata_and_count() {
        let source = NamedTempFile::new().unwrap();
        let other = NamedTempFile::new().unwrap();
        write_trace(source.path(), &metadata(), &events()).unwrap();
        let mut reader = VerifiedTraceReader::open(source.path(), limits()).unwrap();
        reader.next_event().unwrap();
        let checkpoint = reader.checkpoint().unwrap();
        let mut changed = events();
        *changed.last_mut().unwrap() = ReplayEvent::RngSeed { seed: 999 };
        write_trace(other.path(), &metadata(), &changed).unwrap();
        assert!(matches!(VerifiedTraceReader::resume(other.path(), checkpoint, limits()),
            Err(VerifiedTraceError::CheckpointMismatch)));
    }

    #[test]
    fn checkpoint_rejects_metadata_count_and_event_order_changes() {
        let source = NamedTempFile::new().unwrap();
        let other = NamedTempFile::new().unwrap();
        write_trace(source.path(), &metadata(), &events()).unwrap();
        let checkpoint = VerifiedTraceReader::open(source.path(), limits()).unwrap().checkpoint().unwrap();
        let mut reordered = events();
        reordered.swap(0, 1);
        let mut changed_metadata = metadata();
        changed_metadata.config_hash += 1;
        for (meta, events) in [
            (changed_metadata, events()),
            (metadata(), events()[..7].to_vec()),
            (metadata(), reordered),
        ] {
            write_trace(other.path(), &meta, &events).unwrap();
            assert!(matches!(VerifiedTraceReader::resume(other.path(), checkpoint, limits()),
                Err(VerifiedTraceError::CheckpointMismatch)));
        }
    }

    #[test]
    fn checkpoint_encoding_rejects_all_truncations_trailing_data_and_invalid_positions() {
        let checkpoint = VerifiedReplayCheckpoint { position: 1, total_events: 8, content_digest: [42; 32] };
        let bytes = checkpoint.to_bytes();
        for cut in 0..bytes.len() {
            assert!(VerifiedReplayCheckpoint::from_bytes(&bytes[..cut]).is_err());
        }
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(VerifiedReplayCheckpoint::from_bytes(&extra).is_err());
        let mut bad = bytes;
        bad[7] = b'2';
        assert!(VerifiedReplayCheckpoint::from_bytes(&bad).is_err());
        bad = bytes;
        bad[8..16].copy_from_slice(&9u64.to_le_bytes());
        assert!(VerifiedReplayCheckpoint::from_bytes(&bad).is_err());
    }

    #[test]
    fn hostile_declared_count_is_refused_without_header_sized_preallocation() {
        let temp = NamedTempFile::new().unwrap();
        write_legacy(temp.path(), &[], u64::MAX);
        assert!(matches!(VerifiedTraceReader::open(temp.path(), limits()),
            Err(VerifiedTraceError::EventLimit { declared: u64::MAX, .. })));
        // Even an explicitly enormous caller cap never causes count-based allocation.
        assert!(matches!(VerifiedTraceReader::open(temp.path(), TraceReadLimits::new(u64::MAX, u64::MAX)),
            Err(VerifiedTraceError::Trace(TraceFileError::Truncated))));
    }

    #[test]
    fn canonical_byte_limits_cover_the_entire_stream_before_exposing_any_event() {
        let temp = NamedTempFile::new().unwrap();
        write_trace(temp.path(), &metadata(), &events()).unwrap();
        let size = events().iter().map(|event| rmp_serde::to_vec(event).unwrap().len() as u64).sum();
        let reader = VerifiedTraceReader::open(temp.path(), TraceReadLimits::new(8, size)).unwrap();
        assert_eq!(reader.collect::<Result<Vec<_>, _>>().unwrap(), events());
        assert!(matches!(VerifiedTraceReader::open(temp.path(), TraceReadLimits::new(8, size - 1)),
            Err(VerifiedTraceError::ByteLimit { event_index: 7, .. })));
        assert!(matches!(VerifiedTraceReader::open(temp.path(), TraceReadLimits::new(8, 0)),
            Err(VerifiedTraceError::ByteLimit { event_index: 0, .. })));
        assert!(matches!(VerifiedTraceReader::open(temp.path(), TraceReadLimits::new(7, size)),
            Err(VerifiedTraceError::EventLimit { .. })));
    }

    #[test]
    fn empty_trace_with_zero_limits_has_a_resumable_checkpoint() {
        let temp = NamedTempFile::new().unwrap();
        write_trace(temp.path(), &metadata(), &[]).unwrap();
        let reader = VerifiedTraceReader::open(temp.path(), TraceReadLimits::new(0, 0)).unwrap();
        assert!(reader.is_complete());
        let checkpoint = reader.checkpoint().unwrap();
        let resumed = VerifiedTraceReader::resume(temp.path(), checkpoint, TraceReadLimits::new(0, 0)).unwrap();
        assert!(resumed.is_complete());
        assert_eq!(resumed.count(), 0);
    }

    #[test]
    fn truncated_and_checksum_corrupt_files_are_rejected_during_open() {
        let temp = NamedTempFile::new().unwrap();
        write_trace(temp.path(), &metadata(), &events()).unwrap();
        let baseline = std::fs::read(temp.path()).unwrap();
        std::fs::write(temp.path(), &baseline[..baseline.len() - 1]).unwrap();
        assert!(VerifiedTraceReader::open(temp.path(), limits()).is_err());
        let mut corrupt = baseline;
        let offset = HEADER_SIZE + rmp_serde::to_vec(&metadata()).unwrap().len() + 8;
        corrupt[offset] ^= 1;
        std::fs::write(temp.path(), corrupt).unwrap();
        assert!(matches!(VerifiedTraceReader::open(temp.path(), limits()),
            Err(VerifiedTraceError::Trace(TraceFileError::ChecksumMismatch { section: "event stream" }))));
    }

    #[test]
    fn legacy_content_is_verified_and_checkpoint_bound_without_claiming_a_persisted_checksum() {
        let temp = NamedTempFile::new().unwrap();
        write_legacy(temp.path(), &events(), 8);
        let reader = VerifiedTraceReader::open(temp.path(), limits()).unwrap();
        let checkpoint = reader.checkpoint().unwrap();
        assert_eq!(reader.collect::<Result<Vec<_>, _>>().unwrap(), events());
        let current = NamedTempFile::new().unwrap();
        write_trace(current.path(), &metadata(), &events()).unwrap();
        let resumed = VerifiedTraceReader::resume(current.path(), checkpoint, limits()).unwrap();
        assert_eq!(resumed.collect::<Result<Vec<_>, _>>().unwrap(), events());
    }

    #[test]
    fn replay_failure_is_terminal_and_iterator_does_not_loop_or_emit_another_record() {
        let temp = NamedTempFile::new().unwrap();
        let many: Vec<_> = (0..4096).map(|seed| ReplayEvent::RngSeed { seed }).collect();
        write_trace(temp.path(), &metadata(), &many).unwrap();
        let baseline = std::fs::read(temp.path()).unwrap();
        let mut reader = VerifiedTraceReader::open(temp.path(), limits()).unwrap();
        assert_eq!(reader.next_event().unwrap(), Some(many[0].clone()));
        // Corrupt a frame far beyond BufReader's current buffer after admission.
        // This tests failure containment, not permission to mutate a live input.
        let last_size = rmp_serde::to_vec(many.last().unwrap()).unwrap().len();
        let offset = baseline.len() - last_size;
        assert!(offset > 32 * 1024, "mutation must be beyond the prefetched buffer");
        let mut file = std::fs::OpenOptions::new().write(true).open(temp.path()).unwrap();
        file.seek(SeekFrom::Start(offset as u64)).unwrap();
        file.write_all(&[0xc1]).unwrap();
        file.flush().unwrap();
        let mut successes = 1;
        let mut errors = 0;
        // The bound keeps a broken fusing regression finite and observable.
        for item in reader.by_ref().take(many.len() + 4) {
            match item { Ok(_) => successes += 1, Err(_) => errors += 1 }
        }
        assert_eq!(successes, many.len() - 1);
        assert_eq!(errors, 1);
        assert_eq!(reader.events_consumed(), (many.len() - 1) as u64);
        assert!(reader.has_failed());
        assert!(!reader.is_complete());
        assert_eq!(reader.size_hint(), (0, Some(0)));
        assert!(reader.next().is_none());
        assert!(reader.checkpoint().is_err());
        assert!(matches!(reader.next_event(), Err(VerifiedTraceError::ReaderFailed)));
    }

    #[cfg(feature = "trace-compression")]
    #[test]
    fn identical_compressed_and_plain_content_share_a_checkpoint() {
        use crate::trace::file::{CompressionMode, TraceFileConfig, write_trace_with_config};
        let plain = NamedTempFile::new().unwrap();
        let compressed = NamedTempFile::new().unwrap();
        write_trace(plain.path(), &metadata(), &events()).unwrap();
        write_trace_with_config(compressed.path(), &metadata(), &events(),
            TraceFileConfig::new().with_compression(CompressionMode::Lz4 { level: 1 }).with_chunk_size(32)).unwrap();
        let mut reader = VerifiedTraceReader::open(plain.path(), limits()).unwrap();
        reader.next_event().unwrap();
        let checkpoint = reader.checkpoint().unwrap();
        let resumed = VerifiedTraceReader::resume(compressed.path(), checkpoint, limits()).unwrap();
        assert_eq!(resumed.collect::<Result<Vec<_>, _>>().unwrap(), events()[1..]);
    }

    #[test]
    fn valid_legacy_rewrite_is_detected_by_the_final_content_fingerprint() {
        let temp = NamedTempFile::new().unwrap();
        let many: Vec<_> = (0..4096).map(|seed| ReplayEvent::RngSeed { seed }).collect();
        write_legacy(temp.path(), &many, many.len() as u64);
        let baseline = std::fs::read(temp.path()).unwrap();
        let original = rmp_serde::to_vec(many.last().unwrap()).unwrap();
        let changed = rmp_serde::to_vec(&ReplayEvent::RngSeed { seed: 4094 }).unwrap();
        assert_eq!(original.len(), changed.len());
        let offset = baseline.len() - original.len();
        assert!(offset > 32 * 1024);
        let mut reader = VerifiedTraceReader::open(temp.path(), limits()).unwrap();
        assert_eq!(reader.next_event().unwrap(), Some(many[0].clone()));
        let mut file = std::fs::OpenOptions::new().write(true).open(temp.path()).unwrap();
        file.seek(SeekFrom::Start(offset as u64)).unwrap();
        file.write_all(&changed).unwrap();
        file.flush().unwrap();
        for expected in &many[1..many.len() - 1] {
            assert_eq!(reader.next_event().unwrap().as_ref(), Some(expected));
        }
        assert!(matches!(reader.next_event(), Err(VerifiedTraceError::ContentChanged)));
        assert_eq!(reader.events_consumed(), (many.len() - 1) as u64);
        assert!(reader.next().is_none());
        assert!(reader.checkpoint().is_err());
    }
