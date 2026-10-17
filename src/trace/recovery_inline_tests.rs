    #![allow(clippy::pedantic, clippy::nursery, missing_docs)]
    use super::*;
    use crate::trace::file::{HEADER_SIZE, TraceFileConfig, TraceReader, TraceWriter, write_trace};
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn events() -> Vec<ReplayEvent> {
        (0..4).map(|seed| ReplayEvent::RngSeed { seed }).collect()
    }

    fn limits() -> CrashRecoveryLimits {
        CrashRecoveryLimits::new(100, 1024 * 1024)
    }

    fn unfinished_header(compressed: bool, declared: u64) -> Vec<u8> {
        let metadata = TraceMetadata::new(42);
        let payload = rmp_serde::to_vec(&metadata).unwrap();
        let mut bytes = TRACE_MAGIC.to_vec();
        bytes.extend_from_slice(&3u16.to_le_bytes());
        let flags = FLAG_CHECKSUMMED | if compressed { FLAG_COMPRESSED } else { 0 };
        bytes.extend_from_slice(&flags.to_le_bytes());
        bytes.push(u8::from(compressed));
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&Sha256::digest(&payload));
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&declared.to_le_bytes());
        bytes.extend_from_slice(&[0; TRACE_CHECKSUM_LEN]);
        bytes
    }

    fn frame(event: &ReplayEvent) -> Vec<u8> {
        let payload = rmp_serde::to_vec(event).unwrap();
        let mut bytes = (payload.len() as u32).to_le_bytes().to_vec();
        bytes.extend(payload);
        bytes
    }

    fn salvage(bytes: &[u8], limits: CrashRecoveryLimits) -> TraceFileResult<CrashRecovery> {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(bytes).unwrap();
        temp.flush().unwrap();
        recover_crashed_trace_prefix(temp.path(), limits)
    }

    #[test]
    fn unfinished_zero_or_interrupted_count_is_not_trusted() {
        for count in [0, 1, 100, u64::MAX] {
            let mut bytes = unfinished_header(false, count);
            for event in events() {
                bytes.extend(frame(&event));
            }
            let recovered = salvage(&bytes, limits()).unwrap();
            assert_eq!(recovered.metadata.seed, 42);
            assert_eq!(recovered.declared_events, count);
            assert_eq!(recovered.events, events());
            assert_eq!(recovered.input_bytes, bytes.len() as u64);
            assert!(matches!(recovered.stop, CrashRecoveryStop::EndOfAvailableData));
        }
    }

    #[test]
    fn strict_reader_stays_strict_and_salvage_does_not_modify_source() {
        let temp = NamedTempFile::new().unwrap();
        let mut bytes = unfinished_header(false, 0);
        bytes.extend(frame(&events()[0]));
        std::fs::write(temp.path(), &bytes).unwrap();
        assert!(matches!(TraceReader::open(temp.path()), Err(TraceFileError::ChecksumMismatch { .. })));
        let recovered = recover_crashed_trace_prefix(temp.path(), limits()).unwrap();
        assert_eq!(recovered.events, events()[..1]);
        assert_eq!(std::fs::read(temp.path()).unwrap(), bytes);
        assert!(TraceReader::open(temp.path()).is_err());
    }

    #[test]
    fn finalized_trace_is_not_silently_reclassified_as_crashed() {
        for events in [Vec::new(), events()] {
            let temp = NamedTempFile::new().unwrap();
            write_trace(temp.path(), &TraceMetadata::new(42), &events).unwrap();
            let error = recover_crashed_trace_prefix(temp.path(), limits()).unwrap_err();
            assert!(matches!(error, TraceFileError::Io(error) if error.kind() == io::ErrorKind::InvalidInput));
        }
    }

    #[test]
    fn every_truncated_final_frame_recovers_only_the_prior_prefix() {
        let mut prefix = unfinished_header(false, 0);
        prefix.extend(frame(&events()[0]));
        let final_frame = frame(&events()[1]);
        for cut in 0..final_frame.len() {
            let mut bytes = prefix.clone();
            bytes.extend_from_slice(&final_frame[..cut]);
            let recovered = salvage(&bytes, limits()).unwrap();
            assert_eq!(recovered.events, events()[..1], "cut {cut}");
            if cut == 0 {
                assert!(matches!(recovered.stop, CrashRecoveryStop::EndOfAvailableData));
            } else {
                assert!(matches!(recovered.stop, CrashRecoveryStop::CorruptFrame {
                    next_event: 1, error: TraceFileError::Truncated,
                }), "cut {cut}: {:?}", recovered.stop);
            }
        }
    }

    #[test]
    fn malformed_event_never_resynchronizes_to_a_later_valid_frame() {
        let mut bytes = unfinished_header(false, 0);
        bytes.extend(frame(&events()[0]));
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(0xc1); // Reserved MessagePack marker.
        bytes.extend(frame(&events()[2]));
        let recovered = salvage(&bytes, limits()).unwrap();
        assert_eq!(recovered.events, events()[..1]);
        assert!(matches!(recovered.stop, CrashRecoveryStop::CorruptFrame {
            next_event: 1, error: TraceFileError::Deserialize(_),
        }));
    }

    #[test]
    fn trailing_value_inside_one_frame_is_not_silently_ignored() {
        let mut bytes = unfinished_header(false, 0);
        let mut payload = rmp_serde::to_vec(&events()[0]).unwrap();
        payload.push(0xc0); // A second MessagePack value in the same frame.
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend(payload);
        let recovered = salvage(&bytes, limits()).unwrap();
        assert!(recovered.events.is_empty());
        assert!(matches!(recovered.stop, CrashRecoveryStop::CorruptFrame { next_event: 0, .. }));
    }

    #[test]
    fn metadata_corruption_and_every_truncated_header_fail_before_salvage() {
        let bytes = unfinished_header(false, 0);
        for cut in 0..bytes.len() {
            assert!(salvage(&bytes[..cut], limits()).is_err(), "header cut {cut}");
        }
        let mut corrupted = bytes.clone();
        corrupted[HEADER_SIZE - TRACE_CHECKSUM_LEN] ^= 1;
        assert!(matches!(salvage(&corrupted, limits()), Err(TraceFileError::ChecksumMismatch { section: "metadata" })));
        let recovered = salvage(&bytes, limits()).unwrap();
        assert!(recovered.events.is_empty());
        assert!(matches!(recovered.stop, CrashRecoveryStop::EndOfAvailableData));
    }

    #[test]
    fn event_and_decoded_byte_limits_stop_before_the_next_record() {
        let mut bytes = unfinished_header(false, u64::MAX);
        let first_length = frame(&events()[0]).len();
        for event in events() {
            bytes.extend(frame(&event));
        }
        let recovered = salvage(&bytes, CrashRecoveryLimits::new(1, usize::MAX)).unwrap();
        assert_eq!(recovered.events, events()[..1]);
        assert!(matches!(recovered.stop, CrashRecoveryStop::EventLimitReached));
        let recovered = salvage(&bytes, CrashRecoveryLimits::new(100, first_length)).unwrap();
        assert_eq!(recovered.events, events()[..1]);
        assert_eq!(recovered.decoded_bytes, first_length);
        assert!(matches!(recovered.stop, CrashRecoveryStop::DecodedByteLimitReached));
        let recovered = salvage(&bytes, CrashRecoveryLimits::new(100, first_length - 1)).unwrap();
        assert!(recovered.events.is_empty());
        assert!(matches!(recovered.stop, CrashRecoveryStop::DecodedByteLimitReached));
        let recovered = salvage(&bytes, CrashRecoveryLimits::new(0, 0)).unwrap();
        assert!(recovered.events.is_empty());
        assert!(matches!(recovered.stop, CrashRecoveryStop::EventLimitReached));
    }

    #[test]
    fn input_budget_is_distinct_from_physical_truncation() {
        let mut bytes = unfinished_header(false, 0);
        let header_length = bytes.len();
        bytes.extend(frame(&events()[0]));
        let mut cap = limits();
        cap.max_input_bytes = header_length as u64;
        let recovered = salvage(&bytes, cap).unwrap();
        assert!(recovered.events.is_empty());
        assert_eq!(recovered.input_bytes, cap.max_input_bytes);
        assert!(matches!(recovered.stop, CrashRecoveryStop::InputByteLimitReached));
        cap.max_input_bytes = (header_length + 4) as u64;
        let recovered = salvage(&bytes, cap).unwrap();
        assert!(matches!(recovered.stop, CrashRecoveryStop::InputByteLimitReached));
        cap.max_input_bytes = (header_length - 1) as u64;
        assert!(salvage(&bytes, cap).is_err());
    }

    #[test]
    fn oversized_event_length_is_rejected_before_allocating_or_reading_payload() {
        let mut bytes = unfinished_header(false, 0);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        let recovered = salvage(&bytes, CrashRecoveryLimits::new(usize::MAX, usize::MAX)).unwrap();
        assert!(recovered.events.is_empty());
        assert!(matches!(recovered.stop, CrashRecoveryStop::CorruptFrame {
            next_event: 0, error: TraceFileError::OversizedField { field: "event_len", .. },
        }));
    }

    #[cfg(not(feature = "trace-compression"))]
    #[test]
    fn compressed_crash_requires_the_compression_feature() {
        assert!(matches!(salvage(&unfinished_header(true, 0), limits()), Err(TraceFileError::CompressionNotAvailable)));
    }

    #[cfg(feature = "trace-compression")]
    fn chunk(frames: &[u8]) -> Vec<u8> {
        let payload = lz4_flex::compress_prepend_size(frames);
        let mut bytes = (payload.len() as u32).to_le_bytes().to_vec();
        bytes.extend(payload);
        bytes
    }

    #[cfg(feature = "trace-compression")]
    #[test]
    fn compressed_chunks_preserve_order_and_do_not_skip_a_truncated_chunk() {
        let mut bytes = unfinished_header(true, 0);
        let first: Vec<u8> = events()[..2].iter().flat_map(frame).collect();
        let last: Vec<u8> = events()[2..].iter().flat_map(frame).collect();
        bytes.extend(chunk(&first));
        let last_chunk = chunk(&last);
        let mut complete = bytes.clone();
        complete.extend(&last_chunk);
        let recovered = salvage(&complete, limits()).unwrap();
        assert_eq!(recovered.events, events());
        assert!(matches!(recovered.stop, CrashRecoveryStop::EndOfAvailableData));
        for cut in 1..last_chunk.len() {
            let mut partial = bytes.clone();
            partial.extend_from_slice(&last_chunk[..cut]);
            let recovered = salvage(&partial, limits()).unwrap();
            assert_eq!(recovered.events, events()[..2], "chunk cut {cut}");
            assert!(matches!(recovered.stop, CrashRecoveryStop::CorruptFrame { next_event: 2, .. }));
        }
    }

    #[cfg(feature = "trace-compression")]
    #[test]
    fn both_chunk_lengths_are_bounded_before_decompression() {
        let mut bytes = unfinished_header(true, 0);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        let recovered = salvage(&bytes, limits()).unwrap();
        assert!(matches!(recovered.stop, CrashRecoveryStop::ChunkLimitReached { .. }));
        let mut bytes = unfinished_header(true, 0);
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        let recovered = salvage(&bytes, limits()).unwrap();
        assert!(matches!(recovered.stop, CrashRecoveryStop::ChunkLimitReached { .. }));
    }

    #[cfg(feature = "trace-compression")]
    #[test]
    fn compressed_empty_and_split_frames_fail_without_resynchronization() {
        for payload in [Vec::new(), vec![1], vec![10, 0, 0, 0, 0xc0]] {
            let mut bytes = unfinished_header(true, 0);
            bytes.extend(chunk(&payload));
            bytes.extend(chunk(&frame(&events()[0])));
            let recovered = salvage(&bytes, limits()).unwrap();
            assert!(recovered.events.is_empty());
            assert!(matches!(recovered.stop, CrashRecoveryStop::CorruptFrame { next_event: 0, .. }));
        }
    }

    // The subprocess intentionally exits without running TraceWriter::drop.
    // Enough real events are written to force bytes past BufWriter first.
    #[test]
    fn crash_writer_child() {
        let Some(path) = std::env::var_os("ASUPERSYNC_CRASH_RECOVERY_CHILD_PATH") else { return };
        let config = TraceFileConfig::new();
        #[cfg(feature = "trace-compression")]
        let config = if std::env::var_os("ASUPERSYNC_CRASH_RECOVERY_COMPRESSED").is_some() {
            config
                .with_compression(super::super::file::CompressionMode::Lz4 { level: 1 })
                .with_chunk_size(256)
        } else {
            config
        };
        let mut writer = TraceWriter::create_with_config(&path, config).unwrap();
        writer.write_metadata(&TraceMetadata::new(42)).unwrap();
        for seed in 0..16_384 {
            writer.write_event(&ReplayEvent::RngSeed { seed }).unwrap();
        }
        assert!(std::fs::metadata(&path).unwrap().len() > 8192, "no persisted event witness");
        std::process::exit(0);
    }

    fn process_exit_recovery(compressed: bool) {
        let temp = NamedTempFile::new().unwrap();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "trace::recovery::tests::crash_writer_child", "--nocapture"])
            .env("ASUPERSYNC_CRASH_RECOVERY_CHILD_PATH", temp.path());
        if compressed {
            command.env("ASUPERSYNC_CRASH_RECOVERY_COMPRESSED", "1");
        } else {
            command.env_remove("ASUPERSYNC_CRASH_RECOVERY_COMPRESSED");
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "child failed: {output:?}");
        let before = std::fs::read(temp.path()).unwrap();
        let metadata_length = u32::from_le_bytes(before[16..20].try_into().unwrap()) as usize;
        let count_offset = HEADER_SIZE + metadata_length;
        assert_eq!(&before[count_offset..count_offset + 8 + TRACE_CHECKSUM_LEN], &[0; 8 + TRACE_CHECKSUM_LEN]);
        assert!(TraceReader::open(temp.path()).is_err());
        let recovered = recover_crashed_trace_prefix(temp.path(), CrashRecoveryLimits::new(20_000, 4 * 1024 * 1024)).unwrap();
        assert!(!recovered.events.is_empty());
        assert!(recovered.events.len() <= 16_384);
        for (index, event) in recovered.events.iter().enumerate() {
            assert_eq!(*event, ReplayEvent::RngSeed { seed: index as u64 });
        }
        assert!(matches!(recovered.stop, CrashRecoveryStop::EndOfAvailableData | CrashRecoveryStop::CorruptFrame { error: TraceFileError::Truncated, .. }));
        assert_eq!(std::fs::read(temp.path()).unwrap(), before);
    }

    #[test]
    fn recovers_real_process_exit_without_destructors() {
        process_exit_recovery(false);
    }

    #[cfg(feature = "trace-compression")]
    #[test]
    fn recovers_compressed_real_process_exit_without_destructors() {
        process_exit_recovery(true);
    }
