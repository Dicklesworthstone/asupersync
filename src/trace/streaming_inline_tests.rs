    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::trace::file::{HEADER_SIZE, TraceWriter, write_trace};
    use crate::trace::replay::CompactTaskId;
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};
    use tempfile::NamedTempFile;

    fn sample_events(count: u64) -> Vec<ReplayEvent> {
        (0..count)
            .map(|i| ReplayEvent::TaskScheduled {
                task: CompactTaskId(i),
                at_tick: i,
            })
            .collect()
    }

    #[derive(Debug, Default)]
    struct CapturingEvidenceSink {
        chunks: Vec<(u64, u64, Vec<u8>)>,
        backpressure_after_chunks: Option<usize>,
    }

    impl CapturingEvidenceSink {
        fn with_backpressure_after_chunks(limit: usize) -> Self {
            Self {
                chunks: Vec::new(),
                backpressure_after_chunks: Some(limit),
            }
        }

        fn decoded_ticks(&self) -> Vec<u64> {
            let mut ticks = Vec::new();
            for (_, _, payload) in &self.chunks {
                let mut cursor = payload.as_slice();
                while !cursor.is_empty() {
                    let (len_bytes, rest) = cursor.split_at(4);
                    let len = u32::from_le_bytes(len_bytes.try_into().unwrap()) as usize;
                    let (event_bytes, remaining) = rest.split_at(len);
                    let event: ReplayEvent = rmp_serde::from_slice(event_bytes).unwrap();
                    if let ReplayEvent::TaskScheduled { at_tick, .. } = event {
                        ticks.push(at_tick);
                    }
                    cursor = remaining;
                }
            }
            ticks
        }
    }

    impl TraceEvidenceSink for CapturingEvidenceSink {
        fn push_trace_evidence(
            &mut self,
            chunk: TraceEvidenceChunk<'_>,
        ) -> StreamingReplayResult<EvidenceSinkDecision> {
            if let Some(limit) = self.backpressure_after_chunks
                && self.chunks.len() >= limit
            {
                return Ok(EvidenceSinkDecision::Backpressured);
            }
            self.chunks
                .push((chunk.first_sequence, chunk.records, chunk.payload.to_vec()));
            Ok(EvidenceSinkDecision::Accepted)
        }
    }

    #[derive(Debug, Default)]
    struct CountingEvidenceSink {
        chunks: u64,
        max_chunk_len: usize,
    }

    impl TraceEvidenceSink for CountingEvidenceSink {
        fn push_trace_evidence(
            &mut self,
            chunk: TraceEvidenceChunk<'_>,
        ) -> StreamingReplayResult<EvidenceSinkDecision> {
            assert!(!chunk.is_empty());
            self.chunks = self.chunks.saturating_add(1);
            self.max_chunk_len = self.max_chunk_len.max(chunk.len());
            Ok(EvidenceSinkDecision::Accepted)
        }
    }

    #[derive(Debug, Default)]
    struct ClosingEvidenceSink {
        calls: u64,
    }

    impl TraceEvidenceSink for ClosingEvidenceSink {
        fn push_trace_evidence(
            &mut self,
            chunk: TraceEvidenceChunk<'_>,
        ) -> StreamingReplayResult<EvidenceSinkDecision> {
            assert!(!chunk.is_empty());
            self.calls = self.calls.saturating_add(1);
            Ok(EvidenceSinkDecision::Closed)
        }
    }

    #[test]
    fn evidence_stream_chunks_respect_capacity_and_ordering() {
        let events = sample_events(8);
        let config = TraceEvidenceStreamConfig::new().with_max_chunk_bytes(48);
        let mut streamer = TraceEvidenceStreamer::new(config);
        let mut sink = CapturingEvidenceSink::default();

        let stats = streamer.stream_events(events.iter(), &mut sink).unwrap();

        assert_eq!(stats.records_seen, 8);
        assert_eq!(stats.records_emitted, 8);
        assert_eq!(stats.records_dropped, 0);
        assert_eq!(stats.overflow_events, 0);
        assert_eq!(stats.backpressure_events, 0);
        assert!(stats.bytes_emitted > 0);
        assert!(stats.max_buffered_bytes <= config.max_chunk_bytes * 2);
        assert!(!sink.chunks.is_empty());
        for (_, records, payload) in &sink.chunks {
            assert!(*records >= 1);
            assert!(payload.len() <= config.max_chunk_bytes);
        }
        assert_eq!(sink.decoded_ticks(), (0..8).collect::<Vec<_>>());
        assert_eq!(sink.chunks.first().unwrap().0, 0);
    }

    #[test]
    fn evidence_stream_backpressure_drop_newest_records_decision() {
        let events = sample_events(8);
        let config = TraceEvidenceStreamConfig::new()
            .with_max_chunk_bytes(48)
            .with_overflow_policy(EvidenceOverflowPolicy::DropNewest);
        let mut streamer = TraceEvidenceStreamer::new(config);
        let mut sink = CapturingEvidenceSink::with_backpressure_after_chunks(1);

        let stats = streamer.stream_events(events.iter(), &mut sink).unwrap();

        assert_eq!(stats.records_seen, 8);
        assert!(stats.records_emitted > 0);
        assert!(stats.records_emitted < stats.records_seen);
        assert_eq!(
            stats.records_seen,
            stats.records_emitted + stats.records_dropped
        );
        assert!(stats.backpressure_events > 0);
        assert_eq!(sink.chunks.len(), 1);
        let accepted_ticks = sink.decoded_ticks();
        assert_eq!(accepted_ticks.first(), Some(&0));
        assert_eq!(accepted_ticks.len() as u64, stats.records_emitted);
        assert!(accepted_ticks.len() < events.len());
    }

    #[test]
    fn evidence_stream_closed_sink_drops_pending_and_halts() {
        let events = sample_events(8);
        let config = TraceEvidenceStreamConfig::new().with_max_chunk_bytes(256);
        let mut streamer = TraceEvidenceStreamer::new(config);
        let mut closing_sink = ClosingEvidenceSink::default();

        let stats = streamer
            .stream_events(events.iter(), &mut closing_sink)
            .unwrap();

        assert_eq!(closing_sink.calls, 1);
        assert_eq!(stats.records_seen, 8);
        assert_eq!(stats.records_emitted, 0);
        assert_eq!(stats.records_dropped, 8);
        assert_eq!(stats.records_seen, stats.records_dropped);

        let mut accepting_sink = CapturingEvidenceSink::default();
        let after_halt = streamer.finish(&mut accepting_sink).unwrap();
        assert_eq!(after_halt, stats);
        assert!(accepting_sink.chunks.is_empty());
    }

    #[test]
    fn evidence_stream_stop_backpressure_drops_pending_and_current_record() {
        let events = sample_events(8);
        let config = TraceEvidenceStreamConfig::new()
            .with_max_chunk_bytes(48)
            .with_overflow_policy(EvidenceOverflowPolicy::Stop);
        let mut streamer = TraceEvidenceStreamer::new(config);
        let mut sink = CapturingEvidenceSink::with_backpressure_after_chunks(1);

        let stats = streamer.stream_events(events.iter(), &mut sink).unwrap();

        assert_eq!(sink.chunks.len(), 1);
        assert!(stats.records_seen > stats.records_emitted);
        assert_eq!(
            stats.records_seen,
            stats.records_emitted + stats.records_dropped
        );
        assert_eq!(stats.backpressure_events, 1);

        let emitted_before_retry = stats.records_emitted;
        let mut retry_sink = CapturingEvidenceSink::default();
        let retry_stats = streamer
            .stream_events(events.iter(), &mut retry_sink)
            .unwrap();
        assert_eq!(retry_stats, stats);
        assert_eq!(retry_stats.records_emitted, emitted_before_retry);
        assert!(retry_sink.chunks.is_empty());
    }

    #[test]
    fn evidence_stream_oversized_record_errors_when_policy_requires() {
        let events = sample_events(1);
        let config = TraceEvidenceStreamConfig::new()
            .with_max_chunk_bytes(4)
            .with_overflow_policy(EvidenceOverflowPolicy::Error);
        let mut streamer = TraceEvidenceStreamer::new(config);
        let mut sink = CapturingEvidenceSink::default();

        let err = streamer
            .stream_events(events.iter(), &mut sink)
            .unwrap_err();
        assert!(matches!(
            err,
            StreamingReplayError::EvidenceRecordTooLarge { .. }
        ));
    }

    #[test]
    fn evidence_stream_large_trace_keeps_bounded_buffers() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();
        let metadata = TraceMetadata::new(42);
        let event_count = 1_000u64;
        {
            let mut writer = TraceWriter::create(path).unwrap();
            writer.write_metadata(&metadata).unwrap();
            for event in sample_events(event_count) {
                writer.write_event(&event).unwrap();
            }
            writer.finish().unwrap();
        }

        let config = TraceEvidenceStreamConfig::new().with_max_chunk_bytes(256);
        let mut streamer = TraceEvidenceStreamer::new(config);
        let mut replayer = StreamingReplayer::open(path).unwrap();
        let mut sink = CountingEvidenceSink::default();

        let stats = streamer.stream_replayer(&mut replayer, &mut sink).unwrap();

        assert_eq!(stats.records_seen, event_count);
        assert_eq!(stats.records_emitted, event_count);
        assert_eq!(stats.records_dropped, 0);
        assert_eq!(stats.overflow_events, 0);
        assert!(sink.chunks > 1);
        assert!(sink.max_chunk_len <= config.max_chunk_bytes);
        assert!(stats.max_buffered_bytes <= config.max_chunk_bytes * 2);
        assert!(replayer.is_complete());
    }

    #[test]
    fn basic_streaming_replay() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        // Write a trace
        let metadata = TraceMetadata::new(42);
        let events = sample_events(100);
        write_trace(path, &metadata, &events).unwrap();

        // Stream replay
        let mut replayer = StreamingReplayer::open(path).unwrap();

        assert_eq!(replayer.total_events(), 100);
        assert_eq!(replayer.events_consumed(), 0);
        assert!(!replayer.is_complete());

        // Read all events
        let mut count = 0u64;
        while let Some(event) = replayer.next_event().unwrap() {
            if let ReplayEvent::TaskScheduled { task, at_tick } = event {
                assert_eq!(task.0, count);
                assert_eq!(at_tick, count);
            } else {
                panic!("unexpected event type");
            }
            count += 1;
        }

        assert_eq!(count, 100);
        assert!(replayer.is_complete());
    }

    #[test]
    fn progress_tracking() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(100);
        write_trace(path, &metadata, &events).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();

        // Check initial progress
        let progress = replayer.progress();
        assert_eq!(progress.events_processed, 0);
        assert_eq!(progress.total_events, 100);
        assert!((progress.percent() - 0.0).abs() < 0.01);

        // Read 50 events
        for _ in 0..50 {
            replayer.next_event().unwrap();
        }

        // Check midpoint progress
        let progress = replayer.progress();
        assert_eq!(progress.events_processed, 50);
        assert!((progress.percent() - 50.0).abs() < 0.01);
        assert_eq!(progress.remaining(), 50);

        // Read rest
        while replayer.next_event().unwrap().is_some() {}

        // Check final progress
        let progress = replayer.progress();
        assert!(progress.is_complete());
        assert!((progress.percent() - 100.0).abs() < 0.01);
    }

    #[test]
    fn peek_without_consuming() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(10);
        write_trace(path, &metadata, &events).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();

        // Peek multiple times - should return same event
        let peeked1 = replayer.peek().unwrap().cloned();
        let peeked2 = replayer.peek().unwrap().cloned();
        assert_eq!(peeked1, peeked2);
        assert_eq!(replayer.events_consumed(), 0);

        // Now consume
        let consumed = replayer.next_event().unwrap();
        assert_eq!(consumed, peeked1);
        assert_eq!(replayer.events_consumed(), 1);

        // Next peek should be different
        let peeked3 = replayer.peek().unwrap().cloned();
        assert_ne!(peeked3, peeked1);
    }

    #[test]
    fn checkpoint_and_resume() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(100);
        write_trace(path, &metadata, &events).unwrap();

        // Replay partway and checkpoint
        let mut replayer = StreamingReplayer::open(path).unwrap();
        for _ in 0..50 {
            replayer.next_event().unwrap();
        }

        let checkpoint = replayer.checkpoint();
        assert_eq!(checkpoint.events_processed, 50);
        assert_eq!(checkpoint.total_events, 100);

        // Serialize and deserialize checkpoint
        let checkpoint_bytes = checkpoint.to_bytes().unwrap();
        let restored_checkpoint = ReplayCheckpoint::from_bytes(&checkpoint_bytes).unwrap();

        // Resume from checkpoint
        let mut resumed = StreamingReplayer::resume(path, restored_checkpoint).unwrap();
        assert_eq!(resumed.events_consumed(), 50);

        // Continue reading
        let mut count = 50u64;
        while let Some(event) = resumed.next_event().unwrap() {
            if let ReplayEvent::TaskScheduled { task, .. } = event {
                assert_eq!(task.0, count);
            }
            count += 1;
        }

        assert_eq!(count, 100);
    }

    #[test]
    fn checkpoint_deserialization_accepts_initial_deterministic_checkpoint() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(3);
        write_trace(path, &metadata, &events).unwrap();

        let replayer = StreamingReplayer::open(path).unwrap();
        let checkpoint = replayer.checkpoint();

        assert_eq!(checkpoint.events_processed, 0);
        assert_eq!(checkpoint.total_events, 3);
        assert_eq!(
            checkpoint.created_at, 0,
            "recorded_at=0 is the deterministic no-wall-clock trace stamp"
        );

        let checkpoint_bytes = checkpoint.to_bytes().unwrap();
        let restored_checkpoint = ReplayCheckpoint::from_bytes(&checkpoint_bytes).unwrap();
        assert_eq!(restored_checkpoint.events_processed, 0);
        assert_eq!(restored_checkpoint.created_at, 0);

        let resumed = StreamingReplayer::resume(path, restored_checkpoint).unwrap();
        assert_eq!(resumed.events_consumed(), 0);
    }

    #[test]
    fn checkpoint_validation() {
        let temp1 = NamedTempFile::new().unwrap();
        let temp2 = NamedTempFile::new().unwrap();

        // Write two different traces
        let metadata1 = TraceMetadata::new(42);
        let metadata2 = TraceMetadata::new(99);
        write_trace(temp1.path(), &metadata1, &sample_events(100)).unwrap();
        write_trace(temp2.path(), &metadata2, &sample_events(100)).unwrap();

        // Checkpoint from first trace
        let mut replayer = StreamingReplayer::open(temp1.path()).unwrap();
        for _ in 0..50 {
            replayer.next_event().unwrap();
        }
        let checkpoint = replayer.checkpoint();

        // Try to resume with second trace - should fail
        let result = StreamingReplayer::resume(temp2.path(), checkpoint);
        assert!(matches!(
            result,
            Err(StreamingReplayError::CheckpointMismatch(_))
        ));
    }

    #[test]
    fn checkpoint_validation_rejects_same_seed_metadata_drift() {
        let temp1 = NamedTempFile::new().unwrap();
        let temp2 = NamedTempFile::new().unwrap();

        let metadata1 = TraceMetadata {
            version: super::super::replay::REPLAY_SCHEMA_VERSION,
            seed: 42,
            recorded_at: 100,
            config_hash: 0xCAFE,
            description: Some("trace-a".into()),
        };
        let metadata2 = TraceMetadata {
            version: super::super::replay::REPLAY_SCHEMA_VERSION,
            seed: 42,
            recorded_at: 200,
            config_hash: 0xCAFE,
            description: Some("trace-b".into()),
        };
        write_trace(temp1.path(), &metadata1, &sample_events(4)).unwrap();
        write_trace(temp2.path(), &metadata2, &sample_events(4)).unwrap();

        let mut replayer = StreamingReplayer::open(temp1.path()).unwrap();
        for _ in 0..2 {
            replayer.next_event().unwrap();
        }
        let checkpoint = replayer.checkpoint();

        let result = StreamingReplayer::resume(temp2.path(), checkpoint);
        assert!(matches!(
            result,
            Err(StreamingReplayError::CheckpointMismatch(_))
        ));
    }

    #[test]
    fn checkpoint_validation_rejects_event_count_drift() {
        let temp1 = NamedTempFile::new().unwrap();
        let temp2 = NamedTempFile::new().unwrap();

        let metadata = TraceMetadata {
            version: super::super::replay::REPLAY_SCHEMA_VERSION,
            seed: 7,
            recorded_at: 500,
            config_hash: 0xBEEF,
            description: Some("same-metadata".into()),
        };
        write_trace(temp1.path(), &metadata, &sample_events(4)).unwrap();
        write_trace(temp2.path(), &metadata, &sample_events(6)).unwrap();

        let mut replayer = StreamingReplayer::open(temp1.path()).unwrap();
        for _ in 0..2 {
            replayer.next_event().unwrap();
        }
        let checkpoint = replayer.checkpoint();

        let result = StreamingReplayer::resume(temp2.path(), checkpoint);
        assert!(matches!(
            result,
            Err(StreamingReplayError::CheckpointMismatch(_))
        ));
    }

    #[test]
    fn checkpoint_bytes_are_stable_for_same_position() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata {
            version: super::super::replay::REPLAY_SCHEMA_VERSION,
            seed: 42,
            recorded_at: 1_000,
            config_hash: 0xCAFE,
            description: Some("stable checkpoint".into()),
        };
        write_trace(path, &metadata, &sample_events(5)).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();
        for _ in 0..3 {
            replayer.next_event().unwrap();
        }

        let checkpoint_a = replayer.checkpoint();
        let checkpoint_b = replayer.checkpoint();

        assert_eq!(checkpoint_a.events_processed, 3);
        assert_eq!(checkpoint_a.total_events, 5);
        assert_eq!(checkpoint_a.created_at, 1_003);
        assert_eq!(checkpoint_a.created_at, checkpoint_b.created_at);
        assert_eq!(
            checkpoint_a.to_bytes().unwrap(),
            checkpoint_b.to_bytes().unwrap()
        );
    }

    #[test]
    fn checkpoint_created_at_advances_with_position() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata {
            version: super::super::replay::REPLAY_SCHEMA_VERSION,
            seed: 7,
            recorded_at: 500,
            config_hash: 0xBEEF,
            description: None,
        };
        write_trace(path, &metadata, &sample_events(4)).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();

        let first = replayer.checkpoint();
        assert_eq!(first.created_at, 500);

        replayer.next_event().unwrap();
        let second = replayer.checkpoint();
        assert_eq!(second.created_at, 501);
        assert_eq!(second.created_at, first.created_at + 1);

        replayer.next_event().unwrap();
        let third = replayer.checkpoint();
        assert_eq!(third.created_at, 502);
    }

    #[test]
    fn run_with_callback() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(50);
        write_trace(path, &metadata, &events).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();

        let mut event_ids = Vec::new();
        let count = replayer
            .run_with(|event, progress| {
                if let ReplayEvent::TaskScheduled { task, .. } = event {
                    event_ids.push(task.0);
                }
                // Check progress is accurate
                assert!(!progress.is_complete() || progress.events_processed == 50);
                Ok::<_, StreamingReplayError>(())
            })
            .unwrap();

        assert_eq!(count, 50);
        assert_eq!(event_ids.len(), 50);
        for (i, id) in event_ids.iter().enumerate() {
            assert_eq!(*id, i as u64);
        }
    }

    #[test]
    fn large_trace_streaming() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let event_count = 10_000u64;

        // Write large trace using streaming writer
        {
            let mut writer = TraceWriter::create(path).unwrap();
            writer.write_metadata(&metadata).unwrap();
            for i in 0..event_count {
                writer
                    .write_event(&ReplayEvent::TaskScheduled {
                        task: CompactTaskId(i),
                        at_tick: i,
                    })
                    .unwrap();
            }
            writer.finish().unwrap();
        }

        // Stream replay - should use constant memory
        let mut replayer = StreamingReplayer::open(path).unwrap();
        assert_eq!(replayer.total_events(), event_count);

        let mut count = 0u64;
        while replayer.next_event().unwrap().is_some() {
            count += 1;
        }

        assert_eq!(count, event_count);
    }

    #[test]
    fn step_mode_streaming() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(5);
        write_trace(path, &metadata, &events).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();
        replayer.set_mode(ReplayMode::Step);

        // Each step should set breakpoint
        for _ in 0..5 {
            replayer.step().unwrap();
            assert!(replayer.at_breakpoint());
        }

        // Final step returns None
        let event = replayer.step().unwrap();
        assert!(event.is_none());
    }

    #[test]
    fn breakpoint_at_tick() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events: Vec<_> = (0..10)
            .map(|i| ReplayEvent::TaskScheduled {
                task: CompactTaskId(i),
                at_tick: i * 10, // Ticks: 0, 10, 20, 30, ...
            })
            .collect();
        write_trace(path, &metadata, &events).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();
        replayer.set_mode(ReplayMode::RunTo(Breakpoint::Tick(50)));

        let count = replayer.run().unwrap();
        // Should stop at tick >= 50 (which is at_tick=50, event index 5)
        assert!(replayer.at_breakpoint());
        assert_eq!(count, 6); // Events 0-5 (ticks 0, 10, 20, 30, 40, 50)
    }

    #[test]
    fn empty_trace() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        write_trace(path, &metadata, &[]).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();
        assert_eq!(replayer.total_events(), 0);
        assert!(replayer.progress().is_complete());

        let event = replayer.next_event().unwrap();
        assert!(event.is_none());
    }

    #[test]
    fn verify_past_end_of_trace_reports_trace_exhausted() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];
        write_trace(path, &metadata, &events).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();
        assert!(replayer.next_event().unwrap().is_some());
        assert!(replayer.is_complete());

        let actual = ReplayEvent::RngSeed { seed: 99 };
        let err = replayer.verify(&actual).unwrap_err();
        match err {
            StreamingReplayError::Divergence(divergence) => {
                assert!(divergence.expected.is_none());
                assert_eq!(divergence.index, 1);
                assert!(divergence.context.contains("Trace ended"));
                assert!(format!("{divergence}").contains("<trace_exhausted>"));
            }
            other => panic!("expected divergence error, got {other:?}"),
        }
    }

    #[test]
    fn verify_mismatch_preserves_expected_event() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = vec![ReplayEvent::TaskScheduled {
            task: CompactTaskId(1),
            at_tick: 10,
        }];
        write_trace(path, &metadata, &events).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();
        let actual = ReplayEvent::TaskScheduled {
            task: CompactTaskId(2),
            at_tick: 10,
        };
        let err = replayer.verify(&actual).unwrap_err();
        match err {
            StreamingReplayError::Divergence(divergence) => {
                assert_eq!(
                    divergence.expected,
                    Some(ReplayEvent::TaskScheduled {
                        task: CompactTaskId(1),
                        at_tick: 10,
                    })
                );
                assert_eq!(divergence.actual, actual);
                assert_eq!(divergence.index, 0);
            }
            other => panic!("expected divergence error, got {other:?}"),
        }
    }

    #[test]
    fn progress_display() {
        let progress = ReplayProgress::new(250, 1000);
        let display = format!("{progress}");
        assert!(display.contains("250/1000"));
        assert!(display.contains("25.0%"));
    }

    #[test]
    fn run_with_respects_runto_breakpoint() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events: Vec<_> = (0..10)
            .map(|i| ReplayEvent::TaskScheduled {
                task: CompactTaskId(i),
                at_tick: i * 10,
            })
            .collect();
        write_trace(path, &metadata, &events).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();
        replayer.set_mode(ReplayMode::RunTo(Breakpoint::Tick(50)));

        let count = replayer
            .run_with(|_, _| Ok::<_, StreamingReplayError>(()))
            .unwrap();
        assert_eq!(count, 6);
        assert!(replayer.at_breakpoint());
    }

    #[test]
    fn run_with_respects_step_mode() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(7);
        let events = sample_events(5);
        write_trace(path, &metadata, &events).unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();
        replayer.set_mode(ReplayMode::Step);

        let count = replayer
            .run_with(|_, _| Ok::<_, StreamingReplayError>(()))
            .unwrap();
        assert_eq!(count, 1);
        assert!(replayer.at_breakpoint());
    }

    #[test]
    fn event_source_adapter_captures_stream_error() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];
        write_trace(path, &metadata, &events).unwrap();

        // Corrupt the first event payload byte while preserving file structure.
        let meta_len = rmp_serde::to_vec(&metadata).unwrap().len() as u64;
        let first_event_payload = HEADER_SIZE as u64 + meta_len + 8 + 4;
        let mut file = OpenOptions::new().write(true).open(path).unwrap();
        file.seek(SeekFrom::Start(first_event_payload)).unwrap();
        file.write_all(&[0xC1]).unwrap(); // MessagePack never-used marker => decode error.
        file.flush().unwrap();

        let mut replayer = StreamingReplayer::open(path).unwrap();
        let event = <StreamingReplayer as EventSource>::next_event(&mut replayer);
        assert!(event.is_none());

        let err = replayer
            .take_event_source_error()
            .expect("expected captured event-source error");
        assert!(matches!(err, StreamingReplayError::File(_)));
        assert!(replayer.last_event_source_error().is_none());
    }

    #[test]
    fn checkpoint_deserialization_validates_input_size() {
        // Test oversized input rejection
        let large_input = vec![0u8; 2048]; // Exceeds MAX_CHECKPOINT_SIZE
        let result = ReplayCheckpoint::from_bytes(&large_input);
        assert!(matches!(
            result,
            Err(StreamingReplayError::InvalidCheckpoint(_))
        ));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("checkpoint too large")
        );

        // Test undersized input rejection
        let small_input = vec![0u8; 8]; // Below MIN_CHECKPOINT_SIZE
        let result = ReplayCheckpoint::from_bytes(&small_input);
        assert!(matches!(
            result,
            Err(StreamingReplayError::InvalidCheckpoint(_))
        ));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("checkpoint too small")
        );

        // Test malformed MessagePack rejection
        let malformed_input = vec![0xFF; 64]; // Invalid MessagePack
        let result = ReplayCheckpoint::from_bytes(&malformed_input);
        assert!(matches!(
            result,
            Err(StreamingReplayError::InvalidCheckpoint(_))
        ));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("deserialization failed")
        );
    }

    #[test]
    fn checkpoint_deserialization_validates_field_bounds() {
        // Create a checkpoint with invalid bounds (events_processed > total_events)
        let bad_checkpoint = ReplayCheckpoint {
            events_processed: 100,
            total_events: 50, // Invalid: less than events_processed
            seed: 12345,
            metadata_hash: 0xABCD,
            created_at: 1000,
        };

        // Serialize it (bypassing validation)
        let bytes = rmp_serde::to_vec(&bad_checkpoint).unwrap();

        // from_bytes should reject it due to bounds validation
        let result = ReplayCheckpoint::from_bytes(&bytes);
        assert!(matches!(
            result,
            Err(StreamingReplayError::InvalidCheckpoint(_))
        ));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("exceeds total_events")
        );

        // Test excessive event count
        let excessive_checkpoint = ReplayCheckpoint {
            events_processed: 0,
            total_events: u64::MAX, // Too large
            seed: 12345,
            metadata_hash: 0xABCD,
            created_at: 1000,
        };
        let bytes = rmp_serde::to_vec(&excessive_checkpoint).unwrap();
        let result = ReplayCheckpoint::from_bytes(&bytes);
        assert!(matches!(
            result,
            Err(StreamingReplayError::InvalidCheckpoint(_))
        ));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("total_events too large")
        );

        let deterministic_epoch_checkpoint = ReplayCheckpoint {
            events_processed: 0,
            total_events: 10,
            seed: 12345,
            metadata_hash: 0xABCD,
            created_at: 0,
        };
        let bytes = rmp_serde::to_vec(&deterministic_epoch_checkpoint).unwrap();
        let restored = ReplayCheckpoint::from_bytes(&bytes).unwrap();
        assert_eq!(restored.created_at, 0);
    }
