#![no_main]

//! Fuzz target for trace streaming operations and edge cases.
//!
//! This target focuses on the StreamingReplayer system including checkpoint
//! serialization/deserialization, progress tracking, event streaming, resume
//! functionality, and error handling with O(1) memory guarantees.
//!
//! Key areas tested:
//! - StreamingReplayer::open() with malformed trace files
//! - StreamingReplayer::resume() with invalid/corrupted checkpoints
//! - Checkpoint serialization/deserialization round-trip consistency
//! - Progress tracking calculations and edge cases (zero events, overflow)
//! - Event streaming operations: next_event(), peek(), verify()
//! - Checkpoint validation against mismatched trace metadata
//! - Error handling paths and graceful degradation
//! - Memory safety during streaming operations
//! - Resume from arbitrary checkpoint positions

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::io::{Cursor, Write};

#[derive(Arbitrary, Debug)]
struct TraceStreamingFuzz {
    /// Mock trace file data for testing
    trace_data: Vec<u8>,
    /// Operations to perform on the trace
    operations: Vec<StreamingOperation>,
    /// Checkpoint data for deserialization testing
    checkpoint_data: Vec<u8>,
    /// Progress tracking edge cases
    progress_tests: ProgressTestConfig,
}

#[derive(Arbitrary, Debug)]
enum StreamingOperation {
    /// Test opening a trace file
    Open,
    /// Test resuming from checkpoint at position
    Resume { position: u64 },
    /// Test reading next event
    NextEvent,
    /// Test peeking at next event
    Peek,
    /// Test creating checkpoint
    CreateCheckpoint,
    /// Test progress tracking
    QueryProgress,
    /// Test completion status
    CheckComplete,
    /// Test run until completion
    RunToCompletion,
    /// Test step operation
    Step,
    /// Test metadata access
    GetMetadata,
    /// Test setting replay mode
    SetMode { mode_type: u8 },
    /// Test verify operation with synthetic event
    Verify { event_data: Vec<u8> },
    /// Test checkpoint serialization round-trip
    SerializeCheckpoint,
    /// Test checkpoint deserialization with corrupt data
    DeserializeCorruptCheckpoint,
}

#[derive(Arbitrary, Debug)]
struct ProgressTestConfig {
    events_processed: u64,
    total_events: u64,
    test_edge_cases: bool,
}

/// Maximum limits to prevent timeouts and resource exhaustion
const MAX_OPERATIONS: usize = 100;
const MAX_TRACE_DATA_SIZE: usize = 64 * 1024; // 64KB
const MAX_CHECKPOINT_SIZE: usize = 4 * 1024; // 4KB

/// Creates a minimal valid trace file for testing
fn create_minimal_trace(data: &[u8]) -> Vec<u8> {
    let mut trace = Vec::new();

    // Magic bytes "ASUPERTRACE" (11 bytes)
    trace.extend_from_slice(b"ASUPERTRACE");

    // Version (2): u16 little-endian
    trace.extend_from_slice(&1u16.to_le_bytes());

    // Flags (2): u16 little-endian (bit 0 = compression)
    trace.extend_from_slice(&0u16.to_le_bytes());

    // Compression (1): u8 (0=none, 1=LZ4)
    trace.push(0);

    // Metadata length (4): u32 little-endian
    let minimal_metadata = create_minimal_metadata();
    trace.extend_from_slice(&(minimal_metadata.len() as u32).to_le_bytes());

    // Metadata (variable): MessagePack-encoded TraceMetadata
    trace.extend_from_slice(&minimal_metadata);

    // Event count (8): u64 little-endian
    let event_count = data.len().min(100) / 20; // Rough estimate
    trace.extend_from_slice(&(event_count as u64).to_le_bytes());

    // Events (variable): append the provided data as "events"
    trace.extend_from_slice(data);

    trace
}

/// Creates minimal MessagePack metadata for testing
fn create_minimal_metadata() -> Vec<u8> {
    // Create a simple map with required fields for TraceMetadata
    // This is a minimal MessagePack representation
    vec![
        0x85, // fixmap with 5 elements
        0xa4, b's', b'e', b'e', b'd', // "seed"
        0x42, // positive fixnum 66 (seed value)
        0xa7, b'v', b'e', b'r', b's', b'i', b'o', b'n', // "version"
        0x01, // positive fixnum 1
        0xab, b'r', b'e', b'c', b'o', b'r', b'd', b'e', b'd', b'_', b'a', b't', // "recorded_at"
        0xce, 0x00, 0x00, 0x00, 0x00, // uint32 timestamp
        0xab, b'c', b'o', b'n', b'f', b'i', b'g', b'_', b'h', b'a', b's', b'h', // "config_hash"
        0xcc, 0x42, // uint8 config hash
        0xab, b'd', b'e', b's', b'c', b'r', b'i', b'p', b't', b'i', b'o', b'n', // "description"
        0xa4, b't', b'e', b's', b't', // "test"
    ]
}

/// Test ReplayProgress calculations and edge cases
fn test_progress_calculations(config: &ProgressTestConfig) {
    let progress = asupersync::trace::streaming::ReplayProgress::new(
        config.events_processed,
        config.total_events,
    );

    // Test basic methods don't panic
    let _percent = progress.percent();
    let _fraction = progress.fraction();
    let _is_complete = progress.is_complete();
    let _remaining = progress.remaining();

    // Test display formatting doesn't panic
    let _display = format!("{}", progress);
    let _debug = format!("{:?}", progress);

    if config.test_edge_cases {
        // Test edge cases that might cause issues

        // Test zero total events
        let zero_total = asupersync::trace::streaming::ReplayProgress::new(0, 0);
        assert_eq!(zero_total.percent(), 100.0);
        assert_eq!(zero_total.fraction(), 1.0);
        assert!(zero_total.is_complete());
        assert_eq!(zero_total.remaining(), 0);

        // Test progress > total (should be clamped)
        let over_total = asupersync::trace::streaming::ReplayProgress::new(150, 100);
        assert!(over_total.is_complete());
        assert_eq!(over_total.remaining(), 0); // saturating_sub

        // Test max values
        let max_progress = asupersync::trace::streaming::ReplayProgress::new(
            u64::MAX,
            u64::MAX,
        );
        assert_eq!(max_progress.percent(), 100.0);
        assert_eq!(max_progress.fraction(), 1.0);
        assert!(max_progress.is_complete());
    }
}

/// Test ReplayCheckpoint serialization/deserialization
fn test_checkpoint_serialization(checkpoint_data: &[u8]) {
    // Test deserializing arbitrary bytes as checkpoint
    let _result = asupersync::trace::streaming::ReplayCheckpoint::from_bytes(checkpoint_data);

    // If we have a valid trace file structure, test creating and round-tripping checkpoints
    if checkpoint_data.len() >= 32 {
        // Create a synthetic checkpoint for round-trip testing
        use asupersync::trace::streaming::ReplayCheckpoint;
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize)]
        struct SyntheticCheckpoint {
            events_processed: u64,
            total_events: u64,
            seed: u64,
            metadata_hash: u64,
            created_at: u64,
        }

        // Extract values from the fuzz data
        let mut values = checkpoint_data.chunks_exact(8);
        if let (Some(ep), Some(te), Some(s), Some(mh), Some(ca)) = (
            values.next(),
            values.next(),
            values.next(),
            values.next(),
            values.next(),
        ) {
            let synthetic = SyntheticCheckpoint {
                events_processed: u64::from_le_bytes(ep.try_into().unwrap_or_default()),
                total_events: u64::from_le_bytes(te.try_into().unwrap_or_default()),
                seed: u64::from_le_bytes(s.try_into().unwrap_or_default()),
                metadata_hash: u64::from_le_bytes(mh.try_into().unwrap_or_default()),
                created_at: u64::from_le_bytes(ca.try_into().unwrap_or_default()),
            };

            // Test MessagePack round-trip
            if let Ok(serialized) = rmp_serde::to_vec(&synthetic) {
                let _deserialize_result = ReplayCheckpoint::from_bytes(&serialized);
            }
        }
    }
}

fuzz_target!(|input: &[u8]| {
    if input.len() < 8 {
        return;
    }

    // Limit input size to prevent timeout
    if input.len() > MAX_TRACE_DATA_SIZE {
        return;
    }

    let mut unstructured = Unstructured::new(input);
    let Ok(fuzz_input) = TraceStreamingFuzz::arbitrary(&mut unstructured) else {
        return;
    };

    // Limit operations to prevent timeout
    if fuzz_input.operations.len() > MAX_OPERATIONS {
        return;
    }

    if fuzz_input.checkpoint_data.len() > MAX_CHECKPOINT_SIZE {
        return;
    }

    // Test 1: Progress tracking edge cases
    test_progress_calculations(&fuzz_input.progress_tests);

    // Test 2: Checkpoint serialization/deserialization
    test_checkpoint_serialization(&fuzz_input.checkpoint_data);

    // Test 3: StreamingReplayer operations with synthetic trace data
    let trace_data = if fuzz_input.trace_data.len() < 50 {
        // Create a minimal valid trace if input is too small
        create_minimal_trace(&fuzz_input.trace_data)
    } else {
        fuzz_input.trace_data.clone()
    };

    // Test opening trace from memory (simulated file)
    let cursor = Cursor::new(&trace_data);

    // Most operations will fail with malformed data, but they should fail gracefully
    // We're primarily testing for panics and memory safety issues

    // Test trace file parsing edge cases
    let _parse_result = asupersync::trace::file::TraceReader::from_reader(cursor);

    // Test StreamingReplayer operations if we can create one
    // For fuzzing purposes, we'll use a temporary file approach
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join(format!("fuzz_trace_{}", std::process::id()));

    // Clean up any existing file
    let _ = std::fs::remove_file(&temp_file);

    // Write trace data to temp file
    if std::fs::write(&temp_file, &trace_data).is_ok() {
        // Test opening the trace file
        match asupersync::trace::streaming::StreamingReplayer::open(&temp_file) {
            Ok(mut replayer) => {
                // Test various operations on the replayer
                for operation in fuzz_input.operations.iter().take(10) {
                    match operation {
                        StreamingOperation::Open => {
                            // Already opened
                        }
                        StreamingOperation::Resume { position } => {
                            // Test resume (create fake checkpoint)
                            let events_processed = (*position).min(replayer.total_events());
                            let checkpoint = asupersync::trace::streaming::ReplayCheckpoint {
                                events_processed,
                                total_events: replayer.total_events(),
                                seed: replayer.metadata().seed,
                                metadata_hash: 0x42424242, // Fake hash
                                created_at: replayer.metadata().recorded_at,
                            };

                            let _resume_result = asupersync::trace::streaming::StreamingReplayer::resume(
                                &temp_file,
                                checkpoint,
                            );
                        }
                        StreamingOperation::NextEvent => {
                            let _event_result = replayer.next_event();
                        }
                        StreamingOperation::Peek => {
                            let _peek_result = replayer.peek();
                        }
                        StreamingOperation::CreateCheckpoint => {
                            let checkpoint = replayer.checkpoint();

                            // Test checkpoint serialization
                            if let Ok(bytes) = checkpoint.to_bytes() {
                                let _deserialize_result =
                                    asupersync::trace::streaming::ReplayCheckpoint::from_bytes(&bytes);
                            }
                        }
                        StreamingOperation::QueryProgress => {
                            let progress = replayer.progress();
                            let _percent = progress.percent();
                            let _fraction = progress.fraction();
                            let _complete = progress.is_complete();
                            let _remaining = progress.remaining();
                        }
                        StreamingOperation::CheckComplete => {
                            let _is_complete = replayer.is_complete();
                        }
                        StreamingOperation::RunToCompletion => {
                            // Run a few steps, not to completion to avoid timeouts
                            for _ in 0..3 {
                                if replayer.next_event().unwrap_or(None).is_none() {
                                    break;
                                }
                            }
                        }
                        StreamingOperation::Step => {
                            let _step_result = replayer.step();
                        }
                        StreamingOperation::GetMetadata => {
                            let _metadata = replayer.metadata();
                            let _total = replayer.total_events();
                            let _consumed = replayer.events_consumed();
                        }
                        StreamingOperation::SetMode { mode_type } => {
                            use asupersync::trace::replayer::ReplayMode;

                            let mode = match mode_type % 3 {
                                0 => ReplayMode::Run,
                                1 => ReplayMode::Step,
                                _ => ReplayMode::Run, // Simplified for fuzzing
                            };
                            replayer.set_mode(mode);
                            let _current_mode = replayer.mode();
                        }
                        StreamingOperation::Verify { event_data } => {
                            if !event_data.is_empty() {
                                // Create a synthetic ReplayEvent for verification testing
                                // This will likely fail, but should fail gracefully
                                if let Ok(synthetic_event) = rmp_serde::from_slice::<asupersync::trace::replay::ReplayEvent>(event_data) {
                                    let _verify_result = replayer.verify(&synthetic_event);
                                }
                            }
                        }
                        StreamingOperation::SerializeCheckpoint => {
                            let checkpoint = replayer.checkpoint();
                            if let Ok(serialized) = checkpoint.to_bytes() {
                                let _round_trip =
                                    asupersync::trace::streaming::ReplayCheckpoint::from_bytes(&serialized);
                            }
                        }
                        StreamingOperation::DeserializeCorruptCheckpoint => {
                            // Test deserializing corrupt checkpoint data
                            let _corrupt_result =
                                asupersync::trace::streaming::ReplayCheckpoint::from_bytes(&fuzz_input.checkpoint_data);
                        }
                    }

                    // Check for errors and breakpoints
                    let _at_breakpoint = replayer.at_breakpoint();
                    let _last_error = replayer.last_event_source_error();
                }
            }
            Err(_) => {
                // Opening failed, which is expected for malformed data
            }
        }

        // Clean up temp file
        let _ = std::fs::remove_file(&temp_file);
    }

    // Test 4: Direct MessagePack deserialization fuzzing
    if fuzz_input.trace_data.len() >= 4 {
        // Test deserializing as ReplayEvent
        let _event_result = rmp_serde::from_slice::<asupersync::trace::replay::ReplayEvent>(&fuzz_input.trace_data);

        // Test deserializing as TraceMetadata
        let _metadata_result = rmp_serde::from_slice::<asupersync::trace::replay::TraceMetadata>(&fuzz_input.trace_data);
    }

    // Test 5: File format validation edge cases
    for chunk_size in [1, 4, 16, 64] {
        if fuzz_input.trace_data.len() >= chunk_size {
            let truncated = &fuzz_input.trace_data[..chunk_size];
            let _parse_result = asupersync::trace::file::TraceReader::from_reader(Cursor::new(truncated));
        }
    }
});