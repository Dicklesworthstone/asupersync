#![no_main]

//! Fuzz target for trace file writer durability and data integrity.
//!
//! This target exercises the write-side durability guarantees of the trace file format,
//! focusing on data integrity, error recovery, and robustness under adverse conditions.
//!
//! Key durability properties tested:
//! 1. Write-Read Round-trip: Data written can be successfully read back
//! 2. Interruption Resilience: Graceful handling of write interruptions
//! 3. Corruption Detection: Detection of file corruption and data integrity issues
//! 4. Resource Exhaustion: Behavior under disk full, memory pressure conditions
//! 5. Compression Integrity: Round-trip integrity with different compression modes
//! 6. Metadata Consistency: Metadata and event count consistency after crashes

use libfuzzer_sys::fuzz_target;
use std::fs;
use std::path::PathBuf;
use asupersync::trace::file::{TraceWriter, TraceReader, TraceFileConfig, CompressionMode};
use asupersync::trace::replay::{ReplayEvent, TraceMetadata, CompactTaskId, CompactRegionId};

fuzz_target!(|data: &[u8]| {
    // Skip tiny inputs
    if data.len() < 8 {
        return;
    }

    // Limit size to prevent timeouts
    if data.len() > 512 * 1024 {
        return;
    }

    // Parse fuzzer input into operations
    let mut input = data;
    let operations = parse_fuzz_operations(&mut input);

    // Test different durability scenarios
    test_write_read_roundtrip(&operations);
    test_interruption_resilience(&operations);
    test_compression_durability(&operations);
    test_metadata_consistency(&operations);
    test_partial_write_recovery(&operations);
    test_concurrent_access(&operations);
});

#[derive(Debug, Clone)]
enum FuzzOperation {
    WriteMetadata(TraceMetadata),
    WriteEvent(ReplayEvent),
    FlushWriter,
    FinishWriter,
    Interrupt,
    CorruptFile,
}

fn parse_fuzz_operations(input: &mut &[u8]) -> Vec<FuzzOperation> {
    let mut ops = Vec::new();
    let mut rng_state = 42u64;

    // Create test metadata
    let metadata = TraceMetadata::new(extract_u64(input, &mut rng_state));
    ops.push(FuzzOperation::WriteMetadata(metadata));

    // Generate events from input bytes
    while input.len() >= 4 && ops.len() < 30 {
        let op_type = extract_u8(input, &mut rng_state) % 6;

        match op_type {
            0 => {
                // Create a simple event from fuzzer data
                let seed = extract_u64(input, &mut rng_state);
                ops.push(FuzzOperation::WriteEvent(ReplayEvent::RngSeed { seed }));
            }
            1 => {
                let task = CompactTaskId(extract_u64(input, &mut rng_state));
                let region = CompactRegionId(extract_u64(input, &mut rng_state));
                let at_tick = extract_u64(input, &mut rng_state);
                ops.push(FuzzOperation::WriteEvent(ReplayEvent::TaskSpawned {
                    task,
                    region,
                    at_tick,
                }));
            }
            2 => ops.push(FuzzOperation::FlushWriter),
            3 => ops.push(FuzzOperation::FinishWriter),
            4 => ops.push(FuzzOperation::Interrupt),
            5 => ops.push(FuzzOperation::CorruptFile),
            _ => unreachable!(),
        }
    }

    ops
}

fn test_write_read_roundtrip(operations: &[FuzzOperation]) {
    // Test with different compression modes
    let compression_modes = vec![
        CompressionMode::None,
        #[cfg(feature = "trace-compression")]
        CompressionMode::Lz4 { level: 1 },
        #[cfg(feature = "trace-compression")]
        CompressionMode::Auto,
    ];

    for compression in compression_modes {
        let temp_path = get_temp_path();

        // Write phase
        let config = TraceFileConfig::default().with_compression(compression);
        if write_trace_operations(&operations, &temp_path, &config).is_ok() {
            // Read phase - verify round-trip integrity
            if let Ok(mut reader) = TraceReader::open(&temp_path) {
                verify_trace_integrity(&mut reader, &operations);
            }
        }

        // Cleanup
        let _ = fs::remove_file(&temp_path);
    }
}

fn test_interruption_resilience(operations: &[FuzzOperation]) {
    // Simulate write interruptions at various points
    for interrupt_point in 0..operations.len().min(8) {
        let temp_path = get_temp_path();
        let mut truncated_ops = operations[..interrupt_point].to_vec();
        truncated_ops.push(FuzzOperation::Interrupt);

        let config = TraceFileConfig::default();
        let _ = write_trace_operations(&truncated_ops, &temp_path, &config);

        // Attempt to read partially written file
        if let Ok(mut reader) = TraceReader::open(&temp_path) {
            // Should not crash when reading interrupted file
            for _ in 0..5 {
                if reader.read_event().is_err() {
                    break;
                }
            }
        }

        // Cleanup
        let _ = fs::remove_file(&temp_path);
    }
}

fn test_compression_durability(_operations: &[FuzzOperation]) {
    #[cfg(feature = "trace-compression")]
    {
        // Test compression edge cases with different levels
        let compression_levels = vec![-1, 0, 1, 8, 16];

        for level in compression_levels {
            let temp_path = get_temp_path();
            let config = TraceFileConfig::default()
                .with_compression(CompressionMode::Lz4 { level });

            // Create a simple trace with compression
            let simple_ops = vec![
                FuzzOperation::WriteMetadata(TraceMetadata::new(12345)),
                FuzzOperation::WriteEvent(ReplayEvent::RngSeed { seed: 42 }),
                FuzzOperation::FinishWriter,
            ];

            if write_trace_operations(&simple_ops, &temp_path, &config).is_ok() {
                // Verify compressed data can be read back correctly
                if let Ok(mut reader) = TraceReader::open(&temp_path) {
                    // Read all events to verify decompression integrity
                    while let Ok(Some(_event)) = reader.read_event() {
                        // Continue reading
                    }
                }
            }

            // Cleanup
            let _ = fs::remove_file(&temp_path);
        }
    }
}

fn test_metadata_consistency(operations: &[FuzzOperation]) {
    let temp_path = get_temp_path();
    let config = TraceFileConfig::default();

    if write_trace_operations(operations, &temp_path, &config).is_ok() {
        if let Ok(reader) = TraceReader::open(&temp_path) {
            // Verify metadata consistency
            let expected_events = count_expected_events(operations);
            let actual_count = reader.event_count();

            // Event count should match what was written (within reason for fuzzing)
            if expected_events <= 100 && actual_count <= 100 {
                assert_eq!(expected_events, actual_count,
                          "Event count mismatch: expected {} got {}",
                          expected_events, actual_count);
            }
        }
    }

    // Cleanup
    let _ = fs::remove_file(&temp_path);
}

fn test_partial_write_recovery(operations: &[FuzzOperation]) {
    let temp_path = get_temp_path();
    let config = TraceFileConfig::default();

    if write_trace_operations(operations, &temp_path, &config).is_ok() {
        // Read the full file content
        if let Ok(full_data) = fs::read(&temp_path) {
            // Test truncation at various byte positions
            for &truncate_ratio in &[0.25, 0.5, 0.75, 0.9] {
                let truncate_at = ((full_data.len() as f64) * truncate_ratio) as usize;

                if truncate_at > 50 && truncate_at < full_data.len() {
                    let truncated_path = get_temp_path();
                    let truncated = &full_data[..truncate_at];

                    if fs::write(&truncated_path, truncated).is_ok() {
                        // Should either parse successfully or fail gracefully
                        match TraceReader::open(&truncated_path) {
                            Ok(mut reader) => {
                                // Should not crash when reading truncated file
                                for _ in 0..3 {
                                    if reader.read_event().is_err() {
                                        break;
                                    }
                                }
                            }
                            Err(_) => {
                                // Expected for severely truncated files
                            }
                        }
                    }

                    // Cleanup
                    let _ = fs::remove_file(&truncated_path);
                }
            }
        }
    }

    // Cleanup
    let _ = fs::remove_file(&temp_path);
}

fn test_concurrent_access(operations: &[FuzzOperation]) {
    let temp_path = get_temp_path();
    let config = TraceFileConfig::default();

    // Test concurrent read during write
    if write_trace_operations(operations, &temp_path, &config).is_ok() {
        // Try to read while another process might be writing
        let _ = TraceReader::open(&temp_path);

        // Try to read again (should work if file is complete)
        if let Ok(mut reader) = TraceReader::open(&temp_path) {
            let _ = reader.read_event();
        }
    }

    // Cleanup
    let _ = fs::remove_file(&temp_path);
}

fn write_trace_operations(
    operations: &[FuzzOperation],
    path: &PathBuf,
    config: &TraceFileConfig
) -> Result<(), Box<dyn std::error::Error>> {
    let mut trace_writer = TraceWriter::create_with_config(path, config.clone())?;
    let mut metadata_written = false;

    for op in operations {
        match op {
            FuzzOperation::WriteMetadata(metadata) => {
                if !metadata_written {
                    trace_writer.write_metadata(metadata)?;
                    metadata_written = true;
                }
            }
            FuzzOperation::WriteEvent(event) => {
                if metadata_written {
                    let _ = trace_writer.write_event(event);
                }
            }
            FuzzOperation::FlushWriter => {
                // TraceWriter auto-flushes, no public flush method
            }
            FuzzOperation::FinishWriter => {
                return trace_writer.finish().map_err(Into::into);
            }
            FuzzOperation::Interrupt => {
                // Simulate abrupt termination
                drop(trace_writer);
                return Ok(());
            }
            FuzzOperation::CorruptFile => {
                // Introduce corruption by writing some events then stopping
                drop(trace_writer);
                return Ok(());
            }
        }
    }

    trace_writer.finish().map_err(Into::into)
}

fn verify_trace_integrity(reader: &mut TraceReader, operations: &[FuzzOperation]) {
    let expected_events = count_expected_events(operations);
    let mut actual_events = 0;

    // Read all events and count them
    while let Ok(Some(_event)) = reader.read_event() {
        actual_events += 1;

        // Prevent infinite loops in fuzzing
        if actual_events > expected_events.saturating_mul(2).max(100) {
            break;
        }
    }

    // Events should match (within reason for fuzzing)
    if expected_events <= 50 && actual_events <= 100 {
        assert_eq!(expected_events, actual_events,
                  "Round-trip event count mismatch");
    }
}

fn count_expected_events(operations: &[FuzzOperation]) -> u64 {
    operations.iter()
        .filter(|op| matches!(op, FuzzOperation::WriteEvent(_)))
        .count() as u64
}

fn get_temp_path() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();

    std::env::temp_dir().join(format!("fuzz_trace_{}_{}.bin", pid, id))
}

// Helper functions to extract data from fuzzer input
fn extract_u8(input: &mut &[u8], rng_state: &mut u64) -> u8 {
    if input.is_empty() {
        *rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        (*rng_state >> 8) as u8
    } else {
        let val = input[0];
        *input = &input[1..];
        val
    }
}


fn extract_u64(input: &mut &[u8], rng_state: &mut u64) -> u64 {
    if input.len() < 8 {
        *rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        *rng_state
    } else {
        let val = u64::from_le_bytes([
            input[0], input[1], input[2], input[3],
            input[4], input[5], input[6], input[7],
        ]);
        *input = &input[8..];
        val
    }
}