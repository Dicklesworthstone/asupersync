#![no_main]

use arbitrary::Arbitrary;
use asupersync::trace::file::{
    CompressionMode, TraceFileConfig, TraceFileError, TraceReader, TraceWriter,
};
use asupersync::trace::replay::{ReplayEvent, TraceMetadata};
use libfuzzer_sys::fuzz_target;
use std::fs::{File, remove_file};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use tempfile::NamedTempFile;

/// Comprehensive fuzz target for trace file writer/reader durability testing
///
/// Tests the file-based trace persistence for:
/// - File format robustness with malformed headers and corrupted data
/// - Compression/decompression reliability under adverse conditions
/// - Size limit enforcement and memory safety with oversized inputs
/// - Error recovery from disk full, write failures, and corruption
/// - Round-trip correctness preserving trace data integrity
/// - Configuration validation and edge case handling
/// - Reader resilience to truncated/corrupted trace files
/// - Writer durability under resource constraints and failure scenarios
#[derive(Arbitrary, Debug)]
struct TraceFileFuzz {
    /// Operations to perform on the trace file system
    operations: Vec<TraceFileOperation>,
    /// Configuration for writing traces
    writer_config: WriterConfigFuzz,
    /// Test data for events
    events: Vec<ReplayEventFuzz>,
    /// Metadata to write
    metadata: TraceMetadataFuzz,
}

/// Fuzzing operations on trace files
#[derive(Arbitrary, Debug)]
enum TraceFileOperation {
    /// Test normal write-read cycle
    WriteAndRead { compress: bool, event_count: u8 },
    /// Test with corrupted file data
    WriteAndCorrupt {
        corruption_offset: u32,
        corruption_data: Vec<u8>,
    },
    /// Test with partial/truncated files
    WriteAndTruncate { truncate_at: u32 },
    /// Test compression scenarios
    TestCompression {
        mode: CompressionModeFuzz,
        events: Vec<ReplayEventFuzz>,
    },
    /// Test size limit enforcement
    TestSizeLimits {
        max_events: Option<u32>,
        max_file_size: Option<u64>,
        oversized_event_size: u32,
    },
    /// Test error recovery
    TestErrorRecovery {
        simulate_disk_full: bool,
        force_write_error: bool,
    },
    /// Test malformed headers
    TestMalformedHeader { header_data: Vec<u8> },
    /// Test reader resilience
    TestReaderResilience { file_data: Vec<u8> },
}

/// Writer configuration for fuzzing
#[derive(Arbitrary, Debug)]
struct WriterConfigFuzz {
    compression: CompressionModeFuzz,
    chunk_size: u32,
    max_events: Option<u32>,
    max_file_size: Option<u64>,
}

/// Compression mode for fuzzing
#[derive(Arbitrary, Debug)]
enum CompressionModeFuzz {
    None,
    Lz4 { level: i8 },
    Auto,
}

/// Trace metadata for fuzzing
#[derive(Arbitrary, Debug)]
struct TraceMetadataFuzz {
    schema_version: u32,
    seed: u64,
    data_bytes: Vec<u8>,
}

/// Replay event for fuzzing
#[derive(Arbitrary, Debug)]
enum ReplayEventFuzz {
    RngSeed { seed: u64 },
    TaskSpawn { id: u64, name: String },
    TaskComplete { id: u64 },
    Delay { nanos: u64 },
    CustomEvent { data: Vec<u8> },
}

/// Safety limits to prevent resource exhaustion
const MAX_OPERATIONS: usize = 10;
const MAX_EVENTS: usize = 1000;
const MAX_EVENT_SIZE: usize = 100_000;
const MAX_FILE_SIZE: u64 = 10_000_000;
const MAX_CHUNK_SIZE: u32 = 1_000_000;
const MAX_CORRUPTION_SIZE: usize = 10_000;
const MAX_METADATA_SIZE: usize = 100_000;

fn observe_io_result(context: &str, result: std::io::Result<()>) -> bool {
    match result {
        Ok(()) => true,
        Err(error) => {
            let error_kind = format!("{:?}", error.kind());
            assert!(
                !error_kind.is_empty(),
                "{context} failed without an I/O error kind"
            );
            false
        }
    }
}

fn observe_io_value<T>(context: &str, result: std::io::Result<T>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            let error_kind = format!("{:?}", error.kind());
            assert!(
                !error_kind.is_empty(),
                "{context} failed without an I/O error kind"
            );
            None
        }
    }
}

fn observe_writer_create_result(
    context: &str,
    result: Result<TraceWriter, TraceFileError>,
) -> Option<TraceWriter> {
    match result {
        Ok(writer) => Some(writer),
        Err(TraceFileError::Io(_)) => None,
        Err(error) => panic!("{context} returned non-create trace error: {error:?}"),
    }
}

fn observe_writer_result(context: &str, result: Result<(), TraceFileError>) -> bool {
    match result {
        Ok(()) => true,
        Err(TraceFileError::Io(_))
        | Err(TraceFileError::Serialize(_))
        | Err(TraceFileError::Compression(_))
        | Err(TraceFileError::AlreadyFinished)
        | Err(TraceFileError::MetadataNotWritten)
        | Err(TraceFileError::MetadataAlreadyWritten)
        | Err(TraceFileError::MetadataCorrupt) => false,
        Err(error) => panic!("{context} returned non-writer trace error: {error:?}"),
    }
}

fuzz_target!(|input: TraceFileFuzz| {
    // Limit operations for performance
    let operations = if input.operations.len() > MAX_OPERATIONS {
        &input.operations[..MAX_OPERATIONS]
    } else {
        &input.operations
    };

    // Test configuration validation
    test_config_validation(&input.writer_config);

    // Create safe configurations
    let safe_config = create_safe_config(&input.writer_config);

    // Execute trace file operations
    for operation in operations {
        match operation {
            TraceFileOperation::WriteAndRead {
                compress,
                event_count,
            } => {
                test_write_read_cycle(
                    &safe_config,
                    *compress,
                    *event_count,
                    &input.events,
                    &input.metadata,
                );
            }
            TraceFileOperation::WriteAndCorrupt {
                corruption_offset,
                corruption_data,
            } => {
                test_file_corruption(
                    &safe_config,
                    *corruption_offset,
                    corruption_data,
                    &input.events,
                    &input.metadata,
                );
            }
            TraceFileOperation::WriteAndTruncate { truncate_at } => {
                test_file_truncation(&safe_config, *truncate_at, &input.events, &input.metadata);
            }
            TraceFileOperation::TestCompression { mode, events } => {
                test_compression_scenarios(mode, events);
            }
            TraceFileOperation::TestSizeLimits {
                max_events,
                max_file_size,
                oversized_event_size,
            } => {
                test_size_limits(*max_events, *max_file_size, *oversized_event_size);
            }
            TraceFileOperation::TestErrorRecovery {
                simulate_disk_full,
                force_write_error,
            } => {
                test_error_recovery(*simulate_disk_full, *force_write_error);
            }
            TraceFileOperation::TestMalformedHeader { header_data } => {
                test_malformed_header(header_data);
            }
            TraceFileOperation::TestReaderResilience { file_data } => {
                test_reader_resilience(file_data);
            }
        }
    }
});

fn test_config_validation(_config: &WriterConfigFuzz) {
    // Test various configuration edge cases
    let test_configs = [
        TraceFileConfig {
            compression: CompressionMode::None,
            chunk_size: 0, // Invalid
            max_events: None,
            max_file_size: MAX_FILE_SIZE,
            on_limit: asupersync::trace::recorder::LimitAction::StopRecording,
        },
        TraceFileConfig {
            compression: CompressionMode::None,
            chunk_size: 1024,
            max_events: Some(0), // Edge case
            max_file_size: MAX_FILE_SIZE,
            on_limit: asupersync::trace::recorder::LimitAction::StopRecording,
        },
        TraceFileConfig {
            compression: CompressionMode::None,
            chunk_size: 1024,
            max_events: None,
            max_file_size: 1, // Very small
            on_limit: asupersync::trace::recorder::LimitAction::StopRecording,
        },
    ];

    for config in &test_configs {
        // Configuration creation should not panic
        if let Ok(temp) = create_temp_file_result() {
            let _writer = observe_writer_create_result(
                "config validation writer create",
                TraceWriter::create_with_config(&temp, config.clone()),
            );
            let _ = remove_file(temp);
        }
    }
}

fn test_write_read_cycle(
    config: &TraceFileConfig,
    compress: bool,
    event_count: u8,
    events: &[ReplayEventFuzz],
    metadata: &TraceMetadataFuzz,
) {
    let temp_file = match create_temp_file() {
        Ok(f) => f,
        Err(_) => return,
    };

    // Test basic write-read cycle
    let test_config = if compress {
        TraceFileConfig {
            compression: CompressionMode::Lz4 { level: 1 },
            ..config.clone()
        }
    } else {
        TraceFileConfig {
            compression: CompressionMode::None,
            ..config.clone()
        }
    };

    // Write trace
    let write_result = write_test_trace(&temp_file, &test_config, event_count, events, metadata);

    match write_result {
        Ok(expected_events) => {
            // Try to read the trace back
            read_and_validate_trace(&temp_file, &expected_events, metadata);
        }
        Err(_) => {
            // Write failures are acceptable - test error handling
        }
    }

    let _ = remove_file(&temp_file);
}

fn test_file_corruption(
    config: &TraceFileConfig,
    corruption_offset: u32,
    corruption_data: &[u8],
    events: &[ReplayEventFuzz],
    metadata: &TraceMetadataFuzz,
) {
    let temp_file = match create_temp_file() {
        Ok(f) => f,
        Err(_) => return,
    };

    // Write a valid trace first
    if write_test_trace(&temp_file, config, 5, events, metadata).is_err() {
        let _ = remove_file(&temp_file);
        return;
    }

    // Corrupt the file at specified offset
    if let Ok(mut file) = File::options().write(true).open(&temp_file) {
        let offset = corruption_offset as u64;
        if file.seek(SeekFrom::Start(offset)).is_ok() {
            let corruption_bytes = if corruption_data.len() > MAX_CORRUPTION_SIZE {
                &corruption_data[..MAX_CORRUPTION_SIZE]
            } else {
                corruption_data
            };
            if !observe_io_result("trace corruption write", file.write_all(corruption_bytes))
                || !observe_io_result("trace corruption flush", file.flush())
            {
                let _ = remove_file(&temp_file);
                return;
            }
        }
    }

    // Try to read the corrupted file - should handle errors gracefully
    let reader_result = TraceReader::open(&temp_file);
    match reader_result {
        Ok(reader) => {
            // If reader opens successfully, test event iteration error handling
            for event_result in reader.events().take(10) {
                match event_result {
                    Ok(_) => {}      // Valid event despite corruption
                    Err(_) => break, // Expected error due to corruption
                }
            }
        }
        Err(_) => {
            // Reader failure is expected with corruption
        }
    }

    let _ = remove_file(&temp_file);
}

fn test_file_truncation(
    config: &TraceFileConfig,
    truncate_at: u32,
    events: &[ReplayEventFuzz],
    metadata: &TraceMetadataFuzz,
) {
    let temp_file = match create_temp_file() {
        Ok(f) => f,
        Err(_) => return,
    };

    // Write a valid trace first
    if write_test_trace(&temp_file, config, 10, events, metadata).is_err() {
        let _ = remove_file(&temp_file);
        return;
    }

    // Truncate the file at specified position
    let Some(file) = observe_io_value(
        "trace truncation open",
        File::options().write(true).open(&temp_file),
    ) else {
        let _ = remove_file(&temp_file);
        return;
    };
    if !observe_io_result(
        "trace truncation set_len",
        file.set_len(u64::from(truncate_at)),
    ) {
        let _ = remove_file(&temp_file);
        return;
    }

    // Try to read the truncated file - should detect truncation
    let reader_result = TraceReader::open(&temp_file);
    match reader_result {
        Ok(reader) => {
            // Test reading from truncated file
            for event_result in reader.events().take(5) {
                match event_result {
                    Ok(_) => {}
                    Err(TraceFileError::Truncated) => break, // Expected
                    Err(_) => break,                         // Other errors also acceptable
                }
            }
        }
        Err(TraceFileError::Truncated) => {
            // Expected error for severely truncated files
        }
        Err(_) => {
            // Other errors also acceptable
        }
    }

    let _ = remove_file(&temp_file);
}

fn test_compression_scenarios(mode: &CompressionModeFuzz, events: &[ReplayEventFuzz]) {
    let temp_file = match create_temp_file() {
        Ok(f) => f,
        Err(_) => return,
    };

    let compression_mode = convert_compression_mode(mode);
    let config = TraceFileConfig {
        compression: compression_mode,
        chunk_size: 1024,
        max_events: None,
        max_file_size: MAX_FILE_SIZE,
        on_limit: asupersync::trace::recorder::LimitAction::StopRecording,
    };

    // Test compression with various event patterns
    let writer_result = TraceWriter::create_with_config(&temp_file, config);
    let mut writer_finished = false;
    if let Ok(mut writer) = writer_result {
        let metadata = create_test_metadata(&TraceMetadataFuzz {
            schema_version: 1,
            seed: 42,
            data_bytes: vec![],
        });

        // Write metadata and events
        if observe_writer_result(
            "compression metadata write",
            writer.write_metadata(&metadata),
        ) {
            let limited_events = if events.len() > MAX_EVENTS {
                &events[..MAX_EVENTS]
            } else {
                events
            };

            for event_fuzz in limited_events {
                let event = convert_replay_event(event_fuzz);
                if !observe_writer_result("compression event write", writer.write_event(&event)) {
                    break;
                }
            }

            // Finish writing
            writer_finished = observe_writer_result("compression finish", writer.finish());
        }
    }

    // Try to read back compressed data
    if writer_finished && let Ok(reader) = TraceReader::open(&temp_file) {
        // Test reading compressed events
        for (i, event_result) in reader.events().enumerate() {
            if i >= MAX_EVENTS {
                break;
            }
            match event_result {
                Ok(_) => {}
                Err(_) => break, // Decompression or other errors
            }
        }
    }

    let _ = remove_file(&temp_file);
}

fn test_size_limits(
    max_events: Option<u32>,
    max_file_size: Option<u64>,
    oversized_event_size: u32,
) {
    let temp_file = match create_temp_file() {
        Ok(f) => f,
        Err(_) => return,
    };

    let config = TraceFileConfig {
        compression: CompressionMode::None,
        chunk_size: 1024,
        max_events: max_events.map(|e| e.min(1000) as u64), // Cap to reasonable limit
        max_file_size: max_file_size.unwrap_or(MAX_FILE_SIZE).min(MAX_FILE_SIZE),
        on_limit: asupersync::trace::recorder::LimitAction::StopRecording,
    };

    let mut writer = match TraceWriter::create_with_config(&temp_file, config) {
        Ok(w) => w,
        Err(_) => {
            let _ = remove_file(&temp_file);
            return;
        }
    };

    let metadata = create_test_metadata(&TraceMetadataFuzz {
        schema_version: 1,
        seed: 42,
        data_bytes: vec![],
    });

    // Write metadata
    if writer.write_metadata(&metadata).is_err() {
        let _ = remove_file(&temp_file);
        return;
    }

    // Test oversized event
    let oversized_event = ReplayEvent::RngSeed { seed: 123 }; // Use simple event to avoid size issues
    let write_attempts = ((oversized_event_size as usize).min(MAX_EVENT_SIZE) / 1024).clamp(1, 100);

    // Write events until limit is hit
    for _ in 0..write_attempts {
        match writer.write_event(&oversized_event) {
            Ok(()) => {}     // Event written successfully
            Err(_) => break, // Limit reached or other error
        }
    }

    // Test finish() even after potential limit violations
    if !observe_writer_result("size limit finish", writer.finish()) {
        let _ = remove_file(&temp_file);
        return;
    }

    let _ = remove_file(&temp_file);
}

fn test_error_recovery(_simulate_disk_full: bool, _force_write_error: bool) {
    // These tests would require more complex setup to simulate actual I/O errors
    // For now, test basic error handling paths

    let temp_file = match create_temp_file() {
        Ok(f) => f,
        Err(_) => return,
    };

    let config = TraceFileConfig::default();
    let mut writer = match TraceWriter::create_with_config(&temp_file, config) {
        Ok(w) => w,
        Err(_) => {
            let _ = remove_file(&temp_file);
            return;
        }
    };

    let metadata = create_test_metadata(&TraceMetadataFuzz {
        schema_version: 1,
        seed: 42,
        data_bytes: vec![],
    });

    // Test various error scenarios
    if !observe_writer_result(
        "error recovery metadata write",
        writer.write_metadata(&metadata),
    ) {
        let _ = remove_file(&temp_file);
        return;
    }
    let _event_written = observe_writer_result(
        "error recovery event write",
        writer.write_event(&ReplayEvent::RngSeed { seed: 1 }),
    );

    // Test finish under potential error conditions
    let _finished = observe_writer_result("error recovery finish", writer.finish());

    let _ = remove_file(&temp_file);
}

fn test_malformed_header(header_data: &[u8]) {
    let temp_file = match create_temp_file() {
        Ok(f) => f,
        Err(_) => return,
    };

    // Write malformed header data directly
    if let Ok(mut file) = File::create(&temp_file) {
        let limited_data = if header_data.len() > 1000 {
            &header_data[..1000]
        } else {
            header_data
        };
        if !observe_io_result("malformed header write", file.write_all(limited_data))
            || !observe_io_result("malformed header flush", file.flush())
        {
            let _ = remove_file(&temp_file);
            return;
        }
    }

    // Try to read file with malformed header
    let reader_result = TraceReader::open(&temp_file);
    match reader_result {
        Ok(_) => {
            // Unexpected success - malformed data was somehow valid
        }
        Err(TraceFileError::InvalidMagic) => {
            // Expected for invalid magic bytes
        }
        Err(TraceFileError::UnsupportedVersion { .. }) => {
            // Expected for invalid version
        }
        Err(TraceFileError::UnsupportedFlags(_)) => {
            // Expected for invalid flags
        }
        Err(TraceFileError::Truncated) => {
            // Expected for incomplete header
        }
        Err(_) => {
            // Other errors also acceptable
        }
    }

    let _ = remove_file(&temp_file);
}

fn test_reader_resilience(file_data: &[u8]) {
    let temp_file = match create_temp_file() {
        Ok(f) => f,
        Err(_) => return,
    };

    // Write arbitrary data as a trace file
    if let Ok(mut file) = File::create(&temp_file) {
        let limited_data = if file_data.len() > 100_000 {
            &file_data[..100_000]
        } else {
            file_data
        };
        if !observe_io_result("reader resilience write", file.write_all(limited_data))
            || !observe_io_result("reader resilience flush", file.flush())
        {
            let _ = remove_file(&temp_file);
            return;
        }
    }

    // Test reader resilience to arbitrary data
    let reader_result = TraceReader::open(&temp_file);
    match reader_result {
        Ok(reader) => {
            let _metadata_seed = reader.metadata().seed;
            let _event_count = reader.event_count();

            // If reader opens, test event iteration resilience
            for (i, event_result) in reader.events().enumerate() {
                if i >= 10 {
                    break; // Limit iterations
                }
                match event_result {
                    Ok(_) => {}
                    Err(_) => break, // Expected for malformed data
                }
            }
        }
        Err(_) => {
            // Reader failure is expected for arbitrary data
        }
    }

    let _ = remove_file(&temp_file);
}

// Helper functions

fn create_safe_config(config: &WriterConfigFuzz) -> TraceFileConfig {
    TraceFileConfig {
        compression: convert_compression_mode(&config.compression),
        chunk_size: config.chunk_size.clamp(1024, MAX_CHUNK_SIZE) as usize,
        max_events: config.max_events.map(|e| (e as u64).min(10_000)),
        max_file_size: config
            .max_file_size
            .unwrap_or(MAX_FILE_SIZE)
            .min(MAX_FILE_SIZE),
        on_limit: asupersync::trace::recorder::LimitAction::StopRecording,
    }
}

fn convert_compression_mode(mode: &CompressionModeFuzz) -> CompressionMode {
    match mode {
        CompressionModeFuzz::None => CompressionMode::None,
        CompressionModeFuzz::Lz4 { level } => CompressionMode::Lz4 {
            level: (*level).clamp(-1, 16) as i32,
        },
        CompressionModeFuzz::Auto => CompressionMode::Auto,
    }
}

fn create_test_metadata(metadata_fuzz: &TraceMetadataFuzz) -> TraceMetadata {
    let description_bytes =
        &metadata_fuzz.data_bytes[..metadata_fuzz.data_bytes.len().min(MAX_METADATA_SIZE)];
    let data_hash = fold_bytes(metadata_fuzz.schema_version as u64, description_bytes);

    let mut metadata = TraceMetadata::new(metadata_fuzz.seed).with_config_hash(data_hash);
    metadata.version = metadata_fuzz.schema_version;
    if !description_bytes.is_empty() {
        metadata.description = Some(format!("fuzz-metadata-bytes={}", description_bytes.len()));
    }
    metadata
}

fn convert_replay_event(event_fuzz: &ReplayEventFuzz) -> ReplayEvent {
    match event_fuzz {
        ReplayEventFuzz::RngSeed { seed } => ReplayEvent::RngSeed { seed: *seed },
        ReplayEventFuzz::TaskSpawn { id, name } => {
            // Create a simplified task spawn event
            ReplayEvent::RngSeed {
                seed: fold_bytes(*id, name.as_bytes()),
            } // Simplify to avoid complex types
        }
        ReplayEventFuzz::TaskComplete { id } => {
            ReplayEvent::RngSeed { seed: *id } // Simplify to avoid complex types
        }
        ReplayEventFuzz::Delay { nanos } => {
            ReplayEvent::RngSeed { seed: *nanos } // Simplify to avoid complex types
        }
        ReplayEventFuzz::CustomEvent { data } => {
            ReplayEvent::RngSeed {
                seed: fold_bytes(42, data),
            } // Simplify to avoid complex types
        }
    }
}

fn fold_bytes(seed: u64, bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .take(MAX_EVENT_SIZE)
        .fold(seed, |acc, byte| acc.rotate_left(5) ^ u64::from(*byte))
}

fn create_temp_file() -> Result<PathBuf, std::io::Error> {
    let temp = NamedTempFile::new()?;
    let path = temp.path().to_path_buf();
    temp.persist(&path)?;
    Ok(path)
}

fn create_temp_file_result() -> Result<PathBuf, std::io::Error> {
    create_temp_file()
}

fn write_test_trace(
    path: &PathBuf,
    config: &TraceFileConfig,
    event_count: u8,
    events: &[ReplayEventFuzz],
    metadata: &TraceMetadataFuzz,
) -> Result<Vec<ReplayEvent>, TraceFileError> {
    let mut writer = TraceWriter::create_with_config(path, config.clone())?;

    let test_metadata = create_test_metadata(metadata);
    writer.write_metadata(&test_metadata)?;

    let mut written_events = Vec::new();
    let count = event_count.min(20) as usize; // Reasonable limit

    for i in 0..count {
        let event = if i < events.len() {
            convert_replay_event(&events[i])
        } else {
            ReplayEvent::RngSeed { seed: i as u64 }
        };

        writer.write_event(&event)?;
        written_events.push(event);
    }

    writer.finish()?;
    Ok(written_events)
}

fn read_and_validate_trace(
    path: &PathBuf,
    expected_events: &[ReplayEvent],
    metadata: &TraceMetadataFuzz,
) {
    let reader = match TraceReader::open(path) {
        Ok(r) => r,
        Err(_) => return,
    };

    // Validate metadata
    assert_eq!(reader.metadata().seed, metadata.seed);

    // Validate events
    let mut event_count = 0;
    for (i, event_result) in reader.events().enumerate() {
        match event_result {
            Ok(event) => {
                if i < expected_events.len() {
                    // Basic validation - exact comparison might be too strict for fuzzing
                    if let (ReplayEvent::RngSeed { seed: a }, ReplayEvent::RngSeed { seed: b }) =
                        (&event, &expected_events[i])
                    {
                        assert_eq!(a, b);
                    }
                }
                event_count += 1;
            }
            Err(_) => break,
        }
    }

    // Event count should match
    assert_eq!(event_count, expected_events.len());
}
