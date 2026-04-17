#![no_main]

//! Fuzz target for trace file format parsing.
//!
//! This target exercises the main trace file parsing code path in TraceReader,
//! testing the binary format parser, MessagePack deserialization, LZ4 decompression,
//! and all the defensive bounds checking and validation logic.
//!
//! File format (src/trace/file.rs):
//! - Magic bytes (11): "ASUPERTRACE"
//! - Version (2): u16 little-endian
//! - Flags (2): u16 little-endian (bit 0 = compression)
//! - Compression (1): u8 (0=none, 1=LZ4)
//! - Metadata length (4): u32 little-endian
//! - Metadata (variable): MessagePack-encoded TraceMetadata
//! - Event count (8): u64 little-endian
//! - Events (variable): Length-prefixed MessagePack-encoded ReplayEvent structs

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Skip tiny inputs that can't contain a valid header
    if data.len() < 32 {
        return;
    }

    // Limit input size to prevent timeout issues (16MB max)
    if data.len() > 16 * 1024 * 1024 {
        return;
    }

    // Test TraceReader parsing from memory buffer
    let cursor = Cursor::new(data);

    // This is the main parsing entry point - exercises:
    // 1. Binary header parsing (magic, version, flags, compression mode)
    // 2. Metadata deserialization (MessagePack with size limits)
    // 3. Event count validation and pre-allocation guards
    // 4. Individual event parsing with length validation
    // 5. LZ4 decompression if FLAG_COMPRESSED is set
    // 6. Truncation detection and bounds checking
    // 7. DoS mitigation (MAX_META_LEN, MAX_EVENT_LEN, MAX_COMPRESSED_CHUNK_LEN)
    match asupersync::trace::file::TraceReader::from_reader(cursor) {
        Ok(mut reader) => {
            // If parsing succeeded, try to read some events to exercise
            // the streaming event parser and MessagePack deserialization
            for _ in 0..10 {
                match reader.read_event() {
                    Ok(Some(_event)) => {
                        // Successfully parsed an event - continue
                    }
                    Ok(None) => {
                        // End of events - break
                        break;
                    }
                    Err(_) => {
                        // Parse error in event stream - break
                        break;
                    }
                }
            }

            // Test the load_all convenience method if we have a small number of events
            // This exercises pre-allocation logic and batch parsing
            if let Ok(mut reader2) =
                asupersync::trace::file::TraceReader::from_reader(Cursor::new(data))
            {
                if reader2.event_count() <= 1000 {
                    let _ = reader2.load_all();
                }
            }
        }
        Err(_) => {
            // Parse error is expected for malformed input - that's what we're testing
        }
    }

    // Test direct MessagePack deserialization of ReplayEvent and TraceMetadata
    // This exercises the serde deserialization logic independently
    if data.len() >= 4 {
        // Try to deserialize as ReplayEvent
        let _ = rmp_serde::from_slice::<asupersync::trace::replay::ReplayEvent>(data);

        // Try to deserialize as TraceMetadata
        let _ = rmp_serde::from_slice::<asupersync::trace::replay::TraceMetadata>(data);
    }

    // Test LZ4 decompression directly to catch decompression bombs and invalid streams
    if data.len() >= 8 {
        // lz4_flex::decompress_size_prepended expects first 4 bytes to be decompressed size
        let _ = lz4_flex::decompress_size_prepended(data);
    }

    // Test partial parsing scenarios by truncating at various points
    if data.len() > 50 {
        for truncate_at in [20, 30, 40, data.len() / 2] {
            if truncate_at < data.len() {
                let truncated = &data[..truncate_at];
                let _ = asupersync::trace::file::TraceReader::from_reader(Cursor::new(truncated));
            }
        }
    }
});
