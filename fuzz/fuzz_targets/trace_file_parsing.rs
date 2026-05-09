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
use std::fmt::Debug;
use std::io::Write;

const MAX_INPUT_LEN: usize = 16 * 1024 * 1024;
const MAX_DIRECT_DECOMPRESSED_LEN: usize = 16 * 1024 * 1024;

fn assert_visible_debug<T: Debug + ?Sized>(context: &str, value: &T) {
    let rendered = format!("{value:?}");
    assert!(
        !rendered.is_empty(),
        "{context} produced an empty debug representation"
    );
}

fn observe_result<T, E>(context: &str, result: Result<T, E>)
where
    T: Debug,
    E: Debug,
{
    match result {
        Ok(value) => assert_visible_debug(context, &value),
        Err(err) => assert_visible_debug(context, &err),
    }
}

fn observe_trace_reader_result(
    context: &str,
    result: asupersync::trace::file::TraceFileResult<asupersync::trace::file::TraceReader>,
) -> Option<asupersync::trace::file::TraceReader> {
    match result {
        Ok(reader) => {
            assert_visible_debug(context, &reader.event_count());
            Some(reader)
        }
        Err(err) => {
            assert_visible_debug(context, &err);
            None
        }
    }
}

fn observe_trace_reader_from_bytes(
    context: &str,
    data: &[u8],
) -> Option<(
    tempfile::NamedTempFile,
    asupersync::trace::file::TraceReader,
)> {
    let mut trace_file = match tempfile::NamedTempFile::new() {
        Ok(trace_file) => trace_file,
        Err(err) => {
            assert_visible_debug("trace temp file creation", &err);
            return None;
        }
    };

    if let Err(err) = trace_file.write_all(data) {
        assert_visible_debug("trace temp file write", &err);
        return None;
    }

    if let Err(err) = trace_file.flush() {
        assert_visible_debug("trace temp file flush", &err);
        return None;
    }

    observe_trace_reader_result(
        context,
        asupersync::trace::file::TraceReader::open(trace_file.path()),
    )
    .map(|reader| (trace_file, reader))
}

fn observe_direct_lz4(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let decompressed_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if decompressed_len <= MAX_DIRECT_DECOMPRESSED_LEN {
        observe_result(
            "LZ4 size-prepended decompression",
            lz4_flex::decompress_size_prepended(data),
        );
    }
}

fuzz_target!(|data: &[u8]| {
    // Skip tiny inputs that can't contain a valid header
    if data.len() < 32 {
        return;
    }

    // Limit input size to prevent timeout issues (16MB max)
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    // This is the main parsing entry point - exercises:
    // 1. Binary header parsing (magic, version, flags, compression mode)
    // 2. Metadata deserialization (MessagePack with size limits)
    // 3. Event count validation and pre-allocation guards
    // 4. Individual event parsing with length validation
    // 5. LZ4 decompression if FLAG_COMPRESSED is set
    // 6. Truncation detection and bounds checking
    // 7. DoS mitigation (MAX_META_LEN, MAX_EVENT_LEN, MAX_COMPRESSED_CHUNK_LEN)
    match observe_trace_reader_from_bytes("trace reader from full input", data) {
        Some((_trace_file, mut reader)) => {
            // If parsing succeeded, try to read some events to exercise
            // the streaming event parser and MessagePack deserialization
            for _ in 0..10 {
                match reader.read_event() {
                    Ok(Some(_event)) => {
                        // Successfully parsed an event - continue
                        assert_visible_debug("trace event", &_event);
                    }
                    Ok(None) => {
                        // End of events - break
                        assert_visible_debug("trace event end", &None::<()>);
                        break;
                    }
                    Err(err) => {
                        // Parse error in event stream - break
                        assert_visible_debug("trace event parse error", &err);
                        break;
                    }
                }
            }

            // Test the load_all convenience method if we have a small number of events
            // This exercises pre-allocation logic and batch parsing
            if let Some((_trace_file, reader2)) =
                observe_trace_reader_from_bytes("trace reader for load_all", data)
                && reader2.event_count() <= 1000
            {
                observe_result("trace reader load_all", reader2.load_all());
            }
        }
        None => {
            // Parse error is expected for malformed input - that's what we're testing
        }
    }

    // Test direct MessagePack deserialization of ReplayEvent and TraceMetadata
    // This exercises the serde deserialization logic independently
    if data.len() >= 4 {
        // Try to deserialize as ReplayEvent
        observe_result(
            "MessagePack ReplayEvent parse",
            rmp_serde::from_slice::<asupersync::trace::replay::ReplayEvent>(data),
        );

        // Try to deserialize as TraceMetadata
        observe_result(
            "MessagePack TraceMetadata parse",
            rmp_serde::from_slice::<asupersync::trace::replay::TraceMetadata>(data),
        );
    }

    // Test LZ4 decompression directly to catch decompression bombs and invalid streams
    if data.len() >= 8 {
        // lz4_flex::decompress_size_prepended expects first 4 bytes to be decompressed size
        observe_direct_lz4(data);
    }

    // Test partial parsing scenarios by truncating at various points
    if data.len() > 50 {
        for truncate_at in [20, 30, 40, data.len() / 2] {
            if truncate_at < data.len() {
                let truncated = &data[..truncate_at];
                drop(observe_trace_reader_from_bytes(
                    "trace reader from truncated input",
                    truncated,
                ));
            }
        }
    }
});
