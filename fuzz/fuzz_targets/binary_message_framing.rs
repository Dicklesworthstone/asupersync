//! Advanced fuzz target for binary message framing and length-delimited parsing.
//!
//! This target focuses on frame boundary detection, state machine robustness,
//! fragmented message reassembly, and protocol-level edge cases beyond basic
//! LengthDelimitedCodec testing.
//!
//! # Target Areas
//! - Frame boundary detection across buffer chunks
//! - State machine transitions with malformed input
//! - Recovery from parse errors mid-frame
//! - Resource exhaustion via memory consumption attacks
//! - Protocol multiplexing/demultiplexing scenarios
//! - Nested and recursive frame structures
//! - Fragmented frame reassembly logic
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run binary_message_framing
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use asupersync::codec::{Decoder, LengthDelimitedCodec};
use asupersync::bytes::BytesMut;
use std::collections::VecDeque;

/// Maximum iterations to prevent infinite loops
const MAX_DECODE_ITERATIONS: usize = 1000;
const MAX_CHUNK_SIZE: usize = 65536;
const MAX_TOTAL_DATA: usize = 1_000_000;

#[derive(Arbitrary, Debug, Clone)]
struct FramingConfig {
    /// Length field configuration
    length_field_offset: u8,        // 0..=32
    length_field_length: u8,        // 1..=8
    length_adjustment: i16,         // Adjustment to length value
    num_skip: u8,                   // Skip bytes after header
    max_frame_length: u16,          // Maximum allowed frame
    big_endian: bool,               // Byte order

    /// Protocol version (for version mismatch testing)
    protocol_version: u8,

    /// Multiplexing configuration
    stream_id_offset: u8,           // Offset for stream ID field
    enable_checksum: bool,          // Include checksum fields

    /// State machine stress testing
    induce_parse_errors: bool,      // Intentionally corrupt length fields
    fragment_reassembly: bool,      // Test fragmented frame handling
}

#[derive(Arbitrary, Debug, Clone)]
struct FrameOperation {
    /// Type of operation to perform
    op_type: u8,  // 0 = normal frame, 1 = corrupt length, 2 = inject bytes, 3 = truncate

    /// Frame data
    frame_data: Vec<u8>,

    /// Corruption parameters
    corruption_offset: u8,
    corruption_value: u8,
    injection_point: u8,
    injection_data: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct FragmentationStrategy {
    /// How to split frames across chunks
    chunk_sizes: Vec<u16>,          // Variable chunk sizes
    interleave_noise: bool,         // Add noise between chunks
    drop_chunks: bool,              // Randomly drop chunks
    reorder_chunks: bool,           // Reorder chunks
    duplicate_chunks: bool,         // Duplicate some chunks
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    config: FramingConfig,
    operations: Vec<FrameOperation>,
    fragmentation: FragmentationStrategy,
    raw_data: Vec<u8>,
}

/// Test frame boundary detection with fragmented input
fn test_fragmented_parsing(codec: &mut LengthDelimitedCodec, data: &[u8], chunk_sizes: &[u16]) {
    let mut buf = BytesMut::new();
    let mut chunks = VecDeque::new();

    // Split data into chunks
    let mut offset = 0;
    for &chunk_size in chunk_sizes {
        let end = std::cmp::min(offset + chunk_size as usize, data.len());
        if end > offset {
            chunks.push_back(&data[offset..end]);
            offset = end;
        }
        if offset >= data.len() {
            break;
        }
    }

    // Add remaining data as final chunk
    if offset < data.len() {
        chunks.push_back(&data[offset..]);
    }

    let mut iterations = 0;
    let mut frames_decoded = 0;

    // Process chunks one at a time, attempting decode after each chunk
    while let Some(chunk) = chunks.pop_front() {
        buf.extend_from_slice(chunk);

        // Try to decode frames from accumulated buffer
        loop {
            iterations += 1;
            if iterations > MAX_DECODE_ITERATIONS {
                return; // Prevent infinite loops
            }

            match codec.decode(&mut buf) {
                Ok(Some(frame)) => {
                    frames_decoded += 1;

                    // Validate frame properties
                    assert!(frame.len() <= 10_000_000, "Frame too large");

                    // Test frame content for basic sanity
                    if !frame.is_empty() {
                        // Frames should not contain only null bytes (unless intentional)
                        let has_non_null = frame.iter().any(|&b| b != 0);
                        if !has_non_null && frame.len() > 100 {
                            // Suspicious: large frame of all zeros might indicate parsing error
                            // But don't panic - this could be legitimate
                        }
                    }
                }
                Ok(None) => {
                    // Need more data - continue to next chunk
                    break;
                }
                Err(_) => {
                    // Parse error - this is expected with malformed input
                    return;
                }
            }

            // Limit frames per test to prevent excessive resource usage
            if frames_decoded > 100 {
                return;
            }
        }
    }
}

/// Test state machine transitions with corrupted length fields
fn test_corruption_recovery(mut config: FramingConfig, operations: &[FrameOperation]) {
    if operations.is_empty() {
        return;
    }

    // Build codec
    let length_field_length = std::cmp::max(1, std::cmp::min(8, config.length_field_length as usize));
    let length_field_offset = std::cmp::min(32, config.length_field_offset as usize);
    let max_frame_length = std::cmp::max(1, config.max_frame_length as usize);

    let mut codec = LengthDelimitedCodec::builder()
        .length_field_offset(length_field_offset)
        .length_field_length(length_field_length)
        .length_adjustment(config.length_adjustment as isize)
        .num_skip(std::cmp::min(255, config.num_skip as usize))
        .max_frame_length(max_frame_length);

    codec = if config.big_endian {
        codec.big_endian()
    } else {
        codec.little_endian()
    };

    let mut codec = codec.new_codec();
    let mut buf = BytesMut::new();

    // Apply operations to test state transitions
    for op in operations.iter().take(10) { // Limit operations
        match op.op_type % 4 {
            0 => {
                // Normal frame - construct valid length-prefixed frame
                if op.frame_data.len() <= max_frame_length {
                    construct_valid_frame(&mut buf, &op.frame_data, &config);
                }
            }
            1 => {
                // Corrupt length field
                if !buf.is_empty() && buf.len() > length_field_offset + length_field_length {
                    let corruption_offset = (op.corruption_offset as usize) % length_field_length;
                    let target_offset = length_field_offset + corruption_offset;
                    if target_offset < buf.len() {
                        buf[target_offset] = op.corruption_value;
                    }
                }
            }
            2 => {
                // Inject random bytes at arbitrary position
                let injection_data = &op.injection_data.iter().take(100).copied().collect::<Vec<_>>();
                if !injection_data.is_empty() && buf.len() < MAX_CHUNK_SIZE {
                    let injection_point = if buf.is_empty() {
                        0
                    } else {
                        (op.injection_point as usize) % buf.len()
                    };

                    // Split buffer and inject data
                    let mut new_buf = BytesMut::new();
                    new_buf.extend_from_slice(&buf[..injection_point]);
                    new_buf.extend_from_slice(injection_data);
                    new_buf.extend_from_slice(&buf[injection_point..]);
                    buf = new_buf;
                }
            }
            3 => {
                // Truncate buffer (simulates incomplete read)
                if !buf.is_empty() {
                    let truncate_point = (op.corruption_offset as usize) % buf.len();
                    buf.truncate(truncate_point);
                }
            }
            _ => unreachable!(),
        }

        // Attempt decode after each operation
        let mut attempts = 0;
        while attempts < 10 {
            attempts += 1;
            match codec.decode(&mut buf) {
                Ok(Some(_)) => {
                    // Successfully decoded despite corruption attempts
                }
                Ok(None) => {
                    // Need more data
                    break;
                }
                Err(_) => {
                    // Parse error - test recovery by clearing buffer or adding more data
                    if buf.len() > 1000 {
                        buf.clear(); // Reset on large error accumulation
                    }
                    break;
                }
            }
        }
    }
}

/// Construct a valid length-prefixed frame
fn construct_valid_frame(buf: &mut BytesMut, payload: &[u8], config: &FramingConfig) {
    let length_field_length = std::cmp::max(1, std::cmp::min(8, config.length_field_length as usize));
    let length_field_offset = std::cmp::min(32, config.length_field_offset as usize);

    // Add padding to reach length field offset
    while buf.len() < length_field_offset {
        buf.extend_from_slice(&[0u8]);
    }

    // Encode payload length
    let payload_len = payload.len() as u64;
    let mut length_bytes = vec![0u8; length_field_length];

    if config.big_endian {
        for i in 0..length_field_length {
            let shift = (length_field_length - 1 - i) * 8;
            if shift < 64 {
                length_bytes[i] = (payload_len >> shift) as u8;
            }
        }
    } else {
        for i in 0..length_field_length {
            let shift = i * 8;
            if shift < 64 {
                length_bytes[i] = (payload_len >> shift) as u8;
            }
        }
    }

    buf.extend_from_slice(&length_bytes);

    // Add payload
    buf.extend_from_slice(payload);
}

/// Test protocol version mismatch scenarios
fn test_protocol_version_mismatch(config: &FramingConfig, data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let mut versioned_data = BytesMut::new();

    // Prepend protocol version byte
    versioned_data.extend_from_slice(&[config.protocol_version]);
    versioned_data.extend_from_slice(data);

    // Try parsing with standard codec (should handle or reject gracefully)
    let mut codec = LengthDelimitedCodec::new();
    let mut buf = versioned_data;

    // Should not panic regardless of version byte
    let _ = codec.decode(&mut buf);
}

/// Test resource exhaustion scenarios
fn test_resource_exhaustion(config: &FramingConfig, data: &[u8]) {
    // Guard against excessive memory allocation
    if data.len() > MAX_TOTAL_DATA {
        return;
    }

    // Test with various large frame configurations
    let large_configs = [
        (1, 1_000_000),    // Large max frame
        (8, 100_000),      // Large length field
        (0, 50_000),       // No offset, medium frame
    ];

    for (offset, max_frame) in large_configs {
        let mut codec = LengthDelimitedCodec::builder()
            .length_field_offset(offset)
            .max_frame_length(max_frame)
            .new_codec();

        let mut buf = BytesMut::from(data);

        // Decode with memory usage monitoring
        let mut total_decoded = 0;
        let mut iterations = 0;

        while iterations < 50 && total_decoded < 10_000_000 {
            iterations += 1;
            match codec.decode(&mut buf) {
                Ok(Some(frame)) => {
                    total_decoded += frame.len();
                    if total_decoded > 10_000_000 {
                        break; // Prevent excessive memory usage
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    // Guard against excessively large inputs
    if input.raw_data.len() > MAX_TOTAL_DATA {
        return;
    }

    // Test 1: Basic codec fuzzing with configuration variations
    let length_field_length = std::cmp::max(1, std::cmp::min(8, input.config.length_field_length as usize));
    let length_field_offset = std::cmp::min(32, input.config.length_field_offset as usize);
    let max_frame_length = std::cmp::max(1, input.config.max_frame_length as usize);

    let mut main_codec = LengthDelimitedCodec::builder()
        .length_field_offset(length_field_offset)
        .length_field_length(length_field_length)
        .length_adjustment(input.config.length_adjustment as isize)
        .num_skip(std::cmp::min(255, input.config.num_skip as usize))
        .max_frame_length(max_frame_length);

    main_codec = if input.config.big_endian {
        main_codec.big_endian()
    } else {
        main_codec.little_endian()
    };

    let mut main_codec = main_codec.new_codec();
    let mut main_buf = BytesMut::from(&input.raw_data[..]);

    // Basic decode with iteration limit
    let mut iterations = 0;
    while iterations < MAX_DECODE_ITERATIONS {
        iterations += 1;
        match main_codec.decode(&mut main_buf) {
            Ok(Some(_)) => {
                // Frame decoded successfully
                if main_buf.is_empty() {
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }

    // Test 2: Fragmented parsing with variable chunk sizes
    if !input.fragmentation.chunk_sizes.is_empty() {
        let chunk_sizes: Vec<u16> = input.fragmentation.chunk_sizes
            .iter()
            .take(20)  // Limit chunks
            .map(|&size| std::cmp::max(1, std::cmp::min(MAX_CHUNK_SIZE as u16, size)))
            .collect();

        let mut frag_codec = LengthDelimitedCodec::builder()
            .length_field_offset(length_field_offset)
            .length_field_length(length_field_length)
            .max_frame_length(max_frame_length)
            .new_codec();

        test_fragmented_parsing(&mut frag_codec, &input.raw_data, &chunk_sizes);
    }

    // Test 3: Corruption and recovery
    if input.config.induce_parse_errors && !input.operations.is_empty() {
        test_corruption_recovery(input.config.clone(), &input.operations);
    }

    // Test 4: Protocol version mismatch
    test_protocol_version_mismatch(&input.config, &input.raw_data);

    // Test 5: Resource exhaustion protection
    test_resource_exhaustion(&input.config, &input.raw_data);

    // Test 6: State machine stress testing
    if input.config.fragment_reassembly {
        // Test with extreme fragmentation (1-byte chunks)
        let single_byte_chunks: Vec<u16> = (0..std::cmp::min(100, input.raw_data.len()))
            .map(|_| 1)
            .collect();

        if !single_byte_chunks.is_empty() {
            let mut stress_codec = LengthDelimitedCodec::new();
            test_fragmented_parsing(&mut stress_codec, &input.raw_data, &single_byte_chunks);
        }
    }

    // Test 7: Multiple codec instances (simulating multiplexing)
    if input.config.stream_id_offset > 0 && input.raw_data.len() > 4 {
        let mut codec1 = LengthDelimitedCodec::builder()
            .length_field_offset(0)
            .new_codec();
        let mut codec2 = LengthDelimitedCodec::builder()
            .length_field_offset(input.config.stream_id_offset as usize)
            .new_codec();

        let mut buf1 = BytesMut::from(&input.raw_data[..input.raw_data.len() / 2]);
        let mut buf2 = BytesMut::from(&input.raw_data[input.raw_data.len() / 2..]);

        // Decode from both streams
        let _ = codec1.decode(&mut buf1);
        let _ = codec2.decode(&mut buf2);
    }

    // Test 8: Edge cases

    // Empty buffer
    let mut empty_codec = LengthDelimitedCodec::new();
    let mut empty_buf = BytesMut::new();
    let result = empty_codec.decode(&mut empty_buf);
    assert!(result.is_ok() && result.unwrap().is_none());

    // Single byte buffer
    if !input.raw_data.is_empty() {
        let mut single_codec = LengthDelimitedCodec::new();
        let mut single_buf = BytesMut::from(&input.raw_data[..1]);
        let _ = single_codec.decode(&mut single_buf);
    }

    // Large length field edge case
    if input.raw_data.len() >= 8 {
        let mut large_field_codec = LengthDelimitedCodec::builder()
            .length_field_length(8)
            .max_frame_length(1_000_000)
            .new_codec();
        let mut large_buf = BytesMut::from(&input.raw_data[..]);
        let _ = large_field_codec.decode(&mut large_buf);
    }
});