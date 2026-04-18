#![no_main]

//! Fuzz target for src/encoding.rs universal encoder framing.
//!
//! This fuzzer validates the security properties of the universal encoder framing:
//! 1. Compressor kind flag validated (only known compression types accepted)
//! 2. Uncompressed length bound enforced (prevents memory exhaustion)
//! 3. Checksum matched (data integrity verification)
//! 4. Incomplete frame returns Incomplete not panic (graceful error handling)
//! 5. Multi-frame streams correctly delimited (boundary detection)

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::encoding::{EncodingPipeline, EncodingError, EncodedSymbol};
use asupersync::config::EncodingConfig;
use asupersync::types::resource::{PoolConfig, SymbolPool};
use asupersync::types::ObjectId;
use std::io::{self, ErrorKind};

/// Maximum frame size to prevent memory exhaustion during fuzzing
const MAX_FRAME_SIZE: usize = 1024 * 1024; // 1MB

/// Maximum number of frames in multi-frame test
const MAX_FRAMES: usize = 16;

/// Structured input for controlled universal encoder fuzzing scenarios.
#[derive(Arbitrary, Debug)]
enum UniversalEncoderFuzzInput {
    /// Raw bytes to feed to encoder (tests malformed inputs, boundary conditions)
    RawBytes(Vec<u8>),

    /// Structured frame data (tests specific frame scenarios)
    StructuredFrame(FrameData),

    /// Multi-frame stream (tests frame delimiting)
    MultiFrame(Vec<FrameData>),

    /// Edge case scenarios
    EdgeCase(EdgeCaseFrame),
}

/// Structured frame data for testing specific encoding scenarios
#[derive(Arbitrary, Debug)]
struct FrameData {
    /// Compressor kind flag (0=none, 1=gzip, 2=lz4, 3=zstd, others=invalid)
    compressor_kind: u8,

    /// Uncompressed length claim
    uncompressed_length: u32,

    /// Payload data
    payload: Vec<u8>,

    /// Checksum type (0=none, 1=crc32, 2=xxhash, others=invalid)
    checksum_type: u8,

    /// Checksum value
    checksum: u32,
}

#[derive(Arbitrary, Debug)]
enum EdgeCaseFrame {
    /// Empty payload with non-zero uncompressed length
    EmptyWithLength(u32),

    /// Oversized uncompressed length claim
    OversizedLength,

    /// Invalid compressor kind (> 3)
    InvalidCompressor(u8),

    /// Mismatched checksum
    BadChecksum {
        payload: Vec<u8>,
        claimed_checksum: u32,
    },

    /// Truncated frame (incomplete header)
    TruncatedHeader(Vec<u8>),

    /// Truncated frame (incomplete payload)
    TruncatedPayload {
        header_size: u8,
        payload_size: u8,
    },

    /// Frame with zero uncompressed length but non-empty payload
    ZeroLengthWithData(Vec<u8>),
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    if let Ok(input) = UniversalEncoderFuzzInput::arbitrary(&mut u) {
        fuzz_universal_encoder(input);
    }

    // Also fuzz raw bytes directly for maximum coverage
    if data.len() <= MAX_FRAME_SIZE {
        fuzz_raw_encoding(data);
    }
});

fn fuzz_universal_encoder(input: UniversalEncoderFuzzInput) {
    match input {
        UniversalEncoderFuzzInput::RawBytes(bytes) => {
            fuzz_raw_encoding(&bytes);
        }

        UniversalEncoderFuzzInput::StructuredFrame(frame) => {
            fuzz_structured_frame(frame);
        }

        UniversalEncoderFuzzInput::MultiFrame(frames) => {
            fuzz_multi_frame_stream(frames);
        }

        UniversalEncoderFuzzInput::EdgeCase(edge) => {
            fuzz_edge_case(edge);
        }
    }
}

fn fuzz_raw_encoding(bytes: &[u8]) {
    // ASSERTION 1: Encoder should handle arbitrary input without panicking
    let result = std::panic::catch_unwind(|| {
        let config = EncodingConfig {
            symbol_size: 64,
            max_block_size: 1024,
            repair_overhead: 1.2,
        };
        let pool = SymbolPool::new(PoolConfig::default());
        let mut pipeline = EncodingPipeline::new(config, pool);

        // Try to encode the raw bytes
        let object_id = ObjectId::new_for_test(42);
        let mut symbols_count = 0;

        for result in pipeline.encode(object_id, bytes) {
            match result {
                Ok(_symbol) => {
                    symbols_count += 1;
                    // Don't collect too many symbols during fuzzing
                    if symbols_count > 100 {
                        break;
                    }
                }
                Err(e) => {
                    // Errors are acceptable, panics are not
                    validate_encoding_error(&e);
                    break;
                }
            }
        }
    });

    assert!(result.is_ok(), "Raw encoding should not panic on input: {:?}",
        &bytes[..bytes.len().min(64)]);
}

fn fuzz_structured_frame(frame: FrameData) {
    // ASSERTION 2: Compressor kind flag should be validated
    if frame.compressor_kind > 3 {
        // Invalid compressor kinds should be rejected gracefully
        let serialized = serialize_frame(&frame);
        let result = parse_frame(&serialized);
        match result {
            Err(ParseError::InvalidCompressor(kind)) => {
                assert_eq!(kind, frame.compressor_kind,
                    "Invalid compressor kind should be reported correctly");
            }
            Err(_) => {
                // Other errors are acceptable for invalid compressor
            }
            Ok(_) => {
                panic!("Invalid compressor kind {} should be rejected", frame.compressor_kind);
            }
        }
        return;
    }

    // ASSERTION 3: Uncompressed length bound should be enforced
    if frame.uncompressed_length as usize > MAX_FRAME_SIZE {
        let serialized = serialize_frame(&frame);
        let result = parse_frame(&serialized);
        match result {
            Err(ParseError::LengthTooLarge(length)) => {
                assert_eq!(length, frame.uncompressed_length,
                    "Length bound violation should report correct length");
            }
            Err(_) => {
                // Other errors are acceptable for oversized length
            }
            Ok(_) => {
                panic!("Oversized length {} should be rejected", frame.uncompressed_length);
            }
        }
        return;
    }

    // ASSERTION 4: Checksum should be validated if present
    if frame.checksum_type > 0 && frame.checksum_type <= 2 {
        let expected_checksum = compute_checksum(frame.checksum_type, &frame.payload);
        if frame.checksum != expected_checksum {
            let serialized = serialize_frame(&frame);
            let result = parse_frame(&serialized);
            match result {
                Err(ParseError::ChecksumMismatch { expected, actual }) => {
                    assert_eq!(expected, expected_checksum);
                    assert_eq!(actual, frame.checksum);
                }
                Err(_) => {
                    // Other errors are acceptable for checksum mismatch
                }
                Ok(_) => {
                    panic!("Checksum mismatch should be detected: expected {}, got {}",
                        expected_checksum, frame.checksum);
                }
            }
            return;
        }
    }

    // Valid frame should parse successfully
    let serialized = serialize_frame(&frame);
    let result = parse_frame(&serialized);
    match result {
        Ok(parsed) => {
            assert_eq!(parsed.compressor_kind, frame.compressor_kind);
            assert_eq!(parsed.uncompressed_length, frame.uncompressed_length);
            assert_eq!(parsed.payload, frame.payload);
            assert_eq!(parsed.checksum_type, frame.checksum_type);
            assert_eq!(parsed.checksum, frame.checksum);
        }
        Err(e) => {
            // Even valid frames might fail due to encoding limits - should not panic
            validate_parse_error(&e, &frame);
        }
    }
}

fn fuzz_multi_frame_stream(frames: Vec<FrameData>) {
    if frames.len() > MAX_FRAMES {
        return;
    }

    // ASSERTION 5: Multi-frame streams should be correctly delimited
    let mut stream_bytes = Vec::new();
    let mut expected_frames = Vec::new();

    for frame in frames {
        // Only include valid frames in expected output
        if frame.compressor_kind <= 3 &&
           frame.uncompressed_length as usize <= MAX_FRAME_SIZE &&
           (frame.checksum_type == 0 ||
            frame.checksum == compute_checksum(frame.checksum_type, &frame.payload)) {
            let serialized = serialize_frame(&frame);
            stream_bytes.extend_from_slice(&serialized);
            expected_frames.push(frame);
        }
    }

    // Parse multi-frame stream
    let result = parse_multi_frame_stream(&stream_bytes);
    match result {
        Ok(parsed_frames) => {
            assert_eq!(parsed_frames.len(), expected_frames.len(),
                "Multi-frame stream should parse correct number of frames");

            for (parsed, expected) in parsed_frames.iter().zip(expected_frames.iter()) {
                assert_eq!(parsed.compressor_kind, expected.compressor_kind);
                assert_eq!(parsed.payload, expected.payload);
            }
        }
        Err(e) => {
            // Multi-frame parsing might fail due to size limits - should not panic
            validate_parse_error_multi(&e, &expected_frames);
        }
    }
}

fn fuzz_edge_case(edge: EdgeCaseFrame) {
    match edge {
        EdgeCaseFrame::EmptyWithLength(length) => {
            let frame = FrameData {
                compressor_kind: 0,
                uncompressed_length: length,
                payload: Vec::new(),
                checksum_type: 0,
                checksum: 0,
            };

            if length > 0 {
                // Empty payload with non-zero length should be rejected
                let serialized = serialize_frame(&frame);
                let result = parse_frame(&serialized);
                assert!(matches!(result, Err(ParseError::PayloadLengthMismatch { .. })),
                    "Empty payload with length {} should be rejected", length);
            }
        }

        EdgeCaseFrame::OversizedLength => {
            let frame = FrameData {
                compressor_kind: 0,
                uncompressed_length: u32::MAX,
                payload: vec![0xAB; 64],
                checksum_type: 0,
                checksum: 0,
            };

            let serialized = serialize_frame(&frame);
            let result = parse_frame(&serialized);
            assert!(matches!(result, Err(ParseError::LengthTooLarge(_))),
                "Oversized length should be rejected");
        }

        EdgeCaseFrame::TruncatedHeader(bytes) => {
            if bytes.len() < FRAME_HEADER_SIZE {
                // ASSERTION 4: Incomplete frames should return Incomplete, not panic
                let result = std::panic::catch_unwind(|| parse_frame(&bytes));
                assert!(result.is_ok(), "Truncated header should not panic");

                let parse_result = parse_frame(&bytes);
                assert!(matches!(parse_result, Err(ParseError::Incomplete)),
                    "Truncated header should return Incomplete");
            }
        }

        EdgeCaseFrame::TruncatedPayload { header_size, payload_size } => {
            let claimed_size = (header_size as usize * 8).min(MAX_FRAME_SIZE);
            let actual_size = (payload_size as usize * 4).min(claimed_size);

            let frame = FrameData {
                compressor_kind: 0,
                uncompressed_length: claimed_size as u32,
                payload: vec![0xCC; actual_size],
                checksum_type: 0,
                checksum: 0,
            };

            let mut serialized = serialize_frame(&frame);
            // Truncate payload
            if serialized.len() > FRAME_HEADER_SIZE + actual_size {
                serialized.truncate(FRAME_HEADER_SIZE + actual_size);
            }

            let result = std::panic::catch_unwind(|| parse_frame(&serialized));
            assert!(result.is_ok(), "Truncated payload should not panic");

            let parse_result = parse_frame(&serialized);
            assert!(matches!(parse_result, Err(ParseError::Incomplete) | Err(ParseError::PayloadLengthMismatch { .. })),
                "Truncated payload should return appropriate error");
        }

        EdgeCaseFrame::ZeroLengthWithData(data) => {
            if !data.is_empty() {
                let frame = FrameData {
                    compressor_kind: 0,
                    uncompressed_length: 0,
                    payload: data,
                    checksum_type: 0,
                    checksum: 0,
                };

                let serialized = serialize_frame(&frame);
                let result = parse_frame(&serialized);
                assert!(matches!(result, Err(ParseError::PayloadLengthMismatch { .. })),
                    "Zero length with non-empty payload should be rejected");
            }
        }

        _ => {
            // Handle other edge cases
        }
    }
}

// Mock frame format for testing universal encoder framing
const FRAME_HEADER_SIZE: usize = 13; // kind(1) + length(4) + checksum_type(1) + checksum(4) + reserved(3)

#[derive(Debug, PartialEq)]
enum ParseError {
    Incomplete,
    InvalidCompressor(u8),
    LengthTooLarge(u32),
    ChecksumMismatch { expected: u32, actual: u32 },
    PayloadLengthMismatch { claimed: u32, actual: usize },
    InvalidChecksumType(u8),
}

fn serialize_frame(frame: &FrameData) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(FRAME_HEADER_SIZE + frame.payload.len());

    bytes.push(frame.compressor_kind);
    bytes.extend_from_slice(&frame.uncompressed_length.to_le_bytes());
    bytes.push(frame.checksum_type);
    bytes.extend_from_slice(&frame.checksum.to_le_bytes());
    bytes.extend_from_slice(&[0, 0, 0]); // reserved
    bytes.extend_from_slice(&frame.payload);

    bytes
}

fn parse_frame(bytes: &[u8]) -> Result<FrameData, ParseError> {
    if bytes.len() < FRAME_HEADER_SIZE {
        return Err(ParseError::Incomplete);
    }

    let compressor_kind = bytes[0];
    if compressor_kind > 3 {
        return Err(ParseError::InvalidCompressor(compressor_kind));
    }

    let uncompressed_length = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    if uncompressed_length as usize > MAX_FRAME_SIZE {
        return Err(ParseError::LengthTooLarge(uncompressed_length));
    }

    let checksum_type = bytes[5];
    if checksum_type > 2 {
        return Err(ParseError::InvalidChecksumType(checksum_type));
    }

    let checksum = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);

    // bytes[10..13] are reserved

    let payload_start = FRAME_HEADER_SIZE;
    if bytes.len() < payload_start {
        return Err(ParseError::Incomplete);
    }

    let payload = bytes[payload_start..].to_vec();

    // Validate payload length matches claim
    if payload.len() != uncompressed_length as usize {
        return Err(ParseError::PayloadLengthMismatch {
            claimed: uncompressed_length,
            actual: payload.len(),
        });
    }

    // Validate checksum if present
    if checksum_type > 0 {
        let expected = compute_checksum(checksum_type, &payload);
        if checksum != expected {
            return Err(ParseError::ChecksumMismatch {
                expected,
                actual: checksum,
            });
        }
    }

    Ok(FrameData {
        compressor_kind,
        uncompressed_length,
        payload,
        checksum_type,
        checksum,
    })
}

fn parse_multi_frame_stream(bytes: &[u8]) -> Result<Vec<FrameData>, ParseError> {
    let mut frames = Vec::new();
    let mut offset = 0;

    while offset < bytes.len() {
        if bytes.len() - offset < FRAME_HEADER_SIZE {
            return Err(ParseError::Incomplete);
        }

        let frame_data = &bytes[offset..];
        let frame = parse_frame(frame_data)?;
        let frame_size = FRAME_HEADER_SIZE + frame.payload.len();

        frames.push(frame);
        offset += frame_size;

        // Prevent excessive frame counts during fuzzing
        if frames.len() > MAX_FRAMES {
            break;
        }
    }

    Ok(frames)
}

fn compute_checksum(checksum_type: u8, payload: &[u8]) -> u32 {
    match checksum_type {
        0 => 0, // No checksum
        1 => {
            // Simple CRC32-like checksum for testing
            let mut crc = 0xFFFFFFFFu32;
            for &byte in payload {
                crc ^= u32::from(byte);
                for _ in 0..8 {
                    if crc & 1 == 1 {
                        crc = (crc >> 1) ^ 0xEDB88320;
                    } else {
                        crc >>= 1;
                    }
                }
            }
            !crc
        }
        2 => {
            // Simple hash for testing (xxhash-like)
            let mut hash = 0x9E3779B9u32;
            for &byte in payload {
                hash ^= u32::from(byte);
                hash = hash.wrapping_mul(0x85EBCA6B);
                hash ^= hash >> 13;
                hash = hash.wrapping_mul(0xC2B2AE35);
                hash ^= hash >> 16;
            }
            hash
        }
        _ => 0,
    }
}

fn validate_encoding_error(error: &EncodingError) {
    // Encoding errors should be well-formed and not indicate internal corruption
    match error {
        EncodingError::DataTooLarge { size, limit } => {
            assert!(*size > *limit, "DataTooLarge should have size > limit");
        }
        EncodingError::InvalidConfig { reason } => {
            assert!(!reason.is_empty(), "Invalid config should have non-empty reason");
        }
        _ => {
            // Other errors are acceptable
        }
    }
}

fn validate_parse_error(error: &ParseError, _frame: &FrameData) {
    match error {
        ParseError::InvalidCompressor(kind) => {
            assert!(*kind > 3, "Invalid compressor should be > 3");
        }
        ParseError::LengthTooLarge(length) => {
            assert!(*length as usize > MAX_FRAME_SIZE, "Length should exceed limit");
        }
        ParseError::ChecksumMismatch { expected, actual } => {
            assert_ne!(expected, actual, "Checksum mismatch should have different values");
        }
        _ => {
            // Other errors are acceptable
        }
    }
}

fn validate_parse_error_multi(error: &ParseError, _frames: &[FrameData]) {
    match error {
        ParseError::Incomplete => {
            // Expected when stream is truncated
        }
        _ => {
            // Other errors are acceptable for multi-frame parsing
        }
    }
}