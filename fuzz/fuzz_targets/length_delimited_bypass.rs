//! Length-delimited codec bypass attempt fuzz target.
//!
//! This fuzzer tests security vulnerabilities in length-delimited frame parsing per
//! RFC 9110 Section 6.1 "Message Parsing and Routing" with focus on:
//! - Length field length bypass attempts (malformed length prefixes)
//! - Length adjustment negative exploitation (integer overflow/underflow)
//! - Endianness flip attacks (big-endian vs little-endian confusion)
//! - Concatenated frames validation (frame boundary confusion)
//! - Zero-length frame idempotent behavior (edge case handling)

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::convert::TryInto;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::length_delimited::{LengthDelimitedCodec, Builder};

/// Maximum reasonable frame length for bypass testing
const MAX_FRAME_LENGTH: usize = 1_048_576; // 1MB

/// Bypass attack patterns for length-delimited frame parsing
#[derive(Arbitrary, Debug, Clone)]
enum BypassPattern {
    /// Length field length bypass (malformed length prefixes)
    LengthFieldLength {
        /// Number of bytes claimed to encode length (1-8)
        field_length: u8,
        /// Actual length value to encode
        length_value: u32,
        /// Payload to append after length field
        payload: Vec<u8>,
    },
    /// Length adjustment negative exploitation
    LengthAdjustmentNegative {
        /// Negative adjustment value (should cause underflow)
        adjustment: i64,
        /// Base length value
        base_length: u32,
        /// Frame data
        data: Vec<u8>,
    },
    /// Endianness flip attack (confusion between big/little endian)
    EndiannessFlip {
        /// Length value in little-endian
        le_length: u32,
        /// Same value interpreted as big-endian
        be_length: u32,
        /// Frame payload
        payload: Vec<u8>,
        /// Which endianness to use for encoding
        use_big_endian: bool,
    },
    /// Concatenated frames boundary confusion
    ConcatenatedFrames {
        /// First frame data
        frame1: Vec<u8>,
        /// Second frame data
        frame2: Vec<u8>,
        /// Third frame data
        frame3: Vec<u8>,
        /// Malformed boundary data between frames
        boundary_corruption: Vec<u8>,
    },
    /// Zero-length frame edge cases
    ZeroLength {
        /// Should be empty but may contain data
        payload: Vec<u8>,
        /// Number of zero-length frames to chain
        chain_count: u8,
    },
}

impl BypassPattern {
    /// Convert bypass pattern to raw bytes for fuzzing
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            BypassPattern::LengthFieldLength { field_length, length_value, payload } => {
                let mut result = Vec::new();
                let field_len = (*field_length as usize).clamp(1, 8);
                let len_val = *length_value as usize;

                // Encode length with potentially malformed field length
                match field_len {
                    1 => result.extend_from_slice(&(len_val as u8).to_be_bytes()),
                    2 => result.extend_from_slice(&(len_val as u16).to_be_bytes()),
                    3 => {
                        let bytes = (len_val as u32).to_be_bytes();
                        result.extend_from_slice(&bytes[1..]);
                    }
                    4 => result.extend_from_slice(&(len_val as u32).to_be_bytes()),
                    5..=8 => {
                        let bytes = (len_val as u64).to_be_bytes();
                        result.extend_from_slice(&bytes[8 - field_len..]);
                    }
                    _ => unreachable!(),
                }

                result.extend_from_slice(payload);
                result
            }
            BypassPattern::LengthAdjustmentNegative { adjustment, base_length, data } => {
                let mut result = Vec::new();
                // Attempt to create a scenario where negative adjustment causes issues
                let adjusted_length = (*base_length as i64).wrapping_add(*adjustment);
                if adjusted_length >= 0 && adjusted_length <= MAX_FRAME_LENGTH as i64 {
                    let len = adjusted_length as u32;
                    result.extend_from_slice(&len.to_be_bytes());
                    result.extend_from_slice(data);
                }
                result
            }
            BypassPattern::EndiannessFlip { le_length, be_length: _, payload, use_big_endian } => {
                let mut result = Vec::new();
                if *use_big_endian {
                    result.extend_from_slice(&le_length.to_be_bytes());
                } else {
                    result.extend_from_slice(&le_length.to_le_bytes());
                }
                result.extend_from_slice(payload);
                result
            }
            BypassPattern::ConcatenatedFrames { frame1, frame2, frame3, boundary_corruption } => {
                let mut result = Vec::new();

                // Frame 1
                result.extend_from_slice(&(frame1.len() as u32).to_be_bytes());
                result.extend_from_slice(frame1);

                // Boundary corruption
                result.extend_from_slice(boundary_corruption);

                // Frame 2
                result.extend_from_slice(&(frame2.len() as u32).to_be_bytes());
                result.extend_from_slice(frame2);

                // Frame 3
                result.extend_from_slice(&(frame3.len() as u32).to_be_bytes());
                result.extend_from_slice(frame3);

                result
            }
            BypassPattern::ZeroLength { payload, chain_count } => {
                let mut result = Vec::new();
                let count = (*chain_count as usize).min(10); // Limit chains

                for _ in 0..count {
                    // Zero-length frame but may have payload (malformed)
                    result.extend_from_slice(&0u32.to_be_bytes());
                    if !payload.is_empty() {
                        // This is malformed - zero length but has data
                        result.extend_from_slice(payload);
                    }
                }
                result
            }
        }
    }
}

/// Fuzz input structure for bypass testing
#[derive(Arbitrary, Debug)]
struct LengthDelimitedBypassFuzz {
    /// The bypass attack pattern to test
    pattern: BypassPattern,
    /// Codec configuration for testing
    length_field_length: u8,        // 1-8 bytes
    length_adjustment: i64,         // Can be negative
    num_skip: u64,                  // Bytes to skip before length field
    max_frame_length: u32,          // Maximum allowed frame length
}

fuzz_target!(|input: LengthDelimitedBypassFuzz| {
    let raw_data = input.pattern.to_bytes();
    if raw_data.is_empty() || raw_data.len() > MAX_FRAME_LENGTH {
        return;
    }

    // Build codec with potentially vulnerable configuration
    let mut builder = Builder::new();

    let field_len = (input.length_field_length as usize).clamp(1, 8);
    builder.length_field_length(field_len);

    if input.length_adjustment != 0 {
        builder.length_adjustment(input.length_adjustment);
    }

    if input.num_skip > 0 {
        builder.num_skip(input.num_skip as usize);
    }

    let max_len = (input.max_frame_length as usize).min(MAX_FRAME_LENGTH);
    builder.max_frame_length(max_len);

    let mut codec = builder.new_codec();

    // ASSERTION 1: Length field length bypass prevention
    // The codec must reject malformed length fields that don't match configuration
    if let BypassPattern::LengthFieldLength { field_length, length_value, .. } = &input.pattern {
        let configured_field_len = field_len;
        let attempted_field_len = (*field_length as usize).clamp(1, 8);

        // If attempted field length doesn't match config, parsing should fail or be consistent
        if attempted_field_len != configured_field_len {
            let mut buf = BytesMut::from(&raw_data[..]);
            let result = codec.decode(&mut buf);

            // Either should fail gracefully or handle consistently
            match result {
                Ok(Some(_frame)) => {
                    // If it succeeds, the frame length calculation must be consistent
                    // with the configured field length, not the malformed one
                    assert!(*length_value <= max_len as u32,
                        "Length field length bypass: accepted oversized frame {} > {}",
                        length_value, max_len);
                }
                Ok(None) => {
                    // Need more data - acceptable
                }
                Err(_) => {
                    // Error is acceptable for malformed input
                }
            }
        }
    }

    // ASSERTION 2: Length adjustment negative exploitation protection
    // Negative adjustments must not cause integer underflow or buffer access violations
    if let BypassPattern::LengthAdjustmentNegative { adjustment, base_length, .. } = &input.pattern {
        if *adjustment < 0 {
            let mut buf = BytesMut::from(&raw_data[..]);
            let result = codec.decode(&mut buf);

            match result {
                Ok(Some(frame)) => {
                    // If parsing succeeds with negative adjustment, frame size must be reasonable
                    assert!(frame.len() <= max_len,
                        "Negative length adjustment bypass: frame too large {} > {}",
                        frame.len(), max_len);

                    // Frame size must not be larger than original base length
                    assert!(frame.len() <= *base_length as usize,
                        "Negative adjustment resulted in larger frame: {} > {}",
                        frame.len(), base_length);
                }
                Ok(None) => {
                    // Need more data - acceptable
                }
                Err(_) => {
                    // Error is the expected behavior for negative adjustment exploitation
                }
            }
        }
    }

    // ASSERTION 3: Endianness flip attack prevention
    // Parser must consistently interpret length fields regardless of endianness confusion
    if let BypassPattern::EndiannessFlip { le_length, be_length: _, payload, use_big_endian } = &input.pattern {
        let mut buf = BytesMut::from(&raw_data[..]);
        let result = codec.decode(&mut buf);

        match result {
            Ok(Some(frame)) => {
                if *use_big_endian {
                    // Big-endian interpretation should be used consistently
                    let expected_len = payload.len().min(max_len);
                    assert!(frame.len() <= expected_len.max(*le_length as usize),
                        "Endianness flip attack: inconsistent frame length {} vs expected {}",
                        frame.len(), expected_len);
                } else {
                    // Little-endian should not be accepted if codec expects big-endian
                    // Most length-delimited codecs use big-endian by convention
                    if field_len <= 4 {
                        assert!(frame.len() <= max_len,
                            "Endianness flip bypass: frame too large {} > {}",
                            frame.len(), max_len);
                    }
                }
            }
            Ok(None) => {
                // Need more data - acceptable
            }
            Err(_) => {
                // Error is acceptable for malformed endianness
            }
        }
    }

    // ASSERTION 4: Concatenated frames boundary validation
    // Frame boundaries must be strictly respected, no frame bleeding
    if let BypassPattern::ConcatenatedFrames { frame1, frame2, frame3, boundary_corruption } = &input.pattern {
        if !boundary_corruption.is_empty() {
            let mut buf = BytesMut::from(&raw_data[..]);
            let mut frame_count = 0;
            let mut decoded_frames = Vec::new();

            // Attempt to decode multiple frames
            while !buf.is_empty() && frame_count < 5 {
                match codec.decode(&mut buf) {
                    Ok(Some(frame)) => {
                        decoded_frames.push(frame);
                        frame_count += 1;
                    }
                    Ok(None) => break, // Need more data
                    Err(_) => break,   // Parse error
                }
            }

            // If boundary corruption didn't prevent parsing, frames must match originals
            for (i, decoded_frame) in decoded_frames.iter().enumerate() {
                let expected_frame = match i {
                    0 => frame1,
                    1 => frame2,
                    2 => frame3,
                    _ => break,
                };

                // Frame content must not be corrupted by boundary issues
                if decoded_frame.len() == expected_frame.len() {
                    assert_eq!(decoded_frame.as_ref(), expected_frame.as_slice(),
                        "Concatenated frames boundary corruption: frame {} content mismatch",
                        i);
                }

                assert!(decoded_frame.len() <= max_len,
                    "Concatenated frames bypass: frame {} too large {} > {}",
                    i, decoded_frame.len(), max_len);
            }
        }
    }

    // ASSERTION 5: Zero-length frame idempotent behavior
    // Zero-length frames must be handled consistently and not cause state corruption
    if let BypassPattern::ZeroLength { payload, chain_count } = &input.pattern {
        let mut buf = BytesMut::from(&raw_data[..]);
        let mut zero_frames_decoded = 0;
        let mut has_non_empty_payload = false;

        // Decode all frames in the chain
        while !buf.is_empty() && zero_frames_decoded < 10 {
            match codec.decode(&mut buf) {
                Ok(Some(frame)) => {
                    if frame.is_empty() {
                        zero_frames_decoded += 1;
                    } else if !payload.is_empty() {
                        // Zero-length prefix but non-empty payload - this is malformed
                        has_non_empty_payload = true;
                        break;
                    }

                    // Frame must not exceed max length even in zero-length chain
                    assert!(frame.len() <= max_len,
                        "Zero-length chain bypass: frame too large {} > {}",
                        frame.len(), max_len);
                }
                Ok(None) => break, // Need more data
                Err(_) => break,   // Parse error (acceptable for malformed zero-length)
            }
        }

        // Zero-length frames with payload should either be rejected or payload ignored
        if has_non_empty_payload && zero_frames_decoded > 0 {
            // This indicates the codec incorrectly parsed zero-length frame with payload
            assert!(false,
                "Zero-length idempotent violation: parsed {} zero-length frames with non-empty payload",
                zero_frames_decoded);
        }

        // Multiple zero-length frames should be handled consistently (idempotent)
        if *chain_count > 1 && zero_frames_decoded >= 2 {
            // All zero-length frames in chain should behave identically
            assert!(zero_frames_decoded <= *chain_count as usize,
                "Zero-length chain inconsistency: decoded {} frames from {} chain count",
                zero_frames_decoded, chain_count);
        }
    }

    // General robustness: codec must never panic or cause memory safety violations
    let mut buf = BytesMut::from(&raw_data[..]);
    let _ = codec.decode(&mut buf);

    // Additional round-trip test if decoding succeeded
    let mut buf2 = BytesMut::from(&raw_data[..]);
    if let Ok(Some(frame)) = codec.decode(&mut buf2) {
        // Re-encoding the frame should be safe and deterministic
        let mut encoder_buf = BytesMut::new();
        let encode_result = codec.encode(frame.clone(), &mut encoder_buf);

        if encode_result.is_ok() {
            // Re-encoded frame should decode to the same result
            let mut roundtrip_buf = BytesMut::from(encoder_buf.freeze());
            if let Ok(Some(roundtrip_frame)) = codec.decode(&mut roundtrip_buf) {
                assert_eq!(frame.len(), roundtrip_frame.len(),
                    "Round-trip bypass: frame length changed {} -> {}",
                    frame.len(), roundtrip_frame.len());

                assert_eq!(frame, roundtrip_frame,
                    "Round-trip bypass: frame content corrupted");
            }
        }
    }
});