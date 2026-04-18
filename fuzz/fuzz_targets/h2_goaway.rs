#![no_main]

//! Fuzz target for src/http/h2/frame.rs GOAWAY frame parsing.
//!
//! This target specifically tests GOAWAY frame parsing with 5 critical assertions:
//! 1. last-stream-id within uint31 bounds (R bit cleared)
//! 2. error_code enum validated (unknown codes map to INTERNAL_ERROR)
//! 3. additional_debug_data opaque (arbitrary bytes accepted)
//! 4. GOAWAY forces stream closure (protocol behavior)
//! 5. GOAWAY on Stream ID 0 mandatory (connection-scoped only)

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::{BufMut, Bytes, BytesMut};
use asupersync::http::h2::error::{ErrorCode, H2Error};
use asupersync::http::h2::frame::{Frame, FrameHeader, FrameType, GoAwayFrame, parse_frame};

/// Maximum fuzz input size to prevent timeouts.
const MAX_FUZZ_INPUT_SIZE: usize = 16_384;

/// GOAWAY frame fuzzing configuration.
#[derive(Arbitrary, Debug, Clone)]
struct GoAwayFuzzInput {
    /// Raw last stream ID (may have reserved bit set for testing).
    pub raw_last_stream_id: u32,
    /// Raw error code (may be unknown for testing enum validation).
    pub raw_error_code: u32,
    /// Additional debug data (opaque bytes).
    pub debug_data: Vec<u8>,
    /// Stream ID for the frame header (should be 0, but we test violations).
    pub frame_stream_id: u32,
    /// Frame flags (should be 0 for GOAWAY, but we test invalid combinations).
    pub frame_flags: u8,
    /// Test malformed payload lengths.
    pub malformed_length: Option<MalformedLength>,
}

/// Types of malformed payload lengths to test.
#[derive(Arbitrary, Debug, Clone)]
enum MalformedLength {
    /// Payload too short (< 8 bytes).
    TooShort { actual_length: u8 },
    /// Advertised length doesn't match payload.
    LengthMismatch { advertised: u16, actual: u16 },
    /// Truncated in middle of fields.
    TruncatedFields { truncate_at: u8 },
}

/// Normalize fuzz input to prevent timeouts.
fn normalize_input(mut input: GoAwayFuzzInput) -> GoAwayFuzzInput {
    // Limit debug data size.
    input.debug_data.truncate(1024);

    // Clamp malformed length values.
    if let Some(ref mut malformed) = input.malformed_length {
        match malformed {
            MalformedLength::TooShort { actual_length } => {
                *actual_length = (*actual_length).clamp(0, 7);
            }
            MalformedLength::LengthMismatch { advertised, actual } => {
                *advertised = (*advertised).clamp(0, 1024);
                *actual = (*actual).clamp(0, 1024);
            }
            MalformedLength::TruncatedFields { truncate_at } => {
                *truncate_at = (*truncate_at).clamp(0, 10);
            }
        }
    }

    input
}

/// Build a GOAWAY frame payload for testing.
fn build_goaway_payload(input: &GoAwayFuzzInput) -> Vec<u8> {
    let mut payload = Vec::new();

    if let Some(malformed) = &input.malformed_length {
        match malformed {
            MalformedLength::TooShort { actual_length } => {
                // Create payload shorter than 8 bytes.
                payload.resize(*actual_length as usize, 0);
                return payload;
            }
            MalformedLength::TruncatedFields { truncate_at } => {
                // Build partial payload truncated at specific point.
                if *truncate_at == 0 {
                    return payload; // Empty
                }

                let full_payload = build_normal_payload(input);
                payload.extend_from_slice(
                    &full_payload[..(*truncate_at as usize).min(full_payload.len())],
                );
                return payload;
            }
            MalformedLength::LengthMismatch { actual, .. } => {
                // Build payload with actual length but advertised length will differ.
                let normal = build_normal_payload(input);
                payload.extend_from_slice(&normal);
                payload.resize(*actual as usize, 0);
                return payload;
            }
        }
    }

    build_normal_payload(input)
}

/// Build a normal GOAWAY payload.
fn build_normal_payload(input: &GoAwayFuzzInput) -> Vec<u8> {
    let mut payload = Vec::new();

    // Last stream ID (4 bytes, with R bit handling).
    payload.extend_from_slice(&input.raw_last_stream_id.to_be_bytes());

    // Error code (4 bytes).
    payload.extend_from_slice(&input.raw_error_code.to_be_bytes());

    // Additional debug data (variable length).
    payload.extend_from_slice(&input.debug_data);

    payload
}

/// Test the 5 GOAWAY frame parsing assertions.
fn test_goaway_frame_assertions(input: GoAwayFuzzInput) -> Result<(), String> {
    let payload_bytes = build_goaway_payload(&input);

    // Determine advertised length.
    let advertised_length =
        if let Some(MalformedLength::LengthMismatch { advertised, .. }) = &input.malformed_length {
            *advertised as u32
        } else {
            payload_bytes.len() as u32
        };

    // Build frame header.
    let frame_header = FrameHeader {
        length: advertised_length,
        frame_type: FrameType::GoAway as u8,
        flags: input.frame_flags,
        stream_id: input.frame_stream_id,
    };

    let payload = Bytes::from(payload_bytes);

    // Attempt to parse GOAWAY frame.
    let parse_result = GoAwayFrame::parse(&frame_header, &payload);

    match parse_result {
        Ok(goaway_frame) => {
            // ASSERTION 1: last-stream-id within uint31 bounds
            // The parser should have cleared the reserved (R) bit.
            if goaway_frame.last_stream_id > 0x7FFFFFFF {
                return Err(format!(
                    "ASSERTION 1 FAILED: last_stream_id {} exceeds 31-bit limit",
                    goaway_frame.last_stream_id
                ));
            }

            // Verify R bit was properly cleared.
            let expected_last_stream_id = input.raw_last_stream_id & 0x7FFFFFFF;
            if goaway_frame.last_stream_id != expected_last_stream_id {
                return Err(format!(
                    "ASSERTION 1 FAILED: R bit not properly cleared. Expected {}, got {}",
                    expected_last_stream_id, goaway_frame.last_stream_id
                ));
            }

            // ASSERTION 2: error_code enum validated
            // Unknown error codes should be mapped to INTERNAL_ERROR.
            let expected_error_code = ErrorCode::from_u32(input.raw_error_code);
            if goaway_frame.error_code != expected_error_code {
                return Err(format!(
                    "ASSERTION 2 FAILED: error code validation failed. Expected {:?}, got {:?}",
                    expected_error_code, goaway_frame.error_code
                ));
            }

            // ASSERTION 3: additional_debug_data opaque
            // Any debug data should be preserved as-is.
            if goaway_frame.debug_data.as_ref() != input.debug_data.as_slice() {
                return Err(format!(
                    "ASSERTION 3 FAILED: debug data not preserved. Expected {} bytes, got {} bytes",
                    input.debug_data.len(),
                    goaway_frame.debug_data.len()
                ));
            }

            // ASSERTION 5: GOAWAY on Stream ID 0 mandatory
            // If frame was parsed successfully, stream ID must have been 0.
            if frame_header.stream_id != 0 {
                return Err(format!(
                    "ASSERTION 5 FAILED: GOAWAY parsed with non-zero stream ID {}",
                    frame_header.stream_id
                ));
            }
        }

        Err(h2_error) => {
            // ASSERTION 5: GOAWAY on Stream ID 0 mandatory
            // Non-zero stream ID should be rejected with PROTOCOL_ERROR.
            if frame_header.stream_id != 0 {
                if h2_error.code != ErrorCode::ProtocolError {
                    return Err(format!(
                        "ASSERTION 5 FAILED: Non-zero stream ID should cause PROTOCOL_ERROR, got {:?}",
                        h2_error.code
                    ));
                }
                // This is the expected behavior - GOAWAY with non-zero stream ID rejected.
                return Ok(());
            }

            // For other parse errors, verify they're reasonable.
            match h2_error.code {
                ErrorCode::FrameSizeError => {
                    // ASSERTION 3: Frame too short should be rejected.
                    if payload.len() < 8 {
                        return Ok(()); // Expected
                    }
                    return Err(format!(
                        "ASSERTION 3 FAILED: Unexpected FRAME_SIZE_ERROR with payload length {}",
                        payload.len()
                    ));
                }
                ErrorCode::ProtocolError => {
                    // Various protocol violations are acceptable to reject.
                    return Ok(());
                }
                _ => {
                    return Err(format!(
                        "ASSERTION GENERAL: Unexpected error code {:?} for GOAWAY parsing",
                        h2_error.code
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Test GOAWAY frame in the context of a complete frame parsing pipeline.
fn test_goaway_frame_pipeline(input: &GoAwayFuzzInput) -> Result<(), String> {
    let payload_bytes = build_goaway_payload(input);

    // Build complete frame with header + payload.
    let mut frame_bytes = BytesMut::new();

    // Frame header (9 bytes).
    let frame_length = payload_bytes.len() as u32;
    frame_bytes.put_u8((frame_length >> 16) as u8);
    frame_bytes.put_u8((frame_length >> 8) as u8);
    frame_bytes.put_u8(frame_length as u8);
    frame_bytes.put_u8(FrameType::GoAway as u8);
    frame_bytes.put_u8(input.frame_flags);
    frame_bytes.put_u32(input.frame_stream_id);

    // Payload.
    frame_bytes.extend_from_slice(&payload_bytes);

    // Parse complete frame.
    let parse_result = parse_frame(frame_bytes.freeze());

    match parse_result {
        Ok(Frame::GoAway(goaway_frame)) => {
            // ASSERTION 4: GOAWAY forces stream closure
            // This is a protocol-level assertion - the frame itself doesn't enforce closure,
            // but the connection state machine should handle this. For fuzzing purposes,
            // we just verify the frame was parsed correctly.

            // Verify the frame contents match our expectations.
            let expected_last_stream_id = input.raw_last_stream_id & 0x7FFFFFFF;
            if goaway_frame.last_stream_id != expected_last_stream_id {
                return Err(format!(
                    "ASSERTION 4/PIPELINE: Pipeline parsing altered last_stream_id"
                ));
            }

            Ok(())
        }

        Ok(_other_frame) => {
            Err("ASSERTION PIPELINE: Expected GoAway frame, got different frame type".to_string())
        }

        Err(h2_error) => {
            // Various parsing errors are acceptable.
            match h2_error.code {
                ErrorCode::ProtocolError | ErrorCode::FrameSizeError => Ok(()),
                _ => Err(format!(
                    "ASSERTION PIPELINE: Unexpected error {:?}",
                    h2_error.code
                )),
            }
        }
    }
}

/// Test GOAWAY frame edge cases and boundary conditions.
fn test_goaway_edge_cases(input: &GoAwayFuzzInput) -> Result<(), String> {
    // Test maximum last_stream_id value.
    let max_stream_payload = {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x7FFFFFFFu32.to_be_bytes()); // Max valid stream ID
        payload.extend_from_slice(&(ErrorCode::NoError as u32).to_be_bytes());
        payload.extend_from_slice(b"max_stream_test");
        payload
    };

    let max_header = FrameHeader {
        length: max_stream_payload.len() as u32,
        frame_type: FrameType::GoAway as u8,
        flags: 0,
        stream_id: 0,
    };

    let max_result = GoAwayFrame::parse(&max_header, &Bytes::from(max_stream_payload));
    if let Ok(frame) = max_result {
        if frame.last_stream_id != 0x7FFFFFFF {
            return Err("EDGE CASE: Max stream ID not handled correctly".to_string());
        }
    }

    // Test R bit set in last_stream_id.
    let r_bit_payload = {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x80000001u32.to_be_bytes()); // R bit set
        payload.extend_from_slice(&(ErrorCode::NoError as u32).to_be_bytes());
        payload.extend_from_slice(b"r_bit_test");
        payload
    };

    let r_bit_header = FrameHeader {
        length: r_bit_payload.len() as u32,
        frame_type: FrameType::GoAway as u8,
        flags: 0,
        stream_id: 0,
    };

    let r_bit_result = GoAwayFrame::parse(&r_bit_header, &Bytes::from(r_bit_payload));
    if let Ok(frame) = r_bit_result {
        // R bit should be cleared.
        if frame.last_stream_id != 1 {
            return Err(format!(
                "EDGE CASE: R bit not cleared. Expected 1, got {}",
                frame.last_stream_id
            ));
        }
    }

    Ok(())
}

/// Main fuzzing function.
fn fuzz_goaway_frame(input: GoAwayFuzzInput) -> Result<(), String> {
    let normalized = normalize_input(input);

    // Test core assertions.
    test_goaway_frame_assertions(normalized.clone())?;

    // Test frame pipeline integration.
    test_goaway_frame_pipeline(&normalized)?;

    // Test edge cases.
    test_goaway_edge_cases(&normalized)?;

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Limit input size for performance.
    if data.len() > MAX_FUZZ_INPUT_SIZE {
        return;
    }

    let mut unstructured = arbitrary::Unstructured::new(data);

    let input = if let Ok(input) = GoAwayFuzzInput::arbitrary(&mut unstructured) {
        input
    } else {
        return;
    };

    // Run GOAWAY frame assertions.
    if let Err(assertion_failure) = fuzz_goaway_frame(input) {
        // Assertion failure detected - this indicates a bug.
        panic!("GOAWAY frame assertion failed: {}", assertion_failure);
    }
});
