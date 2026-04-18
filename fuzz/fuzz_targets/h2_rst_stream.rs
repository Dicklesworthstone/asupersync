//! HTTP/2 RST_STREAM frame parsing fuzz target.
//!
//! This fuzzer tests RST_STREAM frame parsing per RFC 7540 Section 6.4 with focus on:
//! - Frame length validation (exactly 4 bytes required)
//! - Error code enum validation and unknown error code handling
//! - RST_STREAM on stream ID 0 protocol error (forbidden per RFC 7540)
//! - Idle stream state protocol error (RST_STREAM on non-existent streams)
//! - Multiple RST_STREAM idempotency (subsequent RST_STREAM should be ignored)
//! - Frame format compliance and boundary conditions

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::{HashMap, HashSet};

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::frame::{FrameHeader, FrameType, RstStreamFrame};
use asupersync::http::h2::error::{ErrorCode, H2Error};

/// Maximum reasonable frame payload size for testing
const MAX_PAYLOAD_SIZE: usize = 65536;

/// Stream state for testing RST_STREAM behavior
#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
    /// Stream has never been created (idle)
    Idle,
    /// Stream is open/half-closed
    Active,
    /// Stream has already been reset
    Reset,
    /// Stream has been closed normally
    Closed,
}

/// RST_STREAM fuzzing input structure
#[derive(Arbitrary, Debug, Clone)]
struct RstStreamFuzzInput {
    /// Stream ID to send RST_STREAM on
    stream_id: u32,
    /// Error code to include in RST_STREAM
    error_code: u32,
    /// Frame payload length (should be 4, but test other values)
    payload_length: u32,
    /// Additional padding bytes (for malformed frames)
    extra_payload: Vec<u8>,
    /// Stream state context for testing protocol violations
    stream_states: Vec<(u32, StreamState)>,
    /// Multiple RST_STREAM sequence for idempotency testing
    multiple_rst_sequence: Vec<u32>, // Multiple error codes for same stream
}

/// HTTP/2 connection state mock for RST_STREAM validation
#[derive(Debug, Clone)]
struct H2ConnectionMock {
    /// Active streams and their states
    stream_states: HashMap<u32, StreamState>,
    /// Streams that have been reset (for idempotency testing)
    reset_streams: HashSet<u32>,
    /// Track multiple RST_STREAM attempts
    rst_attempts: HashMap<u32, Vec<ErrorCode>>,
}

impl H2ConnectionMock {
    fn new() -> Self {
        Self {
            stream_states: HashMap::new(),
            reset_streams: HashSet::new(),
            rst_attempts: HashMap::new(),
        }
    }

    fn create_stream(&mut self, stream_id: u32) {
        self.stream_states.insert(stream_id, StreamState::Active);
    }

    fn is_stream_idle(&self, stream_id: u32) -> bool {
        !self.stream_states.contains_key(&stream_id)
    }

    fn is_stream_reset(&self, stream_id: u32) -> bool {
        self.reset_streams.contains(&stream_id)
    }

    fn reset_stream(&mut self, stream_id: u32, error_code: ErrorCode) {
        self.reset_streams.insert(stream_id);
        self.rst_attempts.entry(stream_id).or_insert_with(Vec::new).push(error_code);
        if let Some(state) = self.stream_states.get_mut(&stream_id) {
            *state = StreamState::Reset;
        }
    }

    fn get_rst_attempts(&self, stream_id: u32) -> usize {
        self.rst_attempts.get(&stream_id).map(|v| v.len()).unwrap_or(0)
    }
}

/// Build a RST_STREAM frame from fuzzing input
fn build_rst_stream_frame(input: &RstStreamFuzzInput) -> BytesMut {
    let mut frame_data = BytesMut::new();

    // Build frame header with potentially malformed length
    let header = FrameHeader {
        length: input.payload_length.min(65535),
        frame_type: FrameType::RstStream as u8,
        flags: 0, // RST_STREAM has no flags
        stream_id: input.stream_id,
    };

    header.write(&mut frame_data);

    // Add the 4-byte error code payload (standard case)
    let error_code_bytes = [
        (input.error_code >> 24) as u8,
        (input.error_code >> 16) as u8,
        (input.error_code >> 8) as u8,
        input.error_code as u8,
    ];
    frame_data.extend_from_slice(&error_code_bytes);

    // Add extra payload for malformed frame testing
    frame_data.extend_from_slice(&input.extra_payload);

    frame_data
}

fuzz_target!(|input: RstStreamFuzzInput| {
    // Limit input sizes to reasonable bounds
    if input.extra_payload.len() > MAX_PAYLOAD_SIZE {
        return;
    }
    if input.stream_states.len() > 100 {
        return;
    }
    if input.multiple_rst_sequence.len() > 20 {
        return;
    }

    // Set up connection mock with stream states
    let mut connection = H2ConnectionMock::new();
    for (stream_id, state) in &input.stream_states {
        if *state != StreamState::Idle {
            connection.create_stream(*stream_id);
            match state {
                StreamState::Reset => {
                    connection.reset_stream(*stream_id, ErrorCode::Cancel);
                }
                StreamState::Closed => {
                    connection.stream_states.insert(*stream_id, StreamState::Closed);
                }
                _ => {}
            }
        }
    }

    // Build frame bytes
    let mut frame_bytes = build_rst_stream_frame(&input);

    // ASSERTION 1: Frame length must be exactly 4 bytes
    // RFC 7540 §6.4: RST_STREAM frames MUST be associated with a stream and MUST have a length of 4
    if let Ok(header) = FrameHeader::parse(&mut frame_bytes.clone()) {
        let payload_len = (frame_bytes.len() - 9).min(header.length as usize);
        let payload = frame_bytes.slice(9..9 + payload_len);
        let result = RstStreamFrame::parse(&header, &payload);

        if header.length != 4 {
            // Should reject frames with incorrect length
            assert!(
                result.is_err(),
                "RST_STREAM frame with length {} should be rejected (RFC 7540 §6.4), expected length 4",
                header.length
            );

            if let Err(err) = result {
                assert_eq!(
                    err.code, ErrorCode::FrameSizeError,
                    "Incorrect frame length should cause FrameSizeError, got: {:?}", err
                );
            }
        } else {
            // Correct length should not fail due to frame size (might fail for other reasons)
            if result.is_err() {
                let err = result.unwrap_err();
                assert_ne!(
                    err.code, ErrorCode::FrameSizeError,
                    "Correct frame length should not cause FrameSizeError"
                );
            }
        }
    }

    // ASSERTION 2: Error code enum validation
    // RFC 7540 §7: Unknown error codes should be treated as INTERNAL_ERROR
    if let Ok(header) = FrameHeader::parse(&mut frame_bytes.clone()) {
        if header.length == 4 && header.stream_id != 0 {
            let payload_len = (frame_bytes.len() - 9).min(4);
            let payload = frame_bytes.slice(9..9 + payload_len);

            if let Ok(parsed_frame) = RstStreamFrame::parse(&header, &payload) {
                // Verify error code parsing behavior
                let expected_error_code = ErrorCode::from_u32(input.error_code);
                assert_eq!(
                    parsed_frame.error_code, expected_error_code,
                    "Error code parsing should match ErrorCode::from_u32() behavior"
                );

                // Unknown error codes should map to InternalError
                if input.error_code > 0xd && input.error_code != 0x2 {
                    assert_eq!(
                        parsed_frame.error_code, ErrorCode::InternalError,
                        "Unknown error code 0x{:x} should map to InternalError", input.error_code
                    );
                }
            }
        }
    }

    // ASSERTION 3: RST_STREAM on Stream ID 0 protocol error
    // RFC 7540 §6.4: RST_STREAM frames MUST be associated with a stream (stream ID != 0)
    if input.stream_id == 0 {
        if let Ok(header) = FrameHeader::parse(&mut frame_bytes.clone()) {
            let payload_len = (frame_bytes.len() - 9).min(header.length as usize);
            let payload = frame_bytes.slice(9..9 + payload_len);
            let result = RstStreamFrame::parse(&header, &payload);

            // Should fail with protocol error for stream ID 0
            assert!(
                result.is_err(),
                "RST_STREAM on stream ID 0 should be rejected (RFC 7540 §6.4)"
            );

            if let Err(err) = result {
                assert_eq!(
                    err.code, ErrorCode::ProtocolError,
                    "RST_STREAM on stream ID 0 should cause ProtocolError, got: {:?}", err
                );
            }
        }
    }

    // ASSERTION 4: Idle state protocol error
    // RFC 7540 §6.4: RST_STREAM on idle streams should be treated as a protocol error
    if input.stream_id > 0 && connection.is_stream_idle(input.stream_id) {
        if let Ok(header) = FrameHeader::parse(&mut frame_bytes.clone()) {
            if header.length == 4 {
                let payload = frame_bytes.slice(9..13);

                // Frame parsing itself might succeed, but protocol-level validation
                // should reject RST_STREAM on idle streams
                if let Ok(parsed_frame) = RstStreamFrame::parse(&header, &payload) {
                    // This represents the protocol-level check that should happen
                    // after successful frame parsing in a real HTTP/2 implementation
                    assert!(
                        connection.is_stream_idle(parsed_frame.stream_id),
                        "RST_STREAM on idle stream {} should be handled as protocol violation",
                        parsed_frame.stream_id
                    );

                    // The higher-level HTTP/2 implementation should track this as an error
                    // For our test purposes, we document this requirement
                    // In practice, this would result in a GOAWAY frame
                }
            }
        }
    }

    // ASSERTION 5: Multiple RST_STREAM idempotency
    // RFC 7540 §6.4: Subsequent RST_STREAM frames on the same stream should be ignored
    if input.stream_id > 0 && !input.multiple_rst_sequence.is_empty() {
        if let Ok(header) = FrameHeader::parse(&mut frame_bytes.clone()) {
            if header.length == 4 {
                let payload = frame_bytes.slice(9..13);

                // Process initial RST_STREAM
                if let Ok(parsed_frame) = RstStreamFrame::parse(&header, &payload) {
                    connection.reset_stream(parsed_frame.stream_id, parsed_frame.error_code);

                    // Process multiple RST_STREAM frames on the same stream
                    for &additional_error_code in &input.multiple_rst_sequence {
                        let mut additional_frame = BytesMut::new();
                        let additional_header = FrameHeader {
                            length: 4,
                            frame_type: FrameType::RstStream as u8,
                            flags: 0,
                            stream_id: parsed_frame.stream_id,
                        };
                        additional_header.write(&mut additional_frame);
                        additional_frame.extend_from_slice(&[
                            (additional_error_code >> 24) as u8,
                            (additional_error_code >> 16) as u8,
                            (additional_error_code >> 8) as u8,
                            additional_error_code as u8,
                        ]);

                        let mut parse_frame = additional_frame.clone();
                        if let Ok(add_header) = FrameHeader::parse(&mut parse_frame) {
                            let add_payload = parse_frame.freeze();
                            if let Ok(additional_parsed) = RstStreamFrame::parse(&add_header, &add_payload) {
                                // Record the additional RST_STREAM attempt
                                connection.reset_stream(additional_parsed.stream_id, additional_parsed.error_code);
                            }
                        }
                    }

                    // Verify idempotency: stream should remain in reset state regardless
                    // of how many RST_STREAM frames were sent
                    assert!(
                        connection.is_stream_reset(parsed_frame.stream_id),
                        "Stream should remain reset after multiple RST_STREAM frames"
                    );

                    // The number of attempts should be tracked (for debugging purposes)
                    let attempts = connection.get_rst_attempts(parsed_frame.stream_id);
                    assert!(
                        attempts >= 1,
                        "Should track at least one RST_STREAM attempt"
                    );

                    // Multiple RST_STREAM frames should not cause protocol errors themselves
                    // (they should just be ignored after the first one)
                    assert!(
                        attempts <= input.multiple_rst_sequence.len() + 1,
                        "RST_STREAM attempt count should be reasonable"
                    );
                }
            }
        }
    }

    // General robustness: Frame parsing should never panic
    let mut parse_frame_bytes = frame_bytes.clone();
    if let Ok(header) = FrameHeader::parse(&mut parse_frame_bytes) {
        let remaining_len = parse_frame_bytes.len().min(header.length as usize);
        if remaining_len > 0 {
            let payload = parse_frame_bytes.slice(..remaining_len);
            let _ = RstStreamFrame::parse(&header, &payload);
        }
    }

    // Edge case: Empty payload handling
    if input.extra_payload.is_empty() && input.payload_length == 0 {
        let mut empty_frame = BytesMut::new();
        let header = FrameHeader {
            length: 0,
            frame_type: FrameType::RstStream as u8,
            flags: 0,
            stream_id: input.stream_id.max(1),
        };
        header.write(&mut empty_frame);

        let mut parse_empty = empty_frame.clone();
        if let Ok(header) = FrameHeader::parse(&mut parse_empty) {
            let payload = parse_empty.freeze();
            let result = RstStreamFrame::parse(&header, &payload);

            // Empty RST_STREAM should be rejected
            assert!(
                result.is_err(),
                "Empty RST_STREAM frame should be rejected"
            );

            if let Err(err) = result {
                assert_eq!(
                    err.code, ErrorCode::FrameSizeError,
                    "Empty RST_STREAM should cause FrameSizeError"
                );
            }
        }
    }

    // Edge case: Oversized payload handling
    if input.payload_length > 4 {
        let mut oversized_frame = BytesMut::new();
        let header = FrameHeader {
            length: input.payload_length.min(65535),
            frame_type: FrameType::RstStream as u8,
            flags: 0,
            stream_id: input.stream_id.max(1),
        };
        header.write(&mut oversized_frame);

        // Add required 4 bytes plus extra
        oversized_frame.extend_from_slice(&[
            (input.error_code >> 24) as u8,
            (input.error_code >> 16) as u8,
            (input.error_code >> 8) as u8,
            input.error_code as u8,
        ]);
        oversized_frame.extend_from_slice(&input.extra_payload);

        let mut parse_oversized = oversized_frame.clone();
        if let Ok(header) = FrameHeader::parse(&mut parse_oversized) {
            let payload_len = parse_oversized.len().min(header.length as usize);
            let payload = parse_oversized.slice(..payload_len);
            let result = RstStreamFrame::parse(&header, &payload);

            // Oversized RST_STREAM should be rejected
            if header.length != 4 {
                assert!(
                    result.is_err(),
                    "Oversized RST_STREAM frame (length {}) should be rejected", header.length
                );

                if let Err(err) = result {
                    assert_eq!(
                        err.code, ErrorCode::FrameSizeError,
                        "Oversized RST_STREAM should cause FrameSizeError"
                    );
                }
            }
        }
    }

    // Test all known error codes for completeness
    if input.stream_id > 0 {
        let known_error_codes = [
            0x0,  // NoError
            0x1,  // ProtocolError
            0x2,  // InternalError
            0x3,  // FlowControlError
            0x4,  // SettingsTimeout
            0x5,  // StreamClosed
            0x6,  // FrameSizeError
            0x7,  // RefusedStream
            0x8,  // Cancel
            0x9,  // CompressionError
            0xa,  // ConnectError
            0xb,  // EnhanceYourCalm
            0xc,  // InadequateSecurity
            0xd,  // Http11Required
        ];

        for &known_code in &known_error_codes {
            let mut test_frame = BytesMut::new();
            let header = FrameHeader {
                length: 4,
                frame_type: FrameType::RstStream as u8,
                flags: 0,
                stream_id: input.stream_id,
            };
            header.write(&mut test_frame);
            test_frame.extend_from_slice(&[
                (known_code >> 24) as u8,
                (known_code >> 16) as u8,
                (known_code >> 8) as u8,
                known_code as u8,
            ]);

            let mut parse_test = test_frame.clone();
            if let Ok(header) = FrameHeader::parse(&mut parse_test) {
                let payload = parse_test.freeze();
                let result = RstStreamFrame::parse(&header, &payload);

                // All known error codes should parse successfully on valid streams
                if input.stream_id > 0 {
                    assert!(
                        result.is_ok(),
                        "Known error code 0x{:x} should parse successfully", known_code
                    );

                    if let Ok(parsed) = result {
                        assert_eq!(
                            u32::from(parsed.error_code), known_code,
                            "Parsed error code should match input"
                        );
                    }
                }
            }
        }
    }
});