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

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::Header;
use asupersync::http::h2::connection::Connection;
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{Frame, FrameHeader, FrameType, RstStreamFrame, SettingsFrame};
use asupersync::http::h2::settings::Settings;

/// Maximum reasonable frame payload size for testing.
const MAX_PAYLOAD_SIZE: usize = 65536;

/// RST_STREAM fuzzing input structure.
#[derive(Arbitrary, Debug, Clone)]
struct RstStreamFuzzInput {
    /// Stream ID to send RST_STREAM on.
    stream_id: u32,
    /// Error code to include in RST_STREAM.
    error_code: u32,
    /// Frame payload length (should be 4, but test other values).
    payload_length: u32,
    /// Additional padding bytes (for malformed frames).
    extra_payload: Vec<u8>,
    /// Multiple RST_STREAM sequence for idempotency testing.
    multiple_rst_sequence: Vec<u32>,
}

/// Build a RST_STREAM frame from fuzzing input.
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

fn payload_slice(frame: &BytesMut, start: usize, len: usize) -> Bytes {
    Bytes::copy_from_slice(&frame[start..start + len])
}

fn payload_prefix(frame: &BytesMut, len: usize) -> Bytes {
    Bytes::copy_from_slice(&frame[..len])
}

fn open_client_connection() -> Connection {
    let mut connection = Connection::client(Settings::client());
    let settings = Frame::Settings(SettingsFrame::new(Vec::new()));
    connection
        .process_frame(settings)
        .expect("initial SETTINGS must open connection");
    connection
}

fn open_client_stream(connection: &mut Connection) -> u32 {
    let headers = vec![
        Header::new(":method", "GET"),
        Header::new(":scheme", "https"),
        Header::new(":path", "/"),
        Header::new(":authority", "example.test"),
    ];
    let stream_id = connection
        .open_stream(headers, false)
        .expect("client stream should open");

    while connection.next_frame().is_some() {}

    stream_id
}

fn assert_stream_closed(connection: &Connection, stream_id: u32) {
    let stream = connection
        .stream(stream_id)
        .expect("reset stream should remain tracked");
    assert!(
        stream.state().is_closed(),
        "RST_STREAM should close stream {stream_id}, got {:?}",
        stream.state()
    );
}

fn assert_live_connection_rst_behavior(input: &RstStreamFuzzInput) {
    let error_code = ErrorCode::from_u32(input.error_code);

    // RFC 7540 §6.4: RST_STREAM frames MUST be associated with a stream.
    let mut zero_stream = open_client_connection();
    let zero_err = zero_stream
        .process_frame(Frame::RstStream(RstStreamFrame::new(0, error_code)))
        .expect_err("RST_STREAM on stream 0 must be rejected by the live state machine");
    assert_eq!(zero_err.code, ErrorCode::ProtocolError);
    assert!(
        zero_err.stream_id.is_none(),
        "stream-0 RST_STREAM must be a connection error"
    );

    // RFC 7540 §5.1: RST_STREAM received on an idle stream is a connection error.
    let mut idle_stream = open_client_connection();
    let idle_err = idle_stream
        .process_frame(Frame::RstStream(RstStreamFrame::new(2, error_code)))
        .expect_err("RST_STREAM on an idle peer stream must be rejected");
    assert_eq!(idle_err.code, ErrorCode::ProtocolError);
    assert!(
        idle_err.stream_id.is_none(),
        "idle-stream RST_STREAM must be a connection error"
    );

    // RST_STREAM on a known open stream should be delivered once and close it.
    let mut open_stream = open_client_connection();
    let stream_id = open_client_stream(&mut open_stream);
    let received = open_stream
        .process_frame(Frame::RstStream(RstStreamFrame::new(stream_id, error_code)))
        .expect("RST_STREAM on an open stream should be accepted")
        .expect("RST_STREAM should surface a reset event");
    match received {
        asupersync::http::h2::connection::ReceivedFrame::Reset {
            stream_id: received_stream_id,
            error_code: received_error_code,
        } => {
            assert_eq!(received_stream_id, stream_id);
            assert_eq!(received_error_code, error_code);
        }
        other => panic!("expected Reset event, got {other:?}"),
    }
    assert_stream_closed(&open_stream, stream_id);

    // Repeated RST_STREAM on the same tracked stream must remain clean and terminal.
    for &additional_error_code in &input.multiple_rst_sequence {
        let additional = ErrorCode::from_u32(additional_error_code);
        let received = open_stream
            .process_frame(Frame::RstStream(RstStreamFrame::new(stream_id, additional)))
            .expect("repeated RST_STREAM on a tracked stream should not panic")
            .expect("repeated RST_STREAM should still surface a reset event");
        match received {
            asupersync::http::h2::connection::ReceivedFrame::Reset {
                stream_id: received_stream_id,
                error_code: received_error_code,
            } => {
                assert_eq!(received_stream_id, stream_id);
                assert_eq!(received_error_code, additional);
            }
            other => panic!("expected repeated Reset event, got {other:?}"),
        }
        assert_stream_closed(&open_stream, stream_id);
    }
}

fuzz_target!(|input: RstStreamFuzzInput| {
    // Limit input sizes to reasonable bounds
    if input.extra_payload.len() > MAX_PAYLOAD_SIZE {
        return;
    }
    if input.multiple_rst_sequence.len() > 20 {
        return;
    }

    // Build frame bytes
    let frame_bytes = build_rst_stream_frame(&input);

    assert_live_connection_rst_behavior(&input);

    // ASSERTION 1: Frame length must be exactly 4 bytes
    // RFC 7540 §6.4: RST_STREAM frames MUST be associated with a stream and MUST have a length of 4
    if let Ok(header) = FrameHeader::parse(&mut frame_bytes.clone()) {
        let payload_len = (frame_bytes.len() - 9).min(header.length as usize);
        let payload = payload_slice(&frame_bytes, 9, payload_len);
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
                    err.code,
                    ErrorCode::FrameSizeError,
                    "Incorrect frame length should cause FrameSizeError, got: {:?}",
                    err
                );
            }
        } else {
            // Correct length should not fail due to frame size (might fail for other reasons)
            if result.is_err() {
                let err = result.unwrap_err();
                assert_ne!(
                    err.code,
                    ErrorCode::FrameSizeError,
                    "Correct frame length should not cause FrameSizeError"
                );
            }
        }
    }

    // ASSERTION 2: Error code enum validation
    // RFC 7540 §7: Unknown error codes should be treated as INTERNAL_ERROR
    if let Ok(header) = FrameHeader::parse(&mut frame_bytes.clone())
        && header.length == 4
        && header.stream_id != 0
    {
        let payload_len = (frame_bytes.len() - 9).min(4);
        let payload = payload_slice(&frame_bytes, 9, payload_len);

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
                    parsed_frame.error_code,
                    ErrorCode::InternalError,
                    "Unknown error code 0x{:x} should map to InternalError",
                    input.error_code
                );
            }
        }
    }

    // ASSERTION 3: RST_STREAM on Stream ID 0 protocol error
    // RFC 7540 §6.4: RST_STREAM frames MUST be associated with a stream (stream ID != 0)
    if input.stream_id == 0
        && let Ok(header) = FrameHeader::parse(&mut frame_bytes.clone())
    {
        let payload_len = (frame_bytes.len() - 9).min(header.length as usize);
        let payload = payload_slice(&frame_bytes, 9, payload_len);
        let result = RstStreamFrame::parse(&header, &payload);

        // Should fail with protocol error for stream ID 0
        assert!(
            result.is_err(),
            "RST_STREAM on stream ID 0 should be rejected (RFC 7540 §6.4)"
        );

        if let Err(err) = result {
            assert_eq!(
                err.code,
                ErrorCode::ProtocolError,
                "RST_STREAM on stream ID 0 should cause ProtocolError, got: {:?}",
                err
            );
        }
    }

    // General robustness: Frame parsing should never panic
    let mut parse_frame_bytes = frame_bytes.clone();
    if let Ok(header) = FrameHeader::parse(&mut parse_frame_bytes) {
        let remaining_len = parse_frame_bytes.len().min(header.length as usize);
        if remaining_len > 0 {
            let payload = payload_prefix(&parse_frame_bytes, remaining_len);
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
            assert!(result.is_err(), "Empty RST_STREAM frame should be rejected");

            if let Err(err) = result {
                assert_eq!(
                    err.code,
                    ErrorCode::FrameSizeError,
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
            let payload = payload_prefix(&parse_oversized, payload_len);
            let result = RstStreamFrame::parse(&header, &payload);

            // Oversized RST_STREAM should be rejected
            if header.length != 4 {
                assert!(
                    result.is_err(),
                    "Oversized RST_STREAM frame (length {}) should be rejected",
                    header.length
                );

                if let Err(err) = result {
                    assert_eq!(
                        err.code,
                        ErrorCode::FrameSizeError,
                        "Oversized RST_STREAM should cause FrameSizeError"
                    );
                }
            }
        }
    }

    // Test all known error codes for completeness
    if input.stream_id > 0 {
        let known_error_codes = [
            0x0, // NoError
            0x1, // ProtocolError
            0x2, // InternalError
            0x3, // FlowControlError
            0x4, // SettingsTimeout
            0x5, // StreamClosed
            0x6, // FrameSizeError
            0x7, // RefusedStream
            0x8, // Cancel
            0x9, // CompressionError
            0xa, // ConnectError
            0xb, // EnhanceYourCalm
            0xc, // InadequateSecurity
            0xd, // Http11Required
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
                        "Known error code 0x{:x} should parse successfully",
                        known_code
                    );

                    if let Ok(parsed) = result {
                        assert_eq!(
                            u32::from(parsed.error_code),
                            known_code,
                            "Parsed error code should match input"
                        );
                    }
                }
            }
        }
    }
});
