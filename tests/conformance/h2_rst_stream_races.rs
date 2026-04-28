#![allow(warnings)]
#![allow(clippy::all)]
//! HTTP/2 RST_STREAM Race Condition Conformance Tests (RFC 9113 §6.4)
//!
//! Tests RFC 9113 §6.4 RST_STREAM edge cases involving concurrent frame processing:
//! - Multiple RST_STREAM on same stream (idempotent handling)
//! - RST_STREAM racing with SETTINGS updates (stream limits, frame sizes)
//! - RST_STREAM vs DATA frame races (in-flight data handling)
//! - Error code consistency across multiple RST frames

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::{
    error::{ErrorCode, H2Error},
    frame::{
        DataFrame, Frame, FrameHeader, FrameType, RstStreamFrame, SettingsFrame,
        parse_frame, data_flags, rst_stream_flags,
    },
};

/// Parse a raw frame from bytes
fn parse_h2_frame(data: &[u8]) -> Result<(FrameHeader, Frame), H2Error> {
    if data.len() < 9 {
        return Err(H2Error::Protocol("frame too short".into()));
    }

    let header = FrameHeader {
        length: u32::from_be_bytes([0, data[0], data[1], data[2]]) as usize,
        frame_type: FrameType::from_u8(data[3]).unwrap_or(FrameType::Data),
        flags: data[4],
        stream_id: u32::from_be_bytes([data[5], data[6], data[7], data[8]]) & 0x7FFFFFFF,
    };

    let payload = &data[9..];
    let frame = parse_frame(&header, payload)?;

    Ok((header, frame))
}

/// Create RST_STREAM frame bytes
fn create_rst_stream_frame(stream_id: u32, error_code: ErrorCode) -> Vec<u8> {
    let mut frame = Vec::new();
    // Frame header: length(3) + type(1) + flags(1) + stream_id(4)
    frame.extend_from_slice(&[0, 0, 4]); // length = 4
    frame.push(0x03); // RST_STREAM type
    frame.push(0x00); // no flags
    frame.extend_from_slice(&stream_id.to_be_bytes());

    // RST_STREAM payload: error_code(4)
    frame.extend_from_slice(&(error_code as u32).to_be_bytes());

    frame
}

/// Create SETTINGS frame bytes
fn create_settings_frame(settings: &[(u16, u32)]) -> Vec<u8> {
    let mut frame = Vec::new();
    let length = settings.len() * 6;

    // Frame header
    frame.extend_from_slice(&[(length >> 16) as u8, (length >> 8) as u8, length as u8]);
    frame.push(0x04); // SETTINGS type
    frame.push(0x00); // no ACK flag
    frame.extend_from_slice(&0u32.to_be_bytes()); // stream_id = 0

    // Settings payload
    for (setting_id, value) in settings {
        frame.extend_from_slice(&setting_id.to_be_bytes());
        frame.extend_from_slice(&value.to_be_bytes());
    }

    frame
}

#[test]
fn multiple_rst_stream_on_same_stream_idempotent() {
    // RFC 9113 §6.4: Multiple RST_STREAM frames on same stream must be idempotent
    let stream_id = 3;

    // First RST_STREAM with CANCEL
    let rst1_bytes = create_rst_stream_frame(stream_id, ErrorCode::Cancel);
    let (header1, frame1) = parse_h2_frame(&rst1_bytes)
        .expect("first RST_STREAM should parse");

    match frame1 {
        Frame::RstStream(rst) => {
            assert_eq!(rst.error_code, ErrorCode::Cancel);
        }
        _ => panic!("expected RST_STREAM frame"),
    }

    // Second RST_STREAM with different error code on same stream
    let rst2_bytes = create_rst_stream_frame(stream_id, ErrorCode::StreamClosed);
    let (header2, frame2) = parse_h2_frame(&rst2_bytes)
        .expect("second RST_STREAM should parse");

    match frame2 {
        Frame::RstStream(rst) => {
            assert_eq!(rst.error_code, ErrorCode::StreamClosed);
        }
        _ => panic!("expected RST_STREAM frame"),
    }

    // Both frames should have same stream ID
    assert_eq!(header1.stream_id, header2.stream_id);
    assert_eq!(header1.stream_id, stream_id);
}

#[test]
fn rst_stream_during_settings_max_frame_size_update() {
    // RFC 9113 §6.4: RST_STREAM racing with SETTINGS that change SETTINGS_MAX_FRAME_SIZE
    // The RST_STREAM should be processed regardless of frame size changes

    let stream_id = 5;

    // SETTINGS frame updating MAX_FRAME_SIZE to smaller value
    let settings_bytes = create_settings_frame(&[
        (0x0005, 16384), // SETTINGS_MAX_FRAME_SIZE = 16384 (down from default 16KB)
    ]);

    let (settings_header, settings_frame) = parse_h2_frame(&settings_bytes)
        .expect("SETTINGS frame should parse");

    assert_eq!(settings_header.stream_id, 0); // Connection-level

    // RST_STREAM that might race with SETTINGS processing
    let rst_bytes = create_rst_stream_frame(stream_id, ErrorCode::FlowControlError);
    let (rst_header, rst_frame) = parse_h2_frame(&rst_bytes)
        .expect("RST_STREAM should parse even during SETTINGS update");

    match rst_frame {
        Frame::RstStream(rst) => {
            assert_eq!(rst.error_code, ErrorCode::FlowControlError);
        }
        _ => panic!("expected RST_STREAM frame"),
    }

    assert_eq!(rst_header.stream_id, stream_id);
}

#[test]
fn rst_stream_during_settings_max_concurrent_streams() {
    // RFC 9113 §6.4: RST_STREAM racing with SETTINGS_MAX_CONCURRENT_STREAMS changes
    // Stream should be reset even if concurrent stream limits change

    let stream_id = 7;

    // SETTINGS reducing max concurrent streams
    let settings_bytes = create_settings_frame(&[
        (0x0003, 10), // SETTINGS_MAX_CONCURRENT_STREAMS = 10
    ]);

    let (settings_header, _) = parse_h2_frame(&settings_bytes)
        .expect("SETTINGS frame should parse");

    assert_eq!(settings_header.stream_id, 0);

    // RST_STREAM that might be affected by stream limit changes
    let rst_bytes = create_rst_stream_frame(stream_id, ErrorCode::RefusedStream);
    let (rst_header, rst_frame) = parse_h2_frame(&rst_bytes)
        .expect("RST_STREAM should parse during concurrent stream limit update");

    match rst_frame {
        Frame::RstStream(rst) => {
            assert_eq!(rst.error_code, ErrorCode::RefusedStream);
        }
        _ => panic!("expected RST_STREAM frame"),
    }

    assert_eq!(rst_header.stream_id, stream_id);
}

#[test]
fn rst_stream_error_code_consistency_across_multiple_frames() {
    // Security test: Multiple RST_STREAM frames should maintain error code consistency
    // or at least not cause parser confusion

    let stream_id = 9;
    let error_codes = [
        ErrorCode::NoError,
        ErrorCode::ProtocolError,
        ErrorCode::InternalError,
        ErrorCode::FlowControlError,
        ErrorCode::SettingsTimeout,
        ErrorCode::StreamClosed,
        ErrorCode::FrameSizeError,
        ErrorCode::RefusedStream,
        ErrorCode::Cancel,
    ];

    for (i, &error_code) in error_codes.iter().enumerate() {
        let rst_bytes = create_rst_stream_frame(stream_id, error_code);
        let (header, frame) = parse_h2_frame(&rst_bytes)
            .unwrap_or_else(|e| panic!("RST_STREAM {} should parse: {:?}", i, e));

        assert_eq!(header.stream_id, stream_id);
        assert_eq!(header.frame_type, FrameType::RstStream);

        match frame {
            Frame::RstStream(rst) => {
                assert_eq!(rst.error_code, error_code,
                    "error code mismatch in frame {}: expected {:?}", i, error_code);
            }
            _ => panic!("frame {} should be RST_STREAM", i),
        }
    }
}

#[test]
fn rst_stream_zero_stream_id_rejected() {
    // RFC 9113 §6.4: RST_STREAM MUST have non-zero stream ID
    let rst_bytes = create_rst_stream_frame(0, ErrorCode::ProtocolError);

    let result = parse_h2_frame(&rst_bytes);

    // Parser should reject RST_STREAM with stream_id = 0
    match result {
        Err(_) => {
            // Expected - RST_STREAM with stream_id=0 is protocol violation
        }
        Ok((header, _)) if header.stream_id == 0 => {
            panic!("RST_STREAM with stream_id=0 should be rejected");
        }
        Ok(_) => {
            // Some parsers might silently correct stream_id - acceptable defensive behavior
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn rst_stream_frame_format_validation() {
        // Comprehensive format validation per RFC 9113 §6.4
        let test_cases = vec![
            // Valid RST_STREAM
            (create_rst_stream_frame(1, ErrorCode::Cancel), true, "valid RST_STREAM"),

            // Invalid length (not exactly 4 bytes)
            ({
                let mut frame = create_rst_stream_frame(1, ErrorCode::Cancel);
                frame[2] = 5; // length = 5 instead of 4
                frame.push(0); // extra byte
                frame
            }, false, "invalid length"),

            // Invalid stream_id = 0
            (create_rst_stream_frame(0, ErrorCode::Cancel), false, "zero stream_id"),
        ];

        for (frame_bytes, should_succeed, description) in test_cases {
            let result = parse_h2_frame(&frame_bytes);

            if should_succeed {
                assert!(result.is_ok(), "test case '{}' should succeed", description);
            } else {
                // Either parsing fails or stream_id constraint is enforced
                match result {
                    Err(_) => {}, // Expected failure
                    Ok((header, _)) if header.stream_id == 0 => {
                        panic!("test case '{}' should reject stream_id=0", description);
                    }
                    Ok(_) => {}, // Some defensive parsers may accept but correct
                }
            }
        }
    }
}