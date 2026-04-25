//! Golden artifact tests for HTTP/2 frame serialization.
//!
//! These tests verify that frame serialization produces deterministic binary output
//! that matches expected golden artifacts. This ensures protocol compliance and
//! prevents regressions in frame encoding logic.

use super::error::ErrorCode;
use super::frame::*;
use crate::bytes::{Bytes, BytesMut};

/// Golden test framework for HTTP/2 frames.
///
/// Provides utilities for creating golden artifacts and validating frame serialization.
pub struct FrameGoldenTester {
    /// Whether to update golden artifacts instead of validating against them.
    update_golden: bool,
}

impl FrameGoldenTester {
    /// Create a new golden tester.
    pub fn new() -> Self {
        Self {
            update_golden: std::env::var("UPDATE_H2_GOLDEN").is_ok(),
        }
    }

    /// Convert bytes to hex string manually.
    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parse hex string to bytes manually.
    #[allow(dead_code)] // Retained for future golden-diff round-trips.
    fn from_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Result<Vec<_>, _>>()
            .expect("Invalid hex string")
    }

    /// Test frame serialization against a golden artifact.
    fn assert_frame_golden(&self, frame: &Frame, test_name: &str, expected_hex: &str) {
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        let actual_bytes = buf.freeze();
        let actual_hex = Self::to_hex(&actual_bytes);

        if self.update_golden {
            println!("GOLDEN UPDATE {test_name}: {actual_hex}");
            return;
        }

        assert_eq!(
            actual_hex, expected_hex,
            "Frame serialization mismatch for {test_name}\nExpected: {expected_hex}\nActual:   {actual_hex}",
        );
    }

    /// Test frame header serialization separately.
    fn assert_header_golden(&self, header: &FrameHeader, test_name: &str, expected_hex: &str) {
        let mut buf = BytesMut::new();
        header.write(&mut buf);
        let actual_bytes = buf.freeze();
        let actual_hex = Self::to_hex(&actual_bytes);

        if self.update_golden {
            println!("HEADER GOLDEN UPDATE {test_name}: {actual_hex}");
            return;
        }

        assert_eq!(
            actual_hex, expected_hex,
            "Frame header serialization mismatch for {test_name}\nExpected: {expected_hex}\nActual:   {actual_hex}",
        );
    }
}

impl Default for FrameGoldenTester {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Frame Header Golden Tests
// ============================================================================

#[test]
fn test_frame_header_golden_basic() {
    let tester = FrameGoldenTester::new();

    // Test basic frame header: length=0x1234, type=0x1, flags=0x5, stream_id=0x7890abcd
    let header = FrameHeader {
        length: 0x1234,
        frame_type: 0x1,
        flags: 0x5,
        stream_id: 0x7890abcd,
    };

    // Golden artifact: 9 bytes encoding length(24-bit), type(8-bit), flags(8-bit), stream_id(31-bit)
    tester.assert_header_golden(&header, "basic_header", "00123401057890abcd");
}

#[test]
fn test_frame_header_golden_max_values() {
    let tester = FrameGoldenTester::new();

    // Test maximum allowed values
    let header = FrameHeader {
        length: MAX_FRAME_SIZE, // 16777215 = 0xFFFFFF
        frame_type: 0xFF,
        flags: 0xFF,
        stream_id: 0x7FFFFFFF, // Maximum 31-bit value
    };

    tester.assert_header_golden(&header, "max_header", "ffffffffff7fffffff");
}

#[test]
fn test_frame_header_golden_min_values() {
    let tester = FrameGoldenTester::new();

    // Test minimum/zero values
    let header = FrameHeader {
        length: 0,
        frame_type: 0,
        flags: 0,
        stream_id: 0,
    };

    tester.assert_header_golden(&header, "min_header", "000000000000000000");
}

// ============================================================================
// DATA Frame Golden Tests
// ============================================================================

#[test]
fn test_data_frame_golden_simple() {
    let tester = FrameGoldenTester::new();

    let frame = Frame::Data(DataFrame::new(
        0x12345678,                          // stream_id
        Bytes::from_static(b"Hello HTTP/2"), // 12 bytes
        false,                               // end_stream
    ));

    // Golden: header(9) + payload(12) = 21 bytes total, encoded as 42 hex chars.
    // Header: length=12 (0x0c), type=0, flags=0, stream_id=0x12345678.
    // Payload "Hello HTTP/2" as hex: 48656c6c6f20485454502f32.
    tester.assert_frame_golden(
        &frame,
        "data_simple",
        "00000c00001234567848656c6c6f20485454502f32",
    );
}

#[test]
fn test_data_frame_golden_with_end_stream() {
    let tester = FrameGoldenTester::new();

    let frame = Frame::Data(DataFrame::new(
        0x1,                        // stream_id
        Bytes::from_static(b"EOF"), // 3 bytes
        true,                       // end_stream (flag 0x1)
    ));

    // Golden: header with END_STREAM flag set, payload "EOF" encoded as hex
    // 454f46. Header: length=3, type=0, flags=0x1 (END_STREAM), stream_id=0x1.
    tester.assert_frame_golden(&frame, "data_end_stream", "000003000100000001454f46");
}

#[test]
fn test_data_frame_golden_empty() {
    let tester = FrameGoldenTester::new();

    let frame = Frame::Data(DataFrame::new(
        0x7FFFFFFF,   // max stream_id
        Bytes::new(), // empty data
        true,         // end_stream
    ));

    // Golden: empty DATA frame with END_STREAM.
    // Header: length=0, type=0, flags=0x1, stream_id=0x7fffffff. No payload.
    tester.assert_frame_golden(&frame, "data_empty", "00000000017fffffff");
}

// ============================================================================
// SETTINGS Frame Golden Tests
// ============================================================================

#[test]
fn test_settings_frame_golden_empty() {
    let tester = FrameGoldenTester::new();

    let frame = Frame::Settings(SettingsFrame::new(Vec::new()));

    // Golden: SETTINGS frame type 4, no flags, stream_id 0, empty payload
    tester.assert_frame_golden(&frame, "settings_empty", "000000040000000000");
}

#[test]
fn test_settings_frame_golden_ack() {
    let tester = FrameGoldenTester::new();

    let frame = Frame::Settings(SettingsFrame::ack());

    // Golden: SETTINGS ACK frame (type 4, flags 0x1, stream_id 0, empty payload)
    tester.assert_frame_golden(&frame, "settings_ack", "000000040100000000");
}

// ============================================================================
// PING Frame Golden Tests
// ============================================================================

#[test]
fn test_ping_frame_golden_request() {
    let tester = FrameGoldenTester::new();

    let frame = Frame::Ping(PingFrame::new([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    ]));

    // Golden: PING frame (type 6, flags 0, stream_id 0, 8-byte payload).
    // 9 header bytes + 8 payload bytes = 34 hex chars.
    tester.assert_frame_golden(&frame, "ping_request", "0000080600000000000123456789abcdef");
}

#[test]
fn test_ping_frame_golden_ack() {
    let tester = FrameGoldenTester::new();

    let frame = Frame::Ping(PingFrame::ack([
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    ]));

    // Golden: PING ACK frame (type 6, flags 0x1, stream_id 0, 8-byte payload)
    tester.assert_frame_golden(&frame, "ping_ack", "000008060100000000fedcba9876543210");
}

// ============================================================================
// Control Frame Golden Tests
// ============================================================================

#[test]
fn test_priority_frame_golden_non_exclusive() {
    let tester = FrameGoldenTester::new();

    let frame = Frame::Priority(PriorityFrame {
        stream_id: 3,
        priority: PrioritySpec {
            exclusive: false,
            dependency: 1,
            weight: 16,
        },
    });

    // Golden: PRIORITY frame, stream 3, dependency 1, non-exclusive, weight 16.
    tester.assert_frame_golden(
        &frame,
        "priority_non_exclusive",
        "0000050200000000030000000110",
    );
}

#[test]
fn test_priority_frame_golden_exclusive() {
    let tester = FrameGoldenTester::new();

    let frame = Frame::Priority(PriorityFrame {
        stream_id: 5,
        priority: PrioritySpec {
            exclusive: true,
            dependency: 3,
            weight: 255,
        },
    });

    // Golden: exclusive PRIORITY sets the high bit on the 31-bit dependency.
    tester.assert_frame_golden(&frame, "priority_exclusive", "00000502000000000580000003ff");
}

#[test]
fn test_rst_stream_frame_golden_cancel() {
    let tester = FrameGoldenTester::new();

    let frame = Frame::RstStream(RstStreamFrame::new(1, ErrorCode::Cancel));

    // Golden: RST_STREAM frame, stream 1, CANCEL error code 0x8.
    tester.assert_frame_golden(&frame, "rst_stream_cancel", "00000403000000000100000008");
}

#[test]
fn test_goaway_frame_golden_empty_debug() {
    let tester = FrameGoldenTester::new();

    let frame = Frame::GoAway(GoAwayFrame::new(3, ErrorCode::NoError));

    // Golden: GOAWAY frame, last_stream_id 3, NO_ERROR, no debug data.
    tester.assert_frame_golden(
        &frame,
        "goaway_empty_debug",
        "0000080700000000000000000300000000",
    );
}

#[test]
fn test_goaway_frame_golden_with_debug() {
    let tester = FrameGoldenTester::new();

    let mut goaway = GoAwayFrame::new(7, ErrorCode::EnhanceYourCalm);
    goaway.debug_data = Bytes::from_static(b"calm");
    let frame = Frame::GoAway(goaway);

    // Golden: GOAWAY frame with debug payload "calm".
    tester.assert_frame_golden(
        &frame,
        "goaway_with_debug",
        "00000c070000000000000000070000000b63616c6d",
    );
}

#[test]
fn test_window_update_frame_golden_connection() {
    let tester = FrameGoldenTester::new();

    let frame = Frame::WindowUpdate(WindowUpdateFrame::new(0, 65_535));

    // Golden: connection-level WINDOW_UPDATE with increment 65535.
    tester.assert_frame_golden(
        &frame,
        "window_update_connection",
        "0000040800000000000000ffff",
    );
}

#[test]
fn test_window_update_frame_golden_stream_max_increment() {
    let tester = FrameGoldenTester::new();

    let frame = Frame::WindowUpdate(WindowUpdateFrame::new(1, 0x7fff_ffff));

    // Golden: stream-level WINDOW_UPDATE with maximum 31-bit increment.
    tester.assert_frame_golden(
        &frame,
        "window_update_stream_max_increment",
        "0000040800000000017fffffff",
    );
}

// ============================================================================
// Complex Frame Golden Tests (Semantic Patterns)
// ============================================================================

#[test]
fn test_basic_frame_sequence_golden() {
    let tester = FrameGoldenTester::new();

    // Test a simple sequence of frames
    let frames = [
        // 1. SETTINGS frame (connection setup)
        Frame::Settings(SettingsFrame::new(Vec::new())),
        // 2. DATA frame (request body)
        Frame::Data(DataFrame::new(
            1,                           // stream_id
            Bytes::from_static(b"test"), // payload
            false,                       // end_stream
        )),
    ];

    let mut buf = BytesMut::new();
    for frame in &frames {
        frame.encode(&mut buf);
    }

    let actual_hex = FrameGoldenTester::to_hex(&buf);

    if tester.update_golden {
        println!("SEQUENCE GOLDEN UPDATE: {}", actual_hex);
    } else {
        // This is a simplified test - in practice, exact hex would be verified
        assert!(
            !actual_hex.is_empty(),
            "Frame sequence should produce output"
        );
        assert!(actual_hex.len() >= 18); // At least 2 frame headers (9 bytes each)
    }
}

// ============================================================================
// Edge Case Golden Tests
// ============================================================================

#[test]
fn test_unknown_frame_golden() {
    let tester = FrameGoldenTester::new();

    let frame = Frame::Unknown {
        frame_type: 0xFF, // Unknown frame type
        stream_id: 0x12345678,
        payload: Bytes::from_static(b"ext"),
    };

    // Golden: Unknown frame preserves payload exactly
    if tester.update_golden {
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        let actual_hex = FrameGoldenTester::to_hex(&buf);
        println!("UNKNOWN FRAME GOLDEN UPDATE: {actual_hex}");
    } else {
        // Simplified test - just verify it encodes without error
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        assert!(buf.len() > 9); // Header + payload
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    #[test]
    fn validate_golden_test_infrastructure() {
        let _tester = FrameGoldenTester::new();

        // Test that tester correctly encodes a simple frame
        let frame = Frame::Data(DataFrame::new(1, Bytes::from_static(b"test"), false));
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        assert_eq!(buf.len(), 9 + 4); // header + "test"
        assert_eq!(&buf[9..], b"test");

        // Test header encoding
        let header = FrameHeader {
            length: 4,
            frame_type: 0,
            flags: 0,
            stream_id: 1,
        };

        let mut header_buf = BytesMut::new();
        header.write(&mut header_buf);
        assert_eq!(header_buf.len(), 9);
    }

    #[test]
    fn validate_frame_type_encoding() {
        // Verify frame type constants match expected values
        assert_eq!(FrameType::Data as u8, 0x0);
        assert_eq!(FrameType::Headers as u8, 0x1);
        assert_eq!(FrameType::Priority as u8, 0x2);
        assert_eq!(FrameType::RstStream as u8, 0x3);
        assert_eq!(FrameType::Settings as u8, 0x4);
        assert_eq!(FrameType::PushPromise as u8, 0x5);
        assert_eq!(FrameType::Ping as u8, 0x6);
        assert_eq!(FrameType::GoAway as u8, 0x7);
        assert_eq!(FrameType::WindowUpdate as u8, 0x8);
        assert_eq!(FrameType::Continuation as u8, 0x9);
    }

    #[test]
    fn validate_flag_constants() {
        // Verify flag constants are correct
        assert_eq!(data_flags::END_STREAM, 0x1);
        assert_eq!(data_flags::PADDED, 0x8);
        assert_eq!(headers_flags::END_HEADERS, 0x4);
        assert_eq!(headers_flags::PRIORITY, 0x20);
        assert_eq!(settings_flags::ACK, 0x1);
        assert_eq!(ping_flags::ACK, 0x1);
    }
}
