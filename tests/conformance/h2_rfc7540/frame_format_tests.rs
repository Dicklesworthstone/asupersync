#![allow(warnings)]
#![allow(clippy::all)]
//! Frame format conformance tests.
//!
//! Tests frame format requirements from RFC 7540 Section 4.

use super::*;
use asupersync::bytes::BytesMut;
use asupersync::http::h2::frame::{FRAME_HEADER_SIZE, FrameHeader, FrameType, MAX_FRAME_SIZE};

/// Run all frame format conformance tests.
#[allow(dead_code)]
pub fn run_frame_format_tests() -> Vec<H2ConformanceResult> {
    let mut results = Vec::new();

    results.push(test_frame_header_size());
    results.push(test_frame_length_limits());
    results.push(test_frame_type_validation());
    results.push(test_stream_id_reserved_bit());
    results.push(test_frame_header_encoding());
    results.push(test_unknown_frame_types());
    results.push(test_frame_size_validation());
    results.push(test_frame_flags_validation());

    results
}

/// RFC 7540 Section 4.1: Frame header MUST be 9 octets.
#[allow(dead_code)]
fn test_frame_header_size() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Frame header must be exactly 9 bytes
        if FRAME_HEADER_SIZE != 9 {
            return Err(format!(
                "Frame header size is {} bytes, must be 9",
                FRAME_HEADER_SIZE
            ));
        }

        // Test parsing with insufficient bytes
        let mut buf = BytesMut::from(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00][..]);
        match FrameHeader::parse(&mut buf) {
            Err(_) => {} // Expected error for 8 bytes
            Ok(_) => return Err("Should reject frame header with < 9 bytes".to_string()),
        }

        // Test parsing with exactly 9 bytes
        let mut buf = BytesMut::from(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00][..]);
        match FrameHeader::parse(&mut buf) {
            Ok(header) => {
                assert_eq!(header.length, 0);
                assert_eq!(header.frame_type, 0);
                assert_eq!(header.flags, 0);
                assert_eq!(header.stream_id, 0);
            }
            Err(e) => return Err(format!("Should parse valid 9-byte header: {}", e)),
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-4.1-HEADER-SIZE",
        "Frame header must be exactly 9 octets",
        TestCategory::FrameFormat,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 4.1: Frame length MUST NOT exceed 2^24-1.
#[allow(dead_code)]
fn test_frame_length_limits() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Maximum frame size constant should be 2^24 - 1
        if MAX_FRAME_SIZE != 16_777_215 {
            return Err(format!(
                "MAX_FRAME_SIZE is {}, should be 2^24-1 (16777215)",
                MAX_FRAME_SIZE
            ));
        }

        // Test frame with maximum allowed length
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // 24-bit length: 16777215
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Rest of header

        let header = FrameHeader::parse(&mut buf)
            .map_err(|e| format!("Should parse max length frame: {}", e))?;

        if header.length != MAX_FRAME_SIZE {
            return Err(format!(
                "Parsed length {} != expected {}",
                header.length, MAX_FRAME_SIZE
            ));
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-4.1-FRAME-LENGTH",
        "Frame length must not exceed 2^24-1 octets",
        TestCategory::FrameFormat,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 4.1: Known frame types validation.
#[allow(dead_code)]
fn test_frame_type_validation() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Test all defined frame types (0x0 - 0x9)
        let expected_types = [
            (0x0, FrameType::Data),
            (0x1, FrameType::Headers),
            (0x2, FrameType::Priority),
            (0x3, FrameType::RstStream),
            (0x4, FrameType::Settings),
            (0x5, FrameType::PushPromise),
            (0x6, FrameType::Ping),
            (0x7, FrameType::GoAway),
            (0x8, FrameType::WindowUpdate),
            (0x9, FrameType::Continuation),
        ];

        for (byte_val, expected_type) in &expected_types {
            match FrameType::from_u8(*byte_val) {
                Some(frame_type) => {
                    if frame_type != *expected_type {
                        return Err(format!(
                            "Frame type 0x{:02x} parsed as {:?}, expected {:?}",
                            byte_val, frame_type, expected_type
                        ));
                    }
                }
                None => {
                    return Err(format!(
                        "Failed to parse known frame type 0x{:02x}",
                        byte_val
                    ));
                }
            }
        }

        // Test unknown frame types
        for unknown_type in [0x0A, 0xFF, 0x10, 0x7F] {
            if FrameType::from_u8(unknown_type).is_some() {
                return Err(format!(
                    "Unknown frame type 0x{:02x} should not parse",
                    unknown_type
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-4.1-FRAME-TYPE",
        "Frame type field validation for known types",
        TestCategory::FrameFormat,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 4.1: Stream identifier reserved bit MUST be ignored.
#[allow(dead_code)]
fn test_stream_id_reserved_bit() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Test stream ID with reserved bit set (bit 31)
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x00, 0x00, 0x00]); // Length
        buf.extend_from_slice(&[0x00, 0x00]); // Type and flags
        buf.extend_from_slice(&[0x80, 0x00, 0x00, 0x01]); // Stream ID with reserved bit set

        let header = FrameHeader::parse(&mut buf)
            .map_err(|e| format!("Should parse header with reserved bit: {}", e))?;

        // Reserved bit should be ignored, so stream ID should be 1
        if header.stream_id != 1 {
            return Err(format!(
                "Stream ID with reserved bit should be 1, got {}",
                header.stream_id
            ));
        }

        // Test without reserved bit
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x00, 0x00, 0x00]); // Length
        buf.extend_from_slice(&[0x00, 0x00]); // Type and flags
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Stream ID without reserved bit

        let header = FrameHeader::parse(&mut buf)
            .map_err(|e| format!("Should parse normal header: {}", e))?;

        if header.stream_id != 1 {
            return Err(format!(
                "Normal stream ID should be 1, got {}",
                header.stream_id
            ));
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-4.1-RESERVED-BIT",
        "Stream identifier reserved bit must be ignored",
        TestCategory::FrameFormat,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 4.1: Frame header encoding format.
#[allow(dead_code)]
fn test_frame_header_encoding() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Test big-endian encoding of frame header fields
        let test_cases = [
            // (length, type, flags, stream_id, expected_bytes)
            (
                0x000001u32,
                0x01u8,
                0x05u8,
                0x00000007u32,
                [0x00, 0x00, 0x01, 0x01, 0x05, 0x00, 0x00, 0x00, 0x07],
            ),
            (
                0x001000u32,
                0x04u8,
                0x01u8,
                0x80000001u32,
                [0x00, 0x10, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x01], // Reserved bit ignored
            ),
            (
                0xFFFFFFu32,
                0x07u8,
                0xFFu8,
                0x7FFFFFFFu32,
                [0xFF, 0xFF, 0xFF, 0x07, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF],
            ),
        ];

        for (i, (length, frame_type, flags, stream_id, expected)) in test_cases.iter().enumerate() {
            let mut buf = BytesMut::from(&expected[..]);
            let header = FrameHeader::parse(&mut buf)
                .map_err(|e| format!("Test case {}: parse error: {}", i, e))?;

            if header.length != *length {
                return Err(format!(
                    "Test case {}: length {} != expected {}",
                    i, header.length, length
                ));
            }

            if header.frame_type != *frame_type {
                return Err(format!(
                    "Test case {}: type {} != expected {}",
                    i, header.frame_type, frame_type
                ));
            }

            if header.flags != *flags {
                return Err(format!(
                    "Test case {}: flags {} != expected {}",
                    i, header.flags, flags
                ));
            }

            if header.stream_id != (*stream_id & 0x7FFFFFFF) {
                return Err(format!(
                    "Test case {}: stream_id {} != expected {}",
                    i,
                    header.stream_id,
                    (*stream_id & 0x7FFFFFFF)
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-4.1-ENCODING",
        "Frame header encoding follows big-endian format",
        TestCategory::FrameFormat,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 4.1: Unknown frame types MUST be ignored.
#[allow(dead_code)]
fn test_unknown_frame_types() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Unknown frame types should parse but not be recognized
        let unknown_types = [0x0A, 0x0B, 0x10, 0x20, 0xFF];

        for unknown_type in &unknown_types {
            let mut buf = BytesMut::new();
            buf.extend_from_slice(&[0x00, 0x00, 0x08]); // Length: 8 bytes
            buf.extend_from_slice(&[*unknown_type, 0x00]); // Unknown type, no flags
            buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Stream ID 1

            let header = FrameHeader::parse(&mut buf).map_err(|e| {
                format!(
                    "Should parse unknown frame type 0x{:02x}: {}",
                    unknown_type, e
                )
            })?;

            // Header should parse successfully
            if header.frame_type != *unknown_type {
                return Err(format!(
                    "Unknown frame type 0x{:02x} should be preserved in header",
                    unknown_type
                ));
            }

            // But FrameType::from_u8 should return None
            if FrameType::from_u8(*unknown_type).is_some() {
                return Err(format!(
                    "Unknown frame type 0x{:02x} should not be recognized",
                    unknown_type
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-4.1-UNKNOWN-TYPE",
        "Unknown frame types must be ignored by recipients",
        TestCategory::FrameFormat,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 4.2: Frame size validation.
#[allow(dead_code)]
fn test_frame_size_validation() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Test boundary conditions for frame sizes
        let test_cases = [
            (0u32, "zero-length frame"),
            (1u32, "single-byte frame"),
            (16384u32, "default max frame size"),
            (65535u32, "64KB frame"),
            (MAX_FRAME_SIZE, "maximum allowed frame size"),
        ];

        for (size, description) in &test_cases {
            let mut buf = BytesMut::new();
            // Encode the size in 24-bit big-endian
            buf.extend_from_slice(&[
                ((size >> 16) & 0xFF) as u8,
                ((size >> 8) & 0xFF) as u8,
                (size & 0xFF) as u8,
            ]);
            buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // Rest of header

            let header = FrameHeader::parse(&mut buf)
                .map_err(|e| format!("Failed to parse {}: {}", description, e))?;

            if header.length != *size {
                return Err(format!(
                    "{}: expected length {}, got {}",
                    description, size, header.length
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-4.2-FRAME-SIZE",
        "Frame size validation for various sizes",
        TestCategory::FrameFormat,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Frame flags validation.
#[allow(dead_code)]
fn test_frame_flags_validation() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Test frame flags are preserved during parsing
        let flag_tests = [
            (0x00, "no flags"),
            (0x01, "single flag"),
            (0x0F, "multiple flags"),
            (0xFF, "all flags set"),
            (0x80, "high bit set"),
        ];

        for (flags, description) in &flag_tests {
            let mut buf = BytesMut::new();
            buf.extend_from_slice(&[0x00, 0x00, 0x00]); // Length
            buf.extend_from_slice(&[0x01, *flags]); // HEADERS type with flags
            buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Stream ID

            let header = FrameHeader::parse(&mut buf)
                .map_err(|e| format!("Failed to parse {}: {}", description, e))?;

            if header.flags != *flags {
                return Err(format!(
                    "{}: expected flags 0x{:02x}, got 0x{:02x}",
                    description, flags, header.flags
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-4.1-FLAGS",
        "Frame flags field preservation during parsing",
        TestCategory::FrameFormat,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}
