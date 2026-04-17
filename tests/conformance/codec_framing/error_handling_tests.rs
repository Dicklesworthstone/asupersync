//! Error handling conformance tests.

use super::*;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, LengthDelimitedCodec, LinesCodec};

/// Run all error handling tests.
pub fn run_error_handling_tests() -> Vec<CodecConformanceResult> {
    let mut results = Vec::new();

    results.push(test_malformed_length_handling());
    results.push(test_invalid_utf8_handling());
    results.push(test_buffer_underflow_handling());
    results.push(test_decode_eof_partial_frame());

    results
}

fn test_malformed_length_handling() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::builder()
            .max_frame_length(100)
            .new_codec();
        let mut buf = BytesMut::new();

        // Length that would cause integer overflow
        buf.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);

        match codec.decode(&mut buf) {
            Err(_) => Ok(()), // Expected error
            Ok(_) => Err("Should have rejected malformed length".to_string()),
        }
    });

    create_test_result(
        "EH-MALFORM-001",
        "Malformed length field handling",
        TestCategory::ErrorHandling,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

fn test_invalid_utf8_handling() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LinesCodec::new();
        let mut buf = BytesMut::new();

        // Invalid UTF-8 sequence
        buf.extend_from_slice(&[0xC0, 0x80]); // Overlong encoding
        buf.extend_from_slice(b"\n");

        match codec.decode(&mut buf) {
            Err(_) => Ok(()), // Expected error
            Ok(_) => Err("Should have rejected invalid UTF-8".to_string()),
        }
    });

    create_test_result(
        "EH-UTF8-001",
        "Invalid UTF-8 handling",
        TestCategory::ErrorHandling,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

fn test_buffer_underflow_handling() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::new();
        let mut buf = BytesMut::new();

        // Incomplete length field
        buf.extend_from_slice(&[0x00, 0x00]);

        let result = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?;

        match result {
            None => Ok(()), // Expected - need more data
            Some(_) => Err("Should not decode with incomplete length field".to_string()),
        }
    });

    create_test_result(
        "EH-UNDERFLOW-001",
        "Buffer underflow graceful handling",
        TestCategory::ErrorHandling,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

fn test_decode_eof_partial_frame() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::new();
        let mut buf = BytesMut::new();

        // Complete length field but incomplete data
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x10]);
        buf.extend_from_slice(b"partial");

        match codec.decode_eof(&mut buf) {
            Err(_) => Ok(()), // Expected error
            Ok(_) => Err("Should have rejected partial frame at EOF".to_string()),
        }
    });

    create_test_result(
        "EH-EOF-001",
        "EOF with partial frame error",
        TestCategory::ErrorHandling,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}
