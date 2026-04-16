//! Lines codec conformance tests.

use super::*;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder, LinesCodec};

/// Run all lines codec tests.
pub fn run_lines_codec_tests() -> Vec<CodecConformanceResult> {
    let mut results = Vec::new();

    results.push(test_basic_line_decode());
    results.push(test_crlf_line_endings());
    results.push(test_lf_line_endings());
    results.push(test_multiple_lines());
    results.push(test_empty_lines());
    results.push(test_max_line_length());
    results.push(test_utf8_validation());
    results.push(test_encode_decode_round_trip());

    results
}

fn test_basic_line_decode() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LinesCodec::new();
        let mut buf = BytesMut::from("hello\nworld\n");

        let line1 = codec.decode(&mut buf)
            .map_err(|e| format!("First decode failed: {e}"))?
            .ok_or("Expected first line")?;

        if line1 != "hello" {
            return Err(format!("Expected 'hello', got {:?}", line1));
        }

        let line2 = codec.decode(&mut buf)
            .map_err(|e| format!("Second decode failed: {e}"))?
            .ok_or("Expected second line")?;

        if line2 != "world" {
            return Err(format!("Expected 'world', got {:?}", line2));
        }

        Ok(())
    });

    create_test_result(
        "LC-BASIC-001",
        "Basic line decoding with LF endings",
        TestCategory::Framing,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

fn test_crlf_line_endings() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LinesCodec::new();
        let mut buf = BytesMut::from("hello\r\nworld\r\n");

        let line1 = codec.decode(&mut buf)
            .map_err(|e| format!("First decode failed: {e}"))?
            .ok_or("Expected first line")?;

        if line1 != "hello" {
            return Err(format!("Expected 'hello', got {:?}", line1));
        }

        Ok(())
    });

    create_test_result(
        "LC-ENDING-001",
        "CRLF line ending support",
        TestCategory::Framing,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

fn test_lf_line_endings() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LinesCodec::new();
        let mut buf = BytesMut::from("test\n");

        let line = codec.decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?
            .ok_or("Expected line")?;

        if line != "test" {
            return Err(format!("Expected 'test', got {:?}", line));
        }

        Ok(())
    });

    create_test_result(
        "LC-ENDING-002",
        "LF line ending support",
        TestCategory::Framing,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

fn test_multiple_lines() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LinesCodec::new();
        let mut buf = BytesMut::from("line1\nline2\nline3\n");

        for i in 1..=3 {
            let line = codec.decode(&mut buf)
                .map_err(|e| format!("Decode {} failed: {e}", i))?
                .ok_or_else(|| format!("Expected line {}", i))?;

            let expected = format!("line{}", i);
            if line != expected {
                return Err(format!("Line {}: expected {:?}, got {:?}", i, expected, line));
            }
        }

        Ok(())
    });

    create_test_result(
        "LC-MULTI-001",
        "Multiple lines in buffer",
        TestCategory::Framing,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

fn test_empty_lines() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LinesCodec::new();
        let mut buf = BytesMut::from("\n\nhello\n");

        // First empty line
        let line1 = codec.decode(&mut buf)
            .map_err(|e| format!("First decode failed: {e}"))?
            .ok_or("Expected first empty line")?;

        if !line1.is_empty() {
            return Err(format!("Expected empty line, got {:?}", line1));
        }

        // Second empty line
        let line2 = codec.decode(&mut buf)
            .map_err(|e| format!("Second decode failed: {e}"))?
            .ok_or("Expected second empty line")?;

        if !line2.is_empty() {
            return Err(format!("Expected empty line, got {:?}", line2));
        }

        // Non-empty line
        let line3 = codec.decode(&mut buf)
            .map_err(|e| format!("Third decode failed: {e}"))?
            .ok_or("Expected third line")?;

        if line3 != "hello" {
            return Err(format!("Expected 'hello', got {:?}", line3));
        }

        Ok(())
    });

    create_test_result(
        "LC-EMPTY-001",
        "Empty line handling",
        TestCategory::EdgeCases,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

fn test_max_line_length() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LinesCodec::new_with_max_length(10);
        let mut buf = BytesMut::from("this_line_is_too_long_for_the_limit\n");

        match codec.decode(&mut buf) {
            Err(_) => Ok(()), // Expected error
            Ok(_) => Err("Should have rejected line exceeding max length".to_string()),
        }
    });

    create_test_result(
        "LC-LIMIT-001",
        "Maximum line length enforcement",
        TestCategory::ResourceLimits,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

fn test_utf8_validation() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LinesCodec::new();

        // Invalid UTF-8 sequence
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0xFF, 0xFE, 0xFD]);
        buf.extend_from_slice(b"\n");

        match codec.decode(&mut buf) {
            Err(_) => Ok(()), // Expected error for invalid UTF-8
            Ok(Some(line)) => Err(format!("Should have rejected invalid UTF-8, got: {:?}", line)),
            Ok(None) => Err("Should have errored, not returned None".to_string()),
        }
    });

    create_test_result(
        "LC-UTF8-001",
        "UTF-8 validation",
        TestCategory::ErrorHandling,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

fn test_encode_decode_round_trip() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LinesCodec::new();
        let original = "test line";

        // Encode
        let mut buf = BytesMut::new();
        codec.encode(original, &mut buf)
            .map_err(|e| format!("Encode failed: {e}"))?;

        // Decode
        let decoded = codec.decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?
            .ok_or("Expected decoded line")?;

        if decoded != original {
            return Err(format!("Round-trip failed: expected {:?}, got {:?}", original, decoded));
        }

        Ok(())
    });

    create_test_result(
        "LC-ROUND-001",
        "Encode-decode round-trip",
        TestCategory::RoundTrip,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}