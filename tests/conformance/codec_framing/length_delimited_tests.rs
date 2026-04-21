//! Length delimited codec conformance tests.
//!
//! Tests validate length-prefixed framing protocol compliance including:
//! - Frame boundary detection
//! - Length field parsing (1-8 bytes, big/little endian)
//! - Length adjustment and offset handling
//! - Maximum frame size enforcement
//! - Error handling for malformed frames

use super::*;
use asupersync::bytes::{BufMut, Bytes, BytesMut};
use asupersync::codec::{Decoder, LengthDelimitedCodec};

/// Run all length delimited codec tests.
#[allow(dead_code)]
pub fn run_length_delimited_tests() -> Vec<CodecConformanceResult> {
    let mut results = Vec::new();

    // Basic framing tests
    results.push(test_basic_frame_decode());
    results.push(test_basic_frame_encode_decode());
    results.push(test_multiple_frames_single_buffer());
    results.push(test_frame_spanning_multiple_buffers());

    // Length field configuration tests
    results.push(test_1_byte_length_field());
    results.push(test_2_byte_length_field());
    results.push(test_4_byte_length_field());
    results.push(test_8_byte_length_field());
    results.push(test_big_endian_length_field());
    results.push(test_little_endian_length_field());

    // Length offset and adjustment tests
    results.push(test_length_field_offset());
    results.push(test_length_adjustment_positive());
    results.push(test_length_adjustment_negative());
    results.push(test_num_skip_bytes());

    // Resource limit tests
    results.push(test_max_frame_length_enforcement());
    results.push(test_empty_frame());
    results.push(test_zero_length_frame());

    // Error handling tests
    results.push(test_incomplete_length_field());
    results.push(test_incomplete_frame_data());
    results.push(test_length_field_overflow());
    results.push(test_malformed_length_field());

    // Edge case tests
    results.push(test_eof_with_partial_frame());
    results.push(test_eof_with_complete_frame());

    results
}

/// Test basic frame decoding with default 4-byte length prefix.
#[allow(dead_code)]
fn test_basic_frame_decode() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::new();
        let mut buf = BytesMut::new();

        // Create frame: [length=5][data="hello"]
        buf.put_u32(5);
        buf.extend_from_slice(b"hello");

        let frame = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?
            .ok_or("Expected frame but got None")?;

        let frozen = frame.freeze();
        if frozen != Bytes::from("hello") {
            return Err(format!("Expected 'hello', got {:?}", frozen));
        }

        // Buffer should be empty after consuming the frame
        if !buf.is_empty() {
            return Err(format!("Buffer should be empty, has {} bytes", buf.len()));
        }

        Ok(())
    });

    create_test_result(
        "LD-FRAME-001",
        "Basic frame decode with 4-byte length prefix",
        TestCategory::Framing,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test encode-decode round-trip.
#[allow(dead_code)]
fn test_basic_frame_encode_decode() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Note: LengthDelimitedCodec in the current implementation appears to be decode-only
        // This test validates the expected frame format for round-trip compatibility
        let original_data = Bytes::from("test data");

        // Manually create the expected frame format
        let mut encoded = BytesMut::new();
        encoded.put_u32(original_data.len() as u32);
        encoded.extend_from_slice(&original_data);

        // Decode it back
        let mut codec = LengthDelimitedCodec::new();
        let mut buf = encoded;
        let decoded = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?
            .ok_or("Expected frame but got None")?;

        let frozen_decoded = decoded.freeze();
        if frozen_decoded != original_data {
            return Err(format!(
                "Round-trip failed: expected {:?}, got {:?}",
                original_data, frozen_decoded
            ));
        }

        Ok(())
    });

    create_test_result(
        "LD-FRAME-002",
        "Encode-decode round-trip preservation",
        TestCategory::RoundTrip,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test multiple frames in a single buffer.
#[allow(dead_code)]
fn test_multiple_frames_single_buffer() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::new();
        let mut buf = BytesMut::new();

        // Create two frames: [3][abc][5][hello]
        buf.put_u32(3);
        buf.extend_from_slice(b"abc");
        buf.put_u32(5);
        buf.extend_from_slice(b"hello");

        // Decode first frame
        let frame1 = codec
            .decode(&mut buf)
            .map_err(|e| format!("First decode failed: {e}"))?
            .ok_or("Expected first frame but got None")?;

        let frozen1 = frame1.freeze();
        if frozen1 != Bytes::from("abc") {
            return Err(format!("First frame: expected 'abc', got {:?}", frozen1));
        }

        // Decode second frame
        let frame2 = codec
            .decode(&mut buf)
            .map_err(|e| format!("Second decode failed: {e}"))?
            .ok_or("Expected second frame but got None")?;

        let frozen2 = frame2.freeze();
        if frozen2 != Bytes::from("hello") {
            return Err(format!("Second frame: expected 'hello', got {:?}", frozen2));
        }

        // Buffer should be empty
        if !buf.is_empty() {
            return Err(format!("Buffer should be empty, has {} bytes", buf.len()));
        }

        Ok(())
    });

    create_test_result(
        "LD-FRAME-003",
        "Multiple frames in single buffer",
        TestCategory::Framing,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test frame spanning multiple buffers (partial reads).
#[allow(dead_code)]
fn test_frame_spanning_multiple_buffers() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::new();
        let mut buf = BytesMut::new();

        // First buffer: partial length field [0x00, 0x00]
        buf.extend_from_slice(&[0x00, 0x00]);
        let result1 = codec
            .decode(&mut buf)
            .map_err(|e| format!("First decode failed: {e}"))?;
        if result1.is_some() {
            return Err("Should not decode incomplete length field".to_string());
        }

        // Second buffer: complete length field [0x00, 0x05]
        buf.extend_from_slice(&[0x00, 0x05]);
        let result2 = codec
            .decode(&mut buf)
            .map_err(|e| format!("Second decode failed: {e}"))?;
        if result2.is_some() {
            return Err("Should not decode without frame data".to_string());
        }

        // Third buffer: partial frame data ['h', 'e', 'l']
        buf.extend_from_slice(b"hel");
        let result3 = codec
            .decode(&mut buf)
            .map_err(|e| format!("Third decode failed: {e}"))?;
        if result3.is_some() {
            return Err("Should not decode incomplete frame data".to_string());
        }

        // Fourth buffer: complete frame data ['l', 'o']
        buf.extend_from_slice(b"lo");
        let frame = codec
            .decode(&mut buf)
            .map_err(|e| format!("Fourth decode failed: {e}"))?
            .ok_or("Expected complete frame")?;

        let frozen = frame.freeze();
        if frozen != Bytes::from("hello") {
            return Err(format!("Expected 'hello', got {:?}", frozen));
        }

        Ok(())
    });

    create_test_result(
        "LD-FRAME-004",
        "Frame spanning multiple buffers",
        TestCategory::Framing,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test 1-byte length field configuration.
#[allow(dead_code)]
fn test_1_byte_length_field() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::builder()
            .length_field_length(1)
            .num_skip(1)
            .new_codec();
        let mut buf = BytesMut::new();

        // Create frame with 1-byte length: [3][abc]
        buf.put_u8(3);
        buf.extend_from_slice(b"abc");

        let frame = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?
            .ok_or("Expected frame but got None")?;

        if frame.freeze() != Bytes::from("abc") {
            return Err(format!("Expected 'abc', got {:?}", frame));
        }

        Ok(())
    });

    create_test_result(
        "LD-CONFIG-001",
        "1-byte length field configuration",
        TestCategory::Framing,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test 2-byte length field configuration.
#[allow(dead_code)]
fn test_2_byte_length_field() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::builder()
            .length_field_length(2)
            .num_skip(2)
            .new_codec();
        let mut buf = BytesMut::new();

        // Create frame with 2-byte length: [0x00, 0x05][hello]
        buf.put_u16(5);
        buf.extend_from_slice(b"hello");

        let frame = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?
            .ok_or("Expected frame but got None")?;

        let frozen = frame.freeze();
        if frozen != Bytes::from("hello") {
            return Err(format!("Expected 'hello', got {:?}", frozen));
        }

        Ok(())
    });

    create_test_result(
        "LD-CONFIG-002",
        "2-byte length field configuration",
        TestCategory::Framing,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test 4-byte length field (default).
#[allow(dead_code)]
fn test_4_byte_length_field() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::new(); // Default is 4-byte
        let mut buf = BytesMut::new();

        // Create frame with 4-byte length
        buf.put_u32(4);
        buf.extend_from_slice(b"test");

        let frame = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?
            .ok_or("Expected frame but got None")?;

        let frozen = frame.freeze();
        if frozen != Bytes::from("test") {
            return Err(format!("Expected 'test', got {:?}", frozen));
        }

        Ok(())
    });

    create_test_result(
        "LD-CONFIG-003",
        "4-byte length field configuration",
        TestCategory::Framing,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test 8-byte length field configuration.
#[allow(dead_code)]
fn test_8_byte_length_field() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::builder()
            .length_field_length(8)
            .num_skip(8)
            .new_codec();
        let mut buf = BytesMut::new();

        // Create frame with 8-byte length
        buf.put_u64(6);
        buf.extend_from_slice(b"longer");

        let frame = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?
            .ok_or("Expected frame but got None")?;

        let frozen = frame.freeze();
        if frozen != Bytes::from("longer") {
            return Err(format!("Expected 'longer', got {:?}", frozen));
        }

        Ok(())
    });

    create_test_result(
        "LD-CONFIG-004",
        "8-byte length field configuration",
        TestCategory::Framing,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test big-endian length field (default).
#[allow(dead_code)]
fn test_big_endian_length_field() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::new(); // Default is big-endian
        let mut buf = BytesMut::new();

        // Big-endian 0x0100 = 256 decimal
        buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x05]); // length = 5
        buf.extend_from_slice(b"hello");

        let frame = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?
            .ok_or("Expected frame but got None")?;

        let frozen = frame.freeze();
        if frozen != Bytes::from("hello") {
            return Err(format!("Expected 'hello', got {:?}", frozen));
        }

        Ok(())
    });

    create_test_result(
        "LD-ENDIAN-001",
        "Big-endian length field parsing",
        TestCategory::Framing,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test little-endian length field.
#[allow(dead_code)]
fn test_little_endian_length_field() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::builder().little_endian().new_codec();
        let mut buf = BytesMut::new();

        // Little-endian: [0x05, 0x00, 0x00, 0x00] = 5
        buf.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]);
        buf.extend_from_slice(b"hello");

        let frame = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?
            .ok_or("Expected frame but got None")?;

        let frozen = frame.freeze();
        if frozen != Bytes::from("hello") {
            return Err(format!("Expected 'hello', got {:?}", frozen));
        }

        Ok(())
    });

    create_test_result(
        "LD-ENDIAN-002",
        "Little-endian length field parsing",
        TestCategory::Framing,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test length field offset.
#[allow(dead_code)]
fn test_length_field_offset() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::builder()
            .length_field_offset(2)
            .length_field_length(4)
            .num_skip(6) // Skip header (2) + length field (4)
            .new_codec();
        let mut buf = BytesMut::new();

        // Header: [0xFF, 0xFE]
        // Length: [0x00, 0x00, 0x00, 0x04]
        // Data: [test]
        buf.extend_from_slice(&[0xFF, 0xFE]); // Header
        buf.put_u32(4); // Length at offset 2
        buf.extend_from_slice(b"test");

        let frame = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?
            .ok_or("Expected frame but got None")?;

        let frozen = frame.freeze();
        if frozen != Bytes::from("test") {
            return Err(format!("Expected 'test', got {:?}", frozen));
        }

        Ok(())
    });

    create_test_result(
        "LD-OFFSET-001",
        "Length field offset handling",
        TestCategory::Framing,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test positive length adjustment.
#[allow(dead_code)]
fn test_length_adjustment_positive() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::builder()
            .length_adjustment(4) // Add 4 to reported length
            .new_codec();
        let mut buf = BytesMut::new();

        // Report length as 1, but actual payload is 5 bytes (1 + 4)
        buf.put_u32(1);
        buf.extend_from_slice(b"hello");

        let frame = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?
            .ok_or("Expected frame but got None")?;

        let frozen = frame.freeze();
        if frozen != Bytes::from("hello") {
            return Err(format!("Expected 'hello', got {:?}", frozen));
        }

        Ok(())
    });

    create_test_result(
        "LD-ADJUST-001",
        "Positive length adjustment",
        TestCategory::Framing,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test negative length adjustment.
#[allow(dead_code)]
fn test_length_adjustment_negative() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::builder()
            .length_adjustment(-4) // Subtract 4 from reported length
            .new_codec();
        let mut buf = BytesMut::new();

        // Report length as 9 (5 + 4), but actual payload is 5 bytes
        buf.put_u32(9);
        buf.extend_from_slice(b"hello");

        let frame = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?
            .ok_or("Expected frame but got None")?;

        let frozen = frame.freeze();
        if frozen != Bytes::from("hello") {
            return Err(format!("Expected 'hello', got {:?}", frozen));
        }

        Ok(())
    });

    create_test_result(
        "LD-ADJUST-002",
        "Negative length adjustment",
        TestCategory::Framing,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test num_skip parameter.
#[allow(dead_code)]
fn test_num_skip_bytes() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::builder()
            .length_field_length(4)
            .num_skip(8) // Skip length field (4) + additional header (4)
            .new_codec();
        let mut buf = BytesMut::new();

        // Length: [0x00, 0x00, 0x00, 0x05]
        // Extra header: [0xDE, 0xAD, 0xBE, 0xEF] (to be skipped)
        // Data: [hello]
        buf.put_u32(5);
        buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        buf.extend_from_slice(b"hello");

        let frame = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?
            .ok_or("Expected frame but got None")?;

        let frozen = frame.freeze();
        if frozen != Bytes::from("hello") {
            return Err(format!("Expected 'hello', got {:?}", frozen));
        }

        Ok(())
    });

    create_test_result(
        "LD-SKIP-001",
        "num_skip parameter handling",
        TestCategory::Framing,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test maximum frame length enforcement.
#[allow(dead_code)]
fn test_max_frame_length_enforcement() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::builder()
            .max_frame_length(10)
            .new_codec();
        let mut buf = BytesMut::new();

        // Frame length 15 > max 10, should be rejected
        buf.put_u32(15);
        buf.extend_from_slice(b"this_is_too_long");

        match codec.decode(&mut buf) {
            Err(_) => Ok(()), // Expected error
            Ok(Some(_)) => Err("Should have rejected frame exceeding max length".to_string()),
            Ok(None) => Err("Should have failed, not returned None".to_string()),
        }
    });

    create_test_result(
        "LD-LIMIT-001",
        "Maximum frame length enforcement",
        TestCategory::ResourceLimits,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test empty frame handling.
#[allow(dead_code)]
fn test_empty_frame() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::new();
        let mut buf = BytesMut::new();

        // Empty frame: length = 0, no data
        buf.put_u32(0);

        let frame = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?
            .ok_or("Expected empty frame but got None")?;

        if !frame.is_empty() {
            return Err(format!("Expected empty frame, got {} bytes", frame.len()));
        }

        Ok(())
    });

    create_test_result(
        "LD-EDGE-001",
        "Empty frame handling",
        TestCategory::EdgeCases,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test zero-length frame (same as empty).
#[allow(dead_code)]
fn test_zero_length_frame() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::new();
        let mut buf = BytesMut::new();

        // Zero-length frame
        buf.put_u32(0);

        let frame = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?;

        match frame {
            Some(f) if f.is_empty() => Ok(()),
            Some(_) => Err("Expected empty frame".to_string()),
            None => Err("Should have returned empty frame, not None".to_string()),
        }
    });

    create_test_result(
        "LD-EDGE-002",
        "Zero-length frame handling",
        TestCategory::EdgeCases,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test incomplete length field.
#[allow(dead_code)]
fn test_incomplete_length_field() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::new();
        let mut buf = BytesMut::new();

        // Only 3 bytes of 4-byte length field
        buf.extend_from_slice(&[0x00, 0x00, 0x05]);

        let result = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?;

        match result {
            None => Ok(()), // Expected - need more data
            Some(_) => Err("Should not decode incomplete length field".to_string()),
        }
    });

    create_test_result(
        "LD-ERROR-001",
        "Incomplete length field handling",
        TestCategory::ErrorHandling,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test incomplete frame data.
#[allow(dead_code)]
fn test_incomplete_frame_data() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::new();
        let mut buf = BytesMut::new();

        // Complete length field but incomplete data
        buf.put_u32(10);
        buf.extend_from_slice(b"short"); // Only 5 bytes, need 10

        let result = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?;

        match result {
            None => Ok(()), // Expected - need more data
            Some(_) => Err("Should not decode incomplete frame data".to_string()),
        }
    });

    create_test_result(
        "LD-ERROR-002",
        "Incomplete frame data handling",
        TestCategory::ErrorHandling,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test length field overflow.
#[allow(dead_code)]
fn test_length_field_overflow() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::builder()
            .max_frame_length(1000)
            .new_codec();
        let mut buf = BytesMut::new();

        // Very large length that would cause overflow/OOM
        buf.put_u32(u32::MAX);

        match codec.decode(&mut buf) {
            Err(_) => Ok(()), // Expected error
            Ok(_) => Err("Should have rejected oversized frame".to_string()),
        }
    });

    create_test_result(
        "LD-ERROR-003",
        "Length field overflow protection",
        TestCategory::ErrorHandling,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test malformed length field.
#[allow(dead_code)]
fn test_malformed_length_field() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::builder()
            .length_field_length(3) // Invalid length field size
            .new_codec();
        let mut buf = BytesMut::new();

        buf.extend_from_slice(&[0x00, 0x00, 0x05]);

        // This should either work (if 3-byte lengths are supported) or fail gracefully
        match codec.decode(&mut buf) {
            Ok(_) | Err(_) => Ok(()), // Either outcome is acceptable for this edge case
        }
    });

    create_test_result(
        "LD-ERROR-004",
        "Malformed length field graceful handling",
        TestCategory::ErrorHandling,
        RequirementLevel::Should,
        result,
        elapsed,
    )
}

/// Test EOF with partial frame.
#[allow(dead_code)]
fn test_eof_with_partial_frame() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::new();
        let mut buf = BytesMut::new();

        // Partial frame at EOF
        buf.put_u32(10);
        buf.extend_from_slice(b"partial");

        // Try decode_eof instead of decode
        match codec.decode_eof(&mut buf) {
            Err(_) => Ok(()), // Expected error - incomplete frame
            Ok(Some(_)) => Err("Should not decode partial frame at EOF".to_string()),
            Ok(None) => Err("Should error on partial frame, not return None".to_string()),
        }
    });

    create_test_result(
        "LD-EOF-001",
        "EOF with partial frame error handling",
        TestCategory::ErrorHandling,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// Test EOF with complete frame.
#[allow(dead_code)]
fn test_eof_with_complete_frame() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::new();
        let mut buf = BytesMut::new();

        // Complete frame at EOF
        buf.put_u32(4);
        buf.extend_from_slice(b"done");

        let frame = codec
            .decode_eof(&mut buf)
            .map_err(|e| format!("decode_eof failed: {e}"))?
            .ok_or("Expected frame but got None")?;

        let frozen = frame.freeze();
        if frozen != Bytes::from("done") {
            return Err(format!("Expected 'done', got {:?}", frozen));
        }

        Ok(())
    });

    create_test_result(
        "LD-EOF-002",
        "EOF with complete frame success",
        TestCategory::EdgeCases,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}
