#![allow(clippy::all)]
//! Bytes codec conformance tests.

use super::*;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{BytesCodec, Decoder, Encoder};

/// Run all bytes codec tests.
#[allow(dead_code)]
pub fn run_bytes_codec_tests() -> Vec<CodecConformanceResult> {
    let mut results = Vec::new();

    results.push(test_pass_through_decode());
    results.push(test_encode_decode_round_trip());
    results.push(test_empty_buffer());
    results.push(test_large_buffer());

    results
}

#[allow(dead_code)]

fn test_pass_through_decode() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::from(&b"test data"[..]);

        let decoded = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?
            .ok_or("Expected decoded bytes")?;

        let frozen = decoded.freeze();
        if frozen != Bytes::from("test data") {
            return Err(format!("Expected 'test data', got {:?}", frozen));
        }

        if !buf.is_empty() {
            return Err("Buffer should be empty after decode".to_string());
        }

        Ok(())
    });

    create_test_result(
        "BC-PASS-001",
        "Pass-through decode operation",
        TestCategory::Framing,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]

fn test_encode_decode_round_trip() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = BytesCodec::new();
        let original = Bytes::from("round trip test");

        // Encode
        let mut buf = BytesMut::new();
        codec
            .encode(original.clone(), &mut buf)
            .map_err(|e| format!("Encode failed: {e}"))?;

        // Decode
        let decoded = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?
            .ok_or("Expected decoded bytes")?;

        let frozen_decoded = decoded.freeze();
        if frozen_decoded != original {
            return Err(format!(
                "Round-trip failed: expected {:?}, got {:?}",
                original, frozen_decoded
            ));
        }

        Ok(())
    });

    create_test_result(
        "BC-ROUND-001",
        "Encode-decode round-trip",
        TestCategory::RoundTrip,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]

fn test_empty_buffer() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();

        let result = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?;

        match result {
            None => Ok(()),                            // Expected for empty buffer
            Some(bytes) if bytes.is_empty() => Ok(()), // Also acceptable
            Some(bytes) => Err(format!("Expected None or empty, got {:?}", bytes)),
        }
    });

    create_test_result(
        "BC-EMPTY-001",
        "Empty buffer handling",
        TestCategory::EdgeCases,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]

fn test_large_buffer() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = BytesCodec::new();
        let large_data = vec![0u8; 1024 * 1024]; // 1MB
        let mut buf = BytesMut::from(&large_data[..]);

        let decoded = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?
            .ok_or("Expected decoded bytes")?;

        if decoded.len() != large_data.len() {
            return Err(format!(
                "Size mismatch: expected {}, got {}",
                large_data.len(),
                decoded.len()
            ));
        }

        Ok(())
    });

    create_test_result(
        "BC-LARGE-001",
        "Large buffer handling",
        TestCategory::Performance,
        RequirementLevel::Should,
        result,
        elapsed,
    )
}
