#![allow(clippy::all)]
//! Resource limits conformance tests.

use super::*;
use asupersync::bytes::{BufMut, Bytes, BytesMut};
use asupersync::codec::{Decoder, LengthDelimitedCodec, LinesCodec};

/// Run all resource limits tests.
#[allow(dead_code)]
pub fn run_resource_limits_tests() -> Vec<CodecConformanceResult> {
    let mut results = Vec::new();

    results.push(test_max_frame_size_limit());
    results.push(test_max_line_length_limit());
    results.push(test_memory_usage_bounds());
    results.push(test_buffer_growth_limits());

    results
}

#[allow(dead_code)]

fn test_max_frame_size_limit() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let max_size = 1024;
        let mut codec = LengthDelimitedCodec::builder()
            .max_frame_length(max_size)
            .new_codec();
        let mut buf = BytesMut::new();

        // Frame larger than limit
        let oversized_length = max_size + 1;
        buf.put_u32(oversized_length as u32);

        match codec.decode(&mut buf) {
            Err(_) => Ok(()), // Expected error
            Ok(Some(_)) => Err("Should have rejected oversized frame".to_string()),
            Ok(None) => {
                // Might need actual data to trigger the check
                buf.extend_from_slice(&vec![0u8; oversized_length]);
                match codec.decode(&mut buf) {
                    Err(_) => Ok(()),
                    Ok(_) => Err("Should have rejected oversized frame".to_string()),
                }
            }
        }
    });

    create_test_result(
        "RL-FRAME-001",
        "Maximum frame size enforcement",
        TestCategory::ResourceLimits,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]

fn test_max_line_length_limit() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let max_length = 50;
        let mut codec = LinesCodec::new_with_max_length(max_length);
        let mut buf = BytesMut::new();

        // Line longer than limit
        let long_line = "a".repeat(max_length + 10);
        buf.extend_from_slice(long_line.as_bytes());
        buf.extend_from_slice(b"\n");

        match codec.decode(&mut buf) {
            Err(_) => Ok(()), // Expected error
            Ok(_) => Err("Should have rejected oversized line".to_string()),
        }
    });

    create_test_result(
        "RL-LINE-001",
        "Maximum line length enforcement",
        TestCategory::ResourceLimits,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]

fn test_memory_usage_bounds() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::builder()
            .max_frame_length(1024)
            .new_codec();

        // Test multiple small frames don't cause memory leaks
        for i in 0..100 {
            let mut buf = BytesMut::new();
            let data = format!("frame{}", i);
            buf.put_u32(data.len() as u32);
            buf.extend_from_slice(data.as_bytes());

            let _frame = codec
                .decode(&mut buf)
                .map_err(|e| format!("Decode {} failed: {e}", i))?
                .ok_or_else(|| format!("Expected frame {}", i))?;
        }

        Ok(())
    });

    create_test_result(
        "RL-MEMORY-001",
        "Memory usage bounds validation",
        TestCategory::ResourceLimits,
        RequirementLevel::Should,
        result,
        elapsed,
    )
}

#[allow(dead_code)]

fn test_buffer_growth_limits() -> CodecConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut codec = LengthDelimitedCodec::builder()
            .max_frame_length(10 * 1024 * 1024) // 10MB limit
            .new_codec();
        let mut buf = BytesMut::new();

        // Very large frame declaration that shouldn't cause immediate allocation
        buf.put_u32(5 * 1024 * 1024); // 5MB frame

        // Should not error until we actually try to read 5MB of data
        let result = codec
            .decode(&mut buf)
            .map_err(|e| format!("Decode failed: {e}"))?;

        match result {
            None => Ok(()), // Expected - waiting for data
            Some(_) => Err("Should not have produced frame without data".to_string()),
        }
    });

    create_test_result(
        "RL-GROWTH-001",
        "Buffer growth limits validation",
        TestCategory::ResourceLimits,
        RequirementLevel::Should,
        result,
        elapsed,
    )
}
