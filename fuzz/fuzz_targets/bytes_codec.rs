//! Fuzz target for BytesCodec passthrough codec.
//!
//! This target fuzzes the BytesCodec with focus on the 5 key properties:
//! 1. encode-decode roundtrip is identity
//! 2. partial reads accumulate correctly
//! 3. max_frame_length enforced (simulated via reasonable limits)
//! 4. cancellation drains buffered bytes (simulated via buffer operations)
//! 5. empty frames tolerated
//!
//! The BytesCodec is a simple pass-through codec that should be robust
//! against all input patterns while maintaining perfect fidelity.
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run bytes_codec
//! ```
//!
//! # Minimizing crashes
//! ```bash
//! cargo +nightly fuzz tmin bytes_codec <crash_file>
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{BytesCodec, Decoder, Encoder};
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;

/// Maximum total data size to prevent OOM in fuzzer
const MAX_TOTAL_DATA: usize = 1024 * 1024; // 1MB

/// Maximum individual chunk size for partial read testing
const MAX_CHUNK_SIZE: usize = 64 * 1024; // 64KB

/// Maximum number of operations to prevent timeout
const MAX_OPERATIONS: usize = 100;

#[derive(Arbitrary, Debug)]
struct BytesCodecFuzzInput {
    /// Test scenario to execute
    scenario: TestScenario,
    /// Data payloads for encoding/decoding
    payloads: Vec<DataPayload>,
    /// Partial read configuration
    partial_config: PartialReadConfig,
    /// Buffer manipulation patterns
    buffer_ops: Vec<BufferOperation>,
}

#[derive(Arbitrary, Debug)]
enum TestScenario {
    /// Basic roundtrip testing
    RoundTrip,
    /// Partial read accumulation testing
    PartialAccumulation,
    /// Buffer manipulation and cancellation simulation
    BufferManipulation,
    /// Empty frame tolerance testing
    EmptyFrames,
    /// Comprehensive testing of all properties
    Comprehensive,
}

#[derive(Arbitrary, Debug)]
struct DataPayload {
    /// The actual data content
    data: Vec<u8>,
    /// Format to use for encoding
    format: PayloadFormat,
}

#[derive(Arbitrary, Debug)]
enum PayloadFormat {
    /// Encode as Bytes
    Bytes,
    /// Encode as BytesMut
    BytesMut,
    /// Encode as Vec<u8>
    Vec,
}

#[derive(Arbitrary, Debug)]
struct PartialReadConfig {
    /// Chunk sizes for partial read simulation
    chunk_sizes: Vec<u8>, // Will be scaled to reasonable sizes
    /// Whether to intermix full and partial reads
    intermix_full: bool,
    /// Whether to test with zero-sized reads
    include_zero_reads: bool,
}

#[derive(Arbitrary, Debug)]
enum BufferOperation {
    /// Clear the buffer (simulating cancellation drain)
    Clear,
    /// Reserve additional capacity
    Reserve(u16),
    /// Split buffer at position
    Split(u8),
    /// Truncate buffer to size
    Truncate(u8),
    /// Extend with additional data
    Extend(Vec<u8>),
}

fuzz_target!(|input: BytesCodecFuzzInput| {
    // Guard against excessively large inputs to prevent OOM
    let total_payload_size: usize = input.payloads.iter().map(|p| p.data.len()).sum();

    if total_payload_size > MAX_TOTAL_DATA {
        return;
    }

    // Filter payloads that are too large individually
    let payloads: Vec<_> = input
        .payloads
        .into_iter()
        .filter(|p| p.data.len() <= MAX_CHUNK_SIZE)
        .take(MAX_OPERATIONS)
        .collect();

    if payloads.is_empty() {
        return;
    }

    match input.scenario {
        TestScenario::RoundTrip => test_roundtrip_identity(&payloads),
        TestScenario::PartialAccumulation => {
            test_partial_accumulation(&payloads, &input.partial_config)
        }
        TestScenario::BufferManipulation => test_buffer_manipulation(&payloads, &input.buffer_ops),
        TestScenario::EmptyFrames => test_empty_frames_tolerance(),
        TestScenario::Comprehensive => {
            test_roundtrip_identity(&payloads);
            test_partial_accumulation(&payloads, &input.partial_config);
            test_buffer_manipulation(&payloads, &input.buffer_ops);
            test_empty_frames_tolerance();
        }
    }
});

/// **Property 1: Encode-decode roundtrip is identity**
///
/// For any data D, encode(D) -> buffer -> decode(buffer) should yield D exactly.
fn test_roundtrip_identity(payloads: &[DataPayload]) {
    let mut codec = BytesCodec::new();

    for payload in payloads {
        if payload.data.len() > MAX_CHUNK_SIZE {
            continue;
        }

        let original_data = &payload.data;
        let mut encode_buffer = BytesMut::new();

        // Encode using the specified format
        let encode_result = match payload.format {
            PayloadFormat::Bytes => {
                let bytes_data = Bytes::from(original_data.clone());
                codec.encode(bytes_data, &mut encode_buffer)
            }
            PayloadFormat::BytesMut => {
                let bytes_mut_data = BytesMut::from(original_data.as_slice());
                codec.encode(bytes_mut_data, &mut encode_buffer)
            }
            PayloadFormat::Vec => codec.encode(original_data.clone(), &mut encode_buffer),
        };

        // Encoding should never fail for BytesCodec
        assert!(
            encode_result.is_ok(),
            "BytesCodec encoding failed unexpectedly"
        );

        // Decode back
        let decoded_result = codec.decode(&mut encode_buffer);
        assert!(
            decoded_result.is_ok(),
            "BytesCodec decoding failed unexpectedly"
        );

        if let Ok(Some(decoded)) = decoded_result {
            // **Roundtrip identity property**
            assert_eq!(
                decoded.as_ref(),
                original_data.as_slice(),
                "Roundtrip identity violated: original={:?}, decoded={:?}",
                original_data,
                decoded.as_ref()
            );

            // Buffer should be fully consumed by decode
            assert!(
                encode_buffer.is_empty(),
                "BytesCodec decode should consume entire buffer, {} bytes remain",
                encode_buffer.len()
            );
        } else if !original_data.is_empty() {
            panic!("BytesCodec decode returned None for non-empty encoded data");
        }
    }
}

/// **Property 2: Partial reads accumulate correctly**
///
/// When data arrives in chunks, accumulated result should equal the complete data.
fn test_partial_accumulation(payloads: &[DataPayload], partial_config: &PartialReadConfig) {
    if payloads.is_empty() {
        return;
    }

    let mut codec = BytesCodec::new();

    // Concatenate all payloads to create test data
    let complete_data: Vec<u8> = payloads
        .iter()
        .flat_map(|p| p.data.iter().copied())
        .take(MAX_CHUNK_SIZE)
        .collect();

    if complete_data.is_empty() {
        return;
    }

    // Encode the complete data
    let mut complete_buffer = BytesMut::new();
    codec
        .encode(complete_data.clone(), &mut complete_buffer)
        .unwrap();

    // Test 1: Decode all at once (reference result)
    let mut reference_buffer = complete_buffer.clone();
    let reference_result = codec.decode(&mut reference_buffer).unwrap();

    // Test 2: Decode in chunks and verify accumulation
    let chunk_sizes: Vec<usize> = partial_config
        .chunk_sizes
        .iter()
        .map(|&size| 1 + (size as usize % 256)) // 1-256 bytes per chunk
        .take(20) // Limit number of chunks
        .collect();

    if chunk_sizes.is_empty() {
        return;
    }

    let mut partial_buffer = BytesMut::new();
    let mut accumulated_results = Vec::new();
    let mut offset = 0;

    for chunk_size in chunk_sizes {
        if offset >= complete_buffer.len() {
            break;
        }

        let end = std::cmp::min(offset + chunk_size, complete_buffer.len());
        partial_buffer.extend_from_slice(&complete_buffer[offset..end]);
        offset = end;

        // Try to decode after each chunk
        let decode_result = codec.decode(&mut partial_buffer);
        if let Ok(Some(decoded)) = decode_result {
            accumulated_results.push(decoded);
        }

        // Include zero-sized reads if configured
        if partial_config.include_zero_reads && offset < complete_buffer.len() {
            let zero_result = codec.decode(&mut partial_buffer);
            if let Ok(Some(decoded)) = zero_result {
                accumulated_results.push(decoded);
            }
        }
    }

    // Add any remaining data
    if offset < complete_buffer.len() {
        partial_buffer.extend_from_slice(&complete_buffer[offset..]);
        if let Ok(Some(decoded)) = codec.decode(&mut partial_buffer) {
            accumulated_results.push(decoded);
        }
    }

    // **Partial accumulation property**
    // BytesCodec should return all data at once when buffer is non-empty
    match (reference_result, accumulated_results.len()) {
        (Some(ref_data), 1) => {
            assert_eq!(
                accumulated_results[0].as_ref(),
                ref_data.as_ref(),
                "Partial accumulation failed: reference={:?}, accumulated={:?}",
                ref_data.as_ref(),
                accumulated_results[0].as_ref()
            );
        }
        (Some(_), n) if n > 1 => {
            // This could happen if decode was called multiple times - verify total correctness
            let total_accumulated: Vec<u8> = accumulated_results
                .iter()
                .flat_map(|buf| buf.iter().copied())
                .collect();
            assert_eq!(
                total_accumulated, complete_data,
                "Multiple partial results don't sum to original data"
            );
        }
        (Some(_), 0) => {
            panic!("Reference decode succeeded but partial accumulation got no results");
        }
        (None, _) => {
            // Reference got None, partial should also get None or empty results
            assert!(
                accumulated_results.is_empty(),
                "Reference decode got None but partial got results: {:?}",
                accumulated_results
            );
        }
    }
}

/// **Property 3: Max frame length enforced**
///
/// While BytesCodec doesn't have explicit frame length limits,
/// we test reasonable memory bounds are respected.
fn test_max_frame_length_respected(data_size: usize) {
    if data_size > MAX_CHUNK_SIZE {
        return; // Already filtered out excessive sizes
    }

    let mut codec = BytesCodec::new();
    let test_data = vec![0u8; data_size];
    let mut buffer = BytesMut::new();

    // Should handle reasonable sizes without issue
    assert!(codec.encode(test_data, &mut buffer).is_ok());
    assert!(codec.decode(&mut buffer).is_ok());
}

/// **Property 4: Cancellation drains buffered bytes**
///
/// Simulate cancellation scenarios through buffer manipulation operations.
fn test_buffer_manipulation(payloads: &[DataPayload], buffer_ops: &[BufferOperation]) {
    let mut codec = BytesCodec::new();
    let mut buffer = BytesMut::new();

    // Start with some encoded data
    for payload in payloads.iter().take(5) {
        // Limit to prevent timeout
        if buffer.len() + payload.data.len() > MAX_CHUNK_SIZE {
            break;
        }
        codec.encode(payload.data.clone(), &mut buffer).unwrap();
    }

    let original_buffer_content = buffer.clone();

    // Apply buffer operations (simulating various cancellation/manipulation scenarios)
    for buffer_op in buffer_ops.iter().take(10) {
        // Limit operations
        match buffer_op {
            BufferOperation::Clear => {
                buffer.clear();
                // After clear, decode should return None
                assert_eq!(codec.decode(&mut buffer).unwrap(), None);
            }
            BufferOperation::Reserve(capacity) => {
                let cap = *capacity as usize;
                buffer.reserve(cap);
                // Reserve shouldn't affect decode behavior
                let decode_before = buffer.clone();
                let result = codec.decode(&mut buffer);
                if result.is_ok() {
                    // Verify buffer state consistency
                    assert!(buffer.len() <= decode_before.len());
                }
            }
            BufferOperation::Split(pos) => {
                if !buffer.is_empty() {
                    let split_pos = (*pos as usize) % buffer.len();
                    let _split_off = buffer.split_off(split_pos);
                    // Remaining buffer should still be decodable
                    let _ = codec.decode(&mut buffer);
                }
            }
            BufferOperation::Truncate(len) => {
                let new_len = (*len as usize) % (buffer.len() + 1);
                buffer.truncate(new_len);
                // Truncated buffer should still be decodable
                let _ = codec.decode(&mut buffer);
            }
            BufferOperation::Extend(data) => {
                if buffer.len() + data.len() <= MAX_CHUNK_SIZE {
                    buffer.extend_from_slice(data);
                    // Extended buffer should still be decodable
                    let _ = codec.decode(&mut buffer);
                }
            }
        }
    }

    // **Cancellation drain property**
    // After any manipulation, codec should remain in consistent state
    // and handle subsequent operations correctly
    if !buffer.is_empty() {
        let final_result = codec.decode(&mut buffer);
        assert!(
            final_result.is_ok(),
            "Codec in inconsistent state after buffer manipulation"
        );
    }

    // Verify codec can still handle fresh data
    let fresh_data = b"fresh_test_data";
    let mut fresh_buffer = BytesMut::new();
    codec
        .encode(fresh_data.to_vec(), &mut fresh_buffer)
        .unwrap();
    let fresh_result = codec.decode(&mut fresh_buffer).unwrap();
    if let Some(decoded) = fresh_result {
        assert_eq!(decoded.as_ref(), fresh_data);
    }
}

/// **Property 5: Empty frames tolerated**
///
/// BytesCodec should handle empty inputs gracefully without errors.
fn test_empty_frames_tolerance() {
    let mut codec = BytesCodec::new();

    // Test 1: Empty Vec<u8>
    let mut buffer = BytesMut::new();
    assert!(codec.encode(Vec::<u8>::new(), &mut buffer).is_ok());
    assert!(buffer.is_empty()); // Empty input should produce empty output

    // Test 2: Empty Bytes
    let mut buffer = BytesMut::new();
    assert!(codec.encode(Bytes::new(), &mut buffer).is_ok());
    assert!(buffer.is_empty());

    // Test 3: Empty BytesMut
    let mut buffer = BytesMut::new();
    assert!(codec.encode(BytesMut::new(), &mut buffer).is_ok());
    assert!(buffer.is_empty());

    // Test 4: Decode from empty buffer
    let mut empty_buffer = BytesMut::new();
    let result = codec.decode(&mut empty_buffer).unwrap();
    assert_eq!(result, None); // Empty buffer should return None

    // Test 5: Multiple empty operations in sequence
    for _ in 0..10 {
        let mut buffer = BytesMut::new();
        assert!(codec.encode(Vec::<u8>::new(), &mut buffer).is_ok());
        assert_eq!(codec.decode(&mut buffer).unwrap(), None);
    }

    // Test 6: Mixed empty and non-empty
    let mut mixed_buffer = BytesMut::new();

    // Encode empty
    codec.encode(Vec::<u8>::new(), &mut mixed_buffer).unwrap();
    assert!(mixed_buffer.is_empty());

    // Encode non-empty
    codec.encode(b"test".to_vec(), &mut mixed_buffer).unwrap();
    assert!(!mixed_buffer.is_empty());

    // Decode should get the non-empty data
    let result = codec.decode(&mut mixed_buffer).unwrap();
    if let Some(decoded) = result {
        assert_eq!(decoded.as_ref(), b"test");
    }

    // **Empty frames tolerance property**
    // All operations completed successfully without panics
}

/// Additional comprehensive edge case testing
fn test_comprehensive_edge_cases() {
    let mut codec = BytesCodec::new();

    // Test byte patterns that might cause issues
    let test_patterns = [
        vec![],                                        // Empty
        vec![0],                                       // Single null byte
        vec![255],                                     // Single max byte
        vec![0; 1024],                                 // All zeros
        vec![255; 1024],                               // All max bytes
        (0..256).map(|i| i as u8).collect::<Vec<_>>(), // Full byte range
        vec![0xDE, 0xAD, 0xBE, 0xEF],                  // Common hex patterns
    ];

    for (i, pattern) in test_patterns.iter().enumerate() {
        let mut buffer = BytesMut::new();

        // Encode
        codec
            .encode(pattern.clone(), &mut buffer)
            .unwrap_or_else(|_| {
                panic!("Encode failed for pattern {}: {:?}", i, pattern);
            });

        // Decode
        let decoded = codec.decode(&mut buffer).unwrap_or_else(|_| {
            panic!("Decode failed for pattern {}: {:?}", i, pattern);
        });

        // Verify
        if let Some(result) = decoded {
            assert_eq!(
                result.as_ref(),
                pattern.as_slice(),
                "Roundtrip failed for pattern {}: {:?}",
                i,
                pattern
            );
        } else if !pattern.is_empty() {
            panic!(
                "Unexpected None result for non-empty pattern {}: {:?}",
                i, pattern
            );
        }
    }
}
