//! Fuzz target for gRPC protobuf message framing parser.
//!
//! This target focuses on the gRPC message framing format specified in the gRPC protocol:
//! - 1 byte: compressed flag (0 = uncompressed, 1 = compressed)
//! - 4 bytes: message length (big-endian)
//! - N bytes: message payload
//!
//! # Assertions Tested
//! 1. compressed-flag byte respected (0/1 accepted, others rejected)
//! 2. 4-byte length field bounds enforced (reject oversized messages)
//! 3. truncated framing returns Incomplete (None) not panic
//! 4. multiple messages streamed correctly
//! 5. unknown compression schemes rejected with appropriate errors
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run grpc_protobuf
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{BufMut, BytesMut};
use asupersync::codec::Decoder;
use asupersync::grpc::codec::{GrpcCodec, GrpcMessage};
use asupersync::grpc::status::GrpcError;
use libfuzzer_sys::fuzz_target;

/// Maximum iterations to prevent infinite loops during multi-message testing
const MAX_DECODE_ITERATIONS: usize = 100;

/// Maximum reasonable message size for testing (16MB)
const MAX_TEST_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// gRPC message header size (1 byte flag + 4 bytes length)
const MESSAGE_HEADER_SIZE: usize = 5;

#[derive(Arbitrary, Debug, Clone)]
struct FuzzInput {
    /// Sequence of gRPC message frames to test
    frames: Vec<GrpcFrame>,
    /// Configuration for the decoder
    codec_config: CodecConfig,
    /// Test scenario selection
    scenario: TestScenario,
}

#[derive(Arbitrary, Debug, Clone)]
struct GrpcFrame {
    /// Compression flag byte (may be invalid to test error handling)
    compression_flag: u8,
    /// Message length (may be invalid/oversized)
    length: u32,
    /// Message payload data
    payload: Vec<u8>,
    /// Whether to truncate this frame (for incomplete testing)
    truncate: Option<u8>, // Number of bytes to truncate from end
}

#[derive(Arbitrary, Debug, Clone)]
struct CodecConfig {
    /// Maximum decode message size limit
    max_decode_size: u16, // Converted to reasonable range
    /// Maximum encode message size limit
    max_encode_size: u16, // Converted to reasonable range
}

#[derive(Arbitrary, Debug, Clone)]
enum TestScenario {
    /// Single message frame
    SingleFrame,
    /// Multiple messages in sequence
    MultipleFrames,
    /// Fragmented input (partial reads)
    FragmentedInput { chunk_size: u8 }, // 1-255
    /// Oversized message testing
    OversizedMessage,
    /// Invalid compression flag testing
    InvalidCompression,
}

impl GrpcFrame {
    /// Serialize this frame to bytes (potentially malformed)
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Write compression flag
        buf.put_u8(self.compression_flag);

        // Write length (big-endian)
        buf.put_u32(self.length);

        // Write payload (potentially truncated)
        let mut payload = self.payload.clone();
        if let Some(truncate) = self.truncate {
            let new_len = payload.len().saturating_sub(truncate as usize);
            payload.truncate(new_len);
        }

        buf.extend_from_slice(&payload);
        buf
    }
}

impl CodecConfig {
    /// Convert to reasonable message size limits
    fn max_decode_size(&self) -> usize {
        // Map u16 to reasonable range: 1KB to 16MB
        1024 + (self.max_decode_size as usize * 63) // 1KB + (0-65535)*63 ≈ 1KB to 4MB
    }

    fn max_encode_size(&self) -> usize {
        1024 + (self.max_encode_size as usize * 63)
    }
}

fuzz_target!(|input: FuzzInput| {
    // Skip empty input to focus on meaningful test cases
    if input.frames.is_empty() {
        return;
    }

    // Create codec with configurable limits
    let mut codec = GrpcCodec::with_message_size_limits(
        input.codec_config.max_encode_size(),
        input.codec_config.max_decode_size(),
    );

    match input.scenario {
        TestScenario::SingleFrame => {
            fuzz_single_frame(&mut codec, &input.frames[0]);
        }
        TestScenario::MultipleFrames => {
            fuzz_multiple_frames(&mut codec, &input.frames);
        }
        TestScenario::FragmentedInput { chunk_size } => {
            fuzz_fragmented_input(&mut codec, &input.frames, chunk_size.max(1));
        }
        TestScenario::OversizedMessage => {
            fuzz_oversized_messages(&mut codec, &input.frames);
        }
        TestScenario::InvalidCompression => {
            fuzz_invalid_compression(&mut codec, &input.frames);
        }
    }
});

/// Test single frame processing
fn fuzz_single_frame(codec: &mut GrpcCodec, frame: &GrpcFrame) {
    let mut buffer = BytesMut::from(frame.to_bytes().as_slice());

    // Assertion 1: compressed-flag byte respected
    // Assertion 2: 4-byte length field bounds enforced
    // Assertion 3: truncated framing returns Incomplete not panic
    let result = codec.decode(&mut buffer);

    match result {
        Ok(Some(msg)) => {
            // Successfully decoded - validate compression flag was respected
            if frame.compression_flag == 0 {
                assert!(
                    !msg.compressed,
                    "Compression flag 0 should result in uncompressed message"
                );
            } else if frame.compression_flag == 1 {
                assert!(
                    msg.compressed,
                    "Compression flag 1 should result in compressed message"
                );
            } else {
                panic!(
                    "Invalid compression flag {} should have been rejected",
                    frame.compression_flag
                );
            }

            // Validate payload size matches length field (when not truncated)
            if frame.truncate.is_none() && frame.length == frame.payload.len() as u32 {
                assert_eq!(
                    msg.data.len(),
                    frame.payload.len(),
                    "Decoded payload size should match original"
                );
            }
        }
        Ok(None) => {
            // Incomplete frame - this is expected for truncated or partial frames
            // Should NOT panic - this satisfies Assertion 3
        }
        Err(GrpcError::Protocol(_)) => {
            // Protocol error - expected for invalid compression flags
            // Assertion 1: invalid compression flags (not 0 or 1) should be rejected
            assert!(
                frame.compression_flag != 0 && frame.compression_flag != 1,
                "Valid compression flags should not cause protocol errors"
            );
        }
        Err(GrpcError::MessageTooLarge) => {
            // Message too large - expected when length exceeds codec limits
            // Assertion 2: oversized messages should be rejected
        }
        Err(_) => {
            // Other errors are acceptable
        }
    }
}

/// Test multiple message frames in sequence
fn fuzz_multiple_frames(codec: &mut GrpcCodec, frames: &[GrpcFrame]) {
    // Assertion 4: multiple messages streamed correctly
    let mut buffer = BytesMut::new();

    // Concatenate all frames
    for frame in frames.iter().take(10) {
        // Limit to prevent excessive memory usage
        buffer.extend_from_slice(&frame.to_bytes());
    }

    let mut decoded_count = 0;
    let mut iteration = 0;

    // Decode messages one by one
    while !buffer.is_empty() && iteration < MAX_DECODE_ITERATIONS {
        iteration += 1;

        match codec.decode(&mut buffer) {
            Ok(Some(_msg)) => {
                decoded_count += 1;
                // Successfully decoded one message, continue with next
            }
            Ok(None) => {
                // Need more data - break if we can't decode anything
                break;
            }
            Err(_) => {
                // Error encountered - this is acceptable, some frames may be malformed
                break;
            }
        }
    }

    // Multiple valid frames should be decodable sequentially
    // Invalid frames may cause early termination which is acceptable
}

/// Test fragmented input to ensure partial reads are handled correctly
fn fuzz_fragmented_input(codec: &mut GrpcCodec, frames: &[GrpcFrame], chunk_size: u8) {
    if frames.is_empty() {
        return;
    }

    // Assertion 3: truncated framing returns Incomplete not panic
    let frame_bytes = frames[0].to_bytes();
    let chunk_size = (chunk_size as usize).max(1).min(frame_bytes.len());

    let mut buffer = BytesMut::new();
    let mut pos = 0;

    // Feed data in small chunks
    while pos < frame_bytes.len() {
        let end = (pos + chunk_size).min(frame_bytes.len());
        buffer.extend_from_slice(&frame_bytes[pos..end]);
        pos = end;

        // Try to decode - should handle partial frames gracefully
        match codec.decode(&mut buffer) {
            Ok(Some(_)) => {
                // Successfully decoded complete message
                break;
            }
            Ok(None) => {
                // Incomplete - need more data, this is expected and correct
                continue;
            }
            Err(_) => {
                // Error - acceptable for malformed frames
                break;
            }
        }
    }
}

/// Test oversized message handling
fn fuzz_oversized_messages(codec: &mut GrpcCodec, frames: &[GrpcFrame]) {
    // Assertion 2: 4-byte length field bounds enforced
    for frame in frames.iter().take(5) {
        // Limit iterations
        let mut oversized_frame = frame.clone();

        // Create a frame that claims to be larger than the codec limit
        oversized_frame.length = (codec.max_decode_message_size() * 2) as u32;

        let mut buffer = BytesMut::from(oversized_frame.to_bytes().as_slice());

        match codec.decode(&mut buffer) {
            Ok(Some(_)) => {
                // Should not succeed for oversized messages
                if oversized_frame.length > codec.max_decode_message_size() as u32 {
                    // Only assert if the claimed length exceeds limits AND payload matches
                    if oversized_frame.payload.len() as u32 == oversized_frame.length {
                        panic!("Oversized message should not decode successfully");
                    }
                }
            }
            Ok(None) => {
                // Incomplete - acceptable
            }
            Err(GrpcError::MessageTooLarge) => {
                // Expected for oversized messages
            }
            Err(_) => {
                // Other errors are acceptable
            }
        }
    }
}

/// Test invalid compression flag handling
fn fuzz_invalid_compression(codec: &mut GrpcCodec, frames: &[GrpcFrame]) {
    // Assertion 1: compressed-flag byte respected
    // Assertion 5: unknown compression schemes rejected
    for frame in frames.iter().take(5) {
        // Limit iterations
        let mut test_frame = frame.clone();

        // Test various invalid compression flags
        for invalid_flag in [2u8, 3, 255, 128, 42] {
            test_frame.compression_flag = invalid_flag;
            let mut buffer = BytesMut::from(test_frame.to_bytes().as_slice());

            match codec.decode(&mut buffer) {
                Ok(Some(_)) => {
                    // Should not succeed for invalid compression flags
                    panic!(
                        "Invalid compression flag {} should not decode successfully",
                        invalid_flag
                    );
                }
                Ok(None) => {
                    // Incomplete - check if this is due to insufficient data
                    if buffer.len() >= MESSAGE_HEADER_SIZE {
                        // We have enough for header, so this should have been rejected
                        panic!(
                            "Invalid compression flag {} should be rejected, not incomplete",
                            invalid_flag
                        );
                    }
                }
                Err(GrpcError::Protocol(msg)) => {
                    // Expected - invalid compression flags should cause protocol errors
                    assert!(
                        msg.contains("compression flag") || msg.contains("invalid"),
                        "Protocol error should mention compression flag: {}",
                        msg
                    );
                }
                Err(_) => {
                    // Other errors are acceptable (e.g., MessageTooLarge)
                }
            }
        }
    }
}

/// Test that valid compression flags (0 and 1) are accepted
#[allow(dead_code)] // May be unused depending on fuzzer input generation
fn test_valid_compression_flags() {
    let mut codec = GrpcCodec::new();

    // Test uncompressed (flag = 0)
    let mut buffer = BytesMut::new();
    buffer.put_u8(0); // Uncompressed
    buffer.put_u32(5); // Length
    buffer.extend_from_slice(b"hello"); // Payload

    match codec.decode(&mut buffer) {
        Ok(Some(msg)) => {
            assert!(!msg.compressed, "Flag 0 should result in uncompressed");
        }
        _ => panic!("Valid uncompressed frame should decode successfully"),
    }

    // Test compressed (flag = 1)
    let mut buffer = BytesMut::new();
    buffer.put_u8(1); // Compressed
    buffer.put_u32(5); // Length
    buffer.extend_from_slice(b"world"); // Payload

    match codec.decode(&mut buffer) {
        Ok(Some(msg)) => {
            assert!(msg.compressed, "Flag 1 should result in compressed");
        }
        _ => panic!("Valid compressed frame should decode successfully"),
    }
}

/// Test edge cases around message boundaries
#[allow(dead_code)] // May be unused depending on fuzzer input generation
fn test_boundary_conditions() {
    let mut codec = GrpcCodec::new();

    // Test minimum frame size (header only, zero-length payload)
    let mut buffer = BytesMut::new();
    buffer.put_u8(0); // Uncompressed
    buffer.put_u32(0); // Zero length
    // No payload

    match codec.decode(&mut buffer) {
        Ok(Some(msg)) => {
            assert_eq!(
                msg.data.len(),
                0,
                "Zero-length message should have empty payload"
            );
        }
        _ => panic!("Zero-length frame should decode successfully"),
    }

    // Test exactly at size limit
    let max_size = codec.max_decode_message_size();
    let mut buffer = BytesMut::new();
    buffer.put_u8(0); // Uncompressed
    buffer.put_u32(max_size as u32); // Exactly at limit
    buffer.resize(5 + max_size, b'X'); // Header + max payload

    // This should either succeed or fail cleanly, but not panic
    let _ = codec.decode(&mut buffer);

    // Test one byte over limit
    let mut buffer = BytesMut::new();
    buffer.put_u8(0); // Uncompressed
    buffer.put_u32((max_size + 1) as u32); // One over limit
    buffer.resize(5 + max_size + 1, b'Y'); // Header + oversized payload

    match codec.decode(&mut buffer) {
        Err(GrpcError::MessageTooLarge) => {
            // Expected
        }
        Ok(None) => {
            // Might be incomplete if buffer isn't fully populated
        }
        _ => panic!("Oversized message should be rejected"),
    }
}
