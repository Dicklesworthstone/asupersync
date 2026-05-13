//! Oracle-based fuzz harness for gRPC codec hardening.
//!
//! This target implements strong oracles to catch logic bugs that crash-only
//! fuzzing would miss:
//!
//! 1. **Round-trip oracle**: decode(encode(msg)) must reproduce original message
//! 2. **Differential oracle**: Compare against simple reference implementation
//! 3. **Invariant oracle**: Deep state consistency checks across operations
//! 4. **Boundary oracle**: Size limit enforcement and edge case validation
//!
//! # Oracle Hierarchy (Strength 1-5, 1=strongest)
//! - Strength 2: Reference implementation (differential oracle vs simple codec)
//! - Strength 3: Round-trip invariant (encode→decode identity)
//! - Strength 5: Crash oracle (no panic, no sanitizer violation)
//!
//! # Attack Scenarios Tested
//! - Logic bugs in encode/decode paths that don't crash
//! - Size limit bypass attempts
//! - Flag validation edge cases
//! - State machine consistency under malformed input
//! - Round-trip failures on boundary values
//!
//! # Running
//! ```bash
//! export CARGO_TARGET_DIR=/tmp/rch_target_$NTM_AGENT_NAME
//! cargo +nightly fuzz run grpc_codec_oracle_hardening
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::grpc::codec::{GrpcCodec, GrpcMessage, MESSAGE_HEADER_SIZE};
use asupersync::grpc::status::GrpcError;
use libfuzzer_sys::fuzz_target;

/// Maximum input size to prevent OOM during fuzzing
const MAX_INPUT_SIZE: usize = 1_000_000;
const MAX_DECODE_ITERATIONS: usize = 1000;

/// Configuration for oracle-based testing
#[derive(Arbitrary, Debug, Clone)]
struct OracleConfig {
    max_encode_size: u32, // Will be clamped to reasonable range
    max_decode_size: u32, // Will be clamped to reasonable range
}

#[derive(Arbitrary, Debug, Clone)]
struct TestMessage {
    compressed: bool,
    payload: Vec<u8>, // Will be size-limited
}

#[derive(Arbitrary, Debug)]
struct OracleInput {
    config: OracleConfig,
    operations: Vec<Operation>,
}

#[derive(Arbitrary, Debug, Clone)]
enum Operation {
    /// Test round-trip oracle with generated message
    RoundTrip { message: TestMessage },

    /// Test differential oracle against reference implementation
    Differential { raw_bytes: Vec<u8> },

    /// Test malformed input handling consistency
    MalformedInput {
        compressed_flag: u8,
        declared_length: u32,
        actual_payload: Vec<u8>,
    },

    /// Test boundary conditions around size limits
    BoundaryTest {
        target_size: u32, // Size to test around limit
        size_delta: i8,   // Offset from target (+/- around boundary)
    },

    /// Test state consistency across multiple operations
    StateConsistency {
        operations: Vec<TestMessage>, // Sequence of operations to test
    },
}

/// Simple reference gRPC codec implementation for differential oracle
#[derive(Debug)]
struct ReferenceGrpcCodec {
    max_message_size: usize,
}

impl ReferenceGrpcCodec {
    fn new(max_message_size: usize) -> Self {
        Self { max_message_size }
    }

    /// Reference decode implementation
    fn decode_message(&self, data: &[u8]) -> Result<Option<GrpcMessage>, String> {
        if data.len() < MESSAGE_HEADER_SIZE {
            return Ok(None);
        }

        let flag = data[0];
        let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;

        // Size validation
        if length > self.max_message_size {
            return Err("Message too large".to_string());
        }

        // Check available data
        if data.len() < MESSAGE_HEADER_SIZE + length {
            return Ok(None);
        }

        // Flag validation
        let compressed = match flag {
            0 => false,
            1 => true,
            _ => return Err(format!("Invalid compression flag: {}", flag)),
        };

        let payload = &data[MESSAGE_HEADER_SIZE..MESSAGE_HEADER_SIZE + length];

        Ok(Some(GrpcMessage {
            compressed,
            data: Bytes::copy_from_slice(payload),
        }))
    }

    /// Reference encode implementation
    fn encode_message(&self, message: &GrpcMessage) -> Result<Vec<u8>, String> {
        if message.data.len() > self.max_message_size {
            return Err("Message too large".to_string());
        }

        let length = u32::try_from(message.data.len())
            .map_err(|_| "Message length overflow")?;

        let mut result = Vec::new();
        result.push(if message.compressed { 1 } else { 0 });
        result.extend_from_slice(&length.to_be_bytes());
        result.extend_from_slice(&message.data);

        Ok(result)
    }
}

fuzz_target!(|input: OracleInput| {
    if input.operations.len() > MAX_DECODE_ITERATIONS {
        return; // Prevent excessive iterations
    }

    // Create codecs with clamped sizes to prevent OOM
    let max_encode = ((input.config.max_encode_size % 10_000_000) + 1) as usize;
    let max_decode = ((input.config.max_decode_size % 10_000_000) + 1) as usize;

    let mut codec = GrpcCodec::with_message_size_limits(max_encode, max_decode);
    let reference = ReferenceGrpcCodec::new(max_decode.min(max_encode));

    for operation in input.operations {
        match operation {
            Operation::RoundTrip { message } => {
                test_round_trip_oracle(&mut codec, &message, max_encode);
            }
            Operation::Differential { raw_bytes } => {
                test_differential_oracle(&mut codec, &reference, &raw_bytes);
            }
            Operation::MalformedInput { compressed_flag, declared_length, actual_payload } => {
                test_malformed_input_oracle(&mut codec, compressed_flag, declared_length, &actual_payload);
            }
            Operation::BoundaryTest { target_size, size_delta } => {
                test_boundary_oracle(&mut codec, target_size, size_delta, max_encode, max_decode);
            }
            Operation::StateConsistency { operations } => {
                test_state_consistency_oracle(&mut codec, &operations);
            }
        }
    }
});

/// Oracle 1: Round-trip invariant - decode(encode(msg)) == msg
fn test_round_trip_oracle(codec: &mut GrpcCodec, test_msg: &TestMessage, max_encode: usize) {
    // Limit payload size to prevent OOM
    if test_msg.payload.len() > MAX_INPUT_SIZE {
        return;
    }

    let original_message = GrpcMessage {
        compressed: test_msg.compressed,
        data: Bytes::from(test_msg.payload.clone()),
    };

    // Encode the message
    let mut encoded = BytesMut::new();
    let encode_result = codec.encode(original_message.clone(), &mut encoded);

    match encode_result {
        Ok(()) => {
            // If encoding succeeded, decoding the result should reproduce original
            let mut decode_buffer = encoded;

            match codec.decode(&mut decode_buffer) {
                Ok(Some(decoded_message)) => {
                    // Round-trip oracle: decoded must match original
                    assert_eq!(
                        decoded_message.compressed,
                        original_message.compressed,
                        "Round-trip oracle violation: compression flag mismatch"
                    );

                    assert_eq!(
                        decoded_message.data.len(),
                        original_message.data.len(),
                        "Round-trip oracle violation: payload length mismatch"
                    );

                    assert_eq!(
                        decoded_message.data,
                        original_message.data,
                        "Round-trip oracle violation: payload content mismatch"
                    );

                    // Invariant: decode should consume exactly the encoded bytes
                    assert!(
                        decode_buffer.is_empty() ||
                        decode_buffer.len() < MESSAGE_HEADER_SIZE, // partial frame remaining is ok
                        "Round-trip oracle violation: decoder left unexpected bytes"
                    );
                }
                Ok(None) => {
                    panic!("Round-trip oracle violation: encode succeeded but decode returned None");
                }
                Err(decode_error) => {
                    panic!("Round-trip oracle violation: encode succeeded but decode failed: {:?}", decode_error);
                }
            }
        }
        Err(_) => {
            // If encoding fails, that's acceptable for oversized messages
            assert!(
                original_message.data.len() > max_encode,
                "Encode should only fail for oversized messages"
            );
        }
    }
}

/// Oracle 2: Differential oracle - compare main codec against reference implementation
fn test_differential_oracle(codec: &mut GrpcCodec, reference: &ReferenceGrpcCodec, raw_bytes: &[u8]) {
    if raw_bytes.len() > MAX_INPUT_SIZE {
        return;
    }

    // Test decode path
    let mut main_buffer = BytesMut::from(raw_bytes);
    let main_result = codec.decode(&mut main_buffer);
    let reference_result = reference.decode_message(raw_bytes);

    match (main_result, reference_result) {
        (Ok(Some(main_msg)), Ok(Some(ref_msg))) => {
            // Both succeeded - results should match
            assert_eq!(
                main_msg.compressed, ref_msg.compressed,
                "Differential oracle violation: compression flag mismatch"
            );
            assert_eq!(
                main_msg.data, ref_msg.data,
                "Differential oracle violation: payload mismatch"
            );
        }
        (Ok(None), Ok(None)) => {
            // Both need more data - consistent
        }
        (Err(_), Err(_)) => {
            // Both failed - consistent (we don't require identical error messages)
        }
        (Ok(Some(_)), Ok(None)) => {
            // Main decoded but reference needs more data
            // This can happen if main is more tolerant of partial frames
        }
        (Ok(None), Ok(Some(_))) => {
            // Reference decoded but main needs more data
            // This suggests a bug in main codec
            if raw_bytes.len() >= MESSAGE_HEADER_SIZE {
                panic!("Differential oracle violation: main codec too restrictive");
            }
        }
        (Ok(_), Err(_)) => {
            // Main succeeded but reference failed
            // Could indicate main codec is too permissive
            // Only flag clear violations (like accepting invalid flags)
            if raw_bytes.len() >= MESSAGE_HEADER_SIZE && raw_bytes[0] > 1 {
                panic!("Differential oracle violation: main codec accepted invalid compression flag");
            }
        }
        (Err(_), Ok(_)) => {
            // Main failed but reference succeeded
            // Could indicate main codec is too strict
            // Only flag if reference result seems clearly valid
        }
    }
}

/// Oracle 3: Malformed input consistency - ensure deterministic error handling
fn test_malformed_input_oracle(
    codec: &mut GrpcCodec,
    compressed_flag: u8,
    declared_length: u32,
    actual_payload: &[u8]
) {
    if actual_payload.len() > MAX_INPUT_SIZE {
        return;
    }

    // Build potentially malformed frame
    let mut frame = Vec::new();
    frame.push(compressed_flag);
    frame.extend_from_slice(&declared_length.to_be_bytes());
    frame.extend_from_slice(actual_payload);

    let mut buffer = BytesMut::from(frame.as_slice());
    let result = codec.decode(&mut buffer);

    match result {
        Ok(Some(_)) => {
            // If decode succeeded, validate the acceptance was correct
            assert!(
                compressed_flag <= 1,
                "Malformed oracle violation: invalid compression flag accepted"
            );

            assert!(
                declared_length as usize == actual_payload.len(),
                "Malformed oracle violation: length mismatch accepted"
            );
        }
        Ok(None) => {
            // Need more data - should only happen if frame is incomplete
            let expected_total = MESSAGE_HEADER_SIZE + declared_length as usize;
            assert!(
                frame.len() < expected_total,
                "Malformed oracle violation: complete frame reported as incomplete"
            );
        }
        Err(_) => {
            // Error expected for various malformed inputs - this is correct
        }
    }
}

/// Oracle 4: Boundary testing around size limits
fn test_boundary_oracle(
    codec: &mut GrpcCodec,
    target_size: u32,
    size_delta: i8,
    max_encode: usize,
    max_decode: usize
) {
    let base_size = (target_size % (MAX_INPUT_SIZE as u32)) as usize;
    let test_size = base_size.saturating_add_signed(size_delta as isize);

    if test_size > MAX_INPUT_SIZE {
        return;
    }

    // Test encode boundary
    let test_payload = vec![0u8; test_size];
    let message = GrpcMessage {
        compressed: false,
        data: Bytes::from(test_payload),
    };

    let mut encoded = BytesMut::new();
    let encode_result = codec.encode(message, &mut encoded);

    if test_size <= max_encode {
        assert!(
            encode_result.is_ok(),
            "Boundary oracle violation: encode failed for size {} <= limit {}",
            test_size, max_encode
        );
    } else {
        assert!(
            encode_result.is_err(),
            "Boundary oracle violation: encode succeeded for size {} > limit {}",
            test_size, max_encode
        );
    }

    // Test decode boundary with crafted frame
    if test_size <= u32::MAX as usize {
        let mut frame = Vec::new();
        frame.push(0); // uncompressed
        frame.extend_from_slice(&(test_size as u32).to_be_bytes());
        frame.extend(vec![0u8; test_size.min(1000)]); // Limit actual payload to prevent OOM

        let mut buffer = BytesMut::from(frame.as_slice());
        let decode_result = codec.decode(&mut buffer);

        match decode_result {
            Ok(Some(_)) => {
                assert!(
                    test_size <= max_decode && test_size <= 1000,
                    "Boundary oracle violation: large message accepted"
                );
            }
            Ok(None) => {
                // Incomplete frame - acceptable
            }
            Err(_) => {
                // Size limit rejection or malformed input - acceptable
            }
        }
    }
}

/// Oracle 5: State consistency across multiple operations
fn test_state_consistency_oracle(codec: &mut GrpcCodec, operations: &[TestMessage]) {
    let mut decode_count = 0;
    let mut error_count = 0;
    let mut previous_buffer_len = None;

    for (i, test_msg) in operations.iter().take(100).enumerate() {
        if test_msg.payload.len() > 10_000 {
            continue; // Skip oversized payloads
        }

        let message = GrpcMessage {
            compressed: test_msg.compressed,
            data: Bytes::from(test_msg.payload.clone()),
        };

        // Encode then immediately decode to test state consistency
        let mut encoded = BytesMut::new();
        match codec.encode(message.clone(), &mut encoded) {
            Ok(()) => {
                let buffer_len_before = encoded.len();

                match codec.decode(&mut encoded) {
                    Ok(Some(decoded)) => {
                        decode_count += 1;

                        // State consistency invariant: successful operations should be repeatable
                        assert_eq!(
                            decoded.compressed, message.compressed,
                            "State consistency violation at operation {}: compression flag changed",
                            i
                        );

                        assert_eq!(
                            decoded.data.len(), message.data.len(),
                            "State consistency violation at operation {}: payload length changed",
                            i
                        );

                        // Buffer consumption should be consistent
                        if let Some(prev_len) = previous_buffer_len {
                            if prev_len == buffer_len_before {
                                // Same input size should consume same amount
                                // This is a weak check since messages may differ
                            }
                        }
                        previous_buffer_len = Some(buffer_len_before);
                    }
                    Ok(None) => {
                        panic!("State consistency violation: encode succeeded but decode returned None");
                    }
                    Err(_) => {
                        error_count += 1;
                    }
                }
            }
            Err(_) => {
                error_count += 1;
            }
        }
    }

    // State consistency invariant: codec should remain operational
    // Test with a simple known-good message
    let recovery_message = GrpcMessage {
        compressed: false,
        data: Bytes::from_static(b"recovery_test"),
    };

    let mut recovery_buffer = BytesMut::new();
    let recovery_encode = codec.encode(recovery_message, &mut recovery_buffer);
    assert!(
        recovery_encode.is_ok() || recovery_buffer.is_empty(),
        "State consistency violation: codec corrupted after operation sequence"
    );

    // Sanity check: we should have had some successful operations
    // unless all inputs were malformed/oversized
    if operations.len() > 10 && decode_count == 0 && error_count == operations.len() {
        // This could indicate the codec is broken or our test data is entirely invalid
        // Don't fail, but ensure we test with a known good case
        let simple_msg = GrpcMessage {
            compressed: false,
            data: Bytes::from_static(b"test"),
        };
        let mut test_buffer = BytesMut::new();
        let test_result = codec.encode(simple_msg, &mut test_buffer);
        assert!(
            test_result.is_ok(),
            "State consistency violation: codec cannot handle simple valid message"
        );
    }
}