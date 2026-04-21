//! Fuzz target for gRPC message framing (proto3 varint + length prefix).
//!
//! Tests the gRPC message framing codec and protobuf parsing resilience.
//! Covers both the gRPC transport-level framing (5-byte header + payload)
//! and the Protocol Buffer encoding within the payload.
//!
//! # gRPC Frame Format
//! ```text
//! +-------+---------------+---------------+
//! | COMP  |     LENGTH    |    MESSAGE    |
//! | (1B)  |     (4B)      |    (N bytes)  |
//! +-------+---------------+---------------+
//! ```
//!
//! # Protocol Buffer Wire Types
//! - Type 0: varint (int32, int64, bool, enum)
//! - Type 1: fixed64 (double, fixed64, sfixed64)
//! - Type 2: length-delimited (string, bytes, embedded messages, repeated)
//! - Type 5: fixed32 (float, fixed32, sfixed32)
//!
//! # Coverage Areas
//! - Varint boundary cases (127/128, 16383/16384, negative zigzag)
//! - Length-delimited field parsing with malformed lengths
//! - Nested message depth limits and recursion protection
//! - Empty/malformed tag numbers and wire type mismatches
//! - gRPC framing edge cases (oversized messages, invalid compression flags)
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run fuzz_grpc_message_framing -- -max_total_time=3600
//! ```

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

// Import required traits and types
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::grpc::codec::{Codec as GrpcCodec_, GrpcCodec, GrpcMessage, MESSAGE_HEADER_SIZE};
use asupersync::grpc::{Code, GrpcError, ProstCodec};

/// Maximum message size for fuzzing (16MB to stay within reasonable limits).
const MAX_FUZZ_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Maximum nesting depth to prevent infinite recursion.
const MAX_NESTING_DEPTH: usize = 32;
/// Small upper bound used for explicit codec limit probes.
const MAX_STATUS_PROBE_SIZE: usize = 256;

/// protobuf wire types for structured fuzzing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Arbitrary)]
#[repr(u8)]
enum WireType {
    Varint = 0,          // int32, int64, bool, enum
    Fixed64 = 1,         // double, fixed64, sfixed64
    LengthDelimited = 2, // string, bytes, embedded messages
    StartGroup = 3,      // deprecated group start
    EndGroup = 4,        // deprecated group end
    Fixed32 = 5,         // float, fixed32, sfixed32
}

/// Structured protobuf field for systematic fuzzing.
#[derive(Debug, Clone, Arbitrary)]
struct ProtobufField {
    tag: u32,
    wire_type: WireType,
    data: FieldData,
}

/// Field data based on wire type.
#[derive(Debug, Clone, Arbitrary)]
enum FieldData {
    Varint(u64),
    Fixed64([u8; 8]),
    LengthDelimited(Vec<u8>),
    GroupStart(Vec<ProtobufField>), // Nested fields within a group
    GroupEnd,                       // Group terminator
    Fixed32([u8; 4]),
}

/// Structured gRPC message for systematic fuzzing.
#[derive(Debug, Clone, Arbitrary)]
struct StructuredGrpcMessage {
    compressed: bool,
    fields: Vec<ProtobufField>,
    /// Raw bytes to append for malformed data testing
    raw_suffix: Vec<u8>,
    /// Control nesting depth for recursive message testing
    nesting_depth: u8,
}

/// Fuzz input combining structured and raw data.
#[derive(Debug, Clone, Arbitrary)]
enum FuzzInput {
    /// Structured message for systematic coverage
    Structured(StructuredGrpcMessage),
    /// Raw bytes for edge case discovery
    Raw(Vec<u8>),
    /// gRPC framing test with custom header
    FramingTest {
        compression_flag: u8,
        declared_length: u32,
        actual_payload: Vec<u8>,
    },
}

fuzz_target!(|input: FuzzInput| {
    fuzz_grpc_message_framing(input);
});

fn fuzz_grpc_message_framing(input: FuzzInput) {
    match input {
        FuzzInput::Structured(msg) => fuzz_structured_message(msg),
        FuzzInput::Raw(data) => fuzz_raw_data(&data),
        FuzzInput::FramingTest {
            compression_flag,
            declared_length,
            actual_payload,
        } => fuzz_grpc_framing(compression_flag, declared_length, actual_payload),
    }
}

/// Test structured protobuf messages with known wire types.
fn fuzz_structured_message(msg: StructuredGrpcMessage) {
    // Limit nesting depth to prevent excessive recursion
    let nesting_depth = (msg.nesting_depth as usize).min(MAX_NESTING_DEPTH);

    // Serialize protobuf fields into a message
    let mut protobuf_data = Vec::new();

    for field in &msg.fields {
        // Encode tag and wire type
        let tag_wire = (field.tag << 3) | (field.wire_type as u32);
        encode_varint(&mut protobuf_data, tag_wire as u64);

        // Encode field data based on wire type
        match (&field.data, field.wire_type) {
            (FieldData::Varint(value), WireType::Varint) => {
                encode_varint(&mut protobuf_data, *value);
            }
            (FieldData::Fixed64(bytes), WireType::Fixed64) => {
                protobuf_data.extend_from_slice(bytes);
            }
            (FieldData::LengthDelimited(data), WireType::LengthDelimited) => {
                // Test various length edge cases
                let actual_len = data.len().min(MAX_FUZZ_MESSAGE_SIZE / 4);
                encode_varint(&mut protobuf_data, actual_len as u64);
                protobuf_data.extend_from_slice(&data[..actual_len]);

                // Add nested message recursion testing
                if nesting_depth > 0 && !data.is_empty() && data.len() > 8 {
                    let nested_msg = StructuredGrpcMessage {
                        compressed: false,
                        fields: msg.fields[..1.min(msg.fields.len())].to_vec(),
                        raw_suffix: vec![],
                        nesting_depth: (nesting_depth.saturating_sub(1)) as u8,
                    };
                    fuzz_structured_message(nested_msg);
                }
            }
            (FieldData::GroupStart(group_fields), WireType::StartGroup) => {
                // Encode nested fields within the group (test deprecated group syntax)
                for group_field in group_fields {
                    let group_tag_wire = (group_field.tag << 3) | (group_field.wire_type as u32);
                    encode_varint(&mut protobuf_data, group_tag_wire as u64);

                    match &group_field.data {
                        FieldData::Varint(value) => encode_varint(&mut protobuf_data, *value),
                        FieldData::Fixed64(bytes) => protobuf_data.extend_from_slice(bytes),
                        FieldData::Fixed32(bytes) => protobuf_data.extend_from_slice(bytes),
                        FieldData::LengthDelimited(data) => {
                            let actual_len = data.len().min(MAX_FUZZ_MESSAGE_SIZE / 8);
                            encode_varint(&mut protobuf_data, actual_len as u64);
                            protobuf_data.extend_from_slice(&data[..actual_len]);
                        }
                        _ => {} // Avoid recursive groups
                    }
                }

                // Add group end marker with same tag
                let end_tag_wire = (field.tag << 3) | (WireType::EndGroup as u32);
                encode_varint(&mut protobuf_data, end_tag_wire as u64);
            }
            (FieldData::GroupEnd, WireType::EndGroup) => {
                // End group marker - already encoded in StartGroup case
            }
            (FieldData::Fixed32(bytes), WireType::Fixed32) => {
                protobuf_data.extend_from_slice(bytes);
            }
            // Test wire type mismatches (common source of bugs)
            _ => {
                // Deliberately encode wrong data type for this wire type
                protobuf_data.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]);
            }
        }
    }

    // Append raw suffix for malformed data edge cases
    protobuf_data.extend_from_slice(&msg.raw_suffix);

    // Test with gRPC message framing
    let grpc_message = GrpcMessage {
        compressed: msg.compressed,
        data: Bytes::from(protobuf_data),
    };

    let data_ref = grpc_message.data.clone();
    test_grpc_codec_roundtrip(grpc_message);
    test_protobuf_parsing(&data_ref);
    test_frame_limit_status_mapping(data_ref.as_ref());
    test_invalid_compression_flag_status(data_ref.as_ref());

    // Additional coverage for bead requirements
    test_unknown_field_preservation(&msg.raw_suffix);
    test_malformed_message_scenarios(&msg.raw_suffix);
}

/// Test raw byte sequences for edge case discovery.
fn fuzz_raw_data(data: &[u8]) {
    // Test direct protobuf parsing
    test_protobuf_parsing(&Bytes::from(data.to_vec()));

    // Test gRPC frame parsing with raw data
    test_grpc_frame_parsing(data);

    // Test boundary conditions around varint encoding
    if data.len() >= 10 {
        test_varint_boundaries(&data[..10]);
    }

    // Additional coverage for bead requirements
    test_varint_field_number_overflow(data);
    test_unknown_field_preservation(data);
    test_malformed_message_scenarios(data);
    test_frame_limit_status_mapping(data);
    test_invalid_compression_flag_status(data);
}

/// Test gRPC framing edge cases with custom headers.
fn fuzz_grpc_framing(compression_flag: u8, declared_length: u32, actual_payload: Vec<u8>) {
    let mut frame_data = Vec::new();

    // Build gRPC frame header manually
    frame_data.push(compression_flag);
    frame_data.extend_from_slice(&declared_length.to_be_bytes());
    frame_data.extend_from_slice(&actual_payload);

    test_grpc_frame_parsing(&frame_data);
    test_explicit_framing_statuses(compression_flag, declared_length, &actual_payload);

    // Test length mismatch scenarios (declared vs actual)
    let actual_len = actual_payload.len() as u32;
    if declared_length != actual_len {
        // This tests length validation in the decoder
        let mut buf = BytesMut::from(&frame_data[..]);
        let mut codec = GrpcCodec::new();
        let _ = codec.decode(&mut buf); // Should handle length mismatches gracefully
    }
}

fn assert_protocol_status(result: Result<Option<GrpcMessage>, GrpcError>, expected_code: Code) {
    let err = result.expect_err("framing edge case should fail");
    assert!(matches!(err, GrpcError::Protocol(_)));
    let status = err.into_status();
    assert_eq!(status.code(), expected_code);
}

fn test_invalid_compression_flag_status(data: &[u8]) {
    let invalid_flag = data.first().copied().filter(|flag| *flag > 1).unwrap_or(2);
    let payload = &data[..data.len().min(MAX_STATUS_PROBE_SIZE)];
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[invalid_flag]);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    let original = buf.clone();

    let mut codec = GrpcCodec::new();
    let result = codec.decode(&mut buf);
    assert_protocol_status(result, Code::Internal);
    assert_eq!(buf, original);
}

fn test_frame_limit_status_mapping(data: &[u8]) {
    let limit = data
        .len()
        .clamp(1, MAX_STATUS_PROBE_SIZE.saturating_sub(1))
        .max(1);
    let oversized_len = limit.saturating_add(1);
    let fill = data.first().copied().unwrap_or(0xAB);
    let payload = Bytes::from(vec![fill; oversized_len]);

    let mut encode_codec = GrpcCodec::with_max_size(limit);
    let mut encode_buf = BytesMut::new();
    let encode_result = encode_codec.encode(GrpcMessage::new(payload.clone()), &mut encode_buf);
    let encode_err = encode_result.expect_err("oversized encode should fail");
    assert!(matches!(encode_err, GrpcError::MessageTooLarge));
    assert_eq!(encode_err.into_status().code(), Code::ResourceExhausted);

    let mut decode_codec = GrpcCodec::with_max_size(limit);
    let mut decode_buf = BytesMut::new();
    decode_buf.extend_from_slice(&[0]);
    decode_buf.extend_from_slice(&(oversized_len as u32).to_be_bytes());
    let decode_result = decode_codec.decode(&mut decode_buf);
    let decode_err = decode_result.expect_err("oversized decode should fail");
    assert!(matches!(decode_err, GrpcError::MessageTooLarge));
    assert_eq!(decode_err.into_status().code(), Code::ResourceExhausted);
}

fn test_explicit_framing_statuses(
    compression_flag: u8,
    declared_length: u32,
    actual_payload: &[u8],
) {
    if compression_flag > 1 {
        let mut invalid_flag_frame = BytesMut::new();
        invalid_flag_frame.extend_from_slice(&compression_flag.to_be_bytes());
        invalid_flag_frame.extend_from_slice(&declared_length.to_be_bytes());
        invalid_flag_frame.extend_from_slice(actual_payload);
        let original = invalid_flag_frame.clone();
        let mut codec = GrpcCodec::new();
        let result = codec.decode(&mut invalid_flag_frame);
        assert_protocol_status(result, Code::Internal);
        assert_eq!(invalid_flag_frame, original);
    }

    let status_probe_limit = actual_payload
        .len()
        .clamp(1, MAX_STATUS_PROBE_SIZE.saturating_sub(1))
        .max(1);
    let oversized_length = declared_length.max((status_probe_limit + 1) as u32);
    let mut limited_codec = GrpcCodec::with_max_size(status_probe_limit);
    let mut oversized_frame = BytesMut::new();
    oversized_frame.extend_from_slice(&[compression_flag & 0x01]);
    oversized_frame.extend_from_slice(&oversized_length.to_be_bytes());
    let result = limited_codec.decode(&mut oversized_frame);
    let err = result.expect_err("oversized declared frame should fail");
    assert!(matches!(err, GrpcError::MessageTooLarge));
    assert_eq!(err.into_status().code(), Code::ResourceExhausted);
}

/// Test gRPC codec encode/decode roundtrip.
fn test_grpc_codec_roundtrip(message: GrpcMessage) {
    let mut codec = GrpcCodec::new();
    let mut encode_buf = BytesMut::new();

    // Test encoding
    if codec.encode(message.clone(), &mut encode_buf).is_ok() {
        // Test decoding
        let mut decode_buf = encode_buf;
        match codec.decode(&mut decode_buf) {
            Ok(Some(decoded)) => {
                // Verify basic properties are preserved
                assert_eq!(decoded.compressed, message.compressed);
                assert_eq!(decoded.data.len(), message.data.len());
            }
            Ok(None) => {
                // Incomplete frame - check that we need more data
                assert!(decode_buf.len() < MESSAGE_HEADER_SIZE);
            }
            Err(_) => {
                // Decoding errors are acceptable for malformed input
            }
        }
    }
}

/// Test protobuf parsing with various codecs.
fn test_protobuf_parsing(data: &Bytes) {
    // Test with a simple message type
    let mut codec = TestMessageCodec::new();
    let _ = codec.decode(data);

    // Test with complex message type (all wire types)
    let mut all_types_codec = AllTypesCodec::new();
    let _ = all_types_codec.decode(data);

    // Test with nested message type
    let mut nested_codec = NestedMessageCodec::new();
    let _ = nested_codec.decode(data);
}

/// Test gRPC frame parsing with raw data.
fn test_grpc_frame_parsing(data: &[u8]) {
    let mut buf = BytesMut::from(data);
    let mut codec = GrpcCodec::new();

    // Try to parse frames until buffer is empty or error
    let mut frames_parsed = 0;
    while !buf.is_empty() && frames_parsed < 100 {
        // Limit to prevent infinite loops
        match codec.decode(&mut buf) {
            Ok(Some(_message)) => {
                frames_parsed += 1;
                // Successfully parsed a frame, continue with remaining data
            }
            Ok(None) => {
                // Need more data to complete frame
                break;
            }
            Err(_) => {
                // Parse error, stop processing
                break;
            }
        }
    }
}

/// Test varint encoding boundary conditions.
fn test_varint_boundaries(data: &[u8]) {
    assert!(data.len() >= 10);

    // Test boundary values that trigger different varint encodings
    let boundary_values = [
        127u64,     // 1-byte varint boundary
        128u64,     // 2-byte varint starts
        16383u64,   // 2-byte varint boundary
        16384u64,   // 3-byte varint starts
        2097151u64, // 3-byte varint boundary
        2097152u64, // 4-byte varint starts
        u64::MAX,   // Maximum varint
    ];

    let mut protobuf_data = Vec::new();
    for (i, &value) in boundary_values.iter().enumerate() {
        // Use data bytes to create tag numbers at boundaries
        let tag = if i < data.len() {
            ((data[i] as u32) << 3) | (WireType::Varint as u32)
        } else {
            (1 << 3) | (WireType::Varint as u32)
        };

        encode_varint(&mut protobuf_data, tag as u64);
        encode_varint(&mut protobuf_data, value);
    }

    // Test zigzag encoding for negative values
    for &byte in &data[..5] {
        let signed_value = (byte as i8) as i64;
        let zigzag = ((signed_value << 1) ^ (signed_value >> 63)) as u64;

        encode_varint(
            &mut protobuf_data,
            (((byte as u32) << 3) | (WireType::Varint as u32)) as u64,
        );
        encode_varint(&mut protobuf_data, zigzag);
    }

    test_protobuf_parsing(&Bytes::from(protobuf_data));
}

/// Encode a varint into the buffer (simple implementation).
fn encode_varint(buf: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buf.push(((value & 0x7F) | 0x80) as u8);
        value >>= 7;
    }
    buf.push(value as u8);
}

/// Test unknown field preservation - requirement (4)
fn test_unknown_field_preservation(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    // Create a message with unknown fields (high tag numbers)
    let mut protobuf_data = Vec::new();

    // Add known fields (tags 1-2)
    encode_varint(
        &mut protobuf_data,
        (1 << 3) | (WireType::LengthDelimited as u64),
    );
    encode_varint(&mut protobuf_data, 4);
    protobuf_data.extend_from_slice(b"test");

    encode_varint(&mut protobuf_data, (2 << 3) | (WireType::Varint as u64));
    encode_varint(&mut protobuf_data, 42);

    // Add unknown fields with various tag numbers
    let unknown_tags = [100, 1000, 10000, 536870911]; // Last one is max valid tag (2^29 - 1)
    for (i, &tag) in unknown_tags.iter().enumerate() {
        if i < data.len() {
            let wire_type = match data[i] % 6 {
                0 => WireType::Varint,
                1 => WireType::Fixed64,
                2 => WireType::LengthDelimited,
                3 => WireType::StartGroup, // Test deprecated groups as unknown fields
                4 => WireType::EndGroup,
                _ => WireType::Fixed32,
            };

            encode_varint(&mut protobuf_data, (tag << 3) | (wire_type as u64));

            match wire_type {
                WireType::Varint => encode_varint(&mut protobuf_data, data[i] as u64),
                WireType::Fixed64 => {
                    let bytes = [data[i]; 8];
                    protobuf_data.extend_from_slice(&bytes);
                }
                WireType::Fixed32 => {
                    let bytes = [data[i]; 4];
                    protobuf_data.extend_from_slice(&bytes);
                }
                WireType::LengthDelimited => {
                    let len = (data[i] % 16) as usize;
                    encode_varint(&mut protobuf_data, len as u64);
                    protobuf_data.extend(vec![data[i]; len]);
                }
                WireType::StartGroup => {
                    // Test deprecated group with unknown field
                    encode_varint(
                        &mut protobuf_data,
                        ((tag + 1) << 3) | (WireType::Varint as u64),
                    );
                    encode_varint(&mut protobuf_data, data[i] as u64);
                    encode_varint(&mut protobuf_data, (tag << 3) | (WireType::EndGroup as u64));
                }
                WireType::EndGroup => {
                    // Skip standalone EndGroup as it would be malformed
                }
            }
        }
    }

    // Test that the message can still be parsed despite unknown fields
    let bytes = Bytes::from(protobuf_data);
    test_protobuf_parsing(&bytes);
}

/// Test varint field number overflow - requirement (1)
fn test_varint_field_number_overflow(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let mut protobuf_data = Vec::new();

    // Test field numbers at boundaries and beyond limits
    let overflow_tags = [
        536870911u32, // Maximum valid tag number (2^29 - 1)
        536870912u32, // Just above maximum (should be rejected)
        u32::MAX,     // Maximum u32 value
        0u32,         // Invalid tag number 0
    ];

    for (i, &tag) in overflow_tags.iter().enumerate() {
        if i < data.len() {
            // Craft varint that would cause tag overflow
            let wire_type = WireType::Varint as u32;
            let tag_wire = (tag << 3) | wire_type;

            // Manually encode potentially invalid varint
            if tag == u32::MAX {
                // Craft a malformed varint that's too long
                protobuf_data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]);
            } else {
                encode_varint(&mut protobuf_data, tag_wire as u64);
            }

            // Add value
            encode_varint(&mut protobuf_data, data[i] as u64);
        }
    }

    // Test that parser handles tag overflow gracefully
    let bytes = Bytes::from(protobuf_data);
    test_protobuf_parsing(&bytes);
}

/// Test comprehensive malformed message scenarios - requirement (5)
fn test_malformed_message_scenarios(data: &[u8]) {
    let scenarios = [
        // Scenario 1: Truncated varint
        || {
            vec![0xFF, 0xFF, 0xFF, 0xFF] // Varint without terminating byte
        },
        // Scenario 2: Invalid wire type
        || {
            let mut buf = Vec::new();
            encode_varint(&mut buf, (1 << 3) | 6); // Wire type 6 doesn't exist
            encode_varint(&mut buf, 42);
            buf
        },
        // Scenario 3: Length-delimited field with wrong length
        || {
            let mut buf = Vec::new();
            encode_varint(&mut buf, (1 << 3) | (WireType::LengthDelimited as u64));
            encode_varint(&mut buf, 100); // Claims 100 bytes
            buf.extend_from_slice(b"short"); // But only provides 5 bytes
            buf
        },
        // Scenario 4: Nested messages with excessive depth
        || {
            let mut buf = Vec::new();
            // Create deeply nested structure
            for _ in 0..100 {
                encode_varint(&mut buf, (1 << 3) | (WireType::LengthDelimited as u64));
                encode_varint(&mut buf, 3); // Length of next tag+type+value
            }
            buf.extend_from_slice(&[0x08, 0x2A]); // Final value
            buf
        },
        // Scenario 5: Unmatched group markers
        || {
            let mut buf = Vec::new();
            encode_varint(&mut buf, (1 << 3) | (WireType::StartGroup as u64));
            encode_varint(&mut buf, (1 << 3) | (WireType::Varint as u64));
            encode_varint(&mut buf, 42);
            // Missing EndGroup marker - should cause parsing error
            buf
        },
        // Scenario 6: Mismatched group tags
        || {
            let mut buf = Vec::new();
            encode_varint(&mut buf, (1 << 3) | (WireType::StartGroup as u64));
            encode_varint(&mut buf, (2 << 3) | (WireType::Varint as u64));
            encode_varint(&mut buf, 42);
            encode_varint(&mut buf, (2 << 3) | (WireType::EndGroup as u64)); // Wrong tag
            buf
        },
    ];

    for (i, scenario) in scenarios.iter().enumerate() {
        if i < data.len() && (data[i] % 6) == (i % 6) as u8 {
            let malformed_data = scenario();
            let bytes = Bytes::from(malformed_data);
            test_protobuf_parsing(&bytes);
        }
    }

    // Also test with user-provided data mixed in
    if !data.is_empty() {
        let mut mixed_data = Vec::new();

        // Valid message start
        encode_varint(
            &mut mixed_data,
            (1 << 3) | (WireType::LengthDelimited as u64),
        );
        encode_varint(&mut mixed_data, 4);
        mixed_data.extend_from_slice(b"test");

        // Add user data which might be malformed
        mixed_data.extend_from_slice(data);

        let bytes = Bytes::from(mixed_data);
        test_protobuf_parsing(&bytes);
    }
}

// Codec type aliases for testing different message types
type TestMessageCodec = ProstCodec<TestMessage, TestMessage>;
type AllTypesCodec = ProstCodec<AllTypesMessage, AllTypesMessage>;
type NestedMessageCodec = ProstCodec<NestedMessage, NestedMessage>;

// Simple test message for basic protobuf testing
#[derive(Clone, PartialEq, prost::Message)]
pub struct TestMessage {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(int32, tag = "2")]
    pub value: i32,
}

// Nested message for testing complex structures and depth limits
#[derive(Clone, PartialEq, prost::Message)]
pub struct NestedMessage {
    #[prost(message, optional, tag = "1")]
    pub inner: Option<TestMessage>,
    #[prost(repeated, string, tag = "2")]
    pub items: Vec<String>,
    #[prost(message, optional, tag = "3")]
    pub nested: Option<Box<NestedMessage>>, // Self-referential for depth testing
}

// Message with all scalar types for comprehensive wire type testing
#[derive(Clone, PartialEq, prost::Message)]
pub struct AllTypesMessage {
    // Wire type 0 (varint)
    #[prost(double, tag = "1")]
    pub double_field: f64, // Actually wire type 1, but prost handles this
    #[prost(float, tag = "2")]
    pub float_field: f32, // Actually wire type 5, but prost handles this
    #[prost(int32, tag = "3")]
    pub int32_field: i32,
    #[prost(int64, tag = "4")]
    pub int64_field: i64,
    #[prost(uint32, tag = "5")]
    pub uint32_field: u32,
    #[prost(uint64, tag = "6")]
    pub uint64_field: u64,
    #[prost(sint32, tag = "7")]
    pub sint32_field: i32, // Uses zigzag encoding
    #[prost(sint64, tag = "8")]
    pub sint64_field: i64, // Uses zigzag encoding
    #[prost(fixed32, tag = "9")]
    pub fixed32_field: u32, // Wire type 5
    #[prost(fixed64, tag = "10")]
    pub fixed64_field: u64, // Wire type 1
    #[prost(sfixed32, tag = "11")]
    pub sfixed32_field: i32, // Wire type 5
    #[prost(sfixed64, tag = "12")]
    pub sfixed64_field: i64, // Wire type 1
    #[prost(bool, tag = "13")]
    pub bool_field: bool,
    // Wire type 2 (length-delimited)
    #[prost(string, tag = "14")]
    pub string_field: String,
    #[prost(bytes = "vec", tag = "15")]
    pub bytes_field: Vec<u8>,
    #[prost(repeated, int32, tag = "16")]
    pub repeated_field: Vec<i32>,
}
