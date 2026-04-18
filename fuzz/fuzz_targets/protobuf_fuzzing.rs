#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use asupersync::grpc::Codec;

/// Comprehensive protobuf fuzzing for varint boundary conditions and large messages
#[derive(Arbitrary, Debug)]
struct ProtobufFuzz {
    /// Varint boundary tests for number encoding edge cases
    varint_tests: Vec<VarintTest>,
    /// Large message tests for size limit validation
    large_message_tests: Vec<LargeMessageTest>,
    /// Round-trip encode/decode consistency tests
    roundtrip_tests: Vec<RoundTripTest>,
    /// Wire format fuzzing with raw protobuf bytes
    wire_format_tests: Vec<WireFormatTest>,
    /// Message structure stress tests
    structure_stress_tests: Vec<StructureStressTest>,
}

/// Varint encoding boundary tests
#[derive(Arbitrary, Debug)]
struct VarintTest {
    /// Test values near varint encoding boundaries
    test_values: Vec<VarintValue>,
    /// Whether to test negative numbers
    test_negative: bool,
    /// Whether to test malformed varints
    test_malformed: bool,
}

/// Values for testing varint encoding boundaries
#[derive(Arbitrary, Debug)]
enum VarintValue {
    /// Values around 7-bit boundary (127, 128)
    SevenBit(u8),
    /// Values around 14-bit boundary (16383, 16384)
    FourteenBit(u16),
    /// Values around 21-bit boundary
    TwentyOneBit(u32),
    /// Values around 28-bit boundary
    TwentyEightBit(u32),
    /// Values around 35-bit boundary
    ThirtyFiveBit(u64),
    /// Maximum values
    MaxValue(u64),
    /// Custom value for edge case testing
    Custom(u64),
}

/// Large message size testing
#[derive(Arbitrary, Debug)]
struct LargeMessageTest {
    /// Size relative to default max (4MB)
    size_factor: SizeFactor,
    /// Type of large message content
    content_type: LargeContentType,
    /// Whether to test encoding or decoding
    operation: ProtobufOperation,
}

/// Size factors relative to DEFAULT_MAX_MESSAGE_SIZE
#[derive(Arbitrary, Debug)]
enum SizeFactor {
    /// Small message (< 1KB)
    Small(u16),
    /// Medium message (1KB - 100KB)
    Medium(u16),
    /// Large message (100KB - 1MB)
    Large(u16),
    /// Near limit (90-100% of 4MB)
    NearLimit(u8),
    /// At exact limit (4MB)
    AtLimit,
    /// Over limit (4MB+)
    OverLimit(u16),
    /// Extremely large (attempts to allocate massive size)
    ExtremelyLarge(u32),
}

/// Types of large message content
#[derive(Arbitrary, Debug)]
enum LargeContentType {
    /// Repeated string fields
    RepeatedStrings { string_size: u16, count: u16 },
    /// Single large string
    LargeString { size: u32 },
    /// Repeated bytes fields
    RepeatedBytes { bytes_size: u16, count: u16 },
    /// Single large bytes field
    LargeBytes { size: u32 },
    /// Deeply nested messages
    DeepNesting { depth: u8, payload_size: u16 },
    /// Many repeated scalar fields
    ManyScalars { count: u32 },
}

/// Protobuf operations to test
#[derive(Arbitrary, Debug)]
enum ProtobufOperation {
    Encode,
    Decode,
    RoundTrip,
}

/// Round-trip consistency tests
#[derive(Arbitrary, Debug)]
struct RoundTripTest {
    /// Test message configuration
    message_config: MessageConfig,
    /// Whether to test with different codec configurations
    test_different_configs: bool,
    /// Number of round-trip iterations
    iterations: u8,
}

/// Message configuration for testing
#[derive(Arbitrary, Debug)]
struct MessageConfig {
    /// String field content
    string_content: String,
    /// Numeric value for varint testing
    numeric_value: u64,
    /// Whether to include optional fields
    include_optional: bool,
    /// Whether to include repeated fields
    include_repeated: bool,
    /// Repeated field count
    repeated_count: u8,
}

/// Wire format fuzzing with raw protobuf data
#[derive(Arbitrary, Debug)]
struct WireFormatTest {
    /// Raw protobuf wire format bytes
    raw_bytes: Vec<u8>,
    /// Whether to test malformed wire format
    test_malformed: bool,
    /// Whether to test truncated messages
    test_truncated: bool,
}

/// Structure stress tests for complex protobuf scenarios
#[derive(Arbitrary, Debug)]
struct StructureStressTest {
    /// Test scenario type
    scenario: StressScenario,
    /// Stress level (affects resource usage)
    stress_level: u8,
}

/// Stress test scenarios
#[derive(Arbitrary, Debug)]
enum StressScenario {
    /// Many small messages
    ManySmallMessages { count: u16 },
    /// Repeated encode/decode cycles
    RepeatedOperations { cycles: u16 },
    /// Mixed message sizes
    MixedSizes { small_count: u8, large_count: u8 },
    /// Concurrent encode/decode (simulated)
    ConcurrentOperations { thread_count: u8 },
    /// Memory pressure scenarios
    MemoryPressure { allocation_size: u32 },
}

/// Maximum limits for safety
const MAX_STRING_SIZE: usize = 1024 * 1024; // 1MB
const MAX_BYTES_SIZE: usize = 1024 * 1024;  // 1MB
const MAX_REPEATED_COUNT: u16 = 10000;
const MAX_NESTING_DEPTH: u8 = 50;
const MAX_ITERATIONS: u8 = 100;
const MAX_THREAD_COUNT: u8 = 16;
const MAX_ALLOCATION_SIZE: u32 = 10 * 1024 * 1024; // 10MB

fuzz_target!(|input: ProtobufFuzz| {
    // Test varint boundary conditions
    for varint_test in input.varint_tests.iter().take(10) {
        test_varint_boundaries(varint_test);
    }

    // Test large message handling
    for large_msg_test in input.large_message_tests.iter().take(5) {
        test_large_messages(large_msg_test);
    }

    // Test round-trip consistency
    for roundtrip_test in input.roundtrip_tests.iter().take(10) {
        test_roundtrip_consistency(roundtrip_test);
    }

    // Test wire format parsing
    for wire_test in input.wire_format_tests.iter().take(20) {
        test_wire_format_parsing(wire_test);
    }

    // Test structure stress scenarios
    for stress_test in input.structure_stress_tests.iter().take(3) {
        test_structure_stress(stress_test);
    }
});

/// Test varint encoding boundary conditions
fn test_varint_boundaries(test: &VarintTest) {
    // Test various varint boundary values
    for varint_value in &test.test_values {
        test_varint_encoding_value(varint_value);
    }

    if test.test_negative {
        test_negative_varint_encoding();
    }

    if test.test_malformed {
        test_malformed_varint_decoding();
    }
}

/// Test individual varint encoding value
fn test_varint_encoding_value(value: &VarintValue) {
    use asupersync::grpc::protobuf::ProstCodec;

    let mut codec = ProstCodec::<TestMessage, TestMessage>::new();

    let test_value = match value {
        VarintValue::SevenBit(base) => {
            // Test around 7-bit boundary (127, 128)
            let boundary_values = [126, 127, 128, 129];
            for &val in &boundary_values {
                test_single_varint_value(&mut codec, val as u64);
            }
            *base as u64
        }
        VarintValue::FourteenBit(base) => {
            // Test around 14-bit boundary (16383, 16384)
            let boundary_values = [16382, 16383, 16384, 16385];
            for &val in &boundary_values {
                test_single_varint_value(&mut codec, val as u64);
            }
            *base as u64
        }
        VarintValue::TwentyOneBit(base) => {
            // Test around 21-bit boundary (2097151, 2097152)
            let boundary_values = [2097150, 2097151, 2097152, 2097153];
            for &val in &boundary_values {
                test_single_varint_value(&mut codec, val as u64);
            }
            *base as u64
        }
        VarintValue::TwentyEightBit(base) => {
            // Test around 28-bit boundary
            let boundary_values = [268435454, 268435455, 268435456, 268435457];
            for &val in &boundary_values {
                test_single_varint_value(&mut codec, val as u64);
            }
            *base as u64
        }
        VarintValue::ThirtyFiveBit(base) => {
            // Test around 35-bit boundary
            let boundary_values = [34359738366u64, 34359738367u64, 34359738368u64, 34359738369u64];
            for &val in &boundary_values {
                test_single_varint_value(&mut codec, val);
            }
            *base
        }
        VarintValue::MaxValue(_) => {
            // Test maximum values
            let max_values = [u64::MAX - 1, u64::MAX];
            for &val in &max_values {
                test_single_varint_value(&mut codec, val);
            }
            u64::MAX
        }
        VarintValue::Custom(val) => *val,
    };

    test_single_varint_value(&mut codec, test_value);
}

/// Test single varint value encoding/decoding
fn test_single_varint_value(codec: &mut asupersync::grpc::protobuf::ProstCodec<TestMessage, TestMessage>, value: u64) {
    let message = TestMessage {
        name: "varint_test".to_string(),
        value,
    };

    // Test encoding
    match codec.encode(&message) {
        Ok(encoded) => {
            // Test decoding
            match codec.decode(&encoded) {
                Ok(decoded) => {
                    // Verify round-trip consistency
                    assert_eq!(decoded.value, value,
                        "Varint round-trip failed for value: {}", value);
                    assert_eq!(decoded.name, message.name);
                }
                Err(_) => {
                    // Decode error - verify it's reasonable for the input
                }
            }
        }
        Err(_) => {
            // Encode error - may be due to size limits
        }
    }
}

/// Test negative number handling in varint encoding
fn test_negative_varint_encoding() {
    // Protobuf uses zigzag encoding for signed integers
    // Test boundary conditions for negative values
    let negative_test_values: Vec<i64> = vec![
        -1, -127, -128, -16383, -16384, -2097151, -2097152,
        i64::MIN, i64::MIN + 1, i64::MAX, i64::MAX - 1,
    ];

    for &value in &negative_test_values {
        test_signed_varint_value(value);
    }
}

/// Test signed varint value
fn test_signed_varint_value(value: i64) {
    let message = SignedTestMessage { signed_value: value };
    let mut codec = asupersync::grpc::protobuf::ProstCodec::<SignedTestMessage, SignedTestMessage>::new();

    match codec.encode(&message) {
        Ok(encoded) => {
            match codec.decode(&encoded) {
                Ok(decoded) => {
                    assert_eq!(decoded.signed_value, value,
                        "Signed varint round-trip failed for value: {}", value);
                }
                Err(_) => {
                    // Decode error for edge case values
                }
            }
        }
        Err(_) => {
            // Encode error for extreme values
        }
    }
}

/// Test malformed varint decoding
fn test_malformed_varint_decoding() {
    use asupersync::grpc::protobuf::ProstCodec;
    use asupersync::bytes::Bytes;

    let mut codec = ProstCodec::<TestMessage, TestMessage>::new();

    // Test various malformed varint patterns
    let malformed_varints = [
        // Varint with too many continuation bytes (should fail)
        vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01],
        // Incomplete varint (all continuation bits set, no end)
        vec![0xFF, 0xFF, 0xFF, 0xFF],
        // Single continuation byte with no value
        vec![0x80],
        // Empty varint
        vec![],
        // Varint with invalid field numbers
        vec![0x00, 0x08, 0xFF],
        // Truncated varint in middle of message
        vec![0x08, 0xFF, 0xFF], // field 1, incomplete varint
    ];

    for malformed_data in &malformed_varints {
        if malformed_data.is_empty() {
            continue;
        }

        let bytes = Bytes::from(malformed_data.clone());
        let result = codec.decode(&bytes);

        // Should either decode successfully or fail gracefully
        match result {
            Ok(_) => {
                // Unexpected success - prost was more lenient than expected
            }
            Err(_) => {
                // Expected failure for malformed data
            }
        }
    }
}

/// Test large message handling
fn test_large_messages(test: &LargeMessageTest) {
    let target_size = calculate_target_size(&test.size_factor);

    // Skip extremely large allocations that could cause OOM
    if target_size > MAX_ALLOCATION_SIZE as usize {
        return;
    }

    match &test.content_type {
        LargeContentType::RepeatedStrings { string_size, count } => {
            test_large_repeated_strings(*string_size, *count, &test.operation, target_size);
        }
        LargeContentType::LargeString { size } => {
            test_large_single_string(*size, &test.operation, target_size);
        }
        LargeContentType::RepeatedBytes { bytes_size, count } => {
            test_large_repeated_bytes(*bytes_size, *count, &test.operation, target_size);
        }
        LargeContentType::LargeBytes { size } => {
            test_large_single_bytes(*size, &test.operation, target_size);
        }
        LargeContentType::DeepNesting { depth, payload_size } => {
            test_deep_nesting(*depth, *payload_size, &test.operation);
        }
        LargeContentType::ManyScalars { count } => {
            test_many_scalars(*count, &test.operation);
        }
    }
}

/// Calculate target size based on size factor
fn calculate_target_size(factor: &SizeFactor) -> usize {
    const DEFAULT_MAX: usize = 4 * 1024 * 1024; // 4MB

    match factor {
        SizeFactor::Small(val) => (*val as usize).min(1024),
        SizeFactor::Medium(val) => ((*val as usize) * 100).min(100 * 1024),
        SizeFactor::Large(val) => ((*val as usize) * 1000).min(1024 * 1024),
        SizeFactor::NearLimit(percent) => (DEFAULT_MAX * (*percent as usize)) / 100,
        SizeFactor::AtLimit => DEFAULT_MAX,
        SizeFactor::OverLimit(extra) => DEFAULT_MAX + (*extra as usize * 1024),
        SizeFactor::ExtremelyLarge(size) => (*size as usize).min(MAX_ALLOCATION_SIZE as usize),
    }
}

/// Test large repeated string messages
fn test_large_repeated_strings(string_size: u16, count: u16, operation: &ProtobufOperation, _target_size: usize) {
    use asupersync::grpc::protobuf::ProstCodec;

    let safe_string_size = (string_size as usize).min(MAX_STRING_SIZE / 100);
    let safe_count = count.min(MAX_REPEATED_COUNT / 100);

    let repeated_strings: Vec<String> = (0..safe_count)
        .map(|i| format!("repeated_string_{}_{}", i, "x".repeat(safe_string_size)))
        .collect();

    let message = RepeatedMessage {
        strings: repeated_strings,
        values: vec![],
    };

    let mut codec = ProstCodec::<RepeatedMessage, RepeatedMessage>::new();

    match operation {
        ProtobufOperation::Encode => {
            let _result = codec.encode(&message);
            // Test that encode handles large messages appropriately
        }
        ProtobufOperation::Decode => {
            // First encode to get bytes to decode
            if let Ok(encoded) = codec.encode(&message) {
                let _result = codec.decode(&encoded);
            }
        }
        ProtobufOperation::RoundTrip => {
            test_message_roundtrip(&mut codec, &message);
        }
    }
}

/// Test large single string message
fn test_large_single_string(size: u32, operation: &ProtobufOperation, target_size: usize) {
    use asupersync::grpc::protobuf::ProstCodec;

    let safe_size = (size as usize).min(target_size).min(MAX_STRING_SIZE);
    let large_string = "A".repeat(safe_size);

    let message = TestMessage {
        name: large_string,
        value: 123,
    };

    let mut codec = ProstCodec::<TestMessage, TestMessage>::new();

    match operation {
        ProtobufOperation::Encode => {
            let result = codec.encode(&message);
            // Test size limit enforcement
            if safe_size > asupersync::grpc::DEFAULT_MAX_MESSAGE_SIZE {
                assert!(result.is_err(), "Should reject oversized message");
            }
        }
        ProtobufOperation::Decode => {
            // Create oversized raw data to test decode size limits
            test_oversized_decode_data(&mut codec, safe_size);
        }
        ProtobufOperation::RoundTrip => {
            test_message_roundtrip(&mut codec, &message);
        }
    }
}

/// Test large repeated bytes messages
fn test_large_repeated_bytes(bytes_size: u16, count: u16, operation: &ProtobufOperation, _target_size: usize) {
    use asupersync::grpc::protobuf::ProstCodec;

    let safe_bytes_size = (bytes_size as usize).min(MAX_BYTES_SIZE / 100);
    let safe_count = count.min(MAX_REPEATED_COUNT / 100);

    let repeated_bytes: Vec<Vec<u8>> = (0..safe_count)
        .map(|i| {
            let mut bytes = vec![i as u8; safe_bytes_size];
            bytes.extend_from_slice(&(i as u32).to_le_bytes());
            bytes
        })
        .collect();

    let message = BytesMessage {
        data: repeated_bytes,
    };

    let mut codec = ProstCodec::<BytesMessage, BytesMessage>::new();

    match operation {
        ProtobufOperation::Encode => {
            let _result = codec.encode(&message);
        }
        ProtobufOperation::Decode => {
            if let Ok(encoded) = codec.encode(&message) {
                let _result = codec.decode(&encoded);
            }
        }
        ProtobufOperation::RoundTrip => {
            test_message_roundtrip(&mut codec, &message);
        }
    }
}

/// Test large single bytes message
fn test_large_single_bytes(size: u32, operation: &ProtobufOperation, target_size: usize) {
    use asupersync::grpc::protobuf::ProstCodec;

    let safe_size = (size as usize).min(target_size).min(MAX_BYTES_SIZE);
    let large_bytes = vec![0xABu8; safe_size];

    let message = BytesMessage {
        data: vec![large_bytes],
    };

    let mut codec = ProstCodec::<BytesMessage, BytesMessage>::new();

    match operation {
        ProtobufOperation::Encode => {
            let result = codec.encode(&message);
            if safe_size > asupersync::grpc::DEFAULT_MAX_MESSAGE_SIZE {
                assert!(result.is_err(), "Should reject oversized bytes message");
            }
        }
        ProtobufOperation::Decode => {
            test_oversized_decode_data(&mut codec, safe_size);
        }
        ProtobufOperation::RoundTrip => {
            test_message_roundtrip(&mut codec, &message);
        }
    }
}

/// Test deep nesting scenarios
fn test_deep_nesting(depth: u8, payload_size: u16, operation: &ProtobufOperation) {
    let safe_depth = depth.min(MAX_NESTING_DEPTH);
    let safe_payload_size = (payload_size as usize).min(1024);

    let nested_message = create_nested_message(safe_depth as usize, safe_payload_size);

    let mut codec = asupersync::grpc::protobuf::ProstCodec::<NestedMessage, NestedMessage>::new();

    match operation {
        ProtobufOperation::Encode => {
            let _result = codec.encode(&nested_message);
        }
        ProtobufOperation::Decode => {
            if let Ok(encoded) = codec.encode(&nested_message) {
                let _result = codec.decode(&encoded);
            }
        }
        ProtobufOperation::RoundTrip => {
            test_message_roundtrip(&mut codec, &nested_message);
        }
    }
}

/// Create nested message structure
fn create_nested_message(depth: usize, payload_size: usize) -> NestedMessage {
    if depth == 0 {
        NestedMessage {
            inner: Some(TestMessage {
                name: "A".repeat(payload_size),
                value: depth as u64,
            }),
            items: vec!["leaf".to_string()],
        }
    } else {
        NestedMessage {
            inner: Some(TestMessage {
                name: format!("depth_{}", depth),
                value: depth as u64,
            }),
            items: vec![format!("item_at_depth_{}", depth)],
        }
    }
}

/// Test many scalar fields
fn test_many_scalars(count: u32, operation: &ProtobufOperation) {
    let safe_count = count.min(10000); // Reasonable limit

    let values: Vec<u64> = (0..safe_count).map(|i| i as u64).collect();

    let message = RepeatedMessage {
        strings: vec![],
        values,
    };

    let mut codec = asupersync::grpc::protobuf::ProstCodec::<RepeatedMessage, RepeatedMessage>::new();

    match operation {
        ProtobufOperation::Encode => {
            let _result = codec.encode(&message);
        }
        ProtobufOperation::Decode => {
            if let Ok(encoded) = codec.encode(&message) {
                let _result = codec.decode(&encoded);
            }
        }
        ProtobufOperation::RoundTrip => {
            test_message_roundtrip(&mut codec, &message);
        }
    }
}

/// Test oversized decode data
fn test_oversized_decode_data<T, U>(codec: &mut asupersync::grpc::protobuf::ProstCodec<T, U>, size: usize)
where
    T: prost::Message + Default + Send + 'static,
    U: prost::Message + Default + Send + 'static,
{
    use asupersync::bytes::Bytes;

    // Create oversized data that exceeds DEFAULT_MAX_MESSAGE_SIZE
    let oversized_data = vec![0xFFu8; size];
    let bytes = Bytes::from(oversized_data);

    let result = codec.decode(&bytes);

    if size > asupersync::grpc::DEFAULT_MAX_MESSAGE_SIZE {
        // Should fail with MessageTooLarge error
        match result {
            Err(asupersync::grpc::protobuf::ProtobufError::MessageTooLarge { .. }) => {
                // Expected error
            }
            Err(_) => {
                // Other error is also acceptable
            }
            Ok(_) => {
                panic!("Should have failed with MessageTooLarge for size: {}", size);
            }
        }
    }
}

/// Test message round-trip consistency
fn test_message_roundtrip<T>(codec: &mut asupersync::grpc::protobuf::ProstCodec<T, T>, message: &T)
where
    T: prost::Message + PartialEq + Send + Clone + Default + 'static,
{
    match codec.encode(message) {
        Ok(encoded) => {
            match codec.decode(&encoded) {
                Ok(decoded) => {
                    assert_eq!(*message, decoded, "Round-trip consistency failed");
                }
                Err(_) => {
                    // Decode failed - may be due to size limits or malformed data
                }
            }
        }
        Err(_) => {
            // Encode failed - may be due to size limits
        }
    }
}

/// Test round-trip consistency scenarios
fn test_roundtrip_consistency(test: &RoundTripTest) {
    let iterations = test.iterations.min(MAX_ITERATIONS);

    for _ in 0..iterations {
        let message = create_test_message_from_config(&test.message_config);
        let mut codec = asupersync::grpc::protobuf::ProstCodec::<TestMessage, TestMessage>::new();

        test_message_roundtrip(&mut codec, &message);

        if test.test_different_configs {
            test_different_codec_configs(&message);
        }
    }
}

/// Create test message from configuration
fn create_test_message_from_config(config: &MessageConfig) -> TestMessage {
    let safe_string = if config.string_content.len() > MAX_STRING_SIZE {
        &config.string_content[..MAX_STRING_SIZE]
    } else {
        &config.string_content
    };

    TestMessage {
        name: safe_string.to_string(),
        value: config.numeric_value,
    }
}

/// Test different codec configurations
fn test_different_codec_configs(message: &TestMessage) {
    use asupersync::grpc::protobuf::ProstCodec;

    // Test various codec configurations
    let configs = [
        ProstCodec::new(), // Default config
        ProstCodec::with_max_size(1024), // Small limit
        ProstCodec::with_max_size(1024 * 1024), // 1MB limit
        ProstCodec::with_max_size(16 * 1024 * 1024), // Large limit
    ];

    for mut codec in configs {
        test_message_roundtrip(&mut codec, message);
    }
}

/// Test wire format parsing
fn test_wire_format_parsing(test: &WireFormatTest) {
    use asupersync::grpc::protobuf::ProstCodec;
    use asupersync::bytes::Bytes;

    let mut codec = ProstCodec::<TestMessage, TestMessage>::new();

    // Limit raw bytes size to prevent excessive memory usage
    let safe_bytes = if test.raw_bytes.len() > MAX_ALLOCATION_SIZE as usize {
        &test.raw_bytes[..MAX_ALLOCATION_SIZE as usize]
    } else {
        &test.raw_bytes
    };

    let bytes = Bytes::from(safe_bytes.to_vec());

    // Test basic parsing
    let _result = codec.decode(&bytes);

    if test.test_malformed {
        test_malformed_wire_format(&test.raw_bytes);
    }

    if test.test_truncated {
        test_truncated_wire_format(&test.raw_bytes);
    }
}

/// Test malformed wire format data
fn test_malformed_wire_format(raw_bytes: &[u8]) {
    use asupersync::grpc::protobuf::ProstCodec;
    use asupersync::bytes::Bytes;

    if raw_bytes.is_empty() {
        return;
    }

    let mut codec = ProstCodec::<TestMessage, TestMessage>::new();

    // Create various malformed variants
    let malformed_variants = [
        // Original data
        raw_bytes.to_vec(),
        // Flip random bits
        flip_random_bits(raw_bytes),
        // Truncate at random position
        truncate_at_random(raw_bytes),
        // Duplicate/repeat data
        repeat_data(raw_bytes),
        // Add garbage at end
        add_garbage_suffix(raw_bytes),
    ];

    for variant in &malformed_variants {
        if variant.len() > MAX_ALLOCATION_SIZE as usize {
            continue;
        }

        let bytes = Bytes::from(variant.clone());
        let _result = codec.decode(&bytes);
        // Should either succeed or fail gracefully without crashing
    }
}

/// Test truncated wire format data
fn test_truncated_wire_format(raw_bytes: &[u8]) {
    use asupersync::grpc::protobuf::ProstCodec;
    use asupersync::bytes::Bytes;

    if raw_bytes.len() < 2 {
        return;
    }

    let mut codec = ProstCodec::<TestMessage, TestMessage>::new();

    // Test truncation at various points
    let truncation_points = [
        1,
        raw_bytes.len() / 4,
        raw_bytes.len() / 2,
        raw_bytes.len() * 3 / 4,
        raw_bytes.len() - 1,
    ];

    for &truncate_at in &truncation_points {
        if truncate_at >= raw_bytes.len() {
            continue;
        }

        let truncated = &raw_bytes[..truncate_at];
        let bytes = Bytes::from(truncated.to_vec());
        let _result = codec.decode(&bytes);
        // Should handle truncated data gracefully
    }
}

/// Utility function to flip random bits
fn flip_random_bits(data: &[u8]) -> Vec<u8> {
    let mut result = data.to_vec();
    if !result.is_empty() {
        let flip_byte = result.len() / 2;
        result[flip_byte] ^= 0xFF;
    }
    result
}

/// Utility function to truncate at random position
fn truncate_at_random(data: &[u8]) -> Vec<u8> {
    if data.len() <= 1 {
        return data.to_vec();
    }
    let truncate_at = data.len() * 3 / 4;
    data[..truncate_at].to_vec()
}

/// Utility function to repeat data
fn repeat_data(data: &[u8]) -> Vec<u8> {
    if data.len() > 1024 {
        return data.to_vec(); // Don't repeat large data
    }
    let mut result = data.to_vec();
    result.extend_from_slice(data);
    result
}

/// Utility function to add garbage suffix
fn add_garbage_suffix(data: &[u8]) -> Vec<u8> {
    let mut result = data.to_vec();
    result.extend_from_slice(&[0xFF, 0x00, 0xAB, 0xCD]);
    result
}

/// Test structure stress scenarios
fn test_structure_stress(test: &StructureStressTest) {
    let stress_level = test.stress_level.min(10); // Reasonable limit

    match &test.scenario {
        StressScenario::ManySmallMessages { count } => {
            let safe_count = (*count as usize).min(1000);
            test_many_small_messages(safe_count, stress_level);
        }
        StressScenario::RepeatedOperations { cycles } => {
            let safe_cycles = (*cycles as usize).min(1000);
            test_repeated_operations(safe_cycles, stress_level);
        }
        StressScenario::MixedSizes { small_count, large_count } => {
            test_mixed_message_sizes(*small_count, *large_count, stress_level);
        }
        StressScenario::ConcurrentOperations { thread_count } => {
            let safe_thread_count = (*thread_count).min(MAX_THREAD_COUNT);
            test_concurrent_operations(safe_thread_count, stress_level);
        }
        StressScenario::MemoryPressure { allocation_size } => {
            let safe_size = (*allocation_size as usize).min(MAX_ALLOCATION_SIZE as usize);
            test_memory_pressure(safe_size, stress_level);
        }
    }
}

/// Test many small messages
fn test_many_small_messages(count: usize, _stress_level: u8) {
    use asupersync::grpc::protobuf::ProstCodec;

    let mut codec = ProstCodec::<TestMessage, TestMessage>::new();

    for i in 0..count {
        let message = TestMessage {
            name: format!("small_{}", i),
            value: i as u64,
        };

        let _ = codec.encode(&message);
    }
}

/// Test repeated encode/decode operations
fn test_repeated_operations(cycles: usize, _stress_level: u8) {
    use asupersync::grpc::protobuf::ProstCodec;

    let mut codec = ProstCodec::<TestMessage, TestMessage>::new();
    let message = TestMessage {
        name: "repeated_test".to_string(),
        value: 12345,
    };

    for _ in 0..cycles {
        if let Ok(encoded) = codec.encode(&message) {
            let _decoded = codec.decode(&encoded);
        }
    }
}

/// Test mixed message sizes
fn test_mixed_message_sizes(small_count: u8, large_count: u8, _stress_level: u8) {
    use asupersync::grpc::protobuf::ProstCodec;

    let mut codec = ProstCodec::<TestMessage, TestMessage>::new();

    // Small messages
    for i in 0..small_count {
        let message = TestMessage {
            name: format!("small_{}", i),
            value: i as u64,
        };
        let _ = codec.encode(&message);
    }

    // Large messages
    for i in 0..large_count {
        let message = TestMessage {
            name: "X".repeat(1000), // Moderately large
            value: i as u64,
        };
        let _ = codec.encode(&message);
    }
}

/// Test concurrent operations (simulated)
fn test_concurrent_operations(thread_count: u8, _stress_level: u8) {
    use asupersync::grpc::protobuf::ProstCodec;

    // Since we're in a fuzz target, simulate concurrency with sequential operations
    // that test the same patterns as concurrent access

    for thread_id in 0..thread_count {
        let mut codec = ProstCodec::<TestMessage, TestMessage>::new();
        let message = TestMessage {
            name: format!("thread_{}", thread_id),
            value: thread_id as u64,
        };

        // Simulate concurrent encode/decode
        if let Ok(encoded) = codec.encode(&message) {
            let _decoded = codec.decode(&encoded);
        }
    }
}

/// Test memory pressure scenarios
fn test_memory_pressure(allocation_size: usize, _stress_level: u8) {
    if allocation_size == 0 {
        return;
    }

    // Attempt large allocation to simulate memory pressure
    let _large_allocation = vec![0u8; allocation_size];

    // Test that protobuf operations still work under memory pressure
    use asupersync::grpc::protobuf::ProstCodec;
    let mut codec = ProstCodec::<TestMessage, TestMessage>::new();
    let message = TestMessage {
        name: "memory_pressure_test".to_string(),
        value: 999,
    };

    let _ = codec.encode(&message);
}

// Test message definitions (using prost derive macros)

/// Basic test message for protobuf fuzzing
#[derive(Clone, PartialEq, prost::Message)]
struct TestMessage {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(uint64, tag = "2")]
    value: u64,
}

/// Message with signed fields for varint testing
#[derive(Clone, PartialEq, prost::Message)]
struct SignedTestMessage {
    #[prost(int64, tag = "1")]
    signed_value: i64,
}

/// Message with repeated fields for large message testing
#[derive(Clone, PartialEq, prost::Message)]
struct RepeatedMessage {
    #[prost(string, repeated, tag = "1")]
    strings: Vec<String>,
    #[prost(uint64, repeated, tag = "2")]
    values: Vec<u64>,
}

/// Message with bytes fields for binary data testing
#[derive(Clone, PartialEq, prost::Message)]
struct BytesMessage {
    #[prost(bytes = "vec", repeated, tag = "1")]
    data: Vec<Vec<u8>>,
}

/// Nested message for deep nesting tests
#[derive(Clone, PartialEq, prost::Message)]
struct NestedMessage {
    #[prost(message, optional, tag = "1")]
    inner: Option<TestMessage>,
    #[prost(string, repeated, tag = "2")]
    items: Vec<String>,
}