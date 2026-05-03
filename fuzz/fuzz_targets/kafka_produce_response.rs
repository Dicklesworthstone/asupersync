#![no_main]

//! Structure-aware fuzz target for Kafka ProduceResponse parser.
//!
//! Targets edge cases in Kafka ProduceResponse message parsing:
//! - Response frame structure validation (correlation ID, response length)
//! - Error code handling and error message parsing
//! - RecordMetadata field parsing (topic, partition, offset, timestamp)
//! - Length-prefixed string handling (topic names)
//! - Integer overflow and boundary conditions
//! - Malformed frame structure detection
//! - Delivery result parsing under various error conditions

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::messaging::kafka::{
    KafkaError, RecordMetadata, fuzz_parse_delivery_result, fuzz_parse_kafka_error_response,
    fuzz_parse_response_metadata, fuzz_validate_response_frame,
};

/// Maximum response size for fuzzer performance
const MAX_RESPONSE_SIZE: usize = 1024 * 1024; // 1MB

/// Test scenario for Kafka ProduceResponse parsing
#[derive(Arbitrary, Debug, Clone)]
struct ProduceResponseScenario {
    /// Response frame configuration
    frame_config: ResponseFrameConfig,
    /// Response payload type and structure
    response_payload: ResponsePayload,
    /// Parsing operations to test
    operations: Vec<ResponseOperation>,
}

/// Response frame configuration (correlation ID + length + payload)
#[derive(Arbitrary, Debug, Clone)]
struct ResponseFrameConfig {
    /// Correlation ID from request
    correlation_id: CorrelationId,
    /// Response length field
    response_length: ResponseLength,
    /// Frame consistency (whether length matches actual payload)
    consistency: FrameConsistency,
}

/// Correlation ID patterns for testing
#[derive(Arbitrary, Debug, Clone)]
enum CorrelationId {
    /// Valid correlation ID
    Valid(i32),
    /// Boundary values
    Boundary(CorrelationBoundary),
    /// Invalid values
    Invalid(InvalidCorrelationId),
}

impl CorrelationId {
    fn as_i32(self) -> i32 {
        match self {
            CorrelationId::Valid(id) => id,
            CorrelationId::Boundary(b) => b.as_i32(),
            CorrelationId::Invalid(inv) => inv.as_i32(),
        }
    }
}

/// Correlation ID boundary test cases
#[derive(Arbitrary, Debug, Clone, Copy)]
enum CorrelationBoundary {
    Zero,
    MaxPositive,
    MaxNegative,
    Near1Million,
}

impl CorrelationBoundary {
    fn as_i32(self) -> i32 {
        match self {
            CorrelationBoundary::Zero => 0,
            CorrelationBoundary::MaxPositive => i32::MAX,
            CorrelationBoundary::MaxNegative => i32::MIN,
            CorrelationBoundary::Near1Million => 999_999,
        }
    }
}

/// Invalid correlation ID test cases
#[derive(Arbitrary, Debug, Clone, Copy)]
enum InvalidCorrelationId {
    Negative,
    TooLarge,
    Suspicious,
}

impl InvalidCorrelationId {
    fn as_i32(self) -> i32 {
        match self {
            InvalidCorrelationId::Negative => -42,
            InvalidCorrelationId::TooLarge => 10_000_000,
            InvalidCorrelationId::Suspicious => 0xDEADBEEF_u32 as i32,
        }
    }
}

/// Response length field patterns
#[derive(Arbitrary, Debug, Clone)]
enum ResponseLength {
    /// Valid length matching payload
    Valid(u32), // 0 to MAX_RESPONSE_SIZE
    /// Boundary length values
    Boundary(LengthBoundary),
    /// Invalid length values
    Invalid(InvalidLength),
}

impl ResponseLength {
    fn as_i32(self, actual_payload_len: usize) -> i32 {
        match self {
            ResponseLength::Valid(len) => (len as usize % actual_payload_len.max(1)) as i32,
            ResponseLength::Boundary(b) => b.as_i32(),
            ResponseLength::Invalid(inv) => inv.as_i32(),
        }
    }
}

/// Length boundary test cases
#[derive(Arbitrary, Debug, Clone, Copy)]
enum LengthBoundary {
    Zero,
    MaxValid,
    JustOverLimit,
    I32Max,
}

impl LengthBoundary {
    fn as_i32(self) -> i32 {
        match self {
            LengthBoundary::Zero => 0,
            LengthBoundary::MaxValid => 50 * 1024 * 1024, // 50MB (current limit)
            LengthBoundary::JustOverLimit => 50 * 1024 * 1024 + 1,
            LengthBoundary::I32Max => i32::MAX,
        }
    }
}

/// Invalid length test cases
#[derive(Arbitrary, Debug, Clone, Copy)]
enum InvalidLength {
    Negative,
    Huge,
    Mismatch,
}

impl InvalidLength {
    fn as_i32(self) -> i32 {
        match self {
            InvalidLength::Negative => -1000,
            InvalidLength::Huge => 100 * 1024 * 1024, // Exceeds 50MB limit
            InvalidLength::Mismatch => 12345,         // Won't match actual payload
        }
    }
}

/// Frame consistency patterns
#[derive(Arbitrary, Debug, Clone, Copy)]
enum FrameConsistency {
    /// Length field matches payload size
    Consistent,
    /// Length field too small
    TooSmall,
    /// Length field too large
    TooLarge,
    /// Frame truncated
    Truncated,
}

/// Response payload types
#[derive(Arbitrary, Debug, Clone)]
enum ResponsePayload {
    /// Success response with RecordMetadata
    Success { metadata: ResponseMetadata },
    /// Error response
    Error { error: ErrorResponse },
    /// Mixed response (success + partial error)
    Mixed {
        success_count: u8, // 1-10
        error_count: u8,   // 1-10
    },
    /// Empty response
    Empty,
    /// Malformed response
    Malformed { malformed_type: MalformedType },
}

/// RecordMetadata fields for response
#[derive(Arbitrary, Debug, Clone)]
struct ResponseMetadata {
    /// Topic name
    topic: TopicName,
    /// Partition number
    partition: PartitionNumber,
    /// Offset value
    offset: OffsetValue,
    /// Timestamp (optional)
    timestamp: TimestampValue,
}

/// Topic name patterns
#[derive(Arbitrary, Debug, Clone)]
enum TopicName {
    /// Normal topic name
    Normal(NormalTopicName),
    /// Edge case names
    EdgeCase(EdgeCaseTopicName),
    /// Invalid names
    Invalid(InvalidTopicName),
}

impl TopicName {
    fn as_bytes(&self) -> Vec<u8> {
        match self {
            TopicName::Normal(n) => n.as_string().into_bytes(),
            TopicName::EdgeCase(e) => e.as_bytes(),
            TopicName::Invalid(i) => i.as_bytes(),
        }
    }
}

/// Normal topic name patterns
#[derive(Arbitrary, Debug, Clone)]
enum NormalTopicName {
    Simple(u8),     // "topic{n}"
    Dotted(u8, u8), // "app.events{n}.v{m}"
    Dashed(u8),     // "my-topic-{n}"
}

impl NormalTopicName {
    fn as_string(&self) -> String {
        match self {
            NormalTopicName::Simple(n) => format!("topic{}", n),
            NormalTopicName::Dotted(n, m) => format!("app.events{}.v{}", n, m),
            NormalTopicName::Dashed(n) => format!("my-topic-{}", n),
        }
    }
}

/// Edge case topic names
#[derive(Arbitrary, Debug, Clone)]
enum EdgeCaseTopicName {
    Empty,
    SingleChar,
    VeryLong,
    Unicode,
    Numeric,
}

impl EdgeCaseTopicName {
    fn as_bytes(&self) -> Vec<u8> {
        match self {
            EdgeCaseTopicName::Empty => vec![],
            EdgeCaseTopicName::SingleChar => b"t".to_vec(),
            EdgeCaseTopicName::VeryLong => "a".repeat(1000).into_bytes(),
            EdgeCaseTopicName::Unicode => "тест-тема-📨".as_bytes().to_vec(),
            EdgeCaseTopicName::Numeric => "123456".as_bytes().to_vec(),
        }
    }
}

/// Invalid topic names
#[derive(Arbitrary, Debug, Clone)]
enum InvalidTopicName {
    NonUtf8,
    NullBytes,
    ControlChars,
}

impl InvalidTopicName {
    fn as_bytes(&self) -> Vec<u8> {
        match self {
            InvalidTopicName::NonUtf8 => vec![0xFF, 0xFE, 0xFD],
            InvalidTopicName::NullBytes => b"topic\x00with\x00nulls".to_vec(),
            InvalidTopicName::ControlChars => b"topic\x01\x02\x03".to_vec(),
        }
    }
}

/// Partition number patterns
#[derive(Arbitrary, Debug, Clone, Copy)]
enum PartitionNumber {
    Valid(u16), // 0-65535
    Negative,   // -1
    Large(u32), // Large positive
}

impl PartitionNumber {
    fn as_i32(self) -> i32 {
        match self {
            PartitionNumber::Valid(n) => n as i32,
            PartitionNumber::Negative => -1,
            PartitionNumber::Large(n) => n as i32,
        }
    }
}

/// Offset value patterns
#[derive(Arbitrary, Debug, Clone, Copy)]
enum OffsetValue {
    Valid(u32), // Normal offset
    Zero,       // Start offset
    MaxValue,   // Large offset
    Negative,   // Invalid
}

impl OffsetValue {
    fn as_i64(self) -> i64 {
        match self {
            OffsetValue::Valid(n) => n as i64,
            OffsetValue::Zero => 0,
            OffsetValue::MaxValue => i64::MAX,
            OffsetValue::Negative => -1,
        }
    }
}

/// Timestamp value patterns
#[derive(Arbitrary, Debug, Clone, Copy)]
enum TimestampValue {
    None,       // No timestamp
    Valid(u32), // Unix timestamp
    Future,     // Far future timestamp
    Past,       // Far past timestamp
    Invalid,    // Negative timestamp
}

impl TimestampValue {
    fn as_option_i64(self) -> Option<i64> {
        match self {
            TimestampValue::None => None,
            TimestampValue::Valid(ts) => Some((ts as i64) * 1000), // Convert to millis
            TimestampValue::Future => Some(4_000_000_000_000),     // Year 2096
            TimestampValue::Past => Some(946_684_800_000),         // Year 2000
            TimestampValue::Invalid => Some(-1),
        }
    }

    fn as_i32_for_encoding(self) -> i32 {
        match self.as_option_i64() {
            Some(ts) if ts >= 0 => (ts / 1000) as i32,
            _ => -1,
        }
    }
}

/// Error response patterns
#[derive(Arbitrary, Debug, Clone)]
struct ErrorResponse {
    /// Error code
    error_code: ErrorCode,
    /// Error message
    message: ErrorMessage,
}

/// Error code patterns
#[derive(Arbitrary, Debug, Clone, Copy)]
enum ErrorCode {
    NoError,              // 0
    GenericError,         // 1
    BrokerError(u8),      // 2-10
    TopicError(u8),       // 11-20
    SizeError(u8),        // 21-30
    TransactionError(u8), // 31-40
    QueueError(u8),       // 41-50
    ConfigError(u8),      // 51-60
    CancelError(u8),      // 61-70
    Unknown(u8),          // 71+
}

impl ErrorCode {
    fn as_u8(self) -> u8 {
        match self {
            ErrorCode::NoError => 0,
            ErrorCode::GenericError => 1,
            ErrorCode::BrokerError(n) => 2 + (n % 9),
            ErrorCode::TopicError(n) => 11 + (n % 10),
            ErrorCode::SizeError(n) => 21 + (n % 10),
            ErrorCode::TransactionError(n) => 31 + (n % 10),
            ErrorCode::QueueError(n) => 41 + (n % 10),
            ErrorCode::ConfigError(n) => 51 + (n % 10),
            ErrorCode::CancelError(n) => 61 + (n % 10),
            ErrorCode::Unknown(n) => 71 + n,
        }
    }
}

/// Error message patterns
#[derive(Arbitrary, Debug, Clone)]
enum ErrorMessage {
    Empty,
    Short(u8), // Simple message
    Long,      // Long descriptive message
    Binary,    // Non-UTF8 message
    Truncated, // Message shorter than declared length
}

impl ErrorMessage {
    fn as_bytes(&self) -> Vec<u8> {
        match self {
            ErrorMessage::Empty => vec![],
            ErrorMessage::Short(n) => format!("Error {}", n).into_bytes(),
            ErrorMessage::Long => "This is a very long error message that describes exactly what went wrong in great detail with lots of context and information".into_bytes(),
            ErrorMessage::Binary => vec![0x80, 0x81, 0x82, 0x83],
            ErrorMessage::Truncated => b"Truncated".to_vec(),
        }
    }
}

/// Malformed response types
#[derive(Arbitrary, Debug, Clone, Copy)]
enum MalformedType {
    IncompleteHeader,
    CorruptedPayload,
    WrongApiVersion,
    InvalidStructure,
}

/// Response parsing operations to test
#[derive(Arbitrary, Debug, Clone)]
enum ResponseOperation {
    /// Validate response frame structure
    ValidateFrame,
    /// Parse error response
    ParseError,
    /// Parse response metadata
    ParseMetadata,
    /// Parse full delivery result
    ParseDeliveryResult,
    /// Test boundary conditions
    TestBoundaries,
}

fuzz_target!(|scenario: ProduceResponseScenario| {
    // Limit complexity for fuzzer performance
    if scenario.operations.len() > 20 {
        return;
    }

    // Test ProduceResponse parsing
    test_produce_response_parsing(&scenario);

    // Test frame validation robustness
    test_frame_validation(&scenario);

    // Test error handling paths
    test_error_handling(&scenario);
});

fn test_produce_response_parsing(scenario: &ProduceResponseScenario) {
    // Generate response frame based on scenario
    let response_data = generate_response_frame(scenario);

    // Test all requested operations
    for operation in &scenario.operations {
        match operation {
            ResponseOperation::ValidateFrame => {
                let result = fuzz_validate_response_frame(&response_data);
                // Don't fail on expected validation errors
                let _ = result;
            }

            ResponseOperation::ParseError => {
                if let ResponsePayload::Error { .. } = &scenario.response_payload {
                    // Extract just the error code for error parsing
                    if response_data.len() > 8 {
                        let error_byte = &response_data[8..9];
                        let result = fuzz_parse_kafka_error_response(error_byte);
                        let _ = result; // Expected to succeed or fail gracefully
                    }
                }
            }

            ResponseOperation::ParseMetadata => {
                if let ResponsePayload::Success { .. } = &scenario.response_payload {
                    // Extract metadata portion for parsing
                    if response_data.len() > 9 {
                        let metadata_data = &response_data[9..];
                        let result = fuzz_parse_response_metadata(metadata_data);
                        let _ = result; // Expected to succeed or fail gracefully
                    }
                }
            }

            ResponseOperation::ParseDeliveryResult => {
                let result = fuzz_parse_delivery_result(&response_data);
                let _ = result; // Expected to succeed or fail gracefully
            }

            ResponseOperation::TestBoundaries => {
                // Test with various truncated versions
                for len in 0..response_data.len().min(50) {
                    let truncated = &response_data[..len];
                    let _ = fuzz_validate_response_frame(truncated);
                    let _ = fuzz_parse_delivery_result(truncated);
                }
            }
        }
    }
}

fn test_frame_validation(scenario: &ProduceResponseScenario) {
    let response_data = generate_response_frame(scenario);

    // Test frame validation with different consistency patterns
    match scenario.frame_config.consistency {
        FrameConsistency::Consistent => {
            // Should validate successfully if payload is well-formed
            let result = fuzz_validate_response_frame(&response_data);
            let _ = result;
        }
        FrameConsistency::TooSmall => {
            // Length field smaller than actual payload - should fail
            let result = fuzz_validate_response_frame(&response_data);
            if let Ok(()) = result {
                // Unexpected success with inconsistent length
            }
        }
        FrameConsistency::TooLarge => {
            // Length field larger than actual payload - should fail
            let result = fuzz_validate_response_frame(&response_data);
            if let Ok(()) = result {
                // Unexpected success with inconsistent length
            }
        }
        FrameConsistency::Truncated => {
            // Frame cut off mid-payload - should fail
            let result = fuzz_validate_response_frame(&response_data);
            if let Ok(()) = result {
                // Unexpected success with truncated frame
            }
        }
    }
}

fn test_error_handling(scenario: &ProduceResponseScenario) {
    let response_data = generate_response_frame(scenario);

    // Test that error paths don't panic or crash
    match &scenario.response_payload {
        ResponsePayload::Error { error } => {
            let error_code = error.error_code.as_u8();
            let result = fuzz_parse_kafka_error_response(&[error_code]);

            // Verify error is properly categorized
            match result {
                Ok(kafka_error) => {
                    // Error was parsed successfully
                    let _ = kafka_error;
                }
                Err(_) => {
                    // Error parsing failed - should not happen for single byte
                }
            }
        }
        _ => {
            // Test error parsing on non-error responses (should handle gracefully)
            let result = fuzz_parse_delivery_result(&response_data);
            let _ = result;
        }
    }
}

fn generate_response_frame(scenario: &ProduceResponseScenario) -> Vec<u8> {
    let mut frame = Vec::new();

    // Generate payload first to know its size
    let payload = generate_payload(&scenario.response_payload);

    // Correlation ID (4 bytes)
    let correlation_id = scenario.frame_config.correlation_id.as_i32();
    frame.extend_from_slice(&correlation_id.to_be_bytes());

    // Response length (4 bytes) - may be inconsistent based on config
    let actual_payload_len = payload.len();
    let declared_length = match scenario.frame_config.consistency {
        FrameConsistency::Consistent => actual_payload_len as i32,
        FrameConsistency::TooSmall => (actual_payload_len.saturating_sub(10)) as i32,
        FrameConsistency::TooLarge => (actual_payload_len + 100) as i32,
        FrameConsistency::Truncated => actual_payload_len as i32, // Length will be right but payload truncated
    };

    let final_length = scenario
        .frame_config
        .response_length
        .as_i32(actual_payload_len);
    let length_to_use = if final_length != 0 {
        final_length
    } else {
        declared_length
    };

    frame.extend_from_slice(&length_to_use.to_be_bytes());

    // Add payload
    match scenario.frame_config.consistency {
        FrameConsistency::Truncated => {
            // Truncate payload to simulate network interruption
            let truncate_len = actual_payload_len.saturating_sub(5);
            frame.extend_from_slice(&payload[..truncate_len]);
        }
        _ => {
            frame.extend_from_slice(&payload);
        }
    }

    frame
}

fn generate_payload(payload_type: &ResponsePayload) -> Vec<u8> {
    match payload_type {
        ResponsePayload::Success { metadata } => generate_success_payload(metadata),
        ResponsePayload::Error { error } => generate_error_payload(error),
        ResponsePayload::Mixed {
            success_count,
            error_count,
        } => {
            let mut payload = Vec::new();
            // Generate multiple success/error records
            for _ in 0..(*success_count).min(5) {
                payload.push(0); // Success indicator
                payload.extend_from_slice(&generate_metadata_bytes(&ResponseMetadata {
                    topic: TopicName::Normal(NormalTopicName::Simple(1)),
                    partition: PartitionNumber::Valid(0),
                    offset: OffsetValue::Valid(100),
                    timestamp: TimestampValue::Valid(1000),
                }));
            }
            for i in 0..(*error_count).min(5) {
                payload.push(i + 1); // Error indicator
            }
            payload
        }
        ResponsePayload::Empty => {
            vec![]
        }
        ResponsePayload::Malformed { malformed_type } => match malformed_type {
            MalformedType::IncompleteHeader => vec![0x01],
            MalformedType::CorruptedPayload => vec![0x00, 0xFF, 0xFE, 0xFD, 0xFC],
            MalformedType::WrongApiVersion => vec![0xFF, 0x00, 0x00, 0x00],
            MalformedType::InvalidStructure => vec![0x42; 20],
        },
    }
}

fn generate_success_payload(metadata: &ResponseMetadata) -> Vec<u8> {
    let mut payload = Vec::new();

    // Success indicator (0)
    payload.push(0);

    // Metadata bytes
    payload.extend_from_slice(&generate_metadata_bytes(metadata));

    payload
}

fn generate_error_payload(error: &ErrorResponse) -> Vec<u8> {
    let mut payload = Vec::new();

    // Error code
    payload.push(error.error_code.as_u8());

    // Error message (length-prefixed)
    let msg_bytes = error.message.as_bytes();
    if msg_bytes.len() <= u16::MAX as usize {
        payload.extend_from_slice(&(msg_bytes.len() as u16).to_be_bytes());
        payload.extend_from_slice(&msg_bytes);
    } else {
        // Truncate oversized message
        payload.extend_from_slice(&(u16::MAX).to_be_bytes());
        payload.extend_from_slice(&msg_bytes[..u16::MAX as usize]);
    }

    payload
}

fn generate_metadata_bytes(metadata: &ResponseMetadata) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Offset (8 bytes)
    bytes.extend_from_slice(&metadata.offset.as_i64().to_be_bytes());

    // Partition (4 bytes)
    bytes.extend_from_slice(&metadata.partition.as_i32().to_be_bytes());

    // Timestamp (4 bytes)
    bytes.extend_from_slice(&metadata.timestamp.as_i32_for_encoding().to_be_bytes());

    // Topic name (length-prefixed string)
    let topic_bytes = metadata.topic.as_bytes();
    if topic_bytes.len() <= u16::MAX as usize {
        bytes.extend_from_slice(&(topic_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&topic_bytes);
    } else {
        // Truncate oversized topic name
        bytes.extend_from_slice(&(u16::MAX).to_be_bytes());
        bytes.extend_from_slice(&topic_bytes[..u16::MAX as usize]);
    }

    bytes
}
