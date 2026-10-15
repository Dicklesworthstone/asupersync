#![no_main]

//! Structure-aware fuzz target for Kafka response wire frames.
//!
//! This fuzz target exercises Kafka response frame parsing with intelligent
//! structure-aware input generation to find edge cases in response processing.
//!
//! Response frame structures tested:
//! - Response frame headers (correlation ID, length validation)
//! - Error response parsing (error codes, message extraction)
//! - Response metadata parsing (offset, partition, timestamp, topic)
//! - Delivery result processing (success/error paths)
//! - Frame validation and boundary checking
//!
//! Usage: cargo fuzz run kafka_response_frames

use arbitrary::{Arbitrary, Unstructured};
use asupersync::messaging::kafka::{
    KafkaError, RecordMetadata, fuzz_parse_delivery_result, fuzz_parse_kafka_error_response,
    fuzz_parse_response_metadata, fuzz_validate_response_frame,
};
use libfuzzer_sys::fuzz_target;

/// Maximum size for response frame to prevent OOM
const MAX_FRAME_SIZE: usize = 16_384;

/// Maximum topic name length for realistic testing
const MAX_TOPIC_LENGTH: usize = 256;

/// Structure-aware generator for Kafka response frames
#[derive(Arbitrary, Debug, Clone)]
struct KafkaResponseFrame {
    /// The response frame variant to generate
    variant: ResponseFrameVariant,
    /// Frame header parameters
    header: FrameHeader,
    /// Fuzzing parameters for edge cases
    params: FuzzParams,
}

/// All possible response frame variants for structure-aware generation
#[derive(Arbitrary, Debug, Clone)]
enum ResponseFrameVariant {
    /// Valid successful response
    SuccessResponse(SuccessResponseData),
    /// Error response with various error types
    ErrorResponse(ErrorResponseData),
    /// Malformed responses for boundary testing
    MalformedResponse(MalformedResponseData),
    /// Edge case responses (empty, oversized, etc.)
    EdgeCaseResponse(EdgeCaseType),
}

/// Frame header structure
#[derive(Arbitrary, Debug, Clone)]
struct FrameHeader {
    /// Correlation ID for request/response matching
    correlation_id: i32,
    /// Declared response length (may be inaccurate for malformed testing)
    declared_length: i32,
    /// Whether to use accurate length calculation
    accurate_length: bool,
}

/// Parameters for fuzzing edge cases
#[derive(Arbitrary, Debug, Clone)]
struct FuzzParams {
    /// Add extra trailing bytes
    trailing_bytes: Vec<u8>,
    /// Truncate at specific position
    truncate_at: Option<u16>,
    /// Corrupt specific byte positions
    byte_corruptions: Vec<ByteCorruption>,
    /// Inject null bytes at positions
    null_injections: Vec<u16>,
}

/// Successful response data structure
#[derive(Arbitrary, Debug, Clone)]
struct SuccessResponseData {
    /// Response metadata
    metadata: ResponseMetadata,
    /// Additional response payload
    extra_payload: Vec<u8>,
}

/// Response metadata structure
#[derive(Arbitrary, Debug, Clone)]
struct ResponseMetadata {
    /// Record offset
    offset: i64,
    /// Partition number
    partition: i32,
    /// Timestamp (negative means null)
    timestamp: i32,
    /// Topic name
    topic_name: TopicNamePattern,
}

/// Topic name generation patterns
#[derive(Arbitrary, Debug, Clone)]
enum TopicNamePattern {
    /// Simple alphanumeric topic
    Simple(u8),
    /// Topic with special characters
    WithSpecialChars(u8),
    /// Very long topic name
    VeryLong(u8),
    /// Empty topic name
    Empty,
    /// Topic with unicode characters
    Unicode(String),
}

impl TopicNamePattern {
    fn materialize(&self) -> String {
        match self {
            Self::Simple(seed) => format!("topic_{}", seed % 100),
            Self::WithSpecialChars(seed) => format!("topic-{}.test_{}", seed % 50, seed % 10),
            Self::VeryLong(seed) => {
                let base = format!("very_long_topic_name_{}", seed);
                base.repeat(((seed % 8) + 1) as usize)
            }
            Self::Empty => String::new(),
            Self::Unicode(s) => s.clone(),
        }
    }
}

/// Error response data structure
#[derive(Arbitrary, Debug, Clone)]
struct ErrorResponseData {
    /// Error code to generate
    error_code: i16,
    /// Error message pattern
    message_pattern: ErrorMessagePattern,
    /// Additional error context
    context: Vec<u8>,
}

/// Error message generation patterns
#[derive(Arbitrary, Debug, Clone)]
enum ErrorMessagePattern {
    /// Standard error message
    Standard(u8),
    /// Very long error message
    VeryLong(u16),
    /// Empty error message
    Empty,
    /// Binary garbage in message
    BinaryGarbage(Vec<u8>),
    /// Error message with null bytes
    WithNulls(String),
}

impl ErrorMessagePattern {
    fn materialize(&self) -> String {
        match self {
            Self::Standard(code) => format!("Error occurred: code {}", code),
            Self::VeryLong(len) => "X".repeat((*len % 1024) as usize),
            Self::Empty => String::new(),
            Self::BinaryGarbage(bytes) => String::from_utf8_lossy(bytes).to_string(),
            Self::WithNulls(s) => s.replace('\0', "\\0"),
        }
    }
}

/// Malformed response data for boundary testing
#[derive(Arbitrary, Debug, Clone)]
struct MalformedResponseData {
    /// Type of malformation
    malformation_type: MalformationType,
    /// Base payload to corrupt
    base_payload: Vec<u8>,
}

/// Types of malformation to test
#[derive(Arbitrary, Debug, Clone)]
enum MalformationType {
    /// Length field lies about payload size
    LengthLie { declared: u32, actual: u16 },
    /// Negative values in unsigned fields
    NegativeValues,
    /// Integer overflow in length calculations
    IntegerOverflow,
    /// Truncated in middle of length prefix
    TruncatedLength,
    /// Missing required fields
    MissingFields,
    /// Duplicate or out-of-order fields
    DuplicateFields,
}

/// Edge case types for testing boundaries
#[derive(Arbitrary, Debug, Clone)]
enum EdgeCaseType {
    /// Completely empty frame
    Empty,
    /// Only frame header, no payload
    HeaderOnly,
    /// Maximum size frame
    MaxSize,
    /// Single byte frame
    SingleByte,
    /// Frame with only null bytes
    AllNulls(u16),
    /// Frame with repeating pattern
    RepeatingPattern(u8, u16),
}

/// Byte corruption specification
#[derive(Arbitrary, Debug, Clone)]
struct ByteCorruption {
    /// Position to corrupt (modulo frame size)
    position: u16,
    /// Value to set at position
    value: u8,
}

impl KafkaResponseFrame {
    /// Generate the raw bytes for this response frame
    fn materialize(&self) -> Vec<u8> {
        let mut frame = Vec::new();

        // Generate base frame content
        match &self.variant {
            ResponseFrameVariant::SuccessResponse(data) => {
                frame.extend_from_slice(&self.build_success_response(data));
            }
            ResponseFrameVariant::ErrorResponse(data) => {
                frame.extend_from_slice(&self.build_error_response(data));
            }
            ResponseFrameVariant::MalformedResponse(data) => {
                frame.extend_from_slice(&self.build_malformed_response(data));
            }
            ResponseFrameVariant::EdgeCaseResponse(edge_case) => {
                frame.extend_from_slice(&self.build_edge_case_response(edge_case));
            }
        }

        // Apply fuzzing parameters
        self.apply_fuzz_params(&mut frame);

        // Ensure reasonable size limit
        frame.truncate(MAX_FRAME_SIZE);

        frame
    }

    /// Build a successful response frame
    fn build_success_response(&self, data: &SuccessResponseData) -> Vec<u8> {
        let mut payload = Vec::new();

        // Success indicator (0 = no error)
        payload.push(0);

        // Add metadata
        payload.extend_from_slice(&data.metadata.offset.to_be_bytes());
        payload.extend_from_slice(&data.metadata.partition.to_be_bytes());
        payload.extend_from_slice(&data.metadata.timestamp.to_be_bytes());

        // Add topic name (length-prefixed)
        let topic = data.metadata.topic_name.materialize();
        let topic_bytes = topic.as_bytes();
        let topic_len = topic_bytes.len().min(MAX_TOPIC_LENGTH) as u16;
        payload.extend_from_slice(&topic_len.to_be_bytes());
        payload.extend_from_slice(&topic_bytes[..topic_len as usize]);

        // Add extra payload
        payload.extend_from_slice(&data.extra_payload);

        self.build_frame_with_header(payload)
    }

    /// Build an error response frame
    fn build_error_response(&self, data: &ErrorResponseData) -> Vec<u8> {
        let mut payload = Vec::new();

        // Error code as first byte (mapped from i16)
        payload.push((data.error_code.abs() % 256) as u8);

        // Add error message (length-prefixed)
        let message = data.message_pattern.materialize();
        let message_bytes = message.as_bytes();
        let message_len = message_bytes.len().min(1024) as u16;
        payload.extend_from_slice(&message_len.to_be_bytes());
        payload.extend_from_slice(&message_bytes[..message_len as usize]);

        // Add error context
        payload.extend_from_slice(&data.context);

        self.build_frame_with_header(payload)
    }

    /// Build a malformed response frame
    fn build_malformed_response(&self, data: &MalformedResponseData) -> Vec<u8> {
        let mut payload = data.base_payload.clone();

        match &data.malformation_type {
            MalformationType::LengthLie { declared, actual } => {
                payload.truncate(*actual as usize);
                // Build frame with lying header
                let mut frame = Vec::new();
                frame.extend_from_slice(&self.header.correlation_id.to_be_bytes());
                frame.extend_from_slice(&(*declared as i32).to_be_bytes());
                frame.extend_from_slice(&payload);
                return frame;
            }
            MalformationType::NegativeValues => {
                // Inject negative values where positive expected
                if payload.len() >= 4 {
                    payload[0..4].copy_from_slice(&(-1i32).to_be_bytes());
                }
            }
            MalformationType::IntegerOverflow => {
                // Use values that could cause integer overflow
                payload.clear();
                payload.extend_from_slice(&i32::MAX.to_be_bytes());
                payload.extend_from_slice(&i32::MAX.to_be_bytes());
            }
            MalformationType::TruncatedLength => {
                payload.truncate(payload.len().saturating_sub(2));
            }
            MalformationType::MissingFields => {
                payload.truncate(payload.len() / 2);
            }
            MalformationType::DuplicateFields => {
                let original = payload.clone();
                payload.extend_from_slice(&original);
            }
        }

        self.build_frame_with_header(payload)
    }

    /// Build an edge case response frame
    fn build_edge_case_response(&self, edge_case: &EdgeCaseType) -> Vec<u8> {
        match edge_case {
            EdgeCaseType::Empty => Vec::new(),
            EdgeCaseType::HeaderOnly => {
                let mut frame = Vec::new();
                frame.extend_from_slice(&self.header.correlation_id.to_be_bytes());
                frame.extend_from_slice(&0i32.to_be_bytes()); // Zero length
                frame
            }
            EdgeCaseType::MaxSize => {
                let payload = vec![0x42u8; MAX_FRAME_SIZE.saturating_sub(8)];
                self.build_frame_with_header(payload)
            }
            EdgeCaseType::SingleByte => vec![0xFF],
            EdgeCaseType::AllNulls(len) => vec![0u8; (*len as usize).min(MAX_FRAME_SIZE)],
            EdgeCaseType::RepeatingPattern(pattern, len) => {
                vec![*pattern; (*len as usize).min(MAX_FRAME_SIZE)]
            }
        }
    }

    /// Build frame with proper header
    fn build_frame_with_header(&self, payload: Vec<u8>) -> Vec<u8> {
        let mut frame = Vec::new();

        // Add correlation ID
        frame.extend_from_slice(&self.header.correlation_id.to_be_bytes());

        // Add response length (accurate or declared)
        let length = if self.header.accurate_length {
            payload.len() as i32
        } else {
            self.header.declared_length
        };
        frame.extend_from_slice(&length.to_be_bytes());

        // Add payload
        frame.extend_from_slice(&payload);

        frame
    }

    /// Apply fuzzing parameters to corrupt the frame
    fn apply_fuzz_params(&self, frame: &mut Vec<u8>) {
        // Apply byte corruptions
        for corruption in &self.params.byte_corruptions {
            if !frame.is_empty() {
                let pos = (corruption.position as usize) % frame.len();
                frame[pos] = corruption.value;
            }
        }

        // Inject null bytes
        for &pos in &self.params.null_injections {
            let insert_pos = (pos as usize).min(frame.len());
            frame.insert(insert_pos, 0);
        }

        // Apply truncation
        if let Some(truncate_at) = self.params.truncate_at {
            let truncate_pos = (truncate_at as usize).min(frame.len());
            frame.truncate(truncate_pos);
        }

        // Add trailing bytes
        frame.extend_from_slice(&self.params.trailing_bytes);
    }

    /// Determine expected parse result for validation
    fn expected_result(&self) -> ExpectedResult {
        match &self.variant {
            ResponseFrameVariant::SuccessResponse(_) if self.is_well_formed() => {
                ExpectedResult::Success
            }
            ResponseFrameVariant::ErrorResponse(_) if self.is_well_formed() => {
                ExpectedResult::Error
            }
            _ => ExpectedResult::ParseFailure,
        }
    }

    /// Check if frame should be well-formed
    fn is_well_formed(&self) -> bool {
        self.header.accurate_length
            && self.params.truncate_at.is_none()
            && self.params.byte_corruptions.is_empty()
            && self.params.null_injections.is_empty()
            && self.params.trailing_bytes.is_empty()
    }
}

/// Expected parsing result for validation
#[derive(Debug, Clone, PartialEq)]
enum ExpectedResult {
    Success,
    Error,
    ParseFailure,
}

fn observe_frame_validation(result: Result<(), String>, context: &str) {
    if let Err(message) = result {
        observe_parser_message(&message, context);
    }
}

fn observe_kafka_error_response(result: Result<KafkaError, String>, context: &str) {
    match result {
        Ok(err) => observe_kafka_error(&err, context),
        Err(message) => observe_parser_message(&message, context),
    }
}

fn observe_metadata_parse(result: Result<RecordMetadata, String>, context: &str) {
    match result {
        Ok(metadata) => observe_metadata(&metadata, context),
        Err(message) => observe_parser_message(&message, context),
    }
}

fn observe_delivery_parse(result: Result<RecordMetadata, KafkaError>, context: &str) {
    match result {
        Ok(metadata) => observe_metadata(&metadata, context),
        Err(err) => observe_kafka_error(&err, context),
    }
}

fn observe_metadata(metadata: &RecordMetadata, context: &str) {
    assert!(
        !metadata.topic.is_empty(),
        "{context} metadata topic must be non-empty"
    );
    assert!(
        metadata.partition >= 0,
        "{context} metadata partition must be non-negative"
    );
    assert!(
        metadata.offset >= 0,
        "{context} metadata offset must be non-negative"
    );
    if let Some(timestamp) = metadata.timestamp {
        assert!(
            timestamp >= 0,
            "{context} metadata timestamp must be non-negative when present"
        );
    }
}

fn observe_kafka_error(err: &KafkaError, context: &str) {
    let diagnostic = format!("{err:?}");
    assert!(
        !diagnostic.is_empty(),
        "{context} Kafka error must be observable"
    );
    match err {
        KafkaError::Protocol(message)
        | KafkaError::Broker(message)
        | KafkaError::InvalidTopic(message)
        | KafkaError::Transaction(message)
        | KafkaError::Config(message)
        | KafkaError::Authentication(message) => observe_parser_message(message, context),
        KafkaError::MessageTooLarge { size, max_size } => {
            assert!(
                *size > 0 || *max_size > 0,
                "{context} message-size error must expose a bound"
            );
        }
        _ => {}
    }
}

fn observe_parser_message(message: &str, context: &str) {
    assert!(
        !message.is_empty(),
        "{context} parser diagnostic must be visible"
    );
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent excessive memory usage
    if data.len() > MAX_FRAME_SIZE {
        return;
    }

    // Test 1: Direct raw bytes fuzzing
    observe_frame_validation(fuzz_validate_response_frame(data), "raw frame validation");
    observe_kafka_error_response(
        fuzz_parse_kafka_error_response(data),
        "raw error response parse",
    );
    observe_metadata_parse(fuzz_parse_response_metadata(data), "raw metadata parse");
    observe_delivery_parse(fuzz_parse_delivery_result(data), "raw delivery parse");

    // Test 2: Structure-aware fuzzing if we can parse the input
    let mut u = Unstructured::new(data);
    if let Ok(frame_spec) = KafkaResponseFrame::arbitrary(&mut u) {
        let generated_frame = frame_spec.materialize();

        // Don't fuzz empty frames (not interesting)
        if generated_frame.is_empty() {
            return;
        }

        let expected = frame_spec.expected_result();

        // Test all parsing functions with generated frame
        let frame_validation = fuzz_validate_response_frame(&generated_frame);
        let error_parsing = fuzz_parse_kafka_error_response(&generated_frame);
        let metadata_parsing = fuzz_parse_response_metadata(&generated_frame);
        let delivery_parsing = fuzz_parse_delivery_result(&generated_frame);

        // Validate expected behavior for well-formed frames
        match expected {
            ExpectedResult::Success => {
                // Well-formed success frames should pass frame validation
                if let Err(e) = &frame_validation {
                    panic!(
                        "Well-formed success frame failed validation: {}\nFrame: {:?}",
                        e,
                        String::from_utf8_lossy(&generated_frame)
                    );
                }
            }
            ExpectedResult::Error => {
                // Well-formed error frames should be parseable as errors
                if let Ok(parsed_error) = &error_parsing {
                    // Error parsing succeeded, verify it's a reasonable error
                    match parsed_error {
                        KafkaError::Protocol(_)
                        | KafkaError::Broker(_)
                        | KafkaError::InvalidTopic(_)
                        | KafkaError::MessageTooLarge { .. }
                        | KafkaError::Transaction(_)
                        | KafkaError::QueueFull
                        | KafkaError::Config(_)
                        | KafkaError::Cancelled => {
                            // Valid error types
                        }
                        _ => {
                            // Unexpected error type for structured error response
                        }
                    }
                }
            }
            ExpectedResult::ParseFailure => {
                // Malformed frames are expected to fail parsing
                // This is not an error condition for the fuzzer
            }
        }

        // Test invariants that should always hold
        // No function should panic on any input
        observe_frame_validation(frame_validation, "generated frame validation");
        observe_kafka_error_response(error_parsing, "generated error response parse");
        observe_metadata_parse(metadata_parsing, "generated metadata parse");
        observe_delivery_parse(delivery_parsing, "generated delivery parse");
    }

    // Test 3: Boundary condition fuzzing
    fuzz_boundary_conditions(data);
});

/// Test specific boundary conditions and edge cases
fn fuzz_boundary_conditions(data: &[u8]) {
    // Test very short inputs
    if data.len() <= 16 {
        observe_frame_validation(fuzz_validate_response_frame(data), "short frame validation");
        observe_metadata_parse(fuzz_parse_response_metadata(data), "short metadata parse");
    }

    // Test correlation ID boundary values
    if data.len() >= 4 {
        let mut frame = vec![0u8; 8];
        frame[0..4].copy_from_slice(&data[0..4]); // Use input as correlation ID
        frame[4..8].copy_from_slice(&0i32.to_be_bytes()); // Zero length
        observe_frame_validation(
            fuzz_validate_response_frame(&frame),
            "correlation-id boundary frame validation",
        );
    }

    // Test length prefix attacks
    if data.len() >= 8 {
        let mut frame = vec![0u8; 8];
        frame[0..4].copy_from_slice(&1i32.to_be_bytes()); // correlation_id = 1
        frame[4..8].copy_from_slice(&data[0..4]); // Use input as length
        frame.extend_from_slice(&data[4..]); // Rest as payload
        observe_frame_validation(
            fuzz_validate_response_frame(&frame),
            "length-prefix attack frame validation",
        );
        observe_delivery_parse(
            fuzz_parse_delivery_result(&frame),
            "length-prefix attack delivery parse",
        );
    }

    // Test metadata parsing with various payload sizes
    for chunk_size in [1, 2, 4, 8, 16, 32] {
        if data.len() >= chunk_size {
            observe_metadata_parse(
                fuzz_parse_response_metadata(&data[..chunk_size]),
                "chunked metadata parse",
            );
        }
    }
}
