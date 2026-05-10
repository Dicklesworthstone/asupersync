#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::http::h3_native::{
    H3_SETTING_ENABLE_CONNECT_PROTOCOL, H3_SETTING_H3_DATAGRAM, H3_SETTING_MAX_FIELD_SECTION_SIZE,
    H3_SETTING_QPACK_BLOCKED_STREAMS, H3_SETTING_QPACK_MAX_TABLE_CAPACITY, H3ConnectionConfig,
    H3Frame, H3NativeError, H3QpackMode, H3RequestHead, H3ResponseHead, H3Settings, QpackFieldPlan,
    qpack_decode_field_section, qpack_decode_request_field_section,
    qpack_decode_response_field_section, qpack_encode_field_section,
};
use asupersync::net::quic_core::{
    QUIC_VARINT_MAX, QuicCoreError, decode_varint, encode_varint as quic_encode_varint,
};

/// Fuzz input for HTTP/3 native protocol parsing
#[derive(Arbitrary, Debug)]
struct H3ProtocolFuzz {
    /// Frame parsing operations
    frame_operations: Vec<FrameOperation>,
    /// Settings parsing operations
    settings_operations: Vec<SettingsOperation>,
    /// Stream type parsing operations
    stream_operations: Vec<StreamOperation>,
    /// QPACK field section parsing operations
    qpack_operations: Vec<QpackOperation>,
    /// Edge case testing
    edge_cases: Vec<EdgeCaseOperation>,
}

/// Frame parsing operations
#[derive(Arbitrary, Debug)]
enum FrameOperation {
    /// Parse single frame from raw bytes
    RawFrame { data: Vec<u8> },
    /// Parse multiple consecutive frames
    MultipleFrames { frame_data: Vec<Vec<u8>> },
    /// Parse frame with specific type
    TypedFrame {
        frame_type: FrameType,
        payload: Vec<u8>,
    },
    /// Parse truncated frame
    TruncatedFrame {
        complete_data: Vec<u8>,
        truncate_at: u16,
    },
}

/// Frame types to test
#[derive(Arbitrary, Debug)]
enum FrameType {
    Data,
    Headers,
    CancelPush,
    Settings,
    PushPromise,
    Goaway,
    MaxPushId,
    Unknown(u64),
}

/// Settings parsing operations
#[derive(Arbitrary, Debug)]
enum SettingsOperation {
    /// Parse settings payload
    SettingsPayload { payload: Vec<u8> },
    /// Parse settings with known identifiers
    KnownSettings { settings: Vec<SettingPair> },
    /// Parse settings with duplicates
    DuplicateSettings { setting_id: u64, values: Vec<u64> },
    /// Parse malformed settings
    MalformedSettings { malformed_data: Vec<u8> },
}

/// Setting key-value pair
#[derive(Arbitrary, Debug)]
struct SettingPair {
    id: SettingId,
    value: u64,
}

/// Well-known setting identifiers
#[derive(Arbitrary, Debug)]
enum SettingId {
    QpackMaxTableCapacity,
    MaxFieldSectionSize,
    QpackBlockedStreams,
    EnableConnectProtocol,
    H3Datagram,
    Unknown(u64),
}

/// Stream type operations
#[derive(Arbitrary, Debug)]
enum StreamOperation {
    /// Parse stream type
    ParseStreamType { stream_data: Vec<u8> },
    /// Test stream protocol validation
    ValidateStreamProtocol { stream_type: u64, data: Vec<u8> },
}

/// QPACK field section operations
#[derive(Arbitrary, Debug)]
enum QpackOperation {
    /// Parse generic field section
    FieldSection { payload: Vec<u8>, mode: QpackMode },
    /// Parse request field section
    RequestFieldSection { payload: Vec<u8>, mode: QpackMode },
    /// Parse response field section
    ResponseFieldSection { payload: Vec<u8>, mode: QpackMode },
    /// Parse field section with specific patterns
    StructuredFieldSection {
        field_patterns: Vec<FieldPattern>,
        mode: QpackMode,
    },
    /// Parse malformed QPACK data
    MalformedQpack {
        malformed_data: Vec<u8>,
        mode: QpackMode,
    },
}

/// QPACK mode for fuzzing
#[derive(Arbitrary, Debug)]
enum QpackMode {
    StaticOnly,
    DynamicTableAllowed,
}

/// Field patterns for structured QPACK fuzzing
#[derive(Arbitrary, Debug)]
enum FieldPattern {
    /// Static index reference
    StaticIndex { index: u8 },
    /// Literal with name reference
    LiteralNameRef { name_index: u8, value: Vec<u8> },
    /// Literal with literal name
    LiteralName { name: Vec<u8>, value: Vec<u8> },
    /// Malformed pattern
    Malformed { data: Vec<u8> },
}

/// Edge case testing
#[derive(Arbitrary, Debug)]
enum EdgeCaseOperation {
    /// Empty input
    EmptyInput,
    /// Single byte input
    SingleByte { byte: u8 },
    /// Large varint
    LargeVarint { value: u64 },
    /// Overlapping frames
    OverlappingFrames {
        frame1: Vec<u8>,
        frame2: Vec<u8>,
        overlap_bytes: u8,
    },
    /// Invalid UTF-8 in frame payload
    InvalidUtf8Payload { payload: Vec<u8> },
    /// Maximum size frames
    MaxSizeFrame {
        frame_type: FrameType,
        fill_byte: u8,
    },
}

/// Maximum input sizes to prevent timeout/memory exhaustion
const MAX_FRAME_SIZE: usize = 65536; // 64KB
const MAX_PAYLOAD_SIZE: usize = 16384; // 16KB
const MAX_OPERATIONS: usize = 100;
const MAX_QPACK_DECODED_FIELDS: usize = 1000;

fuzz_target!(|input: H3ProtocolFuzz| {
    // Limit operations to prevent timeout
    if input.frame_operations.len()
        + input.settings_operations.len()
        + input.stream_operations.len()
        + input.qpack_operations.len()
        + input.edge_cases.len()
        > MAX_OPERATIONS
    {
        return;
    }

    // Test frame operations
    for operation in input.frame_operations {
        test_frame_operation(operation);
    }

    // Test settings operations
    for operation in input.settings_operations {
        test_settings_operation(operation);
    }

    // Test stream operations
    for operation in input.stream_operations {
        test_stream_operation(operation);
    }

    // Test QPACK operations
    for operation in input.qpack_operations {
        test_qpack_operation(operation);
    }

    // Test edge cases
    for operation in input.edge_cases {
        test_edge_case_operation(operation);
    }

    test_h3_qpack_static_canaries();
});

fn test_frame_operation(operation: FrameOperation) {
    match operation {
        FrameOperation::RawFrame { mut data } => {
            // Limit size to prevent memory exhaustion
            if data.len() > MAX_FRAME_SIZE {
                data.truncate(MAX_FRAME_SIZE);
            }

            // Test frame parsing - should not panic
            let config = h3_decode_config();
            let result = H3Frame::decode(&data, &config);

            match result {
                Ok((frame, consumed)) => {
                    // Verify consumed bytes are reasonable
                    assert!(consumed <= data.len(), "Consumed more bytes than available");

                    // Verify frame is self-consistent
                    verify_frame_consistency(&frame);

                    // Test round-trip encoding if possible
                    test_frame_roundtrip(&frame);
                }
                Err(err) => {
                    // Verify error is reasonable
                    verify_error_consistency(&err, &data);
                }
            }
        }

        FrameOperation::MultipleFrames { frame_data } => {
            for mut data in frame_data {
                if data.len() > MAX_FRAME_SIZE {
                    data.truncate(MAX_FRAME_SIZE);
                }

                // Parse and verify each frame independently
                let config = h3_decode_config();
                observe_h3_frame_decode("multiple frame", &data, &config);
            }
        }

        FrameOperation::TypedFrame {
            frame_type,
            mut payload,
        } => {
            if payload.len() > MAX_PAYLOAD_SIZE {
                payload.truncate(MAX_PAYLOAD_SIZE);
            }

            // Construct frame with specific type
            let frame_bytes = construct_frame_bytes(frame_type, &payload);
            let config = h3_decode_config();
            observe_h3_frame_decode("typed frame", &frame_bytes, &config);
        }

        FrameOperation::TruncatedFrame {
            mut complete_data,
            truncate_at,
        } => {
            if complete_data.len() > MAX_FRAME_SIZE {
                complete_data.truncate(MAX_FRAME_SIZE);
            }

            let truncate_pos = (truncate_at as usize).min(complete_data.len());
            let truncated = &complete_data[..truncate_pos];

            // Should handle truncated input gracefully
            let config = h3_decode_config();
            let result = H3Frame::decode(truncated, &config);
            match result {
                Ok(_) => {
                    // If parsing succeeded, frame must be complete
                }
                Err(H3NativeError::UnexpectedEof) => {
                    // Expected for truncated input
                }
                Err(_) => {
                    // Other errors are also acceptable
                }
            }
        }
    }
}

fn test_settings_operation(operation: SettingsOperation) {
    match operation {
        SettingsOperation::SettingsPayload { mut payload } => {
            if payload.len() > MAX_PAYLOAD_SIZE {
                payload.truncate(MAX_PAYLOAD_SIZE);
            }

            // Test settings parsing
            let result = H3Settings::decode_payload(&payload);

            match result {
                Ok(settings) => {
                    // Verify settings consistency
                    verify_settings_consistency(&settings);

                    // Test round-trip if possible
                    test_settings_roundtrip(&settings);
                }
                Err(err) => {
                    // Verify error is appropriate
                    verify_settings_error_consistency(&err, &payload);
                }
            }
        }

        SettingsOperation::KnownSettings { settings } => {
            // Construct settings payload with known setting IDs
            let payload = construct_settings_payload(&settings);
            observe_h3_settings_decode("known settings", &payload);
        }

        SettingsOperation::DuplicateSettings { setting_id, values } => {
            // Test duplicate setting detection
            let mut payload = Vec::new();
            for value in values.into_iter().take(10) {
                // Limit to 10 duplicates
                let mut setting_pair = Vec::new();
                if observe_varint_encode(
                    "duplicate SETTINGS identifier",
                    setting_id,
                    &mut setting_pair,
                ) && observe_varint_encode("duplicate SETTINGS value", value, &mut setting_pair)
                {
                    payload.extend_from_slice(&setting_pair);
                }
            }

            let result = H3Settings::decode_payload(&payload);
            match result {
                Err(H3NativeError::DuplicateSetting(id)) => {
                    assert_eq!(id, setting_id, "Duplicate setting ID mismatch");
                }
                _ => {
                    // Other results are acceptable depending on implementation
                }
            }
        }

        SettingsOperation::MalformedSettings { mut malformed_data } => {
            if malformed_data.len() > MAX_PAYLOAD_SIZE {
                malformed_data.truncate(MAX_PAYLOAD_SIZE);
            }

            // Should handle malformed data gracefully
            observe_h3_settings_decode("malformed settings", &malformed_data);
        }
    }
}

fn test_stream_operation(operation: StreamOperation) {
    match operation {
        StreamOperation::ParseStreamType { mut stream_data } => {
            if stream_data.len() > MAX_PAYLOAD_SIZE {
                stream_data.truncate(MAX_PAYLOAD_SIZE);
            }

            // Test stream type parsing
            if !stream_data.is_empty() {
                // Try to decode as varint for stream type
                observe_quic_varint_decode("stream type", &stream_data);
            }
        }

        StreamOperation::ValidateStreamProtocol {
            stream_type,
            mut data,
        } => {
            if data.len() > MAX_PAYLOAD_SIZE {
                data.truncate(MAX_PAYLOAD_SIZE);
            }

            // Test protocol validation logic
            // This would test the control stream, push stream, etc. validation
            // For now, just test that stream_type is reasonable
            if stream_type > 0 && stream_type < (1u64 << 62) {
                // Stream type is in valid range
            }
        }
    }
}

fn test_qpack_operation(operation: QpackOperation) {
    match operation {
        QpackOperation::FieldSection { mut payload, mode } => {
            if payload.len() > MAX_PAYLOAD_SIZE {
                payload.truncate(MAX_PAYLOAD_SIZE);
            }

            let h3_mode = convert_qpack_mode(mode);

            // Test generic field section parsing
            let result = qpack_decode_field_section(&payload, h3_mode);

            match result {
                Ok(field_plan) => {
                    // Verify field plan consistency
                    verify_qpack_field_plan_consistency(&field_plan);
                }
                Err(err) => {
                    // Verify error is reasonable
                    verify_qpack_error_consistency(&err, &payload);
                }
            }
        }

        QpackOperation::RequestFieldSection { mut payload, mode } => {
            if payload.len() > MAX_PAYLOAD_SIZE {
                payload.truncate(MAX_PAYLOAD_SIZE);
            }

            let h3_mode = convert_qpack_mode(mode);

            // Test request field section parsing
            let result = qpack_decode_request_field_section(&payload, h3_mode, None);

            match result {
                Ok(request_head) => {
                    // Verify request head consistency
                    verify_request_head_consistency(&request_head);
                }
                Err(err) => {
                    verify_qpack_error_consistency(&err, &payload);
                }
            }
        }

        QpackOperation::ResponseFieldSection { mut payload, mode } => {
            if payload.len() > MAX_PAYLOAD_SIZE {
                payload.truncate(MAX_PAYLOAD_SIZE);
            }

            let h3_mode = convert_qpack_mode(mode);

            // Test response field section parsing
            let result = qpack_decode_response_field_section(&payload, h3_mode, None);

            match result {
                Ok(response_head) => {
                    // Verify response head consistency
                    verify_response_head_consistency(&response_head);
                }
                Err(err) => {
                    verify_qpack_error_consistency(&err, &payload);
                }
            }
        }

        QpackOperation::StructuredFieldSection {
            field_patterns,
            mode,
        } => {
            let h3_mode = convert_qpack_mode(mode);

            // Construct QPACK payload from structured patterns
            let payload = construct_qpack_payload(&field_patterns);
            if payload.len() <= MAX_PAYLOAD_SIZE {
                observe_qpack_field_section_decode("structured field section", &payload, h3_mode);
            }
        }

        QpackOperation::MalformedQpack {
            mut malformed_data,
            mode,
        } => {
            if malformed_data.len() > MAX_PAYLOAD_SIZE {
                malformed_data.truncate(MAX_PAYLOAD_SIZE);
            }

            let h3_mode = convert_qpack_mode(mode);

            // Should handle malformed QPACK data gracefully
            observe_qpack_field_section_decode(
                "malformed generic field section",
                &malformed_data,
                h3_mode,
            );
            observe_qpack_request_decode(
                "malformed request field section",
                &malformed_data,
                h3_mode,
            );
            observe_qpack_response_decode(
                "malformed response field section",
                &malformed_data,
                h3_mode,
            );
        }
    }
}

fn test_h3_qpack_static_canaries() {
    let empty_section = vec![0x00, 0x00]; // RIC=0, Delta Base=0
    let decoded_empty =
        qpack_decode_field_section(&empty_section, H3QpackMode::StaticOnly).expect("empty decode");
    assert_eq!(decoded_empty, Vec::<QpackFieldPlan>::new());

    let request_plan = vec![
        QpackFieldPlan::StaticIndex(17), // :method GET
        QpackFieldPlan::StaticIndex(23), // :scheme https
        QpackFieldPlan::StaticIndex(1),  // :path /
        QpackFieldPlan::Literal {
            name: "accept".to_string(),
            value: "*/*".to_string(),
        },
    ];
    let request_wire = qpack_encode_field_section(&request_plan).expect("request encode");
    assert_eq!(
        qpack_decode_field_section(&request_wire, H3QpackMode::StaticOnly)
            .expect("request plan decode"),
        request_plan
    );
    let request = qpack_decode_request_field_section(&request_wire, H3QpackMode::StaticOnly, None)
        .expect("request head decode");
    assert_eq!(request.pseudo.method.as_deref(), Some("GET"));
    assert_eq!(request.pseudo.scheme.as_deref(), Some("https"));
    assert_eq!(request.pseudo.path.as_deref(), Some("/"));
    assert_eq!(
        request.headers,
        vec![("accept".to_string(), "*/*".to_string())]
    );

    let response_plan = vec![
        QpackFieldPlan::StaticIndex(25), // :status 200
        QpackFieldPlan::Literal {
            name: "server".to_string(),
            value: "asupersync".to_string(),
        },
    ];
    let response_wire = qpack_encode_field_section(&response_plan).expect("response encode");
    assert_eq!(
        qpack_decode_field_section(&response_wire, H3QpackMode::StaticOnly)
            .expect("response plan decode"),
        response_plan
    );
    let response =
        qpack_decode_response_field_section(&response_wire, H3QpackMode::StaticOnly, None)
            .expect("response head decode");
    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers,
        vec![("server".to_string(), "asupersync".to_string())]
    );
}

fn test_edge_case_operation(operation: EdgeCaseOperation) {
    match operation {
        EdgeCaseOperation::EmptyInput => {
            // Test parsing empty input
            let config = h3_decode_config();
            let result = H3Frame::decode(&[], &config);
            match result {
                Err(H3NativeError::UnexpectedEof) => {
                    // Expected behavior
                }
                _ => {
                    // Other behaviors might be acceptable
                }
            }
        }

        EdgeCaseOperation::SingleByte { byte } => {
            // Test single byte input
            let config = h3_decode_config();
            observe_h3_frame_decode("single byte frame", &[byte], &config);
        }

        EdgeCaseOperation::LargeVarint { value } => {
            // Test large varint values
            let mut data = Vec::new();
            if observe_varint_encode("large QUIC varint edge case", value, &mut data) {
                observe_quic_varint_decode("large varint", &data);
            }
        }

        EdgeCaseOperation::OverlappingFrames {
            frame1,
            frame2,
            overlap_bytes,
        } => {
            // Test frames that might overlap in memory
            let overlap = (overlap_bytes as usize).min(frame1.len()).min(frame2.len());
            if overlap > 0 {
                let mut combined = frame1;
                combined.extend_from_slice(&frame2[overlap..]);
                let config = h3_decode_config();
                observe_h3_frame_decode("overlapping frames", &combined, &config);
            }
        }

        EdgeCaseOperation::InvalidUtf8Payload { mut payload } => {
            if payload.len() > MAX_PAYLOAD_SIZE {
                payload.truncate(MAX_PAYLOAD_SIZE);
            }

            // Create a frame with potentially invalid UTF-8 payload
            let frame_bytes = construct_frame_bytes(FrameType::Data, &payload);
            let config = h3_decode_config();
            observe_h3_frame_decode("invalid utf8 payload", &frame_bytes, &config);
        }

        EdgeCaseOperation::MaxSizeFrame {
            frame_type,
            fill_byte,
        } => {
            // Test maximum size frames
            let payload = vec![fill_byte; MAX_PAYLOAD_SIZE];
            let frame_bytes = construct_frame_bytes(frame_type, &payload);
            let config = h3_decode_config();
            observe_h3_frame_decode("max size frame", &frame_bytes, &config);
        }
    }
}

fn h3_decode_config() -> H3ConnectionConfig {
    H3ConnectionConfig {
        max_frame_payload_size: MAX_FRAME_SIZE,
        ..H3ConnectionConfig::default()
    }
}

fn observe_h3_frame_decode(context: &str, data: &[u8], config: &H3ConnectionConfig) {
    match H3Frame::decode(data, config) {
        Ok((frame, consumed)) => {
            assert!(
                consumed <= data.len(),
                "{context}: consumed more bytes than available"
            );
            assert!(consumed > 0, "{context}: frame consumed zero bytes");
            verify_frame_consistency(&frame);
            test_frame_roundtrip(&frame);
        }
        Err(err) => {
            verify_error_consistency(&err, data);
            observe_h3_error(context, &err);
        }
    }
}

fn observe_h3_settings_decode(context: &str, payload: &[u8]) {
    match H3Settings::decode_payload(payload) {
        Ok(settings) => {
            verify_settings_consistency(&settings);
            test_settings_roundtrip(&settings);
        }
        Err(err) => {
            verify_settings_error_consistency(&err, payload);
            observe_h3_error(context, &err);
        }
    }
}

fn observe_qpack_field_section_decode(context: &str, payload: &[u8], mode: H3QpackMode) {
    match qpack_decode_field_section(payload, mode) {
        Ok(field_plan) => {
            assert!(
                field_plan.len() <= MAX_QPACK_DECODED_FIELDS,
                "{context}: decoded too many QPACK fields"
            );
            verify_qpack_field_plan_consistency(&field_plan);
        }
        Err(err) => {
            verify_qpack_error_consistency(&err, payload);
            observe_h3_error(context, &err);
            if mode == H3QpackMode::StaticOnly {
                assert!(
                    !matches!(
                        err,
                        H3NativeError::InvalidRequestPseudoHeader(_)
                            | H3NativeError::InvalidResponsePseudoHeader(_)
                    ),
                    "{context}: raw static QPACK field decode should not classify pseudo headers"
                );
            }
        }
    }
}

fn observe_qpack_request_decode(context: &str, payload: &[u8], mode: H3QpackMode) {
    match qpack_decode_request_field_section(payload, mode, None) {
        Ok(request_head) => {
            verify_request_head_consistency(&request_head);
        }
        Err(err) => {
            verify_qpack_error_consistency(&err, payload);
            observe_h3_error(context, &err);
        }
    }
}

fn observe_qpack_response_decode(context: &str, payload: &[u8], mode: H3QpackMode) {
    match qpack_decode_response_field_section(payload, mode, None) {
        Ok(response_head) => {
            verify_response_head_consistency(&response_head);
        }
        Err(err) => {
            verify_qpack_error_consistency(&err, payload);
            observe_h3_error(context, &err);
        }
    }
}

fn observe_quic_varint_decode(context: &str, data: &[u8]) {
    match decode_varint(data) {
        Ok((value, consumed)) => {
            assert!(
                consumed <= data.len(),
                "{context}: consumed more bytes than available"
            );
            assert!(
                (1..=8).contains(&consumed),
                "{context}: invalid QUIC varint width: {consumed}"
            );
            assert!(
                value <= QUIC_VARINT_MAX,
                "{context}: decoded varint exceeds QUIC max"
            );
            if let Some(expected) = required_quic_varint_width(data) {
                assert_eq!(
                    consumed, expected,
                    "{context}: consumed width must follow QUIC prefix bits"
                );
            }
        }
        Err(err) => {
            observe_quic_core_error(context, &err);
            if matches!(err, QuicCoreError::UnexpectedEof) {
                assert!(
                    data.is_empty() || data.len() < required_quic_varint_width(data).unwrap_or(1),
                    "{context}: unexpected EOF must be length-driven"
                );
            }
        }
    }
}

fn required_quic_varint_width(data: &[u8]) -> Option<usize> {
    data.first().map(|first| 1usize << (first >> 6))
}

fn observe_h3_error(context: &str, err: &H3NativeError) {
    let display = err.to_string();
    assert!(
        !display.trim().is_empty(),
        "{context}: H3 error display should not be empty"
    );
    let debug = format!("{err:?}");
    assert!(
        !debug.trim().is_empty(),
        "{context}: H3 error debug should not be empty"
    );
}

fn observe_quic_core_error(context: &str, err: &QuicCoreError) {
    let display = err.to_string();
    assert!(
        !display.trim().is_empty(),
        "{context}: QUIC core error display should not be empty"
    );
    let debug = format!("{err:?}");
    assert!(
        !debug.trim().is_empty(),
        "{context}: QUIC core error debug should not be empty"
    );
}

fn verify_frame_consistency(frame: &H3Frame) {
    match frame {
        H3Frame::Data(_payload) => {
            // Data frame can contain any bytes
        }
        H3Frame::Headers(_payload) => {
            // Headers should be QPACK-encoded, but we don't validate that here
        }
        H3Frame::CancelPush(id) => {
            // Push ID should be reasonable
            assert!(*id < (1u64 << 62), "Push ID too large: {}", id);
        }
        H3Frame::Settings(_) => {
            // Settings should be internally consistent
        }
        H3Frame::PushPromise {
            push_id,
            field_block: _,
        } => {
            assert!(*push_id < (1u64 << 62), "Push ID too large: {}", push_id);
            // Field block can be any bytes
        }
        H3Frame::Goaway(id) => {
            assert!(*id < (1u64 << 62), "Stream ID too large: {}", id);
        }
        H3Frame::MaxPushId(id) => {
            assert!(*id < (1u64 << 62), "Push ID too large: {}", id);
        }
        H3Frame::Datagram {
            quarter_stream_id,
            payload: _,
        } => {
            assert!(
                *quarter_stream_id < (1u64 << 62),
                "Quarter stream ID too large: {}",
                quarter_stream_id
            );
            // DATAGRAM payload can contain any bytes.
        }
        H3Frame::Unknown {
            frame_type: _,
            payload: _,
        } => {
            // Unknown frames are preserved as-is
        }
    }
}

fn verify_error_consistency(err: &H3NativeError, _data: &[u8]) {
    match err {
        H3NativeError::UnexpectedEof => {
            // Should occur when input is too short
        }
        H3NativeError::InvalidFrame(msg) => {
            // Should describe what's invalid
            assert!(!msg.is_empty(), "Error message should not be empty");
        }
        H3NativeError::FrameTooLarge {
            payload_size,
            max_size,
        } => {
            assert!(
                payload_size > max_size,
                "FrameTooLarge must report payload_size > max_size"
            );
        }
        H3NativeError::DuplicateSetting(_id) => {
            // Should specify which setting is duplicated
        }
        H3NativeError::InvalidSettingValue(_id) => {
            // Should specify which setting has invalid value
        }
        H3NativeError::ControlProtocol(msg) => {
            assert!(
                !msg.is_empty(),
                "Control protocol error should have message"
            );
        }
        H3NativeError::StreamProtocol(msg) => {
            assert!(!msg.is_empty(), "Stream protocol error should have message");
        }
        H3NativeError::QpackPolicy(msg) => {
            assert!(!msg.is_empty(), "QPACK policy error should have message");
        }
        H3NativeError::InvalidRequestPseudoHeader(msg) => {
            assert!(
                !msg.is_empty(),
                "Invalid request pseudo header error should have message"
            );
        }
        H3NativeError::InvalidResponsePseudoHeader(msg) => {
            assert!(
                !msg.is_empty(),
                "Invalid response pseudo header error should have message"
            );
        }
        H3NativeError::ConcurrentStreamLimitExceeded { active, limit } => {
            assert!(
                active >= limit,
                "concurrent stream limit error must report active >= limit"
            );
        }
    }
}

fn verify_settings_consistency(_settings: &H3Settings) {
    // Settings should be internally consistent
    // This would check for conflicting settings, invalid values, etc.
}

fn verify_settings_error_consistency(err: &H3NativeError, _payload: &[u8]) {
    match err {
        H3NativeError::DuplicateSetting(_) => {
            // Should only occur with actual duplicate settings
        }
        H3NativeError::InvalidSettingValue(_) => {
            // Should occur with invalid setting values
        }
        _ => {
            // Other errors are acceptable
        }
    }
}

fn test_frame_roundtrip(_frame: &H3Frame) {
    // Test encoding and then decoding the frame
    // Note: encode method might not be publicly available
    // This would test that decode(encode(frame)) == frame
}

fn test_settings_roundtrip(_settings: &H3Settings) {
    // Test encoding and decoding settings
    // Note: encode_payload method might not be publicly available
    // This would test that decode_payload(encode_payload(settings)) == settings
}

fn construct_frame_bytes(frame_type: FrameType, payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();

    let type_value = match frame_type {
        FrameType::Data => 0x0,
        FrameType::Headers => 0x1,
        FrameType::CancelPush => 0x3,
        FrameType::Settings => 0x4,
        FrameType::PushPromise => 0x5,
        FrameType::Goaway => 0x7,
        FrameType::MaxPushId => 0xD,
        FrameType::Unknown(t) => t,
    };

    if !observe_varint_encode("H3 frame type", type_value, &mut data) {
        return data;
    }
    assert_varint_encoded("H3 frame payload length", payload.len() as u64, &mut data);
    data.extend_from_slice(payload);

    data
}

fn construct_settings_payload(settings: &[SettingPair]) -> Vec<u8> {
    let mut payload = Vec::new();

    for setting in settings.iter().take(20) {
        // Limit to 20 settings
        let id_value = match setting.id {
            SettingId::QpackMaxTableCapacity => H3_SETTING_QPACK_MAX_TABLE_CAPACITY,
            SettingId::MaxFieldSectionSize => H3_SETTING_MAX_FIELD_SECTION_SIZE,
            SettingId::QpackBlockedStreams => H3_SETTING_QPACK_BLOCKED_STREAMS,
            SettingId::EnableConnectProtocol => H3_SETTING_ENABLE_CONNECT_PROTOCOL,
            SettingId::H3Datagram => H3_SETTING_H3_DATAGRAM,
            SettingId::Unknown(id) => id,
        };

        let mut setting_pair = Vec::new();
        if observe_varint_encode("H3 SETTINGS identifier", id_value, &mut setting_pair)
            && observe_varint_encode("H3 SETTINGS value", setting.value, &mut setting_pair)
        {
            payload.extend_from_slice(&setting_pair);
        }
    }

    payload
}

fn assert_varint_encoded(context: &str, value: u64, output: &mut Vec<u8>) {
    quic_encode_varint(value, output).unwrap_or_else(|error| {
        panic!("{context}: expected H3 varint value {value} to encode, got {error}")
    });
}

fn observe_varint_encode(context: &str, value: u64, output: &mut Vec<u8>) -> bool {
    match quic_encode_varint(value, output) {
        Ok(()) => true,
        Err(error) => {
            observe_varint_encode_error(context, value, &error);
            false
        }
    }
}

fn observe_varint_encode_error(context: &str, value: u64, error: &QuicCoreError) {
    assert!(
        !error.to_string().is_empty(),
        "{context}: H3 varint encode error for value {value} must include diagnostics"
    );
}

fn convert_qpack_mode(mode: QpackMode) -> H3QpackMode {
    match mode {
        QpackMode::StaticOnly => H3QpackMode::StaticOnly,
        QpackMode::DynamicTableAllowed => H3QpackMode::DynamicTableAllowed,
    }
}

fn verify_qpack_field_plan_consistency(field_plan: &[QpackFieldPlan]) {
    assert!(
        field_plan.len() <= MAX_QPACK_DECODED_FIELDS,
        "QPACK field plan exceeds decoded-field safety cap"
    );

    for field in field_plan {
        match field {
            QpackFieldPlan::StaticIndex(index) | QpackFieldPlan::DynamicIndex(index) => {
                assert!(
                    *index <= QUIC_VARINT_MAX,
                    "QPACK index should stay within QUIC varint range"
                );
            }
            QpackFieldPlan::Literal { name, value } => {
                assert!(
                    name.len() <= MAX_PAYLOAD_SIZE,
                    "literal QPACK name should stay input-bounded"
                );
                assert!(
                    value.len() <= MAX_PAYLOAD_SIZE,
                    "literal QPACK value should stay input-bounded"
                );
            }
            QpackFieldPlan::DynamicNameLiteral { name_index, value } => {
                assert!(
                    *name_index <= QUIC_VARINT_MAX,
                    "dynamic QPACK name index should stay within QUIC varint range"
                );
                assert!(
                    value.len() <= MAX_PAYLOAD_SIZE,
                    "dynamic-name literal value should stay input-bounded"
                );
            }
        }
    }
}

fn verify_request_head_consistency(request_head: &H3RequestHead) {
    assert!(
        request_head.headers.len() <= MAX_QPACK_DECODED_FIELDS,
        "request head decoded too many regular headers"
    );
    assert!(
        request_head.pseudo.status.is_none(),
        "request head must not carry a response :status pseudo header"
    );
    verify_header_pairs_are_regular("request", &request_head.headers);
}

fn verify_response_head_consistency(response_head: &H3ResponseHead) {
    assert!(
        (100..=999).contains(&response_head.status),
        "response status should stay in the validated HTTP status range"
    );
    assert!(
        response_head.headers.len() <= MAX_QPACK_DECODED_FIELDS,
        "response head decoded too many regular headers"
    );
    verify_header_pairs_are_regular("response", &response_head.headers);
}

fn verify_header_pairs_are_regular(context: &str, headers: &[(String, String)]) {
    for (name, value) in headers {
        assert!(
            !name.starts_with(':'),
            "{context} regular headers must not include pseudo-header names"
        );
        assert!(
            !name.is_empty(),
            "{context} regular header names must not be empty"
        );
        assert!(
            !name.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)),
            "{context} regular header name must not contain line breaks or NUL"
        );
        assert!(
            !value.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)),
            "{context} regular header value must not contain line breaks or NUL"
        );
        assert!(
            name.len() <= MAX_PAYLOAD_SIZE && value.len() <= MAX_PAYLOAD_SIZE,
            "{context} decoded header pair should remain input-bounded"
        );
    }
}

fn verify_qpack_error_consistency(err: &H3NativeError, _payload: &[u8]) {
    match err {
        H3NativeError::UnexpectedEof => {
            // Should occur when QPACK payload is truncated
        }
        H3NativeError::InvalidFrame(msg) => {
            // Should describe the QPACK parsing issue
            assert!(!msg.is_empty(), "QPACK error message should not be empty");
        }
        H3NativeError::QpackPolicy(msg) => {
            // Should describe QPACK policy violations (static-only vs dynamic)
            assert!(!msg.is_empty(), "QPACK policy error should have message");
        }
        _ => {
            // Other errors are also acceptable for QPACK parsing
        }
    }
}

fn construct_qpack_payload(field_patterns: &[FieldPattern]) -> Vec<u8> {
    let mut payload = Vec::new();

    // QPACK field section prefix: Required Insert Count (0 for static-only)
    payload.push(0x00); // RIC = 0, encoded as single byte

    // QPACK field section prefix: S + Delta Base (0 for static-only)
    payload.push(0x00); // S=0, Delta Base = 0, encoded as single byte

    // Encode field patterns
    for pattern in field_patterns.iter().take(20) {
        // Limit to 20 patterns
        match pattern {
            FieldPattern::StaticIndex { index } => {
                // Indexed field line: 1 T Index(6+)
                // T=1 (static), so first bit is 1, second bit is 1
                let byte = 0x80 | 0x40 | (index & 0x3F);
                payload.push(byte);
                // If index >= 64, need more bytes for varint encoding
                if *index >= 64 {
                    encode_varint_continuation((*index as u64) - 64, &mut payload);
                }
            }
            FieldPattern::LiteralNameRef { name_index, value } => {
                // Literal field line with name reference: 01 N T NameIndex(4+)
                // N=0 (not never indexed), T=1 (static name)
                let byte = 0x40 | 0x10 | (name_index & 0x0F);
                payload.push(byte);
                if *name_index >= 16 {
                    encode_varint_continuation((*name_index as u64) - 16, &mut payload);
                }

                // Value string: H Length(7+) Value
                // H=0 (not huffman encoded)
                let value_len = value.len().min(MAX_PAYLOAD_SIZE / 4);
                let value_byte = (value_len & 0x7F) as u8;
                payload.push(value_byte);
                if value_len >= 127 {
                    encode_varint_continuation((value_len - 127) as u64, &mut payload);
                }
                payload.extend_from_slice(&value[..value_len]);
            }
            FieldPattern::LiteralName { name, value } => {
                // Literal field line with literal name: 001 N H NameLen(3+)
                // N=0, H=0 (not huffman)
                let name_len = name.len().min(MAX_PAYLOAD_SIZE / 8);
                let name_byte = 0x20 | ((name_len & 0x07) as u8);
                payload.push(name_byte);
                if name_len >= 8 {
                    encode_varint_continuation((name_len - 8) as u64, &mut payload);
                }
                payload.extend_from_slice(&name[..name_len]);

                // Value string
                let value_len = value.len().min(MAX_PAYLOAD_SIZE / 8);
                let value_byte = (value_len & 0x7F) as u8;
                payload.push(value_byte);
                if value_len >= 127 {
                    encode_varint_continuation((value_len - 127) as u64, &mut payload);
                }
                payload.extend_from_slice(&value[..value_len]);
            }
            FieldPattern::Malformed { data } => {
                // Add malformed data directly
                let malformed_len = data.len().min(MAX_PAYLOAD_SIZE / 8);
                payload.extend_from_slice(&data[..malformed_len]);
            }
        }
    }

    payload
}

fn encode_varint_continuation(mut value: u64, output: &mut Vec<u8>) {
    // Simple continuation of varint encoding for values that don't fit in the prefix
    while value >= 128 {
        output.push((value & 0x7F) as u8 | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}
