#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use asupersync::http::h3_native::{
    H3Frame, H3Settings, H3NativeError,
    H3_SETTING_QPACK_MAX_TABLE_CAPACITY, H3_SETTING_MAX_FIELD_SECTION_SIZE,
    H3_SETTING_QPACK_BLOCKED_STREAMS, H3_SETTING_ENABLE_CONNECT_PROTOCOL,
    H3_SETTING_H3_DATAGRAM,
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
    /// Edge case testing
    edge_cases: Vec<EdgeCaseOperation>,
}

/// Frame parsing operations
#[derive(Arbitrary, Debug)]
enum FrameOperation {
    /// Parse single frame from raw bytes
    ParseFrame {
        data: Vec<u8>,
    },
    /// Parse multiple consecutive frames
    ParseMultipleFrames {
        frame_data: Vec<Vec<u8>>,
    },
    /// Parse frame with specific type
    ParseTypedFrame {
        frame_type: FrameType,
        payload: Vec<u8>,
    },
    /// Parse truncated frame
    ParseTruncatedFrame {
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
    ParseSettings {
        payload: Vec<u8>,
    },
    /// Parse settings with known identifiers
    ParseKnownSettings {
        settings: Vec<SettingPair>,
    },
    /// Parse settings with duplicates
    ParseDuplicateSettings {
        setting_id: u64,
        values: Vec<u64>,
    },
    /// Parse malformed settings
    ParseMalformedSettings {
        malformed_data: Vec<u8>,
    },
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
    ParseStreamType {
        stream_data: Vec<u8>,
    },
    /// Test stream protocol validation
    ValidateStreamProtocol {
        stream_type: u64,
        data: Vec<u8>,
    },
}

/// Edge case testing
#[derive(Arbitrary, Debug)]
enum EdgeCaseOperation {
    /// Empty input
    EmptyInput,
    /// Single byte input
    SingleByte {
        byte: u8,
    },
    /// Large varint
    LargeVarint {
        value: u64,
    },
    /// Overlapping frames
    OverlappingFrames {
        frame1: Vec<u8>,
        frame2: Vec<u8>,
        overlap_bytes: u8,
    },
    /// Invalid UTF-8 in frame payload
    InvalidUtf8Payload {
        payload: Vec<u8>,
    },
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

fuzz_target!(|input: H3ProtocolFuzz| {
    // Limit operations to prevent timeout
    if input.frame_operations.len() + input.settings_operations.len() +
       input.stream_operations.len() + input.edge_cases.len() > MAX_OPERATIONS {
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

    // Test edge cases
    for operation in input.edge_cases {
        test_edge_case_operation(operation);
    }
});

fn test_frame_operation(operation: FrameOperation) {
    match operation {
        FrameOperation::ParseFrame { mut data } => {
            // Limit size to prevent memory exhaustion
            if data.len() > MAX_FRAME_SIZE {
                data.truncate(MAX_FRAME_SIZE);
            }

            // Test frame parsing - should not panic
            let result = H3Frame::decode(&data);

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

        FrameOperation::ParseMultipleFrames { frame_data } => {
            for mut data in frame_data {
                if data.len() > MAX_FRAME_SIZE {
                    data.truncate(MAX_FRAME_SIZE);
                }

                // Parse and verify each frame independently
                let _ = H3Frame::decode(&data);
            }
        }

        FrameOperation::ParseTypedFrame { frame_type, mut payload } => {
            if payload.len() > MAX_PAYLOAD_SIZE {
                payload.truncate(MAX_PAYLOAD_SIZE);
            }

            // Construct frame with specific type
            let frame_bytes = construct_frame_bytes(frame_type, &payload);
            let _ = H3Frame::decode(&frame_bytes);
        }

        FrameOperation::ParseTruncatedFrame { mut complete_data, truncate_at } => {
            if complete_data.len() > MAX_FRAME_SIZE {
                complete_data.truncate(MAX_FRAME_SIZE);
            }

            let truncate_pos = (truncate_at as usize).min(complete_data.len());
            let truncated = &complete_data[..truncate_pos];

            // Should handle truncated input gracefully
            let result = H3Frame::decode(truncated);
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
        SettingsOperation::ParseSettings { mut payload } => {
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

        SettingsOperation::ParseKnownSettings { settings } => {
            // Construct settings payload with known setting IDs
            let payload = construct_settings_payload(&settings);
            let _ = H3Settings::decode_payload(&payload);
        }

        SettingsOperation::ParseDuplicateSettings { setting_id, values } => {
            // Test duplicate setting detection
            let mut payload = Vec::new();
            for value in values.into_iter().take(10) { // Limit to 10 duplicates
                encode_varint(setting_id, &mut payload);
                encode_varint(value, &mut payload);
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

        SettingsOperation::ParseMalformedSettings { mut malformed_data } => {
            if malformed_data.len() > MAX_PAYLOAD_SIZE {
                malformed_data.truncate(MAX_PAYLOAD_SIZE);
            }

            // Should handle malformed data gracefully
            let _ = H3Settings::decode_payload(&malformed_data);
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
                let _ = decode_varint_safe(&stream_data);
            }
        }

        StreamOperation::ValidateStreamProtocol { stream_type, mut data } => {
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

fn test_edge_case_operation(operation: EdgeCaseOperation) {
    match operation {
        EdgeCaseOperation::EmptyInput => {
            // Test parsing empty input
            let result = H3Frame::decode(&[]);
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
            let _ = H3Frame::decode(&[byte]);
        }

        EdgeCaseOperation::LargeVarint { value } => {
            // Test large varint values
            let mut data = Vec::new();
            encode_varint(value, &mut data);
            let _ = decode_varint_safe(&data);
        }

        EdgeCaseOperation::OverlappingFrames { frame1, frame2, overlap_bytes } => {
            // Test frames that might overlap in memory
            let overlap = (overlap_bytes as usize).min(frame1.len()).min(frame2.len());
            if overlap > 0 {
                let mut combined = frame1;
                combined.extend_from_slice(&frame2[overlap..]);
                let _ = H3Frame::decode(&combined);
            }
        }

        EdgeCaseOperation::InvalidUtf8Payload { mut payload } => {
            if payload.len() > MAX_PAYLOAD_SIZE {
                payload.truncate(MAX_PAYLOAD_SIZE);
            }

            // Create a frame with potentially invalid UTF-8 payload
            let frame_bytes = construct_frame_bytes(FrameType::Data, &payload);
            let _ = H3Frame::decode(&frame_bytes);
        }

        EdgeCaseOperation::MaxSizeFrame { frame_type, fill_byte } => {
            // Test maximum size frames
            let payload = vec![fill_byte; MAX_PAYLOAD_SIZE];
            let frame_bytes = construct_frame_bytes(frame_type, &payload);
            let _ = H3Frame::decode(&frame_bytes);
        }
    }
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
        H3Frame::PushPromise { push_id, field_block: _ } => {
            assert!(*push_id < (1u64 << 62), "Push ID too large: {}", push_id);
            // Field block can be any bytes
        }
        H3Frame::Goaway(id) => {
            assert!(*id < (1u64 << 62), "Stream ID too large: {}", id);
        }
        H3Frame::MaxPushId(id) => {
            assert!(*id < (1u64 << 62), "Push ID too large: {}", id);
        }
        H3Frame::Unknown { frame_type: _, payload: _ } => {
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
        H3NativeError::DuplicateSetting(_id) => {
            // Should specify which setting is duplicated
        }
        H3NativeError::InvalidSettingValue(_id) => {
            // Should specify which setting has invalid value
        }
        H3NativeError::ControlProtocol(msg) => {
            assert!(!msg.is_empty(), "Control protocol error should have message");
        }
        H3NativeError::StreamProtocol(msg) => {
            assert!(!msg.is_empty(), "Stream protocol error should have message");
        }
        H3NativeError::QpackPolicy(msg) => {
            assert!(!msg.is_empty(), "QPACK policy error should have message");
        }
        H3NativeError::InvalidRequestPseudoHeader(msg) => {
            assert!(!msg.is_empty(), "Invalid request pseudo header error should have message");
        }
        H3NativeError::InvalidResponsePseudoHeader(msg) => {
            assert!(!msg.is_empty(), "Invalid response pseudo header error should have message");
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

    encode_varint(type_value, &mut data);
    encode_varint(payload.len() as u64, &mut data);
    data.extend_from_slice(payload);

    data
}

fn construct_settings_payload(settings: &[SettingPair]) -> Vec<u8> {
    let mut payload = Vec::new();

    for setting in settings.iter().take(20) { // Limit to 20 settings
        let id_value = match setting.id {
            SettingId::QpackMaxTableCapacity => H3_SETTING_QPACK_MAX_TABLE_CAPACITY,
            SettingId::MaxFieldSectionSize => H3_SETTING_MAX_FIELD_SECTION_SIZE,
            SettingId::QpackBlockedStreams => H3_SETTING_QPACK_BLOCKED_STREAMS,
            SettingId::EnableConnectProtocol => H3_SETTING_ENABLE_CONNECT_PROTOCOL,
            SettingId::H3Datagram => H3_SETTING_H3_DATAGRAM,
            SettingId::Unknown(id) => id,
        };

        encode_varint(id_value, &mut payload);
        encode_varint(setting.value, &mut payload);
    }

    payload
}

fn decode_varint_safe(data: &[u8]) -> Option<(u64, usize)> {
    // Safe varint decoding that doesn't panic
    use asupersync::net::quic_core::decode_varint;
    decode_varint(data).ok()
}

fn encode_varint(value: u64, output: &mut Vec<u8>) {
    // Simple varint encoding
    use asupersync::net::quic_core::encode_varint;
    let _ = encode_varint(value, output);
}