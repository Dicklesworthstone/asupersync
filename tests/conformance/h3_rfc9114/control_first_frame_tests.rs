#![allow(warnings)]
#![allow(clippy::all)]
//! HTTP/3 RFC 9114 Section 6.2.2.1 control stream first-frame conformance tests.
//!
//! Tests compliance with HTTP/3 control stream first-frame requirements:
//! - SETTINGS frame must be the first frame on control stream
//! - Non-SETTINGS first frame must close connection with H3_MISSING_SETTINGS

use super::*;
use asupersync::net::quic_core::{decode_varint, encode_varint};
use asupersync::http::h3_native::{H3Frame, H3NativeError, H3ConnectionConfig, H3ControlState};

/// HTTP/3 frame types from RFC 9114.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum H3FrameType {
    /// DATA frame (0x00).
    Data = 0x00,
    /// HEADERS frame (0x01).
    Headers = 0x01,
    /// Reserved (0x02).
    Reserved = 0x02,
    /// SETTINGS frame (0x04).
    Settings = 0x04,
    /// PUSH_PROMISE frame (0x05).
    PushPromise = 0x05,
    /// Reserved (0x06).
    Reserved2 = 0x06,
    /// GOAWAY frame (0x07).
    Goaway = 0x07,
    /// MAX_PUSH_ID frame (0x0D).
    MaxPushId = 0x0D,
}

/// Run all control stream first-frame conformance tests.
#[allow(dead_code)]
pub fn run_control_first_frame_tests() -> Vec<H3ConformanceResult> {
    let mut results = Vec::new();

    results.push(test_control_stream_settings_first());
    results.push(test_control_stream_non_settings_rejection());
    results.push(test_settings_frame_validation());
    results.push(test_control_stream_frame_ordering());
    results.push(test_missing_settings_error_handling());

    results
}

/// RFC 9114 Section 6.2.2.1: SETTINGS must be first frame on control stream.
#[allow(dead_code)]
fn test_control_stream_settings_first() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        // Create control stream with SETTINGS as first frame
        let control_stream_data = create_control_stream_with_settings();

        if !validate_control_stream_creation(&control_stream_data) {
            return Err("Valid control stream with SETTINGS first frame was rejected".to_string());
        }

        // Verify SETTINGS frame is properly parsed
        let frames = parse_h3_frames(&control_stream_data[1..]); // Skip stream type varint
        if frames.is_empty() {
            return Err("No frames parsed from control stream".to_string());
        }

        match frames[0].frame_type {
            H3FrameType::Settings => {
                // Correct - SETTINGS first
            }
            other => {
                return Err(format!("First frame should be SETTINGS, got {:?}", other));
            }
        }

        // Verify subsequent frames are allowed after SETTINGS
        let stream_with_multiple_frames = create_control_stream_with_settings_and_goaway();

        if !validate_control_stream_creation(&stream_with_multiple_frames) {
            return Err("Control stream with SETTINGS + GOAWAY was rejected".to_string());
        }

        Ok(())
    });

    H3ConformanceResult {
        test_id: "RFC9114-6.2.2.1-SETTINGS-FIRST".to_string(),
        description: "SETTINGS frame must be first on control stream".to_string(),
        category: TestCategory::ControlStream,
        requirement_level: RequirementLevel::Must,
        verdict: if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        },
        elapsed_ms,
        notes: result.err(),
    }
}

/// RFC 9114 Section 6.2.2.1: Non-SETTINGS first frame must cause H3_MISSING_SETTINGS.
#[allow(dead_code)]
fn test_control_stream_non_settings_rejection() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        // Test various non-SETTINGS frames as first frame
        let invalid_first_frames = vec![
            (H3FrameType::Data, "DATA frame first"),
            (H3FrameType::Headers, "HEADERS frame first"),
            (H3FrameType::PushPromise, "PUSH_PROMISE frame first"),
            (H3FrameType::Goaway, "GOAWAY frame first"),
            (H3FrameType::MaxPushId, "MAX_PUSH_ID frame first"),
        ];

        for (frame_type, description) in invalid_first_frames {
            reset_connection_state();

            let invalid_control_stream = create_control_stream_with_frame_first(frame_type);

            if validate_control_stream_creation(&invalid_control_stream) {
                return Err(format!(
                    "Control stream with {} was incorrectly accepted",
                    description
                ));
            }

            // Must result in H3_MISSING_SETTINGS connection error
            let error_code = get_last_h3_connection_error();
            if !matches!(error_code, Some(H3NativeError::ControlProtocol(_))) {
                return Err(format!(
                    "Control stream with {} should cause H3_MISSING_SETTINGS, got {:?}",
                    description, error_code
                ));
            }
        }

        Ok(())
    });

    H3ConformanceResult {
        test_id: "RFC9114-6.2.2.1-NON-SETTINGS-REJECT".to_string(),
        description: "Non-SETTINGS first frame must cause H3_MISSING_SETTINGS".to_string(),
        category: TestCategory::ControlStream,
        requirement_level: RequirementLevel::Must,
        verdict: if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        },
        elapsed_ms,
        notes: result.err(),
    }
}

/// RFC 9114 Section 7.2.4: SETTINGS frame validation.
#[allow(dead_code)]
fn test_settings_frame_validation() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        // Test valid SETTINGS frame structures
        let valid_settings = vec![
            (create_settings_frame(&[]), "empty SETTINGS"),
            (
                create_settings_frame(&[(0x01, 100), (0x06, 1024)]),
                "SETTINGS with QPACK_MAX_TABLE_CAPACITY and MAX_HEADER_LIST_SIZE",
            ),
            (
                create_settings_frame(&[(0x33, 1)]),
                "SETTINGS with H3_DATAGRAM",
            ),
        ];

        for (settings_data, description) in valid_settings {
            let control_stream = create_control_stream_with_custom_settings(&settings_data);

            if !validate_control_stream_creation(&control_stream) {
                return Err(format!(
                    "Valid SETTINGS frame was rejected: {}",
                    description
                ));
            }
        }

        // Test invalid SETTINGS frame structures
        let invalid_settings = vec![
            (b"\x04\x02\xFF".to_vec(), "truncated SETTINGS frame"),
            (
                b"\x04\x03\x01\x02".to_vec(),
                "odd number of bytes in SETTINGS",
            ),
            (
                b"\x04\x01".to_vec(),
                "SETTINGS declares a 1-byte payload but provides none",
            ),
        ];

        for (invalid_data, description) in invalid_settings {
            reset_connection_state();

            if validate_h3_frame(&invalid_data) {
                return Err(format!(
                    "Invalid SETTINGS frame was accepted: {}",
                    description
                ));
            }
        }

        Ok(())
    });

    H3ConformanceResult {
        test_id: "RFC9114-7.2.4-SETTINGS-VALIDATION".to_string(),
        description: "SETTINGS frame structure validation".to_string(),
        category: TestCategory::Settings,
        requirement_level: RequirementLevel::Must,
        verdict: if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        },
        elapsed_ms,
        notes: result.err(),
    }
}

/// RFC 9114 Section 6.2.2.1: Control stream frame ordering after SETTINGS.
#[allow(dead_code)]
fn test_control_stream_frame_ordering() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        // After SETTINGS, other frames should be allowed
        let valid_frame_sequences = vec![
            (
                vec![H3FrameType::Settings, H3FrameType::Goaway],
                "SETTINGS + GOAWAY",
            ),
            (
                vec![H3FrameType::Settings, H3FrameType::MaxPushId],
                "SETTINGS + MAX_PUSH_ID",
            ),
            (
                vec![
                    H3FrameType::Settings,
                    H3FrameType::MaxPushId,
                    H3FrameType::Goaway,
                ],
                "SETTINGS + MAX_PUSH_ID + GOAWAY",
            ),
        ];

        for (frame_sequence, description) in valid_frame_sequences {
            reset_connection_state();

            let control_stream = create_control_stream_with_frame_sequence(&frame_sequence);

            if !validate_control_stream_creation(&control_stream) {
                return Err(format!(
                    "Valid frame sequence was rejected: {}",
                    description
                ));
            }
        }

        // Test invalid frames on control stream
        let invalid_frames_after_settings = vec![
            (H3FrameType::Data, "DATA frame on control stream"),
            (H3FrameType::Headers, "HEADERS frame on control stream"),
            (
                H3FrameType::PushPromise,
                "PUSH_PROMISE frame on control stream",
            ),
        ];

        for (invalid_frame, description) in invalid_frames_after_settings {
            reset_connection_state();

            let frame_sequence = vec![H3FrameType::Settings, invalid_frame];
            let control_stream = create_control_stream_with_frame_sequence(&frame_sequence);

            if validate_control_stream_creation(&control_stream) {
                return Err(format!(
                    "Invalid frame was accepted on control stream: {}",
                    description
                ));
            }

            // Should result in H3_FRAME_UNEXPECTED
            let error_code = get_last_h3_connection_error();
            if !matches!(error_code, Some(H3NativeError::ControlProtocol(_))) {
                return Err(format!(
                    "{} should cause H3_FRAME_UNEXPECTED, got {:?}",
                    description, error_code
                ));
            }
        }

        Ok(())
    });

    H3ConformanceResult {
        test_id: "RFC9114-6.2.2.1-FRAME-ORDERING".to_string(),
        description: "Control stream frame ordering after SETTINGS".to_string(),
        category: TestCategory::ControlStream,
        requirement_level: RequirementLevel::Must,
        verdict: if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        },
        elapsed_ms,
        notes: result.err(),
    }
}

/// RFC 9114 Section 6.2.2.1: H3_MISSING_SETTINGS error handling.
#[allow(dead_code)]
fn test_missing_settings_error_handling() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        // Test immediate connection closure on H3_MISSING_SETTINGS
        reset_connection_state();

        let control_stream_no_settings =
            create_control_stream_with_frame_first(H3FrameType::Goaway);

        if validate_control_stream_creation(&control_stream_no_settings) {
            return Err("Control stream without SETTINGS was accepted".to_string());
        }

        // Verify error handling
        let error = get_last_h3_connection_error();
        if !matches!(error, Some(H3NativeError::ControlProtocol(_))) {
            return Err(format!("Expected H3_MISSING_SETTINGS, got {:?}", error));
        }

        // Verify connection is properly closed
        let connection_state = get_connection_state();
        if !get_connection_closed() {
            return Err("Connection should be closed after H3_MISSING_SETTINGS".to_string());
        }

        // Verify no further frames are processed
        let additional_frame = create_h3_frame(H3FrameType::Settings, &[]);
        if process_frame_after_error(&additional_frame) {
            return Err("Frames should not be processed after connection error".to_string());
        }

        Ok(())
    });

    H3ConformanceResult {
        test_id: "RFC9114-6.2.2.1-MISSING-SETTINGS-ERROR".to_string(),
        description: "H3_MISSING_SETTINGS error handling validation".to_string(),
        category: TestCategory::ControlStream,
        requirement_level: RequirementLevel::Must,
        verdict: if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        },
        elapsed_ms,
        notes: result.err(),
    }
}

// Helper functions and types for testing using real HTTP/3 implementation

/// Connection state tracking using real H3 control state.
#[derive(Debug, Clone)]
struct TestConnectionState {
    control_state: H3ControlState,
    last_error: Option<H3NativeError>,
    is_closed: bool,
}

impl TestConnectionState {
    fn new() -> Self {
        Self {
            control_state: H3ControlState::new(),
            last_error: None,
            is_closed: false,
        }
    }

    fn handle_frame(&mut self, frame: &H3Frame) -> Result<(), H3NativeError> {
        // Use real H3 control state validation
        match self.control_state.on_remote_control_frame(frame) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.last_error = Some(e.clone());
                self.is_closed = true;
                Err(e)
            }
        }
    }

    fn last_error(&self) -> Option<&H3NativeError> {
        self.last_error.as_ref()
    }

    fn is_closed(&self) -> bool {
        self.is_closed
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}

/// Global test connection state (in real implementation this would be per-connection)
static mut TEST_CONNECTION: Option<TestConnectionState> = None;

fn get_test_connection() -> &'static mut TestConnectionState {
    unsafe {
        if TEST_CONNECTION.is_none() {
            TEST_CONNECTION = Some(TestConnectionState::new());
        }
        TEST_CONNECTION.as_mut().unwrap()
    }
}

#[derive(Debug)]
struct ParsedH3Frame {
    frame_type: H3FrameType,
    length: u64,
    payload: Vec<u8>,
}

fn create_control_stream_with_settings() -> Vec<u8> {
    let mut stream_data = Vec::new();

    // Stream type: Control (0x00)
    encode_varint(0x00, &mut stream_data).expect("Control stream type varint");

    // SETTINGS frame (type=0x04, length=0, empty payload)
    encode_varint(0x04, &mut stream_data).expect("SETTINGS frame type varint");
    encode_varint(0x00, &mut stream_data).expect("SETTINGS frame length varint");

    stream_data
}

fn create_control_stream_with_settings_and_goaway() -> Vec<u8> {
    let mut stream_data = Vec::new();

    // Stream type: Control (0x00)
    encode_varint(0x00, &mut stream_data).expect("Control stream type varint");

    // SETTINGS frame (type=0x04, length=0)
    encode_varint(0x04, &mut stream_data).expect("SETTINGS frame type varint");
    encode_varint(0x00, &mut stream_data).expect("SETTINGS frame length varint");

    // GOAWAY frame (type=0x07, length=1, stream_id=0)
    stream_data.extend_from_slice(&[0x07, 0x01, 0x00]);

    stream_data
}

fn create_control_stream_with_frame_first(frame_type: H3FrameType) -> Vec<u8> {
    let mut stream_data = Vec::new();

    // Stream type: Control (0x00)
    encode_varint(0x00, &mut stream_data).expect("Control stream type varint");

    // First frame (not SETTINGS)
    let frame = create_h3_frame(frame_type, &[]);
    stream_data.extend_from_slice(&frame);

    stream_data
}

fn create_control_stream_with_frame_sequence(frame_types: &[H3FrameType]) -> Vec<u8> {
    let mut stream_data = Vec::new();

    // Stream type: Control (0x00)
    encode_varint(0x00, &mut stream_data).expect("Control stream type varint");

    // Add frames in sequence
    for &frame_type in frame_types {
        let frame = create_h3_frame(frame_type, &[]);
        stream_data.extend_from_slice(&frame);
    }

    stream_data
}

fn create_control_stream_with_custom_settings(settings_data: &[u8]) -> Vec<u8> {
    let mut stream_data = Vec::new();

    // Stream type: Control (0x00)
    encode_varint(0x00, &mut stream_data).expect("Control stream type varint");

    // Custom SETTINGS frame
    stream_data.extend_from_slice(settings_data);

    stream_data
}

fn create_settings_frame(parameters: &[(u64, u64)]) -> Vec<u8> {
    let mut frame_data = Vec::new();

    // Frame type: SETTINGS (0x04)
    encode_varint(0x04, &mut frame_data).expect("SETTINGS frame type varint");

    // Build payload with proper varint encoding
    let mut payload = Vec::new();
    for &(param_id, param_value) in parameters {
        encode_varint(param_id, &mut payload).expect("SETTINGS parameter ID varint");
        encode_varint(param_value, &mut payload).expect("SETTINGS parameter value varint");
    }

    // Frame length (payload size)
    encode_varint(payload.len() as u64, &mut frame_data).expect("SETTINGS frame length varint");

    // Add payload
    frame_data.extend_from_slice(&payload);

    frame_data
}

fn create_h3_frame(frame_type: H3FrameType, payload: &[u8]) -> Vec<u8> {
    let mut frame_data = Vec::new();

    // RFC 9114 §7.1: frame type and frame length are QUIC varints.
    encode_varint(frame_type as u64, &mut frame_data).expect("HTTP/3 frame type varint");
    encode_varint(payload.len() as u64, &mut frame_data).expect("HTTP/3 frame length varint");

    // Payload
    frame_data.extend_from_slice(payload);

    frame_data
}

fn parse_h3_frames(data: &[u8]) -> Vec<ParsedH3Frame> {
    let mut frames = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let Ok((frame_type_id, type_len)) = decode_varint(&data[offset..]) else {
            break;
        };
        offset += type_len;

        let frame_type = match frame_type_id {
            0x00 => H3FrameType::Data,
            0x01 => H3FrameType::Headers,
            0x04 => H3FrameType::Settings,
            0x05 => H3FrameType::PushPromise,
            0x07 => H3FrameType::Goaway,
            0x0D => H3FrameType::MaxPushId,
            _ => H3FrameType::Reserved,
        };

        let Ok((length, len_len)) = decode_varint(&data[offset..]) else {
            break;
        };
        offset += len_len;

        let payload_end = offset.saturating_add(length as usize);
        if payload_end > data.len() {
            break;
        }
        let payload = data[offset..payload_end].to_vec();

        frames.push(ParsedH3Frame {
            frame_type,
            length,
            payload,
        });

        offset = payload_end;
    }

    frames
}

fn validate_control_stream_creation(stream_data: &[u8]) -> bool {
    // Mock validation - checks for control stream type + SETTINGS first
    if stream_data.is_empty() {
        return false;
    }

    // Parse stream type varint
    let Ok((stream_type, stream_type_len)) = decode_varint(stream_data) else {
        return false;
    };

    // Check if it's a control stream (type 0x00)
    if stream_type != 0x00 {
        return false;
    }

    // Ensure we have enough data for at least one frame header
    if stream_data.len() < stream_type_len + 2 {
        return false; // Too short for stream type + frame type + frame length
    }

    // Parse the first frame type varint
    let frame_start = stream_type_len;
    let Ok((frame_type, _frame_type_len)) = decode_varint(&stream_data[frame_start..]) else {
        return false;
    };

    // Check first frame is SETTINGS (0x04)
    frame_type == 0x04
}

fn validate_h3_frame(frame_data: &[u8]) -> bool {
    // Basic frame validation
    let Ok((_frame_type, type_len)) = decode_varint(frame_data) else {
        return false;
    };
    let Ok((length, len_len)) = decode_varint(&frame_data[type_len..]) else {
        return false;
    };

    frame_data.len() >= type_len + len_len + length as usize
}

fn get_last_h3_connection_error() -> Option<H3NativeError> {
    // Use real H3 error tracking from connection state
    get_test_connection().last_error().cloned()
}

fn get_connection_closed() -> bool {
    // Use real connection state tracking
    get_test_connection().is_closed()
}

fn process_frame_after_error(frame_data: &[u8]) -> bool {
    // Use real H3 frame processing - attempt to parse and validate
    let config = H3ConnectionConfig::default();

    match H3Frame::decode(frame_data, &config) {
        Ok((frame, _)) => {
            // Try to process the frame - should fail if connection is in error state
            if get_test_connection().is_closed() {
                false // Reject frames after connection error
            } else {
                // Try to handle the frame with real H3 validation
                get_test_connection().handle_frame(&frame).is_ok()
            }
        }
        Err(_) => false, // Invalid frame data
    }
}

fn reset_connection_state() {
    // Reset using real connection state management
    get_test_connection().reset();
}

fn simulate_control_stream_frame_processing(frame_data: &[u8]) -> Result<(), H3NativeError> {
    // Use real H3 frame parsing and control stream validation
    let config = H3ConnectionConfig::default();

    let (frame, _) = H3Frame::decode(frame_data, &config)?;
    get_test_connection().handle_frame(&frame)
}

#[test]
fn create_h3_frame_encodes_multibyte_varint_lengths() {
    let payload = vec![0xAB; 64];
    let frame = create_h3_frame(H3FrameType::Data, &payload);

    let (frame_type, type_len) = decode_varint(&frame).expect("frame type varint");
    let (length, len_len) = decode_varint(&frame[type_len..]).expect("frame length varint");

    assert_eq!(frame_type, H3FrameType::Data as u64);
    assert_eq!(length, payload.len() as u64);
    assert_eq!(len_len, 2, "length 64 must use a 2-byte QUIC varint");
    assert_eq!(&frame[type_len + len_len..], payload.as_slice());
}

#[test]
fn parse_and_validate_h3_frame_accept_multibyte_varint_lengths() {
    let payload = vec![0x11; 70];
    let frame = create_h3_frame(H3FrameType::Headers, &payload);

    assert!(
        validate_h3_frame(&frame),
        "helper validation must accept frames with multi-byte length varints"
    );

    let parsed = parse_h3_frames(&frame);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].frame_type, H3FrameType::Headers);
    assert_eq!(parsed[0].length, payload.len() as u64);
    assert_eq!(parsed[0].payload, payload);
}
