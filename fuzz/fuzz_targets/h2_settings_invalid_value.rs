#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Test input structure for invalid SETTINGS value scenarios
#[derive(Arbitrary, Clone, Debug)]
struct InvalidSettingsInput {
    settings_parameters: Vec<SettingsParameter>, // SETTINGS parameters to send
    ack_flag: bool,                              // Whether to set ACK flag
    preceding_frames: Vec<PrecedingFrame>,       // Frames before SETTINGS
    follow_up_frames: Vec<FollowUpFrame>,        // Frames after SETTINGS
}

/// A single SETTINGS parameter with potential invalid values
#[derive(Arbitrary, Clone, Debug)]
struct SettingsParameter {
    parameter_type: SettingsParameterType,
    value: u32,
}

/// SETTINGS parameter types to test
#[derive(Arbitrary, Clone, Debug)]
enum SettingsParameterType {
    HeaderTableSize,      // 0x1 - any value is valid
    EnablePush,           // 0x2 - only 0 or 1 valid, others PROTOCOL_ERROR
    MaxConcurrentStreams, // 0x3 - any value is valid
    InitialWindowSize,    // 0x4 - must be <= 2^31-1, others PROTOCOL_ERROR
    MaxFrameSize,         // 0x5 - must be 2^14 <= value <= 2^24-1
    MaxHeaderListSize,    // 0x6 - any value is valid
    Unknown(u16),         // Unknown setting IDs - should be ignored
}

/// Frames that can precede the SETTINGS frame
#[derive(Arbitrary, Clone, Debug)]
enum PrecedingFrame {
    Settings { parameters: Vec<(u16, u32)> },
    WindowUpdate { stream_id: u32, increment: u32 },
    Ping { data: [u8; 8] },
}

/// Frames that can follow the SETTINGS frame
#[derive(Arbitrary, Clone, Debug)]
enum FollowUpFrame {
    SettingsAck,
    WindowUpdate { stream_id: u32, increment: u32 },
    Headers { stream_id: u32, end_headers: bool },
}

/// Mock connection state to track SETTINGS validation
struct MockInvalidSettingsConnection {
    connection_error: Option<u32>,
    protocol_violations: Vec<String>,
    received_settings: Vec<(u16, u32)>,
    settings_ack_expected: bool,
    invalid_settings_detected: Vec<InvalidSettingInfo>,
}

/// Information about invalid SETTINGS detected
#[derive(Clone, Debug)]
struct InvalidSettingInfo {
    parameter_id: u16,
    invalid_value: u32,
    violation_type: ViolationType,
}

#[derive(Clone, Debug, PartialEq)]
enum ViolationType {
    EnablePushInvalid,       // SETTINGS_ENABLE_PUSH not 0 or 1
    InitialWindowSizeTooBig, // SETTINGS_INITIAL_WINDOW_SIZE > 2^31-1
    MaxFrameSizeInvalid,     // SETTINGS_MAX_FRAME_SIZE out of valid range
}

/// HTTP/2 frame types
const FRAME_TYPE_SETTINGS: u8 = 0x4;
const FRAME_TYPE_WINDOW_UPDATE: u8 = 0x8;
const FRAME_TYPE_PING: u8 = 0x6;
const FRAME_TYPE_HEADERS: u8 = 0x1;

/// HTTP/2 frame flags
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;

/// SETTINGS parameter IDs per RFC 7540 §6.5.2
const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
const SETTINGS_ENABLE_PUSH: u16 = 0x2;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;

/// Error codes
const PROTOCOL_ERROR: u32 = 0x1;

/// Value limits per RFC 7540 §6.5.2
const MAX_INITIAL_WINDOW_SIZE: u32 = 0x7FFFFFFF; // 2^31-1 = 2147483647
const MIN_MAX_FRAME_SIZE: u32 = 0x4000; // 2^14 = 16384
const MAX_MAX_FRAME_SIZE: u32 = 0xFFFFFF; // 2^24-1 = 16777215

impl SettingsParameterType {
    fn to_id(&self) -> u16 {
        match self {
            SettingsParameterType::HeaderTableSize => SETTINGS_HEADER_TABLE_SIZE,
            SettingsParameterType::EnablePush => SETTINGS_ENABLE_PUSH,
            SettingsParameterType::MaxConcurrentStreams => SETTINGS_MAX_CONCURRENT_STREAMS,
            SettingsParameterType::InitialWindowSize => SETTINGS_INITIAL_WINDOW_SIZE,
            SettingsParameterType::MaxFrameSize => SETTINGS_MAX_FRAME_SIZE,
            SettingsParameterType::MaxHeaderListSize => SETTINGS_MAX_HEADER_LIST_SIZE,
            SettingsParameterType::Unknown(id) => *id,
        }
    }
}

impl MockInvalidSettingsConnection {
    fn new() -> Self {
        Self {
            connection_error: None,
            protocol_violations: Vec::new(),
            received_settings: Vec::new(),
            settings_ack_expected: false,
            invalid_settings_detected: Vec::new(),
        }
    }

    /// Process a frame and validate SETTINGS parameter values
    fn process_frame(&mut self, frame_type: u8, stream_id: u32, flags: u8, payload: &[u8]) {
        match frame_type {
            FRAME_TYPE_SETTINGS => {
                self.process_settings_frame(stream_id, flags, payload);
            }
            FRAME_TYPE_WINDOW_UPDATE => {
                self.process_window_update_frame(stream_id, payload);
            }
            FRAME_TYPE_PING => {
                self.process_ping_frame(stream_id, payload);
            }
            FRAME_TYPE_HEADERS => {
                self.process_headers_frame(stream_id, flags, payload);
            }
            _ => {
                // Unknown frame type - should be ignored per spec
            }
        }
    }

    fn process_settings_frame(&mut self, stream_id: u32, flags: u8, payload: &[u8]) {
        // SETTINGS frames MUST have stream ID 0
        if stream_id != 0 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("SETTINGS frame with non-zero stream ID".to_string());
            return;
        }

        let ack_flag = (flags & FLAG_ACK) != 0;

        if ack_flag {
            // ACK frames must have empty payload
            if !payload.is_empty() {
                self.connection_error = Some(PROTOCOL_ERROR);
                self.protocol_violations
                    .push("SETTINGS ACK frame with non-empty payload".to_string());
                return;
            }
            // Process ACK (no further validation needed)
            return;
        }

        // Payload length must be multiple of 6 (each parameter is 6 bytes)
        if !payload.len().is_multiple_of(6) {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("SETTINGS frame payload length not multiple of 6".to_string());
            return;
        }

        // Parse and validate each parameter
        for chunk in payload.chunks_exact(6) {
            let parameter_id = u16::from_be_bytes([chunk[0], chunk[1]]);
            let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);

            self.received_settings.push((parameter_id, value));

            // Validate parameter values per RFC 7540 §6.5.2
            let validation_result = self.validate_settings_parameter(parameter_id, value);
            if let Some(violation) = validation_result {
                self.invalid_settings_detected.push(InvalidSettingInfo {
                    parameter_id,
                    invalid_value: value,
                    violation_type: violation,
                });

                // Set connection error - invalid parameter values are PROTOCOL_ERROR
                self.connection_error = Some(PROTOCOL_ERROR);
                self.protocol_violations.push(format!(
                    "Invalid SETTINGS parameter: ID={} value={}",
                    parameter_id, value
                ));
                return; // Stop processing after first invalid parameter
            }
        }

        // If we reach here, all parameters were valid
        self.settings_ack_expected = true;
    }

    fn validate_settings_parameter(&self, parameter_id: u16, value: u32) -> Option<ViolationType> {
        Self::validate_parameter_value(parameter_id, value)
    }

    fn validate_parameter_value(parameter_id: u16, value: u32) -> Option<ViolationType> {
        match parameter_id {
            SETTINGS_HEADER_TABLE_SIZE => {
                // Any value is valid per RFC 7540 §6.5.2
                None
            }
            SETTINGS_ENABLE_PUSH => {
                // CRITICAL: Only 0 or 1 are valid per RFC 7540 §6.5.2
                // Any other value MUST be treated as a connection error of type PROTOCOL_ERROR
                if value != 0 && value != 1 {
                    Some(ViolationType::EnablePushInvalid)
                } else {
                    None
                }
            }
            SETTINGS_MAX_CONCURRENT_STREAMS => {
                // Any value is valid per RFC 7540 §6.5.2
                None
            }
            SETTINGS_INITIAL_WINDOW_SIZE => {
                // CRITICAL: Values greater than 2^31-1 MUST be treated as a connection error
                // of type PROTOCOL_ERROR per RFC 7540 §6.5.2
                if value > MAX_INITIAL_WINDOW_SIZE {
                    Some(ViolationType::InitialWindowSizeTooBig)
                } else {
                    None
                }
            }
            SETTINGS_MAX_FRAME_SIZE => {
                // Values outside 2^14 to 2^24-1 are PROTOCOL_ERROR per RFC 7540 §6.5.2
                if !(MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&value) {
                    Some(ViolationType::MaxFrameSizeInvalid)
                } else {
                    None
                }
            }
            SETTINGS_MAX_HEADER_LIST_SIZE => {
                // Any value is valid per RFC 7540 §6.5.2
                None
            }
            _ => {
                // Unknown settings parameters MUST be ignored per RFC 7540 §6.5
                None
            }
        }
    }

    fn process_window_update_frame(&mut self, _stream_id: u32, payload: &[u8]) {
        if payload.len() != 4 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("WINDOW_UPDATE frame with invalid length".to_string());
            return;
        }

        let increment = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if increment == 0 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("WINDOW_UPDATE with zero increment".to_string());
        }

        // WINDOW_UPDATE doesn't affect SETTINGS validation
    }

    fn process_ping_frame(&mut self, stream_id: u32, payload: &[u8]) {
        if stream_id != 0 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("PING frame with non-zero stream ID".to_string());
            return;
        }

        if payload.len() != 8 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("PING frame with invalid length".to_string());
        }

        // PING doesn't affect SETTINGS validation
    }

    fn process_headers_frame(&mut self, stream_id: u32, _flags: u8, _payload: &[u8]) {
        if stream_id == 0 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("HEADERS frame with stream ID 0".to_string());
        }

        // HEADERS doesn't affect SETTINGS validation
    }

    fn has_protocol_error(&self) -> bool {
        self.connection_error.is_some()
    }

    fn get_error_code(&self) -> Option<u32> {
        self.connection_error
    }

    fn get_violations(&self) -> &[String] {
        &self.protocol_violations
    }

    fn get_received_settings(&self) -> &[(u16, u32)] {
        &self.received_settings
    }

    fn get_invalid_settings(&self) -> &[InvalidSettingInfo] {
        &self.invalid_settings_detected
    }

    fn count_invalid_enable_push(&self) -> usize {
        self.invalid_settings_detected
            .iter()
            .filter(|info| info.violation_type == ViolationType::EnablePushInvalid)
            .count()
    }

    fn count_invalid_window_size(&self) -> usize {
        self.invalid_settings_detected
            .iter()
            .filter(|info| info.violation_type == ViolationType::InitialWindowSizeTooBig)
            .count()
    }

    fn count_invalid_frame_size(&self) -> usize {
        self.invalid_settings_detected
            .iter()
            .filter(|info| info.violation_type == ViolationType::MaxFrameSizeInvalid)
            .count()
    }
}

/// Send a preceding frame to set up connection state
fn send_preceding_frame(conn: &mut MockInvalidSettingsConnection, frame: &PrecedingFrame) {
    match frame {
        PrecedingFrame::Settings { parameters } => {
            let mut payload = Vec::new();
            for (id, value) in parameters {
                payload.extend_from_slice(&id.to_be_bytes());
                payload.extend_from_slice(&value.to_be_bytes());
            }
            conn.process_frame(FRAME_TYPE_SETTINGS, 0, 0, &payload);
        }
        PrecedingFrame::WindowUpdate {
            stream_id,
            increment,
        } => {
            let payload = increment.to_be_bytes().to_vec();
            conn.process_frame(FRAME_TYPE_WINDOW_UPDATE, *stream_id, 0, &payload);
        }
        PrecedingFrame::Ping { data } => {
            conn.process_frame(FRAME_TYPE_PING, 0, 0, data);
        }
    }
}

/// Send a follow-up frame after the SETTINGS frame
fn send_follow_up_frame(conn: &mut MockInvalidSettingsConnection, frame: &FollowUpFrame) {
    match frame {
        FollowUpFrame::SettingsAck => {
            conn.process_frame(FRAME_TYPE_SETTINGS, 0, FLAG_ACK, &[]);
        }
        FollowUpFrame::WindowUpdate {
            stream_id,
            increment,
        } => {
            let payload = increment.to_be_bytes().to_vec();
            conn.process_frame(FRAME_TYPE_WINDOW_UPDATE, *stream_id, 0, &payload);
        }
        FollowUpFrame::Headers {
            stream_id,
            end_headers,
        } => {
            let flags = if *end_headers { FLAG_END_HEADERS } else { 0 };
            conn.process_frame(FRAME_TYPE_HEADERS, *stream_id, flags, b"headers");
        }
    }
}

fuzz_target!(|input: InvalidSettingsInput| {
    // Limit input sizes to prevent excessive memory usage
    if input.settings_parameters.len() > 100
        || input.preceding_frames.len() > 50
        || input.follow_up_frames.len() > 50
    {
        return;
    }

    let mut conn = MockInvalidSettingsConnection::new();

    // Send preceding frames to set up connection state
    for frame in &input.preceding_frames {
        send_preceding_frame(&mut conn, frame);
        if conn.has_protocol_error() {
            // Stop if we hit a protocol error from setup frames
            return;
        }
    }

    // Build the SETTINGS frame payload
    let mut payload = Vec::new();
    let mut has_invalid_setting = false;

    for param in &input.settings_parameters {
        let param_id = param.parameter_type.to_id();
        let value = param.value;

        payload.extend_from_slice(&param_id.to_be_bytes());
        payload.extend_from_slice(&value.to_be_bytes());

        if MockInvalidSettingsConnection::validate_parameter_value(param_id, value).is_some() {
            has_invalid_setting = true;
        }
    }

    let flags = if input.ack_flag { FLAG_ACK } else { 0 };

    // Send the SETTINGS frame with potentially invalid values
    conn.process_frame(FRAME_TYPE_SETTINGS, 0, flags, &payload);

    assert!(
        conn.get_received_settings().len() <= input.settings_parameters.len(),
        "SETTINGS parser recorded more parameters than were sent"
    );
    if input.ack_flag {
        assert!(
            conn.get_received_settings().is_empty(),
            "SETTINGS ACK frames must not parse payload parameters"
        );
    }

    if input.ack_flag && !payload.is_empty() {
        // ACK with payload is always PROTOCOL_ERROR and does not parse parameters.
        assert!(
            conn.has_protocol_error(),
            "SETTINGS ACK with payload must be PROTOCOL_ERROR"
        );
    } else if has_invalid_setting {
        // CRITICAL: Invalid SETTINGS parameter values MUST cause PROTOCOL_ERROR
        assert!(
            conn.has_protocol_error(),
            "Invalid SETTINGS parameter values must cause PROTOCOL_ERROR. \
             ACK flag: {}, Parameters: {:?}, Violations: {:?}",
            input.ack_flag,
            input.settings_parameters,
            conn.get_violations()
        );

        assert_eq!(
            conn.get_error_code(),
            Some(PROTOCOL_ERROR),
            "Invalid SETTINGS must result in PROTOCOL_ERROR (0x1), got {:?}. Violations: {:?}",
            conn.get_error_code(),
            conn.get_violations()
        );

        // Verify we detected the invalid settings
        assert!(
            !conn.get_invalid_settings().is_empty(),
            "Expected invalid settings to be detected and recorded"
        );
        let first_invalid = &conn.get_invalid_settings()[0];
        assert!(
            MockInvalidSettingsConnection::validate_parameter_value(
                first_invalid.parameter_id,
                first_invalid.invalid_value
            )
            .is_some(),
            "Recorded invalid setting should be invalid by the RFC value rules"
        );
    } else if !payload.is_empty() {
        // All parameters valid, should not cause error (unless ACK with payload)
        assert!(
            !conn.has_protocol_error(),
            "Valid SETTINGS parameters should not cause PROTOCOL_ERROR. \
             Violations: {:?}",
            conn.get_violations()
        );
    }

    // Send follow-up frames to test continued operation
    if !conn.has_protocol_error() {
        for frame in &input.follow_up_frames {
            send_follow_up_frame(&mut conn, frame);
            if conn.has_protocol_error() {
                break;
            }
        }
    }

    // Test specific invalid SETTINGS scenarios
    test_invalid_settings_scenarios(&input);
});

/// Test specific invalid SETTINGS value scenarios
fn test_invalid_settings_scenarios(input: &InvalidSettingsInput) {
    // Scenario 1: SETTINGS_ENABLE_PUSH = 2 (invalid, only 0/1 valid)
    {
        let mut conn = MockInvalidSettingsConnection::new();
        let mut payload = Vec::new();
        payload.extend_from_slice(&SETTINGS_ENABLE_PUSH.to_be_bytes());
        payload.extend_from_slice(&2u32.to_be_bytes()); // Invalid value

        conn.process_frame(FRAME_TYPE_SETTINGS, 0, 0, &payload);

        assert!(
            conn.has_protocol_error(),
            "SETTINGS_ENABLE_PUSH=2 must be PROTOCOL_ERROR (only 0/1 valid)"
        );
        assert_eq!(conn.count_invalid_enable_push(), 1);
        let invalid = &conn.get_invalid_settings()[0];
        assert_eq!(invalid.parameter_id, SETTINGS_ENABLE_PUSH);
        assert_eq!(invalid.invalid_value, 2);
    }

    // Scenario 2: SETTINGS_INITIAL_WINDOW_SIZE = 2^31 (invalid, max is 2^31-1)
    {
        let mut conn = MockInvalidSettingsConnection::new();
        let mut payload = Vec::new();
        payload.extend_from_slice(&SETTINGS_INITIAL_WINDOW_SIZE.to_be_bytes());
        payload.extend_from_slice(&0x80000000u32.to_be_bytes()); // 2^31 (too big)

        conn.process_frame(FRAME_TYPE_SETTINGS, 0, 0, &payload);

        assert!(
            conn.has_protocol_error(),
            "SETTINGS_INITIAL_WINDOW_SIZE=2^31 must be PROTOCOL_ERROR (max is 2^31-1)"
        );
        assert_eq!(conn.count_invalid_window_size(), 1);
        let invalid = &conn.get_invalid_settings()[0];
        assert_eq!(invalid.parameter_id, SETTINGS_INITIAL_WINDOW_SIZE);
        assert_eq!(invalid.invalid_value, 0x80000000);
    }

    // Scenario 3: Multiple invalid parameters (should stop at first)
    {
        let mut conn = MockInvalidSettingsConnection::new();
        let mut payload = Vec::new();
        // Invalid ENABLE_PUSH
        payload.extend_from_slice(&SETTINGS_ENABLE_PUSH.to_be_bytes());
        payload.extend_from_slice(&5u32.to_be_bytes());
        // Invalid INITIAL_WINDOW_SIZE (should not be processed)
        payload.extend_from_slice(&SETTINGS_INITIAL_WINDOW_SIZE.to_be_bytes());
        payload.extend_from_slice(&0xFFFFFFFFu32.to_be_bytes());

        conn.process_frame(FRAME_TYPE_SETTINGS, 0, 0, &payload);

        assert!(
            conn.has_protocol_error(),
            "Multiple invalid SETTINGS parameters must cause PROTOCOL_ERROR"
        );
        // Should detect only the first invalid parameter (processing stops)
        assert!(!conn.get_invalid_settings().is_empty());
    }

    // Scenario 4: Mix of valid and invalid parameters
    {
        let mut conn = MockInvalidSettingsConnection::new();
        let mut payload = Vec::new();
        // Valid parameter
        payload.extend_from_slice(&SETTINGS_HEADER_TABLE_SIZE.to_be_bytes());
        payload.extend_from_slice(&4096u32.to_be_bytes());
        // Invalid parameter
        payload.extend_from_slice(&SETTINGS_ENABLE_PUSH.to_be_bytes());
        payload.extend_from_slice(&99u32.to_be_bytes());

        conn.process_frame(FRAME_TYPE_SETTINGS, 0, 0, &payload);

        assert!(
            conn.has_protocol_error(),
            "Mix of valid/invalid SETTINGS parameters must cause PROTOCOL_ERROR"
        );
    }

    // Scenario 5: SETTINGS_ENABLE_PUSH boundary values
    for value in [0u32, 1u32, 2u32, 255u32, 65535u32, 0xFFFFFFFFu32] {
        let mut conn = MockInvalidSettingsConnection::new();
        let mut payload = Vec::new();
        payload.extend_from_slice(&SETTINGS_ENABLE_PUSH.to_be_bytes());
        payload.extend_from_slice(&value.to_be_bytes());

        conn.process_frame(FRAME_TYPE_SETTINGS, 0, 0, &payload);

        if value == 0 || value == 1 {
            assert!(
                !conn.has_protocol_error(),
                "SETTINGS_ENABLE_PUSH={} must be valid",
                value
            );
        } else {
            assert!(
                conn.has_protocol_error(),
                "SETTINGS_ENABLE_PUSH={} must be PROTOCOL_ERROR (only 0/1 valid)",
                value
            );
        }
    }

    // Scenario 6: SETTINGS_INITIAL_WINDOW_SIZE boundary values
    let test_values = [
        (MAX_INITIAL_WINDOW_SIZE - 1, true),  // Valid
        (MAX_INITIAL_WINDOW_SIZE, true),      // Valid (exactly at limit)
        (MAX_INITIAL_WINDOW_SIZE + 1, false), // Invalid
        (0x80000000u32, false),               // Invalid (2^31)
        (0xFFFFFFFFu32, false),               // Invalid (2^32-1)
    ];

    for (value, should_be_valid) in test_values {
        let mut conn = MockInvalidSettingsConnection::new();
        let mut payload = Vec::new();
        payload.extend_from_slice(&SETTINGS_INITIAL_WINDOW_SIZE.to_be_bytes());
        payload.extend_from_slice(&value.to_be_bytes());

        conn.process_frame(FRAME_TYPE_SETTINGS, 0, 0, &payload);

        if should_be_valid {
            assert!(
                !conn.has_protocol_error(),
                "SETTINGS_INITIAL_WINDOW_SIZE={} must be valid",
                value
            );
        } else {
            assert!(
                conn.has_protocol_error(),
                "SETTINGS_INITIAL_WINDOW_SIZE={} must be PROTOCOL_ERROR (> 2^31-1)",
                value
            );
        }
    }

    // Scenario 7: SETTINGS_MAX_FRAME_SIZE boundary values
    let frame_size_tests = [
        (MIN_MAX_FRAME_SIZE - 1, false), // Too small
        (MIN_MAX_FRAME_SIZE, true),      // Valid minimum
        (65536, true),                   // Valid middle
        (MAX_MAX_FRAME_SIZE, true),      // Valid maximum
        (MAX_MAX_FRAME_SIZE + 1, false), // Too big
    ];

    for (value, should_be_valid) in frame_size_tests {
        let mut conn = MockInvalidSettingsConnection::new();
        let mut payload = Vec::new();
        payload.extend_from_slice(&SETTINGS_MAX_FRAME_SIZE.to_be_bytes());
        payload.extend_from_slice(&value.to_be_bytes());

        conn.process_frame(FRAME_TYPE_SETTINGS, 0, 0, &payload);

        if should_be_valid {
            assert!(
                !conn.has_protocol_error(),
                "SETTINGS_MAX_FRAME_SIZE={} must be valid",
                value
            );
            assert_eq!(conn.count_invalid_frame_size(), 0);
        } else {
            assert!(
                conn.has_protocol_error(),
                "SETTINGS_MAX_FRAME_SIZE={} must be PROTOCOL_ERROR (out of range)",
                value
            );
            assert_eq!(conn.count_invalid_frame_size(), 1);
        }
    }

    // Scenario 8: Valid settings should not cause errors
    if !input.ack_flag
        && input.settings_parameters.iter().all(|p| {
            MockInvalidSettingsConnection::validate_parameter_value(
                p.parameter_type.to_id(),
                p.value,
            )
            .is_none()
        })
    {
        let mut conn = MockInvalidSettingsConnection::new();
        let mut payload = Vec::new();

        for param in &input.settings_parameters {
            payload.extend_from_slice(&param.parameter_type.to_id().to_be_bytes());
            payload.extend_from_slice(&param.value.to_be_bytes());
        }

        if !payload.is_empty() {
            conn.process_frame(FRAME_TYPE_SETTINGS, 0, 0, &payload);
            assert!(
                !conn.has_protocol_error(),
                "All valid SETTINGS parameters should not cause PROTOCOL_ERROR"
            );
        }
    }
}
