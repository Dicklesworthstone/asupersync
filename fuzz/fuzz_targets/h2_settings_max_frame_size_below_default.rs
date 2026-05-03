#![no_main]
/*
br-asupersync-q94ai8: the original draft below was mock-only. It is preserved
verbatim for archaeology, but the active fuzz target appended after this block
drives the production HTTP/2 SETTINGS parser and Connection state machine.

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

/// HTTP/2 SETTINGS_MAX_FRAME_SIZE below-minimum validation testing.
/// Per RFC 7540 §6.5.2, MAX_FRAME_SIZE valid range is 16384..2^24-1.
/// Values below 16384 (like 8192) must be rejected as PROTOCOL_ERROR.
/// Tests boundary validation and proper error generation.
///
/// Tests:
/// - SETTINGS_MAX_FRAME_SIZE=8192 (below minimum) → PROTOCOL_ERROR
/// - SETTINGS_MAX_FRAME_SIZE=16384 (minimum valid) → success
/// - SETTINGS_MAX_FRAME_SIZE=16777215 (maximum valid) → success
/// - Various values below 16384 (all invalid)
/// - Various values above 16777215 (all invalid)
/// - PROTOCOL_ERROR generation for out-of-range values
/// - Valid frame size storage and usage

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// SETTINGS frame to test
    settings_frame: SettingsFrame,
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingsFrame {
    /// Frame flags (0 for non-ACK, 1 for ACK)
    flags: u8,
    /// Stream ID (must be 0 for SETTINGS)
    stream_id: u32,
    /// Settings entries
    settings: Vec<SettingEntry>,
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingEntry {
    /// Setting ID
    id: u16,
    /// Setting value
    value: u32,
}

/// HTTP/2 settings constants
const SETTINGS_HEADER_TABLE_SIZE: u16 = 1;
const SETTINGS_ENABLE_PUSH: u16 = 2;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 3;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 4;
const SETTINGS_MAX_FRAME_SIZE: u16 = 5;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 6;

/// Frame size constants per RFC 7540
const MIN_FRAME_SIZE: u32 = 16384;  // 2^14
const MAX_FRAME_SIZE: u32 = 16777215; // 2^24 - 1
const DEFAULT_FRAME_SIZE: u32 = 16384;

/// Mock HTTP/2 SETTINGS frame parser with MAX_FRAME_SIZE validation
struct MockH2SettingsFrameSizeParser {
    /// Current settings
    max_frame_size: u32,
    header_table_size: u32,
    enable_push: bool,
    max_concurrent_streams: Option<u32>,
    initial_window_size: u32,
    max_header_list_size: Option<u32>,
    /// Processing errors
    errors: Vec<String>,
}

impl MockH2SettingsFrameSizeParser {
    fn new() -> Self {
        Self {
            max_frame_size: DEFAULT_FRAME_SIZE,
            header_table_size: 4096,
            enable_push: true,
            max_concurrent_streams: None, // Unlimited by default
            initial_window_size: 65535,
            max_header_list_size: None, // Unlimited by default
            errors: Vec::new(),
        }
    }

    /// Process SETTINGS frame with MAX_FRAME_SIZE validation
    fn process_settings_frame(&mut self, frame: &SettingsFrame) -> Result<(), String> {
        // Validate frame structure
        if frame.stream_id != 0 {
            return Err("PROTOCOL_ERROR: SETTINGS frame stream ID must be 0".into());
        }

        let is_ack = (frame.flags & 0x01) != 0;

        if is_ack {
            // ACK frame should have empty payload
            if !frame.settings.is_empty() {
                return Err("FRAME_SIZE_ERROR: SETTINGS ACK frame must have empty payload".into());
            }
            return Ok(());
        }

        // Process individual settings
        for setting in &frame.settings {
            self.process_setting(setting)?;
        }

        Ok(())
    }

    /// Process individual setting with validation
    fn process_setting(&mut self, setting: &SettingEntry) -> Result<(), String> {
        match setting.id {
            SETTINGS_HEADER_TABLE_SIZE => {
                // Any value allowed per RFC
                self.header_table_size = setting.value;
            }
            SETTINGS_ENABLE_PUSH => {
                if setting.value > 1 {
                    return Err("PROTOCOL_ERROR: ENABLE_PUSH must be 0 or 1".into());
                }
                self.enable_push = setting.value == 1;
            }
            SETTINGS_MAX_CONCURRENT_STREAMS => {
                // Any value allowed (0 means disabled)
                self.max_concurrent_streams = Some(setting.value);
            }
            SETTINGS_INITIAL_WINDOW_SIZE => {
                if setting.value > 2_147_483_647 {
                    return Err("FLOW_CONTROL_ERROR: INITIAL_WINDOW_SIZE exceeds maximum".into());
                }
                self.initial_window_size = setting.value;
            }
            SETTINGS_MAX_FRAME_SIZE => {
                // RFC 7540 §6.5.2: Must be between 2^14 and 2^24-1
                if setting.value < MIN_FRAME_SIZE {
                    return Err(format!(
                        "PROTOCOL_ERROR: MAX_FRAME_SIZE {} below minimum {}",
                        setting.value, MIN_FRAME_SIZE
                    ));
                }
                if setting.value > MAX_FRAME_SIZE {
                    return Err(format!(
                        "PROTOCOL_ERROR: MAX_FRAME_SIZE {} exceeds maximum {}",
                        setting.value, MAX_FRAME_SIZE
                    ));
                }
                self.max_frame_size = setting.value;
            }
            SETTINGS_MAX_HEADER_LIST_SIZE => {
                // Any value allowed per RFC
                self.max_header_list_size = Some(setting.value);
            }
            _ => {
                // Unknown settings are ignored per RFC 7540 §6.5
                self.errors.push(format!("Unknown setting ID: {}", setting.id));
            }
        }

        Ok(())
    }

    /// Validate a frame size against current MAX_FRAME_SIZE setting
    fn validate_frame_size(&self, frame_size: u32) -> Result<(), String> {
        if frame_size > self.max_frame_size {
            return Err(format!(
                "FRAME_SIZE_ERROR: frame size {} exceeds MAX_FRAME_SIZE {}",
                frame_size, self.max_frame_size
            ));
        }
        Ok(())
    }

    /// Get current MAX_FRAME_SIZE setting
    fn get_max_frame_size(&self) -> u32 {
        self.max_frame_size
    }

    /// Get all current settings
    fn get_all_settings(&self) -> SettingsSnapshot {
        SettingsSnapshot {
            max_frame_size: self.max_frame_size,
            header_table_size: self.header_table_size,
            enable_push: self.enable_push,
            max_concurrent_streams: self.max_concurrent_streams,
            initial_window_size: self.initial_window_size,
            max_header_list_size: self.max_header_list_size,
        }
    }

    /// Get processing errors
    fn get_errors(&self) -> &[String] {
        &self.errors
    }

    /// Check if frame size is within valid RFC range
    fn is_valid_frame_size(size: u32) -> bool {
        size >= MIN_FRAME_SIZE && size <= MAX_FRAME_SIZE
    }

    /// Calculate frame overhead for different frame types
    fn calculate_frame_overhead(&self, frame_type: FrameType) -> u32 {
        match frame_type {
            FrameType::Data { padded } => if padded { 1 } else { 0 }, // Pad length byte
            FrameType::Headers { padded, priority } => {
                (if padded { 1 } else { 0 }) + (if priority { 5 } else { 0 })
            },
            FrameType::Priority => 5, // Exclusive(1) + Dependency(4) + Weight(1) = 5
            FrameType::Settings => 0, // Variable number of 6-byte entries
            FrameType::PushPromise { padded } => 4 + (if padded { 1 } else { 0 }), // Promised Stream ID + optional pad
            FrameType::Ping => 8, // Fixed 8-byte payload
            FrameType::GoAway => 8, // Last Stream ID(4) + Error Code(4) + optional debug data
            FrameType::WindowUpdate => 4, // Window Size Increment
            FrameType::Continuation => 0, // Just header block fragment
        }
    }
}

/// Snapshot of current settings state
#[derive(Debug, Clone)]
struct SettingsSnapshot {
    max_frame_size: u32,
    header_table_size: u32,
    enable_push: bool,
    max_concurrent_streams: Option<u32>,
    initial_window_size: u32,
    max_header_list_size: Option<u32>,
}

/// HTTP/2 frame types for overhead calculation
#[derive(Debug)]
enum FrameType {
    Data { padded: bool },
    Headers { padded: bool, priority: bool },
    Priority,
    Settings,
    PushPromise { padded: bool },
    Ping,
    GoAway,
    WindowUpdate,
    Continuation,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let input: FuzzInput = match u.arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Skip invalid inputs
    };

    // Limit settings count to prevent timeouts
    if input.settings_frame.settings.len() > 20 {
        return;
    }

    let mut parser = MockH2SettingsFrameSizeParser::new();
    let result = parser.process_settings_frame(&input.settings_frame);

    // Test 1: Frame structure validation
    if input.settings_frame.stream_id != 0 {
        assert!(result.is_err(),
            "SETTINGS frame with non-zero stream ID should be rejected");
        return;
    }

    let is_ack = (input.settings_frame.flags & 0x01) != 0;
    if is_ack && !input.settings_frame.settings.is_empty() {
        assert!(result.is_err(),
            "SETTINGS ACK frame with payload should be rejected");
        return;
    }

    // Test 2: MAX_FRAME_SIZE validation
    for setting in &input.settings_frame.settings {
        if setting.id == SETTINGS_MAX_FRAME_SIZE {
            if setting.value < MIN_FRAME_SIZE {
                // Below minimum (like 8192) should be PROTOCOL_ERROR
                assert!(result.is_err(),
                    "MAX_FRAME_SIZE {} below minimum {} should be rejected",
                    setting.value, MIN_FRAME_SIZE);

                if let Err(error_msg) = &result {
                    assert!(error_msg.contains("PROTOCOL_ERROR"),
                        "Below-minimum error should mention PROTOCOL_ERROR: {}", error_msg);
                    assert!(error_msg.contains("below minimum"),
                        "Error should indicate below minimum: {}", error_msg);
                }
                return;
            } else if setting.value > MAX_FRAME_SIZE {
                // Above maximum should be PROTOCOL_ERROR
                assert!(result.is_err(),
                    "MAX_FRAME_SIZE {} above maximum {} should be rejected",
                    setting.value, MAX_FRAME_SIZE);

                if let Err(error_msg) = &result {
                    assert!(error_msg.contains("PROTOCOL_ERROR"),
                        "Above-maximum error should mention PROTOCOL_ERROR: {}", error_msg);
                    assert!(error_msg.contains("exceeds maximum"),
                        "Error should indicate exceeds maximum: {}", error_msg);
                }
                return;
            } else {
                // Valid range should succeed
                assert!(result.is_ok(),
                    "Valid MAX_FRAME_SIZE {} should be accepted", setting.value);

                assert_eq!(parser.get_max_frame_size(), setting.value,
                    "MAX_FRAME_SIZE should be stored correctly");

                // Test 3: Frame size validation with new setting
                let valid_frame_size = setting.value - 100; // Smaller than limit
                assert!(parser.validate_frame_size(valid_frame_size).is_ok(),
                    "Frame size within limit should be valid");

                let invalid_frame_size = setting.value + 1; // Exceeds limit
                assert!(parser.validate_frame_size(invalid_frame_size).is_err(),
                    "Frame size exceeding limit should be invalid");
            }
        }
    }

    // Test 4: Other settings validation
    for setting in &input.settings_frame.settings {
        match setting.id {
            SETTINGS_ENABLE_PUSH => {
                if setting.value > 1 {
                    assert!(result.is_err(),
                        "ENABLE_PUSH > 1 should be rejected");
                    return;
                }
            }
            SETTINGS_INITIAL_WINDOW_SIZE => {
                if setting.value > 2_147_483_647 {
                    assert!(result.is_err(),
                        "INITIAL_WINDOW_SIZE > 2^31-1 should be rejected");
                    return;
                }
            }
            _ => {}
        }
    }

    // Test 5: Valid frames should update settings
    if result.is_ok() && !is_ack {
        let settings = parser.get_all_settings();

        // Verify settings were applied
        for setting in &input.settings_frame.settings {
            match setting.id {
                SETTINGS_MAX_FRAME_SIZE => {
                    if MockH2SettingsFrameSizeParser::is_valid_frame_size(setting.value) {
                        assert_eq!(settings.max_frame_size, setting.value,
                            "MAX_FRAME_SIZE should be applied");
                    }
                }
                SETTINGS_HEADER_TABLE_SIZE => {
                    assert_eq!(settings.header_table_size, setting.value,
                        "HEADER_TABLE_SIZE should be applied");
                }
                SETTINGS_ENABLE_PUSH => {
                    if setting.value <= 1 {
                        assert_eq!(settings.enable_push, setting.value == 1,
                            "ENABLE_PUSH should be applied");
                    }
                }
                SETTINGS_INITIAL_WINDOW_SIZE => {
                    if setting.value <= 2_147_483_647 {
                        assert_eq!(settings.initial_window_size, setting.value,
                            "INITIAL_WINDOW_SIZE should be applied");
                    }
                }
                _ => {}
            }
        }
    }

    // Test 6: Frame overhead calculation
    if result.is_ok() {
        let data_overhead = parser.calculate_frame_overhead(FrameType::Data { padded: false });
        assert_eq!(data_overhead, 0, "Unpadded DATA frame has no overhead");

        let padded_data_overhead = parser.calculate_frame_overhead(FrameType::Data { padded: true });
        assert_eq!(padded_data_overhead, 1, "Padded DATA frame has 1-byte overhead");

        let ping_overhead = parser.calculate_frame_overhead(FrameType::Ping);
        assert_eq!(ping_overhead, 8, "PING frame has 8-byte fixed payload");
    }

    // Test 7: Boundary value testing
    if !input.settings_frame.settings.is_empty() {
        let test_values = [
            (8192, false),    // Below minimum
            (16383, false),   // Just below minimum
            (16384, true),    // Minimum valid
            (16385, true),    // Just above minimum
            (16777215, true), // Maximum valid
            (16777216, false), // Just above maximum
            (33554432, false), // Way above maximum
        ];

        for &(test_value, should_be_valid) in &test_values {
            let is_valid = MockH2SettingsFrameSizeParser::is_valid_frame_size(test_value);
            assert_eq!(is_valid, should_be_valid,
                "Frame size {} validity should be {}", test_value, should_be_valid);
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_frame_size_below_minimum() {
        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings: vec![
                SettingEntry { id: SETTINGS_MAX_FRAME_SIZE, value: 8192 }, // Below minimum
            ],
        };

        let mut parser = MockH2SettingsFrameSizeParser::new();
        let result = parser.process_settings_frame(&frame);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("PROTOCOL_ERROR"));
        assert!(result.unwrap_err().contains("below minimum"));
    }

    #[test]
    fn test_max_frame_size_minimum_valid() {
        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings: vec![
                SettingEntry { id: SETTINGS_MAX_FRAME_SIZE, value: 16384 }, // Minimum valid
            ],
        };

        let mut parser = MockH2SettingsFrameSizeParser::new();
        let result = parser.process_settings_frame(&frame);

        assert!(result.is_ok());
        assert_eq!(parser.get_max_frame_size(), 16384);
    }

    #[test]
    fn test_max_frame_size_maximum_valid() {
        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings: vec![
                SettingEntry { id: SETTINGS_MAX_FRAME_SIZE, value: 16777215 }, // Maximum valid
            ],
        };

        let mut parser = MockH2SettingsFrameSizeParser::new();
        let result = parser.process_settings_frame(&frame);

        assert!(result.is_ok());
        assert_eq!(parser.get_max_frame_size(), 16777215);
    }

    #[test]
    fn test_max_frame_size_above_maximum() {
        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings: vec![
                SettingEntry { id: SETTINGS_MAX_FRAME_SIZE, value: 16777216 }, // Above maximum
            ],
        };

        let mut parser = MockH2SettingsFrameSizeParser::new();
        let result = parser.process_settings_frame(&frame);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("PROTOCOL_ERROR"));
        assert!(result.unwrap_err().contains("exceeds maximum"));
    }

    #[test]
    fn test_frame_size_validation() {
        let mut parser = MockH2SettingsFrameSizeParser::new();

        // Set frame size to 20000
        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings: vec![
                SettingEntry { id: SETTINGS_MAX_FRAME_SIZE, value: 20000 },
            ],
        };

        assert!(parser.process_settings_frame(&frame).is_ok());

        // Test frame validation
        assert!(parser.validate_frame_size(19999).is_ok()); // Within limit
        assert!(parser.validate_frame_size(20000).is_ok()); // Exactly at limit
        assert!(parser.validate_frame_size(20001).is_err()); // Exceeds limit
    }

    #[test]
    fn test_boundary_values() {
        let boundary_tests = vec![
            (8191, false),
            (8192, false),    // Test case from description
            (16383, false),
            (16384, true),    // Minimum valid
            (16385, true),
            (32768, true),    // Common power of 2
            (16777215, true), // Maximum valid
            (16777216, false),
        ];

        for (value, should_succeed) in boundary_tests {
            let frame = SettingsFrame {
                flags: 0,
                stream_id: 0,
                settings: vec![
                    SettingEntry { id: SETTINGS_MAX_FRAME_SIZE, value },
                ],
            };

            let mut parser = MockH2SettingsFrameSizeParser::new();
            let result = parser.process_settings_frame(&frame);

            if should_succeed {
                assert!(result.is_ok(), "Value {} should be accepted", value);
                assert_eq!(parser.get_max_frame_size(), value);
            } else {
                assert!(result.is_err(), "Value {} should be rejected", value);
            }
        }
    }

    #[test]
    fn test_other_invalid_settings() {
        // Test ENABLE_PUSH validation
        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings: vec![
                SettingEntry { id: SETTINGS_ENABLE_PUSH, value: 2 }, // Invalid
            ],
        };

        let mut parser = MockH2SettingsFrameSizeParser::new();
        let result = parser.process_settings_frame(&frame);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("ENABLE_PUSH"));
    }

    #[test]
    fn test_settings_ack_frame() {
        let frame = SettingsFrame {
            flags: 0x01, // ACK flag
            stream_id: 0,
            settings: vec![], // Must be empty for ACK
        };

        let mut parser = MockH2SettingsFrameSizeParser::new();
        let result = parser.process_settings_frame(&frame);

        assert!(result.is_ok());
        assert_eq!(parser.get_max_frame_size(), DEFAULT_FRAME_SIZE); // Should not change
    }

    #[test]
    fn test_unknown_settings_ignored() {
        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings: vec![
                SettingEntry { id: 99, value: 12345 }, // Unknown setting
                SettingEntry { id: SETTINGS_MAX_FRAME_SIZE, value: 32768 }, // Valid setting
            ],
        };

        let mut parser = MockH2SettingsFrameSizeParser::new();
        let result = parser.process_settings_frame(&frame);

        assert!(result.is_ok());
        assert_eq!(parser.get_max_frame_size(), 32768);

        let errors = parser.get_errors();
        assert!(errors.iter().any(|e| e.contains("Unknown setting ID: 99")));
    }

    #[test]
    fn test_frame_overhead_calculation() {
        let parser = MockH2SettingsFrameSizeParser::new();

        assert_eq!(parser.calculate_frame_overhead(FrameType::Data { padded: false }), 0);
        assert_eq!(parser.calculate_frame_overhead(FrameType::Data { padded: true }), 1);
        assert_eq!(parser.calculate_frame_overhead(FrameType::Headers { padded: false, priority: false }), 0);
        assert_eq!(parser.calculate_frame_overhead(FrameType::Headers { padded: true, priority: true }), 6);
        assert_eq!(parser.calculate_frame_overhead(FrameType::Priority), 5);
        assert_eq!(parser.calculate_frame_overhead(FrameType::Ping), 8);
        assert_eq!(parser.calculate_frame_overhead(FrameType::WindowUpdate), 4);
    }

    #[test]
    fn test_is_valid_frame_size_function() {
        assert!(!MockH2SettingsFrameSizeParser::is_valid_frame_size(8192));
        assert!(!MockH2SettingsFrameSizeParser::is_valid_frame_size(16383));
        assert!(MockH2SettingsFrameSizeParser::is_valid_frame_size(16384));
        assert!(MockH2SettingsFrameSizeParser::is_valid_frame_size(100000));
        assert!(MockH2SettingsFrameSizeParser::is_valid_frame_size(16777215));
        assert!(!MockH2SettingsFrameSizeParser::is_valid_frame_size(16777216));
    }
}
*/

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::http::h2::{
    Connection, ErrorCode, Frame, FrameHeader, FrameType, Setting, Settings,
    frame::parse_frame,
    settings::{MAX_MAX_FRAME_SIZE, MIN_MAX_FRAME_SIZE},
};
use libfuzzer_sys::fuzz_target;

const MAX_SETTINGS: usize = 64;
const SETTINGS_MAX_FRAME_SIZE_ID: u16 = 0x5;
const SETTINGS_ACK: u8 = 0x1;

#[derive(Arbitrary, Debug)]
struct Scenario {
    stream_id: u32,
    flags: u8,
    entries: Vec<RawSetting>,
    extra_tail: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct RawSetting {
    id: u16,
    value: u32,
}

fuzz_target!(|scenario: Scenario| {
    let mut scenario = scenario;
    scenario.entries.truncate(MAX_SETTINGS);
    scenario.extra_tail.truncate(5);

    let payload = encode_payload(&scenario.entries, &scenario.extra_tail);
    let header = FrameHeader {
        length: payload.len() as u32,
        frame_type: FrameType::Settings as u8,
        flags: scenario.flags,
        stream_id: scenario.stream_id & 0x7fff_ffff,
    };

    let parsed = parse_frame(&header, Bytes::from(payload));
    assert_settings_parse_contract(&header, &scenario.entries, &scenario.extra_tail, &parsed);

    if let Ok(Frame::Settings(settings)) = parsed {
        let mut connection = Connection::server(Settings::default());
        let before = connection.remote_settings().clone();
        let result = connection.process_frame(Frame::Settings(settings));

        let expected_bad_value = first_connection_invalid_setting(&scenario.entries);
        match result {
            Ok(_) => {
                assert!(
                    expected_bad_value.is_none(),
                    "Connection accepted invalid SETTINGS value: {expected_bad_value:?}"
                );
                assert_last_max_frame_size_wins(&scenario.entries, &connection);
            }
            Err(err) => {
                assert_eq!(
                    connection.remote_settings(),
                    &before,
                    "rejected SETTINGS frame must not partially mutate remote settings"
                );
                if let Some(expected_code) = expected_bad_value {
                    assert_eq!(err.code, expected_code);
                }
            }
        }
    }
});

fn encode_payload(entries: &[RawSetting], extra_tail: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(entries.len() * 6 + extra_tail.len());
    for setting in entries {
        payload.extend_from_slice(&setting.id.to_be_bytes());
        payload.extend_from_slice(&setting.value.to_be_bytes());
    }
    payload.extend_from_slice(extra_tail);
    payload
}

fn assert_settings_parse_contract(
    header: &FrameHeader,
    entries: &[RawSetting],
    extra_tail: &[u8],
    parsed: &Result<Frame, asupersync::http::h2::H2Error>,
) {
    if header.stream_id != 0 {
        assert_h2_error(parsed, ErrorCode::ProtocolError, None);
        return;
    }

    if header.flags & SETTINGS_ACK != 0 && (header.length != 0) {
        assert_h2_error(parsed, ErrorCode::FrameSizeError, None);
        return;
    }

    if !extra_tail.is_empty() {
        assert_h2_error(parsed, ErrorCode::FrameSizeError, None);
        return;
    }

    if let Some(code) = first_parse_invalid_setting(entries) {
        assert_h2_error(parsed, code, None);
        return;
    }

    match parsed {
        Ok(Frame::Settings(settings)) => {
            assert_eq!(settings.ack, header.flags & SETTINGS_ACK != 0);
            if settings.ack {
                assert!(settings.settings.is_empty());
            } else {
                assert_eq!(settings.settings.len(), known_settings_count(entries));
            }
        }
        other => panic!("SETTINGS frame parsed to unexpected result: {other:?}"),
    }
}

fn first_parse_invalid_setting(entries: &[RawSetting]) -> Option<ErrorCode> {
    for setting in entries {
        match setting.id {
            0x2 if setting.value > 1 => return Some(ErrorCode::ProtocolError),
            0x4 if setting.value > 0x7fff_ffff => return Some(ErrorCode::FlowControlError),
            SETTINGS_MAX_FRAME_SIZE_ID
                if !(MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&setting.value) =>
            {
                return Some(ErrorCode::ProtocolError);
            }
            _ => {}
        }
    }
    None
}

fn first_connection_invalid_setting(entries: &[RawSetting]) -> Option<ErrorCode> {
    entries.iter().find_map(
        |setting| match Setting::from_id_value(setting.id, setting.value) {
            Some(Setting::InitialWindowSize(value)) if value > 0x7fff_ffff => {
                Some(ErrorCode::FlowControlError)
            }
            Some(Setting::MaxFrameSize(value))
                if !(MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&value) =>
            {
                Some(ErrorCode::ProtocolError)
            }
            _ => None,
        },
    )
}

fn known_settings_count(entries: &[RawSetting]) -> usize {
    entries
        .iter()
        .filter(|entry| Setting::from_id_value(entry.id, entry.value).is_some())
        .count()
}

fn assert_last_max_frame_size_wins(entries: &[RawSetting], connection: &Connection) {
    if let Some(last) = entries
        .iter()
        .rev()
        .find(|entry| entry.id == SETTINGS_MAX_FRAME_SIZE_ID)
    {
        assert_eq!(
            connection.remote_settings().max_frame_size,
            last.value,
            "duplicate SETTINGS_MAX_FRAME_SIZE entries should apply in wire order"
        );
    }
}

fn assert_h2_error(
    parsed: &Result<Frame, asupersync::http::h2::H2Error>,
    code: ErrorCode,
    stream_id: Option<u32>,
) {
    match parsed {
        Err(err) => {
            assert_eq!(err.code, code);
            assert_eq!(err.stream_id, stream_id);
        }
        Ok(frame) => panic!("expected {code:?}, got parsed frame {frame:?}"),
    }
}

#[cfg(test)]
mod production_regressions {
    use super::*;

    #[test]
    fn below_minimum_max_frame_size_is_protocol_error() {
        let scenario = Scenario {
            stream_id: 0,
            flags: 0,
            entries: vec![RawSetting {
                id: SETTINGS_MAX_FRAME_SIZE_ID,
                value: MIN_MAX_FRAME_SIZE - 1,
            }],
            extra_tail: Vec::new(),
        };
        let payload = encode_payload(&scenario.entries, &scenario.extra_tail);
        let header = FrameHeader {
            length: payload.len() as u32,
            frame_type: FrameType::Settings as u8,
            flags: 0,
            stream_id: 0,
        };
        let parsed = parse_frame(&header, Bytes::from(payload));
        assert_h2_error(&parsed, ErrorCode::ProtocolError, None);
    }

    #[test]
    fn valid_duplicate_max_frame_size_applies_last_value_atomically() {
        let mut connection = Connection::server(Settings::default());
        let settings = asupersync::http::h2::frame::SettingsFrame::new(vec![
            Setting::MaxFrameSize(MIN_MAX_FRAME_SIZE),
            Setting::MaxFrameSize(MIN_MAX_FRAME_SIZE + 1),
        ]);
        connection
            .process_frame(Frame::Settings(settings))
            .expect("valid SETTINGS should apply");
        assert_eq!(
            connection.remote_settings().max_frame_size,
            MIN_MAX_FRAME_SIZE + 1
        );
    }

    #[test]
    fn invalid_duplicate_sequence_is_atomic() {
        let mut connection = Connection::server(Settings::default());
        let before = connection.remote_settings().clone();
        let settings = asupersync::http::h2::frame::SettingsFrame::new(vec![
            Setting::InitialWindowSize(12345),
            Setting::MaxFrameSize(MIN_MAX_FRAME_SIZE - 1),
        ]);
        let err = connection
            .process_frame(Frame::Settings(settings))
            .expect_err("invalid SETTINGS_MAX_FRAME_SIZE must fail");
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert_eq!(connection.remote_settings(), &before);
    }
}
