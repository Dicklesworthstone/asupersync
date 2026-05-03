#![no_main]

//! Fuzz target: HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE overflow validation
//!
//! Tests the scenario where a peer sends SETTINGS_INITIAL_WINDOW_SIZE = u32::MAX
//! (4,294,967,295), which equals -1 when read as i32. Per RFC 7540 §6.5.2,
//! the maximum valid value is 2^31-1 (2,147,483,647).
//!
//! Key behaviors tested:
//! - Values above 2^31-1 must be rejected as PROTOCOL_ERROR
//! - Boundary testing around the valid range
//! - Proper handling of u32::MAX and other large values
//! - Flow control window calculations with valid vs invalid values

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 frame type identifiers
const SETTINGS_TYPE: u8 = 0x4;
const DATA_TYPE: u8 = 0x0;

/// HTTP/2 SETTINGS parameter identifiers (RFC 7540 §6.5.2)
const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
const SETTINGS_ENABLE_PUSH: u16 = 0x2;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;

/// HTTP/2 frame flags
const SETTINGS_ACK_FLAG: u8 = 0x1;

/// RFC 7540 §6.5.2: Maximum valid value for SETTINGS_INITIAL_WINDOW_SIZE
const MAX_INITIAL_WINDOW_SIZE: u32 = 2_147_483_647; // 2^31 - 1

/// Mock parser for HTTP/2 SETTINGS frame with INITIAL_WINDOW_SIZE validation
#[derive(Debug)]
struct MockH2InitialWindowSizeParser {
    initial_window_size: u32, // RFC default: 65535
    flow_control_enabled: bool,
    stream_windows: Vec<StreamWindow>,
}

/// Stream window tracking
#[derive(Debug, Clone)]
struct StreamWindow {
    stream_id: u32,
    window_size: i64, // Signed to handle underflow
}

/// Result types for parsing
#[derive(Debug, PartialEq)]
enum ParseResult {
    /// Settings frame processed successfully
    SettingsProcessed(u32), // new window size
    /// Protocol error
    ProtocolError(String),
    /// Frame processed (other frame types)
    FrameProcessed,
    /// Window update applied
    WindowUpdate { stream_id: u32, new_size: i64 },
}

/// Input for fuzz testing
#[derive(Debug, Arbitrary)]
struct H2InitialWindowSizeInput {
    /// Window size values to test
    test_values: Vec<WindowSizeTest>,

    /// Frame size limit for testing (16384..65535)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(16384..=65535))]
    max_frame_size: u32,

    /// Enable flow control tracking
    enable_flow_control: bool,
}

#[derive(Debug, Arbitrary)]
struct WindowSizeTest {
    /// The window size value to test
    window_size: u32,

    /// Whether to test with existing stream windows
    test_with_streams: bool,

    /// Number of streams to create for testing (0-10)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=10))]
    stream_count: u8,
}

impl MockH2InitialWindowSizeParser {
    fn new() -> Self {
        Self {
            initial_window_size: 65535, // RFC default
            flow_control_enabled: true,
            stream_windows: Vec::new(),
        }
    }

    /// Process SETTINGS frame with INITIAL_WINDOW_SIZE validation
    fn process_settings(&mut self, settings: &[(u16, u32)]) -> Result<ParseResult, String> {
        for &(setting_id, value) in settings {
            match setting_id {
                SETTINGS_INITIAL_WINDOW_SIZE => {
                    // RFC 7540 §6.5.2: Values above 2^31-1 MUST cause PROTOCOL_ERROR
                    if value > MAX_INITIAL_WINDOW_SIZE {
                        return Err(format!(
                            "PROTOCOL_ERROR: SETTINGS_INITIAL_WINDOW_SIZE {} exceeds maximum {}",
                            value, MAX_INITIAL_WINDOW_SIZE
                        ));
                    }

                    // Update existing stream windows based on the delta
                    let old_window_size = self.initial_window_size as i64;
                    let new_window_size = value as i64;
                    let delta = new_window_size - old_window_size;

                    if self.flow_control_enabled {
                        for stream in &mut self.stream_windows {
                            stream.window_size += delta;
                            // Note: negative windows are allowed per RFC,
                            // they just block sending until positive
                        }
                    }

                    self.initial_window_size = value;
                    return Ok(ParseResult::SettingsProcessed(value));
                }
                SETTINGS_HEADER_TABLE_SIZE
                | SETTINGS_ENABLE_PUSH
                | SETTINGS_MAX_CONCURRENT_STREAMS
                | SETTINGS_MAX_FRAME_SIZE
                | SETTINGS_MAX_HEADER_LIST_SIZE => {
                    // Other settings - ignore for this test
                }
                _ => {
                    // Unknown setting - ignore per RFC 7540 §6.5
                }
            }
        }
        Ok(ParseResult::FrameProcessed)
    }

    /// Create a new stream window
    fn create_stream(&mut self, stream_id: u32) -> ParseResult {
        if self.flow_control_enabled {
            let window = StreamWindow {
                stream_id,
                window_size: self.initial_window_size as i64,
            };
            self.stream_windows.push(window);
            ParseResult::WindowUpdate {
                stream_id,
                new_size: self.initial_window_size as i64,
            }
        } else {
            ParseResult::FrameProcessed
        }
    }

    /// Get current window size for a stream
    fn get_stream_window(&self, stream_id: u32) -> Option<i64> {
        self.stream_windows
            .iter()
            .find(|s| s.stream_id == stream_id)
            .map(|s| s.window_size)
    }

    /// Apply a WINDOW_UPDATE to a stream
    fn apply_window_update(&mut self, stream_id: u32, increment: u32) -> ParseResult {
        if let Some(stream) = self
            .stream_windows
            .iter_mut()
            .find(|s| s.stream_id == stream_id)
        {
            stream.window_size += increment as i64;

            // Check for overflow beyond 2^31-1
            if stream.window_size > MAX_INITIAL_WINDOW_SIZE as i64 {
                return ParseResult::ProtocolError(format!(
                    "FLOW_CONTROL_ERROR: Stream {} window {} exceeds maximum",
                    stream_id, stream.window_size
                ));
            }

            ParseResult::WindowUpdate {
                stream_id,
                new_size: stream.window_size,
            }
        } else {
            ParseResult::ProtocolError(format!("Stream {} not found", stream_id))
        }
    }
}

/// Encode SETTINGS frame with INITIAL_WINDOW_SIZE
fn encode_settings_frame(settings: &[(u16, u32)], max_frame_size: u32) -> Vec<u8> {
    let payload_len = settings.len() * 6; // Each setting is 6 bytes

    if payload_len > max_frame_size as usize {
        // Frame too large - truncate
        let max_settings = max_frame_size as usize / 6;
        let truncated: Vec<_> = settings.iter().take(max_settings).cloned().collect();
        return encode_settings_frame(&truncated, max_frame_size);
    }

    let mut frame = Vec::new();

    // Frame header (9 bytes)
    frame.extend_from_slice(&(payload_len as u32).to_be_bytes()[1..4]); // Length (24 bits)
    frame.push(SETTINGS_TYPE); // Type
    frame.push(0); // Flags (no ACK)
    frame.extend_from_slice(&0u32.to_be_bytes()); // Stream ID (0 for SETTINGS)

    // Settings payload
    for &(setting_id, value) in settings {
        frame.extend_from_slice(&setting_id.to_be_bytes());
        frame.extend_from_slice(&value.to_be_bytes());
    }

    frame
}

/// Process the input through our mock parser
fn process_input(input: &H2InitialWindowSizeInput) -> Vec<ParseResult> {
    let mut parser = MockH2InitialWindowSizeParser::new();
    parser.flow_control_enabled = input.enable_flow_control;
    let mut results = Vec::new();

    for test in &input.test_values {
        // Create test streams if requested
        if test.test_with_streams {
            for i in 1..=test.stream_count {
                let stream_id = (i as u32) * 2 + 1; // Odd stream IDs for client-initiated
                results.push(parser.create_stream(stream_id));
            }
        }

        // Test the window size setting
        let settings = vec![(SETTINGS_INITIAL_WINDOW_SIZE, test.window_size)];
        match parser.process_settings(&settings) {
            Ok(result) => results.push(result),
            Err(e) => results.push(ParseResult::ProtocolError(e)),
        }

        // Test a window update to verify the new window calculations
        if test.test_with_streams && test.stream_count > 0 {
            let stream_id = 3; // First created stream
            results.push(parser.apply_window_update(stream_id, 1000));
        }
    }

    results
}

fuzz_target!(|input: H2InitialWindowSizeInput| {
    // Skip empty inputs
    if input.test_values.is_empty() {
        return;
    }

    let results = process_input(&input);

    // Test key invariants
    for (i, test) in input.test_values.iter().enumerate() {
        if let Some(result) = results.get(i) {
            match result {
                ParseResult::SettingsProcessed(window_size) => {
                    // Valid window size should be <= MAX_INITIAL_WINDOW_SIZE
                    assert!(
                        *window_size <= MAX_INITIAL_WINDOW_SIZE,
                        "Parser accepted invalid window size: {} > {}",
                        window_size,
                        MAX_INITIAL_WINDOW_SIZE
                    );
                }
                ParseResult::ProtocolError(msg) => {
                    // Protocol errors should occur for values > MAX_INITIAL_WINDOW_SIZE
                    if test.window_size > MAX_INITIAL_WINDOW_SIZE {
                        assert!(
                            msg.contains("PROTOCOL_ERROR") || msg.contains("exceeds maximum"),
                            "Expected proper error for oversized window {}: {}",
                            test.window_size,
                            msg
                        );
                    }
                }
                ParseResult::WindowUpdate {
                    stream_id: _,
                    new_size,
                } => {
                    // Window updates should not exceed maximum
                    assert!(
                        *new_size <= MAX_INITIAL_WINDOW_SIZE as i64 || *new_size < 0,
                        "Window update resulted in invalid size: {}",
                        new_size
                    );
                }
                ParseResult::FrameProcessed => {
                    // Regular frame processing
                }
            }
        }
    }

    // Test specific boundary values
    let boundary_tests = [
        (MAX_INITIAL_WINDOW_SIZE, true),      // Should pass
        (MAX_INITIAL_WINDOW_SIZE + 1, false), // Should fail
        (u32::MAX, false),                    // Should fail (-1 as i32)
        (u32::MAX - 1, false),                // Should fail
        (0, true),                            // Should pass (valid zero window)
    ];

    for (value, should_pass) in boundary_tests {
        let mut parser = MockH2InitialWindowSizeParser::new();
        let settings = vec![(SETTINGS_INITIAL_WINDOW_SIZE, value)];
        let result = parser.process_settings(&settings);

        match (result, should_pass) {
            (Ok(ParseResult::SettingsProcessed(_)), true) => {
                // Expected success
            }
            (Err(_), false) => {
                // Expected failure
            }
            (Ok(_), false) => {
                panic!("Parser incorrectly accepted invalid window size: {}", value);
            }
            (Err(e), true) => {
                panic!(
                    "Parser incorrectly rejected valid window size {}: {}",
                    value, e
                );
            }
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc_maximum_window_size() {
        let mut parser = MockH2InitialWindowSizeParser::new();

        // Test maximum valid value
        let settings = vec![(SETTINGS_INITIAL_WINDOW_SIZE, MAX_INITIAL_WINDOW_SIZE)];
        match parser.process_settings(&settings) {
            Ok(ParseResult::SettingsProcessed(size)) => {
                assert_eq!(size, MAX_INITIAL_WINDOW_SIZE);
            }
            result => panic!("Expected success for max valid size, got: {:?}", result),
        }
    }

    #[test]
    fn test_oversized_window_rejection() {
        let mut parser = MockH2InitialWindowSizeParser::new();

        // Test value above maximum (should fail)
        let settings = vec![(SETTINGS_INITIAL_WINDOW_SIZE, MAX_INITIAL_WINDOW_SIZE + 1)];
        match parser.process_settings(&settings) {
            Err(msg) => {
                assert!(msg.contains("PROTOCOL_ERROR"));
                assert!(msg.contains("exceeds maximum"));
            }
            result => panic!(
                "Expected protocol error for oversized window, got: {:?}",
                result
            ),
        }
    }

    #[test]
    fn test_u32_max_rejection() {
        let mut parser = MockH2InitialWindowSizeParser::new();

        // Test u32::MAX (which is -1 as i32)
        let settings = vec![(SETTINGS_INITIAL_WINDOW_SIZE, u32::MAX)];
        match parser.process_settings(&settings) {
            Err(msg) => {
                assert!(msg.contains("PROTOCOL_ERROR"));
                assert!(msg.contains(&u32::MAX.to_string()));
            }
            result => panic!("Expected protocol error for u32::MAX, got: {:?}", result),
        }
    }

    #[test]
    fn test_zero_window_size() {
        let mut parser = MockH2InitialWindowSizeParser::new();

        // Zero window is valid (blocks sending)
        let settings = vec![(SETTINGS_INITIAL_WINDOW_SIZE, 0)];
        match parser.process_settings(&settings) {
            Ok(ParseResult::SettingsProcessed(0)) => {}
            result => panic!("Expected success for zero window, got: {:?}", result),
        }
    }

    #[test]
    fn test_stream_window_delta_calculation() {
        let mut parser = MockH2InitialWindowSizeParser::new();

        // Create a stream with default window size (65535)
        parser.create_stream(3);
        let initial_window = parser.get_stream_window(3).unwrap();
        assert_eq!(initial_window, 65535);

        // Update INITIAL_WINDOW_SIZE to 32768 (delta = -32767)
        let settings = vec![(SETTINGS_INITIAL_WINDOW_SIZE, 32768)];
        parser.process_settings(&settings).unwrap();

        // Stream window should be updated by the delta
        let updated_window = parser.get_stream_window(3).unwrap();
        assert_eq!(updated_window, 32768);
    }

    #[test]
    fn test_negative_window_after_delta() {
        let mut parser = MockH2InitialWindowSizeParser::new();

        // Create stream and consume some window
        parser.create_stream(3);
        parser.apply_window_update(3, 0); // Just to test the mechanism

        // Dramatically reduce INITIAL_WINDOW_SIZE
        let settings = vec![(SETTINGS_INITIAL_WINDOW_SIZE, 1000)];
        parser.process_settings(&settings).unwrap();

        // Stream window should be reduced (and possibly negative)
        let window = parser.get_stream_window(3).unwrap();
        // 1000 - 65535 + 65535 = 1000 (the new value)
        assert_eq!(window, 1000);
    }

    #[test]
    fn test_settings_frame_encoding() {
        let settings = vec![(SETTINGS_INITIAL_WINDOW_SIZE, MAX_INITIAL_WINDOW_SIZE)];
        let frame = encode_settings_frame(&settings, 16384);

        // Check frame structure
        assert_eq!(frame.len(), 9 + 6); // Header + one setting
        assert_eq!(frame[3], SETTINGS_TYPE); // Frame type
        assert_eq!(frame[4], 0); // No flags

        // Check setting payload
        let setting_id = u16::from_be_bytes([frame[9], frame[10]]);
        let setting_value = u32::from_be_bytes([frame[11], frame[12], frame[13], frame[14]]);
        assert_eq!(setting_id, SETTINGS_INITIAL_WINDOW_SIZE);
        assert_eq!(setting_value, MAX_INITIAL_WINDOW_SIZE);
    }

    #[test]
    fn test_boundary_values() {
        let boundary_cases = [
            (MAX_INITIAL_WINDOW_SIZE - 1, true),  // Just below max
            (MAX_INITIAL_WINDOW_SIZE, true),      // Exactly max
            (MAX_INITIAL_WINDOW_SIZE + 1, false), // Just above max
            (u32::MAX - 1, false),                // Near u32::MAX
            (u32::MAX, false),                    // u32::MAX (-1 as i32)
            (1, true),                            // Valid small value
            (65535, true),                        // RFC default
            (65536, true),                        // Common larger value
        ];

        for (value, should_pass) in boundary_cases {
            let mut parser = MockH2InitialWindowSizeParser::new();
            let settings = vec![(SETTINGS_INITIAL_WINDOW_SIZE, value)];
            let result = parser.process_settings(&settings);

            if should_pass {
                assert!(
                    result.is_ok(),
                    "Value {} should be accepted but was rejected: {:?}",
                    value,
                    result
                );
            } else {
                assert!(
                    result.is_err(),
                    "Value {} should be rejected but was accepted",
                    value
                );
            }
        }
    }
}
