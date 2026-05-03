#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// HTTP/2 SETTINGS frame ACK flag validation testing.
/// Per RFC 7540 §6.5, SETTINGS frame with ACK flag MUST have empty payload.
/// Non-empty payload with ACK flag must be rejected as FRAME_SIZE_ERROR.
///
/// Tests:
/// - SETTINGS with ACK flag and non-empty payload (FRAME_SIZE_ERROR)
/// - SETTINGS with ACK flag and empty payload (valid)
/// - SETTINGS without ACK flag with payload (valid)
/// - Various payload sizes with ACK flag
/// - Stream ID validation (must be 0)
/// - Frame size consistency

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// SETTINGS frame to test
    settings_frame: SettingsFrame,
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingsFrame {
    /// Frame flags (ACK = 0x1)
    flags: u8,
    /// Stream ID (must be 0 for SETTINGS)
    stream_id: u32,
    /// Settings payload (list of setting_id, value pairs)
    settings: Vec<SettingEntry>,
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingEntry {
    /// Setting ID (16-bit)
    id: u16,
    /// Setting value (32-bit)
    value: u32,
}

/// SETTINGS frame flags
const SETTINGS_ACK_FLAG: u8 = 0x1;

/// Mock HTTP/2 SETTINGS frame parser with ACK flag validation
struct MockH2SettingsParser {
    errors: Vec<String>,
}

impl MockH2SettingsParser {
    fn new() -> Self {
        Self { errors: Vec::new() }
    }

    /// Parse SETTINGS frame with ACK flag validation
    fn parse_settings_frame(&mut self, frame: &SettingsFrame) -> Result<(), String> {
        // Validate stream ID first
        if frame.stream_id != 0 {
            return Err("PROTOCOL_ERROR: SETTINGS frame stream ID must be 0".into());
        }

        // Check ACK flag
        let ack_flag_set = (frame.flags & SETTINGS_ACK_FLAG) != 0;

        // Calculate payload length (6 bytes per setting)
        let payload_length = frame.settings.len() * 6;

        if ack_flag_set {
            // RFC 7540 §6.5: ACK flag requires empty payload
            if !frame.settings.is_empty() {
                return Err(format!(
                    "FRAME_SIZE_ERROR: SETTINGS frame with ACK flag must have empty payload (got {} bytes)",
                    payload_length
                ));
            }

            // Valid ACK frame (empty payload)
            return Ok(());
        }

        // Non-ACK SETTINGS frame - validate payload
        if payload_length > 16777215 {
            // 2^24 - 1
            return Err(
                "FRAME_SIZE_ERROR: SETTINGS frame payload exceeds maximum frame size".into(),
            );
        }

        // Validate individual settings (basic validation)
        for setting in &frame.settings {
            // Known setting IDs: 1-6 per RFC 7540
            match setting.id {
                1 => { /* HEADER_TABLE_SIZE - any value allowed */ }
                2 => {
                    // ENABLE_PUSH - only 0 or 1 allowed
                    if setting.value > 1 {
                        self.errors.push(format!(
                            "Invalid ENABLE_PUSH value: {} (must be 0 or 1)",
                            setting.value
                        ));
                    }
                }
                3 => { /* MAX_CONCURRENT_STREAMS - any value allowed */ }
                4 => {
                    // INITIAL_WINDOW_SIZE - max 2^31-1
                    if setting.value > 2_147_483_647 {
                        self.errors.push(format!(
                            "Invalid INITIAL_WINDOW_SIZE value: {} (exceeds 2^31-1)",
                            setting.value
                        ));
                    }
                }
                5 => {
                    // MAX_FRAME_SIZE - must be 2^14 to 2^24-1
                    if setting.value < 16384 || setting.value > 16777215 {
                        self.errors.push(format!(
                            "Invalid MAX_FRAME_SIZE value: {} (must be 16384-16777215)",
                            setting.value
                        ));
                    }
                }
                6 => { /* MAX_HEADER_LIST_SIZE - any value allowed */ }
                _ => {
                    // Unknown setting - should be ignored per RFC 7540 §6.5
                    self.errors
                        .push(format!("Unknown setting ID: {} (ignored)", setting.id));
                }
            }
        }

        Ok(())
    }

    /// Get error messages for inspection
    fn get_errors(&self) -> &[String] {
        &self.errors
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let input: FuzzInput = match u.arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Skip invalid inputs
    };

    // Limit settings count to prevent timeouts
    if input.settings_frame.settings.len() > 50 {
        return;
    }

    let mut parser = MockH2SettingsParser::new();
    let result = parser.parse_settings_frame(&input.settings_frame);

    let ack_flag_set = (input.settings_frame.flags & SETTINGS_ACK_FLAG) != 0;
    let has_payload = !input.settings_frame.settings.is_empty();

    // Test 1: ACK flag with non-empty payload must be FRAME_SIZE_ERROR
    if ack_flag_set && has_payload {
        assert!(
            result.is_err(),
            "SETTINGS frame with ACK flag and payload should be rejected"
        );

        if let Err(error_msg) = &result {
            assert!(
                error_msg.contains("FRAME_SIZE_ERROR"),
                "ACK with payload should generate FRAME_SIZE_ERROR: {}",
                error_msg
            );
            assert!(
                error_msg.contains("empty payload"),
                "Error should mention empty payload requirement: {}",
                error_msg
            );
        }
        return; // No further tests needed for this error case
    }

    // Test 2: ACK flag with empty payload should succeed
    if ack_flag_set && !has_payload {
        assert!(
            result.is_ok(),
            "SETTINGS frame with ACK flag and empty payload should succeed"
        );
        return; // ACK frames don't need further validation
    }

    // Test 3: Non-ACK frames with payload should generally succeed
    // (unless they have other validation errors)
    if !ack_flag_set {
        // Check stream ID validation
        if input.settings_frame.stream_id != 0 {
            assert!(
                result.is_err(),
                "SETTINGS frame with non-zero stream ID should be rejected"
            );
            if let Err(error_msg) = &result {
                assert!(
                    error_msg.contains("stream ID must be 0"),
                    "Non-zero stream ID error should be clear: {}",
                    error_msg
                );
            }
            return;
        }

        // Check frame size limit
        let payload_length = input.settings_frame.settings.len() * 6;
        if payload_length > 16777215 {
            assert!(
                result.is_err(),
                "SETTINGS frame exceeding max frame size should be rejected"
            );
            if let Err(error_msg) = &result {
                assert!(
                    error_msg.contains("exceeds maximum frame size"),
                    "Frame size error should be clear: {}",
                    error_msg
                );
            }
            return;
        }

        // For valid non-ACK frames, parsing should succeed
        // (individual setting validation errors are warnings, not parse failures)
        assert!(
            result.is_ok(),
            "Valid SETTINGS frame without ACK should succeed: {:?}",
            result
        );
    }

    // Test 4: Verify setting-specific validation (for non-ACK frames)
    if !ack_flag_set && result.is_ok() {
        for setting in &input.settings_frame.settings {
            match setting.id {
                2 => {
                    // ENABLE_PUSH
                    if setting.value > 1 {
                        assert!(
                            parser
                                .get_errors()
                                .iter()
                                .any(|e| e.contains("ENABLE_PUSH")),
                            "Invalid ENABLE_PUSH value should generate warning"
                        );
                    }
                }
                4 => {
                    // INITIAL_WINDOW_SIZE
                    if setting.value > 2_147_483_647 {
                        assert!(
                            parser
                                .get_errors()
                                .iter()
                                .any(|e| e.contains("INITIAL_WINDOW_SIZE")),
                            "Invalid INITIAL_WINDOW_SIZE value should generate warning"
                        );
                    }
                }
                5 => {
                    // MAX_FRAME_SIZE
                    if setting.value < 16384 || setting.value > 16777215 {
                        assert!(
                            parser
                                .get_errors()
                                .iter()
                                .any(|e| e.contains("MAX_FRAME_SIZE")),
                            "Invalid MAX_FRAME_SIZE value should generate warning"
                        );
                    }
                }
                _ => {}
            }
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ack_with_empty_payload_valid() {
        let frame = SettingsFrame {
            flags: SETTINGS_ACK_FLAG,
            stream_id: 0,
            settings: vec![], // Empty payload
        };

        let mut parser = MockH2SettingsParser::new();
        let result = parser.parse_settings_frame(&frame);

        assert!(result.is_ok(), "ACK with empty payload should be valid");
    }

    #[test]
    fn test_ack_with_payload_invalid() {
        let frame = SettingsFrame {
            flags: SETTINGS_ACK_FLAG,
            stream_id: 0,
            settings: vec![
                SettingEntry { id: 1, value: 4096 }, // Non-empty payload
            ],
        };

        let mut parser = MockH2SettingsParser::new();
        let result = parser.parse_settings_frame(&frame);

        assert!(result.is_err(), "ACK with payload should be invalid");
        assert!(result.unwrap_err().contains("FRAME_SIZE_ERROR"));
        assert!(result.unwrap_err().contains("empty payload"));
    }

    #[test]
    fn test_ack_with_multiple_settings_invalid() {
        let frame = SettingsFrame {
            flags: SETTINGS_ACK_FLAG,
            stream_id: 0,
            settings: vec![
                SettingEntry { id: 1, value: 4096 },
                SettingEntry { id: 2, value: 1 },
                SettingEntry { id: 3, value: 100 },
            ],
        };

        let mut parser = MockH2SettingsParser::new();
        let result = parser.parse_settings_frame(&frame);

        assert!(
            result.is_err(),
            "ACK with multiple settings should be invalid"
        );
        assert!(result.unwrap_err().contains("FRAME_SIZE_ERROR"));
        assert!(result.unwrap_err().contains("18 bytes")); // 3 * 6 bytes
    }

    #[test]
    fn test_non_ack_with_payload_valid() {
        let frame = SettingsFrame {
            flags: 0, // No ACK flag
            stream_id: 0,
            settings: vec![
                SettingEntry { id: 1, value: 4096 }, // HEADER_TABLE_SIZE
                SettingEntry { id: 2, value: 1 },    // ENABLE_PUSH
                SettingEntry { id: 3, value: 100 },  // MAX_CONCURRENT_STREAMS
            ],
        };

        let mut parser = MockH2SettingsParser::new();
        let result = parser.parse_settings_frame(&frame);

        assert!(result.is_ok(), "Non-ACK with valid payload should succeed");
    }

    #[test]
    fn test_non_ack_with_empty_payload_valid() {
        let frame = SettingsFrame {
            flags: 0, // No ACK flag
            stream_id: 0,
            settings: vec![], // Empty payload is valid for non-ACK
        };

        let mut parser = MockH2SettingsParser::new();
        let result = parser.parse_settings_frame(&frame);

        assert!(result.is_ok(), "Non-ACK with empty payload should succeed");
    }

    #[test]
    fn test_non_zero_stream_id_error() {
        let frame = SettingsFrame {
            flags: 0,
            stream_id: 1, // Invalid for SETTINGS
            settings: vec![],
        };

        let mut parser = MockH2SettingsParser::new();
        let result = parser.parse_settings_frame(&frame);

        assert!(
            result.is_err(),
            "SETTINGS with non-zero stream ID should fail"
        );
        assert!(result.unwrap_err().contains("stream ID must be 0"));
    }

    #[test]
    fn test_ack_flag_with_other_flags() {
        let frame = SettingsFrame {
            flags: SETTINGS_ACK_FLAG | 0x02, // ACK + some other flag
            stream_id: 0,
            settings: vec![
                SettingEntry { id: 1, value: 4096 }, // Payload with ACK
            ],
        };

        let mut parser = MockH2SettingsParser::new();
        let result = parser.parse_settings_frame(&frame);

        assert!(
            result.is_err(),
            "ACK flag with payload should fail regardless of other flags"
        );
        assert!(result.unwrap_err().contains("FRAME_SIZE_ERROR"));
    }

    #[test]
    fn test_setting_validation_warnings() {
        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings: vec![
                SettingEntry { id: 2, value: 5 }, // Invalid ENABLE_PUSH
                SettingEntry {
                    id: 4,
                    value: u32::MAX,
                }, // Invalid INITIAL_WINDOW_SIZE
                SettingEntry { id: 5, value: 1000 }, // Invalid MAX_FRAME_SIZE
                SettingEntry { id: 99, value: 42 }, // Unknown setting
            ],
        };

        let mut parser = MockH2SettingsParser::new();
        let result = parser.parse_settings_frame(&frame);

        // Should still parse successfully but generate warnings
        assert!(
            result.is_ok(),
            "Invalid setting values should generate warnings, not errors"
        );

        let errors = parser.get_errors();
        assert!(errors.iter().any(|e| e.contains("ENABLE_PUSH")));
        assert!(errors.iter().any(|e| e.contains("INITIAL_WINDOW_SIZE")));
        assert!(errors.iter().any(|e| e.contains("MAX_FRAME_SIZE")));
        assert!(errors.iter().any(|e| e.contains("Unknown setting ID: 99")));
    }

    #[test]
    fn test_max_frame_size_exceeded() {
        // Create frame that would exceed max frame size (2^24 - 1 bytes)
        let settings_count = (16777215 / 6) + 1; // Just over the limit
        let mut settings = Vec::new();
        for i in 0..settings_count {
            settings.push(SettingEntry {
                id: (i % 6 + 1) as u16,
                value: 1000,
            });
        }

        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings,
        };

        let mut parser = MockH2SettingsParser::new();
        let result = parser.parse_settings_frame(&frame);

        assert!(
            result.is_err(),
            "Frame exceeding max size should be rejected"
        );
        assert!(result.unwrap_err().contains("exceeds maximum frame size"));
    }

    #[test]
    fn test_edge_case_exactly_max_frame_size() {
        // Create frame that is exactly at max frame size
        let settings_count = 16777215 / 6; // Exactly at the limit
        let mut settings = Vec::new();
        for i in 0..settings_count {
            settings.push(SettingEntry { id: 1, value: 4096 });
        }

        let frame = SettingsFrame {
            flags: 0,
            stream_id: 0,
            settings,
        };

        let mut parser = MockH2SettingsParser::new();
        let result = parser.parse_settings_frame(&frame);

        assert!(
            result.is_ok(),
            "Frame exactly at max size should be accepted"
        );
    }
}
