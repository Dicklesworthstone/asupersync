#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// HTTP/2 SETTINGS frame mixing unknown and known setting IDs.
/// Per RFC 7540 §6.5, unknown settings MUST be silently ignored,
/// known settings MUST be applied, ordering doesn't matter.
///
/// Tests:
/// - Mixed known/unknown settings in various orders
/// - Unknown setting IDs (not in 1-6 range) are ignored
/// - Known setting IDs are applied regardless of position
/// - Duplicate settings (last value wins)
/// - Invalid values for known settings are rejected
/// - Empty settings frame (valid)

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Mix of known and unknown settings
    settings: Vec<SettingEntry>,
    /// Frame flags (should be 0 for SETTINGS)
    flags: u8,
    /// Stream ID (must be 0 for SETTINGS)
    stream_id: u32,
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingEntry {
    /// Setting ID (known: 1-6, unknown: anything else)
    id: u16,
    /// Setting value
    value: u32,
}

/// Known HTTP/2 settings from RFC 7540
#[derive(Debug, PartialEq, Eq)]
enum KnownSetting {
    HeaderTableSize = 1,
    EnablePush = 2,
    MaxConcurrentStreams = 3,
    InitialWindowSize = 4,
    MaxFrameSize = 5,
    MaxHeaderListSize = 6,
}

impl KnownSetting {
    fn from_id(id: u16) -> Option<Self> {
        match id {
            1 => Some(Self::HeaderTableSize),
            2 => Some(Self::EnablePush),
            3 => Some(Self::MaxConcurrentStreams),
            4 => Some(Self::InitialWindowSize),
            5 => Some(Self::MaxFrameSize),
            6 => Some(Self::MaxHeaderListSize),
            _ => None,
        }
    }

    fn validate_value(&self, value: u32) -> bool {
        match self {
            Self::HeaderTableSize => true,                     // Any value allowed
            Self::EnablePush => value <= 1,                    // Only 0 or 1
            Self::MaxConcurrentStreams => true,                // Any value allowed
            Self::InitialWindowSize => value <= 2_147_483_647, // 2^31 - 1
            Self::MaxFrameSize => value >= 16384 && value <= 16777215, // 2^14 to 2^24-1
            Self::MaxHeaderListSize => true,                   // Any value allowed
        }
    }
}

/// Mock HTTP/2 SETTINGS frame parser that validates RFC 7540 §6.5 compliance
struct MockH2SettingsParser {
    /// Applied known settings (unknown ones ignored)
    applied_settings: HashMap<KnownSetting, u32>,
    /// Count of unknown settings encountered (for verification)
    unknown_count: usize,
    /// Errors encountered
    errors: Vec<String>,
}

impl MockH2SettingsParser {
    fn new() -> Self {
        Self {
            applied_settings: HashMap::new(),
            unknown_count: 0,
            errors: Vec::new(),
        }
    }

    /// Parse SETTINGS frame according to RFC 7540 §6.5
    fn parse_settings_frame(&mut self, input: &FuzzInput) -> Result<(), String> {
        // Validate frame structure first
        if input.flags != 0 {
            return Err("SETTINGS frame flags must be 0 (no ACK for data payload)".into());
        }

        if input.stream_id != 0 {
            return Err("SETTINGS frame stream ID must be 0".into());
        }

        // Calculate frame payload size (6 bytes per setting)
        let payload_size = input.settings.len() * 6;
        if payload_size > 16777215 {
            // 2^24 - 1
            return Err("SETTINGS frame payload exceeds maximum frame size".into());
        }

        // Process each setting
        for setting in &input.settings {
            if let Some(known_setting) = KnownSetting::from_id(setting.id) {
                // Known setting - validate and apply
                if !known_setting.validate_value(setting.value) {
                    self.errors.push(format!(
                        "Invalid value {} for setting {:?}",
                        setting.value, known_setting
                    ));
                    continue;
                }

                // Apply setting (last value wins for duplicates)
                self.applied_settings.insert(known_setting, setting.value);
            } else {
                // Unknown setting - silently ignore per RFC 7540 §6.5
                self.unknown_count += 1;
            }
        }

        Ok(())
    }

    /// Verify that ordering doesn't affect final result
    fn verify_ordering_independence(&self, input: &FuzzInput) -> bool {
        // Create a shuffled version of the settings
        let mut shuffled_settings = input.settings.clone();
        shuffled_settings.reverse(); // Simple reordering

        let shuffled_input = FuzzInput {
            settings: shuffled_settings,
            flags: input.flags,
            stream_id: input.stream_id,
        };

        let mut other_parser = MockH2SettingsParser::new();
        let _ = other_parser.parse_settings_frame(&shuffled_input);

        // Applied settings should be identical regardless of order
        self.applied_settings == other_parser.applied_settings
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let input: FuzzInput = match u.arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Skip invalid inputs
    };

    // Limit size to prevent timeouts
    if input.settings.len() > 50 {
        return;
    }

    let mut parser = MockH2SettingsParser::new();
    let result = parser.parse_settings_frame(&input);

    // Test 1: Known settings should be applied, unknown ignored
    match result {
        Ok(_) => {
            // Count known vs unknown settings in input
            let known_count = input
                .settings
                .iter()
                .filter(|s| KnownSetting::from_id(s.id).is_some())
                .count();
            let expected_unknown = input.settings.len() - known_count;

            // Unknown count should match expectations
            assert_eq!(
                parser.unknown_count, expected_unknown,
                "Unknown setting count mismatch: expected {}, got {}",
                expected_unknown, parser.unknown_count
            );

            // Only valid known settings should be applied
            for (&setting, &value) in &parser.applied_settings {
                assert!(
                    setting.validate_value(value),
                    "Invalid value {} applied for setting {:?}",
                    value,
                    setting
                );
            }
        }
        Err(e) => {
            // Frame-level errors are acceptable
            assert!(
                e.contains("flags must be 0")
                    || e.contains("stream ID must be 0")
                    || e.contains("exceeds maximum frame size"),
                "Unexpected error: {}",
                e
            );
            return; // Skip further tests on frame errors
        }
    }

    // Test 2: Ordering independence
    assert!(
        parser.verify_ordering_independence(&input),
        "Settings application affected by ordering"
    );

    // Test 3: Duplicate settings (last value wins)
    if input.settings.len() >= 2 {
        let first_known_setting = input
            .settings
            .iter()
            .find(|s| KnownSetting::from_id(s.id).is_some());

        if let Some(first_setting) = first_known_setting {
            if let Some(known) = KnownSetting::from_id(first_setting.id) {
                // Find last occurrence of this setting
                let last_value = input
                    .settings
                    .iter()
                    .rev()
                    .find(|s| s.id == first_setting.id)
                    .map(|s| s.value);

                if let Some(last_val) = last_value {
                    if known.validate_value(last_val) {
                        if let Some(&applied_value) = parser.applied_settings.get(&known) {
                            assert_eq!(
                                applied_value, last_val,
                                "Duplicate setting should use last value: expected {}, got {}",
                                last_val, applied_value
                            );
                        }
                    }
                }
            }
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mixed_known_unknown_settings() {
        let input = FuzzInput {
            settings: vec![
                SettingEntry { id: 3, value: 100 }, // MAX_CONCURRENT_STREAMS (known)
                SettingEntry { id: 99, value: 42 }, // Unknown setting
                SettingEntry { id: 2, value: 0 },   // ENABLE_PUSH (known)
                SettingEntry {
                    id: 255,
                    value: 123,
                }, // Unknown setting
            ],
            flags: 0,
            stream_id: 0,
        };

        let mut parser = MockH2SettingsParser::new();
        assert!(parser.parse_settings_frame(&input).is_ok());

        // Should apply 2 known settings, ignore 2 unknown
        assert_eq!(parser.applied_settings.len(), 2);
        assert_eq!(parser.unknown_count, 2);

        // Check specific values
        assert_eq!(
            parser
                .applied_settings
                .get(&KnownSetting::MaxConcurrentStreams),
            Some(&100)
        );
        assert_eq!(
            parser.applied_settings.get(&KnownSetting::EnablePush),
            Some(&0)
        );
    }

    #[test]
    fn test_unknown_settings_only() {
        let input = FuzzInput {
            settings: vec![
                SettingEntry { id: 7, value: 1000 }, // Unknown
                SettingEntry {
                    id: 99,
                    value: 2000,
                }, // Unknown
                SettingEntry {
                    id: 255,
                    value: 3000,
                }, // Unknown
            ],
            flags: 0,
            stream_id: 0,
        };

        let mut parser = MockH2SettingsParser::new();
        assert!(parser.parse_settings_frame(&input).is_ok());

        // No known settings applied, all unknown ignored
        assert_eq!(parser.applied_settings.len(), 0);
        assert_eq!(parser.unknown_count, 3);
    }

    #[test]
    fn test_duplicate_known_settings() {
        let input = FuzzInput {
            settings: vec![
                SettingEntry { id: 4, value: 1000 }, // INITIAL_WINDOW_SIZE
                SettingEntry { id: 99, value: 42 },  // Unknown
                SettingEntry { id: 4, value: 2000 }, // INITIAL_WINDOW_SIZE (duplicate)
            ],
            flags: 0,
            stream_id: 0,
        };

        let mut parser = MockH2SettingsParser::new();
        assert!(parser.parse_settings_frame(&input).is_ok());

        // Last value should win
        assert_eq!(
            parser
                .applied_settings
                .get(&KnownSetting::InitialWindowSize),
            Some(&2000)
        );
        assert_eq!(parser.unknown_count, 1);
    }

    #[test]
    fn test_invalid_known_setting_value() {
        let input = FuzzInput {
            settings: vec![
                SettingEntry { id: 2, value: 5 }, // ENABLE_PUSH with invalid value (must be 0 or 1)
                SettingEntry { id: 99, value: 42 }, // Unknown (should still be ignored)
            ],
            flags: 0,
            stream_id: 0,
        };

        let mut parser = MockH2SettingsParser::new();
        assert!(parser.parse_settings_frame(&input).is_ok());

        // Invalid setting should not be applied, but unknown still ignored
        assert_eq!(parser.applied_settings.len(), 0);
        assert_eq!(parser.unknown_count, 1);
        assert!(!parser.errors.is_empty());
    }

    #[test]
    fn test_frame_validation_errors() {
        // Test non-zero flags
        let input = FuzzInput {
            settings: vec![SettingEntry { id: 1, value: 1000 }],
            flags: 1, // Invalid for data SETTINGS frame
            stream_id: 0,
        };

        let mut parser = MockH2SettingsParser::new();
        assert!(parser.parse_settings_frame(&input).is_err());

        // Test non-zero stream ID
        let input = FuzzInput {
            settings: vec![SettingEntry { id: 1, value: 1000 }],
            flags: 0,
            stream_id: 1, // Invalid for SETTINGS frame
        };

        let mut parser = MockH2SettingsParser::new();
        assert!(parser.parse_settings_frame(&input).is_err());
    }

    #[test]
    fn test_ordering_independence() {
        let input1 = FuzzInput {
            settings: vec![
                SettingEntry { id: 1, value: 1000 }, // HEADER_TABLE_SIZE
                SettingEntry { id: 99, value: 42 },  // Unknown
                SettingEntry { id: 3, value: 100 },  // MAX_CONCURRENT_STREAMS
            ],
            flags: 0,
            stream_id: 0,
        };

        let input2 = FuzzInput {
            settings: vec![
                SettingEntry { id: 3, value: 100 },  // MAX_CONCURRENT_STREAMS
                SettingEntry { id: 99, value: 42 },  // Unknown
                SettingEntry { id: 1, value: 1000 }, // HEADER_TABLE_SIZE
            ],
            flags: 0,
            stream_id: 0,
        };

        let mut parser1 = MockH2SettingsParser::new();
        let mut parser2 = MockH2SettingsParser::new();

        assert!(parser1.parse_settings_frame(&input1).is_ok());
        assert!(parser2.parse_settings_frame(&input2).is_ok());

        // Results should be identical
        assert_eq!(parser1.applied_settings, parser2.applied_settings);
        assert_eq!(parser1.unknown_count, parser2.unknown_count);
    }

    #[test]
    fn test_empty_settings_frame() {
        let input = FuzzInput {
            settings: vec![], // Empty settings
            flags: 0,
            stream_id: 0,
        };

        let mut parser = MockH2SettingsParser::new();
        assert!(parser.parse_settings_frame(&input).is_ok());

        assert_eq!(parser.applied_settings.len(), 0);
        assert_eq!(parser.unknown_count, 0);
    }

    #[test]
    fn test_all_known_settings() {
        let input = FuzzInput {
            settings: vec![
                SettingEntry { id: 1, value: 4096 }, // HEADER_TABLE_SIZE
                SettingEntry { id: 2, value: 1 },    // ENABLE_PUSH
                SettingEntry { id: 3, value: 1000 }, // MAX_CONCURRENT_STREAMS
                SettingEntry {
                    id: 4,
                    value: 65536,
                }, // INITIAL_WINDOW_SIZE
                SettingEntry {
                    id: 5,
                    value: 32768,
                }, // MAX_FRAME_SIZE
                SettingEntry { id: 6, value: 8192 }, // MAX_HEADER_LIST_SIZE
            ],
            flags: 0,
            stream_id: 0,
        };

        let mut parser = MockH2SettingsParser::new();
        assert!(parser.parse_settings_frame(&input).is_ok());

        // All 6 known settings should be applied
        assert_eq!(parser.applied_settings.len(), 6);
        assert_eq!(parser.unknown_count, 0);
    }
}
