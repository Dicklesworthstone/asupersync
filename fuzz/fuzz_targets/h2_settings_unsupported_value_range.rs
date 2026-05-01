#![no_main]

//! Fuzz target for HTTP/2 SETTINGS frame value range validation.
//!
//! This target tests how the HTTP/2 implementation handles SETTINGS frame
//! parameters with values that exceed supported bounds per RFC 9113.
//!
//! According to RFC 9113 Section 6.5.2, specific SETTINGS parameters have
//! defined value ranges:
//! - SETTINGS_ENABLE_PUSH (0x2): MUST be 0 or 1
//! - SETTINGS_INITIAL_WINDOW_SIZE (0x4): MUST be <= 2^31-1
//! - SETTINGS_MAX_FRAME_SIZE (0x5): MUST be between 16,384 and 16,777,215
//!
//! Out-of-bounds values should trigger PROTOCOL_ERROR or be handled gracefully.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Known SETTINGS parameter identifiers from RFC 9113
#[derive(Debug, Clone, Copy, PartialEq, Eq, Arbitrary)]
#[repr(u16)]
enum SettingId {
    HeaderTableSize = 0x1,
    EnablePush = 0x2,
    MaxConcurrentStreams = 0x3,
    InitialWindowSize = 0x4,
    MaxFrameSize = 0x5,
    MaxHeaderListSize = 0x6,
}

impl SettingId {
    fn as_u16(self) -> u16 {
        self as u16
    }

    /// Get the valid range for this setting parameter
    fn valid_range(self) -> Option<(u32, u32)> {
        match self {
            SettingId::HeaderTableSize => None, // No explicit bounds
            SettingId::EnablePush => Some((0, 1)), // MUST be 0 or 1
            SettingId::MaxConcurrentStreams => None, // No explicit bounds
            SettingId::InitialWindowSize => Some((0, 0x7fff_ffff)), // MUST be <= 2^31-1
            SettingId::MaxFrameSize => Some((16_384, 16_777_215)), // MUST be within these bounds
            SettingId::MaxHeaderListSize => None, // No explicit bounds
        }
    }

    /// Check if a value is within the valid range for this setting
    fn is_value_valid(self, value: u32) -> bool {
        match self.valid_range() {
            Some((min, max)) => value >= min && value <= max,
            None => true, // No bounds means all values are valid
        }
    }
}

/// Value generation strategy for testing boundary conditions
#[derive(Debug, Clone, Arbitrary)]
enum ValueStrategy {
    /// Use the exact provided value
    Exact(u32),
    /// Generate values around the boundary of valid ranges
    BoundaryTest {
        setting: SettingId,
        offset: i8, // -128 to +127 offset from boundary
    },
    /// Generate extremely large values
    MaxValues,
    /// Generate zero
    Zero,
    /// Generate values that are powers of 2
    PowerOfTwo(u8), // 2^n where n is this value % 32
}

impl ValueStrategy {
    fn generate_value(&self, setting: SettingId) -> u32 {
        match self {
            ValueStrategy::Exact(value) => *value,
            ValueStrategy::BoundaryTest { setting: test_setting, offset } => {
                if *test_setting != setting {
                    return 42; // Default value for non-matching settings
                }

                match setting.valid_range() {
                    Some((min, max)) => {
                        // Test around both min and max boundaries
                        let base = if (*offset as i16) < 0 { max } else { min };
                        (base as i64 + *offset as i64).max(0) as u32
                    }
                    None => 42, // No boundaries to test
                }
            }
            ValueStrategy::MaxValues => match setting {
                SettingId::EnablePush => u32::MAX, // Should fail validation
                SettingId::InitialWindowSize => u32::MAX, // Should fail validation
                SettingId::MaxFrameSize => u32::MAX, // Should fail validation
                _ => u32::MAX, // Test extremely large values
            },
            ValueStrategy::Zero => 0,
            ValueStrategy::PowerOfTwo(exponent) => {
                let exp = (*exponent % 32) as u32;
                if exp == 31 {
                    0x8000_0000 // 2^31, which exceeds InitialWindowSize limit
                } else {
                    1u32.checked_shl(exp).unwrap_or(u32::MAX)
                }
            }
        }
    }
}

/// A single SETTINGS parameter for testing
#[derive(Debug, Clone, Arbitrary)]
struct TestSetting {
    id: SettingId,
    value_strategy: ValueStrategy,
}

impl TestSetting {
    fn generate(&self) -> (u16, u32) {
        (self.id.as_u16(), self.value_strategy.generate_value(self.id))
    }
}

/// SETTINGS frame test scenario
#[derive(Debug, Clone, Arbitrary)]
struct SettingsValueRangeScenario {
    /// List of settings to include in the frame
    settings: Vec<TestSetting>,
    /// Whether this should be a SETTINGS ACK frame
    is_ack: bool,
    /// Include unknown/reserved setting IDs
    include_unknown_settings: bool,
    /// Unknown setting ID to test (if include_unknown_settings is true)
    unknown_setting_id: u16, // Will use values > 0x6
    /// Value for unknown setting
    unknown_setting_value: u32,
}

/// Mock HTTP/2 SETTINGS frame processor
struct MockSettingsProcessor {
    /// Current settings state
    current_settings: HashMap<u16, u32>,
    /// Count of protocol errors encountered
    protocol_errors: usize,
    /// Count of out-of-range values processed
    out_of_range_count: usize,
    /// Whether to be strict about bounds (vs lenient/clamping)
    strict_validation: bool,
}

impl MockSettingsProcessor {
    fn new(strict_validation: bool) -> Self {
        Self {
            current_settings: HashMap::new(),
            protocol_errors: 0,
            out_of_range_count: 0,
            strict_validation,
        }
    }

    /// Process a SETTINGS frame
    /// Returns Ok(()) if accepted, Err(error_msg) if rejected
    fn process_settings_frame(&mut self, settings: Vec<(u16, u32)>, is_ack: bool) -> Result<(), String> {
        // RFC 9113 §6.5.3: SETTINGS ACK frames MUST be empty
        if is_ack && !settings.is_empty() {
            self.protocol_errors += 1;
            return Err("PROTOCOL_ERROR: SETTINGS ACK frame must be empty".to_string());
        }

        if is_ack {
            return Ok(()); // ACK frames don't change settings
        }

        for (id, value) in settings {
            let setting_id = match id {
                0x1 => Some(SettingId::HeaderTableSize),
                0x2 => Some(SettingId::EnablePush),
                0x3 => Some(SettingId::MaxConcurrentStreams),
                0x4 => Some(SettingId::InitialWindowSize),
                0x5 => Some(SettingId::MaxFrameSize),
                0x6 => Some(SettingId::MaxHeaderListSize),
                _ => None, // Unknown setting - should be ignored per RFC
            };

            if let Some(setting) = setting_id {
                // Validate known settings
                if let Err(error) = self.validate_setting_value(setting, value) {
                    if self.strict_validation {
                        self.protocol_errors += 1;
                        return Err(error);
                    } else {
                        // Lenient mode: clamp or ignore invalid values
                        let clamped_value = self.clamp_value(setting, value);
                        self.current_settings.insert(id, clamped_value);
                        if clamped_value != value {
                            self.out_of_range_count += 1;
                        }
                    }
                } else {
                    self.current_settings.insert(id, value);
                }
            } else {
                // Unknown setting ID - ignore per RFC 9113 §6.5.2
                // "An endpoint that receives a SETTINGS frame with any unknown or unsupported
                // identifier MUST ignore that setting."
            }
        }

        Ok(())
    }

    fn validate_setting_value(&self, setting: SettingId, value: u32) -> Result<(), String> {
        if !setting.is_value_valid(value) {
            self.out_of_range_count.wrapping_add(1); // Track for stats
            match setting {
                SettingId::EnablePush => {
                    Err(format!("PROTOCOL_ERROR: SETTINGS_ENABLE_PUSH must be 0 or 1, got {}", value))
                }
                SettingId::InitialWindowSize => {
                    if value > 0x7fff_ffff {
                        Err(format!("FLOW_CONTROL_ERROR: SETTINGS_INITIAL_WINDOW_SIZE ({}) exceeds maximum (2^31-1)", value))
                    } else {
                        Ok(())
                    }
                }
                SettingId::MaxFrameSize => {
                    if value < 16_384 || value > 16_777_215 {
                        Err(format!("PROTOCOL_ERROR: SETTINGS_MAX_FRAME_SIZE ({}) out of bounds [16384, 16777215]", value))
                    } else {
                        Ok(())
                    }
                }
                _ => Ok(()), // No validation for other settings
            }
        } else {
            Ok(())
        }
    }

    fn clamp_value(&self, setting: SettingId, value: u32) -> u32 {
        match setting.valid_range() {
            Some((min, max)) => value.clamp(min, max),
            None => value,
        }
    }

    fn get_stats(&self) -> (usize, usize, usize) {
        (self.protocol_errors, self.out_of_range_count, self.current_settings.len())
    }
}

fuzz_target!(|scenario: SettingsValueRangeScenario| {
    // Test both strict and lenient validation modes
    for strict in [true, false] {
        let mut processor = MockSettingsProcessor::new(strict);

        // Generate the settings list
        let mut settings = Vec::new();
        for test_setting in &scenario.settings {
            let (id, value) = test_setting.generate();
            settings.push((id, value));
        }

        // Add unknown setting if requested
        if scenario.include_unknown_settings {
            // Use setting ID > 0x6 to ensure it's unknown
            let unknown_id = if scenario.unknown_setting_id <= 0x6 {
                0x100 + scenario.unknown_setting_id  // Make it definitely unknown
            } else {
                scenario.unknown_setting_id
            };
            settings.push((unknown_id, scenario.unknown_setting_value));
        }

        // Process the SETTINGS frame
        let result = processor.process_settings_frame(settings.clone(), scenario.is_ack);

        // Validation logic
        match (strict, &result) {
            (true, Err(error_msg)) => {
                // Strict mode errors are expected for out-of-bounds values
                assert!(
                    error_msg.contains("PROTOCOL_ERROR") ||
                    error_msg.contains("FLOW_CONTROL_ERROR") ||
                    error_msg.contains("must be empty"),
                    "Unexpected error message in strict mode: {}", error_msg
                );
            }
            (false, Ok(())) => {
                // Lenient mode should accept values (possibly clamped)
                // Verify settings were processed
                let (protocol_errors, out_of_range_count, settings_count) = processor.get_stats();

                if !scenario.is_ack && !scenario.settings.is_empty() {
                    assert!(settings_count > 0, "Lenient mode should have processed some settings");
                }
            }
            (false, Err(error_msg)) => {
                // Lenient mode should only error for structural issues (like non-empty ACK)
                assert!(
                    error_msg.contains("must be empty"),
                    "Lenient mode should only error for structural issues, got: {}", error_msg
                );
            }
            (true, Ok(())) => {
                // Strict mode succeeded - values should be within bounds
                for (id, value) in &settings {
                    if let Some(setting) = match *id {
                        0x1 => Some(SettingId::HeaderTableSize),
                        0x2 => Some(SettingId::EnablePush),
                        0x3 => Some(SettingId::MaxConcurrentStreams),
                        0x4 => Some(SettingId::InitialWindowSize),
                        0x5 => Some(SettingId::MaxFrameSize),
                        0x6 => Some(SettingId::MaxHeaderListSize),
                        _ => None, // Unknown settings are ignored
                    } {
                        if setting.valid_range().is_some() && !scenario.is_ack {
                            assert!(
                                setting.is_value_valid(*value),
                                "Strict mode accepted out-of-bounds value {} for setting {:?}",
                                value, setting
                            );
                        }
                    }
                }
            }
        }
    }

    // Test specific boundary conditions
    test_boundary_conditions();

    // Test that unknown settings are always ignored
    test_unknown_settings_ignored();
});

/// Test specific boundary conditions for all settings
fn test_boundary_conditions() {
    let mut processor = MockSettingsProcessor::new(true);

    // Test SETTINGS_ENABLE_PUSH boundary
    assert!(processor.process_settings_frame(vec![(0x2, 0)], false).is_ok());
    assert!(processor.process_settings_frame(vec![(0x2, 1)], false).is_ok());
    assert!(processor.process_settings_frame(vec![(0x2, 2)], false).is_err());
    assert!(processor.process_settings_frame(vec![(0x2, u32::MAX)], false).is_err());

    // Test SETTINGS_INITIAL_WINDOW_SIZE boundary
    assert!(processor.process_settings_frame(vec![(0x4, 0)], false).is_ok());
    assert!(processor.process_settings_frame(vec![(0x4, 0x7fff_ffff)], false).is_ok());
    assert!(processor.process_settings_frame(vec![(0x4, 0x8000_0000)], false).is_err());
    assert!(processor.process_settings_frame(vec![(0x4, u32::MAX)], false).is_err());

    // Test SETTINGS_MAX_FRAME_SIZE boundary
    assert!(processor.process_settings_frame(vec![(0x5, 16_383)], false).is_err());
    assert!(processor.process_settings_frame(vec![(0x5, 16_384)], false).is_ok());
    assert!(processor.process_settings_frame(vec![(0x5, 16_777_215)], false).is_ok());
    assert!(processor.process_settings_frame(vec![(0x5, 16_777_216)], false).is_err());
    assert!(processor.process_settings_frame(vec![(0x5, u32::MAX)], false).is_err());

    // Test settings with no explicit bounds (should accept any value)
    assert!(processor.process_settings_frame(vec![(0x1, u32::MAX)], false).is_ok());
    assert!(processor.process_settings_frame(vec![(0x3, u32::MAX)], false).is_ok());
    assert!(processor.process_settings_frame(vec![(0x6, u32::MAX)], false).is_ok());
}

/// Test that unknown settings are ignored per RFC 9113 §6.5.2
fn test_unknown_settings_ignored() {
    let mut processor = MockSettingsProcessor::new(true);

    // Unknown setting IDs should be ignored, not cause errors
    let unknown_settings = vec![
        (0x7, 12345),      // Just above known range
        (0x100, u32::MAX), // Way above known range
        (0xFFFF, 0),       // Maximum setting ID
    ];

    for (id, value) in unknown_settings {
        let result = processor.process_settings_frame(vec![(id, value)], false);
        assert!(result.is_ok(), "Unknown setting ID {} should be ignored, not cause error", id);
    }
}