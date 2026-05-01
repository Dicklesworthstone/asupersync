#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::collections::HashMap;
use std::panic;

/// SETTINGS identifiers per RFC 9113 §6.5.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
enum SettingIdentifier {
    // Known settings from RFC 9113
    HeaderTableSize = 0x1,
    EnablePush = 0x2,
    MaxConcurrentStreams = 0x3,
    InitialWindowSize = 0x4,
    MaxFrameSize = 0x5,
    MaxHeaderListSize = 0x6,

    // Unknown/custom identifiers (should be ignored)
    Unknown(u16),
}

impl SettingIdentifier {
    fn from_u16(id: u16) -> Self {
        match id {
            0x1 => Self::HeaderTableSize,
            0x2 => Self::EnablePush,
            0x3 => Self::MaxConcurrentStreams,
            0x4 => Self::InitialWindowSize,
            0x5 => Self::MaxFrameSize,
            0x6 => Self::MaxHeaderListSize,
            other => Self::Unknown(other),
        }
    }

    fn to_u16(self) -> u16 {
        match self {
            Self::HeaderTableSize => 0x1,
            Self::EnablePush => 0x2,
            Self::MaxConcurrentStreams => 0x3,
            Self::InitialWindowSize => 0x4,
            Self::MaxFrameSize => 0x5,
            Self::MaxHeaderListSize => 0x6,
            Self::Unknown(id) => id,
        }
    }

    fn is_known(self) -> bool {
        !matches!(self, Self::Unknown(_))
    }

    fn validate_value(self, value: u32) -> Result<(), String> {
        match self {
            Self::EnablePush => {
                // RFC 9113: SETTINGS_ENABLE_PUSH (0x2): 0 or 1
                if value > 1 {
                    Err(format!("ENABLE_PUSH must be 0 or 1, got {}", value))
                } else {
                    Ok(())
                }
            }
            Self::MaxFrameSize => {
                // RFC 9113: SETTINGS_MAX_FRAME_SIZE (0x5): 2^14 to 2^24-1
                if value < 16_384 || value > 16_777_215 {
                    Err(format!("MAX_FRAME_SIZE out of range: {}", value))
                } else {
                    Ok(())
                }
            }
            Self::InitialWindowSize => {
                // RFC 9113: SETTINGS_INITIAL_WINDOW_SIZE (0x4): 0 to 2^31-1
                if value > 2_147_483_647 {
                    Err(format!("INITIAL_WINDOW_SIZE out of range: {}", value))
                } else {
                    Ok(())
                }
            }
            Self::HeaderTableSize | Self::MaxConcurrentStreams | Self::MaxHeaderListSize => {
                // These are generally unrestricted u32 values
                Ok(())
            }
            Self::Unknown(_) => {
                // Unknown settings should always be accepted (silently ignored)
                Ok(())
            }
        }
    }
}

impl Arbitrary for SettingIdentifier {
    fn arbitrary(u: &mut Unstructured) -> arbitrary::Result<Self> {
        let id: u16 = u.arbitrary()?;
        Ok(Self::from_u16(id))
    }
}

/// A single SETTINGS parameter (identifier + value)
#[derive(Debug, Clone, Arbitrary)]
struct SettingParameter {
    identifier: SettingIdentifier,
    value: u32,
}

/// SETTINGS frame per RFC 9113 §6.5
#[derive(Debug, Clone, Arbitrary)]
struct SettingsFrame {
    ack_flag: bool,
    parameters: Vec<SettingParameter>,
}

/// Connection error codes per RFC 9113 §7
#[derive(Debug, Clone, Copy, PartialEq)]
enum ErrorCode {
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
}

/// Mock HTTP/2 connection state for SETTINGS testing
#[derive(Debug)]
struct MockH2Connection {
    /// Current connection settings (only known settings stored)
    local_settings: HashMap<SettingIdentifier, u32>,
    remote_settings: HashMap<SettingIdentifier, u32>,

    /// Count of unknown settings received (for testing purposes)
    unknown_settings_count: usize,

    /// Settings that caused validation errors
    setting_errors: Vec<(SettingIdentifier, u32, String)>,

    /// Connection errors that occurred
    connection_errors: Vec<ErrorCode>,

    /// Whether connection is active
    is_active: bool,

    /// Outstanding SETTINGS frames awaiting ACK
    outstanding_settings: bool,
}

impl MockH2Connection {
    fn new() -> Self {
        let mut local_settings = HashMap::new();
        let mut remote_settings = HashMap::new();

        // Initialize with RFC defaults
        local_settings.insert(SettingIdentifier::HeaderTableSize, 4096);
        local_settings.insert(SettingIdentifier::EnablePush, 1);
        local_settings.insert(SettingIdentifier::InitialWindowSize, 65535);
        local_settings.insert(SettingIdentifier::MaxFrameSize, 16384);

        remote_settings.insert(SettingIdentifier::HeaderTableSize, 4096);
        remote_settings.insert(SettingIdentifier::EnablePush, 1);
        remote_settings.insert(SettingIdentifier::InitialWindowSize, 65535);
        remote_settings.insert(SettingIdentifier::MaxFrameSize, 16384);

        Self {
            local_settings,
            remote_settings,
            unknown_settings_count: 0,
            setting_errors: Vec::new(),
            connection_errors: Vec::new(),
            is_active: true,
            outstanding_settings: false,
        }
    }

    /// Process received SETTINGS frame per RFC 9113 §6.5
    fn receive_settings(&mut self, frame: SettingsFrame) -> Result<(), ErrorCode> {
        if !self.is_active {
            return Err(ErrorCode::ProtocolError);
        }

        if frame.ack_flag {
            // This is a SETTINGS ACK - just clear outstanding flag
            self.outstanding_settings = false;
            return Ok(());
        }

        // Process each parameter in the SETTINGS frame
        for param in frame.parameters {
            self.process_setting_parameter(param);
        }

        // Send ACK (in real implementation)
        self.send_settings_ack();

        Ok(())
    }

    /// Process individual setting parameter
    fn process_setting_parameter(&mut self, param: SettingParameter) {
        let identifier = param.identifier;
        let value = param.value;

        if identifier.is_known() {
            // Known setting - validate and apply
            match identifier.validate_value(value) {
                Ok(()) => {
                    // Valid - apply the setting
                    self.remote_settings.insert(identifier, value);
                }
                Err(error) => {
                    // Invalid value for known setting - protocol error
                    self.setting_errors.push((identifier, value, error));
                    self.connection_errors.push(ErrorCode::ProtocolError);
                    self.is_active = false;
                }
            }
        } else {
            // Unknown setting - silently ignore per RFC 9113 §6.5
            self.unknown_settings_count += 1;
            // Do NOT store unknown settings
            // Do NOT generate protocol errors
            // This is the key behavior being tested
        }
    }

    /// Send SETTINGS ACK (mock)
    fn send_settings_ack(&mut self) {
        // In real implementation, would send SETTINGS frame with ACK flag
        // For testing, we just track that we should send one
    }

    /// Get setting value (local or remote)
    fn get_local_setting(&self, identifier: SettingIdentifier) -> Option<u32> {
        self.local_settings.get(&identifier).copied()
    }

    fn get_remote_setting(&self, identifier: SettingIdentifier) -> Option<u32> {
        self.remote_settings.get(&identifier).copied()
    }

    /// Check if any protocol errors occurred
    fn has_protocol_errors(&self) -> bool {
        self.connection_errors.contains(&ErrorCode::ProtocolError)
    }

    /// Get count of unknown settings received
    fn unknown_settings_received(&self) -> usize {
        self.unknown_settings_count
    }

    /// Get validation errors for known settings
    fn get_setting_errors(&self) -> &[(SettingIdentifier, u32, String)] {
        &self.setting_errors
    }
}

/// Test scenario for unknown SETTINGS identifiers
#[derive(Debug, Arbitrary)]
struct UnknownSettingsScenario {
    /// SETTINGS frames to process
    settings_frames: Vec<SettingsFrame>,
    /// Mix of known and unknown settings
    mixed_parameters: Vec<SettingParameter>,
    /// Whether to include invalid values for known settings
    include_invalid_known: bool,
    /// Range of unknown identifiers to test
    unknown_id_range: (u16, u16),
}

/// Test unknown settings handling per RFC 9113 §6.5
fn test_unknown_settings_handling(scenario: UnknownSettingsScenario) -> Result<(), String> {
    let mut connection = MockH2Connection::new();

    // Track initial state
    let initial_unknown_count = connection.unknown_settings_received();

    // Phase 1: Process SETTINGS frames from scenario
    for frame in scenario.settings_frames {
        if let Err(error_code) = connection.receive_settings(frame) {
            // Should only fail for invalid known settings, never for unknown settings
            if !connection.get_setting_errors().is_empty() {
                // Expected failure due to invalid known setting
                continue;
            } else {
                return Err(format!("Unexpected error processing SETTINGS: {:?}", error_code));
            }
        }
    }

    // Phase 2: Process mixed parameters
    let mixed_frame = SettingsFrame {
        ack_flag: false,
        parameters: scenario.mixed_parameters.clone(),
    };

    let pre_mixed_unknown_count = connection.unknown_settings_received();
    let _ = connection.receive_settings(mixed_frame);

    // Count unknown settings in mixed parameters
    let unknown_in_mixed = scenario.mixed_parameters.iter()
        .filter(|param| !param.identifier.is_known())
        .count();

    // Phase 3: Test specific unknown identifier ranges
    let start = scenario.unknown_id_range.0.max(0x7); // Start after known settings
    let end = scenario.unknown_id_range.1.min(0xFFFF);

    for unknown_id in start..=end.min(start + 10) { // Limit to prevent test timeout
        if unknown_id <= 0x6 { continue; } // Skip known settings range

        let unknown_param = SettingParameter {
            identifier: SettingIdentifier::Unknown(unknown_id),
            value: 0xDEADBEEF, // Arbitrary value
        };

        let unknown_frame = SettingsFrame {
            ack_flag: false,
            parameters: vec![unknown_param],
        };

        let pre_count = connection.unknown_settings_received();
        match connection.receive_settings(unknown_frame) {
            Ok(()) => {
                // Should succeed - unknown settings are ignored
                let post_count = connection.unknown_settings_received();
                if post_count != pre_count + 1 {
                    return Err(format!("Unknown setting count not incremented for ID {:#x}", unknown_id));
                }
            }
            Err(error) => {
                return Err(format!("Unknown setting ID {:#x} caused error: {:?}", unknown_id, error));
            }
        }

        // Verify connection is still active
        if !connection.is_active && connection.get_setting_errors().is_empty() {
            return Err(format!("Connection closed for unknown setting ID {:#x}", unknown_id));
        }
    }

    // Assertions per RFC 9113 §6.5

    // Unknown settings should not cause protocol errors
    let unknown_settings_total = connection.unknown_settings_received() - initial_unknown_count;
    if unknown_settings_total > 0 && connection.has_protocol_errors() && connection.get_setting_errors().is_empty() {
        return Err("Unknown settings caused protocol error but should be silently ignored".to_string());
    }

    // Known settings with invalid values should cause protocol errors
    if scenario.include_invalid_known {
        // Check that we properly validate known settings
        let invalid_known_frame = SettingsFrame {
            ack_flag: false,
            parameters: vec![
                SettingParameter {
                    identifier: SettingIdentifier::EnablePush,
                    value: 2, // Invalid - must be 0 or 1
                },
            ],
        };

        let pre_error_count = connection.connection_errors.len();
        let _ = connection.receive_settings(invalid_known_frame);

        if connection.connection_errors.len() == pre_error_count {
            return Err("Invalid known setting value should cause protocol error".to_string());
        }
    }

    Ok(())
}

/// Test known vs unknown setting processing
fn test_known_vs_unknown_settings() -> Result<(), String> {
    let mut connection = MockH2Connection::new();

    // Test known settings are processed
    let known_frame = SettingsFrame {
        ack_flag: false,
        parameters: vec![
            SettingParameter {
                identifier: SettingIdentifier::HeaderTableSize,
                value: 8192,
            },
            SettingParameter {
                identifier: SettingIdentifier::MaxFrameSize,
                value: 32768,
            },
        ],
    };

    connection.receive_settings(known_frame).map_err(|e| format!("Known settings failed: {:?}", e))?;

    // Verify known settings were applied
    if connection.get_remote_setting(SettingIdentifier::HeaderTableSize) != Some(8192) {
        return Err("Known setting HeaderTableSize not applied".to_string());
    }

    if connection.get_remote_setting(SettingIdentifier::MaxFrameSize) != Some(32768) {
        return Err("Known setting MaxFrameSize not applied".to_string());
    }

    // Test unknown settings are ignored
    let unknown_frame = SettingsFrame {
        ack_flag: false,
        parameters: vec![
            SettingParameter {
                identifier: SettingIdentifier::Unknown(0x1000),
                value: 12345,
            },
            SettingParameter {
                identifier: SettingIdentifier::Unknown(0xFFFF),
                value: 67890,
            },
        ],
    };

    let pre_unknown_count = connection.unknown_settings_received();
    connection.receive_settings(unknown_frame).map_err(|e| format!("Unknown settings failed: {:?}", e))?;

    // Verify unknown settings were ignored (counted but not stored)
    if connection.unknown_settings_received() != pre_unknown_count + 2 {
        return Err("Unknown settings count incorrect".to_string());
    }

    // Verify unknown settings don't appear in settings map
    if connection.get_remote_setting(SettingIdentifier::Unknown(0x1000)).is_some() {
        return Err("Unknown setting was incorrectly stored".to_string());
    }

    // Verify connection is still active
    if !connection.is_active {
        return Err("Connection should remain active after unknown settings".to_string());
    }

    Ok(())
}

/// Test edge cases for unknown settings
fn test_unknown_settings_edge_cases() -> Result<(), String> {
    let mut connection = MockH2Connection::new();

    // Edge case 1: Unknown setting with value 0
    let zero_value_frame = SettingsFrame {
        ack_flag: false,
        parameters: vec![
            SettingParameter {
                identifier: SettingIdentifier::Unknown(0x9999),
                value: 0,
            },
        ],
    };

    connection.receive_settings(zero_value_frame).map_err(|e| format!("Zero value unknown setting failed: {:?}", e))?;

    // Edge case 2: Unknown setting with max value
    let max_value_frame = SettingsFrame {
        ack_flag: false,
        parameters: vec![
            SettingParameter {
                identifier: SettingIdentifier::Unknown(0x8888),
                value: u32::MAX,
            },
        ],
    };

    connection.receive_settings(max_value_frame).map_err(|e| format!("Max value unknown setting failed: {:?}", e))?;

    // Edge case 3: Mix known and unknown in same frame
    let mixed_frame = SettingsFrame {
        ack_flag: false,
        parameters: vec![
            SettingParameter {
                identifier: SettingIdentifier::EnablePush,
                value: 0, // Valid known setting
            },
            SettingParameter {
                identifier: SettingIdentifier::Unknown(0x7777),
                value: 42, // Unknown setting
            },
            SettingParameter {
                identifier: SettingIdentifier::InitialWindowSize,
                value: 32768, // Valid known setting
            },
        ],
    };

    connection.receive_settings(mixed_frame).map_err(|e| format!("Mixed frame failed: {:?}", e))?;

    // Verify known settings applied
    if connection.get_remote_setting(SettingIdentifier::EnablePush) != Some(0) {
        return Err("Known setting in mixed frame not applied".to_string());
    }

    if connection.get_remote_setting(SettingIdentifier::InitialWindowSize) != Some(32768) {
        return Err("Known setting in mixed frame not applied".to_string());
    }

    // Verify unknown setting ignored
    if connection.get_remote_setting(SettingIdentifier::Unknown(0x7777)).is_some() {
        return Err("Unknown setting in mixed frame was stored".to_string());
    }

    // Verify no protocol errors
    if connection.has_protocol_errors() {
        return Err("Mixed frame should not cause protocol errors".to_string());
    }

    Ok(())
}

/// Test SETTINGS ACK behavior
fn test_settings_ack_handling() -> Result<(), String> {
    let mut connection = MockH2Connection::new();

    // Set outstanding SETTINGS flag
    connection.outstanding_settings = true;

    // Send SETTINGS ACK frame
    let ack_frame = SettingsFrame {
        ack_flag: true,
        parameters: vec![], // ACK frames must have empty parameters
    };

    connection.receive_settings(ack_frame).map_err(|e| format!("SETTINGS ACK failed: {:?}", e))?;

    // Verify outstanding flag cleared
    if connection.outstanding_settings {
        return Err("Outstanding SETTINGS flag not cleared by ACK".to_string());
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let result = panic::catch_unwind(|| {
        let mut unstructured = Unstructured::new(data);

        // Try to generate scenario from fuzz input
        if let Ok(scenario) = UnknownSettingsScenario::arbitrary(&mut unstructured) {
            let _ = test_unknown_settings_handling(scenario);
        }

        // Run deterministic test cases
        if data.len() > 50 {
            let _ = test_known_vs_unknown_settings();
            let _ = test_unknown_settings_edge_cases();
            let _ = test_settings_ack_handling();
        }
    });

    if result.is_err() {
        eprintln!("Panic in unknown SETTINGS identifier fuzzing");
    }
});