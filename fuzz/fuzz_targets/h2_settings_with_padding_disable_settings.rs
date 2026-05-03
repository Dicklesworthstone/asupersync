#![no_main]

//! Fuzz target for HTTP/2 SETTINGS_MAX_FRAME_SIZE with invalid values below minimum
//!
//! Tests validation of SETTINGS_MAX_FRAME_SIZE parameter when peer sends values
//! below the RFC 7540 minimum of 16384 bytes. Per RFC 7540 §6.5.2, the valid
//! range for MAX_FRAME_SIZE is 16384 to 2^24-1 (16777215). Values below 16384
//! MUST result in PROTOCOL_ERROR.
//!
//! Key test scenarios:
//! - SETTINGS_MAX_FRAME_SIZE = 8192 (well below minimum)
//! - Values from 1 to 16383 (all invalid)
//! - Boundary testing around 16384 minimum
//! - Values above 2^24-1 maximum (also invalid)
//! - Multiple SETTINGS frames with invalid values

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// RFC 7540 constants for MAX_FRAME_SIZE
const MIN_MAX_FRAME_SIZE: u32 = 16384;      // 2^14 = 16KB minimum
const MAX_MAX_FRAME_SIZE: u32 = 16777215;   // 2^24-1 = ~16MB maximum
const DEFAULT_MAX_FRAME_SIZE: u32 = 16384;  // Default value

/// Mock HTTP/2 connection for testing SETTINGS validation
struct MockSettingsValidationConnection {
    /// Current connection settings
    settings: ConnectionSettings,

    /// Received SETTINGS frames
    settings_received: Vec<SettingsFrame>,

    /// Connection state
    state: ConnectionState,

    /// Statistics tracking
    stats: SettingsStats,

    /// Violation tracking
    violations: Vec<ViolationType>,
}

#[derive(Clone, Debug)]
struct ConnectionSettings {
    max_frame_size: u32,
    header_table_size: u32,
    enable_push: bool,
    max_concurrent_streams: Option<u32>,
    initial_window_size: u32,
    max_header_list_size: Option<u32>,
}

impl Default for ConnectionSettings {
    fn default() -> Self {
        Self {
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            header_table_size: 4096,
            enable_push: true,
            max_concurrent_streams: None,
            initial_window_size: 65535,
            max_header_list_size: None,
        }
    }
}

#[derive(Clone, Debug)]
struct SettingsFrame {
    settings: Vec<Setting>,
    ack: bool,
    validation_result: SettingsValidationResult,
}

#[derive(Clone, Debug)]
struct Setting {
    id: u16,
    value: u32,
}

#[derive(Clone, Debug)]
enum SettingsValidationResult {
    Accepted,
    RejectedProtocolError { reason: String },
    RejectedFlowControlError { reason: String },
}

#[derive(Clone, Debug)]
enum ConnectionState {
    Open,
    Closed { reason: String },
}

#[derive(Default, Clone, Debug)]
struct SettingsStats {
    settings_frames_received: u32,
    settings_ack_frames_received: u32,
    invalid_max_frame_size_count: u32,
    below_minimum_frame_size_count: u32,
    above_maximum_frame_size_count: u32,
    protocol_errors: u32,
    settings_applied: u32,
}

#[derive(Clone, Debug)]
enum ViolationType {
    InvalidMaxFrameSizeAccepted,
    BelowMinimumAccepted,
    AboveMaximumAccepted,
    MissingProtocolError,
    InvalidSettingsApplied,
}

impl MockSettingsValidationConnection {
    fn new() -> Self {
        Self {
            settings: ConnectionSettings::default(),
            settings_received: Vec::new(),
            state: ConnectionState::Open,
            stats: SettingsStats::default(),
            violations: Vec::new(),
        }
    }

    /// Process a SETTINGS frame with validation
    fn handle_settings_frame(&mut self, settings: Vec<Setting>, ack: bool) -> Result<(), H2Error> {
        if ack {
            self.stats.settings_ack_frames_received += 1;
            // SETTINGS ACK frames should be empty
            if !settings.is_empty() {
                return Err(H2Error::ProtocolError("SETTINGS ACK must be empty".to_string()));
            }
            return Ok(());
        }

        self.stats.settings_frames_received += 1;

        // Validate each setting before applying any
        for setting in &settings {
            self.validate_setting(setting)?;
        }

        // If validation passed, apply the settings
        for setting in &settings {
            self.apply_setting(setting);
        }

        self.stats.settings_applied += 1;

        // Record the frame
        let frame = SettingsFrame {
            settings,
            ack,
            validation_result: SettingsValidationResult::Accepted,
        };
        self.settings_received.push(frame);

        Ok(())
    }

    /// Validate a single setting parameter
    fn validate_setting(&mut self, setting: &Setting) -> Result<(), H2Error> {
        match setting.id {
            1 => self.validate_header_table_size(setting.value),
            2 => self.validate_enable_push(setting.value),
            3 => self.validate_max_concurrent_streams(setting.value),
            4 => self.validate_initial_window_size(setting.value),
            5 => self.validate_max_frame_size(setting.value),
            6 => self.validate_max_header_list_size(setting.value),
            _ => {
                // Unknown settings are ignored per RFC 7540 §6.5.2
                Ok(())
            }
        }
    }

    /// Validate SETTINGS_MAX_FRAME_SIZE (the main focus of this fuzz target)
    fn validate_max_frame_size(&mut self, value: u32) -> Result<(), H2Error> {
        if value < MIN_MAX_FRAME_SIZE {
            self.stats.invalid_max_frame_size_count += 1;
            self.stats.below_minimum_frame_size_count += 1;
            self.stats.protocol_errors += 1;
            self.violations.push(ViolationType::BelowMinimumAccepted);
            return Err(H2Error::ProtocolError(format!(
                "MAX_FRAME_SIZE {} below minimum {}",
                value, MIN_MAX_FRAME_SIZE
            )));
        }

        if value > MAX_MAX_FRAME_SIZE {
            self.stats.invalid_max_frame_size_count += 1;
            self.stats.above_maximum_frame_size_count += 1;
            self.stats.protocol_errors += 1;
            self.violations.push(ViolationType::AboveMaximumAccepted);
            return Err(H2Error::ProtocolError(format!(
                "MAX_FRAME_SIZE {} above maximum {}",
                value, MAX_MAX_FRAME_SIZE
            )));
        }

        Ok(())
    }

    /// Validate SETTINGS_HEADER_TABLE_SIZE
    fn validate_header_table_size(&self, _value: u32) -> Result<(), H2Error> {
        // Any value is valid for header table size
        Ok(())
    }

    /// Validate SETTINGS_ENABLE_PUSH
    fn validate_enable_push(&self, value: u32) -> Result<(), H2Error> {
        if value != 0 && value != 1 {
            return Err(H2Error::ProtocolError(format!(
                "ENABLE_PUSH must be 0 or 1, got {}",
                value
            )));
        }
        Ok(())
    }

    /// Validate SETTINGS_MAX_CONCURRENT_STREAMS
    fn validate_max_concurrent_streams(&self, _value: u32) -> Result<(), H2Error> {
        // Any value is valid for max concurrent streams
        Ok(())
    }

    /// Validate SETTINGS_INITIAL_WINDOW_SIZE
    fn validate_initial_window_size(&self, value: u32) -> Result<(), H2Error> {
        if value > 0x7FFFFFFF {
            return Err(H2Error::FlowControlError(format!(
                "INITIAL_WINDOW_SIZE {} exceeds maximum 2^31-1",
                value
            )));
        }
        Ok(())
    }

    /// Validate SETTINGS_MAX_HEADER_LIST_SIZE
    fn validate_max_header_list_size(&self, _value: u32) -> Result<(), H2Error> {
        // Any value is valid for max header list size
        Ok(())
    }

    /// Apply a validated setting
    fn apply_setting(&mut self, setting: &Setting) {
        match setting.id {
            1 => self.settings.header_table_size = setting.value,
            2 => self.settings.enable_push = setting.value != 0,
            3 => self.settings.max_concurrent_streams = Some(setting.value),
            4 => self.settings.initial_window_size = setting.value,
            5 => self.settings.max_frame_size = setting.value,
            6 => self.settings.max_header_list_size = Some(setting.value),
            _ => {
                // Unknown settings are ignored
            }
        }
    }

    /// Test specific invalid MAX_FRAME_SIZE scenarios
    fn test_invalid_max_frame_size_scenarios(&mut self) -> InvalidFrameSizeTestResult {
        let mut result = InvalidFrameSizeTestResult::default();

        // Test 1: 8192 (well below minimum)
        let settings1 = vec![Setting { id: 5, value: 8192 }];
        match self.handle_settings_frame(settings1, false) {
            Ok(()) => {
                result.test1_incorrectly_accepted = true;
                self.violations.push(ViolationType::InvalidMaxFrameSizeAccepted);
            }
            Err(H2Error::ProtocolError(_)) => result.test1_correctly_rejected = true,
            Err(_) => result.test1_other_error = true,
        }

        // Test 2: 16383 (one below minimum)
        let settings2 = vec![Setting { id: 5, value: 16383 }];
        match self.handle_settings_frame(settings2, false) {
            Ok(()) => {
                result.test2_incorrectly_accepted = true;
                self.violations.push(ViolationType::InvalidMaxFrameSizeAccepted);
            }
            Err(H2Error::ProtocolError(_)) => result.test2_correctly_rejected = true,
            Err(_) => result.test2_other_error = true,
        }

        // Test 3: 16384 (exact minimum, should be accepted)
        let settings3 = vec![Setting { id: 5, value: 16384 }];
        match self.handle_settings_frame(settings3, false) {
            Ok(()) => result.test3_correctly_accepted = true,
            Err(_) => result.test3_incorrectly_rejected = true,
        }

        // Test 4: 1 (far below minimum)
        let settings4 = vec![Setting { id: 5, value: 1 }];
        match self.handle_settings_frame(settings4, false) {
            Ok(()) => {
                result.test4_incorrectly_accepted = true;
                self.violations.push(ViolationType::InvalidMaxFrameSizeAccepted);
            }
            Err(H2Error::ProtocolError(_)) => result.test4_correctly_rejected = true,
            Err(_) => result.test4_other_error = true,
        }

        // Test 5: 16777216 (one above maximum)
        let settings5 = vec![Setting { id: 5, value: 16777216 }];
        match self.handle_settings_frame(settings5, false) {
            Ok(()) => {
                result.test5_incorrectly_accepted = true;
                self.violations.push(ViolationType::InvalidMaxFrameSizeAccepted);
            }
            Err(H2Error::ProtocolError(_)) => result.test5_correctly_rejected = true,
            Err(_) => result.test5_other_error = true,
        }

        result
    }

    /// Validate connection state consistency
    fn validate_state_consistency(&self) -> Vec<String> {
        let mut issues = Vec::new();

        // Check that MAX_FRAME_SIZE is within valid range
        if self.settings.max_frame_size < MIN_MAX_FRAME_SIZE {
            issues.push(format!(
                "MAX_FRAME_SIZE {} below minimum {}",
                self.settings.max_frame_size, MIN_MAX_FRAME_SIZE
            ));
        }

        if self.settings.max_frame_size > MAX_MAX_FRAME_SIZE {
            issues.push(format!(
                "MAX_FRAME_SIZE {} above maximum {}",
                self.settings.max_frame_size, MAX_MAX_FRAME_SIZE
            ));
        }

        // Check that INITIAL_WINDOW_SIZE is within valid range
        if self.settings.initial_window_size > 0x7FFFFFFF {
            issues.push(format!(
                "INITIAL_WINDOW_SIZE {} exceeds maximum",
                self.settings.initial_window_size
            ));
        }

        issues
    }

    /// Get statistics
    fn get_stats(&self) -> &SettingsStats {
        &self.stats
    }

    /// Get violations
    fn get_violations(&self) -> &[ViolationType] {
        &self.violations
    }

    /// Get current settings
    fn get_settings(&self) -> &ConnectionSettings {
        &self.settings
    }
}

#[derive(Default, Clone, Debug)]
struct InvalidFrameSizeTestResult {
    test1_correctly_rejected: bool,
    test1_incorrectly_accepted: bool,
    test1_other_error: bool,
    test2_correctly_rejected: bool,
    test2_incorrectly_accepted: bool,
    test2_other_error: bool,
    test3_correctly_accepted: bool,
    test3_incorrectly_rejected: bool,
    test4_correctly_rejected: bool,
    test4_incorrectly_accepted: bool,
    test4_other_error: bool,
    test5_correctly_rejected: bool,
    test5_incorrectly_accepted: bool,
    test5_other_error: bool,
}

#[derive(Clone, Debug)]
enum H2Error {
    ProtocolError(String),
    FlowControlError(String),
    InternalError(String),
}

/// Fuzz input structure
#[derive(Arbitrary, Debug, Clone)]
struct FuzzInput {
    /// Settings frames to send
    settings_frames: Vec<SettingsFrameInput>,

    /// Whether to run scenario tests
    run_scenario_tests: bool,
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingsFrameInput {
    /// Individual settings in this frame
    settings: Vec<SettingInput>,

    /// Whether this is an ACK frame
    ack: bool,
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingInput {
    /// Setting ID (1-6 for known settings, others ignored)
    id: u16,

    /// Setting value
    value: u32,
}

fuzz_target!(|input: FuzzInput| {
    // Limit input size to prevent excessive resource usage
    if input.settings_frames.len() > 20 {
        return;
    }

    let mut connection = MockSettingsValidationConnection::new();

    // Process settings frames
    for frame_input in input.settings_frames {
        // Limit settings per frame
        if frame_input.settings.len() > 10 {
            continue;
        }

        // Convert to internal format
        let settings: Vec<Setting> = frame_input.settings.into_iter()
            .map(|s| Setting { id: s.id, value: s.value })
            .collect();

        let result = connection.handle_settings_frame(settings, frame_input.ack);

        // Validate specific MAX_FRAME_SIZE behavior
        for setting in &connection.settings_received.last().unwrap_or(&SettingsFrame {
            settings: Vec::new(),
            ack: frame_input.ack,
            validation_result: SettingsValidationResult::Accepted,
        }).settings {
            if setting.id == 5 { // SETTINGS_MAX_FRAME_SIZE
                validate_max_frame_size_result(setting.value, &result);
            }
        }
    }

    // Run specific scenario tests if requested
    if input.run_scenario_tests {
        let scenario_result = connection.test_invalid_max_frame_size_scenarios();
        validate_scenario_results(&scenario_result);
    }

    // Final validations
    let violations = connection.get_violations();
    for violation in violations {
        match violation {
            ViolationType::InvalidMaxFrameSizeAccepted => {
                panic!("CRITICAL: Invalid MAX_FRAME_SIZE was accepted");
            }
            ViolationType::BelowMinimumAccepted => {
                panic!("CRITICAL: MAX_FRAME_SIZE below minimum was accepted");
            }
            ViolationType::AboveMaximumAccepted => {
                panic!("CRITICAL: MAX_FRAME_SIZE above maximum was accepted");
            }
            ViolationType::MissingProtocolError => {
                panic!("CRITICAL: Expected PROTOCOL_ERROR not generated");
            }
            ViolationType::InvalidSettingsApplied => {
                panic!("CRITICAL: Invalid settings were applied to connection");
            }
        }
    }

    // Validate final state consistency
    let consistency_issues = connection.validate_state_consistency();
    if !consistency_issues.is_empty() {
        panic!("Connection state consistency issues: {:?}", consistency_issues);
    }

    // Test edge cases
    test_max_frame_size_edge_cases(&mut connection);
});

/// Validate that MAX_FRAME_SIZE validation worked correctly
fn validate_max_frame_size_result(value: u32, result: &Result<(), H2Error>) {
    if value < MIN_MAX_FRAME_SIZE {
        // Should be rejected with PROTOCOL_ERROR
        match result {
            Ok(()) => {
                panic!("MAX_FRAME_SIZE {} below minimum {} was incorrectly accepted",
                       value, MIN_MAX_FRAME_SIZE);
            }
            Err(H2Error::ProtocolError(_)) => {
                // Expected behavior
            }
            Err(other) => {
                panic!("MAX_FRAME_SIZE {} below minimum should cause PROTOCOL_ERROR, got {:?}",
                       value, other);
            }
        }
    } else if value > MAX_MAX_FRAME_SIZE {
        // Should be rejected with PROTOCOL_ERROR
        match result {
            Ok(()) => {
                panic!("MAX_FRAME_SIZE {} above maximum {} was incorrectly accepted",
                       value, MAX_MAX_FRAME_SIZE);
            }
            Err(H2Error::ProtocolError(_)) => {
                // Expected behavior
            }
            Err(other) => {
                panic!("MAX_FRAME_SIZE {} above maximum should cause PROTOCOL_ERROR, got {:?}",
                       value, other);
            }
        }
    } else {
        // Should be accepted
        match result {
            Ok(()) => {
                // Expected behavior
            }
            Err(err) => {
                panic!("Valid MAX_FRAME_SIZE {} was incorrectly rejected: {:?}",
                       value, err);
            }
        }
    }
}

/// Validate the scenario test results
fn validate_scenario_results(result: &InvalidFrameSizeTestResult) {
    // Test 1: 8192 should be rejected
    assert!(result.test1_correctly_rejected && !result.test1_incorrectly_accepted,
            "8192 MAX_FRAME_SIZE should be rejected");

    // Test 2: 16383 should be rejected
    assert!(result.test2_correctly_rejected && !result.test2_incorrectly_accepted,
            "16383 MAX_FRAME_SIZE should be rejected");

    // Test 3: 16384 should be accepted
    assert!(result.test3_correctly_accepted && !result.test3_incorrectly_rejected,
            "16384 MAX_FRAME_SIZE should be accepted");

    // Test 4: 1 should be rejected
    assert!(result.test4_correctly_rejected && !result.test4_incorrectly_accepted,
            "1 MAX_FRAME_SIZE should be rejected");

    // Test 5: 16777216 should be rejected
    assert!(result.test5_correctly_rejected && !result.test5_incorrectly_accepted,
            "16777216 MAX_FRAME_SIZE should be rejected");
}

/// Test specific edge cases for MAX_FRAME_SIZE validation
fn test_max_frame_size_edge_cases(connection: &mut MockSettingsValidationConnection) {
    let edge_cases = vec![
        (0, false),          // Zero should be rejected
        (1, false),          // Minimum possible value should be rejected
        (8192, false),       // Target test value should be rejected
        (16383, false),      // One below minimum should be rejected
        (16384, true),       // Exact minimum should be accepted
        (16385, true),       // One above minimum should be accepted
        (65536, true),       // Common value should be accepted
        (16777215, true),    // Maximum should be accepted
        (16777216, false),   // One above maximum should be rejected
        (0xFFFFFFFF, false), // Maximum u32 should be rejected
    ];

    for (value, should_accept) in edge_cases {
        let settings = vec![Setting { id: 5, value }];
        let result = connection.handle_settings_frame(settings, false);

        match (result, should_accept) {
            (Ok(()), true) => {
                // Correctly accepted
            }
            (Err(H2Error::ProtocolError(_)), false) => {
                // Correctly rejected
            }
            (Ok(()), false) => {
                panic!("Edge case MAX_FRAME_SIZE {} should be rejected but was accepted", value);
            }
            (Err(err), true) => {
                panic!("Edge case MAX_FRAME_SIZE {} should be accepted but was rejected: {:?}",
                       value, err);
            }
        }
    }

    // Test multiple invalid settings in one frame
    let multiple_invalid = vec![
        Setting { id: 5, value: 8192 },   // Invalid MAX_FRAME_SIZE
        Setting { id: 2, value: 2 },      // Invalid ENABLE_PUSH
    ];

    let result = connection.handle_settings_frame(multiple_invalid, false);
    assert!(result.is_err(), "Frame with multiple invalid settings should be rejected");
}