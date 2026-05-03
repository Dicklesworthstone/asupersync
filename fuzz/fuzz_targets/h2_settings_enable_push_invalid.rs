//! Fuzzing target for HTTP/2 SETTINGS rejection on invalid SETTINGS_ENABLE_PUSH values.
//!
//! Tests RFC 9113 compliance: SETTINGS_ENABLE_PUSH must only accept 0 or 1.
//! Per RFC 9113 §6.5.2, invalid setting values must result in PROTOCOL_ERROR.
//!
//! Security vulnerability: Current implementation accepts any u32 value for
//! SETTINGS_ENABLE_PUSH and converts it to bool via `value != 0`. A malicious
//! peer can send SETTINGS_ENABLE_PUSH=2 and bypass RFC-compliant behavior.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Mock HTTP/2 SETTINGS frame validator for testing RFC 9113 compliance.
#[derive(Debug, Clone)]
pub struct MockSettingsValidator {
    /// RFC 9113 compliance mode
    strict_rfc_compliance: bool,
    /// Track validation violations for fuzzing analysis
    violations: Vec<SettingsViolation>,
}

/// Types of SETTINGS validation violations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsViolation {
    /// SETTINGS_ENABLE_PUSH with invalid value (not 0 or 1)
    InvalidEnablePushValue { actual: u32 },
    /// SETTINGS_INITIAL_WINDOW_SIZE exceeding 2^31-1
    InvalidInitialWindowSize { actual: u32 },
    /// SETTINGS_MAX_FRAME_SIZE outside 16384..16777215 range
    InvalidMaxFrameSize { actual: u32 },
    /// Unknown setting ID (should be ignored, not error)
    UnknownSetting { id: u16, value: u32 },
    /// Server sending SETTINGS_ENABLE_PUSH (RFC 9113 §6.5.2)
    ServerSentEnablePush,
}

/// Individual HTTP/2 setting for validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingEntry {
    pub id: u16,
    pub value: u32,
}

/// SETTINGS frame test scenario
#[derive(Debug, Clone, Arbitrary)]
pub struct SettingsScenario {
    /// Whether this is from a server (affects ENABLE_PUSH validation)
    pub is_server: bool,
    /// Individual settings in the frame
    pub settings: Vec<SettingEntry>,
    /// Whether to include additional invalid settings for edge case testing
    pub include_edge_cases: bool,
    /// Frame size for testing oversized SETTINGS
    pub frame_size_hint: u16,
}

impl MockSettingsValidator {
    pub fn new(strict_rfc_compliance: bool) -> Self {
        Self {
            strict_rfc_compliance,
            violations: Vec::new(),
        }
    }

    /// Validate a SETTINGS frame according to RFC 9113
    pub fn validate_settings_frame(&mut self, scenario: &SettingsScenario) -> ValidationResult {
        self.violations.clear();

        let mut valid_settings = Vec::new();
        let mut has_protocol_error = false;
        let mut has_flow_control_error = false;

        // Check frame size limits (64KB max for SETTINGS)
        if scenario.settings.len() > 10922 {
            // 65535 / 6 bytes per setting
            self.violations
                .push(SettingsViolation::InvalidMaxFrameSize {
                    actual: scenario.settings.len() as u32 * 6,
                });
        }

        for setting in &scenario.settings {
            match self.validate_individual_setting(setting, scenario.is_server) {
                SettingValidation::Valid(parsed) => {
                    valid_settings.push(parsed);
                }
                SettingValidation::ProtocolError(violation) => {
                    self.violations.push(violation);
                    has_protocol_error = true;
                }
                SettingValidation::FlowControlError(violation) => {
                    self.violations.push(violation);
                    has_flow_control_error = true;
                }
                SettingValidation::Ignored => {
                    // Unknown settings are ignored per RFC
                }
            }
        }

        // Determine overall result
        if has_flow_control_error {
            ValidationResult::FlowControlError {
                violations: self.violations.clone(),
                partial_settings: valid_settings,
            }
        } else if has_protocol_error {
            ValidationResult::ProtocolError {
                violations: self.violations.clone(),
                partial_settings: valid_settings,
            }
        } else {
            ValidationResult::Success {
                settings: valid_settings,
                violations: self.violations.clone(), // May include ignored unknown settings
            }
        }
    }

    fn validate_individual_setting(
        &self,
        setting: &SettingEntry,
        is_server: bool,
    ) -> SettingValidation {
        match setting.id {
            // SETTINGS_HEADER_TABLE_SIZE (0x1)
            0x1 => SettingValidation::Valid(ParsedSetting::HeaderTableSize(setting.value)),

            // SETTINGS_ENABLE_PUSH (0x2) - THE CRITICAL VULNERABILITY CASE
            0x2 => {
                // RFC 9113 §6.5.2: Server MUST NOT send SETTINGS_ENABLE_PUSH
                if is_server {
                    return SettingValidation::ProtocolError(
                        SettingsViolation::ServerSentEnablePush,
                    );
                }

                // RFC 9113 §6.5.2: SETTINGS_ENABLE_PUSH values other than 0 or 1
                // MUST be treated as a connection error of type PROTOCOL_ERROR
                if self.strict_rfc_compliance && setting.value > 1 {
                    SettingValidation::ProtocolError(SettingsViolation::InvalidEnablePushValue {
                        actual: setting.value,
                    })
                } else {
                    // Current vulnerable implementation: any non-zero -> true
                    SettingValidation::Valid(ParsedSetting::EnablePush(setting.value != 0))
                }
            }

            // SETTINGS_MAX_CONCURRENT_STREAMS (0x3)
            0x3 => SettingValidation::Valid(ParsedSetting::MaxConcurrentStreams(setting.value)),

            // SETTINGS_INITIAL_WINDOW_SIZE (0x4)
            0x4 => {
                if setting.value > 0x7fff_ffff {
                    // 2^31 - 1
                    SettingValidation::FlowControlError(
                        SettingsViolation::InvalidInitialWindowSize {
                            actual: setting.value,
                        },
                    )
                } else {
                    SettingValidation::Valid(ParsedSetting::InitialWindowSize(setting.value))
                }
            }

            // SETTINGS_MAX_FRAME_SIZE (0x5)
            0x5 => {
                if setting.value < 16384 || setting.value > 16777215 {
                    SettingValidation::ProtocolError(SettingsViolation::InvalidMaxFrameSize {
                        actual: setting.value,
                    })
                } else {
                    SettingValidation::Valid(ParsedSetting::MaxFrameSize(setting.value))
                }
            }

            // SETTINGS_MAX_HEADER_LIST_SIZE (0x6)
            0x6 => SettingValidation::Valid(ParsedSetting::MaxHeaderListSize(setting.value)),

            // Unknown setting IDs are ignored per RFC 7540 §6.5.2
            _ => {
                if self.strict_rfc_compliance {
                    self.violations
                        .clone()
                        .push(SettingsViolation::UnknownSetting {
                            id: setting.id,
                            value: setting.value,
                        });
                }
                SettingValidation::Ignored
            }
        }
    }

    /// Get count of each violation type for fuzzing analysis
    pub fn violation_summary(&self) -> HashMap<String, u32> {
        let mut summary = HashMap::new();
        for violation in &self.violations {
            let key = match violation {
                SettingsViolation::InvalidEnablePushValue { .. } => "invalid_enable_push",
                SettingsViolation::InvalidInitialWindowSize { .. } => "invalid_window_size",
                SettingsViolation::InvalidMaxFrameSize { .. } => "invalid_frame_size",
                SettingsViolation::UnknownSetting { .. } => "unknown_setting",
                SettingsViolation::ServerSentEnablePush => "server_enable_push",
            };
            *summary.entry(key.to_string()).or_insert(0) += 1;
        }
        summary
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedSetting {
    HeaderTableSize(u32),
    EnablePush(bool),
    MaxConcurrentStreams(u32),
    InitialWindowSize(u32),
    MaxFrameSize(u32),
    MaxHeaderListSize(u32),
}

#[derive(Debug)]
pub enum SettingValidation {
    Valid(ParsedSetting),
    ProtocolError(SettingsViolation),
    FlowControlError(SettingsViolation),
    Ignored,
}

#[derive(Debug)]
pub enum ValidationResult {
    Success {
        settings: Vec<ParsedSetting>,
        violations: Vec<SettingsViolation>,
    },
    ProtocolError {
        violations: Vec<SettingsViolation>,
        partial_settings: Vec<ParsedSetting>,
    },
    FlowControlError {
        violations: Vec<SettingsViolation>,
        partial_settings: Vec<ParsedSetting>,
    },
}

impl Arbitrary<'_> for SettingEntry {
    fn arbitrary(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Self> {
        // Generate setting ID with bias toward known IDs
        let id = if u.ratio(3, 4)? {
            // Known setting IDs
            *u.choose(&[0x1, 0x2, 0x3, 0x4, 0x5, 0x6])?
        } else {
            // Random/unknown setting IDs for edge case testing
            u.int_in_range(0x7..=0xFFFF)?
        };

        // Generate value with bias toward interesting cases
        let value = match id {
            0x2 => {
                // SETTINGS_ENABLE_PUSH - focus on invalid values like 2, 3, etc.
                if u.ratio(1, 3)? {
                    // Valid values
                    if u.arbitrary()? { 1 } else { 0 }
                } else {
                    // Invalid values (the vulnerability case)
                    u.int_in_range(2..=u32::MAX)?
                }
            }
            0x4 => {
                // SETTINGS_INITIAL_WINDOW_SIZE - test boundary values
                if u.ratio(1, 4)? {
                    // Test overflow boundary
                    u.int_in_range(0x7fff_ffff..=u32::MAX)?
                } else {
                    u.arbitrary()?
                }
            }
            0x5 => {
                // SETTINGS_MAX_FRAME_SIZE - test range boundaries
                if u.ratio(1, 4)? {
                    // Below minimum
                    u.int_in_range(0..=16383)?
                } else if u.ratio(1, 3)? {
                    // Above maximum
                    u.int_in_range(16777216..=u32::MAX)?
                } else {
                    // Valid range
                    u.int_in_range(16384..=16777215)?
                }
            }
            _ => u.arbitrary()?,
        };

        Ok(SettingEntry { id, value })
    }
}

/// Test SETTINGS_ENABLE_PUSH validation with specific invalid values
fn test_enable_push_validation() {
    let mut validator_strict = MockSettingsValidator::new(true);
    let mut validator_loose = MockSettingsValidator::new(false);

    // Test critical vulnerability: SETTINGS_ENABLE_PUSH=2 should be rejected
    let invalid_scenarios = vec![
        SettingEntry { id: 0x2, value: 2 }, // The specific case mentioned in Tick #203
        SettingEntry { id: 0x2, value: 3 },
        SettingEntry { id: 0x2, value: 42 },
        SettingEntry {
            id: 0x2,
            value: u32::MAX,
        },
    ];

    for setting in invalid_scenarios {
        let scenario = SettingsScenario {
            is_server: false,
            settings: vec![setting.clone()],
            include_edge_cases: false,
            frame_size_hint: 100,
        };

        // Strict validator should reject invalid values
        let strict_result = validator_strict.validate_settings_frame(&scenario);
        match strict_result {
            ValidationResult::ProtocolError { violations, .. } => {
                assert!(violations.iter().any(|v| matches!(v, SettingsViolation::InvalidEnablePushValue { actual } if *actual == setting.value)));
            }
            _ => panic!(
                "Strict validator should reject SETTINGS_ENABLE_PUSH={}",
                setting.value
            ),
        }

        // Loose validator (current implementation) accepts invalid values
        let loose_result = validator_loose.validate_settings_frame(&scenario);
        match loose_result {
            ValidationResult::Success { settings, .. } => {
                assert!(
                    settings
                        .iter()
                        .any(|s| matches!(s, ParsedSetting::EnablePush(true)))
                );
            }
            _ => panic!(
                "Loose validator unexpectedly rejected SETTINGS_ENABLE_PUSH={}",
                setting.value
            ),
        }
    }
}

/// Test server sending SETTINGS_ENABLE_PUSH (forbidden by RFC)
fn test_server_enable_push_forbidden() {
    let mut validator = MockSettingsValidator::new(true);

    let scenario = SettingsScenario {
        is_server: true, // Server sending SETTINGS_ENABLE_PUSH
        settings: vec![SettingEntry { id: 0x2, value: 1 }],
        include_edge_cases: false,
        frame_size_hint: 100,
    };

    let result = validator.validate_settings_frame(&scenario);
    match result {
        ValidationResult::ProtocolError { violations, .. } => {
            assert!(
                violations
                    .iter()
                    .any(|v| matches!(v, SettingsViolation::ServerSentEnablePush))
            );
        }
        _ => panic!("Should reject server sending SETTINGS_ENABLE_PUSH"),
    }
}

/// Comprehensive edge case testing
fn test_comprehensive_edge_cases() {
    let mut validator = MockSettingsValidator::new(true);

    // Mix of valid, invalid, and unknown settings
    let scenario = SettingsScenario {
        is_server: false,
        settings: vec![
            SettingEntry {
                id: 0x1,
                value: 4096,
            }, // Valid HEADER_TABLE_SIZE
            SettingEntry { id: 0x2, value: 2 }, // Invalid ENABLE_PUSH
            SettingEntry {
                id: 0x4,
                value: 0x8000_0000,
            }, // Invalid INITIAL_WINDOW_SIZE
            SettingEntry {
                id: 0x5,
                value: 1000,
            }, // Invalid MAX_FRAME_SIZE
            SettingEntry {
                id: 0xFFFF,
                value: 12345,
            }, // Unknown setting (ignored)
        ],
        include_edge_cases: true,
        frame_size_hint: 200,
    };

    let result = validator.validate_settings_frame(&scenario);

    // Should be ProtocolError due to invalid ENABLE_PUSH and MAX_FRAME_SIZE
    match result {
        ValidationResult::FlowControlError { violations, .. } => {
            // Should have flow control error for window size, protocol errors for others
            assert!(
                violations
                    .iter()
                    .any(|v| matches!(v, SettingsViolation::InvalidInitialWindowSize { .. }))
            );
        }
        ValidationResult::ProtocolError { violations, .. } => {
            assert!(
                violations
                    .iter()
                    .any(|v| matches!(v, SettingsViolation::InvalidEnablePushValue { .. }))
            );
            assert!(
                violations
                    .iter()
                    .any(|v| matches!(v, SettingsViolation::InvalidMaxFrameSize { .. }))
            );
        }
        _ => {
            // May succeed in loose mode
        }
    }

    let summary = validator.violation_summary();
    assert!(summary.get("invalid_enable_push").unwrap_or(&0) > &0);
}

fuzz_target!(|scenario: SettingsScenario| {
    // Test both strict RFC compliance and current loose implementation
    let mut validator_strict = MockSettingsValidator::new(true);
    let mut validator_loose = MockSettingsValidator::new(false);

    // Size guard - prevent excessive memory usage
    if scenario.settings.len() > 1000 {
        return;
    }

    // Test with strict validator (RFC-compliant)
    let strict_result = validator_strict.validate_settings_frame(&scenario);

    // Test with loose validator (current implementation)
    let loose_result = validator_loose.validate_settings_frame(&scenario);

    // Analyze violations for security testing
    let _strict_violations = validator_strict.violation_summary();
    let _loose_violations = validator_loose.violation_summary();

    // Critical security check: SETTINGS_ENABLE_PUSH with value > 1
    for setting in &scenario.settings {
        if setting.id == 0x2 && setting.value > 1 {
            // In strict mode, this should be a protocol error
            match &strict_result {
                ValidationResult::ProtocolError { violations, .. } => {
                    assert!(violations.iter().any(|v| matches!(v, SettingsViolation::InvalidEnablePushValue { actual } if *actual == setting.value)),
                        "Strict mode should reject SETTINGS_ENABLE_PUSH={}", setting.value);
                }
                _ => {
                    if !scenario.is_server {
                        // Server case has different error
                        panic!(
                            "Strict mode should reject SETTINGS_ENABLE_PUSH={}",
                            setting.value
                        );
                    }
                }
            }

            // In loose mode, this gets accepted as true (the vulnerability)
            match &loose_result {
                ValidationResult::Success { settings, .. } => {
                    if !scenario.is_server {
                        assert!(
                            settings
                                .iter()
                                .any(|s| matches!(s, ParsedSetting::EnablePush(true))),
                            "Loose mode should accept SETTINGS_ENABLE_PUSH={} as true",
                            setting.value
                        );
                    }
                }
                _ => {
                    // May be other errors like server sending ENABLE_PUSH
                }
            }
        }
    }

    // RFC compliance checks
    if scenario.is_server {
        for setting in &scenario.settings {
            if setting.id == 0x2 {
                // SETTINGS_ENABLE_PUSH
                // Both validators should reject this
                match &strict_result {
                    ValidationResult::ProtocolError { violations, .. } => {
                        assert!(
                            violations
                                .iter()
                                .any(|v| matches!(v, SettingsViolation::ServerSentEnablePush))
                        );
                    }
                    _ => panic!("Should reject server sending SETTINGS_ENABLE_PUSH"),
                }
            }
        }
    }

    // Run additional targeted tests periodically
    if scenario.settings.len() == 1 {
        test_enable_push_validation();
        test_server_enable_push_forbidden();
        test_comprehensive_edge_cases();
    }
});
