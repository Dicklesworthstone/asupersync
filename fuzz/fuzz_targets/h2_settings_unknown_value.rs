#![no_main]
#![allow(dead_code)]

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::http::h2::frame::SettingsFrame;
use asupersync::http::h2::{ErrorCode, FrameHeader, FrameType, Settings};
use libfuzzer_sys::fuzz_target;

/// HTTP/2 SETTINGS frame with known IDs but invalid values test input
#[derive(Arbitrary, Debug)]
struct H2SettingsInvalidValueInput {
    /// SETTINGS parameters with invalid values
    invalid_settings: Vec<InvalidSetting>,
    /// Valid settings to mix with invalid ones
    valid_settings: Vec<ValidSetting>,
    /// Frame construction options
    frame_options: FrameOptions,
    /// Test scenario configuration
    test_scenario: TestScenario,
}

#[derive(Arbitrary, Debug)]
struct InvalidSetting {
    /// Known setting ID
    setting_id: KnownSettingId,
    /// Invalid value strategy
    invalid_value_strategy: InvalidValueStrategy,
    /// Position in frame (for error context)
    position: SettingPosition,
}

#[derive(Arbitrary, Debug)]
enum KnownSettingId {
    /// SETTINGS_HEADER_TABLE_SIZE (1)
    HeaderTableSize,
    /// SETTINGS_ENABLE_PUSH (2)
    EnablePush,
    /// SETTINGS_MAX_CONCURRENT_STREAMS (3)
    MaxConcurrentStreams,
    /// SETTINGS_INITIAL_WINDOW_SIZE (4)
    InitialWindowSize,
    /// SETTINGS_MAX_FRAME_SIZE (5)
    MaxFrameSize,
    /// SETTINGS_MAX_HEADER_LIST_SIZE (6)
    MaxHeaderListSize,
}

#[derive(Arbitrary, Debug)]
enum InvalidValueStrategy {
    /// Below minimum allowed value
    BelowMinimum { offset: u32 },
    /// Above maximum allowed value
    AboveMaximum { offset: u32 },
    /// Exactly at invalid boundary
    ExactBoundary(BoundaryType),
    /// Reserved/special invalid values
    ReservedValues(ReservedValueType),
    /// Extreme values
    ExtremeValues(ExtremeType),
    /// Bit pattern attacks
    BitPatterns(BitPatternType),
}

#[derive(Arbitrary, Debug)]
enum BoundaryType {
    /// Just below minimum (min - 1)
    JustBelowMin,
    /// Just above maximum (max + 1)
    JustAboveMax,
    /// At signed/unsigned boundary
    SignBoundary,
    /// At power-of-2 boundary
    PowerOfTwoBoundary,
}

#[derive(Arbitrary, Debug)]
enum ReservedValueType {
    /// Maximum u32 value
    MaxU32,
    /// Maximum i32 value
    MaxI32,
    /// Minimum i32 value
    MinI32,
    /// Common "invalid" sentinel values
    SentinelValues,
}

#[derive(Arbitrary, Debug)]
enum ExtremeType {
    /// Very large values
    VeryLarge,
    /// Zero when not allowed
    ZeroWhenInvalid,
    /// One when not allowed
    OneWhenInvalid,
    /// Maximum valid + small offset
    MaxValidPlusSmall,
}

#[derive(Arbitrary, Debug)]
enum BitPatternType {
    /// All bits set
    AllOnes,
    /// Alternating bit pattern
    Alternating,
    /// Single bit set in invalid position
    SingleBit(u8),
    /// Pattern that might be misinterpreted
    Ambiguous,
}

#[derive(Arbitrary, Debug)]
enum SettingPosition {
    /// First setting in frame
    First,
    /// Middle of frame
    Middle,
    /// Last setting in frame
    Last,
    /// Only setting in frame
    Only,
}

#[derive(Arbitrary, Debug)]
struct ValidSetting {
    /// Setting ID
    setting_id: KnownSettingId,
    /// Valid value for this setting
    value: u32,
}

#[derive(Arbitrary, Debug)]
struct FrameOptions {
    /// Whether frame has ACK flag
    ack_flag: bool,
    /// Frame stream ID (should be 0 for SETTINGS)
    stream_id: u32,
    /// Include padding
    include_padding: bool,
    /// Frame size constraints
    size_constraints: SizeConstraints,
}

#[derive(Arbitrary, Debug)]
struct SizeConstraints {
    /// Maximum frame size for this test
    max_frame_size: u32,
    /// Whether to test frame size boundary
    test_frame_boundary: bool,
    /// Padding amount
    padding_bytes: u8,
}

#[derive(Arbitrary, Debug)]
struct TestScenario {
    /// Validation strictness
    validation_mode: ValidationMode,
    /// Error handling preference
    error_handling: ErrorHandling,
    /// Performance constraints
    performance_limits: PerformanceLimits,
}

#[derive(Arbitrary, Debug, Clone)]
enum ValidationMode {
    /// Strict RFC compliance
    StrictRFC,
    /// Lenient (some invalid values might be accepted)
    Lenient,
    /// Security-focused validation
    Security,
}

#[derive(Arbitrary, Debug, Clone)]
enum ErrorHandling {
    /// Fail fast on first invalid setting
    FailFast,
    /// Validate all settings before failing
    ValidateAll,
    /// Continue processing valid settings
    ContinueValid,
}

#[derive(Arbitrary, Debug)]
struct PerformanceLimits {
    /// Maximum settings per frame
    max_settings_per_frame: u8,
    /// Processing timeout
    max_processing_time_us: u32,
}

/// Mock HTTP/2 SETTINGS frame parser with value validation
struct MockH2SettingsParser {
    validation_mode: ValidationMode,
    error_handling: ErrorHandling,
    frame_validation_state: FrameValidationState,
    settings_state: SettingsState,
}

#[derive(Debug)]
struct FrameValidationState {
    settings_processed: u32,
    validation_errors: Vec<SettingsValidationError>,
    frame_errors: Vec<FrameError>,
}

#[derive(Debug, Clone)]
struct SettingsState {
    header_table_size: u32,
    enable_push: bool,
    max_concurrent_streams: Option<u32>,
    initial_window_size: u32,
    max_frame_size: u32,
    max_header_list_size: Option<u32>,
}

#[derive(Debug, Clone)]
struct ParsedSettings {
    valid_settings: Vec<(u16, u32)>,
    invalid_settings: Vec<InvalidSettingEntry>,
    frame_info: FrameInfo,
    validation_result: ValidationResult,
}

#[derive(Debug, Clone)]
struct InvalidSettingEntry {
    setting_id: u16,
    invalid_value: u32,
    error_type: SettingsValidationError,
    position: usize,
}

#[derive(Debug, Clone)]
struct FrameInfo {
    frame_length: u32,
    flags: u8,
    stream_id: u32,
    settings_count: u32,
}

#[derive(Debug, Clone, PartialEq)]
enum ValidationResult {
    AllValid,
    ProtocolError(ProtocolErrorType),
    FrameError(FrameErrorType),
    PartiallyValid,
}

#[derive(Debug, Clone, PartialEq)]
enum ProtocolErrorType {
    InvalidSettingValue { id: u16, value: u32 },
    MultipleInvalidSettings,
    FrameFormatError,
}

#[derive(Debug, Clone, PartialEq)]
enum FrameErrorType {
    InvalidStreamId,
    AckWithPayload,
    FrameSizeError,
    InvalidFlags,
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, PartialEq)]
enum SettingsValidationError {
    /// SETTINGS_HEADER_TABLE_SIZE: any value is valid per RFC 7541
    HeaderTableSizeInvalid { value: u32, reason: String },
    /// SETTINGS_ENABLE_PUSH: must be 0 or 1
    EnablePushInvalid { value: u32 },
    /// SETTINGS_MAX_CONCURRENT_STREAMS: any value is valid (0 = no new streams)
    MaxConcurrentStreamsInvalid { value: u32, reason: String },
    /// SETTINGS_INITIAL_WINDOW_SIZE: must be ≤ 2^31-1
    InitialWindowSizeInvalid { value: u32, max: u32 },
    /// SETTINGS_MAX_FRAME_SIZE: must be 16384 ≤ value ≤ 16777215
    MaxFrameSizeInvalid { value: u32, min: u32, max: u32 },
    /// SETTINGS_MAX_HEADER_LIST_SIZE: any value is valid per RFC 7540
    MaxHeaderListSizeInvalid { value: u32, reason: String },
}

#[derive(Debug, PartialEq)]
enum FrameError {
    /// SETTINGS frame on non-zero stream
    NonZeroStreamId(u32),
    /// SETTINGS ACK with non-empty payload
    AckWithPayload(u32),
    /// Frame size not multiple of 6
    InvalidFrameSize(u32),
    /// Invalid frame flags
    InvalidFlags(u8),
    /// Frame too large
    FrameTooLarge { size: u32, limit: u32 },
}

// RFC 7540 SETTINGS value ranges
const SETTINGS_HEADER_TABLE_SIZE: u16 = 1;
const SETTINGS_ENABLE_PUSH: u16 = 2;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 3;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 4;
const SETTINGS_MAX_FRAME_SIZE: u16 = 5;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 6;

// Valid value ranges per RFC 7540 §6.5.2
const MAX_INITIAL_WINDOW_SIZE: u32 = 2_147_483_647; // 2^31-1
const MIN_MAX_FRAME_SIZE: u32 = 16_384; // 2^14
const MAX_MAX_FRAME_SIZE: u32 = 16_777_215; // 2^24-1

impl SettingsState {
    fn default() -> Self {
        Self {
            header_table_size: 4096,
            enable_push: true,
            max_concurrent_streams: None,
            initial_window_size: 65535,
            max_frame_size: 16384,
            max_header_list_size: None,
        }
    }
}

impl MockH2SettingsParser {
    fn new(validation_mode: ValidationMode, error_handling: ErrorHandling) -> Self {
        Self {
            validation_mode,
            error_handling,
            frame_validation_state: FrameValidationState {
                settings_processed: 0,
                validation_errors: Vec::new(),
                frame_errors: Vec::new(),
            },
            settings_state: SettingsState::default(),
        }
    }

    fn parse_settings_frame(
        &mut self,
        frame_data: &[u8],
        frame_flags: u8,
        stream_id: u32,
    ) -> Result<ParsedSettings, ValidationResult> {
        // Validate frame-level constraints first
        if let Err(frame_error) =
            self.validate_frame_constraints(frame_data, frame_flags, stream_id)
        {
            return Err(ValidationResult::FrameError(frame_error));
        }

        // Check for ACK flag with payload
        if (frame_flags & 0x01) != 0 && !frame_data.is_empty() {
            return Err(ValidationResult::FrameError(FrameErrorType::AckWithPayload));
        }

        // Parse individual settings
        if !frame_data.len().is_multiple_of(6) {
            return Err(ValidationResult::FrameError(FrameErrorType::FrameSizeError));
        }

        let mut valid_settings = Vec::new();
        let mut invalid_settings = Vec::new();
        let settings_count = frame_data.len() / 6;

        for i in 0..settings_count {
            let offset = i * 6;
            let setting_id = u16::from_be_bytes([frame_data[offset], frame_data[offset + 1]]);
            let value = u32::from_be_bytes([
                frame_data[offset + 2],
                frame_data[offset + 3],
                frame_data[offset + 4],
                frame_data[offset + 5],
            ]);

            match self.validate_setting_value(setting_id, value) {
                Ok(_) => {
                    valid_settings.push((setting_id, value));
                    self.apply_valid_setting(setting_id, value);
                }
                Err(error) => {
                    invalid_settings.push(InvalidSettingEntry {
                        setting_id,
                        invalid_value: value,
                        error_type: error,
                        position: i,
                    });

                    // Handle error based on error handling mode
                    match self.error_handling {
                        ErrorHandling::FailFast => {
                            return Err(ValidationResult::ProtocolError(
                                ProtocolErrorType::InvalidSettingValue {
                                    id: setting_id,
                                    value,
                                },
                            ));
                        }
                        ErrorHandling::ValidateAll | ErrorHandling::ContinueValid => {
                            // Continue processing other settings
                        }
                    }
                }
            }

            self.frame_validation_state.settings_processed += 1;
        }

        // Determine final validation result
        let validation_result = if invalid_settings.is_empty() {
            ValidationResult::AllValid
        } else if invalid_settings.len() == 1 {
            ValidationResult::ProtocolError(ProtocolErrorType::InvalidSettingValue {
                id: invalid_settings[0].setting_id,
                value: invalid_settings[0].invalid_value,
            })
        } else {
            ValidationResult::ProtocolError(ProtocolErrorType::MultipleInvalidSettings)
        };

        let parsed_settings = ParsedSettings {
            valid_settings,
            invalid_settings,
            frame_info: FrameInfo {
                frame_length: frame_data.len() as u32,
                flags: frame_flags,
                stream_id,
                settings_count: settings_count as u32,
            },
            validation_result: validation_result.clone(),
        };

        match self.error_handling {
            ErrorHandling::FailFast => {
                if !parsed_settings.invalid_settings.is_empty() {
                    Err(validation_result)
                } else {
                    Ok(parsed_settings)
                }
            }
            ErrorHandling::ValidateAll => {
                if !parsed_settings.invalid_settings.is_empty() {
                    Err(validation_result)
                } else {
                    Ok(parsed_settings)
                }
            }
            ErrorHandling::ContinueValid => {
                // Return parsed settings even with invalid entries
                Ok(parsed_settings)
            }
        }
    }

    fn validate_frame_constraints(
        &self,
        frame_data: &[u8],
        frame_flags: u8,
        stream_id: u32,
    ) -> Result<(), FrameErrorType> {
        // SETTINGS frames must be sent on stream 0
        if stream_id != 0 {
            return Err(FrameErrorType::InvalidStreamId);
        }

        // Check frame size constraints
        if !frame_data.len().is_multiple_of(6) {
            return Err(FrameErrorType::FrameSizeError);
        }

        // Validate flags (only ACK is defined)
        if frame_flags & 0xFE != 0 {
            // Only bit 0 (ACK) is valid
            return Err(FrameErrorType::InvalidFlags);
        }

        // ACK frames must be empty
        if (frame_flags & 0x01) != 0 && !frame_data.is_empty() {
            return Err(FrameErrorType::AckWithPayload);
        }

        Ok(())
    }

    fn validate_setting_value(
        &self,
        setting_id: u16,
        value: u32,
    ) -> Result<(), SettingsValidationError> {
        match setting_id {
            SETTINGS_HEADER_TABLE_SIZE => {
                // RFC 7541: Any value is acceptable
                // Some implementations might have practical limits
                match self.validation_mode {
                    ValidationMode::Security => {
                        // Security mode might limit very large values
                        if value > 1_048_576 {
                            // 1MB limit
                            Err(SettingsValidationError::HeaderTableSizeInvalid {
                                value,
                                reason: "Exceeds security limit".to_string(),
                            })
                        } else {
                            Ok(())
                        }
                    }
                    _ => Ok(()),
                }
            }
            SETTINGS_ENABLE_PUSH => {
                // RFC 7540 §6.5.2: MUST be 0 or 1
                if value > 1 {
                    Err(SettingsValidationError::EnablePushInvalid { value })
                } else {
                    Ok(())
                }
            }
            SETTINGS_MAX_CONCURRENT_STREAMS => {
                // RFC 7540 §6.5.2: Any value is acceptable
                // 0 means no new streams allowed
                Ok(())
            }
            SETTINGS_INITIAL_WINDOW_SIZE => {
                // RFC 7540 §6.5.2: Values above 2^31-1 MUST trigger PROTOCOL_ERROR
                if value > MAX_INITIAL_WINDOW_SIZE {
                    Err(SettingsValidationError::InitialWindowSizeInvalid {
                        value,
                        max: MAX_INITIAL_WINDOW_SIZE,
                    })
                } else {
                    Ok(())
                }
            }
            SETTINGS_MAX_FRAME_SIZE => {
                // RFC 7540 §6.5.2: Must be between 2^14 (16384) and 2^24-1 (16777215)
                if !(MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&value) {
                    Err(SettingsValidationError::MaxFrameSizeInvalid {
                        value,
                        min: MIN_MAX_FRAME_SIZE,
                        max: MAX_MAX_FRAME_SIZE,
                    })
                } else {
                    Ok(())
                }
            }
            SETTINGS_MAX_HEADER_LIST_SIZE => {
                // RFC 7540 §6.5.2: Any value is acceptable
                Ok(())
            }
            _ => {
                // Unknown setting IDs are ignored per RFC 7540 §6.5.2
                Ok(())
            }
        }
    }

    fn apply_valid_setting(&mut self, setting_id: u16, value: u32) {
        match setting_id {
            SETTINGS_HEADER_TABLE_SIZE => {
                self.settings_state.header_table_size = value;
            }
            SETTINGS_ENABLE_PUSH => {
                self.settings_state.enable_push = value == 1;
            }
            SETTINGS_MAX_CONCURRENT_STREAMS => {
                self.settings_state.max_concurrent_streams = Some(value);
            }
            SETTINGS_INITIAL_WINDOW_SIZE => {
                self.settings_state.initial_window_size = value;
            }
            SETTINGS_MAX_FRAME_SIZE => {
                self.settings_state.max_frame_size = value;
            }
            SETTINGS_MAX_HEADER_LIST_SIZE => {
                self.settings_state.max_header_list_size = Some(value);
            }
            _ => {
                // Unknown settings are ignored
            }
        }
    }

    fn generate_invalid_value(setting_id: &KnownSettingId, strategy: &InvalidValueStrategy) -> u32 {
        match (setting_id, strategy) {
            (KnownSettingId::EnablePush, InvalidValueStrategy::BelowMinimum { .. }) => {
                // 0 and 1 are valid, so there's no "below minimum" - use invalid value
                2 // Any value > 1 is invalid
            }
            (KnownSettingId::EnablePush, InvalidValueStrategy::AboveMaximum { offset }) => {
                1 + offset.saturating_add(1) // > 1 is invalid
            }
            (
                KnownSettingId::EnablePush,
                InvalidValueStrategy::ExactBoundary(BoundaryType::JustAboveMax),
            ) => {
                2 // Just above maximum valid (1)
            }
            (KnownSettingId::EnablePush, InvalidValueStrategy::ReservedValues(_)) => {
                u32::MAX // Definitely invalid
            }

            (KnownSettingId::InitialWindowSize, InvalidValueStrategy::AboveMaximum { offset }) => {
                MAX_INITIAL_WINDOW_SIZE.saturating_add(offset.saturating_add(1))
            }
            (
                KnownSettingId::InitialWindowSize,
                InvalidValueStrategy::ExactBoundary(BoundaryType::JustAboveMax),
            ) => MAX_INITIAL_WINDOW_SIZE + 1,
            (
                KnownSettingId::InitialWindowSize,
                InvalidValueStrategy::ReservedValues(ReservedValueType::MaxU32),
            ) => u32::MAX,

            (KnownSettingId::MaxFrameSize, InvalidValueStrategy::BelowMinimum { offset }) => {
                MIN_MAX_FRAME_SIZE.saturating_sub(offset.saturating_add(1))
            }
            (KnownSettingId::MaxFrameSize, InvalidValueStrategy::AboveMaximum { offset }) => {
                MAX_MAX_FRAME_SIZE.saturating_add(offset.saturating_add(1))
            }
            (
                KnownSettingId::MaxFrameSize,
                InvalidValueStrategy::ExactBoundary(BoundaryType::JustBelowMin),
            ) => MIN_MAX_FRAME_SIZE - 1,
            (
                KnownSettingId::MaxFrameSize,
                InvalidValueStrategy::ExactBoundary(BoundaryType::JustAboveMax),
            ) => MAX_MAX_FRAME_SIZE + 1,
            (
                KnownSettingId::MaxFrameSize,
                InvalidValueStrategy::ExtremeValues(ExtremeType::ZeroWhenInvalid),
            ) => {
                0 // Well below minimum
            }

            // For settings that accept any value, generate values that might be problematic
            (
                KnownSettingId::HeaderTableSize,
                InvalidValueStrategy::ReservedValues(ReservedValueType::MaxU32),
            ) => {
                u32::MAX // Might cause issues in security mode
            }
            (
                KnownSettingId::MaxConcurrentStreams,
                InvalidValueStrategy::ReservedValues(ReservedValueType::MaxU32),
            ) => {
                u32::MAX // Extreme but technically valid
            }
            (
                KnownSettingId::MaxHeaderListSize,
                InvalidValueStrategy::ReservedValues(ReservedValueType::MaxU32),
            ) => {
                u32::MAX // Extreme but technically valid
            }

            // Bit pattern strategies
            (_, InvalidValueStrategy::BitPatterns(BitPatternType::AllOnes)) => 0xFFFFFFFF,
            (_, InvalidValueStrategy::BitPatterns(BitPatternType::Alternating)) => 0xAAAAAAAA,
            (_, InvalidValueStrategy::BitPatterns(BitPatternType::SingleBit(bit))) => {
                1u32 << (bit % 32)
            }

            // Default to a common invalid value
            _ => {
                match setting_id {
                    KnownSettingId::EnablePush => 42, // Invalid (must be 0 or 1)
                    KnownSettingId::InitialWindowSize => u32::MAX, // Invalid (> 2^31-1)
                    KnownSettingId::MaxFrameSize => 10, // Invalid (< 16384)
                    _ => 0xDEADBEEF,                  // Arbitrary invalid value
                }
            }
        }
    }

    fn build_settings_frame(input: &H2SettingsInvalidValueInput) -> Vec<u8> {
        let mut frame_data = Vec::new();

        // Add valid settings first
        for valid_setting in &input.valid_settings {
            let setting_id = Self::setting_id_to_u16(&valid_setting.setting_id);
            let value =
                Self::valid_value_for_setting(&valid_setting.setting_id, valid_setting.value);
            frame_data.extend_from_slice(&setting_id.to_be_bytes());
            frame_data.extend_from_slice(&value.to_be_bytes());
        }

        // Add invalid settings
        for invalid_setting in &input.invalid_settings {
            let setting_id = Self::setting_id_to_u16(&invalid_setting.setting_id);
            let invalid_value = Self::generate_invalid_value(
                &invalid_setting.setting_id,
                &invalid_setting.invalid_value_strategy,
            );

            frame_data.extend_from_slice(&setting_id.to_be_bytes());
            frame_data.extend_from_slice(&invalid_value.to_be_bytes());
        }

        frame_data
    }

    fn setting_id_to_u16(setting_id: &KnownSettingId) -> u16 {
        match setting_id {
            KnownSettingId::HeaderTableSize => SETTINGS_HEADER_TABLE_SIZE,
            KnownSettingId::EnablePush => SETTINGS_ENABLE_PUSH,
            KnownSettingId::MaxConcurrentStreams => SETTINGS_MAX_CONCURRENT_STREAMS,
            KnownSettingId::InitialWindowSize => SETTINGS_INITIAL_WINDOW_SIZE,
            KnownSettingId::MaxFrameSize => SETTINGS_MAX_FRAME_SIZE,
            KnownSettingId::MaxHeaderListSize => SETTINGS_MAX_HEADER_LIST_SIZE,
        }
    }

    fn valid_value_for_setting(setting_id: &KnownSettingId, raw_value: u32) -> u32 {
        match setting_id {
            KnownSettingId::EnablePush => raw_value % 2,
            KnownSettingId::InitialWindowSize => raw_value & MAX_INITIAL_WINDOW_SIZE,
            KnownSettingId::MaxFrameSize => {
                MIN_MAX_FRAME_SIZE + raw_value % (MAX_MAX_FRAME_SIZE - MIN_MAX_FRAME_SIZE + 1)
            }
            KnownSettingId::HeaderTableSize
            | KnownSettingId::MaxConcurrentStreams
            | KnownSettingId::MaxHeaderListSize => raw_value,
        }
    }
}

fuzz_target!(|input: H2SettingsInvalidValueInput| {
    // Skip overly complex frames that would timeout
    if input.invalid_settings.len() + input.valid_settings.len() > 20 {
        return;
    }

    // Build SETTINGS frame with invalid values
    let frame_data = MockH2SettingsParser::build_settings_frame(&input);

    // Skip excessively large frames
    if frame_data.len() > 16384 {
        return;
    }

    let mut parser = MockH2SettingsParser::new(
        input.test_scenario.validation_mode.clone(),
        input.test_scenario.error_handling.clone(),
    );

    let frame_flags = if input.frame_options.ack_flag {
        0x01
    } else {
        0x00
    };
    let stream_id = input.frame_options.stream_id;

    let parse_result = parser.parse_settings_frame(&frame_data, frame_flags, stream_id);
    let expected_invalid_settings = expected_mock_invalid_settings(&input);

    exercise_production_settings_value_validation(&input, &frame_data, frame_flags, stream_id);

    // Test validation behavior based on invalid settings
    if !expected_invalid_settings.is_empty() {
        // Frame contains invalid settings - should be rejected
        match &parse_result {
            Ok(parsed) => {
                // Some parsers might accept in ContinueValid mode
                match input.test_scenario.error_handling {
                    ErrorHandling::ContinueValid => {
                        // Should have recorded invalid settings
                        assert!(
                            !parsed.invalid_settings.is_empty(),
                            "Invalid settings should be recorded even in ContinueValid mode"
                        );
                        assert_ne!(
                            parsed.validation_result,
                            ValidationResult::AllValid,
                            "Validation result should indicate protocol errors"
                        );
                    }
                    _ => {
                        // Other modes should not accept frames with invalid settings
                        panic!(
                            "Frame with invalid settings should be rejected: {:?}",
                            parsed
                        );
                    }
                }
            }
            Err(ValidationResult::ProtocolError(error_type)) => {
                // Expected: protocol error for invalid setting values
                match error_type {
                    ProtocolErrorType::InvalidSettingValue { id, value } => {
                        // Verify the error references an actual invalid setting
                        let has_matching_invalid = expected_invalid_settings
                            .iter()
                            .any(|entry| entry.0 == *id && entry.1 == *value);
                        assert!(
                            has_matching_invalid,
                            "Protocol error should reference an actually invalid setting: {}={}",
                            id, value
                        );
                    }
                    ProtocolErrorType::MultipleInvalidSettings => {
                        assert!(
                            expected_invalid_settings.len() > 1,
                            "Multiple invalid settings error should only occur with >1 invalid setting"
                        );
                    }
                    _ => {
                        // Other protocol errors may occur
                    }
                }
            }
            Err(ValidationResult::FrameError(frame_error)) => {
                // Frame-level errors are also acceptable
                match frame_error {
                    FrameErrorType::InvalidStreamId => {
                        assert_ne!(
                            stream_id, 0,
                            "Invalid stream ID error should only occur for non-zero stream IDs"
                        );
                    }
                    FrameErrorType::AckWithPayload => {
                        assert!(
                            input.frame_options.ack_flag && !frame_data.is_empty(),
                            "ACK with payload error should only occur for ACK frames with payload"
                        );
                    }
                    _ => {
                        // Other frame errors acceptable
                    }
                }
            }
            Err(ValidationResult::PartiallyValid) => {
                // Some parsers might use this for mixed valid/invalid
            }
            Err(ValidationResult::AllValid) => {
                panic!("Invalid SETTINGS values must not produce an AllValid error")
            }
        }
    } else {
        // Frame contains only valid settings - should be accepted unless frame errors
        match &parse_result {
            Ok(parsed) => {
                assert!(
                    parsed.invalid_settings.is_empty(),
                    "Frame with only valid settings should not have invalid entries"
                );
                assert_eq!(
                    parsed.validation_result,
                    ValidationResult::AllValid,
                    "All valid settings should result in AllValid validation"
                );
            }
            Err(ValidationResult::FrameError(_)) => {
                // Frame-level errors are acceptable even with valid settings
            }
            Err(ValidationResult::ProtocolError(_)) => {
                panic!("Frame with only valid settings should not cause protocol error");
            }
            Err(_) => {
                // Other errors may occur
            }
        }
    }

    // Test setting-specific validation invariants
    test_settings_validation_invariants(&input, &parse_result);
});

fn expected_mock_invalid_settings(input: &H2SettingsInvalidValueInput) -> Vec<(u16, u32)> {
    input
        .invalid_settings
        .iter()
        .filter_map(|setting| {
            let setting_id = MockH2SettingsParser::setting_id_to_u16(&setting.setting_id);
            let value = MockH2SettingsParser::generate_invalid_value(
                &setting.setting_id,
                &setting.invalid_value_strategy,
            );
            mock_invalid_setting_value(&input.test_scenario.validation_mode, setting_id, value)
                .then_some((setting_id, value))
        })
        .collect()
}

fn mock_invalid_setting_value(
    validation_mode: &ValidationMode,
    setting_id: u16,
    value: u32,
) -> bool {
    match setting_id {
        SETTINGS_HEADER_TABLE_SIZE => {
            matches!(validation_mode, ValidationMode::Security) && value > 1_048_576
        }
        SETTINGS_ENABLE_PUSH => value > 1,
        SETTINGS_MAX_CONCURRENT_STREAMS => false,
        SETTINGS_INITIAL_WINDOW_SIZE => value > MAX_INITIAL_WINDOW_SIZE,
        SETTINGS_MAX_FRAME_SIZE => !(MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&value),
        SETTINGS_MAX_HEADER_LIST_SIZE => false,
        _ => false,
    }
}

fn exercise_production_settings_value_validation(
    input: &H2SettingsInvalidValueInput,
    frame_data: &[u8],
    frame_flags: u8,
    stream_id: u32,
) {
    let header = FrameHeader {
        length: frame_data.len() as u32,
        frame_type: FrameType::Settings as u8,
        flags: frame_flags,
        stream_id,
    };
    let parse_result = SettingsFrame::parse(&header, &Bytes::copy_from_slice(frame_data));

    if stream_id != 0 {
        let err =
            parse_result.expect_err("production SETTINGS parser must reject non-zero stream IDs");
        assert_eq!(err.code, ErrorCode::ProtocolError);
        return;
    }

    if frame_flags & 0x01 != 0 && !frame_data.is_empty() {
        let err = parse_result
            .expect_err("production SETTINGS parser must reject ACK frames with payload");
        assert_eq!(err.code, ErrorCode::FrameSizeError);
        return;
    }

    let invalid_settings = production_invalid_settings(input);
    match parse_result {
        Ok(parsed) => {
            assert!(
                invalid_settings.is_empty(),
                "production SETTINGS parser accepted invalid setting values: {:?}",
                invalid_settings
            );

            let mut settings = Settings::default();
            for setting in parsed.settings {
                settings
                    .apply(setting)
                    .expect("production Settings::apply must accept parser-validated settings");
            }
        }
        Err(err) => {
            assert!(
                invalid_settings
                    .iter()
                    .any(|entry| entry.expected_error_code == err.code),
                "production SETTINGS parser rejected with unexpected error {:?}; invalid settings: {:?}",
                err,
                invalid_settings
            );
        }
    }
}

#[derive(Debug)]
struct ProductionInvalidSetting {
    setting_id: u16,
    value: u32,
    expected_error_code: ErrorCode,
}

fn production_invalid_settings(
    input: &H2SettingsInvalidValueInput,
) -> Vec<ProductionInvalidSetting> {
    input
        .invalid_settings
        .iter()
        .filter_map(|setting| {
            let setting_id = MockH2SettingsParser::setting_id_to_u16(&setting.setting_id);
            let value = MockH2SettingsParser::generate_invalid_value(
                &setting.setting_id,
                &setting.invalid_value_strategy,
            );
            production_invalid_setting(setting_id, value).map(|expected_error_code| {
                ProductionInvalidSetting {
                    setting_id,
                    value,
                    expected_error_code,
                }
            })
        })
        .collect()
}

fn production_invalid_setting(setting_id: u16, value: u32) -> Option<ErrorCode> {
    match setting_id {
        SETTINGS_ENABLE_PUSH if value > 1 => Some(ErrorCode::ProtocolError),
        SETTINGS_INITIAL_WINDOW_SIZE if value > MAX_INITIAL_WINDOW_SIZE => {
            Some(ErrorCode::FlowControlError)
        }
        SETTINGS_MAX_FRAME_SIZE if !(MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&value) => {
            Some(ErrorCode::ProtocolError)
        }
        _ => None,
    }
}

fn test_settings_validation_invariants(
    input: &H2SettingsInvalidValueInput,
    result: &Result<ParsedSettings, ValidationResult>,
) {
    // Invariant: ENABLE_PUSH values > 1 should always be invalid
    for invalid_setting in &input.invalid_settings {
        if matches!(invalid_setting.setting_id, KnownSettingId::EnablePush) {
            let invalid_value = MockH2SettingsParser::generate_invalid_value(
                &invalid_setting.setting_id,
                &invalid_setting.invalid_value_strategy,
            );
            if invalid_value > 1 {
                match result {
                    Ok(parsed) => {
                        // Should be recorded as invalid
                        let has_invalid_push = parsed.invalid_settings.iter().any(|entry| {
                            entry.setting_id == SETTINGS_ENABLE_PUSH && entry.invalid_value > 1
                        });
                        assert!(
                            has_invalid_push
                                || matches!(
                                    input.test_scenario.error_handling,
                                    ErrorHandling::ContinueValid
                                ),
                            "ENABLE_PUSH value > 1 should be invalid: {}",
                            invalid_value
                        );
                    }
                    Err(ValidationResult::ProtocolError(_)) => {
                        // Expected: rejection
                    }
                    Err(_) => {
                        // Other errors acceptable
                    }
                }
            }
        }
    }

    // Invariant: INITIAL_WINDOW_SIZE > 2^31-1 should always be invalid
    for invalid_setting in &input.invalid_settings {
        if matches!(
            invalid_setting.setting_id,
            KnownSettingId::InitialWindowSize
        ) {
            let invalid_value = MockH2SettingsParser::generate_invalid_value(
                &invalid_setting.setting_id,
                &invalid_setting.invalid_value_strategy,
            );
            if invalid_value > MAX_INITIAL_WINDOW_SIZE {
                match result {
                    Ok(parsed) => {
                        let has_invalid_window = parsed.invalid_settings.iter().any(|entry| {
                            entry.setting_id == SETTINGS_INITIAL_WINDOW_SIZE
                                && entry.invalid_value > MAX_INITIAL_WINDOW_SIZE
                        });
                        assert!(
                            has_invalid_window
                                || matches!(
                                    input.test_scenario.error_handling,
                                    ErrorHandling::ContinueValid
                                ),
                            "INITIAL_WINDOW_SIZE > 2^31-1 should be invalid: {}",
                            invalid_value
                        );
                    }
                    Err(ValidationResult::ProtocolError(_)) => {
                        // Expected: rejection
                    }
                    Err(_) => {
                        // Other errors acceptable
                    }
                }
            }
        }
    }

    // Invariant: MAX_FRAME_SIZE outside [16384, 16777215] should be invalid
    for invalid_setting in &input.invalid_settings {
        if matches!(invalid_setting.setting_id, KnownSettingId::MaxFrameSize) {
            let invalid_value = MockH2SettingsParser::generate_invalid_value(
                &invalid_setting.setting_id,
                &invalid_setting.invalid_value_strategy,
            );
            if !(MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&invalid_value) {
                match result {
                    Ok(parsed) => {
                        let has_invalid_frame_size = parsed.invalid_settings.iter().any(|entry| {
                            entry.setting_id == SETTINGS_MAX_FRAME_SIZE
                                && (entry.invalid_value < MIN_MAX_FRAME_SIZE
                                    || entry.invalid_value > MAX_MAX_FRAME_SIZE)
                        });
                        assert!(
                            has_invalid_frame_size
                                || matches!(
                                    input.test_scenario.error_handling,
                                    ErrorHandling::ContinueValid
                                ),
                            "MAX_FRAME_SIZE outside [16384, 16777215] should be invalid: {}",
                            invalid_value
                        );
                    }
                    Err(ValidationResult::ProtocolError(_)) => {
                        // Expected: rejection
                    }
                    Err(_) => {
                        // Other errors acceptable
                    }
                }
            }
        }
    }

    // Invariant: Frame with non-zero stream ID should be rejected
    if input.frame_options.stream_id != 0 {
        match result {
            Ok(_) => {
                panic!("SETTINGS frame with non-zero stream ID should be rejected");
            }
            Err(ValidationResult::FrameError(FrameErrorType::InvalidStreamId)) => {
                // Expected: frame error
            }
            Err(_) => {
                // Other errors also acceptable
            }
        }
    }

    // Invariant: ACK frame with payload should be rejected
    if input.frame_options.ack_flag {
        let frame_data = MockH2SettingsParser::build_settings_frame(input);
        if !frame_data.is_empty() {
            match result {
                Ok(_) => {
                    panic!("SETTINGS ACK frame with payload should be rejected");
                }
                Err(ValidationResult::FrameError(FrameErrorType::AckWithPayload)) => {
                    // Expected: frame error
                }
                Err(_) => {
                    // Other errors also acceptable
                }
            }
        }
    }

    // Invariant: Frame size must be multiple of 6
    let frame_data = MockH2SettingsParser::build_settings_frame(input);
    if !frame_data.len().is_multiple_of(6) {
        match result {
            Ok(_) => {
                panic!("SETTINGS frame with size not multiple of 6 should be rejected");
            }
            Err(ValidationResult::FrameError(FrameErrorType::FrameSizeError)) => {
                // Expected: frame error
            }
            Err(_) => {
                // Other errors also acceptable
            }
        }
    }

    // Invariant: Successful parsing should have correct number of settings
    if let Ok(parsed) = result {
        let expected_total = input.valid_settings.len() + input.invalid_settings.len();
        let actual_total = parsed.valid_settings.len() + parsed.invalid_settings.len();

        match input.test_scenario.error_handling {
            ErrorHandling::ContinueValid => {
                assert_eq!(
                    actual_total, expected_total,
                    "ContinueValid mode should process all settings"
                );
            }
            _ => {
                // Other modes may stop early on invalid settings
                assert!(
                    actual_total <= expected_total,
                    "Should not process more settings than provided"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enable_push_invalid_values() {
        let mut parser =
            MockH2SettingsParser::new(ValidationMode::StrictRFC, ErrorHandling::FailFast);

        // Valid values: 0 and 1
        let valid_frame_0 = [0x00, 0x02, 0x00, 0x00, 0x00, 0x00]; // ENABLE_PUSH = 0
        let result = parser.parse_settings_frame(&valid_frame_0, 0, 0);
        assert!(result.is_ok());

        let valid_frame_1 = [0x00, 0x02, 0x00, 0x00, 0x00, 0x01]; // ENABLE_PUSH = 1
        let result = parser.parse_settings_frame(&valid_frame_1, 0, 0);
        assert!(result.is_ok());

        // Invalid value: 2
        let invalid_frame = [0x00, 0x02, 0x00, 0x00, 0x00, 0x02]; // ENABLE_PUSH = 2
        let result = parser.parse_settings_frame(&invalid_frame, 0, 0);
        assert!(matches!(result, Err(ValidationResult::ProtocolError(_))));
    }

    #[test]
    fn test_initial_window_size_overflow() {
        let mut parser =
            MockH2SettingsParser::new(ValidationMode::StrictRFC, ErrorHandling::FailFast);

        // Valid value: 2^31-1
        let valid_frame = [0x00, 0x04, 0x7F, 0xFF, 0xFF, 0xFF]; // INITIAL_WINDOW_SIZE = 2^31-1
        let result = parser.parse_settings_frame(&valid_frame, 0, 0);
        assert!(result.is_ok());

        // Invalid value: 2^31
        let invalid_frame = [0x00, 0x04, 0x80, 0x00, 0x00, 0x00]; // INITIAL_WINDOW_SIZE = 2^31
        let result = parser.parse_settings_frame(&invalid_frame, 0, 0);
        assert!(matches!(result, Err(ValidationResult::ProtocolError(_))));

        // Invalid value: u32::MAX
        let max_frame = [0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF]; // INITIAL_WINDOW_SIZE = u32::MAX
        let result = parser.parse_settings_frame(&max_frame, 0, 0);
        assert!(matches!(result, Err(ValidationResult::ProtocolError(_))));
    }

    #[test]
    fn test_max_frame_size_boundaries() {
        let mut parser =
            MockH2SettingsParser::new(ValidationMode::StrictRFC, ErrorHandling::FailFast);

        // Valid minimum: 16384
        let min_valid = [0x00, 0x05, 0x00, 0x00, 0x40, 0x00]; // MAX_FRAME_SIZE = 16384
        let result = parser.parse_settings_frame(&min_valid, 0, 0);
        assert!(result.is_ok());

        // Valid maximum: 16777215
        let max_valid = [0x00, 0x05, 0x00, 0xFF, 0xFF, 0xFF]; // MAX_FRAME_SIZE = 16777215
        let result = parser.parse_settings_frame(&max_valid, 0, 0);
        assert!(result.is_ok());

        // Invalid: below minimum
        let below_min = [0x00, 0x05, 0x00, 0x00, 0x3F, 0xFF]; // MAX_FRAME_SIZE = 16383
        let result = parser.parse_settings_frame(&below_min, 0, 0);
        assert!(matches!(result, Err(ValidationResult::ProtocolError(_))));

        // Invalid: above maximum
        let above_max = [0x00, 0x05, 0x01, 0x00, 0x00, 0x00]; // MAX_FRAME_SIZE = 16777216
        let result = parser.parse_settings_frame(&above_max, 0, 0);
        assert!(matches!(result, Err(ValidationResult::ProtocolError(_))));

        // Invalid: zero
        let zero_frame = [0x00, 0x05, 0x00, 0x00, 0x00, 0x00]; // MAX_FRAME_SIZE = 0
        let result = parser.parse_settings_frame(&zero_frame, 0, 0);
        assert!(matches!(result, Err(ValidationResult::ProtocolError(_))));

        // Invalid: very small value like 10 from the example
        let small_frame = [0x00, 0x05, 0x00, 0x00, 0x00, 0x0A]; // MAX_FRAME_SIZE = 10
        let result = parser.parse_settings_frame(&small_frame, 0, 0);
        assert!(matches!(result, Err(ValidationResult::ProtocolError(_))));
    }

    #[test]
    fn test_frame_level_validation() {
        let mut parser =
            MockH2SettingsParser::new(ValidationMode::StrictRFC, ErrorHandling::FailFast);

        // Invalid: non-zero stream ID
        let valid_settings = [0x00, 0x01, 0x00, 0x00, 0x10, 0x00]; // HEADER_TABLE_SIZE = 4096
        let result = parser.parse_settings_frame(&valid_settings, 0, 1); // stream ID = 1
        assert!(matches!(
            result,
            Err(ValidationResult::FrameError(
                FrameErrorType::InvalidStreamId
            ))
        ));

        // Invalid: ACK with payload
        let result = parser.parse_settings_frame(&valid_settings, 0x01, 0); // ACK flag set
        assert!(matches!(
            result,
            Err(ValidationResult::FrameError(FrameErrorType::AckWithPayload))
        ));

        // Invalid: frame size not multiple of 6
        let invalid_size_frame = [0x00, 0x01, 0x00, 0x00, 0x10]; // Only 5 bytes
        let result = parser.parse_settings_frame(&invalid_size_frame, 0, 0);
        assert!(matches!(
            result,
            Err(ValidationResult::FrameError(FrameErrorType::FrameSizeError))
        ));
    }

    #[test]
    fn test_mixed_valid_invalid_settings() {
        let mut parser =
            MockH2SettingsParser::new(ValidationMode::StrictRFC, ErrorHandling::ValidateAll);

        // Mix of valid and invalid settings
        let mixed_frame = [
            0x00, 0x01, 0x00, 0x00, 0x10, 0x00, // HEADER_TABLE_SIZE = 4096 (valid)
            0x00, 0x02, 0x00, 0x00, 0x00, 0x05, // ENABLE_PUSH = 5 (invalid)
            0x00, 0x05, 0x00, 0x00, 0x00, 0x0A, // MAX_FRAME_SIZE = 10 (invalid)
        ];

        let result = parser.parse_settings_frame(&mixed_frame, 0, 0);
        assert!(matches!(result, Err(ValidationResult::ProtocolError(_))));
    }

    #[test]
    fn test_continue_valid_mode() {
        let mut parser =
            MockH2SettingsParser::new(ValidationMode::StrictRFC, ErrorHandling::ContinueValid);

        // Mix of valid and invalid settings
        let mixed_frame = [
            0x00, 0x01, 0x00, 0x00, 0x10, 0x00, // HEADER_TABLE_SIZE = 4096 (valid)
            0x00, 0x02, 0x00, 0x00, 0x00, 0x05, // ENABLE_PUSH = 5 (invalid)
        ];

        let result = parser.parse_settings_frame(&mixed_frame, 0, 0);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.valid_settings.len(), 1);
        assert_eq!(parsed.invalid_settings.len(), 1);
        assert_ne!(parsed.validation_result, ValidationResult::AllValid);
    }

    #[test]
    fn test_invalid_value_generation() {
        // Test ENABLE_PUSH invalid values
        let enable_push_invalid = MockH2SettingsParser::generate_invalid_value(
            &KnownSettingId::EnablePush,
            &InvalidValueStrategy::AboveMaximum { offset: 1 },
        );
        assert!(enable_push_invalid > 1);

        // Test MAX_FRAME_SIZE below minimum
        let frame_size_below = MockH2SettingsParser::generate_invalid_value(
            &KnownSettingId::MaxFrameSize,
            &InvalidValueStrategy::BelowMinimum { offset: 1 },
        );
        assert!(frame_size_below < MIN_MAX_FRAME_SIZE);

        // Test INITIAL_WINDOW_SIZE above maximum
        let window_size_above = MockH2SettingsParser::generate_invalid_value(
            &KnownSettingId::InitialWindowSize,
            &InvalidValueStrategy::AboveMaximum { offset: 1 },
        );
        assert!(window_size_above > MAX_INITIAL_WINDOW_SIZE);
    }

    #[test]
    fn test_settings_application() {
        let mut parser =
            MockH2SettingsParser::new(ValidationMode::StrictRFC, ErrorHandling::FailFast);

        let settings_frame = [
            0x00, 0x01, 0x00, 0x00, 0x20, 0x00, // HEADER_TABLE_SIZE = 8192
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH = 0
            0x00, 0x05, 0x00, 0x00, 0x80, 0x00, // MAX_FRAME_SIZE = 32768
        ];

        let result = parser.parse_settings_frame(&settings_frame, 0, 0);
        assert!(result.is_ok());

        // Verify settings were applied
        assert_eq!(parser.settings_state.header_table_size, 8192);
        assert_eq!(parser.settings_state.enable_push, false);
        assert_eq!(parser.settings_state.max_frame_size, 32768);
    }
}
