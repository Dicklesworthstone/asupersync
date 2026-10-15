#![no_main]
#![allow(dead_code)]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// HTTP/2 SETTINGS duplicate ID fuzz target.
///
/// Tests RFC 7540 §6.5.2 compliance for SETTINGS frames containing duplicate
/// setting IDs with different values. Per the specification: "A SETTINGS frame
/// MAY contain multiple values for the same identifier. If it does, the last
/// value overrides any earlier values for that same identifier."
///
/// Critical test scenarios:
/// - Same setting ID appearing multiple times in single frame
/// - Different values for duplicate settings (last value wins)
/// - All setting types: table size, push enable, max concurrent streams, etc.
/// - Order dependency verification
/// - Edge cases: alternating values, extreme duplicates

#[derive(Arbitrary, Debug, Clone)]
struct SettingsDuplicateInput {
    /// Settings frame with potential duplicates
    settings_frame: SettingsFrame,

    /// Test scenarios for different duplicate patterns
    duplicate_patterns: Vec<DuplicatePattern>,

    /// Connection state context
    connection_state: ConnectionState,

    /// Parser configuration
    parser_config: SettingsParserConfig,
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingsFrame {
    /// Raw settings entries (may contain duplicates)
    settings: Vec<SettingEntry>,

    /// Whether this is an ACK frame
    ack_flag: bool,

    /// Stream ID (should be 0 for SETTINGS)
    stream_id: u32,
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingEntry {
    /// Setting identifier (RFC 7540 §6.5.2)
    setting_id: SettingId,

    /// Setting value
    value: u32,
}

#[derive(Arbitrary, Debug, Clone, PartialEq, Eq, Hash)]
enum SettingId {
    HeaderTableSize,
    EnablePush,
    MaxConcurrentStreams,
    InitialWindowSize,
    MaxFrameSize,
    MaxHeaderListSize,
    Unknown(u16),
}

impl SettingId {
    fn from_u16(id: u16) -> Self {
        match id {
            1 => SettingId::HeaderTableSize,
            2 => SettingId::EnablePush,
            3 => SettingId::MaxConcurrentStreams,
            4 => SettingId::InitialWindowSize,
            5 => SettingId::MaxFrameSize,
            6 => SettingId::MaxHeaderListSize,
            _ => SettingId::Unknown(id),
        }
    }

    fn to_u16(&self) -> u16 {
        match self {
            SettingId::HeaderTableSize => 1,
            SettingId::EnablePush => 2,
            SettingId::MaxConcurrentStreams => 3,
            SettingId::InitialWindowSize => 4,
            SettingId::MaxFrameSize => 5,
            SettingId::MaxHeaderListSize => 6,
            SettingId::Unknown(id) => *id,
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct DuplicatePattern {
    /// Setting ID to duplicate
    setting_id: SettingId,

    /// Values to use (in order - last should win)
    values: Vec<u32>,

    /// Expected final value (should be last)
    expected_final_value: u32,
}

#[derive(Arbitrary, Debug, Clone)]
struct ConnectionState {
    /// Current setting values before update
    current_settings: HashMap<SettingId, u32>,

    /// Whether connection is in valid state
    connection_active: bool,

    /// Remote peer capabilities
    peer_capabilities: PeerCapabilities,
}

impl Default for ConnectionState {
    fn default() -> Self {
        let mut default_settings = HashMap::new();
        default_settings.insert(SettingId::HeaderTableSize, 4096);
        default_settings.insert(SettingId::EnablePush, 1);
        default_settings.insert(SettingId::MaxConcurrentStreams, u32::MAX);
        default_settings.insert(SettingId::InitialWindowSize, 65535);
        default_settings.insert(SettingId::MaxFrameSize, 16384);
        default_settings.insert(SettingId::MaxHeaderListSize, u32::MAX);

        Self {
            current_settings: default_settings,
            connection_active: true,
            peer_capabilities: PeerCapabilities::default(),
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct PeerCapabilities {
    supports_push: bool,
    max_header_table_size: u32,
    max_frame_size: u32,
}

impl Default for PeerCapabilities {
    fn default() -> Self {
        Self {
            supports_push: true,
            max_header_table_size: 65536,
            max_frame_size: 16777215, // 2^24-1 max per RFC
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingsParserConfig {
    /// Whether to enforce strict RFC validation
    strict_validation: bool,

    /// Whether to track duplicate occurrences
    track_duplicates: bool,

    /// Maximum number of settings in single frame
    max_settings_count: usize,

    /// Whether to validate setting value ranges
    validate_ranges: bool,
}

impl Default for SettingsParserConfig {
    fn default() -> Self {
        Self {
            strict_validation: true,
            track_duplicates: true,
            max_settings_count: 100,
            validate_ranges: true,
        }
    }
}

/// Mock HTTP/2 SETTINGS parser for testing duplicate handling
struct MockSettingsParser {
    config: SettingsParserConfig,
    duplicate_stats: DuplicateStats,
}

impl MockSettingsParser {
    fn new(config: SettingsParserConfig) -> Self {
        Self {
            config,
            duplicate_stats: DuplicateStats::default(),
        }
    }

    /// Parse SETTINGS frame and handle duplicates per RFC 7540 §6.5.2
    fn parse_settings_frame(
        &mut self,
        frame: &SettingsFrame,
        state: &mut ConnectionState,
    ) -> SettingsParseResult {
        // Validate basic frame structure
        if frame.stream_id != 0 {
            return SettingsParseResult::ProtocolError(
                "SETTINGS frame must be on stream 0".to_string(),
            );
        }

        if frame.ack_flag && !frame.settings.is_empty() {
            return SettingsParseResult::ProtocolError(
                "SETTINGS ACK frame must be empty".to_string(),
            );
        }

        if frame.ack_flag {
            return SettingsParseResult::Ack;
        }

        // Check frame size limits
        if frame.settings.len() > self.config.max_settings_count {
            return SettingsParseResult::ProtocolError(format!(
                "Too many settings: {} > {}",
                frame.settings.len(),
                self.config.max_settings_count
            ));
        }

        // Process settings with duplicate handling
        self.process_settings_with_duplicates(&frame.settings, state)
    }

    fn process_settings_with_duplicates(
        &mut self,
        settings: &[SettingEntry],
        state: &mut ConnectionState,
    ) -> SettingsParseResult {
        let mut processed_settings = HashMap::new();
        let mut duplicate_tracking = HashMap::new();
        let mut processing_order = Vec::new();

        // RFC 7540 §6.5.2: "the last value overrides any earlier values"
        for (index, setting) in settings.iter().enumerate() {
            // Track duplicates if enabled
            if self.config.track_duplicates {
                let count = duplicate_tracking
                    .entry(setting.setting_id.clone())
                    .or_insert(0);
                *count += 1;

                if *count > 1 {
                    self.duplicate_stats.total_duplicates += 1;
                    self.duplicate_stats
                        .duplicate_settings
                        .entry(setting.setting_id.clone())
                        .or_default()
                        .push(setting.value);
                }
            }

            // Validate setting value if enabled
            if self.config.validate_ranges
                && let Err(msg) = self.validate_setting_value(&setting.setting_id, setting.value)
            {
                return SettingsParseResult::ProtocolError(msg);
            }

            // Last value wins - this overwrites any previous value
            processed_settings.insert(setting.setting_id.clone(), setting.value);
            processing_order.push((setting.setting_id.clone(), setting.value, index));
        }

        // Apply processed settings to connection state
        let mut updates = Vec::new();
        for (setting_id, new_value) in &processed_settings {
            let old_value = state.current_settings.get(setting_id).copied();

            // Apply specific setting validation
            match self.apply_setting(setting_id, *new_value, state) {
                Ok(()) => {
                    updates.push(SettingUpdate {
                        setting_id: setting_id.clone(),
                        old_value,
                        new_value: *new_value,
                        duplicate_count: duplicate_tracking.get(setting_id).copied().unwrap_or(1),
                    });
                }
                Err(msg) => {
                    return SettingsParseResult::ProtocolError(msg);
                }
            }
        }

        SettingsParseResult::Success {
            updates,
            duplicate_stats: self.duplicate_stats.clone(),
            processing_order,
        }
    }

    fn validate_setting_value(&self, setting_id: &SettingId, value: u32) -> Result<(), String> {
        match setting_id {
            SettingId::EnablePush => {
                if value > 1 {
                    return Err(format!("ENABLE_PUSH must be 0 or 1, got {}", value));
                }
            }

            SettingId::InitialWindowSize => {
                if value > 2_147_483_647 {
                    // 2^31-1
                    return Err(format!("INITIAL_WINDOW_SIZE {} exceeds maximum", value));
                }
            }

            SettingId::MaxFrameSize => {
                if !(16384..=16777215).contains(&value) {
                    // 2^14 to 2^24-1
                    return Err(format!("MAX_FRAME_SIZE {} out of valid range", value));
                }
            }

            SettingId::HeaderTableSize => {
                // No explicit limit in RFC, but validate against peer capabilities
                // Implementation-specific validation can go here
            }

            SettingId::MaxConcurrentStreams => {
                // Any value is valid (u32::MAX means unlimited)
            }

            SettingId::MaxHeaderListSize => {
                // Any value is valid
            }

            SettingId::Unknown(_) => {
                // Unknown settings should be ignored per RFC 7540 §6.5.2
            }
        }

        Ok(())
    }

    fn apply_setting(
        &self,
        setting_id: &SettingId,
        value: u32,
        state: &mut ConnectionState,
    ) -> Result<(), String> {
        // Apply setting-specific logic
        match setting_id {
            SettingId::EnablePush => {
                if value == 0 && state.peer_capabilities.supports_push {
                    // Disabling push when it was enabled
                    state.peer_capabilities.supports_push = false;
                }
            }

            SettingId::HeaderTableSize => {
                if value > state.peer_capabilities.max_header_table_size {
                    return Err(format!(
                        "Header table size {} exceeds peer limit {}",
                        value, state.peer_capabilities.max_header_table_size
                    ));
                }
            }

            SettingId::MaxFrameSize => {
                state.peer_capabilities.max_frame_size = value;
            }

            _ => {
                // Other settings don't require special validation
            }
        }

        // Update state
        state.current_settings.insert(setting_id.clone(), value);
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
struct DuplicateStats {
    total_duplicates: u32,
    duplicate_settings: HashMap<SettingId, Vec<u32>>,
}

#[derive(Debug, PartialEq)]
struct SettingUpdate {
    setting_id: SettingId,
    old_value: Option<u32>,
    new_value: u32,
    duplicate_count: u32,
}

#[derive(Debug, PartialEq)]
enum SettingsParseResult {
    /// Settings parsed and applied successfully
    Success {
        updates: Vec<SettingUpdate>,
        duplicate_stats: DuplicateStats,
        processing_order: Vec<(SettingId, u32, usize)>,
    },

    /// SETTINGS ACK frame (empty)
    Ack,

    /// Protocol error (connection error)
    ProtocolError(String),
}

fuzz_target!(|input: SettingsDuplicateInput| {
    // Normalize input for reasonable fuzzing bounds
    let mut input = input;
    if input.settings_frame.settings.len() > 50 {
        input.settings_frame.settings.truncate(50); // Limit for performance
    }

    let mut parser = MockSettingsParser::new(input.parser_config.clone());
    let mut state = input.connection_state.clone();

    // Test basic duplicate patterns from input
    for pattern in input.duplicate_patterns.iter().take(5) {
        // Limit patterns
        let mut test_frame = SettingsFrame {
            settings: Vec::new(),
            ack_flag: false,
            stream_id: 0,
        };

        // Add settings according to pattern
        for value in &pattern.values {
            test_frame.settings.push(SettingEntry {
                setting_id: pattern.setting_id.clone(),
                value: *value,
            });
        }

        let parse_result = parser.parse_settings_frame(&test_frame, &mut state);

        match parse_result {
            SettingsParseResult::Success {
                updates,
                duplicate_stats,
                processing_order,
            } => {
                // Verify last value wins
                if pattern.values.len() > 1 {
                    let final_update = updates.iter().find(|u| u.setting_id == pattern.setting_id);

                    if let Some(update) = final_update {
                        assert_eq!(
                            update.new_value,
                            *pattern.values.last().unwrap(),
                            "Last value should win for setting {:?}: expected {}, got {}",
                            pattern.setting_id,
                            pattern.values.last().unwrap(),
                            update.new_value
                        );

                        assert!(
                            update.duplicate_count > 1,
                            "Duplicate count should be > 1 for duplicated setting"
                        );
                    }

                    // Verify duplicate statistics
                    if parser.config.track_duplicates {
                        assert!(
                            duplicate_stats.total_duplicates > 0,
                            "Should track duplicates when enabled"
                        );

                        if let Some(tracked_values) =
                            duplicate_stats.duplicate_settings.get(&pattern.setting_id)
                        {
                            assert!(
                                tracked_values.len() >= pattern.values.len() - 1,
                                "Should track all but first occurrence as duplicates"
                            );
                        }
                    }
                }

                // Verify processing order integrity
                for (i, (_setting_id, _value, original_index)) in
                    processing_order.iter().enumerate()
                {
                    assert_eq!(
                        *original_index, i,
                        "Processing order should preserve original sequence"
                    );
                }
            }

            SettingsParseResult::ProtocolError(ref msg) => {
                // Check if error is due to invalid values (which is acceptable)
                if parser.config.validate_ranges {
                    for value in &pattern.values {
                        if let Err(validation_error) =
                            parser.validate_setting_value(&pattern.setting_id, *value)
                        {
                            assert!(
                                msg.contains(&validation_error)
                                    || msg.contains("out of valid range")
                                    || msg.contains("exceeds maximum"),
                                "Protocol error should explain validation failure: {}",
                                msg
                            );
                            break;
                        }
                    }
                }
            }

            SettingsParseResult::Ack => {
                // ACK frames should only occur with ack_flag=true and empty settings
                assert!(
                    test_frame.ack_flag && test_frame.settings.is_empty(),
                    "ACK result should only occur for ACK frames"
                );
            }
        }
    }

    // Test main frame with potential duplicates
    let main_result = parser.parse_settings_frame(&input.settings_frame, &mut state);

    match main_result {
        SettingsParseResult::Success {
            updates,
            duplicate_stats,
            ..
        } => {
            // Verify state consistency
            for update in &updates {
                let current_value = state.current_settings.get(&update.setting_id);
                assert_eq!(
                    current_value,
                    Some(&update.new_value),
                    "State should reflect final setting value"
                );
            }

            // Verify duplicate handling
            let mut setting_counts = HashMap::new();
            for setting in &input.settings_frame.settings {
                *setting_counts
                    .entry(setting.setting_id.clone())
                    .or_insert(0) += 1;
            }

            for (setting_id, count) in setting_counts {
                if count > 1 {
                    // Should have tracked this as duplicate
                    if parser.config.track_duplicates {
                        assert!(
                            duplicate_stats.duplicate_settings.contains_key(&setting_id)
                                || duplicate_stats.total_duplicates > 0,
                            "Should track duplicates for setting {:?}",
                            setting_id
                        );
                    }

                    // Final value should be from last occurrence
                    let last_occurrence = input
                        .settings_frame
                        .settings
                        .iter()
                        .rev()
                        .find(|s| s.setting_id == setting_id);

                    if let Some(last_setting) = last_occurrence {
                        assert_eq!(
                            state.current_settings.get(&setting_id),
                            Some(&last_setting.value),
                            "State should have last occurrence value for {:?}",
                            setting_id
                        );
                    }
                }
            }
        }

        SettingsParseResult::ProtocolError(_) => {
            // Protocol errors are acceptable for malformed frames
        }

        SettingsParseResult::Ack => {
            // ACK is acceptable for ACK frames
        }
    }

    // Verify no panics occurred during duplicate processing
    // (Implicit - if we reach here without panicking, the test passed)

    // Additional edge case: alternating values for same setting
    let alternating_frame = SettingsFrame {
        settings: vec![
            SettingEntry {
                setting_id: SettingId::MaxConcurrentStreams,
                value: 100,
            },
            SettingEntry {
                setting_id: SettingId::InitialWindowSize,
                value: 32768,
            },
            SettingEntry {
                setting_id: SettingId::MaxConcurrentStreams,
                value: 200,
            },
            SettingEntry {
                setting_id: SettingId::InitialWindowSize,
                value: 65536,
            },
            SettingEntry {
                setting_id: SettingId::MaxConcurrentStreams,
                value: 300,
            },
        ],
        ack_flag: false,
        stream_id: 0,
    };

    let alternating_result = parser.parse_settings_frame(&alternating_frame, &mut state);
    if let SettingsParseResult::Success { .. } = alternating_result {
        // Verify last values won
        assert_eq!(
            state.current_settings.get(&SettingId::MaxConcurrentStreams),
            Some(&300)
        );
        assert_eq!(
            state.current_settings.get(&SettingId::InitialWindowSize),
            Some(&65536)
        );
    }
});
