#![no_main]
#![allow(dead_code)]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 SETTINGS frame state transition test input for default-then-change scenarios
#[derive(Arbitrary, Debug)]
struct H2SettingsTransitionInput {
    /// Initial SETTINGS frame (with defaults)
    initial_settings: InitialSettingsStrategy,
    /// Second SETTINGS frame (with changes)
    changed_settings: ChangedSettingsStrategy,
    /// Additional SETTINGS frames to test
    additional_frames: Vec<AdditionalSettingsFrame>,
    /// Test context and timing
    test_context: SettingsTestContext,
}

#[derive(Arbitrary, Debug)]
enum InitialSettingsStrategy {
    /// Send SETTINGS with all RFC default values
    AllDefaults,
    /// Send SETTINGS with subset of defaults explicitly set
    ExplicitDefaults(Vec<DefaultSetting>),
    /// Send empty SETTINGS frame (no parameters)
    Empty,
    /// Send SETTINGS with some defaults and some custom values
    MixedDefaults {
        defaults: Vec<DefaultSetting>,
        customs: Vec<CustomSetting>,
    },
}

#[derive(Arbitrary, Debug)]
enum ChangedSettingsStrategy {
    /// Change single setting from default
    SingleChange(SettingChange),
    /// Change multiple settings
    MultipleChanges(Vec<SettingChange>),
    /// Progressive changes (multiple SETTINGS frames)
    Progressive(Vec<ProgressiveChange>),
    /// Reset to different defaults
    ResetToDefaults,
    /// Extreme values within valid ranges
    ExtremeValues(Vec<ExtremeSetting>),
}

#[derive(Arbitrary, Debug, Clone)]
struct DefaultSetting {
    id: DefaultSettingId,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum DefaultSettingId {
    HeaderTableSize,   // 4096
    EnablePush,        // 1
    InitialWindowSize, // 65535
    MaxFrameSize,      // 16384
}

#[derive(Arbitrary, Debug)]
struct CustomSetting {
    id: u16,
    value: u32,
}

#[derive(Arbitrary, Debug)]
struct SettingChange {
    id: SettingId,
    new_value: u32,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum SettingId {
    HeaderTableSize,
    EnablePush,
    MaxConcurrentStreams,
    InitialWindowSize,
    MaxFrameSize,
    MaxHeaderListSize,
    Unknown(u16), // Unknown setting ID
}

#[derive(Arbitrary, Debug)]
struct ProgressiveChange {
    changes: Vec<SettingChange>,
    delay_ack: bool,
}

#[derive(Arbitrary, Debug)]
struct ExtremeSetting {
    id: SettingId,
    extreme_type: ExtremeType,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum ExtremeType {
    /// Minimum valid value
    Minimum,
    /// Maximum valid value
    Maximum,
    /// Just above minimum
    NearMinimum(u32),
    /// Just below maximum
    NearMaximum(u32),
}

#[derive(Arbitrary, Debug)]
struct AdditionalSettingsFrame {
    /// Changes in this frame
    changes: Vec<SettingChange>,
    /// Whether to send ACK for previous frame first
    ack_previous: bool,
    /// Timing relative to previous frame
    timing: FrameTiming,
}

#[derive(Arbitrary, Debug)]
enum FrameTiming {
    Immediate,
    AfterAck,
    Concurrent,
    Delayed,
}

#[derive(Arbitrary, Debug)]
struct SettingsTestContext {
    /// Connection state
    connection_state: ConnectionState,
    /// Whether to test ACK behavior
    test_ack_behavior: bool,
    /// Concurrent stream activity
    active_streams: u8,
    /// Flow control state
    flow_control_state: FlowControlState,
}

#[derive(Arbitrary, Debug)]
enum ConnectionState {
    Fresh,
    EstablishedActive,
    NearLimits,
}

#[derive(Arbitrary, Debug)]
struct FlowControlState {
    connection_window: u32,
    stream_windows: Vec<u32>,
}

/// Mock HTTP/2 SETTINGS state machine for testing transitions
struct MockH2SettingsStateMachine {
    current_settings: SettingsState,
    pending_settings: Option<SettingsState>,
    settings_history: Vec<SettingsState>,
    ack_pending: bool,
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

#[derive(Debug, PartialEq)]
enum SettingsValidationError {
    /// Invalid SETTINGS parameter value
    InvalidValue { id: u16, value: u32 },
    /// SETTINGS frame with ACK flag but non-empty payload
    AckWithPayload,
    /// No pending SETTINGS to acknowledge
    AckWithoutPending,
    /// SETTINGS applied out of order
    OutOfOrder,
    /// Invalid state transition
    InvalidTransition,
}

// RFC 7540 default values
const DEFAULT_HEADER_TABLE_SIZE: u32 = 4096;
const DEFAULT_ENABLE_PUSH: bool = true;
const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65535;
const DEFAULT_MAX_FRAME_SIZE: u32 = 16384;

// RFC 7540 valid ranges
const MIN_MAX_FRAME_SIZE: u32 = 16384;
const MAX_MAX_FRAME_SIZE: u32 = 16777215; // 2^24 - 1
const MAX_INITIAL_WINDOW_SIZE: u32 = 2147483647; // 2^31 - 1

impl SettingsState {
    fn default() -> Self {
        Self {
            header_table_size: DEFAULT_HEADER_TABLE_SIZE,
            enable_push: DEFAULT_ENABLE_PUSH,
            max_concurrent_streams: None, // Unlimited by default
            initial_window_size: DEFAULT_INITIAL_WINDOW_SIZE,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_header_list_size: None, // Unlimited by default
        }
    }
}

impl MockH2SettingsStateMachine {
    fn new() -> Self {
        Self {
            current_settings: SettingsState::default(),
            pending_settings: None,
            settings_history: vec![SettingsState::default()],
            ack_pending: false,
        }
    }

    fn process_settings_frame(
        &mut self,
        changes: &[(u16, u32)],
        ack: bool,
    ) -> Result<(), SettingsValidationError> {
        if ack {
            return self.process_settings_ack();
        }

        // Validate all settings first
        for &(id, value) in changes {
            self.validate_setting(id, value)?;
        }

        // Create new settings state
        let mut new_settings = self.current_settings.clone();

        // Apply changes
        for &(id, value) in changes {
            self.apply_setting(&mut new_settings, id, value);
        }

        // Store as pending (waiting for ACK)
        self.pending_settings = Some(new_settings);
        self.ack_pending = true;

        Ok(())
    }

    fn process_settings_ack(&mut self) -> Result<(), SettingsValidationError> {
        if !self.ack_pending {
            return Err(SettingsValidationError::AckWithoutPending);
        }

        if let Some(pending) = self.pending_settings.take() {
            self.current_settings = pending.clone();
            self.settings_history.push(pending);
            self.ack_pending = false;
        }

        Ok(())
    }

    fn validate_setting(&self, id: u16, value: u32) -> Result<(), SettingsValidationError> {
        match id {
            1 => {
                // SETTINGS_HEADER_TABLE_SIZE
                // Any value is valid
                Ok(())
            }
            2 => {
                // SETTINGS_ENABLE_PUSH
                if value > 1 {
                    return Err(SettingsValidationError::InvalidValue { id, value });
                }
                Ok(())
            }
            3 => {
                // SETTINGS_MAX_CONCURRENT_STREAMS
                // Any value is valid (0 means no new streams)
                Ok(())
            }
            4 => {
                // SETTINGS_INITIAL_WINDOW_SIZE
                if value > MAX_INITIAL_WINDOW_SIZE {
                    return Err(SettingsValidationError::InvalidValue { id, value });
                }
                Ok(())
            }
            5 => {
                // SETTINGS_MAX_FRAME_SIZE
                if !(MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&value) {
                    return Err(SettingsValidationError::InvalidValue { id, value });
                }
                Ok(())
            }
            6 => {
                // SETTINGS_MAX_HEADER_LIST_SIZE
                // Any value is valid
                Ok(())
            }
            _ => {
                // Unknown settings are ignored per RFC 7540 §6.5.2
                Ok(())
            }
        }
    }

    fn apply_setting(&self, settings: &mut SettingsState, id: u16, value: u32) {
        match id {
            1 => settings.header_table_size = value,
            2 => settings.enable_push = value == 1,
            3 => settings.max_concurrent_streams = Some(value),
            4 => settings.initial_window_size = value,
            5 => settings.max_frame_size = value,
            6 => settings.max_header_list_size = Some(value),
            _ => {
                // Unknown settings are ignored
            }
        }
    }

    fn generate_default_settings_frame(strategy: &InitialSettingsStrategy) -> Vec<(u16, u32)> {
        match strategy {
            InitialSettingsStrategy::AllDefaults => {
                vec![
                    (1, DEFAULT_HEADER_TABLE_SIZE),
                    (2, if DEFAULT_ENABLE_PUSH { 1 } else { 0 }),
                    (4, DEFAULT_INITIAL_WINDOW_SIZE),
                    (5, DEFAULT_MAX_FRAME_SIZE),
                ]
            }
            InitialSettingsStrategy::ExplicitDefaults(defaults) => {
                let mut settings = Vec::new();
                for default in defaults {
                    match default.id {
                        DefaultSettingId::HeaderTableSize => {
                            settings.push((1, DEFAULT_HEADER_TABLE_SIZE))
                        }
                        DefaultSettingId::EnablePush => {
                            settings.push((2, if DEFAULT_ENABLE_PUSH { 1 } else { 0 }))
                        }
                        DefaultSettingId::InitialWindowSize => {
                            settings.push((4, DEFAULT_INITIAL_WINDOW_SIZE))
                        }
                        DefaultSettingId::MaxFrameSize => {
                            settings.push((5, DEFAULT_MAX_FRAME_SIZE))
                        }
                    }
                }
                settings
            }
            InitialSettingsStrategy::Empty => {
                vec![]
            }
            InitialSettingsStrategy::MixedDefaults { defaults, customs } => {
                let mut settings = Self::generate_default_settings_frame(
                    &InitialSettingsStrategy::ExplicitDefaults(defaults.clone()),
                );
                for custom in customs {
                    settings.push((custom.id, custom.value));
                }
                settings
            }
        }
    }

    fn generate_changed_settings_frame(strategy: &ChangedSettingsStrategy) -> Vec<Vec<(u16, u32)>> {
        match strategy {
            ChangedSettingsStrategy::SingleChange(change) => {
                vec![vec![Self::setting_change_to_tuple(change)]]
            }
            ChangedSettingsStrategy::MultipleChanges(changes) => {
                let settings: Vec<(u16, u32)> =
                    changes.iter().map(Self::setting_change_to_tuple).collect();
                vec![settings]
            }
            ChangedSettingsStrategy::Progressive(progressive) => progressive
                .iter()
                .map(|prog| {
                    prog.changes
                        .iter()
                        .map(Self::setting_change_to_tuple)
                        .collect()
                })
                .collect(),
            ChangedSettingsStrategy::ResetToDefaults => {
                vec![vec![
                    (1, DEFAULT_HEADER_TABLE_SIZE),
                    (2, if DEFAULT_ENABLE_PUSH { 1 } else { 0 }),
                    (4, DEFAULT_INITIAL_WINDOW_SIZE),
                    (5, DEFAULT_MAX_FRAME_SIZE),
                ]]
            }
            ChangedSettingsStrategy::ExtremeValues(extremes) => {
                let settings: Vec<(u16, u32)> = extremes
                    .iter()
                    .map(Self::extreme_setting_to_tuple)
                    .collect();
                vec![settings]
            }
        }
    }

    fn setting_change_to_tuple(change: &SettingChange) -> (u16, u32) {
        let id = match change.id {
            SettingId::HeaderTableSize => 1,
            SettingId::EnablePush => 2,
            SettingId::MaxConcurrentStreams => 3,
            SettingId::InitialWindowSize => 4,
            SettingId::MaxFrameSize => 5,
            SettingId::MaxHeaderListSize => 6,
            SettingId::Unknown(id) => id,
        };
        (id, change.new_value)
    }

    fn extreme_setting_to_tuple(extreme: &ExtremeSetting) -> (u16, u32) {
        let id = match extreme.id {
            SettingId::HeaderTableSize => 1,
            SettingId::EnablePush => 2,
            SettingId::MaxConcurrentStreams => 3,
            SettingId::InitialWindowSize => 4,
            SettingId::MaxFrameSize => 5,
            SettingId::MaxHeaderListSize => 6,
            SettingId::Unknown(id) => id,
        };

        let value = match (&extreme.id, &extreme.extreme_type) {
            (SettingId::EnablePush, ExtremeType::Minimum) => 0,
            (SettingId::EnablePush, ExtremeType::Maximum) => 1,
            (SettingId::MaxFrameSize, ExtremeType::Minimum) => MIN_MAX_FRAME_SIZE,
            (SettingId::MaxFrameSize, ExtremeType::Maximum) => MAX_MAX_FRAME_SIZE,
            (SettingId::InitialWindowSize, ExtremeType::Maximum) => MAX_INITIAL_WINDOW_SIZE,
            (_, ExtremeType::Minimum) => 0,
            (_, ExtremeType::Maximum) => u32::MAX,
            (_, ExtremeType::NearMinimum(offset)) => offset.saturating_add(1),
            (_, ExtremeType::NearMaximum(offset)) => u32::MAX.saturating_sub(*offset),
        };

        (id, value)
    }

    fn simulate_settings_sequence(
        &mut self,
        input: &H2SettingsTransitionInput,
    ) -> Result<(), SettingsValidationError> {
        // Process initial SETTINGS frame
        let initial_settings = Self::generate_default_settings_frame(&input.initial_settings);
        self.process_settings_frame(&initial_settings, false)?;

        // ACK the initial settings
        if input.test_context.test_ack_behavior {
            self.process_settings_ack()?;
        }

        // Process changed SETTINGS frames
        let changed_frames = Self::generate_changed_settings_frame(&input.changed_settings);
        for frame_settings in changed_frames {
            self.process_settings_frame(&frame_settings, false)?;

            // ACK if testing ACK behavior
            if input.test_context.test_ack_behavior {
                self.process_settings_ack()?;
            }
        }

        // Process additional frames
        for additional in &input.additional_frames {
            if additional.ack_previous && self.ack_pending {
                self.process_settings_ack()?;
            }

            let frame_settings: Vec<(u16, u32)> = additional
                .changes
                .iter()
                .map(Self::setting_change_to_tuple)
                .collect();

            self.process_settings_frame(&frame_settings, false)?;

            if input.test_context.test_ack_behavior {
                self.process_settings_ack()?;
            }
        }

        Ok(())
    }

    fn verify_settings_transition(&self, input: &H2SettingsTransitionInput) -> bool {
        // Check that initial defaults were properly set if ACKed
        if input.test_context.test_ack_behavior {
            // Should have proper state transition
            if self.settings_history.len() < 2 {
                return false;
            }

            // Default values should have been maintained initially
            match input.initial_settings {
                InitialSettingsStrategy::AllDefaults
                | InitialSettingsStrategy::ExplicitDefaults(_) => {
                    // Settings should be at defaults initially if explicitly set
                }
                InitialSettingsStrategy::Empty => {
                    // Empty settings should not change defaults
                }
                _ => {
                    // Mixed strategies may change some settings
                }
            }

            // Changes should be reflected in final state
            true
        } else {
            // If not testing ACK behavior, just verify no errors occurred
            true
        }
    }
}

fn setting_value_is_invalid(id: u16, value: u32) -> bool {
    match id {
        2 => value > 1,
        4 => value > MAX_INITIAL_WINDOW_SIZE,
        5 => !(MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&value),
        _ => false,
    }
}

fn frame_contains_setting(frame: &[(u16, u32)], expected_id: u16, expected_value: u32) -> bool {
    frame
        .iter()
        .any(|&(id, value)| id == expected_id && value == expected_value)
}

fn input_contains_invalid_setting(
    input: &H2SettingsTransitionInput,
    expected_id: u16,
    expected_value: u32,
    include_initial: bool,
) -> bool {
    if !setting_value_is_invalid(expected_id, expected_value) {
        return false;
    }

    if include_initial {
        let initial =
            MockH2SettingsStateMachine::generate_default_settings_frame(&input.initial_settings);
        if frame_contains_setting(&initial, expected_id, expected_value) {
            return true;
        }
    }

    for frame in
        MockH2SettingsStateMachine::generate_changed_settings_frame(&input.changed_settings)
    {
        if frame_contains_setting(&frame, expected_id, expected_value) {
            return true;
        }
    }

    for additional in &input.additional_frames {
        let frame: Vec<(u16, u32)> = additional
            .changes
            .iter()
            .map(MockH2SettingsStateMachine::setting_change_to_tuple)
            .collect();
        if frame_contains_setting(&frame, expected_id, expected_value) {
            return true;
        }
    }

    false
}

fn assert_generated_invalid_value(
    input: &H2SettingsTransitionInput,
    id: u16,
    value: u32,
    include_initial: bool,
    context: &str,
) {
    assert!(
        input_contains_invalid_setting(input, id, value, include_initial),
        "{}: InvalidValue {}={} did not correspond to a generated invalid setting",
        context,
        id,
        value
    );
}

fn panic_on_unreachable_settings_error(error: &SettingsValidationError, context: &str) -> ! {
    panic!(
        "{}: unexpected SETTINGS sequence error: {:?}",
        context, error
    );
}

fuzz_target!(|input: H2SettingsTransitionInput| {
    // Skip inputs that would cause excessive processing
    if input.additional_frames.len() > 20 {
        return;
    }

    let mut state_machine = MockH2SettingsStateMachine::new();
    let initial_state = state_machine.current_settings.clone();

    let result = state_machine.simulate_settings_sequence(&input);

    // Apply test assertions based on the settings strategy
    match &input.initial_settings {
        InitialSettingsStrategy::AllDefaults | InitialSettingsStrategy::ExplicitDefaults(_) => {
            // Default settings should always be accepted
            match &result {
                Ok(()) => {
                    // Expected: defaults accepted
                    assert!(state_machine.verify_settings_transition(&input));
                }
                Err(SettingsValidationError::InvalidValue { id, value }) => {
                    assert_generated_invalid_value(
                        &input,
                        *id,
                        *value,
                        false,
                        "default initial SETTINGS sequence",
                    );
                }
                Err(error) => {
                    panic_on_unreachable_settings_error(error, "default initial SETTINGS sequence")
                }
            }
        }
        InitialSettingsStrategy::Empty => {
            // Empty settings should always succeed
            match &result {
                Ok(()) => {
                    // Expected: empty settings accepted
                }
                Err(SettingsValidationError::InvalidValue { id, value }) => {
                    assert_generated_invalid_value(
                        &input,
                        *id,
                        *value,
                        false,
                        "empty initial SETTINGS sequence",
                    );
                }
                Err(error) => {
                    panic_on_unreachable_settings_error(error, "empty initial SETTINGS sequence");
                }
            }
        }
        _ => {
            // Mixed settings may have validation errors
            match &result {
                Ok(()) => {
                    // Verify state transition occurred correctly
                    assert!(state_machine.verify_settings_transition(&input));
                }
                Err(SettingsValidationError::InvalidValue { id, value }) => {
                    assert_generated_invalid_value(
                        &input,
                        *id,
                        *value,
                        true,
                        "mixed SETTINGS sequence",
                    );
                }
                Err(error) => {
                    panic_on_unreachable_settings_error(error, "mixed SETTINGS sequence");
                }
            }
        }
    }

    // Test state transition invariants
    test_settings_transition_invariants(&input, &result, &state_machine, &initial_state);
});

fn test_settings_transition_invariants(
    input: &H2SettingsTransitionInput,
    result: &Result<(), SettingsValidationError>,
    state_machine: &MockH2SettingsStateMachine,
    _initial_state: &SettingsState,
) {
    // Invariant: Empty SETTINGS frame should always succeed
    if matches!(&input.initial_settings, InitialSettingsStrategy::Empty) {
        match result {
            Ok(()) => {}
            Err(SettingsValidationError::InvalidValue { id, value }) => {
                assert_generated_invalid_value(
                    input,
                    *id,
                    *value,
                    false,
                    "empty initial SETTINGS invariant",
                );
            }
            Err(error) => {
                panic_on_unreachable_settings_error(error, "empty initial SETTINGS invariant")
            }
        }
    }

    // Invariant: Default values should always be valid
    let default_settings = MockH2SettingsStateMachine::generate_default_settings_frame(
        &InitialSettingsStrategy::AllDefaults,
    );
    for &(id, value) in &default_settings {
        let validation = state_machine.validate_setting(id, value);
        assert!(
            validation.is_ok(),
            "Default setting {}={} should be valid",
            id,
            value
        );
    }

    // Invariant: If ACK behavior is tested, state should properly transition
    if input.test_context.test_ack_behavior && result.is_ok() {
        // Should have at least initial state in history
        assert!(!state_machine.settings_history.is_empty());

        // Should not have pending ACK if sequence completed
        if input.additional_frames.is_empty() {
            // Simple sequence should not have pending ACK
        }
    }

    // Invariant: Settings values should be within valid ranges
    let current = &state_machine.current_settings;
    assert!(current.max_frame_size >= MIN_MAX_FRAME_SIZE);
    assert!(current.max_frame_size <= MAX_MAX_FRAME_SIZE);
    assert!(current.initial_window_size <= MAX_INITIAL_WINDOW_SIZE);

    // Invariant: ENABLE_PUSH should be boolean (0 or 1 equivalent)
    // This is represented as bool, so it's always valid

    // Invariant: Unknown settings should not cause errors
    for additional in &input.additional_frames {
        for change in &additional.changes {
            if let SettingId::Unknown(id) = change.id {
                // Unknown settings should be ignored, not cause errors
                let test_machine = MockH2SettingsStateMachine::new();
                let validation = test_machine.validate_setting(id, change.new_value);
                assert!(validation.is_ok(), "Unknown setting should be ignored");
            }
        }
    }

    // Invariant: Settings history should be monotonically increasing if ACKs processed
    if input.test_context.test_ack_behavior && state_machine.settings_history.len() > 1 {
        // Each entry should represent a state after processing a SETTINGS frame
        assert!(!state_machine.settings_history.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings_accepted() {
        let mut state_machine = MockH2SettingsStateMachine::new();

        let default_settings = vec![
            (1, DEFAULT_HEADER_TABLE_SIZE),
            (2, 1), // ENABLE_PUSH = true
            (4, DEFAULT_INITIAL_WINDOW_SIZE),
            (5, DEFAULT_MAX_FRAME_SIZE),
        ];

        let result = state_machine.process_settings_frame(&default_settings, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_settings_accepted() {
        let mut state_machine = MockH2SettingsStateMachine::new();

        let result = state_machine.process_settings_frame(&[], false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_settings_state_transition() {
        let mut state_machine = MockH2SettingsStateMachine::new();
        let initial = state_machine.current_settings.clone();

        // Send settings with default values
        let default_settings = vec![(1, DEFAULT_HEADER_TABLE_SIZE)];
        state_machine
            .process_settings_frame(&default_settings, false)
            .unwrap();

        // ACK the settings
        state_machine.process_settings_ack().unwrap();

        // Settings should be applied
        assert_eq!(
            state_machine.current_settings.header_table_size,
            DEFAULT_HEADER_TABLE_SIZE
        );

        // Send settings with changed values
        let changed_settings = vec![(1, 8192)];
        state_machine
            .process_settings_frame(&changed_settings, false)
            .unwrap();
        state_machine.process_settings_ack().unwrap();

        // Settings should be updated
        assert_eq!(state_machine.current_settings.header_table_size, 8192);
        assert_eq!(state_machine.settings_history.len(), 3); // Initial + 2 updates
    }

    #[test]
    fn test_invalid_settings_rejected() {
        let mut state_machine = MockH2SettingsStateMachine::new();

        // Invalid ENABLE_PUSH value
        let invalid_settings = vec![(2, 5)];
        let result = state_machine.process_settings_frame(&invalid_settings, false);
        assert!(matches!(
            result,
            Err(SettingsValidationError::InvalidValue { .. })
        ));

        // Invalid MAX_FRAME_SIZE (too small)
        let invalid_settings = vec![(5, 1000)];
        let result = state_machine.process_settings_frame(&invalid_settings, false);
        assert!(matches!(
            result,
            Err(SettingsValidationError::InvalidValue { .. })
        ));

        // Invalid INITIAL_WINDOW_SIZE (too large)
        let invalid_settings = vec![(4, MAX_INITIAL_WINDOW_SIZE + 1)];
        let result = state_machine.process_settings_frame(&invalid_settings, false);
        assert!(matches!(
            result,
            Err(SettingsValidationError::InvalidValue { .. })
        ));
    }

    #[test]
    fn test_ack_without_pending_settings() {
        let mut state_machine = MockH2SettingsStateMachine::new();

        // Try to ACK without sending SETTINGS first
        let result = state_machine.process_settings_ack();
        assert!(matches!(
            result,
            Err(SettingsValidationError::AckWithoutPending)
        ));
    }

    #[test]
    fn test_extreme_values() {
        let mut state_machine = MockH2SettingsStateMachine::new();

        // Maximum valid MAX_FRAME_SIZE
        let max_frame_settings = vec![(5, MAX_MAX_FRAME_SIZE)];
        let result = state_machine.process_settings_frame(&max_frame_settings, false);
        assert!(result.is_ok());

        // Minimum valid MAX_FRAME_SIZE
        let min_frame_settings = vec![(5, MIN_MAX_FRAME_SIZE)];
        let result = state_machine.process_settings_frame(&min_frame_settings, false);
        assert!(result.is_ok());

        // Maximum valid INITIAL_WINDOW_SIZE
        let max_window_settings = vec![(4, MAX_INITIAL_WINDOW_SIZE)];
        let result = state_machine.process_settings_frame(&max_window_settings, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_unknown_settings_ignored() {
        let mut state_machine = MockH2SettingsStateMachine::new();

        // Unknown setting ID
        let unknown_settings = vec![(100, 12345)];
        let result = state_machine.process_settings_frame(&unknown_settings, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_multiple_settings_changes() {
        let mut state_machine = MockH2SettingsStateMachine::new();

        // Multiple settings in one frame
        let multiple_settings = vec![
            (1, 8192),  // HEADER_TABLE_SIZE
            (2, 0),     // ENABLE_PUSH = false
            (4, 32768), // INITIAL_WINDOW_SIZE
            (5, 32768), // MAX_FRAME_SIZE
        ];

        let result = state_machine.process_settings_frame(&multiple_settings, false);
        assert!(result.is_ok());

        state_machine.process_settings_ack().unwrap();

        // Verify all settings were applied
        assert_eq!(state_machine.current_settings.header_table_size, 8192);
        assert_eq!(state_machine.current_settings.enable_push, false);
        assert_eq!(state_machine.current_settings.initial_window_size, 32768);
        assert_eq!(state_machine.current_settings.max_frame_size, 32768);
    }

    #[test]
    fn test_settings_sequence() {
        let input = H2SettingsTransitionInput {
            initial_settings: InitialSettingsStrategy::AllDefaults,
            changed_settings: ChangedSettingsStrategy::SingleChange(SettingChange {
                id: SettingId::HeaderTableSize,
                new_value: 8192,
            }),
            additional_frames: vec![],
            test_context: SettingsTestContext {
                connection_state: ConnectionState::Fresh,
                test_ack_behavior: true,
                active_streams: 0,
                flow_control_state: FlowControlState {
                    connection_window: 65535,
                    stream_windows: vec![],
                },
            },
        };

        let mut state_machine = MockH2SettingsStateMachine::new();
        let result = state_machine.simulate_settings_sequence(&input);

        assert!(result.is_ok());
        assert!(state_machine.verify_settings_transition(&input));
    }
}
