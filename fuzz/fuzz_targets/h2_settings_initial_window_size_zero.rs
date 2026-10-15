#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE=0 flow control fuzz target.
///
/// Tests RFC 7540 §6.5.2 compliance for zero initial window size setting.
/// Per RFC 7540 §6.5.2: "Values above the maximum flow-control window size
/// of 2^31-1 MUST be treated as a FLOW_CONTROL_ERROR. Values of any size are
/// valid, including zero."
///
/// Critical flow control scenarios with INITIAL_WINDOW_SIZE=0:
/// 1. New streams start with 0 send window (no DATA frames allowed)
/// 2. Streams require WINDOW_UPDATE before any data transmission
/// 3. Connection-level window remains independent
/// 4. State machine correctly blocks/unblocks streams based on window
/// 5. Window exhaustion handling and recovery
/// 6. Proper error generation for window violations
///
/// Per RFC 7540 §6.9.1: "A sender MUST NOT send a flow-controlled frame
/// with a length that exceeds the space available in either of the flow-
/// control windows advertised by the receiver."

#[derive(Arbitrary, Debug, Clone)]
struct InitialWindowZeroInput {
    /// Flow control test scenarios
    flow_control_tests: Vec<FlowControlTest>,

    /// Window update patterns
    window_updates: Vec<WindowUpdatePattern>,

    /// Data transmission attempts
    data_attempts: Vec<DataTransmissionTest>,

    /// Settings configuration
    settings_config: SettingsConfig,

    /// Connection state scenarios
    connection_scenarios: Vec<ConnectionScenario>,
}

#[derive(Arbitrary, Debug, Clone)]
struct FlowControlTest {
    /// Stream ID to test
    stream_id: u32,

    /// Initial attempt to send data (should fail)
    initial_data_size: u32,

    /// Window update to provide
    window_increment: Option<u32>,

    /// Follow-up data attempt after window update
    followup_data_size: Option<u32>,

    /// Expected results for each step
    expected_results: FlowControlExpectations,
}

#[derive(Arbitrary, Debug, Clone)]
struct WindowUpdatePattern {
    /// Type of window update
    update_type: WindowUpdateType,

    /// Target stream (0 for connection-level)
    target_stream: u32,

    /// Window increment value
    increment: u32,

    /// Timing relative to other operations
    timing: UpdateTiming,
}

#[derive(Arbitrary, Debug, Clone)]
enum WindowUpdateType {
    /// Connection-level window update
    Connection,

    /// Stream-level window update
    Stream,

    /// Both connection and stream
    Both { connection_increment: u32 },
}

#[derive(Arbitrary, Debug, Clone)]
enum UpdateTiming {
    /// Before any data attempts
    BeforeData,

    /// After failed data attempt
    AfterFailedData,

    /// During data transmission
    DuringTransmission,

    /// Multiple incremental updates
    Incremental { count: u8, delay_ms: u16 },
}

#[derive(Arbitrary, Debug, Clone)]
struct DataTransmissionTest {
    /// Stream ID for transmission
    stream_id: u32,

    /// Size of data to attempt sending
    data_size: u32,

    /// Whether END_STREAM flag should be set
    end_stream: bool,

    /// Expected transmission result
    expected_result: TransmissionExpectation,
}

#[derive(Arbitrary, Debug, Clone, PartialEq)]
enum TransmissionExpectation {
    /// Should be allowed (sufficient window)
    Allow,

    /// Should be blocked (insufficient window)
    Block,

    /// Should generate flow control error
    FlowControlError,

    /// Implementation-defined behavior
    ImplementationDefined,
}

#[derive(Arbitrary, Debug, Clone)]
struct FlowControlExpectations {
    /// Initial data transmission should fail
    initial_transmission_blocked: bool,

    /// Window update should be processed
    window_update_accepted: bool,

    /// Follow-up transmission should succeed (if window sufficient)
    followup_transmission_allowed: bool,

    /// Stream should track window correctly
    window_tracking_correct: bool,
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingsConfig {
    /// Initial window size setting (0 in this test)
    initial_window_size: u32,

    /// Whether to send SETTINGS ACK
    send_ack: bool,

    /// Additional settings to test with
    additional_settings: Vec<AdditionalSetting>,

    /// Test rapid settings changes
    rapid_changes: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum AdditionalSetting {
    MaxFrameSize(u32),
    MaxConcurrentStreams(u32),
    EnablePush(bool),
    HeaderTableSize(u32),
    MaxHeaderListSize(u32),
}

#[derive(Arbitrary, Debug, Clone)]
enum ConnectionScenario {
    /// Single stream with zero window
    SingleStreamZeroWindow { stream_id: u32 },

    /// Multiple streams with zero window
    MultipleStreamsZeroWindow { stream_ids: Vec<u32> },

    /// Zero window then non-zero window
    WindowSizeChange { new_window_size: u32 },

    /// Connection window vs stream window interaction
    WindowInteraction,

    /// Window exhaustion and recovery
    WindowExhaustion { steps: Vec<ExhaustionStep> },

    /// Concurrent window updates and data
    ConcurrentOperations,
}

#[derive(Arbitrary, Debug, Clone)]
enum ExhaustionStep {
    SendData { stream_id: u32, size: u32 },
    WindowUpdate { stream_id: u32, increment: u32 },
    SettingsChange { new_window_size: u32 },
}

impl Default for SettingsConfig {
    fn default() -> Self {
        Self {
            initial_window_size: 0, // Zero window size for this test
            send_ack: true,
            additional_settings: vec![],
            rapid_changes: false,
        }
    }
}

/// Mock HTTP/2 connection for testing zero initial window size
struct MockInitialWindowZeroConnection {
    /// Per-stream states
    streams: HashMap<u32, StreamFlowState>,

    /// Connection-level flow control
    connection_window: i32,

    /// Settings state
    settings: ConnectionSettings,

    /// Window update results
    window_update_results: Vec<WindowUpdateResult>,

    /// Data transmission results
    transmission_results: Vec<TransmissionResult>,

    /// Flow control violations detected
    violations: Vec<FlowControlViolation>,

    /// Statistics
    stats: FlowControlStats,
}

#[derive(Debug, Clone)]
struct StreamFlowState {
    /// Current send window for this stream
    send_window: i32,

    /// Data queued but not yet sent
    queued_data: u32,

    /// Whether stream has been closed
    closed: bool,

    /// Window updates received
    window_updates_received: u32,

    /// Bytes successfully transmitted
    bytes_transmitted: u32,

    /// Flow control errors encountered
    flow_control_errors: u32,
}

#[derive(Debug, Clone)]
struct ConnectionSettings {
    /// Current initial window size setting
    initial_window_size: u32,

    /// Whether settings have been acknowledged
    settings_acked: bool,

    /// History of window size changes
    window_size_history: Vec<u32>,
}

#[derive(Debug, Clone)]
struct WindowUpdateResult {
    target_stream: u32,
    increment: u32,
    successful: bool,
    error_code: Option<u32>,
    new_window_size: i32,
}

#[derive(Debug, Clone)]
struct TransmissionResult {
    stream_id: u32,
    data_size: u32,
    successful: bool,
    error_type: Option<TransmissionError>,
    window_before: i32,
    window_after: i32,
}

#[derive(Debug, Clone, PartialEq)]
enum TransmissionError {
    InsufficientWindow,   // Not enough send window
    FlowControlViolation, // Attempted to exceed window
}

#[derive(Debug, Clone)]
struct FlowControlViolation {
    stream_id: u32,
    violation_type: ViolationType,
    attempted_size: u32,
    available_window: i32,
}

#[derive(Debug, Clone, PartialEq)]
enum ViolationType {
    ExceededStreamWindow,     // Exceeded stream-level window
    ExceededConnectionWindow, // Exceeded connection-level window
    NegativeWindow,           // Window became negative
    WindowOverflow,           // Window increment caused overflow
}

#[derive(Debug, Clone, Default)]
struct FlowControlStats {
    streams_created: u32,
    window_updates_processed: u32,
    data_frames_blocked: u32,
    data_frames_allowed: u32,
    flow_control_errors: u32,
    total_bytes_transmitted: u64,
    total_window_credit_used: u64,
}

#[derive(Debug, Default)]
struct SetupOutcomeObserver {
    stream_create_successes: u32,
    invalid_stream_ids: u32,
    duplicate_streams: u32,
    settings_updates: u32,
    settings_streams_affected: u32,
    settings_negative_deltas: u32,
    exhaustion_data_results: u32,
    exhaustion_window_updates: u32,
    metadata_digest: u64,
}

impl SetupOutcomeObserver {
    fn mix(&mut self, value: u64) {
        self.metadata_digest = self
            .metadata_digest
            .wrapping_mul(0x9e37_79b1_85eb_ca87)
            .wrapping_add(value);
    }

    fn observe_settings_config(&mut self, config: &SettingsConfig) {
        self.mix(u64::from(config.initial_window_size));
        self.mix(u64::from(config.send_ack));
        self.mix(u64::from(config.rapid_changes));
        self.mix(config.additional_settings.len() as u64);
        for setting in config.additional_settings.iter().take(8) {
            match setting {
                AdditionalSetting::MaxFrameSize(value) => self.mix(0x10 | u64::from(*value)),
                AdditionalSetting::MaxConcurrentStreams(value) => {
                    self.mix(0x20 | u64::from(*value));
                }
                AdditionalSetting::EnablePush(enabled) => self.mix(0x30 | u64::from(*enabled)),
                AdditionalSetting::HeaderTableSize(value) => self.mix(0x40 | u64::from(*value)),
                AdditionalSetting::MaxHeaderListSize(value) => self.mix(0x50 | u64::from(*value)),
            }
        }
    }

    fn observe_window_update_pattern(&mut self, pattern: &WindowUpdatePattern) {
        match &pattern.update_type {
            WindowUpdateType::Connection => self.mix(0x100),
            WindowUpdateType::Stream => self.mix(0x200 | u64::from(pattern.target_stream)),
            WindowUpdateType::Both {
                connection_increment,
            } => {
                self.mix(0x300 | u64::from(*connection_increment));
            }
        }

        match &pattern.timing {
            UpdateTiming::BeforeData => self.mix(0x400),
            UpdateTiming::AfterFailedData => self.mix(0x500),
            UpdateTiming::DuringTransmission => self.mix(0x600),
            UpdateTiming::Incremental { count, delay_ms } => {
                self.mix(0x700 | u64::from(*count));
                self.mix(u64::from(*delay_ms));
            }
        }
    }

    fn observe_exhaustion_step(&mut self, step: &ExhaustionStep) {
        match step {
            ExhaustionStep::SendData { stream_id, size } => {
                self.mix(0x800 | u64::from(*stream_id));
                self.mix(u64::from(*size));
            }
            ExhaustionStep::WindowUpdate {
                stream_id,
                increment,
            } => {
                self.mix(0x900 | u64::from(*stream_id));
                self.mix(u64::from(*increment));
            }
            ExhaustionStep::SettingsChange { new_window_size } => {
                self.mix(0xa00 | u64::from(*new_window_size));
            }
        }
    }

    fn observe_stream_creation(
        &mut self,
        stream_id: u32,
        result: &StreamCreationResult,
        connection: &MockInitialWindowZeroConnection,
    ) {
        match result {
            StreamCreationResult::Success { initial_window } => {
                self.stream_create_successes += 1;
                let stream_state = connection
                    .streams
                    .get(&stream_id)
                    .expect("successful stream creation must insert stream state");
                assert_eq!(
                    stream_state.send_window, *initial_window,
                    "Observed stream window should match creation result"
                );
                assert!(
                    *initial_window >= 0,
                    "New streams should not start with negative send windows"
                );
            }
            StreamCreationResult::InvalidStreamId => {
                self.invalid_stream_ids += 1;
                assert!(
                    stream_id == 0 || stream_id.is_multiple_of(2),
                    "Invalid stream creation should only report invalid ids"
                );
            }
            StreamCreationResult::StreamAlreadyExists => {
                self.duplicate_streams += 1;
                assert!(
                    connection.streams.contains_key(&stream_id),
                    "Duplicate stream creation should reference an existing stream"
                );
            }
        }
    }

    fn observe_settings_result(&mut self, result: &SettingsProcessResult) {
        self.settings_updates += 1;
        self.settings_streams_affected = self
            .settings_streams_affected
            .saturating_add(result.streams_affected);
        if result.window_delta < 0 {
            self.settings_negative_deltas += 1;
        }
        assert_eq!(
            result.window_delta,
            effective_window_size(result.new_window_size)
                .saturating_sub(effective_window_size(result.old_window_size)),
            "Settings window delta should match old/new sizes"
        );
    }

    fn observe_exhaustion_data_result(
        &mut self,
        stream_id: u32,
        data_size: u32,
        result: &DataTransmissionResult,
        connection: &MockInitialWindowZeroConnection,
    ) {
        self.exhaustion_data_results += 1;
        self.mix(0xb00 | u64::from(stream_id));
        self.mix(u64::from(data_size));
        match result {
            DataTransmissionResult::Success {
                bytes_sent,
                stream_window_after,
                connection_window_after,
            } => {
                assert_eq!(
                    *bytes_sent, data_size,
                    "Exhaustion DATA success should send the requested bytes"
                );
                let stream_state = connection
                    .streams
                    .get(&stream_id)
                    .expect("successful exhaustion DATA requires a live stream");
                assert_eq!(
                    stream_state.send_window, *stream_window_after,
                    "Exhaustion DATA success should report the live stream window"
                );
                assert_eq!(
                    connection.connection_window, *connection_window_after,
                    "Exhaustion DATA success should report the live connection window"
                );
                let recorded = connection
                    .transmission_results
                    .last()
                    .expect("successful exhaustion DATA should be recorded");
                assert!(
                    recorded.successful,
                    "Successful exhaustion DATA should append a successful record"
                );
                assert_eq!(recorded.stream_id, stream_id);
                assert_eq!(recorded.data_size, data_size);
            }
            DataTransmissionResult::FlowControlBlocked {
                attempted_size,
                stream_window,
                connection_window,
            } => {
                assert_eq!(
                    *attempted_size, data_size,
                    "Blocked exhaustion DATA should report the requested size"
                );
                let requested_window = effective_window_size(data_size);
                assert!(
                    *stream_window < requested_window
                        || *connection_window < requested_window
                        || i32::try_from(data_size).is_err(),
                    "Blocked exhaustion DATA should reflect insufficient credit"
                );
                let recorded = connection
                    .transmission_results
                    .last()
                    .expect("blocked exhaustion DATA should be recorded");
                assert!(
                    !recorded.successful,
                    "Blocked exhaustion DATA should append a blocked record"
                );
                assert_eq!(recorded.stream_id, stream_id);
                assert_eq!(recorded.data_size, data_size);
            }
            DataTransmissionResult::EmptyFrame => {
                assert_eq!(data_size, 0, "Only zero-sized DATA should be empty");
            }
            DataTransmissionResult::StreamClosed => {
                let stream_state = connection
                    .streams
                    .get(&stream_id)
                    .expect("closed exhaustion DATA should reference a tracked stream");
                assert!(
                    stream_state.closed,
                    "StreamClosed exhaustion DATA should reference a closed stream"
                );
            }
            DataTransmissionResult::StreamNotFound => {
                assert!(
                    !connection.streams.contains_key(&stream_id),
                    "StreamNotFound exhaustion DATA should reference an absent stream"
                );
            }
        }
    }

    fn observe_exhaustion_window_update_result(
        &mut self,
        stream_id: u32,
        increment: u32,
        result: &WindowUpdateProcessResult,
        connection: &MockInitialWindowZeroConnection,
    ) {
        self.exhaustion_window_updates += 1;
        self.mix(0xc00 | u64::from(stream_id));
        self.mix(u64::from(increment));
        let recorded = connection
            .window_update_results
            .last()
            .expect("exhaustion WINDOW_UPDATE should append a record");
        assert_eq!(recorded.target_stream, stream_id);
        assert_eq!(recorded.increment, increment);

        match result {
            WindowUpdateProcessResult::Success {
                old_window,
                new_window,
                target,
            } => {
                assert!(increment > 0, "Successful WINDOW_UPDATE requires credit");
                assert!(
                    *new_window >= *old_window,
                    "Successful WINDOW_UPDATE should not reduce a window"
                );
                assert!(recorded.successful);
                match target {
                    WindowUpdateTarget::Connection => {
                        assert_eq!(stream_id, 0);
                        assert_eq!(
                            connection.connection_window, *new_window,
                            "Connection WINDOW_UPDATE should report the live connection window"
                        );
                    }
                    WindowUpdateTarget::Stream(target_stream_id) => {
                        assert_eq!(*target_stream_id, stream_id);
                        let stream_state = connection
                            .streams
                            .get(&stream_id)
                            .expect("successful stream WINDOW_UPDATE requires a live stream");
                        assert_eq!(
                            stream_state.send_window, *new_window,
                            "Stream WINDOW_UPDATE should report the live stream window"
                        );
                    }
                }
            }
            WindowUpdateProcessResult::WindowOverflow { .. } => {
                assert!(increment > 0, "Overflow WINDOW_UPDATE requires credit");
                assert!(!recorded.successful);
                assert_eq!(
                    recorded.error_code,
                    Some(0x3),
                    "Overflow WINDOW_UPDATE should record FLOW_CONTROL_ERROR"
                );
            }
            WindowUpdateProcessResult::ZeroIncrement => {
                assert_eq!(increment, 0);
                assert!(!recorded.successful);
                assert_eq!(
                    recorded.error_code,
                    Some(0x1),
                    "Zero WINDOW_UPDATE should record PROTOCOL_ERROR"
                );
            }
            WindowUpdateProcessResult::StreamNotFound => {
                assert_ne!(stream_id, 0);
                assert!(increment > 0);
                assert!(
                    !connection.streams.contains_key(&stream_id),
                    "StreamNotFound WINDOW_UPDATE should reference an absent stream"
                );
                assert!(!recorded.successful);
            }
        }
    }

    fn assert_consistent(&self) {
        let _observed_digest = std::hint::black_box(self.metadata_digest);
        assert!(
            self.stream_create_successes + self.invalid_stream_ids + self.duplicate_streams > 0,
            "Fuzz target should observe at least the baseline stream creation"
        );
        assert!(
            self.settings_updates > 0,
            "Fuzz target should observe at least the baseline settings update"
        );
    }
}

fn effective_window_size(window_size: u32) -> i32 {
    i32::try_from(window_size).unwrap_or(i32::MAX)
}

impl MockInitialWindowZeroConnection {
    fn new() -> Self {
        Self {
            streams: HashMap::new(),
            connection_window: 65535, // Default connection window
            settings: ConnectionSettings {
                initial_window_size: 0, // Zero initial window
                settings_acked: false,
                window_size_history: vec![0],
            },
            window_update_results: Vec::new(),
            transmission_results: Vec::new(),
            violations: Vec::new(),
            stats: FlowControlStats::default(),
        }
    }

    /// Process SETTINGS frame with INITIAL_WINDOW_SIZE=0
    fn process_settings(&mut self, initial_window_size: u32) -> SettingsProcessResult {
        // Update initial window size setting
        let old_window_size = self.settings.initial_window_size;
        self.settings.initial_window_size = initial_window_size;
        self.settings.window_size_history.push(initial_window_size);

        // Update existing streams' windows based on the difference
        let window_diff = effective_window_size(initial_window_size)
            .saturating_sub(effective_window_size(old_window_size));

        for stream_state in self.streams.values_mut() {
            let old_window = stream_state.send_window;
            stream_state.send_window = stream_state.send_window.saturating_add(window_diff);

            // Check for window overflow
            if stream_state.send_window < 0 && old_window >= 0 && window_diff < 0 {
                // Window became negative due to settings change
                let violation = FlowControlViolation {
                    stream_id: 0, // Will be set by caller
                    violation_type: ViolationType::NegativeWindow,
                    attempted_size: 0,
                    available_window: stream_state.send_window,
                };
                self.violations.push(violation);
            }
        }

        SettingsProcessResult {
            old_window_size,
            new_window_size: initial_window_size,
            streams_affected: self.streams.len() as u32,
            window_delta: window_diff,
        }
    }

    /// Create a new stream with zero initial window
    fn create_stream(&mut self, stream_id: u32) -> StreamCreationResult {
        if stream_id == 0 || stream_id.is_multiple_of(2) {
            return StreamCreationResult::InvalidStreamId;
        }

        if self.streams.contains_key(&stream_id) {
            return StreamCreationResult::StreamAlreadyExists;
        }

        // New stream starts with current initial window size (should be 0)
        let initial_window = effective_window_size(self.settings.initial_window_size);

        let stream_state = StreamFlowState {
            send_window: initial_window,
            queued_data: 0,
            closed: false,
            window_updates_received: 0,
            bytes_transmitted: 0,
            flow_control_errors: 0,
        };

        self.streams.insert(stream_id, stream_state);
        self.stats.streams_created += 1;

        StreamCreationResult::Success { initial_window }
    }

    /// Process WINDOW_UPDATE frame
    fn process_window_update(
        &mut self,
        stream_id: u32,
        increment: u32,
    ) -> WindowUpdateProcessResult {
        if increment == 0 {
            return WindowUpdateProcessResult::ZeroIncrement;
        }

        let result = if stream_id == 0 {
            // Connection-level window update
            let old_window = self.connection_window;
            match i32::try_from(increment) {
                Ok(increment_i32) if self.connection_window <= i32::MAX - increment_i32 => {
                    self.connection_window += increment_i32;
                    self.stats.window_updates_processed += 1;

                    WindowUpdateProcessResult::Success {
                        old_window,
                        new_window: self.connection_window,
                        target: WindowUpdateTarget::Connection,
                    }
                }
                _ => WindowUpdateProcessResult::WindowOverflow {
                    old_window,
                    increment,
                },
            }
        } else {
            // Stream-level window update
            if let Some(stream_state) = self.streams.get_mut(&stream_id) {
                let old_window = stream_state.send_window;
                match i32::try_from(increment) {
                    Ok(increment_i32) if stream_state.send_window <= i32::MAX - increment_i32 => {
                        stream_state.send_window += increment_i32;
                        stream_state.window_updates_received += 1;
                        self.stats.window_updates_processed += 1;

                        WindowUpdateProcessResult::Success {
                            old_window,
                            new_window: stream_state.send_window,
                            target: WindowUpdateTarget::Stream(stream_id),
                        }
                    }
                    _ => {
                        let violation = FlowControlViolation {
                            stream_id,
                            violation_type: ViolationType::WindowOverflow,
                            attempted_size: increment,
                            available_window: old_window,
                        };
                        self.violations.push(violation);

                        WindowUpdateProcessResult::WindowOverflow {
                            old_window,
                            increment,
                        }
                    }
                }
            } else {
                WindowUpdateProcessResult::StreamNotFound
            }
        };

        // Record the result
        let window_update_result = WindowUpdateResult {
            target_stream: stream_id,
            increment,
            successful: matches!(result, WindowUpdateProcessResult::Success { .. }),
            error_code: match &result {
                WindowUpdateProcessResult::WindowOverflow { .. } => Some(0x3), // FLOW_CONTROL_ERROR
                WindowUpdateProcessResult::ZeroIncrement => Some(0x1),         // PROTOCOL_ERROR
                _ => None,
            },
            new_window_size: if stream_id == 0 {
                self.connection_window
            } else {
                self.streams.get(&stream_id).map_or(0, |s| s.send_window)
            },
        };

        self.window_update_results.push(window_update_result);
        result
    }

    /// Attempt to send DATA frame
    fn attempt_data_transmission(
        &mut self,
        stream_id: u32,
        data_size: u32,
        end_stream: bool,
    ) -> DataTransmissionResult {
        if data_size == 0 {
            return DataTransmissionResult::EmptyFrame;
        }

        // Check if stream exists
        let stream_state = match self.streams.get_mut(&stream_id) {
            Some(state) if !state.closed => state,
            Some(_) => return DataTransmissionResult::StreamClosed,
            None => return DataTransmissionResult::StreamNotFound,
        };

        let window_before = stream_state.send_window;
        let connection_window_before = self.connection_window;
        let Ok(data_size_i32) = i32::try_from(data_size) else {
            self.stats.data_frames_blocked += 1;
            stream_state.flow_control_errors += 1;
            self.stats.flow_control_errors += 1;

            let violation = FlowControlViolation {
                stream_id,
                violation_type: ViolationType::ExceededStreamWindow,
                attempted_size: data_size,
                available_window: window_before.min(connection_window_before),
            };
            self.violations.push(violation);

            let transmission_result = TransmissionResult {
                stream_id,
                data_size,
                successful: false,
                error_type: Some(TransmissionError::FlowControlViolation),
                window_before,
                window_after: window_before,
            };
            self.transmission_results.push(transmission_result);

            return DataTransmissionResult::FlowControlBlocked {
                attempted_size: data_size,
                stream_window: window_before,
                connection_window: connection_window_before,
            };
        };

        // Check both stream and connection windows
        let can_send = window_before >= data_size_i32 && self.connection_window >= data_size_i32;

        if can_send {
            // Successful transmission
            stream_state.send_window -= data_size_i32;
            stream_state.bytes_transmitted += data_size;
            self.connection_window -= data_size_i32;
            self.stats.data_frames_allowed += 1;
            self.stats.total_bytes_transmitted += data_size as u64;
            self.stats.total_window_credit_used += data_size as u64;

            if end_stream {
                stream_state.closed = true;
            }

            let transmission_result = TransmissionResult {
                stream_id,
                data_size,
                successful: true,
                error_type: None,
                window_before,
                window_after: stream_state.send_window,
            };
            self.transmission_results.push(transmission_result);

            DataTransmissionResult::Success {
                bytes_sent: data_size,
                stream_window_after: stream_state.send_window,
                connection_window_after: self.connection_window,
            }
        } else {
            // Transmission blocked due to insufficient window
            self.stats.data_frames_blocked += 1;
            stream_state.flow_control_errors += 1;
            self.stats.flow_control_errors += 1;

            // Determine which window was insufficient
            let error_type = if window_before < data_size_i32 {
                TransmissionError::InsufficientWindow
            } else {
                TransmissionError::FlowControlViolation
            };

            let violation_type = if window_before < data_size_i32 {
                ViolationType::ExceededStreamWindow
            } else {
                ViolationType::ExceededConnectionWindow
            };

            let violation = FlowControlViolation {
                stream_id,
                violation_type,
                attempted_size: data_size,
                available_window: window_before.min(connection_window_before),
            };
            self.violations.push(violation);

            let transmission_result = TransmissionResult {
                stream_id,
                data_size,
                successful: false,
                error_type: Some(error_type),
                window_before,
                window_after: window_before, // Window unchanged
            };
            self.transmission_results.push(transmission_result);

            DataTransmissionResult::FlowControlBlocked {
                attempted_size: data_size,
                stream_window: window_before,
                connection_window: connection_window_before,
            }
        }
    }

    fn get_status(&self) -> ConnectionStatus {
        ConnectionStatus {
            settings: self.settings.clone(),
            stream_count: self.streams.len(),
            connection_window: self.connection_window,
            violations: self.violations.clone(),
            stats: self.stats.clone(),
        }
    }
}

#[derive(Debug)]
struct SettingsProcessResult {
    old_window_size: u32,
    new_window_size: u32,
    streams_affected: u32,
    window_delta: i32,
}

#[derive(Debug, PartialEq)]
enum StreamCreationResult {
    Success { initial_window: i32 },
    InvalidStreamId,
    StreamAlreadyExists,
}

#[derive(Debug, PartialEq)]
enum WindowUpdateProcessResult {
    Success {
        old_window: i32,
        new_window: i32,
        target: WindowUpdateTarget,
    },
    WindowOverflow {
        old_window: i32,
        increment: u32,
    },
    ZeroIncrement,
    StreamNotFound,
}

#[derive(Debug, PartialEq)]
enum WindowUpdateTarget {
    Connection,
    Stream(u32),
}

#[derive(Debug, PartialEq)]
enum DataTransmissionResult {
    Success {
        bytes_sent: u32,
        stream_window_after: i32,
        connection_window_after: i32,
    },
    FlowControlBlocked {
        attempted_size: u32,
        stream_window: i32,
        connection_window: i32,
    },
    EmptyFrame,
    StreamClosed,
    StreamNotFound,
}

#[derive(Debug, Clone)]
struct ConnectionStatus {
    settings: ConnectionSettings,
    stream_count: usize,
    connection_window: i32,
    violations: Vec<FlowControlViolation>,
    stats: FlowControlStats,
}

fuzz_target!(|input: InitialWindowZeroInput| {
    // Limit input size for performance
    let mut input = input;
    if input.flow_control_tests.len() > 8 {
        input.flow_control_tests.truncate(8);
    }
    if input.window_updates.len() > 10 {
        input.window_updates.truncate(10);
    }

    let mut connection = MockInitialWindowZeroConnection::new();
    let mut observer = SetupOutcomeObserver::default();
    observer.observe_settings_config(&input.settings_config);
    connection.settings.settings_acked = input.settings_config.send_ack;

    // Apply SETTINGS_INITIAL_WINDOW_SIZE=0
    let settings_result = connection.process_settings(0);
    observer.observe_settings_result(&settings_result);
    assert_eq!(
        settings_result.new_window_size, 0,
        "Initial window size should be set to 0"
    );

    // Test basic zero window behavior
    let stream_id = 1;
    let create_result = connection.create_stream(stream_id);
    observer.observe_stream_creation(stream_id, &create_result, &connection);
    match create_result {
        StreamCreationResult::Success { initial_window } => {
            assert_eq!(
                initial_window, 0,
                "New stream should start with 0 send window per SETTINGS"
            );
        }
        _ => panic!("Stream creation should succeed"),
    }

    // Attempt data transmission with zero window (should be blocked)
    let data_result = connection.attempt_data_transmission(stream_id, 100, false);
    match data_result {
        DataTransmissionResult::FlowControlBlocked { stream_window, .. } => {
            assert_eq!(
                stream_window, 0,
                "Stream window should be 0, preventing data transmission"
            );
        }
        _ => panic!("Data transmission should be blocked with zero window"),
    }

    // Provide window credit via WINDOW_UPDATE
    let window_update_result = connection.process_window_update(stream_id, 1000);
    match window_update_result {
        WindowUpdateProcessResult::Success { new_window, .. } => {
            assert_eq!(
                new_window, 1000,
                "Stream window should be 1000 after WINDOW_UPDATE"
            );
        }
        _ => panic!("WINDOW_UPDATE should succeed"),
    }

    // Now data transmission should succeed
    let data_result2 = connection.attempt_data_transmission(stream_id, 500, false);
    match data_result2 {
        DataTransmissionResult::Success {
            bytes_sent,
            stream_window_after,
            ..
        } => {
            assert_eq!(bytes_sent, 500, "Should send 500 bytes");
            assert_eq!(
                stream_window_after, 500,
                "Stream window should be reduced to 500"
            );
        }
        _ => panic!("Data transmission should succeed with sufficient window"),
    }

    // Test fuzzed input scenarios
    for test_case in &input.flow_control_tests {
        let stream_id = if test_case.stream_id == 0 || test_case.stream_id % 2 == 0 {
            3 // Use odd stream ID
        } else {
            test_case.stream_id
        };

        // Create stream (will have 0 initial window)
        let create_result = connection.create_stream(stream_id);
        observer.observe_stream_creation(stream_id, &create_result, &connection);

        // Attempt initial data transmission (should be blocked if size > 0)
        if test_case.initial_data_size > 0 {
            let stream_window_before = connection
                .streams
                .get(&stream_id)
                .map_or(0, |stream_state| stream_state.send_window);
            let connection_window_before = connection.connection_window;
            let result =
                connection.attempt_data_transmission(stream_id, test_case.initial_data_size, false);

            if test_case.expected_results.initial_transmission_blocked {
                let should_block =
                    i32::try_from(test_case.initial_data_size).map_or(true, |data_size_i32| {
                        stream_window_before < data_size_i32
                            || connection_window_before < data_size_i32
                    });
                if should_block {
                    assert!(
                        matches!(result, DataTransmissionResult::FlowControlBlocked { .. }),
                        "Initial transmission should be blocked with insufficient window"
                    );
                }
            }
        }

        // Apply window update if specified
        if let Some(increment) = test_case.window_increment {
            let stream_window_before = connection
                .streams
                .get(&stream_id)
                .map_or(0, |stream_state| stream_state.send_window);
            let result = connection.process_window_update(stream_id, increment);

            if test_case.expected_results.window_update_accepted
                && let Ok(increment_i32) = i32::try_from(increment)
                && increment > 0
                && stream_window_before <= i32::MAX - increment_i32
            {
                assert!(
                    matches!(result, WindowUpdateProcessResult::Success { .. }),
                    "WINDOW_UPDATE should be accepted when the stream window can grow"
                );
            }
        }

        // Attempt follow-up transmission if specified
        if let Some(followup_size) = test_case.followup_data_size {
            let stream_window_before = connection
                .streams
                .get(&stream_id)
                .map_or(0, |stream_state| stream_state.send_window);
            let connection_window_before = connection.connection_window;
            let result = connection.attempt_data_transmission(stream_id, followup_size, false);

            if test_case.expected_results.followup_transmission_allowed
                && let Ok(followup_size_i32) = i32::try_from(followup_size)
                && stream_window_before >= followup_size_i32
                && connection_window_before >= followup_size_i32
            {
                assert!(
                    matches!(result, DataTransmissionResult::Success { .. }),
                    "Follow-up transmission should succeed with sufficient window"
                );
            }
        }

        if test_case.expected_results.window_tracking_correct {
            let stream_state = connection
                .streams
                .get(&stream_id)
                .expect("observed flow-control stream should remain tracked");
            assert!(
                stream_state.send_window >= 0 || stream_state.flow_control_errors > 0,
                "Tracked stream windows should be non-negative unless an error was recorded"
            );
        }
    }

    // Process window updates from fuzzed input
    for window_update in &input.window_updates {
        observer.observe_window_update_pattern(window_update);
        let target_stream =
            if window_update.target_stream % 2 == 0 && window_update.target_stream != 0 {
                5 // Use odd stream ID for streams
            } else {
                window_update.target_stream
            };

        // Create stream if it doesn't exist and target is not connection
        if target_stream != 0 {
            let create_result = connection.create_stream(target_stream);
            observer.observe_stream_creation(target_stream, &create_result, &connection);
        }

        let result = connection.process_window_update(target_stream, window_update.increment);

        // Verify window updates are processed correctly
        match result {
            WindowUpdateProcessResult::Success { .. } => {
                // Success is good
            }
            WindowUpdateProcessResult::WindowOverflow { .. } => {
                // Overflow is correctly detected
            }
            WindowUpdateProcessResult::ZeroIncrement => {
                assert_eq!(
                    window_update.increment, 0,
                    "Zero increment should be detected"
                );
            }
            WindowUpdateProcessResult::StreamNotFound => {
                // Stream not found is valid if we didn't create it
            }
        }
    }

    // Test data transmission attempts
    for data_test in input.data_attempts.iter().take(5) {
        // Limit for performance
        let stream_id = if data_test.stream_id == 0 || data_test.stream_id % 2 == 0 {
            7 // Use odd stream ID
        } else {
            data_test.stream_id
        };

        // Ensure stream exists
        let create_result = connection.create_stream(stream_id);
        observer.observe_stream_creation(stream_id, &create_result, &connection);

        let stream_window_before = connection
            .streams
            .get(&stream_id)
            .map_or(0, |stream_state| stream_state.send_window);
        let connection_window_before = connection.connection_window;
        let result = connection.attempt_data_transmission(
            stream_id,
            data_test.data_size,
            data_test.end_stream,
        );

        match data_test.expected_result {
            TransmissionExpectation::Allow => {
                // Check if stream has sufficient window
                if let Ok(data_size_i32) = i32::try_from(data_test.data_size)
                    && stream_window_before >= data_size_i32
                    && connection_window_before >= data_size_i32
                {
                    assert!(
                        matches!(result, DataTransmissionResult::Success { .. }),
                        "Transmission should be allowed with sufficient window"
                    );
                }
            }

            TransmissionExpectation::Block => {
                // Should be blocked if insufficient window
                match i32::try_from(data_test.data_size) {
                    Ok(data_size_i32)
                        if stream_window_before < data_size_i32
                            || connection_window_before < data_size_i32 =>
                    {
                        assert!(
                            matches!(result, DataTransmissionResult::FlowControlBlocked { .. }),
                            "Transmission should be blocked with insufficient window"
                        );
                    }
                    Err(_) => assert!(
                        matches!(result, DataTransmissionResult::FlowControlBlocked { .. }),
                        "Oversized DATA frames should be blocked"
                    ),
                    _ => {}
                }
            }

            TransmissionExpectation::FlowControlError => {
                // Should generate flow control error
                let should_error =
                    i32::try_from(data_test.data_size).map_or(true, |data_size_i32| {
                        data_test.data_size > 0
                            && (stream_window_before < data_size_i32
                                || connection_window_before < data_size_i32)
                    });
                if should_error {
                    assert!(
                        matches!(result, DataTransmissionResult::FlowControlBlocked { .. }),
                        "Should generate flow control error"
                    );
                }
            }

            TransmissionExpectation::ImplementationDefined => {
                // Any reasonable result is acceptable
            }
        }
    }

    // Test connection scenarios
    for scenario in input.connection_scenarios.iter().take(3) {
        // Limit for performance
        match scenario {
            ConnectionScenario::SingleStreamZeroWindow { stream_id } => {
                let sid = if *stream_id % 2 == 0 { 9 } else { *stream_id };
                let create_result = connection.create_stream(sid);
                observer.observe_stream_creation(sid, &create_result, &connection);

                // Verify stream starts with zero window
                if matches!(create_result, StreamCreationResult::Success { .. })
                    && let Some(stream_state) = connection.streams.get(&sid)
                {
                    assert_eq!(
                        stream_state.send_window,
                        effective_window_size(connection.settings.initial_window_size),
                        "Stream should start with the current initial window"
                    );
                }
            }

            ConnectionScenario::MultipleStreamsZeroWindow { stream_ids } => {
                for sid in stream_ids.iter().take(4) {
                    let sid = if *sid == 0 || *sid % 2 == 0 { 11 } else { *sid };
                    let create_result = connection.create_stream(sid);
                    observer.observe_stream_creation(sid, &create_result, &connection);
                    if matches!(create_result, StreamCreationResult::Success { .. })
                        && let Some(stream_state) = connection.streams.get(&sid)
                    {
                        assert_eq!(
                            stream_state.send_window,
                            effective_window_size(connection.settings.initial_window_size),
                            "Each stream should start with the current initial window"
                        );
                    }
                }
            }

            ConnectionScenario::WindowSizeChange { new_window_size } => {
                // Change window size setting
                let before_stream_windows = connection
                    .streams
                    .iter()
                    .map(|(&stream_id, stream_state)| (stream_id, stream_state.send_window))
                    .collect::<Vec<_>>();
                let settings_result = connection.process_settings(*new_window_size);
                observer.observe_settings_result(&settings_result);
                let new_status = connection.get_status();

                assert_eq!(
                    new_status.settings.initial_window_size, *new_window_size,
                    "Window size setting should be updated"
                );

                // Verify existing streams' windows are adjusted
                for (stream_id, old_window) in before_stream_windows {
                    let new_stream = connection
                        .streams
                        .get(&stream_id)
                        .expect("settings update should not remove existing streams");
                    assert_eq!(
                        new_stream.send_window,
                        old_window.saturating_add(settings_result.window_delta),
                        "Settings update should adjust existing stream windows by the delta"
                    );
                }
            }

            ConnectionScenario::WindowExhaustion { steps } => {
                for step in steps.iter().take(4) {
                    observer.observe_exhaustion_step(step);
                    match step {
                        ExhaustionStep::SendData { stream_id, size } => {
                            let sid = if *stream_id == 0 || *stream_id % 2 == 0 {
                                13
                            } else {
                                *stream_id
                            };
                            let create_result = connection.create_stream(sid);
                            observer.observe_stream_creation(sid, &create_result, &connection);
                            let result = connection.attempt_data_transmission(sid, *size, false);
                            observer.observe_exhaustion_data_result(
                                sid,
                                *size,
                                &result,
                                &connection,
                            );
                        }
                        ExhaustionStep::WindowUpdate {
                            stream_id,
                            increment,
                        } => {
                            let sid = if *stream_id % 2 == 0 && *stream_id != 0 {
                                15
                            } else {
                                *stream_id
                            };
                            if sid != 0 {
                                let create_result = connection.create_stream(sid);
                                observer.observe_stream_creation(sid, &create_result, &connection);
                            }
                            let result = connection.process_window_update(sid, *increment);
                            observer.observe_exhaustion_window_update_result(
                                sid,
                                *increment,
                                &result,
                                &connection,
                            );
                        }
                        ExhaustionStep::SettingsChange { new_window_size } => {
                            let settings_result = connection.process_settings(*new_window_size);
                            observer.observe_settings_result(&settings_result);
                        }
                    }
                }
            }

            ConnectionScenario::WindowInteraction | ConnectionScenario::ConcurrentOperations => {
                observer.mix(0xb00);
            }
        }
    }

    // Verify final state consistency
    let final_status = connection.get_status();
    observer.assert_consistent();
    assert_eq!(
        final_status.stream_count,
        connection.streams.len(),
        "Connection status stream count should match the live stream table"
    );
    assert_eq!(
        final_status.connection_window, connection.connection_window,
        "Connection status window should match the live connection window"
    );
    assert_eq!(
        final_status.settings.settings_acked, input.settings_config.send_ack,
        "Settings ACK state should reflect the fuzzed config flag"
    );

    // All streams should track their windows correctly
    for stream_state in connection.streams.values() {
        assert_eq!(
            stream_state.queued_data, 0,
            "Mock does not queue DATA frames"
        );
        assert!(
            stream_state.send_window >= 0 || stream_state.flow_control_errors > 0,
            "Stream window should be non-negative or have recorded errors"
        );
    }

    // Statistics should be consistent
    assert_eq!(
        final_status.stats.data_frames_allowed + final_status.stats.data_frames_blocked,
        connection.transmission_results.len() as u32,
        "Data frame statistics should match transmission results"
    );

    for result in &connection.transmission_results {
        assert_ne!(result.stream_id, 0, "DATA results should be stream-scoped");
        if result.successful {
            assert!(
                result.error_type.is_none(),
                "Successful DATA transmissions should not record an error"
            );
            let data_size_i32 =
                i32::try_from(result.data_size).expect("successful DATA size should fit i32");
            assert_eq!(
                result.window_after,
                result.window_before - data_size_i32,
                "Successful DATA transmissions should debit the stream window"
            );
        } else {
            assert!(
                result.error_type.is_some(),
                "Blocked DATA transmissions should record an error"
            );
            assert_eq!(
                result.window_after, result.window_before,
                "Blocked DATA transmissions should not debit the stream window"
            );
        }
    }

    let successful_window_updates = connection
        .window_update_results
        .iter()
        .filter(|result| result.successful)
        .count() as u32;
    assert_eq!(
        successful_window_updates, final_status.stats.window_updates_processed,
        "Successful WINDOW_UPDATE records should match stats"
    );

    for result in &connection.window_update_results {
        if result.target_stream != 0 {
            assert!(
                result.target_stream % 2 == 1,
                "Stream WINDOW_UPDATE records should target odd stream ids"
            );
        }
        if result.successful {
            assert!(
                result.error_code.is_none(),
                "Successful WINDOW_UPDATE records should not include an error code"
            );
        }
        if result.increment == 0 {
            assert_eq!(
                result.error_code,
                Some(0x1),
                "Zero WINDOW_UPDATE increments should record PROTOCOL_ERROR"
            );
        }
        assert!(
            result.new_window_size >= 0 || result.error_code.is_some(),
            "Recorded windows should be non-negative unless an error was recorded"
        );
    }

    // Verify flow control violations are properly tracked
    for violation in &final_status.violations {
        assert!(
            violation.stream_id == 0 || violation.stream_id % 2 == 1,
            "Flow-control violations should be connection-level or stream-scoped"
        );
        match violation.violation_type {
            ViolationType::ExceededStreamWindow => {
                let available_window = u32::try_from(violation.available_window).unwrap_or(0);
                assert!(
                    violation.attempted_size > available_window,
                    "Stream window violation should have attempted > available"
                );
            }
            ViolationType::ExceededConnectionWindow => {
                let available_window = u32::try_from(violation.available_window).unwrap_or(0);
                assert!(
                    violation.attempted_size > available_window,
                    "Connection window violation should have attempted > available"
                );
            }
            _ => {
                // Other violations types are valid
            }
        }
    }

    // Test that SETTINGS_INITIAL_WINDOW_SIZE=0 was correctly applied before any
    // fuzzed settings changes.
    assert_eq!(
        final_status.settings.window_size_history.first().copied(),
        Some(0),
        "Settings history should begin with the zero initial window size"
    );
    assert_eq!(
        final_status.settings.window_size_history.last().copied(),
        Some(final_status.settings.initial_window_size),
        "Final settings should match the last observed settings update"
    );

    // Verify no silent corruption occurred
    assert!(
        final_status.stats.total_window_credit_used <= final_status.stats.total_bytes_transmitted,
        "Window credits used should not exceed bytes transmitted"
    );
});
