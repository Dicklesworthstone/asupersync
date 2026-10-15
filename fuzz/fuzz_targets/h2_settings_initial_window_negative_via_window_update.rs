#![no_main]
#![allow(dead_code)]

//! Fuzz target for HTTP/2 flow control with negative windows via INITIAL_WINDOW_SIZE changes
//!
//! Tests the complex flow control scenario where window size becomes negative through
//! a sequence of INITIAL_WINDOW_SIZE settings, WINDOW_UPDATE, DATA consumption, and
//! subsequent INITIAL_WINDOW_SIZE reduction. Per RFC 7540 §6.9.2, negative windows
//! are valid but block further data transmission.
//!
//! Test sequence:
//! 1. SETTINGS INITIAL_WINDOW_SIZE=10000 (stream window = 10000)
//! 2. WINDOW_UPDATE +5000 (stream window = 15000)
//! 3. DATA -10000 (stream window = 5000)
//! 4. SETTINGS INITIAL_WINDOW_SIZE=2000 (delta -8000, window = -3000)
//!
//! Key validations:
//! - Negative windows block DATA transmission but are valid states
//! - SETTINGS delta affects all existing streams
//! - Flow control state machine handles edge cases correctly

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Mock HTTP/2 connection for testing negative window flow control
struct MockNegativeWindowConnection {
    /// Current connection-level INITIAL_WINDOW_SIZE setting
    initial_window_size: u32,

    /// Per-stream flow control state
    streams: HashMap<u32, StreamFlowControl>,

    /// Connection-level flow control
    connection_window: i64,

    /// Connection state
    state: ConnectionState,

    /// Flow control statistics
    stats: FlowControlStats,

    /// Violation tracking
    violations: Vec<ViolationType>,

    /// History of operations for debugging
    operation_history: Vec<FlowControlOperation>,
}

#[derive(Clone, Debug)]
struct StreamFlowControl {
    stream_id: u32,
    /// Current flow control window (can be negative)
    window: i64,
    /// Total bytes sent on this stream
    bytes_sent: u64,
    /// Total bytes received via WINDOW_UPDATE
    window_updates_received: u64,
    /// Whether stream is blocked due to negative/zero window
    blocked: bool,
    /// Stream state
    state: StreamState,
    /// History of window changes
    window_history: Vec<WindowChange>,
}

#[derive(Clone, Debug)]
struct WindowChange {
    operation_id: u32,
    old_window: i64,
    new_window: i64,
    reason: WindowChangeReason,
}

#[derive(Clone, Debug)]
enum WindowChangeReason {
    InitialWindowSizeChange { old_size: u32, new_size: u32 },
    WindowUpdate { increment: u32 },
    DataSent { bytes: u32 },
}

#[derive(Clone, Debug)]
enum StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

#[derive(Clone, Debug)]
enum ConnectionState {
    Open,
    Closed,
}

#[derive(Default, Clone, Debug)]
struct FlowControlStats {
    settings_frames: u32,
    window_update_frames: u32,
    data_frames: u32,
    negative_windows_created: u32,
    blocked_transmissions: u32,
    initial_window_size_changes: u32,
    streams_affected_by_settings: u32,
}

#[derive(Clone, Debug)]
enum ViolationType {
    WindowOverflow,
    InvalidWindowUpdate,
    DataSentOnBlockedStream,
    NegativeWindowNotHandled,
    SettingsDeltaNotApplied,
}

#[derive(Clone, Debug)]
struct FlowControlOperation {
    id: u32,
    operation: Operation,
    timestamp: u32,
}

#[derive(Clone, Debug)]
enum Operation {
    SettingsInitialWindowSize { old_size: u32, new_size: u32 },
    WindowUpdate { stream_id: u32, increment: u32 },
    DataFrame { stream_id: u32, bytes: u32 },
    StreamCreated { stream_id: u32 },
}

impl MockNegativeWindowConnection {
    fn new() -> Self {
        Self {
            initial_window_size: 65535, // RFC 7540 default
            streams: HashMap::new(),
            connection_window: 65535,
            state: ConnectionState::Open,
            stats: FlowControlStats::default(),
            violations: Vec::new(),
            operation_history: Vec::new(),
        }
    }

    /// Process SETTINGS frame with INITIAL_WINDOW_SIZE
    fn handle_settings_initial_window_size(&mut self, new_size: u32) -> Result<(), H2Error> {
        self.stats.settings_frames += 1;
        self.stats.initial_window_size_changes += 1;

        let old_size = self.initial_window_size;

        // Calculate delta to apply to existing streams
        let delta = new_size as i64 - old_size as i64;

        self.log_operation(Operation::SettingsInitialWindowSize { old_size, new_size });

        // Apply delta to all existing streams
        let mut affected_streams = 0;
        for stream in self.streams.values_mut() {
            let old_window = stream.window;
            stream.window += delta;

            // Check if window became negative
            if stream.window < 0 && old_window >= 0 {
                self.stats.negative_windows_created += 1;
                stream.blocked = true;
            } else if stream.window >= 0 && old_window < 0 {
                stream.blocked = false;
            }

            // Log the change
            stream.window_history.push(WindowChange {
                operation_id: self.operation_history.len() as u32,
                old_window,
                new_window: stream.window,
                reason: WindowChangeReason::InitialWindowSizeChange { old_size, new_size },
            });

            affected_streams += 1;
        }

        self.stats.streams_affected_by_settings = affected_streams;
        self.initial_window_size = new_size;

        Ok(())
    }

    /// Process WINDOW_UPDATE frame
    fn handle_window_update(&mut self, stream_id: u32, increment: u32) -> Result<(), H2Error> {
        self.stats.window_update_frames += 1;

        // Validate increment (RFC 7540 §6.9.1: must be 1 to 2^31-1)
        if increment == 0 || increment > 0x7FFFFFFF {
            self.violations.push(ViolationType::InvalidWindowUpdate);
            return Err(H2Error::ProtocolError);
        }

        self.log_operation(Operation::WindowUpdate {
            stream_id,
            increment,
        });

        if stream_id == 0 {
            // Connection-level window update
            self.connection_window += increment as i64;

            // Check for overflow
            if self.connection_window > 0x7FFFFFFF {
                self.violations.push(ViolationType::WindowOverflow);
                return Err(H2Error::FlowControlError);
            }
        } else {
            // Stream-level window update
            let operation_id = self.operation_history.len() as u32;
            let stream = self.get_or_create_stream(stream_id);
            let old_window = stream.window;
            stream.window += increment as i64;

            // Check for overflow
            if stream.window > 0x7FFFFFFF {
                self.violations.push(ViolationType::WindowOverflow);
                return Err(H2Error::FlowControlError);
            }

            // Update blocked status
            if old_window <= 0 && stream.window > 0 {
                stream.blocked = false;
            }

            // Track window update
            stream.window_updates_received += increment as u64;

            // Log the change
            stream.window_history.push(WindowChange {
                operation_id,
                old_window,
                new_window: stream.window,
                reason: WindowChangeReason::WindowUpdate { increment },
            });
        }

        Ok(())
    }

    /// Process DATA frame (consumes window)
    fn handle_data_frame(&mut self, stream_id: u32, data_length: u32) -> Result<(), H2Error> {
        self.stats.data_frames += 1;

        self.log_operation(Operation::DataFrame {
            stream_id,
            bytes: data_length,
        });

        // Check connection-level window
        if self.connection_window < data_length as i64 {
            self.stats.blocked_transmissions += 1;
            return Err(H2Error::FlowControlError);
        }

        // Check stream-level window and consume
        let operation_id = self.operation_history.len() as u32;
        let stream = self.get_or_create_stream(stream_id);

        if stream.window < data_length as i64 {
            // Attempt to send on blocked stream
            self.violations.push(ViolationType::DataSentOnBlockedStream);
            self.stats.blocked_transmissions += 1;
            return Err(H2Error::FlowControlError);
        }

        let old_window = stream.window;
        stream.window -= data_length as i64;
        stream.bytes_sent += data_length as u64;

        // Update blocked status if window becomes non-positive
        if stream.window <= 0 {
            stream.blocked = true;
        }

        // Log the change
        stream.window_history.push(WindowChange {
            operation_id,
            old_window,
            new_window: stream.window,
            reason: WindowChangeReason::DataSent { bytes: data_length },
        });

        // Consume connection window after stream operations
        self.connection_window -= data_length as i64;

        Ok(())
    }

    /// Create or get existing stream
    fn get_or_create_stream(&mut self, stream_id: u32) -> &mut StreamFlowControl {
        if !self.streams.contains_key(&stream_id) {
            // Stream doesn't exist, create it
            let operation_id = self.operation_history.len() as u32;
            let initial_window_size = self.initial_window_size;

            self.log_operation(Operation::StreamCreated { stream_id });

            let stream = StreamFlowControl {
                stream_id,
                window: initial_window_size as i64,
                bytes_sent: 0,
                window_updates_received: 0,
                blocked: false,
                state: StreamState::Open,
                window_history: vec![WindowChange {
                    operation_id: operation_id + 1, // +1 because we just added the log operation
                    old_window: 0,
                    new_window: initial_window_size as i64,
                    reason: WindowChangeReason::InitialWindowSizeChange {
                        old_size: 0,
                        new_size: initial_window_size,
                    },
                }],
            };

            self.streams.insert(stream_id, stream);
        }

        self.streams.get_mut(&stream_id).unwrap()
    }

    /// Log operation for debugging/analysis
    fn log_operation(&mut self, operation: Operation) {
        let op = FlowControlOperation {
            id: self.operation_history.len() as u32,
            operation,
            timestamp: self.stats.settings_frames
                + self.stats.window_update_frames
                + self.stats.data_frames,
        };
        self.operation_history.push(op);
    }

    /// Execute the specific negative window test scenario
    fn execute_negative_window_scenario(&mut self) -> ScenarioResult {
        let mut result = ScenarioResult::default();
        let stream_id = 1;

        // Step 1: Set INITIAL_WINDOW_SIZE=10000
        result.step1_success = self.handle_settings_initial_window_size(10000).is_ok();
        if !result.step1_success {
            return result;
        }

        // Create stream (will inherit initial window size)
        let stream = self.get_or_create_stream(stream_id);
        result.initial_window = stream.window;

        // Step 2: WINDOW_UPDATE +5000 (window should become 15000)
        result.step2_success = self.handle_window_update(stream_id, 5000).is_ok();
        if result.step2_success {
            result.window_after_update = self.streams[&stream_id].window;
        }

        // Step 3: Send DATA -10000 (window should become 5000)
        result.step3_success = self.handle_data_frame(stream_id, 10000).is_ok();
        if result.step3_success {
            result.window_after_data = self.streams[&stream_id].window;
        }

        // Step 4: Set INITIAL_WINDOW_SIZE=2000 (delta -8000, window should become -3000)
        result.step4_success = self.handle_settings_initial_window_size(2000).is_ok();
        if result.step4_success {
            result.final_window = self.streams[&stream_id].window;
            result.stream_blocked = self.streams[&stream_id].blocked;
        }

        // Verify negative window state
        result.negative_window_achieved = result.final_window < 0;

        result
    }

    /// Validate flow control invariants
    fn validate_flow_control_invariants(&self) -> Vec<String> {
        let mut violations = Vec::new();

        for stream in self.streams.values() {
            // Check if blocked status matches window state
            if stream.blocked && stream.window > 0 {
                violations.push(format!(
                    "Stream {} blocked but has positive window {}",
                    stream.stream_id, stream.window
                ));
            }

            // Check window history consistency
            for (i, change) in stream.window_history.iter().enumerate() {
                if i > 0 {
                    let prev_change = &stream.window_history[i - 1];
                    if prev_change.new_window != change.old_window {
                        violations.push(format!(
                            "Stream {} window history inconsistent at index {}",
                            stream.stream_id, i
                        ));
                    }
                }
            }
        }

        // Check connection window bounds
        if self.connection_window > 0x7FFFFFFF {
            violations.push("Connection window exceeded maximum".to_string());
        }

        violations
    }

    /// Get comprehensive statistics
    fn get_stats(&self) -> &FlowControlStats {
        &self.stats
    }

    /// Get violations
    fn get_violations(&self) -> &[ViolationType] {
        &self.violations
    }

    /// Get stream state
    fn get_stream_state(&self, stream_id: u32) -> Option<&StreamFlowControl> {
        self.streams.get(&stream_id)
    }
}

#[derive(Default, Clone, Debug)]
struct ScenarioResult {
    step1_success: bool,
    step2_success: bool,
    step3_success: bool,
    step4_success: bool,
    initial_window: i64,
    window_after_update: i64,
    window_after_data: i64,
    final_window: i64,
    negative_window_achieved: bool,
    stream_blocked: bool,
}

#[derive(Clone, Debug)]
enum H2Error {
    ProtocolError,
    FlowControlError,
}

/// Fuzz input structure
#[derive(Arbitrary, Debug, Clone)]
struct FuzzInput {
    /// Initial INITIAL_WINDOW_SIZE setting
    initial_window_size: u32,

    /// Sequence of flow control operations
    operations: Vec<FlowControlOp>,

    /// Whether to run the specific negative window scenario
    run_negative_scenario: bool,

    /// Stream IDs to operate on
    stream_ids: Vec<u32>,
}

#[derive(Arbitrary, Debug, Clone)]
enum FlowControlOp {
    /// Change INITIAL_WINDOW_SIZE
    ChangeInitialWindowSize { new_size: u32 },

    /// Send WINDOW_UPDATE
    WindowUpdate { stream_id: u32, increment: u32 },

    /// Send DATA frame
    SendData { stream_id: u32, bytes: u32 },

    /// Create stream explicitly
    CreateStream { stream_id: u32 },
}

fn observe_handle_settings_initial_window_size(
    connection: &mut MockNegativeWindowConnection,
    new_size: u32,
    context: &str,
) {
    let result = connection.handle_settings_initial_window_size(new_size);
    assert!(
        result.is_ok(),
        "{context}: valid INITIAL_WINDOW_SIZE update failed: {result:?}"
    );
    assert_eq!(
        connection.initial_window_size, new_size,
        "{context}: INITIAL_WINDOW_SIZE was not applied"
    );
}

fn observe_handle_window_update(
    connection: &mut MockNegativeWindowConnection,
    stream_id: u32,
    increment: u32,
    context: &str,
) {
    let overflow_violations_before = connection
        .violations
        .iter()
        .filter(|violation| matches!(violation, ViolationType::WindowOverflow))
        .count();
    let result = connection.handle_window_update(stream_id, increment);
    match result {
        Ok(()) => {}
        Err(H2Error::FlowControlError) => {
            let overflow_violations_after = connection
                .violations
                .iter()
                .filter(|violation| matches!(violation, ViolationType::WindowOverflow))
                .count();
            assert!(
                overflow_violations_after > overflow_violations_before,
                "{context}: WINDOW_UPDATE flow-control failure did not record overflow"
            );
        }
        Err(H2Error::ProtocolError) => {
            panic!("{context}: sanitized WINDOW_UPDATE was rejected as a protocol error");
        }
    }
}

fn observe_handle_data_frame(
    connection: &mut MockNegativeWindowConnection,
    stream_id: u32,
    bytes: u32,
    context: &str,
) {
    let blocked_before = connection.stats.blocked_transmissions;
    let result = connection.handle_data_frame(stream_id, bytes);
    match result {
        Ok(()) => {
            assert!(
                connection.streams.contains_key(&stream_id),
                "{context}: DATA succeeded without materializing stream state"
            );
        }
        Err(H2Error::FlowControlError) => {
            assert!(
                connection.stats.blocked_transmissions > blocked_before,
                "{context}: DATA flow-control failure did not update blocked count"
            );
        }
        Err(H2Error::ProtocolError) => {
            panic!("{context}: DATA frame returned an unexpected protocol error");
        }
    }
}

fn observe_get_or_create_stream(
    connection: &mut MockNegativeWindowConnection,
    stream_id: u32,
    context: &str,
) {
    {
        let stream = connection.get_or_create_stream(stream_id);
        assert_eq!(
            stream.stream_id, stream_id,
            "{context}: stream state preserved the wrong id"
        );
    }
    assert!(
        connection.streams.contains_key(&stream_id),
        "{context}: get_or_create_stream did not insert the stream"
    );
}

fuzz_target!(|input: FuzzInput| {
    // Limit input size to prevent excessive resource usage
    if input.operations.len() > 50 {
        return;
    }

    let mut connection = MockNegativeWindowConnection::new();

    // Set initial window size (with bounds checking)
    let safe_initial_size = input.initial_window_size.min(0x7FFFFFFF);
    observe_handle_settings_initial_window_size(
        &mut connection,
        safe_initial_size,
        "initial fuzz setup",
    );

    // Process operations
    for operation in input.operations {
        match operation {
            FlowControlOp::ChangeInitialWindowSize { new_size } => {
                let safe_size = new_size.min(0x7FFFFFFF);
                observe_handle_settings_initial_window_size(
                    &mut connection,
                    safe_size,
                    "fuzz operation INITIAL_WINDOW_SIZE change",
                );
            }

            FlowControlOp::WindowUpdate {
                stream_id,
                increment,
            } => {
                // Sanitize inputs
                let safe_stream_id = (stream_id % 1000) + 1; // Stream IDs 1-1000
                let safe_increment = increment.clamp(1, 0x7FFFFFFF); // Valid increment range

                observe_handle_window_update(
                    &mut connection,
                    safe_stream_id,
                    safe_increment,
                    "fuzz operation WINDOW_UPDATE",
                );
            }

            FlowControlOp::SendData { stream_id, bytes } => {
                let safe_stream_id = (stream_id % 1000) + 1;
                let safe_bytes = bytes.min(1000000); // Max 1MB per frame

                observe_handle_data_frame(
                    &mut connection,
                    safe_stream_id,
                    safe_bytes,
                    "fuzz operation DATA",
                );
            }

            FlowControlOp::CreateStream { stream_id } => {
                let safe_stream_id = (stream_id % 1000) + 1;
                observe_get_or_create_stream(
                    &mut connection,
                    safe_stream_id,
                    "fuzz operation stream creation",
                );
            }
        }
    }

    // Run specific negative window scenario if requested
    if input.run_negative_scenario {
        let scenario_result = connection.execute_negative_window_scenario();

        // Validate the specific scenario worked correctly
        if scenario_result.step1_success
            && scenario_result.step2_success
            && scenario_result.step3_success
            && scenario_result.step4_success
        {
            // Expected sequence:
            // Initial: 10000, After WINDOW_UPDATE: 15000, After DATA: 5000, Final: -3000
            assert_eq!(scenario_result.initial_window, 10000);
            assert_eq!(scenario_result.window_after_update, 15000);
            assert_eq!(scenario_result.window_after_data, 5000);
            assert_eq!(scenario_result.final_window, -3000);
            assert!(scenario_result.negative_window_achieved);
            assert!(scenario_result.stream_blocked);
        }
    }

    // Validate flow control invariants
    let invariant_violations = connection.validate_flow_control_invariants();
    if !invariant_violations.is_empty() {
        panic!(
            "Flow control invariant violations: {:?}",
            invariant_violations
        );
    }

    // Check for critical violations
    let violations = connection.get_violations();
    for violation in violations {
        match violation {
            ViolationType::WindowOverflow => {
                // Window overflow should be detected and handled
            }
            ViolationType::DataSentOnBlockedStream => {
                // Sending data on blocked stream should be rejected
            }
            ViolationType::NegativeWindowNotHandled => {
                panic!("Negative window not handled properly");
            }
            ViolationType::SettingsDeltaNotApplied => {
                panic!("SETTINGS delta not applied to existing streams");
            }
            _ => {
                // Other violations may be acceptable depending on input
            }
        }
    }

    // Test edge cases for negative windows
    test_negative_window_edge_cases(&mut connection);

    // Final validation
    let stats = connection.get_stats();

    // If negative windows were created, ensure they were handled properly
    if stats.negative_windows_created > 0 {
        // Verify streams with negative windows are blocked
        for stream in connection.streams.values() {
            if stream.window < 0 {
                assert!(
                    stream.blocked,
                    "Stream {} has negative window {} but is not blocked",
                    stream.stream_id, stream.window
                );
            }
        }
    }
});

/// Test specific edge cases for negative window handling
fn test_negative_window_edge_cases(connection: &mut MockNegativeWindowConnection) {
    let stream_id = 999;

    // Test case: Large initial window, then reduce to small value
    observe_handle_settings_initial_window_size(connection, 1000000, "edge case large window");
    observe_get_or_create_stream(connection, stream_id, "edge case stream creation");
    observe_handle_data_frame(connection, stream_id, 500000, "edge case large DATA");
    observe_handle_settings_initial_window_size(connection, 100000, "edge case window reduction");

    // Stream should now have window = 500000 - 900000 = -400000
    if let Some(stream) = connection.get_stream_state(stream_id)
        && stream.window < 0
    {
        assert!(
            stream.blocked,
            "Stream with negative window should be blocked"
        );

        // Try to send more data - should fail
        let result = connection.handle_data_frame(stream_id, 1);
        assert!(
            result.is_err(),
            "Should not be able to send data on blocked stream"
        );
    }

    // Test recovery: send WINDOW_UPDATE to make window positive
    observe_handle_window_update(
        connection,
        stream_id,
        500000,
        "edge case WINDOW_UPDATE recovery",
    );
    if let Some(stream) = connection.get_stream_state(stream_id)
        && stream.window > 0
    {
        assert!(
            !stream.blocked,
            "Stream with positive window should not be blocked"
        );
    }
}
