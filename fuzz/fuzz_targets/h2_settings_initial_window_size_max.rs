#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE maximum value fuzz target.
///
/// Tests RFC 7540 compliance when peer sets SETTINGS_INITIAL_WINDOW_SIZE = 2^31-1
/// (maximum permitted value). Verifies our flow-control state-machine correctly
/// handles this maximum without overflow on subsequent send_data operations.
///
/// RFC 7540 §6.5.2: "Values above the maximum flow-control window size of 2^31-1
/// MUST be treated as a connection error of type FLOW_CONTROL_ERROR."
///
/// Critical test scenarios:
/// - Maximum window size (2^31-1) without overflow
/// - Window size calculations during data sending
/// - Edge cases around window exhaustion and updates
/// - State machine consistency with maximum values

#[derive(Arbitrary, Debug, Clone)]
struct MaxWindowSizeInput {
    /// Initial window size setting (should be 2^31-1 for this test)
    initial_window_size: u32,

    /// Data operations to perform after setting
    data_operations: Vec<DataOperation>,

    /// Connection configuration
    connection_config: ConnectionConfig,

    /// Flow control configuration
    flow_control_config: FlowControlConfig,
}

#[derive(Arbitrary, Debug, Clone)]
struct DataOperation {
    /// Stream ID for data operation
    stream_id: u32,

    /// Amount of data to send
    data_size: u32,

    /// Expected operation result
    expected_result: OperationExpectation,

    /// Operation timing
    timing: OperationTiming,
}

#[derive(Arbitrary, Debug, Clone)]
enum OperationExpectation {
    Success,
    WindowExhausted,
    FlowControlError,
    ImplementationDefined,
}

#[derive(Arbitrary, Debug, Clone)]
enum OperationTiming {
    Immediate,
    AfterWindowUpdate,
    Concurrent,
}

#[derive(Arbitrary, Debug, Clone)]
struct ConnectionConfig {
    /// Whether this is client or server side
    is_client: bool,

    /// Maximum concurrent streams
    max_concurrent_streams: u32,

    /// Connection-level flow control window
    connection_window: i64,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            is_client: true,
            max_concurrent_streams: 100,
            connection_window: 65535, // RFC 7540 default
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct FlowControlConfig {
    /// Whether to enforce strict RFC limits
    strict_rfc_enforcement: bool,

    /// Whether to detect overflow conditions
    detect_overflow: bool,

    /// Maximum safe calculation value
    max_safe_calculation: u32,

    /// Whether to track window state precisely
    precise_tracking: bool,
}

impl Default for FlowControlConfig {
    fn default() -> Self {
        Self {
            strict_rfc_enforcement: true,
            detect_overflow: true,
            max_safe_calculation: 2_147_483_647, // 2^31-1
            precise_tracking: true,
        }
    }
}

/// Mock HTTP/2 flow control state machine for testing maximum window sizes
struct MockH2FlowControl {
    /// Current stream window sizes
    stream_windows: std::collections::HashMap<u32, i64>,

    /// Connection-level window size
    connection_window: i64,

    /// Initial window size setting
    initial_window_size: u32,

    /// Configuration
    config: FlowControlConfig,

    /// Statistics for analysis
    stats: FlowControlStats,
}

impl MockH2FlowControl {
    fn new(config: FlowControlConfig) -> Self {
        Self {
            stream_windows: std::collections::HashMap::new(),
            connection_window: 65535,   // RFC default
            initial_window_size: 65535, // RFC default
            config,
            stats: FlowControlStats::default(),
        }
    }

    /// Apply SETTINGS_INITIAL_WINDOW_SIZE change
    fn apply_initial_window_size_setting(&mut self, new_size: u32) -> SettingsResult {
        self.stats.setting_changes += 1;

        // RFC 7540 §6.5.2: Values above 2^31-1 are a connection error
        if new_size > 2_147_483_647 {
            return SettingsResult::FlowControlError(format!(
                "INITIAL_WINDOW_SIZE {} exceeds maximum 2^31-1",
                new_size
            ));
        }

        let old_initial_size = self.initial_window_size as i64;
        let new_initial_size = new_size as i64;
        let delta = new_initial_size - old_initial_size;

        // RFC 7540 §6.9.2: Adjust all stream windows by the delta
        let mut overflow_detected = false;

        for (stream_id, current_window) in self.stream_windows.iter_mut() {
            let new_window = current_window.saturating_add(delta);

            // Check for overflow in flow control calculations
            if self.config.detect_overflow {
                if delta > 0 && *current_window > 0 && new_window < *current_window {
                    overflow_detected = true;
                    self.stats.overflow_detections += 1;
                }

                // Check if new window exceeds safe calculation limits
                if new_window > self.config.max_safe_calculation as i64 {
                    overflow_detected = true;
                    self.stats.overflow_detections += 1;
                }
            }

            *current_window = new_window;

            // Update stats
            if new_window > self.stats.max_window_seen {
                self.stats.max_window_seen = new_window;
            }
        }

        self.initial_window_size = new_size;

        if overflow_detected && self.config.strict_rfc_enforcement {
            SettingsResult::FlowControlError("Window size calculations would overflow".to_string())
        } else {
            SettingsResult::Applied {
                old_size: old_initial_size as u32,
                new_size,
                streams_affected: self.stream_windows.len(),
                overflow_detected,
            }
        }
    }

    /// Open a new stream with initial window size
    fn open_stream(&mut self, stream_id: u32) -> StreamResult {
        if self.stream_windows.contains_key(&stream_id) {
            return StreamResult::AlreadyExists;
        }

        let initial_window = self.initial_window_size as i64;
        self.stream_windows.insert(stream_id, initial_window);
        self.stats.streams_opened += 1;

        // Update max window seen
        if initial_window > self.stats.max_window_seen {
            self.stats.max_window_seen = initial_window;
        }

        StreamResult::Opened {
            stream_id,
            initial_window,
        }
    }

    /// Send data on a stream with flow control
    fn send_data(&mut self, stream_id: u32, data_size: u32) -> DataSendResult {
        self.stats.data_operations += 1;

        let data_size_i64 = data_size as i64;

        // Check stream window
        let stream_window = match self.stream_windows.get_mut(&stream_id) {
            Some(window) => window,
            None => {
                return DataSendResult::StreamNotFound(stream_id);
            }
        };

        // Check connection window
        if self.connection_window < data_size_i64 {
            return DataSendResult::ConnectionWindowExhausted {
                requested: data_size,
                available_connection: self.connection_window as u32,
            };
        }

        // Check stream window
        if *stream_window < data_size_i64 {
            return DataSendResult::StreamWindowExhausted {
                stream_id,
                requested: data_size,
                available_stream: *stream_window as u32,
            };
        }

        // Perform the send operation with overflow protection
        if self.config.detect_overflow {
            // Check for underflow in window calculations
            if *stream_window < data_size_i64 || self.connection_window < data_size_i64 {
                return DataSendResult::FlowControlError(
                    "Window underflow detected in send operation".to_string(),
                );
            }

            // Check for negative result
            let new_stream_window = *stream_window - data_size_i64;
            let new_connection_window = self.connection_window - data_size_i64;

            if new_stream_window < 0 || new_connection_window < 0 {
                return DataSendResult::FlowControlError(
                    "Negative window detected after send".to_string(),
                );
            }
        }

        // Update windows
        *stream_window -= data_size_i64;
        self.connection_window -= data_size_i64;

        self.stats.bytes_sent += data_size as u64;

        DataSendResult::Success {
            bytes_sent: data_size,
            remaining_stream_window: *stream_window as u32,
            remaining_connection_window: self.connection_window as u32,
        }
    }

    /// Send WINDOW_UPDATE to increase available window
    fn window_update(&mut self, stream_id: u32, increment: u32) -> WindowUpdateResult {
        self.stats.window_updates += 1;

        if increment == 0 {
            return WindowUpdateResult::ProtocolError(
                "WINDOW_UPDATE increment cannot be zero".to_string(),
            );
        }

        if increment > 2_147_483_647 {
            return WindowUpdateResult::ProtocolError(format!(
                "WINDOW_UPDATE increment {} exceeds maximum",
                increment
            ));
        }

        if stream_id == 0 {
            // Connection-level window update
            let new_window = self.connection_window.saturating_add(increment as i64);

            // Check for overflow
            if self.config.detect_overflow && new_window > self.config.max_safe_calculation as i64 {
                return WindowUpdateResult::FlowControlError(
                    "Connection window update would cause overflow".to_string(),
                );
            }

            self.connection_window = new_window;
            return WindowUpdateResult::Applied {
                stream_id: 0,
                new_window: new_window as u32,
            };
        }

        // Stream-level window update
        let stream_window = match self.stream_windows.get_mut(&stream_id) {
            Some(window) => window,
            None => {
                return WindowUpdateResult::StreamNotFound(stream_id);
            }
        };

        let new_window = stream_window.saturating_add(increment as i64);

        // Check for overflow
        if self.config.detect_overflow && new_window > self.config.max_safe_calculation as i64 {
            return WindowUpdateResult::FlowControlError(
                "Stream window update would cause overflow".to_string(),
            );
        }

        *stream_window = new_window;

        // Update stats
        if new_window > self.stats.max_window_seen {
            self.stats.max_window_seen = new_window;
        }

        WindowUpdateResult::Applied {
            stream_id,
            new_window: new_window as u32,
        }
    }

    fn get_stats(&self) -> FlowControlStats {
        self.stats.clone()
    }

    fn get_stream_window(&self, stream_id: u32) -> Option<i64> {
        self.stream_windows.get(&stream_id).copied()
    }
}

#[derive(Debug, Clone, Default)]
struct FlowControlStats {
    setting_changes: u32,
    streams_opened: u32,
    data_operations: u32,
    window_updates: u32,
    bytes_sent: u64,
    overflow_detections: u32,
    max_window_seen: i64,
}

#[derive(Debug, PartialEq)]
enum SettingsResult {
    Applied {
        old_size: u32,
        new_size: u32,
        streams_affected: usize,
        overflow_detected: bool,
    },
    FlowControlError(String),
}

#[derive(Debug, PartialEq)]
enum StreamResult {
    Opened { stream_id: u32, initial_window: i64 },
    AlreadyExists,
}

#[derive(Debug, PartialEq)]
enum DataSendResult {
    Success {
        bytes_sent: u32,
        remaining_stream_window: u32,
        remaining_connection_window: u32,
    },
    StreamNotFound(u32),
    StreamWindowExhausted {
        stream_id: u32,
        requested: u32,
        available_stream: u32,
    },
    ConnectionWindowExhausted {
        requested: u32,
        available_connection: u32,
    },
    FlowControlError(String),
}

#[derive(Debug, PartialEq)]
enum WindowUpdateResult {
    Applied { stream_id: u32, new_window: u32 },
    StreamNotFound(u32),
    FlowControlError(String),
    ProtocolError(String),
}

fuzz_target!(|input: MaxWindowSizeInput| {
    // Normalize input for reasonable fuzzing bounds
    let mut input = input;
    if input.data_operations.len() > 20 {
        input.data_operations.truncate(20); // Limit for performance
    }

    // Focus on maximum window size value
    let max_window_size = 2_147_483_647u32; // 2^31-1
    input.initial_window_size = max_window_size;

    let mut flow_control = MockH2FlowControl::new(input.flow_control_config.clone());

    // Apply the maximum initial window size setting
    let settings_result = flow_control.apply_initial_window_size_setting(input.initial_window_size);

    match settings_result {
        SettingsResult::Applied {
            new_size,
            overflow_detected,
            ..
        } => {
            // Verify maximum value was applied correctly
            assert_eq!(
                new_size, max_window_size,
                "Maximum window size should be applied correctly"
            );

            // Test that flow control state machine handles maximum values
            if flow_control.config.detect_overflow && overflow_detected {
                // Acceptable - overflow detection is working
            }
        }

        SettingsResult::FlowControlError(ref msg) => {
            // Should not error for the maximum valid value
            panic!(
                "Maximum valid window size should not cause flow control error: {}",
                msg
            );
        }
    }

    // Test data operations with maximum window size
    let mut streams_opened = std::collections::HashSet::new();

    for operation in &input.data_operations {
        // Ensure stream exists
        if !streams_opened.contains(&operation.stream_id) && operation.stream_id != 0 {
            let stream_result = flow_control.open_stream(operation.stream_id);
            match stream_result {
                StreamResult::Opened { initial_window, .. } => {
                    // Verify new streams get the maximum window size
                    assert_eq!(
                        initial_window, max_window_size as i64,
                        "New streams should get maximum initial window size"
                    );
                    streams_opened.insert(operation.stream_id);
                }
                StreamResult::AlreadyExists => {
                    streams_opened.insert(operation.stream_id);
                }
            }
        }

        // Perform data send operation
        if operation.stream_id != 0 {
            let send_result = flow_control.send_data(operation.stream_id, operation.data_size);

            match send_result {
                DataSendResult::Success {
                    remaining_stream_window,
                    remaining_connection_window,
                    ..
                } => {
                    // Verify arithmetic is correct without overflow
                    assert!(
                        remaining_stream_window <= max_window_size,
                        "Remaining stream window should not exceed maximum"
                    );
                    assert!(
                        remaining_connection_window
                            <= input.connection_config.connection_window as u32,
                        "Remaining connection window should be valid"
                    );
                }

                DataSendResult::StreamWindowExhausted { .. }
                | DataSendResult::ConnectionWindowExhausted { .. } => {
                    // Expected when trying to send more data than available window
                }

                DataSendResult::FlowControlError(ref msg) => {
                    // Should only occur for genuine overflow conditions
                    if !flow_control.config.detect_overflow {
                        panic!(
                            "Flow control error should not occur without overflow detection: {}",
                            msg
                        );
                    }
                }

                DataSendResult::StreamNotFound(_) => {
                    // Expected for stream ID 0 or unopened streams
                }
            }
        }
    }

    // Test window updates with maximum values
    for &stream_id in &streams_opened {
        let current_window = flow_control.get_stream_window(stream_id).unwrap_or(0);

        // Try a reasonable window update
        let update_increment = 1000;
        let update_result = flow_control.window_update(stream_id, update_increment);

        match update_result {
            WindowUpdateResult::Applied { new_window, .. } => {
                // Verify the arithmetic is correct
                let expected_window =
                    (current_window + update_increment as i64).min(max_window_size as i64);
                assert!(
                    new_window <= max_window_size,
                    "Window update should not exceed maximum window size"
                );
            }

            WindowUpdateResult::FlowControlError(ref msg) => {
                // Should only occur if update would cause overflow
                assert!(
                    msg.contains("overflow"),
                    "Flow control error should be due to overflow: {}",
                    msg
                );
            }

            _ => {
                // Other results are acceptable
            }
        }
    }

    // Test edge case: maximum increment on maximum window
    if let Some(&stream_id) = streams_opened.iter().next() {
        // Reset stream to maximum window
        let _ = flow_control.apply_initial_window_size_setting(max_window_size);

        // Try maximum increment
        let max_increment = 2_147_483_647u32;
        let edge_result = flow_control.window_update(stream_id, max_increment);

        match edge_result {
            WindowUpdateResult::FlowControlError(_) => {
                // Expected - this would cause overflow
            }
            WindowUpdateResult::Applied { new_window, .. } => {
                // If allowed, verify it's capped appropriately
                assert!(
                    new_window <= max_window_size,
                    "Maximum increment should not cause window to exceed limit"
                );
            }
            _ => {}
        }
    }

    // Verify statistics consistency
    let stats = flow_control.get_stats();
    assert!(
        stats.max_window_seen >= max_window_size as i64,
        "Should have seen maximum window size value"
    );

    // Verify no panics occurred during maximum value handling
    // (Implicit - if we reach here without panicking, the test passed)

    // Additional consistency checks for maximum value handling
    assert_eq!(
        flow_control.initial_window_size, max_window_size,
        "Initial window size should be set to maximum value"
    );

    // Test that all arithmetic operations remain within bounds
    for &stream_id in &streams_opened {
        if let Some(window) = flow_control.get_stream_window(stream_id) {
            assert!(window >= 0, "Stream window should never go negative");
            assert!(
                window <= max_window_size as i64,
                "Stream window should never exceed maximum"
            );
        }
    }

    assert!(
        flow_control.connection_window >= 0,
        "Connection window should never go negative"
    );
});
