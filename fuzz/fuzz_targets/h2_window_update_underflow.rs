#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

// Mock HTTP/2 flow control and WINDOW_UPDATE frames for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct WindowUpdateTestCase {
    initial_connection_window: i64,
    initial_stream_windows: Vec<StreamWindow>,
    window_updates: Vec<WindowUpdateFrame>,
    data_frames: Vec<DataFrameConsumption>,
    underflow_scenarios: UnderflowScenarios,
}

#[derive(Debug, Clone, Arbitrary)]
struct StreamWindow {
    stream_id: u32,
    initial_window: i64,
}

#[derive(Debug, Clone, Arbitrary)]
struct WindowUpdateFrame {
    stream_id: u32, // 0 = connection level
    window_size_increment: u32,
    timing: UpdateTiming,
    malformed_patterns: WindowUpdateMalformed,
}

#[derive(Debug, Clone, Arbitrary)]
enum UpdateTiming {
    BeforeDataConsumption,
    AfterDataConsumption,
    InterleaveWithData,
    Rapid(u8), // Count of rapid updates
}

#[derive(Debug, Clone, Arbitrary)]
struct WindowUpdateMalformed {
    zero_increment: bool,
    max_u32_increment: bool,
    reserved_bit_set: bool,
    invalid_stream_id: bool,
}

#[derive(Debug, Clone, Arbitrary)]
struct DataFrameConsumption {
    stream_id: u32,
    bytes_consumed: u32,
    consume_connection_window: bool,
}

#[derive(Debug, Clone, Arbitrary)]
struct UnderflowScenarios {
    negative_sum_window: bool,
    multiple_decrements: bool,
    large_increment_then_consumption: bool,
    connection_window_underflow: bool,
    stream_window_underflow: bool,
    zero_window_updates: bool,
    overflow_then_underflow: bool,
}

// HTTP/2 constants
const WINDOW_UPDATE_FRAME_TYPE: u8 = 0x8;
const INITIAL_WINDOW_SIZE: i64 = 65535; // RFC 9113 default
const MAX_WINDOW_SIZE: i64 = 2147483647; // 2^31 - 1

fuzz_target!(|data: &[u8]| {
    // Guard against excessively large inputs
    if data.len() > 50_000 {
        return;
    }

    let mut u = Unstructured::new(data);

    // Try to generate a test case from the fuzz input
    let test_case = match WindowUpdateTestCase::arbitrary(&mut u) {
        Ok(case) => case,
        Err(_) => return, // Invalid input for generating test case
    };

    // Test scenario 1: Basic window update underflow detection
    test_basic_window_underflow(&test_case);

    // Test scenario 2: Connection-level window underflow
    test_connection_window_underflow(&test_case);

    // Test scenario 3: Stream-level window underflow
    test_stream_window_underflow(&test_case);

    // Test scenario 4: Multiple decremental updates causing underflow
    test_multiple_decremental_updates(&test_case);

    // Test scenario 5: Large increment followed by excessive consumption
    test_large_increment_consumption(&test_case);

    // Test scenario 6: Zero increment window updates
    test_zero_increment_updates(&test_case);

    // Test scenario 7: Overflow then underflow sequence
    test_overflow_underflow_sequence(&test_case);

    // Test scenario 8: Rapid window update sequence
    test_rapid_window_updates(&test_case);

    // Test scenario 9: Invalid stream ID window updates
    test_invalid_stream_window_updates(&test_case);

    // Test scenario 10: Window state consistency across operations
    test_window_state_consistency(&test_case);
});

/// Test basic window update underflow detection
fn test_basic_window_underflow(test_case: &WindowUpdateTestCase) {
    let mut flow_control = create_flow_control_context(
        test_case.initial_connection_window,
        &test_case.initial_stream_windows,
    );

    // Process window updates and look for underflow
    for update in &test_case.window_updates {
        let result = flow_control.process_window_update(update);

        match result {
            Ok(window_state) => {
                // Verify window values are never negative
                if update.stream_id == 0 {
                    // Connection window
                    assert!(
                        window_state.connection_window >= 0,
                        "Connection window should never be negative: {}",
                        window_state.connection_window
                    );
                } else {
                    // Stream window
                    if let Some(stream_window) = window_state.stream_windows.get(&update.stream_id)
                    {
                        assert!(
                            *stream_window >= 0,
                            "Stream {} window should never be negative: {}",
                            update.stream_id,
                            stream_window
                        );
                    }
                }

                // Verify window doesn't exceed maximum
                let window_value = if update.stream_id == 0 {
                    window_state.connection_window
                } else {
                    window_state
                        .stream_windows
                        .get(&update.stream_id)
                        .copied()
                        .unwrap_or(0)
                };

                assert!(
                    window_value <= MAX_WINDOW_SIZE,
                    "Window value {} exceeds maximum {}",
                    window_value,
                    MAX_WINDOW_SIZE
                );
            }
            Err(error_msg) => {
                // Check for proper FLOW_CONTROL_ERROR when underflow would occur
                if would_cause_underflow(&flow_control, update) {
                    assert!(
                        error_msg.contains("FLOW_CONTROL_ERROR")
                            || error_msg.contains("window underflow")
                            || error_msg.contains("negative window"),
                        "Underflow should cause FLOW_CONTROL_ERROR, got: {}",
                        error_msg
                    );
                }

                // Check for proper error on invalid increments
                if update.window_size_increment == 0 {
                    assert!(
                        error_msg.contains("zero increment")
                            || error_msg.contains("PROTOCOL_ERROR"),
                        "Zero increment should cause PROTOCOL_ERROR, got: {}",
                        error_msg
                    );
                }
            }
        }
    }
}

/// Test connection-level window underflow
fn test_connection_window_underflow(test_case: &WindowUpdateTestCase) {
    if !test_case.underflow_scenarios.connection_window_underflow {
        return;
    }

    let mut flow_control = create_flow_control_context(
        INITIAL_WINDOW_SIZE, // Start with default window
        &test_case.initial_stream_windows,
    );

    // Consume significant connection window first
    let large_consumption = DataFrameConsumption {
        stream_id: 1,
        bytes_consumed: (INITIAL_WINDOW_SIZE - 1000) as u32, // Leave small window
        consume_connection_window: true,
    };

    let consumption_result = flow_control.consume_window(&large_consumption);
    assert!(
        consumption_result.is_ok(),
        "Initial consumption should succeed"
    );

    // Now try window updates that would cause underflow
    let underflow_updates = vec![WindowUpdateFrame {
        stream_id: 0,                // Connection level
        window_size_increment: 2000, // This should work
        timing: UpdateTiming::AfterDataConsumption,
        malformed_patterns: WindowUpdateMalformed {
            zero_increment: false,
            max_u32_increment: false,
            reserved_bit_set: false,
            invalid_stream_id: false,
        },
    }];

    for update in &underflow_updates {
        let result = flow_control.process_window_update(update);

        match result {
            Ok(window_state) => {
                // Verify connection window is valid
                assert!(
                    window_state.connection_window >= 0,
                    "Connection window underflow: {}",
                    window_state.connection_window
                );
            }
            Err(error_msg) => {
                // Should be FLOW_CONTROL_ERROR if underflow attempted
                if would_cause_connection_underflow(&flow_control, update) {
                    assert!(
                        error_msg.contains("FLOW_CONTROL_ERROR"),
                        "Connection underflow should cause FLOW_CONTROL_ERROR: {}",
                        error_msg
                    );
                }
            }
        }
    }
}

/// Test stream-level window underflow
fn test_stream_window_underflow(test_case: &WindowUpdateTestCase) {
    if !test_case.underflow_scenarios.stream_window_underflow {
        return;
    }

    let mut flow_control = create_flow_control_context(
        test_case.initial_connection_window,
        &test_case.initial_stream_windows,
    );

    // Test each configured stream
    for stream_window in &test_case.initial_stream_windows {
        let stream_id = stream_window.stream_id;

        if stream_id == 0 {
            continue; // Skip connection-level
        }

        // Consume most of the stream window
        let consumption = DataFrameConsumption {
            stream_id,
            bytes_consumed: (stream_window.initial_window.saturating_sub(500).max(0)) as u32,
            consume_connection_window: false, // Only stream window
        };

        let _ = flow_control.consume_window(&consumption);

        // Try window updates on this stream
        for update in test_case
            .window_updates
            .iter()
            .filter(|u| u.stream_id == stream_id)
        {
            let result = flow_control.process_window_update(update);

            match result {
                Ok(window_state) => {
                    if let Some(&stream_window_value) = window_state.stream_windows.get(&stream_id)
                    {
                        assert!(
                            stream_window_value >= 0,
                            "Stream {} window underflow: {}",
                            stream_id,
                            stream_window_value
                        );
                    }
                }
                Err(error_msg) => {
                    if would_cause_stream_underflow(&flow_control, update) {
                        assert!(
                            error_msg.contains("FLOW_CONTROL_ERROR"),
                            "Stream underflow should cause FLOW_CONTROL_ERROR: {}",
                            error_msg
                        );
                    }
                }
            }
        }
    }
}

/// Test multiple decremental updates causing underflow
fn test_multiple_decremental_updates(test_case: &WindowUpdateTestCase) {
    if !test_case.underflow_scenarios.multiple_decrements {
        return;
    }

    let mut flow_control =
        create_flow_control_context(INITIAL_WINDOW_SIZE, &test_case.initial_stream_windows);

    // Create sequence of data consumptions without window updates
    let decremental_operations = vec![
        DataFrameConsumption {
            stream_id: 1,
            bytes_consumed: 20000,
            consume_connection_window: true,
        },
        DataFrameConsumption {
            stream_id: 1,
            bytes_consumed: 20000,
            consume_connection_window: true,
        },
        DataFrameConsumption {
            stream_id: 1,
            bytes_consumed: 30000,
            consume_connection_window: true,
        },
    ];

    for consumption in &decremental_operations {
        let result = flow_control.consume_window(consumption);

        match result {
            Ok(window_state) => {
                // Verify windows remain non-negative
                assert!(
                    window_state.connection_window >= 0,
                    "Connection window should not go negative"
                );
            }
            Err(error_msg) => {
                // Should fail gracefully when attempting to consume more than available
                assert!(
                    error_msg.contains("insufficient window")
                        || error_msg.contains("FLOW_CONTROL_ERROR"),
                    "Overconsumption should be properly rejected: {}",
                    error_msg
                );
                break; // Stop on first failure
            }
        }
    }
}

/// Test large increment followed by excessive consumption
fn test_large_increment_consumption(test_case: &WindowUpdateTestCase) {
    if !test_case
        .underflow_scenarios
        .large_increment_then_consumption
    {
        return;
    }

    let mut flow_control =
        create_flow_control_context(INITIAL_WINDOW_SIZE, &test_case.initial_stream_windows);

    // Apply large window increment
    let large_increment = WindowUpdateFrame {
        stream_id: 0,
        window_size_increment: 1_000_000, // 1MB increment
        timing: UpdateTiming::BeforeDataConsumption,
        malformed_patterns: WindowUpdateMalformed {
            zero_increment: false,
            max_u32_increment: false,
            reserved_bit_set: false,
            invalid_stream_id: false,
        },
    };

    let increment_result = flow_control.process_window_update(&large_increment);

    if let Ok(window_state) = increment_result {
        let available_window = window_state.connection_window;

        // Try to consume more than the available window
        let excessive_consumption = DataFrameConsumption {
            stream_id: 1,
            bytes_consumed: (available_window + 1000) as u32,
            consume_connection_window: true,
        };

        let consumption_result = flow_control.consume_window(&excessive_consumption);

        match consumption_result {
            Ok(_) => {
                // If consumption succeeded, verify window is still non-negative
                let final_state = flow_control.get_window_state();
                assert!(
                    final_state.connection_window >= 0,
                    "Window should not be negative after consumption"
                );
            }
            Err(error_msg) => {
                // Should properly reject excessive consumption
                assert!(
                    error_msg.contains("insufficient") || error_msg.contains("FLOW_CONTROL_ERROR"),
                    "Excessive consumption should be rejected: {}",
                    error_msg
                );
            }
        }
    }
}

/// Test zero increment window updates
fn test_zero_increment_updates(test_case: &WindowUpdateTestCase) {
    if !test_case.underflow_scenarios.zero_window_updates {
        return;
    }

    let mut flow_control = create_flow_control_context(
        test_case.initial_connection_window,
        &test_case.initial_stream_windows,
    );

    // Test zero increment on connection
    let zero_connection_update = WindowUpdateFrame {
        stream_id: 0,
        window_size_increment: 0,
        timing: UpdateTiming::Immediate,
        malformed_patterns: WindowUpdateMalformed {
            zero_increment: true,
            max_u32_increment: false,
            reserved_bit_set: false,
            invalid_stream_id: false,
        },
    };

    let result = flow_control.process_window_update(&zero_connection_update);

    match result {
        Ok(_) => {
            // Some implementations might allow zero increments as no-ops
        }
        Err(error_msg) => {
            // RFC 9113 requires rejecting zero increments
            assert!(
                error_msg.contains("PROTOCOL_ERROR") || error_msg.contains("zero increment"),
                "Zero increment should cause PROTOCOL_ERROR: {}",
                error_msg
            );
        }
    }

    // Test zero increment on stream
    if let Some(stream) = test_case.initial_stream_windows.first() {
        let zero_stream_update = WindowUpdateFrame {
            stream_id: stream.stream_id,
            window_size_increment: 0,
            timing: UpdateTiming::Immediate,
            malformed_patterns: WindowUpdateMalformed {
                zero_increment: true,
                max_u32_increment: false,
                reserved_bit_set: false,
                invalid_stream_id: false,
            },
        };

        let result = flow_control.process_window_update(&zero_stream_update);

        match result {
            Ok(_) => {
                // Some implementations might allow zero increments
            }
            Err(error_msg) => {
                assert!(
                    error_msg.contains("PROTOCOL_ERROR") || error_msg.contains("zero increment"),
                    "Zero stream increment should cause PROTOCOL_ERROR: {}",
                    error_msg
                );
            }
        }
    }
}

/// Test overflow then underflow sequence
fn test_overflow_underflow_sequence(test_case: &WindowUpdateTestCase) {
    if !test_case.underflow_scenarios.overflow_then_underflow {
        return;
    }

    let mut flow_control =
        create_flow_control_context(INITIAL_WINDOW_SIZE, &test_case.initial_stream_windows);

    // First, try to cause overflow with large increment
    let overflow_update = WindowUpdateFrame {
        stream_id: 0,
        window_size_increment: (MAX_WINDOW_SIZE as u32).saturating_sub(INITIAL_WINDOW_SIZE as u32),
        timing: UpdateTiming::Immediate,
        malformed_patterns: WindowUpdateMalformed {
            zero_increment: false,
            max_u32_increment: true,
            reserved_bit_set: false,
            invalid_stream_id: false,
        },
    };

    let overflow_result = flow_control.process_window_update(&overflow_update);

    match overflow_result {
        Ok(window_state) => {
            // Verify no overflow occurred
            assert!(
                window_state.connection_window <= MAX_WINDOW_SIZE,
                "Window should not exceed maximum: {}",
                window_state.connection_window
            );

            // Now try to consume more than available (causing underflow)
            let underflow_consumption = DataFrameConsumption {
                stream_id: 1,
                bytes_consumed: (window_state.connection_window + 1000) as u32,
                consume_connection_window: true,
            };

            let underflow_result = flow_control.consume_window(&underflow_consumption);

            match underflow_result {
                Ok(_) => {
                    // Verify final state is consistent
                    let final_state = flow_control.get_window_state();
                    assert!(
                        final_state.connection_window >= 0,
                        "Final window should be non-negative"
                    );
                }
                Err(error_msg) => {
                    // Should properly reject underflow-causing consumption
                    assert!(
                        error_msg.contains("FLOW_CONTROL_ERROR")
                            || error_msg.contains("insufficient"),
                        "Underflow should be rejected: {}",
                        error_msg
                    );
                }
            }
        }
        Err(error_msg) => {
            // Overflow should be rejected
            assert!(
                error_msg.contains("FLOW_CONTROL_ERROR") || error_msg.contains("overflow"),
                "Overflow should be properly rejected: {}",
                error_msg
            );
        }
    }
}

/// Test rapid window update sequence
fn test_rapid_window_updates(test_case: &WindowUpdateTestCase) {
    let mut flow_control = create_flow_control_context(
        test_case.initial_connection_window,
        &test_case.initial_stream_windows,
    );

    // Apply rapid sequence of updates
    for (i, update) in test_case.window_updates.iter().enumerate().take(10) {
        let result = flow_control.process_window_update(update);

        match result {
            Ok(window_state) => {
                // Verify consistency after each update
                if update.stream_id == 0 {
                    assert!(
                        window_state.connection_window >= 0
                            && window_state.connection_window <= MAX_WINDOW_SIZE,
                        "Connection window out of bounds after update {}: {}",
                        i,
                        window_state.connection_window
                    );
                } else if let Some(&stream_window) =
                    window_state.stream_windows.get(&update.stream_id)
                {
                    assert!(
                        stream_window >= 0 && stream_window <= MAX_WINDOW_SIZE,
                        "Stream {} window out of bounds after update {}: {}",
                        update.stream_id,
                        i,
                        stream_window
                    );
                }
            }
            Err(error_msg) => {
                // Check error is appropriate
                if update.window_size_increment == 0 {
                    assert!(
                        error_msg.contains("PROTOCOL_ERROR"),
                        "Zero increment should cause PROTOCOL_ERROR: {}",
                        error_msg
                    );
                } else {
                    // Other errors should be flow control related
                    assert!(
                        error_msg.contains("FLOW_CONTROL_ERROR")
                            || error_msg.contains("window")
                            || error_msg.contains("overflow"),
                        "Unexpected error type: {}",
                        error_msg
                    );
                }
                break; // Stop on first error
            }
        }
    }
}

/// Test invalid stream ID window updates
fn test_invalid_stream_window_updates(test_case: &WindowUpdateTestCase) {
    let mut flow_control = create_flow_control_context(
        test_case.initial_connection_window,
        &test_case.initial_stream_windows,
    );

    // Test window update on non-existent stream
    let invalid_stream_update = WindowUpdateFrame {
        stream_id: 99999, // Non-existent stream
        window_size_increment: 1000,
        timing: UpdateTiming::Immediate,
        malformed_patterns: WindowUpdateMalformed {
            zero_increment: false,
            max_u32_increment: false,
            reserved_bit_set: false,
            invalid_stream_id: true,
        },
    };

    let result = flow_control.process_window_update(&invalid_stream_update);

    match result {
        Ok(_) => {
            // Some implementations might create stream windows dynamically
        }
        Err(error_msg) => {
            // Should reject updates on invalid streams
            assert!(
                error_msg.contains("invalid stream")
                    || error_msg.contains("unknown stream")
                    || error_msg.contains("PROTOCOL_ERROR"),
                "Invalid stream should be rejected: {}",
                error_msg
            );
        }
    }
}

/// Test window state consistency across operations
fn test_window_state_consistency(test_case: &WindowUpdateTestCase) {
    let mut flow_control = create_flow_control_context(
        test_case.initial_connection_window,
        &test_case.initial_stream_windows,
    );

    let initial_state = flow_control.get_window_state();

    // Apply data consumption and window updates interleaved
    for (i, data_frame) in test_case.data_frames.iter().enumerate().take(5) {
        // Consume window
        let consumption_result = flow_control.consume_window(data_frame);

        if let Ok(state_after_consumption) = consumption_result {
            // Verify consumption decreased windows appropriately
            if data_frame.consume_connection_window {
                assert!(
                    state_after_consumption.connection_window <= initial_state.connection_window,
                    "Connection window should decrease after consumption"
                );
            }
        }

        // Apply window update if available
        if let Some(update) = test_case.window_updates.get(i) {
            let update_result = flow_control.process_window_update(update);

            if let Ok(state_after_update) = update_result {
                // Verify window update increased windows appropriately
                if update.stream_id == 0 && update.window_size_increment > 0 {
                    // Connection window should have increased (unless at max)
                    let expected_min = state_after_consumption
                        .map(|s| s.connection_window)
                        .unwrap_or(initial_state.connection_window);

                    assert!(
                        state_after_update.connection_window >= expected_min,
                        "Window update should not decrease window"
                    );
                }
            }
        }
    }

    // Final consistency check
    let final_state = flow_control.get_window_state();
    assert!(
        final_state.connection_window >= 0,
        "Final connection window should be non-negative"
    );

    for (&stream_id, &window_value) in &final_state.stream_windows {
        assert!(
            window_value >= 0,
            "Final stream {} window should be non-negative: {}",
            stream_id,
            window_value
        );
    }
}

// Helper structures and functions

#[derive(Debug, Clone)]
struct FlowControlContext {
    connection_window: i64,
    stream_windows: HashMap<u32, i64>,
    max_window_size: i64,
}

#[derive(Debug, Clone)]
struct WindowState {
    connection_window: i64,
    stream_windows: HashMap<u32, i64>,
}

fn create_flow_control_context(
    initial_connection_window: i64,
    initial_streams: &[StreamWindow],
) -> FlowControlContext {
    let mut stream_windows = HashMap::new();

    for stream in initial_streams {
        if stream.stream_id != 0 {
            // Skip connection-level
            stream_windows.insert(
                stream.stream_id,
                stream.initial_window.min(MAX_WINDOW_SIZE).max(0),
            );
        }
    }

    FlowControlContext {
        connection_window: initial_connection_window.min(MAX_WINDOW_SIZE).max(0),
        stream_windows,
        max_window_size: MAX_WINDOW_SIZE,
    }
}

impl FlowControlContext {
    fn process_window_update(&mut self, update: &WindowUpdateFrame) -> Result<WindowState, String> {
        // Validate increment
        if update.window_size_increment == 0 {
            return Err("PROTOCOL_ERROR: Window update increment must be non-zero".to_string());
        }

        if update.window_size_increment > (MAX_WINDOW_SIZE as u32) {
            return Err("FLOW_CONTROL_ERROR: Window increment too large".to_string());
        }

        let increment = update.window_size_increment as i64;

        if update.stream_id == 0 {
            // Connection-level window update
            let new_window = self.connection_window.saturating_add(increment);

            if new_window > self.max_window_size {
                return Err("FLOW_CONTROL_ERROR: Window size exceeds maximum".to_string());
            }

            if new_window < 0 {
                return Err("FLOW_CONTROL_ERROR: Window underflow detected".to_string());
            }

            self.connection_window = new_window;
        } else {
            // Stream-level window update
            let current_window = self
                .stream_windows
                .get(&update.stream_id)
                .copied()
                .unwrap_or(INITIAL_WINDOW_SIZE);
            let new_window = current_window.saturating_add(increment);

            if new_window > self.max_window_size {
                return Err("FLOW_CONTROL_ERROR: Stream window size exceeds maximum".to_string());
            }

            if new_window < 0 {
                return Err(format!(
                    "FLOW_CONTROL_ERROR: Stream {} window underflow",
                    update.stream_id
                ));
            }

            self.stream_windows.insert(update.stream_id, new_window);
        }

        Ok(self.get_window_state())
    }

    fn consume_window(
        &mut self,
        consumption: &DataFrameConsumption,
    ) -> Result<WindowState, String> {
        let bytes = consumption.bytes_consumed as i64;

        // Check and update stream window
        if consumption.stream_id != 0 {
            let current_stream_window = self
                .stream_windows
                .get(&consumption.stream_id)
                .copied()
                .unwrap_or(INITIAL_WINDOW_SIZE);

            if current_stream_window < bytes {
                return Err(format!(
                    "FLOW_CONTROL_ERROR: Insufficient stream {} window: {} < {}",
                    consumption.stream_id, current_stream_window, bytes
                ));
            }

            let new_stream_window = current_stream_window - bytes;
            if new_stream_window < 0 {
                return Err(format!(
                    "FLOW_CONTROL_ERROR: Stream {} window would underflow",
                    consumption.stream_id
                ));
            }

            self.stream_windows
                .insert(consumption.stream_id, new_stream_window);
        }

        // Check and update connection window
        if consumption.consume_connection_window {
            if self.connection_window < bytes {
                return Err(format!(
                    "FLOW_CONTROL_ERROR: Insufficient connection window: {} < {}",
                    self.connection_window, bytes
                ));
            }

            let new_connection_window = self.connection_window - bytes;
            if new_connection_window < 0 {
                return Err("FLOW_CONTROL_ERROR: Connection window would underflow".to_string());
            }

            self.connection_window = new_connection_window;
        }

        Ok(self.get_window_state())
    }

    fn get_window_state(&self) -> WindowState {
        WindowState {
            connection_window: self.connection_window,
            stream_windows: self.stream_windows.clone(),
        }
    }
}

// Helper functions for underflow detection
fn would_cause_underflow(flow_control: &FlowControlContext, update: &WindowUpdateFrame) -> bool {
    let increment = update.window_size_increment as i64;

    if update.stream_id == 0 {
        flow_control.connection_window + increment < 0
    } else {
        let current_window = flow_control
            .stream_windows
            .get(&update.stream_id)
            .copied()
            .unwrap_or(INITIAL_WINDOW_SIZE);
        current_window + increment < 0
    }
}

fn would_cause_connection_underflow(
    flow_control: &FlowControlContext,
    update: &WindowUpdateFrame,
) -> bool {
    update.stream_id == 0 && would_cause_underflow(flow_control, update)
}

fn would_cause_stream_underflow(
    flow_control: &FlowControlContext,
    update: &WindowUpdateFrame,
) -> bool {
    update.stream_id != 0 && would_cause_underflow(flow_control, update)
}
