#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// HTTP/2 SETTINGS parameters per RFC 7540 §6.5.2
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;

/// Default initial window size per RFC 7540 §6.9.2
const DEFAULT_INITIAL_WINDOW_SIZE: i64 = 65535;

/// Maximum window size per RFC 7540 §6.9.1 (2^31 - 1)
const MAX_WINDOW_SIZE: i64 = 2147483647;

/// SETTINGS frame parameter per RFC 7540 §6.5
#[derive(Debug, Clone)]
struct SettingsParameter {
    id: u16,
    value: u32,
}

/// Per-stream flow control state
#[derive(Debug, Clone)]
struct StreamFlowState {
    /// Current flow control window size (can go negative per RFC 7540 §6.9.2)
    window_size: i64,
    /// Whether stream is flow-control blocked (window <= 0)
    blocked: bool,
    /// Total data sent on this stream
    data_sent: u64,
    /// Whether stream is closed
    closed: bool,
}

impl StreamFlowState {
    fn new(initial_window_size: i64) -> Self {
        Self {
            window_size: initial_window_size,
            blocked: initial_window_size <= 0,
            data_sent: 0,
            closed: false,
        }
    }

    /// Apply WINDOW_UPDATE to this stream
    fn apply_window_update(&mut self, increment: u32) -> Result<(), String> {
        let new_window = self.window_size.saturating_add(increment as i64);

        // RFC 7540 §6.9.1: Window size must not exceed 2^31 - 1
        if new_window > MAX_WINDOW_SIZE {
            return Err(format!(
                "Window update would overflow: {} + {} > {}",
                self.window_size, increment, MAX_WINDOW_SIZE
            ));
        }

        self.window_size = new_window;
        self.blocked = self.window_size <= 0;
        Ok(())
    }

    /// Apply SETTINGS_INITIAL_WINDOW_SIZE change
    fn apply_initial_window_size_change(
        &mut self,
        old_size: i64,
        new_size: i64,
    ) -> Result<(), String> {
        // RFC 7540 §6.9.2: Existing flow-control windows are updated by the delta
        let delta = new_size.saturating_sub(old_size);
        let new_window = self.window_size.saturating_add(delta);

        // RFC 7540 §6.9.2: Negative windows are valid but block the stream
        // No overflow check here - negative windows are explicitly allowed
        self.window_size = new_window;
        self.blocked = self.window_size <= 0;

        self.assert_window_consistency("SETTINGS_INITIAL_WINDOW_SIZE stream delta");

        Ok(())
    }

    /// Send data on stream (consumes window)
    fn send_data(&mut self, data_size: u32) -> Result<bool, String> {
        if self.closed {
            return Err("Cannot send data on closed stream".to_string());
        }

        // RFC 7540 §6.9.1: Cannot send if flow-control blocked
        if self.blocked || self.window_size <= 0 {
            return Ok(false); // Blocked, cannot send
        }

        let data_size_i64 = data_size as i64;
        if self.window_size < data_size_i64 {
            return Ok(false); // Insufficient window
        }

        self.window_size -= data_size_i64;
        self.data_sent += data_size as u64;
        self.blocked = self.window_size <= 0;

        Ok(true) // Successfully sent
    }

    fn assert_window_consistency(&self, context: &str) {
        assert_eq!(
            self.blocked,
            self.window_size <= 0,
            "{context}: blocked flag inconsistent with stream window {}",
            self.window_size
        );
        assert!(
            self.window_size >= -MAX_WINDOW_SIZE,
            "{context}: stream window underflowed: {}",
            self.window_size
        );
    }
}

/// Mock HTTP/2 flow control state machine
#[derive(Debug)]
struct MockH2FlowControl {
    /// Current SETTINGS_INITIAL_WINDOW_SIZE value
    initial_window_size: i64,
    /// Connection-level flow control window
    connection_window: i64,
    /// Per-stream flow control state
    streams: HashMap<u32, StreamFlowState>,
}

impl MockH2FlowControl {
    fn new() -> Self {
        Self {
            initial_window_size: DEFAULT_INITIAL_WINDOW_SIZE,
            connection_window: DEFAULT_INITIAL_WINDOW_SIZE,
            streams: HashMap::new(),
        }
    }

    /// Create or get stream with current initial window size
    fn get_or_create_stream(&mut self, stream_id: u32) -> &mut StreamFlowState {
        self.streams
            .entry(stream_id)
            .or_insert_with(|| StreamFlowState::new(self.initial_window_size))
    }

    /// Process SETTINGS frame with INITIAL_WINDOW_SIZE
    fn process_settings(&mut self, params: &[SettingsParameter]) -> Result<(), String> {
        for param in params {
            if param.id == SETTINGS_INITIAL_WINDOW_SIZE {
                // RFC 7540 §6.5.2: Value must not exceed 2^31 - 1
                if param.value > MAX_WINDOW_SIZE as u32 {
                    return Err(format!(
                        "SETTINGS_INITIAL_WINDOW_SIZE {} exceeds maximum {}",
                        param.value, MAX_WINDOW_SIZE
                    ));
                }

                let old_window_size = self.initial_window_size;
                let new_window_size = param.value as i64;

                // Update all existing streams per RFC 7540 §6.9.2
                for (stream_id, stream) in &mut self.streams {
                    if let Err(e) =
                        stream.apply_initial_window_size_change(old_window_size, new_window_size)
                    {
                        return Err(format!("Stream {} window update failed: {}", stream_id, e));
                    }
                }

                self.initial_window_size = new_window_size;

                self.assert_all_streams_consistent("SETTINGS_INITIAL_WINDOW_SIZE change");
            }
        }
        Ok(())
    }

    /// Process WINDOW_UPDATE frame
    fn process_window_update(&mut self, stream_id: u32, increment: u32) -> Result<(), String> {
        if stream_id == 0 {
            // Connection-level window update
            let new_window = self.connection_window.saturating_add(increment as i64);
            if new_window > MAX_WINDOW_SIZE {
                return Err(format!(
                    "Connection window update would overflow: {} + {} > {}",
                    self.connection_window, increment, MAX_WINDOW_SIZE
                ));
            }
            self.connection_window = new_window;
        } else {
            // Stream-level window update
            let stream = self.get_or_create_stream(stream_id);
            stream.apply_window_update(increment)?;
        }
        Ok(())
    }

    /// Send data on stream (testing flow control enforcement)
    fn send_data(&mut self, stream_id: u32, data_size: u32) -> Result<bool, String> {
        // Check connection-level window
        if self.connection_window < data_size as i64 {
            return Ok(false); // Connection blocked
        }

        // Check stream-level window
        let stream = self.get_or_create_stream(stream_id);
        let can_send = stream.send_data(data_size)?;

        if can_send {
            // Deduct from connection window too
            self.connection_window -= data_size as i64;
        }

        Ok(can_send)
    }

    /// Get current stream state for testing
    fn get_stream_state(&self, stream_id: u32) -> Option<&StreamFlowState> {
        self.streams.get(&stream_id)
    }

    /// Get current initial window size setting
    fn get_initial_window_size(&self) -> i64 {
        self.initial_window_size
    }

    fn assert_all_streams_consistent(&self, context: &str) {
        for (stream_id, state) in &self.streams {
            state.assert_window_consistency(context);
            assert!(
                state.window_size <= MAX_WINDOW_SIZE,
                "{context}: stream {stream_id} window overflowed: {}",
                state.window_size
            );
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Initial SETTINGS_INITIAL_WINDOW_SIZE value
    initial_window_size: u32,
    /// Stream operations to perform
    operations: Vec<Operation>,
    /// Whether to test the classic negative window scenario
    test_classic_negative: bool,
    /// Whether to test extreme values
    test_extreme_values: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum Operation {
    /// Send SETTINGS frame with new INITIAL_WINDOW_SIZE
    ChangeInitialWindowSize(u32),
    /// Send WINDOW_UPDATE for specific stream
    WindowUpdate { stream_id: u32, increment: u32 },
    /// Try to send data on stream
    SendData { stream_id: u32, size: u32 },
    /// Create new stream
    CreateStream(u32),
}

fn assert_window_update_overflow_error(context: &str, error: &str) {
    assert!(
        !error.trim().is_empty(),
        "{context}: flow-control error should include diagnostics"
    );
    assert!(
        error.contains("overflow") || error.contains("exceed"),
        "{context}: expected overflow diagnostic, got: {error}"
    );
}

fuzz_target!(|input: FuzzInput| {
    let mut flow_control = MockH2FlowControl::new();
    let mut operations = input.operations;

    // Set initial window size
    let initial_params = vec![SettingsParameter {
        id: SETTINGS_INITIAL_WINDOW_SIZE,
        value: input.initial_window_size.min(MAX_WINDOW_SIZE as u32),
    }];

    match flow_control.process_settings(&initial_params) {
        Ok(()) => {}
        Err(error) => {
            panic!("clamped initial SETTINGS_INITIAL_WINDOW_SIZE should be valid: {error}")
        }
    }

    // Add classic negative window test case if requested
    if input.test_classic_negative {
        // Classic scenario: Start with 10000, use 5000, change to 2000 (delta -8000) → -3000 window
        operations.insert(0, Operation::ChangeInitialWindowSize(10000));
        operations.insert(1, Operation::CreateStream(1));
        operations.insert(
            2,
            Operation::SendData {
                stream_id: 1,
                size: 5000,
            },
        );
        operations.insert(3, Operation::ChangeInitialWindowSize(2000));
    }

    // Add extreme value tests
    if input.test_extreme_values {
        operations.push(Operation::ChangeInitialWindowSize(MAX_WINDOW_SIZE as u32));
        operations.push(Operation::WindowUpdate {
            stream_id: 1,
            increment: MAX_WINDOW_SIZE as u32,
        });
        operations.push(Operation::ChangeInitialWindowSize(1));
    }

    // Process operations
    for (op_index, operation) in operations.iter().enumerate() {
        match operation {
            Operation::ChangeInitialWindowSize(new_size) => {
                // Clamp to valid range
                let clamped_size = (*new_size).min(MAX_WINDOW_SIZE as u32);
                let params = vec![SettingsParameter {
                    id: SETTINGS_INITIAL_WINDOW_SIZE,
                    value: clamped_size,
                }];

                match flow_control.process_settings(&params) {
                    Ok(()) => {
                        // Verify initial window size was updated
                        assert_eq!(
                            flow_control.get_initial_window_size(),
                            clamped_size as i64,
                            "Initial window size not updated correctly"
                        );
                    }
                    Err(error) => {
                        panic!("clamped SETTINGS_INITIAL_WINDOW_SIZE should be valid: {error}");
                    }
                }
            }

            Operation::WindowUpdate {
                stream_id,
                increment,
            } => {
                // Ensure stream ID is valid (non-zero for stream-level updates)
                let stream_id = if *stream_id == 0 && op_index % 2 == 0 {
                    1
                } else {
                    *stream_id
                };
                let increment = (*increment).max(1).min(MAX_WINDOW_SIZE as u32);

                match flow_control.process_window_update(stream_id, increment) {
                    Ok(()) => {
                        if stream_id != 0 {
                            let stream_state = flow_control.get_stream_state(stream_id).expect(
                                "successful stream WINDOW_UPDATE should create stream state",
                            );
                            stream_state.assert_window_consistency("WINDOW_UPDATE");
                        }
                    }
                    Err(error) => {
                        assert_window_update_overflow_error("WINDOW_UPDATE", &error);
                    }
                }
            }

            Operation::SendData { stream_id, size } => {
                let stream_id = if *stream_id == 0 { 1 } else { *stream_id };
                let size = (*size).min(MAX_WINDOW_SIZE as u32);

                match flow_control.send_data(stream_id, size) {
                    Ok(sent) => {
                        // Data send attempt completed
                        let stream_state = flow_control.get_stream_state(stream_id);

                        if let Some(state) = stream_state {
                            if sent {
                                // Data was sent - window should be reduced
                                assert!(
                                    !state.blocked || state.window_size > 0,
                                    "Stream marked as not blocked but has non-positive window"
                                );
                            } else {
                                // Data was not sent - should be due to flow control
                                // (either blocked flag or insufficient window)
                                if !state.blocked && state.window_size > size as i64 {
                                    // If not blocked and sufficient window, failure might be connection-level
                                    // This is acceptable
                                }
                            }

                            // CRITICAL: Verify window size is within reasonable bounds
                            // Negative windows are allowed per RFC 7540 §6.9.2, but should not underflow
                            assert!(
                                state.window_size >= -(MAX_WINDOW_SIZE),
                                "Stream window size underflowed: {}",
                                state.window_size
                            );
                        }
                    }
                    Err(error) => {
                        panic!("send_data should not error for open fuzz streams: {error}");
                    }
                }
            }

            Operation::CreateStream(stream_id) => {
                let stream_id = if *stream_id == 0 { 1 } else { *stream_id };

                // Creating stream should use current initial window size
                let initial_window = flow_control.get_initial_window_size();
                let existed = flow_control.get_stream_state(stream_id).is_some();
                let _stream = flow_control.get_or_create_stream(stream_id);

                // Verify new stream has correct initial window
                if let Some(state) = flow_control.get_stream_state(stream_id) {
                    if !existed {
                        assert_eq!(
                            state.window_size, initial_window,
                            "New stream {} did not inherit current SETTINGS_INITIAL_WINDOW_SIZE",
                            stream_id
                        );
                    }
                    state.assert_window_consistency("stream creation");
                }
            }
        }
    }

    // CORE ASSERTION: Test the specific negative window scenario
    if input.test_classic_negative {
        // Verify the classic scenario worked as expected
        if let Some(stream_state) = flow_control.get_stream_state(1) {
            stream_state.assert_window_consistency("classic negative-window scenario");

            // The stream should be flow-control blocked with negative window
            assert!(
                stream_state.blocked,
                "Stream should be blocked after negative window change"
            );

            // Window should be negative (around -3000 in classic scenario)
            assert!(
                stream_state.window_size < 0,
                "Stream window should be negative after classic scenario: {}",
                stream_state.window_size
            );

            // Window should not have underflowed beyond reasonable bounds
            assert!(
                stream_state.window_size > -(MAX_WINDOW_SIZE),
                "Stream window underflowed: {}",
                stream_state.window_size
            );

            // Try to send more data - should fail due to negative window
            let can_send_when_negative = flow_control.send_data(1, 100);
            match can_send_when_negative {
                Ok(false) => {
                    // Expected - should be blocked
                }
                Ok(true) => {
                    panic!("Should not be able to send data when stream has negative window");
                }
                Err(error) => {
                    panic!("negative-window send should report blocked, not error: {error}");
                }
            }

            // Now send a large WINDOW_UPDATE to make window positive again
            if flow_control.process_window_update(1, 10000).is_ok() {
                let updated_state = flow_control.get_stream_state(1).unwrap();

                // Stream should no longer be blocked if window became positive
                if updated_state.window_size > 0 {
                    assert!(
                        !updated_state.blocked,
                        "Stream should not be blocked after window becomes positive"
                    );
                }
            }
        }
    }

    // Additional validation: Check all stream windows are within bounds
    for (stream_id, state) in flow_control.streams.iter() {
        // RFC 7540 §6.9.2: Negative windows are valid, but should not underflow
        assert!(
            state.window_size >= -(MAX_WINDOW_SIZE),
            "Stream {} window underflowed: {}",
            stream_id,
            state.window_size
        );

        // Blocked flag should match window state
        assert_eq!(
            state.blocked,
            state.window_size <= 0,
            "Stream {} blocked flag inconsistent with window size {}",
            stream_id,
            state.window_size
        );

        // Data sent should be reasonable
        assert!(
            state.data_sent < u64::MAX / 2,
            "Stream {} data sent counter seems corrupted: {}",
            stream_id,
            state.data_sent
        );
    }

    // Connection window should also be within bounds
    assert!(
        flow_control.connection_window >= -(MAX_WINDOW_SIZE),
        "Connection window underflowed: {}",
        flow_control.connection_window
    );
    assert!(
        flow_control.connection_window <= MAX_WINDOW_SIZE,
        "Connection window overflowed: {}",
        flow_control.connection_window
    );

    // Initial window size should be within valid range
    assert!(
        flow_control.get_initial_window_size() <= MAX_WINDOW_SIZE,
        "Initial window size invalid: {}",
        flow_control.get_initial_window_size()
    );
    assert!(
        flow_control.get_initial_window_size() >= 0,
        "Initial window size should not be negative: {}",
        flow_control.get_initial_window_size()
    );
});
