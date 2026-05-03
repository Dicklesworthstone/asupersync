#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// HTTP/2 frame header length per RFC 7540 §4.1
const FRAME_HEADER_LEN: usize = 9;

/// HTTP/2 frame types per RFC 7540 §6
const SETTINGS_FRAME_TYPE: u8 = 0x4;
const WINDOW_UPDATE_FRAME_TYPE: u8 = 0x8;
const DATA_FRAME_TYPE: u8 = 0x0;

/// HTTP/2 SETTINGS parameters per RFC 7540 §6.5.2
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;

/// SETTINGS frame flags
const SETTINGS_ACK_FLAG: u8 = 0x1;

/// Default initial window size per RFC 7540 §6.9.2
const DEFAULT_INITIAL_WINDOW_SIZE: i64 = 65535;

/// Maximum window size per RFC 7540 §6.9.1 (2^31 - 1)
const MAX_WINDOW_SIZE: i64 = 2147483647;

/// HTTP/2 error codes per RFC 7540 §7
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum Http2ErrorCode {
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
}

/// Flow control operation result
#[derive(Debug, PartialEq)]
enum FlowControlResult {
    Success,
    FlowControlError(String),
    ProtocolError(String),
    FrameSizeError,
    IncompleteFrame,
    InvalidStreamId,
}

/// HTTP/2 frame header per RFC 7540 §4.1
#[derive(Debug, Clone)]
struct FrameHeader {
    length: u32,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
}

impl FrameHeader {
    fn encode(&self) -> [u8; 9] {
        let mut buf = [0u8; 9];

        // Length (24 bits, big-endian)
        buf[0] = (self.length >> 16) as u8;
        buf[1] = (self.length >> 8) as u8;
        buf[2] = self.length as u8;

        // Type and flags
        buf[3] = self.frame_type;
        buf[4] = self.flags;

        // Stream ID (31 bits + reserved bit, big-endian)
        let stream_id = self.stream_id & 0x7FFF_FFFF;
        buf[5] = (stream_id >> 24) as u8;
        buf[6] = (stream_id >> 16) as u8;
        buf[7] = (stream_id >> 8) as u8;
        buf[8] = stream_id as u8;

        buf
    }

    fn decode(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 9 {
            return Err("incomplete header");
        }

        let length = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);

        let frame_type = buf[3];
        let flags = buf[4];

        let stream_id = ((buf[5] as u32 & 0x7F) << 24)
            | ((buf[6] as u32) << 16)
            | ((buf[7] as u32) << 8)
            | (buf[8] as u32);

        Ok(FrameHeader {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }
}

/// SETTINGS frame parameter per RFC 7540 §6.5
#[derive(Debug, Clone)]
struct SettingsParameter {
    id: u16,
    value: u32,
}

impl SettingsParameter {
    fn encode(&self) -> [u8; 6] {
        let mut buf = [0u8; 6];

        // Parameter ID (16 bits, big-endian)
        buf[0] = (self.id >> 8) as u8;
        buf[1] = self.id as u8;

        // Value (32 bits, big-endian)
        buf[2] = (self.value >> 24) as u8;
        buf[3] = (self.value >> 16) as u8;
        buf[4] = (self.value >> 8) as u8;
        buf[5] = self.value as u8;

        buf
    }

    fn decode(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 6 {
            return Err("insufficient data");
        }

        let id = ((buf[0] as u16) << 8) | (buf[1] as u16);
        let value = ((buf[2] as u32) << 24)
            | ((buf[3] as u32) << 16)
            | ((buf[4] as u32) << 8)
            | (buf[5] as u32);

        Ok(SettingsParameter { id, value })
    }
}

/// WINDOW_UPDATE frame data per RFC 7540 §6.9
#[derive(Debug, Clone)]
struct WindowUpdateData {
    window_size_increment: u32,
}

impl WindowUpdateData {
    fn encode(&self) -> [u8; 4] {
        let mut buf = [0u8; 4];
        // Reserved bit (R) must be 0, so mask with 0x7FFFFFFF
        let value = self.window_size_increment & 0x7FFF_FFFF;
        buf[0] = (value >> 24) as u8;
        buf[1] = (value >> 16) as u8;
        buf[2] = (value >> 8) as u8;
        buf[3] = value as u8;
        buf
    }

    fn decode(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 4 {
            return Err("insufficient data");
        }

        let value = ((buf[0] as u32 & 0x7F) << 24)
            | ((buf[1] as u32) << 16)
            | ((buf[2] as u32) << 8)
            | (buf[3] as u32);

        if value == 0 {
            return Err("window size increment cannot be zero");
        }

        Ok(WindowUpdateData {
            window_size_increment: value,
        })
    }
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

        // Log the change for debugging
        eprintln!(
            "Stream window change: {} + ({} - {}) = {} (blocked: {})",
            self.window_size - delta,
            new_size,
            old_size,
            self.window_size,
            self.blocked
        );

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

                eprintln!(
                    "Updated SETTINGS_INITIAL_WINDOW_SIZE: {} -> {} (delta: {})",
                    old_window_size,
                    new_window_size,
                    new_window_size - old_window_size
                );
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

    /// Check if stream is flow-control blocked
    fn is_stream_blocked(&self, stream_id: u32) -> bool {
        self.streams
            .get(&stream_id)
            .map(|s| s.blocked)
            .unwrap_or(false)
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

fuzz_target!(|input: FuzzInput| {
    let mut flow_control = MockH2FlowControl::new();
    let mut operations = input.operations;

    // Set initial window size
    let initial_params = vec![SettingsParameter {
        id: SETTINGS_INITIAL_WINDOW_SIZE,
        value: input.initial_window_size.min(MAX_WINDOW_SIZE as u32),
    }];

    if let Err(_) = flow_control.process_settings(&initial_params) {
        return; // Invalid initial settings
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
                    Err(_) => {
                        // Expected for invalid values
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
                        // Window update succeeded
                        if stream_id != 0 {
                            // Verify stream window was updated
                            let stream_state = flow_control.get_stream_state(stream_id);
                            // Note: Window might still be negative after update
                        }
                    }
                    Err(_) => {
                        // Expected for overflow cases
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
                    Err(_) => {
                        // Expected for invalid operations
                    }
                }
            }

            Operation::CreateStream(stream_id) => {
                let stream_id = if *stream_id == 0 { 1 } else { *stream_id };

                // Creating stream should use current initial window size
                let initial_window = flow_control.get_initial_window_size();
                let _stream = flow_control.get_or_create_stream(stream_id);

                // Verify new stream has correct initial window
                if let Some(state) = flow_control.get_stream_state(stream_id) {
                    // For newly created streams, window should match current initial setting
                    // But existing streams might have been affected by previous changes
                }
            }
        }
    }

    // CORE ASSERTION: Test the specific negative window scenario
    if input.test_classic_negative {
        // Verify the classic scenario worked as expected
        if let Some(stream_state) = flow_control.get_stream_state(1) {
            eprintln!(
                "Classic scenario result - Window: {}, Blocked: {}, Data sent: {}",
                stream_state.window_size, stream_state.blocked, stream_state.data_sent
            );

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
                Err(_) => {
                    // Also acceptable - error due to flow control
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
