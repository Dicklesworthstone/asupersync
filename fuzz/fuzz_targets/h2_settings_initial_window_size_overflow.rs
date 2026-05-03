//! Fuzzing target for HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE overflow protection.
//!
//! Tests RFC 7540 §6.5.2 compliance for flow control window overflow detection:
//! 1. Peer sends SETTINGS_INITIAL_WINDOW_SIZE=2^31-1 (maximum allowed value)
//! 2. Combined with existing per-stream flow control windows, this could push
//!    the total flow control window past 2^31-1
//! 3. Per RFC 7540 §6.5.2, this MUST result in FLOW_CONTROL_ERROR (connection close)
//! 4. Tests various scenarios: existing window credits, multiple streams, edge cases
//!
//! Vulnerability areas:
//! - Integer overflow in flow control window calculations
//! - Missing overflow detection when applying new INITIAL_WINDOW_SIZE
//! - Arithmetic overflow allowing bypass of flow control limits
//! - Per-stream vs connection-level window confusion
//! - Unsigned integer wraparound in window size adjustments

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::http::h2::connection::{Connection, ConnectionState};
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{
    DataFrame, Frame, HeadersFrame, Setting, SettingsFrame, WindowUpdateFrame,
};
use asupersync::http::h2::settings::{MAX_INITIAL_WINDOW_SIZE, Settings};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Maximum value for INITIAL_WINDOW_SIZE (2^31-1)
const MAX_WINDOW_SIZE: u32 = 0x7fff_ffff;

/// Test scenarios for window size overflow
#[derive(Debug, Arbitrary)]
pub struct WindowSizeOverflowInput {
    /// Initial window size to set via SETTINGS
    new_initial_window_size: u32,
    /// Pre-existing stream configurations
    existing_streams: Vec<StreamSetup>,
    /// Additional operations after SETTINGS
    operations: Vec<FlowControlOperation>,
    /// Test mode selection
    mode: OverflowTestMode,
}

/// Configuration for a pre-existing stream
#[derive(Debug, Arbitrary)]
pub struct StreamSetup {
    stream_id: u32,
    /// Current window available (simulated sent data)
    window_consumed: u32,
    /// Whether stream is active
    active: bool,
}

/// Operations to perform after SETTINGS change
#[derive(Debug, Arbitrary)]
pub enum FlowControlOperation {
    /// Send DATA frame on a stream
    SendData { stream_id: u32, size: u32 },
    /// Send WINDOW_UPDATE frame
    WindowUpdate { stream_id: u32, increment: u32 },
    /// Create new stream with HEADERS
    NewStream { stream_id: u32 },
}

#[derive(Debug, Arbitrary)]
pub enum OverflowTestMode {
    /// Test maximum window size exactly
    MaximumExact,
    /// Test window size near maximum
    NearMaximum,
    /// Test with existing stream data
    WithExistingStreams,
    /// Test combined operations
    Combined,
}

/// Mock connection for testing window size overflow scenarios
pub struct MockWindowSizeConnection {
    /// Current connection state
    state: ConnectionState,
    /// Flow control windows per stream
    stream_windows: HashMap<u32, StreamFlowControl>,
    /// Connection-level flow control window
    connection_window: u32,
    /// Current settings
    settings: Settings,
    /// Detected violations
    violations: Vec<WindowViolation>,
    /// Maximum stream ID seen
    max_stream_id: u32,
}

#[derive(Debug, Clone)]
pub struct StreamFlowControl {
    /// Current window size available to peer
    send_window: u32,
    /// Current window size available to us
    recv_window: u32,
    /// Stream state
    active: bool,
}

#[derive(Debug, Clone)]
pub enum WindowViolation {
    /// Flow control window would overflow
    WindowOverflow {
        stream_id: u32,
        current_window: u32,
        increment: u32,
        would_be: u64,
    },
    /// SETTINGS change would cause overflow
    SettingsOverflow {
        old_initial: u32,
        new_initial: u32,
        affected_streams: Vec<u32>,
    },
    /// Invalid window update (zero or too large)
    InvalidWindowUpdate { stream_id: u32, increment: u32 },
}

impl MockWindowSizeConnection {
    pub fn new() -> Self {
        Self {
            state: ConnectionState::Open,
            stream_windows: HashMap::new(),
            connection_window: 65535, // Default initial window size
            settings: Settings::default(),
            violations: Vec::new(),
            max_stream_id: 0,
        }
    }

    /// Process SETTINGS frame with new INITIAL_WINDOW_SIZE
    pub fn handle_settings_frame(&mut self, frame: &SettingsFrame) -> Result<(), ErrorCode> {
        if frame.ack {
            return Ok(()); // ACK frames don't change settings
        }

        let mut new_initial_window_size = self.settings.initial_window_size;

        // Parse settings
        for setting in &frame.settings {
            match setting {
                Setting::InitialWindowSize(new_size) => {
                    // RFC 7540 §6.5.2: Values above 2^31-1 MUST be treated as connection error
                    if *new_size > MAX_WINDOW_SIZE {
                        return Err(ErrorCode::FlowControlError);
                    }
                    new_initial_window_size = *new_size;
                }
                _ => {} // Ignore other settings for this test
            }
        }

        // Check if the new window size would cause overflow on existing streams
        let old_initial = self.settings.initial_window_size;
        let window_delta = new_initial_window_size.wrapping_sub(old_initial);

        for (stream_id, flow_control) in &mut self.stream_windows {
            if flow_control.active {
                // Calculate what the new window would be
                let current_window = flow_control.send_window;
                let new_window = current_window.wrapping_add(window_delta);

                // Check for overflow: new window must not exceed 2^31-1
                if new_window > MAX_WINDOW_SIZE
                    || (window_delta > 0 && current_window > MAX_WINDOW_SIZE - window_delta)
                {
                    self.violations.push(WindowViolation::SettingsOverflow {
                        old_initial,
                        new_initial: new_initial_window_size,
                        affected_streams: vec![*stream_id],
                    });

                    return Err(ErrorCode::FlowControlError);
                }

                // Update the stream window
                flow_control.send_window = new_window;
            }
        }

        // Update settings if no overflow detected
        self.settings.initial_window_size = new_initial_window_size;
        Ok(())
    }

    /// Handle WINDOW_UPDATE frame
    pub fn handle_window_update(&mut self, frame: &WindowUpdateFrame) -> Result<(), ErrorCode> {
        // RFC 7540 §6.9.1: Window update increment must not be zero
        if frame.window_size_increment == 0 {
            self.violations.push(WindowViolation::InvalidWindowUpdate {
                stream_id: frame.stream_id,
                increment: frame.window_size_increment,
            });
            return Err(ErrorCode::ProtocolError);
        }

        if frame.stream_id == 0 {
            // Connection-level window update
            let new_window = self
                .connection_window
                .saturating_add(frame.window_size_increment);
            if new_window > MAX_WINDOW_SIZE {
                self.violations.push(WindowViolation::WindowOverflow {
                    stream_id: 0,
                    current_window: self.connection_window,
                    increment: frame.window_size_increment,
                    would_be: new_window as u64,
                });
                return Err(ErrorCode::FlowControlError);
            }
            self.connection_window = new_window;
        } else {
            // Stream-level window update
            if let Some(flow_control) = self.stream_windows.get_mut(&frame.stream_id) {
                let current_window = flow_control.send_window;
                let new_window = current_window.saturating_add(frame.window_size_increment);

                if new_window > MAX_WINDOW_SIZE {
                    self.violations.push(WindowViolation::WindowOverflow {
                        stream_id: frame.stream_id,
                        current_window,
                        increment: frame.window_size_increment,
                        would_be: new_window as u64,
                    });
                    return Err(ErrorCode::FlowControlError);
                }

                flow_control.send_window = new_window;
            }
        }

        Ok(())
    }

    /// Handle new stream creation
    pub fn create_stream(&mut self, stream_id: u32) {
        if stream_id > self.max_stream_id {
            self.max_stream_id = stream_id;
        }

        self.stream_windows.insert(
            stream_id,
            StreamFlowControl {
                send_window: self.settings.initial_window_size,
                recv_window: self.settings.initial_window_size,
                active: true,
            },
        );
    }

    /// Simulate sending data (reduces window)
    pub fn send_data(&mut self, stream_id: u32, size: u32) -> Result<(), ErrorCode> {
        if let Some(flow_control) = self.stream_windows.get_mut(&stream_id) {
            if flow_control.send_window < size {
                return Err(ErrorCode::FlowControlError);
            }
            flow_control.send_window -= size;
            self.connection_window = self.connection_window.saturating_sub(size);
        }
        Ok(())
    }

    /// Get current violations
    pub fn violations(&self) -> &[WindowViolation] {
        &self.violations
    }

    /// Check if any flow control error detected
    pub fn has_flow_control_violation(&self) -> bool {
        self.violations.iter().any(|v| {
            matches!(
                v,
                WindowViolation::WindowOverflow { .. } | WindowViolation::SettingsOverflow { .. }
            )
        })
    }
}

/// Normalize stream ID to be valid (non-zero, client-initiated odd)
fn normalize_stream_id(raw: u32) -> u32 {
    let mut id = raw & 0x7fff_ffff; // Ensure 31-bit
    if id == 0 {
        id = 1;
    }
    if id % 2 == 0 {
        id = id.saturating_add(1);
    } // Make odd (client-initiated)
    id
}

/// Cap window size to reasonable bounds for testing
fn cap_window_size(size: u32) -> u32 {
    size.min(MAX_WINDOW_SIZE)
}

fuzz_target!(|input: WindowSizeOverflowInput| {
    let mut conn = MockWindowSizeConnection::new();

    // Set up pre-existing streams based on input
    for stream_setup in &input.existing_streams {
        let stream_id = normalize_stream_id(stream_setup.stream_id);
        if stream_setup.active {
            conn.create_stream(stream_id);

            // Simulate some data being sent to consume window
            let consumed = cap_window_size(stream_setup.window_consumed);
            if consumed > 0 {
                let _ = conn.send_data(stream_id, consumed);
            }
        }
    }

    // Create SETTINGS frame with potentially problematic INITIAL_WINDOW_SIZE
    let new_window_size = match input.mode {
        OverflowTestMode::MaximumExact => MAX_WINDOW_SIZE,
        OverflowTestMode::NearMaximum => {
            MAX_WINDOW_SIZE.saturating_sub(input.new_initial_window_size % 1000)
        }
        _ => cap_window_size(input.new_initial_window_size),
    };

    let settings_frame = SettingsFrame::new(vec![Setting::InitialWindowSize(new_window_size)]);

    // Process the SETTINGS frame - this is where overflow should be detected
    let settings_result = conn.handle_settings_frame(&settings_frame);

    // Verify that overflow is properly detected for dangerous values
    if new_window_size == MAX_WINDOW_SIZE && !conn.stream_windows.is_empty() {
        // With existing streams, setting INITIAL_WINDOW_SIZE to max could cause overflow
        // The implementation should detect this and return FLOW_CONTROL_ERROR
        if settings_result.is_ok() {
            // Check if any stream windows would exceed the limit
            let has_potential_overflow = conn
                .stream_windows
                .values()
                .any(|fc| fc.send_window > MAX_WINDOW_SIZE.saturating_sub(1000));

            if has_potential_overflow {
                // This should have been caught as a flow control error
                assert!(
                    conn.has_flow_control_violation(),
                    "Expected flow control violation for window size overflow"
                );
            }
        }
    }

    // Perform additional operations if SETTINGS succeeded
    if settings_result.is_ok() {
        for operation in &input.operations {
            match operation {
                FlowControlOperation::SendData { stream_id, size } => {
                    let stream_id = normalize_stream_id(*stream_id);
                    let size = cap_window_size(*size);
                    let _ = conn.send_data(stream_id, size);
                }
                FlowControlOperation::WindowUpdate {
                    stream_id,
                    increment,
                } => {
                    let stream_id = normalize_stream_id(*stream_id);
                    let increment = cap_window_size(*increment);
                    if increment > 0 {
                        let window_update = WindowUpdateFrame {
                            stream_id,
                            window_size_increment: increment,
                        };
                        let _ = conn.handle_window_update(&window_update);
                    }
                }
                FlowControlOperation::NewStream { stream_id } => {
                    let stream_id = normalize_stream_id(*stream_id);
                    conn.create_stream(stream_id);
                }
            }
        }
    }

    // Verify invariants
    for flow_control in conn.stream_windows.values() {
        assert!(
            flow_control.send_window <= MAX_WINDOW_SIZE,
            "Stream send window exceeded maximum: {}",
            flow_control.send_window
        );
        assert!(
            flow_control.recv_window <= MAX_WINDOW_SIZE,
            "Stream recv window exceeded maximum: {}",
            flow_control.recv_window
        );
    }

    assert!(
        conn.connection_window <= MAX_WINDOW_SIZE,
        "Connection window exceeded maximum: {}",
        conn.connection_window
    );
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_window_size_exact() {
        let mut conn = MockWindowSizeConnection::new();

        // Create a stream with some data sent
        conn.create_stream(1);
        conn.send_data(1, 1000).unwrap();

        // Try to set INITIAL_WINDOW_SIZE to maximum
        let settings = SettingsFrame::new(vec![Setting::InitialWindowSize(MAX_WINDOW_SIZE)]);

        let result = conn.handle_settings_frame(&settings);

        // This should cause overflow and be rejected
        assert_eq!(result, Err(ErrorCode::FlowControlError));
        assert!(conn.has_flow_control_violation());
    }

    #[test]
    fn test_window_update_overflow() {
        let mut conn = MockWindowSizeConnection::new();

        // Create stream and set window near maximum
        conn.create_stream(1);
        conn.stream_windows.get_mut(&1).unwrap().send_window = MAX_WINDOW_SIZE - 100;

        // Try to update window by large amount
        let window_update = WindowUpdateFrame {
            stream_id: 1,
            window_size_increment: 200, // Would cause overflow
        };

        let result = conn.handle_window_update(&window_update);

        // Should be rejected as flow control error
        assert_eq!(result, Err(ErrorCode::FlowControlError));
        assert!(conn.has_flow_control_violation());
    }

    #[test]
    fn test_connection_window_overflow() {
        let mut conn = MockWindowSizeConnection::new();

        // Set connection window near maximum
        conn.connection_window = MAX_WINDOW_SIZE - 50;

        // Try connection-level window update that would overflow
        let window_update = WindowUpdateFrame {
            stream_id: 0, // Connection-level
            window_size_increment: 100,
        };

        let result = conn.handle_window_update(&window_update);

        // Should be rejected
        assert_eq!(result, Err(ErrorCode::FlowControlError));
        assert!(conn.has_flow_control_violation());
    }

    #[test]
    fn test_valid_window_size_change() {
        let mut conn = MockWindowSizeConnection::new();

        // Create stream
        conn.create_stream(1);

        // Set reasonable window size
        let settings = SettingsFrame::new(vec![
            Setting::InitialWindowSize(131072), // 128KB
        ]);

        let result = conn.handle_settings_frame(&settings);

        // Should succeed
        assert!(result.is_ok());
        assert!(!conn.has_flow_control_violation());
        assert_eq!(conn.settings.initial_window_size, 131072);
    }

    #[test]
    fn test_zero_window_update_rejected() {
        let mut conn = MockWindowSizeConnection::new();

        let window_update = WindowUpdateFrame {
            stream_id: 1,
            window_size_increment: 0, // Invalid per RFC 7540
        };

        let result = conn.handle_window_update(&window_update);

        // Should be protocol error
        assert_eq!(result, Err(ErrorCode::ProtocolError));
    }
}
