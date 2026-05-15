#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::http::h2::{ErrorCode, H2Error, Setting, Settings};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

const MAX_INITIAL_WINDOW_SIZE: u32 = 0x7fff_ffff;

/// HTTP/2 flow control state machine zero window handling testing.
/// Per RFC 7540 §6.9, when INITIAL_WINDOW_SIZE changes, existing streams
/// are adjusted. Setting to 0 should pause sending on affected streams.
/// Tests state machine behavior when window transitions from positive to zero.
///
/// Tests:
/// - Initial SETTINGS_INITIAL_WINDOW_SIZE=65535 (default)
/// - Stream sends initial DATA consuming window
/// - SETTINGS_INITIAL_WINDOW_SIZE=0 (zero window)
/// - Verify state machine pauses sending on affected streams
/// - Window size tracking and adjustment on SETTINGS change
/// - Multiple streams with different window states
/// - WINDOW_UPDATE frame resuming flow

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Flow control scenario to test
    scenario: FlowControlScenario,
}

#[derive(Arbitrary, Debug, Clone)]
struct FlowControlScenario {
    /// Initial window size setting
    initial_window_size: u32,
    /// Stream operations sequence
    stream_operations: Vec<StreamOperation>,
    /// Window size update (typically to 0)
    window_size_update: u32,
    /// Optional WINDOW_UPDATE frames after zero setting
    window_updates: Vec<WindowUpdateFrame>,
}

#[derive(Arbitrary, Debug, Clone)]
enum StreamOperation {
    /// Send DATA frame on stream
    SendData(SendDataOperation),
    /// Receive WINDOW_UPDATE for stream
    ReceiveWindowUpdate(WindowUpdateFrame),
}

#[derive(Arbitrary, Debug, Clone)]
struct SendDataOperation {
    /// Stream ID
    stream_id: u32,
    /// Data size to send
    data_size: u32,
    /// End stream flag
    end_stream: bool,
}

#[derive(Arbitrary, Debug, Clone)]
struct WindowUpdateFrame {
    /// Stream ID (0 = connection-level)
    stream_id: u32,
    /// Window size increment
    increment: u32,
}

/// Flow control window state
#[derive(Debug, Clone)]
struct FlowWindow {
    /// Current window size
    size: i64,
    /// Initial window size (from SETTINGS)
    initial_size: u32,
    /// Whether sending is paused (window <= 0)
    paused: bool,
}

impl FlowWindow {
    fn new(initial_size: u32) -> Self {
        Self {
            size: initial_size as i64,
            initial_size,
            paused: false,
        }
    }

    fn consume(&mut self, amount: u32) -> Result<(), String> {
        if self.paused {
            return Err("Cannot send data: stream is flow control paused".into());
        }

        if amount as i64 > self.size {
            return Err(format!(
                "Cannot send {} bytes: only {} window available",
                amount, self.size
            ));
        }

        self.size -= amount as i64;

        if self.size <= 0 {
            self.paused = true;
        }

        Ok(())
    }

    fn add_window(&mut self, amount: u32) {
        self.size += amount as i64;

        if self.size > 0 {
            self.paused = false;
        }
    }

    fn adjust_for_settings_change(&mut self, old_initial: u32, new_initial: u32) {
        // Per RFC 7540 §6.9.2: adjust existing windows by the difference
        let adjustment = new_initial as i64 - old_initial as i64;
        self.size += adjustment;
        self.initial_size = new_initial;

        // Update paused state based on new window size
        self.paused = self.size <= 0;
    }

    fn is_paused(&self) -> bool {
        self.paused
    }

    fn current_size(&self) -> i64 {
        self.size
    }
}

/// Mock HTTP/2 flow control state machine
struct MockH2FlowController {
    /// Connection-level window
    connection_window: FlowWindow,
    /// Per-stream windows
    stream_windows: HashMap<u32, FlowWindow>,
    /// Current initial window size setting
    initial_window_size: u32,
}

impl MockH2FlowController {
    fn new(initial_window_size: u32) -> Self {
        Self {
            connection_window: FlowWindow::new(initial_window_size),
            stream_windows: HashMap::new(),
            initial_window_size,
        }
    }

    /// Process SETTINGS frame changing INITIAL_WINDOW_SIZE
    fn process_settings_initial_window_size(&mut self, new_size: u32) -> Result<(), String> {
        let old_size = self.initial_window_size;

        // Validate new window size (max 2^31 - 1)
        if new_size > MAX_INITIAL_WINDOW_SIZE {
            return Err("FLOW_CONTROL_ERROR: INITIAL_WINDOW_SIZE exceeds maximum".into());
        }

        // Update all existing stream windows per RFC 7540 §6.9.2
        for window in self.stream_windows.values_mut() {
            window.adjust_for_settings_change(old_size, new_size);
        }

        self.initial_window_size = new_size;

        Ok(())
    }

    /// Send DATA frame on stream
    fn send_data(
        &mut self,
        stream_id: u32,
        data_size: u32,
        _end_stream: bool,
    ) -> Result<(), String> {
        if stream_id == 0 {
            return Err("PROTOCOL_ERROR: DATA frame stream ID must not be 0".into());
        }

        let initial_window_size = self.initial_window_size;
        let stream_window = self
            .stream_windows
            .entry(stream_id)
            .or_insert_with(|| FlowWindow::new(initial_window_size));
        if stream_window.is_paused() {
            return Err(format!("Stream {} is flow control paused", stream_id));
        }

        // Check connection-level window
        if self.connection_window.is_paused() {
            return Err("Connection is flow control paused".into());
        }

        // Consume from both stream and connection windows
        stream_window.consume(data_size)?;
        self.connection_window.consume(data_size)?;

        Ok(())
    }

    /// Process WINDOW_UPDATE frame
    fn process_window_update(&mut self, stream_id: u32, increment: u32) -> Result<(), String> {
        if increment == 0 {
            return Err("PROTOCOL_ERROR: WINDOW_UPDATE increment must not be zero".into());
        }

        if stream_id == 0 {
            // Connection-level WINDOW_UPDATE
            self.connection_window.add_window(increment);
        } else {
            // Stream-level WINDOW_UPDATE
            let initial_window_size = self.initial_window_size;
            self.stream_windows
                .entry(stream_id)
                .or_insert_with(|| FlowWindow::new(initial_window_size))
                .add_window(increment);
        }

        Ok(())
    }

    /// Check if stream can send data
    fn can_send_data(&self, stream_id: u32, data_size: u32) -> bool {
        if self.connection_window.is_paused() {
            return false;
        }

        if let Some(stream_window) = self.stream_windows.get(&stream_id) {
            !stream_window.is_paused()
                && stream_window.current_size() >= data_size as i64
                && self.connection_window.current_size() >= data_size as i64
        } else {
            // New stream would use initial window size
            self.initial_window_size >= data_size
                && self.connection_window.current_size() >= data_size as i64
        }
    }

    /// Get stream window state
    fn get_stream_window_state(&self, stream_id: u32) -> Option<(i64, bool)> {
        self.stream_windows
            .get(&stream_id)
            .map(|w| (w.current_size(), w.is_paused()))
    }

    /// Get connection window state
    fn get_connection_window_state(&self) -> (i64, bool) {
        (
            self.connection_window.current_size(),
            self.connection_window.is_paused(),
        )
    }

    /// Get current initial window size setting
    fn get_initial_window_size(&self) -> u32 {
        self.initial_window_size
    }

    /// Count paused streams
    fn count_paused_streams(&self) -> usize {
        self.stream_windows
            .values()
            .filter(|w| w.is_paused())
            .count()
    }
}

fn assert_live_initial_window_size(value: u32) {
    let mut live_settings = Settings::default();
    let result = live_settings.apply(Setting::InitialWindowSize(value));

    if value <= MAX_INITIAL_WINDOW_SIZE {
        assert!(
            result.is_ok(),
            "live INITIAL_WINDOW_SIZE should accept {value}: {result:?}"
        );
        assert_eq!(
            live_settings.initial_window_size, value,
            "live settings should apply INITIAL_WINDOW_SIZE"
        );
    } else {
        let err = result.expect_err("live INITIAL_WINDOW_SIZE should reject overflow values");
        assert_live_initial_window_overflow(err);
    }
}

fn assert_live_initial_window_overflow(err: H2Error) {
    assert_eq!(
        err.code,
        ErrorCode::FlowControlError,
        "INITIAL_WINDOW_SIZE overflow should be FLOW_CONTROL_ERROR"
    );
    assert!(
        err.is_connection_error(),
        "INITIAL_WINDOW_SIZE overflow should be connection-scoped: {err:?}"
    );
    assert_eq!(
        err.stream_id, None,
        "INITIAL_WINDOW_SIZE overflow should not attach a stream id"
    );
    assert_eq!(
        err.message, "initial window size exceeds maximum (2^31-1)",
        "INITIAL_WINDOW_SIZE overflow should keep the exact live diagnostic"
    );
    assert_eq!(
        err.to_string(),
        "HTTP/2 connection error (FLOW_CONTROL_ERROR): initial window size exceeds maximum (2^31-1)",
        "INITIAL_WINDOW_SIZE overflow should keep stable Display output"
    );
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let input: FuzzInput = match u.arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Skip invalid inputs
    };

    // Limit operation count to prevent timeouts
    if input.scenario.stream_operations.len() > 20 {
        return;
    }

    // Bound initial state to a valid connection configuration, then feed the raw
    // update value through both the mock and live SETTINGS validation paths.
    let initial_window_size = input
        .scenario
        .initial_window_size
        .min(MAX_INITIAL_WINDOW_SIZE);
    let window_update = input.scenario.window_size_update;

    let mut controller = MockH2FlowController::new(initial_window_size);

    // Test 1: Process initial stream operations
    for operation in &input.scenario.stream_operations {
        match operation {
            StreamOperation::SendData(send_op) => {
                if send_op.stream_id > 0
                    && send_op.stream_id <= 1_000_000
                    && send_op.data_size <= 100_000
                {
                    let result = controller.send_data(
                        send_op.stream_id,
                        send_op.data_size,
                        send_op.end_stream,
                    );

                    // Check if send should succeed based on current window state
                    let should_succeed =
                        controller.can_send_data(send_op.stream_id, send_op.data_size);

                    if should_succeed {
                        assert!(
                            result.is_ok(),
                            "Send should succeed when window available: stream={}, size={}, result={:?}",
                            send_op.stream_id,
                            send_op.data_size,
                            result
                        );
                    }
                }
            }
            StreamOperation::ReceiveWindowUpdate(window_update) => {
                if window_update.stream_id <= 1_000_000
                    && window_update.increment > 0
                    && window_update.increment <= 100_000
                {
                    let result = controller
                        .process_window_update(window_update.stream_id, window_update.increment);
                    assert!(result.is_ok(), "Valid WINDOW_UPDATE should succeed");
                }
            }
        }
    }

    // Test 2: Change INITIAL_WINDOW_SIZE (typically to 0)
    assert_live_initial_window_size(window_update);
    let settings_result = controller.process_settings_initial_window_size(window_update);

    if window_update <= MAX_INITIAL_WINDOW_SIZE {
        assert!(
            settings_result.is_ok(),
            "Valid INITIAL_WINDOW_SIZE change should succeed"
        );

        // Test 3: Verify window size was updated
        assert_eq!(
            controller.get_initial_window_size(),
            window_update,
            "Initial window size should be updated"
        );

        // Test 4: Check stream pausing behavior when window_update = 0
        if window_update == 0 {
            // Streams that had consumed their window should now be paused
            // (This depends on the specific operations, but we can check consistency)
            for stream_id in controller.stream_windows.keys() {
                if let Some((window_size, is_paused)) =
                    controller.get_stream_window_state(*stream_id)
                    && window_size <= 0
                {
                    assert!(
                        is_paused,
                        "Stream {} with window size {} should be paused",
                        stream_id, window_size
                    );
                }
            }

            // Test 5: Verify new sends are blocked when window is 0
            if controller.get_initial_window_size() == 0 {
                let blocked_result = controller.send_data(999, 1, false);
                assert!(
                    blocked_result.is_err(),
                    "Should not be able to send data when INITIAL_WINDOW_SIZE is 0"
                );
            }
        }
    } else {
        assert!(
            settings_result.is_err(),
            "Excessive INITIAL_WINDOW_SIZE should be rejected"
        );
    }

    // Test 6: Process WINDOW_UPDATE frames after settings change
    for window_update in &input.scenario.window_updates {
        if window_update.stream_id <= 1_000_000
            && window_update.increment > 0
            && window_update.increment <= 100_000
        {
            let before_paused = controller.count_paused_streams();

            let result =
                controller.process_window_update(window_update.stream_id, window_update.increment);
            assert!(result.is_ok(), "Valid WINDOW_UPDATE should succeed");

            // Check if WINDOW_UPDATE resumed paused streams
            let after_paused = controller.count_paused_streams();
            assert!(
                after_paused <= before_paused,
                "WINDOW_UPDATE should not increase paused streams"
            );

            if window_update.stream_id > 0
                && let Some((window_size, is_paused)) =
                    controller.get_stream_window_state(window_update.stream_id)
                && window_size > 0
            {
                assert!(
                    !is_paused,
                    "Stream {} with positive window {} should not be paused",
                    window_update.stream_id, window_size
                );
            }
        }
    }

    // Test 7: Connection vs stream window interaction
    let (conn_size, conn_paused) = controller.get_connection_window_state();

    if conn_paused {
        assert!(
            conn_size <= 0,
            "paused connection window should be non-positive"
        );

        // If connection is paused, no stream should be able to send
        for stream_id in 1..=5 {
            let can_send = controller.can_send_data(stream_id, 1);
            assert!(
                !can_send,
                "No stream should send when connection window is paused"
            );
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_window_size_zero() {
        let mut controller = MockH2FlowController::new(65535);

        // Send some data first
        assert!(controller.send_data(1, 1000, false).is_ok());

        // Change to zero window size
        let result = controller.process_settings_initial_window_size(0);
        assert!(result.is_ok());

        assert_eq!(controller.get_initial_window_size(), 0);

        // Stream should now be paused (window went from 64535 to -1000)
        let (window_size, is_paused) = controller.get_stream_window_state(1).unwrap();
        assert!(window_size <= 0);
        assert!(is_paused);

        // New sends should fail
        let send_result = controller.send_data(2, 1, false);
        assert!(send_result.is_err());
    }

    #[test]
    fn test_window_update_resume() {
        let mut controller = MockH2FlowController::new(1000);

        // Consume all window
        assert!(controller.send_data(1, 1000, false).is_ok());

        // Stream should be paused
        let (_, is_paused) = controller.get_stream_window_state(1).unwrap();
        assert!(is_paused);

        // WINDOW_UPDATE should resume
        assert!(controller.process_window_update(1, 500).is_ok());

        let (window_size, is_paused) = controller.get_stream_window_state(1).unwrap();
        assert_eq!(window_size, 500);
        assert!(!is_paused);

        // Should be able to send again
        assert!(controller.send_data(1, 100, false).is_ok());
    }

    #[test]
    fn test_connection_window_pause() {
        let mut controller = MockH2FlowController::new(1000);

        // Consume connection window on multiple streams
        assert!(controller.send_data(1, 500, false).is_ok());
        assert!(controller.send_data(2, 500, false).is_ok());

        // Connection window should be paused
        let (conn_size, conn_paused) = controller.get_connection_window_state();
        assert_eq!(conn_size, 0);
        assert!(conn_paused);

        // No stream should be able to send
        assert!(!controller.can_send_data(1, 1));
        assert!(!controller.can_send_data(3, 1));
    }

    #[test]
    fn test_settings_adjustment() {
        let mut controller = MockH2FlowController::new(1000);

        // Send some data
        assert!(controller.send_data(1, 300, false).is_ok());

        // Increase window size
        assert!(
            controller
                .process_settings_initial_window_size(2000)
                .is_ok()
        );

        // Window should be adjusted: 700 + (2000 - 1000) = 1700
        let (window_size, is_paused) = controller.get_stream_window_state(1).unwrap();
        assert_eq!(window_size, 1700);
        assert!(!is_paused);

        // Decrease window size significantly
        assert!(controller.process_settings_initial_window_size(200).is_ok());

        // Window should be adjusted: 1700 + (200 - 2000) = -100
        let (window_size, is_paused) = controller.get_stream_window_state(1).unwrap();
        assert_eq!(window_size, -100);
        assert!(is_paused);
    }

    #[test]
    fn test_excessive_window_size() {
        let mut controller = MockH2FlowController::new(1000);

        let result = controller.process_settings_initial_window_size(3_000_000_000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("FLOW_CONTROL_ERROR"));
    }

    #[test]
    fn test_zero_window_update() {
        let mut controller = MockH2FlowController::new(1000);

        let result = controller.process_window_update(1, 0);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("WINDOW_UPDATE increment must not be zero")
        );
    }

    #[test]
    fn test_can_send_logic() {
        let mut controller = MockH2FlowController::new(1000);

        // Initially can send
        assert!(controller.can_send_data(1, 500));

        // Send some data
        assert!(controller.send_data(1, 800, false).is_ok());

        // Can send small amount
        assert!(controller.can_send_data(1, 200));

        // Cannot send large amount
        assert!(!controller.can_send_data(1, 300));
    }

    #[test]
    fn test_multiple_streams_independent() {
        let mut controller = MockH2FlowController::new(1000);

        // Stream 1 consumes its window
        assert!(controller.send_data(1, 1000, false).is_ok());

        // Stream 1 should be paused
        let (_, is_paused) = controller.get_stream_window_state(1).unwrap();
        assert!(is_paused);

        // Stream 2 should still be able to send (if connection window allows)
        // But connection window is also consumed, so this would fail
        assert!(!controller.can_send_data(2, 1));

        // Add connection window
        assert!(controller.process_window_update(0, 2000).is_ok());

        // Now stream 2 can send
        assert!(controller.can_send_data(2, 500));
        assert!(controller.send_data(2, 500, false).is_ok());
    }

    #[test]
    fn test_invalid_stream_id() {
        let mut controller = MockH2FlowController::new(1000);

        let result = controller.send_data(0, 100, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("stream ID must not be 0"));
    }
}
