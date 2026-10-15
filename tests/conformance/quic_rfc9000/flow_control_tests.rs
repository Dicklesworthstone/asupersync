#![allow(warnings)]
#![allow(clippy::all)]
//! QUIC flow control conformance tests.
//!
//! Tests RFC 9000 Section 4.1 stream flow control requirements:
//! STREAM_DATA_BLOCKED frames, MAX_STREAM_DATA enforcement, credit exhaustion.

use super::*;

/// Run all flow control conformance tests.
#[allow(dead_code)]
pub fn run_flow_control_tests() -> Vec<QuicConformanceResult> {
    let mut results = Vec::new();

    results.push(test_stream_data_blocked_generation());
    results.push(test_max_stream_data_enforcement());
    results.push(test_credit_exhaustion_errors());
    results.push(test_connection_level_flow_control());
    results.push(test_flow_control_recovery());

    results
}

/// RFC 9000 Section 4.1: STREAM_DATA_BLOCKED frame generation.
#[allow(dead_code)]
fn test_stream_data_blocked_generation() -> QuicConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut flow_controller = StreamFlowController::new(1000); // 1KB initial window

        // Fill the flow control window
        flow_controller.send_data(800)?; // 800 bytes sent
        flow_controller.send_data(200)?; // Now at limit (1000 bytes total)

        // Attempt to send more data - should trigger STREAM_DATA_BLOCKED
        let block_result = flow_controller.attempt_send_data(100);

        if !block_result.is_blocked() {
            return Err("Should be blocked when flow control window exhausted".to_string());
        }

        // Verify STREAM_DATA_BLOCKED frame is generated
        let blocked_frame = flow_controller.generate_stream_data_blocked_frame();
        if blocked_frame.is_none() {
            return Err("Should generate STREAM_DATA_BLOCKED frame when blocked".to_string());
        }

        let frame = blocked_frame.unwrap();
        if frame.maximum_stream_data != 1000 {
            return Err("STREAM_DATA_BLOCKED should report current limit".to_string());
        }

        // Receive MAX_STREAM_DATA to increase window
        flow_controller.update_max_stream_data(2000);

        // Should now be able to send more data
        let send_result = flow_controller.attempt_send_data(100);
        if send_result.is_blocked() {
            return Err("Should not be blocked after window increase".to_string());
        }

        Ok(())
    });

    create_test_result(
        "RFC9000-4.1-STREAM-DATA-BLOCKED",
        "STREAM_DATA_BLOCKED frame generation when flow control limits reached",
        TestCategory::FlowControl,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9000 Section 4.1: MAX_STREAM_DATA enforcement.
#[allow(dead_code)]
fn test_max_stream_data_enforcement() -> QuicConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut receiver = StreamReceiver::new();

        // Set initial maximum
        receiver.set_max_stream_data(1000);

        // Should accept data within limit
        if !receiver.can_receive_data(500, 400) {
            return Err("Should accept data within flow control limit".to_string());
        }

        // Should reject data exceeding limit
        if receiver.can_receive_data(800, 300) {
            return Err("Should reject data exceeding flow control limit".to_string());
        }

        // Test exact boundary
        if !receiver.can_receive_data(0, 1000) {
            return Err("Should accept data exactly at limit".to_string());
        }

        if receiver.can_receive_data(0, 1001) {
            return Err("Should reject data exceeding limit by 1 byte".to_string());
        }

        // Test MAX_STREAM_DATA frame processing
        receiver.process_max_stream_data_frame(2000)?;

        // Should now accept previously rejected data
        if !receiver.can_receive_data(1500, 400) {
            return Err("Should accept data within new increased limit".to_string());
        }

        Ok(())
    });

    create_test_result(
        "RFC9000-4.1-MAX-STREAM-DATA-ENFORCEMENT",
        "MAX_STREAM_DATA limit enforcement and updates",
        TestCategory::FlowControl,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9000 Section 4.1: Credit exhaustion error handling.
#[allow(dead_code)]
fn test_credit_exhaustion_errors() -> QuicConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut connection_flow = ConnectionFlowController::new(5000); // 5KB connection limit
        let mut stream_flow = StreamFlowController::new(1000); // 1KB stream limit

        // Test stream-level exhaustion
        stream_flow.send_data(1000)?; // Exhaust stream window

        let stream_block = stream_flow.attempt_send_data(1);
        if !stream_block.is_blocked() {
            return Err("Should be blocked at stream level".to_string());
        }

        // Test connection-level exhaustion
        connection_flow.send_data(5000)?; // Exhaust connection window

        let conn_block = connection_flow.attempt_send_data(1);
        if !conn_block.is_blocked() {
            return Err("Should be blocked at connection level".to_string());
        }

        // Test double blocking (both stream and connection)
        let double_block = check_combined_flow_control(&mut stream_flow, &mut connection_flow, 100);
        if double_block.blocking_level != FlowControlLevel::Both {
            return Err("Should be blocked at both levels when both exhausted".to_string());
        }

        // Test partial credit recovery
        stream_flow.update_max_stream_data(1100); // Add 100 bytes to stream
        // Connection still blocked

        let partial_recovery = check_combined_flow_control(&mut stream_flow, &mut connection_flow, 50);
        if partial_recovery.blocking_level != FlowControlLevel::Connection {
            return Err("Should still be blocked at connection level".to_string());
        }

        Ok(())
    });

    create_test_result(
        "RFC9000-4.1-CREDIT-EXHAUSTION",
        "Flow control credit exhaustion and error handling",
        TestCategory::FlowControl,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9000 Section 4.1: Connection-level flow control.
#[allow(dead_code)]
fn test_connection_level_flow_control() -> QuicConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut conn_controller = ConnectionFlowController::new(10000); // 10KB connection limit

        // Multiple streams sharing connection budget
        let stream_1_usage = 3000;
        let stream_2_usage = 4000;
        let stream_3_usage = 2500;

        conn_controller.send_data(stream_1_usage)?;
        conn_controller.send_data(stream_2_usage)?;

        // Should accept stream 3 data (total: 9500, under 10000 limit)
        if !conn_controller.can_send_data(stream_3_usage) {
            return Err("Should accept data within connection limit".to_string());
        }

        conn_controller.send_data(stream_3_usage)?; // Total: 9500

        // Should reject additional large send (would exceed limit)
        if conn_controller.can_send_data(600) {
            return Err("Should reject data exceeding connection limit".to_string());
        }

        // Should accept small send (total would be 10000)
        if !conn_controller.can_send_data(500) {
            return Err("Should accept data exactly reaching connection limit".to_string());
        }

        // Test MAX_DATA frame for connection-level updates
        conn_controller.process_max_data_frame(15000)?;

        // Should now accept previously rejected data
        if !conn_controller.can_send_data(4000) {
            return Err("Should accept data within new connection limit".to_string());
        }

        Ok(())
    });

    create_test_result(
        "RFC9000-4.1-CONNECTION-FLOW-CONTROL",
        "Connection-level flow control across multiple streams",
        TestCategory::FlowControl,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9000 Section 4.1: Flow control recovery after blocking.
#[allow(dead_code)]
fn test_flow_control_recovery() -> QuicConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let mut stream_controller = StreamFlowController::new(1000);

        // Exhaust flow control window
        stream_controller.send_data(1000)?;

        // Verify blocked state
        let blocked_result = stream_controller.attempt_send_data(1);
        if !blocked_result.is_blocked() {
            return Err("Should be blocked when window exhausted".to_string());
        }

        // Application consumes some data (simulated by peer)
        stream_controller.data_consumed_by_peer(300)?; // 300 bytes consumed

        // Should still be blocked (consumed data doesn't immediately increase send window)
        let still_blocked = stream_controller.attempt_send_data(1);
        if !still_blocked.is_blocked() {
            return Err("Should still be blocked until MAX_STREAM_DATA received".to_string());
        }

        // Receive MAX_STREAM_DATA update reflecting consumed data
        stream_controller.update_max_stream_data(1300)?; // Was 1000, now 1300

        // Should now be able to send again
        let unblocked_result = stream_controller.attempt_send_data(250);
        if unblocked_result.is_blocked() {
            return Err("Should be unblocked after receiving MAX_STREAM_DATA update".to_string());
        }

        // Test gradual recovery
        stream_controller.send_data(250)?; // Use new credit

        let final_attempt = stream_controller.attempt_send_data(100);
        if !final_attempt.is_blocked() {
            return Err("Should be blocked again after using new credit".to_string());
        }

        Ok(())
    });

    create_test_result(
        "RFC9000-4.1-FLOW-CONTROL-RECOVERY",
        "Flow control recovery after blocking and credit replenishment",
        TestCategory::FlowControl,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

// Helper types and functions

struct StreamFlowController {
    max_stream_data: u64,
    bytes_sent: u64,
    bytes_consumed_by_peer: u64,
}

struct ConnectionFlowController {
    max_data: u64,
    bytes_sent: u64,
}

struct StreamReceiver {
    max_stream_data: u64,
    bytes_received: u64,
}

#[derive(Debug)]
struct FlowControlResult {
    is_allowed: bool,
    blocking_level: FlowControlLevel,
}

#[derive(Debug, PartialEq)]
enum FlowControlLevel {
    None,
    Stream,
    Connection,
    Both,
}

struct StreamDataBlockedFrame {
    stream_id: u64,
    maximum_stream_data: u64,
}

impl StreamFlowController {
    fn new(initial_window: u64) -> Self {
        Self {
            max_stream_data: initial_window,
            bytes_sent: 0,
            bytes_consumed_by_peer: 0,
        }
    }

    fn send_data(&mut self, bytes: u64) -> Result<(), String> {
        if self.bytes_sent + bytes > self.max_stream_data {
            return Err("Would exceed flow control limit".to_string());
        }
        self.bytes_sent += bytes;
        Ok(())
    }

    fn attempt_send_data(&self, bytes: u64) -> FlowControlResult {
        let is_allowed = self.bytes_sent + bytes <= self.max_stream_data;
        FlowControlResult {
            is_allowed,
            blocking_level: if is_allowed { FlowControlLevel::None } else { FlowControlLevel::Stream },
        }
    }

    fn can_send_data(&self, bytes: u64) -> bool {
        self.bytes_sent + bytes <= self.max_stream_data
    }

    fn update_max_stream_data(&mut self, new_max: u64) {
        self.max_stream_data = new_max;
    }

    fn data_consumed_by_peer(&mut self, bytes: u64) -> Result<(), String> {
        self.bytes_consumed_by_peer += bytes;
        Ok(())
    }

    fn generate_stream_data_blocked_frame(&self) -> Option<StreamDataBlockedFrame> {
        if self.bytes_sent >= self.max_stream_data {
            Some(StreamDataBlockedFrame {
                stream_id: 0, // Would be actual stream ID
                maximum_stream_data: self.max_stream_data,
            })
        } else {
            None
        }
    }
}

impl FlowControlResult {
    fn is_blocked(&self) -> bool {
        !self.is_allowed
    }
}

impl ConnectionFlowController {
    fn new(initial_window: u64) -> Self {
        Self {
            max_data: initial_window,
            bytes_sent: 0,
        }
    }

    fn send_data(&mut self, bytes: u64) -> Result<(), String> {
        if self.bytes_sent + bytes > self.max_data {
            return Err("Would exceed connection flow control limit".to_string());
        }
        self.bytes_sent += bytes;
        Ok(())
    }

    fn can_send_data(&self, bytes: u64) -> bool {
        self.bytes_sent + bytes <= self.max_data
    }

    fn attempt_send_data(&self, bytes: u64) -> FlowControlResult {
        let is_allowed = self.bytes_sent + bytes <= self.max_data;
        FlowControlResult {
            is_allowed,
            blocking_level: if is_allowed { FlowControlLevel::None } else { FlowControlLevel::Connection },
        }
    }

    fn process_max_data_frame(&mut self, new_max: u64) -> Result<(), String> {
        if new_max < self.max_data {
            return Err("MAX_DATA cannot decrease".to_string());
        }
        self.max_data = new_max;
        Ok(())
    }
}

impl StreamReceiver {
    fn new() -> Self {
        Self {
            max_stream_data: 0,
            bytes_received: 0,
        }
    }

    fn set_max_stream_data(&mut self, max: u64) {
        self.max_stream_data = max;
    }

    fn can_receive_data(&self, offset: u64, length: u64) -> bool {
        offset + length <= self.max_stream_data
    }

    fn process_max_stream_data_frame(&mut self, new_max: u64) -> Result<(), String> {
        if new_max < self.max_stream_data {
            return Err("MAX_STREAM_DATA cannot decrease".to_string());
        }
        self.max_stream_data = new_max;
        Ok(())
    }
}

fn check_combined_flow_control(
    stream: &mut StreamFlowController,
    connection: &mut ConnectionFlowController,
    bytes: u64,
) -> FlowControlResult {
    let stream_ok = stream.can_send_data(bytes);
    let conn_ok = connection.can_send_data(bytes);

    let level = match (stream_ok, conn_ok) {
        (true, true) => FlowControlLevel::None,
        (false, true) => FlowControlLevel::Stream,
        (true, false) => FlowControlLevel::Connection,
        (false, false) => FlowControlLevel::Both,
    };

    FlowControlResult {
        is_allowed: stream_ok && conn_ok,
        blocking_level: level,
    }
}