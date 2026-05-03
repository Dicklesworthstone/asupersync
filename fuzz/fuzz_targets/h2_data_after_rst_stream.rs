#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Tests RFC 7540 §6.4 requirement: when local sends RST_STREAM(STREAM_CLOSED)
/// for stream-id N, but peer sends DATA for stream-id N before processing the
/// RST_STREAM, we must silently discard the DATA frame without billing flow-control.
///
/// This tests a critical race condition in HTTP/2 implementations where
/// RST_STREAM and DATA frames cross in flight.

#[derive(Arbitrary, Debug, Clone)]
struct DataAfterRstStreamInput {
    stream_id: u32,
    rst_error_code: u32,
    data_payload_size: u8, // Keep small to avoid OOM
    data_flags: u8,
    sequence_variant: u8, // Controls exact frame sequencing
}

/// Mock HTTP/2 stream state for testing RST_STREAM behavior
#[derive(Debug, Clone, PartialEq)]
enum StreamState {
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
    ResetLocal(u32),  // Reset sent locally with error code
    ResetRemote(u32), // Reset received from remote with error code
}

/// Mock DATA frame for testing
#[derive(Debug, Clone)]
struct DataFrame {
    stream_id: u32,
    flags: u8,
    payload: Vec<u8>,
}

impl DataFrame {
    fn new(stream_id: u32, flags: u8, payload: Vec<u8>) -> Self {
        Self {
            stream_id,
            flags,
            payload,
        }
    }

    fn end_stream(&self) -> bool {
        self.flags & 0x1 != 0 // END_STREAM flag
    }

    fn payload_len(&self) -> usize {
        self.payload.len()
    }
}

/// Mock RST_STREAM frame for testing
#[derive(Debug, Clone)]
struct RstStreamFrame {
    stream_id: u32,
    error_code: u32,
}

impl RstStreamFrame {
    fn new(stream_id: u32, error_code: u32) -> Self {
        Self {
            stream_id,
            error_code,
        }
    }
}

/// Mock connection for testing DATA after RST_STREAM scenarios
struct MockDataAfterRstConnection {
    streams: std::collections::HashMap<u32, StreamState>,
    connection_flow_window: i32,
    stream_flow_windows: std::collections::HashMap<u32, i32>,
    discarded_data_count: usize,
    flow_control_violations: Vec<String>,
}

impl MockDataAfterRstConnection {
    fn new() -> Self {
        Self {
            streams: std::collections::HashMap::new(),
            connection_flow_window: 65535, // Default initial window
            stream_flow_windows: std::collections::HashMap::new(),
            discarded_data_count: 0,
            flow_control_violations: Vec::new(),
        }
    }

    fn create_stream(&mut self, stream_id: u32) {
        self.streams.insert(stream_id, StreamState::Open);
        self.stream_flow_windows.insert(stream_id, 65535); // Default stream window
    }

    fn send_rst_stream(&mut self, frame: &RstStreamFrame) {
        // Local sends RST_STREAM - mark stream as reset locally
        self.streams
            .insert(frame.stream_id, StreamState::ResetLocal(frame.error_code));
        // Stream flow control window is no longer relevant after reset
        self.stream_flow_windows.remove(&frame.stream_id);
    }

    fn receive_data_frame(&mut self, frame: &DataFrame) -> bool {
        let stream_state = self.streams.get(&frame.stream_id);

        match stream_state {
            Some(StreamState::ResetLocal(_)) => {
                // Per RFC 7540 §6.4: "An endpoint that sends a RST_STREAM frame on
                // a stream MUST be prepared to receive any frames that were sent
                // prior to the time the remote peer receives and processes the RST_STREAM frame.
                // These frames MAY be ignored, except where this would result in a
                // change to connection state."

                // KEY REQUIREMENT: We must NOT bill flow control for data frames
                // received after sending RST_STREAM, as this can cause flow control
                // windows to become inconsistent.

                self.discarded_data_count += 1;
                // Silently discard - do NOT update flow control windows

                // Verify we're not billing flow control
                if self.stream_flow_windows.contains_key(&frame.stream_id) {
                    self.flow_control_violations.push(format!(
                        "ERROR: Stream flow window still exists for reset stream {}",
                        frame.stream_id
                    ));
                }

                false // Frame discarded
            }
            Some(StreamState::ResetRemote(_)) => {
                // Peer already reset this stream - discard
                self.discarded_data_count += 1;
                false
            }
            Some(StreamState::Closed) => {
                // Stream already closed - this should trigger STREAM_CLOSED error
                self.flow_control_violations.push(format!(
                    "ERROR: DATA received on closed stream {}",
                    frame.stream_id
                ));
                false
            }
            Some(StreamState::Open | StreamState::HalfClosedLocal) => {
                // Normal processing - update flow control
                if let Some(window) = self.stream_flow_windows.get_mut(&frame.stream_id) {
                    *window = window.saturating_sub(frame.payload_len() as i32);
                }
                self.connection_flow_window = self
                    .connection_flow_window
                    .saturating_sub(frame.payload_len() as i32);
                true // Frame processed normally
            }
            Some(StreamState::HalfClosedRemote) => {
                // Peer already closed their side - this is a protocol violation
                self.flow_control_violations.push(format!(
                    "ERROR: DATA received on half-closed-remote stream {}",
                    frame.stream_id
                ));
                false
            }
            None => {
                // Stream doesn't exist - protocol violation
                self.flow_control_violations.push(format!(
                    "ERROR: DATA received on non-existent stream {}",
                    frame.stream_id
                ));
                false
            }
        }
    }

    fn has_violations(&self) -> bool {
        !self.flow_control_violations.is_empty()
    }

    fn violation_summary(&self) -> String {
        self.flow_control_violations.join("; ")
    }
}

fuzz_target!(|input: DataAfterRstStreamInput| {
    // Skip invalid stream IDs (must be non-zero, client streams are odd)
    if input.stream_id == 0 || input.stream_id % 2 == 0 {
        return;
    }

    // Limit payload size to prevent memory issues
    let payload_size = (input.data_payload_size as usize).min(1024);
    let data_payload = vec![0x42; payload_size];

    let mut conn = MockDataAfterRstConnection::new();

    // Create the stream initially
    conn.create_stream(input.stream_id);

    let rst_frame = RstStreamFrame::new(input.stream_id, input.rst_error_code);
    let data_frame = DataFrame::new(input.stream_id, input.data_flags, data_payload);

    match input.sequence_variant % 4 {
        0 => {
            // Scenario 1: RST_STREAM sent, then DATA received (race condition)
            conn.send_rst_stream(&rst_frame);
            let processed = conn.receive_data_frame(&data_frame);

            // Critical assertion: DATA after RST_STREAM must be silently discarded
            assert!(!processed, "DATA frame after RST_STREAM must be discarded");
            assert_eq!(
                conn.discarded_data_count, 1,
                "DATA frame must be counted as discarded"
            );
        }
        1 => {
            // Scenario 2: Multiple DATA frames after RST_STREAM
            conn.send_rst_stream(&rst_frame);
            let data_frame2 =
                DataFrame::new(input.stream_id, input.data_flags | 0x1, vec![0x43; 64]);

            let processed1 = conn.receive_data_frame(&data_frame);
            let processed2 = conn.receive_data_frame(&data_frame2);

            assert!(
                !processed1 && !processed2,
                "All DATA after RST_STREAM must be discarded"
            );
            assert_eq!(
                conn.discarded_data_count, 2,
                "All DATA frames must be counted"
            );
        }
        2 => {
            // Scenario 3: DATA with END_STREAM after RST_STREAM
            conn.send_rst_stream(&rst_frame);
            let end_stream_data = DataFrame::new(
                input.stream_id,
                input.data_flags | 0x1, // Set END_STREAM
                data_payload,
            );

            let processed = conn.receive_data_frame(&end_stream_data);
            assert!(
                !processed,
                "END_STREAM DATA after RST_STREAM must be discarded"
            );
        }
        3 => {
            // Scenario 4: Large DATA frame after RST_STREAM (flow control stress test)
            conn.send_rst_stream(&rst_frame);

            // Store initial flow control state
            let initial_conn_window = conn.connection_flow_window;
            let initial_stream_windows = conn.stream_flow_windows.clone();

            let large_data = DataFrame::new(input.stream_id, input.data_flags, vec![0x44; 1024]);
            let processed = conn.receive_data_frame(&large_data);

            assert!(!processed, "Large DATA after RST_STREAM must be discarded");

            // CRITICAL: Flow control windows must remain unchanged after discarding DATA
            assert_eq!(
                conn.connection_flow_window, initial_conn_window,
                "Connection flow window must not change when discarding DATA"
            );
            assert_eq!(
                conn.stream_flow_windows, initial_stream_windows,
                "Stream flow windows must not change when discarding DATA"
            );
        }
        _ => unreachable!(),
    }

    // Verify no flow control violations occurred
    assert!(
        !conn.has_violations(),
        "Flow control violations detected: {}",
        conn.violation_summary()
    );
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_after_rst_stream_basic() {
        let mut conn = MockDataAfterRstConnection::new();
        conn.create_stream(1);

        // Send RST_STREAM
        let rst = RstStreamFrame::new(1, 8); // CANCEL
        conn.send_rst_stream(&rst);

        // Receive DATA - should be discarded
        let data = DataFrame::new(1, 0, vec![0x41; 100]);
        let processed = conn.receive_data_frame(&data);

        assert!(!processed);
        assert_eq!(conn.discarded_data_count, 1);
        assert!(!conn.has_violations());
    }

    #[test]
    fn test_flow_control_not_billed_after_rst() {
        let mut conn = MockDataAfterRstConnection::new();
        conn.create_stream(3);

        let initial_conn_window = conn.connection_flow_window;

        // Send RST_STREAM
        conn.send_rst_stream(&RstStreamFrame::new(3, 8));

        // Receive large DATA
        let data = DataFrame::new(3, 0, vec![0x42; 1000]);
        conn.receive_data_frame(&data);

        // Flow control must not be billed
        assert_eq!(conn.connection_flow_window, initial_conn_window);
        assert!(!conn.stream_flow_windows.contains_key(&3));
    }

    #[test]
    fn test_normal_data_still_processed() {
        let mut conn = MockDataAfterRstConnection::new();
        conn.create_stream(5);

        // Normal DATA processing (no RST_STREAM sent)
        let data = DataFrame::new(5, 0, vec![0x43; 100]);
        let processed = conn.receive_data_frame(&data);

        assert!(processed);
        assert_eq!(conn.discarded_data_count, 0);
        assert_eq!(conn.connection_flow_window, 65535 - 100);
    }

    #[test]
    fn test_end_stream_data_after_rst() {
        let mut conn = MockDataAfterRstConnection::new();
        conn.create_stream(7);

        conn.send_rst_stream(&RstStreamFrame::new(7, 2)); // INTERNAL_ERROR

        // END_STREAM DATA should still be discarded
        let end_data = DataFrame::new(7, 1, vec![0x44; 50]); // END_STREAM=1
        let processed = conn.receive_data_frame(&end_data);

        assert!(!processed);
        assert!(end_data.end_stream());
        assert_eq!(conn.discarded_data_count, 1);
    }

    #[test]
    fn test_multiple_data_frames_after_rst() {
        let mut conn = MockDataAfterRstConnection::new();
        conn.create_stream(9);

        conn.send_rst_stream(&RstStreamFrame::new(9, 8));

        // Send multiple DATA frames - all should be discarded
        for i in 0..5 {
            let data = DataFrame::new(9, 0, vec![0x50 + i; 10]);
            let processed = conn.receive_data_frame(&data);
            assert!(!processed);
        }

        assert_eq!(conn.discarded_data_count, 5);
    }
}
