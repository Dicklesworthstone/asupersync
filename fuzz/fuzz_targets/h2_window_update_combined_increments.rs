#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::{
    bytes::{Bytes, BytesMut},
    http::h2::{
        Connection, ErrorCode, Frame, Header as H2Header, HpackEncoder, Settings,
        frame::{HeadersFrame, SettingsFrame, WindowUpdateFrame as LiveWindowUpdateFrame},
    },
};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// HTTP/2 WINDOW_UPDATE frame overflow testing.
/// Per RFC 7540 §6.9.1, flow control window is 31-bit value.
/// If sum of WINDOW_UPDATE increments would exceed 2^31-1,
/// must return FLOW_CONTROL_ERROR.
///
/// Tests:
/// - Rapid sequence of WINDOW_UPDATE frames
/// - Connection-level (stream_id=0) and stream-level updates
/// - Accumulated window size tracking
/// - Overflow detection at 2^31-1 boundary
/// - Multiple streams with overlapping window updates
/// - Edge cases: exactly at limit vs exceeding

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Sequence of WINDOW_UPDATE frames
    updates: Vec<WindowUpdateFrame>,
    /// Initial window size for all streams
    initial_window_size: u32,
}

#[derive(Arbitrary, Debug, Clone)]
struct WindowUpdateFrame {
    /// Stream ID (0 = connection-level, >0 = stream-level)
    stream_id: u32,
    /// Window size increment (must be 1-2^31-1)
    increment: u32,
    /// Frame flags (must be 0 for WINDOW_UPDATE)
    flags: u8,
}

/// Flow control window state tracker
#[derive(Debug)]
struct FlowControlWindow {
    /// Current window size
    size: i64, // Use i64 to detect overflow
    /// Maximum allowed window size (2^31 - 1)
    max_size: i64,
}

impl FlowControlWindow {
    fn new(initial_size: u32) -> Self {
        Self {
            size: initial_size as i64,
            max_size: 2_147_483_647, // 2^31 - 1
        }
    }

    /// Apply window update increment
    fn update(&mut self, increment: u32) -> Result<(), String> {
        if increment == 0 {
            return Err("WINDOW_UPDATE increment must not be zero".into());
        }

        let new_size = self.size + increment as i64;

        if new_size > self.max_size {
            return Err("FLOW_CONTROL_ERROR: window size exceeds maximum".into());
        }

        self.size = new_size;
        Ok(())
    }

    fn current_size(&self) -> i64 {
        self.size
    }
}

/// Mock HTTP/2 flow control state manager
struct MockH2FlowController {
    /// Connection-level window (stream_id = 0)
    connection_window: FlowControlWindow,
    /// Per-stream windows
    stream_windows: HashMap<u32, FlowControlWindow>,
    /// Error log
    errors: Vec<String>,
}

impl MockH2FlowController {
    fn new(initial_window_size: u32) -> Self {
        Self {
            connection_window: FlowControlWindow::new(initial_window_size),
            stream_windows: HashMap::new(),
            errors: Vec::new(),
        }
    }

    /// Process WINDOW_UPDATE frame
    fn process_window_update(&mut self, frame: &WindowUpdateFrame) -> Result<(), String> {
        // Validate frame structure
        if frame.flags != 0 {
            return Err("WINDOW_UPDATE frame flags must be 0".into());
        }

        if frame.increment == 0 {
            return Err("WINDOW_UPDATE increment must not be zero".into());
        }

        if frame.increment > 2_147_483_647 {
            return Err("WINDOW_UPDATE increment exceeds maximum (2^31-1)".into());
        }

        // Apply update based on stream ID
        if frame.stream_id == 0 {
            // Connection-level window update
            self.connection_window
                .update(frame.increment)
                .map_err(|e| format!("Connection window: {}", e))
        } else {
            // Stream-level window update
            let window = self
                .stream_windows
                .entry(frame.stream_id)
                .or_insert_with(|| FlowControlWindow::new(65535)); // Default initial window

            window
                .update(frame.increment)
                .map_err(|e| format!("Stream {} window: {}", frame.stream_id, e))
        }
    }

    /// Process sequence of WINDOW_UPDATE frames
    fn process_update_sequence(
        &mut self,
        updates: &[WindowUpdateFrame],
    ) -> Vec<Result<(), String>> {
        updates
            .iter()
            .map(|frame| {
                let result = self.process_window_update(frame);
                if let Err(ref e) = result {
                    self.errors.push(e.clone());
                }
                result
            })
            .collect()
    }

    /// Get current window sizes for verification
    fn get_window_sizes(&self) -> (i64, Vec<(u32, i64)>) {
        let connection_size = self.connection_window.current_size();
        let stream_sizes: Vec<_> = self
            .stream_windows
            .iter()
            .map(|(&id, window)| (id, window.current_size()))
            .collect();
        (connection_size, stream_sizes)
    }
}

fuzz_target!(|data: &[u8]| {
    assert_live_combined_window_updates();

    let mut u = Unstructured::new(data);
    let input: FuzzInput = match u.arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Skip invalid inputs
    };

    // Limit sequence length to prevent timeouts
    if input.updates.len() > 100 {
        return;
    }

    // Bound initial window size to reasonable range
    let initial_size = input.initial_window_size.min(2_000_000_000);

    let mut controller = MockH2FlowController::new(initial_size);
    let results = controller.process_update_sequence(&input.updates);

    // Test 1: Verify overflow detection
    let mut total_connection_increment: u64 = 0;
    let mut stream_increments: HashMap<u32, u64> = HashMap::new();

    for (i, frame) in input.updates.iter().enumerate() {
        if frame.increment == 0 || frame.increment > 2_147_483_647 {
            // Invalid frame should be rejected
            assert!(
                results[i].is_err(),
                "Invalid WINDOW_UPDATE should be rejected: increment={}",
                frame.increment
            );
            continue;
        }

        if frame.flags != 0 {
            // Invalid flags should be rejected
            assert!(
                results[i].is_err(),
                "WINDOW_UPDATE with non-zero flags should be rejected"
            );
            continue;
        }

        // Track increments for overflow calculation
        if frame.stream_id == 0 {
            total_connection_increment += frame.increment as u64;
        } else {
            *stream_increments.entry(frame.stream_id).or_insert(0) += frame.increment as u64;
        }

        // Check if this update would cause overflow
        if frame.stream_id == 0 {
            let would_overflow = (initial_size as u64 + total_connection_increment) > 2_147_483_647;
            if would_overflow {
                assert!(
                    results[i].is_err(),
                    "Connection window overflow should be detected at frame {}",
                    i
                );
            }
        } else {
            let stream_total = stream_increments.get(&frame.stream_id).unwrap_or(&0);
            let would_overflow = (65535u64 + stream_total) > 2_147_483_647; // Default initial + increments
            if would_overflow {
                assert!(
                    results[i].is_err(),
                    "Stream {} window overflow should be detected at frame {}",
                    frame.stream_id,
                    i
                );
            }
        }
    }

    // Test 2: Verify window size tracking accuracy
    let (conn_size, stream_sizes) = controller.get_window_sizes();

    // Connection window should not exceed maximum
    assert!(
        conn_size <= 2_147_483_647,
        "Connection window size {} exceeds maximum",
        conn_size
    );

    // Stream windows should not exceed maximum
    for (stream_id, size) in stream_sizes {
        assert!(
            size <= 2_147_483_647,
            "Stream {} window size {} exceeds maximum",
            stream_id,
            size
        );
    }

    // Test 3: Verify error messages contain FLOW_CONTROL_ERROR for overflow
    for error in &controller.errors {
        if error.contains("exceeds maximum") {
            assert!(
                error.contains("FLOW_CONTROL_ERROR"),
                "Overflow error should mention FLOW_CONTROL_ERROR: {}",
                error
            );
        }
    }
});

const DEFAULT_WINDOW_SIZE: u32 = 65_535;
const MAX_FLOW_CONTROL_WINDOW: u32 = i32::MAX as u32;

fn open_live_connection() -> Connection {
    let mut connection = Connection::server(Settings::default());
    connection
        .process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
        .expect("initial SETTINGS should open live H2 connection");
    while connection.next_frame().is_some() {}
    connection
}

fn encode_live_headers(headers: &[H2Header]) -> Bytes {
    let mut encoder = HpackEncoder::new();
    let mut block = BytesMut::new();
    encoder.encode(headers, &mut block);
    block.freeze()
}

fn assert_live_combined_window_updates() {
    let exact_delta_to_max = MAX_FLOW_CONTROL_WINDOW - DEFAULT_WINDOW_SIZE;

    let mut connection = open_live_connection();
    connection
        .process_frame(Frame::WindowUpdate(LiveWindowUpdateFrame::new(
            0,
            exact_delta_to_max,
        )))
        .expect("connection WINDOW_UPDATE sequence should reach the exact maximum");
    assert_eq!(connection.send_window(), i32::MAX);

    let err = connection
        .process_frame(Frame::WindowUpdate(LiveWindowUpdateFrame::new(0, 1)))
        .expect_err("connection WINDOW_UPDATE above the maximum should fail");
    assert_eq!(err.code, ErrorCode::FlowControlError);
    assert_eq!(err.stream_id, None);
    assert_eq!(err.message.as_str(), "connection window overflow");

    let mut stream_connection = open_live_connection();
    stream_connection
        .process_frame(Frame::Headers(HeadersFrame::new(
            1,
            encode_live_headers(&[
                H2Header::new(":method", "GET"),
                H2Header::new(":scheme", "https"),
                H2Header::new(":path", "/window-update-oracle"),
                H2Header::new(":authority", "example.test"),
            ]),
            false,
            true,
        )))
        .expect("HEADERS should open stream 1 for stream-level WINDOW_UPDATE");
    stream_connection
        .process_frame(Frame::WindowUpdate(LiveWindowUpdateFrame::new(
            1,
            exact_delta_to_max,
        )))
        .expect("stream WINDOW_UPDATE sequence should reach the exact maximum");
    assert_eq!(
        stream_connection
            .stream(1)
            .map(|stream| stream.send_window()),
        Some(i32::MAX)
    );

    let err = stream_connection
        .process_frame(Frame::WindowUpdate(LiveWindowUpdateFrame::new(1, 1)))
        .expect_err("stream WINDOW_UPDATE above the maximum should fail");
    assert_eq!(err.code, ErrorCode::FlowControlError);
    assert_eq!(err.stream_id, Some(1));
    assert_eq!(err.message.as_str(), "window size overflow");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_window_update() {
        let mut controller = MockH2FlowController::new(65535);
        let frame = WindowUpdateFrame {
            stream_id: 1,
            increment: 1000,
            flags: 0,
        };

        let result = controller.process_window_update(&frame);
        assert!(result.is_ok());

        let (_, stream_sizes) = controller.get_window_sizes();
        assert_eq!(stream_sizes[0].1, 66535); // 65535 + 1000
    }

    #[test]
    fn test_connection_window_overflow() {
        let mut controller = MockH2FlowController::new(2_147_483_647); // Max initial size
        let frame = WindowUpdateFrame {
            stream_id: 0, // Connection-level
            increment: 1, // Would exceed 2^31-1
            flags: 0,
        };

        let result = controller.process_window_update(&frame);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("FLOW_CONTROL_ERROR"));
    }

    #[test]
    fn test_stream_window_overflow() {
        let mut controller = MockH2FlowController::new(65535);

        // First update that gets close to limit
        let frame1 = WindowUpdateFrame {
            stream_id: 1,
            increment: 2_147_418_112, // 2^31-1 - 65535
            flags: 0,
        };
        assert!(controller.process_window_update(&frame1).is_ok());

        // Second update that would overflow
        let frame2 = WindowUpdateFrame {
            stream_id: 1,
            increment: 1,
            flags: 0,
        };
        let result = controller.process_window_update(&frame2);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("FLOW_CONTROL_ERROR"));
    }

    #[test]
    fn test_rapid_small_increments_overflow() {
        let mut controller = MockH2FlowController::new(0);
        let mut total_increment = 0u64;

        // Add many small increments
        for i in 0..1000 {
            let increment = 2_200_000; // Each increment is ~2.2M
            total_increment += increment;

            let frame = WindowUpdateFrame {
                stream_id: 0,
                increment,
                flags: 0,
            };

            let result = controller.process_window_update(&frame);

            if total_increment > 2_147_483_647 {
                assert!(
                    result.is_err(),
                    "Should overflow at iteration {} with total {}",
                    i,
                    total_increment
                );
                break;
            } else {
                assert!(
                    result.is_ok(),
                    "Should not overflow at iteration {} with total {}",
                    i,
                    total_increment
                );
            }
        }
    }

    #[test]
    fn test_multiple_streams_independent_windows() {
        let mut controller = MockH2FlowController::new(65535);

        // Stream 1 gets close to overflow
        let frame1 = WindowUpdateFrame {
            stream_id: 1,
            increment: 2_147_400_000,
            flags: 0,
        };
        assert!(controller.process_window_update(&frame1).is_ok());

        // Stream 2 should still work fine
        let frame2 = WindowUpdateFrame {
            stream_id: 2,
            increment: 1_000_000,
            flags: 0,
        };
        assert!(controller.process_window_update(&frame2).is_ok());

        // Stream 1 overflow shouldn't affect stream 2
        let frame3 = WindowUpdateFrame {
            stream_id: 1,
            increment: 100_000, // Would overflow stream 1
            flags: 0,
        };
        assert!(controller.process_window_update(&frame3).is_err());

        // Stream 2 should still work
        let frame4 = WindowUpdateFrame {
            stream_id: 2,
            increment: 1000,
            flags: 0,
        };
        assert!(controller.process_window_update(&frame4).is_ok());
    }

    #[test]
    fn test_zero_increment_error() {
        let mut controller = MockH2FlowController::new(65535);
        let frame = WindowUpdateFrame {
            stream_id: 1,
            increment: 0, // Invalid
            flags: 0,
        };

        let result = controller.process_window_update(&frame);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must not be zero"));
    }

    #[test]
    fn test_invalid_flags_error() {
        let mut controller = MockH2FlowController::new(65535);
        let frame = WindowUpdateFrame {
            stream_id: 1,
            increment: 1000,
            flags: 1, // Invalid for WINDOW_UPDATE
        };

        let result = controller.process_window_update(&frame);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("flags must be 0"));
    }

    #[test]
    fn test_exactly_at_maximum() {
        let mut controller = MockH2FlowController::new(1);
        let frame = WindowUpdateFrame {
            stream_id: 1,
            increment: 2_147_483_646, // Exactly reaches 2^31-1
            flags: 0,
        };

        let result = controller.process_window_update(&frame);
        assert!(result.is_ok(), "Should allow window exactly at maximum");

        let (_, stream_sizes) = controller.get_window_sizes();
        assert_eq!(stream_sizes[0].1, 2_147_483_647);
    }

    #[test]
    fn test_edge_case_large_increment() {
        let mut controller = MockH2FlowController::new(65535);
        let frame = WindowUpdateFrame {
            stream_id: 1,
            increment: 2_147_483_648, // Larger than 2^31-1
            flags: 0,
        };

        let result = controller.process_window_update(&frame);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum"));
    }

    #[test]
    fn test_connection_vs_stream_windows() {
        let mut controller = MockH2FlowController::new(1_000_000);

        // Connection window update
        let conn_frame = WindowUpdateFrame {
            stream_id: 0,
            increment: 500_000,
            flags: 0,
        };
        assert!(controller.process_window_update(&conn_frame).is_ok());

        // Stream window update (different from connection)
        let stream_frame = WindowUpdateFrame {
            stream_id: 5,
            increment: 300_000,
            flags: 0,
        };
        assert!(controller.process_window_update(&stream_frame).is_ok());

        let (conn_size, stream_sizes) = controller.get_window_sizes();
        assert_eq!(conn_size, 1_500_000); // 1M + 500K
        assert_eq!(stream_sizes[0].1, 365535); // 65535 (default) + 300K
    }
}
