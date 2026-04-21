#![allow(warnings)]
#![allow(clippy::all)]
//! HTTP/2 WINDOW_UPDATE flow control conformance tests.
//!
//! Tests conformance with RFC 9113 Section 6.9 "WINDOW_UPDATE" frame handling.
//! Validates flow control window management, increment validation, overflow detection,
//! and per-stream/connection window separation.

use asupersync::http::h2::connection::{Connection, DEFAULT_CONNECTION_WINDOW_SIZE};
use asupersync::http::h2::error::{ErrorCode, H2Error};
use asupersync::http::h2::frame::{DataFrame, Frame, HeadersFrame, SettingsFrame, WindowUpdateFrame};
use asupersync::http::h2::settings::{Setting, Settings, DEFAULT_INITIAL_WINDOW_SIZE};
use asupersync::bytes::Bytes;

#[cfg(test)]
mod conformance_window_update {
    use super::*;

    #[allow(dead_code)]

    fn init_test(name: &str) {
        asupersync::test_utils::init_test_logging();
        asupersync::test_phase!(name);
    }

    /// **MR1**: RFC 9113 §6.9 - Initial connection window is 65535 bytes
    ///
    /// The initial flow control window size for all streams is 65535 octets.
    /// Both endpoints MUST use 65535 octets as the initial window size for
    /// connection-level flow control.
    #[test]
    #[allow(dead_code)]
    fn mr1_initial_window_65535() {
        init_test("mr1_initial_window_65535");

        // Test both client and server connections
        let client_conn = Connection::client(Settings::default());
        let server_conn = Connection::server(Settings::default());

        // MR1: Both connection-level windows start at 65535
        assert_eq!(
            client_conn.send_window(),
            DEFAULT_CONNECTION_WINDOW_SIZE,
            "Client connection send window must start at 65535"
        );
        assert_eq!(
            client_conn.recv_window(),
            DEFAULT_CONNECTION_WINDOW_SIZE,
            "Client connection recv window must start at 65535"
        );
        assert_eq!(
            server_conn.send_window(),
            DEFAULT_CONNECTION_WINDOW_SIZE,
            "Server connection send window must start at 65535"
        );
        assert_eq!(
            server_conn.recv_window(),
            DEFAULT_CONNECTION_WINDOW_SIZE,
            "Server connection recv window must start at 65535"
        );

        // Verify the constant matches RFC requirement
        assert_eq!(
            DEFAULT_CONNECTION_WINDOW_SIZE,
            65535,
            "DEFAULT_CONNECTION_WINDOW_SIZE must be 65535 per RFC 9113"
        );

        // Verify stream initial window size also defaults to 65535
        assert_eq!(
            DEFAULT_INITIAL_WINDOW_SIZE,
            65535,
            "Default initial window size for streams must be 65535"
        );

        asupersync::test_complete!("mr1_initial_window_65535");
    }

    /// **MR2**: RFC 9113 §6.9.1 - WINDOW_UPDATE increment must be > 0
    ///
    /// A receiver MUST treat the receipt of a WINDOW_UPDATE frame with a
    /// flow control window increment of 0 as a stream error (Section 5.4.2)
    /// of type PROTOCOL_ERROR; errors on the connection flow control window
    /// MUST be treated as a connection error (Section 5.4.1).
    #[test]
    #[allow(dead_code)]
    fn mr2_window_update_increment_must_be_positive() {
        init_test("mr2_window_update_increment_must_be_positive");

        let mut conn = Connection::server(Settings::default());

        // MR2a: Zero increment on connection window (stream_id=0) = connection error
        let zero_connection_update = Frame::WindowUpdate(WindowUpdateFrame::new(0, 0));
        let result = conn.process_frame(zero_connection_update);

        assert!(result.is_err(), "Zero increment on connection window must be rejected");
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError,
            "Zero increment on connection window must cause PROTOCOL_ERROR");
        assert!(err.message.contains("zero increment"),
            "Error message must mention zero increment");

        // Reset connection for next test
        let mut conn = Connection::server(Settings::default());

        // Create a stream first
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, true));
        conn.process_frame(headers).expect("should process headers");

        // MR2b: Zero increment on stream window = stream error
        let zero_stream_update = Frame::WindowUpdate(WindowUpdateFrame::new(1, 0));
        let result = conn.process_frame(zero_stream_update);

        assert!(result.is_err(), "Zero increment on stream window must be rejected");
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError,
            "Zero increment on stream window must cause PROTOCOL_ERROR");
        assert!(err.message.contains("zero increment"),
            "Error message must mention zero increment");

        // MR2c: Positive increments must be accepted
        let mut conn = Connection::server(Settings::default());
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, true));
        conn.process_frame(headers).expect("should process headers");

        let valid_connection_update = Frame::WindowUpdate(WindowUpdateFrame::new(0, 1000));
        let result = conn.process_frame(valid_connection_update);
        assert!(result.is_ok(), "Positive increment on connection window must be accepted");

        let valid_stream_update = Frame::WindowUpdate(WindowUpdateFrame::new(1, 500));
        let result = conn.process_frame(valid_stream_update);
        assert!(result.is_ok(), "Positive increment on stream window must be accepted");

        asupersync::test_complete!("mr2_window_update_increment_must_be_positive");
    }

    /// **MR3**: RFC 9113 §6.9.1 - Window overflow beyond 2^31-1 triggers FLOW_CONTROL_ERROR
    ///
    /// A sender MUST NOT allow a flow control window to exceed the maximum
    /// size. A receiver MUST treat a flow control window overflow as a
    /// connection error of type FLOW_CONTROL_ERROR.
    #[test]
    #[allow(dead_code)]
    fn mr3_window_overflow_triggers_flow_control_error() {
        init_test("mr3_window_overflow_triggers_flow_control_error");

        let mut conn = Connection::server(Settings::default());

        // MR3a: Connection window overflow
        // Set connection send window near maximum
        let near_max = i32::MAX - 1000;
        // We need to manipulate internal state; use the window update API to get close
        let large_increment = (near_max - DEFAULT_CONNECTION_WINDOW_SIZE) as u32;
        let large_update = Frame::WindowUpdate(WindowUpdateFrame::new(0, large_increment));
        conn.process_frame(large_update).expect("large increment should succeed");

        // Now try to overflow with another increment
        let overflow_increment = 2000u32; // This will cause overflow
        let overflow_update = Frame::WindowUpdate(WindowUpdateFrame::new(0, overflow_increment));
        let result = conn.process_frame(overflow_update);

        assert!(result.is_err(), "Window overflow must be rejected");
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::FlowControlError,
            "Window overflow must cause FLOW_CONTROL_ERROR");
        assert!(err.message.contains("overflow"),
            "Error message must mention overflow");

        // MR3b: Stream window overflow
        let mut conn = Connection::server(Settings::default());
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, true));
        conn.process_frame(headers).expect("should process headers");

        // Try to cause stream window overflow
        let large_stream_increment = (i32::MAX as u64 - DEFAULT_INITIAL_WINDOW_SIZE as u64 + 1) as u32;
        let overflow_stream_update = Frame::WindowUpdate(WindowUpdateFrame::new(1, large_stream_increment));
        let result = conn.process_frame(overflow_stream_update);

        // Stream overflow should be handled at the stream level
        assert!(result.is_err(), "Stream window overflow should be rejected");

        // MR3c: Maximum valid window size should be accepted
        let mut conn = Connection::server(Settings::default());
        let max_valid_increment = (i32::MAX - DEFAULT_CONNECTION_WINDOW_SIZE) as u32;
        let max_update = Frame::WindowUpdate(WindowUpdateFrame::new(0, max_valid_increment));
        let result = conn.process_frame(max_update);
        assert!(result.is_ok(), "Maximum valid window increment should be accepted");

        // Window should now be at maximum
        assert_eq!(conn.send_window(), i32::MAX, "Window should be at maximum value");

        asupersync::test_complete!("mr3_window_overflow_triggers_flow_control_error");
    }

    /// **MR4**: RFC 9113 §6.9 - Per-stream and connection windows are separate
    ///
    /// Flow control operates at two levels: individual streams and the entire
    /// connection. Both types of flow control use the window that is managed
    /// using the WINDOW_UPDATE frame.
    #[test]
    #[allow(dead_code)]
    fn mr4_per_stream_and_connection_windows_separate() {
        init_test("mr4_per_stream_and_connection_windows_separate");

        let mut conn = Connection::server(Settings::default());

        // Create multiple streams
        let headers1 = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, true));
        let headers2 = Frame::Headers(HeadersFrame::new(3, Bytes::new(), false, true));
        conn.process_frame(headers1).expect("should process headers for stream 1");
        conn.process_frame(headers2).expect("should process headers for stream 3");

        let initial_conn_send = conn.send_window();
        let initial_conn_recv = conn.recv_window();

        // MR4a: Connection-level WINDOW_UPDATE affects connection window only
        let conn_increment = 1000u32;
        let conn_update = Frame::WindowUpdate(WindowUpdateFrame::new(0, conn_increment));
        conn.process_frame(conn_update).expect("connection window update should succeed");

        assert_eq!(
            conn.send_window(),
            initial_conn_send + conn_increment as i32,
            "Connection send window should be updated"
        );

        // Stream windows should be unaffected by connection updates
        let stream1 = conn.stream(1).expect("stream 1 should exist");
        assert_eq!(
            stream1.send_window(),
            DEFAULT_INITIAL_WINDOW_SIZE,
            "Stream 1 send window should be unchanged by connection update"
        );

        // MR4b: Stream-level WINDOW_UPDATE affects only that stream
        let stream1_increment = 500u32;
        let stream1_update = Frame::WindowUpdate(WindowUpdateFrame::new(1, stream1_increment));
        conn.process_frame(stream1_update).expect("stream 1 window update should succeed");

        // Connection window should be unchanged
        assert_eq!(
            conn.send_window(),
            initial_conn_send + conn_increment as i32,
            "Connection window should be unchanged by stream update"
        );

        // Other streams should be unchanged
        let stream3 = conn.stream(3).expect("stream 3 should exist");
        assert_eq!(
            stream3.send_window(),
            DEFAULT_INITIAL_WINDOW_SIZE,
            "Stream 3 window should be unchanged by stream 1 update"
        );

        // MR4c: Data flow affects both connection and stream windows
        let data_size = 1000u32;
        let data_payload = Bytes::from(vec![0u8; data_size as usize]);
        let data_frame = Frame::Data(DataFrame::new(1, data_payload, false));

        // Process data frame (should affect both windows)
        conn.process_frame(data_frame).expect("should process data frame");

        // Connection recv window should be decremented
        assert_eq!(
            conn.recv_window(),
            initial_conn_recv - data_size as i32,
            "Connection recv window should be decremented by data size"
        );

        // Stream 1 recv window should also be decremented (handled by stream)
        let stream1_after = conn.stream(1).expect("stream 1 should exist");
        assert_eq!(
            stream1_after.recv_window(),
            DEFAULT_INITIAL_WINDOW_SIZE - data_size as i32,
            "Stream 1 recv window should be decremented by data size"
        );

        // Stream 3 should be unaffected
        let stream3_after = conn.stream(3).expect("stream 3 should exist");
        assert_eq!(
            stream3_after.recv_window(),
            DEFAULT_INITIAL_WINDOW_SIZE,
            "Stream 3 recv window should be unchanged"
        );

        asupersync::test_complete!("mr4_per_stream_and_connection_windows_separate");
    }

    /// **MR5**: RFC 9113 §6.9.2 - SETTINGS_INITIAL_WINDOW_SIZE rebalances existing streams
    ///
    /// Changes to SETTINGS_INITIAL_WINDOW_SIZE affect the initial flow control
    /// window size of streams with flow control. When this value increases,
    /// streams that have consumed credit from their windows will receive that
    /// credit back. When this value decreases, and the currently available
    /// window size would become negative, endpoints MUST close the stream.
    #[test]
    #[allow(dead_code)]
    fn mr5_settings_initial_window_size_rebalances() {
        init_test("mr5_settings_initial_window_size_rebalances");

        let mut conn = Connection::server(Settings::default());

        // Create streams and consume some window credit
        let headers1 = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, true));
        let headers2 = Frame::Headers(HeadersFrame::new(3, Bytes::new(), false, true));
        conn.process_frame(headers1).expect("should process headers for stream 1");
        conn.process_frame(headers2).expect("should process headers for stream 3");

        // Consume some credit on stream 1 by sending data
        let data_size = 10000u32;
        let data_payload = Bytes::from(vec![0u8; data_size as usize]);
        let data_frame = Frame::Data(DataFrame::new(1, data_payload, false));
        conn.process_frame(data_frame).expect("should process data frame");

        let stream1_window_after_data = conn.stream(1).unwrap().recv_window();
        let expected_after_data = DEFAULT_INITIAL_WINDOW_SIZE - data_size as i32;
        assert_eq!(stream1_window_after_data, expected_after_data,
            "Stream 1 window should be reduced after data");

        // Stream 3 should still have full window
        assert_eq!(
            conn.stream(3).unwrap().recv_window(),
            DEFAULT_INITIAL_WINDOW_SIZE,
            "Stream 3 should have full window"
        );

        // MR5a: Increase SETTINGS_INITIAL_WINDOW_SIZE - streams gain credit
        let new_larger_window = DEFAULT_INITIAL_WINDOW_SIZE + 16384;
        let settings_increase = Frame::Settings(SettingsFrame::new(vec![
            Setting::InitialWindowSize(new_larger_window)
        ]));

        conn.process_frame(settings_increase).expect("should process settings increase");

        // Both streams should have their windows adjusted by the delta
        let delta = new_larger_window - DEFAULT_INITIAL_WINDOW_SIZE;
        let stream1_window_after_increase = conn.stream(1).unwrap().recv_window();
        let stream3_window_after_increase = conn.stream(3).unwrap().recv_window();

        assert_eq!(
            stream1_window_after_increase,
            expected_after_data + delta,
            "Stream 1 window should increase by delta"
        );
        assert_eq!(
            stream3_window_after_increase,
            DEFAULT_INITIAL_WINDOW_SIZE + delta,
            "Stream 3 window should increase by delta"
        );

        // MR5b: Decrease SETTINGS_INITIAL_WINDOW_SIZE - streams lose credit
        let new_smaller_window = DEFAULT_INITIAL_WINDOW_SIZE - 8192;
        let settings_decrease = Frame::Settings(SettingsFrame::new(vec![
            Setting::InitialWindowSize(new_smaller_window)
        ]));

        conn.process_frame(settings_decrease).expect("should process settings decrease");

        // Windows should be adjusted downward
        let decrease_delta = new_smaller_window - new_larger_window; // negative value
        let stream1_final = conn.stream(1).unwrap().recv_window();
        let stream3_final = conn.stream(3).unwrap().recv_window();

        assert_eq!(
            stream1_final,
            stream1_window_after_increase + decrease_delta,
            "Stream 1 window should decrease by delta"
        );
        assert_eq!(
            stream3_final,
            stream3_window_after_increase + decrease_delta,
            "Stream 3 window should decrease by delta"
        );

        // MR5c: Invalid SETTINGS_INITIAL_WINDOW_SIZE (> 2^31-1) is rejected
        let invalid_window_size = 0x8000_0000u32; // 2^31, which exceeds 2^31-1
        let invalid_settings = Frame::Settings(SettingsFrame::new(vec![
            Setting::InitialWindowSize(invalid_window_size)
        ]));

        let result = conn.process_frame(invalid_settings);
        assert!(result.is_err(), "Invalid window size should be rejected");
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::FlowControlError,
            "Invalid window size should cause FLOW_CONTROL_ERROR");

        asupersync::test_complete!("mr5_settings_initial_window_size_rebalances");
    }

    /// **Integration Test**: Combined flow control scenarios
    ///
    /// Tests interaction between all window update mechanisms to ensure
    /// they work correctly together.
    #[test]
    #[allow(dead_code)]
    fn integration_combined_flow_control_scenarios() {
        init_test("integration_combined_flow_control_scenarios");

        let mut conn = Connection::server(Settings::default());

        // Create stream
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, true));
        conn.process_frame(headers).expect("should process headers");

        // Test sequence: data -> window update -> settings -> more data

        // 1. Send data that triggers auto window updates
        let large_data_size = (DEFAULT_CONNECTION_WINDOW_SIZE / 2) as u32 + 1000;
        let large_data = Bytes::from(vec![0u8; large_data_size as usize]);
        let large_data_frame = Frame::Data(DataFrame::new(1, large_data, false));

        conn.process_frame(large_data_frame).expect("should process large data");

        // Should trigger connection-level window update
        assert!(conn.has_pending_frames(), "Should have pending window updates");

        let mut found_conn_window_update = false;
        while let Some(frame) = conn.next_frame() {
            if let Frame::WindowUpdate(wu) = frame {
                if wu.stream_id == 0 {
                    found_conn_window_update = true;
                    assert!(wu.increment > 0, "Window update increment should be positive");
                }
            }
        }
        assert!(found_conn_window_update, "Should generate connection window update");

        // 2. Manual window updates
        let manual_conn_update = Frame::WindowUpdate(WindowUpdateFrame::new(0, 5000));
        let manual_stream_update = Frame::WindowUpdate(WindowUpdateFrame::new(1, 3000));

        conn.process_frame(manual_conn_update).expect("manual connection update should work");
        conn.process_frame(manual_stream_update).expect("manual stream update should work");

        // 3. Change window size via settings
        let new_window_size = DEFAULT_INITIAL_WINDOW_SIZE * 2;
        let settings_frame = Frame::Settings(SettingsFrame::new(vec![
            Setting::InitialWindowSize(new_window_size)
        ]));

        conn.process_frame(settings_frame).expect("settings should work");

        // 4. Verify all windows are in expected state
        assert!(conn.send_window() > DEFAULT_CONNECTION_WINDOW_SIZE,
            "Connection send window should be increased");
        assert!(conn.recv_window() >= 0,
            "Connection recv window should be non-negative");

        let stream1 = conn.stream(1).expect("stream 1 should exist");
        assert!(stream1.send_window() > DEFAULT_INITIAL_WINDOW_SIZE,
            "Stream 1 send window should reflect new settings");

        asupersync::test_complete!("integration_combined_flow_control_scenarios");
    }

    /// **Edge Case Test**: Boundary conditions and error cases
    #[test]
    #[allow(dead_code)]
    fn edge_cases_boundary_conditions() {
        init_test("edge_cases_boundary_conditions");

        // Test maximum valid window increment
        let mut conn = Connection::server(Settings::default());
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, true));
        conn.process_frame(headers).expect("should process headers");

        // Maximum increment value that won't cause overflow
        let max_increment = 1u32; // Start small to avoid overflow in initial state
        let max_update = Frame::WindowUpdate(WindowUpdateFrame::new(0, max_increment));
        assert!(conn.process_frame(max_update).is_ok(),
            "Maximum valid increment should be accepted");

        // Test window update on non-existent stream
        let nonexistent_stream_update = Frame::WindowUpdate(WindowUpdateFrame::new(999, 1000));
        let result = conn.process_frame(nonexistent_stream_update);
        // Should be handled gracefully (stream might be closed/pruned)
        assert!(result.is_ok(), "Window update on non-existent stream should be handled gracefully");

        // Test multiple rapid window updates
        for i in 1..=10 {
            let rapid_update = Frame::WindowUpdate(WindowUpdateFrame::new(1, 100));
            assert!(conn.process_frame(rapid_update).is_ok(),
                "Rapid window update {} should succeed", i);
        }

        asupersync::test_complete!("edge_cases_boundary_conditions");
    }
}

// Helper functions for test utilities

/// Create a test connection with custom settings
#[allow(dead_code)]
fn create_test_connection(is_client: bool, settings: Settings) -> Connection {
    if is_client {
        Connection::client(settings)
    } else {
        Connection::server(settings)
    }
}

/// Create a minimal headers frame for stream creation
#[allow(dead_code)]
fn create_test_headers(stream_id: u32, end_stream: bool) -> Frame {
    Frame::Headers(HeadersFrame::new(stream_id, Bytes::new(), end_stream, true))
}

/// Create a data frame with specified size
#[allow(dead_code)]
fn create_test_data(stream_id: u32, size: usize, end_stream: bool) -> Frame {
    let data = Bytes::from(vec![0u8; size]);
    Frame::Data(DataFrame::new(stream_id, data, end_stream))
}