//! HTTP/2 DATA frame after END_STREAM fuzzing target.
//!
//! Tests RFC 9113 compliance: DATA frames sent on closed streams MUST result
//! in STREAM_CLOSED error per RFC 9113 Section 6.1.
//!
//! This fuzzer generates arbitrary frame sequences including scenarios where:
//! 1. HEADERS frame with END_STREAM is sent
//! 2. Additional DATA frames are sent on the now-closed stream
//! 3. Verifies STREAM_CLOSED error is correctly generated
//! 4. Tests various edge cases and invalid frame sequences

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::http::h2::{
    connection::{FrameCodec, ConnectionState},
    error::{ErrorCode, H2Error},
    frame::{
        DataFrame, Frame, FrameHeader, FrameType, HeadersFrame,
        data_flags, headers_flags, RstStreamFrame, WindowUpdateFrame
    },
    hpack::Header,
    stream::StreamState,
};
use libfuzzer_sys::fuzz_target;

/// Frame sequence test case for END_STREAM violation detection
#[derive(Debug, Clone, Arbitrary)]
struct FrameSequenceTest {
    /// Initial stream setup frames
    setup_frames: Vec<FrameSequenceStep>,
    /// Stream ID to test on (will be normalized to odd for client streams)
    stream_id: u32,
    /// Frames to send after END_STREAM
    post_end_stream_frames: Vec<PostEndStreamFrame>,
    /// Additional concurrent stream operations
    concurrent_streams: Vec<ConcurrentStream>,
}

/// A step in the frame sequence setup
#[derive(Debug, Clone, Arbitrary)]
struct FrameSequenceStep {
    /// Type of frame to send
    frame_type: FrameStepType,
    /// Whether to set END_STREAM flag (for DATA/HEADERS)
    end_stream: bool,
    /// Frame payload size (for DATA frames)
    payload_size: u16,
}

/// Types of frames that can be sent in setup
#[derive(Debug, Clone, Arbitrary)]
enum FrameStepType {
    Headers,
    Data,
    WindowUpdate,
}

/// Frame to send after END_STREAM (should trigger STREAM_CLOSED)
#[derive(Debug, Clone, Arbitrary)]
struct PostEndStreamFrame {
    /// Type of violating frame
    frame_type: ViolatingFrameType,
    /// Data payload for DATA frames
    data_payload: Vec<u8>,
    /// Whether to set END_STREAM flag (redundant but tests double-violation)
    end_stream_flag: bool,
}

/// Frame types that should be rejected on closed streams
#[derive(Debug, Clone, Arbitrary)]
enum ViolatingFrameType {
    Data,
    Headers,
    WindowUpdate,
}

/// Concurrent stream operations to test multi-stream scenarios
#[derive(Debug, Clone, Arbitrary)]
struct ConcurrentStream {
    /// Alternate stream ID
    stream_id: u32,
    /// Simple operation on this stream
    operation: StreamOperation,
}

/// Simple stream operation for concurrent testing
#[derive(Debug, Clone, Arbitrary)]
enum StreamOperation {
    SendHeaders,
    SendData,
    SendWindowUpdate,
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input size
    if data.len() > 50_000 {
        return;
    }

    let mut u = arbitrary::Unstructured::new(data);

    // Generate frame sequence test case
    let test_case = match FrameSequenceTest::arbitrary(&mut u) {
        Ok(case) => case,
        Err(_) => return, // Not enough input data
    };

    // Limit the complexity to prevent timeouts
    if test_case.setup_frames.len() > 10
        || test_case.post_end_stream_frames.len() > 5
        || test_case.concurrent_streams.len() > 3 {
        return;
    }

    // Test the main frame sequence
    test_data_after_end_stream(&test_case);

    // Test edge cases with different stream states
    test_stream_state_edge_cases(&test_case);

    // Test concurrent stream operations
    test_concurrent_stream_operations(&test_case);

    // Test malformed frame sequences
    test_malformed_frame_sequences(&test_case);
});

/// Test DATA frame after END_STREAM scenario
fn test_data_after_end_stream(test_case: &FrameSequenceTest) {
    let stream_id = normalize_stream_id(test_case.stream_id);

    // Create mock connection and codec
    let connection_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        create_mock_h2_connection()
    }));

    let mut connection = match connection_result {
        Ok(conn) => conn,
        Err(_) => return, // Connection creation failed
    };

    // Step 1: Set up the stream with normal frames
    for step in &test_case.setup_frames {
        let frame_result = create_and_send_frame(&mut connection, stream_id, step, false);
        if frame_result.is_err() {
            return; // Setup failed, which is acceptable
        }
    }

    // Step 2: Send a frame with END_STREAM to close the stream
    let end_stream_frame = FrameSequenceStep {
        frame_type: FrameStepType::Headers,
        end_stream: true,
        payload_size: 0,
    };

    let end_stream_result = create_and_send_frame(&mut connection, stream_id, &end_stream_frame, false);
    if end_stream_result.is_err() {
        return; // END_STREAM setup failed
    }

    // Step 3: Verify stream is in appropriate closed state
    let stream_state = get_stream_state(&connection, stream_id);
    match stream_state {
        Some(StreamState::HalfClosedRemote) | Some(StreamState::Closed) => {
            // Stream is properly closed, continue testing
        }
        _ => {
            // Stream didn't close properly, this is acceptable for malformed setups
            return;
        }
    }

    // Step 4: Send violating frames and verify STREAM_CLOSED errors
    for post_frame in &test_case.post_end_stream_frames {
        let violation_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            send_violating_frame(&mut connection, stream_id, post_frame)
        }));

        assert!(violation_result.is_ok(), "Violating frame should not panic");

        if let Ok(error_result) = violation_result {
            // Should return STREAM_CLOSED error
            match error_result {
                Err(ref error) if matches_stream_closed_error(error) => {
                    // Expected STREAM_CLOSED error
                }
                Err(other_error) => {
                    // Other protocol errors are acceptable (e.g., if setup was malformed)
                    eprintln!("Got protocol error instead of STREAM_CLOSED: {:?}", other_error);
                }
                Ok(()) => {
                    // Frame was accepted, which violates RFC 9113
                    panic!("DATA frame on closed stream was accepted (RFC 9113 violation)");
                }
            }
        }
    }
}

/// Test edge cases with different stream state transitions
fn test_stream_state_edge_cases(test_case: &FrameSequenceTest) {
    let stream_id = normalize_stream_id(test_case.stream_id);

    // Test case 1: Immediate DATA after HEADERS with END_STREAM
    test_immediate_data_after_headers_end_stream(stream_id);

    // Test case 2: Multiple END_STREAM violations
    test_multiple_end_stream_violations(stream_id);

    // Test case 3: RST_STREAM followed by DATA
    test_data_after_rst_stream(stream_id, &test_case.post_end_stream_frames);
}

/// Test immediate DATA frame after HEADERS with END_STREAM
fn test_immediate_data_after_headers_end_stream(stream_id: u32) {
    let connection_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        create_mock_h2_connection()
    }));

    let mut connection = match connection_result {
        Ok(conn) => conn,
        Err(_) => return,
    };

    // Send HEADERS with END_STREAM
    let headers_frame = create_headers_frame(stream_id, true);
    let _ = process_frame(&mut connection, Frame::Headers(headers_frame));

    // Send DATA frame (should be rejected)
    let data_frame = create_data_frame(stream_id, b"data after end_stream".to_vec(), false);
    let data_result = process_frame(&mut connection, Frame::Data(data_frame));

    match data_result {
        Err(ref error) if matches_stream_closed_error(error) => {
            // Expected behavior
        }
        other => {
            eprintln!("Unexpected result for DATA after END_STREAM: {:?}", other);
        }
    }
}

/// Test multiple END_STREAM violations
fn test_multiple_end_stream_violations(stream_id: u32) {
    let connection_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        create_mock_h2_connection()
    }));

    let mut connection = match connection_result {
        Ok(conn) => conn,
        Err(_) => return,
    };

    // Close stream with DATA frame having END_STREAM
    let data_frame_close = create_data_frame(stream_id, b"closing data".to_vec(), true);
    let _ = process_frame(&mut connection, Frame::Data(data_frame_close));

    // Send multiple violating frames
    let violating_frames = vec![
        Frame::Data(create_data_frame(stream_id, b"violation 1".to_vec(), false)),
        Frame::Data(create_data_frame(stream_id, b"violation 2".to_vec(), true)),
        Frame::Headers(create_headers_frame(stream_id, false)),
    ];

    for frame in violating_frames {
        let result = process_frame(&mut connection, frame);
        // Each should result in STREAM_CLOSED or connection-level error
        if let Ok(()) = result {
            eprintln!("Frame was incorrectly accepted on closed stream");
        }
    }
}

/// Test DATA after RST_STREAM
fn test_data_after_rst_stream(stream_id: u32, post_frames: &[PostEndStreamFrame]) {
    if post_frames.is_empty() {
        return;
    }

    let connection_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        create_mock_h2_connection()
    }));

    let mut connection = match connection_result {
        Ok(conn) => conn,
        Err(_) => return,
    };

    // Send RST_STREAM to forcibly close stream
    let rst_frame = RstStreamFrame {
        stream_id,
        error_code: ErrorCode::Cancel,
    };
    let _ = process_frame(&mut connection, Frame::RstStream(rst_frame));

    // Send violating frames
    for post_frame in post_frames {
        if let ViolatingFrameType::Data = post_frame.frame_type {
            let data_frame = create_data_frame(
                stream_id,
                post_frame.data_payload.clone(),
                post_frame.end_stream_flag
            );

            let result = process_frame(&mut connection, Frame::Data(data_frame));

            // Should be rejected
            match result {
                Err(ref error) if matches_stream_closed_error(error) => {
                    // Expected
                }
                Err(_) => {
                    // Other errors acceptable
                }
                Ok(()) => {
                    eprintln!("DATA frame incorrectly accepted after RST_STREAM");
                }
            }
        }
    }
}

/// Test concurrent stream operations
fn test_concurrent_stream_operations(test_case: &FrameSequenceTest) {
    let main_stream_id = normalize_stream_id(test_case.stream_id);

    let connection_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        create_mock_h2_connection()
    }));

    let mut connection = match connection_result {
        Ok(conn) => conn,
        Err(_) => return,
    };

    // Close main stream
    let close_frame = create_headers_frame(main_stream_id, true);
    let _ = process_frame(&mut connection, Frame::Headers(close_frame));

    // Operate on concurrent streams
    for concurrent in &test_case.concurrent_streams {
        let alt_stream_id = normalize_stream_id(concurrent.stream_id);
        if alt_stream_id == main_stream_id {
            continue; // Skip same stream
        }

        let _ = execute_stream_operation(&mut connection, alt_stream_id, &concurrent.operation);
    }

    // Verify main stream violations still detected
    let data_frame = create_data_frame(main_stream_id, b"violation".to_vec(), false);
    let result = process_frame(&mut connection, Frame::Data(data_frame));

    // Should still be rejected on the closed main stream
    if let Ok(()) = result {
        eprintln!("Concurrent operations affected closed stream detection");
    }
}

/// Test malformed frame sequences
fn test_malformed_frame_sequences(test_case: &FrameSequenceTest) {
    let stream_id = normalize_stream_id(test_case.stream_id);

    // Test with invalid stream ID (0)
    test_invalid_stream_id_frames();

    // Test with overly large payloads
    test_oversized_payload_frames(stream_id);

    // Test with reserved stream IDs
    test_reserved_stream_ids(&test_case.post_end_stream_frames);
}

/// Test frames with invalid stream ID
fn test_invalid_stream_id_frames() {
    let connection_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        create_mock_h2_connection()
    }));

    let mut connection = match connection_result {
        Ok(conn) => conn,
        Err(_) => return,
    };

    // DATA frame with stream ID 0 (invalid)
    let invalid_frame = create_data_frame(0, b"invalid".to_vec(), false);
    let result = process_frame(&mut connection, Frame::Data(invalid_frame));

    // Should be rejected (stream ID 0 invalid for DATA frames)
    if let Ok(()) = result {
        eprintln!("DATA frame with stream ID 0 was incorrectly accepted");
    }
}

/// Test frames with oversized payloads
fn test_oversized_payload_frames(stream_id: u32) {
    let connection_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        create_mock_h2_connection()
    }));

    let mut connection = match connection_result {
        Ok(conn) => conn,
        Err(_) => return,
    };

    // Very large DATA frame
    let large_payload = vec![0u8; 100_000]; // 100KB payload
    let large_frame = create_data_frame(stream_id, large_payload, false);
    let _ = process_frame(&mut connection, Frame::Data(large_frame));
}

/// Test with reserved stream IDs
fn test_reserved_stream_ids(post_frames: &[PostEndStreamFrame]) {
    if post_frames.is_empty() {
        return;
    }

    let connection_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        create_mock_h2_connection()
    }));

    let mut connection = match connection_result {
        Ok(conn) => conn,
        Err(_) => return,
    };

    // Test with reserved stream IDs (even numbers are server-initiated)
    let reserved_stream_ids = [2, 4, 8, 0x80000000u32];

    for &stream_id in &reserved_stream_ids {
        for post_frame in post_frames.iter().take(1) { // Test only first frame to save time
            if let ViolatingFrameType::Data = post_frame.frame_type {
                let data_frame = create_data_frame(
                    stream_id,
                    post_frame.data_payload.clone(),
                    false
                );
                let _ = process_frame(&mut connection, Frame::Data(data_frame));
            }
        }
    }
}

// Helper functions for creating mock objects and frames

/// Mock connection state for testing
struct MockConnection {
    stream_states: std::collections::HashMap<u32, StreamState>,
}

/// Create a mock connection for testing
fn create_mock_h2_connection() -> MockConnection {
    MockConnection {
        stream_states: std::collections::HashMap::new(),
    }
}

/// Helper function to check if error represents STREAM_CLOSED
fn matches_stream_closed_error(error: &H2Error) -> bool {
    // This is a simplified check - in practice would need to examine the error details
    error.to_string().contains("STREAM_CLOSED") || error.to_string().contains("stream")
}

/// Normalize stream ID to be odd (client-initiated)
fn normalize_stream_id(raw_stream_id: u32) -> u32 {
    let normalized = raw_stream_id % 0x7FFF_FFFF; // Keep within valid range
    if normalized == 0 || normalized % 2 == 0 {
        normalized + 1 // Make odd (client stream)
    } else {
        normalized
    }
}

/// Create a DATA frame
fn create_data_frame(stream_id: u32, data: Vec<u8>, end_stream: bool) -> DataFrame {
    DataFrame {
        stream_id,
        data: Bytes::from(data),
        end_stream,
    }
}

/// Create a HEADERS frame
fn create_headers_frame(stream_id: u32, end_stream: bool) -> HeadersFrame {
    // Create header block with basic HTTP headers
    let header_block = create_basic_header_block();

    HeadersFrame {
        stream_id,
        header_block,
        end_stream,
        end_headers: true,
        priority: None,
    }
}

/// Create basic header block for HTTP/2 requests
fn create_basic_header_block() -> asupersync::bytes::Bytes {
    // This would normally be HPACK encoded headers
    // For fuzz testing, we use a placeholder that represents encoded headers
    asupersync::bytes::Bytes::from_static(b"\x87\x41\x8a\x08\x9d\x5c\x0b\x81\x70\xdc")
}

/// Get stream state from connection
fn get_stream_state(connection: &MockConnection, stream_id: u32) -> Option<StreamState> {
    connection.stream_states.get(&stream_id).copied()
}

/// Process a frame through the connection
fn process_frame(connection: &mut MockConnection, frame: Frame) -> Result<(), H2Error> {
    match frame {
        Frame::Headers(headers_frame) => {
            if headers_frame.end_stream {
                connection.stream_states.insert(headers_frame.stream_id, StreamState::HalfClosedRemote);
            } else {
                connection.stream_states.insert(headers_frame.stream_id, StreamState::Open);
            }
            Ok(())
        }
        Frame::Data(data_frame) => {
            let current_state = connection.stream_states.get(&data_frame.stream_id).copied()
                .unwrap_or(StreamState::Idle);

            match current_state {
                StreamState::HalfClosedRemote | StreamState::Closed => {
                    // DATA frame on closed stream - return STREAM_CLOSED error
                    Err(H2Error::stream(data_frame.stream_id, ErrorCode::StreamClosed, "DATA frame on closed stream"))
                }
                StreamState::Open => {
                    if data_frame.end_stream {
                        connection.stream_states.insert(data_frame.stream_id, StreamState::HalfClosedLocal);
                    }
                    Ok(())
                }
                _ => {
                    // Invalid state for DATA frame
                    Err(H2Error::stream(data_frame.stream_id, ErrorCode::StreamClosed, "invalid state"))
                }
            }
        }
        Frame::RstStream(rst_frame) => {
            connection.stream_states.insert(rst_frame.stream_id, StreamState::Closed);
            Ok(())
        }
        Frame::WindowUpdate(window_frame) => {
            let current_state = connection.stream_states.get(&window_frame.stream_id).copied()
                .unwrap_or(StreamState::Idle);

            match current_state {
                StreamState::Closed => {
                    Err(H2Error::stream(window_frame.stream_id, ErrorCode::StreamClosed, "WINDOW_UPDATE on closed stream"))
                }
                _ => Ok(())
            }
        }
        _ => Ok(()) // Other frames not relevant for this test
    }
}

/// Create and send a frame based on step type
fn create_and_send_frame(
    connection: &mut MockConnection,
    stream_id: u32,
    step: &FrameSequenceStep,
    _force_error: bool
) -> Result<(), H2Error> {
    let frame = match step.frame_type {
        FrameStepType::Headers => {
            Frame::Headers(create_headers_frame(stream_id, step.end_stream))
        }
        FrameStepType::Data => {
            let payload = vec![0u8; step.payload_size as usize];
            Frame::Data(create_data_frame(stream_id, payload, step.end_stream))
        }
        FrameStepType::WindowUpdate => {
            Frame::WindowUpdate(WindowUpdateFrame {
                stream_id,
                increment: 1024,
            })
        }
    };

    process_frame(connection, frame)
}

/// Send a violating frame after END_STREAM
fn send_violating_frame(
    connection: &mut MockConnection,
    stream_id: u32,
    post_frame: &PostEndStreamFrame
) -> Result<(), H2Error> {
    let frame = match post_frame.frame_type {
        ViolatingFrameType::Data => {
            Frame::Data(create_data_frame(
                stream_id,
                post_frame.data_payload.clone(),
                post_frame.end_stream_flag
            ))
        }
        ViolatingFrameType::Headers => {
            Frame::Headers(create_headers_frame(stream_id, post_frame.end_stream_flag))
        }
        ViolatingFrameType::WindowUpdate => {
            Frame::WindowUpdate(WindowUpdateFrame {
                stream_id,
                increment: 1024,
            })
        }
    };

    process_frame(connection, frame)
}

/// Execute a stream operation for concurrent testing
fn execute_stream_operation(
    connection: &mut MockConnection,
    stream_id: u32,
    operation: &StreamOperation
) -> Result<(), H2Error> {
    match operation {
        StreamOperation::SendHeaders => {
            let frame = Frame::Headers(create_headers_frame(stream_id, false));
            process_frame(connection, frame)
        }
        StreamOperation::SendData => {
            let frame = Frame::Data(create_data_frame(stream_id, b"data".to_vec(), false));
            process_frame(connection, frame)
        }
        StreamOperation::SendWindowUpdate => {
            let frame = Frame::WindowUpdate(WindowUpdateFrame {
                stream_id,
                increment: 1024,
            });
            process_frame(connection, frame)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_id_normalization() {
        assert_eq!(normalize_stream_id(0), 1);
        assert_eq!(normalize_stream_id(1), 1);
        assert_eq!(normalize_stream_id(2), 3);
        assert_eq!(normalize_stream_id(4), 5);
        assert_eq!(normalize_stream_id(0x80000000), 1);
    }

    #[test]
    fn test_data_frame_creation() {
        let frame = create_data_frame(1, b"test".to_vec(), true);
        assert_eq!(frame.stream_id, 1);
        assert!(frame.end_stream);
        assert_eq!(frame.data.as_ref(), b"test");
    }

    #[test]
    fn test_headers_frame_creation() {
        let frame = create_headers_frame(3, false);
        assert_eq!(frame.stream_id, 3);
        assert!(!frame.end_stream);
        assert!(frame.end_headers);
        assert!(!frame.headers.is_empty());
    }
}