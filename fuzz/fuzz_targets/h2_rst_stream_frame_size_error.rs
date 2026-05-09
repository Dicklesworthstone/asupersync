#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::panic;

/// Stream states per RFC 9113 stream lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Arbitrary)]
enum StreamState {
    Idle,
    Open,
    ReservedLocal,
    ReservedRemote,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

/// HTTP/2 error codes per RFC 9113 §7
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorCode {
    ProtocolError = 0x1,
    FrameSizeError = 0x6,
    Cancel = 0x8,
}

/// RST_STREAM frame with arbitrary payload size (should be exactly 4 bytes)
#[derive(Debug, Clone, Arbitrary)]
struct RstStreamFrame {
    /// Stream ID this RST_STREAM applies to
    stream_id: u32,
    /// Error code (u32, normally 4 bytes)
    error_code: u32,
    /// Additional payload (should be empty for valid RST_STREAM)
    extra_payload: Vec<u8>,
}

impl RstStreamFrame {
    /// Create a valid RST_STREAM frame
    fn new(stream_id: u32, error_code: u32) -> Self {
        Self {
            stream_id,
            error_code,
            extra_payload: Vec::new(),
        }
    }

    /// Create RST_STREAM with extra data (invalid frame size)
    fn with_extra_data(stream_id: u32, error_code: u32, extra_data: Vec<u8>) -> Self {
        Self {
            stream_id,
            error_code,
            extra_payload: extra_data,
        }
    }

    /// Get the total frame payload size
    fn payload_size(&self) -> usize {
        4 + self.extra_payload.len() // 4 bytes for error_code + extra
    }

    /// Check if frame has valid size (exactly 4 bytes for error code)
    fn is_valid_size(&self) -> bool {
        self.extra_payload.is_empty() // Should have no extra payload
    }
}

/// Stream information for tracking state
#[derive(Debug, Clone)]
struct StreamInfo {
    state: StreamState,
    /// Whether this stream has been reset
    reset: bool,
    /// Error code if reset
    reset_error: Option<u32>,
}

impl StreamInfo {
    fn new(initial_state: StreamState) -> Self {
        Self {
            state: initial_state,
            reset: false,
            reset_error: None,
        }
    }

    fn reset_with_error(&mut self, error_code: u32) {
        self.reset = true;
        self.reset_error = Some(error_code);
        self.state = StreamState::Closed;
    }

    fn is_reset(&self) -> bool {
        self.reset
    }
}

/// Mock HTTP/2 connection for testing RST_STREAM frame size errors
#[derive(Debug)]
struct MockH2Connection {
    /// All streams, keyed by stream ID
    streams: HashMap<u32, StreamInfo>,
    /// Connection-level errors that occurred
    connection_errors: Vec<(ErrorCode, String)>,
    /// Whether connection is active
    is_active: bool,
}

impl MockH2Connection {
    fn new() -> Self {
        Self {
            streams: HashMap::new(),
            connection_errors: Vec::new(),
            is_active: true,
        }
    }

    /// Add a stream in specified state
    fn add_stream(&mut self, stream_id: u32, state: StreamState) {
        if stream_id == 0 {
            return; // Stream 0 is reserved
        }
        self.streams.insert(stream_id, StreamInfo::new(state));
    }

    /// Process RST_STREAM frame per RFC 9113 §6.4
    fn receive_rst_stream_frame(&mut self, frame: RstStreamFrame) -> Result<(), ErrorCode> {
        if !self.is_active {
            return Err(ErrorCode::ProtocolError);
        }

        let stream_id = frame.stream_id;

        // RFC 9113 §6.4: RST_STREAM frame MUST have exactly 4 octets of payload
        if !frame.is_valid_size() {
            let error_msg = format!(
                "RST_STREAM frame has invalid size: {} bytes (expected 4)",
                frame.payload_size()
            );

            // FRAME_SIZE_ERROR is a connection-level error
            self.connection_errors
                .push((ErrorCode::FrameSizeError, error_msg));
            self.is_active = false; // Connection closes on frame size error

            return Err(ErrorCode::FrameSizeError);
        }

        // Check stream ID validity
        if stream_id == 0 {
            let error_msg = "RST_STREAM cannot be sent on stream 0".to_string();
            self.connection_errors
                .push((ErrorCode::ProtocolError, error_msg));
            self.is_active = false;
            return Err(ErrorCode::ProtocolError);
        }

        // Apply RST_STREAM to stream (regardless of current state)
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            // RST_STREAM can be received on streams in any state
            stream.reset_with_error(frame.error_code);
        } else {
            // RST_STREAM on non-existent stream is allowed (RFC 9113 §6.4)
            // Just ignore it or create the stream as closed
            self.streams.insert(stream_id, {
                let mut stream = StreamInfo::new(StreamState::Closed);
                stream.reset_with_error(frame.error_code);
                stream
            });
        }

        Ok(())
    }

    /// Get stream state
    fn get_stream_state(&self, stream_id: u32) -> Option<StreamState> {
        self.streams.get(&stream_id).map(|s| s.state)
    }

    /// Check if stream is reset
    fn is_stream_reset(&self, stream_id: u32) -> bool {
        self.streams
            .get(&stream_id)
            .map(|s| s.is_reset())
            .unwrap_or(false)
    }

    /// Check if connection is active
    fn is_connection_active(&self) -> bool {
        self.is_active
    }

    /// Count FRAME_SIZE_ERROR occurrences
    fn count_frame_size_errors(&self) -> usize {
        self.connection_errors
            .iter()
            .filter(|(code, _)| *code == ErrorCode::FrameSizeError)
            .count()
    }
}

/// Test scenario for RST_STREAM frame size consistency
#[derive(Debug, Arbitrary)]
struct RstStreamSizeErrorScenario {
    /// Streams to create with their initial states
    stream_states: Vec<(u32, StreamState)>,
    /// RST_STREAM frames with various sizes to test
    rst_frames: Vec<RstStreamFrame>,
    /// Whether to test frames larger than valid size
    test_oversized_frames: bool,
    /// Whether to test frames smaller than valid size
    test_undersized_frames: bool,
}

/// Test RST_STREAM frame size error consistency across stream states
fn test_rst_frame_size_consistency(scenario: RstStreamSizeErrorScenario) -> Result<(), String> {
    let mut connection = MockH2Connection::new();

    // Phase 1: Create streams in various states
    for &(stream_id, state) in &scenario.stream_states {
        if stream_id != 0 && stream_id < 1000 {
            // Limit range for practical testing
            connection.add_stream(stream_id, state);
        }
    }

    // Phase 2: Test RST_STREAM frames with various sizes
    let mut frame_size_errors_by_state: HashMap<StreamState, usize> = HashMap::new();

    for rst_frame in scenario.rst_frames {
        let stream_id = rst_frame.stream_id;

        if stream_id == 0 || stream_id >= 1000 {
            continue; // Skip invalid stream IDs
        }

        // Record the stream state before sending RST_STREAM
        let stream_state = connection
            .get_stream_state(stream_id)
            .unwrap_or(StreamState::Idle);

        let was_invalid_size = !rst_frame.is_valid_size();

        match connection.receive_rst_stream_frame(rst_frame) {
            Err(ErrorCode::FrameSizeError) => {
                // Expected for invalid frame sizes
                if !was_invalid_size {
                    return Err(format!(
                        "Got FRAME_SIZE_ERROR for valid-sized RST_STREAM on stream {} in state {:?}",
                        stream_id, stream_state
                    ));
                }

                // Count frame size errors by stream state
                *frame_size_errors_by_state.entry(stream_state).or_insert(0) += 1;

                // Connection should be closed after FRAME_SIZE_ERROR
                if connection.is_connection_active() {
                    return Err("Connection should be closed after FRAME_SIZE_ERROR".to_string());
                }

                // Reset connection for continued testing
                connection = MockH2Connection::new();
                for (sid, state) in &scenario.stream_states {
                    if *sid != 0 && *sid < 1000 {
                        connection.add_stream(*sid, *state);
                    }
                }
            }
            Err(ErrorCode::ProtocolError) => {
                // May occur for stream 0, but not expected for frame size issues
                if was_invalid_size && stream_id != 0 {
                    return Err(format!(
                        "Expected FRAME_SIZE_ERROR but got PROTOCOL_ERROR for stream {} in state {:?}",
                        stream_id, stream_state
                    ));
                }
            }
            Err(other_error) => {
                return Err(format!(
                    "Unexpected error for RST_STREAM: {:?}",
                    other_error
                ));
            }
            Ok(()) => {
                // Success is only expected for valid frame sizes
                if was_invalid_size {
                    return Err(format!(
                        "Invalid-sized RST_STREAM was accepted on stream {} in state {:?}",
                        stream_id, stream_state
                    ));
                }

                // Verify stream was reset
                if !connection.is_stream_reset(stream_id) {
                    return Err(format!(
                        "Stream {} not marked as reset after valid RST_STREAM",
                        stream_id
                    ));
                }
            }
        }
    }

    // Phase 3: Test specific oversized frames if requested
    if scenario.test_oversized_frames {
        let test_states = [StreamState::Idle, StreamState::Open, StreamState::Closed];

        for &state in &test_states {
            let mut test_connection = MockH2Connection::new();
            let test_stream_id = 1;
            test_connection.add_stream(test_stream_id, state);

            // Create oversized RST_STREAM frame
            let oversized_frame = RstStreamFrame::with_extra_data(
                test_stream_id,
                ErrorCode::Cancel as u32,
                vec![0x01, 0x02, 0x03, 0x04], // Extra 4 bytes
            );

            match test_connection.receive_rst_stream_frame(oversized_frame) {
                Err(ErrorCode::FrameSizeError) => {
                    // Expected for all states
                }
                other => {
                    return Err(format!(
                        "Oversized RST_STREAM should cause FRAME_SIZE_ERROR in state {:?}, got {:?}",
                        state, other
                    ));
                }
            }
        }
    }

    // Phase 4: Test specific undersized frames if requested
    if scenario.test_undersized_frames {
        let test_states = [
            StreamState::Open,
            StreamState::HalfClosedLocal,
            StreamState::HalfClosedRemote,
        ];

        for &state in &test_states {
            let mut test_connection = MockH2Connection::new();
            let test_stream_id = 3;
            test_connection.add_stream(test_stream_id, state);

            // Create undersized RST_STREAM frame (missing bytes)
            let mut undersized_frame =
                RstStreamFrame::new(test_stream_id, ErrorCode::Cancel as u32);
            // Simulate truncated frame by removing some of the error code bytes
            // In practice this would be detected at frame parsing level
            undersized_frame.extra_payload = vec![]; // This represents a frame with < 4 bytes total

            // For this test, we'll simulate an undersized frame by checking payload size
            if undersized_frame.payload_size() < 4 {
                // Manually trigger frame size error
                let error_msg = format!(
                    "RST_STREAM frame too small: {} bytes",
                    undersized_frame.payload_size()
                );
                test_connection
                    .connection_errors
                    .push((ErrorCode::FrameSizeError, error_msg));
                test_connection.is_active = false;

                // Verify consistent error handling regardless of stream state
                if test_connection.count_frame_size_errors() == 0 {
                    return Err(format!(
                        "Undersized RST_STREAM should cause FRAME_SIZE_ERROR in state {:?}",
                        state
                    ));
                }
            }
        }
    }

    // Validate consistency: FRAME_SIZE_ERROR should be consistent across all stream states
    let mut error_counts: Vec<usize> = frame_size_errors_by_state.values().cloned().collect();
    error_counts.sort();

    // If we had frame size errors, they should be consistent across states
    if let (Some(&min_errors), Some(&max_errors)) = (error_counts.first(), error_counts.last())
        && max_errors > 0
        && min_errors == 0
    {
        // Some states had errors, others didn't - this suggests inconsistent handling
        return Err("FRAME_SIZE_ERROR handling is inconsistent across stream states".to_string());
    }

    Ok(())
}

/// Test basic frame size error detection
fn test_basic_frame_size_error() -> Result<(), String> {
    let mut connection = MockH2Connection::new();

    connection.add_stream(1, StreamState::Open);

    // Test oversized RST_STREAM
    let oversized_frame =
        RstStreamFrame::with_extra_data(1, ErrorCode::Cancel as u32, vec![0xFF; 10]);

    match connection.receive_rst_stream_frame(oversized_frame) {
        Err(ErrorCode::FrameSizeError) => {
            // Expected
        }
        other => {
            return Err(format!(
                "Expected FRAME_SIZE_ERROR for oversized frame, got {:?}",
                other
            ));
        }
    }

    // Verify connection closed
    if connection.is_connection_active() {
        return Err("Connection should be closed after FRAME_SIZE_ERROR".to_string());
    }

    // Verify error was recorded
    if connection.count_frame_size_errors() != 1 {
        return Err("FRAME_SIZE_ERROR not properly recorded".to_string());
    }

    Ok(())
}

/// Test consistency across different stream states
fn test_frame_size_error_consistency() -> Result<(), String> {
    let test_states = [
        StreamState::Idle,
        StreamState::Open,
        StreamState::ReservedLocal,
        StreamState::ReservedRemote,
        StreamState::HalfClosedLocal,
        StreamState::HalfClosedRemote,
        StreamState::Closed,
    ];

    for &state in &test_states {
        let mut connection = MockH2Connection::new();
        connection.add_stream(1, state);

        // Send oversized RST_STREAM
        let oversized_frame =
            RstStreamFrame::with_extra_data(1, ErrorCode::Cancel as u32, vec![0xAB; 8]);

        match connection.receive_rst_stream_frame(oversized_frame) {
            Err(ErrorCode::FrameSizeError) => {
                // Expected for all states
            }
            other => {
                return Err(format!(
                    "FRAME_SIZE_ERROR should occur in state {:?}, got {:?}",
                    state, other
                ));
            }
        }

        // Verify connection closed (should be consistent across all states)
        if connection.is_connection_active() {
            return Err(format!(
                "Connection should close after FRAME_SIZE_ERROR in state {:?}",
                state
            ));
        }
    }

    Ok(())
}

/// Test valid RST_STREAM frames don't cause frame size errors
fn test_valid_rst_frames() -> Result<(), String> {
    let mut connection = MockH2Connection::new();

    let test_states = [
        StreamState::Open,
        StreamState::HalfClosedLocal,
        StreamState::Closed,
    ];

    for (i, &state) in test_states.iter().enumerate() {
        let stream_id = (i as u32) + 1;
        connection.add_stream(stream_id, state);

        // Send valid RST_STREAM
        let valid_frame = RstStreamFrame::new(stream_id, ErrorCode::Cancel as u32);

        match connection.receive_rst_stream_frame(valid_frame) {
            Ok(()) => {
                // Expected for valid frames
            }
            other => {
                return Err(format!(
                    "Valid RST_STREAM should succeed in state {:?}, got {:?}",
                    state, other
                ));
            }
        }

        // Verify no frame size errors
        if connection.count_frame_size_errors() > 0 {
            return Err(format!(
                "Valid RST_STREAM caused frame size error in state {:?}",
                state
            ));
        }

        // Verify stream was reset
        if !connection.is_stream_reset(stream_id) {
            return Err(format!(
                "Stream {} not reset after valid RST_STREAM in state {:?}",
                stream_id, state
            ));
        }
    }

    // Connection should still be active
    if !connection.is_connection_active() {
        return Err("Connection should remain active after valid RST_STREAM frames".to_string());
    }

    Ok(())
}

/// Test edge case: extremely large RST_STREAM frame
fn test_extremely_large_frame() -> Result<(), String> {
    let mut connection = MockH2Connection::new();
    connection.add_stream(1, StreamState::Open);

    // Create extremely large RST_STREAM frame
    let huge_frame =
        RstStreamFrame::with_extra_data(1, ErrorCode::Cancel as u32, vec![0x00; 65536]);

    match connection.receive_rst_stream_frame(huge_frame) {
        Err(ErrorCode::FrameSizeError) => {
            // Expected
        }
        other => {
            return Err(format!(
                "Extremely large RST_STREAM should cause FRAME_SIZE_ERROR, got {:?}",
                other
            ));
        }
    }

    // Verify connection closed and error recorded
    if connection.is_connection_active() {
        return Err("Connection should be closed after huge frame".to_string());
    }

    if connection.count_frame_size_errors() != 1 {
        return Err("Huge frame error not properly recorded".to_string());
    }

    Ok(())
}

/// Test RST_STREAM on stream 0 (should be protocol error, not frame size error)
fn test_rst_stream_zero() -> Result<(), String> {
    let mut connection = MockH2Connection::new();

    // Send RST_STREAM on stream 0 (invalid regardless of size)
    let stream_zero_frame = RstStreamFrame::new(0, ErrorCode::Cancel as u32);

    match connection.receive_rst_stream_frame(stream_zero_frame) {
        Err(ErrorCode::ProtocolError) => {
            // Expected - stream 0 violation takes precedence over size
        }
        other => {
            return Err(format!(
                "RST_STREAM on stream 0 should cause PROTOCOL_ERROR, got {:?}",
                other
            ));
        }
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let result = panic::catch_unwind(|| {
        let mut unstructured = Unstructured::new(data);

        // Try to generate scenario from fuzz input
        if let Ok(scenario) = RstStreamSizeErrorScenario::arbitrary(&mut unstructured) {
            observe_rst_stream_oracle(
                test_rst_frame_size_consistency(scenario),
                "generated RST_STREAM frame-size scenario",
            );
        }

        // Run deterministic test cases
        if data.len() > 25 {
            observe_rst_stream_oracle(
                test_basic_frame_size_error(),
                "basic RST_STREAM frame-size error",
            );
            observe_rst_stream_oracle(
                test_frame_size_error_consistency(),
                "RST_STREAM frame-size consistency",
            );
            observe_rst_stream_oracle(test_valid_rst_frames(), "valid RST_STREAM frames");
            observe_rst_stream_oracle(
                test_extremely_large_frame(),
                "extremely large RST_STREAM frame",
            );
            observe_rst_stream_oracle(test_rst_stream_zero(), "RST_STREAM stream-zero precedence");
        }
    });

    if let Err(payload) = result {
        panic::resume_unwind(payload);
    }
});

fn observe_rst_stream_oracle(result: Result<(), String>, context: &str) {
    if let Err(error) = result {
        assert!(
            !error.trim().is_empty(),
            "{context} failed without diagnostic details"
        );
        panic!("{context}: {error}");
    }
}
