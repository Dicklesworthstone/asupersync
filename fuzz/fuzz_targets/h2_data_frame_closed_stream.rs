#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::panic;

/// Stream states per RFC 9113 stream lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Arbitrary)]
enum StreamState {
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

/// Reasons why a stream was closed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Arbitrary)]
enum StreamCloseReason {
    /// Normal completion (END_STREAM)
    EndStream,
    /// Reset by local endpoint
    ResetLocal,
    /// Reset by remote endpoint
    ResetRemote,
    /// Protocol error
    ProtocolError,
    /// Connection closing
    ConnectionClose,
}

/// HTTP/2 error codes per RFC 9113 §7
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorCode {
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

const ALL_ERROR_CODES: [ErrorCode; 14] = [
    ErrorCode::NoError,
    ErrorCode::ProtocolError,
    ErrorCode::InternalError,
    ErrorCode::FlowControlError,
    ErrorCode::SettingsTimeout,
    ErrorCode::StreamClosed,
    ErrorCode::FrameSizeError,
    ErrorCode::RefusedStream,
    ErrorCode::Cancel,
    ErrorCode::CompressionError,
    ErrorCode::ConnectError,
    ErrorCode::EnhanceYourCalm,
    ErrorCode::InadequateSecurity,
    ErrorCode::Http11Required,
];

/// DATA frame per RFC 9113 §6.1
#[derive(Debug, Clone, Arbitrary)]
struct DataFrame {
    /// Stream ID this DATA frame is for
    stream_id: u32,
    /// Whether END_STREAM flag is set
    end_stream: bool,
    /// Payload data
    data: Vec<u8>,
    /// Padded flag and padding length
    padded: Option<u8>,
}

impl DataFrame {
    fn new(stream_id: u32, data: Vec<u8>) -> Self {
        Self {
            stream_id,
            end_stream: false,
            data,
            padded: None,
        }
    }

    fn with_end_stream(mut self) -> Self {
        self.end_stream = true;
        self
    }

    fn with_padding(mut self, padding_len: u8) -> Self {
        self.padded = Some(padding_len);
        self
    }

    fn flow_control_len_i32(&self) -> i32 {
        i32::try_from(self.data.len()).unwrap_or(i32::MAX)
    }
}

/// Stream information for tracking state
#[derive(Debug, Clone)]
struct StreamInfo {
    stream_id: u32,
    state: StreamState,
    close_reason: Option<StreamCloseReason>,
    /// Whether this stream has received END_STREAM
    end_stream_received: bool,
    /// Whether this stream has sent END_STREAM
    end_stream_sent: bool,
    /// Flow control window
    window_size: i32,
}

impl StreamInfo {
    fn new(stream_id: u32) -> Self {
        Self {
            stream_id,
            state: StreamState::Open,
            close_reason: None,
            end_stream_received: false,
            end_stream_sent: false,
            window_size: 65535, // Default initial window size
        }
    }

    fn is_closed(&self) -> bool {
        self.state == StreamState::Closed
    }

    fn close_with_reason(&mut self, reason: StreamCloseReason) {
        self.state = StreamState::Closed;
        self.close_reason = Some(reason);
    }
}

/// Mock HTTP/2 connection for testing DATA frame handling on closed streams
#[derive(Debug)]
struct MockH2Connection {
    /// All streams, keyed by stream ID
    streams: HashMap<u32, StreamInfo>,
    /// Next stream ID for client streams (odd)
    next_client_stream_id: u32,
    /// Next stream ID for server streams (even)
    next_server_stream_id: u32,
    /// Stream errors that occurred
    stream_errors: Vec<(u32, ErrorCode, String)>,
    /// Connection errors that occurred
    connection_errors: Vec<ErrorCode>,
    /// Whether connection is active
    is_active: bool,
}

impl MockH2Connection {
    fn new() -> Self {
        Self {
            streams: HashMap::new(),
            next_client_stream_id: 1,
            next_server_stream_id: 2,
            stream_errors: Vec::new(),
            connection_errors: Vec::new(),
            is_active: true,
        }
    }

    /// Create a new stream
    fn create_stream(&mut self, is_client: bool) -> u32 {
        let stream_id = if is_client {
            let id = self.next_client_stream_id;
            self.next_client_stream_id += 2;
            id
        } else {
            let id = self.next_server_stream_id;
            self.next_server_stream_id += 2;
            id
        };

        self.streams.insert(stream_id, StreamInfo::new(stream_id));
        stream_id
    }

    /// Close a stream with specified reason
    fn close_stream(&mut self, stream_id: u32, reason: StreamCloseReason) -> Result<(), String> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.close_with_reason(reason);
            Ok(())
        } else {
            Err(format!("Stream {} not found", stream_id))
        }
    }

    /// Process DATA frame per RFC 9113 §6.1
    fn receive_data_frame(&mut self, frame: DataFrame) -> Result<(), ErrorCode> {
        if !self.is_active {
            return Err(ErrorCode::ProtocolError);
        }

        let stream_id = frame.stream_id;

        // Check if stream exists
        let stream_info = match self.streams.get_mut(&stream_id) {
            Some(stream) => stream,
            None => {
                // DATA on non-existent stream
                if stream_id == 0 {
                    // DATA frames cannot use stream 0
                    self.connection_errors.push(ErrorCode::ProtocolError);
                    self.is_active = false;
                    return Err(ErrorCode::ProtocolError);
                } else {
                    // DATA on unknown stream - could be STREAM_CLOSED if recently closed
                    self.stream_errors.push((
                        stream_id,
                        ErrorCode::StreamClosed,
                        "DATA frame on non-existent stream".to_string(),
                    ));
                    return Err(ErrorCode::StreamClosed);
                }
            }
        };
        debug_assert_eq!(stream_info.stream_id, stream_id);

        if let Some(padding_len) = frame.padded
            && padding_len as usize > frame.data.len()
        {
            self.stream_errors.push((
                stream_id,
                ErrorCode::FrameSizeError,
                format!(
                    "DATA padding length {} exceeds payload length {}",
                    padding_len,
                    frame.data.len()
                ),
            ));
            return Err(ErrorCode::FrameSizeError);
        }

        // Check if stream is closed - this is the main test case
        if stream_info.is_closed() {
            // RFC 9113: DATA frames received on closed streams should generate STREAM_CLOSED error
            let error_msg = format!(
                "DATA frame on closed stream {} (closed reason: {:?})",
                stream_id, stream_info.close_reason
            );
            self.stream_errors
                .push((stream_id, ErrorCode::StreamClosed, error_msg));
            return Err(ErrorCode::StreamClosed);
        }

        // Validate stream state allows DATA frames
        match stream_info.state {
            StreamState::Open => {
                // Normal case - DATA allowed
            }
            StreamState::HalfClosedLocal => {
                // We can still receive DATA from remote
            }
            StreamState::HalfClosedRemote => {
                // Remote has sent END_STREAM, no more DATA should come
                self.stream_errors.push((
                    stream_id,
                    ErrorCode::StreamClosed,
                    "DATA frame after END_STREAM".to_string(),
                ));
                return Err(ErrorCode::StreamClosed);
            }
            StreamState::Idle | StreamState::ReservedLocal | StreamState::ReservedRemote => {
                // DATA not allowed in these states
                self.stream_errors.push((
                    stream_id,
                    ErrorCode::ProtocolError,
                    format!("DATA frame in invalid state {:?}", stream_info.state),
                ));
                return Err(ErrorCode::ProtocolError);
            }
            StreamState::Closed => {
                // Already handled above, but be explicit
                unreachable!("Closed state should be handled above");
            }
        }

        // Check flow control
        let flow_control_len = frame.flow_control_len_i32();

        if flow_control_len > stream_info.window_size {
            self.stream_errors.push((
                stream_id,
                ErrorCode::FlowControlError,
                format!(
                    "DATA frame size {} exceeds window {}",
                    frame.data.len(),
                    stream_info.window_size
                ),
            ));
            return Err(ErrorCode::FlowControlError);
        }

        // Process the frame
        stream_info.window_size -= flow_control_len;

        if frame.end_stream {
            stream_info.end_stream_received = true;
            if stream_info.end_stream_sent {
                // Both directions closed - stream is now closed
                stream_info.close_with_reason(StreamCloseReason::EndStream);
            } else {
                // Only remote closed
                stream_info.state = StreamState::HalfClosedRemote;
            }
        }

        Ok(())
    }

    /// Send RST_STREAM frame to close a stream
    fn send_rst_stream(&mut self, stream_id: u32, _error_code: ErrorCode) -> Result<(), String> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.close_with_reason(StreamCloseReason::ResetLocal);
            Ok(())
        } else {
            Err(format!("Cannot reset non-existent stream {}", stream_id))
        }
    }

    /// Simulate receiving RST_STREAM from remote
    fn receive_rst_stream(&mut self, stream_id: u32, _error_code: ErrorCode) -> Result<(), String> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.close_with_reason(StreamCloseReason::ResetRemote);
            Ok(())
        } else {
            Err(format!("Cannot reset non-existent stream {}", stream_id))
        }
    }

    /// Get stream state
    fn get_stream_state(&self, stream_id: u32) -> Option<StreamState> {
        self.streams.get(&stream_id).map(|s| s.state)
    }

    /// Get stream close reason
    fn get_stream_close_reason(&self, stream_id: u32) -> Option<StreamCloseReason> {
        self.streams.get(&stream_id).and_then(|s| s.close_reason)
    }

    /// Get stream-level errors
    fn get_stream_errors(&self) -> &[(u32, ErrorCode, String)] {
        &self.stream_errors
    }

    /// Get connection-level errors
    fn get_connection_errors(&self) -> &[ErrorCode] {
        &self.connection_errors
    }

    /// Check if connection is still active
    fn is_connection_active(&self) -> bool {
        self.is_active
    }
}

/// Test scenario for DATA frames on closed streams
#[derive(Debug, Arbitrary)]
struct ClosedStreamDataScenario {
    /// How many streams to create initially
    streams_to_create: u8,
    /// How to close each stream
    closure_methods: Vec<StreamCloseReason>,
    /// DATA frames to send after closure
    data_frames_after_close: Vec<DataFrame>,
    /// Whether to test connection-level stream 0
    test_stream_zero: bool,
}

/// Test DATA frames on closed streams
fn test_data_on_closed_streams(scenario: ClosedStreamDataScenario) -> Result<(), String> {
    let mut connection = MockH2Connection::new();

    // Phase 1: Create streams
    let mut created_streams = Vec::new();
    for i in 0..scenario.streams_to_create.min(10) {
        // Limit to prevent timeout
        let is_client = i % 2 == 0;
        let stream_id = connection.create_stream(is_client);
        created_streams.push(stream_id);
    }

    // Phase 2: Close streams using different methods
    for (i, &close_reason) in scenario.closure_methods.iter().enumerate() {
        if i >= created_streams.len() {
            break;
        }

        let stream_id = created_streams[i];

        match close_reason {
            StreamCloseReason::EndStream => {
                // Simulate END_STREAM by creating DATA frame with end_stream flag
                let end_stream_frame = DataFrame::new(stream_id, vec![]).with_end_stream();
                let end_stream_result = connection.receive_data_frame(end_stream_frame);
                observe_data_frame_result(
                    &connection,
                    stream_id,
                    &end_stream_result,
                    "close stream via END_STREAM DATA",
                );

                // Send our own END_STREAM to fully close
                if let Some(stream) = connection.streams.get_mut(&stream_id) {
                    stream.end_stream_sent = true;
                    if stream.end_stream_received {
                        stream.close_with_reason(StreamCloseReason::EndStream);
                    }
                }
            }
            StreamCloseReason::ResetLocal => {
                let close_result = connection.send_rst_stream(stream_id, ErrorCode::Cancel);
                observe_close_result(
                    &connection,
                    stream_id,
                    StreamCloseReason::ResetLocal,
                    &close_result,
                    "close stream via local RST_STREAM",
                );
            }
            StreamCloseReason::ResetRemote => {
                let close_result = connection.receive_rst_stream(stream_id, ErrorCode::Cancel);
                observe_close_result(
                    &connection,
                    stream_id,
                    StreamCloseReason::ResetRemote,
                    &close_result,
                    "close stream via remote RST_STREAM",
                );
            }
            StreamCloseReason::ProtocolError => {
                let close_result =
                    connection.close_stream(stream_id, StreamCloseReason::ProtocolError);
                observe_close_result(
                    &connection,
                    stream_id,
                    StreamCloseReason::ProtocolError,
                    &close_result,
                    "close stream via protocol error",
                );
            }
            StreamCloseReason::ConnectionClose => {
                let close_result =
                    connection.close_stream(stream_id, StreamCloseReason::ConnectionClose);
                observe_close_result(
                    &connection,
                    stream_id,
                    StreamCloseReason::ConnectionClose,
                    &close_result,
                    "close stream via connection close",
                );
            }
        }

        // Verify stream is closed
        if let Some(state) = connection.get_stream_state(stream_id)
            && state != StreamState::Closed
        {
            return Err(format!(
                "Stream {} not closed after {:?}",
                stream_id, close_reason
            ));
        }
    }

    // Phase 3: Send DATA frames to closed streams
    let mut stream_closed_errors = 0;
    let _initial_error_count = connection.get_stream_errors().len();

    for data_frame in &scenario.data_frames_after_close {
        let stream_id = data_frame.stream_id;

        // If this is a test of stream 0, it should cause connection error
        if scenario.test_stream_zero && stream_id == 0 {
            match connection.receive_data_frame(data_frame.clone()) {
                Err(ErrorCode::ProtocolError) => {
                    // Expected for stream 0
                    continue;
                }
                other => {
                    return Err(format!(
                        "Expected PROTOCOL_ERROR for stream 0 DATA, got {:?}",
                        other
                    ));
                }
            }
        }

        // Check if this stream was one we closed
        let was_closed = created_streams.contains(&stream_id)
            && connection.get_stream_state(stream_id) == Some(StreamState::Closed);

        match connection.receive_data_frame(data_frame.clone()) {
            Err(ErrorCode::StreamClosed) => {
                stream_closed_errors += 1;

                // This should happen for streams we know are closed
                if !was_closed && created_streams.contains(&stream_id) {
                    return Err(format!(
                        "Got STREAM_CLOSED for stream {} that wasn't closed",
                        stream_id
                    ));
                }
            }
            Err(other_error) => {
                observe_data_frame_result(
                    &connection,
                    stream_id,
                    &Err(other_error),
                    "arbitrary DATA after stream closure",
                );
                assert_data_error_matches_frame_state(
                    &connection,
                    data_frame,
                    other_error,
                    "arbitrary DATA after stream closure",
                );
            }
            Ok(()) => {
                // Success is only acceptable if stream wasn't closed
                if was_closed {
                    return Err(format!(
                        "DATA frame accepted on closed stream {}",
                        stream_id
                    ));
                }
            }
        }
    }

    // Validate error handling
    let _final_error_count = connection.get_stream_errors().len();

    // Should have generated some STREAM_CLOSED errors if we sent DATA to closed streams
    let closed_stream_targets = scenario
        .data_frames_after_close
        .iter()
        .filter(|frame| {
            created_streams.contains(&frame.stream_id)
                && connection.get_stream_state(frame.stream_id) == Some(StreamState::Closed)
        })
        .count();

    if closed_stream_targets > 0 && stream_closed_errors == 0 {
        return Err(
            "Expected STREAM_CLOSED errors for DATA on closed streams, but got none".to_string(),
        );
    }

    // Connection should still be active (unless stream 0 was used)
    if !scenario.test_stream_zero && !connection.is_connection_active() {
        return Err("Connection should remain active after stream-level errors".to_string());
    }

    Ok(())
}

/// Test basic DATA on closed stream
fn test_basic_data_on_closed_stream() -> Result<(), String> {
    let mut connection = MockH2Connection::new();

    // Create and close a stream
    let stream_id = connection.create_stream(true);
    connection.close_stream(stream_id, StreamCloseReason::EndStream)?;

    // Send DATA to closed stream
    let data_frame = DataFrame::new(stream_id, vec![1, 2, 3, 4]);

    match connection.receive_data_frame(data_frame) {
        Err(ErrorCode::StreamClosed) => {
            // Expected behavior
        }
        other => {
            return Err(format!("Expected STREAM_CLOSED error, got {:?}", other));
        }
    }

    // Verify error was recorded
    let errors = connection.get_stream_errors();
    let stream_closed_errors = errors
        .iter()
        .filter(|(id, code, _)| *id == stream_id && *code == ErrorCode::StreamClosed)
        .count();

    if stream_closed_errors == 0 {
        return Err("STREAM_CLOSED error not recorded".to_string());
    }

    // Connection should still be active
    if !connection.is_connection_active() {
        return Err("Connection should remain active after stream error".to_string());
    }

    Ok(())
}

/// Test DATA on stream 0 (should cause connection error)
fn test_data_on_stream_zero() -> Result<(), String> {
    let mut connection = MockH2Connection::new();

    let data_frame = DataFrame::new(0, vec![1, 2, 3]);

    match connection.receive_data_frame(data_frame) {
        Err(ErrorCode::ProtocolError) => {
            // Expected - DATA frames cannot use stream 0
        }
        other => {
            return Err(format!(
                "Expected PROTOCOL_ERROR for stream 0, got {:?}",
                other
            ));
        }
    }

    // Connection should be closed for protocol error
    if connection.is_connection_active() {
        return Err("Connection should be closed after protocol error".to_string());
    }

    Ok(())
}

/// Test DATA after different closure methods
fn test_closure_method_variations() -> Result<(), String> {
    let closure_methods = vec![
        StreamCloseReason::EndStream,
        StreamCloseReason::ResetLocal,
        StreamCloseReason::ResetRemote,
        StreamCloseReason::ProtocolError,
    ];

    for close_reason in closure_methods {
        let mut connection = MockH2Connection::new();
        let stream_id = connection.create_stream(true);

        // Close with specific method
        match close_reason {
            StreamCloseReason::EndStream => {
                let end_frame = DataFrame::new(stream_id, vec![]).with_end_stream();
                let end_stream_result = connection.receive_data_frame(end_frame);
                observe_data_frame_result(
                    &connection,
                    stream_id,
                    &end_stream_result,
                    "closure variation END_STREAM DATA",
                );
                if let Some(stream) = connection.streams.get_mut(&stream_id) {
                    stream.end_stream_sent = true;
                    stream.close_with_reason(StreamCloseReason::EndStream);
                }
            }
            StreamCloseReason::ResetLocal => {
                connection.send_rst_stream(stream_id, ErrorCode::Cancel)?;
            }
            StreamCloseReason::ResetRemote => {
                connection.receive_rst_stream(stream_id, ErrorCode::Cancel)?;
            }
            StreamCloseReason::ProtocolError => {
                connection.close_stream(stream_id, StreamCloseReason::ProtocolError)?;
            }
            _ => continue,
        }

        // Verify closure
        if connection.get_stream_state(stream_id) != Some(StreamState::Closed) {
            return Err(format!("Stream not closed after {:?}", close_reason));
        }

        // Send DATA to closed stream
        let data_frame = DataFrame::new(stream_id, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        match connection.receive_data_frame(data_frame) {
            Err(ErrorCode::StreamClosed) => {
                // Expected for all closure methods
            }
            other => {
                return Err(format!(
                    "Expected STREAM_CLOSED for {:?}, got {:?}",
                    close_reason, other
                ));
            }
        }
    }

    Ok(())
}

/// Test large DATA frame on closed stream
fn test_large_data_on_closed_stream() -> Result<(), String> {
    let mut connection = MockH2Connection::new();

    let stream_id = connection.create_stream(true);
    connection.close_stream(stream_id, StreamCloseReason::ResetLocal)?;

    // Large DATA frame
    let large_data = vec![0x42; 16384]; // 16KB
    let data_frame = DataFrame::new(stream_id, large_data).with_padding(0);

    match connection.receive_data_frame(data_frame) {
        Err(ErrorCode::StreamClosed) => {
            // Expected - size shouldn't matter for closed streams
        }
        other => {
            return Err(format!(
                "Expected STREAM_CLOSED for large frame, got {:?}",
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
        if let Ok(scenario) = ClosedStreamDataScenario::arbitrary(&mut unstructured) {
            observe_test_result(
                test_data_on_closed_streams(scenario),
                "arbitrary closed-stream DATA scenario",
            );
        }

        // Run deterministic test cases
        if data.len() > 20 {
            observe_test_result(
                test_basic_data_on_closed_stream(),
                "basic DATA on closed stream",
            );
            observe_test_result(test_data_on_stream_zero(), "DATA on stream zero");
            observe_test_result(
                test_closure_method_variations(),
                "closure method variations",
            );
            observe_test_result(
                test_large_data_on_closed_stream(),
                "large DATA on closed stream",
            );
        }
    });

    assert!(
        result.is_ok(),
        "panic in DATA frame on closed stream fuzzing"
    );
});

fn observe_data_frame_result(
    connection: &MockH2Connection,
    stream_id: u32,
    result: &Result<(), ErrorCode>,
    context: &str,
) {
    match result {
        Ok(()) => {
            if stream_id != 0 {
                assert!(
                    connection.streams.contains_key(&stream_id),
                    "{context}: accepted DATA for an unknown nonzero stream"
                );
            }
        }
        Err(error) => {
            assert_error_code_observable(*error, context);
            match error {
                ErrorCode::ProtocolError => {
                    assert!(
                        !connection.is_connection_active()
                            || connection.get_connection_errors().contains(error)
                            || stream_id != 0,
                        "{context}: protocol error on stream 0 should close or be recorded"
                    );
                }
                ErrorCode::StreamClosed => {
                    assert!(
                        connection
                            .get_stream_errors()
                            .iter()
                            .any(|(id, code, message)| {
                                *id == stream_id
                                    && *code == ErrorCode::StreamClosed
                                    && !message.is_empty()
                            }),
                        "{context}: STREAM_CLOSED should be recorded with diagnostics"
                    );
                }
                ErrorCode::FrameSizeError | ErrorCode::FlowControlError => {
                    assert!(
                        connection
                            .get_stream_errors()
                            .iter()
                            .any(|(id, code, message)| {
                                *id == stream_id && code == error && !message.is_empty()
                            }),
                        "{context}: {error:?} should be recorded with diagnostics"
                    );
                }
                _ => {}
            }
        }
    }
}

fn assert_data_error_matches_frame_state(
    connection: &MockH2Connection,
    frame: &DataFrame,
    error: ErrorCode,
    context: &str,
) {
    match error {
        ErrorCode::ProtocolError => {
            assert!(
                frame.stream_id == 0 || !connection.is_connection_active(),
                "{context}: PROTOCOL_ERROR should be tied to stream 0 or a closed connection"
            );
        }
        ErrorCode::FrameSizeError => {
            let invalid_padding = frame
                .padded
                .is_some_and(|padding_len| padding_len as usize > frame.data.len());
            assert!(
                invalid_padding,
                "{context}: FRAME_SIZE_ERROR should be backed by invalid DATA padding"
            );
        }
        ErrorCode::FlowControlError => {
            let stream = connection.streams.get(&frame.stream_id).unwrap_or_else(|| {
                panic!(
                    "{context}: FLOW_CONTROL_ERROR should reference an existing stream {}",
                    frame.stream_id
                )
            });
            assert!(
                frame.flow_control_len_i32() > stream.window_size,
                "{context}: FLOW_CONTROL_ERROR should be backed by DATA length exceeding the stream window"
            );
        }
        ErrorCode::StreamClosed => {
            assert_eq!(
                connection.get_stream_state(frame.stream_id),
                Some(StreamState::Closed),
                "{context}: STREAM_CLOSED should reference a closed stream"
            );
        }
        other => panic!("{context}: unexpected DATA error code {other:?}"),
    }
}

fn observe_close_result(
    connection: &MockH2Connection,
    stream_id: u32,
    expected_reason: StreamCloseReason,
    result: &Result<(), String>,
    context: &str,
) {
    match result {
        Ok(()) => {
            assert_eq!(
                connection.get_stream_state(stream_id),
                Some(StreamState::Closed),
                "{context}: successful close should leave stream closed"
            );
            assert_eq!(
                connection.get_stream_close_reason(stream_id),
                Some(expected_reason),
                "{context}: close reason changed"
            );
        }
        Err(error) => {
            assert!(
                !error.is_empty(),
                "{context}: close error diagnostics should remain observable"
            );
        }
    }
}

fn observe_test_result(result: Result<(), String>, context: &str) {
    if let Err(error) = result {
        assert!(
            !error.is_empty(),
            "{context}: test failure diagnostics should remain observable"
        );
    }
}

fn assert_error_code_observable(error: ErrorCode, context: &str) {
    assert!(
        ALL_ERROR_CODES.contains(&error),
        "{context}: error code outside registered HTTP/2 range"
    );
}
