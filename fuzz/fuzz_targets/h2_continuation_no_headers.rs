#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Test input structure for CONTINUATION without HEADERS fuzz scenarios
#[derive(Arbitrary, Clone, Debug)]
struct ContinuationWithoutHeadersInput {
    stream_id: u32,                        // Stream ID for the CONTINUATION frame
    frame_flags: u8,                       // CONTINUATION frame flags (END_HEADERS bit 0x4)
    header_block_fragment: Vec<u8>,        // Header block fragment data
    preceding_frames: Vec<PrecedingFrame>, // Frames sent before CONTINUATION
}

/// Frames that can precede a CONTINUATION (but shouldn't for this test)
#[derive(Arbitrary, Clone, Debug)]
enum PrecedingFrame {
    Data {
        stream_id: u32,
        data: Vec<u8>,
    },
    Settings {
        parameters: Vec<(u16, u32)>,
    },
    Priority {
        stream_id: u32,
        dependency: u32,
        weight: u8,
        exclusive: bool,
    },
    RstStream {
        stream_id: u32,
        error_code: u32,
    },
    Ping {
        data: [u8; 8],
    },
    GoAway {
        last_stream_id: u32,
        error_code: u32,
        debug_data: Vec<u8>,
    },
    WindowUpdate {
        stream_id: u32,
        increment: u32,
    },
}

/// Mock connection state to track frame sequencing
struct MockContinuationConnection {
    stream_states: HashMap<u32, StreamState>,
    connection_error: Option<u32>,
    last_frame_type: Option<u8>,
    expecting_continuation: Option<u32>, // Stream ID expecting CONTINUATION
    protocol_violations: Vec<String>,
}

/// Track the state of each stream for CONTINUATION validation
#[derive(Clone, Debug)]
struct StreamState {
    expecting_continuation: bool,
    header_block_started: bool,
    last_frame_type: Option<u8>,
}

/// HTTP/2 frame types
const FRAME_TYPE_DATA: u8 = 0x0;
const FRAME_TYPE_HEADERS: u8 = 0x1;
const FRAME_TYPE_PRIORITY: u8 = 0x2;
const FRAME_TYPE_RST_STREAM: u8 = 0x3;
const FRAME_TYPE_SETTINGS: u8 = 0x4;
const FRAME_TYPE_PUSH_PROMISE: u8 = 0x5;
const FRAME_TYPE_PING: u8 = 0x6;
const FRAME_TYPE_GOAWAY: u8 = 0x7;
const FRAME_TYPE_WINDOW_UPDATE: u8 = 0x8;
const FRAME_TYPE_CONTINUATION: u8 = 0x9;

/// HTTP/2 frame flags
const FLAG_END_HEADERS: u8 = 0x4;

/// Error codes
const PROTOCOL_ERROR: u32 = 0x1;

impl MockContinuationConnection {
    fn new() -> Self {
        Self {
            stream_states: HashMap::new(),
            connection_error: None,
            last_frame_type: None,
            expecting_continuation: None,
            protocol_violations: Vec::new(),
        }
    }

    /// Process a frame and validate CONTINUATION sequencing rules
    fn process_frame(&mut self, frame_type: u8, stream_id: u32, flags: u8, payload: &[u8]) {
        // Check if we're expecting a CONTINUATION but got something else
        if let Some(expected_stream_id) = self.expecting_continuation {
            if frame_type != FRAME_TYPE_CONTINUATION {
                self.connection_error = Some(PROTOCOL_ERROR);
                self.protocol_violations.push(format!(
                    "Expected CONTINUATION for stream {}, got frame type {} instead",
                    expected_stream_id, frame_type
                ));
                return;
            }
            if stream_id != expected_stream_id {
                self.connection_error = Some(PROTOCOL_ERROR);
                self.protocol_violations.push(format!(
                    "CONTINUATION stream ID {} doesn't match expected {}",
                    stream_id, expected_stream_id
                ));
                return;
            }
        }

        match frame_type {
            FRAME_TYPE_HEADERS => {
                self.process_headers_frame(stream_id, flags, payload);
            }
            FRAME_TYPE_PUSH_PROMISE => {
                self.process_push_promise_frame(stream_id, flags, payload);
            }
            FRAME_TYPE_CONTINUATION => {
                self.process_continuation_frame(stream_id, flags, payload);
            }
            FRAME_TYPE_DATA => {
                self.process_data_frame(stream_id, flags, payload);
            }
            FRAME_TYPE_PRIORITY => {
                self.process_priority_frame(stream_id, payload);
            }
            FRAME_TYPE_RST_STREAM => {
                self.process_rst_stream_frame(stream_id, payload);
            }
            FRAME_TYPE_SETTINGS => {
                self.process_settings_frame(payload);
            }
            FRAME_TYPE_PING => {
                self.process_ping_frame(payload);
            }
            FRAME_TYPE_GOAWAY => {
                self.process_goaway_frame(payload);
            }
            FRAME_TYPE_WINDOW_UPDATE => {
                self.process_window_update_frame(stream_id, payload);
            }
            _ => {
                // Unknown frame type - should be ignored per spec
            }
        }

        self.last_frame_type = Some(frame_type);
    }

    fn process_headers_frame(&mut self, stream_id: u32, flags: u8, _payload: &[u8]) {
        let stream_state = self.stream_states.entry(stream_id).or_insert(StreamState {
            expecting_continuation: false,
            header_block_started: false,
            last_frame_type: None,
        });

        stream_state.header_block_started = true;
        stream_state.last_frame_type = Some(FRAME_TYPE_HEADERS);

        // Check END_HEADERS flag
        if (flags & FLAG_END_HEADERS) == 0 {
            // No END_HEADERS flag, expecting CONTINUATION
            stream_state.expecting_continuation = true;
            self.expecting_continuation = Some(stream_id);
        } else {
            // END_HEADERS flag set, header block complete
            stream_state.expecting_continuation = false;
            stream_state.header_block_started = false;
            self.expecting_continuation = None;
        }
    }

    fn process_push_promise_frame(&mut self, stream_id: u32, flags: u8, _payload: &[u8]) {
        let stream_state = self.stream_states.entry(stream_id).or_insert(StreamState {
            expecting_continuation: false,
            header_block_started: false,
            last_frame_type: None,
        });

        stream_state.header_block_started = true;
        stream_state.last_frame_type = Some(FRAME_TYPE_PUSH_PROMISE);

        // Check END_HEADERS flag
        if (flags & FLAG_END_HEADERS) == 0 {
            // No END_HEADERS flag, expecting CONTINUATION
            stream_state.expecting_continuation = true;
            self.expecting_continuation = Some(stream_id);
        } else {
            // END_HEADERS flag set, header block complete
            stream_state.expecting_continuation = false;
            stream_state.header_block_started = false;
            self.expecting_continuation = None;
        }
    }

    fn process_continuation_frame(&mut self, stream_id: u32, flags: u8, _payload: &[u8]) {
        // CRITICAL: CONTINUATION without preceding HEADERS/PUSH_PROMISE is PROTOCOL_ERROR
        let stream_state = self.stream_states.get(&stream_id);

        if let Some(state) = stream_state {
            if !state.expecting_continuation || !state.header_block_started {
                // CONTINUATION frame without proper setup is PROTOCOL_ERROR
                self.connection_error = Some(PROTOCOL_ERROR);
                self.protocol_violations.push(format!(
                    "CONTINUATION frame on stream {} without preceding HEADERS/PUSH_PROMISE",
                    stream_id
                ));
                return;
            }
        } else {
            // CONTINUATION on stream that never had HEADERS/PUSH_PROMISE
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations.push(format!(
                "CONTINUATION frame on unknown stream {} without HEADERS/PUSH_PROMISE",
                stream_id
            ));
            return;
        }

        // Update stream state
        if let Some(state) = self.stream_states.get_mut(&stream_id) {
            state.last_frame_type = Some(FRAME_TYPE_CONTINUATION);

            // Check END_HEADERS flag
            if (flags & FLAG_END_HEADERS) != 0 {
                // END_HEADERS flag set, header block complete
                state.expecting_continuation = false;
                state.header_block_started = false;
                self.expecting_continuation = None;
            }
        }
    }

    fn process_data_frame(&mut self, _stream_id: u32, _flags: u8, _payload: &[u8]) {
        // DATA frames don't affect CONTINUATION sequencing
        // But if we're expecting CONTINUATION, this is an error
        if self.expecting_continuation.is_some() {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("DATA frame while expecting CONTINUATION".to_string());
        }
    }

    fn process_priority_frame(&mut self, _stream_id: u32, _payload: &[u8]) {
        // PRIORITY frames don't affect CONTINUATION sequencing
        // But if we're expecting CONTINUATION, this is an error
        if self.expecting_continuation.is_some() {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("PRIORITY frame while expecting CONTINUATION".to_string());
        }
    }

    fn process_rst_stream_frame(&mut self, stream_id: u32, _payload: &[u8]) {
        // RST_STREAM resets the stream state
        if let Some(expected_stream_id) = self.expecting_continuation {
            if stream_id == expected_stream_id {
                // Reset the stream we were expecting CONTINUATION for
                self.expecting_continuation = None;
            } else {
                // RST_STREAM for different stream while expecting CONTINUATION is error
                self.connection_error = Some(PROTOCOL_ERROR);
                self.protocol_violations
                    .push("RST_STREAM frame while expecting CONTINUATION".to_string());
            }
        }
        self.stream_states.remove(&stream_id);
    }

    fn process_settings_frame(&mut self, _payload: &[u8]) {
        // SETTINGS frames don't affect CONTINUATION sequencing
        // But if we're expecting CONTINUATION, this is an error
        if self.expecting_continuation.is_some() {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("SETTINGS frame while expecting CONTINUATION".to_string());
        }
    }

    fn process_ping_frame(&mut self, _payload: &[u8]) {
        // PING frames don't affect CONTINUATION sequencing
        // But if we're expecting CONTINUATION, this is an error
        if self.expecting_continuation.is_some() {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("PING frame while expecting CONTINUATION".to_string());
        }
    }

    fn process_goaway_frame(&mut self, _payload: &[u8]) {
        // GOAWAY frames don't affect CONTINUATION sequencing
        // But if we're expecting CONTINUATION, this is an error
        if self.expecting_continuation.is_some() {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("GOAWAY frame while expecting CONTINUATION".to_string());
        }
    }

    fn process_window_update_frame(&mut self, _stream_id: u32, _payload: &[u8]) {
        // WINDOW_UPDATE frames don't affect CONTINUATION sequencing
        // But if we're expecting CONTINUATION, this is an error
        if self.expecting_continuation.is_some() {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("WINDOW_UPDATE frame while expecting CONTINUATION".to_string());
        }
    }

    fn has_protocol_error(&self) -> bool {
        self.connection_error.is_some()
    }

    fn get_error_code(&self) -> Option<u32> {
        self.connection_error
    }

    fn get_violations(&self) -> &[String] {
        &self.protocol_violations
    }
}

/// Send a preceding frame to the mock connection
fn send_preceding_frame(conn: &mut MockContinuationConnection, frame: &PrecedingFrame) {
    match frame {
        PrecedingFrame::Data { stream_id, data } => {
            conn.process_frame(FRAME_TYPE_DATA, *stream_id, 0, data);
        }
        PrecedingFrame::Settings { parameters } => {
            let mut payload = Vec::new();
            for (id, value) in parameters {
                payload.extend_from_slice(&id.to_be_bytes());
                payload.extend_from_slice(&value.to_be_bytes());
            }
            conn.process_frame(FRAME_TYPE_SETTINGS, 0, 0, &payload);
        }
        PrecedingFrame::Priority {
            stream_id,
            dependency,
            weight,
            exclusive,
        } => {
            let mut payload = Vec::new();
            let dep_field = if *exclusive {
                *dependency | 0x80000000
            } else {
                *dependency
            };
            payload.extend_from_slice(&dep_field.to_be_bytes());
            payload.push(*weight);
            conn.process_frame(FRAME_TYPE_PRIORITY, *stream_id, 0, &payload);
        }
        PrecedingFrame::RstStream {
            stream_id,
            error_code,
        } => {
            let payload = error_code.to_be_bytes().to_vec();
            conn.process_frame(FRAME_TYPE_RST_STREAM, *stream_id, 0, &payload);
        }
        PrecedingFrame::Ping { data } => {
            conn.process_frame(FRAME_TYPE_PING, 0, 0, data);
        }
        PrecedingFrame::GoAway {
            last_stream_id,
            error_code,
            debug_data,
        } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(&last_stream_id.to_be_bytes());
            payload.extend_from_slice(&error_code.to_be_bytes());
            payload.extend(debug_data);
            conn.process_frame(FRAME_TYPE_GOAWAY, 0, 0, &payload);
        }
        PrecedingFrame::WindowUpdate {
            stream_id,
            increment,
        } => {
            let payload = increment.to_be_bytes().to_vec();
            conn.process_frame(FRAME_TYPE_WINDOW_UPDATE, *stream_id, 0, &payload);
        }
    }
}

fuzz_target!(|input: ContinuationWithoutHeadersInput| {
    // Limit input sizes to prevent excessive memory usage
    if input.header_block_fragment.len() > 16384 || input.preceding_frames.len() > 100 {
        return;
    }

    // Ensure stream ID is valid (non-zero for client-initiated streams)
    let stream_id = if input.stream_id == 0 || input.stream_id > 0x7FFFFFFF {
        1
    } else {
        input.stream_id | 1 // Ensure odd (client-initiated)
    };

    let mut conn = MockContinuationConnection::new();

    // Send preceding frames (none of which should set up CONTINUATION expectation)
    for frame in &input.preceding_frames {
        send_preceding_frame(&mut conn, frame);

        // If we already have a protocol error, stop
        if conn.has_protocol_error() {
            break;
        }
    }

    // Now send the CONTINUATION frame without proper setup
    // This MUST result in PROTOCOL_ERROR per RFC 7540 §6.10
    conn.process_frame(
        FRAME_TYPE_CONTINUATION,
        stream_id,
        input.frame_flags,
        &input.header_block_fragment,
    );

    // Verify that the connection detected a protocol error
    assert!(
        conn.has_protocol_error(),
        "CONTINUATION frame without preceding HEADERS/PUSH_PROMISE must be PROTOCOL_ERROR. \
         Stream ID: {}, Flags: 0x{:02X}, Fragment length: {}, Preceding frames: {}, Violations: {:?}",
        stream_id,
        input.frame_flags,
        input.header_block_fragment.len(),
        input.preceding_frames.len(),
        conn.get_violations()
    );

    // Verify the error code is PROTOCOL_ERROR
    assert_eq!(
        conn.get_error_code(),
        Some(PROTOCOL_ERROR),
        "CONTINUATION without HEADERS/PUSH_PROMISE must result in PROTOCOL_ERROR (0x1), got {:?}. Violations: {:?}",
        conn.get_error_code(),
        conn.get_violations()
    );

    // Verify we have violation messages
    assert!(
        !conn.get_violations().is_empty(),
        "Expected protocol violation messages for CONTINUATION without HEADERS/PUSH_PROMISE"
    );

    // Test specific scenarios
    test_continuation_scenarios(&input, stream_id);
});

/// Test specific CONTINUATION violation scenarios
fn test_continuation_scenarios(input: &ContinuationWithoutHeadersInput, stream_id: u32) {
    // Scenario 1: CONTINUATION as first frame on connection
    {
        let mut conn = MockContinuationConnection::new();
        conn.process_frame(
            FRAME_TYPE_CONTINUATION,
            stream_id,
            input.frame_flags,
            &input.header_block_fragment,
        );
        assert!(
            conn.has_protocol_error(),
            "CONTINUATION as first frame must be PROTOCOL_ERROR"
        );
    }

    // Scenario 2: CONTINUATION after DATA frame
    {
        let mut conn = MockContinuationConnection::new();
        conn.process_frame(FRAME_TYPE_DATA, stream_id, 0, b"test data");
        conn.process_frame(
            FRAME_TYPE_CONTINUATION,
            stream_id,
            input.frame_flags,
            &input.header_block_fragment,
        );
        assert!(
            conn.has_protocol_error(),
            "CONTINUATION after DATA frame must be PROTOCOL_ERROR"
        );
    }

    // Scenario 3: CONTINUATION after SETTINGS frame
    {
        let mut conn = MockContinuationConnection::new();
        conn.process_frame(FRAME_TYPE_SETTINGS, 0, 0, &[]);
        conn.process_frame(
            FRAME_TYPE_CONTINUATION,
            stream_id,
            input.frame_flags,
            &input.header_block_fragment,
        );
        assert!(
            conn.has_protocol_error(),
            "CONTINUATION after SETTINGS frame must be PROTOCOL_ERROR"
        );
    }

    // Scenario 4: CONTINUATION after PRIORITY frame
    {
        let mut conn = MockContinuationConnection::new();
        let priority_payload = [0, 0, 0, 1, 128]; // Dependency 1, weight 128
        conn.process_frame(FRAME_TYPE_PRIORITY, stream_id, 0, &priority_payload);
        conn.process_frame(
            FRAME_TYPE_CONTINUATION,
            stream_id,
            input.frame_flags,
            &input.header_block_fragment,
        );
        assert!(
            conn.has_protocol_error(),
            "CONTINUATION after PRIORITY frame must be PROTOCOL_ERROR"
        );
    }

    // Scenario 5: CONTINUATION on wrong stream (even if another stream is expecting it)
    if stream_id > 1 {
        let mut conn = MockContinuationConnection::new();
        // Set up HEADERS on stream 1 without END_HEADERS
        conn.process_frame(FRAME_TYPE_HEADERS, 1, 0, b"partial headers");
        // Now send CONTINUATION on different stream
        conn.process_frame(
            FRAME_TYPE_CONTINUATION,
            stream_id,
            input.frame_flags,
            &input.header_block_fragment,
        );
        assert!(
            conn.has_protocol_error(),
            "CONTINUATION on wrong stream must be PROTOCOL_ERROR"
        );
    }

    // Scenario 6: CONTINUATION with END_HEADERS flag set
    {
        let mut conn = MockContinuationConnection::new();
        let flags_with_end_headers = input.frame_flags | FLAG_END_HEADERS;
        conn.process_frame(
            FRAME_TYPE_CONTINUATION,
            stream_id,
            flags_with_end_headers,
            &input.header_block_fragment,
        );
        assert!(
            conn.has_protocol_error(),
            "CONTINUATION with END_HEADERS but no preceding HEADERS/PUSH_PROMISE must be PROTOCOL_ERROR"
        );
    }

    // Scenario 7: Multiple CONTINUATION frames without setup
    {
        let mut conn = MockContinuationConnection::new();
        conn.process_frame(
            FRAME_TYPE_CONTINUATION,
            stream_id,
            0, // No END_HEADERS
            b"fragment 1",
        );
        // First CONTINUATION should already cause error, but test second one too
        if !conn.has_protocol_error() {
            conn.process_frame(
                FRAME_TYPE_CONTINUATION,
                stream_id,
                FLAG_END_HEADERS,
                b"fragment 2",
            );
        }
        assert!(
            conn.has_protocol_error(),
            "Multiple CONTINUATION frames without setup must be PROTOCOL_ERROR"
        );
    }

    // Scenario 8: CONTINUATION after stream reset
    {
        let mut conn = MockContinuationConnection::new();
        // Send RST_STREAM first
        conn.process_frame(FRAME_TYPE_RST_STREAM, stream_id, 0, &1u32.to_be_bytes());
        // Now send CONTINUATION
        conn.process_frame(
            FRAME_TYPE_CONTINUATION,
            stream_id,
            input.frame_flags,
            &input.header_block_fragment,
        );
        assert!(
            conn.has_protocol_error(),
            "CONTINUATION after RST_STREAM must be PROTOCOL_ERROR"
        );
    }
}
