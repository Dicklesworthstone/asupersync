#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Test input structure for zero-length DATA frame scenarios
#[derive(Arbitrary, Clone, Debug)]
struct ZeroLengthDataInput {
    stream_id: u32,                        // Stream ID for the DATA frame
    end_stream: bool,                      // Whether to set END_STREAM flag
    padded: bool,                          // Whether to use PADDED flag (with zero padding)
    preceding_frames: Vec<PrecedingFrame>, // Setup frames before DATA
    follow_up_frames: Vec<FollowUpFrame>,  // Frames after the zero-length DATA
}

/// Frames that can precede the zero-length DATA frame
#[derive(Arbitrary, Clone, Debug)]
enum PrecedingFrame {
    Headers {
        stream_id: u32,
        end_headers: bool,
        end_stream: bool,
    },
    Settings {
        parameters: Vec<(u16, u32)>,
    },
    WindowUpdate {
        stream_id: u32,
        increment: u32,
    },
    Priority {
        stream_id: u32,
        dependency: u32,
        weight: u8,
        exclusive: bool,
    },
}

/// Frames that can follow the zero-length DATA frame
#[derive(Arbitrary, Clone, Debug)]
enum FollowUpFrame {
    Data {
        stream_id: u32,
        data: Vec<u8>,
        end_stream: bool,
    },
    Headers {
        stream_id: u32,
        end_headers: bool,
        end_stream: bool,
    },
    RstStream {
        stream_id: u32,
        error_code: u32,
    },
    WindowUpdate {
        stream_id: u32,
        increment: u32,
    },
}

/// Mock connection state to track DATA frame handling
struct MockZeroDataConnection {
    stream_states: HashMap<u32, StreamState>,
    connection_error: Option<u32>,
    connection_window: i32,
    zero_data_frames_received: Vec<ZeroDataFrameInfo>,
    protocol_violations: Vec<String>,
}

/// Information about received zero-length DATA frames
#[derive(Clone, Debug)]
struct ZeroDataFrameInfo {
    stream_id: u32,
    end_stream: bool,
    padded: bool,
    flow_control_consumed: u32,
}

/// Track the state of each stream
#[derive(Clone, Debug)]
struct StreamState {
    state: StreamStateEnum,
    headers_received: bool,
    data_received: bool,
    ended_remotely: bool,
    flow_control_window: i32,
}

#[derive(Clone, Debug, PartialEq)]
enum StreamStateEnum {
    Open,
    HalfClosedRemote,
    Closed,
}

/// HTTP/2 frame types
const FRAME_TYPE_DATA: u8 = 0x0;
const FRAME_TYPE_HEADERS: u8 = 0x1;
const FRAME_TYPE_PRIORITY: u8 = 0x2;
const FRAME_TYPE_RST_STREAM: u8 = 0x3;
const FRAME_TYPE_SETTINGS: u8 = 0x4;
const FRAME_TYPE_WINDOW_UPDATE: u8 = 0x8;

/// HTTP/2 frame flags
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;

/// Error codes
const PROTOCOL_ERROR: u32 = 0x1;
const FLOW_CONTROL_ERROR: u32 = 0x3;
const STREAM_CLOSED: u32 = 0x5;

/// Initial flow control window size
const INITIAL_WINDOW_SIZE: i32 = 65535;

impl MockZeroDataConnection {
    fn new() -> Self {
        Self {
            stream_states: HashMap::new(),
            connection_error: None,
            connection_window: INITIAL_WINDOW_SIZE,
            zero_data_frames_received: Vec::new(),
            protocol_violations: Vec::new(),
        }
    }

    /// Process a frame and validate zero-length DATA frame handling
    fn process_frame(&mut self, frame_type: u8, stream_id: u32, flags: u8, payload: &[u8]) {
        match frame_type {
            FRAME_TYPE_DATA => {
                self.process_data_frame(stream_id, flags, payload);
            }
            FRAME_TYPE_HEADERS => {
                self.process_headers_frame(stream_id, flags, payload);
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
            FRAME_TYPE_WINDOW_UPDATE => {
                self.process_window_update_frame(stream_id, payload);
            }
            _ => {
                // Unknown frame type - should be ignored per spec
            }
        }
    }

    fn process_data_frame(&mut self, stream_id: u32, flags: u8, payload: &[u8]) {
        // Validate stream ID (must be non-zero for DATA frames)
        if stream_id == 0 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("DATA frame with stream ID 0".to_string());
            return;
        }

        // Get or create stream state
        let stream_state = self.stream_states.entry(stream_id).or_insert(StreamState {
            state: StreamStateEnum::Open,
            headers_received: false,
            data_received: false,
            ended_remotely: false,
            flow_control_window: INITIAL_WINDOW_SIZE,
        });

        // Check if stream is in valid state for receiving DATA
        match stream_state.state {
            StreamStateEnum::HalfClosedRemote | StreamStateEnum::Closed => {
                self.connection_error = Some(STREAM_CLOSED);
                self.protocol_violations.push(format!(
                    "DATA frame on stream {} in state {:?}",
                    stream_id, stream_state.state
                ));
                return;
            }
            _ => {}
        }

        let end_stream = (flags & FLAG_END_STREAM) != 0;
        let padded = (flags & FLAG_PADDED) != 0;

        // Handle PADDED flag
        let (data_length, flow_control_consumed) = if padded {
            if payload.is_empty() {
                self.connection_error = Some(PROTOCOL_ERROR);
                self.protocol_violations
                    .push("PADDED DATA frame with no pad length".to_string());
                return;
            }
            let pad_length = payload[0] as usize;
            if pad_length >= payload.len() {
                self.connection_error = Some(PROTOCOL_ERROR);
                self.protocol_violations.push(format!(
                    "PADDED DATA frame with pad length {} >= frame length {}",
                    pad_length,
                    payload.len()
                ));
                return;
            }
            let data_length = payload.len() - 1 - pad_length; // -1 for pad_length byte
            (data_length, payload.len() as u32) // Flow control counts entire frame payload
        } else {
            (payload.len(), payload.len() as u32)
        };

        // CRITICAL: Zero-length DATA frames are LEGAL per RFC 7540
        // They can be useful as:
        // 1. END_STREAM markers (empty body terminator)
        // 2. Flow control updates (though useless without END_STREAM)
        // The parser must NOT treat them as protocol errors

        if data_length == 0 {
            // Record this zero-length DATA frame
            self.zero_data_frames_received.push(ZeroDataFrameInfo {
                stream_id,
                end_stream,
                padded,
                flow_control_consumed,
            });

            // Zero-length DATA frames are explicitly allowed by RFC 7540
            // Section 6.1: "DATA frames MAY also contain padding.
            // Padding can be added to DATA frames to obscure the size of messages."
            // A frame with only padding (zero data) is valid.
        }

        // Update flow control windows
        if flow_control_consumed > 0 {
            // Check connection-level flow control
            if self.connection_window < flow_control_consumed as i32 {
                self.connection_error = Some(FLOW_CONTROL_ERROR);
                self.protocol_violations
                    .push("Connection flow control window exceeded".to_string());
                return;
            }

            // Check stream-level flow control
            if stream_state.flow_control_window < flow_control_consumed as i32 {
                self.connection_error = Some(FLOW_CONTROL_ERROR);
                self.protocol_violations
                    .push(format!("Stream {} flow control window exceeded", stream_id));
                return;
            }

            // Consume flow control
            self.connection_window -= flow_control_consumed as i32;
            stream_state.flow_control_window -= flow_control_consumed as i32;
        }

        // Update stream state
        stream_state.data_received = true;

        if end_stream {
            stream_state.ended_remotely = true;
            if stream_state.state == StreamStateEnum::Open {
                stream_state.state = StreamStateEnum::HalfClosedRemote;
            }
        }
    }

    fn process_headers_frame(&mut self, stream_id: u32, flags: u8, _payload: &[u8]) {
        if stream_id == 0 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("HEADERS frame with stream ID 0".to_string());
            return;
        }

        let stream_state = self.stream_states.entry(stream_id).or_insert(StreamState {
            state: StreamStateEnum::Open,
            headers_received: false,
            data_received: false,
            ended_remotely: false,
            flow_control_window: INITIAL_WINDOW_SIZE,
        });

        stream_state.headers_received = true;

        let end_stream = (flags & FLAG_END_STREAM) != 0;
        if end_stream {
            stream_state.ended_remotely = true;
            if stream_state.state == StreamStateEnum::Open {
                stream_state.state = StreamStateEnum::HalfClosedRemote;
            }
        }
    }

    fn process_priority_frame(&mut self, stream_id: u32, payload: &[u8]) {
        if payload.len() != 5 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("PRIORITY frame with invalid length".to_string());
            return;
        }

        if stream_id == 0 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("PRIORITY frame with stream ID 0".to_string());
        }

        // PRIORITY frames don't affect stream state for zero-length DATA testing
    }

    fn process_rst_stream_frame(&mut self, stream_id: u32, payload: &[u8]) {
        if payload.len() != 4 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("RST_STREAM frame with invalid length".to_string());
            return;
        }

        if stream_id == 0 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("RST_STREAM frame with stream ID 0".to_string());
            return;
        }

        // Reset stream state
        if let Some(stream_state) = self.stream_states.get_mut(&stream_id) {
            stream_state.state = StreamStateEnum::Closed;
        }
    }

    fn process_settings_frame(&mut self, payload: &[u8]) {
        if !payload.len().is_multiple_of(6) {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("SETTINGS frame with invalid length".to_string());
        }
        // SETTINGS frames don't affect zero-length DATA testing
    }

    fn process_window_update_frame(&mut self, stream_id: u32, payload: &[u8]) {
        if payload.len() != 4 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("WINDOW_UPDATE frame with invalid length".to_string());
            return;
        }

        let increment = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

        if increment == 0 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("WINDOW_UPDATE with zero increment".to_string());
            return;
        }

        if stream_id == 0 {
            // Connection-level window update
            self.connection_window = self.connection_window.saturating_add(increment as i32);
        } else {
            // Stream-level window update
            if let Some(stream_state) = self.stream_states.get_mut(&stream_id) {
                stream_state.flow_control_window = stream_state
                    .flow_control_window
                    .saturating_add(increment as i32);
            }
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

    fn get_zero_data_frames(&self) -> &[ZeroDataFrameInfo] {
        &self.zero_data_frames_received
    }

    fn count_zero_data_with_end_stream(&self) -> usize {
        self.zero_data_frames_received
            .iter()
            .filter(|f| f.end_stream)
            .count()
    }

    fn count_zero_data_without_end_stream(&self) -> usize {
        self.zero_data_frames_received
            .iter()
            .filter(|f| !f.end_stream)
            .count()
    }
}

/// Send a preceding frame to set up the connection state
fn send_preceding_frame(conn: &mut MockZeroDataConnection, frame: &PrecedingFrame) {
    match frame {
        PrecedingFrame::Headers {
            stream_id,
            end_headers,
            end_stream,
        } => {
            let mut flags = 0;
            if *end_headers {
                flags |= FLAG_END_HEADERS;
            }
            if *end_stream {
                flags |= FLAG_END_STREAM;
            }
            conn.process_frame(FRAME_TYPE_HEADERS, *stream_id, flags, b"headers");
        }
        PrecedingFrame::Settings { parameters } => {
            let mut payload = Vec::new();
            for (id, value) in parameters {
                payload.extend_from_slice(&id.to_be_bytes());
                payload.extend_from_slice(&value.to_be_bytes());
            }
            conn.process_frame(FRAME_TYPE_SETTINGS, 0, 0, &payload);
        }
        PrecedingFrame::WindowUpdate {
            stream_id,
            increment,
        } => {
            let payload = increment.to_be_bytes().to_vec();
            conn.process_frame(FRAME_TYPE_WINDOW_UPDATE, *stream_id, 0, &payload);
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
    }
}

/// Send a follow-up frame after the zero-length DATA
fn send_follow_up_frame(conn: &mut MockZeroDataConnection, frame: &FollowUpFrame) {
    match frame {
        FollowUpFrame::Data {
            stream_id,
            data,
            end_stream,
        } => {
            let flags = if *end_stream { FLAG_END_STREAM } else { 0 };
            conn.process_frame(FRAME_TYPE_DATA, *stream_id, flags, data);
        }
        FollowUpFrame::Headers {
            stream_id,
            end_headers,
            end_stream,
        } => {
            let mut flags = 0;
            if *end_headers {
                flags |= FLAG_END_HEADERS;
            }
            if *end_stream {
                flags |= FLAG_END_STREAM;
            }
            conn.process_frame(FRAME_TYPE_HEADERS, *stream_id, flags, b"headers");
        }
        FollowUpFrame::RstStream {
            stream_id,
            error_code,
        } => {
            let payload = error_code.to_be_bytes().to_vec();
            conn.process_frame(FRAME_TYPE_RST_STREAM, *stream_id, 0, &payload);
        }
        FollowUpFrame::WindowUpdate {
            stream_id,
            increment,
        } => {
            let payload = increment.to_be_bytes().to_vec();
            conn.process_frame(FRAME_TYPE_WINDOW_UPDATE, *stream_id, 0, &payload);
        }
    }
}

fuzz_target!(|input: ZeroLengthDataInput| {
    // Limit input sizes to prevent excessive memory usage
    if input.preceding_frames.len() > 50 || input.follow_up_frames.len() > 50 {
        return;
    }

    // Ensure stream ID is valid (non-zero for client-initiated streams)
    let stream_id = if input.stream_id == 0 || input.stream_id > 0x7FFFFFFF {
        1
    } else {
        input.stream_id | 1 // Ensure odd (client-initiated)
    };

    let mut conn = MockZeroDataConnection::new();

    // Send preceding frames to set up connection state
    for frame in &input.preceding_frames {
        send_preceding_frame(&mut conn, frame);
        if conn.has_protocol_error() {
            // Stop if we hit a protocol error from setup frames
            return;
        }
    }

    // Create the zero-length DATA frame payload
    let (payload, expected_flow_control) = if input.padded {
        // PADDED with zero padding: [pad_length=0][no data][no padding]
        (vec![0], 1u32) // pad_length byte counts toward flow control
    } else {
        // No payload
        (vec![], 0u32)
    };

    let mut flags = 0;
    if input.end_stream {
        flags |= FLAG_END_STREAM;
    }
    if input.padded {
        flags |= FLAG_PADDED;
    }

    // Send the zero-length DATA frame
    let initial_zero_frames = conn.get_zero_data_frames().len();
    conn.process_frame(FRAME_TYPE_DATA, stream_id, flags, &payload);

    // CRITICAL: Zero-length DATA frames MUST NOT cause protocol errors
    // Per RFC 7540 §6.1, they are explicitly allowed
    if conn.has_protocol_error() {
        panic!(
            "Zero-length DATA frame caused protocol error: {:?}. \
             Stream ID: {}, END_STREAM: {}, PADDED: {}, Payload: {:?}, Violations: {:?}",
            conn.get_error_code(),
            stream_id,
            input.end_stream,
            input.padded,
            payload,
            conn.get_violations()
        );
    }

    // Verify the zero-length DATA frame was accepted and recorded
    let final_zero_frames = conn.get_zero_data_frames().len();
    assert_eq!(
        final_zero_frames,
        initial_zero_frames + 1,
        "Zero-length DATA frame not recorded. Stream ID: {}, END_STREAM: {}, PADDED: {}",
        stream_id,
        input.end_stream,
        input.padded
    );

    // Verify the recorded frame info
    let last_frame = &conn.get_zero_data_frames()[final_zero_frames - 1];
    assert_eq!(last_frame.stream_id, stream_id, "Stream ID mismatch");
    assert_eq!(
        last_frame.end_stream, input.end_stream,
        "END_STREAM flag mismatch"
    );
    assert_eq!(last_frame.padded, input.padded, "PADDED flag mismatch");
    assert_eq!(
        last_frame.flow_control_consumed, expected_flow_control,
        "Flow control consumption mismatch"
    );

    // Send follow-up frames to test continued operation
    for frame in &input.follow_up_frames {
        send_follow_up_frame(&mut conn, frame);
        if conn.has_protocol_error() {
            // Follow-up frames might cause errors, but that's separate from
            // the zero-length DATA frame handling
            break;
        }
    }

    // Test specific zero-length DATA scenarios
    test_zero_length_scenarios(&input, stream_id);
});

/// Test specific zero-length DATA frame scenarios
fn test_zero_length_scenarios(input: &ZeroLengthDataInput, stream_id: u32) {
    // Scenario 1: Zero-length DATA with END_STREAM=1 (empty body terminator)
    {
        let mut conn = MockZeroDataConnection::new();
        // Set up stream with HEADERS first
        conn.process_frame(FRAME_TYPE_HEADERS, stream_id, FLAG_END_HEADERS, b"headers");

        // Send zero-length DATA with END_STREAM
        conn.process_frame(FRAME_TYPE_DATA, stream_id, FLAG_END_STREAM, &[]);

        assert!(
            !conn.has_protocol_error(),
            "Zero-length DATA with END_STREAM=1 must be valid (empty body terminator)"
        );
        assert_eq!(conn.count_zero_data_with_end_stream(), 1);
    }

    // Scenario 2: Zero-length DATA with END_STREAM=0 (legal but useless)
    {
        let mut conn = MockZeroDataConnection::new();
        // Set up stream with HEADERS first
        conn.process_frame(FRAME_TYPE_HEADERS, stream_id, FLAG_END_HEADERS, b"headers");

        // Send zero-length DATA without END_STREAM
        conn.process_frame(FRAME_TYPE_DATA, stream_id, 0, &[]);

        assert!(
            !conn.has_protocol_error(),
            "Zero-length DATA with END_STREAM=0 must be valid (legal but useless)"
        );
        assert_eq!(conn.count_zero_data_without_end_stream(), 1);
    }

    // Scenario 3: Zero-length PADDED DATA with pad_length=0
    {
        let mut conn = MockZeroDataConnection::new();
        conn.process_frame(FRAME_TYPE_HEADERS, stream_id, FLAG_END_HEADERS, b"headers");

        // PADDED with pad_length=0: [0][no data][no padding]
        conn.process_frame(FRAME_TYPE_DATA, stream_id, FLAG_PADDED, &[0]);

        assert!(
            !conn.has_protocol_error(),
            "Zero-length PADDED DATA with pad_length=0 must be valid"
        );
        let frames = conn.get_zero_data_frames();
        assert!(!frames.is_empty());
        assert!(frames[0].padded);
        assert_eq!(frames[0].flow_control_consumed, 1); // pad_length byte
    }

    // Scenario 4: Multiple zero-length DATA frames on same stream
    {
        let mut conn = MockZeroDataConnection::new();
        conn.process_frame(FRAME_TYPE_HEADERS, stream_id, FLAG_END_HEADERS, b"headers");

        // Send multiple zero-length DATA frames
        conn.process_frame(FRAME_TYPE_DATA, stream_id, 0, &[]);
        conn.process_frame(FRAME_TYPE_DATA, stream_id, 0, &[]);
        conn.process_frame(FRAME_TYPE_DATA, stream_id, FLAG_END_STREAM, &[]);

        assert!(
            !conn.has_protocol_error(),
            "Multiple zero-length DATA frames must be valid"
        );
        assert_eq!(conn.get_zero_data_frames().len(), 3);
    }

    // Scenario 5: Zero-length DATA after regular DATA
    {
        let mut conn = MockZeroDataConnection::new();
        conn.process_frame(FRAME_TYPE_HEADERS, stream_id, FLAG_END_HEADERS, b"headers");

        // Send regular DATA, then zero-length DATA
        conn.process_frame(FRAME_TYPE_DATA, stream_id, 0, b"some data");
        conn.process_frame(FRAME_TYPE_DATA, stream_id, FLAG_END_STREAM, &[]);

        assert!(
            !conn.has_protocol_error(),
            "Zero-length DATA after regular DATA must be valid"
        );
        assert_eq!(conn.get_zero_data_frames().len(), 1);
        assert!(conn.get_zero_data_frames()[0].end_stream);
    }

    // Scenario 6: Zero-length DATA between WINDOW_UPDATE frames
    if input.end_stream {
        let mut conn = MockZeroDataConnection::new();
        conn.process_frame(FRAME_TYPE_HEADERS, stream_id, FLAG_END_HEADERS, b"headers");

        // WINDOW_UPDATE → zero-length DATA → WINDOW_UPDATE
        conn.process_frame(
            FRAME_TYPE_WINDOW_UPDATE,
            stream_id,
            0,
            &1000u32.to_be_bytes(),
        );
        conn.process_frame(FRAME_TYPE_DATA, stream_id, FLAG_END_STREAM, &[]);
        conn.process_frame(
            FRAME_TYPE_WINDOW_UPDATE,
            stream_id,
            0,
            &1000u32.to_be_bytes(),
        );

        assert!(
            !conn.has_protocol_error(),
            "Zero-length DATA between WINDOW_UPDATE frames must be valid"
        );
    }

    // Scenario 7: Zero-length DATA on different stream IDs
    if stream_id < 0x7FFFFFFD {
        // Leave room for stream_id + 2
        let mut conn = MockZeroDataConnection::new();
        let stream2 = stream_id + 2; // Another client-initiated stream

        // Set up both streams
        conn.process_frame(FRAME_TYPE_HEADERS, stream_id, FLAG_END_HEADERS, b"headers1");
        conn.process_frame(FRAME_TYPE_HEADERS, stream2, FLAG_END_HEADERS, b"headers2");

        // Send zero-length DATA on both streams
        conn.process_frame(FRAME_TYPE_DATA, stream_id, 0, &[]);
        conn.process_frame(FRAME_TYPE_DATA, stream2, FLAG_END_STREAM, &[]);

        assert!(
            !conn.has_protocol_error(),
            "Zero-length DATA on different streams must be valid"
        );
        assert_eq!(conn.get_zero_data_frames().len(), 2);
    }

    // Scenario 8: Zero-length DATA with maximum flow control consumption
    {
        let mut conn = MockZeroDataConnection::new();
        conn.process_frame(FRAME_TYPE_HEADERS, stream_id, FLAG_END_HEADERS, b"headers");

        // Zero-length frame still participates in flow control if PADDED
        if input.padded {
            conn.process_frame(
                FRAME_TYPE_DATA,
                stream_id,
                FLAG_PADDED | FLAG_END_STREAM,
                &[0],
            );
            assert!(
                !conn.has_protocol_error(),
                "Zero-length PADDED DATA must respect flow control"
            );
        }
    }
}
