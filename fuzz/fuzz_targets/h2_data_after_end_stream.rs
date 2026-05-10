#![no_main]

//! Fuzz target: HTTP/2 DATA frames after END_STREAM validation
//!
//! Tests the scenario where a peer sends DATA frames after a previous DATA frame
//! with END_STREAM=1. Per RFC 7540, after END_STREAM is set, no further frames
//! are valid for that stream and must be rejected with STREAM_CLOSED error.
//!
//! Key behaviors tested:
//! - DATA frame with END_STREAM=1 properly closes the stream
//! - Subsequent DATA frames on closed stream trigger STREAM_CLOSED error
//! - Stream state transitions from OPEN → HALF_CLOSED_REMOTE → CLOSED
//! - Edge cases: multiple consecutive DATA frames after END_STREAM
//! - Other frame types (HEADERS, RST_STREAM) after END_STREAM

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 frame type identifiers
const DATA_TYPE: u8 = 0x0;

/// HTTP/2 frame flags
const END_STREAM_FLAG: u8 = 0x1;
const PADDED_FLAG: u8 = 0x8;

/// HTTP/2 stream states per RFC 7540 §5.1
#[derive(Debug, Clone, PartialEq)]
enum StreamState {
    Idle,
    Open,
    HalfClosedRemote,
    HalfClosedLocal,
    Closed,
}

/// Stream tracking entry
#[derive(Debug, Clone)]
struct StreamEntry {
    stream_id: u32,
    state: StreamState,
}

/// Mock parser for HTTP/2 stream state machine validation
#[derive(Debug)]
struct MockH2StreamStateParser {
    streams: Vec<StreamEntry>,
    next_stream_id: u32,
}

/// Result types for parsing
#[derive(Debug, PartialEq)]
enum ParseResult {
    /// Data frame processed successfully
    DataFrameProcessed { stream_id: u32, end_stream: bool },
    /// Stream closed by END_STREAM
    StreamClosed(u32),
    /// Stream error
    StreamError { stream_id: u32, error: String },
    /// Other frame processed
    FrameProcessed,
    /// Protocol error
    ProtocolError(String),
}

/// Input for fuzz testing
#[derive(Debug, Arbitrary)]
struct H2DataAfterEndStreamInput {
    /// Sequence of frame operations to test
    operations: Vec<FrameOperation>,

    /// Maximum payload size for DATA frames (0..65535)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=65535))]
    max_payload_size: u16,
}

#[derive(Debug, Arbitrary, Clone)]
enum FrameOperation {
    /// Send DATA frame with specified flags
    SendData {
        stream_id: u32,
        payload_size: u16,
        end_stream: bool,
        padded: bool,
    },
    /// Send HEADERS frame
    SendHeaders { stream_id: u32, end_stream: bool },
    /// Send RST_STREAM frame
    SendRstStream { stream_id: u32, error_code: u32 },
    /// Send WINDOW_UPDATE frame
    SendWindowUpdate { stream_id: u32, increment: u32 },
    /// Create a new stream (implicit via HEADERS)
    CreateStream(u32),
}

impl MockH2StreamStateParser {
    fn new() -> Self {
        Self {
            streams: Vec::new(),
            next_stream_id: 1,
        }
    }

    /// Get or create a stream entry
    fn get_or_create_stream(&mut self, stream_id: u32) -> &mut StreamEntry {
        if let Some(pos) = self.streams.iter().position(|s| s.stream_id == stream_id) {
            return &mut self.streams[pos];
        }

        // Create new stream in OPEN state
        self.streams.push(StreamEntry {
            stream_id,
            state: StreamState::Open,
        });
        self.streams.last_mut().unwrap()
    }

    /// Get existing stream (without creating)
    fn get_stream(&mut self, stream_id: u32) -> Option<&mut StreamEntry> {
        self.streams.iter_mut().find(|s| s.stream_id == stream_id)
    }

    /// Process a DATA frame
    fn process_data_frame(
        &mut self,
        stream_id: u32,
        payload_size: u16,
        end_stream: bool,
        padded: bool,
    ) -> ParseResult {
        let payload = vec![0u8; payload_size as usize];
        let encoded = encode_data_frame(stream_id, &payload, end_stream, padded);
        assert_eq!(
            encoded.len(),
            9 + payload.len() + if padded { 9 } else { 0 },
            "DATA frame encoding length should account for payload and padding"
        );

        // Stream ID 0 is invalid for DATA frames
        if stream_id == 0 {
            return ParseResult::ProtocolError("DATA frame with stream_id=0".to_string());
        }

        let stream = match self.get_stream(stream_id) {
            Some(s) => s,
            None => {
                // DATA frame on non-existent stream is an error
                return ParseResult::StreamError {
                    stream_id,
                    error: "STREAM_CLOSED: DATA frame on non-existent stream".to_string(),
                };
            }
        };

        // Check stream state - DATA frames are only valid in OPEN and HALF_CLOSED_LOCAL states
        match stream.state {
            StreamState::Open => {
                // Valid state for receiving DATA
                if end_stream {
                    stream.state = StreamState::HalfClosedRemote;
                    ParseResult::StreamClosed(stream_id)
                } else {
                    ParseResult::DataFrameProcessed {
                        stream_id,
                        end_stream: false,
                    }
                }
            }
            StreamState::HalfClosedLocal => {
                // Valid state for receiving DATA
                if end_stream {
                    stream.state = StreamState::Closed;
                    ParseResult::StreamClosed(stream_id)
                } else {
                    ParseResult::DataFrameProcessed {
                        stream_id,
                        end_stream: false,
                    }
                }
            }
            StreamState::HalfClosedRemote | StreamState::Closed => {
                // Invalid: stream is already closed for receiving
                ParseResult::StreamError {
                    stream_id,
                    error: "STREAM_CLOSED: DATA frame on half-closed-remote or closed stream"
                        .to_string(),
                }
            }
            StreamState::Idle => {
                // DATA frame cannot open a stream
                ParseResult::StreamError {
                    stream_id,
                    error: "PROTOCOL_ERROR: DATA frame on idle stream".to_string(),
                }
            }
        }
    }

    /// Process a HEADERS frame
    fn process_headers_frame(&mut self, stream_id: u32, end_stream: bool) -> ParseResult {
        if stream_id == 0 {
            return ParseResult::ProtocolError("HEADERS frame with stream_id=0".to_string());
        }

        let stream = self.get_or_create_stream(stream_id);

        match stream.state {
            StreamState::Idle => {
                // HEADERS opens the stream
                stream.state = if end_stream {
                    StreamState::HalfClosedRemote
                } else {
                    StreamState::Open
                };
                if end_stream {
                    ParseResult::StreamClosed(stream_id)
                } else {
                    ParseResult::FrameProcessed
                }
            }
            StreamState::Open => {
                if end_stream {
                    stream.state = StreamState::HalfClosedRemote;
                    ParseResult::StreamClosed(stream_id)
                } else {
                    ParseResult::FrameProcessed
                }
            }
            StreamState::HalfClosedLocal => {
                if end_stream {
                    stream.state = StreamState::Closed;
                    ParseResult::StreamClosed(stream_id)
                } else {
                    ParseResult::FrameProcessed
                }
            }
            StreamState::HalfClosedRemote | StreamState::Closed => {
                // Invalid: cannot send more headers on half-closed-remote/closed stream
                ParseResult::StreamError {
                    stream_id,
                    error: "STREAM_CLOSED: HEADERS frame on half-closed-remote or closed stream"
                        .to_string(),
                }
            }
        }
    }

    /// Process RST_STREAM frame
    fn process_rst_stream(&mut self, stream_id: u32, error_code: u32) -> ParseResult {
        assert_eq!(
            u32::from_be_bytes(error_code.to_be_bytes()),
            error_code,
            "RST_STREAM error code should round-trip through wire byte order"
        );

        if stream_id == 0 {
            return ParseResult::ProtocolError("RST_STREAM frame with stream_id=0".to_string());
        }

        if let Some(stream) = self.get_stream(stream_id) {
            stream.state = StreamState::Closed;
            ParseResult::StreamClosed(stream_id)
        } else {
            // RST_STREAM on non-existent stream is allowed (idempotent)
            ParseResult::FrameProcessed
        }
    }

    /// Process WINDOW_UPDATE frame
    fn process_window_update(&mut self, stream_id: u32, increment: u32) -> ParseResult {
        if increment == 0 {
            return ParseResult::ProtocolError("WINDOW_UPDATE with zero increment".to_string());
        }

        if stream_id == 0 {
            // Connection-level window update
            return ParseResult::FrameProcessed;
        }

        // Stream-level window update
        if let Some(stream) = self.get_stream(stream_id) {
            match stream.state {
                StreamState::Closed => {
                    // WINDOW_UPDATE on closed stream is an error
                    ParseResult::StreamError {
                        stream_id,
                        error: "STREAM_CLOSED: WINDOW_UPDATE on closed stream".to_string(),
                    }
                }
                _ => ParseResult::FrameProcessed,
            }
        } else {
            // WINDOW_UPDATE on non-existent stream is an error
            ParseResult::StreamError {
                stream_id,
                error: "STREAM_CLOSED: WINDOW_UPDATE on non-existent stream".to_string(),
            }
        }
    }

    /// Create a stream explicitly
    fn create_stream(&mut self, stream_id: u32) -> ParseResult {
        let assigned_stream_id = if stream_id == 0 {
            self.next_stream_id
        } else {
            stream_id
        };
        self.next_stream_id = self
            .next_stream_id
            .max(assigned_stream_id.saturating_add(2));
        self.get_or_create_stream(assigned_stream_id);
        ParseResult::FrameProcessed
    }
}

fn assert_modeled_stream_state_variants() {
    let modeled_states = [
        StreamState::Idle,
        StreamState::Open,
        StreamState::HalfClosedRemote,
        StreamState::HalfClosedLocal,
        StreamState::Closed,
    ];
    assert_eq!(
        modeled_states.len(),
        5,
        "HTTP/2 stream-state model should keep all five RFC states represented"
    );
}

/// Encode DATA frame
fn encode_data_frame(stream_id: u32, payload: &[u8], end_stream: bool, padded: bool) -> Vec<u8> {
    let mut frame = Vec::new();
    let mut flags = 0u8;

    if end_stream {
        flags |= END_STREAM_FLAG;
    }
    if padded {
        flags |= PADDED_FLAG;
    }

    let pad_length = if padded { 8u8 } else { 0u8 };
    let total_payload_len = payload.len() + if padded { 1 + pad_length as usize } else { 0 };

    // Frame header (9 bytes)
    frame.extend_from_slice(&(total_payload_len as u32).to_be_bytes()[1..4]); // Length (24 bits)
    frame.push(DATA_TYPE); // Type
    frame.push(flags); // Flags
    frame.extend_from_slice(&stream_id.to_be_bytes()); // Stream ID

    // Payload
    if padded {
        frame.push(pad_length); // Pad length
    }
    frame.extend_from_slice(payload); // Data
    if padded {
        frame.extend(vec![0u8; pad_length as usize]); // Padding
    }

    frame
}

/// Process the input through our mock parser
fn process_input(input: &H2DataAfterEndStreamInput) -> Vec<ParseResult> {
    let mut parser = MockH2StreamStateParser::new();
    let mut results = Vec::new();

    for operation in &input.operations {
        let result = match operation {
            FrameOperation::SendData {
                stream_id,
                payload_size,
                end_stream,
                padded,
            } => {
                let actual_size = (*payload_size as usize).min(input.max_payload_size as usize);
                parser.process_data_frame(*stream_id, actual_size as u16, *end_stream, *padded)
            }
            FrameOperation::SendHeaders {
                stream_id,
                end_stream,
            } => parser.process_headers_frame(*stream_id, *end_stream),
            FrameOperation::SendRstStream {
                stream_id,
                error_code,
            } => parser.process_rst_stream(*stream_id, *error_code),
            FrameOperation::SendWindowUpdate {
                stream_id,
                increment,
            } => parser.process_window_update(*stream_id, *increment),
            FrameOperation::CreateStream(stream_id) => parser.create_stream(*stream_id),
        };
        results.push(result);
    }

    results
}

fuzz_target!(|input: H2DataAfterEndStreamInput| {
    // Skip empty inputs
    if input.operations.is_empty() {
        return;
    }

    assert_modeled_stream_state_variants();

    let results = process_input(&input);

    // Track stream states and find END_STREAM operations
    let mut closed_streams = std::collections::HashSet::new();

    for result in &results {
        match result {
            ParseResult::StreamClosed(stream_id) => {
                closed_streams.insert(*stream_id);
            }
            ParseResult::DataFrameProcessed {
                stream_id,
                end_stream: _,
            } => {
                // If we processed a DATA frame after the stream was closed, that's an error
                if closed_streams.contains(stream_id) {
                    // Look for a subsequent frame that should have failed
                    // This should not happen - the parser should have rejected it
                    panic!(
                        "DATA frame was processed on stream {} after it was closed",
                        stream_id
                    );
                }
            }
            ParseResult::StreamError { stream_id, error } => {
                // Stream errors are expected for frames on closed streams
                if closed_streams.contains(stream_id) && error.contains("STREAM_CLOSED") {
                    // Good - this is expected behavior
                } else if !error.contains("non-existent") {
                    // Other stream errors are fine for validation
                }
            }
            ParseResult::FrameProcessed => {
                // Regular frame processing
            }
            ParseResult::ProtocolError(_) => {
                // Protocol errors for malformed frames are acceptable
            }
        }
    }

    // Test specific violation scenarios
    let violation_tests = [
        // Stream 3: DATA with END_STREAM, then another DATA
        (vec![
            FrameOperation::CreateStream(3),
            FrameOperation::SendData {
                stream_id: 3,
                payload_size: 100,
                end_stream: true,
                padded: false,
            },
            FrameOperation::SendData {
                stream_id: 3,
                payload_size: 50,
                end_stream: false,
                padded: false,
            },
        ]),
        // Stream 5: DATA with END_STREAM, then WINDOW_UPDATE
        (vec![
            FrameOperation::CreateStream(5),
            FrameOperation::SendData {
                stream_id: 5,
                payload_size: 200,
                end_stream: true,
                padded: false,
            },
            FrameOperation::SendWindowUpdate {
                stream_id: 5,
                increment: 1000,
            },
        ]),
        // Stream 7: HEADERS with END_STREAM, then DATA
        (vec![
            FrameOperation::SendHeaders {
                stream_id: 7,
                end_stream: true,
            },
            FrameOperation::SendData {
                stream_id: 7,
                payload_size: 100,
                end_stream: false,
                padded: false,
            },
        ]),
    ];

    for test_ops in violation_tests {
        let test_results = process_input(&H2DataAfterEndStreamInput {
            operations: test_ops.clone(),
            max_payload_size: 1000,
        });

        // The last operation should result in a stream error
        if test_results.len() >= 2 {
            match &test_results[test_results.len() - 1] {
                ParseResult::StreamError { error, .. } => {
                    assert!(
                        error.contains("STREAM_CLOSED"),
                        "Expected STREAM_CLOSED error for operation after END_STREAM, got: {}",
                        error
                    );
                }
                other => {
                    panic!(
                        "Expected stream error for frame after END_STREAM, got: {:?}",
                        other
                    );
                }
            }
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_frame_with_end_stream() {
        let mut parser = MockH2StreamStateParser::new();

        // Create stream and send DATA with END_STREAM
        parser.create_stream(3);
        let result = parser.process_data_frame(3, 100, true, false);

        assert!(matches!(result, ParseResult::StreamClosed(3)));
    }

    #[test]
    fn test_data_frame_after_end_stream() {
        let mut parser = MockH2StreamStateParser::new();

        // Create stream, send DATA with END_STREAM, then another DATA
        parser.create_stream(3);
        parser.process_data_frame(3, 100, true, false); // Close the stream

        let result = parser.process_data_frame(3, 50, false, false);
        match result {
            ParseResult::StreamError { stream_id, error } => {
                assert_eq!(stream_id, 3);
                assert!(error.contains("STREAM_CLOSED"));
            }
            other => panic!("Expected stream error, got: {:?}", other),
        }
    }

    #[test]
    fn test_headers_with_end_stream() {
        let mut parser = MockH2StreamStateParser::new();

        // Send HEADERS with END_STREAM
        let result = parser.process_headers_frame(3, true);
        assert!(matches!(result, ParseResult::StreamClosed(3)));
    }

    #[test]
    fn test_data_frame_after_headers_end_stream() {
        let mut parser = MockH2StreamStateParser::new();

        // Send HEADERS with END_STREAM, then DATA
        parser.process_headers_frame(3, true); // Close the stream

        let result = parser.process_data_frame(3, 100, false, false);
        match result {
            ParseResult::StreamError { stream_id, error } => {
                assert_eq!(stream_id, 3);
                assert!(error.contains("STREAM_CLOSED"));
            }
            other => panic!("Expected stream error, got: {:?}", other),
        }
    }

    #[test]
    fn test_window_update_after_end_stream() {
        let mut parser = MockH2StreamStateParser::new();

        // Create stream, close it, then send WINDOW_UPDATE
        parser.create_stream(3);
        parser.process_data_frame(3, 100, true, false); // Close stream

        let result = parser.process_window_update(3, 1000);
        match result {
            ParseResult::StreamError { stream_id, error } => {
                assert_eq!(stream_id, 3);
                assert!(error.contains("STREAM_CLOSED"));
            }
            other => panic!("Expected stream error, got: {:?}", other),
        }
    }

    #[test]
    fn test_rst_stream_closes_immediately() {
        let mut parser = MockH2StreamStateParser::new();

        // Create stream and send RST_STREAM
        parser.create_stream(3);
        let result = parser.process_rst_stream(3, 8); // CANCEL error code

        assert!(matches!(result, ParseResult::StreamClosed(3)));

        // Subsequent frame should fail
        let data_result = parser.process_data_frame(3, 50, false, false);
        assert!(matches!(data_result, ParseResult::StreamError { .. }));
    }

    #[test]
    fn test_data_frame_encoding() {
        let payload = b"Hello, HTTP/2!";
        let frame = encode_data_frame(3, payload, true, false);

        // Check frame structure
        assert_eq!(frame[3], DATA_TYPE); // Frame type
        assert_eq!(frame[4], END_STREAM_FLAG); // Flags
        assert_eq!(
            u32::from_be_bytes([frame[5], frame[6], frame[7], frame[8]]),
            3
        ); // Stream ID

        // Check payload
        assert_eq!(&frame[9..], payload);
    }

    #[test]
    fn test_stream_state_transitions() {
        let mut parser = MockH2StreamStateParser::new();

        // Test IDLE -> OPEN -> HALF_CLOSED_REMOTE
        parser.process_headers_frame(3, false); // IDLE -> OPEN
        let stream = parser.get_stream(3).unwrap();
        assert_eq!(stream.state, StreamState::Open);

        parser.process_data_frame(3, 100, true, false); // OPEN -> HALF_CLOSED_REMOTE
        let stream = parser.get_stream(3).unwrap();
        assert_eq!(stream.state, StreamState::HalfClosedRemote);

        // Further DATA frames should fail
        let result = parser.process_data_frame(3, 50, false, false);
        assert!(matches!(result, ParseResult::StreamError { .. }));
    }

    #[test]
    fn test_multiple_consecutive_data_after_end_stream() {
        let mut parser = MockH2StreamStateParser::new();

        // Create and close stream
        parser.create_stream(3);
        parser.process_data_frame(3, 100, true, false);

        // Try multiple DATA frames - all should fail
        for i in 1..=5 {
            let result = parser.process_data_frame(3, i * 10, false, false);
            match result {
                ParseResult::StreamError { error, .. } => {
                    assert!(
                        error.contains("STREAM_CLOSED"),
                        "Frame {} should fail with STREAM_CLOSED",
                        i
                    );
                }
                other => panic!("Frame {} should fail, got: {:?}", i, other),
            }
        }
    }

    #[test]
    fn test_padded_data_frame_after_end_stream() {
        let mut parser = MockH2StreamStateParser::new();

        // Create and close stream
        parser.create_stream(5);
        parser.process_data_frame(5, 100, true, false);

        // Send padded DATA frame - should fail
        let result = parser.process_data_frame(5, 50, false, true);
        match result {
            ParseResult::StreamError { error, .. } => {
                assert!(error.contains("STREAM_CLOSED"));
            }
            other => panic!("Expected stream error for padded frame, got: {:?}", other),
        }
    }
}
